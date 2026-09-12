import { NextResponse } from "next/server";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { sendEmail } from "@/lib/email/sendEmail";
import { logAudit } from "@/lib/audit/logAudit";

/**
 * Reply to a reporter from the reports inbox (platform admin / super-admin only).
 *
 * The reporter took the time to write a report; this lets staff send them a
 * free-text response ("this is fixed", "we couldn't reproduce", …) that is
 * emailed to them and stored on the row for an audit trail.
 *
 * SECURITY: the recipient is resolved SERVER-SIDE from the report's user_id
 * (never a client-supplied address), so this can only ever email the person who
 * filed the report — it can't be used as an open relay. The reporter's email is
 * never returned to the client. Admin-gated identically to the inbox GET/PATCH.
 */

function esc(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const user = await getAuthedUser();
  if (!user) return NextResponse.json({ error: "Authentication required." }, { status: 401 });
  if (user.role !== "admin" && !user.isPlatformAdmin) {
    return NextResponse.json({ error: "Admin access required." }, { status: 403 });
  }
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  const { id } = await params;
  let body: { message?: unknown };
  try { body = await req.json(); } catch { return NextResponse.json({ error: "Invalid JSON." }, { status: 400 }); }
  const message = String(body?.message ?? "").trim();
  if (!message) return NextResponse.json({ error: "A reply message is required." }, { status: 400 });
  if (message.length > 5000) return NextResponse.json({ error: "Reply is too long (max 5000 characters)." }, { status: 400 });

  const { data: row, error: rowErr } = await admin
    .from("content_feedback")
    .select("id, user_id, message, target_kind, target_id")
    .eq("id", id)
    .maybeSingle();
  if (rowErr) return NextResponse.json({ error: rowErr.message }, { status: 500 });
  if (!row) return NextResponse.json({ error: "Report not found." }, { status: 404 });
  if (!row.user_id) return NextResponse.json({ error: "This report has no account attached (anonymous or deleted user) — there is no address to reply to." }, { status: 422 });

  // Resolve the reporter's email server-side; never expose it to the client.
  const { data: u, error: uErr } = await admin.auth.admin.getUserById(row.user_id);
  const email = u?.user?.email;
  if (uErr || !email) {
    return NextResponse.json({ error: "The reporter's account no longer has a reachable email address." }, { status: 422 });
  }

  const orig = String(row.message ?? "");
  const subject = "Re: your report on HACK THE SOC";
  const html =
    `<div style="font-family:system-ui,-apple-system,Segoe UI,sans-serif;font-size:15px;line-height:1.6;color:#141413;max-width:560px">` +
      `<p>Thanks for taking the time to report this on <b>HACK THE SOC</b>. Here's a reply from the team:</p>` +
      `<div style="border-left:3px solid #16606f;padding:8px 14px;margin:14px 0;background:#f7f8fa;white-space:pre-wrap">${esc(message)}</div>` +
      `<p style="color:#4a5a6a;font-size:13px;margin-top:20px">Your original report:</p>` +
      `<div style="border-left:3px solid #d3dae2;padding:8px 14px;margin:6px 0;background:#faf9f5;color:#4a5a6a;font-size:13px;white-space:pre-wrap">${esc(orig)}</div>` +
      `<p style="color:#94a3b8;font-size:12px;margin-top:22px">You're receiving this because you submitted a report on HACK THE SOC. You can reply to this email if you need to follow up.</p>` +
    `</div>`;
  const text =
    `Thanks for taking the time to report this on HACK THE SOC. Here's a reply from the team:\n\n` +
    `${message}\n\n` +
    `--- Your original report ---\n${orig}\n\n` +
    `You're receiving this because you submitted a report on HACK THE SOC.`;

  const sent = await sendEmail({ to: email, subject, html, text });
  if (!sent.ok && !sent.skipped) {
    return NextResponse.json({ error: `Could not send the email: ${sent.error ?? "unknown error"}.` }, { status: 502 });
  }

  const { error: updErr } = await admin
    .from("content_feedback")
    .update({ admin_response: message, responded_at: new Date().toISOString(), responded_by: user.id, status: "resolved" })
    .eq("id", id);
  if (updErr) return NextResponse.json({ error: updErr.message }, { status: 500 });

  await logAudit({
    actorId: user.id, action: "feedback.replied",
    targetTable: "content_feedback", targetId: id, metadata: { emailed: !sent.skipped },
  });

  // emailed=false means the reply was saved but RESEND_API_KEY is not configured,
  // so no email actually went out — the UI surfaces this so it isn't mistaken for delivery.
  return NextResponse.json({ ok: true, emailed: !sent.skipped });
}
