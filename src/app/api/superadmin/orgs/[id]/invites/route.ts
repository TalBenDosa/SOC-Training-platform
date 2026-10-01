import { NextResponse } from "next/server";
import { dbFail } from "@/lib/http/dbFail";
import { emailOrigin } from "@/lib/http/siteOrigin";
import { requireSuperAdmin } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { sendEmailBatch } from "@/lib/email/sendEmail";
import { studentInviteEmail } from "@/lib/email/templates";

type Ctx = { params: Promise<{ id: string }> };

function joinLink(req: Request, token: string): string {
  const origin = emailOrigin(req);
  return `${origin}/join?token=${token}`;
}

// ── GET — pending invitations for the org ───────────────────────────────────
export async function GET(req: Request, { params }: Ctx) {
  const gate = await requireSuperAdmin("superadmin.invites.list");
  if ("error" in gate) return gate.error;
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });
  const { id } = await params;

  const { data, error } = await admin
    .from("invitations")
    .select("id, email, role, token, expires_at, accepted_at, created_at")
    .eq("org_id", id)
    .order("created_at", { ascending: false });
  if (error) return dbFail(error, "api/superadmin/orgs/[id]/invites", 500);

  const invites = (data ?? []).map(i => ({ ...i, link: joinLink(req, i.token) }));
  return NextResponse.json({ invites });
}

// ── POST — create invite(s): a generic class link, or one per email ─────────
export async function POST(req: Request, { params }: Ctx) {
  const gate = await requireSuperAdmin("superadmin.invites.create");
  if ("error" in gate) return gate.error;
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });
  const { id: orgId } = await params;

  let body: Record<string, unknown>;
  try { body = await req.json(); } catch { return NextResponse.json({ error: "Invalid JSON." }, { status: 400 }); }

  const role = String(body.role ?? "student");
  if (!["org_admin", "instructor", "student"].includes(role)) {
    return NextResponse.json({ error: "Invalid role." }, { status: 400 });
  }
  const rawDays = Number(body.expires_days ?? 14);
  // Bounded: a negative value minted already-expired links; a huge one threw.
  const days = Number.isFinite(rawDays) ? Math.min(90, Math.max(1, Math.round(rawDays))) : 14;
  const expiresAt = new Date(Date.now() + days * 24 * 3600 * 1000).toISOString();

  // Normalise the recipient list (dedupe, basic email shape). Empty → one
  // generic, shareable link with no fixed recipient.
  const rawEmails = Array.isArray(body.emails) ? (body.emails as unknown[]).map(e => String(e).trim().toLowerCase()) : [];
  // Cap the recipient list to bound the bulk insert + outbound-email fan-out.
  const MAX_INVITES = 200;
  const emails = [...new Set(rawEmails.filter(e => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e)))].slice(0, MAX_INVITES);

  // Since 0029 a student invitation must name its recipient (students join an
  // org with its class code) — an anonymous student link could never be redeemed.
  if (emails.length === 0 && role === "student") {
    return NextResponse.json({ error: "Student invitations need at least one email address — share the class code for open enrolment." }, { status: 400 });
  }

  const rows = (emails.length > 0 ? emails.map(email => ({ email })) : [{ email: null }]).map(r => ({
    org_id: orgId, role, email: r.email, token: crypto.randomUUID(), expires_at: expiresAt,
  }));

  const { data, error } = await admin.from("invitations").insert(rows).select("id, email, role, token, expires_at");
  if (error) return dbFail(error, "api/superadmin/orgs/[id]/invites", 500);

  const invites = (data ?? []).map(i => ({ ...i, link: joinLink(req, i.token) }));

  // Best-effort: email each named recipient their personal link (generic links
  // have no recipient). No-op when email isn't configured; never blocks.
  const { data: org } = await admin.from("organizations").select("name").eq("id", orgId).maybeSingle();
  const orgName = org?.name ?? "your course";
  // Paced batch send: firing up to 200 single sends in parallel tripped the
  // provider's rate limit, so most invites silently never arrived.
  const named = invites.filter(i => i.email);
  const batch = await sendEmailBatch(named.map(i => {
    const mail = studentInviteEmail({ orgName, joinLink: i.link });
    return { to: i.email as string, subject: mail.subject, html: mail.html, text: mail.text };
  }));
  const emailed = batch.sent.filter(Boolean).length;
  const email_failed = batch.skipped ? 0 : named.length - emailed;

  return NextResponse.json({ invites, emailed, email_failed, email_configured: !batch.skipped }, { status: 201 });
}
