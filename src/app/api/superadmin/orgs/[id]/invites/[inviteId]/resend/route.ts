import { NextResponse } from "next/server";
import { emailOrigin } from "@/lib/http/siteOrigin";
import { requireSuperAdmin } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { sendEmail } from "@/lib/email/sendEmail";
import { emailStatusOf } from "@/lib/email/emailStatus";
import { orgWelcomeEmail, studentInviteEmail } from "@/lib/email/templates";
import { getActiveCode } from "@/lib/org/classCode";
import { checkRateLimit } from "@/lib/security/rateLimit";
import { logAudit } from "@/lib/audit/logAudit";

/**
 * Resend an unused invitation email — for the college admin who never got in
 * (the email was missed, landed in spam, or the 14-day link lapsed).
 *
 * The SAME token is kept, so a link from the earlier email works too. If it has
 * expired — or would within 3 days — its window is extended to 14 days from now.
 * An org-admin invite is resent as the welcome email (with the live class code,
 * when there is one — never minting a new code, which would revoke the class's).
 * The link is always returned so it can be shared by hand if delivery fails.
 */
type Ctx = { params: Promise<{ id: string; inviteId: string }> };

const RENEW_IF_WITHIN_MS = 3 * 24 * 3600 * 1000;
const NEW_WINDOW_MS = 14 * 24 * 3600 * 1000;

export async function POST(req: Request, { params }: Ctx) {
  const gate = await requireSuperAdmin("superadmin.invite_resend");
  if ("error" in gate) return gate.error;
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });
  const { id: orgId, inviteId } = await params;

  // A few resends per invitation per 15 minutes — enough for "try again", not an inbox-bomb.
  if (!(await checkRateLimit(`invite-resend:${inviteId}`, 3, 15 * 60_000)).ok) {
    return NextResponse.json({ error: "This invitation was just resent — wait a few minutes before sending it again." }, { status: 429 });
  }

  const { data: inv, error: invErr } = await admin.from("invitations")
    .select("id, org_id, email, role, token, expires_at, accepted_at")
    .eq("id", inviteId).eq("org_id", orgId).maybeSingle();
  if (invErr) return NextResponse.json({ error: "Couldn't read the invitation — please try again." }, { status: 500 });
  if (!inv) return NextResponse.json({ error: "No such invitation in this organization." }, { status: 404 });
  if (inv.accepted_at) return NextResponse.json({ error: "This invitation was already used — the person has an account. Send them a sign-in email instead." }, { status: 409 });
  if (!inv.email) return NextResponse.json({ error: "This is a generic link with no recipient — copy the link and share it yourself." }, { status: 400 });

  const { data: org } = await admin.from("organizations").select("name").eq("id", orgId).maybeSingle();
  const orgName = org?.name ?? "your organization";

  let expiresAt = inv.expires_at as string;
  let renewed = false;
  if (Date.parse(expiresAt) - Date.now() < RENEW_IF_WITHIN_MS) {
    expiresAt = new Date(Date.now() + NEW_WINDOW_MS).toISOString();
    const { error: upErr } = await admin.from("invitations").update({ expires_at: expiresAt }).eq("id", inv.id).is("accepted_at", null);
    if (upErr) return NextResponse.json({ error: "Couldn't renew the invitation — please try again." }, { status: 500 });
    renewed = true;
  }

  const link = `${emailOrigin(req)}/join?token=${inv.token}`;
  let mail;
  if (inv.role === "org_admin") {
    const classCode = (await getActiveCode(admin, orgId).catch(() => null))?.code ?? null;
    mail = orgWelcomeEmail({ orgName, adminLink: link, classCode });
  } else {
    mail = studentInviteEmail({ orgName, joinLink: link });
  }
  const r = await sendEmail({ to: inv.email, subject: mail.subject, html: mail.html, text: mail.text });
  const status = emailStatusOf(r);

  await logAudit({
    actorId: gate.user.id, action: "superadmin.invite_resent",
    targetTable: "invitations", targetId: inv.id,
    metadata: { org_id: orgId, role: inv.role, renewed, email_status: status, resend_error: r.error ?? null },
  });

  return NextResponse.json({ ok: true, emailed: r.ok, email_status: status, email_error: r.error ?? null, email: inv.email, link, expires_at: expiresAt, renewed });
}
