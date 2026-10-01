import { NextResponse } from "next/server";
import { emailOrigin } from "@/lib/http/siteOrigin";
import { requireSuperAdmin } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { sendEmail } from "@/lib/email/sendEmail";
import { accountAccessEmail } from "@/lib/email/templates";
import { emailStatusOf } from "@/lib/email/emailStatus";
import { checkRateLimit } from "@/lib/security/rateLimit";
import { logAudit } from "@/lib/audit/logAudit";

/**
 * Email a sign-in link to a college admin / instructor who HAS an account (the
 * invitation was used) but isn't getting in — forgot the password, never set
 * one up properly, lost the original email.
 *
 * Same mechanism as the self-service password reset (/api/auth/request-reset):
 * a stateless recovery token from the admin API, sent with our own sender to
 * /update-password on this origin — independent of the Supabase Site-URL /
 * redirect allowlist and usable on any device. The link itself is NOT returned
 * (it signs the person in); if delivery fails the console says so and they can
 * use "Forgot password".
 */
type Ctx = { params: Promise<{ id: string; userId: string }> };

export async function POST(req: Request, { params }: Ctx) {
  const gate = await requireSuperAdmin("superadmin.member_sign_in_email");
  if ("error" in gate) return gate.error;
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });
  const { id: orgId, userId } = await params;

  if (!(await checkRateLimit(`sign-in-email:${userId}`, 3, 15 * 60_000)).ok) {
    return NextResponse.json({ error: "A sign-in email was just sent — wait a few minutes before sending another." }, { status: 429 });
  }

  // Only this college's active staff — never an arbitrary account.
  const { data: member, error: memErr } = await admin.from("org_members").select("role, status")
    .eq("org_id", orgId).eq("user_id", userId).maybeSingle();
  if (memErr) return NextResponse.json({ error: "Couldn't check the membership — please try again." }, { status: 500 });
  if (!member || member.status !== "active" || !["org_admin", "instructor"].includes(member.role)) {
    return NextResponse.json({ error: "Not an active admin or instructor of this organization." }, { status: 404 });
  }

  const { data: u } = await admin.auth.admin.getUserById(userId);
  const email = u?.user?.email;
  if (!email) return NextResponse.json({ error: "This account has no email address on file." }, { status: 400 });

  const origin = emailOrigin(req);
  const { data, error } = await admin.auth.admin.generateLink({ type: "recovery", email, options: { redirectTo: `${origin}/update-password` } });
  const tokenHash = data?.properties?.hashed_token;
  if (error || !tokenHash) {
    console.error("[sign-in-email] generateLink failed:", error?.message);
    return NextResponse.json({ error: "Couldn't create a sign-in link — please try again." }, { status: 500 });
  }
  const link = `${origin}/update-password?token_hash=${encodeURIComponent(tokenHash)}&type=recovery`;

  const { data: org } = await admin.from("organizations").select("name").eq("id", orgId).maybeSingle();
  const mail = accountAccessEmail({ orgName: org?.name ?? "your organization", link });
  const r = await sendEmail({ to: email, subject: mail.subject, html: mail.html, text: mail.text });
  const status = emailStatusOf(r);

  await logAudit({
    actorId: gate.user.id, action: "superadmin.member_sign_in_email",
    targetTable: "profiles", targetId: userId,
    metadata: { org_id: orgId, role: member.role, email_status: status, resend_error: r.error ?? null },
  });

  return NextResponse.json({ ok: true, emailed: r.ok, email_status: status, email_error: r.error ?? null, email });
}
