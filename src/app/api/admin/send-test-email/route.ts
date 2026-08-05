import { NextResponse } from "next/server";
import { requireAdmin } from "@/lib/auth/apiGuard";
import { sendEmail } from "@/lib/email/sendEmail";
import { orgWelcomeEmail } from "@/lib/email/templates";

/**
 * Admin-only smoke test for the transactional-email pipeline (Resend). Gated by
 * requireAdmin — the existing platform-owner role — so it works TODAY, before
 * the multi-tenancy migrations, to confirm RESEND_API_KEY + EMAIL_FROM deliver.
 *
 * GET /api/admin/send-test-email          → sends the sample org-welcome email
 *                                           to the signed-in admin's own address.
 * GET /api/admin/send-test-email?to=x@y.z → sends it to a specific address.
 *
 * Returns { ok, skipped, to } — `skipped:true` means RESEND_API_KEY isn't set.
 */
export async function GET(req: Request) {
  const gate = await requireAdmin("admin.send_test_email");
  if ("error" in gate) return gate.error;

  const url = new URL(req.url);
  const to = (url.searchParams.get("to") || gate.user.email || "").trim();
  if (!to) return NextResponse.json({ error: "No recipient address (no ?to= and no email on the admin account)." }, { status: 400 });

  const site = url.origin;
  const mail = orgWelcomeEmail({
    orgName: "Test College",
    classLink: `${site}/join?token=demo-class-link`,
    adminLink: `${site}/join?token=demo-admin-link`,
  });
  const r = await sendEmail({ to, subject: mail.subject, html: mail.html, text: mail.text });

  return NextResponse.json({
    ok: r.ok,
    skipped: r.skipped ?? false,
    to,
    subject: mail.subject,
    note: r.skipped ? "RESEND_API_KEY not set on this deployment." : r.ok ? "Sent." : `Failed: ${r.error}`,
  });
}
