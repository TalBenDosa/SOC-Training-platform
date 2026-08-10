import { NextResponse } from "next/server";
import { requireAdmin } from "@/lib/auth/apiGuard";
import { sendEmail } from "@/lib/email/sendEmail";
import { orgWelcomeEmail } from "@/lib/email/templates";

/**
 * Admin-only smoke test for the transactional-email pipeline (Resend).
 *
 * Restored (it existed as this exact path, removed before an earlier go-live)
 * and adapted to the current template: the org-welcome email now carries a
 * class CODE, not the retired class link. Gated by requireAdmin — the
 * platform-owner role — so the signed-in super-admin can fire it from the
 * browser and confirm delivery through PRODUCTION's own Resend config.
 *
 * GET /api/admin/send-test-email          → sends to the signed-in admin's address
 * GET /api/admin/send-test-email?to=x@y.z → sends to a specific address
 *
 * Returns { ok, skipped, error, to } — skipped:true means RESEND_API_KEY is
 * unset on THIS deployment (nothing was sent); ok:false with an error means
 * Resend rejected it (bad key, unverified sender), which is the useful signal.
 */
export async function GET(req: Request) {
  const gate = await requireAdmin("admin.send_test_email");
  if ("error" in gate) return gate.error;

  const url = new URL(req.url);
  const to = (url.searchParams.get("to") || gate.user.email || "").trim();
  if (!to) {
    return NextResponse.json({ error: "No recipient — pass ?to=you@example.com or set an email on the admin account." }, { status: 400 });
  }

  const site = url.origin;
  const mail = orgWelcomeEmail({
    orgName: "Test College",
    adminLink: `${site}/join?token=demo-admin-invite`,
    classCode: "DEMO1234",
  });
  const r = await sendEmail({ to, subject: mail.subject, html: mail.html, text: mail.text });

  return NextResponse.json({
    to,
    subject: mail.subject,
    ok: r.ok,
    skipped: r.skipped ?? false,
    error: r.error ?? null,
    note: r.skipped
      ? "RESEND_API_KEY is NOT set on this deployment — nothing was sent."
      : r.ok
        ? `Sent to ${to} via Resend. Check the inbox (and spam).`
        : `Resend rejected it: ${r.error}. Likely a bad key or an unverified EMAIL_FROM sender.`,
  });
}
