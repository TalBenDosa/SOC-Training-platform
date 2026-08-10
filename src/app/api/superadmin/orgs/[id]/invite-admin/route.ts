import { NextResponse } from "next/server";
import crypto from "node:crypto";
import { requireSuperAdmin } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { sendEmail } from "@/lib/email/sendEmail";
import { orgWelcomeEmail } from "@/lib/email/templates";
import { logAudit } from "@/lib/audit/logAudit";

/**
 * Invite a NEW org admin to an EXISTING org by email.
 *
 * The member-add route next door only ATTACHES an account that already exists.
 * This one is for the common case Tal described: designate someone as the
 * college's admin who does not have an account yet. It mints an email-bound
 * org_admin invitation and emails them the join link, which lands on their
 * org's registration form (email locked to the invite, role org_admin), after
 * which they get the /manage dashboard — same flow org creation already runs,
 * now available after the org exists.
 *
 * The admin LINK is always returned, whether or not the email actually went
 * out (Resend may be unconfigured). So the super-admin can copy and send it by
 * hand in the meantime — the invite works regardless of email delivery.
 */
type Ctx = { params: Promise<{ id: string }> };
const INTERNAL_ORG = "d0d0d0d0-0000-4000-8000-000000000000";

export async function POST(req: Request, { params }: Ctx) {
  const gate = await requireSuperAdmin("superadmin.invite_admin");
  if ("error" in gate) return gate.error;
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });
  const { id: orgId } = await params;
  if (orgId === INTERNAL_ORG) {
    return NextResponse.json({ error: "The internal org can't take invited admins." }, { status: 400 });
  }

  let body: Record<string, unknown>;
  try { body = await req.json(); } catch { return NextResponse.json({ error: "Invalid JSON." }, { status: 400 }); }
  const email = String(body.email ?? "").trim().toLowerCase();
  if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
    return NextResponse.json({ error: "A valid email is required." }, { status: 400 });
  }

  const { data: org } = await admin.from("organizations").select("id, name").eq("id", orgId).maybeSingle();
  if (!org) return NextResponse.json({ error: "No such organisation." }, { status: 404 });

  // Email-bound org_admin invitation (14-day window), so only this recipient
  // can redeem it — the 0026 binding enforces the email match at signup.
  const token = crypto.randomUUID();
  const expiresAt = new Date(Date.now() + 14 * 24 * 3600 * 1000).toISOString();
  const { error: insErr } = await admin.from("invitations").insert({
    org_id: orgId, email, role: "org_admin", token, expires_at: expiresAt,
  });
  if (insErr) return NextResponse.json({ error: insErr.message }, { status: 500 });

  const origin = new URL(req.url).origin;
  const adminLink = `${origin}/join?token=${token}`;

  const mail = orgWelcomeEmail({ orgName: org.name, adminLink });
  const r = await sendEmail({ to: email, subject: mail.subject, html: mail.html, text: mail.text });

  await logAudit({
    actorId: gate.user.id, action: "superadmin.admin_invited",
    targetTable: "invitations", targetId: orgId, metadata: { email, emailed: r.ok },
  });

  return NextResponse.json({ ok: true, adminLink, emailed: r.ok, emailSkipped: r.skipped ?? false });
}
