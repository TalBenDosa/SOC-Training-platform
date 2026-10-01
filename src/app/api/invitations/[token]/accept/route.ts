import { NextResponse } from "next/server";
import { getValidatedAuth } from "@/lib/auth/validatedUser";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { checkRateLimit } from "@/lib/security/rateLimit";
import { logAudit } from "@/lib/audit/logAudit";

type Ctx = { params: Promise<{ token: string }> };

/**
 * Accept an invitation into an account that ALREADY EXISTS (QA phase 6, SEC-02).
 *
 * Staff roles used to be granted by attaching an existing account by email — but
 * sign-up does not verify the address (mailer_autoconfirm), so anyone holding a
 * class code could pre-register a future college admin's address and then be
 * attached as org_admin. Now an existing account gets a staff role only here, and
 * only when the caller holds BOTH halves of the proof:
 *   - the invitation token — it was emailed to the address, so they read that mailbox;
 *   - a session on the account whose email the invitation names.
 * The person who pre-registered someone else's address has the account but never
 * sees the token; the real owner gets the token and can take the account over
 * with a password reset (to the same mailbox). Every OTHER session of the account
 * is then signed out, so a squatter's still-open session cannot inherit the role.
 *
 * Only email-bound invitations are accepted here — a link without a recipient can
 * be forwarded, so it proves nothing about who is signed in.
 */
export async function POST(_req: Request, { params }: Ctx) {
  const auth = await getValidatedAuth();
  if (!auth) return NextResponse.json({ error: "Sign in first." }, { status: 401 });
  const { user, session } = auth;
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });
  const { token } = await params;

  if (!(await checkRateLimit(`invite-accept:${user.id}`, 10, 15 * 60_000)).ok) {
    return NextResponse.json({ error: "Too many attempts — wait a few minutes and try again." }, { status: 429 });
  }

  const { data: inv, error: invErr } = await admin.from("invitations")
    .select("id, org_id, email, role, expires_at, accepted_at")
    .eq("token", token).maybeSingle();
  if (invErr) return NextResponse.json({ error: "Couldn't check this invitation — please try again." }, { status: 500 });
  if (!inv || inv.accepted_at || Date.parse(inv.expires_at) <= Date.now()) {
    return NextResponse.json({ error: "This invitation isn't valid any more — ask for a fresh one." }, { status: 410 });
  }
  if (!inv.email) {
    return NextResponse.json({ error: "This link isn't addressed to anyone, so it can't be added to an existing account. Ask for an invitation sent to your email." }, { status: 400 });
  }
  if (!user.email || user.email.toLowerCase() !== String(inv.email).toLowerCase()) {
    return NextResponse.json({ error: `This invitation was sent to ${inv.email}. Sign in with that account to accept it.` }, { status: 403 });
  }

  // Consume it first (single use, race-safe: only one request flips accepted_at).
  const { data: claimed, error: claimErr } = await admin.from("invitations")
    .update({ accepted_at: new Date().toISOString() })
    .eq("id", inv.id).is("accepted_at", null).select("id");
  if (claimErr) return NextResponse.json({ error: "Couldn't accept this invitation — please try again." }, { status: 500 });
  if (!claimed?.length) return NextResponse.json({ error: "This invitation was already used." }, { status: 410 });

  const { error: attachErr } = await admin.rpc("attach_member_if_seat_available", {
    p_org: inv.org_id, p_user: user.id, p_role: inv.role,
    p_affiliation_expires: inv.role === "student" ? new Date(Date.now() + 100 * 86_400_000).toISOString() : null,
  });
  if (attachErr) {
    // Give the invitation back — nothing was granted.
    await admin.from("invitations").update({ accepted_at: null }).eq("id", inv.id);
    if (attachErr.message.includes("seat_limit_reached")) {
      return NextResponse.json({ error: "The organisation has no free seats. Ask its administrator to free one." }, { status: 409 });
    }
    console.error("[invitations/accept] attach failed:", attachErr.message);
    return NextResponse.json({ error: "Couldn't add you to the organisation — please try again." }, { status: 500 });
  }

  // Sign out every OTHER session of this account (a squatter's included); this one stays.
  let othersSignedOut = false;
  if (session?.access_token) {
    const { error: soErr } = await admin.auth.admin.signOut(session.access_token, "others");
    othersSignedOut = !soErr;
    if (soErr) console.error("[invitations/accept] signOut(others) failed:", soErr.message);
  }

  await logAudit({
    actorId: user.id, action: "invitation.accepted_existing_account",
    targetTable: "invitations", targetId: inv.id,
    metadata: { org_id: inv.org_id, role: inv.role, others_signed_out: othersSignedOut },
  });

  return NextResponse.json({ ok: true, orgId: inv.org_id, role: inv.role });
}
