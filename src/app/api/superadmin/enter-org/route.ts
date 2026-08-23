import { NextResponse } from "next/server";
import { requireSuperAdmin } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { logAudit } from "@/lib/audit/logAudit";

/**
 * Super-admin: enter (and switch active context to) ANY environment.
 *
 * The super-admin owns every tenant, so joining one is not an enrolment — it
 * is an administrative act, and deliberately skips every gate a real member
 * passes through:
 *
 *  - no access code and no invitation (those doors are for students/admins);
 *  - no seat-cap check — a direct upsert, not attach_member_if_seat_available,
 *    so a full class can still be entered for support/inspection;
 *  - no affiliation clock (affiliation_expires_at stays null) — the 100-day
 *    rule binds students, not the platform owner;
 *  - membership is org_admin — REQUIRED, because the access-token hook derives
 *    the JWT org_id claim from org_members; without it the super-admin has no
 *    org context. Invisibility to the tenant is achieved separately: per-org
 *    views exclude is_platform_admin (roster/analytics + leaderboard 0037).
 *
 * Switching context = updating profiles.org_id. The service role passes the
 * 0005 guard trigger (auth.uid() is null on this connection); the client then
 * refreshes its session so the access-token hook restamps the org claims.
 * The super-admin accumulates a membership per environment entered (that is how
 * the hook can restore context on switch), yet stays invisible everywhere the
 * tenant's own data is shown.
 */
export async function POST(req: Request) {
  const gate = await requireSuperAdmin("superadmin.enter_org");
  if ("error" in gate) return gate.error;
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  let body: Record<string, unknown>;
  try { body = await req.json(); } catch { return NextResponse.json({ error: "Invalid JSON." }, { status: 400 }); }
  const orgId = String(body.org_id ?? "").trim();
  if (!orgId) return NextResponse.json({ error: "org_id is required." }, { status: 400 });

  const { data: org } = await admin
    .from("organizations").select("id, name").eq("id", orgId).maybeSingle();
  if (!org) return NextResponse.json({ error: "No such organisation." }, { status: 404 });

  // Membership IS created (org_admin) — the access-token hook derives the JWT
  // org_id claim from org_members, so a membership is REQUIRED for the super-
  // admin to have any org context at all. Invisibility to the tenant is handled
  // NOT by withholding membership (that only nulls the context), but by
  // excluding is_platform_admin everywhere per-org data is shown: roster +
  // analytics (api/org/{members,analytics}) and the leaderboard (migration 0037).
  const { error: memErr } = await admin.from("org_members").upsert(
    { org_id: orgId, user_id: gate.user.id, role: "org_admin", status: "active", affiliation_expires_at: null },
    { onConflict: "org_id,user_id" },
  );
  if (memErr) return NextResponse.json({ error: memErr.message }, { status: 500 });

  // Active context: where the JWT claims (and therefore /manage, leaderboards,
  // progress writes) point after the next token refresh.
  const { error: profErr } = await admin
    .from("profiles").update({ org_id: orgId }).eq("id", gate.user.id);
  if (profErr) return NextResponse.json({ error: profErr.message }, { status: 500 });

  await logAudit({
    actorId: gate.user.id, action: "superadmin.entered_org",
    targetTable: "organizations", targetId: orgId, metadata: { org_name: org.name },
  });

  return NextResponse.json({ ok: true, org_name: org.name });
}
