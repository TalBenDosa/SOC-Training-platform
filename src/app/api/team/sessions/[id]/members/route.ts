import { NextResponse } from "next/server";
import { requireOrgStaff } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";

/**
 * Add a member to an existing team session (staff only, own org). Lets an
 * instructor grow the team while a session is still live — e.g. a late arrival,
 * or backfilling a role after someone dropped. The invitee must be an ACTIVE
 * member of the same org. Not allowed once the session is ended/debriefed.
 *
 * Single-seat roles (Tier-3 / SOC Manager) can hold at most one ACTIVE occupant,
 * so we refuse a second unless the existing one has left.
 */
const ADDABLE_ROLES = new Set(["t1", "t2", "t3", "mgr", "observer"]);
const SINGLE_SEAT = new Set(["t3", "mgr"]);

export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const gate = await requireOrgStaff("team.session.member.add");
  if ("error" in gate) return gate.error;
  const { user } = gate;
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  let body: Record<string, unknown> = {};
  try { body = await req.json(); } catch { /* validated below */ }
  const targetUserId = typeof body.user_id === "string" ? body.user_id : "";
  const role = typeof body.role === "string" ? body.role : "";
  if (!targetUserId || !ADDABLE_ROLES.has(role)) {
    return NextResponse.json({ error: "Provide a member (user_id) and a valid role." }, { status: 400 });
  }

  const { data: sess } = await admin.from("team_sessions").select("id, org_id, status").eq("id", id).maybeSingle();
  if (!sess) return NextResponse.json({ error: "Session not found." }, { status: 404 });
  if (!user.isPlatformAdmin && sess.org_id !== user.orgId) return NextResponse.json({ error: "Not your session." }, { status: 403 });
  if (["ended", "debriefed"].includes(sess.status)) return NextResponse.json({ error: "This session is closed — you can't add members." }, { status: 409 });

  // Invitee must be an ACTIVE member of this org.
  const { data: orgMem } = await admin.from("org_members")
    .select("user_id").eq("org_id", sess.org_id).eq("user_id", targetUserId).eq("status", "active").maybeSingle();
  if (!orgMem) return NextResponse.json({ error: "That user isn't an active member of your organisation." }, { status: 400 });

  // Already on the roster? Update their role instead of duplicating.
  const { data: existing } = await admin.from("team_session_members")
    .select("user_id, role, status").eq("session_id", id).eq("user_id", targetUserId).maybeSingle();

  if (SINGLE_SEAT.has(role)) {
    const { data: holders } = await admin.from("team_session_members")
      .select("user_id, status").eq("session_id", id).eq("role", role);
    const occupied = (holders ?? []).some(h => h.user_id !== targetUserId && h.status !== "left");
    if (occupied) return NextResponse.json({ error: `${role === "mgr" ? "SOC Manager" : "Tier-3"} is a single-seat role and is already filled.` }, { status: 409 });
  }

  if (existing) {
    const { error } = await admin.from("team_session_members")
      .update({ role, status: existing.status === "left" ? "invited" : existing.status }).eq("session_id", id).eq("user_id", targetUserId);
    if (error) return NextResponse.json({ error: error.message }, { status: 500 });
    return NextResponse.json({ ok: true, user_id: targetUserId, role, updated: true });
  }

  const { error } = await admin.from("team_session_members")
    .insert({ session_id: id, user_id: targetUserId, role, status: "invited", invited_by: user.id });
  if (error) return NextResponse.json({ error: error.message }, { status: 500 });
  return NextResponse.json({ ok: true, user_id: targetUserId, role, added: true });
}
