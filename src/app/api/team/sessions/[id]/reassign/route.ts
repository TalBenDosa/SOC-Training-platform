import { NextResponse } from "next/server";
import { requireOrgStaff } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { appendSystemEvent } from "@/lib/team/appendSystemEvent";

/**
 * Reassign a member's role in a live session (F7 — resilience to disconnects).
 * When a single-seat holder (Tier-3 / SOC Manager) drops, the relay stalls; the
 * instructor hands the vacant seat to another member so the exercise keeps moving.
 *
 * Staff-only, own org, open sessions only. The session owner (instructor row) is
 * never a target, and 'instructor' is never granted (it carries staff.inject).
 * Emits `member.role_changed` so every client refreshes its roster live — before
 * this the UI had to say "ask them to refresh" (audit C3).
 */
const PLAY_ROLES = new Set(["t1", "t2", "t3", "mgr", "lead", "de", "ti", "observer"]);
const SINGLE_SEAT = new Set(["t3", "mgr"]);

export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const gate = await requireOrgStaff("team.session.reassign");
  if ("error" in gate) return gate.error;
  const { user } = gate;

  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  let body: Record<string, unknown> = {};
  try { body = await req.json(); } catch { /* required below */ }
  const targetUserId = typeof body.user_id === "string" ? body.user_id : "";
  const role = typeof body.role === "string" ? body.role : "";
  if (!targetUserId || !PLAY_ROLES.has(role)) {
    return NextResponse.json({ error: "Provide a member (user_id) and a valid role." }, { status: 400 });
  }

  const { data: sess } = await admin.from("team_sessions").select("id, org_id, status").eq("id", id).maybeSingle();
  if (!sess) return NextResponse.json({ error: "Session not found." }, { status: 404 });
  if (!user.isPlatformAdmin && sess.org_id !== user.orgId) {
    return NextResponse.json({ error: "Not your session." }, { status: 403 });
  }
  if (["ended", "debriefed"].includes(sess.status)) {
    return NextResponse.json({ error: "This session is closed — roles can't change." }, { status: 409 });
  }

  const { data: member } = await admin.from("team_session_members")
    .select("user_id, role, status").eq("session_id", id).eq("user_id", targetUserId).maybeSingle();
  if (!member || member.status === "left") return NextResponse.json({ error: "That user isn't a member of this session." }, { status: 404 });
  if (member.role === "instructor") return NextResponse.json({ error: "The session owner's role can't be changed." }, { status: 409 });

  if (SINGLE_SEAT.has(role)) {
    const { data: holders } = await admin.from("team_session_members")
      .select("user_id, status").eq("session_id", id).eq("role", role);
    if ((holders ?? []).some(h => h.user_id !== targetUserId && h.status !== "left")) {
      return NextResponse.json({ error: `${role === "mgr" ? "SOC Manager" : "Tier-3"} is a single-seat role and is already filled.` }, { status: 409 });
    }
  }

  const { error } = await admin.from("team_session_members")
    .update({ role }).eq("session_id", id).eq("user_id", targetUserId);
  if (error) { console.error("[team reassign]", error.message); return NextResponse.json({ error: "Couldn't reassign the role." }, { status: 500 }); }

  await appendSystemEvent(id, "member.role_changed", { user_id: targetUserId, role, from: member.role, by: user.id });
  return NextResponse.json({ ok: true, user_id: targetUserId, role });
}
