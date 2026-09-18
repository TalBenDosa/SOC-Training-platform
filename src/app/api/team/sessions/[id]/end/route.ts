import { NextResponse } from "next/server";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { appendSystemEvent } from "@/lib/team/appendSystemEvent";

/**
 * End a team exercise (Phase 0.5). Flips the session to 'ended' and emits a
 * system session.ended event, which the broadcast trigger fans out so every
 * member's screen switches to the after-action report. The report itself is
 * derived from the append-only session_events log (client-side), so ending is
 * just this state transition.
 *
 * Who can end it (the "runner"): staff of the session's org (platform admin /
 * org_admin / instructor) OR the session's SOC Manager (mgr), who holds the
 * coordinator authority. `reason` lets the caller distinguish a manual end from
 * an automatic one (e.g. the owner/instructor left the live room).
 */
export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const user = await getAuthedUser();
  if (!user) return NextResponse.json({ error: "Authentication required." }, { status: 401 });
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  let reason = "manual";
  try { const body = await req.json(); if (typeof body?.reason === "string") reason = body.reason.slice(0, 40); } catch { /* body optional */ }

  const { data: sess } = await admin.from("team_sessions").select("org_id, status").eq("id", id).maybeSingle();
  if (!sess) return NextResponse.json({ error: "Session not found." }, { status: 404 });

  const isStaff = user.isPlatformAdmin ||
    ((user.orgRole === "org_admin" || user.orgRole === "instructor") && user.orgId === sess.org_id);
  // The session's own SOC Manager may end it too (coordinator authority). And ANY
  // member may drive the AUTOMATIC owner-left close (reason "owner_left"): the
  // client elects one online member to fire it when the instructor has dropped —
  // it can't be a staff/mgr-only call because the instructor is precisely who left.
  let isMember = isStaff;
  let isManager = false;
  if (!isStaff) {
    const { data: mem } = await admin.from("team_session_members")
      .select("role").eq("session_id", id).eq("user_id", user.id).maybeSingle();
    isMember = !!mem;
    isManager = mem?.role === "mgr";
  }
  const autoOwnerLeft = reason === "owner_left" && isMember;
  if (!isStaff && !isManager && !autoOwnerLeft) return NextResponse.json({ error: "Only the instructor or the SOC Manager can end the session." }, { status: 403 });

  if (["ended", "debriefed"].includes(sess.status)) return NextResponse.json({ ok: true, already: true });

  await admin.from("team_sessions").update({ status: "ended", ended_at: new Date().toISOString() }).eq("id", id);

  const ev = await appendSystemEvent(id, "session.ended", { at: new Date().toISOString(), reason, by: user.id });
  if (!ev.ok) return NextResponse.json({ error: ev.error }, { status: 500 });

  return NextResponse.json({ ok: true });
}
