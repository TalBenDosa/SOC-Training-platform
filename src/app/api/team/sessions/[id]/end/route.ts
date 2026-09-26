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
 * coordinator authority. Ending is irreversible, so it is NEVER driven by an
 * automatic client signal: an instructor who drops out now PAUSES the session
 * (reason "owner_left" on /pause) instead — a plain member used to be able to
 * end any session by claiming "owner_left", which the server can't verify.
 */
export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const user = await getAuthedUser();
  if (!user) return NextResponse.json({ error: "Authentication required." }, { status: 401 });
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  // Only a manual end exists now; any other client-supplied reason is ignored.
  const reason = "manual";

  const { data: sess } = await admin.from("team_sessions").select("org_id, status").eq("id", id).maybeSingle();
  if (!sess) return NextResponse.json({ error: "Session not found." }, { status: 404 });

  const isStaff = user.isPlatformAdmin ||
    ((user.orgRole === "org_admin" || user.orgRole === "instructor") && user.orgId === sess.org_id);
  // The session's own SOC Manager may end it too (coordinator authority).
  let isManager = false;
  if (!isStaff) {
    const { data: mem } = await admin.from("team_session_members")
      .select("role").eq("session_id", id).eq("user_id", user.id).maybeSingle();
    isManager = mem?.role === "mgr";
  }
  if (!isStaff && !isManager) return NextResponse.json({ error: "Only the instructor or the SOC Manager can end the session." }, { status: 403 });

  if (["ended", "debriefed"].includes(sess.status)) return NextResponse.json({ ok: true, already: true });

  await admin.from("team_sessions").update({ status: "ended", ended_at: new Date().toISOString() }).eq("id", id);

  const ev = await appendSystemEvent(id, "session.ended", { at: new Date().toISOString(), reason, by: user.id });
  if (!ev.ok) return NextResponse.json({ error: ev.error }, { status: 500 });

  return NextResponse.json({ ok: true });
}
