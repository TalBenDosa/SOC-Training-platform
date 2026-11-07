import { NextResponse } from "next/server";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { teamTransition } from "@/lib/team/transition";
import { logAudit } from "@/lib/audit/logAudit";
import { activeSeat } from "@/lib/team/membership";

/**
 * Pause / resume a team session: a MANUAL human call only, by staff of the org or the
 * session's SOC Manager.
 *
 * 0104 (owner, 2026-11-07): nothing pauses the room automatically any more. The old
 * automatic reasons (`coverage`, `owner_left`) are accepted on the wire so an older
 * client doesn't loop on errors, but they never pause: the answer is a noop with
 * `refused: "automatic_pause_disabled"`, and the database refuses them as well
 * (team_transition). Presence problems reach the room as a non-blocking
 * `presence.notice` from the server's lifecycle tick instead.
 *
 * Every transition goes through the atomic `team_transition` (status + pause clock
 * + pause_reason + lifecycle event in one transaction).
 */
const REASONS = new Set(["manual", "coverage", "owner_left"]);

export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const user = await getAuthedUser();
  if (!user) return NextResponse.json({ error: "Authentication required." }, { status: 401 });
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  let paused = true, reason = "manual";
  try {
    const b = await req.json();
    if (typeof b?.paused === "boolean") paused = b.paused;
    if (typeof b?.reason === "string") reason = b.reason;
  } catch { /* body optional; defaults to a manual pause */ }
  if (!REASONS.has(reason)) return NextResponse.json({ error: "Unknown pause reason." }, { status: 400 });
  // An automatic halt never pauses the room (0104).
  if (reason !== "manual") return NextResponse.json({ ok: true, noop: true, refused: "automatic_pause_disabled" });

  const { data: sess } = await admin.from("team_sessions").select("org_id, status").eq("id", id).maybeSingle();
  if (!sess) return NextResponse.json({ error: "Session not found." }, { status: 404 });

  const isStaff = user.isPlatformAdmin ||
    ((user.orgRole === "org_admin" || user.orgRole === "instructor") && user.orgId === sess.org_id);
  let isManager = false;
  if (!isStaff) {
    const seat = await activeSeat(admin, id, sess.org_id, user.id);   // lapsed affiliation ⇒ no seat
    if (!seat) return NextResponse.json({ error: "Not your session." }, { status: 403 });
    isManager = seat.role === "mgr";
  }
  if (!isStaff && !isManager) {
    return NextResponse.json({ error: "Only the instructor or the SOC Manager can pause or resume the session." }, { status: 403 });
  }
  if (["ended", "debriefed"].includes(sess.status)) return NextResponse.json({ error: "This session is closed." }, { status: 409 });

  const t = await teamTransition(id, paused ? "paused" : "running", "manual", user.id, null);
  if ("error" in t) return NextResponse.json({ error: t.error }, { status: 500 });

  await logAudit({ actorId: user.id, action: paused ? "team.session.pause" : "team.session.resume",
    targetTable: "team_sessions", targetId: id, metadata: { as: isStaff ? "staff" : "mgr", noop: !!t.result.noop } });
  return NextResponse.json({ ok: true, noop: !!t.result.noop });
}
