import { NextResponse, after } from "next/server";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { teamTransition, teamScheduleEnd, teamCancelEnd, END_NOTICE_MS } from "@/lib/team/transition";
import { logAudit } from "@/lib/audit/logAudit";
import { activeSeat } from "@/lib/team/membership";
import { awardTeamXpOnce } from "@/lib/team/awardTeamXp";

/**
 * End a team exercise. Staff of the session's org (platform admin / org_admin /
 * instructor) or the session's SOC Manager only — ending is irreversible, so it is
 * never driven by an automatic client signal (an instructor who drops out PAUSES
 * the session instead; see the 0071 lifecycle tick).
 *
 * `team_transition` flips the status, stamps ended_at, marks pending injects
 * 'skipped' and appends session.ended in ONE transaction (audit I3/I2), and the
 * broadcast trigger switches every screen to the after-action report.
 *
 * 0104 (owner, 2026-11-07): ending is announced. Body `{ mode }`:
 *   "scheduled" (default, also with no body): the team sees "Shift ends in 2 minutes"
 *               (`session.end_scheduled` { ends_at }), and the SERVER ends the session at
 *               that time (lifecycle tick, `session.ended` reason "scheduled").
 *   "now":       end at once (staff chose "End now").
 *   "cancel":    withdraw a scheduled end (`session.end_cancelled`).
 * Response: { ok, mode, ends_at? }.
 *
 * QA M5: the report build + XP award run AFTER the response (`after()`), so ending
 * returns at once; that same build warms the report cache the whole class is about
 * to open (the report route single-flights on it).
 */
export const maxDuration = 60;

const MODES = new Set(["scheduled", "now", "cancel"]);

export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  let mode = "scheduled";
  try { const b = await req.json(); if (typeof b?.mode === "string") mode = b.mode; } catch { /* no body: scheduled */ }
  if (!MODES.has(mode)) return NextResponse.json({ error: "Unknown end mode." }, { status: 400 });
  const user = await getAuthedUser();
  if (!user) return NextResponse.json({ error: "Authentication required." }, { status: 401 });
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  const { data: sess } = await admin.from("team_sessions").select("org_id, status").eq("id", id).maybeSingle();
  if (!sess) return NextResponse.json({ error: "Session not found." }, { status: 404 });

  const isStaff = user.isPlatformAdmin ||
    ((user.orgRole === "org_admin" || user.orgRole === "instructor") && user.orgId === sess.org_id);
  let isManager = false;
  if (!isStaff) {
    const seat = await activeSeat(admin, id, sess.org_id, user.id);   // lapsed affiliation ⇒ no seat
    isManager = seat?.role === "mgr";
  }
  if (!isStaff && !isManager) return NextResponse.json({ error: "Only the instructor or the SOC Manager can end the session." }, { status: 403 });

  if (["ended", "debriefed"].includes(sess.status)) return NextResponse.json({ ok: true, mode, already: true });

  if (mode === "cancel") {
    const c = await teamCancelEnd(id, user.id);
    if ("error" in c) return NextResponse.json({ error: c.error }, { status: 500 });
    await logAudit({ actorId: user.id, action: "team.session.end_cancel", targetTable: "team_sessions", targetId: id,
      metadata: { as: isStaff ? "staff" : "mgr", noop: !!c.result.noop } });
    return NextResponse.json({ ok: true, mode, noop: !!c.result.noop });
  }
  // A lobby that never started has nothing to announce: it ends at once.
  if (mode === "scheduled" && sess.status !== "lobby") {
    const sch = await teamScheduleEnd(id, user.id, END_NOTICE_MS);
    if ("error" in sch) return NextResponse.json({ error: sch.error }, { status: 500 });
    await logAudit({ actorId: user.id, action: "team.session.end_schedule", targetTable: "team_sessions", targetId: id,
      metadata: { as: isStaff ? "staff" : "mgr", noop: !!sch.result.noop, ends_at: sch.result.ends_at ?? null } });
    // XP is awarded by the report route / daily sweep once the server has ended the session.
    return NextResponse.json({ ok: true, mode, ends_at: sch.result.ends_at ?? null, noop: !!sch.result.noop });
  }

  const t = await teamTransition(id, "ended", "manual", user.id);
  if ("error" in t) return NextResponse.json({ error: t.error }, { status: 500 });

  await logAudit({ actorId: user.id, action: "team.session.end", targetTable: "team_sessions", targetId: id,
    metadata: { as: isStaff ? "staff" : "mgr", noop: !!t.result.noop } });

  // Team training XP for every player (0087). Best effort, off the request path — the
  // report route and the daily sweep award it later if this fails; ending never depends on it.
  after(async () => {
    try { await awardTeamXpOnce(admin, id); }
    catch (e) { console.error("[team end] XP award failed (will retry from the report / sweep):", e instanceof Error ? e.message : String(e)); }
  });
  return NextResponse.json({ ok: true, mode: "now", already: !!t.result.noop });
}
