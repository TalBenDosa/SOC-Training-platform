import { NextResponse } from "next/server";
import { tenantFromConfig } from "@/lib/team/tenant";
import { envFromConfig } from "@/lib/team/environment";
import { planFromConfig } from "@/lib/team/attackPlan";
import { sanitizeShiftMinutes, teamLoad } from "@/lib/team/load";
import { sanitizeStack } from "@/lib/logs/native/stack";
import { consoleFromConfig } from "@/lib/team/investigationConsole";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { ISOLATION_ACTIVE_WINDOW_MS } from "@/lib/team/isolationApproval";
import { sessionClock } from "@/lib/team/projections";
import { isTeamAdmin } from "@/lib/team/teamAdmin";

/**
 * One team session + its roster (Phase 0.3) — for the lobby / exercise room.
 * Readable by a member of the session OR a team admin of the session's org (isTeamAdmin:
 * org_admin or the platform owner; an org instructor reads only a session they are seated in). Authorised
 * here; DB RLS (0049) is the second gate. The reporter's identity is limited to
 * handle/display_name — no emails leak to peers.
 *
 * QA M1: a member who was REMOVED (status `left`) is no longer a reader — they get a
 * 403 `{ removed: true }` (the room shows "you were removed"), never the roster or
 * the session meta. Their own after-action card stays readable via /report. Staff
 * also see which members' access to the organisation has expired (`lapsed`): such an
 * invitee can never mark ready, so the lobby offers to remove them.
 *
 * 0104: every roster row carries `active` (heartbeat in the last 120 s, the same rule
 * the database uses to pick the isolation approver), and the session carries `clock`
 * (server-kept shift start, planned length, paused time, scheduled end, end).
 */
export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const user = await getAuthedUser();
  if (!user) return NextResponse.json({ error: "Authentication required." }, { status: 401 });
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  const { data: sess } = await admin.from("team_sessions").select("*").eq("id", id).maybeSingle();
  if (!sess) return NextResponse.json({ error: "Session not found." }, { status: 404 });

  // team_session_members has no FK to profiles (it references auth.users), so a
  // PostgREST embed can't resolve — fetch members and profiles separately, merge.
  const { data: mem } = await admin
    .from("team_session_members")
    .select("user_id, role, status, ready_at, last_seen_at")
    .eq("session_id", id);

  const myRow = (mem ?? []).find(m => m.user_id === user.id);
  const iAmMember = !!myRow && myRow.status !== "left";
  const iAmStaff = isTeamAdmin(user, sess.org_id);
  if (!iAmMember && !iAmStaff) {
    if (myRow) return NextResponse.json({ error: "You were removed from this session by the exercise admin.", removed: true }, { status: 403 });
    return NextResponse.json({ error: "Not your session." }, { status: 403 });
  }

  const ids = (mem ?? []).map(m => m.user_id);
  const { data: profs } = await admin
    .from("profiles").select("id, handle, display_name")
    .in("id", ids.length ? ids : ["00000000-0000-0000-0000-000000000000"]);
  const pmap = new Map((profs ?? []).map(p => [p.id, p as { handle?: string; display_name?: string }]));

  // Staff only: whose org membership is no longer active / unexpired (the same rule as
  // the DB's seat check) — those invitees can't act or mark ready.
  let lapsedIds: Set<string> | null = null;
  if (iAmStaff && ids.length) {
    const { data: om } = await admin.from("org_members").select("user_id, status, affiliation_expires_at")
      .eq("org_id", sess.org_id).in("user_id", ids);
    const okIds = new Set((om ?? []).filter(o => o.status === "active" && (!o.affiliation_expires_at || Date.parse(o.affiliation_expires_at) > Date.now())).map(o => o.user_id as string));
    lapsedIds = new Set(ids.filter(u => !okIds.has(u)));
  }

  const nowMs = Date.now();
  const staffSeen = Date.parse(String((sess as { staff_seen_at?: string | null }).staff_seen_at ?? "")) || 0;
  const roster = (mem ?? []).map(m => {
    const p = pmap.get(m.user_id);
    const seen = Math.max(Date.parse(String((m as { last_seen_at?: string | null }).last_seen_at ?? "")) || 0, m.role === "instructor" ? staffSeen : 0);
    return {
      user_id: m.user_id, role: m.role, status: m.status, ready_at: m.ready_at,
      active: m.status !== "left" && seen > 0 && nowMs - seen <= ISOLATION_ACTIVE_WINDOW_MS,
      name: p?.display_name || p?.handle || m.user_id.slice(0, 8),
      handle: p?.handle ?? null,
      ...(lapsedIds && m.role !== "instructor" && m.status !== "left" ? { lapsed: lapsedIds.has(m.user_id) } : {}),
    };
  });

  // Surface the current pause reason so a client that (re)loads a paused session
  // shows the right halt copy and can auto-resume a coverage pause (client C3).
  let pause_reason: string | null = null, pause_detail: string | null = null;
  if (sess.status === "paused") {
    const { data: pev } = await admin.from("session_events")
      .select("payload").eq("session_id", id).eq("type", "session.paused")
      .order("seq", { ascending: false }).limit(1).maybeSingle();
    const pl = (pev?.payload ?? {}) as { reason?: string; detail?: string };
    pause_reason = pl.reason ?? null;
    pause_detail = pl.detail ?? null;
  }

  // Never ship the grading answer-key (seed) or spoiler fields to a non-staff member.
  let sessionOut: Record<string, unknown> = sess;
  if (!iAmStaff) {
    const { seed: _seed, config: _config, scenario_id: _scn, ...safe } = sess as Record<string, unknown>;
    void _seed; void _config; void _scn;
    sessionOut = safe;
  }

  return NextResponse.json({
    session: { ...sessionOut, pause_reason, pause_detail, stack: sanitizeStack((sess as { config?: { stack?: unknown } }).config?.stack), console: consoleFromConfig((sess as { config?: unknown }).config), tenant: tenantFromConfig((sess as { config?: unknown }).config), env: envFromConfig((sess as { config?: unknown }).config),
      // Staff only: the attack plan (count + chosen storylines) — players never learn it.
      ...(iAmStaff ? { attack_plan: planFromConfig((sess as { config?: unknown }).config, (sess as { scenario_id?: string | null }).scenario_id) } : {}),
      shift_min: sanitizeShiftMinutes(((sess as { config?: { shift_min?: unknown } }).config ?? {}).shift_min),
      // The planned length: the exercise admin's choice, else the size the server built the shift for.
      clock: sessionClock(sess as Parameters<typeof sessionClock>[0],
        sanitizeShiftMinutes(((sess as { config?: { shift_min?: unknown } }).config ?? {}).shift_min)
          ?? teamLoad((sess as { difficulty: "easy" | "medium" | "hard" }).difficulty, mem ?? []).shiftMin, nowMs) },
    roster,
    // The "instructor" seat runs the room: only a team admin uses it. A legacy seat held by
    // someone who is no longer one (an org instructor, a demoted admin) reads as an observer.
    me: { id: user.id, is_staff: iAmStaff, role: iAmMember ? (myRow?.role === "instructor" && !iAmStaff ? "observer" : (myRow?.role ?? null)) : null },
  });
}
