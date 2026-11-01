/**
 * GET /api/me/progress — the signed-in learner's own Progress page (Progress v2).
 *
 * Every read is the caller's own rows AND their current organisation only (iron rule:
 * nothing from one org or environment shows in another). The user id comes from the
 * session, never from a parameter. Tables that a database may not have yet (0101) read
 * as empty instead of failing the page. Answer-free: mistakes with their answers come
 * from /api/me/mistakes under the reveal rule.
 */
import { NextResponse } from "next/server";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { fetchAll } from "@/lib/plans/server";
import { isMissingSchema } from "@/lib/progress/record";
import { techniqueById, tacticById } from "@/lib/mitre/attack";
import { buildProgress, type AttemptRow, type RawRows, type TeamCardRaw } from "@/lib/progress/selfView";
import { loadSelfScope, scopeOrg } from "@/lib/progress/scope";

export const maxDuration = 30;

export async function GET(req: Request) {
  const days = Number(new URL(req.url).searchParams.get("days") ?? "7");
  const user = await getAuthedUser();
  if (!user) return NextResponse.json({ error: "Sign in to see your progress.", guest: true }, { status: 401 });
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Progress storage isn't configured." }, { status: 503 });

  const scope = await loadSelfScope(admin, user);
  const uid = user.id;

  // Optional tables / columns (0101): a missing one is an empty list, not an error.
  const optional = async <T,>(q: PromiseLike<{ data: unknown; error: { message?: string; code?: string } | null }>, name: string): Promise<T[]> => {
    const { data, error } = await q;
    if (error) {
      if (!isMissingSchema(error)) console.error(`[me/progress] ${name} read failed:`, error.message);
      return [];
    }
    return (data ?? []) as T[];
  };

  let attempts: AttemptRow[];
  try {
    attempts = await fetchAll<AttemptRow>((from, to) => scopeOrg(admin.from("task_attempts")
      .select("room_id, task_id, task_type, question_index, attempt_no, correct, latency_ms, created_at")
      .eq("user_id", uid), scope)
      .order("created_at", { ascending: true }).order("id", { ascending: true })
      .range(from, to) as unknown as PromiseLike<{ data: AttemptRow[] | null; error: { message: string } | null }>, "me:attempts", 20_000);
  } catch (e) {
    console.error("[me/progress] attempts read failed:", e instanceof Error ? e.message : e);
    return NextResponse.json({ error: "Couldn't load your answers right now. Please try again." }, { status: 500 });
  }

  // Scenario history: try with the full breakdown column, fall back without it.
  const scenarioCols = "slug, title, score, xp_earned, time_taken, completed_at, report";
  const readScenarios = (cols: string) => scopeOrg(admin.from("scenario_history").select(cols).eq("user_id", uid), scope)
    .order("completed_at", { ascending: false }).limit(1000);
  let scenRes = await readScenarios(`${scenarioCols}, report_detail`);
  if (scenRes.error && isMissingSchema(scenRes.error, "report_detail")) scenRes = await readScenarios(scenarioCols);

  const [firsts, rooms, sessions, incidents, quizzes, learning, lessons, edr, team] = await Promise.all([
    scope.readFirsts(),
    optional<RawRows["rooms"][number]>(scopeOrg(admin.from("room_progress").select("room_id, completed_task_ids, xp_earned, telemetry, completed_at, updated_at").eq("user_id", uid), scope), "room_progress"),
    optional<RawRows["sessions"][number]>(scopeOrg(admin.from("dashboard_sessions").select("played_at, xp_earned, detect_rate, fn_count, avg_catch_ms, attacks_caught_count, attacks_presented_count, events_opened_count, duration_ms").eq("user_id", uid), scope).order("played_at", { ascending: false }).limit(1000), "dashboard_sessions"),
    optional<RawRows["incidents"][number]>(scopeOrg(admin.from("dashboard_incidents").select("id, shift_key, incident_key, story_id, title, company, severity, mitre, outcome, injected_at, first_opened_at, report_opened_at, submitted_at, report_score, attack_score, ioc_score, action_score, graded_by, feedback, strengths, gaps, summary, missed_tell").eq("user_id", uid), scope).order("submitted_at", { ascending: false }).limit(1000), "dashboard_incidents"),
    optional<RawRows["quizzes"][number]>(scopeOrg(admin.from("quiz_progress").select("quiz_slug, best_score_pct, passed, attempts, first_completed_at, last_completed_at").eq("user_id", uid), scope), "quiz_progress"),
    optional<RawRows["learning"][number]>(scopeOrg(admin.from("learning_attempts").select("kind, content_id, score_pct, correct, total, passed, created_at").eq("user_id", uid), scope).order("created_at", { ascending: false }).limit(2000), "learning_attempts"),
    optional<RawRows["lessons"][number]>(scopeOrg(admin.from("lesson_progress").select("lesson_key, best_quiz_pct, completed_at, quiz_passed_at").eq("user_id", uid), scope), "lesson_progress"),
    optional<RawRows["edr"][number]>(scopeOrg(admin.from("edr_case_results").select("case_id, title, chosen, correct, duration_ms, created_at").eq("user_id", uid), scope).order("created_at", { ascending: false }).limit(500), "edr_case_results"),
    loadTeamCards(admin, uid, scope.orgId),
  ]);

  const tacticCache = new Map<string, string | null>();
  const tacticOf = (tech: string) => {
    if (!tacticCache.has(tech)) {
      const t = techniqueById(tech.trim().toUpperCase()) ?? techniqueById(tech.trim().toUpperCase().split(".")[0]);
      tacticCache.set(tech, t ? tacticById(t.tactic)?.name ?? null : null);
    }
    return tacticCache.get(tech)!;
  };

  const payload = buildProgress({
    now: Date.now(), attempts, firsts, rooms, scenarios: (scenRes.data ?? []) as unknown as RawRows["scenarios"],
    sessions, incidents, quizzes, learning, lessons, edr, team, tacticOf,
  }, { periodDays: Number.isFinite(days) ? days : 7 });
  return NextResponse.json(payload, { headers: { "Cache-Control": "private, no-store" } });
}

/** The learner's own card from each ended team session of THIS org (cached reports only). */
async function loadTeamCards(admin: NonNullable<ReturnType<typeof getSupabaseAdminClient>>, uid: string, orgId: string | null): Promise<TeamCardRaw[]> {
  if (!orgId) return [];
  const { data: mems, error } = await admin.from("team_session_members").select("session_id, role").eq("user_id", uid).limit(500);
  if (error || !mems?.length) return [];
  const ids = [...new Set(mems.map(m => m.session_id as string))];
  const { data: sessions } = await admin.from("team_sessions").select("id, org_id, status, started_at, ended_at, company_id")
    .in("id", ids).eq("org_id", orgId).in("status", ["ended", "debriefed"]);
  if (!sessions?.length) return [];
  const { data: reports } = await admin.from("team_session_reports").select("session_id, report").in("session_id", sessions.map(s => s.id));
  const bySession = new Map((reports ?? []).map(r => [r.session_id as string, r.report as { perUser?: Array<Record<string, unknown> & { user_id?: string }> } | null]));
  return sessions.map(s => {
    const mine = bySession.get(s.id)?.perUser?.find(u => u.user_id === uid) ?? null;
    return {
      session_id: s.id, status: s.status, started_at: s.started_at, ended_at: s.ended_at, company_id: s.company_id,
      role: (mems.find(m => m.session_id === s.id)?.role as string | undefined) ?? null,
      card: mine as TeamCardRaw["card"],
    };
  });
}
