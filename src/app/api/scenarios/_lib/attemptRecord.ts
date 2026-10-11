/**
 * Server-side scenario attempt record (#30 of the team-exercise report).
 *
 * The grade route is now the ONLY writer of `scenario_history`. Previously the
 * browser inserted the row itself (remoteBackend, via the RLS "org self"
 * policy), so any signed-in user could insert a row with an arbitrary
 * xp_earned (up to the 2000 CHECK) and self-grant XP without being graded.
 * The coordinator's migration revokes those client writes and makes only the
 * BEST attempt per scenario count; this module builds the row the route writes
 * with the service-role client and computes the honest XP delta for the UI.
 *
 * Pure — no Supabase, no Next — so the clamping and delta rules are unit-tested.
 */

/** 0025 CHECK: scenario_history.xp_earned between 0 and 2000. */
export const SCENARIO_XP_CAP = 2000;
/** A day. Anything longer is a tab left open, not investigation time. */
export const MAX_TIME_TAKEN_S = 86_400;
/** Per free-text field stored in the report jsonb. */
export const REPORT_TEXT_CAP = 8_000;

export function clampTimeTaken(v: unknown): number {
  const n = typeof v === "number" ? v : typeof v === "string" ? Number(v) : NaN;
  if (!Number.isFinite(n)) return 0;
  return Math.min(MAX_TIME_TAKEN_S, Math.max(0, Math.round(n)));
}

export function clampScenarioXp(v: number): number {
  if (!Number.isFinite(v)) return 0;
  return Math.min(SCENARIO_XP_CAP, Math.max(0, Math.round(v)));
}

function capText(v: unknown): string {
  return typeof v === "string" ? v.slice(0, REPORT_TEXT_CAP) : "";
}

export interface AttemptRowInput {
  userId: string;
  orgId: string | null;
  slug: string;
  title: string;
  score: number;
  xpEarned: number;
  timeTaken: unknown;
  verdict: string | null;
  verdictReason: unknown;
  analystNotes: unknown;
  reportScore: number;
  rubric: { verdict: number; depth: number; evidence: number; reasoning: number };
  passed: boolean;
  now?: Date;
}

/**
 * The scenario_history row. `report` keeps the same jsonb shape the client used
 * to write (verdict / verdictReason / notes / reportScore / rubric / passed), so
 * /progress and the org console render server-written rows unchanged.
 * org_id is omitted (column DEFAULT applies) when the caller has no org claim —
 * the column is NOT NULL, so sending null would fail the insert.
 */
export function buildAttemptRow(i: AttemptRowInput): Record<string, unknown> {
  const verdict = i.verdict === "tp" || i.verdict === "fp" ? i.verdict : null;
  return {
    user_id: i.userId,
    ...(i.orgId ? { org_id: i.orgId } : {}),
    slug: i.slug,
    title: i.title.slice(0, 300),
    score: Math.min(100, Math.max(0, Math.round(i.score))),
    xp_earned: clampScenarioXp(i.xpEarned),
    time_taken: clampTimeTaken(i.timeTaken),
    completed_at: (i.now ?? new Date()).toISOString(),
    report: {
      verdict,
      verdictReason: capText(i.verdictReason),
      notes: capText(i.analystNotes),
      reportScore: i.reportScore,
      rubric: i.rubric,
      passed: i.passed,
    },
  };
}

/**
 * XP truth for the completion screen. Only the best attempt per scenario counts,
 * so a run adds `max(0, run − previousBest)` — a retry that doesn't beat the
 * best adds nothing, and the UI must say so rather than claim the full run XP.
 */
export function xpDeltaFor(runXp: number, prevBestXp: number | null): { xpDelta: number; bestXp: number; improved: boolean } {
  const run = clampScenarioXp(runXp);
  const prev = prevBestXp == null ? 0 : clampScenarioXp(prevBestXp);
  return { xpDelta: Math.max(0, run - prev), bestXp: Math.max(run, prev), improved: run > prev };
}
