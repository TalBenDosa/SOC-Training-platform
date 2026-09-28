/**
 * Truthful XP copy for a finished scenario attempt (#30).
 *
 * Only the BEST attempt per scenario counts toward the learner's total, so the
 * completion screen must not claim "+470 XP" for a retry that added nothing.
 * The grade route returns `xpDelta` / `prevBestXp` (read from scenario_history
 * before it records the attempt); this turns them into the headline number and
 * the one-line explanation. Pure — unit-tested in scenarioXp.test.ts.
 */
export interface ScenarioXpInput {
  xpEarned: number;
  xpDelta?: number | null;
  prevBestXp?: number | null;
  bestXp?: number | null;
  persisted?: boolean;
  /** Server withheld the debrief: not every question answered / no report. */
  debriefWithheld?: boolean;
}

export interface ScenarioXpView {
  /** The number shown as "+N". */
  added: number;
  /** Tile label under the number. */
  label: string;
  /** Explanation line, or null when the headline says it all. */
  note: string | null;
  /** True when the server gave no delta — the headline is the raw run XP. */
  headlineOnly: boolean;
}

export function describeScenarioXp(r: ScenarioXpInput): ScenarioXpView {
  const run = Math.max(0, Math.round(r.xpEarned ?? 0));
  if (r.persisted === false && r.debriefWithheld) {
    return {
      added: 0,
      label: "Not Recorded",
      note: "Only complete attempts are recorded and earn XP — answer every question and write your report, then submit again.",
      headlineOnly: false,
    };
  }
  const unsaved = r.persisted === false
    ? "This attempt couldn't be saved to your account — check your connection before retrying."
    : null;

  if (typeof r.xpDelta !== "number") {
    return { added: run, label: "XP This Run", note: unsaved, headlineOnly: true };
  }

  const delta = Math.max(0, Math.round(r.xpDelta));
  const prev = Math.max(0, Math.round(r.prevBestXp ?? 0));
  const best = Math.max(prev, typeof r.bestXp === "number" ? Math.round(r.bestXp) : run);

  if (prev === 0) {
    return { added: delta, label: "XP Earned", note: unsaved, headlineOnly: false };
  }
  if (delta > 0) {
    return {
      added: delta,
      label: "XP Gained",
      note: unsaved ?? `+${delta} XP improvement over your best (${prev} → ${best} XP). This run scored ${run} XP — only your best attempt counts.`,
      headlineOnly: false,
    };
  }
  return {
    added: 0,
    label: "No New XP",
    note: unsaved ?? `No new XP — your best on this scenario is ${prev} XP and this run scored ${run}. Only your best attempt counts toward your total.`,
    headlineOnly: false,
  };
}
