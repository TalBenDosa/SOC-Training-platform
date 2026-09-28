/**
 * Scenario completion state for the /scenarios list (FB-006).
 *
 * Pure helpers so the "✓ Completed" badge and the Show filter can be unit-tested
 * without a browser. The list builds its map from `getScenarioHistory()` (the
 * storage facade → `scenario_history` for a signed-in learner), keyed by the SAME
 * id the play page records: `ScenarioClient` stores the `[slug]` route param, which
 * is the built-in `slug` for static scenarios and the `scenario_id`
 * ("org-<ns>-…") for org-authored ones — both are what the list links to.
 */

export interface ScenarioHistoryLike {
  slug?: string | null;
  score?: number | null;
}

/**
 * Best score per completed scenario id. Any history record counts as "completed"
 * (a pass is not required — the learner finished and got a graded debrief).
 * Ids are normalised through `decodeURIComponent` so a record written with an
 * encoded route param still matches the list's raw id.
 */
export function bestScoresBySlug(history: readonly ScenarioHistoryLike[]): Record<string, number> {
  const best: Record<string, number> = {};
  for (const h of history) {
    if (!h || typeof h.slug !== "string" || !h.slug) continue;
    const id = safeDecode(h.slug);
    const score = typeof h.score === "number" && Number.isFinite(h.score) ? Math.max(0, Math.round(h.score)) : 0;
    best[id] = Math.max(best[id] ?? 0, score);
  }
  return best;
}

export type DoneFilter = "all" | "todo" | "done";

export const DONE_FILTERS: { value: DoneFilter; label: string }[] = [
  { value: "all",  label: "All" },
  { value: "todo", label: "Not done" },
  { value: "done", label: "Completed" },
];

/** Does a scenario with this id pass the Show filter? */
export function matchesDoneFilter(id: string, best: Record<string, number>, filter: DoneFilter): boolean {
  if (filter === "all") return true;
  const done = best[id] !== undefined;
  return filter === "done" ? done : !done;
}

function safeDecode(s: string): string {
  try { return decodeURIComponent(s); } catch { return s; }
}
