/**
 * "Assigned" chips on the content lists (rooms, lessons, quizzes, scenarios) —
 * CLIENT-SAFE types + the PURE derivation from a learner's plans (unit-tested in
 * assigned.test.ts). No corpus import: the server resolves the learner's plans
 * (loadLearnerPlans — same recipient rules as the 0075 RLS policy) and sends
 * only this small key → info map (GET /api/org/assignments?view=assigned-keys).
 */
import { itemKey, type LearnerPlan, type Priority } from "./types";

export interface AssignedInfo {
  /** Highest (numerically lowest) effective priority across every plan holding the item. */
  priority: Priority;
  /** Earliest due date among those plans (null if none has one). */
  due_at: string | null;
  /** The learner has completed it. */
  done: boolean;
  /** It is (also) in the learner's personal plan. */
  personal: boolean;
}

/** itemKey ("kind:id") → info. */
export type AssignedMap = Record<string, AssignedInfo>;

/**
 * Collapse the learner's plans to one entry per item.
 *  - effective priority of an item = its own priority if the manager set one,
 *    otherwise the plan's priority; across plans the highest wins;
 *  - due date = the earliest among the plans holding it;
 *  - done = the learner's status on it is "done" (status is per user × item, so
 *    it's the same in every plan).
 * Archived plans never reach here (loadLearnerPlans drops them), but a plan
 * carrying `archived_at` is skipped defensively anyway.
 */
export function deriveAssignedKeys(plans: readonly (LearnerPlan & { archived_at?: string | null })[]): AssignedMap {
  const out: AssignedMap = {};
  for (const p of plans) {
    if (p.archived_at) continue;
    for (const it of p.items) {
      const key = itemKey(it);
      const priority = (it.priority ?? p.priority) as Priority;
      const prev = out[key];
      if (!prev) {
        out[key] = { priority, due_at: p.due_at ?? null, done: it.status === "done", personal: p.personal };
        continue;
      }
      prev.priority = Math.min(prev.priority, priority) as Priority;
      if (p.due_at && (!prev.due_at || Date.parse(p.due_at) < Date.parse(prev.due_at))) prev.due_at = p.due_at;
      prev.done = prev.done || it.status === "done";
      prev.personal = prev.personal || p.personal;
    }
  }
  return out;
}
