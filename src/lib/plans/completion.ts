/**
 * Plan completion — PURE derivation from the existing progress tables
 * (unit-tested in completion.test.ts). As in v1 there is deliberately no
 * submissions table: an item finished before it was assigned counts at once.
 *
 *   room      room_progress.completed_at        (row without it = in progress)
 *   scenario  any scenario_history row           (a run is a completion)
 *   quiz      quiz_progress.passed               (row not passed = in progress)
 *   lesson    lesson_progress.completed_at       (knowledge check passed but not
 *                                                 marked complete = in progress)
 *
 * Org-authored library lessons have no completion record anywhere on the
 * platform, so they are "untracked": listed, never counted for or against.
 */
import { STATUS_CODE, itemKey, type ItemStatus, type PlanItem } from "./types";

export interface ProgressRows {
  rooms: { user_id: string; room_id: string; completed_at: string | null }[];
  scenarios: { user_id: string; slug: string }[];
  quizzes: { user_id: string; quiz_slug: string; passed: boolean | null }[];
  lessons: { user_id: string; lesson_key: string; completed_at: string | null; quiz_passed_at?: string | null }[];
}

type Mark = "done" | "in_progress";
/** user id → item key → mark. Missing = not started. */
export type ProgressIndex = Map<string, Map<string, Mark>>;

export function buildProgressIndex(rows: Partial<ProgressRows>): ProgressIndex {
  const idx: ProgressIndex = new Map();
  const put = (user: string, key: string, mark: Mark) => {
    let m = idx.get(user);
    if (!m) { m = new Map(); idx.set(user, m); }
    // "done" always wins over "in progress" whatever order rows arrive in.
    if (m.get(key) !== "done") m.set(key, mark);
  };
  for (const r of rows.rooms ?? []) put(r.user_id, itemKey({ kind: "room", id: r.room_id }), r.completed_at ? "done" : "in_progress");
  for (const s of rows.scenarios ?? []) put(s.user_id, itemKey({ kind: "scenario", id: s.slug }), "done");
  for (const q of rows.quizzes ?? []) put(q.user_id, itemKey({ kind: "quiz", id: q.quiz_slug }), q.passed ? "done" : "in_progress");
  for (const l of rows.lessons ?? []) put(l.user_id, itemKey({ kind: "lesson", id: l.lesson_key }), l.completed_at ? "done" : "in_progress");
  return idx;
}

/**
 * Only catalogue lessons (key "{path}--{lesson}") write lesson_progress; an
 * org-authored lesson id ("org-…", no "--") never can.
 */
export function isTrackedItem(item: Pick<PlanItem, "kind" | "id">): boolean {
  return item.kind !== "lesson" || item.id.includes("--");
}

export function itemStatus(idx: ProgressIndex, userId: string, item: Pick<PlanItem, "kind" | "id">): ItemStatus {
  if (!isTrackedItem(item)) return "untracked";
  return idx.get(userId)?.get(itemKey(item)) ?? "not_started";
}

/** A set of statuses is complete when every TRACKED item is done (and there is at least one). */
export function isComplete(statuses: readonly ItemStatus[]): boolean {
  const tracked = statuses.filter(s => s !== "untracked");
  return tracked.length > 0 && tracked.every(s => s === "done");
}

export function countDone(statuses: readonly ItemStatus[]): { done: number; tracked: number } {
  const tracked = statuses.filter(s => s !== "untracked");
  return { done: tracked.filter(s => s === "done").length, tracked: tracked.length };
}

/** Overdue = has a due date in the past and is not complete. */
export function isOverdue(dueAt: string | null, statuses: readonly ItemStatus[], now: number = Date.now()): boolean {
  if (!dueAt) return false;
  const t = Date.parse(dueAt);
  return !Number.isNaN(t) && t < now && !isComplete(statuses);
}

/**
 * The users × items matrix for one plan. Each row's statuses are encoded as
 * one STATUS_CODE character per item (in item order) to keep the payload small
 * — 200 learners × 40 items is 8 KB, not a 200 KB object graph.
 */
export function planMatrix(
  items: readonly Pick<PlanItem, "kind" | "id">[],
  recipients: readonly string[],
  idx: ProgressIndex,
): { rows: { user_id: string; statuses: string }[]; completed: number } {
  let completed = 0;
  const rows = recipients.map(user_id => {
    const st = items.map(it => itemStatus(idx, user_id, it));
    if (isComplete(st)) completed++;
    return { user_id, statuses: st.map(s => STATUS_CODE[s]).join("") };
  });
  return { rows, completed };
}
