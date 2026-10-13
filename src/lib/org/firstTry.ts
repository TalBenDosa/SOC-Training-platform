/**
 * "Right on the first try" — the mastery measure for the org-admin views.
 *
 * task_attempts holds every submission, retries included. Counting submissions made a
 * persistent learner look weak (every flag guess and retry was a "wrong"), and reading
 * checkpoints, which are ungraded, counted too. Here each question is one item: a room
 * task, or one question of a multi-question log_analysis task. An item is "first try
 * right" when its earliest submission was correct. Readings are excluded.
 *
 * Isomorphic and pure (no data access), so the analytics route, the student route and
 * the tests share it.
 */

export interface AttemptLike {
  room_id: string;
  task_id: string;
  task_type: string | null;
  question_index?: number | null;
  attempt_no?: number | null;
  correct: boolean;
  created_at?: string | null;
}

export interface ItemResult<A extends AttemptLike = AttemptLike> {
  key: string;
  room_id: string;
  task_id: string;
  task_type: string | null;
  question_index: number | null;
  attempts: A[];               // oldest first
  firstTryCorrect: boolean;
  solved: boolean;             // any submission correct
  triesToSolve: number | null; // 1-based position of the first correct submission
}

export interface FirstTrySummary {
  items: number;
  firstTryCorrect: number;
  /** Whole percent, or null when nothing gradable was answered. */
  accuracy: number | null;
  unsolved: number;
}

const UNGRADED = new Set(["reading"]);
const itemKey = (a: AttemptLike) => `${a.room_id}|${a.task_id}|${a.question_index ?? 0}`;
const order = (a: AttemptLike, b: AttemptLike) =>
  (Date.parse(a.created_at ?? "") || 0) - (Date.parse(b.created_at ?? "") || 0) || (a.attempt_no ?? 0) - (b.attempt_no ?? 0);

export function groupItems<A extends AttemptLike>(attempts: A[]): ItemResult<A>[] {
  const by = new Map<string, A[]>();
  for (const a of attempts) {
    if (UNGRADED.has(a.task_type ?? "")) continue;
    const k = itemKey(a);
    const list = by.get(k);
    if (list) list.push(a); else by.set(k, [a]);
  }
  return [...by.entries()].map(([key, list]) => {
    const sorted = [...list].sort(order);
    const firstOk = sorted.findIndex(a => a.correct);
    return {
      key, room_id: sorted[0].room_id, task_id: sorted[0].task_id, task_type: sorted[0].task_type,
      question_index: sorted[0].question_index ?? null,
      attempts: sorted, firstTryCorrect: sorted[0].correct, solved: firstOk >= 0,
      triesToSolve: firstOk >= 0 ? firstOk + 1 : null,
    };
  });
}

export function summarize(items: ItemResult[]): FirstTrySummary {
  const firstTryCorrect = items.filter(i => i.firstTryCorrect).length;
  return {
    items: items.length,
    firstTryCorrect,
    accuracy: items.length ? Math.round((firstTryCorrect / items.length) * 100) : null,
    unsolved: items.filter(i => !i.solved).length,
  };
}
