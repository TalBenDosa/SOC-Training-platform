/**
 * Per-device memory of what a learner answered in each Room task and what the
 * grader revealed back (feedback FB-001 — "Review room").
 *
 * The client never holds the answer key, and re-submitting a task just to show
 * its answer would log a fake attempt (task_attempts) and re-run grading. So the
 * review mode shows what was captured at the moment the learner genuinely
 * answered: their submission + the server's reveal (correct index/verdict,
 * explanation, solution). Tasks finished before this existed, or on another
 * device, fall back to the question + the XP earned.
 *
 * Browser storage only — a per-viewer convenience, never a source of truth for
 * progress or XP. Every access is guarded: private mode / blocked storage just
 * means "no details saved".
 */

const KEY = "room_review_v1";

export type QuestionReview = { selected: number | null; answer: number | null; explanation: string; correct: boolean };

export type ReviewRecord =
  | ({ type: "question" } & QuestionReview)
  | { type: "log_analysis"; questions: Record<number, QuestionReview> }
  | { type: "analyst_choice"; selected: string | null; correctVerdict: string | null; explanation: string; fpTrap?: string; correct: boolean }
  | { type: "flag"; value: string; correct: boolean }
  | { type: "query_fill"; values: Record<string, string>; blanks: Record<string, { correct: boolean; answers: string[] }>; explanation: string; correct: boolean }
  | { type: "matching"; connections: Record<string, string>; perPair: { id: string; correct: boolean }[]; solution: { id: string; left: string; right: string }[]; explanation: string; correct: boolean }
  | { type: "ordering"; placed: (string | null)[]; perSlot: { slot: number; correct: boolean }[]; correctOrder: string[]; explanation: string; correct: boolean }
  | { type: "written_report"; text: string; score: number; words: number; iocsCited: number; iocsTotal: number; fabricatedCount: number; explanation: string; correct: boolean }
  | { type: "reading"; checkpoint: QuestionReview };

type Store = Record<string /* roomId */, Record<string /* taskId */, ReviewRecord>>;

function readStore(): Store {
  try {
    const raw = window.localStorage.getItem(KEY);
    const parsed = raw ? JSON.parse(raw) : {};
    return parsed && typeof parsed === "object" ? (parsed as Store) : {};
  } catch {
    return {};
  }
}

function writeStore(store: Store) {
  try { window.localStorage.setItem(KEY, JSON.stringify(store)); } catch { /* quota / blocked — review details are optional */ }
}

/** Save (or merge, for multi-question log analysis) one task's review record. */
export function saveTaskReview(roomId: string, taskId: string, record: ReviewRecord) {
  if (typeof window === "undefined") return;
  const store = readStore();
  const room = store[roomId] ?? {};
  const prev = room[taskId];
  if (record.type === "log_analysis" && prev?.type === "log_analysis") {
    room[taskId] = { type: "log_analysis", questions: { ...prev.questions, ...record.questions } };
  } else {
    room[taskId] = record;
  }
  store[roomId] = room;
  writeStore(store);
}

/** All saved review records for a room (empty object when none / unavailable). */
export function loadRoomReview(roomId: string): Record<string, ReviewRecord> {
  if (typeof window === "undefined") return {};
  return readStore()[roomId] ?? {};
}
