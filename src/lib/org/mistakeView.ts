import "server-only";
/**
 * Turns a student's stored room submissions into mistakes an instructor can read: the
 * question as the student saw it, what they chose, the right answer, the explanation, and
 * how many tries it took. Server-side only: it reads full rooms (with answer keys) through
 * getEffectiveRoom, so org-authored rooms resolve too. The answers go only to the student's
 * own org staff (the route's requireOrgAdmin), and only for items the student already answered.
 */
import type { RoomTask } from "@/data/rooms";
import { getEffectiveRoom } from "@/lib/rooms/resolve";
import { TASK_TYPE_LABEL } from "@/lib/feedback/labels";
import type { AttemptLike, ItemResult } from "./firstTry";

export interface StoredAttempt extends AttemptLike {
  submitted: unknown;
  latency_ms: number | null;
}

export interface MistakeView {
  key: string;
  room_id: string;
  room_title: string;
  room_category: string | null;
  task_id: string;
  task_position: string | null;   // "Task 4 of 12"
  type_label: string;
  prompt: string | null;          // what the student was asked
  chosen: string | null;          // what they answered on the first try
  correct: string | null;         // the right answer
  explanation: string | null;
  tries: number;
  solved: boolean;
  tries_to_solve: number | null;
  latency_ms: number | null;      // first try
  last_at: string | null;
}

export interface MistakeGroup {
  room_id: string;
  room_title: string;
  room_category: string | null;
  items: number;                  // gradable items attempted in this room
  first_try_correct: number;
  mistakes: MistakeView[];
}

const VERDICT: Record<string, string> = {
  true_positive: "True positive", benign_true_positive: "Benign true positive", false_positive: "False positive", escalate: "Escalate", informational: "Informational",
};
const cut = (s: unknown, n = 400): string | null => {
  if (s === undefined || s === null || s === "") return null;
  const t = String(s).replace(/\s+/g, " ").trim();
  return t.length > n ? `${t.slice(0, n - 1)}…` : t;
};
const obj = (v: unknown) => (v && typeof v === "object" ? (v as Record<string, unknown>) : {});

/** The question, the first-try answer, the right answer and the explanation for one item. */
export function describe(task: RoomTask | undefined, item: ItemResult<StoredAttempt>): Pick<MistakeView, "prompt" | "chosen" | "correct" | "explanation"> {
  const sub = obj(item.attempts[0]?.submitted);
  if (!task) return { prompt: null, chosen: cut(JSON.stringify(sub), 200), correct: null, explanation: null };
  const pick = (opts: string[] | undefined, i: unknown) => (typeof i === "number" && opts?.[i] !== undefined ? opts[i] : null);
  switch (task.type) {
    case "question":
      return { prompt: cut(task.question), chosen: cut(pick(task.options, sub.selectedIndex)), correct: cut(task.options[task.answer]), explanation: cut(task.explanation) };
    case "log_analysis": {
      const qi = typeof item.question_index === "number" ? item.question_index : typeof sub.questionIndex === "number" ? sub.questionIndex : 0;
      const q = task.questions[qi];
      return { prompt: cut(q ? `${task.heading}: ${q.question}` : task.heading), chosen: cut(pick(q?.options, sub.selectedIndex)), correct: cut(q?.options[q.answer]), explanation: cut(q?.explanation) };
    }
    case "analyst_choice":
      return { prompt: cut(`${task.heading}: ${task.scenario}`), chosen: cut(VERDICT[String(sub.verdict)] ?? sub.verdict), correct: VERDICT[task.correct_verdict], explanation: cut(task.explanation) };
    case "flag":
      return { prompt: cut(task.prompt), chosen: cut(sub.value), correct: cut(task.answer), explanation: cut(task.hint) };
    case "matching": {
      const conn = obj(sub.connections);
      const wrong = task.pairs.filter(p => conn[p.id] !== p.right);
      return {
        prompt: cut(`${task.heading}: ${task.instructions}`),
        chosen: `${task.pairs.length - wrong.length} of ${task.pairs.length} pairs right. Mixed up: ${wrong.map(p => `${p.left} → ${conn[p.id] ?? "(none)"}`).join("; ")}`.slice(0, 400),
        correct: cut(wrong.map(p => `${p.left} → ${p.right}`).join("; ")),
        explanation: cut(task.explanation),
      };
    }
    case "ordering": {
      const text = (id: unknown) => task.items.find(i => i.id === id)?.text ?? String(id);
      const placed = Array.isArray(sub.placed) ? sub.placed : [];
      return { prompt: cut(`${task.heading}: ${task.instructions}`), chosen: cut(placed.map(text).join(" → ")), correct: cut(task.correct_order.map(text).join(" → ")), explanation: cut(task.explanation) };
    }
    case "query_fill": {
      const vals = obj(sub.values);
      return {
        prompt: cut(`${task.heading}: ${task.context}`),
        chosen: cut(task.blanks.map(b => `${b.id} = ${vals[b.id] ?? "(empty)"}`).join(", ")),
        correct: cut(task.blanks.map(b => `${b.id} = ${b.answers[0]}`).join(", ")),
        explanation: cut(task.explanation),
      };
    }
    case "written_report":
      return { prompt: cut(task.prompt), chosen: "The report scored below the pass mark", correct: null, explanation: cut(task.explanation) };
    default:
      return { prompt: null, chosen: null, correct: null, explanation: null };
  }
}

/** Every room the student touched, with its first-try record and the readable mistakes in it. */
export async function buildMistakeGroups(items: ItemResult<StoredAttempt>[], orgId: string, categoryOf: (roomId: string) => string | null): Promise<MistakeGroup[]> {
  const roomIds = [...new Set(items.map(i => i.room_id))];
  const rooms = new Map(await Promise.all(roomIds.map(async id => [id, await getEffectiveRoom(id, orgId).catch(() => null)] as const)));
  const groups: MistakeGroup[] = roomIds.map(roomId => {
    const room = rooms.get(roomId) ?? null;
    const mine = items.filter(i => i.room_id === roomId);
    const mistakes = mine.filter(i => !i.firstTryCorrect).map(item => {
      const idx = room ? room.tasks.findIndex(t => t.id === item.task_id) : -1;
      const task = idx >= 0 ? room!.tasks[idx] : undefined;
      const qCount = task?.type === "log_analysis" ? task.questions.length : 0;
      const position = room && idx >= 0
        ? `Task ${idx + 1} of ${room.tasks.length}${qCount > 1 ? ` · question ${(item.question_index ?? 0) + 1} of ${qCount}` : ""}`
        : null;
      const last = item.attempts[item.attempts.length - 1];
      return {
        key: item.key, room_id: roomId, room_title: room?.title ?? roomId, room_category: room?.category ?? categoryOf(roomId),
        task_id: item.task_id, task_position: position,
        type_label: TASK_TYPE_LABEL[item.task_type ?? ""] ?? item.task_type ?? "Task",
        ...describe(task, item),
        tries: item.attempts.length, solved: item.solved, tries_to_solve: item.triesToSolve,
        latency_ms: item.attempts[0]?.latency_ms ?? null, last_at: last?.created_at ?? null,
      } satisfies MistakeView;
    });
    return {
      room_id: roomId, room_title: room?.title ?? roomId, room_category: room?.category ?? categoryOf(roomId),
      items: mine.length, first_try_correct: mine.filter(i => i.firstTryCorrect).length, mistakes,
    };
  });
  // Rooms with the most first-try mistakes first.
  return groups.filter(g => g.mistakes.length > 0).sort((a, b) => b.mistakes.length - a.mistakes.length || a.room_title.localeCompare(b.room_title));
}
