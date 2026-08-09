import "server-only";
/**
 * Strips answer-bearing fields from a Room before it's handed to a Client
 * Component. Used by the room-detail page (the SSR payload is otherwise the
 * exact leak the "server-only" guard on src/data/rooms.ts exists to prevent —
 * see that file's doc comment). The player (TaskPlayer.tsx) now gets the
 * correct/xp/reveal data at submit time from
 * /api/rooms/[id]/tasks/[taskId]/submit instead of reading it off the task.
 *
 * `matching` and `ordering` used to be passed through unchanged, because their
 * answer is structurally encoded in data the board needs to render. Both are
 * now closed, each in the way its own leak required:
 *
 *  - MATCHING leaked through shared ids: `pairs[i].id` was on both the left and
 *    the right item, so a correct pairing was readable straight off the payload.
 *    Measured across all 40 matching tasks, no task has two identical right-hand
 *    texts — so the text itself is a unique key and the right side needs no id
 *    at all. It now ships as a bare, shuffled list of strings, and the server
 *    matches submitted text against `pairs[].right`.
 *
 *  - ORDERING leaked twice: through `correct_order` (literally the answer) and,
 *    less obviously, through the order of `items[]` itself — 29 of 32 ordering
 *    tasks are authored with items already in the correct sequence, so dropping
 *    `correct_order` alone would have changed nothing. Items are now shuffled
 *    here as well.
 *
 * The shuffle uses real randomness, NOT a seed derived from the room/task id.
 * A seeded shuffle would be reproducible by the client, which could then invert
 * the permutation and recover the authored order — reintroducing the leak in a
 * form that looks fixed. Grading never depends on the delivered order (matching
 * grades by text, ordering grades submitted ids against `correct_order`), so
 * the permutation only has to be unknowable, never recoverable.
 */
import type { Room, RoomTask } from "@/data/rooms";

/** Fisher-Yates on a copy. See the file doc for why this must not be seeded. */
function shuffled<T>(items: readonly T[]): T[] {
  const out = [...items];
  for (let i = out.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
}

export type SanitizedRoomTask =
  | (Omit<Extract<RoomTask, { type: "question" }>, "answer" | "explanation">)
  | (Omit<Extract<RoomTask, { type: "log_analysis" }>, "questions"> & {
      questions: Omit<Extract<RoomTask, { type: "log_analysis" }>["questions"][number], "answer" | "explanation">[];
    })
  | (Omit<Extract<RoomTask, { type: "flag" }>, "answer">)
  | (Omit<Extract<RoomTask, { type: "analyst_choice" }>, "correct_verdict" | "explanation" | "fp_trap">)
  | (Omit<Extract<RoomTask, { type: "query_fill" }>, "blanks" | "explanation"> & {
      blanks: Omit<Extract<RoomTask, { type: "query_fill" }>["blanks"][number], "answers">[];
    })
  | (Omit<Extract<RoomTask, { type: "reading" }>, "checkpoint"> & {
      checkpoint?: Omit<NonNullable<Extract<RoomTask, { type: "reading" }>["checkpoint"]>, "answer" | "explanation">;
    })
  // Matching: the board gets left items (keyed, so a connection can be named)
  // and right items as bare shuffled text. No id ties the two sides together.
  | (Omit<Extract<RoomTask, { type: "matching" }>, "pairs" | "explanation"> & {
      left: { id: string; text: string }[];
      right: string[];
    })
  // Ordering: items shuffled, correct_order gone.
  | (Omit<Extract<RoomTask, { type: "ordering" }>, "correct_order" | "explanation">);

export interface SanitizedRoom extends Omit<Room, "tasks"> {
  tasks: SanitizedRoomTask[];
}

// Per-type aliases so client components can import a single sanitized type per
// sub-player, mirroring how they used to import ReadingTask/QuestionTask/etc.
// straight off RoomTask.
export type SanitizedReadingTask = Extract<SanitizedRoomTask, { type: "reading" }>;
export type SanitizedQuestionTask = Extract<SanitizedRoomTask, { type: "question" }>;
export type SanitizedLogAnalysisTask = Extract<SanitizedRoomTask, { type: "log_analysis" }>;
export type SanitizedFlagTask = Extract<SanitizedRoomTask, { type: "flag" }>;
export type SanitizedAnalystChoiceTask = Extract<SanitizedRoomTask, { type: "analyst_choice" }>;
export type SanitizedQueryFillTask = Extract<SanitizedRoomTask, { type: "query_fill" }>;
export type SanitizedMatchingTask = Extract<SanitizedRoomTask, { type: "matching" }>;
export type SanitizedOrderingTask = Extract<SanitizedRoomTask, { type: "ordering" }>;

function sanitizeTask(task: RoomTask): SanitizedRoomTask {
  switch (task.type) {
    case "question": {
      const { answer: _answer, explanation: _explanation, ...rest } = task;
      return rest;
    }
    case "log_analysis": {
      return {
        ...task,
        questions: task.questions.map(({ answer: _answer, explanation: _explanation, ...q }) => q),
      };
    }
    case "flag": {
      const { answer: _answer, ...rest } = task;
      return rest;
    }
    case "analyst_choice": {
      const { correct_verdict: _cv, explanation: _explanation, fp_trap: _fp, ...rest } = task;
      return rest;
    }
    case "query_fill": {
      const { explanation: _explanation, ...rest } = task;
      return {
        ...rest,
        blanks: task.blanks.map(({ answers: _answers, ...b }) => b),
      };
    }
    case "reading": {
      if (!task.checkpoint) return task;
      const { answer: _answer, explanation: _explanation, ...checkpointRest } = task.checkpoint;
      return { ...task, checkpoint: checkpointRest };
    }
    case "matching": {
      const { pairs, explanation: _explanation, ...rest } = task;
      return {
        ...rest,
        left: pairs.map(p => ({ id: p.id, text: p.left })),
        right: shuffled(pairs.map(p => p.right)),
      };
    }
    case "ordering": {
      const { correct_order: _order, explanation: _explanation, ...rest } = task;
      return { ...rest, items: shuffled(task.items) };
    }
  }
}

export function sanitizeRoom(room: Room): SanitizedRoom {
  return { ...room, tasks: room.tasks.map(sanitizeTask) };
}
