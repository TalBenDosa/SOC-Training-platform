import "server-only";
/**
 * Strips answer-bearing fields from a Room before it's handed to a Client
 * Component. Used by the room-detail page (the SSR payload is otherwise the
 * exact leak the "server-only" guard on src/data/rooms.ts exists to prevent —
 * see that file's doc comment). The player (TaskPlayer.tsx) now gets the
 * correct/xp/reveal data at submit time from
 * /api/rooms/[id]/tasks/[taskId]/submit instead of reading it off the task.
 *
 * `matching`/`ordering` tasks are passed through UNCHANGED — their answer is
 * structurally encoded in shared/ordered ids the client legitimately needs to
 * render the board (pairs[].id equality, correct_order). This is a known,
 * documented residual gap (see grading.ts's file doc), not an oversight.
 */
import type { Room, RoomTask } from "@/data/rooms";

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
  | Extract<RoomTask, { type: "matching" | "ordering" }>;

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
    case "matching":
    case "ordering":
      return task;
  }
}

export function sanitizeRoom(room: Room): SanitizedRoom {
  return { ...room, tasks: room.tasks.map(sanitizeTask) };
}
