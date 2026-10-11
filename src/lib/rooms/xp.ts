/**
 * Room XP rules — the single definition shared by the server (grading, the
 * completion record) and the room page. Every value comes from the CONTENT
 * (task.xp / question.xp); nothing here is supplied by the client.
 *
 *  - taskMaxXp:     the most a task can award (reading = 0 — engagement XP is
 *                   separate and never counts toward passing).
 *  - readingXp:     the engagement XP a reading task awards once (content xp, or 5).
 *  - retryXp:       XP for a submission after the first on task types that
 *                   REVEAL the answer when graded (so a second try is informed):
 *                   half, rounded down. Flags reveal nothing and keep full XP;
 *                   question / analyst_choice apply their own two-try rule in
 *                   grading.ts from the server-derived attempt number, and pay
 *                   nothing from the third try (the second wrong try revealed it).
 *  - ROOM_PASS_THRESHOLD: share of gradeable XP needed to complete a room.
 */
import type { Room, RoomTask } from "@/data/rooms";

export const ROOM_PASS_THRESHOLD = 0.65;
export const DEFAULT_READING_XP = 5;

export function taskMaxXp(task: RoomTask): number {
  switch (task.type) {
    case "reading":      return 0;
    case "log_analysis": return task.questions.reduce((s, q) => s + q.xp, 0);
    default:             return task.xp;
  }
}

export function readingXp(task: RoomTask): number {
  return task.type === "reading" ? (typeof task.xp === "number" && task.xp > 0 ? task.xp : DEFAULT_READING_XP) : 0;
}

/** { taskId: maxXp } for the gradeable tasks of a room (the 65% gate counts only these). */
export function gradeableTaskMax(room: Room): Record<string, number> {
  const m: Record<string, number> = {};
  for (const t of room.tasks) { const mx = taskMaxXp(t); if (mx > 0) m[t.id] = mx; }
  return m;
}

/** Task types whose graded response reveals the answer — a later try is informed. */
const REVEALING = new Set<RoomTask["type"]>(["log_analysis", "matching", "ordering", "query_fill", "written_report"]);

/** Two-try types: a second wrong try reveals the answer (grading.ts), so try 3+ is informed. */
const TWO_TRY = new Set<RoomTask["type"]>(["question", "analyst_choice"]);

export function retryXp(taskType: RoomTask["type"], xp: number, attemptNo: number): number {
  if (TWO_TRY.has(taskType)) return attemptNo >= 3 ? 0 : xp;   // tries 1–2: grading.ts already applies full / half
  if (attemptNo <= 1 || !REVEALING.has(taskType)) return xp;
  return Math.floor(xp / 2);
}
