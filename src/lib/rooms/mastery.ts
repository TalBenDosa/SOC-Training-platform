/**
 * Room PASS credit, kept apart from XP.
 *
 * WHY (learner reports, Oct 2026: "it says 59% even when I answer everything right"):
 * the 65% gate used to be computed from XP. XP follows the retry rules in xp.ts
 * (a second try on a revealing task pays half, a third try on a question pays
 * nothing), which is right for XP: a later try is informed. But it made the gate
 * impossible to reach once a first run fell short: "Review missed tasks" re-opened
 * the tasks, the learner answered them correctly, earned 0 or half XP, and the
 * score never moved. Passing is about mastery, so a task (or a log-analysis
 * question) answered correctly at any point counts in full toward the gate.
 * XP is unchanged.
 */
import type { Room, RoomTask } from "@/data/rooms";
import { taskMaxXp } from "@/lib/rooms/xp";

export interface GradedAttempt {
  task_id: string;
  question_index: number | null;
  correct: boolean | null;
  xp_awarded: number | null;
}

/** Pass credit of one task from the server's graded attempts (0..taskMaxXp). */
export function taskPassCredit(task: RoomTask, attempts: GradedAttempt[]): number {
  const mine = attempts.filter(a => a.task_id === task.id);
  if (task.type === "log_analysis") {
    return task.questions.reduce((sum, q, i) => {
      const forQ = mine.filter(a => a.question_index === i);
      if (forQ.some(a => a.correct)) return sum + q.xp;
      return sum + Math.min(q.xp, Math.max(0, ...forQ.map(a => a.xp_awarded ?? 0)));
    }, 0);
  }
  const max = taskMaxXp(task);
  if (mine.some(a => a.correct)) return max;
  return Math.min(max, Math.max(0, ...mine.map(a => a.xp_awarded ?? 0)));
}

/** { taskId: pass credit } for every gradeable task (QA-ROOM-2: the client shows it after a reload). */
export function roomPassCredit(room: Room, attempts: GradedAttempt[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const t of room.tasks) if (taskMaxXp(t) > 0) out[t.id] = taskPassCredit(t, attempts);
  return out;
}

/** The room's pass score from graded attempts: gradeable tasks only. */
export function roomPassScore(room: Room, attempts: GradedAttempt[]): { score: number; max: number } {
  let score = 0, max = 0;
  for (const t of room.tasks) {
    const m = taskMaxXp(t);
    if (m <= 0) continue;
    max += m;
    score += taskPassCredit(t, attempts);
  }
  return { score, max };
}
