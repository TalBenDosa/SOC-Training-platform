import "server-only";
/**
 * Server-side grading for Room tasks. This is the ONLY place that ever reads
 * an answer/answers/correct_verdict field out of ROOMS (src/data/rooms.ts) in
 * response to a request — the comparison happens here, in a server module, and
 * only the verdict + (once genuinely attempted) the reveal data crosses back
 * to the client. See src/app/api/rooms/[id]/tasks/[taskId]/submit/route.ts.
 *
 * Mirrors the comparison logic that used to live client-side in
 * src/components/rooms/TaskPlayer.tsx (kept faithful on purpose — the pass/fail
 * rules a student experiences must not change, only where they're evaluated).
 *
 * Scope: covers the 6 task types with an explicit answer field (question,
 * log_analysis, flag, analyst_choice, query_fill, reading.checkpoint).
 * `matching`/`ordering` are NOT covered — their "answer" is structurally
 * encoded in shared/ordered ids on the task itself (pairs[].id equality,
 * correct_order), which the client legitimately needs in full to render the
 * board at all. Closing that residual leak needs a content-schema change
 * (separating displayable ids from a server-only solution key), not a grading
 * endpoint, and is tracked separately rather than attempted here.
 */
import { ROOMS, type Room, type RoomTask } from "@/data/rooms";

export function findRoom(roomId: string): Room | undefined {
  return ROOMS.find(r => r.id === roomId);
}

export function findTask(room: Room, taskId: string): RoomTask | undefined {
  return room.tasks.find(t => t.id === taskId);
}

export type GradeResult =
  | { ok: true; correct: boolean; xpEarned: number; reveal: Record<string, unknown> }
  | { ok: false; error: string; status: number };

function fail(error: string, status = 400): GradeResult {
  return { ok: false, error, status };
}

/**
 * `submission` is the untyped, client-supplied POST body — validated per task
 * type below. `attemptNumber` (1 or 2) mirrors the two-try/half-credit model
 * QuestionPlayer and AnalystChoicePlayer already used client-side: first wrong
 * attempt gets no reveal so the student can genuinely retry; a second attempt
 * (right or wrong) reveals and, if correct, awards half XP. The server trusts
 * the client's claimed attempt number for XP *amount* only — it can never
 * change whether an answer is judged correct, so at worst a student games the
 * XP split between full/half credit, not the underlying score.
 */
export function gradeTask(task: RoomTask, submission: any): GradeResult {
  switch (task.type) {
    case "question": {
      const selected = submission?.selectedIndex;
      if (typeof selected !== "number") return fail("selectedIndex (number) is required.");
      const attemptNumber = submission?.attemptNumber === 2 ? 2 : 1;
      const correct = selected === task.answer;
      if (!correct && attemptNumber === 1) {
        // First miss: no reveal, matches the client's reset-and-retry UX.
        return { ok: true, correct: false, xpEarned: 0, reveal: {} };
      }
      const xpEarned = correct ? (attemptNumber === 1 ? task.xp : Math.ceil(task.xp / 2)) : 0;
      return {
        ok: true,
        correct,
        xpEarned,
        reveal: { answer: task.answer, explanation: task.explanation },
      };
    }

    case "log_analysis": {
      const qIndex = submission?.questionIndex;
      const selected = submission?.selectedIndex;
      if (typeof qIndex !== "number" || typeof selected !== "number") {
        return fail("questionIndex and selectedIndex (numbers) are required.");
      }
      const q = task.questions[qIndex];
      if (!q) return fail("Unknown question index.", 404);
      const correct = selected === q.answer;
      return {
        ok: true,
        correct,
        xpEarned: correct ? q.xp : 0,
        // Single-try, immediate reveal — matches LogAnalysisPlayer's existing UX.
        reveal: { answer: q.answer, explanation: q.explanation },
      };
    }

    case "flag": {
      const value = submission?.value;
      if (typeof value !== "string") return fail("value (string) is required.");
      const correct = value.trim().toLowerCase() === task.answer.trim().toLowerCase();
      return {
        ok: true,
        correct,
        xpEarned: correct ? task.xp : 0,
        // Never reveal the flag on a wrong guess — unlimited retries are the point.
        reveal: {},
      };
    }

    case "analyst_choice": {
      const verdict = submission?.verdict;
      if (typeof verdict !== "string") return fail("verdict (string) is required.");
      const attemptNumber = submission?.attemptNumber === 2 ? 2 : 1;
      const correct = verdict === task.correct_verdict;
      if (!correct && attemptNumber === 1) {
        return { ok: true, correct: false, xpEarned: 0, reveal: {} };
      }
      const xpEarned = correct ? (attemptNumber === 1 ? task.xp : Math.ceil(task.xp / 2)) : 0;
      return {
        ok: true,
        correct,
        xpEarned,
        reveal: { correct_verdict: task.correct_verdict, explanation: task.explanation, fp_trap: task.fp_trap },
      };
    }

    case "query_fill": {
      const values = submission?.values;
      if (!values || typeof values !== "object") return fail("values (object) is required.");
      const normalize = (s: string) => s.trim().toLowerCase().replace(/\s+/g, " ");
      const perBlank = task.blanks.map(b => {
        const given = typeof values[b.id] === "string" ? values[b.id] : "";
        const correct = b.answers.some(a => normalize(a) === normalize(given));
        return { id: b.id, correct, answers: b.answers };
      });
      const correctCount = perBlank.filter(b => b.correct).length;
      const allCorrect = correctCount === task.blanks.length;
      const xpEarned = Math.floor((task.xp * correctCount) / task.blanks.length);
      return {
        ok: true,
        correct: allCorrect,
        xpEarned,
        reveal: { blanks: perBlank, explanation: task.explanation },
      };
    }

    case "reading": {
      const checkpoint = task.checkpoint;
      if (!checkpoint) return fail("This reading has no checkpoint to grade.", 404);
      const selected = submission?.selectedIndex;
      if (typeof selected !== "number") return fail("selectedIndex (number) is required.");
      const correct = selected === checkpoint.answer;
      // Checkpoints are ungraded by design (see ReadingTask.checkpoint doc) — 0 XP here.
      return {
        ok: true,
        correct,
        xpEarned: 0,
        reveal: { answer: checkpoint.answer, explanation: checkpoint.explanation },
      };
    }

    default:
      return fail(`Task type "${task.type}" is not server-graded. Use the client-side board for matching/ordering.`, 501);
  }
}
