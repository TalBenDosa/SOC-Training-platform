/**
 * First-graded-answer policy (migration 0078, graded_first_answers).
 *
 * Quizzes, lesson knowledge checks and scenario questions reveal the correct
 * answer as soon as a question is graded. Without a memory of the FIRST answer,
 * a student could answer anything, read the key, and resubmit for full XP (and
 * the best attempt is what counts). The server therefore records each
 * question's first graded answer, once, and pays:
 *
 *   correct now AND first answer was correct → the question's full XP
 *   correct now but the first answer was not → half (rounded down)
 *   not correct now                          → 0
 *
 * So a retake can still earn something for learning the material, but never
 * the full credit of knowing it the first time.
 *
 * Pure rule + thin DB helpers (service-role client only — the table has no
 * client grants).
 */
import type { SupabaseClient } from "@supabase/supabase-js";

export type FirstAnswerKind = "quiz" | "lesson" | "scenario";

export interface GradedItem {
  questionId: string;
  xp: number;
  correct: boolean;
}

/** XP for one question under the first-answer rule. `firstCorrect` undefined = no first answer on record. */
export function firstAnswerXp(xp: number, correctNow: boolean, firstCorrect: boolean | undefined): number {
  if (!correctNow || !(xp > 0)) return 0;
  return firstCorrect === false ? Math.floor(xp / 2) : xp;
}

export function sumFirstAnswerXp(items: GradedItem[], first: Map<string, boolean>): number {
  return items.reduce((s, it) => s + firstAnswerXp(it.xp, it.correct, first.get(it.questionId)), 0);
}

/**
 * Records the first graded answer for each item (existing rows are kept — ON
 * CONFLICT DO NOTHING), then returns every first answer on record for this
 * content as questionId → correct. Returns null if storage failed, so the caller
 * can decide how to degrade.
 */
export async function recordAndLoadFirstAnswers(
  admin: SupabaseClient,
  userId: string,
  kind: FirstAnswerKind,
  contentId: string,
  answered: { questionId: string; answer: unknown; correct: boolean }[],
): Promise<Map<string, boolean> | null> {
  if (answered.length > 0) {
    const { error } = await admin.from("graded_first_answers").upsert(
      answered.map(a => ({
        user_id: userId, kind, content_id: contentId, question_id: a.questionId,
        answer: a.answer ?? null, correct: a.correct,
      })),
      { onConflict: "user_id,kind,content_id,question_id", ignoreDuplicates: true },
    );
    if (error) { console.error(`[first answers] record ${kind}/${contentId} failed:`, error.message); return null; }
  }
  const { data, error } = await admin.from("graded_first_answers")
    .select("question_id, correct")
    .eq("user_id", userId).eq("kind", kind).eq("content_id", contentId);
  if (error) { console.error(`[first answers] load ${kind}/${contentId} failed:`, error.message); return null; }
  return new Map((data ?? []).map(r => [String(r.question_id), !!r.correct]));
}

/** Share of first answers that must be right for a first-try lesson pass (matches the quiz grade route). */
export const LESSON_FIRST_TRY_PASS = 0.7;

/**
 * Lesson XP from the learner's first graded answers to its knowledge check:
 * full when they already passed (≥ 70%) on first answers, half otherwise. With
 * no first answers on record (a pass recorded before 0078) the full XP stands.
 */
export function lessonXpFromFirstAnswers(xp: number, firstCorrect: boolean[]): number {
  if (!(xp > 0)) return 0;
  if (firstCorrect.length === 0) return xp;
  const share = firstCorrect.filter(Boolean).length / firstCorrect.length;
  return share >= LESSON_FIRST_TRY_PASS ? xp : Math.floor(xp / 2);
}
