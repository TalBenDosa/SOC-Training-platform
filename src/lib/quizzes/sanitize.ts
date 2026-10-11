/**
 * Client-safe projection of a Quiz.
 *
 * SECURITY (M-01): the built-in quiz data (and org-published quiz content) carry
 * the answer key — `answer` (the correct option index) and `explanation` — on
 * every question. Handing the full Quiz to a Client Component embeds that key in
 * the RSC/HTML payload, readable in view-source before the learner answers.
 *
 * `sanitizeQuiz` strips both fields, mirroring `sanitizeRoom` for rooms and the
 * scenario GET allowlist. Correctness + explanation are revealed per-answered
 * question by POST /api/quizzes/[slug]/grade. `xp` is intentionally kept — it is
 * not secret and the UI shows it up front.
 */
import type { Quiz, QuizQuestion } from "@/lib/quizzes/data";

export type ClientQuizQuestion = Omit<QuizQuestion, "answer" | "explanation">;
export type ClientQuiz = Omit<Quiz, "questions"> & { questions: ClientQuizQuestion[] };

export function sanitizeQuizQuestion(q: QuizQuestion): ClientQuizQuestion {
  const { answer: _answer, explanation: _explanation, ...rest } = q;
  return rest;
}

export function sanitizeQuiz(quiz: Quiz): ClientQuiz {
  return { ...quiz, questions: quiz.questions.map(sanitizeQuizQuestion) };
}
