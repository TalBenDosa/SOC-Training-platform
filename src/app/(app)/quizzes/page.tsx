/**
 * Quizzes index (Server Component).
 *
 * SECURITY (M-01): the quiz catalogue carries the answer key. This page reads it
 * server-side and passes ONLY answer-free card metadata to the client — so
 * `ALL_QUIZZES` (with its `answer`/`explanation` on every question) is never
 * bundled into the browser. Previously this page was a Client Component that
 * imported the data directly, shipping the entire answer key in the client
 * chunk and defeating the per-quiz sanitisation.
 */
import { ALL_QUIZZES } from "@/lib/quizzes/data";
import { QuizzesIndexClient, type QuizCardMeta } from "./QuizzesIndexClient";

export default function QuizzesPage() {
  const builtins: QuizCardMeta[] = ALL_QUIZZES.map(q => ({
    slug: q.slug,
    title: q.title,
    description: q.description,
    difficulty: q.difficulty,
    category: q.category,
    icon: q.icon,
    estimatedMinutes: q.estimatedMinutes,
    questionCount: q.questions.length,
    totalXp: q.questions.reduce((s, x) => s + x.xp, 0),
  }));

  return <QuizzesIndexClient builtins={builtins} />;
}
