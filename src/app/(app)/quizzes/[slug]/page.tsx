import { getQuiz } from "@/lib/quizzes/data";
import { sanitizeQuiz } from "@/lib/quizzes/sanitize";
import { QuizClient } from "./QuizClient";
import { QuizFromStorage } from "./QuizFromStorage";

export async function generateStaticParams() {
  const { QUIZZES } = await import("@/lib/quizzes/data");
  return QUIZZES.map(q => ({ slug: q.slug }));
}

export default async function QuizPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const quiz = getQuiz(slug);

  // Known built-in quiz → render server-side. The answer key is stripped before
  // it enters the RSC payload (M-01); QuizClient grades via the server route.
  if (quiz) return <QuizClient quiz={sanitizeQuiz(quiz)} slug={slug} />;

  // Might be an AI-generated quiz stored in localStorage — delegate to client
  return <QuizFromStorage slug={slug} />;
}
