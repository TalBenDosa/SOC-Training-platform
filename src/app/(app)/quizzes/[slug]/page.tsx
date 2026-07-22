import { getQuiz } from "@/lib/quizzes/data";
import { QuizClient } from "./QuizClient";
import { QuizFromStorage } from "./QuizFromStorage";

export async function generateStaticParams() {
  const { QUIZZES } = await import("@/lib/quizzes/data");
  return QUIZZES.map(q => ({ slug: q.slug }));
}

export default async function QuizPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const quiz = getQuiz(slug);

  // Known built-in quiz → render server-side
  if (quiz) return <QuizClient quiz={quiz} />;

  // Might be an AI-generated quiz stored in localStorage — delegate to client
  return <QuizFromStorage slug={slug} />;
}
