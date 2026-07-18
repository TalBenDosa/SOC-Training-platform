import { getQuiz } from "@/lib/quizzes/data";
import { QuizClient } from "./QuizClient";
import { QuizFromStorage } from "./QuizFromStorage";

export async function generateStaticParams() {
  const { QUIZZES } = await import("@/lib/quizzes/data");
  return QUIZZES.map(q => ({ slug: q.slug }));
}

export default async function QuizPage({ params }: { params: { slug: string } }) {
  const quiz = getQuiz(params.slug);

  // Known built-in quiz → render server-side
  if (quiz) return <QuizClient quiz={quiz} />;

  // Might be an AI-generated quiz stored in localStorage — delegate to client
  return <QuizFromStorage slug={params.slug} />;
}
