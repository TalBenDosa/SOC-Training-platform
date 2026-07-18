"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { QuizClient } from "./QuizClient";
import type { Quiz } from "@/lib/quizzes/data";

export function QuizFromStorage({ slug }: { slug: string }) {
  const [quiz, setQuiz]     = useState<Quiz | null | undefined>(undefined); // undefined = loading
  const [error, setError]   = useState(false);

  useEffect(() => {
    try {
      const stored: (Quiz & { id?: string })[] = JSON.parse(
        localStorage.getItem("generated_quizzes") ?? "[]"
      );
      // match by id OR slug (both are stored in generated quiz objects)
      const found = stored.find(q => q.id === slug || q.slug === slug) ?? null;
      setQuiz(found);
    } catch {
      setError(true);
    }
  }, [slug]);

  if (error || quiz === null) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-bg">
        <div className="text-center">
          <p className="text-4xl font-bold text-slate-600 mb-4">404</p>
          <p className="text-sm text-slate-400 mb-6">Quiz not found.</p>
          <Link
            href="/quizzes"
            className="rounded border border-cyber-500/30 bg-cyber-500/10 px-4 py-2 text-sm text-cyber-300 hover:bg-cyber-500/20 transition"
          >
            ← Back to Quizzes
          </Link>
        </div>
      </div>
    );
  }

  if (quiz === undefined) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-bg">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-cyber-500 border-t-transparent" />
      </div>
    );
  }

  return <QuizClient quiz={quiz} />;
}
