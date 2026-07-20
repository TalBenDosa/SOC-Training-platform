"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { Topbar } from "@/components/nav/Topbar";
import { ALL_QUIZZES as QUIZZES } from "@/lib/quizzes/data";
import type { Quiz } from "@/lib/quizzes/data";
import type { GeneratedQuiz } from "@/app/api/quizzes/generate/route";
import { cn } from "@/lib/utils";
import { EyeOff } from "lucide-react";

// ─── Colour helpers ────────────────────────────────────────────────────────────

const DIFF_COLORS = {
  Beginner:     "bg-neon-green/10 text-neon-green border-neon-green/30",
  Intermediate: "bg-neon-amber/10 text-neon-amber border-neon-amber/30",
  Advanced:     "bg-severity-high/10 text-severity-high border-severity-high/30",
};

const CAT_COLORS: Record<string, string> = {
  "Threat Framework":    "text-neon-purple",
  "SOC Fundamentals":    "text-cyber-300",
  "Threat Intelligence": "text-neon-amber",
  "Network":             "text-neon-blue",
  "Cloud Security":      "text-neon-green",
};

// ─── Quiz card ─────────────────────────────────────────────────────────────────

function QuizCard({ quiz, generated, href }: { quiz: Quiz; generated?: boolean; href: string }) {
  const totalXp  = quiz.questions.reduce((s, q) => s + q.xp, 0);
  const diffKey  = quiz.difficulty as keyof typeof DIFF_COLORS;
  const diffColor = DIFF_COLORS[diffKey] ?? "bg-slate-500/10 text-slate-300 border-slate-500/30";
  const catColor  = CAT_COLORS[quiz.category] ?? "text-slate-400";

  return (
    <Link
      href={href}
      className={cn(
        "group flex flex-col rounded border bg-[#0d1520] p-5 transition hover:bg-[#0e1e2e]",
        generated ? "border-neon-green/20 hover:border-neon-green/40" : "border-border/60 hover:border-cyber-500/40"
      )}
    >
      {/* Icon + category */}
      <div className="flex items-start justify-between mb-3">
        <span className="text-3xl">{quiz.icon}</span>
        <div className="flex items-center gap-2">
          {generated && (
            <span className="rounded border border-neon-green/30 bg-neon-green/10 px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider text-neon-green">
              AI
            </span>
          )}
          <span className={cn("text-[10px] font-semibold uppercase tracking-widest", catColor)}>
            {quiz.category}
          </span>
        </div>
      </div>

      {/* Title */}
      <h2 className="text-base font-bold text-white group-hover:text-cyber-300 transition mb-2">
        {quiz.title}
      </h2>

      {/* Description */}
      <p className="text-xs text-slate-400 leading-relaxed flex-1 mb-4 line-clamp-3">
        {quiz.description}
      </p>

      {/* Meta row */}
      <div className="flex items-center gap-2 flex-wrap">
        <span className={cn("rounded border px-2 py-0.5 text-[10px] font-semibold", diffColor)}>
          {quiz.difficulty}
        </span>
        <span className="rounded bg-bg-elevated px-2 py-0.5 text-[10px] text-slate-400">
          {quiz.questions.length} questions
        </span>
        <span className="rounded bg-bg-elevated px-2 py-0.5 text-[10px] text-slate-400">
          ~{quiz.estimatedMinutes} min
        </span>
        <span className="ml-auto rounded bg-cyber-500/10 px-2 py-0.5 text-[10px] font-semibold text-cyber-300">
          +{totalXp} XP
        </span>
      </div>
    </Link>
  );
}

// ─── Page ──────────────────────────────────────────────────────────────────────

export default function QuizzesPage() {
  const [hidden, setHidden]       = useState<string[]>([]);
  const [generated, setGenerated] = useState<GeneratedQuiz[]>([]);

  useEffect(() => {
    try {
      setHidden(JSON.parse(localStorage.getItem("admin_hidden_quizzes") ?? "[]"));
      setGenerated(JSON.parse(localStorage.getItem("generated_quizzes") ?? "[]"));
    } catch { /* storage blocked */ }
  }, []);

  const visible    = QUIZZES.filter(q => !hidden.includes(q.slug));
  const allQuizzes: Quiz[] = [...generated, ...visible];

  const totalQuestions = allQuizzes.reduce((s, q) => s + q.questions.length, 0);
  const totalXp        = allQuizzes.reduce((s, q) =>
    s + q.questions.reduce((sq, question) => sq + question.xp, 0), 0);

  return (
    <div className="min-h-screen bg-bg">
      <Topbar title="Knowledge Quizzes" subtitle="Test your SOC analyst knowledge across key domains" />

      <div className="container mx-auto max-w-[1200px] px-6 py-8">

        {/* Stats row */}
        <div className="mb-8 grid grid-cols-3 gap-4">
          {[
            { label: "Quizzes Available", value: allQuizzes.length },
            { label: "Total Questions",   value: totalQuestions },
            { label: "Max XP Earnable",   value: `+${totalXp}` },
          ].map(s => (
            <div key={s.label} className="rounded border border-border/60 bg-[#0d1520] px-5 py-4">
              <p className="font-mono text-2xl font-bold text-cyber-300">{s.value}</p>
              <p className="mt-1 text-xs text-slate-500">{s.label}</p>
            </div>
          ))}
        </div>

        {/* Hidden notice */}
        {hidden.length > 0 && (
          <div className="mb-6 flex items-center gap-2 rounded border border-border/40 bg-bg-elevated px-4 py-2 text-[11px] text-slate-500">
            <EyeOff className="h-3.5 w-3.5 shrink-0" />
            {hidden.length} quiz{hidden.length > 1 ? "zes" : ""} hidden by admin — manage in Admin → Content Library
          </div>
        )}

        {/* Quiz cards */}
        <div className="grid grid-cols-1 gap-5 md:grid-cols-2 lg:grid-cols-3">
          {/* Generated quizzes first (link by slug; QuizFromStorage matches by slug or id) */}
          {generated.map(quiz => (
            <QuizCard
              key={quiz.id}
              quiz={quiz}
              generated
              href={`/quizzes/${quiz.id}`}
            />
          ))}

          {/* Built-in quizzes */}
          {visible.map(quiz => (
            <QuizCard
              key={quiz.slug}
              quiz={quiz}
              href={`/quizzes/${quiz.slug}`}
            />
          ))}
        </div>

        {allQuizzes.length === 0 && (
          <div className="flex flex-col items-center justify-center rounded border border-border/40 bg-bg-elevated py-16 text-center">
            <p className="text-sm text-slate-400">All quizzes are hidden.</p>
            <p className="text-xs text-slate-600 mt-1">Restore them in Admin → Content Library.</p>
          </div>
        )}
      </div>
    </div>
  );
}
