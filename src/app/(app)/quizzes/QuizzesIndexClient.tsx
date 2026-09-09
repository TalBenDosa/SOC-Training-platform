"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { Topbar } from "@/components/nav/Topbar";
import type { Quiz } from "@/lib/quizzes/data";
import { fetchPublishedQuizzes } from "@/lib/content/publicContent";
import { cn } from "@/lib/utils";
import { EyeOff } from "lucide-react";

/**
 * SECURITY (M-01): this is a Client Component, so anything it imports is shipped
 * in the browser bundle. It therefore must NEVER import the quiz DATA
 * (`ALL_QUIZZES`) — that would bundle every answer + explanation into the client
 * chunk, exactly the leak we are closing. The parent Server Component
 * (`page.tsx`) reads the data server-side and passes down only this
 * answer-FREE card metadata.
 */
export interface QuizCardMeta {
  slug: string;
  title: string;
  description: string;
  difficulty: string;
  category: string;
  icon: string;
  estimatedMinutes: number;
  questionCount: number;
  totalXp: number;
  generated?: boolean;
}

// ─── Colour helpers ────────────────────────────────────────────────────────────

const DIFF_COLORS: Record<string, string> = {
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

function QuizCard({ meta, href }: { meta: QuizCardMeta; href: string }) {
  const diffColor = DIFF_COLORS[meta.difficulty] ?? "bg-slate-500/10 text-slate-300 border-slate-500/30";
  const catColor  = CAT_COLORS[meta.category] ?? "text-slate-400";

  return (
    <Link
      href={href}
      className={cn(
        "group flex flex-col rounded border bg-[#0d1520] p-5 transition hover:bg-[#0e1e2e]",
        meta.generated ? "border-neon-green/20 hover:border-neon-green/40" : "border-border/60 hover:border-cyber-500/40"
      )}
    >
      {/* Icon + category */}
      <div className="flex items-start justify-between mb-3">
        <span className="text-3xl">{meta.icon}</span>
        <div className="flex items-center gap-2">
          {meta.generated && (
            <span className="rounded border border-neon-green/30 bg-neon-green/10 px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider text-neon-green">
              AI
            </span>
          )}
          <span className={cn("text-[10px] font-semibold uppercase tracking-widest", catColor)}>
            {meta.category}
          </span>
        </div>
      </div>

      {/* Title */}
      <h2 className="text-base font-bold text-white group-hover:text-cyber-300 transition mb-2">
        {meta.title}
      </h2>

      {/* Description */}
      <p className="text-xs text-slate-400 leading-relaxed flex-1 mb-4 line-clamp-3">
        {meta.description}
      </p>

      {/* Meta row */}
      <div className="flex items-center gap-2 flex-wrap">
        <span className={cn("rounded border px-2 py-0.5 text-[10px] font-semibold", diffColor)}>
          {meta.difficulty}
        </span>
        <span className="rounded bg-bg-elevated px-2 py-0.5 text-[10px] text-slate-400">
          {meta.questionCount} questions
        </span>
        <span className="rounded bg-bg-elevated px-2 py-0.5 text-[10px] text-slate-400">
          ~{meta.estimatedMinutes} min
        </span>
        <span className="ml-auto rounded bg-cyber-500/10 px-2 py-0.5 text-[10px] font-semibold text-cyber-300">
          +{meta.totalXp} XP
        </span>
      </div>
    </Link>
  );
}

// ─── Page body ───────────────────────────────────────────────────────────────

export function QuizzesIndexClient({ builtins }: { builtins: QuizCardMeta[] }) {
  const [hidden, setHidden]       = useState<string[]>([]);
  const [generated, setGenerated] = useState<QuizCardMeta[]>([]);

  useEffect(() => {
    try {
      setHidden(JSON.parse(localStorage.getItem("admin_hidden_quizzes") ?? "[]"));
    } catch { /* storage blocked */ }
    // Admin-published quizzes live in the durable content_quizzes table
    // (migration 0019). Map them down to answer-free card metadata here.
    fetchPublishedQuizzes<Quiz & { id?: string }>().then(rows => {
      setGenerated(rows.map(q => ({
        slug: q.id ?? q.slug,
        title: q.title,
        description: q.description,
        difficulty: q.difficulty,
        category: q.category,
        icon: q.icon,
        estimatedMinutes: q.estimatedMinutes,
        questionCount: q.questions?.length ?? 0,
        totalXp: (q.questions ?? []).reduce((s, x) => s + (x?.xp ?? 0), 0),
        generated: true,
      })));
    });
  }, []);

  const visible = builtins.filter(q => !hidden.includes(q.slug));
  const allQuizzes = [...generated, ...visible];

  const totalQuestions = allQuizzes.reduce((s, q) => s + q.questionCount, 0);
  const totalXp        = allQuizzes.reduce((s, q) => s + q.totalXp, 0);

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
              <p className="mt-1 text-xs text-slate-400">{s.label}</p>
            </div>
          ))}
        </div>

        {/* Hidden notice */}
        {hidden.length > 0 && (
          <div className="mb-6 flex items-center gap-2 rounded border border-border/40 bg-bg-elevated px-4 py-2 text-[11px] text-slate-400">
            <EyeOff className="h-3.5 w-3.5 shrink-0" />
            {hidden.length} quiz{hidden.length > 1 ? "zes" : ""} hidden by admin — manage in Admin → Content Library
          </div>
        )}

        {/* Quiz cards */}
        <div className="grid grid-cols-1 gap-5 md:grid-cols-2 lg:grid-cols-3">
          {/* Generated quizzes first (link by slug; QuizFromStorage matches by slug or id) */}
          {generated.map(meta => (
            <QuizCard key={meta.slug} meta={meta} href={`/quizzes/${meta.slug}`} />
          ))}

          {/* Built-in quizzes */}
          {visible.map(meta => (
            <QuizCard key={meta.slug} meta={meta} href={`/quizzes/${meta.slug}`} />
          ))}
        </div>

        {allQuizzes.length === 0 && (
          <div className="flex flex-col items-center justify-center rounded border border-border/40 bg-bg-elevated py-16 text-center">
            <p className="text-sm text-slate-400">All quizzes are hidden.</p>
            <p className="text-xs text-slate-400 mt-1">Restore them in Admin → Content Library.</p>
          </div>
        )}
      </div>
    </div>
  );
}
