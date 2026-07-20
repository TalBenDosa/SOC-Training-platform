"use client";
import { useEffect, useState, useMemo } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import {
  ArrowLeft, ArrowRight, BookOpen, CheckCircle2, ChevronLeft,
  Loader2, Star, X,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/Button";
import { findLesson, adjacentLessons } from "@/lib/lessons/paths";
import { MermaidDiagram } from "@/components/rooms/MermaidDiagram";
import { isMermaidSource } from "@/lib/lessons/mermaid";
import { shuffleSeeded } from "@/lib/lessons/shuffle";
import type { GeneratedLesson, LessonPage, LessonQuizQuestion } from "@/app/api/lessons/[slug]/route";

// ─── Markdown renderer (lightweight, no external dep) ────────────────────────

function MarkdownBlock({ text }: { text: string }) {
  // SECURITY: this text is AI-generated (and can be influenced by user-supplied
  // generation prompts), so it is UNTRUSTED. Escape HTML-significant characters
  // FIRST — before any markdown→HTML replacement — so an injected tag like
  // `<img src=x onerror=…>` or `<script>` becomes inert text. We deliberately do
  // NOT escape `>` because it can't open a tag on its own and is used by the
  // blockquote markdown below; escaping `&` and `<` is sufficient to prevent all
  // tag injection. Every tag emitted after this point is one of our own
  // whitelisted formatting tags, so the final HTML is safe to render.
  const html = text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/^### (.+)$/gm, '<h3 class="mt-5 mb-2 text-base font-bold text-white">$1</h3>')
    .replace(/^## (.+)$/gm, '<h2 class="mt-6 mb-3 text-lg font-bold text-white">$1</h2>')
    .replace(/^# (.+)$/gm, '<h1 class="mt-6 mb-3 text-xl font-bold text-white">$1</h1>')
    .replace(/\*\*(.+?)\*\*/g, '<strong class="text-white font-semibold">$1</strong>')
    .replace(/`([^`]+)`/g, '<code class="rounded bg-bg px-1.5 py-0.5 font-mono text-xs text-cyber-300">$1</code>')
    .replace(/^> (.+)$/gm, '<blockquote class="border-l-4 border-cyber-500/40 pl-4 italic text-slate-400 my-3">$1</blockquote>')
    .replace(/^- (.+)$/gm, '<li class="ml-4 list-disc text-slate-300 my-1">$1</li>')
    .replace(/(<li[^>]*>.*<\/li>\n?)+/g, m => `<ul class="my-3 space-y-1">${m}</ul>`)
    .replace(/\n\n/g, '</p><p class="my-3 text-slate-300 leading-relaxed">')
    .replace(/^(?!<[hbuclp])/, '<p class="my-3 text-slate-300 leading-relaxed">')
    .replace(/$(?<![>])/, '</p>');
  return (
    <div
      className="prose-sm max-w-none"
      dangerouslySetInnerHTML={{ __html: html }}
    />
  );
}

// ─── Loading skeleton ─────────────────────────────────────────────────────────

function LoadingSkeleton() {
  return (
    <div className="animate-pulse space-y-4 p-6">
      <div className="h-4 w-3/4 rounded bg-bg-elevated" />
      <div className="h-3 w-full rounded bg-bg-elevated" />
      <div className="h-3 w-5/6 rounded bg-bg-elevated" />
      <div className="h-3 w-full rounded bg-bg-elevated" />
      <div className="h-3 w-4/5 rounded bg-bg-elevated" />
      <div className="mt-6 h-24 w-full rounded bg-bg-elevated" />
      <div className="h-3 w-full rounded bg-bg-elevated" />
      <div className="h-3 w-3/4 rounded bg-bg-elevated" />
      <p className="mt-4 flex items-center gap-2 text-xs text-slate-500">
        <Loader2 className="h-3.5 w-3.5 animate-spin" />
        Generating lesson content with AI…
      </p>
    </div>
  );
}

// ─── Quiz component ───────────────────────────────────────────────────────────

function Quiz({
  questions,
  onPass,
}: {
  questions: LessonQuizQuestion[];
  onPass: () => void;
}) {
  const [answers, setAnswers] = useState<Record<number, string>>({});
  const [submitted, setSubmitted] = useState(false);
  const [score, setScore] = useState(0);

  /**
   * Display order for each question's options.
   *
   * WHY: across the platform's 92 lesson quiz questions the correct answer was
   * "b" 72 times, "c" 17, "a" 3 and "d" never — so always picking "b" scored
   * 78% without reading anything. Authors reach for the second slot, and no
   * amount of care per-lesson fixes a bias that only shows up in aggregate.
   * Shuffling at render time fixes it for existing AND future content, which
   * hand-rebalancing the data files would not.
   *
   * Deterministic, not random: seeded by the question text so a given question
   * always presents in the same order. A fresh order on every keystroke would
   * make options jump under the cursor mid-answer, and re-ordering after
   * submission would scramble the results the learner is reading.
   *
   * SAFE because grading compares opt.value to q.answer (see handleSubmit) —
   * it never depends on position. Only the visual order changes.
   */
  const shuffled = useMemo(
    () => questions.map(q => shuffleSeeded(q.options, q.question)),
    [questions],
  );

  const handleSubmit = () => {
    let correct = 0;
    for (let i = 0; i < questions.length; i++) {
      if (answers[i] === questions[i].answer) correct++;
    }
    setScore(correct);
    setSubmitted(true);
    if ((correct / questions.length) >= 0.7) {
      onPass();
    }
  };

  const pct = submitted ? Math.round((score / questions.length) * 100) : null;
  const passed = pct !== null && pct >= 70;

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <BookOpen className="h-5 w-5 text-cyber-300" />
        <h3 className="text-base font-semibold text-white">Knowledge Check</h3>
        <span className="text-xs text-slate-500">{questions.length} questions · 70% to pass</span>
      </div>

      {questions.map((q, i) => (
        <div key={i} className="rounded-lg border border-border bg-bg p-4">
          <p className="mb-3 text-sm font-semibold text-slate-100">
            {i + 1}. {q.question}
          </p>
          <div className="space-y-2">
            {shuffled[i].map(opt => {
              const isSelected = answers[i] === opt.value;
              const isCorrect  = submitted && opt.value === q.answer;
              const isWrong    = submitted && isSelected && opt.value !== q.answer;
              return (
                <label
                  key={opt.value}
                  className={cn(
                    "flex cursor-pointer items-start gap-3 rounded border p-2.5 text-sm transition",
                    submitted
                      ? isCorrect  ? "border-neon-green/50 bg-neon-green/5 text-neon-green"
                        : isWrong  ? "border-severity-critical/50 bg-severity-critical/5 text-severity-critical"
                        :            "border-border bg-bg text-slate-400"
                      : isSelected ? "border-cyber-500/50 bg-cyber-500/10 text-white"
                                   : "border-border bg-bg text-slate-300 hover:border-border-strong"
                  )}
                >
                  <input
                    type="radio"
                    disabled={submitted}
                    checked={isSelected}
                    onChange={() => setAnswers(prev => ({ ...prev, [i]: opt.value }))}
                    className="mt-0.5 accent-cyber-500"
                  />
                  <span>{opt.label}</span>
                  {submitted && isCorrect && <CheckCircle2 className="ml-auto h-4 w-4 shrink-0" />}
                </label>
              );
            })}
          </div>
          {submitted && (
            <p className="mt-2 text-xs text-slate-400">
              <span className="font-semibold">Explanation:</span> {q.explanation}
            </p>
          )}
        </div>
      ))}

      {!submitted ? (
        <Button
          variant="primary"
          onClick={handleSubmit}
          disabled={Object.keys(answers).length < questions.length}
        >
          Submit Quiz
        </Button>
      ) : (
        <div className={cn(
          "rounded-lg border p-4",
          passed
            ? "border-neon-green/40 bg-neon-green/5 text-neon-green"
            : "border-severity-high/40 bg-severity-high/5 text-severity-high"
        )}>
          <p className="font-semibold">
            {passed ? `✓ Passed! ${score}/${questions.length} correct (${pct}%)` : `✗ ${score}/${questions.length} correct (${pct}%). Need 70% to complete lesson.`}
          </p>
          {!passed && (
            <button
              onClick={() => { setAnswers({}); setSubmitted(false); }}
              className="mt-2 text-sm underline"
            >
              Retry quiz
            </button>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Page renderer ────────────────────────────────────────────────────────────

function LessonPageView({ page }: { page: LessonPage }) {
  return (
    <div className="space-y-4">
      <h2 className="text-xl font-bold text-white">{page.title}</h2>
      <MarkdownBlock text={page.body} />
      {/* Mermaid source renders as a diagram; anything else (SPL/KQL queries,
          comparison tables) stays a code block. Without this branch a lesson
          diagram displayed as literal `flowchart TD` text — the component
          existed but had only ever been wired into rooms. */}
      {page.codeExample && (
        isMermaidSource(page.codeExample)
          ? <MermaidDiagram chart={page.codeExample} />
          : (
            <div className="overflow-x-auto rounded border border-border bg-bg">
              <pre className="p-4 font-mono text-xs text-neon-green leading-relaxed">{page.codeExample}</pre>
            </div>
          )
      )}
      {page.keyPoints.length > 0 && (
        <div className="rounded border border-cyber-500/20 bg-cyber-500/5 p-4">
          <p className="mb-2 text-[10px] font-semibold uppercase tracking-widest text-cyber-300">Key Takeaways</p>
          <ul className="space-y-1.5">
            {page.keyPoints.map((pt, i) => (
              <li key={i} className="flex items-start gap-2 text-sm text-slate-300">
                <span className="mt-0.5 h-1.5 w-1.5 shrink-0 rounded-full bg-cyber-400" />
                {pt}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

// ─── Main lesson reader ───────────────────────────────────────────────────────

export default function LessonReader() {
  const params = useParams<{ slug: string; lesson: string }>();
  const router = useRouter();

  const [content, setContent] = useState<GeneratedLesson | null>(null);
  const [loading, setLoading] = useState(true);
  const [pageIdx, setPageIdx] = useState(0);
  const [quizPassed, setQuizPassed] = useState(false);
  const [completed, setCompleted] = useState(false);
  const [showCompleteToast, setShowCompleteToast] = useState(false);

  const meta = findLesson(params.slug, params.lesson);
  const adjacent = adjacentLessons(params.slug, params.lesson);
  const totalPages = (content?.pages.length ?? 10) + 1; // +1 for quiz
  const isQuizPage = content !== null && pageIdx === content.pages.length;
  const progress = Math.round(((pageIdx + 1) / totalPages) * 100);

  useEffect(() => {
    setLoading(true);
    fetch(`/api/lessons/${encodeURIComponent(`${params.slug}--${params.lesson}`)}`)
      .then(r => r.json())
      .then((data: GeneratedLesson) => {
        setContent(data);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, [params.slug, params.lesson]);

  const handleComplete = () => {
    setCompleted(true);
    setShowCompleteToast(true);
    setTimeout(() => setShowCompleteToast(false), 3000);
  };

  const currentPage = content?.pages[pageIdx];

  return (
    <div className="min-h-screen bg-bg">
      {/* Completion toast */}
      {showCompleteToast && (
        <div className="fixed right-6 top-6 z-50 flex items-center gap-2 rounded-lg border border-neon-green/40 bg-neon-green/10 px-4 py-3 text-sm font-semibold text-neon-green shadow-lg">
          <CheckCircle2 className="h-4 w-4" />
          Lesson complete! +{meta?.lesson.xp ?? 75} XP
        </div>
      )}

      {/* Header */}
      <header className="sticky top-0 z-30 border-b border-border bg-bg/80 px-6 py-3 backdrop-blur">
        <div className="mx-auto flex max-w-4xl items-center gap-4">
          <Link href={`/learn/${params.slug}`} className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-white">
            <ChevronLeft className="h-4 w-4" /> Back
          </Link>
          <div className="flex-1">
            {meta && (
              <p className="text-xs text-slate-500">
                {meta.path.title} · {meta.module.title}
              </p>
            )}
            <h1 className="text-sm font-semibold text-white">{meta?.lesson.title ?? "Loading…"}</h1>
          </div>
          <div className="flex items-center gap-2 text-xs text-slate-400">
            <span className="font-mono text-cyber-300">+{meta?.lesson.xp ?? 75} XP</span>
          </div>
        </div>

        {/* Progress bar */}
        <div className="mx-auto mt-2 max-w-4xl">
          <div className="flex items-center gap-3">
            <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-bg-elevated">
              <div
                className="h-full rounded-full bg-gradient-to-r from-cyber-500 to-neon-green transition-all duration-300"
                style={{ width: `${progress}%` }}
              />
            </div>
            <span className="text-[10px] font-mono text-slate-500">
              {isQuizPage ? "Quiz" : `Page ${pageIdx + 1}`} / {totalPages}
            </span>
          </div>
        </div>
      </header>

      {/* Content */}
      <main className="mx-auto max-w-4xl px-6 py-8">
        {loading ? (
          <LoadingSkeleton />
        ) : !content ? (
          <p className="text-slate-400">Failed to load lesson content.</p>
        ) : isQuizPage ? (
          <Quiz
            questions={content.quiz}
            onPass={() => setQuizPassed(true)}
          />
        ) : currentPage ? (
          <LessonPageView page={currentPage} />
        ) : null}

        {/* Navigation */}
        {!loading && content && (
          <div className="mt-10 flex items-center justify-between border-t border-border pt-6">
            <button
              onClick={() => setPageIdx(i => Math.max(0, i - 1))}
              disabled={pageIdx === 0}
              className="flex items-center gap-2 rounded border border-border px-3 py-2 text-sm text-slate-300 hover:bg-bg-hover disabled:opacity-30"
            >
              <ArrowLeft className="h-4 w-4" /> Previous
            </button>

            <div className="flex gap-1.5">
              {Array.from({ length: totalPages }).map((_, i) => (
                <button
                  key={i}
                  onClick={() => setPageIdx(i)}
                  className={cn(
                    "h-2 rounded-full transition-all",
                    i === pageIdx
                      ? "w-6 bg-cyber-400"
                      : i < pageIdx
                      ? "w-2 bg-neon-green/60"
                      : "w-2 bg-bg-elevated"
                  )}
                />
              ))}
            </div>

            {isQuizPage && quizPassed ? (
              !completed ? (
                <button
                  onClick={handleComplete}
                  className="flex items-center gap-2 rounded bg-neon-green/10 border border-neon-green/40 px-4 py-2 text-sm font-semibold text-neon-green hover:bg-neon-green/20"
                >
                  <CheckCircle2 className="h-4 w-4" /> Mark Complete
                </button>
              ) : adjacent.next ? (
                <Link href={`/learn/${params.slug}/${adjacent.next.slug}`}>
                  <Button variant="primary" size="sm">
                    Next Lesson <ArrowRight className="h-4 w-4" />
                  </Button>
                </Link>
              ) : (
                <Link href={`/learn/${params.slug}`}>
                  <Button variant="outline" size="sm">Back to Path</Button>
                </Link>
              )
            ) : (
              <button
                onClick={() => setPageIdx(i => Math.min(totalPages - 1, i + 1))}
                disabled={pageIdx === totalPages - 1}
                className="flex items-center gap-2 rounded border border-cyber-500/40 bg-cyber-500/10 px-3 py-2 text-sm font-semibold text-cyber-300 hover:bg-cyber-500/20 disabled:opacity-30"
              >
                {pageIdx === content.pages.length - 1 ? "Take Quiz" : "Next"} <ArrowRight className="h-4 w-4" />
              </button>
            )}
          </div>
        )}
      </main>
    </div>
  );
}
