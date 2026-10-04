"use client";
import { ApiError, messageFromResponse, userMessageFor } from "@/lib/http/apiError";
import { useEffect, useState, useMemo } from "react";
import { labelForLang, lessonMarkdownToHtml } from "@/lib/lessons/lessonMarkdown";
import { useParams } from "next/navigation";
import Link from "next/link";
import {
  ArrowLeft, ArrowRight, BookOpen, CheckCircle2, ChevronLeft,
  Loader2,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/Button";
import { findLesson, adjacentLessons } from "@/lib/lessons/paths";
import { MermaidDiagram } from "@/components/rooms/MermaidDiagram";
import { LessonFigure } from "@/components/lessons/LessonFigure";
import { LessonVideo } from "@/components/lessons/LessonVideo";
import { isMermaidSource } from "@/lib/lessons/mermaid";
import { shuffleSeeded } from "@/lib/lessons/shuffle";
import type { ClientLesson, LessonPage, ClientLessonQuizQuestion } from "@/app/api/lessons/[slug]/route";
import { addTotalXp, setTotalXp, recordLessonActivity } from "@/lib/storage/progress";
import { ListenButton } from "@/components/media/ListenButton";

// Guests (no account) keep completed lessons locally so a lesson's XP is added
// to their device total once, never on every "Mark Complete".
const GUEST_LESSON_DONE_KEY = "soc_lesson_done_local";

// What the server actually credited for this lesson — the toast shows THIS,
// never the catalog number (which used to be shown with nothing recorded).
type CompleteState =
  | { status: "idle" | "saving" }
  | { status: "credited"; credited: number }
  | { status: "already"; xpEarned: number }
  | { status: "guest"; credited: number }
  | { status: "error"; message: string };

// Per-question grade result returned by POST /api/lessons/[slug]/quiz/grade.
// `answer`/`explanation` are non-null only for a question that was answered.
interface LessonQuizResult {
  index: number;
  correct: boolean;
  answer: string | null;
  explanation: string | null;
}

// ─── Markdown renderer (lightweight, no external dep) ────────────────────────

// Type label for a fenced-code card's header. Kept in sync with the modal reader
// (learn/page.tsx) so both surfaces render the same "code/example" card.

// JSX twin of the fenced-code card (used for a page's standalone codeExample).
// Same markup/classes as the modal reader's CodeCard so the two stay identical.
function CodeCard({ label, code }: { label: string; code: string }) {
  return (
    <div className="my-4 overflow-hidden rounded-xl border border-slate-700/50 bg-[#0a0f1c] shadow-sm">
      <div className="flex items-center justify-between border-b border-slate-700/40 bg-slate-800/25 px-4 py-2">
        <span className="flex gap-1.5" aria-hidden="true">
          <span className="h-2.5 w-2.5 rounded-full bg-red-400/40" />
          <span className="h-2.5 w-2.5 rounded-full bg-amber-400/40" />
          <span className="h-2.5 w-2.5 rounded-full bg-emerald-400/40" />
        </span>
        <span className="font-mono text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-500">{label}</span>
      </div>
      <pre className="overflow-x-auto px-4 py-3.5 font-mono text-[12.5px] leading-relaxed text-slate-200"><code>{code}</code></pre>
    </div>
  );
}

function MarkdownBlock({ text }: { text: string }) {
  // SECURITY: this text is AI-generated (and can be influenced by user-supplied
  // generation prompts), so it is UNTRUSTED. Escape HTML-significant characters
  // FIRST — before any markdown→HTML replacement — so an injected tag like
  // `<img src=x onerror=…>` or `<script>` becomes inert text. We deliberately do
  // NOT escape `>` because it can't open a tag on its own and is used by the
  // blockquote markdown below; escaping `&` and `<` is sufficient to prevent all
  // tag injection. Every tag emitted after this point is one of our own
  // whitelisted formatting tags, so the final HTML is safe to render.
  // Pull fenced ```code``` blocks out FIRST, into placeholders, so their pipes /
  // blank lines survive the markdown replacements below. Their inner text is
  // HTML-escaped here (same &/< rule) and re-inserted as <pre> at the very end.
  const finalHtml = lessonMarkdownToHtml(text);
  return (
    <div
      className="prose-sm max-w-none"
      dangerouslySetInnerHTML={{ __html: finalHtml }}
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
      <p className="mt-4 flex items-center gap-2 text-xs text-slate-400">
        <Loader2 className="h-3.5 w-3.5 animate-spin" />
        Loading lesson…
      </p>
    </div>
  );
}

// ─── Quiz component ───────────────────────────────────────────────────────────

function Quiz({
  questions,
  gradeEndpoint,
  onPass,
}: {
  questions: ClientLessonQuizQuestion[];
  gradeEndpoint: string;
  onPass: () => void;
}) {
  const [answers, setAnswers] = useState<Record<number, string>>({});
  const [submitted, setSubmitted] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Per-question grading comes back from the server keyed by question index.
  // The client no longer knows any answer until it has submitted (M-01).
  const [results, setResults] = useState<Record<number, LessonQuizResult>>({});
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
   * SAFE because grading is server-side by option value — it never depends on
   * position. Only the visual order changes.
   */
  const shuffled = useMemo(
    () => questions.map(q => shuffleSeeded(q.options, q.question)),
    [questions],
  );

  const handleSubmit = async () => {
    if (submitting) return;
    setSubmitting(true);
    setError(null);
    try {
      const res = await fetch(gradeEndpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ answers }),
      });
      if (!res.ok) throw new ApiError(await messageFromResponse(res), res.status);
      const data: { results: LessonQuizResult[]; correct: number; score: number; passed: boolean } = await res.json();
      const map: Record<number, LessonQuizResult> = {};
      for (const r of data.results) map[r.index] = r;
      setResults(map);
      setScore(data.correct);
      setSubmitted(true);
      if (data.passed) onPass();
    } catch (e) {
      // E-09: an expired session / licence / "slow down" says so — not "check your connection".
      setError(`Couldn't grade the quiz — ${userMessageFor(e)}`);
    } finally {
      setSubmitting(false);
    }
  };

  const pct = submitted ? Math.round((score / questions.length) * 100) : null;
  const passed = pct !== null && pct >= 70;

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <BookOpen className="h-5 w-5 text-cyber-300" />
        <h3 className="text-base font-semibold text-white">Knowledge Check</h3>
        <span className="text-xs text-slate-400">{questions.length} questions · 70% to pass</span>
      </div>

      {questions.map((q, i) => (
        <div key={i} className="rounded-lg border border-border bg-bg p-4">
          <p className="mb-3 text-sm font-semibold text-slate-100">
            {i + 1}. {q.question}
          </p>
          <div className="space-y-2">
            {shuffled[i].map(opt => {
              const isSelected = answers[i] === opt.value;
              const isCorrect  = submitted && opt.value === results[i]?.answer;
              const isWrong    = submitted && isSelected && opt.value !== results[i]?.answer;
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
          {submitted && results[i]?.explanation && (
            <p className="mt-2 text-xs text-slate-400">
              <span className="font-semibold">Explanation:</span> {results[i]?.explanation}
            </p>
          )}
        </div>
      ))}

      {error && (
        <p className="text-sm text-severity-high">{error}</p>
      )}

      {!submitted ? (
        <Button
          variant="primary"
          onClick={handleSubmit}
          disabled={submitting || Object.keys(answers).length < questions.length}
        >
          {submitting ? "Grading…" : "Submit Quiz"}
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
              onClick={() => { setAnswers({}); setSubmitted(false); setResults({}); setError(null); }}
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
  // FB-009: what "Listen" reads — the page as the learner sees it (title, body,
  // key takeaways). Code/diagram blocks are summarised by toSpeechText.
  const speech = [
    `${page.title}.`,
    page.body,
    page.keyPoints.length ? `Key takeaways.\n${page.keyPoints.map(p => `- ${p}`).join("\n")}` : "",
  ].filter(Boolean).join("\n\n");
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-xl font-bold text-white">{page.title}</h2>
        <ListenButton text={speech} />
      </div>
      {/* Authored explainer video leads the page (curated lessons only), rendered
          through the shared LessonVideo so this reader and the /learn modal stay
          in sync — the same reason codeExample/image are shared. */}
      {page.video?.src && <LessonVideo video={page.video} />}
      <MarkdownBlock text={page.body} />
      {/* Mermaid source renders as a diagram; anything else (SPL/KQL queries,
          comparison tables) stays a code block. Without this branch a lesson
          diagram displayed as literal `flowchart TD` text — the component
          existed but had only ever been wired into rooms. */}
      {page.codeExample && (
        isMermaidSource(page.codeExample)
          ? <MermaidDiagram chart={page.codeExample} />
          : <CodeCard label="Example" code={page.codeExample} />
      )}
      {/* Optional still image (curated lessons only). Now rendered through the
          SHARED LessonFigure so this reader and the /learn modal cannot drift
          apart the way codeExample once did. */}
      {page.image?.src && <LessonFigure image={page.image} />}
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

/** Shown instead of pages + quiz while a Learning Path lesson has no content. */
function PreparingNotice({ title, related, backHref }: { title: string; related: { id: string; title: string }[]; backHref: string }) {
  return (
    <div className="rounded-xl border border-border bg-bg-card p-6 sm:p-8">
      <div className="flex items-center gap-2 text-cyber-300">
        <BookOpen className="h-5 w-5" />
        <p className="text-xs font-semibold uppercase tracking-wider">Lesson in preparation</p>
      </div>
      <h2 className="mt-3 text-xl font-bold text-white">{title}</h2>
      <p className="mt-2 max-w-prose text-sm leading-relaxed text-slate-300">
        This lesson is being finalised and isn&apos;t published yet. Until it is, these lessons from the
        Lesson Library cover the same ground in depth:
      </p>
      {related.length > 0 ? (
        <ul className="mt-5 space-y-2">
          {related.map(r => (
            <li key={r.id}>
              <Link
                href={`/learn?open=${encodeURIComponent(r.id)}`}
                className="flex items-center justify-between gap-3 rounded-lg border border-border px-4 py-3 text-sm text-slate-200 transition hover:border-cyber-500/50 hover:bg-bg-hover"
              >
                <span>{r.title}</span>
                <ArrowRight className="h-4 w-4 shrink-0 text-cyber-300" />
              </Link>
            </li>
          ))}
        </ul>
      ) : (
        <p className="mt-4 text-sm text-slate-400">Browse the Lesson Library for related material.</p>
      )}
      <div className="mt-6 flex flex-wrap gap-3">
        <Link href={backHref} className="rounded border border-border px-3 py-2 text-sm text-slate-300 hover:bg-bg-hover">Back to the path</Link>
        <Link href="/learn" className="rounded border border-border px-3 py-2 text-sm text-slate-300 hover:bg-bg-hover">Open the Lesson Library</Link>
      </div>
    </div>
  );
}

export default function LessonReader() {
  const params = useParams<{ slug: string; lesson: string }>();

  const [content, setContent] = useState<ClientLesson | null>(null);
  const [loading, setLoading] = useState(true);
  const [pageIdx, setPageIdx] = useState(0);
  const [quizPassed, setQuizPassed] = useState(false);
  const [completed, setCompleted] = useState(false);
  const [showCompleteToast, setShowCompleteToast] = useState(false);
  const [complete, setComplete] = useState<CompleteState>({ status: "idle" });
  // Why the lesson didn't load (404 = no such lesson; anything else = retryable).
  const [loadError, setLoadError] = useState<number | null>(null);
  const [reloadKey, setReloadKey] = useState(0);

  const meta = findLesson(params.slug, params.lesson);
  const adjacent = adjacentLessons(params.slug, params.lesson);
  const totalPages = (content?.pages.length ?? 10) + 1; // +1 for quiz
  const isQuizPage = content !== null && !content.preparing && pageIdx === content.pages.length;
  const progress = Math.round(((pageIdx + 1) / totalPages) * 100);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    setLoadError(null);
    // P5-01: an error response ({ error } with 401/404/429/5xx) used to be stored
    // as the lesson, and the reader crashed on content.pages — a white screen for
    // a stale link, an expired session or a busy server. Only a real lesson
    // (pages array, or a "preparing" notice) is accepted now.
    fetch(`/api/lessons/${encodeURIComponent(`${params.slug}--${params.lesson}`)}`)
      .then(async r => {
        const data = await r.json().catch(() => null) as ClientLesson | null;
        if (!alive) return;
        if (r.ok && data && (data.preparing || Array.isArray(data.pages))) {
          setContent(data);
        } else {
          setContent(null);
          setLoadError(r.ok ? 500 : r.status);
        }
        setLoading(false);
      })
      .catch(() => { if (alive) { setContent(null); setLoadError(0); setLoading(false); } });
    return () => { alive = false; };
  }, [params.slug, params.lesson, reloadKey]);

  const lessonKey = `${params.slug}--${params.lesson}`;
  const flashToast = () => {
    setShowCompleteToast(true);
    setTimeout(() => setShowCompleteToast(false), 4000);
  };

  // Credit the lesson SERVER-side (lesson_progress, migration 0074): the server
  // decides the XP from the catalog, requires the recorded quiz pass, and pays
  // out once. The toast reflects what it actually credited.
  const handleComplete = async () => {
    if (complete.status === "saving") return;
    setComplete({ status: "saving" });
    try {
      const res = await fetch(`/api/lessons/${encodeURIComponent(lessonKey)}/complete`, { method: "POST" });
      const data = await res.json().catch(() => ({}));
      if (res.ok) {
        // Activity first: setTotalXp's change event is what recomputes the streak.
        if (data.status === "credited") recordLessonActivity(data.completedAt ?? undefined);
        if (typeof data.totalXp === "number") setTotalXp(data.totalXp);
        else if (data.credited > 0) addTotalXp(data.credited);
        setComplete(data.status === "already"
          ? { status: "already", xpEarned: data.xpEarned ?? 0 }
          : { status: "credited", credited: data.credited ?? 0 });
        setCompleted(true);
        flashToast();
      } else if (data?.guest) {
        // Guest / no-Supabase: device-local, once per lesson.
        let done: string[] = [];
        try { done = JSON.parse(localStorage.getItem(GUEST_LESSON_DONE_KEY) ?? "[]"); } catch { /* blocked/malformed */ }
        const first = !done.includes(lessonKey);
        const credited = first ? (meta?.lesson.xp ?? 0) : 0;
        if (first) {
          try { localStorage.setItem(GUEST_LESSON_DONE_KEY, JSON.stringify([...done, lessonKey])); } catch { /* blocked */ }
          recordLessonActivity();
          if (credited > 0) addTotalXp(credited);
        }
        setComplete({ status: "guest", credited });
        setCompleted(true);
        flashToast();
      } else {
        setComplete({
          status: "error",
          message: data?.code === "quiz_not_passed"
            ? "Your quiz pass wasn't saved — retake the knowledge check, then mark complete."
            : "Couldn't save your lesson completion — try again.",
        });
      }
    } catch {
      setComplete({ status: "error", message: "Couldn't save your lesson completion — check your connection and try again." });
    }
  };

  const currentPage = content?.pages[pageIdx];

  return (
    <div className="min-h-screen bg-bg">
      {/* Completion toast */}
      {showCompleteToast && (
        <div role="status" className="fixed right-6 top-6 z-50 flex items-center gap-2 rounded-lg border border-neon-green/40 bg-neon-green/10 px-4 py-3 text-sm font-semibold text-neon-green shadow-lg">
          <CheckCircle2 className="h-4 w-4" />
          {complete.status === "credited" && (complete.credited > 0
            ? `Lesson complete! +${complete.credited} XP added to your overall score`
            : "Lesson complete!")}
          {complete.status === "already" && `Lesson complete — its ${complete.xpEarned} XP already counts toward your score`}
          {complete.status === "guest" && (complete.credited > 0
            ? `Lesson complete! +${complete.credited} XP (this device — sign in to keep it)`
            : "Lesson complete!")}
        </div>
      )}

      {/* Header */}
      <header className="sticky top-0 z-30 border-b border-border bg-bg/80 py-3 pl-16 pr-6 backdrop-blur md:px-6">
        <div className="mx-auto flex max-w-4xl items-center gap-4">
          <Link href={`/learn/${params.slug}`} className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-white">
            <ChevronLeft className="h-4 w-4" /> Back
          </Link>
          <div className="flex-1">
            {meta && (
              <p className="text-xs text-slate-400">
                {meta.path.title} · {meta.module.title}
              </p>
            )}
            <h1 className="text-sm font-semibold text-white">{meta?.lesson.title ?? (loadError === 404 ? "Lesson not found" : loading ? "Loading…" : "Lesson")}</h1>
          </div>
          <div className="flex items-center gap-2 text-xs text-slate-400">
            {meta && <span className="font-mono text-cyber-300">+{meta.lesson.xp} XP</span>}
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
            <span className="text-[10px] font-mono text-slate-400">
              {!content ? null : content.preparing ? "In preparation" : <>{isQuizPage ? "Quiz" : `Page ${pageIdx + 1}`} / {totalPages}</>}
            </span>
          </div>
        </div>
      </header>

      {/* Content */}
      <main className="mx-auto max-w-4xl px-6 py-8">
        {loading ? (
          <LoadingSkeleton />
        ) : !content ? (
          loadError === 404 ? (
            <div className="rounded-lg border border-border bg-bg-elevated/40 p-6">
              <p className="text-sm font-semibold text-white">This lesson doesn&apos;t exist — the link may be out of date.</p>
              <div className="mt-4 flex flex-wrap gap-3">
                <Link href={`/learn/${params.slug}`} className="rounded border border-border px-3 py-2 text-sm text-slate-300 hover:bg-bg-hover">Back to the path</Link>
                <Link href="/learn" className="rounded border border-border px-3 py-2 text-sm text-slate-300 hover:bg-bg-hover">All learning paths</Link>
              </div>
            </div>
          ) : (
            <div className="rounded-lg border border-border bg-bg-elevated/40 p-6">
              <p className="text-sm font-semibold text-white">The lesson couldn&apos;t be loaded.</p>
              <p className="mt-1 text-sm text-slate-400">
                {loadError === 401 ? "Your session may have expired — sign in again, then reload." : "Check your connection and try again."}
              </p>
              <button onClick={() => setReloadKey(k => k + 1)} className="mt-4 rounded border border-cyber-500/40 bg-cyber-500/10 px-3 py-2 text-sm font-semibold text-cyber-300 hover:bg-cyber-500/20">Try again</button>
            </div>
          )
        ) : content.preparing ? (
          <PreparingNotice title={meta?.lesson.title ?? content.lessonTitle} related={content.related ?? []} backHref={`/learn/${params.slug}`} />
        ) : isQuizPage ? (
          <Quiz
            questions={content.quiz}
            gradeEndpoint={`/api/lessons/${encodeURIComponent(`${params.slug}--${params.lesson}`)}/quiz/grade`}
            onPass={() => setQuizPassed(true)}
          />
        ) : currentPage ? (
          <>
            <LessonPageView page={currentPage} />
          </>
        ) : null}

        {/* Navigation */}
        {!loading && content && !content.preparing && (
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
                <div className="flex flex-col items-end gap-1.5">
                  <button
                    onClick={() => void handleComplete()}
                    disabled={complete.status === "saving"}
                    className="flex items-center gap-2 rounded bg-neon-green/10 border border-neon-green/40 px-4 py-2 text-sm font-semibold text-neon-green hover:bg-neon-green/20 disabled:opacity-60"
                  >
                    {complete.status === "saving"
                      ? <><Loader2 className="h-4 w-4 animate-spin" /> Saving…</>
                      : <><CheckCircle2 className="h-4 w-4" /> Mark Complete</>}
                  </button>
                  {complete.status === "error" && (
                    <p role="alert" className="max-w-xs text-right text-xs text-severity-high">{complete.message}</p>
                  )}
                </div>
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
