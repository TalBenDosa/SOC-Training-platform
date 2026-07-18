"use client";
import { useState, useEffect } from "react";
import Link from "next/link";
import { ArrowLeft, CheckCircle2, XCircle, ChevronRight, Trophy, RotateCcw, Clock } from "lucide-react";
import { cn } from "@/lib/utils";
import { Topbar } from "@/components/nav/Topbar";
import type { Quiz } from "@/lib/quizzes/data";

// ─── Types ────────────────────────────────────────────────────────────────────

type QuizPhase = "idle" | "answering" | "complete";

interface AnswerState {
  selected: number | null;  // index into options[]
  revealed: boolean;
}

// ─── Score ring ───────────────────────────────────────────────────────────────

function ScoreRing({ score }: { score: number }) {
  const r = 36;
  const circ = 2 * Math.PI * r;
  const offset = circ - (score / 100) * circ;
  const color = score >= 80 ? "#22c55e" : score >= 60 ? "#f59e0b" : "#ef4444";

  return (
    <div className="relative flex h-24 w-24 items-center justify-center">
      <svg className="-rotate-90" width="96" height="96" viewBox="0 0 96 96">
        <circle cx="48" cy="48" r={r} fill="none" stroke="#1e293b" strokeWidth="8" />
        <circle
          cx="48" cy="48" r={r}
          fill="none"
          stroke={color}
          strokeWidth="8"
          strokeDasharray={circ}
          strokeDashoffset={offset}
          strokeLinecap="round"
          style={{ transition: "stroke-dashoffset 0.8s ease" }}
        />
      </svg>
      <div className="absolute text-center">
        <p className="font-mono text-xl font-bold text-white">{score}%</p>
      </div>
    </div>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

export function QuizClient({ quiz: initialQuiz }: { quiz: Quiz }) {
  // Allow admin edits stored in localStorage to override the built-in quiz data
  const [quiz, setQuiz] = useState<Quiz>(initialQuiz);
  useEffect(() => {
    try {
      const edits: Record<string, Partial<Quiz>> = JSON.parse(
        localStorage.getItem("admin_quiz_edits") ?? "{}"
      );
      if (edits[initialQuiz.slug]) {
        setQuiz(q => ({ ...q, ...edits[initialQuiz.slug] }));
      }
    } catch { /* storage blocked or malformed */ }
  }, [initialQuiz.slug]);

  const [phase, setPhase]     = useState<QuizPhase>("idle");
  const [current, setCurrent] = useState(0);
  const [stateMap, setStateMap] = useState<Record<string, AnswerState>>({});
  const [startTime, setStartTime] = useState<number>(0);
  const [elapsed, setElapsed]     = useState(0);

  const question   = quiz.questions[current];
  const qState     = stateMap[question?.id] ?? { selected: null, revealed: false };
  const totalQ     = quiz.questions.length;
  const answeredQ  = Object.values(stateMap).filter(s => s.revealed).length;
  const isLast     = current === totalQ - 1;

  // ── start ─────────────────────────────────────────────────────
  const handleStart = () => {
    setStateMap({});
    setCurrent(0);
    const now = Date.now();
    setStartTime(now);
    setPhase("answering");
  };

  // ── select option ─────────────────────────────────────────────
  const handleSelect = (idx: number) => {
    if (qState.revealed) return;
    setStateMap(prev => ({
      ...prev,
      [question.id]: { selected: idx, revealed: false },
    }));
  };

  // ── confirm answer ────────────────────────────────────────────
  const handleConfirm = () => {
    if (qState.selected === null || qState.revealed) return;
    setStateMap(prev => ({
      ...prev,
      [question.id]: { ...prev[question.id], revealed: true },
    }));
  };

  // ── next / finish ─────────────────────────────────────────────
  const handleNext = () => {
    if (isLast) {
      setElapsed(Math.round((Date.now() - startTime) / 1000));
      setPhase("complete");
    } else {
      setCurrent(c => c + 1);
    }
  };

  // ── retry ─────────────────────────────────────────────────────
  const handleRetry = () => {
    setStateMap({});
    setCurrent(0);
    setPhase("idle");
  };

  // ── score ─────────────────────────────────────────────────────
  const correctCount = quiz.questions.filter(q => {
    const s = stateMap[q.id];
    return s?.revealed && s.selected === q.answer;
  }).length;

  const xpEarned = quiz.questions.reduce((sum, q) => {
    const s = stateMap[q.id];
    return sum + (s?.revealed && s.selected === q.answer ? q.xp : 0);
  }, 0);

  const scorePercent = Math.round((correctCount / totalQ) * 100);

  const formatTime = (s: number) => {
    const m = Math.floor(s / 60);
    const sec = s % 60;
    return m > 0 ? `${m}m ${sec}s` : `${sec}s`;
  };

  // ═══════════════════════════════════════════════════════════════
  // IDLE STATE
  // ═══════════════════════════════════════════════════════════════
  if (phase === "idle") {
    return (
      <div className="min-h-screen bg-bg">
        <Topbar title={quiz.title} subtitle={quiz.category} />
        <div className="container mx-auto max-w-[680px] px-6 py-12">
          <Link href="/quizzes" className="mb-6 flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 transition">
            <ArrowLeft className="h-3.5 w-3.5" /> Back to Quizzes
          </Link>

          <div className="rounded border border-border/60 bg-[#0d1520] overflow-hidden">
            {/* Hero */}
            <div className="px-8 pt-8 pb-6 text-center border-b border-border/60">
              <div className="mb-4 text-5xl">{quiz.icon}</div>
              <h1 className="text-2xl font-bold text-white mb-2">{quiz.title}</h1>
              <p className="text-sm text-slate-400 leading-relaxed max-w-md mx-auto">{quiz.description}</p>
            </div>

            {/* Stats */}
            <div className="grid grid-cols-3 divide-x divide-border/60 border-b border-border/60">
              {[
                { label: "Questions", value: String(quiz.questions.length) },
                { label: "Est. Time",  value: `~${quiz.estimatedMinutes} min` },
                { label: "Max XP",    value: `+${quiz.questions.reduce((s, q) => s + q.xp, 0)}` },
              ].map(s => (
                <div key={s.label} className="px-6 py-4 text-center">
                  <p className="font-mono text-xl font-bold text-cyber-300">{s.value}</p>
                  <p className="text-[11px] text-slate-500 mt-0.5">{s.label}</p>
                </div>
              ))}
            </div>

            {/* Difficulty */}
            <div className="px-8 py-5 flex items-center justify-between border-b border-border/60">
              <span className="text-xs text-slate-400">Difficulty</span>
              <span className={cn(
                "rounded border px-3 py-1 text-xs font-semibold",
                quiz.difficulty === "Beginner"     && "border-neon-green/30 bg-neon-green/10 text-neon-green",
                quiz.difficulty === "Intermediate" && "border-neon-amber/30 bg-neon-amber/10 text-neon-amber",
                quiz.difficulty === "Advanced"     && "border-severity-high/30 bg-severity-high/10 text-severity-high",
              )}>{quiz.difficulty}</span>
            </div>

            {/* Rules */}
            <div className="px-8 py-5 space-y-2 border-b border-border/60">
              <p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-500 mb-3">How It Works</p>
              {[
                "Each question has one correct answer",
                "Confirm your answer to reveal the explanation",
                "You cannot change an answer after confirming",
                "XP is awarded only for correct answers",
              ].map((rule, i) => (
                <div key={i} className="flex items-start gap-2 text-xs text-slate-400">
                  <span className="mt-0.5 font-mono text-cyber-300/60 shrink-0">{i + 1}.</span>
                  {rule}
                </div>
              ))}
            </div>

            {/* CTA */}
            <div className="px-8 py-6">
              <button
                onClick={handleStart}
                className="w-full rounded border border-cyber-500/30 bg-cyber-500/10 py-3 text-sm font-bold text-cyber-300 hover:bg-cyber-500/20 transition"
              >
                Start Quiz →
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // ═══════════════════════════════════════════════════════════════
  // COMPLETE STATE
  // ═══════════════════════════════════════════════════════════════
  if (phase === "complete") {
    const passed = scorePercent >= 70;

    return (
      <div className="min-h-screen bg-bg">
        <Topbar title={quiz.title} subtitle="Quiz Complete" />
        <div className="container mx-auto max-w-[720px] px-6 py-12">

          {/* Result card */}
          <div className="rounded border border-border/60 bg-[#0d1520] overflow-hidden mb-6">
            <div className="px-8 py-8 text-center border-b border-border/60">
              <div className="mb-4 flex justify-center">
                <ScoreRing score={scorePercent} />
              </div>
              <h2 className="text-xl font-bold text-white mb-1">
                {scorePercent >= 80 ? "Excellent work!" : scorePercent >= 60 ? "Good effort!" : "Keep practising!"}
              </h2>
              <p className="text-sm text-slate-400">
                {correctCount}/{totalQ} correct · {formatTime(elapsed)} · +{xpEarned} XP earned
              </p>
              {passed ? (
                <div className="mt-3 inline-flex items-center gap-1.5 rounded border border-neon-green/30 bg-neon-green/10 px-3 py-1 text-xs font-semibold text-neon-green">
                  <Trophy className="h-3.5 w-3.5" /> Passed
                </div>
              ) : (
                <div className="mt-3 inline-flex items-center gap-1.5 rounded border border-severity-high/30 bg-severity-high/10 px-3 py-1 text-xs font-semibold text-severity-high">
                  Score ≥ 70% to pass
                </div>
              )}
            </div>

            {/* Time stat */}
            <div className="grid grid-cols-3 divide-x divide-border/60 border-b border-border/60">
              {[
                { label: "Score",    value: `${scorePercent}%` },
                { label: "Time",     value: formatTime(elapsed), icon: Clock },
                { label: "XP",       value: `+${xpEarned}` },
              ].map(s => (
                <div key={s.label} className="px-4 py-3 text-center">
                  <p className="font-mono text-lg font-bold text-cyber-300">{s.value}</p>
                  <p className="text-[10px] text-slate-500">{s.label}</p>
                </div>
              ))}
            </div>

            {/* Buttons */}
            <div className="flex gap-3 px-8 py-5">
              <button
                onClick={handleRetry}
                className="flex-1 flex items-center justify-center gap-2 rounded border border-border py-2.5 text-sm font-semibold text-slate-300 hover:border-cyber-500/30 hover:text-cyber-300 transition"
              >
                <RotateCcw className="h-4 w-4" /> Retry Quiz
              </button>
              <Link
                href="/quizzes"
                className="flex-1 flex items-center justify-center gap-2 rounded border border-cyber-500/30 bg-cyber-500/10 py-2.5 text-sm font-semibold text-cyber-300 hover:bg-cyber-500/20 transition"
              >
                All Quizzes <ArrowLeft className="h-4 w-4 rotate-180" />
              </Link>
            </div>
          </div>

          {/* Per-question breakdown */}
          <h3 className="text-xs font-semibold uppercase tracking-[0.15em] text-slate-500 mb-3">Question Breakdown</h3>
          <div className="space-y-3">
            {quiz.questions.map((q, idx) => {
              const s = stateMap[q.id];
              const correct = s?.revealed && s.selected === q.answer;
              const wrong   = s?.revealed && s.selected !== q.answer;

              return (
                <div key={q.id} className={cn(
                  "rounded border px-4 py-3",
                  correct ? "border-neon-green/20 bg-neon-green/5" : "border-severity-high/20 bg-severity-high/5"
                )}>
                  <div className="flex items-start gap-3">
                    {correct
                      ? <CheckCircle2 className="h-4 w-4 shrink-0 mt-0.5 text-neon-green" />
                      : <XCircle className="h-4 w-4 shrink-0 mt-0.5 text-severity-high" />
                    }
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-semibold text-slate-200 mb-1">
                        <span className="font-mono text-cyber-300 mr-1">Q{idx + 1}.</span>
                        {q.question}
                      </p>
                      {wrong && s?.selected !== null && (
                        <p className="text-[11px] text-severity-high mb-1">
                          Your answer: {q.options[s.selected]}
                        </p>
                      )}
                      <p className={cn("text-[11px] mb-1.5", correct ? "text-neon-green" : "text-slate-400")}>
                        {correct ? "✓" : "Correct:"} {q.options[q.answer]}
                      </p>
                      <p className="text-[11px] text-slate-500 leading-relaxed">{q.explanation}</p>
                    </div>
                    {correct && (
                      <span className="shrink-0 rounded bg-neon-green/10 px-1.5 py-0.5 font-mono text-[10px] text-neon-green">
                        +{q.xp}
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    );
  }

  // ═══════════════════════════════════════════════════════════════
  // ANSWERING STATE
  // ═══════════════════════════════════════════════════════════════
  const isCorrect = qState.revealed && qState.selected === question.answer;
  const isWrong   = qState.revealed && qState.selected !== question.answer;

  return (
    <div className="min-h-screen bg-bg">
      <Topbar title={quiz.title} subtitle={`Question ${current + 1} of ${totalQ}`} />

      <div className="container mx-auto max-w-[720px] px-6 py-8">

        {/* Progress bar */}
        <div className="mb-6">
          <div className="flex items-center justify-between mb-1.5">
            <span className="text-[11px] text-slate-500">{answeredQ}/{totalQ} answered</span>
            <span className="text-[11px] text-slate-500">
              +{Object.values(stateMap).reduce((s, st, idx) => {
                const q = quiz.questions[idx];
                return s + (st?.revealed && st.selected === q?.answer ? (q?.xp ?? 0) : 0);
              }, 0)} XP so far
            </span>
          </div>
          <div className="h-1.5 w-full rounded-full bg-slate-700/60">
            <div
              className="h-1.5 rounded-full bg-cyber-500 transition-all duration-300"
              style={{ width: `${((current + (qState.revealed ? 1 : 0)) / totalQ) * 100}%` }}
            />
          </div>
          {/* Question dots */}
          <div className="flex gap-1 mt-2">
            {quiz.questions.map((q, i) => {
              const s = stateMap[q.id];
              const done = s?.revealed;
              const ok   = done && s.selected === q.answer;
              return (
                <button
                  key={q.id}
                  onClick={() => { if (done) setCurrent(i); }}
                  className={cn(
                    "h-2 rounded-full transition-all",
                    i === current ? "w-6 bg-cyber-400" :
                    ok  ? "w-2 bg-neon-green" :
                    done ? "w-2 bg-severity-high" :
                    "w-2 bg-slate-600"
                  )}
                />
              );
            })}
          </div>
        </div>

        {/* Question card */}
        <div className="rounded border border-border/60 bg-[#0d1520] overflow-hidden">
          {/* Question header */}
          <div className="px-6 pt-6 pb-4">
            <div className="flex items-center justify-between mb-4">
              <span className="rounded bg-cyber-500/10 border border-cyber-500/20 px-2.5 py-1 font-mono text-[11px] text-cyber-300">
                {current + 1} / {totalQ}
              </span>
              <span className="rounded bg-bg-elevated px-2.5 py-1 text-[11px] text-slate-400">
                +{question.xp} XP
              </span>
            </div>
            <p className="text-base font-semibold text-white leading-relaxed">
              {question.question}
            </p>
          </div>

          {/* Options */}
          <div className="px-6 pb-4 space-y-2">
            {question.options.map((opt, idx) => {
              const selected  = qState.selected === idx;
              const revCorr   = qState.revealed && idx === question.answer;
              const revWrong  = qState.revealed && selected && idx !== question.answer;

              return (
                <button
                  key={idx}
                  disabled={qState.revealed}
                  onClick={() => handleSelect(idx)}
                  className={cn(
                    "w-full flex items-center gap-3 rounded border px-4 py-3 text-left text-sm transition",
                    !qState.revealed && !selected && "border-border bg-bg text-slate-300 hover:border-cyber-500/30 hover:bg-cyber-500/5",
                    !qState.revealed && selected  && "border-cyber-500/50 bg-cyber-500/10 text-white",
                    revCorr   && "border-neon-green/50 bg-neon-green/10 text-neon-green",
                    revWrong  && "border-severity-high/50 bg-severity-high/10 text-severity-high",
                    qState.revealed && !selected && idx !== question.answer && "border-border/40 bg-bg/50 text-slate-500",
                  )}
                >
                  <span className={cn(
                    "flex h-5 w-5 shrink-0 items-center justify-center rounded-full border text-[11px] font-bold",
                    !qState.revealed && !selected && "border-slate-500/40 text-slate-500",
                    !qState.revealed && selected  && "border-cyber-400 text-cyber-300",
                    revCorr   && "border-neon-green text-neon-green",
                    revWrong  && "border-severity-high text-severity-high",
                    qState.revealed && !selected && idx !== question.answer && "border-slate-700 text-slate-700",
                  )}>
                    {String.fromCharCode(65 + idx)}
                  </span>
                  <span>{opt}</span>
                  {revCorr  && <CheckCircle2 className="ml-auto h-4 w-4 shrink-0 text-neon-green" />}
                  {revWrong && <XCircle       className="ml-auto h-4 w-4 shrink-0 text-severity-high" />}
                </button>
              );
            })}
          </div>

          {/* Explanation (after reveal) */}
          {qState.revealed && (
            <div className={cn(
              "mx-6 mb-4 rounded border px-4 py-3",
              isCorrect ? "border-neon-green/20 bg-neon-green/5" : "border-severity-medium/20 bg-severity-medium/5"
            )}>
              <p className={cn("text-[10px] font-semibold uppercase tracking-[0.15em] mb-1.5",
                isCorrect ? "text-neon-green/70" : "text-severity-medium/70"
              )}>
                {isCorrect ? "Correct!" : "Explanation"}
              </p>
              <p className="text-xs text-slate-300 leading-relaxed">{question.explanation}</p>
            </div>
          )}

          {/* Action buttons */}
          <div className="flex gap-3 border-t border-border/60 px-6 py-4">
            {!qState.revealed ? (
              <button
                onClick={handleConfirm}
                disabled={qState.selected === null}
                className="flex-1 rounded border border-cyber-500/30 bg-cyber-500/10 py-2.5 text-sm font-semibold text-cyber-300 hover:bg-cyber-500/20 transition disabled:opacity-40 disabled:cursor-not-allowed"
              >
                Confirm Answer
              </button>
            ) : (
              <button
                onClick={handleNext}
                className="flex-1 flex items-center justify-center gap-2 rounded border border-cyber-500/30 bg-cyber-500/10 py-2.5 text-sm font-semibold text-cyber-300 hover:bg-cyber-500/20 transition"
              >
                {isLast ? "See Results" : "Next Question"}
                <ChevronRight className="h-4 w-4" />
              </button>
            )}
          </div>
        </div>

        {/* Navigation back */}
        {current > 0 && !qState.revealed && (
          <button
            onClick={() => setCurrent(c => c - 1)}
            className="mt-4 flex items-center gap-1 text-xs text-slate-500 hover:text-slate-300 transition"
          >
            <ArrowLeft className="h-3.5 w-3.5" /> Previous question
          </button>
        )}
      </div>
    </div>
  );
}
