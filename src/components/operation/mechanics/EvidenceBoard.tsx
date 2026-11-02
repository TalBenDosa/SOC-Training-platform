"use client";
import React, { useMemo, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { Pin, X, FileSearch } from "lucide-react";
import { cn } from "@/lib/utils";
import { displayOptions, newShuffleSeed } from "@/lib/rooms/shuffle";
import type { SanitizedLogAnalysisTask } from "@/lib/rooms/sanitize";
import type { QuestionReview } from "@/components/rooms/reviewStore";
import { AlreadyCleared, ContinueButton, Verdict, flattenRaw, useMechanic, type MechanicProps } from "../shared";

const MAX_PINS = 6;

/**
 * log_analysis → Evidence Board. The raw log is the evidence document; clicking
 * a field pins it to the case board (the analyst's own notes, never graded).
 * The case questions are answered one at a time; single try each, immediate
 * reveal — the same contract as LogAnalysisPlayer.
 */
export function EvidenceBoard({ roomId, task, isCompleted, onComplete, onMistake }: MechanicProps<SanitizedLogAnalysisTask>) {
  const { submit, record, complete, recordInteraction } = useMechanic(roomId, task.id, isCompleted, onComplete);
  const fields = useMemo(() => flattenRaw(task.event.raw as Record<string, unknown>), [task.event]);
  const seed = useMemo(() => newShuffleSeed(), []);
  const [pins, setPins] = useState<string[]>([]);
  const [qi, setQi] = useState(0);
  const [selected, setSelected] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const [earned, setEarned] = useState(0);
  const [reviews, setReviews] = useState<Record<number, QuestionReview>>({});
  const current = reviews[qi];

  if (isCompleted) return <AlreadyCleared heading={task.heading} onContinue={() => complete(0)} />;

  const q = task.questions[qi];
  const options = displayOptions(q.options, `${seed}:${task.id}:${qi}`);

  function togglePin(key: string) {
    setPins(p => p.includes(key) ? p.filter(k => k !== key) : p.length >= MAX_PINS ? p : [...p, key]);
  }

  async function answer() {
    if (selected === null || busy) return;
    setBusy(true);
    try {
      const r = await submit({ questionIndex: qi, selectedIndex: selected });
      const explanation = typeof r.reveal.explanation === "string" ? r.reveal.explanation : "";
      const ans = typeof r.reveal.answer === "number" ? r.reveal.answer : null;
      if (!r.correct) onMistake(true);
      const rev: QuestionReview = { selected, answer: ans, explanation, correct: r.correct };
      const next = { ...reviews, [qi]: rev };
      setReviews(next);
      setEarned(e => e + (r.correct ? r.xpEarned : 0));
      record({ type: "log_analysis", questions: next });
    } finally {
      setBusy(false);
    }
  }

  function nextQuestion() {
    if (qi + 1 < task.questions.length) { setQi(qi + 1); setSelected(null); }
    else complete(earned, task.questions.reduce((s, q, i) => s + (reviews[i]?.correct ? q.xp : 0), 0));
  }

  return (
    <div className="space-y-4" onClickCapture={recordInteraction}>
      <p className="rounded-xl border border-indigo-400/30 bg-bg-panel/80 px-4 py-3 text-sm leading-relaxed text-slate-200">{task.context}</p>

      <div className="grid gap-4 lg:grid-cols-[1.15fr_1fr]">
        {/* Evidence document */}
        <div className="rounded-xl border border-cyber-500/30 bg-[#050a12]/95">
          <div className="flex items-center gap-2 border-b border-cyber-500/20 px-4 py-2 text-[11px] uppercase tracking-[0.2em] text-cyber-300">
            <FileSearch className="h-3.5 w-3.5" /> Evidence · {task.event.vendor ?? task.event.source}
            <span className="ml-auto normal-case tracking-normal text-slate-500">click a field to pin it</span>
          </div>
          <div className="max-h-[22rem] overflow-y-auto px-2 py-2 font-mono text-[11px]">
            {fields.map(f => {
              const pinned = pins.includes(f.key);
              return (
                <button
                  key={f.key}
                  onClick={() => togglePin(f.key)}
                  aria-pressed={pinned}
                  className={cn(
                    "flex w-full gap-3 rounded-md px-2 py-1 text-left leading-relaxed transition",
                    pinned ? "bg-neon-amber/15 ring-1 ring-neon-amber/50" : "hover:bg-white/5",
                  )}
                >
                  <span className="w-56 shrink-0 text-cyber-300">{f.key}</span>
                  <span className="break-all text-slate-300">{f.value}</span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Case board */}
        <div className="relative min-h-[14rem] rounded-xl border border-amber-900/50 bg-[radial-gradient(circle_at_50%_0%,rgba(120,72,30,0.35),rgba(20,14,8,0.92)_70%)] p-3">
          <p className="mb-2 text-[11px] font-semibold uppercase tracking-[0.2em] text-amber-200/80">Case board · {pins.length}/{MAX_PINS} pinned</p>
          {pins.length === 0 && (
            <p className="mt-10 text-center text-xs text-amber-100/50">Pin the fields you would quote in your report.</p>
          )}
          <div className="grid grid-cols-2 gap-2">
            <AnimatePresence>
              {pins.map((key, i) => {
                const f = fields.find(x => x.key === key);
                return (
                  <motion.div
                    key={key}
                    initial={{ opacity: 0, scale: 0.8, rotate: 0 }}
                    animate={{ opacity: 1, scale: 1, rotate: i % 2 ? 1.5 : -1.5 }}
                    exit={{ opacity: 0, scale: 0.8 }}
                    className="relative rounded-md bg-amber-50 p-2 text-[10px] text-slate-900 shadow-lg"
                  >
                    <Pin className="absolute -top-2 left-1/2 h-4 w-4 -translate-x-1/2 fill-neon-red text-neon-red" />
                    <button onClick={() => togglePin(key)} aria-label={`Unpin ${key}`} className="absolute right-1 top-1 text-slate-500 hover:text-slate-900">
                      <X className="h-3 w-3" />
                    </button>
                    <p className="pr-3 font-mono font-bold">{key}</p>
                    <p className="mt-0.5 break-all font-mono">{f?.value}</p>
                  </motion.div>
                );
              })}
            </AnimatePresence>
          </div>
        </div>
      </div>

      {/* Case question */}
      <div className="rounded-xl border border-border-strong bg-bg-panel/85 p-4">
        <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-indigo-300">
          Case question {qi + 1} of {task.questions.length}
        </p>
        <p className="mt-1.5 text-sm leading-relaxed text-slate-100">{q.question}</p>
        <div className="mt-3 grid gap-2">
          {options.map(({ label, srcIdx, displayIdx }) => {
            const isAns = current && srcIdx === current.answer;
            const isPicked = selected === srcIdx;
            return (
              <button
                key={srcIdx}
                disabled={!!current}
                onClick={() => setSelected(srcIdx)}
                className={cn(
                  "flex items-start gap-3 rounded-lg border px-3 py-2.5 text-left text-sm transition",
                  current
                    ? isAns ? "border-neon-green/60 bg-neon-green/10 text-neon-green"
                      : isPicked ? "border-neon-red/50 bg-neon-red/10 text-neon-red" : "border-border/40 text-slate-500"
                    : isPicked ? "border-cyber-400/70 bg-cyber-500/15 text-white" : "border-border/60 text-slate-300 hover:border-cyber-500/50",
                )}
              >
                <span className="font-mono text-xs font-bold opacity-70">{String.fromCharCode(65 + displayIdx)}.</span>
                <span className="leading-relaxed">{label}</span>
              </button>
            );
          })}
        </div>
        {!current && (
          <button
            disabled={selected === null || busy}
            onClick={answer}
            className="mt-3 rounded-xl bg-gradient-to-r from-cyber-400 to-indigo-400 px-5 py-2.5 text-sm font-bold text-bg transition hover:brightness-110 disabled:opacity-40"
          >
            Submit finding
          </button>
        )}
      </div>

      {current && (
        <>
          <Verdict correct={current.correct} title={current.correct ? "Finding confirmed" : "Finding rejected. Here is why"} explanation={current.explanation} />
          <ContinueButton onClick={nextQuestion} label={qi + 1 < task.questions.length ? "Next question" : "Close the case"} />
        </>
      )}
    </div>
  );
}
