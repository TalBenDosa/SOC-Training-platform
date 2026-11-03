"use client";
import React, { useCallback, useMemo, useState } from "react";
import { motion } from "framer-motion";
import { KeyRound, FlaskConical, BookOpen, ChevronDown, CheckCircle2, ChevronRight, Lock } from "lucide-react";
import { cn } from "@/lib/utils";
import { ReadingBody } from "@/components/rooms/TaskPlayer";
import { displayOptions, newShuffleSeed } from "@/lib/rooms/shuffle";
import type { SanitizedReadingTask } from "@/lib/rooms/sanitize";
import type { BriefingLab } from "@/lib/rooms/experience";
import { AlreadyCleared, useMechanic, type MechanicProps } from "../shared";
import { Lab } from "./Labs";

export const LAB_ICON: Record<BriefingLab["kind"], string> = {
  inspect: "Inspect", sequence: "Sequence", simulate: "Simulate", sort: "Sort", match: "Match",
  reactor: "Route", lineup: "Line-up", hotspot: "Find the flags",
};

/**
 * reading → Intel Briefing. The reading's material is taught through hands-on
 * labs first; the full text stays one click away as "field notes". The same
 * completion rule as ReadingPlayer applies: the checkpoint must be answered
 * correctly (server-graded, ungraded for score) before the briefing is filed.
 * Working every lab replaces ReadingPlayer's scroll/dwell gate.
 */
export function IntelBriefing({ roomId, task, isCompleted, onComplete, labs }: MechanicProps<SanitizedReadingTask> & { labs: BriefingLab[] }) {
  const { submit, record, complete, recordInteraction } = useMechanic(roomId, task.id, isCompleted, onComplete);
  const [step, setStep] = useState(0);
  const [doneLabs, setDoneLabs] = useState<Set<number>>(new Set());
  const [notesOpen, setNotesOpen] = useState(false);
  const [cpChoice, setCpChoice] = useState<number | null>(null);
  const [cpAnswer, setCpAnswer] = useState<number | null>(null);
  const [cpCorrect, setCpCorrect] = useState(false);
  const [cpExplanation, setCpExplanation] = useState("");
  const [busy, setBusy] = useState(false);
  const seed = useMemo(() => newShuffleSeed(), []);
  const markDone = useCallback((i: number) => setDoneLabs(s => new Set(s).add(i)), []);

  if (isCompleted) return <AlreadyCleared heading={task.heading} onContinue={() => complete(0)} />;

  const cp = task.checkpoint;
  const allLabs = doneLabs.size === labs.length;
  const onLabs = step < labs.length;
  const canFile = allLabs && (!cp || cpCorrect);

  async function answer(i: number) {
    if (busy || cpCorrect) return;
    setCpChoice(i);
    setBusy(true);
    try {
      const r = await submit({ selectedIndex: i });
      const ans = typeof r.reveal.answer === "number" ? r.reveal.answer : null;
      const expl = typeof r.reveal.explanation === "string" ? r.reveal.explanation : "";
      setCpAnswer(ans);
      if (r.correct) {
        setCpCorrect(true);
        setCpExplanation(expl);
        record({ type: "reading", checkpoint: { selected: i, answer: ans, explanation: expl, correct: true } });
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-5" onClickCapture={recordInteraction}>
      <div className="flex flex-wrap items-center gap-2">
        <span className="inline-flex items-center gap-2 rounded-full border border-neon-amber/30 bg-neon-amber/10 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.2em] text-neon-amber">
          <KeyRound className="h-3.5 w-3.5" /> Intel briefing · +1 Intel token
        </span>
        <button onClick={() => setNotesOpen(o => !o)} className="ml-auto inline-flex items-center gap-1.5 text-xs text-slate-300 hover:text-white">
          <BookOpen className="h-3.5 w-3.5" /> {notesOpen ? "Hide" : "Read"} the full field notes
        </button>
      </div>
      <h2 className="text-2xl font-bold leading-tight text-white">{task.heading}</h2>

      {/* Lab stepper */}
      <nav aria-label="Briefing labs" className="flex flex-wrap gap-2">
        {labs.map((l, i) => {
          const reachable = i === 0 || doneLabs.has(i - 1) || doneLabs.has(i);
          return (
            <button
              key={i}
              disabled={!reachable}
              onClick={() => setStep(i)}
              aria-current={step === i ? "step" : undefined}
              className={cn(
                "inline-flex items-center gap-2 rounded-xl border px-3 py-1.5 text-xs font-semibold transition",
                step === i ? "border-cyber-300 bg-cyber-500/20 text-white"
                  : doneLabs.has(i) ? "border-neon-green/40 text-neon-green" : reachable ? "border-white/15 text-slate-300" : "border-white/10 text-slate-600",
              )}
            >
              {doneLabs.has(i) ? <CheckCircle2 className="h-3.5 w-3.5" /> : reachable ? <FlaskConical className="h-3.5 w-3.5" /> : <Lock className="h-3.5 w-3.5" />}
              {l.title}
            </button>
          );
        })}
        <button
          disabled={!allLabs}
          onClick={() => setStep(labs.length)}
          aria-current={!onLabs ? "step" : undefined}
          className={cn(
            "inline-flex items-center gap-2 rounded-xl border px-3 py-1.5 text-xs font-semibold transition",
            !onLabs ? "border-cyber-300 bg-cyber-500/20 text-white" : allLabs ? "border-white/15 text-slate-300" : "border-white/10 text-slate-600",
          )}
        >
          {allLabs ? <KeyRound className="h-3.5 w-3.5" /> : <Lock className="h-3.5 w-3.5" />} Key check
        </button>
      </nav>

      {onLabs ? (
        <motion.section key={step} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="rounded-2xl border border-cyber-500/20 bg-[#060b16]/80 p-4 sm:p-5">
          <p className="text-[11px] font-semibold uppercase tracking-[0.25em] text-cyber-300">
            Lab {step + 1} of {labs.length} · {LAB_ICON[labs[step].kind]}
          </p>
          <h3 className="mt-1 text-lg font-bold text-white">{labs[step].title}</h3>
          <p className="mb-4 mt-1 text-sm leading-relaxed text-slate-300">{labs[step].prompt}</p>
          <Lab key={step} lab={labs[step]} onDone={() => markDone(step)} />
          {doneLabs.has(step) && (
            <button autoFocus onClick={() => setStep(step + 1)} className="mt-5 inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-cyber-400 to-indigo-400 px-5 py-2.5 text-sm font-bold text-bg hover:brightness-110">
              {step + 1 < labs.length ? `Next lab: ${labs[step + 1].title}` : "Key check"} <ChevronRight className="h-4 w-4" />
            </button>
          )}
        </motion.section>
      ) : (
        <motion.section initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="rounded-2xl border border-neon-amber/25 bg-[#120d04]/60 p-4 sm:p-5">
          {cp ? (
            <>
              <p className="text-[11px] font-semibold uppercase tracking-[0.25em] text-neon-amber">Key check · unlocks the next briefing</p>
              <p className="mt-2 text-sm leading-relaxed text-slate-100">{cp.question}</p>
              <div className="mt-3 grid gap-2">
                {displayOptions(cp.options, `${seed}:${task.id}:cp`).map(({ label, srcIdx }) => {
                  const show = cpChoice !== null && cpAnswer !== null;
                  const isRight = show && srcIdx === cpAnswer;
                  const chosen = cpChoice === srcIdx;
                  return (
                    <button
                      key={srcIdx}
                      disabled={cpCorrect || busy}
                      onClick={() => answer(srcIdx)}
                      className={cn(
                        "rounded-lg border px-3 py-2 text-left text-sm transition",
                        isRight && cpCorrect ? "border-neon-green/50 bg-neon-green/10 text-neon-green"
                          : show && chosen && !cpCorrect ? "border-neon-red/50 bg-neon-red/10 text-neon-red"
                            : "border-white/10 bg-bg-panel/60 text-slate-200 hover:border-cyber-400/50",
                      )}
                    >
                      {label}
                    </button>
                  );
                })}
              </div>
              {cpChoice !== null && !cpCorrect && !busy && <p role="status" className="mt-2 text-xs text-neon-amber">Not quite. Revisit a lab or the field notes, then try again.</p>}
              {cpCorrect && cpExplanation && <p role="status" className="mt-3 text-xs leading-relaxed text-slate-300">{cpExplanation}</p>}
            </>
          ) : (
            <p className="text-sm text-slate-300">All labs done.</p>
          )}
          <button
            disabled={!canFile}
            onClick={() => complete(0)}
            className="mt-4 inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-cyber-400 to-indigo-400 px-5 py-2.5 text-sm font-bold text-bg transition hover:brightness-110 disabled:opacity-40"
          >
            <CheckCircle2 className="h-4 w-4" /> File the briefing
          </button>
        </motion.section>
      )}

      {/* The full reading, always available */}
      <section className="rounded-2xl border border-white/10 bg-bg-panel/40">
        <button onClick={() => setNotesOpen(o => !o)} aria-expanded={notesOpen} className="flex w-full items-center gap-2 px-4 py-3 text-left text-sm font-semibold text-slate-200">
          <BookOpen className="h-4 w-4 text-slate-400" /> Field notes · the full briefing text
          <ChevronDown className={cn("ml-auto h-4 w-4 transition-transform", notesOpen && "rotate-180")} />
        </button>
        {notesOpen && <div className="border-t border-white/10 px-4 pb-5 pt-2"><ReadingBody task={task} roomId={roomId} /></div>}
      </section>
    </div>
  );
}
