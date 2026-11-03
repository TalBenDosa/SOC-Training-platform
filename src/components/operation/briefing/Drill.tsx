"use client";
import React, { useState } from "react";
import { motion } from "framer-motion";
import { Crosshair, CheckCircle2, ChevronRight, SkipForward } from "lucide-react";
import { cn } from "@/lib/utils";
import type { BriefingLab } from "@/lib/rooms/experience";
import { HowToPlay, Lab } from "./Labs";
import { LAB_ICON } from "./IntelBriefing";

/**
 * Labs attached to a non-reading task run as a drill before the graded
 * challenge: practice on different examples, then the real thing. A drill is
 * never graded, so it can always be skipped, and it is skipped for a task the
 * learner has already cleared.
 */
export function Drill({ labs, skip, children }: { labs: BriefingLab[]; skip: boolean; children: React.ReactNode }) {
  const [step, setStep] = useState(skip ? labs.length : 0);
  const [done, setDone] = useState<Set<number>>(new Set());
  if (step >= labs.length) return <>{children}</>;
  const lab = labs[step];
  const isDone = done.has(step);
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <span className="inline-flex items-center gap-2 rounded-full border border-teal-300/40 bg-teal-500/10 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.2em] text-teal-200">
          <Crosshair className="h-3.5 w-3.5" /> Drill · not graded
        </span>
        <span className="text-xs text-slate-400">Practice first, then the graded challenge.</span>
        <button onClick={() => setStep(labs.length)} className="ml-auto inline-flex items-center gap-1.5 text-xs font-semibold text-slate-400 hover:text-white">
          <SkipForward className="h-3.5 w-3.5" /> Skip to the challenge
        </button>
      </div>
      <motion.div key={step} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="rounded-2xl border border-white/10 bg-[#060b15]/80 p-5">
        <p className="text-[11px] font-semibold uppercase tracking-[0.25em] text-teal-300">
          Drill {step + 1} of {labs.length} · {LAB_ICON[lab.kind]}
        </p>
        <h3 className="mt-1 text-lg font-bold text-white">{lab.title}</h3>
        <p className="mb-4 mt-1 text-sm leading-relaxed text-slate-300 [overflow-wrap:anywhere]">{lab.prompt}</p>
        <HowToPlay lab={lab} />
        <Lab lab={lab} onDone={() => setDone(d => new Set(d).add(step))} />
      </motion.div>
      <button
        onClick={() => setStep(s => s + 1)}
        disabled={!isDone}
        className={cn(
          "inline-flex items-center gap-2 rounded-xl px-5 py-2.5 text-sm font-bold transition",
          isDone ? "bg-gradient-to-r from-teal-400 to-sky-400 text-bg hover:brightness-110" : "border border-white/10 text-slate-500",
        )}
      >
        {isDone ? <CheckCircle2 className="h-4 w-4" /> : null}
        {step + 1 < labs.length ? "Next drill" : "Start the challenge"} <ChevronRight className="h-4 w-4" />
      </button>
    </div>
  );
}
