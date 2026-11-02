"use client";
import React, { useCallback } from "react";
import { motion } from "framer-motion";
import { CheckCircle2, ShieldAlert, ChevronRight } from "lucide-react";
import { cn } from "@/lib/utils";
import { submitTask } from "@/components/rooms/TaskPlayer";
import { saveTaskReview, type ReviewRecord } from "@/components/rooms/reviewStore";
import { useTaskTelemetry, type TaskTelemetryEntry } from "@/lib/useTaskTelemetry";
import type { TelemetryEvent } from "@/lib/sim/types";
import type { Persona } from "@/lib/rooms/experience";

export interface MechanicProps<T> {
  roomId: string;
  task: T;
  isCompleted: boolean;
  onComplete: (xpEarned: number, telemetry?: TaskTelemetryEntry, passCredit?: number) => void;
  /** Every wrong submission costs the station one shield. `withReveal` = the
   *  explanation is on screen now, so a resulting breach waits until the
   *  learner has read it and continued. */
  onMistake: (withReveal?: boolean) => void;
  /** Too slow (e.g. the triage clock ran out): costs a star at the end of the station, never a shield. */
  onSlow?: () => void;
  persona?: Persona;
  prevLogEvent?: TelemetryEvent;
  intelTokens: number;
  /** Returns false when no token is left. */
  spendToken: () => boolean;
}

/**
 * The same submit / telemetry / review-record contract TaskPlayer's sub-players
 * use, so an Operation-mode answer is graded, logged and reviewable exactly
 * like a Classic one.
 */
export function useMechanic(roomId: string, taskId: string, isCompleted: boolean, onComplete: MechanicProps<unknown>["onComplete"]) {
  const { recordInteraction, finalize } = useTaskTelemetry(taskId);
  const submit = useCallback((body: unknown) => submitTask(roomId, taskId, body), [roomId, taskId]);
  const record = useCallback((r: ReviewRecord) => saveTaskReview(roomId, taskId, r), [roomId, taskId]);
  // passCredit = what this run counts toward the 65% gate (a correct retry earns full credit, half XP) — same rule as TaskPlayer.
  const complete = useCallback((xp: number, passCredit?: number) => onComplete(xp, isCompleted ? undefined : finalize(), isCompleted ? undefined : passCredit), [onComplete, finalize, isCompleted]);
  return { submit, record, complete, recordInteraction };
}

/** Raw log fields as flat dotted rows; nested objects and arrays are expanded, not "[object Object]". */
export function flattenRaw(raw: Record<string, unknown>, prefix = ""): { key: string; value: string }[] {
  const out: { key: string; value: string }[] = [];
  for (const [k, v] of Object.entries(raw)) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (Array.isArray(v)) {
      v.forEach((item, i) => {
        if (item && typeof item === "object") out.push(...flattenRaw(item as Record<string, unknown>, `${key}[${i}]`));
        else out.push({ key: `${key}[${i}]`, value: String(item) });
      });
    } else if (v && typeof v === "object") {
      out.push(...flattenRaw(v as Record<string, unknown>, key));
    } else {
      out.push({ key, value: String(v) });
    }
  }
  return out;
}

/** The "why" panel after a graded answer. Teaching, not just a verdict. */
export function Verdict({ correct, title, xp, explanation, trap }: {
  correct: boolean; title: string; xp?: number; explanation: string; trap?: string;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      role="status"
      className={cn(
        "rounded-xl border p-4 text-sm backdrop-blur",
        correct ? "border-neon-green/40 bg-neon-green/10" : "border-neon-red/40 bg-neon-red/10",
      )}
    >
      <p className={cn("flex items-center gap-2 font-bold", correct ? "text-neon-green" : "text-neon-red")}>
        {correct ? <CheckCircle2 className="h-4 w-4" /> : <ShieldAlert className="h-4 w-4" />}
        {title}{correct && xp ? <span className="ml-auto font-mono text-neon-amber">+{xp} XP</span> : null}
      </p>
      {explanation && <p className="mt-2 leading-relaxed text-slate-200">{explanation}</p>}
      {trap && !correct && (
        <div className="mt-3 border-l-2 border-neon-amber/50 pl-3">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-neon-amber">The trap</p>
          <p className="mt-0.5 text-xs leading-relaxed text-neon-amber/90">{trap}</p>
        </div>
      )}
    </motion.div>
  );
}

export function ContinueButton({ onClick, label = "Continue", tone = "cyan" }: { onClick: () => void; label?: string; tone?: "cyan" | "muted" }) {
  return (
    <button
      onClick={onClick}
      autoFocus
      className={cn(
        "inline-flex items-center gap-2 rounded-xl px-5 py-2.5 text-sm font-bold transition",
        tone === "cyan"
          ? "bg-gradient-to-r from-cyber-400 to-indigo-400 text-bg hover:brightness-110"
          : "border border-border-strong bg-bg-panel/70 text-slate-200 hover:border-cyber-500/50",
      )}
    >
      {label} <ChevronRight className="h-4 w-4" />
    </button>
  );
}

/** Shown when a task in this station was already finished on a previous visit. */
export function AlreadyCleared({ heading, onContinue }: { heading: string; onContinue: () => void }) {
  return (
    <div className="space-y-4 text-center">
      <p className="text-lg font-semibold text-white">{heading}</p>
      <p className="inline-flex items-center gap-2 rounded-full border border-neon-green/40 bg-neon-green/10 px-3 py-1 text-sm text-neon-green">
        <CheckCircle2 className="h-4 w-4" /> Already cleared
      </p>
      <div><ContinueButton onClick={onContinue} /></div>
    </div>
  );
}

/** Stylised initials avatar for in-world characters (no stock photos needed). */
export function PersonaAvatar({ name, size = 96 }: { name: string; size?: number }) {
  const initials = name.split(/[\s.]+/).filter(Boolean).map(p => p[0]).slice(0, 2).join("").toUpperCase();
  return (
    <div
      aria-hidden
      style={{ width: size, height: size }}
      className="relative grid shrink-0 place-items-center rounded-2xl border border-cyber-500/40 bg-[radial-gradient(circle_at_30%_20%,rgba(34,211,238,0.35),rgba(15,23,42,0.95)_70%)] shadow-glow"
    >
      <span className="font-mono text-2xl font-bold tracking-widest text-cyber-100">{initials}</span>
      <span className="absolute inset-x-3 bottom-2 h-px bg-gradient-to-r from-transparent via-cyber-300/70 to-transparent" />
    </div>
  );
}
