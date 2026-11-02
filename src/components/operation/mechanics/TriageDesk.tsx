"use client";
import React, { useEffect, useMemo, useState } from "react";
import { motion } from "framer-motion";
import { Timer, ShieldCheck, ShieldX, ArrowUpRight, Info } from "lucide-react";
import { cn } from "@/lib/utils";
import { ANALYST_VERDICTS } from "@/components/rooms/TaskPlayer";
import { shuffleWithSeed, newShuffleSeed } from "@/lib/rooms/shuffle";
import type { SanitizedAnalystChoiceTask } from "@/lib/rooms/sanitize";
import { AlreadyCleared, ContinueButton, PersonaAvatar, Verdict, flattenRaw, useMechanic, type MechanicProps } from "../shared";

const DESK_SECONDS = 120;

const VERDICT_STYLE: Record<string, { icon: React.ElementType; ring: string }> = {
  true_positive:  { icon: ShieldX,      ring: "border-neon-red/50 hover:bg-neon-red/10 text-neon-red" },
  false_positive: { icon: ShieldCheck,  ring: "border-neon-green/50 hover:bg-neon-green/10 text-neon-green" },
  escalate:       { icon: ArrowUpRight, ring: "border-neon-amber/50 hover:bg-neon-amber/10 text-neon-amber" },
  informational:  { icon: Info,         ring: "border-slate-500/60 hover:bg-slate-500/10 text-slate-300" },
};

/**
 * analyst_choice → Triage Desk. A requester arrives with an alert; the analyst
 * makes the call on a soft clock. Running out of time costs one shield but
 * never auto-submits — the point is pressure, not a coin flip.
 * Same two-try / half-credit contract as AnalystChoicePlayer.
 */
export function TriageDesk({ roomId, task, isCompleted, onComplete, onMistake, persona }: MechanicProps<SanitizedAnalystChoiceTask>) {
  const { submit, record, complete, recordInteraction } = useMechanic(roomId, task.id, isCompleted, onComplete);
  const verdicts = useMemo(() => shuffleWithSeed(ANALYST_VERDICTS, `${newShuffleSeed()}:${task.id}`), [task.id]);
  const fields = useMemo(() => flattenRaw(task.event.raw as Record<string, unknown>), [task.event]);
  const [left, setLeft] = useState(DESK_SECONDS);
  const [overtime, setOvertime] = useState(false);
  const [wrongOnce, setWrongOnce] = useState(false);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ correct: boolean; xp: number; verdict: string | null; explanation: string; trap?: string } | null>(null);

  useEffect(() => {
    if (result || overtime || isCompleted) return;
    const t = setInterval(() => setLeft(s => s - 1), 1000);
    return () => clearInterval(t);
  }, [result, overtime, isCompleted]);

  useEffect(() => {
    if (left <= 0 && !overtime && !result) { setOvertime(true); onMistake(); }
  }, [left, overtime, result, onMistake]);

  if (isCompleted) return <AlreadyCleared heading={task.heading} onContinue={() => complete(0)} />;

  async function decide(verdict: string) {
    if (busy || result) return;
    setBusy(true);
    try {
      const r = await submit({ verdict, attemptNumber: wrongOnce ? 2 : 1 });
      const explanation = typeof r.reveal.explanation === "string" ? r.reveal.explanation : "";
      const trap = typeof r.reveal.fp_trap === "string" ? r.reveal.fp_trap : undefined;
      const cv = typeof r.reveal.correct_verdict === "string" ? r.reveal.correct_verdict : null;
      if (r.correct) {
        setResult({ correct: true, xp: r.xpEarned, verdict: cv ?? verdict, explanation, trap });
        record({ type: "analyst_choice", selected: verdict, correctVerdict: cv ?? verdict, explanation, fpTrap: trap, correct: true });
      } else {
        if (!wrongOnce) { onMistake(); setWrongOnce(true); }
        else {
          onMistake(true);
          setResult({ correct: false, xp: 0, verdict: cv, explanation, trap });
          record({ type: "analyst_choice", selected: verdict, correctVerdict: cv, explanation, fpTrap: trap, correct: false });
        }
      }
    } finally {
      setBusy(false);
    }
  }

  const pct = Math.max(0, left / DESK_SECONDS);
  const correctLabel = result?.verdict ? ANALYST_VERDICTS.find(v => v.key === result.verdict)?.label : null;

  return (
    <div className="space-y-5" onClickCapture={recordInteraction}>
      <div className="grid gap-5 md:grid-cols-[220px_1fr]">
        {/* Requester */}
        <motion.div initial={{ opacity: 0, x: -16 }} animate={{ opacity: 1, x: 0 }} className="flex flex-col items-center gap-3">
          <PersonaAvatar name={persona?.name ?? "Alert"} size={140} />
          <div className="w-full rounded-xl border border-border-strong bg-bg-panel/80 px-3 py-2 text-center">
            <p className="font-bold text-white">{persona?.name ?? "Incoming alert"}</p>
            {persona && <p className="mt-0.5 text-[11px] uppercase tracking-wider text-slate-400">{persona.role}</p>}
          </div>
        </motion.div>

        <div className="space-y-3">
          {persona && (
            <div className="relative rounded-xl border border-border-strong bg-bg-panel/80 px-4 py-3 text-sm italic text-slate-200">
              “{persona.line}”
            </div>
          )}
          <div className="rounded-xl border border-indigo-400/30 bg-bg-panel/80 px-4 py-3">
            <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-indigo-300">The alert</p>
            <p className="mt-1 text-sm leading-relaxed text-slate-200">{task.scenario}</p>
          </div>
          <details className="group rounded-xl border border-border bg-[#050a12]/90" open>
            <summary className="cursor-pointer select-none px-4 py-2 text-[11px] font-semibold uppercase tracking-[0.2em] text-cyber-300">
              Ticket evidence · {task.event.vendor ?? task.event.source} · {fields.length} fields
            </summary>
            <div className="max-h-64 overflow-y-auto px-4 pb-3 font-mono text-[11px]">
              {fields.map(f => (
                <div key={f.key} className="flex gap-3 border-b border-white/5 py-1 leading-relaxed">
                  <span className="w-64 shrink-0 text-cyber-300">{f.key}</span>
                  <span className="break-all text-slate-300">{f.value}</span>
                </div>
              ))}
            </div>
          </details>
        </div>
      </div>

      {/* Clock */}
      <div className="flex items-center gap-3">
        <Timer className={cn("h-4 w-4", overtime ? "text-neon-red" : "text-slate-400")} />
        <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-white/10">
          <div
            className={cn("h-full rounded-full transition-[width] duration-1000 ease-linear", pct > 0.5 ? "bg-cyber-400" : pct > 0.2 ? "bg-neon-amber" : "bg-neon-red")}
            style={{ width: `${pct * 100}%` }}
          />
        </div>
        <span className={cn("w-16 text-right font-mono text-sm", overtime ? "text-neon-red" : "text-slate-300")}>
          {overtime ? "OVERTIME" : `${left}s`}
        </span>
      </div>

      {wrongOnce && !result && (
        <p role="status" className="rounded-lg border border-neon-amber/40 bg-neon-amber/10 px-3 py-2 text-sm text-neon-amber">
          Not that call. Look again at what the evidence supports, not what it looks like. One more try, half credit.
        </p>
      )}

      {!result ? (
        <div className="grid grid-cols-2 gap-3">
          {verdicts.map(v => {
            const s = VERDICT_STYLE[v.key];
            const Icon = s.icon;
            return (
              <button
                key={v.key}
                disabled={busy}
                onClick={() => decide(v.key)}
                className={cn("flex items-center gap-3 rounded-xl border-2 bg-bg-panel/70 px-4 py-3.5 text-left transition", s.ring)}
              >
                <Icon className="h-5 w-5 shrink-0" />
                <span>
                  <span className="block text-base font-bold">{v.label}</span>
                  <span className="block text-xs text-slate-400">{v.desc}</span>
                </span>
              </button>
            );
          })}
        </div>
      ) : (
        <>
          <Verdict
            correct={result.correct}
            title={result.correct ? `Good call: ${correctLabel}` : `Should have been: ${correctLabel ?? "see below"}`}
            xp={result.xp}
            explanation={result.explanation}
            trap={result.trap}
          />
          <ContinueButton onClick={() => complete(result.correct ? result.xp : 0, result.correct ? task.xp : 0)} />
        </>
      )}
    </div>
  );
}
