"use client";
import { useState, useCallback } from "react";
import { cn } from "@/lib/utils";
import { X, Check, ChevronRight } from "lucide-react";
import type { LiveEvent } from "./useLiveEvents";

type KillChainPhase =
  | "Initial Access"
  | "Execution"
  | "C2"
  | "Credential / Lateral"
  | "Impact";

const PHASES: KillChainPhase[] = [
  "Initial Access",
  "Execution",
  "C2",
  "Credential / Lateral",
  "Impact",
];

const TECHNIQUE_TO_PHASE: Record<string, KillChainPhase> = {
  "T1566.001": "Initial Access",
  "T1566.002": "Initial Access",
  "T1078":     "Initial Access",
  "T1110.003": "Initial Access",
  "T1133":     "Initial Access",
  "T1190":     "Initial Access",

  "T1059.001": "Execution",
  "T1059.003": "Execution",
  "T1047":     "Execution",
  "T1053.005": "Execution",
  "T1218.011": "Execution",
  "T1204.002": "Execution",

  "T1071.001": "C2",
  "T1071.004": "C2",
  "T1095":     "C2",
  "T1105":     "C2",
  "T1219":     "C2",

  "T1003.001": "Credential / Lateral",
  "T1021.001": "Credential / Lateral",
  "T1021.002": "Credential / Lateral",
  "T1550.002": "Credential / Lateral",
  "T1114.002": "Credential / Lateral",
  "T1098.005": "Credential / Lateral",

  "T1486":     "Impact",
  "T1490":     "Impact",
  "T1485":     "Impact",
  "T1561.002": "Impact",
  "T1048":     "Impact",
};

function phaseForEvent(event: LiveEvent): KillChainPhase | null {
  const t = event.mitre_technique;
  if (!t) return null;
  // Handle sub-techniques like T1059.001
  const exact = TECHNIQUE_TO_PHASE[t];
  if (exact) return exact;
  const base = t.split(".")[0];
  return TECHNIQUE_TO_PHASE[base] ?? null;
}

type SlotMap = Partial<Record<KillChainPhase, LiveEvent>>;

const PHASE_COLORS: Record<KillChainPhase, { border: string; bg: string; text: string; dot: string }> = {
  "Initial Access":       { border: "border-severity-high/50",     bg: "bg-severity-high/10",     text: "text-severity-high",     dot: "bg-severity-high" },
  "Execution":            { border: "border-neon-amber/50",         bg: "bg-neon-amber/10",         text: "text-neon-amber",         dot: "bg-neon-amber" },
  "C2":                   { border: "border-neon-purple/50",        bg: "bg-neon-purple/10",        text: "text-neon-purple",        dot: "bg-neon-purple" },
  "Credential / Lateral": { border: "border-cyber-500/50",          bg: "bg-cyber-500/10",          text: "text-cyber-300",          dot: "bg-cyber-400" },
  "Impact":               { border: "border-severity-critical/50",  bg: "bg-severity-critical/10",  text: "text-severity-critical",  dot: "bg-severity-critical" },
};

interface AttackChainBoardProps {
  events: LiveEvent[];
  onClose: () => void;
  onXpAward?: (xp: number) => void;
}

export function AttackChainBoard({ events, onClose, onXpAward }: AttackChainBoardProps) {
  const [slots, setSlots]           = useState<SlotMap>({});
  const [dragging, setDragging]     = useState<LiveEvent | null>(null);
  const [hoverPhase, setHoverPhase] = useState<KillChainPhase | null>(null);
  const [submitted, setSubmitted]   = useState(false);
  const [score, setScore]           = useState<{ correct: number; total: number; xp: number } | null>(null);

  const placed = new Set(Object.values(slots).map(e => e?.id));
  const unplaced = events.filter(e => !placed.has(e.id));

  const handleDrop = useCallback((phase: KillChainPhase) => {
    if (!dragging) return;
    setSlots(prev => ({ ...prev, [phase]: dragging }));
    setDragging(null);
    setHoverPhase(null);
  }, [dragging]);

  const handleRemove = (phase: KillChainPhase) => {
    setSlots(prev => {
      const next = { ...prev };
      delete next[phase];
      return next;
    });
  };

  const handleSubmit = () => {
    let correct = 0;
    const total = PHASES.length;
    PHASES.forEach(phase => {
      const assigned = slots[phase];
      if (!assigned) return;
      const expectedPhase = phaseForEvent(assigned);
      if (expectedPhase === phase) correct++;
    });
    const xp = correct * 5 + (correct === total ? 50 : 0);
    setScore({ correct, total, xp });
    setSubmitted(true);
    onXpAward?.(xp);
  };

  const canSubmit = Object.keys(slots).length >= Math.min(PHASES.length, events.filter(e => e.ruleLevel >= 7).length);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
      <div className="relative w-full max-w-3xl rounded-xl border border-border bg-bg-elevated shadow-2xl overflow-hidden max-h-[90vh] flex flex-col">
        <div className="h-1 w-full bg-gradient-to-r from-severity-high via-neon-purple to-severity-critical" />

        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-border/50">
          <div>
            <p className="text-[9px] font-bold uppercase tracking-[0.2em] text-slate-500">LO-3 — Attack Chain Reconstruction</p>
            <h2 className="text-sm font-bold text-white">Build the Kill Chain</h2>
          </div>
          <button onClick={onClose} className="rounded p-1 text-slate-400 hover:text-white transition">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="overflow-y-auto flex-1 px-6 py-5 space-y-5">
          {/* Instructions */}
          <p className="text-[10px] text-slate-400 leading-relaxed">
            Drag each event below into its correct Kill-Chain phase. Benign events should be left unassigned.
            <span className="text-neon-purple"> +5 XP per correct slot, +50 XP bonus for a perfect chain.</span>
          </p>

          {/* Kill-chain slots */}
          <div className="flex items-start gap-1">
            {PHASES.map((phase, i) => {
              const c = PHASE_COLORS[phase];
              const assigned = slots[phase];
              const isHovering = hoverPhase === phase;
              const isCorrect = submitted && assigned && phaseForEvent(assigned) === phase;
              const isWrong   = submitted && assigned && phaseForEvent(assigned) !== phase;

              return (
                <div key={phase} className="flex items-center gap-1 flex-1 min-w-0">
                  <div
                    className={cn(
                      "flex-1 min-w-0 rounded-lg border-2 border-dashed transition p-2 min-h-[90px] flex flex-col",
                      isHovering && !submitted
                        ? `${c.border} ${c.bg}`
                        : submitted
                          ? isCorrect ? "border-neon-green/50 bg-neon-green/5"
                            : isWrong ? "border-severity-critical/50 bg-severity-critical/5"
                            : "border-border/40 bg-[#060b12]"
                        : "border-border/40 bg-[#060b12] hover:border-border"
                    )}
                    onDragOver={e => { e.preventDefault(); if (!submitted) setHoverPhase(phase); }}
                    onDragLeave={() => setHoverPhase(null)}
                    onDrop={() => { if (!submitted) handleDrop(phase); }}
                  >
                    <div className="flex items-center gap-1 mb-1.5">
                      <span className={cn("h-1.5 w-1.5 rounded-full shrink-0", c.dot)} />
                      <p className={cn("text-[8px] font-bold uppercase tracking-wider truncate", c.text)}>
                        {phase}
                      </p>
                    </div>

                    {assigned ? (
                      <div className="flex-1 relative group">
                        <div className={cn(
                          "rounded border p-1.5 text-[9px] leading-snug",
                          submitted
                            ? isCorrect
                              ? "border-neon-green/40 bg-neon-green/10 text-neon-green"
                              : "border-severity-critical/40 bg-severity-critical/10 text-severity-critical"
                            : "border-border/50 bg-slate-900/60 text-slate-300"
                        )}>
                          <div className="flex items-start justify-between gap-1">
                            <span className="truncate leading-tight">{assigned.displayDescription ?? assigned.description}</span>
                            {!submitted && (
                              <button
                                onClick={() => handleRemove(phase)}
                                className="shrink-0 text-slate-500 hover:text-white"
                              >
                                <X className="h-2.5 w-2.5" />
                              </button>
                            )}
                          </div>
                          {assigned.mitre_technique && (
                            <span className="font-mono text-[8px] text-neon-purple/80">{assigned.mitre_technique}</span>
                          )}
                          {submitted && (
                            <div className="mt-1">
                              {isCorrect
                                ? <span className="text-neon-green font-bold">✓ Correct</span>
                                : <span className="text-severity-critical font-bold">✗ {phaseForEvent(assigned) ?? "No clear phase"}</span>}
                            </div>
                          )}
                        </div>
                      </div>
                    ) : (
                      <div className="flex-1 flex items-center justify-center">
                        <p className="text-[9px] text-slate-600">Drop event here</p>
                      </div>
                    )}
                  </div>

                  {i < PHASES.length - 1 && (
                    <ChevronRight className="h-3 w-3 text-slate-600 shrink-0" />
                  )}
                </div>
              );
            })}
          </div>

          {/* Event pool */}
          <div>
            <p className="text-[9px] font-bold uppercase tracking-wider text-slate-500 mb-2">Events to Assign</p>
            {unplaced.length === 0 ? (
              <p className="text-[10px] text-slate-500 italic">All events have been placed.</p>
            ) : (
              <div className="flex flex-wrap gap-2">
                {unplaced.map(event => (
                  <div
                    key={event.id}
                    draggable={!submitted}
                    onDragStart={() => setDragging(event)}
                    onDragEnd={() => setDragging(null)}
                    className={cn(
                      "rounded border px-2.5 py-1.5 text-[10px] cursor-grab select-none transition max-w-[220px]",
                      dragging?.id === event.id
                        ? "border-neon-purple/60 bg-neon-purple/15 opacity-70 scale-95"
                        : "border-border/60 bg-[#060b12] hover:border-border text-slate-300",
                      submitted && "opacity-40 cursor-default"
                    )}
                    title={event.displayDescription ?? event.description}
                  >
                    <p className="truncate font-medium">{event.displayDescription ?? event.description}</p>
                    {event.mitre_technique && (
                      <p className="font-mono text-[8px] text-neon-purple/70 mt-0.5">{event.mitre_technique}</p>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Score */}
          {submitted && score && (
            <div className={cn(
              "rounded-lg border px-5 py-4",
              score.correct === score.total
                ? "border-neon-green/40 bg-neon-green/5"
                : "border-neon-amber/40 bg-neon-amber/5"
            )}>
              <div className="flex items-center justify-between mb-2">
                <p className={cn(
                  "text-sm font-bold",
                  score.correct === score.total ? "text-neon-green" : "text-neon-amber"
                )}>
                  {score.correct === score.total
                    ? "Perfect kill chain! 🏆"
                    : `${score.correct} / ${score.total} slots correct`}
                </p>
                <p className="font-mono text-sm font-bold text-neon-green">+{score.xp} XP</p>
              </div>
              <p className="text-[10px] text-slate-400 leading-relaxed">
                {score.correct === score.total
                  ? "You reconstructed the full attack campaign from Initial Access to Impact. That's Tier-2 level thinking."
                  : `${score.total - score.correct} slot(s) were incorrect. Check the red cells to see where events actually belong in the kill chain.`}
              </p>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="border-t border-border/50 px-6 py-3 flex items-center justify-between bg-[#060b12]">
          <button onClick={onClose} className="text-xs text-slate-500 hover:text-slate-300 transition">
            {submitted ? "Close" : "Skip for now"}
          </button>
          {!submitted && (
            <button
              onClick={handleSubmit}
              disabled={!canSubmit}
              className={cn(
                "flex items-center gap-2 rounded border px-4 py-2 text-xs font-bold transition",
                canSubmit
                  ? "border-neon-green/40 bg-neon-green/10 text-neon-green hover:bg-neon-green/20"
                  : "border-border/40 text-slate-600 cursor-not-allowed opacity-50"
              )}
            >
              <Check className="h-3.5 w-3.5" /> Submit Chain
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
