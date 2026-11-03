"use client";
import React, { useEffect, useMemo, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { Check, ArrowDown, ShieldCheck, ShieldX } from "lucide-react";
import { cn } from "@/lib/utils";
import { newShuffleSeed, shuffleWithSeed } from "@/lib/rooms/shuffle";
import type { BriefingLab } from "@/lib/rooms/experience";
import { DeckSortLab, HotspotLab, LineupLab, ReactorLab } from "./GameLabs";
import { AnatomyLab, LocksLab, TricksLab, XrayLab } from "./LensLabs";
import { EvidenceLab } from "./EvidenceLab";

/** Every lab reports once when the learner has worked all of it. */
interface LabProps<K extends BriefingLab["kind"]> {
  lab: Extract<BriefingLab, { kind: K }>;
  onDone: () => void;
}

function useDoneOnce(done: boolean, onDone: () => void) {
  const [fired, setFired] = useState(false);
  useEffect(() => { if (done && !fired) { setFired(true); onDone(); } }, [done, fired, onDone]);
}

const TONE = {
  trust: "border-neon-green/40 bg-neon-green/10 text-neon-green",
  warn: "border-neon-amber/40 bg-neon-amber/10 text-neon-amber",
  info: "border-cyber-400/40 bg-cyber-500/10 text-cyber-200",
} as const;

// ─── Inspect: click every part of a real-looking artifact ─────────────────────
export function InspectLab({ lab, onDone }: LabProps<"inspect">) {
  const [open, setOpen] = useState<string | null>(null);
  const [seen, setSeen] = useState<Set<string>>(new Set());
  useDoneOnce(seen.size === lab.items.length, onDone);
  const active = lab.items.find(i => i.id === open);
  return (
    <div className="grid gap-4 lg:grid-cols-[1.25fr_1fr]">
      <div className="rounded-xl border border-white/10 bg-[#04070e] p-2">
        <p className="px-2 pb-2 pt-1 text-[11px] uppercase tracking-[0.2em] text-slate-500">{lab.artifact}</p>
        <div className="space-y-1 font-mono text-[12px]">
          {lab.items.map(it => (
            <button
              key={it.id}
              onClick={() => { setOpen(it.id); setSeen(s => new Set(s).add(it.id)); }}
              aria-pressed={open === it.id}
              className={cn(
                "flex w-full items-start gap-2 rounded-lg px-2.5 py-2 text-left leading-relaxed transition",
                open === it.id ? "bg-cyber-500/15 ring-1 ring-cyber-400/60" : "hover:bg-white/5",
              )}
            >
              <span className={cn("mt-1 h-2 w-2 shrink-0 rounded-full", seen.has(it.id) ? "bg-neon-green" : "animate-pulse bg-cyber-300")} />
              <span className="break-all text-slate-200">{it.text}</span>
            </button>
          ))}
        </div>
      </div>
      <div aria-live="polite" className="min-h-[10rem] rounded-xl border border-white/10 bg-bg-panel/70 p-4">
        <AnimatePresence mode="wait">
          {active ? (
            <motion.div key={active.id} initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}>
              <span className={cn("inline-block rounded-full border px-2.5 py-0.5 text-[11px] font-semibold", TONE[active.tone])}>{active.tag}</span>
              <p className="mt-3 text-sm leading-relaxed text-slate-200">{active.note}</p>
            </motion.div>
          ) : (
            <p className="text-sm text-slate-400">Click a line on the left. Each one has a story.</p>
          )}
        </AnimatePresence>
        <p className="mt-4 text-[11px] text-slate-500">{seen.size} / {lab.items.length} inspected</p>
      </div>
    </div>
  );
}

// ─── Sequence: tap items in the right order ───────────────────────────────────
export function SequenceLab({ lab, onDone }: LabProps<"sequence">) {
  const [placed, setPlaced] = useState<string[]>([]);
  const [miss, setMiss] = useState<string | null>(null);
  const done = placed.length === lab.order.length;
  useDoneOnce(done, onDone);
  function tap(id: string) {
    if (done || placed.includes(id)) return;
    if (lab.order[placed.length] === id) { setPlaced(p => [...p, id]); setMiss(null); }
    else setMiss(id);
  }
  const byId = (id: string) => lab.items.find(i => i.id === id)!;
  return (
    <div className="grid gap-4 md:grid-cols-2">
      <div className="space-y-2">
        {lab.items.map(it => {
          const pos = placed.indexOf(it.id);
          return (
            <motion.button
              key={it.id}
              onClick={() => tap(it.id)}
              animate={miss === it.id ? { x: [0, -8, 8, -4, 4, 0] } : undefined}
              transition={{ duration: 0.35 }}
              disabled={pos >= 0}
              className={cn(
                "flex w-full items-center gap-3 rounded-xl border px-3 py-2.5 text-left text-sm transition",
                pos >= 0 ? "border-neon-green/40 bg-neon-green/10 text-neon-green"
                  : miss === it.id ? "border-neon-red/50 bg-neon-red/10 text-neon-red"
                    : "border-white/10 bg-bg-panel/60 text-slate-200 hover:border-cyber-400/50",
              )}
            >
              <span className="grid h-6 w-6 shrink-0 place-items-center rounded-full border border-current font-mono text-xs">{pos >= 0 ? pos + 1 : ""}</span>
              <span className="font-mono text-[12px] leading-snug">{it.text}</span>
            </motion.button>
          );
        })}
        {miss && <p role="status" className="text-xs text-neon-amber">Not yet. What has to happen before that?</p>}
      </div>
      <div className="rounded-xl border border-white/10 bg-[#04070e] p-4">
        <p className="mb-3 text-[11px] uppercase tracking-[0.2em] text-slate-500">Your sequence</p>
        <ol className="space-y-1">
          {placed.map((id, i) => (
            <motion.li key={id} initial={{ opacity: 0, x: 10 }} animate={{ opacity: 1, x: 0 }}>
              <div className="rounded-lg border border-cyber-500/30 bg-cyber-500/10 px-3 py-2">
                <p className="text-sm font-semibold text-white">{i + 1}. {byId(id).text}</p>
                {byId(id).note && <p className="mt-0.5 text-xs leading-relaxed text-slate-300">{byId(id).note}</p>}
              </div>
              {i < lab.order.length - 1 && <ArrowDown className="mx-auto my-0.5 h-3.5 w-3.5 text-cyber-400/70" />}
            </motion.li>
          ))}
          {!done && <li className="rounded-lg border border-dashed border-white/15 px-3 py-2 text-xs text-slate-500">Step {placed.length + 1}…</li>}
        </ol>
        {done && <p role="status" className="mt-3 rounded-lg border border-neon-green/30 bg-neon-green/10 p-3 text-sm leading-relaxed text-neon-green">{lab.doneNote}</p>}
      </div>
    </div>
  );
}

// ─── Simulate: run scenarios through a set of checks ──────────────────────────
export function SimulateLab({ lab, onDone }: LabProps<"simulate">) {
  const [sid, setSid] = useState<string | null>(null);
  const [tried, setTried] = useState<Set<string>>(new Set());
  const [step, setStep] = useState(0);
  useDoneOnce(tried.size === lab.scenarios.length, onDone);
  const sc = lab.scenarios.find(s => s.id === sid);
  useEffect(() => {
    if (!sc) return;
    setStep(0);
    const timers = lab.checks.map((_, i) => setTimeout(() => setStep(i + 1), 450 * (i + 1)));
    const fin = setTimeout(() => setTried(t => new Set(t).add(sc.id)), 450 * (lab.checks.length + 1));
    return () => { timers.forEach(clearTimeout); clearTimeout(fin); };
  }, [sc, lab.checks]);
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-2">
        {lab.scenarios.map(s => (
          <button
            key={s.id}
            onClick={() => setSid(s.id)}
            aria-pressed={sid === s.id}
            className={cn(
              "rounded-full border px-4 py-2 text-sm font-semibold transition",
              sid === s.id ? "border-cyber-300 bg-cyber-500/20 text-white" : "border-white/15 bg-bg-panel/60 text-slate-300 hover:border-cyber-400/50",
            )}
          >
            {tried.has(s.id) && <Check className="mr-1 inline h-3.5 w-3.5 text-neon-green" />}{s.label}
          </button>
        ))}
      </div>
      {sc ? (
        <div>
          <p className="rounded-lg border border-white/10 bg-[#04070e] px-3 py-2 font-mono text-[12px] text-slate-300">{sc.detail}</p>
          <div className="mt-3 grid gap-3 md:grid-cols-3">
            {lab.checks.map((c, i) => {
              const shown = step > i;
              const pass = sc.results[i] === "pass";
              return (
                <div key={c.name} className={cn(
                  "rounded-xl border p-3 transition-colors duration-300",
                  !shown ? "border-white/10 bg-bg-panel/50" : pass ? "border-neon-green/40 bg-neon-green/10" : "border-neon-red/40 bg-neon-red/10",
                )}>
                  <div className="flex items-center gap-2">
                    {shown ? (pass ? <ShieldCheck className="h-5 w-5 text-neon-green" /> : <ShieldX className="h-5 w-5 text-neon-red" />) : <span className="h-5 w-5 animate-pulse rounded-full bg-white/10" />}
                    <span className="font-bold text-white">{c.name}</span>
                    {shown && <span className={cn("ml-auto font-mono text-xs font-bold uppercase", pass ? "text-neon-green" : "text-neon-red")}>{sc.results[i]}</span>}
                  </div>
                  <p className="mt-1.5 text-[11px] text-slate-400">{c.question}</p>
                  {shown && <p className="mt-2 text-xs leading-relaxed text-slate-200">{sc.why[i]}</p>}
                </div>
              );
            })}
          </div>
          {step >= lab.checks.length && (
            <motion.p initial={{ opacity: 0 }} animate={{ opacity: 1 }} role="status" className="mt-3 rounded-lg border border-indigo-400/30 bg-indigo-500/10 p-3 text-sm leading-relaxed text-indigo-100">
              {sc.verdict}
            </motion.p>
          )}
        </div>
      ) : (
        <p className="text-sm text-slate-400">Choose a scenario above.</p>
      )}
    </div>
  );
}

// Sort labs render as a card deck: see DeckSortLab in GameLabs.tsx.

// ─── Match: connect each left item to its right item ──────────────────────────
export function MatchLab({ lab, onDone }: LabProps<"match">) {
  const rights = useMemo(() => shuffleWithSeed(lab.pairs, newShuffleSeed()), [lab.pairs]);
  const [pick, setPick] = useState<string | null>(null);
  const [matched, setMatched] = useState<string[]>([]);
  const [wrong, setWrong] = useState<string | null>(null);
  useDoneOnce(matched.length === lab.pairs.length, onDone);
  function choose(rightId: string) {
    if (!pick) return;
    if (pick === rightId) { setMatched(m => [...m, pick]); setPick(null); setWrong(null); }
    else setWrong(rightId);
  }
  const last = matched.length ? lab.pairs.find(p => p.id === matched[matched.length - 1]) : null;
  return (
    <div className="space-y-3">
      <div className="grid gap-3 md:grid-cols-2">
        <div className="space-y-2">
          {lab.pairs.map(p => {
            const done = matched.includes(p.id);
            return (
              <button
                key={p.id}
                disabled={done}
                onClick={() => { setPick(p.id); setWrong(null); }}
                aria-pressed={pick === p.id}
                className={cn(
                  "w-full rounded-xl border px-3 py-2.5 text-left text-sm transition",
                  done ? "border-neon-green/40 bg-neon-green/10 text-neon-green"
                    : pick === p.id ? "border-cyber-300 bg-cyber-500/20 text-white shadow-glow" : "border-white/10 bg-bg-panel/60 text-slate-200 hover:border-cyber-400/50",
                )}
              >
                {p.left}
              </button>
            );
          })}
        </div>
        <div className="space-y-2">
          {rights.map(p => {
            const done = matched.includes(p.id);
            return (
              <motion.button
                key={p.id}
                disabled={done || !pick}
                onClick={() => choose(p.id)}
                animate={wrong === p.id ? { x: [0, -8, 8, -4, 4, 0] } : undefined}
                transition={{ duration: 0.35 }}
                className={cn(
                  "w-full rounded-xl border px-3 py-2.5 text-left text-sm transition",
                  done ? "border-neon-green/40 bg-neon-green/10 text-neon-green"
                    : wrong === p.id ? "border-neon-red/50 bg-neon-red/10 text-neon-red"
                      : pick ? "border-white/15 bg-bg-panel/60 text-slate-200 hover:border-cyber-400/60" : "border-white/10 bg-bg-panel/40 text-slate-400",
                )}
              >
                {p.right}
              </motion.button>
            );
          })}
        </div>
      </div>
      <p role="status" className="min-h-[1.25rem] text-xs leading-relaxed">
        {wrong ? <span className="text-neon-red">Not a match. Try another.</span>
          : last ? <span className="text-neon-green"><Check className="mr-1 inline h-3.5 w-3.5" />{last.left} → {last.right}. {last.why}</span>
            : <span className="text-slate-500">Pick an item on the left, then its match on the right.</span>}
      </p>
    </div>
  );
}

export function Lab({ lab, onDone }: { lab: BriefingLab; onDone: () => void }) {
  switch (lab.kind) {
    case "inspect":  return <InspectLab lab={lab} onDone={onDone} />;
    case "sequence": return <SequenceLab lab={lab} onDone={onDone} />;
    case "simulate": return <SimulateLab lab={lab} onDone={onDone} />;
    case "sort":     return <DeckSortLab lab={lab} onDone={onDone} />;
    case "match":    return <MatchLab lab={lab} onDone={onDone} />;
    case "reactor":  return <ReactorLab lab={lab} onDone={onDone} />;
    case "lineup":   return <LineupLab lab={lab} onDone={onDone} />;
    case "hotspot":  return <HotspotLab lab={lab} onDone={onDone} />;
    case "xray":     return <XrayLab lab={lab} onDone={onDone} />;
    case "locks":    return <LocksLab lab={lab} onDone={onDone} />;
    case "tricks":   return <TricksLab lab={lab} onDone={onDone} />;
    case "anatomy":  return <AnatomyLab lab={lab} onDone={onDone} />;
    case "evidence": return <EvidenceLab lab={lab} onDone={onDone} />;
  }
}

// Default "how to play" steps per lab kind; a lab can override them with howTo.
const HOW_TO: Record<BriefingLab["kind"], string[]> = {
  inspect: ["Click each highlighted part of the artifact.", "Read what it tells you."],
  sequence: ["Tap the steps in the order they happen.", "A wrong step shakes: try another."],
  simulate: ["Pick a scenario.", "Watch each check pass or fail, and read why."],
  sort: ["Read the card on top of the deck.", "Tap the bin it belongs in.", "Read why, then take the next card."],
  match: ["Tap an item on the left.", "Tap its partner on the right."],
  reactor: ["Read the incident riding the belt.", "Tap the reactor it damages before it reaches the end."],
  lineup: ["Read the evidence for this round.", "Hover or tap suspects to read their dossiers.", "Tap the suspect who fits, then go to the next round."],
  hotspot: ["Click every part of the artifact you would question.", "Find all the red flags to finish."],
  xray: ["Tap an everyday object to scan it with the lens.", "Read the computer inside it and what an attacker could do.", "Scan every object to finish."],
  locks: ["Tap a door and read its idea and example.", "Answer the door's question to open its lock.", "Open all the doors to finish."],
  tricks: ["Tap a face-down card to flip it and read the trick.", "Tap the stamp with the attack that works the same way.", "Stamp every card to finish."],
  anatomy: ["Tap each field with a scan mark.", "Read what that field tells an analyst.", "Decode every marked field to read the alert's story."],
  evidence: ["Study the screen.", "Tap what you think it shows.", "Read the numbered clues on the screen, then go to the next one."],
};

export function HowToPlay({ lab }: { lab: BriefingLab }) {
  const steps = lab.howTo ?? HOW_TO[lab.kind];
  return (
    <ol className="mb-4 flex flex-wrap gap-x-4 gap-y-1.5 rounded-xl border border-white/10 bg-white/[0.03] px-3 py-2 text-xs text-slate-200" aria-label="How to play">
      <li className="font-bold uppercase tracking-[0.2em] text-slate-400">How to play</li>
      {steps.map((s, i) => (
        <li key={s} className="flex gap-1.5"><span className="grid h-4 w-4 shrink-0 place-items-center rounded-full bg-white/10 text-[10px] font-bold">{i + 1}</span>{s}</li>
      ))}
    </ol>
  );
}
