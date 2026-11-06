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
import { EncapLab, QueueLab, TerminalLab, TraceLab, WorksheetLab } from "./PracticeLabs";
import { PcapLab } from "./PcapLab";
import { PortalLab } from "./PortalLab";
import { HuntLab } from "./HuntLab";
import { InlineMd } from "@/components/rooms/InlineMd";
import { ChatLab } from "./ChatLab";
import { CodebreakLab, DefuseLab, DeduceLab, DuelLab, InterceptLab, OutbreakLab, PathwayLab, RushLab, SpotDiffLab, TuneLab } from "./ArcadeLabs";

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
    case "terminal": return <TerminalLab lab={lab} onDone={onDone} />;
    case "chat": return <ChatLab lab={lab} onDone={onDone} />;
    case "trace":    return <TraceLab lab={lab} onDone={onDone} />;
    case "encap":    return <EncapLab lab={lab} onDone={onDone} />;
    case "queue":    return <QueueLab lab={lab} onDone={onDone} />;
    case "worksheet": return <WorksheetLab lab={lab} onDone={onDone} />;
    case "pcap":     return <PcapLab lab={lab} onDone={onDone} />;
    case "portal":   return <PortalLab lab={lab} onDone={onDone} />;
    case "hunt":     return <HuntLab lab={lab} onDone={onDone} />;
    case "intercept": return <InterceptLab lab={lab} onDone={onDone} />;
    case "duel":     return <DuelLab lab={lab} onDone={onDone} />;
    case "deduce":   return <DeduceLab lab={lab} onDone={onDone} />;
    case "tune":     return <TuneLab lab={lab} onDone={onDone} />;
    case "pathway":  return <PathwayLab lab={lab} onDone={onDone} />;
    case "defuse":   return <DefuseLab lab={lab} onDone={onDone} />;
    case "outbreak": return <OutbreakLab lab={lab} onDone={onDone} />;
    case "codebreak": return <CodebreakLab lab={lab} onDone={onDone} />;
    case "rush":     return <RushLab lab={lab} onDone={onDone} />;
    case "spotdiff": return <SpotDiffLab lab={lab} onDone={onDone} />;
  }
}

// Default "how to play" steps per lab kind, plus how you know you have finished;
// a lab can override the steps with howTo.
const HOW_TO: Record<BriefingLab["kind"], { steps: string[]; done: string }> = {
  hunt: { steps: ["Read what the next line of the query has to do.", "Pick a line: it runs at once, and the results below are what it really returns.", "A wrong line shows its result, tells you why, and costs a life. The schema on the left lists every table and column."], done: "the query returns what you were asked for" },
  portal: { steps: ["Read the job for this step above the console.", "Work in the console as you would at your desk: menus, rows, buttons, drop-downs.", "Looking around is free. A wrong action costs a life and tells you why."], done: "the whole job is done" },
  intercept: { steps: ["An item drops toward what you guard.", "Block it or let it through before it lands: doing nothing lets it through.", "A wrong call costs a life. Lose three and the run is over."], done: "the last item has landed and you are still standing" },
  duel: { steps: ["Read the move the attacker just played.", "Play the one card from your hand that stops it.", "A wrong card costs a life, and a played card is gone."], done: "the attacker is out of moves" },
  deduce: { steps: ["Read the clue and rule out who it clears with the X.", "Take another clue if you need it: fewer is better.", "Pick a suspect and accuse. You get two accusations."], done: "you name the culprit" },
  tune: { steps: ["Study the events: what do the attacks share?", "Set the dials, then press Deploy to see what the rule really caught.", "Deploys are limited: hit the goal before you run out."], done: "the rule meets the goal" },
  pathway: { steps: ["You start on the lit node.", "Tap the next hop among the nodes that connect to it.", "A wrong hop costs a life and tells you why."], done: "you reach the end of the route" },
  defuse: { steps: ["Read what the device shows.", "Cut the one wire that fits it, before the clock runs out.", "A wrong cut is a strike and costs ten seconds."], done: "every module is safe" },
  outbreak: { steps: ["Red hosts are infected; lines are the links it can travel.", "Tap one host to isolate it. Then the infection moves one link.", "Cut ahead of it, where one cut protects the most hosts."], done: "the spread stops, the target is safe and enough hosts survive" },
  codebreak: { steps: ["Read the clue and type a guess of exactly that length.", "Green is the right place; amber is in the code but elsewhere.", "Crack it before your tries run out."], done: "every code is cracked" },
  rush: { steps: ["Read the card and make the call, fast.", "Streaks multiply your points.", "Reach the target before the clock stops."], done: "you hit the target" },
  spotdiff: { steps: ["Compare the suspect copy with the known-good one, line by line.", "Tap each line that was tampered with.", "A false accusation costs a life."], done: "every change is found" },
  inspect: { steps: ["Tap each glowing part of the artifact.", "Read the note that opens: it says what that part reveals."], done: "every glowing part is opened" },
  sequence: { steps: ["Read all the steps first.", "Tap them in the order they really happen.", "A wrong tap shakes: think again and tap another."], done: "the whole chain is in order" },
  simulate: { steps: ["Pick one scenario from the list.", "Watch each check run, pass or fail.", "Read why each one passed or failed, then try the next scenario."], done: "every scenario has run" },
  sort: { steps: ["Read the card at the top of the deck.", "Tap the bin it belongs in.", "Read why, then the next card appears."], done: "the deck is empty" },
  match: { steps: ["Tap an item in the left column.", "Tap the item on the right that goes with it.", "A correct pair locks green."], done: "every pair is locked" },
  reactor: { steps: ["Read the card riding the belt toward the end.", "Tap the reactor it belongs in before it gets there.", "Read why, then the next card rides in."], done: "the belt is cleared" },
  lineup: { steps: ["Read the evidence for this round.", "Tap each suspect to read their dossier.", "Tap the one the evidence points to."], done: "every round has a culprit" },
  hotspot: { steps: ["Look over the whole artifact.", "Tap every part you would question.", "Each red flag you find is counted at the top."], done: "all the red flags are found" },
  xray: { steps: ["Tap an everyday object to scan it.", "Read the computer hidden inside and what an attacker could do with it."], done: "every object is scanned" },
  locks: { steps: ["Tap a door to read its idea and an example.", "Answer the door's question to open its lock."], done: "every door is open" },
  tricks: { steps: ["Tap a face-down card to flip it.", "Read the trick on it.", "Tap the stamp for the attack that works the same way."], done: "every card is stamped" },
  anatomy: { steps: ["Tap a field with a scan mark.", "Read what that field tells an analyst.", "Work down the record field by field."], done: "every marked field is decoded" },
  evidence: { steps: ["Study the screen shown.", "Tap what you think it shows.", "Read the numbered clues, then move to the next screen."], done: "every screen is answered" },
  chat: { steps: ["Read your goal at the top.", "Tap a message or write your own, then read the reply.", "Keep trying: some messages fail, and that teaches you why the others work."], done: "every goal is reached" },
  terminal: { steps: ["Read your task at the top.", "Tap a command (or type it) and read the output in the console.", "Type what you found in the answer box and press Check."], done: "every task is answered" },
  trace: { steps: ["Read the question for this step.", "Filter the log with a value from the case board.", "Tap the row that answers it; the next log opens."], done: "the trail reaches its last log" },
  queue: { steps: ["Tap an alert in the queue.", "Read its fields and the context beside it.", "Choose what an analyst would do with it."], done: "the queue is empty" },
  pcap: { steps: ["Read the task.", "Type a display filter and press Apply (dns, http, ip.addr==…).", "Tap a packet and read its layers to find the answer."], done: "every task is answered" },
  worksheet: { steps: ["Study the table: every answer is in it.", "Read the first question and find its row or column.", "Type the answer and press Check (tap 'How do I work it out?' if stuck)."], done: "every question is checked" },
  encap: { steps: ["Read the request being sent.", "At each layer, pick the value its header carries.", "Watch the packet grow, then read it as an analyser would."], done: "the packet is fully built" },
};

/** The short teaching card before a lab: just what this lab needs, with one worked example. */
export function Primer({ lab }: { lab: BriefingLab }) {
  const p = lab.primer;
  if (!p) return null;
  return (
    <details open={!p.fold} className="mb-3 rounded-xl border border-white/15 bg-white/[0.04] p-4">
      <summary className="cursor-pointer select-none text-[11px] font-black uppercase tracking-[0.18em] text-slate-200">What you need to know</summary>
      <p className="mt-2 text-base font-bold leading-snug text-white">{p.title}</p>
      <ul className="mt-2 space-y-1.5">
        {p.points.map(t => <li key={t} className="flex gap-2 text-sm leading-relaxed text-slate-100"><span aria-hidden className="mt-2 h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: "var(--room-accent, #38bdf8)" }} /><span className="min-w-0"><InlineMd text={t} /></span></li>)}
      </ul>
      {p.example && (
        <div className="mt-3 rounded-lg border border-white/10 bg-black/30 p-3">
          <p className="text-[11px] font-bold uppercase tracking-wider text-slate-300">{p.example.label}</p>
          <div className="mt-1.5 space-y-1">{p.example.lines.map(l => <p key={l} className="text-sm leading-relaxed text-slate-100 [overflow-wrap:anywhere]"><InlineMd text={l} /></p>)}</div>
        </div>
      )}
    </details>
  );
}

export function HowToPlay({ lab }: { lab: BriefingLab }) {
  // First time with a game: open. After that it folds to one line, so the game is on screen.
  const key = `howto_seen:${lab.kind}`;
  const [seen, setSeen] = useState(false);
  useEffect(() => {
    try { if (localStorage.getItem(key)) setSeen(true); else localStorage.setItem(key, "1"); } catch { /* storage blocked: stays open */ }
  }, [key]);
  // The console lab carries its own step-by-step card next to the task.
  if (lab.kind === "terminal" && !lab.howTo) return null;
  const base = HOW_TO[lab.kind];
  const steps = lab.howTo ?? base.steps;
  return (
    <details open={!seen} className="mb-4 rounded-xl border p-3" style={{ borderColor: "color-mix(in srgb, var(--room-accent, #38bdf8) 45%, transparent)", background: "color-mix(in srgb, var(--room-accent, #38bdf8) 10%, transparent)" }}>
      <summary className="cursor-pointer select-none text-[11px] font-black uppercase tracking-[0.18em]" style={{ color: "var(--room-accent, #7dd3fc)" }}>What you do here</summary>
      <ol className="mt-2 space-y-1.5">
        {steps.map((s, i) => (
          <li key={s} className="flex gap-2 text-sm leading-snug text-slate-100">
            <span className="grid h-5 w-5 shrink-0 place-items-center rounded-full text-[11px] font-bold text-white" style={{ background: "color-mix(in srgb, var(--room-accent, #38bdf8) 40%, transparent)" }}>{i + 1}</span>{s}
          </li>
        ))}
      </ol>
      <p className="mt-2 text-xs text-emerald-200"><span className="font-bold">Finished when:</span> {base.done}.</p>
    </details>
  );
}
