"use client";
import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { Heart, Timer, Flame, RotateCcw, ShieldX, ShieldCheck, Check, X, Search, Scissors, Crosshair, Trophy, Lightbulb, Lock } from "lucide-react";
import { cn } from "@/lib/utils";
import { newShuffleSeed, shuffleWithSeed } from "@/lib/rooms/shuffle";
import type { BriefingLab } from "@/lib/rooms/experience";

// Games with stakes: a clock, lives, a streak and a real way to lose. The game exists to
// show the idea and teach it, so every outcome teaches: a wrong move says why, the clock
// stops while an explanation is on screen, and a lost run ends on the lesson, not on a
// score. They award nothing beyond the lab itself and report once when won. From the first
// loss the learner can retry without the clock, so nobody is ever stuck behind a timer
// (WCAG 2.2.1). Every game takes the room's colours from --room-accent.

interface LabProps<K extends BriefingLab["kind"]> {
  lab: Extract<BriefingLab, { kind: K }>;
  onDone: () => void;
}

interface Game {
  /** False once the learner chose to play without the clock. */
  clock: boolean;
  lose: (why: string) => void;
  win: () => void;
  won: boolean;
}

const shuffled = <T,>(items: readonly T[]) => shuffleWithSeed([...items], newShuffleSeed());
const ACCENT = "var(--room-accent, #38bdf8)";

/** Holds a run: restart on a loss, a fresh key for each run, onDone once. */
function Arena({ onDone, lesson, timed, children }: { onDone: () => void; lesson: string; timed?: boolean; children: (g: Game) => React.ReactNode }) {
  const [run, setRun] = useState(0);
  const [lost, setLost] = useState<string | null>(null);
  const [won, setWon] = useState(false);
  const [clock, setClock] = useState(true);
  const fired = useRef(false);
  const win = useCallback(() => {
    setWon(true);
    if (!fired.current) { fired.current = true; onDone(); }
  }, [onDone]);
  const lose = useCallback((why: string) => setLost(why), []);
  const retry = (withClock: boolean) => { setClock(withClock); setLost(null); setRun(r => r + 1); };

  if (lost) {
    return (
      <motion.div initial={{ opacity: 0, scale: 0.96 }} animate={{ opacity: 1, scale: 1 }} role="status"
        className="rounded-2xl border border-rose-400/40 bg-rose-500/10 p-6 text-center">
        <ShieldX className="mx-auto h-9 w-9 text-rose-300" />
        <p className="mt-2 text-lg font-extrabold text-white">Run over</p>
        <p className="mx-auto mt-1 max-w-md text-sm leading-relaxed text-slate-200">{lost}</p>
        <div className="mx-auto mt-3 max-w-lg rounded-xl border border-white/10 bg-black/30 p-3 text-left">
          <p className="flex items-center gap-1.5 text-[11px] font-bold uppercase tracking-wider text-amber-300"><Lightbulb className="h-3.5 w-3.5" />What to take from this</p>
          <p className="mt-1 text-sm leading-relaxed text-slate-100">{lesson}</p>
        </div>
        <div className="mt-4 flex flex-wrap justify-center gap-2">
          <button autoFocus onClick={() => retry(clock)} className="inline-flex items-center gap-2 rounded-xl px-5 py-2.5 text-sm font-bold text-[#04121a]" style={{ background: ACCENT }}>
            <RotateCcw className="h-4 w-4" /> Run it again
          </button>
          {timed && clock && (
            <button onClick={() => retry(false)} className="rounded-xl border border-white/20 px-5 py-2.5 text-sm font-semibold text-slate-200 hover:border-white/40">
              Try without the clock
            </button>
          )}
        </div>
      </motion.div>
    );
  }
  return <div key={run}>{children({ clock, lose, win, won })}</div>;
}

/** Counts down once a second while running; calls onZero at zero. */
function useCountdown(seconds: number, running: boolean, onZero: () => void) {
  const [left, setLeft] = useState(seconds);
  const zero = useRef(onZero);
  zero.current = onZero;
  useEffect(() => {
    if (!running) return;
    const t = setInterval(() => setLeft(s => s - 1), 1000);
    return () => clearInterval(t);
  }, [running]);
  useEffect(() => { if (running && left <= 0) zero.current(); }, [left, running]);
  return { left, setLeft };
}

function Lives({ left, max }: { left: number; max: number }) {
  return (
    <span className="inline-flex items-center gap-0.5" aria-label={`${left} of ${max} lives left`}>
      {Array.from({ length: max }, (_, i) => <Heart key={i} className={cn("h-4 w-4", i < left ? "fill-rose-400 text-rose-400" : "text-slate-600")} />)}
    </span>
  );
}

function Hud({ left, max, score, combo, seconds, label }: { left?: number; max?: number; score?: React.ReactNode; combo?: number; seconds?: number; label?: string }) {
  return (
    <div className="mb-3 flex flex-wrap items-center gap-x-4 gap-y-1 rounded-xl border border-white/10 bg-black/30 px-3 py-2 text-xs text-slate-300">
      {left !== undefined && max !== undefined && <Lives left={left} max={max} />}
      {label && <span className="font-semibold text-slate-200">{label}</span>}
      {combo !== undefined && combo > 1 && (
        <motion.span key={combo} initial={{ scale: 1.5 }} animate={{ scale: 1 }} className="inline-flex items-center gap-1 font-bold text-amber-300"><Flame className="h-3.5 w-3.5" />{combo} in a row</motion.span>
      )}
      {score !== undefined && <span className="ml-auto font-mono font-bold text-white">{score}</span>}
      {seconds !== undefined && (
        <span className={cn("inline-flex items-center gap-1 font-mono font-bold", score === undefined && "ml-auto", seconds <= 10 ? "text-rose-300" : "text-slate-200")}>
          <Timer className="h-3.5 w-3.5" />{Math.max(0, seconds)}s
        </span>
      )}
    </div>
  );
}

function Win({ title, children }: { title: string; children?: React.ReactNode }) {
  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} role="status" className="mt-3 rounded-xl border border-emerald-400/40 bg-emerald-500/10 p-4">
      <p className="flex items-center gap-2 text-sm font-bold text-emerald-200"><Trophy className="h-4 w-4" />{title}</p>
      {children && <div className="mt-1 text-sm leading-relaxed text-slate-200">{children}</div>}
    </motion.div>
  );
}

// ─── Intercept: stop the bad ones before they land ───────────────────────────
export function InterceptLab({ lab, onDone }: LabProps<"intercept">) {
  return <Arena onDone={onDone} lesson={lab.lesson} timed>{g => <InterceptRun lab={lab} g={g} />}</Arena>;
}
function InterceptRun({ lab, g }: { lab: LabProps<"intercept">["lab"]; g: Game }) {
  const items = useMemo(() => shuffled(lab.items), [lab.items]);
  const LIVES = 3;
  const [i, setI] = useState(0);
  const [lives, setLives] = useState(LIVES);
  const [combo, setCombo] = useState(0);
  const [caught, setCaught] = useState(0);
  const [note, setNote] = useState<{ ok: boolean; text: string } | null>(null);
  const [fall, setFall] = useState(0);
  const item = items[i];
  const base = lab.seconds ?? 10;
  // Each item arrives a little faster than the last, down to two thirds of the start.
  const span = base * (1 - (i / Math.max(1, items.length)) * 0.34);
  const paused = !!note || g.won;

  const resolve = useCallback((blocked: boolean) => {
    const it = items[i];
    if (!it) return;
    const right = blocked === it.bad;
    if (right) { setCombo(c => c + 1); setCaught(c => c + 1); setNote({ ok: true, text: it.why }); return; }
    setCombo(0);
    setLives(l => l - 1);
    setNote({ ok: false, text: it.why });
  }, [i, items]);

  useEffect(() => {
    if (paused || !g.clock) return;
    const start = performance.now() - fall * span * 1000;
    const t = setInterval(() => {
      const p = (performance.now() - start) / (span * 1000);
      if (p >= 1) { clearInterval(t); setFall(1); resolve(false); } else setFall(p);
    }, 80);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [paused, i, g.clock]);

  const next = () => {
    if (lives <= 0) { g.lose(`Three wrong calls, the last one: ${item.text}. Read the reason, then hold the line.`); return; }
    setNote(null); setFall(0);
    if (i + 1 >= items.length) g.win(); else setI(i + 1);
  };

  if (g.won) return <Win title={`Line held: ${caught} of ${items.length} calls right`}>{lab.lesson}</Win>;
  return (
    <div>
      <Hud left={lives} max={LIVES} combo={combo} score={`${i + 1}/${items.length}`} label={`Guarding ${lab.protect}`} />
      <div className="relative h-56 overflow-hidden rounded-xl border border-white/10 bg-[#050a12]">
        <div aria-hidden className="absolute inset-0 opacity-30" style={{ backgroundImage: `repeating-linear-gradient(180deg, transparent 0 27px, ${ACCENT}22 27px 28px)` }} />
        <motion.div className="absolute inset-x-3 rounded-lg border bg-[#0b1424] p-3 shadow-lg" style={{ top: `${Math.min(fall, 1) * 56}%`, borderColor: `${ACCENT}` }}>
          <p className="font-mono text-[13px] font-semibold leading-snug text-white [overflow-wrap:anywhere]">{item.text}</p>
          {item.sub && <p className="mt-0.5 text-[11px] leading-snug text-slate-400 [overflow-wrap:anywhere]">{item.sub}</p>}
        </motion.div>
        <div className="absolute inset-x-0 bottom-0 flex items-center justify-center gap-2 border-t border-rose-400/40 bg-rose-500/10 py-1 text-[11px] font-bold uppercase tracking-widest text-rose-200">
          <Crosshair className="h-3.5 w-3.5" /> {lab.protect}
        </div>
      </div>
      {note ? (
        <div role="status" className={cn("mt-3 rounded-xl border p-3 text-sm leading-relaxed", note.ok ? "border-emerald-400/40 bg-emerald-500/10 text-emerald-100" : "border-rose-400/40 bg-rose-500/10 text-rose-100")}>
          <p className="font-bold">{note.ok ? "Good call." : lives <= 0 ? "That was your last life." : item.bad ? "It got through." : "That one was fine."}</p>
          <p className="mt-0.5">{note.text}</p>
          <button autoFocus onClick={next} className="mt-2 rounded-lg border border-white/25 px-4 py-1.5 text-sm font-bold text-white hover:bg-white/10">Next</button>
        </div>
      ) : (
        <div className="mt-3 grid grid-cols-2 gap-3">
          <button onClick={() => resolve(true)} className="inline-flex items-center justify-center gap-2 rounded-xl border-2 border-rose-400/60 bg-rose-500/10 px-4 py-3 font-bold text-rose-200 hover:bg-rose-500/20"><ShieldX className="h-5 w-5" />{lab.blockLabel ?? "Block"}</button>
          <button onClick={() => resolve(false)} className="inline-flex items-center justify-center gap-2 rounded-xl border-2 border-emerald-400/60 bg-emerald-500/10 px-4 py-3 font-bold text-emerald-200 hover:bg-emerald-500/20"><ShieldCheck className="h-5 w-5" />{lab.passLabel ?? "Let it through"}</button>
        </div>
      )}
    </div>
  );
}

// ─── Duel: answer every attacker move with the card that stops it ────────────
export function DuelLab({ lab, onDone }: LabProps<"duel">) {
  return <Arena onDone={onDone} lesson={lab.lesson}>{g => <DuelRun lab={lab} g={g} />}</Arena>;
}
function DuelRun({ lab, g }: { lab: LabProps<"duel">["lab"]; g: Game }) {
  const LIVES = 3;
  const hand = useMemo(() => shuffled(lab.cards), [lab.cards]);
  const [round, setRound] = useState(0);
  const [lives, setLives] = useState(LIVES);
  const [used, setUsed] = useState<Set<string>>(new Set());
  const [note, setNote] = useState<{ ok: boolean; text: string } | null>(null);
  const [hit, setHit] = useState(0);
  const move = lab.moves[round];
  const foeHp = lab.moves.length - round;

  function play(id: string) {
    if (!move || note?.ok) return;
    if (id === move.counter) { setUsed(u => new Set(u).add(id)); setNote({ ok: true, text: move.why }); return; }
    const after = lives - 1;
    setLives(after); setHit(h => h + 1);
    if (after <= 0) { g.lose(`${lab.attacker} won that one. ${move.why}`); return; }
    setNote({ ok: false, text: `${lab.cards.find(c => c.id === id)?.name} does not stop this. ${move.hint}` });
  }
  const advance = () => {
    setNote(null);
    if (round + 1 >= lab.moves.length) { setRound(round + 1); g.win(); } else setRound(round + 1);
  };

  if (g.won || !move) return <Win title={`${lab.attacker} is out of moves`}>{lab.lesson}</Win>;
  return (
    <div>
      <Hud left={lives} max={LIVES} label={`Round ${round + 1} of ${lab.moves.length}`} />
      <motion.div key={hit} animate={hit ? { x: [0, -8, 8, -5, 5, 0] } : undefined} className="rounded-xl border border-rose-400/40 bg-gradient-to-br from-rose-500/15 to-transparent p-4">
        <div className="mb-2 flex items-center justify-between gap-3">
          <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-rose-300">{lab.attacker} plays</p>
          <div className="flex gap-1" aria-label={`${foeHp} moves left`}>
            {lab.moves.map((m, i) => <span key={m.id} className={cn("h-2 w-6 rounded-full", i < foeHp ? "bg-rose-400" : "bg-white/10")} />)}
          </div>
        </div>
        <AnimatePresence mode="wait">
          <motion.div key={move.id} initial={{ opacity: 0, rotateX: -50 }} animate={{ opacity: 1, rotateX: 0 }} exit={{ opacity: 0 }}>
            <p className="text-lg font-extrabold text-white">{move.move}</p>
            <p className="mt-0.5 text-sm leading-relaxed text-slate-200">{move.detail}</p>
          </motion.div>
        </AnimatePresence>
      </motion.div>
      {note && (
        <div role="status" className={cn("mt-3 rounded-xl border p-3 text-sm leading-relaxed", note.ok ? "border-emerald-400/40 bg-emerald-500/10 text-emerald-100" : "border-amber-400/40 bg-amber-500/10 text-amber-100")}>
          {note.text}
          {note.ok && <button autoFocus onClick={advance} className="mt-2 block rounded-lg border border-white/25 px-4 py-1.5 text-sm font-bold text-white hover:bg-white/10">Next move</button>}
        </div>
      )}
      <p className="mt-4 text-[11px] font-bold uppercase tracking-[0.2em] text-slate-400">Your hand: a played card is gone</p>
      <div className="mt-2 grid grid-cols-2 gap-2 md:grid-cols-3">
        {hand.map(c => (
          <motion.button key={c.id} whileHover={used.has(c.id) ? undefined : { y: -4 }} disabled={used.has(c.id) || note?.ok} onClick={() => play(c.id)}
            className={cn("rounded-xl border p-3 text-left transition", used.has(c.id) ? "border-white/5 opacity-30" : "border-white/15 bg-[#0b1424] hover:shadow-lg")}
            style={used.has(c.id) ? undefined : { borderColor: `${ACCENT}` }}>
            <span className="block text-sm font-bold text-white">{c.name}</span>
            <span className="mt-1 block text-[11px] leading-snug text-slate-400">{c.effect}</span>
          </motion.button>
        ))}
      </div>
    </div>
  );
}

// ─── Deduce: strike suspects off as the clues arrive, then accuse ────────────
export function DeduceLab({ lab, onDone }: LabProps<"deduce">) {
  return <Arena onDone={onDone} lesson={lab.why}>{g => <DeduceRun lab={lab} g={g} />}</Arena>;
}
function DeduceRun({ lab, g }: { lab: LabProps<"deduce">["lab"]; g: Game }) {
  const LIVES = 2;
  const suspects = useMemo(() => shuffled(lab.suspects), [lab.suspects]);
  const [shown, setShown] = useState(1);
  const [out, setOut] = useState<Set<string>>(new Set());
  const [picked, setPicked] = useState<string | null>(null);
  const [lives, setLives] = useState(LIVES);
  const [wrong, setWrong] = useState<string | null>(null);

  const strike = (id: string) => setOut(s => { const n = new Set(s); if (n.has(id)) n.delete(id); else n.add(id); return n; });
  function accuse() {
    if (!picked) return;
    if (picked === lab.culprit) { g.win(); return; }
    const after = lives - 1;
    setLives(after);
    const name = lab.suspects.find(s => s.id === picked)?.name;
    if (after <= 0) { g.lose(`${name} walked. The clues pointed elsewhere: read them again and strike out who they clear.`); return; }
    setOut(s => new Set(s).add(picked));
    setWrong(`${name} has an alibi. One accusation left.`);
    setPicked(null);
  }

  if (g.won) return <Win title={`Solved with ${shown} of ${lab.clues.length} clues`}>{lab.why}</Win>;
  return (
    <div>
      <Hud left={lives} max={LIVES} label="Accusations left" score={`Clue ${shown}/${lab.clues.length}`} />
      <div className="grid gap-3 lg:grid-cols-[1.35fr_1fr]">
        <div className="overflow-x-auto rounded-xl border border-white/10 bg-[#050a12]">
          <table className="w-full min-w-[26rem] text-[12px]">
            <thead className="text-left text-[10px] uppercase tracking-wider text-slate-400"><tr><th className="px-2 py-1.5" /><th className="px-2 py-1.5">{lab.nameColumn}</th>{lab.columns.map(c => <th key={c} className="px-2 py-1.5">{c}</th>)}<th className="px-2 py-1.5" /></tr></thead>
            <tbody>
              {suspects.map(s => {
                const gone = out.has(s.id);
                return (
                  <tr key={s.id} className={cn("border-t border-white/5", picked === s.id && "bg-white/10", gone && "opacity-40")}>
                    <td className="px-2 py-1.5"><button aria-label={`${gone ? "Restore" : "Rule out"} ${s.name}`} onClick={() => strike(s.id)} className="rounded border border-white/15 p-0.5 text-slate-300 hover:text-white"><X className="h-3.5 w-3.5" /></button></td>
                    <td className={cn("px-2 py-1.5 font-mono font-semibold text-white", gone && "line-through")}>{s.name}</td>
                    {s.cells.map((c, i) => <td key={i} className="px-2 py-1.5 font-mono text-slate-300">{c}</td>)}
                    <td className="px-2 py-1.5"><button disabled={gone} aria-pressed={picked === s.id} onClick={() => setPicked(s.id)} className={cn("rounded-md border px-2 py-0.5 text-[11px] font-bold", picked === s.id ? "border-rose-300 text-rose-200" : "border-white/15 text-slate-300 hover:border-white/40")}>Pick</button></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        <div className="space-y-2">
          <ol className="space-y-2">
            {lab.clues.slice(0, shown).map((c, i) => (
              <motion.li key={c} initial={{ opacity: 0, x: 10 }} animate={{ opacity: 1, x: 0 }} className="rounded-lg border border-amber-300/30 bg-amber-500/10 px-3 py-2 text-sm leading-snug text-amber-50">
                <span className="mr-1 font-bold text-amber-300">{i + 1}.</span>{c}
              </motion.li>
            ))}
          </ol>
          {shown < lab.clues.length && (
            <button onClick={() => setShown(n => n + 1)} className="inline-flex items-center gap-1.5 rounded-lg border border-white/15 px-3 py-1.5 text-xs font-semibold text-slate-200 hover:border-white/40"><Search className="h-3.5 w-3.5" />Next clue (fewer is better)</button>
          )}
          {wrong && <p role="status" className="text-sm font-semibold text-rose-300">{wrong}</p>}
          <button disabled={!picked} onClick={accuse} className={cn("w-full rounded-xl px-4 py-2.5 text-sm font-bold", picked ? "text-[#04121a]" : "border border-white/10 text-slate-500")} style={picked ? { background: ACCENT } : undefined}>
            {picked ? `Accuse ${lab.suspects.find(s => s.id === picked)?.name}` : "Pick a suspect to accuse"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Tune: set the threshold, then deploy and see what it really does ────────
export function TuneLab({ lab, onDone }: LabProps<"tune">) {
  return <Arena onDone={onDone} lesson={lab.lesson}>{g => <TuneRun lab={lab} g={g} />}</Arena>;
}
export function tuneResult(lab: Extract<BriefingLab, { kind: "tune" }>, values: Record<string, number>) {
  const fires = (e: (typeof lab.events)[number]) => {
    const tests = lab.dials.map(d => (d.dir === "below" ? e.values[d.id] <= values[d.id] : e.values[d.id] >= values[d.id]));
    return lab.mode === "any" ? tests.some(Boolean) : tests.every(Boolean);
  };
  const caught = lab.events.filter(e => e.bad && fires(e)).length;
  const falseAlarms = lab.events.filter(e => !e.bad && fires(e)).length;
  return { caught, falseAlarms, fires, pass: caught >= lab.goal.catch && falseAlarms <= lab.goal.maxFalse };
}
function TuneRun({ lab, g }: { lab: LabProps<"tune">["lab"]; g: Game }) {
  const TRIES = lab.deploys ?? 3;
  const [values, setValues] = useState<Record<string, number>>(() => Object.fromEntries(lab.dials.map(d => [d.id, d.start])));
  const [left, setLeft] = useState(TRIES);
  const [report, setReport] = useState<ReturnType<typeof tuneResult> | null>(null);
  const events = useMemo(() => shuffled(lab.events), [lab.events]);

  function deploy() {
    const r = tuneResult(lab, values);
    setReport(r);
    if (r.pass) { g.win(); return; }
    const after = left - 1;
    setLeft(after);
    if (after <= 0) g.lose(`Out of deploys: ${r.caught} of ${lab.events.filter(e => e.bad).length} attacks caught, ${r.falseAlarms} false alarms. Compare what the attacks share that the normal events do not.`);
  }

  return (
    <div>
      <Hud left={left} max={TRIES} label="Deploys left" score={`Goal: ${lab.goal.catch}+ attacks, max ${lab.goal.maxFalse} false`} />
      <div className="grid gap-3 lg:grid-cols-[1fr_1.3fr]">
        <div className="space-y-3 rounded-xl border border-white/10 bg-[#050a12] p-3">
          {lab.dials.map(d => (
            <div key={d.id}>
              <label htmlFor={`dial-${d.id}`} className="flex items-baseline justify-between text-sm font-semibold text-white">
                <span>{d.label}</span>
                <span className="font-mono text-base" style={{ color: ACCENT }}>{d.dir === "below" ? "≤" : "≥"} {values[d.id]}{d.unit ? ` ${d.unit}` : ""}</span>
              </label>
              <input id={`dial-${d.id}`} type="range" min={d.min} max={d.max} step={d.step} value={values[d.id]} disabled={g.won}
                onChange={e => { setValues(v => ({ ...v, [d.id]: Number(e.target.value) })); setReport(null); }}
                className="mt-1 w-full" style={{ accentColor: ACCENT }} />
              <div className="flex justify-between font-mono text-[10px] text-slate-500"><span>{d.min}</span><span>{d.max}</span></div>
            </div>
          ))}
          <button disabled={g.won} onClick={deploy} className="w-full rounded-xl px-4 py-2.5 text-sm font-bold text-[#04121a]" style={{ background: ACCENT }}>Deploy the rule</button>
          {report && !g.won && (
            <p role="status" className="text-sm text-rose-200">Caught {report.caught}, false alarms {report.falseAlarms}. Not there yet: adjust and deploy again.</p>
          )}
        </div>
        <div className="max-h-72 overflow-auto rounded-xl border border-white/10 bg-[#050a12]">
          <table className="w-full min-w-[22rem] text-[12px]">
            <thead className="sticky top-0 bg-[#0e1524] text-left text-[10px] uppercase tracking-wider text-slate-400">
              <tr><th className="px-2 py-1.5">{lab.eventColumn}</th>{lab.dials.map(d => <th key={d.id} className="px-2 py-1.5 text-right">{d.short ?? d.label}</th>)}{report && <th className="px-2 py-1.5">Rule</th>}</tr>
            </thead>
            <tbody>
              {events.map(e => {
                const fired = report?.fires(e);
                return (
                  <tr key={e.id} className="border-t border-white/5 text-slate-200">
                    <td className="px-2 py-1.5 leading-snug">{e.label}</td>
                    {lab.dials.map(d => <td key={d.id} className="px-2 py-1.5 text-right font-mono">{e.values[d.id]}</td>)}
                    {report && <td className={cn("px-2 py-1.5 font-bold", fired === e.bad ? "text-emerald-300" : "text-rose-300")}>{fired ? (e.bad ? "caught" : "false") : (e.bad ? "missed" : "quiet")}</td>}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
      {g.won && <Win title="Rule deployed: signal up, noise down">{lab.lesson}</Win>}
    </div>
  );
}

// ─── Pathway: walk the real route node by node ───────────────────────────────
export function PathwayLab({ lab, onDone }: LabProps<"pathway">) {
  return <Arena onDone={onDone} lesson={lab.lesson}>{g => <PathwayRun lab={lab} g={g} />}</Arena>;
}
function PathwayRun({ lab, g }: { lab: LabProps<"pathway">["lab"]; g: Game }) {
  const LIVES = 3;
  const [at, setAt] = useState(0);
  const [lives, setLives] = useState(LIVES);
  const [note, setNote] = useState<{ ok: boolean; text: string } | null>(lab.notes[lab.route[0]] ? { ok: true, text: lab.notes[lab.route[0]] } : null);
  const [shake, setShake] = useState<string | null>(null);
  const here = lab.route[at];
  const walked = new Set(lab.route.slice(0, at + 1));
  const near = (a: string, b: string) => lab.edges.some(([x, y]) => (x === a && y === b) || (x === b && y === a));
  const pos = (id: string) => lab.nodes.find(n => n.id === id)!;

  function go(id: string) {
    if (g.won || walked.has(id) || !near(here, id)) return;
    if (id === lab.route[at + 1]) {
      setAt(at + 1);
      setNote(lab.notes[id] ? { ok: true, text: lab.notes[id] } : null);
      if (at + 2 >= lab.route.length) g.win();
      return;
    }
    const after = lives - 1;
    setLives(after); setShake(id);
    const why = lab.traps[id] ?? "That hop does not get you there.";
    if (after <= 0) { g.lose(why); return; }
    setNote({ ok: false, text: why });
  }

  return (
    <div>
      <Hud left={lives} max={LIVES} label={lab.goal} score={`${at}/${lab.route.length - 1} hops`} />
      <div className="overflow-x-auto rounded-xl border border-white/10 bg-[#050a12]">
      <div className="relative aspect-[16/8] min-h-[17rem] w-full min-w-[38rem]">
        <svg aria-hidden className="absolute inset-0 h-full w-full" viewBox="0 0 100 100" preserveAspectRatio="none">
          {lab.edges.map(([a, b]) => {
            const A = pos(a), B = pos(b);
            const lit = walked.has(a) && walked.has(b) && Math.abs(lab.route.indexOf(a) - lab.route.indexOf(b)) === 1;
            return <line key={`${a}-${b}`} x1={A.x} y1={A.y} x2={B.x} y2={B.y} stroke={lit ? ACCENT : "#ffffff26"} strokeWidth={lit ? 1.1 : 0.5} vectorEffect="non-scaling-stroke" style={{ strokeWidth: lit ? 3 : 1.5 }} />;
          })}
        </svg>
        {lab.nodes.map(n => {
          const isHere = n.id === here, done = walked.has(n.id) && !isHere, open = !g.won && near(here, n.id) && !walked.has(n.id);
          return (
            <motion.button key={n.id} onClick={() => go(n.id)} disabled={!open}
              animate={shake === n.id ? { x: [0, -6, 6, -4, 4, 0] } : undefined} onAnimationComplete={() => setShake(null)}
              className={cn("absolute w-[6.75rem] -translate-x-1/2 -translate-y-1/2 rounded-lg border px-1.5 py-1 text-center text-[11px] leading-tight transition",
                isHere ? "font-bold text-[#04121a]" : done ? "border-emerald-400/50 bg-emerald-500/15 text-emerald-100" : open ? "cursor-pointer border-white/50 bg-[#0e1a2c] text-white hover:bg-white/15" : "border-white/10 bg-[#0a1220] text-slate-500")}
              style={{ left: `${n.x}%`, top: `${n.y}%`, ...(isHere ? { background: ACCENT, borderColor: ACCENT } : {}) }}>
              <span className="block font-semibold [overflow-wrap:anywhere]">{n.label}</span>
              {n.sub && <span className="block text-[9px] opacity-80 [overflow-wrap:anywhere]">{n.sub}</span>}
            </motion.button>
          );
        })}
      </div>
      </div>
      {note && !g.won && <p role="status" className={cn("mt-3 rounded-xl border p-3 text-sm leading-relaxed", note.ok ? "border-white/15 bg-white/5 text-slate-100" : "border-rose-400/40 bg-rose-500/10 text-rose-100")}>{note.text}</p>}
      {g.won && <Win title="Route complete">{note?.ok ? <p>{note.text}</p> : null}<p className="mt-1">{lab.lesson}</p></Win>}
    </div>
  );
}

// ─── Defuse: read the state, cut the right wire before the clock runs out ────
export function DefuseLab({ lab, onDone }: LabProps<"defuse">) {
  return <Arena onDone={onDone} lesson={lab.lesson} timed>{g => <DefuseRun lab={lab} g={g} />}</Arena>;
}
const WIRE_COLOURS = ["#f43f5e", "#38bdf8", "#fbbf24", "#34d399", "#a78bfa"];
function DefuseRun({ lab, g }: { lab: LabProps<"defuse">["lab"]; g: Game }) {
  const STRIKES = 3;
  const [round, setRound] = useState(0);
  const [strikes, setStrikes] = useState(0);
  const [cut, setCut] = useState<Set<string>>(new Set());
  const [note, setNote] = useState<{ ok: boolean; text: string } | null>(null);
  const r = lab.rounds[round];
  const running = g.clock && !g.won && !note;
  const { left, setLeft } = useCountdown(lab.seconds, running, () => g.lose(`Time ran out on ${lab.device}. The clock is the point: decide from the evidence, quickly.`));
  const wires = useMemo(() => (r ? shuffled(r.wires) : []), [r]);

  function snip(id: string) {
    if (!r || note?.ok || cut.has(id)) return;
    if (id === r.cut) { setCut(c => new Set(c).add(id)); setNote({ ok: true, text: r.why }); return; }
    const after = strikes + 1;
    setStrikes(after); setCut(c => new Set(c).add(id)); setLeft(s => s - 10);
    if (after >= STRIKES) { g.lose(`Three wrong cuts. ${r.why}`); return; }
    setNote({ ok: false, text: `Wrong wire: minus 10 seconds. ${r.hint}` });
  }
  const advance = () => {
    setNote(null); setCut(new Set());
    if (round + 1 >= lab.rounds.length) { setRound(round + 1); g.win(); } else setRound(round + 1);
  };

  if (g.won || !r) return <Win title={`${lab.device} is safe, ${g.clock ? `${Math.max(0, left)} seconds to spare` : "no clock"}`}>{lab.lesson}</Win>;
  return (
    <div>
      <Hud left={STRIKES - strikes} max={STRIKES} label={`Module ${round + 1} of ${lab.rounds.length}`} seconds={g.clock ? left : undefined} />
      <div className="rounded-xl border-2 border-amber-400/40 bg-[#0b0d10] p-4">
        <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-amber-300">{lab.device}</p>
        <p className="mt-1 text-base font-semibold leading-relaxed text-white">{r.state}</p>
        <div className="mt-3 space-y-2">
          {wires.map((w, i) => {
            const off = cut.has(w.id);
            return (
              <button key={w.id} disabled={off || !!note} onClick={() => snip(w.id)} aria-label={`Cut: ${w.label}`} className="group flex w-full items-center gap-3 text-left disabled:cursor-not-allowed">
                <span className="relative h-2 flex-1 overflow-hidden rounded-full" style={{ background: off ? "#334155" : WIRE_COLOURS[i % WIRE_COLOURS.length] }}>
                  {off && <span className="absolute inset-y-0 left-1/2 w-3 -translate-x-1/2 bg-[#0b0d10]" />}
                </span>
                <span className={cn("w-1/2 shrink-0 text-sm font-semibold leading-snug", off ? "text-slate-500 line-through" : "text-slate-100 group-hover:text-white")}>{w.label}</span>
                <Scissors className={cn("h-4 w-4 shrink-0", off ? "text-slate-600" : "text-slate-400 group-hover:text-white")} />
              </button>
            );
          })}
        </div>
      </div>
      {note && (
        <div role="status" className={cn("mt-3 rounded-xl border p-3 text-sm leading-relaxed", note.ok ? "border-emerald-400/40 bg-emerald-500/10 text-emerald-100" : "border-amber-400/40 bg-amber-500/10 text-amber-100")}>
          {note.text}
          <button autoFocus onClick={note.ok ? advance : () => setNote(null)} className="mt-2 block rounded-lg border border-white/25 px-4 py-1.5 text-sm font-bold text-white hover:bg-white/10">{note.ok ? "Next module" : "Back to the wires"}</button>
        </div>
      )}
    </div>
  );
}

// ─── Outbreak: watch an infection spread link by link, and cut it off ────────
export function OutbreakLab({ lab, onDone }: LabProps<"outbreak">) {
  return <Arena onDone={onDone} lesson={lab.lesson}>{g => <OutbreakRun lab={lab} g={g} />}</Arena>;
}

export interface OutbreakNet { links: [number, number][]; start: number; crown: number; target: number }

/** Spreads one hop from every infected, unisolated host. Pure, so the planner can use it. */
function spreadOnce(links: [number, number][], infected: Set<number>, isolated: Set<number>) {
  const next = new Set(infected);
  for (const [a, b] of links) {
    if (isolated.has(a) || isolated.has(b)) continue;
    if (infected.has(a)) next.add(b);
    if (infected.has(b)) next.add(a);
  }
  return next;
}
function reach(links: [number, number][], from: number, blocked: Set<number>) {
  const seen = new Set([from]), stack = [from];
  while (stack.length) {
    const n = stack.pop()!;
    for (const [a, b] of links) {
      const m = a === n ? b : b === n ? a : -1;
      if (m >= 0 && !seen.has(m) && !blocked.has(m)) { seen.add(m); stack.push(m); }
    }
  }
  return seen;
}
/** Plays the sensible strategy: isolate the clean host that protects the most. */
function bestPlay(net: Pick<OutbreakNet, "links" | "start" | "crown">, total: number) {
  let infected = new Set([net.start]);
  const isolated = new Set<number>();
  for (let turn = 0; turn < total; turn++) {
    let best = -1, gain = -1;
    for (let n = 0; n < total; n++) {
      if (infected.has(n) || isolated.has(n)) continue;
      const open = (blocked: Set<number>) => {
        const out = new Set<number>();
        infected.forEach(i => { if (!isolated.has(i)) reach(net.links, i, blocked).forEach(x => out.add(x)); });
        return out;
      };
      const now = open(isolated).size, after = open(new Set(isolated).add(n));
      const g = now - after.size + (after.has(net.crown) ? 0 : total);
      if (g > gain) { gain = g; best = n; }
    }
    if (best < 0) break;
    isolated.add(best);
    infected = spreadOnce(net.links, infected, isolated);
    if (infected.has(net.crown)) return -1;
    const live = new Set<number>();
    infected.forEach(i => { if (!isolated.has(i)) reach(net.links, i, isolated).forEach(x => live.add(x)); });
    if ([...live].every(x => infected.has(x))) break;
  }
  return total - infected.size;
}
/** A fresh office network: a sparse tree of links plus two shortcuts, crown far from the start. */
export function buildNetwork(cols: number, rows: number, pick: (n: number) => number): OutbreakNet {
  const total = cols * rows;
  const neighbours = (i: number) => {
    const out: number[] = [], x = i % cols, y = Math.floor(i / cols);
    for (const [dx, dy] of [[1, 0], [-1, 0], [0, 1], [0, -1], [1, 1], [-1, -1], [1, -1], [-1, 1]]) {
      const nx = x + dx, ny = y + dy;
      if (nx >= 0 && ny >= 0 && nx < cols && ny < rows) out.push(ny * cols + nx);
    }
    return out;
  };
  for (let attempt = 0; attempt < 200; attempt++) {
    const links: [number, number][] = [], seen = new Set<number>();
    const stack = [pick(total)];
    seen.add(stack[0]);
    while (stack.length) {
      const at = stack[stack.length - 1];
      const open = neighbours(at).filter(n => !seen.has(n));
      if (!open.length || (stack.length > 3 && pick(4) === 0)) { stack.splice(pick(stack.length), 1); if (!open.length) continue; }
      const to = open[pick(open.length)];
      seen.add(to); links.push([at, to]); stack.push(to);
    }
    for (let extra = 0; extra < 2; extra++) {
      const a = pick(total), ns = neighbours(a), b = ns[pick(ns.length)];
      if (!links.some(([x, y]) => (x === a && y === b) || (x === b && y === a))) links.push([a, b]);
    }
    const start = pick(total);
    let crown = -1, far = 0;
    const dist = new Map([[start, 0]]), queue = [start];
    while (queue.length) {
      const n = queue.shift()!;
      for (const [a, b] of links) {
        const m = a === n ? b : b === n ? a : -1;
        if (m >= 0 && !dist.has(m)) { dist.set(m, dist.get(n)! + 1); queue.push(m); if (dist.get(m)! > far) { far = dist.get(m)!; crown = m; } }
      }
    }
    if (seen.size < total || far < 5) continue;
    const best = bestPlay({ links, start, crown }, total);
    if (best >= Math.ceil(total * 0.5)) return { links, start, crown, target: Math.max(best - 3, Math.ceil(total * 0.4)) };
  }
  throw new Error("no network");
}

function OutbreakRun({ lab, g }: { lab: LabProps<"outbreak">["lab"]; g: Game }) {
  const { cols, rows } = lab;
  const total = cols * rows;
  const net = useMemo(() => buildNetwork(cols, rows, n => Math.floor(Math.random() * n)), [cols, rows]);
  const [infected, setInfected] = useState<Set<number>>(() => new Set([net.start]));
  const [isolated, setIsolated] = useState<Set<number>>(new Set());
  const [turn, setTurn] = useState(1);
  const [log, setLog] = useState<string>(`${lab.hostPrefix}-${String(net.start + 1).padStart(2, "0")} is infected. It spreads by ${lab.via}. Isolate one host each turn.`);
  const name = (i: number) => i === net.crown ? lab.crown : `${lab.hostPrefix}-${String(i + 1).padStart(2, "0")}`;
  const saved = total - infected.size;

  function isolate(i: number) {
    if (g.won || isolated.has(i) || infected.has(i) || i === net.crown) return;
    const iso = new Set(isolated).add(i);
    const next = spreadOnce(net.links, infected, iso);
    const fell = [...next].filter(n => !infected.has(n));
    setIsolated(iso); setInfected(next); setTurn(t => t + 1);
    if (next.has(net.crown)) { g.lose(`It reached ${lab.crown} on turn ${turn}, over ${lab.via}. Every turn the infection moves one link: cut ahead of it, where the network narrows.`); return; }
    const live = new Set<number>();
    next.forEach(n => { if (!iso.has(n)) reach(net.links, n, iso).forEach(x => live.add(x)); });
    const stopped = [...live].every(n => next.has(n));
    if (stopped) {
      const left = total - next.size;
      if (left >= net.target) g.win();
      else g.lose(`You stopped it and ${lab.crown} is safe, but only ${left} of ${total} hosts survived. The target was ${net.target}: isolate where one cut protects the most hosts.`);
      return;
    }
    setLog(fell.length ? `Turn ${turn}: ${name(i)} isolated. It spread to ${fell.map(name).join(", ")}.` : `Turn ${turn}: ${name(i)} isolated. Nothing new fell this turn.`);
  }

  const cx = (i: number) => ((i % cols) + 0.5) * (100 / cols), cy = (i: number) => (Math.floor(i / cols) + 0.5) * (100 / rows);
  return (
    <div>
      <Hud label={`Turn ${turn}. Protect ${lab.crown}`} score={`${saved}/${total} hosts safe, target ${net.target}`} />
      <div className="relative mx-auto aspect-[6/5] w-full max-w-lg rounded-xl border border-white/10 bg-[#050a12]">
        <svg aria-hidden className="absolute inset-0 h-full w-full" viewBox="0 0 100 100" preserveAspectRatio="none">
          {net.links.map(([a, b]) => {
            const cut = isolated.has(a) || isolated.has(b), hot = !cut && (infected.has(a) || infected.has(b));
            return <line key={`${a}-${b}`} x1={cx(a)} y1={cy(a)} x2={cx(b)} y2={cy(b)} stroke={cut ? "#ffffff14" : hot ? "#f43f5e" : "#ffffff40"} vectorEffect="non-scaling-stroke" style={{ strokeWidth: hot ? 2.5 : 1.5 }} />;
          })}
        </svg>
        {Array.from({ length: total }, (_, i) => {
          const bad = infected.has(i), iso = isolated.has(i), crown = i === net.crown;
          const label = crown ? lab.crown : String(i + 1).padStart(2, "0");
          return (
            <button key={i} onClick={() => isolate(i)} disabled={g.won || iso || crown || infected.has(i)}
              aria-label={`${name(i)}${crown ? ", protect this" : ""}${bad ? ", infected" : ""}${iso ? ", isolated" : ""}`}
              className={cn("absolute grid -translate-x-1/2 -translate-y-1/2 place-items-center rounded-md border font-mono text-[10px] font-bold transition",
                crown ? "h-11 w-16 border-emerald-300 bg-emerald-500/25 text-emerald-100" : "h-8 w-8",
                !crown && (iso ? "border-amber-300 bg-amber-500/25 text-amber-100" : bad ? "border-rose-400 bg-rose-500/40 text-white hover:bg-rose-500/60" : "border-white/25 bg-[#0e1a2c] text-slate-300 hover:border-white/60"))}
              style={{ left: `${cx(i)}%`, top: `${cy(i)}%` }}>
              {iso ? <Lock className="h-3.5 w-3.5" /> : label}
            </button>
          );
        })}
      </div>
      <p role="status" className="mt-3 rounded-xl border border-white/10 bg-black/30 px-3 py-2 text-sm leading-relaxed text-slate-100">{log}</p>
      {g.won && <Win title={`Contained: ${saved} of ${total} hosts safe, ${lab.crown} untouched`}>{lab.lesson}</Win>}
    </div>
  );
}

// ─── Codebreak: guess the term, letter feedback after every try ──────────────
export function CodebreakLab({ lab, onDone }: LabProps<"codebreak">) {
  return <Arena onDone={onDone} lesson={lab.lesson}>{g => <CodebreakRun lab={lab} g={g} />}</Arena>;
}
export function grade(guess: string, answer: string): ("hit" | "near" | "miss")[] {
  const out: ("hit" | "near" | "miss")[] = Array.from({ length: answer.length }, () => "miss");
  const rest: Record<string, number> = {};
  for (let i = 0; i < answer.length; i++) {
    if (guess[i] === answer[i]) out[i] = "hit";
    else rest[answer[i]] = (rest[answer[i]] ?? 0) + 1;
  }
  for (let i = 0; i < answer.length; i++) {
    if (out[i] !== "hit" && rest[guess[i]]) { out[i] = "near"; rest[guess[i]]--; }
  }
  return out;
}
function CodebreakRun({ lab, g }: { lab: LabProps<"codebreak">["lab"]; g: Game }) {
  const TRIES = lab.tries ?? 6;
  const [round, setRound] = useState(0);
  const [guesses, setGuesses] = useState<string[]>([]);
  const [typed, setTyped] = useState("");
  const [solved, setSolved] = useState(false);
  const r = lab.rounds[round];
  const answer = (r?.answer ?? "").toUpperCase();

  function submit(e: React.FormEvent) {
    e.preventDefault();
    const guess = typed.toUpperCase();
    if (solved || guess.length !== answer.length) return;
    const all = [...guesses, guess];
    setGuesses(all); setTyped("");
    if (guess === answer) { setSolved(true); return; }
    if (all.length >= TRIES) g.lose(`The code was ${answer}. ${r.why}`);
  }
  const advance = () => {
    setGuesses([]); setSolved(false); setTyped("");
    if (round + 1 >= lab.rounds.length) { setRound(round + 1); g.win(); } else setRound(round + 1);
  };

  if (g.won || !r) return <Win title="Every code cracked">{lab.lesson}</Win>;
  const rows = [...guesses, ...Array.from({ length: TRIES - guesses.length }, () => "")];
  return (
    <div>
      <Hud left={TRIES - guesses.length} max={TRIES} label={`Code ${round + 1} of ${lab.rounds.length}`} />
      <p className="rounded-xl border border-white/10 bg-black/30 px-4 py-3 text-sm leading-relaxed text-slate-100"><Lightbulb className="mr-1.5 inline h-4 w-4 text-amber-300" />{r.clue}</p>
      <div className="mx-auto mt-3 w-fit space-y-1.5">
        {rows.map((word, y) => {
          const marks = word ? grade(word, answer) : [];
          return (
            <div key={y} className="flex gap-1.5">
              {Array.from({ length: answer.length }, (_, x) => (
                <motion.span key={x} initial={word ? { rotateX: 90 } : false} animate={{ rotateX: 0 }} transition={{ delay: x * 0.06 }}
                  className={cn("grid h-9 w-9 place-items-center rounded-md border font-mono text-sm font-bold sm:h-10 sm:w-10 sm:text-base",
                    marks[x] === "hit" ? "border-emerald-400 bg-emerald-500/40 text-white" : marks[x] === "near" ? "border-amber-400 bg-amber-500/30 text-white" : word ? "border-white/10 bg-white/5 text-slate-400" : "border-white/10 bg-black/20 text-transparent")}>
                  {word[x] ?? "·"}
                </motion.span>
              ))}
            </div>
          );
        })}
      </div>
      <p className="mt-2 text-center text-[11px] text-slate-400"><span className="font-bold text-emerald-300">Green</span>: right place. <span className="font-bold text-amber-300">Amber</span>: in the code, wrong place.</p>
      {solved ? (
        <div role="status" className="mt-3 rounded-xl border border-emerald-400/40 bg-emerald-500/10 p-3 text-sm leading-relaxed text-emerald-100">
          <p className="font-bold"><Check className="mr-1 inline h-4 w-4" />{answer}</p>
          {r.why}
          <button autoFocus onClick={advance} className="mt-2 block rounded-lg border border-white/25 px-4 py-1.5 text-sm font-bold text-white hover:bg-white/10">Next</button>
        </div>
      ) : (
        <form onSubmit={submit} className="mx-auto mt-3 flex max-w-xs gap-2">
          <input autoFocus value={typed} maxLength={answer.length} onChange={e => setTyped(e.target.value.replace(/[^a-zA-Z0-9]/g, ""))}
            aria-label={`Guess, ${answer.length} characters`} placeholder={`${answer.length} characters`}
            className="min-w-0 flex-1 rounded-lg border border-white/15 bg-black/30 px-3 py-2 text-center font-mono text-sm uppercase tracking-widest text-white outline-none focus:border-white/40" />
          <button type="submit" disabled={typed.length !== answer.length} className={cn("rounded-lg px-4 text-sm font-bold", typed.length === answer.length ? "text-[#04121a]" : "border border-white/10 text-slate-500")} style={typed.length === answer.length ? { background: ACCENT } : undefined}>Try</button>
        </form>
      )}
    </div>
  );
}

// ─── Rush: as many right calls as you can before the clock stops ─────────────
export function RushLab({ lab, onDone }: LabProps<"rush">) {
  return <Arena onDone={onDone} lesson={lab.lesson} timed>{g => <RushRun lab={lab} g={g} />}</Arena>;
}
function RushRun({ lab, g }: { lab: LabProps<"rush">["lab"]; g: Game }) {
  const cards = useMemo(() => shuffled(lab.cards), [lab.cards]);
  const seconds = lab.seconds ?? 60;
  const [i, setI] = useState(0);
  const [right, setRight] = useState(0);
  const [combo, setCombo] = useState(0);
  const [best, setBest] = useState(0);
  const [points, setPoints] = useState(0);
  const [misses, setMisses] = useState<typeof lab.cards>([]);
  const [flash, setFlash] = useState<"ok" | "bad" | null>(null);
  const [done, setDone] = useState(false);
  const [wrong, setWrong] = useState<(typeof lab.cards)[number] | null>(null);
  const rightRef = useRef(0);
  const finish = () => {
    setDone(true);
    if (rightRef.current >= lab.target) g.win();
    else g.lose(`${rightRef.current} right, you needed ${lab.target}. The clock rewards certainty: know these cold and the speed follows.`);
  };
  const { left } = useCountdown(seconds, g.clock && !done && !g.won && !wrong, finish);
  const card = cards[i];

  function call(answer: boolean) {
    if (done || !card || wrong) return;
    const ok = answer === card.answer;
    if (ok) {
      rightRef.current += 1;
      const c = combo + 1;
      setRight(r => r + 1); setCombo(c); setBest(b => Math.max(b, c)); setPoints(p => p + 10 * Math.min(4, Math.ceil(c / 3)));
    } else { setCombo(0); setMisses(m => [...m, card]); }
    setFlash(ok ? "ok" : "bad");
    setTimeout(() => setFlash(null), 240);
    if (!ok) { setWrong(card); return; }
    step();
  }
  function step() { if (i + 1 >= cards.length) finish(); else setI(i + 1); }

  if (g.won) {
    return (
      <Win title={`${right} of ${cards.length} right, ${points} points, best streak ${best}`}>
        {misses.length > 0 && <ul className="mt-1 space-y-1">{misses.map(m => <li key={m.id}><X className="mr-1 inline h-3.5 w-3.5 text-rose-300" />{m.text}: {m.why}</li>)}</ul>}
        <p className="mt-1">{lab.lesson}</p>
      </Win>
    );
  }
  if (!card) return null;
  return (
    <div>
      <Hud combo={combo} score={`${points} pts`} label={`Target: ${lab.target} right`} seconds={g.clock ? left : undefined} />
      <motion.div key={card.id} initial={{ opacity: 0, y: 14, scale: 0.97 }} animate={{ opacity: 1, y: 0, scale: 1 }} transition={{ duration: 0.14 }}
        className={cn("grid min-h-[9rem] place-items-center rounded-2xl border-2 bg-[#0b1424] p-5 text-center text-lg font-bold leading-snug text-white transition-colors", flash === "ok" ? "border-emerald-400" : flash === "bad" ? "border-rose-400" : "border-white/15")}>
        {card.text}
      </motion.div>
      {wrong ? (
        <div role="status" className="mt-3 rounded-xl border border-amber-400/40 bg-amber-500/10 p-3 text-sm leading-relaxed text-amber-100">
          <p className="font-bold">The clock is stopped. Here is why:</p>
          <p className="mt-0.5">{wrong.why}</p>
          <button autoFocus onClick={() => { setWrong(null); step(); }} className="mt-2 rounded-lg border border-white/25 px-4 py-1.5 text-sm font-bold text-white hover:bg-white/10">Next card</button>
        </div>
      ) : (
        <div className="mt-3 grid grid-cols-2 gap-3">
          <button onClick={() => call(true)} className="rounded-xl border-2 px-4 py-3 font-bold text-white hover:bg-white/10" style={{ borderColor: ACCENT }}>{lab.trueLabel ?? "True"}</button>
          <button onClick={() => call(false)} className="rounded-xl border-2 border-white/25 px-4 py-3 font-bold text-white hover:bg-white/10">{lab.falseLabel ?? "False"}</button>
        </div>
      )}
      <p className="mt-2 text-center font-mono text-[11px] text-slate-500">{i + 1}/{cards.length}</p>
    </div>
  );
}

// ─── Spot the change: known good beside suspect, find what was tampered ──────
export function SpotDiffLab({ lab, onDone }: LabProps<"spotdiff">) {
  return <Arena onDone={onDone} lesson={lab.lesson}>{g => <SpotDiffRun lab={lab} g={g} />}</Arena>;
}
function SpotDiffRun({ lab, g }: { lab: LabProps<"spotdiff">["lab"]; g: Game }) {
  const LIVES = 3;
  const [found, setFound] = useState<Set<number>>(new Set());
  const [wrong, setWrong] = useState<Set<number>>(new Set());
  const [lives, setLives] = useState(LIVES);
  const [last, setLast] = useState<{ ok: boolean; text: string } | null>(null);

  function tap(line: number) {
    if (g.won || found.has(line) || wrong.has(line)) return;
    const d = lab.diffs.find(x => x.line === line);
    if (d) {
      const next = new Set(found).add(line);
      setFound(next); setLast({ ok: true, text: d.why });
      if (next.size >= lab.diffs.length) g.win();
      return;
    }
    const after = lives - 1;
    setLives(after); setWrong(w => new Set(w).add(line));
    const decoy = lab.decoys?.find(x => x.line === line);
    if (after <= 0) { g.lose(decoy?.why ?? "Three false accusations. Compare each line with the known-good copy before you flag it."); return; }
    setLast({ ok: false, text: decoy?.why ?? lab.sameLine ?? "That line matches the known-good copy." });
  }

  return (
    <div>
      <Hud left={lives} max={LIVES} label={lab.hud ?? "Tap the lines that were tampered with"} score={`${found.size}/${lab.diffs.length} found`} />
      <div className="grid gap-3 md:grid-cols-2">
        <div className="min-w-0 overflow-hidden rounded-xl border border-emerald-400/30 bg-[#050a12]">
          <p className="border-b border-white/10 bg-emerald-500/10 px-3 py-1.5 text-[11px] font-bold text-emerald-200">{lab.goodTitle}</p>
          <ol className="font-mono text-[12px] text-slate-400">
            {lab.good.map((l, i) => <li key={i} className="border-b border-white/5 px-3 py-1.5 leading-snug [overflow-wrap:anywhere]">{l || " "}</li>)}
          </ol>
        </div>
        <div className="min-w-0 overflow-hidden rounded-xl border border-rose-400/30 bg-[#050a12]">
          <p className="border-b border-white/10 bg-rose-500/10 px-3 py-1.5 text-[11px] font-bold text-rose-200">{lab.suspectTitle}</p>
          <ol className="font-mono text-[12px] text-slate-200">
            {lab.suspect.map((l, i) => (
              <li key={i}>
                <button onClick={() => tap(i)} className={cn("block w-full border-b border-white/5 px-3 py-1.5 text-left leading-snug transition [overflow-wrap:anywhere]", found.has(i) ? "bg-rose-500/25 text-white" : wrong.has(i) ? "text-slate-500 line-through" : "hover:bg-white/10")}>
                  {l || " "}
                </button>
              </li>
            ))}
          </ol>
        </div>
      </div>
      {last && !g.won && <p role="status" className={cn("mt-3 rounded-xl border p-3 text-sm leading-relaxed", last.ok ? "border-emerald-400/40 bg-emerald-500/10 text-emerald-100" : "border-amber-400/40 bg-amber-500/10 text-amber-100")}>{last.text}</p>}
      {g.won && <Win title={lab.winTitle ?? "Every change found"}>{last?.text && <p>{last.text}</p>}<p className="mt-1">{lab.lesson}</p></Win>}
    </div>
  );
}
