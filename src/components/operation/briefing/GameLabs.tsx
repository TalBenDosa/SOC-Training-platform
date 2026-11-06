"use client";
import React, { useEffect, useMemo, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { Check, X, Flame, Snowflake, Search, Flag, ExternalLink, UserRound } from "lucide-react";
import { cn } from "@/lib/utils";
import { newShuffleSeed, shuffleWithSeed } from "@/lib/rooms/shuffle";
import type { BriefingLab } from "@/lib/rooms/experience";

// Game-style labs: a timed conveyor, a suspect line-up and a hotspot artifact.
// Like the other labs they teach and award nothing, and report once when done.

interface LabProps<K extends BriefingLab["kind"]> {
  lab: Extract<BriefingLab, { kind: K }>;
  onDone: () => void;
}

function useDoneOnce(done: boolean, onDone: () => void) {
  const [fired, setFired] = useState(false);
  useEffect(() => { if (done && !fired) { setFired(true); onDone(); } }, [done, fired, onDone]);
}

// ─── Reactor: route conveyor items into the right reactor ─────────────────────
const BELT_SECONDS = 9;

export function ReactorLab({ lab, onDone }: LabProps<"reactor">) {
  const queue = useMemo(() => shuffleWithSeed(lab.items, newShuffleSeed()), [lab.items]);
  const [idx, setIdx] = useState(0);
  const [heat, setHeat] = useState<Record<string, number>>({});
  const [flash, setFlash] = useState<{ reactor: string; ok: boolean } | null>(null);
  const [note, setNote] = useState<{ ok: boolean; text: string } | null>(null);
  const [round, setRound] = useState(0); // restarts the belt animation
  const [paused, setPaused] = useState(false);
  const item = queue[idx];
  const done = idx >= queue.length;
  useDoneOnce(done, onDone);

  // The belt runs out: the item comes round again (no penalty, just pressure).
  useEffect(() => {
    if (done || paused) return;
    const t = setTimeout(() => { setNote({ ok: false, text: "It reached the end of the belt. Here it comes again." }); setRound(r => r + 1); }, BELT_SECONDS * 1000);
    return () => clearTimeout(t);
  }, [idx, round, done, paused]);

  function route(reactorId: string) {
    if (!item || paused) return;
    const ok = item.reactor === reactorId;
    setFlash({ reactor: reactorId, ok });
    setHeat(h => ({ ...h, [reactorId]: Math.max(0, Math.min(3, (h[reactorId] ?? 0) + (ok ? -1 : 1))) }));
    if (ok) {
      setNote({ ok: true, text: item.why });
      setPaused(true);
      setTimeout(() => { setPaused(false); setIdx(i => i + 1); setRound(r => r + 1); setFlash(null); }, 1600);
    } else {
      setNote({ ok: false, text: "Wrong reactor: it is heating up. Read the case again: which one does it really belong to?" });
      setTimeout(() => setFlash(null), 500);
    }
  }

  return (
    <div className="space-y-4">
      {/* Conveyor */}
      <div className="relative h-24 overflow-hidden rounded-xl border border-white/10 bg-[repeating-linear-gradient(90deg,#0b1424_0_22px,#0e1a2e_22px_44px)]">
        <div className="absolute inset-x-0 top-1/2 h-px bg-white/5" />
        <AnimatePresence>
          {item && (
            <motion.div
              key={`${item.id}:${round}`}
              initial={{ left: "-40%" }}
              animate={{ left: paused ? undefined : "100%" }}
              exit={{ opacity: 0, y: 30, transition: { duration: 0.3 } }}
              transition={{ duration: BELT_SECONDS, ease: "linear" }}
              className="absolute top-1/2 w-[min(28rem,70%)] -translate-y-1/2 rounded-lg border border-amber-300/50 bg-[#151f33] px-3 py-2 text-sm font-semibold text-amber-50 shadow-[0_0_22px_-6px_rgba(251,191,36,0.6)]"
            >
              <span className="mr-2 font-mono text-[10px] uppercase tracking-widest text-amber-300">Case {Math.min(idx + 1, queue.length)}/{queue.length}</span>
              {item.text}
            </motion.div>
          )}
        </AnimatePresence>
        {done && <p className="grid h-full place-items-center text-sm font-bold text-emerald-300">Belt clear. All three reactors stable.</p>}
      </div>

      {/* Reactors */}
      <div className="grid gap-3 sm:grid-cols-3">
        {lab.reactors.map(r => {
          const h = heat[r.id] ?? 0;
          const f = flash?.reactor === r.id ? flash : null;
          return (
            <motion.button
              key={r.id}
              onClick={() => route(r.id)}
              disabled={done || paused}
              animate={f && !f.ok ? { x: [0, -6, 6, -3, 3, 0] } : f?.ok ? { scale: [1, 1.04, 1] } : undefined}
              className={cn(
                "relative overflow-hidden rounded-2xl border-2 p-4 text-left transition enabled:hover:brightness-125 disabled:cursor-default",
                f?.ok ? "border-emerald-400 bg-emerald-500/15" : f ? "border-rose-500 bg-rose-500/15" : "border-teal-400/40 bg-[#0a1628]",
              )}
            >
              <div className="flex items-center justify-between">
                <span className="grid h-11 w-11 place-items-center rounded-full border-2 border-teal-300/70 font-black text-teal-200">{r.label[0]}</span>
                <span className="flex items-center gap-1 text-xs font-semibold" aria-label={`heat ${h} of 3`}>
                  {h > 0 ? <Flame className="h-4 w-4 text-rose-400" /> : <Snowflake className="h-4 w-4 text-sky-300" />}
                  {[0, 1, 2].map(k => <span key={k} className={cn("h-2.5 w-1.5 rounded-sm", k < h ? "bg-rose-400" : "bg-white/10")} />)}
                </span>
              </div>
              <p className="mt-3 font-bold text-white">{r.label}</p>
              <p className="text-xs text-slate-400">{r.sub}</p>
              <span className="pointer-events-none absolute inset-x-0 bottom-0 h-1 bg-gradient-to-r from-teal-400 via-sky-400 to-teal-400 opacity-60" />
            </motion.button>
          );
        })}
      </div>

      <p role="status" className={cn("min-h-[2.5rem] rounded-lg px-3 py-2 text-sm leading-relaxed", !note ? "text-slate-500" : note.ok ? "bg-emerald-500/10 text-emerald-300" : "bg-rose-500/10 text-rose-300")}>
        {note ? <>{note.ok ? <Check className="mr-1 inline h-4 w-4" /> : <X className="mr-1 inline h-4 w-4" />}{note.text}</> : "Click the reactor this card belongs in."}
      </p>
    </div>
  );
}

// ─── Line-up: pick the suspect that fits the evidence ─────────────────────────
export function LineupLab({ lab, onDone }: LabProps<"lineup">) {
  const [ri, setRi] = useState(0);
  const [wrong, setWrong] = useState<string | null>(null);
  const [solved, setSolved] = useState<Record<string, string>>({}); // round id → suspect id
  const [focus, setFocus] = useState<string | null>(null);
  const round = lab.rounds[ri];
  const done = Object.keys(solved).length === lab.rounds.length;
  useDoneOnce(done, onDone);
  const revealed = new Set(Object.values(solved));
  const just = round && solved[round.id];

  function accuse(id: string) {
    if (!round || just) return;
    if (id === round.suspect) { setSolved(s => ({ ...s, [round.id]: id })); setWrong(null); }
    else setWrong(id);
  }
  const shown = focus ? lab.suspects.find(s => s.id === focus) : null;

  return (
    <div className="space-y-4">
      {/* The glass */}
      <div className="relative rounded-2xl border border-white/10 bg-[linear-gradient(180deg,#0b1220,#060a12)] p-3">
        <div aria-hidden className="pointer-events-none absolute inset-x-3 top-3 grid h-[150px] grid-rows-5 opacity-30">
          {[0, 1, 2, 3, 4].map(k => <span key={k} className="border-t border-dashed border-slate-500" />)}
        </div>
        <div className="relative grid grid-cols-5 gap-2">
          {lab.suspects.map((s, i) => {
            const isRev = revealed.has(s.id);
            const isWrong = wrong === s.id;
            return (
              <motion.button
                key={s.id}
                onClick={() => accuse(s.id)}
                onMouseEnter={() => setFocus(s.id)}
                onFocus={() => setFocus(s.id)}
                animate={isWrong ? { x: [0, -6, 6, -3, 3, 0] } : undefined}
                className={cn(
                  "group flex flex-col items-center rounded-xl border px-1 pb-2 pt-3 transition",
                  just === s.id ? "border-emerald-400 bg-emerald-500/10" : isWrong ? "border-rose-500 bg-rose-500/10" : "border-white/10 hover:border-teal-300/60",
                )}
                aria-label={`Suspect ${i + 1}: ${s.name}`}
              >
                <span className={cn("grid h-[86px] w-[60px] place-items-end justify-center rounded-t-full transition", isRev ? "bg-teal-500/25" : "bg-black/70")}>
                  <UserRound className={cn("h-16 w-16", isRev ? "text-teal-200" : "text-slate-800")} />
                </span>
                <span className="mt-1 font-mono text-[10px] text-slate-500">#{i + 1}</span>
                <span className="text-center text-[11px] font-bold leading-tight text-slate-100">{s.name}</span>
              </motion.button>
            );
          })}
        </div>
      </div>

      <div className="grid gap-3 md:grid-cols-[1.3fr_1fr]">
        {/* Evidence */}
        <div className="rounded-xl border border-amber-300/30 bg-amber-500/5 p-4">
          <p className="text-[11px] font-semibold uppercase tracking-[0.25em] text-amber-300">
            {done ? "Case board complete" : `Evidence · round ${ri + 1} of ${lab.rounds.length}`}
          </p>
          {round && !done && (
            <ul className="mt-2 space-y-1.5">
              {round.evidence.map(e => <li key={e} className="flex gap-2 text-sm text-slate-100"><Search className="mt-0.5 h-4 w-4 shrink-0 text-amber-300" />{e}</li>)}
            </ul>
          )}
          <p role="status" className="mt-3 min-h-[1.25rem] text-sm leading-relaxed">
            {just ? <span className="text-emerald-300"><Check className="mr-1 inline h-4 w-4" />{round.why}</span>
              : wrong ? <span className="text-rose-300">The dossier does not fit. Compare motive and target again.</span>
                : done ? <span className="text-emerald-300">Five rounds, five attackers. Motive tells them apart better than skill.</span>
                  : <span className="text-slate-400">Hover a suspect to read the dossier, click to accuse.</span>}
          </p>
          {just && ri < lab.rounds.length - 1 && (
            <button onClick={() => { setRi(r => r + 1); setWrong(null); }} className="mt-2 rounded-lg border border-teal-300/60 px-3 py-1.5 text-sm font-semibold text-teal-100 hover:bg-teal-500/10">
              Next round
            </button>
          )}
          {just && ri === lab.rounds.length - 1 && !done && null}
        </div>
        {/* Dossier */}
        <div className="rounded-xl border border-white/10 bg-bg-panel/70 p-4">
          <p className="text-[11px] font-semibold uppercase tracking-[0.25em] text-slate-400">Dossier</p>
          {shown ? (
            <dl className="mt-2 space-y-1.5 text-sm">
              <p className="font-bold text-white">{shown.name}</p>
              <div><dt className="inline text-slate-400">Motive: </dt><dd className="inline text-slate-100">{shown.motive}</dd></div>
              <div><dt className="inline text-slate-400">Skill: </dt><dd className="inline text-slate-100">{shown.skill}</dd></div>
              <div><dt className="inline text-slate-400">Typical target: </dt><dd className="inline text-slate-100">{shown.target}</dd></div>
            </dl>
          ) : <p className="mt-2 text-sm text-slate-500">No suspect selected.</p>}
        </div>
      </div>
    </div>
  );
}

// ─── Hotspot: find every red flag on a realistic artifact ─────────────────────
export function HotspotLab({ lab, onDone }: LabProps<"hotspot">) {
  const [hit, setHit] = useState<Set<string>>(new Set());
  const [last, setLast] = useState<string | null>(null);
  const [hover, setHover] = useState<string | null>(null);
  const flags = lab.parts.filter(p => p.flag);
  const found = flags.filter(p => hit.has(p.id)).length;
  useDoneOnce(found === flags.length, onDone);
  const lastPart = lab.parts.find(p => p.id === last);
  const tap = (id: string) => { setHit(h => new Set(h).add(id)); setLast(id); };

  const piece = (p: (typeof lab.parts)[number]) => {
    const marked = hit.has(p.id);
    const tone = marked ? (p.flag ? "ring-2 ring-rose-500 bg-rose-500/10" : "ring-1 ring-slate-400/50 bg-white/5") : "hover:bg-sky-500/10";
    const base = cn("relative w-full rounded-md px-2 py-1 text-left transition", tone);
    const pin = marked && p.flag && <Flag className="absolute -right-1 -top-2 h-4 w-4 fill-rose-500 text-rose-500" />;
    switch (p.style) {
      case "meta":    return <button key={p.id} onClick={() => tap(p.id)} className={cn(base, "font-mono text-[12px] text-slate-600")}>{p.text}{pin}</button>;
      case "subject": return <button key={p.id} onClick={() => tap(p.id)} className={cn(base, "text-lg font-bold text-slate-900")}>{p.text}{pin}</button>;
      case "button":  return (
        <div key={p.id} className="py-2">
          <button onClick={() => tap(p.id)} onMouseEnter={() => setHover(p.href ?? null)} onMouseLeave={() => setHover(null)} onFocus={() => setHover(p.href ?? null)} onBlur={() => setHover(null)} className={cn("relative inline-flex items-center gap-2 rounded-md bg-[#1d4ed8] px-5 py-2 text-sm font-bold text-white transition", marked && p.flag && "ring-4 ring-rose-500")}>
            {p.text}<ExternalLink className="h-3.5 w-3.5" />{pin}
          </button>
        </div>
      );
      default:        return <button key={p.id} onClick={() => tap(p.id)} className={cn(base, "text-sm text-slate-800")}>{p.text}{pin}</button>;
    }
  };

  return (
    <div className="grid gap-4 lg:grid-cols-[1.4fr_1fr]">
      <div className="overflow-hidden rounded-xl border border-white/10 bg-white shadow-2xl">
        <div className="flex items-center gap-2 bg-[#e2e8f0] px-3 py-2 text-[11px] font-semibold text-slate-600">
          <span className="h-2.5 w-2.5 rounded-full bg-rose-400" /><span className="h-2.5 w-2.5 rounded-full bg-amber-400" /><span className="h-2.5 w-2.5 rounded-full bg-emerald-400" />
          <span className="ml-2">{lab.artifact}</span>
        </div>
        <div className="space-y-0.5 p-4">{lab.parts.map(piece)}</div>
        {/* the mail client's status bar: where a hovered link really goes */}
        <div className="h-6 border-t border-slate-200 bg-[#f1f5f9] px-3 font-mono text-[11px] leading-6 text-slate-600">{hover ?? ""}</div>
      </div>
      <div className="space-y-3">
        <div className="flex items-center gap-3 rounded-xl border border-rose-400/30 bg-rose-500/5 p-3">
          <Flag className="h-5 w-5 text-rose-400" />
          <p className="text-sm font-bold text-white">Red flags found: {found} / {flags.length}</p>
        </div>
        <div aria-live="polite" className="min-h-[8rem] rounded-xl border border-white/10 bg-bg-panel/70 p-4">
          {lastPart ? (
            <>
              <p className={cn("text-[11px] font-bold uppercase tracking-[0.2em]", lastPart.flag ? "text-rose-300" : "text-slate-300")}>{lastPart.flag ? "Red flag" : "Looks normal"}</p>
              <p className="mt-2 text-sm leading-relaxed text-slate-200">{lastPart.note}</p>
            </>
          ) : <p className="text-sm text-slate-400">Click any part you would question.</p>}
          {found === flags.length && <p className="mt-3 text-sm font-semibold text-emerald-300">Every flag found.{lab.finish ? ` ${lab.finish}` : ""}</p>}
        </div>
      </div>
    </div>
  );
}

// ─── Deck sort: one card at a time, thrown into the right bin ─────────────────
const BIN_TINTS = ["#2dd4bf", "#60a5fa", "#f472b6", "#fbbf24"];

export function DeckSortLab({ lab, onDone }: LabProps<"sort">) {
  const deck = useMemo(() => shuffleWithSeed(lab.items, newShuffleSeed()), [lab.items]);
  const [idx, setIdx] = useState(0);
  const [wrong, setWrong] = useState<string | null>(null);
  const [landed, setLanded] = useState<string | null>(null); // bucket the current card flew into
  const [streak, setStreak] = useState(0);
  const [best, setBest] = useState(0);
  const [peek, setPeek] = useState(false);
  const card = deck[idx];
  const done = idx >= deck.length;
  useDoneOnce(done, onDone);
  const binIndex = (id: string) => Math.max(0, lab.buckets.findIndex(b => b.id === id));

  function throwTo(bucket: string) {
    if (!card || landed) return;
    if (bucket === card.bucket) {
      setLanded(bucket); setWrong(null);
      setStreak(s => { const n = s + 1; setBest(b => Math.max(b, n)); return n; });
    } else {
      setWrong(bucket); setStreak(0);
    }
  }
  function next() { setLanded(null); setWrong(null); setPeek(false); setIdx(i => i + 1); }

  if (done) {
    return (
      <div className="space-y-3">
        <p className="text-sm font-bold text-emerald-300"><Check className="mr-1 inline h-4 w-4" />Deck cleared. Best streak: {best}.</p>
        <div className="grid gap-3 sm:grid-cols-3">
          {lab.buckets.map((b, i) => (
            <div key={b.id} className="rounded-xl border p-3" style={{ borderColor: `${BIN_TINTS[i % 4]}66` }}>
              <p className="text-xs font-bold uppercase tracking-widest" style={{ color: BIN_TINTS[i % 4] }}>{b.label}</p>
              <ul className="mt-2 space-y-1">
                {lab.items.filter(it => it.bucket === b.id).map(it => <li key={it.id} className="text-sm text-slate-200">{it.text}</li>)}
              </ul>
            </div>
          ))}
        </div>
      </div>
    );
  }

  const tint = landed ? BIN_TINTS[binIndex(landed) % 4] : undefined;
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between text-xs text-slate-400">
        <span className="font-mono">Card {idx + 1} / {deck.length}</span>
        <span className={cn("font-bold", streak >= 2 ? "text-amber-300" : "text-slate-500")}>Streak ×{streak}</span>
      </div>
      {/* The card on top of the deck */}
      <div className="relative mx-auto h-44 max-w-md sm:h-40">
        {deck.slice(idx + 1, idx + 3).map((c, k) => (
          <div key={c.id} aria-hidden className="absolute inset-0 rounded-2xl border border-white/10 bg-[#0d1626]"
            style={{ transform: `translateY(${(k + 1) * 8}px) scale(${1 - (k + 1) * 0.04})`, zIndex: 1 - k }} />
        ))}
        <AnimatePresence mode="popLayout">
          <motion.div
            key={card.id}
            initial={{ y: -30, opacity: 0, rotate: -3 }}
            animate={landed
              ? { y: 70, opacity: 0.0, scale: 0.6, x: (binIndex(landed) - (lab.buckets.length - 1) / 2) * 140, transition: { duration: 0.5, delay: 0.9 } }
              : wrong ? { x: [0, -12, 12, -6, 6, 0], rotate: 0, y: 0, opacity: 1 } : { y: 0, opacity: 1, rotate: 0 }}
            className="absolute inset-0 z-10 flex flex-col justify-center rounded-2xl border-2 bg-gradient-to-br from-[#14213a] to-[#0b1324] p-5 text-center shadow-2xl"
            style={{ borderColor: tint ?? (wrong ? "#f43f5e" : "rgba(148,163,184,0.35)") }}
          >
            <p className="text-lg font-bold leading-snug text-white sm:text-xl">{card.text}</p>
            {card.hidden && (
              peek ? <p className="mt-2 break-all font-mono text-xs text-amber-300">↳ {card.hidden}</p>
                : <button onClick={() => setPeek(true)} onMouseEnter={() => setPeek(true)} className="mx-auto mt-2 inline-flex items-center gap-1 text-xs text-sky-300 hover:underline"><Search className="h-3.5 w-3.5" /> peek underneath</button>
            )}
          </motion.div>
        </AnimatePresence>
      </div>
      {/* Bins */}
      <div className={cn("grid gap-2.5", lab.buckets.length === 2 ? "grid-cols-2" : "grid-cols-3")}>
        {lab.buckets.map((b, i) => {
          const c = BIN_TINTS[i % 4];
          const isWrong = wrong === b.id, isHit = landed === b.id;
          return (
            <motion.button
              key={b.id}
              onClick={() => throwTo(b.id)}
              disabled={!!landed}
              animate={isHit ? { scale: [1, 1.08, 1] } : undefined}
              transition={{ delay: 1.1 }}
              className={cn("flex min-h-[4.5rem] flex-col items-center justify-center rounded-2xl border-2 border-dashed px-2 py-3 text-center text-sm font-bold transition enabled:hover:brightness-125", isWrong && "border-solid")}
              style={{ borderColor: isWrong ? "#f43f5e" : c, color: isWrong ? "#fda4af" : c, background: isHit ? `${c}22` : `${c}0d` }}
            >
              {b.label}
            </motion.button>
          );
        })}
      </div>
      <p role="status" className={cn("min-h-[2.75rem] rounded-lg px-3 py-2 text-sm leading-relaxed", landed ? "bg-emerald-500/10 text-emerald-200" : wrong ? "bg-rose-500/10 text-rose-300" : "text-slate-500")}>
        {landed ? <><Check className="mr-1 inline h-4 w-4" />{card.why}</>
          : wrong ? "Not that bin. What is this, really?" : "Tap the bin this card belongs in."}
      </p>
      {landed && (
        <button onClick={next} className="rounded-xl border border-teal-300/60 px-4 py-2 text-sm font-bold text-teal-100 hover:bg-teal-500/10">
          {idx + 1 < deck.length ? "Next card" : "Finish the deck"}
        </button>
      )}
    </div>
  );
}
