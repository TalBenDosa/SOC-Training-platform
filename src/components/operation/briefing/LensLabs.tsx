"use client";
import React, { useEffect, useRef, useState } from "react";
import { motion } from "framer-motion";
import {
  Check, X, Cpu, Wifi, Lock, LockOpen, ScanLine, Stamp, Sparkles,
  Refrigerator, TrafficCone, Landmark, Syringe, Car, Cctv, Smartphone, Factory, Thermometer,
} from "lucide-react";
import { cn } from "@/lib/utils";
import type { BriefingLab, XrayIcon } from "@/lib/rooms/experience";

// Teaching labs for a first room: they introduce a concept before any graded
// question asks about it. Like the other labs they award nothing and report
// once when done.

interface LabProps<K extends BriefingLab["kind"]> {
  lab: Extract<BriefingLab, { kind: K }>;
  onDone: () => void;
}

function useDoneOnce(done: boolean, onDone: () => void) {
  const [fired, setFired] = useState(false);
  useEffect(() => { if (done && !fired) { setFired(true); onDone(); } }, [done, fired, onDone]);
}

// ─── X-ray: scan everyday objects to find the computer inside ────────────────
const XRAY_ICONS: Record<XrayIcon, React.ComponentType<{ className?: string }>> = {
  fridge: Refrigerator, traffic: TrafficCone, atm: Landmark, pump: Syringe, car: Car,
  camera: Cctv, phone: Smartphone, plant: Factory, thermostat: Thermometer,
};

export function XrayLab({ lab, onDone }: LabProps<"xray">) {
  const [seen, setSeen] = useState<Set<string>>(new Set());
  const [lens, setLens] = useState<{ x: number; y: number } | null>(null);
  const box = useRef<HTMLDivElement>(null);
  const done = seen.size === lab.objects.length;
  useDoneOnce(done, onDone);

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between text-xs">
        <span className="inline-flex items-center gap-1.5 font-mono uppercase tracking-widest text-teal-300"><ScanLine className="h-4 w-4" /> Lens active</span>
        <span className="font-bold text-slate-200">Scanned {seen.size} / {lab.objects.length}</span>
      </div>
      <div
        ref={box}
        onPointerMove={e => { const r = box.current?.getBoundingClientRect(); if (r && e.pointerType === "mouse") setLens({ x: e.clientX - r.left, y: e.clientY - r.top }); }}
        onPointerLeave={() => setLens(null)}
        className="relative grid grid-cols-2 gap-2.5 overflow-hidden rounded-2xl border border-white/10 bg-[linear-gradient(180deg,#0b1424,#070c16)] p-2.5 sm:grid-cols-4"
      >
        {lab.objects.map(o => {
          const Icon = XRAY_ICONS[o.icon];
          const on = seen.has(o.id);
          return (
            <button
              key={o.id}
              onClick={() => setSeen(s => new Set(s).add(o.id))}
              aria-pressed={on}
              className={cn("relative grid min-h-[9.5rem] overflow-hidden rounded-xl border text-left transition [&>*]:col-start-1 [&>*]:row-start-1", on ? "border-teal-300/60" : "border-white/10 hover:border-teal-300/40")}
            >
              {/* the everyday look; both looks share one grid cell so the tile fits the longer one */}
              <div className={cn("flex flex-col items-center justify-center gap-2 p-3 text-center", on && "invisible")}>
                <Icon className="h-10 w-10 text-slate-400" />
                <span className="text-sm font-bold text-slate-200">{o.label}</span>
                {!on && <span className="text-[10px] uppercase tracking-widest text-slate-500">tap to scan</span>}
              </div>
              {/* the x-ray look, revealed by a growing lens */}
              <motion.div
                initial={false}
                animate={{ clipPath: on ? "circle(150% at 50% 40%)" : "circle(0% at 50% 40%)" }}
                transition={{ duration: 0.6, ease: "easeOut" }}
                className="flex flex-col gap-1.5 bg-[#04263a] bg-[linear-gradient(rgba(45,212,191,0.12)_1px,transparent_1px),linear-gradient(90deg,rgba(45,212,191,0.12)_1px,transparent_1px)] bg-[size:14px_14px] p-3"
              >
                <span className="flex items-center gap-1.5 text-teal-200"><Cpu className="h-4 w-4" /><Wifi className="h-4 w-4" /><span className="text-xs font-black uppercase tracking-wide">{o.label}</span></span>
                <p className="text-[12px] leading-snug text-teal-50">{o.inside}</p>
                <p className="mt-auto text-[11px] leading-snug text-rose-300">If hacked: {o.risk}</p>
              </motion.div>
            </button>
          );
        })}
        {lens && (
          <span aria-hidden className="pointer-events-none absolute h-24 w-24 -translate-x-1/2 -translate-y-1/2 rounded-full border-2 border-teal-300/70 shadow-[0_0_30px_rgba(45,212,191,0.45),inset_0_0_24px_rgba(45,212,191,0.25)]"
            style={{ left: lens.x, top: lens.y }} />
        )}
      </div>
      <p role="status" className={cn("min-h-[2.5rem] rounded-lg px-3 py-2 text-sm leading-relaxed", done ? "bg-emerald-500/10 text-emerald-200" : "text-slate-400")}>
        {done ? <><Check className="mr-1 inline h-4 w-4" />{lab.doneNote}</> : "Every object here hides something. Scan them all."}
      </p>
    </div>
  );
}

// ─── Locks: one door per principle, opened by its check ──────────────────────
const LOCK_TINTS = ["#2dd4bf", "#60a5fa", "#fbbf24", "#f472b6"];

export function LocksLab({ lab, onDone }: LabProps<"locks">) {
  const [open, setOpen] = useState<Set<string>>(new Set());
  const [active, setActive] = useState<string>(lab.locks[0]?.id ?? "");
  const [wrong, setWrong] = useState<number | null>(null);
  const done = open.size === lab.locks.length;
  useDoneOnce(done, onDone);
  const lk = lab.locks.find(l => l.id === active);
  const tint = (id: string) => LOCK_TINTS[Math.max(0, lab.locks.findIndex(l => l.id === id)) % 4];

  function answer(i: number) {
    if (!lk || open.has(lk.id)) return;
    if (i === lk.check.answer) {
      setOpen(s => new Set(s).add(lk.id)); setWrong(null);
    } else setWrong(i);
  }
  function pick(id: string) { setActive(id); setWrong(null); }

  return (
    <div className="space-y-4">
      {/* The doors */}
      <div className="grid grid-cols-3 gap-2.5">
        {lab.locks.map(l => {
          const c = tint(l.id), isOpen = open.has(l.id), sel = l.id === active;
          return (
            <button key={l.id} onClick={() => pick(l.id)} aria-current={sel ? "true" : undefined}
              className="relative h-36 overflow-hidden rounded-t-[2.5rem] rounded-b-lg border-2 bg-[#0a1322] [perspective:600px] sm:h-44"
              style={{ borderColor: sel ? c : `${c}55`, boxShadow: isOpen ? `0 0 34px -8px ${c}` : undefined }}>
              {/* light behind the door */}
              <span className="absolute inset-0" style={{ background: `radial-gradient(circle at 50% 60%, ${c}55, transparent 70%)` }} />
              <span className="absolute inset-0 flex flex-col items-center justify-center text-center">
                <span className="text-xs font-bold uppercase tracking-widest" style={{ color: c }}>{l.name}</span>
              </span>
              {/* the door leaf swings open */}
              <motion.span
                initial={false}
                animate={{ rotateY: isOpen ? -78 : 0 }}
                transition={{ duration: 0.8, ease: "easeInOut" }}
                style={{ transformOrigin: "left center", borderColor: `${c}66` }}
                className="absolute inset-0 flex flex-col items-center justify-center gap-2 rounded-t-[2.4rem] border-r bg-[linear-gradient(160deg,#1a2740,#0e1729)]"
              >
                <span className="text-4xl font-black sm:text-5xl" style={{ color: c }}>{l.letter}</span>
                {isOpen ? <LockOpen className="h-6 w-6" style={{ color: c }} /> : <Lock className="h-6 w-6 text-slate-300" />}
              </motion.span>
            </button>
          );
        })}
      </div>

      {/* The selected door's lesson and its check */}
      {lk && (
        <motion.div key={lk.id} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
          className="rounded-2xl border bg-[#081120] p-4" style={{ borderColor: `${tint(lk.id)}55` }}>
          <p className="text-[11px] font-bold uppercase tracking-[0.25em]" style={{ color: tint(lk.id) }}>Lock {lk.letter} · {lk.name}</p>
          <p className="mt-2 font-semibold text-white">{lk.idea}</p>
          <p className="mt-1 text-sm leading-relaxed text-slate-300">{lk.example}</p>
          <p className="mt-4 text-sm font-bold text-slate-100">{lk.check.q}</p>
          <div className="mt-2 grid gap-2 sm:grid-cols-2">
            {lk.check.options.map((o, i) => {
              const right = open.has(lk.id) && i === lk.check.answer;
              return (
                <motion.button key={o} onClick={() => answer(i)} disabled={open.has(lk.id)}
                  animate={wrong === i ? { x: [0, -6, 6, -3, 3, 0] } : undefined}
                  className={cn("rounded-xl border px-3 py-2.5 text-left text-sm transition enabled:hover:bg-white/5",
                    right ? "border-emerald-400 bg-emerald-500/10 text-emerald-100" : wrong === i ? "border-rose-500 bg-rose-500/10 text-rose-200" : "border-white/15 text-slate-200")}>
                  {o}
                </motion.button>
              );
            })}
          </div>
          <p role="status" className="mt-3 min-h-[1.25rem] text-sm leading-relaxed">
            {open.has(lk.id) ? <span className="text-emerald-300"><Check className="mr-1 inline h-4 w-4" />{lk.check.why}</span>
              : wrong !== null ? <span className="text-rose-300"><X className="mr-1 inline h-4 w-4" />That breaks a different lock. Read the idea again.</span>
                : <span className="text-slate-500">Answer to open this lock.</span>}
          </p>
          {open.has(lk.id) && !done && (
            <button onClick={() => pick(lab.locks.find(l => !open.has(l.id))!.id)}
              className="mt-1 rounded-lg border border-teal-300/60 px-3 py-1.5 text-sm font-semibold text-teal-100 hover:bg-teal-500/10">
              Next door
            </button>
          )}
          {done && <p className="mt-1 text-sm font-semibold text-emerald-300">All locks open.{lab.finish ? ` ${lab.finish}` : ""}</p>}
        </motion.div>
      )}
    </div>
  );
}

// ─── Tricks: flip a card, stamp it with the attack it describes ──────────────
export function TricksLab({ lab, onDone }: LabProps<"tricks">) {
  const [flipped, setFlipped] = useState<string | null>(null);
  const [stamped, setStamped] = useState<Record<string, string>>({}); // card id → attack id
  const [wrong, setWrong] = useState<string | null>(null);
  const done = Object.keys(stamped).length === lab.cards.length;
  useDoneOnce(done, onDone);
  const card = lab.cards.find(c => c.id === flipped);
  const name = (id: string) => lab.attacks.find(a => a.id === id)?.name ?? id;

  function stamp(attackId: string) {
    if (!card || stamped[card.id]) return;
    if (attackId === card.attack) { setStamped(s => ({ ...s, [card.id]: attackId })); setWrong(null); }
    else setWrong(attackId);
  }

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-5">
        {lab.cards.map((c, i) => {
          const face = flipped === c.id || !!stamped[c.id];
          return (
            <button key={c.id} onClick={() => { setFlipped(c.id); setWrong(null); }}
              className={cn("relative h-44 [perspective:800px]", flipped === c.id && "z-10")} aria-label={face ? c.analogy : `Card ${i + 1}, face down`}>
              <motion.span initial={false} animate={{ rotateY: face ? 180 : 0, y: flipped === c.id ? -6 : 0 }} transition={{ duration: 0.5 }}
                className="absolute inset-0 [transform-style:preserve-3d]">
                {/* back */}
                <span className="absolute inset-0 grid place-items-center rounded-xl border-2 border-teal-300/40 bg-[repeating-linear-gradient(45deg,#0d1b2e_0_10px,#0a1526_10px_20px)] [backface-visibility:hidden]">
                  <Sparkles className="h-8 w-8 text-teal-300/70" />
                </span>
                {/* face */}
                <span className={cn("absolute inset-0 flex flex-col rounded-xl border-2 bg-[#f8f3e6] p-2.5 text-left [backface-visibility:hidden] [transform:rotateY(180deg)]",
                  flipped === c.id ? "border-amber-400" : "border-amber-200/60")}>
                  <span className="text-[12px] leading-snug text-slate-800">{c.analogy}</span>
                  {stamped[c.id] && (
                    <motion.span initial={{ scale: 2, opacity: 0, rotate: -18 }} animate={{ scale: 1, opacity: 1, rotate: -12 }}
                      className="mt-auto self-center rounded border-2 border-rose-600 px-2 py-0.5 text-xs font-black uppercase tracking-wide text-rose-600">
                      {name(stamped[c.id])}
                    </motion.span>
                  )}
                </span>
              </motion.span>
            </button>
          );
        })}
      </div>

      {/* The stamps */}
      <div className="rounded-2xl border border-white/10 bg-[#081120] p-3">
        <p className="mb-2 flex items-center gap-1.5 text-[11px] font-bold uppercase tracking-[0.25em] text-slate-400"><Stamp className="h-4 w-4" /> Stamp the card</p>
        <div className="flex flex-wrap gap-2">
          {lab.attacks.map(a => {
            const used = Object.values(stamped).includes(a.id);
            return (
              <motion.button key={a.id} onClick={() => stamp(a.id)} disabled={!card || !!stamped[card.id]}
                animate={wrong === a.id ? { x: [0, -6, 6, -3, 3, 0] } : undefined}
                className={cn("rounded-lg border-2 px-3 py-1.5 text-sm font-black uppercase tracking-wide transition enabled:hover:bg-rose-500/10 disabled:opacity-50",
                  wrong === a.id ? "border-rose-500 text-rose-300" : used ? "border-emerald-400/60 text-emerald-200" : "border-rose-400/60 text-rose-200")}>
                {a.name}
              </motion.button>
            );
          })}
        </div>
        <p role="status" className="mt-3 min-h-[2.5rem] text-sm leading-relaxed">
          {card && stamped[card.id] ? <span className="text-emerald-200"><Check className="mr-1 inline h-4 w-4" />{card.real}</span>
            : wrong ? <span className="text-rose-300">Not that one. Which attack works the same way as this trick?</span>
              : card ? <span className="text-slate-300">Which attack is this trick in the digital world?</span>
                : <span className="text-slate-500">Flip a card to read the trick.</span>}
        </p>
        {done && <p className="text-sm font-semibold text-emerald-300">Every trick has a name. The names are new, the tricks are old.</p>}
      </div>
    </div>
  );
}

// ─── Anatomy: decode a sample alert field by field ───────────────────────────
export function AnatomyLab({ lab, onDone }: LabProps<"anatomy">) {
  const keyFields = lab.fields.filter(f => f.note);
  const [seen, setSeen] = useState<Set<string>>(new Set());
  const [last, setLast] = useState<string | null>(null);
  const done = keyFields.every(f => seen.has(f.key));
  useDoneOnce(done, onDone);
  const lastF = lab.fields.find(f => f.key === last);

  return (
    <div className="grid gap-4 lg:grid-cols-[1.35fr_1fr]">
      <div className="overflow-hidden rounded-xl border border-white/10 bg-[#050a14] shadow-2xl">
        <div className="flex items-center gap-2 border-b border-white/10 bg-[#0b1424] px-3 py-2 text-[11px] font-semibold text-slate-300">
          <span className="h-2 w-2 animate-pulse rounded-full bg-rose-500" />
          <span className="truncate">{lab.source}</span>
          <span className="ml-auto font-mono text-slate-400">{seen.size}/{keyFields.length} decoded</span>
        </div>
        <ul className="divide-y divide-white/5 font-mono text-[12px]">
          {lab.fields.map(f => {
            const isKey = !!f.note, on = seen.has(f.key);
            const row = (
              <span className="flex min-w-0 flex-wrap gap-x-2 px-3 py-1.5 sm:flex-nowrap">
                <span className={cn("shrink-0", isKey ? "text-sky-300" : "text-slate-500")}>{f.key}</span>
                <span className={cn("min-w-0 basis-full break-all sm:basis-auto", isKey ? "text-slate-100" : "text-slate-400")}>{f.value}</span>
                {isKey && !on && <ScanLine className="ml-auto h-3.5 w-3.5 shrink-0 text-teal-300" />}
                {on && <Check className="ml-auto h-3.5 w-3.5 shrink-0 text-emerald-300" />}
              </span>
            );
            return (
              <li key={f.key} className={cn(on && "bg-teal-500/10", last === f.key && "ring-1 ring-inset ring-teal-300/60")}>
                {isKey ? (
                  <button onClick={() => { setSeen(s => new Set(s).add(f.key)); setLast(f.key); }} className="w-full text-left hover:bg-white/5">{row}</button>
                ) : row}
                {/* phones: the note opens right under its row */}
                {last === f.key && f.note && <p className="px-3 pb-2 font-sans text-[13px] leading-relaxed text-teal-100 lg:hidden">{f.note}</p>}
              </li>
            );
          })}
        </ul>
      </div>
      <div className="space-y-3">
        <div aria-live="polite" className="hidden min-h-[8rem] rounded-xl border border-white/10 bg-bg-panel/70 p-4 lg:block">
          {lastF?.note ? (
            <>
              <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-teal-300">{lastF.label ?? lastF.key}</p>
              <p className="mt-2 text-sm leading-relaxed text-slate-200">{lastF.note}</p>
            </>
          ) : <p className="text-sm text-slate-400">Fields with a scan mark are the ones an analyst reads first. Click each one.</p>}
        </div>
        {done ? (
          <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="rounded-xl border border-emerald-400/40 bg-emerald-500/10 p-4">
            <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-emerald-300">The alert in one line</p>
            <p className="mt-2 text-sm leading-relaxed text-emerald-50">{lab.summary}</p>
          </motion.div>
        ) : <p className="text-sm text-slate-500 lg:hidden">Tap each field with a scan mark.</p>}
      </div>
    </div>
  );
}
