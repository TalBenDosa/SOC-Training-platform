"use client";
import React, { useEffect } from "react";
import { BookOpen, Check, Clock, Film, FlaskConical, KeyRound, Lock, Play, RotateCcw, Star } from "lucide-react";
import { motion } from "framer-motion";
import { cn } from "@/lib/utils";
import { Logo } from "@/components/Logo";
import { coreLabel, type StageBoardProps } from "./StageBoard";
import { ROLL_MS } from "./useClearRoll";

// The theme's main screen. Left: the site's own logo and the learner's journey.
// Bottom: what the selected station holds. What stands in the world is clickable too.

const MINUTES: Record<string, number> = { reading: 6, log_analysis: 5, written_report: 8, query_fill: 4, analyst_choice: 4 };
const DONE = "#34d399";

function Ring({ pct, color }: { pct: number; color: string }) {
  const r = 26, c = 2 * Math.PI * r;
  return (
    <svg viewBox="0 0 64 64" className="h-16 w-16 shrink-0" role="img" aria-label={`${pct}% complete`}>
      <circle cx="32" cy="32" r={r} fill="none" stroke="rgba(148,163,184,0.25)" strokeWidth="6" />
      <circle cx="32" cy="32" r={r} fill="none" stroke={color} strokeWidth="6" strokeLinecap="round" strokeDasharray={c} strokeDashoffset={c * (1 - pct / 100)} transform="rotate(-90 32 32)" />
      <text x="32" y="37" textAnchor="middle" fontSize="14" fontWeight="700" fill="#fff">{pct}%</text>
    </svg>
  );
}

/** Layouts with no card of their own: a 3D card rolls in, spins, lands on the result and leaves.
 *  The faces swap by opacity while it spins, so the result is never mirrored. */
function ClearCard({ label, stars, accent }: { label: string; stars: number; accent: string }) {
  const seconds = ROLL_MS / 1000;
  const face = "absolute inset-0 flex flex-col items-center justify-center gap-3 rounded-2xl border-2 p-5 text-center";
  return (
    <div aria-hidden className="pointer-events-none absolute inset-0 z-30 grid place-items-center [perspective:1100px]">
      <motion.div className="relative h-80 w-56"
        initial={{ x: "60vw", rotateY: 0, rotateZ: 40, scale: 0.7, opacity: 0 }}
        animate={{ x: ["60vw", "0vw", "0vw", "0vw", "-60vw"], rotateY: [0, 180, 1080, 1080, 1080], rotateZ: [40, 0, 0, 0, -30], scale: [0.7, 1, 1.12, 1.12, 0.7], opacity: [0, 1, 1, 1, 0] }}
        transition={{ duration: seconds, times: [0, 0.16, 0.56, 0.86, 1], ease: "easeInOut" }}>
        <motion.div className={face} style={{ borderColor: accent, background: "#0a1626" }}
          initial={{ opacity: 1 }} animate={{ opacity: [1, 1, 0, 0] }} transition={{ duration: seconds, times: [0, 0.52, 0.55, 1] }}>
          <Star className="h-12 w-12" style={{ color: accent }} />
        </motion.div>
        <motion.div className={face} style={{ borderColor: DONE, background: "radial-gradient(circle at 50% 35%, #0d4a3a, #04141a)" }}
          initial={{ opacity: 0 }} animate={{ opacity: [0, 0, 1, 1] }} transition={{ duration: seconds, times: [0, 0.52, 0.55, 1] }}>
          <span className="grid h-20 w-20 place-items-center rounded-full border-4" style={{ borderColor: DONE }}><Check className="h-10 w-10" style={{ color: DONE }} /></span>
          <p className="text-sm font-bold tracking-widest" style={{ color: DONE }}>CLEARED</p>
          <p className="text-xl font-bold leading-tight text-white">{label}</p>
          <p className="flex gap-1">{[0, 1, 2].map(i => <Star key={i} className={cn("h-5 w-5", i < stars ? "fill-amber-300 text-amber-300" : "text-slate-500")} />)}</p>
        </motion.div>
      </motion.div>
    </div>
  );
}

export function FacilityBoard({ experience, room, stations, selected, onSelect, onEnter, tokens, stories, onPlayStory, rolling = null, cardInWorld = false }: StageBoardProps & { rolling?: number | null; cardInWorld?: boolean }) {
  const accent = experience.look?.primary ?? "#22d3ee";
  const prog = stations.reduce((t, s) => { const [d, n] = s.progress.split("/").map(Number); return { done: t.done + d, all: t.all + n }; }, { done: 0, all: 0 });
  const pct = prog.all ? Math.floor((prog.done / prog.all) * 100) : 0;
  const stars = stations.reduce((a, s) => a + s.stars, 0);
  const sel = stations[selected];
  const station = experience.stations[selected];
  const tasks = room.tasks.filter(t => station?.taskIds.includes(t.id));
  const minutes = tasks.reduce((a, t) => a + (MINUTES[t.type] ?? 2), 0);
  const kind = tasks.some(t => t.type === "reading") ? "Hands-on briefing" : "Evidence work";

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLElement && /input|textarea/i.test(e.target.tagName)) return;
      if (e.key === "ArrowRight") onSelect(Math.min(stations.length - 1, selected + 1));
      if (e.key === "ArrowLeft") onSelect(Math.max(0, selected - 1));
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [selected, stations.length, onSelect]);

  const rolled = rolling === null ? null : stations[rolling];

  return (
    <div className="pointer-events-none absolute inset-0 z-20 flex flex-col">
      <p className="sr-only" role="status">{rolled ? `${coreLabel(rolled.label)} cleared` : ""}</p>
      {rolled && !cardInWorld && <ClearCard key={rolled.id} label={coreLabel(rolled.label)} stars={rolled.stars} accent={accent} />}
      {/* Top row: the logo sits right of the back button that the HUD places top-left */}
      <div className="pointer-events-auto flex items-center gap-3 bg-gradient-to-b from-[#05080f]/80 to-transparent py-[1.1rem] pl-[4.5rem] pr-4">
        <Logo />
        <div className="ml-auto flex items-center gap-2">
          <span className="inline-flex h-10 items-center gap-1.5 rounded-lg border border-white/15 bg-[#0d1320]/80 px-3 text-sm font-bold text-amber-300 backdrop-blur" title="Intel tokens: earned in briefings, spent on hints"><KeyRound className="h-4 w-4" />{tokens}</span>
          <span className="hidden h-10 items-center gap-1.5 rounded-lg border border-white/15 bg-[#0d1320]/80 px-3 text-sm font-bold text-white backdrop-blur sm:inline-flex"><Star className="h-4 w-4 fill-amber-300 text-amber-300" />{stars}/{stations.length * 3}</span>
        </div>
      </div>

      {/* Journey panel */}
      <aside aria-label="Your journey" className="pointer-events-auto mx-4 hidden w-72 rounded-2xl border border-white/15 bg-[#0d1320]/75 p-4 backdrop-blur-md lg:block">
        <div className="flex items-center gap-3">
          <div className="min-w-0 flex-1">
            <p className="text-lg font-bold leading-tight text-white">{room.title}</p>
            <p className="mt-1 text-xs text-slate-300">{experience.codename}</p>
          </div>
          <Ring pct={pct} color={accent} />
        </div>
        <ol className="mt-3 grid gap-0.5">
          {stations.map((s, i) => (
            <li key={s.id}>
              <button onClick={() => onSelect(i)} aria-current={i === selected ? "step" : undefined}
                className={cn("flex w-full items-center gap-3 rounded-lg px-2 py-2 text-left text-sm", i === selected ? "bg-white/10 font-bold text-white" : s.status === "locked" ? "text-slate-400 hover:bg-white/5" : "text-slate-200 hover:bg-white/5")}>
                <span className="grid h-7 w-7 shrink-0 place-items-center rounded-full border-2" style={{ borderColor: s.status === "cleared" ? DONE : s.status === "open" ? accent : "rgba(148,163,184,0.5)", background: s.status === "cleared" ? DONE : "transparent" }}>
                  {s.status === "cleared" ? <Check className="h-4 w-4 text-[#052e22]" /> : s.status === "locked" ? <Lock className="h-3.5 w-3.5" /> : <span className="h-2.5 w-2.5 rounded-full" style={{ background: accent }} />}
                </span>
                {coreLabel(s.label)}
              </button>
            </li>
          ))}
        </ol>
      </aside>

      <div className="flex-1" />

      {stories.length > 0 && (
        <div className="pointer-events-auto mx-4 mb-2 flex flex-wrap items-center gap-2">
          <Film className="h-4 w-4 text-slate-300" />
          {stories.map(s => (
            <button key={s.key} onClick={() => onPlayStory(s)} title={s.clip.title} className="inline-flex items-center gap-1.5 rounded-lg border border-white/15 bg-[#0d1320]/85 px-3 py-1 text-xs font-semibold text-slate-200 backdrop-blur hover:border-white/40">
              <Play className="h-3 w-3 fill-current" /> {s.label}
            </button>
          ))}
        </div>
      )}

      {/* Selected station */}
      {sel && station && (
        <div className="pointer-events-auto mx-3 mb-16 flex flex-col gap-3 rounded-2xl border border-white/15 bg-[#0d1320]/85 p-4 backdrop-blur-md md:mx-4 md:flex-row md:items-center md:gap-5">
          <p className="text-xl font-bold leading-tight text-white md:min-w-[11rem]">{coreLabel(sel.label)}</p>
          <p className="flex-1 text-sm leading-relaxed text-slate-200 md:border-l md:border-white/10 md:pl-5">
            {station.topic && <span className="mb-0.5 flex items-center gap-1.5 text-xs font-semibold" style={{ color: accent }}><BookOpen className="h-3.5 w-3.5" />You learn: {station.topic}</span>}
            {station.tagline}
          </p>
          <div className="flex flex-wrap items-center gap-x-5 gap-y-1 text-sm text-slate-200">
            <span className="inline-flex items-center gap-2"><FlaskConical className="h-4 w-4" /> {kind}</span>
            <span className="inline-flex items-center gap-2"><Clock className="h-4 w-4" /> ~{minutes} min</span>
          </div>
          <button onClick={() => onEnter(sel.id)} disabled={sel.status === "locked"}
            className="inline-flex items-center justify-center gap-2 rounded-xl px-6 py-3 text-base font-extrabold text-[#04121a] enabled:hover:brightness-110 disabled:cursor-not-allowed disabled:bg-slate-600 disabled:text-slate-200"
            style={sel.status === "locked" ? undefined : { background: sel.status === "cleared" ? DONE : accent }}>
            {sel.status === "cleared" ? <><RotateCcw className="h-4 w-4" /> Replay</> : sel.status === "locked" ? <><Lock className="h-4 w-4" /> Locked</> : <><Play className="h-4 w-4 fill-current" /> {sel.progress.startsWith("0/") ? "Enter" : "Continue"}</>}
          </button>
        </div>
      )}
    </div>
  );
}
