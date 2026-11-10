"use client";
import React, { useEffect } from "react";
import { motion } from "framer-motion";
import { Lock, Check, KeyRound, Star, Play, Film, RotateCcw, Clock, FlaskConical, Eye, EyeOff, BookOpen } from "lucide-react";
import { cn } from "@/lib/utils";
import type { RoomExperience } from "@/lib/rooms/experience";
import type { SanitizedRoom } from "@/lib/rooms/sanitize";
import type { HubStation } from "./types";
import type { StoryEntry } from "./MissionBoard";

// The "lens" main screen: the 3D city fills the screen behind this overlay.
// Left: the operation plate and the lens dial, one segment per station (a
// segment lights when its layer is switched on). Right: the lens layers, each
// with the topic it teaches. Bottom left: the selected layer's card with Enter.

const DEFAULT_LOOK = { primary: "#2dd4bf", secondary: "#60a5fa", warn: "#f43f5e" };
const MINUTES: Record<string, number> = { reading: 6, log_analysis: 5, written_report: 8, query_fill: 4, analyst_choice: 4, mission: 12 };

export interface LensBoardProps {
  experience: RoomExperience;
  room: SanitizedRoom;
  stations: HubStation[];
  selected: number;
  onSelect: (i: number) => void;
  onEnter: (id: string) => void;
  tokens: number;
  stories: StoryEntry[];
  onPlayStory: (s: StoryEntry) => void;
}

/** SVG ring of n arc segments: cleared ones lit, the open one pulsing. */
function LensDial({ stations, selected, color, onSelect }: { stations: HubStation[]; selected: number; color: string; onSelect: (i: number) => void }) {
  const n = stations.length, R = 52, gap = 0.09;
  const arc = (i: number) => {
    const a0 = -Math.PI / 2 + (i / n) * Math.PI * 2 + gap, a1 = -Math.PI / 2 + ((i + 1) / n) * Math.PI * 2 - gap;
    const p = (a: number) => `${60 + Math.cos(a) * R} ${60 + Math.sin(a) * R}`;
    return `M ${p(a0)} A ${R} ${R} 0 0 1 ${p(a1)}`;
  };
  const cleared = stations.filter(s => s.status === "cleared").length;
  return (
    <svg viewBox="0 0 120 120" className="h-28 w-28 shrink-0 sm:h-32 sm:w-32" role="group" aria-label={`Lens layers on: ${cleared} of ${n}`}>
      <circle cx="60" cy="60" r="40" fill="#061021" stroke="rgba(255,255,255,0.12)" />
      <circle cx="60" cy="60" r="30" fill="none" stroke={color} strokeOpacity={0.15 + (cleared / n) * 0.6} strokeWidth="1.5" />
      {stations.map((s, i) => (
        <path key={s.id} d={arc(i)} fill="none" strokeLinecap="round" strokeWidth={i === selected ? 10 : 7}
          stroke={s.status === "cleared" ? color : s.status === "open" ? color : "rgba(148,163,184,0.25)"}
          strokeOpacity={s.status === "open" ? 0.45 : 1}
          className={cn("pointer-events-auto cursor-pointer", s.status === "open" && "animate-pulse")}
          onClick={() => onSelect(i)} />
      ))}
      <text x="60" y="58" textAnchor="middle" className="fill-white font-mono text-[20px] font-black">{cleared}/{n}</text>
      <text x="60" y="74" textAnchor="middle" className="fill-slate-400 text-[8px] uppercase tracking-[0.2em]">layers on</text>
    </svg>
  );
}

export function LensBoard({ experience, room, stations, selected, onSelect, onEnter, tokens, stories, onPlayStory }: LensBoardProps) {
  const look = experience.look ?? DEFAULT_LOOK;
  const cleared = stations.filter(s => s.status === "cleared").length;
  const stars = stations.reduce((a, s) => a + s.stars, 0);
  const words = experience.codename.replace(/^Operation\s+/i, "").toUpperCase();
  const sel = stations[selected];
  const station = experience.stations[selected];
  const tasks = room.tasks.filter(t => station?.taskIds.includes(t.id));
  const minutes = tasks.reduce((a, t) => a + (MINUTES[t.type] ?? 2), 0);
  const kinds = new Set(tasks.map(t => t.type));
  const kindLabel = kinds.has("reading") ? "Hands-on games" : kinds.has("log_analysis") ? "Work a real alert" : "Practice + challenge";

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLElement && /input|textarea/i.test(e.target.tagName)) return;
      if (e.key === "ArrowDown" || e.key === "ArrowRight") onSelect(Math.min(stations.length - 1, selected + 1));
      if (e.key === "ArrowUp" || e.key === "ArrowLeft") onSelect(Math.max(0, selected - 1));
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [selected, stations.length, onSelect]);

  const status = (s: HubStation) => s.status === "cleared" ? "Visible" : s.status === "open" ? "Calibrating" : "Hidden";

  return (
    <div className="pointer-events-none absolute inset-0 z-20" style={{ "--op-a": look.primary } as React.CSSProperties}>
      {/* Operation plate + lens dial */}
      <div className="absolute left-4 top-20 max-w-sm sm:left-8">
        <p className="font-mono text-[11px] font-semibold uppercase tracking-[0.35em]" style={{ color: look.primary }}>Day one · {room.title}</p>
        <h1 className="mt-1 text-3xl font-black leading-none tracking-tight text-white drop-shadow-[0_2px_16px_rgba(0,0,0,0.9)] sm:text-5xl">
          {words.split(" ").map((w, i) => <span key={w} className="block" style={i > 0 ? { color: look.primary } : undefined}>{w}</span>)}
        </h1>
        <p className="mt-3 text-sm leading-relaxed text-slate-200 drop-shadow-[0_1px_8px_rgba(0,0,0,0.9)]">{experience.mission}</p>
        <div className="mt-3 flex items-center gap-3">
          <LensDial stations={stations} selected={selected} color={look.primary} onSelect={onSelect} />
          <div className="pointer-events-auto space-y-2">
            <span className="flex items-center gap-1.5 rounded-full border border-amber-400/40 bg-[#071021]/80 px-2.5 py-1 text-xs font-bold text-amber-300" title="Intel tokens: earned in briefings, spent on hints"><KeyRound className="h-3.5 w-3.5" />{tokens} {tokens === 1 ? "token" : "tokens"}</span>
            <span className="flex items-center gap-1.5 rounded-full border border-white/15 bg-[#071021]/80 px-2.5 py-1 text-xs font-bold text-white"><Star className="h-3.5 w-3.5 fill-amber-300 text-amber-300" />{stars}/{stations.length * 3}</span>
          </div>
        </div>
      </div>

      {/* Lens layers */}
      <aside className="pointer-events-auto absolute right-4 top-20 hidden w-[21rem] rounded-2xl border border-white/10 bg-[#061021]/85 p-4 backdrop-blur-md md:block lg:right-8"
        style={{ boxShadow: `0 0 50px -24px ${look.primary}` }} aria-label="Lens layers">
        <div className="flex items-center gap-2">
          <Eye className="h-4 w-4" style={{ color: look.primary }} />
          <p className="font-mono text-[11px] font-bold uppercase tracking-[0.3em] text-slate-200">Cyber Lens layers</p>
          <span className="ml-auto font-mono text-[11px] text-slate-400">{cleared}/{stations.length}</span>
        </div>
        <ol className="mt-3 space-y-1.5">
          {stations.map((s, i) => {
            const st = experience.stations[i];
            return (
              <li key={s.id}>
                <button
                  onClick={() => onSelect(i)}
                  aria-current={i === selected ? "true" : undefined}
                  className={cn("flex w-full items-start gap-3 rounded-xl border px-3 py-2 text-left transition", i === selected ? "bg-white/[0.06]" : "border-transparent hover:bg-white/[0.04]")}
                  style={i === selected ? { borderColor: `${look.primary}88` } : undefined}
                >
                  <span className="mt-0.5 grid h-7 w-7 shrink-0 place-items-center rounded-full border font-mono text-[11px] font-bold"
                    style={{ borderColor: s.status === "cleared" ? look.primary : s.status === "open" ? look.primary : "rgba(148,163,184,0.35)", background: s.status === "cleared" ? `${look.primary}33` : undefined, color: s.status === "locked" ? "#94a3b8" : "#fff" }}>
                    {s.status === "cleared" ? <Check className="h-4 w-4" /> : s.status === "locked" ? <Lock className="h-3.5 w-3.5" /> : i + 1}
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className={cn("block text-sm font-bold leading-snug", s.status === "locked" ? "text-slate-400" : "text-white")}>{s.label}</span>
                    {st?.topic && <span className="block text-[11px] leading-snug text-slate-400">{st.topic}</span>}
                  </span>
                  <span className="mt-0.5 inline-flex items-center gap-1 font-mono text-[10px] uppercase tracking-widest"
                    style={{ color: s.status === "cleared" ? look.primary : s.status === "open" ? "#e2e8f0" : "#64748b" }}>
                    {s.status === "locked" ? <EyeOff className="h-3 w-3" /> : <Eye className="h-3 w-3" />}{status(s)}
                  </span>
                </button>
              </li>
            );
          })}
        </ol>
      </aside>

      {/* Selected layer + story films */}
      <div className="absolute inset-x-3 bottom-4 flex flex-col gap-2 sm:left-8 sm:right-auto sm:w-[30rem]">
        {stories.length > 0 && (
          <div className="pointer-events-auto flex flex-wrap items-center gap-2">
            <Film className="h-4 w-4 text-slate-300" />
            {stories.map(s => (
              <button key={s.key} onClick={() => onPlayStory(s)} title={s.clip.title}
                className="inline-flex items-center gap-1.5 rounded-full border border-white/15 bg-[#071021]/85 px-3 py-1 text-xs font-semibold text-slate-200 backdrop-blur hover:border-white/40">
                <Play className="h-3 w-3 fill-current" /> {s.label}
              </button>
            ))}
          </div>
        )}
        {sel && station && (
          <motion.div key={sel.id} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
            className="pointer-events-auto rounded-2xl border bg-[#061021]/90 p-4 backdrop-blur-md"
            style={{ borderColor: `${look.primary}66`, boxShadow: `0 0 40px -18px ${look.primary}` }}>
            <div className="flex items-baseline gap-3">
              <span className="font-mono text-sm font-black" style={{ color: look.primary }}>Layer {selected + 1}</span>
              <p className="text-xl font-black text-white">{sel.label}</p>
              {station.boss && <span className="rounded-full border border-amber-300/50 px-2 py-0.5 text-[10px] font-bold uppercase tracking-widest text-amber-300">Final</span>}
            </div>
            {station.topic && (
              <p className="mt-1 inline-flex items-center gap-1.5 text-xs font-semibold" style={{ color: look.primary }}><BookOpen className="h-3.5 w-3.5" /> You learn: {station.topic}</p>
            )}
            <p className="mt-1 text-sm leading-relaxed text-slate-300">{station.tagline}</p>
            {sel.status === "locked" && selected > 0 && (
              <p className="mt-1 text-xs font-semibold text-slate-400">Hidden: switch on {stations[selected - 1].label} first.</p>
            )}
            <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-2 text-xs text-slate-300">
              <span className="inline-flex items-center gap-1.5"><FlaskConical className="h-3.5 w-3.5" /> {kindLabel}</span>
              <span className="inline-flex items-center gap-1.5"><Clock className="h-3.5 w-3.5" /> ~{minutes} min</span>
              <button
                onClick={() => onEnter(sel.id)}
                disabled={sel.status === "locked"}
                className="ml-auto inline-flex items-center gap-2 rounded-xl border-2 px-5 py-2.5 text-sm font-extrabold transition enabled:hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-40"
                style={sel.status === "cleared"
                  ? { borderColor: look.primary, color: "#ccfbf1", background: `${look.primary}1a` }
                  : { borderColor: look.primary, color: "#fff", background: `${look.primary}22`, boxShadow: sel.status === "open" ? `0 0 26px -6px ${look.primary}` : undefined }}
              >
                {sel.status === "cleared" ? <><RotateCcw className="h-4 w-4" /> Replay</> : sel.status === "locked" ? <><Lock className="h-4 w-4" /> Hidden</> : <><Play className="h-4 w-4 fill-current" /> {sel.progress.startsWith("0/") ? "Switch on this layer" : "Continue"}</>}
              </button>
            </div>
          </motion.div>
        )}
      </div>
    </div>
  );
}
