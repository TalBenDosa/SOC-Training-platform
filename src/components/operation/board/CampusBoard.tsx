"use client";
import React, { useEffect } from "react";
import { motion } from "framer-motion";
import { Activity, BedDouble, Siren, Lock, Check, KeyRound, Star, Play, Film, RotateCcw, Clock, FlaskConical, Moon, Sunrise, Radio } from "lucide-react";
import { cn } from "@/lib/utils";
import type { RoomExperience } from "@/lib/rooms/experience";
import type { SanitizedRoom } from "@/lib/rooms/sanitize";
import type { HubStation } from "./types";
import type { StoryEntry } from "./MissionBoard";

// The "campus" main screen: the 3D campus fills the screen behind this overlay.
// Left: the operation plate and a shift clock that runs from night to dawn with
// progress. Right: a facility status monitor, one row per building (select a
// row to inspect it). Bottom left: the selected building's card with Enter.

const DEFAULT_LOOK = { primary: "#2dd4bf", secondary: "#60a5fa", warn: "#f43f5e" };
const pad2 = (n: number) => String(n).padStart(2, "0");
const MINUTES: Record<string, number> = { reading: 6, log_analysis: 5, written_report: 8, query_fill: 4, analyst_choice: 4 };
const SHIFT_START = 2 * 60 + 40, DAWN = 6 * 60 + 12;
const clock = (m: number) => `${pad2(Math.floor(m / 60))}:${pad2(Math.round(m % 60))}`;

export interface CampusBoardProps {
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

export function CampusBoard({ experience, room, stations, selected, onSelect, onEnter, tokens, stories, onPlayStory }: CampusBoardProps) {
  const look = experience.look ?? DEFAULT_LOOK;
  const cleared = stations.filter(s => s.status === "cleared").length;
  const prog = stations.length ? cleared / stations.length : 0;
  const stars = stations.reduce((a, s) => a + s.stars, 0);
  const words = experience.codename.replace(/^Operation\s+/i, "").toUpperCase();
  const sel = stations[selected];
  const station = experience.stations[selected];
  const tasks = room.tasks.filter(t => station?.taskIds.includes(t.id));
  const minutes = tasks.reduce((a, t) => a + (MINUTES[t.type] ?? 2), 0);
  const kinds = new Set(tasks.map(t => t.type));
  const kindLabel = kinds.has("reading") ? "Hands-on briefing" : kinds.has("log_analysis") ? "Evidence work" : "Challenge";
  const now = SHIFT_START + (DAWN - SHIFT_START) * prog;
  const all = cleared === stations.length;

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLElement && /input|textarea/i.test(e.target.tagName)) return;
      if (e.key === "ArrowDown" || e.key === "ArrowRight") onSelect(Math.min(stations.length - 1, selected + 1));
      if (e.key === "ArrowUp" || e.key === "ArrowLeft") onSelect(Math.max(0, selected - 1));
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [selected, stations.length, onSelect]);

  const vitals = [
    { icon: Activity, label: "Systems online", value: `${Math.round(18 + prog * 82)}%` },
    { icon: Siren, label: "ER queue", value: stations[1]?.status === "cleared" ? "Moving" : "Frozen" },
    { icon: BedDouble, label: "Beds tracked", value: `${Math.round(120 + prog * 280)} / 400` },
  ];

  return (
    <div className="pointer-events-none absolute inset-0 z-20" style={{ "--op-a": look.primary } as React.CSSProperties}>
      {/* Operation plate + shift clock */}
      <div className="absolute left-4 top-20 max-w-sm sm:left-8">
        <p className="font-mono text-[11px] font-semibold uppercase tracking-[0.35em]" style={{ color: look.primary }}>Night shift · {room.title}</p>
        <h1 className="mt-1 text-3xl font-black leading-none tracking-tight text-white drop-shadow-[0_2px_16px_rgba(0,0,0,0.9)] sm:text-5xl">
          {words.split(" ").map((w, i) => <span key={w} className="block" style={i > 0 ? { color: look.primary } : undefined}>{w}</span>)}
        </h1>
        <p className="mt-3 text-sm leading-relaxed text-slate-200 drop-shadow-[0_1px_8px_rgba(0,0,0,0.9)]">{experience.mission}</p>
        <div className="pointer-events-auto mt-4 inline-flex items-center gap-3 rounded-2xl border border-white/15 bg-[#071021]/80 px-4 py-2.5 backdrop-blur">
          {all ? <Sunrise className="h-6 w-6 text-amber-300" /> : <Moon className="h-6 w-6 text-sky-300" />}
          <div>
            <p className="font-mono text-2xl font-black leading-none text-white">{clock(now)}</p>
            <p className="text-[10px] uppercase tracking-[0.25em] text-slate-400">{all ? "First light" : `Dawn at ${clock(DAWN)}`}</p>
          </div>
          <span className="ml-2 inline-flex items-center gap-1.5 rounded-full border border-amber-400/40 px-2.5 py-1 text-xs font-bold text-amber-300" title="Intel tokens: earned in briefings, spent on hints"><KeyRound className="h-3.5 w-3.5" />{tokens}</span>
          <span className="inline-flex items-center gap-1.5 text-xs font-bold text-white"><Star className="h-3.5 w-3.5 fill-amber-300 text-amber-300" />{stars}/{stations.length * 3}</span>
        </div>
      </div>

      {/* Facility status monitor */}
      <aside className="pointer-events-auto absolute right-4 top-20 hidden w-[19rem] rounded-2xl border border-white/10 bg-[#061021]/85 p-4 backdrop-blur-md md:block lg:right-8"
        style={{ boxShadow: `0 0 50px -24px ${look.primary}` }} aria-label="Facility status">
        <div className="flex items-center gap-2">
          <Radio className="h-4 w-4" style={{ color: look.primary }} />
          <p className="font-mono text-[11px] font-bold uppercase tracking-[0.3em] text-slate-200">Facility status</p>
          <span className="ml-auto font-mono text-[11px] text-slate-400">{cleared}/{stations.length}</span>
        </div>
        <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-white/10">
          <motion.div className="h-full rounded-full" style={{ background: `linear-gradient(90deg, ${look.warn}, ${look.primary})` }} animate={{ width: `${Math.max(4, prog * 100)}%` }} />
        </div>
        <ol className="mt-3 space-y-1.5">
          {stations.map((s, i) => (
            <li key={s.id}>
              <button
                onClick={() => onSelect(i)}
                aria-current={i === selected ? "true" : undefined}
                className={cn("flex w-full items-center gap-3 rounded-xl border px-3 py-2 text-left transition", i === selected ? "bg-white/[0.06]" : "border-transparent hover:bg-white/[0.04]")}
                style={i === selected ? { borderColor: `${look.primary}88` } : undefined}
              >
                <span className="grid h-7 w-7 shrink-0 place-items-center rounded-lg border font-mono text-[11px] font-bold"
                  style={{ borderColor: s.status === "cleared" ? "#34d399" : s.status === "open" ? look.primary : "rgba(148,163,184,0.35)", color: s.status === "locked" ? "#94a3b8" : "#fff" }}>
                  {s.status === "cleared" ? <Check className="h-4 w-4 text-emerald-300" /> : s.status === "locked" ? <Lock className="h-3.5 w-3.5" /> : pad2(i + 1)}
                </span>
                <span className="min-w-0 flex-1">
                  <span className={cn("block truncate text-sm font-bold", s.status === "locked" ? "text-slate-400" : "text-white")}>{s.label}</span>
                  <span className="block font-mono text-[10px] uppercase tracking-widest"
                    style={{ color: s.status === "cleared" ? "#6ee7b7" : s.status === "open" ? look.primary : "#fda4af" }}>
                    {s.status === "cleared" ? "Online" : s.status === "open" ? "Restoring" : "Offline"}
                  </span>
                </span>
                {s.status === "cleared" && <span className="flex gap-0.5">{[0, 1, 2].map(k => <Star key={k} className={cn("h-3 w-3", k < s.stars ? "fill-amber-300 text-amber-300" : "text-slate-600")} />)}</span>}
                {s.status === "open" && <span className="h-2 w-2 animate-pulse rounded-full" style={{ background: look.primary }} />}
              </button>
            </li>
          ))}
        </ol>
        <div className="mt-4 grid grid-cols-3 gap-2 border-t border-white/10 pt-3">
          {vitals.map(v => (
            <div key={v.label} className="rounded-lg bg-white/[0.03] p-2 text-center">
              <v.icon className="mx-auto h-4 w-4 text-slate-300" />
              <p className="mt-1 font-mono text-xs font-bold text-white">{v.value}</p>
              <p className="text-[9px] uppercase tracking-wider text-slate-500">{v.label}</p>
            </div>
          ))}
        </div>
      </aside>

      {/* Selected building + story films */}
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
              <span className="font-mono text-sm font-black" style={{ color: look.primary }}>{pad2(selected + 1)}</span>
              <p className="text-xl font-black text-white">{sel.label}</p>
              {station.boss && <span className="rounded-full border border-amber-300/50 px-2 py-0.5 text-[10px] font-bold uppercase tracking-widest text-amber-300">Final</span>}
            </div>
            <p className="mt-1 text-sm leading-relaxed text-slate-300">{station.tagline}</p>
            {sel.status === "locked" && selected > 0 && (
              <p className="mt-1 text-xs font-semibold" style={{ color: look.warn }}>Offline: restore {stations[selected - 1].label} first.</p>
            )}
            <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-2 text-xs text-slate-300">
              <span className="inline-flex items-center gap-1.5"><FlaskConical className="h-3.5 w-3.5" /> {kindLabel}</span>
              <span className="inline-flex items-center gap-1.5"><Clock className="h-3.5 w-3.5" /> ~{minutes} min</span>
              <button
                onClick={() => onEnter(sel.id)}
                disabled={sel.status === "locked"}
                className="ml-auto inline-flex items-center gap-2 rounded-xl border-2 px-5 py-2.5 text-sm font-extrabold transition enabled:hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-40"
                style={sel.status === "cleared"
                  ? { borderColor: "#34d399", color: "#a7f3d0", background: "rgba(16,185,129,0.12)" }
                  : { borderColor: look.primary, color: "#fff", background: `${look.primary}22`, boxShadow: sel.status === "open" ? `0 0 26px -6px ${look.primary}` : undefined }}
              >
                {sel.status === "cleared" ? <><RotateCcw className="h-4 w-4" /> Replay</> : sel.status === "locked" ? <><Lock className="h-4 w-4" /> Offline</> : <><Play className="h-4 w-4 fill-current" /> {sel.progress.startsWith("0/") ? "Restore this wing" : "Continue"}</>}
              </button>
            </div>
          </motion.div>
        )}
      </div>
    </div>
  );
}
