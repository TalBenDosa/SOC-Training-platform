"use client";
import React, { useEffect } from "react";
import { motion } from "framer-motion";
import { BookOpen, ChevronLeft, ChevronRight, Crosshair, Lock, Check, KeyRound, Star, FlaskConical, Clock, Play, Film, RotateCcw } from "lucide-react";
import { cn } from "@/lib/utils";
import type { RoomExperience } from "@/lib/rooms/experience";
import type { SanitizedRoom } from "@/lib/rooms/sanitize";
import type { HubStation } from "./types";
import type { StoryEntry } from "./MissionBoard";

// The "stage" main screen: the room's 3D world fills the screen behind this
// overlay. Top: progression track and the title plate. Bottom: a command bar
// for the selected station. Stations are chosen on the track (or with the
// arrow keys); the world highlights the selection but is never clickable.

const DEFAULT_LOOK = { primary: "#22d3ee", secondary: "#a78bfa", warn: "#f59e0b" };
const pad2 = (n: number) => String(n).padStart(2, "0");
const shortLabel = (label: string) => label.replace(/^The /, "");
// Only ": " separates a prefix ("Hop 3: ..."), so a time like "03:47" is kept.
const coreName = (label: string) => shortLabel(label.includes(": ") ? label.slice(label.indexOf(": ") + 2).trim() : label);
const MINUTES: Record<string, number> = { reading: 6, log_analysis: 5, written_report: 8, query_fill: 4, analyst_choice: 4 };

export interface StageBoardProps {
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

export function StageBoard({ experience, room, stations, selected, onSelect, onEnter, tokens, stories, onPlayStory }: StageBoardProps) {
  const look = experience.look ?? DEFAULT_LOOK;
  const cleared = stations.filter(s => s.status === "cleared").length;
  const pct = stations.length ? Math.round((cleared / stations.length) * 100) : 0;
  const stars = stations.reduce((a, s) => a + s.stars, 0);
  const words = experience.codename.replace(/^Operation\s+/i, "").toUpperCase();
  const sel = stations[selected];
  const station = experience.stations[selected];

  // What the selected station holds, said the way a mission briefing would.
  const tasks = room.tasks.filter(t => station?.taskIds.includes(t.id));
  const minutes = tasks.reduce((a, t) => a + (MINUTES[t.type] ?? 2), 0);
  const kinds = new Set(tasks.map(t => t.type));
  const kindLabel = kinds.has("reading") ? "Hands-on briefing"
    : kinds.has("log_analysis") || kinds.has("query_fill") ? "Evidence work"
      : kinds.has("written_report") ? "Case write-up"
        : kinds.has("analyst_choice") ? "Live decision" : "Challenge";

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLElement && /input|textarea/i.test(e.target.tagName)) return;
      if (e.key === "ArrowRight") onSelect(Math.min(stations.length - 1, selected + 1));
      if (e.key === "ArrowLeft") onSelect(Math.max(0, selected - 1));
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [selected, stations.length, onSelect]);

  const prevLocked = selected > 0 ? stations[selected - 1] : null;

  return (
    <div className="pointer-events-none absolute inset-0 z-20 flex flex-col"
      style={{ "--op-a": look.primary } as React.CSSProperties}>
      {/* Progression track */}
      <div className="flex flex-col items-center px-4 pt-4">
        <ol className="pointer-events-auto flex items-center" aria-label={`Progression ${cleared} of ${stations.length}`}>
          {stations.map((s, i) => (
            <li key={s.id} className="flex items-center">
              {i > 0 && <span className="h-0.5 w-6 sm:w-14" style={{ background: s.status === "locked" ? "rgba(148,163,184,0.3)" : look.primary }} />}
              <button
                onClick={() => onSelect(i)}
                aria-label={`${pad2(i + 1)} ${s.label}, ${s.status}`}
                aria-current={i === selected ? "step" : undefined}
                className={cn("grid h-8 w-8 place-items-center rounded-full border-2 bg-[#0a1120] transition sm:h-9 sm:w-9", i === selected && "scale-110")}
                style={{
                  borderColor: s.status === "cleared" ? "#34d399" : s.status === "open" ? look.primary : "rgba(148,163,184,0.45)",
                  boxShadow: i === selected ? `0 0 0 3px #05080f, 0 0 0 5px ${look.primary}, 0 0 22px ${look.primary}` : undefined,
                }}
              >
                {s.status === "cleared" ? <Check className="h-4 w-4 text-emerald-300" />
                  : s.status === "locked" ? <Lock className="h-3.5 w-3.5 text-slate-300" />
                    : <span className="h-3 w-3 rounded-full" style={{ background: look.primary }} />}
              </button>
            </li>
          ))}
        </ol>
        <p className="mt-2 font-mono text-[11px] font-semibold uppercase tracking-[0.3em] text-slate-300">
          Progression <b className="text-white">{cleared} / {stations.length}</b> <span className="mx-2 text-slate-600">|</span> <b className="text-white">{pct}%</b> complete
        </p>
      </div>

      {/* Title plate */}
      <div className="mx-auto mt-4 px-4 text-center">
        <div className="relative px-6 py-3 sm:px-10">
          {["left-0 top-0 border-l-2 border-t-2", "right-0 top-0 border-r-2 border-t-2", "left-0 bottom-0 border-b-2 border-l-2", "right-0 bottom-0 border-b-2 border-r-2"].map(c => (
            <span key={c} className={cn("absolute h-4 w-4 border-white/40", c)} />
          ))}
          <h1 className="text-2xl font-black tracking-tight text-white drop-shadow-[0_2px_14px_rgba(0,0,0,0.9)] sm:text-4xl">
            OPERATION <span style={{ color: look.primary }}>{"//"}</span> <span style={{ color: look.primary }}>{words}</span>
          </h1>
          <p className="mt-1 font-mono text-[10px] uppercase tracking-[0.5em] text-slate-300 sm:text-xs">{room.title}</p>
        </div>
      </div>

      <div className="flex-1" />

      {/* Top-right status */}
      <div className="pointer-events-auto absolute right-4 top-4 hidden items-center gap-2 sm:flex">
        <span className="inline-flex h-11 items-center gap-2 rounded-full border border-amber-400/40 bg-[#0a1120]/80 px-4 text-sm font-bold text-amber-300 backdrop-blur" title="Intel tokens: earned in briefings, spent on hints">
          <KeyRound className="h-4 w-4" /> {tokens} Keys
        </span>
        <span className="inline-flex h-11 items-center gap-2 rounded-full border border-white/15 bg-[#0a1120]/80 px-4 text-sm font-bold text-white backdrop-blur">
          <Star className="h-4 w-4 fill-amber-300 text-amber-300" /> {stars} / {stations.length * 3}
        </span>
      </div>

      {/* Story films */}
      {stories.length > 0 && (
        <div className="pointer-events-auto mx-4 mb-2 flex flex-wrap items-center gap-2 sm:mx-8">
          <Film className="h-4 w-4 text-slate-300" />
          {stories.map(s => (
            <button key={s.key} onClick={() => onPlayStory(s)} title={s.clip.title}
              className="inline-flex items-center gap-1.5 rounded-full border border-white/15 bg-[#0a1120]/80 px-3 py-1 text-xs font-semibold text-slate-200 backdrop-blur hover:border-white/40">
              <Play className="h-3 w-3 fill-current" /> {s.label}
            </button>
          ))}
        </div>
      )}

      {/* Command bar */}
      {sel && station && (
        <motion.div
          key={sel.id}
          initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
          className="pointer-events-auto mx-3 mb-4 flex flex-col gap-3 rounded-2xl border bg-[#060c18]/85 p-4 backdrop-blur-md sm:mx-8 md:flex-row md:items-center md:gap-5 md:px-6"
          style={{ borderColor: `${look.primary}66`, boxShadow: `0 0 40px -18px ${look.primary}` }}
        >
          <div className="flex items-center gap-3 md:min-w-[17rem]">
            <button onClick={() => onSelect(Math.max(0, selected - 1))} disabled={selected === 0} aria-label="Previous station"
              className="grid h-8 w-8 shrink-0 place-items-center rounded-full border border-white/15 text-slate-300 disabled:opacity-30">
              <ChevronLeft className="h-4 w-4" />
            </button>
            <Crosshair className="h-8 w-8 shrink-0" style={{ color: sel.status === "locked" ? "#94a3b8" : look.primary }} />
            <p className="text-2xl font-black leading-none text-white sm:text-3xl">
              {pad2(selected + 1)} <span style={{ color: look.primary }}>{"//"}</span> {coreName(sel.label).toUpperCase()}
            </p>
            <button onClick={() => onSelect(Math.min(stations.length - 1, selected + 1))} disabled={selected === stations.length - 1} aria-label="Next station"
              className="ml-auto grid h-8 w-8 shrink-0 place-items-center rounded-full border border-white/15 text-slate-300 disabled:opacity-30 md:ml-0">
              <ChevronRight className="h-4 w-4" />
            </button>
          </div>
          <p className="flex-1 text-sm leading-relaxed text-slate-200 md:border-l md:border-white/10 md:pl-5">
            {station.topic && <span className="mb-0.5 flex items-center gap-1.5 text-xs font-semibold" style={{ color: look.primary }}><BookOpen className="h-3.5 w-3.5" />You learn: {station.topic}</span>}
            {station.tagline}
            {sel.status === "locked" && prevLocked && <span className="mt-1 block text-xs font-semibold" style={{ color: experience.look?.warn ?? "#f59e0b" }}>Locked: clear {prevLocked.label} first.</span>}
          </p>
          <div className="flex flex-wrap items-center gap-x-5 gap-y-2 text-sm text-slate-200 md:border-l md:border-white/10 md:pl-5">
            <span className="inline-flex items-center gap-2"><FlaskConical className="h-4 w-4" /> {kindLabel}</span>
            <span className="inline-flex items-center gap-2"><Clock className="h-4 w-4" /> ~{minutes} min</span>
            {sel.status === "cleared" && <span className="inline-flex gap-0.5">{[0, 1, 2].map(k => <Star key={k} className={cn("h-4 w-4", k < sel.stars ? "fill-amber-300 text-amber-300" : "text-slate-600")} />)}</span>}
          </div>
          <button
            onClick={() => onEnter(sel.id)}
            disabled={sel.status === "locked"}
            className="inline-flex items-center justify-center gap-2 rounded-xl border-2 px-6 py-3 text-base font-extrabold transition enabled:hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-40"
            style={sel.status === "cleared"
              ? { borderColor: "#34d399", color: "#a7f3d0", background: "rgba(16,185,129,0.12)" }
              : { borderColor: look.primary, color: "#fff", background: `${look.primary}22`, boxShadow: sel.status === "open" ? `0 0 26px -6px ${look.primary}` : undefined }}
          >
            {sel.status === "cleared" ? <><RotateCcw className="h-4 w-4" /> Replay</> : sel.status === "locked" ? <><Lock className="h-4 w-4" /> Locked</> : <><Play className="h-4 w-4 fill-current" /> {sel.progress.startsWith("0/") ? "Enter station" : "Continue"}</>}
          </button>
        </motion.div>
      )}
    </div>
  );
}
