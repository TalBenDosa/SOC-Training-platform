"use client";
import React, { useState } from "react";
import { motion } from "framer-motion";
import { ChevronRight, ChevronsRight, ChevronsDown, Lock, Play, CheckCircle2, Star, KeyRound, Flag, Timer, Signal, Layers, RotateCcw } from "lucide-react";
import { cn } from "@/lib/utils";
import type { RoomExperience } from "@/lib/rooms/experience";
import type { HubStation } from "./types";
import { StationArt } from "./StationArt";

// The operation's main screen: mission header, progress track, one illustrated
// card per station, the 3D shield as the centrepiece (OperationView places the
// scene behind `onHeroSlot`), and the journey footer.

const DEFAULT_LOOK = { primary: "#22d3ee", secondary: "#a78bfa", warn: "#fb7185" };

const shortLabel = (label: string) => label.replace(/^The /, "");

export interface MissionBoardProps {
  experience: RoomExperience;
  roomTitle: string;
  difficulty?: string;
  stations: HubStation[];
  tokens: number;
  has3d: boolean;
  onEnter: (id: string) => void;
  onHeroSlot: (el: HTMLDivElement | null) => void;
  onScroll: () => void;
}

export function MissionBoard({ experience, roomTitle, difficulty, stations, tokens, has3d, onEnter, onHeroSlot, onScroll }: MissionBoardProps) {
  const look = experience.look ?? DEFAULT_LOOK;
  const cleared = stations.filter(s => s.status === "cleared").length;
  const words = experience.codename.split(" ");
  const lead = words.length > 2 ? words.slice(0, -2).join(" ") : "";
  const accent = words.length > 2 ? words.slice(-2).join(" ") : experience.codename;
  const [denied, setDenied] = useState<string | null>(null);

  function tap(s: HubStation) {
    if (s.status === "locked") {
      setDenied(s.id);
      window.setTimeout(() => setDenied(d => (d === s.id ? null : d)), 1800);
      return;
    }
    onEnter(s.id);
  }

  return (
    <div
      onScroll={onScroll}
      className="absolute inset-0 z-20 overflow-y-auto"
      style={{ "--op-a": look.primary, "--op-b": look.secondary, "--op-w": look.warn } as React.CSSProperties}
    >
      <style>{BOARD_CSS}</style>
      <div className="mx-auto flex min-h-full max-w-[1440px] flex-col px-4 pb-5 pt-20 sm:px-8">
        {/* Mission header + progress track */}
        <div className="flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between">
          <div className="max-w-2xl">
            <p className="text-xs font-bold uppercase tracking-[0.35em]" style={{ color: look.primary }}>Mission · {roomTitle}</p>
            <h1 className="mt-1 text-4xl font-extrabold tracking-tight text-white sm:text-5xl">
              {lead && <>{lead} </>}
              <span className="bg-clip-text text-transparent" style={{ backgroundImage: `linear-gradient(90deg, ${look.primary}, ${look.secondary})` }}>{accent}</span>
            </h1>
            <p className="mt-3 text-[15px] leading-relaxed text-slate-300">{experience.mission}</p>
          </div>

          <div className="w-full rounded-2xl border border-white/10 bg-[#0a1120]/80 p-4 backdrop-blur lg:w-[30rem]">
            <div className="flex items-center justify-between text-sm">
              <span className="font-bold text-white">Your progress</span>
              <span className="flex items-center gap-3">
                <span className="inline-flex items-center gap-1 font-bold text-neon-amber" title="Intel tokens: earned in briefings, spent on hints">
                  <KeyRound className="h-3.5 w-3.5" /> {tokens}
                </span>
                <span className="text-slate-400"><b className="font-mono" style={{ color: look.primary }}>{cleared}</b> / {stations.length} stations</span>
              </span>
            </div>
            <ol className="mt-4 flex items-start" aria-label={`${cleared} of ${stations.length} stations cleared`}>
              {stations.map((s, i) => (
                <li key={s.id} className="relative flex flex-1 flex-col items-center text-center">
                  {i > 0 && (
                    <span className="absolute right-1/2 top-[9px] h-0.5 w-full -translate-x-[11px]"
                      style={{ background: s.status !== "locked" ? look.primary : "rgba(148,163,184,0.25)" }} />
                  )}
                  <span
                    className={cn("relative z-10 grid h-5 w-5 place-items-center rounded-full border-2", s.status === "open" && "op-node")}
                    style={{
                      borderColor: s.status === "locked" ? "rgba(148,163,184,0.4)" : s.status === "cleared" ? "#34d399" : look.primary,
                      background: s.status === "cleared" ? "#34d399" : "#0a1120",
                    }}
                  >
                    {s.status === "cleared" && <CheckCircle2 className="h-3.5 w-3.5 text-[#0a1120]" />}
                  </span>
                  <span className={cn("mt-1.5 text-[11px] leading-tight", s.status === "locked" ? "text-slate-500" : "text-slate-200")}>{shortLabel(s.label)}</span>
                </li>
              ))}
            </ol>
          </div>
        </div>

        {/* Station cards */}
        <nav aria-label="Stations" className="mt-6 flex flex-col items-stretch gap-1 md:flex-row md:items-stretch md:gap-0 md:overflow-x-auto md:pb-2">
          {stations.map((s, i) => {
            const station = experience.stations[i];
            const prev = i > 0 ? stations[i - 1] : null;
            return (
              <React.Fragment key={s.id}>
                {i > 0 && (
                  <span aria-hidden className="grid shrink-0 place-items-center md:w-8">
                    <ChevronsRight className="hidden h-6 w-6 md:block" style={{ color: s.status === "locked" ? "#475569" : look.primary }} />
                    <ChevronsDown className="h-5 w-5 md:hidden" style={{ color: s.status === "locked" ? "#475569" : look.primary }} />
                  </span>
                )}
                <motion.button
                  onClick={() => tap(s)}
                  aria-disabled={s.status === "locked"}
                  aria-label={`Station ${i + 1}: ${s.label}. ${s.status === "locked" ? "Locked" : s.status === "cleared" ? "Cleared, replay" : "Start"}`}
                  whileHover={s.status === "locked" ? undefined : { y: -6 }}
                  whileTap={s.status === "locked" ? undefined : { scale: 0.97 }}
                  animate={denied === s.id ? { x: [0, -9, 9, -5, 5, 0] } : { x: 0 }}
                  transition={{ duration: 0.35 }}
                  className={cn(
                    "group relative flex min-w-0 flex-1 flex-col rounded-2xl border p-4 text-left md:min-w-[13.5rem]",
                    s.status === "open" ? "op-active border-transparent bg-[#081624]"
                      : s.status === "cleared" ? "border-emerald-400/35 bg-[#0a1a1a]/90 hover:border-emerald-400/70"
                        : s.boss ? "border-violet-400/25 bg-[#0e0b1d]/85" : "border-white/10 bg-[#0b1020]/85",
                  )}
                >
                  <span className="flex items-center justify-between">
                    <span className="text-[11px] font-bold uppercase tracking-[0.25em]" style={{ color: s.status === "locked" ? "#94a3b8" : look.primary }}>
                      Station {i + 1}{s.boss ? " · Final" : ""}
                    </span>
                    {s.status === "cleared" && <Stars n={s.stars} />}
                  </span>
                  <span className="mt-1 text-xl font-extrabold leading-tight text-white">{s.label}</span>
                  <span className="mt-2">
                    {s.status === "open" ? (
                      <span className="inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[11px] font-extrabold uppercase tracking-wider text-[#04121a]" style={{ background: look.primary }}>
                        <Play className="h-3 w-3 fill-current" /> {s.progress.startsWith("0/") ? "Active" : `In progress · ${s.progress}`}
                      </span>
                    ) : s.status === "cleared" ? (
                      <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-400/15 px-2.5 py-1 text-[11px] font-extrabold uppercase tracking-wider text-emerald-300">
                        <CheckCircle2 className="h-3 w-3" /> Cleared
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1.5 rounded-full bg-white/10 px-2.5 py-1 text-[11px] font-extrabold uppercase tracking-wider text-slate-300">
                        <Lock className="h-3 w-3" /> Locked
                      </span>
                    )}
                  </span>
                  <span className={cn(
                    "relative mt-3 block overflow-hidden rounded-xl border border-white/5 bg-[#060b16] transition duration-300",
                    s.status === "locked" ? "opacity-45 grayscale-[0.6]" : "group-hover:border-white/15",
                  )}>
                    <StationArt kind={s.building} className="block h-auto w-full transition-transform duration-500 group-hover:scale-[1.05]" />
                    {s.status === "locked" && (
                      <span className="absolute inset-0 grid place-items-center">
                        <span className="grid h-10 w-10 place-items-center rounded-full border border-white/15 bg-black/60"><Lock className="h-4 w-4 text-slate-300" /></span>
                      </span>
                    )}
                  </span>
                  <span className={cn("mt-3 flex-1 text-[13px] leading-snug", s.status === "locked" ? "text-slate-400" : "text-slate-200")}>
                    {station?.tagline}
                  </span>
                  {denied === s.id && prev && (
                    <span role="status" className="mt-2 text-xs font-semibold text-neon-amber">Clear {prev.label} first.</span>
                  )}
                  {s.status === "open" && (
                    <span className="mt-4 inline-flex items-center justify-center gap-2 rounded-xl py-2.5 text-sm font-extrabold text-[#04121a] transition group-hover:brightness-110" style={{ background: look.primary }}>
                      {s.progress.startsWith("0/") ? "Start station" : "Continue"} <ChevronRight className="h-4 w-4" />
                    </span>
                  )}
                  {s.status === "cleared" && (
                    <span className="mt-4 inline-flex items-center justify-center gap-2 rounded-xl border border-emerald-400/40 py-2 text-sm font-bold text-emerald-200">
                      <RotateCcw className="h-3.5 w-3.5" /> Replay for stars
                    </span>
                  )}
                </motion.button>
              </React.Fragment>
            );
          })}
        </nav>

        {/* 3D shield centrepiece: OperationView draws the scene behind this slot */}
        <div ref={onHeroSlot} className={cn("relative mt-1 hidden min-h-[13rem] flex-1 md:block", !has3d && "md:hidden")} aria-hidden />

        {/* Journey footer */}
        <div className="mt-2 flex flex-col gap-4 rounded-2xl border px-4 py-3 backdrop-blur md:flex-row md:items-center"
          style={{ borderColor: `${look.primary}55`, background: "rgba(8,16,30,0.82)" }}>
          <div className="flex flex-1 items-center gap-4">
            <Flag className="h-7 w-7 shrink-0" style={{ color: look.primary }} />
            <div>
              <p className="font-bold text-white">One mission, one route</p>
              <p className="text-sm text-slate-400">Clear each station in order to unlock the next one and reach {stations[stations.length - 1]?.label}.</p>
            </div>
          </div>
          <div className="flex flex-wrap gap-x-6 gap-y-2 text-sm text-slate-200 md:border-l md:border-white/10 md:pl-6">
            <span className="inline-flex items-center gap-2"><Layers className="h-4 w-4" style={{ color: look.primary }} /> {stations.length} stations</span>
            <span className="inline-flex items-center gap-2"><Timer className="h-4 w-4" style={{ color: look.primary }} /> {experience.estimate}</span>
            {difficulty && <span className="inline-flex items-center gap-2 capitalize"><Signal className="h-4 w-4" style={{ color: look.primary }} /> {difficulty}</span>}
          </div>
        </div>
      </div>
    </div>
  );
}

function Stars({ n }: { n: number }) {
  return (
    <span className="flex gap-0.5" aria-label={`${n} of 3 stars`}>
      {[0, 1, 2].map(i => <Star key={i} className={cn("h-3.5 w-3.5", i < n ? "fill-neon-amber text-neon-amber" : "text-slate-600")} />)}
    </span>
  );
}

// Card glow + the station-art motion. All of it stops for reduced motion.
const BOARD_CSS = `
.op-active { box-shadow: 0 0 0 2px var(--op-a), 0 0 38px -6px var(--op-a), inset 0 0 30px -18px var(--op-a); animation: op-glow 2.6s ease-in-out infinite; }
@keyframes op-glow { 50% { box-shadow: 0 0 0 2px var(--op-a), 0 0 56px -4px var(--op-a), inset 0 0 36px -16px var(--op-a); } }
.op-node { box-shadow: 0 0 0 0 var(--op-a); animation: op-ping 1.8s ease-out infinite; }
@keyframes op-ping { 0% { box-shadow: 0 0 0 0 color-mix(in srgb, var(--op-a) 70%, transparent); } 100% { box-shadow: 0 0 0 10px transparent; } }
.op-scan { animation: op-scan 2.8s ease-in-out infinite; }
@keyframes op-scan { 0%,100% { transform: translateY(0); } 50% { transform: translateY(48px); } }
.op-float { animation: op-float 4s ease-in-out infinite; }
@keyframes op-float { 50% { transform: translateY(-4px); } }
.op-belt { animation: op-belt 0.9s linear infinite; }
@keyframes op-belt { to { stroke-dashoffset: -14; } }
.op-ride { animation: op-ride 4.8s linear infinite; }
@keyframes op-ride { 0% { transform: translateX(-10px); opacity: 0; } 8% { opacity: 1; } 88% { opacity: 1; } 100% { transform: translateX(178px); opacity: 0; } }
.op-blink { animation: op-blink 1.4s steps(2, jump-none) infinite; }
@keyframes op-blink { 50% { opacity: 0.25; } }
.op-pulse { transform-box: fill-box; transform-origin: center; animation: op-pulse 1.6s ease-in-out infinite; }
@keyframes op-pulse { 50% { transform: scale(1.5); opacity: 0.6; } }
.op-spin { transform-box: view-box; animation: op-spin 4s linear infinite; }
@keyframes op-spin { to { transform: rotate(360deg); } }
.op-spin-slow { animation: op-spin 14s linear infinite; }
.op-countdown { animation: op-countdown 6s linear infinite; }
@keyframes op-countdown { from { stroke-dashoffset: 0; } to { stroke-dashoffset: 138; } }
@media (prefers-reduced-motion: reduce) {
  .op-active, .op-node, .op-scan, .op-float, .op-belt, .op-ride, .op-blink, .op-pulse, .op-spin, .op-spin-slow, .op-countdown { animation: none !important; }
}
`;
