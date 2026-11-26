"use client";
/** Small shared pieces of the Recommended Tracks pages. */
import { BookOpen, GraduationCap, DoorOpen, ClipboardList, Target, LayoutDashboard, CheckCircle2, CircleDashed, Circle } from "lucide-react";
import { cn } from "@/lib/utils";
import type { TrackLevel, TrackStepKind } from "@/data/recommendedTracks";
import type { StepStatus } from "@/lib/tracks/progress";

export const LEVEL_LABEL: Record<TrackLevel, string> = {
  beginner: "Beginner", intermediate: "Intermediate", advanced: "Advanced",
};

// Same hues as the difficulty badges on lessons and rooms.
const LEVEL_CLS: Record<TrackLevel, string> = {
  beginner: "border-sky-500/40 bg-sky-500/15 text-sky-300",
  intermediate: "border-yellow-500/40 bg-yellow-500/15 text-yellow-300",
  advanced: "border-orange-500/40 bg-orange-500/15 text-orange-300",
};

export function LevelChip({ level, rank, specialty }: { level: TrackLevel; rank: number; specialty?: string }) {
  return (
    <span className={cn("inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[11px] font-semibold uppercase tracking-wider", specialty ? "border-violet-500/40 bg-violet-500/15 text-violet-300" : LEVEL_CLS[level])}>
      {specialty ? `Specialist track · ${specialty}` : `Level ${rank} · ${LEVEL_LABEL[level]}`}
    </span>
  );
}

export const KIND_ICON: Record<TrackStepKind, typeof BookOpen> = {
  read: BookOpen,
  lesson: GraduationCap,
  room: DoorOpen,
  quiz: ClipboardList,
  scenario: Target,
  shift: LayoutDashboard,
};

export function ProgressBar({ pct, label, className }: { pct: number; label: string; className?: string }) {
  const v = Math.max(0, Math.min(100, pct));
  return (
    <div
      role="progressbar"
      aria-label={label}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={v}
      className={cn("h-1.5 w-full overflow-hidden rounded-full bg-slate-700/50", className)}
    >
      <div
        className={cn("h-full rounded-full transition-[width] duration-500", v === 100 ? "bg-neon-green" : "bg-gradient-to-r from-cyber-600 to-cyber-400")}
        style={{ width: `${v}%` }}
      />
    </div>
  );
}

export function StatusIcon({ status, className }: { status: StepStatus; className?: string }) {
  if (status === "done") return <CheckCircle2 aria-hidden className={cn("h-5 w-5 text-neon-green", className)} />;
  if (status === "started") return <CircleDashed aria-hidden className={cn("h-5 w-5 text-amber-300", className)} />;
  return <Circle aria-hidden className={cn("h-5 w-5 text-slate-500", className)} />;
}

export const STATUS_TEXT: Record<StepStatus, string> = { done: "Done", started: "In progress", todo: "Not started" };
