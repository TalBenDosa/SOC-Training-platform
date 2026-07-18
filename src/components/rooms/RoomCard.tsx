"use client";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/Badge";
import { Lock, CheckCircle2, Clock, Zap, RotateCcw } from "lucide-react";
import type { Room } from "@/data/rooms";
import { ROOMS } from "@/data/rooms";

interface RoomCardProps {
  room: Room;
  progress: {
    completedTaskIds: string[];
    xpEarned: number;
    completedAt?: string;
  } | null;
  locked: boolean;
  onClick: () => void;
}

function difficultyBorder(d: Room["difficulty"]): string {
  switch (d) {
    case "beginner":     return "border-neon-green/40";
    case "intermediate": return "border-severity-medium/40";
    case "advanced":     return "border-severity-high/50";
  }
}

function difficultyBadgeClass(d: Room["difficulty"]): string {
  switch (d) {
    case "beginner":
      return "border-neon-green/40 bg-neon-green/10 text-neon-green";
    case "intermediate":
      return "border-severity-medium/40 bg-severity-medium/10 text-severity-medium";
    case "advanced":
      return "border-severity-high/40 bg-severity-high/10 text-severity-high";
  }
}

function iconBg(d: Room["difficulty"]): string {
  switch (d) {
    case "beginner":     return "bg-neon-green/10 border-neon-green/30";
    case "intermediate": return "bg-severity-medium/10 border-severity-medium/30";
    case "advanced":     return "bg-severity-high/10 border-severity-high/30";
  }
}

export function RoomCard({ room, progress, locked, onClick }: RoomCardProps) {
  const totalTasks      = room.tasks.length;
  const completedCount  = progress ? progress.completedTaskIds.length : 0;
  const isCompleted     = !!progress?.completedAt;
  // Every task was attempted but the room didn't reach the pass threshold —
  // RoomClient shows the retry screen; the card should say so at a glance.
  const needsRetry      = !isCompleted && completedCount === totalTasks && totalTasks > 0;
  const isStarted       = completedCount > 0 && !isCompleted && !needsRetry;

  return (
    <div
      role="button"
      tabIndex={locked ? -1 : 0}
      onClick={locked ? undefined : onClick}
      onKeyDown={e => { if (!locked && (e.key === "Enter" || e.key === " ")) onClick(); }}
      className={cn(
        "relative flex flex-col overflow-hidden rounded-lg border bg-bg-elevated/60 backdrop-blur-sm p-5",
        "transition-all duration-200",
        locked
          ? "cursor-not-allowed opacity-60 border-border"
          : isCompleted
            ? "cursor-pointer border-neon-green/60 shadow-[0_0_12px_0_rgba(57,255,20,0.12)] hover:shadow-[0_0_20px_0_rgba(57,255,20,0.2)] hover:border-neon-green/80"
            : cn(
                "cursor-pointer",
                difficultyBorder(room.difficulty),
                "hover:shadow-glow hover:border-cyber-500/60",
              ),
      )}
    >
      {/* Lock overlay */}
      {locked && (
        <div className="absolute inset-0 z-10 flex flex-col items-center justify-center gap-2 rounded-lg bg-bg/60 backdrop-blur-[2px]">
          <Lock className="h-8 w-8 text-slate-500" />
          <p className="text-center text-xs text-slate-500 px-4">
            Complete{" "}
            <span className="font-semibold text-slate-400">
              {room.prerequisites
                .map((id: string) => ROOMS.find(r => r.id === id)?.title ?? id)
                .join(", ")}
            </span>{" "}
            first
          </p>
        </div>
      )}

      {/* Header row */}
      <div className="flex items-start justify-between gap-3">
        <div className={cn(
          "flex h-12 w-12 shrink-0 items-center justify-center rounded-lg border text-2xl",
          iconBg(room.difficulty),
        )}>
          {room.icon}
        </div>
        <div className="flex items-center gap-2 flex-wrap justify-end">
          {isCompleted && (
            <span className="inline-flex items-center gap-1 rounded border border-neon-green/40 bg-neon-green/10 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider text-neon-green">
              <CheckCircle2 className="h-3 w-3" />
              Completed
            </span>
          )}
          {needsRetry && (
            <span className="inline-flex items-center gap-1 rounded border border-severity-critical/40 bg-severity-critical/10 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider text-severity-critical">
              <RotateCcw className="h-3 w-3" />
              Needs Retry
            </span>
          )}
          <span className={cn(
            "inline-flex items-center rounded border px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider",
            difficultyBadgeClass(room.difficulty),
          )}>
            {room.difficulty}
          </span>
        </div>
      </div>

      {/* Title + description */}
      <h3 className="mt-3 text-base font-bold text-white leading-snug">{room.title}</h3>
      <p className="mt-1 flex-1 text-sm text-slate-400 line-clamp-2 leading-relaxed">
        {room.description}
      </p>

      {/* Tags row */}
      <div className="mt-3 flex flex-wrap items-center gap-2">
        <Badge>{room.category}</Badge>
        <span className="inline-flex items-center gap-1 text-[11px] text-slate-500">
          <Clock className="h-3 w-3" />
          {room.estimatedMinutes} min
        </span>
        <span className="inline-flex items-center gap-1 text-[11px] text-slate-500">
          <Zap className="h-3 w-3 text-neon-amber" />
          {room.xp} XP
        </span>
      </div>

      {/* Progress bar (only when started but not complete) */}
      {isStarted && (
        <div className="mt-4">
          <div className="flex justify-between text-[10px] text-slate-500 mb-1">
            <span>{completedCount}/{totalTasks} tasks</span>
            <span>{Math.round((completedCount / totalTasks) * 100)}%</span>
          </div>
          <div className="h-1.5 w-full rounded-full bg-bg overflow-hidden">
            <div
              className="h-full rounded-full bg-cyber-500 transition-all duration-300"
              style={{ width: `${(completedCount / totalTasks) * 100}%` }}
            />
          </div>
        </div>
      )}

      {/* Completed full bar */}
      {isCompleted && (
        <div className="mt-4">
          <div className="flex justify-between text-[10px] text-slate-500 mb-1">
            <span>{totalTasks}/{totalTasks} tasks</span>
            <span className="text-neon-green">100%</span>
          </div>
          <div className="h-1.5 w-full rounded-full bg-neon-green/20 overflow-hidden">
            <div className="h-full w-full rounded-full bg-neon-green" />
          </div>
        </div>
      )}

      {/* Task count for not-started rooms */}
      {!isStarted && !isCompleted && (
        <div className="mt-4 text-[11px] text-slate-600">
          {totalTasks} task{totalTasks !== 1 ? "s" : ""}
        </div>
      )}
    </div>
  );
}
