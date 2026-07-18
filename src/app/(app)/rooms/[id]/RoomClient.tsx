"use client";
import React, { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/Button";
import { TaskPlayer } from "@/components/rooms/TaskPlayer";
import {
  ArrowLeft, BookOpen, CheckCircle2, Circle, ChevronRight, ChevronLeft,
  Trophy, Zap, FileText, HelpCircle, Search, Flag, RotateCcw, Terminal,
} from "lucide-react";
import type { Room, RoomTask } from "@/data/rooms";
import type { TaskTelemetryEntry } from "@/lib/useTaskTelemetry";
import { addTotalXp } from "@/lib/storage/progress";

// A room must score at least this fraction of its gradeable XP to count as
// passed. Below this, the student must retry the room from the start — a
// completed-but-failed room does not appear as "done" on /rooms or unlock
// anything that depends on its prerequisites.
export const ROOM_PASS_THRESHOLD = 0.65;

// ─── localStorage helpers ───────────────────────────────────────────────────────
type RoomProgressEntry = {
  completedTaskIds: string[];
  xpEarned: number;
  completedAt?: string;
  /** Per-task XP earned, so a near-miss can replay only the tasks scored below
   * full credit instead of wiping the whole room. Additive/optional. */
  perTaskXp?: Record<string, number>;
  /** Phase-1 behavioral telemetry — see ANALYST_TELEMETRY_PLAN.md. Additive
   * and optional; older saved progress simply lacks this field. */
  telemetry?: TaskTelemetryEntry[];
};
type AllProgress = Record<string, RoomProgressEntry>;

function loadProgress(): AllProgress {
  try {
    return JSON.parse(localStorage.getItem("room_progress") ?? "{}");
  } catch { return {}; }
}

function saveProgress(data: AllProgress) {
  try { localStorage.setItem("room_progress", JSON.stringify(data)); } catch { /* ignore */ }
}

// Delegates to the storage facade (src/lib/storage/progress.ts) — the single
// seam that Phase 1 repoints from localStorage to the server DB. Same key, same
// floor-at-0 semantics as before.
function addXpToTotal(xp: number) {
  addTotalXp(xp);
}

/** Max XP a room can award — every gradeable task's xp, summed. Reading tasks
 * carry no xp field and are correctly excluded: they're not gradeable, so they
 * don't count toward the pass/fail score either. */
/** Max XP a single task can award (0 for non-gradeable reading tasks). */
function taskMaxXp(task: RoomTask): number {
  switch (task.type) {
    case "reading":      return 0;
    case "log_analysis": return task.questions.reduce((s, q) => s + q.xp, 0);
    default:              return task.xp;
  }
}

function maxRoomXp(room: Room): number {
  return room.tasks.reduce((sum, t) => sum + taskMaxXp(t), 0);
}

// ─── Task icon by type ──────────────────────────────────────────────────────────
function TaskIcon({ type, className }: { type: RoomTask["type"]; className?: string }) {
  const cls = cn("h-3.5 w-3.5", className);
  switch (type) {
    case "reading":      return <BookOpen className={cls} />;
    case "question":     return <HelpCircle className={cls} />;
    case "log_analysis": return <Search className={cls} />;
    case "flag":         return <Flag className={cls} />;
    case "query_fill":   return <Terminal className={cls} />;
    default:             return <FileText className={cls} />;
  }
}

// ─── RoomClient ─────────────────────────────────────────────────────────────────
interface RoomClientProps {
  room: Room;
}

export function RoomClient({ room }: RoomClientProps) {
  const router = useRouter();

  const [currentTaskIndex, setCurrentTaskIndex] = useState(0);
  const [completedTaskIds, setCompletedTaskIds] = useState<Set<string>>(new Set());
  const [totalXpEarned, setTotalXpEarned]       = useState(0);
  const [perTaskXp, setPerTaskXp]               = useState<Record<string, number>>({});
  const [telemetry, setTelemetry]               = useState<TaskTelemetryEntry[]>([]);
  const [showCompletion, setShowCompletion]      = useState(false);
  const [showFailure, setShowFailure]            = useState(false);
  const [mounted, setMounted]                   = useState(false);

  const maxXp   = maxRoomXp(room);
  const scorePct = maxXp > 0 ? Math.round((totalXpEarned / maxXp) * 100) : 100;

  // Load persisted progress on mount
  useEffect(() => {
    const all     = loadProgress();
    const entry   = all[room.id];
    if (entry) {
      const ids = new Set<string>(entry.completedTaskIds);
      setCompletedTaskIds(ids);
      setTotalXpEarned(entry.xpEarned);
      setPerTaskXp(entry.perTaskXp ?? {});
      setTelemetry(entry.telemetry ?? []);
      if (entry.completedAt) {
        setShowCompletion(true);
      } else if (ids.size === room.tasks.length) {
        // Every task was done in a prior attempt but it never earned
        // completedAt. Re-derive pass/fail from the actual score rather than
        // assuming — completedAt is only missing when a prior run failed,
        // but don't trust that invariant blindly.
        const max = maxRoomXp(room);
        const passed = max === 0 || (entry.xpEarned / max) >= ROOM_PASS_THRESHOLD;
        if (passed) setShowCompletion(true); else setShowFailure(true);
      } else {
        // Resume at first incomplete task
        const firstIncomplete = room.tasks.findIndex(t => !ids.has(t.id));
        setCurrentTaskIndex(firstIncomplete === -1 ? room.tasks.length - 1 : firstIncomplete);
      }
    }
    setMounted(true);
  }, [room]);

  const persistProgress = useCallback((ids: Set<string>, xp: number, xpMap: Record<string, number>, taskTelemetry: TaskTelemetryEntry[], completedAt?: string) => {
    const all = loadProgress();
    all[room.id] = {
      completedTaskIds: Array.from(ids),
      xpEarned: xp,
      perTaskXp: xpMap,
      telemetry: taskTelemetry,
      ...(completedAt ? { completedAt } : {}),
    };
    saveProgress(all);
  }, [room.id]);

  // Gradeable tasks scored below full credit — the only ones a near-miss replays.
  const missedTasks = room.tasks.filter(
    t => taskMaxXp(t) > 0 && (perTaskXp[t.id] ?? 0) < taskMaxXp(t),
  );

  // Review only the tasks scored below full credit. Earned XP and correct
  // answers are kept; the missed tasks are re-opened in place. When they're all
  // re-answered, the pass check re-runs — no full-room wipe, no XP clawback.
  function handleReviewMissed() {
    const missedIds = new Set(missedTasks.map(t => t.id));
    const remaining = new Set(Array.from(completedTaskIds).filter(id => !missedIds.has(id)));
    setCompletedTaskIds(remaining);
    const firstMissed = room.tasks.findIndex(t => missedIds.has(t.id));
    setCurrentTaskIndex(firstMissed === -1 ? 0 : firstMissed);
    setShowFailure(false);
    setShowCompletion(false);
    persistProgress(remaining, totalXpEarned, perTaskXp, telemetry);
  }

  function handleTaskComplete(xpEarned: number, taskTelemetry?: TaskTelemetryEntry) {
    const task     = room.tasks[currentTaskIndex];
    const newIds   = new Set(completedTaskIds);
    newIds.add(task.id);

    // Delta accounting: a task can be re-attempted (review-missed flow), so only
    // credit the IMPROVEMENT over this task's previous best to soc_total_xp —
    // never double-count, never claw back what was already earned.
    const prevXp   = perTaskXp[task.id] ?? 0;
    const bestXp   = Math.max(prevXp, xpEarned);
    const delta    = bestXp - prevXp;
    const newXpMap = { ...perTaskXp, [task.id]: bestXp };
    const newXp    = Object.values(newXpMap).reduce((s, v) => s + v, 0);
    const newTelemetry = taskTelemetry ? [...telemetry, taskTelemetry] : telemetry;

    setCompletedTaskIds(newIds);
    setPerTaskXp(newXpMap);
    setTotalXpEarned(newXp);
    setTelemetry(newTelemetry);
    if (delta > 0) addXpToTotal(delta);

    const allDone = newIds.size === room.tasks.length;
    if (allDone) {
      const passed = maxXp === 0 || (newXp / maxXp) >= ROOM_PASS_THRESHOLD;
      if (passed) {
        const completedAt = new Date().toISOString();
        persistProgress(newIds, newXp, newXpMap, newTelemetry, completedAt);
        setShowCompletion(true);
      } else {
        // Near-miss: KEEP the earned XP and all correct answers, persist the
        // progress WITHOUT completedAt (room stays "in progress", so it doesn't
        // unlock prerequisites yet), and offer to replay only the missed tasks.
        persistProgress(newIds, newXp, newXpMap, newTelemetry);
        setShowFailure(true);
      }
    } else {
      persistProgress(newIds, newXp, newXpMap, newTelemetry);
      // Advance to the next still-incomplete task (linear on first pass; jumps
      // between missed tasks during a review).
      const next = room.tasks.findIndex(t => !newIds.has(t.id));
      setCurrentTaskIndex(next === -1 ? currentTaskIndex : next);
    }
  }

  const completedCount = completedTaskIds.size;
  const totalTasks     = room.tasks.length;
  const currentTask    = room.tasks[currentTaskIndex];

  // If the current task is a flag, check if the immediately preceding task was a log_analysis
  // and surface its event so FlagPlayer can keep the log visible.
  const prevTask = currentTaskIndex > 0 ? room.tasks[currentTaskIndex - 1] : undefined;
  const prevLogEvent = currentTask.type === "flag" && prevTask?.type === "log_analysis"
    ? prevTask.event
    : undefined;

  if (!mounted) return null;

  // ─── Completion modal ───────────────────────────────────────────────────────
  if (showCompletion) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-bg px-6">
        <div className="w-full max-w-md rounded-xl border border-neon-green/40 bg-bg-elevated shadow-[0_0_40px_0_rgba(57,255,20,0.12)] p-8 text-center space-y-5">
          <div className="flex justify-center">
            <div className="flex h-20 w-20 items-center justify-center rounded-full border-2 border-neon-green/50 bg-neon-green/10">
              <Trophy className="h-10 w-10 text-neon-green" />
            </div>
          </div>
          <div>
            <h2 className="text-2xl font-bold text-white">Room Complete!</h2>
            <p className="text-slate-400 text-sm mt-1">{room.title}</p>
          </div>
          <div className="rounded-lg border border-border bg-bg px-6 py-4">
            <p className="text-[11px] uppercase tracking-wider text-slate-500 font-semibold mb-1">Total XP Earned</p>
            <p className="text-3xl font-bold font-mono text-neon-amber">+{totalXpEarned}</p>
            <p className="text-[11px] text-slate-600 mt-1">{totalTasks} tasks completed</p>
          </div>
          <div className="rounded-lg border border-neon-green/30 bg-neon-green/5 px-6 py-3">
            <p className="text-[11px] uppercase tracking-wider text-slate-500 font-semibold mb-1">Score</p>
            <p className="text-xl font-bold text-neon-green">{scorePct}%</p>
            <p className="text-[10px] text-slate-600 mt-0.5">Passed — {Math.round(ROOM_PASS_THRESHOLD * 100)}% required</p>
          </div>
          <div className="flex flex-col gap-2">
            <Button variant="primary" size="lg" className="w-full" onClick={() => router.push("/rooms")}>
              <ArrowLeft className="h-4 w-4" />
              Back to Rooms
            </Button>
          </div>
        </div>
      </div>
    );
  }

  // ─── Almost-there screen — below pass threshold, review just the missed tasks ─
  if (showFailure) {
    const missedCount = missedTasks.length;
    return (
      <div className="flex min-h-screen items-center justify-center bg-bg px-6">
        <div className="w-full max-w-md rounded-xl border border-neon-amber/40 bg-bg-elevated shadow-[0_0_40px_0_rgba(255,176,32,0.10)] p-8 text-center space-y-5">
          <div className="flex justify-center">
            <div className="flex h-20 w-20 items-center justify-center rounded-full border-2 border-neon-amber/50 bg-neon-amber/10">
              <RotateCcw className="h-9 w-9 text-neon-amber" />
            </div>
          </div>
          <div>
            <h2 className="text-2xl font-bold text-white">Almost There</h2>
            <p className="text-slate-400 text-sm mt-1">{room.title}</p>
          </div>
          <div className="rounded-lg border border-border bg-bg px-6 py-4">
            <p className="text-[11px] uppercase tracking-wider text-slate-500 font-semibold mb-1">Your Score</p>
            <p className="text-3xl font-bold font-mono text-neon-amber">{scorePct}%</p>
            <p className="text-[11px] text-slate-500 mt-1">
              {Math.round(ROOM_PASS_THRESHOLD * 100)}% needed to pass — you keep the {totalXpEarned} XP you've earned
            </p>
          </div>
          <p className="text-sm text-slate-300 leading-relaxed">
            You've got most of this room. {missedCount === 1 ? "One task" : `${missedCount} tasks`} to revisit — just{" "}
            {missedCount === 1 ? "that one" : "those"}, not the whole room. Your correct answers and readings stay done.
          </p>
          <div className="flex flex-col gap-2">
            <Button variant="primary" size="lg" className="w-full" onClick={handleReviewMissed}>
              <RotateCcw className="h-4 w-4" />
              Review {missedCount === 1 ? "1 Task" : `${missedCount} Tasks`}
            </Button>
            <Button variant="outline" size="lg" className="w-full" onClick={() => router.push("/rooms")}>
              <ArrowLeft className="h-4 w-4" />
              Back to Rooms
            </Button>
          </div>
        </div>
      </div>
    );
  }

  // ─── Main layout ────────────────────────────────────────────────────────────
  return (
    <div className="flex min-h-screen bg-bg">

      {/* ── Left Sidebar ─────────────────────────────────────────────────── */}
      <aside className="hidden lg:flex w-64 shrink-0 flex-col border-r border-border bg-bg-elevated/40">
        {/* Room header */}
        <div className="p-4 border-b border-border">
          <button
            onClick={() => router.push("/rooms")}
            className="inline-flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors mb-3"
          >
            <ArrowLeft className="h-3.5 w-3.5" />
            All Rooms
          </button>
          <h2 className="text-sm font-bold text-white leading-snug">{room.title}</h2>
          <p className="text-[11px] text-slate-500 mt-0.5">{room.difficulty} · {room.category}</p>
        </div>

        {/* Task list */}
        <nav className="flex-1 overflow-y-auto p-3 space-y-0.5">
          {room.tasks.map((task, idx) => {
            const done    = completedTaskIds.has(task.id);
            const current = idx === currentTaskIndex;
            return (
              <button
                key={task.id}
                onClick={() => done || current ? setCurrentTaskIndex(idx) : undefined}
                className={cn(
                  "flex w-full items-center gap-2.5 rounded-md px-2.5 py-2 text-left text-xs transition-colors",
                  current
                    ? "bg-cyber-500/10 text-white"
                    : done
                      ? "text-slate-400 hover:bg-bg-hover hover:text-slate-200 cursor-pointer"
                      : "text-slate-600 cursor-default",
                )}
              >
                {/* Status icon */}
                <span className="shrink-0">
                  {done ? (
                    <CheckCircle2 className="h-3.5 w-3.5 text-neon-green" />
                  ) : current ? (
                    <ChevronRight className="h-3.5 w-3.5 text-cyber-300" />
                  ) : (
                    <Circle className="h-3.5 w-3.5 text-slate-600" />
                  )}
                </span>
                {/* Task type icon */}
                <TaskIcon type={task.type} className={current ? "text-cyber-300" : done ? "text-slate-500" : "text-slate-700"} />
                {/* Title — use heading for reading tasks, question text for others */}
                <span className="truncate">
                  {task.type === "reading"
                    ? task.heading
                    : task.type === "log_analysis"
                      ? task.heading
                      : task.type === "analyst_choice"
                        ? task.heading
                        : task.type === "matching"
                          ? task.heading
                          : task.type === "ordering"
                            ? task.heading
                            : task.type === "query_fill"
                              ? task.heading
                              : task.type === "question"
                                ? task.question.slice(0, 40) + (task.question.length > 40 ? "…" : "")
                                : task.prompt.split("\n")[0].slice(0, 40)}
                </span>
              </button>
            );
          })}
        </nav>

        {/* Progress + XP */}
        <div className="p-4 border-t border-border space-y-3">
          <div>
            <div className="flex justify-between text-[10px] text-slate-500 mb-1.5">
              <span>{completedCount}/{totalTasks} complete</span>
              <span>{Math.round((completedCount / totalTasks) * 100)}%</span>
            </div>
            <div className="h-1.5 w-full rounded-full bg-bg overflow-hidden">
              <div
                className="h-full rounded-full bg-cyber-500 transition-all duration-500"
                style={{ width: `${(completedCount / totalTasks) * 100}%` }}
              />
            </div>
          </div>
          <div className="flex items-center gap-1.5 text-xs text-slate-400">
            <Zap className="h-3.5 w-3.5 text-neon-amber" />
            <span className="font-mono font-semibold text-neon-amber">+{totalXpEarned}</span>
            <span className="text-slate-600">XP earned</span>
          </div>
        </div>
      </aside>

      {/* ── Main content ─────────────────────────────────────────────────── */}
      <main className="flex-1 overflow-y-auto">
        {/* Mobile back link + progress */}
        <div className="lg:hidden flex items-center justify-between border-b border-border px-4 py-3">
          <button
            onClick={() => router.push("/rooms")}
            className="inline-flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors"
          >
            <ArrowLeft className="h-3.5 w-3.5" />
            Back
          </button>
          <span className="text-[11px] text-slate-500">
            Task {currentTaskIndex + 1} of {totalTasks}
          </span>
        </div>

        <div className="max-w-3xl mx-auto px-6 py-8">
          {/* Task counter */}
          <div className="flex items-center gap-3 mb-6">
            {currentTaskIndex > 0 && (
              <button
                onClick={() => setCurrentTaskIndex(i => i - 1)}
                className="inline-flex items-center gap-1 text-[11px] text-slate-400 hover:text-slate-200 transition-colors"
              >
                <ChevronLeft className="h-3.5 w-3.5" />
                Back
              </button>
            )}
            <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
              Task {currentTaskIndex + 1} of {totalTasks}
            </span>
            <TaskIcon type={currentTask.type} className="text-slate-500" />
            <span className="text-[11px] text-slate-600 capitalize">{currentTask.type.replace("_", " ")}</span>
          </div>

          {/* Task player */}
          <TaskPlayer
            key={currentTask.id}
            task={currentTask}
            onComplete={handleTaskComplete}
            isCompleted={completedTaskIds.has(currentTask.id)}
            prevLogEvent={prevLogEvent}
          />
        </div>
      </main>
    </div>
  );
}
