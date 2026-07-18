"use client";
import React, { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Topbar } from "@/components/nav/Topbar";
import { Card } from "@/components/ui/Card";
import { RoomCard } from "@/components/rooms/RoomCard";
import { ROOMS } from "@/data/rooms";
import { BookOpen } from "lucide-react";

// ─── Types ─────────────────────────────────────────────────────────────────────
type RoomProgress = {
  completedTaskIds: string[];
  xpEarned: number;
  completedAt?: string;
};
type AllProgress = Record<string, RoomProgress>;

const CATEGORIES = ["All", "Foundations", "Log Analysis", "Threat Detection", "Cloud Security"] as const;
type Category = typeof CATEGORIES[number];

// ─── Page ──────────────────────────────────────────────────────────────────────
export default function RoomsPage() {
  const router   = useRouter();
  const [progress, setProgress] = useState<AllProgress>({});
  const [filter, setFilter]     = useState<Category>("All");

  useEffect(() => {
    try {
      const raw = localStorage.getItem("room_progress");
      if (raw) setProgress(JSON.parse(raw));
    } catch { /* storage blocked */ }
  }, []);

  // A room unlocks only once every prerequisite room has been PASSED
  // (completedAt set — a failed/retry-pending attempt does not count). Rooms
  // with no prerequisites (the beginner on-ramp) are always open. This makes
  // the authored prerequisite chains actually shape the learner's path — and
  // makes the landing page's "prerequisites unlock in order" promise true.
  function isLocked(roomId: string): boolean {
    const room = ROOMS.find(r => r.id === roomId);
    if (!room || room.prerequisites.length === 0) return false;
    return !room.prerequisites.every(prereqId => !!progress[prereqId]?.completedAt);
  }

  const filtered = ROOMS.filter(r => filter === "All" || r.category === filter);

  const totalCompleted = ROOMS.filter(r => !!progress[r.id]?.completedAt).length;
  const totalXp        = Object.values(progress).reduce((sum, p) => sum + (p.xpEarned ?? 0), 0);

  // The one room to point a learner at. Rank unlocked, not-yet-passed rooms by
  // PREREQUISITE DEPTH (how deep in the chain they sit), not file order — so a
  // shallow foundational room (e.g. analyst-mindset, gated only on soc-structure)
  // surfaces before dozens of intermediate/advanced rooms that merely appear
  // earlier in the array. Prefer a room the learner already started ("Continue")
  // over a brand-new one ("Start here"); tie-break by difficulty then file order.
  const depthMemo = new Map<string, number>();
  function prereqDepth(roomId: string): number {
    const room = ROOMS.find(r => r.id === roomId);
    if (!room || room.prerequisites.length === 0) return 0;
    if (depthMemo.has(roomId)) return depthMemo.get(roomId)!;
    depthMemo.set(roomId, 0); // cycle guard
    const d = 1 + Math.max(...room.prerequisites.map(prereqDepth));
    depthMemo.set(roomId, d);
    return d;
  }
  const DIFF_RANK: Record<string, number> = { beginner: 0, intermediate: 1, advanced: 2 };
  const available = ROOMS.filter(r => !progress[r.id]?.completedAt && !isLocked(r.id));
  const started   = available.filter(r => (progress[r.id]?.completedTaskIds?.length ?? 0) > 0);
  const recommendedRoom = (started.length > 0 ? started : available)
    .slice()
    .sort((a, b) =>
      (prereqDepth(a.id) - prereqDepth(b.id)) ||
      ((DIFF_RANK[a.difficulty] ?? 1) - (DIFF_RANK[b.difficulty] ?? 1)) ||
      (ROOMS.indexOf(a) - ROOMS.indexOf(b)),
    )[0] ?? null;
  const recommendedStarted = recommendedRoom
    ? (progress[recommendedRoom.id]?.completedTaskIds?.length ?? 0) > 0
    : false;

  return (
    <div>
      <Topbar
        title="Learning Rooms"
        subtitle="Step-by-step cybersecurity training"
      />

      <div className="container mx-auto max-w-[1600px] px-6 py-6 space-y-6">

        {/* Hero card */}
        <Card className="border-cyber-500/30 bg-gradient-to-br from-cyber-500/5 to-neon-purple/5">
          <div className="flex items-start gap-4">
            <div className="rounded-md border border-cyber-500/40 bg-cyber-500/10 p-3 text-cyber-300">
              <BookOpen className="h-5 w-5" />
            </div>
            <div className="flex-1">
              <h3 className="text-lg font-bold text-white">How Learning Rooms work</h3>
              <p className="mt-1 max-w-3xl text-sm text-slate-300">
                Each room is a structured training module combining reading material, multiple-choice questions,
                real SIEM log analysis, and flag challenges. Complete tasks in order to earn XP and unlock
                advanced rooms. Your progress is saved locally as you go.
              </p>
              <div className="mt-3 flex flex-wrap gap-2 text-[11px] text-slate-400">
                <span>· Self-paced</span>
                <span>· Realistic log data</span>
                <span>· XP rewards</span>
                <span>· Progressive difficulty</span>
              </div>
            </div>
            {/* Progress summary */}
            <div className="hidden lg:flex flex-col items-end gap-1 shrink-0">
              <p className="text-[11px] text-slate-500 uppercase tracking-wider font-semibold">Your Progress</p>
              <p className="text-2xl font-bold font-mono text-white">
                {totalCompleted}/{ROOMS.length}
              </p>
              <p className="text-[11px] text-slate-400">rooms complete</p>
              <p className="mt-1 text-sm font-semibold text-neon-amber font-mono">+{totalXp} XP</p>
            </div>
          </div>
        </Card>

        {/* Start Here / Continue — makes the beginner's first choice for them */}
        {recommendedRoom && (
          <button
            onClick={() => router.push(`/rooms/${recommendedRoom.id}`)}
            className="group flex w-full items-center gap-4 rounded-xl border border-neon-green/40 bg-gradient-to-r from-neon-green/10 to-transparent px-5 py-4 text-left transition hover:border-neon-green/70 hover:from-neon-green/15"
          >
            <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-lg border border-neon-green/40 bg-neon-green/10 text-2xl">
              {recommendedRoom.icon}
            </div>
            <div className="min-w-0 flex-1">
              <p className="text-[10px] font-bold uppercase tracking-[0.2em] text-neon-green">
                {recommendedStarted ? "Continue where you left off" : "Start here"}
              </p>
              <p className="truncate text-base font-bold text-white">{recommendedRoom.title}</p>
              <p className="truncate text-xs text-slate-400">{recommendedRoom.description}</p>
            </div>
            <span className="shrink-0 rounded-lg bg-neon-green/15 px-4 py-2 text-sm font-bold text-neon-green transition group-hover:bg-neon-green/25">
              {recommendedStarted ? "Continue →" : "Begin →"}
            </span>
          </button>
        )}

        {/* Filter buttons */}
        <div className="flex flex-wrap gap-2">
          {CATEGORIES.map(cat => (
            <button
              key={cat}
              onClick={() => setFilter(cat)}
              className={
                cat === filter
                  ? "rounded-md border border-cyber-500/60 bg-cyber-500/15 px-3 py-1.5 text-xs font-semibold text-cyber-300 transition-colors"
                  : "rounded-md border border-border/50 bg-bg-elevated/50 px-3 py-1.5 text-xs font-semibold text-slate-400 hover:border-cyber-500/30 hover:text-slate-200 transition-colors"
              }
            >
              {cat}
            </button>
          ))}
          <span className="ml-auto self-center text-[11px] text-slate-600">
            {filtered.length} room{filtered.length !== 1 ? "s" : ""}
          </span>
        </div>

        {/* Room grid */}
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
          {filtered.map(room => (
            <RoomCard
              key={room.id}
              room={room}
              progress={progress[room.id] ?? null}
              locked={isLocked(room.id)}
              onClick={() => router.push(`/rooms/${room.id}`)}
            />
          ))}
        </div>

        {filtered.length === 0 && (
          <div className="flex flex-col items-center justify-center rounded border border-border/40 bg-bg-elevated py-16 text-center">
            <BookOpen className="h-12 w-12 text-slate-600 mb-4" />
            <p className="text-sm text-slate-400">No rooms in this category yet.</p>
          </div>
        )}
      </div>
    </div>
  );
}
