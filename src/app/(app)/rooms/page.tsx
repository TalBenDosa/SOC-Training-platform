"use client";
import React, { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Topbar } from "@/components/nav/Topbar";
import { Card } from "@/components/ui/Card";
import { RoomCard } from "@/components/rooms/RoomCard";
import { ROOMS_META, type RoomMeta } from "@/data/roomsMeta";
import { getRoomProgress } from "@/lib/storage/progress";
import { isRoomLocked, recommendNextRoom, orderRoomsForLearning } from "@/lib/rooms/recommend";
import { MyLearningPlan } from "@/components/plans/MyLearningPlan";
import { useAssignedItems } from "@/lib/plans/useAssigned";
import { useBranding } from "@/lib/auth/useBranding";
import { fetchOrgRoomMetas } from "@/lib/content/publicContent";
import { useProgressSnapshot } from "@/lib/storage/useProgressSnapshot";
import { useAuth } from "@/lib/auth/AuthContext";
import { BookOpen, Loader2 } from "lucide-react";

// ─── Types ─────────────────────────────────────────────────────────────────────
type RoomProgress = {
  completedTaskIds: string[];
  xpEarned: number;
  completedAt?: string;
};
type AllProgress = Record<string, RoomProgress>;

// The three levels, in learning order. A room's level is never below its prerequisites'.
const LEVELS = [
  { key: "beginner", label: "Beginner", hint: "Start here: the foundations every analyst needs." },
  { key: "intermediate", label: "Intermediate", hint: "Core SOC work: logs, tools, triage and investigation." },
  { key: "advanced", label: "Advanced", hint: "Deep dives, hunting and detection engineering." },
] as const;
type Level = typeof LEVELS[number]["key"];

const CHIP_ON  = "rounded-md border border-cyber-500/60 bg-cyber-500/15 px-3 py-1.5 text-xs font-semibold text-cyber-300 transition-colors";
const CHIP_OFF = "rounded-md border border-border/50 bg-bg-elevated/50 px-3 py-1.5 text-xs font-semibold text-slate-400 hover:border-cyber-500/30 hover:text-slate-200 transition-colors";

// ─── Page ──────────────────────────────────────────────────────────────────────
export default function RoomsPage() {
  const router   = useRouter();
  const { roomsLocked } = useBranding();
  const [progress, setProgress] = useState<AllProgress>({});
  const [filter, setFilter]     = useState<string>("All");
  const [level, setLevel]       = useState<Level | "all">("all");
  const [orgRooms, setOrgRooms] = useState<RoomMeta[]>([]);
  // "Assigned" chips — one cached request for the whole grid; empty for solo learners.
  const assigned = useAssignedItems();

  // #1: this page used to read room progress ONCE on mount — before the
  // signed-in learner's remote backend had hydrated — so it rendered this
  // browser's (empty) guest data: "0/108 rooms", everything locked, while the
  // same account showed rooms completed elsewhere. Read only once the source is
  // authoritative, and re-read on every change signal.
  const { ready, version, slow } = useProgressSnapshot();
  const { user } = useAuth();

  useEffect(() => {
    if (!ready) return;
    // Read via the storage facade (Phase-1 seam): DB-backed room_progress for
    // signed-in users, localStorage for guests — same key. Keeps the rooms-list
    // completion/unlock state consistent with what RoomClient now writes.
    try {
      setProgress(getRoomProgress() as AllProgress);
    } catch { /* storage blocked */ }
  }, [ready, version]);

  useEffect(() => {
    // Per-org authored rooms (migration 0043) — RLS returns only this org's
    // published rooms; they merge in alongside the static built-ins.
    fetchOrgRoomMetas().then(rooms => setOrgRooms(rooms as unknown as RoomMeta[])).catch(() => {});
  }, []);

  // Built-in rooms + this org's authored rooms (org rooms appended).
  const allRooms: RoomMeta[] = [...ROOMS_META, ...orgRooms];

  // Prerequisite gating + "recommended next" now come from the SHARED
  // src/lib/rooms/recommend.ts, so the rooms list and the Room-Complete screen
  // can never disagree about what is locked or what to do next.
  // Rooms are open unless the college admin locked them behind prerequisites (migration 0102).
  const isLocked = (roomId: string) => roomsLocked ? isRoomLocked(roomId, progress) : false;
  // Open rooms still name the prerequisites not passed yet, so the path stays gradual.
  const titleOf = (id: string) => allRooms.find(r => r.id === id)?.title ?? id;
  const unmetPrereqs = (room: RoomMeta) => room.prerequisites.filter(p => !progress[p]?.completedAt).map(titleOf);

  // Every category that has rooms (the old fixed list hid most of them behind "All").
  const categories = ["All", ...Array.from(new Set(allRooms.map(r => r.category))).sort()];
  const filtered = orderRoomsForLearning(allRooms).filter(r =>
    (filter === "All" || r.category === filter) && (level === "all" || r.difficulty === level));

  const totalCompleted = allRooms.filter(r => !!progress[r.id]?.completedAt).length;
  const totalXp        = Object.values(progress).reduce((sum, p) => sum + (p.xpEarned ?? 0), 0);

  const rec = recommendNextRoom(progress);
  const recommendedRoom = rec?.room ?? null;
  const recommendedStarted = rec?.started ?? false;

  return (
    <div>
      <Topbar
        title="Learning Rooms"
        subtitle="Step-by-step cybersecurity training"
      />

      <div className="container mx-auto max-w-[1600px] px-6 py-6 space-y-6">

        {/* The learning plan set by the learner's organisation (personal, group
            and org-wide plans). Renders nothing for solo learners. Above the
            hero deliberately: if someone was told to do specific work, that
            outranks the generic "how rooms work" explainer. */}
        <MyLearningPlan />

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
                real SIEM log analysis, and flag challenges. Rooms are grouped by level and listed in learning
                order, each building on the ones before it.{" "}
                {roomsLocked
                  ? "Your college unlocks each room once you pass its prerequisites. "
                  : "Every room is open, so you can start anywhere; the recommended room keeps you on the gradual path. "}
                {user
                  ? "Your progress is saved to your account as you go, on every device."
                  : "Your progress is saved in this browser as you go — sign in to keep it on your account."}
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
              <p className="text-[11px] text-slate-400 uppercase tracking-wider font-semibold">Your Progress</p>
              {ready ? (
                <>
                  <p className="text-2xl font-bold font-mono text-white">
                    {totalCompleted}/{allRooms.length}
                  </p>
                  <p className="text-[11px] text-slate-400">rooms complete</p>
                  <p className="mt-1 text-sm font-semibold text-neon-amber font-mono">+{totalXp} XP</p>
                </>
              ) : (
                <p className="flex items-center gap-1.5 text-xs text-slate-400">
                  <Loader2 className="h-3.5 w-3.5 animate-spin" /> Loading…
                </p>
              )}
            </div>
          </div>
        </Card>

        {/* Start Here / Continue — makes the beginner's first choice for them */}
        {ready && recommendedRoom && (
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

        {/* Level + category filters */}
        <div className="space-y-2">
          <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Level">
            {([["all", "All levels"], ...LEVELS.map(l => [l.key, l.label])] as [Level | "all", string][]).map(([k, lbl]) => (
              <button key={k} onClick={() => setLevel(k)} aria-pressed={k === level}
                className={k === level ? CHIP_ON : CHIP_OFF}>
                {lbl}
                {k !== "all" && <span className="ml-1.5 font-mono text-[10px] opacity-70">{allRooms.filter(r => r.difficulty === k).length}</span>}
              </button>
            ))}
          </div>
          <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Category">
            {categories.map(cat => (
              <button key={cat} onClick={() => setFilter(cat)} aria-pressed={cat === filter}
                className={cat === filter ? CHIP_ON : CHIP_OFF}>
                {cat}
              </button>
            ))}
            <span className="ml-auto self-center text-[11px] text-slate-400">
              {filtered.length} room{filtered.length !== 1 ? "s" : ""}
            </span>
          </div>
        </div>

        {/* Room grid — skeletons until progress is loaded, so rooms never flash
            as locked / not started for a learner who has completed them. */}
        {!ready && (
          <div aria-busy="true">
            <p className="mb-3 flex items-center gap-2 text-xs text-slate-400">
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
              {slow ? "Still loading your room progress — try reloading the page." : "Loading your room progress…"}
            </p>
            <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
              {Array.from({ length: 6 }, (_, i) => (
                <div key={i} className="h-44 animate-pulse rounded-lg border border-border bg-bg-elevated" />
              ))}
            </div>
          </div>
        )}
        {/* One section per level, in learning order. */}
        {ready && LEVELS.map((lv, i) => {
          const rooms = filtered.filter(r => r.difficulty === lv.key);
          if (rooms.length === 0) return null;
          const done = rooms.filter(r => !!progress[r.id]?.completedAt).length;
          return (
            <section key={lv.key} aria-labelledby={`level-${lv.key}`} className="space-y-3">
              <div className="flex flex-wrap items-baseline justify-between gap-2 border-b border-border/50 pb-2">
                <div>
                  <h2 id={`level-${lv.key}`} className="text-base font-bold text-white">
                    <span className="mr-2 font-mono text-xs text-slate-400">Level {i + 1}</span>{lv.label}
                  </h2>
                  <p className="text-[11px] text-slate-400">{lv.hint}</p>
                </div>
                <span className="font-mono text-[11px] text-slate-400">{done}/{rooms.length} complete</span>
              </div>
              <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
                {rooms.map(room => (
                  <RoomCard
                    key={room.id}
                    room={room}
                    progress={progress[room.id] ?? null}
                    locked={isLocked(room.id)}
                    suggestAfter={unmetPrereqs(room)}
                    assigned={assigned[`room:${room.id}`]}
                    onClick={() => router.push(`/rooms/${room.id}`)}
                  />
                ))}
              </div>
            </section>
          );
        })}

        {ready && filtered.length === 0 && (
          <div className="flex flex-col items-center justify-center rounded border border-border/40 bg-bg-elevated py-16 text-center">
            <BookOpen className="h-12 w-12 text-slate-400 mb-4" />
            <p className="text-sm text-slate-400">No rooms match these filters.</p>
          </div>
        )}
      </div>
    </div>
  );
}
