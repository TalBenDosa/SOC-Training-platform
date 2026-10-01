"use client";
import React, { useEffect, useState, useCallback, useMemo, useRef } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/Button";
import { TaskPlayer } from "@/components/rooms/TaskPlayer";
import { TaskReview } from "@/components/rooms/TaskReview";
import { loadRoomReview, type ReviewRecord } from "@/components/rooms/reviewStore";
import {
  ArrowLeft, BookOpen, CheckCircle2, Circle, ChevronRight, ChevronLeft,
  Trophy, Zap, FileText, HelpCircle, Search, Flag, RotateCcw, Terminal, Shield, Eye, X,
} from "lucide-react";
import type { SanitizedRoom as Room, SanitizedRoomTask as RoomTask } from "@/lib/rooms/sanitize";
import type { TaskTelemetryEntry } from "@/lib/useTaskTelemetry";
import { addTotalXp, setTotalXp, getRoomProgress, saveRoomProgress, PROGRESS_HYDRATED_EVENT } from "@/lib/storage/progress";
import { ROOM_PASS_THRESHOLD } from "@/lib/rooms/xp";
import { mergeRoomEntry, mergeTaskXpMax, roomScoreXp } from "@/lib/rooms/progressMerge";
import { recommendNextRoom } from "@/lib/rooms/recommend";
import { ReportIssue } from "@/components/feedback/ReportIssue";

// A room must score at least this fraction of its gradeable XP to count as
// passed. Below this, the student must retry the room from the start — a
// completed-but-failed room does not appear as "done" on /rooms or unlock
// anything that depends on its prerequisites. Defined once in src/lib/rooms/xp.ts
// (the server's completion record applies the same rule).
export { ROOM_PASS_THRESHOLD };

// Rooms whose completion screen offers a direct "practise this live in the
// Dashboard" CTA — the investigation/report capsule rooms, which teach exactly
// the skill the live SOC Dashboard exercises.
const DASHBOARD_CTA_ROOMS = new Set(["investigate-alert-workflow", "incident-report-writing"]);

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

// Both delegate to the storage facade (src/lib/storage/progress.ts) — the same
// "room_progress" key underneath, so guests are unaffected, but a signed-in
// user's room progress now reaches the DB `room_progress` table via
// remoteBackend instead of only localStorage (persistence-migration Stage 2).
function loadProgress(): AllProgress {
  return getRoomProgress() as AllProgress;
}

function saveProgress(data: AllProgress) {
  saveRoomProgress(data);
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
    case "written_report": return <FileText className={cls} />;
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
  // A task completion the server could not record (after one retry) — shown so a
  // student never loses points silently.
  const [saveError, setSaveError]               = useState(false);
  // E-12 (QA phase 7): completions the server hasn't recorded yet. A finished
  // task renders read-only, so "finish it again" was impossible — these are
  // re-sent by the banner's Retry button and when the tab comes back online.
  const pendingSavesRef = useRef<Map<string, TaskTelemetryEntry | undefined>>(new Map());
  const [retryingSaves, setRetryingSaves]       = useState(false);
  // Request ordering for the server's completion responses (P5-20).
  const completionSeqRef = useRef(0);
  const latestAppliedSeqRef = useRef(0);
  const [showCompletion, setShowCompletion]      = useState(false);
  const [showFailure, setShowFailure]            = useState(false);
  const [mounted, setMounted]                   = useState(false);
  // FB-001: read-only walk through a finished room. Never submits, never
  // touches progress/XP — see startReview / TaskReview.
  const [reviewMode, setReviewMode]             = useState(false);
  const [reviewRecords, setReviewRecords]       = useState<Record<string, ReviewRecord>>({});


  const maxXp   = maxRoomXp(room);
  // Max XP per GRADEABLE task — the 65% gate counts only these. Reading tasks'
  // engagement XP lives in perTaskXp too (so it's stored and survives a reload),
  // but must not help pass a room.
  const gradeableMax = useMemo(() => {
    const m: Record<string, number> = {};
    for (const t of room.tasks) { const mx = taskMaxXp(t); if (mx > 0) m[t.id] = mx; }
    return m;
  }, [room]);
  const scoreXp  = roomScoreXp({ xpEarned: totalXpEarned, perTaskXp }, gradeableMax);
  const scorePct = maxXp > 0 ? Math.round((scoreXp / maxXp) * 100) : 100;

  // Tasks finished during THIS visit. If the remote backend hydrates after we
  // mounted (hard reload / new tab), these are merged into the server entry
  // instead of being lost — and the empty pre-hydrate state is never saved.
  const sessionRef = useRef<{ ids: Set<string>; xp: Record<string, number>; telemetry: TaskTelemetryEntry[] }>({
    ids: new Set(), xp: {}, telemetry: [],
  });

  /** Put a stored entry on screen (resume point, completion / failure screen).
   *  No entry = a fresh room (resets whatever the pre-hydrate read showed). */
  const applyEntry = useCallback((entry: RoomProgressEntry | undefined) => {
    if (!entry) {
      setReviewMode(false);
      setCompletedTaskIds(new Set());
      setTotalXpEarned(0);
      setPerTaskXp({});
      setTelemetry([]);
      setShowCompletion(false);
      setShowFailure(false);
      setCurrentTaskIndex(0);
      return;
    }
    const ids = new Set<string>(entry.completedTaskIds);
    setCompletedTaskIds(ids);
    setTotalXpEarned(entry.xpEarned);
    setPerTaskXp(entry.perTaskXp ?? {});
    setTelemetry(entry.telemetry ?? []);
    setShowCompletion(false);
    setShowFailure(false);
    if (entry.completedAt) {
      setShowCompletion(true);
    } else if (room.tasks.every(t => ids.has(t.id))) {
      // Every task was done in a prior attempt but it never earned
      // completedAt. Re-derive pass/fail from the actual score rather than
      // assuming — completedAt is only missing when a prior run failed,
      // but don't trust that invariant blindly.
      const max = maxRoomXp(room);
      const passed = max === 0 || (roomScoreXp(entry, gradeableMax) / max) >= ROOM_PASS_THRESHOLD;
      if (passed) setShowCompletion(true); else setShowFailure(true);
    } else {
      // Resume at first incomplete task (an unfinished room has nothing to review).
      setReviewMode(false);
      const firstIncomplete = room.tasks.findIndex(t => !ids.has(t.id));
      setCurrentTaskIndex(firstIncomplete === -1 ? room.tasks.length - 1 : firstIncomplete);
    }
  }, [room, gradeableMax]);

  // Load persisted progress on mount
  useEffect(() => {
    sessionRef.current = { ids: new Set(), xp: {}, telemetry: [] };
    applyEntry(loadProgress()[room.id]);
    setMounted(true);
  }, [room, applyEntry]);

  // Re-read once the signed-in learner's remote progress lands. On a hard
  // reload we mounted against the empty pre-hydrate backend; without this the
  // room resumed from nothing and the next save overwrote the real server row
  // (lower XP, lost completedAt) — audit 2026-09.
  useEffect(() => {
    const onHydrated = () => {
      const all = loadProgress();
      const stored = all[room.id] as RoomProgressEntry | undefined;
      const session = sessionRef.current;
      if (session.ids.size === 0) { applyEntry(stored); return; }
      // Carry over what was done in this visit before hydration finished.
      const merged = mergeRoomEntry(stored, {
        completedTaskIds: Array.from(session.ids),
        xpEarned: Object.values(session.xp).reduce((s, v) => s + v, 0),
        perTaskXp: session.xp,
        telemetry: session.telemetry,
      }) as RoomProgressEntry;
      if (!merged.completedAt && room.tasks.every(t => merged.completedTaskIds.includes(t.id))) {
        const max = maxRoomXp(room);
        if (max === 0 || roomScoreXp(merged, gradeableMax) / max >= ROOM_PASS_THRESHOLD) {
          merged.completedAt = new Date().toISOString();
        }
      }
      all[room.id] = merged;
      saveProgress(all);
      applyEntry(merged);
    };
    window.addEventListener(PROGRESS_HYDRATED_EVENT, onHydrated);
    return () => window.removeEventListener(PROGRESS_HYDRATED_EVENT, onHydrated);
  }, [room, applyEntry, gradeableMax]);

  /**
   * Save this room's entry MERGED with what is stored: per-task bests and
   * xpEarned never go down and completedAt is never dropped, even if this
   * component's state is stale (other tab, pre-hydrate mount). `replaceIds`
   * is only for the review-missed flow, which deliberately re-opens tasks.
   * Returns the entry actually saved.
   */
  const persistProgress = useCallback((
    ids: Set<string>, xp: number, xpMap: Record<string, number>, taskTelemetry: TaskTelemetryEntry[],
    completedAt?: string, opts: { replaceIds?: boolean } = {},
  ): RoomProgressEntry => {
    const all = loadProgress();
    const merged = mergeRoomEntry(all[room.id], {
      completedTaskIds: Array.from(ids),
      xpEarned: xp,
      perTaskXp: xpMap,
      telemetry: taskTelemetry,
      ...(completedAt ? { completedAt } : {}),
    }, opts) as RoomProgressEntry;
    all[room.id] = merged;
    saveProgress(all);
    return merged;
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
    persistProgress(remaining, totalXpEarned, perTaskXp, telemetry, undefined, { replaceIds: true });
  }

  // FB-001: open the finished room read-only. The saved answers/reveals come
  // from this device's review store; nothing is submitted or persisted, so XP,
  // completedAt and the attempt log are untouched however the learner browses.
  function startReview() {
    setReviewRecords(loadRoomReview(room.id));
    setReviewMode(true);
    setShowCompletion(false);
    setShowFailure(false);
    setCurrentTaskIndex(0);
    if (typeof window !== "undefined") window.scrollTo({ top: 0 });
  }

  function exitReview() {
    setReviewMode(false);
    setShowCompletion(true);
  }

  function goToTask(idx: number) {
    setCurrentTaskIndex(Math.max(0, Math.min(room.tasks.length - 1, idx)));
    if (typeof window !== "undefined") window.scrollTo({ top: 0 });
  }

  function handleTaskComplete(xpEarned: number, taskTelemetry?: TaskTelemetryEntry) {
    const task     = room.tasks[currentTaskIndex];
    const firstTime = !completedTaskIds.has(task.id);

    // Reading tasks report 0 to the room score (they stay non-gradeable, so the
    // 65% mastery gate is unaffected — see roomScoreXp). They earn a symbolic
    // engagement XP on first completion, now STORED in perTaskXp so it reaches
    // room_progress.xp_earned (and therefore the overall score) and survives a
    // reload — it used to be added to the optimistic total only and vanish.
    const earned = task.type === "reading" ? (firstTime ? (task.xp ?? 5) : 0) : xpEarned;

    // Delta accounting against the best KNOWN value (this component's state AND
    // the stored entry — the state can be stale), so the running total only
    // gets the real improvement: never double-counted, never clawed back.
    const stored   = loadProgress()[room.id] as RoomProgressEntry | undefined;
    const knownXp  = mergeTaskXpMax(stored?.perTaskXp, perTaskXp);
    const prevXp   = knownXp[task.id] ?? 0;
    const bestXp   = Math.max(prevXp, earned);
    const delta    = bestXp - prevXp;
    const newXpMap = { ...knownXp, [task.id]: bestXp };
    const newXp    = Object.values(newXpMap).reduce((s, v) => s + v, 0);
    const newTelemetry = taskTelemetry ? [...telemetry, taskTelemetry] : telemetry;
    const newIds   = new Set([...(stored?.completedTaskIds ?? []), ...completedTaskIds, task.id]);

    const session = sessionRef.current;
    session.ids.add(task.id);
    // What THIS visit earned — not bestXp, which before hydration may include
    // this device's guest-era localStorage values.
    session.xp[task.id] = Math.max(session.xp[task.id] ?? 0, earned);
    if (taskTelemetry) session.telemetry.push(taskTelemetry);

    if (delta > 0) addXpToTotal(delta);

    const allDone = room.tasks.every(t => newIds.has(t.id));
    let saved: RoomProgressEntry;
    if (allDone) {
      const passed = maxXp === 0 || (roomScoreXp({ xpEarned: newXp, perTaskXp: newXpMap }, gradeableMax) / maxXp) >= ROOM_PASS_THRESHOLD;
      if (passed) {
        const completedAt = new Date().toISOString();
        saved = persistProgress(newIds, newXp, newXpMap, newTelemetry, completedAt);
        setShowCompletion(true);
      } else {
        // Near-miss: KEEP the earned XP and all correct answers, persist the
        // progress WITHOUT completedAt (room stays "in progress", so it doesn't
        // unlock prerequisites yet), and offer to replay only the missed tasks.
        saved = persistProgress(newIds, newXp, newXpMap, newTelemetry);
        if (saved.completedAt) setShowCompletion(true); else setShowFailure(true);
      }
    } else {
      saved = persistProgress(newIds, newXp, newXpMap, newTelemetry);
      // Advance to the next still-incomplete task (linear on first pass; jumps
      // between missed tasks during a review).
      const next = room.tasks.findIndex(t => !newIds.has(t.id));
      setCurrentTaskIndex(next === -1 ? currentTaskIndex : next);
    }
    // Mirror what was actually saved (the merge may know more than our state).
    setCompletedTaskIds(new Set(saved.completedTaskIds));
    setPerTaskXp(saved.perTaskXp ?? newXpMap);
    setTotalXpEarned(saved.xpEarned);
    setTelemetry((saved.telemetry as TaskTelemetryEntry[] | undefined) ?? newTelemetry);
    void reportCompletion(task.id, taskTelemetry);
  }

  /**
   * Server-authoritative credit (0078). The server records the finished task,
   * computes its XP from its own grading records and returns the real numbers;
   * the optimistic values shown a moment earlier are replaced with them. One
   * automatic retry, then a visible warning.
   */
  async function reportCompletion(taskId: string, taskTelemetry?: TaskTelemetryEntry, retry = true): Promise<void> {
    const seq = ++completionSeqRef.current;
    try {
      const res = await fetch(`/api/rooms/${encodeURIComponent(room.id)}/tasks/${encodeURIComponent(taskId)}/complete`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(taskTelemetry ? { telemetry: taskTelemetry } : {}),
      });
      if (!res.ok) throw new Error(`status ${res.status}`);
      const d = await res.json() as { guest?: boolean; taskXp?: number; roomXp?: number | null; completedAt?: string | null; totalXp?: number | null };
      pendingSavesRef.current.delete(taskId);
      if (pendingSavesRef.current.size === 0) setSaveError(false);
      if (d.guest) return;
      const all = loadProgress();
      const cur = all[room.id];
      // P5-20: two completions in quick succession can answer out of order. The
      // server stays authoritative (it may credit LESS than the optimistic value),
      // but only the response to the most recent request sets the room / account
      // totals — a late, older one can't roll them back.
      const isLatest = seq >= latestAppliedSeqRef.current;
      if (isLatest) latestAppliedSeqRef.current = seq;
      if (cur && typeof d.taskXp === "number") {
        const serverMap = { ...(cur.perTaskXp ?? {}), [taskId]: d.taskXp };
        const next: RoomProgressEntry = {
          ...cur,
          perTaskXp: serverMap,
          xpEarned: isLatest && typeof d.roomXp === "number" ? d.roomXp : cur.xpEarned,
          ...(d.completedAt ? { completedAt: d.completedAt } : {}),
        };
        all[room.id] = next;
        saveProgress(all);
        setPerTaskXp(serverMap);
        setTotalXpEarned(next.xpEarned);
      }
      if (isLatest && typeof d.totalXp === "number") setTotalXp(d.totalXp);
    } catch {
      if (retry) { setTimeout(() => { void reportCompletion(taskId, taskTelemetry, false); }, 2000); return; }
      pendingSavesRef.current.set(taskId, taskTelemetry);
      setSaveError(true);
    }
  }

  // Re-send every completion the server hasn't recorded (E-12). The complete
  // route is idempotent per task, so a duplicate send can't double-credit.
  const retryPendingSaves = useCallback(async () => {
    const pending = [...pendingSavesRef.current.entries()];
    if (pending.length === 0) return;
    setRetryingSaves(true);
    try {
      for (const [taskId, tel] of pending) await reportCompletion(taskId, tel, false);
    } finally {
      setRetryingSaves(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [room.id]);

  useEffect(() => {
    const onBack = () => {
      if (document.visibilityState === "visible") void retryPendingSaves();
    };
    window.addEventListener("online", onBack);
    document.addEventListener("visibilitychange", onBack);
    return () => {
      window.removeEventListener("online", onBack);
      document.removeEventListener("visibilitychange", onBack);
    };
  }, [retryPendingSaves]);

  const completedCount = completedTaskIds.size;
  const totalTasks     = room.tasks.length;
  const currentTask    = room.tasks[currentTaskIndex];

  // A room with no tasks (e.g. a mis-authored / half-published org room) would
  // otherwise crash on `currentTask.type` just below. Render a friendly empty
  // state instead of a white-screen runtime error — the page must degrade, not
  // break, when content data is incomplete.
  if (!currentTask) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-bg px-6">
        <div className="w-full max-w-md rounded-xl border border-border bg-bg-elevated p-8 text-center space-y-3">
          <p className="text-lg font-semibold text-white">This room has no content yet</p>
          <p className="text-sm text-slate-400">There are no tasks to complete here yet. Please check back later.</p>
          <Link href="/rooms" className="inline-block rounded-md bg-neon-purple px-4 py-2 text-sm font-bold text-white transition hover:brightness-110">
            Back to Learning Rooms
          </Link>
        </div>
      </div>
    );
  }

  // If the current task is a flag, surface the NEAREST preceding task that carries a
  // log event (log_analysis or analyst_choice) so FlagPlayer keeps that log visible.
  // Flag prompts routinely ask the student to read a field from a log, and the flag is
  // often not the task immediately after its log_analysis (a reading/question/matching
  // step can sit between) — walking back finds the log the flag actually refers to.
  let prevLogEvent;
  if (currentTask.type === "flag") {
    if (currentTask.event !== undefined) {
      // Explicitly pinned by the author: an event to show, or `null` for no log
      // (a pure recall/knowledge flag whose answer isn't in any log).
      prevLogEvent = currentTask.event ?? undefined;
    } else {
      // A "Log Analysis N" reference pins the Nth log_analysis event — the flag is
      // often not right after its log, and an intervening analyst_choice log would
      // otherwise be shown instead (the mismatch students reported).
      const m = currentTask.prompt?.match(/log analysis\s+(\d+)/i);
      if (m) {
        let n = 0;
        for (const t of room.tasks) {
          if (t.type === "log_analysis") { n++; if (n === Number(m[1])) { prevLogEvent = t.event; break; } }
        }
      }
      // Fallback: the nearest preceding log (log_analysis or analyst_choice).
      if (!prevLogEvent) {
        for (let i = currentTaskIndex - 1; i >= 0; i--) {
          const t = room.tasks[i];
          if (t.type === "log_analysis" || t.type === "analyst_choice") { prevLogEvent = t.event; break; }
        }
      }
    }
  }

  if (!mounted) return null;

  // ─── Completion modal ───────────────────────────────────────────────────────
  if (showCompletion && !reviewMode) {
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
            <p className="text-[11px] uppercase tracking-wider text-slate-400 font-semibold mb-1">Total XP Earned</p>
            <p className="text-3xl font-bold font-mono text-neon-amber">+{totalXpEarned}</p>
            <p className="text-[11px] text-slate-400 mt-1">{totalTasks} tasks completed</p>
          </div>
          <div className="rounded-lg border border-neon-green/30 bg-neon-green/5 px-6 py-3">
            <p className="text-[11px] uppercase tracking-wider text-slate-400 font-semibold mb-1">Score</p>
            <p className="text-xl font-bold text-neon-green">{scorePct}%</p>
            <p className="text-[10px] text-slate-400 mt-0.5">Passed — {Math.round(ROOM_PASS_THRESHOLD * 100)}% required</p>
          </div>
          {/* Transfer moment: the investigation/report capsule rooms teach exactly
              what the live Dashboard demands (triage a real feed, write the incident
              report with no hints). At peak momentum — the instant they pass — point
              them straight at the practice, closing the loop the product already built. */}
          {DASHBOARD_CTA_ROOMS.has(room.id) && (
            <button
              onClick={() => router.push("/dashboard")}
              className="group w-full rounded-lg border border-cyber-500/40 bg-cyber-500/10 px-4 py-3 text-left transition-colors hover:border-cyber-500/60 hover:bg-cyber-500/15"
            >
              <div className="flex items-center gap-2">
                <Shield className="h-4 w-4 text-cyber-300 shrink-0" />
                <span className="text-[13px] font-bold text-cyber-200">Now practise this live</span>
                <ChevronRight className="h-4 w-4 text-cyber-400 ml-auto transition-transform group-hover:translate-x-0.5" />
              </div>
              <p className="text-[11px] text-slate-400 mt-1 leading-relaxed">
                Take it into the SOC Dashboard — triage a live feed and write a real incident report under the clock.
              </p>
            </button>
          )}
          {(() => {
            // Reuse the SAME recommender the rooms list uses, so the next step
            // offered here matches what a learner would pick from the list —
            // closing the "Room Complete → dead end" gap at peak momentum.
            const nextRec = recommendNextRoom(getRoomProgress(), room.id);
            return (
              <div className="flex flex-col gap-2">
                {nextRec && (
                  <Button variant="primary" size="lg" className="w-full" onClick={() => router.push(`/rooms/${nextRec.room.id}`)}>
                    {nextRec.started ? "Continue" : "Next"}: {nextRec.room.title}
                    <ChevronRight className="h-4 w-4" />
                  </Button>
                )}
                {/* FB-001: reopen the finished room READ-ONLY — page through every task:
                    readings in full, questions with your answer / the correct answer /
                    the explanation where this device saved them. Never re-submits and
                    never changes XP or progress. Also reachable on every revisit, since
                    a completed room always opens on this screen. */}
                <Button variant="outline" size="lg" className="w-full" onClick={startReview}>
                  <Eye className="h-4 w-4" />
                  Review room
                </Button>
                <Button variant={nextRec ? "outline" : "primary"} size="lg" className="w-full" onClick={() => router.push("/rooms")}>
                  <ArrowLeft className="h-4 w-4" />
                  Back to Rooms
                </Button>
              </div>
            );
          })()}
        </div>
      </div>
    );
  }

  // ─── Almost-there screen — below pass threshold, review just the missed tasks ─
  if (showFailure && !reviewMode) {
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
            <p className="text-[11px] uppercase tracking-wider text-slate-400 font-semibold mb-1">Your Score</p>
            <p className="text-3xl font-bold font-mono text-neon-amber">{scorePct}%</p>
            <p className="text-[11px] text-slate-400 mt-1">
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
          <p className="text-[11px] text-slate-400 mt-0.5">{room.difficulty} · {room.category}</p>
        </div>

        {/* Task list */}
        <nav className="flex-1 overflow-y-auto p-3 space-y-0.5">
          {room.tasks.map((task, idx) => {
            const done    = reviewMode || completedTaskIds.has(task.id);
            const current = idx === currentTaskIndex;
            return (
              <button
                key={task.id}
                onClick={() => done || current ? goToTask(idx) : undefined}
                aria-current={current ? "step" : undefined}
                className={cn(
                  "flex w-full items-center gap-2.5 rounded-md px-2.5 py-2 text-left text-xs transition-colors",
                  current
                    ? "bg-cyber-500/10 text-white"
                    : done
                      ? "text-slate-400 hover:bg-bg-hover hover:text-slate-200 cursor-pointer"
                      : "text-slate-400 cursor-default",
                )}
              >
                {/* Status icon */}
                <span className="shrink-0">
                  {done ? (
                    <CheckCircle2 className="h-3.5 w-3.5 text-neon-green" />
                  ) : current ? (
                    <ChevronRight className="h-3.5 w-3.5 text-cyber-300" />
                  ) : (
                    <Circle className="h-3.5 w-3.5 text-slate-400" />
                  )}
                </span>
                {/* Task type icon */}
                <TaskIcon type={task.type} className={current ? "text-cyber-300" : done ? "text-slate-400" : "text-slate-700"} />
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
            <div className="flex justify-between text-[10px] text-slate-400 mb-1.5">
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
            <span className="text-slate-400">XP earned</span>
          </div>
        </div>
      </aside>

      {/* ── Main content ─────────────────────────────────────────────────── */}
      <main className="flex-1 overflow-y-auto">
        {/* Mobile back link + progress */}
        <div className="lg:hidden flex items-center justify-between border-b border-border py-3 pl-16 pr-4 md:px-4">
          <button
            onClick={() => router.push("/rooms")}
            className="inline-flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors"
          >
            <ArrowLeft className="h-3.5 w-3.5" />
            Back
          </button>
          <span className="text-[11px] text-slate-400">
            Task {currentTaskIndex + 1} of {totalTasks}
          </span>
        </div>

        <div className="max-w-3xl mx-auto px-6 py-8">
          {/* FB-001: review-mode banner — makes the read-only state unmistakable. */}
          {reviewMode && (
            <div role="status" className="mb-6 flex flex-wrap items-center gap-3 rounded-lg border border-cyber-500/30 bg-cyber-500/5 px-4 py-3">
              <Eye className="h-4 w-4 shrink-0 text-cyber-300" />
              <div className="flex-1 min-w-[12rem]">
                <p className="text-sm font-semibold text-white">Reviewing this room</p>
                <p className="text-[11px] text-slate-400">Read-only — nothing is submitted, and your XP and progress stay exactly as they are.</p>
              </div>
              <Button variant="outline" size="sm" onClick={exitReview}>
                <X className="h-3.5 w-3.5" />
                Exit review
              </Button>
            </div>
          )}

          {/* Task counter */}
          <div className="flex items-center gap-3 mb-6">
            {currentTaskIndex > 0 && (
              <button
                onClick={() => goToTask(currentTaskIndex - 1)}
                className="inline-flex items-center gap-1 text-[11px] text-slate-400 hover:text-slate-200 transition-colors"
              >
                <ChevronLeft className="h-3.5 w-3.5" />
                Back
              </button>
            )}
            <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
              Task {currentTaskIndex + 1} of {totalTasks}
            </span>
            <TaskIcon type={currentTask.type} className="text-slate-400" />
            <span className="text-[11px] text-slate-400 capitalize">{currentTask.type.replace("_", " ")}</span>
          </div>

          {/* Task player — or, in review mode, the read-only view (never submits). */}
          {reviewMode ? (
            <>
              <TaskReview
                key={currentTask.id}
                task={currentTask}
                record={reviewRecords[currentTask.id]}
                earnedXp={perTaskXp[currentTask.id]}
                maxXp={taskMaxXp(currentTask)}
                prevLogEvent={prevLogEvent}
              />
              <div className="mt-8 flex items-center justify-between gap-3">
                <Button variant="outline" size="md" disabled={currentTaskIndex === 0} onClick={() => goToTask(currentTaskIndex - 1)}>
                  <ChevronLeft className="h-4 w-4" />
                  Previous
                </Button>
                {currentTaskIndex < totalTasks - 1 ? (
                  <Button variant="primary" size="md" onClick={() => goToTask(currentTaskIndex + 1)}>
                    Next
                    <ChevronRight className="h-4 w-4" />
                  </Button>
                ) : (
                  <Button variant="primary" size="md" onClick={exitReview}>
                    <CheckCircle2 className="h-4 w-4" />
                    Finish review
                  </Button>
                )}
              </div>
            </>
          ) : (
            <TaskPlayer
              key={currentTask.id}
              roomId={room.id}
              task={currentTask}
              onComplete={handleTaskComplete}
              isCompleted={completedTaskIds.has(currentTask.id)}
              prevLogEvent={prevLogEvent}
            />
          )}

          {/* Quiet escape hatch for "this question is wrong". Placed at the end
              of the task, where a student who just disagreed with the marking
              actually is — and carrying enough context (room, task, type) that
              a report is actionable without a reply. */}
          {saveError && (
            <div role="alert" className="mt-6 flex flex-wrap items-center gap-3 rounded-md border border-severity-high/40 bg-severity-high/10 px-4 py-3 text-sm text-severity-high">
              <span className="min-w-0 flex-1">
                Your answers were graded, but some points from this room haven&apos;t been saved to your account yet. We&apos;ll retry automatically when your connection is back — or retry now.
              </span>
              <Button size="sm" variant="outline" onClick={() => { void retryPendingSaves(); }} disabled={retryingSaves}>
                {retryingSaves ? "Saving…" : "Retry saving"}
              </Button>
            </div>
          )}

          <div className="mt-8 flex justify-end border-t border-border/40 pt-3">
            <ReportIssue
              targetKind="room_task"
              targetId={`${room.id}:${currentTask.id}`}
              context={{
                room: room.title,
                task_index: currentTaskIndex + 1,
                task_type: currentTask.type,
              }}
            />
          </div>
        </div>
      </main>
    </div>
  );
}
