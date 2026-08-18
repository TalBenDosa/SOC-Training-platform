"use client";

// Shared streak signal — so the Topbar flame and the /progress "Current Streak"
// card always show the SAME number. The computation used to live only inside
// progress/page.tsx, which meant the strongest come-back-tomorrow mechanic was
// invisible on every other screen. Both now read the same activity sources
// through the storage facade and recompute on any XP change.

import { useEffect, useState } from "react";
import {
  getScenarioHistory,
  getDashboardSessions,
  getRoomProgress,
  getStreakFreezeDates,
  XP_CHANGED_EVENT,
} from "@/lib/storage/progress";

/** Consecutive-day streak ending today (or yesterday) from activity dates.
 *  Identical logic to progress/page.tsx computeStreak — keep them in sync. */
function computeStreak(dates: string[]): number {
  if (dates.length === 0) return 0;
  const daySet = new Set(dates.map(d => new Date(d).toDateString()));
  let streak = 0;
  const cursor = new Date();
  // Alive if the last activity was yesterday (grace period).
  if (!daySet.has(cursor.toDateString())) cursor.setDate(cursor.getDate() - 1);
  while (daySet.has(cursor.toDateString())) {
    streak += 1;
    cursor.setDate(cursor.getDate() - 1);
  }
  return streak;
}

function gatherActivityDates(): string[] {
  const cutoff = Date.now() - 30 * 24 * 60 * 60 * 1000;
  const freezes = getStreakFreezeDates().filter(d => new Date(d).getTime() >= cutoff);
  let roomDates: string[] = [];
  try {
    const rp = getRoomProgress() as Record<string, { completedAt?: string }>;
    roomDates = Object.values(rp).map(r => r.completedAt).filter((d): d is string => !!d);
  } catch { /* ignore corrupt data */ }
  let scenarioDates: string[] = [];
  let dashDates: string[] = [];
  try { scenarioDates = getScenarioHistory().map(s => s.date); } catch { /* ignore */ }
  try { dashDates = getDashboardSessions().map(s => s.date); } catch { /* ignore */ }
  return [...scenarioDates, ...dashDates, ...roomDates, ...freezes];
}

export interface StreakState {
  /** Consecutive-day count (0 if none). */
  streak: number;
  /** True when a live streak has no activity yet today — breaks tomorrow unless
   *  the learner does something. The cue to nudge. */
  atRisk: boolean;
  /** False until the first client read lands (avoids SSR flicker). */
  ready: boolean;
}

export function useStreak(): StreakState {
  const [state, setState] = useState<StreakState>({ streak: 0, atRisk: false, ready: false });

  useEffect(() => {
    const recompute = () => {
      const dates = gatherActivityDates();
      const streak = computeStreak(dates);
      const hasToday = new Set(dates.map(d => new Date(d).toDateString())).has(new Date().toDateString());
      setState({ streak, atRisk: streak > 0 && !hasToday, ready: true });
    };
    recompute();
    window.addEventListener(XP_CHANGED_EVENT, recompute);
    return () => window.removeEventListener(XP_CHANGED_EVENT, recompute);
  }, []);

  return state;
}
