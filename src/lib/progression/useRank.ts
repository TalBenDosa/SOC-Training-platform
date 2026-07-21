"use client";
/**
 * Live XP + rank for the current learner.
 *
 * XP lives in the storage backend (localStorage for guests, Supabase rows once
 * signed in), which is a plain synchronous read with no subscription of its
 * own. This hook adds the subscription:
 *
 *  - reads once on mount (after mount, never during render — the value differs
 *    between server and client and reading it during render would hydrate-
 *    mismatch);
 *  - listens for the in-tab `soc:xp-changed` event that progress.ts now emits,
 *    so finishing a room promotes you immediately rather than on next reload;
 *  - listens for the cross-tab `storage` event, so two open tabs agree.
 */
import { useEffect, useState } from "react";
import { getTotalXp, XP_CHANGED_EVENT } from "@/lib/storage/progress";
import { LEARNER_KEYS } from "@/lib/storage/keys";
import { rankForXp, nextRank, rankProgress, type Rank } from "./ranks";

export interface RankState {
  xp: number;
  rank: Rank;
  next: Rank | null;
  progress: { earned: number; needed: number; pct: number } | null;
  /** False until the first client-side read lands. Render a neutral state until then. */
  ready: boolean;
}

export function useRank(): RankState {
  const [xp, setXp] = useState(0);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    const read = () => { setXp(getTotalXp()); setReady(true); };
    read();

    const onXp = (e: Event) => {
      const detail = (e as CustomEvent<{ total?: number }>).detail;
      if (typeof detail?.total === "number") setXp(detail.total);
      else read();
    };
    const onStorage = (e: StorageEvent) => {
      if (!e.key || e.key === LEARNER_KEYS.totalXp) read();
    };

    window.addEventListener(XP_CHANGED_EVENT, onXp);
    window.addEventListener("storage", onStorage);
    return () => {
      window.removeEventListener(XP_CHANGED_EVENT, onXp);
      window.removeEventListener("storage", onStorage);
    };
  }, []);

  return { xp, rank: rankForXp(xp), next: nextRank(xp), progress: rankProgress(xp), ready };
}
