"use client";
/**
 * "When may a page read learner progress, and when must it re-read?"
 *
 * ROOT CAUSE of "progress isn't saved to the account" (team-exercise report #1):
 * the rows WERE in scenario_history / room_progress. But /progress and /rooms
 * read the storage facade ONCE on mount — and on any normal load (refresh, new
 * tab, sign-in landing) they mount while the active backend is still the
 * default localStorage one, because ProgressProvider installs the remote
 * backend only after its async hydrate. So a signed-in learner saw THIS
 * BROWSER's guest data (usually nothing): "0 attempted, 0%, 0m", "0/108 rooms".
 * Only the XP header listened for the post-hydrate XP event, which is why the
 * same page showed Total XP 2,567 next to 0 scenarios and a streak of 0 while
 * the Topbar flame (which re-reads on that event) said 1 (#6).
 *
 * This hook is the single rule for every progress-reading page:
 *   · `ready` is false until the data source is authoritative — for a signed-in
 *     learner that means the remote backend has hydrated; guests are ready as
 *     soon as auth has resolved. Pages render a loading state, never zeros.
 *   · `version` bumps whenever the data may have changed (hydrate landed, an
 *     XP/progress write, the tab regained focus) — put it in the read effect's
 *     deps and every stat re-derives from the one source together.
 */
import { useEffect, useState } from "react";
import { useAuth } from "@/lib/auth/AuthContext";
import {
  PROGRESS_HYDRATED_EVENT, XP_CHANGED_EVENT, isProgressHydrated, getProgressLoadFailures,
} from "./progress";
import { isProgressReady } from "./progressReady";

export { isProgressReady };

/** After this long without a hydrate, tell the learner instead of spinning forever. */
const SLOW_MS = 10_000;

export interface ProgressSnapshot {
  ready: boolean;
  /** Bumps on every change signal — use as an effect dependency. */
  version: number;
  /** Signed-in load is taking unusually long (offer a reload). */
  slow: boolean;
  /** Tables the server read failed for — show "couldn't load", not zeros. */
  failed: string[];
}

export function useProgressSnapshot(): ProgressSnapshot {
  const { user, authEnabled, loading } = useAuth();
  const [hydrated, setHydrated] = useState<boolean>(() => isProgressHydrated());
  const [failed, setFailed] = useState<string[]>(() => getProgressLoadFailures());
  const [version, setVersion] = useState(0);
  const [slow, setSlow] = useState(false);

  useEffect(() => {
    const bump = () => setVersion(v => v + 1);
    const onHydrated = () => {
      setHydrated(true);
      setFailed(getProgressLoadFailures());
      bump();
    };
    const onVisible = () => { if (document.visibilityState === "visible") bump(); };
    // The event may have fired between the initial state read and this effect.
    if (isProgressHydrated()) onHydrated();
    window.addEventListener(PROGRESS_HYDRATED_EVENT, onHydrated);
    window.addEventListener(XP_CHANGED_EVENT, bump);
    window.addEventListener("pageshow", bump);
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      window.removeEventListener(PROGRESS_HYDRATED_EVENT, onHydrated);
      window.removeEventListener(XP_CHANGED_EVENT, bump);
      window.removeEventListener("pageshow", bump);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, []);

  const ready = isProgressReady({ authEnabled, authLoading: loading, userId: user?.id ?? null, hydrated });

  useEffect(() => {
    if (ready) { setSlow(false); return; }
    const t = setTimeout(() => setSlow(true), SLOW_MS);
    return () => clearTimeout(t);
  }, [ready]);

  return { ready, version, slow, failed };
}
