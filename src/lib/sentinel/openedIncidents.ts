"use client";
import { useEffect, useMemo, useState } from "react";

/**
 * Which Sentinel incidents this browser has opened, per team session (review 2026-11: a badge counts
 * the incidents still unopened, not every incident). Kept in localStorage, so the Sentinel tab and
 * the team room tab share it and a reload keeps it. A per-viewer convenience only: nothing is
 * scored from it, and a blocked or empty storage just means every incident counts as unopened.
 */
const KEY = (session: string) => `sentinel-opened:${session}`;
const EVENT = "sentinel-opened-change";

export function readOpened(session: string | null | undefined): Set<string> {
  if (!session) return new Set();
  try {
    const raw = window.localStorage.getItem(KEY(session));
    const arr = raw ? JSON.parse(raw) : [];
    return new Set(Array.isArray(arr) ? arr.filter((x): x is string => typeof x === "string") : []);
  } catch { return new Set(); }
}

export function markOpened(session: string | null | undefined, incidentId: string): void {
  if (!session) return;
  try {
    const s = readOpened(session);
    if (s.has(incidentId)) return;
    s.add(incidentId);
    window.localStorage.setItem(KEY(session), JSON.stringify([...s].slice(-500)));
    window.dispatchEvent(new CustomEvent(EVENT, { detail: session }));
  } catch { /* storage blocked: the badge just keeps counting it */ }
}

/** The opened set, live: updates on this tab's changes and on the other tab's (storage event). */
export function useOpenedIncidents(session: string | null | undefined): Set<string> {
  const [opened, setOpened] = useState<Set<string>>(() => (typeof window === "undefined" ? new Set() : readOpened(session)));
  useEffect(() => {
    if (!session) return;
    const sync = () => setOpened(readOpened(session));
    sync();
    const onStorage = (e: StorageEvent) => { if (e.key === KEY(session)) sync(); };
    const onLocal = (e: Event) => { if ((e as CustomEvent).detail === session) sync(); };
    window.addEventListener("storage", onStorage);
    window.addEventListener(EVENT, onLocal);
    return () => { window.removeEventListener("storage", onStorage); window.removeEventListener(EVENT, onLocal); };
  }, [session]);
  return opened;
}

/** How many of these incidents this browser has not opened yet. */
export function unopenedCount(incidentIds: string[], opened: Set<string>): number {
  let n = 0;
  for (const id of incidentIds) if (!opened.has(id)) n++;
  return n;
}

export function useUnopenedCount(session: string | null | undefined, incidentIds: string[]): number {
  const opened = useOpenedIncidents(session);
  const key = incidentIds.join("|");
  // eslint-disable-next-line react-hooks/exhaustive-deps
  return useMemo(() => unopenedCount(incidentIds, opened), [key, opened]);
}
