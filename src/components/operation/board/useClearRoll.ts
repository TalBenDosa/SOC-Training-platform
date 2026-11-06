"use client";
import { useCallback, useEffect, useRef, useState } from "react";
import type { HubStation } from "./types";

/** How long a finished station's card holds the screen, in ms. */
export const ROLL_MS = 4000;

/**
 * Plays one "card roll" for each station the learner finished and has not seen
 * turned yet, one at a time, only on the room's main screen. What was shown is kept
 * per room on this device. A learner with no record yet starts with everything they
 * have already cleared marked as seen, so old progress never replays.
 */
export function useClearRoll(roomId: string, stations: HubStation[], active: boolean, reducedMotion: boolean) {
  const key = `soc:operation:rolled:${roomId}`;
  const seen = useRef<Set<string> | null>(null);
  const [unrolled, setUnrolled] = useState<string[]>([]);
  const [rolling, setRolling] = useState<number | null>(null);

  const save = useCallback(() => {
    try { localStorage.setItem(key, JSON.stringify([...(seen.current ?? [])])); } catch { /* a convenience only */ }
  }, [key]);

  // A station keeps its front face from the moment it clears until its roll has played.
  useEffect(() => {
    if (!seen.current) {
      let stored: string[] | null = null;
      try { const raw = localStorage.getItem(key); stored = raw ? JSON.parse(raw) : null; } catch { stored = null; }
      seen.current = new Set(stored ?? stations.filter(s => s.status === "cleared").map(s => s.id));
      if (!stored) save();
    }
    const known = seen.current;
    const left = stations.filter(s => s.status === "cleared" && !known.has(s.id)).map(s => s.id);
    setUnrolled(u => (u.length === left.length && u.every((x, i) => x === left[i]) ? u : left));
  }, [stations, key, save]);

  const nextId = unrolled[0];
  const index = stations.findIndex(s => s.id === nextId);
  useEffect(() => {
    if (!active || !nextId) return;
    const done = () => { seen.current?.add(nextId); save(); setRolling(null); setUnrolled(u => u.filter(x => x !== nextId)); };
    if (reducedMotion) { done(); return; }
    const start = setTimeout(() => setRolling(index), 700);
    const stop = setTimeout(done, 700 + ROLL_MS);
    return () => { clearTimeout(start); clearTimeout(stop); setRolling(null); };
  }, [active, nextId, index, reducedMotion, save]);

  return { rolling, unrolled };
}
