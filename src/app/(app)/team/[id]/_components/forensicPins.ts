"use client";
import { useCallback, useEffect, useState } from "react";

/** A row a Tier-3 analyst pinned to their working timeline (from any forensic tool). */
export interface PinRow { ref: string; host: string; evidence: string; plugin: string; text: string; atMs: number | null }

const EVT = "fw-pins-changed";

/**
 * The analyst's pinned rows, kept in this browser and shared by every Tier-3 tool on the page
 * (the workbench, the timeline explorer): pinning in one shows in the other at once.
 */
export function useForensicPins(sessionId: string, meId: string) {
  const key = `fw-pins-${sessionId}-${meId}`;
  const read = useCallback((): PinRow[] => { try { return JSON.parse(localStorage.getItem(key) ?? "[]"); } catch { return []; } }, [key]);
  const [pins, setPins] = useState<PinRow[]>([]);
  useEffect(() => {
    setPins(read());
    const sync = () => setPins(read());
    window.addEventListener(EVT, sync);
    window.addEventListener("storage", sync);
    return () => { window.removeEventListener(EVT, sync); window.removeEventListener("storage", sync); };
  }, [read]);
  const save = useCallback((next: PinRow[]) => {
    setPins(next);
    try { localStorage.setItem(key, JSON.stringify(next)); } catch { /* storage blocked */ }
    window.dispatchEvent(new Event(EVT));
  }, [key]);
  const toggle = useCallback((r: PinRow) => { const cur = read(); save(cur.some(p => p.ref === r.ref) ? cur.filter(p => p.ref !== r.ref) : [...cur, r]); }, [read, save]);
  return { pins, toggle };
}
