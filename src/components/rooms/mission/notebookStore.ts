"use client";
/**
 * The case notebook: one per room, kept on this device (localStorage) for the
 * whole room, so the indicators collected in mission 1 are still there in
 * mission 4. Grading never reads it from storage: a step that needs the
 * notebook sends its current contents with the check.
 */
import { useCallback, useEffect, useState } from "react";
import type { IocType } from "@/lib/missions/types";

export interface NotebookIoc { id: string; type: IocType; value: string; source: string }
export interface NotebookPin { id: string; source: string; text: string; time?: string }
export interface Notebook { iocs: NotebookIoc[]; pins: NotebookPin[]; notes: string }

const EMPTY: Notebook = { iocs: [], pins: [], notes: "" };
const key = (roomId: string) => `soc-mission-notebook:${roomId}`;
const listeners = new Map<string, Set<(n: Notebook) => void>>();

function read(roomId: string): Notebook {
  try {
    const raw = window.localStorage.getItem(key(roomId));
    if (!raw) return EMPTY;
    const n = JSON.parse(raw) as Partial<Notebook>;
    return { iocs: Array.isArray(n.iocs) ? n.iocs : [], pins: Array.isArray(n.pins) ? n.pins : [], notes: typeof n.notes === "string" ? n.notes : "" };
  } catch {
    return EMPTY;
  }
}

function write(roomId: string, n: Notebook) {
  try { window.localStorage.setItem(key(roomId), JSON.stringify(n)); } catch { /* private mode: the notebook lives for this page only */ }
  listeners.get(roomId)?.forEach(fn => fn(n));
}

let seq = 0;
export const newId = () => `${Date.now().toString(36)}-${(seq++).toString(36)}`;

/** Shared notebook state: every component of the room sees the same notebook. */
export function useNotebook(roomId: string) {
  const [nb, setNb] = useState<Notebook>(EMPTY);
  useEffect(() => {
    setNb(read(roomId));
    const set = listeners.get(roomId) ?? new Set();
    set.add(setNb);
    listeners.set(roomId, set);
    return () => { set.delete(setNb); };
  }, [roomId]);
  const update = useCallback((fn: (n: Notebook) => Notebook) => { write(roomId, fn(read(roomId))); }, [roomId]);
  return { nb, update };
}

/** Per-task mission progress on this device, so a reload does not lose passed steps or drafts. */
export function loadMissionState<T>(roomId: string, taskId: string): T | null {
  try {
    const raw = window.localStorage.getItem(`soc-mission:${roomId}:${taskId}`);
    return raw ? JSON.parse(raw) as T : null;
  } catch {
    return null;
  }
}

export function saveMissionState(roomId: string, taskId: string, state: unknown) {
  try { window.localStorage.setItem(`soc-mission:${roomId}:${taskId}`, JSON.stringify(state)); } catch { /* ignore */ }
}
