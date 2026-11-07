"use client";
import { useEffect, useState } from "react";

/**
 * Unsent work survives the end of the shift (2026-11 review: End threw everyone into the review in
 * the middle of a report). Each form parks its text here as the player types; at the end the room
 * shows the player their unsent drafts next to their card. Per browser, per session and per player
 * only: drafts are the player's own and never reach the team or the score.
 */
export interface Draft { key: string; label: string; text: string; at: number }

const storeKey = (sessionId: string, userId: string) => `team-drafts-${sessionId}-${userId}`;
const EVT = "team-drafts-changed";

function read(sessionId: string, userId: string): Draft[] {
  try { const v = JSON.parse(localStorage.getItem(storeKey(sessionId, userId)) ?? "[]"); return Array.isArray(v) ? v : []; } catch { return []; }
}
function write(sessionId: string, userId: string, list: Draft[]) {
  try { localStorage.setItem(storeKey(sessionId, userId), JSON.stringify(list.slice(-20))); window.dispatchEvent(new Event(EVT)); } catch { /* storage blocked: drafts are a convenience */ }
}

/** Save (or with empty text, drop) one draft. */
export function saveDraft(sessionId: string, userId: string, key: string, label: string, text: string): void {
  if (!sessionId || !userId) return;
  const list = read(sessionId, userId).filter(d => d.key !== key);
  if (text.trim()) list.push({ key, label: label.slice(0, 160), text: text.slice(0, 4000), at: Date.now() });
  write(sessionId, userId, list);
}
export function clearDraft(sessionId: string, userId: string, key: string): void { saveDraft(sessionId, userId, key, "", ""); }
export function loadDrafts(sessionId: string, userId: string): Draft[] { return read(sessionId, userId); }

/** Keeps a draft in step with a form while it is non-empty (debounced). */
export function useDraft(sessionId: string | undefined, userId: string | undefined, key: string | null, label: string, text: string): void {
  useEffect(() => {
    if (!sessionId || !userId || !key) return;
    const t = setTimeout(() => saveDraft(sessionId, userId, key, label, text), 600);
    return () => clearTimeout(t);
  }, [sessionId, userId, key, label, text]);
}

/** The player's drafts, live. */
export function useDrafts(sessionId: string, userId: string | undefined): Draft[] {
  const [list, setList] = useState<Draft[]>([]);
  useEffect(() => {
    if (!userId) return;
    const load = () => setList(read(sessionId, userId));
    load();
    window.addEventListener(EVT, load);
    window.addEventListener("storage", load);
    return () => { window.removeEventListener(EVT, load); window.removeEventListener("storage", load); };
  }, [sessionId, userId]);
  return list;
}
