/**
 * The storylines this learner met most recently, newest first (light: no story data, so the page can
 * merge the server history in without loading the simulation chunk).
 *
 * Two sources: this browser's own memory (localStorage), and the learner's server-side history
 * (dashboard_incidents.story_id, GET /api/me/incidents), so a new device, a private window or a cleared
 * browser does not deal the same attack again (Tal 2026-11-12: no repeats between trainings).
 */
import { lsReadJson, lsSet, isStringArray } from "@/lib/storage/safeStorage";

export const RECENT_KEY = "soc_recent_story_ids";
/** How many recent storylines a draw avoids (a company has some 25 to 50 it can be dealt). */
export const RECENT_N = 12;

export function readRecent(): string[] {
  // E-22: storage can throw (private mode / blocked) and the value can be any shape.
  return lsReadJson(RECENT_KEY, [] as string[], isStringArray);
}

export function pushRecent(id: string): void {
  const next = [id, ...readRecent().filter(x => x !== id)].slice(0, RECENT_N);
  lsSet(RECENT_KEY, JSON.stringify(next));
}

/** Merge the server's history (newest first) behind this browser's own, without duplicates. */
export function mergeRecent(serverIds: string[]): void {
  const local = readRecent();
  const next = [...local, ...serverIds.filter(id => typeof id === "string" && id && !local.includes(id))].slice(0, RECENT_N);
  lsSet(RECENT_KEY, JSON.stringify(next));
}
