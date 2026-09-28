/**
 * Investigation timer persistence (team-exercise finding #27).
 *
 * The timer was a `setInterval(+1)` counter in component state: a reload reset
 * the page to "Start Investigation", and a throttled background tab skipped
 * ticks, so one run reported 00:37 for several minutes of work. The start time
 * is now persisted per scenario and elapsed is WALL time since that start —
 * reload resumes, throttling can't under-report.
 *
 * localStorage only (a per-viewer convenience — time is never graded, FB-007);
 * every access is guarded because storage can throw (private mode, blocked site
 * data) and the page must still work without it.
 */

const KEY_PREFIX = "soc_scenario_started_at:";

export function clockKey(slug: string): string {
  return `${KEY_PREFIX}${slug}`;
}

/** Longest a stored start is honoured — older than this is a stale abandoned run. */
export const MAX_RESUME_MS = 12 * 60 * 60 * 1000;

type StorageLike = Pick<Storage, "getItem" | "setItem" | "removeItem">;

function store(s?: StorageLike | null): StorageLike | null {
  if (s !== undefined) return s;
  try { return typeof window !== "undefined" ? window.localStorage : null; } catch { return null; }
}

/** The persisted start (epoch ms) for a scenario, or null (none / stale / unreadable). */
export function loadInvestigationStart(slug: string, now = Date.now(), storage?: StorageLike | null): number | null {
  try {
    const raw = store(storage)?.getItem(clockKey(slug));
    if (!raw) return null;
    const t = Number(raw);
    if (!Number.isFinite(t) || t <= 0 || t > now + 60_000 || now - t > MAX_RESUME_MS) return null;
    return t;
  } catch {
    return null;
  }
}

export function saveInvestigationStart(slug: string, startMs: number, storage?: StorageLike | null): void {
  try { store(storage)?.setItem(clockKey(slug), String(startMs)); } catch { /* storage unavailable */ }
}

export function clearInvestigationStart(slug: string, storage?: StorageLike | null): void {
  try { store(storage)?.removeItem(clockKey(slug)); } catch { /* storage unavailable */ }
}

/** Whole seconds of wall time since `startMs` (never negative). */
export function elapsedSeconds(startMs: number | null, now = Date.now()): number {
  if (startMs === null) return 0;
  return Math.max(0, Math.floor((now - startMs) / 1000));
}
