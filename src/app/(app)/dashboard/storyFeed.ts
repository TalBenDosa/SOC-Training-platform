/**
 * How the solo Live Feed releases an attack story (pure, no React; useLiveEvents calls it).
 *
 * R4 (docs/LOG-REALISM-STANDARD.md): a story is re-timed with ONE monotone map from authored time to
 * shift time. The feed reveals a story phase by phase in real time, so the map grows as it goes: every
 * row placed adds an anchor (authored ms, shown ms) and every time inside every row goes through the
 * map built from all anchors so far (withMappedTime). A correlation alert's StartTime, a ticket's
 * opened_at on a later update, a Defender alert's first-activity time: each lands on the row it names,
 * never "my own new time minus the authored gap". A row authored before rows already shown (a late
 * log, a baseline row from the day before) is placed where the map puts it, in the past: it arrives
 * late, as a log does, and slots into its place in the feed.
 *
 * R7: a burst stays a burst. A phase takes the next 2-3 rows plus every following row authored within
 * BURST_MS of the phase's first row, so a spray of 15 failures in 90 seconds is released together and
 * keeps its authored spacing (never stretched), instead of trickling out over half an hour.
 *
 * R8: ordinary noise stays at least twice the attack rows while the attack runs (noiseQuota).
 */
import { storyTimeMap, withMappedTime, type TimeMap } from "@/lib/sim/rebaseTime";

/** Rows authored within this distance of a phase's first row are released with it. */
export const BURST_MS = 90_000;
/** A phase never releases more rows than this at once. */
export const MAX_PHASE_ROWS = 24;
/** The longest span a phase's rows are spread over in the feed (a longer authored span is compressed). */
export const PHASE_WINDOW_MS = 100_000;
/** Ordinary noise rows per attack row (R8: at least twice). */
export const NOISE_PER_ATTACK_ROW = 2;

export interface StoryClock {
  anchors: { authoredMs: number; shownMs: number }[];
  /** Latest authored instant already placed. */
  maxAuthored: number;
  /** Latest shown instant already placed. */
  lastShown: number;
}

export function newStoryClock(): StoryClock {
  return { anchors: [], maxAuthored: -Infinity, lastShown: -Infinity };
}

const authoredMs = (e: { ts?: string }) => (e.ts ? Date.parse(e.ts) : NaN);

/** How many rows the phase starting at `cursor` releases: 2-3, plus the rest of a burst. */
export function phaseSize(events: { ts?: string }[], cursor: number, rnd: () => number = Math.random): number {
  const left = events.length - cursor;
  if (left <= 0) return 0;
  let n = Math.min(left, 2 + (rnd() < 0.5 ? 1 : 0));
  const first = authoredMs(events[cursor]);
  if (!Number.isFinite(first)) return n;
  while (cursor + n < events.length && n < MAX_PHASE_ROWS) {
    const t = authoredMs(events[cursor + n]);
    if (!Number.isFinite(t) || t < first || t - first > BURST_MS) break;
    n++;
  }
  return n;
}

/**
 * Place one phase of story rows: rows newer than everything shown so far are spread over the minute
 * or two before `now` in authored proportion (never stretched past their authored span, and never
 * before the last row shown); older rows go where the story's map puts them. Returns the rows with
 * `ts` and every raw time mapped, and the map they were mapped with.
 */
export function placePhase<E extends { ts?: string; raw?: Record<string, unknown>; description?: string }>(
  clock: StoryClock, rows: E[], now: number, rnd: () => number = Math.random,
): { rows: E[]; map: TimeMap } {
  const fresh = rows.map(authoredMs).filter(a => Number.isFinite(a) && a > clock.maxAuthored);
  const end = now - (5_000 + Math.floor(rnd() * 15_000));            // newest: 5-20 s ago, never in the future
  if (fresh.length > 0) {
    const lo = Math.min(...fresh), hi = Math.max(...fresh);
    const span = Math.min(hi - lo, PHASE_WINDOW_MS);
    const start = Math.min(end, Math.max(end - span, clock.lastShown + 1_000));
    const shown = (a: number) => (hi === lo ? end : Math.round(start + ((a - lo) * (end - start)) / (hi - lo)));
    for (const a of new Set(fresh)) clock.anchors.push({ authoredMs: a, shownMs: shown(a) });
    clock.maxAuthored = hi;
    clock.lastShown = Math.max(clock.lastShown, end);
  }
  const map = storyTimeMap(clock.anchors);
  const out = rows.map(e => {
    const a = authoredMs(e);
    // A row with no authored time is shown as the phase's newest row.
    const at = Number.isFinite(a) ? map(a) : end;
    return withMappedTime(e, new Date(Math.min(at, now)).toISOString(), map, { storyClock: "local" });
  });
  return { rows: out, map };
}

/** Ordinary rows the feed still owes before a phase of `attackRows` lands, given `noiseSince` already shown since the last phase. */
export function noiseQuota(attackRows: number, noiseSince: number): number {
  return Math.max(0, NOISE_PER_ATTACK_ROW * attackRows - noiseSince);
}

/** Times for `n` ordinary rows released with a phase: spread over (from, to], ascending. */
export function noiseTimes(n: number, from: number, to: number, rnd: () => number = Math.random): number[] {
  const lo = Math.min(from, to - 1_000);
  return Array.from({ length: n }, () => lo + Math.floor(rnd() * (to - lo))).sort((a, b) => a - b);
}
