import type { Ev } from "./types";

/**
 * Paused time never counts against the team (QA M3). While a session is paused
 * nobody can act — the DB refuses every action outside `running` — so an alert's
 * SLA age, a claim's 5-minute TTL, the AAR's MTTD / ack / triage latencies and
 * every "seconds into the shift" stamp measure RUNNING time only.
 *
 * The spans are rebuilt from the lifecycle events every client already holds
 * (session.paused / session.resumed / session.ended — team_transition appends them
 * in the same transaction as the status flip), so the live room and the server's
 * report agree, and the DB's claim check uses the same rule (0088 team_active_ms).
 * Pure: no clock reads — pass `openUntil` for a pause that is still running.
 */
export interface PauseSpan { start: number; end: number }

const tsOf = (e: Ev): number | null => {
  if (!e.occurred_at) return null;
  const t = Date.parse(e.occurred_at);
  return Number.isFinite(t) ? t : null;
};

/**
 * Paused spans in time order. A second `session.paused` while already paused (a
 * reason switch: coverage → manual) continues the same span; resumed / ended close
 * it. A pause still open at the end of the log runs to `openUntil` (default: the
 * last timestamp in the log).
 */
export function pausedSpans(events: Ev[], openUntil?: number): PauseSpan[] {
  const out: PauseSpan[] = [];
  let open: number | null = null;
  let last = -Infinity;
  const lifecycle = events.filter(e => e.type === "session.paused" || e.type === "session.resumed" || e.type === "session.ended")
    .slice().sort((a, b) => a.seq - b.seq);
  for (const e of events) { const t = tsOf(e); if (t != null && t > last) last = t; }
  for (const e of lifecycle) {
    const t = tsOf(e); if (t == null) continue;
    if (e.type === "session.paused") { if (open == null) open = t; continue; }
    if (open != null) { if (t > open) out.push({ start: open, end: t }); open = null; }
  }
  if (open != null) {
    const end = openUntil ?? last;
    if (Number.isFinite(end) && end > open) out.push({ start: open, end });
  }
  return out;
}

/** Paused milliseconds inside [a, b]. */
export function pausedBetween(a: number, b: number, spans: PauseSpan[]): number {
  if (!(b > a)) return 0;
  let p = 0;
  for (const s of spans) { const lo = Math.max(a, s.start), hi = Math.min(b, s.end); if (hi > lo) p += hi - lo; }
  return p;
}

/**
 * Running (un-paused) milliseconds from `a` to `b`. b < a keeps its plain negative
 * value, so callers that drop negative deltas (an ack paired with a later request)
 * behave exactly as before.
 */
export function activeMs(a: number, b: number, spans: PauseSpan[]): number {
  if (!(b > a)) return b - a;
  return b - a - pausedBetween(a, b, spans);
}

/** The wall-clock time at which `ms` of RUNNING time has passed since `from` (pauses skipped). */
export function addActive(from: number, ms: number, spans: PauseSpan[]): number {
  let t = from; let left = ms;
  for (const s of [...spans].sort((x, y) => x.start - y.start)) {
    if (s.end <= t) continue;
    if (s.start > t) {
      const run = s.start - t;
      if (run >= left) return t + left;
      left -= run;
    }
    t = Math.max(t, s.end);
  }
  return t + left;
}
