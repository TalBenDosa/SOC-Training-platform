"use client";
import { useEffect, useState } from "react";

/**
 * Server clock for the team room (audit C5). Several rules compare "now" with a
 * server `occurred_at` — claim TTL (5 min), SLA badges, queue age, overload
 * detection. Using the browser's Date.now() made each of them wrong by that
 * machine's clock skew (a laptop 5 min fast saw every claim as expired, so two
 * Tier-1s worked the same alert). serverNow() = Date.now() + an offset estimated
 * from the API's Date header and tightened by every event we receive (an event's
 * server time can never be later than "server now" when it arrives).
 */
let offsetMs = 0;
let calibrated = false;

/** Estimate the offset from a response's Date header (1s resolution) and the request's round trip. */
export function calibrateFromDateHeader(dateHeader: string | null, sentAt: number, receivedAt: number): void {
  if (!dateHeader) return;
  const server = Date.parse(dateHeader);
  if (!Number.isFinite(server)) return;
  const est = server + 500 - (sentAt + receivedAt) / 2;   // +500: the header truncates to the second
  offsetMs = calibrated ? Math.max(offsetMs, est) : est;
  calibrated = true;
}

/** Tighten with an event's server timestamp: server now ≥ occurred_at at receipt. */
export function noteServerTimestamp(iso: string | undefined | null, receivedAt = Date.now()): void {
  if (!iso) return;
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return;
  const lowerBound = t - receivedAt;
  if (!calibrated || lowerBound > offsetMs) { offsetMs = lowerBound; calibrated = true; }
}

export function serverNow(): number {
  return Date.now() + offsetMs;
}

/** Test hook. */
export function _resetServerClock(offset = 0): void { offsetMs = offset; calibrated = false; }

/** Re-renders every `intervalMs` with the current server time, so SLA badges age without new events. */
export function useServerNow(intervalMs = 15_000): number {
  const [now, setNow] = useState(() => serverNow());
  useEffect(() => {
    const iv = setInterval(() => setNow(serverNow()), intervalMs);
    return () => clearInterval(iv);
  }, [intervalMs]);
  return now;
}
