import { activeMs, type PauseSpan } from "../pauses";

/**
 * Shared timing for the SOC Manager's requests (decision cards and stakeholder questions).
 * Client-safe (pauses.ts is pure). Deadlines run on RUNNING time: a pause stops the clock,
 * as it does for alert SLAs and claims (QA-TEAM-4). Before, a pause longer than the
 * deadline closed an open card that nobody could have answered, and revealed its key.
 *
 * After a request's deadline the manager gets a short LATE window: the card or reply box stays,
 * marked late, and the draft is kept. The answer still counts, as late (the deadline cell and
 * the timeline show it). Feedback (best option, model answer) is only revealed once the request
 * is answered or the late window has closed, so a late answer can never copy the key.
 */
export const LATE_GRACE_S = 120;

export type RequestPhase = "open" | "late" | "closed";

/** Where a request stands at `now`: before its deadline, in the late window, or closed.
 *  `pauses` (pausedSpans) are not counted. */
export function requestPhase(firedAtMs: number, deadlineS: number, nowMs: number, pauses: PauseSpan[] = []): RequestPhase {
  const ran = activeMs(firedAtMs, nowMs, pauses);
  if (ran <= deadlineS * 1000) return "open";
  return ran <= (deadlineS + LATE_GRACE_S) * 1000 ? "late" : "closed";
}

/** Was a reply at `atMs` past the deadline (running time)? */
export function answeredLate(firedAtMs: number, deadlineS: number, atMs: number, pauses: PauseSpan[] = []): boolean {
  return activeMs(firedAtMs, atMs, pauses) > deadlineS * 1000;
}
