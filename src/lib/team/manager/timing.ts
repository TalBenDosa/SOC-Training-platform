/**
 * Shared timing for the SOC Manager's requests (decision cards and stakeholder questions).
 * Client-safe: no imports, so the room bundle stays light.
 *
 * After a request's deadline the manager gets a short LATE window: the card or reply box stays,
 * marked late, and the draft is kept. The answer still counts, as late (the deadline cell and
 * the timeline show it). Feedback (best option, model answer) is only revealed once the request
 * is answered or the late window has closed, so a late answer can never copy the key.
 */
export const LATE_GRACE_S = 120;

export type RequestPhase = "open" | "late" | "closed";

/** Where a request stands at `now`: before its deadline, in the late window, or closed. */
export function requestPhase(firedAtMs: number, deadlineS: number, nowMs: number): RequestPhase {
  const due = firedAtMs + deadlineS * 1000;
  if (nowMs <= due) return "open";
  return nowMs <= due + LATE_GRACE_S * 1000 ? "late" : "closed";
}
