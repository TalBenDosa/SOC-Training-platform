/**
 * When a team exercise is over, its EDR console closes (Tal, 2026-10-23: the trainees kept
 * working in the EDR tab after the instructor ended the session).
 *
 * The room tab and the EDR tab are separate tabs: the room writes a per-session marker to
 * localStorage when it sees the end (its `storage` event reaches the EDR tab at once), and the
 * EDR tab also asks the server, so a tab opened later or a room tab that was closed never leaves
 * the console usable.
 */
export const teamEndedKey = (sessionId: string) => `team_session_ended_${sessionId}`;

/** Statuses after which the exercise is over. A paused session is still running. */
const OVER = new Set(["ended", "debriefed"]);

/** Is the team session closed, given the server's answer (HTTP status + session status)? */
export function teamSessionClosed(httpStatus: number, sessionStatus: string | null | undefined): boolean {
  // Removed from the session (403) or the session is gone (404): nothing to investigate any more.
  if (httpStatus === 403 || httpStatus === 404) return true;
  if (httpStatus < 200 || httpStatus >= 300) return false;   // a transient error never locks the analyst out
  return OVER.has(String(sessionStatus ?? "").toLowerCase());
}

/** The room tab marks the session over for its EDR tabs. */
export function markTeamSessionEnded(sessionId: string): void {
  try { localStorage.setItem(teamEndedKey(sessionId), String(Date.now())); } catch { /* storage blocked */ }
}

export function teamSessionMarkedEnded(sessionId: string): boolean {
  try { return !!localStorage.getItem(teamEndedKey(sessionId)); } catch { return false; }
}
