import type { UserReport } from "./report/computeReport";

/**
 * XP a player earns for one team exercise — computed on the SERVER from the
 * after-action report (the same numbers everyone sees in the debrief), stored in
 * team_session_xp and summed into profiles.xp by recompute_user_xp (0087).
 * Team training used to award nothing at all.
 *
 * Per player, by their own activity:
 *   participation  25    — took at least one real action in the shift
 *   activity    0..50    — the report's contribution score (opens, triage,
 *                          escalations, acks, containment, role actions) ÷ 2
 *   performance 0..100   — the role rubric %, only when enough of it was
 *                          measured (insufficientEvidence ⇒ 0, not a guess)
 *   accuracy    0..25    — 2 per correct disposition + 5 per correct isolation
 * Capped at TEAM_XP_MAX. Instructors and observers earn nothing (they don't play).
 * Deterministic: the log is frozen once the session ends, so a recompute gives
 * the same number — awarding twice can't double-credit.
 */
export const TEAM_XP_VERSION = 1;
export const TEAM_XP_MAX = 200;

export function teamXpFor(u: Pick<UserReport, "role" | "opened" | "dispCount" | "dispCorrect" | "escCount" | "acks" | "contReq" | "contDecided" | "roleActions" | "contribution" | "rubricPct" | "insufficientEvidence" | "isoCorrect">): number {
  if (u.role === "instructor" || u.role === "observer") return 0;
  const actions = u.dispCount + u.escCount + u.acks + u.contReq + u.contDecided + u.roleActions;
  if (actions === 0) return 0;   // only opened logs (or nothing) — no credit for showing up
  const participation = 25;
  const activity = Math.round(Math.max(0, Math.min(100, u.contribution)) / 2);
  const performance = !u.insufficientEvidence && u.rubricPct != null ? Math.round(Math.max(0, Math.min(100, u.rubricPct))) : 0;
  const accuracy = Math.min(25, u.dispCorrect * 2 + u.isoCorrect * 5);
  return Math.min(TEAM_XP_MAX, participation + activity + performance + accuracy);
}
