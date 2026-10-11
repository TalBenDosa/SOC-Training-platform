/** Single-seat exercise roles: at most one non-left holder each (DB: 0093 team_session_single_manager).
 *  Tier-3 is multi-seat since 0093: several forensic analysts can split the hosts. */
export const SINGLE_SEAT = new Set(["mgr"]);
/** Members per session, the instructor included (realtime fan-out budget; DB: 0088 team_roster_cap). */
export const MAX_ROSTER = 60;

const seatName = (role: string) => (role === "mgr" ? "SOC Manager" : "Tier-3");

/**
 * QA L1: a route's cap / single-seat checks before a roster write are a friendly early
 * answer; the DB is the real gate. A concurrent write that loses the race comes back as
 * a 409 with the reason instead of a generic 500. Null = not a roster conflict.
 */
export function rosterConflict(error: { code?: string; message?: string } | null, role: string): string | null {
  if (!error) return null;
  const msg = error.message ?? "";
  if (/roster_full/.test(msg)) return `A session holds at most ${MAX_ROSTER} members.`;
  if (error.code === "23505") {
    if (/single_seat/.test(msg) && SINGLE_SEAT.has(role)) return `${seatName(role)} is a single-seat role and is already filled.`;
    return "That member is already on this session's roster.";
  }
  return null;
}
