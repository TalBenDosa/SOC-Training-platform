/**
 * Session Builder rules (exercise-report #18) — pure, so the page and its tests
 * agree on exactly why "Create & open lobby" is disabled and what to do about it.
 *
 * The REAL server rules (POST /api/team/sessions) are: invitees must be active
 * members of the caller's org, at most MAX_INVITES are taken at creation (the rest
 * were silently dropped before), and the SOC Manager is single-seat (Tier-3 is multi-seat since 0093). The builder
 * additionally requires at least one invitee — a lobby with no players can't run a
 * shift (see the dry-run note in the exercise report). Missing Tier-1 / Tier-2 is a
 * warning, not a blocker: an instructor may deliberately run a partial team.
 */

export interface Candidate { user_id: string; display_name: string | null; handle: string | null; role?: string }

/** Server cap on invitees accepted by POST /api/team/sessions (`.slice(0, 12)`). */
export const MAX_INVITES = 12;

/** Case-insensitive match on display name or handle ("@handle" also works). */
export function matchesCandidate(m: Candidate, query: string): boolean {
  const q = query.trim().toLowerCase().replace(/^@/, "");
  if (!q) return true;
  return [m.display_name, m.handle].some(v => !!v && v.toLowerCase().includes(q));
}

/**
 * Filter the roster by a search query. Picked members always stay visible so a
 * search can't hide someone you've already assigned (and their role picker).
 * A full e-mail query switches to exact matching: only the member the server
 * resolved that address to (`emailMatch`, a user_id or null) is shown — the list
 * itself carries no addresses to match against.
 */
export function filterCandidates<T extends Candidate>(members: T[], query: string, picked: Record<string, string> = {}, emailMatch: string | null = null): T[] {
  const byEmail = looksLikeEmail(query);
  return members.filter(m => !!picked[m.user_id] || (byEmail ? m.user_id === emailMatch : matchesCandidate(m, query)));
}

/** Looks like a full e-mail address → resolve it server-side (exact match only). */
export function looksLikeEmail(q: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(q.trim());
}

export interface BuilderState {
  rosterLoading: boolean;
  rosterError: string | null;
  rosterCount: number;
  orgName: string | null;
  picked: Record<string, string>;   // user_id -> role
}

export interface BuilderStatus {
  canCreate: boolean;
  /** Why the button is disabled + what to do — null when it's enabled. */
  blocker: string | null;
  /** Non-blocking coverage warnings. */
  warnings: string[];
}

export function builderStatus(s: BuilderState): BuilderStatus {
  const roles = Object.values(s.picked);
  const n = roles.length;
  const org = s.orgName ?? "your organisation";

  let blocker: string | null = null;
  if (s.rosterLoading) blocker = `Loading the members of ${org}…`;
  else if (s.rosterError) blocker = `Couldn't load who you can invite (${s.rosterError}). Reload the page to try again.`;
  else if (s.rosterCount === 0) blocker = `Nobody else in ${org} to invite yet. Add students first (Manage Class → share your class code, or add them by e-mail), then come back.`;
  else if (n === 0) blocker = "Select at least one member below and give them a role — the button unlocks once someone is on the roster.";
  else if (n > MAX_INVITES) blocker = `At most ${MAX_INVITES} members can be invited when the lobby is created (you picked ${n}). Remove ${n - MAX_INVITES}, then add the rest from inside the lobby with "Add a member".`;

  const warnings: string[] = [];
  if (n > 0 && !roles.includes("t1")) {
    warnings.push("No Tier-1 assigned — with no analyst triaging the feed, nothing will get escalated. Add at least one Tier-1.");
  } else if (n > 0 && !roles.some(r => r === "t2" || r === "t3")) {
    // U5: without a Tier-2, every escalation dead-ends in the queue.
    warnings.push("No Tier-2 or Tier-3 assigned — Tier-1 escalations will have nobody to pick them up. Add a Tier-2 investigator.");
  }
  return { canCreate: blocker === null, blocker, warnings };
}
