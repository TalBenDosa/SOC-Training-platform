/**
 * Who runs Team Training (owner decision, 2026-11): only an organization admin of the
 * session's organization, or the platform owner (super-admin). The org role
 * `instructor` no longer creates, runs or sees everyone's report; an org instructor
 * an admin seats as a player (t1, t2, ...) has exactly a player's rights.
 *
 * Pure (no server imports), so the API routes, the server guard and the client pages
 * share one rule. Not to be confused with the session SEAT role "instructor"
 * (team_session_members.role): that seat runs the room, and only a team admin may hold
 * or use it (enforced in the routes and by migration 0106 in the database).
 */
export interface TeamAdminSubject {
  isPlatformAdmin?: boolean | null;
  orgRole?: string | null;
  orgId?: string | null;
}

/**
 * Is `user` a team admin for `orgId` (the session's organization; for creating a new
 * session, the caller's own org)? The platform owner always is. Fails closed: no user,
 * no org, or a different org means no.
 */
export function isTeamAdmin(user: TeamAdminSubject | null | undefined, orgId: string | null | undefined): boolean {
  if (!user) return false;
  if (user.isPlatformAdmin === true) return true;
  return user.orgRole === "org_admin" && !!user.orgId && !!orgId && user.orgId === orgId;
}

/** Shown where the create button was, and in the 403 an org instructor gets. */
export const TEAM_ADMIN_ONLY = "Team exercises are run by your organization admin.";
