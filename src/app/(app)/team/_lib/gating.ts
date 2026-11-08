/**
 * Who sees which Team Training controls (owner decision 2026-11): only a team admin (an
 * org_admin of the session's organization, or the platform owner; isTeamAdmin) creates a
 * session, starts, pauses, ends, schedules, reassigns, manages seats, opens Debrief mode,
 * the Seats board and the answer key. An org instructor sees the sessions they are seated
 * in, with exactly the rights of that seat. The server enforces all of this; these helpers
 * only keep the pages from offering what the server would refuse.
 */
import { isTeamAdmin, TEAM_ADMIN_ONLY, type TeamAdminSubject } from "@/lib/team/teamAdmin";

/** The /team index for the signed-in user. */
export function teamIndexGate(ctx: TeamAdminSubject) {
  const admin = isTeamAdmin(ctx, ctx.orgId);
  return {
    /** The Session Builder and the create button. */
    canCreate: admin,
    /** Shown where the create button was, for an org instructor. */
    adminOnlyNote: !admin && ctx.orgRole === "instructor" ? TEAM_ADMIN_ONLY : null,
    emptyText: admin
      ? "No team sessions yet. Create one above."
      : "No team sessions yet. You'll see exercises here once your organization admin seats you in one.",
  };
}

/** `me` as GET /api/team/sessions/[id] returns it (is_staff = team admin of the session's org). */
export interface RoomMe { is_staff?: boolean | null; role: string | null }

/** The exercise room for the signed-in user. */
export function teamRoomGate(me: RoomMe | null | undefined) {
  const admin = !!me?.is_staff;
  return {
    /** Start, schedule, reassign, seat management, the workload check, Debrief mode. */
    admin,
    /** The Seats board and the exercise admin panel (attack schedule, answer key): a team
     *  admin in the instructor seat, or one with no seat in this session. */
    runsRoom: admin && (me?.role === "instructor" || !me?.role),
    /** Injects post as the session's instructor seat, so only a team admin holding it sends one. */
    canInject: admin && me?.role === "instructor",
    /** Pause / resume / end: a team admin, or the session's SOC Manager seat. */
    canRunShift: admin || me?.role === "mgr",
  };
}
