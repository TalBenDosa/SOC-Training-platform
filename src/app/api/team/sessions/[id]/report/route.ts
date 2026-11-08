import { NextResponse, after } from "next/server";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import type { ServerReport } from "@/lib/team/report/serverReport";
import { redactManagerReview } from "@/lib/team/report/managerReview";
import { loadOrBuildReport, awardTeamXpOnce, awardedTeamXp, xpFromReport, ReportBuildingError } from "@/lib/team/awardTeamXp";
import { isTeamAdmin } from "@/lib/team/teamAdmin";

/**
 * GET /api/team/sessions/[id]/report — the server-authoritative after-action report.
 *
 * Only once the session has ENDED (the answer key is revealed at debrief, never
 * live). Readable by a team admin of the session's org or any member, including one who
 * left, so they still see their own card. Computed once from the full log (with
 * the staff-only answers joined back) and cached in team_session_reports, so every
 * viewer sees the same numbers and a whole class opening the AAR at once costs one
 * computation.
 *
 * Who sees what (owner decision 2026-11): only a team admin (isTeamAdmin: an org_admin of
 * the session's org, or the platform owner) sees everyone's card and XP (`seesAll`, which
 * also gates the CSV export). Everyone else, the trainee SOC Manager and an org instructor
 * seated as a player included, receives ONLY their own card and XP plus the team-level
 * numbers (S9). The Command Review is whole for a team admin and for the Manager it is
 * about; everyone else, the Lead included, gets it redacted.
 *
 * QA M5: the build is single-flight (a lease — only one request builds, the rest wait
 * for the cached row, else answer 503 `building` and the client retries), and a missing
 * XP award runs after the response instead of inside it.
 */
export const maxDuration = 60;

export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const user = await getAuthedUser();
  if (!user) return NextResponse.json({ error: "Authentication required." }, { status: 401 });
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  const { data: sess } = await admin.from("team_sessions").select("id, org_id, status").eq("id", id).maybeSingle();
  if (!sess) return NextResponse.json({ error: "Session not found." }, { status: 404 });

  const iAmTeamAdmin = isTeamAdmin(user, sess.org_id);
  const { data: mem } = await admin.from("team_session_members").select("role").eq("session_id", id).eq("user_id", user.id).maybeSingle();
  if (!iAmTeamAdmin && !mem) return NextResponse.json({ error: "Not your session." }, { status: 403 });
  if (!["ended", "debriefed"].includes(sess.status)) {
    return NextResponse.json({ error: "The after-action report is available once the session ends." }, { status: 409 });
  }

  // A report cached by an older scoring version is recomputed (the log is frozen
  // once ended, so a rebuild is deterministic — only the rules changed).
  let report: ServerReport;
  try {
    report = (await loadOrBuildReport(admin, id)).report;
  } catch (e) {
    if (e instanceof ReportBuildingError) {
      return NextResponse.json({ error: "The shift review is still being prepared — one moment…", building: true }, { status: 503, headers: { "Retry-After": "2" } });
    }
    console.error("[team report] build failed:", e instanceof Error ? e.message : String(e));
    return NextResponse.json({ error: "Couldn't build the report. Please try again." }, { status: 500 });
  }

  // Team training XP (0087): awarded at session end; this is the safety net for a
  // session ended by the reaper or whose award failed. Never blocks the report: the
  // numbers shown are the deterministic ones the award writes, and the award itself
  // runs after the response (one at a time per session).
  let xp = await awardedTeamXp(admin, id);
  const pending = !xp;
  if (!xp) {
    xp = xpFromReport(report);
    after(async () => {
      try { await awardTeamXpOnce(admin, id, report); }
      catch (e) { console.error("[team report] XP award failed:", e instanceof Error ? e.message : String(e)); }
    });
  }

  // The viewer's account total after the award, so the app's XP counter updates
  // without a reload (same pattern as the room completion route). While the award is
  // still pending the stored total is stale — send none, the counter keeps its value.
  const { data: me } = pending ? { data: null } : await admin.from("profiles").select("xp").eq("id", user.id).maybeSingle();

  const seesAll = iAmTeamAdmin;
  const xpShown = xp ? (seesAll ? xp : (user.id in xp ? { [user.id]: xp[user.id] } : {})) : {};
  return NextResponse.json({
    team: report.team,
    perUser: seesAll ? report.perUser : report.perUser.filter(u => u.user_id === user.id),
    // Command Review: a team admin and the Manager it is about get it whole; the rest of the
    // team (the Lead included) sees the command timeline and what was decided, without the grades.
    managerReview: report.managerReview == null ? null
      : iAmTeamAdmin || (mem?.role === "mgr" && report.managerReview.managerId === user.id) ? report.managerReview
      : redactManagerReview(report.managerReview),
    answers: report.answers,
    xp: xpShown,
    myTotalXp: typeof me?.xp === "number" ? me.xp : null,
    seesAll,
  });
}
