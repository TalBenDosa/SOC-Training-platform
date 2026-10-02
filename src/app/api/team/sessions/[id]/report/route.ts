import { NextResponse, after } from "next/server";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import type { ServerReport } from "@/lib/team/report/serverReport";
import { loadOrBuildReport, awardTeamXpOnce, awardedTeamXp, xpFromReport, ReportBuildingError } from "@/lib/team/awardTeamXp";

/**
 * GET /api/team/sessions/[id]/report — the server-authoritative after-action report.
 *
 * Only once the session has ENDED (the answer key is revealed at debrief, never
 * live). Readable by staff of the session's org or any member — including one who
 * left, so they still see their own card. Computed once from the full log (with
 * the staff-only answers joined back) and cached in team_session_reports, so every
 * viewer sees the same numbers and a whole class opening the AAR at once costs one
 * computation. Non-staff, non-Manager viewers receive ONLY their own card (S9).
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

  const iAmStaff = user.isPlatformAdmin ||
    ((user.orgRole === "org_admin" || user.orgRole === "instructor") && user.orgId === sess.org_id);
  const { data: mem } = await admin.from("team_session_members").select("role").eq("session_id", id).eq("user_id", user.id).maybeSingle();
  if (!iAmStaff && !mem) return NextResponse.json({ error: "Not your session." }, { status: 403 });
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

  const seesAll = iAmStaff || mem?.role === "mgr";
  const xpShown = xp ? (seesAll ? xp : (user.id in xp ? { [user.id]: xp[user.id] } : {})) : {};
  return NextResponse.json({
    team: report.team,
    perUser: seesAll ? report.perUser : report.perUser.filter(u => u.user_id === user.id),
    answers: report.answers,
    xp: xpShown,
    myTotalXp: typeof me?.xp === "number" ? me.xp : null,
    seesAll,
  });
}
