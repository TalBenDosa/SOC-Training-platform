import { NextResponse } from "next/server";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { buildServerReport, type ServerReport } from "@/lib/team/report/serverReport";

/**
 * GET /api/team/sessions/[id]/report — the server-authoritative after-action report.
 *
 * Only once the session has ENDED (the answer key is revealed at debrief, never
 * live). Readable by staff of the session's org or any member — including one who
 * left, so they still see their own card. Computed once from the full log (with
 * the staff-only answers joined back) and cached in team_session_reports, so every
 * viewer sees the same numbers and a whole class opening the AAR at once costs one
 * computation. Non-staff, non-Manager viewers receive ONLY their own card (S9).
 */
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

  let report: ServerReport | null = null;
  const { data: cached } = await admin.from("team_session_reports").select("report").eq("session_id", id).maybeSingle();
  if (cached?.report) report = cached.report as ServerReport;
  if (!report) {
    try {
      report = await buildServerReport(admin, id);
    } catch (e) {
      console.error("[team report] build failed:", e instanceof Error ? e.message : String(e));
      return NextResponse.json({ error: "Couldn't build the report. Please try again." }, { status: 500 });
    }
    const { error: upErr } = await admin.from("team_session_reports")
      .upsert({ session_id: id, report, computed_at: new Date().toISOString() });
    if (upErr) console.error("[team report] cache write failed:", upErr.message);  // serve it anyway
  }

  const seesAll = iAmStaff || mem?.role === "mgr";
  return NextResponse.json({
    team: report.team,
    perUser: seesAll ? report.perUser : report.perUser.filter(u => u.user_id === user.id),
    answers: report.answers,
    seesAll,
  });
}
