import { NextResponse } from "next/server";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { teamTransition } from "@/lib/team/transition";
import { logAudit } from "@/lib/audit/logAudit";
import { activeSeat } from "@/lib/team/membership";

/**
 * End a team exercise. Staff of the session's org (platform admin / org_admin /
 * instructor) or the session's SOC Manager only — ending is irreversible, so it is
 * never driven by an automatic client signal (an instructor who drops out PAUSES
 * the session instead; see the 0071 lifecycle tick).
 *
 * `team_transition` flips the status, stamps ended_at, marks pending injects
 * 'skipped' and appends session.ended in ONE transaction (audit I3/I2), and the
 * broadcast trigger switches every screen to the after-action report.
 */
export async function POST(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const user = await getAuthedUser();
  if (!user) return NextResponse.json({ error: "Authentication required." }, { status: 401 });
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  const { data: sess } = await admin.from("team_sessions").select("org_id, status").eq("id", id).maybeSingle();
  if (!sess) return NextResponse.json({ error: "Session not found." }, { status: 404 });

  const isStaff = user.isPlatformAdmin ||
    ((user.orgRole === "org_admin" || user.orgRole === "instructor") && user.orgId === sess.org_id);
  let isManager = false;
  if (!isStaff) {
    const seat = await activeSeat(admin, id, sess.org_id, user.id);   // lapsed affiliation ⇒ no seat
    isManager = seat?.role === "mgr";
  }
  if (!isStaff && !isManager) return NextResponse.json({ error: "Only the instructor or the SOC Manager can end the session." }, { status: 403 });

  if (["ended", "debriefed"].includes(sess.status)) return NextResponse.json({ ok: true, already: true });

  const t = await teamTransition(id, "ended", "manual", user.id);
  if ("error" in t) return NextResponse.json({ error: t.error }, { status: 500 });

  await logAudit({ actorId: user.id, action: "team.session.end", targetTable: "team_sessions", targetId: id,
    metadata: { as: isStaff ? "staff" : "mgr", noop: !!t.result.noop } });
  return NextResponse.json({ ok: true, already: !!t.result.noop });
}
