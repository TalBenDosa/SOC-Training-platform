import { NextResponse } from "next/server";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { activeSeat } from "@/lib/team/membership";
import { buildMgrState } from "@/lib/team/manager/state";
import { pickCard, materialize } from "@/lib/team/manager/director";
import { loadSession, loadRoster, loadTeamEvents, criticalHostsOf } from "@/lib/team/manager/server";

/**
 * POST /api/team/sessions/[id]/director - the SOC-Manager incident director.
 *
 * Reads the live session (who is seated, escalations, containment requests and decisions,
 * isolations, scope, declarations, SITREPs, the team's own words) and fires at most ONE
 * decision card when the state makes one true (src/lib/team/manager). Nothing is scheduled on
 * the clock: a card exists only because something in the scenario happened. The room's
 * manager / staff clients call this every ~20 s; team_fire_card() makes firing atomic and
 * once-per-card, so concurrent calls are harmless. The answer key never leaves the server.
 */
export async function POST(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const user = await getAuthedUser();
  if (!user) return NextResponse.json({ error: "Authentication required." }, { status: 401 });
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  const sess = await loadSession(admin, id);
  if (!sess) return NextResponse.json({ error: "Session not found." }, { status: 404 });
  const iAmStaff = user.isPlatformAdmin || ((user.orgRole === "org_admin" || user.orgRole === "instructor") && user.orgId === sess.org_id);
  if (!iAmStaff && !(await activeSeat(admin, id, sess.org_id, user.id))) {
    return NextResponse.json({ error: "Not your session." }, { status: 403 });
  }
  if (sess.status !== "running" || (sess.schema_version ?? 1) < 2) return NextResponse.json({ fired: null });

  try {
    const [roster, events] = await Promise.all([loadRoster(admin, id), loadTeamEvents(admin, id)]);
    const s = buildMgrState({ events, roster, nowMs: Date.now(), difficulty: sess.difficulty, criticalHosts: criticalHostsOf(sess.company_id) });
    const pick = pickCard(s);
    if (!pick) return NextResponse.json({ fired: null });
    const { body, answer } = materialize(pick.def, pick.ctx, s, id);
    const { data: seq, error } = await admin.rpc("team_fire_card", { p_session: id, p_card: pick.def.id, p_body: body, p_answer: answer });
    if (error) throw new Error(error.message);
    return NextResponse.json({ fired: seq ? pick.def.id : null }, { headers: { "Cache-Control": "private, no-store" } });
  } catch (e) {
    console.error("[team/director] failed:", (e as Error).message);
    return NextResponse.json({ error: "Director unavailable." }, { status: 500 });
  }
}
