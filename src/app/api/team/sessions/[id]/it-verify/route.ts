import { NextResponse } from "next/server";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { activeSeat } from "@/lib/team/membership";
import { itVerifyAnswer } from "@/lib/sim/itVerify";
import type { TelemetryEvent } from "@/lib/sim/types";

/**
 * POST /api/team/sessions/[id]/it-verify  { event_id } — "Verify with IT" for one fired log.
 *
 * The team feed carries no answer key (schema v2 moves expected_verdict, it_verify_* and the
 * technique to the staff-only session_injects.expected_action), so the dashboard's client-side
 * answer had only the event type and severity to go on: an attacker's admin change at medium
 * severity came back "authorised change", an approved one at high severity "no ticket". The
 * answer is computed here from the log with its answer joined back (itVerifyAnswer, the same
 * rule the single-user dashboard uses) and only the IT reply leaves the server.
 * Same seat check and per-player lookup budget as the threat-intel route.
 */
export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const user = await getAuthedUser();
  if (!user) return NextResponse.json({ error: "Authentication required." }, { status: 401 });
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  const { data: sess } = await admin.from("team_sessions").select("id, org_id").eq("id", id).maybeSingle();
  if (!sess) return NextResponse.json({ error: "Session not found." }, { status: 404 });
  const iAmStaff = user.isPlatformAdmin ||
    ((user.orgRole === "org_admin" || user.orgRole === "instructor") && user.orgId === sess.org_id);
  if (!iAmStaff && !(await activeSeat(admin, id, sess.org_id, user.id))) {
    return NextResponse.json({ error: "Not your session." }, { status: 403 });
  }

  let eventId = "";
  try { const b = await req.json(); eventId = typeof b?.event_id === "string" ? b.event_id.slice(0, 120) : ""; } catch { /* validated below */ }
  if (!eventId) return NextResponse.json({ error: "Name the log to verify (event_id)." }, { status: 400 });

  const { data: allowed, error: rateErr } = await admin.rpc("team_ioc_lookup_allowed", { p_session: id, p_user: user.id, p_n: 1 });
  if (!rateErr && allowed === false) {
    return NextResponse.json({ error: "IT is busy with your earlier calls — wait a moment." }, { status: 429, headers: { "Retry-After": "15" } });
  }

  try {
    const { data: ev } = await admin.from("session_events").select("payload")
      .eq("session_id", id).eq("type", "feed.event").eq("payload->>id", eventId).limit(1).maybeSingle();
    const body = (ev?.payload ?? null) as Record<string, unknown> | null;
    if (!body) return NextResponse.json({ error: "That log isn't in this session's feed." }, { status: 404 });
    const injectId = typeof body.inject_id === "string" ? body.inject_id : null;
    let answer: Record<string, unknown> = {};
    if (injectId) {
      const { data: inj } = await admin.from("session_injects").select("expected_action").eq("id", injectId).maybeSingle();
      answer = (inj?.expected_action ?? {}) as Record<string, unknown>;
    }
    // The log as authored: public fields + the answer key's IT fields, technique and description.
    const merged = {
      ...body,
      description: (answer.authored_description as string | undefined) ?? body.description,
      mitre_technique: answer.mitre_technique ?? body.mitre_technique,
      fp_explanation: answer.fp_explanation,
      is_baseline: answer.is_baseline,
      it_verify_result: answer.it_verify_result,
      it_verify_message: answer.it_verify_message,
      it_context: answer.it_context,
      expected_verdict: undefined,
    } as unknown as TelemetryEvent;
    const verdict = typeof answer.expected_verdict === "string" ? answer.expected_verdict : undefined;
    const reply = itVerifyAnswer(merged, verdict);
    if (!reply) return NextResponse.json({ error: "IT has nothing on file for this kind of log." }, { status: 404 });
    return NextResponse.json(reply, { headers: { "Cache-Control": "private, no-store" } });
  } catch (e) {
    console.error("[team/it-verify] failed:", (e as Error).message);
    return NextResponse.json({ error: "Couldn't reach the IT Help Desk — please try again." }, { status: 500 });
  }
}
