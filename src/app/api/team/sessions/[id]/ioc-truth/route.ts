import { NextResponse } from "next/server";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { pageAll } from "@/lib/team/report/serverReport";
import { buildTeamIocTruth, parseIocQuery, answerIocQuery } from "@/lib/team/iocTruth";
import { activeSeat } from "@/lib/team/membership";
import type { Ev } from "@/lib/team/types";

/**
 * POST /api/team/sessions/[id]/ioc-truth  { iocs: [{ type, value }] } — threat-intel
 * verdicts for the IOCs an analyst is holding.
 *
 * The team feed carries no answer key (schema v2 strips expected_verdict /
 * incident_id from every public log), and the "Check hash / IP / domain" lookup
 * used exactly that to know an attacker's IOC is bad — so in a team exercise a
 * malicious attachment hash or a C2 address came back CLEAN. The truth table is
 * built here, on the server, from the fired logs with their answers joined back
 * (the same buildIocTruth the scenario pages use).
 *
 * QA M4 — no longer a whole-feed oracle: the caller names the IOCs (≤ 20 per call,
 * a per-player budget in the DB — 0088 team_ioc_lookup_allowed), and only IOCs that
 * occur in a fired log the caller has OPENED (click telemetry) or that the team
 * escalated are answered. Staff (who hold the answer key anyway) may ask about any
 * fired log. Keys stay digests of (type, value).
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

  let body: unknown = null;
  try { body = await req.json(); } catch { /* validated below */ }
  const query = parseIocQuery(body);
  if (query.length === 0) return NextResponse.json({ error: "Name the indicators to look up (iocs: [{ type, value }])." }, { status: 400 });

  // Per-player budget. A missing function (before 0088) doesn't block lookups.
  const { data: allowed, error: rateErr } = await admin.rpc("team_ioc_lookup_allowed", { p_session: id, p_user: user.id, p_n: query.length });
  if (!rateErr && allowed === false) {
    return NextResponse.json({ error: "Too many threat-intel lookups — wait a moment." }, { status: 429, headers: { "Retry-After": "15" } });
  }

  try {
    const events = await pageAll<Ev>((from, to) => admin.from("session_events")
      .select("seq, type, actor_id, role, payload, occurred_at").eq("session_id", id).eq("type", "feed.event")
      .order("seq").range(from, to));
    const injects = await pageAll<{ id: string; channel: string | null; expected_action: unknown }>((from, to) => admin.from("session_injects")
      .select("id, channel, expected_action").eq("session_id", id).eq("channel", "feed").not("fired_seq", "is", null)
      .order("id").range(from, to));
    const truth = buildTeamIocTruth(events, injects);

    let inHand = events;
    if (!iAmStaff) {
      const opened = await pageAll<{ event_id: string | null }>((from, to) => admin.from("session_clicks")
        .select("event_id").eq("session_id", id).eq("user_id", user.id).order("id").range(from, to));
      const escalated = await pageAll<{ payload: { event_id?: unknown } | null }>((from, to) => admin.from("session_events")
        .select("payload").eq("session_id", id).eq("type", "escalation.requested").order("seq").range(from, to));
      const ids = new Set<string>([
        ...opened.map(o => o.event_id ?? "").filter(Boolean),
        ...escalated.map(e => String(e.payload?.event_id ?? "")).filter(Boolean),
      ]);
      inHand = events.filter(e => ids.has(String((e.payload as { id?: unknown }).id ?? "")));
    }
    return NextResponse.json(answerIocQuery(truth, query, inHand), { headers: { "Cache-Control": "private, no-store" } });
  } catch (e) {
    console.error("[team/ioc-truth] failed:", (e as Error).message);
    return NextResponse.json({ error: "Couldn't load threat intel — please try again." }, { status: 500 });
  }
}
