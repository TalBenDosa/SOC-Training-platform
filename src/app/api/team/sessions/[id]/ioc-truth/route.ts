import { NextResponse } from "next/server";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { pageAll } from "@/lib/team/report/serverReport";
import { buildTeamIocTruth } from "@/lib/team/iocTruth";
import type { Ev } from "@/lib/team/types";

/**
 * GET /api/team/sessions/[id]/ioc-truth — the threat-intel verdicts for the IOCs in
 * the logs this session has shown so far.
 *
 * The team feed carries no answer key (schema v2 strips expected_verdict /
 * incident_id from every public log), and the "Check hash / IP / domain" lookup
 * used exactly that to know an attacker's IOC is bad — so in a team exercise a
 * malicious attachment hash or a C2 address came back CLEAN. The truth table is
 * built here, on the server, from the fired logs with their answers joined back
 * (the same buildIocTruth the scenario pages use), and only for logs already in
 * the feed. Keys are digests of (type, value); a lookup is what a real TI feed
 * would answer for an IOC the analyst is holding — not a per-log verdict.
 */
export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const user = await getAuthedUser();
  if (!user) return NextResponse.json({ error: "Authentication required." }, { status: 401 });
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  const { data: sess } = await admin.from("team_sessions").select("id, org_id").eq("id", id).maybeSingle();
  if (!sess) return NextResponse.json({ error: "Session not found." }, { status: 404 });
  const iAmStaff = user.isPlatformAdmin ||
    ((user.orgRole === "org_admin" || user.orgRole === "instructor") && user.orgId === sess.org_id);
  if (!iAmStaff) {
    const { data: mem } = await admin.from("team_session_members").select("status").eq("session_id", id).eq("user_id", user.id).maybeSingle();
    if (!mem || mem.status === "left") return NextResponse.json({ error: "Not your session." }, { status: 403 });
  }

  try {
    const events = await pageAll<Ev>((from, to) => admin.from("session_events")
      .select("seq, type, actor_id, role, payload, occurred_at").eq("session_id", id).eq("type", "feed.event")
      .order("seq").range(from, to));
    const injects = await pageAll<{ id: string; channel: string | null; expected_action: unknown }>((from, to) => admin.from("session_injects")
      .select("id, channel, expected_action").eq("session_id", id).eq("channel", "feed").not("fired_seq", "is", null)
      .order("id").range(from, to));
    const truth = buildTeamIocTruth(events, injects);
    return NextResponse.json(truth, { headers: { "Cache-Control": "private, no-store" } });
  } catch (e) {
    console.error("[team/ioc-truth] failed:", (e as Error).message);
    return NextResponse.json({ error: "Couldn't load threat intel — please try again." }, { status: 500 });
  }
}
