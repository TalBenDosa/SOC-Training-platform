import { NextResponse } from "next/server";
import { requireOrgStaff } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { buildTeamTimeline } from "@/lib/team/buildTimeline";
import { teamLoad } from "@/lib/team/load";
import { teamTransition } from "@/lib/team/transition";

/**
 * Start a team session — staff only, own org, LOBBY only (a paused session is
 * resumed via /pause, never re-started: re-starting used to reset started_at and
 * break the pause-aware pacing).
 *
 * Order matters (audit M1): mark the session schema v2 and seed the timeline
 * WHILE STILL IN THE LOBBY, then flip to running through `team_transition`, which
 * re-checks the ready-check under the session lock and appends session.started in
 * the same transaction. A seeding failure therefore leaves a retryable lobby
 * session instead of a "running" one with no feed.
 *
 * v2 = server-side presence/lifecycle, click telemetry off the log, and the
 * answer key kept OFF the wire: each inject's public `body` is what players
 * receive; the ground truth goes to the staff-only `expected_action` column.
 */
export async function POST(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const gate = await requireOrgStaff("team.session.start");
  if ("error" in gate) return gate.error;
  const { user } = gate;
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  const { data: sess } = await admin.from("team_sessions").select("id, org_id, status, company_id, difficulty, seed, scenario_id").eq("id", id).maybeSingle();
  if (!sess) return NextResponse.json({ error: "Session not found." }, { status: 404 });
  if (!user.isPlatformAdmin && sess.org_id !== user.orgId) {
    return NextResponse.json({ error: "Not your session." }, { status: 403 });
  }
  if (sess.status !== "lobby") {
    return NextResponse.json({ error: "This session has already started." }, { status: 409 });
  }

  // Friendly early answer; team_transition re-checks this under the lock.
  const { data: members, error: membersErr } = await admin.from("team_session_members").select("role, status").eq("session_id", id);
  // The roster sizes the whole shift (load.ts) — never start from an unread one.
  if (membersErr) return NextResponse.json({ error: "Couldn't read the team — please try again." }, { status: 503 });
  const notReady = (members ?? []).filter(m => m.role !== "instructor" && m.role !== "observer" && !["ready", "active", "left"].includes(m.status)).length;
  if (notReady > 0) return NextResponse.json({ error: `${notReady} player(s) not ready yet.` }, { status: 409 });

  // v2 + seed while still in the lobby (idempotent: only seeds once).
  const { error: verErr } = await admin.from("team_sessions").update({ schema_version: 2 }).eq("id", id).eq("status", "lobby");
  if (verErr) { console.error("[team start] set v2:", verErr.message); return NextResponse.json({ error: "Couldn't start the session." }, { status: 500 }); }

  // Seeded under the session lock (0072 team_seed_timeline): two concurrent
  // /start calls can no longer both see "0 injects" and double the feed.
  let seeded = 0;
  const { count } = await admin.from("session_injects").select("id", { count: "exact", head: true }).eq("session_id", id);
  if ((count ?? 0) === 0) {
    // Size the shift to the team in the room (load.ts): log pace from the Tier-1
    // count, attack count from the team size. The pace is stored on the session so
    // the DB refill (replenish_feed, 0081) keeps it instead of bursting.
    const load = teamLoad(sess.difficulty, members ?? []);
    const { error: paceErr } = await admin.from("team_sessions")
      .update({ feed_gap_ms: load.baseGapMs, feed_jitter_ms: load.jitterMs }).eq("id", id).eq("status", "lobby");
    if (paceErr) { console.error("[team start] set pace:", paceErr.message); return NextResponse.json({ error: "Couldn't start the session." }, { status: 500 }); }
    // scenario_id = the storyline staff picked in the builder (null → random pick).
    const timeline = buildTeamTimeline(sess.company_id, sess.difficulty, sess.seed, sess.scenario_id, load);
    if (timeline.length) {
      const rows = timeline.map(t => ({ due_offset_ms: t.due_offset_ms, channel: t.channel, body: t.body, expected_action: t.answer ?? null }));
      const { data: n, error: seedErr } = await admin.rpc("team_seed_timeline", { p_session: id, p_rows: rows });
      if (seedErr) { console.error("[team start] seed:", seedErr.message); return NextResponse.json({ error: "Couldn't prepare the exercise feed." }, { status: 500 }); }
      if (n === -1) return NextResponse.json({ error: "This session has already started." }, { status: 409 });
      seeded = typeof n === "number" ? n : 0;
    }
  }

  const t = await teamTransition(id, "running", "start", user.id);
  if ("error" in t) return NextResponse.json({ error: t.error }, { status: 500 });
  if (!t.result.ok) {
    if (t.result.error === "not_ready") return NextResponse.json({ error: `${t.result.count ?? "Some"} player(s) not ready yet.` }, { status: 409 });
    return NextResponse.json({ error: "Couldn't start the session." }, { status: 409 });
  }
  if (t.result.noop) return NextResponse.json({ error: "This session has already started." }, { status: 409 });
  return NextResponse.json({ ok: true, seeded });
}
