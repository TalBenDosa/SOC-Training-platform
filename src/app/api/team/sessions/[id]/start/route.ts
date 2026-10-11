import { NextResponse } from "next/server";
import { tenantFromConfig } from "@/lib/team/tenant";
import { envFromConfig } from "@/lib/team/environment";
import { planFromConfig, pinnedIds, loadWithPlan } from "@/lib/team/attackPlan";
import { requireOrgStaff } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { buildTeamTimeline, resolveTeamStory, teamStoryFilter } from "@/lib/team/buildTimeline";
import { teamLoad } from "@/lib/team/load";
import { teamTransition } from "@/lib/team/transition";
import { sanitizeStack } from "@/lib/logs/native/stack";

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

  const { data: sess } = await admin.from("team_sessions").select("id, org_id, status, company_id, difficulty, seed, scenario_id, config").eq("id", id).maybeSingle();
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
  // QA L7: a shift with nobody to play it would only pause itself for coverage.
  if (!(members ?? []).some(m => m.role !== "instructor" && m.role !== "observer" && m.status !== "left")) {
    return NextResponse.json({ error: "Add at least one player before starting." }, { status: 409 });
  }

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
    // The instructor's attack plan sets the concurrent attack count (else the team's size does).
    const plan = planFromConfig(sess.config, sess.scenario_id);
    const load = loadWithPlan(teamLoad(sess.difficulty, members ?? []), plan);
    const { error: paceErr } = await admin.from("team_sessions")
      .update({ feed_gap_ms: load.baseGapMs, feed_jitter_ms: load.jitterMs }).eq("id", id).eq("status", "lobby");
    if (paceErr) { console.error("[team start] set pace:", paceErr.message); return NextResponse.json({ error: "Couldn't start the session." }, { status: 500 }); }
    // scenario_id = the storyline staff picked in the builder (null → random pick).
    const stack = sanitizeStack((sess.config as { stack?: unknown } | null)?.stack);
    const env = envFromConfig(sess.config);
    // QA M7: a pinned storyline is re-checked here (content can change between create
    // and start) with the same predicate the builder used — never forced in unseen.
    if (pinnedIds(plan).length) {
      const fits = teamStoryFilter(sess.company_id, stack, env);
      for (const sid of pinnedIds(plan)) {
        const pinned = resolveTeamStory(sess.company_id, sess.difficulty, sid, env, stack);
        if (pinned && !fits(pinned)) {
          return NextResponse.json({ error: `The chosen storyline "${pinned.title}" can no longer run on this session's products. Close this lobby and create the session again with another storyline (or a random one).` }, { status: 409 });
        }
      }
    }
    // QA L7: a build failure is a clear, retryable error — the session stays in the lobby.
    let timeline: ReturnType<typeof buildTeamTimeline>;
    try { timeline = buildTeamTimeline(sess.company_id, sess.difficulty, sess.seed, plan.slots, load, stack, tenantFromConfig(sess.config), env, { bonus: plan.bonus }); }
    catch (e) {
      console.error("[team start] timeline build:", e instanceof Error ? e.message : String(e));
      return NextResponse.json({ error: "Couldn't build the exercise feed for this company and difficulty — nothing was started. Try again, or create the session with another storyline." }, { status: 500 });
    }
    if (!timeline.length) return NextResponse.json({ error: "Couldn't build the exercise feed — nothing was started. Try again." }, { status: 500 });
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
