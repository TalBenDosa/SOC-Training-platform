import { NextResponse } from "next/server";
import { requireOrgStaff } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { buildTeamTimeline } from "@/lib/team/buildTimeline";
import { appendSystemEvent } from "@/lib/team/appendSystemEvent";

/**
 * Start a team session (Phase 0.4) — staff only, and only for their own org.
 * Enforces the lobby ready-check, flips the session to running, emits a system
 * session.started event (which the broadcast trigger fans out so every member's
 * countdown fires), and seeds the REAL telemetry timeline into session_injects.
 * pg_cron promotes those on time; the shared feed then streams identically to
 * everyone. Authorised here; done with the service-role client so seeding isn't
 * blocked by the append-only RLS on session_events.
 */
export async function POST(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const gate = await requireOrgStaff("team.session.start");
  if ("error" in gate) return gate.error;
  const { user } = gate;
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  const { data: sess } = await admin.from("team_sessions").select("*").eq("id", id).maybeSingle();
  if (!sess) return NextResponse.json({ error: "Session not found." }, { status: 404 });
  if (!user.isPlatformAdmin && sess.org_id !== user.orgId) {
    return NextResponse.json({ error: "Not your session." }, { status: 403 });
  }
  if (!["lobby", "paused"].includes(sess.status)) {
    return NextResponse.json({ error: "This session has already started." }, { status: 409 });
  }

  // Ready-check: every non-instructor member must be ready/active.
  const { data: members } = await admin.from("team_session_members")
    .select("role, status").eq("session_id", id);
  const notReady = (members ?? []).filter(m => m.role !== "instructor" && m.role !== "observer" && !["ready", "active"].includes(m.status)).length;
  if (notReady > 0) return NextResponse.json({ error: `${notReady} player(s) not ready yet.` }, { status: 409 });

  // Flip to running.
  const { error: upErr } = await admin.from("team_sessions")
    .update({ status: "running", started_at: new Date().toISOString() })
    .eq("id", id).in("status", ["lobby", "paused"]);
  if (upErr) return NextResponse.json({ error: upErr.message }, { status: 500 });

  // System session.started event (broadcast trigger → clients start their countdown).
  const started = await appendSystemEvent(id, "session.started", { at: new Date().toISOString() });
  if (!started.ok) return NextResponse.json({ error: started.error }, { status: 500 });

  // Seed the REAL telemetry timeline (idempotent-ish: skip if already seeded).
  const { count } = await admin.from("session_injects").select("id", { count: "exact", head: true }).eq("session_id", id);
  let seeded = 0;
  if ((count ?? 0) === 0) {
    const timeline = buildTeamTimeline(sess.company_id, sess.difficulty, sess.seed);
    if (timeline.length) {
      const rows = timeline.map(t => ({
        session_id: id, due_offset_ms: t.due_offset_ms,
        trigger: { kind: "at_time" }, channel: t.channel, body: t.body, status: "pending",
      }));
      const { error: seedErr } = await admin.from("session_injects").insert(rows);
      if (seedErr) return NextResponse.json({ error: seedErr.message }, { status: 500 });
      seeded = rows.length;
    }
  }

  return NextResponse.json({ ok: true, seeded });
}
