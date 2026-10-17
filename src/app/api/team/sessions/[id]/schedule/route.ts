import { NextResponse } from "next/server";
import { requireOrgStaff } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { logAudit } from "@/lib/audit/logAudit";
import { pendingAttacks, releasePlan, shiftElapsedMs, type PendingRow } from "@/lib/team/schedule";

/**
 * The attack schedule of a running team exercise (staff of the session's org only — the rows
 * carry the answer key). GET: the attacks that have not reached the feed, with the shift clock.
 * POST { incident? }: bring the next planned attack (or the named one, or the held bonus) forward
 * so it starts in a few seconds (2026-10-18 review: chosen attacks arrived after the session ended).
 */
async function load(id: string) {
  const gate = await requireOrgStaff("team.session.schedule");
  if ("error" in gate) return { error: gate.error } as const;
  const admin = getSupabaseAdminClient();
  if (!admin) return { error: NextResponse.json({ error: "Server not configured." }, { status: 503 }) } as const;
  const { data: sess } = await admin.from("team_sessions").select("id, org_id, status, started_at, paused_ms, paused_at").eq("id", id).maybeSingle();
  if (!sess) return { error: NextResponse.json({ error: "Session not found." }, { status: 404 }) } as const;
  if (!gate.user.isPlatformAdmin && sess.org_id !== gate.user.orgId) return { error: NextResponse.json({ error: "Not your session." }, { status: 403 }) } as const;
  const { data: rows, error } = await admin.from("session_injects").select("id, channel, due_offset_ms, expected_action")
    .eq("session_id", id).eq("status", "pending").in("channel", ["feed", "bonus"]).limit(2000);
  if (error) return { error: NextResponse.json({ error: "Couldn't read the schedule." }, { status: 500 }) } as const;
  return { admin, sess, rows: (rows ?? []) as PendingRow[], user: gate.user } as const;
}

export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const l = await load(id);
  if ("error" in l) return l.error;
  return NextResponse.json({ status: l.sess.status, elapsedMs: shiftElapsedMs(l.sess, Date.now()), pending: pendingAttacks(l.rows) });
}

export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const l = await load(id);
  if ("error" in l) return l.error;
  if (!["running", "paused"].includes(l.sess.status)) return NextResponse.json({ error: "The exercise isn't running." }, { status: 409 });
  const body = await req.json().catch(() => ({})) as { incident?: unknown };
  const incident = typeof body.incident === "string" && body.incident.length <= 200 ? body.incident : undefined;
  const plan = releasePlan(l.rows, shiftElapsedMs(l.sess, Date.now()), incident);
  if (!plan) return NextResponse.json({ error: "No attack is waiting to be released." }, { status: 409 });
  for (const u of plan.updates) {
    const { error } = await l.admin.from("session_injects")
      .update({ due_offset_ms: u.due_offset_ms, ...(u.channel ? { channel: u.channel } : {}) })
      .eq("id", u.id).eq("session_id", id).eq("status", "pending");
    if (error) { console.error("[team schedule] release:", error.message); return NextResponse.json({ error: "Couldn't release the attack." }, { status: 500 }); }
  }
  await logAudit({ actorId: l.user.id, action: "team.session.release_attack", targetTable: "team_sessions", targetId: id, metadata: { incident: plan.incident, rows: plan.updates.length } });
  return NextResponse.json({ ok: true, incident: plan.incident, rows: plan.updates.length });
}
