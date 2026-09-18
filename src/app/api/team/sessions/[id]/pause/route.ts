import { NextResponse } from "next/server";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { appendSystemEvent } from "@/lib/team/appendSystemEvent";

/**
 * Pause / resume a running team session (F7 — resilience). Persists the halt in
 * the DB so it survives a reload and shows as 'paused' in the session list, and
 * emits a system session.paused / session.resumed event that the broadcast
 * trigger fans out so every screen flips together.
 *
 * Two callers:
 *  - staff (instructor/admin) or the SOC Manager → a MANUAL pause/resume
 *    (reason "manual").
 *  - any session member's client → the AUTOMATIC coverage halt (reason
 *    "coverage") when the core relay loses/regains a Tier online. We can't
 *    verify presence server-side, so any member may drive the auto transition;
 *    the transition is a no-op unless the status actually needs to change.
 */
export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const user = await getAuthedUser();
  if (!user) return NextResponse.json({ error: "Authentication required." }, { status: 401 });
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  let paused = true, reason = "manual", detail = "";
  try {
    const b = await req.json();
    if (typeof b?.paused === "boolean") paused = b.paused;
    if (typeof b?.reason === "string") reason = b.reason.slice(0, 40);
    if (typeof b?.detail === "string") detail = b.detail.slice(0, 200);
  } catch { /* body optional; defaults to a manual pause */ }

  const { data: sess } = await admin.from("team_sessions").select("org_id, status, paused_at, paused_ms").eq("id", id).maybeSingle();
  if (!sess) return NextResponse.json({ error: "Session not found." }, { status: 404 });

  // Authorised = staff of the org, the session's SOC Manager, or any member (auto).
  const isStaff = user.isPlatformAdmin ||
    ((user.orgRole === "org_admin" || user.orgRole === "instructor") && user.orgId === sess.org_id);
  let isManager = false;
  let isMember = isStaff;
  if (!isStaff) {
    const { data: mem } = await admin.from("team_session_members").select("role").eq("session_id", id).eq("user_id", user.id).maybeSingle();
    isMember = !!mem;
    isManager = mem?.role === "mgr";
  }
  if (!isMember) return NextResponse.json({ error: "Not your session." }, { status: 403 });
  const privileged = isStaff || isManager;

  if (["ended", "debriefed"].includes(sess.status)) return NextResponse.json({ error: "This session is closed." }, { status: 409 });

  // S7: a MANUAL pause/resume is a human call — only staff or the SOC Manager. A
  // plain member's client may only drive the automatic coverage transition.
  if (reason === "manual" && !privileged) {
    return NextResponse.json({ error: "Only the instructor or the SOC Manager can pause/resume the session." }, { status: 403 });
  }

  // Only a running session can pause; only a paused one can resume. Anything else
  // is a harmless no-op (covers races where two clients both fire the transition).
  if (paused && sess.status !== "running") return NextResponse.json({ ok: true, noop: true });
  if (!paused && sess.status !== "paused") return NextResponse.json({ ok: true, noop: true });

  // S7: an automatic (coverage) resume must NOT clear a pause a human set manually —
  // only staff/Manager can lift a manual pause.
  if (!paused && !privileged) {
    const { data: lastPause } = await admin.from("session_events")
      .select("payload").eq("session_id", id).eq("type", "session.paused")
      .order("seq", { ascending: false }).limit(1).maybeSingle();
    if (((lastPause?.payload ?? {}) as { reason?: string }).reason === "manual") {
      return NextResponse.json({ ok: true, noop: true, kept: "manual_pause" });
    }
  }

  // Maintain the pause clock so injects don't burst-fire on resume: mark when the
  // pause began, and on resume fold the elapsed time into the cumulative paused_ms
  // (promote_due_injects shifts the timeline by paused_ms).
  const patch = paused
    ? { status: "paused", paused_at: new Date().toISOString() }
    : { status: "running", paused_at: null, paused_ms: (sess.paused_ms ?? 0) + Math.max(0, Date.now() - (sess.paused_at ? Date.parse(sess.paused_at) : Date.now())) };
  // The status guard makes concurrent transitions race-safe: only the first write
  // matches, so paused_ms is folded in exactly once.
  const { data: updated, error: upErr } = await admin.from("team_sessions").update(patch).eq("id", id).eq("status", sess.status).select("id");
  if (upErr) return NextResponse.json({ error: upErr.message }, { status: 500 });
  if (!updated || updated.length === 0) return NextResponse.json({ ok: true, noop: true }); // lost the race

  const ev = await appendSystemEvent(id, paused ? "session.paused" : "session.resumed",
    { at: new Date().toISOString(), reason, detail: detail || undefined, by: user.id });
  if (!ev.ok) return NextResponse.json({ error: ev.error }, { status: 500 });

  return NextResponse.json({ ok: true });
}
