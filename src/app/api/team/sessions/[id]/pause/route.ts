import { NextResponse } from "next/server";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { teamTransition } from "@/lib/team/transition";
import { logAudit } from "@/lib/audit/logAudit";

/**
 * Pause / resume a team session.
 *
 * v2 sessions (schema_version ≥ 2): a MANUAL human call — staff of the org or the
 * session's SOC Manager only. Automatic halts (a core Tier or the instructor went
 * missing) are decided SERVER-SIDE by the 0071 lifecycle tick from heartbeats, so
 * members no longer drive lifecycle from their browser at all.
 *
 * v1 (legacy) sessions keep the Phase-0 behavior so already-running rooms on the
 * old client don't break: a playing member's client may drive the automatic
 * `coverage` / `owner_left` pause, with server-built halt text, never an end.
 *
 * Every transition goes through the atomic `team_transition` (status + pause clock
 * + pause_reason + lifecycle event in one transaction). A manual pause over an
 * automatic one upgrades the reason to `manual`, so the tick never resumes it.
 */
const REASONS = new Set(["manual", "coverage", "owner_left"]);
const CORE_LABEL: Record<string, string> = { t1: "Tier-1", t2: "Tier-2" };

export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const user = await getAuthedUser();
  if (!user) return NextResponse.json({ error: "Authentication required." }, { status: 401 });
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  let paused = true, reason = "manual", detail = "";
  let missing: string[] = [], everyone = false;
  try {
    const b = await req.json();
    if (typeof b?.paused === "boolean") paused = b.paused;
    if (typeof b?.reason === "string") reason = b.reason;
    if (typeof b?.detail === "string") detail = b.detail.slice(0, 200);
    if (Array.isArray(b?.missing)) missing = b.missing.filter((r: unknown): r is string => typeof r === "string" && r in CORE_LABEL);
    everyone = b?.everyone === true;
  } catch { /* body optional; defaults to a manual pause */ }
  if (!REASONS.has(reason)) return NextResponse.json({ error: "Unknown pause reason." }, { status: 400 });

  const { data: sess } = await admin.from("team_sessions").select("org_id, status, schema_version, pause_reason").eq("id", id).maybeSingle();
  if (!sess) return NextResponse.json({ error: "Session not found." }, { status: 404 });

  const isStaff = user.isPlatformAdmin ||
    ((user.orgRole === "org_admin" || user.orgRole === "instructor") && user.orgId === sess.org_id);
  let isManager = false, isMember = isStaff, isObserver = false;
  if (!isStaff) {
    const { data: mem } = await admin.from("team_session_members").select("role, status").eq("session_id", id).eq("user_id", user.id).maybeSingle();
    isMember = !!mem && mem.status !== "left";
    isManager = isMember && mem?.role === "mgr";
    isObserver = mem?.role === "observer";
  }
  if (!isMember) return NextResponse.json({ error: "Not your session." }, { status: 403 });
  const privileged = isStaff || isManager;
  if (["ended", "debriefed"].includes(sess.status)) return NextResponse.json({ error: "This session is closed." }, { status: 409 });

  const v2 = (sess.schema_version ?? 1) >= 2;
  if (!privileged) {
    // v2: lifecycle is server-decided — members can't pause/resume.
    if (v2 || isObserver || reason === "manual") {
      return NextResponse.json({ error: "Only the instructor or the SOC Manager can pause/resume the session." }, { status: 403 });
    }
    // v1 legacy automatic halt: server-built text from a closed vocabulary.
    detail = reason === "owner_left"
      ? "The instructor dropped out of the live room — paused until they're back."
      : everyone ? "Everyone has left the exercise."
      : missing.length > 0 ? `No ${missing.map(r => CORE_LABEL[r]).join(" and no ")} online right now.` : "";
    // An automatic resume must never lift a pause a human set manually.
    if (!paused && sess.status === "paused") {
      let lastReason = sess.pause_reason as string | null;
      if (!lastReason) {
        const { data: lastPause } = await admin.from("session_events").select("payload")
          .eq("session_id", id).eq("type", "session.paused").order("seq", { ascending: false }).limit(1).maybeSingle();
        lastReason = ((lastPause?.payload ?? {}) as { reason?: string }).reason ?? null;
      }
      if (lastReason === "manual") return NextResponse.json({ ok: true, noop: true, kept: "manual_pause" });
    }
  } else {
    reason = "manual";
  }

  const t = await teamTransition(id, paused ? "paused" : "running", reason, user.id, detail || null);
  if ("error" in t) return NextResponse.json({ error: t.error }, { status: 500 });

  if (privileged) {
    await logAudit({ actorId: user.id, action: paused ? "team.session.pause" : "team.session.resume",
      targetTable: "team_sessions", targetId: id, metadata: { as: isStaff ? "staff" : "mgr", noop: !!t.result.noop } });
  }
  return NextResponse.json({ ok: true, noop: !!t.result.noop });
}
