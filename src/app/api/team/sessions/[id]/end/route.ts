import { NextResponse } from "next/server";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";

/**
 * End a team exercise (Phase 0.5). Flips the session to 'ended' and emits a
 * system session.ended event, which the broadcast trigger fans out so every
 * member's screen switches to the after-action report. The report itself is
 * derived from the append-only session_events log (client-side), so ending is
 * just this state transition.
 *
 * Who can end it (the "runner"): staff of the session's org (platform admin /
 * org_admin / instructor) OR the session's SOC Manager (mgr), who holds the
 * coordinator authority. `reason` lets the caller distinguish a manual end from
 * an automatic one (e.g. the owner/instructor left the live room).
 */
export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const user = await getAuthedUser();
  if (!user) return NextResponse.json({ error: "Authentication required." }, { status: 401 });
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  let reason = "manual";
  try { const body = await req.json(); if (typeof body?.reason === "string") reason = body.reason.slice(0, 40); } catch { /* body optional */ }

  const { data: sess } = await admin.from("team_sessions").select("org_id, status").eq("id", id).maybeSingle();
  if (!sess) return NextResponse.json({ error: "Session not found." }, { status: 404 });

  const isStaff = user.isPlatformAdmin ||
    ((user.orgRole === "org_admin" || user.orgRole === "instructor") && user.orgId === sess.org_id);
  // The session's own SOC Manager may end it too (coordinator authority).
  let isManager = false;
  if (!isStaff) {
    const { data: mem } = await admin.from("team_session_members")
      .select("role").eq("session_id", id).eq("user_id", user.id).maybeSingle();
    isManager = mem?.role === "mgr";
  }
  if (!isStaff && !isManager) return NextResponse.json({ error: "Only the instructor or the SOC Manager can end the session." }, { status: 403 });

  if (["ended", "debriefed"].includes(sess.status)) return NextResponse.json({ ok: true, already: true });

  await admin.from("team_sessions").update({ status: "ended", ended_at: new Date().toISOString() }).eq("id", id);

  const { data: head } = await admin.from("session_events").select("seq").eq("session_id", id).order("seq", { ascending: false }).limit(1).maybeSingle();
  const nextSeq = (head?.seq ?? 0) + 1;
  await admin.from("session_events").insert({ session_id: id, seq: nextSeq, type: "session.ended", payload: { at: new Date().toISOString(), reason, by: user.id } });
  await admin.from("session_state").upsert({ session_id: id, seq: nextSeq, updated_at: new Date().toISOString() });

  return NextResponse.json({ ok: true });
}
