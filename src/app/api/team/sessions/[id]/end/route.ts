import { NextResponse } from "next/server";
import { requireOrgAdmin } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";

/**
 * End a team exercise (Phase 0.5) — staff only, own org. Flips the session to
 * 'ended' and emits a system session.ended event, which the broadcast trigger
 * fans out so every member's screen switches to the after-action report. The
 * report itself is derived from the append-only session_events log (client-side),
 * so ending is just this state transition.
 */
export async function POST(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const gate = await requireOrgAdmin("team.session.end");
  if ("error" in gate) return gate.error;
  const { user } = gate;
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  const { data: sess } = await admin.from("team_sessions").select("org_id, status").eq("id", id).maybeSingle();
  if (!sess) return NextResponse.json({ error: "Session not found." }, { status: 404 });
  if (!user.isPlatformAdmin && sess.org_id !== user.orgId) return NextResponse.json({ error: "Not your session." }, { status: 403 });
  if (["ended", "debriefed"].includes(sess.status)) return NextResponse.json({ ok: true, already: true });

  await admin.from("team_sessions").update({ status: "ended", ended_at: new Date().toISOString() }).eq("id", id);

  const { data: head } = await admin.from("session_events").select("seq").eq("session_id", id).order("seq", { ascending: false }).limit(1).maybeSingle();
  const nextSeq = (head?.seq ?? 0) + 1;
  await admin.from("session_events").insert({ session_id: id, seq: nextSeq, type: "session.ended", payload: { at: new Date().toISOString() } });
  await admin.from("session_state").upsert({ session_id: id, seq: nextSeq, updated_at: new Date().toISOString() });

  return NextResponse.json({ ok: true });
}
