import { NextResponse } from "next/server";
import { requireOrgAdmin } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";

/**
 * Reassign a member's role in a running session (F7 — resilience to disconnects).
 * When a single-seat holder (Tier-3 / SOC Manager) drops, the relay stalls with
 * no one to hunt or approve containment. The instructor uses this to hand the
 * vacant seat to another connected member so the exercise keeps moving.
 *
 * Staff-only, own-org-only (same guard as start/end). Writes with the service
 * role, since team_session_members is not client-writable.
 */
const PLAY_ROLES = new Set(["t1", "t2", "t3", "mgr", "lead", "de", "ti", "instructor", "observer"]);

export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const gate = await requireOrgAdmin("team.session.reassign");
  if ("error" in gate) return gate.error;
  const { user } = gate;

  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  let body: Record<string, unknown> = {};
  try { body = await req.json(); } catch { /* required below */ }
  const targetUserId = typeof body.user_id === "string" ? body.user_id : "";
  const role = typeof body.role === "string" ? body.role : "";
  if (!targetUserId || !PLAY_ROLES.has(role)) {
    return NextResponse.json({ error: "Provide a member (user_id) and a valid role." }, { status: 400 });
  }

  const { data: sess } = await admin.from("team_sessions").select("id, org_id, status").eq("id", id).maybeSingle();
  if (!sess) return NextResponse.json({ error: "Session not found." }, { status: 404 });
  if (!user.isPlatformAdmin && sess.org_id !== user.orgId) {
    return NextResponse.json({ error: "Not your session." }, { status: 403 });
  }

  // Target must already be a member of this session (we reassign, not invite).
  const { data: member } = await admin.from("team_session_members")
    .select("user_id").eq("session_id", id).eq("user_id", targetUserId).maybeSingle();
  if (!member) return NextResponse.json({ error: "That user isn't a member of this session." }, { status: 404 });

  const { error } = await admin.from("team_session_members")
    .update({ role }).eq("session_id", id).eq("user_id", targetUserId);
  if (error) return NextResponse.json({ error: error.message }, { status: 500 });

  return NextResponse.json({ ok: true, user_id: targetUserId, role });
}
