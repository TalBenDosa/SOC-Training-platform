import { NextResponse } from "next/server";
import { asObject } from "@/lib/http/body";
import { requireOrgStaff } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { appendSystemEvent } from "@/lib/team/appendSystemEvent";

/**
 * Roster management for an existing team session (staff only, own org).
 *
 *  POST   — add a member to a role (or change the role of someone already on the
 *           roster). Lets an instructor grow / backfill the team while it's live.
 *  DELETE — remove a member (they become `left`: no more reads, writes or seat).
 *
 * Every change emits a system `member.added | member.role_changed | member.removed`
 * event, so every client refreshes its roster live (audit C3 — before this, the
 * other screens kept the old roster until a reload, so a reassigned seat never
 * cleared a coverage halt). The session owner (instructor row) can't be changed
 * here, and a roster is capped at 60 active members (realtime fan-out budget).
 */
const ADDABLE_ROLES = new Set(["t1", "t2", "t3", "mgr", "observer"]);
const SINGLE_SEAT = new Set(["t3", "mgr"]);
const MAX_ROSTER = 60;

async function loadSession(id: string, orgId: string | null, isPlatformAdmin: boolean) {
  const admin = getSupabaseAdminClient();
  if (!admin) return { error: NextResponse.json({ error: "Server not configured." }, { status: 503 }) } as const;
  const { data: sess } = await admin.from("team_sessions").select("id, org_id, status").eq("id", id).maybeSingle();
  if (!sess) return { error: NextResponse.json({ error: "Session not found." }, { status: 404 }) } as const;
  if (!isPlatformAdmin && sess.org_id !== orgId) return { error: NextResponse.json({ error: "Not your session." }, { status: 403 }) } as const;
  if (["ended", "debriefed"].includes(sess.status)) return { error: NextResponse.json({ error: "This session is closed — the roster can't change." }, { status: 409 }) } as const;
  return { admin, sess } as const;
}

export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const gate = await requireOrgStaff("team.session.member.add");
  if ("error" in gate) return gate.error;
  const { user } = gate;

  let body: Record<string, unknown> = {};
  try { body = asObject(await req.json()); } catch { /* validated below */ }
  const targetUserId = typeof body.user_id === "string" ? body.user_id : "";
  const role = typeof body.role === "string" ? body.role : "";
  if (!targetUserId || !ADDABLE_ROLES.has(role)) {
    return NextResponse.json({ error: "Provide a member (user_id) and a valid role." }, { status: 400 });
  }

  const loaded = await loadSession(id, user.orgId, user.isPlatformAdmin);
  if ("error" in loaded) return loaded.error;
  const { admin, sess } = loaded;

  // Invitee must be an ACTIVE member of this org.
  const { data: orgMem } = await admin.from("org_members")
    .select("user_id").eq("org_id", sess.org_id).eq("user_id", targetUserId).eq("status", "active").maybeSingle();
  if (!orgMem) return NextResponse.json({ error: "That user isn't an active member of your organisation." }, { status: 400 });

  const { data: roster, error: rosterErr } = await admin.from("team_session_members").select("user_id, role, status").eq("session_id", id);
  if (rosterErr) return NextResponse.json({ error: "Couldn't check that right now — nothing was changed. Please try again." }, { status: 503 });   // E-03: roster cap / single seats need the real roster
  const existing = (roster ?? []).find(m => m.user_id === targetUserId);
  if (existing?.role === "instructor") return NextResponse.json({ error: "The session owner's role can't be changed." }, { status: 409 });
  const active = (roster ?? []).filter(m => m.status !== "left").length;
  if (!existing && active >= MAX_ROSTER) return NextResponse.json({ error: `A session holds at most ${MAX_ROSTER} members.` }, { status: 409 });

  if (SINGLE_SEAT.has(role) && (roster ?? []).some(h => h.role === role && h.user_id !== targetUserId && h.status !== "left")) {
    return NextResponse.json({ error: `${role === "mgr" ? "SOC Manager" : "Tier-3"} is a single-seat role and is already filled.` }, { status: 409 });
  }

  if (existing) {
    const { error } = await admin.from("team_session_members")
      .update({ role, status: existing.status === "left" ? "invited" : existing.status }).eq("session_id", id).eq("user_id", targetUserId);
    if (error) { console.error("[team members] update:", error.message); return NextResponse.json({ error: "Couldn't update the member." }, { status: 500 }); }
    await appendSystemEvent(id, existing.status === "left" ? "member.added" : "member.role_changed",
      { user_id: targetUserId, role, from: existing.role, by: user.id });
    return NextResponse.json({ ok: true, user_id: targetUserId, role, updated: true });
  }

  const { error } = await admin.from("team_session_members")
    .insert({ session_id: id, user_id: targetUserId, role, status: "invited", invited_by: user.id });
  if (error) { console.error("[team members] insert:", error.message); return NextResponse.json({ error: "Couldn't add the member." }, { status: 500 }); }
  await appendSystemEvent(id, "member.added", { user_id: targetUserId, role, by: user.id });
  return NextResponse.json({ ok: true, user_id: targetUserId, role, added: true });
}

export async function DELETE(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const gate = await requireOrgStaff("team.session.member.remove");
  if ("error" in gate) return gate.error;
  const { user } = gate;

  let targetUserId = new URL(req.url).searchParams.get("user_id") ?? "";
  if (!targetUserId) { try { const b = await req.json(); if (typeof b?.user_id === "string") targetUserId = b.user_id; } catch { /* none */ } }
  if (!targetUserId) return NextResponse.json({ error: "Provide the member to remove (user_id)." }, { status: 400 });

  const loaded = await loadSession(id, user.orgId, user.isPlatformAdmin);
  if ("error" in loaded) return loaded.error;
  const { admin } = loaded;

  const { data: member } = await admin.from("team_session_members").select("role, status").eq("session_id", id).eq("user_id", targetUserId).maybeSingle();
  if (!member || member.status === "left") return NextResponse.json({ error: "That user isn't on this session's roster." }, { status: 404 });
  if (member.role === "instructor") return NextResponse.json({ error: "The session owner can't be removed." }, { status: 409 });

  const { error } = await admin.from("team_session_members").update({ status: "left" }).eq("session_id", id).eq("user_id", targetUserId);
  if (error) { console.error("[team members] remove:", error.message); return NextResponse.json({ error: "Couldn't remove the member." }, { status: 500 }); }
  await appendSystemEvent(id, "member.removed", { user_id: targetUserId, role: member.role, by: user.id });
  return NextResponse.json({ ok: true, user_id: targetUserId, removed: true });
}
