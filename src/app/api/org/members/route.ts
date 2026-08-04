import { NextResponse } from "next/server";
import { requireOrgAdmin } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import type { OrgMember, OrgUsage } from "@/lib/org/types";

/**
 * Org-admin roster management — always scoped to the CALLER'S OWN org (from
 * their JWT claim). A college admin can never touch another org: the org id
 * comes from getAuthedUser(), never from a request parameter. Uses the
 * service-role client for the writes, but every operation is pinned to
 * `user.orgId`.
 */

async function callerOrg() {
  const gate = await requireOrgAdmin("org.members");
  if ("error" in gate) return { error: gate.error };
  const orgId = gate.user.orgId;
  if (!orgId) return { error: NextResponse.json({ error: "No organisation in session." }, { status: 400 }) };
  const admin = getSupabaseAdminClient();
  if (!admin) return { error: NextResponse.json({ error: "Server not configured." }, { status: 503 }) };
  return { orgId, admin, userId: gate.user.id };
}

// ── GET — roster + usage for the admin's own org ────────────────────────────
export async function GET() {
  const c = await callerOrg();
  if ("error" in c) return c.error;
  const { orgId, admin } = c;

  const { data: org } = await admin.from("organizations").select("id, name, slug, seat_limit, status, expires_at").eq("id", orgId).maybeSingle();
  const { data: memberRows } = await admin
    .from("org_members")
    .select("org_id, user_id, role, status, joined_at, profiles(handle, display_name, xp)")
    .eq("org_id", orgId)
    .order("joined_at", { ascending: true });

  const members: (OrgMember & { xp?: number })[] = (memberRows ?? []).map(m => {
    const p = m.profiles as unknown as { handle?: string; display_name?: string; xp?: number } | null;
    return {
      org_id: m.org_id, user_id: m.user_id, role: m.role, status: m.status, joined_at: m.joined_at,
      handle: p?.handle ?? null, display_name: p?.display_name ?? null, xp: p?.xp ?? 0,
    };
  });

  const [sessions, scenarios, rooms] = await Promise.all([
    admin.from("dashboard_sessions").select("id", { count: "exact", head: true }).eq("org_id", orgId),
    admin.from("scenario_history").select("id", { count: "exact", head: true }).eq("org_id", orgId),
    admin.from("room_progress").select("user_id", { count: "exact", head: true }).eq("org_id", orgId).not("completed_at", "is", null),
  ]);
  const usage: OrgUsage = {
    members: members.filter(m => m.status === "active").length,
    total_xp: members.reduce((s, m) => s + (m.xp ?? 0), 0),
    sessions: sessions.count ?? 0,
    scenarios_completed: scenarios.count ?? 0,
    rooms_completed: rooms.count ?? 0,
  };

  return NextResponse.json({ org, members, usage });
}

// ── POST — attach an existing account by email to the admin's org ───────────
export async function POST(req: Request) {
  const c = await callerOrg();
  if ("error" in c) return c.error;
  const { orgId, admin } = c;

  let body: Record<string, unknown>;
  try { body = await req.json(); } catch { return NextResponse.json({ error: "Invalid JSON." }, { status: 400 }); }
  const email = String(body.email ?? "").trim();
  // Org-admins may only add students/instructors, not other org-admins.
  const role = ["student", "instructor"].includes(String(body.role)) ? String(body.role) : "student";
  if (!email) return NextResponse.json({ error: "Email is required." }, { status: 400 });

  const { data: userId, error: lookupErr } = await admin.rpc("find_user_id_by_email", { p_email: email });
  if (lookupErr) return NextResponse.json({ error: lookupErr.message }, { status: 500 });
  if (!userId) return NextResponse.json({ error: `No account exists for ${email}. Send them your class invite link instead.` }, { status: 404 });

  const { error } = await admin.rpc("attach_member_if_seat_available", { p_org: orgId, p_user: userId, p_role: role });
  if (error) {
    if (error.message.includes("seat_limit_reached")) return NextResponse.json({ error: "Your organisation has reached its seat limit." }, { status: 409 });
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
  return NextResponse.json({ ok: true });
}

// ── DELETE — remove a member from the admin's org ───────────────────────────
export async function DELETE(req: Request) {
  const c = await callerOrg();
  if ("error" in c) return c.error;
  const { orgId, admin, userId: adminId } = c;

  let body: Record<string, unknown>;
  try { body = await req.json(); } catch { return NextResponse.json({ error: "Invalid JSON." }, { status: 400 }); }
  const target = String(body.user_id ?? "").trim();
  if (!target) return NextResponse.json({ error: "user_id is required." }, { status: 400 });
  if (target === adminId) return NextResponse.json({ error: "You can't remove yourself." }, { status: 400 });

  const { error } = await admin.from("org_members").delete().eq("org_id", orgId).eq("user_id", target);
  if (error) return NextResponse.json({ error: error.message }, { status: 500 });
  await admin.from("profiles").update({ org_id: "d0d0d0d0-0000-4000-8000-000000000000" }).eq("id", target);
  return NextResponse.json({ ok: true });
}
