import { NextResponse } from "next/server";
import { requireSuperAdmin } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import type { OrgMember, OrgStatus, OrgUsage } from "@/lib/org/types";

type Ctx = { params: Promise<{ id: string }> };

// ── GET /api/superadmin/orgs/[id] — detail + members + usage ────────────────
export async function GET(_req: Request, { params }: Ctx) {
  const gate = await requireSuperAdmin("superadmin.org.read");
  if ("error" in gate) return gate.error;
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });
  const { id } = await params;

  const { data: org, error } = await admin.from("organizations").select("*").eq("id", id).maybeSingle();
  if (error) return NextResponse.json({ error: error.message }, { status: 500 });
  if (!org) return NextResponse.json({ error: "Organization not found." }, { status: 404 });

  const { data: memberRows } = await admin
    .from("org_members")
    .select("org_id, user_id, role, status, joined_at, profiles(handle, display_name)")
    .eq("org_id", id)
    .order("joined_at", { ascending: true });

  const members: OrgMember[] = (memberRows ?? []).map(m => {
    const p = m.profiles as unknown as { handle?: string; display_name?: string } | null;
    return {
      org_id: m.org_id, user_id: m.user_id, role: m.role, status: m.status, joined_at: m.joined_at,
      handle: p?.handle ?? null, display_name: p?.display_name ?? null,
    };
  });

  // Usage aggregates for the org's cohort.
  const [xpRows, sessions, scenarios, rooms] = await Promise.all([
    admin.from("profiles").select("xp").eq("org_id", id),
    admin.from("dashboard_sessions").select("id", { count: "exact", head: true }).eq("org_id", id),
    admin.from("scenario_history").select("id", { count: "exact", head: true }).eq("org_id", id),
    admin.from("room_progress").select("user_id", { count: "exact", head: true }).eq("org_id", id).not("completed_at", "is", null),
  ]);
  const usage: OrgUsage = {
    members: members.filter(m => m.status === "active").length,
    total_xp: (xpRows.data ?? []).reduce((s, r) => s + (r.xp ?? 0), 0),
    sessions: sessions.count ?? 0,
    scenarios_completed: scenarios.count ?? 0,
    rooms_completed: rooms.count ?? 0,
  };

  return NextResponse.json({ org, members, usage });
}

// ── PATCH /api/superadmin/orgs/[id] — update license / status ───────────────
export async function PATCH(req: Request, { params }: Ctx) {
  const gate = await requireSuperAdmin("superadmin.org.update");
  if ("error" in gate) return gate.error;
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });
  const { id } = await params;

  let body: Record<string, unknown>;
  try { body = await req.json(); } catch { return NextResponse.json({ error: "Invalid JSON." }, { status: 400 }); }

  const patch: Record<string, unknown> = {};
  if (body.name !== undefined) patch.name = String(body.name).trim();
  if (body.seat_limit !== undefined) {
    const n = Number(body.seat_limit);
    if (!Number.isFinite(n) || n < 0) return NextResponse.json({ error: "Seat limit must be 0 or more." }, { status: 400 });
    patch.seat_limit = n;
  }
  if (body.starts_at !== undefined) patch.starts_at = body.starts_at ? new Date(String(body.starts_at)).toISOString() : null;
  if (body.expires_at !== undefined) patch.expires_at = body.expires_at ? new Date(String(body.expires_at)).toISOString() : null;
  if (body.status !== undefined) {
    const s = String(body.status);
    if (!["trial", "active", "suspended", "expired"].includes(s)) {
      return NextResponse.json({ error: "Invalid status." }, { status: 400 });
    }
    patch.status = s as OrgStatus;
  }
  if (body.allowed_domains !== undefined) {
    const raw = Array.isArray(body.allowed_domains) ? body.allowed_domains : [];
    patch.allowed_domains = [...new Set(
      raw.map(d => String(d).trim().toLowerCase().replace(/^@/, "")).filter(d => /^[^@\s]+\.[^@\s]+$/.test(d)),
    )];
  }
  if (Object.keys(patch).length === 0) return NextResponse.json({ error: "Nothing to update." }, { status: 400 });

  const { data: org, error } = await admin.from("organizations").update(patch).eq("id", id).select().single();
  if (error) return NextResponse.json({ error: error.message }, { status: 500 });
  return NextResponse.json({ org });
}

// ── DELETE /api/superadmin/orgs/[id] — hard delete (cascade) ────────────────
// Destructive: cascades to org_members/invitations and, via each learner
// table's org_id FK, orphans nothing — but the org's rows remain unless purged
// separately. The console requires typing the org name to confirm.
export async function DELETE(_req: Request, { params }: Ctx) {
  const gate = await requireSuperAdmin("superadmin.org.delete");
  if ("error" in gate) return gate.error;
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });
  const { id } = await params;

  // Refuse to delete the bootstrap/internal org.
  if (id === "d0d0d0d0-0000-4000-8000-000000000000") {
    return NextResponse.json({ error: "The internal org cannot be deleted." }, { status: 400 });
  }

  const { error } = await admin.from("organizations").delete().eq("id", id);
  if (error) return NextResponse.json({ error: error.message }, { status: 500 });
  return NextResponse.json({ ok: true });
}
