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
  if (body.branding !== undefined && body.branding && typeof body.branding === "object") {
    const b = body.branding as Record<string, unknown>;
    const branding: Record<string, string> = {};
    // Accept a hex accent colour and an https logo URL only.
    if (typeof b.color === "string" && /^#[0-9a-fA-F]{6}$/.test(b.color)) branding.color = b.color;
    if (typeof b.logo_url === "string" && /^https:\/\/\S+$/.test(b.logo_url)) branding.logo_url = b.logo_url.slice(0, 500);
    patch.branding = branding;
  }
  // Commercial record (migration 0020). Whitelisted + length-capped rather than
  // stored as free-form client JSON: the org can read its own row under the
  // existing RLS policy, so this must never become an arbitrary blob store.
  if (body.contract !== undefined && body.contract && typeof body.contract === "object") {
    const c = body.contract as Record<string, unknown>;
    const contract: Record<string, string | number> = {};
    const str = (v: unknown, max: number) => typeof v === "string" && v.trim() ? v.trim().slice(0, max) : undefined;

    const plan = str(c.plan, 80);                 if (plan) contract.plan = plan;
    const po = str(c.po_number, 80);              if (po) contract.po_number = po;
    const currency = str(c.currency, 8);          if (currency) contract.currency = currency.toUpperCase();
    const notes = str(c.notes, 2000);             if (notes) contract.notes = notes;

    if (c.seats_purchased !== undefined && c.seats_purchased !== "" && c.seats_purchased !== null) {
      const n = Number(c.seats_purchased);
      if (!Number.isFinite(n) || n < 0) return NextResponse.json({ error: "Seats purchased must be 0 or more." }, { status: 400 });
      contract.seats_purchased = Math.floor(n);
    }
    if (c.price !== undefined && c.price !== "" && c.price !== null) {
      const p = Number(c.price);
      if (!Number.isFinite(p) || p < 0) return NextResponse.json({ error: "Price must be 0 or more." }, { status: 400 });
      contract.price = p;
    }
    if (c.signed_at !== undefined && c.signed_at !== null && c.signed_at !== "") {
      const d = new Date(String(c.signed_at));
      if (Number.isNaN(d.getTime())) return NextResponse.json({ error: "Invalid signed date." }, { status: 400 });
      contract.signed_at = d.toISOString();
    }
    patch.contract = contract;
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

  // Atomic purge: deletes the college's learner data, re-homes its accounts to
  // the internal org (so logins survive), then removes the org. Export first.
  const { error } = await admin.rpc("purge_org", { p_org: id });
  if (error) {
    if (error.message.includes("cannot_purge_internal")) {
      return NextResponse.json({ error: "The internal org cannot be deleted." }, { status: 400 });
    }
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
  return NextResponse.json({ ok: true });
}
