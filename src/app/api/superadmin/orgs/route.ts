import { NextResponse } from "next/server";
import { requireSuperAdmin } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import type { OrgSummary, OrgStatus } from "@/lib/org/types";

/**
 * Super-admin org collection. All access gated by requireSuperAdmin (the
 * platform owner), which fails closed until the multi-tenancy hook is live —
 * so this endpoint is dormant and unreachable before the migrations run.
 * Uses the service-role client deliberately: the super-admin operates ACROSS
 * orgs, which is exactly the cross-tenant view RLS forbids for everyone else.
 */

function isActive(status: OrgStatus, expiresAt: string | null): boolean {
  if (status !== "active" && status !== "trial") return false;
  return !expiresAt || new Date(expiresAt).getTime() > Date.now();
}

function normalizeSlug(raw: string): string {
  return raw.trim().toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 40);
}

// ── GET /api/superadmin/orgs — list all orgs with seat usage ────────────────
export async function GET() {
  const gate = await requireSuperAdmin("superadmin.orgs.list");
  if ("error" in gate) return gate.error;

  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured for admin operations." }, { status: 503 });

  const { data: orgs, error } = await admin
    .from("organizations")
    .select("*")
    .order("created_at", { ascending: false });
  if (error) return NextResponse.json({ error: error.message }, { status: 500 });

  // One pass over active memberships → seats per org.
  const { data: members } = await admin.from("org_members").select("org_id").eq("status", "active");
  const seatByOrg = new Map<string, number>();
  for (const m of members ?? []) seatByOrg.set(m.org_id, (seatByOrg.get(m.org_id) ?? 0) + 1);

  const summaries: OrgSummary[] = (orgs ?? []).map(o => ({
    ...o,
    seats_used: seatByOrg.get(o.id) ?? 0,
    active: isActive(o.status, o.expires_at),
  }));
  return NextResponse.json({ orgs: summaries });
}

// ── POST /api/superadmin/orgs — create an org ───────────────────────────────
export async function POST(req: Request) {
  const gate = await requireSuperAdmin("superadmin.orgs.create");
  if ("error" in gate) return gate.error;

  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured for admin operations." }, { status: 503 });

  let body: Record<string, unknown>;
  try { body = await req.json(); } catch { return NextResponse.json({ error: "Invalid JSON." }, { status: 400 }); }

  const name = String(body.name ?? "").trim();
  const slug = normalizeSlug(String(body.slug ?? body.name ?? ""));
  const seatLimit = Number(body.seat_limit ?? 0);
  const startsAt = body.starts_at ? new Date(String(body.starts_at)).toISOString() : new Date().toISOString();
  const expiresAt = body.expires_at ? new Date(String(body.expires_at)).toISOString() : null;
  const status: OrgStatus = (["trial", "active"].includes(String(body.status)) ? body.status : "active") as OrgStatus;

  if (!name) return NextResponse.json({ error: "Name is required." }, { status: 400 });
  if (!slug) return NextResponse.json({ error: "A valid slug (letters/numbers) is required." }, { status: 400 });
  if (!Number.isFinite(seatLimit) || seatLimit < 0) return NextResponse.json({ error: "Seat limit must be 0 or more." }, { status: 400 });
  if (expiresAt && new Date(expiresAt).getTime() <= Date.now()) {
    return NextResponse.json({ error: "Expiry must be in the future." }, { status: 400 });
  }

  const { data: org, error } = await admin
    .from("organizations")
    .insert({ name, slug, seat_limit: seatLimit, starts_at: startsAt, expires_at: expiresAt, status })
    .select()
    .single();

  if (error) {
    if (error.code === "23505") return NextResponse.json({ error: `The slug "${slug}" is already taken.` }, { status: 409 });
    return NextResponse.json({ error: error.message }, { status: 500 });
  }

  // Optionally invite a first org-admin (email). The accept flow is Phase 2;
  // here we just record the invitation so it's ready.
  const adminEmail = String(body.admin_email ?? "").trim();
  if (adminEmail) {
    const token = crypto.randomUUID();
    const inviteExpiry = new Date(Date.now() + 14 * 24 * 3600 * 1000).toISOString();
    await admin.from("invitations").insert({
      org_id: org.id, email: adminEmail, role: "org_admin", token, expires_at: inviteExpiry,
    });
  }

  return NextResponse.json({ org }, { status: 201 });
}
