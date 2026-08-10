import { NextResponse } from "next/server";
import { requireSuperAdmin } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { sendEmail } from "@/lib/email/sendEmail";
import { orgWelcomeEmail } from "@/lib/email/templates";
import { generateCode } from "@/lib/org/classCode";
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
  // Platform-wide LLM spend (migration 0024). Surfaced here because this is the
  // only console that sees across tenants — before this, real dollar spend was
  // invisible until the provider's bill arrived.
  const { data: spend30d } = await admin.rpc("ai_spend_usd", { p_org: null, p_days: 30 });
  const { data: spend7d }  = await admin.rpc("ai_spend_usd", { p_org: null, p_days: 7 });

  return NextResponse.json({
    orgs: summaries,
    ai_spend: {
      usd_30d: Number(spend30d ?? 0),
      usd_7d: Number(spend7d ?? 0),
      cap_30d: Number(process.env.AI_MONTHLY_CAP_USD ?? 100),
    },
  });
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
  // Commercial record (0020) — optional, captured on the create form now (was
  // previously only editable on the org detail page). A plain object; the
  // detail page can later fill in the structured fields (plan/price/PO…).
  const contract = body.contract && typeof body.contract === "object" ? body.contract : undefined;

  if (!name) return NextResponse.json({ error: "Name is required." }, { status: 400 });
  if (!slug) return NextResponse.json({ error: "A valid slug (letters/numbers) is required." }, { status: 400 });
  if (!Number.isFinite(seatLimit) || seatLimit < 0) return NextResponse.json({ error: "Seat limit must be 0 or more." }, { status: 400 });
  if (expiresAt && new Date(expiresAt).getTime() <= Date.now()) {
    return NextResponse.json({ error: "Expiry must be in the future." }, { status: 400 });
  }

  const { data: org, error } = await admin
    .from("organizations")
    .insert({ name, slug, seat_limit: seatLimit, starts_at: startsAt, expires_at: expiresAt, status, ...(contract ? { contract } : {}) })
    .select()
    .single();

  if (error) {
    if (error.code === "23505") return NextResponse.json({ error: `The slug "${slug}" is already taken.` }, { status: 409 });
    return NextResponse.json({ error: error.message }, { status: 500 });
  }

  // The platform super-admin owns every tenant and is present in EVERY
  // environment by design ("super-admin registered in all environments"). Enrol
  // every super-admin (profiles.role='admin') as an org_admin of the new org so
  // it appears in their environments immediately — no need to enter-org after
  // each creation. Non-fatal: the console lists all orgs regardless.
  const { data: supers } = await admin.from("profiles").select("id").eq("role", "admin");
  if (supers && supers.length) {
    await admin.from("org_members").upsert(
      supers.map(s => ({ org_id: org.id, user_id: s.id, role: "org_admin", status: "active" })),
      { onConflict: "org_id,user_id" },
    );
  }

  const origin = new URL(req.url).origin;

  // Optionally invite a first org-admin (email) — capture the link so we can
  // email it to them.
  const adminEmail = String(body.admin_email ?? "").trim();
  let adminLink: string | null = null;
  if (adminEmail) {
    const token = crypto.randomUUID();
    const inviteExpiry = new Date(Date.now() + 14 * 24 * 3600 * 1000).toISOString();
    await admin.from("invitations").insert({
      org_id: org.id, email: adminEmail, role: "org_admin", token, expires_at: inviteExpiry,
    });
    adminLink = `${origin}/join?token=${token}`;
  }

  // 0029: no standing class link — students join with the org's affiliation
  // code. Mint a starter one and include it in the admin's welcome email so
  // the college is ready to enrol students immediately.
  let classCode: string | null = null;
  if (adminEmail) {
    try { classCode = (await generateCode(admin, org.id, gate.user.id)).code; } catch { /* non-fatal */ }
  }
  let emailed = false;
  if (adminEmail) {
    const mail = orgWelcomeEmail({ orgName: name, adminLink, classCode });
    const r = await sendEmail({ to: adminEmail, subject: mail.subject, html: mail.html, text: mail.text });
    emailed = r.ok;
  }

  return NextResponse.json({ org, adminLink, classCode, emailed }, { status: 201 });
}
