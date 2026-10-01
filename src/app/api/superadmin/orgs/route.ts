import { NextResponse } from "next/server";
import { dbFail } from "@/lib/http/dbFail";
import { emailOrigin } from "@/lib/http/siteOrigin";
import { requireSuperAdmin } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { sendEmail } from "@/lib/email/sendEmail";
import { orgWelcomeEmail } from "@/lib/email/templates";
import { generateCode } from "@/lib/org/classCode";
import { fetchAll } from "@/lib/plans/server";
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
  if (error) return dbFail(error, "api/superadmin/orgs", 500);

  // One PAGED pass over active memberships → seats per org (a single unpaged
  // read stopped at 1000 rows and under-reported). The platform admin's own
  // memberships don't use seats — same rule as org_seats_used() (0080).
  const seatByOrg = new Map<string, number>();
  try {
    const members = await fetchAll<{ org_id: string; user_id: string; profiles: unknown }>(
      (f, t) => admin.from("org_members").select("org_id, user_id, profiles(is_platform_admin)").eq("status", "active").order("org_id").order("user_id").range(f, t),
      "superadmin:seats");
    for (const m of members) {
      if ((m.profiles as { is_platform_admin?: boolean } | null)?.is_platform_admin) continue;
      seatByOrg.set(m.org_id, (seatByOrg.get(m.org_id) ?? 0) + 1);
    }
  } catch {
    return NextResponse.json({ error: "Couldn't count seats — please try again." }, { status: 500 });
  }

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
  // E-23: an unparseable date threw RangeError from toISOString() → bodyless 500.
  const startsAt = body.starts_at ? isoOrNull(body.starts_at) : new Date().toISOString();
  const expiresAt = body.expires_at ? isoOrNull(body.expires_at) : null;
  if (!startsAt || (body.expires_at && !expiresAt)) return NextResponse.json({ error: "Invalid start or expiry date." }, { status: 400 });
  const status: OrgStatus = (["trial", "active"].includes(String(body.status)) ? body.status : "active") as OrgStatus;
  // Commercial record (0020) — optional, captured on the create form. Whitelisted
  // + length-capped rather than stored as free-form client JSON (the org can read
  // its own row under RLS, so this must never become an arbitrary blob store) —
  // mirrors the allowlist on the PATCH route in orgs/[id]/route.ts.
  let contract: Record<string, string | number> | undefined;
  if (body.contract && typeof body.contract === "object") {
    const c = body.contract as Record<string, unknown>;
    const out: Record<string, string | number> = {};
    const str = (v: unknown, max: number) => (typeof v === "string" && v.trim() ? v.trim().slice(0, max) : undefined);
    const plan = str(c.plan, 80); if (plan) out.plan = plan;
    const po = str(c.po_number, 80); if (po) out.po_number = po;
    const currency = str(c.currency, 8); if (currency) out.currency = currency.toUpperCase();
    const notes = str(c.notes, 2000); if (notes) out.notes = notes;
    if (c.seats_purchased !== undefined && c.seats_purchased !== "" && c.seats_purchased !== null) {
      const n = Number(c.seats_purchased);
      if (!Number.isFinite(n) || n < 0) return NextResponse.json({ error: "Seats purchased must be 0 or more." }, { status: 400 });
      out.seats_purchased = Math.floor(n);
    }
    if (c.price !== undefined && c.price !== "" && c.price !== null) {
      const p = Number(c.price);
      if (!Number.isFinite(p) || p < 0) return NextResponse.json({ error: "Price must be 0 or more." }, { status: 400 });
      out.price = p;
    }
    if (c.signed_at !== undefined && c.signed_at !== null && c.signed_at !== "") {
      const d = new Date(String(c.signed_at));
      if (Number.isNaN(d.getTime())) return NextResponse.json({ error: "Invalid signed date." }, { status: 400 });
      out.signed_at = d.toISOString();
    }
    if (Object.keys(out).length) contract = out;
  }

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
    return dbFail(error, "api/superadmin/orgs", 500);
  }

  // The platform super-admin owns every tenant and is present in EVERY
  // environment by design ("super-admin registered in all environments"). Enrol
  // every super-admin (profiles.is_platform_admin) as an org_admin of the new org
  // so it appears in their environments immediately — no need to enter-org after
  // each creation. Non-fatal: the console lists all orgs regardless.
  // NB: NOT profiles.role='admin' — that is the content-staff flag (requireAdmin),
  // and enrolling those users would make them visible org admins of every college.
  // E-19 (QA phase 7): the result was ignored — a failed enrol left the new org
  // missing from the super-admin's environments with no hint why.
  let enrolWarning: string | null = null;
  const { data: supers, error: supersErr } = await admin.from("profiles").select("id").eq("is_platform_admin", true);
  if (supersErr) {
    console.error("[superadmin/orgs] could not list super-admins to enrol:", supersErr.message);
    enrolWarning = "The organisation was created, but you weren't added to it — use Enter on the organisation page.";
  } else if (supers && supers.length) {
    const { error: enrolErr } = await admin.from("org_members").upsert(
      supers.map(s => ({ org_id: org.id, user_id: s.id, role: "org_admin", status: "active" })),
      { onConflict: "org_id,user_id" },
    );
    if (enrolErr) {
      console.error("[superadmin/orgs] super-admin enrol failed:", enrolErr.message);
      enrolWarning = "The organisation was created, but you weren't added to it — use Enter on the organisation page.";
    }
  }

  const origin = emailOrigin(req);

  // Optionally invite a first org-admin (email) — capture the link so we can
  // email it to them.
  const rawAdminEmail = String(body.admin_email ?? "").trim();
  // An invalid address would mint an invitation nobody can redeem; skip it.
  const adminEmail = /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(rawAdminEmail) ? rawAdminEmail.toLowerCase() : "";
  let adminLink: string | null = null;
  let inviteError: string | null = rawAdminEmail && !adminEmail ? "admin_email is not a valid address — no invitation was created." : null;
  if (adminEmail) {
    const token = crypto.randomUUID();
    const inviteExpiry = new Date(Date.now() + 14 * 24 * 3600 * 1000).toISOString();
    const { error: invErr } = await admin.from("invitations").insert({
      org_id: org.id, email: adminEmail, role: "org_admin", token, expires_at: inviteExpiry,
    });
    // Only hand out / email a link whose invitation row actually exists.
    if (invErr) inviteError = "The organisation was created, but the admin invitation could not be saved — send it again from the organisation page.";
    else adminLink = `${origin}/join?token=${token}`;
  }

  // 0029: no standing class link — students join with the org's affiliation
  // code. Mint a starter one and include it in the admin's welcome email so
  // the college is ready to enrol students immediately.
  let classCode: string | null = null;
  if (adminEmail) {
    try { classCode = (await generateCode(admin, org.id, gate.user.id)).code; }
    catch (e) { console.error("[superadmin/orgs] starter class code failed:", e instanceof Error ? e.message : e); }
  }
  let emailed = false;
  if (adminEmail && adminLink) {   // never email a join link with no invitation behind it
    const mail = orgWelcomeEmail({ orgName: name, adminLink, classCode });
    const r = await sendEmail({ to: adminEmail, subject: mail.subject, html: mail.html, text: mail.text });
    emailed = r.ok;
  }

  return NextResponse.json({ org, adminLink, classCode, emailed, ...(inviteError ? { invite_error: inviteError } : {}), ...(enrolWarning ? { enrol_warning: enrolWarning } : {}) }, { status: 201 });
}

function isoOrNull(v: unknown): string | null {
  const d = new Date(String(v));
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}
