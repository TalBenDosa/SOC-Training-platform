import { NextResponse } from "next/server";
import { requireSuperAdmin } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";

type Ctx = { params: Promise<{ id: string }> };

function joinLink(req: Request, token: string): string {
  const origin = new URL(req.url).origin;
  return `${origin}/join?token=${token}`;
}

// ── GET — pending invitations for the org ───────────────────────────────────
export async function GET(req: Request, { params }: Ctx) {
  const gate = await requireSuperAdmin("superadmin.invites.list");
  if ("error" in gate) return gate.error;
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });
  const { id } = await params;

  const { data, error } = await admin
    .from("invitations")
    .select("id, email, role, token, expires_at, accepted_at, created_at")
    .eq("org_id", id)
    .order("created_at", { ascending: false });
  if (error) return NextResponse.json({ error: error.message }, { status: 500 });

  const invites = (data ?? []).map(i => ({ ...i, link: joinLink(req, i.token) }));
  return NextResponse.json({ invites });
}

// ── POST — create invite(s): a generic class link, or one per email ─────────
export async function POST(req: Request, { params }: Ctx) {
  const gate = await requireSuperAdmin("superadmin.invites.create");
  if ("error" in gate) return gate.error;
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });
  const { id: orgId } = await params;

  let body: Record<string, unknown>;
  try { body = await req.json(); } catch { return NextResponse.json({ error: "Invalid JSON." }, { status: 400 }); }

  const role = String(body.role ?? "student");
  if (!["org_admin", "instructor", "student"].includes(role)) {
    return NextResponse.json({ error: "Invalid role." }, { status: 400 });
  }
  const days = Number(body.expires_days ?? 14);
  const expiresAt = new Date(Date.now() + (Number.isFinite(days) ? days : 14) * 24 * 3600 * 1000).toISOString();

  // Normalise the recipient list (dedupe, basic email shape). Empty → one
  // generic, shareable link with no fixed recipient.
  const rawEmails = Array.isArray(body.emails) ? (body.emails as unknown[]).map(e => String(e).trim().toLowerCase()) : [];
  const emails = [...new Set(rawEmails.filter(e => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e)))];

  const rows = (emails.length > 0 ? emails.map(email => ({ email })) : [{ email: null }]).map(r => ({
    org_id: orgId, role, email: r.email, token: crypto.randomUUID(), expires_at: expiresAt,
  }));

  const { data, error } = await admin.from("invitations").insert(rows).select("id, email, role, token, expires_at");
  if (error) return NextResponse.json({ error: error.message }, { status: 500 });

  const invites = (data ?? []).map(i => ({ ...i, link: joinLink(req, i.token) }));
  return NextResponse.json({ invites }, { status: 201 });
}
