import { NextResponse } from "next/server";
import { requireOrgAdmin } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { isOrgContentType, ORG_CONTENT_TABLE } from "@/lib/content/orgContent";

/**
 * Publish/unpublish + delete a per-org authored item (Phase 2 — migration 0040).
 * Both re-assert .eq("org_id", orgId) alongside the id, because the service-role
 * client bypasses RLS and the id comes from the URL.
 */

export const runtime = "nodejs";

// ── PATCH — flip status between draft and published ──────────────────────────
export async function PATCH(req: Request, { params }: { params: Promise<{ type: string; id: string }> }) {
  const gate = await requireOrgAdmin("org.content.status");
  if ("error" in gate) return gate.error;
  const orgId = gate.user.orgId;
  if (!orgId) return NextResponse.json({ error: "No organisation in session." }, { status: 400 });

  const { type, id } = await params;
  if (!isOrgContentType(type)) return NextResponse.json({ error: "Unknown content type." }, { status: 404 });

  let body: Record<string, unknown>;
  try { body = await req.json(); } catch { return NextResponse.json({ error: "Invalid JSON." }, { status: 400 }); }
  const status = body.status === "published" ? "published" : body.status === "draft" ? "draft" : null;
  if (!status) return NextResponse.json({ error: "status must be 'draft' or 'published'." }, { status: 400 });

  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  const { data, error } = await admin
    .from(ORG_CONTENT_TABLE[type])
    .update({ status })
    .eq("id", id)
    .eq("org_id", orgId)
    .select("id, status")
    .maybeSingle();
  if (error) return NextResponse.json({ error: error.message }, { status: 500 });
  if (!data) return NextResponse.json({ error: "Not found in this environment." }, { status: 404 });

  return NextResponse.json({ item: data });
}

// ── DELETE — remove an item (own org) ────────────────────────────────────────
export async function DELETE(_req: Request, { params }: { params: Promise<{ type: string; id: string }> }) {
  const gate = await requireOrgAdmin("org.content.delete");
  if ("error" in gate) return gate.error;
  const orgId = gate.user.orgId;
  if (!orgId) return NextResponse.json({ error: "No organisation in session." }, { status: 400 });

  const { type, id } = await params;
  if (!isOrgContentType(type)) return NextResponse.json({ error: "Unknown content type." }, { status: 404 });

  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  const { error } = await admin.from(ORG_CONTENT_TABLE[type]).delete().eq("id", id).eq("org_id", orgId);
  if (error) return NextResponse.json({ error: error.message }, { status: 500 });

  return NextResponse.json({ ok: true });
}
