import { NextResponse } from "next/server";
import { requireOrgAdmin } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { isOrgContentType, ORG_CONTENT_TABLE, normalizeOrgContent } from "@/lib/content/orgContent";
import { splitAuthored } from "@/lib/scenarios/authored";
import { splitAuthoredRoom } from "@/lib/rooms/authored";
import { normalizeCompany } from "@/lib/dashboard/authoredCompany";

/**
 * Per-org, manually-authored content (Phase 2 — migration 0040).
 *
 * Mirrors /api/org/media and /api/org/assignments: service-role client, gated by
 * requireOrgAdmin, every query pinned to the caller's own org from their JWT
 * (never a request parameter), and the tenant boundary re-asserted with
 * .eq("org_id", orgId) because the service role bypasses RLS.
 *
 * Writes flow ONLY through here — the content tables grant no client write, so
 * the answer-bearing `content` jsonb can never be written from the browser. All
 * id namespacing + field allowlisting happens in normalizeOrgContent().
 */

export const runtime = "nodejs";

// ── GET — list this org's authored items of `type` (all statuses, for the editor)
export async function GET(_req: Request, { params }: { params: Promise<{ type: string }> }) {
  const gate = await requireOrgAdmin("org.content.list");
  if ("error" in gate) return gate.error;
  const orgId = gate.user.orgId;
  if (!orgId) return NextResponse.json({ error: "No organisation in session." }, { status: 400 });

  const { type } = await params;
  if (!isOrgContentType(type)) return NextResponse.json({ error: "Unknown content type." }, { status: 404 });

  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  const { data, error } = await admin
    .from(ORG_CONTENT_TABLE[type])
    .select("id, status, content, created_at, updated_at")
    .eq("org_id", orgId)
    .order("updated_at", { ascending: false });
  if (error) return NextResponse.json({ error: error.message }, { status: 500 });

  return NextResponse.json({ items: data ?? [] });
}

// ── POST — create or update an item (org staff only, own org) ─────────────────
export async function POST(req: Request, { params }: { params: Promise<{ type: string }> }) {
  const gate = await requireOrgAdmin("org.content.write");
  if ("error" in gate) return gate.error;
  const orgId = gate.user.orgId;
  if (!orgId) return NextResponse.json({ error: "No organisation in session." }, { status: 400 });

  const { type } = await params;
  if (!isOrgContentType(type)) return NextResponse.json({ error: "Unknown content type." }, { status: 404 });

  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  let body: Record<string, unknown>;
  try { body = await req.json(); } catch { return NextResponse.json({ error: "Invalid JSON." }, { status: 400 }); }
  const status = body.status === "published" ? "published" : "draft";

  // Scenarios use the two-projection split: the client-safe content goes in
  // content_scenarios, the answer key in the service-role-only key table.
  if (type === "scenarios") {
    const split = splitAuthored(orgId, body);
    if (!split.ok) return NextResponse.json({ error: split.error }, { status: 422 });

    const existing = await admin.from("content_scenarios").select("org_id").eq("id", split.id).maybeSingle();
    if (existing.data && existing.data.org_id !== orgId) {
      return NextResponse.json({ error: "That item belongs to another environment." }, { status: 409 });
    }

    const { data, error } = await admin
      .from("content_scenarios")
      .upsert({ id: split.id, org_id: orgId, status, content: split.safeContent, created_by: gate.user.id }, { onConflict: "id" })
      .select("id, status, content, created_at, updated_at")
      .single();
    if (error) return NextResponse.json({ error: error.message }, { status: 500 });

    const { error: keyErr } = await admin
      .from("content_scenario_keys")
      .upsert({ id: split.id, org_id: orgId, answer_key: split.answerKey }, { onConflict: "id" });
    if (keyErr) return NextResponse.json({ error: keyErr.message }, { status: 500 });

    return NextResponse.json({ item: data });
  }

  // Rooms use the same two-projection split (content_rooms + content_room_keys).
  if (type === "rooms") {
    const split = splitAuthoredRoom(orgId, body);
    if (!split.ok) return NextResponse.json({ error: split.error }, { status: 422 });

    const existing = await admin.from("content_rooms").select("org_id").eq("id", split.id).maybeSingle();
    if (existing.data && existing.data.org_id !== orgId) {
      return NextResponse.json({ error: "That item belongs to another environment." }, { status: 409 });
    }

    const { data, error } = await admin
      .from("content_rooms")
      .upsert({ id: split.id, org_id: orgId, status, content: split.safeContent, created_by: gate.user.id }, { onConflict: "id" })
      .select("id, status, content, created_at, updated_at")
      .single();
    if (error) return NextResponse.json({ error: error.message }, { status: 500 });

    const { error: keyErr } = await admin
      .from("content_room_keys")
      .upsert({ id: split.id, org_id: orgId, answer_key: split.answerKey }, { onConflict: "id" });
    if (keyErr) return NextResponse.json({ error: keyErr.message }, { status: 500 });

    return NextResponse.json({ item: data });
  }

  // Companies (live-feed environments) — single content table, no key split.
  if (type === "companies") {
    const cn = normalizeCompany(orgId, body);
    if (!cn.ok) return NextResponse.json({ error: cn.error }, { status: 422 });
    const existing = await admin.from("content_companies").select("org_id").eq("id", cn.id).maybeSingle();
    if (existing.data && existing.data.org_id !== orgId) {
      return NextResponse.json({ error: "That item belongs to another environment." }, { status: 409 });
    }
    const { data, error } = await admin
      .from("content_companies")
      .upsert({ id: cn.id, org_id: orgId, status, content: cn.content, created_by: gate.user.id }, { onConflict: "id" })
      .select("id, status, content, created_at, updated_at")
      .single();
    if (error) return NextResponse.json({ error: error.message }, { status: 500 });
    return NextResponse.json({ item: data });
  }

  const norm = normalizeOrgContent(type, orgId, body);
  if (!norm.ok) return NextResponse.json({ error: norm.error }, { status: 422 });

  // Defence-in-depth: if this id already exists, it MUST belong to this org.
  // (Cross-org collision is impossible by construction — ids carry the owner's
  // org prefix — but re-assert anyway, since the service role bypasses RLS.)
  const existing = await admin.from(ORG_CONTENT_TABLE[type]).select("org_id").eq("id", norm.id).maybeSingle();
  if (existing.data && existing.data.org_id !== orgId) {
    return NextResponse.json({ error: "That item belongs to another environment." }, { status: 409 });
  }

  const { data, error } = await admin
    .from(ORG_CONTENT_TABLE[type])
    .upsert(
      { id: norm.id, org_id: orgId, status, content: norm.content, created_by: gate.user.id },
      { onConflict: "id" },
    )
    .select("id, status, content, created_at, updated_at")
    .single();
  if (error) return NextResponse.json({ error: error.message }, { status: 500 });

  return NextResponse.json({ item: data });
}
