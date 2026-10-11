import { NextResponse } from "next/server";
import { asObject } from "@/lib/http/body";
import { requireOrgAdmin } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { isOrgContentType, ORG_CONTENT_TABLE } from "@/lib/content/orgContent";

/**
 * Publish/unpublish + delete a per-org authored item (Phase 2 — migration 0040).
 * Both re-assert .eq("org_id", orgId) alongside the id, because the service-role
 * client bypasses RLS and the id comes from the URL.
 */

export const runtime = "nodejs";

// ── GET — full row for editing (scenarios also return their answer key, which
//         the editor needs to prefill correct answers / narrative / IOCs) ─────
export async function GET(_req: Request, { params }: { params: Promise<{ type: string; id: string }> }) {
  const gate = await requireOrgAdmin("org.content.get");
  if ("error" in gate) return gate.error;
  const orgId = gate.user.orgId;
  if (!orgId) return NextResponse.json({ error: "No organisation in session." }, { status: 400 });

  const { type, id } = await params;
  if (!isOrgContentType(type)) return NextResponse.json({ error: "Unknown content type." }, { status: 404 });

  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  const { data: row, error: rowErr } = await admin
    .from(ORG_CONTENT_TABLE[type]).select("id, status, content").eq("id", id).eq("org_id", orgId).maybeSingle();
  if (rowErr) return NextResponse.json({ error: "Couldn't load this item — please try again." }, { status: 503 });
  if (!row) return NextResponse.json({ error: "Not found in this environment." }, { status: 404 });

  let answer_key: unknown = null;
  if (type === "scenarios" || type === "rooms") {
    const keyTable = type === "scenarios" ? "content_scenario_keys" : "content_room_keys";
    const { data: key, error: keyErr } = await admin
      .from(keyTable).select("answer_key").eq("id", id).eq("org_id", orgId).maybeSingle();
    // Never hand the editor a null key because of a failed read — re-saving from
    // it would overwrite the real answer key (P4-04).
    if (keyErr) return NextResponse.json({ error: "Couldn't load the answer key — please try again." }, { status: 503 });
    answer_key = key?.answer_key ?? null;
  }
  return NextResponse.json({ item: row, answer_key });
}

// ── PATCH — flip status between draft and published ──────────────────────────
export async function PATCH(req: Request, { params }: { params: Promise<{ type: string; id: string }> }) {
  const gate = await requireOrgAdmin("org.content.status");
  if ("error" in gate) return gate.error;
  const orgId = gate.user.orgId;
  if (!orgId) return NextResponse.json({ error: "No organisation in session." }, { status: 400 });

  const { type, id } = await params;
  if (!isOrgContentType(type)) return NextResponse.json({ error: "Unknown content type." }, { status: 404 });

  let body: Record<string, unknown>;
  try { body = asObject(await req.json()); } catch { return NextResponse.json({ error: "Invalid JSON." }, { status: 400 }); }
  const status = body.status === "published" ? "published" : body.status === "draft" ? "draft" : null;
  if (!status) return NextResponse.json({ error: "status must be 'draft' or 'published'." }, { status: 400 });

  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  // Publishing a scenario/room requires its answer key (P4-04): the create route
  // keeps an item as a draft when the key write fails, and this flip must not
  // publish such an item anyway — students would be graded against nothing.
  if (status === "published" && (type === "scenarios" || type === "rooms")) {
    const keyTable = type === "scenarios" ? "content_scenario_keys" : "content_room_keys";
    const { data: key, error: keyErr } = await admin
      .from(keyTable).select("id").eq("id", id).eq("org_id", orgId).maybeSingle();
    if (keyErr) return NextResponse.json({ error: "Couldn't check the answer key — please try again." }, { status: 503 });
    if (!key) return NextResponse.json({ error: "This item has no saved answer key yet — open it, save it again, then publish." }, { status: 409 });
  }

  const { data, error } = await admin
    .from(ORG_CONTENT_TABLE[type])
    .update({ status })
    .eq("id", id)
    .eq("org_id", orgId)
    .select("id, status")
    .maybeSingle();
  if (error) { console.error("[org content item]", error.message); return NextResponse.json({ error: "Something went wrong on our side — please try again." }, { status: 500 }); }
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
  if (error) { console.error("[org content item]", error.message); return NextResponse.json({ error: "Something went wrong on our side — please try again." }, { status: 500 }); }

  return NextResponse.json({ ok: true });
}
