import { NextResponse } from "next/server";
import { requireOrgAdmin } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { logAudit } from "@/lib/audit/logAudit";

const BUCKET = "org-media";

/** Load a resource and re-assert it belongs to the caller's org (service role
 *  bypasses RLS). Returns the row or a NextResponse error. */
async function ownRow(id: string, orgId: string, admin: ReturnType<typeof getSupabaseAdminClient>) {
  const { data, error } = await admin!
    .from("org_resources").select("id, org_id, storage_key").eq("id", id).maybeSingle();
  if (error) return { error: NextResponse.json({ error: error.message }, { status: 500 }) };
  if (!data || data.org_id !== orgId) return { error: NextResponse.json({ error: "Not found." }, { status: 404 }) };
  return { row: data };
}

/** PATCH — publish / unpublish (the only way students see a resource). */
export async function PATCH(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const gate = await requireOrgAdmin("org.media.status");
  if ("error" in gate) return gate.error;
  const orgId = gate.user.orgId;
  if (!orgId) return NextResponse.json({ error: "No organisation in session." }, { status: 400 });
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  const { id } = await params;
  let body: Record<string, unknown>;
  try { body = await req.json(); } catch { return NextResponse.json({ error: "Invalid JSON." }, { status: 400 }); }
  const status = body.status === "published" ? "published" : body.status === "draft" ? "draft" : null;
  if (!status) return NextResponse.json({ error: "status must be 'published' or 'draft'." }, { status: 400 });

  const owned = await ownRow(id, orgId, admin);
  if ("error" in owned) return owned.error;

  const { error } = await admin.from("org_resources").update({ status }).eq("id", id).eq("org_id", orgId);
  if (error) return NextResponse.json({ error: error.message }, { status: 500 });
  await logAudit({ actorId: gate.user.id, action: `org.media.${status}`, targetTable: "org_resources", targetId: id, metadata: { org_id: orgId } });
  return NextResponse.json({ ok: true, status });
}

/** DELETE — remove the row and its storage object. */
export async function DELETE(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  const gate = await requireOrgAdmin("org.media.delete");
  if ("error" in gate) return gate.error;
  const orgId = gate.user.orgId;
  if (!orgId) return NextResponse.json({ error: "No organisation in session." }, { status: 400 });
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  const { id } = await params;
  const owned = await ownRow(id, orgId, admin);
  if ("error" in owned) return owned.error;

  await admin.storage.from(BUCKET).remove([owned.row.storage_key]).catch(() => {});
  const { error } = await admin.from("org_resources").delete().eq("id", id).eq("org_id", orgId);
  if (error) return NextResponse.json({ error: error.message }, { status: 500 });
  await logAudit({ actorId: gate.user.id, action: "org.media.deleted", targetTable: "org_resources", targetId: id, metadata: { org_id: orgId } });
  return NextResponse.json({ ok: true });
}
