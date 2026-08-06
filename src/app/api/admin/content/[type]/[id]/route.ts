import { NextRequest, NextResponse } from "next/server";
import { requireAdmin } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";

const TABLES = {
  scenarios: "content_scenarios",
  quizzes: "content_quizzes",
  lessons: "content_lessons",
} as const;
type ContentType = keyof typeof TABLES;

function resolveTable(type: string): string | null {
  return TABLES[type as ContentType] ?? null;
}

// ── PATCH — partial update (status change, or content edit after admin edits it) ──
export async function PATCH(req: NextRequest, { params }: { params: Promise<{ type: string; id: string }> }) {
  const gate = await requireAdmin("admin.content.update");
  if ("error" in gate) return gate.error;

  const { type, id } = await params;
  const table = resolveTable(type);
  if (!table) return NextResponse.json({ error: "Unknown content type." }, { status: 400 });

  const body = await req.json().catch(() => null) as { status?: string; content?: unknown } | null;
  if (!body || (body.status === undefined && body.content === undefined)) {
    return NextResponse.json({ error: "Provide status and/or content to update." }, { status: 400 });
  }
  const patch: Record<string, unknown> = {};
  if (body.status !== undefined) patch.status = body.status === "draft" ? "draft" : "published";
  if (body.content !== undefined) patch.content = body.content;

  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  const { data, error } = await admin
    .from(table)
    .update(patch)
    .eq("id", id)
    .select("id, status, content, created_at, updated_at")
    .maybeSingle();
  if (error) return NextResponse.json({ error: error.message }, { status: 500 });
  if (!data) return NextResponse.json({ error: "Not found." }, { status: 404 });

  return NextResponse.json({ item: data });
}

// ── DELETE ────────────────────────────────────────────────────────────────────
export async function DELETE(_req: NextRequest, { params }: { params: Promise<{ type: string; id: string }> }) {
  const gate = await requireAdmin("admin.content.delete");
  if ("error" in gate) return gate.error;

  const { type, id } = await params;
  const table = resolveTable(type);
  if (!table) return NextResponse.json({ error: "Unknown content type." }, { status: 400 });

  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  const { error } = await admin.from(table).delete().eq("id", id);
  if (error) return NextResponse.json({ error: error.message }, { status: 500 });

  return NextResponse.json({ ok: true });
}
