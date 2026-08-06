import { NextRequest, NextResponse } from "next/server";
import { requireAdmin } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";

/**
 * Durable replacement for the old published_scenarios/generated_quizzes/
 * generated_lessons localStorage keys (see migration 0019). One generic route
 * for all three content types since they share an identical shape
 * (id/status/content jsonb) — a per-type route each would be the exact same
 * code three times over.
 *
 * All writes go through the service-role client (bypasses RLS) after
 * requireAdmin() — content_scenarios/quizzes/lessons carry NO RLS write
 * policy at all, so this route is the only way to create/publish content.
 * Students read published rows directly via RLS (see lib/content/publicContent.ts).
 */
const TABLES = {
  scenarios: "content_scenarios",
  quizzes: "content_quizzes",
  lessons: "content_lessons",
} as const;
type ContentType = keyof typeof TABLES;

function resolveTable(type: string): string | null {
  return TABLES[type as ContentType] ?? null;
}

// ── GET — list everything (all statuses; admin console needs drafts too) ────
export async function GET(_req: NextRequest, { params }: { params: Promise<{ type: string }> }) {
  const gate = await requireAdmin("admin.content.list");
  if ("error" in gate) return gate.error;

  const table = resolveTable((await params).type);
  if (!table) return NextResponse.json({ error: "Unknown content type." }, { status: 400 });

  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  const { data, error } = await admin
    .from(table)
    .select("id, status, content, created_at, updated_at")
    .order("created_at", { ascending: false });
  if (error) return NextResponse.json({ error: error.message }, { status: 500 });

  return NextResponse.json({ items: data ?? [] });
}

// ── POST — create or republish (upsert by id) ────────────────────────────────
export async function POST(req: NextRequest, { params }: { params: Promise<{ type: string }> }) {
  const gate = await requireAdmin("admin.content.publish");
  if ("error" in gate) return gate.error;

  const table = resolveTable((await params).type);
  if (!table) return NextResponse.json({ error: "Unknown content type." }, { status: 400 });

  const body = await req.json().catch(() => null) as { id?: string; status?: string; content?: unknown } | null;
  if (!body?.id || !body.content) {
    return NextResponse.json({ error: "id and content are required." }, { status: 400 });
  }
  const status = body.status === "draft" ? "draft" : "published";

  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  const { data, error } = await admin
    .from(table)
    .upsert({ id: body.id, status, content: body.content, created_by: gate.user.id }, { onConflict: "id" })
    .select("id, status, content, created_at, updated_at")
    .single();
  if (error) return NextResponse.json({ error: error.message }, { status: 500 });

  return NextResponse.json({ item: data });
}
