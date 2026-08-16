import { NextResponse } from "next/server";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";

/**
 * Content feedback — "something's wrong with this question/task" (migration 0022).
 *
 * POST is open to any signed-in learner: the whole point is that the person who
 * hit the problem can say so in one click, so anything heavier than that
 * defeats it. The row is written with the caller's own id/org from their JWT,
 * never from the request body, so a report can't be filed as someone else.
 *
 * GET is platform-admin only and returns the triage inbox.
 */

const KINDS = new Set(["room_task", "scenario", "quiz", "dashboard", "other"]);

export async function POST(req: Request) {
  const user = await getAuthedUser();
  if (!user) return NextResponse.json({ error: "Authentication required." }, { status: 401 });

  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  let body: Record<string, unknown>;
  try { body = await req.json(); } catch { return NextResponse.json({ error: "Invalid JSON." }, { status: 400 }); }

  const message = String(body.message ?? "").trim().slice(0, 2000);
  if (!message) return NextResponse.json({ error: "Tell us what's wrong." }, { status: 400 });

  const target_kind = KINDS.has(String(body.target_kind)) ? String(body.target_kind) : "other";
  const target_id = String(body.target_id ?? "").trim().slice(0, 200) || "unknown";

  // Context is caller-supplied but bounded: keys capped, values stringified and
  // truncated, so a report can't be used to stuff arbitrary payloads into the DB.
  const rawCtx = (body.context && typeof body.context === "object") ? body.context as Record<string, unknown> : {};
  const context: Record<string, string> = {};
  for (const [k, v] of Object.entries(rawCtx).slice(0, 12)) {
    context[k.slice(0, 40)] = String(v ?? "").slice(0, 500);
  }

  const { error } = await admin.from("content_feedback").insert({
    user_id: user.id,
    org_id: user.orgId,
    target_kind, target_id, context, message,
  });
  if (error) return NextResponse.json({ error: error.message }, { status: 500 });

  return NextResponse.json({ ok: true });
}

// ── GET — triage inbox (platform admin only) ────────────────────────────────
export async function GET(req: Request) {
  const user = await getAuthedUser();
  if (!user) return NextResponse.json({ error: "Authentication required." }, { status: 401 });
  if (user.role !== "admin" && !user.isPlatformAdmin) return NextResponse.json({ error: "Admin access required." }, { status: 403 });

  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  const status = new URL(req.url).searchParams.get("status");
  let q = admin
    .from("content_feedback")
    .select("id, target_kind, target_id, context, message, status, created_at, profiles:user_id(handle, display_name)")
    .order("created_at", { ascending: false })
    .limit(200);
  if (status && status !== "all") q = q.eq("status", status);

  const { data, error } = await q;
  if (error) return NextResponse.json({ error: error.message }, { status: 500 });

  return NextResponse.json({ items: data ?? [] });
}

// ── PATCH — triage a report (platform admin only) ───────────────────────────
export async function PATCH(req: Request) {
  const user = await getAuthedUser();
  if (!user) return NextResponse.json({ error: "Authentication required." }, { status: 401 });
  if (user.role !== "admin" && !user.isPlatformAdmin) return NextResponse.json({ error: "Admin access required." }, { status: 403 });

  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  let body: Record<string, unknown>;
  try { body = await req.json(); } catch { return NextResponse.json({ error: "Invalid JSON." }, { status: 400 }); }

  const id = String(body.id ?? "");
  const status = String(body.status ?? "");
  if (!id) return NextResponse.json({ error: "id is required." }, { status: 400 });
  if (!["new", "triaged", "resolved", "wontfix"].includes(status)) {
    return NextResponse.json({ error: "Invalid status." }, { status: 400 });
  }

  const { error } = await admin.from("content_feedback").update({ status }).eq("id", id);
  if (error) return NextResponse.json({ error: error.message }, { status: 500 });

  return NextResponse.json({ ok: true });
}
