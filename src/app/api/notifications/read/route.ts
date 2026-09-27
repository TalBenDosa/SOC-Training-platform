import { NextResponse } from "next/server";
import { getValidatedAuth } from "@/lib/auth/validatedUser";
import { decodeOrgClaim } from "@/lib/auth/orgClaim";
import { isUuid } from "@/lib/plans/sanitize";
import { NOTIFICATION_LIMITS } from "@/lib/notifications/types";

/**
 * POST /api/notifications/read — mark the caller's OWN notifications read.
 *   { ids: uuid[] }  (≤ 100)  — those rows
 *   { all: true }             — every unread row in the current org's inbox
 *
 * Runs through the caller's own Supabase client: the "notifications own mark
 * read" RLS policy limits it to their rows, and the column-level grant (0076)
 * limits it to read_at — this route could not change anything else even if it
 * tried. Already-read rows keep their original read_at.
 */

export const runtime = "nodejs";

const fail = (status: number, error: string) => NextResponse.json({ error }, { status });

export async function POST(req: Request) {
  const auth = await getValidatedAuth();
  if (!auth) return fail(401, "Authentication required.");
  const { supabase, user, session } = auth;
  const { orgId } = decodeOrgClaim(session?.access_token);
  if (!orgId) return NextResponse.json({ ok: true, updated: 0 });

  let body: Record<string, unknown>;
  try {
    const b = await req.json();
    if (!b || typeof b !== "object" || Array.isArray(b)) return fail(400, "Invalid JSON.");
    body = b as Record<string, unknown>;
  } catch { return fail(400, "Invalid JSON."); }

  let q = supabase.from("notifications")
    .update({ read_at: new Date().toISOString() })
    .eq("user_id", user.id).eq("org_id", orgId).is("read_at", null);

  if (body.all === true) {
    // whole inbox
  } else if (Array.isArray(body.ids)) {
    const ids = [...new Set(body.ids.filter(isUuid).map(id => id.toLowerCase()))].slice(0, NOTIFICATION_LIMITS.markIds);
    if (ids.length === 0) return fail(400, "No valid notification ids.");
    q = q.in("id", ids);
  } else {
    return fail(400, "Send { ids: [...] } or { all: true }.");
  }

  const { data, error } = await q.select("id");
  if (error) {
    if (["42P01", "PGRST205"].includes(error.code ?? "")) return NextResponse.json({ ok: true, updated: 0 });
    console.error("[notifications] mark read failed:", error.message);
    return fail(500, "Could not update notifications.");
  }
  return NextResponse.json({ ok: true, updated: data?.length ?? 0 });
}
