import { NextResponse } from "next/server";
import { requireAdmin } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";

/**
 * One-shot diagnose-and-fix for the platform super-admin's own tenancy state.
 * Gated by requireAdmin (the existing owner role), so only an admin can call it
 * for THEIR OWN account. Reports whether their profile is flagged
 * is_platform_admin and has an org membership (the two things the access-token
 * hook reads), and idempotently repairs them if the Part-1 migration's
 * owner-specific statements didn't take (e.g. the profile row was created after
 * the backfill). After calling, the admin must re-login for a fresh token.
 *
 * Safe: it only ever elevates the ALREADY-authenticated admin, never anyone else.
 */
const INTERNAL_ORG = "d0d0d0d0-0000-4000-8000-000000000000";

export async function GET() {
  const gate = await requireAdmin("admin.superadmin_bootstrap");
  if ("error" in gate) return gate.error;
  const db = getSupabaseAdminClient();
  if (!db) return NextResponse.json({ error: "Server not configured (no service role key)." }, { status: 503 });
  const admin = db;
  const uid = gate.user.id;

  async function snapshot() {
    const { data: p } = await admin.from("profiles").select("id, role, is_platform_admin, org_id").eq("id", uid).maybeSingle();
    const { data: m } = await admin.from("org_members").select("org_id, role, status").eq("user_id", uid);
    return { profile: p, memberships: m ?? [] };
  }

  const before = await snapshot();

  // Ensure the internal org exists (it should from 0010).
  await admin.from("organizations").upsert(
    { id: INTERNAL_ORG, name: "Internal / Default", slug: "internal", seat_limit: 0, status: "active" },
    { onConflict: "id" },
  );
  // Elevate + home the caller, and ensure a membership.
  const fixErrors: string[] = [];
  const up = await admin.from("profiles").update({ is_platform_admin: true, org_id: before.profile?.org_id ?? INTERNAL_ORG }).eq("id", uid);
  if (up.error) fixErrors.push("profile: " + up.error.message);
  const mem = await admin.from("org_members").upsert(
    { org_id: INTERNAL_ORG, user_id: uid, role: "org_admin", status: "active" },
    { onConflict: "org_id,user_id" },
  );
  if (mem.error) fixErrors.push("member: " + mem.error.message);

  const after = await snapshot();
  return NextResponse.json({
    uid,
    before,
    after,
    fixed: fixErrors.length === 0,
    fixErrors,
    note: "Now sign out and back in to get a token with the org claims.",
  });
}
