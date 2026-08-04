import "server-only";
/**
 * API route auth guards. The single place server-side route handlers decide who
 * may call them. Two postures, both FAIL CLOSED:
 *
 *  - `requireAdmin()` — hard gate for staff-only tooling (content generation,
 *    validation, admin endpoints). 401 if not signed in, 403 if signed in but
 *    not `role='admin'`. When Supabase isn't configured the client is null and
 *    this returns 401 — i.e. a deployment with no auth backend cannot reach
 *    admin tooling at all, which is the safe default.
 *
 *  - `getAuthedUser()` — soft check for student-facing LLM routes. Those routes
 *    already have a zero-cost heuristic/stub fallback, so instead of rejecting
 *    guests we gate only the PAID LLM path behind a signed-in user: a guest gets
 *    the same fallback as a no-API-key deployment (works, costs nothing), a
 *    signed-in user gets the real AI. This closes the anonymous-spend hole
 *    without breaking the guest experience.
 *
 * `supabase.auth.getUser()` (not `getSession()`) is used deliberately — it
 * validates the JWT with the Supabase auth server rather than trusting the
 * cookie, so a forged/expired cookie can't impersonate a user or an admin.
 */
import { NextResponse } from "next/server";
import { getSupabaseServerClient } from "@/lib/supabase/server";
import { logAudit } from "@/lib/audit/logAudit";
import { decodeOrgClaim } from "@/lib/auth/orgClaim";

export interface AuthedUser {
  id: string;
  email: string | null;
  role: string;
  /** Tenant context from the JWT (multi-tenancy). Null until the org hook is live. */
  orgId: string | null;
  /** The org's name (from the JWT claim), for display. */
  orgName: string | null;
  /** Org-scoped role: 'org_admin' | 'instructor' | 'student' | null. */
  orgRole: string | null;
  /** Platform super-admin (cross-org). From the JWT claim; false pre-migration. */
  isPlatformAdmin: boolean;
}

/** The signed-in user (with role from `profiles`), or null if not signed in / Supabase not configured. */
export async function getAuthedUser(): Promise<AuthedUser | null> {
  const supabase = await getSupabaseServerClient();
  if (!supabase) return null;

  // getUser() validates the JWT against the auth server (see file doc).
  const { data: { user }, error } = await supabase.auth.getUser();
  if (error || !user) return null;

  const { data: profile } = await supabase
    .from("profiles")
    .select("role")
    .eq("id", user.id)
    .maybeSingle();

  // The org context lives in the token claims (stamped by the access-token
  // hook), not in a column — reading it here is safe before the migration lands.
  const { data: { session } } = await supabase.auth.getSession();
  const { orgId, orgName, orgRole, isPlatformAdmin } = decodeOrgClaim(session?.access_token);

  return {
    id: user.id,
    email: user.email ?? null,
    role: profile?.role ?? "analyst",
    orgId,
    orgName,
    orgRole,
    isPlatformAdmin,
  };
}

type Gate = { user: AuthedUser } | { error: NextResponse };

/**
 * Hard gate: caller must be a signed-in admin. Use for staff-only /
 * content-authoring routes.
 *
 * Pass `action` (e.g. "lesson.generate") to record the privileged access in the
 * audit trail on success. The write is awaited but fail-safe — logAudit never
 * throws — so it can neither break nor slow-fail the guarded route. A DENIED
 * attempt by a non-admin is logged too: an authenticated user probing an admin
 * endpoint is exactly the kind of event a SOC (and a regulator) wants recorded.
 */
export async function requireAdmin(action?: string): Promise<Gate> {
  const user = await getAuthedUser();
  if (!user) {
    return { error: NextResponse.json({ error: "Authentication required." }, { status: 401 }) };
  }
  if (user.role !== "admin") {
    if (action) await logAudit({ actorId: user.id, action: `${action}.denied`, metadata: { role: user.role } });
    return { error: NextResponse.json({ error: "Admin access required." }, { status: 403 }) };
  }
  if (action) await logAudit({ actorId: user.id, action });
  return { user };
}

/**
 * Hard gate: caller must be the PLATFORM super-admin (cross-org). Use for the
 * super-admin console / provisioning routes (Phase 1). Fail-closed and audited,
 * mirroring requireAdmin. `isPlatformAdmin` comes from the JWT claim, so this
 * denies everyone until the multi-tenancy hook is live — which is the safe
 * default for endpoints that don't exist yet.
 */
export async function requireSuperAdmin(action?: string): Promise<Gate> {
  const user = await getAuthedUser();
  if (!user) {
    return { error: NextResponse.json({ error: "Authentication required." }, { status: 401 }) };
  }
  if (!user.isPlatformAdmin) {
    if (action) await logAudit({ actorId: user.id, action: `${action}.denied`, metadata: { reason: "not_platform_admin" } });
    return { error: NextResponse.json({ error: "Platform admin access required." }, { status: 403 }) };
  }
  if (action) await logAudit({ actorId: user.id, action });
  return { user };
}

/**
 * Gate an org-admin acting on THEIR OWN org (the /manage console). Returns the
 * user whose `orgId` is the org they administer. A platform super-admin always
 * passes (they administer the internal org context in their token). Fail-closed
 * and audited.
 */
export async function requireOrgAdmin(action?: string): Promise<Gate> {
  const user = await getAuthedUser();
  if (!user) {
    return { error: NextResponse.json({ error: "Authentication required." }, { status: 401 }) };
  }
  const ok = user.isPlatformAdmin || (user.orgRole === "org_admin" && !!user.orgId);
  if (!ok) {
    if (action) await logAudit({ actorId: user.id, action: `${action}.denied`, metadata: { orgRole: user.orgRole } });
    return { error: NextResponse.json({ error: "Organisation admin access required." }, { status: 403 }) };
  }
  if (action) await logAudit({ actorId: user.id, action, metadata: { orgId: user.orgId } });
  return { user };
}

/**
 * Gate an org-scoped action: the caller must belong to `orgId` with one of
 * `roles` (e.g. ['org_admin'] for roster management in Phase 3). A platform
 * super-admin always passes. Fail-closed and audited.
 */
export async function requireOrgRole(orgId: string, roles: string[], action?: string): Promise<Gate> {
  const user = await getAuthedUser();
  if (!user) {
    return { error: NextResponse.json({ error: "Authentication required." }, { status: 401 }) };
  }
  const ok = user.isPlatformAdmin || (user.orgId === orgId && !!user.orgRole && roles.includes(user.orgRole));
  if (!ok) {
    if (action) await logAudit({ actorId: user.id, action: `${action}.denied`, metadata: { orgId, orgRole: user.orgRole } });
    return { error: NextResponse.json({ error: "Insufficient permissions for this organisation." }, { status: 403 }) };
  }
  if (action) await logAudit({ actorId: user.id, action, metadata: { orgId } });
  return { user };
}
