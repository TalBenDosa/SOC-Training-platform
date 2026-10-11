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
import { cache } from "react";
import { NextResponse } from "next/server";
import { getValidatedAuth } from "@/lib/auth/validatedUser";
import { logAudit } from "@/lib/audit/logAudit";
import { decodeOrgClaim } from "@/lib/auth/orgClaim";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";

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
  /** Platform super-admin (cross-org). Re-checked in the DB (SEC-05). */
  isPlatformAdmin: boolean;
  /** Is the active org's licence valid right now? null = no org. (SEC-04) */
  orgActive: boolean | null;
}

/**
 * The signed-in user (with role from `profiles`), or null if not signed in /
 * Supabase not configured.
 *
 * The auth read comes from the request-shared `getValidatedAuth()` (React
 * `cache()`), so the layout's affiliation gate and this guard no longer make two
 * separate getUser() round-trips on the same navigation — they share one. This
 * function is itself `cache()`d too, so repeated guards within one render (e.g.
 * a page that calls it more than once) collapse to a single profiles read.
 */
export const getAuthedUser = cache(async (): Promise<AuthedUser | null> => {
  const auth = await getValidatedAuth();
  if (!auth) return null;
  const { supabase, user, session } = auth;

  // The org context is stamped into the token by the access-token hook — but a
  // token lives up to an hour, so removing / demoting a member or revoking the
  // platform-admin flag did not take effect until it expired (SEC-05). The claim
  // says WHICH org is active; whether the caller is still in it, with which role,
  // whether its licence is valid (SEC-04) and whether they are platform admin are
  // re-read from the DB on every guarded call (two parallel point reads).
  const claim = decodeOrgClaim(session?.access_token);
  const admin = getSupabaseAdminClient();
  if (!admin) {
    const { data: profile } = await supabase.from("profiles").select("role").eq("id", user.id).maybeSingle();
    return { id: user.id, email: user.email ?? null, role: profile?.role ?? "analyst",
      orgId: claim.orgId, orgName: claim.orgName, orgRole: claim.orgRole, isPlatformAdmin: claim.isPlatformAdmin, orgActive: claim.orgActive };
  }
  const [profileRes, memberRes] = await Promise.all([
    admin.from("profiles").select("role, is_platform_admin").eq("id", user.id).maybeSingle(),
    claim.orgId
      ? admin.from("org_members").select("role, status, organizations(status, expires_at)")
          .eq("org_id", claim.orgId).eq("user_id", user.id).maybeSingle()
      : Promise.resolve({ data: null, error: null }),
  ]);
  // Fail closed: a read error grants no privilege (no admin flag, no org role).
  const profile = profileRes.error ? null : profileRes.data;
  const member = memberRes.error ? null : (memberRes.data as { role: string; status: string; organizations: { status: string; expires_at: string | null } | { status: string; expires_at: string | null }[] | null } | null);
  const live = member && member.status === "active" ? member : null;
  const org = live ? (Array.isArray(live.organizations) ? live.organizations[0] : live.organizations) : null;
  const orgActive = org ? (org.status === "active" || org.status === "trial") && (!org.expires_at || Date.parse(org.expires_at) > Date.now()) : null;

  return {
    id: user.id,
    email: user.email ?? null,
    role: profile?.role ?? "analyst",
    orgId: live ? claim.orgId : null,
    orgName: live ? claim.orgName : null,
    orgRole: live ? live.role : null,
    isPlatformAdmin: profile?.is_platform_admin === true,
    orgActive,
  };
});

type Gate = { user: AuthedUser } | { error: NextResponse };

/**
 * May this user open UNPUBLISHED org content (authoring preview)? Org staff of
 * their own org and platform admins. The org boundary itself is enforced by the
 * resolvers; this only decides whether drafts are visible inside it.
 */
export function canPreviewDrafts(user: AuthedUser | null): boolean {
  if (!user) return false;
  return user.isPlatformAdmin || user.orgRole === "org_admin" || user.orgRole === "instructor";
}

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
  if (user.orgActive === false && !user.isPlatformAdmin) {
    return { error: NextResponse.json({ error: "Your college's licence isn't active. Contact your administrator." }, { status: 403 }) };
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
 * Gate an org-STAFF action (session-runner): org_admin OR instructor of their own
 * org, plus platform super-admin. Used where an instructor is meant to run a team
 * exercise (start / reassign / add members) — requireOrgAdmin fail-closed and
 * excluded instructors, which the rest of the team feature treats as staff. Audited.
 */
export async function requireOrgStaff(action?: string): Promise<Gate> {
  const user = await getAuthedUser();
  if (!user) {
    return { error: NextResponse.json({ error: "Authentication required." }, { status: 401 }) };
  }
  if (user.orgActive === false && !user.isPlatformAdmin) {
    return { error: NextResponse.json({ error: "Your college's licence isn't active. Contact your administrator." }, { status: 403 }) };
  }
  const ok = user.isPlatformAdmin || ((user.orgRole === "org_admin" || user.orgRole === "instructor") && !!user.orgId);
  if (!ok) {
    if (action) await logAudit({ actorId: user.id, action: `${action}.denied`, metadata: { orgRole: user.orgRole } });
    return { error: NextResponse.json({ error: "Instructor or organisation-admin access required." }, { status: 403 }) };
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
  if (user.orgActive === false && !user.isPlatformAdmin) {
    return { error: NextResponse.json({ error: "Your college's licence isn't active. Contact your administrator." }, { status: 403 }) };
  }
  const ok = user.isPlatformAdmin || (user.orgId === orgId && !!user.orgRole && roles.includes(user.orgRole));
  if (!ok) {
    if (action) await logAudit({ actorId: user.id, action: `${action}.denied`, metadata: { orgId, orgRole: user.orgRole } });
    return { error: NextResponse.json({ error: "Insufficient permissions for this organisation." }, { status: 403 }) };
  }
  if (action) await logAudit({ actorId: user.id, action, metadata: { orgId } });
  return { user };
}
