import "server-only";
/**
 * The 100-day affiliation gate. Answers one question for the app layout:
 * "must this request be diverted to /renew before seeing any app page?"
 *
 * True only for an ORG STUDENT whose org_members.affiliation_expires_at has
 * passed (see 0028_org_codes.sql). Admins, instructors, the super-admin,
 * internal-org users, guests, and students still on the clock all pass.
 *
 * Reads via the USER'S OWN Supabase client, not the service role: RLS already
 * lets a member read their own membership row (proven by the M3 e2e check), so
 * the gate needs no elevated key — and fails OPEN if the row can't be read.
 * Fail-open is correct here: this gate enforces a renewal cadence, not a
 * security boundary, and a transient DB error must not lock every student out
 * of the product.
 */
import { getValidatedAuth } from "@/lib/auth/validatedUser";
import { decodeOrgClaim } from "@/lib/auth/orgClaim";

const INTERNAL_ORG = "d0d0d0d0-0000-4000-8000-000000000000";

export async function affiliationExpired(): Promise<boolean> {
  // Shares the request's single validated auth read (React cache()) with
  // getAuthedUser(), so the layout's gate and the page's guard make ONE
  // getUser() round-trip between them, not two.
  const auth = await getValidatedAuth();
  if (!auth) return false; // guests / unconfigured are gated by auth, not affiliation
  const { supabase, user, session } = auth;

  const { orgId, orgRole, isPlatformAdmin } = decodeOrgClaim(session?.access_token);

  if (isPlatformAdmin) return false;
  if (!orgId || orgId === INTERNAL_ORG) return false;
  if (orgRole !== "student") return false;

  const { data } = await supabase
    .from("org_members")
    .select("affiliation_expires_at")
    .eq("org_id", orgId)
    .eq("user_id", user.id)
    .maybeSingle();

  const exp = data?.affiliation_expires_at;
  return Boolean(exp && new Date(exp).getTime() < Date.now());
}
