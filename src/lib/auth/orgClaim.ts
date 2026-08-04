/**
 * Reads the tenant context out of a Supabase access token.
 *
 * The custom access-token hook (migration 0010) stamps `org_id`, `org_role` and
 * `is_platform_admin` as top-level JWT claims. This decodes them from the raw
 * token WITHOUT verifying the signature — that's fine here because the token
 * already came from a trusted `supabase.auth` call; we only need to READ what
 * the server put in it. RLS (in the DB) is what actually enforces isolation.
 *
 * SAFE BEFORE THE MIGRATION: until the hook is enabled the claims simply aren't
 * present, so every field comes back null/false and callers behave exactly as
 * they do today. This lets the app-layer changes ship before 0010 is applied.
 *
 * Isomorphic: works in the browser (atob) and on the server (Buffer).
 */
export interface OrgClaim {
  orgId: string | null;
  orgRole: string | null;
  isPlatformAdmin: boolean;
}

const EMPTY: OrgClaim = { orgId: null, orgRole: null, isPlatformAdmin: false };

function base64UrlDecode(segment: string): string {
  const b64 = segment.replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4 === 0 ? b64 : b64 + "=".repeat(4 - (b64.length % 4));
  if (typeof atob === "function") return atob(pad);
  // Node / server
  return Buffer.from(pad, "base64").toString("binary");
}

/** Decode org context from a raw JWT access token. Returns EMPTY on anything malformed. */
export function decodeOrgClaim(accessToken: string | null | undefined): OrgClaim {
  if (!accessToken) return EMPTY;
  try {
    const payload = accessToken.split(".")[1];
    if (!payload) return EMPTY;
    const json = JSON.parse(base64UrlDecode(payload)) as Record<string, unknown>;
    const orgId = typeof json.org_id === "string" && json.org_id ? json.org_id : null;
    const orgRole = typeof json.org_role === "string" && json.org_role ? json.org_role : null;
    const isPlatformAdmin = json.is_platform_admin === true;
    return { orgId, orgRole, isPlatformAdmin };
  } catch {
    return EMPTY;
  }
}
