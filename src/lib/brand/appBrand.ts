import "server-only";
/**
 * The brand INSIDE the app, resolved on the server so the first paint is already right
 * (no HACK THE SOC logo flashing before a white-label environment's own, e.g. right after
 * switching environments, which reloads the page with the new session).
 *
 * Same rule as /api/org/branding (iron rule: one environment's identity never shows in
 * another): the session's org (JWT) must be the environment the profile stands in, and that
 * org must be white label. Public pages never use this; they keep the host's brand.
 */
import { getValidatedAuth } from "@/lib/auth/validatedUser";
import { decodeOrgClaim } from "@/lib/auth/orgClaim";
import { brandForOrg, getRequestBrand } from "./server";
import type { Brand } from "./brand";

/** The current environment's white-label brand, or null (platform / guest / any doubt). */
export async function envBrandForSession(): Promise<Brand | null> {
  try {
    const auth = await getValidatedAuth();
    if (!auth) return null;
    const { orgId } = decodeOrgClaim(auth.session?.access_token);
    if (!orgId) return null;
    const { data: profile } = await auth.supabase.from("profiles").select("org_id").eq("id", auth.user.id).maybeSingle();
    if (profile && profile.org_id !== orgId) return null;
    const brand = await brandForOrg(orgId);
    return brand.whiteLabel ? brand : null;
  } catch (e) {
    console.error("[brand] env brand failed:", e instanceof Error ? e.message : String(e));
    return null;
  }
}

/** What an app page presents itself as: a white-label domain's own brand, else the environment's. */
export async function getAppBrand(): Promise<{ brand: Brand; env: Brand | null }> {
  const host = await getRequestBrand();
  if (host.whiteLabel) return { brand: host, env: null };
  const env = await envBrandForSession();
  return { brand: env ?? host, env };
}
