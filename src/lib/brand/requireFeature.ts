import "server-only";
/**
 * Server-side plan gate for app pages (tenant config features, ./features.ts): a page whose
 * feature the current environment's plan doesn't include redirects to /progress with a notice,
 * so hiding the nav link is never the only barrier. Called by each feature's route layout.
 * Guests and the platform super-admin pass (the super-admin previews any environment).
 */
import { redirect } from "next/navigation";
import { getValidatedAuth } from "@/lib/auth/validatedUser";
import { decodeOrgClaim } from "@/lib/auth/orgClaim";
import { featuresForOrg } from "./server";
import type { FeatureKey } from "./features";

export async function requireFeature(key: FeatureKey): Promise<void> {
  const auth = await getValidatedAuth();
  if (!auth) return;
  const { orgId, isPlatformAdmin } = decodeOrgClaim(auth.session?.access_token);
  if (isPlatformAdmin || !orgId) return;
  const features = await featuresForOrg(orgId);
  if (!features[key]) redirect("/progress?reason=feature");
}
