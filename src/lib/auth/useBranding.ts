"use client";
/**
 * The caller's college branding — name, accent colour, logo — for light per-tenant theming
 * (a badge in the top bar), plus the per-org "all rooms unlocked" switch. Fetched once per
 * session by BrandProvider (src/lib/brand/BrandContext.tsx); empty for guests, so the app
 * keeps its default identity.
 */
import { useOrgBranding, type OrgBranding } from "@/lib/brand/BrandContext";

export type Branding = OrgBranding;

export function useBranding(): Branding {
  return useOrgBranding();
}
