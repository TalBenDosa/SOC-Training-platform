import "server-only";
/**
 * Server-side brand resolution (white label, see ./brand.ts).
 *
 * Pages: the Host a request arrives on picks the brand. Platform hosts (production, Vercel
 * aliases, localhost) never hit the database; any other host is looked up once a minute per
 * instance by organizations.custom_domain. The Host header only decides what THIS response
 * looks like, so a forged one changes nothing for anyone else.
 *
 * Emails: links and brand come from the organization row (custom_domain), never the request's
 * Host (the reset-poisoning rule in src/lib/http/siteOrigin.ts).
 */
import { headers } from "next/headers";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { PLATFORM_BRAND, brandFromOrg, hostOf, isPlatformHost, senderFor, type Brand } from "./brand";
import type { EmailBrand } from "@/lib/email/templates";

const TTL_MS = 60_000;
const byHost = new Map<string, { at: number; brand: Brand }>();
const byOrg = new Map<string, { at: number; brand: Brand }>();

const ORG_COLUMNS = "id, name, custom_domain, branding";

export async function brandForHost(host: string): Promise<Brand> {
  if (isPlatformHost(host)) return PLATFORM_BRAND;
  try { return await lookupHostBrand(host); } catch (e) {
    console.error("[brand] host lookup threw:", e instanceof Error ? e.message : String(e));
    return PLATFORM_BRAND;
  }
}

async function lookupHostBrand(host: string): Promise<Brand> {
  const hit = byHost.get(host);
  if (hit && Date.now() - hit.at < TTL_MS) return hit.brand;
  const admin = getSupabaseAdminClient();
  if (!admin) return PLATFORM_BRAND;
  const { data, error } = await admin.from("organizations").select(ORG_COLUMNS).eq("custom_domain", host).maybeSingle();
  if (error) { console.error("[brand] host lookup failed:", error.message); return hit?.brand ?? PLATFORM_BRAND; }
  const brand = brandFromOrg(data);
  byHost.set(host, { at: Date.now(), brand });
  return brand;
}

/** The brand of the current page request (cheap: platform hosts skip the lookup, others hit the TTL cache). */
export async function getRequestBrand(): Promise<Brand> {
  const h = await headers();
  return brandForHost(hostOf(h.get("host")));
}

/** An organization's brand by id (emails, certificates); the platform's for no / unknown org. */
export async function brandForOrg(orgId: string | null | undefined): Promise<Brand> {
  if (!orgId) return PLATFORM_BRAND;
  try { return await lookupOrgBrand(orgId); } catch (e) {
    // Branding must never block an email or a quota answer: fall back to the platform's.
    console.error("[brand] org lookup threw:", e instanceof Error ? e.message : String(e));
    return PLATFORM_BRAND;
  }
}

async function lookupOrgBrand(orgId: string): Promise<Brand> {
  const hit = byOrg.get(orgId);
  if (hit && Date.now() - hit.at < TTL_MS) return hit.brand;
  const admin = getSupabaseAdminClient();
  if (!admin) return PLATFORM_BRAND;
  const { data, error } = await admin.from("organizations").select(ORG_COLUMNS).eq("id", orgId).maybeSingle();
  if (error) { console.error("[brand] org lookup failed:", error.message); return hit?.brand ?? PLATFORM_BRAND; }
  const brand = brandFromOrg(data);
  byOrg.set(orgId, { at: Date.now(), brand });
  return brand;
}

/**
 * Everything an email for this organization needs: the brand for the template, the origin
 * its links use (the org's own domain for a white-label org that has one, else
 * `fallbackOrigin`, the canonical site) and the From line ("" = the platform sender).
 */
export async function emailContextForOrg(orgId: string | null | undefined, fallbackOrigin: string): Promise<{
  brand: Brand; origin: string; emailBrand: EmailBrand; from: string;
}> {
  const brand = await brandForOrg(orgId);
  const origin = brand.origin ?? fallbackOrigin;
  const emailBrand: EmailBrand = {
    productName: brand.productName,
    whiteLabel: brand.whiteLabel,
    logoUrl: brand.whiteLabel && brand.logoSrc ? `${origin}${brand.logoSrc}` : null,
    color: brand.color,
  };
  return { brand, origin, emailBrand, from: senderFor(brand, platformSenderAddress()) };
}

/** The address part of the platform sender (EMAIL_FROM, else the verified default). */
function platformSenderAddress(): string {
  const f = process.env.EMAIL_FROM?.trim() || "noreply@hackthesoc.app";
  const m = /<([^>]+)>/.exec(f);
  return (m ? m[1] : f).trim();
}

/** Drop cached brands after a super-admin edit (this instance; others expire within TTL_MS). */
export function forgetBrand(orgId: string): void {
  byOrg.delete(orgId);
  for (const [host, v] of byHost) if (v.brand.orgId === orgId || v.brand === PLATFORM_BRAND) byHost.delete(host);
}
