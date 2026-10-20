/**
 * White label: who the platform presents itself as on this request.
 *
 * By default the platform is HACK THE SOC. A white-label organization (branding.white_label
 * = true) gets its own product name, logo and colour everywhere a learner looks, on its own
 * host name (organizations.custom_domain, migration 0100), so the experience never shows it
 * is running on another product. Isomorphic: no server or React imports.
 */

export interface Brand {
  /** True for a white-label organization: the platform's own name and logo must not show. */
  whiteLabel: boolean;
  /** The name shown in titles, the logo lockup, emails and certificates. */
  productName: string;
  /** The organization behind a white-label brand (null for the platform). */
  orgId: string | null;
  /** Same-origin URL of the brand logo (null = draw the platform mark / name only). */
  logoSrc: string | null;
  /** The logo already spells the name (a wordmark): show it without the name beside it. */
  logoHasName: boolean;
  /** Accent colour, #rrggbb (null = the platform's). */
  color: string | null;
  /** Where learners and admins are told to ask for help (null = no address shown). */
  supportEmail: string | null;
  /** https://<custom_domain> for a white-label org with its own domain (null otherwise). */
  origin: string | null;
  /** Sender for this org's emails, "Name <noreply@their-domain>" (needs that domain verified
   *  with the email provider); null = the platform's sender under the brand's name. */
  emailFrom: string | null;
}

export const PLATFORM_NAME = "HACK THE SOC";

export const PLATFORM_BRAND: Brand = {
  whiteLabel: false, productName: PLATFORM_NAME, orgId: null, logoSrc: null, logoHasName: false, color: null, supportEmail: null, origin: null, emailFrom: null,
};

/** The logo route: serves the request host's (or the signed-in org's) uploaded logo. */
export const BRAND_LOGO_PATH = "/api/brand/logo";

/** Raster logos only (an SVG served from our origin could carry script); kept small. */
export const LOGO_DATA_URL = /^data:image\/(png|jpeg|webp);base64,[A-Za-z0-9+/]+={0,2}$/;
export const LOGO_MAX_BYTES = 150 * 1024;

const HOSTNAME = /^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

/** A request Host header → bare lower-case host name (no port); "" when unusable. */
export function hostOf(header: string | null | undefined): string {
  const h = (header ?? "").split(",")[0].trim().toLowerCase();
  return h.replace(/:\d+$/, "").replace(/\.$/, "");
}

/** Normalise an admin-typed domain ("https://SOC.College.ac.il/" → "soc.college.ac.il"); null when invalid. */
export function normalizeDomain(input: string): string | null {
  const d = input.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/:\d+$/, "").replace(/\.$/, "");
  if (d.length < 4 || d.length > 253 || !HOSTNAME.test(d)) return null;
  if (isPlatformHost(d)) return null;
  return d;
}

/**
 * Hosts that always show the platform itself: the production domain, Vercel deployment
 * aliases and local development. A white-label brand is only ever looked up for other hosts.
 */
export function isPlatformHost(host: string): boolean {
  if (!host) return true;
  // Bare localhost only: a *.localhost name (e.g. wl-demo.localhost) can stand in for a
  // white-label domain in local development.
  if (host === "localhost" || host === "127.0.0.1" || host === "[::1]") return true;
  if (host === "hackthesoc.app" || host.endsWith(".hackthesoc.app")) return true;
  if (host.endsWith(".vercel.app")) return true;
  const site = process.env.NEXT_PUBLIC_SITE_URL;
  if (site) { try { if (new URL(site).hostname.toLowerCase() === host) return true; } catch { /* ignore */ } }
  return false;
}

export interface OrgBrandRow {
  id: string;
  name: string | null;
  custom_domain?: string | null;
  branding?: unknown;
}

const clip = (v: unknown, max: number) => (typeof v === "string" ? v.trim().slice(0, max) : "");
const EMAIL = /^[^\s@<>"]+@[^\s@<>"]+\.[a-z]{2,}$/i;
/** "Display Name <addr@domain.tld>" or a bare address; the name without <, >, " or line breaks. */
export const SENDER = /^(?:[^<>"\r\n]{1,60} <[^\s@<>"]+@[^\s@<>"]+\.[a-z]{2,}>|[^\s@<>"]+@[^\s@<>"]+\.[a-z]{2,})$/i;

/** An organization row → its brand. Not white label → the platform brand. */
export function brandFromOrg(org: OrgBrandRow | null | undefined): Brand {
  if (!org) return PLATFORM_BRAND;
  const b = (org.branding && typeof org.branding === "object" ? org.branding : {}) as Record<string, unknown>;
  if (b.white_label !== true) return PLATFORM_BRAND;
  const productName = clip(b.product_name, 60) || clip(org.name, 60) || PLATFORM_NAME;
  const hasLogo = typeof b.logo_data === "string" && LOGO_DATA_URL.test(b.logo_data);
  const support = clip(b.support_email, 254);
  return {
    whiteLabel: true,
    productName,
    orgId: org.id,
    logoSrc: hasLogo ? `${BRAND_LOGO_PATH}?org=${encodeURIComponent(org.id)}` : null,
    logoHasName: hasLogo && b.logo_has_name === true,
    color: typeof b.color === "string" && /^#[0-9a-fA-F]{6}$/.test(b.color) ? b.color : null,
    supportEmail: EMAIL.test(support) ? support : null,
    origin: org.custom_domain ? `https://${org.custom_domain}` : null,
    emailFrom: typeof b.email_from === "string" && SENDER.test(b.email_from.trim()) ? b.email_from.trim() : null,
  };
}

/** The From line for this brand's emails ("" = the configured platform sender). */
export function senderFor(brand: Brand, platformAddress = "noreply@hackthesoc.app"): string {
  if (!brand.whiteLabel) return "";
  if (brand.emailFrom) return brand.emailFrom;
  const name = brand.productName.replace(/[<>"\r\n]/g, "").slice(0, 60);
  return `${name} <${platformAddress}>`;
}

/** The tab-title suffix every page uses: "Learning Rooms // <brand>". */
export function brandTitle(page: string, brand: Brand): string {
  return `${page} // ${brand.productName}`;
}

/** "Contact <who>" for messages that send an admin to the seller (quotas, licences). */
export function contactLine(brand: Brand): string {
  if (!brand.whiteLabel) return `Contact ${PLATFORM_NAME}`;
  return brand.supportEmail ? `Contact ${brand.supportEmail}` : "Contact your platform administrator";
}
