/**
 * Server-side validation of the branding a super-admin saves (src/app/api/superadmin/orgs/[id]).
 */
import { LOGO_DATA_URL, LOGO_MAX_BYTES, SENDER } from "./brand";
import { parseTheme } from "./theme";

/**
 * The branding the super-admin may store (organizations.branding is readable by the org's
 * members, so it is whitelisted and capped, never a free-form blob). White-label fields: see
 * src/lib/brand/brand.ts. `keepLogo` = no logo_data sent, so the stored one stays.
 */
export function sanitizeBranding(b: Record<string, unknown>): { branding: Record<string, string | boolean>; keepLogo: boolean } | { error: string } {
  const branding: Record<string, string | boolean> = {};
  if (typeof b.color === "string" && /^#[0-9a-fA-F]{6}$/.test(b.color)) branding.color = b.color;
  if (typeof b.logo_url === "string" && /^https:\/\/\S+$/.test(b.logo_url)) branding.logo_url = b.logo_url.slice(0, 500);
  if (b.white_label === true) branding.white_label = true;
  if (typeof b.product_name === "string") {
    const name = b.product_name.replace(/[\u0000-\u001f<>]/g, "").trim().slice(0, 60);
    if (name) branding.product_name = name;
  }
  if (b.logo_has_name === true) branding.logo_has_name = true;
  if (typeof b.support_email === "string" && b.support_email.trim()) {
    const e = b.support_email.trim();
    if (!/^[^\s@<>"]+@[^\s@<>"]+\.[a-z]{2,}$/i.test(e) || e.length > 254) return { error: "Support email isn't a valid address." };
    branding.support_email = e;
  }
  if (typeof b.email_from === "string" && b.email_from.trim()) {
    const f = b.email_from.trim();
    if (!SENDER.test(f)) return { error: 'Sender must look like "College SOC <noreply@college.ac.il>".' };
    branding.email_from = f;
  }
  // Theme (accent / background colours): only valid #rrggbb values are kept.
  const theme = parseTheme(b.theme);
  if (theme) (branding as Record<string, unknown>).theme = theme;
  let keepLogo = b.logo_data === undefined;
  if (typeof b.logo_data === "string" && b.logo_data) {
    if (!LOGO_DATA_URL.test(b.logo_data)) return { error: "Logo must be a PNG, JPEG or WebP image." };
    const bytes = Math.floor((b.logo_data.length - b.logo_data.indexOf(",") - 1) * 3 / 4);
    if (bytes > LOGO_MAX_BYTES) return { error: `Logo is too large (max ${Math.round(LOGO_MAX_BYTES / 1024)} KB).` };
    branding.logo_data = b.logo_data;
    keepLogo = false;
  }
  return { branding, keepLogo };
}
