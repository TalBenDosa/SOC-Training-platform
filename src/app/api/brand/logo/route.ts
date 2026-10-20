import { NextResponse } from "next/server";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { LOGO_DATA_URL, hostOf, isPlatformHost } from "@/lib/brand/brand";

/**
 * GET /api/brand/logo?org=<id> — a white-label organization's uploaded logo (white label,
 * src/lib/brand/brand.ts). Public: the logo is shown on the sign-in page, as the favicon and
 * in emails, before anyone signs in. Without ?org the request host's organization is used.
 * Only raster images stored as a data URL in organizations.branding.logo_data are served.
 */
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export async function GET(req: Request) {
  const url = new URL(req.url);
  const orgParam = url.searchParams.get("org");
  const admin = getSupabaseAdminClient();
  if (!admin) return new NextResponse(null, { status: 404 });

  let query = admin.from("organizations").select("branding");
  if (orgParam) {
    if (!UUID.test(orgParam)) return new NextResponse(null, { status: 404 });
    query = query.eq("id", orgParam);
  } else {
    const host = hostOf(req.headers.get("host"));
    if (isPlatformHost(host)) return new NextResponse(null, { status: 404 });
    query = query.eq("custom_domain", host);
  }
  const { data } = await query.maybeSingle();
  const b = (data?.branding ?? {}) as Record<string, unknown>;
  const logo = b.white_label === true && typeof b.logo_data === "string" ? b.logo_data : "";
  const m = LOGO_DATA_URL.exec(logo);
  if (!m) return new NextResponse(null, { status: 404 });

  const bytes = Buffer.from(logo.slice(logo.indexOf(",") + 1), "base64");
  return new NextResponse(bytes, {
    headers: {
      "Content-Type": `image/${m[1]}`,
      "Cache-Control": "public, max-age=600, stale-while-revalidate=3600",
      "X-Content-Type-Options": "nosniff",
    },
  });
}
