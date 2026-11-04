import { NextResponse } from "next/server";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { brandFromOrg } from "@/lib/brand/brand";
import { parseFeatures } from "@/lib/brand/features";
import { orgRoomsLocked, isMissingColumn } from "@/lib/org/roomLock";

/**
 * The caller's own org name + branding (accent colour, logo URL), for theming
 * the app, and `brand`: the org's white-label brand (src/lib/brand), which is
 * the platform brand unless the org is white label. Scoped to the org in the
 * caller's JWT — never another org's. Returns empty branding when there's no
 * org context (pre-migration / guest), so the UI keeps the default identity.
 */
export async function GET() {
  const user = await getAuthedUser();
  if (!user || !user.orgId) return NextResponse.json({ name: null, branding: {}, all_rooms_unlocked: false, rooms_locked: false, brand: null });

  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ name: user.orgName ?? null, branding: {}, all_rooms_unlocked: false, rooms_locked: false, brand: null });

  const ORG_COLS = "id, name, slug, custom_domain, branding, all_rooms_unlocked";
  const readOrg = (cols: string) => admin.from("organizations").select(cols).eq("id", user.orgId!).maybeSingle();
  const [orgRes, { data: profile }] = await Promise.all([
    readOrg(`${ORG_COLS}, rooms_locked`),
    admin.from("profiles").select("org_id").eq("id", user.id).maybeSingle(),
  ]);
  // Before migration 0102 there is no rooms_locked column: read without it (rooms stay open).
  const { data } = (isMissingColumn(orgRes.error) ? await readOrg(ORG_COLS) : orgRes) as unknown as {
    data: { id: string; name: string; slug: string; custom_domain: string | null; branding: unknown; all_rooms_unlocked?: boolean; rooms_locked?: boolean } | null;
  };
  // Never brand one environment with another's identity: the white-label brand is returned
  // only when the session's org IS the environment the user is standing in right now.
  const sameEnvironment = !profile || profile.org_id === user.orgId;
  // The uploaded logo (up to 150 KB) is served by /api/brand/logo, not inlined here.
  const { logo_data: _logo, ...branding } = ((data?.branding ?? {}) as Record<string, unknown>);
  void _logo;
  return NextResponse.json({
    name: data?.name ?? user.orgName ?? null,
    branding,
    // Rooms are open unless this org's admin locked them (0102); all_rooms_unlocked (0036)
    // is the older super-admin bypass and still means open.
    all_rooms_unlocked: data?.all_rooms_unlocked === true,
    rooms_locked: orgRoomsLocked(data),
    brand: data && sameEnvironment ? { ...brandFromOrg(data), orgId: data.id } : null,
    // The environment's plan (src/lib/brand/features.ts), white label or not.
    features: parseFeatures((data?.branding as Record<string, unknown> | null)?.features),
  });
}
