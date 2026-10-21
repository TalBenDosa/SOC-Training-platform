import { NextResponse } from "next/server";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { brandFromOrg } from "@/lib/brand/brand";
import { parseFeatures } from "@/lib/brand/features";

/**
 * The caller's own org name + branding (accent colour, logo URL), for theming
 * the app, and `brand`: the org's white-label brand (src/lib/brand), which is
 * the platform brand unless the org is white label. Scoped to the org in the
 * caller's JWT — never another org's. Returns empty branding when there's no
 * org context (pre-migration / guest), so the UI keeps the default identity.
 */
export async function GET() {
  const user = await getAuthedUser();
  if (!user || !user.orgId) return NextResponse.json({ name: null, branding: {}, all_rooms_unlocked: false, brand: null });

  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ name: user.orgName ?? null, branding: {}, all_rooms_unlocked: false, brand: null });

  const [{ data }, { data: profile }] = await Promise.all([
    admin.from("organizations")
      .select("id, name, slug, custom_domain, branding, all_rooms_unlocked")
      .eq("id", user.orgId)
      .maybeSingle(),
    admin.from("profiles").select("org_id").eq("id", user.id).maybeSingle(),
  ]);
  // Never brand one environment with another's identity: the white-label brand is returned
  // only when the session's org IS the environment the user is standing in right now.
  const sameEnvironment = !profile || profile.org_id === user.orgId;
  // The uploaded logo (up to 150 KB) is served by /api/brand/logo, not inlined here.
  const { logo_data: _logo, ...branding } = ((data?.branding ?? {}) as Record<string, unknown>);
  void _logo;
  return NextResponse.json({
    name: data?.name ?? user.orgName ?? null,
    branding,
    // Per-org gate bypass (migration 0036). Default false so normal prerequisite
    // gating applies; true only for orgs a super-admin has opted in.
    all_rooms_unlocked: data?.all_rooms_unlocked === true,
    brand: data && sameEnvironment ? { ...brandFromOrg(data), orgId: data.id } : null,
    // The environment's plan (src/lib/brand/features.ts), white label or not.
    features: parseFeatures((data?.branding as Record<string, unknown> | null)?.features),
  });
}
