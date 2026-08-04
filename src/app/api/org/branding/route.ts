import { NextResponse } from "next/server";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";

/**
 * The caller's own org name + branding (accent colour, logo URL), for theming
 * the app. Scoped to the org in the caller's JWT — never another org's. Returns
 * empty branding when there's no org context (pre-migration / guest), so the UI
 * simply shows the default HACK THE SOC identity.
 */
export async function GET() {
  const user = await getAuthedUser();
  if (!user || !user.orgId) return NextResponse.json({ name: null, branding: {} });

  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ name: user.orgName ?? null, branding: {} });

  const { data } = await admin.from("organizations").select("name, branding").eq("id", user.orgId).maybeSingle();
  return NextResponse.json({ name: data?.name ?? user.orgName ?? null, branding: data?.branding ?? {} });
}
