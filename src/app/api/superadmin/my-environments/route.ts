import { NextResponse } from "next/server";
import { requireSuperAdmin } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";

/**
 * The environments the super-admin has accumulated — every org they are an
 * active member of — plus which one is the ACTIVE context right now
 * (profiles.org_id). Backs the header environment-switcher: the super-admin is
 * present in all environments and switches between them freely, so the switcher
 * needs both the list and the current selection.
 *
 * Super-admin only (requireSuperAdmin). Uses the service role deliberately —
 * this is a cross-tenant read, which RLS forbids for everyone else.
 */
export async function GET() {
  const gate = await requireSuperAdmin("superadmin.my_environments");
  if ("error" in gate) return gate.error;
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  const { data: memberships } = await admin
    .from("org_members")
    .select("org_id, organizations(id, name, slug)")
    .eq("user_id", gate.user.id)
    .eq("status", "active");

  const { data: profile } = await admin
    .from("profiles").select("org_id").eq("id", gate.user.id).maybeSingle();

  const environments = (memberships ?? [])
    .map(m => {
      const o = m.organizations as unknown as { id: string; name: string; slug: string } | null;
      return o ? { id: o.id, name: o.name, slug: o.slug } : null;
    })
    .filter(Boolean)
    .sort((a, b) => (a!.name).localeCompare(b!.name));

  return NextResponse.json({
    environments,
    current_org_id: profile?.org_id ?? null,
  });
}
