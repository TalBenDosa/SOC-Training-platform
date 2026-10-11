import { NextResponse } from "next/server";
import { requireSuperAdmin } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { ROOT_ORG_ID, ROOT_ENVIRONMENT_LABEL } from "@/lib/org/rootEnvironment";

/**
 * The super-admin's environment TREE, not a flat list:
 *
 *   root      — the Main environment (the system org). The super-admin's home
 *               base; where they manage everything.
 *   children  — every OTHER environment the super-admin is an active member of
 *               (the client colleges), each enterable in one click.
 *   current_org_id / at_root — where the super-admin is standing right now, so
 *               the switcher can highlight it and offer "return to Main".
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

  const orgs = (memberships ?? [])
    .map(m => (m.organizations as unknown as { id: string; name: string; slug: string } | null))
    .filter((o): o is { id: string; name: string; slug: string } => !!o);

  // Children = every environment EXCEPT the root, alphabetised.
  const children = orgs
    .filter(o => o.id !== ROOT_ORG_ID)
    .sort((a, b) => a.name.localeCompare(b.name));

  // Root = the Main environment. Present it with a fixed label so the raw system
  // org name ("Internal / Default") never surfaces as the super-admin's home.
  // Fetch it directly if the super-admin somehow isn't a listed member of it, so
  // the root slot is always shown.
  let root = orgs.find(o => o.id === ROOT_ORG_ID) ?? null;
  if (!root) {
    const { data } = await admin
      .from("organizations").select("id, name, slug").eq("id", ROOT_ORG_ID).maybeSingle();
    root = data ?? { id: ROOT_ORG_ID, name: ROOT_ENVIRONMENT_LABEL, slug: "root" };
  }

  const currentOrgId = profile?.org_id ?? null;

  return NextResponse.json({
    root: { id: root.id, name: ROOT_ENVIRONMENT_LABEL, org_name: root.name, slug: root.slug },
    children,
    current_org_id: currentOrgId,
    at_root: currentOrgId === ROOT_ORG_ID,
  });
}
