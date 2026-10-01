import { NextResponse } from "next/server";
import { requireSuperAdmin } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";

/**
 * Who can run this college, and have they actually got in?
 *
 * For the super-admin's org page: the staff invitations nobody has used yet
 * (with expiry) and the registered admins with their last sign-in — so an
 * environment whose admin never even signed in is visible at a glance, next to
 * the resend / sign-in-email buttons.
 */
type Ctx = { params: Promise<{ id: string }> };

export async function GET(_req: Request, { params }: Ctx) {
  const gate = await requireSuperAdmin("superadmin.admin_access");
  if ("error" in gate) return gate.error;
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });
  const { id: orgId } = await params;

  const [invRes, memRes] = await Promise.all([
    admin.from("invitations")
      .select("id, email, role, created_at, expires_at")
      .eq("org_id", orgId).in("role", ["org_admin", "instructor"]).is("accepted_at", null)
      .order("created_at", { ascending: false }).limit(50),
    admin.from("org_members")
      .select("user_id, role, status, joined_at, profiles(display_name, handle, is_platform_admin)")
      .eq("org_id", orgId).in("role", ["org_admin", "instructor"]).eq("status", "active"),
  ]);
  if (invRes.error || memRes.error) {
    console.error("[admin-access]", invRes.error?.message ?? memRes.error?.message);
    return NextResponse.json({ error: "Couldn't load admin access — please try again." }, { status: 500 });
  }

  const now = Date.now();
  const invites = (invRes.data ?? []).map(i => ({
    id: i.id, email: i.email, role: i.role, created_at: i.created_at, expires_at: i.expires_at,
    expired: Date.parse(i.expires_at) < now,
  }));

  // The platform admin's own memberships are oversight, not the college's staff.
  type P = { display_name?: string | null; handle?: string | null; is_platform_admin?: boolean } | null;
  const staff = (memRes.data ?? []).filter(m => !(m.profiles as unknown as P)?.is_platform_admin);
  const admins = await Promise.all(staff.map(async m => {
    const p = m.profiles as unknown as P;
    const { data } = await admin.auth.admin.getUserById(m.user_id);
    return {
      user_id: m.user_id, role: m.role, joined_at: m.joined_at,
      name: p?.display_name || p?.handle || m.user_id.slice(0, 8),
      email: data?.user?.email ?? null,
      last_sign_in_at: data?.user?.last_sign_in_at ?? null,
    };
  }));

  return NextResponse.json({ invites, admins });
}
