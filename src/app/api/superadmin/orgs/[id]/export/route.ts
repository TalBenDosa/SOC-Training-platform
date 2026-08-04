import { NextResponse } from "next/server";
import { requireSuperAdmin } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";

type Ctx = { params: Promise<{ id: string }> };

/**
 * Full export of a college's data as JSON — for offboarding (hand the file to
 * the college) or backup before a purge. Super-admin only; downloaded as an
 * attachment. Covers the org, its roster, and every learner-data row.
 */
export async function GET(_req: Request, { params }: Ctx) {
  const gate = await requireSuperAdmin("superadmin.org.export");
  if ("error" in gate) return gate.error;
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });
  const { id } = await params;

  const [org, members, profiles, userProgress, rooms, sessions, scenarios] = await Promise.all([
    admin.from("organizations").select("*").eq("id", id).maybeSingle(),
    admin.from("org_members").select("*").eq("org_id", id),
    admin.from("profiles").select("id, handle, display_name, xp, level, created_at").eq("org_id", id),
    admin.from("user_progress").select("*").eq("org_id", id),
    admin.from("room_progress").select("*").eq("org_id", id),
    admin.from("dashboard_sessions").select("*").eq("org_id", id),
    admin.from("scenario_history").select("*").eq("org_id", id),
  ]);

  if (!org.data) return NextResponse.json({ error: "Organization not found." }, { status: 404 });

  const payload = {
    exported_at: new Date().toISOString(),
    organization: org.data,
    members: members.data ?? [],
    profiles: profiles.data ?? [],
    user_progress: userProgress.data ?? [],
    room_progress: rooms.data ?? [],
    dashboard_sessions: sessions.data ?? [],
    scenario_history: scenarios.data ?? [],
  };

  return new NextResponse(JSON.stringify(payload, null, 2), {
    headers: {
      "Content-Type": "application/json",
      "Content-Disposition": `attachment; filename="org-${org.data.slug}-export.json"`,
    },
  });
}
