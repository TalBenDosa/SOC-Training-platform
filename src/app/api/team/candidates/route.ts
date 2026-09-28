import { NextResponse } from "next/server";
import { requireOrgStaff } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { isRootOrg, ROOT_ENVIRONMENT_LABEL } from "@/lib/org/rootEnvironment";

/**
 * Team-SOC invite candidates (read-only) — who the Session Builder may put on a
 * roster. Exercise-report #18: the builder showed a flat list with no scoping cue.
 *
 * Scope is ALWAYS the caller's own org, from the JWT (never a request parameter),
 * i.e. exactly the org POST /api/team/sessions pins the new session to and
 * validates invitees against — so every candidate listed here is one the create
 * route will accept. A super-admin "picks an org" with the sidebar environment
 * switcher (which restamps the JWT org); the response names the org so the
 * builder can say where it's inviting from.
 *
 * Same gate as creating a session (org staff: org_admin, instructor or platform admin) — this endpoint must
 * not widen who can enumerate an org's members. Platform super-admins are
 * invisible to per-org views (as in /api/org/members) and the caller is omitted
 * (they join as the instructor).
 *
 *  GET  — { org: { id, name, is_root }, members: [{ user_id, display_name, handle, role }] }
 *  POST — { email } → { user_id | null }: exact e-mail match against THIS org's
 *         active members, so staff can find a student by e-mail without the list
 *         ever shipping anyone's address to the browser (body, not query string,
 *         so the address stays out of URLs/logs).
 */

async function gate() {
  const g = await requireOrgStaff("team.candidates");
  if ("error" in g) return { error: g.error } as const;
  const orgId = g.user.orgId;
  if (!orgId) return { error: NextResponse.json({ error: "No organisation in session." }, { status: 400 }) } as const;
  const admin = getSupabaseAdminClient();
  if (!admin) return { error: NextResponse.json({ error: "Server not configured." }, { status: 503 }) } as const;
  return { admin, orgId, userId: g.user.id } as const;
}

export async function GET() {
  const c = await gate();
  if ("error" in c) return c.error;
  const { admin, orgId, userId } = c;

  const [{ data: org }, { data: rows }] = await Promise.all([
    admin.from("organizations").select("id, name").eq("id", orgId).maybeSingle(),
    admin.from("org_members")
      .select("user_id, role, status, profiles(handle, display_name, is_platform_admin)")
      .eq("org_id", orgId).eq("status", "active")
      .order("joined_at", { ascending: true }),
  ]);

  const members = (rows ?? [])
    .filter(m => m.user_id !== userId)
    .filter(m => !(m.profiles as unknown as { is_platform_admin?: boolean } | null)?.is_platform_admin)
    .map(m => {
      const p = m.profiles as unknown as { handle?: string | null; display_name?: string | null } | null;
      return { user_id: m.user_id as string, display_name: p?.display_name ?? null, handle: p?.handle ?? null, role: m.role as string };
    });

  const root = isRootOrg(orgId);
  return NextResponse.json({
    org: { id: orgId, name: root ? ROOT_ENVIRONMENT_LABEL : (org?.name ?? "your organisation"), is_root: root },
    members,
  });
}

export async function POST(req: Request) {
  const c = await gate();
  if ("error" in c) return c.error;
  const { admin, orgId, userId } = c;

  let body: Record<string, unknown> = {};
  try { body = await req.json(); } catch { /* validated below */ }
  const email = typeof body.email === "string" ? body.email.trim().slice(0, 320) : "";
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return NextResponse.json({ error: "Enter a full e-mail address." }, { status: 400 });

  const { data: found, error } = await admin.rpc("find_user_id_by_email", { p_email: email });
  if (error) { console.error("[team candidates] lookup:", error.message); return NextResponse.json({ error: "Lookup failed." }, { status: 500 }); }
  if (!found || found === userId) return NextResponse.json({ user_id: null });

  // Only reveal a match if they're an ACTIVE member of the caller's org — an
  // address from another college answers exactly like an unknown one.
  const { data: mem } = await admin.from("org_members")
    .select("user_id, profiles(is_platform_admin)")
    .eq("org_id", orgId).eq("user_id", found as string).eq("status", "active").maybeSingle();
  const hidden = (mem?.profiles as unknown as { is_platform_admin?: boolean } | null)?.is_platform_admin;
  return NextResponse.json({ user_id: mem && !hidden ? (found as string) : null });
}
