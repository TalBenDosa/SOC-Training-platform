import { NextResponse } from "next/server";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";

/**
 * One team session + its roster (Phase 0.3) — for the lobby / exercise room.
 * Readable by a member of the session OR staff of the session's org. Authorised
 * here; DB RLS (0049) is the second gate. The reporter's identity is limited to
 * handle/display_name — no emails leak to peers.
 */
export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const user = await getAuthedUser();
  if (!user) return NextResponse.json({ error: "Authentication required." }, { status: 401 });
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  const { data: sess } = await admin.from("team_sessions").select("*").eq("id", id).maybeSingle();
  if (!sess) return NextResponse.json({ error: "Session not found." }, { status: 404 });

  // team_session_members has no FK to profiles (it references auth.users), so a
  // PostgREST embed can't resolve — fetch members and profiles separately, merge.
  const { data: mem } = await admin
    .from("team_session_members")
    .select("user_id, role, status, ready_at")
    .eq("session_id", id);

  const iAmMember = (mem ?? []).some(m => m.user_id === user.id);
  const iAmStaff = user.isPlatformAdmin ||
    ((user.orgRole === "org_admin" || user.orgRole === "instructor") && user.orgId === sess.org_id);
  if (!iAmMember && !iAmStaff) return NextResponse.json({ error: "Not your session." }, { status: 403 });

  const ids = (mem ?? []).map(m => m.user_id);
  const { data: profs } = await admin
    .from("profiles").select("id, handle, display_name")
    .in("id", ids.length ? ids : ["00000000-0000-0000-0000-000000000000"]);
  const pmap = new Map((profs ?? []).map(p => [p.id, p as { handle?: string; display_name?: string }]));

  const roster = (mem ?? []).map(m => {
    const p = pmap.get(m.user_id);
    return {
      user_id: m.user_id, role: m.role, status: m.status, ready_at: m.ready_at,
      name: p?.display_name || p?.handle || m.user_id.slice(0, 8),
      handle: p?.handle ?? null,
    };
  });

  return NextResponse.json({
    session: sess,
    roster,
    me: { id: user.id, is_staff: iAmStaff, role: roster.find(r => r.user_id === user.id)?.role ?? null },
  });
}
