import { NextResponse } from "next/server";
import { getSupabaseServerClient } from "@/lib/supabase/server";

/**
 * Per-cohort leaderboard for the signed-in student.
 *
 * Runs the query through the USER-context client (not the service role), so the
 * `public.org_leaderboard()` SECURITY DEFINER function resolves current_org()
 * from the caller's own JWT and can only ever return their own org's rows (see
 * migration 0018). Returns safe columns only — display name, xp, level, rank.
 *
 * Degrades quietly to an empty list when Supabase isn't configured, the user
 * isn't signed in, has no org (solo user), or the 0018 migration hasn't been
 * applied yet — the UI just shows its empty state rather than erroring.
 */
export async function GET() {
  const supabase = await getSupabaseServerClient();
  if (!supabase) return NextResponse.json({ rows: [], available: false });

  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({ rows: [], available: false });

  const { data, error } = await supabase.rpc("org_leaderboard", { p_limit: 20 });
  if (error) {
    // Missing function (migration not applied) or any RPC error → empty, not 500.
    return NextResponse.json({ rows: [], available: false });
  }

  const rows = (data ?? []).map((r: { rank: number; display_name: string; xp: number; lvl: number; is_me: boolean }) => ({
    rank: Number(r.rank),
    displayName: r.display_name,
    xp: r.xp,
    level: r.lvl,
    isMe: r.is_me,
  }));

  // available:true only when there's a real cohort (more than just yourself).
  return NextResponse.json({ rows, available: rows.length > 1 });
}
