import "server-only";
import type { SupabaseClient } from "@supabase/supabase-js";

/**
 * The caller's live seat in a session, or null — the same rule as the DB's
 * is_team_member (0071): a roster row that isn't `left` AND an active,
 * unexpired membership in the session's org. Routes use it so a member whose
 * affiliation lapsed can't still end / pause a room RLS already locks them out of.
 */
export async function activeSeat(
  admin: SupabaseClient, sessionId: string, orgId: string, userId: string,
): Promise<{ role: string; status: string } | null> {
  const [{ data: mem }, { data: om }] = await Promise.all([
    admin.from("team_session_members").select("role, status").eq("session_id", sessionId).eq("user_id", userId).maybeSingle(),
    admin.from("org_members").select("status, affiliation_expires_at").eq("org_id", orgId).eq("user_id", userId).maybeSingle(),
  ]);
  if (!mem || mem.status === "left") return null;
  if (!om || om.status !== "active") return null;
  if (om.affiliation_expires_at && Date.parse(om.affiliation_expires_at) <= Date.now()) return null;
  return { role: mem.role, status: mem.status };
}
