import "server-only";
import type { SupabaseClient } from "@supabase/supabase-js";

/**
 * End every session of a user whose access was just taken away — removed from
 * an org, deactivated (SEC-05). Deletes their refresh sessions (0083
 * revoke_user_sessions, service-role only), so no new access token can be minted
 * with the old org claims; an access token already issued lapses within the JWT
 * lifetime, and the API gates re-check membership in the DB meanwhile.
 *
 * Never throws: the membership change already happened and must be reported as
 * done — a failure here is logged for follow-up.
 */
export async function revokeUserSessions(admin: SupabaseClient, userId: string): Promise<boolean> {
  try {
    const { error } = await admin.rpc("revoke_user_sessions", { p_user: userId });
    if (error) { console.error("[auth] revoke_user_sessions failed:", error.message); return false; }
    return true;
  } catch (e) {
    console.error("[auth] revoke_user_sessions threw:", (e as Error).message);
    return false;
  }
}
