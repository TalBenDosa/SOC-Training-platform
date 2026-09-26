import { getSupabaseAdminClient } from "@/lib/supabase/admin";

/**
 * Append a SYSTEM session_event (e.g. member.added / member.role_changed) from a
 * route. Goes through the 0071 `append_system_event` RPC, which takes the
 * per-session lock before allocating the next seq — so it can never collide with
 * a player action or the promote tick (the old client-side max(seq)+1 retry loop
 * is gone). The broadcast trigger fans the row out to the room on commit.
 * Lifecycle changes (start / pause / resume / end) use `teamTransition` instead,
 * which flips the status and appends the event atomically.
 */
export async function appendSystemEvent(
  sessionId: string,
  type: string,
  payload: Record<string, unknown>,
): Promise<{ ok: true; seq: number } | { ok: false; error: string }> {
  const admin = getSupabaseAdminClient();
  if (!admin) return { ok: false, error: "Server not configured." };
  const { data, error } = await admin.rpc("append_system_event", { p_session: sessionId, p_type: type, p_payload: payload });
  if (error) {
    console.error("[append_system_event]", sessionId, type, error.message);
    return { ok: false, error: "Couldn't record the session event." };
  }
  return { ok: true, seq: Number(data) };
}
