import "server-only";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";

/**
 * Atomic session lifecycle transition (migration 0071 `team_transition`): the
 * status flip, pause clock, pause reason and the broadcast lifecycle event happen
 * in ONE database transaction under the session lock — so a failed step can no
 * longer leave a session "ended" with no session.ended event (audit I3/M1).
 * Invalid / already-applied transitions come back as `noop`, never an error.
 */
export interface TransitionResult {
  ok: boolean;
  noop?: boolean;
  error?: string;       // e.g. "not_ready", "not_found"
  count?: number;       // not_ready: how many players aren't ready
  seq?: number;
  type?: string;
  status?: string;
}

export async function teamTransition(
  sessionId: string,
  to: "running" | "paused" | "ended",
  reason: string,
  by: string | null,
  detail?: string | null,
): Promise<{ result: TransitionResult } | { error: string }> {
  const admin = getSupabaseAdminClient();
  if (!admin) return { error: "Server not configured." };
  const { data, error } = await admin.rpc("team_transition", {
    p_session: sessionId, p_to: to, p_reason: reason, p_by: by, p_detail: detail ?? null,
  });
  if (error) {
    console.error("[team_transition]", sessionId, to, error.message);
    return { error: "Couldn't update the session. Please try again." };
  }
  return { result: (data ?? { ok: false }) as TransitionResult };
}
