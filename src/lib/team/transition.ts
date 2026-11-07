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

/** How long "End shift" waits by default: the team is told "Shift ends in 2 minutes" (0104). */
export const END_NOTICE_MS = 120_000;

/**
 * Schedule the end of a running / paused shift (0104 team_schedule_end): the server
 * stores end_at, appends `session.end_scheduled` { ends_at, by, delay_ms }, and its
 * lifecycle tick ends the session at that time. Scheduling again while one is pending
 * returns the existing end time (noop).
 */
export async function teamScheduleEnd(sessionId: string, by: string | null, delayMs = END_NOTICE_MS):
  Promise<{ result: { ok: boolean; noop?: boolean; ends_at?: string; status?: string; error?: string } } | { error: string }> {
  const admin = getSupabaseAdminClient();
  if (!admin) return { error: "Server not configured." };
  const { data, error } = await admin.rpc("team_schedule_end", { p_session: sessionId, p_by: by, p_delay_ms: delayMs });
  if (error) {
    console.error("[team_schedule_end]", sessionId, error.message);
    return { error: "Couldn't schedule the end. Please try again." };
  }
  return { result: (data ?? { ok: false }) as { ok: boolean; noop?: boolean; ends_at?: string } };
}

/** Cancel a scheduled end (0104 team_cancel_end): appends `session.end_cancelled`. */
export async function teamCancelEnd(sessionId: string, by: string | null): Promise<{ result: { ok: boolean; noop?: boolean } } | { error: string }> {
  const admin = getSupabaseAdminClient();
  if (!admin) return { error: "Server not configured." };
  const { data, error } = await admin.rpc("team_cancel_end", { p_session: sessionId, p_by: by });
  if (error) {
    console.error("[team_cancel_end]", sessionId, error.message);
    return { error: "Couldn't cancel the end. Please try again." };
  }
  return { result: (data ?? { ok: false }) as { ok: boolean; noop?: boolean } };
}
