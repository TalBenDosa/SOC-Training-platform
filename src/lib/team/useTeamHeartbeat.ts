"use client";
import { useEffect } from "react";
import { getSupabaseBrowserClient } from "@/lib/supabase/client";

/**
 * Server-side presence heartbeat (0071 `team_heartbeat`). The lifecycle tick in
 * the database decides coverage / instructor-left pauses from these — clients no
 * longer "elect" one browser to pause the whole class (audit S3/C4/C7).
 *
 * Every 15s plus on tab focus/visibility. Chrome throttles hidden tabs to about
 * one timer per minute, so the server thresholds (120s for a core Tier, 180s for
 * the instructor, two stale ticks in a row) tolerate a backgrounded tab — e.g. a
 * T2 working in the EDR console tab, which sends its own heartbeats too.
 * Fire-and-forget: a failed beat is simply retried by the next one.
 */
export const TEAM_HEARTBEAT_MS = 15_000;

export function useTeamHeartbeat(sessionId: string | null | undefined, enabled = true): void {
  useEffect(() => {
    if (!sessionId || !enabled) return;
    const sb = getSupabaseBrowserClient();
    if (!sb) return;
    let stopped = false;
    const beat = () => {
      if (stopped) return;
      void sb.rpc("team_heartbeat", { p_session: sessionId }).then(() => undefined, () => undefined);
    };
    beat();
    const iv = setInterval(beat, TEAM_HEARTBEAT_MS);
    const onVisible = () => { if (document.visibilityState === "visible") beat(); };
    document.addEventListener("visibilitychange", onVisible);
    window.addEventListener("focus", onVisible);
    return () => {
      stopped = true;
      clearInterval(iv);
      document.removeEventListener("visibilitychange", onVisible);
      window.removeEventListener("focus", onVisible);
    };
  }, [sessionId, enabled]);
}
