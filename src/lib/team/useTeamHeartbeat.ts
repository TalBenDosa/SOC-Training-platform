"use client";
import { useEffect, useState } from "react";
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
 * A failed beat is retried by the next one; after UNSTABLE_AFTER failures in a
 * row the hook reports `true` so the room can say the connection is unstable —
 * a silent run of failures used to end in a surprise "coverage" pause (E-21).
 */
export const TEAM_HEARTBEAT_MS = 15_000;
const UNSTABLE_AFTER = 2;

export function useTeamHeartbeat(sessionId: string | null | undefined, enabled = true): boolean {
  const [unstable, setUnstable] = useState(false);
  useEffect(() => {
    if (!sessionId || !enabled) { setUnstable(false); return; }
    const sb = getSupabaseBrowserClient();
    if (!sb) return;
    let stopped = false;
    let failures = 0;
    const settle = (ok: boolean) => {
      if (stopped) return;
      failures = ok ? 0 : failures + 1;
      setUnstable(failures >= UNSTABLE_AFTER);
    };
    const beat = () => {
      if (stopped) return;
      void sb.rpc("team_heartbeat", { p_session: sessionId }).then(({ error }) => settle(!error), () => settle(false));
    };
    beat();
    const iv = setInterval(beat, TEAM_HEARTBEAT_MS);
    const onVisible = () => { if (document.visibilityState === "visible") beat(); };
    document.addEventListener("visibilitychange", onVisible);
    window.addEventListener("focus", onVisible);
    window.addEventListener("online", beat);
    return () => {
      stopped = true;
      clearInterval(iv);
      document.removeEventListener("visibilitychange", onVisible);
      window.removeEventListener("focus", onVisible);
      window.removeEventListener("online", beat);
    };
  }, [sessionId, enabled]);
  return unstable;
}
