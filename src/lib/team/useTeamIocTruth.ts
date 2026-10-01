"use client";
import { useEffect, useRef, useState } from "react";
import type { IocTruth } from "@/lib/edr/iocIntel";

/** Don't refetch more often than this while logs stream in (a log lands every ~10–40 s). */
export const IOC_TRUTH_MIN_INTERVAL_MS = 8_000;

/**
 * The server-built threat-intel truth for the logs this team session has shown
 * (/api/team/sessions/[id]/ioc-truth). Refetched as the feed grows (throttled), so
 * a lookup on a log that just arrived is judged with it. Null until the first
 * load / on error — the lookup then falls back to what the log itself says.
 */
export function useTeamIocTruth(sessionId: string | null, feedCount: number, enabled = true): IocTruth | null {
  const [truth, setTruth] = useState<IocTruth | null>(null);
  const lastAt = useRef(0);
  const pending = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    if (!sessionId || !enabled || feedCount === 0) return;
    let cancelled = false;
    const load = () => {
      lastAt.current = Date.now();
      fetch(`/api/team/sessions/${sessionId}/ioc-truth`)
        .then(r => (r.ok ? r.json() : null))
        .then(d => { if (!cancelled && d && d.version === 1 && d.entries) setTruth(d as IocTruth); })
        .catch(() => undefined);
    };
    const wait = IOC_TRUTH_MIN_INTERVAL_MS - (Date.now() - lastAt.current);
    if (pending.current) clearTimeout(pending.current);
    if (wait <= 0) load();
    else pending.current = setTimeout(load, wait);
    return () => { cancelled = true; if (pending.current) clearTimeout(pending.current); };
  }, [sessionId, feedCount, enabled]);

  return truth;
}
