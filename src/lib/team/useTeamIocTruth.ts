"use client";
import { useEffect, useRef, useState } from "react";
import { extractIocs, iocDigest, type IocTruth, type IocType } from "@/lib/edr/iocIntel";
import type { TelemetryEvent } from "@/lib/sim/types";
import type { Ev } from "@/lib/team/types";

/** Batch window: IOCs of logs opened in quick succession go out in one request. */
export const IOC_TRUTH_DEBOUNCE_MS = 600;
/** Back-off after the server's per-player budget says "wait" (429). */
export const IOC_TRUTH_BACKOFF_MS = 15_000;
/** Same cap the route applies (IOC_QUERY_MAX). */
export const IOC_TRUTH_BATCH = 20;

type Q = { type: IocType; value: string; d: string };

/** The IOCs (with digests) of these logs, de-duplicated. */
export function iocsOf(events: Ev[]): Q[] {
  const out = new Map<string, Q>();
  for (const e of events) for (const i of extractIocs(e.payload as unknown as TelemetryEvent)) {
    const d = iocDigest(i.type, i.value);
    if (!out.has(d)) out.set(d, { type: i.type, value: i.value, d });
  }
  return [...out.values()];
}

/**
 * Server-built threat-intel verdicts for the IOCs of the logs THIS analyst has in
 * hand — `inHand` = the feed logs they opened plus the ones the team escalated
 * (POST /api/team/sessions/[id]/ioc-truth, QA M4). Each IOC is asked about once;
 * new logs add only their new IOCs, in batches of ≤ 20. An IOC the server refuses
 * (the open wasn't recorded yet) is asked again when the next log comes into hand.
 * Null until the first verdict arrives — the lookup then falls back to what the log
 * itself says, exactly as for an IOC with no entry.
 */
export function useTeamIocTruth(sessionId: string | null, inHand: Ev[], enabled = true): IocTruth | null {
  const [truth, setTruth] = useState<IocTruth | null>(null);
  const asked = useRef(new Set<string>());
  const queue = useRef<Q[]>([]);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const inFlight = useRef(false);
  const blockedUntil = useRef(0);
  const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; if (timer.current) clearTimeout(timer.current); }; }, []);
  // A new session starts from scratch.
  useEffect(() => { asked.current = new Set(); queue.current = []; setTruth(null); }, [sessionId]);

  useEffect(() => {
    if (!sessionId || !enabled || inHand.length === 0) return;
    for (const q of iocsOf(inHand)) {
      if (asked.current.has(q.d)) continue;
      asked.current.add(q.d);
      queue.current.push(q);
    }
    if (queue.current.length === 0) return;

    const flush = async () => {
      timer.current = null;
      if (inFlight.current || !alive.current) return;
      const wait = blockedUntil.current - Date.now();
      if (wait > 0) { timer.current = setTimeout(flush, wait); return; }
      const batch = queue.current.splice(0, IOC_TRUTH_BATCH);
      if (batch.length === 0) return;
      inFlight.current = true;
      try {
        const res = await fetch(`/api/team/sessions/${sessionId}/ioc-truth`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ iocs: batch.map(({ type, value }) => ({ type, value })) }),
        });
        if (res.status === 429) {
          queue.current.unshift(...batch);
          blockedUntil.current = Date.now() + IOC_TRUTH_BACKOFF_MS;
        } else if (res.ok) {
          const d = await res.json().catch(() => null) as (IocTruth & { refused?: string[] }) | null;
          if (d && d.version === 1 && d.entries && alive.current) {
            if (Object.keys(d.entries).length) setTruth(prev => ({ version: 1, entries: { ...(prev?.entries ?? {}), ...d.entries } }));
            for (const r of d.refused ?? []) asked.current.delete(r);   // retry when the next log comes into hand
          }
        } else {
          for (const q of batch) asked.current.delete(q.d);             // transient — try again later
        }
      } catch {
        for (const q of batch) asked.current.delete(q.d);
      } finally {
        inFlight.current = false;
        if (queue.current.length && alive.current && !timer.current) timer.current = setTimeout(flush, IOC_TRUTH_DEBOUNCE_MS);
      }
    };
    if (!timer.current) timer.current = setTimeout(flush, IOC_TRUTH_DEBOUNCE_MS);
  }, [sessionId, inHand, enabled]);

  return truth;
}
