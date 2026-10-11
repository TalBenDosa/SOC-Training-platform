"use client";
import { useCallback, useEffect, useState } from "react";
import { getSupabaseBrowserClient } from "@/lib/supabase/client";
import type { Ev } from "@/lib/team/types";
import { EDR_ISOLATION_TYPES, isolationState, type HostIsolation } from "@/lib/team/projections";
import { friendlyActionError } from "@/lib/team/format";

/** How often the EDR tab re-reads the team's isolations (a teammate may isolate / release too). */
export const ISOLATION_POLL_MS = 10_000;

export interface TeamIsolation {
  /** Team-wide state, keyed by lower-cased host. */
  state: Map<string, HostIsolation>;
  /** Record an isolate / release in the session log; resolves to an error message, or null on success. */
  set: (host: string, isolated: boolean, caseTitle?: string) => Promise<string | null>;
  /** Isolation is Tier-2 / Tier-3's call (the DB gate, 0082); Tier-1 investigates and escalates. */
  canContain: boolean;
  /** Put an RTR kill / get / memdump on the session record (0095). */
  recordRtr?: (payload: { host: string; action: "kill" | "get" | "memdump"; pid?: number; name?: string; path?: string }) => Promise<void>;
}

/**
 * EDR network containment inside a Team-SOC session (0082). The EDR console runs in
 * its own tab, so it reads the team's isolate/release events straight from the
 * session log (polled, plus on focus) and writes through apply_session_action —
 * the same record the after-action report scores ("was it right to isolate this host?").
 * Returns null outside a team session (the console then keeps its local, single-player store).
 */
export function useTeamIsolation(sessionId: string | null, role: string | null = null): TeamIsolation | null {
  const [state, setState] = useState<Map<string, HostIsolation>>(new Map());

  const refresh = useCallback(async () => {
    const sb = getSupabaseBrowserClient();
    if (!sessionId || !sb) return;
    const { data, error } = await sb.from("session_events")
      .select("seq, type, actor_id, role, payload, occurred_at")
      .eq("session_id", sessionId).in("type", [...EDR_ISOLATION_TYPES]).order("seq");
    if (!error && data) setState(isolationState(data as Ev[]));
  }, [sessionId]);

  useEffect(() => {
    if (!sessionId) return;
    void refresh();
    const iv = setInterval(() => { void refresh(); }, ISOLATION_POLL_MS);
    const onFocus = () => { if (document.visibilityState === "visible") void refresh(); };
    document.addEventListener("visibilitychange", onFocus);
    window.addEventListener("focus", onFocus);
    return () => { clearInterval(iv); document.removeEventListener("visibilitychange", onFocus); window.removeEventListener("focus", onFocus); };
  }, [sessionId, refresh]);

  const set = useCallback(async (host: string, isolated: boolean, caseTitle?: string): Promise<string | null> => {
    const sb = getSupabaseBrowserClient();
    if (!sessionId || !sb) return "Not connected — reload the page.";
    const type = isolated ? "edr.host_isolated" : "edr.host_released";
    const idem = `${type}:${host.toLowerCase()}:${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;
    const payload: Record<string, unknown> = { host };
    if (caseTitle) payload.case = caseTitle.slice(0, 200);
    const { error } = await sb.rpc("apply_session_action", { p_session: sessionId, p_type: type, p_payload: payload, p_idempotency_key: idem });
    await refresh();   // a refusal ("already isolated" by a teammate) still brings the true state
    return error ? friendlyActionError(error.message) : null;
  }, [sessionId, refresh]);

  // RTR actions (0095): a kill or a file collection goes on the session record, so evidence
  // destroyed before a memory capture (or preserved by one) is visible to the team and the review.
  const recordRtr = useCallback(async (payload: { host: string; action: "kill" | "get" | "memdump"; pid?: number; name?: string; path?: string }): Promise<void> => {
    const sb = getSupabaseBrowserClient();
    if (!sessionId || !sb) return;
    const idem = `rtr:${payload.action}:${payload.host.toLowerCase()}:${payload.pid ?? payload.path ?? ""}:${Date.now().toString(36)}`;
    await sb.rpc("apply_session_action", { p_session: sessionId, p_type: "rtr.action", p_payload: payload, p_idempotency_key: idem });
  }, [sessionId]);

  // Unknown role (an older link without &r=) keeps the button; the server still decides.
  return sessionId ? { state, set, recordRtr, canContain: role === null || role === "t2" || role === "t3" } : null;
}
