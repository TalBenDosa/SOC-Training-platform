"use client";
import { useCallback, useEffect, useMemo, useState } from "react";
import { getSupabaseBrowserClient } from "@/lib/supabase/client";
import type { Ev, RosterMember } from "@/lib/team/types";
import { EDR_ISOLATION_TYPES } from "@/lib/team/projections";
import { friendlyActionError } from "@/lib/team/format";
import {
  ISOLATION_REASON_MAX, ISOLATION_REQUEST_TYPES, NO_APPROVER, SELF_APPROVER, approverLabel, isolationApprovers, isolationRequests,
  type ApproverMember, type IsolationRequest,
} from "@/lib/team/isolationApproval";

/**
 * Isolating a host needs the senior on shift's approval (owner, 2026-11-07). The server side
 * (rule, events, the isolation itself on approval) is in isolationApproval.ts and migration 0104.
 * This file is the shared CLIENT side, used by the EDR console, Sentinel's "Isolate device"
 * playbook and the team room: send a request, answer one, and read every request with its answer.
 */

const idem = (type: string, key: string) => `${type}:${key.toLowerCase()}:${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;

async function apply(sessionId: string, type: string, payload: Record<string, unknown>, key: string): Promise<string | null> {
  const sb = getSupabaseBrowserClient();
  if (!sb) return "Not connected. Reload the page.";
  const { error } = await sb.rpc("apply_session_action", { p_session: sessionId, p_type: type, p_payload: payload, p_idempotency_key: idem(type, key) });
  return error ? isolationError(error.message) : null;
}

/** The DB's isolation refusals in plain words; anything else goes through the team's usual mapping. */
export function isolationError(raw: string): string {
  const host = raw.match(/(?:already_isolated|isolation_pending):\s*([^\s"]+)/)?.[1];
  if (/already_isolated/.test(raw)) return `${host ?? "This host"} is already isolated.`;
  if (/isolation_pending/.test(raw)) return `A request to isolate ${host ?? "this host"} is already waiting for approval.`;
  if (/not_approver/.test(raw)) return "Only the senior on shift can answer this request.";
  if (/no_open_request/.test(raw)) return "This request was already answered.";
  return friendlyActionError(raw);
}

export interface IsolationRequestInput { host: string; reason: string; incident?: string; case?: string }

/** Ask the senior on shift to isolate a host. Resolves to an error message, or null when sent. */
export function requestIsolation(sessionId: string, input: IsolationRequestInput): Promise<string | null> {
  const host = input.host.trim();
  const reason = input.reason.trim().slice(0, ISOLATION_REASON_MAX);
  if (!host) return Promise.resolve("Pick the host to isolate.");
  if (!reason) return Promise.resolve("Say in a few words why this host should be isolated.");
  const payload: Record<string, unknown> = { host: host.slice(0, 128), reason };
  if (input.incident?.trim()) payload.incident = input.incident.trim().slice(0, 200);
  if (input.case?.trim()) payload.case = input.case.trim().slice(0, 200);
  return apply(sessionId, "isolation.requested", payload, host);
}

/** Approve or deny a request (the approver only; a deny carries the reason). */
export function answerIsolation(sessionId: string, requestSeq: number, approve: boolean, reason?: string): Promise<string | null> {
  const payload: Record<string, unknown> = { request_seq: requestSeq };
  if (!approve && reason?.trim()) payload.reason = reason.trim().slice(0, ISOLATION_REASON_MAX);
  return apply(sessionId, approve ? "isolation.approved" : "isolation.denied", payload, String(requestSeq));
}

/** The latest request per host (lower-cased), answered or not: what an "Isolate" button shows. */
export function latestRequestByHost(requests: IsolationRequest[]): Map<string, IsolationRequest> {
  const m = new Map<string, IsolationRequest>();
  for (const r of requests) { const k = r.host.toLowerCase(); const prev = m.get(k); if (!prev || prev.seq < r.seq) m.set(k, r); }
  return m;
}

/** Who answers a request right now, for "Waiting for approval from ...". `online` is presence when known. */
export function approverNames(roster: (RosterMember & { active?: boolean })[], requesterId: string | null, online?: Set<string>): string {
  const members: ApproverMember[] = roster.map(m => ({ user_id: m.user_id, role: m.role, status: m.status, active: online ? online.has(m.user_id) : m.active ?? true }));
  const a = isolationApprovers(members, requesterId);
  // The requester is the senior on shift (0107): the server approves their request at once.
  if (a.selfApproves) return SELF_APPROVER;
  // Nobody but the requester could answer it: say so, never name the requester (or a seat nobody holds).
  if (!a.userIds.length) return NO_APPROVER;
  const names = a.userIds.map(u => roster.find(m => m.user_id === u)?.name).filter(Boolean) as string[];
  const label = approverLabel(a.tier);
  return names.length ? `${names.slice(0, 2).join(" or ")} (${label.replace(/^the /, "")})` : label;
}

export interface IsolationRequests {
  /** Every request with its answer, oldest first. */
  requests: IsolationRequest[];
  /** The latest request per host. */
  byHost: Map<string, IsolationRequest>;
  /** The roster (names for requester and approver), when the hook loaded it. */
  roster: (RosterMember & { active?: boolean })[];
  /** The signed-in user, from the session API (null until loaded). */
  meId: string | null;
  request: (input: IsolationRequestInput) => Promise<string | null>;
  answer: (requestSeq: number, approve: boolean, reason?: string) => Promise<string | null>;
  refresh: () => Promise<void>;
}

/** How often a console tab re-reads the requests (the team room gets them from its own event stream). */
export const ISOLATION_REQUEST_POLL_MS = 8_000;

/**
 * For a console in its own tab (EDR, Sentinel): reads the session's isolation requests and the
 * roster, polled and on focus. Pass `events` instead when the caller already holds the session log
 * (the team room), and nothing is fetched.
 */
export function useIsolationRequest(sessionId: string | null, events?: Ev[]): IsolationRequests | null {
  const [polled, setPolled] = useState<Ev[]>([]);
  const [roster, setRoster] = useState<(RosterMember & { active?: boolean })[]>([]);
  const [meId, setMeId] = useState<string | null>(null);
  const own = !events;

  const refresh = useCallback(async () => {
    const sb = getSupabaseBrowserClient();
    if (!sessionId || !sb || !own) return;
    const { data, error } = await sb.from("session_events")
      .select("seq, type, actor_id, role, payload, occurred_at")
      .eq("session_id", sessionId).in("type", [...ISOLATION_REQUEST_TYPES, ...EDR_ISOLATION_TYPES]).order("seq");
    if (!error && data) setPolled(data as Ev[]);
  }, [sessionId, own]);

  useEffect(() => {
    if (!sessionId) return;
    let alive = true;
    fetch(`/api/team/sessions/${sessionId}`).then(r => (r.ok ? r.json() : null)).then(d => { if (!alive) return; if (Array.isArray(d?.roster)) setRoster(d.roster); if (typeof d?.me?.id === "string") setMeId(d.me.id); }).catch(() => {});
    if (!own) return () => { alive = false; };
    void refresh();
    const iv = setInterval(() => { void refresh(); }, ISOLATION_REQUEST_POLL_MS);
    const onFocus = () => { if (document.visibilityState === "visible") void refresh(); };
    document.addEventListener("visibilitychange", onFocus);
    window.addEventListener("focus", onFocus);
    return () => { alive = false; clearInterval(iv); document.removeEventListener("visibilitychange", onFocus); window.removeEventListener("focus", onFocus); };
  }, [sessionId, own, refresh]);

  const requests = useMemo(() => isolationRequests(events ?? polled), [events, polled]);
  const byHost = useMemo(() => latestRequestByHost(requests), [requests]);
  const request = useCallback(async (input: IsolationRequestInput) => {
    if (!sessionId) return "Not in a team session.";
    const err = await requestIsolation(sessionId, input);
    await refresh();
    return err;
  }, [sessionId, refresh]);
  const answer = useCallback(async (seq: number, approve: boolean, reason?: string) => {
    if (!sessionId) return "Not in a team session.";
    const err = await answerIsolation(sessionId, seq, approve, reason);
    await refresh();
    return err;
  }, [sessionId, refresh]);

  return sessionId ? { requests, byHost, roster, meId, request, answer, refresh } : null;
}
