"use client";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { getSupabaseBrowserClient } from "@/lib/supabase/client";
import { withRebasedTime } from "@/lib/sim/rebaseTime";
import type { TelemetryEvent } from "@/lib/sim/types";
import { withoutDetectionFeed, type Stack } from "@/lib/logs/native/stack";
import type { Ev, Me, RosterMember, SessionMeta } from "@/lib/team/types";
import { useTeamIsolation } from "@/lib/team/useTeamIsolation";
import { friendlyActionError } from "@/lib/team/format";
import { buildWorkspace } from "@/lib/sentinel/workspace";
import { foldIncidentState } from "@/lib/sentinel/state";
import { escalatedCases } from "@/lib/team/investigationConsole";
import type { IncidentState, SentinelActions, SentinelBookmark, SentinelWorkspace } from "@/lib/sentinel/types";

/** How often the console reads the session log. The team room's own reconcile uses the same pace. */
export const SENTINEL_POLL_MS = 6_000;

const LOG_TYPES = ["feed.event", "session.ended", "escalation.requested", "sentinel.incident_updated", "sentinel.comment_added", "sentinel.bookmark_added", "sentinel.task_set"];
/** Fewer rows per read than the log can hold, so a long shift pages in rather than timing out. */
const PAGE = 500;

export interface TeamSentinel {
  workspace: SentinelWorkspace | null;
  states: Map<string, IncidentState>;
  actions: SentinelActions | null;
  loading: boolean;
  error: string | null;
  ended: boolean;
  refresh: () => void;
}

/**
 * The live Sentinel workspace of one Team Training session. The console runs in its own tab, so it
 * reads the session log itself: only feed events that have been released, never session_injects,
 * which hold the plan and the answer key. A query therefore cannot see the future of the exercise,
 * and row level security keeps it to members of this session.
 */
export function useTeamSentinel(sessionId: string | null, role: string | null): TeamSentinel {
  const [session, setSession] = useState<SessionMeta | null>(null);
  const [roster, setRoster] = useState<RosterMember[]>([]);
  const [me, setMe] = useState<Me | null>(null);
  const [events, setEvents] = useState<Ev[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const maxSeq = useRef(0);
  const isolation = useTeamIsolation(sessionId, role);

  const loadSession = useCallback(async () => {
    if (!sessionId) return;
    const r = await fetch(`/api/team/sessions/${sessionId}`);
    if (!r.ok) { setError("This session could not be opened. Are you a member of it?"); setLoading(false); return; }
    const d = await r.json() as { session: SessionMeta; roster: RosterMember[]; me: Me };
    setSession(d.session); setRoster(d.roster ?? []); setMe(d.me);
  }, [sessionId]);

  const pull = useCallback(async () => {
    const sb = getSupabaseBrowserClient();
    if (!sessionId || !sb) return;
    for (;;) {
      const { data, error: e } = await sb.from("session_events")
        .select("seq, type, actor_id, role, payload, occurred_at")
        .eq("session_id", sessionId).in("type", LOG_TYPES).gt("seq", maxSeq.current).order("seq").limit(PAGE);
      if (e) { setError("The session log could not be read. Trying again."); return; }
      const rows = (data ?? []) as Ev[];
      if (rows.length) {
        maxSeq.current = rows[rows.length - 1].seq;
        setEvents(prev => [...prev, ...rows]);
      }
      setError(null);
      if (rows.length < PAGE) return;
    }
  }, [sessionId]);

  useEffect(() => {
    if (!sessionId) { setLoading(false); return; }
    let alive = true;
    void (async () => { await loadSession(); await pull(); if (alive) setLoading(false); })();
    const iv = setInterval(() => { void pull(); }, SENTINEL_POLL_MS);
    return () => { alive = false; clearInterval(iv); };
  }, [sessionId, loadSession, pull]);

  const nameOf = useCallback((id: string | null) => roster.find(m => m.user_id === id)?.name ?? "Analyst", [roster]);
  // The workspace reads each log's own record (the Defender row, not its Graph alert).
  const stackKey = JSON.stringify(withoutDetectionFeed((session?.stack ?? {}) as Stack));
  const domain = session?.tenant?.domain, netbios = session?.tenant?.netbios, org = session?.tenant?.name;
  const companyId = session?.company_id;
  const feed = useMemo(() => events.filter(e => e.type === "feed.event"), [events]);

  const escalationKey = JSON.stringify(escalatedCases(events));
  const workspace = useMemo(() => {
    if (!companyId) return null;
    const evs = feed.map(e => { const t = e.payload as unknown as TelemetryEvent; return e.occurred_at ? withRebasedTime(t, e.occurred_at) : t; });
    return buildWorkspace(evs, { companyId, stack: JSON.parse(stackKey) as Stack, identity: domain && netbios ? { domain, netbios } : undefined, orgName: org, escalated: JSON.parse(escalationKey) });
  }, [feed, companyId, stackKey, domain, netbios, org, escalationKey]);

  const log = useMemo(() => events.filter(e => e.type.startsWith("sentinel."))
    .map(e => ({ type: e.type, actor_name: nameOf(e.actor_id), payload: e.payload as unknown, occurred_at: e.occurred_at ?? "" })), [events, nameOf]);

  const states = useMemo(() => {
    const m = new Map<string, IncidentState>();
    for (const inc of workspace?.incidents ?? []) m.set(inc.id, foldIncidentState(log, inc));
    return m;
  }, [workspace, log]);

  const send = useCallback(async (type: string, payload: Record<string, unknown>): Promise<string | null> => {
    const sb = getSupabaseBrowserClient();
    if (!sessionId || !sb) return "Not connected. Reload the page.";
    const idem = `${type}:${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;
    const { error: e } = await sb.rpc("apply_session_action", { p_session: sessionId, p_type: type, p_payload: payload, p_idempotency_key: idem });
    void pull();
    return e ? friendlyActionError(e.message) : null;
  }, [sessionId, pull]);

  const isolatedHosts = useMemo(() => new Set([...(isolation?.state.values() ?? [])].filter(h => h.isolated).map(h => h.host.toLowerCase())), [isolation?.state]);
  const setIsolated = isolation?.set;

  const actions = useMemo<SentinelActions | null>(() => {
    if (!me || !setIsolated) return null;
    return {
      me: { id: me.id, name: nameOf(me.id), role: me.role },
      people: roster.map(m => m.name),
      canContain: isolation?.canContain ?? false,
      isolatedHosts,
      setIsolated,
      updateIncident: (incident_id, patch) => send("sentinel.incident_updated", { incident_id, patch }),
      addComment: (incident_id, text) => send("sentinel.comment_added", { incident_id, text: text.slice(0, 4000) }),
      addBookmark: (b: Omit<SentinelBookmark, "id" | "author" | "at">) => send("sentinel.bookmark_added", { ...b, rows: b.rows.slice(0, 50) }),
      setTask: (incident_id, title, done) => send("sentinel.task_set", { incident_id, title, done }),
      queryRan: q => { void send("sentinel.query_run", { query: q.query.slice(0, 2000), ok: q.ok, rows: q.rows, incident_id: q.incidentId ?? null }); },
    };
  }, [me, roster, nameOf, send, setIsolated, isolatedHosts, isolation?.canContain]);

  return {
    workspace, states, actions, loading, error,
    ended: session?.status === "ended" || events.some(e => e.type === "session.ended"),
    refresh: () => { void pull(); },
  };
}
