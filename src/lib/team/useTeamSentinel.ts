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
import { ISOLATION_REQUEST_TYPES, isolationRequests } from "@/lib/team/isolationApproval";
import type { IncidentState, SentinelActions, SentinelBookmark, SentinelIsolationRequest, SentinelWorkspace } from "@/lib/sentinel/types";

/** How often the console reads the session log. The team room's own reconcile uses the same pace. */
export const SENTINEL_POLL_MS = 6_000;

// escalation.bounced, disposition.set and evidence.pinned complete the analyst's hand-off on an escalated incident.
const LOG_TYPES = ["feed.event", "session.ended", "session.paused", "session.resumed", "escalation.requested", "escalation.acknowledged", "escalation.bounced", "disposition.set", "evidence.pinned", "sentinel.incident_updated", "sentinel.comment_added", "sentinel.bookmark_added", "sentinel.task_set", ...ISOLATION_REQUEST_TYPES];
/** Fewer rows per read than the log can hold, so a long shift pages in rather than timing out. */
const PAGE = 500;

export interface TeamSentinel {
  workspace: SentinelWorkspace | null;
  states: Map<string, IncidentState>;
  actions: SentinelActions | null;
  loading: boolean;
  error: string | null;
  ended: boolean;
  /** The shift is paused: nothing new arrives, and the database refuses actions until it resumes. */
  paused: boolean;
  /** Bookmarks saved with no incident, from the session log, so they survive a reload and reach the team. */
  looseBookmarks: SentinelBookmark[];
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
  const pulling = useRef(false);
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
    // One read at a time: the 6s poll, an action and Refresh can all ask at once, and two reads
    // of the same window would count each row twice.
    if (pulling.current) return;
    pulling.current = true;
    try {
    for (;;) {
      const { data, error: e } = await sb.from("session_events")
        .select("seq, type, actor_id, role, payload, occurred_at")
        .eq("session_id", sessionId).in("type", LOG_TYPES).gt("seq", maxSeq.current).order("seq").limit(PAGE);
      if (e) { setError("The session log could not be read. Trying again."); return; }
      const rows = (data ?? []) as Ev[];
      if (rows.length) {
        maxSeq.current = rows[rows.length - 1].seq;
        setEvents(prev => {
          const seen = new Set(prev.map(x => x.seq));
          return [...prev, ...rows.filter(x => !seen.has(x.seq))];
        });
      }
      setError(null);
      if (rows.length < PAGE) return;
    }
    } finally { pulling.current = false; }
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

  const escalationKey = useMemo(() => JSON.stringify(escalatedCases(events, nameOf)), [events, nameOf]);
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
  // Isolation requests and their answers (2026-11-07), read with the rest of the log so a run in the
  // playbook history moves from "waiting" to approved or denied on the next poll.
  const requestIso = isolation?.request;
  const approverFor = isolation?.approverFor;
  const isoRequests = useMemo<SentinelIsolationRequest[]>(() => isolationRequests(events).map(r => ({
    seq: r.seq, host: r.host, state: r.state, requestedBy: nameOf(r.requestedBy), mine: !!me && r.requestedBy === me.id,
    reason: r.reason, incident: r.incident, at: r.at,
    approver: r.state === "pending" ? (approverFor ? approverFor(r.requestedBy) : "the senior on shift") : nameOf(r.answeredBy),
    answeredAt: r.answeredAt, denyReason: r.denyReason,
  })), [events, nameOf, me, approverFor]);

  const actions = useMemo<SentinelActions | null>(() => {
    if (!me || !setIsolated) return null;
    return {
      me: { id: me.id, name: nameOf(me.id), role: me.role },
      people: roster.map(m => m.name),
      canContain: isolation?.canContain ?? false,
      isolatedHosts,
      setIsolated,
      ...(requestIso ? {
        requestIsolation: async (host: string, reason: string, incidentTitle?: string) => { const err = await requestIso(host, reason, incidentTitle); void pull(); return err; },
        isolationRequests: isoRequests,
        isolationApprover: approverFor ? approverFor(me.id) : undefined,
      } : {}),
      updateIncident: async (incident_id, patch) => {
        // The events behind the incident travel with it, so the report can judge a closing classification.
        const inc = workspace?.incidents.find(i => i.id === incident_id);
        const eventIds = [...new Set((inc?.alertIds ?? []).flatMap(a => workspace?.alertEventIds[a] ?? []))];
        const err = await send("sentinel.incident_updated", { incident_id, patch, ...(patch.status === "Closed" ? { event_ids: eventIds.slice(0, 200) } : {}) });
        // Taking up an escalated incident here is taking up the case: Tier-1 sees it acknowledged.
        if (!err && (me.role === "t2" || me.role === "t3") && (patch.status === "Active" || patch.status === "Closed" || patch.owner)) {
          const acked = new Set(events.filter(e => e.type === "escalation.acknowledged").map(e => String((e.payload as { event_id?: unknown }).event_id)));
          for (const c of escalatedCases(events)) if (eventIds.includes(c.eventId) && !acked.has(c.eventId)) void send("escalation.acknowledged", { event_id: c.eventId });
        }
        return err;
      },
      addComment: (incident_id, text) => send("sentinel.comment_added", { incident_id, text: text.slice(0, 4000) }),
      addBookmark: (b: Omit<SentinelBookmark, "id" | "author" | "at">) => send("sentinel.bookmark_added", { ...b, rows: b.rows.slice(0, 50) }),
      setTask: (incident_id, title, done) => send("sentinel.task_set", { incident_id, title, done }),
      queryRan: q => { void send("sentinel.query_run", { query: q.query.slice(0, 2000), ok: q.ok, rows: q.rows, incident_id: q.incidentId ?? null }); },
    };
  }, [me, roster, nameOf, send, setIsolated, isolatedHosts, isolation?.canContain, workspace, events, requestIso, isoRequests, approverFor, pull]);

  const looseBookmarks = useMemo<SentinelBookmark[]>(() => events.filter(e => e.type === "sentinel.bookmark_added" && !(e.payload as { incidentId?: unknown }).incidentId).map(e => {
    const b = e.payload as unknown as Partial<SentinelBookmark>;
    return { id: `bookmark-${e.seq}`, name: b.name ?? "Bookmark", query: b.query ?? "", columns: b.columns ?? [], rows: b.rows ?? [], notes: b.notes ?? "", author: nameOf(e.actor_id), at: e.occurred_at ?? "", entityIds: b.entityIds ?? [] };
  }), [events, nameOf]);
  const lastPause = [...events].reverse().find(e => e.type === "session.paused" || e.type === "session.resumed");

  return {
    workspace, states, actions, loading, error,
    ended: session?.status === "ended" || events.some(e => e.type === "session.ended"),
    paused: lastPause?.type === "session.paused",
    looseBookmarks,
    refresh: () => { void pull(); },
  };
}
