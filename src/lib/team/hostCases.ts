/**
 * The Tier-1 queue by HOST and CASE (Sdema review 2026-10-25, B2/B3).
 *
 * The queue used to list every high/critical log as its own item. A Tier-1 spent the last ten
 * minutes of a shift on three more logs of a host Tier-2 had already isolated, with a case open,
 * and sent three separate escalations for that one incident, while two other hosts with critical
 * alerts were never opened. This projection groups the queue by host, says which hosts are
 * already in hand (an open case, an isolation), puts a host nobody has looked at yet on top, and
 * lets Tier-1 ADD a log to the open case as evidence instead of escalating it again.
 *
 * Pure projections over the room's own events: what the TEAM did, never the answer key.
 */
import type { Ev } from "./types";
import { escalationStates, type HostIsolation } from "./projections";
import type { QueueItem } from "./alertQueue";

/** Host names are case-insensitive. */
export const hostKeyOf = (h: unknown): string => (typeof h === "string" ? h.trim().toLowerCase() : "");
const str = (v: unknown) => (typeof v === "string" ? v.trim() : "");
const eidOf = (e: Ev) => String((e.payload as { event_id?: unknown } | null)?.event_id ?? "");

/** The host an escalation is about: its own field, else the escalated log's. */
export function hostOfEscalation(e: Ev): string {
  const p = (e.payload ?? {}) as { hostname?: unknown; snapshot?: { hostname?: unknown } };
  return str(p.hostname) || str(p.snapshot?.hostname);
}

export interface HostCase {
  host: string;
  /** The escalated log the case is keyed on (the event_id Tier-2 works). */
  caseEid: string;
  /** The Tier-2 / Tier-3 who took it; null while it waits for someone. */
  owner: string | null;
  /** Who raised it (a Tier-1 escalation, or a Tier-2 / Tier-3 opening a case themselves). */
  openedBy: string | null;
  label: string;
  seq: number;
}

/**
 * Open cases by host: escalations not resolved and not bounced back. When a host has several,
 * one somebody owns beats one still waiting, and the newer wins between equals.
 */
export function openCasesByHost(events: Ev[]): Map<string, HostCase> {
  const m = new Map<string, HostCase>();
  for (const st of escalationStates(events).values()) {
    if (st.resolved || st.bounced || st.request.type !== "escalation.requested") continue;
    const host = hostOfEscalation(st.request);
    const key = hostKeyOf(host);
    if (!key) continue;
    const p = (st.request.payload ?? {}) as { summary?: unknown; what?: unknown };
    const c: HostCase = { host, caseEid: st.eid, owner: st.owner, openedBy: st.request.actor_id, label: (str(p.summary) || str(p.what) || host).slice(0, 120), seq: st.request.seq };
    const prev = m.get(key);
    if (!prev || (!!c.owner && !prev.owner) || (!!c.owner === !!prev.owner && c.seq > prev.seq)) m.set(key, c);
  }
  return m;
}

export interface AttachedLog { by: string | null; caseEid: string; seq: number }
/** Feed logs added to a case from the queue (evidence.pinned carrying case_event_id). */
export function attachedLogs(events: Ev[]): Map<string, AttachedLog> {
  const m = new Map<string, AttachedLog>();
  for (const e of events) {
    if (e.type !== "evidence.pinned") continue;
    const caseEid = str((e.payload as { case_event_id?: unknown }).case_event_id);
    const eid = eidOf(e);
    if (!caseEid || !eid || m.has(eid)) continue;
    m.set(eid, { by: e.actor_id, caseEid, seq: e.seq });
  }
  return m;
}

/** Logs added to each case, keyed by the case's event_id (for the Tier-2 case and the manager). */
export function attachedByCase(events: Ev[]): Map<string, { eid: string; by: string | null; label: string; at: string | null }[]> {
  const m = new Map<string, { eid: string; by: string | null; label: string; at: string | null }[]>();
  const seen = new Set<string>();
  for (const e of events) {
    if (e.type !== "evidence.pinned") continue;
    const p = (e.payload ?? {}) as { case_event_id?: unknown; label?: unknown; summary?: unknown };
    const caseEid = str(p.case_event_id); const eid = eidOf(e);
    if (!caseEid || !eid || seen.has(eid)) continue;
    seen.add(eid);
    if (!m.has(caseEid)) m.set(caseEid, []);
    m.get(caseEid)!.push({ eid, by: e.actor_id, label: str(p.label) || str(p.summary) || eid, at: e.occurred_at ?? null });
  }
  return m;
}

const RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };

export interface HostGroup {
  /** Lower-cased host ("" = logs that name no host). */
  key: string;
  host: string;
  items: QueueItem[];
  maxSeverity: string;
  oldestMins: number;
  breached: number;
  orphans: number;
  isolated: { by: string | null; at: string | null } | null;
  case: HostCase | null;
  /** In hand already: an open case or an isolation. Its alerts belong in that case. */
  covered: boolean;
  /** Nobody has escalated, judged or isolated anything on this host yet: a possible new incident. */
  fresh: boolean;
}

/**
 * Group the queue by host. Order: hosts nobody has in hand first (a host nobody has touched at
 * all on top), then those with alerts past SLA and nobody on them, then severity and age. Hosts
 * already in a case or isolated go last: their alerts are added to that case, not re-escalated.
 * Inside a host the queue's own order is kept.
 */
export function groupQueueByHost(queue: QueueItem[], opts: {
  hostOf: (e: Ev) => string;
  cases: Map<string, HostCase>;
  isolation: Map<string, HostIsolation>;
  /** Hosts with any verdict, escalation or isolation so far (lower-cased). */
  touchedHosts: Set<string>;
}): HostGroup[] {
  const groups = new Map<string, HostGroup>();
  for (const q of queue) {
    const host = str(opts.hostOf(q.e));
    const key = hostKeyOf(host);
    let g = groups.get(key);
    if (!g) {
      const iso = key ? opts.isolation.get(key) : undefined;
      const c = key ? opts.cases.get(key) ?? null : null;
      const isolated = iso?.isolated ? { by: iso.by, at: iso.at } : null;
      g = { key, host: host || "No host", items: [], maxSeverity: "", oldestMins: 0, breached: 0, orphans: 0, isolated, case: c,
        covered: !!c || !!isolated, fresh: !!key && !c && !isolated && !opts.touchedHosts.has(key) };
      groups.set(key, g);
    }
    g.items.push(q);
    if ((RANK[q.severity] ?? 0) > (RANK[g.maxSeverity] ?? 0)) g.maxSeverity = q.severity;
    g.oldestMins = Math.max(g.oldestMins, q.mins);
    if (q.breached) g.breached++;
    if (q.orphan) g.orphans++;
  }
  const cmp = (a: HostGroup, b: HostGroup) =>
    Number(a.covered) - Number(b.covered)
    || Number(b.fresh) - Number(a.fresh)
    || Number(b.orphans > 0) - Number(a.orphans > 0)
    || (RANK[b.maxSeverity] ?? 0) - (RANK[a.maxSeverity] ?? 0)
    || b.oldestMins - a.oldestMins;
  return [...groups.values()].sort(cmp);
}

/** The queue in host order: what the "Needs triage" table shows and what "Take next" pulls from. */
export const flattenGroups = (groups: HostGroup[]): QueueItem[] => groups.flatMap(g => g.items);

/** Hosts the team has already acted on: any verdict, escalation or isolation (lower-cased). */
export function touchedHostsOf(events: Ev[], hostByEid: Map<string, string>): Set<string> {
  const s = new Set<string>();
  for (const e of events) {
    if (e.type === "edr.host_isolated") { const k = hostKeyOf((e.payload as { host?: unknown }).host); if (k) s.add(k); continue; }
    if (e.type === "escalation.requested") { const k = hostKeyOf(hostOfEscalation(e)); if (k) s.add(k); continue; }
    if (e.type === "disposition.set" || e.type === "evidence.pinned") { const k = hostByEid.get(eidOf(e)); if (k) s.add(k); }
  }
  return s;
}
