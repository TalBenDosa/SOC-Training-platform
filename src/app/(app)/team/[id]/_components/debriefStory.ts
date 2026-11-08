/**
 * Debrief helpers for the after-action report (review 2026-11): one duration format for every time
 * the report shows, and the attack story of each incident for the staff debrief screen.
 *
 * The story is rebuilt from the REVEALED log (answers joined after the shift ended) with the same
 * rules the forensic review uses: an attack log is a feed log whose expected verdict is tp /
 * escalate, the patient zero of an incident is the host of its earliest attack log, and the stages
 * are the incident's MITRE tactics in the order they first showed. Times are running time (pauses
 * cut out), like every other time in the report. Nothing here is ever shown in the live room.
 */
import type { Ev } from "@/lib/team/types";
import { asStr, hostKey } from "@/lib/team/format";
import { activeMs, pausedSpans } from "@/lib/team/pauses";

/** One format for every duration and shift time: 40s, 1m 05s, 1h 02m. Never raw seconds. */
export function fmtDur(s: number | null | undefined): string {
  if (s == null || !Number.isFinite(s)) return "-";
  const t = Math.max(0, Math.round(s));
  if (t < 60) return `${t}s`;
  if (t < 3600) return `${Math.floor(t / 60)}m ${String(t % 60).padStart(2, "0")}s`;
  return `${Math.floor(t / 3600)}h ${String(Math.floor((t % 3600) / 60)).padStart(2, "0")}m`;
}

const ATTACK = new Set(["tp", "escalate"]);
const p = (e: Ev) => (e.payload ?? {}) as Record<string, unknown>;
const ms = (e: Ev) => (e.occurred_at ? Date.parse(e.occurred_at) : NaN);

export interface StoryLog { id: string; label: string; atS: number | null; severity: string; host: string }
export interface StorySeen extends StoryLog { how: string; who: string | null }
export interface AttackStory {
  id: string;
  name: string;
  /** The incident's MITRE tactics in the order they first showed. */
  stages: string[];
  /** Host of the incident's earliest attack log. */
  patientZero: string | null;
  hosts: string[];
  firstSeenS: number | null;
  /** Attack logs someone acted on (judged, escalated, opened or isolated the host), earliest first. */
  seen: StorySeen[];
  /** Attack logs nobody acted on. */
  missed: StoryLog[];
  /** Hosts of this incident someone isolated. */
  isolated: string[];
  total: number;
}

const VERDICT_WORD: Record<string, string> = { true_positive: "called it malicious", suspicious: "marked it suspicious", benign: "called it benign", false_positive: "called it a false positive" };

/**
 * The attack story of every incident in a revealed log. `names` gives the attack name per incident id
 * (the report's incident list); `whoOf` names the actor (a role label on the shared debrief screen).
 */
export function attackStories(events: Ev[], names: Record<string, string> = {}, whoOf: (e: Ev) => string | null = () => null): AttackStory[] {
  const started = events.find(e => e.type === "session.started");
  const t0 = started ? ms(started) : events.length ? ms(events[0]) : NaN;
  // Running time, as the report counts it: paused spans are cut out.
  const spans = pausedSpans(events);
  const rel = (e: Ev) => { const m = ms(e); return Number.isFinite(m) && Number.isFinite(t0) ? Math.max(0, Math.round(activeMs(t0, m, spans) / 1000)) : null; };

  // Attack logs per incident.
  const byInc = new Map<string, { logs: (StoryLog & { tactic: string; ms: number })[] }>();
  const incOf = new Map<string, string>();
  for (const e of events) {
    if (e.type !== "feed.event") continue;
    const q = p(e);
    if (!ATTACK.has(asStr(q.expected_verdict))) continue;
    const id = asStr(q.id) || String(e.seq);
    const inc = asStr(q.incident_id) || `solo:${id}`;
    incOf.set(id, inc);
    if (!byInc.has(inc)) byInc.set(inc, { logs: [] });
    byInc.get(inc)!.logs.push({
      id, label: asStr(q.description) || asStr(q.event_type) || "attack activity", atS: rel(e),
      severity: asStr(q.severity), host: asStr(q.hostname), tactic: asStr(q.mitre_tactic), ms: ms(e),
    });
  }

  // What the team did with each attack log (first action wins the "how").
  const acted = new Map<string, { how: string; who: string | null; atS: number | null }>();
  const isolatedHosts = new Set<string>();
  const note = (eid: string, how: string, e: Ev) => { if (eid && incOf.has(eid) && !acted.has(eid)) acted.set(eid, { how, who: whoOf(e), atS: rel(e) }); };
  for (const e of events) {
    const q = p(e);
    const eid = asStr(q.event_id) || (typeof q.event_id === "number" ? String(q.event_id) : "");
    if (e.type === "escalation.requested") note(eid, "escalated it", e);
    else if (e.type === "disposition.set") note(eid, VERDICT_WORD[asStr(q.verdict)] ?? "judged it", e);
    else if (e.type === "event.opened") note(eid, "opened it", e);
    else if (e.type === "edr.host_isolated" || e.type === "containment.executed") { const h = asStr(q.host) || asStr(q.hostname); if (h) isolatedHosts.add(hostKey(h)); }
    else if (e.type === "sentinel.incident_updated" && Array.isArray(q.event_ids)) for (const x of q.event_ids) note(String(x), "closed it in XDR", e);
  }

  const out: AttackStory[] = [];
  for (const [id, { logs }] of byInc) {
    logs.sort((a, b) => (Number.isFinite(a.ms) ? a.ms : Infinity) - (Number.isFinite(b.ms) ? b.ms : Infinity));
    const stages: string[] = [];
    for (const l of logs) if (l.tactic && !stages.includes(l.tactic)) stages.push(l.tactic);
    const hosts: string[] = [];
    for (const l of logs) if (l.host && !hosts.some(h => hostKey(h) === hostKey(l.host))) hosts.push(l.host);
    const clean = (l: StoryLog): StoryLog => ({ id: l.id, label: l.label, atS: l.atS, severity: l.severity, host: l.host });
    const seen: StorySeen[] = [];
    const missed: StoryLog[] = [];
    for (const l of logs) {
      const a = acted.get(l.id);
      if (a) seen.push({ ...clean(l), how: a.how, who: a.who, atS: a.atS });
      else if (!(l.host && isolatedHosts.has(hostKey(l.host)))) missed.push(clean(l));
    }
    seen.sort((a, b) => (a.atS ?? Infinity) - (b.atS ?? Infinity));
    out.push({
      id, name: names[id] || logs[0]?.label || "Attack", stages, patientZero: logs.find(l => l.host)?.host ?? null, hosts,
      firstSeenS: logs[0]?.atS ?? null, seen, missed,
      isolated: hosts.filter(h => isolatedHosts.has(hostKey(h))), total: logs.length,
    });
  }
  return out.sort((a, b) => (a.firstSeenS ?? Infinity) - (b.firstSeenS ?? Infinity));
}
