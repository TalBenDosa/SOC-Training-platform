/**
 * Which case the SOC Manager reports to management.
 *
 * A report used to carry a severity and nothing else, so nobody could tell which of the shift's
 * cases it was about (Tal, 2026-11-28). The manager now picks one of the cases Tier-2 / Tier-3
 * stood behind; later confirmed cases can join the same incident, each with a reason.
 *
 * Session log only: nothing here reads the answer key.
 */
import type { Ev } from "./types";
import { asStr } from "./format";

export interface IncidentCase { eid: string; host: string; summary: string }
export interface ConfirmedCase extends IncidentCase {
  /** Who stood behind it first, and how. */
  by: string | null; byRole: string | null; how: string; atMs: number | null;
}

const SENIOR = new Set(["t2", "t3"]);
const ATTACK_REPORT = new Set(["true_positive", "tp", "escalate", "suspicious"]);
const ms = (e: Ev) => (e.occurred_at ? Date.parse(e.occurred_at) : NaN);
const eidOf = (e: Ev) => asStr((e.payload as { event_id?: unknown }).event_id);
/** The kind a later case carries when it joins the reported incident (a logged decision). */
export const INCIDENT_CASE_KIND = "incident_case";

/** The cases Tier-2 / Tier-3 stood behind, oldest first. A case whose latest report says it is not an attack drops out. */
export function confirmedCases(events: Ev[]): ConfirmedCase[] {
  const feed = new Map<string, Record<string, unknown>>();
  const escalation = new Map<string, Record<string, unknown>>();
  const lastVerdict = new Map<string, string>();
  const first = new Map<string, { by: string | null; byRole: string | null; how: string; atMs: number | null; host: string }>();
  for (const e of events) {
    const p = (e.payload ?? {}) as Record<string, unknown>;
    if (e.type === "feed.event") { feed.set(asStr(p.id) || String(e.seq), p); continue; }
    const eid = eidOf(e);
    if (!eid || !e.actor_id) continue;
    if (e.type === "escalation.requested") escalation.set(eid, p);
    const senior = SENIOR.has(e.role ?? "");
    let how = "";
    if (e.type === "report.submitted") {
      const v = asStr(p.verdict).toLowerCase();
      lastVerdict.set(eid, v);
      if (ATTACK_REPORT.has(v)) how = "investigation report: attack";
    } else if (e.type === "elevation.requested") how = "handed to Tier-3";
    else if (e.type === "containment.requested") how = "containment requested";
    else if (e.type === "escalation.requested" && senior) how = "case opened";
    if (!how || first.has(eid)) continue;
    const t = ms(e);
    first.set(eid, { by: e.actor_id, byRole: e.role ?? null, how, atMs: Number.isFinite(t) ? t : null, host: e.type === "containment.requested" ? asStr(p.target) : "" });
  }
  const out: ConfirmedCase[] = [];
  for (const [eid, f] of first) {
    const v = lastVerdict.get(eid);
    if (v && !ATTACK_REPORT.has(v)) continue;
    const esc = escalation.get(eid) ?? {};
    const log = feed.get(eid) ?? {};
    const host = asStr(esc.hostname) || asStr((esc.snapshot as { hostname?: unknown } | undefined)?.hostname) || asStr(log.hostname) || f.host;
    const summary = asStr(esc.summary) || asStr(esc.what) || asStr(log.description) || "Escalated alert";
    out.push({ eid, host, summary, by: f.by, byRole: f.byRole, how: f.how, atMs: f.atMs });
  }
  return out.sort((a, b) => (a.atMs ?? 0) - (b.atMs ?? 0));
}

/** One incident reported to management: its severity now, and every case in it. */
export interface Incident { id: string; number: number; severity: number | null; atMs: number | null; cases: IncidentCase[] }

/**
 * Every incident the manager reported, oldest first. A shift can hold several: each report names
 * its case (0124), and a later confirmed case either joins one of them or is reported on its own.
 * A severity change names its incident; one without a name is the first incident's (older shifts).
 */
export function reportedIncidents(events: Ev[]): Incident[] {
  const out: Incident[] = [];
  const caseOf = (c: unknown): IncidentCase | null => {
    const x = (c ?? {}) as { event_id?: unknown; host?: unknown; summary?: unknown };
    const eid = asStr(x.event_id);
    return eid ? { eid, host: asStr(x.host), summary: asStr(x.summary) } : null;
  };
  const taken = (eid: string) => out.some(i => i.cases.some(k => k.eid === eid));
  for (const e of events) {
    const p = (e.payload ?? {}) as Record<string, unknown>;
    if (e.type === "incident.declared") {
      const c = caseOf(p.case);
      if (c && taken(c.eid)) continue;
      const t = ms(e); const sev = Number(p.severity);
      out.push({ id: c ? c.eid : `seq:${e.seq}`, number: out.length + 1, severity: Number.isFinite(sev) ? sev : null, atMs: Number.isFinite(t) ? t : null, cases: c ? [c] : [] });
    } else if (e.type === "incident.severity_changed" && out.length) {
      const inc = out.find(i => i.id === asStr(p.incident)) ?? out[0];
      const sev = Number(p.severity);
      if (Number.isFinite(sev)) inc.severity = sev;
    } else if (e.type === "decision.logged" && asStr(p.kind) === INCIDENT_CASE_KIND && out.length) {
      const c = caseOf(p);
      if (!c || taken(c.eid)) continue;
      (out.find(i => i.id === asStr(p.incident)) ?? out[0]).cases.push(c);
    }
  }
  return out;
}

/** The most severe level among the reported incidents (Sev-1 is the most severe); null before any report. */
export function worstSeverity(events: Ev[]): number | null {
  const sevs = reportedIncidents(events).map(i => i.severity).filter((x): x is number => x != null);
  return sevs.length ? Math.min(...sevs) : null;
}

/** Confirmed cases that are not part of any reported incident yet. */
export function casesOutsideIncident(events: Ev[]): ConfirmedCase[] {
  const incs = reportedIncidents(events);
  if (!incs.length) return [];
  const inIt = new Set(incs.flatMap(i => i.cases.map(c => c.eid)));
  return confirmedCases(events).filter(c => !inIt.has(c.eid));
}
