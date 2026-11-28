import { describe, it, expect } from "vitest";
import type { Ev } from "./types";
import { confirmedCases, reportedIncidents, worstSeverity, casesOutsideIncident, INCIDENT_CASE_KIND } from "./incidentCases";

let seq = 0;
const ev = (type: string, role: string | null, payload: Record<string, unknown>, actor = role ? `u-${role}` : null): Ev =>
  ({ seq: ++seq, type, role, actor_id: actor, payload, occurred_at: new Date(1_700_000_000_000 + seq * 60_000).toISOString() }) as unknown as Ev;

const base = (): Ev[] => [
  ev("feed.event", null, { id: "a", hostname: "SRV-FS01", description: "Mass file access" }),
  ev("feed.event", null, { id: "b", hostname: "WS-FIN-01", description: "Office macro" }),
  ev("escalation.requested", "t1", { event_id: "a", summary: "Mass file access by one account", hostname: "SRV-FS01" }),
  ev("escalation.requested", "t1", { event_id: "b", summary: "Macro spawned a shell", hostname: "WS-FIN-01" }),
];

describe("confirmedCases", () => {
  it("lists nothing while only Tier-1 has escalated", () => {
    expect(confirmedCases(base())).toEqual([]);
  });

  it("lists a case once Tier-2 files an attack report, with who stood behind it", () => {
    const events = [...base(), ev("report.submitted", "t2", { event_id: "a", verdict: "true_positive", summary: "confirmed" })];
    const cases = confirmedCases(events);
    expect(cases).toHaveLength(1);
    expect(cases[0]).toMatchObject({ eid: "a", host: "SRV-FS01", summary: "Mass file access by one account", by: "u-t2", byRole: "t2" });
  });

  it("drops a case whose latest report says it is not an attack", () => {
    const events = [...base(),
      ev("elevation.requested", "t2", { event_id: "b" }),
      ev("report.submitted", "t3", { event_id: "b", verdict: "false_positive", summary: "admin script" })];
    expect(confirmedCases(events)).toEqual([]);
  });

  it("takes the host from a containment request when the log has none", () => {
    const events = [ev("containment.requested", "t2", { event_id: "z", target: "DC-01" })];
    expect(confirmedCases(events)[0]).toMatchObject({ eid: "z", host: "DC-01" });
  });
});

describe("reportedIncidents", () => {
  const confirmedBoth = (): Ev[] => [...base(),
    ev("report.submitted", "t2", { event_id: "a", verdict: "true_positive", summary: "x" }),
    ev("report.submitted", "t2", { event_id: "b", verdict: "suspicious", summary: "y" }),
    ev("incident.declared", "mgr", { severity: 3, case: { event_id: "a", host: "SRV-FS01", summary: "Mass file access by one account" } })];

  it("is empty before the report", () => {
    expect(reportedIncidents(base())).toEqual([]);
    expect(worstSeverity(base())).toBeNull();
  });

  it("a later case joins the reported incident, with the severity changed since", () => {
    const events = confirmedBoth();
    expect(casesOutsideIncident(events).map(c => c.eid)).toEqual(["b"]);
    events.push(ev("incident.severity_changed", "mgr", { severity: 2, reason: "second host" }));
    events.push(ev("decision.logged", "mgr", { decision: "Added WS-FIN-01", rationale: "same account", kind: INCIDENT_CASE_KIND, event_id: "b", host: "WS-FIN-01", summary: "Macro spawned a shell" }));
    const incs = reportedIncidents(events);
    expect(incs).toHaveLength(1);
    expect(incs[0].severity).toBe(2);
    expect(incs[0].cases.map(c => c.eid)).toEqual(["a", "b"]);
    expect(casesOutsideIncident(events)).toEqual([]);
  });

  it("a later case reported on its own is a second incident with its own severity", () => {
    const events = confirmedBoth();
    events.push(ev("incident.declared", "mgr", { severity: 1, case: { event_id: "b", host: "WS-FIN-01", summary: "Macro spawned a shell" } }));
    events.push(ev("incident.severity_changed", "mgr", { severity: 4, reason: "downgraded", incident: "a" }));
    const incs = reportedIncidents(events);
    expect(incs.map(i => [i.number, i.id, i.severity])).toEqual([[1, "a", 4], [2, "b", 1]]);
    expect(worstSeverity(events)).toBe(1);
    expect(casesOutsideIncident(events)).toEqual([]);
  });

  it("a case is never counted in two incidents", () => {
    const events = confirmedBoth();
    events.push(ev("incident.declared", "mgr", { severity: 1, case: { event_id: "a", host: "SRV-FS01", summary: "again" } }));
    expect(reportedIncidents(events)).toHaveLength(1);
  });

  it("reads an older report that named no case; an unnamed severity change is the first incident's", () => {
    const incs = reportedIncidents([ev("incident.declared", "mgr", { severity: 1 }), ev("incident.severity_changed", "mgr", { severity: 2, reason: "r" })]);
    expect(incs).toHaveLength(1);
    expect(incs[0]).toMatchObject({ number: 1, severity: 2, cases: [] });
  });
});
