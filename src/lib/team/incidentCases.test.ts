import { describe, it, expect } from "vitest";
import type { Ev } from "./types";
import { confirmedCases, reportedIncident, casesOutsideIncident, INCIDENT_CASE_KIND } from "./incidentCases";

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

describe("reportedIncident", () => {
  it("is null before the report", () => {
    expect(reportedIncident(base())).toBeNull();
  });

  it("carries the chosen case, a later severity, and cases that joined", () => {
    const events = [...base(),
      ev("report.submitted", "t2", { event_id: "a", verdict: "true_positive", summary: "x" }),
      ev("report.submitted", "t2", { event_id: "b", verdict: "suspicious", summary: "y" }),
      ev("incident.declared", "mgr", { severity: 3, case: { event_id: "a", host: "SRV-FS01", summary: "Mass file access by one account" } })];
    expect(casesOutsideIncident(events).map(c => c.eid)).toEqual(["b"]);
    events.push(ev("incident.severity_changed", "mgr", { severity: 2, reason: "second host" }));
    events.push(ev("decision.logged", "mgr", { decision: "Added WS-FIN-01", rationale: "same account", kind: INCIDENT_CASE_KIND, event_id: "b", host: "WS-FIN-01", summary: "Macro spawned a shell" }));
    const inc = reportedIncident(events);
    expect(inc?.severity).toBe(2);
    expect(inc?.cases.map(c => c.eid)).toEqual(["a", "b"]);
    expect(casesOutsideIncident(events)).toEqual([]);
  });

  it("reads an older report that named no case", () => {
    const inc = reportedIncident([ev("incident.declared", "mgr", { severity: 1 })]);
    expect(inc).toMatchObject({ severity: 1, cases: [] });
  });
});
