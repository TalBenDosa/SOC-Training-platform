// Hand-offs (owner, 2026-11-08): every escalation or case opens with the full detail of what the
// analyst reported. The builders read only what players wrote and the log as the feed showed it.
import { describe, it, expect } from "vitest";
import type { Ev } from "./types";
import { at, log, nameOf, sampleEvents } from "./__fixtures__/handoffEvents";
import { containmentRequests } from "./projections";
import { isolationRequests } from "./isolationApproval";
import { containmentHandoff, elevationHandoff, escalationHandoff, escalationSnapshot, handoffText, isolationHandoff, reportHandoff } from "./handoff";

describe("escalationHandoff", () => {
  const events = sampleEvents();
  const h = escalationHandoff(events[3], events, { nameOf });

  it("carries every field the analyst wrote, in full", () => {
    expect(h.summary).toContain("Ticket INC0033424 (New): Locked out, then an encoded PowerShell beacon");
    expect(h.from).toBe("Dana");
    expect(h.fromRole).toBe("Tier-1");
    expect(h.verdict).toBe("true positive");
    expect(h.severity).toBe("high");
    expect(h.action).toBe("contain");
    expect(h.confidence).toBe("70%");
    expect(h.reasoning).toContain("IEX download cradle");
    expect(h.sections).toContainEqual(["Assessment", "Macro dropper with C2"]);
    expect(h.sections.find(([k]) => k === "Isolation")?.[1]).toContain("WS-FIN-2847");
    expect(h.iocs).toHaveLength(10);
    expect(h.affected).toEqual([["Host", "WS-FIN-2847"], ["User", "r.cohen@nexacorp.com"]]);
  });

  it("brings the escalated log's key fields and the log added to the case later", () => {
    expect(h.logs[0].fields).toContainEqual(["Command line", "powershell -enc SQBFAFgA"]);
    expect(h.logs[0].fields).toContainEqual(["Destination IP", "185.220.101.4"]);
    expect(h.logs[1]).toMatchObject({ label: "Beacon to 185.220.101.4", addedBy: "Dana" });
  });

  it("never reads the answer key", () => {
    const all = JSON.stringify(h);
    expect(all).not.toContain("THE ANSWER");
    expect(all).not.toContain("expected_verdict");
  });

  it("adds a later bounce, and prefers the disposition sent with the request", () => {
    const more: Ev[] = [...events, { seq: 20, type: "escalation.bounced", actor_id: "u2", role: "t2", payload: { event_id: "e1", reason: "Needs more context: which user?" }, occurred_at: at(20) }];
    const b = escalationHandoff({ ...events[3], payload: { ...events[3].payload, disposition: "suspicious" } }, more, { nameOf });
    expect(b.verdict).toBe("suspicious");
    expect(b.notes).toContainEqual(expect.objectContaining({ label: "Bounced back", by: "Noa", text: "Needs more context: which user?" }));
  });

  it("reads as plain text for a Sentinel description", () => {
    const t = handoffText(h);
    expect(t.split("\n")[0]).toBe("Escalation from Dana (Tier-1) at 2026-11-08 09:03 UTC");
    expect(t).toContain("Observations: WINWORD.EXE spawned");
    expect(t).toContain("Indicators (10): ip: 185.220.101.1");
    expect(t).not.toContain("—");
  });
});

describe("the other hand-offs", () => {
  const events = sampleEvents();
  it("an elevation carries the hunt ask, Tier-2's report and the Tier-1 escalation behind it", () => {
    const h = elevationHandoff(events[8], events, { nameOf });
    expect(h.reasoning).toBe("Hunt lateral movement from WS-FIN-2847 to the DC");
    expect(h.verdict).toBe("true positive");
    expect(h.sections.map(([k]) => k)).toEqual(["Tier-2 findings", "Tier-2 recommendation"]);
    expect(h.related[0]).toMatchObject({ kind: "escalation", from: "Dana" });
    expect(h.related[0].reasoning).toContain("IEX download cradle");
  });

  it("a containment request carries the trade-off, the case and the report with its scope", () => {
    const h = containmentHandoff(containmentRequests(events)[0], events, { nameOf });
    expect(h.summary).toBe("Disable account: r.cohen@nexacorp.com");
    expect(h.reasoning).toBe("Credentials used from the beacon host");
    expect(h.params).toContainEqual(["What breaks if contained", "The user loses mail for an hour"]);
    expect(h.related.map(r => r.kind)).toEqual(["escalation", "report"]);
    expect(h.related[1].params.find(([k]) => k === "Scope")?.[1]).toContain("WS-FIN-2847");
  });

  it("an isolation request names its case and brings it along", () => {
    const h = isolationHandoff(isolationRequests(events)[0], events, { nameOf });
    expect(h.summary).toBe("Isolate WS-FIN-2847");
    expect(h.params).toContainEqual(["Incident", "INC-A"]);
    expect(h.params.find(([k]) => k === "Case")?.[1]).toContain("Ticket INC0033424");
    expect(h.related[0].iocs).toHaveLength(10);
  });

  it("a report shows verdict, findings, recommendation and scope", () => {
    const h = reportHandoff(events[6], events, { nameOf });
    expect(h).toMatchObject({ kind: "report", verdict: "true positive", reasoning: "Confirmed the beacon in the EDR, one host only." });
    expect(h.sections).toEqual([["Recommendation", "Isolate the host, block 185.220.101.4"]]);
  });

  it("an oversized log is trimmed to fit the action cap and keeps its key fields", () => {
    const big = { ...log, raw: "x".repeat(20000), description: "y".repeat(5000) };
    const snap = escalationSnapshot(big)!;
    expect(JSON.stringify(snap).length).toBeLessThan(12000);
    expect(snap.hostname).toBe("WS-FIN-2847");
    expect(snap.snapshot_truncated).toBe(true);
  });
});
