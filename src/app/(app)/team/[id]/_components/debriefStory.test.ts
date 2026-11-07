import { describe, it, expect } from "vitest";
import { attackStories, fmtDur } from "./debriefStory";
import type { Ev } from "@/lib/team/types";

const T0 = Date.parse("2026-11-01T10:00:00.000Z");
const at = (s: number) => new Date(T0 + s * 1000).toISOString();

describe("fmtDur: one duration format, never raw seconds", () => {
  it("formats seconds, minutes and hours", () => {
    expect(fmtDur(null)).toBe("-");
    expect(fmtDur(undefined)).toBe("-");
    expect(fmtDur(0)).toBe("0s");
    expect(fmtDur(40)).toBe("40s");
    expect(fmtDur(65)).toBe("1m 05s");
    expect(fmtDur(400)).toBe("6m 40s");
    expect(fmtDur(3725)).toBe("1h 02m");
    expect(fmtDur(-5)).toBe("0s");
  });
});

describe("attackStories: the staff debrief's story of each incident", () => {
  function log(): Ev[] {
    const ev: Ev[] = [];
    const add = (type: string, actor: string | null, s: number, payload: Record<string, unknown> = {}, role: string | null = null) =>
      ev.push({ seq: ev.length + 1, type, actor_id: actor, role, payload, occurred_at: at(s) });
    add("session.started", null, 0);
    add("feed.event", null, 30, { id: "a1", expected_verdict: "tp", incident_id: "inc-A", hostname: "WS-HR-7", mitre_tactic: "Initial Access", description: "Macro spawned PowerShell", severity: "high" });
    add("feed.event", null, 60, { id: "a2", expected_verdict: "tp", incident_id: "inc-A", hostname: "WS-HR-7", mitre_tactic: "Command and Control", description: "Beacon to 203.0.113.47", severity: "high" });
    add("feed.event", null, 90, { id: "a3", expected_verdict: "escalate", incident_id: "inc-A", hostname: "FS-01", mitre_tactic: "Lateral Movement", description: "SMB logon from WS-HR-7", severity: "medium" });
    add("feed.event", null, 100, { id: "a4", expected_verdict: "tp", incident_id: "inc-A", hostname: "FS-01", mitre_tactic: "Command and Control", description: "Second beacon", severity: "high" });
    add("feed.event", null, 40, { id: "n1", expected_verdict: "benign", hostname: "WS-IT-1", description: "Patch run" });
    add("feed.event", null, 200, { id: "b1", expected_verdict: "tp", incident_id: "inc-B", hostname: "WS-FIN-2", mitre_tactic: "Exfiltration", description: "Upload to file share" });
    add("escalation.requested", "u1", 120, { event_id: "a2" }, "t1");
    add("disposition.set", "u1", 130, { event_id: "a1", verdict: "benign" }, "t1");
    add("edr.host_isolated", "u2", 150, { host: "fs-01.corp.local" }, "t2");
    add("disposition.set", "u1", 140, { event_id: "n1", verdict: "benign" }, "t1");
    return ev;
  }

  it("orders stages, names patient zero, and splits what was seen from what was missed", () => {
    const [a, b] = attackStories(log(), { "inc-A": "Macro to C2" }, e => (e.role === "t1" ? "Tier-1" : e.role === "t2" ? "Tier-2" : null));
    expect(a.name).toBe("Macro to C2");
    expect(a.stages).toEqual(["Initial Access", "Command and Control", "Lateral Movement"]);
    expect(a.patientZero).toBe("WS-HR-7");
    expect(a.hosts).toEqual(["WS-HR-7", "FS-01"]);
    expect(a.firstSeenS).toBe(30);
    expect(a.total).toBe(4);
    // seen: escalated a2, judged a1 (as benign), earliest action first
    expect(a.seen.map(s => [s.id, s.how, s.who, s.atS])).toEqual([["a2", "escalated it", "Tier-1", 120], ["a1", "called it benign", "Tier-1", 130]]);
    // a3 and a4 sit on FS-01, which was isolated: handled, not missed
    expect(a.missed).toEqual([]);
    expect(a.isolated).toEqual(["FS-01"]);
    // an incident nobody touched, named by its first log when the report has no name
    expect(b.name).toBe("Upload to file share");
    expect(b.seen).toEqual([]);
    expect(b.missed.map(m => m.id)).toEqual(["b1"]);
  });

  it("ignores benign logs and an empty log", () => {
    expect(attackStories([])).toEqual([]);
    expect(attackStories(log()).flatMap(s => [...s.seen, ...s.missed]).some(l => l.id === "n1")).toBe(false);
  });
});

describe("attackStories: running time", () => {
  it("cuts paused spans out of every time, as the report does", () => {
    const ev: Ev[] = [
      { seq: 1, type: "session.started", actor_id: null, role: null, payload: {}, occurred_at: at(0) },
      { seq: 2, type: "session.paused", actor_id: null, role: null, payload: {}, occurred_at: at(10) },
      { seq: 3, type: "session.resumed", actor_id: null, role: null, payload: {}, occurred_at: at(610) },
      { seq: 4, type: "feed.event", actor_id: null, role: null, payload: { id: "x1", expected_verdict: "tp", incident_id: "i", hostname: "H1" }, occurred_at: at(640) },
    ];
    expect(attackStories(ev)[0].firstSeenS).toBe(40);
  });
});
