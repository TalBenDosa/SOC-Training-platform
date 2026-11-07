/**
 * Report truth after the 2026-11 review of two real exercises (fix brief items 2 to 6, and
 * isolation by approval). Small synthetic logs, one rule each.
 */
import { describe, it, expect } from "vitest";
import { computeReport, isGhostMember, type ShiftPlan } from "./computeReport";
import type { Ev, RosterMember } from "@/lib/team/types";

const T0 = Date.parse("2026-11-01T10:00:00.000Z");
const at = (sec: number) => new Date(T0 + sec * 1000).toISOString();
const member = (user_id: string, role: string, status = "ready"): RosterMember => ({ user_id, role, status, name: `User ${user_id}`, handle: null });

function log() {
  const events: Ev[] = [];
  const add = (type: string, actor_id: string | null, sec: number, payload: Record<string, unknown> = {}, role: string | null = null) => {
    events.push({ seq: events.length + 1, type, actor_id, role, payload, occurred_at: at(sec) });
    return api;
  };
  const api = { events, add };
  return api;
}
const cell = (rubric: { label: string; score: number | null; value?: string }[], label: string) => rubric.find(r => r.label === label);

describe("self-acknowledged escalations are no hand-off (item 2)", () => {
  const build = () => {
    const { events, add } = log();
    add("session.started", null, 0);
    add("feed.event", null, 10, { id: "a1", expected_verdict: "tp", incident_id: "inc:a", severity: "high", hostname: "WS-1" });
    add("event.opened", "t2", 20, { event_id: "a1", dwell_ms: 5000 });
    add("escalation.requested", "t2", 60, { event_id: "a1", summary: "shell" }, "t2");
    add("escalation.acknowledged", "t2", 60, { event_id: "a1" }, "t2");
    for (const [i, s] of [[2, 70], [3, 75]] as const) {   // two more self-opened cases: T2 "overloaded" by itself
      add("feed.event", null, s, { id: `b${i}`, expected_verdict: "benign", severity: "high" });
      add("escalation.requested", "t2", s + 1, { event_id: `b${i}`, summary: "x" }, "t2");
      add("escalation.acknowledged", "t2", s + 1, { event_id: `b${i}` }, "t2");
    }
    add("coordination.nudge", "mgr", 400, { target: "t2" }, "mgr");
    add("session.ended", null, 1200);
    return events;
  };
  const r = computeReport(build(), [member("t1", "t1"), member("t2", "t2"), member("mgr", "mgr")]);

  it("loop closure, acknowledged count and SLA ignore self-opened cases", () => {
    expect(r.team.selfOpened).toBe(3);
    expect(r.team.acknowledged).toBe(0);
    expect(r.team.loopClosure).toBeNull();
    expect(r.team.incidents[0].slaMet).toBeNull();
    expect(r.team.incidents[0].escalated).toBe(true);
  });
  it("the per-player escalation is marked self-opened, with no SLA verdict", () => {
    const t2 = r.perUser.find(u => u.user_id === "t2")!;
    const item = t2.reported.find(x => x.kind === "escalation" && x.truth === "attack")!;
    expect(item.selfOpened).toBe(true);
    expect(item.withinSla).toBeNull();
  });
  it("three self-opened cases are no overload: nothing to rebalance", () => {
    const mgr = r.perUser.find(u => u.user_id === "mgr")!;
    expect(cell(mgr.rubric, "Overload rebalanced")?.score).toBeNull();
  });
  it("a real Tier-1 hand-off still closes the loop", () => {
    const { events, add } = log();
    add("session.started", null, 0);
    add("feed.event", null, 10, { id: "a1", expected_verdict: "tp", incident_id: "inc:a", severity: "high" });
    add("escalation.requested", "t1", 30, { event_id: "a1", summary: "x" }, "t1");
    add("escalation.acknowledged", "t2", 90, { event_id: "a1" }, "t2");
    add("session.ended", null, 1200);
    const rr = computeReport(events, [member("t1", "t1"), member("t2", "t2")]);
    expect(rr.team.loopClosure).toBe(100);
    expect(rr.team.acknowledged).toBe(1);
    expect(rr.team.incidents[0].slaMet).toBe(true);
    expect(rr.team.handoffLatS).toBe(60);
  });
});

describe("ghost players (item 3)", () => {
  it("a seat removed before the start, or that left with no action, is not scored", () => {
    const { events, add } = log();
    add("member.ready", "gone", -30);
    add("member.removed", "instr", -11, { user_id: "gone" });
    add("session.started", null, 0);
    add("feed.event", null, 10, { id: "n1", expected_verdict: "benign", severity: "low" });
    add("disposition.set", "t1", 40, { event_id: "n1", verdict: "benign" }, "t1");
    add("note.added", "left2", 50, { text: "here" }, "t1");
    add("session.ended", null, 600);
    const roster = [member("t1", "t1"), member("gone", "t1", "left"), member("idle", "mgr", "left"), member("left2", "t1", "left")];
    expect(isGhostMember(roster[1], events)).toBe(true);
    expect(isGhostMember(roster[2], events)).toBe(true);
    expect(isGhostMember(roster[3], events)).toBe(false);
    const r = computeReport(events, roster);
    expect(r.perUser.map(u => u.user_id).sort()).toEqual(["left2", "t1"]);
    expect(r.team.ghosts).toBe(2);
  });
});

describe("containment (item 4)", () => {
  const base = (isolateBoth: boolean) => {
    const { events, add } = log();
    add("session.started", null, 0);
    add("feed.event", null, 10, { id: "a1", expected_verdict: "tp", incident_id: "inc:a", severity: "high", hostname: "WS-1" });
    add("feed.event", null, 20, { id: "a2", expected_verdict: "tp", incident_id: "inc:a", severity: "high", hostname: "WS-2" });
    add("event.opened", "t2", 100, { event_id: "a1", dwell_ms: 4000 });
    add("isolation.requested", "t2", 200, { host: "WS-1", reason: "shell" }, "t2");
    add("isolation.approved", "mgr", 230, { request_seq: 5 }, "mgr");
    add("edr.host_isolated", "t2", 230, { host: "WS-1", request_seq: 5, approved_by: "mgr" }, "t2");
    add("feed.event", null, 231, { id: "iso-8", kind: "containment_status", hostname: "WS-1", severity: "informational" });
    if (isolateBoth) {
      add("isolation.requested", "t2", 300, { host: "WS-2", reason: "same actor" }, "t2");
      add("isolation.approved", "mgr", 310, { request_seq: 9 }, "mgr");
      add("edr.host_isolated", "t2", 310, { host: "WS-2", request_seq: 9, approved_by: "mgr" }, "t2");
    }
    add("escalation.requested", "t2", 333, { event_id: "a1", summary: "late self-ack" }, "t2");
    add("escalation.acknowledged", "t2", 333, { event_id: "a1" }, "t2");
    add("session.ended", null, 1500);
    return computeReport(events, [member("t2", "t2"), member("mgr", "mgr")]);
  };

  it("one isolated host of a two-host attack is not containment", () => {
    const r = base(false);
    expect(r.team.incidents[0]).toMatchObject({ contained: false, hostsTotal: 2, hostsIsolated: 1 });
    expect(r.team.contained).toBe(0);
    expect(r.team.logs).toBe(2);   // the containment status row is telemetry, not a graded log
  });
  it("every attack host isolated contains the incident; the hot-wash counts the EDR isolation", () => {
    const r = base(true);
    expect(r.team.incidents[0]).toMatchObject({ contained: true, hostsIsolated: 2 });
    expect(r.team.contained).toBe(1);
    expect(r.team.hotWash.contained).toBe(true);
    expect(r.team.hotWash.containedS).toBe(230);
    expect(r.team.hotWash.moments.map(m => m.title)).toEqual(["Isolation requested", "Isolation approved", "Host isolated", "First case opened (self-opened)"]);
  });
  it("time to contain runs from when the case reached the analyst, not from a late self-acknowledgement", () => {
    const t2 = base(true).perUser.find(u => u.user_id === "t2")!;
    // opened a1 at 100 → asked to isolate at 200: 1m 40s (was 0s from the ack at 333)
    expect(cell(t2.rubric, "Time to contain")?.value).toBe("1m 40s");
  });
  it("isolation requests are scored: the request, the approval delay, the approver's call", () => {
    const r = base(true);
    expect(r.team.isolationRequests).toHaveLength(2);
    expect(r.team.isolationRequests[0]).toMatchObject({ host: "WS-1", state: "approved", delayS: 30, requestRight: true, answerRight: true });
    expect(r.team.isolations[0]).toMatchObject({ host: "WS-1", requestedS: 200, approvedBy: "mgr", approvalDelayS: 30 });
    const mgr = r.perUser.find(u => u.user_id === "mgr")!;
    expect(cell(mgr.rubric, "Isolation approvals right")?.value).toBe("2 of 2");
    expect(cell(mgr.rubric, "Time to approve containment")?.value).toBe("20s (median)");
  });
  it("a request for a clean host is a wrong request even when denied; the denial is a right call", () => {
    const { events, add } = log();
    add("session.started", null, 0);
    add("feed.event", null, 10, { id: "n1", expected_verdict: "benign", severity: "low", hostname: "WS-9" });
    add("isolation.requested", "t2", 60, { host: "WS-9", reason: "looks odd" }, "t2");
    add("isolation.denied", "mgr", 90, { request_seq: 3, reason: "nothing there" }, "mgr");
    add("session.ended", null, 900);
    const r = computeReport(events, [member("t2", "t2"), member("mgr", "mgr")]);
    expect(r.team.isolationRequests[0]).toMatchObject({ state: "denied", requestRight: false, answerRight: true });
    expect(r.perUser.find(u => u.user_id === "t2")!.isoPct).toBe(0);
    expect(r.team.hotWash).toMatchObject({ contained: false, denied: true });
  });
});

describe("time cells (item 5)", () => {
  it("time to detect never spans two attacks", () => {
    const { events, add } = log();
    add("session.started", null, 0);
    add("feed.event", null, 10, { id: "a1", expected_verdict: "tp", incident_id: "inc:a", severity: "high" });
    add("feed.event", null, 200, { id: "b1", expected_verdict: "tp", incident_id: "inc:b", severity: "high" });
    add("escalation.requested", "t1", 260, { event_id: "b1", summary: "x" }, "t1");
    add("session.ended", null, 1500);
    const r = computeReport(events, [member("t1", "t1")]);
    expect(r.team.timeToDetectS).toBe(60);   // was 250: inc:a's first log to inc:b's escalation
  });
  it("pauses are summed at the top, and the hand-off ladder runs on running time", () => {
    const { events, add } = log();
    add("session.started", null, 0);
    add("feed.event", null, 10, { id: "a1", expected_verdict: "tp", incident_id: "inc:a", severity: "high" });
    add("escalation.requested", "t1", 30, { event_id: "a1", summary: "x" }, "t1");
    add("session.paused", null, 40, { reason: "manual", by: "instr" });
    add("session.resumed", null, 100, {});
    add("escalation.acknowledged", "t2", 110, { event_id: "a1" }, "t2");
    add("session.ended", null, 600);
    const r = computeReport(events, [member("t1", "t1"), member("t2", "t2")]);
    expect(r.team.pauses).toEqual({ totalS: 60, count: 1, list: [{ atS: 40, durationS: 60, reason: "manual", by: "instr" }] });
    const chain = r.team.handoffChains[0];
    expect(chain.steps.map(s => [s.type, s.atS, s.dS])).toEqual([["escalation.requested", 30, 0], ["escalation.acknowledged", 50, 20]]);
    expect(r.team.missedAttacks).toEqual([]);
  });
});

describe("shift truth (item 6)", () => {
  const plan: ShiftPlan = { plannedMs: 45 * 60_000, rows: [
    { incident: "inc:x", attack: true, status: "fired", skipReason: null, planned: true },
    { incident: "inc:x", attack: true, status: "fired", skipReason: null, planned: true },
    { incident: "inc:x", attack: true, status: "skipped", skipReason: "shift_ended", planned: true, name: "ML model" },
    { incident: "inc:y", attack: true, status: "skipped", skipReason: "shift_ended", planned: true, name: "LOL" },
    { incident: null, attack: false, status: "skipped", skipReason: "shift_ended", planned: true },
    { incident: null, attack: false, status: "skipped", skipReason: "isolated:ws-1", planned: true },
    { incident: null, attack: false, status: "fired", skipReason: null, planned: false },
  ] };
  const { events, add } = log();
  add("session.started", null, 0);
  add("feed.event", null, 10, { id: "x1", expected_verdict: "tp", incident_id: "inc:x", severity: "high", event_type: "net_connection" });
  add("feed.event", null, 20, { id: "x2", expected_verdict: "tp", incident_id: "inc:x", severity: "low", event_type: "dns_query" });
  add("feed.event", null, 30, { id: "z1", expected_verdict: "tp", incident_id: "inc:z", severity: "high", event_type: "edr_alert", is_detection: true });
  add("session.ended", null, 27 * 60, { reason: "manual" });
  const r = computeReport(events, [member("t1", "t1")], { plan });

  it("says how many planned rows and attacks never fired", () => {
    expect(r.team.shift).toMatchObject({ endedEarly: true, endReason: "manual", plannedRows: 6, firedRows: 2, unfiredRows: 3, unfiredAttackRows: 2, preventedByIsolation: 1 });
    expect(r.team.shift?.attacksNeverStarted).toEqual([{ id: "inc:y", name: "LOL" }]);
  });
  it("an attack stopped before any alert row fired is not reached, not missed", () => {
    const x = r.team.incidents.find(i => i.id === "inc:x")!;
    expect(x).toMatchObject({ grade: "not_reached", notReached: true, slaMet: null });
    expect(r.team.missedAttacks.map(a => a.name)).not.toContain(x.label);
    expect(r.team.missedAttacks).toHaveLength(1);                      // inc:z had its alert: a real miss
    expect(r.team.incidentRecall).toBe(0);                             // 0 of 1 judged (inc:x not counted)
    expect(r.team.shift?.attacksNotReached).toEqual([{ id: "inc:x", name: "ML model", firedRows: 2, unfiredRows: 1 }]);
  });
});
