import { describe, it, expect } from "vitest";
import { isolationApprovers, canApproveIsolation, isolationRequests, pendingIsolationRequests, type ApproverMember } from "./isolationApproval";
import { sessionClock, openPresenceNotices, scheduledEnd } from "./projections";
import type { Ev } from "./types";

const m = (user_id: string, role: string, active = true, status = "active"): ApproverMember => ({ user_id, role, active, status });

describe("isolation approver rule (same as team_isolation_can_approve, 0104)", () => {
  it("an active SOC Manager or Lead approves first", () => {
    const team = [m("t2", "t2"), m("t3", "t3"), m("mgr", "mgr"), m("ins", "instructor")];
    expect(isolationApprovers(team, "t2")).toMatchObject({ tier: "mgr", userIds: ["mgr"], staffIds: ["ins"] });
    expect(canApproveIsolation(team, "t2", "t3")).toBe(false);
    expect(canApproveIsolation(team, "t2", "mgr")).toBe(true);
  });
  it("no active Manager: a Tier-3 who is not the requester", () => {
    const team = [m("t2", "t2"), m("t3a", "t3"), m("t3b", "t3"), m("mgr", "mgr", false), m("ins", "instructor")];
    expect(isolationApprovers(team, "t3a")).toMatchObject({ tier: "t3", userIds: ["t3b"] });
    expect(canApproveIsolation(team, "t3a", "t3a")).toBe(false);
    expect(canApproveIsolation(team, "t3a", "t3b")).toBe(true);
  });
  it("otherwise staff; staff may always answer; nobody approves their own request", () => {
    const team = [m("t2", "t2"), m("t3", "t3", true, "left"), m("ins", "instructor", false)];
    expect(isolationApprovers(team, "t2")).toMatchObject({ tier: "staff", userIds: ["ins"] });
    expect(canApproveIsolation([m("t2", "t2"), m("mgr", "mgr"), m("ins", "instructor")], "t2", "ins")).toBe(true);
    expect(canApproveIsolation(team, "t2", "t2")).toBe(false);
  });
  it("the acting Manager counts as active even with a stale heartbeat", () => {
    expect(canApproveIsolation([m("t2", "t2"), m("mgr", "mgr", false), m("t3", "t3")], "t2", "mgr")).toBe(true);
  });
});

describe("isolation request projection", () => {
  const ev = (seq: number, type: string, actor: string, payload: Record<string, unknown>): Ev => ({ seq, type, actor_id: actor, role: null, payload, occurred_at: new Date(Date.UTC(2026, 10, 7, 20, 0, seq)).toISOString() });
  const log = [
    ev(1, "isolation.requested", "t2", { host: "WS-1", reason: "shell", incident: "c1" }),
    ev(2, "isolation.requested", "t2", { host: "WS-2", reason: "beacon" }),
    ev(3, "isolation.approved", "mgr", { request_seq: 1 }),
    ev(4, "isolation.denied", "mgr", { request_seq: 99 }),
  ];
  it("pairs each request with its answer", () => {
    expect(isolationRequests(log).map(r => [r.host, r.state, r.answeredBy])).toEqual([["WS-1", "approved", "mgr"], ["WS-2", "pending", null]]);
    expect([...pendingIsolationRequests(log).keys()]).toEqual(["ws-2"]);
  });
});

describe("shift clock and lifecycle projections (0104)", () => {
  it("clock: running time excludes closed and open pauses", () => {
    const now = Date.parse("2026-11-07T20:30:00Z");
    const c = sessionClock({ status: "paused", started_at: "2026-11-07T20:00:00Z", paused_at: "2026-11-07T20:25:00Z", paused_ms: 60_000, end_at: null }, 45, now);
    expect(c).toMatchObject({ planned_ms: 2_700_000, paused_ms: 360_000, active_ms: 1_440_000, paused_at: "2026-11-07T20:25:00.000Z", end_at: null });
  });
  it("presence notices and the scheduled end come from the log", () => {
    const e = (seq: number, type: string, payload: Record<string, unknown>): Ev => ({ seq, type, actor_id: null, role: null, payload });
    const log = [
      e(1, "presence.notice", { kind: "owner_left", state: "raised" }),
      e(2, "presence.notice", { kind: "coverage", state: "raised", missing: ["t1"] }),
      e(3, "presence.notice", { kind: "owner_left", state: "cleared" }),
      e(4, "session.end_scheduled", { ends_at: "2026-11-07T20:32:00Z", by: "ins" }),
    ];
    expect(openPresenceNotices(log)).toEqual([{ kind: "coverage", detail: null, missing: ["t1"], seq: 2 }]);
    expect(scheduledEnd(log)).toEqual({ endsAt: "2026-11-07T20:32:00Z", by: "ins", seq: 4 });
    expect(scheduledEnd([...log, e(5, "session.end_cancelled", {})])).toBeNull();
  });
});
