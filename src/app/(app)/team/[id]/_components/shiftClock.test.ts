// Shift clock, presence notices, the Manager's end request and stuck seats (2026-11 review).
import { describe, it, expect } from "vitest";
import type { Ev, RosterMember } from "@/lib/team/types";
import { fmtClock, openEndRequest, openPresenceNotices, seatActivity, shiftClock } from "./shiftClock";

const T0 = Date.parse("2026-11-07T10:00:00Z");
const at = (min: number) => new Date(T0 + min * 60_000).toISOString();
let seq = 0;
const ev = (type: string, min: number, payload: Record<string, unknown> = {}, actor: string | null = null): Ev => ({ seq: ++seq, type, actor_id: actor, role: null, payload, occurred_at: at(min) });

describe("shiftClock", () => {
  it("counts running time only: a pause does not age the shift", () => {
    const events = [ev("session.started", 0), ev("session.paused", 10), ev("session.resumed", 15)];
    const c = shiftClock(events, { startedAt: at(0), plannedMs: 30 * 60_000, now: T0 + 20 * 60_000 });
    expect(c.activeMs).toBe(15 * 60_000);
    expect(c.remainingMs).toBe(15 * 60_000);
    expect(c.overtime).toBe(false);
    expect(c.paused).toBe(false);
  });
  it("an open pause stops the clock at the pause", () => {
    const events = [ev("session.started", 0), ev("session.paused", 10)];
    const c = shiftClock(events, { startedAt: at(0), plannedMs: 30 * 60_000, now: T0 + 25 * 60_000 });
    expect(c.activeMs).toBe(10 * 60_000);
    expect(c.paused).toBe(true);
  });
  it("reports the planned time reached, a scheduled end, and its cancellation", () => {
    const sched = ev("session.end_scheduled", 31, { ends_at: at(33), delay_ms: 120_000 }, "staff-1");
    const c = shiftClock([ev("session.started", 0), sched], { startedAt: at(0), plannedMs: 30 * 60_000, now: T0 + 32 * 60_000 });
    expect(c.overtime).toBe(true);
    expect(c.endsAt).toBe(T0 + 33 * 60_000);
    expect(c.endBy).toBe("staff-1");
    const cancelled = shiftClock([ev("session.started", 0), sched, ev("session.end_cancelled", 32)], { startedAt: at(0), plannedMs: 30 * 60_000, now: T0 + 32 * 60_000 });
    expect(cancelled.endsAt).toBeNull();
  });
  it("stops at the end and says nothing before the start", () => {
    expect(shiftClock([], { startedAt: null, plannedMs: 60_000, now: T0 }).started).toBe(false);
    const c = shiftClock([ev("session.started", 0), ev("session.ended", 12)], { startedAt: at(0), plannedMs: 30 * 60_000, now: T0 + 50 * 60_000 });
    expect(c.activeMs).toBe(12 * 60_000);
    expect(c.endsAt).toBeNull();
  });
  it("formats mm:ss and h:mm:ss", () => {
    expect(fmtClock(65_000)).toBe("01:05");
    expect(fmtClock(3_725_000)).toBe("1:02:05");
    expect(fmtClock(-5)).toBe("00:00");
  });
});

describe("openPresenceNotices", () => {
  it("keeps a raised notice until it is cleared, per kind", () => {
    const raised = ev("presence.notice", 5, { kind: "coverage", state: "raised", missing: ["t1"] });
    expect(openPresenceNotices([raised]).map(n => n.missing)).toEqual([["t1"]]);
    expect(openPresenceNotices([raised, ev("presence.notice", 6, { kind: "coverage", state: "cleared" })])).toEqual([]);
    expect(openPresenceNotices([raised, ev("presence.notice", 6, { kind: "owner_left", state: "raised" })]).map(n => n.kind).sort()).toEqual(["coverage", "owner_left"]);
  });
});

describe("openEndRequest", () => {
  it("is open until the instructor schedules the end or declines", () => {
    const req = ev("message.sent", 20, { text: "The SOC Manager asks to end the shift.", kind: "end_request" }, "mgr-1");
    expect(openEndRequest([req])?.seq).toBe(req.seq);
    expect(openEndRequest([req, ev("session.end_scheduled", 21, { ends_at: at(23) })])).toBeNull();
    expect(openEndRequest([req, ev("message.sent", 21, { text: "not yet", kind: "end_request_declined" })])).toBeNull();
    expect(openEndRequest([ev("message.sent", 20, { text: "hi" }, "mgr-1")])).toBeNull();
  });
});

describe("seatActivity", () => {
  const roster: RosterMember[] = [
    { user_id: "t1", role: "t1", status: "active", name: "Ana", handle: null },
    { user_id: "mgr", role: "mgr", status: "active", name: "Noa", handle: null },
    { user_id: "gone", role: "t1", status: "left", name: "Ghost", handle: null },
    { user_id: "ins", role: "instructor", status: "active", name: "Tal", handle: null },
  ];
  it("flags a silent seat, the Manager included; a log open counts as activity, a removed seat is gone", () => {
    const events = [ev("session.started", 0), ev("disposition.set", 2, {}, "t1"), ev("event.opened", 18, {}, "t1")];
    const seats = seatActivity(events, roster, T0 + 20 * 60_000, T0);
    expect(seats.map(s => s.userId)).toEqual(["t1", "mgr"]);
    const t1 = seats.find(s => s.userId === "t1")!, mgr = seats.find(s => s.userId === "mgr")!;
    expect(t1.lastActionMs).toBe(T0 + 2 * 60_000);
    expect(t1.idleMin).toBe(2);
    expect(t1.idle).toBe(false);
    expect(mgr.idleMin).toBe(20);
    expect(mgr.idle).toBe(true);
  });
});
