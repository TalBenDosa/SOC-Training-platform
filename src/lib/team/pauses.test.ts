import { describe, it, expect } from "vitest";
import { pausedSpans, pausedBetween, activeMs, addActive } from "./pauses";
import { buildAlertQueue } from "./alertQueue";
import { activeClaims, CLAIM_TTL_MS } from "./projections";
import { computeReport } from "./report/computeReport";
import type { Ev, RosterMember } from "./types";

const T0 = Date.parse("2026-10-02T10:00:00Z");
const at = (s: number) => new Date(T0 + s * 1000).toISOString();
const ev = (seq: number, type: string, actor: string | null, payload: Record<string, unknown>, s: number): Ev =>
  ({ seq, type, actor_id: actor, role: null, payload, occurred_at: at(s) });
const MIN = 60_000;

describe("pausedSpans / activeMs (QA M3 — pauses never count against the team)", () => {
  const life: Ev[] = [
    ev(1, "session.started", null, {}, 0),
    ev(2, "session.paused", null, { reason: "coverage" }, 100),
    ev(3, "session.paused", null, { reason: "manual" }, 150),   // reason switch: same pause
    ev(4, "session.resumed", null, {}, 400),
    ev(5, "session.paused", null, {}, 1000),
    ev(6, "session.ended", null, {}, 1100),
  ];

  it("rebuilds the paused spans from the lifecycle events (a reason switch continues the span)", () => {
    expect(pausedSpans(life)).toEqual([{ start: T0 + 100_000, end: T0 + 400_000 }, { start: T0 + 1_000_000, end: T0 + 1_100_000 }]);
  });

  it("an open pause runs to openUntil, else to the last timestamp in the log", () => {
    const open = [ev(1, "session.started", null, {}, 0), ev(2, "session.paused", null, {}, 60), ev(3, "feed.event", null, {}, 90)];
    expect(pausedSpans(open)).toEqual([{ start: T0 + 60_000, end: T0 + 90_000 }]);
    expect(pausedSpans(open, T0 + 600_000)).toEqual([{ start: T0 + 60_000, end: T0 + 600_000 }]);
  });

  it("activeMs removes only the overlap; negative deltas pass through unchanged", () => {
    const spans = pausedSpans(life);
    expect(pausedBetween(T0, T0 + 200_000, spans)).toBe(100_000);
    expect(activeMs(T0 + 50_000, T0 + 450_000, spans)).toBe(100_000);    // 400 s wall − 300 s paused
    expect(activeMs(T0 + 500_000, T0 + 400_000, spans)).toBe(-100_000);
    expect(activeMs(T0, T0 + 90_000, [])).toBe(90_000);
  });

  it("addActive skips paused spans when adding running time", () => {
    const spans = pausedSpans(life);
    expect(addActive(T0 + 50_000, 100_000, spans)).toBe(T0 + 450_000);
    expect(addActive(T0, 50_000, spans)).toBe(T0 + 50_000);
    expect(addActive(T0 + 200_000, 10_000, spans)).toBe(T0 + 410_000);   // starts inside a pause
  });
});

describe("live projections honour pauses", () => {
  it("an alert's SLA age stops while the session is paused", () => {
    const feed = [ev(1, "feed.event", null, { id: "a", severity: "high" }, 0)];
    const now = T0 + 10 * MIN;
    const base = { feed, dispositions: new Map<string, string>(), escalated: new Set<string>(), claims: new Map<string, { by: string }>(), nowMs: now, withMedium: false };
    expect(buildAlertQueue(base)[0]).toMatchObject({ mins: 10, breached: true });
    const pauses = [{ start: T0 + 1 * MIN, end: T0 + 9 * MIN }];
    expect(buildAlertQueue({ ...base, pauses })[0]).toMatchObject({ mins: 2, breached: false });
  });

  it("a claim's 5-minute TTL counts running time only", () => {
    const log = [
      ev(1, "alert.claimed", "a", { event_id: "x" }, 0),
      ev(2, "session.paused", null, {}, 60),
      ev(3, "session.resumed", null, {}, 60 + 10 * 60),
    ];
    // 11 min of wall clock, but only 1 + 1 = 2 min running → still held.
    expect(activeClaims(log, T0 + 12 * MIN).get("x")?.by).toBe("a");
    expect(activeClaims(log, T0 + 10 * MIN + CLAIM_TTL_MS + 1_000).size).toBe(0);
  });
});

describe("computeReport timing is pause-aware", () => {
  const roster: RosterMember[] = [
    { user_id: "t1", role: "t1", status: "ready", name: "T1", handle: null },
    { user_id: "t2", role: "t2", status: "ready", name: "T2", handle: null },
  ];
  const log = (withPause: boolean): Ev[] => [
    ev(1, "session.started", null, {}, 0),
    ev(2, "feed.event", null, { id: "e1", severity: "high", expected_verdict: "tp", incident_id: "inc1" }, 60),
    ...(withPause ? [ev(3, "session.paused", null, { reason: "manual" }, 90), ev(4, "session.resumed", null, {}, 90 + 20 * 60)] : []),
    ev(5, "escalation.requested", "t1", { event_id: "e1", summary: "phish" }, withPause ? 120 + 20 * 60 : 120),
    ev(6, "escalation.acknowledged", "t2", { event_id: "e1" }, withPause ? 150 + 20 * 60 : 150),
    ev(7, "session.ended", null, {}, withPause ? 600 + 20 * 60 : 600),
  ];

  it("a 20-minute pause leaves MTTD, ack latency and the per-log SLA exactly as without it", () => {
    const a = computeReport(log(false), roster);
    const b = computeReport(log(true), roster);
    expect(b.team.timeToDetectS).toBe(a.team.timeToDetectS);
    expect(b.team.timeToDetectS).toBe(120);
    expect(b.team.handoffLatS).toBe(30);
    expect(b.team.incidents[0].dwellS).toBe(60);
    const t1 = b.perUser.find(u => u.user_id === "t1")!;
    expect(t1.reported[0]).toMatchObject({ responseS: 60, withinSla: true });
    expect(t1.firstActionS).toBe(120);
    expect(b.perUser.find(u => u.user_id === "t2")!.rubric.find(c => c.label === "Ack latency")?.score)
      .toBe(a.perUser.find(u => u.user_id === "t2")!.rubric.find(c => c.label === "Ack latency")?.score);
  });

  it("without the pause rule the same log would have breached the SLA (regression guard)", () => {
    const b = computeReport(log(true), roster);
    expect(b.perUser.find(u => u.user_id === "t1")!.slaMet).toBe(1);
    expect(b.team.attackSlaMet).toBe(1);
  });
});
