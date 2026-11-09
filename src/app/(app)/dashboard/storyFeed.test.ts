/**
 * storyFeed.ts: how the Live Feed releases a story (R4 one monotone map, R7 a burst stays a burst).
 */
import { describe, it, expect } from "vitest";
import { newStoryClock, noiseQuota, phaseSize, placePhase } from "./storyFeed";

const at = (m: number, s = 0) => new Date(Date.UTC(2026, 4, 10, 9, m, s)).toISOString();
const ev = (id: string, ts: string, raw: Record<string, unknown> = {}) => ({ id, ts, raw });

describe("phaseSize (R7)", () => {
  it("releases a burst together instead of 2-3 rows at a time", () => {
    // 12 failed logons over 80 seconds, then a success five minutes later
    const spray = Array.from({ length: 12 }, (_, i) => ev(`f${i}`, at(0, i * 7)));
    const events = [...spray, ev("ok", at(5))];
    expect(phaseSize(events, 0, () => 0.9)).toBe(12);
    expect(phaseSize(events, 12, () => 0.9)).toBe(1);
  });
  it("keeps 2-3 rows when the story is spread out", () => {
    const events = [ev("a", at(0)), ev("b", at(4)), ev("c", at(9)), ev("d", at(15))];
    expect(phaseSize(events, 0, () => 0.9)).toBe(2);
    expect(phaseSize(events, 0, () => 0.1)).toBe(3);
  });
});

describe("placePhase (R4)", () => {
  it("one map: order kept, a burst keeps its authored spacing, a time naming another row lands on it", () => {
    const clock = newStoryClock();
    const now1 = Date.parse("2026-11-09T10:00:00Z");
    const p1 = placePhase(clock, [ev("a", at(0)), ev("b", at(0, 30))], now1, () => 0.5).rows;
    expect(Date.parse(p1[1].ts!) - Date.parse(p1[0].ts!)).toBe(30_000);
    expect(Date.parse(p1[1].ts!)).toBeLessThan(now1);
    // An alert written later names row a's time as its first activity, and a ticket names row b's.
    const now2 = now1 + 180_000;
    const p2 = placePhase(clock, [ev("alert", at(10), { StartTime: at(0), "ExtendedProperties.EndTime": at(0, 30) })], now2, () => 0.5).rows;
    expect(p2[0].raw!.StartTime).toBe(p1[0].ts);
    expect(p2[0].raw!["ExtendedProperties.EndTime"]).toBe(p1[1].ts);
    expect(Date.parse(p2[0].ts!)).toBeGreaterThan(Date.parse(p1[1].ts!));
  });
  it("a row authored before rows already shown arrives late, in its place in time", () => {
    const clock = newStoryClock();
    const now1 = Date.parse("2026-11-09T10:00:00Z");
    const p1 = placePhase(clock, [ev("a", at(0)), ev("b", at(1))], now1, () => 0.5).rows;
    const late = placePhase(clock, [ev("baseline", at(0, 30))], now1 + 150_000, () => 0.5).rows[0];
    expect(Date.parse(late.ts!)).toBeGreaterThan(Date.parse(p1[0].ts!));
    expect(Date.parse(late.ts!)).toBeLessThan(Date.parse(p1[1].ts!));
  });
  it("never stamps a row in the future", () => {
    const clock = newStoryClock();
    const now = Date.parse("2026-11-09T10:00:00Z");
    const rows = placePhase(clock, [ev("a", at(0)), ev("b", at(30))], now, () => 0.99).rows;
    for (const r of rows) expect(Date.parse(r.ts!)).toBeLessThanOrEqual(now);
  });
});

describe("noiseQuota (R8)", () => {
  it("owes twice the attack rows, less what already flowed", () => {
    expect(noiseQuota(5, 0)).toBe(10);
    expect(noiseQuota(5, 4)).toBe(6);
    expect(noiseQuota(5, 12)).toBe(0);
  });
});
