// Attack-phase timestamps are in the past and in story order; the feed stays sorted
// newest-first by event time, so a late-arriving log slots into its place.
import { describe, it, expect } from "vitest";
import { phaseTimes, mergeByTime } from "./useLiveEvents";

describe("attack phase timing", () => {
  it("never stamps a log in the future, and keeps story order", () => {
    for (let k = 0; k < 200; k++) {
      const now = 1_790_000_000_000;
      const t = phaseTimes(3, now);
      expect(Math.max(...t)).toBeLessThan(now);
      expect(t[0]).toBeLessThan(t[1]);
      expect(t[1]).toBeLessThan(t[2]);
      expect(now - t[0]).toBeLessThanOrEqual(110_000);   // a phase spans < the 2-min minimum gap to the next
    }
  });
  it("merges newest-first by event time, stable for equal times", () => {
    const at = (id: string, s: number) => ({ id, ts: new Date(1_790_000_000_000 + s * 1000).toISOString() });
    const prev = [at("b3", 90), at("b2", 50), at("b1", 10)];
    const batch = [at("a1", 30), at("a1-siem", 30), at("a2", 70)];
    expect(mergeByTime(batch, prev, 10).map(e => e.id)).toEqual(["b3", "a2", "b2", "a1", "a1-siem", "b1"]);
    expect(mergeByTime(batch, prev, 2).map(e => e.id)).toEqual(["b3", "a2"]);
  });
});
