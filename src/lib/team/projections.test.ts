import { describe, it, expect } from "vitest";
import { activeClaims, openLoadByUser, CLAIM_TTL_MS } from "./projections";
import { advanceWatermark, revealsGap } from "./eventLog";
import type { Ev } from "./types";

const T0 = Date.parse("2026-01-01T10:00:00Z");
const ev = (seq: number, type: string, actor: string | null, payload: Record<string, unknown>, s: number): Ev =>
  ({ seq, type, actor_id: actor, role: null, payload, occurred_at: new Date(T0 + s * 1000).toISOString() });

describe("projections — one claims/load rule (audit A3)", () => {
  const log: Ev[] = [
    ev(1, "alert.claimed", "a", { event_id: "x" }, 0),
    ev(2, "alert.claimed", "b", { event_id: "y" }, 10),
    ev(3, "alert.released", "b", { event_id: "y" }, 20),
    ev(4, "alert.claimed", "a", { event_id: "z" }, 30),
    ev(5, "disposition.set", "a", { event_id: "z", verdict: "benign" }, 40),
    ev(6, "escalation.acknowledged", "t2", { event_id: "e1" }, 50),
    ev(7, "escalation.acknowledged", "t2b", { event_id: "e1" }, 55),
    ev(8, "escalation.acknowledged", "t2", { event_id: "e2" }, 60),
    ev(9, "escalation.resolved", "t2", { event_id: "e2" }, 70),
  ];

  it("claims clear on release/disposition and expire after the TTL", () => {
    expect([...activeClaims(log, T0 + 60_000).keys()]).toEqual(["x"]);
    expect(activeClaims(log, T0 + CLAIM_TTL_MS + 1_000).size).toBe(0);
  });

  it("open load = active claims + first-acked unresolved escalations", () => {
    const load = openLoadByUser(log, T0 + 60_000);
    expect(load.get("a")).toBe(1);        // claim x
    expect(load.get("t2")).toBe(1);       // e1 (first acker); e2 resolved
    expect(load.get("t2b")).toBeUndefined();
    expect(openLoadByUser(log, T0 + CLAIM_TTL_MS + 1_000).get("a")).toBeUndefined(); // stale claim dropped
  });
});

describe("eventLog — contiguous watermark (audit C1)", () => {
  it("advances only over contiguous seqs", () => {
    expect(advanceWatermark(new Set([1, 2, 3, 5]), 0)).toBe(3);
    expect(advanceWatermark(new Set([1, 2, 3, 4, 5]), 3)).toBe(5);
  });
  it("detects a hole above the watermark", () => {
    expect(revealsGap(3, 4)).toBe(false);
    expect(revealsGap(3, 5)).toBe(true);
  });
});
