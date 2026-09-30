import { describe, it, expect } from "vitest";
import { buildAlertQueue, nextAlertFor, slaMinFor } from "./alertQueue";
import type { Ev } from "./types";

const NOW = Date.parse("2026-09-30T12:00:00Z");
const ago = (min: number) => new Date(NOW - min * 60000).toISOString();
let seq = 0;
const log = (id: string, severity: string, minAgo: number): Ev =>
  ({ seq: ++seq, type: "feed.event", actor_id: null, role: null, payload: { id, severity }, occurred_at: ago(minAgo) });

const base = { dispositions: new Map<string, string>(), escalated: new Set<string>(), claims: new Map<string, { by: string }>(), nowMs: NOW, withMedium: false };

describe("buildAlertQueue", () => {
  it("is a projection of the feed: high/critical logs that still need triage", () => {
    const feed = [log("a", "high", 0), log("b", "low", 0), log("c", "critical", 0), log("d", "medium", 0)];
    expect(buildAlertQueue({ ...base, feed }).map(q => q.eid).sort()).toEqual(["a", "c"]);
  });

  it("pulls medium in on request", () => {
    const feed = [log("a", "high", 0), log("d", "medium", 0)];
    expect(buildAlertQueue({ ...base, feed, withMedium: true }).map(q => q.eid).sort()).toEqual(["a", "d"]);
  });

  it("drains as logs are dispositioned or escalated", () => {
    const feed = [log("a", "high", 0), log("b", "high", 0), log("c", "high", 0)];
    const q = buildAlertQueue({ ...base, feed, dispositions: new Map([["a", "benign"]]), escalated: new Set(["b"]) });
    expect(q.map(x => x.eid)).toEqual(["c"]);
  });

  it("puts orphans (past SLA, unclaimed) first, then severity × age", () => {
    const feed = [log("fresh-crit", "critical", 0), log("old-high", "high", 10), log("claimed-old", "high", 20)];
    const q = buildAlertQueue({ ...base, feed, claims: new Map([["claimed-old", { by: "u2" }]]) });
    expect(q[0].eid).toBe("old-high");
    expect(q[0].orphan).toBe(true);
    expect(q.find(x => x.eid === "claimed-old")!.orphan).toBe(false);
    expect(q.find(x => x.eid === "claimed-old")!.breached).toBe(true);
  });

  it("uses the severity SLA for the breach flag", () => {
    expect(slaMinFor("critical")).toBe(1);
    const q = buildAlertQueue({ ...base, feed: [log("h", "high", 2)] });
    expect(q[0].breached).toBe(false);
    expect(q[0].mins).toBe(2);
  });

  it("falls back to the seq when a log has no payload id", () => {
    const e: Ev = { seq: 999, type: "feed.event", actor_id: null, role: null, payload: { severity: "high" }, occurred_at: ago(0) };
    expect(buildAlertQueue({ ...base, feed: [e] })[0].eid).toBe("999");
  });
});

describe("nextAlertFor", () => {
  it("skips alerts another analyst holds, keeps my own claim", () => {
    const feed = [log("x", "critical", 5), log("y", "high", 5)];
    const claims = new Map([["x", { by: "other" }]]);
    const q = buildAlertQueue({ ...base, feed, claims });
    expect(nextAlertFor(q, claims, "me")?.eid).toBe("y");
    // Only x in the queue: held by someone else → nothing for me; held by me → mine to continue.
    const onlyX = [feed[0]];
    expect(nextAlertFor(buildAlertQueue({ ...base, feed: onlyX, claims }), claims, "me")).toBeNull();
    const mine = new Map([["x", { by: "me" }]]);
    expect(nextAlertFor(buildAlertQueue({ ...base, feed: onlyX, claims: mine }), mine, "me")?.eid).toBe("x");
    expect(nextAlertFor([], claims, "me")).toBeNull();
  });
});
