// 2026-10-18 review: the low / medium steps of an attack were walked past once one alert of it was
// found. Correlation by host / user / external address pulls them next to the analyst.
import { describe, it, expect } from "vitest";
import { entityKeys, relatedLogs, linkedToHot } from "./correlate";
import { buildAlertQueue } from "./alertQueue";
import type { Ev } from "./types";

const ev = (seq: number, min: number, p: Record<string, unknown>): Ev =>
  ({ seq, type: "feed.event", actor_id: null, role: null, payload: { id: `e${seq}`, ...p }, occurred_at: new Date(Date.UTC(2026, 9, 18, 10, min)).toISOString() });

const feed = [
  ev(1, 0, { hostname: "WS-ACC-4477", severity: "high", description: "encoded powershell" }),
  ev(2, 2, { hostname: "WS-ACC-4477", severity: "low", description: "dns lookup KNCVGU2J.nexus-update-svc.xyz" }),
  ev(3, 3, { src_ip: "10.0.0.5", dst_ip: "193.42.36.58", severity: "informational", description: "outbound 443" }),
  ev(4, 4, { hostname: "WS-HR-1142", severity: "low", description: "logon" }),
  ev(5, 50, { hostname: "WS-ACC-4477", severity: "low", description: "much later" }),
  ev(6, 1, { hostname: "LT-OPS-1", dst_ip: "193.42.36.58", severity: "low", description: "same C2 address" }),
];

describe("correlate", () => {
  it("entity keys: host, user, external addresses only", () => {
    expect(entityKeys(feed[2])).toEqual(["ip:193.42.36.58"]);
    expect(entityKeys(ev(9, 0, { hostname: "A", user_email: "SYSTEM" }))).toEqual(["host:a"]);
  });

  it("related logs: same entity within the window", () => {
    expect(relatedLogs(feed, feed[0]).map(r => r.eid)).toEqual(["e2"]);
    expect(relatedLogs(feed, feed[2]).map(r => r.eid)).toEqual(["e6"]);
  });

  it("an escalated alert pulls its quiet neighbours into Needs triage, nothing else", () => {
    const linked = linkedToHot(feed, new Map(), new Set(["e1"]));
    expect([...linked.keys()]).toEqual(["e2"]);
    const q = buildAlertQueue({ feed, dispositions: new Map(), escalated: new Set(["e1"]), claims: new Map(), nowMs: Date.UTC(2026, 9, 18, 10, 5), withMedium: false });
    expect(q.map(i => i.eid)).toEqual(["e2"]);
    expect(q[0].linked).toBe("ws-acc-4477");
    // before anything is escalated, a low log stays out of the queue
    expect(buildAlertQueue({ feed, dispositions: new Map(), escalated: new Set(), claims: new Map(), nowMs: Date.UTC(2026, 9, 18, 10, 5), withMedium: false }).map(i => i.eid)).toEqual(["e1"]);
  });
});
