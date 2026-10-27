import { describe, it, expect } from "vitest";
import { buildAlertQueue } from "./alertQueue";
import { attachedByCase, attachedLogs, flattenGroups, groupQueueByHost, openCasesByHost, touchedHostsOf } from "./hostCases";
import { isolationState } from "./projections";
import type { Ev } from "./types";

const NOW = Date.parse("2026-10-25T11:00:00Z");
const ago = (min: number) => new Date(NOW - min * 60000).toISOString();
let seq = 0;
const log = (id: string, severity: string, hostname: string, minAgo = 1): Ev =>
  ({ seq: ++seq, type: "feed.event", actor_id: null, role: null, payload: { id, severity, hostname }, occurred_at: ago(minAgo) });
const ev = (type: string, actor: string, role: string, payload: Record<string, unknown>): Ev =>
  ({ seq: ++seq, type, actor_id: actor, role, payload, occurred_at: ago(0) });
const hostOf = (e: Ev) => String((e.payload as { hostname?: unknown }).hostname ?? "");
const base = { dispositions: new Map<string, string>(), claims: new Map<string, { by: string }>(), nowMs: NOW, withMedium: false };

// The Sdema 2026-10-25 shape: Tier-2 has a case and an isolation on WS-SALES-1876; two other hosts
// carry critical alerts nobody opened.
function sdema() {
  const feed = [
    log("33", "high", "WS-SALES-1876", 20), log("48", "high", "WS-SALES-1876", 12), log("54", "high", "WS-SALES-1876", 9),
    log("83", "critical", "WS-OPS-2214", 6), log("95", "critical", "WS-ENG-2093", 4), log("12", "high", "SRV-SCAN", 3),
  ];
  const events: Ev[] = [
    ...feed,
    ev("escalation.requested", "dmitry", "t2", { event_id: "33", summary: "Encoded PowerShell from WINWORD", snapshot: { hostname: "WS-SALES-1876" } }),
    ev("escalation.acknowledged", "dmitry", "t2", { event_id: "33" }),
    ev("edr.host_isolated", "dmitry", "t2", { host: "WS-SALES-1876" }),
    ev("disposition.set", "aviv", "t1", { event_id: "12", verdict: "false_positive" }),
  ];
  return { feed, events };
}

describe("openCasesByHost", () => {
  it("keys an open case by its host, with its owner", () => {
    const { events } = sdema();
    const c = openCasesByHost(events).get("ws-sales-1876");
    expect(c?.caseEid).toBe("33");
    expect(c?.owner).toBe("dmitry");
  });
  it("drops a case once it is resolved or bounced", () => {
    const { events } = sdema();
    expect(openCasesByHost([...events, ev("escalation.resolved", "dmitry", "t2", { event_id: "33" })]).size).toBe(0);
    expect(openCasesByHost([...events, ev("escalation.bounced", "dmitry", "t2", { event_id: "33", reason: "x" })]).size).toBe(0);
  });
});

describe("groupQueueByHost", () => {
  it("puts hosts nobody has touched on top and the host already in a case last", () => {
    const { feed, events } = sdema();
    const queue = buildAlertQueue({ ...base, feed, dispositions: new Map([["12", "false_positive"]]), escalated: new Set(["33"]) });
    const hostByEid = new Map(feed.map(e => [String(e.payload.id), hostOf(e).toLowerCase()]));
    const groups = groupQueueByHost(queue, { hostOf, cases: openCasesByHost(events), isolation: isolationState(events), touchedHosts: touchedHostsOf(events, hostByEid) });
    expect(groups.map(g => g.host)).toEqual(["WS-OPS-2214", "WS-ENG-2093", "WS-SALES-1876"]);
    const sales = groups[2];
    expect(sales.covered).toBe(true);
    expect(sales.case?.owner).toBe("dmitry");
    expect(sales.isolated?.by).toBe("dmitry");
    expect(sales.items.map(i => i.eid)).toEqual(["48", "54"]);
    expect(groups[0].fresh).toBe(true);
    // The table and Take next follow the host order.
    expect(flattenGroups(groups)[0].eid).toBe("83");
  });

  it("a log added to the case leaves the queue and shows under the case", () => {
    const { events } = sdema();
    const withAttach = [...events, ev("evidence.pinned", "aviv", "t1", { event_id: "48", case_event_id: "33", label: "inv.exe downloaded" })];
    expect(attachedLogs(withAttach).get("48")).toMatchObject({ by: "aviv", caseEid: "33" });
    expect(attachedByCase(withAttach).get("33")?.map(a => a.eid)).toEqual(["48"]);
    // A Tier-2 pin with no case_event_id is not an add-to-case.
    expect(attachedLogs([...events, ev("evidence.pinned", "dmitry", "t2", { event_id: "33", label: "x" })]).size).toBe(0);
  });
});
