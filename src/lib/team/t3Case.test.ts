import { describe, it, expect } from "vitest";
import type { Ev } from "./types";
import { buildRegister, indicatorKind, nextStep, readinessBlockers, reportDraft, scansOf, stateChangeProblem, sweepFeed, updateDueMs } from "./t3Case";

let seq = 0;
const at = (min: number) => new Date(Date.UTC(2026, 10, 16, 22, min)).toISOString();
const ev = (type: string, payload: Record<string, unknown>, min = 0, actor = "t3a"): Ev => ({ seq: ++seq, type, actor_id: actor, role: "t3", payload, occurred_at: at(min) });
const feedRow = (host: string, extra: Record<string, unknown>, min = 0): Ev => ({ seq: ++seq, type: "feed.event", actor_id: null, role: null, payload: { id: `f${seq}`, hostname: host, ...extra }, occurred_at: at(min) });

describe("t3Case: sweeps", () => {
  it("recognises indicator kinds", () => {
    expect(indicatorKind("193.106.191.42")).toBe("ip");
    expect(indicatorKind("a".repeat(64))).toBe("hash");
    expect(indicatorKind("evil-cdn.example")).toBe("domain");
    expect(indicatorKind("updater.exe")).toBe("process");
    expect(indicatorKind("CORP\\j.cohen")).toBe("account");
    expect(indicatorKind("beacon")).toBe("text");
  });

  it("finds every host whose logs mention the indicator, most hits first", () => {
    const feed = [
      feedRow("WS-FIN-2847.corp.local", { dst_ip: "193.106.191.42" }, 1),
      feedRow("WS-FIN-2847", { dst_ip: "193.106.191.42" }, 3),
      feedRow("SRV-FS-02", { raw: "connect 193.106.191.42:443" }, 2),
      feedRow("WS-HR-1", { dst_ip: "8.8.8.8" }, 2),
      { ...feedRow("", { src_ip: "193.106.191.42" }, 4) },
    ];
    const r = sweepFeed(feed, " 193.106.191.42 ");
    expect(r.rows).toBe(4);
    expect(r.hosts.map(h => [h.host, h.count])).toEqual([["WS-FIN-2847.corp.local", 2], ["SRV-FS-02", 1]]);
    expect(sweepFeed(feed, "19").hosts).toEqual([]);
  });
});

describe("t3Case: register", () => {
  it("keeps the latest state per entity and turns host_status findings into states", () => {
    const events = [
      ev("t3.scope.entity", { entity: "WS-FIN-2847", entity_kind: "host", state: "suspected" }, 1),
      ev("forensic.finding", { kind: "host_status", host: "ws-fin-2847.corp.local", status: "compromised", confidence: "high", summary: "beacon" }, 2),
      ev("t3.scope.entity", { entity: "j.cohen", entity_kind: "account", state: "confirmed", cites: [5] }, 3),
      ev("t3.scope.entity", { entity: "SRV-FS-02", state: "suspected" }, 4),
      ev("t3.scope.entity", { entity: "SRV-FS-02", state: "removed" }, 5),
      ev("forensic.finding", { kind: "c2", host: "WS-HR-1", summary: "x" }, 6),
    ];
    const reg = buildRegister(events);
    expect(reg.map(r => [r.entity, r.kind, r.state, r.source])).toEqual([
      ["WS-FIN-2847", "host", "confirmed", "finding"],
      ["j.cohen", "account", "confirmed", "register"],
    ]);
    expect(reg[0].cites).toEqual([events[1].seq]);
  });

  it("demands evidence to confirm or clear", () => {
    expect(stateChangeProblem("confirmed", [], "")).toMatch(/evidence/);
    expect(stateChangeProblem("confirmed", [3], "")).toBeNull();
    expect(stateChangeProblem("cleared", [], "admin")).toMatch(/10 characters/);
    expect(stateChangeProblem("cleared", [], "change ticket CHG-1042")).toBeNull();
    expect(stateChangeProblem("cannot_check", [], "")).toMatch(/why/);
    expect(stateChangeProblem("suspected", [], "")).toBeNull();
  });
});

describe("t3Case: readiness and next step", () => {
  it("walks the loop: hand-off, collect, sweep, resolve, sign", () => {
    expect(nextStep([], { pendingHandoffs: 1 }).target).toBe("inbox");
    const e: Ev[] = [ev("t3.scope.entity", { entity: "WS-1", state: "confirmed", cites: [1] }, 1)];
    expect(nextStep(e)).toMatchObject({ phase: "collecting", target: "evidence", host: "WS-1" });
    e.push(ev("forensic.collected", { host: "ws-1", kind: "memory", evidence_id: "MEM-001" }, 2));
    expect(nextStep(e).text).toMatch(/Sweep/);
    const scan = ev("t3.scan", { indicator: "1.2.3.4", kind: "ip", hosts: [{ host: "WS-1", count: 3 }, { host: "WS-2", count: 1 }], rows: 4 }, 3);
    e.push(scan, ev("t3.scope.entity", { entity: "WS-2", state: "suspected", cites: [scan.seq] }, 3));
    expect(nextStep(e).text).toMatch(/Resolve 1 suspected entity/);
    expect(readinessBlockers(e).map(b => b.id)).toContain("sus:ws-2");
    e.push(ev("t3.scope.entity", { entity: "WS-2", state: "cleared", reason: "patch server, change ticket CHG-77" }, 4));
    expect(nextStep(e)).toMatchObject({ phase: "verdict", target: "readiness" });
    e.push(ev("t3.readiness", { verdict: "ready", blockers: [], reason: "scope confirmed" }, 5));
    expect(nextStep(e).phase).toBe("signed");
    // A new suspect after signing re-opens the case.
    e.push(ev("t3.scope.entity", { entity: "WS-3", state: "suspected" }, 6));
    expect(nextStep(e).phase).toBe("scoping");
  });

  it("drafts the manager report from the register and knows when the next update is due", () => {
    const e: Ev[] = [
      ev("t3.scope.entity", { entity: "WS-1", state: "confirmed", cites: [1] }, 1),
      ev("t3.scope.entity", { entity: "WS-9", state: "cannot_check", reason: "no EDR" }, 1),
      ev("t3.scan", { indicator: "evil.example", hosts: [] }, 2),
      ev("forensic.report", { next_update_min: 15 }, 10),
    ];
    const d = reportDraft(e);
    expect(d.summary).toMatch(/Confirmed compromised: WS-1/);
    expect(d.summary).toMatch(/Cannot check: WS-9/);
    expect(scansOf(e)[0].kind).toBe("domain");
    expect(updateDueMs(e)).toBe(Date.parse(at(10)) + 15 * 60_000);
    expect(updateDueMs(e, "someone-else")).toBeNull();
  });
});
