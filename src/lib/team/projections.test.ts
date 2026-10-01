import { describe, it, expect } from "vitest";
import { activeClaims, openLoadByUser, CLAIM_TTL_MS, escalationStates, isOpenEscalation, containmentRequests, incidentByEvent, incidentLabels, scopeByIncident, latestScope, isolationState } from "./projections";
import { actionErrorCode, friendlyActionError } from "./format";
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

describe("escalation state machine — rounds, take-over, bounce (2026-09-27 fix round)", () => {
  const log: Ev[] = [
    ev(1, "escalation.requested", "t1a", { event_id: "x", summary: "first" }, 0),
    ev(2, "escalation.bounced", "t2", { event_id: "x", reason: "Needs more context" }, 10),
    ev(3, "escalation.requested", "t1a", { event_id: "y", summary: "y" }, 20),
    ev(4, "escalation.acknowledged", "t2", { event_id: "y" }, 30),
    ev(5, "escalation.acknowledged", "t3", { event_id: "y" }, 35),               // no take-over → t2 keeps it
    ev(6, "escalation.acknowledged", "t3", { event_id: "y", takeover: true }, 40), // explicit take-over
  ];
  it("a bounced escalation is not open; a re-escalation opens a fresh round", () => {
    const st = escalationStates(log);
    expect(st.get("x")!.bounced).toBe(true);
    expect(isOpenEscalation(st.get("x")!)).toBe(false);
    expect(st.get("x")!.bounceReason).toBe("Needs more context");
    const again = escalationStates([...log, ev(7, "escalation.requested", "t1a", { event_id: "x", summary: "second" }, 50)]).get("x")!;
    expect(again.rounds).toBe(2);
    expect(isOpenEscalation(again)).toBe(true);
    expect((again.request.payload as { summary: string }).summary).toBe("second");
  });
  it("ownership moves only on an explicit take-over", () => {
    expect(escalationStates(log.slice(0, 5)).get("y")!.owner).toBe("t2");
    expect(escalationStates(log).get("y")!.owner).toBe("t3");
    const load = openLoadByUser(log, T0 + 60_000);
    expect(load.get("t3")).toBe(1);
    expect(load.get("t2")).toBeUndefined();
  });
});

describe("containment requests — keyed by request, re-request after deny", () => {
  const log: Ev[] = [
    ev(1, "containment.requested", "t2", { event_id: "c", target: "WS-FIN-2847" }, 0),
    ev(2, "containment.denied", "mgr", { event_id: "c", reason: "wrong host" }, 10),
    ev(3, "containment.requested", "t2", { event_id: "c", target: "s.katz", incident: "INC-C" }, 20),
    ev(4, "containment.approved", "mgr", { event_id: "c" }, 30),
    ev(5, "containment.executed", "t2", { event_id: "c", target: "s.katz" }, 40),
    ev(6, "containment.requested", "t2", { event_id: "d", target: "WS-OPS-2214" }, 50),
  ];
  it("tracks each request's own status", () => {
    const r = containmentRequests(log);
    expect(r.map(x => [x.seq, x.status])).toEqual([[1, "denied"], [3, "executed"], [6, "pending"]]);
    expect(r[0].decisionReason).toBe("wrong host");
  });
  it("a decision naming request_seq hits that request", () => {
    const r = containmentRequests([ev(1, "containment.requested", "t2", { event_id: "c" }, 0), ev(2, "containment.requested", "t2", { event_id: "c" }, 5), ev(3, "containment.denied", "mgr", { event_id: "c", request_seq: 1 }, 9)]);
    expect(r.map(x => x.status)).toEqual(["denied", "pending"]);
  });
  it("matches a decision by target (server rule), a bare legacy decision covers every waiting request", () => {
    const two = [ev(1, "containment.requested", "t2", { event_id: "c", target: "A" }, 0), ev(2, "containment.requested", "t2", { event_id: "c", target: "B" }, 5)];
    expect(containmentRequests([...two, ev(3, "containment.approved", "mgr", { event_id: "c", target: "A" }, 9)]).map(x => x.status)).toEqual(["approved", "pending"]);
    expect(containmentRequests([...two, ev(3, "containment.denied", "mgr", { event_id: "c", reason: "no" }, 9)]).map(x => x.status)).toEqual(["denied", "denied"]);
  });
  it("claims follow the server rule — the latest claim/disposition/release/escalation decides", () => {
    const log = [ev(1, "alert.claimed", "a", { event_id: "k" }, 0), ev(2, "disposition.set", "a", { event_id: "k", verdict: "true_positive" }, 5), ev(3, "alert.claimed", "a", { event_id: "k" }, 6)];
    expect(activeClaims(log, T0 + 10_000).get("k")?.by).toBe("a");
    expect(activeClaims([...log, ev(4, "escalation.requested", "a", { event_id: "k" }, 9)], T0 + 10_000).has("k")).toBe(false);
  });
});

describe("incidents + per-incident scope", () => {
  const log: Ev[] = [
    ev(1, "scope.set", "t2", { hosts: ["WS-1"], users: [], techniques: [] }, 0),
    ev(2, "scope.confirmed", "t3", { hosts: ["WS-1"], users: [], techniques: [] }, 5),
    ev(3, "scope.set", "t2", { hosts: ["WS-1", "WS-2"], users: [], techniques: [] }, 10),
    ev(4, "scope.set", "t2", { hosts: ["DC01"], users: ["s.katz"], techniques: ["T1098"], incident: "INC-C" }, 15),
    ev(5, "report.submitted", "t2", { event_id: "e9", incident: "INC-C" }, 20),
    ev(6, "hunt.logged", "t3", { event_id: "e7", incident: " INC-B ", hypothesis: "h" }, 25),
  ];
  it("confirmed is not sticky — a later scope.set reopens it", () => {
    const m = scopeByIncident(log);
    expect(m.get("")!.confirmed).toBe(false);
    expect(m.get("")!.hosts).toEqual(["WS-1", "WS-2"]);
    expect(m.get("INC-C")!.users).toEqual(["s.katz"]);
    expect(latestScope(log)!.seq).toBe(4);
  });
  it("maps logs to incident labels, unlabelled stays ungrouped", () => {
    const m = incidentByEvent(log);
    expect(m.get("e9")).toBe("INC-C");
    expect(m.get("e7")).toBe("INC-B");
    expect(incidentLabels(log)).toEqual(["INC-C", "INC-B"]);
  });
});

describe("server rejection codes → friendly text", () => {
  it("extracts the code from a raw RPC message", () => {
    expect(actionErrorCode("claim_held")).toBe("claim_held");
    expect(actionErrorCode("P0001: case_owned")).toBe("case_owned");
    expect(actionErrorCode("already_escalated: e123")).toBe("already_escalated");
    expect(actionErrorCode("boom")).toBeNull();
  });
  it("every contract-2 code has its own actionable text", () => {
    const codes = ["claim_held", "case_owned", "already_escalated", "unknown_event: e1", "not_escalated: e1", "invalid_payload: summary", "ticket_answered", "no_pending_request", "not_approved"];
    const texts = codes.map(friendlyActionError);
    expect(new Set(texts).size).toBe(codes.length);
    for (const t of texts) expect(t).not.toMatch(/Check your connection/);
    expect(friendlyActionError("invalid_payload: summary")).toMatch(/summary/);
  });
  it("a deleted session says so (E-21)", () => {
    expect(actionErrorCode("P0001: no_such_session")).toBe("no_such_session");
    expect(friendlyActionError("no_such_session")).toMatch(/no longer exists/);
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

describe("isolationState (EDR host isolation, 0082)", () => {
  it("the latest isolate / release per host decides; host names are case-insensitive", () => {
    const ev = (seq: number, type: string, host: string, actor = "u1"): Ev => ({ seq, type, actor_id: actor, role: "t2", payload: { host }, occurred_at: `2026-10-01T09:00:${String(seq).padStart(2, "0")}Z` });
    const s = isolationState([
      ev(1, "edr.host_isolated", "WS-FIN-2847"), ev(2, "edr.host_isolated", "SRV-DB-01", "u2"),
      ev(3, "edr.host_released", "ws-fin-2847"), ev(4, "message.sent", "x"),
    ]);
    expect(s.get("ws-fin-2847")?.isolated).toBe(false);
    expect(s.get("srv-db-01")).toMatchObject({ isolated: true, by: "u2", host: "SRV-DB-01" });
    expect(s.size).toBe(2);
  });
});
