// 2026-10-18 review: no ticket, decoy or management request was handled in four exercises.
// Each player's Action-required box lists exactly what is waiting for THEM; the report scores the answers.
import { describe, it, expect } from "vitest";
import { actionInbox } from "./actionInbox";
import { computeReport } from "./report/computeReport";
import type { Ev } from "./types";

const inj = (seq: number, kind: string, text = "x"): Ev => ({ seq, type: "staff.inject", actor_id: null, role: null, payload: { kind, text, inject_id: `i${seq}` } });
const resp = (seq: number, actor: string, role: string, inject_seq: number, decision: string, ts = "2026-10-18T10:05:00Z"): Ev =>
  ({ seq, type: "inject.responded", actor_id: actor, role, payload: { inject_seq, decision, note: "checked the approved list" }, occurred_at: ts });

describe("actionInbox", () => {
  const events = [inj(1, "ticket"), inj(2, "update"), inj(3, "mgmt_request")];
  const noMgr = [{ role: "t1", status: "ready" }, { role: "t2", status: "ready" }];
  const withMgr = [...noMgr, { role: "mgr", status: "ready" }];

  it("routes tickets to Tier-1, updates to every analyst, a management request to Tier-2 only without a Manager", () => {
    expect(actionInbox(events, { id: "a", role: "t1" }, noMgr).map(i => i.kind)).toEqual(["ticket", "update"]);
    expect(actionInbox(events, { id: "b", role: "t2" }, noMgr).map(i => i.kind)).toEqual(["update", "mgmt"]);
    expect(actionInbox(events, { id: "b", role: "t2" }, withMgr).map(i => i.kind)).toEqual(["update"]);
    expect(actionInbox(events, { id: "m", role: "mgr" }, withMgr)).toEqual([]);
    expect(actionInbox(events, { id: "c", role: "t3" }, [{ role: "t1", status: "ready" }, { role: "t3", status: "ready" }]).map(i => i.kind)).toEqual(["update", "mgmt"]);
  });

  it("an update stays until THIS player made a call; a ticket / request leaves once anyone answered", () => {
    const answered = [...events, resp(4, "b", "t2", 2, "benign"), { seq: 5, type: "ticket.answered", actor_id: "a2", role: "t1", payload: { ticket_seq: 1, decision: "rejected" } } as Ev, resp(6, "b", "t2", 3, "status")];
    expect(actionInbox(answered, { id: "a", role: "t1" }, noMgr).map(i => i.kind)).toEqual(["update"]);
    expect(actionInbox(answered, { id: "b", role: "t2" }, noMgr)).toEqual([]);
  });
});

describe("report: inject answers", () => {
  const roster = [{ user_id: "a", role: "t1", name: "A" }, { user_id: "b", role: "t2", name: "B" }];
  const at = (seq: number, e: Ev): Ev => ({ ...e, occurred_at: `2026-10-18T10:0${seq}:00Z` });
  const base: Ev[] = [
    { seq: 0, type: "session.started", actor_id: null, role: null, payload: {}, occurred_at: "2026-10-18T10:00:00Z" },
    at(1, inj(1, "false_lead")), at(1, inj(2, "twist")), at(1, inj(3, "mgmt_pressure")),
  ];
  const injectsOf = (evs: Ev[]) => computeReport(evs, roster as never).team.injects;

  it("a decoy answered 'not an incident' is handled; answered 'real' is chased", () => {
    const ok = injectsOf([...base, resp(10, "a", "t1", 1, "benign", "2026-10-18T10:03:00Z")]).find(i => i.kind === "false_lead")!;
    expect(ok).toMatchObject({ scored: true, handled: true });
    const bad = injectsOf([...base, resp(10, "a", "t1", 1, "investigate", "2026-10-18T10:03:00Z")]).find(i => i.kind === "false_lead")!;
    expect(bad).toMatchObject({ scored: true, handled: false });
    expect(bad.note).toMatch(/treated the decoy as real/);
  });

  it("a twist answered as a change to the case is handled", () => {
    expect(injectsOf([...base, resp(10, "b", "t2", 2, "rescope", "2026-10-18T10:04:00Z")]).find(i => i.kind === "twist")).toMatchObject({ scored: true, handled: true });
  });

  it("with no Manager, Tier-2's status answer handles the management request", () => {
    expect(injectsOf([...base, resp(10, "b", "t2", 3, "status", "2026-10-18T10:06:00Z")]).find(i => i.kind === "mgmt_pressure")).toMatchObject({ scored: true, handled: true });
    expect(injectsOf(base).find(i => i.kind === "mgmt_pressure")).toMatchObject({ scored: true, handled: false });
  });
});
