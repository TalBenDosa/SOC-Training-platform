// Stage D (T3 interface spec): the Tier-3's verdict reaches the SOC Manager as a decision, a missed
// update becomes a manager card, and an early containment that missed a host is told in the report.
import { describe, expect, it } from "vitest";
import type { Ev, RosterMember } from "@/lib/team/types";
import { buildMgrState, type Member } from "./manager/state";
import { CARD_BY_ID } from "./manager/cards";
import { computeReport } from "./report/computeReport";

const T0 = Date.parse("2026-11-16T22:00:00.000Z");
const at = (min: number) => new Date(T0 + min * 60_000).toISOString();
let seq = 0;
const ev = (type: string, min: number, payload: Record<string, unknown> = {}, actor: string | null = null, role: string | null = null): Ev =>
  ({ seq: ++seq, type, actor_id: actor, role, payload, occurred_at: at(min) });
const ROSTER: Member[] = [
  { user_id: "u-t2", role: "t2", status: "joined", name: "Dana" },
  { user_id: "u-t3", role: "t3", status: "joined", name: "Lior" },
  { user_id: "u-mgr", role: "mgr", status: "joined", name: "Noam" },
];
const state = (events: Ev[], nowMin: number) => buildMgrState({ events, roster: ROSTER, nowMs: T0 + nowMin * 60_000, difficulty: "hard" });

describe("stage D: Tier-3 NOT READY reaches the manager", () => {
  it("a NOT READY after a pending host isolation raises isolate_or_wait with both sides quoted", () => {
    const events = [
      ev("isolation.requested", 5, { host: "WS-FIN-2847", reason: "beaconing to 193.106.191.42" }, "u-t2", "t2"),
      ev("t3.readiness", 6, { verdict: "not_ready", reason: "WS-FIN-2851 still suspected" }, "u-t3", "t3"),
    ];
    const ctx = CARD_BY_ID.get("isolate_or_wait")!.when(state(events, 7));
    expect(ctx).toMatchObject({ target: "WS-FIN-2847", requester: "Dana", objector: "Lior", objection: "WS-FIN-2851 still suspected" });
  });
  it("a READY verdict, or a NOT READY signed before the request, raises nothing", () => {
    expect(CARD_BY_ID.get("isolate_or_wait")!.when(state([
      ev("isolation.requested", 5, { host: "WS-1", reason: "x" }, "u-t2", "t2"),
      ev("t3.readiness", 6, { verdict: "ready", reason: "scope complete" }, "u-t3", "t3"),
    ], 7))).toBeNull();
    expect(CARD_BY_ID.get("isolate_or_wait")!.when(state([
      ev("t3.readiness", 4, { verdict: "not_ready", reason: "old" }, "u-t3", "t3"),
      ev("isolation.requested", 5, { host: "WS-1", reason: "x" }, "u-t2", "t2"),
    ], 7))).toBeNull();
  });
  it("a NOT READY also objects to a pending containment request", () => {
    const events = [
      ev("containment.requested", 5, { event_id: "e1", target: "j.cohen", containment_type: "disable_account", reason: "token theft" }, "u-t2", "t2"),
      ev("t3.readiness", 6, { verdict: "not_ready", reason: "two hosts not swept" }, "u-t3", "t3"),
    ];
    expect(state(events, 7).containments[0].advice).toMatchObject([{ by: "u-t3", stance: "object", via: "readiness" }]);
  });
});

describe("stage D: a missed forensic update", () => {
  it("raises a card 2 minutes after the promised time, not before", () => {
    const events = [ev("forensic.report", 10, { next_update_min: 15, summary: "s" }, "u-t3", "t3")];
    const card = CARD_BY_ID.get("t3_update_overdue")!;
    expect(card.when(state(events, 26))).toBeNull();
    expect(card.when(state(events, 28))).toMatchObject({ who: "Lior", due: "22:25" });
    expect(card.when(state([...events, ev("forensic.report", 27, { next_update_min: 15 }, "u-t3", "t3")], 28))).toBeNull();
  });
});

describe("stage D: the report says when the attacker came back", () => {
  it("names the host the attacker returned from", () => {
    const roster: RosterMember[] = [{ user_id: "instr", role: "instructor", status: "ready", name: "i", handle: null }];
    const events = [
      ev("session.started", 0, {}, "instr"),
      ev("feed.event", 2, { id: "f1", hostname: "WS-1", expected_verdict: "tp" }),
      ev("feed.event", 12, { id: "f1-rc", hostname: "WS-2", expected_verdict: "tp", recompromise: "ws-2" }),
    ];
    expect(computeReport(events, roster).team.recompromise).toMatchObject({ host: "WS-2", atS: 720 });
    expect(computeReport(events.slice(0, 2), roster).team.recompromise).toBeNull();
  });
});
