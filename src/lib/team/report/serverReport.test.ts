import { describe, it, expect } from "vitest";
import { mergeAnswers, publicAnswers, clicksAsEvents, pageAll } from "./serverReport";
import { computeReport } from "./computeReport";
import type { Ev, RosterMember } from "@/lib/team/types";

const T0 = Date.parse("2026-01-01T10:00:00Z");
const at = (s: number) => new Date(T0 + s * 1000).toISOString();

describe("serverReport — joining the answer key after the shift", () => {
  it("publicAnswers keeps only reveal-safe keys per channel", () => {
    const a = publicAnswers([
      { id: "i1", channel: "feed", expected_action: { expected_verdict: "tp", fp_explanation: null, original_id: "aitm_02", incident_id: "x" } },
      { id: "i2", channel: "inject", expected_action: { kind: "false_lead", expected_response: "reject", linked_objective: "accuracy", original_id: "msel_false_lead" } },
      { id: "i3", channel: "feed", expected_action: null },
    ]);
    // incident_id (per-incident detection) and the inject's original_id (curveball ↔ its
    // supporting telemetry) are now kept for scoring; a FEED log's original_id is not.
    expect(a).toEqual({ i1: { expected_verdict: "tp", incident_id: "x" }, i2: { kind: "false_lead", expected_response: "reject", linked_objective: "accuracy", original_id: "msel_false_lead" } });
  });

  it("mergeAnswers restores feed verdicts and real inject kinds; v1 / player events pass through", () => {
    const events: Ev[] = [
      { seq: 1, type: "feed.event", actor_id: null, role: null, payload: { id: "e1", inject_id: "i1" } },
      { seq: 2, type: "staff.inject", actor_id: null, role: null, payload: { id: "m1", kind: "update", inject_id: "i2" } },
      { seq: 3, type: "feed.event", actor_id: null, role: null, payload: { id: "legacy", expected_verdict: "fp" } },
      { seq: 4, type: "disposition.set", actor_id: "u", role: "t1", payload: { event_id: "e1", verdict: "true_positive", inject_id: "i1" } },
    ];
    const out = mergeAnswers(events, { i1: { expected_verdict: "tp" }, i2: { kind: "twist", expected_response: "re-scope" } });
    expect(out[0].payload).toMatchObject({ id: "e1", expected_verdict: "tp" });
    expect(out[1].payload).toMatchObject({ kind: "twist", expected_response: "re-scope" });
    expect(out[2]).toBe(events[2]);                  // legacy v1 untouched
    expect(out[3]).toBe(events[3]);                  // player actions never enriched
  });

  it("clicksAsEvents feeds computeReport's opened/dwell counts without touching the log's seqs", () => {
    const clicks = clicksAsEvents([{ user_id: "u1", event_id: "e1", dwell_ms: 5000, occurred_at: at(30) }], 10);
    expect(clicks[0]).toMatchObject({ seq: 11, type: "event.opened", actor_id: "u1", payload: { event_id: "e1", dwell_ms: 5000 } });
    const roster: RosterMember[] = [{ user_id: "u1", role: "t1", status: "ready", name: "A", handle: null }];
    const events: Ev[] = [{ seq: 1, type: "session.started", actor_id: null, role: null, payload: {}, occurred_at: at(0) }, ...clicks];
    const { perUser } = computeReport(events, roster);
    expect(perUser[0].opened).toBe(1);
    expect(perUser[0].avgDwellS).toBe(5);
  });

  it("a v2 log (no keys on the wire) scores the same as a v1 log once answers are merged", () => {
    const roster: RosterMember[] = [{ user_id: "u1", role: "t1", status: "ready", name: "A", handle: null }];
    const base = (withKey: boolean): Ev[] => [
      { seq: 1, type: "session.started", actor_id: null, role: null, payload: {}, occurred_at: at(0) },
      { seq: 2, type: "feed.event", actor_id: null, role: null, payload: { id: "e1", severity: "high", inject_id: "i1", ...(withKey ? { expected_verdict: "tp" } : {}) }, occurred_at: at(10) },
      { seq: 3, type: "disposition.set", actor_id: "u1", role: "t1", payload: { event_id: "e1", verdict: "true_positive" }, occurred_at: at(40) },
      { seq: 4, type: "escalation.requested", actor_id: "u1", role: "t1", payload: { event_id: "e1" }, occurred_at: at(50) },
    ];
    const v1 = computeReport(base(true), roster);
    const v2 = computeReport(mergeAnswers(base(false), { i1: { expected_verdict: "tp" } }), roster);
    expect(v2.team).toEqual(v1.team);
    expect(v2.perUser).toEqual(v1.perUser);
    expect(v2.team.detected).toBe(true);
  });
});

describe("serverReport — scoring keys travel with the merge", () => {
  it("mergeAnswers restores incident_id / supports_inject on feed logs and original_id on injects", () => {
    const events: Ev[] = [
      { seq: 1, type: "feed.event", actor_id: null, role: null, payload: { id: "e1", inject_id: "i1" } },
      { seq: 2, type: "staff.inject", actor_id: null, role: null, payload: { id: "m1", kind: "update", inject_id: "i2" } },
    ];
    const answers = publicAnswers([
      { id: "i1", channel: "feed", expected_action: { expected_verdict: "tp", incident_id: "inc-A", supports_inject: "msel_twist", original_id: "fbu_03" } },
      { id: "i2", channel: "inject", expected_action: { kind: "twist", expected_response: "re-scope", original_id: "msel_twist" } },
    ]);
    const out = mergeAnswers(events, answers);
    expect(out[0].payload).toMatchObject({ expected_verdict: "tp", incident_id: "inc-A", supports_inject: "msel_twist" });
    expect(out[0].payload).not.toHaveProperty("original_id");
    expect(out[1].payload).toMatchObject({ kind: "twist", original_id: "msel_twist" });
  });
});

describe("pageAll (P4-07: never a partial list)", () => {
  it("returns every page until a short page", async () => {
    const pages = [[1, 2], [3]];
    let call = 0;
    const out = await pageAll<number>(async () => ({ data: pages[call++] ?? [], error: null }), 2);
    expect(out).toEqual([1, 2, 3]);
  });
  it("throws on a read error instead of returning what it has", async () => {
    await expect(pageAll<number>(async () => ({ data: null, error: { message: "boom" } }), 2)).rejects.toThrow("boom");
  });
  it("throws when the row cap is reached instead of silently truncating", async () => {
    await expect(pageAll<number>(async () => ({ data: [1, 2], error: null }), 2, 4)).rejects.toThrow("more than 4 rows");
  });
});
