// 2026-10-18 review: Tier-3 logged one hunt in four exercises (a message to a user), took over a
// Tier-2 case and lost it straight back; the manager declared Sev-1 on a false alarm and the cards
// followed it; decisions were logged with no reason.
import { describe, it, expect } from "vitest";
import { huntProblems, starterHypotheses } from "./huntQuality";
import { takeoverAllowed, TAKEOVER_IDLE_MS } from "./projections";
import { confirmedAt } from "./manager/state";
import { actionInbox } from "./actionInbox";
import type { Ev } from "./types";

describe("hunt record", () => {
  it("rejects a message to a person and empty fields; accepts a real hunt", () => {
    expect(huntProblems({ hypothesis: "Hi n.shapiro, this is familer with it?", finding: "please confirm with the user", technique: "" })[0]).toMatch(/message to a person/);
    expect(huntProblems({ hypothesis: "short", finding: "", technique: "" }).length).toBe(2);
    expect(huntProblems({ hypothesis: "Kerberoasting of svc_sql from WS-ACC-4477", finding: "4769 with RC4 (0x17) for 6 SPNs within 2 minutes", technique: "T1558.003" })).toEqual([]);
    expect(huntProblems({ hypothesis: "Kerberoasting of svc_sql from WS-ACC-4477", finding: "4769 with RC4 (0x17) for 6 SPNs", technique: "kerberoast" })[0]).toMatch(/Technique/);
  });
  it("offers starter hypotheses, more when the org runs cloud / Linux", () => {
    expect(starterHypotheses().length).toBeGreaterThanOrEqual(5);
    expect(starterHypotheses(["aws", "linux"]).length).toBe(starterHypotheses().length + 2);
  });
});

describe("takeover rule", () => {
  it("Tier-3 takes a Tier-2 case only once elevated or the owner is quiet; Tier-2 does not take back an elevated case", () => {
    expect(takeoverAllowed({ myRole: "t3", ownerRole: "t2", elevated: false, ownerIdleMs: 60_000 }).ok).toBe(false);
    expect(takeoverAllowed({ myRole: "t3", ownerRole: "t2", elevated: true, ownerIdleMs: 60_000 }).ok).toBe(true);
    expect(takeoverAllowed({ myRole: "t3", ownerRole: "t2", elevated: false, ownerIdleMs: TAKEOVER_IDLE_MS }).ok).toBe(true);
    expect(takeoverAllowed({ myRole: "t2", ownerRole: "t3", elevated: true, ownerIdleMs: 60_000 }).ok).toBe(false);
    expect(takeoverAllowed({ myRole: "t2", ownerRole: "t2", elevated: false, ownerIdleMs: 60_000 }).ok).toBe(false);
  });
});

describe("Tier-3 Action required: elevations", () => {
  const el: Ev = { seq: 4, type: "elevation.requested", actor_id: "t2", role: "t2", payload: { event_id: "e9", summary: "external IP to DC", hunt_ask: "check ITAdmin activity" } };
  const roster = [{ role: "t2", status: "ready" }, { role: "t3", status: "ready" }];
  it("an elevation waits for Tier-3 until a hunt answers it", () => {
    expect(actionInbox([el], { id: "z", role: "t3" }, roster)).toMatchObject([{ kind: "elevation", eventId: "e9", taken: false }]);
    const taken = [el, { seq: 5, type: "elevation.acknowledged", actor_id: "z", role: "t3", payload: { event_id: "e9" } } as Ev];
    expect(actionInbox(taken, { id: "z", role: "t3" }, roster)).toMatchObject([{ kind: "elevation", taken: true }]);
    expect(actionInbox([...taken, { seq: 6, type: "hunt.logged", actor_id: "z", role: "t3", payload: { event_id: "e9" } } as Ev], { id: "z", role: "t3" }, roster)).toEqual([]);
  });
});

describe("manager: confirmation before cards", () => {
  const at = (s: number) => `2026-10-18T10:0${s}:00Z`;
  it("a Tier-1 escalation alone is not a confirmation; a Tier-2 attack report, an elevation or a Tier-2 case is", () => {
    const t1: Ev = { seq: 1, type: "escalation.requested", actor_id: "a", role: "t1", payload: {}, occurred_at: at(1) };
    expect(confirmedAt([t1])).toBeNull();
    expect(confirmedAt([t1, { seq: 2, type: "report.submitted", actor_id: "b", role: "t2", payload: { verdict: "benign" }, occurred_at: at(2) }])).toBeNull();
    expect(confirmedAt([t1, { seq: 2, type: "report.submitted", actor_id: "b", role: "t2", payload: { verdict: "true_positive" }, occurred_at: at(3) }])).toBe(Date.parse(at(3)));
    expect(confirmedAt([{ seq: 3, type: "escalation.requested", actor_id: "b", role: "t2", payload: {}, occurred_at: at(4) }])).toBe(Date.parse(at(4)));
  });
});
