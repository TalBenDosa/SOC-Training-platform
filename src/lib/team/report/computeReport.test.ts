/**
 * computeReport — the Team-SOC after-action report, derived entirely from the
 * session event log. It was extracted verbatim from the live-room page
 * (src/app/(app)/team/[id]/page.tsx) into this server-safe module, so it can
 * later be computed server-side (and trusted) instead of in the browser.
 *
 * Two layers of protection:
 *  1. Characterization — a real (anonymized) ended session is snapshotted, so
 *     ANY behavioural drift in the scoring shows up as a snapshot diff.
 *  2. Unit fixtures — small synthetic logs pin the individual rules that are
 *     easy to break silently: no-fault self-correction, contested verdicts,
 *     curveball (inject) pairing, backup take-overs, loop closure and MTTR.
 */
import { describe, it, expect } from "vitest";
import endedSession from "./__fixtures__/ended-session.json";
import { computeReport } from "./computeReport";
import type { Ev, RosterMember } from "@/lib/team/types";

// ── helpers ──────────────────────────────────────────────────────────────────
const T0 = Date.parse("2026-09-01T10:00:00.000Z");
const at = (sec: number) => new Date(T0 + sec * 1000).toISOString();

function member(user_id: string, role: string): RosterMember {
  return { user_id, role, status: "ready", name: `User ${user_id}`, handle: null };
}

/** Builds an ordered event log; seq is assigned in call order. */
function log() {
  const events: Ev[] = [];
  const add = (type: string, actor_id: string | null, sec: number, payload: Record<string, unknown> = {}, role: string | null = null) => {
    events.push({ seq: events.length + 1, type, actor_id, role, payload, occurred_at: at(sec) });
    return api;
  };
  const api = { events, add };
  add("session.started", "instr", 0);
  return api;
}

const cell = (rubric: { label: string; score: number | null }[], label: string) => {
  const c = rubric.find(r => r.label === label);
  if (!c) throw new Error(`rubric cell "${label}" not found in [${rubric.map(r => r.label).join(", ")}]`);
  return c;
};

// ── 1. characterization ─────────────────────────────────────────────────────
describe("computeReport — characterization (real ended session)", () => {
  it("produces the same report as before the extraction", () => {
    const { events, roster } = endedSession as unknown as { events: Ev[]; roster: RosterMember[] };
    expect(events.length).toBeGreaterThan(0);
    expect(computeReport(events, roster)).toMatchSnapshot();
  });
});

// ── 2. unit fixtures ─────────────────────────────────────────────────────────
describe("computeReport — self-correction (no-fault)", () => {
  it("a wrong→right correction keeps accuracy at 100 and scores the Self-correction cell", () => {
    const { events, add } = log();
    add("feed.event", null, 1, { id: "atk-1", expected_verdict: "tp", severity: "high" });
    add("feed.event", null, 2, { id: "noise-1", expected_verdict: "benign", severity: "low" });
    add("disposition.set", "a", 30, { event_id: "atk-1", verdict: "benign" }, "t1");
    add("disposition.set", "a", 60, { event_id: "atk-1", verdict: "true_positive" }, "t1");
    add("disposition.set", "b", 40, { event_id: "noise-1", verdict: "benign" }, "t1");
    const { perUser } = computeReport(events, [member("instr", "instructor"), member("a", "t1"), member("b", "t1")]);

    const a = perUser.find(u => u.user_id === "a")!;
    expect(a.dispAcc).toBe(100);
    expect(a.dispCount).toBe(2);
    expect(cell(a.rubric, "Self-correction").score).not.toBeNull();
    expect(cell(a.rubric, "Self-correction").score).toBe(8); // bandHigh(1, 2, 1, 1)

    const b = perUser.find(u => u.user_id === "b")!;
    expect(b.dispAcc).toBe(100);
    expect(cell(b.rubric, "Self-correction").score).toBeNull();
  });

  it("excludes instructors/observers from perUser", () => {
    const { events } = log();
    const { perUser } = computeReport(events, [member("instr", "instructor"), member("obs", "observer"), member("a", "t1")]);
    expect(perUser.map(u => u.user_id)).toEqual(["a"]);
  });
});

describe("computeReport — contested verdicts", () => {
  it("two analysts with opposite verdict classes on one event ⇒ contested === 1", () => {
    const { events, add } = log();
    add("feed.event", null, 1, { id: "evt-1", expected_verdict: "tp", description: "Suspicious PowerShell" });
    add("disposition.set", "a", 20, { event_id: "evt-1", verdict: "true_positive" }, "t1");
    add("disposition.set", "b", 25, { event_id: "evt-1", verdict: "benign" }, "t1");
    const { team } = computeReport(events, [member("a", "t1"), member("b", "t1")]);
    expect(team.contested).toBe(1);
    expect(team.contestedList[0].eid).toBe("evt-1");
    expect(team.contestedList[0].label).toBe("Suspicious PowerShell");
  });

  it("agreeing verdicts are not contested", () => {
    const { events, add } = log();
    add("feed.event", null, 1, { id: "evt-1", expected_verdict: "benign" });
    add("disposition.set", "a", 20, { event_id: "evt-1", verdict: "false_positive" }, "t1");
    add("disposition.set", "b", 25, { event_id: "evt-1", verdict: "benign" }, "t1");
    expect(computeReport(events, [member("a", "t1"), member("b", "t1")]).team.contested).toBe(0);
  });
});

describe("computeReport — curveballs (evaluable injects)", () => {
  const inj = (kind: string) => ({ kind, text: `${kind} text`, expected_response: "respond", linked_objective: "obj" });

  it("twist + scope.set within 15 min ⇒ handled & scored", () => {
    const { events, add } = log();
    add("staff.inject", "instr", 60, inj("twist"));
    add("scope.set", "t2", 60 + 5 * 60, { hosts: ["WS-1"] }, "t2");
    const [r] = computeReport(events, [member("t2", "t2")]).team.injects;
    expect(r).toMatchObject({ kind: "twist", scored: true, handled: true, decoy: false });
  });

  it("twist with the response AFTER the 15-min window ⇒ scored but not handled", () => {
    const { events, add } = log();
    add("staff.inject", "instr", 60, inj("twist"));
    add("scope.set", "t2", 60 + 16 * 60, { hosts: ["WS-1"] }, "t2");
    const [r] = computeReport(events, [member("t2", "t2")]).team.injects;
    expect(r).toMatchObject({ scored: true, handled: false });
  });

  it("false_lead ⇒ decoy, not scored", () => {
    const { events, add } = log();
    add("staff.inject", "instr", 60, inj("false_lead"));
    const { team } = computeReport(events, []);
    expect(team.injects[0]).toMatchObject({ kind: "false_lead", decoy: true, scored: false });
    expect(team.injectsScored).toBe(0);
  });

  it("mgmt_pressure + a later sitrep.sent ⇒ handled", () => {
    const { events, add } = log();
    add("staff.inject", "instr", 60, inj("mgmt_pressure"));
    add("sitrep.sent", "mgr", 120, { text: "status" }, "mgr");
    const { team } = computeReport(events, [member("mgr", "mgr")]);
    expect(team.injects[0]).toMatchObject({ kind: "mgmt_pressure", scored: true, handled: true });
    expect(team.injectsHandled).toBe(1);
  });

  it("ticket + ticket.answered ⇒ handled", () => {
    const { events, add } = log();
    add("staff.inject", "instr", 60, inj("ticket"));
    add("ticket.answered", "a", 200, {}, "t1");
    const { team } = computeReport(events, [member("a", "t1")]);
    expect(team.injects[0]).toMatchObject({ kind: "ticket", scored: true, handled: true });
  });

  it("one SITREP answers only one inject (one-to-one pairing)", () => {
    const { events, add } = log();
    add("staff.inject", "instr", 60, inj("mgmt_pressure"));
    add("staff.inject", "instr", 70, inj("mgmt_pressure"));
    add("sitrep.sent", "mgr", 120, {}, "mgr");
    const { team } = computeReport(events, [member("mgr", "mgr")]);
    expect(team.injectsScored).toBe(2);
    expect(team.injectsHandled).toBe(1);
  });
});

describe("computeReport — backup take-over", () => {
  it("B claiming an alert A currently holds scores B's Backup & load-balancing cell", () => {
    const { events, add } = log();
    add("feed.event", null, 1, { id: "evt-1", expected_verdict: "tp" });
    add("alert.claimed", "a", 10, { event_id: "evt-1" }, "t1");
    add("alert.claimed", "b", 20, { event_id: "evt-1" }, "t1");
    const { perUser } = computeReport(events, [member("a", "t1"), member("b", "t1")]);
    const a = perUser.find(u => u.user_id === "a")!;
    const b = perUser.find(u => u.user_id === "b")!;
    expect(cell(b.rubric, "Backup & load-balancing").score).toBe(8); // bandHigh(1, 2, 1, 1)
    expect(cell(a.rubric, "Backup & load-balancing").score).toBeNull();
  });

  it("claiming an alert nobody holds is not a take-over", () => {
    const { events, add } = log();
    add("alert.claimed", "a", 10, { event_id: "evt-1" }, "t1");
    add("alert.released", "a", 15, { event_id: "evt-1" }, "t1");
    add("alert.claimed", "b", 20, { event_id: "evt-1" }, "t1");
    const b = computeReport(events, [member("a", "t1"), member("b", "t1")]).perUser.find(u => u.user_id === "b")!;
    expect(cell(b.rubric, "Backup & load-balancing").score).toBeNull();
  });

  it("A3: claiming an alert whose claim went stale (> 5 min) is not a take-over", () => {
    const { events, add } = log();
    add("alert.claimed", "a", 10, { event_id: "evt-1" }, "t1");
    add("alert.claimed", "b", 10 + 6 * 60, { event_id: "evt-1" }, "t1");
    const b = computeReport(events, [member("a", "t1"), member("b", "t1")]).perUser.find(u => u.user_id === "b")!;
    expect(cell(b.rubric, "Backup & load-balancing").score).toBeNull();
  });

  it("A3: stale claims stop counting toward overload, matching the live Situation Board", () => {
    const { events, add } = log();
    // A grabs 3 alerts, then goes quiet; 6 minutes later the board shows A at 0 open.
    for (const id of ["e1", "e2", "e3"]) add("alert.claimed", "a", 10, { event_id: id }, "t1");
    add("coordination.nudge", "mgr", 20, { target: "a" }, "mgr");
    const fresh = computeReport(events, [member("a", "t1"), member("mgr", "mgr")]).perUser.find(u => u.user_id === "mgr")!;
    expect(cell(fresh.rubric, "Load balancing").score).not.toBeNull();

    const { events: ev2, add: add2 } = log();
    add2("alert.claimed", "a", 10, { event_id: "e1" }, "t1");
    add2("alert.claimed", "a", 10 + 6 * 60, { event_id: "e2" }, "t1");
    add2("alert.claimed", "a", 10 + 12 * 60, { event_id: "e3" }, "t1");
    const stale = computeReport(ev2, [member("a", "t1"), member("mgr", "mgr")]).perUser.find(u => u.user_id === "mgr")!;
    expect(cell(stale.rubric, "Load balancing").score).toBeNull(); // A never held 3 at once
  });
});

describe("computeReport — handoff loop closure & MTTR", () => {
  it("2 escalations, 1 acknowledged ⇒ loopClosure === 50", () => {
    const { events, add } = log();
    add("escalation.requested", "a", 30, { event_id: "e1", summary: "s" }, "t1");
    add("escalation.requested", "a", 40, { event_id: "e2", summary: "s" }, "t1");
    add("escalation.acknowledged", "t2", 90, { event_id: "e1" }, "t2");
    const { team } = computeReport(events, [member("a", "t1"), member("t2", "t2")]);
    expect(team.escalations).toBe(2);
    expect(team.acknowledged).toBe(1);
    expect(team.loopClosure).toBe(50);
    expect(team.handoffLatS).toBe(60);
  });

  it("no escalations ⇒ loopClosure is null", () => {
    expect(computeReport(log().events, []).team.loopClosure).toBeNull();
  });

  it("escalation at t and escalation.resolved at t+120s ⇒ mttrS === 120", () => {
    const { events, add } = log();
    add("escalation.requested", "a", 100, { event_id: "e1" }, "t1");
    add("escalation.acknowledged", "t2", 130, { event_id: "e1" }, "t2");
    add("escalation.resolved", "t2", 220, { event_id: "e1" }, "t2");
    const { team } = computeReport(events, [member("a", "t1"), member("t2", "t2")]);
    expect(team.mttrS).toBe(120);
  });
});
