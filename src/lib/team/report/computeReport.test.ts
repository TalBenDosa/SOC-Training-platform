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

  // Playtest P1: a twist with NO supporting telemetry used to count as "handled" by any
  // unrelated scope/escalation within 15 min. It is now "not evaluable" (not scored).
  it("twist WITHOUT supporting telemetry ⇒ not evaluable (not scored, not handled)", () => {
    const { events, add } = log();
    add("staff.inject", "instr", 60, inj("twist"));
    add("scope.set", "t2", 60 + 5 * 60, { hosts: ["WS-1"] }, "t2");
    const { team } = computeReport(events, [member("t2", "t2")]);
    expect(team.injects[0]).toMatchObject({ kind: "twist", scored: false, handled: false, evaluable: false, decoy: false });
    expect(team.injectsScored).toBe(0);
  });

  it("twist with supporting telemetry: a response AFTER the window ⇒ scored but not handled", () => {
    const { events, add } = log();
    add("staff.inject", "instr", 60, { ...inj("twist"), id: "msel_twist" });
    add("feed.event", null, 70, { id: "tw-1", expected_verdict: "tp", incident_id: "inc-a", supports_inject: "msel_twist", hostname: "WS-FIN-2847", network: { domain: "new-c2-sync.net" } });
    add("escalation.requested", "a", 70 + 16 * 60, { event_id: "tw-1", summary: "beacon" }, "t1");
    const [r] = computeReport(events, [member("a", "t1")]).team.injects;
    expect(r).toMatchObject({ scored: true, handled: false, evaluable: true });
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
  it("an explicit takeover ack from an overloaded same-role owner credits the backup analyst", () => {
    const { events, add } = log();
    for (const id of ["c1", "c2", "c3"]) {
      add("feed.event", null, 1, { id, expected_verdict: "tp" });
      add("escalation.requested", "t1", 5, { event_id: id, summary: "suspicious activity" }, "t1");
      add("escalation.acknowledged", "a", 10, { event_id: id }, "t2");
    }
    add("escalation.acknowledged", "b", 20, { event_id: "c3", takeover: true }, "t2");
    add("escalation.acknowledged", "b", 21, { event_id: "c2" }, "t2"); // plain second ack: no ownership change, no credit
    const { perUser } = computeReport(events, [member("t1", "t1"), member("a", "t2"), member("b", "t2")]);
    const b = perUser.find(u => u.user_id === "b")!;
    expect(cell(b.rubric, "Backup & load-balancing").score).not.toBeNull();
  });

  // Playtest P1 (t1b.md): a 5-second claim COLLISION used to score as "backup".
  it("B claiming an alert A freshly holds (A not overloaded) is a collision — no credit", () => {
    const { events, add } = log();
    add("feed.event", null, 1, { id: "evt-1", expected_verdict: "tp" });
    add("alert.claimed", "a", 10, { event_id: "evt-1" }, "t1");
    add("alert.claimed", "b", 15, { event_id: "evt-1" }, "t1");
    const { perUser } = computeReport(events, [member("a", "t1"), member("b", "t1")]);
    expect(cell(perUser.find(u => u.user_id === "b")!.rubric, "Backup & load-balancing").score).toBeNull();
    expect(cell(perUser.find(u => u.user_id === "a")!.rubric, "Backup & load-balancing").score).toBeNull();
  });

  it("B taking an alert off an OVERLOADED A (≥ OVERLOAD_CASES open) scores B's backup cell", () => {
    const { events, add } = log();
    for (const id of ["e1", "e2", "e3"]) add("alert.claimed", "a", 10, { event_id: id }, "t1");
    add("alert.claimed", "b", 30, { event_id: "e2", takeover: true }, "t1");
    const { perUser } = computeReport(events, [member("a", "t1"), member("b", "t1")]);
    expect(cell(perUser.find(u => u.user_id === "b")!.rubric, "Backup & load-balancing").score).toBe(8); // bandHigh(1, 2, 1, 1)
  });

  it("claiming an alert nobody holds is not a take-over", () => {
    const { events, add } = log();
    add("alert.claimed", "a", 10, { event_id: "evt-1" }, "t1");
    add("alert.released", "a", 15, { event_id: "evt-1" }, "t1");
    add("alert.claimed", "b", 20, { event_id: "evt-1" }, "t1");
    const b = computeReport(events, [member("a", "t1"), member("b", "t1")]).perUser.find(u => u.user_id === "b")!;
    expect(cell(b.rubric, "Backup & load-balancing").score).toBeNull();
  });

  // Fix round 2026-09-27: rescuing an ABANDONED alert (claim older than CLAIM_TTL_MS and
  // never released) IS backup — same spirit as the T2/T3 rule. (Was "not a take-over".)
  it("claiming an alert whose claim went stale (> 5 min, never released) is a rescue — credited", () => {
    const { events, add } = log();
    add("alert.claimed", "a", 10, { event_id: "evt-1" }, "t1");
    add("alert.claimed", "b", 10 + 6 * 60, { event_id: "evt-1" }, "t1");
    const b = computeReport(events, [member("a", "t1"), member("b", "t1")]).perUser.find(u => u.user_id === "b")!;
    expect(cell(b.rubric, "Backup & load-balancing").score).toBe(8);
  });

  it("A3: stale claims stop counting toward overload, matching the live Situation Board", () => {
    const { events, add } = log();
    // A grabs 3 alerts, then goes quiet; 6 minutes later the board shows A at 0 open.
    for (const id of ["e1", "e2", "e3"]) add("alert.claimed", "a", 10, { event_id: id }, "t1");
    add("coordination.nudge", "mgr", 20, { target: "a" }, "mgr");
    add("session.ended", "instr", 200); // the overload lasted ≥ OVERLOAD_MIN_MS (60s)
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

// ── 3. fix round after the 2026-09-27 live playtest (P0-1 + P1 scoring fairness) ──
const words = (n: number, extra = "") => `${extra} ${Array.from({ length: n }, (_, i) => `w${i}`).join(" ")}`.trim();

describe("computeReport — per-incident detection (fix 1)", () => {
  it("escalating ONE log of a multi-log incident detects the whole incident; recall is per incident", () => {
    const { events, add } = log();
    add("feed.event", null, 10, { id: "a1", expected_verdict: "tp", incident_id: "inc-A", description: "phish" });
    add("feed.event", null, 20, { id: "a2", expected_verdict: "tp", incident_id: "inc-A" });
    add("feed.event", null, 30, { id: "a3", expected_verdict: "escalate", incident_id: "inc-A" });
    add("feed.event", null, 35, { id: "ctl", expected_verdict: "benign", incident_id: "inc-A" }); // legit control step
    add("feed.event", null, 40, { id: "s1", expected_verdict: "tp", incident_id: "solo:s1" });
    add("feed.event", null, 50, { id: "n1" }); // pure noise, verdict missing ⇒ benign
    add("escalation.requested", "a", 70, { event_id: "a2", summary: "s" }, "t1");
    const { team, perUser } = computeReport(events, [member("a", "t1")]);
    expect(team.attacks).toBe(4);
    expect(team.incidentsTotal).toBe(2);
    expect(team.incidentsDetected).toBe(1);
    expect(team.incidentRecall).toBe(50);
    expect(team.incidents.find(i => i.id === "inc-A")).toMatchObject({ detected: true, escalated: true, attackEvents: 3, firstSeenS: 10, detectS: 70, dwellS: 60, label: "phish" });
    expect(team.incidents.find(i => i.id === "solo:s1")!.detected).toBe(false);
    expect(cell(perUser[0].rubric, "Attack recall (team)").score).toBe(8); // bandHigh(50, 80, 50, 25)
    expect(team.detected).toBe(true);
    expect(team.timeToDetectS).toBe(60);   // 70 − first attack log (a1 at 10)
  });

  it("marking an attack log true_positive or suspicious (no escalation) also detects its incident", () => {
    const { events, add } = log();
    add("feed.event", null, 10, { id: "a1", expected_verdict: "tp", incident_id: "inc-A" });
    add("feed.event", null, 20, { id: "b1", expected_verdict: "tp", incident_id: "inc-B" });
    add("disposition.set", "a", 40, { event_id: "a1", verdict: "suspicious" }, "t1");
    add("disposition.set", "a", 50, { event_id: "b1", verdict: "benign" }, "t1");
    const { team } = computeReport(events, [member("a", "t1")]);
    expect(team.incidents.find(i => i.id === "inc-A")).toMatchObject({ detected: true, escalated: false, detectS: 40 });
    expect(team.incidents.find(i => i.id === "inc-B")!.detected).toBe(false);
    expect(team.timeToDetectS).toBeNull(); // MTTD needs an escalation
  });

  it("legacy fallback: attack logs without incident_id are one incident each; a missing verdict is benign", () => {
    const { events, add } = log();
    add("feed.event", null, 10, { id: "x1", expected_verdict: "tp" });
    add("feed.event", null, 20, { id: "x2", expected_verdict: "tp" });
    add("feed.event", null, 30, { id: "n1" });
    add("disposition.set", "a", 40, { event_id: "n1", verdict: "benign" }, "t1");
    add("escalation.requested", "a", 50, { event_id: "x1" }, "t1");
    const { team, perUser } = computeReport(events, [member("a", "t1")]);
    expect(team.incidentsTotal).toBe(2);
    expect(team.incidentsDetected).toBe(1);
    expect(perUser[0].dispAcc).toBe(100);
  });
});

describe("computeReport — suspicious = partial credit (fix 2)", () => {
  it("suspicious on an attack = partial credit (0.75), on benign = a mild penalty (0.5)", () => {
    const { events, add } = log();
    add("feed.event", null, 1, { id: "atk", expected_verdict: "tp" });
    add("feed.event", null, 2, { id: "ben", expected_verdict: "benign" });
    add("disposition.set", "a", 30, { event_id: "atk", verdict: "suspicious" }, "t1");
    add("disposition.set", "b", 30, { event_id: "ben", verdict: "suspicious" }, "t1");
    const { perUser } = computeReport(events, [member("a", "t1"), member("b", "t1")]);
    expect(perUser.find(u => u.user_id === "a")!.dispAcc).toBe(75);
    expect(perUser.find(u => u.user_id === "b")!.dispAcc).toBe(50);
    expect(perUser.find(u => u.user_id === "a")!.dispCorrect).toBe(0);
  });

  it("benign→suspicious on an attack is a real self-correction; an invalid verdict neither scores nor fakes one", () => {
    const { events, add } = log();
    add("feed.event", null, 1, { id: "atk", expected_verdict: "tp" });
    add("feed.event", null, 2, { id: "n1", expected_verdict: "benign" });
    add("disposition.set", "a", 30, { event_id: "atk", verdict: "benign" }, "t1");
    add("disposition.set", "a", 60, { event_id: "atk", verdict: "suspicious" }, "t1");
    add("disposition.set", "b", 30, { event_id: "n1", verdict: "probably_fine" }, "t1");
    add("disposition.set", "b", 60, { event_id: "n1", verdict: "benign" }, "t1");
    add("disposition.set", "b", 70, { event_id: "e0000deadbeef", verdict: "benign" }, "t1"); // unknown id
    const { perUser, team } = computeReport(events, [member("a", "t1"), member("b", "t1")]);
    const a = perUser.find(u => u.user_id === "a")!; const b = perUser.find(u => u.user_id === "b")!;
    expect(cell(a.rubric, "Self-correction").score).toBe(8);
    expect(cell(b.rubric, "Self-correction").score).toBeNull();
    expect(b.dispCount).toBe(1);
    expect(b.dispAcc).toBe(100);
    expect(team.dispTotal).toBe(2);
  });
});

describe("computeReport — escalation precision per incident, smooth band (fix 3)", () => {
  it("duplicate escalations of one incident count once; 25% no longer collapses to 0", () => {
    const { events, add } = log();
    for (const id of ["a1", "a2", "a3"]) add("feed.event", null, 1, { id, expected_verdict: "tp", incident_id: "inc-A" });
    for (const id of ["n1", "n2", "n3"]) add("feed.event", null, 2, { id, expected_verdict: "benign" });
    for (const id of ["a1", "a2", "a3", "n1"]) add("escalation.requested", "a", 30, { event_id: id }, "t1");
    for (const id of ["a1", "n1", "n2", "n3"]) add("escalation.requested", "b", 30, { event_id: id }, "t1");
    const { perUser } = computeReport(events, [member("a", "t1"), member("b", "t1")]);
    // a: targets = {inc-A: 1, n1: 0} ⇒ 50% ⇒ round(12·40/70) = 7
    expect(cell(perUser.find(u => u.user_id === "a")!.rubric, "Escalation precision").score).toBe(7);
    // b: 1 of 4 ⇒ 25% ⇒ round(12·15/70) = 3 (the old bandHigh cliff gave 0)
    expect(cell(perUser.find(u => u.user_id === "b")!.rubric, "Escalation precision").score).toBe(3);
  });

  it("escalating only the control log of a real incident earns half credit", () => {
    const { events, add } = log();
    add("feed.event", null, 1, { id: "a1", expected_verdict: "tp", incident_id: "inc-A" });
    add("feed.event", null, 2, { id: "ctl", expected_verdict: "benign", incident_id: "inc-A" });
    add("escalation.requested", "a", 30, { event_id: "ctl" }, "t1");
    add("escalation.requested", "c", 30, { event_id: "ctl" }, "t1");
    add("escalation.requested", "c", 40, { event_id: "a1" }, "t1");
    const { perUser } = computeReport(events, [member("a", "t1"), member("c", "t1")]);
    expect(cell(perUser.find(u => u.user_id === "a")!.rubric, "Escalation precision").score).toBe(7);  // 50%
    expect(cell(perUser.find(u => u.user_id === "c")!.rubric, "Escalation precision").score).toBe(12); // one incident, 100%
  });
});

describe("computeReport — help-desk scored on the decision (fix 4)", () => {
  const vish = { kind: "ticket", text: "Someone from 'IT support' asked a Finance user to read back an MFA code.", expected_response: "Never read back an MFA code; refuse and report it as social engineering." };

  it("vishing ticket: 'rejected' is the right call (12 with ONE ticket); a second answer earns nothing", () => {
    const { events, add } = log();
    add("staff.inject", "instr", 60, vish); // seq 2
    add("ticket.answered", "a", 100, { ticket_seq: 2, decision: "rejected", response: "refused" }, "t1");
    add("ticket.answered", "b", 110, { ticket_seq: 2, decision: "rejected", response: "refused" }, "t1");
    const { perUser, team } = computeReport(events, [member("a", "t1"), member("b", "t1")]);
    expect(cell(perUser.find(u => u.user_id === "a")!.rubric, "Help-desk tickets").score).toBe(12);
    const bCell = cell(perUser.find(u => u.user_id === "b")!.rubric, "Help-desk tickets");
    expect(bCell.score).toBeNull();
    expect((bCell as { note?: string }).note).toMatch(/second answer/);
    expect(team.injects[0]).toMatchObject({ kind: "ticket", scored: true, handled: true });
  });

  it("'handled' on a vishing ticket is the wrong call — 0, and the curveball is missed", () => {
    const { events, add } = log();
    add("staff.inject", "instr", 60, vish);
    add("ticket.answered", "a", 100, { ticket_seq: 2, decision: "handled", response: "verified caller, no code shared" }, "t1");
    const { perUser, team } = computeReport(events, [member("a", "t1")]);
    expect(cell(perUser[0].rubric, "Help-desk tickets").score).toBe(0);
    expect(team.injects[0]).toMatchObject({ scored: true, handled: false });
  });

  it("a ticket nobody answered counts against the Tier-1s", () => {
    const { events, add } = log();
    add("staff.inject", "instr", 60, vish);
    const { perUser, team } = computeReport(events, [member("a", "t1")]);
    expect(cell(perUser[0].rubric, "Help-desk tickets").score).toBe(0);
    expect(team.injects[0].handled).toBe(false);
  });
});

describe("computeReport — overload episodes need a minimum duration (fix 6)", () => {
  const run = (releaseAt: number) => {
    const { events, add } = log();
    for (const id of ["e1", "e2", "e3"]) add("alert.claimed", "a", 10, { event_id: id }, "t1");
    add("coordination.nudge", "mgr", 20, { target: "a" }, "mgr");
    add("alert.released", "a", releaseAt, { event_id: "e1" }, "t1");
    add("session.ended", "instr", 400);
    return cell(computeReport(events, [member("a", "t1"), member("mgr", "mgr")]).perUser.find(u => u.user_id === "mgr")!.rubric, "Load balancing").score;
  };
  it("a 30-second spike is not overload", () => { expect(run(40)).toBeNull(); });
  it("≥60s at ≥ OVERLOAD_CASES, nudged by the Manager, scores Load balancing", () => { expect(run(100)).toBe(12); });
});

describe("computeReport — evidence-based triage (fix 7)", () => {
  it("a disposition on a log the analyst never opened counts at reduced weight", () => {
    const { events, add } = log();
    add("feed.event", null, 1, { id: "n1", expected_verdict: "benign" });
    add("feed.event", null, 2, { id: "n2", expected_verdict: "benign" });
    add("event.opened", "a", 10, { event_id: "n1", dwell_ms: 8000 }, "t1");
    add("disposition.set", "a", 20, { event_id: "n1", verdict: "benign" }, "t1");
    add("disposition.set", "a", 21, { event_id: "n2", verdict: "benign" }, "t1");
    const a = computeReport(events, [member("a", "t1")]).perUser[0];
    expect(a.dispAcc).toBe(75); // (1 + 0.5) / 2
    expect(a.dispUnopened).toBe(1);
    expect(a.dispCorrect).toBe(2);
  });

  it("a session with NO click telemetry is not down-weighted", () => {
    const { events, add } = log();
    add("feed.event", null, 1, { id: "n1", expected_verdict: "benign" });
    add("disposition.set", "a", 20, { event_id: "n1", verdict: "benign" }, "t1");
    expect(computeReport(events, [member("a", "t1")]).perUser[0].dispAcc).toBe(100);
  });

  it("a very short average read time caps Time-to-triage at 4", () => {
    const { events, add } = log();
    add("feed.event", null, 10, { id: "h1", expected_verdict: "benign", severity: "high" });
    add("event.opened", "a", 15, { event_id: "h1", dwell_ms: 1000 }, "t1");
    add("disposition.set", "a", 20, { event_id: "h1", verdict: "benign" }, "t1");
    expect(cell(computeReport(events, [member("a", "t1")]).perUser[0].rubric, "Time-to-triage").score).toBe(4);
  });
});

describe("computeReport — Tier-3 (fix 8)", () => {
  const caseFeed = (add: ReturnType<typeof log>["add"]) =>
    add("feed.event", null, 5, { id: "a1", expected_verdict: "tp", incident_id: "inc-A", mitre_technique: "T1078", user_email: "m.torres@nexacorp.com", hostname: "WS-ENG-2093.nexacorp.com" });

  it("a confirmed scope with hosts + users + techniques reaches 12 (was capped at 8)", () => {
    const { events, add } = log();
    add("scope.confirmed", "t3", 60, { hosts: ["WS-1"], users: ["u1"], techniques: ["T1078"] }, "t3");
    expect(cell(computeReport(events, [member("t3", "t3")]).perUser[0].rubric, "Final scope (confirmed)").score).toBe(12);
  });

  it("hunt quality accepts a sub-technique of an observed technique and entity matches by local-part / short host", () => {
    const hunt = (technique: string) => {
      const { events, add } = log(); caseFeed(add);
      add("hunt.logged", "t3", 60, { hypothesis: "short", finding: words(15, "m.torres logged on to ws-eng-2093 over RDP"), technique, conclusion: "confirmed" }, "t3");
      return cell(computeReport(events, [member("t3", "t3")]).perUser[0].rubric, "Hunt quality").score;
    };
    expect(hunt("T1078.004")).toBe(12); // 35 + 25 + 15 = 75
    expect(hunt("T1566")).toBe(8);      // valid but unrelated technique: 35 + 12 + 15 = 62
  });

  it("a REFUTED hunt with evidence earns full technique credit", () => {
    const hunt = (conclusion: string) => {
      const { events, add } = log(); caseFeed(add);
      add("hunt.logged", "t3", 60, { hypothesis: "short", finding: words(15, "m.torres ws-eng-2093 stage-2 blocked per #240"), technique: "T1105", conclusion }, "t3");
      return cell(computeReport(events, [member("t3", "t3")]).perUser[0].rubric, "Hunt quality").score;
    };
    expect(hunt("refuted")).toBe(12);
    expect(hunt("confirmed")).toBe(8);
  });

  it("a hunt linked to an elevation (event_id) answers it", () => {
    const { events, add } = log();
    add("elevation.requested", "t2", 100, { event_id: "a1", summary: "s", hunt_ask: "sweep" }, "t2");
    add("elevation.requested", "t2", 110, { event_id: "a2", summary: "s", hunt_ask: "sweep" }, "t2");
    add("hunt.logged", "t3", 200, { event_id: "a1", hypothesis: "h", finding: "f", technique: "T1078", conclusion: "confirmed" }, "t3");
    const half = computeReport(events, [member("t2", "t2"), member("t3", "t3")]).perUser.find(u => u.user_id === "t3")!;
    expect(cell(half.rubric, "Elevations answered").score).toBe(4); // 1 of 2 (a2 nobody took)
    add("hunt.logged", "t3", 260, { event_id: "a2", hypothesis: "h", finding: "f", technique: "T1078", conclusion: "refuted" }, "t3");
    const full = computeReport(events, [member("t2", "t2"), member("t3", "t3")]).perUser.find(u => u.user_id === "t3")!;
    expect(cell(full.rubric, "Elevations answered").score).toBe(12);
  });

  it("hypothesis→conclusion is timed from the hunt that led to the confirmation, not the first (proactive) hunt", () => {
    const { events, add } = log();
    add("hunt.logged", "t3", 60, { hypothesis: "early proactive hunt" }, "t3");
    add("hunt.logged", "t3", 900, { hypothesis: "the hunt that confirmed it" }, "t3");
    add("scope.confirmed", "t3", 960, { hosts: ["WS-1"] }, "t3");
    expect(cell(computeReport(events, [member("t3", "t3")]).perUser[0].rubric, "Hypothesis→conclusion time").score).toBe(12); // 1 min
  });
});

describe("computeReport — TI substance + insufficient evidence (fix 9)", () => {
  it("non-empty but unrelated fields don't score; <2 measured cells ⇒ insufficient evidence, no %", () => {
    const { events, add } = log();
    add("feed.event", null, 10, { id: "a1", expected_verdict: "tp", mitre_technique: "T1566" });
    add("intel.published", "ti", 100, { actor: "APT29", technique: "T1000", next_expected: "x" }, "ti");
    const ti = computeReport(events, [member("ti", "ti")]).perUser[0];
    expect(cell(ti.rubric, "Attribution accuracy").score).toBe(0);
    expect(cell(ti.rubric, "Next-step prediction").score).toBeNull(); // nothing arrived after it
    expect(ti.measuredCells).toBe(1);
    expect(ti.insufficientEvidence).toBe(true);
    expect(ti.rubricPct).toBeNull();
  });

  it("attribution tied to an observed technique, a prediction that came true and a verified IOC score; the decoy IOC costs", () => {
    const { events, add } = log();
    add("feed.event", null, 10, { id: "a1", expected_verdict: "tp", mitre_technique: "T1566", network: { domain: "invoice-doc-share.net" } });
    add("feed.event", null, 300, { id: "a2", expected_verdict: "tp", mitre_technique: "T1021.001", mitre_tactic: "Lateral Movement", hostname: "WS-ENG-2093" });
    add("intel.published", "ti", 100, { actor: "FIN-style phishing crew", technique: "T1566.002", next_expected: "lateral movement over RDP to engineering hosts", ioc: "invoice-doc-share.net" }, "ti");
    add("intel.published", "ti", 120, { actor: "OSINT cluster", technique: "T1566", next_expected: "", ioc: "8.8.8.8" }, "ti");
    const ti = computeReport(events, [member("ti", "ti")]).perUser[0];
    expect(cell(ti.rubric, "Attribution accuracy").score).toBe(12);
    expect(cell(ti.rubric, "Next-step prediction").score).toBe(4); // 1 of 2
    expect(cell(ti.rubric, "IOC precision").score).toBe(4);        // 1 of 2 (8.8.8.8 isn't in the attack)
    expect(ti.insufficientEvidence).toBe(false);
    expect(ti.rubricPct).toBe(56); // 20 / 36
  });
});

describe("computeReport — Tier-2 containment quality + report accuracy (fix 10)", () => {
  it("approved + executed containment and a correct report verdict score full", () => {
    const { events, add } = log();
    add("feed.event", null, 1, { id: "a1", expected_verdict: "tp", incident_id: "inc-A" });
    add("report.submitted", "t2", 90, { event_id: "a1", verdict: "true_positive", summary: "s", findings: "f", recommendation: "r" }, "t2");
    add("containment.requested", "t2", 100, { event_id: "a1", target: "WS-1", reason: "isolate the beaconing host" }, "t2");
    add("containment.approved", "mgr", 120, { event_id: "a1" }, "mgr");
    add("containment.executed", "t2", 140, { event_id: "a1", target: "WS-1" }, "t2");
    const t2 = computeReport(events, [member("t2", "t2"), member("mgr", "mgr")]).perUser.find(u => u.user_id === "t2")!;
    expect(cell(t2.rubric, "Containment quality").score).toBe(12);
    expect(cell(t2.rubric, "Report accuracy").score).toBe(12);
  });

  it("a denied request and a re-targeted request lower containment quality; a wrong report verdict lowers accuracy", () => {
    const { events, add } = log();
    add("feed.event", null, 1, { id: "a1", expected_verdict: "tp", incident_id: "inc-A" });
    add("feed.event", null, 2, { id: "n1", expected_verdict: "benign" });
    add("report.submitted", "t2", 90, { event_id: "a1", verdict: "true_positive" }, "t2");
    add("report.submitted", "t2", 95, { event_id: "n1", verdict: "true_positive" }, "t2");
    add("containment.requested", "t2", 100, { event_id: "a1", target: "WS-FIN-2847", reason: "isolate the host now" }, "t2");
    add("containment.denied", "mgr", 130, { event_id: "a1", reason: "wrong asset" }, "mgr");
    add("containment.requested", "t2", 200, { event_id: "a1", target: "SRV-DC01", reason: "disable the rogue admin" }, "t2");
    add("containment.approved", "mgr", 220, { event_id: "a1" }, "mgr");
    add("containment.executed", "t2", 240, { event_id: "a1", target: "SRV-DC01" }, "t2");
    const t2 = computeReport(events, [member("t2", "t2"), member("mgr", "mgr")]).perUser.find(u => u.user_id === "t2")!;
    expect(cell(t2.rubric, "Containment quality").score).toBe(4); // (0 + 1) / 2 = 50%
    expect(cell(t2.rubric, "Report accuracy").score).toBe(4);     // 1 of 2

    const { events: ev2, add: add2 } = log();
    add2("containment.requested", "t2", 100, { event_id: "a1", target: "WS-A" }, "t2");
    add2("containment.requested", "t2", 150, { event_id: "a1", target: "WS-B" }, "t2"); // re-targeted
    add2("containment.approved", "mgr", 160, { event_id: "a1" }, "mgr");
    add2("containment.executed", "t2", 170, { event_id: "a1", target: "WS-B" }, "t2");
    const t2b = computeReport(ev2, [member("t2", "t2"), member("mgr", "mgr")]).perUser.find(u => u.user_id === "t2")!;
    expect(cell(t2b.rubric, "Containment quality").score).toBe(8); // (0.25 + 1) / 2 = 63%
  });
});

describe("computeReport — timing (fix 11)", () => {
  it("MTTR uses the FIRST escalation — a duplicate raised after the resolve doesn't drop the case", () => {
    const { events, add } = log();
    add("escalation.requested", "a", 100, { event_id: "e1" }, "t1");
    add("escalation.acknowledged", "t2", 130, { event_id: "e1" }, "t2");
    add("escalation.resolved", "t2", 220, { event_id: "e1" }, "t2");
    add("escalation.requested", "b", 260, { event_id: "e1" }, "t1");
    const { team, perUser } = computeReport(events, [member("a", "t1"), member("b", "t1"), member("t2", "t2")]);
    expect(team.mttrS).toBe(120);
    expect(team.handoffLatS).toBe(30);
    expect(cell(perUser.find(u => u.user_id === "t2")!.rubric, "Ack latency").score).toBe(12);
  });

  it("a bounced escalation is a closed loop", () => {
    const { events, add } = log();
    add("escalation.requested", "a", 30, { event_id: "e1" }, "t1");
    add("escalation.requested", "a", 40, { event_id: "e2" }, "t1");
    add("escalation.bounced", "t2", 60, { event_id: "e1", reason: "duplicate" }, "t2");
    add("escalation.acknowledged", "t2", 90, { event_id: "e2" }, "t2");
    expect(computeReport(events, [member("a", "t1"), member("t2", "t2")]).team.loopClosure).toBe(100);
  });

  it("team MTTD = the first CORRECT escalation of a malicious log (an earlier FP escalation doesn't count)", () => {
    const { events, add } = log();
    add("feed.event", null, 1, { id: "a1", expected_verdict: "tp" });
    add("feed.event", null, 2, { id: "n1", expected_verdict: "benign" });
    add("escalation.requested", "a", 50, { event_id: "n1" }, "t1");
    add("escalation.requested", "a", 122, { event_id: "a1" }, "t1");
    add("escalation.requested", "b", 530, { event_id: "a1" }, "t1");
    // MTTD runs from the first attack log reaching the feed (a1 at sec 1), not shift start: 122 − 1.
    expect(computeReport(events, [member("a", "t1"), member("b", "t1")]).team.timeToDetectS).toBe(121);
  });
});

describe("computeReport — curveballs need supporting telemetry (fix 12)", () => {
  const twist = { kind: "twist", text: "EDR update: a host is beaconing to a NEW C2 domain", expected_response: "re-scope", linked_objective: "adaptability" };
  const support = (add: ReturnType<typeof log>["add"], sec: number) =>
    add("feed.event", null, sec, { id: "tw-1", expected_verdict: "tp", incident_id: "inc-A", supports_inject: "msel_twist", hostname: "WS-FIN-2847", network: { domain: "new-c2-sync.net" } });

  it("a twist is handled when a response references its supporting telemetry", () => {
    const { events, add } = log();
    add("staff.inject", "instr", 60, { ...twist, id: "msel_twist" });
    support(add, 90);
    add("hunt.logged", "t3", 200, { hypothesis: "beacon", finding: "WS-FIN-2847 resolves new-c2-sync.net every 60s" }, "t3");
    expect(computeReport(events, [member("t3", "t3")]).team.injects[0]).toMatchObject({ scored: true, handled: true, evaluable: true });
  });

  it("v2: the merged original_id links the inject to its telemetry; a scope change BEFORE the telemetry doesn't count, a re-scope after it does", () => {
    const { events, add } = log();
    add("staff.inject", "instr", 60, { ...twist, id: "m0a1b2c3d", original_id: "msel_twist" });
    add("scope.set", "t2", 70, { hosts: ["SRV-9"] }, "t2");
    support(add, 90);
    expect(computeReport(events, [member("t2", "t2")]).team.injects[0]).toMatchObject({ scored: true, handled: false });
    add("scope.set", "t2", 150, { hosts: ["SRV-9", "SRV-10"] }, "t2");
    expect(computeReport(events, [member("t2", "t2")]).team.injects[0]).toMatchObject({ scored: true, handled: true });
  });

  it("a decoy is handled only by an EXPLICIT benign call — not by inaction; chasing it is missed", () => {
    const decoy = { kind: "false_lead", text: "Marketing SaaS looks like exfil", expected_response: "reject", linked_objective: "discrimination" };
    const build = (action: "none" | "benign" | "chase") => {
      const { events, add } = log();
      add("staff.inject", "instr", 60, { ...decoy, id: "msel_false_lead" });
      add("feed.event", null, 80, { id: "fl-1", expected_verdict: "benign", supports_inject: "msel_false_lead" });
      if (action === "benign") add("disposition.set", "a", 120, { event_id: "fl-1", verdict: "benign" }, "t1");
      if (action === "chase") add("escalation.requested", "a", 120, { event_id: "fl-1" }, "t1");
      return computeReport(events, [member("a", "t1")]).team;
    };
    expect(build("benign").injects[0]).toMatchObject({ decoy: true, scored: true, handled: true });
    expect(build("none").injects[0]).toMatchObject({ decoy: true, scored: true, handled: false });
    expect(build("chase").injects[0]).toMatchObject({ decoy: true, scored: true, handled: false });
    expect(build("benign").injectsScored).toBe(1);
  });
});

describe("computeReport — review fixes (2026-09-27)", () => {
  it("a manual ticket that merely says \"don't\" is expected to be HANDLED, not refused", () => {
    const { events, add } = log();
    add("staff.inject", "instr", 60, { kind: "ticket", text: "User says they don't have VPN access after the password reset" });
    add("ticket.answered", "a", 90, { ticket_seq: 2, decision: "handled", response: "restored access" }, "t1");
    const a = computeReport(events, [member("a", "t1")]).perUser.find(u => u.user_id === "a")!;
    expect(cell(a.rubric, "Help-desk tickets").score).toBe(12);
  });

  it("an instructor-typed twist does not borrow the scripted twist's telemetry", () => {
    const { events, add } = log();
    add("feed.event", null, 5, { id: "sup1", expected_verdict: "tp", supports_inject: "msel_twist", hostname: "WS-9" });
    add("staff.inject", "instr", 60, { kind: "twist", text: "manual curveball" }); // no id / original_id → manual
    const [r] = computeReport(events, [member("t2", "t2")]).team.injects;
    expect(r.evaluable).toBe(false);
  });

  it("an escalation ends the claim (no phantom load if the follow-up release is lost)", () => {
    const { events, add } = log();
    for (const id of ["x1", "x2", "x3"]) {
      add("feed.event", null, 1, { id, expected_verdict: "tp" });
      add("alert.claimed", "a", 10, { event_id: id }, "t1");
      add("escalation.requested", "a", 20, { event_id: id, summary: "suspicious activity" }, "t1");
    }
    add("coordination.nudge", "mgr", 200, { target: "a", reason: "overloaded", load: 3 }, "mgr");
    add("session.ended", null, 400);
    const mgr = computeReport(events, [member("a", "t1"), member("mgr", "mgr")]).perUser.find(u => u.user_id === "mgr")!;
    expect(cell(mgr.rubric, "Load balancing").score).toBeNull(); // A never carried 3 live claims for ≥60s
  });
});

describe("computeReport — v3: SLA per reported event, misses, team triage", () => {
  // SLA: critical 1 min · high 3 min · medium 10 min · low/other 30 min.
  function shift() {
    const { events, add } = log();
    add("feed.event", null, 10, { id: "atk1", expected_verdict: "tp", incident_id: "inc-A", severity: "high", description: "beacon to C2" });
    add("feed.event", null, 20, { id: "atk2", expected_verdict: "tp", incident_id: "inc-A", severity: "critical", description: "credential dump" });
    add("feed.event", null, 30, { id: "atk3", expected_verdict: "tp", incident_id: "inc-B", severity: "high", description: "mailbox rule" });
    add("feed.event", null, 40, { id: "atk4", expected_verdict: "tp", incident_id: "inc-C", severity: "medium", description: "USB copy" });
    add("feed.event", null, 50, { id: "n1", severity: "high", description: "admin login" });
    add("feed.event", null, 60, { id: "n2", severity: "low", description: "dns lookup" });
    // a: escalates atk1 within SLA (100s ≤ 180s), escalates benign n1 late (400s > 180s),
    //    calls atk3 benign (false negative), opens atk4 and walks past it.
    add("escalation.requested", "a", 110, { event_id: "atk1", summary: "c2" }, "t1");
    add("escalation.acknowledged", "b", 150, { event_id: "atk1" }, "t2");
    add("escalation.requested", "a", 450, { event_id: "n1", summary: "odd" }, "t1");
    add("disposition.set", "a", 200, { event_id: "atk3", verdict: "benign" }, "t1");
    add("event.opened", "a", 300, { event_id: "atk4", dwell_ms: 20000 });
    // b triages critical atk2 late (100s > 60s) as true positive.
    add("disposition.set", "b", 120, { event_id: "atk2", verdict: "true_positive" }, "t1");
    return computeReport(events, [member("a", "t1"), member("b", "t1")]);
  }

  it("lists each reported event with its response time, SLA and outcome", () => {
    const { perUser } = shift();
    const a = perUser.find(u => u.user_id === "a")!;
    const atk1 = a.reported.find(r => r.label === "beacon to C2")!;
    expect(atk1).toMatchObject({ kind: "escalation", severity: "high", responseS: 100, slaS: 180, withinSla: true, truth: "attack", outcome: "acknowledged" });
    const n1 = a.reported.find(r => r.label === "admin login")!;
    expect(n1).toMatchObject({ kind: "escalation", responseS: 400, withinSla: false, truth: "benign", outcome: "open" });
    // high/critical triage counts too (atk3 was high, called benign → still a triage action on time)
    expect(a.reported.find(r => r.label === "mailbox rule")).toMatchObject({ kind: "triage", responseS: 170, withinSla: true, verdict: "benign" });
    expect(a).toMatchObject({ slaTotal: 3, slaMet: 2, slaPct: 67 });
    const b = perUser.find(u => u.user_id === "b")!;
    expect(b.reported[0]).toMatchObject({ kind: "triage", severity: "critical", responseS: 100, slaS: 60, withinSla: false });
  });

  it("names what the analyst missed: false negatives, walked-past attacks, false alarms", () => {
    const { perUser } = shift();
    const a = perUser.find(u => u.user_id === "a")!;
    expect(a.falseNegatives.map(m => m.label)).toEqual(["mailbox rule"]);
    expect(a.walkedPast.map(m => m.label)).toEqual(["USB copy"]);
    expect(a.falseAlarms.map(m => m.label)).toEqual(["admin login"]);
    const b = perUser.find(u => u.user_id === "b")!;
    expect(b.falseNegatives).toEqual([]);
    expect(b.walkedPast).toEqual([]);
  });

  it("an attack someone else caught is not counted as walked past", () => {
    const { events, add } = log();
    add("feed.event", null, 10, { id: "atk", expected_verdict: "tp", incident_id: "inc", severity: "high" });
    add("event.opened", "a", 20, { event_id: "atk", dwell_ms: 9000 });
    add("escalation.requested", "b", 30, { event_id: "atk" }, "t1");
    const { perUser } = computeReport(events, [member("a", "t1"), member("b", "t1")]);
    expect(perUser.find(u => u.user_id === "a")!.walkedPast).toEqual([]);
  });

  it("team metrics: attack SLA, high/critical coverage, MTTT, missed logs, false negatives/alarms, workload", () => {
    const { team } = shift();
    // attack logs: atk1 in SLA (110-10=100 ≤ 180) · atk2 late (120-20=100 > 60) · atk3 in SLA (200-30=170 ≤ 180) · atk4 never triaged
    expect(team).toMatchObject({ attackSlaTotal: 4, attackSlaMet: 2, attackSlaPct: 50 });
    // high/critical: atk1, atk2, atk3, n1 → all triaged
    expect(team).toMatchObject({ highCritTotal: 4, highCritTriaged: 4, highCritCoverage: 100 });
    expect(team.mtttS).toBe(135);   // median of 100, 100, 170, 400
    expect(team.missedAttackCount).toBe(1);
    expect(team.missedAttackLogs[0]).toMatchObject({ label: "USB copy", severity: "medium", detail: "its incident was not caught" });
    expect(team.falseNegatives.map(m => m.label)).toEqual(["mailbox rule"]);
    expect(team.falseAlarms.map(m => m.label)).toEqual(["admin login"]);
    expect(team).toMatchObject({ triageActions: 4, triagers: 2, busiestShare: 75, busiestName: "User a" });
  });
});

describe("computeReport — v4: EDR host isolation judged against the answer key", () => {
  const roster = [member("t1", "t1"), member("t2", "t2"), member("t3", "t3")];
  function shift() {
    const l = log();
    l.add("feed.event", null, 10, { id: "a1", expected_verdict: "tp", incident_id: "inc-1", severity: "high", hostname: "WS-FIN-2847", description: "encoded PowerShell" });
    l.add("feed.event", null, 40, { id: "a2", expected_verdict: "escalate", incident_id: "inc-1", severity: "critical", hostname: "ws-fin-2847.corp.local" });
    l.add("feed.event", null, 50, { id: "a3", expected_verdict: "tp", incident_id: "inc-2", severity: "high", hostname: "SRV-DB-01" });
    l.add("feed.event", null, 20, { id: "n1", expected_verdict: "benign", severity: "low", hostname: "WS-HR-1142" });
    return l;
  }

  it("isolating a compromised host is a right call (short-name / case-insensitive match); a clean host is a wrong call", () => {
    const { events, add } = shift();
    add("edr.host_isolated", "t2", 130, { host: "WS-FIN-2847" }, "t2");     // compromised → right, 120s after its first attack log
    add("edr.host_isolated", "t2", 200, { host: "ws-hr-1142" }, "t2");      // clean → wrong
    add("edr.host_released", "t2", 260, { host: "WS-HR-1142" }, "t2");
    const r = computeReport(events, roster);
    const t2 = r.perUser.find(u => u.user_id === "t2")!;
    expect(t2.isolations.map(i => [i.host, i.verdict, i.correct])).toEqual([["WS-FIN-2847", "compromised", true], ["ws-hr-1142", "clean", false]]);
    expect(t2.isolations[0].timeToIsolateS).toBe(120);
    expect(t2.isolations[1].releasedS).toBe(260);
    expect(t2.isoPct).toBe(50);
    expect(cell(t2.rubric, "Host isolation").score).toBe(4);      // 1 of 2 right → the lowest non-zero band
  });

  it("team view: first isolation per host, incident marked contained, compromised hosts left online, MTTI", () => {
    const { events, add } = shift();
    add("edr.host_isolated", "t3", 100, { host: "WS-FIN-2847" }, "t3");
    add("edr.host_released", "t3", 150, { host: "WS-FIN-2847" }, "t3");
    add("edr.host_isolated", "t2", 160, { host: "WS-FIN-2847" }, "t2");     // re-isolation is not a new team decision
    const r = computeReport(events, roster);
    expect(r.team.version).toBe(4);
    expect(r.team.isoTotal).toBe(1);
    expect(r.team.isoCorrect).toBe(1);
    expect(r.team.isolations[0]).toMatchObject({ host: "WS-FIN-2847", by: "t3", correct: true, releasedS: 150, timeToIsolateS: 90 });
    expect(r.team.mttiS).toBe(90);
    expect(r.team.compromisedHosts).toBe(2);
    expect(r.team.hostsLeftOnline).toEqual([{ host: "SRV-DB-01", attackLogs: 1, firstAttackS: 50 }]);
    expect(r.team.incidents.find(i => i.id === "inc-1")!.contained).toBe(true);
    expect(r.team.incidents.find(i => i.id === "inc-2")!.contained).toBe(false);
    // Each analyst is judged on the hosts THEY isolated.
    expect(r.perUser.find(u => u.user_id === "t2")!.isolations.map(i => i.host)).toEqual(["WS-FIN-2847"]);
    expect(r.perUser.find(u => u.user_id === "t3")!.isoPct).toBe(100);
    expect(cell(r.perUser.find(u => u.user_id === "t3")!.rubric, "Host isolation").score).toBe(12);
  });

  it("no isolation → the criterion is not measured and does not move the score", () => {
    const { events } = shift();
    const r = computeReport(events, roster);
    const t2 = r.perUser.find(u => u.user_id === "t2")!;
    expect(t2.isolations).toEqual([]);
    expect(t2.isoPct).toBeNull();
    expect(cell(t2.rubric, "Host isolation").score).toBeNull();
    expect(r.team.isoTotal).toBe(0);
    expect(r.team.hostsLeftOnline.map(h => h.host)).toEqual(["WS-FIN-2847", "SRV-DB-01"]);
  });
});

// ── "good catch" grading (an incident is built from several logs) ──────────────
describe("computeReport — incident catch grade (scope coverage + timeliness + verdict)", () => {
  // A 3-log incident on three hosts; vary what the team surfaces.
  const incident = (api: ReturnType<typeof log>) => {
    api.add("feed.event", null, 1, { id: "a1", expected_verdict: "tp", incident_id: "inc-1", severity: "high", hostname: "H1", mitre_technique: "T1059" });
    api.add("feed.event", null, 2, { id: "a2", expected_verdict: "tp", incident_id: "inc-1", severity: "high", hostname: "H2", mitre_technique: "T1021" });
    api.add("feed.event", null, 3, { id: "a3", expected_verdict: "tp", incident_id: "inc-1", severity: "high", hostname: "H3", mitre_technique: "T1048" });
    api.add("feed.event", null, 4, { id: "n1", expected_verdict: "benign", severity: "low", hostname: "H9" });
    return api;
  };
  const inc = (r: ReturnType<typeof computeReport>) => r.team.incidents.find(i => i.id === "inc-1")!;

  it("caught_well: ≥60% scope, within SLA, firm TP verdict", () => {
    const api = incident(log());
    api.add("disposition.set", "a", 60, { event_id: "a1", verdict: "true_positive" }, "t1");
    api.add("disposition.set", "a", 90, { event_id: "a2", verdict: "true_positive" }, "t1");
    const i = inc(computeReport(api.events, [member("a", "t1")]));
    expect(i.scopeCoverage).toBe(67);          // 2 of 3 logs
    expect(i.slaMet).toBe(true);               // dwell 59s ≤ 900s (high)
    expect(i.grade).toBe("caught_well");
    expect(i.handlingScore).toBeGreaterThanOrEqual(85);
  });

  it("partial: within SLA but low scope (1 of 3)", () => {
    const api = incident(log());
    api.add("disposition.set", "a", 60, { event_id: "a1", verdict: "true_positive" }, "t1");
    const i = inc(computeReport(api.events, [member("a", "t1")]));
    expect(i.scopeCoverage).toBe(33);
    expect(i.grade).toBe("partial");
  });

  it("noticed: a single late escalation, no firm verdict", () => {
    const api = incident(log());
    api.add("escalation.requested", "a", 2400, { event_id: "a1" }, "t1"); // >2×SLA, dwell ~2399s
    const i = inc(computeReport(api.events, [member("a", "t1")]));
    expect(i.detected).toBe(true);
    expect(i.slaMet).toBe(false);
    expect(i.scopeCoverage).toBe(33);
    expect(i.grade).toBe("noticed");
  });

  it("missed: no action on any of the incident's logs", () => {
    const api = incident(log());
    const r = computeReport(api.events, [member("a", "t1")]);
    const i = inc(r);
    expect(i.detected).toBe(false);
    expect(i.grade).toBe("missed");
    expect(i.handlingScore).toBe(0);
    expect(r.team.incidentsMissed).toBe(1);
    expect(r.team.incidentsCaughtWell).toBe(0);
  });

  it("team tallies + averages aggregate per grade", () => {
    const api = incident(log());
    api.add("disposition.set", "a", 60, { event_id: "a1", verdict: "true_positive" }, "t1");
    api.add("disposition.set", "a", 90, { event_id: "a2", verdict: "true_positive" }, "t1");
    const r = computeReport(api.events, [member("a", "t1")]);
    expect(r.team.incidentsCaughtWell).toBe(1);
    expect(r.team.avgScopeCoverage).toBe(67);
    expect(r.team.avgHandlingScore).toBeGreaterThanOrEqual(85);
  });
});
