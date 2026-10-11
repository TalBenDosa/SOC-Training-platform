// Command Review: the SOC Manager is graded on decision quality (cards ranked at fire time,
// confidence-calibrated), declaration, containment calls, SITREPs, and team outcome; a
// critical error caps the score at 69. Built end-to-end through computeReport + mergeAnswers.
import { describe, it, expect } from "vitest";
import { computeReport } from "./computeReport";
import { mergeAnswers, publicAnswers } from "./serverReport";
import { redactManagerReview, MANAGER_SCORE_CAP } from "./managerReview";
import type { Ev, RosterMember } from "@/lib/team/types";

const T0 = Date.parse("2026-10-10T10:00:00.000Z");
const at = (sec: number) => new Date(T0 + sec * 1000).toISOString();
const member = (user_id: string, role: string): RosterMember => ({ user_id, role, status: "joined", name: `User ${user_id}`, handle: null });
const roster = [member("t1", "t1"), member("t2", "t2"), member("t3", "t3"), member("mgr", "mgr")];

function shift() {
  const events: Ev[] = [];
  const add = (type: string, actor_id: string | null, sec: number, payload: Record<string, unknown> = {}, role: string | null = null) => {
    events.push({ seq: events.length + 1, type, actor_id, role, payload, occurred_at: at(sec) });
  };
  add("session.started", "instr", 0);
  add("feed.event", null, 10, { id: "a1", expected_verdict: "tp", incident_id: "inc-1", severity: "high", hostname: "WS-FIN-2847", description: "Encoded PowerShell download cradle" });
  add("feed.event", null, 20, { id: "n1", expected_verdict: "benign", severity: "low", hostname: "WS-HR-1142", description: "Scheduled backup" });
  add("feed.event", null, 300, { id: "a2", expected_verdict: "tp", incident_id: "inc-1", severity: "critical", hostname: "WS-FIN-2847", description: "rclone upload of staged archive to cloud storage", mitre_tactic: "Exfiltration" });
  add("escalation.requested", "t1", 60, { event_id: "a1", summary: "PowerShell cradle" }, "t1");
  add("escalation.acknowledged", "t2", 90, { event_id: "a1" }, "t2");
  return { events, add };
}

/** A fired decision card + its server-side answer key, keyed like session_injects. */
function card(add: ReturnType<typeof shift>["add"], answers: { id: string; channel: string; expected_action: unknown }[], id: string, cardId: string, sec: number, audience: "internal" | "external", extra: Record<string, unknown> = {}) {
  add("staff.inject", null, sec, {
    kind: "decision", card: cardId, inject_id: id, audience, pillar: audience === "internal" ? "team" : "stakeholders",
    from: { name: audience === "internal" ? "Dana" : "Maya Klein", role: audience === "internal" ? "Tier-2" : "CISO" }, channel: "call", text: "Decide.",
    options: [{ id: "o1", label: "Best" }, { id: "o2", label: "Good" }, { id: "o3", label: "Okay" }, { id: "o4", label: "Weak" }], deadline_s: 180,
  });
  answers.push({ id, channel: "inject", expected_action: {
    card: cardId, ranks: { o1: "great", o2: "good", o3: "okay", o4: "weak" }, notes: { o1: "n1", o2: "n2", o3: "n3", o4: "n4" },
    deltas: { o1: { trust: 1 }, o2: {}, o3: { trust: -1 }, o4: { continuity: -2, trust: -2 } }, best: "o1", timeout_delta: { trust: -1 }, objective: "obj", context: {}, ...extra,
  } });
}

function review(events: Ev[], answers: { id: string; channel: string; expected_action: unknown }[]) {
  return computeReport(mergeAnswers(events, publicAnswers(answers)), roster).managerReview!;
}

describe("Command Review", () => {
  it("a strong manager: early declaration, right severity, best calls, steady complete SITREPs", () => {
    const { events, add } = shift();
    const answers: { id: string; channel: string; expected_action: unknown }[] = [];
    add("incident.declared", "mgr", 120, { severity: 1 }, "mgr");
    add("containment.requested", "t2", 130, { event_id: "a1", target: "WS-FIN-2847" }, "t2");
    add("containment.approved", "mgr", 170, { event_id: "a1", target: "WS-FIN-2847" }, "mgr");
    card(add, answers, "11111111-1111-4111-8111-111111111111", "ciso_status", 200, "external");
    add("decision.answered", "mgr", 260, { inject_id: "11111111-1111-4111-8111-111111111111", option: "o1", confidence: "high", rationale: "scope first then report" }, "mgr");
    for (const s of [240, 700, 1200]) add("sitrep.sent", "mgr", s, { situation: "Attack on WS-FIN-2847 with suspected data exfiltration under investigation", actions: "host isolated and scoped", status: "partially contained, investigating", next: "confirm scope then update" }, "mgr");
    card(add, answers, "22222222-2222-4222-8222-222222222222", "isolate_or_wait", 500, "internal");
    add("decision.answered", "mgr", 560, { inject_id: "22222222-2222-4222-8222-222222222222", option: "o1", confidence: "medium", rationale: "watch until scope is confirmed" }, "mgr");
    add("session.ended", "instr", 1500);
    const r = review(events, answers);
    expect(r.truthSeverity).toBe(1);                                        // exfiltration in the feed
    expect(r.criticalErrors).toEqual([]);
    expect(r.decisions.map(d => [d.card, d.rank, d.score])).toEqual([["ciso_status", "great", 12], ["isolate_or_wait", "great", 11]]);
    expect(r.pillars.find(p => p.key === "team")!.cells.find(c => c.label === "Incident declared on time")!.score).toBe(12);
    expect(r.pillars.find(p => p.key === "team")!.cells.find(c => c.label === "Severity accuracy")!.score).toBe(12);
    expect(r.pillars.find(p => p.key === "reporting")!.cells.find(c => c.label === "Status requests answered")!.score).toBe(12);
    expect(r.score).toBeGreaterThanOrEqual(85);
    expect(r.level).toBe("command_ready");
  });

  it("a critical option caps the score at 69 and is named in the review", () => {
    const { events, add } = shift();
    const answers: { id: string; channel: string; expected_action: unknown }[] = [];
    add("incident.declared", "mgr", 120, { severity: 1 }, "mgr");
    for (const s of [240, 700, 1200]) add("sitrep.sent", "mgr", s, { situation: "Attack on WS-FIN-2847 with suspected data exfiltration under investigation", actions: "host isolated and scoped", status: "investigating now", next: "confirm scope then update" }, "mgr");
    card(add, answers, "33333333-3333-4333-8333-333333333333", "reimage_request", 400, "internal", { critical: { o4: "Approved reimaging an isolated host before evidence was captured" } });
    add("decision.answered", "mgr", 430, { inject_id: "33333333-3333-4333-8333-333333333333", option: "o4", confidence: "high", rationale: "user needs to work" }, "mgr");
    add("session.ended", "instr", 1500);
    const r = review(events, answers);
    expect(r.criticalErrors.map(c => c.label)).toEqual(["Approved reimaging an isolated host before evidence was captured"]);
    expect(r.score).toBeLessThanOrEqual(MANAGER_SCORE_CAP);
    expect(r.decisions[0].score).toBe(0);                                   // weak + high confidence
  });

  it("ruling out data loss in a SITREP after exfiltration is a false statement (critical)", () => {
    const { events, add } = shift();
    add("incident.declared", "mgr", 120, { severity: 2 }, "mgr");
    add("sitrep.sent", "mgr", 400, { situation: "Malware on one finance workstation, handled by the team", actions: "isolated", status: "No personal data was affected", next: "monitor" }, "mgr");
    add("session.ended", "instr", 900);
    const r = review(events, []);
    expect(r.criticalErrors.map(c => c.label)).toContain("False statement to management");
    expect(r.pillars.find(p => p.key === "reporting")!.cells.find(c => c.label === "Accuracy to management")!.score).toBe(0);
  });

  it("a Sev-1 incident that was never declared is a critical error; an expired card scores 0 and costs the deadline cell", () => {
    const { events, add } = shift();
    const answers: { id: string; channel: string; expected_action: unknown }[] = [];
    card(add, answers, "44444444-4444-4444-8444-444444444444", "ciso_status", 200, "external");
    add("session.ended", "instr", 900);
    const r = review(events, answers);
    expect(r.criticalErrors.map(c => c.label)).toContain("A Sev-1 incident was never declared");
    expect(r.decisions[0]).toMatchObject({ state: "expired", score: 0, rank: null });
    expect(r.pillars.find(p => p.key === "stakeholders")!.cells.find(c => c.label === "Answered before the deadline")!.score).toBe(8);
    expect(r.indicators.trust).toBe(2);                                     // the timeout delta applied
  });

  it("the team's view carries the timeline and decisions, never the grades", () => {
    const { events, add } = shift();
    const answers: { id: string; channel: string; expected_action: unknown }[] = [];
    card(add, answers, "55555555-5555-4555-8555-555555555555", "ciso_status", 200, "external");
    add("decision.answered", "mgr", 230, { inject_id: "55555555-5555-4555-8555-555555555555", option: "o4", confidence: "high", rationale: "x" }, "mgr");
    add("session.ended", "instr", 900);
    const red = redactManagerReview(review(events, answers));
    expect(red.score).toBeNull();
    expect(red.pillars).toEqual([]);
    expect(red.decisions[0].rank).toBeNull();
    expect(red.decisions[0].optionLabel).toBe("Weak");
    expect(red.redacted).toBe(true);
  });

  it("one answered card and nothing else is not enough evidence for a command score", () => {
    const events: Ev[] = [{ seq: 1, type: "session.started", actor_id: "instr", role: null, payload: {}, occurred_at: at(0) }];
    const answers: { id: string; channel: string; expected_action: unknown }[] = [];
    const add = (type: string, actor_id: string | null, sec: number, payload: Record<string, unknown> = {}, role: string | null = null) => { events.push({ seq: events.length + 1, type, actor_id, role, payload, occurred_at: at(sec) }); };
    card(add, answers, "66666666-6666-4666-8666-666666666666", "owner_veto", 100, "external");
    add("decision.answered", "mgr", 130, { inject_id: "66666666-6666-4666-8666-666666666666", option: "o1", confidence: "high", rationale: "agreed limited containment" }, "mgr");
    add("session.ended", "instr", 600);
    const r = review(events, answers);
    expect(r.decisions[0].score).toBe(12);
    expect(r.score).toBeNull();
    expect(r.levelLabel).toBe("Not enough evidence");
  });

  it("stakeholder questions: on-time answers are graded; ruling out data after exfiltration is a critical error", () => {
    const { events, add } = shift();
    const answers: { id: string; channel: string; expected_action: unknown }[] = [];
    add("incident.declared", "mgr", 120, { severity: 1 }, "mgr");
    const q = (id: string, qid: string, sec: number, checks: string[]) => {
      add("stakeholder.asked", null, sec, { kind: "question", qid, inject_id: id, from: { name: "Noa Ben-Ami", role: "Legal counsel" }, channel: "chat", text: "Is data affected?", deadline_s: 240 });
      answers.push({ id, channel: "inject", expected_action: { qid, checks, model: "m", objective: "o", facts: { contained: false, suspectsData: true, severity: 1, target: "" } } });
    };
    q("77777777-7777-4777-8777-777777777777", "q_status", 200, ["substance", "status", "no_overclaim", "next_update"]);
    add("stakeholder.replied", "mgr", 260, { inject_id: "77777777-7777-4777-8777-777777777777", text: "We are still scoping two finance hosts, not contained yet. Next update in 15 minutes." }, "mgr");
    q("88888888-8888-4888-8888-888888888888", "q_data", 400, ["substance", "honest_data", "no_false_data", "next_update"]);
    add("stakeholder.replied", "mgr", 430, { inject_id: "88888888-8888-4888-8888-888888888888", text: "No personal data was affected, nothing left the network." }, "mgr");
    add("session.ended", "instr", 900);
    const r = review(events, answers);
    expect(r.questions.map(x => [x.qid, x.state])).toEqual([["q_status", "answered"], ["q_data", "answered"]]);
    expect(r.questions[0].score).toBe(12);
    expect(r.criticalErrors.map(c => c.label)).toContain("False statement to a stakeholder");
  });

  it("stakeholder report: early and complete scores; a kept next-update promise is credited", () => {
    const { events, add } = shift();
    add("incident.declared", "mgr", 120, { severity: 1 }, "mgr");
    add("stakeholder.report_sent", "mgr", 300, { audience: "ciso", status: "investigating", title: "Intrusion on finance", what_happened: "A finance workstation ran a malicious PowerShell download and contacted an external server", business_impact: "One finance laptop offline, the team works on spares", affected: ["WS-FIN-2847"], data_impact: "suspected", actions_taken: "host isolated, outbound blocked", known: "one host", unknown: "whether data left", next_update_min: 10 }, "mgr");
    add("sitrep.sent", "mgr", 800, { situation: "Scope confirmed on one finance host with suspected exfiltration", actions: "isolated and blocked", status: "investigating data impact", next: "legal briefing then update" }, "mgr");
    add("session.ended", "instr", 1500);
    const r = review(events, []);
    expect(r.reports).toHaveLength(1);
    expect(r.reports[0].completeness).toBe(100);
    expect(r.reports[0].promiseKept).toBe(true);
    expect(r.pillars.find(p => p.key === "reporting")!.cells.find(c => c.label === "Stakeholder report")!.score).toBe(12);
  });

  it("no SOC Manager seated: no Command Review", () => {
    const { events } = shift();
    expect(computeReport(events, roster.filter(m => m.role !== "mgr")).managerReview).toBeNull();
  });
});
