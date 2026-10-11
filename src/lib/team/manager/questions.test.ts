// Stakeholder questions: asked only from what really happened (declaration, a real isolation,
// the team's own words about data, a real severity change), paced, and replies checked by
// deterministic rules against the facts at the time of asking.
import { describe, expect, it } from "vitest";
import type { Ev } from "@/lib/team/types";
import { buildMgrState, type Member } from "./state";
import { QUESTIONS, pickQuestion, materializeQuestion, checkReply, QUESTION_SPACING_MS } from "./questions";

const T0 = Date.parse("2026-10-10T10:00:00.000Z");
const at = (min: number) => new Date(T0 + min * 60_000).toISOString();
let seq = 0;
const ev = (type: string, min: number, payload: Record<string, unknown> = {}, actor: string | null = null, role: string | null = null): Ev =>
  ({ seq: ++seq, type, actor_id: actor, role, payload, occurred_at: at(min) });
const ROSTER: Member[] = [
  { user_id: "u-t1", role: "t1", status: "joined", name: "Avi" },
  { user_id: "u-t2", role: "t2", status: "joined", name: "Dana" },
  { user_id: "u-mgr", role: "mgr", status: "joined", name: "Noam" },
];
const state = (events: Ev[], nowMin: number, difficulty: "easy" | "medium" | "hard" = "hard") =>
  buildMgrState({ events, roster: ROSTER, nowMs: T0 + nowMin * 60_000, difficulty });
const eligible = (events: Ev[], nowMin: number) => { const s = state(events, nowMin); return new Set(QUESTIONS.filter(q => q.when(s)).map(q => q.id)); };
const declare = (min: number, severity = 2) => ev("incident.declared", min, { severity }, "u-mgr", "mgr");
const esc = (min: number) => ev("escalation.requested", min, { event_id: "e1", summary: "PowerShell cradle", hostname: "WS-FIN-2901" }, "u-t1", "t1");

describe("questions come only from what happened", () => {
  it("nothing before the incident is declared, however long the shift runs", () => {
    expect(pickQuestion(state([esc(1)], 40))).toBeNull();
  });

  it("the CISO asks for status shortly after the declaration", () => {
    expect(eligible([esc(1), declare(2)], 2.5).has("q_status")).toBe(false);
    expect(eligible([esc(1), declare(2)], 3).has("q_status")).toBe(true);
  });

  it("the head of a department asks about their system only after it was really isolated, and names it", () => {
    const base = [esc(1), declare(2)];
    expect(eligible(base, 6).has("q_business")).toBe(false);
    const iso = [...base, ev("edr.host_isolated", 4, { host: "WS-FIN-2901" }, "u-t2", "t2")];
    const s = state(iso, 6);
    const q = QUESTIONS.find(x => x.id === "q_business")!;
    const m = materializeQuestion(q, q.when(s)!, s);
    expect(m.body.text).toContain("WS-FIN-2901");
    expect(m.body.from.role).toBe("Head of Finance");
  });

  it("Legal asks about data when the team itself wrote about data leaving", () => {
    const base = [esc(1), declare(2, 3)];
    expect(eligible(base, 4).has("q_data")).toBe(false);
    expect(eligible([...base, ev("message.sent", 3, { text: "seeing rclone upload to cloud" }, "u-t2", "t2")], 4).has("q_data")).toBe(true);
  });

  it("the CEO's office asks about a severity change only after a real one", () => {
    const base = [esc(1), declare(2)];
    expect(eligible(base, 5).has("q_sev_change")).toBe(false);
    expect(eligible([...base, ev("incident.severity_changed", 4, { severity: 1, reason: "exfil confirmed" }, "u-mgr", "mgr")], 5).has("q_sev_change")).toBe(true);
  });

  it("pacing: spaced, at most two open, within the budget; no manager, no questions", () => {
    const base = [esc(1), declare(2)];
    const asked = (qid: string, min: number) => ev("stakeholder.asked", min, { qid, inject_id: `q-${qid}`, deadline_s: 240 });
    expect(pickQuestion(state([...base, asked("q_status", 3)], 3.5))).toBeNull();                                    // spacing
    expect(pickQuestion(state([...base, asked("q_status", 3)], 3 + QUESTION_SPACING_MS / 60_000 + 0.1))).toBeNull();   // spaced, but nothing new happened
    expect(pickQuestion(state([...base, asked("q_status", 3)], 7))?.def.id).toBe("q_eta");                            // 5 min into the incident: the CEO wants a time
    const two = [...base, asked("q_status", 3), asked("q_eta", 5.5)];
    expect(pickQuestion(state(two, 6))).toBeNull();                                                                  // two open
    const s = buildMgrState({ events: base, roster: ROSTER.filter(m => m.role !== "mgr"), nowMs: T0 + 10 * 60_000, difficulty: "hard" });
    expect(pickQuestion(s)).toBeNull();
  });

  it("no answer key in the public body", () => {
    const s = state([esc(1), declare(2)], 3);
    const q = QUESTIONS.find(x => x.id === "q_status")!;
    const m = materializeQuestion(q, q.when(s)!, s);
    expect(JSON.stringify(m.body)).not.toMatch(/checks|model|facts/);
    expect(m.answer.checks.length).toBeGreaterThan(0);
  });

  it("no em dash in any question", () => {
    const s = state([esc(1), declare(2), ev("edr.host_isolated", 4, { host: "WS-FIN-2901" }, "u-t2", "t2"), ev("incident.severity_changed", 4, { severity: 1, reason: "x" }, "u-mgr", "mgr")], 30);
    for (const q of QUESTIONS) {
      const b = q.build(q.when(s) ?? { target: "H", dept: "Finance", sev: "1", open: "1" }, s);
      expect([b.text, b.model, b.objective].join(" ").includes("—"), q.id).toBe(false);
    }
  });
});

describe("checking a reply", () => {
  const facts = (o: Partial<{ contained: boolean; suspectsData: boolean; severity: number | null; target: string }> = {}) =>
    ({ contained: false, suspectsData: false, severity: 2, target: "", ...o });

  it("a strong status answer passes; 'it's contained' before it is fails", () => {
    const good = checkReply("We are still scoping: one finance workstation is isolated, two more are being checked. Not contained yet. Next update in 15 minutes.", { checks: ["substance", "status", "no_overclaim", "next_update"], facts: facts() });
    expect(good.score).toBe(12);
    const bad = checkReply("It's contained, all good.", { checks: ["substance", "status", "no_overclaim", "next_update"], facts: facts() });
    expect(bad.checks.find(c => c.id === "no_overclaim")!.ok).toBe(false);
    expect(bad.score).toBeLessThan(6);
  });

  it("ETA: a time, or an honest 'not known yet' with a next update; a vague answer fails", () => {
    const k = { checks: ["eta"] as const, facts: facts() };
    expect(checkReply("If the scope holds, about 30 minutes.", { ...k, checks: [...k.checks] }).score).toBe(12);
    expect(checkReply("We don't know yet; I'll update you in 20 minutes.", { ...k, checks: [...k.checks] }).score).toBe(12);
    expect(checkReply("Soon, we are working hard on it.", { ...k, checks: [...k.checks] }).score).toBe(0);
  });

  it("ruling out data loss while the team suspects it fails; 'no evidence so far' passes", () => {
    const k = { checks: ["no_false_data", "honest_data"] as ("no_false_data" | "honest_data")[], facts: facts({ suspectsData: true }) };
    expect(checkReply("No personal data was affected.", k).checks.find(c => c.id === "no_false_data")!.ok).toBe(false);
    expect(checkReply("Suspected, under investigation: we see an upload to cloud storage and are checking what it held.", k).score).toBe(12);
  });

  it("a severity named in the answer must match the declaration", () => {
    const k = { checks: ["severity_consistent"] as "severity_consistent"[], facts: facts({ severity: 1 }) };
    expect(checkReply("We moved it to Sev-1 because data left the network.", k).score).toBe(12);
    expect(checkReply("This is a Sev-3, minor.", k).score).toBe(0);
  });
});
