import { describe, it, expect } from "vitest";
import type { Ev, RosterMember } from "./types";
import type { TimelineEntry } from "./buildTimeline";
import { pickShiftLead, leadText } from "./shiftLead";
import { closedCases, consultsOf, shiftLeadOf, t3Waiting } from "./t3Work";
import { nextStep } from "./t3Case";
import { computeReport } from "./report/computeReport";

const feedEntry = (at: number, host: string, verdict: string, sev = "low"): TimelineEntry =>
  ({ due_offset_ms: at, channel: "feed", body: { id: `f${at}`, hostname: host, severity: sev }, answer: { expected_verdict: verdict } });

describe("stage C: the open lead", () => {
  const tl = [
    feedEntry(1_000, "WS-QUIET", "benign"), feedEntry(5_000, "WS-QUIET", "benign"),
    feedEntry(60_000, "WS-ATTACK", "tp"), feedEntry(90_000, "SRV-2", "tp"),
  ];
  it("needs a Tier-3 seat", () => {
    expect(pickShiftLead(tl, { seed: "s", difficulty: "medium", hasTier3: false })).toBeNull();
  });
  it("on easy it always points at the attack's first host, a little after that host's first log", () => {
    const l = pickShiftLead(tl, { seed: "anything", difficulty: "easy", hasTier3: true })!;
    expect(l.body).toMatchObject({ kind: "t3_lead", host: "WS-ATTACK" });
    expect(l.answer).toEqual({ kind: "t3_lead", lead_truth: "compromised" });
    expect(l.due_offset_ms).toBe(80_000);
  });
  it("otherwise the seed picks the attack or a quiet host, with the same text either way", () => {
    const picks = Array.from({ length: 40 }, (_, i) => pickShiftLead(tl, { seed: `seed-${i}`, difficulty: "hard", hasTier3: true })!);
    const truths = new Set(picks.map(p => p.answer!.lead_truth));
    expect(truths).toEqual(new Set(["compromised", "clean"]));
    for (const p of picks) {
      expect(p.body.text).toBe(leadText(String(p.body.host)));
      expect(p.body).not.toHaveProperty("lead_truth");
      if (p.answer!.lead_truth === "clean") expect(p.body.host).toBe("WS-QUIET");
    }
  });
});

const at = (s: number) => new Date(Date.UTC(2026, 10, 16, 22, 0, s)).toISOString();
const E = (seq: number, type: string, actor: string | null, payload: Record<string, unknown>, sec = seq): Ev => ({ seq, type, actor_id: actor, role: null, payload, occurred_at: at(sec) });

describe("stage C: own work from the events", () => {
  const feed = [
    E(1, "feed.event", null, { id: "a1", hostname: "WS-1", severity: "high", description: "Encoded PowerShell" }),
    E(2, "feed.event", null, { id: "n1", hostname: "WS-2", severity: "high", description: "Patch agent update" }),
    E(3, "feed.event", null, { id: "n2", hostname: "WS-3", severity: "low", description: "DNS" }),
  ];
  const events = [
    ...feed,
    E(4, "staff.inject", null, { kind: "t3_lead", host: "WS-1", text: "lead" }),
    E(5, "disposition.set", "t1", { event_id: "a1", verdict: "false_positive" }),
    E(6, "disposition.set", "t1", { event_id: "n1", verdict: "benign" }),
    E(7, "disposition.set", "t1", { event_id: "n2", verdict: "benign" }),
    E(8, "consult.asked", "t2", { event_id: "n1", question: "Is WS-2 infected or is this the patch agent?" }),
  ];
  it("lists alerts closed as benign (not quiet logs), newest first, without who closed them", () => {
    const c = closedCases(events, feed);
    expect(c.map(x => x.eventId)).toEqual(["n1", "a1"]);
    expect(Object.keys(c[0])).not.toContain("by");
    expect(closedCases([...events, E(9, "review.verdict", "t3", { event_id: "n1", decision: "agree" })], feed).map(x => x.eventId)).toEqual(["a1"]);
  });
  it("tracks consults and the lead, and the next step points at them", () => {
    expect(consultsOf(events)[0]).toMatchObject({ eventId: "n1", answer: null });
    expect(shiftLeadOf(events)).toMatchObject({ host: "WS-1", opened: false });
    const w = t3Waiting(events, feed);
    expect(w).toMatchObject({ consults: 1, reviews: 2 });
    expect(nextStep(events, { leadHost: w.lead?.host, consults: w.consults, reviews: w.reviews }).text).toMatch(/Open the lead the previous shift left on WS-1/);
    const answered = [...events, E(9, "consult.answered", "t3", { consult_seq: 8, answer: "not_infected", reason: "signed patch agent" })];
    expect(consultsOf(answered)[0].answer?.value).toBe("not_infected");
  });
});

describe("stage C: the report", () => {
  const member = (user_id: string, role: string): RosterMember => ({ user_id, role, status: "ready", name: user_id, handle: null });
  const roster = [member("instr", "instructor"), member("t1", "t1"), member("t2", "t2"), member("x", "t3")];
  const base = (truth: "compromised" | "clean") => [
    E(1, "session.started", "instr", {}),
    E(2, "feed.event", null, { id: "a1", hostname: "WS-1", severity: "high", expected_verdict: "tp", incident_id: "i1" }),
    E(3, "feed.event", null, { id: "n1", hostname: "WS-2", severity: "high", expected_verdict: "benign" }),
    E(4, "staff.inject", null, { kind: "t3_lead", host: truth === "compromised" ? "WS-1" : "WS-2", text: "lead", lead_truth: truth }),
  ];
  const cell = (u: { rubric: { label: string; score: number | null; value?: string }[] }, label: string) => u.rubric.find(r => r.label === label);
  it("scores the lead, consults and closure reviews against the truth", () => {
    const ev = [
      ...base("clean"),
      E(5, "t3.scope.entity", "x", { entity: "WS-2", state: "suspected" }),
      E(6, "t3.scope.entity", "x", { entity: "WS-2", state: "cleared", reason: "patch agent, change ticket CHG-12" }),
      E(7, "disposition.set", "t1", { event_id: "a1", verdict: "false_positive" }),
      E(8, "review.verdict", "x", { event_id: "a1", decision: "reopen", reason: "encoded PowerShell from Word" }), // right: a real miss
      E(9, "consult.asked", "t2", { event_id: "n1", question: "Is WS-2 infected or not?" }),
      E(10, "consult.answered", "x", { consult_seq: 9, answer: "infected", reason: "looked odd to me" }),   // wrong
    ];
    const u = computeReport(ev, roster).perUser.find(p => p.user_id === "x")!;
    expect(cell(u, "Open lead")).toMatchObject({ score: 12, value: "cleared; it was clean" });
    expect(cell(u, "Professional authority")).toMatchObject({ value: "1 of 2 right" });
    const r = computeReport(ev, roster);
    expect(r.team.injects.find((i: { kind: string }) => i.kind === "t3_lead")).toMatchObject({ scored: true, handled: true });
  });
  it("an unopened lead is open, not right", () => {
    const u = computeReport(base("compromised"), roster).perUser.find(p => p.user_id === "x")!;
    expect(cell(u, "Open lead")).toMatchObject({ score: 0, value: "not opened; it was compromised" });
  });
});
