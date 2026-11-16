/**
 * 0112 Tier-3 case work in the team report: the scope register is graded against the hosts the
 * attack really reached, and each readiness verdict against what was confirmed when it was signed.
 */
import { describe, it, expect } from "vitest";
import { computeReport } from "./computeReport";
import type { Ev, RosterMember } from "@/lib/team/types";

const T0 = Date.parse("2026-11-16T22:00:00.000Z");
const at = (sec: number) => new Date(T0 + sec * 1000).toISOString();
const member = (user_id: string, role: string): RosterMember => ({ user_id, role, status: "ready", name: `User ${user_id}`, handle: null });
const cell = (rubric: { label: string; score: number | null; value?: string }[], label: string) => {
  const c = rubric.find(r => r.label === label);
  if (!c) throw new Error(`no "${label}" in [${rubric.map(r => r.label).join(", ")}]`);
  return c;
};

function session() {
  const events: Ev[] = [];
  const add = (type: string, actor_id: string | null, sec: number, payload: Record<string, unknown> = {}, role: string | null = null) => {
    events.push({ seq: events.length + 1, type, actor_id, role, payload, occurred_at: at(sec) });
  };
  add("session.started", "instr", 0);
  // The attack reaches WS-1 first, then SRV-2 later; WS-9 is benign noise.
  add("feed.event", null, 10, { id: "a1", expected_verdict: "tp", incident_id: "inc1", hostname: "WS-1.corp.local", severity: "high" });
  add("feed.event", null, 20, { id: "n1", expected_verdict: "benign", hostname: "WS-9", severity: "low" });
  add("feed.event", null, 300, { id: "a2", expected_verdict: "tp", incident_id: "inc1", hostname: "SRV-2", severity: "high" });
  return { events, add };
}
const roster = [member("instr", "instructor"), member("x", "t3")];

describe("report: Tier-3 scope register (0112)", () => {
  it("full, correct scope scores 100; a wrong host and a missed host lower it", () => {
    const s = session();
    s.add("t3.scope.entity", "x", 100, { entity: "WS-1", entity_kind: "host", state: "confirmed", cites: [2] }, "t3");
    s.add("t3.scope.entity", "x", 400, { entity: "srv-2", entity_kind: "host", state: "confirmed", cites: [4] }, "t3");
    const u = computeReport(s.events, roster).perUser.find(p => p.user_id === "x")!;
    expect(cell(u.rubric, "Scope accuracy")).toMatchObject({ score: 12, value: "100%: found 2 of 2, 2 of 2 right" });

    const w = session();
    w.add("t3.scope.entity", "x", 100, { entity: "WS-1", state: "confirmed", cites: [2] }, "t3");
    w.add("t3.scope.entity", "x", 110, { entity: "WS-9", state: "confirmed", cites: [3] }, "t3");
    const v = computeReport(w.events, roster).perUser.find(p => p.user_id === "x")!;
    // recall 1/2 = 50, precision 1/2 = 50
    expect(cell(v.rubric, "Scope accuracy").value).toBe("50%: found 1 of 2, 1 of 2 right");
  });

  it("judges READY against the hosts reached when it was signed", () => {
    const s = session();
    s.add("t3.scope.entity", "x", 100, { entity: "WS-1", state: "confirmed", cites: [2] }, "t3");
    s.add("t3.readiness", "x", 120, { verdict: "ready", reason: "one host, confirmed" }, "t3");       // right: only WS-1 reached so far
    s.add("t3.readiness", "x", 350, { verdict: "ready", reason: "still one host" }, "t3");            // wrong: SRV-2 reached, not confirmed
    s.add("t3.readiness", "x", 360, { verdict: "not_ready", reason: "SRV-2 beaconing" }, "t3");       // right
    s.add("t3.readiness", "x", 370, { verdict: "unknown", reason: "?" }, "t3");                       // not judged
    const u = computeReport(s.events, roster).perUser.find(p => p.user_id === "x")!;
    expect(cell(u.rubric, "Readiness verdict").value).toBe("2 of 3 correct");
  });

  it("without the register the old field-count cell stays, and the new cells are empty", () => {
    const s = session();
    const u = computeReport(s.events, roster).perUser.find(p => p.user_id === "x")!;
    expect(cell(u.rubric, "Confirmed scope").score).toBeNull();
    expect(cell(u.rubric, "Readiness verdict").score).toBeNull();
  });
});
