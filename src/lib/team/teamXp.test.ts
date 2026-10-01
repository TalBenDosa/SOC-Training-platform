// 0087: team training earns XP from the player's own activity in the shift.
import { describe, it, expect } from "vitest";
import { teamXpFor, TEAM_XP_MAX } from "./teamXp";

const u = (o: Partial<Parameters<typeof teamXpFor>[0]> = {}) => ({
  role: "t1", opened: 10, dispCount: 6, dispCorrect: 5, escCount: 1, acks: 0, contReq: 0, contDecided: 0,
  roleActions: 1, contribution: 70, rubricPct: 80, insufficientEvidence: false, isoCorrect: 0, ...o,
});

describe("teamXpFor", () => {
  it("an active Tier-1 earns participation + activity + rubric + accuracy", () => {
    expect(teamXpFor(u())).toBe(25 + 35 + 80 + 10);
  });
  it("no actions (only opened logs) → 0; instructors / observers → 0", () => {
    expect(teamXpFor(u({ dispCount: 0, escCount: 0, roleActions: 0 }))).toBe(0);
    expect(teamXpFor(u({ role: "instructor" }))).toBe(0);
    expect(teamXpFor(u({ role: "observer" }))).toBe(0);
  });
  it("insufficient evidence pays activity, not a guessed rubric", () => {
    expect(teamXpFor(u({ insufficientEvidence: true }))).toBe(25 + 35 + 0 + 10);
  });
  it("more and better work earns more, capped", () => {
    expect(teamXpFor(u({ contribution: 100, rubricPct: 95, dispCorrect: 9 }))).toBeGreaterThan(teamXpFor(u()));
    expect(teamXpFor(u({ contribution: 100, rubricPct: 100, dispCorrect: 50, isoCorrect: 5 }))).toBeLessThanOrEqual(TEAM_XP_MAX);
  });
  it("a manager's SITREPs / approvals count as activity", () => {
    expect(teamXpFor(u({ role: "mgr", dispCount: 0, dispCorrect: 0, escCount: 0, roleActions: 3, contDecided: 1, contribution: 65, rubricPct: 70 }))).toBe(25 + 33 + 70);
  });
});
