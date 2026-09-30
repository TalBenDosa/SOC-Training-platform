import { describe, it, expect, vi } from "vitest";
vi.mock("server-only", () => ({}));
import { teamLoad, LOAD_RULES } from "./load";
import { buildTeamTimeline } from "./buildTimeline";

const r = (...roles: string[]) => roles.map(role => ({ role, status: "ready" }));

describe("teamLoad — log pace follows the Tier-1 count", () => {
  it("a lone Tier-1 gets the per-analyst rate, not a floor's worth", () => {
    expect(teamLoad("medium", r("t1", "t2", "mgr")).logsPerMin).toBe(2);
    expect(teamLoad("easy", r("t1")).logsPerMin).toBe(1.5);
    expect(teamLoad("hard", r("t1", "t2")).logsPerMin).toBe(2.5);
  });
  it("grows with each Tier-1, up to the room cap", () => {
    expect(teamLoad("medium", r("t1", "t1", "t2")).logsPerMin).toBe(4);
    expect(teamLoad("medium", r("t1", "t1", "t1", "t1", "t1")).logsPerMin).toBe(LOAD_RULES.maxLogsPerMin.medium);
  });
  it("non-triage roles and non-players don't raise the pace", () => {
    const base = teamLoad("medium", r("t1")).logsPerMin;
    expect(teamLoad("medium", r("t1", "t2", "t3", "mgr", "ti", "instructor", "observer")).logsPerMin).toBe(base);
  });
  it("members who left don't count", () => {
    expect(teamLoad("medium", [{ role: "t1", status: "ready" }, { role: "t1", status: "left" }]).logsPerMin).toBe(2);
  });
  it("a team with no Tier-1 still gets one analyst's pace (someone triages)", () => {
    expect(teamLoad("medium", r("t2", "mgr")).triageAnalysts).toBe(1);
  });
  it("mean gap matches the rate (base + half the jitter)", () => {
    const l = teamLoad("medium", r("t1"));
    expect(l.baseGapMs + l.jitterMs / 2).toBeCloseTo(30_000, -2);
  });
});

describe("teamLoad — attacks follow team size", () => {
  it("more players → more concurrent stories and standalone attacks", () => {
    const small = teamLoad("medium", r("t1", "t2"));
    const big = teamLoad("medium", r("t1", "t1", "t2", "t2", "t3", "mgr", "ti", "t1"));
    expect(small.stories).toBe(1);
    expect(big.stories).toBe(2);
    expect(big.poolAttacks).toBeGreaterThan(small.poolAttacks);
  });
  it("hard adds a third story for a large team; easy stays single-threaded for small groups", () => {
    expect(teamLoad("hard", r("t1", "t1", "t2", "t2", "t3", "mgr", "ti")).stories).toBe(3);
    expect(teamLoad("easy", r("t1", "t2", "mgr")).stories).toBe(1);
    expect(teamLoad("easy", r("t1", "t2")).poolAttacks).toBe(0);
  });
  it("attacks stay a minority of the feed even for the smallest room", () => {
    const l = teamLoad("hard", r("t1"));
    expect(l.noiseCount).toBeGreaterThanOrEqual((l.stories * 10 + l.poolAttacks * 2) * 2);
  });
});

describe("buildTeamTimeline with a team load", () => {
  const feedOf = (t: ReturnType<typeof buildTeamTimeline>) => t.filter(e => e.channel === "feed");
  const rate = (t: ReturnType<typeof buildTeamTimeline>) => {
    const f = feedOf(t);
    const spanMin = (f[f.length - 1].due_offset_ms - f[0].due_offset_ms) / 60_000;
    return f.length / spanMin;
  };
  it("a solo Tier-1 room gets a markedly slower feed than a four-analyst floor", () => {
    const solo = buildTeamTimeline("nexacorp", "medium", "seed-1", null, teamLoad("medium", r("t1", "t2", "mgr")));
    const floor = buildTeamTimeline("nexacorp", "medium", "seed-1", null, teamLoad("medium", r("t1", "t1", "t1", "t2", "t2", "mgr")));
    expect(rate(solo)).toBeLessThan(3);          // ~2/min + a few inject-support logs
    expect(rate(floor)).toBeGreaterThan(rate(solo) * 1.8);
  });
  it("the shift length holds regardless of the team", () => {
    const len = (t: ReturnType<typeof buildTeamTimeline>) => feedOf(t).at(-1)!.due_offset_ms / 60_000;
    const solo = buildTeamTimeline("nexacorp", "medium", "seed-2", null, teamLoad("medium", r("t1")));
    const floor = buildTeamTimeline("nexacorp", "medium", "seed-2", null, teamLoad("medium", r("t1", "t1", "t1", "t2")));
    expect(Math.abs(len(solo) - len(floor))).toBeLessThan(8);
    expect(len(solo)).toBeGreaterThan(25);
  });
  it("a bigger team gets more malicious activity in the answer key", () => {
    const tp = (t: ReturnType<typeof buildTeamTimeline>) =>
      new Set(feedOf(t).filter(e => ["tp", "escalate"].includes(String((e.answer as { expected_verdict?: string } | undefined)?.expected_verdict))).map(e => (e.answer as { incident_id?: string }).incident_id)).size;
    const small = buildTeamTimeline("nexacorp", "medium", "seed-3", null, teamLoad("medium", r("t1", "t2")));
    const big = buildTeamTimeline("nexacorp", "medium", "seed-3", null, teamLoad("medium", r("t1", "t1", "t2", "t2", "t3", "mgr", "ti", "t1")));
    expect(tp(big)).toBeGreaterThan(tp(small));
  });
});
