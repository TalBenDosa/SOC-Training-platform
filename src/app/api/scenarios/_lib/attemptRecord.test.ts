import { describe, it, expect } from "vitest";
import {
  buildAttemptRow, clampTimeTaken, clampScenarioXp, xpDeltaFor,
  SCENARIO_XP_CAP, MAX_TIME_TAKEN_S, REPORT_TEXT_CAP,
} from "./attemptRecord";

const base = {
  userId: "u1", orgId: "org-1", slug: "multi-host-intrusion", title: "Multi-Host Intrusion",
  score: 92, xpEarned: 470, timeTaken: 1234.6, verdict: "tp",
  verdictReason: "reason", analystNotes: "notes", reportScore: 80,
  rubric: { verdict: 25, depth: 25, evidence: 18, reasoning: 12 }, passed: true,
  now: new Date("2026-09-28T10:47:00Z"),
};

describe("clampTimeTaken", () => {
  it("rounds to an integer within 0..86400", () => {
    expect(clampTimeTaken(1234.6)).toBe(1235);
    expect(clampTimeTaken(-5)).toBe(0);
    expect(clampTimeTaken(10 ** 9)).toBe(MAX_TIME_TAKEN_S);
    expect(clampTimeTaken("90")).toBe(90);
  });
  it("junk becomes 0", () => {
    for (const v of [undefined, null, NaN, Infinity, "abc", {}, []]) expect(clampTimeTaken(v)).toBe(0);
  });
});

describe("clampScenarioXp", () => {
  it("respects the 0..2000 DB CHECK", () => {
    expect(clampScenarioXp(470)).toBe(470);
    expect(clampScenarioXp(-10)).toBe(0);
    expect(clampScenarioXp(999999)).toBe(SCENARIO_XP_CAP);
    expect(clampScenarioXp(NaN)).toBe(0);
  });
});

describe("buildAttemptRow", () => {
  it("builds the scenario_history row with server-computed values", () => {
    const row = buildAttemptRow(base);
    expect(row).toMatchObject({
      user_id: "u1", org_id: "org-1", slug: "multi-host-intrusion", title: "Multi-Host Intrusion",
      score: 92, xp_earned: 470, time_taken: 1235, completed_at: "2026-09-28T10:47:00.000Z",
      report: { verdict: "tp", verdictReason: "reason", notes: "notes", reportScore: 80, passed: true },
    });
  });

  it("omits org_id when there is no org claim (NOT NULL column → DEFAULT applies)", () => {
    const row = buildAttemptRow({ ...base, orgId: null });
    expect("org_id" in row).toBe(false);
  });

  it("caps report text and normalises an unknown verdict", () => {
    const long = "x".repeat(REPORT_TEXT_CAP + 500);
    const row = buildAttemptRow({ ...base, verdict: "definitely-evil", analystNotes: long, verdictReason: 42 });
    const report = row.report as Record<string, unknown>;
    expect((report.notes as string).length).toBe(REPORT_TEXT_CAP);
    expect(report.verdictReason).toBe("");
    expect(report.verdict).toBeNull();
  });

  it("clamps an out-of-range score and XP", () => {
    const row = buildAttemptRow({ ...base, score: 140, xpEarned: 5000 });
    expect(row.score).toBe(100);
    expect(row.xp_earned).toBe(SCENARIO_XP_CAP);
  });
});

describe("xpDeltaFor — only the best attempt counts", () => {
  it("first attempt adds the full run", () => {
    expect(xpDeltaFor(260, 0)).toEqual({ xpDelta: 260, bestXp: 260, improved: true });
    expect(xpDeltaFor(260, null)).toEqual({ xpDelta: 260, bestXp: 260, improved: true });
  });
  it("a better retry adds only the improvement", () => {
    expect(xpDeltaFor(470, 260)).toEqual({ xpDelta: 210, bestXp: 470, improved: true });
  });
  it("a worse or equal retry adds nothing", () => {
    expect(xpDeltaFor(200, 470)).toEqual({ xpDelta: 0, bestXp: 470, improved: false });
    expect(xpDeltaFor(470, 470)).toEqual({ xpDelta: 0, bestXp: 470, improved: false });
  });
});
