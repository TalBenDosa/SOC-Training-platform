import { describe, it, expect, beforeEach } from "vitest";
import { describeScenarioXp } from "./scenarioXp";
import {
  bestScenarioXp, scenarioXpDelta, recordScenarioCompletion, getScenarioHistory, getTotalXp, setTotalXp,
  type ScenarioRecord,
} from "./progress";
import { setStorageBackend, localStorageBackend } from "./backend";

const rec = (slug: string, xpEarned: number): ScenarioRecord => ({
  slug, title: slug, score: 70, xpEarned, timeTaken: 60, date: "2026-09-28T10:00:00Z",
});

describe("describeScenarioXp (#30 truthful completion XP)", () => {
  it("first attempt: the full run XP counts", () => {
    const v = describeScenarioXp({ xpEarned: 260, xpDelta: 260, prevBestXp: 0, bestXp: 260 });
    expect(v).toMatchObject({ added: 260, label: "XP Earned", note: null });
  });

  it("improvement: shows only the delta over the previous best", () => {
    const v = describeScenarioXp({ xpEarned: 470, xpDelta: 210, prevBestXp: 260, bestXp: 470 });
    expect(v.added).toBe(210);
    expect(v.label).toBe("XP Gained");
    expect(v.note).toContain("260 → 470");
  });

  it("no improvement: +0 and says what the best was", () => {
    const v = describeScenarioXp({ xpEarned: 200, xpDelta: 0, prevBestXp: 470, bestXp: 470 });
    expect(v.added).toBe(0);
    expect(v.label).toBe("No New XP");
    expect(v.note).toContain("best on this scenario is 470 XP");
  });

  it("server gave no delta: falls back to the run XP, labelled as such", () => {
    const v = describeScenarioXp({ xpEarned: 300 });
    expect(v).toMatchObject({ added: 300, label: "XP This Run", headlineOnly: true });
  });

  it("flags an attempt that couldn't be saved", () => {
    expect(describeScenarioXp({ xpEarned: 300, persisted: false }).note).toMatch(/couldn't be saved/);
  });
});

describe("scenario XP facade helpers", () => {
  beforeEach(() => {
    window.localStorage.clear();
    setStorageBackend(localStorageBackend);
  });

  it("bestScenarioXp takes the max for that slug only", () => {
    expect(bestScenarioXp([rec("a", 100), rec("a", 300), rec("b", 900)], "a")).toBe(300);
    expect(bestScenarioXp([], "a")).toBe(0);
  });

  it("scenarioXpDelta prefers the server delta, else derives from local history", () => {
    expect(scenarioXpDelta({ xpEarned: 470, xpDelta: 210 }, [], "a")).toBe(210);
    expect(scenarioXpDelta({ xpEarned: 470 }, [rec("a", 260)], "a")).toBe(210);
    expect(scenarioXpDelta({ xpEarned: 200 }, [rec("a", 470)], "a")).toBe(0);
  });

  it("recordScenarioCompletion adds only the improvement when no server total is given", () => {
    setTotalXp(1000);
    recordScenarioCompletion(rec("a", 260), { xpEarned: 260 });
    expect(getTotalXp()).toBe(1260);
    // A worse retry: recorded in history, but the total does not move.
    recordScenarioCompletion(rec("a", 200), { xpEarned: 200 });
    expect(getTotalXp()).toBe(1260);
    // A better retry: only the +210 improvement.
    recordScenarioCompletion(rec("a", 470), { xpEarned: 470 });
    expect(getTotalXp()).toBe(1470);
    expect(getScenarioHistory()).toHaveLength(3);
  });

  it("recordScenarioCompletion adopts the server's authoritative total when present", () => {
    setTotalXp(1000);
    recordScenarioCompletion(rec("a", 470), { xpEarned: 470, xpDelta: 210, totalXp: 2567 });
    expect(getTotalXp()).toBe(2567);
  });
});

describe("describeScenarioXp — incomplete attempt", () => {
  it("says the run was not recorded and shows no XP", () => {
    const v = describeScenarioXp({ xpEarned: 120, persisted: false, debriefWithheld: true });
    expect(v.added).toBe(0);
    expect(v.label).toBe("Not Recorded");
  });
});
