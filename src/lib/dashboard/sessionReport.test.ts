import { describe, expect, it } from "vitest";
import { buildSessionReport, SESSION_LIMIT_MS, type SessionFacts } from "./sessionReport";

const T0 = Date.parse("2026-11-12T10:00:00Z");
const base: SessionFacts = {
  company: "nexacorp", difficulty: "easy", startedAt: T0, endedAt: T0 + SESSION_LIMIT_MS, endedBy: "time",
  presented: 0, caught: 0, missed: [], reports: [], eventsOpened: 0, responseTargetSec: 900, edrInvestigations: 0, xp: 0,
};
const report = (id: string, score: number, min: number, sub = { attack: 32, ioc: 24, action: 21 }, detectMin = 2) => ({
  incidentId: id, title: `Attack ${id}`, score, passed: score >= 60, subScores: sub,
  injectedAt: T0 + 60_000, firstOpenedAt: T0 + (1 + detectMin) * 60_000, at: T0 + min * 60_000,
});

describe("end-of-training report", () => {
  it("a session is capped at 30 minutes", () => expect(SESSION_LIMIT_MS).toBe(1_800_000));

  it("a shift with nothing in it says so instead of grading", () => {
    const r = buildSessionReport(base);
    expect(r.overall).toBeNull();
    expect(r.band).toBe("not_enough_data");
    expect(r.metrics.every(m => m.status === "na")).toBe(true);
  });

  it("a strong shift meets its targets and has no improvement areas", () => {
    const r = buildSessionReport({ ...base, presented: 2, caught: 2, edrInvestigations: 2, reports: [report("a", 88, 9, { attack: 36, ioc: 28, action: 24 }), report("b", 84, 22, { attack: 34, ioc: 27, action: 23 })] });
    expect(r.band).toBe("excellent");
    expect(r.improvements).toEqual([]);
    expect(r.strengths.length).toBeGreaterThanOrEqual(5);
  });

  it("a missed attack and thin evidence come out as the first things to improve, with concrete steps", () => {
    const r = buildSessionReport({ ...base, presented: 2, caught: 1, edrInvestigations: 1,
      missed: [{ title: "Password spray against the VPN", techniques: ["T1110.003"], tell: "40 failed sign-ins from one address" }],
      reports: [report("a", 45, 10, { attack: 30, ioc: 6, action: 9 }), report("a", 66, 16, { attack: 32, ioc: 14, action: 20 })] });
    expect(r.improvements[0].metric).toBe("detection");
    expect(r.improvements[0].why).toContain("Password spray");
    expect(r.improvements.map(i => i.metric)).toContain("evidence");
    expect(r.improvements.length).toBeLessThanOrEqual(3);
    for (const i of r.improvements) expect(i.how.length).toBeGreaterThan(0);
    // The retried report counts as the incident's result; the first attempt counts for the first-pass rate.
    expect(r.metrics.find(m => m.id === "report_quality")!.value).toBe("66/100");
    expect(r.metrics.find(m => m.id === "first_pass")!.value).toBe("0/1");
  });

  it("an attack with no report at all asks for the report", () => {
    const r = buildSessionReport({ ...base, presented: 1, caught: 0, missed: [{ title: "Phishing", techniques: [], tell: "" }] });
    expect(r.improvements.map(i => i.metric)).toEqual(expect.arrayContaining(["detection", "report_quality"]));
    expect(r.overall).toBe(0);
  });

  it("slow detection is measured from the attack's first row", () => {
    const r = buildSessionReport({ ...base, presented: 1, caught: 1, edrInvestigations: 1, reports: [report("a", 80, 25, undefined, 15)] });
    const m = r.metrics.find(x => x.id === "time_to_detect")!;
    expect(m.value).toBe("15m 00s");
    expect(m.status).toBe("below");
  });
});
