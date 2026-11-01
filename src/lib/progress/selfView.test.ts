import { describe, it, expect } from "vitest";
import { buildProgress, blindAttempts, firstPassPerIncident, reportQuality, median, p90, type RawRows, type ScenarioRow, type IncidentRow } from "./selfView";
import { answerRevealed } from "@/lib/org/mistakeView";
import { ROOMS_META } from "@/data/roomsMeta";

const NOW = Date.parse("2026-11-01T12:00:00Z");
const iso = (minsAgo: number) => new Date(NOW - minsAgo * 60_000).toISOString();
const empty = (): RawRows => ({ now: NOW, attempts: [], firsts: [], rooms: [], scenarios: [], sessions: [], incidents: [], quizzes: [], learning: [], lessons: [], edr: [], team: [], tacticOf: () => null });
const scen = (score: number, timeS: number, minsAgo: number, extra: Partial<ScenarioRow> = {}): ScenarioRow =>
  ({ slug: "phish", title: "Phishing", score, xp_earned: score, time_taken: timeS, completed_at: iso(minsAgo), report: null, ...extra });
const inc = (over: Partial<IncidentRow>): IncidentRow => ({
  id: 1, shift_key: "s1", incident_key: "i1", story_id: null, title: "Kerberoasting", company: null, severity: "high", mitre: ["T1558.003"],
  outcome: "passed", injected_at: iso(30), first_opened_at: iso(25), report_opened_at: iso(20), submitted_at: iso(15),
  report_score: 70, attack_score: 30, ioc_score: 24, action_score: 15, graded_by: "deterministic", feedback: null, strengths: [], gaps: [], summary: null, missed_tell: null, ...over,
});

describe("statistics", () => {
  it("median and p90 ignore order and survive one outlier", () => {
    expect(median([5, 1, 3])).toBe(3);
    expect(median([1, 2, 3, 400])).toBe(3); // (2+3)/2 rounded
    expect(p90([1, 2, 3, 4, 5, 6, 7, 8, 9, 100])).toBe(9);
    expect(median([])).toBeNull();
  });
});

describe("blind scenario attempts", () => {
  it("flags seconds-long submissions and keeps them out of the best score", () => {
    const rows = [scen(4, 8, 10), scen(4, 7, 20), scen(76, 1400, 30), scen(72, 1600, 40)];
    const blind = blindAttempts(rows);
    expect([...blind].map(r => r.time_taken).sort()).toEqual([7, 8]);
    const p = buildProgress({ ...empty(), scenarios: rows });
    const group = p.reports.scenarios[0];
    expect(group.best).toBe(76);
    expect(group.count).toBe(4);
    expect(group.attempts.filter(a => a.blind)).toHaveLength(2);
    // Only real attempts feed the scenario time median.
    expect(p.response.scenarios.count).toBe(2);
  });

  it("one timeline row per scenario, with every attempt listed", () => {
    const p = buildProgress({ ...empty(), scenarios: [scen(4, 8, 10), scen(76, 1400, 30)] });
    const rows = p.activity.timeline.filter(t => t.kind === "scenario");
    expect(rows).toHaveLength(1);
    expect(rows[0].attempts).toHaveLength(2);
    expect(rows[0].blind).toBe(true); // the latest attempt was the 8-second one
  });
});

describe("live-feed response times", () => {
  it("splits notice / investigate / write and measures the first PASSING report per incident", () => {
    const rows = [
      inc({ id: 1, outcome: "failed", submitted_at: iso(18) }),
      inc({ id: 2 }),                                  // first pass: 15 min after injection
      inc({ id: 3, submitted_at: iso(5) }),            // a re-submit after the pass: not a new response
    ];
    expect(firstPassPerIncident(rows).map(r => r.id)).toEqual([2]);
    const p = buildProgress({ ...empty(), incidents: rows });
    expect(p.response.live.source).toBe("incidents");
    expect(p.response.live.notice.median).toBe(5 * 60_000);
    expect(p.response.live.investigate.median).toBe(5 * 60_000);
    expect(p.response.live.write.median).toBe(5 * 60_000);
    expect(p.response.live.total.median).toBe(15 * 60_000);
    expect(p.response.live.total.withinTarget).toBe(100);
  });

  it("a missed attack is a critical miss with a practice room for its technique", () => {
    const p = buildProgress({ ...empty(), incidents: [inc({ outcome: "missed", report_score: null, missed_tell: "4769 with RC4" })] });
    expect(p.criticalMisses).toHaveLength(1);
    expect(p.criticalMisses[0].detail).toBe("4769 with RC4");
    expect(p.overview.tiles.missed.now).toBe(1);
  });
});

describe("report quality", () => {
  it("puts scenarios and incidents on one scale and names the part most often lowest", () => {
    const s = [1, 2, 3].map(i => scen(70, 900, 100 + i, { report: { rubric: { verdict: 25, depth: 20, evidence: 6, reasoning: 18 } } }));
    const q = reportQuality(s, [inc({})]);
    expect(q.points).toHaveLength(4);
    expect(q.points[0].evidence).toBe(20); // 6 of 30
    expect(q.weakest?.key).toBe("evidence");
  });
});

describe("topics and first try", () => {
  it("uses right-first-try per item and never rates an area under 5 questions", () => {
    const room = ROOMS_META.find(r => r.tasks.filter(t => t.type !== "reading").length >= 3)!;
    const tasks = room.tasks.filter(t => t.type !== "reading").slice(0, 3);
    const attempts = tasks.flatMap((t, i) => [
      { room_id: room.id, task_id: t.id, task_type: t.type, question_index: 0, attempt_no: 1, correct: i === 0, latency_ms: 20_000, created_at: iso(60 - i) },
      ...(i === 0 ? [] : [{ room_id: room.id, task_id: t.id, task_type: t.type, question_index: 0, attempt_no: 2, correct: true, latency_ms: 10_000, created_at: iso(50 - i) }]),
    ]);
    const p = buildProgress({ ...empty(), attempts });
    expect(p.skills.firstTry).toMatchObject({ items: 3, firstTryCorrect: 1 });
    expect(p.skills.persistence.solvedAfterRetry).toBe(2);
    const area = p.skills.areas.find(a => a.items > 0)!;
    expect(area.level).toBe("insufficient");
    expect(p.response.rooms.source).toBe("attempts");
    expect(p.response.rooms.count).toBe(3);
  });
});

describe("reveal rule for the learner's own mistakes", () => {
  it("never reveals an unsolved flag; multiple choice only after the second try", () => {
    expect(answerRevealed("flag", { solved: false, attempts: [1, 2, 3] }, "self")).toBe(false);
    expect(answerRevealed("flag", { solved: true, attempts: [1, 2] }, "self")).toBe(true);
    expect(answerRevealed("question", { solved: false, attempts: [1] }, "self")).toBe(false);
    expect(answerRevealed("analyst_choice", { solved: false, attempts: [1, 2] }, "self")).toBe(true);
    expect(answerRevealed("log_analysis", { solved: false, attempts: [1] }, "self")).toBe(true);
    // Staff always see the answer.
    expect(answerRevealed("flag", { solved: false, attempts: [1] }, "staff")).toBe(true);
  });
});
