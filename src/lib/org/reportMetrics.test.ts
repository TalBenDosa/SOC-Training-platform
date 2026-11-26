import { describe, it, expect } from "vitest";
import { activityOf, lastSeenOf, latestOf } from "./activity";
import { lastSeenAt, metricsOf, reportNarrative, sanitizeReportMetrics } from "./reportMetrics";
import type { StudentDetail } from "@/app/api/org/students/[id]/route";

const NOW = Date.parse("2026-11-11T12:00:00Z");
const daysAgo = (d: number) => new Date(NOW - d * 86_400_000).toISOString();

function student(over: Partial<StudentDetail> = {}): StudentDetail {
  return {
    user_id: "u", handle: "noa", display_name: "Noa Levi", role: "student", status: "active", joined_at: daysAgo(40), affiliation_expires_at: null,
    xp: 1000, level: 3, last_active_at: daysAgo(1), last_seen_at: daysAgo(1),
    summary: { rooms_completed: 3, rooms_started: 4, scenarios_completed: 1, scenario_avg_score: 70, sessions: 2, avg_detect_rate: 60, median_decision_latency_ms: 30_000, tasks_answered: 50,
      first_try: { items: 50, firstTryCorrect: 35, accuracy: 70, unsolved: 2 } },
    skills: [
      { area: "email", label: "Email", items: 20, firstTryCorrect: 18, accuracy: 90, sources: { room: 20, quiz: 0, lesson: 0, scenario: 0 } },
      { area: "siem", label: "SIEM and KQL", items: 10, firstTryCorrect: 4, accuracy: 40, sources: { room: 10, quiz: 0, lesson: 0, scenario: 0 } },
    ] as unknown as StudentDetail["skills"],
    recommendations: [{ room_id: "r", title: "Microsoft Sentinel Fundamentals", difficulty: "intermediate", area_label: "SIEM and KQL" }],
    mistake_groups: [], rooms: [], scenarios: [], sessions: [],
    activity: { last_sign_in_at: daysAgo(1), active_days_7: 3, active_days_30: 9, answered_7: 10, answered_30: 40, weeks: [1, 2, 2, 3] },
    ...over,
  };
}

describe("activity", () => {
  it("counts distinct active days and answers per window", () => {
    const a = activityOf([daysAgo(0), daysAgo(0.2), daysAgo(3), daysAgo(10), daysAgo(40)], [daysAgo(1), daysAgo(20)], null, NOW);
    expect(a.active_days_7).toBe(2);
    expect(a.active_days_30).toBe(3);
    expect(a.answered_7).toBe(1);
    expect(a.answered_30).toBe(2);
    expect(a.weeks).toEqual([0, 0, 1, 2]); // oldest week first; 10 days ago is last week but one
  });

  it("last seen is the latest signal, not the last password sign-in", () => {
    // The reported case: password typed 8 days ago, session renewed and questions answered 2 days ago.
    const a = activityOf([daysAgo(2)], [daysAgo(2)], daysAgo(8), NOW, { last_session_at: daysAgo(2) });
    expect(a.last_sign_in_at).toBe(daysAgo(8));
    expect(a.last_seen_at).toBe(daysAgo(2));
    // Without the migration (no session, no presence) the learning records alone still give it.
    expect(activityOf([daysAgo(2)], [], daysAgo(8), NOW).last_seen_at).toBe(daysAgo(2));
    // A learner who only browsed: no learning record, but a presence beat today.
    const seen = { last_sign_in_at: daysAgo(8), presence: [{ day: daysAgo(0).slice(0, 10), first_seen_at: daysAgo(0.1), last_seen_at: daysAgo(0.01), active_seconds: 600, visits: 2 }] };
    expect(lastSeenOf(seen, [], NOW)).toBe(daysAgo(0.01));
    const b = activityOf([], [], daysAgo(8), NOW, seen);
    expect(b.active_days_7).toBe(1);
    expect(b.visits_30).toBe(2);
    expect(b.active_minutes_30).toBe(10);
    expect(b.days).toHaveLength(30);
    expect(b.days?.[29]).toMatchObject({ active: true, minutes: 10, answers: 0 });
    // Presence not recorded yet: the totals are unknown, not zero.
    expect(activityOf([daysAgo(1)], [], null, NOW).visits_30).toBeNull();
  });

  it("ignores missing, invalid and future dates", () => {
    expect(latestOf([null, undefined, "nope", daysAgo(3), daysAgo(-5)], NOW)).toBe(daysAgo(3));
    expect(latestOf([], NOW)).toBeNull();
  });
});

describe("report narrative", () => {
  it("first report: sign-in, activity, strengths, topics to strengthen, recommendation", () => {
    const n = reportNarrative(student(), null, null, NOW);
    const text = n.paragraphs.map(p => p.text).join(" ");
    expect(text).toMatch(/was last on the platform yesterday/);
    expect(text).not.toMatch(/opened with a password/);   // same day: nothing to explain
    expect(text).toMatch(/Active on 9 of the last 30 days/);
    expect(text).toMatch(/first report/);
    expect(text).toMatch(/Strong in Email \(90%\)/);
    expect(text).toMatch(/Needs strengthening in SIEM and KQL \(40% right first try\)/);
    expect(text).toMatch(/Microsoft Sentinel Fundamentals/);
    expect(n.status).toBe("needs attention");
    expect(text).not.toMatch(/\b(he|she|his|her)\b/i);
  });

  it("compares with the previous report", () => {
    const s = student();
    const prev = { created_at: daysAgo(14), metrics: { ...metricsOf(s), xp: 600, rooms_completed: 1, first_try_pct: 62, areas: { email: 90, siem: 30 } } };
    const n = reportNarrative(s, null, prev, NOW);
    const text = n.paragraphs.map(p => p.text).join(" ");
    expect(text).toMatch(/\+400 XP/);
    expect(text).toMatch(/\+2 rooms completed/);
    expect(text).toMatch(/from 62% to 70%/);
    expect(text).toMatch(/Improved in SIEM and KQL/);
    expect(n.change).toMatch(/\+400 XP/);
  });

  it("flags a learner who never signed in, and one who stopped", () => {
    expect(reportNarrative(student({ last_active_at: null, last_seen_at: null, activity: { last_sign_in_at: null, active_days_7: 0, active_days_30: 0, answered_7: 0, answered_30: 0, weeks: [0, 0, 0, 0] } }), null, null, NOW).status).toBe("not started");
    const gone = reportNarrative(student({ last_active_at: daysAgo(30), last_seen_at: daysAgo(30), activity: { last_sign_in_at: daysAgo(30), active_days_7: 0, active_days_30: 0, answered_7: 0, answered_30: 0, weeks: [0, 0, 0, 0] } }), null, null, NOW);
    expect(gone.status).toBe("inactive");
    expect(gone.paragraphs.find(p => p.title === "Needs action")?.text).toMatch(/not seen on the platform for 30 days/);
  });

  it("a learner who stays signed in is reported by the last visit, not the last password sign-in", () => {
    const s = student({ last_active_at: daysAgo(2), last_seen_at: daysAgo(2),
      activity: { last_sign_in_at: daysAgo(20), last_seen_at: daysAgo(2), active_days_7: 1, active_days_30: 4, answered_7: 13, answered_30: 14, weeks: [0, 1, 2, 1], visits_30: 6, active_minutes_30: 95 } });
    expect(lastSeenAt(s, NOW)).toBe(daysAgo(2));
    const n = reportNarrative(s, null, null, NOW);
    const text = n.paragraphs.map(p => p.text).join(" ");
    expect(text).toMatch(/was last on the platform 2 days ago/);
    expect(text).toMatch(/opened with a password on .* and has stayed signed in since/);
    expect(text).toMatch(/6 visits and 95 active minutes/);
    expect(text).not.toMatch(/follow up/);          // 20 days since the password, but seen 2 days ago
    expect(n.status).not.toBe("inactive");
  });

  it("stored metrics are re-shaped and bounded", () => {
    const m = sanitizeReportMetrics({ xp: "1200", first_try_pct: 140, areas: { siem: 55, "bad key!": 3 }, extra: "x" });
    expect(m?.xp).toBe(1200);
    expect(m?.first_try_pct).toBe(100);
    expect(m?.areas).toEqual({ siem: 55 });
    expect(sanitizeReportMetrics("nope")).toBeNull();
  });
});
