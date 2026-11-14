// Fix A (Tal, 2026-11-14 debrief): the feed must never fire faster than the
// Tier-1 team can triage, and must still end within the shift. load.ts sizes the
// pace to the team (its size and roles); buildTimeline sheds filler (noise, then
// ITSM) when content overflows, rather than compressing the whole feed into a
// firehose, and then compresses only the irreducible remainder to fit the shift.
import { describe, it, expect } from "vitest";
import { buildTeamTimeline } from "./buildTimeline";
import { teamLoad, withShiftMinutes, LOAD_RULES, type Difficulty } from "./load";

type Role = { role: string };
const roster = (t1: number, others: number): Role[] => [
  ...Array.from({ length: t1 }, () => ({ role: "t1" })),
  ...Array.from({ length: others }, (_, i) => ({ role: ["t2", "t3", "manager", "ti"][i % 4] })),
];

function feedTimes(tl: { channel: string; due_offset_ms: number }[]): number[] {
  return tl.filter(e => e.channel === "feed").map(e => e.due_offset_ms).sort((a, b) => a - b);
}
/** Logs per minute across the populated span of the released feed. */
function feedPace(t: number[]): number {
  if (t.length < 2) return 0;
  const spanMin = (t[t.length - 1] - t[0]) / 60_000;
  return spanMin > 0 ? t.length / spanMin : 0;
}

describe("team feed pace stays triageable and fits the shift (fix A)", () => {
  const diffs: Difficulty[] = ["easy", "medium", "hard"];
  const TOL = 1.2; // headroom for jitter, the 0.95 fit target and injects

  for (const d of diffs) {
    for (const [t1, others] of [[1, 0], [2, 2], [1, 5], [3, 5]] as const) {
      it(`${d}, ${t1} T1 + ${others} others: within ceiling and ends on time`, () => {
        const load = teamLoad(d, roster(t1, others));
        const t = feedTimes(buildTeamTimeline("nexacorp", d, `pace-${d}-${t1}-${others}`, undefined, load));
        expect(feedPace(t)).toBeLessThanOrEqual(LOAD_RULES.maxLogsPerMin[d] * TOL);
        expect(Math.max(...t)).toBeLessThanOrEqual(load.shiftMin * 60_000);
      });
    }
  }

  // Overflow: a large team (many attacks) on a deliberately short shift. The feed must still END
  // within the shift (the 2026-10-18 invariant), and filler is shed so the pace is as close to the
  // ceiling as the irreducible attack content allows, instead of the whole feed being firehosed.
  it("large team on a short shift still ends on time", () => {
    const load = withShiftMinutes(teamLoad("hard", roster(2, 6)), 20);
    const t = feedTimes(buildTeamTimeline("nexacorp", "hard", "pace-overflow", undefined, load));
    expect(Math.max(...t)).toBeLessThanOrEqual(20 * 60_000);
  });
});
