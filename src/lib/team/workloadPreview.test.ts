import { describe, it, expect, vi } from "vitest";
vi.mock("server-only", () => ({}));
import { buildTeamTimeline, teamStoryFilter } from "./buildTimeline";
import { teamLoad, withShiftMinutes } from "./load";
import { loadWithPlan } from "./attackPlan";
import { measureWorkload } from "./workloadPreview";
import { buildFittedTimeline, TIER1_TARGET } from "./fitTimeline";
import { storiesForTier } from "@/app/(app)/dashboard/attackStories";

const r = (...roles: string[]) => roles.map(role => ({ role, status: "ready" }));

describe("workload preview: the exercise measured before it starts", () => {
  it("the Sdema overload (three storylines, one Tier-1, 20 minutes) stays flagged: the attacks alone are too much", () => {
    const roster = r("t1", "t2", "mgr");
    const fits = teamStoryFilter("nexacorp", {}, null);
    const slots = storiesForTier("hard", true).filter(fits).slice(0, 3).map(s => s.id);
    const plan = { count: 3, slots, bonus: false };
    const load = loadWithPlan(withShiftMinutes(teamLoad("hard", roster), 20), plan);
    const raw = measureWorkload(buildTeamTimeline("nexacorp", "hard", "sdema-like", slots, load, {}), load, roster);
    const fitted = buildFittedTimeline({ companyId: "nexacorp", difficulty: "hard", seed: "sdema-like", slots, load, roster });
    expect(raw.level).toBe("over");
    expect(fitted.workload.level).toBe("over");
    expect(fitted.workload.tier1.pct!).toBeLessThanOrEqual(raw.tier1.pct!);   // only noise is ever trimmed, the attacks stay
  });

  it("a room with its automatic plan is fitted to the target after building", () => {
    const roster = r("t1", "t1", "t2", "t3", "mgr");
    const load = withShiftMinutes(teamLoad("medium", roster), 30);
    const { workload, timeline } = buildFittedTimeline({ companyId: "nexacorp", difficulty: "medium", seed: "fits", slots: null, load, roster });
    expect(workload.tier1.pct!).toBeLessThanOrEqual(TIER1_TARGET + 0.05);
    expect(workload.level).not.toBe("over");
    // The fitted feed still spans the shift (spaced out, not cut short).
    const lastFeed = Math.max(...timeline.filter(t => t.channel === "feed").map(t => t.due_offset_ms));
    expect(lastFeed).toBeGreaterThan(load.shiftMin * 60_000 * 0.75);
  });

  it("no Tier-2/3 in the room: their load is not measured, Tier-1 still is", () => {
    const roster = r("t1", "mgr");
    const load = teamLoad("easy", roster);
    const w = measureWorkload(buildTeamTimeline("nexacorp", "easy", "solo", null, load, {}), load, roster);
    expect(w.tier2.pct).toBeNull();
    expect(w.tier1.pct).not.toBeNull();
  });
});
