// The instructor's attack plan: up to three concurrent attacks, each a chosen storyline or random.
import { describe, it, expect, vi } from "vitest";
vi.mock("server-only", () => ({}));
import { sanitizeAttackPlan, planFromConfig, attackCount, loadWithPlan, pinnedIds } from "./attackPlan";
import { teamLoad } from "./load";
import { buildTeamTimeline, teamStoryPool, teamStoryFilter } from "./buildTimeline";
import { DEFAULT_ENV } from "./environment";
import { parseTenant, TENANT_TEMPLATE, type Tenant } from "./tenant";

const small = teamLoad("medium", [{ role: "t1" }, { role: "t2" }]);   // auto → 1 attack

describe("attack plan input", () => {
  it("count 1–3 or auto; ≤3 slots; repeats collapse; slots past the count drop", () => {
    expect(sanitizeAttackPlan({})).toEqual({ count: null, slots: [] });
    expect(sanitizeAttackPlan({ attack_count: 3, scenario_ids: ["a-1", null, "b-2", "c-3"] })).toEqual({ count: 3, slots: ["a-1", null, "b-2"] });
    expect(sanitizeAttackPlan({ attack_count: 9, scenario_ids: ["a-1", "a-1"] })).toEqual({ count: null, slots: ["a-1"] });
    expect(sanitizeAttackPlan({ attack_count: 1, scenario_ids: ["a-1", "b-2"] })).toEqual({ count: 1, slots: ["a-1"] });
    expect(sanitizeAttackPlan({ scenario_ids: ["<script>", "b-2"] }).slots).toEqual([null, "b-2"]);
    expect(sanitizeAttackPlan({ scenario_id: "legacy-one" })).toEqual({ count: null, slots: ["legacy-one"] });
  });
  it("reads the stored plan, else the legacy single storyline", () => {
    expect(planFromConfig({ attacks: { count: 2, slots: ["x-1"] } })).toEqual({ count: 2, slots: ["x-1"] });
    expect(planFromConfig({}, "old-story")).toEqual({ count: null, slots: ["old-story"] });
  });
  it("the count: the chosen one, else the team's — and always reaching the last chosen slot", () => {
    expect(attackCount({ count: null, slots: [] }, small)).toBe(small.stories);
    expect(attackCount({ count: 3, slots: [] }, small)).toBe(3);
    expect(attackCount({ count: null, slots: [null, null, "z-9"] }, small)).toBe(3);
    const l = loadWithPlan(small, { count: 3, slots: [] });
    expect(l.stories).toBe(3);
    expect(l.noiseCount).toBeGreaterThanOrEqual(2 * (3 * 10 + l.poolAttacks * 2));   // attacks stay a minority of the feed
  });
});

describe("the timeline runs the plan", () => {
  const tenant = parseTenant("acme") as Tenant;
  const fits = teamStoryFilter(TENANT_TEMPLATE, {}, DEFAULT_ENV);
  const three = teamStoryPool(TENANT_TEMPLATE, "medium", DEFAULT_ENV).filter(fits).slice(0, 3).map(s => s.id);
  const incidents = (slots: (string | null)[], count: number | null) => {
    const load = loadWithPlan(small, { count, slots });
    const tl = buildTeamTimeline(TENANT_TEMPLATE, "medium", "plan-test", slots, load, {}, tenant, DEFAULT_ENV);
    const story = tl.filter(t => (t.answer as { origin?: string })?.origin === "story");
    return new Set(story.map(t => String((t.answer as { incident_id?: string }).incident_id ?? "")));
  };
  it("three chosen storylines → three concurrent incidents, every one of them in the feed", () => {
    expect(three).toHaveLength(3);
    const inc = incidents(three, 3);
    expect(inc.size).toBe(3);
  });
  it("chosen + random slots: the count holds and the random ones are other storylines", () => {
    expect(incidents([three[0], null, null], 3).size).toBe(3);
    expect(incidents([null, three[1]], null).size).toBe(2);   // auto (1 for this team) reaches slot 2
  });
  it("a chosen storyline is the one that runs in its slot", () => {
    const load = loadWithPlan(small, { count: 1, slots: [three[2]] });
    const tl = buildTeamTimeline(TENANT_TEMPLATE, "medium", "plan-one", [three[2]], load, {}, null, DEFAULT_ENV);
    const ids = new Set(tl.map(t => String((t.answer as { original_id?: string })?.original_id ?? "")).filter(Boolean));
    const story = teamStoryPool(TENANT_TEMPLATE, "medium", DEFAULT_ENV).find(s => s.id === three[2])!;
    const authored = story.events.map(e => String(e.id));
    expect(authored.some(id => [...ids].some(x => x.startsWith(id)))).toBe(true);
    expect(pinnedIds({ count: 1, slots: [three[2]] })).toEqual([three[2]]);
  });
});
