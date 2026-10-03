// The instructor's attack plan: up to three concurrent attacks, each a chosen storyline or random.
import { describe, it, expect, vi } from "vitest";
vi.mock("server-only", () => ({}));
import { sanitizeAttackPlan, planFromConfig, attackCount, loadWithPlan, pinnedIds } from "./attackPlan";
import { teamLoad } from "./load";
import { buildTeamTimeline, teamStoryPool, teamStoryFilter, BONUS_HOLD_MS } from "./buildTimeline";
import { DEFAULT_ENV } from "./environment";
import { parseTenant, TENANT_TEMPLATE, type Tenant } from "./tenant";

const small = teamLoad("medium", [{ role: "t1" }, { role: "t2" }]);   // auto → 1 attack

describe("attack plan input", () => {
  it("count 1–3 or auto; ≤3 slots; repeats collapse; slots past the count drop", () => {
    expect(sanitizeAttackPlan({})).toMatchObject({ count: null, slots: [] });
    expect(sanitizeAttackPlan({ attack_count: 3, scenario_ids: ["a-1", null, "b-2", "c-3"] })).toMatchObject({ count: 3, slots: ["a-1", null, "b-2"] });
    expect(sanitizeAttackPlan({ attack_count: 9, scenario_ids: ["a-1", "a-1"] })).toMatchObject({ count: null, slots: ["a-1"] });
    expect(sanitizeAttackPlan({ attack_count: 1, scenario_ids: ["a-1", "b-2"] })).toMatchObject({ count: 1, slots: ["a-1"] });
    expect(sanitizeAttackPlan({ scenario_ids: ["<script>", "b-2"] }).slots).toEqual([null, "b-2"]);
    expect(sanitizeAttackPlan({ scenario_id: "legacy-one" })).toMatchObject({ count: null, slots: ["legacy-one"] });
  });
  it("the bonus attack is on unless switched off", () => {
    expect(sanitizeAttackPlan({}).bonus).toBe(true);
    expect(sanitizeAttackPlan({ bonus_attack: false }).bonus).toBe(false);
    expect(planFromConfig({ attacks: { count: 2, slots: [], bonus: false } }).bonus).toBe(false);
    expect(planFromConfig({}, "old").bonus).toBe(true);
  });
  it("reads the stored plan, else the legacy single storyline", () => {
    expect(planFromConfig({ attacks: { count: 2, slots: ["x-1"] } })).toMatchObject({ count: 2, slots: ["x-1"] });
    expect(planFromConfig({}, "old-story")).toMatchObject({ count: null, slots: ["old-story"] });
  });
  it("the count: the chosen one, else the team's — and always reaching the last chosen slot", () => {
    expect(attackCount({ count: null, slots: [], bonus: false }, small)).toBe(small.stories);
    expect(attackCount({ count: 3, slots: [], bonus: false }, small)).toBe(3);
    expect(attackCount({ count: null, slots: [null, null, "z-9"], bonus: false }, small)).toBe(3);
    const l = loadWithPlan(small, { count: 3, slots: [], bonus: false });
    expect(l.stories).toBe(3);
    expect(l.noiseCount).toBeGreaterThanOrEqual(2 * (3 * 10 + l.poolAttacks * 2));   // attacks stay a minority of the feed
  });
});

describe("the timeline runs the plan", () => {
  const tenant = parseTenant("acme") as Tenant;
  const fits = teamStoryFilter(TENANT_TEMPLATE, {}, DEFAULT_ENV);
  const three = teamStoryPool(TENANT_TEMPLATE, "medium", DEFAULT_ENV).filter(fits).slice(0, 3).map(s => s.id);
  const incidents = (slots: (string | null)[], count: number | null) => {
    const load = loadWithPlan(small, { count, slots, bonus: false });
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
    const load = loadWithPlan(small, { count: 1, slots: [three[2]], bonus: false });
    const tl = buildTeamTimeline(TENANT_TEMPLATE, "medium", "plan-one", [three[2]], load, {}, null, DEFAULT_ENV);
    const ids = new Set(tl.map(t => String((t.answer as { original_id?: string })?.original_id ?? "")).filter(Boolean));
    const story = teamStoryPool(TENANT_TEMPLATE, "medium", DEFAULT_ENV).find(s => s.id === three[2])!;
    const authored = story.events.map(e => String(e.id));
    expect(authored.some(id => [...ids].some(x => x.startsWith(id)))).toBe(true);
    expect(pinnedIds({ count: 1, slots: [three[2]], bonus: false })).toEqual([three[2]]);
  });
});

describe("timing and the bonus attack", () => {
  const roster = [{ role: "t1" }, { role: "t1" }, { role: "t2" }, { role: "t3" }, { role: "mgr" }];
  const build = (seed: string, bonus: boolean) => buildTeamTimeline(TENANT_TEMPLATE, "medium", seed, [null, null, null], loadWithPlan(teamLoad("medium", roster), { count: 3, slots: [], bonus }), {}, null, DEFAULT_ENV, { bonus });
  const ans = (t: { answer?: Record<string, unknown> }) => (t.answer ?? {}) as { origin?: string; incident_id?: string; bonus?: boolean; expected_verdict?: string };
  it("a warm-up of ordinary traffic opens the shift — no attack in its first tenth", () => {
    for (const seed of ["w1", "w2", "w3"]) {
      const feed = build(seed, false).filter(t => t.channel === "feed");
      const firstTenth = feed.slice(0, Math.floor(feed.length * 0.1));
      expect(firstTenth.some(t => ["story", "pool_attack"].includes(String(ans(t).origin))), seed).toBe(false);
    }
  });
  it("the attacks start at staggered points, and the timing differs between sessions", () => {
    const startsOf = (seed: string) => {
      const feed = build(seed, false).filter(t => t.channel === "feed");
      const first = new Map<string, number>();
      feed.forEach((t, i) => { const a = ans(t); if (a.origin === "story" && a.incident_id && !first.has(a.incident_id)) first.set(a.incident_id, i / feed.length); });
      return [...first.values()].sort((a, b) => a - b);
    };
    const a = startsOf("s1"), b = startsOf("s2");
    expect(a).toHaveLength(3);
    expect(a[1] - a[0]).toBeGreaterThan(0.08);
    expect(a[2] - a[1]).toBeGreaterThan(0.08);
    expect(a.map(x => x.toFixed(2))).not.toEqual(b.map(x => x.toFixed(2)));
  });
  it("the bonus attack is held: its own incident and victim, parked past the shift, and marked in the answer key only", () => {
    const tl = build("b1", true);
    const held = tl.filter(t => t.channel === "bonus");
    expect(held.length).toBeGreaterThan(2);
    expect(held.every(t => t.due_offset_ms >= BONUS_HOLD_MS && ans(t).bonus === true)).toBe(true);
    expect(held.every(t => !("bonus" in t.body) && !("bonus_attack" in t.body))).toBe(true);
    const planned = new Set(tl.filter(t => t.channel === "feed" && ans(t).origin === "story").map(t => ans(t).incident_id));
    expect(planned.has(ans(held[0]).incident_id)).toBe(false);
    expect(build("b1", false).some(t => t.channel === "bonus")).toBe(false);
  });
});
