// The admin chooses the attacks of a team exercise, and a chosen attack always happens (Tal, 2026-11-12: "there
// is no situation where he chose an attack and it did not happen"). Every storyline the Session Builder offers
// (the storylines route: teamStoryPool filtered by teamStoryFilter), on every company, level and named-organization
// environment, renders whole when chosen; a plan of three choices renders all three, also after the fitter trims
// the shift to the team's pace.
import { describe, expect, it } from "vitest";
import { ATTACK_STORIES, type AttackStory } from "@/app/(app)/dashboard/attackStories";
import type { Stack } from "@/lib/logs/native/stack";
import { buildTeamTimeline, teamStoryFilter, teamStoryPool, type TimelineEntry } from "./buildTimeline";
import { buildFittedTimeline } from "./fitTimeline";
import { teamLoad } from "./load";
import { loadWithPlan } from "./attackPlan";
import { TENANT_TEMPLATE } from "./tenant";
import { DEFAULT_ENV, PLATFORM_CHOICES, type TeamEnv } from "./environment";

const COMPANIES = ["nexacorp", "rocketstack", "medcore", "globallogis", "quantumbank"];
const DIFFS = ["easy", "medium", "hard"] as const;
const ROSTER = [{ role: "t1" }, { role: "t1" }, { role: "t2" }, { role: "mgr" }];
const FULL_ENV: TeamEnv = { platforms: PLATFORM_CHOICES.map(p => p.id), industry: "general" };
const orig = (e: TimelineEntry) => String((e.answer as { original_id?: string } | undefined)?.original_id ?? "").replace(/__\d+$/, "");
/** What the Session Builder lists for this company / level / environment. */
const offered = (c: string, d: typeof DIFFS[number], env: TeamEnv | null, stack: Stack = {}) =>
  teamStoryPool(c, d, env, stack).filter(teamStoryFilter(c, stack, env));
/** The chosen story's authored rows that reached the timeline. */
const rendered = (tl: TimelineEntry[], s: AttackStory) => { const ids = new Set(s.events.map(e => e.id)); return new Set(tl.filter(e => ids.has(orig(e))).map(orig)); };

const SETUPS: { c: string; env: TeamEnv | null; label: string }[] = [
  ...COMPANIES.map(c => ({ c, env: null, label: c })),
  { c: TENANT_TEMPLATE, env: DEFAULT_ENV, label: "named organization, default environment" },
  { c: TENANT_TEMPLATE, env: FULL_ENV, label: "named organization, every platform" },
];

describe("a chosen attack always happens", () => {
  for (const { c, env, label } of SETUPS) {
    it(`every storyline offered is the session's attack, whole (${label})`, () => {
      const missing: string[] = [];
      let n = 0;
      for (const d of DIFFS) for (const s of offered(c, d, env)) {
        n++;
        const tl = buildTeamTimeline(c, d, `chosen-${s.id}`, s.id, teamLoad(d, ROSTER), {}, null, env);
        const got = rendered(tl, s);
        if (got.size !== s.events.length) missing.push(`${d} ${s.id}: ${got.size}/${s.events.length} rows`);
      }
      expect(n, "the builder offers storylines").toBeGreaterThan(5);
      expect(missing).toEqual([]);
    }, 600_000);
  }

  it("a plan of three choices runs all three, also once the shift is fitted to the team", () => {
    for (const { c, env, label } of SETUPS) {
      const list = offered(c, "medium", env);
      const chosen = list.filter((s, i) => i % Math.max(1, Math.floor(list.length / 3)) === 0).slice(0, 3);
      expect(chosen.length, label).toBe(3);
      const slots = chosen.map(s => s.id);
      const load = loadWithPlan(teamLoad("medium", ROSTER), { count: 3, slots, bonus: false });
      const raw = buildTeamTimeline(c, "medium", `plan-${label}`, slots, load, {}, null, env);
      const fitted = buildFittedTimeline({ companyId: c, difficulty: "medium", seed: `plan-${label}`, slots, load, stack: {}, tenant: null, env, opts: {}, roster: ROSTER }).timeline as TimelineEntry[];
      for (const s of chosen) {
        expect(rendered(raw, s).size, `${label}: ${s.id}`).toBe(s.events.length);
        // The fitter trims noise, never a chosen attack's malicious rows.
        const bad = s.events.filter(e => !e.is_baseline && e.expected_verdict !== "fp").map(e => e.id);
        const kept = rendered(fitted, s);
        expect(bad.filter(id => !kept.has(id)), `${label}: ${s.id} after fitting`).toEqual([]);
      }
    }
  }, 600_000);

  it("never offers a storyline the timeline would not run", () => {
    // The offered list and the timeline's pinned resolution are one rule: everything listed resolves to itself.
    for (const { c, env } of SETUPS) for (const d of DIFFS) for (const s of offered(c, d, env)) {
      expect(ATTACK_STORIES.find(x => x.id === s.id)?.teamOnly, s.id).toBe(true);
    }
  });
});
