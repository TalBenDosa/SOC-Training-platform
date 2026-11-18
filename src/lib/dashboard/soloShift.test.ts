// Stage B1: the server deals the solo Dashboard's stories (soloShift.ts) the way the page did, and keeps
// their answers. These pin the properties the grader and the learner rely on.
import { describe, it, expect } from "vitest";
import { dealBuiltInStory, shiftStoryOf, shiftTotals, storyTruth, storyHasOpened, FIRST_PHASE_MIN_MS, OPEN_SLACK_MS, MISSION_BONUS_XP, type ShiftStory } from "./soloShift";
import { ATTACK_STORIES, storiesForCompany } from "@/app/(app)/dashboard/attackStories";
import { isAttackEvent } from "@/app/(app)/dashboard/groundTruth";
import { storyThemes } from "@/lib/team/storyCategory";
import { namesTheStory, THEME_WORDS } from "./reportIdentification";

const COMPANIES = ["nexacorp", "rocketstack", "medcore", "globallogis", "quantumbank"];
const LEVELS = ["easy", "medium", "hard"] as const;
const teamOnly = new Set(ATTACK_STORIES.filter(s => s.teamOnly).map(s => s.id));

describe("server-dealt solo stories", () => {
  it("every company and level deals a single-player story of its own pool, with rows and an answer", () => {
    for (const c of COMPANIES) for (const l of LEVELS) {
      const st = dealBuiltInStory(c, l, [], `t:${c}:${l}`);
      expect(teamOnly.has(st.id), `${c}/${l} dealt a Team Training story`).toBe(false);
      expect(storiesForCompany(c, l, true).some(x => x.id === st.id), `${c}/${l}`).toBe(true);
      expect(st.events.length).toBeGreaterThan(0);
      const t = storyTruth(st);
      expect(t.title).toBe(st.title);
      expect(t.indicators.length, `${st.id} has no indicators`).toBeGreaterThan(0);
    }
  }, 120_000);

  it("is reproducible from its seed, and survives the trip to the browser as JSON", () => {
    const a = dealBuiltInStory("medcore", "medium", [], "seed-1");
    const b = dealBuiltInStory("medcore", "medium", [], "seed-1");
    expect(b.id).toBe(a.id);
    expect(JSON.stringify(b.events)).toBe(JSON.stringify(a.events));
    expect(JSON.parse(JSON.stringify(a))).toEqual(a);
  }, 60_000);

  it("never deals a story the learner met recently while others are left", () => {
    const first = dealBuiltInStory("nexacorp", "medium", [], "r-1");
    for (let i = 0; i < 6; i++) expect(dealBuiltInStory("nexacorp", "medium", [first.id], `r-2-${i}`).id).not.toBe(first.id);
  }, 60_000);

  it("the answer is the attack rows only: no baseline or decoy row's values", () => {
    const st = dealBuiltInStory("globallogis", "hard", [], "truth-1");
    const t = storyTruth(st);
    const attackValues = JSON.stringify(st.events.filter(isAttackEvent));
    for (const v of t.indicators) expect(attackValues.includes(v), v).toBe(true);
  }, 60_000);
});

describe("shift bookkeeping", () => {
  const at = (ms: number) => new Date(ms).toISOString();
  it("a story opens no earlier than its first phase can reach the feed", () => {
    const s = shiftStoryOf(dealBuiltInStory("nexacorp", "easy", [], "o-1"), 1_000_000);
    expect(storyHasOpened(s, 1_000_000 + FIRST_PHASE_MIN_MS - OPEN_SLACK_MS - 1)).toBe(false);
    expect(storyHasOpened(s, 1_000_000 + FIRST_PHASE_MIN_MS)).toBe(true);
  }, 60_000);

  it("counts presented and caught from the server's record, XP by the dashboard's rule plus the mission bonus", () => {
    const now = 10_000_000;
    const mk = (opens: number, caught: boolean, score: number | null): ShiftStory => ({
      storyId: `s${opens}`, title: "t", mitre: [], indicators: [], dealtAt: at(0), opensAt: at(opens), bestScore: score, caughtAt: caught ? at(opens + 1) : null,
    });
    const one = shiftTotals([mk(1, true, 80), mk(now + 1, false, null)], now);
    expect(one).toEqual({ presented: 1, caught: 1, xp: 120, detectRate: 100 });
    const two = shiftTotals([mk(1, true, 70), mk(2, true, 90), mk(3, false, 40)], now);
    expect(two.caught).toBe(2);
    expect(two.presented).toBe(3);
    expect(two.xp).toBe(105 + 135 + MISSION_BONUS_XP);
    expect(two.detectRate).toBe(67);
  });
});

describe("report identification covers every single-player story", () => {
  it("each story has a kind of attack the grader knows, and its own kind names it", () => {
    for (const s of ATTACK_STORIES.filter(x => !x.teamOnly)) {
      const themes = storyThemes(s.id).filter(t => THEME_WORDS[t]);
      expect(themes.length, `${s.id} has no attack vocabulary`).toBeGreaterThan(0);
    }
  });

  it("a report in another kind's words does not name the story", () => {
    expect(namesTheStory("Kerberoasting of a service account", { title: "Verify You Are Human: ClickFix Paste-and-Run", mitre: ["T1204.004"], themes: ["endpoint"] })).toBe(false);
    expect(namesTheStory("ClickFix paste-and-run lure", { title: "Verify You Are Human: ClickFix Paste-and-Run", mitre: ["T1204.004"], themes: ["endpoint"] })).toBe(true);
  });
});
