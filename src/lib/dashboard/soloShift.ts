/**
 * The solo SOC Dashboard's server-dealt story and its answer (Stage B1, dashboard review 2026-11).
 *
 * The browser used to pick the attack story and send its answer (title, techniques, indicators)
 * to the grader, which believed it. Now the server deals every story of a training here, keeps
 * the answer in dashboard_shifts and grades only against that. The story itself still travels to
 * the browser, which runs the feed (hiding the answer flags from the browser is Stage B2).
 *
 * The deal is the one the dashboard page made (resolveStory + stackedStory with the company's own
 * products): the same candidate pool, lock rule, anti-repeat and attack-type rotation, instantiation,
 * one SID per account and product relabelling. The draw and the variation run on a seeded generator,
 * so a shift's story can be rebuilt from its seed. Server only in practice (it imports the whole
 * story catalog); kept free of "server-only" so tests import it directly.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { BENIGN_EVENTS } from "@/app/(app)/dashboard/benignEvents";
import { COMPANY_EVENTS } from "@/lib/sim/companyProfiles";
import { instantiateStory, pickSoloStory, storiesForCompany, type AttackStory } from "@/app/(app)/dashboard/attackStories";
import { companyFeedPool, feedCompanyProfile, feedStoryEvents } from "@/app/(app)/dashboard/feedPool";
import { extractIndicators, isAttackEvent } from "@/app/(app)/dashboard/groundTruth";
import { applyStack, storyHonoursLocks } from "@/lib/logs/native";
import { COMPANY_PROFILES } from "@/lib/sim/companyProfilesMeta";
import { hashSeed, mulberry32 } from "@/lib/team/variety";
import type { OrgCompanyContent } from "@/lib/content/publicContent";

export type SoloDifficulty = "easy" | "medium" | "hard";

/** The earliest a dealt story's first attack row can reach the feed: the page arms it 2-3 minutes out. */
export const FIRST_PHASE_MIN_MS = 120_000;
/** Clock and network slack on the server-side "has the attack appeared yet" check. */
export const OPEN_SLACK_MS = 10_000;
/** A training is 30 minutes; a few more stories than it can hold is the ceiling (a script, not a learner). */
export const MAX_STORIES_PER_SHIFT = 12;

/** What the grader checks a report against. Never sent to the browser. */
export interface StoryTruth {
  storyId: string;
  title: string;
  mitre: string[];
  indicators: string[];
}

/** One dealt story as dashboard_shifts keeps it. */
export interface ShiftStory extends StoryTruth {
  dealtAt: string;
  /** Before this instant no row of the attack can be on screen, so no report can describe it. */
  opensAt: string;
  bestScore: number | null;
  caughtAt: string | null;
}

export const isBuiltInCompany = (id: string) => COMPANY_PROFILES.some(c => c.id === id);

const SIM = { BENIGN_EVENTS, COMPANY_EVENTS };

/** The answer of an instantiated story: its attack rows' techniques and indicators (baseline and decoy rows excluded). */
export function storyTruth(story: AttackStory): StoryTruth {
  const attack = story.events.filter(isAttackEvent);
  const seen = [...new Set(attack.map(e => e.mitre_technique).filter((m): m is string => !!m))];
  return {
    storyId: story.id,
    title: story.title,
    mitre: seen.length ? seen : [...new Set(story.mitre ?? [])],
    indicators: extractIndicators(attack),
  };
}

/** A story as the solo Live Feed shows it with the company's own products (page.tsx stackedStory, empty stack). */
function asFed(story: AttackStory, companyId: string): AttackStory {
  return { ...story, events: feedStoryEvents(story.events, companyId).map(e => applyStack(e, companyId, {})) };
}

/**
 * Deal one story for a built-in company. `recent` is the learner's history, newest first (their recorded
 * incidents, then this shift's stories); `seed` makes the draw and the variation reproducible.
 */
export function dealBuiltInStory(companyId: string, difficulty: SoloDifficulty, recent: string[], seed: string): AttackStory {
  const rnd = mulberry32(hashSeed(`${companyId}:${difficulty}:${seed}`));
  const pool = companyFeedPool(SIM, companyId);
  const edr = feedCompanyProfile(companyId).architecture?.edr;
  const all = storiesForCompany(companyId, difficulty, true);
  // The company rule (page.tsx stackedStory): no story written about another vendor's artifacts.
  const fitting = all.filter(st => {
    try { return storyHonoursLocks(instantiateStory(st, pool, edr, companyId, () => 0.5).events, companyId); }
    catch { return false; }
  });
  const picked = pickSoloStory(fitting.length ? fitting : all, recent, rnd);
  return asFed(instantiateStory(picked, pool, edr, companyId, rnd, { seed }), companyId);
}

/** Deal the story of a college-authored company (its own single story, as the page did). */
export function dealOrgStory(org: OrgCompanyContent): AttackStory {
  const id = org.profile.id;
  const edr = (org.profile.architecture as { edr?: string } | undefined)?.edr;
  const story = instantiateStory(org.story as unknown as AttackStory, org.benignEvents as TelemetryEvent[], edr, id);
  return asFed(story, id);
}

/** The shift entry for a story dealt at `now`. */
export function shiftStoryOf(story: AttackStory, now: number): ShiftStory {
  return {
    ...storyTruth(story),
    dealtAt: new Date(now).toISOString(),
    opensAt: new Date(now + FIRST_PHASE_MIN_MS - OPEN_SLACK_MS).toISOString(),
    bestScore: null,
    caughtAt: null,
  };
}

/** Has this story's attack had time to reach the feed? */
export const storyHasOpened = (s: Pick<ShiftStory, "opensAt">, now: number) => Date.parse(s.opensAt) <= now;

/** XP of a training, from the server's own record: per caught story the dashboard's rule, plus the mission bonus. */
export const CATCH_XP = (score: number) => Math.max(25, Math.round(score * 1.5));
export const MISSION_BONUS_XP = 250;
export const ADVANCE_CATCHES = 2;

export function shiftTotals(stories: ShiftStory[], now: number) {
  const presented = stories.filter(s => s.caughtAt || storyHasOpened(s, now)).length;
  const caught = stories.filter(s => s.caughtAt).length;
  const xp = stories.reduce((a, s) => a + (s.caughtAt && s.bestScore != null ? CATCH_XP(s.bestScore) : 0), 0)
    + (caught >= ADVANCE_CATCHES ? MISSION_BONUS_XP : 0);
  return { presented, caught, xp, detectRate: presented > 0 ? Math.round((caught / presented) * 100) : 0 };
}
