import { describe, it, expect, beforeEach, vi } from "vitest";
import { pickStoryForCompany } from "@/app/(app)/dashboard/attackStories";
import { RECENT_KEY, mergeRecent, readRecent } from "@/app/(app)/dashboard/recentStories";
import { storyThemes } from "@/lib/team/storyCategory";
import { buildTeamTimeline, type VarietyOpts } from "@/lib/team/buildTimeline";
import { emptyHistory, type VarietyRecord } from "@/lib/team/variety";

/*
 * Attack-type rotation (Tal 2026-11-12: "vary the attack types every time"): the solo draw never deals the
 * kind of attack of the last shift, and merges the learner's server-side history; a Team session prefers the
 * kinds its organization met longest ago.
 */
const store = new Map<string, string>();
beforeEach(() => {
  store.clear();
  vi.stubGlobal("localStorage", {
    getItem: (k: string) => store.get(k) ?? null, setItem: (k: string, v: string) => void store.set(k, v),
    removeItem: (k: string) => void store.delete(k), clear: () => store.clear(), key: () => null, length: 0,
  });
  vi.stubGlobal("window", { localStorage: globalThis.localStorage });
});

describe("solo rotation", () => {
  it("the next shift never repeats the kind of attack of the last one", () => {
    for (const co of ["nexacorp", "medcore", "quantumbank"]) for (let i = 0; i < 25; i++) {
      const first = pickStoryForCompany(co, "medium");
      const next = pickStoryForCompany(co, "medium");
      const shared = storyThemes(next.id).filter(t => storyThemes(first.id).includes(t));
      expect(shared, `${co}: ${first.id} then ${next.id}`).toEqual([]);
      store.clear();
    }
  });

  it("merges the server history behind this browser's memory and avoids it", () => {
    store.set(RECENT_KEY, JSON.stringify(["phishing"]));
    mergeRecent(["bec", "phishing", "ransomware"]);
    expect(readRecent()).toEqual(["phishing", "bec", "ransomware"]);
    for (let i = 0; i < 20; i++) {
      store.set(RECENT_KEY, JSON.stringify(["bec", "ransomware"]));
      expect(["bec", "ransomware"]).not.toContain(pickStoryForCompany("nexacorp", "easy").id);
    }
  });
});

describe("team rotation", () => {
  it("a session prefers the kinds of attack its organization met longest ago", () => {
    // The organization's last session ran one story; the next sessions avoid its kind while others are left.
    let last: VarietyRecord | null = null;
    const opts = (): VarietyOpts => ({ onVariety: r => { last = r; } });
    buildTeamTimeline("nexacorp", "medium", "rotation-1", null, undefined, {}, null, null, opts());
    const before = (last as VarietyRecord | null)?.stories ?? [];
    expect(before.length).toBeGreaterThan(0);
    const history = { ...emptyHistory(), stories: Object.fromEntries(before.map(id => [id, 1])) };
    const kinds = new Set(before.flatMap(id => storyThemes(id)));
    for (const seed of ["rotation-2", "rotation-3", "rotation-4"]) {
      last = null;
      buildTeamTimeline("nexacorp", "medium", seed, null, undefined, {}, null, null, { history, onVariety: r => { last = r; } });
      const primary = (last as VarietyRecord | null)?.stories[0];
      expect(primary, seed).toBeTruthy();
      expect(storyThemes(primary!).filter(t => kinds.has(t)), `${seed}: ${primary}`).toEqual([]);
    }
  });
});
