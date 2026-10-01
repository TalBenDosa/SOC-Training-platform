/**
 * Scenario review 2026-10-01, fix 3: a story's BASELINE step (the legitimate
 * sign-in / login before the attack) must never be graded as an attack log. The
 * impossible-travel story's Tel Aviv login carried no flag, so the team answer key
 * counted it as "tp" — and "attack logs nobody handled" listed it.
 */
import { describe, it, expect, vi } from "vitest";
vi.mock("server-only", () => ({}));
import { ATTACK_STORIES } from "@/app/(app)/dashboard/attackStories";
import { classifyStoryEvent } from "./buildTimeline";

describe("story baseline steps", () => {
  it("every step whose id names it a baseline is graded benign", () => {
    const wrong: string[] = [];
    for (const story of ATTACK_STORIES) {
      for (const ev of story.events) {
        if (!/baseline/i.test(ev.id)) continue;
        if (classifyStoryEvent(ev) !== "benign") wrong.push(`${story.id}: ${ev.id} → ${classifyStoryEvent(ev)}`);
      }
    }
    expect(wrong).toEqual([]);
  });

  it("the impossible-travel story's Tel Aviv login is benign; the Lagos login stays an attack", () => {
    const st = ATTACK_STORIES.find(s => s.events.some(e => e.id === "evt_imp_01_baseline"));
    expect(st).toBeTruthy();
    expect(classifyStoryEvent(st!.events.find(e => e.id === "evt_imp_01_baseline")!)).toBe("benign");
    expect(classifyStoryEvent(st!.events.find(e => e.id.startsWith("evt_imp_02"))!)).toBe("tp");
  });
});
