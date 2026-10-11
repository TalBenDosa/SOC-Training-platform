import { describe, expect, it } from "vitest";
import { ATTACK_STORIES } from "@/app/(app)/dashboard/attackStories";
import { groupByCategory, storyCategory } from "./storyCategory";

describe("storyline categories", () => {
  it("every attack story has a category (add new stories to storyCategory.ts)", () => {
    expect(ATTACK_STORIES.filter(s => storyCategory(s.id) === "other").map(s => s.id)).toEqual([]);
  });

  it("groups in category order and drops empty groups", () => {
    const g = groupByCategory([
      { id: "ai-x", category: storyCategory("ai-x") },
      { id: "dcsync", category: storyCategory("dcsync") },
      { id: "phishing", category: storyCategory("phishing") },
    ]);
    expect(g.map(x => x.id)).toEqual(["phishing", "ad", "ai"]);
  });
});
