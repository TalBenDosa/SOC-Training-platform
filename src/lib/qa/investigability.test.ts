// INVESTIGABILITY GATE — every storyline can be detected and worked end to end from its logs
// (src/lib/qa/investigability.ts). Per story: storyProblems(renderedStories().find(...)).
import { describe, it, expect } from "vitest";
import { renderedStories, storyProblems } from "./investigability";

const by = (cat: string) => {
  const out: string[] = [];
  for (const r of renderedStories()) for (const p of storyProblems(r)) if (p.startsWith(`${cat}:`)) out.push(`${r.story.id} — ${p}`);
  return out;
};

describe("investigability gate", { timeout: 300_000 }, () => {
  it("no cryptocurrency incident anywhere in the arsenal", () => expect(by("crypto")).toEqual([]));
  it("every storyline has an alert / detection a SOC would really get", () => expect(by("first-alert")).toEqual([]));
  it("every count a description states is carried by the record", () => expect(by("claims")).toEqual([]));
  it("a host a command line fetches from appears in the story's network logs", () => expect(by("cmd-domain")).toEqual([]));
  it("each storyline has its own attacker infrastructure", () => expect(by("reuse")).toEqual([]));
});
