import { describe, it, expect } from "vitest";
import { bestScoresBySlug, matchesDoneFilter } from "./completion";

describe("bestScoresBySlug", () => {
  it("keeps the best score per scenario across attempts", () => {
    const best = bestScoresBySlug([
      { slug: "kerberoasting", score: 55 },
      { slug: "kerberoasting", score: 82 },
      { slug: "kerberoasting", score: 70 },
      { slug: "dns-tunneling", score: 40 },
    ]);
    expect(best).toEqual({ kerberoasting: 82, "dns-tunneling": 40 });
  });

  it("marks a zero-score attempt as completed (key present)", () => {
    const best = bestScoresBySlug([{ slug: "lolbins", score: 0 }]);
    expect(best.lolbins).toBe(0);
    expect(matchesDoneFilter("lolbins", best, "done")).toBe(true);
  });

  it("matches org-authored scenario ids, including an encoded record", () => {
    const id = "org-acme-phish drill-1a2b";
    const best = bestScoresBySlug([{ slug: encodeURIComponent(id), score: 90 }]);
    expect(best[id]).toBe(90);
  });

  it("ignores malformed rows", () => {
    const best = bestScoresBySlug([
      { slug: "", score: 10 },
      { slug: null, score: 10 },
      { slug: "x", score: Number.NaN },
      null as unknown as { slug: string },
    ]);
    expect(best).toEqual({ x: 0 });
  });
});

describe("matchesDoneFilter", () => {
  const best = { a: 75 };
  it("filters by completion", () => {
    expect(matchesDoneFilter("a", best, "all")).toBe(true);
    expect(matchesDoneFilter("b", best, "all")).toBe(true);
    expect(matchesDoneFilter("a", best, "done")).toBe(true);
    expect(matchesDoneFilter("b", best, "done")).toBe(false);
    expect(matchesDoneFilter("a", best, "todo")).toBe(false);
    expect(matchesDoneFilter("b", best, "todo")).toBe(true);
  });
});
