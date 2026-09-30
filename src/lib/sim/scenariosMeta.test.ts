import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import { SCENARIOS } from "./scenarios";
import { SCENARIOS_META } from "./scenariosMeta";

describe("SCENARIOS_META (client-safe scenario list)", () => {
  it("is in sync with SCENARIOS — regenerate with `npx tsx scripts/generate-scenarios-meta.mjs`", () => {
    expect(SCENARIOS_META).toEqual(
      SCENARIOS.map(s => ({ slug: s.slug, title: s.title, difficulty: s.difficulty, summary: s.summary })),
    );
  });

  it("carries no answer-bearing or verdict-revealing field", () => {
    for (const m of SCENARIOS_META) expect(Object.keys(m).sort()).toEqual(["difficulty", "slug", "summary", "title"]);
  });

  it("no client component imports the full scenarios module (it bundles every answer key)", () => {
    const offenders: string[] = [];
    const walk = (dir: string) => {
      for (const name of readdirSync(dir)) {
        const p = path.join(dir, name);
        if (statSync(p).isDirectory()) { walk(p); continue; }
        if (!/\.(tsx?|jsx?)$/.test(name)) continue;
        const src = readFileSync(p, "utf8");
        if (/^\s*["']use client["']/.test(src) && /from\s+["']@\/lib\/sim\/scenarios["']/.test(src)) offenders.push(p);
      }
    };
    walk(path.join(process.cwd(), "src"));
    expect(offenders).toEqual([]);
  });
});
