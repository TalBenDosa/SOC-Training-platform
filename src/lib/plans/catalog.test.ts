import { describe, expect, it } from "vitest";
import { getPlanCatalog } from "./catalog";
import { ALL_QUIZZES } from "@/lib/quizzes/data";
import { SCENARIOS } from "@/lib/sim/scenarios";

// The catalogue reads quizzes and scenarios from the generated catalogMeta
// index. These checks pin it to the real corpora, so the index can never hide
// or misgroup an item a manager should be able to assign.
describe("plan catalog built from catalogMeta", () => {
  it("indexes every built-in quiz and scenario with its real title and link", async () => {
    const { index } = await getPlanCatalog(null, null, false);
    for (const q of ALL_QUIZZES) {
      expect(index.get(`quiz:${q.slug}`)).toMatchObject({ title: q.title, href: `/quizzes/${q.slug}` });
    }
    for (const s of SCENARIOS) {
      expect(index.get(`scenario:${s.slug}`)).toMatchObject({ title: s.title, href: `/scenarios/${s.slug}` });
    }
  });

  it("groups quizzes by category and scenarios by difficulty, in corpus order", async () => {
    const { tree } = await getPlanCatalog(null, null, false);
    const quizzes = tree.find(n => n.key === "grp:quizzes")!;
    const scenarios = tree.find(n => n.key === "grp:scenarios")!;
    const quizIds = quizzes.children!.flatMap(c => c.children!.map(l => l.item!.id));
    const byCat = new Map<string, string[]>();
    for (const q of ALL_QUIZZES) byCat.set(q.category, [...(byCat.get(q.category) ?? []), q.slug]);
    expect(quizIds).toEqual([...byCat.values()].flat());
    const scenarioCount = scenarios.children!.reduce((n, c) => n + c.children!.length, 0);
    expect(scenarioCount).toBe(SCENARIOS.length);
    for (const grp of scenarios.children!) {
      for (const leaf of grp.children!) {
        const s = SCENARIOS.find(x => x.slug === leaf.item!.id)!;
        expect(grp.key).toBe(`grp:scenarios:${String(s.difficulty)}`);
      }
    }
  });
});
