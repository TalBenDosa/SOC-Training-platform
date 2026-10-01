/**
 * Corpus gate: every authored event, under every built-in company's stack, either
 * renders in its source's native format with ZERO schema violations, or is one of
 * the categories with no native module yet. Prints the per-company coverage.
 */
import { describe, it, expect } from "vitest";
import { corpus } from "./testing/corpus";
import { nativize, NATIVE_SOURCES, useCasesFor } from "./index";
import { categoryOf, sourceFor } from "./stack";
import { stackFor } from "./index";
import { validateNative } from "./validate";

const COMPANIES = ["nexacorp", "rocketstack", "medcore", "globallogis", "quantumbank"];

describe("native corpus gate", () => {
  it("32 source modules, every use case uniquely named", () => {
    expect(Object.keys(NATIVE_SOURCES).length).toBe(32);
    const ids = useCasesFor().map(u => u.id);
    expect(new Set(ids).size).toBe(ids.length);
    console.log(`[gate] ${ids.length} use cases`);
  });

  for (const companyId of COMPANIES) {
    it(`${companyId}: rendered events have zero violations`, () => {
      let rendered = 0, nullByProduct = 0, noModule = 0;
      const bad: string[] = [];
      const byCat = new Map<string, { r: number; n: number }>();
      for (const c of corpus()) {
        const cat = categoryOf(c.ev) ?? "(no module)";
        const sid = sourceFor(c.ev, stackFor(companyId));
        const slot = byCat.get(cat) ?? { r: 0, n: 0 };
        if (!sid || !NATIVE_SOURCES[sid]) { noModule++; byCat.set(cat, slot); continue; }
        const log = nativize(c.ev, companyId);
        if (!log) { nullByProduct++; slot.n++; byCat.set(cat, slot); continue; }
        rendered++; slot.r++; byCat.set(cat, slot);
        const v = validateNative(log, NATIVE_SOURCES[sid]!.schema);
        if (v.length) bad.push(`${c.ev.id} [${sid}] ${v.slice(0, 3).map(x => `${x.problem}:${x.path}`).join(", ")}`);
      }
      console.log(`[gate] ${companyId}: rendered ${rendered}, null-by-product ${nullByProduct}, no-module ${noModule} — ` +
        [...byCat].map(([k, s]) => `${k} ${s.r}/${s.r + s.n}`).join(" · "));
      expect(bad.slice(0, 20)).toEqual([]);
    });
  }
});
