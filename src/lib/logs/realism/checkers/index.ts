import type { Checker, Collected, RuleId, Violation } from "../types";
import { r1 } from "./r1";
import { r2 } from "./r2";
import { r3 } from "./r3";
import { r4 } from "./r4";
import { r5 } from "./r5";
import { r6 } from "./r6";
import { r7 } from "./r7";
import { r8 } from "./r8";
import { r9 } from "./r9";

export const CHECKERS: Record<RuleId, Checker> = { R1: r1, R2: r2, R3: r3, R4: r4, R5: r5, R6: r6, R7: r7, R8: r8, R9: r9 };

/** Every checker over every surface, de-duplicated by key, in a stable order. */
export function runAll(c: Collected): Violation[] {
  const all: Violation[] = [];
  const seen = new Set<string>();
  for (const [rule, f] of Object.entries(CHECKERS)) {
    for (const v of f(c)) {
      const k = `${v.surface}|${rule}|${v.rowId}|${v.detail}`;
      if (seen.has(k)) continue;
      seen.add(k);
      all.push(v);
    }
  }
  return all.sort((a, b) => (a.surface + a.rule + a.rowId + a.detail).localeCompare(b.surface + b.rule + b.rowId + b.detail));
}
