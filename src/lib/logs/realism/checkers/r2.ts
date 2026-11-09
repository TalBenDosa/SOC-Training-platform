/**
 * R2 Same shape for attack and benign. Per (surface, source, event type) with at least 2 attack and
 * 2 benign rows of known ground truth:
 *  - the median field count of attack rows and of benign rows differs by more than 30%;
 *  - a field is on at least 80% of attack rows and on no benign row (or the reverse), with at least
 *    3 rows on the side that lacks it.
 * Text-only rows (a tool's output) are not compared.
 */
import type { Checker, LogRow, Violation } from "../types";
import { fieldSet } from "../util";

const median = (xs: number[]) => { const s = [...xs].sort((a, b) => a - b); const m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };

export const r2: Checker = c => {
  const groups = new Map<string, LogRow[]>();
  for (const r of c.rows) {
    if (typeof r.raw === "string" || r.isAttack === undefined) continue;
    const k = `${r.surface}|${r.source}/${r.eventType}`;
    (groups.get(k) ?? groups.set(k, []).get(k)!).push(r);
  }
  const out: Violation[] = [];
  for (const [k, rows] of groups) {
    const atk = rows.filter(r => r.isAttack), ben = rows.filter(r => !r.isAttack);
    if (atk.length < 2 || ben.length < 2) continue;
    const surface = rows[0].surface;
    const rowId = k.split("|")[1];
    const af = atk.map(fieldSet), bf = ben.map(fieldSet);
    const ma = median(af.map(s => s.size)), mb = median(bf.map(s => s.size));
    if (Math.abs(ma - mb) / Math.max(ma, mb, 1) > 0.3) {
      out.push({ surface, rule: "R2", rowId, detail: "field count differs by more than 30%", example: `attack median ${ma} vs benign ${mb} fields (${atk.length} attack, ${ben.length} benign rows): ${atk[0].rowId} vs ${ben[0].rowId}` });
    }
    const share = (sets: Set<string>[], f: string) => sets.filter(s => s.has(f)).length / sets.length;
    const all = new Set([...af, ...bf].flatMap(s => [...s]));
    // One violation per field that is on one side only: fixing a field removes its key.
    for (const f of [...all].sort()) {
      const a = share(af, f), b = share(bf, f);
      const side = a >= 0.8 && b === 0 && ben.length >= 3 ? "attack" : b >= 0.8 && a === 0 && atk.length >= 3 ? "benign" : null;
      if (side) out.push({ surface, rule: "R2", rowId, detail: `field ${f} on ${side} rows only`, example: `${atk[0].rowId} vs ${ben[0].rowId} (${atk.length} attack, ${ben.length} benign rows)` });
    }
  }
  return out;
};
