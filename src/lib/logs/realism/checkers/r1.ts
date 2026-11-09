/**
 * R1 Native fields only. Not re-implemented here: this checker calls the two existing R1 checks.
 *  - Rendered native records (live, scenario, team): validateNative against the source's schema
 *    (src/lib/logs/native/validate.ts), one violation per (source/kind, field problem).
 *  - Authored raw blocks (rooms-batch, benign / company pools, scenario packs): the field registry
 *    gate scripts/validate-log-fields.mjs, run with its own baseline hidden so every current
 *    violation is counted (its baseline still governs `npm run validate:logs`).
 */
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { NATIVE_SOURCES } from "@/lib/logs/native";
import { validateNative } from "@/lib/logs/native/validate";
import type { Checker, Surface, Violation } from "../types";

const HIDE_BASELINE = "data:text/javascript,import fs from 'node:fs'; const o=fs.existsSync; fs.existsSync=(p)=>String(p).endsWith('log-field-baseline.json')?false:o(p);";

export interface FieldGateViolation { file: string; line: number; vendor: string; vendorKey: string; field: string }

let gateCache: FieldGateViolation[] | null = null;
/** Every violation the field-registry gate finds today (its baseline ignored). */
export function fieldGateViolations(): FieldGateViolation[] {
  if (gateCache) return gateCache;
  let out = "";
  try {
    out = execFileSync(process.execPath, ["--import", HIDE_BASELINE, join(process.cwd(), "scripts", "validate-log-fields.mjs"), "--json"], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  } catch (e) {
    out = String((e as { stdout?: string }).stdout ?? "");
  }
  try { gateCache = (JSON.parse(out).new ?? []) as FieldGateViolation[]; } catch { gateCache = []; }
  return gateCache;
}

export function surfaceOfFile(file: string): Surface {
  const f = file.replace(/\\/g, "/");
  if (f.startsWith("src/data/")) return "room";
  if (/src\/lib\/sim\/(scenario|scenarios)/.test(f) || /scenario-packs/.test(f)) return "scenario";
  return "live";
}

export const r1: Checker = c => {
  const out: Violation[] = [];
  const seen = new Set<string>();
  for (const row of c.rows) {
    if (!row.native) continue;
    const schema = NATIVE_SOURCES[row.native.sourceId]?.schema;
    if (!schema) continue;
    for (const v of validateNative(row.native, schema)) {
      const rowId = `${row.native.sourceId}/${row.native.kind}`;
      const detail = `${v.problem}:${v.path}`;
      const k = `${row.surface}|${rowId}|${detail}`;
      if (seen.has(k)) continue;
      seen.add(k);
      out.push({ surface: row.surface, rule: "R1", rowId, detail, company: row.company, storyId: row.storyId, example: row.rowId });
    }
  }
  const fileSeen = new Set<string>();
  for (const v of fieldGateViolations()) {
    const rowId = `${v.file}:${v.vendorKey}`;
    const k = `${rowId}|${v.field}`;
    if (fileSeen.has(k)) continue;
    fileSeen.add(k);
    out.push({ surface: surfaceOfFile(v.file), rule: "R1", rowId, detail: `field ${v.field}`, example: `${v.file}:${v.line} (${v.vendor})` });
  }
  return out;
};
