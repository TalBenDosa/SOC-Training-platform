/**
 * Native-format coverage of the log surfaces (the second half of the realism gate).
 *
 * A row a page renders through a native source module (src/lib/logs/native) is checked against its
 * product's schema and carries the product's own field names. A row with no module falls back to the
 * legacy raw block (rawLogFormat.ts): it is never schema-checked. The collectors mark those rows with
 * a `legacy:<source>:<vendor>` source (collectors/live.ts legacySource).
 *
 * The gate keeps that share from growing: per surface and legacy source, the number of rows may only
 * go down (native-coverage-baseline.json). A new story written for a product with no module fails the
 * gate until the module exists or the baseline is raised on purpose (`--grow`).
 */
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Collected, Surface } from "./types";

/** Surfaces whose rows go through nativeView (the others render tool tables or authored blocks). */
export const COVERAGE_SURFACES: Surface[] = ["live", "scenario"];

export const COVERAGE_PATH = join(process.cwd(), "src", "lib", "logs", "realism", "native-coverage-baseline.json");

export interface Coverage {
  /** Per surface: rows rendered, of which legacy. */
  totals: Record<string, { rows: number; legacy: number }>;
  /** `surface|legacy:<source>:<vendor>` -> legacy rows. */
  groups: Record<string, number>;
}

export interface CoverageBaseline { note: string; totals: Coverage["totals"]; groups: Record<string, number> }

export function coverage(c: Collected): Coverage {
  const totals: Coverage["totals"] = {};
  const groups: Record<string, number> = {};
  for (const r of c.rows) {
    if (!COVERAGE_SURFACES.includes(r.surface)) continue;
    const t = (totals[r.surface] ??= { rows: 0, legacy: 0 });
    t.rows++;
    if (!r.source.startsWith("legacy:")) continue;
    t.legacy++;
    const k = `${r.surface}|${r.source}`;
    groups[k] = (groups[k] ?? 0) + 1;
  }
  return { totals, groups: Object.fromEntries(Object.entries(groups).sort(([a], [b]) => a.localeCompare(b))) };
}

export function readCoverageBaseline(): CoverageBaseline | null {
  if (!existsSync(COVERAGE_PATH)) return null;
  return JSON.parse(readFileSync(COVERAGE_PATH, "utf8")) as CoverageBaseline;
}

/** Groups above their baseline ceiling (or new), and groups that went down (the baseline can shrink). */
export function compareCoverage(cov: Coverage, base: CoverageBaseline | null): { grown: string[]; shrunk: string[] } {
  const ceil = base?.groups ?? {};
  const grown = Object.entries(cov.groups)
    .filter(([k, n]) => n > (ceil[k] ?? 0))
    .map(([k, n]) => `${k}: ${n} legacy rows (baseline ${ceil[k] ?? 0})`);
  const shrunk = Object.entries(ceil)
    .filter(([k, n]) => (cov.groups[k] ?? 0) < n)
    .map(([k, n]) => `${k}: ${cov.groups[k] ?? 0} (baseline ${n})`);
  return { grown, shrunk };
}

/** Write the baseline. Shrink-only: a group may not grow or appear unless `allowGrow`. */
export function writeCoverageBaseline(cov: Coverage, allowGrow = false): { refused: string[] } {
  const prev = readCoverageBaseline();
  const { grown } = compareCoverage(cov, prev);
  const refused = prev && !allowGrow ? grown : [];
  const groups: Record<string, number> = {};
  for (const [k, n] of Object.entries(cov.groups)) groups[k] = prev && !allowGrow ? Math.min(n, prev.groups[k] ?? 0) : n;
  for (const k of Object.keys(groups)) if (groups[k] === 0) delete groups[k];
  const body: CoverageBaseline = {
    note: "Legacy (non-native) log rows per surface and source, as the realism gate collects them. Ceilings only go down: add the source's native module (src/lib/logs/native/sources), then `npm run realism:baseline`.",
    totals: cov.totals, groups,
  };
  writeFileSync(COVERAGE_PATH, JSON.stringify(body, null, 1) + "\n");
  return { refused };
}

export function coverageText(cov: Coverage): string {
  const lines = Object.entries(cov.totals).map(([s, t]) => `${s}: ${t.legacy} of ${t.rows} rows legacy (${t.rows ? ((100 * t.legacy) / t.rows).toFixed(1) : "0"}%)`);
  const top = Object.entries(cov.groups).sort((a, b) => b[1] - a[1]).slice(0, 12).map(([k, n]) => `  ${n}  ${k}`);
  return [...lines, ...(top.length ? ["largest legacy groups:", ...top] : [])].join("\n");
}
