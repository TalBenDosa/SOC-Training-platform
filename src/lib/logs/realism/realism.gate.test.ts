/**
 * Log realism gate (docs/LOG-REALISM-STANDARD.md): every checker (R1 to R9) over every surface (Live
 * Feed, Scenarios, Team Training, XDR, EDR, Forensic workbench, learning rooms). Prints the
 * per-surface x per-rule table and fails only on violations missing from realism-baseline.json.
 *
 * Modes (env REALISM_MODE, set by src/lib/logs/realism/cli.mjs):
 *   (unset)   gate: fail on new violations
 *   baseline  rewrite the baseline from the current violations (shrink-only unless REALISM_ALLOW_GROW=1)
 *   report    write realism-report.md
 */
import { describe, expect, it } from "vitest";
import { collectAll } from "./collect";
import { runAll } from "./checkers";
import { violationKey } from "./types";
import { readBaseline, tableText, writeBaseline, writeReport } from "./report";
import { compareCoverage, coverage, coverageText, readCoverageBaseline, writeCoverageBaseline } from "./coverage";

describe("log realism gate", () => {
  it("no violation outside the reviewed baseline", () => {
    const c = collectAll();
    const vs = runAll(c);
    const cov = coverage(c);
    console.log(`[realism]\n${c.notes.join("\n")}\n\n${tableText(vs)}\n\n[native coverage]\n${coverageText(cov)}\n`);
    const mode = process.env.REALISM_MODE;
    if (mode === "baseline") {
      const grow = process.env.REALISM_ALLOW_GROW === "1";
      const r = writeBaseline(vs, grow);
      const rc = writeCoverageBaseline(cov, grow);
      console.log(`[realism] baseline written: ${r.written} keys${r.refused.length ? `; refused ${r.refused.length} new keys (the baseline only shrinks):\n${r.refused.slice(0, 30).join("\n")}` : ""}`);
      if (rc.refused.length) console.log(`[realism] native coverage: refused to raise ${rc.refused.length} ceilings:\n${rc.refused.join("\n")}`);
      expect([...r.refused, ...rc.refused]).toEqual([]);
      return;
    }
    if (mode === "report") {
      writeReport(c, vs);
      console.log("[realism] report written to src/lib/logs/realism/realism-report.md");
      return;
    }
    const base = readBaseline();
    const accepted = new Set(base?.accepted ?? []);
    const keys = new Set(vs.map(violationKey));
    const fresh = vs.filter(v => !accepted.has(violationKey(v)));
    const fixed = [...accepted].filter(k => !keys.has(k));
    if (fixed.length) console.log(`[realism] ${fixed.length} baselined violations are fixed: run \`npm run realism:baseline\` to shrink the baseline.`);
    expect(fresh.map(v => `${violationKey(v)}${v.example ? `  e.g. ${v.example}` : ""}`).slice(0, 40)).toEqual([]);
    // Native coverage: legacy (non-native) rows per surface and source may only go down.
    const { grown, shrunk } = compareCoverage(cov, readCoverageBaseline());
    if (shrunk.length) console.log(`[realism] native coverage improved (${shrunk.length} groups): run \`npm run realism:baseline\` to lower the ceilings.`);
    expect(grown).toEqual([]);
  }, 900_000);
});
