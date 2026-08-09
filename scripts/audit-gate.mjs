#!/usr/bin/env node
/**
 * audit-gate.mjs — fail the build on any PRODUCTION dependency vulnerability
 * that isn't a documented, still-justified exception.
 *
 * Why this exists rather than a bare `npm audit`:
 *
 *  1. `npm audit` exits non-zero for dev-only findings too. A build tool with a
 *     DoS advisory cannot be exploited by a visitor to the deployed site, so
 *     gating on it trains people to pass --audit-level or ignore the step. We
 *     scan --omit=dev and gate on what actually ships.
 *
 *  2. Some advisories have NO upstream fix. Left unhandled they make the audit
 *     permanently red, which is strictly worse than no audit: a real new
 *     finding arrives into output everyone has already learned to skip. Each
 *     one here is listed below with why it cannot be reached, and a date to
 *     re-check — so the exception is a decision on the record, not a silence.
 *
 * Anything NOT in ALLOW fails the build, at any severity. That is the point:
 * the allowlist is the only escape hatch, and adding to it takes a written
 * reason.
 *
 * Usage: node scripts/audit-gate.mjs
 */
import { execSync } from "node:child_process";

/**
 * Each entry: why the vulnerable code cannot execute in this app, and when to
 * look again. `recheck` is advisory — it prints a reminder rather than failing,
 * because a hard expiry would break deploys on a date nobody chose.
 */
const ALLOW = {
  "image-size": {
    advisories: [
      "ICNS parser infinite-loop DoS",
      "JXL and HEIF parser infinite-loop DoS",
    ],
    reason:
      "No fixed release exists (2.0.2 is latest and still in range), and the " +
      "code is unreachable here on three independent counts: (a) image-size " +
      "appears only in pptxgenjs's package.json — it is never imported by " +
      "anything in its dist/ or types/, so it is a declared-but-unused dep; " +
      "(b) our only pptxgenjs use is src/lib/lessons/exportPptx.ts, which " +
      "never calls addImage, so no image is passed to it at all; (c) .pptx " +
      "PARSING is client-side (jszip, src/lib/lessons/importPptx.ts) — the " +
      "import-pptx route receives already-extracted slide text as JSON and " +
      "never handles the binary. Exploiting it needs attacker-controlled " +
      "image bytes reaching the parser; no such path exists.",
    recheck: "2026-11-01",
    // Re-verify (a) with: grep -rl image-size node_modules/pptxgenjs/
    //          and (b) with: grep -n addImage src/lib/lessons/exportPptx.ts
  },
};

function main() {
  let report;
  try {
    // npm audit exits non-zero when it finds anything, so capture rather than throw.
    // One hardcoded string, no interpolation and no caller input, so there is
    // nothing for a shell to mis-split. execFileSync with an args array is the
    // usual safer choice, but it cannot launch npm.cmd on Windows without
    // shell:true (spawnSync EINVAL on Node 20+), and shell:true WITH an args
    // array is the unescaped-concatenation footgun (DEP0190). A fixed command
    // string sidesteps both. Keep it literal — if this ever needs a dynamic
    // argument, switch to execFileSync and solve the Windows launch separately.
    report = execSync("npm audit --omit=dev --json", {
      encoding: "utf8",
      maxBuffer: 32 * 1024 * 1024,
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (err) {
    report = err.stdout;
    if (!report) {
      console.error("audit-gate: could not run `npm audit`.");
      console.error(err.stderr || err.message);
      process.exit(2);
    }
  }

  let parsed;
  try {
    parsed = JSON.parse(report);
  } catch {
    console.error("audit-gate: `npm audit --json` did not return JSON.");
    process.exit(2);
  }

  const vulns = parsed.vulnerabilities ?? {};
  const blocking = [];
  const allowed = [];

  for (const [name, v] of Object.entries(vulns)) {
    // `via` holds advisory objects for the package itself and plain strings for
    // packages that are only vulnerable through a dependency. A package whose
    // via is all strings has no advisory of its own — its parent is reported
    // separately, so counting it here would double-report the same finding.
    const advisories = (v.via ?? []).filter(x => typeof x === "object");
    if (advisories.length === 0) continue;

    (ALLOW[name] ? allowed : blocking).push({ name, severity: v.severity, advisories });
  }

  for (const { name, severity, advisories } of allowed) {
    const entry = ALLOW[name];
    console.log(`ALLOWED  ${name} (${severity}) — ${advisories.length} advisory/advisories`);
    console.log(`         ${entry.reason.replace(/\s+/g, " ")}`);
    console.log(`         re-check by ${entry.recheck}`);
    if (new Date(entry.recheck) < new Date()) {
      console.log(`         ^ NOTE: re-check date has passed — confirm this is still unreachable.`);
    }
  }

  if (blocking.length === 0) {
    console.log(
      `\naudit-gate: PASS — no unreviewed production vulnerabilities ` +
      `(${allowed.length} documented exception${allowed.length === 1 ? "" : "s"}).`,
    );
    return;
  }

  console.error("\naudit-gate: FAIL — production vulnerabilities with no documented exception:\n");
  for (const { name, severity, advisories } of blocking) {
    console.error(`  ${severity.toUpperCase().padEnd(8)} ${name}`);
    for (const a of advisories) console.error(`           - ${a.title}`);
  }
  console.error(
    `\nFix by upgrading, or by pinning the transitive package in package.json ` +
    `"overrides". If genuinely unreachable and unfixable upstream, add it to ` +
    `ALLOW in ${"scripts/audit-gate.mjs"} WITH the reason it cannot execute.`,
  );
  process.exit(1);
}

main();
