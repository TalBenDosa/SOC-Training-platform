#!/usr/bin/env node
/**
 * npm run realism:baseline   rewrite realism-baseline.json (shrink-only; --grow for an approved reset)
 * npm run realism:report     write realism-report.md
 * Both run the gate test with REALISM_MODE set, so they see exactly what the gate sees.
 */
import { spawnSync } from "node:child_process";

const mode = process.argv[2];
if (mode !== "baseline" && mode !== "report") {
  console.error("usage: node src/lib/logs/realism/cli.mjs baseline|report [--grow]");
  process.exit(2);
}
const env = { ...process.env, REALISM_MODE: mode, ...(process.argv.includes("--grow") ? { REALISM_ALLOW_GROW: "1" } : {}) };
const r = spawnSync("npx", ["vitest", "run", "src/lib/logs/realism/realism.gate.test.ts", "--testTimeout=900000"], { stdio: "inherit", env, shell: process.platform === "win32" });
process.exit(r.status ?? 1);
