#!/usr/bin/env node
/**
 * Vendor normalisation codemod.
 *
 * The corpus declared 116 distinct `vendor:` strings for roughly 60 real products
 * — `Sysmon` / `Microsoft Sysmon` / `Sysinternals Sysmon`, `FortiGate 100F` /
 * `FortiGate 600F` / `Fortinet FortiGate`, and so on. That made the log-field gate
 * unable to resolve a schema for a large share of events, so they went unvalidated.
 *
 * This rewrites every `vendor: "..."` to the canonical product name from
 * scripts/vendor-normalization-map.json. Canonical names stay human-readable
 * because `vendor` is displayed in the raw-log view.
 *
 * Usage:
 *   node scripts/normalize-vendors.mjs            # dry run (default) — shows the diff summary
 *   node scripts/normalize-vendors.mjs --write    # apply
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");
const WRITE = process.argv.includes("--write");

const SCAN = ["src/data", "src/lib/sim", "src/app/(app)/dashboard"];

const { map } = JSON.parse(
  fs.readFileSync(path.join(__dirname, "vendor-normalization-map.json"), "utf8"),
);

function walk(dir, acc = []) {
  if (!fs.existsSync(dir)) return acc;
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const f = path.join(dir, e.name);
    if (e.isDirectory()) walk(f, acc);
    else if (/\.tsx?$/.test(e.name)) acc.push(f);
  }
  return acc;
}

const files = SCAN.flatMap(g => walk(path.join(ROOT, g)));
const VENDOR_RE = /vendor:\s*"((?:[^"\\]|\\.)*)"/g;

// ── pass 1: completeness check ────────────────────────────────────────────
const found = new Map();
for (const f of files) {
  const text = fs.readFileSync(f, "utf8");
  for (const m of text.matchAll(VENDOR_RE)) {
    found.set(m[1], (found.get(m[1]) ?? 0) + 1);
  }
}

const unmapped = [...found.keys()].filter(v => !(v in map));
if (unmapped.length) {
  console.error(`\n\x1b[31mRefusing to run — ${unmapped.length} vendor string(s) have no mapping:\x1b[0m\n`);
  for (const v of unmapped.sort()) console.error(`  ${String(found.get(v)).padStart(4)}x  "${v}"`);
  console.error(`\nAdd them to scripts/vendor-normalization-map.json first. Guessing here would`);
  console.error(`silently mis-declare a schema, which is the bug this codemod exists to fix.\n`);
  process.exit(1);
}

// ── pass 2: rewrite ───────────────────────────────────────────────────────
let filesChanged = 0, replacements = 0;
const changes = new Map(); // "from -> to" : count

for (const f of files) {
  const text = fs.readFileSync(f, "utf8");
  let touched = false;
  const next = text.replace(VENDOR_RE, (whole, raw) => {
    const canon = map[raw];
    if (canon === raw) return whole;
    touched = true;
    replacements++;
    const k = `"${raw}" -> "${canon}"`;
    changes.set(k, (changes.get(k) ?? 0) + 1);
    return `vendor: "${canon}"`;
  });
  if (touched) {
    filesChanged++;
    if (WRITE) fs.writeFileSync(f, next);
  }
}

// ── report ────────────────────────────────────────────────────────────────
const before = found.size;
const after = new Set([...found.keys()].map(v => map[v])).size;

console.log(`\n\x1b[1mVendor normalisation${WRITE ? "" : "  (dry run — pass --write to apply)"}\x1b[0m`);
console.log(`  files scanned      ${files.length}`);
console.log(`  files changed      ${filesChanged}`);
console.log(`  declarations       ${[...found.values()].reduce((a, b) => a + b, 0)}`);
console.log(`  rewritten          ${replacements}`);
console.log(`  distinct vendors   ${before} -> \x1b[32m${after}\x1b[0m\n`);

const rows = [...changes.entries()].sort((a, b) => b[1] - a[1]);
for (const [k, n] of rows) console.log(`  ${String(n).padStart(4)}x  ${k}`);
console.log();

if (!WRITE) console.log(`  Nothing written. Re-run with --write to apply.\n`);
