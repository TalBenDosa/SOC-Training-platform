#!/usr/bin/env node
/**
 * Vendor log-field CI gate.
 *
 * Every `raw: { ... }` block in the content data is a claim: "this is what
 * <vendor> actually emits." Five independent expert reviews found that claim
 * to be false often enough to be the platform's single largest credibility
 * risk — fields like `crowdstrike.Confidence`, `s1.extensionAdded` and
 * `RequestorName` (on Event 4769) do not exist in the named product, and in
 * several cases a graded answer depended on one.
 *
 * This script parses the real TypeScript AST (not regex) to find every event
 * literal carrying a `raw` object, resolves its declared vendor through an
 * alias table, and checks each field against scripts/log-field-registry.json.
 *
 * Usage:
 *   node scripts/validate-log-fields.mjs                 # report + exit 1 on violations
 *   node scripts/validate-log-fields.mjs --baseline      # write current state as accepted
 *   node scripts/validate-log-fields.mjs --json          # machine-readable output
 *   node scripts/validate-log-fields.mjs --unknown-vendors  # list vendors with no registry entry
 *
 * Exit codes: 0 = clean (or only baselined violations), 1 = new violations, 2 = harness error.
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");

// LOG_FIELD_REGISTRY lets you point the gate at an alternate registry (used
// when iterating on the registry itself, and by the harness self-test).
const REGISTRY_PATH = process.env.LOG_FIELD_REGISTRY
  ? path.resolve(process.env.LOG_FIELD_REGISTRY)
  : path.join(__dirname, "log-field-registry.json");
const BASELINE_PATH = path.join(__dirname, "log-field-baseline.json");

const SCAN_GLOBS = [
  "src/data",
  "src/lib/sim",
  "src/app/(app)/dashboard",
];

const args = new Set(process.argv.slice(2));
const WRITE_BASELINE = args.has("--baseline");
const AS_JSON = args.has("--json");
const LIST_UNKNOWN_VENDORS = args.has("--unknown-vendors");

// ── helpers ───────────────────────────────────────────────────────────────

function die(msg) {
  console.error(`\x1b[31mvalidate-log-fields: ${msg}\x1b[0m`);
  process.exit(2);
}

function walkFiles(dir, acc = []) {
  if (!fs.existsSync(dir)) return acc;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walkFiles(full, acc);
    else if (/\.tsx?$/.test(entry.name)) acc.push(full);
  }
  return acc;
}

/** Property name for both `foo:` and `"foo.bar":` forms. */
function propName(prop) {
  const n = prop.name;
  if (!n) return null;
  if (ts.isIdentifier(n)) return n.text;
  if (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n)) return n.text;
  return null;
}

function stringValue(node) {
  if (!node) return null;
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
  return null;
}

/** Find a direct string-valued property on an object literal. */
function directProp(objLit, name) {
  for (const p of objLit.properties) {
    if (!ts.isPropertyAssignment(p)) continue;
    if (propName(p) === name) return stringValue(p.initializer);
  }
  return null;
}

// ── registry ──────────────────────────────────────────────────────────────

if (!fs.existsSync(REGISTRY_PATH)) {
  die(`registry not found at ${path.relative(ROOT, REGISTRY_PATH)}.\n` +
      `  The registry is committed to the repo so CI can run without the authoring environment.`);
}

let registry;
try {
  registry = JSON.parse(fs.readFileSync(REGISTRY_PATH, "utf8"));
} catch (e) {
  die(`registry is not valid JSON: ${e.message}`);
}

const commonExact = new Set((registry.commonFields ?? []).filter(f => !f.endsWith(".")));
const commonPrefixes = (registry.commonFields ?? []).filter(f => f.endsWith("."));

/** alias (lowercased) -> vendor key */
const aliasIndex = new Map();
for (const [key, v] of Object.entries(registry.vendors ?? {})) {
  aliasIndex.set(key.toLowerCase(), key);
  aliasIndex.set((v.label ?? "").toLowerCase(), key);
  for (const a of v.aliases ?? []) aliasIndex.set(a.toLowerCase(), key);
}
aliasIndex.delete("");

function resolveVendor(declared) {
  if (!declared) return null;
  const lower = declared.toLowerCase().trim();
  if (aliasIndex.has(lower)) return aliasIndex.get(lower);
  // Longest-alias containment fallback: "FortiGate 100F" -> "fortigate".
  let best = null;
  for (const [alias, key] of aliasIndex) {
    if (alias.length < 4) continue;
    if (lower.includes(alias) && (!best || alias.length > best.alias.length)) {
      best = { alias, key };
    }
  }
  return best ? best.key : null;
}

function fieldAllowed(vendorKey, field) {
  if (commonExact.has(field)) return true;
  if (commonPrefixes.some(p => field.startsWith(p))) return true;
  const v = registry.vendors[vendorKey];
  if (!v) return false;
  if ((v.exactFields ?? []).includes(field)) return true;
  if ((v.prefixes ?? []).some(p => field.startsWith(p))) return true;
  return false;
}

// ── extraction ────────────────────────────────────────────────────────────

const files = SCAN_GLOBS.flatMap(g => walkFiles(path.join(ROOT, g)));
if (files.length === 0) die("no source files found to scan — check SCAN_GLOBS.");

/** @type {{file:string,line:number,vendor:string|null,fields:string[]}[]} */
const events = [];

for (const file of files) {
  const text = fs.readFileSync(file, "utf8");
  const sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);

  const visit = (node) => {
    if (ts.isObjectLiteralExpression(node)) {
      for (const prop of node.properties) {
        if (!ts.isPropertyAssignment(prop)) continue;
        if (propName(prop) !== "raw") continue;
        if (!ts.isObjectLiteralExpression(prop.initializer)) continue;

        const fields = [];
        for (const rp of prop.initializer.properties) {
          if (!ts.isPropertyAssignment(rp) && !ts.isShorthandPropertyAssignment(rp)) continue;
          const name = propName(rp);
          if (name) fields.push(name);
        }

        // `vendor` normally sits beside `raw` on the event literal; some
        // shapes nest raw one level deeper, so fall back to the enclosing
        // object literal before giving up.
        let vendor = directProp(node, "vendor");
        if (!vendor) {
          let p = node.parent;
          while (p && !vendor) {
            if (ts.isObjectLiteralExpression(p)) vendor = directProp(p, "vendor");
            p = p.parent;
          }
        }

        const { line } = sf.getLineAndCharacterOfPosition(prop.getStart(sf));
        events.push({
          file: path.relative(ROOT, file).replace(/\\/g, "/"),
          line: line + 1,
          vendor,
          fields,
        });
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
}

// ── evaluation ────────────────────────────────────────────────────────────

const violations = [];
const vendorless = [];
const unresolvedVendors = new Map(); // declared -> count

for (const ev of events) {
  if (!ev.vendor) {
    vendorless.push(ev);
    continue;
  }
  const key = resolveVendor(ev.vendor);
  if (!key) {
    unresolvedVendors.set(ev.vendor, (unresolvedVendors.get(ev.vendor) ?? 0) + 1);
    continue; // no registry coverage -> cannot judge; reported separately
  }
  for (const f of ev.fields) {
    if (!fieldAllowed(key, f)) {
      violations.push({ file: ev.file, line: ev.line, vendor: ev.vendor, vendorKey: key, field: f });
    }
  }
}

const violationId = v => `${v.file}:${v.vendorKey}:${v.field}`;

// ── baseline ──────────────────────────────────────────────────────────────

if (WRITE_BASELINE) {
  const accepted = [...new Set(violations.map(violationId))].sort();
  fs.writeFileSync(BASELINE_PATH, JSON.stringify({
    note: "Pre-existing field violations, accepted so the gate can block NEW ones while the backlog is worked down. Shrink this list; never grow it.",
    generated: "run `node scripts/validate-log-fields.mjs --baseline` to regenerate",
    count: accepted.length,
    accepted,
  }, null, 2) + "\n");
  console.log(`Baseline written: ${accepted.length} accepted violations -> ${path.relative(ROOT, BASELINE_PATH)}`);
  process.exit(0);
}

let baseline = new Set();
if (fs.existsSync(BASELINE_PATH)) {
  try {
    baseline = new Set(JSON.parse(fs.readFileSync(BASELINE_PATH, "utf8")).accepted ?? []);
  } catch (e) {
    die(`baseline is not valid JSON: ${e.message}`);
  }
}

const fresh = violations.filter(v => !baseline.has(violationId(v)));

// ── reporting ─────────────────────────────────────────────────────────────

if (LIST_UNKNOWN_VENDORS) {
  const rows = [...unresolvedVendors.entries()].sort((a, b) => b[1] - a[1]);
  console.log(`Vendors with no registry entry (${rows.length}):\n`);
  for (const [name, n] of rows) console.log(`  ${String(n).padStart(4)}x  ${name}`);
  process.exit(0);
}

if (AS_JSON) {
  console.log(JSON.stringify({
    scannedFiles: files.length,
    events: events.length,
    fieldsChecked: events.reduce((n, e) => n + e.fields.length, 0),
    violations: violations.length,
    newViolations: fresh.length,
    baselined: baseline.size,
    vendorless: vendorless.length,
    unresolvedVendors: Object.fromEntries(unresolvedVendors),
    new: fresh,
  }, null, 2));
  process.exit(fresh.length > 0 ? 1 : 0);
}

const totalFields = events.reduce((n, e) => n + e.fields.length, 0);
console.log(`\n\x1b[1mVendor log-field gate\x1b[0m`);
console.log(`  files scanned      ${files.length}`);
console.log(`  raw blocks found   ${events.length}`);
console.log(`  fields checked     ${totalFields}`);
console.log(`  registry vendors   ${Object.keys(registry.vendors ?? {}).length}`);
if (baseline.size) console.log(`  baselined          ${baseline.size}`);

if (vendorless.length) {
  console.log(`\n\x1b[33m  ${vendorless.length} raw block(s) with no resolvable \`vendor\` — cannot be validated:\x1b[0m`);
  for (const e of vendorless.slice(0, 10)) console.log(`    ${e.file}:${e.line}`);
  if (vendorless.length > 10) console.log(`    ... and ${vendorless.length - 10} more`);
}

if (unresolvedVendors.size) {
  const rows = [...unresolvedVendors.entries()].sort((a, b) => b[1] - a[1]);
  console.log(`\n\x1b[33m  ${rows.length} declared vendor(s) absent from the registry — NOT validated:\x1b[0m`);
  for (const [name, n] of rows.slice(0, 12)) console.log(`    ${String(n).padStart(4)}x  ${name}`);
  if (rows.length > 12) console.log(`    ... and ${rows.length - 12} more (see --unknown-vendors)`);
}

if (fresh.length === 0) {
  console.log(`\n\x1b[32m  PASS — no new field violations.\x1b[0m\n`);
  process.exit(0);
}

// Group by vendor for a readable failure.
const byVendor = new Map();
for (const v of fresh) {
  if (!byVendor.has(v.vendorKey)) byVendor.set(v.vendorKey, []);
  byVendor.get(v.vendorKey).push(v);
}

console.log(`\n\x1b[31m  FAIL — ${fresh.length} field(s) not documented for their declared vendor:\x1b[0m\n`);
for (const [key, list] of [...byVendor.entries()].sort((a, b) => b[1].length - a[1].length)) {
  console.log(`  \x1b[1m${registry.vendors[key]?.label ?? key}\x1b[0m  (${list.length})`);
  const seen = new Set();
  for (const v of list) {
    if (seen.has(v.field)) continue;
    seen.add(v.field);
    console.log(`    \x1b[31m${v.field}\x1b[0m`);
    console.log(`      ${v.file}:${v.line}`);
  }
  console.log();
}
console.log(`  A field here either does not exist in the product, or the registry is`);
console.log(`  missing it. Fix the log — or, if the field is real, add it to`);
console.log(`  ${path.relative(ROOT, REGISTRY_PATH).replace(/\\/g, "/")} with a source.\n`);

process.exit(1);
