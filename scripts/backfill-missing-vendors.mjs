#!/usr/bin/env node
/**
 * Backfill `vendor:` on raw blocks that declare none.
 *
 * The log-field gate skips any block it cannot attribute to a product, so a
 * missing `vendor` is a silent hole in coverage. This fills only the cases the
 * raw fields identify UNAMBIGUOUSLY (winlog.*, data.office365.*, aws.cloudtrail.*,
 * Wazuh decoder fields). Anything it cannot prove is left alone and reported —
 * guessing a vendor would fabricate a schema claim, which is the exact defect
 * the gate exists to catch.
 *
 *   node scripts/backfill-missing-vendors.mjs           # dry run
 *   node scripts/backfill-missing-vendors.mjs --write   # apply
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");
const WRITE = process.argv.includes("--write");
const SCAN = ["src/data", "src/lib/sim", "src/app/(app)/dashboard"];

function walk(d, acc = []) {
  if (!fs.existsSync(d)) return acc;
  for (const e of fs.readdirSync(d, { withFileTypes: true })) {
    const f = path.join(d, e.name);
    if (e.isDirectory()) walk(f, acc);
    else if (/\.tsx?$/.test(e.name)) acc.push(f);
  }
  return acc;
}

const pn = p => {
  const n = p.name;
  if (!n) return null;
  return ts.isIdentifier(n) || ts.isStringLiteral(n) ? n.text : null;
};

/** Decide a vendor from the raw fields alone, or null if not provable. */
function inferVendor(entries) {
  const keys = entries.map(([k]) => k);
  const has = re => keys.some(k => re.test(k));
  const valueOf = name => (entries.find(([k]) => k === name) ?? [])[1] ?? "";

  if (has(/^aws\.cloudtrail\./)) return "AWS CloudTrail";
  if (has(/^data\.office365\./)) return "Microsoft 365 Unified Audit Log";
  if (has(/^okta\./)) return "Okta";

  if (has(/^winlog\.|^event\.code$/)) {
    const provider = valueOf("winlog.provider_name");
    if (/sysmon/i.test(provider)) return "Microsoft Sysmon";
    if (/DNS-Server/i.test(provider)) return "Windows DNS Server";
    if (/TerminalServices/i.test(provider)) return "Windows TerminalServices";
    const channel = valueOf("winlog.channel");
    if (/^Security$/i.test(channel) || provider === "") return "Windows Security";
    return null; // some other channel — don't guess
  }

  // Wazuh decoder shape: SIEM rule.* metadata over data.srcip/data.dstip.
  if (has(/^data\.(srcip|dstip)$/) && has(/^rule\./)) return "Wazuh";

  return null;
}

const filled = [];
const skipped = [];

for (const file of SCAN.flatMap(g => walk(path.join(ROOT, g)))) {
  const text = fs.readFileSync(file, "utf8");
  const sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);
  /** @type {{pos:number, indent:string, vendor:string}[]} */
  const inserts = [];

  const visit = node => {
    if (ts.isObjectLiteralExpression(node)) {
      for (const prop of node.properties) {
        if (!ts.isPropertyAssignment(prop)) continue;
        if (pn(prop) !== "raw") continue;
        if (!ts.isObjectLiteralExpression(prop.initializer)) continue;

        // Already has a vendor anywhere up the chain? Accept ANY initializer —
        // some generators compute it (`vendor: x === "gsuite" ? "A" : "B"`), and
        // only matching string literals here would insert a duplicate property.
        let ven = null;
        const scan = o => {
          for (const q of o.properties) {
            if (ts.isPropertyAssignment(q) && pn(q) === "vendor") {
              ven = ven || (ts.isStringLiteral(q.initializer) ? q.initializer.text : "<computed>");
            }
          }
        };
        scan(node);
        let x = node.parent;
        while (x && !ven) { if (ts.isObjectLiteralExpression(x)) scan(x); x = x.parent; }
        if (ven) continue;

        const entries = prop.initializer.properties
          .filter(ts.isPropertyAssignment)
          .map(q => [pn(q), ts.isStringLiteral(q.initializer) ? q.initializer.text : ""])
          .filter(([k]) => k);

        const rel = path.relative(ROOT, file).replace(/\\/g, "/");
        const { line } = sf.getLineAndCharacterOfPosition(prop.getStart(sf));
        const vendor = inferVendor(entries);

        if (!vendor) {
          skipped.push({ file: rel, line: line + 1, sample: entries.slice(0, 4).map(([k]) => k).join(", ") });
          continue;
        }

        const start = prop.getStart(sf);
        const lineStart = text.lastIndexOf("\n", start) + 1;
        const indent = text.slice(lineStart, start);
        inserts.push({ pos: lineStart, indent, vendor });
        filled.push({ file: rel, line: line + 1, vendor });
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);

  if (inserts.length && WRITE) {
    let next = text;
    for (const ins of inserts.sort((a, b) => b.pos - a.pos)) {
      next = next.slice(0, ins.pos) + `${ins.indent}vendor: "${ins.vendor}",\n` + next.slice(ins.pos);
    }
    fs.writeFileSync(file, next);
  }
}

console.log(`\n\x1b[1mBackfill missing vendors${WRITE ? "" : "  (dry run — pass --write to apply)"}\x1b[0m`);
console.log(`  inferred   ${filled.length}`);
console.log(`  unprovable ${skipped.length}\n`);

const byVendor = {};
for (const f of filled) byVendor[f.vendor] = (byVendor[f.vendor] ?? 0) + 1;
for (const [v, n] of Object.entries(byVendor).sort((a, b) => b[1] - a[1])) {
  console.log(`  ${String(n).padStart(3)}x  ${v}`);
}

if (skipped.length) {
  console.log(`\n\x1b[33m  Left alone — raw fields do not identify a product:\x1b[0m`);
  for (const s of skipped.slice(0, 8)) console.log(`    ${s.file}:${s.line}  [${s.sample}]`);
  if (skipped.length > 8) console.log(`    ... and ${skipped.length - 8} more`);
  console.log(`\n  These use generic normalised field names and are not modelled on any real`);
  console.log(`  product. They need rewriting against a vendor schema, not a label.`);
}
console.log();
