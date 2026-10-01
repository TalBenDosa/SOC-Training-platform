// Replace hand-typed placeholder digests ("A1B2C3D4E5F6789012…") in telemetry and
// content with realistic ones. Deterministic and global: the same placeholder maps to
// the same replacement in every file, so a log, its answer key, the hash lookup and a
// room's flag all stay consistent. Real sourced hashes (malwareHashes.ts /
// hashDatabase.ts) are never touched. Case is preserved (an upper-case authored digest
// stays upper-case).
//
//   node scripts/fix-synthetic-hashes.mjs          # dry run: report
//   node scripts/fix-synthetic-hashes.mjs --write  # rewrite files
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { isSyntheticHex } from "./lib/syntheticHash.mjs";

const ROOTS = ["src/lib/sim", "src/app/(app)/dashboard", "src/data", "src/lib/edr", "src/lib/team"];
const SKIP = new Set(["src/lib/sim/malwareHashes.ts", "src/lib/sim/hashDatabase.ts"].map(p => path.normalize(p)));
const write = process.argv.includes("--write");

const known = new Set();
for (const f of SKIP) for (const m of fs.readFileSync(f, "utf8").matchAll(/\b[a-f0-9]{32,64}\b/gi)) known.add(m[0].toLowerCase());

const walk = (d, o = []) => {
  if (!fs.existsSync(d)) return o;
  for (const e of fs.readdirSync(d, { withFileTypes: true })) {
    const p = path.join(d, e.name);
    if (e.isDirectory()) walk(p, o);
    else if (/\.(ts|tsx|json)$/.test(e.name) && !/\.test\.tsx?$/.test(e.name) && !SKIP.has(path.normalize(p))) o.push(p);
  }
  return o;
};

const map = new Map();
function replacement(orig) {
  const key = orig.toLowerCase();
  if (map.has(key)) return map.get(key);
  let i = 0, r;
  do { r = crypto.createHash("sha256").update(`hts-realistic:${key}:${i++}`).digest("hex"); while (r.length < key.length) r += crypto.createHash("sha256").update(r).digest("hex"); r = r.slice(0, key.length); }
  while (isSyntheticHex(r) || known.has(r));
  map.set(key, r);
  return r;
}

let files = 0, occ = 0;
for (const f of ROOTS.flatMap(r => walk(r))) {
  const t = fs.readFileSync(f, "utf8");
  let n = 0;
  const out = t.replace(/\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b/g, v => {
    if (known.has(v.toLowerCase()) || !isSyntheticHex(v)) return v;
    n++;
    const r = replacement(v);
    return v === v.toUpperCase() && /[A-F]/.test(v) ? r.toUpperCase() : r;
  });
  if (n) { files++; occ += n; if (write) fs.writeFileSync(f, out, "utf8"); }
}
console.log(`${write ? "rewrote" : "would rewrite"} ${occ} occurrence(s) of ${map.size} placeholder digest(s) in ${files} file(s)`);
