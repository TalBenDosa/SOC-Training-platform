#!/usr/bin/env node
// Replaces hand-typed looking hex digests (32, 40 or 64 hex chars that isSyntheticHex flags) in a
// track staging folder with realistic ones, the same way scripts/fix-synthetic-hashes.mjs does for
// repo files, so a value stays identical across lesson.json, room.json and evidence.json.
//   node scripts/track-builder/fix-staging-hashes.mjs <track staging folder>
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { isSyntheticHex } from "../lib/syntheticHash.mjs";

const root = process.argv[2];
if (!root) { console.error("usage: fix-staging-hashes.mjs <track staging folder>"); process.exit(2); }
const map = new Map();
const replacement = orig => {
  const key = orig.toLowerCase();
  if (!map.has(key)) {
    let i = 0, r;
    do {
      r = crypto.createHash("sha256").update(`hts-realistic:${key}:${i++}`).digest("hex");
      while (r.length < key.length) r += crypto.createHash("sha256").update(r).digest("hex");
      r = r.slice(0, key.length);
    } while (isSyntheticHex(r));
    map.set(key, r);
  }
  const r = map.get(key);
  return orig === orig.toUpperCase() && /[A-F]/.test(orig) ? r.toUpperCase() : r;
};
let n = 0;
for (const d of fs.readdirSync(root, { withFileTypes: true }).filter(d => d.isDirectory())) {
  for (const f of ["lesson.json", "room.json", "evidence.json"]) {
    const p = path.join(root, d.name, f);
    if (!fs.existsSync(p)) continue;
    const text = fs.readFileSync(p, "utf8");
    const out = text.replace(/\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b/g, m => (isSyntheticHex(m) ? (n++, replacement(m)) : m));
    if (out !== text) { JSON.parse(out); fs.writeFileSync(p, out); console.log(`${d.name}/${f}`); }
  }
}
console.log(`${n} value(s) replaced, ${map.size} distinct`);
