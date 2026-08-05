// MITRE ATT&CK coverage report — quantifies the gap the content audit flagged.
//
// PRACTISED = every mitre_technique that appears in the simulation data the
// student is tested on (scenarios + company live-feed profiles + scenario packs).
// TAUGHT    = every technique ID that appears anywhere in the Learning Rooms.
// The gap = techniques a learner is tested on but never taught in a room.
//
// Run: node scripts/coverage-report.mjs
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join, dirname } from "node:path";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const DATA = join(ROOT, "src", "data");
const SIM = join(ROOT, "src", "lib", "sim");
const TECH = /\bT\d{4}(?:\.\d{3})?\b/g;

function read(p) { try { return readFileSync(p, "utf8"); } catch { return ""; } }
function techniquesIn(text) { return new Set(text.match(TECH) ?? []); }
function base(t) { return t.split(".")[0]; } // sub-technique -> parent

// ── PRACTISED: mitre_technique fields in the sim data ────────────────────────
const simFiles = [
  join(SIM, "scenarios.ts"),
  join(SIM, "companyProfiles.ts"),
  ...readdirSync(join(SIM, "scenario-packs")).filter(f => f.endsWith(".ts")).map(f => join(SIM, "scenario-packs", f)),
];
const practised = new Set();
for (const f of simFiles) {
  const txt = read(f);
  // only count IDs attached to a mitre_technique field (what the student faces)
  for (const m of txt.matchAll(/mitre_technique:\s*"(T\d{4}(?:\.\d{3})?)"/g)) practised.add(m[1]);
}

// ── TAUGHT: every technique ID mentioned anywhere in the Rooms ───────────────
const roomFiles = readdirSync(DATA).filter(f => /^rooms-batch-.*\.ts$/.test(f));
const taught = new Set();
for (const f of roomFiles) for (const t of techniquesIn(read(join(DATA, f)))) taught.add(t);
// also credit lessons
for (const f of ["attackTypeLessons.ts", "playbookLessons.ts", "builtinLessons.ts", "pathLessons-a.ts", "pathLessons-b.ts", "pathLessons-c.ts", "pathLessons-d.ts", "pathLessons-e.ts", "pathLessons-f.ts", "pathLessons-g.ts"]) {
  for (const t of techniquesIn(read(join(DATA, f)))) taught.add(t);
}

// A practised technique counts as taught if the exact ID OR its parent is taught.
const taughtBases = new Set([...taught].map(base));
const isTaught = t => taught.has(t) || taught.has(base(t)) || taughtBases.has(base(t));

const missing = [...practised].filter(t => !isTaught(t)).sort();
const covered = [...practised].filter(isTaught).sort();

console.log(`\n\x1b[1mMITRE ATT&CK Coverage Report\x1b[0m`);
console.log(`${"─".repeat(48)}`);
console.log(`Practised (in sim data):   ${practised.size} techniques`);
console.log(`Taught (in rooms/lessons): ${taught.size} technique IDs`);
console.log(`\x1b[32mCovered:  ${covered.length}/${practised.size}\x1b[0m  (${Math.round(covered.length / practised.size * 100)}%)`);
console.log(`${missing.length ? "\x1b[31m" : "\x1b[32m"}Gaps:     ${missing.length}\x1b[0m`);
if (missing.length) {
  console.log(`\n\x1b[33mPractised but NOT taught in any room/lesson:\x1b[0m`);
  for (const t of missing) console.log(`  - ${t}`);
}
console.log("");
process.exit(0);
