/**
 * Post-build gate: no scenario answer key in any public client chunk.
 *
 * Everything under .next/static is served to anyone, signed in or not. A
 * scenario's answer key (question explanations, killchain, narrative) must only
 * ever leave the server through the authenticated, post-submit API responses.
 * It leaked once already: the live feed's attackStories.ts imported the
 * scenario builders, and a ~1.9 MB lazily-loaded chunk carried every
 * explanation. Unit tests (src/lib/sim/clientAnswerKeyGuard.test.ts) guard the
 * import graph; this checks the artifact the browser actually downloads, so it
 * also catches paths the import walk cannot see.
 *
 * Needles are built from the real answer key, not a hand-picked list: for every
 * scenario, the longest plain-ASCII runs (letters, digits, spaces, basic
 * punctuation) of each explanation, killchain action and the narrative. Plain
 * runs survive minification unchanged, whatever the bundler does to quotes,
 * newlines or non-ASCII characters around them.
 *
 * Run after `npm run build`:  npm run check:client-answers
 */
import { pathToFileURL } from "node:url";
import path from "node:path";
import fs from "node:fs";

const ROOT = process.cwd();
const imp = p => import(pathToFileURL(path.join(ROOT, p)).href);
const STATIC = path.join(ROOT, ".next", "static");

if (!fs.existsSync(STATIC)) {
  console.error("check-client-answer-leak: .next/static not found — run `npm run build` first.");
  process.exit(2);
}

const MIN_NEEDLE = 28;
const MAX_NEEDLE = 48;

/**
 * Up to three longest runs of plain characters, each clipped to MAX_NEEDLE.
 * Several per text because a run can straddle a `${...}` interpolation, which
 * reads differently in the bundle than in the built string.
 */
function needlesOf(text) {
  if (typeof text !== "string") return [];
  const runs = (text.match(/[A-Za-z0-9 ,.;()-]+/g) ?? []).map(r => r.trim()).filter(r => r.length >= MIN_NEEDLE);
  return runs.sort((a, b) => b.length - a.length).slice(0, 3).map(r => {
    const start = Math.floor((r.length - Math.min(r.length, MAX_NEEDLE)) / 2);
    return r.slice(start, start + MAX_NEEDLE).trim();
  });
}

const { SCENARIOS, buildScenarioBySlug } = await imp("src/lib/sim/scenarios.ts");

/** @type {{ needle: string, where: string }[]} */
const needles = [];
const seen = new Set();
const push = (text, where) => {
  for (const n of needlesOf(text)) if (!seen.has(n)) { seen.add(n); needles.push({ needle: n, where }); }
};
for (const { slug } of SCENARIOS) {
  const b = buildScenarioBySlug(slug);
  if (!b) continue;
  push(b.narrative, `${slug} narrative`);
  for (const q of b.questions ?? []) push(q.explanation, `${slug} ${q.id} explanation`);
  for (const [i, k] of (b.killchain ?? []).entries()) push(k.action, `${slug} killchain[${i}]`);
}

function walk(dir, re, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, re, out);
    else if (re.test(e.name)) out.push(p);
  }
  return out;
}

// A needle that also appears in some NON-answer-key source file (a lesson that
// quotes the same Entra log string, a room that teaches the same command, the
// events modules) is public by design and would only produce noise. Keep the
// needles that exist nowhere but in the answer key.
const isAnswerKeySource = f => {
  const r = path.relative(ROOT, f).replace(/\\/g, "/");
  return r === "src/lib/sim/scenarios.ts" ||
    (/^src\/lib\/sim\/scenario-packs\/[^/]+\.ts$/.test(r) && !/\.(events|test)\.ts$/.test(r));
};
const publicSource = walk(path.join(ROOT, "src"), /\.(ts|tsx|md|json)$/)
  .filter(f => !isAnswerKeySource(f))
  .map(f => fs.readFileSync(f, "utf8"))
  .join("\n");
const specific = needles.filter(({ needle }) => !publicSource.includes(needle));

if (specific.length < SCENARIOS.length * 3) {
  console.error(`check-client-answer-leak: only ${specific.length} usable needles from ${SCENARIOS.length} scenarios — needle extraction is broken.`);
  process.exit(2);
}

const files = walk(STATIC, /\.(js|mjs|json|html|txt)$/);
/** @type {Map<string, string[]>} chunk -> hits */
const hits = new Map();
let bytes = 0;
for (const f of files) {
  const text = fs.readFileSync(f, "utf8");
  bytes += text.length;
  for (const { needle, where } of specific) {
    if (text.includes(needle)) {
      const rel = path.relative(ROOT, f).replace(/\\/g, "/");
      if (!hits.has(rel)) hits.set(rel, []);
      hits.get(rel).push(`${where}: "${needle}"`);
    }
  }
}

const scanned = `${files.length} files, ${(bytes / 1e6).toFixed(1)} MB, ${specific.length} answer-key needles (${needles.length - specific.length} also public elsewhere, skipped) from ${SCENARIOS.length} scenarios`;
if (hits.size) {
  console.error(`\x1b[31mFAIL — scenario answer key found in public client chunks\x1b[0m (${scanned})\n`);
  for (const [chunk, list] of hits) {
    console.error(`  ${chunk}  (${list.length} hits)`);
    for (const h of list.slice(0, 5)) console.error(`    ${h}`);
    if (list.length > 5) console.error(`    ... and ${list.length - 5} more`);
  }
  console.error(`\nSome client module imports a scenario builder (src/lib/sim/scenarios.ts or a
scenario-packs/<pack>.ts). Import the events-only module instead (scenarioEvents.ts,
<pack>.events.ts) or fetch through an authenticated API. \`npx vitest run
src/lib/sim/clientAnswerKeyGuard.test.ts\` names the import chain.`);
  process.exit(1);
}
console.log(`\x1b[32mPASS — no scenario answer key in client chunks\x1b[0m (${scanned})`);
