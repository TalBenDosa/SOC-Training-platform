#!/usr/bin/env node
/**
 * Audit: does every SHA256 that appears in a scenario's events have a verdict?
 *
 * The Check Hash button resolves a verdict from the scenario's own `iocs` list.
 * If an event shows a hash the IOC list never mentions, the lookup falls through
 * to "not in any feed" — i.e. the dropper the whole story is about would come
 * back clean. That is worse than having no button at all, so this fails loudly.
 *
 *   npm run audit:hashes
 */
import { pathToFileURL } from "node:url";
import path from "node:path";

const ROOT = process.cwd();
const { SCENARIOS } = await import(pathToFileURL(path.join(ROOT, "src/lib/sim/scenarios.ts")).href);

const SHA = /^[a-f0-9]{64}$/i;

function collectHashes(obj, out = new Set()) {
  if (obj == null) return out;
  if (typeof obj === "string") { if (SHA.test(obj)) out.add(obj.toLowerCase()); return out; }
  if (Array.isArray(obj)) { obj.forEach(o => collectHashes(o, out)); return out; }
  if (typeof obj === "object") { Object.values(obj).forEach(o => collectHashes(o, out)); return out; }
  return out;
}

let totalScenarios = 0, totalHashes = 0, uncovered = 0;
const problems = [];

for (const def of SCENARIOS) {
  const bundle = typeof def.build === "function" ? def.build() : def;
  totalScenarios++;

  const iocHashes = new Set(
    (bundle.iocs ?? [])
      .filter(i => i.type === "sha256" || i.type === "md5")
      .map(i => i.value.toLowerCase()),
  );

  const eventHashes = collectHashes(bundle.events ?? []);
  totalHashes += eventHashes.size;

  const missing = [...eventHashes].filter(h => !iocHashes.has(h));
  if (missing.length) {
    uncovered += missing.length;
    problems.push({
      id: bundle.scenario_id ?? def.slug ?? "(unknown)",
      title: bundle.title ?? "",
      iocCount: iocHashes.size,
      missing,
    });
  }
}

console.log(`\n\x1b[1mScenario hash coverage\x1b[0m`);
console.log(`  scenarios          ${totalScenarios}`);
console.log(`  distinct hashes    ${totalHashes}`);
console.log(`  without a verdict  ${uncovered}\n`);

if (problems.length === 0) {
  console.log(`\x1b[32m  PASS — every hash shown in an event has a scenario verdict.\x1b[0m\n`);
  process.exit(0);
}

console.log(`\x1b[31m  FAIL — ${problems.length} scenario(s) show a hash with no IOC entry:\x1b[0m\n`);
for (const p of problems) {
  console.log(`  \x1b[1m${p.id}\x1b[0m  ${p.title}`);
  console.log(`    sha256 IOCs declared: ${p.iocCount}`);
  for (const h of p.missing) console.log(`    \x1b[31m${h}\x1b[0m`);
  console.log();
}
console.log(`  Add each hash to that scenario's \`iocs\` array with the reputation the story`);
console.log(`  implies. Without it, Check Hash reports the attack's own payload as clean.\n`);
process.exit(1);
