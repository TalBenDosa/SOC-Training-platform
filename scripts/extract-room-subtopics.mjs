// One-off extraction: for every room, list its actual sub-topics as taught —
// the heading of every reading task (the real content headings, not guesses).
// Read-only; not part of the content gate.
import path from "node:path";
import { pathToFileURL } from "node:url";

const ROOT = process.cwd();
const imp = f => import(pathToFileURL(path.join(ROOT, f)).href);

const { ROOMS } = await imp("src/data/rooms.ts");

const byCategory = {};
for (const room of ROOMS) {
  const headings = room.tasks
    .filter(t => t.type === "reading" && t.heading)
    .map(t => t.heading);
  (byCategory[room.category] ??= []).push({
    title: room.title,
    id: room.id,
    difficulty: room.difficulty,
    headings,
  });
}

for (const cat of Object.keys(byCategory).sort()) {
  console.log(`\n### ${cat} (${byCategory[cat].length})`);
  for (const r of byCategory[cat]) {
    console.log(`\n**${r.title}** [${r.difficulty}] (${r.id})`);
    for (const h of r.headings) console.log(`  - ${h}`);
  }
}
