// One-off extraction: for every Learning-Path lesson, list its title, topic,
// and every section heading — the real content structure, not a guess.
// Read-only; not part of the content gate.
import path from "node:path";
import { pathToFileURL } from "node:url";

const ROOT = process.cwd();
const imp = f => import(pathToFileURL(path.join(ROOT, f)).href);

const { BUILTIN_LESSONS } = await imp("src/data/builtinLessons.ts");

const byTopic = {};
for (const lesson of BUILTIN_LESSONS) {
  const headings = (lesson.sections ?? []).map(s => s.heading);
  (byTopic[lesson.topic ?? "Uncategorized"] ??= []).push({
    title: lesson.title,
    id: lesson.id,
    difficulty: lesson.difficulty,
    headings,
  });
}

console.log(`TOTAL LESSONS: ${BUILTIN_LESSONS.length}`);
for (const topic of Object.keys(byTopic).sort()) {
  console.log(`\n### ${topic} (${byTopic[topic].length})`);
  for (const l of byTopic[topic]) {
    console.log(`\n**${l.title}** [${l.difficulty}] (${l.id})`);
    for (const h of l.headings) console.log(`  - ${h}`);
  }
}
