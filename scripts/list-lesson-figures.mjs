#!/usr/bin/env node
/**
 * Which lessons carry an authored figure, and which do not.
 *
 * Read-only planning tool. Also reports the Mermaid diagram count per lesson,
 * because a lesson already well served by diagrams does not automatically need
 * a still image — the figure is for what a diagram cannot express (tables,
 * annotated artifacts, console layouts), not for decoration.
 *
 *   npx tsx scripts/list-lesson-figures.mjs
 */
import { pathToFileURL } from "node:url";
import path from "node:path";

const ROOT = process.cwd();
const { BUILTIN_LESSONS } = await import(pathToFileURL(path.join(ROOT, "src/data/builtinLessons.ts")).href);

const MERMAID = /^(flowchart|graph|sequenceDiagram|classDiagram|stateDiagram(-v2)?|erDiagram|journey|gantt|pie|mindmap|timeline|quadrantChart|requirementDiagram|gitGraph)\b/;

let withFig = 0;
const missing = [];

for (const [i, l] of BUILTIN_LESSONS.entries()) {
  const secs = l.sections ?? [];
  const figs = secs.filter(s => s.image).length;
  const diags = secs.filter(s => s.codeExample && MERMAID.test(String(s.codeExample).trim().split("\n")[0])).length;
  const flag = figs ? "FIG" : "   ";
  console.log(`${flag} ${String(i + 1).padStart(2)}. ${l.slug.padEnd(58)} fig=${figs} mermaid=${diags}`);
  if (figs) withFig++; else missing.push({ n: i + 1, slug: l.slug, topic: l.topic, headings: secs.map(s => s.heading) });
}

console.log(`\n${withFig}/${BUILTIN_LESSONS.length} lessons have at least one figure. ${missing.length} without.\n`);
console.log("WITHOUT A FIGURE — section headings, to pick a subject from:");
for (const m of missing) {
  console.log(`\n${m.n}. ${m.slug}`);
  m.headings.forEach(h => console.log(`     - ${h}`));
}
