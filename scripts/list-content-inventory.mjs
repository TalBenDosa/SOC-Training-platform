#!/usr/bin/env node
/**
 * Read-only inventory of the platform's quizzes and Learning-Path lessons.
 * Used when planning new content, to see what already exists before writing
 * anything new. Not part of the content gate.
 *
 *   npx tsx scripts/list-content-inventory.mjs
 */
import { pathToFileURL } from "node:url";
import path from "node:path";

const ROOT = process.cwd();
const imp = f => import(pathToFileURL(path.join(ROOT, f)).href);

const { ALL_QUIZZES } = await imp("src/lib/quizzes/data.ts");
const { BUILTIN_LESSONS } = await imp("src/data/builtinLessons.ts");

console.log(`=== QUIZZES (${ALL_QUIZZES.length}) ===`);
for (const q of ALL_QUIZZES) {
  console.log(`  ${q.slug}  |  ${q.title}  |  ${q.questions.length} Qs  |  ${q.difficulty ?? "?"}`);
}

console.log(`\n=== LEARNING PATH LESSONS (${BUILTIN_LESSONS.length}) ===`);
for (const l of BUILTIN_LESSONS) {
  console.log(`  ${l.slug ?? l.id}  |  ${l.title}  |  topic=${l.topic ?? "?"}  |  ${(l.sections ?? []).length} sections`);
}
