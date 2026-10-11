#!/usr/bin/env node
/**
 * Pre-flight option-balance check for a single quiz-pack or lesson file,
 * BEFORE it is wired into ALL_QUIZZES / BUILTIN_LESSONS. Applies exactly the
 * same 1.7x ratio rule scripts/validate-content.mjs enforces, so a new pack can
 * be checked in isolation instead of only after integration.
 *
 *   npx tsx scripts/check-quiz-balance.mjs src/lib/quizzes/data-foo.ts
 */
import { pathToFileURL } from "node:url";
import path from "node:path";

const target = process.argv[2];
if (!target) {
  console.error("usage: npx tsx scripts/check-quiz-balance.mjs <file.ts>");
  process.exit(2);
}

const mod = await import(pathToFileURL(path.join(process.cwd(), target)).href);

let checked = 0, bad = 0;
function check(where, labels, correctIdx) {
  checked++;
  const right = labels[correctIdx] ?? "";
  const wrong = labels.filter((_, i) => i !== correctIdx);
  if (!wrong.length) return;
  const longestWrong  = Math.max(...wrong.map(s => s.length));
  const shortestWrong = Math.min(...wrong.map(s => s.length));
  if (right.length > longestWrong * 1.7) {
    bad++;
    console.log(`  FAIL ${where}: correct is ${Math.round(right.length / longestWrong * 100)}% of longest distractor`);
  } else if (shortestWrong > right.length * 1.7) {
    bad++;
    console.log(`  FAIL ${where}: shortest distractor is ${Math.round(shortestWrong / right.length * 100)}% of correct`);
  }
}

for (const [exportName, value] of Object.entries(mod)) {
  // `default` is handled separately below; iterating it here too would double-count.
  if (exportName === "default" || !Array.isArray(value)) continue;
  for (const item of value) {
    // Quiz pack shape: { slug, questions: [{ options: string[], answer: number }] }
    for (const [i, q] of (item.questions ?? []).entries()) {
      if (!Array.isArray(q.options) || typeof q.answer !== "number") continue;
      check(`${item.slug}/q${i + 1} (${q.id ?? i})`, q.options.map(String), q.answer);
    }
    // Lesson shape: { slug, quiz: [{ options: [{label,value}], answer: value }] }
    for (const [i, q] of (item.quiz ?? []).entries()) {
      if (!Array.isArray(q.options)) continue;
      const labels = q.options.map(o => String(o?.label ?? ""));
      const idx = q.options.findIndex(o => o?.value === q.answer);
      if (idx === -1) { bad++; console.log(`  FAIL ${item.slug}/quiz${i + 1}: answer matches no option value`); continue; }
      check(`${item.slug}/quiz${i + 1}`, labels, idx);
    }
  }
  console.log(`${exportName}: ${checked} question(s) checked`);
}

// A default-exported lesson array (pathLessons-*.ts) has no named export.
if (mod.default && Array.isArray(mod.default)) {
  for (const item of mod.default) {
    for (const [i, q] of (item.quiz ?? []).entries()) {
      if (!Array.isArray(q.options)) continue;
      const labels = q.options.map(o => String(o?.label ?? ""));
      const idx = q.options.findIndex(o => o?.value === q.answer);
      if (idx === -1) { bad++; console.log(`  FAIL ${item.slug}/quiz${i + 1}: answer matches no option value`); continue; }
      check(`${item.slug}/quiz${i + 1}`, labels, idx);
    }
  }
  console.log(`default export: ${checked} question(s) checked`);
}

console.log(bad === 0 ? `PASS — ${checked} checked, 0 imbalanced.` : `FAIL — ${bad} imbalanced of ${checked}.`);
process.exit(bad === 0 ? 0 : 1);
