#!/usr/bin/env node
/**
 * Objective readability/shape metrics for the 34 theory lessons.
 *
 * Deliberately NOT a quality judgement — a long paragraph can be excellent and a
 * short one can be useless. This measures the things a human reviewer reads past
 * without noticing: paragraph length outliers, sections with no concrete example,
 * lessons far from the corpus median, and quizzes that are shorter than the norm.
 * Use it to point the human review at the right places, not to replace it.
 *
 *   npx tsx scripts/lesson-readability.mjs
 */
import { pathToFileURL } from "node:url";
import path from "node:path";

const { BUILTIN_LESSONS } = await import(
  pathToFileURL(path.join(process.cwd(), "src/data/builtinLessons.ts")).href
);

const words = s => String(s || "").trim().split(/\s+/).filter(Boolean).length;
const paras = s => String(s || "").split(/\n\n+/).map(p => p.trim()).filter(Boolean);

// A "concrete anchor" = something a student could type, search or recognise:
// an Event ID, a file/process name, a command, a field name, an ATT&CK ID, an IP.
const CONCRETE = [
  /\b\d{4}\b(?=[^%]*(?:event|id))/i, /\bT1\d{3}(?:\.\d{3})?\b/, /\b[a-z0-9_-]+\.(?:exe|dll|ps1|sh|log|conf|xml)\b/i,
  /\b(?:sudo|grep|awk|systemctl|schtasks|reg|netstat|ss|ps|whoami|curl|dig)\b/,
  /\b[A-Z][a-zA-Z]+(?:Events|Name|Id|Type|Address|Path|Line)\b/, /\b\d{1,3}(?:\.\d{1,3}){3}\b/,
  /\|\s*(?:where|summarize|project|stats|search|table)\b/i,
];
const hasConcrete = s => CONCRETE.some(re => re.test(String(s || "")));

const rows = [];
for (const [i, l] of BUILTIN_LESSONS.entries()) {
  const secs = l.sections ?? [];
  const secWords = secs.map(s => words(s.content));
  const allParas = secs.flatMap(s => paras(s.content));
  // A bulleted/numbered block is NOT a wall of prose — it is the fix for one.
  // Counting it as a long paragraph made this script report the restructured
  // lessons as still-dense and would push a later pass into breaking up the
  // very lists that resolved the problem. Only running prose is measured here.
  const isListBlock = p => {
    const lines = String(p).split("\n").map(l => l.trim()).filter(Boolean);
    const items = lines.filter(l => /^(?:[-*]\s+|\d+[.)]\s+)/.test(l));
    return items.length > 0 && items.length >= lines.length - 1; // allow one lead-in line
  };
  const longParas = allParas.filter(p => !isListBlock(p) && words(p) > 140).length;
  const noAnchor = secs.filter(s => !hasConcrete(s.content) && !hasConcrete(s.codeExample)).map(s => s.heading);
  rows.push({
    n: i + 1,
    slug: l.slug,
    totalWords: words(l.intro) + secWords.reduce((a, b) => a + b, 0),
    introWords: words(l.intro),
    sections: secs.length,
    maxSection: Math.max(0, ...secWords),
    longParas,
    noAnchor,
    quizQs: (l.quiz ?? []).length,
    takeaways: (l.keyTakeaways ?? []).length,
  });
}

const median = a => { const s = [...a].sort((x, y) => x - y); return s[Math.floor(s.length / 2)]; };
const medWords = median(rows.map(r => r.totalWords));

console.log(`corpus: ${rows.length} lessons · median length ${medWords} words\n`);
console.log("  #  lesson                                          words  Δmed  secs  maxSec  long¶  quiz  no-anchor");
for (const r of rows) {
  const d = Math.round(((r.totalWords - medWords) / medWords) * 100);
  const flag = Math.abs(d) >= 40 ? "*" : " ";
  console.log(
    `${flag}${String(r.n).padStart(3)}  ${r.slug.slice(0, 46).padEnd(46)} ${String(r.totalWords).padStart(5)} ${String(d > 0 ? "+" + d : d).padStart(5)}%  ${String(r.sections).padStart(4)}  ${String(r.maxSection).padStart(6)}  ${String(r.longParas).padStart(5)}  ${String(r.quizQs).padStart(4)}  ${r.noAnchor.length}`,
  );
}

console.log("\n— outliers by length (|Δ| >= 40% from median) —");
for (const r of rows) {
  const d = Math.round(((r.totalWords - medWords) / medWords) * 100);
  if (Math.abs(d) >= 40) console.log(`  ${r.slug}  ${r.totalWords}w (${d > 0 ? "+" : ""}${d}%)`);
}

console.log("\n— sections with NO concrete anchor (no event id / command / field / ATT&CK id) —");
let anchorless = 0;
for (const r of rows) for (const h of r.noAnchor) { anchorless++; console.log(`  ${r.slug} :: ${h}`); }
console.log(`  total: ${anchorless} of ${rows.reduce((a, r) => a + r.sections, 0)} sections`);

console.log("\n— paragraphs over 140 words (cognitive-load risk) —");
const heavy = rows.filter(r => r.longParas > 0).sort((a, b) => b.longParas - a.longParas);
for (const r of heavy) console.log(`  ${r.slug}: ${r.longParas}`);
console.log(`  lessons affected: ${heavy.length}/${rows.length}`);

console.log("\n— quiz depth —");
for (const r of rows.filter(r => r.quizQs < 3).sort((a, b) => a.quizQs - b.quizQs)) {
  console.log(`  ${r.slug}: only ${r.quizQs} question(s)`);
}
