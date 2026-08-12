#!/usr/bin/env node
/**
 * Structural gate for authored lesson figures (public/lesson-images/**.svg).
 *
 * A malformed SVG is SILENT: the browser renders nothing much, no build step
 * complains, and validate-content.mjs only checks that the FILE EXISTS — not
 * that its contents parse. Same failure mode Mermaid had before
 * validate-diagrams.mjs. So parse every figure as real XML here.
 *
 *   npx tsx scripts/validate-svg.mjs
 *
 * Checks per file:
 *   - parses as well-formed XML (catches unescaped & < >, unclosed tags)
 *   - root element is <svg> and carries a viewBox (so it scales in the reader)
 *   - has a <title> (screen readers; the alt attribute alone is not enough
 *     once the SVG is opened on its own)
 *   - references nothing external — the CSP would block it and the asset must
 *     stay self-contained and offline-safe
 *   - size budget, mirroring validate-content.mjs
 */
import { readFileSync, statSync, readdirSync } from "node:fs";
import path from "node:path";
// jsdom, not @xmldom — it is already a dependency here (validate-diagrams.mjs
// needs it to give Mermaid a DOM), so this gate adds no new package.
import { JSDOM } from "jsdom";

const MAX_BYTES = 500 * 1024;

function walk(dir) {
  const out = [];
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...walk(p));
    else if (e.name.endsWith(".svg")) out.push(p);
  }
  return out;
}
const files = walk("public/lesson-images").sort();

const { DOMParser } = new JSDOM("").window;
const parser = new DOMParser();

let errors = 0;
const err = (f, msg) => { errors++; console.log(`  \x1b[31mFAIL\x1b[0m ${f}: ${msg}`); };

for (const file of files) {
  const rel = path.relative("public/lesson-images", file).replace(/\\/g, "/");
  const src = readFileSync(file, "utf8");

  // XML well-formedness. Parsing as image/svg+xml (NOT text/html) is what makes
  // this strict: an unescaped & or an unclosed tag yields a <parsererror> node
  // instead of being silently repaired the way HTML parsing would.
  const doc = parser.parseFromString(src, "image/svg+xml");
  const perr = doc.getElementsByTagName("parsererror")[0];
  if (perr) { err(rel, `not well-formed XML — ${perr.textContent.trim().split("\n")[0].slice(0, 120)}`); continue; }

  const root = doc.documentElement;
  if (!root || root.nodeName !== "svg") { err(rel, "root element is not <svg>"); continue; }
  if (!root.getAttribute("viewBox")) err(rel, "no viewBox — will not scale in the reader");
  if (!doc.getElementsByTagName("title").length) err(rel, "no <title> element");

  // Nothing external: no remote hrefs, no <image>, no <script>, no @import.
  if (/\b(?:href|xlink:href|src)\s*=\s*["']https?:/i.test(src)) err(rel, "references a remote URL");
  if (/<script[\s>]/i.test(src)) err(rel, "contains <script>");
  if (/@import/i.test(src)) err(rel, "contains a CSS @import");

  const bytes = statSync(file).size;
  if (bytes > MAX_BYTES) err(rel, `${Math.round(bytes / 1024)}KB over the ${MAX_BYTES / 1024}KB budget`);
}

console.log(`\n\x1b[1mSVG gate\x1b[0m   ${files.length} figures`);
console.log(errors === 0
  ? "\x1b[32m  PASS — every figure parses and is self-contained.\x1b[0m"
  : `\x1b[31m  FAIL — ${errors} problem(s).\x1b[0m`);
process.exit(errors === 0 ? 0 : 1);
