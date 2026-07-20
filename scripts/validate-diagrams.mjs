/**
 * Mermaid diagram gate.
 *
 * A diagram with a syntax error does not fail the build, does not fail tsc, and
 * does not fail any content check — it simply renders as an error box, or not at
 * all, and the learner silently loses the illustration. One shipped that way
 * (`malware-types`: a `subgraph` title containing `--`, which Mermaid reads as
 * edge syntax) and nothing caught it.
 *
 * So: parse every diagram in the corpus with the real Mermaid parser.
 *
 * Mermaid needs a DOM, so jsdom is shimmed in before it loads. Without that it
 * throws "DOMPurify.addHook is not a function" on EVERY diagram — a failure of
 * the harness that looks exactly like a failure of the content. If you see that
 * error, the shim broke; do not go rewriting diagrams.
 */
import { JSDOM } from "jsdom";
const dom = new JSDOM("<!doctype html><html><body></body></html>", { pretendToBeVisual: true });
for (const k of ["window","document","Element","SVGElement","HTMLElement","Node","DocumentFragment","getComputedStyle","MutationObserver"]) {
  try { Object.defineProperty(globalThis, k, { value: k === "window" ? dom.window : dom.window[k], configurable: true, writable: true }); } catch {}
}

import { pathToFileURL } from "node:url";
import path from "node:path";
const u = f => pathToFileURL(path.join(process.cwd(), f)).href;

const { isMermaidSource } = await import(u("src/lib/lessons/mermaid.ts"));
const { BUILTIN_LESSONS } = await import(u("src/data/builtinLessons.ts"));
const { ROOMS } = await import(u("src/data/rooms.ts"));

const diagrams = [];
for (const l of BUILTIN_LESSONS)
  for (const s of l.sections ?? [])
    if (s.codeExample && isMermaidSource(s.codeExample))
      diagrams.push({ where: `lesson/${l.slug} — ${s.heading}`, src: s.codeExample });
for (const r of ROOMS)
  for (const t of r.tasks ?? [])
    if (t.diagram) diagrams.push({ where: `room/${r.id}/${t.id}`, src: t.diagram });

const { default: mermaid } = await import("mermaid");
mermaid.initialize({ startOnLoad: false, securityLevel: "strict" });

const failures = [];
for (const d of diagrams) {
  try { await mermaid.parse(d.src); }
  catch (e) { failures.push({ ...d, msg: String(e.message).split("\n").slice(0, 2).join(" | ") }); }
}

console.log(`\n\x1b[1mDiagram gate\x1b[0m   ${diagrams.length} mermaid diagrams`);
if (failures.length === 0) {
  console.log("\x1b[32m  PASS — every diagram parses.\x1b[0m");
} else {
  for (const f of failures) console.log(`\x1b[31m  FAIL  ${f.where}\n        ${f.msg}\x1b[0m`);
  console.log(`\x1b[31m  ${failures.length} diagram(s) will not render.\x1b[0m`);
  process.exit(1);
}
