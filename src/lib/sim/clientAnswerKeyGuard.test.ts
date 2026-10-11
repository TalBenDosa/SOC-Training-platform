import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";
import ts from "typescript";

/**
 * No browser code may reach a scenario builder.
 *
 * The builders (src/lib/sim/scenarios.ts and each src/lib/sim/scenario-packs/<pack>.ts)
 * define the answer key (questions, answers, explanations, IOCs, killchain,
 * narrative) inside the same function as the events, so a bundler cannot
 * tree-shake it away. Whatever a "use client" module imports, directly or
 * through a chain of static or dynamic imports, ends up in a public
 * /_next/static chunk. That is how the key leaked through the live feed
 * (attackStories.ts, loaded via simData.ts's `import()`).
 *
 * The live feed reads events from the events-only modules (scenarioEvents.ts,
 * scenario-packs/*.events.ts). This test walks the real import graph from every
 * client entry point and fails on any path to a builder. Type-only imports are
 * erased at compile time and are ignored.
 */

const ROOT = process.cwd();
const SRC = path.join(ROOT, "src");

/**
 * Client modules allowed to import a builder. EMPTY since fix/qa-phase2-3 landed
 * (the /scenarios list reads scenariosMeta.ts, the admin pages admin-only API
 * routes) — nothing may be added here.
 */
const PENDING_QA_PHASE2_3 = new Set<string>([]);

const rel = (p: string) => path.relative(ROOT, p).replace(/\\/g, "/");

function isAnswerKeyModule(file: string): boolean {
  const r = rel(file);
  if (r === "src/lib/sim/scenarios.ts") return true;
  return /^src\/lib\/sim\/scenario-packs\/[^/]+\.ts$/.test(r) && !/\.(events|test)\.ts$/.test(r);
}

function walk(dir: string, out: string[] = []): string[] {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, out);
    else if (/\.tsx?$/.test(e.name) && !/\.test\.tsx?$/.test(e.name)) out.push(p);
  }
  return out;
}

function resolve(spec: string, from: string): string | null {
  let base: string;
  if (spec.startsWith("@/")) base = path.join(SRC, spec.slice(2));
  else if (spec.startsWith(".")) base = path.resolve(path.dirname(from), spec);
  else return null;                                   // package import
  for (const cand of [base, `${base}.ts`, `${base}.tsx`, path.join(base, "index.ts"), path.join(base, "index.tsx")]) {
    if (/\.tsx?$/.test(cand) && fs.existsSync(cand) && fs.statSync(cand).isFile()) return cand;
  }
  return null;
}

const importCache = new Map<string, string[]>();
/** Runtime (non-type-only) static + dynamic import specifiers of a file. */
function runtimeImports(file: string): string[] {
  const hit = importCache.get(file);
  if (hit) return hit;
  const sf = ts.createSourceFile(file, fs.readFileSync(file, "utf8"), ts.ScriptTarget.Latest, true);
  const specs: string[] = [];
  const visit = (n: ts.Node) => {
    if (ts.isImportDeclaration(n) && ts.isStringLiteral(n.moduleSpecifier)) {
      const c = n.importClause;
      const typeOnly = !!c && (c.isTypeOnly || (!c.name && !!c.namedBindings && ts.isNamedImports(c.namedBindings)
        && c.namedBindings.elements.length > 0 && c.namedBindings.elements.every(e => e.isTypeOnly)));
      if (!typeOnly) specs.push(n.moduleSpecifier.text);
    } else if (ts.isExportDeclaration(n) && n.moduleSpecifier && ts.isStringLiteral(n.moduleSpecifier)) {
      if (!n.isTypeOnly) specs.push(n.moduleSpecifier.text);
    } else if (ts.isCallExpression(n) && n.expression.kind === ts.SyntaxKind.ImportKeyword) {
      const a = n.arguments[0];
      if (a && ts.isStringLiteralLike(a)) specs.push(a.text);
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  const out = specs.map(s => resolve(s, file)).filter((p): p is string => !!p);
  importCache.set(file, out);
  return out;
}

const USE_CLIENT = /^﻿?(?:\s|\/\/[^\n]*\n|\/\*[\s\S]*?\*\/)*["']use client["']/;

describe("client bundles cannot reach the scenario answer key", () => {
  it("no \"use client\" module imports a scenario builder, directly or transitively", () => {
    const entries = walk(SRC).filter(f => USE_CLIENT.test(fs.readFileSync(f, "utf8")));
    expect(entries.length).toBeGreaterThan(20);        // sanity: the scan found the app

    const violations: string[] = [];
    const seen = new Set<string>();
    // BFS keeping the path, so a failure names the exact import chain.
    const queue: string[][] = entries.map(e => [e]);
    while (queue.length) {
      const chain = queue.shift()!;
      const file = chain[chain.length - 1];
      if (seen.has(file)) continue;
      seen.add(file);
      for (const dep of runtimeImports(file)) {
        if (isAnswerKeyModule(dep)) {
          if (!(chain.length === 1 && PENDING_QA_PHASE2_3.has(rel(file)))) {
            violations.push([...chain, dep].map(rel).join("\n    → "));
          }
          continue;                                      // don't walk into the builder
        }
        if (!seen.has(dep)) queue.push([...chain, dep]);
      }
    }
    expect(violations, `answer-bearing scenario builders reachable from client code:\n  ${violations.join("\n  ")}`).toEqual([]);
  });

  it("the live feed reads the events-only modules", () => {
    const stories = path.join(SRC, "app/(app)/dashboard/attackStories.ts");
    const deps = runtimeImports(stories).map(rel);
    expect(deps).toContain("src/lib/sim/scenarioEvents.ts");
    expect(deps.filter(d => d.endsWith(".events.ts")).length).toBeGreaterThan(20);
    expect(deps.filter(d => isAnswerKeyModule(path.join(ROOT, d)))).toEqual([]);
  });

  it("the events-only modules carry no answer key", () => {
    const files = [path.join(SRC, "lib/sim/scenarioEvents.ts"),
      ...walk(path.join(SRC, "lib/sim/scenario-packs")).filter(f => f.endsWith(".events.ts"))];
    for (const f of files) {
      const text = fs.readFileSync(f, "utf8");
      for (const key of ["questions", "explanation", "killchain", "narrative", "learning_objectives", "briefing"]) {
        expect(new RegExp(`\\b${key}\\s*:`).test(text), `${rel(f)} defines \`${key}:\``).toBe(false);
      }
      expect(/\bScenarioQuestion\b|\bIOC\b/.test(text), `${rel(f)} references answer-key types`).toBe(false);
      for (const dep of runtimeImports(f)) expect(isAnswerKeyModule(dep), `${rel(f)} imports ${rel(dep)}`).toBe(false);
    }
  });
});
