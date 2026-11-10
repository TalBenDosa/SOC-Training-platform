/**
 * Runs a learner's KQL on a mission dataset and compares the RESULT with the
 * reference query's result. Text is never compared, so every correct query
 * passes: `count()` or `count() by X`, `FailCount` or `count_`, `distinct` or
 * `summarize by`. Columns are matched by their CONTENT, not their names.
 *
 * Pure; used by the grader (server, both datasets) and by the player's Run
 * button (browser, visible dataset only, no comparison).
 */
import { runKql } from "@/lib/kql";
import type { KqlColumn, KqlResult, KqlRow, KqlTable } from "@/lib/kql/types";
import type { KqlAnswerSpec, MissionDataset } from "./types";

const hydrated = new WeakMap<MissionDataset, Record<string, KqlTable>>();

/** Dataset -> engine tables, with datetime cells as Dates. Cached per dataset object. */
export function hydrate(ds: MissionDataset): Record<string, KqlTable> {
  const hit = hydrated.get(ds);
  if (hit) return hit;
  const out: Record<string, KqlTable> = {};
  for (const t of ds.tables) {
    const dates = t.columns.filter(c => c.type === "datetime").map(c => c.name);
    const rows = dates.length === 0 ? t.rows : t.rows.map(r => {
      const copy: KqlRow = { ...r };
      for (const c of dates) {
        const v = copy[c];
        if (typeof v === "string") { const d = new Date(v); copy[c] = Number.isNaN(d.getTime()) ? null : d; }
      }
      return copy;
    });
    out[t.name] = { name: t.name, columns: t.columns, rows };
  }
  hydrated.set(ds, out);
  return out;
}

export function runMissionQuery(ds: MissionDataset, query: string): KqlResult {
  return runKql(query, { tables: hydrate(ds), now: new Date(ds.now), maxRows: 5000 });
}

// ─── Cell normalisation ───────────────────────────────────────────────────────

function decimalsFor(tol?: number): number {
  if (!tol || tol <= 0) return 6;
  return Math.max(0, Math.min(6, Math.ceil(-Math.log10(tol))));
}

const NUMERIC = /^[+-]?\d+(\.\d+)?$/;

/** One comparable string per cell: case-insensitive text, numbers rounded, times to the second. */
export function cellKey(v: unknown, tol?: number): string {
  if (v === null || v === undefined || v === "") return "∅";
  if (v instanceof Date) return Number.isNaN(v.getTime()) ? "∅" : v.toISOString().slice(0, 19);
  if (typeof v === "number") return Number.isInteger(v) && !tol ? String(v) : v.toFixed(decimalsFor(tol)).replace(/\.?0+$/, "");
  if (typeof v === "bigint") return v.toString();
  if (typeof v === "boolean") return String(v);
  if (typeof v === "string") {
    const s = v.trim();
    if (NUMERIC.test(s)) return cellKey(Number(s), tol);
    return s.toLowerCase();
  }
  if (typeof v === "object" && v && "ms" in (v as Record<string, unknown>)) {
    // KqlTimespan-like values: compare by duration.
    return `ts:${String((v as { ms: unknown }).ms)}`;
  }
  try {
    const sortKeys = (x: unknown): unknown => Array.isArray(x) ? x.map(sortKeys)
      : x && typeof x === "object" ? Object.fromEntries(Object.keys(x as object).sort().map(k => [k, sortKeys((x as Record<string, unknown>)[k])])) : x;
    const items = Array.isArray(v) ? [...v].map(i => cellKey(i, tol)).sort() : null;
    return items ? `[${items.join(",")}]` : JSON.stringify(sortKeys(v)).toLowerCase();
  } catch {
    return String(v).toLowerCase();
  }
}

function columnKeys(rows: KqlRow[], col: string, tol?: number): string[] {
  return rows.map(r => cellKey(r[col], tol));
}

const sameMultiset = (a: string[], b: string[]) => {
  if (a.length !== b.length) return false;
  const x = [...a].sort(), y = [...b].sort();
  return x.every((v, i) => v === y[i]);
};
const sameSet = (a: string[], b: string[]) => {
  const x = new Set(a), y = new Set(b);
  return x.size === y.size && [...x].every(v => y.has(v));
};

// ─── Comparison ───────────────────────────────────────────────────────────────

export type Compare =
  | { pass: true }
  | { pass: false; why: "no-match" | "row-count" | "column"; learnerRows: number; expectedRows: number; extras: string[] };

function okResult(r: KqlResult): r is Extract<KqlResult, { ok: true }> { return r.ok; }

/**
 * Compares the learner's result with ONE reference result on ONE dataset.
 * `extras` lists up to three of the learner's own values that should not be there
 * (safe to show: they came from the learner's query, not from the answer).
 */
export function compareResults(spec: KqlAnswerSpec, learner: { columns: KqlColumn[]; rows: KqlRow[] }, ref: { columns: KqlColumn[]; rows: KqlRow[] }): Compare {
  const tol = spec.tolerance;
  if (spec.mode === "values") {
    const key = spec.keys[0];
    const want = new Set(columnKeys(ref.rows, key, tol).filter(v => v !== "∅"));
    let best: { col: string; extras: string[]; overlap: number; size: number } | null = null;
    for (const c of learner.columns) {
      const got = new Set(columnKeys(learner.rows, c.name, tol).filter(v => v !== "∅"));
      if (sameSet([...got], [...want])) return { pass: true };
      const overlap = [...got].filter(v => want.has(v)).length;
      if (!best || overlap > best.overlap || (overlap === best.overlap && Math.abs(got.size - want.size) < Math.abs(best.size - want.size))) {
        best = {
          col: c.name, overlap, size: got.size,
          extras: learner.rows.map(r => r[c.name]).filter(v => !want.has(cellKey(v, tol)) && v !== null && v !== "").map(v => String(v instanceof Date ? v.toISOString() : v)).filter((v, i, a) => a.indexOf(v) === i).slice(0, 3),
        };
      }
    }
    const learnerDistinct = best ? best.size : 0;
    return { pass: false, why: "no-match", learnerRows: learnerDistinct, expectedRows: want.size, extras: best && best.overlap > 0 ? best.extras : [] };
  }

  // rows: find, for every key column, the learner columns holding the same values.
  const keys = spec.keys;
  const refCols = keys.map(k => columnKeys(ref.rows, k, tol));
  const learnerByName = learner.columns.map(c => ({ name: c.name, vals: columnKeys(learner.rows, c.name, tol) }));
  const same = spec.distinct ? sameSet : sameMultiset;
  const candidates = refCols.map(rc => learnerByName.filter(lc => same(lc.vals, rc)).map(lc => lc.name));
  const rowsDiffer = spec.distinct
    ? new Set(learner.rows.map(r => JSON.stringify(learner.columns.map(c => cellKey(r[c.name], tol))))).size !== new Set(ref.rows.map(r => JSON.stringify(keys.map(k => cellKey(r[k], tol))))).size
    : learner.rows.length !== ref.rows.length;
  if (candidates.some(c => c.length === 0)) {
    return { pass: false, why: rowsDiffer ? "row-count" : "column", learnerRows: learner.rows.length, expectedRows: ref.rows.length, extras: [] };
  }
  const refTuples = ref.rows.map(r => JSON.stringify(keys.map(k => cellKey(r[k], tol))));
  // Try every assignment of candidate columns (bounded: candidates are almost always unique).
  let tried = 0;
  const pick: string[] = [];
  const walk = (i: number): boolean => {
    if (tried > 256) return false;
    if (i === keys.length) {
      tried++;
      if (new Set(pick).size !== pick.length) return false;
      const got = learner.rows.map(r => JSON.stringify(pick.map(c => cellKey(r[c], tol))));
      return same(got, refTuples);
    }
    for (const c of candidates[i]) { pick.push(c); if (walk(i + 1)) return true; pick.pop(); }
    return false;
  };
  if (walk(0)) return { pass: true };
  return { pass: false, why: "no-match", learnerRows: learner.rows.length, expectedRows: ref.rows.length, extras: [] };
}

export interface KqlVerdict {
  pass: boolean;
  /** The learner's query failed to run: an engine error, never an attempt. */
  error?: { message: string; line: number; column: number };
  /** Passed on the visible data, failed on the shadow copy: hard-coded values. */
  overfit?: boolean;
  feedback: string[];
  learnerRows?: number;
}

/** Grades one KQL step on the visible and the shadow dataset. */
export function gradeKql(spec: KqlAnswerSpec, query: string, visible: MissionDataset, shadow?: MissionDataset): KqlVerdict {
  const mine = runMissionQuery(visible, query);
  if (!okResult(mine)) return { pass: false, error: mine.error, feedback: [] };

  const attempt = (ds: MissionDataset, learner: Extract<KqlResult, { ok: true }>) => {
    let lastFail: Compare | null = null;
    for (const refQ of spec.reference) {
      const ref = runMissionQuery(ds, refQ);
      if (!okResult(ref)) throw new Error(`Reference query failed: ${ref.error.message}`);
      const c = compareResults(spec, learner, ref);
      if (c.pass) return c;
      lastFail = c;
    }
    return lastFail!;
  };

  const onVisible = attempt(visible, mine);
  if (onVisible.pass) {
    if (!shadow) return { pass: true, feedback: [], learnerRows: mine.rows.length };
    const mineShadow = runMissionQuery(shadow, query);
    if (okResult(mineShadow) && attempt(shadow, mineShadow).pass) return { pass: true, feedback: [], learnerRows: mine.rows.length };
    return {
      pass: false, overfit: true, learnerRows: mine.rows.length,
      feedback: ["Right on today's data, wrong on tomorrow's: the check also runs your query on a second copy of these tables with different names and addresses. Filter on the behaviour the question describes, not on a value you read on the screen."],
    };
  }

  const feedback: string[] = [];
  for (const t of spec.traps ?? []) {
    const hitQuery = t.ifQuery ? safeTest(t.ifQuery, query) : true;
    const hitMore = t.ifRowsMoreThan === undefined || mine.rows.length > t.ifRowsMoreThan;
    const hitFewer = t.ifRowsFewerThan === undefined || mine.rows.length < t.ifRowsFewerThan;
    const hitEmpty = t.ifEmpty === undefined || (mine.rows.length === 0) === t.ifEmpty;
    if (hitQuery && hitMore && hitFewer && hitEmpty && (t.ifQuery || t.ifRowsMoreThan !== undefined || t.ifRowsFewerThan !== undefined || t.ifEmpty !== undefined)) {
      feedback.push(t.say);
      break;
    }
  }
  if (mine.rows.length === 0) {
    feedback.push("Your query returned no rows. Run it a line at a time and watch the row counts: the line that drops to 0 is the one to fix. `==` is exact and case-sensitive; `=~` and `has` are not.");
  } else if (spec.mode === "values") {
    const f = onVisible as Extract<Compare, { pass: false }>;
    feedback.push(`Your result holds ${f.learnerRows} distinct value${f.learnerRows === 1 ? "" : "s"} where the answer has ${f.expectedRows}.`);
    if (f.extras.length) feedback.push(`These should not be in it: ${f.extras.join(", ")}. Look at what makes them different from the rest.`);
  } else {
    const f = onVisible as Extract<Compare, { pass: false }>;
    if (f.learnerRows !== f.expectedRows) feedback.push(`Your result has ${f.learnerRows} row${f.learnerRows === 1 ? "" : "s"}; the answer has ${f.expectedRows}.`);
    else feedback.push("Same number of rows as the answer, but the values differ. Check the filter and what you count or group by.");
  }
  return { pass: false, feedback, learnerRows: mine.rows.length };
}

function safeTest(pattern: string, text: string): boolean {
  try { return new RegExp(pattern, "i").test(text); } catch { return false; }
}

/**
 * Row counts after each pipe line, for the pipeline inspector: "SigninLogs 1,812 -> where 640 -> summarize 41".
 * Only for a single statement without `let`; otherwise null.
 */
export function pipelineCounts(ds: MissionDataset, query: string): { line: number; label: string; rows: number | null }[] | null {
  const text = query.replace(/\/\/[^\n]*/g, "");
  if (/(^|\n)\s*let\s/i.test(text) || text.includes(";")) return null;
  const lines = query.split("\n");
  const out: { line: number; label: string; rows: number | null }[] = [];
  let acc = "";
  for (let i = 0; i < lines.length; i++) {
    acc += (i ? "\n" : "") + lines[i];
    const next = lines.slice(i + 1).find(l => l.trim() && !l.trim().startsWith("//"));
    const raw = lines[i].trim();
    if (!raw || raw.startsWith("//")) continue;
    // A stage ends where the next non-empty line starts a new pipe (or at the end).
    if (next !== undefined && !next.trim().startsWith("|")) continue;
    const r = runMissionQuery(ds, acc);
    const label = (/^\|?\s*([A-Za-z_-]+)/.exec(raw)?.[1] ?? raw).slice(0, 24);
    out.push({ line: i + 1, label, rows: r.ok ? r.rows.length : null });
  }
  return out.length > 1 ? out : null;
}
