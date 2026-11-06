// A tiny query engine for the hunting labs. The result grid is computed from the rows,
// so a clause can never claim a result it does not produce. Clause text is what the
// learner reads; the structured step is what actually runs.

export interface HuntTable {
  name: string;
  /** One line: what this table holds. */
  note: string;
  columns: string[];
  rows: string[][];
}

export type HuntStep =
  | { op: "where"; col: string; test: "eq" | "ieq" | "has" | "in" | "notin"; value: string | string[] }
  | { op: "join"; table: string; left: string; right: string; /** A further column both sides must match, e.g. the device. */ also?: string }
  | { op: "summarize"; by: string[]; /** Name of the count column: count_ in KQL, count in SPL. */ as?: string }
  | { op: "project"; cols: string[] };

export interface HuntResult {
  columns: string[];
  rows: string[][];
  /** The console's own message when a clause cannot run. */
  error?: string;
}

const lower = (s: string) => s.toLowerCase();

function matches(cell: string, step: Extract<HuntStep, { op: "where" }>): boolean {
  const values = Array.isArray(step.value) ? step.value : [step.value];
  switch (step.test) {
    case "eq": return cell === values[0];
    case "ieq": return lower(cell) === lower(values[0]);
    case "has": return lower(cell).includes(lower(values[0]));
    case "in": return values.some(v => lower(v) === lower(cell));
    case "notin": return !values.some(v => lower(v) === lower(cell));
  }
}

const missing = (col: string) => `Failed to resolve column '${col}'.`;

/** Runs a query from the start table, one step at a time, as the console would. */
export function runHunt(tables: HuntTable[], start: string, steps: HuntStep[], opts?: { emptyColumns?: boolean }): HuntResult {
  const first = tables.find(t => t.name === start);
  if (!first) return { columns: [], rows: [], error: `Failed to resolve table '${start}'.` };
  let columns = [...first.columns];
  let rows = first.rows.map(r => [...r]);
  for (const step of steps) {
    if (step.op === "where") {
      const i = columns.indexOf(step.col);
      if (i < 0) return { columns, rows: [], error: missing(step.col) };
      rows = rows.filter(r => matches(r[i], step));
    } else if (step.op === "join") {
      const other = tables.find(t => t.name === step.table);
      if (!other) return { columns, rows: [], error: `Failed to resolve table '${step.table}'.` };
      const l = columns.indexOf(step.left), r = other.columns.indexOf(step.right);
      if (l < 0) return { columns, rows: [], error: missing(step.left) };
      if (r < 0) return { columns, rows: [], error: missing(step.right) };
      // Like Kusto: a right-hand column that clashes gets the suffix 1.
      const named = other.columns.map(c => (columns.includes(c) ? `${c}1` : c));
      const la = step.also ? columns.indexOf(step.also) : -1, ra = step.also ? other.columns.indexOf(step.also) : -1;
      if (step.also && (la < 0 || ra < 0)) return { columns, rows: [], error: missing(step.also) };
      rows = rows.flatMap(a => other.rows.filter(b => b[r] === a[l] && (!step.also || b[ra] === a[la])).map(b => [...a, ...b]));
      columns = [...columns, ...named];
    } else if (step.op === "summarize") {
      const idx = step.by.map(c => columns.indexOf(c));
      const gone = step.by.find((_, i) => idx[i] < 0);
      if (gone) return { columns, rows: [], error: missing(gone) };
      const counts = new Map<string, { key: string[]; n: number }>();
      for (const r of rows) {
        const key = idx.map(i => r[i]);
        const id = key.join("\u0000");
        const hit = counts.get(id);
        if (hit) hit.n += 1; else counts.set(id, { key, n: 1 });
      }
      columns = [...step.by, step.as ?? "count_"];
      rows = [...counts.values()].map(c => [...c.key, String(c.n)]);
    } else {
      const idx = step.cols.map(c => columns.indexOf(c));
      const gone = step.cols.find((_, i) => idx[i] < 0);
      // SPL shows a field that is not there as an empty column; KQL refuses the query.
      if (gone && !opts?.emptyColumns) return { columns, rows: [], error: missing(gone) };
      columns = [...step.cols];
      rows = rows.map(r => idx.map(i => (i < 0 ? "" : r[i])));
    }
  }
  return { columns, rows };
}
