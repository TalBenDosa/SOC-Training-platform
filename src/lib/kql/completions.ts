import { AGGREGATE_NAMES } from "./aggregates";
import { resetBudget } from "./errors";
import { execute } from "./exec";
import { FUNCTIONS } from "./functions";
import { lex, type Tok } from "./lexer";
import { TABULAR_OPERATORS, parseKql } from "./parser";
import type { KqlColumn, KqlCompletion, KqlEnv, KqlTable } from "./types";

const OPERATOR_HELP: Record<string, string> = {
  where: "Filter rows", filter: "Filter rows", project: "Select or compute columns", "project-away": "Drop columns",
  "project-keep": "Keep matching columns", "project-rename": "Rename columns", "project-reorder": "Reorder columns",
  extend: "Add computed columns", summarize: "Aggregate rows", count: "Count rows", distinct: "Distinct rows",
  top: "First N rows by an expression", take: "Any N rows", limit: "Any N rows", sort: "Sort rows", order: "Sort rows",
  join: "Merge rows of two tables", union: "Rows of several tables", "mv-expand": "Expand a dynamic array into rows",
  parse: "Extract columns from a string", "parse-where": "Parse and drop unmatched rows", search: "Search for a term",
  getschema: "Show the schema", sample: "Random rows", render: "Chart the result",
};
const NEEDS_ARGUMENT = new Set(TABULAR_OPERATORS.filter((o) => o !== "count" && o !== "getschema"));

const STRING_OPS = [
  "==", "!=", "=~", "!~", "has", "!has", "has_cs", "!has_cs", "hasprefix", "!hasprefix", "hassuffix", "!hassuffix",
  "contains", "!contains", "contains_cs", "!contains_cs", "startswith", "!startswith", "endswith", "!endswith",
  "matches regex", "in", "!in", "in~", "!in~", "has_any", "has_all", "between", "!between",
];
const CHARTS = ["timechart", "barchart", "columnchart", "piechart", "linechart", "areachart", "table"];
const JOIN_KINDS = ["innerunique", "inner", "leftouter", "rightouter", "fullouter", "leftanti", "rightanti", "leftsemi", "rightsemi"];
const SCALAR_SPECIALS = ["iff", "iif", "case", "coalesce", "not", "min_of", "max_of", "column_ifexists", "toscalar"];
const FIRST_POSITION = ["let", "union", "search", "print", "datatable", "range"];

const isOp = (t: Tok | undefined, text: string) => t?.kind === "op" && t.text === text;
const isWord = (t: Tok | undefined, text: string) => t?.kind === "ident" && t.text === text;

function quoteName(name: string): string {
  return /^[A-Za-z_][A-Za-z0-9_]*$/.test(name) ? name : `['${name.replace(/'/g, "\\'")}']`;
}

function columnItems(columns: KqlColumn[]): KqlCompletion[] {
  return columns.map((c) => ({ label: c.name, kind: "column", insert: quoteName(c.name), detail: c.type }));
}

function functionItems(names: string[], detail: string): KqlCompletion[] {
  return names.map((n) => ({ label: n, kind: "function", insert: `${n}(`, detail }));
}

function operatorItems(): KqlCompletion[] {
  return TABULAR_OPERATORS.map((o) => ({ label: o, kind: "operator", insert: NEEDS_ARGUMENT.has(o) ? `${o} ` : o, detail: OPERATOR_HELP[o] }));
}

function keywordItems(words: string[], detail?: string): KqlCompletion[] {
  return words.map((w) => ({ label: w, kind: "keyword", insert: w, detail }));
}

function comparisonItems(): KqlCompletion[] {
  return [
    ...STRING_OPS.map((o): KqlCompletion => ({ label: o, kind: "operator", insert: `${o} ` })),
    ...keywordItems(["and", "or"]),
  ];
}

function scalarFunctions(): KqlCompletion[] {
  return functionItems([...Object.keys(FUNCTIONS), ...SCALAR_SPECIALS], "function");
}

function aggregateFunctions(): KqlCompletion[] {
  return functionItems(AGGREGATE_NAMES, "aggregation");
}

function tableItems(env: KqlEnv, lets: string[]): KqlCompletion[] {
  return [
    ...Object.keys(env.tables).map((n): KqlCompletion => ({ label: n, kind: "table", insert: quoteName(n), detail: "table" })),
    ...lets.map((n): KqlCompletion => ({ label: n, kind: "table", insert: quoteName(n), detail: "let" })),
  ];
}

function schemaOnly(env: KqlEnv): KqlEnv {
  const tables: Record<string, KqlTable> = {};
  for (const [name, table] of Object.entries(env.tables)) tables[name] = { ...table, rows: [] };
  return { tables, now: env.now };
}

/** Columns a query prefix produces, by running it over empty tables. */
function columnsOf(text: string, env: KqlEnv): KqlColumn[] | null {
  try {
    resetBudget();
    return execute(parseKql(text), env).table.columns;
  } catch {
    return null;
  }
}

function letNames(src: string, toks: Tok[]): string[] {
  const out: string[] = [];
  toks.forEach((t, i) => {
    if (isWord(t, "let") && toks[i + 1]?.kind === "ident" && isOp(toks[i + 2], "=") && !src.slice(0, t.pos).includes(`let ${toks[i + 1].text} =`)) {
      out.push(toks[i + 1].text);
    }
  });
  return out;
}

const QUERY_INTRO = new Set(["join", "union", "in", "!in", "in~", "!in~", "has_any", "has_all", "toscalar", "materialize", "let"]);

/** Is the open paren at `open` the start of a nested tabular query? */
function opensSubquery(toks: Tok[], open: number, limit: number): boolean {
  const prev = toks[open - 1];
  const first = toks[open + 1];
  const nested = open + 1 < limit && toks.slice(open + 1, limit).some((t) => isOp(t, "|"));
  if (isOp(prev, "=") && isWord(toks[open - 3], "let")) return true;
  if (!prev) return true;
  if (prev.kind === "ident" && QUERY_INTRO.has(prev.text)) {
    if (prev.text === "join" || prev.text === "union") return true;
    return nested || (first?.kind === "ident" && /^[A-Z]/.test(first.text) && open + 2 >= limit);
  }
  // join kind=inner ( ... )
  if (prev.kind === "ident" && isOp(toks[open - 2], "=") && isWord(toks[open - 3], "kind")) return true;
  if (isOp(prev, ",") && nested) return true;
  return false;
}

interface Position {
  /** First token of the pipeline holding the cursor. */
  start: number;
  /** Index of the pipe opening the current operator, or -1 at the source position. */
  lastPipe: number;
  /** Open parens inside the current operator. */
  depth: number;
}

function locate(toks: Tok[], stmtStart: number): Position {
  const stack: number[] = [];
  for (let i = stmtStart; i < toks.length; i++) {
    if (isOp(toks[i], "(") || isOp(toks[i], "[")) stack.push(i);
    else if (isOp(toks[i], ")") || isOp(toks[i], "]")) stack.pop();
  }
  let start = stmtStart;
  if (isWord(toks[start], "let") && isOp(toks[start + 2], "=")) start += 3;
  for (let i = stack.length - 1; i >= 0; i--) {
    if (isOp(toks[stack[i]], "(") && opensSubquery(toks, stack[i], toks.length)) {
      start = stack[i] + 1;
      break;
    }
  }
  let depth = 0;
  let lastPipe = -1;
  for (let i = start; i < toks.length; i++) {
    if (isOp(toks[i], "(") || isOp(toks[i], "[")) depth++;
    else if (isOp(toks[i], ")") || isOp(toks[i], "]")) depth--;
    else if (depth === 0 && isOp(toks[i], "|")) lastPipe = i;
  }
  return { start, lastPipe, depth };
}

function endsTerm(t: Tok | undefined): boolean {
  if (!t) return false;
  if (t.kind === "string" || t.kind === "number" || t.kind === "timespan" || t.kind === "raw") return true;
  if (t.kind === "op") return t.text === ")" || t.text === "]";
  return t.kind === "ident" && !STRING_OPS.includes(t.text) && t.text !== "and" && t.text !== "or" && t.text !== "by" && t.text !== "on";
}

function expressionItems(prev: Tok | undefined, columns: KqlColumn[], aggregates: boolean, afterTerm: KqlCompletion[]): KqlCompletion[] {
  if (endsTerm(prev)) return [...afterTerm, ...comparisonItems()];
  return [...columnItems(columns), ...(aggregates ? aggregateFunctions() : []), ...scalarFunctions()];
}

function suggest(src: string, toks: Tok[], pos: Position, stmtStart: number, env: KqlEnv, lets: string[]): KqlCompletion[] {
  const empty = schemaOnly(env);
  const prev = toks[toks.length - 1];
  if (isOp(prev, ".")) return [];
  if (pos.lastPipe < 0) {
    if (pos.start >= toks.length) {
      const stmtFirst = pos.start === stmtStart;
      return [...tableItems(env, lets), ...(stmtFirst ? keywordItems(FIRST_POSITION) : [])];
    }
    const first = toks[pos.start];
    if (isWord(first, "union") || isWord(first, "search")) return tableItems(env, lets);
    if (endsTerm(prev)) return [];
    return tableItems(env, lets);
  }
  const preamble = src.slice(0, toks[stmtStart]?.pos ?? 0);
  let prefixEnd = pos.lastPipe;
  let columns: KqlColumn[] | null = null;
  while (columns === null) {
    const text = src.slice(toks[pos.start]?.pos ?? 0, toks[prefixEnd]?.pos ?? 0);
    columns = columnsOf(preamble + text, empty) ?? columnsOf(text, empty);
    if (columns !== null) break;
    let back = prefixEnd - 1;
    let d = 0;
    for (; back > pos.start; back--) {
      if (isOp(toks[back], ")")) d++;
      else if (isOp(toks[back], "(")) d--;
      else if (d === 0 && isOp(toks[back], "|")) break;
    }
    if (back <= pos.start) {
      columns = [];
      break;
    }
    prefixEnd = back;
  }

  const seg = toks.slice(pos.lastPipe + 1);
  if (seg.length === 0) return operatorItems();
  const op = seg[0].text;
  if (seg.length === 1 && op === "sort") return keywordItems(["by"]);
  if (seg.length === 1 && op === "order") return keywordItems(["by"]);
  const wordAtTop = (word: string): number => {
    let d = 0;
    for (let i = 0; i < seg.length; i++) {
      if (isOp(seg[i], "(")) d++;
      else if (isOp(seg[i], ")")) d--;
      else if (d === 0 && isWord(seg[i], word)) return i;
    }
    return -1;
  };
  switch (op) {
    case "render":
      return seg.length === 1 ? keywordItems(CHARTS, "visualization") : [];
    case "join": {
      if (wordAtTop("on") >= 0) return columnItems(columns);
      if (isOp(prev, "=") && isWord(toks[toks.length - 2], "kind")) return keywordItems(JOIN_KINDS, "join kind");
      if (endsTerm(prev) && !isWord(prev, "join")) return keywordItems(["on"]);
      return [...keywordItems(["kind="]), ...tableItems(env, lets)];
    }
    case "union":
      if (isOp(prev, "=") && isWord(toks[toks.length - 2], "kind")) return keywordItems(["inner", "outer"]);
      return [...keywordItems(["kind=", "withsource=", "isfuzzy="]), ...tableItems(env, lets)];
    case "project-away":
    case "project-keep":
    case "project-reorder":
    case "project-rename":
      return columnItems(columns);
    case "distinct":
    case "mv-expand":
    case "parse":
    case "parse-where":
      return endsTerm(prev) && !isOp(prev, ",") && prev !== seg[0] ? keywordItems(op.startsWith("parse") ? ["with"] : []) : columnItems(columns);
    case "take":
    case "limit":
    case "sample":
    case "count":
    case "getschema":
      return [];
    case "top": {
      if (wordAtTop("by") < 0) return seg.length > 1 ? keywordItems(["by"]) : [];
      return expressionItems(prev === seg[wordAtTop("by")] ? undefined : prev, columns, false, keywordItems(["asc", "desc", "nulls first", "nulls last"]));
    }
    case "sort":
    case "order": {
      const after = keywordItems(["asc", "desc", "nulls first", "nulls last"]);
      return endsTerm(prev) ? after : [...columnItems(columns), ...scalarFunctions()];
    }
    case "summarize": {
      const by = wordAtTop("by");
      if (by >= 0) {
        if (prev === seg[by] || isOp(prev, ",")) {
          const bin = functionItems(["bin"], "function");
          return [...columnItems(columns), ...bin, ...scalarFunctions().filter((f) => f.label !== "bin")];
        }
        return expressionItems(prev, columns, false, []);
      }
      const inCall = pos.depth > 0;
      if (prev === seg[0] || isOp(prev, ",") || isOp(prev, "=")) {
        return inCall ? [...columnItems(columns), ...scalarFunctions()] : [...aggregateFunctions(), ...scalarFunctions()];
      }
      return expressionItems(prev, columns, true, inCall ? [] : keywordItems(["by"]));
    }
    case "where":
    case "filter":
    case "extend":
    case "project":
      return expressionItems(prev === seg[0] ? undefined : prev, columns, false, []);
    default:
      return seg.length === 1 ? operatorItems() : [];
  }
}

/**
 * Context-aware suggestions at `cursor`: tables at the start of a statement, operators
 * after a pipe, columns in scope after where, project, by and the like, functions in
 * expressions. Text after the cursor is ignored. Results are ranked for the typed prefix.
 */
export function kqlCompletions(query: string, cursor: number, env: KqlEnv): KqlCompletion[] {
  try {
    const at = Math.max(0, Math.min(cursor, query.length));
    const src = query.slice(0, at);
    const { toks: all, comments } = lex(src, true);
    const last = comments[comments.length - 1];
    if (last && last.end === src.length) return [];
    const toks = all.slice(0, -1);
    const tail = toks[toks.length - 1];
    if (tail?.kind === "string" && tail.open) return [];

    let prefix = "";
    if (tail && tail.end === src.length && tail.kind === "ident") {
      prefix = tail.text;
      toks.pop();
      const before = toks[toks.length - 1];
      const beforeThat = toks[toks.length - 2];
      if (isOp(before, "-") && beforeThat?.kind === "ident" && before.end === tail.pos && beforeThat.end === before.pos) {
        prefix = `${beforeThat.text}-${prefix}`;
        toks.length -= 2;
      }
    } else if (tail && tail.end === src.length && (tail.kind === "number" || tail.kind === "timespan")) {
      return [];
    } else if (isOp(tail, "-") && tail?.end === src.length && toks[toks.length - 2]?.kind === "ident" && toks[toks.length - 2].end === tail.pos) {
      prefix = `${toks[toks.length - 2].text}-`;
      toks.length -= 2;
    }

    let stmtStart = 0;
    let depth = 0;
    toks.forEach((t, i) => {
      if (isOp(t, "(")) depth++;
      else if (isOp(t, ")")) depth--;
      else if (depth === 0 && isOp(t, ";")) stmtStart = i + 1;
    });
    const lets = letNames(src, toks.slice(0, stmtStart));
    const position = locate(toks, stmtStart);
    const items = suggest(src, toks, position, stmtStart, env, lets);

    const low = prefix.toLowerCase();
    const seen = new Set<string>();
    const unique = items.filter((c) => {
      if (seen.has(c.label)) return false;
      seen.add(c.label);
      return true;
    });
    if (!low) return unique.slice(0, 300);
    const starts = unique.filter((c) => c.label.toLowerCase().startsWith(low));
    const inside = unique.filter((c) => !c.label.toLowerCase().startsWith(low) && c.label.toLowerCase().includes(low));
    return [...starts, ...inside].slice(0, 300);
  } catch {
    return [];
  }
}
