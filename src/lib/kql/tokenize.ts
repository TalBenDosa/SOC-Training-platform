import { lex, type Tok } from "./lexer";
import { TABULAR_OPERATORS, WORD_OPERATORS } from "./parser";
import type { KqlEnv } from "./types";

export type KqlTokenClass = "keyword" | "operator" | "function" | "string" | "number" | "comment" | "table" | "other";

export interface KqlToken {
  text: string;
  class: KqlTokenClass;
  /** Offsets into the query. Tokens cover the whole text, whitespace included, as class "other". */
  start: number;
  end: number;
}

const KEYWORDS = new Set([
  ...TABULAR_OPERATORS, "let", "by", "on", "with", "asc", "desc", "nulls", "first", "last", "true", "false", "to", "typeof",
  "print", "datatable", "range", "from", "step", "regex", "view",
]);
const WORD_OPS = new Set([...WORD_OPERATORS, "and", "or"]);
/** Columns can be called these, so they only count as keywords where an operator can start. */
const POSITIONAL = new Set([...TABULAR_OPERATORS]);
const TYPE_LITERALS = new Set(["datetime", "date", "timespan", "time", "guid"]);

const QUERY_PARENS = new Set(["join", "union", "in", "toscalar", "materialize"]);

function classify(tok: Tok, prev: Tok | undefined, next: Tok | undefined, before: Tok | undefined, tableNames: Set<string> | undefined): KqlTokenClass {
  switch (tok.kind) {
    case "string":
      return "string";
    case "number":
    case "timespan":
      return "number";
    case "raw":
      return TYPE_LITERALS.has(tok.text) ? "function" : "other";
    case "op":
      return tok.text === "(" || tok.text === ")" || tok.text === "," || tok.text === "." || tok.text === "[" || tok.text === "]" || tok.text === ";" ? "other" : "operator";
    case "eof":
      return "other";
  }
  const word = tok.text;
  const afterPipe = prev?.kind === "op" && prev.text === "|";
  if (afterPipe && POSITIONAL.has(word)) return "keyword";
  if (prev?.kind === "op" && prev.text === ".") return "other";
  if (WORD_OPS.has(word)) return "operator";
  if (tableNames?.has(word)) return "table";
  if (next?.kind === "op" && next.text === "(") return "function";
  const inQueryParen = prev?.kind === "op" && prev.text === "(" && (!before || (before.kind === "ident" && QUERY_PARENS.has(before.text)));
  const atStart = !prev || inQueryParen || (prev.kind === "op" && (prev.text === ";" || prev.text === "=")) || (prev.kind === "ident" && prev.text === "union");
  if (word === "let" || word === "by" || word === "on" || word === "asc" || word === "desc" || word === "with" || word === "true" || word === "false") return "keyword";
  if (word === "kind" && next?.text === "=") return "keyword";
  if (next?.kind === "op" && next.text === "|") return "table";
  if (atStart && !POSITIONAL.has(word) && !KEYWORDS.has(word) && /^[A-Z]/.test(word) && !(next?.kind === "op" && (next.text === "=" || next.text === "=="))) return "table";
  if (KEYWORDS.has(word) && (word === "print" || word === "datatable" || word === "range" || word === "union" || word === "search") && !prev) return "keyword";
  return "other";
}

/** Tokens for syntax colouring. Never throws, whatever the text. Pass env to mark exact table names. */
export function tokenizeKql(query: string, env?: Pick<KqlEnv, "tables">): KqlToken[] {
  const out: KqlToken[] = [];
  try {
    const { toks, comments } = lex(query, true);
    const tableNames = env ? new Set(Object.keys(env.tables)) : undefined;
    const spans: KqlToken[] = comments.map((c) => ({ text: query.slice(c.pos, c.end), class: "comment", start: c.pos, end: c.end }));
    toks.forEach((tok, i) => {
      if (tok.kind === "eof") return;
      spans.push({
        text: query.slice(tok.pos, tok.end),
        class: classify(tok, toks[i - 1], toks[i + 1], toks[i - 2], tableNames),
        start: tok.pos,
        end: tok.end,
      });
    });
    spans.sort((a, b) => a.start - b.start);
    let at = 0;
    for (const span of spans) {
      if (span.start > at) out.push({ text: query.slice(at, span.start), class: "other", start: at, end: span.start });
      out.push(span);
      at = span.end;
    }
    if (at < query.length) out.push({ text: query.slice(at), class: "other", start: at, end: query.length });
    return out;
  } catch {
    return query ? [{ text: query, class: "other", start: 0, end: query.length }] : [];
  }
}
