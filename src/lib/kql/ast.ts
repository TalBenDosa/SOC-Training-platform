import type { KqlChart, KqlType } from "./types";

export type Expr =
  | { k: "lit"; type: KqlType; value: unknown; pos: number }
  | { k: "name"; name: string; pos: number }
  | { k: "star"; pos: number }
  | { k: "bin"; op: string; l: Expr; r: Expr; pos: number }
  | { k: "unary"; op: "-" | "+"; e: Expr; pos: number }
  | { k: "in"; op: string; l: Expr; items: Expr[]; pos: number }
  | { k: "between"; neg: boolean; l: Expr; lo: Expr; hi: Expr; pos: number }
  | { k: "call"; name: string; args: Expr[]; argNames: (string | undefined)[]; pos: number }
  | { k: "member"; obj: Expr; prop: string; pos: number }
  | { k: "index"; obj: Expr; idx: Expr; pos: number }
  | { k: "paren"; e: Expr; pos: number }
  | { k: "query"; q: Pipeline; pos: number }
  | { k: "typeof"; type: KqlType; pos: number }
  | { k: "searchterm"; term: string; col?: string; pos: number };

export interface NamedExpr {
  name?: string;
  /** `(a, b) = arg_max(...)` */
  names?: string[];
  expr: Expr;
  pos: number;
}

export interface NamePattern {
  text: string;
  pos: number;
  dir?: "asc" | "desc";
}

export interface SortKey {
  expr: Expr;
  dir: "asc" | "desc";
  nulls?: "first" | "last";
}

export interface JoinKey {
  left: string;
  right: string;
  pos: number;
}

export interface UnionSource {
  name?: string;
  q?: Pipeline;
  pos: number;
}

export type ParseItem =
  | { t: "lit"; text: string }
  | { t: "star" }
  | { t: "col"; name: string; type: KqlType; pos: number };

export interface MvItem {
  name?: string;
  expr: Expr;
  type?: KqlType;
  pos: number;
}

export type Op =
  | { k: "where"; expr: Expr; pos: number; alias: string }
  | { k: "project"; items: NamedExpr[]; pos: number }
  | { k: "extend"; items: NamedExpr[]; pos: number }
  | { k: "project-away"; patterns: NamePattern[]; pos: number }
  | { k: "project-keep"; patterns: NamePattern[]; pos: number }
  | { k: "project-rename"; pairs: { to: string; from: string; pos: number }[]; pos: number }
  | { k: "project-reorder"; patterns: NamePattern[]; pos: number }
  | { k: "summarize"; aggs: NamedExpr[]; by: NamedExpr[]; pos: number }
  | { k: "count"; pos: number }
  | { k: "distinct"; items: NamedExpr[]; star: boolean; pos: number }
  | { k: "top"; n: Expr; key: SortKey; pos: number }
  | { k: "take"; n: Expr; pos: number; alias: string }
  | { k: "sort"; keys: SortKey[]; pos: number; alias: string }
  | { k: "join"; kind: string; right: Pipeline; on: JoinKey[]; pos: number }
  | { k: "union"; kind: "inner" | "outer"; withsource?: string; isfuzzy: boolean; sources: UnionSource[]; pos: number }
  | { k: "mv-expand"; bagKind: "bag" | "array"; itemIndex?: string; items: MvItem[]; limit?: number; pos: number }
  | { k: "parse"; kind: "simple" | "relaxed" | "regex"; flags: string; expr: Expr; pattern: ParseItem[]; dropUnmatched: boolean; pos: number }
  | { k: "search"; caseSensitive: boolean; sources?: UnionSource[]; pred: Expr; pos: number }
  | { k: "getschema"; pos: number }
  | { k: "sample"; n: Expr; pos: number }
  | { k: "render"; chart: KqlChart["kind"]; pos: number };

export type Source =
  | { k: "table"; name: string; pos: number }
  | { k: "paren"; q: Pipeline; pos: number }
  | { k: "op"; op: Extract<Op, { k: "union" | "search" }>; pos: number }
  | { k: "print"; items: NamedExpr[]; pos: number }
  | { k: "datatable"; columns: { name: string; type: KqlType }[]; values: Expr[]; pos: number }
  | { k: "range"; name: string; from: Expr; to: Expr; step: Expr; pos: number };

export interface Pipeline {
  source: Source;
  ops: Op[];
  pos: number;
}

export type Statement =
  | { k: "let"; name: string; value: Expr | Pipeline; isPipeline: boolean; pos: number }
  | { k: "query"; q: Pipeline; pos: number };

export interface Query {
  statements: Statement[];
}
