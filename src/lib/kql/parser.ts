import type { Expr, JoinKey, MvItem, NamedExpr, NamePattern, Op, ParseItem, Pipeline, Query, SortKey, Source, Statement, UnionSource } from "./ast";
import { KqlFail, LIMITS, didYouMean } from "./errors";
import { lex, parseFailure, type Tok } from "./lexer";
import type { KqlChart, KqlType } from "./types";
import { parseDatetime, parseTimespan, KqlTimespan, datetimeToIso } from "./values";

/** Every tabular operator the engine runs, used for error suggestions and completions. */
export const TABULAR_OPERATORS = [
  "where", "filter", "project", "project-away", "project-keep", "project-rename", "project-reorder", "extend",
  "summarize", "count", "distinct", "top", "take", "limit", "sort", "order", "join", "union", "mv-expand",
  "parse", "parse-where", "search", "getschema", "sample", "render",
];

const UNSUPPORTED_OPERATORS = new Set([
  "make-series", "make_series", "mv-apply", "evaluate", "lookup", "top-nested", "top-hitters", "as", "serialize",
  "invoke", "reduce", "fork", "facet", "partition", "find", "externaldata", "parse-kv", "project-smart", "scan",
  "sample-distinct", "graph-match",
]);

const JOIN_KINDS: Record<string, string> = {
  innerunique: "innerunique", inner: "inner", leftouter: "leftouter", rightouter: "rightouter", fullouter: "fullouter",
  leftanti: "leftanti", anti: "leftanti", leftantisemi: "leftanti", rightanti: "rightanti", rightantisemi: "rightanti",
  leftsemi: "leftsemi", rightsemi: "rightsemi",
};

const TYPE_NAMES: Record<string, KqlType> = {
  string: "string", int: "int", int32: "int", long: "long", int64: "long", real: "real", double: "real",
  bool: "bool", boolean: "bool", datetime: "datetime", date: "datetime", timespan: "timespan", time: "timespan",
  dynamic: "dynamic", guid: "guid", uuid: "guid", uniqueid: "guid", decimal: "real",
};

const CHARTS: KqlChart["kind"][] = ["timechart", "barchart", "columnchart", "piechart", "linechart", "areachart", "table"];

const STRING_OPERATORS = new Set<string>();
for (const base of ["has", "hasprefix", "hassuffix", "contains", "startswith", "endswith"]) {
  STRING_OPERATORS.add(base).add(`${base}_cs`).add(`!${base}`).add(`!${base}_cs`);
}
export const WORD_OPERATORS = [...STRING_OPERATORS, "in", "!in", "in~", "!in~", "has_any", "has_all", "has_cs", "between", "!between", "matches"];

const IN_FAMILY = new Set(["in", "!in", "in~", "!in~", "has_any", "has_all"]);
const COMPARE_SYMBOLS = new Set(["==", "!=", "<>", "=~", "!~", "<", ">", "<=", ">="]);

class Parser {
  private i = 0;
  private depth = 0;
  private searchMode = false;
  private readonly toks: Tok[];
  private readonly src: string;

  constructor(src: string) {
    this.src = src;
    this.toks = lex(src).toks;
  }

  private get tok(): Tok {
    return this.toks[this.i];
  }

  private at(offset: number): Tok {
    return this.toks[Math.min(this.i + offset, this.toks.length - 1)];
  }

  private fail(tok: Tok = this.tok): never {
    throw parseFailure(this.src, tok.pos, tok.text);
  }

  private isOp(text: string, tok: Tok = this.tok): boolean {
    return tok.kind === "op" && tok.text === text;
  }

  private isWord(text: string, tok: Tok = this.tok): boolean {
    return tok.kind === "ident" && tok.text === text;
  }

  private eatOp(text: string): boolean {
    if (this.isOp(text)) {
      this.i++;
      return true;
    }
    return false;
  }

  private eatWord(text: string): boolean {
    if (this.isWord(text)) {
      this.i++;
      return true;
    }
    return false;
  }

  private expectOp(text: string): Tok {
    if (!this.isOp(text)) this.fail();
    return this.toks[this.i++];
  }

  private expectWord(text: string): Tok {
    if (!this.isWord(text)) this.fail();
    return this.toks[this.i++];
  }

  private atEnd(): boolean {
    return this.tok.kind === "eof";
  }

  private enter(): void {
    if (++this.depth > LIMITS.maxDepth) throw new KqlFail("Query syntax depth exceeds the maximum safe limit.", this.tok.pos);
  }

  private leave(): void {
    this.depth--;
  }

  parseQuery(): Query {
    const statements: Statement[] = [];
    while (!this.atEnd()) {
      if (this.eatOp(";")) continue;
      statements.push(this.statement());
      if (!this.atEnd() && !this.isOp(";")) this.fail();
    }
    return { statements };
  }

  private statement(): Statement {
    const pos = this.tok.pos;
    if (this.isWord("let") && this.at(1).kind === "ident") return this.letStatement();
    if (this.isWord("set") && this.at(1).kind === "ident" && this.isOp("=", this.at(2))) {
      this.fail(this.at(1));
    }
    return { k: "query", q: this.pipeline(), pos };
  }

  private letStatement(): Statement {
    const pos = this.tok.pos;
    this.i++;
    const name = this.toks[this.i++].text;
    this.expectOp("=");
    if (this.isWord("view") || (this.isOp("(") && (this.isOp(")", this.at(1)) || this.isOp(":", this.at(2))))) {
      throw new KqlFail(`The let statement '${name}' declares a user-defined function, which this console does not support. Use a scalar or tabular let.`, pos);
    }
    const value = this.exprOrPipeline();
    if (isPipeline(value)) return { k: "let", name, value, isPipeline: true, pos };
    return { k: "let", name, value, isPipeline: false, pos };
  }

  /** A scalar expression or a tabular pipeline. The two share a first token, so the pipe decides. */
  private exprOrPipeline(): Expr | Pipeline {
    if ((this.isWord("union") || this.isWord("search") || this.isWord("print") || this.isWord("datatable")) && !this.isOp("=", this.at(1))) return this.pipeline();
    if (this.isWord("range") && !this.isOp("(", this.at(1)) && !this.isOp("=", this.at(1))) return this.pipeline();
    const start = this.tok;
    const e = this.expression();
    if (!this.isOp("|")) return e;
    let source: Source;
    if (e.k === "name") source = { k: "table", name: e.name, pos: e.pos };
    else if (e.k === "query") source = { k: "paren", q: e.q, pos: e.pos };
    else if (e.k === "call" && e.name === "materialize" && e.args[0]?.k === "query") source = { k: "paren", q: e.args[0].q, pos: e.pos };
    else this.fail();
    return { source, ops: this.operators(), pos: start.pos };
  }

  private pipeline(): Pipeline {
    this.enter();
    const pos = this.tok.pos;
    const source = this.source();
    const ops = this.operators();
    this.leave();
    return { source, ops, pos };
  }

  private operators(): Op[] {
    const ops: Op[] = [];
    while (this.eatOp("|")) ops.push(this.operator());
    return ops;
  }

  private nameToken(): { name: string; pos: number } {
    const t = this.tok;
    if (t.kind === "ident") {
      this.i++;
      return { name: t.text, pos: t.pos };
    }
    if (this.isOp("[") && this.at(1).kind === "string") {
      this.i++;
      const s = this.toks[this.i++];
      this.expectOp("]");
      return { name: s.value as string, pos: t.pos };
    }
    return this.fail();
  }

  private source(): Source {
    const t = this.tok;
    if (this.isOp("(")) {
      this.i++;
      const q = this.pipeline();
      this.expectOp(")");
      return { k: "paren", q, pos: t.pos };
    }
    if (t.kind === "ident") {
      const eq = this.isOp("=", this.at(1));
      if (t.text === "union" && !eq) {
        this.i++;
        return { k: "op", op: this.unionOp(t.pos), pos: t.pos };
      }
      if (t.text === "search" && !eq) {
        this.i++;
        return { k: "op", op: this.searchOp(t.pos), pos: t.pos };
      }
      if (t.text === "print") {
        this.i++;
        return { k: "print", items: this.namedList(), pos: t.pos };
      }
      if (t.text === "datatable") return this.datatable();
      if (t.text === "range" && !this.isOp("(", this.at(1))) return this.rangeSource();
    }
    const { name, pos } = this.nameToken();
    return { k: "table", name, pos };
  }

  private typeName(): KqlType {
    const t = this.tok;
    if (t.kind !== "ident" || !Object.prototype.hasOwnProperty.call(TYPE_NAMES, t.text)) this.fail();
    this.i++;
    return TYPE_NAMES[t.text];
  }

  private datatable(): Source {
    const pos = this.tok.pos;
    this.i++;
    this.expectOp("(");
    const columns: { name: string; type: KqlType }[] = [];
    while (!this.isOp(")")) {
      const { name } = this.nameToken();
      this.expectOp(":");
      columns.push({ name, type: this.typeName() });
      if (!this.eatOp(",")) break;
    }
    this.expectOp(")");
    this.expectOp("[");
    const values: Expr[] = [];
    while (!this.isOp("]")) {
      values.push(this.expression());
      if (!this.eatOp(",")) break;
    }
    this.expectOp("]");
    return { k: "datatable", columns, values, pos };
  }

  private rangeSource(): Source {
    const pos = this.tok.pos;
    this.i++;
    const { name } = this.nameToken();
    this.expectWord("from");
    const from = this.expression();
    this.expectWord("to");
    const to = this.expression();
    this.expectWord("step");
    const step = this.expression();
    return { k: "range", name, from, to, step, pos };
  }

  private operator(): Op {
    const t = this.tok;
    if (t.kind !== "ident") this.fail();
    this.i++;
    const pos = t.pos;
    switch (t.text) {
      case "where":
      case "filter":
        return { k: "where", expr: this.expression(), pos, alias: t.text };
      case "project":
        return { k: "project", items: this.namedList(), pos };
      case "extend":
        return { k: "extend", items: this.namedList(), pos };
      case "project-away":
      case "project-keep":
        return { k: t.text, patterns: this.patterns(false), pos };
      case "project-reorder":
        return { k: t.text, patterns: this.patterns(true), pos };
      case "project-rename":
        return { k: "project-rename", pairs: this.renames(), pos };
      case "summarize":
        return this.summarize(pos);
      case "count":
        return { k: "count", pos };
      case "distinct":
        if (this.eatOp("*")) return { k: "distinct", items: [], star: true, pos };
        return { k: "distinct", items: this.namedList(), star: false, pos };
      case "top": {
        const n = this.expression();
        this.expectWord("by");
        return { k: "top", n, key: this.sortKey(), pos };
      }
      case "take":
      case "limit":
        return { k: "take", n: this.expression(), pos, alias: t.text };
      case "sort":
      case "order": {
        this.expectWord("by");
        const keys: SortKey[] = [this.sortKey()];
        while (this.eatOp(",")) keys.push(this.sortKey());
        return { k: "sort", keys, pos, alias: t.text };
      }
      case "join":
        return this.join(pos);
      case "union":
        return this.unionOp(pos);
      case "mv-expand":
      case "mvexpand":
        return this.mvExpand(pos);
      case "parse":
      case "parse-where":
        return this.parseOp(pos, t.text === "parse-where");
      case "search":
        return this.searchOp(pos);
      case "getschema":
        return { k: "getschema", pos };
      case "sample":
        return { k: "sample", n: this.expression(), pos };
      case "render":
        return this.render(pos);
    }
    if (UNSUPPORTED_OPERATORS.has(t.text)) {
      throw new KqlFail(`The '${t.text}' operator is not supported in this console.`, pos);
    }
    throw new KqlFail(`'${t.text}' is not a recognized operator.${didYouMean(t.text, TABULAR_OPERATORS)}`, pos);
  }

  private namedItem(): NamedExpr {
    const pos = this.tok.pos;
    if (this.isOp("(")) {
      // Tuple assignment: (a, b) = arg_max(...). Scan ahead without consuming.
      const names: string[] = [];
      let k = 1;
      while (this.at(k).kind === "ident") {
        names.push(this.at(k).text);
        if (!this.isOp(",", this.at(k + 1))) break;
        k += 2;
      }
      if (names.length > 0 && this.isOp(")", this.at(k + 1)) && this.isOp("=", this.at(k + 2))) {
        this.i += k + 3;
        return { names, expr: this.expression(), pos };
      }
    }
    if (this.tok.kind === "ident" && this.isOp("=", this.at(1))) {
      const name = this.tok.text;
      this.i += 2;
      return { name, expr: this.expression(), pos };
    }
    if (this.isOp("[") && this.at(1).kind === "string" && this.isOp("]", this.at(2)) && this.isOp("=", this.at(3))) {
      const name = this.at(1).value as string;
      this.i += 4;
      return { name, expr: this.expression(), pos };
    }
    return { expr: this.expression(), pos };
  }

  private namedList(): NamedExpr[] {
    const items = [this.namedItem()];
    while (this.eatOp(",")) items.push(this.namedItem());
    return items;
  }

  /** Column names with optional `*` wildcards, as project-away and friends take them. */
  private patterns(withDir: boolean): NamePattern[] {
    const out: NamePattern[] = [];
    for (;;) {
      const pos = this.tok.pos;
      let text = "";
      let end = pos;
      while ((this.tok.kind === "ident" || this.isOp("*") || (text === "" && this.isOp("["))) && (text === "" || this.tok.pos === end)) {
        if (this.isOp("[")) {
          text = this.nameToken().name;
          end = this.toks[this.i - 1].end;
          break;
        }
        text += this.tok.text;
        end = this.tok.end;
        this.i++;
      }
      if (text === "") this.fail();
      const item: NamePattern = { text, pos };
      if (withDir && (this.isWord("asc") || this.isWord("desc"))) item.dir = this.toks[this.i++].text as "asc" | "desc";
      out.push(item);
      if (!this.eatOp(",")) break;
    }
    return out;
  }

  private renames(): { to: string; from: string; pos: number }[] {
    const out: { to: string; from: string; pos: number }[] = [];
    do {
      const { name: to, pos } = this.nameToken();
      this.expectOp("=");
      const { name: from } = this.nameToken();
      out.push({ to, from, pos });
    } while (this.eatOp(","));
    return out;
  }

  private skipHints(): void {
    while (this.tok.kind === "ident" && (this.tok.text === "hint" || this.tok.text.startsWith("hint")) && this.isOp(".", this.at(1))) {
      this.i += 3;
      this.expectOp("=");
      this.i++;
    }
  }

  private summarize(pos: number): Op {
    this.skipHints();
    const aggs: NamedExpr[] = [];
    if (!this.isWord("by") && !this.endsOperator()) {
      aggs.push(this.namedItem());
      while (this.eatOp(",")) aggs.push(this.namedItem());
    }
    const by: NamedExpr[] = [];
    if (this.eatWord("by")) by.push(...this.namedList());
    if (aggs.length === 0 && by.length === 0) this.fail();
    return { k: "summarize", aggs, by, pos };
  }

  private endsOperator(): boolean {
    return this.tok.kind === "eof" || this.isOp("|") || this.isOp(";") || this.isOp(")");
  }

  private sortKey(): SortKey {
    const expr = this.expression();
    let dir: "asc" | "desc" = "desc";
    if (this.isWord("asc") || this.isWord("desc")) dir = this.toks[this.i++].text as "asc" | "desc";
    let nulls: "first" | "last" | undefined;
    if (this.eatWord("nulls")) {
      if (!this.isWord("first") && !this.isWord("last")) this.fail();
      nulls = this.toks[this.i++].text as "first" | "last";
    }
    return { expr, dir, nulls };
  }

  private join(pos: number): Op {
    let kind = "innerunique";
    for (;;) {
      if (this.isWord("kind") && this.isOp("=", this.at(1))) {
        const v = this.at(2);
        if (v.kind !== "ident" || !Object.prototype.hasOwnProperty.call(JOIN_KINDS, v.text)) {
          throw new KqlFail(`'${v.text}' is not a valid join kind.${didYouMean(v.text, Object.keys(JOIN_KINDS))}`, v.pos);
        }
        kind = JOIN_KINDS[v.text];
        this.i += 3;
        continue;
      }
      if (this.tok.kind === "ident" && this.tok.text.startsWith("hint") && this.isOp(".", this.at(1))) {
        this.skipHints();
        continue;
      }
      break;
    }
    let right: Pipeline;
    if (this.isOp("(")) {
      this.i++;
      right = this.pipeline();
      this.expectOp(")");
    } else {
      const { name, pos: p } = this.nameToken();
      right = { source: { k: "table", name, pos: p }, ops: [], pos: p };
    }
    this.expectWord("on");
    const on: JoinKey[] = [];
    do {
      on.push(this.joinKey());
    } while (this.eatOp(",") || this.eatWord("and"));
    return { k: "join", kind, right, on, pos };
  }

  private joinKey(): JoinKey {
    const pos = this.tok.pos;
    const side = (): { side: string; name: string } => {
      const s = this.tok;
      if (!this.isWord("$left") && !this.isWord("$right")) {
        throw new KqlFail("The join condition must be either the name of a column common to both tables or in the form $left.<column> == $right.<column>.", s.pos);
      }
      this.i++;
      this.expectOp(".");
      return { side: s.text, name: this.nameToken().name };
    };
    if (this.isWord("$left") || this.isWord("$right")) {
      const a = side();
      this.expectOp("==");
      const b = side();
      if (a.side === b.side) {
        throw new KqlFail("The join condition must be either the name of a column common to both tables or in the form $left.<column> == $right.<column>.", pos);
      }
      return a.side === "$left" ? { left: a.name, right: b.name, pos } : { left: b.name, right: a.name, pos };
    }
    const { name } = this.nameToken();
    return { left: name, right: name, pos };
  }

  private unionOp(pos: number): Extract<Op, { k: "union" }> {
    let kind: "inner" | "outer" = "outer";
    let withsource: string | undefined;
    let isfuzzy = false;
    for (;;) {
      if (this.tok.kind !== "ident" || !this.isOp("=", this.at(1))) break;
      const key = this.tok.text;
      const v = this.at(2);
      if (key === "kind") {
        if (v.text !== "inner" && v.text !== "outer") this.fail(v);
        kind = v.text;
      } else if (key === "withsource") {
        withsource = v.text;
      } else if (key === "isfuzzy") {
        if (v.text !== "true" && v.text !== "false") this.fail(v);
        isfuzzy = v.text === "true";
      } else break;
      this.i += 3;
    }
    return { k: "union", kind, withsource, isfuzzy, sources: this.tableList(), pos };
  }

  private tableList(): UnionSource[] {
    const sources: UnionSource[] = [];
    do {
      const pos = this.tok.pos;
      if (this.isOp("(")) {
        this.i++;
        const q = this.pipeline();
        this.expectOp(")");
        sources.push({ q, pos });
        continue;
      }
      if (this.isOp("[")) {
        sources.push({ name: this.nameToken().name, pos });
        continue;
      }
      let name = "";
      let end = pos;
      while ((this.tok.kind === "ident" || this.isOp("*")) && (name === "" || this.tok.pos === end)) {
        name += this.tok.text;
        end = this.tok.end;
        this.i++;
      }
      if (name === "") this.fail();
      sources.push({ name, pos });
    } while (this.eatOp(","));
    return sources;
  }

  private mvExpand(pos: number): Op {
    let bagKind: "bag" | "array" = "bag";
    let itemIndex: string | undefined;
    for (;;) {
      if (this.tok.kind !== "ident" || !this.isOp("=", this.at(1))) break;
      const key = this.tok.text;
      const v = this.at(2);
      if (key === "kind" || key === "bagexpansion") {
        if (v.text !== "bag" && v.text !== "array") this.fail(v);
        bagKind = v.text;
      } else if (key === "with_itemindex") itemIndex = v.text;
      else break;
      this.i += 3;
    }
    const items: MvItem[] = [];
    do {
      const n = this.namedItem();
      const item: MvItem = { name: n.name, expr: n.expr, pos: n.pos };
      if (this.eatWord("to")) {
        this.expectWord("typeof");
        this.expectOp("(");
        item.type = this.typeName();
        this.expectOp(")");
      }
      items.push(item);
    } while (this.eatOp(","));
    let limit: number | undefined;
    if (this.eatWord("limit")) {
      if (this.tok.kind !== "number") this.fail();
      limit = this.toks[this.i++].value as number;
    }
    return { k: "mv-expand", bagKind, itemIndex, items, limit, pos };
  }

  private parseOp(pos: number, dropUnmatched: boolean): Op {
    let kind: "simple" | "relaxed" | "regex" = "simple";
    let flags = "";
    for (;;) {
      if (!this.isOp("=", this.at(1)) || this.tok.kind !== "ident") break;
      const key = this.tok.text;
      const v = this.at(2);
      if (key === "kind") {
        if (v.text !== "simple" && v.text !== "relaxed" && v.text !== "regex") this.fail(v);
        kind = v.text;
      } else if (key === "flags") flags = v.text;
      else break;
      this.i += 3;
    }
    const expr = this.expression();
    this.expectWord("with");
    const pattern: ParseItem[] = [];
    while (!this.endsOperator()) {
      const t = this.tok;
      if (t.kind === "string") {
        this.i++;
        pattern.push({ t: "lit", text: t.value as string });
      } else if (this.isOp("*")) {
        this.i++;
        const prev = pattern[pattern.length - 1];
        if (prev?.t === "col" && prev.type === "string") {
          throw new KqlFail("Using * after parsing a string column is ambiguous.", t.pos);
        }
        pattern.push({ t: "star" });
      } else if (t.kind === "ident" || this.isOp("[")) {
        const { name, pos: p } = this.nameToken();
        let type: KqlType = "string";
        if (this.eatOp(":")) type = this.typeName();
        pattern.push({ t: "col", name, type, pos: p });
      } else if (!this.eatOp(",")) this.fail();
    }
    if (pattern.length === 0) this.fail();
    return { k: "parse", kind, flags, expr, pattern, dropUnmatched, pos };
  }

  private searchOp(pos: number): Extract<Op, { k: "search" }> {
    let caseSensitive = false;
    let sources: UnionSource[] | undefined;
    if (this.isWord("kind") && this.isOp("=", this.at(1))) {
      const v = this.at(2);
      if (v.text !== "case_sensitive" && v.text !== "case_insensitive" && v.text !== "default") this.fail(v);
      caseSensitive = v.text === "case_sensitive";
      this.i += 3;
    }
    if (this.isWord("in") && this.isOp("(", this.at(1))) {
      this.i += 2;
      sources = this.tableList();
      this.expectOp(")");
    }
    const wasSearch = this.searchMode;
    this.searchMode = true;
    const pred = this.isOp("*") && (this.endsOperator2(1)) ? this.searchStar() : this.expression();
    this.searchMode = wasSearch;
    return { k: "search", caseSensitive, sources, pred: toSearchPredicate(pred), pos };
  }

  private searchStar(): Expr {
    const pos = this.tok.pos;
    this.i++;
    return { k: "lit", type: "bool", value: true, pos };
  }

  private endsOperator2(offset: number): boolean {
    const t = this.at(offset);
    return t.kind === "eof" || this.isOp("|", t) || this.isOp(";", t) || this.isOp(")", t);
  }

  private render(pos: number): Op {
    const t = this.tok;
    if (t.kind !== "ident") this.fail();
    if (!CHARTS.includes(t.text as KqlChart["kind"])) {
      throw new KqlFail(`'${t.text}' is not a supported visualization. Use one of: ${CHARTS.join(", ")}.${didYouMean(t.text, CHARTS)}`, t.pos);
    }
    this.i++;
    if (this.eatWord("with")) {
      this.expectOp("(");
      let depth = 1;
      while (depth > 0) {
        if (this.tok.kind === "eof") this.fail();
        if (this.isOp("(")) depth++;
        if (this.isOp(")")) depth--;
        this.i++;
      }
    }
    return { k: "render", chart: t.text as KqlChart["kind"], pos };
  }

  // Expressions, lowest precedence first.

  private expression(): Expr {
    this.enter();
    const e = this.orExpr();
    this.leave();
    return e;
  }

  private orExpr(): Expr {
    let l = this.andExpr();
    while (this.isWord("or")) {
      const pos = this.toks[this.i++].pos;
      l = { k: "bin", op: "or", l, r: this.andExpr(), pos };
    }
    return l;
  }

  private andExpr(): Expr {
    let l = this.compareExpr();
    while (this.isWord("and")) {
      const pos = this.toks[this.i++].pos;
      l = { k: "bin", op: "and", l, r: this.compareExpr(), pos };
    }
    return l;
  }

  private exprList(): Expr[] {
    this.expectOp("(");
    const items: Expr[] = [];
    while (!this.isOp(")")) {
      const v = this.exprOrPipeline();
      items.push(isPipeline(v) ? { k: "query", q: v, pos: v.pos } : v);
      if (!this.eatOp(",")) break;
    }
    this.expectOp(")");
    return items;
  }

  private compareExpr(): Expr {
    let l = this.addExpr();
    for (;;) {
      const t = this.tok;
      if (t.kind === "op" && COMPARE_SYMBOLS.has(t.text)) {
        this.i++;
        const op = t.text === "<>" ? "!=" : t.text;
        l = { k: "bin", op, l, r: this.addExpr(), pos: t.pos };
        continue;
      }
      if (t.kind !== "ident") return l;
      if (IN_FAMILY.has(t.text)) {
        this.i++;
        const items = this.isOp("(") ? this.exprList() : [this.addExpr()];
        l = { k: "in", op: t.text, l, items, pos: t.pos };
        continue;
      }
      if (t.text === "between" || t.text === "!between") {
        this.i++;
        this.expectOp("(");
        const lo = this.addExpr();
        this.expectOp("..");
        const hi = this.addExpr();
        this.expectOp(")");
        l = { k: "between", neg: t.text === "!between", l, lo, hi, pos: t.pos };
        continue;
      }
      if (t.text === "matches" && this.isWord("regex", this.at(1))) {
        this.i += 2;
        l = { k: "bin", op: "matches regex", l, r: this.addExpr(), pos: t.pos };
        continue;
      }
      if (STRING_OPERATORS.has(t.text)) {
        this.i++;
        l = { k: "bin", op: t.text, l, r: this.addExpr(), pos: t.pos };
        continue;
      }
      return l;
    }
  }

  private addExpr(): Expr {
    let l = this.mulExpr();
    while (this.isOp("+") || this.isOp("-")) {
      const t = this.toks[this.i++];
      l = { k: "bin", op: t.text, l, r: this.mulExpr(), pos: t.pos };
    }
    return l;
  }

  private mulExpr(): Expr {
    let l = this.unary();
    while (this.isOp("*") || this.isOp("/") || this.isOp("%")) {
      const t = this.toks[this.i++];
      l = { k: "bin", op: t.text, l, r: this.unary(), pos: t.pos };
    }
    return l;
  }

  private unary(): Expr {
    if (this.isOp("-") || this.isOp("+")) {
      const t = this.toks[this.i++];
      this.enter();
      const e = this.unary();
      this.leave();
      if (e.k === "lit" && t.text === "-" && typeof e.value === "number") return { ...e, value: -e.value, pos: t.pos };
      if (e.k === "lit" && t.text === "-" && e.value instanceof KqlTimespan) return { ...e, value: new KqlTimespan(-e.value.ticks), pos: t.pos };
      return { k: "unary", op: t.text as "-" | "+", e, pos: t.pos };
    }
    return this.postfix();
  }

  private postfix(): Expr {
    let e = this.primary();
    for (;;) {
      if (this.isOp(".")) {
        const pos = this.toks[this.i++].pos;
        if (this.isOp("[")) {
          const { name } = this.nameToken();
          e = { k: "member", obj: e, prop: name, pos };
        } else {
          const t = this.tok;
          if (t.kind !== "ident") this.fail();
          this.i++;
          e = { k: "member", obj: e, prop: t.text, pos };
        }
        continue;
      }
      if (this.isOp("[")) {
        const pos = this.toks[this.i++].pos;
        const idx = this.expression();
        this.expectOp("]");
        e = { k: "index", obj: e, idx, pos };
        continue;
      }
      return e;
    }
  }

  private primary(): Expr {
    const t = this.tok;
    const pos = t.pos;
    switch (t.kind) {
      case "number":
        this.i++;
        return { k: "lit", type: t.real ? "real" : "long", value: t.value, pos };
      case "timespan":
        this.i++;
        return { k: "lit", type: "timespan", value: new KqlTimespan(t.value as number), pos };
      case "string": {
        this.i++;
        let value = t.value as string;
        while (this.tok.kind === "string") value += this.toks[this.i++].value as string;
        return { k: "lit", type: "string", value, pos };
      }
      case "raw":
        this.i++;
        return this.rawLiteral(t);
      case "ident":
        return this.identExpr();
      case "op":
        break;
      default:
        this.fail();
    }
    if (this.isOp("(")) {
      this.i++;
      this.enter();
      const v = this.exprOrPipeline();
      this.leave();
      this.expectOp(")");
      return isPipeline(v) ? { k: "query", q: v, pos } : { k: "paren", e: v, pos };
    }
    if (this.isOp("[") && this.at(1).kind === "string") {
      const { name } = this.nameToken();
      return { k: "name", name, pos };
    }
    if (this.isOp("*")) {
      this.i++;
      return { k: "star", pos };
    }
    return this.fail();
  }

  private rawLiteral(t: Tok): Expr {
    const inner = t.value as string;
    const pos = t.pos;
    if (t.text === "datetime" || t.text === "date") {
      if (inner === "null") return { k: "lit", type: "datetime", value: null, pos };
      const d = parseDatetime(inner);
      if (!d) throw new KqlFail(`Failed to parse the datetime literal '${inner}'.`, pos);
      return { k: "lit", type: "datetime", value: d, pos };
    }
    if (t.text === "timespan" || t.text === "time") {
      if (inner === "null") return { k: "lit", type: "timespan", value: null, pos };
      const ts = parseTimespan(inner);
      if (ts) return { k: "lit", type: "timespan", value: ts, pos };
      if (/^-?\d+(\.\d+)?$/.test(inner)) return { k: "lit", type: "timespan", value: parseTimespan(`${inner}d`), pos };
      throw new KqlFail(`Failed to parse the timespan literal '${inner}'.`, pos);
    }
    if (inner === "null") return { k: "lit", type: "guid", value: null, pos };
    if (!/^[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}$/.test(inner)) {
      throw new KqlFail(`Failed to parse the guid literal '${inner}'.`, pos);
    }
    return { k: "lit", type: "guid", value: inner.toLowerCase(), pos };
  }

  private identExpr(): Expr {
    const t = this.tok;
    const pos = t.pos;
    const next = this.at(1);
    if (this.searchMode && this.isOp(":", next) && this.at(2).kind === "string") {
      this.i += 2;
      const term = this.toks[this.i++].value as string;
      return { k: "searchterm", term, col: t.text, pos };
    }
    if (t.text === "true" || t.text === "True" || t.text === "TRUE") {
      this.i++;
      return { k: "lit", type: "bool", value: true, pos };
    }
    if (t.text === "false" || t.text === "False" || t.text === "FALSE") {
      this.i++;
      return { k: "lit", type: "bool", value: false, pos };
    }
    if (this.isOp("(", next)) {
      if (t.text === "dynamic") {
        this.i += 2;
        const value = this.dynamicValue();
        this.expectOp(")");
        return { k: "lit", type: "dynamic", value, pos };
      }
      if (t.text === "typeof") {
        this.i += 2;
        const type = this.typeName();
        this.expectOp(")");
        return { k: "typeof", type, pos };
      }
      if (Object.prototype.hasOwnProperty.call(TYPE_NAMES, t.text) && t.text !== "string" && t.text !== "guid" && t.text !== "dynamic") {
        this.i += 2;
        return this.typedLiteral(TYPE_NAMES[t.text], pos);
      }
      if (t.text === "string" && this.isWord("null", this.at(2))) {
        this.i += 3;
        this.expectOp(")");
        return { k: "lit", type: "string", value: "", pos };
      }
      this.i += 2;
      return this.callArgs(t);
    }
    this.i++;
    return { k: "name", name: t.text, pos };
  }

  private typedLiteral(type: KqlType, pos: number): Expr {
    const t = this.tok;
    let value: unknown;
    if (this.isWord("null")) {
      this.i++;
      value = null;
    } else if (type === "bool") {
      if (!this.isWord("true") && !this.isWord("false")) this.fail();
      this.i++;
      value = t.text === "true";
    } else if (this.isWord("nan") && type === "real") {
      this.i++;
      value = NaN;
    } else {
      let sign = 1;
      if (this.eatOp("-")) sign = -1;
      else this.eatOp("+");
      if (this.isWord("inf") && type === "real") {
        this.i++;
        value = sign * Infinity;
      } else {
        if (this.tok.kind !== "number") this.fail();
        const n = (this.toks[this.i++].value as number) * sign;
        value = type === "real" ? n : Math.trunc(n);
      }
    }
    this.expectOp(")");
    return { k: "lit", type, value, pos };
  }

  private callArgs(t: Tok): Expr {
    const args: Expr[] = [];
    const argNames: (string | undefined)[] = [];
    this.enter();
    while (!this.isOp(")")) {
      if (this.isOp("*") && (this.isOp(",", this.at(1)) || this.isOp(")", this.at(1)))) {
        args.push({ k: "star", pos: this.toks[this.i++].pos });
        argNames.push(undefined);
      } else if (this.tok.kind === "ident" && this.isOp("=", this.at(1))) {
        argNames.push(this.tok.text);
        this.i += 2;
        args.push(this.expression());
      } else {
        const v = this.exprOrPipeline();
        args.push(isPipeline(v) ? { k: "query", q: v, pos: v.pos } : v);
        argNames.push(undefined);
      }
      if (!this.eatOp(",")) break;
    }
    this.leave();
    this.expectOp(")");
    return { k: "call", name: t.text, args, argNames, pos: t.pos };
  }

  private dynamicValue(): unknown {
    this.enter();
    const v = this.dynamicValueInner();
    this.leave();
    return v;
  }

  private dynamicValueInner(): unknown {
    const t = this.tok;
    if (t.kind === "string") {
      this.i++;
      return t.value;
    }
    if (t.kind === "number") {
      this.i++;
      return t.value;
    }
    if (this.isOp("-")) {
      this.i++;
      if (this.tok.kind !== "number") this.fail();
      return -(this.toks[this.i++].value as number);
    }
    if (t.kind === "timespan") {
      this.i++;
      return new KqlTimespan(t.value as number).toString();
    }
    if (t.kind === "raw") {
      this.i++;
      const lit = this.rawLiteral(t);
      if (lit.k === "lit" && lit.value instanceof Date) return datetimeToIso(lit.value);
      return lit.k === "lit" ? (lit.value === null ? null : String(lit.value)) : null;
    }
    if (t.kind === "ident") {
      this.i++;
      if (t.text === "true") return true;
      if (t.text === "false") return false;
      if (t.text === "null") return null;
      this.fail(t);
    }
    if (this.eatOp("[")) {
      const out: unknown[] = [];
      while (!this.isOp("]")) {
        out.push(this.dynamicValue());
        if (!this.eatOp(",")) break;
      }
      this.expectOp("]");
      return out;
    }
    if (this.eatOp("{")) {
      const out: Record<string, unknown> = {};
      while (!this.isOp("}")) {
        const key = this.tok;
        if (key.kind !== "string" && key.kind !== "ident") this.fail();
        this.i++;
        this.expectOp(":");
        Object.defineProperty(out, key.kind === "string" ? (key.value as string) : key.text, {
          value: this.dynamicValue(), enumerable: true, writable: true, configurable: true,
        });
        if (!this.eatOp(",")) break;
      }
      this.expectOp("}");
      return out;
    }
    return this.fail();
  }
}

export function isPipeline(v: Expr | Pipeline): v is Pipeline {
  return "source" in v;
}

/** Bare strings in a search predicate become term searches over every column. */
function toSearchPredicate(e: Expr): Expr {
  switch (e.k) {
    case "lit":
      return e.type === "string" ? { k: "searchterm", term: e.value as string, pos: e.pos } : e;
    case "star":
      return { k: "lit", type: "bool", value: true, pos: e.pos };
    case "paren":
      return { ...e, e: toSearchPredicate(e.e) };
    case "bin":
      return e.op === "and" || e.op === "or" ? { ...e, l: toSearchPredicate(e.l), r: toSearchPredicate(e.r) } : e;
    case "call":
      return e.name === "not" ? { ...e, args: e.args.map(toSearchPredicate) } : e;
    default:
      return e;
  }
}

export function parseKql(src: string): Query {
  return new Parser(src).parseQuery();
}
