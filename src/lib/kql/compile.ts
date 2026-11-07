import { AGG_PREFIX, MULTI_AGGS, buildAggregate, percentileState, percentileType, type AggSpec, type Compiled, type Row } from "./aggregates";
import type { Expr, Pipeline } from "./ast";
import { KqlFail, charge, nearest, withHint } from "./errors";
import { FUNCTIONS, validateRegex, wildcardRegex, type ArgInfo, type FnDef, type ParamKind } from "./functions";
import { RegexError, compileRegex } from "./regex";
import type { KqlColumn, KqlType } from "./types";
import { KqlTimespan, TICKS_PER_MS, castDyn, compareValues, keyOf, toDatetimeValue, toDyn, toNumber, toStr, toTimespanValue } from "./values";

export type { Compiled, Row };

export interface Tabular {
  columns: KqlColumn[];
  rows: Row[];
  /** Table name, for search and union sources. */
  name?: string;
}

export type LetValue = { kind: "scalar"; type: KqlType; value: unknown } | { kind: "tabular"; table: Tabular };

export interface Runtime {
  now: Date;
  lets: Map<string, LetValue>;
  evalPipeline(q: Pipeline): Tabular;
  /** Resolves a name to a table or tabular let, or undefined when there is none. */
  lookupTable(name: string): Tabular | undefined;
  tableNames(): string[];
}

export interface AggCollector {
  specs: AggSpec[];
  input: Map<string, KqlType>;
}

export interface Scope {
  columns: Map<string, KqlType>;
  op: string;
  rt: Runtime;
  agg?: AggCollector;
  /** Set for the search operator, whose wildcard columns only match in case when asked. */
  searchCaseSensitive?: boolean;
}

export function scopeOf(columns: KqlColumn[], op: string, rt: Runtime): Scope {
  return { columns: new Map(columns.map((c) => [c.name, c.type])), op, rt };
}

function constant(type: KqlType, value: unknown): Compiled {
  return { type, fn: () => value, constant: true, cost: 0 };
}

function make(type: KqlType, fn: (row: Row) => unknown, parts: Compiled[], folded = true): Compiled {
  const allConst = parts.every((p) => p.constant);
  if (allConst && folded) return constant(type, fn({}));
  return { type, fn, constant: false, cost: parts.reduce((n, p) => n + p.cost, 1) };
}

const isNum = (t: KqlType) => t === "int" || t === "long" || t === "real";
const isIntegral = (t: KqlType) => t === "int" || t === "long";

function opPrefix(s: Scope): string {
  return s.op ? `'${s.op}' operator: ` : "";
}

function unresolvedColumn(name: string, pos: number, s: Scope): KqlFail {
  if (!s.op) {
    return new KqlFail(withHint(`Failed to resolve table or column expression named '${name}'`, name, s.rt.tableNames()), pos);
  }
  return new KqlFail(withHint(`${opPrefix(s)}Failed to resolve column or scalar expression named '${name}'`, name, s.columns.keys()), pos);
}

function compareError(a: KqlType, b: KqlType, pos: number): KqlFail {
  return new KqlFail(`Cannot compare values of types ${a} and ${b}. Try adding explicit casts`, pos);
}

/** Equality per the engine: same family, or dynamic against a value it can hold. */
function checkEquatable(a: KqlType, b: KqlType, pos: number): void {
  if (a === b || (isNum(a) && isNum(b))) return;
  if ((a === "guid" && b === "string") || (a === "string" && b === "guid")) return;
  const other = a === "dynamic" ? b : b === "dynamic" ? a : null;
  if (other !== null && (other === "string" || other === "bool" || other === "guid" || isNum(other))) return;
  throw compareError(a, b, pos);
}

/** Ordering per Kusto.Language Operators.cs: numbers, timespans, datetimes, dynamic against numbers. Not strings. */
function checkOrderable(a: KqlType, b: KqlType, pos: number): void {
  if (isNum(a) && isNum(b)) return;
  if (a === b && (a === "timespan" || a === "datetime" || a === "dynamic" || a === "bool")) return;
  if ((a === "dynamic" && isNum(b)) || (isNum(a) && b === "dynamic")) return;
  throw compareError(a, b, pos);
}

function looseEqual(a: unknown, b: unknown): boolean {
  if (typeof a === "number" && typeof b === "number") return a === b;
  if (typeof a === "string" && typeof b === "string") return a === b;
  return keyOf(a) === keyOf(b);
}

function asBool(v: unknown): boolean | null {
  return v === null || v === undefined ? null : v === true;
}

function compileLogical(e: Extract<Expr, { k: "bin" }>, s: Scope): Compiled {
  const l = compile(e.l, s);
  const r = compile(e.r, s);
  for (const side of [l, r]) {
    if (side.type !== "bool" && side.type !== "dynamic") {
      throw new KqlFail(`Operator '${e.op}' expects bool operands, got ${side.type}.`, e.pos);
    }
  }
  const a = l.fn;
  const b = r.fn;
  const fn = e.op === "and"
    ? (row: Row) => {
        const x = asBool(a(row));
        if (x === false) return false;
        const y = asBool(b(row));
        if (y === false) return false;
        return x === null || y === null ? null : true;
      }
    : (row: Row) => {
        const x = asBool(a(row));
        if (x === true) return true;
        const y = asBool(b(row));
        if (y === true) return true;
        return x === null || y === null ? null : false;
      };
  return make("bool", fn, [l, r]);
}

function compileCompare(op: string, l: Compiled, r: Compiled, pos: number): Compiled {
  const a = l.fn;
  const b = r.fn;
  if (op === "==" || op === "!=") {
    checkEquatable(l.type, r.type, pos);
    const eq = op === "==";
    return make("bool", (row) => {
      const x = a(row);
      const y = b(row);
      const xn = x === null || x === undefined;
      const yn = y === null || y === undefined;
      if (xn && yn) return null;
      if (xn || yn) return !eq;
      return looseEqual(x, y) === eq;
    }, [l, r]);
  }
  checkOrderable(l.type, r.type, pos);
  const test = op === "<" ? (c: number) => c < 0 : op === "<=" ? (c: number) => c <= 0 : op === ">" ? (c: number) => c > 0 : (c: number) => c >= 0;
  const compareNumbers = (x: unknown, y: unknown) => {
    if (typeof x === "number" && typeof y === "number") {
      if (Number.isNaN(x) || Number.isNaN(y)) return null;
      return x < y ? -1 : x > y ? 1 : 0;
    }
    if (typeof x !== typeof y || typeof x === "object") {
      if (x instanceof Date && y instanceof Date) return x.getTime() - y.getTime();
      if (x instanceof KqlTimespan && y instanceof KqlTimespan) return x.ticks - y.ticks;
      return null;
    }
    return compareValues(x, y);
  };
  return make("bool", (row) => {
    const x = a(row);
    const y = b(row);
    if (x === null || y === null || x === undefined || y === undefined) return null;
    const c = compareNumbers(x, y);
    return c === null ? null : test(c);
  }, [l, r]);
}

function arithmetic(op: string, l: Compiled, r: Compiled, pos: number): Compiled {
  const lt = l.type;
  const rt = r.type;
  const a = l.fn;
  const b = r.fn;
  const bad = () => new KqlFail(`Operator '${op}' cannot be applied to operands of types ${lt} and ${rt}.`, pos);
  const sticky = (type: KqlType, f: (x: never, y: never) => unknown): Compiled =>
    make(type, (row) => {
      const x = a(row);
      const y = b(row);
      return x === null || y === null || x === undefined || y === undefined ? null : f(x as never, y as never);
    }, [l, r]);

  if ((isNum(lt) || lt === "dynamic") && (isNum(rt) || rt === "dynamic")) {
    const dyn = lt === "dynamic" || rt === "dynamic";
    const type: KqlType = lt === "real" || rt === "real" ? "real" : lt === "dynamic" && rt === "dynamic" ? "dynamic" : "long";
    const integral = isIntegral(lt) && isIntegral(rt);
    const num = (f: (x: number, y: number) => number | null) =>
      sticky(type, (x: unknown, y: unknown) => {
        const p = dyn ? toNumber(x) : (x as number);
        const q = dyn ? toNumber(y) : (y as number);
        return p === null || q === null ? null : f(p, q);
      });
    switch (op) {
      case "+": return num((x, y) => x + y);
      case "-": return num((x, y) => x - y);
      case "*": return num((x, y) => x * y);
      case "/": return num((x, y) => {
        if (integral) return y === 0 ? null : Math.trunc(x / y);
        return x / y;
      });
      case "%": return num((x, y) => {
        if (y === 0) return integral ? null : NaN;
        const d = Math.abs(y);
        return ((x % d) + d) % d;
      });
    }
  }
  const ms = (t: KqlTimespan) => t.ticks / TICKS_PER_MS;
  if (op === "+") {
    if (lt === "timespan" && rt === "timespan") return sticky("timespan", (x: KqlTimespan, y: KqlTimespan) => new KqlTimespan(x.ticks + y.ticks));
    if (lt === "datetime" && rt === "timespan") return sticky("datetime", (x: Date, y: KqlTimespan) => new Date(x.getTime() + ms(y)));
    if (lt === "timespan" && rt === "datetime") return sticky("datetime", (x: KqlTimespan, y: Date) => new Date(y.getTime() + ms(x)));
  }
  if (op === "-") {
    if (lt === "timespan" && rt === "timespan") return sticky("timespan", (x: KqlTimespan, y: KqlTimespan) => new KqlTimespan(x.ticks - y.ticks));
    if (lt === "datetime" && rt === "datetime") return sticky("timespan", (x: Date, y: Date) => new KqlTimespan((x.getTime() - y.getTime()) * TICKS_PER_MS));
    if (lt === "datetime" && rt === "timespan") return sticky("datetime", (x: Date, y: KqlTimespan) => new Date(x.getTime() - ms(y)));
  }
  if (op === "*") {
    if (lt === "timespan" && isNum(rt)) return sticky("timespan", (x: KqlTimespan, y: number) => new KqlTimespan(x.ticks * y));
    if (isNum(lt) && rt === "timespan") return sticky("timespan", (x: number, y: KqlTimespan) => new KqlTimespan(y.ticks * x));
  }
  if (op === "/") {
    if (lt === "timespan" && rt === "timespan") return sticky("real", (x: KqlTimespan, y: KqlTimespan) => x.ticks / y.ticks);
    if (lt === "timespan" && isNum(rt)) return sticky("timespan", (x: KqlTimespan, y: number) => (y === 0 ? null : new KqlTimespan(x.ticks / y)));
  }
  if (op === "%" && lt === "timespan" && rt === "timespan") {
    return sticky("timespan", (x: KqlTimespan, y: KqlTimespan) => (y.ticks === 0 ? null : new KqlTimespan(((x.ticks % y.ticks) + Math.abs(y.ticks)) % Math.abs(y.ticks))));
  }
  throw bad();
}

// Term matching. A term is a maximal run of alphanumerics. An edge of the needle that is
// itself non-alphanumeric already sits on a term break, so only alphanumeric edges are checked.

function isTermChar(code: number): boolean {
  if (code < 128) return (code >= 48 && code <= 57) || (code >= 65 && code <= 90) || (code >= 97 && code <= 122);
  return /[\p{L}\p{N}]/u.test(String.fromCharCode(code));
}

function termSearch(hay: string, needle: string, left: boolean, right: boolean): boolean {
  if (needle === "") return true;
  const edgeL = left && isTermChar(needle.charCodeAt(0));
  const edgeR = right && isTermChar(needle.charCodeAt(needle.length - 1));
  let at = hay.indexOf(needle);
  while (at >= 0) {
    charge(1);
    const okL = !edgeL || at === 0 || !isTermChar(hay.charCodeAt(at - 1));
    const end = at + needle.length;
    const okR = !edgeR || end === hay.length || !isTermChar(hay.charCodeAt(end));
    if (okL && okR) return true;
    at = hay.indexOf(needle, at + 1);
  }
  return false;
}

const BASE_TESTS: Partial<Record<string, (h: string, n: string) => boolean>> & { equals: (h: string, n: string) => boolean; has: (h: string, n: string) => boolean } = {
  has: (h, n) => termSearch(h, n, true, true),
  hasprefix: (h, n) => termSearch(h, n, true, false),
  hassuffix: (h, n) => termSearch(h, n, false, true),
  contains: (h, n) => h.includes(n),
  startswith: (h, n) => h.startsWith(n),
  endswith: (h, n) => h.endsWith(n),
  equals: (h, n) => h === n,
};

interface StrOp {
  test: (h: string, n: string) => boolean;
  negate: boolean;
  cs: boolean;
}

function stringOp(op: string): StrOp | null {
  if (op === "=~") return { test: BASE_TESTS.equals, negate: false, cs: false };
  if (op === "!~") return { test: BASE_TESTS.equals, negate: true, cs: false };
  const negate = op.startsWith("!");
  const body = negate ? op.slice(1) : op;
  const cs = body.endsWith("_cs");
  const test = BASE_TESTS[cs ? body.slice(0, -3) : body];
  return test ? { test, negate, cs } : null;
}

function runStrOp(o: StrOp, hay: string, needle: string): boolean {
  charge(1 + (hay.length >> 6));
  const h = o.cs ? hay : hay.toLowerCase();
  const hit = o.test(h, needle);
  return hit !== o.negate;
}

function compileStrOp(op: StrOp, l: Compiled, r: Compiled): Compiled {
  const a = l.fn;
  const b = r.fn;
  if (r.constant) {
    const n0 = toStr(b({}));
    const needle = op.cs ? n0 : n0.toLowerCase();
    return make("bool", (row) => runStrOp(op, toStr(a(row)), needle), [l, r]);
  }
  return make("bool", (row) => {
    const n = toStr(b(row));
    return runStrOp(op, toStr(a(row)), op.cs ? n : n.toLowerCase());
  }, [l, r]);
}

function compileStarOp(op: StrOp, r: Compiled, s: Scope): Compiled {
  const cols = [...s.columns.keys()];
  const b = r.fn;
  return {
    type: "bool",
    constant: false,
    cost: cols.length + r.cost,
    fn: (row) => {
      const n = toStr(b(row));
      const needle = op.cs ? n : n.toLowerCase();
      const anyHit = cols.some((c) => {
        const h = toStr(row[c]);
        const low = op.cs ? h : h.toLowerCase();
        return op.test(low, needle);
      });
      return anyHit !== op.negate;
    },
  };
}

function compileRegexMatch(l: Compiled, r: Compiled, pos: number): Compiled {
  const a = l.fn;
  if (r.constant) {
    const source = toStr(r.fn({}));
    validateRegex(source, pos);
    const rx = compileRegex(source);
    return make("bool", (row) => rx.test(toStr(a(row))), [l, r]);
  }
  const b = r.fn;
  return make("bool", (row) => {
    try {
      return compileRegex(toStr(b(row))).test(toStr(a(row)));
    } catch (e) {
      if (e instanceof RegexError) return null;
      throw e;
    }
  }, [l, r]);
}

/** Search predicates map onto the string operators by where the wildcard sits. */
function compileSearchTerm(e: Extract<Expr, { k: "searchterm" }>, s: Scope): Compiled {
  const term = e.term;
  const lead = term.startsWith("*");
  const trail = term.endsWith("*") && term.length > 1;
  const core = term.slice(lead ? 1 : 0, trail ? -1 : undefined);
  const cs = !!s.searchCaseSensitive;
  const needleOp = core.includes("*") ? null : lead && trail ? "contains" : lead ? "hassuffix" : trail ? "hasprefix" : "has";
  const lit = constant("string", core);
  if (needleOp === null) {
    const rx = compileRegex(`${cs ? "" : "(?i)"}${wildcardRegex(term)}`);
    const cols = e.col ? [e.col] : [...s.columns.keys()];
    return {
      type: "bool", constant: false, cost: cols.length,
      fn: (row) => cols.some((c) => rx.test(toStr(row[c]))),
    };
  }
  const op = stringOp(cs ? `${needleOp}_cs` : needleOp) as StrOp;
  if (e.col) {
    if (!s.columns.has(e.col)) throw unresolvedColumn(e.col, e.pos, s);
    return compileStrOp(op, compile({ k: "name", name: e.col, pos: e.pos }, s), lit);
  }
  return compileStarOp(op, lit, s);
}

/** A list item that names or contains a table yields the first column of its rows. */
function tabularItem(e: Expr, s: Scope): Tabular | null {
  if (e.k === "paren") return tabularItem(e.e, s);
  if (e.k === "query") return s.rt.evalPipeline(e.q);
  if (e.k === "call" && e.name === "materialize" && e.args[0]) return tabularItem(e.args[0], s);
  if (e.k === "name" && !s.columns.has(e.name)) {
    const letv = s.rt.lets.get(e.name);
    if (letv?.kind === "scalar") return null;
    return s.rt.lookupTable(e.name) ?? null;
  }
  return null;
}

function firstColumnValues(t: Tabular, pos: number): { values: unknown[]; type: KqlType } {
  const col = t.columns[0];
  if (!col) throw new KqlFail("A tabular value with one column expected.", pos);
  return { values: t.rows.map((r) => r[col.name]), type: col.type };
}

/** Elements on the right of in, has_any and has_all: flat values, with dynamic arrays expanded. */
function listSources(e: Extract<Expr, { k: "in" }>, s: Scope, wantType: (t: KqlType) => void) {
  const fixed: unknown[] = [];
  const perRow: Compiled[] = [];
  for (const item of e.items) {
    const table = tabularItem(item, s);
    if (table) {
      const { values, type } = firstColumnValues(table, item.pos);
      wantType(type);
      fixed.push(...values);
      continue;
    }
    const c = compile(item, s);
    wantType(c.type);
    if (c.constant) {
      const v = c.fn({});
      if (Array.isArray(v)) fixed.push(...v);
      else fixed.push(v);
    } else perRow.push(c);
  }
  return { fixed, perRow };
}

function compileIn(e: Extract<Expr, { k: "in" }>, s: Scope): Compiled {
  const l = compile(e.l, s);
  const a = l.fn;
  if (e.op === "has_any" || e.op === "has_all") {
    const { fixed, perRow } = listSources(e, s, () => undefined);
    const all = e.op === "has_all";
    const has = BASE_TESTS.has;
    const needles = fixed.map((v) => toStr(v).toLowerCase());
    return {
      type: "bool", constant: false, cost: l.cost + needles.length + 1,
      fn: (row) => {
        const hay = toStr(a(row)).toLowerCase();
        charge(1 + (hay.length >> 6));
        let list = needles;
        if (perRow.length > 0) {
          list = needles.slice();
          for (const c of perRow) {
            const v = c.fn(row);
            for (const x of Array.isArray(v) ? v : [v]) list.push(toStr(x).toLowerCase());
          }
        }
        return all ? list.every((n) => has(hay, n)) : list.some((n) => has(hay, n));
      },
    };
  }
  const fold = e.op.endsWith("~");
  const negate = e.op.startsWith("!");
  const { fixed, perRow } = listSources(e, s, (t) => {
    if (fold) return;
    if (t !== "dynamic") checkEquatable(l.type, t, e.pos);
  });
  const norm = (v: unknown): string => {
    const key = keyOf(v);
    return fold ? key.toLowerCase() : key;
  };
  const set = new Set<string>();
  let hasNull = false;
  for (const v of fixed) {
    if (v === null || v === undefined) hasNull = true;
    else set.add(norm(v));
  }
  return {
    type: "bool", constant: false, cost: l.cost + 1 + perRow.length,
    fn: (row) => {
      const v = a(row);
      let found = false;
      let nullItem = hasNull;
      const isNull = v === null || v === undefined;
      const key = isNull ? "" : norm(v);
      if (!isNull) found = set.has(key);
      for (const c of perRow) {
        const items = c.fn(row);
        for (const x of Array.isArray(items) ? items : [items]) {
          if (x === null || x === undefined) nullItem = true;
          else if (!isNull && norm(x) === key) found = true;
        }
      }
      if (isNull) return nullItem ? null : negate;
      return found !== negate;
    },
  };
}

function compileBetween(e: Extract<Expr, { k: "between" }>, s: Scope): Compiled {
  const v = compile(e.l, s);
  const lo = compile(e.lo, s);
  let hi = compile(e.hi, s);
  const groupOk = (a: KqlType, b: KqlType) => (isNum(a) && isNum(b)) || a === b || a === "dynamic" || b === "dynamic";
  if (v.type === "datetime" && lo.type === "datetime" && hi.type === "timespan") hi = arithmetic("+", lo, hi, e.pos);
  if (!groupOk(v.type, lo.type) || !groupOk(v.type, hi.type)) throw compareError(v.type, !groupOk(v.type, lo.type) ? lo.type : hi.type, e.pos);
  if (v.type === "string" || v.type === "bool" || v.type === "guid") throw compareError(v.type, v.type, e.pos);
  return make("bool", (row) => {
    const x = v.fn(row);
    const a = lo.fn(row);
    const b = hi.fn(row);
    if (x === null || a === null || b === null || x === undefined || a === undefined || b === undefined) return null;
    const inside = compareValues(x, a) >= 0 && compareValues(x, b) <= 0;
    return inside !== e.neg;
  }, [v, lo, hi]);
}

function compileMember(obj: Compiled, keyFn: (row: Row) => unknown, keyC: Compiled | null, pos: number): Compiled {
  if (obj.type !== "dynamic") {
    throw new KqlFail(`Dynamic access requires a dynamic value, but the expression is of type ${obj.type}. Convert it with parse_json() first.`, pos);
  }
  const o = obj.fn;
  const fn = (row: Row) => {
    const v = o(row);
    if (v === null || typeof v !== "object") return null;
    const key = keyFn(row);
    if (Array.isArray(v)) {
      if (typeof key !== "number") return null;
      const i = key < 0 ? v.length + key : key;
      return v[i] ?? null;
    }
    if (key === null || key === undefined) return null;
    const k = String(key);
    return Object.prototype.hasOwnProperty.call(v, k) ? ((v as Record<string, unknown>)[k] ?? null) : null;
  };
  return make("dynamic", fn, keyC ? [obj, keyC] : [obj]);
}

function commonType(types: KqlType[], name: string, pos: number): KqlType {
  const concrete = types.filter((t) => t !== "dynamic");
  if (concrete.length === 0) return "dynamic";
  if (concrete.every(isNum)) return concrete.includes("real") ? "real" : concrete.includes("long") ? "long" : "int";
  if (concrete.every((t) => t === concrete[0])) return concrete[0];
  throw new KqlFail(`${name}(): no common type can be determined from the arguments (${types.join(", ")}).`, pos);
}

function coerceTo(c: Compiled, type: KqlType): Compiled {
  if (c.type !== "dynamic" || type === "dynamic") return { ...c, type };
  const f = c.fn;
  return make(type, (row) => castDyn(f(row), type), [c]);
}

function compileSpecial(name: string, e: Extract<Expr, { k: "call" }>, s: Scope): Compiled | null {
  const arity = (min: number, max: number) => {
    if (e.args.length < min || e.args.length > max) throw new KqlFail(`The function '${name}' was called with an incorrect number of arguments.`, e.pos);
  };
  switch (name) {
    case "not": {
      arity(1, 1);
      const c = compile(e.args[0], s);
      if (c.type !== "bool" && c.type !== "dynamic") throw new KqlFail(`The function 'not' expects a bool, got ${c.type}.`, e.pos);
      const f = c.fn;
      return make("bool", (row) => {
        const v = f(row);
        return v === null || v === undefined ? null : v !== true;
      }, [c]);
    }
    case "iff":
    case "iif": {
      arity(3, 3);
      const cond = compile(e.args[0], s);
      if (cond.type !== "bool" && cond.type !== "dynamic") throw new KqlFail(`${name}(): the condition must be of type bool, got ${cond.type}.`, e.pos);
      const a = compile(e.args[1], s);
      const b = compile(e.args[2], s);
      const type = commonType([a.type, b.type], name, e.pos);
      const x = coerceTo(a, type).fn;
      const y = coerceTo(b, type).fn;
      const f = cond.fn;
      return make(type, (row) => (f(row) === true ? x(row) : y(row)), [cond, a, b]);
    }
    case "case": {
      if (e.args.length < 3 || e.args.length % 2 === 0) throw new KqlFail("case(): expects predicate, value pairs and a final else value.", e.pos);
      const compiled = e.args.map((a) => compile(a, s));
      const results = compiled.filter((_, i) => i % 2 === 1 || i === compiled.length - 1);
      const type = commonType(results.map((c) => c.type), "case", e.pos);
      const conds: ((r: Row) => unknown)[] = [];
      const vals: ((r: Row) => unknown)[] = [];
      for (let i = 0; i + 1 < compiled.length; i += 2) {
        if (compiled[i].type !== "bool" && compiled[i].type !== "dynamic") throw new KqlFail(`case(): each predicate must be of type bool, got ${compiled[i].type}.`, e.pos);
        conds.push(compiled[i].fn);
        vals.push(coerceTo(compiled[i + 1], type).fn);
      }
      const other = coerceTo(compiled[compiled.length - 1], type).fn;
      return make(type, (row) => {
        for (let i = 0; i < conds.length; i++) if (conds[i](row) === true) return vals[i](row);
        return other(row);
      }, compiled);
    }
    case "coalesce": {
      if (e.args.length < 2) arity(2, 64);
      const compiled = e.args.map((a) => compile(a, s));
      const type = commonType(compiled.map((c) => c.type), name, e.pos);
      const fns = compiled.map((c) => coerceTo(c, type).fn);
      return make(type, (row) => {
        for (const f of fns) {
          const v = f(row);
          if (v !== null && v !== undefined && v !== "") return v;
        }
        return type === "string" ? "" : null;
      }, compiled);
    }
    case "min_of":
    case "max_of": {
      if (e.args.length < 2) arity(2, 64);
      const compiled = e.args.map((a) => compile(a, s));
      const type = commonType(compiled.map((c) => c.type), name, e.pos);
      const fns = compiled.map((c) => coerceTo(c, type).fn);
      const sign = name === "min_of" ? -1 : 1;
      return make(type, (row) => {
        let best: unknown = null;
        for (const f of fns) {
          const v = f(row);
          if (v === null || v === undefined) continue;
          if (best === null || compareValues(v, best) * sign > 0) best = v;
        }
        return best;
      }, compiled);
    }
    case "column_ifexists":
    case "columnifexists": {
      arity(2, 2);
      const nameArg = compile(e.args[0], s);
      if (!nameArg.constant) throw new KqlFail("column_ifexists(): the column name must be a constant string.", e.pos);
      const col = toStr(nameArg.fn({}));
      if (s.columns.has(col)) return compile({ k: "name", name: col, pos: e.pos }, s);
      return compile(e.args[1], s);
    }
    case "toscalar": {
      arity(1, 1);
      const table = tabularItem(e.args[0], s);
      if (table) {
        const col = table.columns[0];
        if (!col) throw new KqlFail("toscalar(): the tabular expression has no columns.", e.pos);
        const value = table.rows.length > 0 ? table.rows[0][col.name] : null;
        return constant(col.type, value ?? (col.type === "string" ? "" : null));
      }
      return compile(e.args[0], s);
    }
    case "materialize":
      throw new KqlFail("Scalar value expected.", e.pos);
    default:
      return null;
  }
}

function coerceArg(c: Compiled, kind: ParamKind, name: string, pos: number, allTypes: KqlType[]): (row: Row) => unknown {
  const f = c.fn;
  const reject = () => new KqlFail(`The function '${name}' is not compatible with arguments (${allTypes.join(", ")})`, pos);
  switch (kind) {
    case "n":
      if (isNum(c.type)) return f;
      if (c.type !== "dynamic") throw reject();
      return (row) => {
        const v = f(row);
        return v === undefined ? undefined : toNumber(v);
      };
    case "d":
      if (c.type === "datetime") return f;
      if (c.type !== "dynamic") throw reject();
      return (row) => toDatetimeValue(f(row));
    case "t":
      if (c.type === "timespan") return f;
      if (c.type !== "dynamic") throw reject();
      return (row) => toTimespanValue(f(row));
    case "y":
      if (c.type === "dynamic") return f;
      if (c.type === "string") throw reject();
      return (row) => toDyn(f(row));
    default:
      return f;
  }
}

function compileFunction(def: FnDef, name: string, e: Extract<Expr, { k: "call" }>, s: Scope): Compiled {
  const max = def.max ?? def.params.length;
  if (e.args.length < def.min || e.args.length > max) {
    throw new KqlFail(`The function '${name}' was called with an incorrect number of arguments.`, e.pos);
  }
  if (e.args.some((a) => a.k === "star")) throw new KqlFail("The * syntax is not allowed here.", e.pos);
  const args = e.args.map((a) => compile(a, s));
  const types = args.map((a) => a.type);
  const fns = args.map((a, i) => coerceArg(a, def.params[Math.min(i, def.params.length - 1)], name, e.pos, types));
  const info: ArgInfo[] = args.map((a) => ({
    type: a.type, constant: a.constant, value: a.constant ? a.fn({}) : undefined, typeLit: a.typeLit,
  }));
  def.check?.(info, e.pos);
  if (def.regexArg !== undefined) {
    const r = info[def.regexArg];
    if (r?.constant) validateRegex(toStr(r.value), e.pos);
  }
  const ret = typeof def.ret === "function" ? def.ret(info) : def.ret;
  const ctx = { now: s.rt.now };
  const impl = def.impl;
  const n = fns.length;
  return make(ret, (row) => {
    const a = new Array<unknown>(n);
    for (let i = 0; i < n; i++) a[i] = fns[i](row);
    return impl(a, types, ctx);
  }, args);
}

function compileCall(e: Extract<Expr, { k: "call" }>, s: Scope): Compiled {
  const name = e.name;
  if (Object.prototype.hasOwnProperty.call(AGG_PREFIX, name) || MULTI_AGGS.has(name)) {
    if (!s.agg) throw new KqlFail(`The aggregate function '${name}' is not allowed in this context.`, e.pos);
    if (name === "arg_max" || name === "arg_min") throw new KqlFail(`${name}() must be a top-level expression of summarize.`, e.pos);
    const inner: Scope = { ...s, columns: s.agg.input, agg: undefined };
    if (name === "percentile" || name === "percentiles") {
      const value = compile(e.args[0], inner);
      const p = compile(e.args[1], inner);
      const spec: AggSpec = {
        type: percentileType(value.type),
        make() {
          const st = percentileState(value, [toNumber(p.fn({})) ?? 0]);
          return { add: st.add, result: () => (st.result() as unknown[])[0] };
        },
      };
      return slotOf(spec, s);
    }
    const args = e.args.filter((a) => a.k !== "star").map((a) => compile(a, inner));
    return slotOf(buildAggregate(name, args, e.pos), s);
  }
  const special = compileSpecial(name, e, s);
  if (special) return special;
  const def = FUNCTIONS[name];
  if (def) return compileFunction(def, name, e, s);
  const near = nearest(name, [...Object.keys(FUNCTIONS), ...Object.keys(AGG_PREFIX), ...MULTI_AGGS, "iff", "iif", "case", "coalesce", "not"]);
  throw new KqlFail(`The name '${name}' does not refer to any known function.${near ? ` Did you mean '${near}'?` : ""}`, e.pos);
}

function slotOf(spec: AggSpec, s: Scope): Compiled {
  const agg = s.agg as AggCollector;
  const idx = agg.specs.push(spec) - 1;
  const key = `$agg${idx}`;
  return { type: spec.type, fn: (row) => row[key], constant: false, cost: 1 };
}

export function compile(e: Expr, s: Scope): Compiled {
  charge(1);
  switch (e.k) {
    case "lit":
      return constant(e.type, e.value);
    case "name": {
      const type = s.columns.get(e.name);
      if (type !== undefined) {
        const name = e.name;
        return { type, fn: (row) => row[name], constant: false, cost: 1 };
      }
      const v = s.rt.lets.get(e.name);
      if (v?.kind === "scalar") return constant(v.type, v.value);
      if (v?.kind === "tabular" || s.rt.lookupTable(e.name)) {
        throw new KqlFail(`The name '${e.name}' refers to a table, where a scalar value is expected.`, e.pos);
      }
      if (s.agg?.input.has(e.name)) {
        throw new KqlFail(`'summarize' operator: '${e.name}' is not an aggregation. Use an aggregation function such as count() or take_any(${e.name}), or move it to the by clause.`, e.pos);
      }
      throw unresolvedColumn(e.name, e.pos, s);
    }
    case "star":
      throw new KqlFail("The * syntax is not allowed here.", e.pos);
    case "paren":
      return compile(e.e, s);
    case "query":
      throw new KqlFail("Scalar value expected. Use toscalar() to read one value from a tabular expression.", e.pos);
    case "typeof":
      return { ...constant("string", e.type), typeLit: e.type };
    case "searchterm":
      return compileSearchTerm(e, s);
    case "unary": {
      const c = compile(e.e, s);
      if (e.op === "+") return c;
      const f = c.fn;
      if (c.type === "timespan") {
        return make("timespan", (row) => {
          const v = f(row) as KqlTimespan | null;
          return v === null ? null : new KqlTimespan(-v.ticks);
        }, [c]);
      }
      if (!isNum(c.type) && c.type !== "dynamic") throw new KqlFail(`Operator '-' cannot be applied to a value of type ${c.type}.`, e.pos);
      return make(c.type === "dynamic" ? "real" : c.type, (row) => {
        const v = toNumber(f(row));
        return v === null ? null : -v;
      }, [c]);
    }
    case "member":
      return compileMember(compile(e.obj, s), () => e.prop, null, e.pos);
    case "index": {
      const idx = compile(e.idx, s);
      return compileMember(compile(e.obj, s), idx.fn, idx, e.pos);
    }
    case "in":
      return compileIn(e, s);
    case "between":
      return compileBetween(e, s);
    case "call":
      return compileCall(e, s);
    case "bin": {
      if (e.op === "and" || e.op === "or") return compileLogical(e, s);
      const op = stringOp(e.op);
      if (e.l.k === "star") {
        if (!op) throw new KqlFail("The * syntax is not allowed here.", e.pos);
        return compileStarOp(op, compile(e.r, s), s);
      }
      const l = compile(e.l, s);
      const r = compile(e.r, s);
      if (e.op === "matches regex") return compileRegexMatch(l, r, e.pos);
      if (op) return compileStrOp(op, l, r);
      if (["==", "!=", "<", "<=", ">", ">="].includes(e.op)) return compileCompare(e.op, l, r, e.pos);
      return arithmetic(e.op, l, r, e.pos);
    }
  }
}

/** The column name Kusto derives for an unnamed expression, per GetExpressionResultName. */
export function resultName(e: Expr, fallback: string | null): string | null {
  switch (e.k) {
    case "paren":
      return resultName(e.e, fallback);
    case "name":
      return e.name;
    case "member": {
      const left = resultName(e.obj, null);
      return left ? `${left}_${e.prop}` : e.prop;
    }
    case "index": {
      const right = e.idx.k === "lit" && (typeof e.idx.value === "string" || typeof e.idx.value === "number") ? String(e.idx.value) : "";
      const left = resultName(e.obj, null);
      return left ? `${left}_${right}` : right;
    }
    case "call":
      return callResultName(e, fallback);
    default:
      return fallback;
  }
}

function callResultName(e: Extract<Expr, { k: "call" }>, fallback: string | null): string | null {
  const prefix = Object.prototype.hasOwnProperty.call(AGG_PREFIX, e.name) ? AGG_PREFIX[e.name] : undefined;
  const first = e.args[0];
  if (prefix !== undefined) {
    return first ? `${prefix}_${resultName(first, "") ?? ""}` : `${prefix}_`;
  }
  const naming = FUNCTIONS[e.name]?.naming;
  if (naming === "first") return first ? resultName(first, fallback) : null;
  if (naming === "nameFirst") return `${e.name}_${(first && resultName(first, "")) ?? ""}`;
  if (typeof naming === "object") return `${naming.prefix}_${(first && resultName(first, "")) ?? ""}`;
  return fallback;
}

/** Numbered copies of a taken name: x, x1, x2. */
export function uniqueName(name: string, used: Set<string> | Map<string, unknown>): string {
  if (!used.has(name)) return name;
  for (let i = 1; ; i++) {
    const candidate = `${name}${i}`;
    if (!used.has(candidate)) return candidate;
  }
}
