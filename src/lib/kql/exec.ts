import { buildAggregate, percentileState, percentileType, type AggState } from "./aggregates";
import type { Expr, NamedExpr, NamePattern, Op, ParseItem, Pipeline, Query, SortKey, Source, UnionSource } from "./ast";
import { KqlFail, KqlLimitFail, charge, checkRows, withHint } from "./errors";
import { compile, resultName, scopeOf, uniqueName, type AggCollector, type Compiled, type LetValue, type Row, type Runtime, type Scope, type Tabular } from "./compile";
import { RegexError, compileRegex, escapeRegex } from "./regex";
import type { KqlChart, KqlColumn, KqlEnv, KqlType } from "./types";
import { KqlTimespan, castDyn, compareValues, defaultFor, keyOf, normalizeCell, toDyn, toNumber, toStr } from "./values";

const TIME_COLUMN = "TimeGenerated";
const hasOwn = (o: object, k: string) => Object.prototype.hasOwnProperty.call(o, k);

const DOTNET_TYPES: Record<KqlType, string> = {
  string: "System.String", int: "System.Int32", long: "System.Int64", real: "System.Double", bool: "System.SByte",
  datetime: "System.DateTime", timespan: "System.TimeSpan", dynamic: "System.Object", guid: "System.Guid",
};

/** True when any where clause or search predicate in the query references TimeGenerated. */
export function queryFiltersTime(node: unknown, inFilter = false): boolean {
  if (Array.isArray(node)) return node.some((n) => queryFiltersTime(n, inFilter));
  if (node === null || typeof node !== "object" || node instanceof Date) return false;
  const obj = node as Record<string, unknown>;
  if (inFilter && obj.k === "name" && obj.name === TIME_COLUMN) return true;
  const filter = inFilter || obj.k === "where" || obj.k === "search";
  return Object.values(obj).some((v) => typeof v === "object" && queryFiltersTime(v, filter));
}

export interface ExecResult {
  table: Tabular;
  chart?: KqlChart;
  warnings: string[];
}

export function execute(query: Query, env: KqlEnv): ExecResult {
  return new Engine(query, env).run();
}

class Engine implements Runtime {
  readonly now: Date;
  readonly lets = new Map<string, LetValue>();
  private readonly env: KqlEnv;
  private readonly query: Query;
  private readonly warnings: string[] = [];
  private readonly scanned = new Map<string, Tabular>();
  private chart?: KqlChart;
  private applyRange = false;

  constructor(query: Query, env: KqlEnv) {
    this.query = query;
    this.env = env;
    this.now = env.now;
  }

  run(): ExecResult {
    const { env, query } = this;
    if (env.timeRange) {
      if (queryFiltersTime(query)) {
        this.warnings.push("Time range picker overridden: the query filters on TimeGenerated (Set in query).");
      } else this.applyRange = true;
    }
    let last: Tabular | undefined;
    let tabularStatements = 0;
    for (const st of query.statements) {
      if (st.k === "let") {
        this.lets.set(st.name, this.evalLet(st.value, st.isPipeline));
      } else {
        this.chart = undefined;
        last = this.evalPipeline(st.q);
        tabularStatements++;
      }
    }
    if (!last) {
      const end = query.statements[query.statements.length - 1]?.pos ?? 0;
      throw new KqlFail("The query has no tabular expression to run. End it with a table or a let name.", end);
    }
    if (tabularStatements > 1) this.warnings.push("The query has several tabular statements. Showing the result of the last one.");
    return { table: last, chart: this.chart, warnings: this.warnings };
  }

  private evalLet(value: Expr | Pipeline, pipeline: boolean): LetValue {
    if (pipeline) return { kind: "tabular", table: this.evalPipeline(value as Pipeline) };
    const e = value as Expr;
    if (e.k === "query") return { kind: "tabular", table: this.evalPipeline(e.q) };
    if (e.k === "call" && e.name === "materialize" && e.args[0]?.k === "query") {
      return { kind: "tabular", table: this.evalPipeline(e.args[0].q) };
    }
    if (e.k === "name") {
      const scalar = this.lets.get(e.name);
      if (scalar?.kind === "scalar") return scalar;
      const table = this.lookupTable(e.name);
      if (table) return { kind: "tabular", table };
    }
    const c = compile(e, scopeOf([], "", this));
    return { kind: "scalar", type: c.type, value: c.fn({}) };
  }

  tableNames(): string[] {
    const lets = [...this.lets].filter(([, v]) => v.kind === "tabular").map(([k]) => k);
    return [...Object.keys(this.env.tables), ...lets];
  }

  lookupTable(name: string): Tabular | undefined {
    const v = this.lets.get(name);
    if (v?.kind === "tabular") return { ...v.table, name };
    return hasOwn(this.env.tables, name) ? this.scan(name) : undefined;
  }

  private scan(name: string): Tabular {
    const cached = this.scanned.get(name);
    if (cached) return cached;
    const source = this.env.tables[name];
    const columns = source.columns.map((c) => ({ name: c.name, type: c.type }));
    const rows: Row[] = [];
    const range = this.applyRange && columns.some((c) => c.name === TIME_COLUMN && c.type === "datetime") ? this.env.timeRange : undefined;
    const from = range?.from.getTime();
    const to = range?.to.getTime();
    for (const raw of source.rows) {
      charge(1);
      const row: Row = {};
      for (const c of columns) row[c.name] = normalizeCell(raw[c.name], c.type);
      if (range) {
        const t = row[TIME_COLUMN] as Date | null;
        if (!t || t.getTime() < (from as number) || t.getTime() > (to as number)) continue;
      }
      rows.push(row);
    }
    const table: Tabular = { columns, rows, name };
    this.scanned.set(name, table);
    return table;
  }

  private resolve(name: string, pos: number): Tabular {
    const t = this.lookupTable(name);
    if (t) return t;
    if (this.lets.get(name)?.kind === "scalar") throw new KqlFail(`The name '${name}' refers to a scalar value, where a table is expected.`, pos);
    throw new KqlFail(withHint(`Failed to resolve table or column expression named '${name}'`, name, this.tableNames()), pos, name);
  }

  evalPipeline(q: Pipeline): Tabular {
    let t = this.evalSource(q.source);
    for (const op of q.ops) {
      try {
        t = this.applyOp(op, t);
      } catch (e) {
        // Budget failures fire deep in an expression, so they take the position of their operator.
        if (e instanceof KqlLimitFail && e.pos === 0) e.pos = op.pos;
        throw e;
      }
    }
    return t;
  }

  private evalSource(s: Source): Tabular {
    switch (s.k) {
      case "table":
        return this.resolve(s.name, s.pos);
      case "paren":
        return this.evalPipeline(s.q);
      case "op":
        return s.op.k === "union" ? this.union(s.op) : this.search(s.op, undefined);
      case "print":
        return this.print(s.items);
      case "datatable":
        return this.datatable(s);
      case "range":
        return this.range(s);
    }
  }

  private print(items: NamedExpr[]): Tabular {
    const scope = scopeOf([], "print", this);
    const row: Row = {};
    const columns: KqlColumn[] = [];
    const used = new Set<string>();
    items.forEach((item, i) => {
      const c = compile(item.expr, scope);
      const name = uniqueName(item.name ?? resultName(item.expr, null) ?? `print_${i}`, used);
      used.add(name);
      columns.push({ name, type: c.type });
      row[name] = c.fn({});
    });
    return { columns, rows: [row] };
  }

  private datatable(s: Extract<Source, { k: "datatable" }>): Tabular {
    const n = s.columns.length;
    if (n === 0 || s.values.length % n !== 0) throw new KqlFail(`Incorrect number of data values. The values should appear in multiples of ${n}.`, s.pos);
    const scope = scopeOf([], "datatable", this);
    const rows: Row[] = [];
    for (let i = 0; i < s.values.length; i += n) {
      const row: Row = {};
      s.columns.forEach((col, j) => {
        row[col.name] = normalizeCell(compile(s.values[i + j], scope).fn({}), col.type);
      });
      rows.push(row);
    }
    return { columns: s.columns.map((c) => ({ ...c })), rows };
  }

  private range(s: Extract<Source, { k: "range" }>): Tabular {
    const scope = scopeOf([], "range", this);
    const from = compile(s.from, scope);
    const to = compile(s.to, scope);
    const step = compile(s.step, scope);
    const rows: Row[] = [];
    const a = from.fn({});
    const b = to.fn({});
    const st = step.fn({});
    const push = (v: unknown) => {
      rows.push({ [s.name]: v });
      checkRows(rows.length, s.pos);
      charge(1);
    };
    if (a instanceof Date && b instanceof Date && st instanceof KqlTimespan && st.ticks > 0) {
      for (let t = a.getTime(); t <= b.getTime(); t += st.ms) push(new Date(t));
    } else if (typeof a === "number" && typeof b === "number" && typeof st === "number" && st !== 0) {
      for (let v = a; st > 0 ? v <= b : v >= b; v += st) push(v);
    } else throw new KqlFail("The range operator needs from, to and step of matching types and a non-zero step.", s.pos);
    return { columns: [{ name: s.name, type: from.type === "int" ? "long" : from.type }], rows };
  }

  private applyOp(op: Op, t: Tabular): Tabular {
    switch (op.k) {
      case "where": return this.where(op, t);
      case "project": return this.project(op.items, t);
      case "extend": return this.extend(op.items, t);
      case "project-away": return this.projectAway(op.patterns, t);
      case "project-keep": return this.projectKeep(op.patterns, t);
      case "project-rename": return this.projectRename(op.pairs, t);
      case "project-reorder": return this.projectReorder(op.patterns, t);
      case "summarize": return this.summarize(op.aggs, op.by, t);
      case "count": return { columns: [{ name: "Count", type: "long" }], rows: [{ Count: t.rows.length }] };
      case "distinct": return this.distinct(op, t);
      case "top": return this.top(op, t);
      case "take": return this.take(op, t);
      case "sort": return this.sortTable(op.keys, t, op.alias);
      case "join": return this.join(op, t);
      case "union": return this.union(op, t);
      case "mv-expand": return this.mvExpand(op, t);
      case "parse": return this.parse(op, t);
      case "search": return this.search(op, t);
      case "getschema": return this.getSchema(t);
      case "sample": return this.sample(op, t);
      case "render":
        this.chart = { kind: op.chart };
        return t;
    }
  }

  private where(op: Extract<Op, { k: "where" }>, t: Tabular): Tabular {
    const scope = scopeOf(t.columns, op.alias, this);
    const c = compile(op.expr, scope);
    if (c.type !== "bool" && c.type !== "dynamic") {
      throw new KqlFail(`'${op.alias}' operator: the predicate must be of type bool, got ${c.type}.`, op.pos);
    }
    const rows: Row[] = [];
    const cost = c.cost + 1;
    for (const row of t.rows) {
      charge(cost);
      if (c.fn(row) === true) rows.push(row);
    }
    return { columns: t.columns, rows, name: t.name };
  }

  /** Compiles a named list in order, so later items can use earlier ones, as Kusto allows. */
  private assignments(items: NamedExpr[], t: Tabular, op: string): { name: string; c: Compiled }[] {
    const scope = scopeOf(t.columns, op, this);
    const out: { name: string; c: Compiled }[] = [];
    let auto = 1;
    const autoName = (): string => {
      for (;;) {
        const n = `Column${auto++}`;
        if (!scope.columns.has(n)) return n;
      }
    };
    for (const item of items) {
      if (item.names) throw new KqlFail("A tuple assignment needs an aggregate that returns several columns.", item.pos);
      const c = compile(item.expr, scope);
      const name = item.name ?? resultName(item.expr, null) ?? autoName();
      scope.columns.set(name, c.type);
      out.push({ name, c });
    }
    return out;
  }

  private project(items: NamedExpr[], t: Tabular): Tabular {
    const list = this.assignments(items, t, "project");
    const used = new Set<string>();
    const outNames = list.map((a) => {
      const n = uniqueName(a.name, used);
      used.add(n);
      return n;
    });
    const columns = list.map((a, i) => ({ name: outNames[i], type: a.c.type }));
    const cost = list.reduce((n, a) => n + a.c.cost, 1);
    const rows = t.rows.map((row) => {
      charge(cost);
      const work: Row = { ...row };
      const out: Row = {};
      list.forEach((a, i) => {
        const v = a.c.fn(work);
        work[a.name] = v;
        out[outNames[i]] = v;
      });
      return out;
    });
    return { columns, rows, name: t.name };
  }

  private extend(items: NamedExpr[], t: Tabular): Tabular {
    const list = this.assignments(items, t, "extend");
    const columns = t.columns.slice();
    for (const a of list) {
      // An existing column keeps its position, as Kusto.Language's ProjectionBuilder does.
      const at = columns.findIndex((c) => c.name === a.name);
      if (at >= 0) columns[at] = { name: a.name, type: a.c.type };
      else columns.push({ name: a.name, type: a.c.type });
    }
    const cost = list.reduce((n, a) => n + a.c.cost, 1);
    const rows = t.rows.map((row) => {
      charge(cost);
      const out: Row = { ...row };
      for (const a of list) out[a.name] = a.c.fn(out);
      return out;
    });
    return { columns, rows, name: t.name };
  }

  private matchPattern(p: NamePattern, columns: KqlColumn[], op: string): KqlColumn[] {
    if (p.text.includes("*")) {
      const parts = p.text.split("*");
      const hit = (name: string) => {
        if (!name.startsWith(parts[0])) return false;
        let at = parts[0].length;
        for (let i = 1; i < parts.length - 1; i++) {
          const next = name.indexOf(parts[i], at);
          if (next < 0) return false;
          at = next + parts[i].length;
        }
        const tail = parts[parts.length - 1];
        return name.length - tail.length >= at && name.endsWith(tail);
      };
      return columns.filter((c) => hit(c.name));
    }
    const col = columns.find((c) => c.name === p.text);
    if (!col) {
      throw new KqlFail(withHint(`'${op}' operator: Failed to resolve column or scalar expression named '${p.text}'`, p.text, columns.map((c) => c.name)), p.pos);
    }
    return [col];
  }

  private pickColumns(t: Tabular, keep: KqlColumn[]): Tabular {
    const names = keep.map((c) => c.name);
    const rows = t.rows.map((row) => {
      charge(1);
      const out: Row = {};
      for (const n of names) out[n] = row[n];
      return out;
    });
    return { columns: keep, rows, name: t.name };
  }

  private projectAway(patterns: NamePattern[], t: Tabular): Tabular {
    const drop = new Set<string>();
    for (const p of patterns) for (const c of this.matchPattern(p, t.columns, "project-away")) drop.add(c.name);
    return this.pickColumns(t, t.columns.filter((c) => !drop.has(c.name)));
  }

  private projectKeep(patterns: NamePattern[], t: Tabular): Tabular {
    const keep = new Set<string>();
    for (const p of patterns) for (const c of this.matchPattern(p, t.columns, "project-keep")) keep.add(c.name);
    return this.pickColumns(t, t.columns.filter((c) => keep.has(c.name)));
  }

  private projectRename(pairs: Extract<Op, { k: "project-rename" }>["pairs"], t: Tabular): Tabular {
    const map = new Map<string, string>();
    for (const p of pairs) {
      if (!t.columns.some((c) => c.name === p.from)) {
        throw new KqlFail(withHint(`'project-rename' operator: Failed to resolve column or scalar expression named '${p.from}'`, p.from, t.columns.map((c) => c.name)), p.pos);
      }
      map.set(p.from, p.to);
    }
    const targets = new Set(map.values());
    const kept = t.columns.filter((c) => map.has(c.name) || !targets.has(c.name));
    const columns = kept.map((c) => ({ name: map.get(c.name) ?? c.name, type: c.type }));
    const rows = t.rows.map((row) => {
      charge(1);
      const out: Row = {};
      for (const c of kept) out[map.get(c.name) ?? c.name] = row[c.name];
      return out;
    });
    return { columns, rows, name: t.name };
  }

  private projectReorder(patterns: NamePattern[], t: Tabular): Tabular {
    const first: KqlColumn[] = [];
    for (const p of patterns) {
      const hits = this.matchPattern(p, t.columns, "project-reorder").filter((c) => !first.includes(c));
      if (p.dir) hits.sort((a, b) => compareValues(a.name, b.name) * (p.dir === "asc" ? 1 : -1));
      first.push(...hits);
    }
    return { ...t, columns: [...first, ...t.columns.filter((c) => !first.includes(c))] };
  }

  private summarize(aggs: NamedExpr[], by: NamedExpr[], t: Tabular): Tabular {
    const input = scopeOf(t.columns, "summarize", this);
    const used = new Set<string>();
    const columns: KqlColumn[] = [];
    let auto = 1;

    const keys = by.map((item) => {
      const c = compile(item.expr, input);
      const derived = item.name ?? resultName(item.expr, null);
      if (c.type === "dynamic") {
        throw new KqlFail(`Summarize group key '${derived ?? "Column1"}' is of a 'dynamic' type. Please use an explicit cast as grouping by a 'dynamic' type is not supported.`, item.pos);
      }
      const name = uniqueName(derived ?? `Column${auto++}`, used);
      used.add(name);
      columns.push({ name, type: c.type });
      return { name, c };
    });

    const collector: AggCollector = { specs: [], input: input.columns };
    const outer: Scope = { columns: new Map(keys.map((k) => [k.name, k.c.type])), op: "summarize", rt: this, agg: collector };
    const outputs: { name: string; fn: (row: Row) => unknown }[] = [];
    const add = (rawName: string, type: KqlType, fn: (row: Row) => unknown) => {
      const name = uniqueName(rawName, used);
      used.add(name);
      columns.push({ name, type });
      outputs.push({ name, fn });
    };

    for (const item of aggs) {
      const multi = this.multiAggregate(item, input, collector, by, add);
      if (multi) continue;
      const before = collector.specs.length;
      const c = compile(item.expr, outer);
      if (collector.specs.length === before) {
        throw new KqlFail("'summarize' operator: an aggregation function is expected, such as count().", item.pos);
      }
      add(item.name ?? resultName(item.expr, null) ?? `Column${auto++}`, c.type, c.fn);
    }

    const specs = collector.specs;
    const groups = new Map<string, { keys: unknown[]; states: AggState[] }>();
    const cost = specs.length + keys.reduce((n, k) => n + k.c.cost, 1);
    const open = (keyValues: unknown[]) => ({ keys: keyValues, states: specs.map((s) => s.make()) });
    if (keys.length === 0) groups.set("", open([]));
    for (const row of t.rows) {
      charge(cost);
      const keyValues = keys.map((k) => k.c.fn(row));
      const key = keys.length === 1 ? keyOf(keyValues[0]) : keyValues.map(keyOf).join("\u0001");
      let g = groups.get(key);
      if (!g) {
        g = open(keyValues);
        groups.set(key, g);
      }
      for (const st of g.states) st.add(row);
    }
    const rows: Row[] = [];
    for (const g of groups.values()) {
      const work: Row = {};
      keys.forEach((k, i) => {
        work[k.name] = g.keys[i];
      });
      g.states.forEach((st, i) => {
        work[`$agg${i}`] = st.result();
      });
      const out: Row = {};
      keys.forEach((k, i) => {
        out[k.name] = g.keys[i];
      });
      for (const o of outputs) out[o.name] = o.fn(work);
      rows.push(out);
    }
    return { columns, rows };
  }

  /** arg_max, arg_min, take_any and percentiles return several columns from one state. */
  private multiAggregate(
    item: NamedExpr, input: Scope, collector: AggCollector, by: NamedExpr[],
    add: (name: string, type: KqlType, fn: (row: Row) => unknown) => void,
  ): boolean {
    const e = item.expr;
    if (e.k !== "call") return false;
    const slot = (st: () => AggState, type: KqlType) => {
      const idx = collector.specs.push({ type, make: st }) - 1;
      return `$agg${idx}`;
    };
    if (e.name === "percentile" || e.name === "percentiles") {
      if (e.args.length < 2) throw new KqlFail(`The function '${e.name}' was called with an incorrect number of arguments.`, e.pos);
      const value = compile(e.args[0], input);
      const percents = e.args.slice(1).map((a) => {
        const c = compile(a, input);
        const p = c.constant ? toNumber(c.fn({})) : null;
        if (p === null) throw new KqlFail("The percentile must be a constant number.", a.pos);
        return p;
      });
      const type = percentileType(value.type);
      const key = slot(() => percentileState(value, percents), type);
      const base = resultName(e.args[0], "") ?? "";
      percents.forEach((p, i) => {
        add(item.names?.[i] ?? item.name ?? `percentile_${base}_${String(p).replace(/\./g, "_")}`, type, (row) => (row[key] as unknown[])[i]);
      });
      return true;
    }
    if (e.name === "take_any") {
      if (e.args.length === 1 && e.args[0].k !== "star" && e.args[0].k !== "name") {
        const c = compile(e.args[0], input);
        const key = slot(() => buildAggregate("take_any", [c], e.pos).make(), c.type);
        add(item.name ?? (resultName(e.args[0], "") || "any_arg0"), c.type, (row) => row[key]);
        return true;
      }
      const list = e.args.flatMap((a, i) => {
        if (a.k === "star") {
          const taken = new Set(by.map((b) => b.name ?? resultName(b.expr, null)));
          return [...input.columns.keys()].filter((n) => !taken.has(n)).map((n) => ({ name: n, c: compile({ k: "name", name: n, pos: a.pos }, input) }));
        }
        const c = compile(a, input);
        return [{ name: e.argNames[i] ?? (resultName(a, "") || `any_arg${i}`), c }];
      });
      if (list.length === 1 && item.name) list[0].name = item.name;
      list.forEach(({ name, c }, i) => {
        const key = slot(() => buildAggregate("take_any", [c], e.pos).make(), c.type);
        add(item.names?.[i] ?? name, c.type, (row) => row[key]);
      });
      return true;
    }
    if (e.name !== "arg_max" && e.name !== "arg_min") return false;
    if (e.args.length < 1) throw new KqlFail(`The function '${e.name}' was called with an incorrect number of arguments.`, e.pos);
    const prefix = e.name === "arg_max" ? "max" : "min";
    const primary = compile(e.args[0], input);
    if (primary.type === "dynamic") throw new KqlFail("The argument value must be orderable: a number, timespan, datetime, string or boolean.", e.pos);
    const sign = e.name === "arg_max" ? 1 : -1;
    const primaryName = resultName(e.args[0], null);
    const bySet = new Set(by.map((b) => b.name ?? resultName(b.expr, null)));
    const anyStar = e.args.some((a) => a.k === "star");
    const seen = new Set<string>(primaryName ? [primaryName] : []);
    const returned: { name: string; c: Compiled }[] = [{ name: item.names?.[0] ?? item.name ?? primaryName ?? `${prefix}_`, c: primary }];
    e.args.slice(1).forEach((a, offset) => {
      if (a.k === "star") {
        for (const n of input.columns.keys()) {
          if (seen.has(n) || bySet.has(n)) continue;
          seen.add(n);
          returned.push({ name: n, c: compile({ k: "name", name: n, pos: a.pos }, input) });
        }
        return;
      }
      const c = compile(a, input);
      const declared = e.argNames[offset + 1];
      const direct = a.k === "name" ? a.name : null;
      if (anyStar && direct && (seen.has(direct) || bySet.has(direct))) return;
      if (direct) seen.add(direct);
      returned.push({ name: declared ?? resultName(a, null) ?? `${prefix}_${primaryName ?? ""}_arg${offset + 1}`, c });
    });
    const key = slot(() => {
      let best: unknown = null;
      let bestRow: Row | null = null;
      let firstRow: Row | null = null;
      return {
        add(row) {
          if (!firstRow) firstRow = row;
          const v = primary.fn(row);
          if (v === null || v === undefined) return;
          if (best === null || compareValues(v, best) * sign > 0) {
            best = v;
            bestRow = row;
          }
        },
        result: () => bestRow ?? firstRow,
      };
    }, "dynamic");
    returned.forEach(({ name, c }, i) => {
      const fallback = defaultFor(c.type);
      add(item.names?.[i] ?? name, c.type, (row) => {
        const src = row[key] as Row | null;
        return src ? c.fn(src) : fallback;
      });
    });
    return true;
  }

  private distinct(op: Extract<Op, { k: "distinct" }>, t: Tabular): Tabular {
    if (op.star) {
      for (const c of t.columns) {
        if (c.type === "dynamic") throw new KqlFail(`distinct group key '${c.name}' is of a 'dynamic' type. Please use an explicit cast as grouping by a 'dynamic' type is not supported.`, op.pos);
      }
      return this.dedupe(t.rows, t.columns, t.columns.map((c) => ({ name: c.name, fn: (r: Row) => r[c.name] })));
    }
    const list = this.assignments(op.items, t, "distinct");
    for (const a of list) {
      if (a.c.type === "dynamic") throw new KqlFail(`distinct group key '${a.name}' is of a 'dynamic' type. Please use an explicit cast as grouping by a 'dynamic' type is not supported.`, op.pos);
    }
    return this.dedupe(t.rows, list.map((a) => ({ name: a.name, type: a.c.type })), list.map((a) => ({ name: a.name, fn: a.c.fn })));
  }

  private dedupe(input: Row[], columns: KqlColumn[], fns: { name: string; fn: (r: Row) => unknown }[]): Tabular {
    const seen = new Set<string>();
    const rows: Row[] = [];
    for (const row of input) {
      charge(fns.length);
      const values = fns.map((f) => f.fn(row));
      const key = values.map(keyOf).join("\u0001");
      if (seen.has(key)) continue;
      seen.add(key);
      const out: Row = {};
      fns.forEach((f, i) => {
        out[f.name] = values[i];
      });
      rows.push(out);
    }
    return { columns, rows };
  }

  private constantCount(e: Expr, op: string, t: Tabular): number {
    const c = compile(e, scopeOf(t.columns, op, this));
    if (!c.constant) throw new KqlFail(`'${op}' operator: the row count must be a constant.`, e.pos);
    const n = toNumber(c.fn({}));
    if (n === null || n < 0) throw new KqlFail(`'${op}' operator: the row count must be a non-negative number.`, e.pos);
    return Math.trunc(n);
  }

  private take(op: Extract<Op, { k: "take" }>, t: Tabular): Tabular {
    return { ...t, rows: t.rows.slice(0, this.constantCount(op.n, op.alias, t)) };
  }

  private sortRows(keys: SortKey[], t: Tabular, op: string): Row[] {
    const scope = scopeOf(t.columns, op, this);
    const compiled = keys.map((k) => {
      const c = compile(k.expr, scope);
      if (c.type === "dynamic") throw new KqlFail(`'${op}' operator: key can't be of dynamic type`, k.expr.pos);
      const nullsFirst = k.nulls ? k.nulls === "first" : k.dir === "asc";
      return { fn: c.fn, sign: k.dir === "asc" ? 1 : -1, nullsFirst };
    });
    const rows = t.rows.map((row) => ({ row, keys: compiled.map((k) => k.fn(row)) }));
    charge(rows.length * (1 + Math.ceil(Math.log2(rows.length + 1))));
    const isGap = (v: unknown) => v === null || v === undefined || (typeof v === "number" && Number.isNaN(v));
    rows.sort((a, b) => {
      for (let i = 0; i < compiled.length; i++) {
        const k = compiled[i];
        const x = a.keys[i];
        const y = b.keys[i];
        const xg = isGap(x);
        const yg = isGap(y);
        if (xg || yg) {
          if (xg && yg) continue;
          return (xg ? -1 : 1) * (k.nullsFirst ? 1 : -1);
        }
        const c = compareValues(x, y);
        if (c !== 0) return c * k.sign;
      }
      return 0;
    });
    return rows.map((r) => r.row);
  }

  private sortTable(keys: SortKey[], t: Tabular, op: string): Tabular {
    return { ...t, rows: this.sortRows(keys, t, op) };
  }

  private top(op: Extract<Op, { k: "top" }>, t: Tabular): Tabular {
    const n = this.constantCount(op.n, "top", t);
    return { ...t, rows: this.sortRows([op.key], t, "top").slice(0, n) };
  }

  private sample(op: Extract<Op, { k: "sample" }>, t: Tabular): Tabular {
    const n = Math.min(this.constantCount(op.n, "sample", t), t.rows.length);
    // Seeded from the query clock, so the same query over the same data stays reproducible.
    let state = (this.now.getTime() ^ (t.rows.length * 2654435761)) >>> 0;
    const next = () => {
      state = (state + 0x6d2b79f5) >>> 0;
      let z = state;
      z = Math.imul(z ^ (z >>> 15), z | 1);
      z ^= z + Math.imul(z ^ (z >>> 7), z | 61);
      return ((z ^ (z >>> 14)) >>> 0) / 4294967296;
    };
    const pool = t.rows.slice();
    for (let i = 0; i < n; i++) {
      const j = i + Math.floor(next() * (pool.length - i));
      [pool[i], pool[j]] = [pool[j], pool[i]];
    }
    return { ...t, rows: pool.slice(0, n) };
  }

  private getSchema(t: Tabular): Tabular {
    return {
      columns: [
        { name: "ColumnName", type: "string" }, { name: "ColumnOrdinal", type: "int" },
        { name: "DataType", type: "string" }, { name: "ColumnType", type: "string" },
      ],
      rows: t.columns.map((c, i) => ({ ColumnName: c.name, ColumnOrdinal: i, DataType: DOTNET_TYPES[c.type], ColumnType: c.type })),
    };
  }

  private join(op: Extract<Op, { k: "join" }>, left: Tabular): Tabular {
    const right = this.evalPipeline(op.right);
    const typeOf = (t: Tabular, name: string) => t.columns.find((c) => c.name === name)?.type;
    for (const key of op.on) {
      const lt = typeOf(left, key.left);
      const rt = typeOf(right, key.right);
      if (lt === undefined || rt === undefined) {
        const missing = lt === undefined ? key.left : key.right;
        const side = lt === undefined ? left : right;
        throw new KqlFail(withHint(`'join' operator: The column '${missing}' must exist on both sides of the join`, missing, side.columns.map((c) => c.name)), key.pos);
      }
      if (lt === "dynamic" || rt === "dynamic") throw new KqlFail("Join keys cannot be dynamic", key.pos);
      const numeric = (t: KqlType) => t === "int" || t === "long" || t === "real";
      if (lt !== rt && !(numeric(lt) && numeric(rt))) throw new KqlFail(`Inconsistent data types for join keys: (${lt}, ${rt})`, key.pos);
    }
    const keyFor = (row: Row, side: "left" | "right"): string | null => {
      let key = "";
      for (const k of op.on) {
        const v = row[k[side]];
        // Equality on null never holds, so a null key matches nothing.
        if (v === null || v === undefined) return null;
        key += `${keyOf(v)}\u0001`;
      }
      return key;
    };

    const kind = op.kind;
    if (kind === "leftsemi" || kind === "leftanti" || kind === "rightsemi" || kind === "rightanti") {
      const probeLeft = kind === "leftsemi" || kind === "leftanti";
      const keep = kind === "leftsemi" || kind === "rightsemi";
      const [source, other, sideA, sideB] = probeLeft ? [left, right, "left", "right"] as const : [right, left, "right", "left"] as const;
      const present = new Set<string>();
      for (const row of other.rows) {
        charge(1);
        const k = keyFor(row, sideB);
        if (k !== null) present.add(k);
      }
      const rows = source.rows.filter((row) => {
        charge(1);
        const k = keyFor(row, sideA);
        return (k !== null && present.has(k)) === keep;
      });
      return { columns: source.columns, rows };
    }

    const used = new Set(left.columns.map((c) => c.name));
    const rename = new Map<string, string>();
    const columns: KqlColumn[] = left.columns.slice();
    for (const c of right.columns) {
      const name = uniqueName(c.name, used);
      used.add(name);
      rename.set(c.name, name);
      columns.push({ name, type: c.type });
    }
    const index = new Map<string, number[]>();
    right.rows.forEach((row, i) => {
      charge(1);
      const k = keyFor(row, "right");
      if (k === null) return;
      const bucket = index.get(k);
      if (bucket) bucket.push(i);
      else index.set(k, [i]);
    });
    const emptyLeft: Row = {};
    for (const c of left.columns) emptyLeft[c.name] = defaultFor(c.type);
    const emptyRight: Row = {};
    for (const c of right.columns) emptyRight[rename.get(c.name) as string] = defaultFor(c.type);
    const mapRight = (row: Row): Row => {
      const out: Row = {};
      for (const c of right.columns) out[rename.get(c.name) as string] = row[c.name];
      return out;
    };
    const rows: Row[] = [];
    const matchedRight = new Set<number>();
    const seenLeft = new Set<string>();
    const emit = (row: Row) => {
      charge(columns.length);
      rows.push(row);
      checkRows(rows.length, op.pos);
    };
    for (const row of left.rows) {
      const k = keyFor(row, "left");
      if (kind === "innerunique" && k !== null) {
        // Deduplication keeps the first left row per key, before matching.
        if (seenLeft.has(k)) continue;
        seenLeft.add(k);
      }
      const bucket = k === null ? undefined : index.get(k);
      if (bucket) {
        for (const i of bucket) {
          matchedRight.add(i);
          emit({ ...row, ...mapRight(right.rows[i]) });
        }
      } else if (kind === "leftouter" || kind === "fullouter") {
        emit({ ...row, ...emptyRight });
      }
    }
    if (kind === "rightouter" || kind === "fullouter") {
      right.rows.forEach((row, i) => {
        if (!matchedRight.has(i)) emit({ ...emptyLeft, ...mapRight(row) });
      });
    }
    return { columns, rows };
  }

  /** Expands a table list. Wildcards and fuzzy misses resolve here, against tables and tabular lets. */
  private sources(list: UnionSource[], fuzzy: boolean): Tabular[] {
    const out: Tabular[] = [];
    const failed: { name: string; pos: number }[] = [];
    list.forEach((s, i) => {
      if (s.q) {
        try {
          const t = this.evalPipeline(s.q);
          out.push({ ...t, name: t.name ?? `union_arg${i}` });
        } catch (e) {
          if (fuzzy && e instanceof KqlFail && e.unresolvedTable) failed.push({ name: e.unresolvedTable, pos: s.pos });
          else throw e;
        }
        return;
      }
      const name = s.name as string;
      if (name.includes("*")) {
        const parts = name.split("*");
        const re = compileRegex(`^${parts.map(escapeRegex).join(".*")}$`);
        const hits = this.tableNames().filter((n) => re.test(n));
        if (hits.length === 0) failed.push({ name, pos: s.pos });
        for (const n of hits) out.push(this.resolve(n, s.pos));
        return;
      }
      const t = this.lookupTable(name);
      if (t) out.push(t);
      else failed.push({ name, pos: s.pos });
    });
    if (failed.length > 0 && (!fuzzy || out.length === 0)) {
      const f = failed[0];
      this.resolve(f.name, f.pos);
      throw new KqlFail(`Failed to resolve table or column expression named '${f.name}'`, f.pos, f.name);
    }
    for (const f of failed) this.warnings.push(`Failed to resolve entity '${f.name}'`);
    return out;
  }

  private merge(tables: Tabular[], kind: "inner" | "outer", sourceColumn: string | undefined, pos: number): Tabular {
    const typesByName = new Map<string, KqlType[]>();
    for (const t of tables) {
      for (const c of t.columns) {
        const list = typesByName.get(c.name);
        if (!list) typesByName.set(c.name, [c.type]);
        else if (!list.includes(c.type)) list.push(c.type);
      }
    }
    const columns: KqlColumn[] = sourceColumn ? [{ name: sourceColumn, type: "string" }] : [];
    const used = new Set<string>(sourceColumn ? [sourceColumn] : []);
    const outName = new Map<string, string>();
    const inner = (name: string, type: KqlType) => tables.every((t) => t.columns.some((c) => c.name === name && c.type === type));
    for (const [name, types] of typesByName) {
      if (kind === "inner" && !(types.length === 1 && inner(name, types[0]))) continue;
      for (const type of types) {
        const target = uniqueName(types.length > 1 ? `${name}_${type}` : name, used);
        used.add(target);
        outName.set(`${name}\u0001${type}`, target);
        columns.push({ name: target, type });
      }
    }
    const rows: Row[] = [];
    for (const t of tables) {
      const pairs = t.columns
        .map((c) => ({ from: c.name, to: outName.get(`${c.name}\u0001${c.type}`) }))
        .filter((p): p is { from: string; to: string } => p.to !== undefined);
      const label = t.name ?? "";
      for (const row of t.rows) {
        charge(1);
        const out: Row = {};
        for (const c of columns) out[c.name] = defaultFor(c.type);
        if (sourceColumn) out[sourceColumn] = label;
        for (const p of pairs) out[p.to] = row[p.from];
        rows.push(out);
      }
      checkRows(rows.length, pos);
    }
    return { columns, rows };
  }

  private union(op: Extract<Op, { k: "union" }>, input?: Tabular): Tabular {
    const tables = this.sources(op.sources, op.isfuzzy);
    if (input) tables.unshift(input);
    return this.merge(tables, op.kind, op.withsource, op.pos);
  }

  private search(op: Extract<Op, { k: "search" }>, input: Tabular | undefined): Tabular {
    let tables: Tabular[];
    if (input) tables = [input];
    else if (op.sources) tables = this.sources(op.sources, false);
    else tables = Object.keys(this.env.tables).map((n) => this.scan(n));
    const matched: Tabular[] = [];
    for (const t of tables) {
      const scope: Scope = { ...scopeOf(t.columns, "search", this), searchCaseSensitive: op.caseSensitive };
      let c: Compiled;
      try {
        c = compile(op.pred, scope);
      } catch (e) {
        // A column named in the predicate that one table lacks only rules that table out.
        if (tables.length > 1 && e instanceof KqlFail && !(e.unresolvedTable) && e.message.includes("Failed to resolve column")) continue;
        throw e;
      }
      const rows = t.rows.filter((row) => {
        charge(c.cost + 1);
        return c.fn(row) === true;
      });
      if (rows.length > 0 || tables.length === 1) matched.push({ ...t, rows, name: t.name });
    }
    return this.merge(matched, "outer", "$table", op.pos);
  }

  private mvExpand(op: Extract<Op, { k: "mv-expand" }>, t: Tabular): Tabular {
    const scope = scopeOf(t.columns, "mv-expand", this);
    const items = op.items.map((item) => {
      const c = compile(item.expr, scope);
      if (c.type !== "dynamic") throw new KqlFail(`'mv-expand' operator: the expanded expression must be of type dynamic, got ${c.type}.`, item.pos);
      const name = item.name ?? resultName(item.expr, null) ?? "Column1";
      return { name, c, type: item.type ?? ("dynamic" as KqlType) };
    });
    const columns = t.columns.map((c) => {
      const replaced = items.find((i) => i.name === c.name);
      return replaced ? { name: c.name, type: replaced.type } : c;
    });
    for (const i of items) if (!t.columns.some((c) => c.name === i.name)) columns.push({ name: i.name, type: i.type });
    if (op.itemIndex) columns.push({ name: op.itemIndex, type: "long" });
    const elements = (v: unknown): unknown[] => {
      if (v === null || v === undefined) return [null];
      if (Array.isArray(v)) return v;
      if (typeof v === "object") {
        return Object.entries(v as Record<string, unknown>).map(([k, val]) => {
          if (op.bagKind === "array") return [k, val];
          const bag: Record<string, unknown> = {};
          Object.defineProperty(bag, k, { value: val, enumerable: true, writable: true, configurable: true });
          return bag;
        });
      }
      return [v];
    };
    const rows: Row[] = [];
    const cost = items.reduce((n, i) => n + i.c.cost, 1);
    for (const row of t.rows) {
      charge(cost);
      const lists = items.map((i) => elements(i.c.fn(row)));
      let n = Math.max(...lists.map((l) => l.length));
      if (op.limit !== undefined) n = Math.min(n, op.limit);
      for (let k = 0; k < n; k++) {
        const out: Row = { ...row };
        items.forEach((item, idx) => {
          const v = k < lists[idx].length ? (lists[idx][k] ?? null) : null;
          out[item.name] = item.type === "dynamic" ? toDyn(v) : v === null ? defaultFor(item.type) : castDyn(v, item.type);
        });
        if (op.itemIndex) out[op.itemIndex] = k;
        rows.push(out);
      }
      charge(n);
      checkRows(rows.length, op.pos);
    }
    return { columns, rows };
  }

  private parse(op: Extract<Op, { k: "parse" }>, t: Tabular): Tabular {
    const c = compile(op.expr, scopeOf(t.columns, "parse", this));
    const fields = op.pattern.filter((p): p is Extract<ParseItem, { t: "col" }> => p.t === "col");
    const rx = parseRegex(op);
    const columns = t.columns.filter((col) => !fields.some((f) => f.name === col.name));
    for (const f of fields) columns.push({ name: f.name, type: f.type });
    const groupOf = fields.map((_, i) => i + 1);
    const rows: Row[] = [];
    for (const row of t.rows) {
      charge(c.cost + 1);
      const text = toStr(c.fn(row));
      const m = rx.exec(text);
      const out: Row = { ...row };
      const parsed = fields.map((f, i) => {
        const g = groupOf[i];
        if (!m || m[g * 2] < 0) return defaultFor(f.type);
        const cap = text.slice(m[g * 2], m[g * 2 + 1]);
        return f.type === "dynamic" ? cap : normalizeCell(cap, f.type);
      });
      const failed = fields.some((f, i) => parsed[i] === null && f.type !== "string" && f.type !== "dynamic");
      if ((!m || (failed && op.kind !== "relaxed")) && op.dropUnmatched) continue;
      fields.forEach((f, i) => {
        out[f.name] = !m || (failed && op.kind !== "relaxed") ? defaultFor(f.type) : parsed[i];
      });
      rows.push(out);
    }
    return { columns, rows, name: t.name };
  }
}

function parseRegex(op: Extract<Op, { k: "parse" }>) {
  const regexMode = op.kind === "regex";
  const parts: string[] = ["^"];
  op.pattern.forEach((p, i) => {
    if (p.t === "lit") parts.push(regexMode ? p.text : escapeRegex(p.text));
    else if (p.t === "star") parts.push(".*?");
    else {
      const last = i === op.pattern.length - 1;
      if (regexMode && p.type === "string") parts.push("(.*)");
      else if (p.type === "long" || p.type === "int") parts.push(op.kind === "relaxed" ? "(.*?)" : "(-?\\d+)");
      else if (p.type === "real") parts.push(op.kind === "relaxed" ? "(.*?)" : "([-+]?\\d+(?:\\.\\d*)?(?:[eE][-+]?\\d+)?)");
      else parts.push(last ? "(.*)" : "(.*?)");
    }
  });
  try {
    return compileRegex(parts.join(""), { s: !regexMode || op.flags.includes("s"), i: op.flags.includes("i"), m: op.flags.includes("m"), U: op.flags.includes("U") });
  } catch (e) {
    if (e instanceof RegexError) throw new KqlFail(`Invalid parse pattern: ${e.message}`, op.pos);
    throw e;
  }
}
