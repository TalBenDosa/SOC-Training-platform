import { KqlFail, charge } from "./errors";
import type { KqlType } from "./types";
import { KqlTimespan, compareValues, keyOf, toDyn, toNumber } from "./values";

export type Row = Record<string, unknown>;

/** The compiled form of an expression: its static type and a row closure. */
export interface Compiled {
  type: KqlType;
  fn: (row: Row) => unknown;
  constant: boolean;
  /** Node count, charged per row. */
  cost: number;
  typeLit?: KqlType;
}

export interface AggState {
  add(row: Row): void;
  result(): unknown;
}

export interface AggSpec {
  type: KqlType;
  make(): AggState;
}

/** Result-column prefix of each single-column aggregate, from Kusto.Language Aggregates.cs. */
export const AGG_PREFIX: Record<string, string> = {
  count: "count", countif: "countif", dcount: "dcount", dcountif: "dcountif",
  sum: "sum", sumif: "sumif", avg: "avg", avgif: "avgif", min: "min", max: "max", minif: "minif", maxif: "maxif",
  make_list: "list", make_set: "set", make_bag: "bag", any: "any", stdev: "stdev", variance: "variance",
};

/** Aggregates that can produce several columns. */
export const MULTI_AGGS = new Set(["arg_max", "arg_min", "take_any", "percentile", "percentiles"]);

export const AGGREGATE_NAMES = [...Object.keys(AGG_PREFIX), ...MULTI_AGGS];

function isSummable(t: KqlType): boolean {
  return t === "int" || t === "long" || t === "real" || t === "timespan" || t === "datetime";
}

const notSummable = (pos: number) => new KqlFail("The argument value must be summable: a number, timespan or datetime.", pos);
const notOrderable = (pos: number) => new KqlFail("The argument value must be orderable: a number, timespan, datetime, string or boolean.", pos);

function requireArgs(name: string, args: Compiled[], min: number, max: number, pos: number): void {
  if (args.length < min || args.length > max) throw new KqlFail(`The function '${name}' was called with an incorrect number of arguments.`, pos);
}

function requireBool(c: Compiled, pos: number): void {
  if (c.type !== "bool" && c.type !== "dynamic") throw new KqlFail(`The aggregate predicate must be of type bool, got ${c.type}.`, pos);
}

function toTotal(v: unknown): number | null {
  if (v instanceof KqlTimespan) return v.ticks;
  if (v instanceof Date) return v.getTime();
  return toNumber(v);
}

function fromTotal(n: number, type: KqlType): unknown {
  if (type === "timespan") return new KqlTimespan(Math.round(n));
  if (type === "datetime") return new Date(n);
  return n;
}

function pick(args: Compiled[], withPredicate: boolean): { value: Compiled; pred?: Compiled } {
  return { value: args[0], pred: withPredicate ? args[1] : undefined };
}

function extreme(sign: 1 | -1, value: Compiled, pred?: Compiled): AggSpec {
  return {
    type: value.type,
    make() {
      let best: unknown = null;
      return {
        add(row) {
          if (pred && pred.fn(row) !== true) return;
          const v = value.fn(row);
          if (v === null || v === undefined || (typeof v === "number" && Number.isNaN(v))) return;
          if (best === null || compareValues(v, best) * sign > 0) best = v;
        },
        result: () => (best === null && value.type === "string" ? "" : best),
      };
    },
  };
}

function sum(value: Compiled, pred?: Compiled): AggSpec {
  const type: KqlType = value.type === "int" ? "long" : value.type;
  return {
    type,
    make() {
      let total = 0;
      return {
        add(row) {
          if (pred && pred.fn(row) !== true) return;
          const n = toTotal(value.fn(row));
          if (n !== null) total += n;
        },
        result: () => fromTotal(total, type),
      };
    },
  };
}

function avg(value: Compiled, pred?: Compiled): AggSpec {
  const type: KqlType = value.type === "timespan" || value.type === "datetime" ? value.type : "real";
  return {
    type,
    make() {
      let total = 0;
      let n = 0;
      return {
        add(row) {
          if (pred && pred.fn(row) !== true) return;
          const v = toTotal(value.fn(row));
          if (v !== null) {
            total += v;
            n++;
          }
        },
        result: () => (n === 0 ? (type === "real" ? NaN : null) : fromTotal(total / n, type)),
      };
    },
  };
}

function spread(value: Compiled, root: boolean): AggSpec {
  return {
    type: "real",
    make() {
      let n = 0;
      let mean = 0;
      let m2 = 0;
      return {
        add(row) {
          const x = toNumber(value.fn(row));
          if (x === null) return;
          n++;
          const d = x - mean;
          mean += d / n;
          m2 += d * (x - mean);
        },
        result() {
          if (n < 2) return 0;
          const variance = m2 / (n - 1);
          return root ? Math.sqrt(variance) : variance;
        },
      };
    },
  };
}

function count(pred?: Compiled): AggSpec {
  return {
    type: "long",
    make() {
      let n = 0;
      return {
        add(row) {
          if (!pred || pred.fn(row) === true) n++;
        },
        result: () => n,
      };
    },
  };
}

function dcount(value: Compiled, pred?: Compiled): AggSpec {
  return {
    type: "long",
    make() {
      const seen = new Set<string>();
      return {
        add(row) {
          if (pred && pred.fn(row) !== true) return;
          const v = value.fn(row);
          if (v !== null && v !== undefined) seen.add(keyOf(v));
        },
        result: () => seen.size,
      };
    },
  };
}

function collect(value: Compiled, maxSize: Compiled | undefined, distinct: boolean): AggSpec {
  const cap = maxSize ? (toNumber(maxSize.fn({})) ?? 1048576) : 1048576;
  return {
    type: "dynamic",
    make() {
      const out: unknown[] = [];
      const seen = new Set<string>();
      return {
        add(row) {
          if (out.length >= cap) return;
          const v = value.fn(row);
          if (v === null || v === undefined) return;
          const dyn = toDyn(v);
          if (distinct) {
            const key = keyOf(dyn);
            if (seen.has(key)) return;
            seen.add(key);
          }
          out.push(dyn);
        },
        result: () => out,
      };
    },
  };
}

function makeBag(value: Compiled): AggSpec {
  return {
    type: "dynamic",
    make() {
      const out: Record<string, unknown> = {};
      return {
        add(row) {
          const v = value.fn(row);
          if (v === null || typeof v !== "object" || Array.isArray(v)) return;
          for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
            if (!Object.prototype.hasOwnProperty.call(out, k)) {
              Object.defineProperty(out, k, { value: val, enumerable: true, writable: true, configurable: true });
            }
          }
        },
        result: () => out,
      };
    },
  };
}

function firstValue(value: Compiled): AggSpec {
  return {
    type: value.type,
    make() {
      let v: unknown;
      let has = false;
      return {
        add(row) {
          if (!has) {
            const x = value.fn(row);
            if (x !== null && x !== undefined) {
              v = x;
              has = true;
            }
          }
        },
        result: () => (has ? v : value.type === "string" ? "" : null),
      };
    },
  };
}

/** Nearest-rank percentile, as the docs define it. Exact here, where Kusto estimates with T-Digest. */
export function percentileState(value: Compiled, percents: number[]): AggState {
  const values: unknown[] = [];
  return {
    add(row) {
      const v = value.fn(row);
      if (v !== null && v !== undefined && !(typeof v === "number" && Number.isNaN(v))) values.push(v);
    },
    result() {
      charge(values.length);
      values.sort(compareValues);
      return percents.map((p) => {
        if (values.length === 0) return null;
        const rank = p <= 0 ? 1 : Math.ceil((p / 100) * values.length);
        return values[Math.min(rank, values.length) - 1];
      });
    },
  };
}

export function percentileType(t: KqlType): KqlType {
  return t === "int" ? "long" : t;
}

export function buildAggregate(name: string, args: Compiled[], pos: number): AggSpec {
  const orderable = (c: Compiled) => {
    if (c.type === "dynamic" || c.type === "guid") throw notOrderable(pos);
  };
  const summable = (c: Compiled) => {
    if (!isSummable(c.type)) throw notSummable(pos);
  };
  switch (name) {
    case "count":
      requireArgs(name, args, 0, 1, pos);
      return count();
    case "countif":
      requireArgs(name, args, 1, 1, pos);
      requireBool(args[0], pos);
      return count(args[0]);
    case "dcount":
      requireArgs(name, args, 1, 2, pos);
      return dcount(args[0]);
    case "dcountif":
      requireArgs(name, args, 2, 3, pos);
      requireBool(args[1], pos);
      return dcount(args[0], args[1]);
    case "sum":
    case "sumif": {
      requireArgs(name, args, name === "sum" ? 1 : 2, name === "sum" ? 1 : 2, pos);
      summable(args[0]);
      if (name === "sumif") requireBool(args[1], pos);
      const { value, pred } = pick(args, name === "sumif");
      return sum(value, pred);
    }
    case "avg":
    case "avgif": {
      requireArgs(name, args, name === "avg" ? 1 : 2, name === "avg" ? 1 : 2, pos);
      summable(args[0]);
      if (name === "avgif") requireBool(args[1], pos);
      const { value, pred } = pick(args, name === "avgif");
      return avg(value, pred);
    }
    case "min":
    case "max":
    case "minif":
    case "maxif": {
      const withPred = name.endsWith("if");
      requireArgs(name, args, withPred ? 2 : 1, withPred ? 2 : 1, pos);
      orderable(args[0]);
      if (withPred) requireBool(args[1], pos);
      const { value, pred } = pick(args, withPred);
      return extreme(name.startsWith("min") ? -1 : 1, value, pred);
    }
    case "stdev":
    case "variance":
      requireArgs(name, args, 1, 1, pos);
      if (!isSummable(args[0].type) || args[0].type === "datetime") throw notSummable(pos);
      return spread(args[0], name === "stdev");
    case "make_list":
    case "make_set":
      requireArgs(name, args, 1, 2, pos);
      return collect(args[0], args[1], name === "make_set");
    case "make_bag":
      requireArgs(name, args, 1, 2, pos);
      return makeBag(args[0]);
    case "any":
    case "take_any":
      requireArgs(name, args, 1, 1, pos);
      return firstValue(args[0]);
    default:
      throw new KqlFail(`The name '${name}' does not refer to any known function.`, pos);
  }
}
