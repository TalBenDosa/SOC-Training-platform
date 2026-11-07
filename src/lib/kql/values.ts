import type { KqlType } from "./types";
import { charge, tooLarge } from "./errors";

export const TICKS_PER_MS = 10_000;
export const TICKS_PER_SECOND = 10_000_000;
export const TICKS_PER_MINUTE = 60 * TICKS_PER_SECOND;
export const TICKS_PER_HOUR = 60 * TICKS_PER_MINUTE;
export const TICKS_PER_DAY = 24 * TICKS_PER_HOUR;
/** Milliseconds from 0001-01-01, the origin of Kusto datetime ticks, to the Unix epoch. */
export const EPOCH_OFFSET_MS = 62_135_596_800_000;

/**
 * A Kusto timespan, in 100ns ticks. This is the type-tagged form timespans keep in
 * result rows: `kqlType` identifies it, and String(value) prints the portal form.
 */
export class KqlTimespan {
  readonly kqlType = "timespan" as const;
  readonly ticks: number;
  constructor(ticks: number) {
    this.ticks = ticks;
  }
  get ms(): number {
    return this.ticks / TICKS_PER_MS;
  }
  toString(): string {
    return formatTimespan(this.ticks);
  }
  toJSON(): string {
    return formatTimespan(this.ticks);
  }
}

export function isTimespan(v: unknown): v is KqlTimespan {
  return v instanceof KqlTimespan;
}

/** .NET "c" form, which is what the portal prints: [-][d.]hh:mm:ss[.fffffff]. */
export function formatTimespan(ticks: number): string {
  const t = Math.abs(Math.round(ticks));
  const days = Math.floor(t / TICKS_PER_DAY);
  let rest = t - days * TICKS_PER_DAY;
  const hours = Math.floor(rest / TICKS_PER_HOUR);
  rest -= hours * TICKS_PER_HOUR;
  const minutes = Math.floor(rest / TICKS_PER_MINUTE);
  rest -= minutes * TICKS_PER_MINUTE;
  const seconds = Math.floor(rest / TICKS_PER_SECOND);
  rest -= seconds * TICKS_PER_SECOND;
  const sign = ticks < 0 ? "-" : "";
  const d = days > 0 ? `${days}.` : "";
  const frac = rest > 0 ? `.${String(rest).padStart(7, "0")}` : "";
  return `${sign}${d}${pad2(hours)}:${pad2(minutes)}:${pad2(seconds)}${frac}`;
}

function pad2(n: number): string {
  return n < 10 ? `0${n}` : String(n);
}

const UNIT_TICKS: Record<string, number> = {
  d: TICKS_PER_DAY, day: TICKS_PER_DAY, days: TICKS_PER_DAY,
  h: TICKS_PER_HOUR, hr: TICKS_PER_HOUR, hrs: TICKS_PER_HOUR, hour: TICKS_PER_HOUR, hours: TICKS_PER_HOUR,
  m: TICKS_PER_MINUTE, min: TICKS_PER_MINUTE, mins: TICKS_PER_MINUTE, minute: TICKS_PER_MINUTE, minutes: TICKS_PER_MINUTE,
  s: TICKS_PER_SECOND, sec: TICKS_PER_SECOND, secs: TICKS_PER_SECOND, second: TICKS_PER_SECOND, seconds: TICKS_PER_SECOND,
  ms: TICKS_PER_MS, milli: TICKS_PER_MS, millis: TICKS_PER_MS, millisecond: TICKS_PER_MS, milliseconds: TICKS_PER_MS,
  microsecond: 10, microseconds: 10, micro: 10, micros: 10,
  tick: 1, ticks: 1,
};

export function timespanUnitTicks(unit: string): number | undefined {
  return Object.prototype.hasOwnProperty.call(UNIT_TICKS, unit.toLowerCase()) ? UNIT_TICKS[unit.toLowerCase()] : undefined;
}

/** Accepts `[-][d.]hh:mm[:ss[.fffffff]]` and unit forms such as `5m`, `1.5h`. */
export function parseTimespan(text: string): KqlTimespan | null {
  if (text.length > 64) return null;
  const s = text.trim();
  const unit = /^(-?\d+(?:\.\d+)?)\s*([A-Za-z]+)$/.exec(s);
  if (unit) {
    const u = timespanUnitTicks(unit[2]);
    return u === undefined ? null : new KqlTimespan(Math.round(Number(unit[1]) * u));
  }
  const m = /^(-)?(?:(\d+)\.)?(\d{1,2}):(\d{2})(?::(\d{2})(?:\.(\d{1,7})\d*)?)?$/.exec(s);
  if (!m) return null;
  const frac = m[6] ? Number(m[6].padEnd(7, "0")) : 0;
  const ticks =
    Number(m[2] ?? 0) * TICKS_PER_DAY +
    Number(m[3]) * TICKS_PER_HOUR +
    Number(m[4]) * TICKS_PER_MINUTE +
    Number(m[5] ?? 0) * TICKS_PER_SECOND +
    frac;
  return new KqlTimespan(m[1] ? -ticks : ticks);
}

const MONTHS: Record<string, number> = { jan: 1, feb: 2, mar: 3, apr: 4, may: 5, jun: 6, jul: 7, aug: 8, sep: 9, oct: 10, nov: 11, dec: 12 };

function utc(y: number, mo: number, d: number, h: number, mi: number, s: number, ms: number): Date | null {
  const date = new Date(0);
  date.setUTCFullYear(y, mo - 1, d);
  date.setUTCHours(h, mi, s, ms);
  if (date.getUTCMonth() !== mo - 1 || date.getUTCDate() !== d || h > 23 || mi > 59 || s > 59) return null;
  return date;
}

/** Date-only and timezone-less values are UTC, as in Kusto. Precision stops at milliseconds. */
export function parseDatetime(text: string): Date | null {
  if (text.length > 64) return null;
  const s = text.trim();
  let m = /^(\d{4})-(\d{1,2})-(\d{1,2})(?:[T ]+(\d{1,2}):(\d{2})(?::(\d{2})(?:\.(\d{1,9}))?)?)?\s*(Z|z|[+-]\d{2}(?::?\d{2})?)?$/.exec(s);
  if (m) {
    const ms = m[7] ? Number(m[7].padEnd(3, "0").slice(0, 3)) : 0;
    const base = utc(Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4] ?? 0), Number(m[5] ?? 0), Number(m[6] ?? 0), ms);
    if (!base) return null;
    const tz = m[8];
    if (tz && tz !== "Z" && tz !== "z") {
      const sign = tz[0] === "-" ? -1 : 1;
      const digits = tz.slice(1).replace(":", "");
      const offset = Number(digits.slice(0, 2)) * 60 + Number(digits.slice(2, 4) || 0);
      return new Date(base.getTime() - sign * offset * 60_000);
    }
    return base;
  }
  m = /^(\d{1,2})\/(\d{1,2})\/(\d{4})(?:[ ,]+(\d{1,2}):(\d{2})(?::(\d{2})(?:\.(\d{1,3}))?)?\s*([AaPp][Mm])?)?$/.exec(s);
  if (m) {
    let h = Number(m[4] ?? 0);
    const ampm = m[8]?.toLowerCase();
    if (ampm === "pm" && h < 12) h += 12;
    if (ampm === "am" && h === 12) h = 0;
    return utc(Number(m[3]), Number(m[1]), Number(m[2]), h, Number(m[5] ?? 0), Number(m[6] ?? 0), m[7] ? Number(m[7].padEnd(3, "0")) : 0);
  }
  m = /^(?:[A-Za-z]{3},\s*)?(\d{1,2})\s+([A-Za-z]{3})\s+(\d{4})(?:\s+(\d{1,2}):(\d{2})(?::(\d{2}))?)?(?:\s+(?:GMT|UTC|Z))?$/.exec(s);
  if (m) {
    const mo = MONTHS[m[2].toLowerCase()];
    return mo ? utc(Number(m[3]), mo, Number(m[1]), Number(m[4] ?? 0), Number(m[5] ?? 0), Number(m[6] ?? 0), 0) : null;
  }
  return null;
}

/** tostring() form of a datetime. */
export function datetimeToIso(d: Date): string {
  const t = d.getTime();
  if (Number.isNaN(t)) return "";
  const iso = d.toISOString();
  const ms = d.getUTCMilliseconds();
  const base = iso.slice(0, 19);
  return ms === 0 ? `${base}Z` : `${base}.${String(ms).padStart(3, "0")}0000Z`;
}

/** Results grid form in the Log Analytics portal, in UTC: 11/7/2026, 10:00:00.000 AM */
function datetimePortal(d: Date): string {
  if (Number.isNaN(d.getTime())) return "";
  const h24 = d.getUTCHours();
  const h12 = h24 % 12 === 0 ? 12 : h24 % 12;
  const ms = String(d.getUTCMilliseconds()).padStart(3, "0");
  return `${d.getUTCMonth() + 1}/${d.getUTCDate()}/${d.getUTCFullYear()}, ${h12}:${pad2(d.getUTCMinutes())}:${pad2(d.getUTCSeconds())}.${ms} ${h24 < 12 ? "AM" : "PM"}`;
}

/** JSON text of a dynamic value, charged to the budget so shared structure cannot explode. */
export function dynToJson(v: unknown): string {
  const parts: string[] = [];
  const write = (x: unknown, depth: number): void => {
    charge(1);
    if (depth > 400) throw new RangeError("dynamic value too deep");
    if (x === null || x === undefined) parts.push("null");
    else if (typeof x === "string") parts.push(JSON.stringify(x));
    else if (typeof x === "number") parts.push(Number.isFinite(x) ? String(x) : "null");
    else if (typeof x === "boolean") parts.push(String(x));
    else if (x instanceof Date) parts.push(JSON.stringify(datetimeToIso(x)));
    else if (x instanceof KqlTimespan) parts.push(JSON.stringify(x.toString()));
    else if (Array.isArray(x)) {
      parts.push("[");
      x.forEach((item, i) => {
        if (i > 0) parts.push(",");
        write(item, depth + 1);
      });
      parts.push("]");
    } else if (typeof x === "object") {
      parts.push("{");
      let first = true;
      for (const [k, val] of Object.entries(x as Record<string, unknown>)) {
        if (!first) parts.push(",");
        first = false;
        parts.push(JSON.stringify(k), ":");
        write(val, depth + 1);
      }
      parts.push("}");
    } else parts.push(JSON.stringify(String(x)));
    if (parts.length > 2_000_000) throw tooLarge();
  };
  write(v, 0);
  return parts.join("");
}

/** tostring(): null becomes the empty string, dynamic strings lose their JSON quotes. */
export function toStr(v: unknown): string {
  if (v === null || v === undefined) return "";
  if (typeof v === "string") return v;
  if (typeof v === "number") return Number.isNaN(v) ? "NaN" : v === Infinity ? "+inf" : v === -Infinity ? "-inf" : String(v);
  if (typeof v === "boolean") return v ? "true" : "false";
  if (v instanceof Date) return datetimeToIso(v);
  if (v instanceof KqlTimespan) return v.toString();
  return dynToJson(v);
}

/** Moves a typed value into dynamic. Datetimes and timespans are held as their string forms. */
export function toDyn(v: unknown): unknown {
  if (v === undefined) return null;
  if (v instanceof Date) return datetimeToIso(v);
  if (v instanceof KqlTimespan) return v.toString();
  return v;
}

export function toNumber(v: unknown): number | null {
  if (v === null || v === undefined) return null;
  if (typeof v === "number") return v;
  if (typeof v === "boolean") return v ? 1 : 0;
  if (typeof v === "string") {
    const s = v.trim();
    if (s === "") return null;
    if (!/^[+-]?(\d+(\.\d*)?|\.\d+)([eE][+-]?\d+)?$/.test(s) && !/^0[xX][0-9a-fA-F]+$/.test(s)) return null;
    return Number(s);
  }
  if (v instanceof KqlTimespan) return v.ticks;
  if (v instanceof Date) return (v.getTime() + EPOCH_OFFSET_MS) * TICKS_PER_MS;
  return null;
}

export function toLongValue(v: unknown): number | null {
  const n = toNumber(v);
  return n === null || !Number.isFinite(n) ? null : Math.trunc(n);
}

export function toBoolValue(v: unknown): boolean | null {
  if (v === null || v === undefined) return null;
  if (typeof v === "boolean") return v;
  if (typeof v === "number") return Number.isNaN(v) ? null : v !== 0;
  if (typeof v === "string") {
    const s = v.trim().toLowerCase();
    if (s === "true" || s === "1") return true;
    if (s === "false" || s === "0") return false;
  }
  return null;
}

export function toDatetimeValue(v: unknown): Date | null {
  if (v === null || v === undefined) return null;
  if (v instanceof Date) return Number.isNaN(v.getTime()) ? null : v;
  if (typeof v === "string") return parseDatetime(v);
  return null;
}

export function toTimespanValue(v: unknown): KqlTimespan | null {
  if (v === null || v === undefined) return null;
  if (v instanceof KqlTimespan) return v;
  if (typeof v === "string") return parseTimespan(v);
  if (typeof v === "number") return Number.isFinite(v) ? new KqlTimespan(Math.round(v)) : null;
  return null;
}

export function defaultFor(type: KqlType): unknown {
  return type === "string" ? "" : null;
}

/** Converts a raw table cell into the engine's form for its declared type. Tolerant of JSON-shaped inputs. */
export function normalizeCell(v: unknown, type: KqlType): unknown {
  if (v === undefined || v === null) return defaultFor(type);
  switch (type) {
    case "string":
      return typeof v === "string" ? v : toStr(v);
    case "int":
    case "long":
      return typeof v === "number" ? (Number.isFinite(v) ? v : null) : typeof v === "bigint" ? Number(v) : toLongValue(v);
    case "real":
      return typeof v === "number" ? v : toNumber(v);
    case "bool":
      return toBoolValue(v);
    case "datetime":
      return typeof v === "number" ? new Date(v) : toDatetimeValue(v);
    case "timespan":
      if (typeof v === "number") return new KqlTimespan(Math.round(v * TICKS_PER_MS));
      if (typeof v === "object" && v !== null && !(v instanceof KqlTimespan) && typeof (v as { ticks?: unknown }).ticks === "number") {
        return new KqlTimespan((v as { ticks: number }).ticks);
      }
      return toTimespanValue(v);
    case "guid":
      return typeof v === "string" && v !== "" ? v.toLowerCase() : null;
    case "dynamic":
      return toDyn(v);
    default:
      return v;
  }
}

/** Converts a dynamic value to a typed column value, for mv-expand `to typeof()` and common-type widening. */
export function castDyn(v: unknown, type: KqlType): unknown {
  switch (type) {
    case "dynamic":
      return v;
    case "string":
      return toStr(v);
    case "int":
    case "long":
      return typeof v === "number" ? Math.trunc(v) : null;
    case "real":
      return typeof v === "number" ? v : null;
    case "bool":
      return typeof v === "boolean" ? v : null;
    case "datetime":
      return v instanceof Date ? v : typeof v === "string" ? parseDatetime(v) : null;
    case "timespan":
      return v instanceof KqlTimespan ? v : typeof v === "string" ? parseTimespan(v) : null;
    case "guid":
      return typeof v === "string" ? v : null;
  }
}

/** Canonical key for grouping, distinct, in-sets and joins. Equal keys mean equal values, across int, long and real. */
export function keyOf(v: unknown): string {
  if (v === null || v === undefined) return "\u0000null";
  if (typeof v === "string") return `s${v}`;
  if (typeof v === "number") return `n${v}`;
  if (typeof v === "boolean") return v ? "b1" : "b0";
  if (v instanceof Date) return `d${v.getTime()}`;
  if (v instanceof KqlTimespan) return `t${v.ticks}`;
  return `j${dynToJson(v)}`;
}

/** Ordering for values of one type. Never called with null. */
export function compareValues(a: unknown, b: unknown): number {
  if (typeof a === "number" && typeof b === "number") return a < b ? -1 : a > b ? 1 : 0;
  if (typeof a === "string" && typeof b === "string") return a < b ? -1 : a > b ? 1 : 0;
  if (a instanceof Date && b instanceof Date) return a.getTime() - b.getTime();
  if (a instanceof KqlTimespan && b instanceof KqlTimespan) return a.ticks - b.ticks;
  if (typeof a === "boolean" && typeof b === "boolean") return Number(a) - Number(b);
  const x = toStr(a);
  const y = toStr(b);
  return x < y ? -1 : x > y ? 1 : 0;
}

/**
 * Prints a result cell exactly as the Log Analytics results grid does:
 * timespan `00:05:00`, `1.00:00:00`, `00:00:01.5000000`; datetime `11/7/2026, 10:00:00.000 AM` (UTC);
 * dynamic as compact JSON; null as an empty cell.
 */
export function formatKqlValue(value: unknown, type: KqlType): string {
  if (value === null || value === undefined) return "";
  switch (type) {
    case "datetime": {
      const d = value instanceof Date ? value : toDatetimeValue(value);
      return d ? datetimePortal(d) : "";
    }
    case "timespan": {
      const t = value instanceof KqlTimespan ? value : normalizeCell(value, "timespan");
      return t instanceof KqlTimespan ? t.toString() : "";
    }
    case "dynamic":
      return typeof value === "string" ? value : toStr(value);
    default:
      return toStr(value);
  }
}
