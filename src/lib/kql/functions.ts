import { KqlFail, LIMITS, charge, checkString, tooLarge } from "./errors";
import { base64Decode, base64Encode, md5Hex, sha256Hex, utf8Decode, utf8Encode } from "./hash";
import { RegexError, compileRegex, escapeRegex, type Regex } from "./regex";
import type { KqlType } from "./types";
import {
  EPOCH_OFFSET_MS, KqlTimespan, TICKS_PER_DAY, compareValues, keyOf, normalizeCell, toBoolValue,
  toDatetimeValue, toDyn, toLongValue, toNumber, toStr, toTimespanValue,
} from "./values";

/** Argument kinds: s string (anything prints), n number, d datetime, t timespan, y dynamic, b bool, a any. */
export type ParamKind = "s" | "n" | "d" | "t" | "y" | "b" | "a";

export interface FnContext {
  now: Date;
}

export interface ArgInfo {
  type: KqlType;
  constant: boolean;
  value?: unknown;
  typeLit?: KqlType;
}

export interface FnDef {
  params: ParamKind[];
  /** Last parameter repeats up to this many arguments. Defaults to params.length. */
  max?: number;
  min: number;
  ret: KqlType | ((args: ArgInfo[]) => KqlType);
  impl: (a: unknown[], types: KqlType[], ctx: FnContext) => unknown;
  /** Result-column naming, from Kusto.Language. */
  naming?: "first" | "nameFirst" | { prefix: string };
  /** Index of an argument that holds an RE2 pattern, validated when constant. */
  regexArg?: number;
  check?: (args: ArgInfo[], pos: number) => void;
}

export const FUNCTIONS: Record<string, FnDef> = Object.create(null) as Record<string, FnDef>;

function def(names: string | string[], params: ParamKind[], ret: FnDef["ret"], impl: FnDef["impl"], opts: Partial<FnDef> = {}): void {
  for (const name of Array.isArray(names) ? names : [names]) {
    FUNCTIONS[name] = { params, min: params.length, ret, impl, ...opts };
  }
}

const str = (v: unknown) => (typeof v === "string" ? v : toStr(v));

function safeRegex(source: string): Regex | null {
  try {
    return compileRegex(source);
  } catch (e) {
    if (e instanceof RegexError) return null;
    throw e;
  }
}

export function validateRegex(source: string, pos: number): void {
  try {
    compileRegex(source);
  } catch (e) {
    if (e instanceof RegexError) throw new KqlFail(`Invalid regular expression '${source}': ${e.message}`, pos);
    throw e;
  }
}

function codePointLength(s: string): number {
  let n = s.length;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xdc00 && c < 0xe000) n--;
  }
  return n;
}

// Conversions

def("tostring", ["a"], "string", ([v]) => toStr(v), { naming: "first" });
def(["toint"], ["a"], "int", ([v]) => toLongValue(v), { naming: "first" });
def(["tolong"], ["a"], "long", ([v]) => toLongValue(v), { naming: "first" });
def(["toreal", "todouble"], ["a"], "real", ([v]) => toNumber(v), { naming: "first" });
def(["tobool", "toboolean"], ["a"], "bool", ([v]) => toBoolValue(v), { naming: "first" });
def("todatetime", ["a"], "datetime", ([v]) => toDatetimeValue(v), { naming: "first" });
def(["totimespan", "totime"], ["a"], "timespan", ([v]) => toTimespanValue(v), { naming: "first" });
def("toguid", ["a"], "guid", ([v]) => {
  const s = toStr(v);
  return /^[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}$/.test(s) ? s.toLowerCase() : null;
}, { naming: "first" });

function parseJson(v: unknown): unknown {
  if (typeof v !== "string") return toDyn(v);
  charge(1 + (v.length >> 4));
  try {
    return JSON.parse(v);
  } catch {
    return v;
  }
}
def(["todynamic", "toobject", "parse_json", "parsejson"], ["a"], "dynamic", ([v]) => parseJson(v), { naming: "first" });

// Strings

def("tolower", ["s"], "string", ([s]) => str(s).toLowerCase());
def("toupper", ["s"], "string", ([s]) => str(s).toUpperCase());
def("strlen", ["s"], "long", ([s]) => codePointLength(str(s)), { naming: "nameFirst" });

def("substring", ["s", "n", "n"], "string", ([s, start, len]) => {
  const chars = Array.from(str(s));
  if (start === null) return "";
  let from = Math.trunc(start as number);
  if (from < 0) from = Math.max(0, chars.length + from);
  if (from >= chars.length) return "";
  if (len === null || len === undefined) return chars.slice(from).join("");
  const count = Math.trunc(len as number);
  return count <= 0 ? "" : chars.slice(from, from + count).join("");
}, { min: 2 });

def("strcat", ["s"], "string", (a) => {
  let out = "";
  for (const v of a) out += str(v);
  return checkString(out);
}, { min: 1, max: 64 });

def("strcat_delim", ["s", "s"], "string", ([d, ...rest]) => checkString(rest.map(str).join(str(d))), { min: 3, max: 65 });

def("split", ["s", "s", "n"], "dynamic", ([s, d, idx]) => {
  const delim = str(d);
  const parts = delim === "" ? [str(s)] : str(s).split(delim);
  if (idx === null || idx === undefined) return parts;
  const i = Math.trunc(idx as number);
  return i >= 0 && i < parts.length ? [parts[i]] : [];
}, { min: 2, naming: "first" });

function stripRegex(source: string, text: string, start: boolean, end: boolean): string {
  const head = start ? safeRegex(`^(?:${source})+`) : null;
  const tail = end ? safeRegex(`(?:${source})+$`) : null;
  let out = text;
  if (head) {
    const m = head.exec(out);
    if (m) out = out.slice(m[1]);
  }
  if (tail) {
    const m = tail.exec(out);
    if (m) out = out.slice(0, m[0]);
  }
  return out;
}
def("trim", ["s", "s"], "string", ([r, s]) => stripRegex(str(r), str(s), true, true), { regexArg: 0 });
def("trim_start", ["s", "s"], "string", ([r, s]) => stripRegex(str(r), str(s), true, false), { regexArg: 0 });
def("trim_end", ["s", "s"], "string", ([r, s]) => stripRegex(str(r), str(s), false, true), { regexArg: 0 });

def("replace_string", ["s", "s", "s"], "string", ([t, l, r]) => {
  const lookup = str(l);
  return lookup === "" ? str(t) : checkString(str(t).split(lookup).join(str(r)));
});

function expandRewrite(rewrite: string, text: string, caps: number[]): string {
  let out = "";
  for (let i = 0; i < rewrite.length; i++) {
    const c = rewrite[i];
    if (c === "\\" && i + 1 < rewrite.length) {
      const d = rewrite.charCodeAt(i + 1) - 48;
      if (d >= 0 && d <= 9) {
        if (caps[d * 2] !== undefined && caps[d * 2] >= 0) out += text.slice(caps[d * 2], caps[d * 2 + 1]);
        i++;
        continue;
      }
      if (rewrite[i + 1] === "\\") {
        out += "\\";
        i++;
        continue;
      }
    }
    out += c;
  }
  return out;
}

def("replace_regex", ["s", "s", "s"], "string", ([src, re, rw]) => {
  const text = str(src);
  const rx = safeRegex(str(re));
  if (!rx) return text;
  const rewrite = str(rw);
  let out = "";
  let pos = 0;
  let last = 0;
  while (pos <= text.length) {
    const m = rx.exec(text, pos);
    if (!m) break;
    out += text.slice(last, m[0]) + expandRewrite(rewrite, text, m);
    checkString(out);
    last = m[1];
    pos = m[1] > m[0] ? m[1] : m[1] + 1;
  }
  return out + text.slice(last);
}, { regexArg: 1 });

def("extract", ["s", "n", "s", "a"], (args) => args[3]?.typeLit ?? "string", ([re, g, src, t]) => {
  const rx = safeRegex(str(re));
  const type = (t ?? "string") as KqlType;
  const miss = type === "string" ? "" : null;
  if (!rx || g === null) return miss;
  const text = str(src);
  const m = rx.exec(text);
  if (!m) return miss;
  const group = Math.trunc(g as number);
  if (group < 0 || group > rx.groupCount || m[group * 2] < 0) return miss;
  const cap = text.slice(m[group * 2], m[group * 2 + 1]);
  return type === "string" ? cap : normalizeCell(cap, type);
}, { min: 3, regexArg: 0 });

def("extract_all", ["s", "a", "a"], "dynamic", (a) => {
  const rx = safeRegex(str(a[0]));
  if (!rx) return null;
  const text = str(a.length === 3 ? a[2] : a[1]);
  const wanted: number[] = [];
  if (a.length === 3 && Array.isArray(a[1])) for (const g of a[1]) wanted.push(Math.trunc(Number(g)));
  else for (let g = 1; g <= rx.groupCount; g++) wanted.push(g);
  if (wanted.length === 0) wanted.push(0);
  const out: unknown[] = [];
  let pos = 0;
  while (pos <= text.length) {
    const m = rx.exec(text, pos);
    if (!m) break;
    const values = wanted.map((g) => (m[g * 2] !== undefined && m[g * 2] >= 0 ? text.slice(m[g * 2], m[g * 2 + 1]) : ""));
    out.push(values.length === 1 ? values[0] : values);
    pos = m[1] > m[0] ? m[1] : m[1] + 1;
  }
  return out.length === 0 ? null : out;
}, { min: 2, regexArg: 0 });

def("indexof", ["s", "s", "n", "n", "n"], "long", ([s, m, st, ln, oc]) => {
  const text = str(s);
  const needle = str(m);
  let start = st === undefined ? 0 : st === null ? null : Math.trunc(st as number);
  const length = ln === undefined ? -1 : ln === null ? null : Math.trunc(ln as number);
  const occurrence = oc === undefined ? 1 : oc === null ? null : Math.trunc(oc as number);
  if (start === null || length === null || occurrence === null) return null;
  if (length < -1 || occurrence < 0) return null;
  if (start < 0) start = Math.max(0, text.length + start);
  // The length window restarts after each occurrence, which is what the documented table shows.
  let at = start;
  for (let n = 0; n < occurrence; n++) {
    const from = n === 0 ? at : at + 1;
    const hit = text.indexOf(needle, from);
    const end = length === -1 ? text.length : Math.min(text.length, from + length);
    if (hit < 0 || hit + needle.length > end) return -1;
    at = hit;
  }
  return occurrence === 0 ? -1 : at;
}, { min: 2 });

def("countof", ["s", "s", "s"], "long", ([s, q, k]) => {
  const text = str(s);
  const needle = str(q);
  if (needle === "") return 0;
  if (k === "regex") {
    const rx = safeRegex(needle);
    if (!rx) return null;
    let n = 0;
    let pos = 0;
    while (pos <= text.length) {
      const m = rx.exec(text, pos);
      if (!m) break;
      n++;
      pos = m[1] > m[0] ? m[1] : m[1] + 1;
    }
    return n;
  }
  let n = 0;
  for (let i = text.indexOf(needle); i >= 0; i = text.indexOf(needle, i + 1)) {
    charge(1 + (needle.length >> 4));
    n++;
  }
  return n;
}, { min: 2 });

def("reverse", ["s"], "string", ([s]) => Array.from(str(s)).reverse().join(""), { naming: "first" });
def("strcmp", ["s", "s"], "long", ([a, b]) => compareValues(str(a), str(b)));
def("strrep", ["s", "n", "s"], "string", ([s, n, d]) => {
  const count = Math.trunc((n as number) ?? 0);
  const text = str(s);
  if (count <= 0) return "";
  if ((text.length + str(d ?? "").length) * count > LIMITS.maxStringLength) throw tooLarge();
  return new Array(count).fill(text).join(d === undefined ? "" : str(d));
}, { min: 2 });

def("base64_encode_tostring", ["s"], "string", ([s]) => base64Encode(utf8Encode(str(s))));
def("base64_decode_tostring", ["s"], "string", ([s]) => {
  const bytes = base64Decode(str(s).trim());
  return bytes ? utf8Decode(bytes) : "";
});
def("url_decode", ["s"], "string", ([s]) => {
  try {
    return decodeURIComponent(str(s));
  } catch {
    return "";
  }
});
def("hash_md5", ["s"], "string", ([s]) => md5Hex(utf8Encode(str(s))));
def("hash_sha256", ["s"], "string", ([s]) => sha256Hex(utf8Encode(str(s))));

/** Cuts `text` at the first `mark`: what comes before, and what comes after or "". */
function cut(text: string, mark: string): [string, string] {
  const at = text.indexOf(mark);
  return at < 0 ? [text, ""] : [text.slice(0, at), text.slice(at + 1)];
}

/** Hand-written rather than a regex, so a hostile URL string stays linear. */
function parseUrl(text: string): Record<string, unknown> {
  const url = { Scheme: "", Host: "", Port: "", Path: "", Username: "", Password: "", "Query Parameters": {} as Record<string, string>, Fragment: "" };
  const schemeEnd = text.indexOf("://");
  if (schemeEnd <= 0 || !/^[a-zA-Z][a-zA-Z0-9+.-]*$/.test(text.slice(0, schemeEnd))) return url;
  url.Scheme = text.slice(0, schemeEnd);
  const [beforeFragment, fragment] = cut(text.slice(schemeEnd + 3), "#");
  const [beforeQuery, query] = cut(beforeFragment, "?");
  const [authority, path] = cut(beforeQuery, "/");
  url.Fragment = fragment;
  url.Path = path;
  const at = authority.lastIndexOf("@");
  const hostPart = at < 0 ? authority : authority.slice(at + 1);
  if (at >= 0) [url.Username, url.Password] = cut(authority.slice(0, at), ":");
  const colon = hostPart.lastIndexOf(":");
  const hasPort = colon >= 0 && colon < hostPart.length - 1 && /^[0-9]+$/.test(hostPart.slice(colon + 1));
  url.Host = hasPort ? hostPart.slice(0, colon) : hostPart;
  url.Port = hasPort ? hostPart.slice(colon + 1) : "";
  if (query) {
    for (const part of query.split("&")) {
      const [key, value] = cut(part, "=");
      if (key) Object.defineProperty(url["Query Parameters"], key, { value, enumerable: true, writable: true, configurable: true });
    }
  }
  return url;
}

def("parse_url", ["s"], "dynamic", ([s]) => parseUrl(str(s)));

function ipv4ToLong(text: string): { value: number; prefix: number } | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/.exec(text.trim());
  if (!m) return null;
  const octets = [m[1], m[2], m[3], m[4]].map(Number);
  if (octets.some((o) => o > 255)) return null;
  const prefix = m[5] === undefined ? 32 : Number(m[5]);
  if (prefix > 32) return null;
  return { value: octets[0] * 16777216 + octets[1] * 65536 + octets[2] * 256 + octets[3], prefix };
}

function maskIp(value: number, prefix: number): number {
  const block = 2 ** (32 - prefix);
  return Math.floor(value / block) * block;
}

def("parse_ipv4", ["s"], "long", ([s]) => {
  const ip = ipv4ToLong(str(s));
  return ip ? maskIp(ip.value, ip.prefix) : null;
});
def("ipv4_is_private", ["s"], "bool", ([s]) => {
  const ip = ipv4ToLong(str(s));
  if (!ip) return null;
  const inNet = (base: string, bits: number) => maskIp(ip.value, bits) === (ipv4ToLong(base) as { value: number }).value;
  return inNet("10.0.0.0", 8) || inNet("172.16.0.0", 12) || inNet("192.168.0.0", 16);
});
def("ipv4_is_in_range", ["s", "s"], "bool", ([a, b]) => {
  const ip = ipv4ToLong(str(a));
  const range = ipv4ToLong(str(b));
  if (!ip || !range) return null;
  return maskIp(ip.value, range.prefix) === maskIp(range.value, range.prefix);
});

// Null and empty

def("isnull", ["a"], "bool", ([v]) => v === null || v === undefined);
def("isnotnull", ["a"], "bool", ([v]) => v !== null && v !== undefined);
def("isempty", ["a"], "bool", ([v]) => v === null || v === undefined || v === "");
def("isnotempty", ["a"], "bool", ([v]) => !(v === null || v === undefined || v === ""));

// Math

function numericResult(args: ArgInfo[]): KqlType {
  return args[0].type === "int" ? "long" : args[0].type === "dynamic" ? "real" : args[0].type;
}

function binValue(v: unknown, size: unknown): unknown {
  if (v === null || v === undefined || size === null || size === undefined) return null;
  if (v instanceof Date) {
    const ms = size instanceof KqlTimespan ? size.ms : null;
    if (ms === null || ms <= 0) return null;
    const origin = v.getTime() + EPOCH_OFFSET_MS;
    return new Date(Math.floor(origin / ms) * ms - EPOCH_OFFSET_MS);
  }
  if (v instanceof KqlTimespan) {
    const ticks = size instanceof KqlTimespan ? size.ticks : typeof size === "number" ? size * TICKS_PER_DAY : 0;
    return ticks > 0 ? new KqlTimespan(Math.floor(v.ticks / ticks) * ticks) : null;
  }
  const n = toNumber(v);
  const s = toNumber(size);
  if (n === null || s === null || s <= 0) return null;
  return Math.floor(n / s) * s;
}

function binType(args: ArgInfo[]): KqlType {
  const [v, s] = args;
  if (v.type === "datetime" || v.type === "timespan") return v.type;
  return v.type === "real" || s.type === "real" ? "real" : "long";
}

function checkBin(args: ArgInfo[], pos: number): void {
  const [v, s] = args;
  const ok = v.type === "datetime" ? s.type === "timespan"
    : v.type === "timespan" ? s.type === "timespan" || isNumeric(s.type)
      : (isNumeric(v.type) || v.type === "dynamic") && (isNumeric(s.type) || s.type === "dynamic");
  if (!ok) throw new KqlFail(`The function 'bin' is not compatible with arguments (${v.type}, ${s.type})`, pos);
}

function isNumeric(t: KqlType): boolean {
  return t === "int" || t === "long" || t === "real";
}

def(["bin", "floor"], ["a", "a"], binType, ([v, s]) => binValue(v, s), { naming: "first", check: checkBin });

def("ceiling", ["n"], numericResult, ([v]) => (v === null ? null : Math.ceil(v as number)), { naming: "first" });

def("round", ["n", "n"], (args) => (args[0].type === "dynamic" ? "real" : args[0].type), ([v, p]) => {
  if (v === null) return null;
  const digits = p === undefined || p === null ? 0 : Math.trunc(p as number);
  const n = v as number;
  const scale = 10 ** Math.abs(digits);
  const magnitude = Math.round(digits >= 0 ? Math.abs(n) * scale : Math.abs(n) / scale);
  return Math.sign(n) * (digits >= 0 ? magnitude / scale : magnitude * scale);
}, { min: 1, naming: "first" });

def("abs", ["a"], (args) => (args[0].type === "int" ? "long" : args[0].type === "dynamic" ? "real" : args[0].type), ([v]) => {
  if (v instanceof KqlTimespan) return new KqlTimespan(Math.abs(v.ticks));
  const n = toNumber(v);
  return n === null ? null : Math.abs(n);
}, {
  naming: "first",
  check: (args, pos) => {
    const t = args[0].type;
    if (!isNumeric(t) && t !== "timespan" && t !== "dynamic") throw new KqlFail(`The function 'abs' is not compatible with arguments (${t})`, pos);
  },
});

const positiveOrNull = (fn: (n: number) => number) => ([v]: unknown[]) => {
  const n = v as number | null;
  return n === null || n < 0 ? null : fn(n);
};
def("log10", ["n"], "real", positiveOrNull(Math.log10), { naming: "first" });
def("log", ["n"], "real", positiveOrNull(Math.log), { naming: "first" });
def("sqrt", ["n"], "real", positiveOrNull(Math.sqrt), { naming: "first" });
def("exp", ["n"], "real", ([v]) => (v === null ? null : Math.exp(v as number)), { naming: "first" });
def("pow", ["n", "n"], "real", ([a, b]) => (a === null || b === null ? null : (a as number) ** (b as number)), { naming: "first" });
def("isnan", ["n"], "bool", ([v]) => v !== null && Number.isNaN(v));
def("isinf", ["n"], "bool", ([v]) => v === Infinity || v === -Infinity);
def("isfinite", ["n"], "bool", ([v]) => v !== null && Number.isFinite(v));
def("sign", ["n"], (args) => numericResult(args), ([v]) => (v === null ? null : Math.sign(v as number)));

// Datetime

const DAY_MS = 86_400_000;

def("now", ["t"], "datetime", ([o], _t, ctx) => {
  const t = ctx.now.getTime();
  return new Date(o instanceof KqlTimespan ? t + o.ms : t);
}, { min: 0 });
def("ago", ["t"], "datetime", ([o], _t, ctx) => (o instanceof KqlTimespan ? new Date(ctx.now.getTime() - o.ms) : null));

const offsetDay = (d: Date, offset: unknown) => new Date(Math.floor(d.getTime() / DAY_MS) * DAY_MS + ((offset as number | null) ?? 0) * DAY_MS);
const startOfWeekMs = (d: Date) => {
  const day = Math.floor(d.getTime() / DAY_MS);
  return (day - ((day + 4) % 7 + 7) % 7) * DAY_MS;
};
function monthStart(d: Date, addMonths: number): Date {
  const out = new Date(0);
  out.setUTCFullYear(d.getUTCFullYear(), d.getUTCMonth() + addMonths, 1);
  return out;
}
function yearStart(d: Date, addYears: number): Date {
  const out = new Date(0);
  out.setUTCFullYear(d.getUTCFullYear() + addYears, 0, 1);
  return out;
}

const withDate = (fn: (d: Date, off: number) => Date) => ([d, o]: unknown[]) => (d === null ? null : fn(d as Date, (o as number | null | undefined) ?? 0));

def("startofday", ["d", "n"], "datetime", withDate((d, o) => offsetDay(d, o)), { min: 1, naming: "first" });
def("endofday", ["d", "n"], "datetime", withDate((d, o) => new Date(offsetDay(d, o + 1).getTime() - 1)), { min: 1 });
def("startofhour", ["d", "n"], "datetime", withDate((d, o) => new Date((Math.floor(d.getTime() / 3_600_000) + o) * 3_600_000)), { min: 1, naming: "first" });
def("endofhour", ["d", "n"], "datetime", withDate((d, o) => new Date((Math.floor(d.getTime() / 3_600_000) + o + 1) * 3_600_000 - 1)), { min: 1 });
def("startofweek", ["d", "n"], "datetime", withDate((d, o) => new Date(startOfWeekMs(d) + o * 7 * DAY_MS)), { min: 1, naming: "first" });
def("endofweek", ["d", "n"], "datetime", withDate((d, o) => new Date(startOfWeekMs(d) + (o + 1) * 7 * DAY_MS - 1)), { min: 1 });
def("startofmonth", ["d", "n"], "datetime", withDate((d, o) => monthStart(d, o)), { min: 1, naming: "first" });
def("endofmonth", ["d", "n"], "datetime", withDate((d, o) => new Date(monthStart(d, o + 1).getTime() - 1)), { min: 1 });
def("startofyear", ["d", "n"], "datetime", withDate((d, o) => yearStart(d, o)), { min: 1, naming: "first" });
def("endofyear", ["d", "n"], "datetime", withDate((d, o) => new Date(yearStart(d, o + 1).getTime() - 1)), { min: 1 });

def("dayofweek", ["d"], "timespan", ([d]) => {
  if (d === null) return null;
  const day = Math.floor((d as Date).getTime() / DAY_MS);
  return new KqlTimespan((((day + 4) % 7 + 7) % 7) * TICKS_PER_DAY);
});
def("hourofday", ["d"], "int", ([d]) => (d === null ? null : (d as Date).getUTCHours()));
def("dayofmonth", ["d"], "int", ([d]) => (d === null ? null : (d as Date).getUTCDate()));
def("dayofyear", ["d"], "int", ([d]) => (d === null ? null : Math.floor(((d as Date).getTime() - yearStart(d as Date, 0).getTime()) / DAY_MS) + 1));
def(["getmonth", "monthofyear"], ["d"], "int", ([d]) => (d === null ? null : (d as Date).getUTCMonth() + 1));
def("getyear", ["d"], "int", ([d]) => (d === null ? null : (d as Date).getUTCFullYear()));

const PERIOD_MS: Record<string, number> = {
  day: DAY_MS, days: DAY_MS, d: DAY_MS, hour: 3_600_000, hours: 3_600_000, h: 3_600_000,
  minute: 60_000, minutes: 60_000, m: 60_000, second: 1000, seconds: 1000, s: 1000,
  millisecond: 1, milliseconds: 1, ms: 1,
};

function checkPeriod(args: ArgInfo[], pos: number): void {
  const a = args[0];
  if (!a.constant || typeof a.value !== "string") return;
  if (normalizePeriod(a.value) === null) throw new KqlFail(`'${a.value}' is not a valid datetime part.`, pos);
}

function normalizePeriod(p: string): string | null {
  const s = p.toLowerCase();
  if (Object.prototype.hasOwnProperty.call(PERIOD_MS, s)) return s;
  for (const known of ["year", "quarter", "month", "week", "microsecond", "nanosecond"]) {
    if (s === known || s === `${known}s`) return known;
  }
  return null;
}

def("datetime_diff", ["s", "d", "d"], "long", ([p, a, b]) => {
  if (a === null || b === null) return null;
  const x = a as Date;
  const y = b as Date;
  const period = normalizePeriod(str(p));
  if (period === null) return null;
  const months = (d: Date) => d.getUTCFullYear() * 12 + d.getUTCMonth();
  switch (period) {
    case "year": return x.getUTCFullYear() - y.getUTCFullYear();
    case "quarter": return Math.floor(months(x) / 3) - Math.floor(months(y) / 3);
    case "month": return months(x) - months(y);
    case "week": return Math.round((startOfWeekMs(x) - startOfWeekMs(y)) / (7 * DAY_MS));
    case "microsecond": return (x.getTime() - y.getTime()) * 1000;
    case "nanosecond": return (x.getTime() - y.getTime()) * 1_000_000;
    default: {
      const unit = PERIOD_MS[period];
      return Math.floor(x.getTime() / unit) - Math.floor(y.getTime() / unit);
    }
  }
}, { check: checkPeriod });

def("datetime_add", ["s", "n", "d"], "datetime", ([p, n, d]) => {
  if (n === null || d === null) return null;
  const date = d as Date;
  const amount = Math.trunc(n as number);
  const period = normalizePeriod(str(p));
  if (period === null) return null;
  const addMonths = (count: number) => {
    const first = monthStart(date, count);
    const lastDay = new Date(monthStart(date, count + 1).getTime() - DAY_MS).getUTCDate();
    return new Date(first.getTime() + (Math.min(date.getUTCDate(), lastDay) - 1) * DAY_MS + (date.getTime() - Math.floor(date.getTime() / DAY_MS) * DAY_MS));
  };
  switch (period) {
    case "year": return addMonths(amount * 12);
    case "quarter": return addMonths(amount * 3);
    case "month": return addMonths(amount);
    case "week": return new Date(date.getTime() + amount * 7 * DAY_MS);
    case "microsecond": return new Date(date.getTime() + amount / 1000);
    case "nanosecond": return new Date(date.getTime() + amount / 1_000_000);
    default: return new Date(date.getTime() + amount * PERIOD_MS[period]);
  }
}, { check: checkPeriod });

/** Splits a format string into runs of one specifier letter. */
function eachRun(format: string, emit: (run: string) => void): void {
  let i = 0;
  while (i < format.length) {
    let j = i + 1;
    while (j < format.length && format[j] === format[i]) j++;
    emit(format.slice(i, j));
    i = j;
  }
}

function fraction(run: string, sevenDigits: string): string {
  const digits = sevenDigits.slice(0, run.length);
  return run[0] === "f" ? digits : digits.replace(/0+$/, "");
}

const pad = (n: number, width: number) => String(n).padStart(width, "0");

def("format_datetime", ["d", "s"], "string", ([d, f]) => {
  if (d === null) return "";
  const date = d as Date;
  const seven = `${pad(date.getUTCMilliseconds(), 3)}0000`;
  const hour12 = date.getUTCHours() % 12 === 0 ? 12 : date.getUTCHours() % 12;
  let out = "";
  eachRun(str(f), (run) => {
    switch (run[0]) {
      case "y": out += run.length >= 4 ? pad(date.getUTCFullYear(), 4) : run.length === 2 ? pad(date.getUTCFullYear() % 100, 2) : String(date.getUTCFullYear() % 100); break;
      case "M": out += pad(date.getUTCMonth() + 1, run.length > 1 ? 2 : 1); break;
      case "d": out += pad(date.getUTCDate(), run.length > 1 ? 2 : 1); break;
      case "h": out += pad(hour12, run.length > 1 ? 2 : 1); break;
      case "H": out += pad(date.getUTCHours(), run.length > 1 ? 2 : 1); break;
      case "m": out += pad(date.getUTCMinutes(), run.length > 1 ? 2 : 1); break;
      case "s": out += pad(date.getUTCSeconds(), run.length > 1 ? 2 : 1); break;
      case "f":
      case "F": out += fraction(run, seven); break;
      case "t": out += date.getUTCHours() < 12 ? "AM" : "PM"; break;
      default: out += run;
    }
  });
  return out;
}, { naming: "first" });

def("format_timespan", ["t", "s"], "string", ([t, f]) => {
  if (t === null) return "";
  const total = Math.abs((t as KqlTimespan).ticks);
  const days = Math.floor(total / TICKS_PER_DAY);
  const inDay = total - days * TICKS_PER_DAY;
  const seconds = Math.floor(inDay / 10_000_000);
  const seven = pad(inDay - seconds * 10_000_000, 7);
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor(seconds / 60) % 60;
  let out = "";
  eachRun(str(f), (run) => {
    switch (run[0]) {
      case "d": out += pad(days, run.length); break;
      case "h":
      case "H": out += pad(hours, run.length > 1 ? 2 : 1); break;
      case "m": out += pad(minutes, run.length > 1 ? 2 : 1); break;
      case "s": out += pad(seconds % 60, run.length > 1 ? 2 : 1); break;
      case "f":
      case "F": out += fraction(run, seven); break;
      default: out += run;
    }
  });
  return out;
}, { naming: "first" });

// Dynamic

def("array_length", ["y"], "long", ([a]) => (Array.isArray(a) ? a.length : null));

def("array_sort_asc", ["y", "b"], "dynamic", ([a, nullsLast]) => {
  if (!Array.isArray(a)) return null;
  const present = a.filter((v) => v !== null && v !== undefined);
  const nulls = a.length - present.length;
  charge(a.length);
  present.sort(compareValues);
  const blanks = new Array<null>(nulls).fill(null);
  return nullsLast === false ? [...blanks, ...present] : [...present, ...blanks];
}, { min: 1 });

def("array_concat", ["y"], "dynamic", (a) => {
  const out: unknown[] = [];
  for (const arr of a) {
    if (!Array.isArray(arr)) return null;
    if (out.length + arr.length > LIMITS.maxArrayLength) throw tooLarge();
    charge(arr.length);
    out.push(...arr);
  }
  return out;
}, { min: 1, max: 64 });

def("bag_keys", ["y"], "dynamic", ([b]) => (b !== null && typeof b === "object" && !Array.isArray(b) ? Object.keys(b) : null));

def(["pack", "bag_pack"], ["a"], "dynamic", (a) => {
  const out: Record<string, unknown> = {};
  for (let i = 0; i + 1 < a.length; i += 2) {
    Object.defineProperty(out, str(a[i]), { value: toDyn(a[i + 1]), enumerable: true, writable: true, configurable: true });
  }
  return out;
}, {
  min: 2, max: 128,
  check: (args, pos) => {
    if (args.length % 2 !== 0) throw new KqlFail("The function 'pack' expects an even number of arguments: key, value, key, value.", pos);
  },
});

def("pack_array", ["a"], "dynamic", (a) => a.map(toDyn), { min: 1, max: 1024 });

def("set_has_element", ["y", "a"], "bool", ([s, v]) => {
  if (!Array.isArray(s)) return null;
  const key = keyOf(toDyn(v));
  charge(s.length);
  return s.some((x) => keyOf(x) === key);
});

function dynamicTypeName(v: unknown): string {
  if (v === null || v === undefined) return "null";
  if (Array.isArray(v)) return "array";
  if (typeof v === "string") return "string";
  if (typeof v === "boolean") return "bool";
  if (typeof v === "number") return !Number.isInteger(v) ? "real" : Math.abs(v) <= 2147483647 ? "int" : "long";
  return "dictionary";
}

def("gettype", ["a"], "string", ([v], types) => (types[0] === "dynamic" ? dynamicTypeName(v) : types[0]), { naming: { prefix: "type" } });

/** Kept with the function table because search wildcards share the escape rules. */
export function wildcardRegex(term: string): string {
  return `\\b${term.split("*").map(escapeRegex).join(".*")}\\b`;
}
