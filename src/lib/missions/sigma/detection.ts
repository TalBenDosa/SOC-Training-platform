/**
 * Sigma detection semantics: search identifiers, value modifiers and the condition
 * expression. Matching is pure and synchronous. Learner regexes (`|re`) run on the
 * linear Pike VM in src/lib/kql/regex.ts; wildcards use an iterative glob matcher
 * whose worst case is O(value * pattern), never exponential.
 */
import { compileRegex, RegexError, type Regex } from "@/lib/kql/regex";
import { didYouMean, KqlLimitFail, resetBudget } from "@/lib/kql/errors";
import { YamlError, type YMap, type YNode, type YScalar } from "./yamlLite";

export type SigmaEvent = Record<string, unknown>;
type Test = (ev: SigmaEvent) => boolean;
type ValueTest = (v: unknown) => boolean;

export interface SigmaSearch {
  id: string;
  line: number;
  test: Test;
}

export type SigmaCondition =
  | { k: "id"; id: string }
  | { k: "of"; quant: "1" | "all"; ids: string[] }
  | { k: "not"; e: SigmaCondition }
  | { k: "and" | "or"; l: SigmaCondition; r: SigmaCondition };

/** Sigma's windash set: hyphen, slash, en dash, em dash, horizontal bar (as in pySigma). */
const WINDASH_CHARS = ["-", "/", String.fromCharCode(0x2013), String.fromCharCode(0x2014), String.fromCharCode(0x2015)];
const MAX_WINDASH_POSITIONS = 4;

const SUPPORTED = ["contains", "startswith", "endswith", "all", "re", "i", "m", "s", "cased", "windash", "cidr", "exists", "gt", "gte", "lt", "lte", "base64", "base64offset"];
const KNOWN_UNSUPPORTED = ["expand", "fieldref", "wide", "utf16", "utf16le", "utf16be", "neq", "minute", "hour", "day", "week", "month", "year"];

function fail(message: string, line: number): never {
  throw new YamlError(message, line);
}

// ---- field lookup ----------------------------------------------------------

const MISSING = Symbol("missing");

function lookupKey(obj: Record<string, unknown>, key: string): unknown {
  if (Object.prototype.hasOwnProperty.call(obj, key)) return obj[key];
  const lower = key.toLowerCase();
  for (const k of Object.keys(obj)) if (k.toLowerCase() === lower) return obj[k];
  return MISSING;
}

/** Exact key first, then a case-insensitive key, then a dotted path into nested objects. */
export function getField(ev: SigmaEvent, field: string): unknown {
  const direct = lookupKey(ev, field);
  if (direct !== MISSING || !field.includes(".")) return direct;
  let cur: unknown = ev;
  for (const part of field.split(".")) {
    if (cur === null || typeof cur !== "object" || Array.isArray(cur)) return MISSING;
    cur = lookupKey(cur as Record<string, unknown>, part);
    if (cur === MISSING) return MISSING;
  }
  return cur;
}

/** Every scalar value in the event, for keyword searches. Bounded depth and count. */
function allValues(ev: unknown, out: unknown[] = [], depth = 0): unknown[] {
  if (depth > 8 || out.length > 5000) return out;
  if (Array.isArray(ev)) for (const x of ev) allValues(x, out, depth + 1);
  else if (ev !== null && typeof ev === "object") for (const x of Object.values(ev)) allValues(x, out, depth + 1);
  else out.push(ev);
  return out;
}

const asText = (v: unknown): string | null => (typeof v === "string" ? v : typeof v === "number" || typeof v === "boolean" ? String(v) : null);

/** Arrays in events (e.g. lists of IPs) match when any element matches. */
const anyElement = (v: unknown, t: ValueTest): boolean => (Array.isArray(v) ? v.some((x) => t(x)) : t(v));

// ---- wildcard patterns -------------------------------------------------------

type GlobTok = { t: "lit"; c: string } | { t: "star" } | { t: "one" };

/** pySigma escaping: `\*`, `\?` and `\\` are literals; any other backslash is itself. */
function parseWildcards(s: string): GlobTok[] {
  const out: GlobTok[] = [];
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === "\\") {
      const n = s[i + 1];
      if (n === "*" || n === "?" || n === "\\") {
        out.push({ t: "lit", c: n });
        i++;
      } else out.push({ t: "lit", c: "\\" });
    } else if (c === "*") {
      if (out[out.length - 1]?.t !== "star") out.push({ t: "star" });
    } else if (c === "?") out.push({ t: "one" });
    else out.push({ t: "lit", c });
  }
  return out;
}

const literal = (s: string): GlobTok[] => Array.from(s, (c) => ({ t: "lit", c }) as GlobTok);

/** Iterative glob match with single-star backtracking: O(n * m) worst case. */
function globMatch(p: GlobTok[], s: string, cased: boolean): boolean {
  const text = cased ? s : s.toLowerCase();
  const pat = cased ? p : p.map((t) => (t.t === "lit" ? { t: "lit" as const, c: t.c.toLowerCase() } : t));
  let i = 0;
  let j = 0;
  let star = -1;
  let mark = 0;
  while (i < text.length) {
    const t = pat[j];
    if (t && (t.t === "one" || (t.t === "lit" && t.c === text[i]))) {
      i++;
      j++;
    } else if (t && t.t === "star") {
      star = j++;
      mark = i;
    } else if (star >= 0) {
      j = star + 1;
      i = ++mark;
    } else return false;
  }
  while (pat[j]?.t === "star") j++;
  return j === pat.length;
}

// ---- value transforms ---------------------------------------------------------

function windashVariants(s: string, line: number): string[] {
  const isWord = (c: string | undefined) => c !== undefined && /[A-Za-z0-9_]/.test(c);
  // pySigma uses \B[-/]\b: a dash or slash not preceded by a word char and followed by one.
  const positions: number[] = [];
  for (let k = 0; k < s.length; k++) {
    if ((s[k] === "-" || s[k] === "/") && !isWord(s[k - 1]) && isWord(s[k + 1])) positions.push(k);
  }
  if (positions.length > MAX_WINDASH_POSITIONS) fail(`windash value '${s}' has too many switches (max ${MAX_WINDASH_POSITIONS})`, line);
  let variants = [s];
  for (const pos of positions) {
    const next: string[] = [];
    for (const v of variants) for (const d of WINDASH_CHARS) next.push(v.slice(0, pos) + d + v.slice(pos + 1));
    variants = next;
  }
  return variants;
}

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

function base64(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
    out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63];
    out += i + 1 < bytes.length ? B64[(n >> 6) & 63] : "=";
    out += i + 2 < bytes.length ? B64[n & 63] : "=";
  }
  return out;
}

/** The three shifted encodings pySigma's base64offset produces, so "contains" finds the value at any alignment. */
function base64Offsets(s: string): string[] {
  const value = new TextEncoder().encode(s);
  const startOffsets = [0, 2, 3];
  const endOffsets = [0, -3, -2];
  const out: string[] = [];
  for (let i = 0; i < 3; i++) {
    const padded = new Uint8Array(i + value.length);
    padded.fill(0x20, 0, i);
    padded.set(value, i);
    const enc = base64(padded);
    const end = endOffsets[(value.length + i) % 3];
    out.push(enc.slice(startOffsets[i], end === 0 ? undefined : enc.length + end));
  }
  return out;
}

function parseCidr(s: string, line: number): { base: number; mask: number } {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/.exec(s.trim());
  if (!m) {
    if (s.includes(":")) fail(`'${s}': only IPv4 CIDR ranges are supported in this console`, line);
    fail(`'${s}' is not a valid CIDR range like 10.0.0.0/8`, line);
  }
  const octets = m!.slice(1, 5).map(Number);
  const bits = Number(m![5]);
  if (octets.some((o) => o > 255) || bits > 32) fail(`'${s}' is not a valid CIDR range`, line);
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  const base = ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
  return { base: (base & mask) >>> 0, mask };
}

function ipv4(v: unknown): number | null {
  const s = asText(v);
  const m = s === null ? null : /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s.trim());
  if (!m) return null;
  const o = m.slice(1, 5).map(Number);
  if (o.some((x) => x > 255)) return null;
  return ((o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]) >>> 0;
}

function toNumber(v: unknown): number | null {
  if (typeof v === "number") return Number.isFinite(v) ? v : null;
  if (typeof v === "string" && /^\s*[-+]?(\d+\.?\d*|\.\d+)\s*$/.test(v)) return Number(v);
  return null;
}

function regexTest(re: Regex, s: string): boolean {
  try {
    return re.test(s);
  } catch (e) {
    if (e instanceof KqlLimitFail) return false;
    throw e;
  }
}

// ---- field items ------------------------------------------------------------------

interface CompiledItem {
  test: Test;
  /** Plain string values, used for the IOC-literal warning. */
  literals: string[];
}

/** Compiles one `Field|mod|mod: value(s)` item. A null field means "any value in the event". */
function compileItem(rawKey: string, node: YNode, line: number): CompiledItem {
  const [field, ...mods] = rawKey.split("|");
  const seen = new Set<string>();
  for (const m of mods) {
    if (m === "") fail(`empty modifier in '${rawKey}'`, line);
    if (KNOWN_UNSUPPORTED.includes(m)) fail(`modifier '${m}' is not supported in this console`, line);
    if (!SUPPORTED.includes(m)) fail(`Unknown modifier '${m}'.${didYouMean(m, SUPPORTED)}`.replace(/\.$/, ""), line);
    if (seen.has(m)) fail(`modifier '${m}' is used twice in '${rawKey}'`, line);
    seen.add(m);
  }
  const has = (m: string) => seen.has(m);
  const position = ["contains", "startswith", "endswith"].filter(has);
  if (position.length > 1) fail(`'${rawKey}': contains, startswith and endswith cannot be combined`, line);
  const standalone = ["re", "cidr", "exists", "gt", "gte", "lt", "lte"].filter(has);
  if (standalone.length > 1) fail(`'${rawKey}': ${standalone.join(" and ")} cannot be combined`, line);
  if (standalone.length && (position.length || has("windash") || has("base64") || has("base64offset"))) {
    fail(`'${rawKey}': ${standalone[0]} cannot be combined with ${[...position, "windash", "base64", "base64offset"].filter(has).join(", ")}`, line);
  }
  if ((has("i") || has("m") || has("s")) && !has("re")) fail(`'${rawKey}': the i, m and s flags only work together with re`, line);
  if (has("base64") && has("base64offset")) fail(`'${rawKey}': use either base64 or base64offset`, line);
  if ((has("base64") || has("base64offset")) && has("windash")) fail(`'${rawKey}': windash cannot be combined with base64`, line);

  let scalars: YScalar[];
  if (node.kind === "scalar") scalars = [node];
  else if (node.kind === "seq") {
    if (node.items.length === 0) fail(`'${rawKey}' has an empty list of values`, line);
    scalars = node.items.map((it) => (it.kind === "scalar" ? it : fail(`values of '${rawKey}' must be plain values, not nested lists or maps`, it.line)));
  } else return fail(`the value of '${rawKey}' must be a value or a list of values, not a map`, line);

  const get = (ev: SigmaEvent): unknown => (field === "" ? MISSING : getField(ev, field));
  const onField = (vt: ValueTest): Test =>
    field === ""
      ? (ev) => allValues(ev).some((v) => vt(v))
      : (ev) => {
          const v = get(ev);
          return v !== MISSING && anyElement(v, vt);
        };

  if (has("exists")) {
    if (scalars.length !== 1 || typeof scalars[0].value !== "boolean") fail(`'${rawKey}' needs true or false`, line);
    if (field === "") fail("exists needs a field name", line);
    const want = scalars[0].value as boolean;
    return {
      test: (ev) => {
        const v = get(ev);
        return (v !== MISSING && v !== null && v !== undefined) === want;
      },
      literals: [],
    };
  }

  const tests: ValueTest[] = [];
  const literals: string[] = [];
  let nullTest = false;
  for (const sc of scalars) {
    if (sc.value === null) {
      if (standalone.length || position.length) fail(`'${rawKey}': null cannot be combined with modifiers`, sc.line);
      nullTest = true;
      continue;
    }
    if (has("gt") || has("gte") || has("lt") || has("lte")) {
      const n = toNumber(sc.value);
      if (n === null) fail(`'${rawKey}' needs a number, got '${String(sc.value)}'`, sc.line);
      const op = standalone[0];
      tests.push((v) => {
        const x = toNumber(v);
        if (x === null) return false;
        return op === "gt" ? x > n! : op === "gte" ? x >= n! : op === "lt" ? x < n! : x <= n!;
      });
      continue;
    }
    const text = String(sc.value);
    if (has("cidr")) {
      const { base, mask } = parseCidr(text, sc.line);
      tests.push((v) => {
        const ip = ipv4(v);
        return ip !== null && ((ip & mask) >>> 0) === base;
      });
      continue;
    }
    if (has("re")) {
      let re: Regex;
      try {
        resetBudget();
        re = compileRegex(text, { i: has("i"), m: has("m"), s: has("s") });
      } catch (e) {
        if (e instanceof RegexError || e instanceof KqlLimitFail) return fail(`invalid regular expression in '${rawKey}': ${e.message}`, sc.line);
        throw e;
      }
      tests.push((v) => {
        const s = asText(v);
        return s !== null && regexTest(re, s);
      });
      continue;
    }

    literals.push(text);
    // Each value expands to alternatives (base64 shifts, windash spellings); any alternative may match.
    let alternatives: GlobTok[][];
    if (has("base64") || has("base64offset")) {
      if (/[*?]/.test(text.replace(/\\[*?\\]/g, ""))) fail(`'${rawKey}': wildcards cannot be used with base64 modifiers`, sc.line);
      const plain = parseWildcards(text).map((t) => (t.t === "lit" ? t.c : "")).join("");
      const encoded = has("base64") ? [base64(new TextEncoder().encode(plain))] : base64Offsets(plain);
      alternatives = encoded.map(literal);
    } else {
      const spellings = has("windash") ? windashVariants(text, sc.line) : [text];
      alternatives = spellings.map(parseWildcards);
    }
    const star: GlobTok = { t: "star" };
    alternatives = alternatives.map((a) =>
      has("contains") ? [star, ...a, star] : has("startswith") ? [...a, star] : has("endswith") ? [star, ...a] : a,
    );
    const cased = has("cased");
    tests.push((v) => {
      const s = asText(v);
      return s !== null && alternatives.some((a) => globMatch(a, s, cased));
    });
  }

  const all = has("all");
  const combined: ValueTest = (v) => (all ? tests.every((t) => t(v)) : tests.some((t) => t(v)));
  if (nullTest) {
    // null: the field is absent or empty; it can sit in a list next to real values.
    return {
      test: (ev) => {
        const v = get(ev);
        if (v === MISSING || v === null || v === "") return true;
        return tests.length > 0 && anyElement(v, combined);
      },
      literals,
    };
  }
  if (all && field !== "") {
    // |all over a list-valued event field: each value may be satisfied by a different element.
    return {
      test: (ev) => {
        const v = get(ev);
        if (v === MISSING) return false;
        return tests.every((t) => anyElement(v, t));
      },
      literals,
    };
  }
  if (all) return { test: (ev) => tests.every((t) => allValues(ev).some((v) => t(v))), literals };
  return { test: onField(combined), literals };
}

// ---- search identifiers --------------------------------------------------------------

export interface CompiledSearch extends SigmaSearch {
  literals: { field: string; value: string; line: number }[];
}

function compileMap(map: YMap, out: CompiledSearch["literals"]): Test {
  if (map.entries.length === 0) fail("a selection map cannot be empty", map.line);
  const items = map.entries.map((e) => {
    const c = compileItem(e.key, e.value, e.keyLine);
    for (const v of c.literals) out.push({ field: e.key, value: v, line: e.keyLine });
    return c.test;
  });
  return (ev) => items.every((t) => t(ev));
}

export function compileSearch(id: string, node: YNode, line: number): CompiledSearch {
  const literals: CompiledSearch["literals"] = [];
  if (node.kind === "map") return { id, line, test: compileMap(node, literals), literals };
  if (node.kind === "seq") {
    if (node.items.length === 0) fail(`search identifier '${id}' is an empty list`, line);
    if (node.items.every((x) => x.kind === "map")) {
      const alts = node.items.map((m) => compileMap(m as YMap, literals));
      return { id, line, test: (ev) => alts.some((t) => t(ev)), literals };
    }
    if (node.items.every((x) => x.kind === "scalar")) {
      // A plain list is a keyword search: case-insensitive "contains" over every value in the event.
      const item = compileItem("|contains", node, line);
      return { id, line, test: item.test, literals: item.literals.map((v) => ({ field: "keywords", value: v, line })) };
    }
    fail(`search identifier '${id}' mixes maps and plain values; use either a list of maps or a list of keywords`, line);
  }
  return fail(`search identifier '${id}' must be a map of fields or a list`, line);
}

// ---- condition ---------------------------------------------------------------------------

type CTok = { v: string; pos: number };

function lexCondition(src: string, line: number): CTok[] {
  const out: CTok[] = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (/\s/.test(c)) {
      i++;
      continue;
    }
    if (c === "(" || c === ")") {
      out.push({ v: c, pos: i++ });
      continue;
    }
    if (c === "|") fail("aggregation expressions ('| count() ...') are not supported; Sigma moved them to correlation rules", line);
    const m = /^[A-Za-z0-9_*.-]+/.exec(src.slice(i));
    if (!m) return fail(`unexpected character '${c}' in condition`, line);
    out.push({ v: m[0], pos: i });
    i += m[0].length;
  }
  return out;
}

const RESERVED = new Set(["and", "or", "not", "of", "them", "1", "all", "any"]);

export function parseCondition(src: string, ids: string[], line: number): { cond: SigmaCondition; used: Set<string> } {
  const toks = lexCondition(src, line);
  let p = 0;
  let depth = 0;
  const used = new Set<string>();
  const peek = () => toks[p]?.v.toLowerCase();
  const describeNext = () => (toks[p] ? `'${toks[p].v}'` : "end of condition");

  const resolve = (pattern: string): string[] => {
    if (pattern === "them") return ids.filter((id) => !id.startsWith("_"));
    if (!pattern.includes("*")) {
      if (!ids.includes(pattern)) fail(`condition references '${pattern}', which is not defined`, line);
      return [pattern];
    }
    const glob = parseWildcards(pattern);
    const hit = ids.filter((id) => globMatch(glob, id, true));
    if (hit.length === 0) fail(`condition pattern '${pattern}' does not match any search identifier`, line);
    return hit;
  };

  const primary = (): SigmaCondition => {
    const t = toks[p];
    if (!t) return fail("condition ends unexpectedly", line);
    const v = t.v.toLowerCase();
    if (v === "(") {
      if (++depth > 32) fail("condition is nested too deeply", line);
      p++;
      const e = orExpr();
      if (peek() !== ")") fail(`expected ')' in condition but found ${describeNext()}`, line);
      p++;
      depth--;
      return e;
    }
    if (toks[p + 1]?.v.toLowerCase() === "of") {
      if (v === "any") fail("'any of' is not Sigma; use '1 of'", line);
      if (v !== "1" && v !== "all") fail(`'${t.v} of' is not valid; Sigma only has '1 of' and 'all of'`, line);
      p += 2;
      const target = toks[p];
      if (!target || target.v === "(" || target.v === ")") fail(`expected an identifier pattern or 'them' after '${t.v} of'`, line);
      p++;
      const matched = resolve(target!.v === "them" ? "them" : target!.v);
      matched.forEach((id) => used.add(id));
      return { k: "of", quant: v as "1" | "all", ids: matched };
    }
    if (v === ")" || RESERVED.has(v)) fail(`unexpected ${describeNext()} in condition`, line);
    if (t.v.includes("*")) fail(`wildcard '${t.v}' needs '1 of' or 'all of' in front of it`, line);
    p++;
    resolve(t.v);
    used.add(t.v);
    return { k: "id", id: t.v };
  };

  const notExpr = (): SigmaCondition => {
    if (peek() === "not") {
      p++;
      if (++depth > 32) fail("condition is nested too deeply", line);
      const e = notExpr();
      depth--;
      return { k: "not", e };
    }
    return primary();
  };

  const andExpr = (): SigmaCondition => {
    let l = notExpr();
    while (peek() === "and") {
      p++;
      l = { k: "and", l, r: notExpr() };
    }
    return l;
  };

  const orExpr = (): SigmaCondition => {
    let l = andExpr();
    while (peek() === "or") {
      p++;
      l = { k: "or", l, r: andExpr() };
    }
    return l;
  };

  if (toks.length === 0) fail("condition is empty", line);
  const cond = orExpr();
  if (p < toks.length) fail(`unexpected ${describeNext()} in condition`, line);
  return { cond, used };
}

export function evalCondition(c: SigmaCondition, results: Record<string, boolean>): boolean {
  switch (c.k) {
    case "id":
      return results[c.id] === true;
    case "of":
      return c.quant === "all" ? c.ids.every((id) => results[id]) : c.ids.some((id) => results[id]);
    case "not":
      return !evalCondition(c.e, results);
    case "and":
      return evalCondition(c.l, results) && evalCondition(c.r, results);
    case "or":
      return evalCondition(c.l, results) || evalCondition(c.r, results);
  }
}
