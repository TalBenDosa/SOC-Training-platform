/**
 * Runs compiled rules over a byte buffer. Text strings use KMP (linear, no budget
 * needed); hex and regex strings run on the Pike VM from src/lib/kql/regex.ts over
 * a latin1 view of the bytes (one char per byte), which is linear in input size
 * and charges a shared work budget. When the budget runs out the affected string
 * keeps the matches found so far and a warning is returned; scanYara never throws.
 */
import { compileRegex, type Regex } from "@/lib/kql/regex";
import { KqlLimitFail, resetBudget } from "@/lib/kql/errors";
import type { CompiledYaraRule, CompiledYaraString, YaraExpr } from "./compile";

/** Same cap idea as yara's "too many matches": counts stop growing here. */
export const MAX_MATCHES_PER_STRING = 10_000;
/** Work units for one scanYara call; well under a second on the slowest pattern. */
export const SCAN_BUDGET = 60_000_000;
/** How many offsets per string are returned for highlighting. */
const REPORTED_OFFSETS = 32;

export interface YaraStringResult {
  id: string;
  count: number;
  firstOffset: number | null;
  /** First few match offsets, ascending, for hex-view highlighting. */
  offsets: number[];
}

export interface YaraFileResult {
  /** True when any non-private rule matched. */
  matched: boolean;
  /** Non-private rules, in source order. */
  rules: { name: string; matched: boolean; strings: YaraStringResult[] }[];
  /** Non-fatal notes such as a capped match count or an exhausted work budget. */
  warnings?: string[];
}

interface Matches {
  offsets: number[];
  lengths: number[];
}

const isAlnum = (b: number) => (b >= 48 && b <= 57) || (b >= 65 && b <= 90) || (b >= 97 && b <= 122);
const lower = (b: number) => (b >= 65 && b <= 90 ? b + 32 : b);

class ScanContext {
  readonly warnings: string[] = [];
  private latin1Cache: string | null = null;
  private wideCache: { start: number; text: string }[] | null = null;
  constructor(readonly bytes: Uint8Array) {}

  get latin1(): string {
    if (this.latin1Cache === null) {
      let s = "";
      const CHUNK = 4096;
      for (let i = 0; i < this.bytes.length; i += CHUNK) {
        s += String.fromCharCode(...this.bytes.subarray(i, Math.min(i + CHUNK, this.bytes.length)));
      }
      this.latin1Cache = s;
    }
    return this.latin1Cache;
  }

  /**
   * Maximal runs of (byte, 0x00) pairs at both alignments, narrowed to one char per
   * pair. A wide regex runs inside each run, so a match can never cross a pair whose
   * high byte is not zero, which is exactly what yara's wide regex requires.
   */
  get wideRuns(): { start: number; text: string }[] {
    if (this.wideCache === null) {
      const runs: { start: number; text: string }[] = [];
      const b = this.bytes;
      for (let align = 0; align < 2; align++) {
        let start = -1;
        let text = "";
        for (let i = align; i < b.length; i += 2) {
          const ok = i + 1 < b.length && b[i + 1] === 0;
          if (ok) {
            if (start < 0) start = i;
            text += String.fromCharCode(b[i]);
          } else if (start >= 0) {
            runs.push({ start, text });
            start = -1;
            text = "";
          }
        }
        if (start >= 0) runs.push({ start, text });
      }
      this.wideCache = runs;
    }
    return this.wideCache;
  }
}

/** All start offsets of `pat` in `hay` (KMP), with optional ASCII case folding. */
function kmpAll(hay: Uint8Array, pat: number[], nocase: boolean, onMatch: (off: number) => boolean): void {
  const m = pat.length;
  if (m === 0 || m > hay.length) return;
  const p = nocase ? pat.map(lower) : pat;
  const fail = new Int32Array(m);
  for (let i = 1, k = 0; i < m; i++) {
    while (k > 0 && p[i] !== p[k]) k = fail[k - 1];
    if (p[i] === p[k]) k++;
    fail[i] = k;
  }
  for (let i = 0, k = 0; i < hay.length; i++) {
    const c = nocase ? lower(hay[i]) : hay[i];
    while (k > 0 && c !== p[k]) k = fail[k - 1];
    if (c === p[k]) k++;
    if (k === m) {
      if (!onMatch(i - m + 1)) return;
      k = fail[k - 1];
    }
  }
}

function fullwordOk(b: Uint8Array, off: number, len: number, wide: boolean): boolean {
  if (wide) {
    if (off >= 2 && b[off - 1] === 0 && isAlnum(b[off - 2])) return false;
    if (off + len + 1 < b.length && isAlnum(b[off + len]) && b[off + len + 1] === 0) return false;
    return true;
  }
  if (off >= 1 && isAlnum(b[off - 1])) return false;
  if (off + len < b.length && isAlnum(b[off + len])) return false;
  return true;
}

/** Every start offset where `re` matches in `text`; offsets map back through base/stride. */
function regexAll(re: Regex, text: string, base: number, stride: 1 | 2, onMatch: (off: number, len: number) => boolean): void {
  let pos = 0;
  while (pos <= text.length) {
    const m = re.exec(text, pos);
    if (!m) return;
    const [st, en] = m;
    // Zero-length matches are not reported, as in yara.
    if (en > st && !onMatch(base + st * stride, (en - st) * stride)) return;
    pos = st + 1;
  }
}

function findMatches(s: CompiledYaraString, ctx: ScanContext, ruleName: string): Matches {
  const found = new Map<number, number>();
  let capped = false;
  const add = (off: number, len: number, wide: boolean): boolean => {
    if (s.fullword && !fullwordOk(ctx.bytes, off, len, wide)) return true;
    if (!found.has(off)) {
      if (found.size >= MAX_MATCHES_PER_STRING) {
        capped = true;
        return false;
      }
      found.set(off, len);
    }
    return true;
  };

  try {
    if (s.kind === "text") {
      if (s.ascii) kmpAll(ctx.bytes, s.bytes, s.nocase, (off) => add(off, s.bytes.length, false));
      if (s.wide && !capped) {
        const wide: number[] = [];
        for (const b of s.bytes) wide.push(b, 0);
        kmpAll(ctx.bytes, wide, s.nocase, (off) => add(off, wide.length, true));
      }
    } else if (s.regex) {
      const re = compileRegex(s.regex.source, { i: s.regex.i, s: s.regex.s });
      if (s.kind === "hex" || s.ascii) regexAll(re, ctx.latin1, 0, 1, (off, len) => add(off, len, false));
      if (s.kind === "regex" && s.wide && !capped) {
        for (const run of ctx.wideRuns) {
          if (capped) break;
          regexAll(re, run.text, run.start, 2, (off, len) => add(off, len, true));
        }
      }
    }
  } catch (e) {
    if (!(e instanceof KqlLimitFail)) throw e;
    ctx.warnings.push(`rule "${ruleName}": string ${s.id} is too expensive to search; it stopped early and its count may be low`);
  }
  if (capped) ctx.warnings.push(`rule "${ruleName}": string ${s.id} reached ${MAX_MATCHES_PER_STRING} matches; the count is capped`);

  const offsets = [...found.keys()].sort((a, b) => a - b);
  return { offsets, lengths: offsets.map((o) => found.get(o) as number) };
}

type Val = number | boolean | null;

const truthy = (v: Val): boolean => (typeof v === "boolean" ? v : typeof v === "number" ? v !== 0 : false);

function readUint(bytes: Uint8Array, off: number, size: 1 | 2 | 4, be: boolean): number | null {
  if (!Number.isInteger(off) || off < 0 || off + size > bytes.length) return null;
  let v = 0;
  for (let i = 0; i < size; i++) {
    const byte = bytes[be ? off + i : off + size - 1 - i];
    v = v * 256 + byte;
  }
  return v;
}

interface EvalEnv {
  bytes: Uint8Array;
  filesize: number;
  matches: Matches[];
  ruleResults: boolean[];
}

function evalExpr(e: YaraExpr, env: EvalEnv): Val {
  switch (e.k) {
    case "bool":
    case "int":
      return e.v;
    case "filesize":
      return env.filesize;
    case "str":
      return env.matches[e.s].offsets.length > 0;
    case "count":
      return env.matches[e.s].offsets.length;
    case "offset":
    case "length": {
      const i = evalExpr(e.idx, env);
      const m = env.matches[e.s];
      if (typeof i !== "number" || i < 1 || i > m.offsets.length) return null;
      return e.k === "offset" ? m.offsets[i - 1] : m.lengths[i - 1];
    }
    case "at": {
      const off = evalExpr(e.off, env);
      return typeof off === "number" && env.matches[e.s].offsets.includes(off);
    }
    case "in": {
      const lo = evalExpr(e.lo, env);
      const hi = evalExpr(e.hi, env);
      if (typeof lo !== "number" || typeof hi !== "number") return false;
      return env.matches[e.s].offsets.some((o) => o >= lo && o <= hi);
    }
    case "of": {
      const hits = e.set.filter((s) => env.matches[s].offsets.length > 0).length;
      if (e.quant === "any") return hits >= 1;
      if (e.quant === "all") return hits === e.set.length;
      if (e.quant === "none") return hits === 0;
      const n = evalExpr(e.quant, env);
      return typeof n === "number" ? hits >= n : null;
    }
    case "rule":
      return env.ruleResults[e.r] ?? false;
    case "uint": {
      const off = evalExpr(e.off, env);
      return typeof off === "number" ? readUint(env.bytes, off, e.size, e.be) : null;
    }
    case "neg": {
      const v = evalExpr(e.e, env);
      return typeof v === "number" ? -v : null;
    }
    case "not": {
      // yara: not(undefined) stays undefined, which is false at the top.
      const v = evalExpr(e.e, env);
      return v === null ? null : !truthy(v);
    }
    case "and":
      return truthy(evalExpr(e.l, env)) && truthy(evalExpr(e.r, env));
    case "or":
      return truthy(evalExpr(e.l, env)) || truthy(evalExpr(e.r, env));
    case "cmp": {
      const l = evalExpr(e.l, env);
      const r = evalExpr(e.r, env);
      if (typeof l !== "number" || typeof r !== "number") return null;
      switch (e.op) {
        case "==": return l === r;
        case "!=": return l !== r;
        case "<": return l < r;
        case "<=": return l <= r;
        case ">": return l > r;
        case ">=": return l >= r;
      }
      return null;
    }
    case "arith": {
      const l = evalExpr(e.l, env);
      const r = evalExpr(e.r, env);
      if (typeof l !== "number" || typeof r !== "number") return null;
      switch (e.op) {
        case "+": return l + r;
        case "-": return l - r;
        case "*": return l * r;
        case "\\": return r === 0 ? null : Math.trunc(l / r);
      }
      return null;
    }
  }
}

/**
 * Scans one file. `filesize` is the declared size (BuiltSample.filesize); the
 * uint functions read the materialised bytes and return undefined past them.
 */
export function scanYara(rules: CompiledYaraRule[], bytes: Uint8Array, filesize: number): YaraFileResult {
  const ctx = new ScanContext(bytes);
  const results: YaraFileResult["rules"] = [];
  const ruleResults: boolean[] = [];
  resetBudget(SCAN_BUDGET);
  for (const rule of rules) {
    let matched = false;
    let matches: Matches[] = rule.strings.map(() => ({ offsets: [], lengths: [] }));
    try {
      matches = rule.strings.map((s) => findMatches(s, ctx, rule.name));
      matched = truthy(evalExpr(rule.condition, { bytes, filesize, matches, ruleResults }));
    } catch (e) {
      ctx.warnings.push(`rule "${rule.name}" could not be evaluated: ${(e as Error).message}`);
    }
    ruleResults.push(matched);
    if (rule.isPrivate) continue;
    results.push({
      name: rule.name,
      matched,
      strings: rule.strings.map((s, i) => ({
        id: s.id,
        count: matches[i].offsets.length,
        firstOffset: matches[i].offsets[0] ?? null,
        offsets: matches[i].offsets.slice(0, REPORTED_OFFSETS),
      })),
    });
  }
  const out: YaraFileResult = { matched: results.some((r) => r.matched), rules: results };
  if (ctx.warnings.length) out.warnings = ctx.warnings;
  return out;
}
