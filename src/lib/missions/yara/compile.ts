/**
 * YARA rule compiler for the learner subset. Produces a small AST plus compiled
 * string patterns. Errors use yara's own wording ("syntax error, unexpected ...",
 * "unreferenced string ...") so what learners read here is what they will read
 * from the real tool.
 */
import { compileRegex, RegexError } from "@/lib/kql/regex";
import { KqlLimitFail, resetBudget } from "@/lib/kql/errors";
import { describe, KEYWORDS, tokenize, YaraError, type Token } from "./lexer";

export const MAX_SOURCE = 64 * 1024;
export const MAX_STRINGS_PER_RULE = 64;
export const MAX_RULES = 256;
const MAX_HEX_JUMP = 256;
const MAX_DEPTH = 64;

export type YaraMetaValue = string | number | boolean;

export interface CompiledYaraString {
  /** "$a", or "$" for anonymous strings. */
  id: string;
  line: number;
  kind: "text" | "hex" | "regex";
  isPrivate: boolean;
  /** text strings: raw bytes. */
  bytes: number[];
  ascii: boolean;
  wide: boolean;
  nocase: boolean;
  fullword: boolean;
  /** hex and regex strings run on the linear regex engine over a latin1 view of the bytes. */
  regex: { source: string; i: boolean; s: boolean } | null;
}

export type YaraExpr =
  | { k: "bool"; v: boolean }
  | { k: "int"; v: number }
  | { k: "filesize" }
  | { k: "str"; s: number }
  | { k: "count"; s: number }
  | { k: "offset"; s: number; idx: YaraExpr }
  | { k: "length"; s: number; idx: YaraExpr }
  | { k: "at"; s: number; off: YaraExpr }
  | { k: "in"; s: number; lo: YaraExpr; hi: YaraExpr }
  | { k: "of"; quant: "any" | "all" | "none" | YaraExpr; set: number[] }
  | { k: "rule"; r: number }
  | { k: "uint"; size: 1 | 2 | 4; be: boolean; off: YaraExpr }
  | { k: "neg"; e: YaraExpr }
  | { k: "not"; e: YaraExpr }
  | { k: "and" | "or"; l: YaraExpr; r: YaraExpr }
  | { k: "cmp"; op: "==" | "!=" | "<" | "<=" | ">" | ">="; l: YaraExpr; r: YaraExpr }
  | { k: "arith"; op: "+" | "-" | "*" | "\\"; l: YaraExpr; r: YaraExpr };

export interface CompiledYaraRule {
  name: string;
  line: number;
  tags: string[];
  meta: { key: string; value: YaraMetaValue }[];
  isPrivate: boolean;
  strings: CompiledYaraString[];
  condition: YaraExpr;
}

type Typed = { e: YaraExpr; t: "bool" | "int" };

const UINT_FUNCS: Record<string, { size: 1 | 2 | 4; be: boolean }> = {
  uint8: { size: 1, be: false },
  uint16: { size: 2, be: false },
  uint32: { size: 4, be: false },
  uint8be: { size: 1, be: true },
  uint16be: { size: 2, be: true },
  uint32be: { size: 4, be: true },
};

const TEXT_MODIFIERS = new Set(["ascii", "wide", "nocase", "fullword", "private"]);
const UNSUPPORTED_MODIFIERS = new Set(["xor", "base64", "base64wide"]);

/** Converts the body of a hex string `{ ... }` into a regex over latin1 bytes. */
export function hexToRegex(body: string): string {
  const src = body.replace(/\s+/g, " ").trim();
  let i = 0;
  const bad = (why: string): never => {
    throw new Error(why);
  };
  const skip = () => {
    while (src[i] === " ") i++;
  };
  const hexDigit = (c: string | undefined) => c !== undefined && /[0-9A-Fa-f]/.test(c);
  const b = (v: number) => "\\x" + v.toString(16).padStart(2, "0");

  // seq returns [regex, itemKinds] so jumps at the edges can be rejected like yara does.
  const seq = (depth: number): { re: string; kinds: ("byte" | "jump")[] } => {
    if (depth > 8) bad("alternatives nested too deeply");
    let re = "";
    const kinds: ("byte" | "jump")[] = [];
    for (;;) {
      skip();
      const c = src[i];
      if (c === undefined || c === "|" || c === ")") break;
      if (c === "~") bad("the ~ (not) operator is not supported in this console");
      if (c === "(") {
        i++;
        const alts: string[] = [];
        for (;;) {
          const inner = seq(depth + 1);
          if (inner.kinds.length === 0) bad("empty alternative");
          alts.push(inner.re);
          skip();
          if (src[i] === "|") {
            i++;
            continue;
          }
          if (src[i] === ")") {
            i++;
            break;
          }
          bad("missing )");
        }
        re += `(?:${alts.join("|")})`;
        kinds.push("byte");
        continue;
      }
      if (c === "[") {
        const close = src.indexOf("]", i);
        if (close < 0) bad("missing ]");
        const inside = src.slice(i + 1, close).replace(/ /g, "");
        i = close + 1;
        const m = /^(\d*)(-?)(\d*)$/.exec(inside);
        if (!m || (m[1] === "" && m[2] === "")) bad(`invalid jump [${inside}]`);
        if (m![2] === "-" && m![3] === "") bad("unbounded jumps are not supported in this console, give an upper bound like [0-256]");
        const lo = m![1] === "" ? 0 : Number(m![1]);
        const hi = m![2] === "" ? lo : Number(m![3]);
        if (hi < lo) bad(`invalid jump [${inside}]`);
        if (hi > MAX_HEX_JUMP) bad(`jump [${inside}] is too large (max ${MAX_HEX_JUMP})`);
        re += lo === hi ? `[\\x00-\\xff]{${lo}}` : `[\\x00-\\xff]{${lo},${hi}}`;
        kinds.push("jump");
        continue;
      }
      const hi = src[i];
      const lo = src[i + 1];
      if (!((hexDigit(hi) || hi === "?") && (hexDigit(lo) || lo === "?"))) bad(`unexpected "${src.slice(i, i + 2)}"`);
      i += 2;
      if (hi === "?" && lo === "?") re += "[\\x00-\\xff]";
      else if (hi === "?") {
        const l = parseInt(lo, 16);
        re += "[" + Array.from({ length: 16 }, (_, k) => b(k * 16 + l)).join("") + "]";
      } else if (lo === "?") {
        const h = parseInt(hi, 16) * 16;
        re += `[${b(h)}-${b(h + 15)}]`;
      } else re += b(parseInt(hi + lo, 16));
      kinds.push("byte");
    }
    if (kinds[0] === "jump" || kinds[kinds.length - 1] === "jump") bad("jumps are not allowed at the start or end");
    return { re, kinds };
  };

  const out = seq(0);
  skip();
  if (i < src.length) bad(`unexpected "${src[i]}"`);
  if (out.kinds.length === 0) bad("empty hex string");
  return out.re;
}

class Parser {
  private p = 0;
  private depth = 0;
  private readonly rules: CompiledYaraRule[] = [];
  // Per-rule state while parsing a condition.
  private strings: CompiledYaraString[] = [];
  private referenced: boolean[] = [];
  private ruleName = "";

  constructor(private readonly toks: Token[]) {}

  private get tok(): Token {
    return this.toks[this.p];
  }

  private next(): Token {
    const t = this.toks[this.p];
    if (t.kind !== "eof") this.p++;
    return t;
  }

  private unexpected(t: Token = this.tok): never {
    throw new YaraError(`syntax error, unexpected ${describe(t)}`, t.line);
  }

  private isId(v: string, t: Token = this.tok): boolean {
    return t.kind === "id" && t.value === v;
  }

  private isPunct(v: string, t: Token = this.tok): boolean {
    return t.kind === "punct" && t.value === v;
  }

  private expectPunct(v: string): Token {
    if (!this.isPunct(v)) this.unexpected();
    return this.next();
  }

  private expectId(v: string): Token {
    if (!this.isId(v)) this.unexpected();
    return this.next();
  }

  parseAll(): CompiledYaraRule[] {
    while (this.tok.kind !== "eof") {
      if (this.isId("import")) {
        const t = this.next();
        const mod = this.tok.kind === "text" ? String.fromCharCode(...(this.tok.bytes ?? [])) : "";
        throw new YaraError(`modules are not available in this console (import "${mod}"); use strings, filesize and uint functions`, t.line);
      }
      if (this.isId("include")) throw new YaraError("include is not available in this console", this.tok.line);
      this.parseRule();
      if (this.rules.length > MAX_RULES) throw new YaraError(`too many rules (max ${MAX_RULES})`, this.tok.line);
    }
    if (this.rules.length === 0) throw new YaraError("no rules found; a rule starts with: rule Name {", this.tok.line);
    return this.rules;
  }

  private parseRule(): void {
    let isPrivate = false;
    for (;;) {
      if (this.isId("private")) {
        isPrivate = true;
        this.next();
      } else if (this.isId("global")) {
        throw new YaraError("global rules are not supported in this console", this.tok.line);
      } else break;
    }
    const ruleTok = this.expectId("rule");
    const nameTok = this.tok;
    if (nameTok.kind !== "id" || KEYWORDS.has(nameTok.value)) this.unexpected();
    this.next();
    const name = nameTok.value;
    if (name.length > 128) throw new YaraError(`identifier "${name.slice(0, 20)}..." is too long`, nameTok.line);
    if (this.rules.some((r) => r.name === name)) throw new YaraError(`duplicated identifier "${name}"`, nameTok.line);

    const tags: string[] = [];
    if (this.isPunct(":")) {
      this.next();
      while (this.tok.kind === "id" && !KEYWORDS.has(this.tok.value)) {
        const t = this.next();
        if (tags.includes(t.value)) throw new YaraError(`duplicated tag identifier "${t.value}"`, t.line);
        tags.push(t.value);
      }
      if (tags.length === 0) this.unexpected();
    }
    this.expectPunct("{");

    const meta: { key: string; value: YaraMetaValue }[] = [];
    if (this.isId("meta")) {
      this.next();
      this.expectPunct(":");
      while (this.tok.kind === "id" && !(this.isId("strings") || this.isId("condition"))) {
        const key = this.next().value;
        this.expectPunct("=");
        const v = this.tok;
        if (v.kind === "text") meta.push({ key, value: new TextDecoder().decode(new Uint8Array(v.bytes ?? [])) });
        else if (v.kind === "int") meta.push({ key, value: v.num as number });
        else if (this.isPunct("-") && this.toks[this.p + 1]?.kind === "int") {
          this.next();
          meta.push({ key, value: -(this.tok.num as number) });
        } else if (this.isId("true") || this.isId("false")) meta.push({ key, value: v.value === "true" });
        else this.unexpected();
        this.next();
      }
    }

    this.strings = [];
    this.referenced = [];
    this.ruleName = name;
    if (this.isId("strings")) {
      const st = this.next();
      this.expectPunct(":");
      if (this.tok.kind !== "strid") {
        if (this.isId("condition") || this.isPunct("}")) throw new YaraError("empty strings section", st.line);
        this.unexpected();
      }
      while (this.tok.kind === "strid") this.parseString();
    }

    if (!this.isId("condition")) {
      if (this.isPunct("}") || this.tok.kind === "eof") throw new YaraError(`rule "${name}" has no condition`, this.tok.line);
      this.unexpected();
    }
    this.next();
    this.expectPunct(":");
    if (this.isPunct("}")) throw new YaraError(`rule "${name}" has no condition`, this.tok.line);
    const cond = this.expr();
    if (!this.isPunct("}")) this.unexpected();
    this.next();

    this.strings.forEach((s, idx) => {
      if (!this.referenced[idx] && !s.id.startsWith("$_")) throw new YaraError(`unreferenced string "${s.id}"`, s.line);
    });

    this.rules.push({ name, line: ruleTok.line, tags, meta, isPrivate, strings: this.strings, condition: cond.e });
  }

  private parseString(): void {
    const idTok = this.next();
    const id = idTok.value;
    if (id.endsWith("*")) this.unexpected(idTok);
    if (id !== "$" && this.strings.some((s) => s.id === id)) throw new YaraError(`duplicated string identifier "${id}"`, idTok.line);
    if (this.strings.length >= MAX_STRINGS_PER_RULE) throw new YaraError(`too many strings in rule "${this.ruleName}" (max ${MAX_STRINGS_PER_RULE})`, idTok.line);
    this.expectPunct("=");
    const v = this.next();
    const s: CompiledYaraString = {
      id, line: idTok.line, kind: "text", isPrivate: false, bytes: [],
      ascii: false, wide: false, nocase: false, fullword: false, regex: null,
    };
    if (v.kind === "text") {
      s.bytes = v.bytes ?? [];
      if (s.bytes.length === 0) throw new YaraError(`empty string "${id}"`, v.line);
    } else if (v.kind === "hex") {
      s.kind = "hex";
      try {
        s.regex = { source: hexToRegex(v.value), i: false, s: true };
      } catch (e) {
        throw new YaraError(`invalid hex string "${id}": ${(e as Error).message}`, v.line);
      }
    } else if (v.kind === "regex") {
      s.kind = "regex";
      const flags = v.flags ?? "";
      s.regex = { source: v.value, i: flags.includes("i"), s: flags.includes("s") };
    } else this.unexpected(v);

    const seen = new Set<string>();
    while (this.tok.kind === "id" && (TEXT_MODIFIERS.has(this.tok.value) || UNSUPPORTED_MODIFIERS.has(this.tok.value))) {
      const m = this.next();
      if (UNSUPPORTED_MODIFIERS.has(m.value)) throw new YaraError(`the "${m.value}" modifier is not supported in this console`, m.line);
      if (seen.has(m.value)) throw new YaraError(`duplicated modifier "${m.value}"`, m.line);
      seen.add(m.value);
      if (s.kind === "hex" && m.value !== "private") throw new YaraError(`invalid modifier "${m.value}" for hex string "${id}"`, m.line);
    }
    s.isPrivate = seen.has("private");
    s.wide = seen.has("wide");
    s.ascii = seen.has("ascii") || !s.wide;
    s.nocase = seen.has("nocase");
    s.fullword = seen.has("fullword");
    if (s.kind === "regex" && s.regex) {
      if (s.nocase) s.regex.i = true;
      try {
        resetBudget();
        compileRegex(s.regex.source, { i: s.regex.i, s: s.regex.s });
      } catch (e) {
        if (e instanceof RegexError || e instanceof KqlLimitFail) throw new YaraError(`invalid regular expression in string "${id}": ${e.message}`, v.line);
        throw e;
      }
    }
    if (s.kind === "hex" && s.regex) {
      try {
        resetBudget();
        compileRegex(s.regex.source, { s: true });
      } catch (e) {
        if (e instanceof RegexError || e instanceof KqlLimitFail) throw new YaraError(`invalid hex string "${id}": ${e.message}`, v.line);
        throw e;
      }
    }
    this.strings.push(s);
  }

  // ---- condition -------------------------------------------------------

  private enter(t: Token): void {
    if (++this.depth > MAX_DEPTH) throw new YaraError("condition is nested too deeply", t.line);
  }

  private expr(): Typed {
    this.enter(this.tok);
    let l = this.andExpr();
    while (this.isId("or")) {
      this.next();
      const r = this.andExpr();
      l = { e: { k: "or", l: l.e, r: r.e }, t: "bool" };
    }
    this.depth--;
    return l;
  }

  private andExpr(): Typed {
    let l = this.notExpr();
    while (this.isId("and")) {
      this.next();
      const r = this.notExpr();
      l = { e: { k: "and", l: l.e, r: r.e }, t: "bool" };
    }
    return l;
  }

  private notExpr(): Typed {
    if (this.isId("not")) {
      const t = this.next();
      this.enter(t);
      const e = this.notExpr();
      this.depth--;
      return { e: { k: "not", e: e.e }, t: "bool" };
    }
    if (this.isId("defined")) throw new YaraError('"defined" is not supported in this console', this.tok.line);
    return this.relExpr();
  }

  private needInt(x: Typed, op: string, t: Token): YaraExpr {
    if (x.t !== "int") throw new YaraError(`wrong type "boolean" for "${op}" operator`, t.line);
    return x.e;
  }

  private relExpr(): Typed {
    const l = this.addExpr();
    const t = this.tok;
    if (t.kind === "punct" && ["==", "!=", "<", "<=", ">", ">="].includes(t.value)) {
      this.next();
      const r = this.addExpr();
      const op = t.value as "==" | "!=" | "<" | "<=" | ">" | ">=";
      return { e: { k: "cmp", op, l: this.needInt(l, op, t), r: this.needInt(r, op, t) }, t: "bool" };
    }
    if (t.kind === "id" && ["contains", "icontains", "matches", "startswith", "endswith", "iequals", "istartswith", "iendswith"].includes(t.value)) {
      throw new YaraError(`the "${t.value}" operator needs module strings, which this console does not have`, t.line);
    }
    return l;
  }

  private addExpr(): Typed {
    let l = this.mulExpr();
    while (this.isPunct("+") || this.isPunct("-")) {
      const t = this.next();
      const r = this.mulExpr();
      const op = t.value as "+" | "-";
      l = { e: { k: "arith", op, l: this.needInt(l, op, t), r: this.needInt(r, op, t) }, t: "int" };
    }
    return l;
  }

  private mulExpr(): Typed {
    let l = this.unary();
    while (this.isPunct("*") || this.isPunct("\\")) {
      const t = this.next();
      const r = this.unary();
      const op = t.value as "*" | "\\";
      l = { e: { k: "arith", op, l: this.needInt(l, op, t), r: this.needInt(r, op, t) }, t: "int" };
    }
    return l;
  }

  private unary(): Typed {
    if (this.isPunct("-")) {
      const t = this.next();
      this.enter(t);
      const e = this.unary();
      this.depth--;
      return { e: { k: "neg", e: this.needInt(e, "-", t) }, t: "int" };
    }
    return this.primary();
  }

  /** Resolves `$a` to a string index and marks it referenced. */
  private stringIndex(t: Token, name: string): number {
    if (name === "$") throw new YaraError('anonymous strings can only be used through "of them" or a set like ($*)', t.line);
    const idx = this.strings.findIndex((s) => s.id === name);
    if (idx < 0) throw new YaraError(`undefined string identifier "${name}"`, t.line);
    this.referenced[idx] = true;
    return idx;
  }

  private stringSet(): number[] {
    if (this.isId("them")) {
      const t = this.next();
      if (this.strings.length === 0) throw new YaraError('"them" used in a rule with no strings', t.line);
      this.strings.forEach((_, i) => (this.referenced[i] = true));
      return this.strings.map((_, i) => i);
    }
    this.expectPunct("(");
    const set = new Set<number>();
    for (;;) {
      const t = this.tok;
      if (t.kind !== "strid") this.unexpected();
      this.next();
      if (t.value.endsWith("*")) {
        const prefix = t.value.slice(0, -1);
        let hit = false;
        this.strings.forEach((s, i) => {
          if (s.id.startsWith(prefix)) {
            set.add(i);
            this.referenced[i] = true;
            hit = true;
          }
        });
        if (!hit) throw new YaraError(`undefined string identifier "${t.value}"`, t.line);
      } else set.add(this.stringIndex(t, t.value));
      if (this.isPunct(",")) {
        this.next();
        continue;
      }
      this.expectPunct(")");
      break;
    }
    return [...set].sort((a, b) => a - b);
  }

  private ofTail(quant: "any" | "all" | "none" | YaraExpr): Typed {
    this.expectId("of");
    return { e: { k: "of", quant, set: this.stringSet() }, t: "bool" };
  }

  private index(): YaraExpr {
    if (!this.isPunct("[")) return { k: "int", v: 1 };
    const t = this.next();
    const e = this.expr();
    this.expectPunct("]");
    return this.needInt(e, "[]", t);
  }

  private primary(): Typed {
    const t = this.tok;
    if (t.kind === "int") {
      this.next();
      const e: YaraExpr = { k: "int", v: t.num as number };
      if (this.isId("of")) return this.ofTail(e);
      return { e, t: "int" };
    }
    if (t.kind === "strid") {
      this.next();
      const s = this.stringIndex(t, t.value.endsWith("*") ? this.unexpected(t) : t.value);
      if (this.isId("at")) {
        const at = this.next();
        return { e: { k: "at", s, off: this.needInt(this.addExpr(), "at", at) }, t: "bool" };
      }
      if (this.isId("in")) {
        const it = this.next();
        this.expectPunct("(");
        const lo = this.needInt(this.addExpr(), "in", it);
        this.expectPunct("..");
        const hi = this.needInt(this.addExpr(), "in", it);
        this.expectPunct(")");
        return { e: { k: "in", s, lo, hi }, t: "bool" };
      }
      return { e: { k: "str", s }, t: "bool" };
    }
    if (t.kind === "count") {
      this.next();
      if (t.value === "#") throw new YaraError('"#" without a name only works inside for loops, which this console does not support', t.line);
      return { e: { k: "count", s: this.stringIndex(t, "$" + t.value.slice(1)) }, t: "int" };
    }
    if (t.kind === "offset" || t.kind === "length") {
      this.next();
      if (t.value.length === 1) throw new YaraError(`"${t.value}" without a name only works inside for loops, which this console does not support`, t.line);
      const s = this.stringIndex(t, "$" + t.value.slice(1));
      const idx = this.index();
      return { e: t.kind === "offset" ? { k: "offset", s, idx } : { k: "length", s, idx }, t: "int" };
    }
    if (t.kind === "punct" && t.value === "(") {
      this.next();
      const e = this.expr();
      this.expectPunct(")");
      if (e.t === "int" && this.isId("of")) return this.ofTail(e.e);
      return e;
    }
    if (t.kind === "id") {
      switch (t.value) {
        case "true":
        case "false":
          this.next();
          return { e: { k: "bool", v: t.value === "true" }, t: "bool" };
        case "filesize":
          this.next();
          return { e: { k: "filesize" }, t: "int" };
        case "any":
        case "all":
        case "none":
          this.next();
          return this.ofTail(t.value);
        case "for":
          throw new YaraError("for loops are not supported in this console; use 'N of (...)' or #a", t.line);
        case "entrypoint":
          throw new YaraError('"entrypoint" is deprecated and not supported; use the pe module in real yara', t.line);
        case "them":
          throw new YaraError('syntax error, unexpected "them" (did you mean "any of them"?)', t.line);
      }
      const fn = UINT_FUNCS[t.value];
      if (fn) {
        this.next();
        this.expectPunct("(");
        const off = this.needInt(this.expr(), t.value, t);
        this.expectPunct(")");
        return { e: { k: "uint", size: fn.size, be: fn.be, off }, t: "int" };
      }
      if (/^int(8|16|32)(be)?$/.test(t.value)) throw new YaraError(`"${t.value}" (signed read) is not supported in this console; use u${t.value}`, t.line);
      if (KEYWORDS.has(t.value)) this.unexpected();
      if (this.isPunct(".", this.toks[this.p + 1])) {
        throw new YaraError(`modules are not available in this console ("${t.value}.")`, t.line);
      }
      const r = this.rules.findIndex((x) => x.name === t.value);
      if (r < 0) throw new YaraError(`undefined identifier "${t.value}"`, t.line);
      this.next();
      return { e: { k: "rule", r }, t: "bool" };
    }
    return this.unexpected();
  }
}

export type YaraCompileResult = { ok: true; rules: CompiledYaraRule[] } | { ok: false; error: { message: string; line: number } };

export function compileYara(source: string): YaraCompileResult {
  if (source.length > MAX_SOURCE) return { ok: false, error: { message: `rule source too large (max ${MAX_SOURCE / 1024} KB)`, line: 1 } };
  try {
    const rules = new Parser(tokenize(source)).parseAll();
    return { ok: true, rules };
  } catch (e) {
    if (e instanceof YaraError) return { ok: false, error: { message: e.message, line: e.line } };
    // Anything else is an engine bug; still never throw at the learner.
    return { ok: false, error: { message: `internal error: ${(e as Error).message}`, line: 1 } };
  }
}
