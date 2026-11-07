/**
 * RE2-compatible regex matching on a Pike VM. Kusto regexes are RE2, which has no
 * backreferences or lookaround, and that is what makes linear-time matching possible.
 * JS RegExp backtracks, so any user pattern handed to it could hang the tab; here
 * matching is O(pattern * input) and each step is charged to the query budget.
 * Patterns RE2 itself rejects are rejected here too.
 */
import { charge } from "./errors";

export class RegexError extends Error {}

const MAX_PROGRAM = 30_000;
const MAX_REPEAT = 1000;
const MAX_NEST = 200;

type CharTest = (c: number) => boolean;

type Node =
  | { t: "empty" }
  | { t: "char"; c: number; fold: boolean }
  | { t: "any"; dotall: boolean }
  | { t: "class"; test: CharTest }
  | { t: "assert"; kind: AssertKind }
  | { t: "cat"; items: Node[] }
  | { t: "alt"; items: Node[] }
  | { t: "rep"; node: Node; min: number; max: number; greedy: boolean }
  | { t: "group"; node: Node; index: number };

type AssertKind = "bot" | "eot" | "bol" | "eol" | "wb" | "nwb";

interface Flags {
  i: boolean;
  s: boolean;
  m: boolean;
  U: boolean;
}

const isWord = (c: number) => (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 95;
const isDigit = (c: number) => c >= 48 && c <= 57;
const isSpace = (c: number) => c === 32 || (c >= 9 && c <= 13);

function foldCase(c: number): number {
  if (c < 128) return c >= 65 && c <= 90 ? c + 32 : c;
  const s = String.fromCodePoint(c).toLowerCase();
  return s.length <= 2 ? (s.codePointAt(0) as number) : c;
}

const POSIX: Record<string, CharTest> = {
  alnum: (c) => (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122),
  alpha: (c) => (c >= 65 && c <= 90) || (c >= 97 && c <= 122),
  ascii: (c) => c < 128,
  blank: (c) => c === 32 || c === 9,
  cntrl: (c) => c < 32 || c === 127,
  digit: isDigit,
  graph: (c) => c > 32 && c < 127,
  lower: (c) => c >= 97 && c <= 122,
  print: (c) => c >= 32 && c < 127,
  punct: (c) => (c > 32 && c < 48) || (c > 57 && c < 65) || (c > 90 && c < 97) || (c > 122 && c < 127),
  space: isSpace,
  upper: (c) => c >= 65 && c <= 90,
  word: isWord,
  xdigit: (c) => isDigit(c) || (c >= 65 && c <= 70) || (c >= 97 && c <= 102),
};

const UNICODE_CLASSES: Record<string, RegExp> = {
  L: /^\p{L}$/u, Lu: /^\p{Lu}$/u, Ll: /^\p{Ll}$/u, N: /^\p{N}$/u, Nd: /^\p{Nd}$/u,
  P: /^\p{P}$/u, S: /^\p{S}$/u, Z: /^\p{Z}$/u, Latin: /^\p{Script=Latin}$/u, Greek: /^\p{Script=Greek}$/u,
  Cyrillic: /^\p{Script=Cyrillic}$/u, Hebrew: /^\p{Script=Hebrew}$/u, Arabic: /^\p{Script=Arabic}$/u, Han: /^\p{Script=Han}$/u,
};

class RegexParser {
  private i = 0;
  private flags: Flags;
  private nest = 0;
  groups = 0;
  names = new Map<string, number>();
  private readonly cps: number[];

  constructor(src: string, flags: Partial<Flags>) {
    this.cps = Array.from(src, (c) => c.codePointAt(0) as number);
    this.flags = { i: false, s: false, m: false, U: false, ...flags };
  }

  parse(): Node {
    const n = this.alt();
    if (this.i < this.cps.length) throw new RegexError("unexpected )");
    return n;
  }

  private peek(): number | undefined {
    return this.cps[this.i];
  }

  private ch(s: string): boolean {
    return this.cps[this.i] === s.codePointAt(0);
  }

  private eat(s: string): boolean {
    if (this.ch(s)) {
      this.i++;
      return true;
    }
    return false;
  }

  private alt(): Node {
    if (++this.nest > MAX_NEST) throw new RegexError("regex too deeply nested");
    const saved = { ...this.flags };
    const items: Node[] = [this.cat()];
    while (this.eat("|")) items.push(this.cat());
    this.flags = saved;
    this.nest--;
    return items.length === 1 ? items[0] : { t: "alt", items };
  }

  private cat(): Node {
    const items: Node[] = [];
    while (this.i < this.cps.length && !this.ch("|") && !this.ch(")")) {
      const atom = this.repeat();
      if (atom) items.push(atom);
    }
    if (items.length === 0) return { t: "empty" };
    return items.length === 1 ? items[0] : { t: "cat", items };
  }

  private repeat(): Node | null {
    let node = this.atom();
    while (node) {
      let min: number;
      let max: number;
      if (this.eat("*")) { min = 0; max = Infinity; }
      else if (this.eat("+")) { min = 1; max = Infinity; }
      else if (this.eat("?")) { min = 0; max = 1; }
      else if (this.ch("{")) {
        const bounds = this.braces();
        if (!bounds) break;
        [min, max] = bounds;
      } else break;
      let greedy = !this.flags.U;
      if (this.eat("?")) greedy = !greedy;
      if (this.ch("*") || this.ch("+")) throw new RegexError("invalid nested repetition operator");
      node = { t: "rep", node, min, max, greedy };
    }
    return node;
  }

  private braces(): [number, number] | null {
    const start = this.i;
    this.i++;
    const num = (): number | null => {
      const s = this.i;
      while (isDigit(this.peek() ?? 0)) this.i++;
      return this.i === s ? null : Number(String.fromCodePoint(...this.cps.slice(s, this.i)));
    };
    const min = num();
    let max: number | null = min;
    if (min !== null && this.eat(",")) {
      max = this.ch("}") ? Infinity : num();
    }
    if (min === null || max === null || !this.eat("}")) {
      this.i = start;
      return null;
    }
    if (min > MAX_REPEAT || (max !== Infinity && max > MAX_REPEAT) || min > max) {
      throw new RegexError("invalid repeat count");
    }
    return [min, max];
  }

  private atom(): Node | null {
    const c = this.cps[this.i];
    if (c === 40) return this.group();
    if (c === 91) return this.charClass();
    if (c === 46) {
      this.i++;
      return { t: "any", dotall: this.flags.s };
    }
    if (c === 94) {
      this.i++;
      return { t: "assert", kind: this.flags.m ? "bol" : "bot" };
    }
    if (c === 36) {
      this.i++;
      return { t: "assert", kind: this.flags.m ? "eol" : "eot" };
    }
    if (c === 92) return this.escape();
    if (c === 42 || c === 43 || c === 63) throw new RegexError("missing argument to repetition operator");
    this.i++;
    return this.literal(c);
  }

  private literal(c: number): Node {
    return this.flags.i ? { t: "char", c: foldCase(c), fold: true } : { t: "char", c, fold: false };
  }

  private group(): Node | null {
    this.i++;
    if (!this.eat("?")) {
      const index = ++this.groups;
      const node = this.alt();
      if (!this.eat(")")) throw new RegexError("missing closing )");
      return { t: "group", node, index };
    }
    if (this.ch("=") || this.ch("!")) throw new RegexError("invalid or unsupported Perl syntax: lookahead is not available in RE2");
    if (this.ch("<") || this.ch("P")) {
      const look = this.cps[this.i + 1];
      if (this.ch("<") && (look === 61 || look === 33)) throw new RegexError("invalid or unsupported Perl syntax: lookbehind is not available in RE2");
      this.i += this.ch("P") ? 2 : 1;
      const start = this.i;
      while (this.i < this.cps.length && !this.ch(">")) this.i++;
      const name = String.fromCodePoint(...this.cps.slice(start, this.i));
      if (!this.eat(">") || name === "") throw new RegexError("invalid named capture group");
      const index = ++this.groups;
      this.names.set(name, index);
      const node = this.alt();
      if (!this.eat(")")) throw new RegexError("missing closing )");
      return { t: "group", node, index };
    }
    let on = true;
    const next: Flags = { ...this.flags };
    for (;;) {
      const c = this.peek();
      if (c === undefined) throw new RegexError("missing closing )");
      this.i++;
      const ch = String.fromCodePoint(c);
      if (ch === ":" || ch === ")") {
        if (ch === ")") {
          this.flags = next;
          return null;
        }
        const saved = this.flags;
        this.flags = next;
        const node = this.alt();
        this.flags = saved;
        if (!this.eat(")")) throw new RegexError("missing closing )");
        return node;
      }
      if (ch === "-") on = false;
      else if (ch === "i" || ch === "s" || ch === "m" || ch === "U") next[ch] = on;
      else throw new RegexError(`invalid or unsupported Perl syntax: (?${ch}`);
    }
  }

  /** The code point of a single-character escape, or null when `\x` is a class such as \d. */
  private escapeChar(c: number): number | null {
    const s = String.fromCodePoint(c);
    switch (s) {
      case "n": return 10;
      case "t": return 9;
      case "r": return 13;
      case "f": return 12;
      case "v": return 11;
      case "a": return 7;
      case "x": {
        if (this.eat("{")) {
          const start = this.i;
          while (this.i < this.cps.length && !this.ch("}")) this.i++;
          const hex = String.fromCodePoint(...this.cps.slice(start, this.i));
          if (!this.eat("}") || !/^[0-9a-fA-F]{1,6}$/.test(hex)) throw new RegexError("invalid escape sequence");
          return parseInt(hex, 16);
        }
        const hex = String.fromCodePoint(...this.cps.slice(this.i, this.i + 2));
        if (!/^[0-9a-fA-F]{2}$/.test(hex)) throw new RegexError("invalid escape sequence");
        this.i += 2;
        return parseInt(hex, 16);
      }
      default:
        return null;
    }
  }

  private classEscape(c: number): CharTest | null {
    switch (String.fromCodePoint(c)) {
      case "d": return isDigit;
      case "D": return (x) => !isDigit(x);
      case "w": return isWord;
      case "W": return (x) => !isWord(x);
      case "s": return isSpace;
      case "S": return (x) => !isSpace(x);
      case "p":
      case "P": {
        const neg = c === 80;
        let name: string;
        if (this.eat("{")) {
          const start = this.i;
          while (this.i < this.cps.length && !this.ch("}")) this.i++;
          name = String.fromCodePoint(...this.cps.slice(start, this.i));
          if (!this.eat("}")) throw new RegexError("invalid character class range");
        } else {
          name = String.fromCodePoint(this.cps[this.i++] ?? 63);
        }
        const re = UNICODE_CLASSES[name];
        if (!re) throw new RegexError(`invalid character class range: \\p{${name}}`);
        return neg ? (x) => !re.test(String.fromCodePoint(x)) : (x) => re.test(String.fromCodePoint(x));
      }
      default:
        return null;
    }
  }

  private escape(): Node {
    this.i++;
    const c = this.peek();
    if (c === undefined) throw new RegexError("trailing backslash at end of expression");
    this.i++;
    const s = String.fromCodePoint(c);
    if (s === "b") return { t: "assert", kind: "wb" };
    if (s === "B") return { t: "assert", kind: "nwb" };
    if (s === "A") return { t: "assert", kind: "bot" };
    if (s === "z") return { t: "assert", kind: "eot" };
    if (s === "Q") {
      const items: Node[] = [];
      while (this.i < this.cps.length) {
        if (this.ch("\\") && this.cps[this.i + 1] === 69) {
          this.i += 2;
          break;
        }
        items.push(this.literal(this.cps[this.i++]));
      }
      return { t: "cat", items };
    }
    if (isDigit(c)) {
      if (c === 48) return this.literal(0);
      throw new RegexError("invalid escape sequence: backreferences are not available in RE2");
    }
    const test = this.classEscape(c);
    if (test) return { t: "class", test };
    const code = this.escapeChar(c);
    if (code !== null) return this.literal(code);
    if (isWord(c)) throw new RegexError(`invalid escape sequence: \\${s}`);
    return this.literal(c);
  }

  private charClass(): Node {
    this.i++;
    const negate = this.eat("^");
    const ranges: [number, number][] = [];
    const tests: CharTest[] = [];
    let first = true;
    for (;;) {
      const c = this.peek();
      if (c === undefined) throw new RegexError("missing closing ]");
      if (c === 93 && !first) {
        this.i++;
        break;
      }
      first = false;
      if (c === 91 && this.cps[this.i + 1] === 58) {
        let end = this.i + 2;
        while (end < this.cps.length && !(this.cps[end] === 58 && this.cps[end + 1] === 93)) end++;
        if (end < this.cps.length) {
          let name = String.fromCodePoint(...this.cps.slice(this.i + 2, end));
          const neg = name.startsWith("^");
          if (neg) name = name.slice(1);
          const test = POSIX[name];
          if (!test) throw new RegexError(`invalid character class range: [:${name}:]`);
          tests.push(neg ? (x) => !test(x) : test);
          this.i = end + 2;
          continue;
        }
      }
      const lo = this.classAtom(tests);
      if (lo === null) continue;
      if (this.ch("-") && this.cps[this.i + 1] !== 93 && this.cps[this.i + 1] !== undefined) {
        this.i++;
        const hi = this.classAtom(tests);
        if (hi === null) throw new RegexError("invalid character class range");
        if (hi < lo) throw new RegexError("invalid character class range");
        ranges.push([lo, hi]);
      } else ranges.push([lo, lo]);
    }
    const fold = this.flags.i;
    const inRanges = (x: number) => {
      for (const [lo, hi] of ranges) if (x >= lo && x <= hi) return true;
      for (const t of tests) if (t(x)) return true;
      return false;
    };
    const match: CharTest = fold
      ? (x) => {
          if (inRanges(x)) return true;
          const s = String.fromCodePoint(x);
          const lower = s.toLowerCase().codePointAt(0) as number;
          const upper = s.toUpperCase().codePointAt(0) as number;
          return inRanges(lower) || inRanges(upper);
        }
      : inRanges;
    return { t: "class", test: negate ? (x) => !match(x) : match };
  }

  private classAtom(tests: CharTest[]): number | null {
    const c = this.cps[this.i++];
    if (c !== 92) return c;
    const e = this.peek();
    if (e === undefined) throw new RegexError("trailing backslash at end of expression");
    this.i++;
    const test = this.classEscape(e);
    if (test) {
      tests.push(test);
      return null;
    }
    if (String.fromCodePoint(e) === "b") return 8;
    const code = this.escapeChar(e);
    if (code !== null) return code;
    return e;
  }
}

const enum Op { Char, Any, Class, Split, Jmp, Save, Assert, Match }

interface Inst {
  op: Op;
  x: number;
  y: number;
  c: number;
  fold: boolean;
  dotall: boolean;
  test?: CharTest;
  assert?: AssertKind;
}

function compile(root: Node): Inst[] {
  const prog: Inst[] = [];
  const emit = (op: Op, extra: Partial<Inst> = {}): number => {
    if (prog.length >= MAX_PROGRAM) throw new RegexError("expression too large");
    prog.push({ op, x: 0, y: 0, c: 0, fold: false, dotall: false, ...extra });
    return prog.length - 1;
  };
  const gen = (n: Node): void => {
    charge(1);
    switch (n.t) {
      case "empty":
        return;
      case "char":
        emit(Op.Char, { c: n.c, fold: n.fold });
        return;
      case "any":
        emit(Op.Any, { dotall: n.dotall });
        return;
      case "class":
        emit(Op.Class, { test: n.test });
        return;
      case "assert":
        emit(Op.Assert, { assert: n.kind });
        return;
      case "cat":
        n.items.forEach(gen);
        return;
      case "group":
        emit(Op.Save, { c: n.index * 2 });
        gen(n.node);
        emit(Op.Save, { c: n.index * 2 + 1 });
        return;
      case "alt": {
        const jumps: number[] = [];
        n.items.forEach((item, idx) => {
          if (idx < n.items.length - 1) {
            const split = emit(Op.Split);
            prog[split].x = prog.length;
            gen(item);
            jumps.push(emit(Op.Jmp));
            prog[split].y = prog.length;
          } else gen(item);
        });
        for (const j of jumps) prog[j].x = prog.length;
        return;
      }
      case "rep": {
        for (let i = 0; i < n.min; i++) gen(n.node);
        if (n.max === Infinity) {
          const split = emit(Op.Split);
          const body = prog.length;
          gen(n.node);
          const jmp = emit(Op.Jmp);
          prog[jmp].x = split;
          setSplit(prog[split], body, prog.length, n.greedy);
        } else {
          const splits: number[] = [];
          for (let i = n.min; i < n.max; i++) {
            const split = emit(Op.Split);
            splits.push(split);
            prog[split].x = prog.length;
            gen(n.node);
          }
          for (const s of splits) setSplit(prog[s], prog[s].x, prog.length, n.greedy);
        }
        return;
      }
    }
  };
  gen({ t: "group", node: root, index: 0 });
  emit(Op.Match);
  return prog;
}

function setSplit(inst: Inst, body: number, exit: number, greedy: boolean): void {
  inst.x = greedy ? body : exit;
  inst.y = greedy ? exit : body;
}

/** A thread list in priority order. Parallel typed arrays, so a step allocates nothing unless captures change. */
interface ThreadList {
  pcs: Int32Array;
  caps: (number[] | null)[];
  size: number;
  mark: Int32Array;
  gen: number;
}

function threadList(n: number): ThreadList {
  return { pcs: new Int32Array(n), caps: new Array<number[] | null>(n).fill(null), size: 0, mark: new Int32Array(n), gen: 0 };
}

export class Regex {
  readonly groupCount: number;
  readonly groupNames: ReadonlyMap<string, number>;
  private readonly prog: Inst[];
  private a: ThreadList;
  private b: ThreadList;
  private readonly stackPc: Int32Array;
  private readonly stackCaps: (number[] | null)[];

  constructor(source: string, flags: Partial<Flags> = {}) {
    const parser = new RegexParser(source, flags);
    const root = parser.parse();
    this.groupCount = parser.groups;
    this.groupNames = parser.names;
    this.prog = compile(root);
    const n = this.prog.length;
    this.a = threadList(n);
    this.b = threadList(n);
    this.stackPc = new Int32Array(2 * n + 2);
    this.stackCaps = new Array<number[] | null>(2 * n + 2).fill(null);
  }

  test(s: string): boolean {
    return this.run(s, 0, false) !== null;
  }

  /** Leftmost-first match from `start`. Returns capture offsets [s0, e0, s1, e1, ...], -1 for unset groups. */
  exec(s: string, start = 0): number[] | null {
    return this.run(s, start, true);
  }

  /** Follows empty transitions from pc0. Each pc is visited once per step, which bounds the work and ends empty loops. */
  private add(list: ThreadList, pc0: number, caps0: number[] | null, s: string, pos: number, track: boolean): void {
    const prog = this.prog;
    const { stackPc, stackCaps } = this;
    const { mark, gen, pcs, caps: listCaps } = list;
    let top = 0;
    stackPc[0] = pc0;
    stackCaps[0] = caps0;
    top = 1;
    let steps = 1;
    while (top > 0) {
      top--;
      const pc = stackPc[top];
      const caps = stackCaps[top];
      if (mark[pc] === gen) continue;
      mark[pc] = gen;
      steps++;
      const inst = prog[pc];
      switch (inst.op) {
        case Op.Jmp:
          stackPc[top] = inst.x;
          stackCaps[top++] = caps;
          break;
        case Op.Split:
          stackPc[top] = inst.y;
          stackCaps[top++] = caps;
          stackPc[top] = inst.x;
          stackCaps[top++] = caps;
          break;
        case Op.Save: {
          let next = caps;
          if (track && caps) {
            next = caps.slice();
            next[inst.c] = pos;
          }
          stackPc[top] = pc + 1;
          stackCaps[top++] = next;
          break;
        }
        case Op.Assert:
          if (assertAt(inst.assert as AssertKind, s, pos)) {
            stackPc[top] = pc + 1;
            stackCaps[top++] = caps;
          }
          break;
        default:
          pcs[list.size] = pc;
          listCaps[list.size++] = caps;
      }
    }
    charge(steps);
  }

  private run(s: string, start: number, track: boolean): number[] | null {
    const prog = this.prog;
    const slots = (this.groupCount + 1) * 2;
    let clist = this.a;
    let nlist = this.b;
    clist.size = 0;
    nlist.size = 0;
    clist.gen++;
    let matched: number[] | null = null;
    let found = false;
    const blank = track ? new Array<number>(slots).fill(-1) : null;
    let pos = start;
    for (;;) {
      if (!found) this.add(clist, 0, blank, s, pos, track);
      if (clist.size === 0 && (found || pos >= s.length)) break;
      const c = pos < s.length ? (s.codePointAt(pos) as number) : -1;
      const step = c > 0xffff ? 2 : 1;
      nlist.gen++;
      nlist.size = 0;
      charge(clist.size + 1);
      const size = clist.size;
      for (let k = 0; k < size; k++) {
        const pc = clist.pcs[k];
        const inst = prog[pc];
        let advance = false;
        switch (inst.op) {
          case Op.Char:
            advance = c >= 0 && (inst.fold ? foldCase(c) === inst.c : c === inst.c);
            break;
          case Op.Any:
            advance = c >= 0 && (inst.dotall || c !== 10);
            break;
          case Op.Class:
            advance = c >= 0 && (inst.test as CharTest)(c);
            break;
          case Op.Match:
            matched = track ? (clist.caps[k] as number[]).slice() : [];
            found = true;
            // Lower-priority threads cannot beat this match.
            k = size;
            break;
        }
        if (advance) this.add(nlist, pc + 1, clist.caps[k], s, pos + step, track);
      }
      if (c < 0) break;
      const t = clist;
      clist = nlist;
      nlist = t;
      pos += step;
    }
    this.a = clist;
    this.b = nlist;
    return matched;
  }
}

function assertAt(kind: AssertKind, s: string, pos: number): boolean {
  switch (kind) {
    case "bot":
      return pos === 0;
    case "eot":
      return pos === s.length;
    case "bol":
      return pos === 0 || s.charCodeAt(pos - 1) === 10;
    case "eol":
      return pos === s.length || s.charCodeAt(pos) === 10;
    case "wb":
    case "nwb": {
      const before = pos > 0 && isWord(s.charCodeAt(pos - 1));
      const after = pos < s.length && isWord(s.charCodeAt(pos));
      return kind === "wb" ? before !== after : before === after;
    }
  }
}

const cache = new Map<string, Regex>();

export function compileRegex(source: string, flags: Partial<Flags> = {}): Regex {
  const key = `${flags.i ? "i" : ""}${flags.s ? "s" : ""}${flags.m ? "m" : ""}${flags.U ? "U" : ""}/${source}`;
  let re = cache.get(key);
  if (!re) {
    re = new Regex(source, flags);
    if (cache.size >= 256) cache.clear();
    cache.set(key, re);
  }
  return re;
}

export function escapeRegex(text: string): string {
  return text.replace(/[\\.+*?()|[\]{}^$]/g, "\\$&");
}
