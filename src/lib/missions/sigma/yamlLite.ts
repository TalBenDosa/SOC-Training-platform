/**
 * A deliberately small YAML subset for Sigma rules: block maps, block lists, flow
 * lists, plain/quoted scalars, `|` and `>` block scalars and comments. Anchors,
 * aliases, tags, merge keys and flow maps are rejected outright: they are what
 * makes "billion laughs" style YAML bombs possible, and Sigma rules never need them.
 * Every node keeps its source line so rule errors can point at the right place.
 */

export class YamlError extends Error {
  readonly line: number;
  constructor(message: string, line: number) {
    super(message);
    this.line = line;
  }
}

export type YScalar = { kind: "scalar"; value: string | number | boolean | null; quoted: boolean; line: number };
export type YSeq = { kind: "seq"; items: YNode[]; line: number };
export type YMap = { kind: "map"; entries: { key: string; keyLine: number; value: YNode }[]; line: number };
export type YNode = YScalar | YSeq | YMap;

export const MAX_YAML_BYTES = 32 * 1024;
export const MAX_YAML_DEPTH = 10;

interface Line {
  /** 1-based source line. */
  no: number;
  indent: number;
  /** Text after the indentation (raw, comments not yet stripped). */
  text: string;
  raw: string;
}

const isBlankOrComment = (l: Line) => l.text === "" || l.text.startsWith("#");

/** Resolves a plain scalar the way YAML 1.2 core schema does, minus the exotic forms. */
function plainValue(s: string): string | number | boolean | null {
  if (s === "" || s === "~" || s === "null" || s === "Null" || s === "NULL") return null;
  if (/^(true|True|TRUE)$/.test(s)) return true;
  if (/^(false|False|FALSE)$/.test(s)) return false;
  if (/^[-+]?[0-9]+$/.test(s) && Number.isSafeInteger(Number(s))) return Number(s);
  if (/^0x[0-9A-Fa-f]+$/.test(s)) return parseInt(s.slice(2), 16);
  if (/^[-+]?[0-9]*\.[0-9]+$/.test(s)) return Number(s);
  return s;
}

/** Rejects the YAML features that this subset does not allow, at the start of a value. */
function checkPlainStart(s: string, line: number): void {
  const c = s[0];
  if (c === "&") throw new YamlError("anchors (&name) are not allowed in this console", line);
  if (c === "*") throw new YamlError(`aliases (*name) are not allowed; if '${s}' is a wildcard value, put it in quotes`, line);
  if (c === "!") throw new YamlError("tags (!tag, !!type) are not allowed in this console", line);
  if (c === "{") throw new YamlError("flow mappings ({ ... }) are not supported; use block style (key: value on its own line)", line);
  if (c === "@" || c === "`") throw new YamlError(`a plain value cannot start with '${c}'; put it in quotes`, line);
  if (c === "%") throw new YamlError("YAML directives are not allowed", line);
}

class Parser {
  private i = 0;
  constructor(private readonly lines: Line[]) {}

  private skipBlank(): void {
    while (this.i < this.lines.length && isBlankOrComment(this.lines[this.i])) this.i++;
  }

  private peek(): Line | undefined {
    this.skipBlank();
    return this.lines[this.i];
  }

  parseDocument(): YNode {
    const first = this.peek();
    if (!first) throw new YamlError("the rule is empty", 1);
    if (first.indent !== 0) throw new YamlError("the document must start at column 1", first.no);
    const node = this.block(0, 1);
    const rest = this.peek();
    if (rest) throw new YamlError(`unexpected indentation or content: '${rest.text.slice(0, 40)}'`, rest.no);
    return node;
  }

  private block(indent: number, depth: number): YNode {
    if (depth > MAX_YAML_DEPTH) throw new YamlError(`nesting too deep (max ${MAX_YAML_DEPTH} levels)`, this.peek()?.no ?? 1);
    const l = this.peek() as Line;
    if (l.text === "-" || l.text.startsWith("- ")) return this.seq(indent, depth);
    return this.map(indent, depth);
  }

  private seq(indent: number, depth: number): YSeq {
    const items: YNode[] = [];
    const startLine = (this.peek() as Line).no;
    for (;;) {
      const l = this.peek();
      if (!l || l.indent < indent) break;
      if (l.indent > indent) throw new YamlError("bad indentation of a list item", l.no);
      // A non-dash line ends the list. That is normal when a list sits at its key's
      // own indent and the next key follows it.
      if (!(l.text === "-" || l.text.startsWith("- "))) break;
      const rest = l.text.slice(1).replace(/^ +/, "");
      if (rest === "" || rest.startsWith("#")) {
        this.i++;
        const child = this.peek();
        if (child && child.indent > indent) items.push(this.block(child.indent, depth + 1));
        else items.push({ kind: "scalar", value: null, quoted: false, line: l.no });
        continue;
      }
      const contentIndent = l.indent + (l.text.length - rest.length);
      if (rest.startsWith("- ") || rest === "-" || this.looksLikeKey(rest)) {
        // "- key: value" opens a map whose column is where "key" starts; re-read
        // this line as if it were indented to that column.
        this.lines[this.i] = { ...l, indent: contentIndent, text: rest };
        items.push(this.block(contentIndent, depth + 1));
        continue;
      }
      this.i++;
      items.push(this.inlineValue(rest, l.no, indent, depth + 1));
    }
    return { kind: "seq", items, line: startLine };
  }

  /** True when text starts with `key:` (plain or quoted key) rather than a scalar. */
  private looksLikeKey(text: string): boolean {
    if (text.startsWith('"') || text.startsWith("'")) {
      const q = text[0];
      let j = 1;
      while (j < text.length) {
        if (text[j] === "\\" && q === '"') j += 2;
        else if (text[j] === q && q === "'" && text[j + 1] === "'") j += 2;
        else if (text[j] === q) break;
        else j++;
      }
      return /^\s*:(\s|$)/.test(text.slice(j + 1));
    }
    if (text.startsWith("[") || text.startsWith("{")) return false;
    return this.keyEnd(text) >= 0;
  }

  /** Index of the ':' that ends a plain key, or -1. */
  private keyEnd(text: string): number {
    for (let j = 0; j < text.length; j++) {
      if (text[j] === "#" && j > 0 && /\s/.test(text[j - 1])) return -1;
      if (text[j] === ":" && (j + 1 === text.length || text[j + 1] === " " || text[j + 1] === "\t")) return j;
    }
    return -1;
  }

  private map(indent: number, depth: number): YMap {
    const entries: YMap["entries"] = [];
    const startLine = (this.peek() as Line).no;
    for (;;) {
      const l = this.peek();
      if (!l || l.indent < indent) break;
      if (l.indent > indent) throw new YamlError("bad indentation of a mapping entry", l.no);
      if (l.text === "-" || l.text.startsWith("- ")) throw new YamlError("a list item cannot appear here; check the indentation", l.no);
      if (l.text === "---" || l.text === "...") {
        throw new YamlError("multiple YAML documents (---) are not supported; put one rule per editor", l.no);
      }
      let key: string;
      let rest: string;
      if (l.text.startsWith('"') || l.text.startsWith("'")) {
        const { value, end } = readQuoted(l.text, 0, l.no);
        const after = l.text.slice(end).replace(/^\s*/, "");
        if (!after.startsWith(":")) throw new YamlError("expected ':' after a quoted key", l.no);
        key = value;
        rest = after.slice(1).trim();
      } else {
        if (l.text.startsWith("? ")) throw new YamlError("complex keys ('? ') are not supported", l.no);
        const k = this.keyEnd(l.text);
        if (k < 0) throw new YamlError(`expected 'key: value' but found '${l.text.slice(0, 40)}'`, l.no);
        key = l.text.slice(0, k).trim();
        rest = l.text.slice(k + 1).trim();
        if (key === "<<") throw new YamlError("merge keys (<<) are not allowed in this console", l.no);
        checkPlainStart(key, l.no);
      }
      if (entries.some((e) => e.key === key)) throw new YamlError(`duplicate key '${key}'`, l.no);
      this.i++;

      let value: YNode;
      if (rest === "" || rest.startsWith("#")) {
        const child = this.peek();
        if (child && child.indent > indent) value = this.block(child.indent, depth + 1);
        else if (child && child.indent === indent && (child.text === "-" || child.text.startsWith("- "))) value = this.seq(indent, depth + 1);
        else value = { kind: "scalar", value: null, quoted: false, line: l.no };
      } else value = this.inlineValue(rest, l.no, indent, depth + 1);
      entries.push({ key, keyLine: l.no, value });
    }
    return { kind: "map", entries, line: startLine };
  }

  /** A value written on the same line as its key or dash. */
  private inlineValue(text: string, no: number, parentIndent: number, depth: number): YNode {
    if (depth > MAX_YAML_DEPTH) throw new YamlError(`nesting too deep (max ${MAX_YAML_DEPTH} levels)`, no);
    if (text.startsWith('"') || text.startsWith("'")) {
      const { value, end } = readQuoted(text, 0, no);
      const after = text.slice(end).trim();
      if (after !== "" && !after.startsWith("#")) throw new YamlError(`unexpected text after a quoted value: '${after.slice(0, 30)}'`, no);
      return { kind: "scalar", value, quoted: true, line: no };
    }
    if (text.startsWith("[")) return this.flowList(text, no, depth);
    if (/^[|>][-+]?\s*(#.*)?$/.test(text)) return this.blockScalar(text[0] as "|" | ">", text[1], no, parentIndent);
    checkPlainStart(text, no);
    let plain = stripComment(text);
    // Plain scalars may continue on more-indented lines (folded with a space).
    for (;;) {
      const next = this.lines[this.i];
      if (!next || isBlankOrComment(next) || next.indent <= parentIndent) break;
      if (next.text.startsWith("- ") || this.keyEnd(next.text) >= 0) break;
      plain += " " + stripComment(next.text);
      this.i++;
    }
    return { kind: "scalar", value: plainValue(plain), quoted: false, line: no };
  }

  private flowList(text: string, no: number, depth: number): YSeq {
    const items: YNode[] = [];
    let j = 1;
    const skipWs = () => {
      while (text[j] === " " || text[j] === "\t") j++;
    };
    skipWs();
    if (text[j] === "]") j++;
    else {
      for (;;) {
        skipWs();
        const c = text[j];
        if (c === undefined) throw new YamlError("a flow list [ ... ] must close on the same line", no);
        if (c === "[") throw new YamlError("nested flow lists are not supported", no);
        if (c === '"' || c === "'") {
          const q = readQuoted(text, j, no);
          items.push({ kind: "scalar", value: q.value, quoted: true, line: no });
          j = q.end;
        } else {
          let k = j;
          while (k < text.length && text[k] !== "," && text[k] !== "]") k++;
          const raw = text.slice(j, k).trim();
          if (raw === "") throw new YamlError("empty item in a flow list", no);
          checkPlainStart(raw, no);
          items.push({ kind: "scalar", value: plainValue(raw), quoted: false, line: no });
          j = k;
        }
        skipWs();
        if (text[j] === ",") {
          j++;
          continue;
        }
        if (text[j] === "]") {
          j++;
          break;
        }
        throw new YamlError("expected ',' or ']' in a flow list", no);
      }
    }
    const after = text.slice(j).trim();
    if (after !== "" && !after.startsWith("#")) throw new YamlError(`unexpected text after a flow list: '${after.slice(0, 30)}'`, no);
    if (depth > MAX_YAML_DEPTH) throw new YamlError(`nesting too deep (max ${MAX_YAML_DEPTH} levels)`, no);
    return { kind: "seq", items, line: no };
  }

  private blockScalar(style: "|" | ">", chomp: string | undefined, no: number, parentIndent: number): YScalar {
    const body: string[] = [];
    let blockIndent = -1;
    while (this.i < this.lines.length) {
      const l = this.lines[this.i];
      if (l.text === "") {
        body.push("");
        this.i++;
        continue;
      }
      if (l.indent <= parentIndent) break;
      if (blockIndent < 0) blockIndent = l.indent;
      if (l.indent < blockIndent) break;
      body.push(l.raw.slice(blockIndent));
      this.i++;
    }
    while (body.length && body[body.length - 1] === "") body.pop();
    let value: string;
    if (style === "|") value = body.join("\n");
    else {
      // Folded: single newlines become spaces, blank lines stay as newlines.
      value = "";
      for (let k = 0; k < body.length; k++) {
        if (body[k] === "") value += "\n";
        else value += (k > 0 && body[k - 1] !== "" ? " " : "") + body[k];
      }
    }
    if (chomp !== "-" && value !== "") value += "\n";
    return { kind: "scalar", value, quoted: true, line: no };
  }
}

function stripComment(text: string): string {
  for (let j = 0; j < text.length; j++) {
    if (text[j] === "#" && (j === 0 || text[j - 1] === " " || text[j - 1] === "\t")) return text.slice(0, j).trimEnd();
  }
  return text.trimEnd();
}

/** Reads a single-line quoted scalar starting at `start`; returns the value and the index after the closing quote. */
function readQuoted(text: string, start: number, no: number): { value: string; end: number } {
  const q = text[start];
  let j = start + 1;
  let out = "";
  for (;;) {
    if (j >= text.length) throw new YamlError("unterminated quoted string (quoted values must end on the same line)", no);
    const c = text[j];
    if (q === "'") {
      if (c === "'") {
        if (text[j + 1] === "'") {
          out += "'";
          j += 2;
          continue;
        }
        return { value: out, end: j + 1 };
      }
      out += c;
      j++;
      continue;
    }
    if (c === '"') return { value: out, end: j + 1 };
    if (c === "\\") {
      const e = text[j + 1];
      const simple: Record<string, string> = { n: "\n", t: "\t", r: "\r", "0": "\0", '"': '"', "\\": "\\", "/": "/", " ": " " };
      if (e !== undefined && e in simple) {
        out += simple[e];
        j += 2;
        continue;
      }
      const len = e === "x" ? 2 : e === "u" ? 4 : 0;
      const hex = text.slice(j + 2, j + 2 + len);
      if (len && new RegExp(`^[0-9A-Fa-f]{${len}}$`).test(hex)) {
        out += String.fromCharCode(parseInt(hex, 16));
        j += 2 + len;
        continue;
      }
      throw new YamlError(`invalid escape '\\${e ?? ""}' in a double-quoted string; use single quotes for Windows paths`, no);
    }
    out += c;
    j++;
  }
}

/** Parses one YAML document into a node tree. Throws YamlError with a line number. */
export function parseYaml(source: string): YNode {
  if (source.length > MAX_YAML_BYTES) throw new YamlError(`input too large (max ${MAX_YAML_BYTES / 1024} KB)`, 1);
  const rawLines = source.replace(/\r\n?/g, "\n").split("\n");
  const lines: Line[] = [];
  let sawContent = false;
  rawLines.forEach((raw, idx) => {
    const no = idx + 1;
    const m = /^[ \t]*/.exec(raw) as RegExpExecArray;
    const lead = m[0];
    const text = raw.slice(lead.length).trimEnd();
    if (lead.includes("\t") && text !== "") throw new YamlError("tab characters are not allowed in indentation; use spaces", no);
    if (lead.length === 0 && (text === "---" || text.startsWith("--- "))) {
      if (sawContent) throw new YamlError("multiple YAML documents (---) are not supported; put one rule per editor", no);
      return; // a leading document marker is harmless
    }
    if (lead.length === 0 && text === "...") throw new YamlError("document end markers (...) are not supported", no);
    if (text !== "" && !text.startsWith("#")) sawContent = true;
    lines.push({ no, indent: lead.length, text, raw });
  });
  return new Parser(lines).parseDocument();
}

/** Converts a node tree into plain JS values (maps become objects). */
export function toPlain(node: YNode): unknown {
  if (node.kind === "scalar") return node.value;
  if (node.kind === "seq") return node.items.map(toPlain);
  const out: Record<string, unknown> = {};
  for (const e of node.entries) out[e.key] = toPlain(e.value);
  return out;
}
