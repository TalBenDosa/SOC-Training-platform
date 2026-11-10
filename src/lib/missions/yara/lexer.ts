/**
 * YARA tokenizer. Hex strings and regexes are context-sensitive in YARA (a `{` or
 * `/` right after `=` starts a string value), so the lexer remembers whether the
 * previous token was `=` instead of leaving that to the parser.
 */

export class YaraError extends Error {
  readonly line: number;
  constructor(message: string, line: number) {
    super(message);
    this.line = line;
  }
}

export type TokKind =
  | "id" // identifiers and keywords
  | "strid" // $a, $, $a*, $*
  | "count" // #a
  | "offset" // @a
  | "length" // !a
  | "int"
  | "text" // "..." (bytes already unescaped)
  | "hex" // { ... } body, parsed later
  | "regex" // /.../flags
  | "punct"
  | "eof";

export interface Token {
  kind: TokKind;
  /** Source spelling for ids/puncts/string ids; body for hex/regex. */
  value: string;
  line: number;
  num?: number;
  bytes?: number[];
  flags?: string;
}

/** Longest regex or text literal we accept; keeps compiled programs small. */
const MAX_LITERAL = 1024;

const PUNCT2 = ["..", "==", "!=", "<=", ">=", "<<", ">>"];
const PUNCT1 = "{}()[]:=,<>+-*\\&|^~%.";

const isIdStart = (c: string) => /[A-Za-z_]/.test(c);
const isIdChar = (c: string) => /[A-Za-z0-9_]/.test(c);

export function tokenize(src: string): Token[] {
  const toks: Token[] = [];
  let i = 0;
  let line = 1;
  const n = src.length;

  const push = (t: Token) => toks.push(t);
  const prevIsAssign = () => {
    const p = toks[toks.length - 1];
    return p !== undefined && p.kind === "punct" && p.value === "=";
  };

  while (i < n) {
    const c = src[i];
    if (c === "\n") {
      line++;
      i++;
      continue;
    }
    if (c === " " || c === "\t" || c === "\r") {
      i++;
      continue;
    }
    if (c === "/" && src[i + 1] === "/") {
      while (i < n && src[i] !== "\n") i++;
      continue;
    }
    if (c === "/" && src[i + 1] === "*") {
      const start = line;
      i += 2;
      while (i < n && !(src[i] === "*" && src[i + 1] === "/")) {
        if (src[i] === "\n") line++;
        i++;
      }
      if (i >= n) throw new YaraError("unterminated comment", start);
      i += 2;
      continue;
    }

    if (c === "{" && prevIsAssign()) {
      const start = line;
      let j = i + 1;
      let body = "";
      while (j < n && src[j] !== "}") {
        // Comments are allowed inside hex strings.
        if (src[j] === "/" && src[j + 1] === "/") {
          while (j < n && src[j] !== "\n") j++;
          continue;
        }
        if (src[j] === "/" && src[j + 1] === "*") {
          j += 2;
          while (j < n && !(src[j] === "*" && src[j + 1] === "/")) {
            if (src[j] === "\n") line++;
            j++;
          }
          j += 2;
          continue;
        }
        if (src[j] === "\n") line++;
        body += src[j];
        j++;
      }
      if (j >= n) throw new YaraError("unterminated hex string", start);
      if (body.length > MAX_LITERAL * 4) throw new YaraError("hex string too long", start);
      push({ kind: "hex", value: body, line: start });
      i = j + 1;
      continue;
    }

    if (c === "/" && prevIsAssign()) {
      let j = i + 1;
      let body = "";
      while (j < n && src[j] !== "/") {
        if (src[j] === "\n") throw new YaraError("unterminated regular expression", line);
        if (src[j] === "\\" && j + 1 < n && src[j + 1] !== "\n") {
          // `\/` is an escaped slash; other escapes pass through to the regex engine.
          body += src[j + 1] === "/" ? "/" : src[j] + src[j + 1];
          j += 2;
          continue;
        }
        body += src[j];
        j++;
      }
      if (j >= n) throw new YaraError("unterminated regular expression", line);
      j++;
      let flags = "";
      while (j < n && /[A-Za-z]/.test(src[j])) flags += src[j++];
      if (/[^is]/.test(flags)) throw new YaraError(`invalid regular expression flag "${flags}" (only i and s are supported)`, line);
      if (body.length === 0) throw new YaraError("empty regular expression", line);
      if (body.length > MAX_LITERAL) throw new YaraError("regular expression too long", line);
      push({ kind: "regex", value: body, flags, line });
      i = j;
      continue;
    }

    if (c === '"') {
      const bytes: number[] = [];
      let j = i + 1;
      for (;;) {
        if (j >= n || src[j] === "\n") throw new YaraError("unterminated string", line);
        const ch = src[j];
        if (ch === '"') break;
        if (ch === "\\") {
          const e = src[j + 1];
          if (e === "\\" || e === '"') bytes.push(e.charCodeAt(0));
          else if (e === "n") bytes.push(10);
          else if (e === "t") bytes.push(9);
          else if (e === "r") bytes.push(13);
          else if (e === "x") {
            const h = src.slice(j + 2, j + 4);
            if (!/^[0-9A-Fa-f]{2}$/.test(h)) throw new YaraError("illegal escape sequence", line);
            bytes.push(parseInt(h, 16));
            j += 2;
          } else throw new YaraError(`illegal escape sequence "\\${e ?? ""}"`, line);
          j += 2;
          continue;
        }
        const cp = src.codePointAt(j) as number;
        // Non-ASCII source text becomes its UTF-8 bytes, which is what yara does.
        for (const b of new TextEncoder().encode(String.fromCodePoint(cp))) bytes.push(b);
        j += cp > 0xffff ? 2 : 1;
      }
      if (bytes.length > MAX_LITERAL) throw new YaraError("string too long", line);
      push({ kind: "text", value: src.slice(i, j + 1), bytes, line });
      i = j + 1;
      continue;
    }

    if (c === "$" || c === "#" || c === "@" || (c === "!" && src[i + 1] !== "=")) {
      let j = i + 1;
      while (j < n && isIdChar(src[j])) j++;
      let value = src.slice(i, j);
      if (c === "$" && src[j] === "*") {
        value += "*";
        j++;
      }
      const kind: TokKind = c === "$" ? "strid" : c === "#" ? "count" : c === "@" ? "offset" : "length";
      push({ kind, value, line });
      i = j;
      continue;
    }

    if (/[0-9]/.test(c)) {
      let j = i;
      let num: number;
      if (c === "0" && (src[i + 1] === "x" || src[i + 1] === "X")) {
        j = i + 2;
        while (j < n && /[0-9A-Fa-f]/.test(src[j])) j++;
        if (j === i + 2) throw new YaraError("syntax error, unexpected identifier", line);
        num = parseInt(src.slice(i + 2, j), 16);
      } else {
        while (j < n && /[0-9]/.test(src[j])) j++;
        num = Number(src.slice(i, j));
        if (src.startsWith("KB", j)) {
          num *= 1024;
          j += 2;
        } else if (src.startsWith("MB", j)) {
          num *= 1024 * 1024;
          j += 2;
        }
      }
      if (j < n && isIdChar(src[j])) throw new YaraError(`syntax error, unexpected identifier "${src.slice(i, j + 1)}"`, line);
      if (!Number.isSafeInteger(num)) throw new YaraError("integer is too large", line);
      push({ kind: "int", value: src.slice(i, j), num, line });
      i = j;
      continue;
    }

    if (isIdStart(c)) {
      let j = i;
      while (j < n && isIdChar(src[j])) j++;
      push({ kind: "id", value: src.slice(i, j), line });
      i = j;
      continue;
    }

    const two = src.slice(i, i + 2);
    if (PUNCT2.includes(two)) {
      push({ kind: "punct", value: two, line });
      i += 2;
      continue;
    }
    if (PUNCT1.includes(c)) {
      push({ kind: "punct", value: c, line });
      i++;
      continue;
    }
    throw new YaraError(`syntax error, unexpected character '${c}'`, line);
  }
  push({ kind: "eof", value: "", line });
  return toks;
}

/** How a token is named in "syntax error, unexpected ..." messages. */
export function describe(t: Token): string {
  switch (t.kind) {
    case "eof":
      return "end of file";
    case "id":
      return KEYWORDS.has(t.value) ? `"${t.value}"` : `identifier "${t.value}"`;
    case "int":
      return `integer ${t.value}`;
    case "text":
      return "text string";
    case "hex":
      return "hex string";
    case "regex":
      return "regular expression";
    case "punct":
      return `'${t.value}'`;
    default:
      return `string identifier "${t.value}"`;
  }
}

export const KEYWORDS = new Set([
  "all", "and", "any", "ascii", "at", "base64", "base64wide", "condition", "contains", "defined", "endswith",
  "entrypoint", "false", "filesize", "for", "fullword", "global", "icontains", "iendswith", "iequals", "import",
  "in", "include", "int16", "int16be", "int32", "int32be", "int8", "int8be", "istartswith", "matches", "meta",
  "nocase", "none", "not", "of", "or", "private", "rule", "startswith", "strings", "them", "true", "uint16",
  "uint16be", "uint32", "uint32be", "uint8", "uint8be", "wide", "xor",
]);
