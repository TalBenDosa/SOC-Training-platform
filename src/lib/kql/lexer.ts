import { KqlFail, lineCol } from "./errors";
import { timespanUnitTicks } from "./values";

export type TokKind = "ident" | "number" | "timespan" | "string" | "raw" | "op" | "eof";

export interface Tok {
  kind: TokKind;
  text: string;
  pos: number;
  end: number;
  /** number: value. timespan: ticks. string: decoded text. raw: text between the parentheses. */
  value?: unknown;
  /** number token that is a real, not a long. */
  real?: boolean;
  /** string token left open at the end of the text, only produced in tolerant mode. */
  open?: boolean;
}

export interface LexResult {
  toks: Tok[];
  comments: { pos: number; end: number }[];
}

const RAW_LITERALS = new Set(["datetime", "date", "timespan", "time", "guid"]);
const HYPHENATED = new Set([
  "project-away", "project-keep", "project-rename", "project-reorder", "project-smart", "mv-expand", "mv-apply",
  "parse-where", "parse-kv", "make-series", "top-nested", "top-hitters", "make_series",
]);
export const NEGATED_WORDS = new Set([
  "has", "has_cs", "hasprefix", "hasprefix_cs", "hassuffix", "hassuffix_cs", "contains", "contains_cs",
  "startswith", "startswith_cs", "endswith", "endswith_cs", "in", "between",
]);

const SYMBOLS2 = ["==", "!=", "=~", "!~", "<>", "<=", ">=", "..", "=>"];

const isIdentStart = (c: number) => (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 95 || c === 36 || c > 127;
const isIdentPart = (c: number) => isIdentStart(c) || (c >= 48 && c <= 57);
const isDigit = (c: number) => c >= 48 && c <= 57;

export function parseFailure(src: string, pos: number, text: string): KqlFail {
  const { line, column } = lineCol(src, pos);
  return new KqlFail(`Query could not be parsed at '${text}' on line [${line},${column}]`, pos);
}

export function lex(src: string, tolerant = false): LexResult {
  const toks: Tok[] = [];
  const comments: { pos: number; end: number }[] = [];
  const n = src.length;
  let i = 0;

  const fail = (pos: number, text: string): never => {
    throw parseFailure(src, pos, text);
  };

  const readQuoted = (start: number, quote: number, verbatim: boolean): void => {
    let j = i;
    let value = "";
    for (;;) {
      if (j >= n || (src.charCodeAt(j) === 10 && !verbatim)) {
        if (!tolerant) throw new KqlFail(`Unterminated string literal, opened on line ${lineCol(src, start).line}`, start);
        toks.push({ kind: "string", text: src.slice(start, j), pos: start, end: j, value, open: true });
        i = j;
        return;
      }
      const c = src.charCodeAt(j);
      if (c === quote) {
        if (verbatim && src.charCodeAt(j + 1) === quote) {
          value += src[j];
          j += 2;
          continue;
        }
        break;
      }
      if (c === 92 && !verbatim) {
        const e = src[j + 1];
        j += 2;
        switch (e) {
          case "n": value += "\n"; break;
          case "t": value += "\t"; break;
          case "r": value += "\r"; break;
          case "a": value += "\u0007"; break;
          case "b": value += "\b"; break;
          case "f": value += "\f"; break;
          case "v": value += "\v"; break;
          case "0": value += "\0"; break;
          case "u":
          case "x": {
            const len = e === "u" ? 4 : 2;
            const hex = src.slice(j, j + len);
            if (/^[0-9a-fA-F]+$/.test(hex) && hex.length === len) {
              value += String.fromCharCode(parseInt(hex, 16));
              j += len;
            } else value += e;
            break;
          }
          case undefined:
            break;
          default:
            value += e;
        }
        continue;
      }
      value += src[j];
      j++;
    }
    i = j + 1;
    toks.push({ kind: "string", text: src.slice(start, i), pos: start, end: i, value });
  };

  while (i < n) {
    const c = src.charCodeAt(i);
    if (c === 32 || (c >= 9 && c <= 13)) {
      i++;
      continue;
    }
    if (c === 47 && src.charCodeAt(i + 1) === 47) {
      const start = i;
      while (i < n && src.charCodeAt(i) !== 10) i++;
      comments.push({ pos: start, end: i });
      continue;
    }
    const start = i;
    // Verbatim and obfuscated string prefixes: @"", h"", h@""
    if (c === 64 || c === 104 || c === 72) {
      let j = i;
      if (c !== 64) j++;
      const hasAt = src.charCodeAt(j) === 64;
      if (hasAt) j++;
      const q = src.charCodeAt(j);
      if ((q === 34 || q === 39) && (hasAt || c !== 64)) {
        i = j + 1;
        readQuoted(start, q, hasAt);
        continue;
      }
    }
    if (c === 34 || c === 39) {
      i++;
      readQuoted(start, c, false);
      continue;
    }
    if (isDigit(c)) {
      if (c === 48 && (src[i + 1] === "x" || src[i + 1] === "X")) {
        i += 2;
        while (i < n && /[0-9a-fA-F]/.test(src[i])) i++;
        toks.push({ kind: "number", text: src.slice(start, i), pos: start, end: i, value: Number(src.slice(start, i)) });
        continue;
      }
      while (i < n && isDigit(src.charCodeAt(i))) i++;
      let real = false;
      if (src[i] === "." && isDigit(src.charCodeAt(i + 1))) {
        real = true;
        i++;
        while (i < n && isDigit(src.charCodeAt(i))) i++;
      }
      if ((src[i] === "e" || src[i] === "E") && (isDigit(src.charCodeAt(i + 1)) || ((src[i + 1] === "+" || src[i + 1] === "-") && isDigit(src.charCodeAt(i + 2))))) {
        real = true;
        i += 2;
        while (i < n && isDigit(src.charCodeAt(i))) i++;
      }
      const numEnd = i;
      while (i < n && isIdentPart(src.charCodeAt(i))) i++;
      const value = Number(src.slice(start, numEnd));
      if (i > numEnd) {
        const unit = timespanUnitTicks(src.slice(numEnd, i));
        if (unit === undefined) {
          if (!tolerant) fail(start, src.slice(start, i));
          toks.push({ kind: "ident", text: src.slice(start, i), pos: start, end: i });
          continue;
        }
        toks.push({ kind: "timespan", text: src.slice(start, i), pos: start, end: i, value: Math.round(value * unit) });
        continue;
      }
      toks.push({ kind: "number", text: src.slice(start, i), pos: start, end: i, value, real });
      continue;
    }
    if (isIdentStart(c)) {
      i++;
      while (i < n && isIdentPart(src.charCodeAt(i))) i++;
      let word = src.slice(start, i);
      if (src[i] === "-" && isIdentStart(src.charCodeAt(i + 1))) {
        let j = i + 1;
        while (j < n && isIdentPart(src.charCodeAt(j))) j++;
        const joined = src.slice(start, j);
        if (HYPHENATED.has(joined)) {
          word = joined;
          i = j;
        }
      }
      if (word === "in" && src[i] === "~") {
        i++;
        toks.push({ kind: "ident", text: "in~", pos: start, end: i });
        continue;
      }
      if (RAW_LITERALS.has(word)) {
        let j = i;
        while (j < n && (src.charCodeAt(j) === 32 || src.charCodeAt(j) === 9)) j++;
        if (src[j] === "(") {
          let k = j + 1;
          let quote = 0;
          let depth = 1;
          for (; k < n; k++) {
            const d = src.charCodeAt(k);
            if (quote) {
              if (d === quote) quote = 0;
            } else if (d === 34 || d === 39) quote = d;
            else if (d === 40) depth++;
            else if (d === 41 && --depth === 0) break;
          }
          if (k >= n) {
            if (!tolerant) fail(start, word);
            i = n;
            toks.push({ kind: "ident", text: word, pos: start, end: start + word.length });
            continue;
          }
          i = k + 1;
          const inner = src.slice(j + 1, k).trim().replace(/^(['"])(.*)\1$/s, "$2");
          toks.push({ kind: "raw", text: word, pos: start, end: i, value: inner });
          continue;
        }
      }
      toks.push({ kind: "ident", text: word, pos: start, end: i });
      continue;
    }
    if (c === 33) {
      // !has, !contains_cs, !in~ and the rest of the negated word operators.
      let j = i + 1;
      while (j < n && isIdentPart(src.charCodeAt(j))) j++;
      const word = src.slice(i + 1, j);
      if (NEGATED_WORDS.has(word)) {
        i = j;
        if (word === "in" && src[i] === "~") i++;
        toks.push({ kind: "ident", text: src.slice(start, i), pos: start, end: i });
        continue;
      }
    }
    const two = src.slice(i, i + 2);
    if (SYMBOLS2.includes(two)) {
      i += 2;
      toks.push({ kind: "op", text: two, pos: start, end: i });
      continue;
    }
    if ("|()[]{},;:=<>+-*/%.!?".includes(src[i])) {
      i++;
      toks.push({ kind: "op", text: src[start], pos: start, end: i });
      continue;
    }
    if (!tolerant) fail(i, src[i]);
    i++;
    toks.push({ kind: "op", text: src[start], pos: start, end: i });
  }
  toks.push({ kind: "eof", text: "<EOF>", pos: n, end: n });
  return { toks, comments };
}
