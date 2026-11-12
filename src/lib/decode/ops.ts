/**
 * Decode operations for the analyst's Decoder (demo feedback 2026-11: "add a CyberChef-like
 * helper for Base64, URL and so on, so we don't copy values out of the platform").
 *
 * Pure and synchronous except the decompressors (DecompressionStream). Every op returns a
 * result object instead of throwing, so a bad input shows a reason, never a crash. Bytes are
 * shown as text when they are text: UTF-8, or UTF-16LE (PowerShell -EncodedCommand), which is
 * detected by its zero bytes.
 */

export type OpResult = { ok: true; out: string; note?: string } | { ok: false; error: string };

export interface DecodeOp {
  id: string;
  label: string;
  /** One line: what it does and when to use it. */
  help: string;
  run: (input: string) => OpResult | Promise<OpResult>;
}

const MAX_INPUT = 200_000;

function bytesToText(bytes: Uint8Array): { text: string; note?: string } {
  // UTF-16LE: every second byte zero on ASCII text (PowerShell -EncodedCommand).
  if (bytes.length >= 4) {
    let zeros = 0;
    for (let i = 1; i < bytes.length; i += 2) if (bytes[i] === 0) zeros++;
    if (zeros >= Math.floor(bytes.length / 2) * 0.9) {
      return { text: new TextDecoder("utf-16le").decode(bytes), note: "Decoded as UTF-16LE (the encoding PowerShell -EncodedCommand uses)." };
    }
  }
  const utf8 = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  const bad = (utf8.match(/�/g) ?? []).length;
  if (bad > 0 && bad / Math.max(1, utf8.length) > 0.05) {
    return { text: hexOf(bytes), note: "Not text: shown as hex bytes. It may be compressed (try Gunzip) or encrypted." };
  }
  return { text: utf8 };
}

function hexOf(bytes: Uint8Array): string {
  return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join(" ");
}

export function base64ToBytes(input: string): Uint8Array | null {
  let s = input.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
  if (!s || /[^A-Za-z0-9+/=]/.test(s)) return null;
  s = s.replace(/=+$/, "");
  if (s.length % 4 === 1) return null;
  s += "=".repeat((4 - (s.length % 4)) % 4);
  try {
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

function bytesToBase64(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function hexToBytes(input: string): Uint8Array | null {
  const s = input.replace(/0x/gi, "").replace(/\\x/gi, "").replace(/[\s:,-]/g, "");
  if (!s || s.length % 2 || /[^0-9a-f]/i.test(s)) return null;
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

async function decompress(bytes: Uint8Array, format: "gzip" | "deflate" | "deflate-raw"): Promise<Uint8Array> {
  if (typeof DecompressionStream === "undefined") throw new Error("This browser cannot decompress.");
  const stream = new Blob([bytes as BlobPart]).stream().pipeThrough(new DecompressionStream(format));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

/** Bytes of the input: Base64 if it parses, else hex if it parses, else the UTF-8 text itself. */
function inputBytes(input: string): Uint8Array {
  return base64ToBytes(input) ?? hexToBytes(input) ?? new TextEncoder().encode(input);
}

const ENTITIES: Record<string, string> = { amp: "&", lt: "<", gt: ">", quot: "\"", apos: "'", nbsp: " " };

export const OPS: DecodeOp[] = [
  {
    id: "ps-enc", label: "PowerShell -enc", help: "Takes the Base64 after -enc / -EncodedCommand out of a command line and decodes it (UTF-16LE).",
    run: input => {
      const blob = encodedCommandOf(` ${input}`) ?? input.trim();
      const bytes = base64ToBytes(blob);
      if (!bytes) return { ok: false, error: "No -enc / -EncodedCommand Base64 found in this command line." };
      const { text, note } = bytesToText(bytes);
      return { ok: true, out: text, note };
    },
  },
  {
    id: "from-base64", label: "From Base64", help: "Base64 or Base64URL to text. UTF-16LE (PowerShell -EncodedCommand) is detected.",
    run: input => {
      const bytes = base64ToBytes(input);
      if (!bytes) return { ok: false, error: "Not valid Base64: only A-Z, a-z, 0-9, +, / (or - and _) and = padding." };
      const { text, note } = bytesToText(bytes);
      return { ok: true, out: text, note };
    },
  },
  {
    id: "to-base64", label: "To Base64", help: "Text to Base64 (UTF-8).",
    run: input => ({ ok: true, out: bytesToBase64(new TextEncoder().encode(input)) }),
  },
  {
    id: "url-decode", label: "URL decode", help: "%2F, %3A and + back to characters. Run it twice for double-encoded input.",
    run: input => {
      try { return { ok: true, out: decodeURIComponent(input.replace(/\+/g, " ")) }; }
      catch { return { ok: false, error: "Broken % sequence: a % must be followed by two hex digits." }; }
    },
  },
  {
    id: "url-encode", label: "URL encode", help: "Characters to %XX.",
    run: input => ({ ok: true, out: encodeURIComponent(input) }),
  },
  {
    id: "from-hex", label: "From hex", help: "41 42 43, 0x41, \\x41 or 414243 to text.",
    run: input => {
      const bytes = hexToBytes(input);
      if (!bytes) return { ok: false, error: "Not hex: an even number of 0-9 and a-f digits." };
      const { text, note } = bytesToText(bytes);
      return { ok: true, out: text, note };
    },
  },
  {
    id: "to-hex", label: "To hex", help: "Text to hex bytes.",
    run: input => ({ ok: true, out: hexOf(new TextEncoder().encode(input)) }),
  },
  {
    id: "html-entities", label: "HTML entities", help: "&lt;script&gt;, &#x3c; and &#60; back to characters.",
    run: input => ({
      ok: true,
      out: input
        .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)))
        .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(parseInt(d, 10)))
        .replace(/&([a-z]+);/gi, (m, n) => ENTITIES[n.toLowerCase()] ?? m),
    }),
  },
  {
    id: "unicode-escapes", label: "Unescape \\u / \\x", help: "\\u0041, \\x41 and \\n escapes (JavaScript, JSON, PowerShell strings).",
    run: input => ({
      ok: true,
      out: input
        .replace(/\\u\{([0-9a-f]+)\}/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)))
        .replace(/\\u([0-9a-f]{4})/gi, (_, h) => String.fromCharCode(parseInt(h, 16)))
        .replace(/\\x([0-9a-f]{2})/gi, (_, h) => String.fromCharCode(parseInt(h, 16)))
        .replace(/\\n/g, "\n").replace(/\\r/g, "\r").replace(/\\t/g, "\t"),
    }),
  },
  {
    id: "gunzip", label: "Gunzip", help: "Gzip bytes (as Base64 or hex) to text. Starts with H4sI in Base64, 1f 8b in hex.",
    run: async input => {
      try { const { text, note } = bytesToText(await decompress(inputBytes(input), "gzip")); return { ok: true, out: text, note }; }
      catch { return { ok: false, error: "Not gzip data. Gzip starts with H4sI in Base64 or 1f 8b in hex." }; }
    },
  },
  {
    id: "inflate", label: "Inflate (raw deflate)", help: "Raw deflate (PowerShell [IO.Compression.DeflateStream]) to text.",
    run: async input => {
      const bytes = inputBytes(input);
      for (const f of ["deflate-raw", "deflate"] as const) {
        try { const { text, note } = bytesToText(await decompress(bytes, f)); return { ok: true, out: text, note }; } catch { /* try the next */ }
      }
      return { ok: false, error: "Not deflate data." };
    },
  },
  {
    id: "rot13", label: "ROT13", help: "Letters rotated by 13 (used to hide strings in scripts and some registry values).",
    run: input => ({ ok: true, out: input.replace(/[a-z]/gi, c => String.fromCharCode((c <= "Z" ? 65 : 97) + ((c.charCodeAt(0) - (c <= "Z" ? 65 : 97) + 13) % 26))) }),
  },
  {
    id: "reverse", label: "Reverse", help: "Reverse the string (attackers reverse PowerShell to dodge simple matching).",
    run: input => ({ ok: true, out: Array.from(input).reverse().join("") }),
  },
  {
    id: "jwt", label: "JWT decode", help: "Header and payload of a JSON Web Token. The signature is not verified.",
    run: input => {
      const parts = input.trim().split(".");
      if (parts.length < 2) return { ok: false, error: "A JWT has three parts separated by dots: header.payload.signature." };
      const part = (p: string) => { const b = base64ToBytes(p); if (!b) throw new Error(); return JSON.stringify(JSON.parse(new TextDecoder().decode(b)), null, 2); };
      try { return { ok: true, out: `// header\n${part(parts[0])}\n// payload\n${part(parts[1])}`, note: "Signature not verified: decoding is not validating." }; }
      catch { return { ok: false, error: "The header or payload is not Base64URL JSON." }; }
    },
  },
  {
    id: "refang", label: "Refang", help: "hxxp, [.] and [@] back to live form (to search for it, never to click).",
    run: input => ({ ok: true, out: input.replace(/hxxp/gi, m => (m[0] === "H" ? "Http" : "http")).replace(/\[\s*\.\s*\]|\(\s*\.\s*\)|\[dot\]/gi, ".").replace(/\[\s*@\s*\]|\[at\]/gi, "@").replace(/\[:\]/g, ":") }),
  },
  {
    id: "defang", label: "Defang", help: "Make URLs, domains and IPs safe to paste into a ticket: hxxps://site[.]example.",
    run: input => ({ ok: true, out: input.replace(/\bhttp/gi, m => (m[0] === "H" ? "Hxxp" : "hxxp")).replace(/(\w)\.(?=[a-z0-9-]+\b)/gi, "$1[.]").replace(/@/g, "[@]") }),
  },
];

export const OP_BY_ID = new Map(OPS.map(o => [o.id, o]));

/**
 * Suggests the next decode for a value, like CyberChef's Magic: gzip-in-Base64, Base64,
 * percent-encoding, hex, HTML entities, a JWT. Returns null when the value looks like plain text.
 */
export function suggestOp(input: string): string | null {
  const s = input.trim();
  if (!s || s.length > MAX_INPUT) return null;
  if (encodedCommandOf(` ${s}`)) return "ps-enc";
  if (/^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.?[A-Za-z0-9_-]*$/.test(s)) return "jwt";
  if (/^H4sI[A-Za-z0-9+/=\s]+$/.test(s)) return "gunzip";
  if (/%[0-9a-f]{2}/i.test(s)) return "url-decode";
  if (/&(#x?[0-9a-f]+|[a-z]+);/i.test(s)) return "html-entities";
  if (/\\u[0-9a-f]{4}|\\x[0-9a-f]{2}/i.test(s)) return "unicode-escapes";
  if (/^(?:[0-9a-f]{2}[\s:]?){8,}$/i.test(s) && s.replace(/[\s:]/g, "").length % 2 === 0) return "from-hex";
  if (/hxxp|\[\.\]/i.test(s)) return "refang";
  // Base64 may wrap over lines, but never has spaces between words: a sentence or a command line is not Base64.
  if (s.length >= 16 && !/ /.test(s) && /^[A-Za-z0-9+/_-]+={0,2}$/.test(s.replace(/[\r\n]+/g, "")) && /[A-Z]/.test(s) && /[a-z]/.test(s)) {
    const bytes = base64ToBytes(s);
    if (bytes && bytes.length >= 8) return "from-base64";
  }
  return null;
}

/** Share of bytes that are printable text (tab, newline, ASCII 0x20-0x7E, or UTF-8 / UTF-16 text bytes). */
function textShare(bytes: Uint8Array): number {
  if (!bytes.length) return 0;
  let ok = 0;
  for (const b of bytes) if (b === 9 || b === 10 || b === 13 || (b >= 0x20 && b < 0x7f) || b === 0) ok++;
  return ok / bytes.length;
}

/**
 * True when a field value is worth a one-click "Decode" (an encoded blob, not a name or a number). A hash, a
 * session or transaction id, a token or a resource path is long and alphanumeric too, but decoding it gives
 * random bytes: Base64 and hex are offered only when they decode to readable text (owner 2026-11-12: the decode
 * tag showed on values that need no decoding).
 */
export function looksEncoded(value: string): boolean {
  if (value.length < 12) return false;
  // A PowerShell -EncodedCommand / -enc argument inside a command line.
  if (/\s-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{16,}/i.test(value)) return true;
  const op = suggestOp(value);
  if (!op || op === "refang") return false;
  const s = value.trim();
  if (op === "from-hex") { const b = hexToBytes(s); return !!b && textShare(b) >= 0.9; }
  if (op === "from-base64") { const b = base64ToBytes(s); return !!b && textShare(b) >= 0.9; }
  return true;
}

/** The Base64 blob after -enc / -EncodedCommand in a PowerShell command line, if any. */
export function encodedCommandOf(value: string): string | null {
  const m = /\s-e(?:nc(?:odedcommand)?)?\s+([A-Za-z0-9+/=]{16,})/i.exec(value);
  return m ? m[1] : null;
}

/** Runs a chain of ops; stops at the first error. */
export async function runRecipe(input: string, ids: string[]): Promise<{ steps: { id: string; result: OpResult }[]; output: string }> {
  let cur = input.slice(0, MAX_INPUT);
  const steps: { id: string; result: OpResult }[] = [];
  for (const id of ids) {
    const op = OP_BY_ID.get(id);
    if (!op) break;
    const result = await op.run(cur);
    steps.push({ id, result });
    if (!result.ok) break;
    cur = result.out;
  }
  return { steps, output: cur };
}
