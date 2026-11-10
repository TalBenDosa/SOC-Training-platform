/**
 * Synthetic "files" for YARA missions. Nothing here is real malware: a sample is
 * a JSON spec (name, declared size, the strings and byte patterns an analyst should
 * find) turned into deterministic bytes. Client and server build the same bytes
 * from the same spec, so the in-browser preview and the server grader agree.
 *
 * Only the first 48 KB are materialised. `filesize` is the DECLARED size, so an
 * "18 MB installer" costs 48 KB of memory while `filesize < 300KB` still behaves
 * as it would on the real file.
 */

export interface SampleSpec {
  /** Display name, e.g. "calhelper_b2.exe". */
  name: string;
  /** Declared file size in bytes. YARA `filesize` returns this. */
  size: number;
  /** PRNG seed for the filler bytes and the placement of authored items. */
  seed: number;
  /** Default true: minimal MZ/PE header so uint16(0) == 0x5A4D and the PE signature check pass. */
  pe?: boolean;
  /** Sets IMAGE_FILE_DLL in the COFF characteristics. */
  dll?: boolean;
  /** Text placed `count` (default 1) times. "wide" is UTF-16LE. */
  strings?: { value: string; enc: "ascii" | "wide"; count?: number }[];
  /** Byte patterns such as "33 C1 C1 C0 05", placed `count` times. */
  hex?: { hex: string; count: number }[];
}

export interface BuiltSample {
  bytes: Uint8Array;
  /** The declared size (spec.size); pass this to scanYara. */
  filesize: number;
}

/** Upper bound on materialised bytes, unless the authored items need more room. */
export const MAX_REAL_BYTES = 48 * 1024;

/** Headers end at the PE FileAlignment; authored content starts after them. */
const PE_HEADER_END = 0x200;
const E_LFANEW = 0x80;
/** Minimum filler between two authored items, so strings never run together. */
const GAP = 4;

/** mulberry32: tiny, fast, and identical in every JS engine (Math.imul is exact). */
function prng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/**
 * Filler is drawn only from 0x00 and 0x80-0xFF. No printable byte can appear, so
 * extractStrings shows exactly the authored text plus header text, and a pattern
 * that contains any byte in 0x01-0x7F (for example 0x33) can never occur by chance.
 */
function fillerByte(r: number): number {
  return r < 0.12 ? 0 : 0x80 + Math.floor(r * 1000) % 128;
}

export function parseHexBytes(hex: string): Uint8Array {
  const parts = hex.trim().split(/\s+/).filter(Boolean);
  const out = new Uint8Array(parts.length);
  parts.forEach((p, i) => {
    if (!/^[0-9A-Fa-f]{2}$/.test(p)) throw new Error(`sample hex "${hex}": "${p}" is not a byte`);
    out[i] = parseInt(p, 16);
  });
  return out;
}

function encodeAscii(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function encodeWide(value: string): Uint8Array {
  const out = new Uint8Array(value.length * 2);
  for (let i = 0; i < value.length; i++) {
    const u = value.charCodeAt(i);
    out[i * 2] = u & 0xff;
    out[i * 2 + 1] = u >>> 8;
  }
  return out;
}

function writeU16(buf: Uint8Array, off: number, v: number): void {
  buf[off] = v & 0xff;
  buf[off + 1] = (v >>> 8) & 0xff;
}

function writeU32(buf: Uint8Array, off: number, v: number): void {
  writeU16(buf, off, v & 0xffff);
  writeU16(buf, off + 2, (v >>> 16) & 0xffff);
}

function writeText(buf: Uint8Array, off: number, text: string): void {
  for (let i = 0; i < text.length; i++) buf[off + i] = text.charCodeAt(i);
}

/**
 * A small but plausible PE32+ header: DOS header, the classic DOS stub, COFF
 * header, an optional header that is mostly zero and three section headers. It is
 * enough for the usual header checks in rules and for `strings` to show the stub
 * text and section names the way it does on a real binary.
 */
function writePeHeader(buf: Uint8Array, seed: number, dll: boolean): void {
  buf.fill(0, 0, PE_HEADER_END);
  writeText(buf, 0, "MZ");
  writeU16(buf, 0x02, 0x90);
  writeU16(buf, 0x04, 0x03);
  writeU16(buf, 0x08, 0x04);
  writeU16(buf, 0x0c, 0xffff);
  writeU16(buf, 0x10, 0xb8);
  writeU16(buf, 0x18, 0x40);
  writeU32(buf, 0x3c, E_LFANEW);
  buf.set([0x0e, 0x1f, 0xba, 0x0e, 0x00, 0xb4, 0x09, 0xcd, 0x21, 0xb8, 0x01, 0x4c, 0xcd, 0x21], 0x40);
  writeText(buf, 0x4e, "This program cannot be run in DOS mode.\r\r\n$");

  const pe = E_LFANEW;
  writeText(buf, pe, "PE\0\0");
  writeU16(buf, pe + 4, 0x8664); // Machine: AMD64
  writeU16(buf, pe + 6, 3); // NumberOfSections
  writeU32(buf, pe + 8, (0x60000000 + ((seed >>> 0) % 0x08000000)) >>> 0); // TimeDateStamp
  writeU16(buf, pe + 20, 0xf0); // SizeOfOptionalHeader (PE32+)
  writeU16(buf, pe + 22, 0x0022 | (dll ? 0x2000 : 0)); // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE [| DLL]

  const opt = pe + 24;
  writeU16(buf, opt, 0x20b); // PE32+ magic
  writeU32(buf, opt + 16, 0x1000 + ((seed >>> 3) % 0x4000)); // AddressOfEntryPoint
  writeU32(buf, opt + 24, 0x40000000); // ImageBase (low dword)
  writeU32(buf, opt + 28, 0x1); // ImageBase (high dword) -> 0x140000000
  writeU32(buf, opt + 32, 0x1000); // SectionAlignment
  writeU32(buf, opt + 36, 0x200); // FileAlignment
  writeU16(buf, opt + 68, dll ? 2 : 3); // Subsystem: GUI for DLLs, console otherwise
  writeU32(buf, opt + 108, 16); // NumberOfRvaAndSizes

  const sections = [".text", ".rdata", ".data"];
  sections.forEach((name, i) => {
    const sh = opt + 0xf0 + i * 40;
    writeText(buf, sh, name);
    writeU32(buf, sh + 8, 0x1000); // VirtualSize
    writeU32(buf, sh + 12, 0x1000 * (i + 1)); // VirtualAddress
    writeU32(buf, sh + 16, 0x200); // SizeOfRawData
    writeU32(buf, sh + 20, PE_HEADER_END + i * 0x200); // PointerToRawData
    writeU32(buf, sh + 36, i === 0 ? 0x60000020 : i === 1 ? 0x40000040 : 0xc0000040);
  });
}

/**
 * Builds the bytes for a spec. Same spec -> identical bytes. Throws only on a
 * malformed spec (bad hex), which is an authoring error, never learner input.
 */
export function buildSample(spec: SampleSpec): BuiltSample {
  const rng = prng(spec.seed);
  const isPe = spec.pe !== false;
  const bodyStart = isPe ? PE_HEADER_END : 0;

  const items: Uint8Array[] = [];
  for (const s of spec.strings ?? []) {
    const enc = s.enc === "wide" ? encodeWide(s.value) : encodeAscii(s.value);
    for (let i = 0; i < (s.count ?? 1); i++) items.push(enc);
  }
  for (const h of spec.hex ?? []) {
    const b = parseHexBytes(h.hex);
    for (let i = 0; i < h.count; i++) items.push(b);
  }
  // Fisher-Yates, so copies of one pattern are spread through the file instead of clustered.
  for (let i = items.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    [items[i], items[j]] = [items[j], items[i]];
  }

  const itemBytes = items.reduce((n, it) => n + it.length, 0);
  const needed = bodyStart + itemBytes + GAP * (items.length + 1);
  const realLen = Math.max(Math.min(Math.max(0, Math.floor(spec.size)), MAX_REAL_BYTES), needed);

  const buf = new Uint8Array(realLen);
  for (let i = bodyStart; i < realLen; i++) buf[i] = fillerByte(rng());
  if (isPe) writePeHeader(buf, spec.seed, spec.dll === true);

  // Spread the spare room across the gaps with random weights.
  const free = realLen - needed;
  const weights = items.map(() => rng());
  const total = weights.reduce((a, b) => a + b, 0) + 1;
  let cursor = bodyStart + GAP;
  items.forEach((it, i) => {
    const off = cursor + Math.floor((free * weights[i]) / total);
    buf.set(it, off);
    cursor = off + it.length + GAP;
  });

  return { bytes: buf, filesize: spec.size };
}

const isPrintable = (b: number) => (b >= 0x20 && b <= 0x7e) || b === 0x09;

/**
 * strings(1)/FLOSS-style extraction: ASCII runs and UTF-16LE runs (printable byte
 * followed by 0x00) of at least `minLen` characters, sorted by offset.
 */
export function extractStrings(bytes: Uint8Array, minLen = 6): { offset: number; enc: "ascii" | "wide"; value: string }[] {
  const out: { offset: number; enc: "ascii" | "wide"; value: string }[] = [];
  const min = Math.max(1, Math.floor(minLen));

  let i = 0;
  while (i < bytes.length) {
    if (!isPrintable(bytes[i])) {
      i++;
      continue;
    }
    const start = i;
    while (i < bytes.length && isPrintable(bytes[i])) i++;
    if (i - start >= min) {
      let value = "";
      for (let k = start; k < i; k++) value += String.fromCharCode(bytes[k]);
      out.push({ offset: start, enc: "ascii", value });
    }
  }

  i = 0;
  while (i + 1 < bytes.length) {
    if (!(isPrintable(bytes[i]) && bytes[i + 1] === 0)) {
      i++;
      continue;
    }
    const start = i;
    let chars = "";
    while (i + 1 < bytes.length && isPrintable(bytes[i]) && bytes[i + 1] === 0) {
      chars += String.fromCharCode(bytes[i]);
      i += 2;
    }
    // No other run can start inside this one: every odd byte in it is 0x00.
    if (chars.length >= min) out.push({ offset: start, enc: "wide", value: chars });
  }

  return out.sort((a, b) => a.offset - b.offset || (a.enc === "ascii" ? -1 : 1));
}
