import { describe, expect, it } from "vitest";
import { buildSample, compileYara, extractStrings, scanYara, type CompiledYaraRule, type SampleSpec } from "./index";

const FMT = "id=%s&st=%d&ck=%08x";
const TYPO = "conect fail retry";
const PIPE = String.raw`\\.\pipe\pcal_ctl`;
const ROT = "33 C1 C1 C0 05";

const BAD: SampleSpec[] = [
  {
    name: "calhelper.exe", size: 184_320, seed: 11,
    strings: [{ value: FMT, enc: "ascii" }, { value: TYPO, enc: "ascii" }, { value: TYPO, enc: "wide" }, { value: PIPE, enc: "ascii" }],
    hex: [{ hex: ROT, count: 14 }],
  },
  {
    name: "calhelper_b2.exe", size: 176_128, seed: 22,
    strings: [{ value: FMT, enc: "ascii" }, { value: TYPO, enc: "ascii" }, { value: PIPE, enc: "wide" }],
    hex: [{ hex: ROT, count: 9 }],
  },
  {
    name: "pcalsvc.dll", size: 98_304, seed: 33, dll: true,
    strings: [{ value: TYPO, enc: "wide" }, { value: PIPE, enc: "ascii" }],
    hex: [{ hex: ROT, count: 14 }],
  },
  {
    name: "calhelper_b4.exe", size: 190_464, seed: 44,
    strings: [{ value: FMT, enc: "ascii" }, { value: PIPE, enc: "wide" }, { value: "VirtualAlloc", enc: "ascii" }],
    hex: [{ hex: ROT, count: 14 }],
  },
  {
    name: "calhelper_b5.exe", size: 201_728, seed: 55,
    strings: [{ value: FMT, enc: "ascii" }, { value: TYPO, enc: "ascii" }, { value: "kernel32.dll", enc: "ascii" }],
    hex: [{ hex: ROT, count: 12 }],
  },
];

const GOOD: SampleSpec[] = [
  {
    name: "notepad_helper.exe", size: 143_360, seed: 101,
    strings: [{ value: "VirtualAlloc", enc: "ascii" }, { value: "kernel32.dll", enc: "ascii" }, { value: "http://", enc: "ascii" }],
  },
  {
    name: "updater.exe", size: 266_240, seed: 102,
    strings: [{ value: "VirtualAlloc", enc: "ascii" }, { value: "http://", enc: "ascii" }, { value: "kernel32.dll", enc: "wide" }],
    hex: [{ hex: ROT, count: 2 }],
  },
  {
    name: "CalibrationStudio_Setup.exe", size: 18 * 1024 * 1024, seed: 103,
    strings: [
      { value: "Calibration Studio installer", enc: "ascii" },
      { value: "VirtualAlloc", enc: "ascii" },
      { value: "kernel32.dll", enc: "ascii" },
      { value: "http://", enc: "ascii" },
      { value: TYPO, enc: "ascii" },
      { value: FMT, enc: "ascii" },
    ],
    hex: [{ hex: ROT, count: 22 }],
  },
  {
    name: "tlshelper.dll", size: 81_920, seed: 104, dll: true,
    strings: [{ value: "VirtualAlloc", enc: "ascii" }, { value: "kernel32.dll", enc: "ascii" }, { value: "TLS helper", enc: "ascii" }],
    hex: [{ hex: ROT, count: 16 }],
  },
];

const STRONG = String.raw`
rule PEL_Calhelper_Loader {
  meta: author = "Pelham DCA"
  strings:
    $fmt = "id=%s&st=%d&ck=%08x" ascii
    $typo = "conect fail retry" ascii wide
    $pipe = "\\\\.\\pipe\\pcal_ctl" ascii wide
    $rot = { 33 C1 C1 C0 05 }
  condition: uint16(0) == 0x5A4D and filesize < 300KB and 2 of ($fmt, $typo, $pipe) and #rot >= 6
}`;

const WEAK = `
rule Weak_Loader {
  strings:
    $a = "VirtualAlloc"
    $b = "http://"
    $c = "kernel32.dll"
  condition: 2 of them
}`;

function rules(src: string): CompiledYaraRule[] {
  const c = compileYara(src);
  if (!c.ok) throw new Error(`compile failed: ${c.error.message} (line ${c.error.line})`);
  return c.rules;
}

function scan(src: string, spec: SampleSpec) {
  const { bytes, filesize } = buildSample(spec);
  return scanYara(rules(src), bytes, filesize);
}

function errorOf(src: string): { message: string; line: number } {
  const c = compileYara(src);
  if (c.ok) throw new Error("expected a compile error");
  return c.error;
}

describe("samples", () => {
  it("is deterministic and caps real bytes while keeping the declared filesize", () => {
    const a = buildSample(GOOD[2]);
    const b = buildSample(GOOD[2]);
    expect(a.bytes).toEqual(b.bytes);
    expect(a.filesize).toBe(18 * 1024 * 1024);
    expect(a.bytes.length).toBe(48 * 1024);
  });

  it("writes a PE header that passes the usual header checks", () => {
    const { bytes, filesize } = buildSample(BAD[2]);
    const r = scanYara(
      rules("rule pe { condition: uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 }"),
      bytes,
      filesize,
    );
    expect(r.matched).toBe(true);
    // IMAGE_FILE_DLL bit is set for dll builds and not otherwise.
    const dllCheck = "rule d { condition: (uint16(uint32(0x3C) + 22) \\ 0x2000) == 1 }";
    expect(scanYara(rules(dllCheck), bytes, filesize).matched).toBe(true);
    const exe = buildSample(BAD[0]);
    expect(scanYara(rules(dllCheck), exe.bytes, exe.filesize).matched).toBe(false);
  });

  it("filler never forms printable runs, so strings shows only authored text and header text", () => {
    const { bytes } = buildSample(BAD[0]);
    const found = extractStrings(bytes);
    const values = found.map((s) => `${s.enc}:${s.value}`);
    expect(values).toEqual(
      expect.arrayContaining([`ascii:${FMT}`, `ascii:${TYPO}`, `wide:${TYPO}`, `ascii:${PIPE}`, "ascii:!This program cannot be run in DOS mode."]),
    );
    // Header noise looks like a real PE under strings(1): "!This program...", "`.rdata", "@.data".
    expect(found).toHaveLength(7);
    for (const s of found) {
      const len = s.enc === "wide" ? s.value.length * 2 : s.value.length;
      const raw = Array.from(bytes.subarray(s.offset, s.offset + len));
      const expected = s.enc === "wide" ? Array.from(s.value).flatMap((ch) => [ch.charCodeAt(0), 0]) : Array.from(s.value, (ch) => ch.charCodeAt(0));
      expect(raw).toEqual(expected);
    }
    const offsets = found.map((s) => s.offset);
    expect(offsets).toEqual([...offsets].sort((x, y) => x - y));
  });

  it("places hex patterns exactly count times", () => {
    for (const spec of [BAD[0], BAD[1], GOOD[2], GOOD[3]]) {
      const r = scan("rule h { strings: $rot = { 33 C1 C1 C0 05 } condition: $rot }", spec);
      expect(r.rules[0].strings[0].count).toBe(spec.hex?.[0].count);
    }
  });

  it("works without a PE header", () => {
    const { bytes } = buildSample({ name: "blob.bin", size: 4096, seed: 9, pe: false, strings: [{ value: "plain text here", enc: "ascii" }] });
    expect(bytes[0] === 0x4d && bytes[1] === 0x5a).toBe(false);
    expect(extractStrings(bytes).map((s) => s.value)).toEqual(["plain text here"]);
  });
});

describe("PEL_Calhelper_Loader scenario", () => {
  it("matches all five bad builds", () => {
    for (const spec of BAD) {
      const r = scan(STRONG, spec);
      expect(r.matched, spec.name).toBe(true);
      expect(r.rules[0].name).toBe("PEL_Calhelper_Loader");
    }
  });

  it("matches none of the goodware", () => {
    for (const spec of GOOD) expect(scan(STRONG, spec).matched, spec.name).toBe(false);
  });

  it("the weak rule fires on goodware", () => {
    for (const spec of GOOD) expect(scan(WEAK, spec).matched, spec.name).toBe(true);
  });

  it("reports per-string counts and offsets", () => {
    const r = scan(STRONG, BAD[0]);
    const byId = Object.fromEntries(r.rules[0].strings.map((s) => [s.id, s]));
    expect(byId.$fmt.count).toBe(1);
    expect(byId.$typo.count).toBe(2); // ascii + wide copy
    expect(byId.$pipe.count).toBe(1);
    expect(byId.$rot.count).toBe(14);
    const { bytes } = buildSample(BAD[0]);
    const strs = extractStrings(bytes);
    expect(byId.$fmt.firstOffset).toBe(strs.find((s) => s.value === FMT)?.offset);
  });
});

describe("matching semantics", () => {
  const spec: SampleSpec = {
    name: "t.exe", size: 8192, seed: 5,
    strings: [
      { value: "Hello World", enc: "ascii" },
      { value: "MixedCase", enc: "wide" },
      { value: "xabcx", enc: "ascii" },
      { value: "abc", enc: "ascii", count: 3 },
    ],
    hex: [{ hex: "4D 5A 90 00 AA BB", count: 1 }, { hex: "DE AD 01 BE EF", count: 2 }],
  };

  const m = (cond: string, strs: string) => scan(`rule t { strings: ${strs} condition: ${cond} }`, spec).matched;

  it("nocase, wide and fullword", () => {
    expect(m("$a", '$a = "hello world"')).toBe(false);
    expect(m("$a", '$a = "hello world" nocase')).toBe(true);
    expect(m("$a", '$a = "MixedCase"')).toBe(false);
    expect(m("$a", '$a = "mixedcase" wide nocase')).toBe(true);
    expect(m("#a == 4", '$a = "abc"')).toBe(true);
    expect(m("#a == 3", '$a = "abc" fullword')).toBe(true);
  });

  it("hex wildcards, nibbles, jumps and alternatives", () => {
    expect(m("$h", "$h = { 4D 5A ?? 00 }")).toBe(true);
    expect(m("$h", "$h = { 4D 5A 9? 00 A? ?B }")).toBe(true);
    expect(m("#h == 2", "$h = { DE AD [1] BE EF }")).toBe(true);
    expect(m("#h == 2", "$h = { DE AD [0-2] BE EF }")).toBe(true);
    expect(m("$h", "$h = { DE AD ( 01 | 02 03 ) BE }")).toBe(true);
    expect(m("$h", "$h = { DE AD ( 02 | 02 03 ) BE }")).toBe(false);
  });

  it("regex strings run on the linear engine", () => {
    expect(m("$r", "$r = /Hel+o\\sW[a-z]+/")).toBe(true);
    expect(m("$r", "$r = /hello world/i")).toBe(true);
    expect(m("$r", "$r = /mixed[a-z]+/ wide nocase")).toBe(true);
    // A pattern that is exponential on a backtracking engine finishes instantly here.
    const start = Date.now();
    expect(m("$r", "$r = /(a|a|aa)+(a|a)*qz/")).toBe(false);
    expect(Date.now() - start).toBeLessThan(5000);
  });

  it("count, offsets, at, in, uint and filesize arithmetic", () => {
    const { bytes } = buildSample(spec);
    const first = extractStrings(bytes).find((s) => s.value === "Hello World")?.offset as number;
    expect(m(`$a at ${first}`, '$a = "Hello World"')).toBe(true);
    expect(m(`$a at ${first + 1}`, '$a = "Hello World"')).toBe(false);
    expect(m(`$a in (${first - 2}..${first + 2})`, '$a = "Hello World"')).toBe(true);
    expect(m(`@a[1] == ${first} and @a == ${first} and !a[1] == 11`, '$a = "Hello World"')).toBe(true);
    expect(m("@a[5] == 0 or not (@a[5] == 0)", '$a = "Hello World"')).toBe(false); // undefined stays false
    expect(m("filesize == 8KB and filesize \\ 1024 == 8 and filesize - 192 + 0x40 == 8 * 1024 - 128", '$_unused = "x"')).toBe(true);
    expect(m("uint8(0) == 0x4D and uint16be(0) == 0x4D5A and uint32(0x3C) == 0x80", '$_a = "x"')).toBe(true);
    expect(m("uint32(1000000) == 0 or true", '$_a = "x"')).toBe(true);
  });

  it("of-expressions over sets and wildcards", () => {
    const strs = '$s1 = "Hello" $s2 = "abc" $s3 = "nope" $x = "zzz"';
    expect(m("all of ($s1, $s2) and none of ($x) and any of ($s*)", strs)).toBe(true);
    expect(m("2 of ($s*) and not all of ($s*) and $x or #x == 0", strs)).toBe(true);
    expect(m("3 of them", strs)).toBe(false);
    expect(m("any of them", '$ = "Hello" $ = "nope"')).toBe(true);
  });

  it("rule references and private rules", () => {
    const src = `
      private rule has_mz { condition: uint16(0) == 0x5A4D }
      rule big { strings: $a = "Hello" condition: has_mz and $a }`;
    const r = scan(src, spec);
    expect(r.rules.map((x) => x.name)).toEqual(["big"]);
    expect(r.matched).toBe(true);
  });

  it("comments and tags are accepted", () => {
    const src = `/* header */ rule c : apt loader { // tags
      meta: score = 80 neg = -1 ok = true
      strings: $a = "Hello" // greet
      condition: $a }`;
    expect(scan(src, spec).matched).toBe(true);
  });
});

describe("compile errors", () => {
  it.each([
    ["rule a { condition: true and }", "syntax error, unexpected '}'", 1],
    ["rule a {\n strings: $a = \"x\"\n condition: $b }", 'undefined string identifier "$b"', 3],
    ["rule a {\n strings:\n  $a = \"x\"\n  $b = \"y\"\n condition: $a }", 'unreferenced string "$b"', 4],
    ["rule a { strings: $a = \"x\" $a = \"y\" condition: $a }", 'duplicated string identifier "$a"', 1],
    ["rule a { strings: $h = { 4D 5Z } condition: $h }", 'invalid hex string "$h"', 1],
    ["rule a { strings: $h = { [2] 4D } condition: $h }", 'invalid hex string "$h": jumps are not allowed', 1],
    ["rule a { strings: $h = { 4D [0-] 5A } condition: $h }", "unbounded jumps", 1],
    ["rule a { strings: $h = { 4D [0-900] 5A } condition: $h }", "too large", 1],
    ["rule a {\n strings: $a = \"x\"\n}", 'rule "a" has no condition', 3],
    ["rule a { condition: true }\nrule a { condition: true }", 'duplicated identifier "a"', 2],
    ['import "pe"\nrule a { condition: true }', "modules are not available", 1],
    ["rule a { condition: pe.is_dll() }", "modules are not available", 1],
    ["rule a { strings: $a = \"x\" condition: for any i in (1..#a): (@a[i] > 0) }", "for loops are not supported", 1],
    ["rule a { strings: $a = \"x\" xor condition: $a }", '"xor" modifier is not supported', 1],
    ["rule a { strings: $h = { 41 } wide condition: $h }", 'invalid modifier "wide" for hex string', 1],
    ["rule a { strings: $r = /a(?=b)/ condition: $r }", 'invalid regular expression in string "$r"', 1],
    ["rule a { strings: $a = \"x\" condition: $a + 1 > 0 }", 'wrong type "boolean"', 1],
    ["rule a { condition: other_rule }", 'undefined identifier "other_rule"', 1],
    ["global rule a { condition: true }", "global rules are not supported", 1],
    ["rule a { strings: $a = \"\" condition: $a }", 'empty string "$a"', 1],
    ["rule a { strings: $a = \"x\" condition: any of ($b*) }", 'undefined string identifier "$b*"', 1],
    ['rule a { strings: $a = "unterminated condition: $a }', "unterminated string", 1],
  ])("%s", (src, message, line) => {
    const e = errorOf(src);
    expect(e.message).toContain(message);
    expect(e.line).toBe(line);
  });

  it("rejects oversized sources and too many strings", () => {
    expect(errorOf("rule a { condition: true }" + " ".repeat(70 * 1024)).message).toContain("too large");
    const many = Array.from({ length: 65 }, (_, i) => `$s${i} = "v${i}"`).join("\n");
    expect(errorOf(`rule a { strings: ${many} condition: any of them }`).message).toContain("too many strings");
  });

  it("allows $_ strings to stay unreferenced", () => {
    expect(compileYara('rule a { strings: $_note = "x" condition: true }').ok).toBe(true);
  });
});

describe("scanYara robustness", () => {
  it("never throws, even on an expensive regex over a long run", () => {
    const { bytes, filesize } = buildSample({ name: "a.bin", size: 48 * 1024, seed: 1, pe: false, strings: [{ value: "a".repeat(1000), enc: "ascii" }] });
    const r = scanYara(rules("rule a { strings: $r = /a[\\x00-\\xff]{0,900}a/ condition: #r > 0 }"), bytes, filesize);
    expect(r.matched).toBe(true);
  });
});
