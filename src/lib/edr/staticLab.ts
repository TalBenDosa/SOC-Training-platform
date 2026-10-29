/**
 * Static Analysis Lab — what an analyst sees after pulling a suspect file off a host with
 * RTR `get` and opening it on an isolated analysis VM. The views reproduce the real tools'
 * output format (PE triage / Sysinternals Strings / Mandiant FLOSS / Mandiant capa), built
 * DETERMINISTICALLY from the case's own telemetry. Nothing here is a real binary, a real
 * address or a real hash of a real sample: it is simulated, realistic tool output.
 *
 * The teaching points the format is designed to carry:
 *  - A signed, legitimate file still shows CRL/OCSP URLs and ASN.1 OIDs; those are PKI noise,
 *    not IOCs. Precision matters more than recall.
 *  - `strings` misses what is built or decoded at runtime; FLOSS recovers stack / tight /
 *    decoded strings that `strings` cannot see.
 *  - capa answers "what is this capable of" (mapped to ATT&CK), not "is this malicious".
 *  - Every network IOC pulled from a sample must be pivoted in the SIEM before it is acted on.
 */
import type { EdrInvestigation, EdrProcess } from "./investigations";

export interface SampleRef {
  name: string;            // update.dll
  path: string;            // full on-host path
  sha256: string;
  signed: boolean;
  signer?: string;
  sizeBytes: number;
  isPe: boolean;
  isDll: boolean;
  /** Export names rundll32/regsvr32 reveal from the command line (Start, DllRegisterServer…). */
  exports: string[];
  originalFileName?: string;
  /** Network indicators this file was observed using (the real C2 among the strings). */
  net: { domain?: string; ip?: string; port?: number; application?: string }[];
  /** Files it touched — a browser credential store read is a strong capability tell. */
  touched: string[];
  wroteRunKey: boolean;
  /** The Run-key value name that re-launches it (e.g. "Updater"), when the case shows one. */
  runValueName?: string;
  /** Seconds between its repeated C2 connections (the beacon interval), when observed. */
  beaconSec?: number;
}

export interface SampleEvidence {
  id: string;              // SMP-001
  collectedAt: string;     // HH:MM:SS
  host: string;
  sample: SampleRef;
}

function fnv(s: string): number {
  let h = 2166136261 >>> 0;
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619) >>> 0; }
  return h >>> 0;
}
/** Deterministic lowercase hex of n chars seeded by s (fake but stable; labelled as simulated). */
function hex(s: string, n: number): string {
  let out = "", i = 0;
  while (out.length < n) { out += (fnv(s + "#" + i) >>> 0).toString(16).padStart(8, "0"); i++; }
  return out.slice(0, n);
}
const baseName = (p: string) => p.split("\\").pop() ?? p;

/** Resolve the file RTR `get <path>` collected into a static-analysis sample, from the case. */
export function sampleFromPath(inv: EdrInvestigation, rawPath: string): SampleRef | null {
  const path = rawPath.trim().replace(/^"|"$/g, "");
  const lc = path.toLowerCase();
  // The process whose own image is this file, or that wrote/loaded it.
  const proc = inv.processes.find(p => (p.path ?? "").toLowerCase() === lc)
    ?? inv.processes.find(p => (p.files ?? []).some(f => f.path.toLowerCase() === lc && f.action === "write"))
    ?? inv.processes.find(p => (p.modules ?? []).some(m => m.path.toLowerCase() === lc));
  if (!proc) return null;
  const name = baseName(path);
  const isPe = /\.(exe|dll|sys|scr|ocx|cpl)$/i.test(name);
  const isDll = /\.(dll|ocx|cpl)$/i.test(name);

  // Exports an analyst can infer from how the file is invoked.
  const exports: string[] = [];
  for (const p of inv.processes) {
    const cl = p.cmdline ?? "";
    if (p.path?.toLowerCase() === lc || cl.toLowerCase().includes(lc)) {
      const rd = cl.match(/rundll32(?:\.exe)?\s+[^,]+,\s*([#@\w]+)/i);
      if (rd) exports.push(rd[1]);
      if (/regsvr32/i.test(cl)) exports.push("DllRegisterServer", "DllInstall");
    }
  }
  if (isDll && !exports.length) exports.push("DllMain");

  // The sample is identified by the process that IS this image (its sha256/signature),
  // else the writer process's hash of the dropped file isn't on the node, so synthesise one.
  const imageProc = inv.processes.find(p => (p.path ?? "").toLowerCase() === lc) ?? proc;
  const sha256 = imageProc.sha256 ?? hex("sha|" + lc, 64);
  const net = (imageProc.network ?? proc.network ?? []).map(c => ({ domain: c.domain, ip: c.remote_ip, port: c.remote_port, application: c.application ?? c.proto }));
  const touched = (imageProc.files ?? []).map(f => f.path);
  const wroteRunKey = (imageProc.registry ?? proc.registry ?? []).some(r => /\\Run\\/i.test(r.path))
    || (inv.autoruns ?? []).some(a => a.value.toLowerCase().includes(lc));
  const sizeBytes = 24_576 + (fnv("sz|" + sha256) % 900) * 1024;   // 24 KB .. ~900 KB, stable

  return {
    name, path, sha256, signed: imageProc.signed, signer: imageProc.signed ? "Microsoft Windows" : undefined,
    sizeBytes, isPe, isDll, exports: [...new Set(exports)], originalFileName: imageProc.originalFileName,
    net, touched, wroteRunKey,
  };
}

const n = (x: number) => x.toLocaleString("en-US");

/** 1. PE triage (pestudio / Detect It Easy / Defender `fileinfo` style). */
export function peInfo(s: SampleRef): string {
  if (!s.isPe) return `${s.name} is not a PE file. Static PE triage expects a PE (.exe/.dll). SHA-256: ${s.sha256}`;
  const arch = fnv("arch" + s.sha256) % 5 === 0 ? "PE32 (x86)" : "PE32+ (x64)";
  const y = 2025 + (fnv("yr" + s.sha256) % 2), mo = 1 + fnv("mo" + s.sha256) % 12, d = 1 + fnv("dy" + s.sha256) % 27;
  const compiled = `${y}-${String(mo).padStart(2, "0")}-${String(d).padStart(2, "0")} ${String(fnv("h" + s.sha256) % 24).padStart(2, "0")}:${String(fnv("mi" + s.sha256) % 60).padStart(2, "0")} UTC`;
  // Entropy: normal here (not packed). A packed sample in a harder case would read >7.2.
  const ent = (seed: string, lo: number, hi: number) => (lo + (fnv(seed + s.sha256) % Math.round((hi - lo) * 100)) / 100).toFixed(2);
  const sections = [
    ["\.text", ".text", ent("t", 6.1, 6.7)], ["\.rdata", ".rdata", ent("r", 4.8, 5.6)],
    ["\.data", ".data", ent("d", 3.2, 4.4)], ["\.reloc", ".reloc", ent("x", 4.0, 5.0)],
  ];
  // Imports an analyst would read as the file's "reach": network, crypto, process, files.
  const imports = ["KERNEL32.dll", "ADVAPI32.dll"];
  if (s.net.length) imports.push("WININET.dll", "WS2_32.dll");
  if (s.touched.some(f => /login data|cookies|crypt/i.test(f)) || s.net.length) imports.push("CRYPT32.dll");
  imports.push("USER32.dll");
  return [
    `File:         ${s.name}`,
    `Size:         ${n(s.sizeBytes)} bytes`,
    `Type:         ${arch} ${s.isDll ? "DLL" : "executable"}`,
    `MD5:          ${hex("md5" + s.sha256, 32)}`,
    `SHA-256:      ${s.sha256}`,
    `Imphash:      ${hex("imp" + imports.join(","), 32)}`,
    `Compiled:     ${compiled}`,
    `Signature:    ${s.signed ? `signed (${s.signer})` : "UNSIGNED  <- no Authenticode signature"}`,
    s.originalFileName ? `OriginalName: ${s.originalFileName}${s.originalFileName.toLowerCase() !== s.name.toLowerCase() ? "  <- differs from on-disk name (rename tell)" : ""}` : "",
    "",
    "Sections      VirtAddr    RawSize     Entropy",
    ...sections.map(([, nm, e]) => `  ${nm.padEnd(10)}0x${hex("va" + nm + s.sha256, 6)}  ${n(16384 + fnv(nm + s.sha256) % 180000).padStart(9)}   ${e}`),
    "",
    `Imports:      ${[...new Set(imports)].join(", ")}`,
    `Exports:      ${s.isDll ? (s.exports.join(", ") || "(none)") : "(not a DLL)"}`,
  ].filter(Boolean).join("\n");
}

/** The visible-string lines: PKI/runtime decoys mixed with the case's real indicators. */
function stringLines(s: SampleRef): string[] {
  const decoys = [
    "!This program cannot be run in DOS mode.",
    ".text", ".rdata", ".data", ".reloc", "Rich",
    "mscoree.dll", "KERNEL32.dll", "ADVAPI32.dll",
    "http://www.microsoft.com/pkiops/certs/",
    "http://crl.microsoft.com/pki/crl/products/",
    "http://ocsp.digicert.com",
    "1.3.6.1.5.5.7.3.3", "2.5.29.19", "1.2.840.113549.1.1.11",
    "GetProcAddress", "LoadLibraryW", "VirtualAlloc",
  ];
  const real: string[] = [];
  for (const c of s.net) {
    if (c.domain) real.push(c.domain, `https://${c.domain}/${hex("uri" + c.domain, 6)}`);
    else if (c.ip) real.push(`${c.ip}`);
  }
  if (s.net.length) real.push("Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
  for (const f of s.touched) if (/login data|cookies/i.test(f)) real.push(baseName(f));
  if (s.exports.length && s.isDll) real.push(...s.exports);
  if (s.wroteRunKey) real.push("Software\\Microsoft\\Windows\\CurrentVersion\\Run");
  // Interleave deterministically so the real ones are not simply at the end.
  const out: string[] = [];
  const mix = [...decoys];
  real.forEach((r, i) => mix.splice(Math.min(mix.length, 2 + i * 3), 0, r));
  return mix;
}

/** 2. Sysinternals-style `strings -n 6` (ASCII + UTF-16LE). */
export function stringsOutput(s: SampleRef): string {
  return stringLines(s).join("\n");
}

/** 3. Mandiant FLOSS — static strings plus what `strings` cannot see (stack / decoded). */
export function flossOutput(s: SampleRef): string {
  const statics = stringLines(s).filter(l => !/^\.|Rich|DOS mode/.test(l)).slice(0, 10);
  // Stack strings: short operational fragments a loader builds byte-by-byte on the stack.
  const stack = ["cmd.exe /c", "\\\\.\\pipe\\", "Global\\"].map(x => x + hex("st" + x + s.sha256, 4));
  // Decoded strings: produced by a decode routine in the binary. In this (easy) sample the
  // C2 is already in plain strings, so the decoded set is small operational config.
  const decoded = s.net.flatMap(c => c.domain ? [`beacon:${c.domain}:${c.port ?? 443}`] : c.ip ? [`beacon:${c.ip}`] : []).slice(0, 2);
  return [
    `FLARE FLOSS RESULTS (simulated)`,
    ` file path: ${s.name}`,
    ` sha256:    ${s.sha256}`,
    "",
    `FLOSS STATIC STRINGS (${statics.length})`,
    ...statics,
    "",
    `------------------------------ stack strings ------------------------------`,
    ...(stack.length ? stack : ["(none)"]),
    "",
    `----------------------------- decoded strings -----------------------------`,
    ...(decoded.length ? decoded : ["(none recovered)"]),
  ].join("\n");
}

/** 4. Mandiant capa — capabilities mapped to ATT&CK (what it CAN do, not a verdict). */
export function capaOutput(s: SampleRef): string {
  const attack: [string, string][] = [];
  const caps: [string, string][] = [];
  if (s.net.length) {
    attack.push(["COMMAND AND CONTROL", "Application Layer Protocol: Web Protocols [T1071.001]"]);
    caps.push(["connect to HTTP/HTTPS server", "communication/http/client"]);
    caps.push(["send and receive data on a socket", "communication/socket"]);
  }
  if (s.touched.some(f => /login data|cookies/i.test(f))) {
    attack.push(["CREDENTIAL ACCESS", "Credentials from Web Browsers [T1555.003]"]);
    caps.push(["read a browser credential store", "collection/browser"]);
  }
  if (s.touched.length) caps.push(["write and read files", "host-interaction/file-system"]);
  if (s.wroteRunKey) { attack.push(["PERSISTENCE", "Registry Run Keys / Startup Folder [T1547.001]"]); caps.push(["set a registry Run key", "host-interaction/registry"]); }
  if (s.isDll && s.exports.length) caps.push([`export a DLL entry point (${s.exports.join(", ")})`, "executable/pe/export"]);
  caps.push(["parse PE header", "load-code/pe"], ["resolve API by name at runtime", "linking/runtime-linking"]);
  const col = (rows: [string, string][], a: string, b: string) => {
    const w = Math.max(a.length, ...rows.map(r => r[0].length)) + 2;
    return [`${a.padEnd(w)}${b}`, "-".repeat(w + b.length), ...rows.map(r => `${r[0].padEnd(w)}${r[1]}`)];
  };
  return [
    `capa (simulated)   sha256 ${s.sha256}`,
    s.signed ? "" : "WARNING: file is unsigned.",
    "",
    ...col(attack.length ? attack : [["(none identified)", ""]], "ATT&CK Tactic", "ATT&CK Technique"),
    "",
    ...col(caps, "Capability", "Namespace"),
    "",
    "capa reports what the file is CAPABLE of, not whether it is malicious. A benign tool can",
    "match many of these. Weigh them with the file's origin, signature and where it ran.",
  ].filter(Boolean).join("\n");
}

/** Network indicators worth pivoting on in the SIEM (extraction only, no verdict). */
export function candidateIocs(s: SampleRef): { value: string; type: "domain" | "ip" }[] {
  const out: { value: string; type: "domain" | "ip" }[] = [];
  const seen = new Set<string>();
  for (const c of s.net) {
    if (c.domain && !seen.has(c.domain)) { seen.add(c.domain); out.push({ value: c.domain, type: "domain" }); }
    if (c.ip && !seen.has(c.ip)) { seen.add(c.ip); out.push({ value: c.ip, type: "ip" }); }
  }
  return out;
}
