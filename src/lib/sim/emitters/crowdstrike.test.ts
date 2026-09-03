import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { csDetection, csProcess, csNetwork, csDns, csFile } from "./crowdstrike";
import { buildInvestigationFromStory } from "@/lib/edr/fromLiveStory";
import { COMPANY_ASSETS } from "@/lib/sim/companyProfilesMeta";

// Mirror the log-field gate's rule: a raw key is valid if it's a shared common field,
// a CrowdStrike exact field, or under one of the vendor's allowed prefixes.
const REG = JSON.parse(fs.readFileSync(path.resolve("scripts/log-field-registry.json"), "utf-8"));
const cs = REG.vendors["crowdstrike-falcon"];
const COMMON = new Set<string>(REG.commonFields);
const EXACT = new Set<string>(cs.exactFields);
const PREFIXES: string[] = cs.prefixes;
const keyValid = (k: string) => COMMON.has(k) || EXACT.has(k) || PREFIXES.some(p => k.startsWith(p));

const T = (m: number) => new Date(Date.UTC(2026, 4, 10, 9, m, 0)).toISOString();

describe("CrowdStrike emitters", () => {
  const all = [
    csDetection({ id: "e1", ts: T(1), companyId: "quantumbank", processName: "update.exe",
      parentName: "explorer.exe", threatName: "CobaltStrike.Beacon", mitre: "T1055.001",
      tactic: "Defense Evasion", technique: "Process Injection", severity: "critical", action: "quarantined",
      expectedVerdict: "tp" }),
    csProcess({ id: "e2", ts: T(2), companyId: "quantumbank", processName: "powershell.exe",
      cmdline: "powershell.exe -enc SQBFAFgA", parentName: "WINWORD.EXE", mitre: "T1059.001", tactic: "Execution" }),
    csNetwork({ id: "e3", ts: T(3), companyId: "quantumbank", remoteIp: "45.135.232.44", remotePort: 443,
      application: "tls", domain: "cdn-metrics-eu.com", mitre: "T1071.001", tactic: "Command and Control" }),
    csDns({ id: "e4", ts: T(4), companyId: "quantumbank", domain: "a3f9.exfil-dns.net", resolvedIp: "45.135.232.44",
      mitre: "T1071.004", tactic: "Command and Control" }),
    csFile({ id: "e5", ts: T(5), companyId: "quantumbank", path: "C:\\Windows\\Temp\\svc32.dll", action: "file_create" }),
  ];

  it("emit only registry-valid CrowdStrike fields", () => {
    for (const e of all) {
      for (const k of Object.keys(e.raw ?? {})) {
        expect(keyValid(k), `invalid CrowdStrike field "${k}" in ${e.id}`).toBe(true);
      }
    }
  });

  it("carry the vendor and endpoint source", () => {
    for (const e of all) { expect(e.vendor).toBe("CrowdStrike Falcon"); expect(e.source).toBe("edr"); }
  });

  it("draw host, IP and user from the company fabric (no drift)", () => {
    const qb = COMPANY_ASSETS.quantumbank;
    for (const e of all) {
      if (e.hostname) expect(qb.hosts).toContain(e.hostname);                 // host is a real QB asset
      if (e.src_ip) expect(e.src_ip.startsWith(qb.subnet + ".")).toBe(true);  // IP in QB subnet
      const u = e.process?.user;
      if (u) expect(u.startsWith(qb.netbios + "\\")).toBe(true);              // DOMAIN\user form
    }
  });

  it("keep the detection's hash coherent across process and file", () => {
    const det = all[0];
    expect(det.process?.hash?.sha256).toBeTruthy();
    expect(det.process?.hash?.sha256).toBe(det.file?.sha256);   // one hash → one file
  });

  it("are deterministic — same inputs yield the same host/ip/hash", () => {
    const a = csDetection({ id: "dup", ts: T(1), companyId: "medcore", processName: "x.exe", threatName: "Trojan.X" });
    const b = csDetection({ id: "dup", ts: T(1), companyId: "medcore", processName: "x.exe", threatName: "Trojan.X" });
    expect(a.hostname).toBe(b.hostname);
    expect(a.src_ip).toBe(b.src_ip);
    expect(a.file?.sha256).toBe(b.file?.sha256);
  });

  it("flip src/dst correctly for an inbound connection", () => {
    const inb = csNetwork({ id: "in1", ts: T(6), companyId: "quantumbank", host: "WKS-QB-012",
      remoteIp: "203.0.113.9", remotePort: 8443, direction: "inbound" });
    // remote is the attacker source; our host is the destination
    expect(inb.src_ip).toBe("203.0.113.9");
    expect(inb.raw?.["network.direction"]).toBe("inbound");
  });

  it("compose into a coherent EDR investigation", () => {
    // A phishing → execution → C2 → prevention chain, all on ONE company host.
    const host = "WKS-QB-012";
    const chain = [
      csProcess({ id: "k1", ts: T(1), companyId: "quantumbank", host, processName: "WINWORD.EXE",
        cmdline: "WINWORD.EXE /n Invoice.docm", parentName: "explorer.exe" }),
      csProcess({ id: "k2", ts: T(2), companyId: "quantumbank", host, processName: "powershell.exe",
        cmdline: "powershell.exe -enc SQBFAFgA", parentName: "WINWORD.EXE", mitre: "T1059.001",
        tactic: "Execution", severity: "high", isDetection: true }),
      csNetwork({ id: "k3", ts: T(3), companyId: "quantumbank", host, remoteIp: "45.135.232.44",
        remotePort: 443, application: "tls", domain: "cdn-metrics-eu.com", mitre: "T1071.001",
        tactic: "Command and Control", isDetection: true }),
      csDetection({ id: "k4", ts: T(4), companyId: "quantumbank", host, processName: "beacon.exe",
        threatName: "CobaltStrike.Beacon", mitre: "T1055.001", tactic: "Defense Evasion",
        severity: "critical", action: "quarantined", expectedVerdict: "tp" }),
    ];
    const inv = buildInvestigationFromStory({ id: "cs-chain", title: "CS chain", events: chain });
    expect(inv).not.toBeNull();
    expect(inv!.host.name).toBe(host);                       // console host == the chain's host
    expect(inv!.host.ip.startsWith("10.100.1.")).toBe(true); // QB subnet
    expect(inv!.detections.length).toBeGreaterThan(0);       // detections mapped
    expect(inv!.answer.pid).toBeGreaterThan(0);              // a real payload to flag
  });
});
