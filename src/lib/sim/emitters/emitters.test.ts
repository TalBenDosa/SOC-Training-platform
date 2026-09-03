import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { csDetection, csProcess, csNetwork, csDns, csFile } from "./crowdstrike";
import { s1Detection, s1Process, s1Network, s1Dns, s1File } from "./sentinelone";
import { mdeDetection, mdeProcess, mdeNetwork, mdeDns, mdeFile } from "./mde";
import { buildInvestigationFromStory } from "@/lib/edr/fromLiveStory";
import { COMPANY_ASSETS } from "@/lib/sim/companyProfilesMeta";
import type { TelemetryEvent } from "@/lib/sim/types";

const REG = JSON.parse(fs.readFileSync(path.resolve("scripts/log-field-registry.json"), "utf-8"));
const COMMON = new Set<string>(REG.commonFields);
function validatorFor(vendorKey: string) {
  const v = REG.vendors[vendorKey];
  const exact = new Set<string>(v.exactFields);
  const prefixes: string[] = v.prefixes;
  return (k: string) => COMMON.has(k) || exact.has(k) || prefixes.some(p => k.startsWith(p));
}

const T = (m: number) => new Date(Date.UTC(2026, 4, 10, 9, m, 0)).toISOString();

// One kit per vendor — the same five emitter shapes, different dialect.
interface Kit {
  name: string; regKey: string; companyId: string; subnet: string;
  detection: (o: { id: string; ts: string; companyId: string; host?: string; processName: string; threatName: string; mitre?: string; tactic?: string; severity?: "critical" | "high"; action?: "quarantined"; expectedVerdict?: "tp"; parentName?: string }) => TelemetryEvent;
  process: (o: { id: string; ts: string; companyId: string; host?: string; processName: string; cmdline: string; parentName?: string; mitre?: string; tactic?: string; severity?: "high"; isDetection?: boolean }) => TelemetryEvent;
  network: (o: { id: string; ts: string; companyId: string; host?: string; remoteIp: string; remotePort: number; direction?: "inbound" | "outbound"; application?: "tls"; domain?: string; mitre?: string; tactic?: string; isDetection?: boolean }) => TelemetryEvent;
  dns: (o: { id: string; ts: string; companyId: string; domain: string; resolvedIp?: string; mitre?: string; tactic?: string }) => TelemetryEvent;
  file: (o: { id: string; ts: string; companyId: string; path: string; action?: "file_create" }) => TelemetryEvent;
}

const KITS: Kit[] = [
  { name: "CrowdStrike Falcon", regKey: "crowdstrike-falcon", companyId: "quantumbank", subnet: "10.100.1",
    detection: csDetection, process: csProcess, network: csNetwork, dns: csDns, file: csFile },
  { name: "SentinelOne Singularity", regKey: "sentinelone", companyId: "medcore", subnet: "192.168.10",
    detection: s1Detection, process: s1Process, network: s1Network, dns: s1Dns, file: s1File },
  { name: "Microsoft Defender for Endpoint", regKey: "microsoft-defender-endpoint", companyId: "nexacorp", subnet: "10.10.20",
    detection: mdeDetection, process: mdeProcess, network: mdeNetwork, dns: mdeDns, file: mdeFile },
];

describe.each(KITS)("$name emitters", (kit) => {
  const keyValid = validatorFor(kit.regKey);
  const c = kit.companyId;
  const events: TelemetryEvent[] = [
    kit.detection({ id: "d", ts: T(1), companyId: c, processName: "update.exe", threatName: "Trojan.GenericKD", mitre: "T1204.002", tactic: "Execution", severity: "high", action: "quarantined", expectedVerdict: "tp", parentName: "explorer.exe" }),
    kit.process({ id: "p", ts: T(2), companyId: c, processName: "powershell.exe", cmdline: "powershell.exe -enc SQBFAFgA", parentName: "WINWORD.EXE", mitre: "T1059.001", tactic: "Execution" }),
    kit.network({ id: "n", ts: T(3), companyId: c, remoteIp: "45.135.232.44", remotePort: 443, application: "tls", domain: "cdn-metrics-eu.com", mitre: "T1071.001", tactic: "Command and Control" }),
    kit.dns({ id: "q", ts: T(4), companyId: c, domain: "a3f9.exfil.net", resolvedIp: "45.135.232.44", mitre: "T1071.004", tactic: "Command and Control" }),
    kit.file({ id: "f", ts: T(5), companyId: c, path: "C:\\Windows\\Temp\\svc32.dll", action: "file_create" }),
  ];

  it("emits only registry-valid fields for the declared vendor", () => {
    for (const e of events) {
      expect(e.vendor).toBe(kit.name);
      for (const k of Object.keys(e.raw ?? {})) {
        expect(keyValid(k), `invalid ${kit.name} field "${k}" in ${e.id}`).toBe(true);
      }
    }
  });

  it("draws host, IP and user from the fabric (no drift)", () => {
    const a = COMPANY_ASSETS[c];
    for (const e of events) {
      if (e.hostname) expect(a.hosts).toContain(e.hostname);
      if (e.src_ip && !e.src_ip.startsWith("45.")) expect(e.src_ip.startsWith(kit.subnet + ".")).toBe(true);
      const u = e.process?.user;
      if (u) expect(u.startsWith(a.netbios + "\\")).toBe(true);
    }
  });

  it("keeps the detection hash coherent across process and file", () => {
    const det = events[0];
    expect(det.process?.hash?.sha256).toBeTruthy();
    expect(det.process?.hash?.sha256).toBe(det.file?.sha256);
  });

  it("is deterministic", () => {
    const a = kit.detection({ id: "x", ts: T(1), companyId: c, processName: "a.exe", threatName: "T.X" });
    const b = kit.detection({ id: "x", ts: T(1), companyId: c, processName: "a.exe", threatName: "T.X" });
    expect(a.hostname).toBe(b.hostname);
    expect(a.src_ip).toBe(b.src_ip);
    expect(a.file?.sha256).toBe(b.file?.sha256);
  });

  it("composes into a coherent EDR investigation on one host", () => {
    const host = COMPANY_ASSETS[c].hosts[0];
    const chain = [
      kit.process({ id: "k1", ts: T(1), companyId: c, host, processName: "WINWORD.EXE", cmdline: "WINWORD.EXE /n Invoice.docm", parentName: "explorer.exe" }),
      kit.process({ id: "k2", ts: T(2), companyId: c, host, processName: "powershell.exe", cmdline: "powershell.exe -enc SQBF", parentName: "WINWORD.EXE", mitre: "T1059.001", tactic: "Execution", severity: "high", isDetection: true }),
      kit.network({ id: "k3", ts: T(3), companyId: c, host, remoteIp: "45.135.232.44", remotePort: 443, application: "tls", domain: "cdn-metrics-eu.com", mitre: "T1071.001", tactic: "Command and Control", isDetection: true }),
      kit.detection({ id: "k4", ts: T(4), companyId: c, host, processName: "beacon.exe", threatName: "CobaltStrike.Beacon", mitre: "T1055.001", tactic: "Defense Evasion", severity: "critical", action: "quarantined", expectedVerdict: "tp" }),
    ];
    const inv = buildInvestigationFromStory({ id: "chain", title: "chain", events: chain });
    expect(inv).not.toBeNull();
    expect(inv!.host.name).toBe(host);
    expect(inv!.host.ip.startsWith(kit.subnet + ".")).toBe(true);
    expect(inv!.detections.length).toBeGreaterThan(0);
    expect(inv!.answer.pid).toBeGreaterThan(0);
  });
});

describe("emitters — cross-vendor", () => {
  it("flip src/dst correctly for an inbound connection (all vendors)", () => {
    const inb = [
      csNetwork({ id: "i1", ts: T(6), companyId: "quantumbank", host: "WKS-QB-012", remoteIp: "203.0.113.9", remotePort: 8443, direction: "inbound" }),
      s1Network({ id: "i2", ts: T(6), companyId: "medcore", host: "WS-MED-022", remoteIp: "203.0.113.9", remotePort: 8443, direction: "inbound" }),
      mdeNetwork({ id: "i3", ts: T(6), companyId: "nexacorp", host: "WS-HR-1182", remoteIp: "203.0.113.9", remotePort: 8443, direction: "inbound" }),
    ];
    for (const e of inb) {
      expect(e.src_ip).toBe("203.0.113.9");           // remote is the attacker source
      expect(e.raw?.["network.direction"]).toBe("inbound");
    }
  });
});
