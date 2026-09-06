import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { fgTraffic, fgThreat, fgVpn } from "./fortigate";
import { cpTraffic, cpThreat } from "./checkpoint";
import { zscalerWeb } from "./zscaler";
import { m365Operation, m365Dlp } from "./m365";

const REG = JSON.parse(fs.readFileSync(path.resolve("scripts/log-field-registry.json"), "utf-8"));
const COMMON = new Set<string>(REG.commonFields);
function validatorFor(key: string) {
  const v = REG.vendors[key];
  const exact = new Set<string>(v.exactFields);
  const pre: string[] = v.prefixes;
  return (k: string) => COMMON.has(k) || exact.has(k) || pre.some(p => k.startsWith(p));
}
function assertValid(events: { id: string; vendor?: string; raw?: Record<string, unknown> }[], key: string, vendor: string) {
  const ok = validatorFor(key);
  for (const e of events) {
    expect(e.vendor).toBe(vendor);
    for (const k of Object.keys(e.raw ?? {})) expect(ok(k), `invalid ${vendor} field "${k}" in ${e.id}`).toBe(true);
  }
}
const T = (m: number) => new Date(Date.UTC(2026, 4, 10, 9, m, 0)).toISOString();

describe("FortiGate emitters", () => {
  const c = "rocketstack";
  const events = [
    fgTraffic({ id: "t", ts: T(1), companyId: c, remoteIp: "45.135.232.44", remotePort: 443, domain: "cdn-metrics-eu.com", service: "HTTPS", action: "accept", bytesSent: 1200, bytesReceived: 40000 }),
    fgThreat({ id: "h", ts: T(2), companyId: c, remoteIp: "45.135.232.44", subtype: "ips", threatName: "Backdoor.CobaltStrike", action: "blocked", mitre: "T1071.001" }),
    fgVpn({ id: "v", ts: T(3), companyId: c, user: "t.levy@rocketstack.io", remoteIp: "91.108.23.7", assignedIp: "10.212.134.9", outcome: "success" }),
  ];
  it("registry-valid", () => assertValid(events, "fortigate", "FortiGate"));
  it("maps outcomes", () => {
    expect(events[0].event_type).toBe("net_connection");
    expect(events[1].event_type).toBe("ids_blocked");
    expect(events[2].event_type).toBe("vpn_login");
    expect(events[2].geo?.country).toBe("Russia");
  });
});

describe("Check Point emitters", () => {
  const c = "medcore";
  const events = [
    cpTraffic({ id: "t", ts: T(1), companyId: c, remoteIp: "203.0.113.44", remotePort: 443, action: "accept", natIp: "198.51.100.7" }),
    cpTraffic({ id: "d", ts: T(2), companyId: c, remoteIp: "203.0.113.44", remotePort: 4444, action: "drop" }),
    cpThreat({ id: "h", ts: T(3), companyId: c, remoteIp: "203.0.113.44", threatName: "Trojan.Emotet", blade: "Anti-Bot", action: "Prevent", mitre: "T1071.001" }),
  ];
  it("registry-valid", () => assertValid(events, "check-point-ngfw", "Check Point NGFW"));
  it("maps outcomes", () => {
    expect(events[0].event_type).toBe("net_connection");
    expect(events[1].event_type).toBe("net_blocked");
    expect(events[2].event_type).toBe("ids_blocked");
  });
});

describe("Zscaler emitter", () => {
  const c = "quantumbank";
  const events = [
    zscalerWeb({ id: "a", ts: T(1), companyId: c, host: "WKS-QB-012", user: "f.zimmermann@quantumbank.ch", url: "https://cdn-assets-relay92.net/verify", domain: "cdn-assets-relay92.net", method: "POST", action: "allowed", category: "Newly Registered Domains" }),
    zscalerWeb({ id: "b", ts: T(2), companyId: c, host: "WKS-QB-012", user: "f.zimmermann@quantumbank.ch", url: "https://malware.example/x.exe", domain: "malware.example", threatName: "Win32.Downloader", malwareCategory: "Trojan", action: "blocked", mitre: "T1105" }),
  ];
  it("registry-valid", () => assertValid(events, "zscaler-internet-access", "Zscaler Internet Access"));
  it("maps outcomes", () => {
    expect(events[0].event_type).toBe("http_request");
    expect(events[1].event_type).toBe("http_blocked");
    expect(events[1].is_detection).toBe(true);
  });
});

describe("Microsoft 365 emitters", () => {
  const c = "nexacorp";
  const events = [
    m365Operation({ id: "r", ts: T(1), companyId: c, user: "d.harel@nexacorp.com", operation: "New-InboxRule", workload: "Exchange", srcIp: "45.142.212.61", parameters: "Move to RSS, mark read", mitre: "T1114.003", tactic: "Collection" }),
    m365Operation({ id: "f", ts: T(2), companyId: c, user: "d.harel@nexacorp.com", operation: "FileDownloaded", workload: "SharePoint", srcIp: "45.142.212.61", objectId: "/sites/Finance/Payroll/2026.xlsx", siteUrl: "https://nexacorp.sharepoint.com/sites/Finance" }),
    m365Dlp({ id: "d", ts: T(3), companyId: c, user: "j.chen@nexacorp.com", policyName: "PII-Egress", ruleName: "Block Credit Cards External", srcIp: "10.10.20.9", sensitiveType: "Credit Card Number", sensitiveCount: 42, action: "blocked", recipients: "external@gmail.com" }),
  ];
  it("registry-valid", () => assertValid(events, "microsoft-365", "Microsoft 365 Unified Audit Log"));
  it("maps types + carries actor geo", () => {
    expect(events[0].event_type).toBe("policy_modification");
    expect(events[1].event_type).toBe("sharepoint_download");
    expect(events[2].event_type).toBe("dlp_block");
    expect(events[0].geo?.country).toBe("Ukraine");      // 45.142. → Kyiv
    expect(events[0].raw?.["GeoLocation.country_name"]).toBe("Ukraine");
  });
});
