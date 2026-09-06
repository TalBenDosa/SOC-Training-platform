import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { sysmonProcess, sysmonNetwork, sysmonFile, sysmonDns, sysmonRegistry } from "./sysmon";
import { cloudTrailEvent } from "./cloudtrail";
import { COMPANY_ASSETS } from "@/lib/sim/companyProfilesMeta";

const REG = JSON.parse(fs.readFileSync(path.resolve("scripts/log-field-registry.json"), "utf-8"));
const COMMON = new Set<string>(REG.commonFields);
function validatorFor(key: string) {
  const v = REG.vendors[key];
  const exact = new Set<string>(v.exactFields);
  const pre: string[] = v.prefixes;
  return (k: string) => COMMON.has(k) || exact.has(k) || pre.some(p => k.startsWith(p));
}
const T = (m: number) => new Date(Date.UTC(2026, 4, 10, 9, m, 0)).toISOString();

describe("Sysmon emitters", () => {
  const keyValid = validatorFor("sysmon");
  const c = "globallogis";
  const events = [
    sysmonProcess({ id: "p", ts: T(1), companyId: c, host: "WS-LOG-045", processName: "powershell.exe", cmdline: "powershell -enc SQBFAFgA", parentName: "WINWORD.EXE", mitre: "T1059.001", tactic: "Execution", signed: true }),
    sysmonNetwork({ id: "n", ts: T(2), companyId: c, host: "WS-LOG-045", processName: "powershell.exe", remoteIp: "45.135.232.44", remotePort: 443, remoteHost: "cdn-metrics-eu.com", mitre: "T1071.001", tactic: "Command and Control" }),
    sysmonFile({ id: "f", ts: T(3), companyId: c, host: "WS-LOG-045", processName: "powershell.exe", path: "C:\\Users\\Public\\u.dll" }),
    sysmonDns({ id: "d", ts: T(4), companyId: c, host: "WS-LOG-045", processName: "powershell.exe", domain: "a3f9.exfil.net", resolvedIp: "45.135.232.44" }),
    sysmonRegistry({ id: "r", ts: T(5), companyId: c, host: "WS-LOG-045", processName: "powershell.exe", targetObject: "HKU\\S-1-5-21\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater", details: "C:\\Users\\Public\\u.dll" }),
  ];

  it("emits only registry-valid Sysmon fields", () => {
    for (const e of events) {
      expect(e.vendor).toBe("Microsoft Sysmon");
      expect(e.source).toBe("sysmon");
      for (const k of Object.keys(e.raw ?? {})) expect(keyValid(k), `invalid Sysmon field "${k}" in ${e.id}`).toBe(true);
    }
  });
  it("draws host + user from the fabric", () => {
    const a = COMPANY_ASSETS[c];
    for (const e of events) {
      expect(e.hostname).toBe("WS-LOG-045");
      if (e.process?.user) expect(e.process.user.startsWith(a.netbios + "\\")).toBe(true);
    }
  });
  it("is deterministic", () => {
    const a = sysmonProcess({ id: "x", ts: T(1), companyId: c, host: "WS-LOG-045", processName: "cmd.exe", cmdline: "cmd /c whoami" });
    const b = sysmonProcess({ id: "x", ts: T(1), companyId: c, host: "WS-LOG-045", processName: "cmd.exe", cmdline: "cmd /c whoami" });
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
  });
});

describe("AWS CloudTrail emitter", () => {
  const keyValid = validatorFor("aws-cloudtrail");
  const events = [
    cloudTrailEvent({ id: "c1", ts: T(1), eventName: "ConsoleLogin", srcIp: "45.142.212.61", outcome: "success", mfa: false, actorName: "cyberark.svc", mitre: "T1078.004", tactic: "Initial Access" }),
    cloudTrailEvent({ id: "c2", ts: T(2), eventName: "GetObject", srcIp: "45.142.212.61", s3Bucket: "qb-customer-exports", s3Key: "2026/pii.csv", bytes: 193000000, mitre: "T1530", tactic: "Exfiltration" }),
    cloudTrailEvent({ id: "c3", ts: T(3), eventName: "CreateAccessKey", srcIp: "45.142.212.61", actorName: "svc-deploy", mitre: "T1098", tactic: "Persistence" }),
    cloudTrailEvent({ id: "c4", ts: T(4), eventName: "StopLogging", srcIp: "45.142.212.61", mitre: "T1562.008", tactic: "Defense Evasion" }),
    cloudTrailEvent({ id: "c5", ts: T(5), eventName: "GetObject", srcIp: "10.100.1.5", outcome: "failure", errorCode: "AccessDenied" }),
  ];

  it("emits only registry-valid CloudTrail fields", () => {
    for (const e of events) {
      expect(e.vendor).toBe("AWS CloudTrail");
      expect(e.source).toBe("cloudtrail");
      for (const k of Object.keys(e.raw ?? {})) expect(keyValid(k), `invalid CloudTrail field "${k}" in ${e.id}`).toBe(true);
    }
  });
  it("maps eventName → the right event type and source", () => {
    const [login, get, key, stop] = events;
    expect(login.event_type).toBe("auth_success");
    expect(login.raw?.["aws.cloudtrail.event_source"]).toBe("signin.amazonaws.com");
    expect(get.event_type).toBe("cloud_storage_access");
    expect(get.raw?.["aws.s3.bucket.name"]).toBe("qb-customer-exports");
    expect(key.event_type).toBe("cloud_role_change");
    expect(key.raw?.["aws.cloudtrail.event_source"]).toBe("iam.amazonaws.com");
    expect(stop.event_type).toBe("audit_log_cleared");
  });
  it("resolves geo deterministically from the IP, and marks failures", () => {
    expect(events[0].geo?.country).toBe("Ukraine");      // 45.142. → Kyiv
    expect(events[4].event_type).toBe("cloud_storage_access");
    expect(events[4].raw?.["event.outcome"]).toBe("failure");
    expect(events[4].raw?.["event.reason"]).toBe("AccessDenied");
  });
});
