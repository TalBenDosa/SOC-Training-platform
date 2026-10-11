import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { winFailedLogon, winLogon, winShareAccess, winObjectAccess } from "./windowsSecurity";

const REG = JSON.parse(fs.readFileSync(path.resolve("scripts/log-field-registry.json"), "utf-8"));
const COMMON = new Set<string>(REG.commonFields);
const v = REG.vendors["microsoft-active-directory"];
const exact = new Set<string>(v.exactFields);
const prefixes: string[] = v.prefixes;
const keyValid = (k: string) => COMMON.has(k) || exact.has(k) || prefixes.some(p => k.startsWith(p));
const T = (m: number) => new Date(Date.UTC(2026, 5, 4, 9, m, 0)).toISOString();

describe("Windows Security emitters", () => {
  const c = "nexacorp";
  const events = [
    winFailedLogon({ id: "f1", ts: T(2), companyId: c, host: "SRV-RDS-02", targetUser: "swolfe", userEmail: null, srcIp: "91.108.23.146", subStatus: "0xC0000064", logonType: 3, mitre: "T1110.001", tactic: "Credential Access" }),
    winLogon({ id: "s1", ts: T(20), companyId: c, host: "SRV-RDS-02", targetUser: "s.wolfe", targetSid: "S-1-5-21-1-1-1-4419", srcIp: "91.108.23.146", logonType: 3, mitre: "T1078", tactic: "Initial Access" }),
    winShareAccess({ id: "sh", ts: T(22), companyId: c, host: "FS-CORP-02", targetUser: "s.wolfe", srcIp: "10.30.9.20", shareName: "\\\\*\\HR-Confidential" }),
    winObjectAccess({ id: "fr", ts: T(23), companyId: c, host: "FS-CORP-02", targetUser: "s.wolfe", srcIp: "10.30.9.20", objectName: "E:\\Shares\\HR-Confidential\\salary.xlsx", mitre: "T1039", tactic: "Collection" }),
  ];

  it("emits only registry-valid Windows Security fields", () => {
    for (const e of events) {
      expect(e.vendor).toBe("Windows Security");
      for (const k of Object.keys(e.raw ?? {})) expect(keyValid(k), `invalid field "${k}" in ${e.id}`).toBe(true);
    }
  });
  it("maps event ids + a no-mailbox 4625 for a non-existent user", () => {
    expect(events[0].raw?.["winlog.event_id"]).toBe("4625");
    expect(events[0].raw?.["winlog.event_data.SubStatus"]).toBe("0xC0000064");
    expect(events[0].user_email).toBeUndefined();       // userEmail: null → no mailbox
    expect(events[1].raw?.["winlog.event_id"]).toBe("4624");
    expect(events[1].user_email).toBe("s.wolfe@nexacorp.com");
    expect(events[2].raw?.["winlog.event_id"]).toBe("5140");
    expect(events[3].raw?.["winlog.event_id"]).toBe("4663");
  });
  it("stamps the company NetBIOS realm", () => {
    expect(events[1].raw?.["winlog.event_data.TargetDomainName"]).toBe("NEXACORP");
  });
});
