import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { entraSignIn } from "./entra";

const REG = JSON.parse(fs.readFileSync(path.resolve("scripts/log-field-registry.json"), "utf-8"));
const COMMON = new Set<string>(REG.commonFields);
const v = REG.vendors["azure-ad"];
const exact = new Set<string>(v.exactFields);
const prefixes: string[] = v.prefixes;
const keyValid = (k: string) => COMMON.has(k) || exact.has(k) || prefixes.some(p => k.startsWith(p));

const T = (m: number) => new Date(Date.UTC(2026, 4, 10, 6, m, 0)).toISOString();

describe("Microsoft Entra ID emitter", () => {
  const baseline = entraSignIn({ id: "b", ts: T(0), companyId: "nexacorp", user: "d.harel@nexacorp.com", srcIp: "207.154.10.9", mfa: true, managed: true, compliant: true, os: "Windows 11", browser: "Edge 124.0" });
  const foreign = entraSignIn({ id: "f", ts: T(135), companyId: "nexacorp", user: "d.harel@nexacorp.com", srcIp: "45.142.212.61", result: "success", mfa: false, riskLevel: "high", mitre: "T1078.004", tactic: "Initial Access" });
  const fail = entraSignIn({ id: "x", ts: T(1), companyId: "nexacorp", user: "d.harel@nexacorp.com", srcIp: "91.108.23.9", result: "failure", errorCode: "50126" });
  const events = [baseline, foreign, fail];

  it("emits only registry-valid Entra fields", () => {
    for (const e of events) {
      expect(e.vendor).toBe("Microsoft Entra ID");
      expect(e.source).toBe("o365");
      for (const k of Object.keys(e.raw ?? {})) {
        expect(keyValid(k), `invalid Entra field "${k}" in ${e.id}`).toBe(true);
      }
    }
  });

  it("resolves geography deterministically from the IP", () => {
    expect(baseline.geo?.city).toBe("London");          // 207.154. → London
    expect(foreign.geo?.country).toBe("Ukraine");        // 45.142. → Kyiv, Ukraine
    expect(fail.geo?.country).toBe("Russia");            // 91.108. → Moscow
    expect(baseline.raw?.["GeoLocation.city_name"]).toBe("London");
    expect(baseline.raw?.["azure.signinlogs.properties.location.countryOrRegion"]).toBe("GB");
  });

  it("maps success vs failure correctly", () => {
    expect(baseline.event_type).toBe("auth_success");
    expect(baseline.raw?.["azure.signinlogs.resultType"]).toBe("0");
    expect(baseline.raw?.["azure.signinlogs.properties.authenticationRequirement"]).toBe("multiFactorAuthentication");
    expect(fail.event_type).toBe("auth_failure");
    expect(fail.raw?.["azure.signinlogs.resultType"]).toBe("50126");
    expect(String(fail.raw?.["azure.signinlogs.resultDescription"])).toContain("invalid username or password");
  });

  it("is deterministic", () => {
    const a = entraSignIn({ id: "z", ts: T(9), companyId: "nexacorp", user: "d.harel@nexacorp.com", srcIp: "207.154.10.9" });
    const b = entraSignIn({ id: "z", ts: T(9), companyId: "nexacorp", user: "d.harel@nexacorp.com", srcIp: "207.154.10.9" });
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
  });
});
