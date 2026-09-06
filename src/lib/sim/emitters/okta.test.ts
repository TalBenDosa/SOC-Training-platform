import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { oktaSignIn, oktaAuthFailure, oktaMfa } from "./okta";

const REG = JSON.parse(fs.readFileSync(path.resolve("scripts/log-field-registry.json"), "utf-8"));
const COMMON = new Set<string>(REG.commonFields);
const okta = REG.vendors["okta"];
const exact = new Set<string>(okta.exactFields);
const prefixes: string[] = okta.prefixes;
const keyValid = (k: string) => COMMON.has(k) || exact.has(k) || prefixes.some(p => k.startsWith(p));

const T = (m: number) => new Date(Date.UTC(2026, 4, 10, 2, m, 0)).toISOString();

describe("Okta emitters", () => {
  const events = [
    oktaAuthFailure({ id: "f1", ts: T(0), companyId: "rocketstack", user: "m.ben-david@rocketstack.io", srcIp: "91.108.23.5", mitre: "T1110.001", tactic: "Credential Access" }),
    oktaSignIn({ id: "s1", ts: T(20), companyId: "rocketstack", user: "m.ben-david@rocketstack.io", srcIp: "91.108.23.5", mfaUsed: true, factor: "OKTA_VERIFY_PUSH" }),
    oktaMfa({ id: "m1", ts: T(21), companyId: "rocketstack", user: "m.ben-david@rocketstack.io", srcIp: "91.108.23.5", result: "denied" }),
  ];

  it("emits only registry-valid Okta fields", () => {
    for (const e of events) {
      expect(e.vendor).toBe("Okta");
      expect(e.source).toBe("okta");
      for (const k of Object.keys(e.raw ?? {})) {
        expect(keyValid(k), `invalid Okta field "${k}" in ${e.id}`).toBe(true);
      }
    }
  });

  it("resolves sign-in geography DETERMINISTICALLY from the source IP (one IP → one place)", () => {
    // 91.108.* is Russia/Moscow in the shared KNOWN_GEO map.
    for (const e of events) {
      expect(e.geo?.country).toBe("Russia");
      expect(e.geo?.city).toBe("Moscow");
      expect(e.raw?.["source.geo.country_name"]).toBe("Russia");
      expect(e.raw?.["okta.client.geographicalContext.country"]).toBe("Russia");
    }
  });

  it("maps outcomes and event types correctly", () => {
    const [fail, ok, deny] = events;
    expect(fail.event_type).toBe("auth_failure");
    expect(fail.raw?.["okta.outcome.result"]).toBe("FAILURE");
    expect(fail.raw?.["okta.outcome.reason"]).toBe("INVALID_CREDENTIALS");
    expect(ok.event_type).toBe("auth_success");
    expect(ok.raw?.["okta.outcome.result"]).toBe("SUCCESS");
    expect(ok.raw?.["authentication.mfa"]).toBe("true");
    expect(deny.event_type).toBe("mfa_denied");
    expect(deny.raw?.["okta.eventType"]).toBe("user.mfa.okta_verify.deny_push");
  });

  it("is deterministic — same inputs render byte-identical output", () => {
    const a = oktaSignIn({ id: "x", ts: T(5), companyId: "rocketstack", user: "t.levy@rocketstack.io", srcIp: "203.0.113.10" });
    const b = oktaSignIn({ id: "x", ts: T(5), companyId: "rocketstack", user: "t.levy@rocketstack.io", srcIp: "203.0.113.10" });
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
  });

  it("carries the real target identity through the ECS + Okta fields", () => {
    const e = events[0];
    expect(e.user_email).toBe("m.ben-david@rocketstack.io");
    expect(e.raw?.["target.user.email"]).toBe("m.ben-david@rocketstack.io");
    expect(e.raw?.["okta.actor.alternateId"]).toBe("m.ben-david@rocketstack.io");
  });
});
