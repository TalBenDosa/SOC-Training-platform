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
    // A denied Okta Verify push in an Identity Engine org (card idp-okta): auth_via_mfa FAILURE,
    // reason INVALID_CREDENTIALS, pushOnlyResponseType OV_RESPONSE_DENY.
    expect(deny.event_type).toBe("mfa_denied");
    expect(deny.raw?.["okta.eventType"]).toBe("user.authentication.auth_via_mfa");
    expect(deny.raw?.["okta.outcome.result"]).toBe("FAILURE");
    expect(deny.raw?.["okta.outcome.reason"]).toBe("INVALID_CREDENTIALS");
    expect(deny.raw?.["okta.debugContext.debugData.pushOnlyResponseType"]).toBe("OV_RESPONSE_DENY");
    expect(deny.raw?.["okta.debugContext.debugData.factor"]).toBe("OKTA_VERIFY_PUSH");
  });

  it("uses only real Okta event types and outcomes (card idp-okta)", () => {
    const base = { ts: T(30), companyId: "rocketstack", user: "m.ben-david@rocketstack.io", srcIp: "91.108.23.5" };
    const sent = oktaMfa({ ...base, id: "p1", result: "sent" });
    expect(sent.raw?.["okta.eventType"]).toBe("system.push.send_factor_verify_push");
    expect(sent.raw?.["okta.outcome.result"]).toBe("SUCCESS");
    const ok = oktaMfa({ ...base, id: "p2", result: "approved" });
    expect(ok.raw?.["okta.eventType"]).toBe("user.authentication.auth_via_mfa");
    expect(ok.raw?.["okta.outcome.result"]).toBe("SUCCESS");
    expect(ok.raw?.["okta.debugContext.debugData.pushOnlyResponseType"]).toBe("OV_RESPONSE_APPROVE");
    // "Password accepted, second factor required" is the sign-on policy answering CHALLENGE, not a failure.
    for (const e of [oktaMfa({ ...base, id: "p3", result: "challenge" }), oktaAuthFailure({ ...base, id: "p4", reason: "MFA_REQUIRED", authStep: 1 })]) {
      expect(e.raw?.["okta.eventType"]).toBe("policy.evaluate_sign_on");
      expect(e.raw?.["okta.outcome.result"]).toBe("CHALLENGE");
      expect(e.raw?.["okta.outcome.reason"]).toBe("Sign-on policy evaluation resulted in CHALLENGE");
      expect(e.event_type).toBe("mfa_challenge");
    }
    const REAL = new Set(["user.session.start", "user.authentication.auth_via_mfa", "system.push.send_factor_verify_push", "policy.evaluate_sign_on"]);
    const RESULTS = new Set(["SUCCESS", "FAILURE", "CHALLENGE", "ALLOW", "DENY"]);
    for (const e of [...events, sent, ok]) {
      expect(REAL.has(String(e.raw?.["okta.eventType"])), String(e.raw?.["okta.eventType"])).toBe(true);
      expect(RESULTS.has(String(e.raw?.["okta.outcome.result"]))).toBe(true);
      // authenticationStep is always 0 (deprecated in the System Log).
      expect(e.raw?.["okta.authenticationContext.authenticationStep"]).toBe("0");
    }
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
