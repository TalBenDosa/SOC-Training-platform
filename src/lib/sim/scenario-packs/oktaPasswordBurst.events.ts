/**
 * Events-only half of the ./oktaPasswordBurst.ts scenario pack.
 *
 * The dashboard's live feed runs in the browser (attackStories.ts), so what it
 * imports ships in a public /_next/static chunk. The answer key (questions,
 * answers, explanations, IOCs, killchain, narrative) stays in the builder in
 * ./oktaPasswordBurst.ts, which composes this module on the server. Keep anything
 * answer-bearing out of this file: every visitor can read it.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { oktaAuthFailure, oktaSignIn, oktaMfa, oktaSystem } from "@/lib/sim/emitters/okta";
import { sentinelAlert } from "@/lib/sim/emitters/sentinel";

/** Telemetry half of `buildOktaPasswordBurstScenario`: the events and the story title, no answer key. */
export function oktaPasswordBurstScenarioEvents() {
  const B = new Date("2026-06-11T02:14:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  // The targeted account — a finance user, no admin entitlement.
  const victim = { email: "m.ben-david@rocketstack.io", name: "Maya Ben-David" };

  // Single attacker address, hosting-provider ASN.
  const attackerIp = "45.132.192.77";
  const attackerAsn = "AS200651";
  const attackerAsOrg = "FlokiNET ehf";

  // The user's own device and network, for contrast.
  const corpIp = "94.188.12.61";

  const ua =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";

  // EDR↔scenario integration (Phase 4): control-plane-only incident — a password
  // burst against a single Okta account, with no host EDR events and no process to
  // walk. edr_scope "non_edr": nothing to investigate in the EDR console.
  const INCIDENT = "inc:okb:1";

  const SESSION = "trs2Wn9kQmyTQiKp0LxVfA";

  // Shared attacker sign-in context — one attacker, one origin, one ASN, one geo.
  const atk = {
    companyId: "rocketstack" as const, user: victim.email, displayName: victim.name,
    userTitle: "Finance Analyst", srcIp: attackerIp,
    geo: { country: "Iceland", city: "Reykjavik", latitude: 64.15, longitude: -21.94 },
    userAgent: ua, os: "Windows 10", browser: "CHROME",
    asn: attackerAsn, asOrg: attackerAsOrg, domain: "flokinet.is", threatSuspected: false,
    mitre: "T1110.001", tactic: "Credential Access" as const,
  };

  const events: TelemetryEvent[] = [
    // 1. First authentication request seen by the tenant — a failed sign-in.
    oktaAuthFailure({
      ...atk, id: "evt_okb_01_okta_first_seen", ts: T(0), severity: "low",
      description:
        "Okta System Log: user.session.start FAILURE (INVALID_CREDENTIALS) for m.ben-david@rocketstack.io from 45.132.192.77 (AS200651 FlokiNET ehf, Reykjavik) at 02:14.",
    }),

    // 2. First failure — the address is unknown to the tenant.
    oktaAuthFailure({
      ...atk, id: "evt_okb_02_fail_first", ts: T(1 * MIN), severity: "low",
      description:
        "A second user.session.start FAILURE (INVALID_CREDENTIALS) for the same account from 45.132.192.77 at 02:15.",
    }),

    // 4. The first alert: Okta ThreatInsight (log-only mode) flags the address — it is on
    //    Okta's cross-tenant list of IPs running credential attacks. Log mode = ALLOW, so the
    //    attempts keep reaching the password check.
    oktaSystem({
      companyId: "rocketstack", id: "evt_okb_04_threatinsight", ts: T(4 * MIN), srcIp: attackerIp,
      eventType: "security.threat.detected", displayMessage: "Request from suspicious actor",
      event_type: "threat_intel_match", outcome: "SUCCESS", severity: "medium",
      geo: atk.geo, asn: attackerAsn, asOrg: attackerAsOrg, domain: "flokinet.is",
      mitre: "T1110.001", tactic: "Credential Access",
      description: "Okta ThreatInsight logged security.threat.detected for 45.132.192.77 at 02:18 against the tenant's /api/v1/authn endpoint; outcome ALLOW (log-only mode).",
    }),

    // 3. The burst proper — representative of 96 identical rejections.
    oktaAuthFailure({
      ...atk, id: "evt_okb_03_fail_burst", ts: T(6 * MIN), severity: "medium",
      description:
        "A representative user.session.start FAILURE (INVALID_CREDENTIALS) of the burst for the same account, from 45.132.192.77 at 02:20.",
    }),

    // 5. THE EVENT THAT MATTERS — reason flips to MFA_REQUIRED, authStep → 1.
    oktaAuthFailure({
      ...atk, id: "evt_okb_05_password_accepted", ts: T(27 * MIN), severity: "high",
      reason: "MFA_REQUIRED", authStep: 1, sessionId: SESSION,
      description:
        "At 02:41 the next sign-in for the same account from 45.132.192.77 is not an INVALID_CREDENTIALS failure: Okta evaluated the sign-on policy for it — policy.evaluate_sign_on, outcome CHALLENGE, rule \"Require MFA outside Corporate HQ\".",
    }),

    // 6. The factor challenge is issued to the real user's phone.
    oktaMfa({
      ...atk, id: "evt_okb_06_factor_challenge", ts: T(27 * MIN + 4_000), result: "challenge",
      factor: "OKTA_VERIFY_PUSH", sessionId: SESSION, severity: "medium", mitre: "T1621",
      description: "system.push.send_factor_verify_push at 02:41:04 — an Okta Verify push sent to the account's enrolled device for the session started from 45.132.192.77.",
    }),

    // 7. The push is rejected — by the user, on her own phone, at 02:41.
    oktaMfa({
      ...atk, id: "evt_okb_07_factor_denied", ts: T(27 * MIN + 51_000), result: "denied",
      factor: "OKTA_VERIFY_PUSH", sessionId: SESSION, severity: "high", mitre: "T1621",
      description:
        "Forty-seven seconds later user.authentication.auth_via_mfa for the same session: outcome FAILURE, factor OKTA_VERIFY_PUSH, pushOnlyResponseType OV_RESPONSE_DENY.",
    }),

    // 8. Two more push attempts in the following four minutes, then nothing.
    oktaMfa({
      ...atk, id: "evt_okb_08_factor_retry", ts: T(31 * MIN), result: "denied",
      factor: "OKTA_VERIFY_PUSH", transactionId: "YkQ1a2VuMTAz", severity: "high", mitre: "T1621",
      description:
        "02:45 — another user.authentication.auth_via_mfa FAILURE (OV_RESPONSE_DENY) for a push from the same address; the System Log shows no later event from 45.132.192.77.",
    }),

    // 10. The correlation that opened the ticket, with the account context.
    {
      ...sentinelAlert({
        companyId: "rocketstack", id: "evt_okb_10_siem_context", ts: T(38 * MIN),
        srcIp: attackerIp, user: victim.email, alertName: "OktaSignInFailureBurst_SingleAccount",
        ruleId: "SEN-IDENT-0204", severity: "medium", eventType: "ueba_anomaly",
        fullName: victim.name, department: "Finance", title: "Finance Analyst",
        extendedProperties: {
          "Window Start": T(1 * MIN),
          "Window End": T(31 * MIN),
          "Failure Count": "96",
          "Event Types Seen": ["security.threat.detected", "user.session.start", "policy.evaluate_sign_on", "system.push.send_factor_verify_push", "user.authentication.auth_via_mfa"],
          "Outcome Reasons Seen": ["INVALID_CREDENTIALS", "CHALLENGE", "OV_RESPONSE_DENY"],
          "Source Addresses In Window": [attackerIp],
          "Sessions Created In Window": "0",
          "Password Last Changed": "2025-11-02T08:41:00Z",
          "Group Memberships": ["Everyone", "Finance", "Okta-MFA-Required"],
        },
        description:
          "Sentinel raised a Medium alert at 02:52 for m.ben-david@rocketstack.io: 96 sign-in failures from 45.132.192.77, then a sign-on policy CHALLENGE and denied pushes, 0 sessions created.",
      }),
      // An identity alert: no device entity (the attacker's machine is not ours).
      hostname: undefined,
      edr_scope: "non_edr",
    },

    // 9. The user's own successful sign-in that morning — the baseline.
    {
      ...oktaSignIn({
        companyId: "rocketstack", id: "evt_okb_09_user_normal_login", ts: T(5 * 60 * MIN + 12 * MIN),
        user: victim.email, displayName: victim.name, userTitle: "Finance Analyst", srcIp: corpIp,
        geo: { country: "Israel", city: "Tel Aviv" }, mfaUsed: true, factor: "OKTA_VERIFY_PUSH",
        userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
        os: "Mac OS X", browser: "SAFARI", asn: "AS12849", asOrg: "Hot-Net internet services Ltd.", severity: "low",
        description: "The account's own sign-in at 07:26 from the corporate range, with a Mac device and Okta Verify satisfied.",
      }),
      is_baseline: true,
    },
  ];

  // Every event belongs to the one Okta password-burst incident.
  for (const e of events) e.incident_id = INCIDENT;
  // The identity alert's entities are the account and the source address — no device.
  for (const e of events) if (e.source === "siem" && e.raw) {
    delete e.raw["host.name"];
    delete e.raw["host.ip"];
    e.raw["source.ip"] = attackerIp;
  }

  return { title: "Sign-In Failure Burst — Okta Tenant, One Account", events, T, MIN, victim, attackerIp };
}
