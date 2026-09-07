/**
 * Scenario pack: "Sign-In Failure Burst — Okta Tenant, One Account"
 *
 * BEGINNER tier. The identity counterpart to the Windows brute-force pack, for
 * estates that have no Active Directory: everything happens inside the Okta
 * System Log.
 *
 * The teaching point is deliberately the opposite of the usual one. The attack
 * FAILS — the second factor holds — and the ticket still matters, because the
 * `outcome.reason` on the last sign-in attempt changes from INVALID_CREDENTIALS
 * to a factor challenge. That single field flip is the whole incident: it means
 * the password was finally correct. Analysts who grade an incident by whether
 * the attacker got in will close this as "blocked, no impact" and leave a live
 * working password in the hands of whoever was guessing.
 *
 * TELEMETRY: fully emitter-authored (Okta + Sentinel) — no hand-typed raw
 * blocks, so every field is registry-correct and the identity is fabric-drawn.
 *
 * NOTE: `difficulty: "beginner"` is declared on the SCENARIOS registry entry in
 * scenarios.ts (ScenarioBundle itself carries no difficulty field).
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { oktaAuthFailure, oktaSignIn, oktaMfa, oktaSystem } from "@/lib/sim/emitters/okta";
import { sentinelAlert } from "@/lib/sim/emitters/sentinel";

export function buildOktaPasswordBurstScenario(
  scenarioId = "okta-password-burst-2026",
): ScenarioBundle {
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
        "Okta's System Log records the first authentication request from 45.132.192.77 at 02:14 — a user.session.start that failed with INVALID_CREDENTIALS. This is the tenant's OWN view of the attacker: Okta is a SaaS IdP, so a customer perimeter firewall never sees this traffic — the evidence lives in the Okta System Log, not on FortiGate.",
    }),

    // 2. First failure — the address is unknown to the tenant.
    oktaAuthFailure({
      ...atk, id: "evt_okb_02_fail_first", ts: T(1 * MIN), severity: "low",
      description:
        "Another user.session.start failure for m.ben-david@rocketstack.io from 45.132.192.77 at 02:15 — one minute after the first, the burst is clearly under way.",
    }),

    // 3. The burst proper — representative of 96 identical rejections.
    oktaAuthFailure({
      ...atk, id: "evt_okb_03_fail_burst", ts: T(6 * MIN), severity: "medium",
      description:
        "A representative record from 96 user.session.start failures written for the same account between 02:15 and 02:41, all from 45.132.192.77.",
    }),

    // 4. Okta's own rate limiter kicks in — the tenant is defending itself.
    oktaSystem({
      companyId: "rocketstack", id: "evt_okb_04_ratelimit", ts: T(24 * MIN), srcIp: attackerIp,
      eventType: "system.org.rate_limit.warning", displayMessage: "Rate limit warning",
      event_type: "http_blocked", outcome: "SUCCESS", severity: "low",
      thresholds: { threshold: "60", timeSpan: "1", timeUnit: "MINUTE" },
      description: "Okta recorded a rate-limit warning for the /api/v1/authn endpoint against this tenant at 02:38.",
    }),

    // 5. THE EVENT THAT MATTERS — reason flips to MFA_REQUIRED, authStep → 1.
    oktaAuthFailure({
      ...atk, id: "evt_okb_05_password_accepted", ts: T(27 * MIN), severity: "high",
      reason: "MFA_REQUIRED", authStep: 1, sessionId: SESSION,
      description:
        "At 02:41 a user.session.start for the same account from the same address records outcome.reason MFA_REQUIRED and authenticationStep 1, with credentialType PASSWORD.",
    }),

    // 6. The factor challenge is issued to the real user's phone.
    oktaMfa({
      ...atk, id: "evt_okb_06_factor_challenge", ts: T(27 * MIN + 4_000), result: "challenge",
      factor: "OKTA_VERIFY_PUSH", sessionId: SESSION, severity: "medium", mitre: "T1621",
      description: "Okta issued an Okta Verify push challenge for this transaction at 02:41:04.",
    }),

    // 7. The push is rejected — by the user, on her own phone, at 02:41.
    oktaMfa({
      ...atk, id: "evt_okb_07_factor_denied", ts: T(27 * MIN + 51_000), result: "denied",
      factor: "OKTA_VERIFY_PUSH", sessionId: SESSION, severity: "high", mitre: "T1621",
      description:
        "Forty-seven seconds later the same transaction records outcome.result REJECTED with reason USER_REJECTED_PUSH.",
    }),

    // 8. Two more push attempts in the following four minutes, then nothing.
    oktaMfa({
      ...atk, id: "evt_okb_08_factor_retry", ts: T(31 * MIN), result: "denied",
      factor: "OKTA_VERIFY_PUSH", transactionId: "YkQ1a2VuMTAz", severity: "high", mitre: "T1621",
      description:
        "The last of two further push challenges from the same address, also rejected. No further activity from 45.132.192.77 after 02:45.",
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
          "Outcome Reasons Seen": ["INVALID_CREDENTIALS", "MFA_REQUIRED", "USER_REJECTED_PUSH"],
          "Source Addresses In Window": [attackerIp],
          "Sessions Created In Window": "0",
          "Password Last Changed": "2025-11-02T08:41:00Z",
          "Group Memberships": ["Everyone", "Finance", "Okta-MFA-Required"],
        },
        description:
          "The SIEM correlated the sign-in failures and raised a Medium alert at 02:52, with the account's directory context and the outcome reasons seen in the window.",
      }),
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

  const iocs: IOC[] = [
    {
      type: "ip",
      value: attackerIp,
      first_seen: T(0),
      last_seen: T(31 * MIN),
      reputation: "malicious",
      tags: ["external", "hosting-asn", "credential-attack"],
    },
    {
      type: "user",
      value: victim.email,
      first_seen: T(1 * MIN),
      last_seen: T(38 * MIN),
      // The account is not hostile — it is the target, and its password is now
      // known to someone else. "suspicious" flags it for action, not for blame.
      reputation: "suspicious",
      tags: ["finance", "targeted-account", "password-exposed"],
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1",
      prompt:
        "Compare okta.outcome.reason in evt_okb_03_fail_burst and in evt_okb_05_password_accepted. What changed, and what does it mean?",
      hint: "Also look at okta.authenticationContext.authenticationStep in each event.",
      kind: "single",
      options: [
        { value: "pw_correct", label: "INVALID_CREDENTIALS became MFA_REQUIRED — the password was accepted and the transaction reached the second factor" },
        { value: "locked", label: "The account was locked out, so Okta stopped evaluating the password entirely" },
        { value: "same_thing", label: "Both are password rejections; MFA_REQUIRED is just Okta's wording once a factor is enrolled" },
        { value: "policy", label: "A conditional-access policy changed mid-burst and started demanding MFA for everyone" },
      ],
      answer: "pw_correct",
      xp: 50,
      explanation:
        "INVALID_CREDENTIALS means the password itself was wrong — Okta never got past stage zero. MFA_REQUIRED is only ever written after the password stage has been SATISFIED, which is why authenticationStep moves from 0 to 1 on that same event. So at 02:41 the attacker supplied the correct password for this account. Option (c) is the most tempting and the most wrong: Okta does not report a bad password as MFA_REQUIRED, and if it did, the step counter would not have advanced. Option (d) would have changed the reason for every account in the tenant, not for one address on one account.",
    },
    {
      id: "q2",
      prompt:
        "No session was ever created (ExtendedProperties.Sessions Created In Window is 0). Which conclusion does the evidence actually support?",
      kind: "single",
      options: [
        { value: "pw_compromised", label: "The attack was blocked at the second factor, but the account's password is compromised and must be reset" },
        { value: "no_impact", label: "Nothing was accessed, so there is no impact and the ticket can be closed as blocked" },
        { value: "full_compromise", label: "The account is fully compromised — the attacker holds a valid Okta session" },
        { value: "false_positive", label: "This is a false positive caused by the user mistyping her own password from a VPN exit" },
      ],
      answer: "pw_compromised",
      xp: 60,
      explanation:
        "Two facts have to be held at once. Access was prevented — the push was rejected three times, no session exists, so there is nothing to hunt for downstream. And a credential was lost — evt_okb_05 proves the password is known to someone at 45.132.192.77, and it has not changed since 2025-11-02. Closing this as 'blocked, no impact' (option b) is the exact failure this scenario exists to prevent: the same password will work the next time the attacker catches the user off-guard on a push prompt, and it will work on any other system where she reused it. Option (d) is contradicted by evt_okb_09, which shows her real sign-in from the Tel Aviv corporate range on a Mac, while every attempt in the burst came from an Icelandic hosting provider on Windows.",
    },
    {
      id: "q3",
      prompt:
        "Which field in the sign-in events most directly separates the attacker's attempts from the user's own successful login in evt_okb_09?",
      kind: "single",
      options: [
        { value: "asorg", label: "okta.securityContext.asOrg — a hosting provider (FlokiNET) versus a consumer ISP" },
        { value: "eventtype", label: "okta.eventType — the attacker's events use a different event type" },
        { value: "severity", label: "okta.severity — the attacker's events are logged at a higher severity" },
        { value: "actorid", label: "okta.actor.id — a different actor id was used for the attempts" },
      ],
      answer: "asorg",
      xp: 50,
      explanation:
        "Every attempt in the burst carries asOrg 'FlokiNET ehf' — a bulletproof-adjacent hosting provider — while her genuine sign-in carries a residential Israeli ISP. Ordinary employees do not sign in from datacenter address space, so the ASN is one of the highest-signal, lowest-effort fields in an Okta investigation. The event type (b) is identical, user.session.start, which is the point: the attacker is using the normal login endpoint. Severity (c) stays INFO on the failures — Okta does not know it is under attack. And actor.id (d) is the same throughout, because it identifies the account being targeted, not who is doing the targeting.",
    },
    {
      id: "q4",
      prompt:
        "What is the correct immediate containment action, given exactly what these events show?",
      kind: "single",
      options: [
        { value: "reset_and_block", label: "Force a password reset for the account and block the source address, then confirm no session exists" },
        { value: "disable_user", label: "Disable the user account until the investigation is complete" },
        { value: "reimage", label: "Isolate and reimage the user's laptop, since the credential must have come from malware on it" },
        { value: "nothing", label: "No action — Okta's rate limiter and MFA already handled it automatically" },
      ],
      answer: "reset_and_block",
      xp: 50,
      explanation:
        "The lost asset is the password, so the fix is to invalidate the password and remove the attacker's path back. Disabling the account (b) punishes the victim and stops her working for a problem a reset solves in a minute. Reimaging (c) assumes a source for the credential that nothing here evidences — there is no endpoint telemetry in this incident at all, and passwords are far more often obtained from a public breach corpus or a phishing page than from local malware; you would ask the question, not act on the assumption. Option (d) mistakes 'the attack failed' for 'the risk ended'.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "Sign-In Failure Burst — Okta Tenant, One Account",
    threat_actor: "Opportunistic credential-attack operator",
    attack_kind: "okta_password_burst",
    briefing:
      "The SIEM raised a Medium alert at 02:52 for m.ben-david@rocketstack.io: a burst of Okta sign-in failures overnight from a single external IP. Okta records zero sessions created in the window. Work out what actually changed for this user, and what the ticket should ask for.",
    narrative: `Between 02:15 and 02:41 a single address in Iceland, 45.132.192.77, worked one account's password against the Okta tenant. Ninety-six user.session.start events were written for m.ben-david@rocketstack.io in twenty-six minutes, every one of them outcome.result FAILURE with reason INVALID_CREDENTIALS. Okta's own rate limiter logged a warning on /api/v1/authn at 02:38. On the face of it the tenant defended itself and the story ends there.

It does not. At 02:41 one more sign-in event is written for the same account from the same address, and its outcome.reason is not INVALID_CREDENTIALS — it is MFA_REQUIRED, with authenticationStep 1 and credentialType PASSWORD. Okta only writes that once the password stage has been satisfied. Four seconds later an Okta Verify push challenge goes out, and forty-seven seconds after that the transaction is closed with USER_REJECTED_PUSH. Two more pushes follow in the next four minutes; both are rejected. After 02:45 the address goes quiet.

So the attacker never got in. Sessions created in the window: zero. There is no session to revoke, no application to check, no data to account for. And the account's password, unchanged since November 2025, is now known to whoever is sitting behind that hosting provider.

The user's own sign-in that morning at 07:26 came from the Tel Aviv corporate range on her Mac, with Okta Verify satisfied on the first prompt — the ordinary shape of a legitimate login for this account, and a useful contrast to every attempt in the burst.`,
    learning_objectives: [
      "Read Okta System Log outcome.reason values and tell a rejected password (INVALID_CREDENTIALS) from an accepted one (MFA_REQUIRED)",
      "Use okta.authenticationContext.authenticationStep to see how far a sign-in transaction actually got",
      "Recognise that a blocked attack can still mean a lost credential, and report both facts",
      "Use okta.securityContext.asOrg to separate datacenter address space from a user's real ISP",
      "Choose containment that matches the asset actually lost, rather than the loudest available action",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: T(0), phase: "Reconnaissance", action: `TLS session to the Okta tenant from ${attackerIp}, allowed at the perimeter` },
      { ts: T(1 * MIN), phase: "Credential Access", action: "First sign-in failure for the account — INVALID_CREDENTIALS" },
      { ts: T(6 * MIN), phase: "Credential Access", action: "96 failures over 26 minutes, all from the same address" },
      { ts: T(24 * MIN), phase: "Credential Access", action: "Okta rate-limit warning on /api/v1/authn" },
      { ts: T(27 * MIN), phase: "Credential Access", action: "outcome.reason becomes MFA_REQUIRED — the password is now correct" },
      { ts: T(27 * MIN + 4_000), phase: "Credential Access", action: "Okta Verify push challenge issued to the real user's device" },
      { ts: T(27 * MIN + 51_000), phase: "Defence Success", action: "Push rejected by the user — USER_REJECTED_PUSH" },
      { ts: T(31 * MIN), phase: "Defence Success", action: "Two further pushes rejected; the source address goes quiet" },
      { ts: T(38 * MIN), phase: "Detection", action: "SIEM correlates the burst and raises the alert at 02:52" },
    ],
    questions,
  };
}
