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

import type { ScenarioBundle, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { oktaPasswordBurstScenarioEvents } from "./oktaPasswordBurst.events";

export function buildOktaPasswordBurstScenario(
  scenarioId = "okta-password-burst-2026",
): ScenarioBundle {
  const { title, events, T, MIN, victim, attackerIp } = oktaPasswordBurstScenarioEvents();

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
        { value: "pw_correct", label: "The reason became MFA_REQUIRED — the password stage passed and the sign-in moved on to the second factor" },
        { value: "locked", label: "The account hit Okta's lockout threshold, so the password stage was skipped and MFA_REQUIRED was written" },
        { value: "same_thing", label: "Both are password rejections; MFA_REQUIRED is simply how Okta words a bad password once a push factor is enrolled" },
        { value: "policy", label: "A sign-on policy was edited mid-burst to demand MFA on every sign-in, so the reason changed whatever the password" },
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
        { value: "pw_compromised", label: "Access was blocked at the second factor, but the password itself is compromised and must be reset" },
        { value: "no_impact", label: "No session and no data access means no impact — the ticket can be closed as a blocked attack" },
        { value: "full_compromise", label: "The account is fully compromised — MFA_REQUIRED means the attacker already holds a valid Okta session" },
        { value: "false_positive", label: "A false positive — the user mistyping her own password through a VPN exit node, then rejecting her own pushes" },
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
        { value: "eventtype", label: "okta.eventType — the attempts are logged under a different, API-level authentication event type" },
        { value: "severity", label: "okta.severity — Okta logs the attacker's attempts at WARN, above the INFO of a normal sign-in" },
        { value: "actorid", label: "okta.actor.id — the attempts carry a different actor id from the one on the user's own login" },
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
        { value: "disable_user", label: "Disable the user account in Okta until the investigation is complete, so nobody can use the password" },
        { value: "reimage", label: "Isolate and reimage the user's laptop, since the password must have been harvested by malware on it" },
        { value: "nothing", label: "No action — Okta's rate limiter and the rejected pushes show the controls already contained the attack" },
      ],
      answer: "reset_and_block",
      xp: 50,
      explanation:
        "The lost asset is the password, so the fix is to invalidate the password and remove the attacker's path back. Disabling the account (b) punishes the victim and stops her working for a problem a reset solves in a minute. Reimaging (c) assumes a source for the credential that nothing here evidences — there is no endpoint telemetry in this incident at all, and passwords are far more often obtained from a public breach corpus or a phishing page than from local malware; you would ask the question, not act on the assumption. Option (d) mistakes 'the attack failed' for 'the risk ended'.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title,
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
