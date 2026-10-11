/**
 * Scenario pack: "Help Desk MFA Reset — Social Engineering Account Takeover"
 *
 * CORE tier. The Scattered-Spider-style help-desk social-engineering pattern
 * behind the largest 2023-2025 identity breaches. No malware, no exploit —
 * a phone call.
 *
 * An attacker calls the IT help desk impersonating a real employee (T1684.001),
 * convinces the agent to reset her password and clear her MFA. The ticket is
 * opened and resolved like any other MFA-reset call — because on its face it
 * is one; NexaCorp's help desk handles several of these a week. Within
 * minutes a NEW Microsoft Authenticator is registered on the account
 * (T1098.005) and a genuinely-MFA-satisfied sign-in arrives from a new IP and
 * a new country (T1078.004) — while the real employee's own session, opened
 * earlier the same morning from her own laptop, is still live.
 *
 * The teaching point is deliberately uncomfortable: nothing in any single
 * record is malicious. The ticket looks like routine support. The reset
 * looks like routine administration. The new sign-in genuinely completes
 * password + MFA, because the attacker now holds a working second factor.
 * Entra's own risk engine has nothing to key on. The only thing that gives
 * this away is the SEQUENCE — ticket, reset, new device, new geo, all inside
 * nineteen minutes — compared against the plain fact that the account's
 * legitimate owner was demonstrably still working from London ten minutes
 * before the reset even started.
 *
 * Covers T1684.001 (Social Engineering: Impersonation, formerly T1656), T1556.006 (Modify Authentication Process:
 * Multi-Factor Authentication), T1098.005 (Account Manipulation: Device
 * Registration) and T1078.004 (Valid Accounts: Cloud Accounts) — an
 * identity-help-desk-abuse case the live feed did not previously have.
 *
 * NOTE: register in scenarios.ts with difficulty "core" (ScenarioBundle
 * itself carries no difficulty field). Company allowlist: nexacorp, medcore,
 * globallogis — the three profiles running Microsoft 365 / Entra ID.
 */

import type { ScenarioBundle, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { helpdeskMfaResetScenarioEvents } from "./helpdeskMfaReset.events";

export function buildHelpdeskMfaResetScenario(
  scenarioId = "helpdesk-mfa-reset-2026",
): ScenarioBundle {
  const { title, events, T, MIN, victim, attackerIp, vdiHost } = helpdeskMfaResetScenarioEvents();

  const iocs: IOC[] = [
    {
      type: "ip",
      value: attackerIp,
      first_seen: T(58 * MIN),
      last_seen: T(61 * MIN),
      reputation: "malicious",
      tags: ["hosting-provider", "asn-60068", "amsterdam", "new-mfa-device"],
    },
    {
      type: "user",
      value: victim.email,
      first_seen: T(0),
      last_seen: T(66 * MIN),
      reputation: "suspicious",
      tags: ["compromised-account", "helpdesk-mfa-reset"],
    },
    {
      type: "host",
      value: vdiHost.hostname,
      first_seen: T(66 * MIN),
      last_seen: T(66 * MIN),
      reputation: "unknown",
      tags: ["internal-vdi", "session-landed"],
    },
    {
      type: "ip",
      value: victim.homeIp,
      first_seen: T(0),
      last_seen: T(45 * MIN),
      reputation: "clean",
      tags: ["user-baseline", "london"],
    },
    {
      type: "host",
      value: victim.hostname,
      first_seen: T(0),
      last_seen: T(45 * MIN),
      reputation: "clean",
      tags: ["corporate-laptop", "entra-joined"],
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1",
      prompt:
        "Which pair of events makes this undeniable — not just an odd coincidence of timing?",
      hint: "Compare where l.ferreira's account is authenticating from at 09:45 against where it authenticates from at 10:01.",
      kind: "single",
      options: [
        {
          value: "concurrent_sessions",
          label:
            "London sign-in at 09:45 + Amsterdam sign-in at 10:01 — the same account, MFA-satisfied, from two cities sixteen minutes apart",
        },
        {
          value: "ticket_pair",
          label: "Ticket created at 09:41 + ticket resolved at 09:52 — an MFA-reset ticket opened and closed in eleven minutes, far faster than normal",
        },
        {
          value: "reset_alone",
          label: "The help-desk MFA reset at 09:53 on its own — removing a user's second factor is inherently a red flag for account takeover",
        },
        {
          value: "vdi_alone",
          label: "The VDI session at 10:06 on its own — an interactive logon landing on a VDI host is unusual enough to confirm the intrusion",
        },
      ],
      answer: "concurrent_sessions",
      xp: 50,
      explanation:
        "No commercial flight gets a person from London to Amsterdam in sixteen minutes, and both records show a completed password + Authenticator MFA challenge — this isn't a stale token or a risk-engine guess, it's two independently authenticated sessions on one account at the same time. Option (b) is a normal turnaround for a routine call; NexaCorp's help desk resolves several MFA-reset tickets a week in under fifteen minutes. Option (c) overstates a single field — MFA resets are routine help-desk work, not evidence on their own. Option (d) is real supporting detail but proves nothing without the concurrent-session evidence behind it.",
    },
    {
      id: "q2",
      prompt:
        "A month ago a different employee called this same help desk after genuinely losing her phone: MFA was reset, and she registered a new Authenticator that afternoon from her desk. What in THIS case distinguishes it from that ordinary one?",
      hint: "Ask where the new-device registration actually came from, and what the account owner was doing at the same time.",
      kind: "single",
      options: [
        {
          value: "ip_and_concurrent",
          label:
            "The device was registered from an IP seen nowhere else for her or the help desk, while her own London session was still live",
        },
        {
          value: "verification_dob",
          label: "The caller was verified by date of birth alone, a knowledge factor weak enough that it marks the call as social engineering",
        },
        {
          value: "any_reset_bad",
          label: "The reset was performed over the phone rather than in person, and remote MFA resets should be handled as compromise by default",
        },
        {
          value: "ticket_priority",
          label: "The ticket was logged as priority 3 rather than priority 1, which is inconsistent with a user who is genuinely locked out",
        },
      ],
      answer: "ip_and_concurrent",
      xp: 70,
      explanation:
        "The genuine lost-phone case looks exactly like evt_hmr_02 through evt_hmr_05 on their own — a phone call, a reset, a new registration. What separates an ordinary re-enrollment from this one is where evt_hmr_06 comes from: 5.181.234.19, an address that appears nowhere else in l.ferreira's telemetry, and the fact that her own laptop was still authenticating normally from London in evt_hmr_03 seven minutes before the reset even started. An employee who actually lost her phone doesn't have a second, live, unrelated session running from her own desk while someone else re-enrolls her account. Option (b) overweights a single, common verification method — DOB checks are standard and weak, but weak process alone isn't proof of an incident. Option (c) would flag every legitimate lost-phone case; phone-based MFA resets are how most help desks operate. Option (d) is not a real signal — urgency and priority reflect what the caller claimed, not what happened next.",
    },
    {
      id: "q3",
      prompt:
        "In evt_hmr_06, initiatedBy.user.userPrincipalName reads l.ferreira@nexacorp.com — her own identity performed the registration. Why doesn't that clear her?",
      hint: "InitiatedBy tells you which account was used. It does not tell you who was sitting at the keyboard.",
      kind: "single",
      options: [
        {
          value: "identity_vs_network",
          label:
            "initiatedBy shows which account acted, not who was at the keyboard; with MFA cleared anyone with the password could, and ipAddress shows it wasn't her",
        },
        {
          value: "field_wrong",
          label: "initiatedBy.user is only populated for admin-initiated actions, so a user UPN appearing here indicates a logging or ingestion error",
        },
        {
          value: "self_service_impossible",
          label: "Users cannot register their own security info through self-service in this tenant, so the record must have been forged by the attacker",
        },
        {
          value: "doesnt_matter",
          label: "It doesn't matter who initiated it, because registering an Authenticator is a low-sensitivity, self-service action that Entra does not treat as privileged",
        },
      ],
      answer: "identity_vs_network",
      xp: 60,
      explanation:
        "After evt_hmr_05, l.ferreira's account had no registered second factor and a password the caller had just had reset — exactly the state needed for anyone who knows that password to sign in and self-enroll a fresh Authenticator, which is precisely what evt_hmr_06 records. Entra logs faithfully report which account performed the action; it has no way to know whose hands were on the keyboard. That's why ipAddress matters here — it's independent, network-layer evidence that sits alongside the identity claim, and in this record it points to Amsterdam while every other trace of l.ferreira that morning points to London. Option (b) is wrong — self-service registration is exactly how most users legitimately re-enroll after a reset. Option (c) is also wrong for the same reason. Option (d) understates the technique: T1098.005 exists precisely because a self-registered authenticator is a durable foothold that survives a password change.",
    },
    {
      id: "q4",
      prompt: "You're closing this out. Which action set actually removes the attacker's access?",
      hint: "A password reset alone does nothing to an authenticator that's already enrolled.",
      kind: "single",
      options: [
        {
          value: "revoke_and_delete",
          label:
            "Revoke her sessions and tokens, delete the Authenticator added at 09:58, reset the password, and verify her out-of-band",
        },
        {
          value: "reset_password_only",
          label: "Reset the password a second time, require MFA on next sign-in, note the earlier reset in the ticket, and close the matter",
        },
        {
          value: "block_ip_only",
          label: "Block 5.181.234.19 at the perimeter and on the VDI gateway — with the attacker's IP blocked, their access to the account is gone",
        },
        {
          value: "retrain_agent",
          label: "Leave the account as is and retrain James Oduya on the caller-verification procedure he skipped, since that process gap caused this",
        },
      ],
      answer: "revoke_and_delete",
      xp: 70,
      explanation:
        "A second password reset does nothing on its own — the attacker's Authenticator app, registered at evt_hmr_06, still satisfies MFA on the very next sign-in attempt, password change or not. The session opened at evt_hmr_07 also needs to be killed directly; a live session can outlast a credential change. Blocking the IP (option c) stops nothing durable — it's trivial to originate the next sign-in from a different address once the rogue authenticator is already enrolled. Retraining the help desk (option d) is a legitimate process fix for next time, but it does not touch the account that is compromised right now. The only sequence that actually closes this out is: revoke sessions and tokens first (kills the live access), remove the attacker's registered method (closes the persistence), reset the password, and confirm with l.ferreira herself through a channel other than the phone number that called in — the same one an attacker could also spoof.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "Scattered-Spider-style ATO operator (help-desk social engineering)",
    attack_kind: "helpdesk_mfa_reset_ato",
    briefing:
      "A ServiceNow ticket for l.ferreira@nexacorp.com was opened and resolved this morning as a routine MFA reset. Entra sign-in logs show two successful, MFA-satisfied sign-ins for the same account within the same hour, and CrowdStrike recorded a new interactive session landing on an internal VDI host shortly after. Determine whether this is ordinary help-desk support or an account takeover, and what to do about it.",
    narrative: `At 09:00 Lucia Ferreira, a trade settlements analyst, signed in to Office from her usual London address on her corporate laptop, MFA completed by an Authenticator push — an entirely ordinary start to the day.

At 09:41 the IT Service Desk opened ticket INC0048217: the caller reported being locked out and having lost her phone, and asked for a password and MFA reset. James Oduya verified the caller with an employee ID and date of birth over the phone — the bank's standard phone-verification procedure, and also exactly what a caller who has done a little research on their target can usually produce (T1684.001). At 09:45, four minutes into that call, Lucia's own account signed in again from the same London address on the same laptop — she was at her desk in SharePoint the entire time.

At 09:52 the ticket was resolved: password reset, MFA requirement cleared, caller told to re-enroll on next sign-in — closed exactly the way this help desk closes several tickets like it every week. One minute later the reset itself landed in the directory (T1556.006). Five minutes after that, at 09:58, a new Microsoft Authenticator was registered as Lucia's security info. The identity performing the registration was hers — because by then anyone holding the new password could act as her — but the IP address behind it was 5.181.234.19 in Amsterdam, an address that appears nowhere else in her telemetry (T1098.005).

At 10:01 that account signed in to Exchange Online from the same Amsterdam address, on an unmanaged Windows 10 machine running Chrome. Password and MFA both genuinely completed — Conditional Access shows success, sign-in risk shows none, because the attacker now held a working second factor and Entra's risk engine had nothing unusual to key on (T1078.004). Five minutes later a fresh session started on VDI-POOL-014 under her account.

No single record here reads as malicious. The ticket looks like routine support. The reset looks like routine administration. The sign-in genuinely passes every automated check available to it. What gives this away is only the sequence, laid against one plain fact the automated tooling never checked: the real Lucia Ferreira was still working from London when someone else, five minutes after her ticket closed, registered a new phone on her account from the Netherlands.`,
    learning_objectives: [
      "Recognise help-desk-driven MFA reset abuse (T1684.001 Impersonation, formerly T1656; T1556.006; T1098.005) as an identity attack path that produces no malware and no exploit telemetry at all",
      "Read Entra AuditLogs initiatedBy fields correctly: an action attributed to the victim's own identity is not proof the victim performed it once MFA has been cleared",
      "Use a concurrent, independently-authenticated session as stronger evidence of takeover than an anomalous IP or geography alone",
      "Distinguish a genuine lost-device MFA reset from a social-engineered one using network-layer evidence (source IP) rather than the presence of a reset itself",
      "Select containment that addresses persistence — revoking sessions and removing the attacker-registered authentication method — not just a second password change",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: T(0), phase: "Baseline", action: "l.ferreira signs in normally from London with an Authenticator push" },
      { ts: T(41 * MIN), phase: "Impersonation", action: "Caller impersonates l.ferreira to the help desk, requests password + MFA reset (T1684.001)" },
      { ts: T(45 * MIN), phase: "Baseline", action: "l.ferreira signs in again from the same London address — still genuinely active" },
      { ts: T(52 * MIN), phase: "Impersonation", action: "Ticket INC0048217 resolved: password reset, MFA cleared" },
      { ts: T(53 * MIN), phase: "Defense Impairment", action: "Registered authentication methods cleared on the account (T1556.006)" },
      { ts: T(58 * MIN), phase: "Persistence", action: "New Microsoft Authenticator registered from 5.181.234.19, Amsterdam (T1098.005)" },
      { ts: T(61 * MIN), phase: "Initial Access", action: "Account signs in from Amsterdam, MFA genuinely satisfied on the new device (T1078.004)" },
      { ts: T(66 * MIN), phase: "Lateral Movement", action: "New session lands on internal host VDI-POOL-014" },
    ],
    questions,
  };
}
