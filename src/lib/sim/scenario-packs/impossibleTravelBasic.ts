/**
 * Scenario pack: "Impossible Travel — Accounts Payable Mailbox"
 *
 * A REAL account takeover, told at beginner reading level.
 *
 * A finance user signs in normally from her usual city in the morning. Two and
 * a quarter hours later the same account signs in successfully from another
 * country, and the identity correlation rule fires on the geography.
 *
 * "Impossible travel" is only a HYPOTHESIS at that point. The two failure modes
 * a beginner falls into are closing it as "probably a VPN" and escalating on the
 * map alone. Neither is analysis. The telemetry contains the fields that settle
 * it, and the student has to go and read them:
 *
 *   - the corporate VPN session is logged, and it ENDED 47 minutes before the
 *     foreign sign-in — so "she was on the VPN" is testable, and it fails;
 *   - the foreign sign-in carries a different device (no deviceId, unmanaged,
 *     non-compliant, different OS and browser) and a hosting-provider ASN
 *     rather than her consumer ISP or the VPN gateway's address;
 *   - MFA is recorded as "satisfied", but by a claim inside the token rather
 *     than by the Authenticator push she completes every other morning;
 *   - and the foreign session then does things this mailbox has never done.
 *
 * Registry note: register in scenarios.ts with difficulty "beginner"
 * (ScenarioBundle itself carries no difficulty field).
 */

import type { ScenarioBundle, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { impossibleTravelBasicScenarioEvents } from "./impossibleTravelBasic.events";

export function buildImpossibleTravelBasicScenario(
  scenarioId = "impossible-travel-basic-2026",
): ScenarioBundle {
  const { title, events, T, MIN, victim, attackerIp, phishDomain, phishIp, dropAddress } = impossibleTravelBasicScenarioEvents();

  const iocs: IOC[] = [
    {
      type: "ip",
      value: attackerIp,
      first_seen: T(135 * MIN),
      last_seen: T(160 * MIN),
      reputation: "malicious",
      tags: ["hosting-provider", "asn-14061", "amsterdam"],
    },
    {
      type: "domain",
      value: phishDomain,
      first_seen: T(74 * MIN),
      last_seen: T(79 * MIN),
      reputation: "malicious",
      tags: ["credential-harvesting", "newly-registered", "lookalike"],
    },
    {
      type: "ip",
      value: phishIp,
      first_seen: T(79 * MIN),
      last_seen: T(79 * MIN),
      reputation: "malicious",
      tags: ["phishing-host"],
    },
    {
      type: "email",
      value: dropAddress,
      first_seen: T(141 * MIN),
      last_seen: T(141 * MIN),
      reputation: "malicious",
      tags: ["forwarding-target", "external"],
    },
    {
      type: "user",
      value: victim.email,
      first_seen: T(0),
      last_seen: T(160 * MIN),
      reputation: "suspicious",
      tags: ["compromised-account", "accounts-payable"],
    },
    {
      type: "ip",
      value: victim.homeIp,
      first_seen: T(0),
      last_seen: T(88 * MIN),
      reputation: "clean",
      tags: ["home-isp", "asn-5378", "user-baseline"],
    },
    {
      type: "host",
      value: victim.hostname,
      first_seen: T(0),
      last_seen: T(79 * MIN),
      reputation: "clean",
      tags: ["corporate-laptop", "entra-joined"],
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1",
      prompt:
        "Your team lead says \"she's probably just on the company VPN.\" Which PAIR of events lets you test that claim and rule it out?",
      hint: "One event tells you when the VPN session ended; the other tells you where the 08:27 sign-in actually came from.",
      kind: "single",
      options: [
        {
          value: "vpnend_foreign",
          label:
            "VPN disconnect + New York sign-in — the tunnel closed at 07:40, and 08:27 came from a different address",
        },
        {
          value: "morning_vpnstart",
          label:
            "Morning sign-in + VPN connect — she authenticated from home and then opened a tunnel through VPN-GW-01",
        },
        {
          value: "phish_post",
          label:
            "Phishing email + proxy POST — a lure arrived and the linked page then received a form submission from her laptop",
        },
        {
          value: "alert_rule",
          label:
            "Travel alert + inbox rule — the anomaly fired and a mailbox rule was created on the account shortly afterwards",
        },
      ],
      answer: "vpnend_foreign",
      xp: 50,
      explanation:
        "\"Probably a VPN\" is a claim you can check, and checking it is the job. The gateway log shows the d.harel tunnel torn down at 07:40 with no later session, so at 08:27 there was nothing to be on. And traffic that does leave through that gateway appears on the internet as 194.90.7.20, whereas the 08:27 sign-in came from 146.190.62.117 on AutonomousSystemNumber 14061 — a hosting provider, not the corporate gateway and not her ISP's 5378. Pair (b) is the ordinary baseline. Pair (c) matters for how the account was taken, not for the VPN question. Pair (d) is the alarm plus a consequence of the compromise.",
    },
    {
      id: "q2",
      prompt:
        "Both sign-ins record AuthenticationRequirement as multiFactorAuthentication. What is actually different between them?",
      kind: "single",
      options: [
        {
          value: "token_claim",
          label:
            "At 06:12 an Authenticator push was answered; at 08:27 MFA was satisfied by a claim already inside the token",
        },
        {
          value: "ca_status",
          label:
            "ConditionalAccessStatus reads success in the morning but notApplied on the foreign sign-in, so no policy evaluated it",
        },
        {
          value: "app_used",
          label:
            "The morning sign-in targeted Exchange Online while the foreign one targeted a different application",
        },
        {
          value: "result_type",
          label:
            "The morning sign-in returned ResultType 0 and the foreign sign-in returned a non-zero failure code",
        },
      ],
      answer: "token_claim",
      xp: 60,
      explanation:
        "The AuthenticationDetails block is where the difference lives. In the morning there are two steps: a correct password, then \"Mobile app notification — MFA completed in Azure AD\". Dana physically approved something. At 08:27 there is one step: \"Previously satisfied — MFA requirement satisfied by claim in the token\", with IncomingTokenType primaryRefreshToken. Nobody was challenged, because whoever signed in already held a token that says MFA happened. Options (b), (c) and (d) all describe fields you can read directly in the two records, and in each case the two records agree — ConditionalAccessStatus is success on both, both target Office 365 Exchange Online, and both returned ResultType 0.",
    },
    {
      id: "q3",
      prompt:
        "Which detail in evt_itb_06_foreign_signin most strongly argues the 08:27 session is NOT Dana's laptop with a VPN app running on it?",
      kind: "single",
      options: [
        {
          value: "device_block",
          label:
            "DeviceDetail carries an empty deviceId with isManaged and isCompliant both false, on MacOs and Firefox",
        },
        {
          value: "geo_city",
          label:
            "LocationDetails places the sign-in in New York, over 5,500 km from the London office where Finance say she is sitting",
        },
        {
          value: "risk_level",
          label:
            "RiskLevelDuringSignIn is high and RiskState is atRisk, which Entra sets automatically on the record",
        },
        {
          value: "app_display",
          label:
            "AppDisplayName is Office 365 Exchange Online, an application she does not normally sign in to",
        },
      ],
      answer: "device_block",
      xp: 60,
      explanation:
        "A VPN client changes where a device appears on the network. It does not erase the device. Her laptop is Entra-joined and Intune-managed, so its records carry deviceId 6b41f0d9-2ea7-4c85-b310-97ff5c2a4e68, displayName LT-FIN-3390, Windows 11, Edge, isCompliant true. The 08:27 record has an empty deviceId, isManaged false, isCompliant false, MacOs and Firefox. That is a different machine, and no VPN does that. Option (b) is the alert you already have, which is exactly what you are trying to explain. Option (c) is Entra's own opinion, not independent evidence. Option (d) is wrong on the facts — the 06:12 record targets the same application.",
    },
    {
      id: "q4",
      prompt:
        "Which single finding turns \"an odd sign-in location\" into a confirmed account takeover you should escalate?",
      hint: "Compare the SessionId on the post-sign-in activity with the SessionId on the foreign sign-in.",
      kind: "single",
      options: [
        {
          value: "session_actions",
          label:
            "A hiding forward rule, an 812-item folder read and a supplier payment email, all in the foreign session",
        },
        {
          value: "distance",
          label:
            "Sentinel computed 5,570 km in 135 minutes, an implied travel speed no commercial aircraft achieves",
        },
        {
          value: "phish_delivered",
          label:
            "A phishing message reached the inbox because the gateway recorded DetectionMethods as None",
        },
        {
          value: "asn_hosting",
          label:
            "The sign-in address sits on AS14061, a hosting provider, rather than on her home ISP or on the corporate gateway",
        },
      ],
      answer: "session_actions",
      xp: 70,
      explanation:
        "SessionId a4f8c1d2-7b93-4e15-8c60-3d29f7a1b504 appears on the 08:27 sign-in and then on all three follow-on actions: a rule that forwards payment mail to ap-archive.2026@securemaildrop.net and buries the originals in RSS Subscriptions, a Sync read of 812 items from the Vendor Banking folder, and an outbound message to ridgeline-supply.com changing remittance details. Nobody explains that away with a travel booking. Option (b) is the hypothesis, not the proof. Option (c) explains how it started. Option (d) is strong supporting evidence but hosting ASNs also carry consumer VPN exits — on its own it moves your confidence, it does not close the case. State the SessionId in your report: it is the thread that ties the intrusion together.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "Business Email Compromise operator (financially motivated)",
    attack_kind: "impossible_travel_basic",
    briefing:
      "Microsoft Sentinel opened a ticket at 08:29 on an impossible-travel anomaly for d.harel@nexacorp.com: a successful Exchange Online sign-in from London at 06:12 and another successful sign-in from New York at 08:27. Finance say Dana is at her desk in the London office today. Determine whether the account is compromised and what was done with it.",
    narrative: `At 06:12 Dana Harel, an accounts payable clerk, signed in to Exchange Online the way she signs in every morning: from her home address 86.150.23.44 on her corporate laptop LT-FIN-3390, an Entra-joined and Intune-managed Windows 11 machine, with an Authenticator push answered on her phone. Six minutes later she brought up the corporate VPN through VPN-GW-01.

At 07:26 a message reached her inbox claiming her sign-in session needed re-verifying, with a link to nexacorp-signin-verify.com — a lookalike domain that failed SPF and DMARC and was delivered anyway (T1566.002). Five minutes later the proxy recorded her laptop POSTing form data to that page, which the proxy filed under "Newly Registered and Observed Domains" and allowed. That request is where her authenticated session left the building (T1539). At 07:40 the VPN session closed after one hour and twenty-two minutes.

At 08:27 the same account signed in successfully to Exchange Online from 146.190.62.117 in New York, on AutonomousSystemNumber 14061 — a hosting provider, not her ISP and not the 194.90.7.20 address the corporate gateway uses. The device fields are empty: no deviceId, isManaged false, isCompliant false, MacOs and Firefox instead of Windows 11 and Edge. MFA is recorded as satisfied, but by a claim carried inside the token rather than by any challenge anyone answered. Those three facts together are what convert the impossible-travel hypothesis into a verdict; the map alone never could, and "she must be on a VPN" is a claim the gateway log had already disproved.

What the intruder did next removes any doubt. Everything from 08:27 onwards shares SessionId a4f8c1d2-7b93-4e15-8c60-3d29f7a1b504. At 08:33 a rule called "AP sync" was created on the mailbox, forwarding anything matching invoice, remittance, bank details, IBAN or payment to ap-archive.2026@securemaildrop.net and moving the originals into RSS Subscriptions marked as read (T1114.003). At 08:41 the Vendor Banking folder was read in bulk — 812 items in a single sync (T1114.002). At 08:52 a message went out to a supplier contact at ridgeline-supply.com with new remittance details attached, composed and sent inside the same session as the inbox rule and the bulk read.

Containment is an identity action, not a host action: revoke the account's refresh tokens so the stolen session dies, force a password reset, delete the "AP sync" rule, and tell accounts payable to phone the supplier on a number from the contract rather than one from any email.`,
    learning_objectives: [
      "Treat an impossible-travel alert as a hypothesis and name the specific fields that would confirm or refute it, rather than deciding from the map",
      "Test the innocent explanation with evidence — read the VPN gateway log for session start, end and public egress address instead of assuming a VPN was involved",
      "Compare DeviceDetail, AutonomousSystemNumber and UserAgent against the user's own baseline sign-in to tell a different network from a different machine",
      "Read AuthenticationDetails to see how MFA was satisfied, and recognise that a requirement met by a claim in the token means no challenge was ever answered",
      "Use SessionId to link post-authentication actions back to a specific sign-in, and escalate on that linkage rather than on geography",
    ],
    // alerts are attached by the catalogue wiring
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: T(0), phase: "Baseline", action: "d.harel signs in from London on LT-FIN-3390 with an Authenticator push" },
      { ts: T(74 * MIN), phase: "Initial Access", action: "Lookalike re-verification email delivered to the inbox" },
      { ts: T(79 * MIN), phase: "Credential Access", action: "Laptop POSTs to nexacorp-signin-verify.com — session token captured" },
      { ts: T(88 * MIN), phase: "Context", action: "Corporate VPN session ends — nothing after this came through the gateway" },
      { ts: T(135 * MIN), phase: "Valid Accounts", action: "Successful sign-in from 146.190.62.117, unmanaged device, MFA satisfied by token claim" },
      { ts: T(137 * MIN), phase: "Detection", action: "Sentinel raises the impossible-travel anomaly" },
      { ts: T(141 * MIN), phase: "Persistence", action: "\"AP sync\" inbox rule forwards payment mail out and hides the originals" },
      { ts: T(149 * MIN), phase: "Collection", action: "812 items read in one sync from the Vendor Banking folder" },
      { ts: T(160 * MIN), phase: "Impact", action: "Payment-detail change sent to a supplier from the compromised mailbox" },
    ],
    questions,
  };
}
