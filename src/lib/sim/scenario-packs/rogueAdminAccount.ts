/**
 * Scenario pack: "Out-of-Hours Account Creation — Service Desk Credentials"
 *
 * BEGINNER tier. A helpdesk administrator's account creates a new domain user
 * late at night and puts it into Domain Admins three minutes later. Every one
 * of those actions is something that account is entitled to do, and every one
 * of them succeeds cleanly. Nothing is blocked, nothing is malformed, no
 * malware runs.
 *
 * The scenario deliberately ships a CONTROL: earlier the same day the same
 * administrator created a different account, during business hours, against an
 * approved onboarding request. Put the two side by side and the difference is
 * not technical — it is the absence of an authorisation record, the hour, and
 * the group membership that followed. That comparison is the whole lesson:
 * a beginner asks "was this allowed?", an analyst asks "was this authorised?".
 *
 * NOTE: `difficulty: "beginner"` is declared on the SCENARIOS registry entry in
 * scenarios.ts (ScenarioBundle itself carries no difficulty field).
 */

import type { ScenarioBundle, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { rogueAdminAccountScenarioEvents } from "./rogueAdminAccount.events";

export function buildRogueAdminAccountScenario(
  scenarioId = "rogue-admin-account-2026",
): ScenarioBundle {
  const { title, events, T, MIN, N, dc, adminServer, originHost, admin, onboardingTicket, rogue } = rogueAdminAccountScenarioEvents();

  const iocs: IOC[] = [
    {
      type: "user",
      value: rogue.sam,
      first_seen: T(N + 4 * MIN),
      last_seen: T(N + 21 * MIN),
      reputation: "malicious",
      tags: ["created-out-of-hours", "domain-admins"],
    },
    {
      type: "user",
      value: admin.sam,
      first_seen: T(0),
      last_seen: T(N + 21 * MIN),
      reputation: "suspicious",
      tags: ["service-desk", "acting-account"],
    },
    {
      type: "host",
      value: originHost.hostname,
      first_seen: T(N),
      last_seen: T(N + 15 * MIN),
      reputation: "suspicious",
      tags: ["engineering-workstation", "session-origin"],
    },
    {
      type: "host",
      value: adminServer.hostname,
      first_seen: T(N),
      last_seen: T(N + 21 * MIN),
      reputation: "unknown",
      tags: ["administrative-server", "rdp-target"],
    },
    {
      type: "host",
      value: dc.hostname,
      first_seen: T(6 * MIN),
      last_seen: T(N + 7 * MIN),
      reputation: "clean",
      tags: ["domain-controller", "directory-changes"],
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1",
      prompt:
        "Creating a domain user is a routine Service Desk task. What single fact turns evt_ra_05_acct_create from routine administration into an incident?",
      hint: "Compare it with evt_ra_01_ticket and evt_ra_02_baseline_create.",
      kind: "single",
      options: [
        { value: "no_ticket", label: "No onboarding or change request exists for s.katz, unlike the creation of n.peretz" },
        { value: "wrong_actor", label: "It was performed by a Service Desk administrator rather than by a domain administrator" },
        { value: "naming", label: "The name does not follow the naming convention used elsewhere in this directory" },
        { value: "wrong_host", label: "It was written on DC01 instead of on the administrative server SRV-ADM-07" },
      ],
      answer: "no_ticket",
      xp: 50,
      explanation:
        "The 4720 at 22:51 is byte-for-byte the same kind of record as the 4720 at 14:16 — same event ID, same creator, same domain controller. What separates them is entirely outside the event: the afternoon one is backed by RITM0092416, and Sentinel's lookup for the late-night one returns no linked request of any kind. Option (b) is wrong because provisioning accounts is precisely a Service Desk job. Option (c) is not supported — s.katz matches the same first-initial-dot-surname form as n.peretz. Option (d) is wrong because 4720 is always written on the domain controller that processed the change.",
    },
    {
      id: "q2",
      prompt:
        "Which pair of events, read together, shows that the same workstation drove both the administrative changes and the new account's first logon?",
      hint: "Two events share a WorkstationName and an IpAddress.",
      kind: "single",
      options: [
        { value: "both_logons", label: "The t.aharoni Remote Desktop logon + the first s.katz logon — both come from WS-ENG-2208" },
        { value: "create_group", label: "The s.katz creation + its Domain Admins addition — both were performed against DC01" },
        { value: "control_pair", label: "The RITM0092416 ticket + the n.peretz creation — an approved request and its account" },
        { value: "privs_siem", label: "The s.katz 4672 privilege grant + the Sentinel context summary — rights issued, then restated" },
      ],
      answer: "both_logons",
      xp: 70,
      explanation:
        "evt_ra_03_admin_logon carries WorkstationName WS-ENG-2208 and IpAddress 10.10.44.61; evt_ra_08_new_acct_logon carries exactly the same two values for a different account fifteen minutes later. One person at one keyboard used the administrator to build the account and then used the account. That is also what pushes the case from 'a helpdesk admin did something odd' towards 'the helpdesk admin's credentials are being used by someone else' — Sentinel records that t.aharoni is assigned WS-ITS-1140 and had logged on only from that device for the previous thirty days. Pair (b) shares a host but is one actor doing two things, pair (c) is the control, and pair (d) is the aftermath and its restatement.",
    },
    {
      id: "q3",
      prompt:
        "evt_ra_04_admin_privs shows that the t.aharoni session held the rights needed for everything that followed. What does that establish?",
      kind: "single",
      options: [
        { value: "permitted_not_authorised", label: "Only that the actions were technically permitted, not that they were authorised" },
        { value: "legitimate", label: "That the actions must be legitimate, because those rights were granted deliberately" },
        { value: "escalated", label: "That the helpdesk session escalated itself to a higher privilege level during the night" },
        { value: "domain_admin", label: "That the operations were carried out by a domain administrator and not by the helpdesk" },
      ],
      answer: "permitted_not_authorised",
      xp: 60,
      explanation:
        "This is the distinction the scenario is built around. Windows enforces permission, not intention: it checks whether the token holds the right and then does the work. A Service Desk administrator legitimately holds account-management rights, so a stolen Service Desk credential produces a clean, error-free, entirely 'allowed' sequence of events. Authorisation is a business fact recorded outside the operating system — a ticket, an approval, a named requester — and it is missing here. Option (c) is contradicted by the log: no escalation event appears, the rights were already present at 22:49.",
    },
    {
      id: "q4",
      prompt:
        "Put the night's events in the order the logs actually support.",
      kind: "single",
      options: [
        { value: "correct_order", label: "Admin logon → new user created → added to Domain Admins → the new user logs in" },
        { value: "order_b", label: "New user created → admin logon → the new user logs in → added to Domain Admins" },
        { value: "order_c", label: "Added to Domain Admins → new user created → admin logon → the new user logs in" },
        { value: "order_d", label: "The new user logs in → admin logon → new user created → added to Domain Admins" },
      ],
      answer: "correct_order",
      xp: 60,
      explanation:
        "The timestamps give it directly: 22:47 the administrator's Remote Desktop session opens on SRV-ADM-07, 22:51 the 4720 creates s.katz on DC01, 22:54 the 4728 adds it to Domain Admins and 22:56 the 4732 adds it to the local Administrators group, 23:02 the 4624 shows s.katz logging on for the first time. The other orders are impossible — a group cannot take a member that does not exist yet, and an account cannot log on before it is created. Getting this sequence right is what lets you state, in the report, that the compromise of t.aharoni came first and the new account is its product, not its cause.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "Intruder operating a legitimate Service Desk administrator account",
    attack_kind: "rogue_admin_account",
    briefing:
      "Microsoft Sentinel raised a High alert at 23:08 on DC01. The domain user s.katz did not exist at 22:00 and was a member of a privileged group by 22:56. The Service Desk has no record of a request for it. Establish whether this was authorised and report what has happened since.",
    narrative: `At 14:10 an approved onboarding request, RITM0092416, reached the Service Desk queue, and six minutes later t.aharoni created the domain user n.peretz on DC01. That is the shape of a legitimate account creation at NexaCorp: a request, an approver, a named person, and a daytime timestamp. Keep it in mind, because the record written eight hours later looks exactly the same.

At 22:47 the t.aharoni account opened a Remote Desktop session on the administrative server SRV-ADM-07 — from 10.10.44.61, the address of WS-ENG-2208. WS-ENG-2208 is an Engineering workstation whose primary user is y.dagan; t.aharoni sits in the Service Desk, is assigned WS-ITS-1140, and had logged on from nothing else in the previous thirty days. Two minutes later the session was issued its usual administrative privilege set, which is why nothing that follows is ever refused.

At 22:51 that session created the domain user s.katz on DC01. At 22:54 s.katz was added to Domain Admins, and at 22:56 to the local Administrators group on SRV-ADM-07. At 23:02, eleven minutes old, s.katz logged on interactively to SRV-ADM-07 — from WS-ENG-2208 and 10.10.44.61 again, the same keyboard that had just built it — and the 4672 written a minute later shows the account collecting SeDebugPrivilege and SeBackupPrivilege, so the group memberships were live.

Every one of those operations was permitted. A Service Desk administrator is entitled to create users and manage groups, and Windows raised not a single error. What makes it an incident is what is missing and what surrounds it: Sentinel's lookups return no change request and no onboarding request for s.katz, the work happened outside the standard change window, the new account went straight into the domain's most privileged group three minutes after birth, and both sessions came from a workstation that belongs to neither of the accounts involved.

The working conclusion is that t.aharoni's credentials are being used by someone else, and that s.katz is a second way back in for when the first one is closed. The lesson for the report is the question you asked: not "was this allowed?" — it plainly was — but "who authorised it?", which nobody did.`,
    learning_objectives: [
      "Read the Windows account-lifecycle events in order: 4720 creation, 4728 global group addition, 4732 local group addition, 4624 first logon, 4672 privileges issued",
      "Treat the absence of a change or onboarding record as evidence in its own right, and know where to look for it",
      "Separate 'technically permitted' from 'authorised', and recognise that a stolen administrator credential produces a completely clean log trail",
      "Use timing — outside business hours, and minutes between creation and privileged group membership — as a supporting rather than a standalone indicator",
      "Correlate WorkstationName and IpAddress across two different accounts' logons to place them at one origin",
    ],
    // alerts are attached by the catalogue wiring
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: T(0), phase: "Baseline", action: `${onboardingTicket} approved — an authorised onboarding request reaches the Service Desk` },
      { ts: T(6 * MIN), phase: "Baseline", action: "t.aharoni creates n.peretz on DC01 under that request — the control case" },
      { ts: T(N), phase: "Valid Accounts", action: "t.aharoni opens a Remote Desktop session on SRV-ADM-07 from WS-ENG-2208" },
      { ts: T(N + 4 * MIN), phase: "Persistence", action: "4720 — the domain user s.katz is created on DC01 with no linked request" },
      { ts: T(N + 7 * MIN), phase: "Persistence", action: "4728 — s.katz added to Domain Admins three minutes after creation" },
      { ts: T(N + 9 * MIN), phase: "Persistence", action: "4732 — s.katz added to the local Administrators group on SRV-ADM-07" },
      { ts: T(N + 15 * MIN), phase: "Valid Accounts", action: "s.katz logs on to SRV-ADM-07 from WS-ENG-2208 — the same origin as the admin session" },
      { ts: T(N + 16 * MIN), phase: "Valid Accounts", action: "4672 — the new account is issued SeDebugPrivilege and SeBackupPrivilege" },
      { ts: T(N + 21 * MIN), phase: "Detection", action: "Sentinel correlates the creation and the group addition and raises the alert" },
    ],
    questions,
  };
}
