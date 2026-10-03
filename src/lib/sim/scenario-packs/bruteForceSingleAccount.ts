/**
 * Scenario pack: "Logon Failure Burst — Published Remote Desktop Server"
 *
 * BEGINNER tier. A single external address works one account's password over
 * roughly twenty minutes against an internet-published Remote Desktop server,
 * fails repeatedly, and then succeeds. The successful logon looks exactly like
 * any other 4624 — same account, same server, same event ID a hundred normal
 * logons a day produce — which is precisely why new analysts read the loud
 * failure burst, close the ticket as "attempts blocked", and miss it.
 *
 * Everything the debrief asserts is observable in the events: the source
 * address, the two different SubStatus codes, the success, the RDP session it
 * produced, the share the session mapped, and the shares the account had used
 * before. Nothing in the telemetry states the verdict.
 *
 * TELEMETRY: fully emitter-authored (Windows Security + CrowdStrike + Palo Alto
 * + Sentinel) — no hand-typed raw blocks, so every field is registry-correct and
 * the host/user/realm are drawn from the company asset fabric by construction.
 *
 * NOTE: `difficulty: "beginner"` is declared on the SCENARIOS registry entry in
 * scenarios.ts (ScenarioBundle itself carries no difficulty field).
 */

import type { ScenarioBundle, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { bruteForceSingleAccountScenarioEvents } from "./bruteForceSingleAccount.events";

export function buildBruteForceSingleAccountScenario(
  scenarioId = "brute-force-single-account-2026",
): ScenarioBundle {
  const { title, events, T, MIN, rds, fileServer, victim, attackerIp } = bruteForceSingleAccountScenarioEvents();

  const iocs: IOC[] = [
    {
      type: "ip",
      value: attackerIp,
      first_seen: T(0),
      last_seen: T(26 * MIN),
      reputation: "malicious",
      tags: ["external", "rdp-3389", "ru"],
    },
    {
      type: "user",
      value: victim.sam,
      first_seen: T(3 * MIN),
      last_seen: T(26 * MIN),
      reputation: "suspicious",
      tags: ["accounts-payable", "targeted-account"],
    },
    {
      type: "host",
      value: rds.hostname,
      first_seen: T(0),
      last_seen: T(26 * MIN),
      // "unknown", not "suspicious". Reputation describes whether the INDICATOR
      // is hostile, and this is the organisation's own published RDP server —
      // the victim, not adversary infrastructure. Tagging your own estate
      // suspicious is how a real blocklist ends up blocking production.
      reputation: "unknown",
      tags: ["internet-published", "rdp"],
    },
    {
      type: "host",
      value: fileServer.hostname,
      first_seen: T(22 * MIN + 20_000),
      last_seen: T(23 * MIN),
      reputation: "clean",
      tags: ["file-server", "hr-share"],
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1",
      prompt:
        "The first failure (evt_bf_02_fail_wrong_user) carries a different SubStatus code from the ones that follow it. What does that difference tell you?",
      hint: "Look at winlog.event_data.SubStatus in evt_bf_02 and then in evt_bf_03.",
      kind: "single",
      options: [
        { value: "nouser_then_badpw", label: "0xC0000064 — no such account; the later failures use 0xC000006A, wrong password" },
        { value: "badpw_then_nouser", label: "0xC000006A — wrong password first; the later failures switch to 0xC0000064, no such account" },
        { value: "locked", label: "0xC0000234 — the account was already locked out when the first attempt reached the server" },
        { value: "disabled", label: "0xC0000072 — the account was disabled at first and then re-enabled a few minutes later" },
      ],
      answer: "nouser_then_badpw",
      xp: 40,
      explanation:
        "0xC0000064 means the username itself does not exist in the directory — 'swolfe' is not an account here. 0xC000006A means the username IS valid and only the password was wrong. So the first minute is the attacker discovering the naming convention, and everything after 09:03 is password work against a confirmed real account. That distinction matters operationally: a wall of 0xC0000064 is usually a scanner guessing names, while a wall of 0xC000006A means someone already knows a live account and is grinding at it.",
    },
    {
      id: "q2",
      prompt:
        "Which single event marks the moment this account stopped being 'under attack' and became 'compromised'?",
      kind: "single",
      options: [
        { value: "fw", label: "The first inbound TCP/3389 session from the Russian address, allowed by the firewall" },
        { value: "last_fail", label: "The final 4625 of the burst at 09:19:20, after which the failures stop for good" },
        { value: "success", label: "The 4624 LogonType 3 network logon at 09:20:00 from that same external address" },
        { value: "siem", label: "The Sentinel correlation alert at 09:26 that opened this ticket for s.wolfe" },
      ],
      answer: "success",
      xp: 60,
      explanation:
        "Compromise happens the instant an attempt succeeds. Up to 09:19:20 the attacker has nothing but rejected guesses; at 09:20:00 a 4624 is written for the same account from the same address and they hold a working session. This is the event beginners walk past, because a 4624 is the most common line in a Windows Security log — thousands a day are completely normal. The failures are loud and harmless; the success is quiet and is the entire incident. The firewall event is only reachability, and the Sentinel alert is the SOC finding out forty minutes late.",
    },
    {
      id: "q3",
      prompt:
        "The session mapped \\\\SRV-FS-02\\HR-Confidential. Which pair of events, read together, shows that this was abnormal for this particular account?",
      hint: "One event shows the action; the other shows what this account normally does.",
      kind: "single",
      options: [
        { value: "use_plus_context", label: "The net use mapping plus the Sentinel directory context — the share mapped, and the shares used before" },
        { value: "use_plus_5140", label: "The net use mapping plus the SRV-FS-02 4624 network logon — the mapping, and the file-server session it produced" },
        { value: "success_plus_read", label: "The 09:20:00 logon success plus the payroll workbook read — the session opened, and the file it took" },
        { value: "fw_plus_rdp", label: "The inbound RDP session plus the LogonType 10 logon — the external connection, and the desktop it opened" },
      ],
      answer: "use_plus_context",
      xp: 70,
      explanation:
        "Neither event is enough on its own. evt_bf_07_net_use only shows that a share was mapped, which is a completely ordinary command. evt_bf_10_siem_context supplies the comparison: s.wolfe is an Accounts Payable clerk whose share history over ninety days is AP-Invoices, Scans and Finance-Reports — HR-Confidential appears nowhere in it. 'Abnormal' is always a claim about a baseline, so you need the event that carries the baseline. Pair (b) is the same action seen twice, from the workstation and from the file server. Pair (c) and (d) are steps in the chain, not a comparison against normal.",
    },
    {
      id: "q4",
      prompt:
        "You are writing the report. Which statement is actually supported by the events in front of you?",
      kind: "single",
      options: [
        { value: "success_and_read", label: "The account authenticated from the external address, and the session then read an HR file" },
        { value: "all_failed", label: "Every attempt from the external address failed, and no session was ever established on the server" },
        { value: "blocked", label: "The external address reached the server, but the firewall blocked it before authentication began" },
        { value: "lockout", label: "The lockout policy stopped the attempts, so the account was never accessed from the external address" },
      ],
      answer: "success_and_read",
      xp: 60,
      explanation:
        "The chain is fully evidenced: 4624 at 09:20:00 from 194.26.192.77, a LogonType 10 desktop eight seconds later, net.exe mapping HR-Confidential at 09:22, a 4624 network logon on SRV-FS-02 at 09:22:20 (TargetLogonId 0x74C2E19) and a 4663 read of salary_bands_2026.xlsx at 09:23 under that same logon session. Option (b) is the error this scenario exists to prevent — reporting the failure burst and never checking whether anything succeeded. Option (c) contradicts evt_bf_01_fw_inbound, where pan.action is allow. Option (d) contradicts evt_bf_10_siem_context, which records that the lockout policy did not apply to this account, and the failures did in fact run uninterrupted for eighteen minutes.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "Opportunistic external attacker (internet-facing RDP)",
    attack_kind: "brute_force_single_account",
    briefing:
      "Microsoft Sentinel raised a High alert at 09:26 for the user s.wolfe: 214 Windows logon failures from one external address against the internet-published Remote Desktop server SRV-RDS-02, followed by one success. Establish what happened to that user and whether anything followed.",
    narrative: `Between 09:02 and 09:20 a single address in Russia, 194.26.192.77, worked one account's password against SRV-RDS-02, the Remote Desktop server NexaCorp publishes to the internet. The first attempt used the name swolfe, which does not exist in the directory — SubStatus 0xC0000064. A minute later the attacker had the naming convention right and switched to s.wolfe, and from then on every rejection carried SubStatus 0xC000006A: valid account, wrong password. 214 of those were written in eighteen minutes. The account was never locked out, because the lockout policy does not apply to the group it belongs to, so the attempts simply continued until one of them worked.

At 09:20:00 one did. The 4624 that records it is unremarkable to look at — same account, same server, same source address as the 214 rejections before it — and it is the whole incident. Eight seconds later a second 4624 with LogonType 10 shows a full Remote Desktop session open on SRV-RDS-02.

What the session then did looks routine and is not. At 09:22 cmd.exe spawned net.exe to map a drive to \\\\SRV-FS-02\\HR-Confidential. SRV-FS-02 logged the session from its own side at 09:22:20 — a 4624 network logon from the RDS server, TargetLogonId 0x74C2E19 — and at 09:23 a payroll workbook, salary_bands_2026.xlsx, was opened for read under that logon session. s.wolfe is an Accounts Payable clerk; the shares this account had touched in the previous ninety days were AP-Invoices, Scans and Finance-Reports. HR-Confidential is not one of them, and nothing about her role explains it.

Sentinel only correlated the failure burst at 09:26, six minutes after the attacker was already inside. The failure burst was the noise. The success was the incident.`,
    learning_objectives: [
      "Read Windows 4625 SubStatus codes and tell a wrong username (0xC0000064) from a wrong password (0xC000006A)",
      "Search past the failure burst for the 4624 that ends it — the successful logon is the compromise, not the attempts",
      "Correlate a successful logon back to the source address and account of the failures that preceded it",
      "Distinguish LogonType 3 (network) from LogonType 10 (RemoteInteractive) when describing what access the attacker actually got",
      "Judge an action as abnormal by comparing it to the account's own history rather than to whether it was technically permitted",
    ],
    // alerts are attached by the catalogue wiring
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: T(0), phase: "Reconnaissance", action: `Inbound TCP/3389 from ${attackerIp} to SRV-RDS-02 — allowed by the published RDP rule` },
      { ts: T(2 * MIN), phase: "Credential Access", action: "First 4625 — username 'swolfe' does not exist (SubStatus 0xC0000064)" },
      { ts: T(3 * MIN), phase: "Credential Access", action: "Failures switch to s.wolfe — 214 wrong-password rejections over 18 minutes" },
      { ts: T(20 * MIN), phase: "Initial Access", action: "4624 SUCCESS for s.wolfe from the same address — the account is now compromised" },
      { ts: T(20 * MIN + 8_000), phase: "Initial Access", action: "Second 4624, LogonType 10 — Remote Desktop session open on SRV-RDS-02" },
      { ts: T(22 * MIN), phase: "Discovery", action: "net.exe maps Z: to \\\\SRV-FS-02\\HR-Confidential from inside the session" },
      { ts: T(23 * MIN), phase: "Collection", action: "salary_bands_2026.xlsx opened for read on the HR share" },
      { ts: T(26 * MIN), phase: "Detection", action: "Sentinel correlates the failure burst and raises the alert — six minutes after the success" },
    ],
    questions,
  };
}
