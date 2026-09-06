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

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";
import { winFailedLogon, winLogon, winShareAccess, winObjectAccess } from "@/lib/sim/emitters/windowsSecurity";
import { csProcess } from "@/lib/sim/emitters/crowdstrike";
import { panConnection } from "@/lib/sim/emitters/paloalto";
import { sentinelAlert } from "@/lib/sim/emitters/sentinel";

export function buildBruteForceSingleAccountScenario(
  scenarioId = "brute-force-single-account-2026",
): ScenarioBundle {
  const B = new Date("2026-06-04T09:00:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  // The internet-published Remote Desktop server and the file server behind it.
  const rds = { hostname: "SRV-RDS-02", fqdn: "SRV-RDS-02.nexacorp.com", ip: "10.30.9.20", nat: "193.34.145.27" };
  const fileServer = { hostname: "FS-CORP-02", fqdn: "FS-CORP-02.nexacorp.com", ip: "10.30.9.55" };

  // The single targeted account. Accounts Payable clerk — no HR entitlement.
  const victim = { sam: "s.wolfe", email: "s.wolfe@nexacorp.com" };
  const victimSid = "S-1-5-21-3421479547-3897544621-1789562108-4419";

  // The attacker's first guess at the username format — this account never existed.
  const wrongFormat = "swolfe";

  const attackerIp = "91.108.23.146";

  // Signed Microsoft binary — the tool is ordinary, the context is not.
  const netExeHash = makeSha256("windows_system32_net_exe_signed_microsoft");

  // EDR↔scenario integration (Phase 4): one incident. Host-primary brute force
  // against the published RDP server (Windows 4625/4624 + EDR on the server) →
  // edr_scope "edr". The successful 4624 and share reads are Windows Security
  // pivot telemetry; the EDR net.exe lateral-movement detection is alert-grade.
  const INCIDENT = "inc:bf:1";

  const RU = { country: "Russia", city: "Moscow" };
  const RU_GEO = { ...RU, latitude: 55.75, longitude: 37.62 };
  const cx = { companyId: "nexacorp" as const };

  const events: TelemetryEvent[] = [
    // 1. First contact — inbound RDP from the internet, allowed by policy.
    {
      ...panConnection({
        ...cx, id: "evt_bf_01_fw_inbound", ts: T(0), host: rds.hostname, user: null,
        srcIp: attackerIp, dstIp: rds.ip, remotePort: 3389, app: "ms-rdp", transport: "tcp",
        action: "allow", end: true, bytesOut: 9840, bytesIn: 26112,
        mitre: "T1133", tactic: "Initial Access", severity: "medium",
        description:
          "An address in Russia opened an inbound TCP/3389 session to the published Remote Desktop server SRV-RDS-02, allowed by the firewall.",
      }),
      geo: RU_GEO,
    },

    // 2. First failure — the username itself is wrong (0xC0000064).
    winFailedLogon({
      ...cx, id: "evt_bf_02_fail_wrong_user", ts: T(2 * MIN), host: rds.hostname, fqdn: rds.fqdn,
      targetUser: wrongFormat, userEmail: null, srcIp: attackerIp, subStatus: "0xC0000064",
      logonType: 3, workstation: "WORKSTATION", srcPort: "49712", recordId: "3310442",
      severity: "low", mitre: "T1110.001", tactic: "Credential Access", geo: RU,
      description:
        "The first logon failure on SRV-RDS-02 was a 4625 for the account name swolfe, over NTLM from 91.108.23.146.",
    }),

    // 3. The burst proper — correct account name, wrong password (0xC000006A).
    winFailedLogon({
      ...cx, id: "evt_bf_03_fail_burst", ts: T(3 * MIN), host: rds.hostname, fqdn: rds.fqdn,
      targetUser: victim.sam, srcIp: attackerIp, subStatus: "0xC000006A",
      logonType: 3, workstation: "WORKSTATION", srcPort: "49883", recordId: "3310519",
      severity: "medium", mitre: "T1110.001", tactic: "Credential Access", geo: RU,
      description:
        "One minute later the failures switch to the account name s.wolfe — a representative record from 214 failures written between 09:02 and 09:20, all from 91.108.23.146.",
    }),

    // 4. Last failure of the burst — 40 seconds before the ticket's answer.
    winFailedLogon({
      ...cx, id: "evt_bf_04_fail_last", ts: T(19 * MIN + 20_000), host: rds.hostname, fqdn: rds.fqdn,
      targetUser: victim.sam, srcIp: attackerIp, subStatus: "0xC000006A",
      logonType: 3, workstation: "WORKSTATION", srcPort: "51204", recordId: "3312088",
      severity: "medium", mitre: "T1110.001", tactic: "Credential Access", geo: RU,
      description:
        "The final 4625 of the burst, written at 09:19:20 for s.wolfe on SRV-RDS-02 from 91.108.23.146 over NTLM.",
    }),

    // 5. THE EVENT THAT MATTERS — 4624 success, same account, same address.
    winLogon({
      ...cx, id: "evt_bf_05_auth_success", ts: T(20 * MIN), host: rds.hostname, fqdn: rds.fqdn,
      targetUser: victim.sam, targetSid: victimSid, srcIp: attackerIp, logonType: 3,
      logonId: "0x2F91A44", srcPort: "51377", recordId: "3312194",
      severity: "high", mitre: "T1078", tactic: "Initial Access", geo: RU_GEO,
      description:
        "A successful 4624 network logon for s.wolfe on SRV-RDS-02 at 09:20:00, LogonType 3 over NTLM, from 91.108.23.146.",
    }),

    // 6. The interactive desktop the network logon unlocked (LogonType 10).
    winLogon({
      ...cx, id: "evt_bf_06_rdp_session", ts: T(20 * MIN + 8_000), host: rds.hostname, fqdn: rds.fqdn,
      targetUser: victim.sam, targetSid: victimSid, srcIp: attackerIp, logonType: 10,
      authPackage: "Negotiate", logonProcess: "User32 ", subjectSid: "S-1-5-18", subjectUser: "SRV-RDS-02$",
      logonId: "0x2F92B71", srcPort: "51377", workstation: rds.hostname, recordId: "3312203",
      processName: "C:\\Windows\\System32\\svchost.exe",
      severity: "high", mitre: "T1021.001", tactic: "Lateral Movement", geo: RU_GEO,
      description:
        "Eight seconds later a second 4624 on SRV-RDS-02 records LogonType 10 — RemoteInteractive — for s.wolfe from the same address, over Negotiate.",
    }),

    // 7. Ordinary-looking command, wrong share for this account (EDR detection).
    {
      ...csProcess({
        ...cx, id: "evt_bf_07_net_use", ts: T(22 * MIN), host: rds.hostname, user: victim.email, srcIp: rds.ip,
        processName: "net.exe", processPath: "C:\\Windows\\System32\\net.exe",
        cmdline: "net use Z: \\\\FS-CORP-02\\HR-Confidential", parentName: "cmd.exe",
        pid: 6248, parentPid: 6112, sha256: netExeHash, signed: true,
        mitre: "T1021.002", tactic: "Lateral Movement", severity: "medium", isDetection: true,
        description:
          "Inside the new desktop session cmd.exe spawned the signed net.exe, running: net use Z: \\\\FS-CORP-02\\HR-Confidential as NEXACORP\\s.wolfe.",
      }),
      edr_scope: "edr",
    },

    // 8. The share connection as the file server recorded it (5140).
    winShareAccess({
      ...cx, id: "evt_bf_08_share_access", ts: T(22 * MIN + 20_000), host: fileServer.hostname, fqdn: fileServer.fqdn,
      targetUser: victim.sam, targetSid: victimSid, srcIp: rds.ip,
      shareName: "\\\\*\\HR-Confidential", shareLocalPath: "\\??\\E:\\Shares\\HR-Confidential",
      subjectLogonId: "0x74C2E19", recordId: "8874120", severity: "medium",
      description:
        "FS-CORP-02 recorded a 5140 connection to the HR-Confidential share under the s.wolfe logon session, with IpAddress 10.30.9.20.",
    }),

    // 9. A file is actually read off the share (4663).
    {
      ...winObjectAccess({
        ...cx, id: "evt_bf_09_file_read", ts: T(23 * MIN), host: fileServer.hostname, fqdn: fileServer.fqdn,
        targetUser: victim.sam, targetSid: victimSid, srcIp: rds.ip, processName: "System",
        objectName: "E:\\Shares\\HR-Confidential\\Payroll\\2026\\salary_bands_2026.xlsx",
        fileName: "salary_bands_2026.xlsx", subjectLogonId: "0x74C2E19", recordId: "8874233",
        severity: "high", mitre: "T1039", tactic: "Collection",
        description:
          "An object-access record from FS-CORP-02 showing a payroll workbook on the HR-Confidential share being opened with read access under the s.wolfe logon session.",
      }),
      file: {
        path: "E:\\Shares\\HR-Confidential\\Payroll\\2026\\salary_bands_2026.xlsx",
        name: "salary_bands_2026.xlsx", extension: "xlsx", size: 842_240,
      },
    },

    // 10. The correlation that opened the ticket, plus the account's context.
    sentinelAlert({
      ...cx, id: "evt_bf_10_siem_context", ts: T(26 * MIN), host: rds.hostname, srcIp: attackerIp, user: victim.email,
      alertName: "ExternalAuthenticationBurst_SingleAccount", ruleId: "SEN-IDENT-0117", severity: "high",
      fullName: "Sara Wolfe", department: "Accounts Payable", title: "Accounts Payable Clerk",
      extendedProperties: {
        "Window Start": T(2 * MIN),
        "Window End": T(20 * MIN),
        "Shares Connected (Prior 90d)": ["\\\\FS-CORP-02\\AP-Invoices", "\\\\FS-CORP-02\\Scans", "\\\\FS-CORP-02\\Finance-Reports"],
        "Source Addresses In Window": [attackerIp],
        "Lockout Policy Applied": "false",
        "Group Memberships": ["Domain Users", "AP-Clerks", "Finance-Readers"],
      },
      description:
        "Sentinel raised the alert for s.wolfe with the account's directory context attached: department, group memberships, 90-day share history and the source addresses seen in the window.",
    }),
  ];

  // Every event belongs to the one incident.
  for (const e of events) e.incident_id = INCIDENT;

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
        { value: "badpw_then_nouser", label: "0xC000006A — wrong password; the later failures use 0xC0000064, no such account" },
        { value: "locked", label: "0xC0000234 — the account was already locked out when the first attempt arrived" },
        { value: "disabled", label: "0xC0000072 — the account was disabled and was re-enabled a few minutes later" },
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
        { value: "fw", label: "evt_bf_01_fw_inbound — the first inbound RDP session from the external address" },
        { value: "last_fail", label: "evt_bf_04_fail_last — the final logon failure of the burst at 09:19:20" },
        { value: "success", label: "evt_bf_05_auth_success — the 4624 at 09:20:00 from the same address" },
        { value: "siem", label: "evt_bf_10_siem_context — the correlation alert that opened this ticket" },
      ],
      answer: "success",
      xp: 60,
      explanation:
        "Compromise happens the instant an attempt succeeds. Up to 09:19:20 the attacker has nothing but rejected guesses; at 09:20:00 a 4624 is written for the same account from the same address and they hold a working session. This is the event beginners walk past, because a 4624 is the most common line in a Windows Security log — thousands a day are completely normal. The failures are loud and harmless; the success is quiet and is the entire incident. The firewall event is only reachability, and the Sentinel alert is the SOC finding out forty minutes late.",
    },
    {
      id: "q3",
      prompt:
        "The session mapped \\\\FS-CORP-02\\HR-Confidential. Which pair of events, read together, shows that this was abnormal for this particular account?",
      hint: "One event shows the action; the other shows what this account normally does.",
      kind: "single",
      options: [
        { value: "use_plus_context", label: "evt_bf_07_net_use + evt_bf_10_siem_context — the share mapped, and the shares used before" },
        { value: "use_plus_5140", label: "evt_bf_07_net_use + evt_bf_08_share_access — the mapping, and the connection it produced" },
        { value: "success_plus_read", label: "evt_bf_05_auth_success + evt_bf_09_file_read — the logon success, and the file that was read" },
        { value: "fw_plus_rdp", label: "evt_bf_01_fw_inbound + evt_bf_06_rdp_session — the inbound session, and the desktop opened" },
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
        { value: "all_failed", label: "Every attempt from the external address failed and no session was ever established" },
        { value: "blocked", label: "The external address reached the server but the firewall blocked it before authentication" },
        { value: "lockout", label: "The lockout policy stopped the attempts, so the account was never accessed remotely" },
      ],
      answer: "success_and_read",
      xp: 60,
      explanation:
        "The chain is fully evidenced: 4624 at 09:20:00 from 91.108.23.146, a LogonType 10 desktop eight seconds later, net.exe mapping HR-Confidential at 09:22, a 5140 on FS-CORP-02 at 09:22:20 and a 4663 read of salary_bands_2026.xlsx at 09:23. Option (b) is the error this scenario exists to prevent — reporting the failure burst and never checking whether anything succeeded. Option (c) contradicts evt_bf_01_fw_inbound, where pan.action is allow. Option (d) contradicts evt_bf_10_siem_context, which records that the lockout policy did not apply to this account, and the failures did in fact run uninterrupted for eighteen minutes.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "Logon Failure Burst — Published Remote Desktop Server",
    threat_actor: "Opportunistic external attacker (internet-facing RDP)",
    attack_kind: "brute_force_single_account",
    briefing:
      "Microsoft Sentinel raised a High alert at 09:26 for the user s.wolfe: a burst of Windows logon failures from one external address against the internet-published Remote Desktop server SRV-RDS-02. Establish what happened to that user and whether anything followed.",
    narrative: `Between 09:02 and 09:20 a single address in Russia, 91.108.23.146, worked one account's password against SRV-RDS-02, the Remote Desktop server NexaCorp publishes to the internet. The first attempt used the name swolfe, which does not exist in the directory — SubStatus 0xC0000064. A minute later the attacker had the naming convention right and switched to s.wolfe, and from then on every rejection carried SubStatus 0xC000006A: valid account, wrong password. 214 of those were written in eighteen minutes. The account was never locked out, because the lockout policy does not apply to the group it belongs to, so the attempts simply continued until one of them worked.

At 09:20:00 one did. The 4624 that records it is unremarkable to look at — same account, same server, same source address as the 214 rejections before it — and it is the whole incident. Eight seconds later a second 4624 with LogonType 10 shows a full Remote Desktop session open on SRV-RDS-02.

What the session then did looks routine and is not. At 09:22 cmd.exe spawned net.exe to map a drive to \\\\FS-CORP-02\\HR-Confidential. FS-CORP-02 logged the connection from its own side at 09:22:20, and at 09:23 a payroll workbook, salary_bands_2026.xlsx, was opened for read. s.wolfe is an Accounts Payable clerk; the shares this account had touched in the previous ninety days were AP-Invoices, Scans and Finance-Reports. HR-Confidential is not one of them, and nothing about her role explains it.

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
      { ts: T(22 * MIN), phase: "Discovery", action: "net.exe maps Z: to \\\\FS-CORP-02\\HR-Confidential from inside the session" },
      { ts: T(23 * MIN), phase: "Collection", action: "salary_bands_2026.xlsx opened for read on the HR share" },
      { ts: T(26 * MIN), phase: "Detection", action: "Sentinel correlates the failure burst and raises the alert — six minutes after the success" },
    ],
    questions,
  };
}
