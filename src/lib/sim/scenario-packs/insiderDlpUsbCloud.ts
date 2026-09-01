/**
 * Scenario pack: "Departing Insider — Client Data to USB and Personal Cloud"
 *
 * INTERMEDIATE tier. Daniel Okafor is a Senior Financial Analyst on NexaCorp's
 * Client Accounts team. He submitted his resignation three days ago; his last
 * working day is Friday and his access-revocation is already scheduled in
 * Workday. On the Monday afternoon of his final week he opens the client &
 * finance file share, reads far more of it than his own 30-day baseline, copies
 * a large slice of labeled client financial records to a personal Kingston USB
 * stick, AND uploads the same material to a consumer Dropbox account through the
 * browser.
 *
 * The teaching point is that EVERY action in this chain was ALLOWED. NexaCorp's
 * Microsoft Purview DLP is deployed in AUDIT mode, not Block — so the bulk
 * access, the removable-media copy and the personal-cloud upload each generated
 * a policy match that was logged and notified but never stopped. There is no
 * "denied", no "blocked", no malware, no stolen credential: it is the man's own
 * valid account (T1078) doing things his role technically permits. The verdict
 * is still malicious insider data theft, and the analyst has to reach it from
 * (a) audit-only DLP telemetry and (b) the HR/context signal that this is a
 * departing employee acting well outside his own norm — NOT from any control
 * that said "no".
 *
 * A benign heavy-transfer control is included for contrast: a Data Engineer,
 * Hannah Reyes, moving an even larger volume the same day as part of a
 * change-ticketed migration to a SANCTIONED corporate destination. Same "big
 * transfer" shape, opposite verdict — which is the whole point of the
 * exfil-vs-legitimate-work question.
 *
 * Covers T1078 (Valid Accounts — his own), T1039 (Data from Network Shared
 * Drive), T1074.001 (Local Data Staging), T1052.001 (Exfiltration over USB) and
 * T1567.002 (Exfiltration to Cloud Storage).
 *
 * SOURCES (all fields registry-valid for their declared vendor): Microsoft
 * Purview DLP (endpoint DLP policy matches — bulk access, removable-media copy,
 * cloud egress; device-control USB record), Microsoft Defender for Endpoint
 * (local staging + file-write-to-removable telemetry), Zscaler Internet Access
 * (the browser upload session and its byte volume), Workday (the HR resignation
 * / lifecycle record the case turns on) and Microsoft Sentinel (the correlation
 * that ties HR + access + USB + cloud into one incident). This pack fits the
 * Microsoft-365 / Purview-DLP company profiles (nexacorp, medcore, globallogis).
 *
 * NOTE: `difficulty: "intermediate"` is declared on the SCENARIOS registry entry
 * in scenarios.ts (ScenarioBundle itself carries no difficulty field).
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";

export function buildInsiderDlpUsbCloudScenario(
  scenarioId = "insider-dlp-usb-cloud-2026",
): ScenarioBundle {
  const B = new Date("2026-08-24T13:15:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const HOUR = 3_600_000;
  const DAY = 86_400_000;

  // The departing insider and his laptop.
  const host = { hostname: "LAPTOP-NX-FIN14", ip: "10.20.4.58" };
  const insider = {
    email: "d.okafor@nexacorp.com",
    name: "Daniel Okafor",
    sam: "d.okafor",
    title: "Senior Financial Analyst",
    dept: "Client Accounts",
  };
  const deviceId = "b4e8c2a17f9d4e63a5c1082fb7e34d91";
  const insiderSid = "S-1-5-21-3421479547-3897544621-1789562108-5277";

  // The client/finance file share he pulls from.
  const fileServer = { name: "SRV-NX-FIN02", share: "\\\\SRV-NX-FIN02\\ClientShare" };

  // The removable drive: serial + volume label are the citable USB indicators.
  const usbSerial = "KINGSTON-DT-6F2A9C41";
  const usbVolume = "DOKAFOR-BACKUP";

  // The personal, unsanctioned cloud destination.
  const personalCloud = "www.dropbox.com";

  // The two marquee sensitive files, cited verbatim across the chain.
  const file1 = "Client_Master_Book_2026.xlsx";
  const file2 = "FY26_Client_Pricing_Model.xlsx";
  const file1Hash = makeSha256("nexacorp_client_master_book_2026_xlsx");
  const file2Hash = makeSha256("nexacorp_fy26_client_pricing_model_xlsx");
  const robocopyHash = makeSha256("windows_system32_robocopy_exe_signed_microsoft_2026");

  // The benign control — a Data Engineer doing sanctioned, change-ticketed bulk work.
  const colleague = { email: "h.reyes@nexacorp.com", name: "Hannah Reyes", sam: "h.reyes", host: "LAPTOP-NX-ENG07", ip: "10.20.4.61" };

  // One incident. Host artifacts (USB write, local staging on the laptop) AND a
  // control-plane facet (DLP cloud egress + proxy) → edr_scope "hybrid", stamped
  // on the primary EDR detection. The DLP cloud/USB matches are the crux
  // detections; the rest is pivot/correlation telemetry.
  const INCIDENT = "inc:idt:1";

  const events: TelemetryEvent[] = [
    // ---------------------------------------------------------------------
    // 0. The HR record the whole case turns on. A resignation was submitted
    //    three days ago and access-revocation is already scheduled — the
    //    context that turns "big transfer" into "departing insider".
    // ---------------------------------------------------------------------
    {
      id: "evt_idt_00_hr_context",
      ts: T(-3 * DAY),
      source: "hr",
      vendor: "Workday",
      event_type: "account_modify",
      user_email: insider.email,
      severity: "informational",
      description:
        "A worker lifecycle change was recorded for d.okafor: a voluntary resignation with an employment end date of 2026-08-28 and an access-revocation already scheduled for that evening. The notice period is active.",
      raw: {
        "workday.event_type": "Worker_Resignation_Submitted",
        "workday.worker_id": "WD-0071254",
        "workday.worker_email": insider.email,
        "workday.termination_date": "2026-08-28",
        "workday.termination_reason_category": "Voluntary",
        "workday.initiated_by": insider.email,
        "workday.notice_period_active": "true",
        "workday.access_revocation_scheduled": "2026-08-28T17:00:00Z",
        "event.action": "Worker_Resignation_Submitted",
        "event.outcome": "success",
      },
    },

    // ---------------------------------------------------------------------
    // 1. Ordinary interactive logon under his OWN valid account (T1078).
    //    Nothing is stolen or spoofed anywhere in this incident — every
    //    action that follows is authenticated as Daniel Okafor.
    // ---------------------------------------------------------------------
    {
      id: "evt_idt_01_logon",
      ts: T(0),
      source: "ad",
      vendor: "Windows Security",
      event_type: "auth_success",
      hostname: host.hostname,
      user_email: insider.email,
      src_ip: host.ip,
      severity: "informational",
      mitre_technique: "T1078",
      mitre_tactic: "Initial Access",
      description:
        "A routine 4624 interactive logon for d.okafor on LAPTOP-NX-FIN14 at 13:15, LogonType 2 over Kerberos — the analyst's normal workstation session.",
      authentication: { method: "Kerberos", result: "success", logon_type: 2 },
      raw: {
        "winlog.event_id": "4624",
        "winlog.channel": "Security",
        "winlog.computer_name": `${host.hostname}.nexacorp.com`,
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "5540921",
        "winlog.event_data.SubjectUserSid": "S-1-5-18",
        "winlog.event_data.SubjectUserName": `${host.hostname}$`,
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.SubjectLogonId": "0x3E7",
        "winlog.event_data.TargetUserSid": insiderSid,
        "winlog.event_data.TargetUserName": insider.sam,
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.TargetLogonId": "0x8A41C6",
        "winlog.event_data.LogonType": "2",
        "winlog.event_data.LogonProcessName": "User32 ",
        "winlog.event_data.AuthenticationPackageName": "Kerberos",
        "winlog.event_data.WorkstationName": host.hostname,
        "winlog.event_data.IpAddress": host.ip,
        "winlog.event_data.IpPort": "0",
        "winlog.event_data.ProcessName": "C:\\Windows\\System32\\winlogon.exe",
        "event.code": "4624",
        "event.action": "logged-in",
        "event.outcome": "success",
        "source.ip": host.ip,
        "user.name": `NEXACORP\\${insider.sam}`,
        "user.domain": "NEXACORP",
        "host.name": host.hostname,
      },
    },

    // ---------------------------------------------------------------------
    // 2. Mass access to the client/finance share — many files read in a
    //    short window, well above what this account normally touches.
    //    Representative record; the count is a SIEM-side aggregate.
    // ---------------------------------------------------------------------
    {
      id: "evt_idt_02_mass_access",
      ts: T(6 * MIN),
      source: "dlp",
      vendor: "Microsoft Purview",
      event_type: "cloud_api_call",
      hostname: host.hostname,
      user_email: insider.email,
      user_title: "Senior Financial Analyst",
      src_ip: host.ip,
      severity: "medium",
      mitre_technique: "T1039",
      mitre_tactic: "Collection",
      description:
        "Beginning 13:21, d.okafor opened 190+ files from the Client Accounts file share in about eight minutes — a representative FileAccessed record from a burst far above his usual read volume.",
      raw: {
        "event.action": "FileAccessed",
        "event.outcome": "success",
        "user.email": insider.email,
        "user.title": insider.title,
        "source.ip": host.ip,
        "cloud.resource.name": `${fileServer.share}\\ClientRecords`,
        "cloud.provider": "Microsoft365",
        "data.office365.SourceFileName": file1,
        "file.sensitivity_label": "Highly Confidential — Client",
        "host.name": host.hostname,
        "user.name": `NEXACORP\\${insider.sam}`,
      },
    },

    // ---------------------------------------------------------------------
    // 3. Purview Endpoint DLP matches the bulk access to labeled client
    //    financial data — RuleMode Enforce, but Actions are Audit+Notify,
    //    so it is LOGGED, not blocked. First "allowed ≠ benign" signal.
    // ---------------------------------------------------------------------
    {
      id: "evt_idt_03_dlp_bulk",
      ts: T(14 * MIN),
      source: "dlp",
      vendor: "Microsoft Purview",
      event_type: "dlp_alert",
      hostname: host.hostname,
      user_email: insider.email,
      src_ip: host.ip,
      severity: "high",
      mitre_technique: "T1039",
      mitre_tactic: "Collection",
      description:
        "Microsoft Purview matched 2,214 instances of labeled client financial data being opened by d.okafor on LAPTOP-NX-FIN14. The rule is enforced, but its configured actions are Audit and NotifyUser — logged and the user notified, nothing blocked.",
      file: { name: file1, path: `${fileServer.share}\\ClientRecords\\${file1}`, extension: "xlsx", size: 5_218_304, sha256: file1Hash },
      raw: {
        "data.office365.Operation": "DlpRuleMatch",
        "data.office365.Workload": "Endpoint",
        "data.office365.UserId": insider.email,
        "data.office365.ObjectId": `${fileServer.share}\\ClientRecords\\${file1}`,
        "data.office365.IncidentId": "6742013",
        "data.office365.PolicyDetails.PolicyName": "NexaCorp — Client & Financial Data Protection",
        "data.office365.PolicyDetails.Rules.RuleName": "Bulk access to labeled client financial records",
        "data.office365.PolicyDetails.Rules.RuleMode": "Enforce",
        "data.office365.PolicyDetails.Rules.Severity": "High",
        "data.office365.PolicyDetails.Rules.Actions": ["Audit", "NotifyUser"],
        "data.office365.PolicyDetails.Rules.ConditionsMatched.SensitiveInformation.SensitiveInformationTypeName": "EU IBAN",
        "data.office365.PolicyDetails.Rules.ConditionsMatched.SensitiveInformation.Count": "2214",
        "data.office365.PolicyDetails.Rules.ConditionsMatched.SensitiveInformation.Confidence": "85",
        "data.office365.PolicyDetails.Rules.ConditionsMatched.SensitiveInformation.ClassifierType": "PatternMatch",
        "purview.PolicyName": "NexaCorp — Client & Financial Data Protection",
        "purview.RuleName": "Bulk access to labeled client financial records",
        "purview.SensitiveInfoType": "EU IBAN",
        "purview.Workload": "Endpoint",
        "purview.ActionTaken": "Audit",
        "purview.Override": "false",
        "data.office365.DeviceId": deviceId,
        "data.office365.DeviceDisplayName": host.hostname,
        "data.office365.ClientProcessName": "EXCEL.EXE",
        "file.name": file1,
        "file.sensitivity_label": "Highly Confidential — Client",
        "user.name": `NEXACORP\\${insider.sam}`,
        "host.name": host.hostname,
        "action_result": "allowed",
      },
    },

    // ---------------------------------------------------------------------
    // 4. Local staging (T1074.001). robocopy — a signed, built-in Windows
    //    utility — mirrors the client-records tree into a local temp folder,
    //    consolidating the files before they leave the host.
    // ---------------------------------------------------------------------
    {
      id: "evt_idt_04_staging",
      ts: T(22 * MIN),
      source: "edr",
      vendor: "Microsoft Defender for Endpoint",
      event_type: "process_create",
      hostname: host.hostname,
      user_email: insider.email,
      src_ip: host.ip,
      severity: "medium",
      mitre_technique: "T1074.001",
      mitre_tactic: "Collection",
      description:
        "At 13:37 robocopy.exe mirrored the ClientRecords folder from the file share into a local staging folder under d.okafor's profile on LAPTOP-NX-FIN14, consolidating the files onto the endpoint.",
      process: {
        name: "robocopy.exe",
        pid: 7044,
        path: "C:\\Windows\\System32\\Robocopy.exe",
        parent_name: "cmd.exe",
        parent_pid: 6620,
        cmdline: `robocopy.exe "${fileServer.share}\\ClientRecords" "C:\\Users\\${insider.sam}\\AppData\\Local\\Temp\\ClientBackup" /E /Z /R:1 /W:1 /MT:16 /NFL /NDL`,
        user: `NEXACORP\\${insider.sam}`,
        integrity: "medium",
        hash: { sha256: robocopyHash },
      },
      raw: {
        "mde.ActionType": "ProcessCreated",
        "ActionType": "ProcessCreated",
        "DeviceName": host.hostname,
        "DeviceId": deviceId,
        "ReportId": "884213",
        "AccountName": insider.sam,
        "AccountDomain": "NEXACORP",
        "ProcessCommandLine": `robocopy.exe "${fileServer.share}\\ClientRecords" "C:\\Users\\${insider.sam}\\AppData\\Local\\Temp\\ClientBackup" /E /Z /R:1 /W:1 /MT:16 /NFL /NDL`,
        "process.name": "robocopy.exe",
        "process.pid": "7044",
        "process.executable": "C:\\Windows\\System32\\Robocopy.exe",
        "process.command_line": `robocopy.exe "${fileServer.share}\\ClientRecords" "C:\\Users\\${insider.sam}\\AppData\\Local\\Temp\\ClientBackup" /E /Z /R:1 /W:1 /MT:16 /NFL /NDL`,
        "process.hash.sha256": robocopyHash,
        "process.code_signature.status": "signed",
        "process.code_signature.subject_name": "Microsoft Windows",
        "process.integrity_level": "Medium",
        "process.parent.name": "cmd.exe",
        "process.parent.pid": "6620",
        "user.name": `NEXACORP\\${insider.sam}`,
        "host.name": host.hostname,
        "host.ip": host.ip,
      },
    },

    // ---------------------------------------------------------------------
    // 5. Removable media mounts. Purview device control logs the Kingston
    //    stick — serial and volume label are the citable USB indicators —
    //    and, in Audit mode, allows it.
    // ---------------------------------------------------------------------
    {
      id: "evt_idt_05_usb_mount",
      ts: T(31 * MIN),
      source: "dlp",
      vendor: "Microsoft Purview",
      event_type: "dlp_alert",
      hostname: host.hostname,
      user_email: insider.email,
      src_ip: host.ip,
      severity: "medium",
      mitre_technique: "T1052.001",
      mitre_tactic: "Exfiltration",
      description:
        `At 13:46 a Kingston DataTraveler USB stick (serial ${usbSerial}, volume labeled ${usbVolume}) was mounted on LAPTOP-NX-FIN14 as drive D:. Purview device control is in Audit mode, so the mount was recorded and permitted.`,
      raw: {
        "purview.PolicyName": "NexaCorp — Removable Media Control",
        "purview.RuleName": "Audit removable storage mount",
        "purview.Workload": "Endpoint",
        "purview.ActionTaken": "Audit",
        "purview.Override": "false",
        "usb.action": "mounted",
        "usb.device.name": "Kingston DataTraveler 3.0",
        "usb.device.serial": usbSerial,
        "usb.vendor": "Kingston",
        "usb.product": "DataTraveler 3.0",
        "removable_media.type": "USB Mass Storage",
        "data.office365.DeviceId": deviceId,
        "data.office365.DeviceDisplayName": host.hostname,
        "host.name": host.hostname,
        "user.name": `NEXACORP\\${insider.sam}`,
        "action_result": "allowed",
      },
    },

    // ---------------------------------------------------------------------
    // 6. EDR sees the copy to removable media. MDE FileCreated on D:, the
    //    host-observable proof that files actually left onto the stick.
    //    This is the alert-grade EDR detection carrying the USB-exfil crux.
    // ---------------------------------------------------------------------
    {
      id: "evt_idt_06_usb_write",
      ts: T(32 * MIN),
      source: "edr",
      vendor: "Microsoft Defender for Endpoint",
      event_type: "file_create",
      hostname: host.hostname,
      user_email: insider.email,
      src_ip: host.ip,
      severity: "high",
      mitre_technique: "T1052.001",
      mitre_tactic: "Exfiltration",
      is_detection: true, // alert-grade: the EDR file-write-to-removable-media detection (the USB-exfil crux)
      edr_scope: "hybrid", // host artifacts (USB, staging) AND a control-plane cloud-egress facet
      description:
        `At 13:47 explorer.exe wrote ${file1} to the mounted USB volume ${usbVolume} (D:) on LAPTOP-NX-FIN14 — a representative record from 34 client files copied to the stick within two minutes of the mount.`,
      file: { name: file1, path: `D:\\${file1}`, extension: "xlsx", size: 5_218_304, sha256: file1Hash },
      raw: {
        "mde.ActionType": "FileCreated",
        "ActionType": "FileCreated",
        "DeviceName": host.hostname,
        "DeviceId": deviceId,
        "ReportId": "884377",
        "FileName": file1,
        "FolderPath": `D:\\${file1}`,
        "SHA256": file1Hash,
        "FileSize": "5218304",
        "AccountName": insider.sam,
        "AccountDomain": "NEXACORP",
        "InitiatingProcessFileName": "explorer.exe",
        "InitiatingProcessFolderPath": "C:\\Windows\\explorer.exe",
        "InitiatingProcessAccountName": insider.sam,
        "InitiatingProcessCommandLine": "explorer.exe",
        "file.name": file1,
        "file.path": `D:\\${file1}`,
        "file.hash.sha256": file1Hash,
        "file.size": "5218304",
        "user.name": `NEXACORP\\${insider.sam}`,
        "host.name": host.hostname,
        "host.ip": host.ip,
      },
    },

    // ---------------------------------------------------------------------
    // 7. Purview Endpoint DLP matches the copy-to-removable-media on labeled
    //    data — again Enforce mode, Audit action, allowed. The USB-egress
    //    counterpart to the earlier access match.
    // ---------------------------------------------------------------------
    {
      id: "evt_idt_07_usb_dlp",
      ts: T(33 * MIN),
      source: "dlp",
      vendor: "Microsoft Purview",
      event_type: "dlp_alert",
      hostname: host.hostname,
      user_email: insider.email,
      src_ip: host.ip,
      severity: "high",
      mitre_technique: "T1052.001",
      mitre_tactic: "Exfiltration",
      is_detection: true, // alert-grade: DLP policy match on the removable-media copy of labeled client data
      description:
        `Purview matched labeled client data — including ${file2} — being copied to the removable device ${usbSerial}. The rule fired in Audit mode: 34 files were flagged and allowed onto the USB stick.`,
      file: { name: file2, path: `D:\\${file2}`, extension: "xlsx", size: 3_907_072, sha256: file2Hash },
      raw: {
        "data.office365.Operation": "DlpRuleMatch",
        "data.office365.Workload": "Endpoint",
        "data.office365.UserId": insider.email,
        "data.office365.ObjectId": `D:\\${file2}`,
        "data.office365.IncidentId": "6742088",
        "data.office365.PolicyDetails.PolicyName": "NexaCorp — Client & Financial Data Protection",
        "data.office365.PolicyDetails.Rules.RuleName": "Copy of labeled client data to removable media",
        "data.office365.PolicyDetails.Rules.RuleMode": "Enforce",
        "data.office365.PolicyDetails.Rules.Severity": "High",
        "data.office365.PolicyDetails.Rules.Actions": ["Audit", "NotifyUser"],
        "data.office365.PolicyDetails.Rules.ConditionsMatched.SensitiveInformation.SensitiveInformationTypeName": "EU IBAN",
        "data.office365.PolicyDetails.Rules.ConditionsMatched.SensitiveInformation.Count": "1663",
        "data.office365.PolicyDetails.Rules.ConditionsMatched.SensitiveInformation.Confidence": "85",
        "purview.PolicyName": "NexaCorp — Client & Financial Data Protection",
        "purview.RuleName": "Copy of labeled client data to removable media",
        "purview.SensitiveInfoType": "EU IBAN",
        "purview.Workload": "Endpoint",
        "purview.ActionTaken": "Audit",
        "purview.Override": "false",
        "removable_media.type": "USB Mass Storage",
        "usb.device.serial": usbSerial,
        "data.office365.DeviceId": deviceId,
        "data.office365.DeviceDisplayName": host.hostname,
        "data.office365.ClientProcessName": "explorer.exe",
        "file.name": file2,
        "file.sensitivity_label": "Highly Confidential — Client",
        "user.name": `NEXACORP\\${insider.sam}`,
        "host.name": host.hostname,
        "action_result": "allowed",
      },
    },

    // ---------------------------------------------------------------------
    // 8. Personal-cloud egress. Purview Endpoint DLP flags the SAME labeled
    //    data being uploaded through the browser to a consumer Dropbox
    //    account — an unsanctioned service — and, in Audit mode, allows it.
    // ---------------------------------------------------------------------
    {
      id: "evt_idt_08_cloud_dlp",
      ts: T(48 * MIN),
      source: "dlp",
      vendor: "Microsoft Purview",
      event_type: "dlp_alert",
      hostname: host.hostname,
      user_email: insider.email,
      src_ip: host.ip,
      severity: "high",
      mitre_technique: "T1567.002",
      mitre_tactic: "Exfiltration",
      is_detection: true, // alert-grade: DLP policy match on labeled data uploaded to an unsanctioned personal cloud
      description:
        `At 14:03 Purview matched ${file1} and 33 sibling client files being uploaded through Microsoft Edge to ${personalCloud}, a consumer cloud account not on NexaCorp's sanctioned list. Rule mode Audit — flagged and allowed.`,
      file: { name: file1, path: `D:\\${file1}`, extension: "xlsx", size: 5_218_304, sha256: file1Hash },
      raw: {
        "data.office365.Operation": "DlpRuleMatch",
        "data.office365.Workload": "Endpoint",
        "data.office365.UserId": insider.email,
        "data.office365.IncidentId": "6742151",
        "data.office365.PolicyDetails.PolicyName": "NexaCorp — Client & Financial Data Protection",
        "data.office365.PolicyDetails.Rules.RuleName": "Upload of labeled client data to unsanctioned cloud service",
        "data.office365.PolicyDetails.Rules.RuleMode": "Enforce",
        "data.office365.PolicyDetails.Rules.Severity": "High",
        "data.office365.PolicyDetails.Rules.Actions": ["Audit", "NotifyUser"],
        "data.office365.PolicyDetails.Rules.ConditionsMatched.SensitiveInformation.SensitiveInformationTypeName": "EU IBAN",
        "data.office365.PolicyDetails.Rules.ConditionsMatched.SensitiveInformation.Count": "1980",
        "data.office365.PolicyDetails.Rules.ConditionsMatched.SensitiveInformation.Confidence": "85",
        "purview.PolicyName": "NexaCorp — Client & Financial Data Protection",
        "purview.RuleName": "Upload of labeled client data to unsanctioned cloud service",
        "purview.SensitiveInfoType": "EU IBAN",
        "purview.Workload": "Endpoint",
        "purview.ActionTaken": "Audit",
        "purview.Override": "false",
        "cloud.application": "Dropbox (Consumer)",
        "cloud.provider": "Dropbox",
        "upload.destination": personalCloud,
        "upload.file_count": "34",
        "upload.total_size": "612812800",
        "browser.name": "Microsoft Edge",
        "browser.version": "128.0.2739.42",
        "channel.name": "CloudEgress",
        "channel.type": "Browser Upload",
        "url.domain": personalCloud,
        "url.full": `https://${personalCloud}/home`,
        "data.classification": "Highly Confidential — Client",
        "data.office365.DeviceId": deviceId,
        "data.office365.DeviceDisplayName": host.hostname,
        "file.name": file1,
        "user.name": `NEXACORP\\${insider.sam}`,
        "host.name": host.hostname,
        "action_result": "allowed",
      },
    },

    // ---------------------------------------------------------------------
    // 9. The upload as the web proxy saw it. Zscaler logs the TLS POST
    //    session to the consumer cloud — ~584 MB out — allowed under a
    //    file-sharing category, corroborating the DLP match with volume.
    // ---------------------------------------------------------------------
    {
      id: "evt_idt_09_proxy",
      ts: T(49 * MIN),
      source: "proxy",
      vendor: "Zscaler Internet Access",
      event_type: "http_request",
      hostname: host.hostname,
      user_email: insider.email,
      src_ip: host.ip,
      dst_port: 443,
      protocol: "tcp",
      severity: "high",
      mitre_technique: "T1567.002",
      mitre_tactic: "Exfiltration",
      description:
        `Zscaler logged an allowed HTTPS POST session from LAPTOP-NX-FIN14 to ${personalCloud} that carried about 584 MB outbound over roughly 14 minutes, categorized File Sharing.`,
      network: { url: `https://${personalCloud}/upload`, domain: personalCloud, method: "POST", bytes_out: 598_291_000, bytes_in: 842_100 },
      raw: {
        "zscaler.login": insider.sam,
        "zscaler.department": insider.dept,
        "zscaler.location": "Nexacorp HQ",
        "zscaler.cip": host.ip,
        "zscaler.sip": "104.20.16.51",
        "zscaler.hostname": personalCloud,
        "zscaler.url": `https://${personalCloud}/upload`,
        "zscaler.urlcategory": "File Sharing",
        "zscaler.urlclass": "Miscellaneous or Unknown",
        "zscaler.reqmethod": "POST",
        "zscaler.respcode": 200,
        "zscaler.reqsize": 598_291_000,
        "zscaler.respsize": 842_100,
        "zscaler.useragent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.2739.42",
        "zscaler.action": "Allowed",
        "zscaler.threatname": "None",
        "zscaler.appname": "Dropbox",
        "zscaler.serverip": "104.20.16.51",
        "zscaler.clienttranstime": 842_000,
        "user.email": insider.email,
        "user.name": `NEXACORP\\${insider.sam}`,
        "source.hostname": host.hostname,
      },
    },

    // ---------------------------------------------------------------------
    // 10. Sentinel correlation. HR departure + above-baseline access + USB
    //     copy + personal-cloud upload joined into one incident, with the
    //     30-day baseline and the audit-only DLP posture spelled out.
    // ---------------------------------------------------------------------
    {
      id: "evt_idt_10_correlation",
      ts: T(70 * MIN),
      source: "siem",
      vendor: "Microsoft Sentinel",
      event_type: "ueba_anomaly",
      hostname: host.hostname,
      user_email: insider.email,
      src_ip: host.ip,
      severity: "critical",
      description:
        "Sentinel correlated four signals for d.okafor into one incident: a scheduled departure, client-share access far above his 30-day norm, a bulk copy to removable media, and a personal-cloud upload of the same data — every DLP control on the path in Audit mode.",
      raw: {
        "AlertName": "InsiderDataStaging_DepartingEmployee",
        "alert.rule.id": "SEN-INSIDER-0207",
        "alert.severity": "High",
        "target.user.name": `NEXACORP\\${insider.sam}`,
        "user.full_name": insider.name,
        "user.department": insider.dept,
        "user.title": insider.title,
        "user.manager": "priya.desai@nexacorp.com",
        "host.name": host.hostname,
        "MassDownloadActivity": "true",
        "ActionUncommonlyPerformedByUser": "true",
        "behavior.name": "bulk_client_data_access_and_egress",
        "behavior.score": "190",
        "anomaly.score": "92",
        "ExtendedProperties.HR Status": "Resignation submitted; termination 2026-08-28",
        "ExtendedProperties.30-Day File Access Baseline": "14 files/day",
        "ExtendedProperties.Files Copied To Removable Media": "34",
        "ExtendedProperties.Upload Destination": personalCloud + " (unsanctioned personal cloud)",
        "ExtendedProperties.DLP Enforcement Mode": "Audit (no block on any control)",
        "event.action": "correlation-alert",
        "event.outcome": "alerted",
      },
    },

    // ---------------------------------------------------------------------
    // 11. BENIGN CONTROL. A Data Engineer moving an even larger volume the
    //     same day — but as change-ticketed migration work to a SANCTIONED
    //     corporate destination, in role, with no departure flag. Same
    //     "big transfer" shape, opposite verdict.
    // ---------------------------------------------------------------------
    {
      id: "evt_idt_11_benign_control",
      ts: T(-2 * HOUR),
      is_baseline: true,
      source: "dlp",
      vendor: "Microsoft Purview",
      event_type: "cloud_storage_access",
      hostname: colleague.host,
      user_email: colleague.email,
      user_title: "Data Engineer",
      src_ip: colleague.ip,
      severity: "informational",
      fp_explanation:
        "Benign. h.reyes is a Data Engineer whose role is bulk data movement; the transfer is larger than the insider's but goes to a SANCTIONED corporate destination (nexacorp-my.sharepoint.com) under change ticket CHG-2026-0814, matches her baseline for migration windows, and carries no HR-departure flag. Volume alone is not the signal — destination, authorization and context are.",
      description:
        "The same afternoon, h.reyes uploaded 120 files (~1.4 GB) to the corporate OneDrive for Business tenant as part of a scheduled data-warehouse migration referenced by change ticket CHG-2026-0814.",
      raw: {
        "event.action": "FileUploaded",
        "event.outcome": "success",
        "user.email": colleague.email,
        "user.title": "Data Engineer",
        "user.name": `NEXACORP\\${colleague.sam}`,
        "source.ip": colleague.ip,
        "host.name": colleague.host,
        "cloud.application": "Microsoft OneDrive for Business",
        "cloud.provider": "Microsoft365",
        "cloud.resource.name": "nexacorp-my.sharepoint.com/personal/h_reyes",
        "upload.destination": "nexacorp-my.sharepoint.com",
        "upload.file_count": "120",
        "upload.total_size": "1503238553",
        "data.classification": "Internal",
        "policy.name": "NexaCorp — Client & Financial Data Protection",
        "policy.action": "Allowed",
        "action_result": "allowed",
      },
    },
  ];

  // Every event belongs to the one incident.
  for (const e of events) e.incident_id = INCIDENT;

  const iocs: IOC[] = [
    {
      type: "host",
      value: host.hostname,
      first_seen: T(0),
      last_seen: T(70 * MIN),
      // "unknown", not "suspicious" — this is NexaCorp's own asset, the origin
      // of the theft, not adversary infrastructure.
      reputation: "unknown",
      tags: ["insider-host", "affected", "finance"],
    },
    {
      type: "user",
      value: insider.sam,
      first_seen: T(-3 * DAY),
      last_seen: T(70 * MIN),
      reputation: "suspicious",
      tags: ["departing-employee", "insider", "valid-account-abused"],
    },
    {
      type: "email",
      value: insider.email,
      first_seen: T(-3 * DAY),
      last_seen: T(70 * MIN),
      reputation: "suspicious",
      tags: ["departing-employee", "client-accounts"],
    },
    {
      type: "domain",
      value: personalCloud,
      first_seen: T(48 * MIN),
      last_seen: T(63 * MIN),
      reputation: "suspicious",
      tags: ["personal-cloud", "unsanctioned", "exfil-destination", "consumer-dropbox"],
    },
    {
      type: "sha256",
      value: file1Hash,
      first_seen: T(6 * MIN),
      last_seen: T(63 * MIN),
      reputation: "unknown",
      tags: ["sensitivity-labeled", "client-data", "copied-to-usb", "uploaded-to-cloud"],
    },
    {
      type: "sha256",
      value: file2Hash,
      first_seen: T(33 * MIN),
      last_seen: T(33 * MIN),
      reputation: "unknown",
      tags: ["sensitivity-labeled", "client-data", "copied-to-usb"],
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1",
      prompt:
        "The same 34 client files leave the environment by two different routes in this chain. Which pair of events are the two separate exfiltration channels — T1052.001 (over USB) and T1567.002 (to cloud storage)?",
      hint: "One channel writes to a physical drive letter; the other pushes bytes over HTTPS to an internet destination. Staging (T1074.001) is neither — it never leaves the host.",
      kind: "single",
      options: [
        { value: "usb_and_cloud", label: "evt_idt_06_usb_write (files written to the USB volume D:) + evt_idt_09_proxy (the HTTPS POST of the same files to www.dropbox.com)" },
        { value: "staging_and_usb", label: "evt_idt_04_staging (robocopy to a local folder) + evt_idt_06_usb_write (files written to the USB volume)" },
        { value: "access_and_cloud", label: "evt_idt_03_dlp_bulk (bulk access match) + evt_idt_08_cloud_dlp (cloud upload match)" },
        { value: "mount_and_correlation", label: "evt_idt_05_usb_mount (USB mounted) + evt_idt_10_correlation (the Sentinel incident)" },
      ],
      answer: "usb_and_cloud",
      xp: 40,
      explanation:
        "T1052.001 is exfiltration onto removable media — evidenced by evt_idt_06_usb_write, where explorer.exe writes the client files to drive D: (the Kingston volume). T1567.002 is exfiltration to a web service — evidenced by evt_idt_09_proxy, the ~584 MB HTTPS POST to www.dropbox.com. Those are the two channels. evt_idt_04_staging is T1074.001 (local staging): robocopy only consolidates the files into a folder on the same laptop, so nothing has left yet — it is a precursor, not a channel. evt_idt_03/evt_idt_08 are the DLP policy matches that describe the activity, and evt_idt_05/evt_idt_10 are the mount and the correlation; useful evidence, but not themselves the two egress events.",
    },
    {
      id: "q2",
      prompt:
        "Every DLP match in this incident — bulk access, USB copy, and cloud upload — shows RuleMode: Enforce, Actions: [Audit, NotifyUser], and action_result: allowed. Nothing was blocked. What does that tell you about NexaCorp's DLP posture, and how should it change your reading of the incident?",
      kind: "single",
      options: [
        { value: "audit_only_still_theft", label: "The policies are live and matched correctly, but their configured response is to log and notify, not block — so 'allowed' here means 'not prevented', not 'approved'. The data still left; the DLP simply couldn't stop it." },
        { value: "allowed_means_authorized", label: "action_result: allowed means the platform authorized the transfers as legitimate business activity, so the matches can be closed as expected behaviour" },
        { value: "policy_broken", label: "The DLP policies are misconfigured or disabled — a working policy would have blocked, so these events are noise from a broken control and should be ignored" },
        { value: "false_positives", label: "Three matches on the same user in one afternoon is a classifier tuning problem; the EU IBAN detections are false positives that inflate the incident" },
      ],
      answer: "audit_only_still_theft",
      xp: 50,
      explanation:
        "RuleMode is Enforce and purview.ActionTaken is Audit on every match — the policies are switched on and matched real labeled data (2,214 / 1,663 / 1,980 IBAN instances at 85% confidence), which rules out 'disabled' (c) and 'false positive' (d). But the configured Actions are [Audit, NotifyUser], with no BlockAccess or RestrictAccess anywhere — so the enforced behaviour IS logging, not blocking. That is why action_result reads allowed: the control observed the activity and permitted it by design. The trap is (b) — reading 'allowed' as 'authorized'. In audit-mode DLP, 'allowed' is the default outcome for everything, benign and malicious alike; it carries no verdict at all. The correct reading is that these three matches are high-quality evidence of data leaving, and the absence of a block is a gap in the control, not exoneration of the user.",
    },
    {
      id: "q3",
      prompt:
        "evt_idt_11_benign_control shows h.reyes moving 1.4 GB — a LARGER transfer than the insider's ~584 MB — the same afternoon, yet it is benign. Reading it against Daniel Okafor's activity, what actually separates exfiltration from legitimate bulk work here?",
      hint: "If raw volume decided it, the bigger transfer would be the worse one. It isn't. Compare destination, authorization, role, and the HR signal.",
      kind: "single",
      options: [
        { value: "destination_auth_context", label: "Destination and context: Reyes sends to a SANCTIONED corporate tenant under change ticket CHG-2026-0814, in a role whose job is bulk data movement, with no departure flag — Okafor sends labeled CLIENT data to an unsanctioned personal cloud and a USB, above his own baseline, days before his access is revoked" },
        { value: "volume_decides", label: "Volume decides it — Reyes moved 1.4 GB against Okafor's ~584 MB, so by raw transfer size her upload is the objectively higher-risk one and should be escalated ahead of his" },
        { value: "dlp_fired_or_not", label: "Whether DLP fired — Okafor triggered Purview policy matches and Reyes's transfer did not, so the presence or absence of a DLP alert alone cleanly separates the two cases with no further context needed" },
        { value: "same_verdict", label: "Nothing meaningfully separates them — both are large transfers off the corporate network on the same afternoon by authenticated employees, so both should be logged and closed as ordinary benign business activity" },
      ],
      answer: "destination_auth_context",
      xp: 60,
      explanation:
        "This is the core skill the scenario trains: exfiltration is judged by destination, authorization and baseline — not by byte count. Reyes moves MORE data, but to nexacorp-my.sharepoint.com (a sanctioned corporate destination), under an actual change ticket, in a Data Engineer role whose remit is bulk migration, with classification Internal and no HR flag. Okafor moves Highly-Confidential CLIENT data to a personal Dropbox and a personal USB, at 13.6x his own 30-day file-access baseline, three days into a resignation with access-revocation already scheduled. Option (b) inverts the logic — 'bigger = worse' would clear the thief and flag the engineer. Option (c) over-trusts the DLP: audit-mode matches flag sensitive-data movement but don't by themselves prove intent; the exoneration of Reyes comes from her context, and the incrimination of Okafor comes from his — the destination, the authorization, the baseline and the departure, read together.",
    },
    {
      id: "q4",
      prompt:
        "You are writing the verdict. No control blocked anything, no malware ran, and every action was authenticated as Daniel Okafor's own valid account. How should this incident be classified and handled?",
      kind: "single",
      options: [
        { value: "malicious_insider_escalate", label: "Malicious insider data theft — client data was exfiltrated by two channels by a departing employee acting well outside his baseline. Preserve the endpoint and USB evidence, escalate to HR/Legal, and treat pending access-revocation as urgent; 'nothing was blocked' is a control gap, not innocence" },
        { value: "benign_all_allowed", label: "Benign — since every action was allowed, performed under a valid account, and involved data his role can access, there is no policy violation to action" },
        { value: "low_priority_dlp_tuning", label: "Low-priority — route it to the DLP engineering backlog as tuning feedback (policies should have blocked) and close the security ticket with no user action" },
        { value: "wait_for_malware", label: "Hold — without malware, a blocked action, or a compromised credential there is no confirmed intrusion, so wait for a second signal before treating it as an incident" },
      ],
      answer: "malicious_insider_escalate",
      xp: 60,
      explanation:
        "Insider threats look exactly like this: authorized access, a valid account, no malware, nothing blocked. The evidence is nonetheless complete and dated inside one afternoon — bulk access at 13.6x baseline (T1039), a 34-file copy to a personal USB (T1052.001), and an upload of the same files to a personal Dropbox (T1567.002) — by a man whose resignation and access-revocation are already logged in Workday. Option (b) is the exact failure the scenario exists to prevent: equating 'allowed' with 'benign' in an audit-only DLP estate, where allowed is the outcome of everything. Option (c) buries a live data-theft in an engineering queue. Option (d) waits for a malware signal that will never come in a valid-account insider case. The correct handling is to classify it as malicious insider exfiltration, preserve the host and the USB serial (KINGSTON-DT-6F2A9C41) as evidence, loop in HR and Legal, and make sure the scheduled revocation actually happens — and to raise moving the DLP policies from Audit to Block so the next one is stopped, not just recorded.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "Departing Insider — Client Data to USB and Personal Cloud",
    threat_actor: "Malicious insider (departing employee, valid account — no external actor)",
    attack_kind: "insider_data_theft",
    briefing:
      "Microsoft Sentinel raised an insider-risk incident at 14:25 for d.okafor, a Senior Financial Analyst whose resignation is already in Workday. DLP logged bulk access to client data, a copy to removable media, and an upload to a personal cloud — all in Audit mode, none blocked. Establish what left the environment, by which routes, and whether this is theft or legitimate work.",
    narrative: `Daniel Okafor is a Senior Financial Analyst on NexaCorp's Client Accounts team. Three days before this window, he submitted his resignation; Workday shows a voluntary termination dated 2026-08-28, his last working Friday, with access-revocation already scheduled for that evening. He is inside his notice period, and everything he does over this Monday afternoon is authenticated as his own valid account — nothing is stolen or spoofed.

At 13:15 he logs on to LAPTOP-NX-FIN14 normally. By 13:21 he is opening the Client Accounts file share far faster than usual — a representative record from a burst of 190-plus files in about eight minutes, against a 30-day baseline of roughly fourteen a day. At 13:29 Microsoft Purview matches 2,214 instances of labeled client financial data being read; the rule is enforced, but its configured actions are Audit and NotifyUser, so it logs and notifies and blocks nothing. At 13:37 robocopy mirrors the ClientRecords folder into a local staging folder under his profile.

At 13:46 a Kingston DataTraveler USB stick — serial KINGSTON-DT-6F2A9C41, volume labeled DOKAFOR-BACKUP — mounts as drive D:. Within two minutes, explorer.exe writes 34 client files to it, including Client_Master_Book_2026.xlsx and FY26_Client_Pricing_Model.xlsx; Defender for Endpoint records the writes, and Purview's removable-media policy matches them — again in Audit mode, again allowed. At 14:03 the same 34 files are uploaded through Microsoft Edge to www.dropbox.com, a consumer account on no sanctioned list; Purview's cloud-egress policy matches it (Audit, allowed), and Zscaler logs the HTTPS POST session carrying about 584 MB out over roughly fourteen minutes.

Not one control on this path said no. Sentinel finally correlates the departure, the above-baseline access, the USB copy and the personal-cloud upload into a single incident at 14:25. For contrast, the same afternoon a Data Engineer, Hannah Reyes, moved an even larger 1.4 GB — but to a sanctioned corporate tenant, under change ticket CHG-2026-0814, in role, with no departure flag. Same shape, opposite verdict. The lesson is that in an audit-only DLP estate 'allowed' is the outcome of everything, and the analyst has to reach 'theft' from the data's destination and the actor's context, not from any control that blocked it.`,
    learning_objectives: [
      "Recognise insider data theft where every action is allowed, performed under a valid account (T1078), with no malware and no blocked control",
      "Distinguish the two exfiltration channels — over USB (T1052.001) and to cloud storage (T1567.002) — from local staging (T1074.001), which never leaves the host",
      "Read Purview RuleMode/Actions/ActionTaken fields to see that an enforced-but-audit-only policy logs rather than blocks, so 'action_result: allowed' carries no verdict",
      "Judge exfiltration by destination, authorization and baseline rather than raw transfer volume — using the benign heavy-transfer control to calibrate",
      "Weigh HR/Workday context (a scheduled departure) and 30-day behavioural baseline as decisive evidence when technical controls stay silent",
      "Correlate Workday, Purview DLP, Defender for Endpoint, Zscaler and Sentinel on one user and host to reconstruct a single insider incident",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: T(-3 * DAY), phase: "Context", action: "Workday records d.okafor's resignation — termination 2026-08-28, access revocation scheduled" },
      { ts: T(0), phase: "Valid Accounts", action: "Normal 4624 logon on LAPTOP-NX-FIN14 under his own account (T1078)" },
      { ts: T(6 * MIN), phase: "Collection", action: "Client-share access 190+ files vs ~14/day baseline (T1039)" },
      { ts: T(14 * MIN), phase: "Detection", action: "Purview matches 2,214 labeled client-data instances — Audit mode, allowed" },
      { ts: T(22 * MIN), phase: "Collection", action: "robocopy stages ClientRecords into a local folder on the laptop (T1074.001)" },
      { ts: T(31 * MIN), phase: "Exfiltration", action: `Kingston USB ${usbSerial} (volume ${usbVolume}) mounts as D: — device control in Audit mode` },
      { ts: T(32 * MIN), phase: "Exfiltration", action: "Defender for Endpoint records 34 client files written to the USB volume (T1052.001)" },
      { ts: T(48 * MIN), phase: "Exfiltration", action: `Same 34 files uploaded via browser to ${personalCloud} — Purview match, Audit mode, allowed (T1567.002)` },
      { ts: T(49 * MIN), phase: "Exfiltration", action: `Zscaler logs the allowed HTTPS POST to ${personalCloud} — ~584 MB out over ~14 minutes` },
      { ts: T(70 * MIN), phase: "Detection", action: "Sentinel correlates departure + access + USB + cloud into one insider incident" },
    ],
    questions,
  };
}
