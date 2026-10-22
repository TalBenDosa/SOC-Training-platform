/**
 * Scenario pack: "Sentinel incident for a finance analyst who resigned"
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
 * exfil-vs-legitimate-work question. It lives in its own incident (inc:idt:2),
 * so it never sits inside the insider's endpoint case.
 *
 * Covers T1078 (Valid Accounts — his own), T1039 (Data from Network Shared
 * Drive), T1074.001 (Local Data Staging), T1052.001 (Exfiltration over USB) and
 * T1567.002 (Exfiltration to Cloud Storage).
 *
 * SOURCES (each in its own product's format): Windows Security (the logon and the
 * file server's share-access records), Microsoft Defender for Endpoint (the
 * processes, the USB mount, the writes to the removable volume, the browser's
 * network session), Microsoft Purview endpoint DLP (policy matches), Zscaler
 * Internet Access (the upload as the proxy saw it), Workday (the HR resignation
 * record the case turns on), ServiceNow (the benign migration's change ticket),
 * Microsoft 365 audit (the benign upload) and Microsoft Sentinel (the correlation
 * that ties HR + access + USB + cloud into one incident). This pack fits the
 * Microsoft-365 / Purview-DLP company profiles (nexacorp, medcore, globallogis).
 *
 * NOTE: `difficulty: "intermediate"` is declared on the SCENARIOS registry entry
 * in scenarios.ts (ScenarioBundle itself carries no difficulty field).
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";
import { winLogon, winShareAccess, winDetailedShareAccess, domainSidFor } from "@/lib/sim/emitters/windowsSecurity";
import { mdeProcess, mdeFile, mdeNetwork, mdeDns } from "@/lib/sim/emitters/mde";
import { zscalerWeb } from "@/lib/sim/emitters/zscaler";
import { sentinelAlert } from "@/lib/sim/emitters/sentinel";
import { m365Operation } from "@/lib/sim/emitters/m365";
import { serviceNowRecord } from "@/lib/sim/emitters/servicenow";

export function buildInsiderDlpUsbCloudScenario(
  scenarioId = "insider-dlp-usb-cloud-2026",
): ScenarioBundle {
  const B = new Date("2026-08-24T13:15:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const SEC = 1_000;
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
  const deviceId = "2d360a3dd9a1e8b39a4a772e451bc663";
  const insiderSid = "S-1-5-21-3421479547-3897544621-1789562108-5277";

  // The client/finance file share he pulls from (an on-premises file server).
  const fileServer = { name: "SRV-NX-FIN02", ip: "10.20.4.30", share: "\\\\SRV-NX-FIN02\\ClientShare" };

  // The removable drive: serial + volume label are the citable USB indicators.
  const usbSerial = "KINGSTON-DT-6F2A9C41";
  const usbVolume = "DOKAFOR-BACKUP";

  // The personal, unsanctioned cloud destination, and the address Dropbox publishes for it.
  const personalCloud = "www.dropbox.com";
  const dropboxIp = "162.125.248.18";
  // NexaCorp's public egress NAT address (the address the proxy sees the laptop behind).
  const egressIp = "217.177.80.10";

  // The two marquee sensitive files, cited verbatim across the chain.
  const file1 = "Client_Master_Book_2026.xlsx";
  const file2 = "FY26_Client_Pricing_Model.xlsx";
  const file1Hash = makeSha256("nexacorp_client_master_book_2026_xlsx");
  const file2Hash = makeSha256("nexacorp_fy26_client_pricing_model_xlsx");
  const robocopyHash = makeSha256("windows_system32_robocopy_exe_signed_microsoft_2026");
  const explorerHash = makeSha256("windows_explorer_exe_signed_microsoft_2026");
  const cmdHash = makeSha256("windows_system32_cmd_exe_signed_microsoft_2026");
  const edgeHash = makeSha256("microsoft_edge_msedge_exe_signed_microsoft_2026");

  // The benign control — a Data Engineer doing sanctioned, change-ticketed bulk work.
  const colleague = { email: "h.reyes@nexacorp.com", name: "Hannah Reyes", sam: "h.reyes", host: "LAPTOP-NX-ENG07", ip: "10.20.4.61" };
  const change = "CHG-2026-0814";

  // Two incidents. The insider's case is host-primary (USB write, local staging on the
  // laptop) AND has a control-plane facet (DLP cloud egress + proxy) → edr_scope "hybrid",
  // stamped on the primary EDR detection. The benign migration is a control-plane-only
  // record in its own incident, so it never enters the insider's endpoint case.
  const INCIDENT = "inc:idt:1";
  const INCIDENT_CTRL = "inc:idt:2";

  const cx = "nexacorp" as const;
  const base = { companyId: cx, host: host.hostname, user: insider.email, srcIp: host.ip, incidentId: INCIDENT } as const;
  const EDGE = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
  const EDGE_CMD = `"${EDGE}" --profile-directory=Default`;
  const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36 Edg/150.0.3520.46";
  const acct = `NEXACORP\\${insider.sam}`;
  const STAGE = `C:\\Users\\${insider.sam}\\AppData\\Local\\Temp\\ClientBackup`;
  const SHARE_LOGON = "0x8A5D210";
  const PID = { explorer: 3920, userinit: 3884, cmd: 6620, robocopy: 7044, edge: 9120 };
  const withProc = (e: TelemetryEvent, p: NonNullable<TelemetryEvent["process"]>): TelemetryEvent => ({ ...e, process: p });
  const explorerProc = { name: "explorer.exe", pid: PID.explorer, path: "C:\\Windows\\explorer.exe", cmdline: "C:\\WINDOWS\\Explorer.EXE", parent_name: "userinit.exe", parent_pid: PID.userinit, user: acct, integrity: "medium" as const, hash: { sha256: explorerHash } };
  const edgeProc = { name: "msedge.exe", pid: PID.edge, path: EDGE, cmdline: `${EDGE_CMD} https://${personalCloud}`, parent_name: "explorer.exe", parent_pid: PID.explorer, user: acct, integrity: "medium" as const, hash: { sha256: edgeHash } };

  // Per-file records of the share reads (the on-premises file server's own Security log).
  const sampleReads: [string, number, string][] = [
    [file1, 0, "ClientRecords\\Client_Master_Book_2026.xlsx"],
    [file2, 70, "ClientRecords\\FY26_Client_Pricing_Model.xlsx"],
    ["Q2_Client_Holdings_Summary.xlsx", 150, "ClientRecords\\Holdings\\Q2_Client_Holdings_Summary.xlsx"],
    ["Fee_Schedule_2026_Institutional.pdf", 260, "ClientRecords\\Contracts\\Fee_Schedule_2026_Institutional.pdf"],
    ["Onboarding_Pack_Meridian_Capital.docx", 380, "ClientRecords\\Onboarding\\Onboarding_Pack_Meridian_Capital.docx"],
  ];

  // The 34 files copied to the stick: six representative records (the rest are the same pattern).
  const usbCopies: [string, number, string, number][] = [
    [file1, 0, file1Hash, 5_218_304],
    [file2, 28, file2Hash, 3_907_072],
    ["Q2_Client_Holdings_Summary.xlsx", 51, makeSha256("nexacorp_q2_client_holdings_summary_xlsx"), 2_641_920],
    ["Fee_Schedule_2026_Institutional.pdf", 74, makeSha256("nexacorp_fee_schedule_2026_institutional_pdf"), 1_187_840],
    ["Onboarding_Pack_Meridian_Capital.docx", 97, makeSha256("nexacorp_onboarding_pack_meridian_capital_docx"), 764_928],
    ["Client_Contact_Register.xlsx", 118, makeSha256("nexacorp_client_contact_register_xlsx"), 2_105_344],
  ];

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
    // 0b. The benign migration's change ticket, approved that morning (ServiceNow).
    // ---------------------------------------------------------------------
    serviceNowRecord({
      companyId: cx, id: "evt_idt_00b_change_ticket", ts: "2026-08-24T09:30:00.000Z", table: "change_request", number: change, state: "Implement",
      shortDescription: "Data-warehouse migration: stage extracts in OneDrive for Business", callerId: colleague.email, incidentId: INCIDENT_CTRL,
      severity: "informational",
      extra: {
        "servicenow.category": "Data", "servicenow.opened_by": colleague.email, "servicenow.assignment_group": "Data Platform",
        "servicenow.opened_at": "2026-08-24 09:30:00",
        "servicenow.description": "Approved standard change: h.reyes uploads the warehouse extracts (about 120 files, 1.4 GB) to her corporate OneDrive for Business for the migration window of 24 August.",
      },
      description: "Change request CHG-2026-0814 was approved for h.reyes to stage about 120 data-warehouse extracts in the corporate OneDrive for Business on 24 August.",
    }),

    // ---------------------------------------------------------------------
    // 1. Ordinary interactive logon under his OWN valid account (T1078).
    //    Nothing is stolen or spoofed anywhere in this incident — every
    //    action that follows is authenticated as Daniel Okafor.
    // ---------------------------------------------------------------------
    winLogon({
      id: "evt_idt_01_logon", ts: T(0), companyId: cx, host: host.hostname, logSource: "windows_security", targetUser: insider.sam, userEmail: insider.email,
      targetSid: insiderSid, logonType: 2, authPackage: "Kerberos", logonProcess: "User32 ", workstation: host.hostname, logonId: "0x8A41C6",
      subjectUser: `${host.hostname}$`, subjectSid: "S-1-5-18", processName: "C:\\Windows\\System32\\winlogon.exe", recordId: "5540921",
      severity: "informational", incidentId: INCIDENT, mitre: "T1078", tactic: "Initial Access",
      description:
        "A routine 4624 interactive logon for d.okafor on LAPTOP-NX-FIN14 at 13:15, LogonType 2 over Kerberos — the analyst's normal workstation session.",
    }),
    // 1b. His shell starts (explorer.exe, from userinit.exe) and he opens a command prompt.
    withProc(mdeProcess({
      ...base, id: "evt_idt_01b_shell", ts: T(12 * SEC), processName: "explorer.exe", processPath: "C:\\Windows\\explorer.exe", cmdline: "C:\\WINDOWS\\Explorer.EXE",
      parentName: "userinit.exe", parentPid: PID.userinit, pid: PID.explorer, sha256: explorerHash, integrity: "Medium", signed: true, severity: "informational",
      description: "userinit.exe started explorer.exe in d.okafor's session on LAPTOP-NX-FIN14, twelve seconds after the logon.",
    }), explorerProc),

    // ---------------------------------------------------------------------
    // 2. Mass access to the client/finance share — many files read in a
    //    short window, well above what this account normally touches. The file
    //    server's own Security log: a share connection and per-file samples.
    // ---------------------------------------------------------------------
    { ...winShareAccess({
      id: "evt_idt_02_mass_access", ts: T(5 * MIN + 50 * SEC), companyId: cx, host: fileServer.name, targetUser: insider.sam, targetSid: domainSidFor(cx, insider.sam),
      userEmail: insider.email, srcIp: host.ip, shareName: "\\\\*\\ClientShare", shareLocalPath: "\\??\\D:\\Shares\\ClientShare", subjectLogonId: SHARE_LOGON,
      severity: "medium", incidentId: INCIDENT, mitre: "T1039", tactic: "Collection",
      description:
        "Beginning 13:20 d.okafor connected to the ClientShare share on SRV-NX-FIN02 from LAPTOP-NX-FIN14 and, from 13:21, opened 192 files from it in about eight minutes — far above his usual read volume.",
    }), source: "windows_security" as const },
    ...sampleReads.map(([name, off, rel], i) => ({
      ...winDetailedShareAccess({
        id: `evt_idt_02${String.fromCharCode(97 + i)}_read_${i + 1}`, ts: T(6 * MIN + off * SEC), companyId: cx, host: fileServer.name, targetUser: insider.sam,
        targetSid: domainSidFor(cx, insider.sam), userEmail: insider.email, srcIp: host.ip, shareName: "\\\\*\\ClientShare", shareLocalPath: "\\??\\D:\\Shares\\ClientShare",
        relativeTargetName: rel, accessMask: "0x1", accessList: "%%4416", subjectLogonId: SHARE_LOGON, severity: "low", incidentId: INCIDENT,
        description: `A 5145 on SRV-NX-FIN02: d.okafor requested ReadData on ${name} under ClientShare from 10.20.4.58.`,
      }),
      source: "windows_security" as const,
    })),

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
      raw: {
        "data.office365.RecordType": "63",
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
        "data.office365.EndpointMetaData.Application": "EXCEL.EXE",
        "data.office365.EndpointMetaData.DeviceName": host.hostname,
        "data.office365.DeviceId": deviceId,
        "data.office365.DeviceDisplayName": host.hostname,
        "data.office365.ClientProcessName": "EXCEL.EXE",
      },
    },

    // ---------------------------------------------------------------------
    // 4. Local staging (T1074.001). robocopy — a signed, built-in Windows
    //    utility — mirrors the client-records tree into a local temp folder,
    //    consolidating the files before they leave the host.
    // ---------------------------------------------------------------------
    withProc(mdeProcess({
      ...base, id: "evt_idt_04a_cmd", ts: T(21 * MIN + 40 * SEC), processName: "cmd.exe", processPath: "C:\\Windows\\System32\\cmd.exe", cmdline: "\"C:\\WINDOWS\\system32\\cmd.exe\"",
      parentName: "explorer.exe", parentPid: PID.explorer, pid: PID.cmd, sha256: cmdHash, integrity: "Medium", signed: true, severity: "informational",
      description: "explorer.exe started a command prompt in d.okafor's session at 13:36:40.",
    }), { name: "cmd.exe", pid: PID.cmd, path: "C:\\Windows\\System32\\cmd.exe", cmdline: "\"C:\\WINDOWS\\system32\\cmd.exe\"", parent_name: "explorer.exe", parent_pid: PID.explorer, user: acct, integrity: "medium", hash: { sha256: cmdHash } }),
    mdeProcess({
      ...base, id: "evt_idt_04_staging", ts: T(22 * MIN), processName: "robocopy.exe", processPath: "C:\\Windows\\System32\\Robocopy.exe",
      cmdline: `robocopy.exe "${fileServer.share}\\ClientRecords" "${STAGE}" /E /Z /R:1 /W:1 /MT:16 /NFL /NDL`,
      parentName: "cmd.exe", parentPid: PID.cmd, pid: PID.robocopy, sha256: robocopyHash, integrity: "Medium", signed: true, severity: "medium",
      mitre: "T1074.001", tactic: "Collection",
      description:
        "At 13:37 robocopy.exe mirrored the ClientRecords folder from the file share into a local staging folder under d.okafor's profile on LAPTOP-NX-FIN14, consolidating the files onto the endpoint.",
    }),

    // ---------------------------------------------------------------------
    // 5. Removable media mounts: Defender for Endpoint records the Kingston
    //    stick (DeviceEvents UsbDriveMounted) — serial and drive letter are the
    //    citable USB indicators. Device control is in Audit mode, so it is allowed.
    // ---------------------------------------------------------------------
    {
      id: "evt_idt_05_usb_mount",
      ts: T(31 * MIN),
      source: "edr",
      vendor: "Microsoft Defender for Endpoint",
      event_type: "file_create",
      hostname: host.hostname,
      user_email: insider.email,
      src_ip: host.ip,
      severity: "medium",
      mitre_technique: "T1052.001",
      mitre_tactic: "Exfiltration",
      incident_id: INCIDENT,
      description:
        `At 13:46 a Kingston DataTraveler USB stick (serial ${usbSerial}, volume labeled ${usbVolume}) was mounted on LAPTOP-NX-FIN14 as drive D:. Device control is in Audit mode, so the mount was recorded and permitted.`,
      raw: {
        "usb.action": "mounted",
        "usb.mount_point": "D:",
        "usb.device.name": "DataTraveler 3.0",
        "usb.product": "DataTraveler 3.0",
        "usb.vendor": "Kingston",
        "usb.device.serial": usbSerial,
        "DeviceName": host.hostname,
        "DeviceId": deviceId,
        "AccountName": insider.sam,
        "AccountDomain": "NEXACORP",
      },
    },

    // ---------------------------------------------------------------------
    // 6. EDR sees the copy to removable media. MDE FileCreated on D:, the
    //    host-observable proof that files actually left onto the stick.
    //    This is the alert-grade EDR detection carrying the USB-exfil crux.
    // ---------------------------------------------------------------------
    ...usbCopies.map(([name, off, sha, size], i) => {
      const e = mdeFile({
        ...base, id: i === 0 ? "evt_idt_06_usb_write" : `evt_idt_06${String.fromCharCode(96 + i)}_usb_write_${i + 1}`, ts: T(32 * MIN + off * SEC),
        path: `D:\\${name}`, sha256: sha, size, action: "file_create", initiatingProcess: "explorer.exe", initiatingCmdline: "explorer.exe", signed: undefined,
        severity: i === 0 ? "high" : "medium",
        ...(i === 0 ? { isDetection: true, mitre: "T1052.001", tactic: "Exfiltration" } : {}),
        description: i === 0
          ? `At 13:47 explorer.exe wrote ${file1} to the mounted USB volume ${usbVolume} (D:) on LAPTOP-NX-FIN14 — the first of 34 client files copied to the stick over the next two minutes.`
          : `explorer.exe wrote ${name} to the USB volume D: on LAPTOP-NX-FIN14.`,
      });
      return withProc(i === 0 ? { ...e, edr_scope: "hybrid" as const } : e, explorerProc);
    }),

    // ---------------------------------------------------------------------
    // 7. Purview Endpoint DLP matches the copy-to-removable-media on labeled
    //    data — again Enforce mode, Audit action. The USB-egress
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
      raw: {
        "data.office365.RecordType": "63",
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
        "data.office365.EndpointMetaData.Application": "explorer.exe",
        "data.office365.EndpointMetaData.DeviceName": host.hostname,
        "data.office365.DeviceId": deviceId,
        "data.office365.DeviceDisplayName": host.hostname,
        "data.office365.ClientProcessName": "explorer.exe",
      },
    },

    // ---------------------------------------------------------------------
    // 8. Personal-cloud egress. Edge is started, resolves Dropbox and opens a
    //    TLS session to it (MDE); Purview Endpoint DLP flags the SAME labeled
    //    data being uploaded to a consumer Dropbox account — an unsanctioned
    //    service — and, in Audit mode, allows it.
    // ---------------------------------------------------------------------
    withProc(mdeProcess({
      ...base, id: "evt_idt_07a_edge_start", ts: T(47 * MIN + 30 * SEC), processName: "msedge.exe", processPath: EDGE, cmdline: `${EDGE_CMD} https://${personalCloud}`,
      parentName: "explorer.exe", parentPid: PID.explorer, pid: PID.edge, sha256: edgeHash, integrity: "Medium", signed: true, severity: "low",
      description: "explorer.exe started Microsoft Edge in d.okafor's session at 14:02:30, pointed at www.dropbox.com.",
    }), edgeProc),
    withProc(mdeDns({
      ...base, id: "evt_idt_07b_dropbox_dns", ts: T(47 * MIN + 40 * SEC), domain: personalCloud, resolvedIp: dropboxIp, severity: "low",
      description: "msedge.exe on LAPTOP-NX-FIN14 resolved www.dropbox.com to 162.125.248.18.",
    }), edgeProc),
    withProc(mdeNetwork({
      ...base, id: "evt_idt_07c_dropbox_net", ts: T(47 * MIN + 45 * SEC), remoteIp: dropboxIp, remotePort: 443, domain: personalCloud, initiatingProcess: "msedge.exe", severity: "medium",
      description: "msedge.exe opened a TCP/443 connection to 162.125.248.18 (www.dropbox.com).",
    }), edgeProc),
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
      raw: {
        "data.office365.RecordType": "63",
        "data.office365.Operation": "DlpRuleMatch",
        "data.office365.Workload": "Endpoint",
        "data.office365.UserId": insider.email,
        "data.office365.ObjectId": `${STAGE}\\${file1}`,
        "data.office365.IncidentId": "6742151",
        "data.office365.PolicyDetails.PolicyName": "NexaCorp — Client & Financial Data Protection",
        "data.office365.PolicyDetails.Rules.RuleName": "Upload of labeled client data to unsanctioned cloud service",
        "data.office365.PolicyDetails.Rules.RuleMode": "Enforce",
        "data.office365.PolicyDetails.Rules.Severity": "High",
        "data.office365.PolicyDetails.Rules.Actions": ["Audit", "NotifyUser"],
        "data.office365.PolicyDetails.Rules.ConditionsMatched.SensitiveInformation.SensitiveInformationTypeName": "EU IBAN",
        "data.office365.PolicyDetails.Rules.ConditionsMatched.SensitiveInformation.Count": "1980",
        "data.office365.PolicyDetails.Rules.ConditionsMatched.SensitiveInformation.Confidence": "85",
        "data.office365.EndpointMetaData.Application": "msedge.exe",
        "data.office365.EndpointMetaData.DeviceName": host.hostname,
        "data.office365.DeviceId": deviceId,
        "data.office365.DeviceDisplayName": host.hostname,
        "data.office365.ClientProcessName": "msedge.exe",
      },
    },

    // ---------------------------------------------------------------------
    // 9. The upload as the web proxy saw it. Zscaler logs the TLS POST sessions
    //    to the consumer cloud — three requests of one chunked upload, 613,402,611
    //    bytes out in total — each written when it completes, allowed under a
    //    file-sharing category, corroborating the DLP match with volume.
    // ---------------------------------------------------------------------
    ...([
      { id: "evt_idt_09a_proxy_chunk1", off: 54 * MIN + 20 * SEC, req: 215_000_000, resp: 301_400, ms: 320_000, desc: "Zscaler logged the first allowed HTTPS POST to www.dropbox.com, 215 MB out, completing at 14:09:20." },
      { id: "evt_idt_09b_proxy_chunk2", off: 58 * MIN + 50 * SEC, req: 210_000_000, resp: 288_900, ms: 270_000, desc: "Zscaler logged the second allowed HTTPS POST to www.dropbox.com, 210 MB out, completing at 14:13:50." },
      { id: "evt_idt_09_proxy", off: 63 * MIN + 2 * SEC, req: 188_402_611, resp: 251_800, ms: 252_000, desc: "Zscaler logged the third allowed HTTPS POST to www.dropbox.com, 188 MB out, completing at 14:18:02. The three requests carry 613,402,611 bytes (about 584 MiB) in total over 14 minutes, categorized File Sharing." },
    ] as const).map(c => {
      const e = zscalerWeb({
        ...base, id: c.id, ts: T(c.off), url: `https://${personalCloud}/upload`, domain: personalCloud, method: "POST", action: "allowed", category: "File Sharing",
        bytesSent: c.req, bytesReceived: c.resp, userAgent: UA, appName: "Dropbox", location: "NexaCorp HQ", status: 200, severity: "high",
        ...(c.id === "evt_idt_09_proxy" ? { mitre: "T1567.002", tactic: "Exfiltration" } : {}),
        description: c.desc,
      });
      // The proxy sees the laptop behind the company's public NAT address; the private client address rides in cip.
      e.src_ip = egressIp;
      e.dst_ip = dropboxIp;
      Object.assign(e.raw, {
        "zscaler.cip": host.ip, "zscaler.serverip": dropboxIp, "zscaler.clienttranstime": c.ms, "zscaler.department": insider.dept,
        "zscaler.urlclass": "Miscellaneous or Unknown", "zscaler.respcode": 200,
      });
      return e;
    }),

    // ---------------------------------------------------------------------
    // 10. BENIGN CONTROL. A Data Engineer moving an even larger volume the
    //     same day — but as change-ticketed migration work to a SANCTIONED
    //     corporate destination, in role, with no departure flag. Same
    //     "big transfer" shape, opposite verdict. Its own incident.
    // ---------------------------------------------------------------------
    {
      ...m365Operation({
        companyId: cx, id: "evt_idt_11_benign_control", ts: T(55 * MIN), srcIp: egressIp, user: colleague.email, userTitle: "Data Engineer",
        operation: "FileUploaded", workload: "OneDrive", objectId: "https://nexacorp-my.sharepoint.com/personal/h_reyes_nexacorp_com/Documents/warehouse-migration/extract_2026_08_24_part01.parquet",
        fileName: "extract_2026_08_24_part01.parquet", siteUrl: "https://nexacorp-my.sharepoint.com/personal/h_reyes_nexacorp_com", userAgent: UA, severity: "informational",
        incidentId: INCIDENT_CTRL,
        extra: { "RecordType": "6", "UserType": "0", "ResultStatus": "Succeeded", "SourceRelativeUrl": "Documents/warehouse-migration", "EventSource": "OneDrive", "ItemType": "File" },
        description: "At 14:10 h.reyes uploaded warehouse-migration/extract_2026_08_24_part01.parquet to her corporate OneDrive for Business: the first record of a 120-file, 1.4 GB upload covered by change ticket CHG-2026-0814.",
      }),
      fp_explanation:
        "Benign. h.reyes is a Data Engineer whose role is bulk data movement; the transfer is larger than the insider's but goes to a SANCTIONED corporate destination (nexacorp-my.sharepoint.com) under change ticket CHG-2026-0814, matches her baseline for migration windows, and carries no HR-departure flag. Volume alone is not the signal — destination, authorization and context are.",
    },

    // ---------------------------------------------------------------------
    // 11. Sentinel correlation. HR departure + above-baseline access + USB
    //     copy + personal-cloud upload joined into one incident, with the
    //     30-day baseline and the audit-only DLP posture spelled out.
    // ---------------------------------------------------------------------
    sentinelAlert({
      ...base, id: "evt_idt_10_correlation", ts: T(70 * MIN), alertName: "InsiderDataStaging_DepartingEmployee", ruleId: "SEN-INSIDER-0207",
      severity: "high", eventType: "ueba_anomaly", tactic: "Exfiltration", fullName: insider.name, department: insider.dept, title: insider.title,
      extendedProperties: {
        "Manager": "priya.desai@nexacorp.com",
        "HR Status": "Resignation submitted; termination 2026-08-28",
        "30-Day File Access Baseline": "14 files/day",
        "Files Accessed In Window": "192",
        "Files Copied To Removable Media": "34",
        "USB Serial Number": usbSerial,
        "USB Volume Label": usbVolume,
        "Upload Destination": `${personalCloud} (unsanctioned personal cloud)`,
        "DLP Enforcement Mode": "Audit (no block on any control)",
      },
      description:
        "Sentinel correlated four signals for d.okafor into one incident: a scheduled departure, client-share access far above his 30-day norm, a bulk copy to removable media, and a personal-cloud upload of the same data — every DLP control on the path in Audit mode.",
    }),
  ];

  // Chronological order is the contract (the integrity gate); the HR context sits three days earlier by design.
  events.sort((a, b) => Date.parse(a.ts) - Date.parse(b.ts));
  // Every event belongs to the insider's incident unless it was authored into the benign control's own.
  for (const e of events) e.incident_id = e.incident_id ?? INCIDENT;

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
      type: "domain",
      value: personalCloud,
      first_seen: T(47 * MIN + 40 * SEC),
      last_seen: T(63 * MIN),
      reputation: "suspicious",
      tags: ["personal-cloud", "unsanctioned", "upload-destination", "consumer-dropbox"],
    },
    {
      type: "ip",
      value: dropboxIp,
      first_seen: T(47 * MIN + 40 * SEC),
      last_seen: T(63 * MIN + 2 * SEC),
      reputation: "suspicious",
      tags: ["personal-cloud", "upload-destination"],
    },
    {
      type: "sha256",
      value: file1Hash,
      first_seen: T(32 * MIN),
      last_seen: T(32 * MIN),
      reputation: "unknown",
      tags: ["sensitivity-labeled", "client-data", "copied-to-usb"],
    },
    {
      type: "sha256",
      value: file2Hash,
      first_seen: T(32 * MIN + 28 * SEC),
      last_seen: T(32 * MIN + 28 * SEC),
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
        { value: "usb_and_cloud", label: "The file writes to USB volume D: + the HTTPS POSTs of the same files to www.dropbox.com" },
        { value: "staging_and_usb", label: "The robocopy into a local staging folder + the file write to the Kingston USB volume" },
        { value: "access_and_cloud", label: "The DLP bulk-access match on the file share + the DLP policy match on the Dropbox upload" },
        { value: "mount_and_correlation", label: "The Kingston USB mount event + the Sentinel incident that correlated the whole chain" },
      ],
      answer: "usb_and_cloud",
      xp: 40,
      explanation:
        "T1052.001 is exfiltration onto removable media — evidenced by evt_idt_06_usb_write and its sibling records, where explorer.exe writes the client files to drive D: (the Kingston volume). T1567.002 is exfiltration to a web service — evidenced by the Zscaler records (evt_idt_09_proxy and the two chunks before it), three allowed HTTPS POSTs to www.dropbox.com carrying about 613 MB in total, plus the msedge.exe session to 162.125.248.18. Those are the two channels. evt_idt_04_staging is T1074.001 (local staging): robocopy only consolidates the files into a folder on the same laptop, so nothing has left yet — it is a precursor, not a channel. evt_idt_03/evt_idt_08 are the DLP policy matches that describe the activity, and evt_idt_05/evt_idt_10 are the mount and the correlation; useful evidence, but not themselves the two egress events.",
    },
    {
      id: "q2",
      prompt:
        "Every DLP match in this incident — bulk access, USB copy, and cloud upload — shows RuleMode: Enforce and Actions: [Audit, NotifyUser], and yet the transfers all completed: the files are on the USB volume and the proxy records the POSTs as allowed. What does that tell you about NexaCorp's DLP posture, and how should it change your reading of the incident?",
      kind: "single",
      options: [
        { value: "audit_only_still_theft", label: "The policies matched correctly but are set to log and notify, not block — 'allowed' means 'not prevented', not 'approved', and the data still left" },
        { value: "allowed_means_authorized", label: "Allowed means the platform authorized the transfers as legitimate business activity, so the matches can be closed as expected behaviour" },
        { value: "policy_broken", label: "The DLP policies are misconfigured or disabled — a working policy would have blocked, so these events are noise from a broken control and should be ignored" },
        { value: "false_positives", label: "Three matches on the same user in one afternoon is a classifier tuning problem; the EU IBAN detections are false positives that inflate the incident" },
      ],
      answer: "audit_only_still_theft",
      xp: 50,
      explanation:
        "RuleMode is Enforce and the configured Actions are Audit and NotifyUser on every match — the policies are switched on and matched real labeled data (2,214 / 1,663 / 1,980 IBAN instances at 85% confidence), which rules out 'disabled' (c) and 'false positive' (d). But there is no BlockAccess or RestrictAccess anywhere in the Actions — so the enforced behaviour IS logging, not blocking. That is why the copy to D: and the Dropbox POSTs completed: the control observed the activity and permitted it by design. The trap is (b) — reading 'allowed' as 'authorized'. In audit-mode DLP, 'allowed' is the default outcome for everything, benign and malicious alike; it carries no verdict at all. The correct reading is that these three matches are high-quality evidence of data leaving, and the absence of a block is a gap in the control, not exoneration of the user.",
    },
    {
      id: "q3",
      prompt:
        "evt_idt_11_benign_control shows h.reyes moving 1.4 GB — a LARGER transfer than the insider's ~613 MB — the same afternoon, yet it is benign. Reading it against Daniel Okafor's activity, what actually separates exfiltration from legitimate bulk work here?",
      hint: "If raw volume decided it, the bigger transfer would be the worse one. It isn't. Compare destination, authorization, role, and the HR signal.",
      kind: "single",
      options: [
        { value: "destination_auth_context", label: "Destination and context: Reyes sends to a sanctioned corporate tenant under a change ticket, in a bulk-data role; Okafor sends client data to a personal cloud and USB, above baseline, while departing" },
        { value: "volume_decides", label: "Volume decides it — Reyes moved 1.4 GB against Okafor's ~613 MB, so by raw transfer size her upload is the objectively higher-risk one and should be escalated ahead of his" },
        { value: "dlp_fired_or_not", label: "Whether DLP fired — Okafor triggered Purview policy matches and Reyes's transfer did not, so the presence or absence of a DLP alert alone cleanly separates the two cases with no further context needed" },
        { value: "same_verdict", label: "Nothing meaningfully separates them — both are large transfers off the corporate network on the same afternoon by authenticated employees, so both should be logged and closed as ordinary benign business activity" },
      ],
      answer: "destination_auth_context",
      xp: 60,
      explanation:
        "This is the core skill the scenario trains: exfiltration is judged by destination, authorization and baseline — not by byte count. Reyes moves MORE data, but to nexacorp-my.sharepoint.com (a sanctioned corporate destination), under an actual change ticket (CHG-2026-0814, approved that morning), in a Data Engineer role whose remit is bulk migration, with no HR flag. Okafor moves Highly-Confidential CLIENT data to a personal Dropbox and a personal USB, at about 14 times his own 30-day file-access baseline (192 files against 14 a day), three days into a resignation with access-revocation already scheduled. Option (b) inverts the logic — 'bigger = worse' would clear the thief and flag the engineer. Option (c) over-trusts the DLP: audit-mode matches flag sensitive-data movement but don't by themselves prove intent; the exoneration of Reyes comes from her context, and the incrimination of Okafor comes from his — the destination, the authorization, the baseline and the departure, read together.",
    },
    {
      id: "q4",
      prompt:
        "You are writing the verdict. No control blocked anything, no malware ran, and every action was authenticated as Daniel Okafor's own valid account. How should this incident be classified and handled?",
      kind: "single",
      options: [
        { value: "malicious_insider_escalate", label: "Malicious insider theft — a departing employee took client data out by two channels, far off his baseline. Preserve evidence, escalate to HR/Legal, expedite revocation" },
        { value: "benign_all_allowed", label: "Benign — every action was allowed, performed under his own valid account and on data his role can access, so there is no policy violation to action or escalate" },
        { value: "low_priority_dlp_tuning", label: "Low priority — route it to the DLP engineering backlog as tuning feedback, since the policies should have blocked, and close the security ticket with no user action" },
        { value: "wait_for_malware", label: "Hold — without malware, a blocked action or a compromised credential there is no confirmed intrusion yet, so wait for a second signal before treating it as an incident" },
      ],
      answer: "malicious_insider_escalate",
      xp: 60,
      explanation:
        "Insider threats look exactly like this: authorized access, a valid account, no malware, nothing blocked. The evidence is nonetheless complete and dated inside one afternoon — bulk access at about 14 times baseline (T1039), a 34-file copy to a personal USB (T1052.001), and an upload of the same files to a personal Dropbox (T1567.002) — by a man whose resignation and access-revocation are already logged in Workday. Option (b) is the exact failure the scenario exists to prevent: equating 'allowed' with 'benign' in an audit-only DLP estate, where allowed is the outcome of everything. Option (c) buries a live data-theft in an engineering queue. Option (d) waits for a malware signal that will never come in a valid-account insider case. The correct handling is to classify it as malicious insider exfiltration, preserve the host and the USB serial (KINGSTON-DT-6F2A9C41) as evidence, loop in HR and Legal, and make sure the scheduled revocation actually happens — and to raise moving the DLP policies from Audit to Block so the next one is stopped, not just recorded.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "Sentinel incident for a finance analyst who resigned",
    threat_actor: "Malicious insider (departing employee, valid account — no external actor)",
    attack_kind: "insider_data_theft",
    briefing:
      "Microsoft Sentinel raised an insider-risk incident at 14:25 for d.okafor, a Senior Financial Analyst whose resignation is already in Workday. Establish what left the environment, by which routes, and whether this is theft or legitimate work.",
    narrative: `Daniel Okafor is a Senior Financial Analyst on NexaCorp's Client Accounts team. Three days before this window, he submitted his resignation; Workday shows a voluntary termination dated 2026-08-28, his last working Friday, with access-revocation already scheduled for that evening. He is inside his notice period, and everything he does over this Monday afternoon is authenticated as his own valid account — nothing is stolen or spoofed.

At 13:15 he logs on to LAPTOP-NX-FIN14 normally. By 13:20 he has connected to the Client Accounts file share and from 13:21 he is opening files far faster than usual — 192 in about eight minutes, against a 30-day baseline of roughly fourteen a day; the file server's own Security log shows the share connection and per-file reads. At 13:29 Microsoft Purview matches 2,214 instances of labeled client financial data being read; the rule is enforced, but its configured actions are Audit and NotifyUser, so it logs and notifies and blocks nothing. At 13:36 he opens a command prompt and at 13:37 robocopy mirrors the ClientRecords folder into a local staging folder under his profile.

At 13:46 a Kingston DataTraveler USB stick — serial KINGSTON-DT-6F2A9C41, volume labeled DOKAFOR-BACKUP — mounts as drive D:. Within two minutes, explorer.exe writes 34 client files to it, including Client_Master_Book_2026.xlsx and FY26_Client_Pricing_Model.xlsx; Defender for Endpoint records the writes, and Purview's removable-media policy matches them — again in Audit mode, again allowed. At 14:02 he starts Microsoft Edge on www.dropbox.com; at 14:03 Purview's cloud-egress policy matches the same files being uploaded through it to a consumer account on no sanctioned list (Audit, allowed), and Zscaler logs the HTTPS POST sessions that carry about 613 MB out over roughly fourteen minutes.

Not one control on this path said no. Sentinel finally correlates the departure, the above-baseline access, the USB copy and the personal-cloud upload into a single incident at 14:25. For contrast, the same afternoon a Data Engineer, Hannah Reyes, moved an even larger 1.4 GB — but to a sanctioned corporate tenant, under change ticket CHG-2026-0814, in role, with no departure flag. Same shape, opposite verdict. The lesson is that in an audit-only DLP estate 'allowed' is the outcome of everything, and the analyst has to reach 'theft' from the data's destination and the actor's context, not from any control that blocked it.`,
    learning_objectives: [
      "Recognise insider data theft where every action is allowed, performed under a valid account (T1078), with no malware and no blocked control, by correlating Workday, Purview DLP, Defender for Endpoint, Zscaler and Sentinel on one user and host",
      "Distinguish the two exfiltration channels — over USB (T1052.001) and to cloud storage (T1567.002) — from local staging (T1074.001), which never leaves the host",
      "Read Purview RuleMode and Actions fields to see that an enforced-but-audit-only policy logs rather than blocks, so a completed transfer carries no verdict",
      "Judge exfiltration by destination, authorization, baseline and HR/Workday context (a scheduled departure) rather than raw transfer volume — using the benign heavy-transfer control to calibrate",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: T(-3 * DAY), phase: "Context", action: "Workday records d.okafor's resignation — termination 2026-08-28, access revocation scheduled" },
      { ts: T(0), phase: "Valid Accounts", action: "Normal 4624 logon on LAPTOP-NX-FIN14 under his own account (T1078)" },
      { ts: T(5 * MIN + 50 * SEC), phase: "Collection", action: "Client-share connection and 192 files read vs ~14/day baseline (T1039)" },
      { ts: T(14 * MIN), phase: "Detection", action: "Purview matches 2,214 labeled client-data instances — Audit mode, allowed" },
      { ts: T(22 * MIN), phase: "Collection", action: "robocopy stages ClientRecords into a local folder on the laptop (T1074.001)" },
      { ts: T(31 * MIN), phase: "Exfiltration", action: `Kingston USB ${usbSerial} (volume ${usbVolume}) mounts as D: — device control in Audit mode` },
      { ts: T(32 * MIN), phase: "Exfiltration", action: "Defender for Endpoint records 34 client files written to the USB volume by explorer.exe (T1052.001)" },
      { ts: T(47 * MIN + 30 * SEC), phase: "Exfiltration", action: `Edge starts on ${personalCloud} and opens a session to ${dropboxIp}` },
      { ts: T(48 * MIN), phase: "Exfiltration", action: `Same 34 files uploaded via browser to ${personalCloud} — Purview match, Audit mode (T1567.002)` },
      { ts: T(63 * MIN + 2 * SEC), phase: "Exfiltration", action: `Zscaler has logged three allowed HTTPS POSTs to ${personalCloud} — 613 MB out over ~14 minutes` },
      { ts: T(70 * MIN), phase: "Detection", action: "Sentinel correlates departure + access + USB + cloud into one insider incident" },
    ],
    questions,
  };
}
