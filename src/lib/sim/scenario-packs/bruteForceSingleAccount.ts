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
 * NOTE: `difficulty: "beginner"` is declared on the SCENARIOS registry entry in
 * scenarios.ts (ScenarioBundle itself carries no difficulty field).
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";

export function buildBruteForceSingleAccountScenario(
  scenarioId = "brute-force-single-account-2026",
): ScenarioBundle {
  const B = new Date("2026-06-04T09:00:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  // The internet-published Remote Desktop server and the file server behind it.
  const rds = { hostname: "SRV-RDS-02", fqdn: "SRV-RDS-02.nexacorp.com", ip: "10.30.9.20", nat: "198.51.100.27" };
  const fileServer = { hostname: "FS-CORP-02", fqdn: "FS-CORP-02.nexacorp.com", ip: "10.30.9.55" };

  // The single targeted account. Accounts Payable clerk — no HR entitlement.
  const victim = { sam: "s.wolfe", email: "s.wolfe@nexacorp.com" };
  const victimSid = "S-1-5-21-3421479547-3897544621-1789562108-4419";

  // The attacker's first guess at the username format — this account never existed.
  const wrongFormat = "swolfe";

  const attackerIp = "91.108.23.146";

  // Signed Microsoft binary — the tool is ordinary, the context is not.
  const netExeHash = makeSha256("windows_system32_net_exe_signed_microsoft");

  const events: TelemetryEvent[] = [
    // ---------------------------------------------------------------------
    // 1. First contact — inbound RDP from the internet, allowed by policy.
    // ---------------------------------------------------------------------
    {
      id: "evt_bf_01_fw_inbound",
      ts: T(0),
      source: "firewall",
      vendor: "Palo Alto Networks PAN-OS",
      event_type: "net_connection",
      hostname: rds.hostname,
      src_ip: attackerIp,
      dst_ip: rds.ip,
      dst_port: 3389,
      protocol: "tcp",
      severity: "medium",
      mitre_technique: "T1133",
      mitre_tactic: "TA0001",
      geo: { country: "Russia", city: "Moscow", latitude: 55.75, longitude: 37.62 },
      description:
        "An address in Russia opened an inbound TCP/3389 session to the published Remote Desktop server SRV-RDS-02. The perimeter rule permits RDP from anywhere, so the connection was allowed — allowed here means matched a rule, not vetted.",
      network: { bytes_out: 9840, bytes_in: 26112 },
      raw: {
        "pan.type": "TRAFFIC",
        "pan.subtype": "end",
        "pan.action": "allow",
        "pan.rule": "INBOUND-RDP-PUBLISHED",
        "pan.src": attackerIp,
        "pan.dst": rds.nat,
        "pan.natdst": rds.ip,
        "pan.sport": "49712",
        "pan.dport": "3389",
        "pan.proto": "tcp",
        "pan.app": "ms-rdp",
        "pan.from_zone": "UNTRUST",
        "pan.to_zone": "DMZ",
        "pan.session_id": "612440",
        "pan.bytes_sent": "9840",
        "pan.bytes_received": "26112",
        "pan.packets": "184",
        "pan.srcloc": "RU",
        "pan.dstloc": "IL",
        "source.ip": attackerIp,
        "destination.ip": rds.ip,
        "destination.port": "3389",
        "action_result": "allow",
      },
    },

    // ---------------------------------------------------------------------
    // 2. First failure — the username itself is wrong (0xC0000064).
    // ---------------------------------------------------------------------
    {
      id: "evt_bf_02_fail_wrong_user",
      ts: T(2 * MIN),
      source: "windows_security",
      vendor: "Windows Security",
      event_type: "auth_failure",
      hostname: rds.hostname,
      src_ip: attackerIp,
      severity: "low",
      mitre_technique: "T1110.001",
      mitre_tactic: "TA0006",
      geo: { country: "Russia", city: "Moscow" },
      description:
        "The first logon failure on SRV-RDS-02 was for the account name swolfe. Read TargetUserName and SubStatus together on this record, then compare both fields against the failures that follow a minute later — the two codes do not mean the same thing.",
      authentication: { method: "NTLM", result: "failure", logon_type: 3 },
      raw: {
        // Windows Security Event 4625 — An account failed to log on
        "winlog.event_id": "4625",
        "winlog.channel": "Security",
        "winlog.computer_name": rds.fqdn,
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "3310442",
        "winlog.event_data.SubjectUserSid": "S-1-0-0",
        "winlog.event_data.SubjectUserName": "-",
        "winlog.event_data.SubjectDomainName": "-",
        "winlog.event_data.SubjectLogonId": "0x0",
        "winlog.event_data.TargetUserSid": "S-1-0-0",
        "winlog.event_data.TargetUserName": wrongFormat,
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.LogonType": "3",
        "winlog.event_data.Status": "0xC000006D",
        "winlog.event_data.SubStatus": "0xC0000064",
        "winlog.event_data.FailureReason": "%%2313",
        "winlog.event_data.LogonProcessName": "NtLmSsp ",
        "winlog.event_data.AuthenticationPackageName": "NTLM",
        "winlog.event_data.WorkstationName": "WORKSTATION",
        "winlog.event_data.IpAddress": attackerIp,
        "winlog.event_data.IpPort": "49712",
        "winlog.event_data.ProcessName": "-",
        "event.code": "4625",
        "event.action": "logon-failed",
        "event.outcome": "failure",
        "source.ip": attackerIp,
        "user.name": wrongFormat,
        "user.domain": "NEXACORP",
      },
    },

    // ---------------------------------------------------------------------
    // 3. The burst proper — correct account name, wrong password (0xC000006A).
    // ---------------------------------------------------------------------
    {
      id: "evt_bf_03_fail_burst",
      ts: T(3 * MIN),
      source: "windows_security",
      vendor: "Windows Security",
      event_type: "auth_failure",
      hostname: rds.hostname,
      user_email: victim.email,
      src_ip: attackerIp,
      severity: "medium",
      mitre_technique: "T1110.001",
      mitre_tactic: "TA0006",
      geo: { country: "Russia", city: "Moscow" },
      description:
        "One minute later the failures switch to the account name s.wolfe and the SubStatus code changes. This is a representative record from the burst — 214 failures for this one account were written between 09:02 and 09:20, every one of them from the same address, and no other account was attempted.",
      authentication: { method: "NTLM", result: "failure", logon_type: 3 },
      raw: {
        "winlog.event_id": "4625",
        "winlog.channel": "Security",
        "winlog.computer_name": rds.fqdn,
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "3310519",
        "winlog.event_data.SubjectUserSid": "S-1-0-0",
        "winlog.event_data.SubjectUserName": "-",
        "winlog.event_data.SubjectDomainName": "-",
        "winlog.event_data.SubjectLogonId": "0x0",
        "winlog.event_data.TargetUserSid": "S-1-0-0",
        "winlog.event_data.TargetUserName": victim.sam,
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.LogonType": "3",
        "winlog.event_data.Status": "0xC000006D",
        "winlog.event_data.SubStatus": "0xC000006A",
        "winlog.event_data.FailureReason": "%%2313",
        "winlog.event_data.LogonProcessName": "NtLmSsp ",
        "winlog.event_data.AuthenticationPackageName": "NTLM",
        "winlog.event_data.WorkstationName": "WORKSTATION",
        "winlog.event_data.IpAddress": attackerIp,
        "winlog.event_data.IpPort": "49883",
        "winlog.event_data.ProcessName": "-",
        "event.code": "4625",
        "event.action": "logon-failed",
        "event.outcome": "failure",
        "source.ip": attackerIp,
        "user.name": victim.sam,
        "user.domain": "NEXACORP",
      },
    },

    // ---------------------------------------------------------------------
    // 4. Last failure of the burst — 40 seconds before the ticket's answer.
    // ---------------------------------------------------------------------
    {
      id: "evt_bf_04_fail_last",
      ts: T(19 * MIN + 20_000),
      source: "windows_security",
      vendor: "Windows Security",
      event_type: "auth_failure",
      hostname: rds.hostname,
      user_email: victim.email,
      src_ip: attackerIp,
      severity: "medium",
      mitre_technique: "T1110.001",
      mitre_tactic: "TA0006",
      geo: { country: "Russia", city: "Moscow" },
      description:
        "The final 4625 in the burst, written at 09:19:20 for s.wolfe from the same address. The account was never locked out: the lockout policy on this domain does not apply to the group s.wolfe belongs to, so the attempts were free to continue.",
      authentication: { method: "NTLM", result: "failure", logon_type: 3 },
      raw: {
        "winlog.event_id": "4625",
        "winlog.channel": "Security",
        "winlog.computer_name": rds.fqdn,
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "3312088",
        "winlog.event_data.SubjectUserSid": "S-1-0-0",
        "winlog.event_data.SubjectUserName": "-",
        "winlog.event_data.SubjectDomainName": "-",
        "winlog.event_data.SubjectLogonId": "0x0",
        "winlog.event_data.TargetUserSid": "S-1-0-0",
        "winlog.event_data.TargetUserName": victim.sam,
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.LogonType": "3",
        "winlog.event_data.Status": "0xC000006D",
        "winlog.event_data.SubStatus": "0xC000006A",
        "winlog.event_data.FailureReason": "%%2313",
        "winlog.event_data.LogonProcessName": "NtLmSsp ",
        "winlog.event_data.AuthenticationPackageName": "NTLM",
        "winlog.event_data.WorkstationName": "WORKSTATION",
        "winlog.event_data.IpAddress": attackerIp,
        "winlog.event_data.IpPort": "51204",
        "winlog.event_data.ProcessName": "-",
        "event.code": "4625",
        "event.action": "logon-failed",
        "event.outcome": "failure",
        "source.ip": attackerIp,
        "user.name": victim.sam,
        "user.domain": "NEXACORP",
      },
    },

    // ---------------------------------------------------------------------
    // 5. THE EVENT THAT MATTERS — 4624 success, same account, same address.
    //    Looks identical to any ordinary network logon.
    // ---------------------------------------------------------------------
    {
      id: "evt_bf_05_auth_success",
      ts: T(20 * MIN),
      source: "windows_security",
      vendor: "Windows Security",
      event_type: "auth_success",
      hostname: rds.hostname,
      user_email: victim.email,
      src_ip: attackerIp,
      severity: "high",
      mitre_technique: "T1078",
      mitre_tactic: "TA0001",
      geo: { country: "Russia", city: "Moscow" },
      description:
        "A successful 4624 network logon for s.wolfe on SRV-RDS-02 at 09:20:00. Compare every field of this record against the 4625 records that precede it — the account, the server, the source address and the source port range are all the same, only the event ID and the outcome differ.",
      authentication: { method: "NTLM", result: "success", logon_type: 3 },
      raw: {
        // Windows Security Event 4624 — An account was successfully logged on
        "winlog.event_id": "4624",
        "winlog.channel": "Security",
        "winlog.computer_name": rds.fqdn,
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "3312194",
        "winlog.event_data.SubjectUserSid": "S-1-0-0",
        "winlog.event_data.SubjectUserName": "-",
        "winlog.event_data.SubjectDomainName": "-",
        "winlog.event_data.SubjectLogonId": "0x0",
        "winlog.event_data.TargetUserSid": victimSid,
        "winlog.event_data.TargetUserName": victim.sam,
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.TargetLogonId": "0x2F91A44",
        "winlog.event_data.LogonType": "3",
        "winlog.event_data.LogonProcessName": "NtLmSsp ",
        "winlog.event_data.AuthenticationPackageName": "NTLM",
        "winlog.event_data.WorkstationName": "WORKSTATION",
        "winlog.event_data.LogonGuid": "{00000000-0000-0000-0000-000000000000}",
        "winlog.event_data.IpAddress": attackerIp,
        "winlog.event_data.IpPort": "51377",
        "winlog.event_data.ImpersonationLevel": "%%1833",
        "winlog.event_data.ElevatedToken": "%%1843",
        "winlog.event_data.ProcessName": "-",
        "event.code": "4624",
        "event.action": "logged-in",
        "event.outcome": "success",
        "source.ip": attackerIp,
        "user.name": victim.sam,
        "user.domain": "NEXACORP",
      },
    },

    // ---------------------------------------------------------------------
    // 6. The interactive desktop that the network logon unlocked (LogonType 10).
    // ---------------------------------------------------------------------
    {
      id: "evt_bf_06_rdp_session",
      ts: T(20 * MIN + 8_000),
      source: "windows_security",
      vendor: "Windows Security",
      event_type: "auth_success",
      hostname: rds.hostname,
      user_email: victim.email,
      src_ip: attackerIp,
      severity: "high",
      mitre_technique: "T1021.001",
      mitre_tactic: "TA0008",
      geo: { country: "Russia", city: "Moscow" },
      description:
        "Eight seconds after the network logon, a second 4624 on SRV-RDS-02 records LogonType 10 — RemoteInteractive. A desktop session is now open for s.wolfe, driven from the same address, with a full user profile loaded.",
      authentication: { method: "Negotiate", result: "success", logon_type: 10 },
      raw: {
        "winlog.event_id": "4624",
        "winlog.channel": "Security",
        "winlog.computer_name": rds.fqdn,
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "3312203",
        "winlog.event_data.SubjectUserSid": "S-1-5-18",
        "winlog.event_data.SubjectUserName": "SRV-RDS-02$",
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.SubjectLogonId": "0x3E7",
        "winlog.event_data.TargetUserSid": victimSid,
        "winlog.event_data.TargetUserName": victim.sam,
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.TargetLogonId": "0x2F92B71",
        "winlog.event_data.LogonType": "10",
        "winlog.event_data.LogonProcessName": "User32 ",
        "winlog.event_data.AuthenticationPackageName": "Negotiate",
        "winlog.event_data.WorkstationName": rds.hostname,
        "winlog.event_data.IpAddress": attackerIp,
        "winlog.event_data.IpPort": "51377",
        "winlog.event_data.ElevatedToken": "%%1843",
        "winlog.event_data.ProcessName": "C:\\Windows\\System32\\svchost.exe",
        "event.code": "4624",
        "event.action": "logged-in",
        "event.outcome": "success",
        "source.ip": attackerIp,
        "user.name": victim.sam,
        "user.domain": "NEXACORP",
      },
    },

    // ---------------------------------------------------------------------
    // 7. Ordinary-looking command, wrong share for this account.
    // ---------------------------------------------------------------------
    {
      id: "evt_bf_07_net_use",
      ts: T(22 * MIN),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: rds.hostname,
      user_email: victim.email,
      src_ip: rds.ip,
      severity: "medium",
      mitre_technique: "T1021.002",
      mitre_tactic: "TA0008",
      description:
        "Inside the new desktop session, cmd.exe spawned net.exe to map a drive letter to a share on FS-CORP-02. The binary is the signed Microsoft one and the command is something a helpdesk technician types every day — what matters is which share was chosen.",
      process: {
        name: "net.exe",
        pid: 6248,
        path: "C:\\Windows\\System32\\net.exe",
        parent_name: "cmd.exe",
        parent_pid: 6112,
        cmdline: "net use Z: \\\\FS-CORP-02\\HR-Confidential",
        user: "NEXACORP\\s.wolfe",
        integrity: "medium",
        hash: { sha256: netExeHash },
      },
      raw: {
        "crowdstrike.event_simplename": "ProcessRollup2",
        "crowdstrike.detection.tactic": "Lateral Movement",
        "crowdstrike.detection.tactic_id": "TA0008",
        "crowdstrike.detection.technique": "Remote Services: SMB/Windows Admin Shares",
        "crowdstrike.detection.technique_id": "T1021.002",
        "crowdstrike.detection.severity": "Medium",
        "crowdstrike.detection.pattern_disposition": "10",
        "crowdstrike.detection.pattern_disposition_description": "Detection, No Action",
        "crowdstrike.sensor.id": "a7c1f0e93b2d4a86b5c0d1e2f3a4b5c6",
        "crowdstrike.network_containment_state": "Not Contained",
        "event.action": "process_created",
        "event.code": "1",
        "process.name": "net.exe",
        "process.pid": "6248",
        "process.executable": "C:\\Windows\\System32\\net.exe",
        "process.command_line": "net use Z: \\\\FS-CORP-02\\HR-Confidential",
        "process.hash.sha256": netExeHash,
        "process.signed": "true",
        "process.parent.name": "cmd.exe",
        "process.parent.pid": "6112",
        "user.name": "NEXACORP\\s.wolfe",
        "user.logon_id": "0x2F92B71",
        "host.name": rds.hostname,
        "host.ip": rds.ip,
      },
    },

    // ---------------------------------------------------------------------
    // 8. The share connection as the file server recorded it (5140).
    // ---------------------------------------------------------------------
    {
      id: "evt_bf_08_share_access",
      ts: T(22 * MIN + 20_000),
      source: "windows_security",
      vendor: "Windows Security",
      event_type: "file_access",
      hostname: fileServer.hostname,
      user_email: victim.email,
      src_ip: rds.ip,
      severity: "medium",
      description:
        "FS-CORP-02 recorded the share connection from its own side. Note the IpAddress on this record: the file server sees the Remote Desktop server's internal address, not the external address, because the session is being driven from inside that desktop.",
      raw: {
        // Windows Security Event 5140 — A network share object was accessed
        "winlog.event_id": "5140",
        "winlog.channel": "Security",
        "winlog.computer_name": fileServer.fqdn,
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "8874120",
        "winlog.event_data.SubjectUserSid": victimSid,
        "winlog.event_data.SubjectUserName": victim.sam,
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.SubjectLogonId": "0x74C2E19",
        "winlog.event_data.ObjectType": "File",
        "winlog.event_data.IpAddress": rds.ip,
        "winlog.event_data.IpPort": "50219",
        "winlog.event_data.ShareName": "\\\\*\\HR-Confidential",
        "winlog.event_data.ShareLocalPath": "\\??\\E:\\Shares\\HR-Confidential",
        "winlog.event_data.AccessMask": "0x1",
        "winlog.event_data.AccessList": "%%4416",
        "event.code": "5140",
        "event.action": "share-accessed",
        "event.outcome": "success",
        "source.ip": rds.ip,
        "user.name": victim.sam,
        "user.domain": "NEXACORP",
      },
    },

    // ---------------------------------------------------------------------
    // 9. A file is actually read off the share.
    // ---------------------------------------------------------------------
    {
      id: "evt_bf_09_file_read",
      ts: T(23 * MIN),
      source: "windows_security",
      vendor: "Windows Security",
      event_type: "file_access",
      hostname: fileServer.hostname,
      user_email: victim.email,
      src_ip: rds.ip,
      severity: "high",
      mitre_technique: "T1039",
      mitre_tactic: "TA0009",
      description:
        "An object-access record from FS-CORP-02 showing a payroll workbook on the HR-Confidential share being opened with read access under the s.wolfe logon session.",
      file: {
        path: "E:\\Shares\\HR-Confidential\\Payroll\\2026\\salary_bands_2026.xlsx",
        name: "salary_bands_2026.xlsx",
        extension: "xlsx",
        size: 842_240,
      },
      raw: {
        // Windows Security Event 4663 — An attempt was made to access an object
        "winlog.event_id": "4663",
        "winlog.channel": "Security",
        "winlog.computer_name": fileServer.fqdn,
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "8874233",
        "winlog.event_data.SubjectUserSid": victimSid,
        "winlog.event_data.SubjectUserName": victim.sam,
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.SubjectLogonId": "0x74C2E19",
        "winlog.event_data.ObjectServer": "Security",
        "winlog.event_data.ObjectType": "File",
        "winlog.event_data.ObjectName":
          "E:\\Shares\\HR-Confidential\\Payroll\\2026\\salary_bands_2026.xlsx",
        "winlog.event_data.HandleId": "0x1a2c",
        "winlog.event_data.AccessMask": "0x1",
        "winlog.event_data.AccessList": "%%4416",
        "winlog.event_data.ProcessId": "0x4",
        "winlog.event_data.ProcessName": "System",
        "event.code": "4663",
        "event.action": "file-accessed",
        "event.outcome": "success",
        "source.ip": rds.ip,
        "user.name": victim.sam,
        "user.domain": "NEXACORP",
      },
    },

    // ---------------------------------------------------------------------
    // 10. The correlation that opened the ticket, plus the account's context.
    // ---------------------------------------------------------------------
    {
      id: "evt_bf_10_siem_context",
      ts: T(26 * MIN),
      source: "siem",
      vendor: "Microsoft Sentinel",
      event_type: "ueba_anomaly",
      hostname: rds.hostname,
      user_email: victim.email,
      src_ip: attackerIp,
      severity: "high",
      description:
        "Sentinel raised the alert and attached the account's directory context: which department s.wolfe sits in, which shares this account had connected to over the previous ninety days, and which single external address every authentication in the window came from.",
      raw: {
        "siem.rule_name": "ExternalAuthenticationBurst_SingleAccount",
        "siem.rule_id": "SEN-IDENT-0117",
        "siem.window_start": T(2 * MIN),
        "siem.window_end": T(20 * MIN),
        "siem.account": "NEXACORP\\s.wolfe",
        "siem.account_display_name": "Sara Wolfe",
        "siem.account_department": "Accounts Payable",
        "siem.account_title": "Accounts Payable Clerk",
        "siem.account_group_memberships": ["Domain Users", "AP-Clerks", "Finance-Readers"],
        "siem.shares_connected_prior_90d": [
          "\\\\FS-CORP-02\\AP-Invoices",
          "\\\\FS-CORP-02\\Scans",
          "\\\\FS-CORP-02\\Finance-Reports",
        ],
        "siem.source_addresses_in_window": [attackerIp],
        "siem.targeted_host": rds.hostname,
        "siem.lockout_policy_applied": "false",
        "event.action": "correlation-alert",
        "event.outcome": "alerted",
      },
    },
  ];

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
      reputation: "suspicious",
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
