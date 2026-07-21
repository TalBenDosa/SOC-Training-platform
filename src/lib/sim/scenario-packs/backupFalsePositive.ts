/**
 * Scenario pack: "Mass File Encryption Alert — Enterprise Backup Agent"
 *
 * A FALSE POSITIVE. An EDR ransomware-behaviour heuristic fires CRITICAL on a
 * scheduled enterprise backup job that has just been moved to a full-backup
 * schedule by an approved change. Everything the heuristic keyed on is real:
 * a service account walking thousands of files at machine speed, VSS activity,
 * and large files with an unfamiliar extension appearing fast.
 *
 * The discriminating evidence is present and findable in the telemetry — it is
 * never stated as a conclusion. The student has to go and read it.
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";

export function buildBackupFalsePositiveScenario(
  scenarioId = "backup-agent-false-positive-2026",
): ScenarioBundle {
  const B = new Date("2026-03-16T14:20:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const HOUR = 3_600_000;

  // Backup window opens 11h40m after the change ticket is approved → 02:00Z next day.
  const W = 11 * HOUR + 40 * MIN;

  const fileServer = { hostname: "FS-PROD-04", ip: "10.20.14.31" };
  const repo = { hostname: "BKP-REPO-01", ip: "10.20.14.60" };
  const svcAccount = { name: "svc_bkp_agent", email: "svc_bkp_agent@nexacorp.com" };
  const svcSid = "S-1-5-21-3421479547-3897544621-1789562108-1147";

  // Genuine, signed vendor binary. One hash = one file.
  const agentHash = makeSha256("veeam_agent_exe_signed_vendor_binary_v12");
  const vssadminHash = makeSha256("windows_system32_vssadmin_exe_signed_microsoft");

  // Unattributed external endpoint the agent talks to during the window.
  const vendorEndpointIp = "104.18.27.94";

  const jobGuid = "{7F2A9C41-3E8B-4D16-9A05-C2B77E4D8813}";
  const changeTicket = "CHG0041887";

  const events: TelemetryEvent[] = [
    // ---------------------------------------------------------------------
    // 1. The change that explains the new schedule (the day before).
    // ---------------------------------------------------------------------
    {
      id: "evt_bkpfp_01_change",
      ts: T(0),
      source: "soar",
      vendor: "ServiceNow ITSM",
      event_type: "policy_modification",
      severity: "informational",
      description:
        "Change CHG0041887 records the FS-PROD-04 backup job moving from a nightly incremental at 23:00 to a weekly full backup at 02:00, writing to BKP-REPO-01.",
      raw: {
        "servicenow.table": "change_request",
        "servicenow.number": changeTicket,
        "servicenow.short_description": "Backup policy change — FS-PROD-04 weekly full at 02:00",
        "servicenow.state": "Scheduled",
        "servicenow.approval": "Approved",
        "servicenow.type": "Normal",
        "servicenow.risk": "Moderate",
        "servicenow.assignment_group": "Infrastructure Operations",
        "servicenow.requested_by": "r.mizrahi@nexacorp.com",
        "servicenow.approved_by": "CAB — Infrastructure",
        "servicenow.cmdb_ci": "FS-PROD-04",
        "servicenow.start_date": "2026-03-17 02:00:00",
        "servicenow.end_date": "2026-03-17 05:00:00",
        "servicenow.sys_updated_on": "2026-03-16 14:20:00",
      },
    },

    // ---------------------------------------------------------------------
    // 2. Service logon for the backup account — LogonType 5 (service).
    // ---------------------------------------------------------------------
    {
      id: "evt_bkpfp_02_svc_logon",
      ts: T(W),
      source: "windows_security",
      vendor: "Windows Security",
      event_type: "auth_success",
      hostname: fileServer.hostname,
      user_email: svcAccount.email,
      severity: "informational",
      description:
        "NEXACORP\\svc_bkp_agent logged on to FS-PROD-04 with LogonType 5, issued by services.exe under the local system account (Event 4624).",
      authentication: { method: "Negotiate", result: "success", logon_type: 5 },
      raw: {
        // Windows Security Event 4624 — Successful Logon
        "winlog.event_id": "4624",
        "winlog.channel": "Security",
        "winlog.computer_name": "FS-PROD-04.nexacorp.com",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "9174432",
        "winlog.event_data.SubjectUserSid": "S-1-5-18",
        "winlog.event_data.SubjectUserName": "FS-PROD-04$",
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.SubjectLogonId": "0x3E7",
        "winlog.event_data.TargetUserSid": svcSid,
        "winlog.event_data.TargetUserName": svcAccount.name,
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.TargetLogonId": "0x1C4A9E3",
        "winlog.event_data.LogonType": "5",
        "winlog.event_data.LogonProcessName": "Advapi",
        "winlog.event_data.AuthenticationPackageName": "Negotiate",
        "winlog.event_data.WorkstationName": "-",
        "winlog.event_data.IpAddress": "-",
        "winlog.event_data.IpPort": "-",
        "winlog.event_data.ProcessId": "0x1F4",
        "winlog.event_data.ProcessName": "C:\\Windows\\System32\\services.exe",
        "winlog.event_data.ElevatedToken": "%%1842",
      },
    },

    // ---------------------------------------------------------------------
    // 3. AMBIGUOUS #1 — the account holds very heavy file-system privileges.
    // ---------------------------------------------------------------------
    {
      id: "evt_bkpfp_03_privileges",
      ts: T(W + 2_000),
      source: "windows_security",
      vendor: "Windows Security",
      event_type: "privileged_operation",
      hostname: fileServer.hostname,
      user_email: svcAccount.email,
      severity: "medium",
      description:
        "The svc_bkp_agent logon session on FS-PROD-04 was assigned SeBackupPrivilege, SeRestorePrivilege, SeSecurityPrivilege and SeTakeOwnershipPrivilege (Event 4672).",
      raw: {
        // Windows Security Event 4672 — Special Privileges Assigned to New Logon
        "winlog.event_id": "4672",
        "winlog.channel": "Security",
        "winlog.computer_name": "FS-PROD-04.nexacorp.com",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "9174433",
        "winlog.event_data.SubjectUserSid": svcSid,
        "winlog.event_data.SubjectUserName": svcAccount.name,
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.SubjectLogonId": "0x1C4A9E3",
        "winlog.event_data.PrivilegeList":
          "SeBackupPrivilege\n\t\t\tSeRestorePrivilege\n\t\t\tSeSecurityPrivilege\n\t\t\tSeTakeOwnershipPrivilege\n\t\t\tSeChangeNotifyPrivilege",
      },
    },

    // ---------------------------------------------------------------------
    // 4. The agent process itself — signed, real install path, SCM parent.
    // ---------------------------------------------------------------------
    {
      id: "evt_bkpfp_04_agent_start",
      ts: T(W + 5_000),
      source: "edr",
      vendor: "Microsoft Defender for Endpoint",
      event_type: "process_create",
      hostname: fileServer.hostname,
      user_email: svcAccount.email,
      src_ip: fileServer.ip,
      severity: "low",
      description:
        "VeeamAgent.exe started on FS-PROD-04 as svc_bkp_agent with services.exe as its parent, carrying a backup job GUID and /mode:full on the command line.",
      process: {
        name: "VeeamAgent.exe",
        pid: 5284,
        path: "C:\\Program Files\\Veeam\\Backup and Replication\\Backup\\VeeamAgent.exe",
        parent_name: "services.exe",
        parent_pid: 500,
        cmdline: `"C:\\Program Files\\Veeam\\Backup and Replication\\Backup\\VeeamAgent.exe" /job:${jobGuid} /mode:full /target:\\\\BKP-REPO-01\\repo01`,
        user: "NEXACORP\\svc_bkp_agent",
        integrity: "system",
        hash: { sha256: agentHash },
      },
      raw: {
        Timestamp: T(W + 5_000),
        ActionType: "ProcessCreated",
        DeviceName: fileServer.hostname,
        FileName: "VeeamAgent.exe",
        FolderPath: "C:\\Program Files\\Veeam\\Backup and Replication\\Backup\\VeeamAgent.exe",
        SHA256: agentHash,
        ProcessId: "5284",
        ProcessCommandLine: `"C:\\Program Files\\Veeam\\Backup and Replication\\Backup\\VeeamAgent.exe" /job:${jobGuid} /mode:full /target:\\\\BKP-REPO-01\\repo01`,
        ProcessIntegrityLevel: "System",
        ProcessTokenElevation: "TokenElevationTypeDefault",
        AccountDomain: "nexacorp",
        AccountName: svcAccount.name,
        LogonId: "0x1C4A9E3",
        InitiatingProcessFileName: "services.exe",
        InitiatingProcessId: "500",
        InitiatingProcessFolderPath: "C:\\Windows\\System32\\services.exe",
        InitiatingProcessAccountName: "system",
        // DeviceFileCertificateInfo for the image
        IsSigned: true,
        IsTrusted: true,
        SignatureStatus: "Valid",
        Signer: "Veeam Software Group GmbH",
        Issuer: "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1",
        CertificateCreationTime: "2025-08-04T00:00:00Z",
        CertificateExpirationTime: "2027-08-06T23:59:59Z",
        ReportId: "4417102",
      },
    },

    // ---------------------------------------------------------------------
    // 5. VSS — a snapshot is CREATED (the inverse of ransomware behaviour).
    // ---------------------------------------------------------------------
    {
      id: "evt_bkpfp_05_vss",
      ts: T(W + 25_000),
      source: "edr",
      vendor: "Microsoft Defender for Endpoint",
      event_type: "process_create",
      hostname: fileServer.hostname,
      user_email: svcAccount.email,
      severity: "medium",
      description:
        "VeeamAgent.exe spawned vssadmin.exe on FS-PROD-04, running as svc_bkp_agent at System integrity twenty seconds after the agent started.",
      process: {
        name: "vssadmin.exe",
        pid: 5311,
        path: "C:\\Windows\\System32\\vssadmin.exe",
        parent_name: "VeeamAgent.exe",
        parent_pid: 5284,
        cmdline: "vssadmin.exe create shadow /for=D:",
        user: "NEXACORP\\svc_bkp_agent",
        integrity: "system",
        hash: { sha256: vssadminHash },
      },
      raw: {
        Timestamp: T(W + 25_000),
        ActionType: "ProcessCreated",
        DeviceName: fileServer.hostname,
        FileName: "vssadmin.exe",
        FolderPath: "C:\\Windows\\System32\\vssadmin.exe",
        SHA256: vssadminHash,
        ProcessId: "5311",
        ProcessCommandLine: "vssadmin.exe create shadow /for=D:",
        ProcessIntegrityLevel: "System",
        AccountDomain: "nexacorp",
        AccountName: svcAccount.name,
        InitiatingProcessFileName: "VeeamAgent.exe",
        InitiatingProcessId: "5284",
        InitiatingProcessFolderPath:
          "C:\\Program Files\\Veeam\\Backup and Replication\\Backup\\VeeamAgent.exe",
        InitiatingProcessAccountName: svcAccount.name,
        IsSigned: true,
        SignatureStatus: "Valid",
        Signer: "Microsoft Windows",
        ReportId: "4417118",
      },
    },

    // ---------------------------------------------------------------------
    // 6. A representative file-read record (4663, ReadData only).
    // ---------------------------------------------------------------------
    {
      id: "evt_bkpfp_06_file_read",
      ts: T(W + MIN),
      source: "windows_security",
      vendor: "Windows Security",
      event_type: "file_access",
      hostname: fileServer.hostname,
      user_email: svcAccount.email,
      severity: "low",
      description:
        "Representative 4663 object-access record from FS-PROD-04: VeeamAgent.exe accessed D:\\Finance\\FY2026\\Q1\\AR_aging_2026-02.xlsx under the svc_bkp_agent session.",
      file: {
        path: "D:\\Finance\\FY2026\\Q1\\AR_aging_2026-02.xlsx",
        name: "AR_aging_2026-02.xlsx",
        extension: "xlsx",
        size: 1_184_768,
      },
      raw: {
        // Windows Security Event 4663 — An attempt was made to access an object
        "winlog.event_id": "4663",
        "winlog.channel": "Security",
        "winlog.computer_name": "FS-PROD-04.nexacorp.com",
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "9174902",
        "winlog.event_data.SubjectUserSid": svcSid,
        "winlog.event_data.SubjectUserName": svcAccount.name,
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.SubjectLogonId": "0x1C4A9E3",
        "winlog.event_data.ObjectServer": "Security",
        "winlog.event_data.ObjectType": "File",
        "winlog.event_data.ObjectName": "D:\\Finance\\FY2026\\Q1\\AR_aging_2026-02.xlsx",
        "winlog.event_data.HandleId": "0x9d4c",
        "winlog.event_data.AccessMask": "0x1",
        "winlog.event_data.AccessList": "%%4416",
        "winlog.event_data.ProcessId": "0x14A4",
        "winlog.event_data.ProcessName":
          "C:\\Program Files\\Veeam\\Backup and Replication\\Backup\\VeeamAgent.exe",
      },
    },

    // ---------------------------------------------------------------------
    // 7. Large file with an unfamiliar extension — on a dedicated target.
    // ---------------------------------------------------------------------
    {
      id: "evt_bkpfp_07_vbk_write",
      ts: T(W + 4 * MIN),
      source: "edr",
      vendor: "Microsoft Defender for Endpoint",
      event_type: "file_create",
      hostname: fileServer.hostname,
      user_email: svcAccount.email,
      severity: "high",
      description:
        "A 26 GB file named FS-PROD-04_2026-03-17T020000_FULL.vbk was created by VeeamAgent.exe on the share \\\\BKP-REPO-01\\repo01.",
      file: {
        path: "\\\\BKP-REPO-01\\repo01\\FS-PROD-04\\FS-PROD-04_2026-03-17T020000_FULL.vbk",
        name: "FS-PROD-04_2026-03-17T020000_FULL.vbk",
        extension: "vbk",
        size: 26_548_912_128,
      },
      raw: {
        Timestamp: T(W + 4 * MIN),
        ActionType: "FileCreated",
        DeviceName: fileServer.hostname,
        FileName: "FS-PROD-04_2026-03-17T020000_FULL.vbk",
        FolderPath: "\\\\BKP-REPO-01\\repo01\\FS-PROD-04\\",
        FileSize: 26_548_912_128,
        ShareName: "repo01",
        RequestAccountName: svcAccount.name,
        RequestAccountDomain: "nexacorp",
        InitiatingProcessFileName: "VeeamAgent.exe",
        InitiatingProcessId: "5284",
        InitiatingProcessFolderPath:
          "C:\\Program Files\\Veeam\\Backup and Replication\\Backup\\VeeamAgent.exe",
        InitiatingProcessAccountName: svcAccount.name,
        ReportId: "4418044",
      },
    },

    // ---------------------------------------------------------------------
    // 8. AMBIGUOUS #2 — outbound TLS to an unattributed external address.
    // ---------------------------------------------------------------------
    {
      id: "evt_bkpfp_08_egress",
      ts: T(W + 6 * MIN),
      source: "firewall",
      vendor: "Palo Alto Networks PAN-OS",
      event_type: "net_connection",
      hostname: fileServer.hostname,
      src_ip: fileServer.ip,
      dst_ip: vendorEndpointIp,
      dst_port: 443,
      protocol: "tcp",
      severity: "medium",
      description:
        "FS-PROD-04 opened a 3-second outbound TLS session to 104.18.27.94:443 during the backup window — 4,812 bytes sent, 2,190 received, allowed by rule Servers-to-Internet-Restricted.",
      network: { bytes_out: 4812, bytes_in: 2190 },
      raw: {
        "pan.type": "TRAFFIC",
        "pan.subtype": "end",
        "pan.action": "allow",
        "pan.rule": "Servers-to-Internet-Restricted",
        "pan.src": fileServer.ip,
        "pan.dst": vendorEndpointIp,
        "pan.sport": "51884",
        "pan.dport": "443",
        "pan.proto": "tcp",
        "pan.app": "ssl",
        "pan.from_zone": "SERVERS",
        "pan.to_zone": "UNTRUST",
        "pan.session_id": "184402",
        "pan.bytes_sent": "4812",
        "pan.bytes_received": "2190",
        "pan.packets": "26",
        "pan.elapsed_time": "3",
        "pan.category": "computer-and-internet-info",
        "pan.dstloc": "US",
      },
    },

    // ---------------------------------------------------------------------
    // 9. THE ALARM — EDR ransomware-behaviour heuristic, CRITICAL.
    // ---------------------------------------------------------------------
    {
      id: "evt_bkpfp_09_edr_alert",
      ts: T(W + 7 * MIN),
      source: "edr",
      vendor: "Microsoft Defender for Endpoint",
      event_type: "edr_alert",
      hostname: fileServer.hostname,
      user_email: svcAccount.email,
      severity: "critical",
      mitre_technique: "T1486",
      mitre_tactic: "TA0040",
      description:
        "Defender for Endpoint raised a CRITICAL \"Ransomware behavior detected\" alert on FS-PROD-04 naming VeeamAgent.exe. RemediationAction is None.",
      raw: {
        Timestamp: T(W + 7 * MIN),
        AlertId: "da637-9021-4471-b3ae-2f8c19d5e004",
        Title: "Ransomware behavior detected",
        Category: "Impact",
        Severity: "High",
        DetectionSource: "EDR",
        ServiceSource: "Microsoft Defender for Endpoint",
        DetectorId: "BehaviorMonitoring/RansomwareFileActivity",
        DeviceName: fileServer.hostname,
        AccountName: svcAccount.name,
        AccountDomain: "nexacorp",
        AttackTechniques: ["T1486"],
        EntityType: "Process",
        FileName: "VeeamAgent.exe",
        SHA256: agentHash,
        RemediationAction: "None",
        AlertStatus: "New",
        ReportId: "4418311",
      },
    },

    // ---------------------------------------------------------------------
    // 10. SIEM correlation — the aggregates live here, not in device logs.
    // ---------------------------------------------------------------------
    {
      id: "evt_bkpfp_10_correlation",
      ts: T(W + 8 * MIN),
      source: "siem",
      vendor: "Microsoft Sentinel",
      event_type: "ueba_anomaly",
      hostname: fileServer.hostname,
      user_email: svcAccount.email,
      severity: "high",
      description:
        "Sentinel rule HighVolumeFileAccess_SingleAccount summarised svc_bkp_agent's activity on FS-PROD-04 across a 360-second window.",
      raw: {
        "siem.rule_name": "HighVolumeFileAccess_SingleAccount",
        "siem.rule_id": "SEN-FILE-0231",
        "siem.window_start": T(W + MIN),
        "siem.window_end": T(W + 7 * MIN),
        "siem.window_seconds": 360,
        "siem.account": "NEXACORP\\svc_bkp_agent",
        "siem.host": fileServer.hostname,
        "siem.event_4663_readdata_count": 41208,
        "siem.event_4663_writedata_count": 0,
        "siem.event_4663_delete_count": 0,
        "siem.file_renamed_count": 0,
        "siem.file_deleted_count": 0,
        "siem.distinct_extensions_written": [".vbk"],
        "siem.distinct_write_targets": ["\\\\BKP-REPO-01\\repo01"],
        "siem.bytes_read": 44198412288,
        "siem.new_autoruns_count": 0,
        "siem.new_services_count": 0,
        "siem.new_scheduled_tasks_count": 0,
        "siem.remote_logons_initiated_count": 0,
        "siem.threat_intel_matches": 0,
        "siem.linked_change_request": changeTicket,
        "event.action": "correlation-alert",
        "event.outcome": "alerted",
      },
    },
  ];

  const iocs: IOC[] = [
    {
      type: "host",
      value: fileServer.hostname,
      first_seen: T(W),
      last_seen: T(W + 8 * MIN),
      reputation: "clean",
      tags: ["file-server", "alert-source"],
    },
    {
      type: "user",
      value: svcAccount.name,
      first_seen: T(W),
      last_seen: T(W + 8 * MIN),
      reputation: "clean",
      tags: ["service-account", "logon-type-5"],
    },
    {
      type: "sha256",
      value: agentHash,
      first_seen: T(W + 5_000),
      last_seen: T(W + 7 * MIN),
      reputation: "clean",
      tags: ["signed", "program-files"],
    },
    {
      type: "ip",
      value: vendorEndpointIp,
      first_seen: T(W + 6 * MIN),
      last_seen: T(W + 6 * MIN),
      reputation: "unknown",
      tags: ["external", "tls-443", "unattributed"],
    },
    {
      type: "host",
      value: repo.hostname,
      first_seen: T(W + 4 * MIN),
      last_seen: T(W + 4 * MIN),
      reputation: "clean",
      tags: ["backup-repository", "write-target"],
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1",
      prompt:
        "Which PAIR of events, read together, best explains why the job ran at 02:00 and argues it was not started ad hoc by a person on the box?",
      hint: "One event has to come from outside the host telemetry.",
      kind: "single",
      options: [
        { value: "change_start", label: "evt_bkpfp_01_change + evt_bkpfp_04_agent_start — approved schedule, then an SCM-launched process at that time" },
        { value: "logon_priv", label: "evt_bkpfp_02_svc_logon + evt_bkpfp_03_privileges — a service logon followed by heavy backup privileges" },
        { value: "vss_write", label: "evt_bkpfp_05_vss + evt_bkpfp_07_vbk_write — a shadow copy taken, then a large container written out" },
        { value: "alert_corr", label: "evt_bkpfp_09_edr_alert + evt_bkpfp_10_correlation — the critical alert and its correlation summary" },
      ],
      answer: "change_start",
      xp: 40,
      explanation:
        "Neither event proves it alone. The ticket only shows what was *meant* to happen; the process event only shows what *did* happen. Together they line up: a CAB-approved 02:00 full-backup window, and at 02:00 a process whose parent is services.exe — the Service Control Manager — with a job GUID on the command line. The logon and privilege pair (b) tells you what the account can do, not who scheduled it. Pair (c) is exactly the behaviour the heuristic already flagged, so it cannot resolve the question. Pair (d) is the alarm and its restatement, which is where the investigation started.",
    },
    {
      id: "q2",
      prompt:
        "The alert names VeeamAgent.exe. Which attributes in evt_bkpfp_04_agent_start argue this is the genuine vendor product rather than a binary masquerading under that name?",
      kind: "single",
      options: [
        { value: "sig_path", label: "Vendor Authenticode signature, plus execution from its real install path" },
        { value: "integrity", label: "High process integrity and a command line carrying the backup job GUID" },
        { value: "first_seen", label: "First seen in the environment nine hours before the alert triggered" },
        { value: "name_match", label: "File name matches the product name listed on the vendor's website" },
      ],
      answer: "sig_path",
      xp: 50,
      explanation:
        "A valid Authenticode signature from Veeam Software Group GmbH, chaining to a trusted CA, plus the binary living under C:\\Program Files\\Veeam\\... is the combination that is expensive for an attacker to fake — malware that impersonates a product almost always runs from ProgramData, Temp or a user profile. Integrity level (b) proves nothing on its own: ransomware run by a service also gets a System token. Prevalence (c) is not shown in the telemetry and would not be reassuring anyway. A matching file name (d) is the single easiest thing in the whole chain to forge, which is precisely why analysts check the signer and the path instead.",
    },
    {
      id: "q3",
      prompt:
        "vssadmin.exe running is a classic ransomware indicator. What does evt_bkpfp_05_vss actually show it doing?",
      kind: "single",
      options: [
        { value: "create", label: "vssadmin create shadow — a snapshot was added, not removed" },
        { value: "delete", label: "vssadmin delete shadows — existing recovery points were destroyed" },
        { value: "resize", label: "vssadmin resize shadowstorage — the snapshot area was shrunk to nothing" },
        { value: "list", label: "vssadmin list shadows — existing snapshots were only enumerated" },
      ],
      answer: "create",
      xp: 50,
      explanation:
        "The verb is the whole answer. Ransomware runs `delete shadows` or `resize shadowstorage /maxsize=1MB` (both T1490, Inhibit System Recovery) so the victim cannot roll back. Backup software runs `create shadow` so it can read open and locked files consistently — it is adding a recovery point, the exact opposite intent. `list` is reconnaissance and would be neutral here. If you alert on the string 'vssadmin' rather than on the sub-command, you will page someone for every backup job in the estate.",
    },
    {
      id: "q4",
      prompt:
        "Comparing evt_bkpfp_06_file_read, evt_bkpfp_07_vbk_write and evt_bkpfp_10_correlation, which observation is the strongest evidence AGAINST ransomware?",
      kind: "single",
      options: [
        { value: "read_only", label: "Files were opened ReadData only; the new data went to a separate repository share" },
        { value: "one_share", label: "Every file that was touched sits under a single finance share on that server" },
        { value: "volume", label: "The number of files touched was lower than in previous backup windows" },
        { value: "svc_acct", label: "The account doing the reading is a service account rather than a person" },
      ],
      answer: "read_only",
      xp: 60,
      explanation:
        "Ransomware must WRITE to the originals — the 4663 records would carry WriteData or DELETE in the AccessList, and you would see thousands of rename events as extensions change. Sentinel counted 41,208 ReadData accesses, zero WriteData, zero deletes and zero renames, and every byte written landed on \\\\BKP-REPO-01\\repo01 while D:\\Finance kept its original paths and .xlsx extensions. Option (b) is just the job's scope. Option (c) is not in the telemetry and lower volume would not make encryption benign. Option (d) is neutral at best — compromised service accounts are a standard ransomware deployment path.",
    },
    {
      id: "q5",
      prompt:
        "You are closing this as benign. Which finding, had it been present, should have flipped the verdict to malicious?",
      hint: "Think about what backup software never needs to do.",
      kind: "single",
      options: [
        { value: "delete_rewrite", label: "Shadow copies deleted and source files rewritten in place with a new extension" },
        { value: "time_shift", label: "The job starting at 02:00 rather than in the previous 23:00 nightly window" },
        { value: "priv_held", label: "A service account holding SeBackupPrivilege on a production file server" },
        { value: "read_rate", label: "The agent reading far more files in six minutes than a user reads in a week" },
      ],
      answer: "delete_rewrite",
      xp: 70,
      explanation:
        "Those two findings together have no benign reading: destroying recovery points serves only the attacker, and rewriting originals in place is the definition of encryption for impact (T1486 plus T1490). Option (b) is fully explained by CHG0041887 — a schedule change is a change, not a compromise. Option (c) is required for the software to function at all; the privilege being present is expected, the question is only whether the right process holds it. Option (d) is the machine-speed access that made the heuristic fire in the first place, and it is normal for any backup agent. The lesson is that closing benign is a positive claim: you close on evidence you found, and you name in the ticket which evidence would have changed your mind.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "Mass File Encryption Alert — Enterprise Backup Agent",
    threat_actor: "None — benign scheduled operations activity",
    attack_kind: "false_positive",
    briefing: "Microsoft Defender for Endpoint fired a CRITICAL alert, \"Ransomware behavior detected\", on production file server FS-PROD-04 at 02:07 — mass file access across the finance shares by a single process, plus volume shadow copy activity. Nothing was blocked or terminated. Night shift is holding for an isolate decision.",
    narrative: `At 02:07 a CRITICAL Microsoft Defender for Endpoint alert titled "Ransomware behavior detected" fires on FS-PROD-04, one of NexaCorp's production file servers. In the preceding minutes a single process, running as the service account svc_bkp_agent, opened tens of thousands of files across the finance shares at machine speed, touched Volume Shadow Copy Service, and produced multi-gigabyte files with an extension nobody on the shift recognises. Every ingredient of a live ransomware deployment appears to be on the table, and the on-call is already reaching for host isolation.

Isolating this server at 02:07 would kill the company's only full backup of the finance data and cost the night shift several hours. Before you pull the cable, work the evidence: who started the process and on whose authority, what the binary actually is, what was done to the original files, and which direction the shadow-copy operation went. The answer is in the telemetry — but only if you read the command lines and the access masks rather than the alert title.`,
    learning_objectives: [
      "Support a 'benign' verdict with positive corroborating evidence — a change record plus a service-controlled start — rather than with the absence of badness",
      "Use code signature, install path and parent process to validate a process as a genuine vendor product instead of a masquerading binary",
      "Read Volume Shadow Copy operations by sub-command: creating a snapshot supports recovery, deleting or resizing one destroys it (T1490)",
      "Distinguish backup file activity (read-only access, output to a separate target) from ransomware file activity (in-place rewrite and rename)",
      "Name the specific evidence that would have changed the verdict to malicious, and record it when closing the alert",
    ],
    // alerts are attached by the catalogue wiring
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: T(0), phase: "Authorised Change", action: `${changeTicket} approved — FS-PROD-04 moves to a weekly full backup at 02:00` },
      { ts: T(W), phase: "Scheduled Start", action: "Service Control Manager logs on svc_bkp_agent (LogonType 5) and starts the job" },
      { ts: T(W + 25_000), phase: "Snapshot", action: "vssadmin create shadow /for=D: — a recovery point is added before reading" },
      { ts: T(W + MIN), phase: "Bulk Read", action: "41,208 files opened with ReadData across the D:\\Finance shares" },
      { ts: T(W + 4 * MIN), phase: "Backup Write", action: "26 GB .vbk container written to \\\\BKP-REPO-01\\repo01 — originals untouched" },
      { ts: T(W + 6 * MIN), phase: "Open Question", action: "Short outbound TLS session to an unattributed external address" },
      { ts: T(W + 7 * MIN), phase: "Detection", action: "EDR behavioural heuristic fires CRITICAL — no block, no process termination" },
      { ts: T(W + 8 * MIN), phase: "Triage", action: "SIEM correlation shows zero writes, zero renames, zero new persistence" },
    ],
    questions,
  };
}
