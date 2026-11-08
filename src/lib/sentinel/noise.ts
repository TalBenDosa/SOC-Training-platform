/**
 * Noisy analytics rules, the kind real SOCs run. They exist so that no tactic on an incident gives the
 * attack away: measured on the team feeds, the use cases alone left tactics such as Credential Access
 * and Lateral Movement almost entirely on attack incidents.
 *
 * Each part pairs its KQL with the same logic as a row test, so a rule fires without running a query on
 * every poll; a test holds the two equal. The logic reads only columns of the row: never a verdict.
 */
import type { KqlRow } from "@/lib/kql/types";
import type { AnalyticsRule, SentinelSeverity } from "./types";

/** One table's half of a rule. */
export interface NoisePart {
  table: string;
  /** KQL predicate over the table. */
  where: string;
  test: (r: KqlRow) => boolean;
  /** Fire at `count` rows sharing this column inside `windowSec`. */
  threshold?: { by: string; count: number; windowSec: number };
}

export interface NoiseRule {
  id: string; name: string; severity: SentinelSeverity; tactics: string[]; techniques: string[]; description: string; falsePositives: string[];
  parts: NoisePart[];
}

export interface NoiseHit { rows: KqlRow[] }

const s = (v: unknown) => (v === undefined || v === null ? "" : String(v));
const has = (v: unknown, re: RegExp) => re.test(s(v));

const SIGNIN_FAILURE = (r: KqlRow) => s(r.ResultType) !== "" && s(r.ResultType) !== "0";

const ADMIN_TOOLS = /(^|\\)(psexec(64)?|paexec|wmic|sc|schtasks|nltest|mstsc|winrs|certutil|bitsadmin|reg|robocopy|net1?)(\.exe)$/i;
const ADMIN_TOOLS_KQL = String.raw`(?i)(^|\\)(psexec(64)?|paexec|wmic|sc|schtasks|nltest|mstsc|winrs|certutil|bitsadmin|reg|robocopy|net1?)(\.exe)$`;
const USER_FOLDER = /\\Users\\[^\\]+\\(Downloads|Desktop|AppData\\Local\\Temp)\\|\\Windows\\Temp\\/i;
const USER_FOLDER_KQL = String.raw`(?i)\\Users\\[^\\]+\\(Downloads|Desktop|AppData\\Local\\Temp)\\|\\Windows\\Temp\\`;
const BACKUP_TOOLS = /veeam|vssadmin|wbadmin|ntbackup|sqlbackup|db_backup|rsync/i;
const BACKUP_TOOLS_KQL = "(?i)veeam|vssadmin|wbadmin|ntbackup|sqlbackup|db_backup|rsync";

const sysmonData = (name: string) => `extract(@'<Data Name="${name}">([^<]*)', 1, EventData)`;
const sysmonValue = (r: KqlRow, name: string) => new RegExp(`<Data Name="${name}">([^<]*)`).exec(s(r.EventData))?.[1] ?? "";
const unescapeXml = (v: string) => v.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
const sysmonOf = (r: KqlRow, name: string) => unescapeXml(sysmonValue(r, name));
const SYSMON_PROCESS = `Source == "Microsoft-Windows-Sysmon" and EventID == 1`;
const isSysmonProcess = (r: KqlRow) => r.Source === "Microsoft-Windows-Sysmon" && r.EventID === 1;

/** A process-start rule on every table a shop's process telemetry lands in. */
const processParts = (kqlRegex: string, re: RegExp): NoisePart[] => [
  { table: "DeviceProcessEvents", where: `FolderPath matches regex @"${kqlRegex}"`, test: r => has(r.FolderPath, re) },
  { table: "ASimProcessEventLogs", where: `TargetProcessName matches regex @"${kqlRegex}"`, test: r => has(r.TargetProcessName, re) },
  { table: "Event", where: `${SYSMON_PROCESS} and ${sysmonData("Image")} matches regex @"${kqlRegex}"`, test: r => isSysmonProcess(r) && re.test(sysmonOf(r, "Image")) },
  { table: "SecurityEvent", where: `EventID == 4688 and NewProcessName matches regex @"${kqlRegex}"`, test: r => r.EventID === 4688 && has(r.NewProcessName, re) },
];

type ProcField = "image" | "cmd" | "parent";
/** Where each table keeps the process path, its command line and its parent. */
const PROC_COLUMN: Record<"DeviceProcessEvents" | "ASimProcessEventLogs" | "SecurityEvent", Record<ProcField, string>> = {
  DeviceProcessEvents: { image: "FolderPath", cmd: "ProcessCommandLine", parent: "InitiatingProcessFileName" },
  ASimProcessEventLogs: { image: "TargetProcessName", cmd: "TargetProcessCommandLine", parent: "ActingProcessName" },
  SecurityEvent: { image: "NewProcessName", cmd: "CommandLine", parent: "ParentProcessName" },
};
const SYSMON_FIELD: Record<ProcField, string> = { image: "Image", cmd: "CommandLine", parent: "ParentImage" };

/**
 * A process-start rule on one field of the process (its path, its command line or its parent), on every
 * table process telemetry lands in. The pattern is case-insensitive on both sides and holds no quote.
 * Sysmon's KQL reads the field as the XML holds it, so the row test does too.
 */
const processFieldParts = (field: ProcField, pattern: string): NoisePart[] => {
  const re = new RegExp(pattern, "i"), kql = `@"(?i)${pattern}"`;
  const col = (t: keyof typeof PROC_COLUMN) => PROC_COLUMN[t][field];
  return [
    { table: "DeviceProcessEvents", where: `${col("DeviceProcessEvents")} matches regex ${kql}`, test: r => has(r[col("DeviceProcessEvents")], re) },
    { table: "ASimProcessEventLogs", where: `${col("ASimProcessEventLogs")} matches regex ${kql}`, test: r => has(r[col("ASimProcessEventLogs")], re) },
    { table: "Event", where: `${SYSMON_PROCESS} and ${sysmonData(SYSMON_FIELD[field])} matches regex ${kql}`, test: r => isSysmonProcess(r) && re.test(sysmonValue(r, SYSMON_FIELD[field])) },
    { table: "SecurityEvent", where: `EventID == 4688 and ${col("SecurityEvent")} matches regex ${kql}`, test: r => r.EventID === 4688 && has(r[col("SecurityEvent")], re) },
  ];
};

/** The service a remote-execution tool installs on its target runs the command (PsExec, PAExec, PDQ Deploy, RemCom, CSExec). */
const DEPLOY_SERVICE = String.raw`(^|\\)(psexesvc|paexec(-[\w.]+)?|pdqdeployrunner(-\d+)?|remcomsvc|csexecsvc)\.exe$`;
const POLICY_BYPASS = String.raw`-(ep|ex|exec|executionpolicy)\s+bypass\b`;
const REMOTE_COMMAND = String.raw`invoke-command\s+-computername|enter-pssession|new-pssession|\bwinrs(\.exe)?\s+-r:|\bwmic(\.exe)?\s+/node:`;
const OFFENSIVE_TOOLS = String.raw`(^|[\\/])(rubeus|sharphound|certify|seatbelt|mimikatz|sharpup|lazagne|kerbrute|winpeas\w*)(\.exe)?$`;
const SCANNER_TOOLS = String.raw`(^|[\\/])(advanced_ip_scanner|advanced_port_scanner|ipscan|nmap|masscan|netscan)(\.exe)?$`;
const PACKET_CAPTURE = String.raw`\b(dumpcap|tshark|windump|tcpdump)(\.exe)?\x22?\s|\bpktmon(\.exe)?\s+start\b|\bnetsh(\.exe)?\s+trace\s+start\b`;
const CLOUD_SYNC = String.raw`\brclone(\.exe)?\x22?\s+(copy|copyto|sync|move)\b|\bmega-(put|sync)\b`;

export const NOISE_RULES: NoiseRule[] = [
  {
    id: "noise.signin_failures", name: "Repeated sign-in failures for one account", severity: "Medium", tactics: ["CredentialAccess"], techniques: ["T1110"],
    description: "An account failed to sign in more than once within 15 minutes.",
    falsePositives: ["A forgotten or recently changed password", "An old credential saved on a phone or mail client"],
    parts: [
      { table: "SigninLogs", where: `ResultType != "0"`, test: SIGNIN_FAILURE, threshold: { by: "UserPrincipalName", count: 2, windowSec: 900 } },
      { table: "OktaV2_CL", where: `EventOriginalType == "user.session.start" and OriginalOutcomeResult == "FAILURE"`, test: r => r.EventOriginalType === "user.session.start" && r.OriginalOutcomeResult === "FAILURE", threshold: { by: "OriginalActorAlternateId", count: 2, windowSec: 900 } },
      { table: "SecurityEvent", where: `EventID == 4625`, test: r => r.EventID === 4625, threshold: { by: "TargetUserName", count: 2, windowSec: 900 } },
    ],
  },
  {
    id: "noise.mfa_failure", name: "MFA challenge failed or was not completed", severity: "Low", tactics: ["CredentialAccess"], techniques: ["T1621"],
    description: "A sign-in stopped at the MFA step.",
    falsePositives: ["The user dismissed the prompt or changed phones"],
    parts: [
      { table: "SigninLogs", where: `ResultType in ("50074", "50076", "50079", "500121")`, test: r => ["50074", "50076", "50079", "500121"].includes(s(r.ResultType)) },
      { table: "OktaV2_CL", where: `EventOriginalType == "user.authentication.auth_via_mfa" and OriginalOutcomeResult != "SUCCESS"`, test: r => r.EventOriginalType === "user.authentication.auth_via_mfa" && r.OriginalOutcomeResult !== "SUCCESS" },
    ],
  },
  {
    id: "noise.admin_tool", name: "Administration tool used on an endpoint", severity: "Medium", tactics: ["LateralMovement", "Execution"], techniques: ["T1569.002", "T1021"],
    description: "A built-in or remote administration tool ran. Real attackers and real administrators use the same ones.",
    falsePositives: ["IT administrators and deployment scripts"],
    parts: processParts(ADMIN_TOOLS_KQL, ADMIN_TOOLS),
  },
  {
    id: "noise.privileged_change", name: "Privileged role or group changed", severity: "Medium", tactics: ["PrivilegeEscalation", "Persistence"], techniques: ["T1098"],
    description: "A role, an admin group or a privileged membership changed.",
    falsePositives: ["An approved access request", "Joiner and mover changes"],
    parts: [
      { table: "AuditLogs", where: `OperationName has_any ("member to role", "member to group", "role assignment")`, test: r => has(r.OperationName, /\b(member to role|member to group|role assignment)\b/i) },
      { table: "SecurityEvent", where: `EventID in (4728, 4732, 4756)`, test: r => [4728, 4732, 4756].includes(Number(r.EventID)) },
      { table: "OktaV2_CL", where: `EventOriginalType in ("user.account.privilege.grant", "group.user_membership.add")`, test: r => ["user.account.privilege.grant", "group.user_membership.add"].includes(s(r.EventOriginalType)) },
      { table: "AzureActivity", where: `OperationNameValue contains "ROLEASSIGNMENTS/WRITE"`, test: r => has(r.OperationNameValue, /ROLEASSIGNMENTS\/WRITE/i) },
    ],
  },
  {
    id: "noise.mass_download", name: "Many files downloaded by one user", severity: "Low", tactics: ["Collection"], techniques: ["T1213"],
    description: "A user downloaded or synced several files within 30 minutes.",
    falsePositives: ["Sync clients", "A user preparing to travel"],
    parts: [
      { table: "OfficeActivity", where: `Operation in ("FileDownloaded", "FileSyncDownloadedFull")`, test: r => ["FileDownloaded", "FileSyncDownloadedFull"].includes(s(r.Operation)), threshold: { by: "UserId", count: 2, windowSec: 1800 } },
    ],
  },
  {
    id: "noise.user_folder_exec", name: "Executable started from a user folder", severity: "Medium", tactics: ["Stealth"], techniques: ["T1036.005"],
    description: "A program ran from Downloads, the Desktop or a temp folder.",
    falsePositives: ["Installers and portable tools", "Software updaters"],
    parts: processParts(USER_FOLDER_KQL, USER_FOLDER),
  },
  {
    id: "noise.remote_logon", name: "Remote logon to a server", severity: "Low", tactics: ["LateralMovement"], techniques: ["T1021.001"],
    description: "An account logged on to a server over the network or by RDP.",
    falsePositives: ["Routine server administration"],
    parts: [
      { table: "SecurityEvent", where: `EventID == 4624 and LogonType in (3, 10) and Computer startswith "SRV"`, test: r => r.EventID === 4624 && [3, 10].includes(Number(r.LogonType)) && has(r.Computer, /^SRV/i) },
      { table: "DeviceLogonEvents", where: `LogonType in ("RemoteInteractive", "Network") and DeviceName startswith "SRV"`, test: r => ["RemoteInteractive", "Network"].includes(s(r.LogonType)) && has(r.DeviceName, /^SRV/i) },
    ],
  },
  {
    id: "noise.backup_tooling", name: "Backup or shadow copy tooling ran", severity: "Low", tactics: ["Impact"], techniques: ["T1490"],
    description: "A backup or snapshot job ran. Ransomware operators touch the same tools to remove recovery options.",
    falsePositives: ["Scheduled backups"],
    parts: [
      ...processParts(BACKUP_TOOLS_KQL, BACKUP_TOOLS),
      { table: "Syslog", where: `SyslogMessage matches regex @"${BACKUP_TOOLS_KQL}"`, test: r => has(r.SyslogMessage, BACKUP_TOOLS) },
      { table: "AzureActivity", where: `OperationNameValue contains "backupJobs"`, test: r => has(r.OperationNameValue, /backupJobs/i) },
    ],
  },
  {
    id: "noise.instance_terminated", name: "Cloud workload terminated or replaced", severity: "Low", tactics: ["Impact"], techniques: ["T1578.003"],
    description: "A cloud instance or service was terminated or replaced.",
    falsePositives: ["Auto scaling", "A release pipeline"],
    parts: [
      { table: "AWSCloudTrail", where: `EventName in ("TerminateInstances", "TerminateInstanceInAutoScalingGroup", "UpdateService")`, test: r => ["TerminateInstances", "TerminateInstanceInAutoScalingGroup", "UpdateService"].includes(s(r.EventName)) },
    ],
  },
  {
    id: "noise.uncategorised_web", name: "Web request to an uncategorised or generic site", severity: "Low", tactics: ["ResourceDevelopment"], techniques: ["T1583.001"],
    description: "A host reached a site the URL filter could not place in a business category. New attacker domains and new vendor sites both land here.",
    falsePositives: ["Small vendors and newly launched sites"],
    parts: [
      { table: "CommonSecurityLog", where: `DeviceVendor == "Palo Alto Networks" and DeviceCustomString2 in ("unknown", "computer-and-internet-info", "not-resolved")`, test: r => r.DeviceVendor === "Palo Alto Networks" && ["unknown", "computer-and-internet-info", "not-resolved"].includes(s(r.DeviceCustomString2)) },
      { table: "CommonSecurityLog", where: `DeviceVendor == "Zscaler" and DeviceEventCategory in ("Miscellaneous or Unknown", "Internet Services")`, test: r => r.DeviceVendor === "Zscaler" && ["Miscellaneous or Unknown", "Internet Services"].includes(s(r.DeviceEventCategory)) },
      { table: "CommonSecurityLog", where: `DeviceVendor == "Check Point" and DeviceProduct == "URL Filtering"`, test: r => r.DeviceVendor === "Check Point" && r.DeviceProduct === "URL Filtering" },
      { table: "CommonSecurityLog", where: `DeviceVendor =~ "Fortinet" and DeviceEventCategory == "utm:webfilter"`, test: r => s(r.DeviceVendor).toLowerCase() === "fortinet" && r.DeviceEventCategory === "utm:webfilter" },
    ],
  },
  {
    id: "noise.service_account_signin", name: "Sign-in by a service account", severity: "Low", tactics: ["Stealth"], techniques: ["T1078.002"],
    description: "A service account signed in. Attackers prefer accounts nobody watches; automation signs in the same way.",
    falsePositives: ["Scheduled jobs and integrations"],
    parts: [
      { table: "SigninLogs", where: `UserPrincipalName startswith "svc" and IsInteractive == true`, test: r => has(r.UserPrincipalName, /^svc/i) && r.IsInteractive === true },
      { table: "SecurityEvent", where: `EventID == 4624 and TargetUserName startswith "svc" and LogonType != 5`, test: r => r.EventID === 4624 && has(r.TargetUserName, /^svc/i) && r.LogonType !== 5 },
      { table: "OktaV2_CL", where: `OriginalActorAlternateId startswith "svc" and EventOriginalType != "app.oauth2.as.token.grant"`, test: r => has(r.OriginalActorAlternateId, /^svc/i) && r.EventOriginalType !== "app.oauth2.as.token.grant" },
      { table: "AWSCloudTrail", where: `EventName == "AssumeRole"`, test: r => r.EventName === "AssumeRole" },
    ],
  },
  {
    id: "noise.security_control_change", name: "Security control changed", severity: "Medium", tactics: ["DefenseImpairment"], techniques: ["T1562.007"],
    description: "A firewall rule, a bucket policy or an MFA factor changed.",
    falsePositives: ["Approved change requests", "Infrastructure as code deployments"],
    parts: [
      { table: "AWSCloudTrail", where: `EventName in ("AuthorizeSecurityGroupIngress", "PutBucketPolicy", "PutBucketAcl", "PutBucketPublicAccessBlock")`, test: r => ["AuthorizeSecurityGroupIngress", "PutBucketPolicy", "PutBucketAcl", "PutBucketPublicAccessBlock"].includes(s(r.EventName)) },
      { table: "AzureActivity", where: `OperationNameValue contains "NETWORKSECURITYGROUPS"`, test: r => has(r.OperationNameValue, /NETWORKSECURITYGROUPS/i) },
      { table: "OktaV2_CL", where: `EventOriginalType == "user.mfa.factor.deactivate"`, test: r => r.EventOriginalType === "user.mfa.factor.deactivate" },
      { table: "GCPAuditLogs", where: `MethodName == "storage.buckets.update"`, test: r => r.MethodName === "storage.buckets.update" },
    ],
  },
  // Endpoint process rules over the EDR and Windows tables, the kind SOCs import from the content hub
  // and Sigma. Each one fires on the tool, never on who ran it.
  {
    id: "noise.deploy_service_exec", name: "Command run by a remote execution service", severity: "Medium", tactics: ["LateralMovement", "Execution"], techniques: ["T1569.002"],
    description: "A process started under the service a remote execution tool installs on its target (PsExec, PAExec, PDQ Deploy, RemCom). Software deployment and lateral movement both arrive this way.",
    falsePositives: ["Software deployment from the IT console", "Administrators running PsExec"],
    parts: processFieldParts("parent", DEPLOY_SERVICE),
  },
  {
    id: "noise.ps_policy_bypass", name: "PowerShell started with the execution policy bypassed", severity: "Medium", tactics: ["Execution"], techniques: ["T1059.001"],
    description: "A command line set the PowerShell execution policy to Bypass. Management agents start their scripts this way, and so do droppers.",
    falsePositives: ["Configuration Manager and Intune scripts", "Vendor installers"],
    parts: processFieldParts("cmd", POLICY_BYPASS),
  },
  {
    id: "noise.remote_command", name: "Command sent to another host over WinRM or WMI", severity: "Medium", tactics: ["LateralMovement", "Execution"], techniques: ["T1021.006", "T1047"],
    description: "A command line ran a command on another computer through PowerShell remoting, winrs or WMI.",
    falsePositives: ["Server administration and patching scripts"],
    parts: processFieldParts("cmd", REMOTE_COMMAND),
  },
  {
    id: "noise.offensive_tool", name: "Known offensive security tool executed", severity: "High", tactics: ["CredentialAccess", "Discovery"], techniques: ["T1558.003", "T1087.002", "T1649", "T1082", "T1003.001"],
    description: "A process carries the name of a public red-team or credential tool (Rubeus, SharpHound, Certify, Seatbelt, Mimikatz and similar).",
    falsePositives: ["A penetration test in its rules of engagement"],
    parts: processFieldParts("image", OFFENSIVE_TOOLS),
  },
  {
    id: "noise.network_scanner", name: "Network scanner run on an endpoint", severity: "Low", tactics: ["Discovery"], techniques: ["T1046"],
    description: "A network or port scanner ran on a computer (Advanced IP Scanner, Angry IP Scanner, Nmap and similar). Administrators and ransomware operators use the same tools.",
    falsePositives: ["IT staff troubleshooting the network"],
    parts: processFieldParts("image", SCANNER_TOOLS),
  },
  {
    id: "noise.packet_capture", name: "Packet capture started on an endpoint", severity: "Low", tactics: ["Discovery", "CredentialAccess"], techniques: ["T1040"],
    description: "A command line started a packet capture (dumpcap, tshark, tcpdump, pktmon or netsh trace).",
    falsePositives: ["Developers and network engineers debugging a connection"],
    parts: processFieldParts("cmd", PACKET_CAPTURE),
  },
  {
    id: "noise.cloud_sync_tool", name: "Data copied to a cloud remote with rclone or MEGAcmd", severity: "High", tactics: ["Exfiltration"], techniques: ["T1567.002"],
    description: "A command line copied or synced files to a cloud storage remote with rclone or the MEGA command-line client.",
    falsePositives: ["An engineer's own backup to an approved storage account"],
    parts: processFieldParts("cmd", CLOUD_SYNC),
  },
];

/** The rule part's KQL. */
export function partQuery(p: NoisePart): string {
  const base = `${p.table}\n| where ${p.where}`;
  if (!p.threshold) return base;
  return `${base}\n| summarize Count = count(), StartTime = min(TimeGenerated), EndTime = max(TimeGenerated) by ${p.threshold.by}\n| where Count >= ${p.threshold.count}`;
}

/** The rows of one firing of a part, in table order. Fires once per threshold group, on the first full window. */
export function evaluatePart(p: NoisePart, rows: KqlRow[]): NoiseHit[] {
  const matched = rows.filter(p.test);
  if (!p.threshold) return matched.map(r => ({ rows: [r] }));
  const groups = new Map<string, KqlRow[]>();
  for (const r of matched) {
    const k = s(r[p.threshold.by]);
    if (!k) continue;
    groups.set(k, [...(groups.get(k) ?? []), r]);
  }
  const hits: NoiseHit[] = [];
  for (const members of groups.values()) {
    const sorted = [...members].sort((a, b) => Date.parse(s(a.TimeGenerated)) - Date.parse(s(b.TimeGenerated)));
    let lo = 0;
    for (let hi = 0; hi < sorted.length; hi++) {
      while (Date.parse(s(sorted[hi].TimeGenerated)) - Date.parse(s(sorted[lo].TimeGenerated)) > p.threshold.windowSec * 1000) lo++;
      if (hi - lo + 1 >= p.threshold.count) { hits.push({ rows: sorted.slice(lo, hi + 1) }); break; }
    }
  }
  return hits;
}

export function noiseAnalyticsRules(): AnalyticsRule[] {
  return NOISE_RULES.map(r => {
    const window = r.parts.find(p => p.threshold)?.threshold?.windowSec;
    const queries = r.parts.map(partQuery);
    return {
      id: r.id, name: r.name, severity: r.severity, tactics: r.tactics, techniques: r.techniques, description: r.description,
      query: queries.length === 1 ? queries[0] : `union\n${queries.map(q => `(${q.replace(/\n/g, "\n  ")})`).join(",\n")}`,
      frequency: "5 minutes", lookback: window ? `${window / 60} minutes` : "1 hour", dataSources: r.parts.map(p => p.table), falsePositives: r.falsePositives,
    };
  });
}
