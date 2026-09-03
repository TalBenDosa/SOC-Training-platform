/**
 * Microsoft Defender for Endpoint log EMITTERS — Advanced Hunting schema.
 *
 * Same contract as the other vendor emitters (see crowdstrike.ts). MDE's dialect is the
 * Advanced Hunting tables: DeviceProcessEvents / DeviceNetworkEvents / DeviceFileEvents /
 * AlertEvidence, with PascalCase columns (DeviceName, FileName, FolderPath, SHA256,
 * ProcessCommandLine, InitiatingProcess*, ActionType) plus the mde.* prefix. All keys are
 * registry-valid; host/user/IP come from the company fabric.
 */
import type { TelemetryEvent, Severity, ExpectedVerdict } from "../types";
import { makeSha256 } from "../iocs";
import { type Ctx, resolve, pidFrom, downloadsPath } from "./_core";
import { assetsFor } from "../fabric";

const VENDOR = "Microsoft Defender for Endpoint";

// Split a DOMAIN\user into the AccountDomain + AccountName columns MDE uses.
function acct(companyId: string | undefined, bareUser: string) {
  return { AccountName: bareUser, AccountDomain: assetsFor(companyId)?.netbios ?? "WORKGROUP" };
}

// ── Detection (AlertEvidence / AntivirusDetection) ───────────────────────────────────
export interface MdeDetectionOpts extends Ctx {
  processName: string;
  processPath?: string;
  cmdline?: string;
  parentName?: string;
  sha256?: string;
  threatName: string;
  category?: string;            // MDE alert category, e.g. "Malware", "Execution"
  mitre?: string;
  tactic?: string;
  severity?: Severity;
  action?: "prevented" | "killed" | "quarantined" | "detected";
  expectedVerdict?: ExpectedVerdict;
  description?: string;
}
const REMEDIATION: Record<NonNullable<MdeDetectionOpts["action"]>, { result: string; quarantine: string }> = {
  prevented:   { result: "blocked",             quarantine: "n/a" },
  killed:      { result: "process_killed",      quarantine: "n/a" },
  quarantined: { result: "quarantined",         quarantine: "quarantined" },
  detected:    { result: "detected_not_blocked", quarantine: "n/a" },
};
export function mdeDetection(o: MdeDetectionOpts): TelemetryEvent {
  const r = resolve(o);
  const sev = o.severity ?? "high";
  const action = o.action ?? "quarantined";
  const rem = REMEDIATION[action];
  const sha256 = o.sha256 ?? makeSha256(`${o.threatName}:${o.processName}`);
  const path = o.processPath ?? downloadsPath(r.bareUser, o.processName);
  const folder = path.slice(0, path.lastIndexOf("\\")) || path;
  const cmdline = o.cmdline ?? `"${path}"`;
  const pid = pidFrom(o.id);
  const a = acct(o.companyId, r.bareUser);
  return {
    id: o.id, ts: o.ts, source: "edr", vendor: VENDOR, event_type: "av_detection",
    severity: sev, hostname: r.host, src_ip: r.srcIp, user_email: r.email,
    mitre_technique: o.mitre, mitre_tactic: o.tactic, is_detection: true,
    expected_verdict: o.expectedVerdict, incident_id: o.incidentId,
    description: o.description ?? `${VENDOR} ${action === "detected" ? "detected" : "blocked"} ${o.threatName} on ${r.host}`,
    process: { pid, name: o.processName, path, cmdline, parent_name: o.parentName, user: r.domainUser, hash: { sha256 } },
    file: { name: o.processName, path, sha256 },
    raw: {
      "ActionType": "AntivirusDetection",
      "DeviceName": r.host,
      "AccountName": a.AccountName,
      "AccountDomain": a.AccountDomain,
      "FileName": o.processName,
      "FolderPath": folder,
      "SHA256": sha256,
      "ProcessCommandLine": cmdline,
      "InitiatingProcessFileName": o.parentName ?? "",
      "mde.AlertTitle": o.threatName,
      "mde.Category": o.category ?? "Malware",
      "mde.DetectionSource": "Antivirus",
      "mde.SHA256": sha256,
      "file.hash.sha256": sha256,
      "threat.name": o.threatName,
      "action_result": rem.result,
      "quarantine.status": rem.quarantine,
      "event.outcome": "success",
    },
  };
}

// ── Incident alert (AlertEvidence / Defender incident summary) ───────────────────────
// A behavioural incident that ties the earlier evidence together. Unlike mdeDetection it
// carries NO process of its own — it is the alert row that opens the ticket, so the EDR
// console shows it in the timeline/feed, not as another tree node.
export interface MdeAlertOpts extends Ctx {
  alertTitle: string;
  category?: string;            // e.g. "CredentialAccess"
  malwareName?: string;         // e.g. "Trojan:Win32/Rhadesta.SP!MTB"
  malwareCategory?: string;     // e.g. "infostealer"
  sha256?: string;
  mitre?: string;               // technique id
  techniqueName?: string;
  remediation?: string;         // e.g. "Quarantine"
  remediationStatus?: string;   // e.g. "Completed"
  evidenceRole?: string;        // e.g. "Impacted"
  mdeIncidentId?: string;       // Defender incident number (distinct from the story incident_id)
  detectionSource?: string;     // e.g. "AntivirusBehavior"
  alertSeverity?: string;       // Defender's own label (defaults from severity)
  severity?: Severity;
  expectedVerdict?: ExpectedVerdict;
  description?: string;
}
export function mdeAlert(o: MdeAlertOpts): TelemetryEvent {
  const r = resolve(o);
  const sev = o.severity ?? "critical";
  const a = acct(o.companyId, r.bareUser);
  const alertSev = o.alertSeverity ?? (sev === "critical" ? "High" : sev[0].toUpperCase() + sev.slice(1));
  return {
    id: o.id, ts: o.ts, source: "edr", vendor: VENDOR, event_type: "edr_alert",
    severity: sev, hostname: r.host, src_ip: r.srcIp, user_email: r.email,
    mitre_technique: o.mitre, is_detection: true,
    expected_verdict: o.expectedVerdict, incident_id: o.incidentId,
    description: o.description ?? `${VENDOR} raised ${o.alertTitle} on ${r.host}`,
    raw: {
      "mde.AlertTitle": o.alertTitle,
      ...(o.category ? { "mde.Category": o.category } : {}),
      ...(o.detectionSource ? { "mde.DetectionSource": o.detectionSource } : {}),
      ...(o.evidenceRole ? { "mde.EvidenceRole": o.evidenceRole } : {}),
      ...(o.mdeIncidentId ? { "mde.IncidentId": o.mdeIncidentId } : {}),
      "mde.DeviceName": r.host,
      ...(o.sha256 ? { "mde.SHA256": o.sha256 } : {}),
      ...(o.malwareCategory ? { "malware.category": o.malwareCategory } : {}),
      ...(o.malwareName ? { "malware.name": o.malwareName } : {}),
      "alert.severity": alertSev,
      ...(o.category ? { "alert.category": o.category } : {}),
      ...(o.mitre ? { "threat.technique.id": o.mitre } : {}),
      ...(o.techniqueName ? { "threat.technique.name": o.techniqueName } : {}),
      ...(o.remediation ? { "remediation.action": o.remediation } : {}),
      ...(o.remediationStatus ? { "remediation.status": o.remediationStatus } : {}),
      "AccountName": a.AccountName,
      "AccountDomain": a.AccountDomain,
      "event.action": "alert",
    },
  };
}

// ── Process creation (DeviceProcessEvents) ───────────────────────────────────────────
export interface MdeProcessOpts extends Ctx {
  processName: string;
  processPath?: string;
  cmdline: string;
  parentName?: string;
  parentPid?: number;
  pid?: number;
  sha256?: string;
  signed?: boolean;
  integrity?: "Low" | "Medium" | "High" | "System";
  mitre?: string;
  tactic?: string;
  severity?: Severity;
  isDetection?: boolean;
  description?: string;
}
export function mdeProcess(o: MdeProcessOpts): TelemetryEvent {
  const r = resolve(o);
  const pid = o.pid ?? pidFrom(o.id);
  const ppid = o.parentPid ?? pidFrom(`${o.id}:parent`);
  const path = o.processPath ?? `C:\\Windows\\System32\\${o.processName}`;
  const folder = path.slice(0, path.lastIndexOf("\\")) || path;
  const a = acct(o.companyId, r.bareUser);
  return {
    id: o.id, ts: o.ts, source: "edr", vendor: VENDOR, event_type: "process_create",
    severity: o.severity ?? "low", hostname: r.host, src_ip: r.srcIp, user_email: r.email,
    mitre_technique: o.mitre, mitre_tactic: o.tactic, is_detection: o.isDetection ?? false,
    incident_id: o.incidentId,
    description: o.description ?? `${o.processName} launched on ${r.host}`,
    process: { pid, name: o.processName, path, cmdline: o.cmdline, parent_name: o.parentName, parent_pid: ppid, user: r.domainUser, integrity: o.integrity?.toLowerCase() as "low" | "medium" | "high" | "system" | undefined, hash: o.sha256 ? { sha256: o.sha256 } : undefined },
    raw: {
      "ActionType": "ProcessCreated",
      "DeviceName": r.host,
      "AccountName": a.AccountName,
      "AccountDomain": a.AccountDomain,
      "FileName": o.processName,
      "FolderPath": folder,
      "ProcessCommandLine": o.cmdline,
      "ProcessId": String(pid),
      "InitiatingProcessFileName": o.parentName ?? "",
      "InitiatingProcessId": String(ppid),
      ...(o.sha256 ? { "SHA256": o.sha256, "process.hash.sha256": o.sha256 } : {}),
      ...(o.signed !== undefined ? { "process.code_signature.status": o.signed ? "trusted" : "unsigned" } : {}),
      ...(o.integrity ? { "process.integrity_level": o.integrity } : {}),
      "process.command_line": o.cmdline,
    },
  };
}

// ── Network connection (DeviceNetworkEvents) ─────────────────────────────────────────
export interface MdeNetworkOpts extends Ctx {
  remoteIp: string;
  remotePort: number;
  direction?: "outbound" | "inbound";
  transport?: "tcp" | "udp";
  application?: "tls" | "http" | "dns" | "ssh";
  domain?: string;
  url?: string;
  initiatingProcess?: string;
  mitre?: string;
  tactic?: string;
  severity?: Severity;
  isDetection?: boolean;
  description?: string;
}
export function mdeNetwork(o: MdeNetworkOpts): TelemetryEvent {
  const r = resolve(o);
  const dir = o.direction ?? "outbound";
  const transport = o.transport ?? "tcp";
  const remote = dir === "inbound" ? { src: o.remoteIp, dst: r.srcIp } : { src: r.srcIp, dst: o.remoteIp };
  return {
    id: o.id, ts: o.ts, source: "edr", vendor: VENDOR, event_type: "net_connection",
    severity: o.severity ?? "medium", hostname: r.host, user_email: r.email,
    src_ip: remote.src, dst_ip: remote.dst, dst_port: o.remotePort, protocol: transport,
    mitre_technique: o.mitre, mitre_tactic: o.tactic, is_detection: o.isDetection ?? false,
    incident_id: o.incidentId, network: { domain: o.domain, url: o.url },
    description: o.description ?? `${dir === "inbound" ? "Inbound" : "Outbound"} ${transport.toUpperCase()} connection ${dir === "inbound" ? "to" : "from"} ${r.host} ${dir === "inbound" ? "from" : "to"} ${o.remoteIp}:${o.remotePort}`,
    raw: {
      "ActionType": dir === "inbound" ? "InboundConnectionAccepted" : "ConnectionSuccess",
      "DeviceName": r.host,
      "LocalIP": r.srcIp,
      "RemoteIP": o.remoteIp,
      "RemotePort": String(o.remotePort),
      "Protocol": transport.toUpperCase(),
      "InitiatingProcessFileName": o.initiatingProcess ?? "",
      ...(o.url ? { "RemoteUrl": o.url } : {}),
      "source.ip": remote.src,
      "destination.ip": remote.dst,
      "destination.port": String(o.remotePort),
      "network.direction": dir,
      "network.transport": transport,
      ...(o.application ? { "network.application": o.application } : {}),
      ...(o.domain ? { "destination.domain": o.domain } : {}),
    },
  };
}

// ── DNS request (DeviceNetworkEvents / DnsConnectionInspected) ───────────────────────
export interface MdeDnsOpts extends Ctx {
  domain: string;
  resolvedIp?: string;
  qtype?: string;
  mitre?: string;
  tactic?: string;
  severity?: Severity;
  isDetection?: boolean;
  description?: string;
}
export function mdeDns(o: MdeDnsOpts): TelemetryEvent {
  const r = resolve(o);
  return {
    id: o.id, ts: o.ts, source: "edr", vendor: VENDOR, event_type: "dns_query",
    severity: o.severity ?? "medium", hostname: r.host, src_ip: r.srcIp, user_email: r.email,
    mitre_technique: o.mitre, mitre_tactic: o.tactic, is_detection: o.isDetection ?? false,
    incident_id: o.incidentId,
    dns: { query: o.domain, query_type: o.qtype ?? "A", response: o.resolvedIp },
    network: { domain: o.domain },
    description: o.description ?? `${r.host} resolved ${o.domain}`,
    raw: {
      "ActionType": "DnsConnectionInspected",
      "DeviceName": r.host,
      "RemoteUrl": o.domain,
      "dns.question.name": o.domain,
      "dns.question.type": o.qtype ?? "A",
      ...(o.resolvedIp ? { "dns.resolved_ip": o.resolvedIp } : {}),
    },
  };
}

// ── File creation (DeviceFileEvents) ─────────────────────────────────────────────────
export interface MdeFileOpts extends Ctx {
  path: string;
  sha256?: string | null;       // null → omit a hash (a copied data file has none logged)
  action?: "file_create" | "file_modify" | "file_delete";
  initiatingProcess?: string;
  initiatingCmdline?: string;
  signed?: boolean;
  mitre?: string;
  tactic?: string;
  severity?: Severity;
  isDetection?: boolean;
  description?: string;
}
export function mdeFile(o: MdeFileOpts): TelemetryEvent {
  const r = resolve(o);
  const name = o.path.split(/[\\/]/).pop() ?? o.path;
  const folder = o.path.slice(0, o.path.lastIndexOf("\\")) || o.path;
  const sha256 = o.sha256 === null ? undefined : (o.sha256 ?? makeSha256(`file:${o.path}`));
  const ACTION: Record<NonNullable<MdeFileOpts["action"]>, string> = {
    file_create: "FileCreated", file_modify: "FileModified", file_delete: "FileDeleted",
  };
  return {
    id: o.id, ts: o.ts, source: "edr", vendor: VENDOR, event_type: o.action ?? "file_create",
    severity: o.severity ?? "low", hostname: r.host, src_ip: r.srcIp, user_email: r.email,
    mitre_technique: o.mitre, mitre_tactic: o.tactic, is_detection: o.isDetection ?? false,
    incident_id: o.incidentId,
    file: { name, path: o.path, ...(sha256 ? { sha256 } : {}) },
    description: o.description ?? `${name} written on ${r.host}`,
    raw: {
      "ActionType": ACTION[o.action ?? "file_create"],
      "DeviceName": r.host,
      "FileName": name,
      "FolderPath": folder,
      ...(sha256 ? { "SHA256": sha256, "file.hash.sha256": sha256 } : {}),
      ...(o.initiatingProcess ? { "InitiatingProcessFileName": o.initiatingProcess } : {}),
      ...(o.initiatingCmdline ? { "InitiatingProcessCommandLine": o.initiatingCmdline } : {}),
      ...(o.signed !== undefined ? { "file.signature.status": o.signed ? "trusted" : "unsigned" } : {}),
      "file.path": o.path,
      "file.name": name,
      "event.action": o.action ?? "file_create",
    },
  };
}
