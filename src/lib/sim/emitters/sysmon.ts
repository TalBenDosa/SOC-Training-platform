/**
 * Microsoft Sysmon log EMITTERS.
 *
 * The free host-telemetry sensor that sits alongside (or instead of) an EDR — the
 * process/network/file/DNS/registry evidence an analyst walks when the shop runs
 * Sysmon into the SIEM. Same contract as the endpoint emitters: a typed call
 * renders a complete TelemetryEvent whose raw block uses only registry-valid
 * Sysmon fields (the winlog. / winlog.event_data. / sysmon. prefixes + the shared
 * ECS process./file./dns./destination.* fields), with host, IP and user drawn
 * from the company asset fabric so the console shows the same identity the feed did.
 *
 * Sysmon is source:"sysmon". Process/network/file events carry a process node so
 * the EDR console can still reconstruct the tree.
 */
import type { TelemetryEvent, Severity } from "../types";
import { makeSha256 } from "../iocs";
import { resolve, pidFrom, type Ctx } from "./_core";

const VENDOR = "Microsoft Sysmon";
const CHANNEL = "Microsoft-Windows-Sysmon/Operational";
const PROVIDER = "Microsoft-Windows-Sysmon";

function base(o: Ctx & { severity?: Severity }, r: ReturnType<typeof resolve>) {
  return {
    "winlog.channel": CHANNEL,
    "winlog.provider_name": PROVIDER,
    "winlog.computer_name": r.host,
  } as Record<string, string>;
}

// ── Event 1 — Process creation ────────────────────────────────────────────────────────
export interface SysmonProcessOpts extends Ctx {
  processName: string;
  processPath?: string;
  cmdline: string;
  parentName?: string;
  parentPath?: string;
  parentCmdline?: string;
  pid?: number;
  parentPid?: number;
  sha256?: string;
  signed?: boolean;
  integrity?: "Low" | "Medium" | "High" | "System";
  originalFileName?: string;
  mitre?: string;
  tactic?: string;
  severity?: Severity;
  isDetection?: boolean;
  description?: string;
}
export function sysmonProcess(o: SysmonProcessOpts): TelemetryEvent {
  const r = resolve(o);
  const pid = o.pid ?? pidFrom(o.id);
  const ppid = o.parentPid ?? pidFrom(`${o.id}:parent`);
  const path = o.processPath ?? `C:\\Windows\\System32\\${o.processName}`;
  const parentPath = o.parentPath ?? (o.parentName ? `C:\\Windows\\explorer.exe` : undefined);
  const sha256 = o.sha256 ?? makeSha256(`sysmon:${o.processName}:${o.cmdline}`);
  return {
    id: o.id, ts: o.ts, source: "sysmon", vendor: VENDOR, event_type: "process_create",
    severity: o.severity ?? "low", hostname: r.host, src_ip: r.srcIp, user_email: r.email,
    mitre_technique: o.mitre, mitre_tactic: o.tactic, is_detection: o.isDetection ?? false, incident_id: o.incidentId,
    process: { pid, name: o.processName, path, cmdline: o.cmdline, parent_name: o.parentName, parent_pid: ppid, user: r.domainUser, hash: { sha256 } },
    description: o.description ?? `${o.processName} created on ${r.host} (Sysmon 1)`,
    raw: {
      ...base(o, r),
      "winlog.event_id": "1",
      "winlog.event_data.Image": path,
      "winlog.event_data.CommandLine": o.cmdline,
      "winlog.event_data.ProcessId": String(pid),
      ...(o.parentName ? { "winlog.event_data.ParentImage": parentPath ?? o.parentName } : {}),
      ...(o.parentCmdline ? { "winlog.event_data.ParentCommandLine": o.parentCmdline } : {}),
      "winlog.event_data.ParentProcessId": String(ppid),
      "winlog.event_data.User": r.domainUser,
      "winlog.event_data.Hashes": `SHA256=${sha256}`,
      "winlog.event_data.IntegrityLevel": o.integrity ?? "Medium",
      ...(o.originalFileName ? { "winlog.event_data.OriginalFileName": o.originalFileName } : {}),
      "event.code": "1",
      "event.category": "process",
      "event.type": "start",
      "event.action": "process-created",
      "process.executable": path,
      "process.name": o.processName,
      "process.pid": String(pid),
      "process.command_line": o.cmdline,
      ...(o.parentName ? { "process.parent.name": o.parentName } : {}),
      "process.parent.pid": String(ppid),
      "process.hash.sha256": sha256,
      ...(o.signed !== undefined ? { "process.code_signature.status": o.signed ? "trusted" : "unsigned" } : {}),
      "user.name": r.bareUser,
      "host.name": r.host,
    },
  };
}

// ── Event 3 — Network connection ──────────────────────────────────────────────────────
export interface SysmonNetworkOpts extends Ctx {
  processName: string;
  processPath?: string;
  pid?: number;
  remoteIp: string;
  remotePort: number;
  remoteHost?: string;
  transport?: "tcp" | "udp";
  mitre?: string;
  tactic?: string;
  severity?: Severity;
  isDetection?: boolean;
  description?: string;
}
export function sysmonNetwork(o: SysmonNetworkOpts): TelemetryEvent {
  const r = resolve(o);
  const pid = o.pid ?? pidFrom(o.id);
  const path = o.processPath ?? `C:\\Windows\\System32\\${o.processName}`;
  const transport = o.transport ?? "tcp";
  return {
    id: o.id, ts: o.ts, source: "sysmon", vendor: VENDOR, event_type: "net_connection",
    severity: o.severity ?? "medium", hostname: r.host, src_ip: r.srcIp, dst_ip: o.remoteIp,
    dst_port: o.remotePort, protocol: transport, user_email: r.email,
    mitre_technique: o.mitre, mitre_tactic: o.tactic, is_detection: o.isDetection ?? false, incident_id: o.incidentId,
    network: { domain: o.remoteHost },
    description: o.description ?? `${o.processName} connected to ${o.remoteHost ?? o.remoteIp}:${o.remotePort} (Sysmon 3)`,
    raw: {
      ...base(o, r),
      "winlog.event_id": "3",
      "winlog.event_data.Image": path,
      "winlog.event_data.ProcessId": String(pid),
      "winlog.event_data.User": r.domainUser,
      "winlog.event_data.Protocol": transport,
      "winlog.event_data.SourceIp": r.srcIp,
      "winlog.event_data.DestinationIp": o.remoteIp,
      "winlog.event_data.DestinationPort": String(o.remotePort),
      ...(o.remoteHost ? { "winlog.event_data.DestinationHostname": o.remoteHost } : {}),
      "winlog.event_data.Initiated": "true",
      "event.code": "3",
      "event.category": "network",
      "event.type": "connection",
      "event.action": "network-connection",
      "process.executable": path,
      "process.name": o.processName,
      "process.pid": String(pid),
      "source.ip": r.srcIp,
      "destination.ip": o.remoteIp,
      "destination.port": String(o.remotePort),
      ...(o.remoteHost ? { "destination.domain": o.remoteHost } : {}),
      "network.transport": transport,
      "host.name": r.host,
    },
  };
}

// ── Event 11 — File create ────────────────────────────────────────────────────────────
export interface SysmonFileOpts extends Ctx {
  processName: string;
  processPath?: string;
  pid?: number;
  path: string;                    // TargetFilename
  mitre?: string;
  tactic?: string;
  severity?: Severity;
  isDetection?: boolean;
  description?: string;
}
export function sysmonFile(o: SysmonFileOpts): TelemetryEvent {
  const r = resolve(o);
  const pid = o.pid ?? pidFrom(o.id);
  const image = o.processPath ?? `C:\\Windows\\System32\\${o.processName}`;
  const name = o.path.split(/[\\/]/).pop() ?? o.path;
  return {
    id: o.id, ts: o.ts, source: "sysmon", vendor: VENDOR, event_type: "file_create",
    severity: o.severity ?? "low", hostname: r.host, src_ip: r.srcIp, user_email: r.email,
    mitre_technique: o.mitre, mitre_tactic: o.tactic, is_detection: o.isDetection ?? false, incident_id: o.incidentId,
    file: { name, path: o.path },
    description: o.description ?? `${name} written by ${o.processName} on ${r.host} (Sysmon 11)`,
    raw: {
      ...base(o, r),
      "winlog.event_id": "11",
      "winlog.event_data.Image": image,
      "winlog.event_data.TargetFilename": o.path,
      "winlog.event_data.ProcessId": String(pid),
      "winlog.event_data.CreationUtcTime": o.ts,
      "event.code": "11",
      "event.category": "file",
      "event.type": "creation",
      "event.action": "file-created",
      "process.executable": image,
      "process.name": o.processName,
      "process.pid": String(pid),
      "file.path": o.path,
      "file.name": name,
      "host.name": r.host,
    },
  };
}

// ── Event 22 — DNS query ──────────────────────────────────────────────────────────────
export interface SysmonDnsOpts extends Ctx {
  processName: string;
  processPath?: string;
  pid?: number;
  domain: string;
  resolvedIp?: string;
  mitre?: string;
  tactic?: string;
  severity?: Severity;
  isDetection?: boolean;
  description?: string;
}
export function sysmonDns(o: SysmonDnsOpts): TelemetryEvent {
  const r = resolve(o);
  const pid = o.pid ?? pidFrom(o.id);
  const image = o.processPath ?? `C:\\Windows\\System32\\${o.processName}`;
  return {
    id: o.id, ts: o.ts, source: "sysmon", vendor: VENDOR, event_type: "dns_query",
    severity: o.severity ?? "medium", hostname: r.host, src_ip: r.srcIp, user_email: r.email,
    mitre_technique: o.mitre, mitre_tactic: o.tactic, is_detection: o.isDetection ?? false, incident_id: o.incidentId,
    dns: { query: o.domain, query_type: "A", response: o.resolvedIp }, network: { domain: o.domain },
    description: o.description ?? `${o.processName} resolved ${o.domain} on ${r.host} (Sysmon 22)`,
    raw: {
      ...base(o, r),
      "winlog.event_id": "22",
      "winlog.event_data.Image": image,
      "winlog.event_data.ProcessId": String(pid),
      "winlog.event_data.QueryName": o.domain,
      ...(o.resolvedIp ? { "winlog.event_data.QueryResults": `::ffff:${o.resolvedIp};` } : {}),
      "winlog.event_data.QueryStatus": "0",
      "event.code": "22",
      "event.category": "network",
      "event.type": "info",
      "event.action": "dns-query",
      "process.executable": image,
      "process.name": o.processName,
      "process.pid": String(pid),
      "dns.question.name": o.domain,
      "dns.question.type": "A",
      ...(o.resolvedIp ? { "dns.resolved_ip": o.resolvedIp } : {}),
      "host.name": r.host,
    },
  };
}

// ── Event 13 — Registry value set ─────────────────────────────────────────────────────
export interface SysmonRegistryOpts extends Ctx {
  processName: string;
  processPath?: string;
  pid?: number;
  targetObject: string;            // full registry path\value
  details: string;                 // the value written
  mitre?: string;
  tactic?: string;
  severity?: Severity;
  isDetection?: boolean;
  description?: string;
}
export function sysmonRegistry(o: SysmonRegistryOpts): TelemetryEvent {
  const r = resolve(o);
  const pid = o.pid ?? pidFrom(o.id);
  const image = o.processPath ?? `C:\\Windows\\System32\\${o.processName}`;
  const key = o.targetObject.substring(0, o.targetObject.lastIndexOf("\\"));
  const valueName = o.targetObject.substring(o.targetObject.lastIndexOf("\\") + 1);
  return {
    id: o.id, ts: o.ts, source: "sysmon", vendor: VENDOR, event_type: "registry_set",
    severity: o.severity ?? "high", hostname: r.host, src_ip: r.srcIp, user_email: r.email,
    mitre_technique: o.mitre, mitre_tactic: o.tactic, is_detection: o.isDetection ?? false, incident_id: o.incidentId,
    registry: { path: key, key: valueName, value: o.details },
    description: o.description ?? `${o.processName} set ${o.targetObject} on ${r.host} (Sysmon 13)`,
    raw: {
      ...base(o, r),
      "winlog.event_id": "13",
      "winlog.event_data.Image": image,
      "winlog.event_data.ProcessId": String(pid),
      "winlog.event_data.EventType": "SetValue",
      "winlog.event_data.TargetObject": o.targetObject,
      "winlog.event_data.Details": o.details,
      "event.code": "13",
      "event.category": "registry",
      "event.type": "change",
      "event.action": "registry-value-set",
      "process.executable": image,
      "process.name": o.processName,
      "process.pid": String(pid),
      "host.name": r.host,
    },
  };
}
