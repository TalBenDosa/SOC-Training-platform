/**
 * CrowdStrike Falcon log EMITTERS.
 *
 * Instead of hand-typing a `raw: { "crowdstrike.event_simpleName": … }` block per event
 * — the artisanal process that produced years of field drift (snake_case vs camelCase,
 * invented `cs.*` keys, `crowdstrike.Confidence` that doesn't exist) — an author calls a
 * typed function that RENDERS a well-formed Falcon event: a Detection Summary, a
 * ProcessRollup2, a NetworkConnectIP4, a DnsRequest, a file write. Every key an emitter
 * writes is drawn from the CrowdStrike vocabulary in scripts/log-field-registry.json
 * (exactFields + the crowdstrike./file./pe./process. prefixes), so emitter output passes
 * the log-field gate by construction — correctness is structural, not checked after.
 *
 * Each emitter returns a complete TelemetryEvent: the structured fields the feed and the
 * EDR console read (process tree, file, network, hostname, src_ip, user, mitre) AND the
 * vendor-native raw block. Host / user / IP default from the company asset fabric
 * (fabric.ts) when not given, so a whole scenario reads as one company's estate and the
 * EDR console shows the same host + IP the SIEM feed did.
 */
import type { TelemetryEvent, Severity, ExpectedVerdict } from "../types";
import { makeSha256 } from "../iocs";
import { type Ctx, resolve, pidFrom, SEV_NAME, downloadsPath } from "./_core";

const VENDOR = "CrowdStrike Falcon";

// ── Detection / prevention (DetectionSummaryEvent) ───────────────────────────────────
export interface CsDetectionOpts extends Ctx {
  processName: string;          // e.g. "update.exe"
  processPath?: string;         // full on-disk path; defaults under the user's Downloads
  cmdline?: string;
  parentName?: string;          // launching process, e.g. "explorer.exe"
  sha256?: string;              // known-bad hash; defaults to a deterministic one
  threatName: string;          // e.g. "Trojan.GenericKD"
  mitre?: string;               // technique id, e.g. "T1204.002"
  tactic?: string;              // human tactic, e.g. "Execution"
  technique?: string;           // human technique, e.g. "User Execution: Malicious File"
  severity?: Severity;
  action?: "prevented" | "killed" | "quarantined" | "detected"; // Falcon pattern disposition
  expectedVerdict?: ExpectedVerdict;
  pid?: number;                 // pin the PID (else deterministic from id) to keep a tree stable
  parentPid?: number;
  eventType?: "av_detection" | "edr_alert";
  description?: string;
}
const DISPO: Record<NonNullable<CsDetectionOpts["action"]>, { desc: string; result: string; quarantine: string }> = {
  prevented:   { desc: "Prevention, process blocked",                 result: "prevented",      quarantine: "n/a" },
  killed:      { desc: "Prevention, process killed",                  result: "process_killed", quarantine: "n/a" },
  quarantined: { desc: "Prevention, process killed, quarantine file", result: "process_killed", quarantine: "quarantined" },
  detected:    { desc: "Detection only, no action taken",             result: "detected",       quarantine: "n/a" },
};
export function csDetection(o: CsDetectionOpts): TelemetryEvent {
  const r = resolve(o);
  const sev = o.severity ?? "high";
  const action = o.action ?? "quarantined";
  const d = DISPO[action];
  const sha256 = o.sha256 ?? makeSha256(`${o.threatName}:${o.processName}`);
  const path = o.processPath ?? downloadsPath(r.bareUser, o.processName);
  const cmdline = o.cmdline ?? `"${path}"`;
  const pid = o.pid ?? pidFrom(o.id);
  return {
    id: o.id, ts: o.ts, source: "edr", vendor: VENDOR, event_type: o.eventType ?? "av_detection",
    severity: sev, hostname: r.host, src_ip: r.srcIp,
    user_email: r.email, mitre_technique: o.mitre, mitre_tactic: o.tactic,
    is_detection: true, expected_verdict: o.expectedVerdict, incident_id: o.incidentId,
    description: o.description ?? `${VENDOR} ${action === "detected" ? "detected" : "blocked"} ${o.threatName} on ${r.host}`,
    process: { pid, name: o.processName, path, cmdline, parent_name: o.parentName, parent_pid: o.parentPid, user: r.domainUser, hash: { sha256 } },
    file: { name: o.processName, path, sha256 },
    raw: {
      "crowdstrike.event_simpleName": "DetectionSummaryEvent",
      "crowdstrike.DetectName": o.threatName,
      "crowdstrike.Tactic": o.tactic ?? "",
      "crowdstrike.Technique": o.technique ?? "",
      "crowdstrike.PatternDispositionDescription": d.desc,
      "crowdstrike.SeverityName": SEV_NAME[sev],
      "crowdstrike.ComputerName": r.host,
      "crowdstrike.UserName": r.domainUser,
      "crowdstrike.FileName": o.processName,
      "crowdstrike.FilePath": path,
      "crowdstrike.CommandLine": cmdline,
      "crowdstrike.aid": r.sensorId,
      "file.hash.sha256": sha256,
      "threat.name": o.threatName,
      "action_result": d.result,
      "quarantine.status": d.quarantine,
      "event.outcome": "success",
    },
  };
}

// ── Process creation telemetry (ProcessRollup2) ──────────────────────────────────────
export interface CsProcessOpts extends Ctx {
  processName: string;
  processPath?: string;
  cmdline: string;
  parentName?: string;
  parentPid?: number;
  pid?: number;                 // pin the PID to keep a multi-event tree stable
  sha256?: string;
  signed?: boolean;             // authenticode result; drives the console's signed field
  mitre?: string;
  tactic?: string;
  severity?: Severity;
  isDetection?: boolean;        // true → shows as a feed alert; else pivot-only tree telemetry
  description?: string;
}
export function csProcess(o: CsProcessOpts): TelemetryEvent {
  const r = resolve(o);
  const pid = o.pid ?? pidFrom(o.id);
  const ppid = o.parentPid ?? pidFrom(`${o.id}:parent`);
  const path = o.processPath ?? `C:\\Windows\\System32\\${o.processName}`;
  const sha256 = o.sha256;
  return {
    id: o.id, ts: o.ts, source: "edr", vendor: VENDOR, event_type: "process_create",
    severity: o.severity ?? "low", hostname: r.host, src_ip: r.srcIp, user_email: r.email,
    mitre_technique: o.mitre, mitre_tactic: o.tactic, is_detection: o.isDetection ?? false,
    incident_id: o.incidentId,
    description: o.description ?? `${o.processName} launched on ${r.host}`,
    process: { pid, name: o.processName, path, cmdline: o.cmdline, parent_name: o.parentName, parent_pid: ppid, user: r.domainUser, hash: sha256 ? { sha256 } : undefined },
    raw: {
      "crowdstrike.event_simpleName": "ProcessRollup2",
      "crowdstrike.ComputerName": r.host,
      "crowdstrike.UserName": r.domainUser,
      "crowdstrike.FileName": o.processName,
      "crowdstrike.FilePath": path,
      "crowdstrike.CommandLine": o.cmdline,
      "crowdstrike.ParentProcessName": o.parentName ?? "",
      "crowdstrike.TargetProcessId_decimal": String(pid),
      "crowdstrike.ContextProcessId_decimal": String(ppid),
      "crowdstrike.aid": r.sensorId,
      ...(sha256 ? { "process.hash.sha256": sha256 } : {}),
      ...(o.signed !== undefined ? { "process.code_signature.status": o.signed ? "trusted" : "unsigned" } : {}),
      "process.command_line": o.cmdline,
    },
  };
}

// ── Registry persistence (AsepValueUpdate — Run key, service, …) ─────────────────────
export interface CsRegistryOpts extends Ctx {
  keyPath: string;              // e.g. HKCU\Software\Microsoft\Windows\CurrentVersion\Run
  valueName: string;           // e.g. WindowsUpdateHelper
  valueData: string;           // e.g. the path the value points at
  writerProcess?: string;      // the process that set the value
  mitre?: string;
  tactic?: string;
  severity?: Severity;
  isDetection?: boolean;
  description?: string;
}
export function csRegistry(o: CsRegistryOpts): TelemetryEvent {
  const r = resolve(o);
  const hive = o.keyPath.split("\\")[0].toUpperCase().replace("HKCU", "HKEY_CURRENT_USER").replace("HKLM", "HKEY_LOCAL_MACHINE");
  return {
    id: o.id, ts: o.ts, source: "edr", vendor: VENDOR, event_type: "registry_set",
    severity: o.severity ?? "high", hostname: r.host, src_ip: r.srcIp, user_email: r.email,
    mitre_technique: o.mitre, mitre_tactic: o.tactic, is_detection: o.isDetection ?? false,
    incident_id: o.incidentId,
    registry: { path: o.keyPath, key: o.valueName, value: o.valueData },
    description: o.description ?? `Run value ${o.valueName} written on ${r.host}`,
    raw: {
      "crowdstrike.event_simpleName": "AsepValueUpdate",
      "crowdstrike.ComputerName": r.host,
      "crowdstrike.UserName": r.domainUser,
      "crowdstrike.aid": r.sensorId,
      ...(o.writerProcess ? { "crowdstrike.FileName": o.writerProcess } : {}),
      "registry.hive": hive,
      "registry.path": o.keyPath,
      "registry.value": o.valueName,
      "registry.data.strings": o.valueData,
      "event.action": "registry_value_set",
    },
  };
}

// ── Cross-process access (hook / injection / LSASS read) ─────────────────────────────
export interface CsProcessAccessOpts extends Ctx {
  processName: string;          // the ACTING process
  processPath?: string;
  cmdline?: string;
  parentName?: string;
  parentPid?: number;
  pid?: number;
  sha256?: string;
  signed?: boolean;
  targetProcess?: string;       // the process being read/hooked/injected
  targetPid?: number;
  api?: string;                 // e.g. SetWindowsHookExW / OpenProcess / WriteProcessMemory
  threatName?: string;          // detection name when this is alert-grade
  mitre?: string;
  tactic?: string;
  technique?: string;
  severity?: Severity;
  isDetection?: boolean;
  expectedVerdict?: ExpectedVerdict;
  description?: string;
}
export function csProcessAccess(o: CsProcessAccessOpts): TelemetryEvent {
  const r = resolve(o);
  const pid = o.pid ?? pidFrom(o.id);
  const path = o.processPath ?? `C:\\Users\\${r.bareUser}\\AppData\\Roaming\\${o.processName}`;
  const cmdline = o.cmdline ?? o.processName;
  return {
    id: o.id, ts: o.ts, source: "edr", vendor: VENDOR, event_type: "process_access",
    severity: o.severity ?? "high", hostname: r.host, src_ip: r.srcIp, user_email: r.email,
    mitre_technique: o.mitre, mitre_tactic: o.tactic, is_detection: o.isDetection ?? false,
    expected_verdict: o.expectedVerdict, incident_id: o.incidentId,
    description: o.description ?? `${o.processName} accessed ${o.targetProcess ?? "another process"} on ${r.host}`,
    process: { pid, name: o.processName, path, cmdline, parent_name: o.parentName, parent_pid: o.parentPid, user: r.domainUser, hash: o.sha256 ? { sha256: o.sha256 } : undefined },
    raw: {
      "crowdstrike.event_simpleName": o.api?.startsWith("SetWindowsHook") ? "SuspiciousWindowsHook" : "CrossProcessOpen",
      "crowdstrike.ComputerName": r.host,
      "crowdstrike.UserName": r.domainUser,
      "crowdstrike.aid": r.sensorId,
      "crowdstrike.FileName": o.processName,
      "crowdstrike.FilePath": path,
      "crowdstrike.CommandLine": cmdline,
      ...(o.threatName ? { "crowdstrike.DetectName": o.threatName } : {}),
      ...(o.tactic ? { "crowdstrike.Tactic": o.tactic } : {}),
      ...(o.technique ? { "crowdstrike.Technique": o.technique } : {}),
      ...(o.api ? { "crowdstrike.HookApi": o.api } : {}),
      ...(o.targetProcess ? { "crowdstrike.CrossProcessTargetName": o.targetProcess } : {}),
      ...(o.targetPid ? { "crowdstrike.CrossProcessTargetPid": String(o.targetPid) } : {}),
      ...(o.sha256 ? { "process.hash.sha256": o.sha256 } : {}),
      ...(o.signed !== undefined ? { "process.code_signature.status": o.signed ? "trusted" : "unsigned" } : {}),
      "event.action": "process_access",
    },
  };
}

// ── Network connection (NetworkConnectIP4) ───────────────────────────────────────────
export interface CsNetworkOpts extends Ctx {
  remoteIp: string;
  remotePort: number;
  direction?: "outbound" | "inbound";
  transport?: "tcp" | "udp";
  application?: "tls" | "http" | "dns" | "ssh";  // layer-7, its own field (not proto)
  domain?: string;
  processName?: string;
  mitre?: string;
  tactic?: string;
  severity?: Severity;
  isDetection?: boolean;
  description?: string;
}
export function csNetwork(o: CsNetworkOpts): TelemetryEvent {
  const r = resolve(o);
  const dir = o.direction ?? "outbound";
  const transport = o.transport ?? "tcp";
  const remote = dir === "inbound" ? { src: o.remoteIp, dst: r.srcIp } : { src: r.srcIp, dst: o.remoteIp };
  return {
    id: o.id, ts: o.ts, source: "edr", vendor: VENDOR, event_type: "net_connection",
    severity: o.severity ?? "medium", hostname: r.host, user_email: r.email,
    src_ip: remote.src, dst_ip: remote.dst, dst_port: o.remotePort, protocol: transport,
    mitre_technique: o.mitre, mitre_tactic: o.tactic, is_detection: o.isDetection ?? false,
    incident_id: o.incidentId,
    network: { domain: o.domain },
    description: o.description ?? `${dir === "inbound" ? "Inbound" : "Outbound"} ${transport.toUpperCase()} connection ${dir === "inbound" ? "to" : "from"} ${r.host} ${dir === "inbound" ? "from" : "to"} ${o.remoteIp}:${o.remotePort}`,
    raw: {
      "crowdstrike.event_simpleName": "NetworkConnectIP4",
      "crowdstrike.ComputerName": r.host,
      "crowdstrike.aid": r.sensorId,
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

// ── DNS request (DnsRequest) ─────────────────────────────────────────────────────────
export interface CsDnsOpts extends Ctx {
  domain: string;
  resolvedIp?: string;
  qtype?: string;               // "A" | "AAAA" | "TXT" …
  mitre?: string;
  tactic?: string;
  severity?: Severity;
  isDetection?: boolean;
  description?: string;
}
export function csDns(o: CsDnsOpts): TelemetryEvent {
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
      "crowdstrike.event_simpleName": "DnsRequest",
      "crowdstrike.ComputerName": r.host,
      "crowdstrike.aid": r.sensorId,
      "dns.question.name": o.domain,
      "dns.question.type": o.qtype ?? "A",
      ...(o.resolvedIp ? { "dns.resolved_ip": o.resolvedIp } : {}),
    },
  };
}

// ── File write (NewExecutableWritten / file op) ──────────────────────────────────────
export interface CsFileOpts extends Ctx {
  path: string;
  sha256?: string | null;       // null → omit a hash (a growing data buffer has none)
  action?: "file_create" | "file_modify" | "file_delete";
  signed?: boolean;
  mitre?: string;
  tactic?: string;
  severity?: Severity;
  isDetection?: boolean;
  description?: string;
}
export function csFile(o: CsFileOpts): TelemetryEvent {
  const r = resolve(o);
  const name = o.path.split(/[\\/]/).pop() ?? o.path;
  const action = o.action ?? "file_create";
  const isExe = /\.(exe|dll|sys|scr)$/i.test(name);
  const sha256 = o.sha256 === null ? undefined : (o.sha256 ?? makeSha256(`file:${o.path}`));
  // A new PE is "NewExecutableWritten"; anything else is a plain FileWritten/Modified.
  const simpleName = action === "file_delete" ? "FileDeleted"
    : action === "file_modify" ? "FileWritten"
    : isExe ? "NewExecutableWritten" : "FileWritten";
  return {
    id: o.id, ts: o.ts, source: "edr", vendor: VENDOR, event_type: action,
    severity: o.severity ?? "low", hostname: r.host, src_ip: r.srcIp, user_email: r.email,
    mitre_technique: o.mitre, mitre_tactic: o.tactic, is_detection: o.isDetection ?? false,
    incident_id: o.incidentId,
    file: { name, path: o.path, ...(sha256 ? { sha256 } : {}) },
    description: o.description ?? `${name} written on ${r.host}`,
    raw: {
      "crowdstrike.event_simpleName": simpleName,
      "crowdstrike.ComputerName": r.host,
      "crowdstrike.aid": r.sensorId,
      "file.path": o.path,
      "file.name": name,
      ...(sha256 ? { "file.hash.sha256": sha256 } : {}),
      ...(o.signed !== undefined ? { "file.signature.status": o.signed ? "trusted" : "unsigned" } : {}),
      "event.action": action === "file_delete" ? "file_deleted" : action === "file_modify" ? "file_modified" : "file_created",
    },
  };
}
