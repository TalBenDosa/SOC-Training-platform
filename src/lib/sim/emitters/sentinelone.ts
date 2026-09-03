/**
 * SentinelOne Singularity log EMITTERS — Deep Visibility / Threat schema.
 *
 * Same contract as the CrowdStrike emitters (see crowdstrike.ts): a typed call renders a
 * complete TelemetryEvent whose raw block uses only registry-valid SentinelOne fields
 * (the s1./sentinelone. prefixes + the shared ECS fields), with host/user/IP drawn from
 * the company asset fabric. The difference is dialect: S1 speaks eventType, mitigation
 * status, and srcProc / tgtFile columns rather than Falcon's event_simpleName + pattern
 * disposition.
 */
import type { TelemetryEvent, Severity, ExpectedVerdict } from "../types";
import { makeSha256 } from "../iocs";
import { type Ctx, resolve, pidFrom, downloadsPath } from "./_core";

const VENDOR = "SentinelOne Singularity";

// ── Detection (Threats) ──────────────────────────────────────────────────────────────
export interface S1DetectionOpts extends Ctx {
  processName: string;
  processPath?: string;
  cmdline?: string;
  parentName?: string;
  sha256?: string;
  threatName: string;
  mitre?: string;
  tactic?: string;
  severity?: Severity;
  action?: "prevented" | "killed" | "quarantined" | "detected";
  confidence?: "malicious" | "suspicious";
  expectedVerdict?: ExpectedVerdict;
  pid?: number;
  parentPid?: number;
  eventType?: "av_detection" | "edr_alert";
  description?: string;
}
const MITIGATION: Record<NonNullable<S1DetectionOpts["action"]>, { status: string; result: string; quarantine: string }> = {
  prevented:   { status: "mitigated",     result: "prevented",      quarantine: "n/a" },
  killed:      { status: "mitigated",     result: "process_killed", quarantine: "n/a" },
  quarantined: { status: "mitigated",     result: "process_killed", quarantine: "quarantined" },
  detected:    { status: "not_mitigated", result: "detected",       quarantine: "n/a" },
};
export function s1Detection(o: S1DetectionOpts): TelemetryEvent {
  const r = resolve(o);
  const sev = o.severity ?? "high";
  const action = o.action ?? "quarantined";
  const m = MITIGATION[action];
  const sha256 = o.sha256 ?? makeSha256(`${o.threatName}:${o.processName}`);
  const path = o.processPath ?? downloadsPath(r.bareUser, o.processName);
  const cmdline = o.cmdline ?? `"${path}"`;
  const pid = o.pid ?? pidFrom(o.id);
  return {
    id: o.id, ts: o.ts, source: "edr", vendor: VENDOR, event_type: o.eventType ?? "av_detection",
    severity: sev, hostname: r.host, src_ip: r.srcIp, user_email: r.email,
    mitre_technique: o.mitre, mitre_tactic: o.tactic, is_detection: true,
    expected_verdict: o.expectedVerdict, incident_id: o.incidentId,
    description: o.description ?? `${VENDOR} ${action === "detected" ? "detected" : "mitigated"} ${o.threatName} on ${r.host}`,
    process: { pid, name: o.processName, path, cmdline, parent_name: o.parentName, parent_pid: o.parentPid, user: r.domainUser, hash: { sha256 } },
    file: { name: o.processName, path, sha256 },
    raw: {
      "s1.eventType": "Threats",
      "s1.threat.threatName": o.threatName,
      "s1.threat.classification": o.threatName.split(/[.\/]/)[0] || "Malware",
      "s1.threat.confidenceLevel": o.confidence ?? "malicious",
      "s1.threat.mitigationStatus": m.status,
      "s1.threat.analystVerdict": o.expectedVerdict === "fp" ? "false_positive" : "undefined",
      "s1.agent.computerName": r.host,
      "s1.agent.uuid": r.sensorId,
      "s1.process.user": r.domainUser,
      "s1.process.name": o.processName,
      "s1.process.cmdline": cmdline,
      "file.hash.sha256": sha256,
      "threat.name": o.threatName,
      "action_result": m.result,
      "quarantine.status": m.quarantine,
      "event.outcome": "success",
    },
  };
}

// ── Process creation (Deep Visibility) ───────────────────────────────────────────────
export interface S1ProcessOpts extends Ctx {
  processName: string;
  processPath?: string;
  cmdline: string;
  parentName?: string;
  parentPid?: number;
  sha256?: string;
  mitre?: string;
  pid?: number;
  signed?: boolean;
  /** when a process ALSO writes a Run/service key (cmd reg add, reg.exe, powershell) */
  registry?: { keyPath: string; valueName: string; valueData: string };
  tactic?: string;
  severity?: Severity;
  isDetection?: boolean;
  description?: string;
}
export function s1Process(o: S1ProcessOpts): TelemetryEvent {
  const r = resolve(o);
  const pid = o.pid ?? pidFrom(o.id);
  const ppid = o.parentPid ?? pidFrom(`${o.id}:parent`);
  const path = o.processPath ?? `C:\\Windows\\System32\\${o.processName}`;
  const reg = o.registry;
  const hive = reg ? reg.keyPath.split("\\")[0].toUpperCase().replace("HKCU", "HKEY_CURRENT_USER").replace("HKLM", "HKEY_LOCAL_MACHINE") : undefined;
  return {
    id: o.id, ts: o.ts, source: "edr", vendor: VENDOR, event_type: reg ? "registry_set" : "process_create",
    severity: o.severity ?? "low", hostname: r.host, src_ip: r.srcIp, user_email: r.email,
    mitre_technique: o.mitre, mitre_tactic: o.tactic, is_detection: o.isDetection ?? false,
    incident_id: o.incidentId,
    description: o.description ?? `${o.processName} launched on ${r.host}`,
    process: { pid, name: o.processName, path, cmdline: o.cmdline, parent_name: o.parentName, parent_pid: ppid, user: r.domainUser, hash: o.sha256 ? { sha256: o.sha256 } : undefined },
    ...(reg ? { registry: { path: reg.keyPath, key: reg.valueName, value: reg.valueData } } : {}),
    raw: {
      "s1.eventType": reg ? "Registry Modification" : "Process Creation",
      "s1.agent.computerName": r.host,
      "s1.agent.uuid": r.sensorId,
      "s1.srcProcName": o.processName,
      "s1.srcProcCmdLine": o.cmdline,
      "s1.srcProcParentName": o.parentName ?? "",
      "s1.srcProcUser": r.domainUser,
      "s1.srcProcPid": String(pid),
      ...(o.sha256 ? { "process.hash.sha256": o.sha256 } : {}),
      ...(o.signed !== undefined ? { "process.code_signature.status": o.signed ? "trusted" : "unsigned" } : {}),
      ...(reg ? { "registry.hive": hive!, "registry.path": reg.keyPath, "registry.value": reg.valueName, "registry.data.strings": reg.valueData } : {}),
      "process.command_line": o.cmdline,
    },
  };
}

// ── Cross-process access (hook / injection / clipboard listener / LSASS read) ────────
export interface S1ProcessAccessOpts extends Ctx {
  processName: string;
  processPath?: string;
  cmdline?: string;
  parentName?: string;
  parentPid?: number;
  pid?: number;
  sha256?: string;
  signed?: boolean;
  targetProcess?: string;
  indicatorName?: string;       // S1 behavioural indicator, e.g. "Process Monitors and Modifies Clipboard Content"
  threatName?: string;
  mitre?: string;
  tactic?: string;
  technique?: string;
  severity?: Severity;
  isDetection?: boolean;
  expectedVerdict?: ExpectedVerdict;
  description?: string;
}
export function s1ProcessAccess(o: S1ProcessAccessOpts): TelemetryEvent {
  const r = resolve(o);
  const pid = o.pid ?? pidFrom(o.id);
  const path = o.processPath ?? `C:\\Users\\${r.bareUser}\\AppData\\Roaming\\${o.processName}`;
  const cmdline = o.cmdline ?? o.processName;
  return {
    id: o.id, ts: o.ts, source: "edr", vendor: VENDOR, event_type: "process_access",
    severity: o.severity ?? "high", hostname: r.host, src_ip: r.srcIp, user_email: r.email,
    mitre_technique: o.mitre, mitre_tactic: o.tactic, is_detection: o.isDetection ?? false,
    expected_verdict: o.expectedVerdict, incident_id: o.incidentId,
    description: o.description ?? `${o.processName} performed suspicious cross-process activity on ${r.host}`,
    process: { pid, name: o.processName, path, cmdline, parent_name: o.parentName, parent_pid: o.parentPid, user: r.domainUser, hash: o.sha256 ? { sha256: o.sha256 } : undefined },
    raw: {
      "s1.eventType": "Indicators",
      "s1.agent.computerName": r.host,
      "s1.agent.uuid": r.sensorId,
      "s1.detection.classification": "Suspicious Activity",
      "s1.detection.classification_source": "Behavioral Engine",
      ...(o.indicatorName ? { "s1.indicator.name": o.indicatorName } : {}),
      ...(o.tactic ? { "s1.indicator.tactic": o.tactic } : {}),
      ...(o.technique ? { "s1.indicator.technique": o.technique } : {}),
      ...(o.mitre ? { "s1.indicator.technique_id": o.mitre } : {}),
      ...(o.threatName ? { "s1.threat.threatName": o.threatName } : {}),
      ...(o.targetProcess ? { "s1.tgtProcName": o.targetProcess } : {}),
      "s1.mitigation_status": "not_mitigated",
      "s1.srcProcName": o.processName,
      ...(o.sha256 ? { "process.hash.sha256": o.sha256 } : {}),
      ...(o.signed !== undefined ? { "process.code_signature.status": o.signed ? "trusted" : "unsigned" } : {}),
    },
  };
}

// ── Network connection (IP Connect) ──────────────────────────────────────────────────
export interface S1NetworkOpts extends Ctx {
  remoteIp: string;
  remotePort: number;
  direction?: "outbound" | "inbound";
  transport?: "tcp" | "udp";
  application?: "tls" | "http" | "dns" | "ssh";
  domain?: string;
  mitre?: string;
  tactic?: string;
  severity?: Severity;
  isDetection?: boolean;
  description?: string;
}
export function s1Network(o: S1NetworkOpts): TelemetryEvent {
  const r = resolve(o);
  const dir = o.direction ?? "outbound";
  const transport = o.transport ?? "tcp";
  const remote = dir === "inbound" ? { src: o.remoteIp, dst: r.srcIp } : { src: r.srcIp, dst: o.remoteIp };
  return {
    id: o.id, ts: o.ts, source: "edr", vendor: VENDOR, event_type: "net_connection",
    severity: o.severity ?? "medium", hostname: r.host, user_email: r.email,
    src_ip: remote.src, dst_ip: remote.dst, dst_port: o.remotePort, protocol: transport,
    mitre_technique: o.mitre, mitre_tactic: o.tactic, is_detection: o.isDetection ?? false,
    incident_id: o.incidentId, network: { domain: o.domain },
    description: o.description ?? `${dir === "inbound" ? "Inbound" : "Outbound"} ${transport.toUpperCase()} connection ${dir === "inbound" ? "to" : "from"} ${r.host} ${dir === "inbound" ? "from" : "to"} ${o.remoteIp}:${o.remotePort}`,
    raw: {
      "s1.eventType": "IP Connect",
      "s1.agent.computerName": r.host,
      "s1.agent.uuid": r.sensorId,
      "s1.connectionDirection": dir === "inbound" ? "INCOMING" : "OUTGOING",
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

// ── DNS request ──────────────────────────────────────────────────────────────────────
export interface S1DnsOpts extends Ctx {
  domain: string;
  resolvedIp?: string;
  qtype?: string;
  mitre?: string;
  tactic?: string;
  severity?: Severity;
  isDetection?: boolean;
  description?: string;
}
export function s1Dns(o: S1DnsOpts): TelemetryEvent {
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
      "s1.eventType": "DNS",
      "s1.agent.computerName": r.host,
      "s1.agent.uuid": r.sensorId,
      "s1.dnsRequest": o.domain,
      "dns.question.name": o.domain,
      "dns.question.type": o.qtype ?? "A",
      ...(o.resolvedIp ? { "dns.resolved_ip": o.resolvedIp } : {}),
    },
  };
}

// ── File creation ────────────────────────────────────────────────────────────────────
export interface S1FileOpts extends Ctx {
  path: string;
  sha256?: string;
  action?: "file_create" | "file_modify" | "file_delete";
  mitre?: string;
  tactic?: string;
  severity?: Severity;
  isDetection?: boolean;
  description?: string;
}
export function s1File(o: S1FileOpts): TelemetryEvent {
  const r = resolve(o);
  const name = o.path.split(/[\\/]/).pop() ?? o.path;
  const sha256 = o.sha256 ?? makeSha256(`file:${o.path}`);
  return {
    id: o.id, ts: o.ts, source: "edr", vendor: VENDOR, event_type: o.action ?? "file_create",
    severity: o.severity ?? "low", hostname: r.host, src_ip: r.srcIp, user_email: r.email,
    mitre_technique: o.mitre, mitre_tactic: o.tactic, is_detection: o.isDetection ?? false,
    incident_id: o.incidentId,
    file: { name, path: o.path, sha256 },
    description: o.description ?? `${name} written on ${r.host}`,
    raw: {
      "s1.eventType": "File Creation",
      "s1.agent.computerName": r.host,
      "s1.agent.uuid": r.sensorId,
      "s1.tgtFilePath": o.path,
      "s1.tgtFileSha256": sha256,
      "file.path": o.path,
      "file.name": name,
      "file.hash.sha256": sha256,
      "event.action": o.action ?? "file_create",
    },
  };
}
