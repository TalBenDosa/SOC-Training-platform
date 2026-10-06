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
import type { TelemetryEvent, Severity, ExpectedVerdict, EventType } from "../types";
import { makeSha256 } from "../iocs";
import { hashString } from "../rng";
import { type Ctx, resolve, pidFrom, SEV_NAME, downloadsPath } from "./_core";
import { ecsTechnique, ecsCodeSignature, type SignState } from "@/lib/logs/ecsFields";

const VENDOR = "CrowdStrike Falcon";

// ── Falcon field dictionary helpers ──────────────────────────────────────────────────
// Falcon keys a process by its OWN id, not the OS PID:
//   TargetProcessId  — Falcon's unique process id (UPID) of the process the event is about
//   ParentProcessId  — the parent's Falcon UPID (ProcessRollup2)
//   ContextProcessId — the Falcon UPID of the process that PERFORMED a network / DNS /
//                      file action (NetworkConnectIP4, DnsRequest, …) — i.e. that
//                      process's TargetProcessId
//   RawProcessId     — the operating-system PID (what Task Manager / ps shows)
// The UPID is derived from (sensor, OS pid) so a child's ParentProcessId always equals
// its parent's TargetProcessId, and a connection's ContextProcessId equals the
// connecting process's TargetProcessId — the pivot an analyst actually performs.
export function falconUpid(aid: string, osPid: number): string {
  const h = hashString(`upid:${aid}:${osPid}`);
  return String(4_294_967_296 + (h % 900_000_000) * 97 + (osPid % 97));
}
/** ImageFileName as the sensor records it: an NT device path on Windows. */
function imageFileName(path: string): string {
  if (!/^[A-Za-z]:\\/.test(path)) return path;             // Linux / macOS: already absolute
  return `\\Device\\HarddiskVolume3\\${path.slice(3)}`;
}
/** Falcon FilePath is the containing directory (with a trailing separator). */
function dirOf(path: string): string {
  const i = Math.max(path.lastIndexOf("\\"), path.lastIndexOf("/"));
  return i >= 0 ? path.slice(0, i + 1) : path;
}
function platformOf(path: string): "Win" | "Lin" | "Mac" {
  if (/^[A-Za-z]:\\/.test(path)) return "Win";
  return /^\/(Applications|Users|Library|System|private)\//.test(path) ? "Mac" : "Lin";
}
/** A stable MD5-shaped digest paired with a SHA256 (both hashes describe one file). */
export function md5For(sha256: string): string {
  return makeSha256(`md5:${sha256}`).slice(0, 32);
}
// Falcon IntegrityLevel is the mandatory-label RID in decimal.
const INTEG_RID = { low: "4096", medium: "8192", high: "12288", system: "16384" } as const;

// ── Incident alert (DetectionSummaryEvent, no process node) ──────────────────────────
// A behavioural Falcon detection that summarises a chain (or a browser/renderer finding)
// and carries NO process of its own — the alert row that opens the ticket, shown in the
// feed/timeline rather than as another tree node. Use csDetection when the alert IS a
// concrete flagged process+hash; use csAlert when it is a behavioural summary.
export interface CsAlertOpts extends Ctx {
  threatName: string;           // crowdstrike.DetectName
  detail?: string;              // crowdstrike.DetectDescription
  mitre?: string;
  tactic?: string;
  technique?: string;
  malwareCategory?: string;     // e.g. "cryptominer"
  action?: "detected" | "killed" | "quarantined" | "prevented";
  processTree?: string;         // "explorer.exe > WINWORD.EXE > powershell.exe" → FileName / ParentImageFileName / GrandparentImageFileName
  severity?: Severity;
  expectedVerdict?: ExpectedVerdict;
  isDetection?: boolean;        // default true; set false for a precursor summary that isn't the ticket-opener
  runAsUser?: string;           // UserName override (verbatim, e.g. "root")
  extra?: Record<string, string | number | boolean>; // extra registry-valid raw fields (host.os.*, crowdstrike.*)
  // The triggering process, as the DetectionSummaryEvent records it. A real Falcon
  // detection always names the process + its hashes; pass these so the alert is
  // pivotable on its own (FileName / FilePath / CommandLine / SHA256String / MD5String).
  processName?: string;
  processPath?: string;
  cmdline?: string;
  sha256?: string;
  pid?: number;
  parentPath?: string;          // ParentImageFileName (full path)
  parentCmdline?: string;       // ParentCommandLine
  grandparentPath?: string;     // GrandparentImageFileName
  description?: string;
}
export function csAlert(o: CsAlertOpts): TelemetryEvent {
  const r = resolve(o);
  const sev = o.severity ?? "critical";
  const dispoDesc = o.action === "killed" ? "Detection, Process Killed"
    : o.action === "quarantined" ? "Detection, Process Killed, Quarantine File"
    : o.action === "prevented" ? "Prevention, process blocked"
    : "Detection, No Action";
  const result = o.action === "killed" || o.action === "quarantined" ? "process_killed"
    : o.action === "prevented" ? "prevented" : "detected";
  // A detection names at most three generations of its chain — the triggering process
  // (FileName) and its Parent/Grandparent image — never a free-text "process tree".
  const chain = (o.processTree ?? "").split(/\s*>\s*/).map(n => n.replace(/\s*\(.*\)\s*$/, "").trim()).filter(Boolean);
  const fileName = o.processName ?? chain.at(-1);
  const parentImage = o.parentPath ?? (chain.length > 1 ? chain.at(-2) : undefined);
  const grandparentImage = o.grandparentPath ?? (chain.length > 2 ? chain.at(-3) : undefined);
  return {
    id: o.id, ts: o.ts, source: "edr", vendor: VENDOR, event_type: "edr_alert",
    severity: sev, hostname: r.host, src_ip: r.srcIp, user_email: r.email,
    mitre_technique: o.mitre, mitre_tactic: o.tactic, is_detection: o.isDetection ?? true,
    expected_verdict: o.expectedVerdict, incident_id: o.incidentId,
    // A real DetectionSummaryEvent names the flagged file + its hash. Surfacing it as a
    // structured `file` keeps enrichment identical whether an IOC is looked up from the
    // alert or from the process events (deterministic cross-surface intel).
    ...(o.processName ? { file: { name: o.processName, path: o.processPath ?? o.processName, ...(o.sha256 ? { sha256: o.sha256 } : {}) } } : {}),
    description: o.description ?? `${VENDOR} raised ${o.threatName} on ${r.host}`,
    raw: {
      "crowdstrike.event_simpleName": "DetectionSummaryEvent",
      "crowdstrike.DetectName": o.threatName,
      ...(o.detail ? { "crowdstrike.DetectDescription": o.detail } : {}),
      ...(o.tactic ? { "crowdstrike.Tactic": o.tactic } : {}),
      ...(o.technique ? { "crowdstrike.Technique": o.technique } : {}),
      "crowdstrike.PatternDispositionDescription": dispoDesc,
      "crowdstrike.SeverityName": SEV_NAME[sev],
      "crowdstrike.ComputerName": r.host,
      "crowdstrike.UserName": o.runAsUser ?? r.domainUser,
      "crowdstrike.aid": r.sensorId,
      ...(fileName ? { "crowdstrike.FileName": fileName } : {}),
      ...(o.processPath ? { "crowdstrike.FilePath": dirOf(o.processPath) } : {}),
      ...(o.cmdline ? { "crowdstrike.CommandLine": o.cmdline } : {}),
      ...(o.pid !== undefined ? { "crowdstrike.ProcessId": falconUpid(r.sensorId, o.pid) } : {}),
      ...(parentImage ? { "crowdstrike.ParentImageFileName": parentImage } : {}),
      ...(o.parentCmdline ? { "crowdstrike.ParentCommandLine": o.parentCmdline } : {}),
      ...(grandparentImage ? { "crowdstrike.GrandparentImageFileName": grandparentImage } : {}),
      ...(o.sha256 ? { "crowdstrike.SHA256String": o.sha256, "crowdstrike.MD5String": md5For(o.sha256) } : {}),
      "threat.name": o.threatName,
      ...(o.extra ?? {}),
      ...ecsTechnique(o.mitre),
      ...(o.technique ? { "threat.technique.name": o.technique } : {}),
      ...(o.malwareCategory ? { "malware.category": o.malwareCategory } : {}),
      "action_result": result,
      "event.outcome": result === "detected" ? "detected" : "blocked",
    },
  };
}

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
      "crowdstrike.FilePath": dirOf(path),
      "crowdstrike.CommandLine": cmdline,
      ...(o.parentName ? { "crowdstrike.ParentImageFileName": o.parentName } : {}),
      "crowdstrike.SHA256String": sha256,
      "crowdstrike.MD5String": md5For(sha256),
      "crowdstrike.aid": r.sensorId,
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
  signatureSubject?: string;    // code_signature.subject_name (e.g. "Microsoft Corporation")
  originalFileName?: string;    // PE embedded OriginalFileName — the rename tell (rclone → svchost-update)
  runAsUser?: string;           // token owner override (verbatim DOMAIN\user, e.g. "NT AUTHORITY\\SYSTEM")
  integrity?: "low" | "medium" | "high" | "system";
  simpleName?: string;          // override crowdstrike.event_simpleName (e.g. "RawDiskAccess")
  expectedVerdict?: ExpectedVerdict;
  fpExplanation?: string;       // benign-control rationale (a decoy that resolves fp)
  extra?: Record<string, string | number | boolean>; // extra registry-valid raw fields (threat.*, host.os.*, OperationType…)
  mitre?: string;
  tactic?: string;
  severity?: Severity;
  isDetection?: boolean;        // true → shows as a feed alert; else pivot-only tree telemetry
  eventType?: EventType;        // override (e.g. "scheduled_task" for a schtasks.exe run)
  description?: string;
}
export function csProcess(o: CsProcessOpts): TelemetryEvent {
  const r = resolve(o);
  const pid = o.pid ?? pidFrom(o.id);
  const ppid = o.parentPid ?? pidFrom(`${o.id}:parent`);
  const path = o.processPath ?? `C:\\Windows\\System32\\${o.processName}`;
  const sha256 = o.sha256;
  const userFull = o.runAsUser ?? r.domainUser;
  return {
    id: o.id, ts: o.ts, source: "edr", vendor: VENDOR, event_type: o.eventType ?? "process_create",
    severity: o.severity ?? "low", hostname: r.host, src_ip: r.srcIp, user_email: r.email,
    mitre_technique: o.mitre, mitre_tactic: o.tactic, is_detection: o.isDetection ?? false,
    expected_verdict: o.expectedVerdict, ...(o.fpExplanation ? { fp_explanation: o.fpExplanation } : {}),
    incident_id: o.incidentId,
    description: o.description ?? `${o.processName} launched on ${r.host}`,
    process: { pid, name: o.processName, path, cmdline: o.cmdline, parent_name: o.parentName, parent_pid: ppid, user: userFull, ...(o.integrity ? { integrity: o.integrity } : {}), hash: sha256 ? { sha256 } : undefined },
    raw: {
      "crowdstrike.event_simpleName": o.simpleName ?? "ProcessRollup2",
      "crowdstrike.event_platform": platformOf(path),
      "crowdstrike.aid": r.sensorId,
      "crowdstrike.ComputerName": r.host,
      "crowdstrike.TargetProcessId": falconUpid(r.sensorId, pid),
      "crowdstrike.ParentProcessId": falconUpid(r.sensorId, ppid),
      "crowdstrike.RawProcessId": String(pid),
      "crowdstrike.ImageFileName": imageFileName(path),
      "crowdstrike.FileName": o.processName,
      "crowdstrike.FilePath": dirOf(path),
      "crowdstrike.CommandLine": o.cmdline,
      ...(o.parentName ? { "crowdstrike.ParentBaseFileName": o.parentName } : {}),
      "crowdstrike.UserName": userFull,
      ...(sha256 ? { "crowdstrike.SHA256HashData": sha256, "crowdstrike.MD5HashData": md5For(sha256) } : {}),
      ...(o.integrity ? { "crowdstrike.IntegrityLevel": INTEG_RID[o.integrity] } : {}),
      // PE version-info OriginalFilename (Falcon's PeVersionInfo data, shown on the
      // process details panel) — the rename tell.
      ...(o.originalFileName ? { "crowdstrike.OriginalFilename": o.originalFileName } : {}),
      // Authenticode result as shown on Falcon's process-details panel. ProcessRollup2
      // itself has no readable signing field (SignInfoFlags is an undocumented bitmask);
      // this is the one ECS attribute kept — process.code_signature.exists / .trusted, as
      // Elastic's CrowdStrike integration maps it — because several benign-control
      // scenarios hinge on "signed by Microsoft" vs "unsigned".
      ...ecsCodeSignature("process", o.signed === undefined ? undefined : o.signed ? "trusted" : "unsigned"),
      ...(o.signatureSubject ? { "process.code_signature.subject_name": o.signatureSubject } : {}),
      ...(o.extra ?? {}),
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
  targetPid?: number;           // not on the Falcon record (no target-pid field) — carried as process.target.pid
  grantedAccess?: string;       // access mask in hex, e.g. 0x1FFFFF (PROCESS_ALL_ACCESS) — the LSASS tell; emitted as DesiredAccess (decimal)
  simpleName?: string;          // override the Falcon event name
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
    process: { pid, name: o.processName, path, cmdline, parent_name: o.parentName, parent_pid: o.parentPid, user: r.domainUser, hash: o.sha256 ? { sha256: o.sha256 } : undefined,
      target: o.targetProcess ? { name: o.targetProcess, pid: o.targetPid } : undefined },
    raw: {
      "crowdstrike.event_simpleName": o.simpleName ?? (o.api?.startsWith("SetWindowsHook") ? "SuspiciousWindowsHook" : "CrossProcessOpen"),
      "crowdstrike.event_platform": platformOf(path),
      "crowdstrike.ComputerName": r.host,
      "crowdstrike.UserName": r.domainUser,
      "crowdstrike.aid": r.sensorId,
      // ContextProcessId = the ACTING process's Falcon UPID; RawProcessId its OS pid.
      "crowdstrike.ContextProcessId": falconUpid(r.sensorId, pid),
      "crowdstrike.RawProcessId": String(pid),
      "crowdstrike.FileName": o.processName,
      "crowdstrike.FilePath": dirOf(path),
      "crowdstrike.CommandLine": cmdline,
      ...(o.threatName ? { "crowdstrike.DetectName": o.threatName } : {}),
      ...(o.tactic ? { "crowdstrike.Tactic": o.tactic } : {}),
      ...(o.technique ? { "crowdstrike.Technique": o.technique } : {}),
      // FalconProcessHandleOpDetectInfo: the opened process (TargetProcessImageFileName) and the requested
      // access mask as Falcon writes it — a decimal string (0x1FFFFF → "2097151"). The record names no
      // target OS pid and no API, so targetPid / api shape the scenario, not the log.
      ...(o.targetProcess ? { "crowdstrike.TargetProcessImageFileName": o.targetProcess } : {}),
      ...(o.grantedAccess ? { "crowdstrike.DesiredAccess": String(parseInt(o.grantedAccess, 16)) } : {}),
      ...(o.sha256 ? { "crowdstrike.SHA256HashData": o.sha256, "crowdstrike.MD5HashData": md5For(o.sha256) } : {}),
      ...ecsCodeSignature("process", o.signed === undefined ? undefined : o.signed ? "trusted" : "unsigned"),
    },
  };
}

// ── Network connection (NetworkConnectIP4) ───────────────────────────────────────────
export interface CsNetworkOpts extends Ctx {
  remoteIp: string;
  remotePort: number;
  localPort?: number;           // client ephemeral port (deterministic if omitted)
  direction?: "outbound" | "inbound";
  transport?: "tcp" | "udp";
  application?: "tls" | "http" | "dns" | "ssh";  // layer-7, its own field (not proto)
  domain?: string;
  processName?: string;         // the connecting process (Falcon ContextBaseFileName)
  processPath?: string;
  cmdline?: string;
  pid?: number;
  parentName?: string;
  parentPid?: number;
  sha256?: string;
  bytesOut?: number;            // transferred volume — shown in the console, not a CS raw field
  bytesIn?: number;
  extra?: Record<string, string | number | boolean>; // extra crowdstrike.* fields (DetectName, threat.*…)
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
  const pid = o.processName ? (o.pid ?? pidFrom(o.id)) : undefined;
  return {
    id: o.id, ts: o.ts, source: "edr", vendor: VENDOR, event_type: "net_connection",
    severity: o.severity ?? "medium", hostname: r.host, user_email: r.email,
    src_ip: remote.src, dst_ip: remote.dst, dst_port: o.remotePort, protocol: transport,
    mitre_technique: o.mitre, mitre_tactic: o.tactic, is_detection: o.isDetection ?? false,
    incident_id: o.incidentId,
    ...(o.processName ? { process: { pid: pid!, name: o.processName, path: o.processPath ?? `C:\\Windows\\System32\\${o.processName}`, cmdline: o.cmdline ?? o.processName, parent_name: o.parentName, parent_pid: o.parentPid, user: r.domainUser, hash: o.sha256 ? { sha256: o.sha256 } : undefined } } : {}),
    network: { domain: o.domain, ...(o.bytesOut !== undefined ? { bytes_out: o.bytesOut } : {}), ...(o.bytesIn !== undefined ? { bytes_in: o.bytesIn } : {}) },
    description: o.description ?? `${dir === "inbound" ? "Inbound" : "Outbound"} ${transport.toUpperCase()} connection ${dir === "inbound" ? "to" : "from"} ${r.host} ${dir === "inbound" ? "from" : "to"} ${o.remoteIp}:${o.remotePort}`,
    raw: {
      // A real NetworkConnectIP4 (NetworkReceiveAcceptIP4 for inbound): Local*/Remote*
      // address + port pairs, IANA protocol number, ConnectionDirection (0 = outbound,
      // 1 = inbound) and the connecting process's Falcon UPID in ContextProcessId. It
      // carries NO domain name and NO byte counts — those live in DnsRequest and in
      // the firewall's session record respectively.
      "crowdstrike.event_simpleName": dir === "inbound" ? "NetworkReceiveAcceptIP4" : "NetworkConnectIP4",
      "crowdstrike.aid": r.sensorId,
      "crowdstrike.ComputerName": r.host,
      ...(o.processName && pid !== undefined ? { "crowdstrike.ContextProcessId": falconUpid(r.sensorId, pid), "crowdstrike.ContextBaseFileName": o.processName } : {}),
      "crowdstrike.LocalAddressIP4": r.srcIp,
      "crowdstrike.LocalPort": String(o.localPort ?? (49152 + (hashString(`lport:${o.id}`) % 16383))),
      "crowdstrike.RemoteAddressIP4": o.remoteIp,
      "crowdstrike.RemotePort": String(o.remotePort),
      "crowdstrike.Protocol": transport === "udp" ? "17" : "6",
      "crowdstrike.ConnectionDirection": dir === "inbound" ? "1" : "0",
      ...(o.extra ?? {}),
    },
  };
}

// ── DNS request (DnsRequest) ─────────────────────────────────────────────────────────
export interface CsDnsOpts extends Ctx {
  domain: string;
  resolvedIp?: string;
  qtype?: string;               // "A" | "AAAA" | "TXT" …
  processName?: string;         // the requesting process (ContextBaseFileName)
  processPath?: string;
  cmdline?: string;
  pid?: number;                 // its OS pid — becomes ContextProcessId (Falcon UPID)
  parentName?: string;
  parentPid?: number;
  sha256?: string;
  mitre?: string;
  tactic?: string;
  severity?: Severity;
  isDetection?: boolean;
  description?: string;
}
const DNS_RTYPE: Record<string, string> = { A: "1", NS: "2", CNAME: "5", MX: "15", TXT: "16", AAAA: "28", SRV: "33" };
export function csDns(o: CsDnsOpts): TelemetryEvent {
  const r = resolve(o);
  const qtype = o.qtype ?? "A";
  return {
    id: o.id, ts: o.ts, source: "edr", vendor: VENDOR, event_type: "dns_query",
    severity: o.severity ?? "medium", hostname: r.host, src_ip: r.srcIp, user_email: r.email,
    mitre_technique: o.mitre, mitre_tactic: o.tactic, is_detection: o.isDetection ?? false,
    incident_id: o.incidentId,
    dns: { query: o.domain, query_type: qtype, response: o.resolvedIp },
    network: { domain: o.domain },
    ...(o.processName && o.pid !== undefined ? { process: { pid: o.pid, name: o.processName, path: o.processPath ?? `C:\\Windows\\System32\\${o.processName}`, cmdline: o.cmdline ?? o.processName, parent_name: o.parentName, parent_pid: o.parentPid, user: r.domainUser, hash: o.sha256 ? { sha256: o.sha256 } : undefined } } : {}),
    description: o.description ?? `${r.host} resolved ${o.domain}`,
    raw: {
      "crowdstrike.event_simpleName": "DnsRequest",
      "crowdstrike.aid": r.sensorId,
      "crowdstrike.ComputerName": r.host,
      ...(o.processName && o.pid !== undefined ? { "crowdstrike.ContextProcessId": falconUpid(r.sensorId, o.pid), "crowdstrike.ContextBaseFileName": o.processName } : {}),
      "crowdstrike.DomainName": o.domain,
      "crowdstrike.RequestType": DNS_RTYPE[qtype] ?? qtype,
      ...(o.resolvedIp ? { "crowdstrike.IP4Records": `${o.resolvedIp};` } : {}),
    },
  };
}

// ── File write (NewExecutableWritten / file op) ──────────────────────────────────────
export interface CsFileOpts extends Ctx {
  path: string;
  sha256?: string | null;       // null → omit a hash (a growing data buffer has none)
  size?: number;
  action?: "file_create" | "file_modify" | "file_delete" | "file_access";
  signed?: boolean;
  actorProcess?: string;        // the process that wrote/opened the file (Falcon ContextBaseFileName)
  actorPid?: number;
  actorPath?: string;
  actorParentName?: string;     // the actor's parent (keeps the tree linked)
  actorParentPid?: number;
  actorSha256?: string;
  actorSigned?: "trusted" | "unsigned" | "adhoc" | "valid" | "revoked";
  actorIntegrity?: "high" | "medium" | "low" | "system";
  runAsUser?: string;           // actor token owner (verbatim, e.g. "root" / "NT AUTHORITY\\SYSTEM")
  extra?: Record<string, string | number | boolean>; // extra registry-valid raw fields (threat.*, host.os.*, code_signature…)
  mitre?: string;
  tactic?: string;
  severity?: Severity;
  isDetection?: boolean;
  description?: string;
}
/** Author-facing signing words → the ECS signing state (adhoc = a signature with no trusted publisher). */
const ACTOR_SIGN: Record<NonNullable<CsFileOpts["actorSigned"]>, SignState> = {
  trusted: "trusted", valid: "trusted", unsigned: "unsigned", adhoc: "untrusted", revoked: "revoked",
};
export function csFile(o: CsFileOpts): TelemetryEvent {
  const r = resolve(o);
  const name = o.path.split(/[\\/]/).pop() ?? o.path;
  const action = o.action ?? "file_create";
  const isExe = /\.(exe|dll|sys|scr)$/i.test(name);
  const sha256 = o.sha256 === null ? undefined : (o.sha256 ?? makeSha256(`file:${o.path}`));
  const ext = name.includes(".") ? name.split(".").pop() : undefined;
  // A new PE is "NewExecutableWritten"; a read/mount is FileOpenInfo; else FileWritten/Deleted.
  const simpleName = action === "file_delete" ? "FileDeleted"
    : action === "file_access" ? "FileOpenInfo"
    : action === "file_modify" ? "FileWritten"
    : isExe ? "NewExecutableWritten" : "FileWritten";
  const actionResult = action === "file_delete" ? "file_deleted"
    : action === "file_access" ? "file_opened"
    : action === "file_modify" ? "file_modified" : "file_created";
  return {
    id: o.id, ts: o.ts, source: "edr", vendor: VENDOR, event_type: action,
    severity: o.severity ?? "low", hostname: r.host, src_ip: r.srcIp, user_email: r.email,
    mitre_technique: o.mitre, mitre_tactic: o.tactic, is_detection: o.isDetection ?? false,
    incident_id: o.incidentId,
    file: { name, path: o.path, ...(sha256 ? { sha256 } : {}), ...(o.size ? { size: o.size } : {}), ...(ext ? { extension: ext } : {}) },
    ...(o.actorProcess ? { process: { pid: o.actorPid ?? pidFrom(o.id), name: o.actorProcess, path: o.actorPath ?? `C:\\Windows\\System32\\${o.actorProcess}`, ...(o.actorParentName ? { parent_name: o.actorParentName } : {}), ...(o.actorParentPid ? { parent_pid: o.actorParentPid } : {}), user: o.runAsUser ?? r.domainUser, ...(o.actorSha256 ? { hash: { sha256: o.actorSha256 } } : {}), ...(o.actorIntegrity ? { integrity: o.actorIntegrity } : {}) } } : {}),
    description: o.description ?? `${name} ${action === "file_access" ? "opened" : "written"} on ${r.host}`,
    raw: {
      "crowdstrike.event_simpleName": simpleName,
      "crowdstrike.ComputerName": r.host,
      "crowdstrike.aid": r.sensorId,
      ...(o.actorProcess ? { "crowdstrike.ContextBaseFileName": o.actorProcess, "crowdstrike.ContextProcessId": falconUpid(r.sensorId, o.actorPid ?? pidFrom(o.id)) } : {}),
      ...(o.runAsUser ? { "crowdstrike.UserName": o.runAsUser, "user.name": o.runAsUser.split("\\").pop() ?? o.runAsUser } : {}),
      "file.path": o.path,
      "file.name": name,
      ...(ext ? { "file.extension": ext } : {}),
      ...(o.size ? { "file.size": String(o.size) } : {}),
      ...(sha256 ? { "file.hash.sha256": sha256 } : {}),
      ...(o.actorSha256 ? { "process.hash.sha256": o.actorSha256 } : {}),
      ...ecsCodeSignature("file", o.signed === undefined ? undefined : o.signed ? "trusted" : "unsigned"),
      ...ecsCodeSignature("process", o.actorSigned ? ACTOR_SIGN[o.actorSigned] : undefined),
      "event.action": actionResult,
      ...(o.extra ?? {}),
    },
  };
}
