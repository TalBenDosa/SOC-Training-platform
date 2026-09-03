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
import { hashString } from "../rng";
import { pickHost, pickUser, ipFor, netbiosUser } from "../fabric";
import { makeSha256 } from "../iocs";

const VENDOR = "CrowdStrike Falcon";

// A stable 32-hex Falcon Agent ID (aid) per host — the sensor's identity, constant for
// a given endpoint across all its events (as real Falcon telemetry is).
function aidFor(host: string): string {
  return makeSha256(`aid:${host}`).slice(0, 32);
}
// A stable decimal PID from a seed — Falcon FDR carries a hex PID and a *_decimal twin.
function pidFrom(seed: string): number {
  return 1000 + (hashString(`pid:${seed}`) % 63000);
}
// Human severity name Falcon prints, from the platform severity.
const SEV_NAME: Record<Severity, string> = {
  critical: "Critical", high: "High", medium: "Medium", low: "Low", informational: "Informational",
};

// Shared identity/asset resolution: caller may pass explicit host/user/ip, else the
// fabric supplies company-native ones keyed by the event id (stable per event).
interface Ctx {
  id: string;
  ts: string;
  companyId?: string;
  host?: string;
  /** login name or email; rendered as DOMAIN\user in the raw block */
  user?: string;
  srcIp?: string;
  incidentId?: string;
}
function resolve(c: Ctx) {
  const host = c.host ?? pickHost(c.companyId, c.id, "workstation");
  const ru = c.user ? { name: c.user.includes("@") ? c.user.split("@")[0] : c.user, email: c.user.includes("@") ? c.user : undefined }
                    : pickUser(c.companyId, c.id);
  const bareUser = ru.name;
  const email = ("email" in ru && ru.email) ? ru.email : undefined;
  const srcIp = c.srcIp ?? ipFor(c.companyId, host);   // keyed by host → same host, same IP
  return {
    host,
    bareUser,
    email,
    domainUser: netbiosUser(c.companyId, bareUser),
    srcIp,
    aid: aidFor(host),
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
  const path = o.processPath ?? `C:\\Users\\${r.bareUser}\\Downloads\\${o.processName}`;
  const cmdline = o.cmdline ?? `"${path}"`;
  const pid = pidFrom(o.id);
  return {
    id: o.id, ts: o.ts, source: "edr", vendor: VENDOR, event_type: "av_detection",
    severity: sev, hostname: r.host, src_ip: r.srcIp,
    user_email: r.email, mitre_technique: o.mitre, mitre_tactic: o.tactic,
    is_detection: true, expected_verdict: o.expectedVerdict, incident_id: o.incidentId,
    description: o.description ?? `${VENDOR} ${action === "detected" ? "detected" : "blocked"} ${o.threatName} on ${r.host}`,
    process: { pid, name: o.processName, path, cmdline, parent_name: o.parentName, user: r.domainUser, hash: { sha256 } },
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
      "crowdstrike.aid": r.aid,
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
  sha256?: string;
  mitre?: string;
  tactic?: string;
  severity?: Severity;
  isDetection?: boolean;        // true → shows as a feed alert; else pivot-only tree telemetry
  description?: string;
}
export function csProcess(o: CsProcessOpts): TelemetryEvent {
  const r = resolve(o);
  const pid = pidFrom(o.id);
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
      "crowdstrike.aid": r.aid,
      ...(sha256 ? { "process.hash.sha256": sha256 } : {}),
      "process.command_line": o.cmdline,
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
      "crowdstrike.aid": r.aid,
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
      "crowdstrike.aid": r.aid,
      "dns.question.name": o.domain,
      "dns.question.type": o.qtype ?? "A",
      ...(o.resolvedIp ? { "dns.resolved_ip": o.resolvedIp } : {}),
    },
  };
}

// ── File write (NewExecutableWritten / file op) ──────────────────────────────────────
export interface CsFileOpts extends Ctx {
  path: string;
  sha256?: string;
  action?: "file_create" | "file_modify" | "file_delete";
  mitre?: string;
  tactic?: string;
  severity?: Severity;
  isDetection?: boolean;
  description?: string;
}
export function csFile(o: CsFileOpts): TelemetryEvent {
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
      "crowdstrike.event_simpleName": "NewExecutableWritten",
      "crowdstrike.ComputerName": r.host,
      "crowdstrike.aid": r.aid,
      "file.path": o.path,
      "file.name": name,
      "file.hash.sha256": sha256,
      "event.action": o.action ?? "file_create",
    },
  };
}
