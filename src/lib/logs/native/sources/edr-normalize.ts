/**
 * Vendor-neutral facts of an EDR event, read from the TelemetryEvent's structured
 * fields AND every legacy raw vocabulary the corpus uses (crowdstrike.*, Defender
 * Advanced-Hunting columns, s1.*, sophos.*, ECS-style process.* / file.*). The four
 * EDR modules (crowdstrike, mde, sentinelone, sophos) render these facts in their
 * own native format, so one authored event can be shown as any EDR product.
 *
 * Only values that already exist on the event are read — nothing is invented here.
 */
import type { TelemetryEvent } from "@/lib/sim/types";

export type EdrKind = "process" | "network" | "dns" | "file" | "registry" | "logon" | "detection" | "unsupported";

export interface EdrProc { name?: string; path?: string; pid?: number; cmdline?: string; sha256?: string; md5?: string; integrity?: string; signed?: boolean }
export interface EdrFacts {
  kind: EdrKind;
  /** Why the event cannot be rendered by an EDR (USB/device control, file read, agent offline …). */
  unsupportedReason?: string;
  timeMs: number;
  eventId: string;
  host?: string;
  hostIp?: string;
  os: "Win" | "Lin" | "Mac";
  /** sAMAccountName-style user (no domain), domain, and email when known. */
  user?: string;
  userDomain?: string;
  userEmail?: string;
  proc: EdrProc;
  parent: EdrProc;
  file: { path?: string; name?: string; sha256?: string; md5?: string; size?: number; extension?: string };
  net: { remoteIp?: string; remotePort?: number; localIp?: string; localPort?: number; protocol?: string; url?: string; domain?: string; direction: "outbound" | "inbound" };
  dns: { query?: string; type?: string; response?: string };
  registry: { path?: string; value?: string };
  detection?: {
    name?: string; description?: string; severity?: string; technique?: string; techniqueId?: string;
    tactic?: string; tacticId?: string; confidence?: number;
    /** What the product did. */
    action: "killed" | "quarantined" | "blocked" | "detected";
  };
}

const str = (v: unknown): string | undefined => (v === undefined || v === null || v === "" ? undefined : String(v));
const numOrU = (v: unknown): number | undefined => { const n = Number(v); return v === undefined || v === null || v === "" || isNaN(n) ? undefined : n; };
const first = (...vals: unknown[]) => { for (const v of vals) { const s = str(v); if (s) return s; } return undefined; };
const baseName = (p?: string) => (p ? p.split(/[\\/]/).pop() : undefined);
const dirName = (p?: string) => (p && /[\\/]/.test(p) ? p.replace(/[\\/][^\\/]+$/, "") : undefined);

function splitUser(raw?: string): { user?: string; domain?: string; email?: string } {
  if (!raw) return {};
  if (raw.includes("@")) return { user: raw.split("@")[0], email: raw };
  if (raw.includes("\\")) { const [d, u] = raw.split("\\"); return { user: u, domain: d }; }
  return { user: raw };
}

const UNSUPPORTED_SIMPLE = /^(RemovableMedia|DcUsb|AgentOffline|FileOpenInfo|DocumentScan|SensorHeartbeat)/i;

function kindOf(ev: TelemetryEvent, r: Record<string, unknown>): { kind: EdrKind; reason?: string } {
  const simple = str(r["crowdstrike.event_simpleName"]) ?? "";
  const s1type = (str(r["s1.eventType"]) ?? "").toLowerCase();
  const et = ev.event_type ?? "";
  if (UNSUPPORTED_SIMPLE.test(simple) || s1type.includes("device control") || /usb|removable/i.test(et))
    return { kind: "unsupported", reason: "device-control / USB telemetry has no documented native record in the cards" };
  if (et === "file_access" || /FileOpenInfo|DocumentScan/.test(simple)) return { kind: "unsupported", reason: "file-read telemetry is not a documented native record" };
  if (ev.is_detection || et === "edr_alert" || et === "av_detection" || et === "av_quarantine" || /Detection|Alert/i.test(simple) || s1type === "threats")
    return { kind: "detection" };
  if (et === "net_connection" || /NetworkConnect/i.test(simple) || s1type === "ip connect") return { kind: "network" };
  if (et === "dns_query" || /DnsRequest/i.test(simple) || ev.dns?.query) return { kind: "dns" };
  if (et.startsWith("file_") || /FileWritten|FileCreat/i.test(simple)) {
    if (!(ev.file?.path || r["file.path"] || r["crowdstrike.FilePath"] || r["FolderPath"] || r["crowdstrike.TargetFileName"]))
      return { kind: "unsupported", reason: "file event without a file path" };
    return { kind: "file" };
  }
  if (et === "registry_set" || ev.registry?.path || r["registry.path"]) return { kind: "registry" };
  if (et === "auth_failure" || et === "auth_success" || /UserLogon/i.test(simple)) return { kind: "logon" };
  if (et === "process_create" || et === "linux_execve" || et === "scheduled_task" || et === "service_install" ||
      et === "privilege_escalation" || et === "process_access" || /ProcessRollup|SyntheticProcess/i.test(simple) || ev.process?.name)
    return { kind: "process" };
  return { kind: "unsupported", reason: `event_type ${et} has no EDR native record` };
}

function actionOf(r: Record<string, unknown>): "killed" | "quarantined" | "blocked" | "detected" {
  const a = `${str(r["action_result"]) ?? ""} ${str(r["quarantine.status"]) ?? ""} ${str(r["crowdstrike.PatternDispositionDescription"]) ?? ""} ${str(r["crowdstrike.detection.pattern_disposition_description"]) ?? ""} ${str(r["s1.mitigation_status"]) ?? ""} ${str(r["s1.threat.mitigationStatus"]) ?? ""} ${str(r["process.killed"]) === "true" ? "killed" : ""}`.toLowerCase();
  if (/kill|terminat/.test(a)) return "killed";
  if (/quarantin/.test(a)) return "quarantined";
  if (/block|prevent|denied|mitigated(?!.*not)/.test(a) && !/not_mitigated|no action|detect.?only/.test(a)) return "blocked";
  return "detected";
}

export function edrFacts(ev: TelemetryEvent): EdrFacts {
  const r = (ev.raw ?? {}) as Record<string, unknown>;
  const { kind, reason } = kindOf(ev, r);
  const platform = (first(r["crowdstrike.event_platform"], r["host.os.type"], r["host.os.name"]) ?? "").toLowerCase();
  const os: EdrFacts["os"] = /lin|ubuntu|rhel|debian|centos/.test(platform) || ev.event_type === "linux_execve" ? "Lin" : /mac|darwin/.test(platform) ? "Mac" : "Win";

  const u = splitUser(first(ev.process?.user, r["crowdstrike.UserName"], r["user.name"], r["AccountName"] && r["AccountDomain"] ? `${r["AccountDomain"]}\\${r["AccountName"]}` : r["AccountName"], r["InitiatingProcessAccountName"], r["s1.srcProcUser"], r["s1.process.user"]));
  const procPath = first(ev.process?.path, r["process.executable"], r["crowdstrike.ImageFileName"], r["FolderPath"] && r["FileName"] && kind === "process" ? `${String(r["FolderPath"]).replace(/[\\/]$/, "")}\\${r["FileName"]}` : undefined, r["InitiatingProcessFolderPath"] && r["InitiatingProcessFileName"] && kind !== "process" ? `${r["InitiatingProcessFolderPath"]}\\${r["InitiatingProcessFileName"]}` : undefined);
  const procName = first(ev.process?.name, r["process.name"], r["crowdstrike.FileName"] && kind === "process" ? r["crowdstrike.FileName"] : undefined, r["crowdstrike.process_name"], kind === "process" ? r["FileName"] : r["InitiatingProcessFileName"], r["s1.srcProcName"], baseName(procPath));
  const proc: EdrProc = {
    name: procName, path: procPath,
    pid: numOrU(ev.process?.pid ?? r["process.pid"] ?? r["crowdstrike.RawProcessId"] ?? (kind === "process" ? r["ProcessId"] : r["InitiatingProcessId"]) ?? r["s1.srcProcPid"]),
    cmdline: first(ev.process?.cmdline, r["process.command_line"], r["crowdstrike.CommandLine"], kind === "process" ? r["ProcessCommandLine"] : r["InitiatingProcessCommandLine"], r["s1.srcProcCmdLine"], r["s1.process.cmdline"]),
    sha256: first(ev.process?.hash?.sha256, r["process.hash.sha256"], kind === "process" ? r["crowdstrike.SHA256HashData"] : undefined, kind === "process" ? r["SHA256"] : undefined),
    md5: first(ev.process?.hash?.md5, kind === "process" ? r["crowdstrike.MD5HashData"] : undefined),
    integrity: first(ev.process?.integrity, r["process.integrity_level"], r["ProcessIntegrityLevel"], r["crowdstrike.IntegrityLevel"]),
    signed: str(r["process.code_signature.status"] ?? r["file.signed"]) ? !/unsigned|false|not/i.test(String(r["process.code_signature.status"] ?? r["file.signed"])) : undefined,
  };
  const parentName = first(ev.process?.parent_name, r["process.parent.name"], r["crowdstrike.ParentBaseFileName"], r["crowdstrike.parent_basefilename"], r["crowdstrike.ParentProcessName"], kind === "process" ? r["InitiatingProcessFileName"] : undefined, r["s1.srcProcParentName"]);
  const parent: EdrProc = {
    name: parentName,
    path: kind === "process" ? first(r["InitiatingProcessFolderPath"] && r["InitiatingProcessFileName"] ? `${r["InitiatingProcessFolderPath"]}\\${r["InitiatingProcessFileName"]}` : undefined) : undefined,
    pid: numOrU(ev.process?.parent_pid ?? r["process.parent.pid"] ?? (kind === "process" ? r["InitiatingProcessId"] : undefined)),
    cmdline: kind === "process" ? first(r["InitiatingProcessCommandLine"]) : undefined,
  };
  const filePath = first(ev.file?.path, r["file.path"], r["crowdstrike.FilePath"] && r["crowdstrike.FileName"] && kind !== "process" ? `${String(r["crowdstrike.FilePath"]).replace(/[\\/]$/, "")}\\${r["crowdstrike.FileName"]}` : r["crowdstrike.TargetFileName"], kind === "file" && r["FolderPath"] ? (String(r["FolderPath"]).endsWith(String(r["FileName"] ?? "")) ? r["FolderPath"] : `${r["FolderPath"]}\\${r["FileName"] ?? ""}`) : undefined);
  return {
    kind, unsupportedReason: reason,
    timeMs: Date.parse(ev.ts),
    eventId: ev.id,
    host: first(ev.hostname, r["host.name"], r["crowdstrike.ComputerName"], r["DeviceName"], r["s1.agent.computerName"]),
    hostIp: first(r["host.ip"], r["crowdstrike.local_address"], r["LocalIP"], ev.src_ip && kind !== "network" ? ev.src_ip : undefined),
    os,
    user: u.user, userDomain: u.domain, userEmail: ev.user_email ?? ev.user?.email ?? u.email,
    proc, parent,
    file: {
      path: filePath, name: first(ev.file?.name, r["file.name"], baseName(filePath)),
      sha256: first(ev.file?.sha256, r["file.hash.sha256"], kind !== "process" ? r["crowdstrike.SHA256HashData"] ?? r["SHA256"] ?? r["crowdstrike.SHA256"] : undefined),
      md5: first(ev.file?.md5, kind !== "process" ? r["crowdstrike.MD5HashData"] : undefined),
      size: numOrU(ev.file?.size ?? r["file.size"]),
      extension: first(ev.file?.extension, r["file.extension"]),
    },
    net: {
      remoteIp: first(ev.dst_ip, r["destination.ip"], r["RemoteIP"], r["crowdstrike.RemoteAddressIP4"]),
      remotePort: numOrU(ev.dst_port ?? r["destination.port"] ?? r["RemotePort"] ?? r["crowdstrike.RemotePort"]),
      localIp: first(ev.src_ip, r["source.ip"], r["LocalIP"], r["crowdstrike.LocalAddressIP4"]),
      localPort: numOrU(ev.src_port ?? r["source.port"]),
      protocol: first(ev.protocol),
      url: first(ev.network?.url, r["RemoteUrl"], r["url.full"]),
      domain: first(ev.network?.domain, ev.dns?.query, r["destination.domain"], r["network.destination"]),
      direction: "outbound",
    },
    dns: { query: first(ev.dns?.query, r["dns.question.name"]), type: first(ev.dns?.query_type), response: first(ev.dns?.response) },
    registry: { path: first(ev.registry?.path, r["registry.path"]), value: first(ev.registry?.value, r["registry.value"]) },
    detection: kind === "detection" ? {
      name: first(r["crowdstrike.DetectName"], r["crowdstrike.detection.scenario"], r["threat.name"], r["malware.name"], r["mde.AlertTitle"], r["s1.indicator.name"], r["s1.threat.threatName"], r["sophos.detection_name"], ev.rule?.name),
      description: first(r["crowdstrike.detection.description"], ev.description),
      severity: first(ev.severity, r["crowdstrike.SeverityName"], r["crowdstrike.detection.severity"]),
      technique: first(r["crowdstrike.detection.technique"], r["crowdstrike.Technique"], r["threat.technique.name"]),
      techniqueId: first(ev.mitre_technique, r["crowdstrike.detection.technique_id"], r["crowdstrike.TechniqueId"], r["threat.technique.id"]),
      tactic: first(ev.mitre_tactic, r["crowdstrike.detection.tactic"], r["crowdstrike.Tactic"]),
      tacticId: first(r["crowdstrike.detection.tactic_id"]),
      confidence: numOrU(r["crowdstrike.detection.confidence"] ?? r["crowdstrike.Confidence"]),
      action: actionOf(r),
    } : undefined,
  };
}

export { baseName, dirName };
