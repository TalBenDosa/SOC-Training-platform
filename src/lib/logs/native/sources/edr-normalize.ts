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
import { ecsTechniqueId, signState } from "@/lib/logs/ecsFields";
import { techniqueIdByName } from "./_edr_mde_sophos_common";

export type EdrKind = "process" | "network" | "dns" | "file" | "registry" | "logon" | "detection" | "usb" | "unsupported";

/**
 * `inst` separates two instances of one image the story shows as parent and child; `user` is the
 * account the process runs as when the story says so and it differs from the event's user (a
 * parent's own row ran as SYSTEM, the child as the user).
 */
export interface EdrProc { name?: string; path?: string; pid?: number; cmdline?: string; sha256?: string; md5?: string; integrity?: string; signed?: boolean; inst?: string; user?: string }

/**
 * Facts one event cannot know on its own but the STORY does (filled by the story pass in
 * ./_proc-identity, threadEndpointStory, when the story is instantiated): the canonical image path
 * and hash of the acting process and of its parent (the process's own row wins), the parent's
 * integrity / account / command line from its own row, the process that wrote a file when the row
 * names none, the user's authored SID and logon id, and a download's origin URL. Rendering stays
 * per event; these keep every record of one story pivotable on the same values.
 */
export interface ThreadProc { name?: string; path?: string; sha256?: string; md5?: string; inst?: string; integrity?: string; user?: string; cmdline?: string; pid?: number }
export interface EndpointThread {
  proc?: ThreadProc;
  parent?: ThreadProc;
  /** The process that wrote the file / set the value when the event names none. */
  writer?: ThreadProc;
  sid?: string;
  /** Authored logon id of the user's session on this host ("0x…" hex). */
  logonId?: string;
  /** Ordinal of the event's day among the user's days on this host in the story (a later day = a new session). */
  logonSeq?: number;
  originUrl?: string;
  referrerUrl?: string;
  /** A cross-process access kept across a vendor reshape (the authored target / rights have no structured field). */
  access?: { name?: string; path?: string; pid?: number; granted?: string };
  /** The threat name the story's other detection of the same file authored (one file → one verdict name). */
  threatName?: string;
  /** The account active on this host at that time in the story, for a row that names no user ("DOMAIN\user" or "user"). */
  user?: string;
}
type Threaded = TelemetryEvent & { _endpoint?: EndpointThread };
export const threadOf = (ev: TelemetryEvent): EndpointThread | undefined => (ev as Threaded)._endpoint;
export const withThread = (ev: TelemetryEvent, t: EndpointThread): TelemetryEvent => ({ ...ev, _endpoint: t } as Threaded);
/** Merge facts into a freshly built event's thread in place (the event object is not shared). */
export function stashThread(ev: TelemetryEvent, patch: EndpointThread): void {
  (ev as Threaded)._endpoint = { ...threadOf(ev), ...patch };
}

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
  registry: { path?: string; key?: string; value?: string };
  /** The user's SID / logon id as the story authored them (absent → the module derives them). */
  sid?: string;
  logonId?: string;
  logonSeq?: number;
  /** Mark-of-the-Web origin of a downloaded file (authored on the file row or on the story's download). */
  originUrl?: string;
  referrerUrl?: string;
  /** A cross-process handle open (process_access): the target process and the rights granted. */
  access?: { name?: string; path?: string; pid?: number; granted?: string };
  /** A removable drive mounted on the host (usb kind). */
  usb?: { drive?: string; product?: string; vendor?: string; serial?: string; type?: string };
  /** A service installation (service_install): the service and the binary it runs. */
  service?: { name: string; path?: string; account?: string; startType?: string };
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
/** "\Device\HarddiskVolume3\X" → "C:\X": one path spelling per binary whatever vocabulary authored it. */
const drive = (p?: string) => (p ? p.replace(/^\\Device\\HarddiskVolume\d+\\/i, "C:\\") : p);
const lcEq = (a?: string, b?: string) => !!a && !!b && a.toLowerCase() === b.toLowerCase();
const baseName = (p?: string) => (p ? p.split(/[\\/]/).pop() : undefined);
/** Folder + file name, without doubling when the folder value already ends with the file name. */
const joinPath = (folder: unknown, file: unknown): string | undefined => {
  const d = str(folder); const f = str(file);
  if (!d) return undefined;
  if (!f || d.toLowerCase().endsWith(`\\${f.toLowerCase()}`) || d.toLowerCase().endsWith(`/${f.toLowerCase()}`) || d.toLowerCase() === f.toLowerCase()) return d;
  return `${d.replace(/[\\/]$/, "")}\\${f}`;
};
const isPrivateIp = (ip?: string) => !!ip && /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|fd|fe80)/i.test(ip);
const dirName = (p?: string) => (p && /[\\/]/.test(p) ? p.replace(/[\\/][^\\/]+$/, "") : undefined);

/** Is the image signed at all (ECS process.code_signature.*)? */
function signedOf(r: Record<string, unknown>): boolean | undefined {
  const st = signState(r, "process");
  return st ? st !== "unsigned" : undefined;
}

function splitUser(raw?: string): { user?: string; domain?: string; email?: string } {
  if (!raw) return {};
  if (raw.includes("@")) return { user: raw.split("@")[0], email: raw };
  if (raw.includes("\\")) { const [d, u] = raw.split("\\"); return { user: u, domain: d }; }
  return { user: raw };
}

const UNSUPPORTED_SIMPLE = /^(RemovableMedia|DcUsb|AgentOffline|FileOpenInfo|DocumentScan|SensorHeartbeat)/i;
/** Event types that describe a telemetry step, not a verdict. */
const TELEMETRY_ET = /^(file_|process_create$|linux_execve$|net_connection$|dns_query$|registry_set$|scheduled_task$|service_install$|process_access$|privilege_escalation$)/;
/**
 * Raw keys only an authored product verdict carries (a detection name, a disposition, a mitigation).
 * Deliberately NOT here: the keys a cross-vendor reshape stamps on every alert-grade row whatever it
 * is (threat.technique.id, crowdstrike.SeverityName, s1.threat.confidenceLevel / classification /
 * mitigationStatus, s1.detection.classification) — they say "this row is important", not "the product
 * convicted it".
 */
const VERDICT_KEY = /^(crowdstrike\.(DetectName|DetectDescription|DetectId|PatternDisposition\w*)|s1\.(threat\.threatName|indicator\.name|mitigation_status|detection\.classification_source)|threat\.name|malware\.name|ThreatName|windefend\.\w+(\.\w+)*)$/;
/** Placeholder names a reshape writes when the authored event has no detection name. */
const PLACEHOLDER_VERDICT = /^(none|troj\/agent-a|suspicious activity detected)$/i;

/** Falcon's DesiredAccess is the access mask as a decimal string ("2097151"); the facts carry the Windows hex form ("0x1FFFFF"). */
export function accessMask(v: unknown): string | undefined {
  const s = str(v);
  return s && /^\d+$/.test(s) ? `0x${Number(s).toString(16).toUpperCase()}` : s;
}

function kindOf(ev: TelemetryEvent, r: Record<string, unknown>): { kind: EdrKind; reason?: string } {
  const simple = str(r["crowdstrike.event_simpleName"]) ?? "";
  const s1type = (str(r["s1.eventType"]) ?? "").toLowerCase();
  const et = ev.event_type ?? "";
  // A file copied onto a mounted USB drive is a file write on that drive; the mount itself is a USB-mount record.
  if (/^FileWrittenToRemovableMedia$/i.test(simple) || str(r["event.action"]) === "FileCopiedToRemovableMedia") return { kind: "file" };
  if (/^RemovableMedia(Connected|VolumeMounted)$/i.test(simple || str(r["event.action"]) || "") || /^mount/i.test(str(r["usb.action"]) ?? "")) return { kind: "usb" };
  if (UNSUPPORTED_SIMPLE.test(simple) || s1type.includes("device control") || /usb|removable/i.test(et))
    return { kind: "unsupported", reason: "device-control / USB telemetry has no documented native record in the cards" };
  if (et === "file_access" || /FileOpenInfo|DocumentScan/.test(simple)) return { kind: "unsupported", reason: "file-read telemetry is not a documented native record" };
  const sophosDet = str(r["sophos.detection_name"]);
  // A telemetry step (a process start, a file write, a connection …) is a product DETECTION only
  // when the product's own verdict is on it. `is_detection` marks the feed row as alert-grade, and a
  // generic "DetectionSummaryEvent" simple name is what a vendor reshape stamps on any non-process
  // event — neither turns a download into an alert or a process start into a threat record.
  const telemetryStep = TELEMETRY_ET.test(et);
  const mdeTitle = str(r["mde.AlertTitle"]);
  const productVerdict = Object.keys(r).some(k => VERDICT_KEY.test(k)) ||
    (!!sophosDet && !PLACEHOLDER_VERDICT.test(sophosDet)) || (!!mdeTitle && !PLACEHOLDER_VERDICT.test(mdeTitle)) ||
    str(r["process.killed"]) === "true" || /kill|terminat|quarantin|block|prevent/i.test(str(r["action_result"]) ?? "");
  const flagged = ev.is_detection || /Detection|Alert/i.test(simple) || s1type === "threats" ||
    (!!sophosDet && sophosDet.toLowerCase() !== "none") || str(r["process.killed"]) === "true";
  if (et === "edr_alert" || et === "av_detection" || et === "av_quarantine" || (flagged && (!telemetryStep || productVerdict)))
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
  const parts = [r["action_result"], r["quarantine.status"], r["crowdstrike.PatternDispositionDescription"],
    r["s1.mitigation_status"], r["s1.threat.mitigationStatus"],
    r["sophos.action"], r["windefend.action"], r["remediation.status"] && /complet|success/i.test(String(r["remediation.status"])) ? r["remediation.action"] : undefined]
    .map(v => (str(v) ?? "").toLowerCase());
  // Negatives win: "not_quarantined", "allowed", "not_mitigated", "detect only".
  const neg = (t: string) => /not[_ ]?(quarantin|mitigat|block|kill)|^allowed$|detect.?only|no action|none/.test(t);
  const pos = parts.filter(t => t && !neg(t)).join(" ");
  // No \b before "kill": "process_killed" (the corpus's own spelling) has no word boundary there.
  if (str(r["process.killed"]) === "true" || /kill|terminat/.test(pos)) return "killed";
  if (/quarantin/.test(pos)) return "quarantined";
  if (/block|prevent|denied|\bmitigated|remov|clean/.test(pos)) return "blocked";
  return "detected";
}

export function edrFacts(ev: TelemetryEvent): EdrFacts {
  const r = (ev.raw ?? {}) as Record<string, unknown>;
  const { kind, reason } = kindOf(ev, r);
  const platform = (first(r["crowdstrike.event_platform"], r["host.os.type"], r["host.os.name"]) ?? "").toLowerCase();
  const anyPath = String(ev.process?.path ?? r["process.executable"] ?? r["crowdstrike.ImageFileName"] ?? ev.file?.path ?? "");
  const os: EdrFacts["os"] = /lin|ubuntu|rhel|debian|centos|eks|bottlerocket/.test(platform) || ev.event_type === "linux_execve" ? "Lin"
    : /mac|darwin/.test(platform) || /^\/(Applications|System|Library|Users)\//.test(anyPath) || /\.app\//.test(anyPath) ? "Mac"
    : !platform && anyPath.startsWith("/") ? "Lin" : "Win";

  const u = splitUser(first(ev.process?.user, r["crowdstrike.UserName"], r["user.name"], r["AccountName"] && r["AccountDomain"] ? `${r["AccountDomain"]}\\${r["AccountName"]}` : r["AccountName"], r["InitiatingProcessAccountName"], r["s1.srcProcUser"], r["s1.process.user"]));
  const csName = str(r["crowdstrike.FileName"]);
  // A Falcon detection's chain: Grandparent → Parent → the triggering process (FileName), its last node.
  const tree = kind === "detection"
    ? [r["crowdstrike.GrandparentImageFileName"], r["crowdstrike.ParentImageFileName"], r["crowdstrike.FileName"]].map(v => baseName(str(v))).filter((v): v is string => !!v)
    : [];
  const procPath = first(ev.process?.path, r["process.executable"], r["crowdstrike.ImageFileName"], kind === "process" ? joinPath(r["FolderPath"], r["FileName"]) : undefined, kind !== "process" ? joinPath(r["InitiatingProcessFolderPath"], r["InitiatingProcessFileName"]) : undefined,
    // A Falcon process row authored as FilePath + FileName of the image itself.
    kind === "process" && csName && lcEq(csName, first(ev.process?.name, r["process.name"], r["crowdstrike.ContextBaseFileName"], csName)) ? joinPath(r["crowdstrike.FilePath"], csName) : undefined,
    // A Sysmon EventData block (the actor of events 1/3/10/11/13/22).
    r["winlog.event_data.Image"], r["winlog.event_data.SourceImage"]);
  const procName = first(ev.process?.name, r["process.name"], r["crowdstrike.FileName"] && kind === "process" ? r["crowdstrike.FileName"] : undefined, r["crowdstrike.ContextBaseFileName"], kind === "process" ? r["FileName"] : r["InitiatingProcessFileName"], r["s1.srcProcName"], baseName(procPath), tree[tree.length - 1]);
  const proc: EdrProc = {
    name: procName, path: procPath,
    pid: numOrU(ev.process?.pid ?? r["process.pid"] ?? r["crowdstrike.RawProcessId"] ?? (kind === "process" ? r["ProcessId"] : r["InitiatingProcessId"]) ?? r["s1.srcProcPid"] ?? r["winlog.event_data.ProcessId"] ?? r["winlog.event_data.SourceProcessId"]),
    cmdline: first(ev.process?.cmdline, r["process.command_line"], r["crowdstrike.CommandLine"], kind === "process" ? r["ProcessCommandLine"] : r["InitiatingProcessCommandLine"], r["s1.srcProcCmdLine"], r["s1.process.cmdline"], r["winlog.event_data.CommandLine"]),
    sha256: first(ev.process?.hash?.sha256, r["process.hash.sha256"], kind === "process" ? r["crowdstrike.SHA256HashData"] : undefined, kind === "process" ? r["SHA256"] : r["InitiatingProcessSHA256"]),
    md5: first(ev.process?.hash?.md5, r["process.hash.md5"], kind === "process" ? r["crowdstrike.MD5HashData"] : r["InitiatingProcessMD5"]),
    integrity: first(ev.process?.integrity, r["process.integrity_level"], r["ProcessIntegrityLevel"], r["crowdstrike.IntegrityLevel"]),
    signed: signedOf(r),
  };
  const parentName = first(ev.process?.parent_name, r["process.parent.name"], r["crowdstrike.ParentBaseFileName"], kind === "process" ? r["InitiatingProcessFileName"] : undefined, r["s1.srcProcParentName"], baseName(str(r["process.parent.executable"])), baseName(str(r["winlog.event_data.ParentImage"])), tree.length > 1 ? tree[tree.length - 2] : undefined);
  const parent: EdrProc = {
    name: parentName,
    path: first(r["process.parent.executable"], kind === "process" ? joinPath(r["InitiatingProcessFolderPath"], r["InitiatingProcessFileName"]) : undefined, r["winlog.event_data.ParentImage"]),
    pid: numOrU(ev.process?.parent_pid ?? r["process.parent.pid"] ?? (kind === "process" ? r["InitiatingProcessId"] : undefined) ?? r["winlog.event_data.ParentProcessId"]),
    cmdline: first(r["process.parent.command_line"], r["crowdstrike.ParentCommandLine"], kind === "process" ? r["InitiatingProcessCommandLine"] : undefined, r["winlog.event_data.ParentCommandLine"]),
    sha256: first(r["process.parent.hash.sha256"], kind === "process" ? r["InitiatingProcessSHA256"] : undefined),
    md5: first(r["process.parent.hash.md5"], kind === "process" ? r["InitiatingProcessMD5"] : undefined),
  };
  const filePath = first(ev.file?.path, r["file.path"], joinPath(r["usb.destination"], r["file.name"]), r["crowdstrike.FilePath"] && r["crowdstrike.FileName"] && kind !== "process" ? `${String(r["crowdstrike.FilePath"]).replace(/[\\/]$/, "")}\\${r["crowdstrike.FileName"]}` : r["crowdstrike.TargetFileName"], kind === "file" ? joinPath(r["FolderPath"], r["FileName"]) : undefined);
  // Direction: an authored inbound connection has a PUBLIC source and the host as
  // destination (RDP from the internet). Read it as remote = source, local = host.
  const srcIp = first(ev.src_ip, r["source.ip"]);
  const dstIp = first(ev.dst_ip, r["destination.ip"], r["RemoteIP"], r["crowdstrike.RemoteAddressIP4"]);
  const inbound = kind === "network" && !!srcIp && !isPrivateIp(srcIp) && (!dstIp || isPrivateIp(dstIp));
  const accessTarget = first(r["crowdstrike.TargetProcessImageFileName"], r["s1.tgtProcName"], r["winlog.event_data.TargetImage"], r["TargetImage"]);
  const svcName = ev.event_type === "service_install" ? first(r["service.name"], r["ServiceName"], r["winlog.event_data.ServiceName"], (procName ?? baseName(procPath))?.replace(/\.exe$/i, "")) : undefined;
  proc.path = drive(proc.path); parent.path = drive(parent.path);
  const out: EdrFacts = {
    kind, unsupportedReason: reason,
    timeMs: Date.parse(ev.ts),
    eventId: ev.id,
    host: first(ev.hostname, r["host.name"], r["crowdstrike.ComputerName"], r["DeviceName"], r["s1.agent.computerName"]),
    hostIp: first(r["host.ip"], r["crowdstrike.LocalAddressIP4"], r["LocalIP"], isPrivateIp(ev.src_ip) ? ev.src_ip : undefined, inbound && isPrivateIp(dstIp) ? dstIp : undefined),
    os,
    user: u.user, userDomain: u.domain, userEmail: ev.user_email ?? ev.user?.email ?? u.email,
    proc, parent,
    file: {
      path: filePath, name: first(ev.file?.name, r["file.name"], baseName(filePath)),
      sha256: first(ev.file?.sha256, r["file.hash.sha256"], kind !== "process" ? r["crowdstrike.SHA256HashData"] ?? r["SHA256"] : undefined),
      md5: first(ev.file?.md5, kind !== "process" ? r["crowdstrike.MD5HashData"] : undefined),
      size: numOrU(ev.file?.size ?? r["file.size"]),
      extension: first(ev.file?.extension, r["file.extension"]),
    },
    net: {
      remoteIp: inbound ? srcIp : dstIp,
      remotePort: inbound ? numOrU(ev.src_port ?? r["source.port"]) : numOrU(ev.dst_port ?? r["destination.port"] ?? r["RemotePort"] ?? r["crowdstrike.RemotePort"]),
      localIp: inbound ? (isPrivateIp(dstIp) ? dstIp : undefined) : first(srcIp, r["LocalIP"], r["crowdstrike.LocalAddressIP4"]),
      localPort: inbound ? numOrU(ev.dst_port ?? r["destination.port"]) : numOrU(ev.src_port ?? r["source.port"]),
      protocol: first(ev.protocol),
      url: first(ev.network?.url, r["RemoteUrl"], r["url.full"]),
      // network.destination sometimes holds the TARGET HOST of an inbound connection, not a domain.
      domain: first(ev.network?.domain, ev.dns?.query, r["destination.domain"], inbound ? undefined : (str(r["network.destination"]) && !/^\d+\.\d+\.\d+\.\d+$/.test(String(r["network.destination"])) ? r["network.destination"] : undefined)),
      direction: inbound ? "inbound" : "outbound",
    },
    dns: { query: first(ev.dns?.query, r["dns.question.name"]), type: first(ev.dns?.query_type), response: first(ev.dns?.response) },
    registry: { path: first(ev.registry?.path, r["registry.path"]), key: first(ev.registry?.key, r["registry.key"]), value: first(ev.registry?.value, r["registry.value"]) },
    detection: kind === "detection" ? {
      name: first(r["crowdstrike.DetectName"], r["threat.name"], r["malware.name"], r["mde.AlertTitle"], r["s1.indicator.name"], r["s1.threat.threatName"], r["sophos.detection_name"], r["ThreatName"], r["windefend.threat.name"], ev.rule?.name),
      // Vendor field only — the authored description states the conclusion (L-05).
      description: first(r["crowdstrike.DetectDescription"]),
      severity: first(ev.severity, r["crowdstrike.SeverityName"]),
      technique: first(r["crowdstrike.Technique"], r["threat.technique.name"]),
      // A flat Falcon detection names its technique, not the id — resolve the id from the name.
      techniqueId: first(ev.mitre_technique, ecsTechniqueId(r), techniqueIdByName(str(r["crowdstrike.Technique"]))),
      tactic: first(ev.mitre_tactic, r["crowdstrike.Tactic"]),
      tacticId: first(r["threat.tactic.id"]),
      action: actionOf(r),
    } : undefined,
    sid: first(r["crowdstrike.UserSid"], kind === "process" ? r["AccountSid"] : r["InitiatingProcessAccountSid"], /^S-1-5-/.test(String(r["user.id"] ?? "")) ? r["user.id"] : undefined),
    originUrl: first(r["FileOriginUrl"], r["file.origin_url"]),
    referrerUrl: first(r["FileOriginReferrerUrl"], r["file.origin_referrer_url"]),
    access: ev.event_type === "process_access" && accessTarget ? {
      name: baseName(accessTarget), path: /[\\/]/.test(accessTarget) ? accessTarget : undefined,
      pid: numOrU(ev.process?.target?.pid ?? r["winlog.event_data.TargetProcessId"] ?? r["TargetProcessId"]),
      granted: first(accessMask(r["crowdstrike.DesiredAccess"]), r["s1.granted_access"], r["winlog.event_data.GrantedAccess"], r["GrantedAccess"]),
    } : undefined,
    usb: kind === "usb" ? { drive: first(r["usb.mount_point"])?.replace(/\\$/, ""), product: first(r["usb.device.name"]), vendor: first(r["usb.vendor"]), serial: first(r["usb.device.serial"]), type: first(r["removable_media.type"]) } : undefined,
    service: svcName ? { name: svcName, path: procPath, account: first(r["service.account"], r["winlog.event_data.AccountName"]), startType: first(r["service.start_type"], r["winlog.event_data.StartType"]) } : undefined,
  };
  return applyThread(out, threadOf(ev));
}

/** Story facts (EndpointThread) over the event's own: canonical path / hash / instance win; authored text fills gaps. */
function applyThread(f: EdrFacts, t: EndpointThread | undefined): EdrFacts {
  if (!t) return f;
  let proc = f.proc;
  // A file / registry row that names no actor: the story's writer.
  if (t.writer && (f.kind === "file" || f.kind === "registry") && !proc.name && !proc.path && !proc.cmdline) {
    proc = { name: t.writer.name, path: t.writer.path, cmdline: t.writer.cmdline, sha256: t.writer.sha256, md5: t.writer.md5, inst: t.writer.inst, integrity: t.writer.integrity, user: t.writer.user };
  }
  const merge = (p: EdrProc, s?: ThreadProc): EdrProc => (!s ? p : {
    ...p,
    path: s.path ?? p.path, sha256: s.sha256 ?? p.sha256, md5: s.md5 ?? p.md5, inst: s.inst ?? p.inst,
    cmdline: p.cmdline ?? s.cmdline, integrity: p.integrity ?? s.integrity, user: p.user ?? s.user,
  });
  const tu = !f.user && !f.userEmail && t.user ? splitUser(t.user) : undefined;
  return {
    ...f,
    ...(tu ? { user: tu.user, userDomain: tu.domain } : {}),
    proc: merge(proc, proc === f.proc ? t.proc : undefined),
    parent: merge(f.parent, t.parent),
    sid: t.sid ?? f.sid,
    logonId: t.logonId ?? f.logonId,
    logonSeq: t.logonSeq,
    originUrl: f.originUrl ?? t.originUrl,
    referrerUrl: f.referrerUrl ?? t.referrerUrl,
    access: f.access ?? (f.kind === "process" ? t.access : undefined),
    detection: f.detection && !f.detection.name && t.threatName ? { ...f.detection, name: t.threatName } : f.detection,
  };
}

/**
 * What the product did, as separate facts — an alert can kill a process AND quarantine its file,
 * which {@link EdrFacts.detection}.action (one word) cannot say. `blockedExec` = the authored event
 * says execution itself was prevented (the process never ran).
 */
export interface ActionFlags { kill: boolean; quarantine: boolean; block: boolean; blockedExec: boolean }
export function actionFlags(ev: TelemetryEvent): ActionFlags {
  const r = (ev.raw ?? {}) as Record<string, unknown>;
  const parts = [r["action_result"], r["quarantine.status"], r["crowdstrike.PatternDispositionDescription"],
    r["s1.mitigation_status"], r["s1.threat.mitigationStatus"],
    r["sophos.action"], r["windefend.action"], r["remediation.status"] && /complet|success/i.test(String(r["remediation.status"])) ? r["remediation.action"] : undefined]
    .map(v => (str(v) ?? "").toLowerCase());
  const neg = (t: string) => /not[_ ]?(quarantin|mitigat|block|kill)|^allowed$|detect.?only|no action|none/.test(t);
  const pos = parts.filter(t => t && !neg(t)).join(" ");
  const said = `${pos} ${(ev.description ?? "").toLowerCase()}`;
  return {
    kill: str(r["process.killed"]) === "true" || /kill|terminat/.test(pos),
    quarantine: /quarantin/.test(pos),
    block: /block|prevent|denied|\bmitigated|remov|clean/.test(pos),
    // "blocked X from executing", "prevented it from running", "execution was blocked", "blocked on execution".
    blockedExec: /(block|prevent)\w*\s+(\S+\s+){0,3}?from\s+(execut|launch|running|start)|(block|prevent)\w*\s+(its\s+|the\s+)?(execution|launch)\b|execution\s+(was\s+)?(blocked|prevented)|(blocked|prevented)\s+(on|at)\s+execution|before\s+it\s+(could\s+)?(run|execut|start)/.test(said),
  };
}

/** A scheduled-task registration authored on the event (MDE ScheduledTaskCreated, Falcon ScheduledTaskRegistered, S1 Task Register). */
export interface TaskFacts {
  /** Task name without the leading folder backslash, e.g. "OfficeLicenseRefresh". */
  name: string;
  /** Task Scheduler path, e.g. "\\OfficeLicenseRefresh". */
  path: string;
  /** The program the task runs, when the event says. */
  command?: string;
  args?: string;
  /** The process that registered the task (schtasks.exe, an installer …). */
  registrar: EdrProc;
}
export function taskFacts(ev: TelemetryEvent, f: EdrFacts): TaskFacts | null {
  const r = (ev.raw ?? {}) as Record<string, unknown>;
  const action = str(r["ActionType"]);
  const simple = str(r["crowdstrike.event_simpleName"]);
  const s1type = (str(r["s1.eventType"]) ?? "").toLowerCase();
  const rawName = first(r["TaskName"], r["crowdstrike.TaskName"], r["task.name"], r["s1.task.name"]);
  const registration = action === "ScheduledTaskCreated" || simple === "ScheduledTaskRegistered" || /task register/.test(s1type) ||
    (ev.event_type === "scheduled_task" && !!first(r["TaskName"], r["crowdstrike.TaskName"]) && !ev.process?.name);
  if (!registration || !rawName) return null;
  const name = rawName.replace(/^\\+/, "").split("\\").pop()!;
  const path = rawName.startsWith("\\") ? rawName : `\\${rawName}`;
  // MDE puts the task's program in FolderPath / FileName and the registrar in InitiatingProcess*;
  // edrFacts reads that row as "process = program, parent = registrar".
  const command = first(r["TaskExecCommand"], r["crowdstrike.TaskExecCommand"], r["task.command"],
    action === "ScheduledTaskCreated" ? joinPath(r["FolderPath"], r["FileName"]) : undefined,
    !ev.process?.name && f.proc.path && /[\\/]/.test(f.proc.path) ? f.proc.path : undefined);
  const registrar: EdrProc = ev.process?.name ? f.proc : f.parent;
  return { name, path, command, args: first(r["TaskExecArguments"], r["crowdstrike.TaskExecArguments"]), registrar };
}

/**
 * The task a `schtasks.exe /create` process creation registers (/tn name, /tr program). The
 * schtasks process is the registrar — the Task Scheduler records the registration as its own event
 * next to the process start (Falcon ScheduledTaskRegistered, S1 Task Register, MDE ScheduledTaskCreated).
 */
export function schtasksTask(f: EdrFacts): TaskFacts | null {
  if (f.kind !== "process" || !/^schtasks(\.exe)?$/i.test(f.proc.name ?? baseName(f.proc.path) ?? "")) return null;
  const cmd = f.proc.cmdline ?? "";
  if (!/\s\/create\b/i.test(cmd)) return null;
  const arg = (flag: string) => new RegExp(`\\s/${flag}\\s+("([^"]*)"|(\\S+))`, "i").exec(cmd);
  const tn = arg("tn"), tr = arg("tr");
  const rawName = tn ? (tn[2] ?? tn[3]) : undefined;
  if (!rawName) return null;
  const action = tr ? (tr[2] ?? tr[3]) : undefined;
  // /tr may carry arguments after the program ("C:\x\a.exe" -silent / C:\x\a.exe -silent).
  const prog = action ? (/^"([^"]+)"\s*(.*)$/.exec(action) ?? /^(\S+)\s*(.*)$/.exec(action)) : null;
  return {
    name: rawName.replace(/^\\+/, "").split("\\").pop()!, path: rawName.startsWith("\\") ? rawName : `\\${rawName}`,
    command: prog?.[1], args: prog?.[2] || undefined, registrar: f.proc,
  };
}

export { baseName, dirName };
