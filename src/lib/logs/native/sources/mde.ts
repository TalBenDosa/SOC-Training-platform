/**
 * Microsoft Defender for Endpoint — native module (card: docs/log-schemas/edr-defender-endpoint.md).
 *
 * Representation: ONE element of the Defender XDR Streaming API `records[]` array —
 *   { time, tenantId, operationName:"Publish", category:"AdvancedHunting-<Table>", properties:{ <AH row> } }
 * with `properties` holding the untouched Advanced Hunting columns. The kind is the table name.
 *
 * Facts come from edrFacts() (vendor-neutral, every legacy raw vocabulary); this module only maps
 * them onto the documented columns and fills the rest deterministically:
 *   process  → DeviceProcessEvents  (ProcessCreated; new process = FileName/ProcessId/ProcessCommandLine,
 *                                    creator = InitiatingProcess*)
 *   network  → DeviceNetworkEvents  (ConnectionSuccess)
 *   file     → DeviceFileEvents     (FileCreated / FileModified / FileDeleted / FileRenamed)
 *   dns      → DeviceEvents         (ActionType DnsQueryResponse, AdditionalFields JSON string)
 *   registry → DeviceRegistryEvents (RegistryValueSet)
 *   logon    → DeviceLogonEvents    (LogonSuccess / LogonFailed)
 *   detection→ AlertEvidence        (the entity row: Process, File, Ip or Machine). The matching
 *                                    AlertInfo row is derived with {@link alertInfoFor}.
 *
 * Correlation rules (so one story pivots like the real product):
 *   - DeviceId = 40 hex seeded from `${companyId}:${host}`; tenantId = ctx.tenant.azureTenantId.
 *   - A process is identified by host + image name + PID. When the event has no PID it is seeded
 *     from host + image name, so the creator's InitiatingProcessId on a network/file/DNS row equals
 *     the ProcessId of that process's DeviceProcessEvents row; ProcessUniqueId /
 *     InitiatingProcessUniqueId and SHA1 are seeded from the same identity.
 *   - InitiatingProcessCreationTime is NOT emitted on child rows: the process start time is only
 *     known on its own ProcessCreated row, and a guessed value would break the documented
 *     DeviceId + InitiatingProcessId + InitiatingProcessCreationTime join.
 *
 * Returns null when Defender has no truthful row: edrFacts marks the event unsupported (USB /
 * device control, file-read scans), a process event carries no image identity at all, or a
 * network event has no remote endpoint.
 */
import type { NativeSource, NativeLog, KindSchema, UseCase, NativeCtx } from "../types";
import type { TelemetryEvent } from "@/lib/sim/types";
import { edrFacts, type EdrFacts, type EdrProc } from "./edr-normalize";
import {
  TACTICS, techniqueName, tacticOf, fixPath, baseOf, dirOf, effectiveAction, imageName,
  isPrivate, ipType, isSystemUser, userSid, isoFrac, isServer,
} from "./_edr_mde_sophos_common";

// ── Schema ──────────────────────────────────────────────────────────────────
const ENV_REQ = ["time", "tenantId", "operationName", "category", "properties"];
const ENV_OPT = ["Tenant", "_TimeReceivedBySvc"];
const P = (xs: string[]) => xs.map(x => `properties.${x}`);

const DEVICE_REQ = ["Timestamp", "DeviceId", "DeviceName", "ActionType", "ReportId", "MachineGroup"];
const VERSION_INFO = ["CompanyName", "ProductName", "ProductVersion", "InternalFileName", "OriginalFileName", "FileDescription"];
const INITIATING = [
  "FileName", "FolderPath", "CommandLine", "Id", "CreationTime", "SHA1", "SHA256", "MD5", "FileSize",
  ...VERSION_INFO.map(v => `VersionInfo${v}`),
  "ParentId", "ParentFileName", "ParentCreationTime",
  "AccountDomain", "AccountName", "AccountSid", "AccountUpn", "AccountObjectId", "LogonId",
  "IntegrityLevel", "TokenElevation", "UniqueId", "SessionId", "RemoteSessionDeviceName", "RemoteSessionIP",
].map(c => `InitiatingProcess${c}`);
const DEVICE_OPT = ["AdditionalFields", "AppGuardContainerId", ...INITIATING, "IsInitiatingProcessRemoteSession"];

const device = (req: string[], opt: string[]): KindSchema => ({
  required: [...ENV_REQ, ...P([...DEVICE_REQ, ...req])],
  optional: [...ENV_OPT, ...P([...DEVICE_OPT, ...opt].filter(c => !req.includes(c)))],
});

const ALERT_COMMON = ["Timestamp", "AlertId", "Title", "ServiceSource", "DetectionSource", "AttackTechniques", "MachineGroup"];
const kinds: Record<string, KindSchema> = {
  DeviceProcessEvents: device(
    ["FileName", "FolderPath", "SHA1", "ProcessId", "ProcessCommandLine", "ProcessCreationTime", "AccountName", "InitiatingProcessFileName", "InitiatingProcessId"],
    ["SHA256", "MD5", "FileSize", ...VERSION_INFO.map(v => `ProcessVersionInfo${v}`), "ProcessIntegrityLevel", "ProcessTokenElevation",
      "AccountDomain", "AccountSid", "AccountUpn", "AccountObjectId", "LogonId", "ProcessUniqueId", "CreatedProcessSessionId",
      "IsProcessRemoteSession", "ProcessRemoteSessionDeviceName", "ProcessRemoteSessionIP",
      "InitiatingProcessSignerType", "InitiatingProcessSignatureStatus"],
  ),
  DeviceNetworkEvents: device(
    ["RemoteIP", "RemotePort", "LocalIP", "LocalPort", "Protocol", "InitiatingProcessFileName", "InitiatingProcessId"],
    ["RemoteUrl", "LocalIPType", "RemoteIPType"],
  ),
  DeviceFileEvents: device(
    ["FileName", "FolderPath", "SHA1", "InitiatingProcessFileName"],
    ["SHA256", "MD5", "FileSize", "FileOriginUrl", "FileOriginReferrerUrl", "FileOriginIP", "PreviousFileName", "PreviousFolderPath",
      "RequestProtocol", "RequestSourceIP", "RequestSourcePort", "RequestAccountName", "RequestAccountDomain", "RequestAccountSid",
      "ShareName", "SensitivityLabel", "SensitivitySubLabel", "IsAzureInfoProtectionApplied"],
  ),
  DeviceEvents: device(
    ["AdditionalFields"],
    ["FileName", "FolderPath", "SHA1", "SHA256", "MD5", "FileSize", "AccountDomain", "AccountName", "AccountSid", "RemoteUrl",
      "RemoteDeviceName", "ProcessId", "ProcessCommandLine", "ProcessCreationTime", "ProcessTokenElevation", "LogonId",
      "RegistryKey", "RegistryValueName", "RegistryValueData", "RemoteIP", "RemotePort", "LocalIP", "LocalPort",
      "FileOriginUrl", "FileOriginIP"],
  ),
  DeviceRegistryEvents: device(
    ["RegistryKey", "RegistryValueName", "RegistryValueData"],
    ["RegistryValueType", "PreviousRegistryKey", "PreviousRegistryValueName", "PreviousRegistryValueData"],
  ),
  DeviceLogonEvents: device(
    ["AccountName", "LogonType"],
    ["AccountDomain", "AccountSid", "Protocol", "FailureReason", "IsLocalAdmin", "LogonId", "RemoteDeviceName", "RemoteIP", "RemoteIPType", "RemotePort"],
  ),
  AlertInfo: {
    required: [...ENV_REQ, ...P([...ALERT_COMMON, "Category", "Severity"])],
    optional: ENV_OPT,
  },
  AlertEvidence: {
    required: [...ENV_REQ, ...P(["Timestamp", "AlertId", "Title", "ServiceSource", "DetectionSource", "EntityType", "EvidenceRole"])],
    optional: [...ENV_OPT, ...P(["Categories", "AttackTechniques", "EvidenceDirection", "FileName", "FolderPath", "SHA1", "SHA256", "FileSize",
      "ThreatFamily", "RemoteIP", "RemoteUrl", "AccountName", "AccountDomain", "AccountSid", "AccountObjectId", "AccountUpn",
      "DeviceId", "DeviceName", "LocalIP", "NetworkMessageId", "EmailSubject", "Application", "ApplicationId", "OAuthApplicationId",
      "ProcessCommandLine", "RegistryKey", "RegistryValueName", "RegistryValueData", "AdditionalFields", "Severity", "MachineGroup"])],
  },
};

/** Classify a streamed record (one element of `records[]`) by its table. */
export function kindOf(record: Record<string, unknown>): string | null {
  const c = record.category;
  if (typeof c !== "string" || !c.startsWith("AdvancedHunting-") || typeof record.properties !== "object") return null;
  const table = c.slice("AdvancedHunting-".length);
  return table in kinds ? table : null;
}

// ── Builders ────────────────────────────────────────────────────────────────
interface Proc { name: string | null; path: string | null; pid: number | null; cmdline: string | null; sha1: string | null; sha256: string | null; md5: string | null; uniqueId: string | null }

/** Stable process identity: host + image + PID (PID seeded from host + image when not authored). */
function proc(ctx: NativeCtx, host: string, p: EdrProc): Proc {
  const name = imageName(p) ?? null;
  const path = fixPath(p.path) ?? null;
  const h = host.toLowerCase();
  const pid = p.pid ?? (name ? ctx.int(`${ctx.companyId}:${h}:${name.toLowerCase()}:pid`, 250, 3750) * 4 : null);
  const ident = p.sha256 ?? (path ?? name ?? "").toLowerCase();
  return {
    name, path, pid, cmdline: p.cmdline ?? null,
    sha1: ident ? ctx.hex(`sha1:${ident}`, 40) : null,
    sha256: p.sha256 ?? null, md5: p.md5 ?? null,
    uniqueId: name ? String(ctx.int(`${ctx.companyId}:${h}:${name.toLowerCase()}:${pid}:uid`, 30_000_000_000_000, 39_999_999_999_999)) : null,
  };
}

interface Who { name: string | null; domain: string | null; sid: string | null; upn: string | null; objectId: string | null; logonId: number | null; system: boolean }
function who(ctx: NativeCtx, f: EdrFacts, host: string): Who {
  const name = f.user ?? (f.userEmail ? f.userEmail.split("@")[0] : undefined);
  if (!name) return { name: null, domain: null, sid: null, upn: null, objectId: null, logonId: null, system: false };
  const system = isSystemUser(name);
  const win = f.os === "Win";
  return {
    name,
    domain: system ? "nt authority" : win ? (f.userDomain ?? ctx.netbios.toLowerCase()) : host.toLowerCase(),
    sid: win ? userSid(ctx, name) : null,
    upn: !system && f.userEmail ? f.userEmail : null,
    objectId: !system && win ? ctx.uuid(`${ctx.companyId}:aadobj:${name.toLowerCase()}`) : null,
    logonId: system ? 999 : ctx.int(`${ctx.companyId}:${host.toLowerCase()}:${name.toLowerCase()}:logon`, 100_000, 9_999_999),
    system,
  };
}

function integrity(f: EdrFacts, u: Who): { level: string | null; elevation: string | null } {
  if (f.os !== "Win") return { level: null, elevation: null };
  const raw = (f.proc.integrity ?? (u.system ? "system" : "medium")).toLowerCase();
  const level = raw.charAt(0).toUpperCase() + raw.slice(1);
  const elevation = level === "High" ? "TokenElevationTypeFull" : level === "Medium" ? "TokenElevationTypeLimited" : "TokenElevationTypeDefault";
  return { level, elevation };
}

function machineGroup(host: string, os: EdrFacts["os"]): string {
  if (os === "Lin") return "Linux-Servers";
  if (os === "Mac") return "macOS-Devices";
  if (/(^|-)DC\d*($|-)|DC\d\d/i.test(host)) return "Domain-Controllers";
  if (isServer(host)) return "Servers";
  if (/^LAP/i.test(host)) return "Laptops";
  return "Workstations";
}

function initiatingCols(p: Proc, parent: Proc | null, u: Who, integ: { level: string | null; elevation: string | null }) {
  return {
    InitiatingProcessFileName: p.name,
    InitiatingProcessFolderPath: p.path,
    InitiatingProcessCommandLine: p.cmdline,
    InitiatingProcessId: p.pid,
    InitiatingProcessSHA1: p.sha1,
    InitiatingProcessSHA256: p.sha256,
    InitiatingProcessMD5: p.md5,
    InitiatingProcessParentFileName: parent?.name ?? null,
    InitiatingProcessParentId: parent?.pid ?? null,
    InitiatingProcessAccountDomain: u.domain,
    InitiatingProcessAccountName: u.name,
    InitiatingProcessAccountSid: u.sid,
    InitiatingProcessAccountUpn: u.upn,
    InitiatingProcessAccountObjectId: u.objectId,
    InitiatingProcessLogonId: u.logonId,
    InitiatingProcessIntegrityLevel: integ.level,
    InitiatingProcessTokenElevation: integ.elevation,
    InitiatingProcessUniqueId: p.uniqueId,
    InitiatingProcessSessionId: u.system ? 0 : 1,
    IsInitiatingProcessRemoteSession: false,
  };
}

const SEVERITY: Record<string, string> = { critical: "High", high: "High", medium: "Medium", low: "Low", informational: "Informational", info: "Informational" };
const DEFENDER_THREAT = /^([A-Za-z]+):([A-Za-z0-9]+)\/([A-Za-z0-9_-]+)/; // e.g. Trojan:Win32/Wacatac.B!ml

const VENDOR_MATCH = ["microsoft defender", "defender for endpoint", "defender antivirus", "windows defender", "mde"];
const isNative = (ev: TelemetryEvent) => VENDOR_MATCH.some(v => (ev.vendor ?? "").toLowerCase().includes(v));

function fromTelemetry(ev: TelemetryEvent, ctx: NativeCtx): NativeLog | null {
  const f = edrFacts(ev);
  if (f.kind === "unsupported" || !f.host) return null;
  const host = f.host;
  const seed = (p: string) => `${ev.id}:mde:${p}`;
  const u = who(ctx, f, host);
  const integ = integrity(f, u);
  const ts = isoFrac(f.timeMs, 7, ctx, seed("ts"));
  const base = {
    Timestamp: ts,
    DeviceId: ctx.hex(`${ctx.companyId}:${host.toLowerCase()}`, 40),
    DeviceName: host,
  };
  const tail = {
    ReportId: ctx.int(seed("report"), 1_000, 999_999),
    AppGuardContainerId: null,
    MachineGroup: machineGroup(host, f.os),
  };
  const wrap = (table: string, props: Record<string, unknown>): NativeLog => ({
    sourceId: "mde", kind: table, format: "json", timeMs: f.timeMs,
    record: {
      // Export time: the streaming API forwards within seconds of the event (a larger lag
      // would stamp the record after the moment the row is shown).
      time: isoFrac(f.timeMs + ctx.int(seed("lag"), 1_000, 6_000), 7, ctx, seed("time")),
      tenantId: ctx.tenant.azureTenantId,
      operationName: "Publish",
      category: `AdvancedHunting-${table}`,
      properties: props,
    },
  });
  const p = proc(ctx, host, f.proc);
  const parent = f.parent.name || f.parent.path ? proc(ctx, host, f.parent) : null;

  switch (f.kind) {
    case "process": {
      if (!p.name) return null; // no image identity at all — Defender never emits a nameless ProcessCreated row
      const creator = parent ?? proc(ctx, host, {});
      return wrap("DeviceProcessEvents", {
        ...base,
        ActionType: "ProcessCreated",
        FileName: p.name,
        FolderPath: p.path,
        SHA1: p.sha1,
        SHA256: p.sha256,
        MD5: p.md5,
        ProcessId: p.pid,
        ProcessCommandLine: p.cmdline,
        ProcessIntegrityLevel: integ.level,
        ProcessTokenElevation: integ.elevation,
        ProcessCreationTime: isoFrac(f.timeMs - 1, 7, ctx, seed("pct")),
        AccountDomain: u.domain,
        AccountName: u.name,
        AccountSid: u.sid,
        AccountUpn: u.upn,
        AccountObjectId: u.objectId,
        LogonId: u.logonId,
        ...initiatingCols(creator, null, u, integ),
        ProcessUniqueId: p.uniqueId,
        CreatedProcessSessionId: u.system ? 0 : 1,
        IsProcessRemoteSession: false,
        AdditionalFields: null,
        ...tail,
      });
    }
    case "network": {
      const n = f.net;
      if (!n.remoteIp) return null; // no remote endpoint in the facts (inbound/IMDS events authored without one)
      const proto = n.protocol ? n.protocol.charAt(0).toUpperCase() + n.protocol.slice(1).toLowerCase()
        : [53, 123, 161, 514].includes(n.remotePort ?? 0) ? "Udp" : "Tcp";
      return wrap("DeviceNetworkEvents", {
        ...base,
        ActionType: "ConnectionSuccess",
        RemoteIP: n.remoteIp,
        RemotePort: n.remotePort ?? null,
        RemoteUrl: n.url ?? n.domain ?? null,
        LocalIP: n.localIp ?? null,
        LocalPort: n.localPort ?? ctx.int(seed("lport"), 49_152, 65_535),
        Protocol: proto,
        LocalIPType: ipType(n.localIp),
        RemoteIPType: ipType(n.remoteIp),
        ...initiatingCols(p, parent, u, integ),
        AdditionalFields: null,
        ...tail,
      });
    }
    case "file": {
      const path = f.file.path!;
      const action = ev.event_type === "file_delete" ? "FileDeleted" : ev.event_type === "file_modify" ? "FileModified"
        : ev.event_type === "file_rename" ? "FileRenamed" : "FileCreated";
      const browser = /^(chrome|msedge|firefox|iexplore|outlook|brave|opera)\.exe$/i.test(p.name ?? "");
      return wrap("DeviceFileEvents", {
        ...base,
        ActionType: action,
        FileName: f.file.name ?? baseOf(path) ?? null,
        FolderPath: path,
        SHA1: ctx.hex(`sha1:${f.file.sha256 ?? path.toLowerCase()}`, 40),
        SHA256: f.file.sha256 ?? null,
        MD5: f.file.md5 ?? null,
        FileSize: f.file.size ?? null,
        // FileOriginUrl comes from Mark-of-the-Web — only for browser/mail downloads (card §4.4 note).
        FileOriginUrl: browser && f.net.url ? f.net.url : null,
        FileOriginIP: null,
        PreviousFileName: null,
        PreviousFolderPath: null,
        ...initiatingCols(p.name ? p : { ...p, pid: null, sha1: null, uniqueId: null }, parent, u, integ),
        RequestProtocol: "Local",
        RequestSourceIP: null,
        RequestAccountName: u.name,
        RequestAccountDomain: u.domain ? u.domain.toUpperCase() : null,
        RequestAccountSid: u.sid,
        ShareName: null,
        AdditionalFields: null,
        ...tail,
      });
    }
    case "dns": {
      const q = f.dns.query ?? f.net.domain;
      if (!q) return null;
      const result = f.dns.response ? [{ DnsQueryType: f.dns.type ?? "A", Result: f.dns.response }] : [];
      return wrap("DeviceEvents", {
        ...base,
        ActionType: "DnsQueryResponse",
        FileName: null, FolderPath: null, SHA1: null, SHA256: null, MD5: null,
        AccountDomain: null, AccountName: null, AccountSid: null,
        RemoteUrl: null, RemoteIP: null, RemotePort: null, LocalIP: null, LocalPort: null,
        ...initiatingCols(p.name ? p : { ...p, pid: null, sha1: null, uniqueId: null }, parent, u, integ),
        AdditionalFields: JSON.stringify({ DnsQueryString: q, DnsQueryResult: result }),
        ...tail,
      });
    }
    case "registry": {
      let key = f.registry.path ?? null;
      // edrFacts drops the authored value NAME (ev.registry.key / legacy raw "registry.key"); read it here.
      const rawKey = (ev.raw as Record<string, unknown> | undefined)?.["registry.key"];
      const valueName = ev.registry?.key ?? (typeof rawKey === "string" && rawKey ? rawKey : null);
      if (key && valueName && key.toLowerCase().endsWith(`\\${valueName.toLowerCase()}`)) key = key.slice(0, -(valueName.length + 1));
      if (!key) return null;
      return wrap("DeviceRegistryEvents", {
        ...base,
        ActionType: "RegistryValueSet",
        RegistryKey: key,
        RegistryValueName: valueName,
        RegistryValueData: f.registry.value ?? null,
        PreviousRegistryKey: null,
        PreviousRegistryValueName: null,
        PreviousRegistryValueData: null,
        ...initiatingCols(p.name ? p : { ...p, pid: null, sha1: null, uniqueId: null }, parent, u, integ),
        AdditionalFields: null,
        ...tail,
      });
    }
    case "logon": {
      const failed = ev.event_type === "auth_failure";
      const lt = ev.authentication?.logon_type;
      const LOGON: Record<number, string> = { 2: "Interactive", 3: "Network", 4: "Batch", 5: "Service", 7: "Unlock", 10: "RemoteInteractive", 11: "CachedInteractive" };
      return wrap("DeviceLogonEvents", {
        ...base,
        ActionType: failed ? "LogonFailed" : "LogonSuccess",
        LogonType: (lt && LOGON[lt]) ?? (f.net.domain || f.net.remoteIp ? "Network" : "Interactive"),
        AccountDomain: u.domain,
        AccountName: u.name,
        AccountSid: u.sid,
        LogonId: failed ? null : u.logonId,
        RemoteDeviceName: null,
        RemoteIP: null,
        RemoteIPType: null,
        RemotePort: null,
        ...initiatingCols(p.name ? p : { ...p, pid: null, sha1: null, uniqueId: null }, parent, u, integ),
        AdditionalFields: null,
        ...tail,
      });
    }
    case "detection":
      return wrap("AlertEvidence", alertEvidence(ev, f, ctx, host, base, tail, p, u));
  }
  return null;
}

function alertEvidence(ev: TelemetryEvent, f: EdrFacts, ctx: NativeCtx, host: string,
  base: Record<string, unknown>, tail: { MachineGroup: string }, p: Proc, u: Who): Record<string, unknown> {
  const d = f.detection!;
  const action = effectiveAction(ev, f);
  const tactic = tacticOf(f);
  const techName = techniqueName(d.techniqueId, d.technique);
  const av = ev.source === "av" || /^av_/.test(ev.event_type) || /antivirus/i.test(ev.vendor ?? "");
  const hasProc = !!(p.name || p.cmdline);
  const filePath = f.file.path && !/^memory:/i.test(f.file.path) ? f.file.path : undefined;
  const entity = hasProc ? "Process" : filePath ? "File" : f.net.remoteIp ? "Ip" : "Machine";
  const category = (tactic && TACTICS[tactic]?.token) ?? (entity === "File" ? "Malware" : "SuspiciousActivity");
  const m = d.name ? DEFENDER_THREAT.exec(d.name) : null;
  const verb = action === "detected" ? "detected" : "prevented";
  let title: string;
  let family: string | null = null;
  if (m) {
    family = m[3].split(".")[0];
    const kind = /hacktool/i.test(m[1]) ? "hacktool" : /^pua|^app$/i.test(m[1]) ? "unwanted software" : "malware";
    title = `'${family}' ${kind} was ${verb}`;
  } else if (d.name && isNative(ev)) {
    title = d.name; // authored for Defender: keep the detection name verbatim
    if (av) family = d.name;
  } else if (entity === "File") {
    title = `Malware was ${verb}`;
  } else if (techName) {
    title = `Suspicious ${techName} activity`;
  } else {
    title = tactic ? `Suspicious ${tactic.toLowerCase()} activity` : "Suspicious activity";
  }
  const alertId = `da${String(ctx.int(`${ev.id}:mde:alert:a`, 100_000_000, 999_999_999))}${String(ctx.int(`${ev.id}:mde:alert:b`, 100_000_000, 999_999_999))}_${ctx.int(`${ev.id}:mde:alert:c`, -2_147_483_648, 2_147_483_647)}`;
  const sameImage = !!(filePath && p.name && baseOf(filePath)?.toLowerCase() === p.name.toLowerCase());
  const procDir = dirOf(p.path ?? undefined) ?? (sameImage ? dirOf(filePath) : undefined) ?? null;
  const row: Record<string, unknown> = {
    Timestamp: base.Timestamp,
    AlertId: alertId,
    Title: title,
    Categories: JSON.stringify([category]),
    AttackTechniques: JSON.stringify(d.techniqueId ? [`${techName ?? d.techniqueId} (${d.techniqueId})`] : []),
    ServiceSource: "Microsoft Defender for Endpoint",
    DetectionSource: av ? "Antivirus" : "EDR",
    EntityType: entity,
    EvidenceRole: entity === "Process" || entity === "Machine" ? "Impacted" : "Related",
    EvidenceDirection: entity === "Ip" ? "Destination" : null,
    FileName: null, FolderPath: null, SHA1: null, SHA256: null, FileSize: null,
    ThreatFamily: family,
    RemoteIP: null, RemoteUrl: null,
    AccountName: null, AccountDomain: null, AccountSid: null, AccountObjectId: null, AccountUpn: null,
    DeviceId: base.DeviceId,
    DeviceName: host,
    LocalIP: null,
    ProcessCommandLine: null,
    RegistryKey: null, RegistryValueName: null, RegistryValueData: null,
    AdditionalFields: null,
    Severity: SEVERITY[(d.severity ?? "medium").toLowerCase()] ?? "Medium",
    MachineGroup: tail.MachineGroup,
  };
  if (entity === "Process") {
    Object.assign(row, {
      FileName: p.name, FolderPath: procDir, SHA1: p.sha1,
      SHA256: p.sha256 ?? (sameImage ? f.file.sha256 ?? null : null),
      FileSize: sameImage ? f.file.size ?? null : null,
      AccountName: u.name, AccountDomain: u.domain, AccountSid: u.sid, AccountObjectId: u.objectId, AccountUpn: u.upn,
      ProcessCommandLine: p.cmdline,
      AdditionalFields: JSON.stringify({ ProcessId: p.pid === null ? null : String(p.pid), ImageFile: { FileName: p.name, FolderPath: procDir } }),
    });
  } else if (entity === "File") {
    Object.assign(row, {
      FileName: f.file.name ?? baseOf(filePath), FolderPath: dirOf(filePath) ?? null,
      SHA1: ctx.hex(`sha1:${f.file.sha256 ?? filePath!.toLowerCase()}`, 40),
      SHA256: f.file.sha256 ?? null, FileSize: f.file.size ?? null,
    });
  } else if (entity === "Ip") {
    Object.assign(row, { RemoteIP: f.net.remoteIp, RemoteUrl: f.net.url ?? f.net.domain ?? null });
  } else {
    row.LocalIP = isPrivate(f.hostIp) ? f.hostIp : null;
  }
  return row;
}

/**
 * The AlertInfo row (one per alert) that accompanies an AlertEvidence row produced by
 * fromTelemetry — same AlertId / Title / Severity / techniques, joinable on AlertId.
 */
export function alertInfoFor(evidence: NativeLog): NativeLog | null {
  if (evidence.sourceId !== "mde" || evidence.kind !== "AlertEvidence") return null;
  const r = evidence.record as { time: string; tenantId: string; operationName: string; properties: Record<string, unknown> };
  const e = r.properties;
  let category = "SuspiciousActivity";
  try { category = (JSON.parse(String(e.Categories ?? "[]")) as string[])[0] ?? category; } catch { /* keep default */ }
  return {
    sourceId: "mde", kind: "AlertInfo", format: "json", timeMs: evidence.timeMs,
    record: {
      time: r.time, tenantId: r.tenantId, operationName: r.operationName, category: "AdvancedHunting-AlertInfo",
      properties: {
        Timestamp: e.Timestamp, AlertId: e.AlertId, Title: e.Title, Category: category, Severity: e.Severity,
        ServiceSource: e.ServiceSource, DetectionSource: e.DetectionSource, AttackTechniques: e.AttackTechniques ?? "[]",
        MachineGroup: e.MachineGroup,
      },
    },
  };
}

// ── Use cases (KQL over the Advanced Hunting tables) ────────────────────────
const OFFICE = "^(winword|excel|powerpnt|outlook|onenote|mspub|msaccess|visio)\\.exe$";
const SCRIPT_HOST = "^(powershell|pwsh|cmd|wscript|cscript|mshta)\\.exe$";
// PowerShell accepts any unambiguous prefix of -EncodedCommand (-e, -en, -enc, …).
const ENCODED_FLAG = "\\s[-/]e(c|n|nc|nco|ncod|ncode|ncoded|ncodedc|ncodedco|ncodedcom|ncodedcomm|ncodedcomma|ncodedcommand)?\\s";
const LOLBIN = "^(powershell|pwsh|mshta|rundll32|regsvr32|certutil|bitsadmin|curl|wscript|cscript|msbuild|installutil|wmic)\\.exe$";
const USER_WRITABLE = String.raw`\\(Users\\[^\\]+\\(Downloads|Desktop|Documents|AppData)|ProgramData|Windows\\Temp|Users\\Public)\\`;

const useCases: UseCase[] = [
  {
    id: "mde.office-encoded-script-host",
    title: "Office application spawned a script host with an encoded command",
    sourceId: "mde", kinds: ["DeviceProcessEvents"], severity: "high", mitre: ["T1566.001", "T1204.002", "T1059.001", "T1027"],
    description: "A Word/Excel/PowerPoint/Outlook process created PowerShell, cmd, wscript, cscript or mshta whose command line carries an encoded-command switch. Documents have no business launching hidden encoded scripts — this is the classic macro-dropper chain. In DeviceProcessEvents the creator is InitiatingProcessFileName and the new process is FileName.",
    logic: "// KQL — Microsoft Defender XDR Advanced Hunting\nDeviceProcessEvents\n| where ActionType == \"ProcessCreated\"\n| where InitiatingProcessFileName in~ (\"winword.exe\",\"excel.exe\",\"powerpnt.exe\",\"outlook.exe\",\"onenote.exe\",\"mspub.exe\",\"msaccess.exe\",\"visio.exe\")\n| where FileName in~ (\"powershell.exe\",\"pwsh.exe\",\"cmd.exe\",\"wscript.exe\",\"cscript.exe\",\"mshta.exe\")\n| where ProcessCommandLine matches regex @\"(?i)\\s[-/]e(nc|ncodedcommand|c)?\\s\"\n| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA1",
    match: { all: [
      { field: "properties.ActionType", op: "eq", value: "ProcessCreated" },
      { field: "properties.InitiatingProcessFileName", op: "regex", value: OFFICE },
      { field: "properties.FileName", op: "regex", value: SCRIPT_HOST },
      { field: "properties.ProcessCommandLine", op: "regex", value: ENCODED_FLAG },
    ] },
    falsePositives: ["Signed internal Office add-ins that shell out to PowerShell (verify the add-in, the signer and the decoded command)", "Admin test documents used in awareness exercises"],
  },
  {
    id: "mde.lolbin-external-connection",
    title: "Living-off-the-land binary connected to a public IP",
    sourceId: "mde", kinds: ["DeviceNetworkEvents"], severity: "high", mitre: ["T1105", "T1218", "T1071.001"],
    description: "A built-in Windows binary that attackers abuse to download or run payloads (PowerShell, mshta, rundll32, regsvr32, certutil, bitsadmin, curl, script hosts, msbuild…) completed an outbound connection to a public address. Pivot on InitiatingProcessCommandLine and RemoteUrl, then check what the same InitiatingProcessId did next in DeviceFileEvents.",
    logic: "// KQL\nDeviceNetworkEvents\n| where ActionType == \"ConnectionSuccess\" and RemoteIPType == \"Public\"\n| where InitiatingProcessFileName in~ (\"powershell.exe\",\"pwsh.exe\",\"mshta.exe\",\"rundll32.exe\",\"regsvr32.exe\",\"certutil.exe\",\"bitsadmin.exe\",\"curl.exe\",\"wscript.exe\",\"cscript.exe\",\"msbuild.exe\",\"installutil.exe\",\"wmic.exe\")\n| summarize Connections=count(), Urls=make_set(RemoteUrl) by DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP",
    match: { all: [
      { field: "properties.ActionType", op: "eq", value: "ConnectionSuccess" },
      { field: "properties.RemoteIPType", op: "eq", value: "Public" },
      { field: "properties.InitiatingProcessFileName", op: "regex", value: LOLBIN },
    ] },
    falsePositives: ["IT automation that uses PowerShell/curl to reach vendor APIs or package feeds — baseline by RemoteUrl and the signer of the parent", "Software updaters invoked through rundll32"],
  },
  {
    id: "mde.dropped-executable-run-from-user-folder",
    title: "Executable written to a user-writable folder and then executed",
    sourceId: "mde", kinds: ["DeviceFileEvents", "DeviceProcessEvents"], severity: "medium", mitre: ["T1204.002", "T1105", "T1036.005"],
    description: "The same device first records a FileCreated row for an .exe/.dll/.scr in Downloads, Desktop, AppData, ProgramData, Windows\\Temp or Users\\Public, and within an hour a ProcessCreated row whose FileName is that file. Legitimate software installs to Program Files; payloads land in folders any user can write to.",
    logic: "// KQL\nlet drops = DeviceFileEvents\n| where ActionType in (\"FileCreated\",\"FileRenamed\") and FileName matches regex @\"(?i)\\.(exe|dll|scr|com)$\"\n| where FolderPath matches regex @\"(?i)\\\\(Users\\\\[^\\\\]+\\\\(Downloads|Desktop|Documents|AppData)|ProgramData|Windows\\\\Temp|Users\\\\Public)\\\\\"\n| project DropTime=Timestamp, DeviceId, FileName, SHA1, Dropper=InitiatingProcessFileName;\nDeviceProcessEvents\n| join kind=inner drops on DeviceId, FileName\n| where Timestamp between (DropTime .. DropTime + 1h)",
    match: { any: [
      { all: [
        { field: "category", op: "eq", value: "AdvancedHunting-DeviceFileEvents" },
        { field: "properties.ActionType", op: "in", value: ["FileCreated", "FileRenamed"] },
        { field: "properties.FileName", op: "regex", value: "\\.(exe|dll|scr|com)$" },
        { field: "properties.FolderPath", op: "regex", value: USER_WRITABLE },
      ] },
      { all: [
        { field: "category", op: "eq", value: "AdvancedHunting-DeviceProcessEvents" },
        { field: "properties.FolderPath", op: "regex", value: USER_WRITABLE },
      ] },
    ] },
    threshold: { groupBy: ["properties.DeviceId", "properties.FileName"], count: 2, windowSec: 3600, distinct: "category" },
    falsePositives: ["Per-user installers (Teams, Zoom, Chrome) that unpack into AppData and run — allow-list by signer", "Portable admin tools run from Downloads by IT staff"],
  },
  {
    id: "mde.credential-access-alert",
    title: "Defender alert in the Credential Access category",
    sourceId: "mde", kinds: ["AlertInfo", "AlertEvidence"], severity: "high", mitre: ["T1003", "T1555", "T1539"],
    description: "Any Defender alert whose Category (AlertInfo) or Categories (AlertEvidence) is CredentialAccess — credential dumping, browser credential theft, cookie theft. Stolen credentials let the attacker log in as the user anywhere, so these alerts are escalated even when the process was stopped: reset the account and revoke sessions.",
    logic: "// KQL\nAlertInfo\n| where Category == \"CredentialAccess\"\n| join kind=inner (AlertEvidence | where EntityType in (\"Process\",\"File\",\"User\",\"Machine\")) on AlertId\n| project Timestamp, AlertId, Title, Severity, EntityType, DeviceName, AccountName, FileName, ProcessCommandLine",
    match: { any: [
      { field: "properties.Category", op: "eq", value: "CredentialAccess" },
      { field: "properties.Categories", op: "contains", value: "\"CredentialAccess\"" },
    ] },
    falsePositives: ["Authorised penetration tests / red-team exercises (confirm the engagement window)", "Password-manager or backup agents reading browser stores"],
  },
  {
    id: "mde.high-severity-alert",
    title: "High-severity Defender alert",
    sourceId: "mde", kinds: ["AlertInfo", "AlertEvidence"], severity: "high", mitre: [],
    description: "Defender rates the alert High (its top severity — Defender has no 'Critical'). High alerts go to the front of the queue: open the alert story, check whether the activity was prevented, and decide on isolating the device.",
    logic: "// KQL\nAlertInfo\n| where Severity == \"High\"\n| join kind=inner AlertEvidence on AlertId\n| summarize Entities=make_set(EntityType), Devices=make_set(DeviceName) by AlertId, Title, Category, DetectionSource",
    match: { field: "properties.Severity", op: "eq", value: "High" },
    falsePositives: ["Known test files (EICAR) and sanctioned security tooling", "Duplicate alerts for an already-contained incident"],
  },
  {
    id: "mde.run-key-persistence",
    title: "Registry Run key value written",
    sourceId: "mde", kinds: ["DeviceRegistryEvents"], severity: "medium", mitre: ["T1547.001"],
    description: "A value was set under a CurrentVersion\\Run or RunOnce key, so its data (a program path) starts at every logon. Check RegistryValueData: a binary in AppData, Temp, ProgramData or on removable media written by a freshly downloaded process is persistence, not software installation.",
    logic: "// KQL\nDeviceRegistryEvents\n| where ActionType == \"RegistryValueSet\"\n| where RegistryKey matches regex @\"(?i)\\\\CurrentVersion\\\\Run(Once)?$\"\n| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine",
    match: { all: [
      { field: "properties.ActionType", op: "eq", value: "RegistryValueSet" },
      { field: "properties.RegistryKey", op: "regex", value: "\\\\CurrentVersion\\\\Run(Once)?$" },
    ] },
    falsePositives: ["Software installers and updaters (OneDrive, Teams, vendor agents) registering autostart entries — check the signer and the folder"],
  },
  {
    id: "mde.event-log-cleared-wevtutil",
    title: "Windows event log cleared with wevtutil",
    sourceId: "mde", kinds: ["DeviceProcessEvents", "AlertEvidence"], severity: "high", mitre: ["T1070.001"],
    description: "wevtutil.exe ran with the clear-log verb (cl / clear-log). Wiping Security or System logs destroys the evidence trail and is almost always done by an intruder covering tracks after privilege escalation.",
    logic: "// KQL\nunion DeviceProcessEvents, (AlertEvidence | where EntityType == \"Process\")\n| where FileName =~ \"wevtutil.exe\"\n| where ProcessCommandLine matches regex @\"(?i)\\s(cl|clear-log)\\s\"\n| project Timestamp, DeviceName, AccountName, ProcessCommandLine",
    match: { all: [
      { field: "properties.FileName", op: "regex", value: "^wevtutil\\.exe$" },
      { field: "properties.ProcessCommandLine", op: "regex", value: "\\s(cl|clear-log)\\s" },
    ] },
    falsePositives: ["Golden-image / VDI build scripts that clear logs before sealing the image"],
  },
];

export const source: NativeSource = {
  schema: {
    sourceId: "mde",
    category: "edr",
    card: "edr-defender-endpoint.md",
    product: "Microsoft Defender for Endpoint",
    format: "json",
    vendorMatch: VENDOR_MATCH,
    telemetrySources: ["edr", "av"],
    kinds,
  },
  fromTelemetry,
  useCases,
};
