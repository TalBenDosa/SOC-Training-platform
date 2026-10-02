/**
 * CrowdStrike Falcon — native module (card: docs/log-schemas/edr-crowdstrike.md).
 *
 * Two native representations, never mixed:
 *   - Falcon Data Replicator (FDR) raw sensor events — flat JSON, PascalCase keys, EVERY value a
 *     string, keys sorted as on the wire: ProcessRollup2, DnsRequest, NetworkConnectIP4,
 *     NetworkReceiveAcceptIP4, PeFileWritten / NewScriptWritten / OoxmlFileWritten /
 *     ZipFileWritten / GenericFileWritten, AsepValueUpdate / RegGenericValueUpdate, UserLogon /
 *     UserLogonFailed2. Current-sensor host context (ComputerName + LocalAddressIP4) is carried.
 *   - Alerts API v2 resource (kind "alert") for detections — nested snake_case, typed values.
 * Card-only kinds (validated against the card samples, never produced from telemetry because the
 * platform has no such events): Event Streams EppDetectionSummaryEvent, aidmaster, userinfo.
 *
 * Input = vendor-neutral facts from ./edr-normalize (edrFacts), so a Defender-, SentinelOne- or
 * Sophos-authored event renders here too. Correlation (card §5):
 *   - same host → same `aid` (seeded `${companyId}:${host}`), `cid` = ctx.tenant.crowdstrikeCid;
 *   - a process's TargetProcessId (UPID) is seeded from host + image name + OS pid, so the
 *     ContextProcessId on its own DnsRequest / NetworkConnectIP4 / *FileWritten events and the
 *     ParentProcessId of its children are the same value; alert `process_id` = that UPID too;
 *   - AuthenticationId (logon LUID) is stable per host + user ("999" for SYSTEM).
 * Raw Windows ProcessRollup2 carries NO user name (card §6) — only UserSid / AuthenticationId; the
 * name comes from UserLogon or, on file events, the event's own UserName. Linux PR2 carries UserName.
 *
 * Returns null (never fakes a record) for: device-control / USB / file-read telemetry (edrFacts
 * unsupported), file deletions (ExecutableDeleted has no documented field inventory), process
 * events with no image at all, network events with no IPv4 peer, and client-side logon failures
 * (an ssh/RDP client failing against a REMOTE server is not a logon on the sensor host).
 */
import { techniqueById } from "@/lib/mitre/attack";
import type { NativeSource, NativeLog, KindSchema, UseCase, NativeCtx } from "../types";
import type { TelemetryEvent } from "@/lib/sim/types";
import { edrFacts, type EdrFacts, type EdrProc } from "./edr-normalize";
import {
  osOf, rhex, ruuid, hostIpOf, egressIp, hostRole, digits, secMs, iso, isoNano, userOf, procName, imagePath, ntDevicePath,
  pidOf, procSeed, netFacts, registryFacts, fixPath, baseName, isIPv4, alt, OFFICE, SCRIPT_HOSTS, LOLBINS,
  PRIVATE_CIDRS, USER_WRITABLE_RE, DOWNLOADS_PUBLIC_RE, type UserFacts,
} from "./_cs-s1-common";

// ── schema ───────────────────────────────────────────────────────────────────

const COMMON_REQ = ["aid", "aip", "cid", "event_platform", "event_simpleName", "id", "name", "timestamp", "ConfigBuild", "ConfigStateHash", "Entitlements", "EffectiveTransmissionClass"];
const COMMON_OPT = ["EventOrigin", "ComputerName", "LocalAddressIP4"];
const CTX = ["ContextProcessId", "ContextTimeStamp"];

const PR2: KindSchema = {
  required: [...COMMON_REQ, "TargetProcessId", "ParentProcessId", "RawProcessId", "CommandLine", "ProcessStartTime", "ProcessEndTime"],
  optional: [...COMMON_OPT, "SourceProcessId", "SourceThreadId", "ImageFileName", "ParentBaseFileName", "SHA256HashData", "SHA1HashData",
    "MD5HashData", "UserSid", "AuthenticationId", "ParentAuthenticationId", "IntegrityLevel", "TokenType", "SessionId", "ImageSubsystem",
    "ProcessCreateFlags", "ProcessParameterFlags", "ProcessSxsFlags", "WindowFlags", "SignInfoFlags", "AuthenticodeHashData", "Tags",
    "LinkName", "ShowWindowFlags", "RpcClientProcessId",
    // Linux ProcessRollup2LinV12 carries UserName on the raw event (card §1); never emitted on Windows.
    "UserName"],
};
const NET: KindSchema = {
  required: [...COMMON_REQ, ...CTX, "LocalAddressIP4", "LocalPort", "RemoteAddressIP4", "RemotePort", "Protocol", "ConnectionDirection"],
  optional: ["EventOrigin", "ComputerName", "ContextBaseFileName", "ConnectionFlags", "InContext"],
};
const PE_WRITTEN: KindSchema = {
  required: [...COMMON_REQ, ...CTX, "TargetFileName"],
  optional: [...COMMON_OPT, "AuthenticationId", "ContextBaseFileName", "ContextImageFileName", "ContextThreadId", "DiskParentDeviceInstanceId",
    "DllCharacteristics", "FileCategory", "FileEcpBitmask", "FileIdentifier", "FileObject", "FileOperatorSid", "FileWrittenFlags",
    "ImageCheckSum", "ImageEntryPoint", "ImageSubsystem", "ImageTimeStamp", "IrpFlags", "IsOnNetwork", "IsOnRemovableDisk",
    "IsTransactedFile", "MajorFunction", "MinorFunction", "ModuleCharacteristics", "OperationFlags", "SHA256HashData", "Size", "TokenType", "UserName"],
};
/**
 * NewScriptWritten / NewExecutableWritten field inventory (card §3h). The other *FileWritten
 * types (OoxmlFileWritten, ZipFileWritten, GenericFileWritten) are listed in §3a without their own
 * inventory; they are rendered with this sibling layout (the card argues the same way for
 * PeFileWritten ↔ PngFileWritten). SHA256HashData / Size / UserName follow PeFileWritten (§3c:
 * "hash may be absent on some write events") — UNVERIFIED on the non-PE types.
 */
const FILE_WRITTEN: KindSchema = {
  required: [...COMMON_REQ, ...CTX, "TargetFileName"],
  optional: [...COMMON_OPT, "ContextBaseFileName", "ContextImageFileName", "ContextThreadId", "DesiredAccess", "FileAttributes", "FileEcpBitmask",
    "FileIdentifier", "FileObject", "Information", "IrpFlags", "MajorFunction", "MinorFunction", "OperationFlags", "Options", "ShareAccess",
    "Status", "SHA256HashData", "Size", "UserName"],
};
const REG_COMMON = ["RegObjectName", "RegValueName", "RegOperationType", ...CTX];
const ALERT_OPT_DETAILS = ["cmdline", "filename", "filepath", "local_process_id", "md5", "process_graph_id", "process_id", "sha256", "timestamp", "user_graph_id", "user_id", "user_name"];
const DISPOSITION_KEYS = ["blocking_unsupported_or_disabled", "bootup_safeguard_enabled", "critical_process_disabled", "detect", "fs_operation_blocked",
  "handle_operation_downgraded", "inddet_mask", "indicator", "kill_action_failed", "kill_parent", "kill_process", "kill_subprocess", "operation_blocked",
  "policy_disabled", "process_blocked", "quarantine_file", "quarantine_machine", "registry_operation_blocked", "rooting", "sensor_only", "suspend_parent", "suspend_process"];
const DEVICE_KEYS = ["agent_load_flags", "agent_local_time", "agent_version", "cid", "config_id_base", "config_id_build", "config_id_platform", "device_id",
  "external_ip", "first_seen", "groups[]", "hostinfo.active_directory_dn_display[]", "hostinfo.domain", "hostname", "last_seen", "local_ip", "mac_address",
  "machine_domain", "major_version", "minor_version", "modified_timestamp", "os_version", "ou[]", "platform_id", "platform_name", "product_type",
  "product_type_desc", "site_name", "status", "system_manufacturer", "system_product_name"];

const kinds: Record<string, KindSchema> = {
  ProcessRollup2: PR2,
  DnsRequest: {
    required: [...COMMON_REQ, ...CTX, "DomainName", "RequestType", "QueryStatus"],
    optional: [...COMMON_OPT, "ContextThreadId", "ContextBaseFileName", "IP4Records", "FirstIP4Record", "CNAMERecords", "RespondingDnsServer",
      "DnsResponseType", "DualRequest", "DnsRequestCount", "InterfaceIndex"],
  },
  NetworkConnectIP4: NET,
  NetworkReceiveAcceptIP4: NET,
  PeFileWritten: PE_WRITTEN,
  NewScriptWritten: FILE_WRITTEN,
  OoxmlFileWritten: FILE_WRITTEN,
  ZipFileWritten: FILE_WRITTEN,
  GenericFileWritten: FILE_WRITTEN,
  AsepValueUpdate: {
    required: [...COMMON_REQ, ...REG_COMMON],
    optional: [...COMMON_OPT, "RegStringValue", "RegType", "AsepClass", "AsepFlags", "AsepIndex", "AsepValueType", "Data1", "TargetFileName",
      "TargetCommandLineParameters", "TargetSHA256HashData", "AuthenticationId", "TokenType", "ContextThreadId"],
  },
  RegGenericValueUpdate: {
    required: [...COMMON_REQ, ...REG_COMMON],
    optional: [...COMMON_OPT, "RegStringValue", "RegType", "RegClassification", "RegClassificationFlags", "RegClassificationIndex",
      "AuthenticationId", "TokenType", "ContextThreadId"],
  },
  UserLogon: {
    required: [...COMMON_REQ, "UserName", "UserSid", "AuthenticationId", "LogonType", "LogonTime", "ContextTimeStamp"],
    optional: [...COMMON_OPT, "AuthenticationPackage", "ClientComputerName", "ContextProcessId", "ContextThreadId", "EnabledPrivilegesBitmask",
      "LogonDomain", "LogonServer", "PasswordLastSet", "PrivilegesBitmask", "RemoteAccount", "UserFlags", "UserGroupsBitmask", "UserIsAdmin",
      "UserLogonFlags", "UserPrincipal"],
  },
  UserLogonFailed2: {
    required: [...COMMON_REQ, "UserName", "LogonType", "Status"],
    optional: [...COMMON_OPT, "LogonDomain", "SubStatus", "RemoteAddressIP4", "ClientComputerName", "EtwRawProcessId", "EtwRawThreadId", "RawProcessId", "TargetProcessId"],
  },
  alert: {
    required: ["composite_id", "id", "indicator_id", "aggregate_id", "agent_id", "cid", "product", "type", "name", "description", "severity",
      "severity_name", "confidence", "status", "pattern_id", "pattern_disposition", "pattern_disposition_description",
      "pattern_disposition_details.detect", "pattern_disposition_details.kill_process", "timestamp", "created_timestamp", "updated_timestamp",
      "device.device_id", "device.hostname", "platform", "process_id"],
    optional: ["alleged_filetype", "cloud_indicator", "cmdline", "context_timestamp", "control_graph_id", "data_domains[]", "display_name",
      ...DEVICE_KEYS.map(k => `device.${k}`), "falcon_host_link", "filename", "filepath",
      ...ALERT_OPT_DETAILS.map(k => `grandparent_details.${k}`), ...ALERT_OPT_DETAILS.map(k => `parent_details.${k}`),
      "local_process_id", "logon_domain", "md5", "objective", "parent_process_id",
      ...DISPOSITION_KEYS.map(k => `pattern_disposition_details.${k}`), "process_end_time", "process_start_time", "scenario", "sha1", "sha256",
      "show_in_ui", "source_products[]", "source_vendors[]", "tactic", "tactic_id", "technique", "technique_id", "tree_id", "tree_root",
      "triggering_process_graph_id", "user_id", "user_name", "ioc_type", "ioc_value", "ioc_source", "ioc_description"],
  },
  // ── card-only kinds (never produced by fromTelemetry) ──
  EppDetectionSummaryEvent: {
    required: ["metadata.customerIDString", "metadata.offset", "metadata.eventType", "metadata.eventCreationTime", "metadata.version", "event.AgentId", "event.CompositeId", "event.Name"],
    optional: ["AggregateId", "CommandLine", "DataDomains", "Description", "FalconHostLink", "FileName", "FilePath", "GrandParentCommandLine",
      "GrandParentImageFileName", "GrandParentImageFilePath", "HostGroups", "Hostname", "LocalIP", "LocalIPv6", "LogonDomain", "MACAddress",
      "MD5String", "Objective", "ParentCommandLine", "ParentImageFileName", "ParentImageFilePath", "ParentProcessId",
      "PatternDispositionDescription", ...["Indicator", "Detect", "InddetMask", "SensorOnly", "Rooting", "KillProcess", "KillSubProcess",
        "QuarantineMachine", "QuarantineFile", "PolicyDisabled", "KillParent", "OperationBlocked", "ProcessBlocked", "RegistryOperationBlocked",
        "CriticalProcessDisabled", "BootupSafeguardEnabled", "FsOperationBlocked", "HandleOperationDowngraded", "KillActionFailed",
        "BlockingUnsupportedOrDisabled", "SuspendProcess", "SuspendParent"].map(k => `PatternDispositionFlags.${k}`),
      "PatternDispositionValue", "PatternId", "ProcessEndTime", "ProcessId", "ProcessStartTime", "SHA1String", "SHA256String", "Severity",
      "SeverityName", "SourceProducts", "SourceVendors", "Tactic", "Technique", "Type", "UserName"].map(k => `event.${k}`),
  },
  aidmaster: {
    required: ["aid", "cid", "aip", "event_platform", "ComputerName", "Time"],
    optional: ["AgentLoadFlags", "AgentLocalTime", "AgentTimeOffset", "AgentVersion", "BiosManufacturer", "BiosVersion", "ChassisType", "City",
      "ConfigBuild", "ConfigIDBuild", "Continent", "Country", "FalconGroupingTags", "FirstSeen", "HostHiddenStatus", "MachineDomain", "OU",
      "PointerSize", "ProductType", "SensorGroupingTags", "ServicePackMajor", "SiteName", "SystemManufacturer", "SystemProductName", "Timezone", "Version"],
  },
  userinfo: {
    required: ["UserSid_readable", "User", "cid", "_time"],
    optional: ["AccountType", "LastLoggedOnHost", "LocalAdminAccess", "LogonInfo", "LogonTime", "LogonType", "PasswordLastSet", "UserIsAdmin",
      "UserLogonFlags_decimal", "event_platform", "monthsincereset"],
  },
};

export function kindOf(record: Record<string, unknown>): string | null {
  if (typeof record.event_simpleName === "string") return record.event_simpleName;
  const meta = record.metadata as Record<string, unknown> | undefined;
  if (meta && typeof meta.eventType === "string") return meta.eventType;
  if (typeof record.composite_id === "string") return "alert";
  if ("AgentVersion" in record && "aid" in record) return "aidmaster";
  if ("UserSid_readable" in record) return "userinfo";
  return null;
}

// ── rendering helpers ────────────────────────────────────────────────────────

/** Versioned `name`. Card-confirmed: PR2 V19, DnsRequest V5, NetworkConnectIP4 V5, PeFileWritten V14, UserLogon V8,
 *  ProcessRollup2LinV12. The other suffixes are not public — UNVERIFIED (sibling versions used). */
const NAME_SUFFIX: Record<string, string> = {
  ProcessRollup2: "V19", DnsRequest: "V5", NetworkConnectIP4: "V5", NetworkReceiveAcceptIP4: "V5", PeFileWritten: "V14",
  NewScriptWritten: "V12", OoxmlFileWritten: "V12", ZipFileWritten: "V12", GenericFileWritten: "V12",
  AsepValueUpdate: "V7", RegGenericValueUpdate: "V7", UserLogon: "V8", UserLogonFailed2: "V2",
};
const INTEGRITY: Record<string, string> = { low: "4096", medium: "8192", high: "12288", system: "16384" };
const CONSOLE = new Set(["cmd.exe", "powershell.exe", "pwsh.exe", "cscript.exe", "reg.exe", "net.exe", "net1.exe", "certutil.exe", "wmic.exe",
  "schtasks.exe", "vssadmin.exe", "ntdsutil.exe", "bitsadmin.exe", "wevtutil.exe", "robocopy.exe", "curl.exe", "whoami.exe", "nltest.exe",
  "ipconfig.exe", "ping.exe", "7z.exe", "rclone.exe", "psexec.exe", "psexesvc.exe", "python.exe", "node.exe", "git.exe", "kubectl.exe", "docker.exe"]);
const MS_SIGNED_FLAGS = "8683538"; // seen on Microsoft-signed powershell.exe (card §3b)
const PE_EXT = new Set(["exe", "dll", "sys", "scr", "cpl", "ocx", "drv", "efi", "com"]);
const SCRIPT_EXT = new Set(["ps1", "psm1", "psd1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "bat", "cmd", "py", "sh"]);
const OOXML_EXT = new Set(["docx", "docm", "dotm", "xlsx", "xlsm", "xltm", "pptx", "pptm"]);

const sortKeys = (o: Record<string, unknown>) =>
  Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));

const aidOf = (ctx: NativeCtx, host: string) => rhex(ctx, `${ctx.companyId}:${host}:aid`, 32);
/** Falcon-unique process id (UPID) — 12 decimal digits, stable per process instance. */
const upid = (ctx: NativeCtx, seed: string) => `2${digits(ctx, `${seed}:upid`, 11)}`;
const threadId = (ctx: NativeCtx, seed: string) => `1${digits(ctx, `${seed}:tid`, 11)}`;
const luid = (ctx: NativeCtx, host: string, u: UserFacts) => (u.system ? "999" : u.user ? digits(ctx, `${ctx.companyId}:${host}:${u.user.toLowerCase()}:luid`, 7) : undefined);

interface Base { ctx: NativeCtx; ev: TelemetryEvent; f: EdrFacts; host: string; os: "Win" | "Lin" | "Mac"; hostIp: string; aid: string; u: UserFacts }

function common(b: Base, simple: string, cls = "3"): Record<string, unknown> {
  const { ctx, ev, f, host, os } = b;
  const name = simple === "ProcessRollup2" && os === "Lin" ? "ProcessRollup2LinV12" : `${simple}${NAME_SUFFIX[simple] ?? ""}`;
  return {
    aid: b.aid, aip: egressIp(ctx), cid: ctx.tenant.crowdstrikeCid, event_platform: os, event_simpleName: simple,
    id: ruuid(ctx, `${ev.id}:crowdstrike:id`), name,
    // `timestamp` = cloud receive time (epoch ms) — lags the sensor time by a fraction of a second.
    timestamp: String(f.timeMs + ctx.int(`${ev.id}:cs:lag`, 90, 950)),
    ConfigBuild: "1007.3.0019807.1", ConfigStateHash: String(ctx.int(`${ctx.companyId}:${host}:csh`, 100_000_000, 4_000_000_000)),
    Entitlements: "15", EffectiveTransmissionClass: cls, EventOrigin: "1", ComputerName: host, LocalAddressIP4: b.hostIp,
  };
}

/** Context* fields naming the actor process (or an opaque, stable id when the actor is not authored). */
function actor(b: Base, p: EdrProc, fallbackSeed: string): Record<string, unknown> {
  const { ctx, host, f } = b;
  const known = !!procName(p);
  const seed = known ? procSeed(ctx, host, p) : `${ctx.companyId}:${host}:${fallbackSeed}`;
  const path = known ? imagePath(p) : undefined;
  return {
    ContextProcessId: upid(ctx, seed),
    ContextBaseFileName: known ? procName(p) : undefined,
    ContextImageFileName: path && b.os === "Win" ? ntDevicePath(path) : path,
    ContextThreadId: threadId(ctx, `${seed}:${f.eventId}`),
    ContextTimeStamp: secMs(f.timeMs),
  };
}

function signFlags(p: EdrProc, path?: string): string | undefined {
  if (p.signed === false) return "0";
  if (p.signed === true || (path && /^([A-Za-z]:|\\Device\\HarddiskVolume\d+)\\(Windows\\|Program Files\\Microsoft Office\\)/i.test(path))) return MS_SIGNED_FLAGS;
  return undefined;
}

// ── per-kind renderers ───────────────────────────────────────────────────────

function processRollup2(b: Base): Record<string, unknown> | null {
  const { ctx, f, host, os, u } = b;
  const p = f.proc;
  const name = procName(p);
  if (!name && !p.cmdline) return null;
  const path = imagePath(p);
  const seed = procSeed(ctx, host, p);
  const parentSeed = f.parent.name || f.parent.path ? procSeed(ctx, host, f.parent) : `${seed}:unattributed-parent`;
  const ppid = upid(ctx, parentSeed);
  const auth = luid(ctx, host, u);
  const win = os === "Win";
  const cmd = p.cmdline ?? (path ? (path.includes(" ") ? `"${path}"` : path) : name!);
  return {
    ...common(b, "ProcessRollup2"),
    TargetProcessId: upid(ctx, seed), ParentProcessId: ppid, SourceProcessId: ppid, SourceThreadId: threadId(ctx, parentSeed),
    RawProcessId: String(pidOf(ctx, host, p)),
    ImageFileName: path ? (win ? ntDevicePath(path) : path) : undefined,
    CommandLine: cmd,
    ParentBaseFileName: f.parent.name ?? baseName(f.parent.path),
    SHA256HashData: p.sha256, MD5HashData: p.md5, SHA1HashData: win && p.sha256 ? "0".repeat(40) : undefined,
    AuthenticodeHashData: win && p.sha256 ? rhex(ctx, `${p.sha256}:authenticode`, 64) : undefined,
    SignInfoFlags: win ? signFlags(p, path) : undefined,
    UserSid: win ? u.sid : undefined,
    AuthenticationId: win ? auth : undefined, ParentAuthenticationId: win ? auth : undefined,
    IntegrityLevel: win ? (INTEGRITY[(p.integrity ?? "").toLowerCase()] ?? (u.system ? "16384" : "8192")) : undefined,
    TokenType: win ? "1" : undefined, SessionId: win ? (u.system ? "0" : "1") : undefined,
    ImageSubsystem: win ? (CONSOLE.has((name ?? "").toLowerCase()) ? "3" : "2") : undefined,
    ProcessCreateFlags: win ? "1024" : undefined, ProcessParameterFlags: win ? "24577" : undefined, ProcessSxsFlags: win ? "64" : undefined,
    WindowFlags: win ? "128" : undefined, Tags: win ? "25, 27, 874, 12094627905582, 12094627906234" : undefined,
    ProcessStartTime: secMs(f.timeMs), ProcessEndTime: "",
    UserName: os === "Lin" ? u.user : undefined,
  };
}

const QTYPE: Record<string, string> = { A: "1", NS: "2", CNAME: "5", SOA: "6", PTR: "12", MX: "15", TXT: "16", AAAA: "28", SRV: "33", ANY: "255" };

function dnsRequest(b: Base, ev: TelemetryEvent): Record<string, unknown> | null {
  const { f } = b;
  const q = f.dns.query ?? f.net.domain;
  if (!q) return null;
  const rcode = (ev.dns?.rcode ?? "").toUpperCase();
  const status = rcode === "NXDOMAIN" ? "9003" : rcode === "SERVFAIL" ? "9002" : "0";
  const ips = status === "0" ? (f.dns.response ?? "").split(/[;,\s]+/).filter(isIPv4) : [];
  const ipParts = b.hostIp.split(".");
  return {
    ...common(b, "DnsRequest"), ...actor(b, f.proc, `dns-client:${f.eventId}`),
    DomainName: q, RequestType: QTYPE[(f.dns.type ?? "A").toUpperCase()] ?? "1", QueryStatus: status,
    IP4Records: ips.length ? `${ips.join(";")};` : undefined, FirstIP4Record: ips[0],
    RespondingDnsServer: ips.length ? `${ipParts[0]}.${ipParts[1]}.0.10` : undefined, DnsResponseType: ips.length ? "1" : undefined,
    DualRequest: "0", DnsRequestCount: "1", InterfaceIndex: "0",
  };
}

function network(b: Base, ev: TelemetryEvent): { simple: string; rec: Record<string, unknown> } | null {
  const { ctx, f, host } = b;
  const n = netFacts(f, ev);
  if (!n.remoteIp || !isIPv4(n.remoteIp)) return null;
  const simple = n.inbound ? "NetworkReceiveAcceptIP4" : "NetworkConnectIP4";
  const local = n.localIp && isIPv4(n.localIp) ? n.localIp : b.hostIp;
  const localPort = n.localPort ?? ctx.int(`${ev.id}:cs:sport`, 49152, 65535);
  const remotePort = n.remotePort ?? ctx.int(`${ev.id}:cs:rport`, 49152, 65535);
  const a = actor(b, f.proc, n.inbound ? `listener:${localPort}` : `net:${f.eventId}`);
  delete a.ContextThreadId; delete a.ContextImageFileName; // absent on every real Windows network line (card §3c)
  return {
    simple,
    rec: {
      ...common(b, simple), ...a, LocalAddressIP4: local, LocalPort: String(localPort), RemoteAddressIP4: n.remoteIp, RemotePort: String(remotePort),
      Protocol: n.protocol === "udp" ? "17" : "6", ConnectionDirection: n.inbound ? "1" : "0", ConnectionFlags: "0", InContext: "0",
      ComputerName: host,
    },
  };
}

function fileWritten(b: Base, ev: TelemetryEvent): { simple: string; rec: Record<string, unknown> } | null {
  const { ctx, f, host, os, u } = b;
  if (ev.event_type === "file_delete") return null; // ExecutableDeleted: no documented field inventory
  const path = fixPath(f.file.path);
  if (!path) return null;
  const ext = (f.file.extension ?? (/\.([A-Za-z0-9]+)$/.exec(path)?.[1] ?? "")).replace(/^\./, "").toLowerCase();
  const simple = os === "Win" && PE_EXT.has(ext) ? "PeFileWritten" : SCRIPT_EXT.has(ext) ? "NewScriptWritten"
    : OOXML_EXT.has(ext) ? "OoxmlFileWritten" : ext === "zip" ? "ZipFileWritten" : "GenericFileWritten";
  const win = os === "Win";
  const seed = `${ctx.companyId}:${host}:file:${path.toLowerCase()}`;
  const rec: Record<string, unknown> = {
    ...common(b, simple), ...actor(b, f.proc, `writer:${path.toLowerCase()}`),
    TargetFileName: win ? ntDevicePath(path) : path, SHA256HashData: f.file.sha256, Size: f.file.size !== undefined ? String(f.file.size) : undefined,
    UserName: u.user, FileIdentifier: rhex(ctx, `${seed}:fid`, 48), FileObject: "0", IrpFlags: "0", MajorFunction: "0", MinorFunction: "0",
    OperationFlags: "0", FileEcpBitmask: "0",
  };
  if (simple === "PeFileWritten") {
    Object.assign(rec, {
      AuthenticationId: luid(ctx, host, u), TokenType: "1", FileOperatorSid: u.sid, FileCategory: "6", FileWrittenFlags: "0",
      IsOnNetwork: path.startsWith("\\\\") ? "1" : "0", IsOnRemovableDisk: /^[D-Zd-z]:\\/.test(path) ? "1" : "0", IsTransactedFile: "0",
      DiskParentDeviceInstanceId: `PCI\\VEN_144D&DEV_A80A&SUBSYS_0B0F1028&REV_00\\4&${rhex(ctx, `${ctx.companyId}:${host}:disk`, 8)}&0&0008`,
      ImageSubsystem: "2", ImageEntryPoint: String(ctx.int(`${seed}:ep`, 4096, 400_000)),
      ImageTimeStamp: String(Math.floor(f.timeMs / 1000) - ctx.int(`${seed}:link`, 86_400, 86_400 * 400)), ImageCheckSum: "0",
      DllCharacteristics: "33120", ModuleCharacteristics: ext === "dll" ? "8226" : "34",
    });
  } else {
    rec.Status = "0";
  }
  return { simple, rec };
}

const ASEP_RE = /\\(Run|RunOnce|RunServices|RunOnceEx|Winlogon|Image File Execution Options|Shell Folders|User Shell Folders)(\\|$)|\\Services\\[^\\]+$/i;

function registry(b: Base, ev: TelemetryEvent): { simple: string; rec: Record<string, unknown> } | null {
  const { ctx, f, host, os, u } = b;
  if (os !== "Win") return null;
  const rf = registryFacts(f, ev);
  if (!rf) return null;
  const obj = rf.hive === "HKCU" ? `\\REGISTRY\\USER\\${u.sid ?? "S-1-5-18"}\\${rf.keyPath}` : rf.hive === "HKU" ? `\\REGISTRY\\USER\\${rf.keyPath}` : `\\REGISTRY\\MACHINE\\${rf.keyPath}`;
  const asep = ASEP_RE.test(`\\${rf.keyPath}`);
  const simple = asep ? "AsepValueUpdate" : "RegGenericValueUpdate";
  const a = actor(b, f.proc, `reg:${f.eventId}`);
  delete a.ContextBaseFileName; delete a.ContextImageFileName; // not on registry events (card §3h)
  const target = rf.data ? /^"?([A-Za-z]:\\[^"]+?\.(exe|dll|bat|cmd|ps1|vbs|js|scr))"?(\s|$)/i.exec(rf.data)?.[1] : undefined;
  return {
    simple,
    rec: {
      ...common(b, simple), ...a, RegObjectName: obj, RegValueName: rf.valueName, RegStringValue: rf.data, RegType: "1",
      RegOperationType: "1", AuthenticationId: luid(ctx, host, u), TokenType: "1",
      TargetFileName: asep && target ? ntDevicePath(target) : undefined,
    },
  };
}

const CLIENT_TOOLS = /^(ssh|ssh\.exe|putty\.exe|plink\.exe|mstsc\.exe|winscp\.exe|sftp|scp)$/i;

function logon(b: Base, ev: TelemetryEvent): { simple: string; rec: Record<string, unknown> } | null {
  const { ctx, f, host, os, u } = b;
  if (os !== "Win" || !u.user) return null;
  // A client tool failing/succeeding against a remote server: the logon happens on that server.
  if (CLIENT_TOOLS.test(procName(f.proc) ?? "") || (f.net.domain && f.net.domain.toLowerCase() !== host.toLowerCase())) return null;
  const logonType = String(ev.authentication?.logon_type ?? 2);
  if (ev.event_type === "auth_failure") {
    return {
      simple: "UserLogonFailed2",
      rec: {
        ...common(b, "UserLogonFailed2", "2"), UserName: u.user, LogonDomain: u.domain, LogonType: logonType,
        Status: "3221225578", SubStatus: "0", ClientComputerName: host,
        RemoteAddressIP4: ev.src_ip && ev.src_ip !== b.hostIp ? ev.src_ip : undefined,
      },
    };
  }
  const t = secMs(f.timeMs);
  return {
    simple: "UserLogon",
    rec: {
      ...common(b, "UserLogon", "2"), UserName: u.user, LogonDomain: u.domain, UserPrincipal: u.upn, UserSid: u.sid,
      AuthenticationId: luid(ctx, host, u), LogonType: logonType, LogonTime: t, ContextTimeStamp: t,
      AuthenticationPackage: u.system ? "Negotiate" : "Kerberos", UserLogonFlags: "0", UserIsAdmin: "0", ClientComputerName: host,
      ContextProcessId: upid(ctx, `${ctx.companyId}:${host}:lsass`), ContextThreadId: threadId(ctx, `${ctx.companyId}:${host}:lsass:${f.eventId}`),
    },
  };
}

// ── alerts ───────────────────────────────────────────────────────────────────

const SEV: Record<string, [number, string]> = { critical: [90, "Critical"], high: [70, "High"], medium: [50, "Medium"], low: [30, "Low"], informational: [10, "Informational"] };
const TACTIC_ID: Record<string, string> = {
  "initial access": "TA0001", execution: "TA0002", persistence: "TA0003", "privilege escalation": "TA0004", "defense evasion": "TA0005",
  "credential access": "TA0006", discovery: "TA0007", "lateral movement": "TA0008", collection: "TA0009", exfiltration: "TA0010",
  "command and control": "TA0011", impact: "TA0040", reconnaissance: "TA0043", "resource development": "TA0042",
};
const OBJECTIVE: Record<string, string> = {
  "initial access": "Gain Access", execution: "Follow Through", persistence: "Keep Access", "privilege escalation": "Gain Access",
  "defense evasion": "Keep Access", "credential access": "Gain Access", discovery: "Explore", "lateral movement": "Explore",
  collection: "Follow Through", exfiltration: "Follow Through", "command and control": "Contact Controlled Systems", impact: "Follow Through",
};
/** What the sensor did. Code 0 / "Detection, standard detection." is card-confirmed; the non-zero codes and texts are
 *  UNVERIFIED (the card documents the boolean `pattern_disposition_details` flags, which carry the meaning). */
const DISPOSITION: Record<string, { code: number; text: string; flags: string[] }> = {
  detected: { code: 0, text: "Detection, standard detection.", flags: [] },
  killed: { code: 2048, text: "Prevention, process killed.", flags: ["kill_process"] },
  quarantined: { code: 2304, text: "Prevention, process killed and file quarantined.", flags: ["kill_process", "quarantine_file"] },
  blocked: { code: 16, text: "Prevention, process blocked from execution.", flags: ["process_blocked"] },
};

function alert(b: Base, ev: TelemetryEvent): Record<string, unknown> {
  const { ctx, f, host, os, u, aid } = b;
  const d = f.detection!;
  const cid = ctx.tenant.crowdstrikeCid;
  // Triggering process: the authored process, or (on-write / quarantine detections of a file) the file itself.
  const fileFirst = !!f.file.path && (d.action === "quarantined" || !procName(f.proc));
  const trig: EdrProc = fileFirst
    ? { name: f.file.name ?? baseName(fixPath(f.file.path)), path: fixPath(f.file.path), sha256: f.file.sha256 ?? f.proc.sha256, md5: f.file.md5, pid: f.proc.pid, cmdline: f.proc.cmdline }
    : f.proc;
  const tName = procName(trig);
  const tPath = imagePath(trig);
  const seed = tName ? procSeed(ctx, host, trig) : `${ctx.companyId}:${host}:alert:${f.eventId}`;
  const processId = upid(ctx, seed);
  const parentKnown = !!(f.parent.name || f.parent.path);
  const parentId = parentKnown ? upid(ctx, procSeed(ctx, host, f.parent)) : undefined;
  const display = d.name ?? d.technique ?? (d.tactic ? `${d.tactic} activity` : "Suspicious activity");
  const name = d.name && /^[A-Za-z0-9_.]+$/.test(d.name) ? d.name : display.replace(/[^A-Za-z0-9]+(.)?/g, (_, c: string | undefined) => (c ? c.toUpperCase() : "")).replace(/^./, c => c.toUpperCase());
  const patternId = ctx.int(`crowdstrike:pattern:${name}`, 10_000, 59_999);
  const n = digits(ctx, `${ev.id}:cs:ind`, 7);
  const indicator = `ind:${aid}:${processId}-${patternId}-${n}`;
  const composite = `${cid}:${indicator}`;
  const treeId = digits(ctx, `${ctx.companyId}:${host}:tree:${ev.incident_id ?? parentId ?? processId}`, 11);
  const [sevNum, sevName] = SEV[(d.severity ?? "medium").toLowerCase()] ?? SEV.medium;
  const tacticKey = (d.tactic ?? "").toLowerCase();
  const disp = DISPOSITION[d.action];
  const techId = d.techniqueId?.split(",")[0]?.trim();
  const scenario = d.action === "quarantined" ? "known_malware" : /^T1003|^T1555|^T1558/.test(techId ?? "") ? "attacker_methodology" : "suspicious_activity";
  const role = hostRole(host);
  const win = os === "Win";
  const region = /\.eu$|\.de$|\.nl$/.test(ctx.domain) ? "eu-1" : "us-1";
  const created = f.timeMs + ctx.int(`${ev.id}:cs:created`, 4_000, 15_000);
  const ext = tName && /\.([A-Za-z0-9]+)$/.exec(tName)?.[1]?.toLowerCase();
  const containment = String(ev.raw?.["crowdstrike.network_containment_state"] ?? "").toLowerCase();
  return {
    agent_id: aid, aggregate_id: `aggind:${aid}:${treeId}`, alleged_filetype: ext || undefined, cid, cloud_indicator: "false",
    cmdline: trig.cmdline ?? (tPath ? (tPath.includes(" ") ? `"${tPath}"` : tPath) : undefined),
    composite_id: composite, confidence: d.confidence !== undefined ? (d.confidence <= 1 ? Math.round(d.confidence * 100) : Math.round(d.confidence)) : sevNum >= 90 ? 90 : sevNum >= 70 ? 80 : 60,
    context_timestamp: iso(f.timeMs), control_graph_id: `ctg:${aid}:${treeId}`,
    created_timestamp: isoNano(ctx, created, `${ev.id}:cs:cns`), data_domains: ["Endpoint"],
    description: d.description ?? falconDescription(d.action, techId, d.technique ?? display), display_name: display,
    device: {
      agent_load_flags: "0", agent_version: "7.29.19807.0", cid, config_id_build: "19807", device_id: aid,
      external_ip: egressIp(ctx), first_seen: iso(Date.UTC(2025, 10, 3) + ctx.int(`${ctx.companyId}:${host}:fs`, 0, 86_400 * 120) * 1000).replace(/\.\d{3}Z$/, "Z"),
      hostname: host, last_seen: iso(f.timeMs - ctx.int(`${ev.id}:cs:ls`, 30, 600) * 1000).replace(/\.\d{3}Z$/, "Z"), local_ip: b.hostIp,
      mac_address: rhex(ctx, `${ctx.companyId}:${host}:mac`, 12).replace(/(..)(?!$)/g, "$1-"), machine_domain: win ? ctx.domain.toUpperCase() : undefined,
      os_version: win ? (role === "server" || role === "dc" ? "Windows Server 2022" : "Windows 11") : os === "Mac" ? "Sonoma (14)" : "Ubuntu 22.04",
      platform_name: win ? "Windows" : os === "Mac" ? "Mac" : "Linux",
      product_type: role === "dc" ? "2" : role === "server" ? "3" : "1",
      product_type_desc: role === "dc" ? "Domain Controller" : role === "server" ? "Server" : "Workstation",
      status: containment.includes("contain") && !containment.includes("not") ? "contained" : "normal",
    },
    falcon_host_link: `https://falcon.${region}.crowdstrike.com/activity-v2/detections/${composite}?_cid=${cid}`,
    filename: tName, filepath: tPath ? (win ? ntDevicePath(tPath) : tPath) : undefined,
    id: indicator, indicator_id: indicator, local_process_id: tName ? String(pidOf(ctx, host, trig)) : undefined,
    logon_domain: u.user ? u.domain : undefined, md5: trig.md5, name, objective: OBJECTIVE[tacticKey],
    parent_details: parentKnown ? {
      cmdline: f.parent.cmdline, filename: f.parent.name ?? baseName(f.parent.path),
      filepath: imagePath(f.parent) ? (win ? ntDevicePath(imagePath(f.parent)!) : imagePath(f.parent)) : undefined,
      local_process_id: String(pidOf(ctx, host, f.parent)), process_graph_id: `pid:${aid}:${parentId}`, process_id: parentId,
      user_id: u.sid, user_name: u.user,
    } : undefined,
    parent_process_id: parentId,
    pattern_disposition: disp.code, pattern_disposition_description: disp.text,
    pattern_disposition_details: Object.fromEntries(DISPOSITION_KEYS.map(k => [k, disp.flags.includes(k)])),
    pattern_id: patternId, platform: win ? "Windows" : os === "Mac" ? "Mac" : "Linux",
    process_end_time: "", process_id: processId, process_start_time: String(Math.floor(f.timeMs / 1000)),
    product: "epp", scenario, severity: sevNum, severity_name: sevName,
    sha1: win && trig.sha256 ? "0".repeat(40) : undefined, sha256: trig.sha256,
    show_in_ui: true, source_products: ["Falcon Insight"], source_vendors: ["CrowdStrike"], status: "new",
    tactic: d.tactic, tactic_id: d.tacticId ?? TACTIC_ID[tacticKey], technique: d.technique, technique_id: techId,
    timestamp: iso(f.timeMs + ctx.int(`${ev.id}:cs:ts`, 200, 900)), tree_id: treeId, tree_root: parentId ?? processId,
    triggering_process_graph_id: `pid:${aid}:${processId}`, type: "ldt",
    updated_timestamp: isoNano(ctx, created, `${ev.id}:cs:uns`), user_id: u.sid, user_name: u.user,
  };
}

/** Drop undefined members (recursively for the alert's nested objects). */
function clean(o: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(o)) {
    if (v === undefined) continue;
    out[k] = v && typeof v === "object" && !Array.isArray(v) ? clean(v as Record<string, unknown>) : v;
  }
  return out;
}

function fromTelemetry(ev: TelemetryEvent, ctx: NativeCtx): NativeLog | null {
  const f = edrFacts(ev);
  if (f.kind === "unsupported" || !f.host) return null;
  const host = f.host;
  const os = osOf(f, ev);
  const b: Base = { ctx, ev, f, host, os, hostIp: hostIpOf(ctx, f, host), aid: aidOf(ctx, host), u: userOf(ctx, f, os) };
  const timeMs = Date.parse(ev.ts);
  const out = (kind: string, rec: Record<string, unknown> | null): NativeLog | null =>
    rec ? { sourceId: "crowdstrike", kind, format: "json", record: kind === "alert" ? clean(rec) : sortKeys(rec), timeMs } : null;
  switch (f.kind) {
    case "process": return out("ProcessRollup2", processRollup2(b));
    case "dns": return out("DnsRequest", dnsRequest(b, ev));
    case "detection": return out("alert", alert(b, ev));
    case "network": { const r = network(b, ev); return r ? out(r.simple, r.rec) : null; }
    case "file": { const r = fileWritten(b, ev); return r ? out(r.simple, r.rec) : null; }
    case "registry": { const r = registry(b, ev); return r ? out(r.simple, r.rec) : null; }
    case "logon": { const r = logon(b, ev); return r ? out(r.simple, r.rec) : null; }
    default: return null;
  }
}

// ── use cases ────────────────────────────────────────────────────────────────

const SCRIPT_HOST_IMG = `\\\\(${alt(SCRIPT_HOSTS.filter(s => s !== "cmd.exe"))})$`;
const ENCODED = "\\s-(e|ec|en|enc|enco|encod|encode|encoded|encodedcommand)\\s";
const writableRe = USER_WRITABLE_RE;

const useCases: UseCase[] = [
  {
    id: "crowdstrike.office_spawns_encoded_script", title: "Office application spawns a script host with an encoded command", sourceId: "crowdstrike",
    kinds: ["ProcessRollup2"], severity: "high", mitre: ["T1566.001", "T1204.002", "T1059.001", "T1027"],
    description: "A Word/Excel/Outlook process should never start PowerShell (or wscript/mshta) with an encoded command line — that is the classic malicious-macro hand-off. In FDR the child PR2 names its parent only by ParentBaseFileName + ParentProcessId; pivot from TargetProcessId to every DnsRequest / NetworkConnectIP4 / PeFileWritten with that ContextProcessId to see what the script did next, and from AuthenticationId to the UserLogon that names the user.",
    logic: "LogScale: #event_simpleName=ProcessRollup2 ParentBaseFileName=/^(WINWORD|EXCEL|POWERPNT|OUTLOOK|MSACCESS)\\.EXE$/i ImageFileName=/\\\\(powershell|pwsh|wscript|cscript|mshta)\\.exe$/i CommandLine=/\\s-(e|enc|encodedcommand)\\s/i | table([@timestamp, aid, ComputerName, ParentBaseFileName, CommandLine, TargetProcessId])",
    match: { all: [
      { field: "ParentBaseFileName", op: "in", value: OFFICE },
      { any: [{ field: "ImageFileName", op: "regex", value: SCRIPT_HOST_IMG }, { field: "CommandLine", op: "regex", value: `(^|\\\\|")(${alt(SCRIPT_HOSTS.filter(s => s !== "cmd.exe"))})` }] },
      { field: "CommandLine", op: "regex", value: ENCODED },
    ] },
    falsePositives: ["Signed internal add-ins that shell out to PowerShell (rarely encoded — verify the decoded text and the document's origin)"],
  },
  {
    id: "crowdstrike.script_host_encoded_command", title: "Script host launched with an encoded / hidden command line", sourceId: "crowdstrike",
    kinds: ["ProcessRollup2"], severity: "medium", mitre: ["T1059.001", "T1027"],
    description: "Encoded PowerShell is used legitimately by a few management tools, but most often to hide a download cradle. Any parent: review the ParentBaseFileName, decode the argument, and check what the same TargetProcessId connected to.",
    logic: "LogScale: #event_simpleName=ProcessRollup2 ImageFileName=/\\\\(powershell|pwsh)\\.exe$/i CommandLine=/\\s-(e|enc|encodedcommand)\\s/i | groupBy([ParentBaseFileName, ComputerName])",
    match: { all: [{ field: "CommandLine", op: "regex", value: `(powershell|pwsh)(\\.exe)?"?\\s` }, { field: "CommandLine", op: "regex", value: ENCODED }] },
    falsePositives: ["SCCM / Intune scripts and some RMM agents run encoded commands from services.exe or their own agent process"],
  },
  {
    id: "crowdstrike.lolbin_external_connection", title: "LOLBin makes an outbound connection to an external address", sourceId: "crowdstrike",
    kinds: ["NetworkConnectIP4"], severity: "high", mitre: ["T1105", "T1218", "T1197"],
    description: "certutil, bitsadmin, rundll32, regsvr32, mshta, msiexec and similar signed Windows binaries rarely talk to the internet themselves. A NetworkConnectIP4 whose ContextBaseFileName is one of them and whose RemoteAddressIP4 is not RFC1918 usually means a download or proxy-execution step. Join ContextProcessId → ProcessRollup2.TargetProcessId for the command line.",
    logic: "LogScale: #event_simpleName=NetworkConnectIP4 ContextBaseFileName=/^(certutil|bitsadmin|rundll32|regsvr32|mshta|msiexec|curl|wmic)\\.exe$/i !cidr(RemoteAddressIP4, subnet=[\"10.0.0.0/8\",\"172.16.0.0/12\",\"192.168.0.0/16\"])",
    match: { all: [{ field: "ContextBaseFileName", op: "in", value: LOLBINS }, { field: "RemoteAddressIP4", op: "notCidr", value: PRIVATE_CIDRS }] },
    falsePositives: ["msiexec contacting a vendor update CDN during a sanctioned install", "curl.exe used by developer tooling"],
  },
  {
    id: "crowdstrike.script_host_external_connection", title: "Script host connects to an external address", sourceId: "crowdstrike",
    kinds: ["NetworkConnectIP4"], severity: "high", mitre: ["T1059.001", "T1071.001"],
    description: "PowerShell / wscript / cscript / mshta opening a socket to an internet address is uncommon on a user workstation and is how stagers fetch their second stage. Few distinct ComputerName values per RemoteAddressIP4 across the fleet makes it rarer still — check the domain in the DnsRequest with the same ContextProcessId just before.",
    logic: "LogScale: #event_simpleName=NetworkConnectIP4 ContextBaseFileName=/^(powershell|pwsh|wscript|cscript|mshta)\\.exe$/i !cidr(RemoteAddressIP4, subnet=[\"10.0.0.0/8\",\"172.16.0.0/12\",\"192.168.0.0/16\"]) | groupBy([RemoteAddressIP4], function=[count(aid, distinct=true)]) | _count < 3",
    match: { all: [{ field: "ContextBaseFileName", op: "in", value: SCRIPT_HOSTS.filter(s => s !== "cmd.exe") }, { field: "RemoteAddressIP4", op: "notCidr", value: PRIVATE_CIDRS }] },
    falsePositives: ["Admin scripts calling public APIs (package galleries, cloud CLIs)"],
  },
  {
    id: "crowdstrike.written_then_executed", title: "Executable written to a user-writable folder and then executed", sourceId: "crowdstrike",
    kinds: ["PeFileWritten", "ProcessRollup2"], severity: "high", mitre: ["T1105", "T1204.002"],
    description: "A PE file lands in Downloads / AppData / Temp / ProgramData / Public and a ProcessRollup2 with the same SHA256HashData starts on the same aid shortly after. The hash is the join key (FDR spells it SHA256HashData on both events); the writer is the PeFileWritten ContextBaseFileName.",
    logic: "LogScale: #event_simpleName=PeFileWritten TargetFileName=/\\\\(Users\\\\[^\\\\]+\\\\(Downloads|AppData|Desktop)|Users\\\\Public|ProgramData|Temp)\\\\/i | join({#event_simpleName=ProcessRollup2}, field=[aid, SHA256HashData], include=[CommandLine, TargetProcessId])",
    match: { any: [
      { all: [{ field: "event_simpleName", op: "eq", value: "PeFileWritten" }, { field: "TargetFileName", op: "regex", value: writableRe }, { field: "SHA256HashData", op: "exists" }] },
      { all: [{ field: "event_simpleName", op: "eq", value: "ProcessRollup2" }, { field: "ImageFileName", op: "regex", value: writableRe }, { field: "SHA256HashData", op: "exists" }] },
    ] },
    threshold: { groupBy: ["aid", "SHA256HashData"], count: 2, windowSec: 3600, distinct: "event_simpleName" },
    falsePositives: ["Users installing software from Downloads (check signer and prevalence of the hash)", "Self-updating apps under AppData (Teams, Zoom)"],
  },
  {
    id: "crowdstrike.unsigned_exec_downloads_public", title: "Unsigned binary executed from Downloads or C:\\Users\\Public", sourceId: "crowdstrike",
    kinds: ["ProcessRollup2"], severity: "medium", mitre: ["T1204.002", "T1036"],
    description: "Phishing payloads and cracked installers run straight from the browser's Downloads folder or the world-writable Public profile. SignInfoFlags \"0\" marks an image with no valid signature (value semantics UNVERIFIED in public docs — confirm in the console's process details).",
    logic: "LogScale: #event_simpleName=ProcessRollup2 ImageFileName=/\\\\Users\\\\([^\\\\]+\\\\Downloads|Public)\\\\/i SignInfoFlags=0",
    match: { all: [{ field: "ImageFileName", op: "regex", value: DOWNLOADS_PUBLIC_RE }, { field: "SignInfoFlags", op: "eq", value: "0" }] },
    falsePositives: ["Portable tools and unsigned internal utilities distributed by IT"],
  },
  {
    id: "crowdstrike.credential_access_alert", title: "Credential-access detection (LSASS / SAM / browser credential store)", sourceId: "crowdstrike",
    kinds: ["alert"], severity: "critical", mitre: ["T1003", "T1003.001", "T1555.003"],
    description: "Any Falcon alert whose technique_id is under T1003 (OS credential dumping, incl. LSASS memory) or T1555 (credential stores) means credentials on that host must be treated as exposed — even when the process was killed. Scope: which accounts had sessions on device.hostname, and were they used elsewhere afterwards?",
    logic: "Alerts API: filter=product:'epp'+technique_id:*'T1003*',technique_id:*'T1555*'  (LogScale on NG-SIEM: #repo=detections technique_id=/^T(1003|1555)/)",
    match: { any: [{ field: "technique_id", op: "regex", value: "^T(1003|1555)" }, { field: "tactic", op: "eq", value: "Credential Access" }] },
    falsePositives: ["Approved red-team / pentest windows (confirm the engagement ticket)", "Password-manager or backup agents reading browser stores"],
  },
  {
    id: "crowdstrike.high_severity_not_prevented", title: "High/critical detection with no prevention action", sourceId: "crowdstrike",
    kinds: ["alert"], severity: "high", mitre: [],
    description: "pattern_disposition 0 (\"Detection, standard detection.\") with every pattern_disposition_details flag false means the sensor only alerted — the process kept running. On a high/critical alert that is an active compromise: contain the host (network containment) and kill the tree from RTR. Often caused by a detect-only prevention policy on that host group.",
    logic: "Alerts API: filter=severity:>=70+pattern_disposition:0+status:'new'",
    match: { all: [{ field: "severity", op: "gte", value: 70 }, { field: "pattern_disposition", op: "eq", value: 0 }, { field: "pattern_disposition_details.kill_process", op: "eq", value: false }] },
    falsePositives: ["Detections deliberately left in monitor mode during a policy roll-out"],
  },
  {
    id: "crowdstrike.run_key_to_user_writable", title: "Run-key persistence pointing into a user-writable folder", sourceId: "crowdstrike",
    kinds: ["AsepValueUpdate"], severity: "high", mitre: ["T1547.001"],
    description: "AsepValueUpdate is Falcon's autostart-extensibility-point event. A Run / RunOnce value whose data points into AppData, Temp, Downloads or ProgramData survives reboots and is the most common commodity-malware persistence. Pivot ContextProcessId → the PR2 that wrote it.",
    logic: "LogScale: #event_simpleName=AsepValueUpdate RegObjectName=/\\\\CurrentVersion\\\\Run(Once)?$/i RegStringValue=/\\\\(AppData|Temp|Downloads|ProgramData|Users\\\\Public)\\\\/i",
    match: { all: [{ field: "RegObjectName", op: "regex", value: "\\\\CurrentVersion\\\\Run(Once)?$" }, { field: "RegStringValue", op: "regex", value: "\\\\(AppData|Temp|Downloads|ProgramData|Users\\\\Public|Desktop)\\\\" }] },
    falsePositives: ["Per-user installs of chat/meeting clients (Teams, Zoom, Slack) register Run values under AppData"],
  },
  {
    id: "crowdstrike.inbound_rdp_from_internet", title: "Inbound RDP accepted from an internet address", sourceId: "crowdstrike",
    kinds: ["NetworkReceiveAcceptIP4"], severity: "high", mitre: ["T1021.001", "T1133"],
    description: "NetworkReceiveAcceptIP4 (ConnectionDirection 1) on LocalPort 3389 from a non-private RemoteAddressIP4: the workstation is reachable over RDP from outside, or a VPN/NAT path exposes it. Check the following UserLogon (LogonType 10) for who logged in.",
    logic: "LogScale: #event_simpleName=NetworkReceiveAcceptIP4 LocalPort=3389 !cidr(RemoteAddressIP4, subnet=[\"10.0.0.0/8\",\"172.16.0.0/12\",\"192.168.0.0/16\"])",
    match: { all: [{ field: "LocalPort", op: "eq", value: "3389" }, { field: "RemoteAddressIP4", op: "notCidr", value: PRIVATE_CIDRS }] },
    falsePositives: ["Remote-access gateways that NAT users to a public range"],
  },
];

export const source: NativeSource = {
  schema: {
    sourceId: "crowdstrike", category: "edr", card: "edr-crowdstrike.md", product: "CrowdStrike Falcon",
    format: "json", vendorMatch: ["crowdstrike", "falcon"], telemetrySources: ["edr", "av"], kinds,
  },
  fromTelemetry,
  useCases,
};

/**
 * The text Falcon itself puts in a detection's `description` — product wording keyed to
 * how it detected (on-sensor ML for a quarantined file, a behavioural pattern otherwise),
 * never the scenario's narrative, which states the conclusion the analyst must reach.
 */
function falconDescription(action: string | undefined, techId: string | undefined, technique: string): string {
  if (action === "quarantined") return "This file meets the machine learning-based on-sensor AV protection's high confidence threshold for malicious files.";
  const name = (techId && techniqueById(techId)?.name) || technique;
  return `A process exhibited behavior consistent with ${name}${techId ? ` (${techId})` : ""}. Review the process tree and command line.`;
}
