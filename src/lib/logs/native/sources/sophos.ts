/**
 * Sophos Intercept X / Sophos Central — native module (card: docs/log-schemas/edr-sophos.md).
 *
 * Sophos does not stream raw per-event endpoint telemetry. Its native records are:
 *   "event"     — SIEM Integration API item (GET /siem/v1/events), one element of `items[]` as returned
 *                 (before the Sophos SIEM script renames keys);
 *   "alert"     — SIEM Integration API alert item (GET /siem/v1/alerts);
 *   "detection" — Detections API item (XDR detection with forensic `rawData`);
 *   "running_processes_windows_sophos" — a Data Lake (XDR Query API) result row of that hydration query.
 *
 * Mapping from edrFacts():
 *   process   → Data Lake `running_processes_windows_sophos` row (Windows only — the card documents
 *               the column set of the Windows query only; Linux/macOS process rows → null).
 *   detection → Detections API item when the event is from a Windows endpoint and carries a command
 *               line (rawData.process_cmd_line is the only native place a command line exists);
 *               otherwise a SIEM event: Threat::Detected / Threat::PuaDetected for a file detection,
 *               CoreBehavioralDetection for a behavioural one, with core_remedy_items describing what
 *               was cleaned (absent when nothing was cleaned).
 *   network / dns / file / registry / logon → null: Sophos has NO native per-event stream for these
 *               (card §4.7 and §6 — only on-demand Live Discover journals with undocumented columns).
 *   "alert" records are never produced from telemetry (an alert duplicates its event); the kind exists
 *   so the card sample validates and the not-cleaned use case can read data.threat_status.
 *
 * Identity: endpoint_id = uuid seeded from `${companyId}:${host}` everywhere (SIEM endpoint_id = Detections
 * device.id / rawData.meta_eid = Data Lake endpoint_id / meta_eid); customer_id is per company.
 */
import type { NativeSource, NativeLog, KindSchema, UseCase, NativeCtx } from "../types";
import type { TelemetryEvent } from "@/lib/sim/types";
import { edrFacts, type EdrFacts } from "./edr-normalize";
import {
  TACTICS, techniqueName, tacticOf, fixPath, baseOf, effectiveAction, imageName,
  isPrivate, isSystemUser, userSid, isoFrac, isServer,
} from "./_edr_mde_sophos_common";

// ── Schema ──────────────────────────────────────────────────────────────────
const REMEDY = ["type", "result", "suspendResult", "descriptor", "processPath", "sophosPid"];
const JAVA_ID = ["timestamp", "machineIdentifier", "processIdentifier", "counter", "time", "date", "timeSecond"];
const RAW_DATA = [
  "meta_eid", "meta_licence", "meta_public_ip", "meta_aggressive_activity", "meta_os_platform", "meta_os_version",
  "meta_domain_controller", "customer_region", "meta_ip_address", "meta_query_pack_version", "meta_boot_time",
  "meta_endpoint_type", "meta_hostname", "meta_mac_address", "meta_os_type", "stream_ingest_time", "meta_os_name",
  "customer_id", "meta_ip_mask", "meta_username", "osquery_action", "calendar_time", "item_type", "process_parent_path",
  "detection_item", "detection_name", "process_local_rep_signers", "sid", "process_cmd_line", "process_name",
  "monitor_mode", "threat_type", "process_cmd_line_truncated", "process_pua_score", "process_file_size",
  "process_local_rep", "sophos_pid", "associated_lineages", "process_pid", "detection_thumbprint",
  "process_ml_score_band", "process_ml_score", "threat_source", "process_parent_sophos_pid", "process_path", "time",
  "process_parent_name", "process_sha256", "process_global_rep", "username", "counter", "epoch", "folded",
  "host_identifier", "numerics", "tag", "unix_time",
];
const DATA_LAKE_META = [
  "meta_ip_address", "meta_public_ip", "meta_mac_address", "meta_os_name", "meta_os_platform", "meta_os_version",
  "meta_endpoint_type", "meta_eid", "meta_username", "meta_boot_time", "meta_query_pack_version", "meta_ip_mask", "meta_os_type",
];

const kinds: Record<string, KindSchema> = {
  event: {
    required: ["id", "customer_id", "severity", "created_at", "type", "name", "when", "group", "source", "location", "endpoint_id", "endpoint_type"],
    optional: [
      "source_info.ip", "source_info.detection_name", "source_info.case_id", "origin", "user_id", "threat",
      "appSha256", "appCerts", "appCerts[].signer", "appCerts[].thumbprint",
      "core_remedy_items.items", ...REMEDY.map(k => `core_remedy_items.items[].${k}`), "core_remedy_items.totalItems",
      ...["processName", "processId", "processPath", "parentProcessId", "parentProcessPath"].map(k => `amsi_threat_data.${k}`),
      ...["remoteIp", "remotePort", "localPort", "executableName", "executablePath", "executablePid", "executableVersion",
        "techSupportId", "rawData", "detectionType"].map(k => `ips_threat_data.${k}`),
      "details", "details[].type", "details[].property", "whitelist_properties", "whitelist_properties[].type", "whitelist_properties[].property",
    ],
  },
  alert: {
    required: ["id", "type", "severity", "description", "when", "created_at", "customer_id", "data.endpoint_id", "data.endpoint_type"],
    optional: [
      "event_service_event_id", "source", "location", "threat", "threat_cleanable", "info.threat_case_link_id",
      "data.app_id", "data.source_app_id", "data.created_at", "data.inserted_at", "data.make_actionable_at",
      "data.endpoint_java_id", "data.endpoint_platform", "data.policy_type", "data.source_info.ip", "data.threat_status",
      "data.case_id", "data.detection_name", "data.source_info.detection_name",
      "data.core_remedy_items.items", ...REMEDY.map(k => `data.core_remedy_items.items[].${k}`), "data.core_remedy_items.totalItems",
      ...JAVA_ID.map(k => `data.threat_id.${k}`), ...JAVA_ID.map(k => `data.user_match_id.${k}`),
      "data.user_match_uuid.type", "data.user_match_uuid.data",
    ],
    // Observed but undocumented internal sub-objects.
    openPrefixes: ["data.certificates", "data.ips_threat", "data.hmpa_exploit"],
  },
  detection: {
    required: ["id", "type", "attackType", "detectionRule", "sensorGeneratedAt", "sensor.id", "sensor.type", "sensor.source", "sensor.version",
      "device.id", "device.type", "device.entity", "severity", "time", "rawData.query_name"],
    optional: [
      "caseDescription.correlatedReasonId", "caseDescription.createdReasonId",
      "detectionDescription.createdReasonId", "detectionDescription.significanceId",
      "detectionAttack", "detectionLicenses", "ruleDescription", "suppressed",
      "geolocation", ...["fieldName", "fieldValue", "city", "state", "country", "countryCode", "postal", "latitude", "longitude"].map(k => `geolocation[].${k}`),
      "entities", "entities[].id", "entities[].type", "entities[].category",
      "intelixFileReputation", "intelixFileReputation[].fieldName", "intelixFileReputation[].fieldValue", "intelixFileReputation[].reputationScore",
      "mitreAttacks", "mitreAttacks[].tactic.id", "mitreAttacks[].tactic.name", "mitreAttacks[].tactic.techniques[].id", "mitreAttacks[].tactic.techniques[].name",
      ...RAW_DATA.map(k => `rawData.${k}`),
    ],
    // entities[].attributes differ per entity type (device / ip_address / user).
    openPrefixes: ["entities[].attributes"],
  },
  running_processes_windows_sophos: {
    required: ["query_name", "calendar_time", "endpoint_id", "customer_id", "meta_hostname", "name", "path", "cmdline", "pid", "sophos_pid", "time"],
    optional: [
      "host_identifier", "ingestion_timestamp", "message_identifier", "query_source", "schema_version", "upload_size",
      ...DATA_LAKE_META, "file_size", "gid", "uid", "global_rep", "global_rep_data", "local_rep", "local_rep_data",
      "ml_score", "ml_score_data", "pua_score", "parent", "parent_name", "parent_path", "parent_sophos_pid",
      "sha1", "sha256", "username", "counter", "epoch", "numerics", "osquery_action", "unix_time",
    ],
  },
};

/**
 * Classify a native Sophos record. The Live Discover journal row of card §4.7 ({time, sophosPID, name})
 * is not a supported kind: the card marks its column set UNVERIFIED and it is not a streamed record.
 */
export function kindOf(record: Record<string, unknown>): string | null {
  if (typeof record.detectionRule === "string" && record.rawData && typeof record.rawData === "object") return "detection";
  if (record.query_name === "running_processes_windows_sophos") return "running_processes_windows_sophos";
  if (typeof record.type === "string" && record.type.startsWith("Event::")) return record.data && typeof record.data === "object" ? "alert" : "event";
  return null;
}

// ── Helpers ─────────────────────────────────────────────────────────────────
const SIEM_SEV: Record<string, string> = { critical: "critical", high: "high", medium: "medium", low: "low", informational: "low", info: "low" };
const DET_SEV: Record<string, number> = { critical: 9, high: 8, medium: 5, low: 3, informational: 1, info: 1 };
/** Sophos behavioural rule families (detection_name prefix / detectionRule segment) per tactic. */
const RULE_FAMILY: Record<string, [string, string]> = {
  "Execution": ["Exec", "EXEC"], "Credential Access": ["Creds", "CREDS"], "Defense Evasion": ["Evade", "EVADE"],
  "Persistence": ["Persist", "PERSIST"], "Privilege Escalation": ["Privesc", "PRIVESC"], "Impact": ["Impact", "IMPACT"],
  "Collection": ["Collect", "COLLECT"], "Lateral Movement": ["Lateral", "LATERAL"], "Exfiltration": ["Exfil", "EXFIL"],
  "Command and Control": ["C2", "C2"], "Discovery": ["Discovery", "DISCOVERY"], "Initial Access": ["Access", "ACCESS"],
};
const VENDOR_MATCH = ["sophos"];
const isNative = (ev: TelemetryEvent) => VENDOR_MATCH.some(v => (ev.vendor ?? "").toLowerCase().includes(v));

/** Windows FILETIME (100-ns ticks since 1601) as a decimal string, sub-ms digits seeded. */
function filetime(ms: number, ctx: NativeCtx, seed: string): string {
  return `${ms + 11_644_473_600_000}${String(ctx.int(seed, 0, 9999)).padStart(4, "0")}`;
}
function sophosUser(f: EdrFacts, ctx: NativeCtx): string | undefined {
  const u = f.user ?? (f.userEmail ? f.userEmail.split("@")[0] : undefined);
  if (!u) return undefined;
  if (isSystemUser(u)) return `NT AUTHORITY\\${u.toUpperCase()}`;
  if (f.os !== "Win") return u;
  return `${(f.userDomain ?? ctx.netbios).toUpperCase()}\\${u}`;
}
function pidOf(ctx: NativeCtx, host: string, name: string | undefined, pid?: number): number {
  return pid ?? ctx.int(`${ctx.companyId}:${host.toLowerCase()}:${(name ?? "").toLowerCase()}:pid`, 250, 3750) * 4;
}
/** Stable Sophos endpoint id per host (seeded from the entity, never the event). */
const endpointIdOf = (ctx: NativeCtx, host: string) => ctx.uuid(`${ctx.companyId}:${host.toLowerCase()}:sophos-endpoint`);
const macOf = (ctx: NativeCtx, host: string) => (ctx.hex(`${ctx.companyId}:${host.toLowerCase()}:mac`, 12).match(/../g) ?? []).join(":");

function deviceMeta(f: EdrFacts, ctx: NativeCtx, host: string, endpointId: string) {
  const server = isServer(host);
  const bootSec = Math.floor(f.timeMs / 1000) - ctx.int(`${ctx.companyId}:${host.toLowerCase()}:boot`, 3_600, 432_000);
  const ip = isPrivate(f.hostIp) ? f.hostIp : undefined;
  return {
    server, bootSec, ip,
    cols: {
      meta_hostname: host,
      ...(ip ? { meta_ip_address: ip, meta_ip_mask: "255.255.255.0" } : {}),
      meta_mac_address: macOf(ctx, host),
      meta_os_name: server ? "Microsoft Windows Server 2022 Standard" : "Microsoft Windows 11 Enterprise",
      meta_os_platform: "windows",
      meta_os_type: "",
      meta_os_version: server ? "10.0.20348" : "10.0.26100",
      meta_endpoint_type: server ? "server" : "computer",
      meta_eid: endpointId,
      meta_boot_time: bootSec,
      meta_query_pack_version: "1.31.2.4",
    },
  };
}

// ── Conversion ──────────────────────────────────────────────────────────────
function fromTelemetry(ev: TelemetryEvent, ctx: NativeCtx): NativeLog | null {
  const f = edrFacts(ev);
  if (!f.host) return null;
  if (f.kind === "process") return dataLakeProcess(ev, f, ctx, f.host);
  if (f.kind === "detection") {
    return f.os === "Win" && f.proc.cmdline ? detectionItem(ev, f, ctx, f.host) : siemEvent(ev, f, ctx, f.host);
  }
  // network / dns / file / registry / logon / unsupported: no native Sophos record (card §4.7, §6).
  return null;
}

function dataLakeProcess(ev: TelemetryEvent, f: EdrFacts, ctx: NativeCtx, host: string): NativeLog | null {
  if (f.os !== "Win") return null; // only the Windows hydration query's column set is documented
  const name = imageName(f.proc);
  if (!name) return null;
  const seed = (p: string) => `${ev.id}:sophos:${p}`;
  const endpointId = endpointIdOf(ctx, host);
  const meta = deviceMeta(f, ctx, host, endpointId);
  const pid = pidOf(ctx, host, name, f.proc.pid);
  const parentName = f.parent.name;
  const ppid = parentName ? pidOf(ctx, host, parentName, f.parent.pid) : 0;
  // The row's time is when the scheduled query saw the process (calendar_time); the
  // process started a little before, and the result reaches the data lake seconds later
  // — never stamped after the moment the row is shown.
  const startMs = f.timeMs - ctx.int(seed("cal"), 5_000, 60_000);
  const startSec = Math.floor(startMs / 1000);
  const calSec = Math.floor(f.timeMs / 1000);
  const user = sophosUser(f, ctx) ?? "";
  const ident = f.proc.sha256 ?? (fixPath(f.proc.path) ?? name).toLowerCase();
  const record: Record<string, unknown> = {
    calendar_time: isoFrac(calSec * 1000, 0, ctx, seed("c")),
    endpoint_id: endpointId,
    host_identifier: host,
    ingestion_timestamp: isoFrac(calSec * 1000 + ctx.int(seed("ingest"), 1_500, 6_000), 3, ctx, seed("i")),
    message_identifier: ctx.hex(seed("msg"), 64),
    query_name: "running_processes_windows_sophos",
    query_source: "xdr_only",
    schema_version: "1",
    upload_size: ctx.int(seed("upload"), 1_200, 4_800),
    cmdline: f.proc.cmdline ?? "",
    gid: 0,
    global_rep: -1,
    global_rep_data: "",
    local_rep: -1,
    local_rep_data: "",
    ml_score: ctx.int(seed("ml"), 0, 20),
    ml_score_data: "",
    name,
    parent: ppid,
    parent_name: parentName ?? "",
    parent_path: fixPath(f.parent.path) ?? "",
    parent_sophos_pid: parentName ? `${ppid}:${filetime(f.timeMs - ctx.int(seed("pstart"), 1_000, 600_000), ctx, seed("pft"))}` : "",
    path: fixPath(f.proc.path) ?? "",
    pid,
    pua_score: ctx.int(seed("pua"), 0, 20),
    sha1: ctx.hex(`sha1:${ident}`, 40),
    sha256: f.proc.sha256 ?? "",
    sophos_pid: `${pid}:${filetime(startMs, ctx, seed("ft"))}`,
    time: startSec,
    uid: 0,
    username: user,
    ...meta.cols,
    meta_username: user,
    counter: ctx.int(seed("counter"), 1, 400),
    epoch: meta.bootSec + 1,
    numerics: false,
    osquery_action: "added",
    unix_time: calSec,
    customer_id: ctx.uuid(`${ctx.companyId}:sophos-customer`),
  };
  return { sourceId: "sophos", kind: "running_processes_windows_sophos", format: "json", record, timeMs: f.timeMs };
}

function behaviouralName(f: EdrFacts, ctx: NativeCtx, seed: string): { rule: string; name: string; tactic?: string } {
  const tactic = tacticOf(f);
  const [fam, seg] = (tactic && RULE_FAMILY[tactic]) ?? ["Exec", "EXEC"];
  const n = ctx.int(`${seed}:n`, 1, 40);
  const l = "abcdefghijkl"[ctx.int(`${seed}:l`, 0, 11)];
  const tid = f.detection?.techniqueId;
  const rule = `WIN-PROT-BEHAVIORAL-MALWARE-${seg}-${n}${l.toUpperCase()}${tid ? `-${tid.replace(".", "-")}` : ""}`;
  return { rule, name: `${fam}_${n}${l}${tid ? ` (${tid})` : ""}`, tactic };
}

function detectionItem(ev: TelemetryEvent, f: EdrFacts, ctx: NativeCtx, host: string): NativeLog {
  const seed = (p: string) => `${ev.id}:sophos:${p}`;
  const d = f.detection!;
  const endpointId = endpointIdOf(ctx, host);
  const meta = deviceMeta(f, ctx, host, endpointId);
  const name = imageName(f.proc) ?? "";
  const path = fixPath(f.proc.path) ?? (f.file.path && baseOf(f.file.path)?.toLowerCase() === name.toLowerCase() ? f.file.path : undefined);
  const pid = pidOf(ctx, host, name, f.proc.pid);
  const sha256 = f.proc.sha256 ?? (path && path === f.file.path ? f.file.sha256 : undefined);
  const user = sophosUser(f, ctx);
  const beh = behaviouralName(f, ctx, seed("rule"));
  const tactic = beh.tactic;
  const tacticId = tactic ? TACTICS[tactic]?.id : undefined;
  const sensorMs = f.timeMs;
  const startMs = f.timeMs - ctx.int(seed("start"), 500, 30_000);
  const custId = ctx.uuid(`${ctx.companyId}:sophos-customer`);
  const entities: Record<string, unknown>[] = [
    { id: ctx.hex(seed("ent:dev"), 64), type: "device", category: "impacted", attributes: {
      domain_controller: /(^|-)DC\d*($|-)/i.test(host) ? "True" : "False", endpoint_type: meta.server ? "server" : "computer",
      hostname: host, id: endpointId, mac_address: macOf(ctx, host), os_platform: "windows", os_type: "" } },
  ];
  if (meta.ip) entities.push({ id: ctx.hex(seed("ent:ip"), 64), type: "ip_address", category: "impacted",
    attributes: { address: meta.ip, external: false, id: ctx.hex(`${ctx.companyId}:${meta.ip}:ipent`, 64), type: "ipv4" } });
  if (user) entities.push({ id: ctx.hex(seed("ent:user"), 64), type: "user", category: "impacted",
    attributes: { id: ctx.hex(`${ctx.companyId}:${user.toLowerCase()}:userent`, 64), sub_type: "logged_in_user", username: user } });
  const detectionName = isNative(ev) && d.name ? d.name : beh.name;
  const rawData: Record<string, unknown> = {
    meta_eid: endpointId,
    meta_licence: "XDR",
    meta_aggressive_activity: "False",
    meta_os_platform: "windows",
    meta_os_version: meta.cols.meta_os_version,
    meta_domain_controller: entities[0].attributes && (entities[0].attributes as Record<string, string>).domain_controller,
    ...(meta.ip ? { meta_ip_address: meta.ip, meta_ip_mask: "255.255.255.0" } : {}),
    meta_query_pack_version: "1.31.2.4",
    meta_boot_time: meta.bootSec,
    meta_endpoint_type: meta.cols.meta_endpoint_type,
    meta_hostname: host,
    meta_mac_address: meta.cols.meta_mac_address,
    meta_os_type: "",
    meta_os_name: meta.cols.meta_os_name,
    customer_id: custId,
    ...(user ? { meta_username: user, username: user } : {}),
    osquery_action: "added",
    calendar_time: Math.floor(sensorMs / 1000) * 1000,
    item_type: "Process",
    ...(path ? { detection_item: path, process_path: path } : {}),
    detection_name: detectionName,
    ...(user && f.os === "Win" ? { sid: userSid(ctx, f.user ?? user.split("\\").pop()) } : {}),
    process_cmd_line: f.proc.cmdline,
    process_cmd_line_truncated: 0,
    process_name: name,
    process_pid: pid,
    sophos_pid: `${pid}:${filetime(startMs, ctx, seed("ft"))}`,
    ...(sha256 ? { process_sha256: sha256 } : {}),
    ...(f.parent.name ? {
      process_parent_name: f.parent.name,
      process_parent_sophos_pid: `${pidOf(ctx, host, f.parent.name, f.parent.pid)}:${filetime(startMs - ctx.int(seed("pstart"), 1_000, 600_000), ctx, seed("pft"))}`,
      ...(f.parent.path ? { process_parent_path: fixPath(f.parent.path) } : {}),
    } : {}),
    monitor_mode: 0,
    threat_type: "Malware",
    threat_source: "Behavioral",
    process_ml_score: ctx.int(seed("ml"), 0, 20),
    process_pua_score: ctx.int(seed("pua"), 0, 20),
    process_local_rep: -1,
    process_global_rep: -1,
    detection_thumbprint: ctx.hex(seed("thumb"), 64),
    associated_lineages: "",
    time: Math.floor(startMs / 1000),
    unix_time: Math.floor(sensorMs / 1000) * 1000,
    counter: ctx.int(seed("counter"), 1, 50),
    epoch: meta.bootSec + 1,
    folded: 0,
    host_identifier: ctx.uuid(`${ctx.companyId}:${host.toLowerCase()}:hostid`).toUpperCase(),
    query_name: "sophos_detections_windows",
    numerics: false,
    tag: "stream",
    stream_ingest_time: String(sensorMs + ctx.int(seed("ingest"), 200, 4_000)),
  };
  const techName = techniqueName(d.techniqueId, d.technique);
  const record: Record<string, unknown> = {
    id: `${ctx.hex(seed("id:a"), 64)}_${ctx.hex(seed("id:b"), 40)}`,
    attackType: "Security Event Service Detections",
    caseDescription: { correlatedReasonId: "", createdReasonId: "" },
    detectionDescription: { createdReasonId: beh.rule, significanceId: beh.rule },
    detectionRule: beh.rule,
    sensorGeneratedAt: isoFrac(sensorMs, 0, ctx, seed("sg")),
    sensor: { id: "SophosSensorID", type: "endpoint", source: "Sophos", version: "1.31.2.4" },
    device: { id: endpointId, type: meta.server ? "server" : "computer", entity: host },
    ...(tactic ? { detectionAttack: tactic } : {}),
    detectionLicenses: "[\"XDR\"]",
    entities,
    ...(sha256 ? { intelixFileReputation: [{ fieldName: "raw.process_sha256", fieldValue: sha256, reputationScore: ctx.int(seed("rep"), 0, 99) }] } : {}),
    mitreAttacks: tactic && tacticId ? [{ tactic: { id: tacticId, name: tactic, techniques: d.techniqueId ? [{ id: d.techniqueId, name: techName ?? d.techniqueId }] : [] } }] : [],
    rawData,
    ruleDescription: `${tactic ?? "Execution"} behavior based protection from Sophos`,
    severity: DET_SEV[(d.severity ?? "medium").toLowerCase()] ?? 5,
    suppressed: "false",
    time: isoFrac(sensorMs + ctx.int(seed("rec"), 1_000, 8_000), 3, ctx, seed("t")),
    type: "Threat",
  };
  return { sourceId: "sophos", kind: "detection", format: "json", record, timeMs: f.timeMs };
}

function siemEvent(ev: TelemetryEvent, f: EdrFacts, ctx: NativeCtx, host: string): NativeLog {
  const seed = (p: string) => `${ev.id}:sophos:${p}`;
  const d = f.detection!;
  const action = effectiveAction(ev, f);
  const endpointId = endpointIdOf(ctx, host);
  const filePath = f.file.path && !/^memory:/i.test(f.file.path) ? f.file.path : undefined;
  const procName = imageName(f.proc);
  const procPath = fixPath(f.proc.path);
  const pid = procName ? pidOf(ctx, host, procName, f.proc.pid) : undefined;
  const pe = /\.(exe|dll|scr|sys|com)$/i.test(filePath ?? "");
  // Threat label: authored name for Sophos-authored events; a Sophos-style label otherwise
  // (another vendor's detection name is not something Sophos would print).
  const threat = isNative(ev) && d.name ? d.name
    : filePath ? (pe ? "ML/PE-A" : "Mal/Generic-S")
    : behaviouralName(f, ctx, seed("rule")).name;
  const pua = /^pua/i.test(threat);
  const cleaned = action !== "detected";
  // name text formats beyond the card's "Malware detected: '<threat>' at '<path>'" are UNVERIFIED.
  const type = filePath ? (pua ? "Event::Endpoint::Threat::PuaDetected" : "Event::Endpoint::Threat::Detected") : "Event::Endpoint::CoreBehavioralDetection";
  const name = filePath ? `${pua ? "PUA" : "Malware"} detected: '${threat}' at '${filePath}'`
    : `Malicious behavior ${cleaned ? "prevented" : "detected"}: '${threat}'${procPath || procName ? ` in ${procPath ?? procName}` : ""}`;
  const items: Record<string, string>[] = [];
  const procItem = () => ({ type: "process", result: "SUCCESS", suspendResult: "NOT_APPLICABLE", descriptor: procPath ?? procName ?? "",
    processPath: procPath ?? "", sophosPid: pid !== undefined ? `${pid}:${filetime(f.timeMs - ctx.int(seed("start"), 500, 30_000), ctx, seed("ft"))}` : "" });
  const fileItem = () => ({ type: "file", result: "SUCCESS", suspendResult: "NOT_APPLICABLE", descriptor: filePath!, processPath: "", sophosPid: "" });
  if (action === "killed" && (procName || procPath)) items.push(procItem());
  if ((action === "quarantined" || action === "killed" || action === "blocked") && filePath) items.push(fileItem());
  if (action === "blocked" && !filePath && (procName || procPath)) items.push(procItem());
  const user = sophosUser(f, ctx);
  const whenMs = Math.floor(f.timeMs / 1000) * 1000;
  const record: Record<string, unknown> = {
    id: ctx.uuid(seed("event")),
    customer_id: ctx.uuid(`${ctx.companyId}:sophos-customer`),
    severity: SIEM_SEV[(d.severity ?? "medium").toLowerCase()] ?? "medium",
    created_at: isoFrac(whenMs + ctx.int(seed("created"), 400, 6_000), 3, ctx, seed("ca")),
    ...(isPrivate(f.hostIp) ? { source_info: { ip: f.hostIp } } : {}),
    endpoint_type: isServer(host) ? "server" : "computer",
    endpoint_id: endpointId,
    origin: filePath ? (threat.startsWith("ML/") ? "ML_MALWARE_DETECTION" : "VDL_MALWARE_DETECTION") : "BEHAVIORAL_DETECTION",
    type,
    location: host,
    source: user ?? "n/a",
    group: filePath ? (pua ? "PUA" : "MALWARE") : "RUNTIME_DETECTIONS",
    name,
    ...(user ? { user_id: ctx.hex(`${ctx.companyId}:${user.toLowerCase()}:sophos-user`, 24) } : {}),
    when: new Date(whenMs).toISOString(),
    threat,
    ...((f.file.sha256 ?? f.proc.sha256) ? { appSha256: f.file.sha256 ?? f.proc.sha256 } : {}),
    ...(items.length ? { core_remedy_items: { items, totalItems: items.length } } : {}),
  };
  return { sourceId: "sophos", kind: "event", format: "json", record, timeMs: f.timeMs };
}

// ── Use cases ───────────────────────────────────────────────────────────────
const OFFICE = "^(winword|excel|powerpnt|outlook|onenote|mspub|msaccess|visio)\\.exe$";
const SCRIPT_HOST = "^(powershell|pwsh|cmd|wscript|cscript|mshta)\\.exe$";
const ENCODED_FLAG = "\\s[-/]e(c|n|nc|nco|ncod|ncode|ncoded|ncodedc|ncodedco|ncodedcom|ncodedcomm|ncodedcomma|ncodedcommand)?\\s";
const DETECTION_TYPES = ["Event::Endpoint::Threat::Detected", "Event::Endpoint::Threat::PuaDetected", "Event::Endpoint::CoreDetection",
  "Event::Endpoint::CorePuaDetection", "Event::Endpoint::CoreBehavioralDetection"];

const useCases: UseCase[] = [
  {
    id: "sophos.threat-not-cleaned",
    title: "Threat detected but not cleaned up",
    sourceId: "sophos", kinds: ["event", "alert"], severity: "high", mitre: ["T1204.002"],
    description: "Intercept X detected a threat but recorded no successful cleanup: a detection event with no SUCCESS item in core_remedy_items, a Threat::CleanupFailed event, or an alert whose data.threat_status is anything other than CLEANED_UP / DISMISSED. The malware may still be on disk or running — the analyst must act (manual clean, isolate, re-image).",
    logic: "# SIEM search over Sophos Central /siem/v1 items (SPL style)\nindex=sophos_central (sourcetype=sophos:events type IN (\"Event::Endpoint::Threat::Detected\",\"Event::Endpoint::Threat::PuaDetected\",\"Event::Endpoint::CoreBehavioralDetection\") NOT \"core_remedy_items.items{}.result\"=\"SUCCESS\")\n  OR (sourcetype=sophos:events type=\"Event::Endpoint::Threat::CleanupFailed\")\n  OR (sourcetype=sophos:alerts NOT data.threat_status IN (\"CLEANED_UP\",\"DISMISSED\"))\n| table when location source type threat name data.threat_status",
    match: { any: [
      { all: [
        { field: "type", op: "in", value: DETECTION_TYPES },
        { not: { field: "core_remedy_items.items[].result", op: "eq", value: "SUCCESS" } },
        { field: "data", op: "missing" },
      ] },
      { field: "type", op: "eq", value: "Event::Endpoint::Threat::CleanupFailed" },
      { all: [
        { field: "data.threat_status", op: "exists" },
        { field: "data.threat_status", op: "nin", value: ["CLEANED_UP", "DISMISSED"] },
      ] },
    ] },
    falsePositives: ["Detect-only (monitor) policies on test machines", "Threats in archives or read-only locations that Sophos reports as NOT_CLEANUPABLE but which never executed"],
  },
  {
    id: "sophos.amsi-behavioural-protection",
    title: "AMSI or behavioural (runtime) protection fired",
    sourceId: "sophos", kinds: ["event", "detection"], severity: "high", mitre: ["T1059.001", "T1027"],
    description: "Sophos runtime protection caught malicious behaviour rather than a malicious file: an AMSI block (script content scanned in memory), a behavioural detection event, or a Detections API item whose rawData.threat_source is Behavioral. These fire on fileless attacks — the command line in rawData.process_cmd_line and the parent process tell you how it started.",
    logic: "# SIEM items\ntype IN (\"Event::Endpoint::CoreAmsiBlocked\",\"Event::Endpoint::CoreBehavioralDetection\") OR origin IN (\"AMSI_DETECTION\",\"BEHAVIORAL_DETECTION\",\"HMPA_DETECTION\")\n-- Detections API (Threat Analysis Center → Detections)\nSELECT time, device.entity, detectionRule, rawData.process_cmd_line FROM detections WHERE rawData.threat_source = 'Behavioral'",
    match: { any: [
      { field: "type", op: "in", value: ["Event::Endpoint::CoreAmsiBlocked", "Event::Endpoint::CoreBehavioralDetection"] },
      { field: "origin", op: "in", value: ["AMSI_DETECTION", "BEHAVIORAL_DETECTION", "HMPA_DETECTION"] },
      { field: "rawData.threat_source", op: "eq", value: "Behavioral" },
    ] },
    falsePositives: ["Admin scripts that use download cradles or obfuscation for legitimate deployment (add a scoped exclusion only after review)"],
  },
  {
    id: "sophos.office-encoded-script-host",
    title: "Office application launched a script host with an encoded command",
    sourceId: "sophos", kinds: ["detection", "running_processes_windows_sophos"], severity: "high", mitre: ["T1566.001", "T1204.002", "T1059.001", "T1027"],
    description: "A process whose parent is Word/Excel/PowerPoint/Outlook is PowerShell, cmd, wscript, cscript or mshta and its command line has an encoded-command switch. Visible both in Data Lake process rows (parent_name / name / cmdline) and in the Detections API rawData (process_parent_name / process_name / process_cmd_line).",
    logic: "-- Sophos Data Lake SQL (Threat Analysis Center → Search)\nSELECT meta_hostname, username, parent_name, name, cmdline, sophos_pid, parent_sophos_pid\nFROM xdr_data\nWHERE query_name = 'running_processes_windows_sophos'\n  AND LOWER(parent_name) IN ('winword.exe','excel.exe','powerpnt.exe','outlook.exe','onenote.exe','mspub.exe','msaccess.exe')\n  AND LOWER(name) IN ('powershell.exe','pwsh.exe','cmd.exe','wscript.exe','cscript.exe','mshta.exe')\n  AND REGEXP_LIKE(cmdline, '(?i)\\s[-/]e(nc|ncodedcommand|c)?\\s')",
    match: { any: [
      { all: [
        { field: "rawData.process_parent_name", op: "regex", value: OFFICE },
        { field: "rawData.process_name", op: "regex", value: SCRIPT_HOST },
        { field: "rawData.process_cmd_line", op: "regex", value: ENCODED_FLAG },
      ] },
      { all: [
        { field: "parent_name", op: "regex", value: OFFICE },
        { field: "name", op: "regex", value: SCRIPT_HOST },
        { field: "cmdline", op: "regex", value: ENCODED_FLAG },
      ] },
    ] },
    falsePositives: ["Signed Office add-ins that invoke PowerShell (verify signer and decoded content)"],
  },
  {
    id: "sophos.repeated-detections-endpoint",
    title: "Repeated detections on one endpoint",
    sourceId: "sophos", kinds: ["event"], severity: "medium", mitre: [],
    description: "Three or more Sophos security events for the same endpoint_id within an hour. One detection may be a stray download; a burst on one machine (AMSI block, IPS hit, file detection…) means an active intrusion working around each block — isolate and investigate the whole chain in Threat Graphs.",
    logic: "# SIEM search over /siem/v1/events\nindex=sophos_central sourcetype=sophos:events group IN (\"MALWARE\",\"PUA\",\"RUNTIME_DETECTIONS\")\n| bin _time span=1h\n| stats count dc(type) as kinds values(threat) as threats by endpoint_id location _time\n| where count >= 3",
    match: { field: "group", op: "in", value: ["MALWARE", "PUA", "RUNTIME_DETECTIONS"] },
    threshold: { groupBy: ["endpoint_id"], count: 3, windowSec: 3600 },
    falsePositives: ["A full scan finding several copies of the same PUA in a user's Downloads folder"],
  },
  {
    id: "sophos.credential-theft-detection",
    title: "Credential-theft detection (Credential Access tactic or credential-dumping tool)",
    sourceId: "sophos", kinds: ["event", "detection"], severity: "critical", mitre: ["T1003", "T1555"],
    description: "A Detections API item mapped to MITRE tactic TA0006 Credential Access (mitreAttacks[].tactic.id) or a Creds_* behavioural rule, or a SIEM event naming a credential-dumping tool. Assume the passwords/hashes of every account logged on to that device are compromised.",
    logic: "-- Detections API\nSELECT time, device.entity, detectionRule, rawData.detection_name, rawData.process_cmd_line FROM detections\nWHERE ARRAY_CONTAINS(mitreAttacks[].tactic.id, 'TA0006') OR rawData.detection_name LIKE 'Creds_%'\n# SIEM items\nthreat=\"*Mimikatz*\" OR name=\"*Mimikatz*\"",
    match: { any: [
      { field: "mitreAttacks[].tactic.id", op: "eq", value: "TA0006" },
      { field: "rawData.detection_name", op: "regex", value: "^Creds_|mimikatz" },
      { all: [{ field: "type", op: "startsWith", value: "Event::Endpoint::" }, { field: "threat", op: "regex", value: "mimikatz|lsass" }] },
    ] },
    falsePositives: ["Authorised red-team / penetration-test tooling"],
  },
  {
    id: "sophos.ips-outbound-c2",
    title: "Malicious outbound traffic blocked by endpoint IPS",
    sourceId: "sophos", kinds: ["event"], severity: "high", mitre: ["T1071.001", "T1105"],
    description: "Intercept X's endpoint IPS / Malicious Traffic Detection stopped outbound traffic matching a C2 signature. ips_threat_data names the process (executablePath / executablePid) and the remote endpoint (remoteIp / remotePort) — pivot on both.",
    logic: "# SIEM search\ntype=\"Event::Endpoint::Threat::IpsOutboundDetection\" OR (origin=\"IPS_DETECTION\" AND ips_threat_data.detectionType=1)\n| table when location source threat ips_threat_data.executablePath ips_threat_data.remoteIp ips_threat_data.remotePort",
    match: { any: [
      { field: "type", op: "eq", value: "Event::Endpoint::Threat::IpsOutboundDetection" },
      { all: [{ field: "origin", op: "eq", value: "IPS_DETECTION" }, { field: "ips_threat_data.detectionType", op: "eq", value: 1 }] },
    ] },
    falsePositives: ["Signature false positives on newly released legitimate software updaters"],
  },
];

export const source: NativeSource = {
  schema: {
    sourceId: "sophos",
    category: "edr",
    card: "edr-sophos.md",
    product: "Sophos Intercept X (Sophos Central)",
    format: "json",
    vendorMatch: VENDOR_MATCH,
    telemetrySources: ["edr", "av"],
    kinds,
  },
  fromTelemetry,
  useCases,
};
