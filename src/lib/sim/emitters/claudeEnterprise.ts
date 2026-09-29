/**
 * Anthropic Claude Enterprise audit-log EMITTER (Compliance API → Wazuh → Elasticsearch).
 *
 * Shape taken from a REAL customer log (field tree provided 2026-09-29): the Wazuh
 * envelope (`input`, `agent`, `manager`, `rule`, `decoder`, `location`, `id`,
 * `full_log`, `timestamp`) around the Compliance API activity in `data.*`:
 *   data.actor.{email_address,user_id,ip_address,type,user_agent}
 *   data.claude_project_id / claude_artifact_id / claude_file_id / filename
 *   data.organization_id / organization_uuid / created_at / id / source / type
 *
 * What this log does NOT carry: prompt or response text. It records WHO did WHAT
 * to WHICH chat/project/file/artifact, from WHERE — so an investigation correlates
 * activity type, volume, timing, filename and actor context.
 *
 * Actor types follow the Compliance API (`user_actor`, `api_actor`,
 * `admin_api_key_actor`, `unauthenticated_user_actor`, `anthropic_actor`,
 * `system_actor`, `scim_directory_sync_actor`). Activity types used here are the
 * documented ones plus artifact activity implied by `claude_artifact_id`.
 *
 * The customer's own Wazuh rule ids/levels/groups are unknown, so the envelope uses
 * a consistent, plausible custom-rule range (100xxx) with Wazuh-style groups.
 */
import type { TelemetryEvent, Severity, EventType } from "../types";
import { makeSha256 } from "@/lib/sim/iocs";
import { knownGeoForIp, type GeoPoint } from "@/lib/geo/resolveGeo";

const VENDOR = "Anthropic Claude Enterprise";

export type ClaudeActorType =
  | "user_actor" | "api_actor" | "admin_api_key_actor" | "unauthenticated_user_actor"
  | "anthropic_actor" | "system_actor" | "scim_directory_sync_actor";

export type ClaudeActivityType =
  | "sso_login_initiated" | "sso_login_succeeded"
  | "claude_chat_created" | "claude_chat_viewed"
  | "claude_project_created" | "claude_project_viewed"
  | "claude_file_uploaded" | "claude_file_viewed"
  | "claude_artifact_created" | "claude_artifact_viewed" | "claude_artifact_shared"
  | "admin_api_key_created" | "org_user_invite_accepted"
  | "platform_memory_store_created" | "platform_memory_created" | "platform_memory_deleted";

/** Wazuh custom rule per activity (level, description, groups). Plausible customer ruleset. */
const RULES: Record<ClaudeActivityType, { id: string; level: number; description: string; groups: string[] }> = {
  sso_login_initiated:          { id: "100510", level: 3,  description: "Claude Enterprise: SSO login initiated",            groups: ["claude", "authentication"] },
  sso_login_succeeded:          { id: "100511", level: 3,  description: "Claude Enterprise: SSO login succeeded",            groups: ["claude", "authentication", "authentication_success"] },
  claude_chat_created:          { id: "100520", level: 3,  description: "Claude Enterprise: chat created",                   groups: ["claude", "ai_activity"] },
  claude_chat_viewed:           { id: "100521", level: 3,  description: "Claude Enterprise: chat viewed",                    groups: ["claude", "ai_activity"] },
  claude_project_created:       { id: "100530", level: 3,  description: "Claude Enterprise: project created",                groups: ["claude", "ai_activity"] },
  claude_project_viewed:        { id: "100531", level: 3,  description: "Claude Enterprise: project viewed",                 groups: ["claude", "ai_activity"] },
  claude_file_uploaded:         { id: "100540", level: 5,  description: "Claude Enterprise: file uploaded",                  groups: ["claude", "ai_activity", "file_upload"] },
  claude_file_viewed:           { id: "100541", level: 3,  description: "Claude Enterprise: file viewed",                    groups: ["claude", "ai_activity"] },
  claude_artifact_created:      { id: "100550", level: 3,  description: "Claude Enterprise: artifact created",               groups: ["claude", "ai_activity"] },
  claude_artifact_viewed:       { id: "100551", level: 3,  description: "Claude Enterprise: artifact viewed",                groups: ["claude", "ai_activity"] },
  claude_artifact_shared:       { id: "100552", level: 6,  description: "Claude Enterprise: artifact shared",                groups: ["claude", "ai_activity", "sharing"] },
  admin_api_key_created:        { id: "100560", level: 8,  description: "Claude Enterprise: admin API key created",          groups: ["claude", "admin_activity", "credential_change"] },
  org_user_invite_accepted:     { id: "100570", level: 4,  description: "Claude Enterprise: organization invite accepted",   groups: ["claude", "admin_activity", "account_change"] },
  platform_memory_store_created:{ id: "100580", level: 3,  description: "Claude Enterprise: memory store created",           groups: ["claude", "ai_activity"] },
  platform_memory_created:      { id: "100581", level: 3,  description: "Claude Enterprise: memory created",                 groups: ["claude", "ai_activity"] },
  platform_memory_deleted:      { id: "100582", level: 5,  description: "Claude Enterprise: memory deleted",                 groups: ["claude", "ai_activity"] },
};

/** Wazuh compliance tags per rule family (same style as Wazuh's default ruleset). */
type Compliance = { pci_dss?: string[]; gdpr?: string[]; hipaa?: string[]; nist_800_53?: string[]; tsc?: string[] };
const AUTH_TAGS: Compliance   = { pci_dss: ["10.2.5"], gdpr: ["IV_32.2"], hipaa: ["164.312.b"], nist_800_53: ["AU.14", "AC.7"], tsc: ["CC6.8", "CC7.2", "CC7.3"] };
const DATA_TAGS: Compliance   = { pci_dss: ["10.2.1"], gdpr: ["IV_30.1.g"], hipaa: ["164.312.b"], nist_800_53: ["AU.2", "AU.12"], tsc: ["CC7.2"] };
const ADMIN_TAGS: Compliance  = { pci_dss: ["8.1.2", "10.2.5"], gdpr: ["IV_32.2", "IV_35.7.d"], hipaa: ["164.312.a.2.I", "164.312.b"], nist_800_53: ["AC.2", "IA.4"], tsc: ["CC6.1", "CC6.2", "CC6.3"] };
const COMPLIANCE: Record<ClaudeActivityType, Compliance> = {
  sso_login_initiated: AUTH_TAGS, sso_login_succeeded: AUTH_TAGS,
  claude_chat_created: {}, claude_chat_viewed: DATA_TAGS,
  claude_project_created: {}, claude_project_viewed: DATA_TAGS,
  claude_file_uploaded: DATA_TAGS, claude_file_viewed: DATA_TAGS,
  claude_artifact_created: {}, claude_artifact_viewed: DATA_TAGS, claude_artifact_shared: DATA_TAGS,
  admin_api_key_created: ADMIN_TAGS, org_user_invite_accepted: ADMIN_TAGS,
  platform_memory_store_created: {}, platform_memory_created: {}, platform_memory_deleted: DATA_TAGS,
};

/** ATT&CK names for the techniques Claude activity rules are tagged with (Wazuh rule.mitre.*). */
const TECHNIQUE_NAMES: Record<string, string> = {
  "T1078": "Valid Accounts", "T1078.004": "Cloud Accounts",
  "T1098": "Account Manipulation", "T1098.001": "Additional Cloud Credentials",
  "T1213": "Data from Information Repositories",
  "T1530": "Data from Cloud Storage",
  "T1567": "Exfiltration Over Web Service",
  "T1552": "Unsecured Credentials", "T1552.001": "Credentials In Files",
  "T1070": "Indicator Removal",
};

const isPrivate = (ip?: string) => !ip || /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)/.test(ip);

/** Normalised event_type for the platform (drives descriptions, filters, alert classing). */
const EVENT_TYPE: Record<ClaudeActivityType, EventType> = {
  sso_login_initiated: "auth_success", sso_login_succeeded: "auth_success",
  claude_chat_created: "cloud_api_call", claude_chat_viewed: "cloud_api_call",
  claude_project_created: "cloud_api_call", claude_project_viewed: "cloud_storage_access",
  claude_file_uploaded: "cloud_storage_access", claude_file_viewed: "cloud_storage_access",
  claude_artifact_created: "cloud_api_call", claude_artifact_viewed: "cloud_storage_access", claude_artifact_shared: "cloud_storage_access",
  admin_api_key_created: "account_modify", org_user_invite_accepted: "account_modify",
  platform_memory_store_created: "cloud_api_call", platform_memory_created: "cloud_api_call", platform_memory_deleted: "cloud_api_call",
};

/** Stable Compliance-API-style identifiers (base58-ish, "_01" + 24 chars). */
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
export function claudeId(prefix: string, seed: string): string {
  const h = makeSha256(`claude:${prefix}:${seed}`);
  let s = "";
  for (let i = 0; i < 24; i++) s += B58[parseInt(h.slice(i * 2, i * 2 + 2), 16) % B58.length];
  return `${prefix}_01${s}`;
}
const uuidFrom = (seed: string) => {
  const h = makeSha256(`uuid:${seed}`);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-a${h.slice(17, 20)}-${h.slice(20, 32)}`;
};

export interface ClaudeOrg {
  /** Company key used for stable ids (e.g. "nexacorp"). */
  key: string;
  /** Wazuh agent that runs the Compliance API collector. */
  agentName?: string;
  agentId?: string;
  managerName?: string;
  agentIp?: string;
}

export interface ClaudeActivityOpts {
  id: string;
  ts: string;                       // event time (data.created_at); Wazuh ingest adds ~1s
  org: ClaudeOrg;
  type: ClaudeActivityType;
  actorType?: ClaudeActorType;      // default user_actor
  email?: string;                   // user_actor
  ip?: string;
  userAgent?: string;
  apiKeyId?: string;                // api_actor / admin_api_key_actor
  hostname?: string;                // endpoint the activity came from, when known (not in the raw log)
  projectSeed?: string;             // → data.claude_project_id
  fileSeed?: string;                // → data.claude_file_id
  artifactSeed?: string;            // → data.claude_artifact_id
  chatSeed?: string;                // → data.claude_chat_id
  filename?: string;
  source?: string;                  // data.source (collector channel)
  firedTimes?: number;              // Wazuh rule.firedtimes at this event
  geo?: GeoPoint;                   // GeoIP of actor.ip_address (Wazuh GeoLocation.*); else known-prefix table
  service?: string;                 // system_actor → data.actor.service
  directoryId?: string;             // scim_directory_sync_actor → data.actor.directory_id
  idpConnectionType?: string;       // scim_directory_sync_actor → data.actor.idp_connection_type
  severity?: Severity;
  mitre?: string;
  tactic?: string;
  incidentId?: string;
  description?: string;
  expectedVerdict?: TelemetryEvent["expected_verdict"];
  fpExplanation?: string;
  isBaseline?: boolean;
}

export function claudeActivity(o: ClaudeActivityOpts): TelemetryEvent {
  const actorType = o.actorType ?? "user_actor";
  const rule = RULES[o.type];
  const ingest = new Date(Date.parse(o.ts) + 1_000 + (parseInt(makeSha256(o.id).slice(0, 2), 16) % 900)).toISOString();
  const orgId = claudeId("org", o.org.key);
  const activityId = claudeId("activity", o.id);
  const userId = o.email ? claudeId("user", o.email) : undefined;

  const data: Record<string, unknown> = {
    "data.id": activityId,
    "data.type": o.type,
    "data.created_at": o.ts,
    "data.organization_id": orgId,
    "data.organization_uuid": uuidFrom(`org:${o.org.key}`),
    "data.source": o.source ?? "compliance_api",
    "data.actor.type": actorType,
  };
  if (actorType === "user_actor" || actorType === "unauthenticated_user_actor") {
    if (o.email) data["data.actor.email_address"] = o.email;
    if (userId && actorType === "user_actor") data["data.actor.user_id"] = userId;
    if (o.ip) data["data.actor.ip_address"] = o.ip;
    if (o.userAgent) data["data.actor.user_agent"] = o.userAgent;
  } else if (actorType === "system_actor") {
    data["data.actor.service"] = o.service ?? "claude_platform";
  } else if (actorType === "scim_directory_sync_actor") {
    data["data.actor.directory_id"] = o.directoryId ?? claudeId("directory", o.org.key);
    data["data.actor.idp_connection_type"] = o.idpConnectionType ?? "okta";
  } else if (actorType === "api_actor" || actorType === "admin_api_key_actor") {
    data[actorType === "api_actor" ? "data.actor.api_key_id" : "data.actor.admin_api_key_id"] = o.apiKeyId ?? claudeId("apikey", o.id);
    if (o.ip) data["data.actor.ip_address"] = o.ip;
  }
  if (o.projectSeed) data["data.claude_project_id"] = claudeId("claude_proj", o.projectSeed);
  if (o.chatSeed) data["data.claude_chat_id"] = claudeId("claude_chat", o.chatSeed);
  if (o.fileSeed) data["data.claude_file_id"] = claudeId("claude_file", o.fileSeed);
  if (o.artifactSeed) data["data.claude_artifact_id"] = claudeId("claude_artifact", o.artifactSeed);
  if (o.filename) data["data.filename"] = o.filename;

  // full_log = the original Compliance API JSON line as the collector wrote it.
  const fullLog: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(data)) {
    const path = k.replace(/^data\./, "").split(".");
    let cur = fullLog as Record<string, unknown>;
    path.slice(0, -1).forEach(p => { cur[p] = (cur[p] as Record<string, unknown>) ?? {}; cur = cur[p] as Record<string, unknown>; });
    cur[path[path.length - 1]] = v;
  }

  const epoch = (Date.parse(ingest) / 1000).toFixed(0);
  const geo = isPrivate(o.ip) ? null : (o.geo ?? knownGeoForIp(o.ip));
  const tags = COMPLIANCE[o.type];
  const baseTech = o.mitre?.split(".")[0];
  return {
    id: o.id, ts: o.ts, source: "siem", vendor: VENDOR,
    event_type: EVENT_TYPE[o.type],
    severity: o.severity ?? (rule.level >= 8 ? "medium" : rule.level >= 5 ? "low" : "informational"),
    hostname: o.hostname,
    user_email: o.email,
    src_ip: o.ip,
    mitre_technique: o.mitre, mitre_tactic: o.tactic, incident_id: o.incidentId,
    ...(o.expectedVerdict ? { expected_verdict: o.expectedVerdict } : {}),
    ...(o.fpExplanation ? { fp_explanation: o.fpExplanation } : {}),
    ...(o.isBaseline ? { is_baseline: true } : {}),
    ...(o.filename ? { file: { name: o.filename, path: o.filename } } : {}),
    description: o.description ?? `${rule.description}${o.email ? ` by ${o.email}` : ""}${o.filename ? ` (${o.filename})` : ""}`,
    raw: {
      "_index": `wazuh-alerts-4.x-${o.ts.slice(0, 10).replace(/-/g, ".")}`,
      "input.type": "log",
      "agent.name": o.org.agentName ?? "claude-compliance-collector",
      "agent.id": o.org.agentId ?? "014",
      "agent.ip": o.org.agentIp ?? "10.0.5.14",
      "manager.name": o.org.managerName ?? "wazuh-manager-01",
      ...data,
      "rule.id": rule.id,
      "rule.level": rule.level,
      "rule.description": rule.description,
      "rule.groups": rule.groups,
      "rule.firedtimes": o.firedTimes ?? 1,
      "rule.mail": rule.level >= 10,
      ...(tags.pci_dss ? { "rule.pci_dss": tags.pci_dss } : {}),
      ...(tags.gdpr ? { "rule.gdpr": tags.gdpr } : {}),
      ...(tags.hipaa ? { "rule.hipaa": tags.hipaa } : {}),
      ...(tags.nist_800_53 ? { "rule.nist_800_53": tags.nist_800_53 } : {}),
      ...(tags.tsc ? { "rule.tsc": tags.tsc } : {}),
      ...(o.mitre ? {
        "rule.mitre.id": [o.mitre],
        ...(o.tactic ? { "rule.mitre.tactic": [o.tactic] } : {}),
        ...(TECHNIQUE_NAMES[o.mitre] ?? (baseTech && TECHNIQUE_NAMES[baseTech]) ? { "rule.mitre.technique": [TECHNIQUE_NAMES[o.mitre] ?? TECHNIQUE_NAMES[baseTech!]] } : {}),
      } : {}),
      ...(geo ? {
        "GeoLocation.country_name": geo.country,
        "GeoLocation.city_name": geo.city,
        "GeoLocation.location.lat": geo.lat,
        "GeoLocation.location.lon": geo.lon,
      } : {}),
      "location": "/var/ossec/logs/claude/compliance_activities.json",
      "decoder.name": "json",
      "id": `${epoch}.${parseInt(makeSha256(`wz:${o.id}`).slice(0, 7), 16)}`,
      "full_log": JSON.stringify(fullLog),
      "timestamp": ingest.replace("Z", "+0000"),
      "@timestamp": ingest,
      "action_result": "allowed",
    },
  };
}
