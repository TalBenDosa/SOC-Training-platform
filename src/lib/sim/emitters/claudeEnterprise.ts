/**
 * Anthropic Claude Enterprise audit-log EMITTER — one Compliance API activity as it lands
 * in the training SIEM. Generic on purpose: no collector/SIEM-product envelope. Two layers:
 *
 *  1. The activity record exactly as the Compliance API returns it
 *     id, created_at, type, organization_id/_uuid (null on sign-in and Compliance API
 *     activities), actor.* (discriminated by actor.type), claude_chat_id / claude_project_id
 *     (null for a chat outside a project) / claude_file_id / claude_artifact_id, filename.
 *  2. The SIEM's generic (ECS-style) normalization and enrichment of that record
 *     @timestamp, event.{kind,module,dataset,provider,id,action,category,type,outcome,created},
 *     user.{email,id,name,domain}, source.ip + source.geo.* (GeoIP, public IPs only) +
 *     source.as.organization.name (when known), user_agent.* (parsed), related.{ip,user}, tags.
 *
 * Field names, activity types and actor fields follow Anthropic's Compliance API reference
 * (platform.claude.com > Manage Claude > Compliance API, checked 2026-09-29):
 *  - actor union: user_actor {email_address,user_id,ip_address,user_agent} · api_actor
 *    {api_key_id,ip_address,user_agent} · admin_api_key_actor {admin_api_key_id,ip_address,
 *    user_agent} · unauthenticated_user_actor {unauthenticated_email_address,ip_address,
 *    user_agent} (e.g. sso_login_initiated) · anthropic_actor {email_address:null} ·
 *    system_actor {service|null} · scim_directory_sync_actor {workos_event_id,directory_id,
 *    idp_connection_type e.g. OktaSCIMV2};
 *  - ids are prefix + "_01" + 22 base58 chars (activity_, org_, user_, apikey_, claude_chat_,
 *    claude_proj_, claude_file_, claude_artifact_);
 *  - Compliance Access Key calls surface as `compliance_api_accessed` by an api_actor;
 *    Admin API keys reach the Activity Feed only, never chat/file content.
 *
 * What this log does NOT carry: prompt or response text. It records WHO did WHAT to WHICH
 * chat/project/file/artifact, from WHERE.
 */
import type { TelemetryEvent, Severity, EventType } from "../types";
import { makeSha256 } from "@/lib/sim/iocs";
import { knownGeoForIp, type GeoPoint } from "@/lib/geo/resolveGeo";

const VENDOR = "Anthropic Claude Enterprise";

export type ClaudeActorType =
  | "user_actor" | "api_actor" | "admin_api_key_actor" | "unauthenticated_user_actor"
  | "anthropic_actor" | "system_actor" | "scim_directory_sync_actor";

export type ClaudeActivityType =
  | "sso_login_initiated" | "sso_login_succeeded" | "sso_login_failed"
  | "claude_chat_created" | "claude_chat_viewed" | "claude_chat_deleted"
  | "claude_project_created" | "claude_project_viewed" | "claude_project_sharing_updated"
  | "claude_file_uploaded" | "claude_file_viewed" | "claude_file_deleted"
  | "claude_artifact_created" | "claude_artifact_viewed" | "claude_artifact_sharing_updated" | "claude_artifact_published"
  | "claude_artifact_external_sharing_permission_updated"
  | "admin_api_key_created" | "api_key_created" | "compliance_api_accessed"
  | "org_ip_restriction_deleted" | "org_data_export_started" | "org_data_export_completed" | "org_data_export_accessed"
  | "org_user_invite_accepted"
  | "platform_memory_store_created" | "platform_memory_created" | "platform_memory_deleted";

/** Platform classification per activity: normalised event_type, default severity, fallback wording. */
const META: Record<ClaudeActivityType, { et: EventType; sev: Severity; label: string }> = {
  sso_login_initiated:             { et: "auth_success",         sev: "informational", label: "SSO login initiated" },
  sso_login_succeeded:             { et: "auth_success",         sev: "informational", label: "SSO login succeeded" },
  sso_login_failed:                { et: "auth_failure",         sev: "low",           label: "SSO login failed" },
  claude_chat_created:             { et: "cloud_api_call",       sev: "informational", label: "chat created" },
  claude_chat_viewed:              { et: "cloud_api_call",       sev: "informational", label: "chat loaded" },
  claude_chat_deleted:             { et: "cloud_api_call",       sev: "low",           label: "chat deleted" },
  claude_project_created:          { et: "cloud_api_call",       sev: "informational", label: "project created" },
  claude_project_viewed:           { et: "cloud_storage_access", sev: "informational", label: "project loaded" },
  claude_project_sharing_updated:  { et: "cloud_storage_access", sev: "low",           label: "project sharing settings updated" },
  claude_file_uploaded:            { et: "cloud_storage_access", sev: "low",           label: "file uploaded" },
  claude_file_viewed:              { et: "cloud_storage_access", sev: "informational", label: "file loaded" },
  claude_file_deleted:             { et: "cloud_storage_access", sev: "low",           label: "file deleted" },
  claude_artifact_created:         { et: "cloud_api_call",       sev: "informational", label: "artifact created" },
  claude_artifact_viewed:          { et: "cloud_storage_access", sev: "informational", label: "artifact loaded" },
  claude_artifact_sharing_updated: { et: "cloud_storage_access", sev: "low",           label: "artifact sharing settings updated" },
  claude_artifact_published:       { et: "cloud_storage_access", sev: "low",           label: "artifact version published" },
  claude_artifact_external_sharing_permission_updated: { et: "cloud_storage_access", sev: "low", label: "artifact external sharing permission updated" },
  admin_api_key_created:           { et: "account_modify",       sev: "medium",        label: "admin API key created" },
  api_key_created:                 { et: "account_modify",       sev: "medium",        label: "API key created" },
  compliance_api_accessed:         { et: "cloud_api_call",       sev: "informational", label: "Compliance API accessed" },
  org_ip_restriction_deleted:      { et: "account_modify",       sev: "medium",        label: "organization IP restriction deleted" },
  org_data_export_started:         { et: "cloud_storage_access", sev: "medium",        label: "organization data export started" },
  org_data_export_completed:       { et: "cloud_storage_access", sev: "low",           label: "organization data export completed" },
  org_data_export_accessed:        { et: "cloud_storage_access", sev: "medium",        label: "organization data export accessed" },
  org_user_invite_accepted:        { et: "account_modify",       sev: "low",           label: "organization invite accepted" },
  platform_memory_store_created:   { et: "cloud_api_call",       sev: "informational", label: "memory store created" },
  platform_memory_created:         { et: "cloud_api_call",       sev: "informational", label: "memory created" },
  platform_memory_deleted:         { et: "cloud_api_call",       sev: "low",           label: "memory deleted" },
};

/** Activities not tied to an organization carry organization_id/uuid = null (Compliance API docs). */
const ORGLESS = new Set<ClaudeActivityType>(["sso_login_initiated", "sso_login_succeeded", "sso_login_failed", "compliance_api_accessed"]);
/** Default actor per activity when the caller does not choose one. */
const DEFAULT_ACTOR: Partial<Record<ClaudeActivityType, ClaudeActorType>> = {
  sso_login_initiated: "unauthenticated_user_actor",
  compliance_api_accessed: "api_actor",
};

/** ECS event.category / event.type per activity (what a generic SIEM parser assigns). */
const ECS: Record<ClaudeActivityType, { cat: string; type: string }> = {
  sso_login_initiated: { cat: "authentication", type: "info" },
  sso_login_succeeded: { cat: "authentication", type: "start" },
  sso_login_failed: { cat: "authentication", type: "start" },
  claude_chat_created: { cat: "web", type: "creation" }, claude_chat_viewed: { cat: "web", type: "access" }, claude_chat_deleted: { cat: "web", type: "deletion" },
  claude_project_created: { cat: "web", type: "creation" }, claude_project_viewed: { cat: "web", type: "access" }, claude_project_sharing_updated: { cat: "web", type: "change" },
  claude_file_uploaded: { cat: "file", type: "creation" }, claude_file_viewed: { cat: "file", type: "access" }, claude_file_deleted: { cat: "file", type: "deletion" },
  claude_artifact_created: { cat: "web", type: "creation" }, claude_artifact_viewed: { cat: "web", type: "access" },
  claude_artifact_sharing_updated: { cat: "web", type: "change" }, claude_artifact_published: { cat: "web", type: "change" },
  claude_artifact_external_sharing_permission_updated: { cat: "web", type: "change" },
  admin_api_key_created: { cat: "iam", type: "creation" }, api_key_created: { cat: "iam", type: "creation" },
  compliance_api_accessed: { cat: "api", type: "access" },
  org_ip_restriction_deleted: { cat: "configuration", type: "deletion" },
  org_data_export_started: { cat: "web", type: "start" },
  org_data_export_completed: { cat: "web", type: "end" }, org_data_export_accessed: { cat: "web", type: "access" },
  org_user_invite_accepted: { cat: "iam", type: "change" },
  platform_memory_store_created: { cat: "web", type: "creation" }, platform_memory_created: { cat: "web", type: "creation" }, platform_memory_deleted: { cat: "web", type: "deletion" },
};

const ISO2: Record<string, string> = {
  "Israel": "IL", "United Kingdom": "GB", "United States": "US", "Russia": "RU", "Netherlands": "NL", "Germany": "DE",
  "France": "FR", "Switzerland": "CH", "India": "IN", "Ukraine": "UA", "Romania": "RO", "China": "CN", "Singapore": "SG",
};

/** Minimal user-agent parser (browser/OS for humans, client/library for scripts). */
function parseUserAgent(ua: string): Record<string, string> {
  const out: Record<string, string> = { "user_agent.original": ua };
  const lib = ua.match(/^(python-requests|python-httpx|curl|Go-http-client|axios|node-fetch|anthropic-python|anthropic-typescript)\/([\d.]+)/i);
  if (lib) return { ...out, "user_agent.name": lib[1], "user_agent.version": lib[2], "user_agent.device.name": "Other" };
  const edge = ua.match(/Edg\/([\d.]+)/), ff = ua.match(/Firefox\/([\d.]+)/), chrome = ua.match(/Chrome\/([\d.]+)/), safari = ua.match(/Version\/([\d.]+).*Safari/);
  const b = edge ? ["Edge", edge[1]] : ff ? ["Firefox", ff[1]] : chrome ? ["Chrome", chrome[1]] : safari ? ["Safari", safari[1]] : null;
  if (b) { out["user_agent.name"] = b[0]; out["user_agent.version"] = b[1]; }
  const mac = ua.match(/Mac OS X ([\d_]+)/);
  if (/Windows NT 10\.0/.test(ua)) { out["user_agent.os.name"] = "Windows"; out["user_agent.os.version"] = "10"; }
  else if (mac) { out["user_agent.os.name"] = "Mac OS X"; out["user_agent.os.version"] = mac[1].replace(/_/g, "."); }
  else if (/Linux/.test(ua)) out["user_agent.os.name"] = "Linux";
  out["user_agent.device.name"] = /Mobile|iPhone|Android/.test(ua) ? "Mobile" : "Other";
  return out;
}

const isPrivate = (ip?: string) => !ip || /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)/.test(ip);

/** Stable Compliance-API-style identifiers (base58-ish, "_01" + 22 chars, as in the API docs). */
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
export function claudeId(prefix: string, seed: string): string {
  const h = makeSha256(`claude:${prefix}:${seed}`);
  let s = "";
  for (let i = 0; i < 22; i++) s += B58[parseInt(h.slice(i * 2, i * 2 + 2), 16) % B58.length];
  return `${prefix}_01${s}`;
}
const uuidFrom = (seed: string) => {
  const h = makeSha256(`uuid:${seed}`);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-a${h.slice(17, 20)}-${h.slice(20, 32)}`;
};

export interface ClaudeOrg {
  /** Company key used for stable ids (e.g. "nexacorp"). */
  key: string;
}

export interface ClaudeActivityOpts {
  id: string;
  ts: string;                       // event time (created_at)
  org: ClaudeOrg;
  type: ClaudeActivityType;
  actorType?: ClaudeActorType;      // default per activity, else user_actor
  email?: string;                   // user_actor / unauthenticated_user_actor
  ip?: string;
  userAgent?: string;
  apiKeyId?: string;                // api_actor / admin_api_key_actor
  hostname?: string;                // endpoint the activity came from, when known (not in the raw log)
  projectSeed?: string;             // → claude_project_id
  fileSeed?: string;                // → claude_file_id
  artifactSeed?: string;            // → claude_artifact_id
  chatSeed?: string;                // → claude_chat_id
  filename?: string;
  geo?: GeoPoint;                   // GeoIP of actor.ip_address; else known-prefix table
  asOrg?: string;                   // source.as.organization.name, when the address owner is known
  service?: string | null;          // system_actor → actor.service (nullable)
  directoryId?: string;             // scim_directory_sync_actor → actor.directory_id
  idpConnectionType?: string;       // scim_directory_sync_actor → actor.idp_connection_type (e.g. OktaSCIMV2)
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
  const actorType = o.actorType ?? DEFAULT_ACTOR[o.type] ?? "user_actor";
  const meta = META[o.type];
  const orgless = ORGLESS.has(o.type);

  const actor: Record<string, unknown> = { "actor.type": actorType };
  if (actorType === "user_actor") {
    if (o.email) { actor["actor.email_address"] = o.email; actor["actor.user_id"] = claudeId("user", o.email); }
    if (o.ip) actor["actor.ip_address"] = o.ip;
    if (o.userAgent) actor["actor.user_agent"] = o.userAgent;
  } else if (actorType === "unauthenticated_user_actor") {
    if (o.email) actor["actor.unauthenticated_email_address"] = o.email;
    if (o.ip) actor["actor.ip_address"] = o.ip;
    if (o.userAgent) actor["actor.user_agent"] = o.userAgent;
  } else if (actorType === "anthropic_actor") {
    actor["actor.email_address"] = null;
  } else if (actorType === "system_actor") {
    actor["actor.service"] = o.service ?? null;
  } else if (actorType === "scim_directory_sync_actor") {
    actor["actor.workos_event_id"] = claudeId("event", o.id);
    actor["actor.directory_id"] = o.directoryId ?? claudeId("directory", o.org.key);
    actor["actor.idp_connection_type"] = o.idpConnectionType ?? "OktaSCIMV2";
  } else {
    actor[actorType === "api_actor" ? "actor.api_key_id" : "actor.admin_api_key_id"] = o.apiKeyId ?? claudeId("apikey", o.id);
    if (o.ip) actor["actor.ip_address"] = o.ip;
    if (o.userAgent) actor["actor.user_agent"] = o.userAgent;
  }

  const geo = isPrivate(o.ip) ? null : (o.geo ?? knownGeoForIp(o.ip));
  const activityId = claudeId("activity", o.id);
  const ecs = ECS[o.type];
  // Activities are queryable ~1 min after they occur; the SIEM poller picks them up shortly after.
  const created = new Date(Date.parse(o.ts) + 62_000 + (parseInt(makeSha256(o.id).slice(0, 2), 16) % 40) * 1000).toISOString();
  const [local, domain] = (o.email ?? "").split("@");
  const userFields: Record<string, unknown> = o.email ? {
    "user.email": o.email, ...(actorType === "user_actor" ? { "user.id": claudeId("user", o.email) } : {}),
    "user.name": local, "user.domain": domain,
  } : {};
  return {
    id: o.id, ts: o.ts, source: "siem", vendor: VENDOR,
    event_type: meta.et,
    severity: o.severity ?? meta.sev,
    hostname: o.hostname,
    user_email: o.email,
    src_ip: o.ip,
    mitre_technique: o.mitre, mitre_tactic: o.tactic, incident_id: o.incidentId,
    ...(o.expectedVerdict ? { expected_verdict: o.expectedVerdict } : {}),
    ...(o.fpExplanation ? { fp_explanation: o.fpExplanation } : {}),
    ...(o.isBaseline ? { is_baseline: true } : {}),
    ...(o.filename ? { file: { name: o.filename, path: o.filename } } : {}),
    description: o.description ?? `Claude Enterprise ${meta.label}${o.email ? ` by ${o.email}` : ""}${o.filename ? ` (${o.filename})` : ""}.`,
    raw: {
      "@timestamp": o.ts,
      "id": activityId,
      "created_at": o.ts,
      "type": o.type,
      "organization_id": orgless ? null : claudeId("org", o.org.key),
      "organization_uuid": orgless ? null : uuidFrom(`org:${o.org.key}`),
      ...actor,
      ...(o.chatSeed ? { "claude_chat_id": claudeId("claude_chat", o.chatSeed) } : {}),
      ...(o.projectSeed ? { "claude_project_id": claudeId("claude_proj", o.projectSeed) }
        : o.type === "claude_chat_created" ? { "claude_project_id": null } : {}),
      ...(o.fileSeed ? { "claude_file_id": claudeId("claude_file", o.fileSeed) } : {}),
      ...(o.artifactSeed ? { "claude_artifact_id": claudeId("claude_artifact", o.artifactSeed) } : {}),
      ...(o.filename ? { "filename": o.filename } : {}),
      // ── SIEM normalization / enrichment ──
      "event.kind": "event",
      "event.module": "anthropic",
      "event.dataset": "anthropic.compliance_activities",
      "event.provider": "claude_enterprise",
      "event.id": activityId,
      "event.action": o.type,
      "event.category": [ecs.cat],
      "event.type": [ecs.type],
      "event.outcome": o.type === "sso_login_failed" ? "failure" : "success",
      "event.created": created,
      ...userFields,
      ...(o.ip ? { "source.ip": o.ip } : {}),
      ...(geo ? {
        "source.geo.country_name": geo.country,
        ...(ISO2[geo.country] ? { "source.geo.country_iso_code": ISO2[geo.country] } : {}),
        "source.geo.city_name": geo.city,
        "source.geo.location.lat": geo.lat,
        "source.geo.location.lon": geo.lon,
      } : {}),
      ...(o.asOrg ? { "source.as.organization.name": o.asOrg } : {}),
      ...(o.userAgent ? parseUserAgent(o.userAgent) : {}),
      ...(o.ip ? { "related.ip": [o.ip] } : {}),
      ...(o.email ? { "related.user": [o.email] } : {}),
      "tags": ["claude-enterprise", "compliance-api", "genai"],
    },
  };
}
