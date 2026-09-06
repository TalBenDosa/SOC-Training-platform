/**
 * Microsoft 365 Unified Audit Log EMITTERS.
 *
 * The tenant-wide audit trail across Exchange / SharePoint / OneDrive / Entra —
 * the record an analyst reads for BEC inbox rules, mailbox-permission grants,
 * file access/sharing/download, and DLP rule matches. Renders registry-valid M365
 * fields (the data.office365. prefix + GeoLocation.*), identity from the fabric,
 * geography deterministic from the actor IP.
 *
 * M365 is source:"o365" and carries no process.
 */
import type { TelemetryEvent, Severity, EventType } from "../types";
import { resolve, type Ctx } from "./_core";
import { knownGeoForIp } from "@/lib/geo/resolveGeo";

const VENDOR = "Microsoft 365 Unified Audit Log";

function geoFields(ip?: string): Record<string, string | number> {
  const k = knownGeoForIp(ip);
  if (!k) return {};
  return { "GeoLocation.country_name": k.country, "GeoLocation.city_name": k.city, "GeoLocation.latitude": k.lat, "GeoLocation.longitude": k.lon };
}

// ── Generic audit operation (Exchange / SharePoint / OneDrive / Entra admin) ──────────
export interface M365OperationOpts extends Ctx {
  operation: string;               // e.g. "New-InboxRule", "FileAccessed", "Add-MailboxPermission"
  workload?: "Exchange" | "SharePoint" | "OneDrive" | "AzureActiveDirectory" | "MicrosoftTeams";
  srcIp: string;                   // ActorIpAddress
  outcome?: "success" | "failure";
  eventType?: EventType;           // override; else inferred from the operation
  objectId?: string;               // file path / mailbox / target object
  fileName?: string;
  siteUrl?: string;
  userAgent?: string;
  targetUser?: string;             // for permission/impersonation ops
  parameters?: string;            // rule parameters etc. (free text)
  mitre?: string;
  tactic?: string;
  severity?: Severity;
  description?: string;
}
function inferType(op: string): EventType {
  const n = op.toLowerCase();
  if (/inboxrule|transportrule|mailflow/.test(n)) return "policy_modification";
  if (/mailboxpermission|addfolderpermission|delegate|impersonat/.test(n)) return "privileged_operation";
  if (/filedownload/.test(n)) return "sharepoint_download";
  if (/fileaccessed|filepreviewed/.test(n)) return "sharepoint_access";
  if (/sharing|anonymouslink|addedtogroup|companylinkcreated/.test(n)) return "sharepoint_share";
  if (/^add member|add-|new-|update-|set-/.test(n)) return "account_modify";
  return "cloud_api_call";
}
export function m365Operation(o: M365OperationOpts): TelemetryEvent {
  const r = resolve(o);
  const email = r.email ?? `${r.bareUser}@example.com`;
  const workload = o.workload ?? "Exchange";
  const ok = (o.outcome ?? "success") === "success";
  const name = o.fileName ?? (o.objectId ? o.objectId.split(/[\\/]/).pop() : undefined);
  return {
    id: o.id, ts: o.ts, source: "o365", vendor: VENDOR,
    event_type: o.eventType ?? inferType(o.operation),
    severity: o.severity ?? "medium", src_ip: o.srcIp, user_email: email,
    mitre_technique: o.mitre, mitre_tactic: o.tactic, incident_id: o.incidentId,
    geo: knownGeoForIp(o.srcIp) ? { country: knownGeoForIp(o.srcIp)!.country, city: knownGeoForIp(o.srcIp)!.city } : undefined,
    ...(name ? { file: { name, path: o.objectId ?? name } } : {}),
    description: o.description ?? `M365 ${o.operation} (${workload}) by ${email} — ${ok ? "Succeeded" : "Failed"}`,
    raw: {
      "data.office365.Operation": o.operation,
      "data.office365.Workload": workload,
      "data.office365.UserId": email,
      "data.office365.UserKey": email,
      "data.office365.ClientIP": o.srcIp,
      "data.office365.ActorIpAddress": o.srcIp,
      "data.office365.ResultStatus": ok ? "Succeeded" : "Failed",
      "data.office365.CreationTime": o.ts,
      ...(o.objectId ? { "data.office365.ObjectId": o.objectId } : {}),
      ...(o.fileName ? { "data.office365.SourceFileName": o.fileName } : {}),
      ...(o.siteUrl ? { "data.office365.SiteUrl": o.siteUrl } : {}),
      ...(o.userAgent ? { "data.office365.UserAgent": o.userAgent } : {}),
      ...(o.targetUser ? { "data.office365.TargetUser": o.targetUser } : {}),
      ...(o.parameters ? { "data.office365.Parameters": o.parameters } : {}),
      ...geoFields(o.srcIp),
      // outcome/action live in the vendor's own Operation + ResultStatus fields;
      // event.* are not valid M365 keys. source.ip is a shared common field.
      "source.ip": o.srcIp,
    },
  };
}

// ── DLP rule match (Purview / Exchange / SharePoint DLP) ──────────────────────────────
export interface M365DlpOpts extends Ctx {
  policyName: string;
  ruleName: string;
  workload?: "Exchange" | "SharePoint" | "OneDrive";
  srcIp: string;
  sensitiveType: string;           // e.g. "Credit Card Number"
  sensitiveCount?: number;
  action?: "blocked" | "notified" | "audited";
  fileName?: string;
  recipients?: string;             // for Exchange DLP
  subject?: string;
  mitre?: string;
  tactic?: string;
  severity?: Severity;
  description?: string;
}
export function m365Dlp(o: M365DlpOpts): TelemetryEvent {
  const r = resolve(o);
  const email = r.email ?? `${r.bareUser}@example.com`;
  const workload = o.workload ?? "Exchange";
  const action = o.action ?? "blocked";
  return {
    id: o.id, ts: o.ts, source: "o365", vendor: VENDOR,
    event_type: action === "blocked" ? "dlp_block" : "dlp_alert",
    severity: o.severity ?? "high", src_ip: o.srcIp, user_email: email,
    mitre_technique: o.mitre, mitre_tactic: o.tactic, incident_id: o.incidentId,
    ...(o.fileName ? { file: { name: o.fileName, path: o.fileName } } : {}),
    description: o.description ?? `M365 DLP "${o.ruleName}" ${action} — ${o.sensitiveType} by ${email}`,
    raw: {
      "data.office365.Operation": "DlpRuleMatch",
      "data.office365.Workload": workload,
      "data.office365.UserId": email,
      "data.office365.ClientIP": o.srcIp,
      "data.office365.PolicyName": o.policyName,
      "data.office365.RuleName": o.ruleName,
      "data.office365.SensitiveInfoTypeName": o.sensitiveType,
      ...(o.sensitiveCount !== undefined ? { "data.office365.SensitiveInfoCount": String(o.sensitiveCount) } : {}),
      "data.office365.DlpRuleAction": action,
      ...(o.fileName ? { "data.office365.SourceFileName": o.fileName } : {}),
      ...(o.recipients ? { "data.office365.Recipients": o.recipients } : {}),
      ...(o.subject ? { "data.office365.Subject": o.subject } : {}),
      "data.office365.ResultStatus": "Succeeded",
      "data.office365.CreationTime": o.ts,
      ...geoFields(o.srcIp),
      "source.ip": o.srcIp,
    },
  };
}
