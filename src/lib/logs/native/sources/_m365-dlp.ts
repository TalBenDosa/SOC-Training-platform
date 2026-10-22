/**
 * Microsoft Purview DLP rule matches as the Unified Audit Log delivers them (DLP.All content type),
 * rendered by the m365 module (not a module itself).
 *
 * Shape: the Office 365 Management Activity API "Data Loss Prevention (DLP) schema"
 * (learn.microsoft.com/office/office-365-management-api/office-365-management-activity-api-schema):
 * the common schema (CreationTime, Id, Operation "DlpRuleMatch", OrganizationId, RecordType, UserKey
 * "DlpAgent", UserType, Version, Workload, UserId, ObjectId) plus IncidentId, PolicyDetails[] (PolicyId,
 * PolicyName, Rules[] with RuleId, RuleName, Actions[], OverriddenActions[], Severity, RuleMode,
 * ConditionsMatched.SensitiveInformation[]), SensitiveInfoDetectionIsIncluded and ONE workload block:
 * ExchangeMetaData (RecordType 13), SharePointMetaData (RecordType 11) or EndpointMetaData
 * (RecordType 63, DLPEndpoint). The card collab-m365.md does not document DLP records; these names
 * are the schema reference's. EndpointMetaData.Application (the process that touched the file) is
 * UNVERIFIED in the reference's complex type, emitted only when the scenario authors it.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { KindSchema, NativeCtx, NativeLog } from "../types";
import { rs, rv, isoNoMs, type Raw } from "./collab-email-shared";

const COMMON = ["Id", "RecordType", "CreationTime", "Operation", "OrganizationId", "UserType", "UserKey", "Workload", "UserId"];
const SI = "PolicyDetails[].Rules[].ConditionsMatched.SensitiveInformation[]";
export const DLP_KIND: KindSchema = {
  required: [...COMMON, "ObjectId", "IncidentId", "PolicyDetails", "PolicyDetails[].PolicyId", "PolicyDetails[].PolicyName", "PolicyDetails[].Rules",
    "PolicyDetails[].Rules[].RuleId", "PolicyDetails[].Rules[].RuleName", "PolicyDetails[].Rules[].Actions", "PolicyDetails[].Rules[].Severity",
    "PolicyDetails[].Rules[].RuleMode", "SensitiveInfoDetectionIsIncluded"],
  optional: ["Version", "ClientIP", "PolicyDetails[].Rules[].OverriddenActions", "PolicyDetails[].Rules[].ConditionsMatched",
    `${SI}.SensitiveInformationTypeName`, `${SI}.SensitiveType`, `${SI}.Count`, `${SI}.UniqueCount`, `${SI}.Confidence`, `${SI}.Location`,
    "ExceptionInfo", "ExceptionInfo.Reason", "ExceptionInfo.Justification", "ExceptionInfo.FalsePositive",
    "ExchangeMetaData", "ExchangeMetaData.MessageID", "ExchangeMetaData.From", "ExchangeMetaData.To", "ExchangeMetaData.CC", "ExchangeMetaData.BCC",
    "ExchangeMetaData.Subject", "ExchangeMetaData.Sent", "ExchangeMetaData.RecipientCount",
    "SharePointMetaData", "SharePointMetaData.From", "SharePointMetaData.itemCreationTime", "SharePointMetaData.SiteCollectionGuid",
    "SharePointMetaData.SiteCollectionUrl", "SharePointMetaData.FileName", "SharePointMetaData.FileOwner", "SharePointMetaData.FilePathUrl",
    "SharePointMetaData.DocumentLastModifier", "SharePointMetaData.DocumentSharer", "SharePointMetaData.UniqueId", "SharePointMetaData.LastModifiedTime",
    "SharePointMetaData.IsViewableByExternalUsers",
    "EndpointMetaData", "EndpointMetaData.EnforcementMode", "EndpointMetaData.FileExtension", "EndpointMetaData.FileType", "EndpointMetaData.DeviceName",
    "EndpointMetaData.Application"],
};
export const DLP_RECORD_TYPES = { Exchange: 13, SharePoint: 11, OneDrive: 11, Endpoint: 63 } as const;

const POLICY_KEYS = ["PolicyDetails.PolicyName", "PolicyDetails[0].PolicyName", "purview.PolicyName", "policy.name", "dlp.policy.name"];
/** A Purview DLP rule match: a DLP event that names the policy whose rule matched. */
export function isDlpRuleMatch(ev: TelemetryEvent): boolean {
  const raw = (ev.raw ?? {}) as Raw;
  if (!/purview|microsoft 365|office 365/i.test(ev.vendor ?? "") && ev.source !== "dlp") return false;
  const op = rs(raw, "Operation");
  if (op && op !== "DlpRuleMatch") return false;
  return !!rs(raw, ...POLICY_KEYS) && (ev.source === "dlp" || op === "DlpRuleMatch");
}

const arr = (v: unknown): string[] => (Array.isArray(v) ? v.map(String) : v === undefined || v === null || v === "" ? [] : String(v).split(/\s*,\s*/));

function workloadOf(ev: TelemetryEvent, raw: Raw): keyof typeof DLP_RECORD_TYPES {
  const w = rs(raw, "Workload");
  if (w && /exchange/i.test(w)) return "Exchange";
  if (w && /onedrive/i.test(w)) return "OneDrive";
  if (w && /sharepoint/i.test(w)) return "SharePoint";
  if (w && /endpoint/i.test(w)) return "Endpoint";
  if (Object.keys(raw).some(k => k.startsWith("email.")) || ev.event_type === "email_sent") return "Exchange";
  if (rs(raw, "DeviceName", "DeviceDisplayName", "EndpointMetaData.DeviceName", "host.name") || ev.hostname || Object.keys(raw).some(k => /^(usb|removable_media|print)\./.test(k))) return "Endpoint";
  return /onedrive|-my\.sharepoint/i.test(rs(raw, "cloud.resource.name", "ObjectId") ?? "") ? "OneDrive" : "SharePoint";
}

/** The DlpRuleMatch audit record for a Purview DLP event (null when it names no policy). */
export function dlpRecord(ev: TelemetryEvent, ctx: NativeCtx, user: string | undefined): NativeLog | null {
  const raw = (ev.raw ?? {}) as Raw;
  const policy = rs(raw, ...POLICY_KEYS);
  if (!policy || !user) return null;
  const workload = workloadOf(ev, raw);
  const rt = DLP_RECORD_TYPES[workload];
  const rule = rs(raw, "PolicyDetails.Rules.RuleName", "PolicyDetails[0].Rules[0].RuleName", "purview.RuleName", "policy.rule") ?? policy;
  const authoredActions = rv(raw, "PolicyDetails.Rules.Actions", "PolicyDetails[0].Rules[0].Actions");
  const legacyAction = rs(raw, "purview.ActionTaken", "policy.action", "action_result") ?? "";
  // Purview rule actions: the documented vocabulary (Audit, NotifyUser, BlockAccess, GenerateIncidentReport…).
  const actions = authoredActions !== undefined ? arr(authoredActions)
    : /block|prevent|denied/i.test(legacyAction) ? ["BlockAccess", "NotifyUser", "GenerateIncidentReport"]
    : /warn|override/i.test(legacyAction) ? ["NotifyUser", "GenerateIncidentReport"] : ["Audit", "GenerateIncidentReport"];
  const sevRaw = rs(raw, "PolicyDetails.Rules.Severity", "PolicyDetails[0].Rules[0].Severity") ?? ev.severity ?? "medium";
  const severity = /crit|high/i.test(sevRaw) ? "High" : /low|info/i.test(sevRaw) ? "Low" : "Medium";
  const sitName = rs(raw, "PolicyDetails.Rules.ConditionsMatched.SensitiveInformation.SensitiveInformationTypeName", "purview.SensitiveInfoType", "data.classification", "data.type");
  const count = Number(rs(raw, "PolicyDetails.Rules.ConditionsMatched.SensitiveInformation.Count") ?? rs(raw, "file.count") ?? 1);
  const confidence = Number(rs(raw, "PolicyDetails.Rules.ConditionsMatched.SensitiveInformation.Confidence") ?? 85);
  const filePath = ev.file?.path ?? rs(raw, "ObjectId", "file.path", "cloud.resource.name", "print.file_name", "email.attachment.name", "file.name");
  const fileName = ev.file?.name ?? rs(raw, "file.name", "EndpointMetaData.FileName", "SourceFileName", "email.attachment.name", "print.file_name") ?? filePath?.split(/[\\/]/).pop();
  const ext = (fileName ?? "").includes(".") ? fileName!.split(".").pop()!.toLowerCase() : undefined;
  const seed = `${ctx.companyId}:dlp:${policy.toLowerCase()}`;
  const rec: Record<string, unknown> = {
    CreationTime: isoNoMs(ev.ts),
    Id: ctx.uuid(`${ev.id}:ualid`),
    Operation: "DlpRuleMatch",
    OrganizationId: ctx.tenant.azureTenantId,
    RecordType: rt,
    UserKey: "DlpAgent",
    UserType: 4,
    Version: 1,
    Workload: workload,
    ObjectId: filePath ?? (workload === "Exchange" ? rs(raw, "email.subject") ?? user : user),
    UserId: user,
    IncidentId: rs(raw, "IncidentId") ?? ctx.uuid(`${ev.id}:dlp-incident`),
    PolicyDetails: [{
      PolicyId: ctx.uuid(`${seed}:policy`),
      PolicyName: policy,
      Rules: [{
        RuleId: ctx.uuid(`${seed}:rule:${rule.toLowerCase()}`),
        RuleName: rule,
        Actions: actions,
        OverriddenActions: /override/i.test(`${legacyAction} ${rs(raw, "purview.Override") ?? ""}`) && rs(raw, "purview.Override") !== "false" ? ["BlockAccess"] : [],
        Severity: severity,
        RuleMode: rs(raw, "PolicyDetails.Rules.RuleMode") ?? "Enable",
        ...(sitName ? { ConditionsMatched: { SensitiveInformation: [{
          Confidence: Number.isFinite(confidence) ? confidence : 85, Count: Number.isFinite(count) ? count : 1,
          SensitiveInformationTypeName: sitName, SensitiveType: ctx.uuid(`global:sit:${sitName.toLowerCase()}`), UniqueCount: Math.max(1, Math.min(Number.isFinite(count) ? count : 1, Math.ceil((Number.isFinite(count) ? count : 1) * 0.8))),
        }] } } : {}),
      }],
    }],
    SensitiveInfoDetectionIsIncluded: false,
  };
  const just = rs(raw, "purview.JustificationText");
  if (just) rec.ExceptionInfo = { Reason: "Override", Justification: just, FalsePositive: false };
  if (workload === "Exchange") {
    const to = arr(rv(raw, "ExchangeMetaData.To", "email.to.address"));
    rec.ExchangeMetaData = {
      MessageID: rs(raw, "ExchangeMetaData.MessageID", "email.message_id") ?? `<${ctx.hex(`${ev.id}:msgid`, 24).toUpperCase()}@${user.split("@")[1]}>`,
      From: rs(raw, "ExchangeMetaData.From", "email.from.address") ?? user, To: to, CC: [], BCC: [],
      Subject: rs(raw, "ExchangeMetaData.Subject", "email.subject") ?? "", Sent: new Date(Date.parse(ev.ts)).toISOString().slice(0, 19), RecipientCount: Math.max(1, to.length),
    };
  } else if (workload === "Endpoint") {
    const enforce = actions.includes("BlockAccess") ? (rec.PolicyDetails as { Rules: { OverriddenActions: string[] }[] }[])[0].Rules[0].OverriddenActions.length ? "Warn" : "Block" : "Audit";
    const app = rs(raw, "EndpointMetaData.Application", "ClientProcessName", "process.name") ?? ev.process?.name;
    rec.EndpointMetaData = {
      DeviceName: rs(raw, "EndpointMetaData.DeviceName", "DeviceDisplayName", "DeviceName", "host.name") ?? ev.hostname ?? "-",
      EnforcementMode: enforce,
      ...(ext ? { FileExtension: ext, FileType: ext.toUpperCase() } : {}),
      ...(app ? { Application: app } : {}),
    };
  } else {
    const url = filePath && /^https?:\/\//.test(filePath) ? filePath : undefined;
    const site = url ? url.split("/").slice(0, 5).join("/") : rs(raw, "SiteUrl");
    rec.SharePointMetaData = {
      From: user, FileName: fileName ?? "-", FileOwner: rs(raw, "file.owner") ?? user, FilePathUrl: url ?? filePath ?? "-",
      ...(site ? { SiteCollectionUrl: site, SiteCollectionGuid: ctx.uuid(`${ctx.companyId}:site:${site.toLowerCase()}`) } : {}),
      UniqueId: ctx.uuid(`${ctx.companyId}:spfile:${(filePath ?? fileName ?? ev.id).toLowerCase()}`),
      DocumentLastModifier: user, IsViewableByExternalUsers: /external|anyone|anonymous/i.test(rs(raw, "SharingType", "upload.destination") ?? ""),
    };
  }
  return { sourceId: "m365", kind: "DlpRuleMatch", format: "json", record: rec, timeMs: Date.parse(ev.ts) };
}
