/**
 * Azure AI workload EMITTERS — what the SIEM receives when an Azure OpenAI / Foundry
 * model deployment is used or attacked.
 *
 *  - azureOpenAiRequest   Azure OpenAI resource log, category RequestResponse (Azure Monitor
 *                         diagnostic setting → SIEM). Per-request metadata only: operation,
 *                         deployment, model, latency, HTTP result, request/response LENGTHS.
 *                         No prompt or completion text. The caller IP arrives with its last
 *                         octet masked ("x.y.z.***"), as Azure writes it.
 *  - defenderAiAlert      Microsoft Defender for Cloud — threat protection for AI services.
 *                         Alert display names / types are the documented AI.Azure_* set
 *                         (learn.microsoft.com › defender-for-cloud › alerts-ai-workloads).
 *                         Carries the full client IP and, with "user prompt evidence" on,
 *                         a redacted suspicious prompt segment.
 *  - azureActivity        Azure Activity Log control-plane operation (key listing, new
 *                         deployments) on the Cognitive Services account.
 *
 * Field naming follows the platform's existing Azure convention (azure.* / ECS), the same
 * shape as the other Defender for Cloud and Activity Log events in the feed.
 */
import type { TelemetryEvent, Severity, EventType, ExpectedVerdict } from "../types";
import { makeSha256 } from "@/lib/sim/iocs";

export interface AzureAiResource {
  subscriptionId: string;
  resourceGroup: string;
  account: string;           // Cognitive Services account name, e.g. "aoai-support-weu"
  region: string;            // e.g. "westeurope"
}

export interface GeoLite { country: string; iso: string; city: string; lat: number; lon: number }

const guid = (seed: string) => {
  const h = makeSha256(`guid:${seed}`);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-${(8 + (parseInt(h[16], 16) % 4)).toString(16)}${h.slice(17, 20)}-${h.slice(20, 32)}`;
};
const resourceId = (r: AzureAiResource) =>
  `/SUBSCRIPTIONS/${r.subscriptionId.toUpperCase()}/RESOURCEGROUPS/${r.resourceGroup.toUpperCase()}/PROVIDERS/MICROSOFT.COGNITIVESERVICES/ACCOUNTS/${r.account.toUpperCase()}`;
const maskIp = (ip: string) => ip.replace(/\.\d+$/, ".***");
const addMs = (ts: string, ms: number) => new Date(Date.parse(ts) + ms).toISOString();

const geoFields = (g?: GeoLite, asOrg?: string) => ({
  ...(g ? {
    "source.geo.country_name": g.country, "source.geo.country_iso_code": g.iso, "source.geo.city_name": g.city,
    "source.geo.location.lat": g.lat, "source.geo.location.lon": g.lon,
  } : {}),
  ...(asOrg ? { "source.as.organization.name": asOrg } : {}),
});

interface Common {
  id: string;
  ts: string;
  resource: AzureAiResource;
  severity?: Severity;
  mitre?: string;
  tactic?: string;
  description: string;
  expectedVerdict?: ExpectedVerdict;
  fpExplanation?: string;
  isBaseline?: boolean;
  user?: string;
}

const meta = (c: Common) => ({
  ...(c.mitre ? { mitre_technique: c.mitre } : {}), ...(c.tactic ? { mitre_tactic: c.tactic } : {}),
  ...(c.expectedVerdict ? { expected_verdict: c.expectedVerdict } : {}),
  ...(c.fpExplanation ? { fp_explanation: c.fpExplanation } : {}),
  ...(c.isBaseline ? { is_baseline: true } : {}),
});

// ── Azure OpenAI RequestResponse resource log ────────────────────────────────
export interface AzureOpenAiRequestOpts extends Common {
  callerIp: string;               // full IP (masked in the raw record)
  operation?: string;             // default ChatCompletions_Create
  deployment: string;             // modelDeploymentName
  model?: string;                 // default gpt-4o
  modelVersion?: string;          // default 2024-11-20
  status: 200 | 400 | 401 | 429;
  durationMs: number;
  requestLength: number;
  responseLength: number;
  stream?: boolean;
  apiVersion?: string;            // default 2025-01-01-preview
}

export function azureOpenAiRequest(o: AzureOpenAiRequestOpts): TelemetryEvent {
  const r = o.resource;
  const ok = o.status === 200;
  const reqTime = addMs(o.ts, -o.durationMs);
  return {
    id: o.id, ts: o.ts, source: "cloud_azure", vendor: "Azure OpenAI",
    event_type: "cloud_api_call" as EventType,
    severity: o.severity ?? (ok ? "informational" : "low"),
    user_email: o.user,
    description: o.description,
    ...meta(o),
    raw: {
      "@timestamp": o.ts,
      "azure.open_ai.category": "RequestResponse",
      "azure.open_ai.operation_name": o.operation ?? "ChatCompletions_Create",
      "azure.open_ai.result_signature": String(o.status),
      "azure.open_ai.duration_ms": o.durationMs,
      "azure.open_ai.caller_ip_address": maskIp(o.callerIp),
      "azure.open_ai.correlation_id": guid(`corr:${o.id}`),
      "azure.open_ai.event": "ShoeboxCallResult",
      "azure.open_ai.location": r.region,
      "azure.open_ai.properties.api_name": `Azure OpenAI API version ${o.apiVersion ?? "2025-01-01-preview"}`,
      "azure.open_ai.properties.request_time": reqTime,
      "azure.open_ai.properties.request_length": o.requestLength,
      "azure.open_ai.properties.response_time": o.ts,
      "azure.open_ai.properties.response_length": o.responseLength,
      "azure.open_ai.properties.model_deployment_name": o.deployment,
      "azure.open_ai.properties.model_name": o.model ?? "gpt-4o",
      "azure.open_ai.properties.model_version": o.modelVersion ?? "2024-11-20",
      "azure.open_ai.properties.stream_type": o.stream ? "Streaming" : "NonStreaming",
      "azure.resource.id": resourceId(r),
      "azure.resource.group": r.resourceGroup.toUpperCase(),
      "azure.resource.provider": "MICROSOFT.COGNITIVESERVICES/ACCOUNTS",
      "azure.resource.name": r.account.toUpperCase(),
      "azure.subscription_id": r.subscriptionId,
      "cloud.provider": "azure",
      "cloud.region": r.region,
      "event.kind": "event",
      "event.dataset": "azure_openai.logs",
      "event.action": o.operation ?? "ChatCompletions_Create",
      "event.category": ["web"],
      "event.outcome": ok ? "success" : "failure",
      "event.duration": o.durationMs * 1_000_000,
      "http.response.status_code": o.status,
    },
  };
}

// ── Microsoft Defender for Cloud — AI threat protection alert ────────────────
export const AI_ALERTS = {
  jailbreakBlocked: { name: "A Jailbreak attempt on an Azure AI model deployment was blocked by Azure AI Content Safety Prompt Shields", type: "AI.Azure_Jailbreak.ContentFiltering.BlockedAttempt", sev: "Medium", intent: "PrivilegeEscalation, DefenseEvasion" },
  jailbreakDetected: { name: "A Jailbreak attempt on an Azure AI model deployment was detected by Azure AI Content Safety Prompt Shields", type: "AI.Azure_Jailbreak.ContentFiltering.DetectedAttempt", sev: "Medium", intent: "PrivilegeEscalation, DefenseEvasion" },
  llmRecon: { name: "(Preview) LLM Reconnaissance Attempt Detected", type: "AI.Azure_LLMReconnaissance", sev: "Low", intent: "Reconnaissance" },
  suspiciousIp: { name: "Access from suspicious IP", type: "AI.Azure_AccessFromSuspiciousIP", sev: "High", intent: "Execution" },
  walletVolume: { name: "Suspected wallet attack - volume anomaly", type: "AI.Azure_DOWVolumeAnomaly", sev: "Medium", intent: "Impact" },
  accessAnomaly: { name: "Access anomaly in AI resource", type: "AI.Azure_AccessAnomaly", sev: "Medium", intent: "Execution, Reconnaissance, InitialAccess" },
} as const;

export interface DefenderAiAlertOpts extends Common {
  alert: keyof typeof AI_ALERTS;
  clientIp: string;
  geo?: GeoLite;
  asOrg?: string;
  deployment: string;
  alertDescription: string;
  promptSegment?: string;          // "Suspicious user prompt segment" (redacted evidence)
  extra?: Record<string, string>;  // further extended properties
  startTs?: string;                // first activity covered by the alert
  /**
   * End-user security context the calling application passes with each request (user_security_context:
   * end-user id, source IP, application name). With it, the alert names the person behind an app's
   * request and carries their address as the IP entity; "Client IP address" stays the app's own.
   */
  endUser?: { id: string; ip: string; app: string };
}

export function defenderAiAlert(o: DefenderAiAlertOpts): TelemetryEvent {
  const a = AI_ALERTS[o.alert];
  const r = o.resource;
  const alertId = guid(`dfc:${o.id}`);
  const sev: Severity = a.sev === "High" ? "high" : a.sev === "Medium" ? "medium" : "low";
  return {
    id: o.id, ts: o.ts, source: "cloud_azure", vendor: "Microsoft Defender for Cloud",
    event_type: "cloud_api_call" as EventType,
    severity: o.severity ?? sev,
    src_ip: o.endUser?.ip ?? o.clientIp,
    user_email: o.user,
    is_detection: true,
    description: o.description,
    ...meta(o),
    raw: {
      "@timestamp": o.ts,
      "azure.alert.displayName": a.name,
      "azure.alert.alertType": a.type,
      "azure.alert.severity": a.sev,
      "azure.alert.status": "Active",
      "azure.alert.intent": a.intent,
      "azure.alert.description": o.alertDescription,
      "azure.alert.compromisedEntity": r.account,
      "azure.alert.productName": "Microsoft Defender for Cloud",
      "azure.alert.vendorName": "Microsoft",
      "azure.alert.systemAlertId": alertId,
      "azure.alert.startTimeUtc": o.startTs ?? o.ts,
      "azure.alert.endTimeUtc": o.ts,
      "azure.alert.timeGeneratedUtc": addMs(o.ts, 94_000),
      "azure.alert.extendedProperties.Model deployment name": o.deployment,
      "azure.alert.extendedProperties.Azure AI resource": r.account,
      "azure.alert.extendedProperties.Client IP address": o.clientIp,
      ...(o.endUser ? {
        "azure.alert.extendedProperties.End user ID": o.endUser.id,
        "azure.alert.extendedProperties.End user IP address": o.endUser.ip,
        "azure.alert.extendedProperties.Application name": o.endUser.app,
      } : {}),
      ...(o.promptSegment ? { "azure.alert.extendedProperties.Suspicious user prompt segment": o.promptSegment } : {}),
      ...Object.fromEntries(Object.entries(o.extra ?? {}).map(([k, v]) => [`azure.alert.extendedProperties.${k}`, v])),
      "azure.subscription_id": r.subscriptionId,
      "azure.resource.id": resourceId(r),
      "azure.resource.group": r.resourceGroup,
      "azure.resource.provider": "MICROSOFT.COGNITIVESERVICES",
      "azure.resource.name": r.account,
      "cloud.provider": "azure",
      "cloud.region": r.region,
      "event.kind": "alert",
      "event.action": a.type,
      "event.category": ["intrusion_detection"],
      "event.outcome": "success",
      "source.ip": o.endUser?.ip ?? o.clientIp,
      ...geoFields(o.geo, o.asOrg),
    },
  };
}

// ── Azure Activity Log operation on the AI account ───────────────────────────
export interface AzureActivityOpts extends Common {
  operation: string;               // e.g. MICROSOFT.COGNITIVESERVICES/ACCOUNTS/LISTKEYS/ACTION
  caller: string;                  // UPN
  callerIp: string;
  geo?: GeoLite;
  asOrg?: string;
  subResource?: string;            // e.g. "deployments/gpt-4o-2"
  category?: "Administrative";
}

export function azureActivity(o: AzureActivityOpts): TelemetryEvent {
  const r = o.resource;
  const rid = resourceId(r) + (o.subResource ? `/${o.subResource.toUpperCase()}` : "");
  const corr = guid(`act:${o.id}`);
  return {
    id: o.id, ts: o.ts, source: "cloud_azure", vendor: "Azure Activity Log",
    event_type: "cloud_api_call" as EventType,
    severity: o.severity ?? "low",
    user_email: o.caller,
    src_ip: o.callerIp,
    description: o.description,
    ...meta(o),
    raw: {
      "@timestamp": o.ts,
      "azure.activitylogs.operationName": o.operation,
      "azure.activitylogs.event_category": o.category ?? "Administrative",
      "azure.activitylogs.resultType": "Success",
      "azure.activitylogs.resultSignature": "Succeeded.OK",
      "azure.activitylogs.level": "Information",
      "azure.activitylogs.callerIpAddress": o.callerIp,
      "azure.activitylogs.identity.claims_initiated_by_user.name": o.caller,
      "azure.activitylogs.identity.authorization.evidence.role": "Cognitive Services Contributor",
      "azure.activitylogs.identity.authorization.scope": rid.toLowerCase(),
      "azure.correlation_id": corr,
      "azure.resource.id": rid,
      "azure.resource.group": r.resourceGroup.toUpperCase(),
      "azure.resource.provider": "MICROSOFT.COGNITIVESERVICES",
      "azure.resource.name": r.account.toUpperCase(),
      "azure.subscription_id": r.subscriptionId,
      "cloud.provider": "azure",
      "cloud.region": r.region,
      "event.kind": "event",
      "event.action": o.operation,
      "event.category": ["configuration"],
      "event.outcome": "success",
      "user.name": o.caller,
      "source.ip": o.callerIp,
      ...geoFields(o.geo, o.asOrg),
    },
  };
}
