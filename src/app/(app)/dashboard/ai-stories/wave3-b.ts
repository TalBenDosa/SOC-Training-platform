/**
 * AI-related attack stories — wave 3 part B (live feed & team training). Two prompt-injection
 * stories, both grounded in what Microsoft's own products record:
 *
 *  1. ai-rag-chatbot-document-injection  (core, nexacorp/medcore) — a customer-facing assistant
 *     built on Azure OpenAI retrieves over customer-uploaded documents. An attacker uploads a
 *     document that carries hidden instructions (indirect prompt injection, OWASP LLM01). When
 *     the assistant later summarises that document, it tries to pull internal knowledge-base text
 *     and its responses grow abnormally large. Telemetry: Azure Storage blob logs (the user delegation
 *     key the app signs upload links with, the upload, the app's reads), Azure OpenAI RequestResponse
 *     logs, the app's Prompt Shields calls as its API Management gateway logs them (documentsAnalysis
 *     attackDetected), a Microsoft Defender for Cloud AI alert (AI.Azure_ASCIISmuggling), and a
 *     Sentinel correlation. The chat is anonymous: end users appear only as the app's opaque ids.
 *
 *  2. ai-stored-injection-copilot-kb     (core, nexacorp/quantumbank) — a compromised account edits
 *     an internal SharePoint knowledge-base page that Microsoft 365 Copilot cites, planting hidden
 *     instructions that make Copilot hand back a changed vendor bank account for payment questions.
 *     A finance user asks Copilot, gets the poisoned answer and starts a payment change. Telemetry:
 *     the compromised Entra sign-in, the SharePoint FileModified audit, the Purview CopilotInteraction
 *     record naming the page as an accessed resource (JailbreakDetected / XPIADetected false — the
 *     stored injection was not caught in-line), the payment-change email, and a Sentinel correlation.
 *
 * Real schemas, each verified against vendor documentation:
 *  - Azure Storage StorageBlobLogs columns (OperationName / CallerIpAddress / AuthenticationType /
 *    ObjectKey / StatusCode / RequestBodySize …) — learn.microsoft.com azure-monitor StorageBlobLogs.
 *  - Azure OpenAI RequestResponse resource log (azure.open_ai.*) via the shared emitter — no prompt text.
 *  - Azure AI Content Safety Prompt Shields response (userPromptAnalysis / documentsAnalysis[].attackDetected,
 *    learn.microsoft.com azure/ai-services/content-safety quickstart-jailbreak), in the backend response body
 *    of the API Management gateway log (ApiManagementGatewayLogs). Content Safety's own resource log has no
 *    verdict. No document or prompt text is logged.
 *  - Microsoft Defender for Cloud AI alert names (AI.Azure_ASCIISmuggling — "ASCII Smuggling prompt
 *    injection detected", High, Impact; commonly attributed to indirect prompt injection) —
 *    learn.microsoft.com defender-for-cloud alerts-ai-workloads.
 *  - Purview CopilotInteraction (RecordType 261, CopilotEventData.Messages[].JailbreakDetected,
 *    AccessedResources[].{Action,Id,Name,SiteUrl,Type,SensitivityLabelId,Status,XPIADetected}) —
 *    learn.microsoft.com office-365-management-api copilot-schema + purview audit-copilot.
 *
 * No working exploit payloads, malware or step-by-step procedures: the injection text appears only
 * as the short, generic instruction a defender's log would record. ATT&CK v19 IDs/tactics throughout.
 */
import type { TelemetryEvent, Severity } from "@/lib/sim/types";
import type { AiStoryDef } from "./wave2";
import { entraSignIn } from "@/lib/sim/emitters/entra";
import { m365Operation } from "@/lib/sim/emitters/m365";
import { azureOpenAiRequest, type AzureAiResource, type GeoLite } from "@/lib/sim/emitters/azureAi";
import { makeSha256 } from "@/lib/sim/iocs";
import { makeCtx } from "@/lib/logs/native/ctx";

// ── small deterministic helpers (self-contained; no shared-file edits) ──────────
const guid = (seed: string): string => {
  const h = makeSha256(`w3b:${seed}`);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-${(8 + (parseInt(h[16], 16) % 4)).toString(16)}${h.slice(17, 20)}-${h.slice(20, 32)}`;
};
const addMs = (ts: string, ms: number): string => new Date(Date.parse(ts) + ms).toISOString();

// ══════════════════════════════════════════════════════════════════════════════
// 1. ai-rag-chatbot-document-injection — core (nexacorp / medcore)
// ══════════════════════════════════════════════════════════════════════════════

// Authored on NexaCorp's own subscription and tenant; instantiateStory re-keys both per company.
const AOAI: AzureAiResource = {
  subscriptionId: makeCtx("nexacorp").tenant.azureSubscriptionId,
  resourceGroup: "rg-ai-prod", account: "aoai-assist-weu", region: "westeurope",
};
const RAG_TENANT_ID = makeCtx("nexacorp").tenant.azureTenantId;
const ASSIST_DEPLOYMENT = "gpt-4o-assist";
const APP_EGRESS = "198.51.100.84";          // the assistant app's App Service outbound address (Azure, West Europe)
const APIM_EGRESS = "198.51.100.86";         // the API Management gateway in front of Azure OpenAI and Content Safety
const APIM_NAME = "apim-assist-weu";
const CONTENT_SAFETY = "cs-assist-weu";      // the Azure AI Content Safety resource the app calls before grounding
const STORAGE_ACCOUNT = "stassistuploads";   // the blob account the RAG app ingests uploads from
const UPLOAD_CONTAINER = "rag-uploads";
const DOC_NAME = "acme-vendor-quote-2026.pdf";
const DOC_BLOB = `${UPLOAD_CONTAINER}/${DOC_NAME}`;
/** The assistant app's system-assigned managed identity: object id and client (application) id. */
const APP_MI_OID = guid("app:managed-identity");
const APP_MI_APPID = guid("app:managed-identity:client");
/** Built-in roles the managed identity holds on the storage account (Azure built-in role ids). */
const ROLE_BLOB_READER = "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1";   // Storage Blob Data Reader
const ROLE_BLOB_DELEGATOR = "db58b8e5-c6ad-4a2a-8342-4190687cbf4a"; // Storage Blob Delegator

/**
 * Azure Storage blob service diagnostic log (Azure Monitor StorageBlobLogs, categories StorageRead /
 * StorageWrite). Real column names; CallerIpAddress carries the client port, as the table writes it.
 *  - GetUserDelegationKey: the app's managed identity (OAuth) asks for a user delegation key, the key
 *    it signs the upload SAS with. AuthorizationDetails names the RBAC action that allowed it.
 *  - PutBlob with that SAS (AuthenticationType DelegationSas): the customer's browser writes straight
 *    to the container; the row names the identity the SAS was delegated from (RequesterObjectId).
 *  - GetBlob (OAuth): the app reads the document with its managed identity to index or cite it.
 * No file content.
 */
function blobLog(o: {
  id: string; ts: string; operation: "PutBlob" | "GetBlob" | "GetUserDelegationKey"; callerIp: string; callerPort: number;
  auth: "DelegationSas" | "OAuth"; status: 200 | 201; bytes: number; durationMs: number; serverMs: number;
  geo?: GeoLite; asOrg?: string; userAgent: string;
  severity: Severity; description: string; mitre?: string; tactic?: string;
  expectedVerdict?: TelemetryEvent["expected_verdict"]; fpExplanation?: string; isBaseline?: boolean;
}): TelemetryEvent {
  const statusText = o.status === 201 ? "Created" : "Success";
  const service = o.operation === "GetUserDelegationKey";
  const uri = service
    ? `https://${STORAGE_ACCOUNT}.blob.core.windows.net/?restype=service&comp=userdelegationkey`
    : `https://${STORAGE_ACCOUNT}.blob.core.windows.net/${DOC_BLOB}`;
  const oauth = o.auth === "OAuth";
  const action = service ? "Microsoft.Storage/storageAccounts/blobServices/generateUserDelegationKey/action" : "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read";
  const role = service ? ROLE_BLOB_DELEGATOR : ROLE_BLOB_READER;
  const scope = `/subscriptions/${AOAI.subscriptionId}/resourceGroups/rg-ai-data/providers/Microsoft.Storage/storageAccounts/${STORAGE_ACCOUNT}`;
  return {
    id: o.id, ts: o.ts, source: "cloud_azure", vendor: "Azure Blob Storage", event_type: "cloud_storage_access",
    severity: o.severity, src_ip: o.callerIp,
    ...(o.geo ? { geo: { country: o.geo.country, city: o.geo.city, latitude: o.geo.lat, longitude: o.geo.lon } } : {}),
    ...(o.mitre ? { mitre_technique: o.mitre } : {}), ...(o.tactic ? { mitre_tactic: o.tactic } : {}),
    ...(o.expectedVerdict ? { expected_verdict: o.expectedVerdict } : {}),
    ...(o.fpExplanation ? { fp_explanation: o.fpExplanation } : {}),
    ...(o.isBaseline ? { is_baseline: true } : {}),
    ...(service ? {} : { file: { name: DOC_NAME, path: DOC_BLOB, size: o.bytes, extension: "pdf" } }),
    description: o.description,
    raw: {
      "TimeGenerated": o.ts,
      "AccountName": STORAGE_ACCOUNT,
      "Category": o.operation === "PutBlob" ? "StorageWrite" : "StorageRead",
      "OperationName": o.operation,
      "OperationVersion": "2022-11-02",
      "StatusCode": String(o.status),
      "StatusText": statusText,
      "DurationMs": o.durationMs,
      "ServerLatencyMs": o.serverMs,
      "CallerIpAddress": `${o.callerIp}:${o.callerPort}`,
      "AuthenticationType": o.auth,
      // The OAuth caller, or for a user delegation SAS the identity whose key signed it.
      "RequesterObjectId": APP_MI_OID,
      "RequesterTenantId": RAG_TENANT_ID,
      ...(oauth ? {
        "RequesterAppId": APP_MI_APPID,
        "RequesterAudience": "https://storage.azure.com/",
        "RequesterTokenIssuer": `https://sts.windows.net/${RAG_TENANT_ID}/`,
        "AuthorizationDetails": [{
          action, roleAssignmentId: guid(`ra:${role}`), roleDefinitionId: role, principals: [{ id: APP_MI_OID, type: "ServicePrincipal" }],
          type: "RBAC", result: "Granted", reason: "MatchedAllowAssignment", scope,
        }],
      } : {}),
      "Uri": uri,
      "ObjectKey": service ? `"/${STORAGE_ACCOUNT}"` : `"/${STORAGE_ACCOUNT}/${DOC_BLOB}"`,
      "UserAgentHeader": `"${o.userAgent}"`,
      "RequestBodySize": o.operation === "PutBlob" ? o.bytes : service ? 132 : 0,
      "ResponseBodySize": o.operation === "PutBlob" ? 0 : service ? 518 : o.bytes,
      "ContentLengthHeader": o.operation === "PutBlob" ? o.bytes : service ? 132 : 0,
      "ServiceType": "blob",
      "Protocol": "HTTPS",
      "TlsVersion": "TLS 1.3",
      "CorrelationId": guid(`blobcorr:${o.id}`),
      "Location": AOAI.region,
      "SchemaVersion": "1.0",
      "Type": "StorageBlobLogs",
      "_ResourceId": `${scope}/blobServices/default`,
      "cloud.provider": "azure",
      "cloud.region": AOAI.region,
      "source.ip": o.callerIp,
    },
  };
}

/**
 * The app runs Azure AI Content Safety Prompt Shields over each retrieved document before it grounds a
 * completion on it, through its API Management gateway. The gateway log (ApiManagementGatewayLogs,
 * backend response body logging on) is where the verdict is recorded: the Prompt Shields response
 * `{"userPromptAnalysis":{"attackDetected":…},"documentsAnalysis":[{"attackDetected":…}]}`. Content
 * Safety's own resource log carries no verdict. The app only logs the verdict and goes on (no block):
 * the completion still runs. No document text is logged.
 */
function shieldPromptCall(o: {
  id: string; ts: string; documentAttack: boolean; requestSize: number; totalMs: number;
  severity: Severity; description: string; mitre?: string; tactic?: string;
  expectedVerdict?: TelemetryEvent["expected_verdict"]; fpExplanation?: string; isBaseline?: boolean;
}): TelemetryEvent {
  const body = `{"userPromptAnalysis":{"attackDetected":false},"documentsAnalysis":[{"attackDetected":${o.documentAttack}}]}`;
  return {
    id: o.id, ts: o.ts, source: "cloud_azure", vendor: "Azure API Management", event_type: "http_request", severity: o.severity,
    src_ip: APP_EGRESS,
    ...(o.mitre ? { mitre_technique: o.mitre } : {}), ...(o.tactic ? { mitre_tactic: o.tactic } : {}),
    ...(o.expectedVerdict ? { expected_verdict: o.expectedVerdict } : {}),
    ...(o.fpExplanation ? { fp_explanation: o.fpExplanation } : {}),
    ...(o.isBaseline ? { is_baseline: true } : {}),
    description: o.description,
    raw: {
      TimeGenerated: o.ts,
      Type: "ApiManagementGatewayLogs",
      _ResourceId: `/subscriptions/${AOAI.subscriptionId}/resourcegroups/${AOAI.resourceGroup}/providers/microsoft.apimanagement/service/${APIM_NAME}`,
      ApimSubscriptionId: "assist-support-chat",
      ApiId: "content-safety",
      OperationId: "shieldPrompt",
      Method: "POST",
      Url: `https://${APIM_NAME}.azure-api.net/contentsafety/text:shieldPrompt?api-version=2024-09-01`,
      BackendUrl: `https://${CONTENT_SAFETY}.cognitiveservices.azure.com/contentsafety/text:shieldPrompt?api-version=2024-09-01`,
      CallerIpAddress: APP_EGRESS,
      ResponseCode: 200,
      BackendResponseCode: 200,
      IsRequestSuccess: true,
      RequestSize: o.requestSize,
      ResponseSize: 412 + body.length,
      BackendTime: o.totalMs - 14,
      TotalTime: o.totalMs,
      BackendResponseBody: body,
      CorrelationId: makeSha256(`apim:${o.id}`).slice(0, 32),
      Region: "West Europe",
    },
  };
}

/**
 * Microsoft Defender for Cloud — AI threat protection alert, in the same raw shape the shared
 * defenderAiAlert emitter renders, but for AI.Azure_ASCIISmuggling (not in the emitter's fixed
 * alert set). "ASCII Smuggling prompt injection detected" is the documented alert for indirect
 * prompt injection via hidden instructions (High, Impact). azure.alert.* is rendered natively by
 * the azure_activity card. startTimeUtc / endTimeUtc are the first and last request it covers.
 */
function defenderAsciiSmuggling(o: {
  id: string; ts: string; clientIp: string; geo: GeoLite; asOrg?: string; deployment: string;
  endUser: { id: string; ip: string; app: string }; evidenceDoc: string;
  severity: Severity; description: string; mitre: string; tactic: string; startTs: string; endTs: string;
}): TelemetryEvent {
  const r = AOAI;
  const resId = `/SUBSCRIPTIONS/${r.subscriptionId.toUpperCase()}/RESOURCEGROUPS/${r.resourceGroup.toUpperCase()}/PROVIDERS/MICROSOFT.COGNITIVESERVICES/ACCOUNTS/${r.account.toUpperCase()}`;
  return {
    id: o.id, ts: o.ts, source: "cloud_azure", vendor: "Microsoft Defender for Cloud", event_type: "cloud_api_call",
    severity: o.severity, is_detection: true, src_ip: o.endUser.ip,
    geo: { country: o.geo.country, city: o.geo.city, latitude: o.geo.lat, longitude: o.geo.lon },
    mitre_technique: o.mitre, mitre_tactic: o.tactic,
    description: o.description,
    raw: {
      "@timestamp": o.ts,
      "azure.alert.displayName": "ASCII Smuggling prompt injection detected",
      "azure.alert.alertType": "AI.Azure_ASCIISmuggling",
      "azure.alert.severity": "High",
      "azure.alert.status": "Active",
      "azure.alert.intent": "Impact",
      "azure.alert.description": "An ASCII smuggling technique was used to pass hidden instructions to the AI model. This technique is commonly attributed to indirect prompt injection, where hidden instructions are carried inside content the model processes.",
      "azure.alert.compromisedEntity": r.account,
      "azure.alert.productName": "Microsoft Defender for Cloud",
      "azure.alert.vendorName": "Microsoft",
      "azure.alert.systemAlertId": guid(`dfc:${o.id}`),
      "azure.alert.startTimeUtc": o.startTs,
      "azure.alert.endTimeUtc": o.endTs,
      "azure.alert.timeGeneratedUtc": addMs(o.ts, 92_000),
      "azure.alert.extendedProperties.Model deployment name": o.deployment,
      "azure.alert.extendedProperties.Azure AI resource": r.account,
      "azure.alert.extendedProperties.Client IP address": o.clientIp,
      "azure.alert.extendedProperties.End user ID": o.endUser.id,
      "azure.alert.extendedProperties.End user IP address": o.endUser.ip,
      "azure.alert.extendedProperties.Application name": o.endUser.app,
      "azure.alert.extendedProperties.Grounding document": o.evidenceDoc,
      "azure.subscription_id": r.subscriptionId,
      "azure.resource.id": resId,
      "azure.resource.group": r.resourceGroup,
      "azure.resource.provider": "MICROSOFT.COGNITIVESERVICES",
      "azure.resource.name": r.account,
      "cloud.provider": "azure",
      "cloud.region": r.region,
      "event.kind": "alert",
      "event.action": "AI.Azure_ASCIISmuggling",
      "event.category": ["intrusion_detection"],
      "event.outcome": "success",
      "source.ip": o.endUser.ip,
      "source.geo.country_name": o.geo.country,
      "source.geo.country_iso_code": o.geo.iso,
      "source.geo.city_name": o.geo.city,
      ...(o.asOrg ? { "source.as.organization.name": o.asOrg } : {}),
    },
  };
}

function buildRagDocumentInjection(): TelemetryEvent[] {
  const attackerIp = "203.0.113.47";
  const attackerGeo: GeoLite = { country: "Germany", iso: "DE", city: "Frankfurt am Main", lat: 50.1109, lon: 8.6821 };
  const asOrg = "Hostwinds LLC";
  // The chat is anonymous: the app names an end user only by its own opaque id, never an employee.
  const uploaderEndUser = "assist-enduser-2604";   // the uploader's own later chat session
  const browserUa = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36";
  const appUa = "azsdk-net-Storage.Blobs/12.22.2 (.NET 8.0.11; Microsoft Windows 10.0.20348)";
  // The model sees the gateway's address (masked by Azure to x.y.z.***), and the app signs in with its managed identity.
  const req = { resource: AOAI, deployment: ASSIST_DEPLOYMENT, callerIp: APIM_EGRESS, objectId: APP_MI_OID };
  const upload = "2026-09-28T10:41:52.370Z";
  const lastBig = "2026-09-28T13:50:31.675Z";

  return [
    // 1. BASELINE: the app checks a customer's document with Prompt Shields, then summarises it.
    shieldPromptCall({
      id: "airag1c", ts: "2026-09-28T09:03:09.236Z", documentAttack: false, requestSize: 18_420, totalMs: 188, severity: "informational",
      isBaseline: true, expectedVerdict: "fp",
      fpExplanation: "Routine document check before grounding: Prompt Shields found no attack in the user prompt or the document.",
      description: "API Management logged the assistant app's Prompt Shields call (text:shieldPrompt) to cs-assist-weu: HTTP 200 in 188 ms; the response reports attackDetected false for the user prompt and for the one document.",
    }),
    azureOpenAiRequest({
      ...req, id: "airag1", ts: "2026-09-28T09:03:11.204Z", status: 200,
      durationMs: 1760, requestLength: 3100, responseLength: 1480, isBaseline: true, expectedVerdict: "fp",
      fpExplanation: "Normal assistant traffic: the app's managed identity through its gateway, HTTP 200, request and response sizes in the usual range.",
      description: "Azure OpenAI logged a chat completion on the gpt-4o-assist deployment from the assistant's API gateway with the app's managed identity: HTTP 200, 3.1 KB in, 1.5 KB out.",
    }),

    // 2. THE SAS: the app's managed identity gets a user delegation key to sign the customer's upload link.
    blobLog({
      id: "airag1b", ts: "2026-09-28T10:41:49.902Z", operation: "GetUserDelegationKey", callerIp: APP_EGRESS, callerPort: 50412,
      auth: "OAuth", status: 200, bytes: 0, durationMs: 21, serverMs: 17, userAgent: appUa, severity: "informational",
      description: "Azure Storage logged GetUserDelegationKey on stassistuploads by the assistant app's managed identity (OAuth, RBAC generateUserDelegationKey granted): the key the app signs customer upload links with.",
    }),

    // 3. THE UPLOAD: a customer uploads a document straight to blob storage with the delegation SAS the app issued.
    blobLog({
      id: "airag2", ts: upload, operation: "PutBlob", callerIp: attackerIp, callerPort: 52114,
      auth: "DelegationSas", status: 201, bytes: 24180, durationMs: 142, serverMs: 118, geo: attackerGeo, asOrg, userAgent: browserUa,
      severity: "low", mitre: "T1565.001", tactic: "Impact",
      description: "Azure Storage logged a PutBlob on the rag-uploads container: acme-vendor-quote-2026.pdf (24 KB) uploaded from 203.0.113.47 (Frankfurt, Hostwinds) with a user delegation SAS signed by the app's managed identity, HTTP 201. The customer-facing assistant ingests this container; the address has no earlier upload.",
    }),

    // 4. INGESTION: the app reads the blob and embeds it (RAG indexing). Benign-looking.
    blobLog({
      id: "airag3", ts: "2026-09-28T10:42:09.880Z", operation: "GetBlob", callerIp: APP_EGRESS, callerPort: 50431,
      auth: "OAuth", status: 200, bytes: 24180, durationMs: 60, serverMs: 41, userAgent: appUa, severity: "informational",
      description: "17 seconds later the assistant app read the same blob with its managed identity (OAuth) to index it for retrieval: GetBlob, HTTP 200, same ObjectKey as the upload.",
    }),

    // 5. THE DOCUMENT-ATTACK SIGNAL: a later customer's question grounds on the document; Prompt Shields flags it, the app goes on.
    shieldPromptCall({
      id: "airag5", ts: "2026-09-28T13:21:57.180Z", documentAttack: true, requestSize: 26_912, totalMs: 214, severity: "medium",
      mitre: "T1565.001", tactic: "Impact",
      description: "API Management logged the assistant app's Prompt Shields call (text:shieldPrompt) to cs-assist-weu before a completion: HTTP 200 in 214 ms; the response reports attackDetected false for the user prompt and true for the retrieved document.",
    }),

    // 6. FIRST SIGN: the same request's completion; the response is abnormally large.
    azureOpenAiRequest({
      ...req, id: "airag4", ts: "2026-09-28T13:22:04.512Z", status: 200,
      durationMs: 7120, requestLength: 4200, responseLength: 9820, severity: "medium",
      mitre: "T1213", tactic: "Collection",
      description: "Azure OpenAI logged a chat completion on gpt-4o-assist through the gateway seven seconds later with a 9.8 KB response, about six times the assistant's usual output size.",
    }),

    // 7. THE APP READS THE FLAGGED BLOB AGAIN: to cite it for a new session.
    blobLog({
      id: "airag6", ts: "2026-09-28T13:48:37.115Z", operation: "GetBlob", callerIp: APP_EGRESS, callerPort: 51077,
      auth: "OAuth", status: 200, bytes: 24180, durationMs: 58, serverMs: 39, userAgent: appUa, severity: "low", mitre: "T1213", tactic: "Collection",
      description: "The assistant app read acme-vendor-quote-2026.pdf again from its managed identity (GetBlob, HTTP 200) while serving a new session, the same ObjectKey the earlier Prompt Shields check flagged.",
    }),

    // 8. THE SAME SEQUENCE, LARGER: the uploader's own session pulls the document; the response balloons.
    azureOpenAiRequest({
      ...req, id: "airag8", ts: lastBig, status: 200,
      durationMs: 11240, requestLength: 4600, responseLength: 15240, stream: true, severity: "high",
      mitre: "T1213", tactic: "Collection",
      description: "A streamed completion on gpt-4o-assist through the gateway returned 15.2 KB, roughly ten times the assistant's baseline output, two minutes after the second read of the flagged document.",
    }),

    // 9. THE DEFENDER ALERT: hidden instructions through grounded content, named to the resource and the end user.
    defenderAsciiSmuggling({
      id: "airag7", ts: "2026-09-28T13:51:48.233Z", clientIp: APP_EGRESS, geo: attackerGeo, asOrg,
      deployment: ASSIST_DEPLOYMENT, endUser: { id: uploaderEndUser, ip: attackerIp, app: "assist-support-chat" },
      evidenceDoc: DOC_NAME, severity: "high", mitre: "T1565.001", tactic: "Impact", startTs: "2026-09-28T13:21:57.392Z", endTs: lastBig,
      description: "Microsoft Defender for Cloud raised 'ASCII Smuggling prompt injection detected' (AI.Azure_ASCIISmuggling, High) on aoai-assist-weu: hidden instructions were passed to gpt-4o-assist through grounded content. The app's security context names end user assist-enduser-2604 at 203.0.113.47 (Frankfurt) and the grounding document acme-vendor-quote-2026.pdf.",
    }),

    // 10. THE SOC CORRELATION: Sentinel ties the upload, the Prompt Shields verdict, the Defender alert and the oversized responses.
    {
      id: "airag9", ts: "2026-09-28T14:06:33.418Z", source: "siem", vendor: "Microsoft Sentinel", event_type: "cloud_api_call",
      severity: "high", is_detection: true, src_ip: attackerIp, mitre_technique: "T1565.001", mitre_tactic: "Impact",
      geo: { country: attackerGeo.country, city: attackerGeo.city, latitude: attackerGeo.lat, longitude: attackerGeo.lon },
      description: "Microsoft Sentinel raised 'Indirect prompt injection on Azure OpenAI with oversized responses' (High): the document acme-vendor-quote-2026.pdf uploaded from 203.0.113.47 was flagged by Prompt Shields as a document attack, Defender for Cloud raised AI.Azure_ASCIISmuggling for gpt-4o-assist, and completions grounding on that document returned 9.8-15.2 KB against a ~1.5 KB baseline.",
      raw: {
        "TimeGenerated": "2026-09-28T14:06:33.418Z",
        "TenantId": RAG_TENANT_ID,
        "AlertName": "Indirect prompt injection on Azure OpenAI with oversized responses",
        "DisplayName": "Indirect prompt injection on Azure OpenAI with oversized responses",
        "AlertSeverity": "High",
        "ProductName": "Azure Sentinel",
        "ProviderName": "ASI Scheduled Alerts",
        "ProductComponentName": "Scheduled Alerts",
        "VendorName": "Microsoft",
        "SystemAlertId": guid("sentinel:airag9"),
        "Status": "New",
        // The span of the rows the rule matched: the upload, then the last oversized completion.
        "StartTime": upload,
        "EndTime": lastBig,
        "ProcessingEndTime": "2026-09-28T14:06:33.418Z",
        "Tactics": "Impact, Collection",
        "Techniques": "[\"T1565\",\"T1213\"]",
        "CompromisedEntity": AOAI.account,
        "Description": "Correlates a Prompt Shields document attack (documentsAnalysis attackDetected true) logged by the API gateway and a Defender for Cloud AI.Azure_ASCIISmuggling alert on the same Azure OpenAI deployment with Azure OpenAI RequestResponse logs whose responseLength is far above the deployment baseline, and with the StorageBlobLogs PutBlob of the grounding document.",
        "ExtendedProperties.Azure OpenAI deployment": ASSIST_DEPLOYMENT,
        "ExtendedProperties.Grounding document": DOC_NAME,
        "ExtendedProperties.Upload caller IP": attackerIp,
        "ExtendedProperties.Upload authentication": "DelegationSas",
        "ExtendedProperties.Prompt Shields result": "documentsAnalysis attackDetected true",
        "ExtendedProperties.Defender alert": "AI.Azure_ASCIISmuggling",
        "ExtendedProperties.Max response length": "15240",
        "Entities": JSON.stringify([
          { $id: "2", Type: "azure-resource", ResourceId: `/subscriptions/${AOAI.subscriptionId}/resourceGroups/${AOAI.resourceGroup}/providers/Microsoft.CognitiveServices/accounts/${AOAI.account}` },
          { $id: "3", Type: "ip", Address: attackerIp },
          { $id: "4", Type: "file", Name: DOC_NAME, Directory: `/${STORAGE_ACCOUNT}/${UPLOAD_CONTAINER}` },
        ]),
        "event.kind": "alert",
        "event.action": "SecurityAlert",
      },
    },
  ];
}

// ══════════════════════════════════════════════════════════════════════════════
// 2. ai-stored-injection-copilot-kb — core (nexacorp / quantumbank)
// ══════════════════════════════════════════════════════════════════════════════

const KB_TENANT_ID = makeCtx("nexacorp").tenant.azureTenantId;
const KB_SITE = "https://nexacorp.sharepoint.com/sites/Finance-Operations/";
const KB_PAGE = "Vendor-Payment-Instructions.aspx";
const KB_PAGE_REL = "SitePages/Vendor-Payment-Instructions.aspx";
const FINANCE_USER = "r.avraham@nexacorp.com";        // asks Copilot, starts the payment change
const FINANCE_USER2 = "j.chen@nexacorp.com";          // a second finance user Copilot also answers
const COMPROMISED = "m.levi@nexacorp.com";            // the account used to edit the KB page
const OFFICE_IP = "198.51.100.8";                      // NexaCorp London office egress
const OFFICE_GEO = { country: "United Kingdom", iso: "GB", city: "London", lat: 51.5074, lon: -0.1278 };
const ATTACKER_IP = "198.51.100.66";                  // hosting / VPN address the compromised sign-in came from
const ATTACKER_GEO = { country: "Germany", iso: "DE", city: "Falkenstein", lat: 50.4779, lon: 12.3713 };
const EDGE_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0";

interface CpRes { name: string; type: string; site?: string; label?: string }
/**
 * Purview CopilotInteraction audit record (RecordType 261). CopilotEventData.Messages carries the
 * JailbreakDetected flag on the prompt; AccessedResources names each file/page Copilot read, with
 * XPIADetected per resource. Both flags are false here: the stored injection lives in a trusted
 * internal page and was not caught in-line — the record's value to the analyst is that it names the
 * poisoned page as the resource that grounded the answer. No prompt or response text.
 */
function kbCopilot(o: {
  id: string; ts: string; user: string; threadId: string; resources: CpRes[];
  severity: Severity; description: string; isBaseline?: boolean; mitre?: string; tactic?: string;
}): TelemetryEvent {
  const t = Date.parse(o.ts);
  const bare = o.user.split("@")[0];
  return {
    id: o.id, ts: o.ts, source: "o365", vendor: "Microsoft Purview", event_type: "cloud_api_call",
    severity: o.severity, user_email: o.user, src_ip: OFFICE_IP,
    geo: { country: OFFICE_GEO.country, city: OFFICE_GEO.city },
    ...(o.mitre ? { mitre_technique: o.mitre, mitre_tactic: o.tactic } : {}),
    ...(o.isBaseline ? { is_baseline: true, expected_verdict: "informational" as const } : {}),
    description: o.description,
    raw: {
      "data.office365.Id": guid(`ci:${o.id}`),
      "data.office365.CreationTime": o.ts.replace(/\.\d{3}Z$/, ""),
      "data.office365.Operation": "CopilotInteraction",
      "data.office365.RecordType": "261",
      "data.office365.Workload": "Copilot",
      "data.office365.OrganizationId": KB_TENANT_ID,
      "data.office365.UserId": o.user,
      "data.office365.UserKey": guid(`userkey:${o.user}`),
      "data.office365.UserType": "0",
      "data.office365.ClientIP": OFFICE_IP,
      "data.office365.AppIdentity": "Copilot.MicrosoftCopilot.BizChat",
      "data.office365.CopilotEventData.AppHost": "BizChat",
      "data.office365.CopilotEventData.ThreadId": o.threadId,
      "data.office365.CopilotEventData.Messages": [
        { Id: String(t), isPrompt: true, JailbreakDetected: false },
        { Id: String(t + 1142), isPrompt: false },
      ],
      "data.office365.CopilotEventData.AccessedResources": o.resources.map(r => ({
        Action: "Read",
        Id: r.type === "aspx" ? `01${makeSha256(`res:${r.name}`).slice(0, 32).toUpperCase()}` : `01${makeSha256(`res:${r.name}`).slice(0, 32).toUpperCase()}`,
        Name: r.name,
        ...(r.site ? { SiteUrl: `${r.site}${r.type === "aspx" ? "SitePages/" : "Shared Documents/"}${r.name}` } : {}),
        Type: r.type,
        ...(r.label ? { SensitivityLabelId: r.label } : {}),
        Status: "success",
        XPIADetected: false,
      })),
      "data.office365.CopilotEventData.ModelTransparencyDetails": [{ ModelProviderName: "OpenAI" }],
      "data.office365.Version": "1",
      "source.ip": OFFICE_IP,
      "user.email": o.user,
      "user.name": `NEXACORP\\${bare}`,
      "event.action": "CopilotInteraction",
      "event.outcome": "success",
      "event.module": "o365",
      "event.dataset": "o365.audit",
    },
  };
}

function buildStoredInjectionCopilotKb(): TelemetryEvent[] {
  return [
    // 1. BASELINE: normal finance Copilot use over internal documents.
    kbCopilot({
      id: "aikb1", ts: "2026-10-01T09:12:40.118Z", user: FINANCE_USER,
      threadId: "19:Qd4mTz7YtR1bXc6VgL0mKe5HuPj2oIaA9sFv4TyNx8Cs@thread.v2",
      resources: [
        { name: "AP_Calendar_Q4.xlsx", type: "xlsx", site: KB_SITE },
        { name: "Expense_Policy_2026.docx", type: "docx", site: KB_SITE },
      ],
      severity: "informational", isBaseline: true,
      description: "Purview logged a CopilotInteraction for r.avraham in BizChat at 09:12: two internal finance documents were read, JailbreakDetected false, no accessed page flagged. This is the account's normal Copilot pattern.",
    }),

    // 2. COMPROMISED SIGN-IN: the editor account signs in from a hosting address, MFA satisfied, risk medium.
    entraSignIn({
      id: "aikb2", ts: "2026-10-01T07:41:16.902Z", companyId: "nexacorp", user: COMPROMISED, srcIp: ATTACKER_IP,
      app: "Office 365 SharePoint Online", appId: "00000003-0000-0ff1-ce00-000000000000", resource: "Office 365 SharePoint Online",
      mfa: true, managed: false, compliant: false, os: "Windows 10", browser: "Chrome 141.0.0",
      riskLevel: "medium", riskEventTypes: ["unfamiliarFeatures"], conditionalAccess: "success",
      geo: { country: ATTACKER_GEO.country, city: ATTACKER_GEO.city, latitude: ATTACKER_GEO.lat, longitude: ATTACKER_GEO.lon },
      severity: "medium", mitre: "T1078.004", tactic: "Initial Access",
      description: "Entra sign-in for m.levi to SharePoint Online at 07:41 from 198.51.100.66 (Falkenstein) on an unmanaged device, a new country for the account. The password step passed and the Authenticator push was approved; the sign-in scored medium risk for unfamiliar properties.",
    }),

    // 3. THE STORED INJECTION: the compromised account edits the KB page Copilot cites for payments.
    {
      ...m365Operation({
        companyId: "nexacorp", id: "aikb3", ts: "2026-10-01T07:58:44.333Z", user: COMPROMISED, operation: "FileModified",
        workload: "SharePoint", srcIp: ATTACKER_IP, userAgent: EDGE_UA, fileName: KB_PAGE, fileExtension: "aspx",
        objectId: `${KB_SITE}${KB_PAGE_REL}`,
        extra: {
          SiteUrl: KB_SITE, SourceRelativeUrl: KB_PAGE_REL, ItemType: "File",
          Site: guid("site:finance-ops"), WebId: guid("web:finance-ops"), ListId: guid("list:sitepages"),
          ListItemUniqueId: guid("item:vendor-payment"), CorrelationId: guid("corr:aikb3"),
          BrowserName: "Chrome", BrowserVersion: "141.0.0.0", IsManagedDevice: "false",
        },
        mitre: "T1565.001", tactic: "Impact", severity: "high",
        description: "Microsoft 365 audit: m.levi modified the site page Vendor-Payment-Instructions.aspx in the Finance-Operations site at 07:58 from 198.51.100.66, the same address as the risky sign-in 17 minutes earlier. This is the knowledge-base page Microsoft 365 Copilot cites for vendor-payment questions; the edit adds an instruction, addressed to the assistant, to return a changed remittance bank account for a named vendor.",
      }),
      source: "sharepoint" as const,
      hostname: undefined,
    },

    // 4. THE VICTIM'S OWN SIGN-IN — normal office sign-in before the poisoned session.
    entraSignIn({
      id: "aikb4", ts: "2026-10-01T10:04:51.207Z", companyId: "nexacorp", user: FINANCE_USER, srcIp: OFFICE_IP,
      app: "OfficeHome", appId: "4765445b-32c6-49b0-83e6-1d93765276ca", resource: "Microsoft 365 Copilot",
      mfa: true, managed: true, compliant: true, os: "Windows 11", browser: "Edge 141.0.0", trustType: "Azure AD joined",
      riskLevel: "none", conditionalAccess: "success",
      geo: { country: OFFICE_GEO.country, city: OFFICE_GEO.city, latitude: OFFICE_GEO.lat, longitude: OFFICE_GEO.lon },
      severity: "informational", isInteractive: true,
      description: "Entra sign-in for r.avraham to the Microsoft 365 home at 10:04 from the London office 198.51.100.8 on a managed, compliant device. The account's normal start of day.",
    }),

    // 5. THE POISONED ANSWER: Copilot answers the finance user and cites the edited KB page.
    kbCopilot({
      id: "aikb5", ts: "2026-10-01T10:31:09.556Z", user: FINANCE_USER,
      threadId: "19:Rp8nDz2YtR9sXw3KpC7dLe4NyOa6IuG0jFv2TnYx1Bs@thread.v2",
      resources: [{ name: KB_PAGE, type: "aspx", site: KB_SITE }],
      severity: "medium", mitre: "T1213.002", tactic: "Collection",
      description: "Purview logged a CopilotInteraction for r.avraham in BizChat at 10:31 that read the site page Vendor-Payment-Instructions.aspx as its grounding resource. JailbreakDetected is false on the prompt and XPIADetected is false on the page; the same site page was modified at 07:58 from the hosting address 198.51.100.66. The record holds message IDs and the resource name, not the prompt or the answer.",
    }),

    // 6. THE PAYMENT-CHANGE REQUEST: the finance user acts on the poisoned answer and emails AP.
    {
      id: "aikb6", ts: "2026-10-01T10:48:27.004Z", source: "o365", vendor: "Microsoft 365 Unified Audit Log",
      event_type: "email_sent", severity: "high", user_email: FINANCE_USER, src_ip: OFFICE_IP,
      geo: { country: OFFICE_GEO.country, city: OFFICE_GEO.city },
      mitre_technique: "T1657", mitre_tactic: "Impact",
      description: "Microsoft 365 audit: r.avraham sent 'Vendor bank detail update - ACME Supplies' to accounts-payable at 10:48, 17 minutes after the Copilot answer that cited the edited page. The body asks AP to update ACME's remittance bank account for the next payment run, per the assistant.",
      raw: {
        "data.office365.Operation": "Send",
        "data.office365.Workload": "Exchange",
        "data.office365.UserId": FINANCE_USER,
        "data.office365.ClientIP": OFFICE_IP,
        "data.office365.MailboxOwnerUPN": FINANCE_USER,
        "data.office365.Subject": "Vendor bank detail update - ACME Supplies",
        "data.office365.CreationTime": "2026-10-01T10:48:27.004Z",
        "email.from.address": FINANCE_USER,
        "email.sender.address": FINANCE_USER,
        "email.to.address": "accounts-payable@nexacorp.com",
        "email.subject": "Vendor bank detail update - ACME Supplies",
        "email.direction": "outbound",
        "email.message_id": `<${makeSha256("aikb6:msg").slice(0, 32)}@nexacorp.com>`,
        "source.ip": OFFICE_IP,
      },
    },

    // 7. SCOPE: a second finance user asks Copilot the same question and is given the same poisoned grounding.
    kbCopilot({
      id: "aikb7", ts: "2026-10-01T11:19:52.740Z", user: FINANCE_USER2,
      threadId: "19:Th2bVm5RqZ3sXw8KpC1dLe6NyOa0IuG4jFv6TnYx9Bs@thread.v2",
      resources: [{ name: KB_PAGE, type: "aspx", site: KB_SITE }],
      severity: "medium", mitre: "T1213.002", tactic: "Collection",
      description: "A second CopilotInteraction, for j.chen at 11:19, read the same Vendor-Payment-Instructions.aspx page as its grounding resource. One edited page reaches every employee whose Copilot answer draws on it.",
    }),

    // 8. THE SOC CORRELATION: Sentinel ties the risky sign-in, the page edit, the Copilot reads and the email.
    {
      id: "aikb8", ts: "2026-10-01T11:42:18.661Z", source: "siem", vendor: "Microsoft Sentinel", event_type: "cloud_api_call",
      severity: "high", is_detection: true, user_email: COMPROMISED, src_ip: ATTACKER_IP,
      mitre_technique: "T1565.001", mitre_tactic: "Impact",
      geo: { country: ATTACKER_GEO.country, city: ATTACKER_GEO.city, latitude: ATTACKER_GEO.lat, longitude: ATTACKER_GEO.lon },
      description: "Microsoft Sentinel raised 'Copilot-grounded SharePoint page edited from a risky sign-in, then cited in finance answers' (High): m.levi modified Vendor-Payment-Instructions.aspx from 198.51.100.66 after a medium-risk sign-in, and Copilot then cited that page for r.avraham and j.chen, one of whom emailed a vendor bank-detail change to accounts payable.",
      raw: {
        "TimeGenerated": "2026-10-01T11:42:18.661Z",
        "AlertName": "Copilot-grounded SharePoint page edited from a risky sign-in, then cited in finance answers",
        "AlertSeverity": "High",
        "ProductName": "Azure Sentinel",
        "ProviderName": "ASI Scheduled Alerts",
        "ProductComponentName": "Scheduled Alerts",
        "SystemAlertId": guid("sentinel:aikb8"),
        "Status": "New",
        "StartTime": "2026-10-01T07:41:16.902Z",
        "EndTime": "2026-10-01T11:19:52.740Z",
        "Tactics": "InitialAccess,Impact,Collection",
        "Techniques": "[\"T1078\",\"T1565\",\"T1213\"]",
        "Description": "Correlates an Entra risky sign-in, a SharePoint FileModified on a page referenced as a CopilotInteraction AccessedResource, subsequent CopilotInteraction records that cite the same page, and an outbound Exchange Send about a vendor bank-account change.",
        "ExtendedProperties.Edited page": KB_PAGE,
        "ExtendedProperties.Editor account": COMPROMISED,
        "ExtendedProperties.Editor sign-in IP": ATTACKER_IP,
        "ExtendedProperties.Grounded answers for": "r.avraham@nexacorp.com, j.chen@nexacorp.com",
        "ExtendedProperties.Payment-change email": "Vendor bank detail update - ACME Supplies",
        "Entities": JSON.stringify([
          { $id: "2", Type: "account", Name: "m.levi", UPNSuffix: "nexacorp.com" },
          { $id: "3", Type: "account", Name: "r.avraham", UPNSuffix: "nexacorp.com" },
          { $id: "4", Type: "ip", Address: ATTACKER_IP },
          { $id: "5", Type: "url", Url: `${KB_SITE}${KB_PAGE_REL}` },
        ]),
        "event.kind": "alert",
        "event.action": "SecurityAlert",
      },
    },
  ];
}

export const AI_WAVE3_B_STORIES: AiStoryDef[] = [
  {
    id: "ai-rag-chatbot-document-injection",
    title: "Uploaded Document Carries Hidden Instructions to a RAG Assistant",
    complexity: "core",
    companies: ["nexacorp", "medcore"],
    events: buildRagDocumentInjection(),
  },
  {
    id: "ai-stored-injection-copilot-kb",
    title: "Poisoned Knowledge-Base Page Makes Copilot Hand Back a Changed Vendor Account",
    complexity: "core",
    companies: ["nexacorp", "medcore", "globallogis", "quantumbank"], soloCompanies: ["nexacorp", "quantumbank"], seat: "finance",
    events: buildStoredInjectionCopilotKb(),
  },
];
