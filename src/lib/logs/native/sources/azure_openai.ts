/**
 * Azure OpenAI resource logs (card: docs/log-schemas/cloud-azure-ai-storage.md, "Azure OpenAI in AzureDiagnostics").
 *
 * One record is one RequestResponse resource log entry as Azure writes it to a diagnostic setting (Event Hub /
 * storage), the shape the card quotes from the Elastic integration sample: `time`, `resourceId`, `category`,
 * `operationName`, `resultSignature` (HTTP status as a string), `durationMs`, `callerIpAddress` (last octet
 * masked), `correlationId`, `event` ShoeboxCallResult, `location` and `Tenant` (both the region), and `properties`,
 * a JSON string (apiName, requestTime / responseTime in .NET ticks, requestLength / responseLength in bytes,
 * objectId, streamType, modelDeploymentName, modelName, modelVersion).
 *
 * Not in the record: the prompt, the completion, token counts or the end user. The size is the signal.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { KindSchema, NativeCtx, NativeLog, NativeSource, UseCase } from "../types";

type Rec = Record<string, unknown>;

const REQUEST_RESPONSE: KindSchema = {
  required: ["time", "resourceId", "category", "operationName", "resultSignature", "durationMs", "callerIpAddress", "correlationId", "event", "location", "Tenant", "properties"],
  optional: [],
};

export function kindOf(r: Rec): string | null {
  return r.category === "RequestResponse" && typeof r.properties === "string" && r.event === "ShoeboxCallResult" ? "RequestResponse" : null;
}

const str = (v: unknown) => (typeof v === "string" && v !== "" ? v : undefined);
const num = (v: unknown) => (typeof v === "number" ? v : typeof v === "string" && v.trim() !== "" && !isNaN(Number(v)) ? Number(v) : undefined);
/** .NET ticks (100 ns since 0001-01-01) of an epoch-ms time, as properties.requestTime carries it. */
const ticks = (ms: number) => String(BigInt(ms + 62_135_596_800_000) * 10_000n);
/** The resource log masks the caller's last octet. */
const masked = (ip: string) => (/\*\*\*$/.test(ip) ? ip : ip.replace(/\.\d{1,3}$/, ".***"));

export function isAzureOpenAi(ev: TelemetryEvent): boolean {
  return (ev.source as string) === "cloud_azure" && /azure openai/i.test(ev.vendor ?? "");
}

function fromTelemetry(ev: TelemetryEvent, ctx: NativeCtx): NativeLog | null {
  if (!isAzureOpenAi(ev)) return null;
  const r = (ev.raw ?? {}) as Rec;
  const timeMs = Date.parse(ev.ts);
  if (!Number.isFinite(timeMs)) return null;
  const op = str(r["azure.open_ai.operation_name"]) ?? "ChatCompletions_Create";
  const region = str(r["azure.open_ai.location"]) ?? str(r["cloud.region"]) ?? "westeurope";
  const account = str(r["azure.resource.name"]) ?? `${ctx.org}-openai`;
  const group = str(r["azure.resource.group"]) ?? `rg-${ctx.org}-ai`;
  const resourceId = `/SUBSCRIPTIONS/${ctx.tenant.azureSubscriptionId}/RESOURCEGROUPS/${group}/PROVIDERS/MICROSOFT.COGNITIVESERVICES/ACCOUNTS/${account}`.toUpperCase();
  const duration = num(r["azure.open_ai.duration_ms"]) ?? ctx.int(`${ev.id}:dur`, 400, 4_000);
  const caller = str(r["azure.open_ai.caller_ip_address"]) ?? (ev.src_ip ? masked(ev.src_ip) : "");
  const respMs = timeMs, reqMs = timeMs - duration;
  const props: Rec = {
    apiName: str(r["azure.open_ai.properties.api_name"]) ?? "Azure OpenAI API version 2025-01-01-preview",
    requestTime: Number(ticks(reqMs)),
    requestLength: num(r["azure.open_ai.properties.request_length"]) ?? ctx.int(`${ev.id}:req`, 800, 4_000),
    responseTime: Number(ticks(respMs)),
    responseLength: num(r["azure.open_ai.properties.response_length"]) ?? ctx.int(`${ev.id}:resp`, 600, 3_000),
    objectId: str(r["azure.open_ai.properties.object_id"]) ?? "",
    streamType: str(r["azure.open_ai.properties.stream_type"]) ?? "NonStreaming",
    modelDeploymentName: str(r["azure.open_ai.properties.model_deployment_name"]) ?? "gpt-4o",
    modelName: str(r["azure.open_ai.properties.model_name"]) ?? "gpt-4o",
    modelVersion: str(r["azure.open_ai.properties.model_version"]) ?? "2024-11-20",
  };
  const record: Rec = {
    time: new Date(timeMs).toISOString(),
    resourceId,
    category: "RequestResponse",
    operationName: op,
    resultSignature: str(r["azure.open_ai.result_signature"]) ?? str(r["http.response.status_code"]) ?? "200",
    durationMs: duration,
    callerIpAddress: caller,
    correlationId: str(r["azure.open_ai.correlation_id"]) ?? ctx.uuid(`${ev.id}:corr`),
    event: "ShoeboxCallResult",
    location: region,
    Tenant: region,
    // properties is a JSON string in the resource log; requestTime / responseTime are .NET ticks (exact integers
    // beyond 2^53 are written as JSON numbers by Azure, so the string is assembled with the ticks verbatim).
    properties: JSON.stringify(props).replace(`"requestTime":${props.requestTime}`, `"requestTime":${ticks(reqMs)}`).replace(`"responseTime":${props.responseTime}`, `"responseTime":${ticks(respMs)}`),
  };
  return { sourceId: "azure_openai", kind: "RequestResponse", format: "json", record, timeMs };
}

const K = ["RequestResponse"];
const useCases: UseCase[] = [
  {
    id: "azure_openai.oversized-completion", title: "Unusually large completion from a deployment",
    sourceId: "azure_openai", kinds: K, severity: "medium", mitre: ["T1530", "T1213"],
    description: "The log never holds the prompt or the answer, so size is the signal: a completion tens of KB long from a deployment that answers in one or two KB is a model dumping retrieved documents or its system prompt. Compare with the deployment's own median.",
    logic: "// KQL (AzureDiagnostics)\nAzureDiagnostics\n| where ResourceProvider == \"MICROSOFT.COGNITIVESERVICES\" and Category == \"RequestResponse\"\n| extend p = parse_json(properties_s)\n| where toint(p.responseLength) > 10000\n| project TimeGenerated, Resource, CallerIPAddress, p.modelDeploymentName, p.responseLength",
    match: { field: "properties", op: "regex", value: "\"responseLength\":[1-9]\\d{4,}" },
    falsePositives: ["Summaries of long documents and code generation, which a deployment built for them returns every day"],
  },
  {
    id: "azure_openai.throttling-burst", title: "Burst of throttled calls (HTTP 429) from one caller",
    sourceId: "azure_openai", kinds: K, severity: "high", mitre: ["T1078.004", "T1552.001"],
    description: "A stolen key used to resell or burn the quota runs the deployment into its rate limit. Many 429s from one caller in minutes, from an address that is not the company's app, is the pattern of LLMjacking.",
    logic: "// KQL (AzureDiagnostics)\nAzureDiagnostics\n| where Category == \"RequestResponse\" and ResultSignature == \"429\"\n| summarize calls = count() by CallerIPAddress, bin(TimeGenerated, 5m)\n| where calls >= 10",
    match: { field: "resultSignature", op: "eq", value: "429" },
    threshold: { groupBy: ["callerIpAddress"], count: 10, windowSec: 300 },
    falsePositives: ["A load test or a batch job the app team runs against its own deployment"],
  },
  {
    id: "azure_openai.auth-failures", title: "Rejected calls (HTTP 401 / 403) to a deployment",
    sourceId: "azure_openai", kinds: K, severity: "medium", mitre: ["T1110", "T1552.001"],
    description: "Someone is trying keys or tokens the account does not accept: an old leaked key after rotation, or a guess. Find where the key came from (a repository, a config file) before it is a working one.",
    logic: "// KQL (AzureDiagnostics)\nAzureDiagnostics\n| where Category == \"RequestResponse\" and ResultSignature in (\"401\", \"403\")\n| summarize count() by CallerIPAddress, Resource",
    match: { field: "resultSignature", op: "in", value: ["401", "403"] },
    falsePositives: ["An app deployed with a rotated key before its settings were updated"],
  },
  {
    id: "azure_openai.key-call-new-caller", title: "API-key call (no Entra identity) to a deployment",
    sourceId: "azure_openai", kinds: K, severity: "low", mitre: ["T1078.004"],
    description: "A call with an API key carries no identity (objectId is empty), so the caller address is all you have. Keys belong in the app's managed identity setup; a key call from outside the app's own egress is someone else holding the key.",
    logic: "// KQL (AzureDiagnostics)\nAzureDiagnostics\n| where Category == \"RequestResponse\"\n| extend oid = tostring(parse_json(properties_s).objectId)\n| where isempty(oid)\n| summarize count() by CallerIPAddress, Resource",
    match: { field: "properties", op: "contains", value: "\"objectId\":\"\"" },
    falsePositives: ["Apps that were set up with keys and never moved to managed identity"],
  },
];

export const source: NativeSource = {
  schema: {
    sourceId: "azure_openai",
    category: "cloud",
    card: "cloud-azure-ai-storage.md",
    product: "Azure OpenAI",
    format: "json",
    vendorMatch: ["azure openai"],
    telemetrySources: ["cloud_azure"],
    kinds: { RequestResponse: REQUEST_RESPONSE },
  },
  fromTelemetry,
  useCases,
};
