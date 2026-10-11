/**
 * Azure Activity Log + Microsoft Defender for Cloud alerts — native source module.
 *
 * Card: docs/log-schemas/cloud-azure-activity.md. Two native kinds:
 *  - ActivityLog: the resource-log (Event-Hub / storage) shape — `operationName`,
 *    `category`, `resultType` as plain strings — which is what a SIEM ingests.
 *  - DefenderAlert: the Defender for Cloud alert ARM resource (`properties{...}`).
 * No `azure.activitylogs.*` / `azure.signinlogs.*` ECS flattening, no Wazuh envelope.
 *
 * Out of this card's scope (declined, never faked): Microsoft Entra ID sign-in /
 * directory-audit logs (that is the entra module) and Azure OpenAI request/response
 * diagnostic logs (`azure.open_ai.*`, a separate dataset the card does not document).
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { KindSchema, NativeCtx, NativeLog, NativeSource, SourceSchema, UseCase } from "../types";
import { entitySeed, iso7, iso7z, rs, rv, underPrefix } from "./cloud-shared";

const kinds: Record<string, KindSchema> = {
  ActivityLog: {
    required: ["time", "resourceId", "operationName", "category", "resultType", "level"],
    optional: ["resultSignature", "resultDescription", "durationMs", "callerIpAddress", "correlationId", "location"],
    openPrefixes: ["identity", "properties"],
  },
  DefenderAlert: {
    required: ["id", "name", "type", "properties"],
    optional: [],
    openPrefixes: ["properties"],
  },
};

const schema: SourceSchema = {
  sourceId: "azure_activity",
  category: "cloud",
  card: "cloud-azure-activity.md",
  product: "Azure Activity Log / Microsoft Defender for Cloud",
  format: "json",
  vendorMatch: ["azure activity", "azure monitor", "defender for cloud"],
  telemetrySources: ["cloud_azure"],
  kinds,
};

export function kindOf(record: Record<string, unknown>): string | null {
  const t = record["type"];
  if ((typeof t === "string" && /Microsoft\.Security\/.*alerts/i.test(t)) || (record["properties"] && typeof record["properties"] === "object" && (record["properties"] as Record<string, unknown>)["alertType"])) return "DefenderAlert";
  if (record["operationName"] && record["category"] && record["time"]) return "ActivityLog";
  return null;
}

// ── conversion ────────────────────────────────────────────────────────────────

const UPN = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn";

function buildActivityLog(ev: TelemetryEvent, ctx: NativeCtx): NativeLog {
  const raw = ev.raw ?? {};
  const op = rs(raw, "azure.activitylogs.operationName")!;
  const resourceId = rs(raw, "azure.resource.id") ?? `/SUBSCRIPTIONS/${ctx.tenant.azureSubscriptionId.toUpperCase()}/RESOURCEGROUPS/${(rs(raw, "azure.resource.group") ?? "rg-prod").toUpperCase()}/PROVIDERS/${(rs(raw, "azure.resource.provider") ?? "MICROSOFT.RESOURCES").toUpperCase()}/${(rs(raw, "azure.resource.name") ?? "resource").toUpperCase()}`;
  const upn = rs(raw, "azure.activitylogs.identity.claims_initiated_by_user.name", "azure.activitylogs.identity.claims.upn") ?? ev.user?.email ?? ev.user_email;
  const ip = ev.src_ip ?? rs(raw, "azure.activitylogs.callerIpAddress", "source.ip");
  const result = rs(raw, "azure.activitylogs.resultType") ?? "Success";

  const identity: Record<string, unknown> = {
    authorization: {
      action: op.toLowerCase().includes("/action") || op.toLowerCase().includes("/write") || op.toLowerCase().includes("/read") ? op : `${op}`,
      scope: resourceId.toLowerCase(),
      ...(rs(raw, "azure.activitylogs.identity.authorization.evidence.role") ? { evidence: { role: rs(raw, "azure.activitylogs.identity.authorization.evidence.role") } } : {}),
    },
    claims: {
      ...(upn ? { [UPN]: upn, name: upn } : {}),
      ...(ip ? { ipaddr: ip } : {}),
    },
  };

  const record: Record<string, unknown> = {
    time: iso7(ev.ts, ctx, ev.id + ":time"),
    resourceId,
    operationName: op,
    category: rs(raw, "azure.activitylogs.event_category") ?? "Administrative",
    resultType: result,
    resultSignature: rs(raw, "azure.activitylogs.resultSignature") ?? `${result}.OK`,
    durationMs: 0,
    correlationId: rs(raw, "azure.correlation_id") ?? ctx.uuid(ev.id + ":corr"),
    identity,
    level: rs(raw, "azure.activitylogs.level") ?? "Informational",
    location: "global",
    properties: {
      eventCategory: rs(raw, "azure.activitylogs.event_category") ?? "Administrative",
      entity: resourceId.toLowerCase(),
      message: op,
      hierarchy: `${ctx.tenant.azureTenantId}/${ctx.tenant.azureSubscriptionId}`,
    },
  };
  if (ip) record.callerIpAddress = ip;

  return { sourceId: "azure_activity", kind: "ActivityLog", format: "json", record, timeMs: Date.parse(ev.ts) };
}

function buildDefenderAlert(ev: TelemetryEvent, ctx: NativeCtx): NativeLog {
  const raw = ev.raw ?? {};
  const alertType = rs(raw, "azure.alert.alertType") ?? "Generic.SuspiciousActivity";
  const sysId = rs(raw, "azure.alert.systemAlertId") ?? ctx.uuid(ev.id + ":alert");
  const sub = ctx.tenant.azureSubscriptionId;
  const rg = rs(raw, "azure.resource.group") ?? "prod-rg";
  const compromised = rs(raw, "azure.alert.compromisedEntity") ?? rs(raw, "azure.resource.name") ?? "resource";
  const ip = ev.src_ip ?? rs(raw, "azure.alert.extendedProperties.Client IP address");

  const extended = underPrefix(raw, "azure.alert.extendedProperties.");
  const entities: Record<string, unknown>[] = [];
  if (ip) entities.push({ type: "ip", address: ip, ...(ev.geo?.country ? { location: { countryCode: (ev.geo.country ?? "").slice(0, 2).toLowerCase(), city: ev.geo.city, latitude: ev.geo.latitude, longitude: ev.geo.longitude } } : {}) });
  const acct = ev.user?.email ?? ev.user_email;
  if (acct) entities.push({ type: "account", name: acct });

  const sev = rs(raw, "azure.alert.severity") ?? (ev.severity === "critical" ? "High" : ev.severity === "high" ? "High" : ev.severity === "medium" ? "Medium" : "Low");

  const properties: Record<string, unknown> = {
    alertDisplayName: rs(raw, "azure.alert.displayName") ?? alertType,
    alertType,
    description: rs(raw, "azure.alert.description") ?? ev.description ?? alertType,
    severity: sev,
    status: rs(raw, "azure.alert.status") ?? "Active",
    intent: rs(raw, "azure.alert.intent") ?? "Unknown",
    startTimeUtc: rs(raw, "azure.alert.startTimeUtc") ?? iso7z(ev.ts),
    endTimeUtc: rs(raw, "azure.alert.endTimeUtc") ?? iso7z(ev.ts),
    timeGeneratedUtc: rs(raw, "azure.alert.timeGeneratedUtc") ?? iso7z(ev.ts, 90),
    compromisedEntity: compromised,
    productName: rs(raw, "azure.alert.productName") ?? "Microsoft Defender for Cloud",
    vendorName: rs(raw, "azure.alert.vendorName") ?? "Microsoft",
    resourceIdentifiers: [{ type: "AzureResource", azureResourceId: rs(raw, "azure.resource.id") ?? `/subscriptions/${sub}/resourceGroups/${rg}` }],
    entities,
    isIncident: false,
    systemAlertId: sysId,
  };
  if (Object.keys(extended).length) properties.extendedProperties = extended;

  const record: Record<string, unknown> = {
    id: `/subscriptions/${sub}/resourceGroups/${rg}/providers/Microsoft.Security/locations/${rs(raw, "cloud.region") ?? "westeurope"}/alerts/${sysId}`,
    name: sysId,
    type: "Microsoft.Security/Locations/alerts",
    properties,
  };

  return { sourceId: "azure_activity", kind: "DefenderAlert", format: "json", record, timeMs: Date.parse(ev.ts) };
}

function fromTelemetry(ev: TelemetryEvent, ctx: NativeCtx): NativeLog | null {
  if ((ev.vendor ?? "").toLowerCase().includes("entra")) return null; // Entra sign-in/audit → entra module
  const raw = ev.raw ?? {};
  if (rv(raw, "azure.alert.alertType", "azure.alert.displayName")) return buildDefenderAlert(ev, ctx);
  if (rs(raw, "azure.activitylogs.operationName")) return buildActivityLog(ev, ctx);
  // Azure OpenAI request/response diagnostics (azure.open_ai.*) are not documented
  // by this card — decline rather than fabricate a schema.
  return null;
}

// ── use cases ─────────────────────────────────────────────────────────────────

const useCases: UseCase[] = [
  {
    id: "azure_activity.keyvault_secret_listing",
    title: "Key Vault / account key enumeration",
    sourceId: "azure_activity", severity: "high", mitre: ["T1552", "T1555"],
    kinds: ["ActivityLog"],
    description: "A secrets/list on a Key Vault, or a ListKeys on a storage / Cognitive-Services account — bulk enumeration of secrets or access keys, a credential-access step distinct from an app reading its one secret.",
    logic: "KQL: AzureActivity | where OperationNameValue matches regex \"(?i)(keyvault/vaults/secrets/list|/listkeys/action)\"",
    match: { any: [
      { field: "operationName", op: "regex", value: "keyvault/vaults/secrets/list" },
      { field: "operationName", op: "regex", value: "/listkeys/action" },
    ] },
    falsePositives: ["A deployment job that legitimately lists vault secrets or rotates account keys (correlate with the service principal)."],
  },
  {
    id: "azure_activity.privileged_role_assignment",
    title: "Privileged RBAC role assignment",
    sourceId: "azure_activity", severity: "critical", mitre: ["T1098.003"],
    kinds: ["ActivityLog"],
    description: "Microsoft.Authorization/roleAssignments/write granting a privileged built-in role (Owner / Contributor / User Access Administrator) — persistence / privilege escalation; read properties.requestbody for the roleDefinitionId.",
    logic: "KQL: AzureActivity | where OperationName=~\"Microsoft.Authorization/roleAssignments/write\" and properties.requestbody has_any (Owner GUID, Contributor GUID, UAA GUID)",
    match: { all: [
      { field: "operationName", op: "regex", value: "Microsoft.Authorization/roleAssignments/write" },
      { any: [
        { field: "properties.requestbody", op: "icontains", value: "8e3af657-a8ff-443c-a75c-2fe8c4bcb635" }, // Owner
        { field: "properties.requestbody", op: "icontains", value: "b24988ac-6180-42a0-ab88-20f7382dd24c" }, // Contributor
        { field: "properties.requestbody", op: "icontains", value: "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9" }, // User Access Administrator
      ] },
    ] },
    falsePositives: ["Identity team granting Owner/Contributor as part of an approved access request (verify the ticket and the assigned principal)."],
  },
  {
    id: "azure_activity.vm_run_command",
    title: "VM Run Command (remote code execution)",
    sourceId: "azure_activity", severity: "high", mitre: ["T1059", "T1651"],
    kinds: ["ActivityLog"],
    description: "Microsoft.Compute/virtualMachines/runCommand/action — arbitrary code executed on a VM through the Azure control plane, bypassing in-guest logging; high-signal on a production VM.",
    logic: "KQL: AzureActivity | where OperationNameValue =~ \"Microsoft.Compute/virtualMachines/runCommand/action\"",
    match: { field: "operationName", op: "regex", value: "Microsoft.Compute/virtualMachines/runCommand/action" },
    falsePositives: ["Automation / configuration tooling that legitimately uses Run Command (scope by the invoking identity)."],
  },
  {
    id: "azure_activity.cognitive_deployment_write",
    title: "Unexpected Azure AI model deployment created",
    sourceId: "azure_activity", severity: "high", mitre: ["T1578"],
    kinds: ["ActivityLog"],
    description: "Microsoft.CognitiveServices/accounts/deployments/write — a new Azure OpenAI model deployment; attacker-created to route abusive traffic around the original deployment's quota (LLM capacity abuse).",
    logic: "KQL: AzureActivity | where OperationNameValue matches regex \"(?i)cognitiveservices/accounts/deployments/write\"",
    match: { field: "operationName", op: "regex", value: "cognitiveservices/accounts/deployments/write" },
    falsePositives: ["A platform team deploying a new model through an approved change (confirm the change request)."],
  },
  {
    id: "azure_activity.defender_high_alert",
    title: "Defender for Cloud High-severity alert",
    sourceId: "azure_activity", severity: "high", mitre: [],
    kinds: ["DefenderAlert"],
    description: "A Microsoft Defender for Cloud alert with severity High — Microsoft's own high-confidence detection (suspicious-IP access, key-vault abuse, suspicious compute creation), to be triaged ahead of lower bands.",
    logic: "KQL: SecurityAlert | where AlertSeverity == \"High\"",
    match: { field: "properties.severity", op: "eq", value: "High" },
    falsePositives: ["Benign anomalies (a new legitimate automation source) that Defender rated High — confirm the entity."],
  },
  {
    id: "azure_activity.defender_alert",
    title: "Defender for Cloud alert raised",
    sourceId: "azure_activity", severity: "medium", mitre: [],
    kinds: ["DefenderAlert"],
    description: "Any Defender for Cloud alert (jailbreak blocked, LLM reconnaissance, data-exfiltration, wallet abuse). Triage by severity and intent; correlate the entities' IP/account with the Activity Log.",
    logic: "KQL: SecurityAlert | where ProductName startswith \"Microsoft Defender\"",
    match: { field: "properties.alertType", op: "exists" },
    falsePositives: ["Low/Informational alerts that are expected for the workload."],
  },
];

export const source: NativeSource = { schema, fromTelemetry, useCases };
