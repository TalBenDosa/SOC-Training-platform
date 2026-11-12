/**
 * Microsoft Sentinel SecurityAlert rows as the workspace stores them (card: docs/log-schemas/siem-sentinel-securityalert.md).
 *
 * The feed's SIEM alerts (a scheduled or NRT analytics rule, a Defender alert the connector forwards, the
 * SIEM mirror of an EDR detection) are authored with the Sentinel emitter (src/lib/sim/emitters/sentinel.ts),
 * whose raw block carries the SecurityAlert columns next to ECS mirrors the rest of the platform reads
 * (host.name, target.user.name, event.action, flat ExtendedProperties.<Name> keys). This module renders the
 * row the way Log Analytics returns it: SecurityAlert columns only, with `Entities`, `ExtendedProperties`
 * and `Techniques` as the JSON strings the table holds and `Tactics` as its comma-separated string.
 *
 * Company facts come from the native context, never from the authored row: the tenant id is the
 * company's (a story re-homed to another company names that company's tenant), an account entity's
 * AadUserId is the person's Entra object id (the one their SigninLogs carry), and a host entity's FQDN
 * uses the company domain. Times: TimeGenerated / ProcessingEndTime follow the row's feed time, and the
 * StartTime / EndTime span never ends after it.
 *
 * Applies to a Microsoft Sentinel row that names its alert (AlertName + SystemAlertId). UEBA anomalies
 * (sentinelUeba) and other SIEM products keep their own view (null).
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { KindSchema, NativeCtx, NativeLog, NativeSource, UseCase } from "../types";
import { entraObjectId } from "./_identity-common";

type Rec = Record<string, unknown>;

// ── Schema (Azure Monitor table reference: SecurityAlert) ─────────────────────

const REQUIRED = [
  "TimeGenerated", "TenantId", "Type", "SourceSystem", "AlertName", "DisplayName", "AlertSeverity", "ProductName",
  "ProviderName", "VendorName", "SystemAlertId", "VendorOriginalId", "AlertType", "Status", "StartTime", "EndTime",
  "ProcessingEndTime", "IsIncident", "CompromisedEntity", "Entities", "ExtendedProperties", "Tactics", "ConfidenceLevel",
];
const OPTIONAL = [
  "Description", "ProductComponentName", "Techniques", "SubTechniques", "RemediationSteps", "AlertLink", "ExtendedLinks",
  "ConfidenceScore", "ResourceId", "SourceComputerId", "WorkspaceResourceGroup", "WorkspaceSubscriptionId",
];
const SECURITY_ALERT: KindSchema = { required: REQUIRED, optional: OPTIONAL };

export function kindOf(record: Rec): string | null {
  return record.Type === "SecurityAlert" && typeof record.SystemAlertId === "string" ? "SecurityAlert" : null;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const str = (v: unknown) => (typeof v === "string" && v.trim() !== "" ? v : undefined);
const SEVERITY: Record<string, string> = { critical: "High", high: "High", medium: "Medium", low: "Low", informational: "Informational", info: "Informational" };
const SEVERITIES = new Set(["High", "Medium", "Low", "Informational"]);
const STATUSES = new Set(["New", "InProgress", "Resolved", "Dismissed", "Unknown"]);

/**
 * A row this module renders: a Microsoft Sentinel row that names its alert in SecurityAlert columns (the
 * emitter's sentinelAlert output, or a hand-authored alert block). A UEBA anomaly (entity.* / anomaly.*
 * fields, sentinelUeba) is a BehaviorAnalytics record, not a SecurityAlert: it keeps its own view.
 */
export function isSentinelSecurityAlert(ev: TelemetryEvent): boolean {
  if (ev.source !== "siem" || !/microsoft sentinel/i.test(ev.vendor ?? "")) return false;
  const r = (ev.raw ?? {}) as Rec;
  if (!str(r.AlertName)) return false;
  if ("entity.type" in r || Object.keys(r).some(k => k.startsWith("anomaly."))) return false;
  return !!(str(r.SystemAlertId) || str(r.ProviderName) || str(r.ProductName));
}

const isoMs = (ms: number) => new Date(ms).toISOString();
const lc = (v: unknown) => String(v ?? "").toLowerCase();

/**
 * Entities as the product wrote them, with company identity facts from the context. Evidence the row
 * states (a host, an account, an address, a domain, a URL, a process, a hash) that the authored list
 * leaves out is added as the entity Sentinel maps it to, so what the analyst quotes is in the alert.
 */
function entitiesOf(ev: TelemetryEvent, r: Rec, ctx: NativeCtx): Rec[] {
  let list: unknown = r.Entities;
  if (typeof list === "string") { try { list = JSON.parse(list); } catch { list = undefined; } }
  const out: Rec[] = Array.isArray(list) ? list.filter((e): e is Rec => !!e && typeof e === "object").map(e => ({ ...e })) : [];
  const flat = (k: string) => str(r[k]);
  const has = (pred: (e: Rec) => boolean) => out.some(pred);
  const add = (e: Rec) => out.push(e);
  const host = ev.hostname ?? flat("Entities.Host.HostName");
  if (host && !has(e => lc(e.Type) === "host" && lc(e.HostName) === lc(host))) add({ Type: "host", HostName: host });
  const upn = ev.user_email?.includes("@") ? ev.user_email : undefined;
  const sam = upn ? upn.split("@")[0] : flat("Entities.Account.Name");
  if (sam && !has(e => lc(e.Type) === "account" && lc(e.Name) === lc(sam))) add({ Type: "account", Name: sam, ...(upn ? { UPNSuffix: upn.split("@")[1] } : flat("Entities.Account.UPNSuffix") ? { UPNSuffix: flat("Entities.Account.UPNSuffix") } : {}) });
  for (const ip of [ev.src_ip, flat("Entities.IP.Address"), ev.dst_ip]) {
    if (ip && !has(e => lc(e.Type) === "ip" && e.Address === ip)) add({ Type: "ip", Address: ip });
  }
  const domain = ev.dns?.query;
  if (domain && !has(e => lc(e.Type) === "dns" && lc(e.DomainName) === lc(domain))) add({ Type: "dns", DomainName: domain });
  const url = ev.network?.url;
  if (url && !has(e => lc(e.Type) === "url" && e.Url === url)) add({ Type: "url", Url: url });
  const cmd = ev.process?.cmdline;
  if (cmd && !has(e => lc(e.Type) === "process" && e.CommandLine === cmd)) add({ Type: "process", CommandLine: cmd, ...(ev.process?.name ? { ImageFile: { Name: ev.process.name } } : {}) });
  const sha = ev.process?.hash?.sha256 ?? ev.file?.sha256;
  if (sha && !has(e => lc(e.Type) === "filehash" && lc(e.Value) === lc(sha))) add({ Type: "filehash", Algorithm: "SHA256", Value: sha });
  return out.map((e, i) => {
    const type = lc(e.Type);
    const o: Rec = { $id: String(i + 2), ...e };
    if (type === "account" && str(e.Name) && str(e.UPNSuffix)) o.AadUserId = entraObjectId(ctx, `${e.Name}@${e.UPNSuffix}`);
    if (type === "host" && str(e.HostName) && !/[.]/.test(String(e.HostName))) { o.DnsDomain = ctx.domain; o.FQDN = `${e.HostName}.${ctx.domain}`; }
    return o;
  });
}

/** ExtendedProperties: the rule's own keys, the forwarded product's custom columns, the analytic's id. */
/** The analytic's own name: an alert name that names its entity (alert details override) keeps the rule's static name. */
function ruleNameOf(name: string, ev: TelemetryEvent): string {
  const subject = [ev.hostname, ev.user_email].filter((x): x is string => !!x);
  for (const s of subject) {
    const tail = ` ${s}`.toLowerCase();
    for (const w of [" on", " for"]) if (name.toLowerCase().endsWith(w + tail)) return name.slice(0, name.length - (w + tail).length);
  }
  return name;
}

/** The keys a scheduled / NRT analytic writes into ExtendedProperties itself (anything else is the rule's Custom Details). */
const SCHEDULED_KEYS = new Set(["Query", "Query Period", "Query Start Time UTC", "Query End Time UTC", "Trigger Operator", "Trigger Threshold",
  "Search Query Results Overall Count", "Data Sources", "Event Grouping", "Analytic Rule Ids", "Analytic Rule Name", "Correlation Id",
  "ProcessedBySentinel", "Alert generation status", "Custom Details"]);
/** A Custom Details key as Sentinel accepts it: letters and digits only ("Source EDR Vendor" -> "SourceEDRVendor"). */
const customKey = (k: string) => k.replace(/[^A-Za-z0-9]+/g, "");
/** The analytic rule's id in the workspace (the same id its alerts' AlertType and "Analytic Rule Ids" carry). */
const ruleIdOf = (ctx: NativeCtx, r: Rec, ruleName: string) => ctx.uuid(`sentinel-rule:${ctx.companyId}:${str(r["alert.rule.id"]) ?? ruleName}`);

function extendedOf(r: Rec, ctx: NativeCtx, scheduled: boolean, ruleName: string): Rec {
  const out: Rec = {};
  const custom: Record<string, string[]> = {};
  for (const [k, v] of Object.entries(r)) {
    const m = /^(?:ExtendedProperties|azure\.alert\.extendedProperties)\.(.+)$/.exec(k);
    if (m && v !== undefined && v !== null && v !== "") {
      // A scheduled rule writes only its own keys; the fields its author chose to surface are Custom Details, a JSON
      // string of arrays ({"SourceEDRVendor":["CrowdStrike Falcon"]}). A product's alert keeps its own keys as is.
      if (scheduled && !SCHEDULED_KEYS.has(m[1])) custom[customKey(m[1])] = (Array.isArray(v) ? v : [v]).map(String);
      else out[m[1]] = Array.isArray(v) ? v.join(", ") : v;
    }
    // Defender for Endpoint's alert fields ride in ExtendedProperties under its own prefix.
    if (/^MicrosoftDefenderAtp\./.test(k) && str(v)) out[k] = v;
  }
  if (str(r.ThreatName)) out.ThreatName = r.ThreatName;
  if (str(r.ThreatFamilyName)) out.ThreatFamilyName = r.ThreatFamilyName;
  // A scheduled / NRT analytic names itself (the rule's id in the workspace, never the platform's rule label) and
  // states the query window and trigger it ran with.
  if (scheduled) {
    out["Query Period"] ??= "01:00:00";
    out["Trigger Operator"] ??= "GreaterThan";
    out["Trigger Threshold"] ??= "0";
    out["Search Query Results Overall Count"] ??= "1";
    out["Analytic Rule Ids"] = JSON.stringify([ruleIdOf(ctx, r, ruleName)]);
    out["Analytic Rule Name"] = ruleName;
    if (Object.keys(custom).length) out["Custom Details"] = JSON.stringify(custom);
  }
  return out;
}

function fromTelemetry(ev: TelemetryEvent, ctx: NativeCtx): NativeLog | null {
  if (!isSentinelSecurityAlert(ev)) return null;
  const r = (ev.raw ?? {}) as Rec;
  const timeMs = Date.parse(ev.ts);
  if (!Number.isFinite(timeMs)) return null;
  const name = str(r.AlertName)!;
  const provider = str(r.ProviderName) ?? "ASI Scheduled Alerts";
  const scheduled = provider === "ASI Scheduled Alerts";
  const sev = str(r.AlertSeverity) && SEVERITIES.has(String(r.AlertSeverity)) ? String(r.AlertSeverity) : SEVERITY[ev.severity ?? "medium"] ?? "Medium";
  // The span the alert covers, inside the feed's time: never after the alert itself.
  const startA = Date.parse(String(r.StartTime ?? "")), endA = Date.parse(String(r.EndTime ?? ""));
  const end = Number.isFinite(endA) ? Math.min(endA, timeMs) : timeMs;
  const start = Number.isFinite(startA) ? Math.min(startA, end) : end;
  const entities = entitiesOf(ev, r, ctx);
  const tactics = Array.isArray(r.Tactics) ? (r.Tactics as unknown[]).map(String) : str(r.Tactics) ? String(r.Tactics).split(",").map(s => s.trim()) : [];
  const techniques = Array.isArray(r.Techniques) ? (r.Techniques as unknown[]).map(String) : [];
  const host = entities.find(e => String(e.Type).toLowerCase() === "host");
  const account = entities.find(e => String(e.Type).toLowerCase() === "account");
  const compromised = str(r.CompromisedEntity) ?? str(host?.HostName) ?? (account ? `${account.Name}${account.UPNSuffix ? `@${account.UPNSuffix}` : ""}` : "");
  const remediation = Array.isArray(r.RemediationSteps) ? JSON.stringify(r.RemediationSteps) : str(r.RemediationSteps);

  const record: Rec = {
    TimeGenerated: isoMs(timeMs),
    TenantId: ctx.tenant.azureTenantId,
    Type: "SecurityAlert",
    SourceSystem: "Detection",
    DisplayName: str(r.DisplayName) ?? name,
    AlertName: name,
    AlertSeverity: sev,
    ...(str(r.Description) ? { Description: r.Description } : {}),
    ProviderName: provider,
    VendorName: str(r.VendorName) ?? "Microsoft",
    ProductName: str(r.ProductName) ?? "Azure Sentinel",
    ...(str(r.ProductComponentName) ? { ProductComponentName: r.ProductComponentName } : {}),
    // A scheduled / NRT analytic's alert type is "<workspace id>_<rule id>", never its name run together; a
    // product's own alert type (Defender's "SuspiciousPowerShellCommandLine") is what the product wrote.
    AlertType: scheduled ? `${ctx.uuid(`sentinel-workspace:${ctx.companyId}`)}_${ruleIdOf(ctx, r, ruleNameOf(name, ev))}` : str(r.AlertType) ?? name.replace(/[^A-Za-z0-9]+/g, ""),
    SystemAlertId: str(r.SystemAlertId) ?? ctx.uuid(`${ev.id}:system`),
    VendorOriginalId: str(r.VendorOriginalId) ?? ctx.uuid(`${ev.id}:vendor`),
    Status: str(r.Status) && STATUSES.has(String(r.Status)) ? r.Status : "New",
    ConfidenceLevel: "Unknown",
    StartTime: isoMs(start),
    EndTime: isoMs(end),
    ProcessingEndTime: isoMs(timeMs),
    IsIncident: false,
    CompromisedEntity: compromised,
    Tactics: tactics.join(","),
    ...(techniques.length ? { Techniques: JSON.stringify(techniques) } : {}),
    Entities: JSON.stringify(entities),
    ExtendedProperties: JSON.stringify(extendedOf(r, ctx, scheduled, ruleNameOf(name, ev))),
    ...(remediation ? { RemediationSteps: remediation } : {}),
    ...(str(r.AlertLink) ? { AlertLink: r.AlertLink } : {}),
  };
  return { sourceId: "sentinel_alert", kind: "SecurityAlert", format: "json", record, timeMs };
}

// ── Use cases (KQL on SecurityAlert) ──────────────────────────────────────────

const K = ["SecurityAlert"];
const useCases: UseCase[] = [
  {
    id: "sentinel_alert.high-severity-new",
    title: "New high-severity alert",
    sourceId: "sentinel_alert", kinds: K, severity: "high", mitre: [],
    description: "A high-severity alert nobody has triaged. Sentinel has no critical severity, so High is the top of the queue. The alert says what a rule or product saw; open its entities and the raw logs behind them before you decide.",
    logic: "// KQL (Microsoft Sentinel)\nSecurityAlert\n| where AlertSeverity == \"High\" and Status == \"New\"\n| project TimeGenerated, AlertName, CompromisedEntity, ProductName, Tactics",
    match: { all: [{ field: "AlertSeverity", op: "eq", value: "High" }, { field: "Status", op: "eq", value: "New" }] },
    falsePositives: ["A sanctioned penetration test", "A second alert for activity an open incident already covers"],
  },
  {
    id: "sentinel_alert.forwarded-edr-detection",
    title: "Endpoint detection forwarded from the EDR",
    sourceId: "sentinel_alert", kinds: K, severity: "medium", mitre: [],
    description: "The SIEM copy of an EDR detection. It names the host and the technique; the process tree, command line and hashes are in the EDR. Use it to line the endpoint up with the sign-ins and network rows of the same host.",
    logic: "// KQL (Microsoft Sentinel)\nSecurityAlert\n| extend cd = parse_json(tostring(parse_json(ExtendedProperties)[\"Custom Details\"]))\n| where isnotempty(cd.SourceEDRVendor)\n| extend Edr = tostring(cd.SourceEDRVendor[0])\n| summarize count() by Edr, CompromisedEntity",
    match: { field: "ExtendedProperties", op: "contains", value: "SourceEDRVendor" },
    falsePositives: ["Every EDR alert is forwarded, including the ones the EDR itself will clear as benign"],
  },
  {
    id: "sentinel_alert.credential-access",
    title: "Alert in the Credential Access tactic",
    sourceId: "sentinel_alert", kinds: K, severity: "high", mitre: ["T1003", "T1110", "T1558"],
    description: "Any rule or product reporting credential theft or guessing: LSASS access, password spray, Kerberos ticket abuse. A stolen credential works from anywhere, so check the account's sign-ins even when the host was contained.",
    logic: "// KQL (Microsoft Sentinel)\nSecurityAlert\n| where Tactics has \"CredentialAccess\"\n| project TimeGenerated, AlertName, CompromisedEntity, Entities",
    match: { field: "Tactics", op: "contains", value: "CredentialAccess" },
    falsePositives: ["Authorised penetration tests", "A password manager or backup agent reading credential stores"],
  },
  {
    id: "sentinel_alert.multi-alert-entity",
    title: "Several alerts on one entity within an hour",
    sourceId: "sentinel_alert", kinds: K, severity: "high", mitre: [],
    description: "Two or more alerts about the same host or account in one hour. Separate rules agreeing about one entity is the strongest triage signal a queue gives: work them as one case, oldest first.",
    logic: "// KQL (Microsoft Sentinel)\nSecurityAlert\n| where TimeGenerated > ago(1h)\n| summarize Alerts = dcount(SystemAlertId), Names = make_set(AlertName) by CompromisedEntity\n| where Alerts >= 2",
    match: { field: "CompromisedEntity", op: "exists" },
    threshold: { groupBy: ["CompromisedEntity"], count: 2, windowSec: 3600, distinct: "SystemAlertId" },
    falsePositives: ["One noisy rule firing twice on a scheduled job", "A shared jump host many admins use"],
  },
  {
    id: "sentinel_alert.persistence-or-impact",
    title: "Alert in the Persistence or Impact tactic",
    sourceId: "sentinel_alert", kinds: K, severity: "high", mitre: ["T1098", "T1486", "T1490"],
    description: "Persistence means the attacker plans to come back; Impact means damage is happening now. Neither waits for the next shift: confirm the entity and escalate.",
    logic: "// KQL (Microsoft Sentinel)\nSecurityAlert\n| where Tactics has_any (\"Persistence\", \"Impact\")",
    match: { any: [{ field: "Tactics", op: "contains", value: "Persistence" }, { field: "Tactics", op: "contains", value: "Impact" }] },
    falsePositives: ["An admin creating a scheduled task or a service account during a change window"],
  },
];

export const source: NativeSource = {
  schema: {
    sourceId: "sentinel_alert",
    category: "siem",
    card: "siem-sentinel-securityalert.md",
    product: "Microsoft Sentinel",
    format: "json",
    vendorMatch: ["microsoft sentinel"],
    telemetrySources: ["siem"],
    kinds: { SecurityAlert: SECURITY_ALERT },
  },
  fromTelemetry,
  useCases,
};
