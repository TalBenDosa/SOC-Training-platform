/**
 * buildWorkspace: the released feed as a Microsoft Sentinel workspace.
 *
 *   TelemetryEvent[] -> native record -> Log Analytics row
 *                    -> SecurityAlert (product detections + analytics rules) -> incidents
 *
 * Input is the public payload only. Deterministic and append-stable: alerts are processed in arrival
 * order, so events added later never change an earlier incident's id, number or first alert.
 */
import { authoredOf, NATIVE_SOURCES, nativeView, stackFor, type NativeIdentity, type Stack } from "@/lib/logs/native";
import { makeCtx, seededInt, seededUuid } from "@/lib/logs/native/ctx";
import { runUseCase } from "@/lib/logs/native/engine";
import type { NativeLog, SourceId, UseCase } from "@/lib/logs/native/types";
import type { KqlRow, KqlTable } from "@/lib/kql/types";
import { techniqueById } from "@/lib/mitre/attack";
import { COMPANY_ASSETS } from "@/lib/sim/companyProfilesMeta";
import type { TelemetryEvent } from "@/lib/sim/types";
import { EntityBook, entitiesColumn, isPrivateIp } from "./entities";
import { buildHunting } from "./hunting";
import { logKey, mapRow, type MapContext } from "./mapRow";
import { evaluatePart, NOISE_RULES, noiseAnalyticsRules } from "./noise";
import { alertDescription, buildRules, groupFilter, kstr, plain, ruleSeverity, tacticName, tacticsOf, stackUseCases, type CompiledRule } from "./rules";
import { emptyTable, TABLE_NAMES } from "./tables";
import type { SentinelAlert, SentinelEntity, SentinelIncident, SentinelSeverity, SentinelWorkspace } from "./types";

export interface BuildOptions {
  companyId: string;
  stack?: Stack;
  identity?: NativeIdentity;
  /** The organization shown in the workspace name. */
  orgName?: string;
}

/** What the build left out, for the report and the console's Data connectors view. */
export interface WorkspaceCoverage {
  rows: number;
  /** Events with no native record (`source / vendor`). */
  noNativeRecord: Record<string, number>;
  /** Native records no real table takes (`sourceId/kind`). */
  noTable: Record<string, number>;
}

interface Entry { index: number; ev: TelemetryEvent; log?: NativeLog; table?: string; row?: KqlRow; entityIds: string[] }

const SEV_RANK: Record<SentinelSeverity, number> = { High: 3, Medium: 2, Low: 1, Informational: 0 };
const toSeverity = (s: unknown): SentinelSeverity => {
  const v = String(s ?? "").toLowerCase();
  return v === "critical" || v === "high" ? "High" : v === "medium" ? "Medium" : v === "low" ? "Low" : "Informational";
};

// ── Product detections ───────────────────────────────────────────────────────

const ALERT_TYPES = new Set(["edr_alert", "av_detection", "av_quarantine", "av_blocked", "dlp_alert", "dlp_block"]);
const SCHEDULED = { product: "Azure Sentinel", provider: "ASI Scheduled Alerts" };

const raw = (ev: TelemetryEvent, k: string): string | undefined => {
  const v = (ev.raw as Record<string, unknown> | undefined)?.[k];
  return typeof v === "string" && v ? v : undefined;
};

export function isProductDetection(ev: TelemetryEvent, log?: NativeLog): boolean {
  if (ev.is_detection || ALERT_TYPES.has(ev.event_type)) return true;
  if (ev.source === "siem" && raw(ev, "AlertName")) return true;
  return log?.sourceId === "azure_activity" && log.kind === "DefenderAlert";
}

/** Current product names as the ProductName column still writes them. */
const PRODUCT_COLUMN: Record<string, { product: string; provider: string }> = {
  "Microsoft Defender for Office 365": { product: "Office 365 Advanced Threat Protection", provider: "OATP" },
  "Microsoft Defender for Endpoint": { product: "Microsoft Defender Advanced Threat Protection", provider: "MDATP" },
  "Microsoft Defender for Identity": { product: "Azure Advanced Threat Protection", provider: "AATP" },
  "Microsoft Defender for Cloud": { product: "Azure Security Center", provider: "Azure Security Center" },
  "Microsoft Defender for Cloud Apps": { product: "Microsoft Cloud App Security", provider: "MCAS" },
  "Microsoft Entra ID Protection": { product: "Azure Active Directory Identity Protection", provider: "IPC" },
};

/** ProductName and ProviderName of the SecurityAlert row. A third-party product raises alerts through a scheduled rule. */
function providerOf(ev: TelemetryEvent, log?: NativeLog): { product: string; provider: string } {
  const named = raw(ev, "AlertName") ? raw(ev, "ProductName") : undefined;
  if (named) return PRODUCT_COLUMN[named] ?? { product: named, provider: raw(ev, "ProviderName") ?? named };
  const vendor = ev.vendor ?? "";
  const id = log?.sourceId;
  if (id === "mde") return { product: "Microsoft Defender Advanced Threat Protection", provider: "MDATP" };
  if (id === "defender_o365") return { product: "Office 365 Advanced Threat Protection", provider: "OATP" };
  if (id === "entra") return { product: "Azure Active Directory Identity Protection", provider: "IPC" };
  if (id === "azure_activity" && log?.kind === "DefenderAlert") return { product: "Azure Security Center", provider: "Azure Security Center" };
  if (id === "m365" && log?.kind === "DlpRuleMatch") return { product: "Microsoft Data Loss Prevention", provider: "Microsoft Data Loss Prevention" };
  if (/defender for identity/i.test(vendor)) return { product: "Azure Advanced Threat Protection", provider: "AATP" };
  if (/defender for cloud apps/i.test(vendor)) return { product: "Microsoft Cloud App Security", provider: "MCAS" };
  if (/defender for cloud/i.test(vendor)) return { product: "Azure Security Center", provider: "Azure Security Center" };
  if (/insider risk/i.test(vendor)) return { product: "Microsoft Insider Risk Management", provider: "Microsoft Insider Risk Management" };
  if (/purview/i.test(vendor)) return { product: "Microsoft Data Loss Prevention", provider: "Microsoft Data Loss Prevention" };
  return SCHEDULED;
}

function recordString(r: Record<string, unknown> | undefined, ...paths: string[][]): string | undefined {
  if (!r) return undefined;
  for (const p of paths) {
    let cur: unknown = r;
    for (const k of p) cur = (cur as Record<string, unknown> | undefined)?.[k];
    if (typeof cur === "string" && cur) return cur;
  }
  return undefined;
}

const TYPE_NAME: Record<string, string> = {
  auth_success: "Sign-in flagged by the identity provider", auth_failure: "Failed sign-in flagged by the identity provider", privilege_escalation: "Elevated privileges assigned",
  group_modify: "Group membership changed", account_modify: "Account properties changed", account_create: "New account created", role_assignment: "Role assignment changed",
  process_create: "Process flagged by endpoint protection", file_create: "File flagged by endpoint protection", net_connection: "Connection flagged by network protection",
  email_received: "Message flagged by mail protection", cloud_api_call: "Cloud API call flagged", policy_modification: "Security policy changed",
};

/** The alert's display name, as its product names it. */
function detectionName(ev: TelemetryEvent, log?: NativeLog): string {
  const r = log?.record;
  const byKind = log?.kind === "alert" ? recordString(r, ["display_name"])
    : log?.kind === "threat" ? recordString(r, ["threatInfo", "threatName"])
    : log?.kind === "detection" ? recordString(r, ["rawData", "detection_name"], ["detectionRule"])
    : log?.kind === "event" ? recordString(r, ["threat"], ["name"])
    : log?.kind === "AlertEvidence" || log?.kind === "AlertInfo" ? recordString(r, ["properties", "Title"])
    : log?.kind === "DefenderAlert" ? recordString(r, ["properties", "alertDisplayName"]) : undefined;
  const named = raw(ev, "AlertName") ?? raw(ev, "DisplayName") ?? raw(ev, "purview.Title") ?? byKind ?? ev.rule?.name;
  if (named) return named;
  // A detection the row names only by technique reads as its product does: the technique's name.
  const technique = ev.mitre_technique ? techniqueById(ev.mitre_technique)?.name : undefined;
  return technique ?? TYPE_NAME[ev.event_type] ?? (ev.description ?? `${ev.event_type} on ${ev.hostname ?? "unknown host"}`).replace(/^Alert:\s*/, "");
}

const splitList = (s: string | undefined): string[] => {
  if (!s) return [];
  if (s.startsWith("[")) { try { return (JSON.parse(s) as unknown[]).map(String); } catch { return []; } }
  return s.split(",").map(x => x.trim()).filter(Boolean);
};

// ── Alerts ───────────────────────────────────────────────────────────────────

interface Pending { alert: Omit<SentinelAlert, "entityIds">; order: number; entries: Entry[]; firstMs: number; lastMs: number; provider: string; displayEntity?: string }

const isoMs = (ms: number) => new Date(ms).toISOString();
const between = (a: number, b: number) => `| where TimeGenerated between (datetime(${isoMs(a)}) .. datetime(${isoMs(b)}))`;

const HOST_COLUMN: Record<string, string> = {
  SigninLogs: "UserPrincipalName", AuditLogs: "Identity", OfficeActivity: "UserId", OktaV2_CL: "OriginalActorAlternateId", AWSCloudTrail: "UserIdentityArn", EmailEvents: "RecipientEmailAddress", GCPAuditLogs: "PrincipalEmail",
  CommonSecurityLog: "DestinationHostName", SecurityEvent: "Computer", Event: "Computer", DnsEvents: "Computer", Syslog: "Computer", SentinelOneThreats_CL: "AgentComputerName",
  SophosEPAlerts_CL: "DvcHostname", SophosEPEvents_CL: "DvcHostname", ASimProcessEventLogs: "DvcHostname", ASimNetworkSessionLogs: "DvcHostname", ASimFileEventLogs: "DvcHostname",
  ASimRegistryEventLogs: "DvcHostname", ASimDnsActivityLogs: "DvcHostname", DeviceProcessEvents: "DeviceName", DeviceNetworkEvents: "DeviceName", DeviceFileEvents: "DeviceName",
  DeviceRegistryEvents: "DeviceName", DeviceLogonEvents: "DeviceName", DeviceEvents: "DeviceName", AlertEvidence: "DeviceName",
};

/** KQL for the single row behind a product detection. */
function rowQuery(e: Entry, alertId: string): string {
  if (!e.table || !e.row) return `SecurityAlert\n| where SystemAlertId == ${kstr(alertId)}`;
  const ms = Date.parse(String(e.row.TimeGenerated));
  const hostCol = HOST_COLUMN[e.table];
  const host = hostCol ? e.row[hostCol] : undefined;
  return [e.table, between(ms, ms), ...(typeof host === "string" ? [`| where ${hostCol} == ${kstr(host)}`] : [])].join("\n");
}

function ruleAlertQuery(c: CompiledRule, uc: UseCase, entries: Entry[], firstMs: number, lastMs: number, groupKey?: string): string {
  const tables = new Set(entries.map(e => e.table));
  const parts = c.bases.filter(b => tables.has(b.spec.table)).map(b => [b.query, between(firstMs, lastMs), ...groupFilter(uc, b.spec, groupKey)].join("\n"));
  return parts.length === 1 ? parts[0] : `union\n${parts.map(p => `(${p.replace(/\n/g, "\n  ")})`).join(",\n")}`;
}

/** SecurityAlert fields a feed row already states: KQL shows the feed's value. */
const FEED_ALERT_COLUMNS = ["AlertType", "VendorOriginalId", "ProductComponentName", "ConfidenceLevel", "RemediationSteps", "ExtendedLinks", "AlertLink"];

function alertRow(a: Pending, entities: SentinelEntity[], tenantId: string, orgId: string): KqlRow {
  const al = a.alert;
  const ev = a.entries[0].ev;
  const feed: KqlRow = {};
  if (!al.ruleId) for (const c of FEED_ALERT_COLUMNS) { const v = raw(ev, c); if (v) feed[c] = v; }
  const compromised = entities.find(e => e.kind === "host")?.name ?? entities.find(e => e.kind === "account")?.name ?? "";
  return {
    TimeGenerated: al.time, Type: "SecurityAlert", TenantId: tenantId, SystemAlertId: al.id, AlertName: al.name, DisplayName: al.name, AlertSeverity: al.severity, Description: al.description,
    ProductName: al.product, ProviderName: a.provider, VendorName: "Microsoft", VendorOriginalId: seededUuid(`${orgId}:vendor:${al.id}`), AlertType: al.ruleId ? `${orgId}_${al.ruleId}` : al.name.replace(/\s+/g, ""),
    Status: "New", ConfidenceLevel: "Unknown", StartTime: isoMs(a.firstMs), EndTime: isoMs(a.lastMs), ProcessingEndTime: al.time, IsIncident: false, CompromisedEntity: compromised,
    Tactics: al.tactics.join(","), Techniques: JSON.stringify(al.techniques), Entities: entitiesColumn(entities), ExtendedProperties: JSON.stringify({ "Analytic Rule Ids": al.ruleId ? [al.ruleId] : [] }),
    SourceSystem: "Detection", WorkspaceSubscriptionId: seededUuid(`${orgId}:sub`), WorkspaceResourceGroup: `rg-${orgId}-sentinel`, ...feed,
  };
}

// ── Incidents (entity grouping) ──────────────────────────────────────────────

/** Sentinel's default grouping lookback (PT5H). */
const GROUP_WINDOW_MS = 5 * 3_600_000;
/** A scheduled rule's run: the default five minutes. */
const RULE_RUN_MS = 300_000;
const NUMBER_BASE = (companyId: string) => seededInt(`${companyId}:incident-base`, 2100, 8900);

/** Entities that tie alerts together: people, machines, outside addresses, outside domains. An internal IP is shared infrastructure. */
function groupingIds(ids: string[], book: Record<string, SentinelEntity>): string[] {
  return ids.filter(id => {
    const e = book[id];
    if (!e) return false;
    if (e.kind === "account" || e.kind === "host" || e.kind === "mailbox" || e.kind === "domain") return true;
    return e.kind === "ip" && !isPrivateIp(e.name);
  });
}

const SINGLE_PRODUCT_NOUN: Record<string, string> = { host: "one endpoint", account: "one user" };

function incidentTitle(alerts: SentinelAlert[], entities: SentinelEntity[]): string {
  const names = [...new Set(alerts.map(a => a.name))];
  if (names.length === 1) {
    if (alerts.length === 1) return names[0];
    const who = entities.find(e => e.kind === "account") ?? entities.find(e => e.kind === "host");
    return who ? `${names[0]} involving ${who.name}` : names[0];
  }
  const tactics = [...new Set(alerts.flatMap(a => a.tactics))].slice(0, 2).map(t => t.replace(/([a-z])([A-Z])/g, "$1 $2"));
  const hosts = entities.filter(e => e.kind === "host").length;
  const users = entities.filter(e => e.kind === "account").length;
  const where = hosts > 1 ? "multiple endpoints" : hosts === 1 ? SINGLE_PRODUCT_NOUN.host : users > 1 ? "multiple users" : SINGLE_PRODUCT_NOUN.account;
  const sources = new Set(alerts.map(a => a.product)).size > 1 ? " reported by multiple sources" : "";
  return tactics.length ? `Multi-stage incident involving ${tactics.join(" & ")} on ${where}${sources}` : `Multi-stage incident on ${where}${sources}`;
}

interface Building { first: Pending; members: Pending[]; ids: Set<string>; lastMs: number }

function groupAlerts(pending: Pending[], book: Record<string, SentinelEntity>): Building[] {
  const incidents: Building[] = [];
  const open = new Map<string, Building>();
  for (const p of pending) {
    const keys = groupingIds(p.entries.flatMap(e => e.entityIds), book);
    let into: Building | undefined;
    for (const k of keys) {
      const cand = open.get(k);
      if (cand && p.firstMs - cand.lastMs <= GROUP_WINDOW_MS && (!into || incidents.indexOf(cand) > incidents.indexOf(into))) into = cand;
    }
    if (!into) {
      into = { first: p, members: [], ids: new Set(), lastMs: p.lastMs };
      incidents.push(into);
    }
    into.members.push(p);
    into.lastMs = Math.max(into.lastMs, p.lastMs);
    for (const k of keys) { into.ids.add(k); open.set(k, into); }
  }
  return incidents;
}

export interface SentinelWorkspaceBuild extends SentinelWorkspace {
  coverage: WorkspaceCoverage;
  /** SystemAlertId -> ids of the feed events behind the alert. */
  alertEventIds: Record<string, string[]>;
}

export function buildWorkspace(events: TelemetryEvent[], opts: BuildOptions): SentinelWorkspaceBuild {
  const { companyId, stack, identity } = opts;
  const nativeCtx = makeCtx(companyId, identity ?? {});
  const eff = stackFor(companyId, stack);
  const tenantId = nativeCtx.tenant.azureTenantId;
  const mapCtx: MapContext = { tenantId, cloud: eff.cloud };
  const orgId = (opts.orgName ?? nativeCtx.org).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");

  const tables: Record<string, KqlTable> = Object.fromEntries(TABLE_NAMES.map(n => [n, emptyTable(n)]));

  const coverage: WorkspaceCoverage = { rows: 0, noNativeRecord: {}, noTable: {} };
  const bump = (m: Record<string, number>, k: string) => { m[k] = (m[k] ?? 0) + 1; };

  const book = new EntityBook(COMPANY_ASSETS[companyId]?.roster);
  const entries: Entry[] = [];
  const logs: NativeLog[] = [];
  /** logs[i] -> its entry. */
  const logEntry: Entry[] = [];

  const push = (ev: TelemetryEvent, index: number, log: NativeLog, entry: Entry) => {
    logs.push(log);
    logEntry.push(entry);
    const m = mapRow(log, mapCtx);
    if (!m) { bump(coverage.noTable, logKey(log)); return null; }
    tables[m.table].rows.push(m.row);
    coverage.rows++;
    return m;
  };

  events.forEach((ev, index) => {
    const view = nativeView(ev, companyId, stack, identity);
    const entry: Entry = { index, ev, entityIds: [] };
    if (view) {
      entry.log = view.log;
      const m = push(ev, index, view.log, entry);
      if (m) { entry.table = m.table; entry.row = m.row; }
      const companions = NATIVE_SOURCES[view.log.sourceId]?.companions?.(authoredOf(ev), nativeCtx) ?? [];
      for (const c of companions) push(ev, index, c, entry);
    } else {
      bump(coverage.noNativeRecord, `${ev.source} / ${ev.vendor ?? "?"}`);
    }
    entry.entityIds = book.add(ev, entry.log, entry.row);
    entries.push(entry);
  });

  // ── Raise alerts ────────────────────────────────────────────────────────
  const pending: Pending[] = [];

  for (const e of entries) {
    if (!isProductDetection(e.ev, e.log)) continue;
    const id = raw(e.ev, "SystemAlertId") ?? seededUuid(`${orgId}:product:${e.ev.id}`);
    const { product, provider } = providerOf(e.ev, e.log);
    const techniques = e.ev.mitre_technique ? [e.ev.mitre_technique] : splitList(raw(e.ev, "Techniques"));
    const tactics = e.ev.mitre_tactic ? [tacticName(e.ev.mitre_tactic)] : splitList(raw(e.ev, "Tactics"));
    const ms = Date.parse(e.ev.ts);
    pending.push({
      order: e.index * 1000, entries: [e], firstMs: ms, lastMs: ms, provider,
      alert: {
        id, name: plain(detectionName(e.ev, e.log)), severity: toSeverity(raw(e.ev, "AlertSeverity") ?? e.ev.severity), product,
        description: plain(raw(e.ev, "Description") ?? e.ev.description ?? ""), time: e.ev.ts, tactics: tactics.length ? tactics : tacticsOf(techniques), techniques, query: rowQuery(e, id),
      },
    });
  }

  const inStack = stackUseCases(companyId, stack);
  const bySource = new Map<SourceId, number[]>();
  logs.forEach((l, i) => { bySource.set(l.sourceId, [...(bySource.get(l.sourceId) ?? []), i]); });
  const logsBySource = new Map([...bySource].map(([s, idx]) => [s, idx.map(i => logs[i])]));
  const entryBySource = new Map([...bySource].map(([s, idx]) => [s, idx.map(i => logEntry[i])]));

  /**
   * A scheduled rule's run makes one alert: hits of the same rule, on the same subject, in the same
   * run share it. Keyed by the first hit, so a later event only adds to that alert.
   */
  const runs = new Map<string, Pending>();
  const raise = (ruleId: string, slot: number, hitEntries: Entry[], firstMs: number, lastMs: number, make: (id: string, entries: Entry[], from: number, to: number) => Pending["alert"]) => {
    const lastEntry = hitEntries.reduce((a, b) => (b.index > a.index ? b : a));
    const ev = hitEntries[0].ev;
    const key = `${ruleId}|${Math.floor(firstMs / RULE_RUN_MS)}|${ev.hostname ?? ev.user_email ?? ev.src_ip ?? ""}`;
    const run = runs.get(key);
    if (run) {
      run.entries = [...new Set([...run.entries, ...hitEntries])];
      run.firstMs = Math.min(run.firstMs, firstMs);
      run.lastMs = Math.max(run.lastMs, lastMs);
      run.alert = make(run.alert.id, run.entries, run.firstMs, run.lastMs);
      return;
    }
    const id = seededUuid(`${orgId}:rule:${ruleId}:${ev.id}`);
    const p: Pending = { order: lastEntry.index * 1000 + slot, entries: hitEntries, firstMs, lastMs, provider: SCHEDULED.provider, alert: make(id, hitEntries, firstMs, lastMs) };
    runs.set(key, p);
    pending.push(p);
  };

  inStack.forEach(({ uc, compiled }, ucIndex) => {
    const sl = logsBySource.get(uc.sourceId);
    if (!sl) return;
    const se = entryBySource.get(uc.sourceId)!;
    for (const hit of runUseCase(uc, sl)) {
      const hitEntries = [...new Set(hit.records.map(i => se[i]))].filter(e => e.table);
      if (!hitEntries.length) continue;
      const times = hit.records.map(i => sl[i].timeMs);
      raise(uc.id, 1 + ucIndex, hitEntries, Math.min(...times), Math.max(...times), (id, all, from, to) => ({
        id, name: plain(uc.title), severity: ruleSeverity(uc.severity), product: SCHEDULED.product, description: alertDescription(uc.description), time: isoMs(to), tactics: tacticsOf(uc.mitre), techniques: uc.mitre,
        ruleId: uc.id, query: ruleAlertQuery(compiled, uc, all, from, to, hit.groupKey),
      }));
    }
  });

  const entryOfRow = new Map<KqlRow, Entry>();
  for (const e of entries) if (e.row) entryOfRow.set(e.row, e);
  NOISE_RULES.forEach((rule, i) => {
    for (const part of rule.parts) {
      const rows = tables[part.table].rows;
      if (!rows.length) continue;
      for (const hit of evaluatePart(part, rows)) {
        const hitEntries = hit.rows.map(r => entryOfRow.get(r)).filter((e): e is Entry => !!e);
        if (!hitEntries.length) continue;
        const times = hit.rows.map(r => Date.parse(String(r.TimeGenerated)));
        raise(rule.id, 500 + i, hitEntries, Math.min(...times), Math.max(...times), (id, _all, from, to) => ({
          id, name: rule.name, severity: rule.severity, product: SCHEDULED.product, description: rule.description, time: isoMs(to), tactics: rule.tactics, techniques: rule.techniques,
          ruleId: rule.id, query: [part.table, `| where ${part.where}`, between(from, to), ...(part.threshold ? [`| where ${part.threshold.by} == ${kstr(String(hit.rows[0][part.threshold.by]))}`] : [])].join("\n"),
        }));
      }
    }
  });

  pending.sort((a, b) => a.order - b.order);

  // ── Entities and incidents ──────────────────────────────────────────────
  const used = new Set(pending.flatMap(p => p.entries.flatMap(e => e.entityIds)));
  const entities = book.resolve(used);
  const alerts: SentinelAlert[] = pending.map(p => ({ ...p.alert, entityIds: [...new Set(p.entries.flatMap(e => e.entityIds))] }));
  pending.forEach((p, i) => {
    tables.SecurityAlert.rows.push(alertRow(p, alerts[i].entityIds.map(id => entities[id]).filter(Boolean), tenantId, orgId));
  });
  const alertOf = new Map(pending.map((p, i) => [p, alerts[i]]));

  const base = NUMBER_BASE(companyId);
  const incidents: SentinelIncident[] = groupAlerts(pending, entities).map((b, i) => {
    const members = b.members.map(m => alertOf.get(m)!);
    const ids = [...new Set(members.flatMap(a => a.entityIds))];
    const ents = ids.map(id => entities[id]).filter(Boolean);
    const severity = members.reduce<SentinelSeverity>((s, a) => (SEV_RANK[a.severity] > SEV_RANK[s] ? a.severity : s), "Informational");
    const title = incidentTitle(members, ents);
    const products = [...new Set(members.map(a => a.product))];
    const techniques = [...new Set(members.flatMap(a => a.techniques))];
    const tactics = [...new Set(members.flatMap(a => a.tactics))];
    const created = members[0].time;
    const lastUpdate = members[members.length - 1].time;
    const eventIds = new Set(b.members.flatMap(m => m.entries.map(e => e.ev.id)));
    const distinctQueries = [...new Set(members.map(a => a.query))];
    const incident: SentinelIncident = {
      number: base + i, id: seededUuid(`${orgId}:incident:${members[0].id}`), title, severity, created, lastUpdate, alertIds: members.map(a => a.id), entityIds: ids, tactics, techniques, products,
      description: members.length === 1 ? members[0].description : `${members.length} alerts from ${products.length} ${products.length === 1 ? "product" : "products"} share ${ents.slice(0, 3).map(e => e.name).join(", ")}.`,
      eventCount: eventIds.size,
      eventsQuery: distinctQueries.length === 1 ? distinctQueries[0] : `union\n${distinctQueries.map(q => `(${q.replace(/\n/g, "\n  ")})`).join(",\n")}`,
    };
    tables.SecurityIncident.rows.push({
      TimeGenerated: lastUpdate, Type: "SecurityIncident", TenantId: tenantId, IncidentName: incident.id, IncidentNumber: incident.number, Title: title, Description: incident.description, Severity: severity, Status: "New",
      CreatedTime: created, LastModifiedTime: lastUpdate, FirstActivityTime: created, LastActivityTime: lastUpdate, FirstModifiedTime: created, AlertIds: incident.alertIds, BookmarkIds: [], Comments: [], Tasks: [], Labels: [],
      Owner: { objectId: null, email: null, assignedTo: null, userPrincipalName: null }, ProviderName: "Azure Sentinel", ProviderIncidentId: String(incident.number), ModifiedBy: "Microsoft Sentinel",
      RelatedAnalyticRuleIds: [...new Set(members.map(a => a.ruleId).filter(Boolean))], AdditionalData: { alertsCount: members.length, bookmarksCount: 0, commentsCount: 0, alertProductNames: products, tactics, techniques },
      IncidentUrl: `https://portal.azure.com/#asset/Microsoft_Azure_Security_Insights/Incident/subscriptions/${seededUuid(`${orgId}:sub`)}/resourceGroups/rg-${orgId}-sentinel/providers/Microsoft.OperationalInsights/workspaces/${orgId}-sentinel-prod/providers/Microsoft.SecurityInsights/Incidents/${incident.id}`,
      SourceSystem: "Azure",
    });
    return incident;
  });

  const alertEventIds = Object.fromEntries(pending.map((p, i) => [alerts[i].id, p.entries.map(e => e.ev.id)]));
  const now = events.reduce((m, e) => { const t = Date.parse(e.ts); return t > m ? t : m; }, 0);
  return {
    name: `${orgId}-sentinel-prod`, tables, alerts, incidents, entities,
    rules: [...buildRules(companyId, stack), ...noiseAnalyticsRules()], hunting: buildHunting(), now: new Date(now || 0).toISOString(), coverage, alertEventIds,
  };
}
