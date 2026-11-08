/**
 * buildWorkspace: the released feed as the workspace of the XDR console (KQL tables, alerts, incidents).
 *
 *   TelemetryEvent[] -> native record -> Log Analytics row
 *                    -> SecurityAlert (product detections + analytics rules) -> incidents
 *
 * Input is the public payload only. Deterministic and append-stable: alerts are processed in arrival
 * order, so events added later never change an earlier incident's id, number or first alert.
 */
import { authoredOf, graphAlertFor, NATIVE_SOURCES, nativeView, stackFor, withoutDetectionFeed, type NativeIdentity, type Stack } from "@/lib/logs/native";
import { makeCtx, seededInt, seededUuid } from "@/lib/logs/native/ctx";
import { runUseCase } from "@/lib/logs/native/engine";
import type { NativeLog, SourceId, UseCase } from "@/lib/logs/native/types";
import type { KqlRow, KqlTable } from "@/lib/kql/types";
import { techniqueById } from "@/lib/mitre/attack";
import { COMPANY_ASSETS } from "@/lib/sim/companyProfilesMeta";
import type { TelemetryEvent } from "@/lib/sim/types";
import { EntityBook, entitiesColumn, graphEntitiesColumn, isPrivateIp } from "./entities";
import { buildHunting } from "./hunting";
import { addBaseline } from "./baseline";
import { alignNames, buildDirectory, hostKeyOf, type Directory } from "./directory";
import { fallbackRow, identityColumns, noteAddress, reconcileRow } from "./fallback";
import { logKey, mapRow, type MapContext } from "./mapRow";
import { evaluatePart, NOISE_RULES, noiseAnalyticsRules } from "./noise";
import { alertDescription, buildRules, groupFilter, kstr, plain, ruleSeverity, tacticName, tacticsOf, stackUseCases, type CompiledRule } from "./rules";
import { emptyTable, TABLE_NAMES } from "./tables";
import type { GraphAlertDetails, SentinelAlert, SentinelEntity, SentinelIncident, SentinelSeverity, SentinelWorkspace } from "./types";
import { handoffText, type Handoff } from "@/lib/team/handoff";
import { mentionsConsole, XDR_ACTOR, XDR_PRODUCT, XDR_PROVIDER, xdrValue } from "./xdrBrand";

export interface BuildOptions {
  companyId: string;
  stack?: Stack;
  identity?: NativeIdentity;
  /** The organization shown in the workspace name. */
  orgName?: string;
  /** Cases an analyst escalated: each opens an incident, whatever the rules made of it, and carries
   *  the analyst's report (title, description, first comment) and indicators (entities). */
  escalated?: { eventId: string; summary?: string; handoff?: Handoff }[];
  /** Off for a caller that needs incidents only (the team room). Default on. */
  baseline?: boolean;
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
// The console's own analytics rules raise as XDR Analytics, never as Microsoft Sentinel (xdrBrand.ts).
const SCHEDULED = { product: XDR_PRODUCT, provider: XDR_PROVIDER };

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
  // A SIEM analytics alert in the feed is the console's own analytics: XDR, not Sentinel.
  if (named && /^(?:Azure|Microsoft) Sentinel$/.test(named)) return SCHEDULED;
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

/**
 * `raised`: when the alert first reached the workspace. A scheduled rule's run that takes in a later
 * hit updates the alert (its EndTime and TimeGenerated move on), never the moment it was raised.
 */
interface Pending { alert: Omit<SentinelAlert, "entityIds">; order: number; entries: Entry[]; firstMs: number; lastMs: number; raised: string; provider: string; displayEntity?: string }

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
  const g = al.graph;
  const ev = a.entries[0].ev;
  const feed: KqlRow = {};
  if (!al.ruleId) for (const c of FEED_ALERT_COLUMNS) { const v = raw(ev, c); if (v) feed[c] = v; }
  const compromised = entities.find(e => e.kind === "host")?.name ?? entities.find(e => e.kind === "account")?.name ?? "";
  return {
    TimeGenerated: al.time, Type: "SecurityAlert", TenantId: tenantId, SystemAlertId: al.id, AlertName: al.name, DisplayName: al.name, AlertSeverity: al.severity, Description: al.description,
    ProductName: al.product, ProviderName: a.provider, VendorName: al.product === XDR_PRODUCT ? XDR_ACTOR : "Microsoft", VendorOriginalId: seededUuid(`${orgId}:vendor:${al.id}`), AlertType: al.ruleId ? `${orgId}_${al.ruleId}` : al.name.replace(/\s+/g, ""),
    Status: "New", ConfidenceLevel: "Unknown", StartTime: isoMs(a.firstMs), EndTime: isoMs(a.lastMs), ProcessingEndTime: al.time, IsIncident: false, CompromisedEntity: compromised,
    Tactics: al.tactics.join(","), Techniques: JSON.stringify(al.techniques), Entities: g ? graphEntitiesColumn(g.evidence) : entitiesColumn(entities),
    ExtendedProperties: JSON.stringify({
      "Analytic Rule Ids": al.ruleId ? [al.ruleId] : [],
      ...(g ? { "Graph Alert Id": g.id, "Graph Incident Id": g.incidentId, ServiceSource: g.serviceSource, DetectionSource: g.detectionSource, DetectorId: g.detectorId, Category: g.category, Classification: g.classification, Determination: g.determination } : {}),
    }),
    SourceSystem: "Detection", WorkspaceSubscriptionId: seededUuid(`${orgId}:sub`), WorkspaceResourceGroup: `rg-${orgId}-xdr`, ...feed,
    ...(g ? { VendorOriginalId: g.id, AlertLink: g.alertWebUrl, RemediationSteps: g.recommendedActions, ProductComponentName: g.detectionSource } : {}),
  };
}

// ── Incidents (entity grouping) ──────────────────────────────────────────────

/** Sentinel's default grouping lookback (PT5H). */
const GROUP_WINDOW_MS = 5 * 3_600_000;
/** A scheduled rule's run: the default five minutes. */
const RULE_RUN_MS = 300_000;
/** Below this many logs around its host or account, a single alert leaves nothing to investigate. */
export const MIN_INVESTIGATION_LOGS = 3;
const ALWAYS_REVIEWED = new Set(["CommandAndControl", "Impact"]);

/**
 * Sentinel is where the team investigates in depth (Tal, 2026-11-07), so an incident opens only when
 * there is something to work: several alerts tied to one another, or one high-severity alert with
 * activity around it to pull on, or one alert of a kind a SOC never leaves alone (command and control,
 * impact). An analyst's escalation always opens one. Anything else stays a
 * SecurityAlert row, which KQL can still reach. The test reads only what a real rule sees, never
 * whether the activity is an attack.
 */
export function warrantsInvestigation(alertCount: number, severity: SentinelSeverity, logsAround: number, tactics: string[] = []): boolean {
  if (alertCount >= 2 || tactics.some(t => ALWAYS_REVIEWED.has(t))) return true;
  return severity === "High" && logsAround >= MIN_INVESTIGATION_LOGS;
}

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

/**
 * Rendering an event is deterministic, and the console rebuilds every 6 seconds from the same events:
 * a session renders each event once.
 */
interface Rendered { view: ReturnType<typeof nativeView>; graph?: GraphAlertDetails }
const RENDERS = new Map<string, Map<string, Rendered>>();
function renderMemo(session: string): Map<string, Rendered> {
  let m = RENDERS.get(session);
  if (m) { RENDERS.delete(session); RENDERS.set(session, m); return m; }
  m = new Map();
  RENDERS.set(session, m);
  if (RENDERS.size > 4) RENDERS.delete(RENDERS.keys().next().value as string);
  return m;
}

export interface SentinelWorkspaceBuild extends SentinelWorkspace {
  coverage: WorkspaceCoverage;
  /** SystemAlertId -> ids of the feed events behind the alert. */
  alertEventIds: Record<string, string[]>;
  /** Feed event id -> the rows that hold it. */
  eventRows: Record<string, { table: string; row: KqlRow }[]>;
  /** The session's people and hosts, when the baseline is on. */
  directory?: Directory;
  /** Background and inventory rows in the tables. */
  baselineRows: number;
}

export function buildWorkspace(events: TelemetryEvent[], opts: BuildOptions): SentinelWorkspaceBuild {
  const { companyId, identity } = opts;
  // The logs render as their own products. A Microsoft detection gets its Graph alert on top: the
  // Defender records and AlertEvidence stay.
  const stack = opts.stack && withoutDetectionFeed(opts.stack);
  const memo = renderMemo(JSON.stringify([companyId, stack ?? {}, identity ?? null]));
  const rendered = (ev: TelemetryEvent): Rendered => {
    const key = `${ev.id}|${ev.ts}`;
    let r = memo.get(key);
    if (!r) {
      const graph = graphAlertFor(ev, companyId, stack, identity);
      r = { view: nativeView(ev, companyId, stack, identity), graph: graph ? ((graph.record as { data: Record<string, unknown> }).data["ms-graph"] as GraphAlertDetails) : undefined };
      memo.set(key, r);
    }
    return r;
  };
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
  const eventRows: SentinelWorkspaceBuild["eventRows"] = {};
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
    (eventRows[ev.id] ??= []).push(m);
    return m;
  };

  // What analysts escalated, by feed event: the summary and the whole hand-off.
  const escalated = new Map((opts.escalated ?? []).map(c => [c.eventId, c.summary]));
  const handoffOf = new Map((opts.escalated ?? []).filter(c => c.handoff).map(c => [c.eventId, c.handoff as Handoff]));

  events.forEach((ev, index) => {
    const { view } = rendered(ev);
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
    // The analyst's indicators on an escalated log are entities of every alert that holds it.
    const h = handoffOf.get(ev.id);
    if (h) {
      const ms = Date.parse(ev.ts);
      for (const i of h.iocs) { const id = book.addIndicator(i.type, i.value, ms); if (id && !entry.entityIds.includes(id)) entry.entityIds.push(id); }
    }
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
    const { graph } = rendered(e.ev);
    pending.push({
      order: e.index * 1000, entries: [e], firstMs: ms, lastMs: ms, raised: e.ev.ts, provider,
      alert: {
        ...(graph ? { graph } : {}),
        id, name: plain(graph?.title ?? detectionName(e.ev, e.log)), severity: toSeverity(graph?.severity ?? raw(e.ev, "AlertSeverity") ?? e.ev.severity), product,
        description: plain(raw(e.ev, "Description") ?? e.ev.description ?? ""), time: e.ev.ts, tactics: tactics.length ? tactics : tacticsOf(techniques), techniques, query: rowQuery(e, id),
      },
    });
  }

  const inStack = stackUseCases(companyId, stack);
  const bySource = new Map<SourceId, number[]>();
  logs.forEach((l, i) => {
    const list = bySource.get(l.sourceId);
    if (list) list.push(i); else bySource.set(l.sourceId, [i]);
  });
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
    const alert = make(id, hitEntries, firstMs, lastMs);
    const p: Pending = { order: lastEntry.index * 1000 + slot, entries: hitEntries, firstMs, lastMs, raised: alert.time, provider: SCHEDULED.provider, alert };
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

  // An escalated log that no rule raised still reaches the team as an alert of its own, named by the
  // analyst's own summary and described by their report (owner, 2026-11-08: no generic prefix).
  const raisedEvents = new Set(pending.flatMap(p => p.entries.map(e => e.ev.id)));
  const escalatedAlertIds = new Set<string>();
  for (const e of entries) {
    if (!escalated.has(e.ev.id) || raisedEvents.has(e.ev.id)) continue;
    const id = seededUuid(`${orgId}:escalated:${e.ev.id}`);
    escalatedAlertIds.add(id);
    const ms = Date.parse(e.ev.ts);
    const techniques = e.ev.mitre_technique ? [e.ev.mitre_technique] : [];
    pending.push({
      order: e.index * 1000 + 999, entries: [e], firstMs: ms, lastMs: ms, raised: e.ev.ts, provider: SCHEDULED.provider,
      alert: {
        id, name: plain(handoffOf.get(e.ev.id)?.summary || escalated.get(e.ev.id) || `Escalated for investigation: ${e.ev.description ?? e.ev.event_type}`), severity: toSeverity(e.ev.severity), product: SCHEDULED.product,
        description: plain(handoffOf.has(e.ev.id) ? handoffText(handoffOf.get(e.ev.id)!) : escalated.get(e.ev.id) || e.ev.description || "Escalated by an analyst."), time: e.ev.ts, tactics: tacticsOf(techniques), techniques, query: rowQuery(e, id),
      },
    });
  }

  pending.sort((a, b) => a.order - b.order);

  // ── Entities and incidents ──────────────────────────────────────────────
  const used = new Set(pending.flatMap(p => p.entries.flatMap(e => e.entityIds)));
  const entities = book.resolve(used);
  const alerts: SentinelAlert[] = pending.map(p => ({ ...p.alert, entityIds: [...new Set(p.entries.flatMap(e => e.entityIds))] }));
  pending.forEach((p, i) => {
    tables.SecurityAlert.rows.push(alertRow(p, alerts[i].entityIds.map(id => entities[id]).filter(Boolean), tenantId, orgId));
  });
  const alertOf = new Map(pending.map((p, i) => [p, alerts[i]]));

  // Logs per host and per account, for how much there is to pull on around an alert. A host entity is
  // named by its short name (web-01 for web-01.example.org), so its logs count under that name.
  const logsOf = new Map<string, number>();
  for (const e of events) {
    for (const k of [e.hostname?.split(".")[0], e.user?.email ?? e.user_email]) if (k) logsOf.set(k.toLowerCase(), (logsOf.get(k.toLowerCase()) ?? 0) + 1);
  }

  const base = NUMBER_BASE(companyId);
  const incidents: SentinelIncident[] = [];
  const numbers = new Set<number>();
  groupAlerts(pending, entities).forEach(b => {
    const members = b.members.map(m => alertOf.get(m)!);
    const ids = [...new Set(members.flatMap(a => a.entityIds))];
    const ents = ids.map(id => entities[id]).filter(Boolean);
    const severity = members.reduce<SentinelSeverity>((s, a) => (SEV_RANK[a.severity] > SEV_RANK[s] ? a.severity : s), "Informational");
    const logsAround = Math.max(0, ...ents.filter(e => e.kind === "host" || e.kind === "account").map(e => logsOf.get(e.name.toLowerCase()) ?? 0));
    const wasEscalated = b.members.some(m => m.entries.some(e => escalated.has(e.ev.id)));
    if (!wasEscalated && !warrantsInvestigation(members.length, severity, logsAround, [...new Set(members.flatMap(a => a.tactics))])) return;
    // Numbered from the feed position of its first alert, so nothing that arrives later renumbers it.
    let number = base + Math.floor(b.members[0].order / 1000);
    while (numbers.has(number)) number++;
    numbers.add(number);
    const title = incidentTitle(members, ents);
    const products = [...new Set(members.map(a => a.product))];
    const techniques = [...new Set(members.flatMap(a => a.techniques))];
    const tactics = [...new Set(members.flatMap(a => a.tactics))];
    // Created when its first alert was raised: a later hit that joins that alert's rule run moves the
    // alert's end, not the incident's birth.
    const created = b.first.raised;
    const lastUpdate = members[members.length - 1].time;
    const eventIds = new Set(b.members.flatMap(m => m.entries.map(e => e.ev.id)));
    const distinctQueries = [...new Set(members.map(a => a.query))];
    // The analysts' reports on the logs behind it, oldest first: the incident opens with them.
    const handoffs = [...eventIds].map(id => handoffOf.get(id)).filter((x): x is Handoff => !!x).sort((a, b) => Date.parse(a.at ?? "") - Date.parse(b.at ?? ""));
    const detection = members.length === 1 ? members[0].description : `${members.length} alerts from ${products.length} ${products.length === 1 ? "product" : "products"} share ${ents.slice(0, 3).map(e => e.name).join(", ")}.`;
    // Opened by the escalation alone: the analyst's report is the whole description.
    const onlyEscalated = handoffs.length > 0 && members.every(a => escalatedAlertIds.has(a.id));
    const incident: SentinelIncident = {
      number, id: seededUuid(`${orgId}:incident:${members[0].id}`), title, severity, created, lastUpdate, alertIds: members.map(a => a.id), entityIds: ids, tactics, techniques, products,
      description: handoffs.length ? [...handoffs.map(h => plain(handoffText(h))), ...(onlyEscalated ? [] : [`Detection: ${detection}`])].join("\n\n") : detection,
      ...(handoffs.length ? { handoffs, ...(onlyEscalated ? {} : { detectionDescription: detection }) } : {}),
      eventCount: eventIds.size,
      eventsQuery: distinctQueries.length === 1 ? distinctQueries[0] : `union\n${distinctQueries.map(q => `(${q.replace(/\n/g, "\n  ")})`).join(",\n")}`,
    };
    tables.SecurityIncident.rows.push({
      TimeGenerated: lastUpdate, Type: "SecurityIncident", TenantId: tenantId, IncidentName: incident.id, IncidentNumber: incident.number, Title: title, Description: incident.description, Severity: severity, Status: "New",
      CreatedTime: created, LastModifiedTime: lastUpdate, FirstActivityTime: created, LastActivityTime: lastUpdate, FirstModifiedTime: created, AlertIds: incident.alertIds, BookmarkIds: [], Comments: [], Tasks: [],
      // An escalated incident keeps its rule's title and carries a tag (owner review 2026-11-08), as a real SOC's automation tags it.
      Labels: [...new Set(handoffs.map(h => h.from))].map(name => ({ labelName: `Escalated by ${name}`, labelType: "AutoAssigned" })),
      Owner: { objectId: null, email: null, assignedTo: null, userPrincipalName: null }, ProviderName: XDR_ACTOR, ProviderIncidentId: String(incident.number), ModifiedBy: XDR_ACTOR,
      RelatedAnalyticRuleIds: [...new Set(members.map(a => a.ruleId).filter(Boolean))], AdditionalData: { alertsCount: members.length, bookmarksCount: 0, commentsCount: 0, alertProductNames: products, tactics, techniques },
      IncidentUrl: `/xdr?incident=${incident.id}`,
      SourceSystem: XDR_ACTOR,
    });
    incidents.push(incident);
  });

  const alertEventIds = Object.fromEntries(pending.map((p, i) => [alerts[i].id, p.entries.map(e => e.ev.id)]));
  const now = events.reduce((m, e) => { const t = Date.parse(e.ts); return t > m ? t : m; }, 0);

  // ── The rest of the workspace ───────────────────────────────────────────
  // Everything below comes after the rules: none of it can raise an alert.

  // Graph alerts, as a Logic App or connector ingestion would land them: no built-in table holds alerts_v2.
  for (const a of alerts) {
    const g = a.graph;
    if (!g) continue;
    tables.GraphSecurityAlerts_CL.rows.push({
      TimeGenerated: a.time, Type: "GraphSecurityAlerts_CL", TenantId: tenantId, id: g.id, providerAlertId: g.providerAlertId, incidentId: g.incidentId, title: g.title, description: g.description, severity: g.severity, status: g.status,
      classification: g.classification, determination: g.determination, serviceSource: g.serviceSource, detectionSource: g.detectionSource, productName: g.productName, detectorId: g.detectorId, category: g.category,
      ...(g.threatDisplayName ? { threatDisplayName: g.threatDisplayName } : {}), mitreTechniques: g.mitreTechniques, evidence: g.evidence, alertWebUrl: g.alertWebUrl, incidentWebUrl: g.incidentWebUrl, createdDateTime: g.createdDateTime,
      lastUpdateDateTime: g.lastUpdateDateTime, firstActivityDateTime: g.firstActivityDateTime, lastActivityDateTime: g.lastActivityDateTime,
    });
  }

  // A detection with no log of its own lives in SecurityAlert.
  pending.forEach((p, i) => {
    if (alerts[i].ruleId || p.entries.length !== 1) return;
    const id = p.entries[0].ev.id;
    if (!eventRows[id]) (eventRows[id] ??= []).push({ table: "SecurityAlert", row: tables.SecurityAlert.rows[i] });
  });
  for (const e of entries) {
    if (eventRows[e.ev.id]) continue;
    const { table, row } = fallbackRow(e.ev, nativeCtx, e.log?.record, e.log?.sourceId);
    tables[table].rows.push(row);
    coverage.rows++;
    eventRows[e.ev.id] = [{ table, row }];
  }
  for (const e of entries) for (const m of eventRows[e.ev.id] ?? []) if (m.table !== "SecurityAlert") reconcileRow(m.table, m.row, e.ev);

  let baselineRows = 0;
  let directory: Directory | undefined;
  if (opts.baseline !== false && events.length) {
    directory = buildDirectory(events, id => (eventRows[id] ?? []).map(x => x.row), companyId, nativeCtx, identity);
    alignNames(directory, tables);
    // An address that only a row with no IP column knows is still found by a search.
    const hostAddresses = new Set([...directory.hosts.values()].flatMap(h => [h.ip, ...h.otherIps]));
    for (const e of entries) {
      for (const ip of [e.ev.src_ip, e.ev.dst_ip]) {
        if (!ip || hostAddresses.has(ip)) continue;
        for (const m of (eventRows[e.ev.id] ?? []).slice(0, 1)) if (!identityColumns(m.table)?.ip) noteAddress(m.table, m.row, ip);
      }
    }
    for (const e of Object.values(entities)) {
      if (e.kind === "account") {
        const p = directory.people.get(e.name.toLowerCase());
        if (p) e.info = { ...e.info, ...(p.department && !e.info.Department ? { Department: p.department } : {}), ...(p.title && !e.info.Title ? { Title: p.title } : {}), "Usual host": p.host };
      } else if (e.kind === "host") {
        const h = directory.hosts.get(hostKeyOf(e.name));
        if (h) e.info = { ...e.info, IP: h.ip, ...(e.info.OS ? {} : { OS: h.os }) };
      }
    }
    const hostLastSeen = new Map<string, number>();
    for (const e of events) if (e.hostname) hostLastSeen.set(hostKeyOf(e.hostname), Math.max(hostLastSeen.get(hostKeyOf(e.hostname)) ?? 0, Date.parse(e.ts)));
    baselineRows = addBaseline(tables, { companyId, stack, identity, orgName: opts.orgName, tenantId, anchorMs: Date.parse(events[0].ts), clockMs: now, directory, hostLastSeen });
  }

  // XDR is the console's name wherever the analyst reads (xdrBrand.ts): a feed row or an authored
  // text that names Microsoft Sentinel as the SIEM reads as XDR here. Rows are this build's own
  // objects (eventRows points at them), so they change in place; nested values copy on write.
  // Only rows that can carry the name are walked (this runs on every poll): the alert and incident
  // tables, and the rows of events whose payload mentions it.
  const fix = (row: KqlRow) => { for (const k of Object.keys(row)) { const v = row[k]; const x = xdrValue(v); if (x !== v) row[k] = x; } };
  for (const t of ["SecurityAlert", "SecurityIncident"]) for (const row of tables[t]?.rows ?? []) fix(row);
  for (const ev of events) if (mentionsConsole(ev)) for (const m of eventRows[ev.id] ?? []) fix(m.row);
  for (const item of [...alerts, ...incidents] as unknown as Record<string, unknown>[]) for (const k of Object.keys(item)) { const v = item[k]; const x = xdrValue(v); if (x !== v) item[k] = x; }

  return {
    name: `${orgId}-xdr-prod`, tables, alerts, incidents, entities,
    rules: xdrValue([...buildRules(companyId, stack), ...noiseAnalyticsRules()]), hunting: xdrValue(buildHunting()), now: new Date(now || 0).toISOString(), coverage, alertEventIds, eventRows, directory, baselineRows,
  };
}
