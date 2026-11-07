// Pure helpers of the Sentinel console: formatting, query text, similarity and exploration.
// Nothing here touches React or the KQL engine, so all of it is cheap to test.
import type { KqlColumn, KqlRow, KqlTable } from "@/lib/kql/types";
import type {
  ClosingClassification, EntityKind, IncidentState, IncidentStatus, SentinelAlert, SentinelBookmark,
  SentinelEntity, SentinelIncident, SentinelSeverity, SentinelWorkspace,
} from "@/lib/sentinel/types";

export const SEVERITIES: SentinelSeverity[] = ["High", "Medium", "Low", "Informational"];
export const SEV_RANK: Record<SentinelSeverity, number> = { High: 0, Medium: 1, Low: 2, Informational: 3 };
export const STATUSES: IncidentStatus[] = ["New", "Active", "Closed"];
export const CLASSIFICATIONS: ClosingClassification[] = [
  "True Positive - suspicious activity",
  "Benign Positive - suspicious but expected",
  "False Positive - incorrect alert logic",
  "False Positive - incorrect data",
  "Undetermined",
];
export const KIND_LABEL: Record<EntityKind, string> = {
  account: "Account", host: "Host", ip: "IP", file: "File", process: "Process", url: "URL", domain: "DNS",
  mailbox: "Mailbox", cloudapp: "Cloud application", azureresource: "Azure resource", registry: "Registry key",
};
/** The product offers Add to TI for these types only. */
export const TI_KINDS: EntityKind[] = ["ip", "domain", "url", "file"];
/** The only playbooks that exist here act on devices. */
export const PLAYBOOK_KINDS: EntityKind[] = ["host"];

const noDash = (s: string) => s.replace(/\s*\u2014\s*/g, ", ");

/** Rule and alert text comes from shared content that may carry em dashes. The console shows none. */
export function tidyWorkspace(ws: SentinelWorkspace): SentinelWorkspace {
  return {
    ...ws,
    rules: ws.rules.map(r => ({ ...r, name: noDash(r.name), description: noDash(r.description), falsePositives: r.falsePositives.map(noDash) })),
    hunting: ws.hunting.map(h => ({ ...h, name: noDash(h.name), description: noDash(h.description) })),
    alerts: ws.alerts.map(a => ({ ...a, name: noDash(a.name), description: noDash(a.description) })),
    incidents: ws.incidents.map(i => ({ ...i, title: noDash(i.title), description: noDash(i.description) })),
  };
}

export function defaultState(i: Pick<SentinelIncident, "severity">): IncidentState {
  return { status: "New", owner: null, severity: i.severity, comments: [], bookmarks: [], tasks: [], activity: [] };
}

const pad = (n: number, w = 2) => String(n).padStart(w, "0");
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/** 1/12/2023, 10:47:07 PM, always in UTC, as the portal shows with Display time UTC. */
export function fmtDateTime(iso: string | number | Date | null | undefined): string {
  if (iso == null || iso === "") return "-";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  const h = d.getUTCHours();
  return `${d.getUTCMonth() + 1}/${d.getUTCDate()}/${d.getUTCFullYear()}, ${h % 12 || 12}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} ${h < 12 ? "AM" : "PM"}`;
}
export function fmtMonthDay(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "" : `${MONTHS[d.getUTCMonth()]} ${d.getUTCDate()}`;
}
export function fmtClock(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "" : `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
}
export function fmtDuration(ms: number): string {
  const s = Math.max(0, ms) / 1000;
  return `${pad(Math.floor(s / 60))}:${pad(Math.floor(s % 60))}.${pad(Math.floor((s % 1) * 1000), 3)}`;
}
/** 12/26/22, 01:38 PM: the grid, the preview and the activity log. */
export function fmtShortTime(iso: string | number | Date | null | undefined): string {
  if (iso == null || iso === "") return "-";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  const h = d.getUTCHours();
  return `${pad(d.getUTCMonth() + 1)}/${pad(d.getUTCDate())}/${pad(d.getUTCFullYear() % 100)}, ${pad(h % 12 || 12)}:${pad(d.getUTCMinutes())} ${h < 12 ? "AM" : "PM"}`;
}
/** 1/12/2023, 03:27 PM: Similar incidents and the alert flyout. */
export function fmtMediumTime(iso: string | number | Date | null | undefined): string {
  if (iso == null || iso === "") return "-";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  const h = d.getUTCHours();
  return `${d.getUTCMonth() + 1}/${d.getUTCDate()}/${d.getUTCFullYear()}, ${pad(h % 12 || 12)}:${pad(d.getUTCMinutes())} ${h < 12 ? "AM" : "PM"}`;
}
/** 2s 567ms, as the Logs panel footer shows a run. */
export function fmtElapsed(ms: number): string {
  const whole = Math.max(0, Math.round(ms));
  return whole < 1000 ? `${whole}ms` : `${Math.floor(whole / 1000)}s ${whole % 1000}ms`;
}
/** 1.2K: the KPI tiles. */
export function fmtCompact(n: number): string {
  return n >= 1000 ? `${+(n / 1000).toFixed(1)}K` : String(n);
}
/** CommandAndControl reads as Command and Control. */
export function tacticLabel(t: string): string {
  return t.replace(/([a-z])([A-Z])/g, "$1 $2").replace(/\bAnd\b/g, "and");
}
export function fmtCount(n: number): string {
  return n.toLocaleString("en-US");
}

/* ------------------------------------------- time range ------------------------------------------ */

export type RangeKey = "30m" | "1h" | "4h" | "12h" | "24h" | "custom";
const MIN = 60_000; const HOUR = 60 * MIN;
export const TIME_RANGES: { key: RangeKey; label: string; ms: number; phrase: string }[] = [
  { key: "30m", label: "Last 30 minutes", ms: 30 * MIN, phrase: "the last 30 minutes" },
  { key: "1h", label: "Last hour", ms: HOUR, phrase: "the last hour" },
  { key: "4h", label: "Last 4 hours", ms: 4 * HOUR, phrase: "the last 4 hours" },
  { key: "12h", label: "Last 12 hours", ms: 12 * HOUR, phrase: "the last 12 hours" },
  { key: "24h", label: "Last 24 hours", ms: 24 * HOUR, phrase: "the last 24 hours" },
];

/** Value of an <input type="datetime-local"> read as UTC, the console's only display zone. */
export function isoToLocalInput(iso: string): string { return iso.slice(0, 16); }
export function localInputToDate(v: string): Date { return new Date(`${v}:00.000Z`); }

/* ------------------------------------------ query text ------------------------------------------- */

export interface QueryBlock { start: number; end: number; text: string; firstLine: number }

/** A blank line ends a query: the one under the cursor is what Run sends, as in Log Analytics. */
export function queryBlockAt(text: string, cursor: number): QueryBlock {
  const lines = text.split("\n");
  const offsets: number[] = [];
  let at = 0;
  for (const l of lines) { offsets.push(at); at += l.length + 1; }
  let line = 0;
  for (let i = 0; i < lines.length; i++) if (offsets[i] <= cursor) line = i;
  const blank = (i: number) => lines[i].trim() === "";
  let i = line;
  if (blank(i)) {
    let up = i; while (up >= 0 && blank(up)) up--;
    let down = i; while (down < lines.length && blank(down)) down++;
    if (up >= 0) i = up; else if (down < lines.length) i = down; else return { start: 0, end: text.length, text: "", firstLine: 0 };
  }
  let a = i; while (a > 0 && !blank(a - 1)) a--;
  let b = i; while (b < lines.length - 1 && !blank(b + 1)) b++;
  const start = offsets[a];
  const end = offsets[b] + lines[b].length;
  return { start, end, text: text.slice(start, end), firstLine: a };
}

/** The opening `| take 100`-free query a table double-click or a Run on a table would produce. */
export function kqlString(s: string): string {
  return `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n").replace(/\r/g, "\\r").replace(/\t/g, "\\t")}"`;
}
export function kqlIdent(name: string): string {
  return /^[A-Za-z_][A-Za-z0-9_]*$/.test(name) ? name : `['${name.replace(/'/g, "\\'")}']`;
}

/** The line Include or Exclude appends to the query. */
export function whereClause(col: KqlColumn, value: unknown, exclude: boolean): string {
  const name = kqlIdent(col.name);
  const eq = exclude ? "!=" : "==";
  if (value === null || value === undefined) return `| where ${exclude ? "isnotnull" : "isnull"}(${name})`;
  switch (col.type) {
    case "bool": return `| where ${name} ${eq} ${Boolean(value)}`;
    case "int": case "long": case "real": return `| where ${name} ${eq} ${Number(value)}`;
    case "datetime": {
      const d = new Date(value as string);
      return `| where ${name} ${eq} datetime(${Number.isNaN(d.getTime()) ? String(value) : d.toISOString()})`;
    }
    case "dynamic": return `| where tostring(${name}) ${eq} ${kqlString(typeof value === "string" ? value : JSON.stringify(value))}`;
    case "guid": case "timespan": return `| where tostring(${name}) ${eq} ${kqlString(String(value))}`;
    default:
      if (value === "") return `| where ${exclude ? "isnotempty" : "isempty"}(${name})`;
      return `| where ${name} ${eq} ${kqlString(String(value))}`;
  }
}

/** Formula cells in a spreadsheet run on open, and log text is attacker-controlled: quote them. */
export function toCsv(columns: string[], rows: string[][]): string {
  const cell = (v: string) => {
    const safe = /^[=+\-@\t\r]/.test(v) ? `'${v}` : v;
    return /[",\n\r]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
  };
  return [columns.map(cell).join(","), ...rows.map(r => r.map(cell).join(","))].join("\r\n");
}

/* --------------------------------------------- incidents ------------------------------------------ */

export function alertsOf(incident: SentinelIncident, ws: SentinelWorkspace): SentinelAlert[] {
  const ids = new Set(incident.alertIds);
  return ws.alerts.filter(a => ids.has(a.id));
}
export function entitiesOf(incident: SentinelIncident, ws: SentinelWorkspace): SentinelEntity[] {
  return incident.entityIds.map(id => ws.entities[id]).filter((e): e is SentinelEntity => !!e);
}
export function alertsQuery(incident: SentinelIncident): string {
  return `SecurityAlert\n| where SystemAlertId in (${incident.alertIds.map(kqlString).join(", ")})`;
}
export function bookmarksQuery(incident: SentinelIncident): string {
  return `HuntingBookmark\n| where IncidentInfo has ${kqlString(incident.id)}\n| project TimeGenerated, BookmarkName, Notes, QueryText, CreatedBy, Entities`;
}

export interface SimilarIncident { incident: SentinelIncident; reason: string; common: string[]; entities: SentinelEntity[]; rules: string[]; score: number }

/** Up to 20 other incidents, ranked by shared entities and shared detections. */
export function similarIncidents(incident: SentinelIncident, ws: SentinelWorkspace): SimilarIncident[] {
  const mine = new Set(incident.entityIds);
  const mineAlerts = alertsOf(incident, ws);
  const myRules = new Set(mineAlerts.map(a => a.ruleId ?? a.name));
  const out: SimilarIncident[] = [];
  for (const other of ws.incidents) {
    if (other.id === incident.id) continue;
    const shared = other.entityIds.filter(e => mine.has(e));
    const rules = [...new Set(alertsOf(other, ws).map(a => a.ruleId ?? a.name))].filter(r => myRules.has(r));
    const sameTitle = other.title === incident.title;
    if (!shared.length && !rules.length && !sameTitle) continue;
    const entities = shared.map(e => ws.entities[e]).filter((e): e is SentinelEntity => !!e);
    const ruleNames = rules.map(r => ws.rules.find(x => x.id === r)?.name ?? r);
    const common = [...entities.map(e => e.name), ...ruleNames];
    out.push({ incident: other, reason: shared.length ? "Similar entities" : "Same rule name", common, entities, rules: ruleNames, score: shared.length * 2 + rules.length * 3 + (sameTitle ? 1 : 0) });
  }
  return out.sort((a, b) => b.score - a.score || Date.parse(b.incident.lastUpdate) - Date.parse(a.incident.lastUpdate)).slice(0, 20);
}

/** Every bookmark the team saved, newest first. */
export function allBookmarks(states: Map<string, IncidentState>): SentinelBookmark[] {
  const seen = new Map<string, SentinelBookmark>();
  for (const s of states.values()) for (const b of s.bookmarks) seen.set(b.id, b);
  return [...seen.values()].sort((a, b) => Date.parse(b.at) - Date.parse(a.at));
}

/** The real HuntingBookmark table: the team's bookmarks live in the event log, so KQL reaches them here. */
export function bookmarkTable(bookmarks: SentinelBookmark[]): KqlTable {
  return {
    name: "HuntingBookmark",
    columns: [
      { name: "TimeGenerated", type: "datetime" }, { name: "BookmarkId", type: "string" }, { name: "BookmarkName", type: "string" },
      { name: "CreatedBy", type: "string" }, { name: "Notes", type: "string" }, { name: "QueryText", type: "string" },
      { name: "QueryResultRow", type: "string" }, { name: "Entities", type: "string" }, { name: "IncidentInfo", type: "string" },
      { name: "Type", type: "string" },
    ],
    rows: bookmarks.map(b => ({
      TimeGenerated: b.at, BookmarkId: b.id, BookmarkName: b.name, CreatedBy: b.author, Notes: b.notes, QueryText: b.query,
      QueryResultRow: JSON.stringify(b.rows), Entities: JSON.stringify(b.entityIds), IncidentInfo: b.incidentId ?? "", Type: "HuntingBookmark",
    })),
  };
}

/* ------------------------------------------ threat indicators ------------------------------------- */

const TI_PREFIX = "Added to threat intelligence";
export const tiComment = (e: SentinelEntity) => `${TI_PREFIX} | ${e.kind} | ${e.name}`;

/** A TI record as a person would read it in the activity log. */
export function commentText(text: string): string {
  const p = text.split(" | ");
  return p.length >= 3 && p[0] === TI_PREFIX ? `Added to threat intelligence: ${p.slice(2).join(" | ")}` : text;
}

export interface Indicator { id: string; kind: EntityKind; name: string; addedBy: string; at: string; incidentId: string }

/** Add to TI is written to the incident's comments: that is the shared, audited record of it. */
export function tiIndicators(states: Map<string, IncidentState>): Indicator[] {
  const out = new Map<string, Indicator>();
  for (const [incidentId, s] of states) {
    for (const c of s.comments) {
      const parts = c.text.split(" | ");
      if (parts.length < 3 || parts[0] !== TI_PREFIX) continue;
      const kind = parts[1] as EntityKind;
      const name = parts.slice(2).join(" | ");
      const id = `${kind}:${name.toLowerCase()}`;
      if (!out.has(id)) out.set(id, { id, kind, name, addedBy: c.author, at: c.at, incidentId });
    }
  }
  return [...out.values()].sort((a, b) => Date.parse(b.at) - Date.parse(a.at));
}

/* --------------------------------------------- entities ------------------------------------------- */

function has(ws: SentinelWorkspace, table: string, ...cols: string[]): boolean {
  const t = ws.tables[table];
  return !!t && cols.every(c => t.columns.some(x => x.name === c));
}

/** The forms an entity name takes in a cell: corp\user, user@corp, host.corp.local. */
function nameKeys(name: string): string[] {
  const n = name.toLowerCase();
  const keys = [n];
  if (n.includes("\\")) keys.push(n.split("\\").pop() as string);
  if (n.includes("@")) keys.push(n.split("@")[0]);
  if (/^[a-z0-9-]+\.[a-z]/.test(n) && !/\.(com|org|net|io|app)$/.test(n)) keys.push(n.split(".")[0]);
  return keys;
}

/** Entities found in result rows: what Add bookmark maps. */
export function entitiesFromRows(rows: KqlRow[], ws: SentinelWorkspace): SentinelEntity[] {
  const index = new Map<string, SentinelEntity>();
  for (const e of Object.values(ws.entities)) for (const k of nameKeys(e.name)) if (!index.has(k)) index.set(k, e);
  const found = new Map<string, SentinelEntity>();
  for (const row of rows) {
    for (const v of Object.values(row)) {
      if (typeof v !== "string" || !v) continue;
      // The Entities column of SecurityAlert and other JSON cells hold the names inside the text.
      if (/^\s*[[{]/.test(v)) {
        const low = v.toLowerCase();
        for (const [k, e] of index) if (k.length > 2 && low.includes(k)) found.set(e.id, e);
        continue;
      }
      if (v.length > 300) continue;
      for (const k of nameKeys(v)) { const e = index.get(k); if (e) found.set(e.id, e); }
    }
  }
  return [...found.values()];
}

const NOT_ACTIVITY = new Set(["SecurityAlert", "SecurityIncident", "AlertInfo", "AlertEvidence"]);

export interface LoggedHost { name: string; first: string; last: string }

export interface EntityActivity {
  hosts: LoggedHost[];
  firstSeen: string | null;
  lastSeen: string | null;
  tables: { name: string; count: number }[];
  recent: { time: string; table: string; text: string }[];
  query: string;
}

/** Log Activity of an entity: where it appears in the workspace, from the rows themselves. */
export function entityActivity(entity: SentinelEntity, ws: SentinelWorkspace): EntityActivity {
  const needle = (entity.kind === "account" ? accountShort(entity.name) : entity.name).toLowerCase();
  const tables: EntityActivity["tables"] = [];
  const recent: EntityActivity["recent"] = [];
  let first = Infinity; let last = -Infinity;
  const hosts = new Map<string, { first: number; last: number }>();
  for (const t of Object.values(ws.tables)) {
    if (NOT_ACTIVITY.has(t.name)) continue;
    let count = 0;
    for (const row of t.rows) {
      let hit = false;
      for (const v of Object.values(row)) {
        if (typeof v === "string" && v.toLowerCase().includes(needle)) { hit = true; break; }
      }
      if (!hit) continue;
      count++;
      const ts = Date.parse(String(row.TimeGenerated ?? ""));
      if (Number.isNaN(ts)) continue;
      first = Math.min(first, ts); last = Math.max(last, ts);
      const host = row.DeviceName ?? row.Computer;
      if (typeof host === "string" && host && entity.name.toLowerCase() !== host.toLowerCase()) {
        const seen = hosts.get(host);
        hosts.set(host, seen ? { first: Math.min(seen.first, ts), last: Math.max(seen.last, ts) } : { first: ts, last: ts });
      }
      recent.push({ time: String(row.TimeGenerated), table: t.name, text: summarizeRow(row) });
    }
    if (count) tables.push({ name: t.name, count });
  }
  recent.sort((a, b) => Date.parse(b.time) - Date.parse(a.time));
  return {
    hosts: [...hosts].map(([name, h]) => ({ name, first: new Date(h.first).toISOString(), last: new Date(h.last).toISOString() })).sort((a, b) => a.name.localeCompare(b.name)),
    firstSeen: Number.isFinite(first) ? new Date(first).toISOString() : null,
    lastSeen: Number.isFinite(last) ? new Date(last).toISOString() : null,
    tables: tables.sort((a, b) => b.count - a.count),
    recent: recent.slice(0, 25),
    query: `search ${kqlString(entity.name)}\n| sort by TimeGenerated desc`,
  };
}

const SUMMARY_COLS = ["Activity", "ActionType", "OperationName", "Operation", "AlertName", "EventID", "ResultDescription", "AppDisplayName", "ProcessCommandLine", "FileName", "Message"];
function summarizeRow(row: KqlRow): string {
  for (const c of SUMMARY_COLS) {
    const v = row[c];
    if (v !== null && v !== undefined && v !== "") return `${c}: ${String(v).slice(0, 120)}`;
  }
  return "Log record";
}

/* ---------------------------------------- exploration queries ------------------------------------- */

export interface Exploration {
  id: string;
  label: string;
  query: string;
  /** Result columns that become nodes on the graph. */
  pick: { col: string; kind: EntityKind | "alert" }[];
}

interface Source { table: string; needs: string[]; query: string; pick: Exploration["pick"] }

/** The same question has a different table per stack: the first one holding rows answers it. */
function answer(ws: SentinelWorkspace, id: string, label: string, sources: Source[]): Exploration[] {
  const fits = sources.filter(s => has(ws, s.table, ...s.needs));
  const best = fits.find(s => (ws.tables[s.table]?.rows.length ?? 0) > 0) ?? fits[0];
  return best ? [{ id, label, query: best.query, pick: best.pick }] : [];
}

/** user@corp and CORP\\user are both `user` in the tables that keep the bare account name. */
function accountShort(name: string): string {
  return name.split("@")[0].split("\\").pop() as string;
}

/** Questions per entity kind. */
export function explorationsFor(entity: SentinelEntity, ws: SentinelWorkspace): Exploration[] {
  const n = kqlString(entity.name);
  const short = kqlString(accountShort(entity.name));
  const related = answer(ws, "related-alerts", "Related alerts", [{
    table: "SecurityAlert", needs: ["Entities", "SystemAlertId"],
    query: `SecurityAlert\n| where Entities has ${entity.kind === "account" ? short : n}\n| project TimeGenerated, AlertName, AlertSeverity, ProductName, SystemAlertId\n| sort by TimeGenerated desc`,
    pick: [{ col: "SystemAlertId", kind: "alert" }],
  }]);
  if (entity.kind === "account") {
    return [
      ...related,
      ...answer(ws, "signins", "Sign-ins for account", [
        {
          table: "SigninLogs", needs: ["UserPrincipalName", "IPAddress"],
          query: `SigninLogs\n| where UserPrincipalName has ${n}\n| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, ResultType, Location\n| sort by TimeGenerated desc`,
          pick: [{ col: "IPAddress", kind: "ip" }, { col: "AppDisplayName", kind: "cloudapp" }],
        },
        {
          table: "SecurityEvent", needs: ["Account", "Computer", "EventID"],
          query: `SecurityEvent\n| where EventID == 4624 and Account has ${short}\n| project TimeGenerated, Account, Computer, IpAddress, LogonType\n| sort by TimeGenerated desc`,
          pick: [{ col: "Computer", kind: "host" }, { col: "IpAddress", kind: "ip" }],
        },
        {
          table: "DeviceLogonEvents", needs: ["AccountName", "DeviceName"],
          query: `DeviceLogonEvents\n| where AccountName has ${short}\n| project TimeGenerated, AccountName, DeviceName, RemoteIP, LogonType, ActionType\n| sort by TimeGenerated desc`,
          pick: [{ col: "DeviceName", kind: "host" }, { col: "RemoteIP", kind: "ip" }],
        },
      ]),
      ...answer(ws, "account-hosts", "Hosts used by account", [{
        table: "DeviceProcessEvents", needs: ["AccountName", "DeviceName"],
        query: `DeviceProcessEvents\n| where AccountName has ${short}\n| summarize Processes = count() by DeviceName\n| sort by Processes desc`,
        pick: [{ col: "DeviceName", kind: "host" }],
      }]),
    ];
  }
  if (entity.kind === "host") {
    return [
      ...related,
      ...answer(ws, "processes", "Processes running on Host", [
        {
          table: "DeviceProcessEvents", needs: ["DeviceName", "FileName"],
          query: `DeviceProcessEvents\n| where DeviceName has ${n}\n| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine\n| sort by TimeGenerated desc`,
          pick: [{ col: "FileName", kind: "process" }],
        },
        {
          table: "SecurityEvent", needs: ["Computer", "EventID", "NewProcessName"],
          query: `SecurityEvent\n| where EventID == 4688 and Computer has ${n}\n| project TimeGenerated, Computer, Account, NewProcessName, CommandLine\n| sort by TimeGenerated desc`,
          pick: [{ col: "NewProcessName", kind: "process" }],
        },
      ]),
      ...answer(ws, "host-connections", "Connections from host", [{
        table: "DeviceNetworkEvents", needs: ["DeviceName", "RemoteIP"],
        query: `DeviceNetworkEvents\n| where DeviceName has ${n}\n| project TimeGenerated, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName\n| sort by TimeGenerated desc`,
        pick: [{ col: "RemoteIP", kind: "ip" }],
      }]),
    ];
  }
  if (entity.kind === "ip") {
    return [
      ...related,
      ...answer(ws, "connections", "Connections to IP", [
        {
          table: "DeviceNetworkEvents", needs: ["RemoteIP", "DeviceName"],
          query: `DeviceNetworkEvents\n| where RemoteIP == ${n}\n| project TimeGenerated, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName\n| sort by TimeGenerated desc`,
          pick: [{ col: "DeviceName", kind: "host" }],
        },
        {
          table: "CommonSecurityLog", needs: ["SourceIP", "DestinationIP"],
          query: `CommonSecurityLog\n| where DestinationIP == ${n} or SourceIP == ${n}\n| project TimeGenerated, DeviceVendor, SourceIP, DestinationIP, DestinationPort, DeviceAction\n| sort by TimeGenerated desc`,
          pick: [{ col: "SourceIP", kind: "ip" }, { col: "DestinationIP", kind: "ip" }],
        },
      ]),
      ...answer(ws, "ip-signins", "Sign-ins from IP", [{
        table: "SigninLogs", needs: ["IPAddress", "UserPrincipalName"],
        query: `SigninLogs\n| where IPAddress == ${n}\n| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, ResultType\n| sort by TimeGenerated desc`,
        pick: [{ col: "UserPrincipalName", kind: "account" }],
      }]),
    ];
  }
  return related;
}

/** The heading the activity log gives an entry. */
export function activityTitle(text: string): string {
  if (/^Status changed/.test(text)) return "Incident status was changed";
  if (/^Severity changed/.test(text)) return "Incident severity was changed";
  if (/^Incident (assigned|unassigned)/.test(text)) return "Incident owner was changed";
  if (/^Classification set/.test(text)) return "Incident classification was changed";
  if (/^Incident created/.test(text)) return "Incident was created";
  if (/^Bookmark/.test(text)) return "Bookmark was added";
  if (/^Task/.test(text)) return "Incident task was changed";
  return "Incident was changed";
}

/** The SecurityAlert row behind an alert: what the flyout reads beyond the alert object. */
export function alertRecord(ws: SentinelWorkspace, id: string): KqlRow | undefined {
  return ws.tables.SecurityAlert?.rows.find(r => r.SystemAlertId === id);
}

/** What Add to TI and Run playbook may do on this entity. */
export const canAddToTi = (e: SentinelEntity) => TI_KINDS.includes(e.kind);
export const canRunPlaybook = (e: SentinelEntity) => PLAYBOOK_KINDS.includes(e.kind);
