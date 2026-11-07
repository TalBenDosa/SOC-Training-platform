// A tiny hand-built workspace for the render tests: small enough to reason about, no build step.
import type { KqlTable } from "@/lib/kql/types";
import type { IncidentState, SentinelActions, SentinelAlert, SentinelEntity, SentinelIncident, SentinelWorkspace } from "@/lib/sentinel/types";

const T0 = Date.parse("2026-01-01T08:00:00.000Z");
const at = (min: number) => new Date(T0 + min * 60_000).toISOString();

const entity = (kind: SentinelEntity["kind"], name: string, info: Record<string, string> = {}): SentinelEntity => ({ id: `${kind}:${name.toLowerCase()}`, kind, name, info });
export const ENTITIES = [
  entity("account", "jdoe@contoso.example", { "User principal name": "jdoe@contoso.example", Department: "Finance" }),
  entity("host", "FIN-LT-042", { "OS family": "Windows" }),
  entity("ip", "203.0.113.50", { Country: "Reserved" }),
  entity("file", "invoice.exe", {}),
  entity("account", "svc-backup@contoso.example", {}),
];
const ids = ENTITIES.map(e => e.id);

const SIGNIN: KqlTable = {
  name: "SigninLogs",
  columns: [
    { name: "TimeGenerated", type: "datetime" }, { name: "UserPrincipalName", type: "string" }, { name: "IPAddress", type: "string" },
    { name: "AppDisplayName", type: "string" }, { name: "ResultType", type: "string" }, { name: "Location", type: "string" },
  ],
  rows: Array.from({ length: 120 }, (_, i) => ({
    TimeGenerated: at(i), UserPrincipalName: i % 2 ? "jdoe@contoso.example" : "svc-backup@contoso.example", IPAddress: i % 3 ? "203.0.113.50" : "198.51.100.7",
    AppDisplayName: "Office 365", ResultType: i % 4 ? "0" : "50126", Location: "US",
  })),
};
const PROCESS: KqlTable = {
  name: "DeviceProcessEvents",
  columns: [
    { name: "TimeGenerated", type: "datetime" }, { name: "DeviceName", type: "string" }, { name: "AccountName", type: "string" },
    { name: "FileName", type: "string" }, { name: "ProcessCommandLine", type: "string" },
  ],
  rows: [
    { TimeGenerated: at(30), DeviceName: "FIN-LT-042", AccountName: "jdoe", FileName: "invoice.exe", ProcessCommandLine: "invoice.exe /s" },
    { TimeGenerated: at(31), DeviceName: "FIN-LT-042", AccountName: "jdoe", FileName: "powershell.exe", ProcessCommandLine: "powershell -enc AAAA" },
  ],
};

export const ALERTS: SentinelAlert[] = [
  { id: "aaaaaaaa-0001", name: "Unfamiliar sign-in properties", severity: "High", product: "Azure Active Directory Identity Protection", description: "Sign-in from an unfamiliar location.", time: at(10), tactics: ["InitialAccess"], techniques: ["T1078"], entityIds: [ids[0], ids[2]], ruleId: "rule-1", query: 'SigninLogs\n| where UserPrincipalName == "jdoe@contoso.example"' },
  { id: "aaaaaaaa-0002", name: "Suspicious process launched", severity: "Medium", product: "Microsoft Defender for Endpoint", description: "A renamed binary ran from Downloads.", time: at(30), tactics: ["Execution"], techniques: ["T1204.002"], entityIds: [ids[0], ids[1], ids[3]], query: 'DeviceProcessEvents\n| where DeviceName == "FIN-LT-042"' },
  { id: "aaaaaaaa-0003", name: "Service account failed sign-ins", severity: "Low", product: "Microsoft Sentinel", description: "Failed sign-ins for a service account.", time: at(40), tactics: ["CredentialAccess"], techniques: ["T1110"], entityIds: [ids[4], ids[2]], ruleId: "rule-1", query: 'SigninLogs\n| where ResultType != "0"' },
];

const ALERT_TABLE: KqlTable = {
  name: "SecurityAlert",
  columns: [
    { name: "TimeGenerated", type: "datetime" }, { name: "AlertName", type: "string" }, { name: "AlertSeverity", type: "string" }, { name: "ProductName", type: "string" },
    { name: "SystemAlertId", type: "string" }, { name: "Entities", type: "string" },
  ],
  rows: ALERTS.map(a => ({ TimeGenerated: a.time, AlertName: a.name, AlertSeverity: a.severity, ProductName: a.product, SystemAlertId: a.id, Entities: JSON.stringify(a.entityIds.map(i => ENTITIES.find(e => e.id === i)).map(e => (e?.kind === "account" ? { Type: "account", Name: e.name.split("@")[0], UPNSuffix: e.name.split("@")[1] } : { Type: e?.kind, Name: e?.name }))) })),
};

export const INCIDENTS: SentinelIncident[] = [
  { number: 101, id: "inc-101", title: "Initial access involving one user", severity: "High", created: at(10), lastUpdate: at(30), alertIds: [ALERTS[0].id, ALERTS[1].id], entityIds: ids.slice(0, 4), tactics: ["InitialAccess", "Execution"], techniques: ["T1078", "T1204.002"], products: ["Azure Active Directory Identity Protection", "Microsoft Defender for Endpoint"], description: "A user signed in from an unfamiliar place, then ran a binary.", eventCount: 42, eventsQuery: "SigninLogs\n| take 42" },
  { number: 102, id: "inc-102", title: "Service account failed sign-ins", severity: "Low", created: at(40), lastUpdate: at(40), alertIds: [ALERTS[2].id], entityIds: [ids[4], ids[2]], tactics: ["CredentialAccess"], techniques: ["T1110"], products: ["Microsoft Sentinel"], description: "", eventCount: 30, eventsQuery: 'SigninLogs\n| where ResultType != "0"' },
];

export function fixtureWorkspace(extra?: Partial<SentinelWorkspace>): SentinelWorkspace {
  return {
    name: "contoso-sentinel-prod",
    tables: { SigninLogs: SIGNIN, DeviceProcessEvents: PROCESS, SecurityAlert: ALERT_TABLE },
    alerts: ALERTS, incidents: INCIDENTS, entities: Object.fromEntries(ENTITIES.map(e => [e.id, e])),
    rules: [{ id: "rule-1", name: "Sign-ins from a rare location", severity: "Medium", tactics: ["InitialAccess"], techniques: ["T1078"], description: "Rare location for this user.", query: 'SigninLogs\n| where ResultType == "0"', frequency: "1 hour", lookback: "1 day", dataSources: ["SigninLogs"], falsePositives: ["Travel"] }],
    hunting: [{ id: "h-1", name: "Failed sign-ins by account", description: "Accounts with failed sign-ins.", tactics: ["CredentialAccess"], techniques: ["T1110"], dataSources: ["SigninLogs"], query: 'SigninLogs\n| where ResultType != "0"\n| summarize Failures = count() by UserPrincipalName' }],
    now: at(120),
    ...extra,
  };
}

export function fixtureState(over: Partial<IncidentState> = {}): IncidentState {
  return { status: "New", owner: null, severity: "High", comments: [], bookmarks: [], tasks: [{ id: "t", title: "Review the alerts", done: false }], activity: [{ at: at(10), actor: "Sentinel", text: "Incident created" }], ...over };
}

export function fakeActions(over: Partial<SentinelActions> = {}) {
  const calls: { fn: string; args: unknown[] }[] = [];
  const log = (fn: string) => async (...args: unknown[]) => { calls.push({ fn, args }); return null; };
  const actions: SentinelActions = {
    me: { id: "u1", name: "Tal Analyst", role: "t2" }, people: ["Tal Analyst", "Dana Lead"], canContain: true, isolatedHosts: new Set(),
    setIsolated: log("setIsolated"), updateIncident: log("updateIncident"), addComment: log("addComment"), addBookmark: log("addBookmark"), setTask: log("setTask"),
    queryRan: q => { calls.push({ fn: "queryRan", args: [q] }); },
    ...over,
  };
  return { actions, calls };
}
