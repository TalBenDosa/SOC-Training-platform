/**
 * Room 36 "Operation Clear Sky": Ashgrove Pharmacy's investigation console, on
 * top of the "clear-sky" mission dataset (SigninLogs, AuditLogs, OfficeActivity,
 * DeviceProcessEvents). Every alert and incident below is backed by rows the
 * dataset really holds, and every alert query and detection query runs in the
 * KQL engine (consoles.test.ts).
 *
 * The queue at the start of the room (clock: the dataset's now, 9 Nov 12:00 UTC):
 *   4412 High   New     d.okafor: sign-in from Nigeria with a single factor, a forwarding
 *                       inbox rule, nine SharePoint downloads (3 alerts, 3 detections)
 *   4415 Medium New     password spray from 203.0.113.77 (13 accounts, one got in)
 *   4416 Medium New     the same detection on the shops' NAT at the 08:00 shift change
 *                       (staff mistyping, then signing in: the rule's logic, not an attack)
 *   4410 Low    New     consent to a new application (Rota Planner)
 *   4409 Medium Closed  r.ansah's trip, closed by R. Nowak as Benign Positive
 *
 * The spray detection counts failed accounts per address over its one-hour look-back
 * with a threshold of 13: it catches 203.0.113.77 and the NAT, and misses the second
 * spray from 198.51.100.140 (12 accounts), which the boss hunt finds.
 */
import type { AnalyticsRule, HuntingQuery, IncidentState, SentinelAlert, SentinelEntity, SentinelIncident } from "@/lib/sentinel/types";
import { CLEAR_SKY_FACTS } from "../datasets/clearSky";
import type { MissionTable } from "../types";
import type { MissionConsole } from "./types";

const { at, u } = CLEAR_SKY_FACTS;

const entity = (kind: SentinelEntity["kind"], name: string, info: Record<string, string>): SentinelEntity =>
  ({ id: `${kind}:${name.toLowerCase()}`, kind, name, info });

const ENTITIES: SentinelEntity[] = [
  entity("account", u("d.okafor"), { "User principal name": u("d.okafor"), "Display name": "Dami Okafor", Department: "Dispensing Operations", Office: "Head office, Leeds" }),
  entity("mailbox", u("d.okafor"), { "Mailbox primary address": u("d.okafor"), "Display name": "Dami Okafor" }),
  entity("ip", "198.51.100.23", { Address: "198.51.100.23", Country: "NG (from sign-in logs)" }),
  entity("cloudapp", "Office 365 SharePoint Online", { "App name": "Office 365 SharePoint Online" }),
  entity("ip", "203.0.113.77", { Address: "203.0.113.77", Country: "RU (from sign-in logs)" }),
  entity("ip", "198.51.100.10", { Address: "198.51.100.10", Note: "Ashgrove shops' outbound NAT" }),
  entity("account", u("f.lindqvist"), { "User principal name": u("f.lindqvist"), "Display name": "Frida Lindqvist", Department: "Store Operations" }),
  entity("cloudapp", "Rota Planner", { "App name": "Rota Planner", Publisher: "Not verified" }),
  entity("account", u("r.ansah"), { "User principal name": u("r.ansah"), "Display name": "Rhoda Ansah", Department: "Procurement" }),
  entity("ip", "203.0.113.36", { Address: "203.0.113.36", Country: "IE (from sign-in logs)" }),
];
const E = (kind: SentinelEntity["kind"], name: string) => `${kind}:${name.toLowerCase()}`;

// ─── Detections ──────────────────────────────────────────────────────────────

const RULES: AnalyticsRule[] = [
  {
    id: "rule-rare-country", name: "Sign-in from a country never seen for the user", severity: "Medium",
    tactics: ["InitialAccess"], techniques: ["T1078.004"],
    description: "A successful sign-in from a country the account has not signed in from in the previous 14 days.",
    query: [
      "let known = SigninLogs",
      "    | where TimeGenerated between (ago(14d) .. ago(1h)) and ResultType == \"0\"",
      "    | distinct UserPrincipalName, Location;",
      "SigninLogs",
      "| where TimeGenerated > ago(1h) and ResultType == \"0\"",
      "| join kind=leftanti known on UserPrincipalName, Location",
      "| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, AuthenticationRequirement",
    ].join("\n"),
    frequency: "1 hour", lookback: "14 days", dataSources: ["SigninLogs"],
    falsePositives: ["Business travel: check the device and MFA before you call it", "A new VPN egress country"],
  },
  {
    id: "rule-forward-rule", name: "Inbox rule forwards mail outside the company", severity: "Medium",
    tactics: ["Collection", "Stealth"], techniques: ["T1114.003", "T1564.008"],
    description: "An inbox rule was created or changed that forwards or redirects mail to an address outside ashgrove.example.",
    query: [
      "OfficeActivity",
      "| where Operation in (\"New-InboxRule\", \"Set-InboxRule\")",
      "| where Parameters has_any (\"ForwardTo\", \"RedirectTo\", \"ForwardAsAttachmentTo\")",
      "| where Parameters !has \"@ashgrove.example\"",
      "| project TimeGenerated, UserId, ClientIP, Operation, Parameters",
    ].join("\n"),
    frequency: "5 minutes", lookback: "5 minutes", dataSources: ["OfficeActivity"],
    falsePositives: ["A user forwarding to a personal mailbox (still a policy breach)"],
  },
  {
    id: "rule-bulk-download", name: "Bulk file download from SharePoint", severity: "High",
    tactics: ["Collection"], techniques: ["T1213.002"],
    description: "One account downloaded 8 or more files from SharePoint within 15 minutes.",
    query: [
      "OfficeActivity",
      "| where Operation == \"FileDownloaded\"",
      "| summarize Files = count(), First = min(TimeGenerated), Last = max(TimeGenerated) by UserId, ClientIP, bin(TimeGenerated, 15m)",
      "| where Files >= 8",
    ].join("\n"),
    frequency: "15 minutes", lookback: "15 minutes", dataSources: ["OfficeActivity"],
    falsePositives: ["Syncing a library with the OneDrive client"],
  },
  {
    id: "rule-spray", name: "Password spray: one address, many accounts", severity: "Medium",
    tactics: ["CredentialAccess"], techniques: ["T1110.003"],
    description: "One source address failed to sign in to 13 or more different accounts within the look-back.",
    query: [
      "SigninLogs",
      "| where ResultType == \"50126\"",
      "| summarize Accounts = dcount(UserPrincipalName), Attempts = count(), First = min(TimeGenerated), Last = max(TimeGenerated) by IPAddress",
      "| where Accounts >= 13",
    ].join("\n"),
    frequency: "1 hour", lookback: "1 hour", dataSources: ["SigninLogs"],
    falsePositives: ["Many staff behind one NAT mistyping at a shift change"],
  },
  {
    id: "rule-consent", name: "Consent to an application not seen before", severity: "Low",
    tactics: ["Persistence"], techniques: ["T1098.003"],
    description: "A user granted an application access to their data, and no one in the tenant had consented to it before.",
    query: [
      "AuditLogs",
      "| where OperationName == \"Consent to application\"",
      "| extend App = tostring(TargetResources[0].displayName), Actor = tostring(InitiatedBy.user.userPrincipalName)",
      "| project TimeGenerated, Actor, App",
    ].join("\n"),
    frequency: "1 day", lookback: "1 day", dataSources: ["AuditLogs"],
    falsePositives: ["A team adopting a new tool without IT"],
  },
];

const HUNTS: HuntingQuery[] = [
  {
    id: "hunt-legacy", name: "Sign-ins over legacy authentication",
    description: "Legacy protocols cannot do MFA. Every address and protocol that tried one, with its successes.",
    tactics: ["CredentialAccess", "InitialAccess"], techniques: ["T1110.003", "T1078.004"], dataSources: ["SigninLogs"],
    query: [
      "SigninLogs",
      "| where ClientAppUsed in (\"Exchange ActiveSync\", \"Authenticated SMTP\", \"IMAP4\", \"POP3\")",
      "| summarize Attempts = count(), Accounts = dcount(UserPrincipalName), Successes = countif(ResultType == \"0\") by IPAddress, ClientAppUsed",
      "| sort by Attempts desc",
    ].join("\n"),
  },
  {
    id: "hunt-script-ua", name: "Sign-ins from scripted clients",
    description: "A browser is not the only thing that can type a password. User agents of scripting libraries, by address and result.",
    tactics: ["CredentialAccess"], techniques: ["T1110"], dataSources: ["SigninLogs"],
    query: [
      "SigninLogs",
      "| where UserAgent has_any (\"python-requests\", \"curl/\", \"Go-http-client\")",
      "| summarize Attempts = count(), Accounts = dcount(UserPrincipalName) by IPAddress, Location, ResultType",
      "| sort by IPAddress asc",
    ].join("\n"),
  },
  {
    id: "hunt-consent", name: "Application consents by users",
    description: "Which users granted which applications access to their data.",
    tactics: ["Persistence"], techniques: ["T1098.003"], dataSources: ["AuditLogs"],
    query: [
      "AuditLogs",
      "| where OperationName == \"Consent to application\"",
      "| project TimeGenerated, Actor = tostring(InitiatedBy.user.userPrincipalName), App = tostring(TargetResources[0].displayName)",
    ].join("\n"),
  },
];

// ─── Alerts ──────────────────────────────────────────────────────────────────

const PRODUCT = "XDR Analytics";
const ALERTS: SentinelAlert[] = [
  {
    id: "b7d3a1e2-4412-4c1a-9f01-000000000001", name: "Sign-in from a country never seen for the user", severity: "Medium", product: PRODUCT,
    description: "d.okafor@ashgrove.example signed in successfully from NG (198.51.100.23). The account has not signed in from NG in the previous 14 days.",
    time: at(1, 23, 41, 7), tactics: ["InitialAccess"], techniques: ["T1078.004"],
    entityIds: [E("account", u("d.okafor")), E("ip", "198.51.100.23")], ruleId: "rule-rare-country",
    query: `SigninLogs\n| where UserPrincipalName == "${u("d.okafor")}" and IPAddress == "198.51.100.23"\n| project TimeGenerated, UserPrincipalName, IPAddress, Location, ResultType, AuthenticationRequirement, ClientAppUsed, UserAgent`,
  },
  {
    id: "b7d3a1e2-4412-4c1a-9f01-000000000002", name: "Inbox rule forwards mail outside the company", severity: "Medium", product: PRODUCT,
    description: "A New-InboxRule on d.okafor@ashgrove.example forwards matching mail to an address outside ashgrove.example.",
    time: at(1, 23, 44), tactics: ["Collection", "Stealth"], techniques: ["T1114.003", "T1564.008"],
    entityIds: [E("account", u("d.okafor")), E("mailbox", u("d.okafor")), E("ip", "198.51.100.23")], ruleId: "rule-forward-rule",
    query: `OfficeActivity\n| where UserId == "${u("d.okafor")}" and Operation == "New-InboxRule"\n| project TimeGenerated, UserId, ClientIP, Operation, Parameters`,
  },
  {
    id: "b7d3a1e2-4412-4c1a-9f01-000000000003", name: "Bulk file download from SharePoint", severity: "High", product: PRODUCT,
    description: "d.okafor@ashgrove.example downloaded 8 or more files from SharePoint within 15 minutes from 198.51.100.23.",
    time: at(1, 23, 55, 37), tactics: ["Collection"], techniques: ["T1213.002"],
    entityIds: [E("account", u("d.okafor")), E("ip", "198.51.100.23"), E("cloudapp", "Office 365 SharePoint Online")], ruleId: "rule-bulk-download",
    query: `OfficeActivity\n| where UserId == "${u("d.okafor")}" and Operation == "FileDownloaded" and ClientIP == "198.51.100.23"\n| project TimeGenerated, UserId, ClientIP, Operation, OfficeObjectId`,
  },
  {
    id: "c2e8f0a4-4415-4b7e-8d22-000000000004", name: "Password spray: one address, many accounts", severity: "Medium", product: PRODUCT,
    description: "203.0.113.77 failed to sign in to 13 different accounts within one hour.",
    time: at(2, 3, 22, 41), tactics: ["CredentialAccess"], techniques: ["T1110.003"],
    entityIds: [E("ip", "203.0.113.77")], ruleId: "rule-spray",
    query: `SigninLogs\n| where IPAddress == "203.0.113.77" and ResultType == "50126"\n| project TimeGenerated, UserPrincipalName, IPAddress, ResultType, ClientAppUsed`,
  },
  {
    id: "c2e8f0a4-4416-4b7e-8d22-000000000005", name: "Password spray: one address, many accounts", severity: "Medium", product: PRODUCT,
    description: "198.51.100.10 failed to sign in to 13 different accounts within one hour.",
    time: at(0, 8, 8, 24), tactics: ["CredentialAccess"], techniques: ["T1110.003"],
    entityIds: [E("ip", "198.51.100.10")], ruleId: "rule-spray",
    query: `SigninLogs\n| where IPAddress == "198.51.100.10" and ResultType == "50126"\n| project TimeGenerated, UserPrincipalName, IPAddress, ResultType, ClientAppUsed`,
  },
  {
    id: "d9a4c6b1-4410-4e3f-a611-000000000006", name: "Consent to an application not seen before", severity: "Low", product: PRODUCT,
    description: "f.lindqvist@ashgrove.example consented to Rota Planner. No one in the tenant had consented to it before.",
    time: at(2, 15, 7), tactics: ["Persistence"], techniques: ["T1098.003"],
    entityIds: [E("account", u("f.lindqvist")), E("cloudapp", "Rota Planner")], ruleId: "rule-consent",
    query: `AuditLogs\n| where OperationName == "Consent to application"\n| project TimeGenerated, OperationName, InitiatedBy, TargetResources`,
  },
  {
    id: "a1f5e7c3-4409-4d2b-b733-000000000007", name: "Sign-in from a country never seen for the user", severity: "Medium", product: PRODUCT,
    description: "r.ansah@ashgrove.example signed in successfully from IE (203.0.113.36). The account has not signed in from IE in the previous 14 days.",
    time: at(3, 10, 21, 11), tactics: ["InitialAccess"], techniques: ["T1078.004"],
    entityIds: [E("account", u("r.ansah")), E("ip", "203.0.113.36")], ruleId: "rule-rare-country",
    query: `SigninLogs\n| where UserPrincipalName == "${u("r.ansah")}"\n| project TimeGenerated, UserPrincipalName, IPAddress, Location, ResultType, AuthenticationRequirement, DeviceDetail`,
  },
];

const A = (n: number) => ALERTS[n - 1];

// ─── Incidents ───────────────────────────────────────────────────────────────

const incident = (number: number, title: string, severity: SentinelIncident["severity"], created: string, alerts: SentinelAlert[], description: string, eventsQuery: string, eventCount: number): SentinelIncident => ({
  number, id: `inc-${number}`, title, severity, created, lastUpdate: alerts.reduce((m, a) => (a.time > m ? a.time : m), created),
  alertIds: alerts.map(a => a.id), entityIds: [...new Set(alerts.flatMap(a => a.entityIds))],
  tactics: [...new Set(alerts.flatMap(a => a.tactics))], techniques: [...new Set(alerts.flatMap(a => a.techniques))],
  products: [...new Set(alerts.map(a => a.product))], description, eventsQuery, eventCount,
});

const INCIDENTS: SentinelIncident[] = [
  incident(4412, "Sign-in from a rare country, forwarding rule and bulk download", "High", at(1, 23, 52, 30), [A(1), A(2), A(3)],
    "Three detections on one account within fifteen minutes: a sign-in from a country never seen for the user, an inbox rule that forwards mail outside the company, and a bulk download from SharePoint.",
    `union SigninLogs, OfficeActivity\n| where UserPrincipalName == "${u("d.okafor")}" or UserId == "${u("d.okafor")}"\n| where TimeGenerated between (datetime(2026-11-08T23:30:00Z) .. datetime(2026-11-09T00:00:00Z))\n| project TimeGenerated, UserPrincipalName, UserId, IPAddress, ClientIP, ResultType, Operation`,
    14),
  incident(4415, "Password spray against many accounts from one address", "Medium", at(2, 3, 30, 12), [A(4)],
    "One address failed to sign in to 13 or more accounts within the detection's look-back.",
    `SigninLogs\n| where IPAddress == "203.0.113.77"\n| project TimeGenerated, UserPrincipalName, IPAddress, ResultType, ClientAppUsed`, 14),
  incident(4416, "Password spray against many accounts from one address", "Medium", at(0, 8, 30, 5), [A(5)],
    "One address failed to sign in to 13 or more accounts within the detection's look-back.",
    `SigninLogs\n| where IPAddress == "198.51.100.10" and TimeGenerated between (datetime(2026-11-09T07:55:00Z) .. datetime(2026-11-09T08:15:00Z))\n| project TimeGenerated, UserPrincipalName, IPAddress, ResultType, ClientAppUsed`, 26),
  incident(4410, "Consent to an application not seen before", "Low", at(1, 2, 0, 41), [A(6)],
    "A user granted a new application access to their data.",
    `AuditLogs\n| where OperationName == "Consent to application"`, 1),
  incident(4409, "Sign-in from a country never seen for the user", "Medium", at(3, 10, 30, 2), [A(7)],
    "A successful sign-in from a country the account had not used in 14 days.",
    `SigninLogs\n| where UserPrincipalName == "${u("r.ansah")}"`, 6),
];

const STATES: Record<string, IncidentState> = {
  "inc-4409": {
    status: "Closed", owner: "R. Nowak", severity: "Medium",
    classification: "Benign Positive - suspicious but expected",
    closingComment: "Business trip (Dublin, then Paris) confirmed with the line manager. Same compliant laptop and MFA on every sign-in.",
    comments: [{ id: "c-4409-1", author: "R. Nowak", text: "Same device ID as her sign-ins from home, MFA satisfied each time. Asked her manager.", at: at(3, 11, 2) }],
    bookmarks: [], tasks: [],
    activity: [
      { at: at(3, 10, 30, 2), actor: "XDR", text: "Incident created" },
      { at: at(3, 10, 48), actor: "R. Nowak", text: "Assigned to R. Nowak, status Active" },
      { at: at(3, 13, 15), actor: "R. Nowak", text: "Closed as Benign Positive - suspicious but expected" },
    ],
  },
};

// ─── Tables the console adds ─────────────────────────────────────────────────

const entityJson = (ids: string[]) => JSON.stringify(ids.map(id => ENTITIES.find(e => e.id === id)).filter(Boolean).map(e => {
  const x = e as SentinelEntity;
  if (x.kind === "account") { const [name, suffix] = x.name.split("@"); return { Type: "account", Name: name, UPNSuffix: suffix }; }
  if (x.kind === "ip") return { Type: "ip", Address: x.name };
  if (x.kind === "mailbox") return { Type: "mailbox", MailboxPrimaryAddress: x.name };
  return { Type: x.kind, Name: x.name };
}));

const ALERT_TABLE: MissionTable = {
  name: "SecurityAlert",
  columns: [
    { name: "TimeGenerated", type: "datetime" }, { name: "AlertName", type: "string" }, { name: "AlertSeverity", type: "string" },
    { name: "ProductName", type: "string" }, { name: "ProviderName", type: "string" }, { name: "SystemAlertId", type: "string" },
    { name: "Description", type: "string" }, { name: "Tactics", type: "string" }, { name: "Techniques", type: "string" },
    { name: "Entities", type: "string" }, { name: "Status", type: "string" },
  ],
  rows: ALERTS.map(a => ({
    TimeGenerated: a.time, AlertName: a.name, AlertSeverity: a.severity, ProductName: a.product, ProviderName: "ASI Scheduled Alerts",
    SystemAlertId: a.id, Description: a.description, Tactics: a.tactics.join(", "), Techniques: JSON.stringify(a.techniques),
    Entities: entityJson(a.entityIds), Status: "New",
  })),
};

const INCIDENT_TABLE: MissionTable = {
  name: "SecurityIncident",
  columns: [
    { name: "TimeGenerated", type: "datetime" }, { name: "IncidentNumber", type: "int" }, { name: "Title", type: "string" },
    { name: "Severity", type: "string" }, { name: "Status", type: "string" }, { name: "Classification", type: "string" },
    { name: "Owner", type: "dynamic" }, { name: "AlertIds", type: "dynamic" }, { name: "CreatedTime", type: "datetime" },
    { name: "LastModifiedTime", type: "datetime" },
  ],
  rows: INCIDENTS.map(i => {
    const s = STATES[i.id];
    return {
      TimeGenerated: i.created, IncidentNumber: i.number, Title: i.title, Severity: i.severity, Status: s?.status ?? "New",
      Classification: s?.classification?.split(" - ")[0].replace(/\s+/g, "") ?? "", Owner: { assignedTo: s?.owner ?? null },
      AlertIds: i.alertIds, CreatedTime: i.created, LastModifiedTime: i.lastUpdate,
    };
  }),
};

export const CLEAR_SKY_CONSOLE: MissionConsole = {
  id: "clear-sky",
  dataset: "clear-sky",
  name: "ashgrove-xdr-prod",
  tables: [ALERT_TABLE, INCIDENT_TABLE],
  alerts: ALERTS,
  incidents: INCIDENTS,
  entities: Object.fromEntries(ENTITIES.map(e => [e.id, e])),
  rules: RULES,
  hunting: HUNTS,
  states: STATES,
  people: ["R. Nowak", "Malik Haddad", "S. Patel"],
};
