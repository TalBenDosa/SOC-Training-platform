/**
 * Top insights, as the incident page and entity pages show them. Every card is a KQL query run through
 * the engine over the workspace, so an analyst can open the query in Logs and get the same rows.
 */
import { formatKqlValue, runKql } from "@/lib/kql";
import type { KqlEnv } from "@/lib/kql/types";
import { kstr } from "./rules";
import type { EntityInsight, SentinelIncident, SentinelWorkspace } from "./types";

const PREVIEW_ROWS = 5;

function run(ws: SentinelWorkspace, title: string, description: string, query: string): EntityInsight | null {
  const env: KqlEnv = { tables: ws.tables, now: new Date(ws.now) };
  const r = runKql(query, env);
  if (!r.ok || r.rows.length === 0) return null;
  const columns = r.columns.map(c => c.name);
  const types = r.columns.map(c => c.type);
  return {
    title, description, query,
    preview: { columns, rows: r.rows.slice(0, PREVIEW_ROWS).map(row => columns.map((c, i) => formatKqlValue(row[c], types[i]))) },
  };
}

type Card = [title: string, description: string, query: string];

const accountCards = (name: string): Card[] => {
  const v = kstr(name);
  const sam = kstr(name.split("@")[0].split("\\").pop() ?? name);
  return [
    ["Sign-in activity", "Sign-ins by this account, by result and address.",
      `SigninLogs\n| where UserPrincipalName =~ ${v}\n| summarize Attempts = count(), Failures = countif(ResultType != "0"), Apps = make_set(AppDisplayName, 5) by IPAddress, Location\n| sort by Attempts desc`],
    ["Sign-in activity", "Okta sign-ins by this account, by outcome and address.",
      `OktaV2_CL\n| where OriginalActorAlternateId =~ ${v}\n| summarize Events = count(), Failures = countif(OriginalOutcomeResult == "FAILURE") by EventOriginalType, SrcIpAddr, SrcGeoCountry\n| sort by Events desc`],
    ["Windows logons", "Logon events on Windows hosts for this account.",
      `SecurityEvent\n| where TargetUserName =~ ${sam} or SubjectUserName =~ ${sam}\n| summarize Events = count() by EventID, Computer, IpAddress\n| sort by Events desc`],
    ["Actions by account", "Office activity by this account.",
      `OfficeActivity\n| where UserId =~ ${v}\n| summarize Actions = count() by Operation, ClientIP\n| sort by Actions desc`],
    ["Actions by account", "Directory changes made by this account.",
      `AuditLogs\n| where tostring(InitiatedBy.user.userPrincipalName) =~ ${v}\n| summarize Actions = count() by OperationName, Result\n| sort by Actions desc`],
    ["Cloud activity", "AWS API calls under this identity.",
      `AWSCloudTrail\n| where UserIdentityArn has ${sam} or UserIdentityUserName =~ ${sam}\n| summarize Calls = count() by EventName, SourceIpAddress\n| sort by Calls desc`],
    ["Alerts related to this account", "Alerts that name this account.",
      `SecurityAlert\n| where Entities has ${sam}\n| project TimeGenerated, AlertName, AlertSeverity, ProductName\n| sort by TimeGenerated desc`],
  ];
};

const hostCards = (name: string): Card[] => {
  const v = kstr(name);
  return [
    ["Processes on this host", "Process starts on this device, most frequent first.",
      `DeviceProcessEvents\n| where DeviceName startswith ${v}\n| summarize Starts = count() by FileName, AccountName, InitiatingProcessFileName\n| sort by Starts desc`],
    ["Processes on this host", "Process starts the Falcon sensor saw on this host.",
      `ASimProcessEventLogs\n| where DvcHostname startswith ${v}\n| summarize Starts = count() by TargetProcessName, ActingProcessName\n| sort by Starts desc`],
    ["Network connections", "Remote endpoints this device connected to.",
      `DeviceNetworkEvents\n| where DeviceName startswith ${v}\n| summarize Connections = count() by RemoteIP, RemotePort, InitiatingProcessFileName\n| sort by Connections desc`],
    ["Network connections", "Remote endpoints the Falcon sensor saw from this host.",
      `ASimNetworkSessionLogs\n| where DvcHostname startswith ${v}\n| summarize Connections = count() by DstIpAddr, DstPortNumber, SrcAppName\n| sort by Connections desc`],
    ["Logons to this host", "Accounts that logged on here, from the Security log.",
      `SecurityEvent\n| where Computer startswith ${v}\n| where EventID in (4624, 4625, 4648)\n| summarize Events = count() by EventID, TargetUserName, IpAddress\n| sort by Events desc`],
    ["Sysmon activity", "Sysmon events on this host, by event ID.",
      `Event\n| where Source == "Microsoft-Windows-Sysmon" and Computer startswith ${v}\n| summarize Events = count() by EventID\n| sort by Events desc`],
    ["Firewall traffic", "Traffic the firewall logged for this host.",
      `CommonSecurityLog\n| where SourceHostName startswith ${v} or DestinationHostName startswith ${v}\n| summarize Sessions = count(), Sent = sum(SentBytes) by DestinationIP, DeviceAction\n| sort by Sessions desc`],
    ["Alerts related to this host", "Alerts that name this host.",
      `SecurityAlert\n| where Entities has ${v}\n| project TimeGenerated, AlertName, AlertSeverity, ProductName\n| sort by TimeGenerated desc`],
  ];
};

const ipCards = (name: string): Card[] => {
  const v = kstr(name);
  return [
    ["IP remote connections", "Firewall and proxy sessions from or to this address.",
      `CommonSecurityLog\n| where SourceIP == ${v} or DestinationIP == ${v}\n| summarize Sessions = count(), Sent = sum(SentBytes), Received = sum(ReceivedBytes) by SourceIP, DestinationIP, DestinationPort, DeviceAction\n| sort by Sessions desc`],
    ["Sign-ins from this address", "Accounts that signed in from here.",
      `SigninLogs\n| where IPAddress == ${v}\n| summarize Attempts = count(), Failures = countif(ResultType != "0") by UserPrincipalName, AppDisplayName\n| sort by Attempts desc`],
    ["Sign-ins from this address", "Okta activity from this address.",
      `OktaV2_CL\n| where SrcIpAddr == ${v}\n| summarize Events = count() by OriginalActorAlternateId, EventOriginalType, OriginalOutcomeResult\n| sort by Events desc`],
    ["Windows logons from this address", "Logons that came from here.",
      `SecurityEvent\n| where IpAddress == ${v}\n| summarize Events = count() by EventID, TargetUserName, Computer\n| sort by Events desc`],
    ["Endpoint connections", "Devices that connected to this address.",
      `DeviceNetworkEvents\n| where RemoteIP == ${v}\n| summarize Connections = count() by DeviceName, InitiatingProcessFileName\n| sort by Connections desc`],
    ["Office activity from this address", "Mailbox and file actions from here.",
      `OfficeActivity\n| where ClientIP has ${v} or Client_IPAddress has ${v}\n| summarize Actions = count() by UserId, Operation\n| sort by Actions desc`],
    ["Cloud calls from this address", "AWS API calls from here.",
      `AWSCloudTrail\n| where SourceIpAddress == ${v}\n| summarize Calls = count() by UserIdentityArn, EventName\n| sort by Calls desc`],
  ];
};

const fileCards = (name: string): Card[] => {
  const v = kstr(name);
  return [
    ["File activity", "Hosts where this file was written.",
      `DeviceFileEvents\n| where FileName =~ ${v}\n| summarize Events = count() by DeviceName, ActionType, InitiatingProcessFileName\n| sort by Events desc`],
    ["File activity", "Hosts where the Falcon sensor saw this file written.",
      `ASimFileEventLogs\n| where TargetFileName =~ ${v}\n| summarize Events = count() by DvcHostname, ActingProcessName\n| sort by Events desc`],
    ["Mail attachments", "Messages that carried this file.",
      `EmailAttachmentInfo\n| where FileName =~ ${v}\n| project TimeGenerated, SenderFromAddress, RecipientEmailAddress, FileName, SHA256`],
  ];
};

const domainCards = (name: string): Card[] => {
  const v = kstr(name);
  return [
    ["DNS lookups", "Clients that resolved this name.",
      `DnsEvents\n| where Name has ${v}\n| summarize Lookups = count() by ClientIP, QueryType, Result\n| sort by Lookups desc`],
    ["Web requests", "Requests to this domain through the firewall or proxy.",
      `CommonSecurityLog\n| where RequestURL has ${v} or DestinationHostName has ${v}\n| summarize Requests = count() by SourceIP, DeviceAction, DeviceVendor\n| sort by Requests desc`],
    ["Clicks", "Safe Links clicks on this domain.",
      `UrlClickEvents\n| where Url has ${v}\n| project TimeGenerated, AccountUpn, Url, ActionType`],
  ];
};

const mailCards = (name: string): Card[] => {
  const v = kstr(name);
  return [
    ["Mail received", "Messages delivered to this mailbox.",
      `EmailEvents\n| where RecipientEmailAddress =~ ${v}\n| project TimeGenerated, SenderFromAddress, Subject, DeliveryAction, ThreatTypes\n| sort by TimeGenerated desc`],
    ["Mailbox changes", "Rules and forwarding on this mailbox.",
      `OfficeActivity\n| where UserId =~ ${v} and RecordType == "ExchangeAdmin"\n| project TimeGenerated, Operation, ClientIP\n| sort by TimeGenerated desc`],
  ];
};

function cardsFor(kind: string, name: string): Card[] {
  switch (kind) {
    case "account": return accountCards(name);
    case "host": return hostCards(name);
    case "ip": return ipCards(name);
    case "file": return fileCards(name);
    case "domain": return domainCards(name);
    case "url": return domainCards(name.replace(/^[a-z]+:\/\//i, "").split("/")[0]);
    case "mailbox": return mailCards(name);
    default: return [];
  }
}

/** Keeps one card per title: the first with rows. Query results decide which table a shop's card reads. */
function firstByTitle(ws: SentinelWorkspace, cards: Card[]): EntityInsight[] {
  const out = new Map<string, EntityInsight>();
  for (const [title, description, query] of cards) {
    if (out.has(title)) continue;
    const i = run(ws, title, description, query);
    if (i) out.set(title, i);
  }
  return [...out.values()];
}

export function entityInsights(ws: SentinelWorkspace, entityId: string): EntityInsight[] {
  const e = ws.entities[entityId];
  return e ? firstByTitle(ws, cardsFor(e.kind, e.name)) : [];
}

/** Insights for the incident's main entities, then its alerts over time. */
export function incidentInsights(ws: SentinelWorkspace, incident: SentinelIncident): EntityInsight[] {
  const ents = incident.entityIds.map(id => ws.entities[id]).filter(Boolean);
  const pick = (kind: string) => ents.find(e => e.kind === kind);
  const out: EntityInsight[] = [];
  const ids = incident.alertIds.map(kstr).join(", ");
  const timeline = run(ws, "Alerts in this incident", "Each alert with its product and severity.",
    `SecurityAlert\n| where SystemAlertId in (${ids})\n| project TimeGenerated, AlertName, AlertSeverity, ProductName, Tactics\n| sort by TimeGenerated asc`);
  if (timeline) out.push(timeline);
  for (const kind of ["account", "host", "ip"]) {
    const e = pick(kind);
    if (!e) continue;
    for (const i of firstByTitle(ws, cardsFor(e.kind, e.name)).slice(0, 2)) out.push({ ...i, title: `${i.title}: ${e.name}` });
  }
  return out;
}
