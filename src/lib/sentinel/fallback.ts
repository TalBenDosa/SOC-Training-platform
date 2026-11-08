/**
 * Every released feed event reaches a table. A record the native layer has no mapping for still has a
 * real home: the table its connector fills, or, with no built-in table, a custom-log table named the
 * way ingestion names it (`<Source>_CL`). Rows here are built from the public event alone.
 *
 * Real tables come from the Azure Monitor reference and the Azure-Sentinel connector files. Custom-log
 * tables are declared in tables.ts, which says which names no connector confirms.
 */
import { deviceKey } from "@/lib/logs/native/sources/mde";
import type { KqlRow } from "@/lib/kql/types";
import type { NativeCtx } from "@/lib/logs/native/types";
import type { TelemetryEvent } from "@/lib/sim/types";
import { columnType, CUSTOM_LOG_TABLES } from "./tables";

const isCustomTable = (name: string) => CUSTOM_LOG_TABLES.has(name);

const r = (ev: TelemetryEvent, ...keys: string[]): string | undefined => {
  for (const k of keys) {
    const v = (ev.raw as Record<string, unknown> | undefined)?.[k];
    if (v !== undefined && v !== null && v !== "") return String(v);
  }
  return undefined;
};

const userOf = (ev: TelemetryEvent) => ev.user_email ?? ev.user?.email ?? r(ev, "user.name", "db.user", "actor.email_address", "emr.user");

function custom(ev: TelemetryEvent, table: string, tenantId: string, record?: unknown): { table: string; row: KqlRow } {
  const row: KqlRow = {
    TimeGenerated: ev.ts, Type: table, TenantId: tenantId, SourceSystem: "RestAPI", EventVendor: (ev.vendor ?? ev.source).split(" ")[0], EventProduct: ev.vendor ?? ev.source, EventType: ev.event_type,
    EventMessage: ev.description, EventSeverity: ev.severity, DvcHostname: ev.hostname, ActorUsername: userOf(ev), SrcIpAddr: ev.src_ip, SrcPortNumber: ev.src_port, DstIpAddr: ev.dst_ip, DstPortNumber: ev.dst_port,
    Url: ev.network?.url, RawData: record ?? ev.raw ?? {},
  };
  for (const k of Object.keys(row)) if (row[k] === undefined) delete row[k];
  return { table, row };
}

function build(table: string, ev: TelemetryEvent, tenantId: string, cols: KqlRow): { table: string; row: KqlRow } {
  const row: KqlRow = { TimeGenerated: ev.ts, Type: table };
  if (columnType(table, "TenantId")) row.TenantId = tenantId;
  for (const [k, v] of Object.entries(cols)) if (v !== undefined && v !== null && v !== "" && columnType(table, k)) row[k] = v;
  return { table, row };
}

const num = (v: unknown) => { const n = Number(v); return Number.isFinite(n) && v !== undefined && v !== null && v !== "" ? n : undefined; };

const CEF_VENDOR: [RegExp, string, string][] = [[/imperva/i, "Imperva Inc.", "SecureSphere"], [/guardium/i, "IBM", "Guardium"], [/zscaler/i, "Zscaler", "NSSWeblog"]];

function cefRow(ev: TelemetryEvent, tenantId: string, vendor: string, product: string, cols: KqlRow = {}) {
  return build("CommonSecurityLog", ev, tenantId, {
    DeviceVendor: vendor, DeviceProduct: product, Activity: ev.event_type, Message: ev.description, LogSeverity: ev.severity, SourceSystem: "OpsManager", SourceIP: ev.src_ip, SourcePort: ev.src_port, DestinationIP: ev.dst_ip,
    DestinationPort: ev.dst_port, DestinationHostName: ev.hostname, Computer: ev.hostname, SourceUserName: userOf(ev), RequestURL: ev.network?.url, AdditionalExtensions: JSON.stringify(ev.raw ?? {}), ...cols,
  });
}

function syslogRow(ev: TelemetryEvent, tenantId: string, process: string, facility: string) {
  return build("Syslog", ev, tenantId, {
    Computer: ev.hostname, HostName: ev.hostname, HostIP: ev.src_ip, ProcessName: process, Facility: facility, SeverityLevel: "info", SourceSystem: "Linux",
    SyslogMessage: r(ev, "event.original", "syslog.message") ?? [ev.description, userOf(ev) && `user=${userOf(ev)}`, ev.src_ip && `src=${ev.src_ip}`, ev.dst_ip && `dst=${ev.dst_ip}`].filter(Boolean).join(" "),
  });
}

function eventRow(ev: TelemetryEvent, tenantId: string, source: string, log: string) {
  return build("Event", ev, tenantId, {
    Computer: ev.hostname, EventID: num(r(ev, "event.code", "winlog.event_id")) ?? 0, EventLog: log, Source: source, EventLevelName: "Information", EventLevel: 4, SourceSystem: "OpsManager", UserName: userOf(ev),
    RenderedDescription: [ev.description, ev.src_ip && `Client address: ${ev.src_ip}`].filter(Boolean).join(" "), Message: ev.description, EventData: JSON.stringify(ev.raw ?? {}),
  });
}

/** The row of a feed event the native layer could not place. Always returns one. */
export function fallbackRow(ev: TelemetryEvent, ctx: NativeCtx, record?: Record<string, unknown>, sourceId?: string): { table: string; row: KqlRow } {
  const tenantId = ctx.tenant.azureTenantId;
  const v = ev.vendor ?? "";
  const user = userOf(ev);
  switch (sourceId) {
    case "servicenow": return custom(ev, "ServiceNow_CL", tenantId, record);
    case "zscaler_zpa": return custom(ev, "ZPA_CL", tenantId, record);
    case "cloudflare_access":
      return build("CloudflareV2_CL", ev, tenantId, { Email: user, ClientIP: ev.src_ip, ClientRequestHost: ev.hostname, Action: ev.event_type });
    case "workday":
      return build("ASimAuditEventLogs", ev, tenantId, {
        EventVendor: "Workday", EventProduct: "Workday", EventType: "Set", EventResult: "Success", EventCount: 1, EventSchemaVersion: "0.1", Operation: ev.event_type, ActorUsername: user, ActorUsernameType: "UPN", Dvc: ev.hostname, DvcHostname: ev.hostname, SrcIpAddr: ev.src_ip, EventMessage: ev.description, AdditionalFields: record ?? {}, EventStartTime: ev.ts, EventEndTime: ev.ts, SourceSystem: "RestAPI",
      });
    case "k8s_audit": {
      const rec = (record ?? {}) as { verb?: string; stage?: string; userAgent?: string; responseStatus?: { code?: number }; objectRef?: unknown; user?: { username?: string } };
      return build("AWSEKSLogs_CL", ev, tenantId, { Verb: rec.verb, User: rec.user?.username ?? user, SourceIPs: ev.src_ip ? [ev.src_ip] : [], UserAgent: rec.userAgent, ObjectRef: JSON.stringify(rec.objectRef ?? {}), ResponseCode: rec.responseStatus?.code, Stage: rec.stage, RawEvent: { ...rec, hostname: ev.hostname } });
    }
    default: break;
  }
  switch (ev.source as string) {
    case "ueba":
      if (/sentinel|xdr/i.test(v)) {
        return build("BehaviorAnalytics", ev, tenantId, {
          UserPrincipalName: user, UserName: user?.split("@")[0], SourceIPAddress: ev.src_ip, SourceDevice: ev.hostname, DestinationIPAddress: ev.dst_ip, ActivityType: r(ev, "ueba.anomaly_type"), ActionType: ev.event_type,
          EventSource: "SecurityAlert", EventVendor: "Microsoft", InvestigationPriority: num(r(ev, "ueba.risk_score", "ueba.investigation_priority")), ActivityInsights: ev.raw ?? {}, SourceRecordId: ev.id, TimeProcessed: ev.ts, SourceSystem: "Azure",
        });
      }
      break;
    case "waf":
      if (/aws/i.test(v)) {
        return build("AWSWAF", ev, tenantId, {
          ClientIp: ev.src_ip, Action: r(ev, "action") ?? (ev.event_type === "waf_block" ? "BLOCK" : "ALLOW"), WebAclId: r(ev, "webaclId"), TerminatingRuleId: r(ev, "terminatingRuleId"), TerminatingRuleType: r(ev, "terminatingRuleType"),
          HttpMethod: ev.network?.method, Uri: ev.network?.url, HttpSourceName: r(ev, "httpSourceName"), HttpSourceId: ev.hostname, Headers: ev.network?.user_agent ? [{ name: "User-Agent", value: ev.network.user_agent }] : [],
          HttpRequest: { clientIp: ev.src_ip, host: ev.network?.domain, destinationIp: ev.dst_ip, serverHost: ev.hostname }, ResponseCodeSent: ev.network?.status, SourceSystem: "Azure",
        });
      }
      if (/application gateway/i.test(v)) {
        return build("AGWFirewallLogs", ev, tenantId, {
          ClientIp: ev.src_ip ?? r(ev, "azure.appgw.clientIp"), RequestUri: r(ev, "azure.appgw.requestUri") ?? ev.network?.url, Hostname: ev.hostname, Action: ev.event_type === "waf_block" ? "Blocked" : "Allowed", Message: ev.description,
          OperationName: r(ev, "azure.appgw.operationName") ?? "ApplicationGatewayFirewall", PolicyId: r(ev, "azure.appgw.policyId"), InstanceId: r(ev, "azure.appgw.instanceId"), SourceSystem: "Azure",
        });
      }
      if (/front door/i.test(v)) {
        return build("AzureDiagnostics", ev, tenantId, { Category: "FrontDoorWebApplicationFirewallLog", OperationName: r(ev, "operationName"), ResourceProvider: "MICROSOFT.CDN", clientIP_s: ev.src_ip, requestUri_s: r(ev, "properties.requestUri") ?? ev.network?.url, Resource: ev.hostname, host_s: ev.hostname, CallerIPAddress: ev.src_ip, Message: ev.description, SourceSystem: "Azure" });
      }
      if (/cloudflare/i.test(v)) {
        return build("CloudflareV2_CL", ev, tenantId, {
          ClientIP: ev.src_ip, ClientRequestHost: ev.hostname, ClientRequestURI: ev.network?.url ?? r(ev, "url.path"), ClientRequestMethod: ev.network?.method ?? r(ev, "http.request.method"), ClientRequestUserAgent: ev.network?.user_agent,
          RayID: r(ev, "cf.ray_id"), Action: r(ev, "cf.action") ?? ev.event_type, RuleID: r(ev, "cf.rule.id", "waf.rule.id"), ZoneName: r(ev, "cf.zone.name"), EdgeResponseStatus: num(ev.network?.status), Source: r(ev, "cf.source"), Email: user,
        });
      }
      if (/f5/i.test(v)) return custom(ev, "F5Telemetry_ASM_CL", tenantId);
      break;
    case "db_monitor":
      if (/azure sql/i.test(v)) {
        return build("AzureDiagnostics", ev, tenantId, { Category: "SQLSecurityAuditEvents", OperationName: "AuditEvent", ResourceProvider: "MICROSOFT.SQL", Resource: ev.hostname, client_ip_s: ev.src_ip ?? r(ev, "azure.sql.client_ip"), CallerIPAddress: ev.src_ip, database_name_s: r(ev, "azure.sql.database_name"), action_s: r(ev, "azure.sql.action_name"), Message: ev.description, SourceSystem: "Azure" });
      }
      if (/sql server/i.test(v)) return eventRow(ev, tenantId, "MSSQLSERVER", "Application");
      if (/mysql/i.test(v)) return syslogRow(ev, tenantId, "mysqld", "daemon");
      for (const [re, vendor, product] of CEF_VENDOR) if (re.test(v)) return cefRow(ev, tenantId, vendor, product);
      if (/epiq/i.test(v)) return custom(ev, "EpiqEMRAudit_CL", tenantId);
      break;
    case "virtualization":
      return syslogRow(ev, tenantId, /vcenter/i.test(v) ? "vpxd" : "hostd", "local4");
    case "nac":
      return syslogRow(ev, tenantId, "CISE_RADIUS_Accounting", "local6");
    case "dhcp":
      return custom(ev, "DHCP_CL", tenantId);
    case "vcs":
      if (/advanced security/i.test(v)) return custom(ev, "GitHubAdvancedSecurityAlerts_CL", tenantId);
      return build("GitHubAuditLogsV2_CL", ev, tenantId, { Action: r(ev, "github.audit.action", "event.action") ?? ev.event_type, Actor: r(ev, "github.audit.actor") ?? user, Repo: r(ev, "github.audit.repo", "github.actions.repository"), User: user, ActorIp: ev.src_ip, Email: user, Org: ctx.org });
    case "cloud_gcp":
      return build("GoogleCloudSCC", ev, tenantId, { Findings: { ...(ev.raw ?? {}), hostname: ev.hostname, sourceIp: ev.src_ip, user }, FindingsResource: { name: ev.cloud?.resource ?? ev.hostname }, SourceProperties: { description: ev.description }, SourceSystem: "Azure" });
    case "cloud_azure":
      if (/blob/i.test(v)) {
        return build("StorageBlobLogs", ev, tenantId, { AccountName: r(ev, "AccountName") ?? ev.hostname, CallerIpAddress: ev.src_ip, Category: r(ev, "Category") ?? "StorageRead", OperationName: r(ev, "OperationName"), ObjectKey: r(ev, "ObjectKey"), Uri: r(ev, "Uri"), UserAgentHeader: r(ev, "UserAgentHeader"), AuthenticationType: r(ev, "AuthenticationType"), RequesterUpn: user, SourceSystem: "Azure" });
      }
      if (/graph/i.test(v)) {
        return build("MicrosoftGraphActivityLogs", ev, tenantId, { IPAddress: ev.src_ip, UserId: user, RequestUri: r(ev, "requestUri") ?? ev.network?.url, RequestMethod: ev.network?.method, ResponseStatusCode: ev.network?.status, UserAgent: ev.network?.user_agent, DeviceId: ev.hostname, SourceSystem: "Azure" });
      }
      return build("AzureDiagnostics", ev, tenantId, {
        Category: r(ev, "azure.open_ai.category") ?? "Audit", OperationName: r(ev, "azure.open_ai.operation_name") ?? ev.cloud?.api_call, ResourceProvider: "MICROSOFT.COGNITIVESERVICES", Resource: ev.hostname ?? ev.cloud?.resource, CallerIPAddress: ev.src_ip ?? r(ev, "azure.open_ai.caller_ip_address"),
        Caller_s: user, Message: ev.description, SourceSystem: "Azure",
      });
    case "siem": {
      if (r(ev, "Type") === "W3CIISLog") {
        return build("W3CIISLog", ev, tenantId, {
          Computer: r(ev, "Computer") ?? ev.hostname, sSiteName: r(ev, "sSiteName"), sComputerName: r(ev, "sComputerName"), sIP: r(ev, "sIP") ?? ev.dst_ip, sPort: num(r(ev, "sPort")), csMethod: r(ev, "csMethod"), csUriStem: r(ev, "csUriStem"), csUriQuery: r(ev, "csUriQuery"),
          csUserName: r(ev, "csUserName") ?? user, cIP: ev.src_ip ?? r(ev, "cIP"), csHost: r(ev, "csHost"), csUserAgent: r(ev, "csUserAgent"), scStatus: r(ev, "scStatus"), SourceSystem: "OpsManager",
        });
      }
      if (/anthropic/i.test(v)) return custom(ev, "BV_ClaudeCompliance_ComplianceActivities_CL", tenantId);
      if (/canary/i.test(v)) return custom(ev, "ThinkstCanaryIncidents_CL", tenantId);
      if (/content safety/i.test(v)) return build("AzureDiagnostics", ev, tenantId, { Category: "Audit", OperationName: ev.event_type, ResourceProvider: "MICROSOFT.COGNITIVESERVICES", Resource: ev.hostname, CallerIPAddress: ev.src_ip, Caller_s: user, Message: ev.description, SourceSystem: "Azure" });
      break;
    }
    case "edr":
      return build("DeviceEvents", ev, tenantId, {
        Timestamp: ev.ts, DeviceId: ctx.hex(`${ctx.companyId}:${deviceKey(ev.hostname ?? "")}`, 40), DeviceName: ev.hostname, ActionType: "SensitiveFileRead", FileName: ev.file?.name, FolderPath: ev.file?.path, SHA256: ev.file?.sha256,
        AccountName: user?.split("@")[0].split("\\").pop(), AccountUpn: user?.includes("@") ? user : undefined, LocalIP: ev.src_ip, RemoteIP: ev.dst_ip, InitiatingProcessFileName: ev.process?.name, InitiatingProcessCommandLine: ev.process?.cmdline, InitiatingProcessId: ev.process?.pid, SourceSystem: "Azure",
      });
    case "windows_security": case "ad":
      if (/terminalservices/i.test(v)) return eventRow(ev, tenantId, "Microsoft-Windows-TerminalServices-LocalSessionManager", "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational");
      return build("SecurityEvent", ev, tenantId, {
        EventID: num(r(ev, "winlog.event_id", "event.code")) ?? 0, Computer: ev.hostname, Channel: "Security", EventSourceName: "Microsoft-Windows-Security-Auditing", Account: user, TargetUserName: user?.split("@")[0], IpAddress: ev.src_ip, Activity: ev.description, SourceSystem: "OpsManager",
        EventData: JSON.stringify(ev.raw ?? {}),
      });
    case "proxy":
      return cefRow(ev, tenantId, "Zscaler", "NSSWeblog", { RequestURL: ev.network?.url, SourceHostName: ev.hostname, DestinationHostName: ev.network?.domain ?? ev.hostname });
    case "gws":
      return build("GoogleWorkspaceReports", ev, tenantId, { ActorEmail: user, SrcIpAddr: ev.src_ip, EventName: r(ev, "gws.event.type") ?? ev.event_type, EventType: ev.event_type, EventParameters: ev.raw ?? {}, EventVendor: "Google", EventProduct: "Workspace", IdTime: ev.ts, IdApplicationName: "gmail" });
    case "email_gateway":
      return build("ProofPointTAPMessagesDeliveredV2_CL", ev, tenantId, { QID: r(ev, "pps.QID"), messageID: r(ev, "pps.messageID"), sender: r(ev, "pps.sender"), senderIP: r(ev, "pps.senderIP") ?? ev.src_ip, headerFrom: r(ev, "pps.headerFrom"), subject: r(ev, "pps.subject"), recipient: user ? [user] : [], phishScore: num(r(ev, "pps.phishScore")), spamScore: num(r(ev, "pps.spamScore")), messageTime: ev.ts });
    case "dlp":
      return build("CloudAppEvents", ev, tenantId, { Timestamp: ev.ts, Application: "Microsoft Purview", ActionType: r(ev, "purview.action") ?? ev.event_type, AccountDisplayName: user, AccountId: user, IPAddress: ev.src_ip, ObjectName: ev.file?.name, DeviceType: ev.hostname, RawEventData: ev.raw ?? {}, SourceSystem: "Azure" });
    case "o365": case "exchange": case "sharepoint":
      return build("OfficeActivity", ev, tenantId, { Operation: r(ev, "data.office365.Operation") ?? ev.event_type, UserId: user, ClientIP: ev.src_ip, OfficeWorkload: r(ev, "data.office365.Workload"), RecordType: r(ev, "data.office365.RecordType"), OfficeObjectId: r(ev, "data.office365.ObjectId"), OfficeId: r(ev, "data.office365.Id") ?? ev.id, UserAgent: ev.network?.user_agent, SourceSystem: "OfficeActivityManager", MachineId: ev.hostname });
    default: break;
  }
  if (/exabeam/i.test(v)) return custom(ev, "Exabeam_CL", tenantId, record);
  if (/securonix/i.test(v)) return custom(ev, "Securonix_CL", tenantId, record);
  if (/github/i.test(v)) return build("GitHubAuditLogsV2_CL", ev, tenantId, { Action: ev.event_type, Actor: user, User: user, ActorIp: ev.src_ip, Email: user, Org: ctx.org });
  if (/cloudwatch/i.test(v)) return build("AWSCloudWatch", ev, tenantId, { Message: JSON.stringify({ description: ev.description, hostname: ev.hostname, user, src: ev.src_ip, dst: ev.dst_ip, ...(ev.raw ?? {}) }), ExtractedTime: ev.ts, SourceSystem: "Azure" });
  return custom(ev, "ThirdPartyLogs_CL", tenantId, record);
}

/** Where a table states who, on what, from where. Rows are held to the feed event on these. */
export const IDENTITY_COLUMNS: Record<string, { user?: string[]; host?: string[]; ip?: string[] }> = {
  SigninLogs: { user: ["UserPrincipalName"], ip: ["IPAddress", "IPAddressFromResourceProvider"] },
  AuditLogs: { user: ["Identity"] },
  SecurityEvent: { user: ["TargetUserName", "SubjectUserName", "Account", "UserPrincipalName"], host: ["Computer", "WorkstationName"], ip: ["IpAddress", "ClientIPAddress", "RemoteIpAddress"] },
  Event: { user: ["UserName"], host: ["Computer"] },
  DeviceProcessEvents: { user: ["AccountUpn", "AccountName"], host: ["DeviceName"] },
  DeviceNetworkEvents: { user: ["InitiatingProcessAccountUpn", "InitiatingProcessAccountName"], host: ["DeviceName"], ip: ["LocalIP", "RemoteIP"] },
  DeviceFileEvents: { user: ["RequestAccountName", "InitiatingProcessAccountUpn", "InitiatingProcessAccountName"], host: ["DeviceName"] },
  DeviceRegistryEvents: { user: ["InitiatingProcessAccountUpn", "InitiatingProcessAccountName"], host: ["DeviceName"] },
  DeviceLogonEvents: { user: ["AccountName"], host: ["DeviceName"], ip: ["RemoteIP"] },
  DeviceEvents: { user: ["AccountName", "InitiatingProcessAccountName"], host: ["DeviceName"], ip: ["LocalIP", "RemoteIP"] },
  AlertEvidence: { user: ["AccountUpn", "AccountName"], host: ["DeviceName"], ip: ["RemoteIP", "LocalIP"] },
  OfficeActivity: { user: ["UserId"], ip: ["ClientIP", "Client_IPAddress"] },
  EmailEvents: { user: ["RecipientEmailAddress"], ip: ["SenderIPv4"] },
  EmailAttachmentInfo: { user: ["RecipientEmailAddress"] },
  EmailPostDeliveryEvents: { user: ["RecipientEmailAddress"] },
  UrlClickEvents: { user: ["AccountUpn"], ip: ["IPAddress"] },
  CommonSecurityLog: { user: ["SourceUserName", "DestinationUserName"], host: ["SourceHostName", "DestinationHostName", "Computer", "DeviceName"], ip: ["SourceIP", "DestinationIP", "SourceTranslatedAddress"] },
  Syslog: { host: ["Computer", "HostName"], ip: ["HostIP"] },
  DnsEvents: { ip: ["ClientIP"] },
  AzureActivity: { user: ["Caller"], ip: ["CallerIpAddress"] },
  AWSCloudTrail: { user: ["UserIdentityPrincipalid", "UserIdentityArn", "UserIdentityUserName"], ip: ["SourceIpAddress"] },
  GCPAuditLogs: { user: ["PrincipalEmail"] },
  OktaV2_CL: { user: ["OriginalActorAlternateId", "ActorUsername"], ip: ["SrcIpAddr"] },
  GoogleWorkspaceReports: { user: ["ActorEmail"], ip: ["SrcIpAddr"] },
  AKSAudit: { user: ["User"] },
  BehaviorAnalytics: { user: ["UserPrincipalName"], host: ["SourceDevice"], ip: ["SourceIPAddress", "DestinationIPAddress"] },
  AWSWAF: { ip: ["ClientIp"] },
  AGWFirewallLogs: { host: ["Hostname"], ip: ["ClientIp"] },
  AzureDiagnostics: { user: ["Caller_s"], host: ["Resource"], ip: ["CallerIPAddress"] },
  W3CIISLog: { user: ["csUserName"], host: ["Computer"], ip: ["cIP", "sIP"] },
  StorageBlobLogs: { user: ["RequesterUpn"], ip: ["CallerIpAddress"] },
  CloudAppEvents: { user: ["AccountDisplayName"], ip: ["IPAddress"] },
  CloudflareV2_CL: { user: ["Email"], host: ["ClientRequestHost"], ip: ["ClientIP"] },
  GitHubAuditLogsV2_CL: { user: ["Actor", "User"], ip: ["ActorIp"] },
  ASimAuditEventLogs: { user: ["ActorUsername"], host: ["DvcHostname"], ip: ["SrcIpAddr"] },
  MicrosoftGraphActivityLogs: { user: ["UserId"], ip: ["IPAddress"] },
};

/** The columns of a custom table, for the same check. */
const CUSTOM_IDENTITY = { user: ["ActorUsername"], host: ["DvcHostname"], ip: ["SrcIpAddr", "DstIpAddr"] };
export const identityColumns = (table: string) => IDENTITY_COLUMNS[table] ?? (isCustomTable(table) ? CUSTOM_IDENTITY : undefined);

/** Where a row notes what the feed event states and the table has no free column for. */
const NOTE_TEXT: Record<string, string> = { Syslog: "SyslogMessage", DnsEvents: "Message", Event: "RenderedDescription", AGWFirewallLogs: "Message", AzureDiagnostics: "Message", AuditLogs: "ResultDescription", SecurityEvent: "Activity", CommonSecurityLog: "Message", AWSCloudTrail: "ServiceEventDetails", AzureActivity: "Hierarchy", W3CIISLog: "csUriQuery", GCPAuditLogs: "StatusMessage" };
const NOTE_DYNAMIC: Record<string, string> = { OktaV2_CL: "DebugData", AKSAudit: "Annotations", SigninLogs: "MfaDetail", OfficeActivity: "OperationProperties", GoogleWorkspaceReports: "EventParameters", AWSWAF: "HttpRequest", BehaviorAnalytics: "ActivityInsights", DeviceNetworkEvents: "AdditionalFields", DeviceEvents: "AdditionalFields", DeviceLogonEvents: "AdditionalFields", DeviceProcessEvents: "AdditionalFields", DeviceFileEvents: "AdditionalFields", DeviceRegistryEvents: "AdditionalFields", AlertEvidence: "AdditionalFields", UrlClickEvents: "AdditionalFields" };

/**
 * A native record does not always print what the feed row states: a firewall session names no user, a
 * cloud sign-in prints the office egress for a client the row gives its private address. Where the table
 * has a free column the row takes the value there; otherwise it is noted, so that a search on the value
 * finds the row. A value the record prints is never changed.
 */
export function noteAddress(table: string, row: KqlRow, ip: string): void {
  const dyn = NOTE_DYNAMIC[table], text = NOTE_TEXT[table];
  if (JSON.stringify(row).includes(ip)) return;
  if (text) row[text] = [row[text], `ip=${ip}`].filter(Boolean).join(" ");
  else if (dyn) row[dyn] = { ...(typeof row[dyn] === "object" ? (row[dyn] as object) : {}), feed: `ip=${ip}` };
}

export function reconcileRow(table: string, row: KqlRow, ev: TelemetryEvent): void {
  row.TimeGenerated = new Date(ev.ts).toISOString();
  const cols = identityColumns(table);
  const notes: string[] = [];
  const text = JSON.stringify(row).toLowerCase();
  const fill = (names: string[] | undefined, value: string | undefined, label: string, mentioned: (s: string) => boolean) => {
    if (!value || !names) return;
    if (mentioned(text)) return;
    const free = names.find(n => row[n] === undefined || row[n] === "");
    if (free) row[free] = value; else notes.push(`${label}=${value}`);
  };
  const user = ev.user_email ?? ev.user?.email;
  const local = user?.split("@")[0].toLowerCase();
  fill(cols?.user, user, "user", s => !!local && (s.includes(local) || s.includes(local.replace(/\./g, ""))));
  const host = ev.hostname?.split(".")[0].toLowerCase();
  fill(cols?.host, ev.hostname, "host", s => !!host && s.includes(host));
  for (const ip of [ev.src_ip, ev.dst_ip]) if (ip) fill(cols?.ip, ip, "ip", s => s.includes(ip));
  if (!notes.length) return;
  const note = NOTE_TEXT[table];
  if (note) { row[note] = [row[note], ...notes].filter(Boolean).join(" "); return; }
  const dyn = NOTE_DYNAMIC[table];
  if (dyn) { row[dyn] = { ...(typeof row[dyn] === "object" ? (row[dyn] as object) : {}), feed: notes.join(" ") }; return; }
  if (isCustomTable(table)) row.RawData = { ...(row.RawData as object), feed: notes.join(" ") };
}
