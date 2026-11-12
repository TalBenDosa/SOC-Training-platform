/**
 * Native log -> Log Analytics row. One mapping per source, following what the real connector does.
 *
 * Every value comes from the native record (the feed's source of truth), so a value in KQL equals the
 * value in the team feed. A mapping is declarative on purpose: the same table drives the row (mapRow)
 * and the reverse lookup that compiles a use case into KQL over the mapped columns (fieldOn, rules.ts).
 *
 * Connector facts behind the mappings:
 *  - OktaV2_CL, SentinelOneThreats_CL, SophosEP*_CL, ProofPointTAP*V2_CL: the transformKql of each
 *    connector's DCR in github.com/Azure/Azure-Sentinel/Solutions.
 *  - CommonSecurityLog: learn.microsoft.com/en-us/azure/sentinel/cef-name-mapping, with DeviceVendor /
 *    DeviceProduct as the Azure-Sentinel connector queries test them. CEF keys with no column stay in
 *    AdditionalExtensions.
 *  - CrowdStrike: the Falcon SIEM connector's CEF (detections) and the Falcon Data Replicator connector's
 *    ASIM tables (sensor telemetry).
 *
 * A record with no real table returns null. It is left out and counted, never forced into a wrong table.
 */
import type { KqlRow, KqlType } from "@/lib/kql/types";
import { getAll } from "@/lib/logs/native/paths";
import type { NativeLog, SourceId } from "@/lib/logs/native/types";
import { columnType } from "./tables";

export interface MapContext {
  tenantId: string;
  /** The cloud the company runs on (its stack's `cloud` source): AKS audit logs exist on Azure only. */
  cloud?: SourceId;
}

export interface MappedRow { table: string; row: KqlRow }

type Rec = Record<string, unknown>;
type Fn = (r: Rec, log: NativeLog, ctx: MapContext) => unknown;

/** How one native kind lands in one table. */
export interface Spec {
  table: string;
  /** KQL predicate that isolates this source's rows in a shared table. */
  base?: string;
  /** KQL predicate for one kind within the source. */
  kindFilter?: (kind: string) => string | undefined;
  /** Column -> native path (reversible) or function. */
  cols: Record<string, string | Fn>;
  /** Constant columns. */
  fixed?: Rec | ((ctx: MapContext) => Rec);
  /** Record keys under this prefix copy to the columns of the same name. */
  pass?: { prefix: string };
  /** Native paths with no column of their own: the KQL that reads them. */
  exprs?: Record<string, string>;
  /** Native values the column stores under another name, by native path. */
  values?: Record<string, Record<string, string>>;
  /** Native fields with no column go in AdditionalExtensions as `<prefix><field>=value`. */
  extension?: { prefix: string };
  /** Native fields with no column go in the EventData XML (SecurityEvent, Event). */
  eventData?: boolean;
  /** Native fields with no column go in this dynamic column (ASIM's AdditionalFields). */
  rest?: string;
}

const first = (r: unknown, path: string): unknown => getAll(r, path)[0];
const str = (v: unknown): string | undefined => (v === undefined || v === null || v === "" ? undefined : String(v));
const iso = (ms: number): string => new Date(ms).toISOString();

const esc = (v: string) => v.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

/** Leaf scalars of a record, dotted (arrays and null left out). */
function scalars(o: Rec, prefix = "", out: [string, unknown][] = []): [string, unknown][] {
  for (const [k, v] of Object.entries(o)) {
    const p = prefix ? `${prefix}.${k}` : k;
    if (v === null || v === undefined || v === "") continue;
    if (Array.isArray(v)) continue;
    if (typeof v === "object") scalars(v as Rec, p, out);
    else out.push([p, v]);
  }
  return out;
}

function coerce(t: KqlType, v: unknown): unknown {
  if (v === undefined || v === null || v === "") return undefined;
  switch (t) {
    case "string": return typeof v === "object" ? JSON.stringify(v) : String(v);
    case "int": case "long": case "real": { const n = typeof v === "number" ? v : Number(v); return Number.isFinite(n) ? n : undefined; }
    case "bool": return v === true || v === "true" || v === "True" || v === 1 || v === "1";
    case "datetime": {
      if (typeof v === "number") return iso(v);
      const ms = Date.parse(String(v));
      return Number.isFinite(ms) ? iso(ms) : undefined;
    }
    default: return v;
  }
}

// ── Microsoft identity ───────────────────────────────────────────────────────

const ENTRA_SIGNIN: Spec = {
  table: "SigninLogs",
  cols: {
    Id: "id", CreatedDateTime: "createdDateTime", UserDisplayName: "userDisplayName", Identity: "userDisplayName",
    UserPrincipalName: "userPrincipalName", UserId: "userId", UserType: r => { const t = str(r.userType); return t && t[0].toUpperCase() + t.slice(1); },
    AppId: "appId", AppDisplayName: "appDisplayName", IPAddress: "ipAddress", AutonomousSystemNumber: "autonomousSystemNumber",
    ClientAppUsed: "clientAppUsed", UserAgent: "userAgent", CorrelationId: "correlationId", OriginalRequestId: "originalRequestId",
    ConditionalAccessStatus: "conditionalAccessStatus", IsInteractive: "isInteractive", AuthenticationProtocol: "authenticationProtocol",
    IncomingTokenType: "incomingTokenType", AuthenticationRequirement: "authenticationRequirement", AuthenticationMethodsUsed: "authenticationMethodsUsed",
    TokenIssuerName: "tokenIssuerName", TokenIssuerType: "tokenIssuerType", ProcessingTimeInMilliseconds: "processingTimeInMilliseconds",
    RiskDetail: "riskDetail", RiskLevelAggregated: "riskLevelAggregated", RiskLevelDuringSignIn: "riskLevelDuringSignIn", RiskState: "riskState",
    RiskEventTypes_V2: "riskEventTypes_v2", ResourceIdentity: "resourceId", ResourceDisplayName: "resourceDisplayName",
    ResourceTenantId: "resourceTenantId", HomeTenantId: "homeTenantId", HomeTenantName: "homeTenantName", SignInIdentifier: "signInIdentifier",
    SignInIdentifierType: "signInIdentifierType", ServicePrincipalId: "servicePrincipalId", SessionId: "sessionId", UniqueTokenIdentifier: "uniqueTokenIdentifier",
    CrossTenantAccessType: "crossTenantAccessType", FlaggedForReview: "flaggedForReview", IsTenantRestricted: "isTenantRestricted",
    // Flattened and renamed, as the diagnostic export does.
    ResultType: "status.errorCode", ResultDescription: "status.failureReason", Location: "location.countryOrRegion",
    DeviceDetail: "deviceDetail", LocationDetails: "location", Status: "status", ConditionalAccessPolicies: "appliedConditionalAccessPolicies",
    AuthenticationProcessingDetails: "authenticationProcessingDetails", NetworkLocationDetails: "networkLocationDetails", AuthenticationDetails: "authenticationDetails",
    MfaDetail: "mfaDetail",
  },
  fixed: ctx => ({
    Category: "SignInLogs", OperationName: "Sign-in activity", OperationVersion: "1.0", SourceSystem: "Azure AD", Level: "4",
    Resource: "Microsoft.aadiam", ResourceProvider: "Microsoft.aadiam", ResourceGroup: "Microsoft.aadiam",
    ResourceId: `/tenants/${ctx.tenantId}/providers/Microsoft.aadiam`, AADTenantId: ctx.tenantId,
  }),
};

const ENTRA_AUDIT: Spec = {
  table: "AuditLogs",
  cols: {
    Id: "id", Category: "category", CorrelationId: "correlationId", Result: "result", ResultReason: "resultReason",
    ActivityDisplayName: "activityDisplayName", OperationName: "activityDisplayName", ActivityDateTime: "activityDateTime",
    LoggedByService: "loggedByService", AADOperationType: "operationType", InitiatedBy: "initiatedBy", TargetResources: "targetResources",
    AdditionalDetails: "additionalDetails",
    Identity: r => str(first(r, "initiatedBy.user.userPrincipalName")) ?? str(first(r, "initiatedBy.app.displayName")),
  },
  fixed: ctx => ({
    OperationVersion: "1.0", SourceSystem: "Azure AD", Level: "Informational", Resource: "Microsoft.aadiam", ResourceProvider: "Microsoft.aadiam",
    ResourceGroup: "Microsoft.aadiam", ResourceId: `/tenants/${ctx.tenantId}/providers/Microsoft.aadiam`, AADTenantId: ctx.tenantId,
  }),
};

/** A directory change seen through the Unified Audit Log: the Office connector skips it, Entra's own export carries it. */
const UAL_DIRECTORY: Spec = {
  table: "AuditLogs",
  cols: {
    Id: "Id", CorrelationId: "CorrelationId",
    OperationName: r => str(r.Operation)?.replace(/\.$/, ""), ActivityDisplayName: r => str(r.Operation)?.replace(/\.$/, ""),
    ActivityDateTime: "CreationTime", Result: r => (/success/i.test(String(r.ResultStatus)) ? "success" : "failure"), Identity: "UserId",
    InitiatedBy: r => ({ user: { userPrincipalName: r.UserId, ipAddress: r.ClientIP } }),
    TargetResources: r => [{ id: r.ObjectId, modifiedProperties: r.ModifiedProperties ?? [] }],
    AdditionalDetails: "ExtendedProperties",
  },
  fixed: ctx => ({
    Category: "ApplicationManagement", LoggedByService: "Core Directory", OperationVersion: "1.0", SourceSystem: "Azure AD", Level: "Informational",
    Resource: "Microsoft.aadiam", ResourceProvider: "Microsoft.aadiam", ResourceGroup: "Microsoft.aadiam",
    ResourceId: `/tenants/${ctx.tenantId}/providers/Microsoft.aadiam`, AADTenantId: ctx.tenantId,
  }),
  exprs: {
    Operation: `strcat(OperationName, ".")`,
    "ModifiedProperties[].NewValue": "tostring(TargetResources)", UserId: "Identity", ClientIP: "tostring(InitiatedBy.user.ipAddress)",
  },
};

// ── Windows ──────────────────────────────────────────────────────────────────

const UAC: Record<string, string> = { "2": "2 - Interactive", "3": "3 - Network", "4": "4 - Batch", "5": "5 - Service", "7": "7 - Unlock", "8": "8 - NetworkCleartext", "9": "9 - NewCredentials", "10": "10 - RemoteInteractive", "11": "11 - CachedInteractive" };

const account = (domain: unknown, user: unknown) => {
  const u = str(user);
  if (!u || u === "-") return undefined;
  const d = str(domain);
  return d && d !== "-" ? `${d}\\${u}` : u;
};

const WINDOWS_SECURITY: Spec = {
  table: "SecurityEvent",
  kindFilter: k => `EventID == ${k}`,
  pass: { prefix: "" },
  eventData: true,
  cols: {
    EventID: "EventID", Computer: "Computer", Channel: "Channel", EventSourceName: "Provider", EventRecordId: "EventRecordID",
    Keywords: "KeywordsText", LogonType: "LogonType",
    Account: r => account(r.TargetDomainName, r.TargetUserName) ?? account(r.SubjectDomainName, r.SubjectUserName),
    SubjectAccount: r => account(r.SubjectDomainName, r.SubjectUserName),
    TargetAccount: r => account(r.TargetDomainName, r.TargetUserName),
    LogonTypeName: r => UAC[String(r.LogonType)],
    Process: r => str(r.ProcessName)?.split("\\").pop(),
    Activity: r => `${r.EventID}`,
  },
  fixed: { SourceSystem: "OpsManager", Level: "8" },
};

const SYSMON_DESC: Record<string, string> = {
  "1": "Process Create", "3": "Network connection detected", "5": "Process terminated", "6": "Driver loaded", "7": "Image loaded", "8": "CreateRemoteThread detected",
  "10": "Process accessed", "11": "File created", "12": "Registry object added or deleted", "13": "Registry value set", "15": "File stream created",
  "17": "Pipe Created", "18": "Pipe Connected", "22": "Dns query", "23": "File Delete archived",
};
const SYSMON_HEADER = new Set(["ProviderName", "EventID", "Version", "Level", "Task", "Opcode", "Keywords", "TimeCreated", "EventRecordID", "ProcessID", "ThreadID", "Channel", "Computer", "UserID"]);

const SYSMON: Spec = {
  table: "Event",
  base: `Source == "Microsoft-Windows-Sysmon"`,
  kindFilter: k => `EventID == ${k}`,
  cols: {
    EventID: "EventID", Computer: "Computer", EventLog: "Channel", EventCategory: "Task", EventLevel: "Level", UserName: "User",
    RenderedDescription: r => {
      const body = Object.entries(r).filter(([k]) => !SYSMON_HEADER.has(k)).map(([k, v]) => `${k}: ${v}`).join("\n");
      return `${SYSMON_DESC[String(r.EventID)] ?? "Sysmon event"}:\n${body}`;
    },
    EventData: r => `<DataItem type="System.XmlData" time="${r.TimeCreated}" sourceHealthServiceId=""><EventData xmlns="http://schemas.microsoft.com/win/2004/08/events/event">${
      Object.entries(r).filter(([k]) => !SYSMON_HEADER.has(k)).map(([k, v]) => `<Data Name="${k}">${esc(String(v))}</Data>`).join("")}</EventData></DataItem>`,
  },
  fixed: { Source: "Microsoft-Windows-Sysmon", EventLevelName: "Information", SourceSystem: "OpsManager" },
  eventData: true,
};

const QTYPE_NAME: Record<string, string> = { "1": "A", "2": "NS", "5": "CNAME", "6": "SOA", "12": "PTR", "15": "MX", "16": "TXT", "28": "AAAA", "33": "SRV", "255": "ANY" };

const WINDOWS_DNS: Spec = {
  table: "DnsEvents",
  kindFilter: k => `EventId == ${k}`,
  cols: {
    Computer: "Computer", EventId: "EventID", ClientIP: "Destination", ResultCode: "RCODE", TaskCategory: r => (r.EventID === 256 ? "QUERY_RECEIVED" : "RESPONSE_SUCCESS"),
    Name: r => str(first(r, "QNAME"))?.replace(/\.$/, ""),
    QueryType: r => QTYPE_NAME[String(r.QTYPE)] ?? str(r.QTYPE),
    Result: r => (String(r.RCODE) === "0" ? "Success" : "Failed"),
    Message: log => log.QNAME,
  },
  fixed: { SubType: "LookupQuery", SourceSystem: "OpsManager" },
  exprs: { QNAME: `strcat(Name, ".")`, QTYPE: "QueryType" },
  values: { QTYPE: QTYPE_NAME },
};

// ── Endpoint: Defender for Endpoint (the record is already the streamed row) ─

const passProperties = (table: string): Spec => ({ table, pass: { prefix: "properties." }, cols: {}, fixed: { SourceSystem: "Azure" } });

// ── CommonSecurityLog (CEF) ──────────────────────────────────────────────────

const ext = (prefix: string): Spec["extension"] => ({ prefix });

const PAN_BASE = `DeviceVendor == "Palo Alto Networks" and DeviceProduct has "PAN-OS"`;
const PAN_COMMON: Spec["cols"] = {
  ReceiptTime: "receive_time", DeviceExternalID: "serial", DeviceName: "device_name", Computer: "device_name", DeviceEventClassID: "subtype", Activity: "type",
  SourceIP: "src", DestinationIP: "dst", SourceTranslatedAddress: "natsrc", DestinationTranslatedAddress: "natdst", SourceUserName: "srcuser", DestinationUserName: "dstuser",
  ApplicationProtocol: "app", DeviceInboundInterface: "inbound_if", DeviceOutboundInterface: "outbound_if", SourcePort: "sport", DestinationPort: "dport",
  SourceTranslatedPort: "natsport", DestinationTranslatedPort: "natdport", Protocol: "proto", DeviceAction: "action", SentBytes: "bytes_sent", ReceivedBytes: "bytes_received",
  DeviceCustomString1: "rule", DeviceCustomString2: "category", DeviceCustomString3: "vsys", DeviceCustomString4: "from", DeviceCustomString5: "to", DeviceCustomString6: "logset",
  DeviceCustomNumber1: "sessionid", DeviceCustomNumber2: "packets", DeviceCustomNumber3: "elapsed", FlexString1: "flags", FlexNumber1: "bytes", EventCount: "repeatcnt",
  ExtID: "seqno", Reason: "session_end_reason", RequestURL: "misc", RequestMethod: "http_method", RequestClientApplication: "user_agent", FileName: "misc_file",
  LogSeverity: "severity", DeviceEventCategory: "thr_category", SourceHostName: "src_host",
};
const PAN_FIXED: Rec = {
  DeviceVendor: "Palo Alto Networks", DeviceProduct: "PAN-OS", DeviceCustomString1Label: "Rule", DeviceCustomString2Label: "URL Category", DeviceCustomString3Label: "Virtual System",
  DeviceCustomString4Label: "Source Zone", DeviceCustomString5Label: "Destination Zone", DeviceCustomString6Label: "LogProfile", DeviceCustomNumber1Label: "SessionID",
  DeviceCustomNumber2Label: "Packets", DeviceCustomNumber3Label: "Elapsed time in seconds", FlexString1Label: "Flags", FlexNumber1Label: "Total bytes", SourceSystem: "OpsManager",
};
const PALOALTO: Spec = {
  table: "CommonSecurityLog", base: PAN_BASE, kindFilter: k => `Activity == "${k}"`, cols: PAN_COMMON, fixed: PAN_FIXED, extension: ext("PanOS"),
};
const GLOBALPROTECT: Spec = {
  table: "CommonSecurityLog", base: `${PAN_BASE} and Activity == "GLOBALPROTECT"`, kindFilter: k => `DeviceEventClassID == "${k}"`,
  cols: {
    ReceiptTime: "receive_time", DeviceExternalID: "serial", DeviceName: "device_name", Computer: "device_name", DeviceEventClassID: "eventid", Activity: "type",
    SourceUserName: "srcuser", SourceIP: "public_ip", SourceTranslatedAddress: "private_ip", SourceHostName: "machinename", EventOutcome: "status", Reason: "reason", ExtID: "seqno",
    DeviceCustomString1: "gateway", DeviceCustomString2: "portal", DeviceCustomString3: "auth_method", DeviceCustomString4: "stage", DeviceCustomString5: "srcregion", Message: "error",
  },
  fixed: { DeviceVendor: "Palo Alto Networks", DeviceProduct: "PAN-OS", DeviceCustomString1Label: "Gateway", DeviceCustomString2Label: "Portal", DeviceCustomString3Label: "AuthMethod",
    DeviceCustomString4Label: "Stage", DeviceCustomString5Label: "SourceRegion", SourceSystem: "OpsManager" },
  extension: ext("PanOS"),
};

const FTNT_BASE = `DeviceVendor =~ "Fortinet" and DeviceProduct startswith "Fortigate"`;
const FORTIGATE: Spec = {
  table: "CommonSecurityLog", base: FTNT_BASE,
  kindFilter: k => `DeviceEventCategory == "${k.replace("/", ":")}"`,
  cols: {
    DeviceExternalID: "devid", DeviceName: "devname", Computer: "devname", DeviceEventClassID: "logid", SourceIP: "srcip", SourcePort: "srcport", DestinationIP: "dstip", DestinationPort: "dstport",
    DeviceInboundInterface: "srcintf", DeviceOutboundInterface: "dstintf", Protocol: "proto", DeviceAction: "action", SentBytes: "sentbyte", ReceivedBytes: "rcvdbyte",
    SourceUserName: "user", DestinationHostName: "hostname", RequestURL: "url", Message: "msg", LogSeverity: "level", DestinationServiceName: "service", ExtID: "sessionid",
    DeviceEventCategory: r => `${r.type}:${r.subtype}`,
    Activity: r => `${r.type}:${r.subtype} ${r.action ?? ""}`.trim(),
  },
  fixed: { DeviceVendor: "Fortinet", DeviceProduct: "Fortigate", SourceSystem: "OpsManager" },
  extension: ext("FTNTFGT"),
};
const FORTIGATE_SSLVPN: Spec = { ...FORTIGATE, cols: { ...FORTIGATE.cols, SourceIP: "remip", SourceUserName: "user" }, kindFilter: k => `DeviceEventClassID == "${k}"` };

const CHECKPOINT: Spec = {
  table: "CommonSecurityLog", base: `DeviceVendor == "Check Point"`,
  kindFilter: k => ({
    firewall: `DeviceProduct == "VPN-1 & FireWall-1"`, ips: `DeviceProduct == "SmartDefense"`, url_filtering: `DeviceProduct == "URL Filtering"`,
    app_control: `DeviceProduct == "Application Control"`, anti_bot: `DeviceProduct == "Anti-Bot"`,
  } as Record<string, string>)[k],
  cols: {
    DeviceProduct: "product", DeviceAddress: "origin", DeviceAction: "action", SourceIP: "src", DestinationIP: "dst", SourcePort: "s_port", DestinationPort: "service", Protocol: "proto",
    CommunicationDirection: "ifdir", DeviceInboundInterface: "ifname", ExtID: "loguid", SourceUserName: "src_user_name", ApplicationProtocol: "appi_name", RequestURL: "resource",
    DeviceEventCategory: "app_category", LogSeverity: "severity", Message: "protection_name", Computer: "originsicname", SentBytes: "client_outbound_bytes", ReceivedBytes: "client_inbound_bytes",
    Activity: r => str(r.product),
  },
  fixed: { DeviceVendor: "Check Point", SourceSystem: "OpsManager" },
  extension: ext(""),
};

const ciscoSpec = (product: string, cols: Spec["cols"]): Spec => ({
  table: "CommonSecurityLog", base: `DeviceVendor =~ "Cisco" and DeviceProduct == "${product}"`, kindFilter: k => `DeviceEventClassID == "${k}"`,
  cols, fixed: { DeviceVendor: "Cisco", DeviceProduct: product, SourceSystem: "OpsManager" }, extension: ext(""),
});
const CISCO_FTD = ciscoSpec("FTD", {
  DeviceEventClassID: "Message_number", Computer: "device_id", DeviceName: "device_id", DeviceAction: "AccessControlRuleAction", SourceIP: "SrcIP", DestinationIP: "DstIP", SourcePort: "SrcPort", DestinationPort: "DstPort",
  Protocol: "Protocol", DeviceInboundInterface: "IngressInterface", DeviceOutboundInterface: "EgressInterface", SourceUserName: "User", ApplicationProtocol: "ApplicationProtocol",
  SentBytes: "InitiatorBytes", ReceivedBytes: "ResponderBytes", RequestURL: "URL", ExtID: "ConnectionID", LogSeverity: "Level", Reason: "AccessControlRuleReason", Activity: "EventPriority",
});
const CISCO_ASA = ciscoSpec("ASA", {
  DeviceEventClassID: "Message_number", Computer: "device_id", DeviceName: "device_id", LogSeverity: "Level", Message: "Message_text", SourceIP: "Source_IP", DestinationIP: "Destination_IP",
  Activity: "Message_number",
});
const ANYCONNECT = ciscoSpec("ASA", {
  DeviceEventClassID: "message_id", Computer: "hostname", DeviceName: "hostname", LogSeverity: "severity", SourceUserName: "User", SourceIP: "IP", Reason: "Reason", Activity: "message_id",
  Message: r => Object.entries(r).filter(([k]) => !["timestamp", "hostname", "severity", "message_id"].includes(k)).map(([k, v]) => `${k} <${v}>`).join(" "),
});

const CYBERARK: Spec = {
  table: "CommonSecurityLog", base: `DeviceVendor == "Cyber-Ark" and DeviceProduct == "Vault"`, kindFilter: k => `DeviceEventClassID == "${k}"`,
  cols: {
    Computer: "hostname", DeviceVersion: "DeviceVersion", DeviceEventClassID: "SignatureID", Activity: "Name", LogSeverity: "Severity",
    DeviceAction: "act", SourceUserName: "suser", FileName: "fname", SourceHostName: "shost", DestinationHostName: "dhost", DestinationUserName: "duser", ApplicationProtocol: "app", Reason: "reason", Message: "msg",
    DeviceCustomString1: "cs1", DeviceCustomString1Label: "cs1Label", DeviceCustomString2: "cs2", DeviceCustomString2Label: "cs2Label", DeviceCustomString3: "cs3", DeviceCustomString3Label: "cs3Label",
    DeviceCustomString4: "cs4", DeviceCustomString4Label: "cs4Label", DeviceCustomString5: "cs5", DeviceCustomString5Label: "cs5Label", DeviceCustomNumber1: "cn1", DeviceCustomNumber1Label: "cn1Label",
    DeviceCustomNumber2: "cn2", DeviceCustomNumber2Label: "cn2Label",
  },
  fixed: { DeviceVendor: "Cyber-Ark", DeviceProduct: "Vault", SourceSystem: "OpsManager" },
  exprs: { timestamp: `format_datetime(TimeGenerated, "HH:mm:ss")` },
};

const ZSCALER_ZIA: Spec = {
  table: "CommonSecurityLog", base: `DeviceVendor == "Zscaler" and DeviceProduct == "NSSWeblog"`,
  cols: {
    DeviceAction: "event.action", Reason: "event.reason", ApplicationProtocol: "event.protocol", DestinationHostName: "event.hostname", DestinationIP: "event.serverip",
    SourceIP: "event.ClientIP", SourceTranslatedAddress: "event.clientpublicIP", ReceivedBytes: "event.responsesize", SentBytes: "event.requestsize", RequestURL: "event.url", RequestContext: "event.refererURL",
    EventOutcome: "event.status", RequestClientApplication: "event.useragent", RequestMethod: "event.requestmethod", SourceUserName: "event.user", SourceHostName: "event.devicehostname",
    FileType: "event.filetype", FileHash: "event.md5", DestinationServiceName: "event.appname", DeviceEventCategory: "event.urlcategory", ExtID: "event.event_id",
    DeviceCustomString1: "event.department", DeviceCustomString2: "event.urlcategory", DeviceCustomString3: "event.urlsupercategory", DeviceCustomString4: "event.appclass", DeviceCustomString5: "event.threatname", DeviceCustomString6: "event.threatcategory",
    Computer: "event.location",
  },
  fixed: { DeviceVendor: "Zscaler", DeviceProduct: "NSSWeblog", Activity: "Web", DeviceCustomString1Label: "dept", DeviceCustomString2Label: "urlcat", DeviceCustomString3Label: "urlsupercat", DeviceCustomString4Label: "appclass",
    DeviceCustomString5Label: "threatname", DeviceCustomString6Label: "threatcat", SourceSystem: "OpsManager" },
  extension: ext(""),
};

const FALCON_ALERT: Spec = {
  table: "CommonSecurityLog", base: `DeviceVendor == "CrowdStrike" and DeviceProduct == "FalconHost"`,
  cols: {
    Activity: "display_name", Message: "description", LogSeverity: "severity", ExtID: "composite_id", DestinationHostName: "device.hostname", Computer: "device.hostname", DeviceAddress: "device.local_ip",
    SourceIP: "device.local_ip", DestinationUserName: "user_name", FileName: "filename", FilePath: "filepath", FileHash: "sha256", DeviceCustomString1: "cmdline",
    DeviceCustomString4: "technique_id", DeviceCustomString5: "tactic", DeviceCustomString6: "falcon_host_link", DeviceAction: "pattern_disposition_description",
  },
  fixed: { DeviceVendor: "CrowdStrike", DeviceProduct: "FalconHost", DeviceVersion: "1.0", DeviceEventClassID: "DetectionSummaryEvent", DeviceCustomString1Label: "CommandLine",
    DeviceCustomString4Label: "Technique", DeviceCustomString5Label: "Tactic", DeviceCustomString6Label: "FalconHostLink", SourceSystem: "OpsManager" },
  extension: ext(""),
};

// ── CrowdStrike sensor telemetry (Falcon Data Replicator connector -> ASIM tables) ──

const FDR_FIXED: Rec = { EventVendor: "CrowdStrike", EventProduct: "FDR", EventCount: 1, EventResult: "Success", SourceSystem: "RestAPI" };
const FDR_COMMON: Spec["cols"] = { DvcHostname: "ComputerName", DvcIpAddr: "LocalAddressIP4", DvcId: "aid", EventOriginalType: "event_simpleName", EventOriginalUid: "id", EventStartTime: "timestamp" };
const fdrFilter = (k: string) => `EventOriginalType == "${k}"`;
const commandImage = (cmd: unknown) => /^"([^"]+)"|^(\S+)/.exec(String(cmd ?? ""))?.slice(1).find(Boolean);
const fdrSpec = (table: string, type: string, version: string, cols: Spec["cols"], exprs?: Record<string, string>): Spec => ({
  table, base: `EventVendor == "CrowdStrike"`, kindFilter: fdrFilter, rest: "AdditionalFields",
  cols: { ...FDR_COMMON, ...cols }, fixed: { ...FDR_FIXED, EventType: type, EventSchemaVersion: version }, exprs,
});
const FDR_PROCESS = fdrSpec("ASimProcessEventLogs", "ProcessCreated", "0.1.4", {
  // The sensor omits the image path on some rollups: the command line still names the program.
  TargetProcessName: r => str(r.ImageFileName) ?? commandImage(r.CommandLine), TargetProcessFilename: r => (str(r.ImageFileName) ?? commandImage(r.CommandLine) ?? "").split(/[\\/]/).pop(),
  TargetProcessCommandLine: "CommandLine", TargetProcessId: "RawProcessId", TargetProcessSHA256: "SHA256HashData", TargetProcessSHA1: "SHA1HashData",
  TargetProcessMD5: "MD5HashData", ActingProcessName: "ParentBaseFileName", ParentProcessName: "ParentBaseFileName", ActingProcessId: "ParentProcessId", ActorUsername: "UserName", ActorUserId: "UserSid",
  TargetUsername: "UserName", TargetUserId: "UserSid", DvcOs: "event_platform", TargetProcessIntegrityLevel: "IntegrityLevel",
}, { ImageFileName: "TargetProcessName" });
const FDR_NETWORK = fdrSpec("ASimNetworkSessionLogs", "NetworkSession", "0.2.6", {
  SrcIpAddr: "LocalAddressIP4", SrcPortNumber: "LocalPort", DstIpAddr: "RemoteAddressIP4", DstPortNumber: "RemotePort", NetworkProtocol: "Protocol", SrcAppName: "ContextBaseFileName",
  NetworkDirection: r => (String(r.ConnectionDirection) === "1" ? "Inbound" : "Outbound"),
});
const FDR_FILE = fdrSpec("ASimFileEventLogs", "FileCreated", "0.2.1", {
  TargetFileName: r => str(r.TargetFileName)?.split("\\").pop(), TargetFilePath: "TargetFileName", TargetFileSHA256: "SHA256HashData", ActingProcessName: "ContextBaseFileName", ActorUsername: "UserName", ActorUserId: "UserSid",
});
const FDR_REGISTRY = fdrSpec("ASimRegistryEventLogs", "RegistryValueSet", "0.1.2", {
  RegistryKey: "RegObjectName", RegistryValue: "RegValueName", RegistryValueData: "RegStringValue", ActingProcessName: "ContextBaseFileName", ActorUsername: "UserName", ActorUserId: "UserSid",
});
const FDR_DNS = fdrSpec("ASimDnsActivityLogs", "Query", "0.1.7", {
  DnsQuery: "DomainName", SrcIpAddr: "LocalAddressIP4", SrcHostname: "ComputerName", DnsResponseName: "IP4Records", DnsQueryTypeName: "RequestType", NetworkProtocol: "Protocol",
});

// ── SentinelOne and Sophos: the threat / alert streams their connectors pull ─

const S1_THREAT: Spec = {
  table: "SentinelOneThreats_CL",
  cols: {
    Id: "id", FilePath: "threatInfo.filePath", CloudVerdict: "threatInfo.cloudVerdict", MitigationMode: "agentDetectionInfo.agentMitigationMode", AgentOsType: "agentRealtimeInfo.agentOsType",
    AgentInfected: "agentRealtimeInfo.agentInfected", InitiatingUserId: "threatInfo.initiatingUserId", Engines: "threatInfo.engines", FileExtensionType: "threatInfo.fileExtensionType",
    MitigationStatus: "threatInfo.mitigationStatus", AgentDomain: "agentDetectionInfo.agentDomain", CreatedAt: "threatInfo.createdAt", IsCertValid: "threatInfo.isValidCertificate",
    FileDisplayName: "threatInfo.filePath", AgentIp: "agentDetectionInfo.agentIpV4", AccountName: "agentRealtimeInfo.accountName", AgentMachineType: "agentRealtimeInfo.agentMachineType",
    FileVerificationType: "threatInfo.fileVerificationType", Indicators: "indicators", InitiatedByDescription: "threatInfo.initiatedByDescription", AutomaticallyResolved: "threatInfo.automaticallyResolved",
    AgentId: "agentRealtimeInfo.agentId", ProcessArguments: "threatInfo.maliciousProcessArguments", ThreatName: "threatInfo.threatName", ClassificationSource: "threatInfo.classificationSource",
    UpdatedAt: "threatInfo.updatedAt", InitiatedBy: "threatInfo.initiatedBy", AgentNetworkStatus: "agentRealtimeInfo.agentNetworkStatus", AgentComputerName: "agentRealtimeInfo.agentComputerName",
    Classification: "threatInfo.classification", CertId: "threatInfo.certificateId", AgentIsActive: "agentRealtimeInfo.agentIsActive", SiteId: "agentRealtimeInfo.siteId", AgentVersion: "agentRealtimeInfo.agentVersion",
    FileContentHash: "threatInfo.sha1", FileSha256: "threatInfo.sha256", Username: "threatInfo.processUser", AgentIsDecommissioned: "agentRealtimeInfo.agentIsDecommissioned", CollectionId: "threatInfo.collectionId",
    SiteName: "agentRealtimeInfo.siteName", AccountId: "agentRealtimeInfo.accountId", ThreatInfo: "threatInfo", AgentDetectionInfo: "agentDetectionInfo", AgentRealtimeInfo: "agentRealtimeInfo",
  },
};

const SOPHOS_EVENT: Spec = {
  table: "SophosEPEvents_CL",
  cols: {
    AppSha256: "appSha256", Created: "created_at", CustomerId: "customer_id", DstUserSid: "user_id", DvcHostname: "location", EndpointId: "endpoint_id", EventEndTime: "when", EventMessage: "name",
    EventOriginalUid: "id", EventSubType: "origin", EventSeverity: "severity", DvcAction: "type", Source: "source", SrcDvcType: "endpoint_type", ThreatCategory: "group", ThreatName: "threat",
    SrcIpAddr: "source_info.ip", CoreRemedyItems: r => first(r, "core_remedy_items.items") && JSON.stringify((r.core_remedy_items as Rec).items), CoreRemedyTotalItems: "core_remedy_items.totalItems",
    source_info: "source_info", amsi_threat_data: "amsi_threat_data", ips_threat_data: "ips_threat_data", appCerts: "appCerts", whitelist_properties: "whitelist_properties",
  },
  fixed: { EventType: "event", EventVendor: "Sophos", EventProduct: "Endpoint Protection" },
  exprs: { "core_remedy_items.items[].result": "CoreRemedyItems" },
};
const SOPHOS_ALERT: Spec = {
  table: "SophosEPAlerts_CL",
  cols: {
    CustomerId: "customer_id", DvcAction: "type", DvcHostname: "location", EventEndTime: "when", EventOriginalUid: "id", EventSeverity: "severity", Source: "source", ThreatName: "threat", description: "description",
    data: "data", info: "info", event_service_event_id: "event_service_event_id", threat_cleanable: "threat_cleanable",
  },
  fixed: { EventType: "alert", EventVendor: "Sophos", EventProduct: "Endpoint Protection" },
};
/** Sophos XDR detection: reaches the workspace through the SIEM alerts stream, the only stream the connector pulls. */
const SOPHOS_DETECTION: Spec = {
  table: "SophosEPAlerts_CL",
  cols: {
    EventOriginalUid: "id", DvcHostname: "device.entity", ThreatName: "rawData.detection_name", DvcAction: "detectionRule", EventSeverity: "severity", Source: "rawData.username",
    description: "attackType", EventEndTime: "sensorGeneratedAt", data: "rawData", info: "mitreAttacks",
  },
  fixed: { EventType: "alert", EventVendor: "Sophos", EventProduct: "Endpoint Protection" },
  exprs: { "rawData.process_cmd_line": "tostring(data.process_cmd_line)", "rawData.process_name": "tostring(data.process_name)", "rawData.process_parent_name": "tostring(data.process_parent_name)",
    "rawData.threat_source": "tostring(data.threat_source)", "rawData.detection_name": "ThreatName", "mitreAttacks[].tactic.id": "tostring(info)" },
};

// ── Okta (OktaV2_CL, per the connector's DCR transform) ──────────────────────

const OKTA_RESULT: Record<string, string> = { SUCCESS: "Success", ALLOW: "Success", DENY: "Failure", SKIPPED: "Failure", FAILURE: "Failure", CHALLENGE: "Partial", UNKNOWN: "NA" };
const OKTA_ACTION: Record<string, string> = { ALLOW: "Allow", DENY: "Deny", SKIPPED: "Drop" };
const OKTA_SEV: Record<string, string> = { DEBUG: "Informational", INFO: "Informational", WARN: "Medium", ERROR: "High" };
const OKTA_USER_TYPE: Record<string, string> = { SystemPrincipal: "System Principal", PublicClientApp: "Application", User: "Regular" };

const OKTA: Spec = {
  table: "OktaV2_CL",
  kindFilter: k => `EventOriginalType == "${k}"`,
  cols: {
    ActorDetailEntry: "actor.detailEntry", ActorDisplayName: "actor.displayName", OriginalUserId: "actor.id", OriginalActorAlternateId: "actor.alternateId", OriginalUserType: "actor.type",
    ActorUserId: r => { const id = str(first(r, "actor.id")); return id === "unknown" ? undefined : id; },
    ActorUserIdType: r => (str(first(r, "actor.id")) && first(r, "actor.id") !== "unknown" ? "OktaId" : undefined),
    ActorUsername: r => { const u = str(first(r, "actor.alternateId")); return u?.includes("@") ? u : undefined; },
    ActorUsernameType: r => (str(first(r, "actor.alternateId"))?.includes("@") ? "UPN" : undefined),
    ActorUserType: r => OKTA_USER_TYPE[String(first(r, "actor.type"))],
    AuthenticationContextAuthenticationProvider: "authenticationContext.authenticationProvider", AuthenticationContextAuthenticationStep: "authenticationContext.authenticationStep",
    AuthenticationContextCredentialProvider: "authenticationContext.credentialProvider", LogonMethod: "authenticationContext.credentialType", ActorSessionId: "authenticationContext.externalSessionId",
    AuthenticationContextInterface: "authenticationContext.interface", AuthenticationContextIssuerId: "authenticationContext.issuer.id", AuthenticationContextIssuerType: "authenticationContext.issuer.type",
    OriginalClientDevice: "client.device", SrcDeviceType: r => (first(r, "client.device") === "Computer" ? "Computer" : undefined), SrcGeoCity: "client.geographicalContext.city",
    SrcGeoCountry: "client.geographicalContext.country", SrcGeoLatitude: "client.geographicalContext.geolocation.lat", SrcGeoLongtitude: "client.geographicalContext.geolocation.lon",
    SrcGeoPostalCode: "client.geographicalContext.postalCode", SrcGeoRegion: "client.geographicalContext.state", SrcDvcId: "client.id", SrcIpAddr: "client.ipAddress", ActingAppName: "client.userAgent.browser",
    SrcDvcOs: "client.userAgent.os", HttpUserAgent: "client.userAgent.rawUserAgent", SrcZone: "client.zone", DebugData: "debugContext.debugData", EventMessage: "displayMessage", EventOriginalType: "eventType",
    LegacyEventType: "legacyEventType", EventOriginalUid: "uuid", EventOriginalResultDetails: "outcome.reason", OriginalOutcomeResult: "outcome.result",
    EventResult: r => OKTA_RESULT[String(first(r, "outcome.result"))], Request: "request", SecurityContextAsNumber: "securityContext.asNumber", SecurityContextAsOrg: "securityContext.asOrg",
    SecurityContextDomain: "securityContext.domain", SrcIsp: "securityContext.isp", SecurityContextIsProxy: "securityContext.isProxy", EventSeverity: r => OKTA_SEV[String(r.severity)], OriginalSeverity: "severity",
    OriginalTarget: "target", Version: "version", TransactionType: "transaction.type", TransactionId: "transaction.id", TransactionDetail: "transaction.detail",
    DvcAction: r => OKTA_ACTION[String(first(r, "outcome.result"))],
  },
  fixed: { ActingAppType: "Browser" },
};

// ── Email and collaboration ──────────────────────────────────────────────────

const USER_TYPE: Record<string, string> = { "0": "Regular", "1": "Reserved", "2": "Admin", "3": "DcAdmin", "4": "System", "5": "Application", "6": "ServicePrincipal", "7": "CustomPolicy", "8": "SystemPolicy" };

const OFFICE: Spec = {
  table: "OfficeActivity",
  kindFilter: k => `RecordType == "${k}"`,
  cols: {
    OfficeId: "Id", Operation: "Operation", OrganizationId: "OrganizationId", OfficeTenantId: "OrganizationId", OfficeWorkload: "Workload", ResultStatus: "ResultStatus", UserKey: "UserKey", UserId: "UserId",
    ClientIP: "ClientIP", Client_IPAddress: "ClientIPAddress", OfficeObjectId: "ObjectId", Parameters: "Parameters", ClientInfoString: "ClientInfoString", ExternalAccess: "ExternalAccess",
    OriginatingServer: "OriginatingServer", OrganizationName: "OrganizationName", LogonUserSid: "LogonUserSid", MailboxGuid: "MailboxGuid", MailboxOwnerUPN: "MailboxOwnerUPN", MailboxOwnerSid: "MailboxOwnerSid",
    InternalLogonType: "InternalLogonType", Logon_Type: "LogonType", Site_Url: "SiteUrl", Site_: "Site", SourceFileName: "SourceFileName", SourceRelativeUrl: "SourceRelativeUrl", SourceFileExtension: "SourceFileExtension",
    DestinationFileName: "DestinationFileName", DestinationRelativeUrl: "DestinationRelativeUrl", EventSource: "EventSource", ItemType: "ItemType", ListItemUniqueId: "ListItemUniqueId", UserAgent: "UserAgent",
    MachineDomainInfo: "MachineDomainInfo", MachineId: "MachineId", TargetUserOrGroupName: "TargetUserOrGroupName", TargetUserOrGroupType: "TargetUserOrGroupType", AppId: "AppId", ClientAppId: "ClientAppId",
    AppAccessContext: "AppAccessContext", ModifiedProperties: "ModifiedProperties", OperationProperties: "OperationProperties", Folders: "Folders", Folder: "Folder", Item: "Item", AffectedItems: "AffectedItems",
    DestFolder: "DestFolder", TeamName: "TeamName", TeamGuid: "TeamGuid", ChannelName: "ChannelName", IsManagedDevice: "IsManagedDevice", DeviceInformation: "DeviceDisplayName", CrossMailboxOperations: "CrossMailboxOperation",
    RecordType: (_r, log) => log.kind, UserType: r => USER_TYPE[String(r.UserType)] ?? str(r.UserType),
  },
  fixed: { SourceSystem: "OfficeActivityManager" },
  exprs: { Workload: "OfficeWorkload" },
};

const GOOGLE_WORKSPACE: Spec = {
  table: "GoogleWorkspaceReports",
  kindFilter: k => `IdApplicationName == "${k}"`,
  cols: {
    Kind: "kind", Etag: "etag", IdTime: "id.time", IdUniqueQualifier: "id.uniqueQualifier", IdApplicationName: "id.applicationName", IdCustomerId: "id.customerId", ActorCallerType: "actor.callerType",
    ActorEmail: "actor.email", ActorProfileId: "actor.profileId", ActorKey: "actor.key", OwnerDomain: "ownerDomain", SrcIpAddr: "ipAddress",
    EventType: r => first(r, "events[].type"), EventName: r => first(r, "events[].name"), EventParameters: r => first(r, "events[].parameters"),
  },
  fixed: { EventVendor: "Google", EventProduct: "Workspace" },
  exprs: {
    "events[].name": "EventName", "events[].parameters[].boolValue": "tostring(EventParameters)", "events[].parameters[].name": "tostring(EventParameters)",
    "events[].parameters[].value": "tostring(EventParameters)", "events[].parameters[].multiValue[]": "tostring(EventParameters)",
  },
};

const PROOFPOINT_CLICK = (table: string): Spec => ({
  table,
  cols: {
    campaignId: "campaignId", classification: "classification", clickIP: "clickIP", clickTime: "clickTime", GUID: "GUID", id: "id", messageID: "messageID", recipient: "recipient", sender: "sender", senderIP: "senderIP",
    threatID: "threatID", threatStatus: "threatStatus", threatTime: "threatTime", threatURL: "threatURL", url: "url", userAgent: "userAgent",
  },
});
const PROOFPOINT_MESSAGE = (table: string): Spec => ({
  table,
  cols: {
    ccAddresses: "ccAddresses", cluster: "cluster", completelyRewritten: "completelyRewritten", fromAddress: "fromAddress", GUID: "GUID", headerFrom: "headerFrom", headerReplyTo: "headerReplyTo", id: "id",
    impostorScore: "impostorScore", malwareScore: "malwareScore", messageID: "messageID", messageParts: "messageParts", messageSize: "messageSize", messageTime: "messageTime", modulesRun: "modulesRun", phishScore: "phishScore",
    policyRoutes: "policyRoutes", QID: "QID", quarantineFolder: "quarantineFolder", quarantineRule: "quarantineRule", recipient: "recipient", replyToAddress: "replyToAddress", sender: "sender", senderIP: "senderIP",
    spamScore: "spamScore", subject: "subject", threatsInfoMap: "threatsInfoMap", toAddresses: "toAddresses", xmailer: "xmailer",
  },
});

const PROOFPOINT: Record<string, Spec> = {
  clicksPermitted: PROOFPOINT_CLICK("ProofPointTAPClicksPermittedV2_CL"), clicksBlocked: PROOFPOINT_CLICK("ProofPointTAPClicksBlockedV2_CL"),
  messagesDelivered: PROOFPOINT_MESSAGE("ProofPointTAPMessagesDeliveredV2_CL"), messagesBlocked: PROOFPOINT_MESSAGE("ProofPointTAPMessagesBlockedV2_CL"),
};

// ── Cloud ────────────────────────────────────────────────────────────────────

const AWS_CLOUDTRAIL: Spec = {
  table: "AWSCloudTrail",
  kindFilter: k => `EventTypeName == "${k}"`,
  cols: {
    EventVersion: "eventVersion", UserIdentityType: "userIdentity.type", UserIdentityPrincipalid: "userIdentity.principalId", UserIdentityArn: "userIdentity.arn", UserIdentityAccountId: "userIdentity.accountId",
    UserIdentityAccessKeyId: "userIdentity.accessKeyId", UserIdentityUserName: "userIdentity.userName", UserIdentityInvokedBy: "userIdentity.invokedBy", SessionIssuerType: "userIdentity.sessionContext.sessionIssuer.type",
    SessionIssuerPrincipalId: "userIdentity.sessionContext.sessionIssuer.principalId", SessionIssuerArn: "userIdentity.sessionContext.sessionIssuer.arn", SessionIssuerAccountId: "userIdentity.sessionContext.sessionIssuer.accountId",
    SessionIssuerUserName: "userIdentity.sessionContext.sessionIssuer.userName", SessionCreationDate: "userIdentity.sessionContext.attributes.creationDate", SessionMfaAuthenticated: "userIdentity.sessionContext.attributes.mfaAuthenticated",
    EventSource: "eventSource", EventName: "eventName", AWSRegion: "awsRegion", SourceIpAddress: "sourceIPAddress", UserAgent: "userAgent", RequestParameters: "requestParameters", ResponseElements: "responseElements",
    AdditionalEventData: "additionalEventData", AwsRequestId: "requestID", AwsEventId: "eventID", ReadOnly: "readOnly", EventTypeName: "eventType", ManagementEvent: "managementEvent", RecipientAccountId: "recipientAccountId",
    Category: "eventCategory", ErrorCode: "errorCode", ErrorMessage: "errorMessage", Resources: "resources", TlsVersion: "tlsDetails.tlsVersion", CipherSuite: "tlsDetails.cipherSuite", ClientProvidedHostHeader: "tlsDetails.clientProvidedHostHeader",
    VpcEndpointId: "vpcEndpointId", SharedEventId: "sharedEventID", ServiceEventDetails: "serviceEventDetails", APIVersion: "apiVersion",
  },
  fixed: { SourceSystem: "Azure" },
};

const AWS_GUARDDUTY: Spec = {
  table: "AWSGuardDuty",
  cols: {
    SchemaVersion: "schemaVersion", AccountId: "accountId", Region: "region", Partition: "partition", Id: "id", Arn: "arn", ActivityType: "type", ResourceDetails: "resource", ServiceDetails: "service",
    Severity: "severity", Title: "title", Description: "description", TimeCreated: "createdAt",
  },
  fixed: { SourceSystem: "Azure" },
};

const AWS_VPCFLOW: Spec = {
  table: "AWSVPCFlow",
  cols: {
    Version: "version", AccountId: "account-id", InterfaceId: "interface-id", SrcAddr: "srcaddr", DstAddr: "dstaddr", SrcPort: "srcport", DstPort: "dstport", Protocol: "protocol", Packets: "packets", Bytes: "bytes",
    Start: "start", End: "end", Action: "action", LogStatus: "log-status", VpcId: "vpc-id", SubnetId: "subnet-id", InstanceId: "instance-id", TcpFlags: "tcp-flags", TrafficType: "type", PktSrcAddr: "pkt-srcaddr", PktDstAddr: "pkt-dstaddr",
    Region: "region", AzId: "az-id", FlowDirection: "flow-direction", TrafficPath: "traffic-path",
  },
  fixed: { SourceSystem: "Azure" },
};

const AZURE_ACTIVITY: Spec = {
  table: "AzureActivity",
  kindFilter: () => undefined,
  cols: {
    OperationName: "operationName", OperationNameValue: "operationName", ResourceId: "resourceId", CategoryValue: "category", Category: "category", ActivityStatusValue: "resultType", ActivityStatus: "resultType",
    CorrelationId: "correlationId", Level: "level", CallerIpAddress: "callerIpAddress", Properties_d: "properties", Authorization_d: "identity.authorization", Claims_d: "identity.claims",
    Properties: r => JSON.stringify(r.properties ?? {}), Authorization: r => JSON.stringify(first(r, "identity.authorization") ?? {}), Claims: r => JSON.stringify(first(r, "identity.claims") ?? {}),
    Hierarchy: "properties.hierarchy", Caller: r => str(first(r, "identity.claims.name")) ?? str(first(r, `identity.claims.http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn`)),
    SubscriptionId: r => /\/subscriptions\/([^/]+)/i.exec(String(r.resourceId))?.[1]?.toLowerCase(),
    ResourceGroup: r => /\/resourcegroups\/([^/]+)/i.exec(String(r.resourceId))?.[1],
    ResourceProviderValue: r => /\/providers\/([^/]+)/i.exec(String(r.resourceId))?.[1],
  },
  fixed: { SourceSystem: "Azure" },
  exprs: { "properties.requestbody": "tostring(Properties_d.requestbody)" },
};

const GCP_AUDIT: Spec = {
  table: "GCPAuditLogs",
  cols: {
    InsertId: "insertId", LogName: "logName", MethodName: "protoPayload.methodName", ServiceName: "protoPayload.serviceName", GCPResourceName: "protoPayload.resourceName", PrincipalEmail: "protoPayload.authenticationInfo.principalEmail",
    AuthenticationInfo: "protoPayload.authenticationInfo", AuthorizationInfo: "protoPayload.authorizationInfo", RequestMetadata: "protoPayload.requestMetadata", Request: "protoPayload.request", Response: "protoPayload.response",
    ServiceData: "protoPayload.serviceData", Metadata: "protoPayload.metadata", Status: "protoPayload.status", StatusMessage: "protoPayload.status.message", ResourceLocation: "protoPayload.resourceLocation",
    ResourceOriginalState: "protoPayload.resourceOriginalState", NumResponseItems: "protoPayload.numResponseItems", Severity: "severity", GCPResourceType: "resource.type", Timestamp: "timestamp",
    ProjectId: r => str(first(r, "resource.labels.project_id")) ?? /^projects\/([^/]+)/.exec(String(r.logName))?.[1],
  },
  fixed: { SourceSystem: "Azure" },
};

const AKS_AUDIT: Spec = {
  table: "AKSAudit",
  cols: {
    Level: "level", AuditId: "auditID", Stage: "stage", RequestUri: "requestURI", Verb: "verb", User: "user", SourceIps: "sourceIPs", UserAgent: "userAgent", ObjectRef: "objectRef", ResponseStatus: "responseStatus",
    RequestObject: "requestObject", ResponseObject: "responseObject", RequestReceivedTime: "requestReceivedTimestamp", StageReceivedTime: "stageTimestamp", Annotations: "annotations",
  },
  fixed: { SourceSystem: "Azure" },
  exprs: { "sourceIPs[]": "tostring(SourceIps[0])" },
};

// ── Syslog ───────────────────────────────────────────────────────────────────

/** The message part of an RFC 3164 line. */
const syslogBody = (line: string | undefined) => line?.replace(/^<\d+>[A-Z][a-z]{2}\s+\d+\s+[\d:]+\s+\S+\s+[^:]*:\s*/, "");

const INFOBLOX: Spec = {
  table: "Syslog",
  base: `ProcessName == "named"`,
  cols: {
    Computer: "hostname", HostName: "hostname", ProcessID: "pid",
    SyslogMessage: (_r, log) => syslogBody(log.rawLine),
  },
  fixed: { ProcessName: "named", Facility: "daemon", SeverityLevel: "info", SourceSystem: "Linux" },
  exprs: {
    client_ip: `extract(@"client ([0-9.]+)#", 1, SyslogMessage)`, qname: `extract(@"query: (\\S+) IN", 1, SyslogMessage)`, qtype: `extract(@"IN (\\S+) response", 1, SyslogMessage)`,
    rcode: `extract(@"response: (\\S+)", 1, SyslogMessage)`,
  },
};

const LINUX_SSHD: Spec = {
  table: "Syslog",
  base: `ProcessName == "sshd"`,
  cols: { Computer: "hostname", HostName: "hostname", ProcessID: "pid", SyslogMessage: "message" },
  fixed: { ProcessName: "sshd", Facility: "authpriv", SeverityLevel: "info", SourceSystem: "Linux" },
};
const LINUX_AUDIT: Spec = {
  table: "Syslog",
  base: `ProcessName == "audisp-syslog"`,
  kindFilter: k => `SyslogMessage has "type=${k}"`,
  cols: {
    Computer: "node", HostName: "node",
    SyslogMessage: (r, log) => {
      const decoded = Object.entries(r).filter(([k]) => k.endsWith("_decoded")).map(([k, v]) => ` ${k}="${v}"`).join("");
      return `${log.rawLine ?? ""}${decoded}`;
    },
  },
  fixed: { Facility: "local6", SeverityLevel: "info", ProcessName: "audisp-syslog", SourceSystem: "Linux" },
};
/** A native key printed `key=value` or `key="value"` in the audit line. */
const auditField = (key: string) => (key.endsWith("_decoded") ? `extract(@"\\b${key}=""([^""]*)", 1, SyslogMessage)` : `extract(@"\\b${key}=""?([^""' ]*)", 1, SyslogMessage)`);

// ── Database audit and DAM ───────────────────────────────────────────────────

/**
 * IBM Guardium: the QRadar LEEF alert line arrives over syslog. LEEF is not CEF, so the CEF connector
 * does not parse it: the Syslog table holds it, sent by the Guardium collector (guard_sender), facility
 * daemon at the priority of IBM's samples (<30> daemon.info for an INFO rule, <25> daemon.alert above).
 */
const GUARDIUM_KEYS = ["ruleID", "ruleDesc", "severity", "devTime", "serverType", "classification", "category", "dbProtocolVersion", "usrName",
  "sourceProgram", "start", "dbUser", "dst", "dstPort", "src", "srcPort", "protocol", "type", "violationID", "sql", "error"];
const GUARDIUM: Spec = {
  table: "Syslog",
  base: `ProcessName == "guard_sender"`,
  kindFilter: k => `SyslogMessage has "|type=${k}|"`,
  cols: {
    Computer: "hostname", HostName: "hostname", ProcessID: "procId",
    SeverityLevel: r => (r.severity === "INFO" || r.severity === "LOW" ? "info" : "alert"),
    SyslogMessage: (_r, log) => log.rawLine?.slice(log.rawLine.indexOf("]: ") + 3),
  },
  fixed: { ProcessName: "guard_sender", Facility: "daemon", SourceSystem: "Linux" },
  exprs: Object.fromEntries(GUARDIUM_KEYS.map(k => [k, k === "error" ? `extract(@"\\|error=(.*)$", 1, SyslogMessage)` : `extract(@"\\|${k}=([^|]*)", 1, SyslogMessage)`])),
};

/**
 * SQL Server Audit: an audit written to the Windows Application log is event 33205 from MSSQLSERVER
 * (MSSQL$<instance> for a named instance), its data the record's own columns as `name:value` lines
 * (the Sigma rule win_mssql_disable_audit_settings matches `statement:ALTER SERVER AUDIT` in it).
 * The Windows events connector lands it in Event. A bit prints true / false there.
 */
const MSSQL_BITS = new Set(["succeeded", "is_column_permission"]);
const mssqlData = (r: Rec) => Object.entries(r).map(([k, v]) => `${k}:${v === null || v === undefined ? "" : MSSQL_BITS.has(k) ? (v === 1 || v === "1" || v === true ? "true" : "false") : String(v)}`).join("\n");
const MSSQL_AUDIT: Spec = {
  table: "Event",
  base: `EventID == 33205 and Source startswith "MSSQL"`,
  kindFilter: k => `RenderedDescription has "action_id:${k}"`,
  cols: {
    Computer: r => str(r.server_instance_name)?.split("\\")[0],
    Source: r => { const inst = str(r.server_instance_name)?.split("\\")[1]; return !inst || /^MSSQLSERVER$/i.test(inst) ? "MSSQLSERVER" : `MSSQL$${inst}`; },
    RenderedDescription: r => `Audit event: ${mssqlData(r)}`,
    EventData: r => `<DataItem type="System.XmlData" time="${str(r.event_time)?.replace(" ", "T")}Z" sourceHealthServiceId=""><EventData xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><Data>${esc(mssqlData(r))}</Data></EventData></DataItem>`,
  },
  fixed: { EventID: 33205, EventLog: "Application", EventLevelName: "Information", EventLevel: 4, EventCategory: 4, SourceSystem: "OpsManager" },
};
for (const k of ["event_time", "action_id", "succeeded", "server_principal_name", "database_principal_name", "server_instance_name", "database_name", "schema_name", "object_name",
  "statement", "client_ip", "application_name", "host_name", "class_type", "session_id"]) {
  (MSSQL_AUDIT.exprs ??= {})[k] = `extract(@"(?m)(?:^|\\s)${k}:(.*)$", 1, RenderedDescription)`;
}

/**
 * MySQL Enterprise Audit: the JSON audit log file, collected by the Azure Monitor Agent as a custom JSON
 * log. The table name and its columns are this workspace's (no connector defines one); the record is kept
 * whole in RawData.
 */
const rawData = (keys: string[]): Record<string, string> => Object.fromEntries(keys.map(k => [k, `tostring(RawData.${k})`]));
const MYSQL_AUDIT: Spec = {
  table: "MySQLAudit_CL",
  kindFilter: k => `EventType == "${k}"`,
  cols: {
    EventType: (_r, log) => log.kind, ActorUsername: "account.user", SrcIpAddr: "login.ip",
    EventMessage: r => str(first(r, "general_data.query")),
    RawData: r => r,
  },
  fixed: { EventVendor: "Oracle", EventProduct: "MySQL Enterprise Audit", SourceSystem: "Linux" },
  exprs: { ...rawData(["timestamp", "class", "event", "connection_id"]), "general_data.query": "EventMessage", "general_data.sql_command": "tostring(RawData.general_data.sql_command)",
    "general_data.status": "tostring(RawData.general_data.status)", "connection_data.status": "tostring(RawData.connection_data.status)",
    "query_statistics.rows_examined": "tostring(RawData.query_statistics.rows_examined)" },
};

// ── UEBA ─────────────────────────────────────────────────────────────────────

/** Exabeam / Securonix forward to this workspace's custom tables (no connector table): the record is RawData. */
const EXABEAM: Spec = {
  table: "Exabeam_CL",
  kindFilter: k => `EventType == "${k}"`,
  cols: {
    EventType: (_r, log) => log.kind, ActorUsername: r => str(r.user) ?? str(r.created_by), DvcHostname: "src_host", SrcIpAddr: "src_ip",
    EventMessage: (_r, log) => log.rawLine, RawData: r => r,
  },
  fixed: { EventVendor: "Exabeam", EventProduct: "Exabeam Advanced Analytics", SourceSystem: "RestAPI" },
  exprs: rawData(["id", "score", "start_time", "status", "user", "accounts", "assets", "reasons", "reasons_count", "events_count", "alerts_count", "job_status", "job_id", "created_by"]),
};
const SECURONIX: Spec = {
  table: "Securonix_CL",
  kindFilter: k => `EventType == "${k}"`,
  cols: {
    EventType: (_r, log) => log.kind, ActorUsername: "accountname", DvcHostname: "resourcename", SrcIpAddr: "ipaddress", EventMessage: "policyname", RawData: r => r,
  },
  fixed: { EventVendor: "Securonix", EventProduct: "Securonix SNYPR", SourceSystem: "RestAPI" },
  exprs: rawData(["violator", "entityid", "u_department", "riskthreatname", "riskscore", "tenantname", "generationtime", "datetime"]),
};

// ── Selection ────────────────────────────────────────────────────────────────

const MDE_TABLES = new Set(["DeviceProcessEvents", "DeviceNetworkEvents", "DeviceFileEvents", "DeviceRegistryEvents", "DeviceLogonEvents", "DeviceEvents", "DeviceImageLoadEvents", "AlertInfo", "AlertEvidence"]);
const MDO_TABLES = new Set(["EmailEvents", "EmailAttachmentInfo", "EmailUrlInfo", "EmailPostDeliveryEvents", "UrlClickEvents"]);
const FDR_BY_KIND: Record<string, Spec> = {
  ProcessRollup2: FDR_PROCESS, SyntheticProcessRollup2: FDR_PROCESS, NetworkConnectIP4: FDR_NETWORK, NetworkReceiveAcceptIP4: FDR_NETWORK, PeFileWritten: FDR_FILE, GenericFileWritten: FDR_FILE,
  NewScriptWritten: FDR_FILE, AsepValueUpdate: FDR_REGISTRY, RegGenericValueUpdate: FDR_REGISTRY, DnsRequest: FDR_DNS,
};
const MDE_SPECS = new Map([...MDE_TABLES, ...MDO_TABLES].map(t => [t, passProperties(t)]));


// ── Web tier (injection round 2026-11-12) ───────────────────────────────────
// AWS WAF through the AWS S3 connector (AWSWAF), Application Gateway WAF resource-specific tables
// (AGWFirewallLogs, AGWAccessLogs: learn.microsoft.com/azure/azure-monitor/reference/tables, checked
// 2026-11-12), IIS through the agent's IIS collection (W3CIISLog), nginx access lines as a text log
// collected by the Azure Monitor Agent into NGINX_CL (the NGINX HTTP Server solution's table: RawData).
const AWS_WAF: Spec = {
  table: "AWSWAF",
  cols: {
    Action: "action", ClientIp: "httpRequest.clientIp", Country: "httpRequest.country", FormatVersion: "formatVersion", HttpMethod: "httpRequest.httpMethod", HttpSourceId: "httpSourceId",
    HttpSourceName: "httpSourceName", HttpVersion: "httpRequest.httpVersion", RequestId: "httpRequest.requestId", TerminatingRuleId: "terminatingRuleId", TerminatingRuleType: "terminatingRuleType",
    Uri: "httpRequest.uri", Args: "httpRequest.args", WebAclId: "webaclId", Ja3Fingerprint: "ja3Fingerprint", Headers: "httpRequest.headers", HttpRequest: "httpRequest", Labels: "labels",
    NonTerminatingMatchingRules: "nonTerminatingMatchingRules", RateBasedRuleList: "rateBasedRuleList", RuleGroupList: "ruleGroupList", TerminatingRuleMatchDetails: "terminatingRuleMatchDetails",
    OversizeFields: "oversizeFields",
  },
  fixed: { SourceSystem: "Azure" },
};
const AGW_FIREWALL: Spec = {
  table: "AGWFirewallLogs",
  cols: {
    OperationName: "operationName", InstanceId: "properties.instanceId", ClientIp: "properties.clientIp", RequestUri: "properties.requestUri", RuleSetType: "properties.ruleSetType",
    RuleSetVersion: "properties.ruleSetVersion", RuleId: "properties.ruleId", Message: "properties.message", Action: "properties.action", Site: "properties.site",
    DetailedMessage: "properties.details.message", DetailedData: "properties.details.data", FileDetails: "properties.details.file", LineDetails: "properties.details.line",
    Hostname: "properties.hostname", TransactionId: "properties.transactionId", PolicyId: "properties.policyId", PolicyScope: "properties.policyScope", PolicyScopeName: "properties.policyScopeName",
  },
  fixed: { SourceSystem: "Azure" },
  // The table has no rule-group column: the rule file names it.
  exprs: { "properties.ruleGroup": String.raw`extract(@"rules/([^.]+)\.conf", 1, FileDetails)` },
};
const AGW_ACCESS: Spec = {
  table: "AGWAccessLogs",
  cols: {
    OperationName: "operationName", ListenerName: "listenerName", RuleName: "ruleName", BackendPoolName: "backendPoolName", BackendSettingName: "backendSettingName",
    InstanceId: "properties.instanceId", ClientIp: "properties.clientIP", ClientPort: "properties.clientPort", HttpMethod: "properties.httpMethod", OriginalRequestUriWithArgs: "properties.originalRequestUriWithArgs",
    RequestUri: "properties.requestUri", RequestQuery: "properties.requestQuery", UserAgent: "properties.userAgent", HttpStatus: "properties.httpStatus", HttpVersion: "properties.httpVersion",
    ReceivedBytes: "properties.receivedBytes", SentBytes: "properties.sentBytes", TimeTaken: "properties.timeTaken", WafEvaluationTime: "properties.WAFEvaluationTime", WafMode: "properties.WAFMode",
    TransactionId: "properties.transactionId", SslEnabled: "properties.sslEnabled", SslCipher: "properties.sslCipher", SslProtocol: "properties.sslProtocol",
    ServerRouted: "properties.serverRouted", ServerStatus: "properties.serverStatus", ServerResponseLatency: "properties.serverResponseLatency", OriginalHost: "properties.originalHost",
    Host: "properties.host", ErrorInfo: "properties.error_info",
  },
  fixed: { SourceSystem: "Azure" },
};
const IIS_W3C: Spec = {
  table: "W3CIISLog",
  cols: {
    Computer: "s-computername", sSiteName: "s-sitename", sIP: "s-ip", csMethod: "cs-method", csUriStem: "cs-uri-stem", csUriQuery: "cs-uri-query", sPort: "s-port", csUserName: "cs-username",
    cIP: "c-ip", csVersion: "cs-version", csUserAgent: "cs(User-Agent)", csReferer: "cs(Referer)", csHost: "cs-host", scStatus: "sc-status", scSubStatus: "sc-substatus",
    scWin32Status: "sc-win32-status", scBytes: "sc-bytes", csBytes: "cs-bytes", TimeTaken: "time-taken",
  },
  fixed: { SourceSystem: "OpsManager" },
};
/** One field of the estate's nginx log_format, read out of RawData (the order rawLineOf prints). */
// A quote in the line is \x22: a verbatim KQL string cannot hold one.
const nginxField = (re: string) => `extract(@"${re}", 1, RawData)`;
const NGINX_ACCESS: Spec = {
  table: "NGINX_CL",
  cols: { Computer: "hostname", RawData: (_r, log) => log.rawLine },
  fixed: { FilePath: "/var/log/nginx/access.log" },
  exprs: {
    remote_addr: nginxField(String.raw`^(\S+)`), request: nginxField(String.raw`\]\s\x22([^\x22]*)\x22`),
    status: nginxField(String.raw`\x22\s(\d{3})\s`), body_bytes_sent: nginxField(String.raw`\x22\s\d{3}\s(\d+)`),
    http_user_agent: nginxField(String.raw`\x22([^\x22]*)\x22\s\x22[^\x22]*\x22\s\S+\s\S+\s\S+\s\d+\s[\d.]+$`),
    http_x_forwarded_for: nginxField(String.raw`\x22([^\x22]*)\x22\s\S+\s\S+\s\S+\s\d+\s[\d.]+$`),
    http_host: nginxField(String.raw`(\S+)\s\d+\s[\d.]+$`),
  },
};

/** The spec a native kind lands on. Null: no real table takes this record. */
export function specFor(sourceId: SourceId, kind: string, cloud?: SourceId): Spec | null {
  switch (sourceId) {
    case "entra": return kind === "signIn" ? ENTRA_SIGNIN : kind === "directoryAudit" ? ENTRA_AUDIT : null;
    case "windows_security": return WINDOWS_SECURITY;
    case "sysmon": return SYSMON;
    case "windows_dns": return WINDOWS_DNS;
    case "mde": return MDE_TABLES.has(kind) ? MDE_SPECS.get(kind)! : null;
    case "defender_o365": return MDO_TABLES.has(kind) ? MDE_SPECS.get(kind)! : null;
    case "paloalto": return PALOALTO;
    case "globalprotect": return GLOBALPROTECT;
    case "fortigate": return FORTIGATE;
    case "fortigate_sslvpn": return FORTIGATE_SSLVPN;
    case "checkpoint": return CHECKPOINT;
    case "cisco_ftd": return CISCO_FTD;
    case "cisco_asa": return CISCO_ASA;
    case "anyconnect": return ANYCONNECT;
    case "cyberark": return CYBERARK;
    case "zscaler_zia": return ZSCALER_ZIA;
    case "crowdstrike": return kind === "alert" ? FALCON_ALERT : FDR_BY_KIND[kind] ?? null;
    case "sentinelone": return kind === "threat" ? S1_THREAT : null;
    case "sophos": return kind === "event" ? SOPHOS_EVENT : kind === "alert" ? SOPHOS_ALERT : kind === "detection" ? SOPHOS_DETECTION : null;
    case "okta": return OKTA;
    case "m365":
      if (kind === "AzureActiveDirectory") return UAL_DIRECTORY;
      // The Office 365 connector carries Exchange, SharePoint / OneDrive and Teams, not DLP or sign-ins.
      return /^(Exchange|SharePoint|OneDrive|MicrosoftTeams)/.test(kind) ? OFFICE : null;
    case "google_workspace": return GOOGLE_WORKSPACE;
    case "proofpoint":
      return PROOFPOINT[kind] ?? null;
    case "aws_cloudtrail": return AWS_CLOUDTRAIL;
    case "aws_guardduty": return AWS_GUARDDUTY;
    case "aws_vpcflow": return AWS_VPCFLOW;
    case "azure_activity": return kind === "ActivityLog" ? AZURE_ACTIVITY : null;
    case "gcp_audit": return GCP_AUDIT;
    case "k8s_audit": return cloud === "azure_activity" ? AKS_AUDIT : null;
    case "infoblox": return kind === "response" || kind === "query" ? INFOBLOX : null;
    case "linux_auditd": return kind === "sshd" ? LINUX_SSHD : LINUX_AUDIT;
    case "guardium": return GUARDIUM;
    case "mssql_audit": return MSSQL_AUDIT;
    case "mysql_audit": return MYSQL_AUDIT;
    case "exabeam": return EXABEAM;
    case "securonix": return SECURONIX;
    case "aws_waf": return AWS_WAF;
    case "azure_waf": return kind === "ApplicationGatewayFirewallLog" ? AGW_FIREWALL : kind === "ApplicationGatewayAccessLog" ? AGW_ACCESS : null;
    case "iis": return IIS_W3C;
    case "nginx": return NGINX_ACCESS;
    // ServiceNow tickets, Workday activity, ZPA, Cloudflare Access: no confirmed table with these records.
    default: return null;
  }
}

function usedPaths(spec: Spec): Set<string> {
  return new Set(Object.values(spec.cols).filter((c): c is string => typeof c === "string"));
}

function extensionOf(spec: Spec, r: Rec): string | undefined {
  const used = usedPaths(spec);
  const parts: string[] = [];
  for (const [k, v] of scalars(r)) {
    if (used.has(k)) continue;
    parts.push(`${spec.extension!.prefix}${k}=${String(v).replace(/;/g, ",")}`);
  }
  return parts.length ? parts.join(";") : undefined;
}

function eventDataOf(spec: Spec, r: Rec): string | undefined {
  const used = usedPaths(spec);
  const parts = Object.entries(r)
    .filter(([k, v]) => !used.has(k) && v !== null && v !== undefined && !columnType(spec.table, k))
    .map(([k, v]) => `<Data Name="${k}">${esc(typeof v === "object" ? JSON.stringify(v) : String(v))}</Data>`);
  return parts.length ? `<EventData xmlns="http://schemas.microsoft.com/win/2004/08/events/event">${parts.join("")}</EventData>` : undefined;
}

function restOf(spec: Spec, r: Rec): Rec | undefined {
  const used = usedPaths(spec);
  const out: Rec = {};
  for (const [k, v] of Object.entries(r)) if (!used.has(k) && v !== null && v !== undefined && v !== "") out[k] = v;
  return Object.keys(out).length ? out : undefined;
}

/** Out-of-table tally key of a native log: `<sourceId>/<kind>`. */
export function logKey(log: NativeLog): string { return `${log.sourceId}/${log.kind}`; }

/** The Log Analytics row of a native log, or null when no real table takes it. */
export function mapRow(log: NativeLog, ctx: MapContext): MappedRow | null {
  const spec = specFor(log.sourceId, log.kind, ctx.cloud);
  if (!spec) return null;
  const table = spec.table;
  const row: KqlRow = {};
  const put = (col: string, v: unknown) => {
    const t = columnType(table, col);
    if (!t) return;
    const c = coerce(t, v);
    if (c !== undefined) row[col] = c;
  };
  const fixed = typeof spec.fixed === "function" ? spec.fixed(ctx) : spec.fixed;
  if (fixed) for (const [k, v] of Object.entries(fixed)) put(k, v);
  if (spec.pass) {
    const src = (spec.pass.prefix ? first(log.record, spec.pass.prefix.replace(/\.$/, "")) : log.record) as Rec | undefined;
    if (src) for (const [k, v] of Object.entries(src)) put(k, v);
  }
  for (const [col, from] of Object.entries(spec.cols)) put(col, typeof from === "string" ? first(log.record, from) : from(log.record, log, ctx));
  if (spec.extension) put("AdditionalExtensions", extensionOf(spec, log.record));
  if (spec.eventData && table === "SecurityEvent") put("EventData", eventDataOf(spec, log.record));
  if (spec.rest) put(spec.rest, restOf(spec, log.record));
  put("TimeGenerated", iso(log.timeMs));
  put("Type", table);
  put("TenantId", ctx.tenantId);
  return { table, row };
}

// ── Reverse lookup: native path -> KQL ───────────────────────────────────────

export interface FieldRef {
  /** KQL expression reading the field. */
  expr: string;
  type: KqlType;
  /** The field sits inside text (JSON or a message): compare by containment, not equality. */
  inText?: boolean;
  /** Last key of the native path, for a JSON text search. */
  key?: string;
  /** Native value -> stored value. */
  values?: Record<string, string>;
}

/** Quote a dynamic path segment when it is not a plain identifier. */
const dyn = (col: string, rest: string) => {
  const parts = rest.split(".").filter(Boolean);
  return `${col}${parts.map(p => (/^[A-Za-z_][A-Za-z0-9_]*$/.test(p) ? `.${p}` : `["${p}"]`)).join("")}`;
};

/** How a use-case field is read over the mapped columns, or null when the row does not keep it. */
export function fieldOn(spec: Spec, path: string): FieldRef | null {
  const key = path.replace(/\[\]/g, "").split(".").pop();
  const ex = spec.exprs?.[path];
  if (ex) return { expr: ex, type: "string", inText: ex.startsWith("tostring(") && /\[\]/.test(path) && !ex.includes("[0]"), key, values: spec.values?.[path] };
  if (spec === LINUX_AUDIT || spec === LINUX_SSHD) {
    if (path === "message") return { expr: "SyslogMessage", type: "string" };
    if (path === "node" || (spec === LINUX_SSHD && path === "hostname")) return { expr: "Computer", type: "string" };
    if (spec === LINUX_AUDIT) return { expr: auditField(path), type: "string" };
  }
  for (const [col, from] of Object.entries(spec.cols)) {
    if (from !== path) continue;
    const t = columnType(spec.table, col);
    if (t) return { expr: col, type: t, inText: t === "dynamic" };
  }
  // Under a dynamic or JSON column.
  for (const [col, from] of Object.entries(spec.cols)) {
    if (typeof from !== "string") continue;
    const flat = from.replace(/\[\]/g, "");
    const bare = path.replace(/\[\]/g, "");
    if (bare !== flat && !bare.startsWith(`${flat}.`)) continue;
    const t = columnType(spec.table, col);
    if (!t) continue;
    if (path.includes("[]")) return { expr: t === "dynamic" ? `tostring(${col})` : col, type: "string", inText: true, key };
    if (t === "string") return { expr: `tostring(${dyn(`parse_json(${col})`, bare.slice(flat.length))})`, type: "string" };
    return { expr: `tostring(${dyn(col, bare.slice(flat.length))})`, type: "string" };
  }
  if (spec.pass) {
    const name = spec.pass.prefix && path.startsWith(spec.pass.prefix) ? path.slice(spec.pass.prefix.length) : path;
    const t = columnType(spec.table, name);
    if (t) return { expr: name, type: t };
  }
  if (spec.extension) return { expr: `extract(@"(?:^|;)${spec.extension.prefix}${path.replace(/\./g, "\\.")}=([^;]*)", 1, AdditionalExtensions)`, type: "string" };
  if (spec.eventData) return { expr: `extract(@'<Data Name="${path}">([^<]*)', 1, EventData)`, type: "string" };
  if (spec.rest) return { expr: `tostring(${dyn(spec.rest, path)})`, type: "string" };
  return null;
}
