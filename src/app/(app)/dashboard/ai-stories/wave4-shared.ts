/**
 * Shared authoring helpers for the wave-4 AI stories (wave4-a.ts, wave4-b.ts).
 *
 * Every wave-4 story is authored on the NexaCorp identity (the same one every other shared
 * story uses): instantiateStory re-homes people, domain, hosts, subnet and tenant ids onto the
 * company a session runs on, so one authored chain reads as native on all of them. A story NexaCorp
 * never runs (the AWS shops' chains) is moved onto the first company that runs it (authoredFor).
 *
 * A chain that needs a job names it on the story (`seat`): instantiateStory then draws the person
 * and their machine from the company's seats, and a company with no such seat does not list the
 * story. A coding agent, a Jupyter kernel or a cloud CLI on a nurse's or a warehouse clerk's account
 * would not be believable. A chain's own servers (`ownServers`) keep their name under the company's
 * prefix: an AI worker is not the domain controller, the file server or the PACS.
 */
import type { TelemetryEvent, Severity, EventType } from "@/lib/sim/types";
import { csProcess, csFile, csNetwork, type CsProcessOpts } from "@/lib/sim/emitters/crowdstrike";
import { panWeb, panConnection, type PanWebOpts, type PanConnectionOpts } from "@/lib/sim/emitters/paloalto";
import { sentinelAlert, type SentinelAlertOpts } from "@/lib/sim/emitters/sentinel";
import { serviceNowRecord } from "@/lib/sim/emitters/servicenow";
import { azureActivity, type AzureActivityOpts, type AzureAiResource } from "@/lib/sim/emitters/azureAi";
import { makeCtx } from "@/lib/logs/native/ctx";
import { COMPANY_ASSETS, COMPANY_PROFILES } from "@/lib/sim/companyProfilesMeta";
import { makeSha256 } from "@/lib/sim/iocs";

export const CX = "nexacorp";
export const DEV = { user: "k.ops@nexacorp.com", bare: "k.ops", host: "WS-ENG-2093", ip: "10.10.20.93" };
export const SUB = makeCtx(CX).tenant.azureSubscriptionId;
/** The authored office's NAT egress; a story's `officeEgress` makes it each company's own, with its place. */
export const OFFICE_EGRESS = "192.0.2.150";
/** The public address a company publishes a server on: a documentation address, never a real one. */
export const PUBLISHED_IP = "203.0.113.115";

export type Base = { id: string; ts: string };

/**
 * The benign twin of an attack row: same shape, innocent cause. An alert twin stays an alert the
 * team must close as a false positive; a plain log twin is a baseline row.
 */
export function benign(e: TelemetryEvent, why: string): TelemetryEvent {
  return { ...e, ...(e.is_detection ? {} : { is_baseline: true }), expected_verdict: "fp", fp_explanation: why };
}

export function withIncident(events: TelemetryEvent[], incident: string): TelemetryEvent[] {
  for (const e of events) e.incident_id = incident;
  return events;
}

/**
 * A chain the template company never runs (an AWS shop's story, listed only for companies other
 * than NexaCorp) is authored on the first company that runs it: the NexaCorp identity the helpers
 * write (mail domain, realm, brand, the name stem in tenant and bucket names) becomes that company's.
 * instantiateStory re-homes it onto the session's company as it does every story; the authored data
 * never names a company the story is not listed for (validate:feed TENANT_PURITY).
 */
export function authoredFor(companyId: string, events: TelemetryEvent[]): TelemetryEvent[] {
  const from = COMPANY_ASSETS[CX], to = COMPANY_ASSETS[companyId];
  const brandOf = (id: string) => (COMPANY_PROFILES.find(c => c.id === id)?.name ?? id).split(/\s+/)[0];
  const stem = (a: typeof from) => a.domain.split(".")[0];
  const pairs: [string, string][] = [
    [from.domain, to.domain], [from.netbios, to.netbios], [brandOf(CX), brandOf(companyId)], [stem(from), stem(to)],
  ];
  const swap = (v: unknown): unknown => {
    if (typeof v === "string") return pairs.reduce((acc, [f, t]) => acc.split(f).join(t), v);
    if (Array.isArray(v)) return v.map(swap);
    if (v && typeof v === "object") return Object.fromEntries(Object.entries(v as Record<string, unknown>).map(([k, x]) => [k, swap(x)]));
    return v;
  };
  return events.map(e => swap(e) as TelemetryEvent);
}

/** Process telemetry on one host. Pins the pid so a tree stays linked across rows. */
export function proc(on: { host: string; ip: string; user: string }, o: Omit<CsProcessOpts, "companyId" | "host" | "srcIp" | "user">): TelemetryEvent {
  return csProcess({ companyId: CX, host: on.host, srcIp: on.ip, user: on.user, ...o });
}

export function fileRow(on: { host: string; ip: string; user: string }, o: Omit<Parameters<typeof csFile>[0], "companyId" | "host" | "srcIp" | "user">): TelemetryEvent {
  return csFile({ companyId: CX, host: on.host, srcIp: on.ip, user: on.user, ...o });
}

export function netRow(on: { host: string; ip: string; user: string }, o: Omit<Parameters<typeof csNetwork>[0], "companyId" | "host" | "srcIp" | "user">): TelemetryEvent {
  return csNetwork({ companyId: CX, host: on.host, srcIp: on.ip, user: on.user, ...o });
}

export function web(on: { host: string; ip: string; user: string | null }, o: Omit<PanWebOpts, "companyId" | "host" | "srcIp" | "user">): TelemetryEvent {
  return panWeb({ companyId: CX, host: on.host, srcIp: on.ip, user: on.user, ...o });
}

export function conn(on: { host: string; ip: string; user: string | null }, o: Omit<PanConnectionOpts, "companyId" | "host" | "srcIp" | "user">): TelemetryEvent {
  return panConnection({ companyId: CX, host: on.host, srcIp: on.ip, user: on.user, ...o });
}

/**
 * A session opened from the internet to a server the company publishes. `bytesOut` is what the
 * server sent to the client: on a firewall record that is the responder's count, the side a
 * reader of an inbound session must look at to see data leaving.
 */
export function inbound(o: Base & {
  fromIp: string; server: string; serverIp: string; port: number; app?: string; bytesIn?: number; bytesOut?: number; elapsedSec?: number;
  repeatCount?: number; severity: Severity; description: string; mitre?: string; tactic?: string; action?: "allow" | "deny"; publishedAs?: string;
}): TelemetryEvent {
  const ev = panConnection({
    companyId: CX, id: o.id, ts: o.ts, host: o.server, srcIp: o.fromIp, user: null, dstIp: o.serverIp, remotePort: o.port,
    direction: "inbound", app: o.app ?? "ssl", action: o.action ?? "allow", end: (o.action ?? "allow") === "allow",
    bytesIn: o.bytesOut, bytesOut: o.bytesIn, elapsedSec: o.elapsedSec, repeatCount: o.repeatCount,
    severity: o.severity, description: o.description, mitre: o.mitre, tactic: o.tactic,
  });
  const row = { ...ev, network: { ...(ev.network ?? {}), direction: "inbound" } as TelemetryEvent["network"] };
  return o.publishedAs ? published(row, o.publishedAs) : row;
}

/** A session that reached a private server through a publish rule: the record shows the public address, and the server as the translation. */
export function published(e: TelemetryEvent, publicIp: string, serverIp = e.dst_ip ?? ""): TelemetryEvent {
  const url = e.network?.url;
  return {
    ...e,
    // The firewall's URL field drops the scheme; a service on a plain-HTTP port keeps http in the record the other products print.
    ...(url && !/^https?:/.test(url) && e.dst_port !== 443 ? { network: { ...e.network, url: `http://${url}` } } : {}),
    raw: { ...e.raw, "pan.dst": publicIp, "pan.natdst": serverIp },
  };
}

/** A resolver record, in the shape every DNS product module reads. */
export function dnsRow(o: Base & {
  on: { host: string; ip: string; user?: string }; query: string; answer: string;
  severity?: Severity; description: string; mitre?: string; tactic?: string;
}): TelemetryEvent {
  return {
    id: o.id, ts: o.ts, source: "dns", vendor: "Infoblox DNS", event_type: "dns_query",
    hostname: o.on.host, src_ip: o.on.ip, severity: o.severity ?? "informational",
    ...(o.mitre ? { mitre_technique: o.mitre } : {}), ...(o.tactic ? { mitre_tactic: o.tactic } : {}),
    dns: { query: o.query, query_type: "A", response: o.answer, rcode: "NOERROR" },
    description: o.description,
    raw: {
      "dns.question.name": o.query,
      "dns.question.type": "A",
      "dns.question.class": "IN",
      "dns.answers.data": o.answer,
      "dns.answers.ttl": "300",
      "dns.response_code": "NOERROR",
      "dns.resolved_ip": o.answer,
      "source.ip": o.on.ip,
      "event.action": "dns-query",
      "event.outcome": "success",
    },
  };
}

/**
 * A Sentinel analytic that opens the case: a detection row, not one with an EDR process behind it.
 * With no `user` the alert is about a resource or a visitor, so it names no employee: the emitter
 * would draw one, and an analyst would chase a person who has nothing to do with it.
 */
export function sentinel(o: Base & Omit<SentinelAlertOpts, "companyId" | "id" | "ts"> & { entity?: string }): TelemetryEvent {
  const { entity, ...opts } = o;
  const e = { ...sentinelAlert({ companyId: CX, ...opts }), is_detection: true };
  if (o.user) return e;
  const { user_email: _user, ...row } = e;
  const { "target.user.name": _account, ...raw } = e.raw ?? {};
  return {
    ...row,
    raw: {
      ...raw,
      Entities: (raw.Entities as { Type?: string }[]).filter(x => x.Type !== "account"),
      CompromisedEntity: o.host ?? entity ?? o.srcIp ?? "",
    },
  };
}

export function ticket(o: Base & {
  table?: string; number: string; state: string; caller: string; shortDescription: string; severity: Severity; description: string;
  eventType?: EventType; mitre?: string; tactic?: string; extra?: Record<string, string | number>;
  /** The caller is a system (a portal intake), not a person the row is about. */
  systemCaller?: boolean;
}): TelemetryEvent {
  const e = serviceNowRecord({
    companyId: CX, id: o.id, ts: o.ts, table: o.table ?? "incident", number: o.number, state: o.state, callerId: o.caller,
    shortDescription: o.shortDescription, severity: o.severity, eventType: o.eventType ?? "policy_modification",
    mitre: o.mitre, tactic: o.tactic, description: o.description, extra: o.extra,
  });
  if (!o.systemCaller) return e;
  const { user_email: _user, ...row } = e;
  return row;
}

/** One row of ServiceNow's transaction log (syslog_transaction): a transaction has a URL, a type and a user, not a ticket number. */
export function snowTransaction(o: Base & { url: string; type: string; createdBy: string; responseTimeMs: number; severity: Severity; description: string; mitre?: string; tactic?: string }): TelemetryEvent {
  return {
    id: o.id, ts: o.ts, source: "soar", vendor: "ServiceNow ITSM", event_type: "cloud_api_call", severity: o.severity, user_email: o.createdBy,
    ...(o.mitre ? { mitre_technique: o.mitre } : {}), ...(o.tactic ? { mitre_tactic: o.tactic } : {}),
    description: o.description,
    raw: {
      "servicenow.table": "syslog_transaction",
      "servicenow.url": o.url,
      "servicenow.type": o.type,
      "servicenow.sys_created_by": o.createdBy.split("@")[0],
      "servicenow.sys_created_on": `${o.ts.slice(0, 10)} ${o.ts.slice(11, 19)}`,
      "servicenow.response_time": o.responseTimeMs,
    },
  };
}

/** An Azure Activity Log operation on any resource (azureActivity alone writes Cognitive Services ids). */
export function azureOp(o: Omit<AzureActivityOpts, "resource"> & {
  provider: string; group: string; name: string; region?: string; type: string; role: string;
}): TelemetryEvent {
  const resource: AzureAiResource = { subscriptionId: SUB, resourceGroup: o.group, account: o.name, region: o.region ?? "westeurope" };
  const e = azureActivity({ ...o, resource });
  const rid = `/SUBSCRIPTIONS/${SUB.toUpperCase()}/RESOURCEGROUPS/${o.group.toUpperCase()}/PROVIDERS/${o.provider.toUpperCase()}/${o.type.toUpperCase()}/${o.name.toUpperCase()}`;
  return {
    ...e,
    raw: {
      ...e.raw,
      "azure.resource.id": rid,
      "azure.resource.provider": o.provider.toUpperCase(),
      "azure.activitylogs.identity.authorization.scope": rid.toLowerCase(),
      "azure.activitylogs.identity.authorization.evidence.role": o.role,
    },
  };
}

/** Azure Front Door Standard/Premium access log (FrontDoorAccessLog), the only hop that sees a visitor's own address. */
export function frontDoor(o: Base & {
  hostName: string; clientIp: string; method: "GET" | "POST"; uri: string; status: number;
  requestBytes: number; responseBytes: number; timeTakenS: number; userAgent: string; severity: Severity; description: string;
  mitre?: string; tactic?: string; route?: string;
}): TelemetryEvent {
  return {
    id: o.id, ts: o.ts, source: "cloud_azure", vendor: "Azure Front Door", event_type: "http_request", severity: o.severity,
    src_ip: o.clientIp, dst_port: 443, protocol: "tcp",
    ...(o.mitre ? { mitre_technique: o.mitre } : {}), ...(o.tactic ? { mitre_tactic: o.tactic } : {}),
    network: { url: `https://${o.hostName}${o.uri}`, domain: o.hostName, method: o.method, status: o.status, bytes_out: o.requestBytes, bytes_in: o.responseBytes, user_agent: o.userAgent },
    description: o.description,
    raw: {
      time: o.ts,
      resourceId: `/SUBSCRIPTIONS/${SUB.toUpperCase()}/RESOURCEGROUPS/RG-PORTAL-WEB/PROVIDERS/MICROSOFT.CDN/PROFILES/AFD-PORTAL`,
      category: "FrontDoorAccessLog",
      operationName: "Microsoft.Cdn/Profiles/AccessLog/Write",
      "properties.trackingReference": `${o.ts.slice(0, 10).replace(/-/g, "")}T${o.ts.slice(11, 19).replace(/:/g, "")}Z-${makeSha256(`afd:${o.id}`).slice(0, 20)}`,
      "properties.httpMethod": o.method,
      "properties.httpVersion": "1.1.0.0",
      "properties.requestUri": `https://${o.hostName}:443${o.uri}`,
      "properties.hostName": o.hostName,
      "properties.requestBytes": String(o.requestBytes),
      "properties.responseBytes": String(o.responseBytes),
      "properties.userAgent": o.userAgent,
      "properties.clientIp": o.clientIp,
      "properties.socketIp": o.clientIp,
      "properties.timeTaken": o.timeTakenS.toFixed(3),
      "properties.clientPort": String(49152 + (parseInt(makeSha256(`afd:port:${o.id}`).slice(0, 4), 16) % 16000)),
      "properties.requestProtocol": "HTTPS",
      "properties.securityProtocol": "TLSv1.2",
      "properties.endpoint": "afd-portal-e7f2.z01.azurefd.net",
      "properties.pop": "AMS",
      "properties.httpStatusCode": String(o.status),
      "properties.cacheStatus": "CACHE_NOCONFIG",
      "properties.errorInfo": "NoError",
      "properties.originName": "app-portal-weu.azurewebsites.net",
      "properties.routeName": o.route ?? "route-api",
    },
  };
}

/** App Service HTTP log (table AppServiceHTTPLogs) of a request the portal's backend served. */
export function appServiceHttp(o: Base & {
  site: string; clientIp: string; method: "GET" | "POST"; stem: string; query?: string; status: number; csBytes: number; scBytes: number;
  timeTakenMs: number; userAgent: string; severity: Severity; description: string; mitre?: string; tactic?: string;
}): TelemetryEvent {
  return {
    id: o.id, ts: o.ts, source: "cloud_azure", vendor: "Azure App Service", event_type: "http_request", severity: o.severity,
    src_ip: o.clientIp,
    ...(o.mitre ? { mitre_technique: o.mitre } : {}), ...(o.tactic ? { mitre_tactic: o.tactic } : {}),
    description: o.description,
    raw: {
      TimeGenerated: o.ts,
      Type: "AppServiceHTTPLogs",
      _ResourceId: `/subscriptions/${SUB}/resourcegroups/rg-portal-web/providers/microsoft.web/sites/${o.site}`,
      CsHost: `${o.site}.azurewebsites.net`,
      CsMethod: o.method,
      CsUriStem: o.stem,
      ...(o.query ? { CsUriQuery: o.query } : {}),
      CIp: o.clientIp,
      SPort: "443",
      ScStatus: o.status,
      CsBytes: o.csBytes,
      ScBytes: o.scBytes,
      TimeTaken: o.timeTakenMs,
      UserAgent: o.userAgent,
      Result: o.status < 400 ? "Success" : "Failure",
    },
  };
}

/** API Management gateway log (table ApiManagementGatewayLogs): the hop that knows which subscription key a call used. */
export function apimGateway(o: Base & {
  subscription: string; api: string; operation: string; callerIp: string; method: "GET" | "POST"; url: string; status: number;
  requestSize: number; responseSize: number; totalTimeMs: number; severity: Severity; description: string; mitre?: string; tactic?: string;
}): TelemetryEvent {
  return {
    id: o.id, ts: o.ts, source: "cloud_azure", vendor: "Azure API Management", event_type: "http_request", severity: o.severity,
    src_ip: o.callerIp,
    ...(o.mitre ? { mitre_technique: o.mitre } : {}), ...(o.tactic ? { mitre_tactic: o.tactic } : {}),
    description: o.description,
    raw: {
      TimeGenerated: o.ts,
      Type: "ApiManagementGatewayLogs",
      _ResourceId: `/subscriptions/${SUB}/resourcegroups/rg-portal-web/providers/microsoft.apimanagement/service/apim-partner-weu`,
      ApimSubscriptionId: o.subscription,
      ApiId: o.api,
      OperationId: o.operation,
      Method: o.method,
      Url: o.url,
      CallerIpAddress: o.callerIp,
      ResponseCode: o.status,
      BackendResponseCode: o.status,
      IsRequestSuccess: o.status < 400,
      RequestSize: o.requestSize,
      ResponseSize: o.responseSize,
      TotalTime: o.totalTimeMs,
      CorrelationId: makeSha256(`apim:${o.id}`).slice(0, 32),
      Region: "West Europe",
    },
  };
}

/** Amazon Bedrock model invocation log (CloudWatch Logs): token counts per call, body logging off. */
export function bedrockInvocation(o: Base & {
  arn: string; modelId: string; operation?: string; inputTokens: number; outputTokens: number; severity: Severity; description: string; mitre?: string; tactic?: string;
}): TelemetryEvent {
  return {
    id: o.id, ts: o.ts, source: "cloudtrail", vendor: "AWS CloudWatch", event_type: "cloud_api_call", severity: o.severity,
    ...(o.mitre ? { mitre_technique: o.mitre } : {}), ...(o.tactic ? { mitre_tactic: o.tactic } : {}),
    description: o.description,
    raw: {
      schemaType: "ModelInvocationLog",
      schemaVersion: "1.0",
      timestamp: o.ts.replace(/\.\d{3}Z$/, "Z"),
      accountId: "418772153604",
      region: "us-east-1",
      requestId: makeSha256(`bedrock:${o.id}`).slice(0, 36),
      operation: o.operation ?? "InvokeModel",
      modelId: o.modelId,
      "identity.arn": o.arn,
      "input.inputContentType": "application/json",
      "input.inputTokenCount": o.inputTokens,
      "output.outputContentType": "application/json",
      "output.outputTokenCount": o.outputTokens,
      "cloud.provider": "aws",
      "cloud.account.id": "418772153604",
      "cloud.region": "us-east-1",
    },
  };
}

export { makeSha256 };
