/**
 * Shared authoring helpers for the wave-4 AI stories (wave4-a.ts, wave4-b.ts).
 *
 * Every wave-4 story is authored on the NexaCorp identity (the same one every other shared
 * story uses): instantiateStory re-homes people, domain, hosts, subnet and tenant ids onto the
 * company a session runs on, so one authored chain reads as native on all of them.
 *
 * The authored developer login carries the role word "ops" on purpose: instantiateStory then
 * draws the replacement victim from the company's technical staff. A coding agent, a Jupyter
 * kernel or a cloud CLI on a nurse's or a warehouse clerk's account would not be believable.
 */
import type { TelemetryEvent, Severity, EventType } from "@/lib/sim/types";
import { csProcess, csFile, csNetwork, type CsProcessOpts } from "@/lib/sim/emitters/crowdstrike";
import { panWeb, panConnection, type PanWebOpts, type PanConnectionOpts } from "@/lib/sim/emitters/paloalto";
import { sentinelAlert, type SentinelAlertOpts } from "@/lib/sim/emitters/sentinel";
import { serviceNowRecord } from "@/lib/sim/emitters/servicenow";
import { azureActivity, type AzureActivityOpts, type AzureAiResource } from "@/lib/sim/emitters/azureAi";
import { makeCtx } from "@/lib/logs/native/ctx";
import { makeSha256 } from "@/lib/sim/iocs";

export const CX = "nexacorp";
export const DEV = { user: "k.ops@nexacorp.com", bare: "k.ops", host: "WS-ENG-2093", ip: "10.10.20.93" };
export const SUB = makeCtx(CX).tenant.azureSubscriptionId;
/** The company's own NAT egress: what SaaS and cloud control planes see for the office. */
export const OFFICE_EGRESS = "217.177.80.10";

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
  repeatCount?: number; severity: Severity; description: string; mitre?: string; tactic?: string; action?: "allow" | "deny";
}): TelemetryEvent {
  const ev = panConnection({
    companyId: CX, id: o.id, ts: o.ts, host: o.server, srcIp: o.fromIp, user: null, dstIp: o.serverIp, remotePort: o.port,
    direction: "inbound", app: o.app ?? "ssl", action: o.action ?? "allow", end: (o.action ?? "allow") === "allow",
    bytesIn: o.bytesOut, bytesOut: o.bytesIn, elapsedSec: o.elapsedSec, repeatCount: o.repeatCount,
    severity: o.severity, description: o.description, mitre: o.mitre, tactic: o.tactic,
  });
  return { ...ev, network: { ...(ev.network ?? {}), direction: "inbound" } as TelemetryEvent["network"] };
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

/** A Sentinel analytic that opens the case: a detection row, not one with an EDR process behind it. */
export function sentinel(o: Base & Omit<SentinelAlertOpts, "companyId" | "id" | "ts">): TelemetryEvent {
  return { ...sentinelAlert({ companyId: CX, ...o }), is_detection: true };
}

export function ticket(o: Base & {
  table?: string; number: string; state: string; caller: string; shortDescription: string; severity: Severity; description: string;
  eventType?: EventType; mitre?: string; tactic?: string; extra?: Record<string, string | number>;
}): TelemetryEvent {
  return serviceNowRecord({
    companyId: CX, id: o.id, ts: o.ts, table: o.table ?? "incident", number: o.number, state: o.state, callerId: o.caller,
    shortDescription: o.shortDescription, severity: o.severity, eventType: o.eventType ?? "policy_modification",
    mitre: o.mitre, tactic: o.tactic, description: o.description, extra: o.extra,
  });
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

/** Azure Front Door access log (FrontDoorAccessLog), the only hop that sees a visitor's own address. */
export function frontDoor(o: Base & {
  hostName: string; clientIp: string; country: string; method: "GET" | "POST"; uri: string; status: number;
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
      "properties.requestProtocol": "HTTPS",
      "properties.securityProtocol": "TLS 1.3",
      "properties.httpStatusCode": String(o.status),
      "properties.httpStatusDetails": String(o.status),
      "properties.cacheStatus": "CONFIG_NOCACHE",
      "properties.errorInfo": "NoError",
      "properties.originName": "app-portal-weu.azurewebsites.net",
      "properties.clientCountry": o.country,
      "properties.routingRuleName": o.route ?? "route-api",
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

export { makeSha256 };
