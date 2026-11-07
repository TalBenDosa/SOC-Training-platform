/**
 * Azure WAF on Application Gateway, native source module (Azure Monitor resource logs, JSON).
 *
 * Card: docs/log-schemas/waf-azure.md. Two categories:
 *  - ApplicationGatewayFirewallLog: one row per rule that fired. With anomaly scoring the rule that
 *    fired is "Matched" and does not itself block; rule 949110 then writes the "Blocked" row, with the
 *    same transactionId (Microsoft: troubleshoot anomaly scoring and rule 949110). That row is the
 *    module's companion record, and the feed prints it under the rule row. A site's policy is in one
 *    mode: on a Detection policy every rule row is "Detected" and nothing is blocked.
 *  - ApplicationGatewayAccessLog: one row per request, for traffic no rule touched: a request with no
 *    firewall row still has one here, with the origin's status (serverStatus) and the bytes sent.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { KindSchema, NativeCtx, NativeLog, NativeSource, SourceSchema, UseCase } from "../types";
import { balancerIp, siteLabel, WAF_RULES, webFacts, type WebFacts } from "./_web-common";

const ENVELOPE = ["resourceId", "operationName", "category"];
const kinds: Record<string, KindSchema> = {
  ApplicationGatewayFirewallLog: {
    required: [...ENVELOPE, "time", "properties.instanceId", "properties.clientIp", "properties.requestUri", "properties.ruleSetType", "properties.ruleSetVersion",
      "properties.ruleId", "properties.message", "properties.action", "properties.site", "properties.details.message", "properties.details.data",
      "properties.details.file", "properties.details.line", "properties.hostname", "properties.transactionId", "properties.policyId", "properties.policyScope", "properties.policyScopeName"],
    optional: ["properties.ruleGroup"],
  },
  ApplicationGatewayAccessLog: {
    required: [...ENVELOPE, "timeStamp", "properties.instanceId", "properties.clientIP", "properties.clientPort", "properties.httpMethod", "properties.requestUri",
      "properties.userAgent", "properties.httpStatus", "properties.httpVersion", "properties.receivedBytes", "properties.sentBytes", "properties.timeTaken",
      "properties.transactionId", "properties.sslEnabled", "properties.serverRouted", "properties.serverStatus", "properties.host"],
    optional: ["listenerName", "ruleName", "backendPoolName", "backendSettingName", "properties.originalRequestUriWithArgs", "properties.requestQuery", "properties.clientResponseTime",
      "properties.WAFEvaluationTime", "properties.WAFMode", "properties.sslCipher", "properties.sslProtocol", "properties.serverResponseLatency", "properties.upstreamSourcePort",
      "properties.originalHost", "properties.error_info"],
  },
};

const schema: SourceSchema = {
  sourceId: "azure_waf", category: "waf", card: "waf-azure.md", product: "Azure WAF", format: "json",
  vendorMatch: ["web application firewall", "azure application gateway", "azure waf"],
  telemetrySources: ["waf"],
  kinds,
};

export function kindOf(record: Record<string, unknown>): string | null {
  const c = record.category;
  return c === "ApplicationGatewayFirewallLog" || c === "ApplicationGatewayAccessLog" ? c : null;
}

const gatewayId = (ctx: NativeCtx) => `/SUBSCRIPTIONS/${ctx.tenant.azureSubscriptionId.toUpperCase()}/RESOURCEGROUPS/RG-EDGE-PROD/PROVIDERS/MICROSOFT.NETWORK/APPLICATIONGATEWAYS/${ctx.org.toUpperCase()}-WAF-GW`;
const uriOf = (f: WebFacts) => (f.query ? `${f.path}?${f.query}` : f.path);
const transactionOf = (ev: TelemetryEvent, ctx: NativeCtx) => ctx.hex(`agw-txn:${ev.id}`, 32);
const listenerOf = (ctx: NativeCtx, f: WebFacts) => `${ctx.org}-${siteLabel(f.site)}-https-listener`;

/** The firewall-log row of a rule that fired. */
function firewallRow(ev: TelemetryEvent, ctx: NativeCtx, f: WebFacts, p: { ruleSetType: string; ruleSetVersion: string; ruleId: string; ruleGroup?: string; message: string; action: string; detail: string; data: string; file: string }): NativeLog {
  const policy = `${ctx.org}-${siteLabel(f.site)}-waf-policy`;
  const record: Record<string, unknown> = {
    resourceId: gatewayId(ctx),
    operationName: "ApplicationGatewayFirewall",
    time: ev.ts.replace(/\.(\d{3})Z$/, ".$10000Z"),
    category: "ApplicationGatewayFirewallLog",
    properties: {
      instanceId: `appgw_${ctx.int(`agw-instance:${ev.id}`, 0, 1)}`,
      clientIp: f.clientIp,
      requestUri: uriOf(f),
      ruleSetType: p.ruleSetType,
      ruleSetVersion: p.ruleSetVersion,
      ruleId: p.ruleId,
      ...(p.ruleGroup ? { ruleGroup: p.ruleGroup } : {}),
      message: p.message,
      action: p.action,
      site: "Global",
      details: { message: p.detail, data: p.data, file: p.file, line: String(ctx.int(`agw-line:${p.ruleId}`, 90, 1400)) },
      hostname: f.site,
      transactionId: transactionOf(ev, ctx),
      policyId: `/subscriptions/${ctx.tenant.azureSubscriptionId}/resourceGroups/rg-edge-prod/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/${policy}`,
      policyScope: "Listener",
      policyScopeName: listenerOf(ctx, f),
    },
  };
  return { sourceId: "azure_waf", kind: "ApplicationGatewayFirewallLog", format: "json", record, timeMs: Date.parse(ev.ts) };
}

function fromTelemetry(ev: TelemetryEvent, ctx: NativeCtx): NativeLog | null {
  const f = webFacts(ev);
  if (!f.rule) return accessRow(ev, ctx, f);
  const blocked = f.action === "block";
  const location = f.location ?? (f.query ? "ARGS" : "REQUEST_BODY");
  const data = f.matched ? `Matched Data: ${f.matched} found within ${location}: ${f.matched}` : `Matched Data found within ${location}`;
  const def = f.rule !== "rate" && f.rule !== "custom" ? WAF_RULES[f.rule]?.azure : undefined;
  if (def && "ruleId" in def) {
    return firewallRow(ev, ctx, f, {
      ruleSetType: "OWASP", ruleSetVersion: "3.2", ruleId: def.ruleId, ruleGroup: def.ruleGroup, message: def.message,
      // Prevention + anomaly scoring: the rule only scores (the Blocked row is the companion).
      // A managed rule that lets the request through means the site's policy is in Detection.
      action: blocked ? "Matched" : "Detected",
      detail: `Warning. ${def.detail} at ${location}.`, data, file: `rules/${def.ruleGroup}.conf`,
    });
  }
  // A custom rule (rate limit, match rule). UNVERIFIED in Microsoft's docs: the shape of a custom
  // rule's row (ruleSetType "Custom", ruleId = the rule's name, no ruleGroup); see the card. A Log rule
  // on a Prevention policy lets evaluation continue, Microsoft's meaning of Matched.
  const name = def && "custom" in def ? def.custom : f.ruleName ?? (f.rule === "rate" ? "RateLimitPerClientIp" : "CustomRule");
  return firewallRow(ev, ctx, f, {
    ruleSetType: "Custom", ruleSetVersion: "1.0", ruleId: name, message: `Custom rule ${name}`, action: blocked ? "Blocked" : f.wafMode === "Detection" ? "Detected" : "Matched",
    detail: f.rule === "rate" || f.rateLimit ? `Rate limit of ${f.rateLimit ?? 300} requests in ${f.rateWindowSec ?? 300} seconds exceeded by client.` : "Custom rule matched.",
    data, file: "CustomRules",
  });
}

/** The access-log row of a request no rule touched. */
function accessRow(ev: TelemetryEvent, ctx: NativeCtx, f: WebFacts): NativeLog {
  const blocked = f.action === "block";
  const backend = `${f.serverIp ?? balancerIp(undefined, ctx)}:443`;
  const taken = (ctx.int(`agw-time:${ev.id}`, 18, 640) / 1000);
  const record: Record<string, unknown> = {
    timeStamp: ev.ts.replace(/\.\d{3}Z$/, "+00:00"),
    resourceId: gatewayId(ctx),
    listenerName: listenerOf(ctx, f),
    ruleName: `${ctx.org}-${siteLabel(f.site)}-routing-rule`,
    backendPoolName: `${ctx.org}-web-pool`,
    backendSettingName: `${ctx.org}-https-setting`,
    operationName: "ApplicationGatewayAccess",
    category: "ApplicationGatewayAccessLog",
    properties: {
      instanceId: `appgw_${ctx.int(`agw-instance:${ev.id}`, 0, 1)}`,
      clientIP: f.clientIp,
      clientPort: ctx.int(`agw-port:${ev.id}`, 32768, 60999),
      httpMethod: f.method,
      originalRequestUriWithArgs: uriOf(f),
      requestUri: f.path,
      requestQuery: f.query,
      userAgent: f.userAgent,
      httpStatus: f.status,
      httpVersion: "HTTP/1.1",
      receivedBytes: f.bytesIn,
      sentBytes: f.bytesOut,
      timeTaken: taken,
      WAFEvaluationTime: "0.001",
      WAFMode: f.wafMode,
      transactionId: transactionOf(ev, ctx),
      sslEnabled: "on",
      sslCipher: "ECDHE-RSA-AES256-GCM-SHA384",
      sslProtocol: "TLSv1.2",
      serverRouted: blocked ? "-" : backend,
      serverStatus: blocked ? "-" : String(f.status),
      serverResponseLatency: blocked ? "-" : (taken * 0.8).toFixed(3),
      originalHost: f.hostHeader ?? f.site,
      host: f.site,
      error_info: "ERRORINFO_NO_ERROR",
    },
  };
  return { sourceId: "azure_waf", kind: "ApplicationGatewayAccessLog", format: "json", record, timeMs: Date.parse(ev.ts) };
}

/** Anomaly scoring: the row that actually blocked the request (rule 949110, same transactionId). */
function companions(ev: TelemetryEvent, ctx: NativeCtx): NativeLog[] {
  const f = webFacts(ev);
  if (f.action !== "block" || !f.rule || f.rule === "rate" || f.rule === "custom") return [];
  const def = WAF_RULES[f.rule]?.azure;
  if (!def || !("ruleId" in def)) return [];
  return [firewallRow(ev, ctx, f, {
    ruleSetType: "OWASP", ruleSetVersion: "3.2", ruleId: "949110", ruleGroup: "REQUEST-949-BLOCKING-EVALUATION",
    message: "Mandatory rule. Cannot be disabled. Inbound Anomaly Score Exceeded (Total Score: 5)", action: "Blocked",
    detail: "Access denied with code 403 (phase 2). Operator GE matched 5 at TX:anomaly_score.", data: "-", file: "rules/REQUEST-949-BLOCKING-EVALUATION.conf",
  })];
}

const P = "properties.";
const useCases: UseCase[] = [
  {
    id: "azure_waf.metadata_address", title: "Metadata address in a request parameter", sourceId: "azure_waf", kinds: ["ApplicationGatewayFirewallLog"], severity: "high", mitre: ["T1190", "T1552.005"],
    description: "Rule 931100 saw a URL built on a literal IP address in a parameter. When that address is the instance metadata service the application is being asked to fetch its own credentials.",
    logic: 'KQL: AGWFirewallLogs | where RuleId == "931100" and RequestUri has "169.254.169.254"',
    match: { all: [{ field: `${P}ruleId`, op: "eq", value: "931100" }, { field: `${P}requestUri`, op: "contains", value: "169.254" }] },
    falsePositives: ["An external vulnerability scan during its approved window"],
  },
  {
    id: "azure_waf.detection_mode_match", title: "Rule fired on a listener in Detection mode: nothing stopped it", sourceId: "azure_waf", kinds: ["ApplicationGatewayFirewallLog"], severity: "medium", mitre: ["T1190"],
    description: "Action Detected means the request was logged and passed to the backend. The origin's log decides what happened to it.",
    logic: 'AGWFirewallLogs | where Action == "Detected"',
    match: { field: `${P}action`, op: "eq", value: "Detected" },
    falsePositives: ["A rich-text editor posting HTML", "A rule on a listener still being tuned"],
  },
  {
    id: "azure_waf.scored_match", title: "Injection rule scored a request", sourceId: "azure_waf", kinds: ["ApplicationGatewayFirewallLog"], severity: "medium", mitre: ["T1190"],
    description: "A rule matched and added to the anomaly score. Follow the transactionId to the 949110 row to see whether the total crossed the threshold.",
    logic: 'AGWFirewallLogs | where Action == "Matched" | join (AGWFirewallLogs | where RuleId == "949110") on TransactionId',
    match: { field: `${P}action`, op: "eq", value: "Matched" },
    falsePositives: ["Approved penetration test", "External scanner"],
  },
  {
    id: "azure_waf.repeat_client", title: "One client scoring repeatedly: is it adapting?", sourceId: "azure_waf", kinds: ["ApplicationGatewayFirewallLog"], severity: "high", mitre: ["T1190", "T1027"],
    description: "Three or more scored requests from one client in ten minutes. Read requestUri across the rows: a changing encoding is a person at work.",
    logic: 'AGWFirewallLogs | where Action == "Matched" | summarize count() by ClientIp, bin(TimeGenerated, 10m) | where count_ >= 3',
    match: { field: `${P}action`, op: "eq", value: "Matched" },
    threshold: { groupBy: [`${P}clientIp`], count: 3, windowSec: 600 },
    falsePositives: ["Approved penetration test", "External scanner"],
  },
  {
    id: "azure_waf.custom_rule", title: "Custom rule fired (rate limit or match rule)", sourceId: "azure_waf", kinds: ["ApplicationGatewayFirewallLog"], severity: "medium", mitre: ["T1110.004", "T1119"],
    description: "A rule the site's own team wrote fired. Read its name, then the client's other requests.",
    logic: 'AGWFirewallLogs | where RuleSetType == "Custom"',
    match: { field: `${P}ruleSetType`, op: "eq", value: "Custom" },
    falsePositives: ["A partner batch job", "A broken client retrying"],
  },
  {
    id: "azure_waf.large_response_clean", title: "Large response with no rule fired", sourceId: "azure_waf", kinds: ["ApplicationGatewayAccessLog"], severity: "medium", mitre: ["T1190", "T1041"],
    description: "A request no rule touched answered with more than 5 MB. On a page that normally returns kilobytes, that is what a request the WAF did not understand looks like.",
    logic: 'AGWAccessLogs | where SentBytes > 5000000 and HttpStatus == 200',
    match: { all: [{ field: `${P}sentBytes`, op: "gt", value: 5_000_000 }, { field: `${P}httpStatus`, op: "eq", value: 200 }] },
    falsePositives: ["A report or file download page"],
  },
];

export const source: NativeSource = { schema, fromTelemetry, companions, useCases };
