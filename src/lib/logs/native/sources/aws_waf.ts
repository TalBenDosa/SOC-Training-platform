/**
 * AWS WAF web ACL traffic log, native source module (JSON).
 *
 * Card: docs/log-schemas/waf-aws.md. One record per request the web ACL inspected, delivered
 * through Firehose, S3 or CloudWatch Logs: the terminating rule and action, the rule groups and
 * rate-based rules that were evaluated, the labels, and the request's metadata. The request BODY
 * is never logged and neither is the response: a rule name is all the record says about a body,
 * and whether the origin answered 200 lives in the web server's log.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { KindSchema, NativeCtx, NativeLog, NativeSource, SourceSchema, UseCase } from "../types";
import { clientCountry, WAF_RULES, webFacts, type WebFacts } from "./_web-common";

const REQUEST = ["httpRequest.clientIp", "httpRequest.country", "httpRequest.headers", "httpRequest.uri", "httpRequest.args", "httpRequest.httpVersion", "httpRequest.httpMethod", "httpRequest.requestId"];
const kinds: Record<string, KindSchema> = {
  web_acl: {
    required: ["timestamp", "formatVersion", "webaclId", "terminatingRuleId", "terminatingRuleType", "action", "terminatingRuleMatchDetails",
      "httpSourceName", "httpSourceId", "ruleGroupList", "rateBasedRuleList", "nonTerminatingMatchingRules", ...REQUEST],
    optional: ["requestHeadersInserted", "responseCodeSent", "labels", "ja3Fingerprint", "ja4Fingerprint", "oversizeFields", "captchaResponse", "challengeResponse"],
  },
};

const schema: SourceSchema = {
  sourceId: "aws_waf", category: "waf", card: "waf-aws.md", product: "AWS WAF", format: "json",
  vendorMatch: ["web application firewall", "aws waf"],
  telemetrySources: ["waf"],
  kinds,
};

export function kindOf(record: Record<string, unknown>): string | null {
  return record.webaclId !== undefined && record.terminatingRuleId !== undefined ? "web_acl" : null;
}

/** The web ACL rule that references a managed group: "AWS-" + group, the console default name. */
const aclRule = (group: string) => `AWS-${group}`;

function fromTelemetry(ev: TelemetryEvent, ctx: NativeCtx): NativeLog | null {
  const f = webFacts(ev);
  const acct = ctx.tenant.awsAccountId;
  const region = "eu-west-1";
  const acl = `${ctx.org}-edge-acl`;
  const trace = `1-${ctx.hex(`waf-trace-a:${ev.id}`, 8)}-${ctx.hex(`waf-trace-b:${ev.id}`, 24)}`;
  const headers = [
    { name: "Host", value: f.hostHeader ?? f.site },
    { name: "User-Agent", value: f.userAgent },
    { name: "Accept", value: "*/*" },
    ...(f.referer ? [{ name: "Referer", value: f.referer }] : []),
    { name: "X-Forwarded-For", value: f.clientIp },
    { name: "X-Forwarded-Proto", value: "https" },
    { name: "X-Amzn-Trace-Id", value: `Root=${trace}` },
  ];
  const record: Record<string, unknown> = {
    timestamp: Date.parse(ev.ts),
    formatVersion: 1,
    webaclId: `arn:aws:wafv2:${region}:${acct}:regional/webacl/${acl}/${ctx.uuid(`waf-acl:${ctx.companyId}`)}`,
    ...decision(f, `${ctx.org}-rate-per-ip`),
    httpSourceName: "ALB",
    httpSourceId: `${acct}-app/${ctx.org}-public-alb/${ctx.hex(`waf-alb:${ctx.companyId}`, 16)}`,
    requestHeadersInserted: null,
    responseCodeSent: null,
    httpRequest: {
      clientIp: f.clientIp, country: clientCountry(ev, ctx), headers,
      uri: f.path, args: f.query, httpVersion: "HTTP/1.1", httpMethod: f.method, requestId: trace,
    },
    // The same client software presents the same TLS hello whichever address it comes from.
    ja3Fingerprint: ctx.hex(`waf-ja3:${f.userAgent}`, 32),
  };
  if (f.oversizeBody) record.oversizeFields = ["REQUEST_BODY"];
  const labels = labelsOf(f);
  if (labels.length) record.labels = labels.map(name => ({ name }));
  return { sourceId: "aws_waf", kind: "web_acl", format: "json", record, timeMs: Date.parse(ev.ts) };
}

/**
 * The web ACL's shape never changes per request: one list of rule groups, the one that matched (if
 * any) reporting its rule, and its rate rule, which AWS lists whether or not the client is over it.
 */
function decision(f: WebFacts, rateName: string): Record<string, unknown> {
  const blocked = f.action === "block";
  const rate = { rateBasedRuleId: rateName, rateBasedRuleName: rateName, limitKey: "IP", limitValue: f.clientIp, maxRateAllowed: f.rateLimit ?? 300, evaluationWindowSec: String(f.rateWindowSec ?? 300) };
  const base = {
    terminatingRuleId: "Default_Action", terminatingRuleType: "REGULAR", action: blocked ? "BLOCK" : "ALLOW", terminatingRuleMatchDetails: [] as unknown[],
    rateBasedRuleList: [rate] as unknown[], nonTerminatingMatchingRules: [] as unknown[],
  };
  const groups = ["AWSManagedRulesCommonRuleSet", "AWSManagedRulesKnownBadInputsRuleSet", "AWSManagedRulesSQLiRuleSet", "AWSManagedRulesPHPRuleSet", "AWSManagedRulesATPRuleSet"];
  const idle = (g: string) => ({ ruleGroupId: `AWS#${g}`, terminatingRule: null, nonTerminatingMatchingRules: [], excludedRules: null });
  if (f.rule === "rate") {
    return { ...base, ruleGroupList: groups.map(idle),
      ...(blocked ? { terminatingRuleId: rateName, terminatingRuleType: "RATE_BASED" } : { nonTerminatingMatchingRules: [{ ruleId: rateName, action: "COUNT", ruleMatchDetails: [] }] }) };
  }
  if (f.rule === "custom") {
    const name = f.ruleName ?? "custom-rule";
    return { ...base, ruleGroupList: groups.map(idle),
      ...(blocked ? { terminatingRuleId: name } : { nonTerminatingMatchingRules: [{ ruleId: name, action: "COUNT", ruleMatchDetails: [] }] }) };
  }
  const def = f.rule ? WAF_RULES[f.rule]?.aws : undefined;
  if (!def) return { ...base, ruleGroupList: groups.map(idle) };
  // A rule overridden to Count: the request passes, the group reports the match with the configured action.
  const matched = blocked
    ? { ruleGroupId: `AWS#${def.group}`, terminatingRule: { ruleId: def.rule, action: "BLOCK", ruleMatchDetails: null }, nonTerminatingMatchingRules: [], excludedRules: null }
    : { ruleGroupId: `AWS#${def.group}`, terminatingRule: null, nonTerminatingMatchingRules: [{ ruleId: def.rule, action: "COUNT", overriddenAction: "BLOCK", ruleMatchDetails: [] }], excludedRules: null };
  return { ...base, ruleGroupList: groups.map(g => (g === def.group ? matched : idle(g))),
    ...(blocked ? { terminatingRuleId: aclRule(def.group), terminatingRuleType: "MANAGED_RULE_GROUP" } : {}) };
}

function labelsOf(f: WebFacts): string[] {
  const def = f.rule && f.rule !== "rate" && f.rule !== "custom" ? WAF_RULES[f.rule]?.aws : undefined;
  return def ? [def.label, ...(def.extraLabel ? [def.extraLabel] : [])] : [];
}

const useCases: UseCase[] = [
  {
    id: "aws_waf.metadata_ssrf", title: "Cloud metadata address in a request parameter", sourceId: "aws_waf", severity: "high", mitre: ["T1190", "T1552.005"],
    description: "A request tried to make the application fetch the instance metadata service. The rule name says what it looked like: check the next requests from the client that did not match, because a redirector or an encoded address passes where the literal address is blocked.",
    logic: 'CloudWatch Logs Insights: fields httpRequest.clientIp, httpRequest.uri, httpRequest.args | filter labels.0.name like /EC2MetaDataSSRF/',
    match: { field: "labels[].name", op: "contains", value: "EC2MetaDataSSRF" },
    falsePositives: ["An external vulnerability scan during its approved window"],
  },
  {
    id: "aws_waf.managed_rule_counted", title: "Managed rule matched in Count: the request was let through", sourceId: "aws_waf", severity: "medium", mitre: ["T1190"],
    description: "A rule overridden to Count matched. Nothing stopped this request, so the origin's log decides what happened to it.",
    logic: 'filter action = "ALLOW" and ruleGroupList.0.nonTerminatingMatchingRules.0.action = "COUNT"',
    match: { all: [{ field: "action", op: "eq", value: "ALLOW" }, { field: "ruleGroupList[].nonTerminatingMatchingRules[].action", op: "eq", value: "COUNT" }] },
    falsePositives: ["A rich-text editor posting HTML", "A rule put in Count while it is tuned"],
  },
  {
    id: "aws_waf.injection_block", title: "Injection rule blocked a request", sourceId: "aws_waf", severity: "medium", kinds: ["web_acl"], mitre: ["T1190"],
    description: "SQL injection, cross-site scripting or file inclusion blocked by a managed rule. One block is noise; the same client changing its encoding is an operator working around the rule.",
    logic: 'filter action = "BLOCK" and terminatingRuleType = "MANAGED_RULE_GROUP"',
    match: { all: [{ field: "action", op: "eq", value: "BLOCK" }, { field: "terminatingRuleType", op: "eq", value: "MANAGED_RULE_GROUP" }] },
    falsePositives: ["Approved penetration test", "External scanner"],
  },
  {
    id: "aws_waf.block_then_retry", title: "One client blocked repeatedly: is it adapting?", sourceId: "aws_waf", severity: "high", kinds: ["web_acl"], mitre: ["T1190", "T1027"],
    description: "Three or more blocks from one client within ten minutes. Read the args across the rows: a changing encoding is a person, and the first ALLOW after them is the row that matters.",
    logic: 'filter action = "BLOCK" | stats count() by httpRequest.clientIp, bin(10m) | filter count >= 3',
    match: { field: "action", op: "eq", value: "BLOCK" },
    threshold: { groupBy: ["httpRequest.clientIp"], count: 3, windowSec: 600 },
    falsePositives: ["Approved penetration test", "External scanner"],
  },
  {
    id: "aws_waf.rate_rule", title: "Rate-based rule evaluated over its limit", sourceId: "aws_waf", severity: "medium", mitre: ["T1110.004", "T1119"],
    description: "A client went over a rate-based rule's limit. Check whether the rule blocks or only counts, and what the client was walking through.",
    logic: 'filter nonTerminatingMatchingRules.0.ruleId like /rate-per-ip/ or terminatingRuleType = "RATE_BASED"',
    match: { field: "nonTerminatingMatchingRules[].ruleId", op: "contains", value: "rate-per-ip" },
    falsePositives: ["A partner batch job", "A broken client retrying"],
  },
  {
    id: "aws_waf.atp_credentials", title: "Account takeover prevention flagged login traffic", sourceId: "aws_waf", severity: "high", mitre: ["T1110.004"],
    description: "The ATP rule group labelled login requests for volume or for stolen credentials. Rotating addresses often share a ja3Fingerprint: pivot on it to find the addresses the volume rule did not reach.",
    logic: 'filter labels.0.name like /awswaf:managed:aws:atp:aggregate/',
    match: { field: "labels[].name", op: "contains", value: "awswaf:managed:aws:atp:aggregate" },
    falsePositives: ["A mobile client bug retrying expired sessions from carrier NAT"],
  },
];

export const source: NativeSource = { schema, fromTelemetry, useCases };
