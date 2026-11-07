/**
 * Shared facts for the web tier's native modules (aws_waf, azure_waf, iis, nginx).
 *
 * A web attack story is authored once, in a vendor-neutral shape (src/lib/sim/emitters/web.ts):
 * the HTTP request in ev.network, the WAF decision in a few neutral raw keys. Each module prints
 * those facts in its own format, so one story reads as AWS WAF + nginx at one company and as
 * Azure WAF + IIS at another. The rule catalog below maps a rule to each product's real rule.
 *
 * Sources: AWS WAF developer guide (managed rule groups, ATP rule group), Microsoft Learn (WAF on
 * Application Gateway rule groups, CRS 3.2 tab). Cards: docs/log-schemas/waf-*.md, web-*.md.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { NativeCtx } from "../types";
import { countryInfo } from "./_identity-common";

/** The authored vendor of a WAF row that follows the session's WAF product (stack.ts categoryOf). */
export const WEB_WAF_VENDOR = "Web Application Firewall";
/** The authored vendor of an access log row that follows the session's web server. */
export const WEB_SERVER_VENDOR = "Web Server";

export type WafRuleKey =
  | "xss_body" | "sqli_query" | "lfi_query" | "lfi_body" | "ssrf_query" | "java_body" | "php_body"
  | "bad_bot" | "size_body" | "restricted_ext" | "exploitable_path" | "login_volumetric" | "login_stolen"
  | "rate" | "custom";

interface AwsRule { group: string; rule: string; label: string; extraLabel?: string }
interface AzureRule { ruleId: string; ruleGroup: string; message: string; detail: string }
/** A rule with no managed equivalent on Azure WAF renders as a custom rule of this name. */
export const WAF_RULES: Record<Exclude<WafRuleKey, "custom" | "rate">, { aws: AwsRule; azure: AzureRule | { custom: string } }> = {
  xss_body: {
    aws: { group: "AWSManagedRulesCommonRuleSet", rule: "CrossSiteScripting_BODY", label: "awswaf:managed:aws:core-rule-set:CrossSiteScripting_Body" },
    azure: { ruleId: "941100", ruleGroup: "REQUEST-941-APPLICATION-ATTACK-XSS", message: "XSS Attack Detected via libinjection", detail: "detected XSS using libinjection." },
  },
  sqli_query: {
    aws: { group: "AWSManagedRulesSQLiRuleSet", rule: "SQLi_QUERYARGUMENTS", label: "awswaf:managed:aws:sql-database:SQLi_QueryArguments" },
    azure: { ruleId: "942100", ruleGroup: "REQUEST-942-APPLICATION-ATTACK-SQLI", message: "SQL Injection Attack Detected via libinjection", detail: "detected SQLi using libinjection." },
  },
  lfi_query: {
    aws: { group: "AWSManagedRulesCommonRuleSet", rule: "GenericLFI_QUERYARGUMENTS", label: "awswaf:managed:aws:core-rule-set:GenericLFI_QueryArguments" },
    azure: { ruleId: "930100", ruleGroup: "REQUEST-930-APPLICATION-ATTACK-LFI", message: "Path Traversal Attack (/../)", detail: "Pattern match" },
  },
  lfi_body: {
    aws: { group: "AWSManagedRulesCommonRuleSet", rule: "GenericLFI_BODY", label: "awswaf:managed:aws:core-rule-set:GenericLFI_Body" },
    azure: { ruleId: "930120", ruleGroup: "REQUEST-930-APPLICATION-ATTACK-LFI", message: "OS File Access Attempt", detail: "Matched phrase" },
  },
  ssrf_query: {
    aws: { group: "AWSManagedRulesCommonRuleSet", rule: "EC2MetaDataSSRF_QUERYARGUMENTS", label: "awswaf:managed:aws:core-rule-set:EC2MetaDataSSRF_QueryArguments" },
    azure: { ruleId: "931100", ruleGroup: "REQUEST-931-APPLICATION-ATTACK-RFI", message: "Possible Remote File Inclusion (RFI) Attack = URL Parameter using IP Address", detail: "Pattern match" },
  },
  java_body: {
    aws: { group: "AWSManagedRulesKnownBadInputsRuleSet", rule: "JavaDeserializationRCE_BODY", label: "awswaf:managed:aws:known-bad-inputs:JavaDeserializationRCE_Body" },
    azure: { ruleId: "944130", ruleGroup: "REQUEST-944-APPLICATION-ATTACK-JAVA", message: "Suspicious Java classes", detail: "Matched phrase" },
  },
  php_body: {
    aws: { group: "AWSManagedRulesPHPRuleSet", rule: "PHPHighRiskMethodsVariables_BODY", label: "awswaf:managed:aws:php-app:PHPHighRiskMethodsVariables_Body" },
    azure: { ruleId: "933150", ruleGroup: "REQUEST-933-APPLICATION-ATTACK-PHP", message: "PHP Injection Attack = High-Risk PHP Function Name Found", detail: "Matched phrase" },
  },
  bad_bot: {
    aws: { group: "AWSManagedRulesCommonRuleSet", rule: "UserAgent_BadBots_HEADER", label: "awswaf:managed:aws:core-rule-set:BadBots_Header" },
    azure: { ruleId: "913100", ruleGroup: "REQUEST-913-SCANNER-DETECTION", message: "Found User-Agent associated with security scanner", detail: "Matched phrase" },
  },
  size_body: {
    aws: { group: "AWSManagedRulesCommonRuleSet", rule: "SizeRestrictions_BODY", label: "awswaf:managed:aws:core-rule-set:SizeRestrictions_Body" },
    azure: { custom: "LogLargeRequestBody" },
  },
  restricted_ext: {
    aws: { group: "AWSManagedRulesCommonRuleSet", rule: "RestrictedExtensions_QUERYARGUMENTS", label: "awswaf:managed:aws:core-rule-set:RestrictedExtensions_QueryArguments" },
    azure: { ruleId: "930130", ruleGroup: "REQUEST-930-APPLICATION-ATTACK-LFI", message: "Restricted File Access Attempt", detail: "Matched phrase" },
  },
  exploitable_path: {
    aws: { group: "AWSManagedRulesKnownBadInputsRuleSet", rule: "ExploitablePaths_URIPATH", label: "awswaf:managed:aws:known-bad-inputs:ExploitablePaths_URIPath" },
    azure: { ruleId: "930130", ruleGroup: "REQUEST-930-APPLICATION-ATTACK-LFI", message: "Restricted File Access Attempt", detail: "Matched phrase" },
  },
  login_volumetric: {
    aws: { group: "AWSManagedRulesATPRuleSet", rule: "VolumetricIpHigh", label: "awswaf:managed:aws:atp:aggregate:volumetric:ip:high", extraLabel: "awswaf:managed:aws:atp:VolumetricIpHigh" },
    azure: { custom: "RateLimitLogin" },
  },
  login_stolen: {
    aws: { group: "AWSManagedRulesATPRuleSet", rule: "AttributeCompromisedCredentials", label: "awswaf:managed:aws:atp:aggregate:attribute:compromised_credentials", extraLabel: "awswaf:managed:aws:atp:AttributeCompromisedCredentials" },
    azure: { custom: "RateLimitLogin" },
  },
};

export interface WebFacts {
  site: string; method: string; path: string; query: string; status: number;
  /** Bytes the client received / sent. */
  bytesOut: number; bytesIn: number;
  userAgent: string; referer?: string; clientIp: string; serverIp?: string;
  action: "block" | "count" | "allow";
  rule?: WafRuleKey; ruleName?: string; matched?: string; location?: string;
  rateLimit?: number; rateWindowSec?: number;
  /** The Host the client really sent, when it differs from the site. */
  hostHeader?: string;
}

const str = (v: unknown) => (v === undefined || v === null || v === "" ? undefined : String(v));
const int = (v: unknown) => { const n = Number(v); return Number.isFinite(n) ? n : undefined; };

/** The request as the story authored it (neutral), or as much of it as a legacy row carries. */
export function webFacts(ev: TelemetryEvent): WebFacts {
  const r = (ev.raw ?? {}) as Record<string, unknown>;
  const n = ev.network;
  const m = /^https?:\/\/([^/?#]+)([^?#]*)(?:\?(.*))?$/.exec(n?.url ?? "");
  const blocked = ev.event_type === "waf_block" || str(r["waf.action"]) === "block";
  return {
    site: n?.domain ?? m?.[1] ?? str(r["url.domain"]) ?? "www.example.com",
    method: n?.method ?? str(r["http.request.method"]) ?? "GET",
    path: str(r["url.path"]) ?? (m?.[2] || "/"),
    query: str(r["url.query"]) ?? m?.[3] ?? "",
    status: n?.status ?? int(r["http.response.status_code"]) ?? (blocked ? 403 : 200),
    bytesOut: n?.bytes_in ?? int(r["http.response.body.bytes"]) ?? 512,
    bytesIn: n?.bytes_out ?? int(r["http.request.body.bytes"]) ?? 412,
    userAgent: n?.user_agent ?? str(r["user_agent.original"]) ?? "-",
    referer: str(r["http.request.referrer"]),
    clientIp: ev.src_ip ?? str(r["source.ip"]) ?? "-",
    serverIp: ev.dst_ip ?? str(r["destination.ip"]),
    action: blocked ? "block" : str(r["waf.action"]) === "count" ? "count" : "allow",
    rule: str(r["waf.rule.key"]) as WafRuleKey | undefined,
    ruleName: str(r["waf.rule.name"]),
    matched: str(r["waf.matched_data"]),
    location: str(r["waf.match_location"]),
    rateLimit: int(r["waf.rate.limit"]),
    rateWindowSec: int(r["waf.rate.window_sec"]),
    hostHeader: str(r["http.request.header.host"]),
  };
}

/** Two-letter country of a client as the WAF geolocates it; "-" when it cannot (a private address). */
export function clientCountry(ev: TelemetryEvent, ctx: NativeCtx): string {
  const ip = ev.src_ip ?? "";
  if (/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip)) return "-";
  return countryInfo(ev.geo?.country)?.iso ?? ["NL", "DE", "US", "RO", "BG"][ctx.int(`web-country:${ip}`, 0, 4)];
}

/** The load balancer in front of a server: an address of the server's own /24 (.9 by convention). */
export function balancerIp(serverIp: string | undefined, ctx: NativeCtx): string {
  const base = (serverIp ?? "").split(".").slice(0, 3).join(".");
  return base ? `${base}.9` : `10.${ctx.int("web-lb:a", 10, 60)}.${ctx.int("web-lb:b", 10, 200)}.9`;
}

export const isPrivateClient = (ip: string) => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip);

/** Short lower-case machine name of a row's host. */
export const machineOf = (ev: TelemetryEvent) => (ev.hostname ?? "web-01").split(".")[0];
