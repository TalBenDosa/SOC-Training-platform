/**
 * Web tier log EMITTER: one HTTP request, seen by the WAF and by the origin web server.
 *
 * The event is vendor-neutral: the request in `network`, the WAF's decision in a few neutral raw keys.
 * The session's stack decides how it prints (AWS WAF or Azure WAF, nginx or IIS: sources/_web-common).
 * `server` binds an access log to one product when the story shows that server's own process tree.
 *
 * Attack strings in a URL stay abbreviated and inert: enough to recognize the class, never a payload.
 */
import type { EventType, ExpectedVerdict, Severity, TelemetryEvent } from "../types";
import { WEB_SERVER_VENDOR, WEB_WAF_VENDOR, type WafRuleKey } from "@/lib/logs/native/sources/_web-common";

export interface WebSite {
  /** The public site. */
  site: string;
  /** The origin server: keep a dotted name, a web server stays itself on every company. */
  host: string;
  /** Its private address. */
  ip: string;
  /** Bind the access log to this product; omit to follow the session's web server. */
  server?: "nginx" | "iis";
}

export interface WebRequest {
  id: string; ts: string;
  srcIp: string;
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  path: string;
  query?: string;
  status?: number;
  /** Bytes returned to the client. */
  bytes?: number;
  /** Bytes the client sent. */
  sent?: number;
  ua: string;
  referer?: string;
  /** The Host the client really sent, when it is not the site. */
  hostHeader?: string;
  geo?: TelemetryEvent["geo"];
  description: string;
  severity?: Severity;
  mitre?: string; tactic?: string;
  isDetection?: boolean;
  verdict?: ExpectedVerdict;
  fpExplanation?: string;
  isBaseline?: boolean;
}

export interface WafDecision extends WebRequest {
  action: "block" | "count" | "allow";
  rule?: WafRuleKey;
  /** The rule's own name, for a custom or rate rule. */
  ruleName?: string;
  /** What the rule matched: abbreviated. */
  matched?: string;
  /** Where it matched, ModSecurity style (ARGS:file, REQUEST_BODY). */
  location?: string;
  rateLimit?: number; rateWindowSec?: number;
}

const common = (w: WebSite, r: WebRequest) => ({
  id: r.id, ts: r.ts,
  src_ip: r.srcIp,
  protocol: "tcp",
  severity: r.severity ?? ("low" as Severity),
  ...(r.geo ? { geo: r.geo } : {}),
  network: {
    url: `https://${w.site}${r.path}${r.query ? `?${r.query}` : ""}`,
    domain: w.site, method: r.method ?? "GET", status: r.status ?? 200,
    bytes_in: r.bytes ?? 1840, bytes_out: r.sent ?? 612, user_agent: r.ua,
  },
  description: r.description,
  ...(r.mitre ? { mitre_technique: r.mitre, mitre_tactic: r.tactic } : {}),
  ...(r.isDetection ? { is_detection: true } : {}),
  ...(r.verdict ? { expected_verdict: r.verdict } : {}),
  ...(r.fpExplanation ? { fp_explanation: r.fpExplanation } : {}),
  ...(r.isBaseline ? { is_baseline: true } : {}),
});

const requestRaw = (w: WebSite, r: WebRequest) => ({
  "url.domain": w.site, "url.path": r.path, ...(r.query ? { "url.query": r.query } : {}),
  "http.request.method": r.method ?? "GET", "user_agent.original": r.ua, "source.ip": r.srcIp,
  ...(r.referer ? { "http.request.referrer": r.referer } : {}),
  ...(r.hostHeader ? { "http.request.header.host": r.hostHeader } : {}),
});

/** One request as the origin web server logged it. */
export function webAccess(w: WebSite, r: WebRequest): TelemetryEvent {
  const vendor = w.server === "iis" ? "Microsoft IIS" : w.server === "nginx" ? "nginx" : WEB_SERVER_VENDOR;
  return {
    ...common(w, r), source: "web_server", vendor, event_type: "http_request" as EventType,
    hostname: w.host, dst_ip: w.ip, dst_port: 443,
    raw: { ...requestRaw(w, r), "destination.ip": w.ip, "http.response.status_code": r.status ?? 200, "http.response.body.bytes": r.bytes ?? 1840, "http.request.body.bytes": r.sent ?? 612 },
  };
}

/** One request as the WAF in front of the site logged it (no server address: a WAF log has none). */
export function wafRequest(w: WebSite, r: WafDecision): TelemetryEvent {
  return {
    ...common(w, { ...r, status: r.status ?? (r.action === "block" ? 403 : 200), bytes: r.bytes ?? (r.action === "block" ? 197 : undefined) }),
    source: "waf", vendor: WEB_WAF_VENDOR, event_type: (r.action === "block" ? "waf_block" : "waf_allow") as EventType,
    raw: {
      ...requestRaw(w, r),
      "waf.action": r.action,
      ...(r.rule ? { "waf.rule.key": r.rule } : {}),
      ...(r.ruleName ? { "waf.rule.name": r.ruleName } : {}),
      ...(r.matched ? { "waf.matched_data": r.matched } : {}),
      ...(r.location ? { "waf.match_location": r.location } : {}),
      ...(r.rateLimit ? { "waf.rate.limit": r.rateLimit } : {}),
      ...(r.rateWindowSec ? { "waf.rate.window_sec": r.rateWindowSec } : {}),
    },
  };
}
