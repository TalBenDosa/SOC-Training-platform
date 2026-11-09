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
  /** The site's WAF policy mode, default Prevention. A Detection policy logs a managed rule and passes the request. */
  wafMode?: "Detection" | "Prevention";
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
  /** The port the server took the request on, default 443. */
  port?: number;
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
  /** The body was longer than the WAF inspects. */
  oversizeBody?: boolean;
}

/** A request with no authored size: its request line and usual headers, as a server counts them. */
const requestSize = (w: WebSite, r: WebRequest) => (r.method ?? "GET").length + r.path.length + (r.query ? r.query.length + 1 : 0) + w.site.length + r.ua.length + (r.referer?.length ?? 0) + 148;

const common = (w: WebSite, r: WebRequest) => ({
  id: r.id, ts: r.ts,
  src_ip: r.srcIp,
  protocol: "tcp",
  severity: r.severity ?? ("low" as Severity),
  ...(r.geo ? { geo: r.geo } : {}),
  network: {
    url: `https://${w.site}${r.path}${r.query ? `?${r.query}` : ""}`,
    domain: w.site, method: r.method ?? "GET", status: r.status ?? 200,
    bytes_in: r.bytes ?? 1840, bytes_out: r.sent ?? requestSize(w, r), user_agent: r.ua,
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
    hostname: w.host, dst_ip: w.ip, dst_port: r.port ?? 443,
    raw: { ...requestRaw(w, r), "destination.ip": w.ip, "http.response.status_code": r.status ?? 200, "http.response.body.bytes": r.bytes ?? 1840, "http.request.body.bytes": r.sent ?? requestSize(w, r) },
  };
}

/** One request as the WAF in front of the site logged it. The event names no server (a WAF rule row has none); the raw origin address is what an access row routes to. */
export function wafRequest(w: WebSite, r: WafDecision): TelemetryEvent {
  return {
    ...common(w, { ...r, status: r.status ?? (r.action === "block" ? 403 : 200), bytes: r.bytes ?? (r.action === "block" ? 197 : undefined) }),
    source: "waf", vendor: WEB_WAF_VENDOR, event_type: (r.action === "block" ? "waf_block" : "waf_allow") as EventType,
    raw: {
      ...requestRaw(w, r),
      "destination.ip": w.ip,
      "waf.action": r.action,
      ...(w.wafMode ? { "waf.mode": w.wafMode } : {}),
      ...(r.oversizeBody ? { "waf.oversize_body": true } : {}),
      ...(r.rule ? { "waf.rule.key": r.rule } : {}),
      ...(r.ruleName ? { "waf.rule.name": r.ruleName } : {}),
      ...(r.matched ? { "waf.matched_data": r.matched } : {}),
      ...(r.location ? { "waf.match_location": r.location } : {}),
      ...(r.rateLimit ? { "waf.rate.limit": r.rateLimit } : {}),
      ...(r.rateWindowSec ? { "waf.rate.window_sec": r.rateWindowSec } : {}),
    },
  };
}

/** One GraphQL request as the origin application logged it. */
export interface GraphqlOperation {
  id: string; ts: string;
  /** The client as the app sees it behind its proxy: the X-Forwarded-For address. */
  clientIp: string;
  ua: string;
  operationName: string;
  /** Top-level fields the document asked for under aliases (0 for an ordinary query). */
  aliases: number;
  /** Errors the response carried, by GraphQL error code (Apollo Server: UNAUTHENTICATED, BAD_USER_INPUT ...). */
  errors?: Record<string, number>;
  responseMs: number;
  pid: number;
  /** pino-http's per-process request counter. */
  reqId: number;
  description: string;
  severity?: Severity;
  mitre?: string; tactic?: string;
  isBaseline?: boolean;
}
/**
 * The origin GraphQL service's own request log: a Node.js service with pino-http, one JSON line per
 * request (pino's level / time / pid / hostname / msg, pino-http's req / res / responseTime), and the
 * operation summary the service adds through pino-http customProps. A batched document is one HTTP
 * 200 with one error per failed alias: the error count is the record of every guess.
 */
export function graphqlAppLog(w: WebSite, o: GraphqlOperation): TelemetryEvent {
  const failed = Object.values(o.errors ?? {}).reduce((a, b) => a + b, 0);
  return {
    id: o.id, ts: o.ts, source: "app_log", vendor: "Node.js pino-http", event_type: "http_request" as EventType,
    severity: o.severity ?? "low", hostname: w.host, src_ip: o.clientIp, dst_ip: w.ip, dst_port: 4000, protocol: "tcp",
    network: { url: `https://${w.site}/graphql`, domain: w.site, method: "POST", status: 200, user_agent: o.ua },
    description: o.description,
    ...(o.mitre ? { mitre_technique: o.mitre, mitre_tactic: o.tactic } : {}),
    ...(o.isBaseline ? { is_baseline: true } : {}),
    raw: {
      level: failed ? 40 : 30,
      // pino with timestamp: pino.stdTimeFunctions.isoTime (an ISO string rather than epoch ms).
      time: o.ts,
      pid: o.pid,
      hostname: w.host.split(".")[0],
      // pino-http's default request id: a per-process counter.
      "req.id": o.reqId,
      "req.method": "POST",
      "req.url": "/graphql",
      "req.remoteAddress": "127.0.0.1",
      "req.headers.x-forwarded-for": o.clientIp,
      "req.headers.user-agent": o.ua,
      "res.statusCode": 200,
      responseTime: o.responseMs,
      "graphql.operationName": o.operationName,
      "graphql.aliasCount": o.aliases,
      ...Object.fromEntries(Object.entries(o.errors ?? {}).map(([code, n]) => [`graphql.errors.${code}`, n])),
      // pino-http's own message: a GraphQL error rides in a 200 response, so the request "completed".
      msg: "request completed",
    },
  };
}
