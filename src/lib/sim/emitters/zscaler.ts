/**
 * Zscaler Internet Access (ZIA) log EMITTER.
 *
 * The cloud proxy that sees ALL egress for the Zscaler shops — the web request an
 * analyst reads for phishing click-through, newly-registered-domain access, C2 over
 * HTTPS, and malware download blocks. Renders registry-valid Zscaler fields (the
 * zscaler./url./http. prefixes + ECS), client identity from the fabric, remote
 * geography deterministic from the peer IP.
 *
 * Zscaler is source:"proxy" and carries no process.
 */
import type { TelemetryEvent, Severity } from "../types";
import { resolve, type Ctx } from "./_core";

const VENDOR = "Zscaler Internet Access";

export interface ZscalerWebOpts extends Ctx {
  url: string;                     // full URL
  domain: string;
  method?: "GET" | "POST";
  action?: "allowed" | "blocked";
  category?: string;               // url.category / zscaler.urlcategory
  status?: number;
  bytesSent?: number;
  bytesReceived?: number;
  userAgent?: string;
  appName?: string;                // zscaler.appname (e.g. "General Browsing")
  location?: string;               // zscaler.location (egress node / office label)
  threatName?: string;             // set → a threat block/detection
  malwareCategory?: string;
  reason?: string;                 // zscaler block reason
  mitre?: string;
  tactic?: string;
  severity?: Severity;
  description?: string;
}
export function zscalerWeb(o: ZscalerWebOpts): TelemetryEvent {
  const r = resolve(o);
  const method = o.method ?? "GET";
  const action = o.action ?? (o.threatName ? "blocked" : "allowed");
  const blocked = action === "blocked";
  const isThreat = !!o.threatName;
  return {
    id: o.id, ts: o.ts, source: "proxy", vendor: VENDOR,
    event_type: blocked ? "http_blocked" : "http_request",
    severity: o.severity ?? (isThreat ? "high" : blocked ? "medium" : "low"),
    hostname: r.host, src_ip: r.srcIp, dst_port: 443, protocol: "tcp", user_email: r.email,
    mitre_technique: o.mitre, mitre_tactic: o.tactic, is_detection: isThreat, incident_id: o.incidentId,
    network: { url: o.url, domain: o.domain, method, status: o.status ?? (blocked ? 403 : 200), bytes_out: o.bytesSent, bytes_in: o.bytesReceived, user_agent: o.userAgent },
    description: o.description ?? `Zscaler ${action} ${method} ${o.domain}${isThreat ? ` (${o.threatName})` : ""}`,
    raw: {
      "zscaler.action": blocked ? "Blocked" : "Allowed",
      "zscaler.url": o.url.replace(/^https?:\/\//, ""),
      "zscaler.hostname": o.domain,
      "zscaler.urlcategory": o.category ?? "Miscellaneous",
      "zscaler.appname": o.appName ?? "General Browsing",
      "zscaler.login": r.email ?? r.bareUser,
      ...(o.location ? { "zscaler.location": o.location } : {}),
      ...(o.bytesSent !== undefined ? { "zscaler.reqsize": String(o.bytesSent) } : {}),
      ...(o.bytesReceived !== undefined ? { "zscaler.respsize": String(o.bytesReceived) } : {}),
      ...(o.reason ? { "zscaler.reason": o.reason } : {}),
      ...(isThreat ? { "zscaler.threatname": o.threatName!, "zscaler.malwarecategory": o.malwareCategory ?? "Malware" } : {}),
      // shared ECS
      "action": blocked ? "blocked" : "allowed",
      "action_result": blocked ? "blocked" : "allowed",
      "event.action": isThreat ? "threat-block" : "web-access",
      "event.category": "network",
      "event.reason": o.reason ?? (blocked ? "Policy block" : ""),
      "url.full": o.url,
      "url.domain": o.domain,
      "url.category": o.category ?? "Miscellaneous",
      "http.request.method": method,
      "http.response.status_code": String(o.status ?? (blocked ? 403 : 200)),
      ...(o.userAgent ? { "http.user_agent": o.userAgent } : {}),
      "source.ip": r.srcIp,
      "source.user.name": r.bareUser,
      ...(r.email ? { "user.email": r.email } : {}),
      ...(isThreat ? { "threat.name": o.threatName! } : {}),
      ...(isThreat && o.mitre ? { "threat.technique.id": o.mitre } : {}),
    },
  };
}
