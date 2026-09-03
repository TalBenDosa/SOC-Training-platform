/**
 * Palo Alto Networks PAN-OS (NGFW) log EMITTERS.
 *
 * The network half of the kill chain — the web request that downloads a dropper, the
 * loader's outbound fetch of its second stage, the C2 config pull, the exfil POST. Same
 * contract as the endpoint emitters: a typed call renders a complete TelemetryEvent whose
 * raw block uses only registry-valid PAN fields (the pan./gp. prefixes + the shared ECS
 * fields), with the client host/IP/user drawn from the company asset fabric.
 *
 * PAN-OS is a firewall (source:"firewall"), so these events carry no process — they are
 * the transport evidence an analyst correlates against the endpoint tree.
 */
import type { TelemetryEvent, Severity } from "../types";
import { hashString } from "../rng";
import { resolve, type Ctx } from "./_core";

const VENDOR = "Palo Alto Networks PAN-OS";

// A stable routable "server" IP for a domain, when the caller doesn't pin one.
function serverIpFor(domain: string): string {
  const h = hashString(`panip:${domain}`);
  // 23.x / 45.x / 104.x / 146.x / 185.x — common hosting ranges, never RFC1918.
  const firsts = [23, 45, 104, 146, 185, 188];
  return `${firsts[h % firsts.length]}.${(h >> 3) % 254 + 1}.${(h >> 8) % 254 + 1}.${(h >> 16) % 254 + 1}`;
}

const PAN_TYPE = { alert: "THREAT", deny: "THREAT", block: "THREAT", allow: "TRAFFIC" } as const;

export interface PanWebOpts extends Ctx {
  url: string;                 // full https URL
  domain: string;
  category: string;            // PAN URL category, e.g. "newly-registered-domain"
  method?: "GET" | "POST";
  action?: "alert" | "allow" | "deny" | "block";
  dstIp?: string;              // resolved server IP (public); deterministic if omitted
  status?: number;
  bytesIn?: number;
  bytesOut?: number;
  referer?: string;
  userAgent?: string;
  repeatCount?: number;        // PAN aggregates repeated identical sessions (repeatcnt)
  userTitle?: string;          // shown as the analyst-facing role chip in the feed
  file?: { name: string; path?: string; sha256?: string; size?: number }; // a download
  fileType?: string;           // pan.filetype for a download — "pe" | "script" | "pdf" …
  mitre?: string;
  tactic?: string;
  severity?: Severity;
  description?: string;
}
export function panWeb(o: PanWebOpts): TelemetryEvent {
  const r = resolve(o);
  const method = o.method ?? "GET";
  const action = o.action ?? "alert";
  const dstIp = o.dstIp ?? serverIpFor(o.domain);
  const panType = PAN_TYPE[action];
  const subtype = o.file ? "file" : method === "POST" ? "end" : "url";
  const panUrl = o.url.replace(/^https?:\/\//, "");
  const srcUser = r.domainUser.toLowerCase();   // PAN logs domain\user in lower case
  const blocked = action === "deny" || action === "block";
  // A URL-filtering block is logged as "block-url"; a policy deny as "deny".
  const actionStr = action === "block" ? "block-url" : action;
  return {
    id: o.id, ts: o.ts, source: "firewall", vendor: VENDOR,
    event_type: blocked ? "http_blocked" : "http_request",
    severity: o.severity ?? "medium", hostname: r.host, src_ip: r.srcIp, dst_ip: dstIp,
    dst_port: 443, protocol: "tcp",
    user_email: r.email, user_title: o.userTitle,
    mitre_technique: o.mitre, mitre_tactic: o.tactic, incident_id: o.incidentId,
    network: { url: o.url, domain: o.domain, method, status: o.status ?? 200, bytes_in: o.bytesIn, bytes_out: o.bytesOut, user_agent: o.userAgent },
    ...(o.file ? { file: { name: o.file.name, path: o.file.path ?? `/${o.file.name}`, ...(o.file.sha256 ? { sha256: o.file.sha256 } : {}), ...(o.file.size ? { size: o.file.size } : {}), extension: o.file.name.split(".").pop() } } : {}),
    description: o.description ?? `${r.host} ${method === "POST" ? "POSTed to" : "requested"} ${o.domain}`,
    raw: {
      "pan.type": panType,
      "pan.subtype": subtype,
      "pan.action": actionStr,
      "pan.rule": blocked ? "BLOCK-NEWLY-REGISTERED" : "CORP-WEB-OUTBOUND",
      "pan.src": r.srcIp,
      "pan.srcuser": srcUser,
      "pan.dst": dstIp,
      "pan.dport": "443",
      "pan.app": "web-browsing",
      "pan.category": o.category,
      "pan.url": panUrl,
      ...(o.referer ? { "pan.referer": o.referer } : {}),
      "pan.http_method": method,
      ...(o.file ? { "pan.filename": o.file.name, "pan.filetype": o.fileType ?? "pe", ...(o.file.sha256 ? { "pan.file_hash": o.file.sha256 } : {}), "pan.direction": "download" } : {}),
      ...(o.bytesOut !== undefined ? { "pan.bytes_sent": String(o.bytesOut) } : {}),
      ...(o.bytesIn !== undefined ? { "pan.bytes_received": String(o.bytesIn) } : {}),
      ...(o.repeatCount !== undefined ? { "pan.repeat_count": String(o.repeatCount) } : {}),
      "source.ip": r.srcIp,
      "url.domain": o.domain,
      "http.request.method": method,
      "http.response.status_code": String(o.status ?? 200),
      "action_result": actionStr,
    },
  };
}

// ── Connection / session (net_connection) ────────────────────────────────────────────
// A firewall connection or session-end record — a WebSocket tunnel, a raw socket, a
// session summary with byte counts and duration. Distinct from panWeb (an HTTP request):
// the app is not "web-browsing" and there may be no URL.
export interface PanConnectionOpts extends Ctx {
  domain?: string;
  dstIp?: string;
  remotePort?: number;
  app?: string;                // pan.app — "websocket" | "ssl" | "ssh" …
  transport?: "tcp" | "udp";
  action?: "alert" | "allow" | "deny" | "block";
  category?: string;
  url?: string;                // optional (a WebSocket upgrade URL)
  bytesIn?: number;
  bytesOut?: number;
  elapsedSec?: number;
  end?: boolean;               // true → a TRAFFIC/end session summary (else a start/alert)
  mitre?: string;
  tactic?: string;
  severity?: Severity;
  description?: string;
}
export function panConnection(o: PanConnectionOpts): TelemetryEvent {
  const r = resolve(o);
  const action = o.action ?? (o.end ? "allow" : "alert");
  const dstIp = o.dstIp ?? (o.domain ? serverIpFor(o.domain) : "—");
  const transport = o.transport ?? "tcp";
  const port = o.remotePort ?? 443;
  const actionStr = action === "block" ? "block-url" : action;
  return {
    id: o.id, ts: o.ts, source: "firewall", vendor: VENDOR,
    event_type: action === "deny" || action === "block" ? "net_blocked" : "net_connection",
    severity: o.severity ?? "medium", hostname: r.host, src_ip: r.srcIp, dst_ip: dstIp,
    dst_port: port, protocol: transport, user_email: r.email,
    mitre_technique: o.mitre, mitre_tactic: o.tactic, incident_id: o.incidentId,
    network: { domain: o.domain, url: o.url, bytes_in: o.bytesIn, bytes_out: o.bytesOut },
    description: o.description ?? `${r.host} ${o.end ? "closed" : "opened"} a ${o.app ?? transport} connection to ${o.domain ?? dstIp}`,
    raw: {
      "pan.type": o.end ? "TRAFFIC" : (action === "alert" ? "THREAT" : "TRAFFIC"),
      "pan.subtype": o.end ? "end" : "url",
      "pan.action": actionStr,
      "pan.rule": "CORP-WEB-OUTBOUND",
      "pan.src": r.srcIp,
      "pan.srcuser": r.domainUser.toLowerCase(),
      "pan.dst": dstIp,
      "pan.dport": String(port),
      "pan.app": o.app ?? "ssl",
      ...(o.category ? { "pan.category": o.category } : {}),
      ...(o.url ? { "pan.url": o.url.replace(/^https?:\/\//, "") } : {}),
      ...(o.bytesOut !== undefined ? { "pan.bytes_sent": String(o.bytesOut) } : {}),
      ...(o.bytesIn !== undefined ? { "pan.bytes_received": String(o.bytesIn) } : {}),
      ...(o.elapsedSec !== undefined ? { "pan.elapsed_time": String(o.elapsedSec) } : {}),
      "source.ip": r.srcIp,
      ...(o.domain ? { "url.domain": o.domain } : {}),
      "destination.ip": dstIp,
      "destination.port": String(port),
      "network.transport": transport,
      "action_result": actionStr,
    },
  };
}
