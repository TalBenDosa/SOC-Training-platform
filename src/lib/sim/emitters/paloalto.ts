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
      "pan.action": action,
      "pan.rule": "CORP-WEB-OUTBOUND",
      "pan.src": r.srcIp,
      "pan.srcuser": srcUser,
      "pan.dst": dstIp,
      "pan.dport": "443",
      "pan.app": "web-browsing",
      "pan.category": o.category,
      "pan.url": panUrl,
      ...(o.referer ? { "pan.referer": o.referer } : {}),
      "pan.http_method": method,
      ...(o.file ? { "pan.filename": o.file.name, "pan.filetype": "pe", ...(o.file.sha256 ? { "pan.file_hash": o.file.sha256 } : {}), "pan.direction": "download" } : {}),
      ...(o.bytesOut !== undefined ? { "pan.bytes_sent": String(o.bytesOut) } : {}),
      ...(o.bytesIn !== undefined ? { "pan.bytes_received": String(o.bytesIn) } : {}),
      ...(o.repeatCount !== undefined ? { "pan.repeat_count": String(o.repeatCount) } : {}),
      "source.ip": r.srcIp,
      "url.domain": o.domain,
      "http.request.method": method,
      "http.response.status_code": String(o.status ?? 200),
      "action_result": action,
    },
  };
}
