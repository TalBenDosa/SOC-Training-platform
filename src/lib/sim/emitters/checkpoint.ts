/**
 * Check Point NGFW log EMITTERS.
 *
 * The perimeter firewall for the Check Point shops — accepted/dropped connections
 * and Threat-Prevention blocks. Like FortiGate, the registry pins Check Point to
 * an EXACT field set (no prefixes), so these emitters render Check Point's native
 * fields (src/dst/proto/service_id/rule_name/inzone/outzone/xlatesrc…) alongside
 * the shared ECS fields — every key one the registry allows. Client identity from
 * the fabric; remote geography deterministic from the peer IP (@/lib/geo/resolveGeo).
 *
 * Check Point is source:"firewall" (or "ids" for Threat Prevention).
 */
import type { TelemetryEvent, Severity } from "../types";
import { resolve, type Ctx } from "./_core";
import { knownGeoForIp } from "@/lib/geo/resolveGeo";

const VENDOR = "Check Point NGFW";
const geoCountry = (ip?: string) => knownGeoForIp(ip)?.country;

// ── Connection (Firewall blade: accept / drop) ────────────────────────────────────────
export interface CpTrafficOpts extends Ctx {
  remoteIp: string;
  remotePort: number;
  service?: string;                // service_id, e.g. "https"
  transport?: "tcp" | "udp";
  action?: "accept" | "drop" | "reject";
  direction?: "outbound" | "inbound";
  ruleName?: string;
  bytes?: number;
  natIp?: string;                  // xlatesrc for outbound
  mitre?: string;
  tactic?: string;
  severity?: Severity;
  description?: string;
}
export function cpTraffic(o: CpTrafficOpts): TelemetryEvent {
  const r = resolve(o);
  const transport = o.transport ?? "tcp";
  const action = o.action ?? "accept";
  const blocked = action !== "accept";
  const inbound = o.direction === "inbound";
  const src = inbound ? o.remoteIp : r.srcIp;
  const dst = inbound ? r.srcIp : o.remoteIp;
  return {
    id: o.id, ts: o.ts, source: "firewall", vendor: VENDOR,
    event_type: blocked ? "net_blocked" : "net_connection",
    severity: o.severity ?? (blocked ? "medium" : "low"), hostname: r.host,
    src_ip: src, dst_ip: dst, dst_port: o.remotePort, protocol: transport, user_email: r.email,
    mitre_technique: o.mitre, mitre_tactic: o.tactic, incident_id: o.incidentId,
    network: { bytes_out: o.bytes },
    description: o.description ?? `Check Point ${action} ${transport.toUpperCase()} ${src} → ${dst}:${o.remotePort}`,
    raw: {
      "ProductName": "VPN-1 & FireWall-1",
      "ProductFamily": "Network",
      "action": action,
      "src": src,
      "dst": dst,
      "proto": transport === "tcp" ? "6" : "17",
      "service_id": o.service ?? (o.remotePort === 443 ? "https" : o.remotePort === 80 ? "http" : `TCP/${o.remotePort}`),
      "svc": String(o.remotePort),
      "rule_name": o.ruleName ?? (blocked ? "Drop-Threat" : "Corp-Outbound"),
      "layer_name": "Network Security",
      "inzone": inbound ? "External" : "Internal",
      "outzone": inbound ? "Internal" : "External",
      ...(o.natIp && !inbound ? { "xlatesrc": o.natIp } : {}),
      // shared ECS
      "action_result": blocked ? "blocked" : "allowed",
      "event.action": action,
      "event.category": "network",
      "event.outcome": blocked ? "failure" : "success",
      "source.ip": src,
      "destination.ip": dst,
      "destination.port": String(o.remotePort),
      "network.transport": transport,
      ...(geoCountry(o.remoteIp) ? { "destination.geo.country_name": geoCountry(o.remoteIp)! } : {}),
    },
  };
}

// ── Threat Prevention (IPS / Anti-Bot / Anti-Virus) ───────────────────────────────────
export interface CpThreatOpts extends Ctx {
  remoteIp: string;
  remotePort?: number;
  threatName: string;
  blade?: "IPS" | "Anti-Bot" | "Anti-Virus" | "Threat Emulation";
  domain?: string;
  url?: string;
  action?: "Prevent" | "Detect";
  mitre?: string;
  tactic?: string;
  technique?: string;
  severity?: Severity;
  description?: string;
}
export function cpThreat(o: CpThreatOpts): TelemetryEvent {
  const r = resolve(o);
  const action = o.action ?? "Prevent";
  const blocked = action === "Prevent";
  return {
    id: o.id, ts: o.ts, source: "ids", vendor: VENDOR,
    event_type: blocked ? "ids_blocked" : "ids_signature",
    severity: o.severity ?? "high", hostname: r.host, src_ip: r.srcIp, dst_ip: o.remoteIp,
    dst_port: o.remotePort, user_email: r.email, mitre_technique: o.mitre, mitre_tactic: o.tactic,
    is_detection: true, incident_id: o.incidentId, network: { domain: o.domain, url: o.url },
    description: o.description ?? `Check Point ${o.blade ?? "IPS"} ${action} ${o.threatName} from ${r.host} → ${o.domain ?? o.remoteIp}`,
    raw: {
      "ProductName": o.blade ?? "IPS",
      "ProductFamily": "Threat",
      "action": blocked ? "Prevent" : "Detect",
      "src": r.srcIp,
      "dst": o.remoteIp,
      ...(o.remotePort ? { "svc": String(o.remotePort) } : {}),
      "rule_name": "Threat Prevention",
      "layer_name": "Threat Prevention",
      "sig_id": `CP-${Math.abs(hash(o.threatName)) % 90000 + 10000}`,
      // shared ECS
      "action_result": blocked ? "blocked" : "detected",
      "event.action": (o.blade ?? "IPS").toLowerCase(),
      "event.category": "intrusion_detection",
      "event.outcome": blocked ? "success" : "failure",
      "source.ip": r.srcIp,
      "destination.ip": o.remoteIp,
      "threat.name": o.threatName,
      ...(o.mitre ? { "threat.technique.id": o.mitre } : {}),
      ...(o.technique ? { "threat.technique.name": o.technique } : {}),
      ...(o.domain ? { "url.domain": o.domain } : {}),
      ...(o.url ? { "url.full": o.url } : {}),
      ...(geoCountry(o.remoteIp) ? { "destination.geo.country_name": geoCountry(o.remoteIp)! } : {}),
    },
  };
}

// tiny stable hash for a signature id
function hash(s: string): number { let x = 2166136261; for (let i = 0; i < s.length; i++) { x ^= s.charCodeAt(i); x = Math.imul(x, 16777619); } return x; }
