/**
 * Fortinet FortiGate log EMITTERS.
 *
 * The perimeter firewall for the FortiGate shops — allowed/denied sessions, IPS
 * and AV blocks, web filtering, and SSL-VPN logins. The registry pins FortiGate
 * to an EXACT field set (no prefixes), so these emitters render the FortiGate
 * native `data.*` fields alongside the shared ECS fields — every key checked to
 * be one the registry allows. Client host/IP/user come from the company fabric;
 * remote geography is deterministic from the peer IP (@/lib/geo/resolveGeo).
 *
 * FortiGate is source:"firewall" (or "vpn" for tunnel logins) and carries no process.
 */
import type { TelemetryEvent, Severity } from "../types";
import { resolve, type Ctx } from "./_core";
import { knownGeoForIp } from "@/lib/geo/resolveGeo";

const VENDOR = "FortiGate";

function geoCountry(ip?: string): string | undefined { return knownGeoForIp(ip)?.country; }

// ── Traffic / session (forward) ───────────────────────────────────────────────────────
export interface FgTrafficOpts extends Ctx {
  remoteIp: string;
  remotePort: number;
  domain?: string;
  service?: string;                // FortiGate service name, e.g. "HTTPS"
  transport?: "tcp" | "udp";
  action?: "accept" | "deny" | "close";
  direction?: "outbound" | "inbound";
  bytesSent?: number;
  bytesReceived?: number;
  durationSec?: number;
  policyId?: number;
  policyName?: string;
  mitre?: string;
  tactic?: string;
  severity?: Severity;
  description?: string;
}
export function fgTraffic(o: FgTrafficOpts): TelemetryEvent {
  const r = resolve(o);
  const transport = o.transport ?? "tcp";
  const action = o.action ?? "accept";
  const blocked = action === "deny";
  const inbound = o.direction === "inbound";
  const src = inbound ? o.remoteIp : r.srcIp;
  const dst = inbound ? r.srcIp : o.remoteIp;
  return {
    id: o.id, ts: o.ts, source: "firewall", vendor: VENDOR,
    event_type: blocked ? "net_blocked" : "net_connection",
    severity: o.severity ?? (blocked ? "medium" : "low"), hostname: r.host,
    src_ip: src, dst_ip: dst, dst_port: o.remotePort, protocol: transport, user_email: r.email,
    mitre_technique: o.mitre, mitre_tactic: o.tactic, incident_id: o.incidentId,
    network: { domain: o.domain, bytes_out: o.bytesSent, bytes_in: o.bytesReceived },
    description: o.description ?? `FortiGate ${action} ${transport.toUpperCase()} ${src} → ${o.domain ?? dst}:${o.remotePort}`,
    raw: {
      "data.type": "traffic",
      "data.subtype": "forward",
      "data.action": action,
      "data.srcip": src,
      "data.srcport": String(inbound ? o.remotePort : 49152 + (o.remotePort % 1000)),
      "data.dstip": dst,
      "data.dstport": String(o.remotePort),
      "data.proto": transport === "tcp" ? "6" : "17",
      ...(o.service ? { "data.service": o.service } : {}),
      ...(o.domain ? { "data.hostname": o.domain } : {}),
      ...(geoCountry(o.remoteIp) ? { [inbound ? "data.srccountry" : "data.dstcountry"]: geoCountry(o.remoteIp)! } : {}),
      ...(o.bytesSent !== undefined ? { "data.sentbyte": String(o.bytesSent) } : {}),
      ...(o.bytesReceived !== undefined ? { "data.rcvdbyte": String(o.bytesReceived) } : {}),
      ...(o.durationSec !== undefined ? { "data.duration": String(o.durationSec) } : {}),
      ...(o.policyId !== undefined ? { "data.policyid": String(o.policyId) } : {}),
      "data.policyname": o.policyName ?? (blocked ? "Block-Threat" : "Corp-Outbound"),
      "data.level": blocked ? "warning" : "notice",
      "data.trandisp": "snat",
      // shared ECS
      "action": action,
      "action_result": blocked ? "blocked" : "allowed",
      "event.action": blocked ? "deny" : "accept",
      "event.category": "network",
      "event.outcome": blocked ? "failure" : "success",
      "source.ip": src,
      "destination.ip": dst,
      "destination.port": String(o.remotePort),
      "network.transport": transport,
      ...(o.domain ? { "destination.domain": o.domain } : {}),
      ...(geoCountry(o.remoteIp) ? { "destination.geo.country_name": geoCountry(o.remoteIp)! } : {}),
    },
  };
}

// ── UTM threat (IPS / AV / webfilter block) ───────────────────────────────────────────
export interface FgThreatOpts extends Ctx {
  remoteIp: string;
  remotePort?: number;
  subtype?: "ips" | "virus" | "webfilter";
  threatName: string;
  url?: string;
  domain?: string;
  category?: string;               // url.category / threat category
  action?: "blocked" | "detected" | "dropped";
  mitre?: string;
  tactic?: string;
  technique?: string;
  severity?: Severity;
  description?: string;
}
export function fgThreat(o: FgThreatOpts): TelemetryEvent {
  const r = resolve(o);
  const subtype = o.subtype ?? "ips";
  const action = o.action ?? "blocked";
  const blocked = action !== "detected";
  return {
    id: o.id, ts: o.ts, source: "ids", vendor: VENDOR,
    event_type: subtype === "webfilter" ? (blocked ? "http_blocked" : "http_request") : (blocked ? "ids_blocked" : "ids_signature"),
    severity: o.severity ?? "high", hostname: r.host, src_ip: r.srcIp, dst_ip: o.remoteIp,
    dst_port: o.remotePort, user_email: r.email, mitre_technique: o.mitre, mitre_tactic: o.tactic,
    is_detection: true, incident_id: o.incidentId, network: { domain: o.domain, url: o.url },
    description: o.description ?? `FortiGate ${subtype} ${action} ${o.threatName} from ${r.host} → ${o.domain ?? o.remoteIp}`,
    raw: {
      "data.type": "utm",
      "data.subtype": subtype,
      "data.action": action,
      "data.srcip": r.srcIp,
      "data.dstip": o.remoteIp,
      ...(o.remotePort ? { "data.dstport": String(o.remotePort) } : {}),
      "data.msg": o.threatName,
      ...(o.url ? { "data.url": o.url } : {}),
      ...(o.domain ? { "data.hostname": o.domain } : {}),
      ...(o.category ? { "data.cat": o.category } : {}),
      "data.utmaction": blocked ? "block" : "detect",
      "data.level": "warning",
      ...(geoCountry(o.remoteIp) ? { "data.dstcountry": geoCountry(o.remoteIp)! } : {}),
      // shared ECS
      "action": action,
      "action_result": blocked ? "blocked" : "detected",
      "event.action": subtype,
      "event.category": subtype === "webfilter" ? "network" : "intrusion_detection",
      "event.outcome": blocked ? "success" : "failure",
      "source.ip": r.srcIp,
      "destination.ip": o.remoteIp,
      "threat.name": o.threatName,
      ...(o.mitre ? { "threat.technique.id": o.mitre } : {}),
      ...(o.technique ? { "threat.technique.name": o.technique } : {}),
      ...(o.category ? { "threat.category": o.category } : {}),
      ...(o.url ? { "url.full": o.url } : {}),
      ...(o.domain ? { "url.domain": o.domain } : {}),
      ...(geoCountry(o.remoteIp) ? { "destination.geo.country_name": geoCountry(o.remoteIp)! } : {}),
    },
  };
}

// ── SSL-VPN login ─────────────────────────────────────────────────────────────────────
export interface FgVpnOpts extends Ctx {
  remoteIp: string;                // the client's public IP
  assignedIp?: string;             // tunnel IP handed to the client
  outcome?: "success" | "failure";
  tunnelName?: string;
  mitre?: string;
  tactic?: string;
  severity?: Severity;
  description?: string;
}
export function fgVpn(o: FgVpnOpts): TelemetryEvent {
  const r = resolve(o);
  const ok = (o.outcome ?? "success") === "success";
  return {
    id: o.id, ts: o.ts, source: "vpn", vendor: VENDOR,
    event_type: ok ? "vpn_login" : "vpn_failed",
    severity: o.severity ?? (ok ? "medium" : "low"), hostname: r.host, src_ip: o.remoteIp,
    user_email: r.email, mitre_technique: o.mitre, mitre_tactic: o.tactic, incident_id: o.incidentId,
    geo: knownGeoForIp(o.remoteIp) ? { country: knownGeoForIp(o.remoteIp)!.country, city: knownGeoForIp(o.remoteIp)!.city } : undefined,
    authentication: { method: "SSL-VPN", result: ok ? "success" : "failure" },
    description: o.description ?? `FortiGate SSL-VPN ${ok ? "login" : "login FAILED"} for ${r.email ?? r.bareUser} from ${o.remoteIp}`,
    raw: {
      "data.type": "event",
      "data.subtype": "vpn",
      "data.action": ok ? "tunnel-up" : "ssl-login-fail",
      "data.user": r.bareUser,
      "data.remip": o.remoteIp,
      ...(o.assignedIp ? { "data.tunnelip": o.assignedIp } : {}),
      "data.tunneltype": "ssl-web",
      "data.msg": ok ? "SSL tunnel established" : "SSL user failed to authenticate",
      "data.level": ok ? "information" : "warning",
      ...(geoCountry(o.remoteIp) ? { "data.srccountry": geoCountry(o.remoteIp)! } : {}),
      // shared ECS
      "action": ok ? "tunnel-up" : "login-fail",
      "action_result": ok ? "allowed" : "blocked",
      "event.action": "vpn-login",
      "event.category": "authentication",
      "event.outcome": ok ? "success" : "failure",
      "source.ip": o.remoteIp,
      "source.user.name": r.bareUser,
      ...(o.assignedIp ? { "vpn.assigned.ip": o.assignedIp } : {}),
      "vpn.user": r.bareUser,
      "vpn.status": ok ? "up" : "failed",
      ...(geoCountry(o.remoteIp) ? { "source.geo.country_name": geoCountry(o.remoteIp)! } : {}),
    },
  };
}
