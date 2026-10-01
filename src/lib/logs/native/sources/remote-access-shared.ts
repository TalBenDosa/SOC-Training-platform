/**
 * Shared helpers for the remote-access (VPN / ZTNA) and proxy native modules:
 * globalprotect, anyconnect, fortigate_sslvpn, zscaler_zpa, cloudflare_access, zscaler_zia.
 *
 * The platform's VPN corpus was authored for three vendors (GlobalProtect, Cisco
 * AnyConnect, FortiGate SSL-VPN) with legacy raw keys (gp.*, pan.*, cisco.asa.*,
 * data.* …). {@link vpnFacts} reads all of them into one vendor-neutral fact set so
 * every VPN/ZTNA module renders the SAME event (category-wide rendering), and the
 * evidence values (user, public IP, tunnel IP, hosts) survive verbatim.
 *
 * Nothing here emits a field — each module decides which facts its product has.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { NativeCtx } from "../types";

// ── Countries ────────────────────────────────────────────────────────────────

export interface Country {
  iso: string;          // ISO-3166 alpha-2, upper case
  name: string;         // common English name
  fortinet: string;     // FortiOS GeoIP database spelling (srccountry)
  lat: number;
  lon: number;
  zen: string;          // nearest Zscaler Public Service Edge (broker) label
}

const C = (iso: string, name: string, lat: number, lon: number, zen: string, fortinet = name): Country => ({ iso, name, fortinet, lat, lon, zen });

export const COUNTRIES: Country[] = [
  C("IL", "Israel", 32.08, 34.78, "broker2a.tlv1"),
  C("GB", "United Kingdom", 51.51, -0.13, "broker1a.lon3"),
  C("US", "United States", 40.71, -74.01, "broker1a.nyc2"),
  C("NL", "Netherlands", 52.37, 4.89, "broker1b.ams2"),
  C("DE", "Germany", 50.11, 8.68, "broker2b.fra4"),
  C("CH", "Switzerland", 47.37, 8.54, "broker1a.zrh1"),
  C("FR", "France", 48.86, 2.35, "broker1a.cdg1"),
  C("IE", "Ireland", 53.35, -6.26, "broker1a.dub1"),
  C("SG", "Singapore", 1.35, 103.82, "broker1a.sin2"),
  C("NG", "Nigeria", 6.52, 3.38, "broker1a.jnb1"),
  C("RU", "Russia", 55.75, 37.62, "broker2b.fra4", "Russian Federation"),
  C("UA", "Ukraine", 50.45, 30.52, "broker1b.waw1"),
  C("BG", "Bulgaria", 42.70, 23.32, "broker1b.fra4"),
  C("RO", "Romania", 44.43, 26.10, "broker1b.fra4"),
  C("BY", "Belarus", 53.90, 27.57, "broker1b.waw1"),
  C("CN", "China", 39.90, 116.40, "broker1a.hkg1"),
  C("HK", "Hong Kong", 22.32, 114.17, "broker1a.hkg1"),
  C("KP", "North Korea", 39.03, 125.75, "broker1a.hkg1", "Korea, Democratic People's Republic of"),
  C("IR", "Iran", 35.69, 51.39, "broker1a.dxb1", "Iran, Islamic Republic of"),
  C("IN", "India", 19.08, 72.88, "broker1a.bom1"),
  C("BR", "Brazil", -23.55, -46.63, "broker1a.gru1"),
  C("ES", "Spain", 40.42, -3.70, "broker1a.mad1"),
  C("IT", "Italy", 45.46, 9.19, "broker1a.mil1"),
  C("PL", "Poland", 52.23, 21.01, "broker1b.waw1"),
  C("SE", "Sweden", 59.33, 18.07, "broker1a.sto1"),
  C("CA", "Canada", 43.65, -79.38, "broker1a.yyz1"),
  C("AU", "Australia", -33.87, 151.21, "broker1a.syd3"),
  C("JP", "Japan", 35.68, 139.69, "broker1a.tyo1"),
  C("AE", "United Arab Emirates", 25.20, 55.27, "broker1a.dxb1"),
  C("TR", "Turkey", 41.01, 28.98, "broker1b.ist1"),
];

const ALIASES: Record<string, string> = {
  uk: "GB", "great britain": "GB", england: "GB", usa: "US", "united states of america": "US",
  "russian federation": "RU", "the netherlands": "NL", holland: "NL", "korea, democratic people's republic of": "KP",
  "iran, islamic republic of": "IR", uae: "AE",
};

export function countryOf(v: unknown): Country | undefined {
  if (typeof v !== "string" || !v.trim()) return undefined;
  const s = v.trim();
  const up = s.toUpperCase();
  const byIso = COUNTRIES.find(c => c.iso === up);
  if (byIso) return byIso;
  const low = s.toLowerCase();
  const alias = ALIASES[low];
  if (alias) return COUNTRIES.find(c => c.iso === alias);
  return COUNTRIES.find(c => c.name.toLowerCase() === low || c.fortinet.toLowerCase() === low);
}

/** Regions a SOC treats as high-risk for a remote-access login (sanctioned / no business presence / story hot-spots). */
export const HIGH_RISK_ISO = ["RU", "BY", "CN", "KP", "IR", "NG", "SY"];
export const HIGH_RISK_FORTINET = ["Russian Federation", "Belarus", "China", "Korea, Democratic People's Republic of", "Iran, Islamic Republic of", "Nigeria", "Syrian Arab Republic"];

// ── Company constants ────────────────────────────────────────────────────────

const COMPANY: Record<string, { name: string; short: string; home: string; idp: string; prefix: string }> = {
  nexacorp: { name: "NexaCorp Ltd", short: "NXC", home: "GB", idp: "NexaCorp-EntraID", prefix: "NXC" },
  rocketstack: { name: "RocketStack Inc", short: "RKS", home: "US", idp: "RocketStack-Okta", prefix: "RKS" },
  medcore: { name: "MedCore Health", short: "MDC", home: "NL", idp: "MedCore-EntraID", prefix: "MDC" },
  globallogis: { name: "GlobalLogis GmbH", short: "GLG", home: "DE", idp: "GlobalLogis-EntraID", prefix: "GLG" },
  quantumbank: { name: "QuantumBank AG", short: "QB", home: "CH", idp: "QuantumBank-EntraID", prefix: "QB" },
};
export function company(ctx: NativeCtx) {
  return COMPANY[ctx.companyId] ?? { name: ctx.companyId, short: ctx.netbios.slice(0, 3), home: "US", idp: `${ctx.netbios}-EntraID`, prefix: ctx.netbios.slice(0, 3) };
}
export function homeCountry(ctx: NativeCtx): Country {
  return countryOf(company(ctx).home) ?? COUNTRIES[2];
}

// ── IP helpers ───────────────────────────────────────────────────────────────

export function isIPv4(v: unknown): v is string {
  return typeof v === "string" && /^\d{1,3}(\.\d{1,3}){3}$/.test(v);
}
export function isPrivateIp(ip: string): boolean {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.)/.test(ip);
}
/** PAN-OS region name for a private address (srcregion shows the address-range name). */
export function privateRange(ip: string): string {
  if (ip.startsWith("10.")) return "10.0.0.0-10.255.255.255";
  if (ip.startsWith("192.168.")) return "192.168.0.0-192.168.255.255";
  return "172.16.0.0-172.31.255.255";
}

// ── Raw-map access ───────────────────────────────────────────────────────────

export function rawStr(ev: TelemetryEvent, ...keys: string[]): string | undefined {
  const raw = ev.raw ?? {};
  for (const k of keys) {
    const v = (raw as Record<string, unknown>)[k];
    if (v === undefined || v === null) continue;
    const s = String(v).trim();
    if (s !== "" && s !== "N/A") return s;
  }
  return undefined;
}
export function rawNum(ev: TelemetryEvent, ...keys: string[]): number | undefined {
  const s = rawStr(ev, ...keys);
  if (s === undefined) return undefined;
  const n = Number(s);
  return Number.isFinite(n) ? n : undefined;
}

// ── Time formatting (all UTC — devices in this simulation log in UTC) ───────

const MON = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const DOW = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const p2 = (n: number) => String(n).padStart(2, "0");
const p3 = (n: number) => String(n).padStart(3, "0");

export function parts(ms: number) {
  const d = new Date(ms);
  return { Y: d.getUTCFullYear(), M: d.getUTCMonth(), D: d.getUTCDate(), h: d.getUTCHours(), m: d.getUTCMinutes(), s: d.getUTCSeconds(), ms: d.getUTCMilliseconds(), dow: d.getUTCDay() };
}
/** 2026/10/01 08:02:11 (PAN-OS) */
export function panTime(ms: number): string { const t = parts(ms); return `${t.Y}/${p2(t.M + 1)}/${p2(t.D)} ${p2(t.h)}:${p2(t.m)}:${p2(t.s)}`; }
/** 2026-10-01T08:02:11.114+00:00 (PAN-OS high_res_timestamp) */
export function panHiRes(ms: number): string { const t = parts(ms); return `${t.Y}-${p2(t.M + 1)}-${p2(t.D)}T${p2(t.h)}:${p2(t.m)}:${p2(t.s)}.${p3(t.ms)}+00:00`; }
/** Oct  1 08:02:11 (RFC 3164 header) */
export function bsdTime(ms: number): string { const t = parts(ms); return `${MON[t.M]} ${String(t.D).padStart(2, " ")} ${p2(t.h)}:${p2(t.m)}:${p2(t.s)}`; }
/** Oct 01 2026 08:02:10 (ASA `logging timestamp`) */
export function asaTime(ms: number): string { const t = parts(ms); return `${MON[t.M]} ${p2(t.D)} ${t.Y} ${p2(t.h)}:${p2(t.m)}:${p2(t.s)}`; }
/** 2026-10-01 / 08:02:11 */
export function isoDate(ms: number): string { const t = parts(ms); return `${t.Y}-${p2(t.M + 1)}-${p2(t.D)}`; }
export function hms(ms: number): string { const t = parts(ms); return `${p2(t.h)}:${p2(t.m)}:${p2(t.s)}`; }
/** Thu Oct  1 05:02:11 2026 (ctime) */
export function ctime(ms: number): string { const t = parts(ms); return `${DOW[t.dow]} ${MON[t.M]} ${String(t.D).padStart(2, " ")} ${p2(t.h)}:${p2(t.m)}:${p2(t.s)} ${t.Y}`; }
/** 2026-10-01T05:02:09.000Z */
export function isoMs(ms: number): string { return new Date(ms).toISOString(); }
/** 2026-10-01T05:02:11Z */
export function isoSec(ms: number): string { return new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z"); }

export function parseAsaTime(s: string): number {
  const m = /^(\w{3}) (\d{2}) (\d{4}) (\d{2}):(\d{2}):(\d{2})$/.exec(s);
  if (!m) return NaN;
  return Date.UTC(+m[3], MON.indexOf(m[1]), +m[2], +m[4], +m[5], +m[6]);
}

/** "1h:22m:11s" or a seconds count → seconds. */
export function durationSeconds(v: string | undefined): number | undefined {
  if (!v) return undefined;
  const m = /^(\d+)h:(\d+)m:(\d+)s$/.exec(v);
  if (m) return +m[1] * 3600 + +m[2] * 60 + +m[3];
  const n = Number(v);
  return Number.isFinite(n) ? n : undefined;
}
/** seconds → "9h:02m:44s" (ASA 113019 Duration) */
export function asaDuration(sec: number): string {
  const h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60), s = Math.floor(sec % 60);
  return `${h}h:${p2(m)}m:${p2(s)}s`;
}

// ── Deterministic id helpers ─────────────────────────────────────────────────

/** Base64-alphabet id of `len` chars (ZPA SessionID / ConnectionID style). */
export function b64id(ctx: NativeCtx, seed: string, len: number): string {
  const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  const hex = ctx.hex(seed, len * 2);
  let out = "";
  for (let i = 0; i < len; i++) out += A[parseInt(hex.slice(i * 2, i * 2 + 2), 16) % A.length];
  return out;
}
/** A digit string of exactly `len` digits (no leading zero). */
export function digits(ctx: NativeCtx, seed: string, len: number): string {
  let s = "";
  let i = 0;
  while (s.length < len) s += String(ctx.int(`${seed}#${i++}`, 100000000, 999999999));
  return s.slice(0, len);
}
/** A documentation-range (TEST-NET) IPv4, so a filler IP can never be a real host. */
export function testNetIp(ctx: NativeCtx, seed: string): string {
  const nets = ["192.0.2", "198.51.100", "203.0.113"];
  return `${nets[ctx.int(`${seed}:net`, 0, 2)]}.${ctx.int(`${seed}:host`, 10, 250)}`;
}

// ── Identity ─────────────────────────────────────────────────────────────────

export interface Identity { email?: string; sam?: string; display?: string }

export function identity(ev: TelemetryEvent): Identity {
  const candidates = [ev.user_email, ev.user?.email, rawStr(ev, "user.email", "zscaler.login", "cisco.asa.username", "data.user", "gp.user", "source.user.name", "vpn.user", "pan.srcuser")];
  const email = candidates.find(v => typeof v === "string" && v.includes("@"));
  const samRaw = rawStr(ev, "cisco.asa.username", "data.user", "gp.user", "source.user.name", "vpn.user", "zscaler.login", "pan.srcuser");
  const sam = samRaw && !samRaw.includes("@") ? samRaw : email ? email.split("@")[0] : undefined;
  return { email, sam, display: ev.user?.full_name };
}
export function emailDomain(ev: TelemetryEvent, ctx: NativeCtx): string {
  const id = identity(ev);
  return id.email ? id.email.split("@")[1] : ctx.domain;
}

// ── Hosts ────────────────────────────────────────────────────────────────────

const GATEWAY_RE = /^(FG|FGT|PA-|ASA|VPN-GW|vpn-gw|asa-|gw-)/i;
export function isGatewayHost(h: string | undefined): boolean { return !!h && GATEWAY_RE.test(h); }

/** Stable corporate laptop name for a user whose device name the event did not carry. */
export function corpDeviceName(ctx: NativeCtx, user: string): string {
  return `${company(ctx).prefix}-LT-${String(ctx.int(`${ctx.companyId}:laptop:${user}`, 100, 4999)).padStart(4, "0")}`;
}
/** Stable unmanaged Windows default name (DESKTOP-XXXXXXX) for an unknown device. */
export function unmanagedDeviceName(ctx: NativeCtx, seed: string): string {
  return `DESKTOP-${ctx.hex(`${seed}:desktop`, 7).toUpperCase()}`;
}

// ── VPN facts ────────────────────────────────────────────────────────────────

export type VpnPhase = "auth_fail" | "login" | "logout" | "mfa_challenge" | "mfa_denied";

export interface VpnFacts {
  phase: VpnPhase;
  id: Identity;
  /** The username exactly as the authoring vendor printed it (if any). */
  userAsLogged?: string;
  publicIp?: string;
  tunnelIp?: string;
  country?: Country;
  /** Client device. `clientHostKnown` = came from the event (not generated). */
  clientHost?: string;
  clientUnmanaged: boolean;
  /** Firewall / VPN concentrator hostname. */
  gatewayHost?: string;
  gatewayName?: string;
  tunnelGroup?: string;
  groupPolicy?: string;
  clientOs?: string;
  clientVersion?: string;
  authMethod?: string;
  reason?: string;
  durationSec?: number;
  bytesToClient?: number;
  bytesFromClient?: number;
  sessionType?: string;
  asaMessageId?: string;
  fgtLogid?: string;
  fgtTunnelType?: string;
  fgtLevel?: string;
  fgtTunnelId?: number;
  fgtGroup?: string;
  attemptCount?: number;
}

export function vpnPhase(ev: TelemetryEvent): VpnPhase | null {
  const msg = rawStr(ev, "cisco.asa.message_id");
  const fgtAction = rawStr(ev, "data.action", "action");
  switch (ev.event_type) {
    case "vpn_failed": case "auth_failure": return "auth_fail";
    case "mfa_denied": return "mfa_denied";
    case "mfa_challenge": return "mfa_challenge";
    case "vpn_logout": return "logout";
    case "vpn_login":
      if (msg === "113019" || fgtAction === "tunnel-down") return "logout";
      if (msg === "113005" || msg === "113015" || fgtAction === "ssl-login-fail") return "auth_fail";
      return "login";
    default: return null;
  }
}

export function vpnFacts(ev: TelemetryEvent): VpnFacts | null {
  const phase = vpnPhase(ev);
  if (!phase) return null;
  const id = identity(ev);
  const publicIp = [ev.src_ip, rawStr(ev, "source.ip", "gp.srcip", "cisco.asa.public_ip", "data.remip")].find(isIPv4);
  const tunnelIp = [rawStr(ev, "gp.tunnel_ip", "gp.private_ip", "cisco.asa.assigned_ip", "data.tunnelip", "vpn.assigned.ip")].find(isIPv4);
  const country = countryOf(rawStr(ev, "source.geo.country_iso_code")) ?? countryOf(ev.geo?.country) ?? countryOf(rawStr(ev, "source.geo.country_name", "GeoLocation.country_name", "data.srccountry", "geo.country"));
  const rawClient = rawStr(ev, "gp.client_hostname");
  const regRaw = rawStr(ev, "gp.device_registered");
  const unknownRaw = !!rawClient && /^unknown/i.test(rawClient);
  let clientHost = rawClient && !unknownRaw ? rawClient : undefined;
  let gatewayHost = rawStr(ev, "observer.name");
  if (ev.hostname) {
    if (isGatewayHost(ev.hostname)) gatewayHost = gatewayHost ?? ev.hostname;
    else clientHost = clientHost ?? ev.hostname;
  }
  const clientUnmanaged = unknownRaw || regRaw === "false" || (!!clientHost && /^(DESKTOP-|WIN-)/i.test(clientHost));
  return {
    phase,
    id,
    userAsLogged: rawStr(ev, "cisco.asa.username", "data.user", "gp.user", "vpn.user", "source.user.name"),
    publicIp,
    tunnelIp,
    country,
    clientHost,
    clientUnmanaged,
    gatewayHost,
    gatewayName: rawStr(ev, "gp.gateway", "pan.gateway"),
    tunnelGroup: rawStr(ev, "cisco.asa.tunnel_group"),
    groupPolicy: rawStr(ev, "cisco.asa.group_policy"),
    clientOs: rawStr(ev, "gp.client_os", "pan.os", "cisco.asa.client_os", "cisco.asa.client_type"),
    clientVersion: rawStr(ev, "cisco.asa.client_version"),
    authMethod: rawStr(ev, "gp.auth_method", "pan.auth_method", "data.authproto", "cisco.asa.aaa_server_group") ?? ev.authentication?.method,
    reason: rawStr(ev, "cisco.asa.reason", "pan.reason", "gp.disconnect_reason", "data.reason"),
    durationSec: durationSeconds(rawStr(ev, "cisco.asa.duration", "gp.session_duration_sec", "gp.duration", "data.duration")),
    bytesToClient: rawNum(ev, "cisco.asa.bytes_xmt", "gp.bytes_in", "data.sentbyte"),
    bytesFromClient: rawNum(ev, "cisco.asa.bytes_rcv", "data.rcvdbyte"),
    sessionType: rawStr(ev, "cisco.asa.session_type"),
    asaMessageId: rawStr(ev, "cisco.asa.message_id"),
    fgtLogid: rawStr(ev, "data.logid"),
    fgtTunnelType: rawStr(ev, "data.tunneltype"),
    fgtLevel: rawStr(ev, "data.level"),
    fgtTunnelId: rawNum(ev, "data.tunnelid"),
    fgtGroup: rawStr(ev, "data.group"),
    attemptCount: rawNum(ev, "pan.attempt_count"),
  };
}

/** Canonical per-user seed (lower-cased UPN, else sAMAccountName, else client IP) — every module derives the same device ids from it. */
export function userKey(f: VpnFacts): string {
  return (f.id.email ?? f.id.sam ?? f.userAsLogged ?? f.publicIp ?? "unknown").toLowerCase();
}

/** The user string a product shows when it logs the name the user typed (sAMAccountName preferred, else UPN). */
export function typedUser(f: VpnFacts): string | undefined {
  return f.userAsLogged ?? f.id.sam ?? f.id.email;
}

/** Client OS family from an authored OS string. */
export function osFamily(os: string | undefined): "windows" | "mac" | "linux" | "ios" | "android" {
  const s = (os ?? "").toLowerCase();
  if (/mac|os x|darwin/.test(s)) return "mac";
  if (/linux|ubuntu|embedded|debian|rhel/.test(s)) return "linux";
  if (/ios|iphone|ipad/.test(s)) return "ios";
  if (/android/.test(s)) return "android";
  return "windows";
}

/** Deep string search used by the tests (exported so every module's test uses the same notion). */
export function deepStrings(v: unknown, out: string[] = []): string[] {
  if (v === null || v === undefined) return out;
  if (Array.isArray(v)) { for (const x of v) deepStrings(x, out); return out; }
  if (typeof v === "object") { for (const x of Object.values(v as Record<string, unknown>)) deepStrings(x, out); return out; }
  out.push(String(v));
  return out;
}
