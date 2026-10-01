/**
 * Shared, vendor-neutral extraction for the FIREWALL category modules
 * (paloalto / fortigate / checkpoint / cisco_ftd / cisco_asa).
 *
 * Every firewall module renders the SAME connection / URL / threat facts, so a
 * story authored on Palo Alto is shown with identical 5-tuple, NAT, session and
 * policy values on FortiGate, Check Point or Cisco. This file turns one
 * TelemetryEvent (structured fields + the legacy `raw` map of any firewall vendor:
 * `pan.*`, `panw.*`, `data.*` (FortiGate/Wazuh), Check Point legacy keys,
 * `cisco.ftd.*`, ECS-ish `source.ip` …) into {@link FwFacts}. Each module then maps
 * the facts onto its own native field names only.
 *
 * All filler values are deterministic (ctx.hex / ctx.int seeded from the event id,
 * the company or the entity) — never Math.random / Date.now.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { NativeCtx } from "../types";

export type Sev = "informational" | "low" | "medium" | "high" | "critical";
export type Dir = "outbound" | "inbound" | "internal";
/** What kind of firewall record the event is. */
export type FwClass = "traffic" | "url" | "file" | "threat" | "admin";
export type ThreatKind = "c2" | "exploit" | "bruteforce" | "scan" | "sqli";

export interface FwFacts {
  ev: TelemetryEvent;
  timeMs: number;
  companyId: string;
  /** True when the authoring vendor is this module's own product. */
  native: boolean;
  cls: FwClass;
  dir: Dir;
  src: string;
  dst: string;
  sport: number;
  dport: number;
  proto: "tcp" | "udp" | "icmp";
  protoNum: number;
  blocked: boolean;
  /** Session-start record (PAN `start`, FTD 430002 for an allowed connection). */
  startOnly: boolean;
  /** Threat seen but not blocked (alert / detect). */
  detectOnly: boolean;
  /** Canonical application token (see APPS). */
  app: string;
  domain?: string;
  /** URL with scheme (https://host/path?q). */
  url?: string;
  /** host/path?q (no scheme) — PAN `misc` style. */
  urlNoScheme?: string;
  /** Path + query only ("/api/login"). */
  path?: string;
  method?: string;
  userAgent?: string;
  referer?: string;
  /** Canonical URL category (key of CATEGORIES) or undefined when no web lookup. */
  category?: string;
  /** Raw authored PAN slug kept when it is not in our table. */
  categoryPanRaw?: string;
  bytesOut: number;
  bytesIn: number;
  pktsOut: number;
  pktsIn: number;
  elapsed: number;
  /** Authored rule / policy name (verbatim) or a neutral default. */
  rule: string;
  ruleAuthored: boolean;
  user?: { sam: string; email?: string; panUser?: string };
  host?: { name: string; role: "src" | "dst" | "device" };
  srcCountry?: string;
  dstCountry?: string;
  threat?: { name: string; id?: string; kind: ThreatKind; severity: Sev; cve?: string; catRaw?: string };
  file?: { name: string; sha256?: string; ext?: string; size?: number };
  /** Cisco Security-Intelligence style feed category (TOR, scanners …). */
  siCategory?: string;
  /** Authored native session id when the story correlates start/end records. */
  sessionIdAuthored?: string;
  severity: Sev;
}

// ── raw helpers ──────────────────────────────────────────────────────────────
const s = (v: unknown): string | undefined => {
  if (v === undefined || v === null) return undefined;
  const t = String(v).trim();
  return t === "" ? undefined : t;
};
export function rawGet(raw: Record<string, unknown> | undefined, ...keys: string[]): string | undefined {
  if (!raw) return undefined;
  for (const k of keys) { const v = s(raw[k]); if (v !== undefined) return v; }
  return undefined;
}
const n = (v: string | number | undefined): number | undefined => {
  if (v === undefined) return undefined;
  const x = typeof v === "number" ? v : Number(String(v).replace(/^SID:/i, ""));
  return Number.isFinite(x) ? x : undefined;
};

// ── IP helpers ───────────────────────────────────────────────────────────────
export function isIp(v: string | undefined): v is string { return !!v && /^\d{1,3}(\.\d{1,3}){3}$/.test(v); }
export function isPrivate(ip: string): boolean {
  const p = ip.split(".").map(Number);
  return p[0] === 10 || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 192 && p[1] === 168) ||
    (p[0] === 100 && p[1] >= 64 && p[1] <= 127) || p[0] === 127 || p[0] >= 224;
}
/** PAN `srcloc`/`dstloc` label for private ranges. */
export function panPrivateLabel(ip: string): string | undefined {
  const p = ip.split(".").map(Number);
  if (p[0] === 10) return "10.0.0.0-10.255.255.255";
  if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return "172.16.0.0-172.31.255.255";
  if (p[0] === 192 && p[1] === 168) return "192.168.0.0-192.168.255.255";
  return undefined;
}

const CO_PREFIX: Record<string, string> = { nexacorp: "10.10", rocketstack: "172.16", medcore: "192.168", globallogis: "10.50", quantumbank: "10.100" };
const PUB_FIRST = [62, 77, 82, 109, 145, 176, 212, 213, 217];
const EXT_FIRST = [23, 34, 45, 46, 51, 64, 66, 81, 89, 94, 103, 104, 107, 141, 146, 149, 151, 159, 162, 167, 178, 188, 193, 194, 195, 198, 199, 206, 209];

/** The company's SNAT / hide-NAT egress address (stable per company). */
export function egressIp(ctx: NativeCtx): string {
  const k = `${ctx.companyId}:egress`;
  return `${PUB_FIRST[ctx.int(k, 0, PUB_FIRST.length - 1)]}.${ctx.int(k + "b", 1, 254)}.${ctx.int(k + "c", 1, 254)}.10`;
}
/** A published (public) address of the company — used only when the authored event lacks a destination. */
export function companyVip(ctx: NativeCtx, seed: string): string {
  const e = egressIp(ctx).split(".");
  return `${e[0]}.${e[1]}.${e[2]}.${ctx.int(`${ctx.companyId}:vip:${seed}`, 20, 60)}`;
}
/** Stable internal address for a hostname (destination given only by name). */
export function internalIpFor(ctx: NativeCtx, host: string): string {
  const pre = CO_PREFIX[ctx.companyId] ?? "10.20";
  const k = `${ctx.companyId}:host:${host.toLowerCase()}`;
  return pre.split(".").length === 2 ? `${pre}.${ctx.int(k, 1, 254)}.${ctx.int(k + "d", 2, 254)}` : `${pre}.${ctx.int(k, 2, 254)}`;
}
/** Stable public address for a domain whose IP the authored event omits. */
export function publicIpForDomain(ctx: NativeCtx, domain: string): string {
  const k = `dom:${domain.toLowerCase()}`;
  return `${EXT_FIRST[ctx.int(k, 0, EXT_FIRST.length - 1)]}.${ctx.int(k + "b", 0, 255)}.${ctx.int(k + "c", 0, 255)}.${ctx.int(k + "d", 1, 254)}`;
}

// ── countries ────────────────────────────────────────────────────────────────
const ISO: Record<string, string> = {
  FI: "Finland", RO: "Romania", UA: "Ukraine", DE: "Germany", NL: "Netherlands", RU: "Russian Federation", CN: "China",
  US: "United States", IR: "Iran", KP: "North Korea", GB: "United Kingdom", FR: "France", CA: "Canada", IL: "Israel",
  SE: "Sweden", CH: "Switzerland", BG: "Bulgaria", MD: "Moldova", HK: "Hong Kong", SG: "Singapore", IN: "India",
  BR: "Brazil", PL: "Poland", LT: "Lithuania", LV: "Latvia", SC: "Seychelles", PA: "Panama", BY: "Belarus",
  KZ: "Kazakhstan", TR: "Turkey", VN: "Vietnam", NZ: "New Zealand",
};
export function normCountry(v: string | undefined): string | undefined {
  if (!v) return undefined;
  if (/^[A-Z]{2}$/.test(v)) return ISO[v] ?? v;
  if (/^russia$/i.test(v)) return "Russian Federation";
  if (/^reserved$/i.test(v)) return undefined;
  return v;
}
/** Countries the use cases treat as high-risk destinations / sources. */
export const HIGH_RISK_COUNTRIES = ["Russian Federation", "Iran", "North Korea", "Belarus", "China"];

// ── categories (canonical key = PAN-DB slug) ─────────────────────────────────
export interface CatMap { pan: string; fgtCat: number; fgtDesc: string; cp: string; talos: string; risky: boolean }
export const CATEGORIES: Record<string, CatMap> = {
  "newly-registered-domain": { pan: "newly-registered-domain", fgtCat: 91, fgtDesc: "Newly Registered Domain", cp: "Uncategorized", talos: "Newly Seen Domains", risky: true },
  "newly-observed-domain": { pan: "unknown", fgtCat: 90, fgtDesc: "Newly Observed Domain", cp: "Uncategorized", talos: "Newly Seen Domains", risky: true },
  unknown: { pan: "unknown", fgtCat: 0, fgtDesc: "Unrated", cp: "Uncategorized", talos: "Uncategorized", risky: true },
  malware: { pan: "malware", fgtCat: 26, fgtDesc: "Malicious Websites", cp: "Spyware / Malicious Sites", talos: "Malware Sites", risky: true },
  "command-and-control": { pan: "command-and-control", fgtCat: 26, fgtDesc: "Malicious Websites", cp: "Botnets", talos: "Malware Sites", risky: true },
  phishing: { pan: "phishing", fgtCat: 61, fgtDesc: "Phishing", cp: "Phishing", talos: "Phishing", risky: true },
  "dynamic-dns": { pan: "dynamic-dns", fgtCat: 88, fgtDesc: "Dynamic DNS", cp: "Dynamic DNS", talos: "Dynamic and Residential", risky: true },
  "online-storage-and-backup": { pan: "online-storage-and-backup", fgtCat: 24, fgtDesc: "File Sharing and Storage", cp: "File Storage and Sharing", talos: "Online Storage and Backup", risky: false },
  "computer-and-internet-info": { pan: "computer-and-internet-info", fgtCat: 52, fgtDesc: "Information Technology", cp: "Computers / Internet", talos: "Computers and Internet", risky: false },
  "business-and-economy": { pan: "business-and-economy", fgtCat: 49, fgtDesc: "Business", cp: "Business / Economy", talos: "Business and Industry", risky: false },
  "shareware-and-freeware": { pan: "shareware-and-freeware", fgtCat: 19, fgtDesc: "Freeware and Software Downloads", cp: "Software Downloads", talos: "Freeware and Shareware", risky: false },
  "content-delivery-networks": { pan: "content-delivery-networks", fgtCat: 82, fgtDesc: "Content Servers", cp: "Computers / Internet", talos: "Infrastructure and Content Delivery Networks", risky: false },
  "financial-services": { pan: "financial-services", fgtCat: 31, fgtDesc: "Finance and Banking", cp: "Financial Services", talos: "Finance", risky: false },
  "social-networking": { pan: "social-networking", fgtCat: 37, fgtDesc: "Social Networking", cp: "Social Networking", talos: "Social Networking", risky: false },
  "internet-communications-and-telephony": { pan: "internet-communications-and-telephony", fgtCat: 95, fgtDesc: "Online Meeting", cp: "Computers / Internet", talos: "Online Meetings", risky: false },
  "search-engines": { pan: "search-engines", fgtCat: 41, fgtDesc: "Search Engines and Portals", cp: "Search Engines / Portals", talos: "Search Engines and Portals", risky: false },
};
const CAT_ALIASES: Record<string, string> = {
  "unknown/uncategorized": "unknown", uncategorized: "unknown", unrated: "unknown", "newly observed domain": "newly-observed-domain",
  "newly registered domain": "newly-registered-domain", "newly seen domains": "newly-registered-domain", "malicious websites": "malware",
  "malware sites": "malware", "spyware / malicious sites": "malware", "shareware-download": "shareware-and-freeware",
  "file storage and sharing": "online-storage-and-backup", "file sharing and storage": "online-storage-and-backup", botnets: "command-and-control",
};
function canonCategory(v: string | undefined): { key?: string; panRaw?: string } {
  if (!v) return {};
  const l = v.toLowerCase();
  if (CAT_ALIASES[l]) return { key: CAT_ALIASES[l] };
  if (CATEGORIES[l]) return { key: l };
  if (/^[a-z0-9-]+$/.test(l)) return { panRaw: l };
  return {};
}
const PAN_THREAT_CATS = new Set(["brute-force", "code-execution", "command-and-control", "spyware", "backdoor", "info-leak", "sql-injection", "dns-c2", "scan"]);

function defaultCategory(domain: string): string {
  const d = domain.toLowerCase();
  if (/mega\.(co\.nz|nz|io)$|drive\.google|dropbox|wetransfer|blob\.core\.windows\.net$/.test(d)) return "online-storage-and-backup";
  if (/linkedin|facebook|twitter|instagram/.test(d)) return "social-networking";
  if (/zoom(gov)?\.(us|com)$|webex/.test(d)) return "internet-communications-and-telephony";
  if (/(^|\.)google\.com$|bing\.com$/.test(d)) return "search-engines";
  if (/slack/.test(d)) return "business-and-economy";
  return "computer-and-internet-info";
}

// ── applications ─────────────────────────────────────────────────────────────
export interface AppMap { pan: string; fgt: string; fgtCat: string; ftdProto: string; ftdWebApp?: string; cpApp?: string; cpCat?: string; port: number; transport: "tcp" | "udp" }
export const APPS: Record<string, AppMap> = {
  ssl: { pan: "ssl", fgt: "SSL_TLSv1.3", fgtCat: "Network.Service", ftdProto: "HTTPS", port: 443, transport: "tcp" },
  "web-browsing": { pan: "web-browsing", fgt: "HTTP.BROWSER", fgtCat: "Web.Client", ftdProto: "HTTP", port: 80, transport: "tcp" },
  websocket: { pan: "websocket", fgt: "WebSocket", fgtCat: "Web.Client", ftdProto: "HTTPS", port: 443, transport: "tcp" },
  mega: { pan: "mega", fgt: "MEGA", fgtCat: "Storage.Backup", ftdProto: "HTTPS", ftdWebApp: "MEGA", cpApp: "MEGA", cpCat: "File Storage and Sharing", port: 443, transport: "tcp" },
  smb: { pan: "ms-ds-smb", fgt: "SMB", fgtCat: "Network.Service", ftdProto: "SMB", port: 445, transport: "tcp" },
  msrpc: { pan: "msrpc-base", fgt: "MS.RPC", fgtCat: "Network.Service", ftdProto: "DCE/RPC", port: 135, transport: "tcp" },
  ssh: { pan: "ssh", fgt: "SSH", fgtCat: "Network.Service", ftdProto: "SSH", port: 22, transport: "tcp" },
  rdp: { pan: "ms-rdp", fgt: "RDP", fgtCat: "Remote.Access", ftdProto: "RDP", port: 3389, transport: "tcp" },
  dns: { pan: "dns", fgt: "DNS", fgtCat: "Network.Service", ftdProto: "DNS", port: 53, transport: "udp" },
  ftp: { pan: "ftp", fgt: "FTP", fgtCat: "Network.Service", ftdProto: "FTP", port: 21, transport: "tcp" },
  postgres: { pan: "postgres", fgt: "PostgreSQL", fgtCat: "Business", ftdProto: "PostgreSQL", port: 5432, transport: "tcp" },
  llmnr: { pan: "llmnr", fgt: "LLMNR", fgtCat: "Network.Service", ftdProto: "LLMNR", port: 5355, transport: "udp" },
  kerberos: { pan: "kerberos", fgt: "Kerberos", fgtCat: "Network.Service", ftdProto: "Kerberos", port: 88, transport: "udp" },
  "ms-adfs": { pan: "ms-adfs", fgt: "Microsoft.ADFS", fgtCat: "Collaboration", ftdProto: "HTTPS", ftdWebApp: "Microsoft ADFS", port: 443, transport: "tcp" },
  office365: { pan: "office365-enterprise-access", fgt: "Microsoft.Office.365", fgtCat: "Collaboration", ftdProto: "HTTPS", ftdWebApp: "Office 365", cpApp: "Office365", cpCat: "Business Applications", port: 443, transport: "tcp" },
  teams: { pan: "ms-teams", fgt: "Microsoft.Teams", fgtCat: "Collaboration", ftdProto: "HTTPS", ftdWebApp: "Microsoft Teams", cpApp: "Microsoft Teams", cpCat: "Business Applications", port: 443, transport: "tcp" },
  github: { pan: "github", fgt: "GitHub", fgtCat: "Collaboration", ftdProto: "HTTPS", ftdWebApp: "GitHub", cpApp: "GitHub", cpCat: "Software Development", port: 443, transport: "tcp" },
  zoom: { pan: "zoom", fgt: "Zoom", fgtCat: "Collaboration", ftdProto: "HTTPS", ftdWebApp: "Zoom", cpApp: "Zoom", cpCat: "Business Applications", port: 443, transport: "tcp" },
  slack: { pan: "slack-base", fgt: "Slack", fgtCat: "Collaboration", ftdProto: "HTTPS", ftdWebApp: "Slack", cpApp: "Slack", cpCat: "Business Applications", port: 443, transport: "tcp" },
  linkedin: { pan: "linkedin-base", fgt: "LinkedIn", fgtCat: "Social.Media", ftdProto: "HTTPS", ftdWebApp: "LinkedIn", cpApp: "LinkedIn", cpCat: "Social Networking", port: 443, transport: "tcp" },
  "google-drive": { pan: "google-drive-web", fgt: "Google.Drive", fgtCat: "Storage.Backup", ftdProto: "HTTPS", ftdWebApp: "Google Drive", cpApp: "Google Drive", cpCat: "File Storage and Sharing", port: 443, transport: "tcp" },
  docker: { pan: "docker-hub", fgt: "Docker.Hub", fgtCat: "Cloud.IT", ftdProto: "HTTPS", ftdWebApp: "Docker Hub", port: 443, transport: "tcp" },
  azure: { pan: "ms-azure", fgt: "Microsoft.Azure", fgtCat: "Cloud.IT", ftdProto: "HTTPS", ftdWebApp: "Microsoft Azure", cpApp: "Microsoft Azure", cpCat: "Cloud Services", port: 443, transport: "tcp" },
  bloomberg: { pan: "bloomberg", fgt: "Bloomberg", fgtCat: "Business", ftdProto: "HTTPS", ftdWebApp: "Bloomberg", port: 443, transport: "tcp" },
  sap: { pan: "sap", fgt: "SAP", fgtCat: "Business", ftdProto: "HTTPS", ftdWebApp: "SAP", port: 443, transport: "tcp" },
  doh: { pan: "dns-over-https", fgt: "DNS.over.HTTPS", fgtCat: "Network.Service", ftdProto: "HTTPS", port: 443, transport: "tcp" },
  "unknown-tcp": { pan: "unknown-tcp", fgt: "unknown", fgtCat: "unscanned", ftdProto: "", port: 0, transport: "tcp" },
  "unknown-udp": { pan: "unknown-udp", fgt: "unknown", fgtCat: "unscanned", ftdProto: "", port: 0, transport: "udp" },
};
function canonApp(v: string | undefined): string | undefined {
  if (!v) return undefined;
  const l = v.toLowerCase();
  const table: [RegExp, string][] = [
    [/^(https|ssl|tls|ssl_tlsv1\.\d)$/, "ssl"], [/^(http|web-browsing)$/, "web-browsing"], [/websocket/, "websocket"], [/^mega$/, "mega"],
    [/^(smb|microsoft-ds|ms-ds-smb)$/, "smb"], [/msrpc|ms\.rpc|dce/, "msrpc"], [/^(ssh|sftp)$/, "ssh"], [/^(rdp|ms-rdp)$/, "rdp"],
    [/^dns$/, "dns"], [/^ftp$/, "ftp"], [/postgres|pgsql/, "postgres"], [/llmnr/, "llmnr"], [/kerberos/, "kerberos"], [/adfs/, "ms-adfs"],
    [/office.?365/, "office365"], [/teams/, "teams"], [/github/, "github"], [/zoom/, "zoom"], [/slack/, "slack"], [/linkedin/, "linkedin"],
    [/google-drive/, "google-drive"], [/docker/, "docker"], [/azure/, "azure"], [/bloomberg/, "bloomberg"], [/sap/, "sap"], [/dns.over.https/, "doh"],
    [/^(unknown|unknown-tcp)$/, "unknown-tcp"], [/^unknown-udp$/, "unknown-udp"],
  ];
  for (const [re, k] of table) if (re.test(l)) return k;
  return undefined;
}
function appFromPort(port: number, proto: string): string {
  const byPort: Record<number, string> = { 443: "ssl", 8443: "ssl", 80: "web-browsing", 8080: "web-browsing", 445: "smb", 135: "msrpc", 22: "ssh", 3389: "rdp", 53: "dns", 21: "ftp", 5432: "postgres", 5355: "llmnr", 88: "kerberos" };
  return byPort[port] ?? (proto === "udp" ? "unknown-udp" : "unknown-tcp");
}
/** Service name by destination port, per vendor dialect. */
export function serviceName(port: number, proto: string, dialect: "fgt" | "cp"): string | undefined {
  const fgt: Record<number, string> = { 443: "HTTPS", 80: "HTTP", 22: "SSH", 3389: "RDP", 445: "SMB", 53: "DNS", 21: "FTP", 25: "SMTP", 135: "DCE-RPC", 88: "KERBEROS", 389: "LDAP" };
  const cp: Record<number, string> = { 443: "https", 80: "http", 22: "ssh_version_2", 3389: "Remote_Desktop_Protocol", 445: "microsoft-ds", 21: "ftp", 25: "smtp", 135: "ALL_DCE_RPC", 389: "ldap", 8080: "webcache", 5432: "postgres" };
  if (dialect === "fgt") return fgt[port] ?? `${proto}/${port}`;
  if (port === 53) return proto === "udp" ? "domain-udp" : "domain-tcp";
  return cp[port];
}

// ── severity ─────────────────────────────────────────────────────────────────
export function normSev(v: string | undefined): Sev | undefined {
  if (!v) return undefined;
  const l = v.toLowerCase();
  if (/^crit/.test(l) || l === "4") return "critical";
  if (/^high/.test(l) || l === "3") return "high";
  if (/^med/.test(l) || l === "2") return "medium";
  if (/^low/.test(l) || l === "1") return "low";
  if (/^info/.test(l) || l === "0") return "informational";
  return undefined;
}

// ── formatting ───────────────────────────────────────────────────────────────
const p2 = (x: number) => String(x).padStart(2, "0");
const MON = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
/** Firewalls in this platform run on UTC (a common, legitimate device setting). */
export function ymdSlash(ms: number): string { const d = new Date(ms); return `${d.getUTCFullYear()}/${p2(d.getUTCMonth() + 1)}/${p2(d.getUTCDate())} ${p2(d.getUTCHours())}:${p2(d.getUTCMinutes())}:${p2(d.getUTCSeconds())}`; }
export function ymdDash(ms: number): string { const d = new Date(ms); return `${d.getUTCFullYear()}-${p2(d.getUTCMonth() + 1)}-${p2(d.getUTCDate())}`; }
export function hms(ms: number): string { const d = new Date(ms); return `${p2(d.getUTCHours())}:${p2(d.getUTCMinutes())}:${p2(d.getUTCSeconds())}`; }
export function bsdHeaderTime(ms: number): string { const d = new Date(ms); return `${MON[d.getUTCMonth()]} ${p2(d.getUTCDate())} ${hms(ms)}`; }
export function asaTime(ms: number): string { const d = new Date(ms); return `${MON[d.getUTCMonth()]} ${p2(d.getUTCDate())} ${d.getUTCFullYear()} ${hms(ms)}`; }
export function isoZ(ms: number): string { return new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z"); }
export function isoMsOffset(ms: number): string { return new Date(ms).toISOString().replace("Z", "+00:00"); }
export function hmsDuration(sec: number): string { const h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60), x = sec % 60; return `${h}:${p2(m)}:${p2(x)}`; }
export const pkts = (bytes: number) => (bytes <= 0 ? 0 : Math.max(1, Math.round(bytes / 1180)));

// ── classification helpers ───────────────────────────────────────────────────
const BLOCK_RE = /^(deny|denied|drop|dropped|block|blocked|block-url|block-ip|reset|reset-both|reset-client|reset-server|reject|prevent|sinkhole|ids_block)$/i;
const FW_HOST_RE = /^(fgt|fg|pa|asa|ftd|cp|gw)[-_]/i;

function threatKindOf(name: string, cat: string | undefined, dir: Dir): ThreatKind {
  const t = `${name} ${cat ?? ""}`;
  if (/sql/i.test(t)) return "sqli";
  if (/brute|stuffing|password|login/i.test(t)) return "bruteforce";
  if (/scan|nmap|probe|recon/i.test(t)) return "scan";
  if (/c2|cobalt|command|cnc|c&c|beacon|botnet|backdoor|trojan|mule|fraud|spyware|tunnel/i.test(t)) return "c2";
  return dir === "outbound" ? "c2" : "exploit";
}
function defaultThreatName(kind: ThreatKind, catRaw?: string): string {
  switch (kind) {
    case "bruteforce": return "Brute Force Login Attempt";
    case "scan": return "Port Scan Detected";
    case "sqli": return "SQL Injection Attempt";
    case "c2": return catRaw && /tunnel/i.test(catRaw) ? "Suspicious DNS Tunneling" : "Generic Command and Control Traffic";
    default: return "Generic Exploit Attempt";
  }
}
function schemeFor(port: number): "https" | "http" { return port === 80 || port === 8080 ? "http" : "https"; }

/**
 * Extract the vendor-neutral firewall facts. Returns null for events that no
 * firewall records (e.g. passive NSM sensors such as Zeek/Corelight: their
 * Kerberos/SMB records describe intra-segment traffic the firewall never sees).
 */
export function extractFacts(ev: TelemetryEvent, ctx: NativeCtx, vendorMatch: string[]): FwFacts | null {
  const raw = (ev.raw ?? {}) as Record<string, unknown>;
  const vendor = (ev.vendor ?? "").toLowerCase();
  if (/zeek|corelight|suricata|snort sensor/.test(vendor)) return null;
  const native = vendorMatch.some(v => vendor.includes(v));
  const timeMs = Date.parse(ev.ts);

  // ── 5-tuple ──
  let src = ev.src_ip ?? rawGet(raw, "source.ip", "pan.src", "data.srcip", "src", "id.orig_h");
  let dst = ev.dst_ip ?? rawGet(raw, "destination.ip", "pan.dst", "data.dstip", "dst", "id.resp_h");
  const dstName = rawGet(raw, "destination.address");
  // domain / URL
  const panUrl = rawGet(raw, "pan.url");
  const dataUrl = rawGet(raw, "data.url");
  const hostHint = rawGet(raw, "url.domain", "dns.query_domain", "destination.host", "data.hostname");
  let domain = ev.network?.domain ?? ev.dns?.query ?? hostHint;
  if (!domain && panUrl) domain = panUrl.split("/")[0];
  let dport = ev.dst_port ?? n(rawGet(raw, "destination.port", "pan.dport", "data.dstport", "svc", "service", "id.resp_p"));
  const protoRaw = (ev.protocol ?? rawGet(raw, "network.transport", "data.proto", "proto", "protocol") ?? "").toLowerCase();
  const appRawStr = rawGet(raw, "pan.app", "application", "network.application", "data.app", "app_name", "cisco.ftd.application_protocol", "network.protocol");
  let app = canonApp(appRawStr) ?? (ev.protocol && /^https?$/i.test(ev.protocol) ? canonApp(ev.protocol) : undefined);
  if (!dport) dport = app && APPS[app]?.port ? APPS[app].port : 443;
  let proto: "tcp" | "udp" | "icmp" = protoRaw === "17" || protoRaw === "udp" ? "udp" : protoRaw === "1" || protoRaw === "icmp" ? "icmp" : protoRaw === "" ? (app && APPS[app]?.transport === "udp" ? "udp" : [53, 5355, 123, 161, 514].includes(dport) ? "udp" : "tcp") : "tcp";
  if (!app) app = appFromPort(dport, proto);
  if (proto === "tcp" && APPS[app]?.transport === "udp" && protoRaw === "") proto = "udp";

  if (!isIp(src)) src = undefined;
  if (!isIp(dst)) dst = undefined;
  // Missing destination: derive deterministically (never evidence — the authored event had none).
  if (!dst) {
    if (dstName) dst = internalIpFor(ctx, dstName);
    else if (domain) dst = publicIpForDomain(ctx, domain);
    else if (src && !isPrivate(src)) dst = companyVip(ctx, ev.hostname ?? String(dport));
    else dst = publicIpForDomain(ctx, `${ev.id}`);
  }
  if (!src) src = ev.hostname ? internalIpFor(ctx, ev.hostname) : internalIpFor(ctx, ev.id);
  const sPriv = isPrivate(src), dPriv = isPrivate(dst);
  const dir: Dir = sPriv && !dPriv ? "outbound" : !sPriv ? "inbound" : "internal";
  const sport = ev.src_port ?? n(rawGet(raw, "source.port", "pan.sport", "data.srcport", "sport_svc", "s_port", "id.orig_p")) ?? ctx.int(`${ev.id}:sport`, 49152, 65535);

  // URL normalisation
  let url = ev.network?.url;
  let urlNoScheme: string | undefined, path: string | undefined;
  if (!url && rawGet(raw, "url.full")) url = rawGet(raw, "url.full");
  if (!url && panUrl) url = `${schemeFor(dport)}://${panUrl}`;
  if (!url && dataUrl) url = dataUrl.startsWith("/") ? (domain ? `${schemeFor(dport)}://${domain}${dataUrl}` : undefined) : /^[a-z]+:\/\//i.test(dataUrl) ? dataUrl : `${schemeFor(dport)}://${dataUrl}`;
  if (!url && rawGet(raw, "url.path")) url = `${schemeFor(dport)}://${domain ?? dst}${rawGet(raw, "url.path")}`;
  if (url && !/^[a-z]+:\/\//i.test(url)) url = `${schemeFor(dport)}://${url}`;
  if (url) {
    const m = /^[a-z]+:\/\/([^/?#]+)(.*)$/i.exec(url);
    if (m) { if (!domain && !isIp(m[1])) domain = m[1]; path = m[2] || "/"; urlNoScheme = `${m[1]}${m[2] || "/"}`; }
  }
  if (!path && rawGet(raw, "url.path")) path = rawGet(raw, "url.path");

  const method = (ev.network?.method ?? rawGet(raw, "http.request.method", "pan.http_method") ?? (rawGet(raw, "data.method") !== "domain" ? rawGet(raw, "data.method") : undefined))?.toUpperCase();
  const userAgent = ev.network?.user_agent ?? rawGet(raw, "data.agent", "user_agent");
  const referer = rawGet(raw, "pan.referer", "data.referralurl", "referrer");

  // ── verdict ──
  const actRaw = rawGet(raw, "pan.action", "data.action", "action", "cisco.ftd.action", "panw.action", "firewall.action", "event.action", "action_result", "event.action_result");
  const resultRaw = rawGet(raw, "action_result", "event.action_result", "event.outcome");
  const blocked = ["net_blocked", "http_blocked", "ids_blocked"].includes(ev.event_type) ||
    (actRaw !== undefined && BLOCK_RE.test(actRaw)) || (resultRaw !== undefined && /^block/i.test(resultRaw));
  const startOnly = rawGet(raw, "pan.subtype") === "start";

  // ── threat ──
  const thName = rawGet(raw, "pan.threat_name", "threat.name", "ids.signature_name", "data.attack", "protection_name");
  const thId = rawGet(raw, "pan.threat_id", "panw.threatid", "ids.signature_id", "data.attackid")?.replace(/^SID:/i, "");
  const panCat = rawGet(raw, "pan.category");
  const thCatRaw = rawGet(raw, "pan.threat_category", "ids.category", "panw.category", "threat.category", "protection_type") ?? (panCat && PAN_THREAT_CATS.has(panCat) ? panCat : undefined);
  const thSev = normSev(rawGet(raw, "pan.severity", "pan.threat_severity", "threat.severity", "ids.severity", "data.severity", "severity"));
  const isThreat = ev.event_type === "ids_signature" || ev.event_type === "ids_blocked" || !!thName || !!thId;
  const evSev: Sev = (ev.severity as Sev) ?? "informational";

  // ── file ──
  const fName = ev.file?.name ?? rawGet(raw, "pan.filename", "data.filename");
  const fHash = ev.file?.sha256 ?? rawGet(raw, "pan.file_hash", "threat.file.hash.sha256", "file.hash.sha256");
  const file = fName ? { name: fName, sha256: fHash, ext: (ev.file?.extension ?? fName.split(".").pop() ?? "").toLowerCase(), size: ev.file?.size } : undefined;

  // ── class ──
  let cls: FwClass;
  const rawPanType = rawGet(raw, "pan.type"), rawPanSub = rawGet(raw, "pan.subtype");
  const bytesOutRaw = ev.network?.bytes_out ?? n(rawGet(raw, "network.bytes_out", "pan.bytes_sent", "data.sentbyte", "cisco.ftd.initiator_bytes", "bytes_out", "client_outbound_bytes"));
  const webPort = [80, 443, 8080, 8443].includes(dport);
  if (isThreat) cls = "threat";
  else if (file && (ev.event_type === "http_request" || ev.event_type === "file_create")) cls = "file";
  else if (rawPanType === "THREAT" && rawPanSub === "url") cls = "url";
  else if (dir === "outbound" && (ev.event_type === "http_request" || ev.event_type === "http_blocked") && (url || domain)) cls = "url";
  else if (dir === "outbound" && ev.event_type === "net_connection" && domain && webPort && !startOnly && (bytesOutRaw ?? 0) < 10 * 1024 * 1024 && rawPanType !== "TRAFFIC" && !rawGet(raw, "data.type")) cls = "url";
  else cls = "traffic";
  if (["auth_success", "auth_failure"].includes(ev.event_type)) cls = "admin";

  // ── category ──
  let category: string | undefined, categoryPanRaw: string | undefined;
  const catSrc = rawGet(raw, "data.catdesc") ?? (panCat && !PAN_THREAT_CATS.has(panCat) && panCat !== "any" ? panCat : undefined) ?? rawGet(raw, "url.category", "app_category", "cisco.ftd.url_category");
  const cc = canonCategory(catSrc);
  category = cc.key; categoryPanRaw = cc.panRaw;
  if (!category && !categoryPanRaw && rawGet(raw, "data.cat")) {
    const c = Number(rawGet(raw, "data.cat"));
    category = Object.entries(CATEGORIES).find(([, m]) => m.fgtCat === c)?.[0];
  }
  const age = n(rawGet(raw, "domain.registration_age_days"));
  const ageInDesc = /registered\s+(\d+|one|two|three|four|five|six|seven|a few)\s+days?\s+ago/i.test(ev.description ?? "");
  if ((!category || category === "unknown") && !categoryPanRaw && ((age !== undefined && age <= 30) || ageInDesc)) category = "newly-registered-domain";
  if (!category && !categoryPanRaw && /newly[- ]observed/i.test(ev.description ?? "")) category = "newly-observed-domain";
  if (!category && !categoryPanRaw && domain) category = defaultCategory(domain);
  if (!category && !categoryPanRaw && rawGet(raw, "threat.category") === "CommandAndControl" && domain) category = "unknown";

  // ── counters ──
  let bytesOut = bytesOutRaw;
  let bytesIn = ev.network?.bytes_in ?? n(rawGet(raw, "network.bytes_in", "pan.bytes_received", "data.rcvdbyte", "cisco.ftd.responder_bytes", "client_inbound_bytes"));
  const cpTotal = n(rawGet(raw, "bytes", "network.bytes"));
  if (cpTotal !== undefined) {
    if (bytesOut !== undefined && bytesIn === undefined) bytesIn = cpTotal;
    else if (bytesOut === undefined && bytesIn === undefined) { bytesOut = Math.round(cpTotal * 0.1); bytesIn = cpTotal - bytesOut; }
  }
  if (blocked && cls !== "url") { bytesOut = bytesOut && bytesOut > 0 ? bytesOut : 0; bytesIn = bytesIn ?? 0; }
  if (bytesOut === undefined) bytesOut = blocked ? ctx.int(`${ev.id}:bo`, 300, 900) : startOnly ? ctx.int(`${ev.id}:bo`, 200, 700) : ctx.int(`${ev.id}:bo`, 600, 9000);
  if (bytesIn === undefined) bytesIn = blocked ? 0 : startOnly ? ctx.int(`${ev.id}:bi`, 0, 600) : ctx.int(`${ev.id}:bi`, 900, 60000);
  const elapsed = n(rawGet(raw, "pan.elapsed_time", "pan.elapsed", "data.duration", "cisco.ftd.connection_duration", "duration", "elapsed")) ?? (blocked || startOnly ? 0 : ctx.int(`${ev.id}:el`, 0, 30));

  // ── rule ──
  const ruleAuth = rawGet(raw, "pan.rule", "panw.rule", "pan.rulename", "rule.name", "data.policyname", "rule_name", "cisco.ftd.rule_name", "cisco.ftd.access_control_rule_name");
  const rule = ruleAuth ?? (cls === "url" && blocked ? "Block-Risky-URL-Categories"
    : blocked ? (dir === "inbound" ? "Block-Inbound-Default" : "Block-Outbound-Default")
    : dir === "inbound" ? "Allow-Inbound-Published" : dir === "internal" ? "Allow-Internal" : "Allow-Outbound-Internet");

  // ── identity ──
  const email = ev.user?.email ?? ev.user_email;
  const panUser = rawGet(raw, "pan.srcuser");
  const samRaw = panUser?.split("\\").pop() ?? rawGet(raw, "data.user", "cisco.asa.username", "src_user_name");
  const sam = samRaw ?? (email ? email.split("@")[0] : undefined);
  const user = sam ? { sam, email, panUser } : undefined;

  let host: FwFacts["host"];
  if (ev.hostname) {
    const role = native && FW_HOST_RE.test(ev.hostname) ? "device" : dir === "inbound" ? "dst" : "src";
    host = { name: ev.hostname, role };
  }

  // ── geo ──
  let srcCountry = normCountry(rawGet(raw, "source.geo.country_name", "source.geo.country_iso_code", "data.srccountry", "src_country"));
  let dstCountry = normCountry(rawGet(raw, "destination.geo.country_name", "destination.geo.country_iso_code", "data.dstcountry", "dst_country"));
  const g = normCountry(ev.geo?.country);
  if (g) { if (dir === "inbound") srcCountry = srcCountry ?? g; else dstCountry = dstCountry ?? g; }
  if (sPriv) srcCountry = undefined;
  if (dPriv) dstCountry = undefined;

  // ── threat object ──
  let threat: FwFacts["threat"];
  if (cls === "threat") {
    const kind = threatKindOf(thName ?? "", thCatRaw, dir);
    const name = thName ?? defaultThreatName(kind, thCatRaw);
    const cve = /CVE-\d{4}-\d{4,7}/i.exec(`${name} ${ev.description ?? ""}`)?.[0]?.toUpperCase();
    threat = { name, id: thId, kind, severity: thSev ?? (evSev === "informational" ? "medium" : evSev), cve, catRaw: thCatRaw };
  }

  // ── SI (reputation feed) category ──
  let siCategory = rawGet(raw, "cisco.ftd.security_intelligence_category");
  const ind = `${rawGet(raw, "threat.indicator") ?? ""} ${rawGet(raw, "threat.category") ?? ""}`;
  if (!siCategory && /tor/i.test(ind) && blocked) siCategory = "Tor_exit_node";

  return {
    ev, timeMs, companyId: ctx.companyId, native, cls, dir, src, dst, sport, dport, proto,
    protoNum: proto === "udp" ? 17 : proto === "icmp" ? 1 : 6,
    blocked, startOnly, detectOnly: cls === "threat" && !blocked,
    app, domain, url, urlNoScheme, path, method, userAgent, referer, category, categoryPanRaw,
    bytesOut, bytesIn, pktsOut: pkts(bytesOut), pktsIn: pkts(bytesIn), elapsed,
    rule, ruleAuthored: !!ruleAuth, user, host, srcCountry, dstCountry, threat, file, siCategory,
    sessionIdAuthored: rawGet(raw, "pan.session_id", "data.sessionid"),
    severity: evSev,
  };
}

/** Stable numeric session id for the connection (authored id wins so start/end records correlate). */
export function sessionNumber(f: FwFacts, ctx: NativeCtx, min: number, max: number): number {
  const a = f.sessionIdAuthored ? Number(f.sessionIdAuthored) : NaN;
  if (Number.isFinite(a) && a >= min && a <= max) return a;
  const seed = f.sessionIdAuthored ? `${f.companyId}:sess:${f.sessionIdAuthored}` : `${f.ev.id}:session`;
  return ctx.int(seed, min, max);
}
/** Stable SNAT source port for this connection. */
export function natPort(f: FwFacts, ctx: NativeCtx): number {
  return ctx.int(f.sessionIdAuthored ? `${f.companyId}:nat:${f.sessionIdAuthored}` : `${f.ev.id}:natport`, 1024, 64999);
}
/** True when the connection is source-NATed to the company egress (outbound to the internet). */
export const isSnat = (f: FwFacts) => f.dir === "outbound";
/** Stable threat id for a named signature when the authored event has none. */
export function threatNumber(name: string, ctx: NativeCtx, min: number, max: number): number {
  return ctx.int(`threat:${name.toLowerCase()}`, min, max);
}
