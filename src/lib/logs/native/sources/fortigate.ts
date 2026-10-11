/**
 * Fortinet FortiGate (FortiOS 7.x) — traffic/forward, utm/webfilter, utm/ips,
 * utm/virus and event/system logs, rendered per docs/log-schemas/fw-fortigate.md:
 * a FLAT object with FortiOS key names in emitted order; quoted values → JSON
 * strings, unquoted integers → JSON numbers, unquoted IP/MAC/date/time → strings;
 * `logid` stays a quoted 10-digit string. `rawLine` = the key=value syslog body.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { KindSchema, NativeCtx, NativeLog, NativeSource, SourceSchema, UseCase } from "../types";
import {
  APPS, CATEGORIES, HIGH_RISK_COUNTRIES, egressIp, extractFacts, hms, isPrivate, isSnat, natPort, rawGet,
  serviceName, sessionNumber, threatNumber, ymdDash, type FwFacts, type Sev,
} from "./firewall-shared";

const HEADER = ["date", "time", "devname", "devid", "eventtime", "tz", "logid", "type", "subtype", "level", "vd"];
const TRAFFIC_OPT = ["srcname", "srcport", "srcintfrole", "dstport", "dstintfrole", "srccountry", "dstcountry", "srcmac", "mastersrcmac",
  "policytype", "poluuid", "policyname", "user", "group", "authserver", "unauthuser", "service", "trandisp", "transip", "transport",
  "app", "appid", "appcat", "apprisk", "applist", "appact", "duration", "sentbyte", "rcvdbyte", "sentpkt", "rcvdpkt", "utmaction",
  "countweb", "countips", "countav", "countapp", "utmref", "crscore", "craction", "crlevel", "osname", "srcswversion", "devtype", "srcserver"];
const SESSION_OPT = ["policyid", "poluuid", "policytype", "srcport", "srccountry", "srcintf", "srcintfrole", "dstport", "dstcountry", "dstintf",
  "dstintfrole", "proto", "service", "profile", "direction", "msg", "crscore", "craction", "crlevel"];
const k = (required: string[], optional: string[]): KindSchema => ({ required: [...HEADER, ...required], optional: optional.filter(x => !required.includes(x)) });

export const schema: SourceSchema = {
  sourceId: "fortigate",
  category: "firewall",
  card: "fw-fortigate.md",
  product: "Fortinet FortiGate (FortiOS)",
  format: "kv",
  vendorMatch: ["fortigate", "fortinet", "fortios"],
  telemetrySources: ["firewall", "ids"],
  kinds: {
    "traffic/forward": k(["srcip", "dstip", "srcintf", "dstintf", "sessionid", "proto", "action", "policyid"], TRAFFIC_OPT),
    "utm/webfilter": k(["eventtype", "srcip", "dstip", "sessionid", "action", "hostname", "url", "cat", "catdesc"],
      [...SESSION_OPT, "user", "group", "authserver", "reqtype", "referralurl", "sentbyte", "rcvdbyte", "method"]),
    "utm/ips": k(["eventtype", "severity", "srcip", "dstip", "sessionid", "action", "attack", "attackid"],
      [...SESSION_OPT, "hostname", "url", "agent", "httpmethod", "ref", "incidentserialno"]),
    // Card 3.5 lists the AV-specific keys; the session block is the same as the other UTM logs.
    "utm/virus": k(["eventtype", "srcip", "dstip", "sessionid", "action", "virus", "filename"],
      [...SESSION_OPT, "virusid", "dtype", "url", "hostname", "quarskip", "ref", "analyticscksum", "analyticssubmit"]),
    "event/system": k(["logdesc", "msg"], ["sn", "user", "ui", "method", "srcip", "dstip", "action", "status", "reason", "profile"]),
  },
};

export function kindOf(record: Record<string, unknown>): string | null {
  const kk = `${record.type}/${record.subtype}`;
  return schema.kinds[kk] ? kk : null;
}

// ── helpers ──────────────────────────────────────────────────────────────────
type Rec = Record<string, string | number>;
const FSEV: Record<Sev, string> = { informational: "info", low: "low", medium: "medium", high: "high", critical: "critical" };
const APPRISK: Record<string, string> = { mega: "elevated", ssh: "elevated", rdp: "high", smb: "medium", ssl: "medium", "web-browsing": "medium", ftp: "elevated", websocket: "medium" };
function intf(role: "lan" | "wan" | "dmz", side: "src" | "dst" = "src"): string { return role === "wan" ? "port1" : role === "dmz" ? "port3" : side === "dst" ? "port4" : "port2"; }
function roles(f: FwFacts): ["lan" | "wan" | "dmz", "lan" | "wan" | "dmz"] {
  if (f.dir === "outbound") return ["lan", "wan"];
  if (f.dir === "internal") return ["lan", "lan"];
  return ["wan", [80, 443, 8080, 8443, 25].includes(f.dport) ? "dmz" : "lan"];
}
const country = (ip: string, c: string | undefined) => (isPrivate(ip) ? "Reserved" : c);

function header(f: FwFacts, ctx: NativeCtx, logid: string, type: string, subtype: string, level: string, eventtype?: string): Rec {
  const raw = (f.ev.raw ?? {}) as Record<string, unknown>;
  const r: Rec = {
    date: ymdDash(f.timeMs), time: hms(f.timeMs),
    devname: rawGet(raw, "data.devname") ?? (f.host?.role === "device" ? f.host.name : "FGT-HQ-01"),
    devid: rawGet(raw, "data.devid") ?? `FG200FTK${ctx.int(`${ctx.companyId}:fgt:devid`, 10000000, 99999999)}`,
    // epoch in ns (19 digits); sub-ms digits are zero so the JSON number stays exact.
    eventtime: f.timeMs * 1_000_000, tz: "+0000", logid, type, subtype,
  };
  if (eventtype) r.eventtype = eventtype;
  r.level = level; r.vd = rawGet(raw, "data.vd") ?? "root";
  return r;
}
function policy(f: FwFacts, ctx: NativeCtx): { policyid: number; poluuid?: string; policyname?: string } {
  const raw = (f.ev.raw ?? {}) as Record<string, unknown>;
  const authoredId = Number(rawGet(raw, "data.policyid"));
  if (!f.ruleAuthored && f.blocked && !Number.isFinite(authoredId)) return { policyid: 0 }; // implicit deny
  const policyid = Number.isFinite(authoredId) && authoredId > 0 ? authoredId : ctx.int(`${ctx.companyId}:fgt:pol:${f.rule}`, 2, 180);
  return { policyid, poluuid: ctx.uuid(`${ctx.companyId}:fgt:poluuid:${policyid}`), policyname: f.rule };
}
function identity(f: FwFacts, ctx: NativeCtx, r: Rec): void {
  if (!f.user || f.dir === "inbound") return;
  r.user = f.user.sam;
  if (f.ev.user?.department) r.group = f.ev.user.department;
  r.authserver = `${ctx.netbios}-FSSO`;
}
function fiveTupleUtm(f: FwFacts, r: Rec): void {
  const [sr, dr] = roles(f);
  r.srcip = f.src; r.srcport = f.sport;
  const sc = country(f.src, f.srcCountry), dc = country(f.dst, f.dstCountry);
  if (sc) r.srccountry = sc;
  r.srcintf = intf(sr); r.srcintfrole = sr;
  r.dstip = f.dst; r.dstport = f.dport;
  if (dc) r.dstcountry = dc;
  r.dstintf = intf(dr, "dst"); r.dstintfrole = dr;
  r.proto = f.protoNum;
}
function mac(ctx: NativeCtx, host: string): string {
  const h = ctx.hex(`${ctx.companyId}:mac:${host.toLowerCase()}`, 6);
  return `3c:52:82:${h.slice(0, 2)}:${h.slice(2, 4)}:${h.slice(4, 6)}`;
}

function traffic(f: FwFacts, ctx: NativeCtx): Rec {
  const raw = (f.ev.raw ?? {}) as Record<string, unknown>;
  const authoredLogid = rawGet(raw, "data.logid");
  const logid = authoredLogid && ["0000000013", "0000000020", "0000000011"].includes(authoredLogid) ? authoredLogid : "0000000013";
  const r = header(f, ctx, logid, "traffic", "forward", "notice");
  const [sr, dr] = roles(f);
  r.srcip = f.src;
  if (f.host?.role === "src") r.srcname = f.host.name;
  if (f.proto !== "icmp") r.srcport = f.sport;
  r.srcintf = rawGet(raw, "data.srcintf") ?? intf(sr); r.srcintfrole = rawGet(raw, "data.srcintfrole") ?? sr;
  r.dstip = f.dst;
  if (f.proto !== "icmp") r.dstport = f.dport;
  r.dstintf = rawGet(raw, "data.dstintf") ?? intf(dr, "dst"); r.dstintfrole = rawGet(raw, "data.dstintfrole") ?? dr;
  const sc = country(f.src, f.srcCountry), dc = country(f.dst, f.dstCountry);
  if (sc) r.srccountry = sc;
  if (dc) r.dstcountry = dc;
  r.sessionid = sessionNumber(f, ctx, 10000000, 999999999);
  r.proto = f.protoNum;
  r.action = f.blocked ? "deny" : f.startOnly ? "start" : f.proto === "udp" ? "accept" : "close";
  const p = policy(f, ctx);
  r.policyid = p.policyid; r.policytype = "policy";
  if (p.poluuid) r.poluuid = p.poluuid;
  if (p.policyname) r.policyname = p.policyname;
  identity(f, ctx, r);
  r.service = rawGet(raw, "data.service") ?? serviceName(f.dport, f.proto, "fgt")!;
  if (f.blocked) r.trandisp = "noop";
  else if (isSnat(f)) { r.trandisp = "snat"; r.transip = egressIp(ctx); r.transport = natPort(f, ctx); }
  else r.trandisp = "noop";
  const a = APPS[f.app];
  if (!f.blocked && a && !f.app.startsWith("unknown")) {
    r.appid = ctx.int(`fgt:appid:${f.app}`, 15000, 49999); r.app = a.fgt; r.appcat = a.fgtCat;
    r.apprisk = APPRISK[f.app] ?? "low"; r.applist = "Corp-AppCtrl";
  } else r.appcat = "unscanned";
  r.duration = f.elapsed;
  r.sentbyte = f.blocked ? 0 : f.bytesOut; r.rcvdbyte = f.blocked ? 0 : f.bytesIn;
  r.sentpkt = f.blocked ? 0 : f.pktsOut; r.rcvdpkt = f.blocked ? 0 : f.pktsIn;
  if (f.blocked) { r.crscore = 30; r.craction = 131072; r.crlevel = "high"; }
  else {
    r.utmaction = "allow";
    if ([80, 443, 8080, 8443].includes(f.dport) && f.dir === "outbound") r.countweb = 1;
    if (r.app) r.countapp = 1;
  }
  if (r.srcname) {
    if (/^(ws|lap|lt|laptop|desktop)/i.test(String(r.srcname))) { r.osname = "Windows"; r.srcswversion = "11"; }
    const m = mac(ctx, String(r.srcname));
    r.mastersrcmac = m; r.srcmac = m; r.srcserver = 0;
  }
  return r;
}

function catOf(f: FwFacts): { cat: number; catdesc: string } {
  const m = (f.category && CATEGORIES[f.category]) || CATEGORIES["computer-and-internet-info"];
  return { cat: m.fgtCat, catdesc: m.fgtDesc };
}

function webfilter(f: FwFacts, ctx: NativeCtx): Rec {
  const r = header(f, ctx, f.blocked ? "0316013056" : "0317013312", "utm", "webfilter", f.blocked ? "warning" : "notice", f.blocked ? "ftgd_blk" : "ftgd_allow");
  const p = policy(f, ctx);
  r.policyid = p.policyid || ctx.int(`${ctx.companyId}:fgt:pol:${f.rule}`, 2, 180);
  r.poluuid = p.poluuid ?? ctx.uuid(`${ctx.companyId}:fgt:poluuid:${r.policyid}`);
  r.policytype = "policy";
  r.sessionid = sessionNumber(f, ctx, 10000000, 999999999);
  identity(f, ctx, r);
  fiveTupleUtm(f, r);
  r.service = serviceName(f.dport, f.proto, "fgt")!;
  r.hostname = f.domain ?? f.dst;
  r.profile = "Corp-WebFilter";
  r.action = f.blocked ? "blocked" : "passthrough";
  r.reqtype = f.referer ? "referral" : "direct";
  r.url = f.url ?? `https://${r.hostname}/`;
  if (f.referer) r.referralurl = f.referer;
  r.sentbyte = f.blocked ? ctx.int(`${f.ev.id}:req`, 380, 720) : f.bytesOut;
  r.rcvdbyte = f.blocked ? 0 : f.bytesIn;
  r.direction = f.dir === "inbound" ? "incoming" : "outgoing";
  r.msg = f.blocked ? "URL belongs to a denied category in policy" : "URL belongs to an allowed category in policy";
  r.method = "domain";
  const c = catOf(f);
  r.cat = c.cat; r.catdesc = c.catdesc;
  if (f.blocked) { r.crscore = 30; r.craction = 4194304; r.crlevel = "high"; }
  return r;
}

function ips(f: FwFacts, ctx: NativeCtx): Rec {
  const t = f.threat!;
  const raw = (f.ev.raw ?? {}) as Record<string, unknown>;
  const r = header(f, ctx, "0419016384", "utm", "ips", "alert", "signature");
  r.severity = FSEV[t.severity];
  r.srcip = f.src;
  const sc = country(f.src, f.srcCountry), dc = country(f.dst, f.dstCountry);
  if (sc) r.srccountry = sc;
  r.dstip = f.dst;
  if (dc) r.dstcountry = dc;
  const [sr, dr] = roles(f);
  r.srcintf = intf(sr); r.srcintfrole = sr; r.dstintf = intf(dr, "dst"); r.dstintfrole = dr;
  r.sessionid = sessionNumber(f, ctx, 10000000, 999999999);
  r.action = f.blocked ? "dropped" : "detected";
  r.proto = f.protoNum;
  r.service = serviceName(f.dport, f.proto, "fgt")!;
  const p = policy(f, ctx);
  r.policyid = p.policyid || ctx.int(`${ctx.companyId}:fgt:pol:${f.rule}`, 2, 180);
  r.poluuid = p.poluuid ?? ctx.uuid(`${ctx.companyId}:fgt:poluuid:${r.policyid}`);
  r.policytype = "policy";
  r.attack = t.name;
  r.srcport = f.sport; r.dstport = f.dport;
  if (f.domain || f.url) r.hostname = f.domain ?? f.dst;
  if (f.url) r.url = f.path ?? "/";
  if (f.userAgent) r.agent = f.userAgent;
  if (f.method && f.url) r.httpmethod = f.method;
  r.direction = f.dir === "inbound" ? "incoming" : "outgoing"; // client-to-server request (attacker or implant is the client)
  const attackid = Number(t.id) || threatNumber(t.name, ctx, 10000, 59999);
  r.attackid = attackid;
  r.profile = rawGet(raw, "data.profile") ?? (f.dir === "outbound" ? "protect_client" : [80, 443, 8080, 8443].includes(f.dport) ? "protect_http_server" : "high_security");
  r.ref = `http://www.fortinet.com/ids/VID${attackid}`;
  r.incidentserialno = ctx.int(`${f.ev.id}:incident`, 100000000, 999999999);
  const group = t.kind === "c2" ? "backdoor" : t.kind === "sqli" ? "web_app3" : "applications3";
  r.msg = `${group}: ${t.name},`;
  const cr: Record<Sev, [number, string]> = { critical: [50, "critical"], high: [30, "high"], medium: [10, "medium"], low: [5, "low"], informational: [5, "low"] };
  r.crscore = cr[t.severity][0]; r.craction = 4096; r.crlevel = cr[t.severity][1];
  return r;
}

function systemEvent(f: FwFacts, ctx: NativeCtx): Rec {
  const ok = f.ev.event_type === "auth_success";
  const r = header(f, ctx, ok ? "0100032001" : "0100032002", "event", "system", ok ? "information" : "alert");
  const user = f.user?.sam ?? "admin";
  r.logdesc = ok ? "Admin login successful" : "Admin login failed";
  r.sn = "0"; r.user = user; r.ui = `https(${f.src})`; r.method = "https";
  r.srcip = f.src; r.dstip = f.dst;
  r.action = "login"; r.status = ok ? "success" : "failed";
  if (!ok) r.reason = "passwd_invalid";
  r.msg = ok ? `Administrator ${user} logged in successfully from https(${f.src})` : `Administrator ${user} login failed from https(${f.src}) because of invalid password`;
  return r;
}

// ── wire line ────────────────────────────────────────────────────────────────
const UNQUOTED = new Set(["date", "time", "srcip", "dstip", "transip", "srcmac", "dstmac", "mastersrcmac"]);
export function toRawLine(r: Record<string, unknown>): string {
  return Object.entries(r).map(([key, v]) => (typeof v === "number" || UNQUOTED.has(key) ? `${key}=${v}` : `${key}="${String(v).replace(/"/g, '\\"')}"`)).join(" ");
}

function fromTelemetry(ev: TelemetryEvent, ctx: NativeCtx): NativeLog | null {
  const f = extractFacts(ev, ctx, schema.vendorMatch);
  if (!f) return null;
  let record: Rec;
  if (f.cls === "admin") record = systemEvent(f, ctx);
  else if (f.cls === "threat") record = ips(f, ctx);
  // Web filtering applies to outbound HTTP(S); a downloaded file is logged by the
  // web filter as its URL (the AV log exists only for an infected verdict).
  else if ((f.cls === "url" || f.cls === "file") && f.dir === "outbound") record = webfilter(f, ctx);
  // A web-filter profile on an inbound (published-server) policy logs the request it rated too.
  else if (f.cls === "url" && f.dir === "inbound") record = webfilter(f, ctx);
  else record = traffic(f, ctx);
  const kind = `${record.type}/${record.subtype}`;
  return { sourceId: "fortigate", kind, format: "kv", record, rawLine: toRawLine(record), timeMs: f.timeMs };
}

// ── use cases ────────────────────────────────────────────────────────────────
const ALLOWED = ["close", "accept", "start", "timeout", "passthrough", "client-rst", "server-rst"];
export const useCases: UseCase[] = [
  {
    id: "fortigate.newly-registered-domain", title: "Web request to a Newly Registered / Newly Observed Domain", sourceId: "fortigate", kinds: ["utm/webfilter"],
    severity: "medium", mitre: ["T1071.001", "T1583.001"],
    description: "FortiGuard category 91 (Newly Registered Domain) and 90 (Newly Observed Domain) flag domains that only just appeared — typical of C2, phishing and payload hosting. A passthrough means the request succeeded; join on sessionid to the forward-traffic log for byte counts.",
    logic: "FortiAnalyzer: type==utm and subtype==webfilter and (cat==91 or cat==90) | SPL: sourcetype=fortigate_utm subtype=webfilter cat IN (90,91) | stats count by srcip user hostname action",
    match: { field: "cat", op: "in", value: [90, 91] },
    falsePositives: ["New marketing / SaaS domains", "CDN hostnames rotated by legitimate providers"],
  },
  {
    id: "fortigate.webfilter-block-malicious", title: "Web filter blocked a malicious category", sourceId: "fortigate", kinds: ["utm/webfilter"],
    severity: "medium", mitre: ["T1189", "T1566.002"],
    description: "eventtype ftgd_blk with cat 26 (Malicious Websites), 61 (Phishing), 86 (Spam URLs), 88 (Dynamic DNS) or 90/91 (new domains): something on the host tried to reach known-bad infrastructure. The block worked — find out what made the request.",
    logic: "FortiAnalyzer: subtype==webfilter and eventtype==ftgd_blk and cat in (26,61,86,88,90,91)",
    match: { all: [{ field: "eventtype", op: "eq", value: "ftgd_blk" }, { field: "cat", op: "in", value: [26, 61, 86, 88, 90, 91] }] },
    falsePositives: ["Malvertising redirects on legitimate news sites", "Mis-rated domains"],
  },
  {
    id: "fortigate.ips-critical-inbound", title: "Critical IPS signature from the internet", sourceId: "fortigate", kinds: ["utm/ips"],
    severity: "critical", mitre: ["T1190"],
    description: "utm/ips with severity=\"critical\" arriving on a WAN interface is an exploitation attempt against a published service (e.g. Apache.Log4j.Error.Log.Remote.Code.Execution). action=\"dropped\" means it was stopped; \"detected\" means it reached the server.",
    logic: "FortiAnalyzer: type==utm and subtype==ips and severity==critical and srcintfrole==wan",
    match: { all: [{ field: "severity", op: "eq", value: "critical" }, { field: "srcintfrole", op: "eq", value: "wan" }] },
    falsePositives: ["Contracted external vulnerability scans"],
  },
  {
    id: "fortigate.ips-outbound-c2", title: "IPS signature on traffic leaving the LAN (C2 / botnet)", sourceId: "fortigate", kinds: ["utm/ips"],
    severity: "critical", mitre: ["T1071", "T1071.001"],
    description: "An IPS signature on a session that ORIGINATES from a LAN interface toward the WAN means an internal host is speaking a malware protocol (backdoor / botnet C2). Treat the source host as compromised.",
    logic: "FortiAnalyzer: subtype==ips and srcintfrole==lan and dstintfrole==wan | SPL: sourcetype=fortigate_utm subtype=ips srcintfrole=lan",
    match: { all: [{ field: "srcintfrole", op: "eq", value: "lan" }, { field: "dstintfrole", op: "eq", value: "wan" }] },
    falsePositives: ["Sandbox / malware-analysis hosts", "Generic signatures matching unusual but benign apps"],
  },
  {
    id: "fortigate.large-outbound-transfer", title: "Large outbound transfer (sentbyte ≥ 100 MB)", sourceId: "fortigate", kinds: ["traffic/forward"],
    severity: "high", mitre: ["T1048", "T1567.002"],
    description: "Forward-traffic session-end logs carry sentbyte (from the originator). One session uploading ≥100 MB to a WAN destination — especially to storage / file-sharing apps — is a primary exfiltration signal. Sum interim 0000000020 logs per sessionid if present.",
    logic: "FortiAnalyzer: type==traffic and dstintfrole==wan and sentbyte>=104857600 | SPL: sourcetype=fortigate_traffic dstintfrole=wan sentbyte>=104857600 | table srcip srcname user dstip app sentbyte rcvdbyte duration",
    match: { all: [{ field: "dstintfrole", op: "eq", value: "wan" }, { field: "sentbyte", op: "gte", value: 104857600 }] },
    falsePositives: ["Approved cloud backup / sync jobs"],
  },
  {
    id: "fortigate.port-scan", title: "Port scan: many denied destination ports from one source", sourceId: "fortigate", kinds: ["traffic/forward"],
    severity: "medium", mitre: ["T1046", "T1595.001"],
    description: "Ten or more distinct dstport values denied for the same srcip within five minutes is scanning. Client-reputation (crscore) also rises on these denies.",
    logic: "SPL: sourcetype=fortigate_traffic action=deny | bin _time span=5m | stats dc(dstport) as ports by srcip _time | where ports>=10",
    match: { field: "action", op: "eq", value: "deny" },
    threshold: { groupBy: ["srcip"], count: 10, windowSec: 300, distinct: "dstport" },
    falsePositives: ["Internal vulnerability scanners", "Monitoring systems"],
  },
  {
    id: "fortigate.beaconing", title: "Beaconing: repeated sessions from one host to one external server", sourceId: "fortigate", kinds: ["traffic/forward", "utm/webfilter"],
    severity: "medium", mitre: ["T1071.001", "T1573"],
    description: "Six or more allowed sessions/requests from the same srcip to the same dstip within an hour, typically with near-identical sentbyte, is a beacon. Repeated ftgd_allow for one hostname in cat 90/91 makes it urgent.",
    logic: "SPL: sourcetype=fortigate_* dstintfrole=wan action IN (close, accept, passthrough) | bin _time span=1h | stats count by srcip dstip _time | where count>=6",
    match: { all: [{ field: "dstintfrole", op: "eq", value: "wan" }, { field: "action", op: "in", value: ALLOWED }] },
    threshold: { groupBy: ["srcip", "dstip"], count: 6, windowSec: 3600 },
    falsePositives: ["Update agents, telemetry, chat keep-alives"],
  },
  {
    id: "fortigate.high-risk-country", title: "Allowed traffic to/from a high-risk country", sourceId: "fortigate", kinds: ["traffic/forward", "utm/webfilter"],
    severity: "medium", mitre: ["T1071", "T1133"],
    description: "srccountry / dstcountry come from FortiGuard GeoIP. Allowed sessions involving a country the organisation has no business with are a quick triage pivot (C2 hosting, brute force, remote access).",
    logic: "FortiAnalyzer: action in (close, accept, passthrough) and (dstcountry in (\"Russian Federation\", Iran, \"North Korea\", Belarus, China) or srccountry in (…))",
    match: { all: [{ field: "action", op: "in", value: ALLOWED }, { any: [{ field: "dstcountry", op: "in", value: HIGH_RISK_COUNTRIES }, { field: "srccountry", op: "in", value: HIGH_RISK_COUNTRIES }] }] },
    falsePositives: ["Overseas suppliers or travelling employees"],
  },
  {
    id: "fortigate.admin-login-bruteforce", title: "Repeated failed admin logins on the firewall", sourceId: "fortigate", kinds: ["event/system"],
    severity: "high", mitre: ["T1110.001", "T1078"],
    description: "logid 0100032002 (Admin login failed) five or more times from one srcip in ten minutes is password guessing against the FortiGate management interface — a direct path to owning the perimeter.",
    logic: "FortiAnalyzer: logid==0100032002 | SPL: sourcetype=fortigate_event logid=0100032002 | bin _time span=10m | stats count values(user) by srcip _time | where count>=5",
    match: { field: "logid", op: "eq", value: "0100032002" },
    threshold: { groupBy: ["srcip"], count: 5, windowSec: 600 },
    falsePositives: ["An admin with a stale saved password in a script"],
  },
  {
    id: "fortigate.deny-then-allow", title: "WAN source denied, then allowed", sourceId: "fortigate", kinds: ["traffic/forward"],
    severity: "medium", mitre: ["T1190", "T1133"],
    description: "The same internet srcip hits a deny and, within the hour, gets an accepted/closed session — the attacker probed until finding an open service. Check which policyid let it in.",
    logic: "SPL: sourcetype=fortigate_traffic srcintfrole=wan | stats dc(action) as verdicts values(action) values(dstport) values(policyid) by srcip | where verdicts>=2 AND mvfind(action,\"deny\")>=0",
    match: { field: "srcintfrole", op: "eq", value: "wan" },
    threshold: { groupBy: ["srcip"], count: 2, windowSec: 3600, distinct: "action" },
    falsePositives: ["Partners allowed on one service and denied on others"],
  },
  {
    id: "fortigate.inbound-rdp-allowed", title: "Inbound RDP from the internet accepted", sourceId: "fortigate", kinds: ["traffic/forward"],
    severity: "high", mitre: ["T1133", "T1021.001"],
    description: "A forward-traffic log from a WAN interface to dstport 3389 that was not denied means Remote Desktop is published to the internet — prime ransomware initial access.",
    logic: "FortiAnalyzer: type==traffic and srcintfrole==wan and dstport==3389 and action!=deny",
    match: { all: [{ field: "srcintfrole", op: "eq", value: "wan" }, { field: "dstport", op: "eq", value: 3389 }, { field: "action", op: "in", value: ALLOWED }] },
    falsePositives: ["Vendor jump host restricted by source address"],
  },
];

export const source: NativeSource = { schema, fromTelemetry, useCases };
