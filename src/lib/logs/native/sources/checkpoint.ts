/**
 * Check Point Quantum Security Gateway — default Log Exporter (syslog) format,
 * rendered per docs/log-schemas/fw-checkpoint.md: a FLAT object keyed by the
 * Check Point field names, all values strings, repeated match-table keys
 * (layer_name, rule_name, rule_uid …) as JSON arrays in emitted order.
 * `rawLine` = RFC 5424 header + `[key:"value"; …]` body.
 *
 * Never the `ProductName` / `ProductFamily` / `svc` / `sport_svc` variant (card §6):
 * the legacy keys of that style found in the corpus `raw` map are read as INPUT
 * only and re-emitted under the default-format names (`product`, `service`, `s_port`).
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { KindSchema, NativeCtx, NativeLog, NativeSource, SourceSchema, UseCase } from "../types";
import {
  APPS, CATEGORIES, HIGH_RISK_COUNTRIES, egressIp, extractFacts, isSnat, natPort, serviceName, type FwFacts, type Sev,
} from "./firewall-shared";

const HEAD = ["action", "flags", "ifdir", "ifname", "logid", "loguid", "origin", "originsicname", "sequencenum", "time", "version", "product"];
const CONN = ["src", "dst", "proto"];
const CONN_OPT = ["__policy_id_tag", "s_port", "service", "service_id", "inzone", "outzone", "src_country", "dst_country", "src_machine_name", "src_user_name", "user",
  "xlatesrc", "xlatedst", "xlatesport", "xlatedport"];
const MATCH = ["layer_name", "layer_uuid", "match_id", "parent_rule", "rule_action", "rule_name", "rule_uid"];
const ACCOUNTING = ["bytes", "packets", "client_outbound_bytes", "client_inbound_bytes", "server_inbound_bytes", "server_outbound_bytes",
  "client_outbound_packets", "client_inbound_packets", "server_inbound_packets", "server_outbound_packets", "client_inbound_interface",
  "server_outbound_interface", "sent_bytes", "received_bytes", "segment_time", "start_time", "elapsed", "lastupdatetime", "hll_key"];
const DROP_INFO = ["reason", "action_reason", "tcp_flags", "tcp_packet_out_of_state"];
// `referrer` appears in card sample CP-5 but is marked UNVERIFIED: accepted when validating, never emitted.
const APPURL = ["app_category", "app_id", "app_risk", "appi_name", "matched_category", "app_desc", "app_properties", "resource", "method",
  "web_client_type", "proxy_src_ip", "usercheck_interaction_name", "referrer"];
const THREAT = ["confidence_level", "severity", "policy", "protection_id", "protection_name", "protection_type", "session_id", "resource",
  "layer_name", "layer_uuid", "packet_capture_name", "packet_capture_unique_id"];
const k = (opt: string[]): KindSchema => ({ required: [...HEAD, ...CONN], optional: [...new Set(opt)] });

export const schema: SourceSchema = {
  sourceId: "checkpoint",
  category: "firewall",
  card: "fw-checkpoint.md",
  product: "Check Point Quantum Security Gateway",
  format: "syslog",
  vendorMatch: ["check point", "checkpoint"],
  telemetrySources: ["firewall", "ids"],
  kinds: {
    firewall: k([...CONN_OPT, ...MATCH, ...ACCOUNTING, ...DROP_INFO]),
    url_filtering: k([...CONN_OPT, ...MATCH, ...APPURL, ...ACCOUNTING]),
    app_control: k([...CONN_OPT, ...MATCH, ...APPURL, ...ACCOUNTING]),
    ips: k([...CONN_OPT, ...THREAT, "attack", "attack_info", "http_host", "industry_reference", "method", "performance_impact", "smartdefense_profile", "user_agent"]),
    anti_bot: k([...CONN_OPT, ...THREAT, "malware_action", "malware_family", "malware_rule_id", "proxy_src_ip"]),
  },
};

const PRODUCT_KIND: Record<string, string> = {
  "VPN-1 & FireWall-1": "firewall", "URL Filtering": "url_filtering", "Application Control": "app_control",
  SmartDefense: "ips", "Anti-Bot": "anti_bot", "Anti Malware": "anti_bot",
};
export function kindOf(record: Record<string, unknown>): string | null {
  return PRODUCT_KIND[String(record.product)] ?? null;
}

// ── helpers ──────────────────────────────────────────────────────────────────
type Rec = Record<string, string | string[]>;
const CPSEV: Record<Sev, string> = { informational: "0", low: "1", medium: "2", high: "3", critical: "4" };
const CO_PREFIX: Record<string, string> = { nexacorp: "10.10", rocketstack: "172.16", medcore: "192.168", globallogis: "10.50", quantumbank: "10.100" };
const gwIp = (ctx: NativeCtx) => `${CO_PREFIX[ctx.companyId] ?? "10.20"}.0.1`;
const guid = (ctx: NativeCtx, seed: string) => `{${ctx.uuid(seed).toUpperCase()}}`;
function zones(f: FwFacts): [string, string] {
  if (f.dir === "outbound") return ["Internal", "External"];
  if (f.dir === "internal") return ["Internal", "Internal"];
  return ["External", [80, 443, 8080, 8443, 25].includes(f.dport) ? "DMZ" : "Internal"];
}
function cpCategory(f: FwFacts): string { return ((f.category && CATEGORIES[f.category]) || CATEGORIES["computer-and-internet-info"]).cp; }
function riskOf(cat: string): string {
  if (["Spyware / Malicious Sites", "Phishing", "Botnets"].includes(cat)) return "5";
  if (cat === "Uncategorized") return "0";
  if (cat === "File Storage and Sharing") return "4";
  return "1";
}
function webClient(ua: string | undefined): string | undefined {
  if (!ua) return undefined;
  if (/Edg\//.test(ua)) return "Edge";
  if (/Chrome\//.test(ua)) return "Chrome";
  if (/Firefox\//.test(ua)) return "Firefox";
  return `Other: ${ua}`;
}

function head(f: FwFacts, ctx: NativeCtx, action: string, flags: string, logid: string, seq: string): Rec {
  const t = Math.floor(f.timeMs / 1000);
  const gwName = f.host?.role === "device" ? f.host.name : "gw-hq-01";
  const policyDate = Math.floor(t / 86400) * 86400 - 86400;
  return {
    action, flags, ifdir: f.dir === "inbound" ? "inbound" : "outbound", ifname: f.dir === "inbound" ? "eth0" : "eth1", logid,
    loguid: `{0x${t.toString(16)},0x${ctx.int(`${f.ev.id}:lu`, 0, 63).toString(16)},0x${ctx.hex(`${ctx.companyId}:cp:gw3`, 8)},0x${ctx.hex(`${ctx.companyId}:cp:gw4`, 8)}}`,
    origin: gwIp(ctx), originsicname: `CN=${gwName},O=mgmt-hq.${ctx.domain}.${ctx.hex(`${ctx.companyId}:cp:sic`, 6)}`,
    sequencenum: seq, time: String(t), version: "5",
    __policy_id_tag: `product=VPN-1 & FireWall-1[db_tag=${guid(ctx, `${ctx.companyId}:cp:db`)};mgmt=mgmt-hq;date=${policyDate};policy_name=Corp_Policy\\]`,
  };
}
function conn(f: FwFacts, r: Rec, withZones = true): void {
  r.src = f.src; r.dst = f.dst; r.proto = String(f.protoNum);
  if (f.proto !== "icmp") { r.s_port = String(f.sport); r.service = String(f.dport); }
  const sid = serviceName(f.dport, f.proto, "cp");
  if (sid) r.service_id = sid;
  if (withZones) { const [i, o] = zones(f); r.inzone = i; r.outzone = o; }
  if (f.srcCountry) r.src_country = f.srcCountry;
  if (f.dstCountry) r.dst_country = f.dstCountry;
  if (f.host?.role === "src") r.src_machine_name = f.host.name;
  if (f.user && f.dir !== "inbound") r.src_user_name = f.user.sam;
}
function xlate(f: FwFacts, ctx: NativeCtx, r: Rec, full = true): void {
  if (!isSnat(f)) return;
  r.xlatesrc = egressIp(ctx); r.xlatesport = String(natPort(f, ctx));
  if (full) { r.xlatedst = "0.0.0.0"; r.xlatedport = "0"; }
}
function matchTable(f: FwFacts, ctx: NativeCtx, r: Rec, layers: { name: string; rule: string; action: string }[]): void {
  const netId = String(ctx.int(`${ctx.companyId}:cp:rule:${layers[0].rule}`, 2, 60));
  const ids = layers.map((l, i) => (i === 0 ? netId : String(33554432 + ctx.int(`${ctx.companyId}:cp:sub:${l.rule}`, 1, 40))));
  const vals = {
    layer_name: layers.map(l => l.name),
    layer_uuid: layers.map(l => ctx.uuid(`${ctx.companyId}:cp:layer:${l.name}`)),
    match_id: ids,
    parent_rule: layers.map((_, i) => (i === 0 ? "0" : netId)),
    rule_action: layers.map(l => l.action),
    rule_name: layers.map(l => l.rule),
    rule_uid: layers.map(l => ctx.uuid(`${ctx.companyId}:cp:ruleuid:${l.name}:${l.rule}`)),
  };
  for (const [key, v] of Object.entries(vals)) r[key] = v.length === 1 ? v[0] : v;
}
function accounting(f: FwFacts, ctx: NativeCtx, r: Rec): void {
  const t = Math.floor(f.timeMs / 1000), st = t - f.elapsed;
  r.bytes = String(f.bytesOut + f.bytesIn); r.packets = String(f.pktsOut + f.pktsIn);
  r.client_inbound_bytes = String(f.bytesIn); r.client_inbound_interface = f.dir === "inbound" ? "eth0" : "eth2"; r.client_inbound_packets = String(f.pktsIn);
  r.client_outbound_bytes = String(f.bytesOut); r.client_outbound_packets = String(f.pktsOut);
  r.elapsed = String(f.elapsed);
  r.hll_key = `${ctx.int(`${f.ev.id}:hll`, 100000000, 999999999)}${ctx.int(`${f.ev.id}:hll2`, 1000000000, 2147483647)}`;
  r.lastupdatetime = String(t);
  r.segment_time = String(st);
  r.server_inbound_bytes = String(f.bytesOut); r.server_inbound_packets = String(f.pktsOut);
  r.server_outbound_bytes = String(f.bytesIn); r.server_outbound_interface = f.dir === "inbound" ? "eth2" : "eth1"; r.server_outbound_packets = String(f.pktsIn);
  r.start_time = String(st);
}

function firewall(f: FwFacts, ctx: NativeCtx): Rec {
  const acct = !f.blocked && !f.startOnly;
  const r = head(f, ctx, f.blocked ? "Drop" : "Accept", f.blocked ? "425988" : "411908", acct ? "6" : "0", acct ? String(ctx.int(`${f.ev.id}:seq`, 2, 9)) : "1");
  r.product = "VPN-1 & FireWall-1";
  conn(f, r);
  matchTable(f, ctx, r, [{ name: "Network", rule: f.blocked && !f.ruleAuthored ? "Cleanup rule" : f.rule, action: f.blocked ? "Drop" : "Accept" }]);
  if (!f.blocked) xlate(f, ctx, r);
  if (acct) accounting(f, ctx, r);
  return r;
}

function urlFiltering(f: FwFacts, ctx: NativeCtx): Rec {
  const r = head(f, ctx, f.blocked ? "Block" : "Accept", "411908", "0", "1");
  r.product = "URL Filtering";
  conn(f, r);
  const cat = cpCategory(f);
  r.app_category = cat; r.app_id = "0"; r.app_risk = riskOf(cat);
  r.appi_name = f.domain ?? f.dst;
  r.matched_category = cat;
  if (f.blocked) matchTable(f, ctx, r, [{ name: "Web Control", rule: f.ruleAuthored ? f.rule : "Block high-risk categories", action: "Drop" }]);
  else matchTable(f, ctx, r, [{ name: "Network", rule: f.rule, action: "Inline" }, { name: "Web Control", rule: cat === "Uncategorized" ? "Allow uncategorized" : "Allow business categories", action: "Accept" }]);
  if (f.method) r.method = f.method;
  r.proxy_src_ip = f.src;
  r.resource = f.url ?? `https://${r.appi_name}`;
  if (f.blocked) r.usercheck_interaction_name = "Blocked Message - Access Control";
  const wc = webClient(f.userAgent);
  if (wc) r.web_client_type = wc;
  xlate(f, ctx, r, !f.blocked);
  return r;
}

function appControl(f: FwFacts, ctx: NativeCtx): Rec {
  const r = head(f, ctx, "Accept", "411908", "6", String(ctx.int(`${f.ev.id}:seq`, 2, 9)));
  r.product = "Application Control";
  conn(f, r);
  const a = APPS[f.app];
  r.app_category = a?.cpCat ?? cpCategory(f);
  r.app_id = String(ctx.int(`cp:appid:${f.app}`, 10000000, 99999999));
  r.app_risk = r.app_category === "File Storage and Sharing" ? "4" : "1";
  r.appi_name = a?.cpApp ?? f.app;
  if (f.domain) r.resource = `https://${f.domain}`;
  matchTable(f, ctx, r, [{ name: "Network", rule: f.rule, action: "Inline" }, { name: "Web Control", rule: `Allow ${r.appi_name} (monitor)`, action: "Accept" }]);
  xlate(f, ctx, r, false);
  accounting(f, ctx, r);
  return r;
}

function threatCommon(f: FwFacts, ctx: NativeCtx, r: Rec, loguid: string): void {
  const t = f.threat!;
  r.confidence_level = t.severity === "critical" || t.severity === "high" ? "5" : "3";
  r.layer_name = "Standard Threat Prevention";
  r.layer_uuid = guid(ctx, `${ctx.companyId}:cp:tp-layer`);
  r.policy = "Corp_Policy";
  r.protection_name = t.name;
  r.session_id = loguid;
  r.severity = CPSEV[t.severity];
}
function ips(f: FwFacts, ctx: NativeCtx): Rec {
  const t = f.threat!;
  const r = head(f, ctx, f.blocked ? "Prevent" : "Detect", "311552", "0", "1");
  r.product = "SmartDefense";
  conn(f, r, false);
  threatCommon(f, ctx, r, String(r.loguid));
  if (f.domain && f.url) r.http_host = f.domain;
  if (t.cve) r.industry_reference = t.cve;
  if (f.method && f.url) r.method = f.method;
  const slug = (t.cve ?? t.name).toUpperCase().replace(/[^A-Z0-9]+/g, "_").replace(/^_|_$/g, "").slice(0, 48);
  r.protection_id = `asm_dynamic_prop_${slug}`;
  r.protection_type = "IPS";
  if (f.url) r.resource = f.url;
  r.smartdefense_profile = "Optimized";
  if (f.userAgent) r.user_agent = f.userAgent;
  return r;
}
function antiBot(f: FwFacts, ctx: NativeCtx): Rec {
  const t = f.threat!;
  const r = head(f, ctx, f.blocked ? "Prevent" : "Detect", "311552", "0", "1");
  r.product = "Anti-Bot";
  conn(f, r, false);
  threatCommon(f, ctx, r, String(r.loguid));
  r.malware_action = "Communication with C&C site";
  if (/cobalt/i.test(t.name)) r.malware_family = "CobaltStrike";
  r.malware_rule_id = guid(ctx, `${ctx.companyId}:cp:abrule`);
  r.protection_id = ctx.hex(`cp:prot:${t.name}`, 9).toUpperCase();
  r.protection_type = f.domain ? "URL reputation" : "IP reputation";
  r.proxy_src_ip = f.src;
  if (f.domain) r.resource = f.domain;
  return r;
}

// ── wire line ────────────────────────────────────────────────────────────────
const TAIL = ["xlatesrc", "xlatesport", "xlatedst", "xlatedport", "web_client_type"];
function order(r: Rec): Rec {
  const headKeys = [...HEAD.filter(x => x !== "product"), "__policy_id_tag"];
  const rest = Object.keys(r).filter(x => !headKeys.includes(x) && !TAIL.includes(x))
    .sort((a, b) => (a === "outzone" ? "rule_uid~" : a).localeCompare(b === "outzone" ? "rule_uid~" : b));
  const out: Rec = {};
  for (const key of [...headKeys, ...rest, ...TAIL]) if (r[key] !== undefined) out[key] = r[key];
  return out;
}
export function toRawLine(r: Record<string, unknown>, timeMs: number): string {
  const host = /CN=([^,]+)/.exec(String(r.originsicname))?.[1] ?? "gw-hq-01";
  const pairs: string[] = [];
  for (const [key, v] of Object.entries(r)) for (const x of Array.isArray(v) ? v : [v]) pairs.push(`${key}:"${String(x).replace(/"/g, '\\"')}"`);
  return `<134>1 ${new Date(timeMs).toISOString().replace(/\.\d{3}Z$/, "Z")} ${host} CheckPoint 26144 - [${pairs.join("; ")}]`;
}

function fromTelemetry(ev: TelemetryEvent, ctx: NativeCtx): NativeLog | null {
  const f = extractFacts(ev, ctx, schema.vendorMatch);
  if (!f) return null;
  if (f.cls === "admin") return null; // gateway admin audit logs are not part of this card.
  let r: Rec;
  if (f.cls === "threat") r = f.threat!.kind === "c2" && f.dir !== "inbound" ? antiBot(f, ctx) : ips(f, ctx);
  else if ((f.cls === "url" || f.cls === "file") && f.dir === "outbound") r = urlFiltering(f, ctx);
  else if (f.dir === "outbound" && !f.blocked && !f.startOnly && APPS[f.app]?.cpApp) r = appControl(f, ctx);
  else r = firewall(f, ctx);
  const record = order(r);
  return { sourceId: "checkpoint", kind: kindOf(record)!, format: "syslog", record, rawLine: toRawLine(record, f.timeMs), timeMs: f.timeMs };
}

// ── use cases ────────────────────────────────────────────────────────────────
export const useCases: UseCase[] = [
  {
    id: "checkpoint.antibot-cnc", title: "Anti-Bot: communication with a C&C site", sourceId: "checkpoint", kinds: ["anti_bot"],
    severity: "critical", mitre: ["T1071", "T1071.001", "T1568"],
    description: "The Anti-Bot blade matched a host talking to known command-and-control infrastructure (malware_action \"Communication with C&C site\"). Even when action is Prevent, the src_machine_name is infected and needs endpoint investigation.",
    logic: "SmartConsole: blade:\"Anti-Bot\" | SPL: sourcetype=cp_log product=\"Anti-Bot\" | stats count values(resource) values(protection_name) by src src_machine_name src_user_name action",
    match: { any: [{ field: "malware_action", op: "icontains", value: "C&C" }, { field: "product", op: "in", value: ["Anti-Bot", "Anti Malware"] }] },
    falsePositives: ["Sinkholed domains contacted by security tools", "Research / sandbox networks"],
  },
  {
    id: "checkpoint.ips-critical-inbound", title: "IPS: critical-severity protection on inbound traffic", sourceId: "checkpoint", kinds: ["ips"],
    severity: "critical", mitre: ["T1190"],
    description: "SmartDefense (IPS) log with severity 4 (Critical) on an inbound connection: an exploit against a published service. Read severity together with confidence_level (5 = High) and industry_reference (CVE).",
    logic: "SmartConsole: blade:IPS AND severity:Critical AND ifdir:inbound | SPL: sourcetype=cp_log product=SmartDefense severity=4 ifdir=inbound",
    match: { all: [{ field: "severity", op: "eq", value: "4" }, { field: "ifdir", op: "eq", value: "inbound" }] },
    falsePositives: ["Authorised penetration tests / external scanners"],
  },
  {
    id: "checkpoint.urlf-block-malicious", title: "URL Filtering blocked a malicious category", sourceId: "checkpoint", kinds: ["url_filtering"],
    severity: "medium", mitre: ["T1189", "T1566.002"],
    description: "URL Filtering Block with matched_category Spyware / Malicious Sites, Phishing, Botnets or Anonymizer. The request was stopped, but something on src_machine_name generated it — check the referring page or process.",
    logic: "SmartConsole: blade:\"URL Filtering\" AND action:Block | SPL: sourcetype=cp_log product=\"URL Filtering\" action IN (Block, Drop) matched_category IN (\"Spyware / Malicious Sites\", Phishing, Botnets, Anonymizer, Uncategorized)",
    match: { all: [{ field: "action", op: "in", value: ["Block", "Drop", "Reject"] }, { field: "matched_category", op: "in", value: ["Spyware / Malicious Sites", "Phishing", "Botnets", "Anonymizer", "High Risk", "Critical Risk", "Uncategorized"] }] },
    falsePositives: ["Ad-network redirects", "Mis-categorised sites"],
  },
  {
    id: "checkpoint.uncategorized-site-allowed", title: "Allowed web access to an uncategorised site", sourceId: "checkpoint", kinds: ["url_filtering"],
    severity: "medium", mitre: ["T1071.001", "T1583.001"],
    description: "Fresh C2 and payload domains are usually Uncategorized in Check Point's URL database. An Accept with matched_category Uncategorized from a workstation is worth pivoting on (appi_name = the domain).",
    logic: "SPL: sourcetype=cp_log product=\"URL Filtering\" action=Accept matched_category=Uncategorized | stats count by src src_machine_name appi_name",
    match: { all: [{ field: "action", op: "eq", value: "Accept" }, { field: "matched_category", op: "eq", value: "Uncategorized" }] },
    falsePositives: ["New legitimate SaaS tenants and marketing domains"],
  },
  {
    id: "checkpoint.script-client-uncategorized", title: "Non-browser client reaching an uncategorised site", sourceId: "checkpoint", kinds: ["url_filtering"],
    severity: "high", mitre: ["T1071.001", "T1059"],
    description: "web_client_type \"Other: …\" (Python-urllib, curl, PowerShell) talking to an Uncategorized domain from a user workstation is how scripted implants beacon — browsers report Chrome/Edge/Firefox.",
    logic: "SPL: sourcetype=cp_log product=\"URL Filtering\" action=Accept app_category=Uncategorized web_client_type=\"Other:*\"",
    match: { all: [{ field: "action", op: "eq", value: "Accept" }, { field: "app_category", op: "eq", value: "Uncategorized" }, { field: "web_client_type", op: "startsWith", value: "Other:" }] },
    falsePositives: ["Developer tooling and package managers hitting new mirrors"],
  },
  {
    id: "checkpoint.large-outbound-transfer", title: "Large upload (client_outbound_bytes ≥ 100 MB)", sourceId: "checkpoint", kinds: ["firewall", "app_control", "url_filtering"],
    severity: "high", mitre: ["T1048", "T1567.002"],
    description: "Accounting logs re-emit a connection with growing counters (same loguid, higher sequencenum). client_outbound_bytes = what the internal client uploaded. ≥100 MB to an External zone — especially to File Storage and Sharing apps — is an exfiltration indicator. Dedupe by loguid and keep the latest.",
    logic: "SPL: sourcetype=cp_log logid=6 outzone=External | dedup loguid sortby -sequencenum | where client_outbound_bytes>=104857600 | table start_time elapsed src src_machine_name dst appi_name client_outbound_bytes client_inbound_bytes",
    match: { all: [{ field: "outzone", op: "eq", value: "External" }, { field: "client_outbound_bytes", op: "gte", value: 104857600 }] },
    falsePositives: ["Sanctioned backup / replication jobs"],
  },
  {
    id: "checkpoint.port-scan", title: "Port scan: one source dropped on many services", sourceId: "checkpoint", kinds: ["firewall"],
    severity: "medium", mitre: ["T1046", "T1595.001"],
    description: "Ten or more distinct destination ports (service) dropped for one src within five minutes — reconnaissance. On Check Point the destination port is `service`, the source port is `s_port`.",
    logic: "SPL: sourcetype=cp_log product=\"VPN-1 & FireWall-1\" action=Drop | bin _time span=5m | stats dc(service) as ports by src _time | where ports>=10",
    match: { field: "action", op: "in", value: ["Drop", "Reject"] },
    threshold: { groupBy: ["src"], count: 10, windowSec: 300, distinct: "service" },
    falsePositives: ["Vulnerability scanners", "Network monitoring"],
  },
  {
    id: "checkpoint.beaconing", title: "Beaconing: repeated accepts from one host to one external server", sourceId: "checkpoint", kinds: ["firewall", "url_filtering", "app_control"],
    severity: "medium", mitre: ["T1071.001", "T1573"],
    description: "Six or more accepted connections from the same src to the same dst within an hour (Uncategorized appi_name, non-browser web_client_type) is a beacon pattern.",
    logic: "SPL: sourcetype=cp_log action=Accept outzone=External | bin _time span=1h | stats count by src dst _time | where count>=6",
    match: { all: [{ field: "action", op: "eq", value: "Accept" }, { field: "outzone", op: "eq", value: "External" }] },
    threshold: { groupBy: ["src", "dst"], count: 6, windowSec: 3600 },
    falsePositives: ["Update agents and SaaS keep-alives"],
  },
  {
    id: "checkpoint.high-risk-country", title: "Accepted traffic to/from a high-risk country", sourceId: "checkpoint",
    severity: "medium", mitre: ["T1071", "T1133"],
    description: "src_country / dst_country hold Check Point's GeoIP country. Accepted sessions with countries the organisation does not do business with are a fast triage pivot.",
    logic: "SPL: sourcetype=cp_log action=Accept (dst_country IN (\"Russian Federation\", Iran, \"North Korea\", Belarus, China) OR src_country IN (…))",
    match: { all: [{ field: "action", op: "eq", value: "Accept" }, { any: [{ field: "dst_country", op: "in", value: HIGH_RISK_COUNTRIES }, { field: "src_country", op: "in", value: HIGH_RISK_COUNTRIES }] }] },
    falsePositives: ["Overseas suppliers or travelling staff"],
  },
  {
    id: "checkpoint.deny-then-allow", title: "External source dropped, then accepted", sourceId: "checkpoint", kinds: ["firewall"],
    severity: "medium", mitre: ["T1190", "T1133"],
    description: "The same external src is dropped by one rule and accepted by another within the hour: the scan found an open door. rule_name / layer_name show which rule let it in.",
    logic: "SPL: sourcetype=cp_log inzone=External | stats dc(action) as verdicts values(action) values(service) values(rule_name) by src | where verdicts>=2",
    match: { field: "inzone", op: "eq", value: "External" },
    threshold: { groupBy: ["src"], count: 2, windowSec: 3600, distinct: "action" },
    falsePositives: ["Partners allowed on one service only"],
  },
  {
    id: "checkpoint.inbound-rdp-accepted", title: "Inbound RDP from the internet accepted", sourceId: "checkpoint", kinds: ["firewall"],
    severity: "high", mitre: ["T1133", "T1021.001"],
    description: "An Accept from the External zone with service 3389 (service_id Remote_Desktop_Protocol) means RDP is published to the internet.",
    logic: "SmartConsole: action:Accept AND service:3389 AND inzone:External",
    match: { all: [{ field: "action", op: "eq", value: "Accept" }, { field: "inzone", op: "eq", value: "External" }, { field: "service", op: "eq", value: "3389" }] },
    falsePositives: ["Vendor jump host restricted by source"],
  },
];

export const source: NativeSource = { schema, fromTelemetry, useCases };
