/**
 * Palo Alto Networks PAN-OS — TRAFFIC / THREAT (incl. URL Filtering, file,
 * spyware, vulnerability) syslog logs, rendered per docs/log-schemas/fw-paloalto.md:
 * a FLAT object keyed by the PAN-OS 11.x variable names (all values strings,
 * FUTURE_USE positions dropped, empty positions omitted) plus the original
 * BSD-syslog + positional CSV line in `rawLine` (117 TRAFFIC / 123 THREAT columns).
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { KindSchema, NativeCtx, NativeLog, NativeSource, SourceSchema, UseCase } from "../types";
import {
  APPS, CATEGORIES, HIGH_RISK_COUNTRIES, bsdHeaderTime, egressIp, extractFacts, isSnat, isoMsOffset, natPort,
  panPrivateLabel, sessionNumber, threatNumber, ymdSlash, type FwFacts,
} from "./firewall-shared";

// ── column order (PAN-OS 11.1 default syslog format) ─────────────────────────
const HEAD = "future_use1,receive_time,serial,type,subtype,future_use2,time_generated,src,dst,natsrc,natdst,rule,srcuser,dstuser,app,vsys,from,to,inbound_if,outbound_if,logset,future_use3,sessionid,repeatcnt,sport,dport,natsport,natdport,flags,proto,action".split(",");
export const TRAFFIC_COLUMNS = HEAD.concat("bytes,bytes_sent,bytes_received,packets,start,elapsed,category,future_use4,seqno,actionflags,srcloc,dstloc,future_use5,pkts_sent,pkts_received,session_end_reason,dg_hier_level_1,dg_hier_level_2,dg_hier_level_3,dg_hier_level_4,vsys_name,device_name,action_source,src_uuid,dst_uuid,tunnelid/imsi,monitortag/imei,parent_session_id,parent_start_time,tunnel,assoc_id,chunks,chunks_sent,chunks_received,rule_uuid,http2_connection,link_change_count,policy_id,link_switches,sdwan_cluster,sdwan_device_type,sdwan_cluster_type,sdwan_site,dynusergroup_name,xff_ip,src_category,src_profile,src_model,src_vendor,src_osfamily,src_osversion,src_host,src_mac,dst_category,dst_profile,dst_model,dst_vendor,dst_osfamily,dst_osversion,dst_host,dst_mac,container_id,pod_namespace,pod_name,src_edl,dst_edl,hostid,serialnumber,src_dag,dst_dag,session_owner,high_res_timestamp,nssai_sst,nssai_sd,subcategory_of_app,category_of_app,technology_of_app,risk_of_app,characteristic_of_app,container_of_app,tunneled_app,is_saas_of_app,sanctioned_state_of_app,offloaded,flow_type,cluster_name".split(","));
export const THREAT_COLUMNS = HEAD.concat("misc,threatid,category,severity,direction,seqno,actionflags,srcloc,dstloc,future_use4,contenttype,pcap_id,filedigest,cloud,url_idx,user_agent,filetype,xff,referer,sender,subject,recipient,reportid,dg_hier_level_1,dg_hier_level_2,dg_hier_level_3,dg_hier_level_4,vsys_name,device_name,future_use5,src_uuid,dst_uuid,http_method,tunnel_id/imsi,monitortag/imei,parent_session_id,parent_start_time,tunnel,thr_category,contentver,future_use6,assoc_id,ppid,http_headers,url_category_list,rule_uuid,http2_connection,dynusergroup_name,xff_ip,src_category,src_profile,src_model,src_vendor,src_osfamily,src_osversion,src_host,src_mac,dst_category,dst_profile,dst_model,dst_vendor,dst_osfamily,dst_osversion,dst_host,dst_mac,container_id,pod_namespace,pod_name,src_edl,dst_edl,hostid,serialnumber,domain_edl,src_dag,dst_dag,partial_hash,high_res_timestamp,reason,justification,nssai_sst,subcategory_of_app,category_of_app,technology_of_app,risk_of_app,characteristic_of_app,container_of_app,tunneled_app,is_saas_of_app,sanctioned_state_of_app,cloud_reportid,flow_type,cluster_name".split(","));

const named = (cols: string[]) => cols.filter(c => !c.startsWith("future_use"));
const COMMON_REQ = ["receive_time", "serial", "type", "subtype", "time_generated", "src", "dst", "rule", "app", "vsys", "from", "to", "sessionid", "repeatcnt", "sport", "dport", "flags", "proto", "action", "seqno", "actionflags", "device_name"];
const TRAFFIC_REQ = [...COMMON_REQ, "bytes", "bytes_sent", "bytes_received", "packets", "start", "elapsed", "category", "pkts_sent", "pkts_received", "session_end_reason"];
const THREAT_REQ = [...COMMON_REQ, "threatid", "category", "severity", "direction"];
const kind = (cols: string[], req: string[]): KindSchema => ({ required: req, optional: named(cols).filter(c => !req.includes(c)) });

export const schema: SourceSchema = {
  sourceId: "paloalto",
  category: "firewall",
  card: "fw-paloalto.md",
  product: "Palo Alto Networks PAN-OS",
  format: "csv",
  vendorMatch: ["palo alto", "pan-os", "panw"],
  telemetrySources: ["firewall", "ids"],
  kinds: { TRAFFIC: kind(TRAFFIC_COLUMNS, TRAFFIC_REQ), THREAT: kind(THREAT_COLUMNS, THREAT_REQ) },
};

export function kindOf(record: Record<string, unknown>): string | null {
  return record.type === "TRAFFIC" || record.type === "THREAT" ? String(record.type) : null;
}

// ── value helpers ────────────────────────────────────────────────────────────
const APP_META: Record<string, [string, string, string, string, string, string]> = {
  ssl: ["encrypted-tunnel", "networking", "browser-based", "4", "used-by-malware,able-to-transfer-file,has-known-vulnerability,tunnel-other-application,pervasive-use", "no"],
  "web-browsing": ["internet-utility", "general-internet", "browser-based", "4", "used-by-malware,able-to-transfer-file,has-known-vulnerability,tunnel-other-application,pervasive-use", "no"],
  mega: ["file-sharing", "general-internet", "browser-based", "4", "able-to-transfer-file,has-known-vulnerability,tunnel-other-application,prone-to-misuse,is-saas", "yes"],
};
const PAN_THREAT_ACTIONS = new Set(["alert", "allow", "deny", "drop", "reset-client", "reset-server", "reset-both", "block-url", "block-ip", "sinkhole", "block-continue", "continue", "block-override", "override", "random-drop"]);
const RISKY_CATS = new Set(["newly-registered-domain", "unknown", "malware", "command-and-control", "phishing", "dynamic-dns", "grayware", "high-risk"]);
const isWeb = (p: number) => [80, 443, 8080, 8443].includes(p);

function panCategory(f: FwFacts): string {
  if (f.categoryPanRaw) return f.categoryPanRaw;
  if (f.category && CATEGORIES[f.category]) return CATEGORIES[f.category].pan;
  return "any";
}
function loc(ip: string, country: string | undefined): string | undefined { return panPrivateLabel(ip) ?? country; }
const digits = (ctx: NativeCtx, seed: string) => `${ctx.int(seed + "a", 100000000, 999999999)}${ctx.int(seed + "b", 100000000, 999999999)}${ctx.int(seed + "c", 1, 9)}`;
function zones(f: FwFacts): [string, string] {
  if (f.dir === "outbound") return ["trust", "untrust"];
  if (f.dir === "internal") return ["trust", "trust"];
  return ["untrust", [80, 443, 8080, 8443, 25].includes(f.dport) ? "dmz" : "trust"];
}
const IFACE: Record<string, string> = { trust: "ethernet1/2", untrust: "ethernet1/1", dmz: "ethernet1/3" };

/** Fields common to TRAFFIC and THREAT. */
function head(f: FwFacts, ctx: NativeCtx, type: "TRAFFIC" | "THREAT", subtype: string): Record<string, string> {
  const t = ymdSlash(f.timeMs);
  const [from, to] = zones(f);
  const r: Record<string, string> = {
    receive_time: t, serial: `0132${ctx.int(`${ctx.companyId}:pan:serial`, 10000000, 99999999)}`, type, subtype, time_generated: t,
    src: f.src, dst: f.dst,
  };
  const firstPacketDrop = type === "TRAFFIC" && subtype === "drop";
  // NAT is applied at session setup: THREAT logs keep it even when the threat
  // engine resets the session; only policy-denied TRAFFIC has no translation.
  const natted = !firstPacketDrop && !(type === "TRAFFIC" && f.blocked);
  if (natted) {
    r.natsrc = isSnat(f) ? egressIp(ctx) : "0.0.0.0";
    r.natdst = isSnat(f) ? f.dst : "0.0.0.0";
  }
  r.rule = f.rule;
  if (f.user && f.dir !== "inbound") r.srcuser = f.user.panUser ?? `${ctx.netbios.toLowerCase()}\\${f.user.sam}`;
  r.app = firstPacketDrop ? "not-applicable" : APPS[f.app]?.pan ?? f.app;
  r.vsys = "vsys1"; r.from = from; r.to = to;
  r.inbound_if = IFACE[from];
  if (!firstPacketDrop) r.outbound_if = IFACE[to] === r.inbound_if ? "ethernet1/4" : IFACE[to];
  r.logset = "Panorama-Fwd";
  r.sessionid = firstPacketDrop ? "0" : String(sessionNumber(f, ctx, 100000, 999999));
  r.repeatcnt = String(Number((f.ev.raw as Record<string, unknown>)?.["repeatcnt"] ?? (f.ev.raw as Record<string, unknown>)?.["pan.repeat_count"] ?? 1) || 1);
  r.sport = String(f.sport); r.dport = String(f.dport);
  r.natsport = natted && isSnat(f) ? String(natPort(f, ctx)) : "0";
  r.natdport = natted ? String(f.dport) : "0";
  r.flags = firstPacketDrop ? "0x0" : type === "THREAT" ? (f.dir === "inbound" ? "0x402000" : "0x403000") : isSnat(f) ? "0x400053" : "0x400050";
  r.proto = f.proto;
  return r;
}
function tail(f: FwFacts, ctx: NativeCtx, r: Record<string, string>, appName: string): void {
  r.rule_uuid = ctx.uuid(`${ctx.companyId}:pan:rule:${f.rule}`);
  r.http2_connection = "0";
  if (f.host?.role === "src") r.src_host = f.host.name;
  if (f.host?.role === "dst") r.dst_host = f.host.name;
  r.high_res_timestamp = isoMsOffset(f.timeMs);
  const meta = APP_META[f.app];
  if (meta && appName !== "not-applicable") {
    [r.subcategory_of_app, r.category_of_app, r.technology_of_app, r.risk_of_app, r.characteristic_of_app] = meta;
  }
  r.tunneled_app = appName;
  if (meta && appName !== "not-applicable") { r.is_saas_of_app = meta[5]; r.sanctioned_state_of_app = "no"; }
}

function traffic(f: FwFacts, ctx: NativeCtx): Record<string, string> {
  // A deny before App-ID ran is a first-packet "drop" (inbound probes); an
  // outbound deny after App-ID identified the app is "deny".
  const subtype = f.blocked ? (f.dir === "inbound" || f.dir === "internal" ? "drop" : "deny") : f.startOnly ? "start" : "end";
  const r = head(f, ctx, "TRAFFIC", subtype);
  r.action = subtype === "drop" ? "drop" : subtype === "deny" ? "deny" : "allow";
  const bo = f.blocked ? 0 : f.bytesOut, bi = f.blocked ? 0 : f.bytesIn;
  const po = f.blocked ? 1 : f.pktsOut, pi = f.blocked ? 0 : f.pktsIn;
  r.bytes = String(bo + bi); r.bytes_sent = String(bo); r.bytes_received = String(bi); r.packets = String(po + pi);
  r.start = ymdSlash(f.timeMs - f.elapsed * 1000); r.elapsed = String(f.elapsed);
  r.category = f.blocked && subtype === "drop" ? "any" : isWeb(f.dport) || f.categoryPanRaw ? panCategory(f) : "any";
  r.seqno = digits(ctx, `${f.ev.id}:seq`); r.actionflags = "0x0";
  const sl = loc(f.src, f.srcCountry), dl = loc(f.dst, f.dstCountry);
  if (sl) r.srcloc = sl;
  if (dl) r.dstloc = dl;
  r.pkts_sent = String(po); r.pkts_received = String(pi);
  r.session_end_reason = f.blocked ? "policy-deny" : f.startOnly ? "n/a" : ((f.ev.raw as Record<string, unknown>)?.["pan.session_end_reason"] as string) ?? "tcp-fin";
  for (const k of ["dg_hier_level_1", "dg_hier_level_2", "dg_hier_level_3", "dg_hier_level_4"]) r[k] = "0";
  r.device_name = f.host?.role === "device" ? f.host.name : "PA-3220-HQ";
  r.action_source = "from-policy";
  r["tunnelid/imsi"] = "0"; r.parent_session_id = "0"; r.tunnel = "N/A"; r.assoc_id = "0";
  r.chunks = "0"; r.chunks_sent = "0"; r.chunks_received = "0";
  tail(f, ctx, r, r.app);
  r.link_change_count = "0";
  r.offloaded = "0"; r.flow_type = "NonProxyTraffic";
  return r;
}

function fileThreat(ext: string): [string, string, string | undefined] {
  switch (ext) {
    case "exe": return ["Windows Executable (EXE)", "pe", "application/x-msdownload"];
    case "dll": return ["Windows Dynamic Link Library (DLL)", "pe", "application/x-msdownload"];
    case "iso": return ["ISO Image File", "iso", "application/x-iso9660-image"];
    case "zip": return ["ZIP Archive", "zip", "application/zip"];
    case "js": case "ps1": case "vbs": case "hta": case "sct": case "bat": return ["Script File", "script", undefined];
    default: return [`${ext.toUpperCase()} File`, ext || "unknown", undefined];
  }
}

function threat(f: FwFacts, ctx: NativeCtx): Record<string, string> {
  const raw = (f.ev.raw ?? {}) as Record<string, unknown>;
  let subtype: string, misc: string | undefined, threatid: string, severity: string, thr: string, action: string;
  const authoredAct = String(raw["pan.action"] ?? raw["event.action"] ?? "").toLowerCase();
  if (f.cls === "threat" && f.threat) {
    const t = f.threat;
    subtype = t.kind === "c2" ? "spyware" : "vulnerability";
    misc = f.urlNoScheme ?? (f.domain ? `${f.domain}/` : undefined);
    const id = t.id ?? String(t.kind === "c2" ? threatNumber(t.name, ctx, 86000, 86999) : threatNumber(t.name, ctx, 30000, 44999));
    threatid = `${t.name}(${id})`;
    severity = t.severity;
    thr = t.kind === "c2" ? (/dns|tunnel/i.test(`${t.name} ${t.catRaw ?? ""}`) ? "dns-c2" : "command-and-control") : t.kind === "bruteforce" ? "brute-force" : t.kind === "scan" ? "info-leak" : t.kind === "sqli" ? "sql-injection" : "code-execution";
    action = f.blocked ? (PAN_THREAT_ACTIONS.has(authoredAct) && authoredAct !== "alert" && authoredAct !== "allow" ? authoredAct : "reset-both") : "alert";
  } else if (f.cls === "file" && f.file) {
    subtype = "file";
    misc = f.file.name;
    const [nm, , ] = fileThreat(f.file.ext ?? "");
    threatid = `${nm}(${threatNumber(nm, ctx, 52000, 52999)})`;
    severity = "low"; thr = "unknown";
    action = f.blocked ? "deny" : "alert";
  } else {
    subtype = "url";
    misc = f.urlNoScheme ?? `${f.domain}/`;
    threatid = "(9999)"; severity = "informational"; thr = "unknown";
    action = f.blocked ? "block-url" : PAN_THREAT_ACTIONS.has(authoredAct) && ["alert", "allow", "continue", "override"].includes(authoredAct) ? authoredAct : "alert";
  }
  const r = head(f, ctx, "THREAT", subtype);
  r.action = action;
  if (misc) r.misc = misc;
  r.threatid = threatid;
  const cat = isWeb(f.dport) || f.categoryPanRaw || f.cls === "url" ? panCategory(f) : "any";
  r.category = cat;
  r.severity = severity;
  r.direction = subtype === "file" && f.dir !== "inbound" && f.method !== "PUT" && f.method !== "POST" ? "server-to-client" : "client-to-server";
  r.seqno = digits(ctx, `${f.ev.id}:seq`); r.actionflags = "0x0";
  const sl = loc(f.src, f.srcCountry), dl = loc(f.dst, f.dstCountry);
  if (sl) r.srcloc = sl;
  if (dl) r.dstloc = dl;
  if (subtype === "file") {
    const [, ft, ct] = fileThreat(f.file?.ext ?? "");
    if (ct) r.contenttype = ct;
    if (f.file?.sha256) r.filedigest = f.file.sha256;
    r.filetype = String(raw["pan.filetype"] ?? ft);
  }
  r.pcap_id = subtype === "url" || subtype === "file" ? "0" : String(ctx.int(`${f.ev.id}:pcap`, 1200000000, 1299999999));
  if (subtype === "url" || f.url) r.url_idx = "1";
  if (f.userAgent) r.user_agent = f.userAgent;
  if (f.referer) r.referer = f.referer;
  r.reportid = "0";
  for (const k of ["dg_hier_level_1", "dg_hier_level_2", "dg_hier_level_3", "dg_hier_level_4"]) r[k] = "0";
  r.device_name = f.host?.role === "device" ? f.host.name : "PA-3220-HQ";
  if (f.method) r.http_method = f.method.toLowerCase();
  r["tunnel_id/imsi"] = "0"; r.parent_session_id = "0"; r.tunnel = "N/A";
  r.thr_category = thr;
  r.contentver = `AppThreat-${ctx.int(`${ctx.companyId}:contentver`, 8900, 8999)}-${ctx.int(`${ctx.companyId}:contentver2`, 9100, 9299)}`;
  r.assoc_id = "0"; r.ppid = "4294967295";
  if (cat !== "any") r.url_category_list = `${cat},${RISKY_CATS.has(cat) ? (cat === "malware" || cat === "phishing" || cat === "command-and-control" ? "high-risk" : "medium-risk") : "low-risk"}`;
  tail(f, ctx, r, r.app);
  r.flow_type = "NonProxyTraffic";
  return r;
}

// ── wire line ────────────────────────────────────────────────────────────────
const FU: Record<string, (r: Record<string, string>) => string> = { future_use1: () => "1", future_use2: () => "2562", future_use3: r => r.receive_time, future_use6: () => "0x0" };
const ALWAYS_QUOTE = new Set(["misc"]);
function csvCell(k: string, v: string): string {
  if (v === "") return "";
  if (ALWAYS_QUOTE.has(k) || /[",]/.test(v)) return `"${v.replace(/"/g, '""')}"`;
  return v;
}
export function toRawLine(r: Record<string, string>, timeMs: number): string {
  const cols = r.type === "TRAFFIC" ? TRAFFIC_COLUMNS : THREAT_COLUMNS;
  const cells = cols.map(c => (c.startsWith("future_use") ? (FU[c]?.(r) ?? "") : csvCell(c, r[c] ?? "")));
  return `<14>${bsdHeaderTime(timeMs)} ${r.device_name} ${cells.join(",")}`;
}

function fromTelemetry(ev: TelemetryEvent, ctx: NativeCtx): NativeLog | null {
  const f = extractFacts(ev, ctx, schema.vendorMatch);
  if (!f) return null;
  if (f.cls === "admin") return null; // PAN SYSTEM/AUTHENTICATION logs are out of this card's scope.
  const record = f.cls === "traffic" ? traffic(f, ctx) : threat(f, ctx);
  return { sourceId: "paloalto", kind: record.type, format: "csv", record, rawLine: toRawLine(record, f.timeMs), timeMs: f.timeMs };
}

// ── use cases ────────────────────────────────────────────────────────────────
const ALLOWED = ["allow", "alert"];
export const useCases: UseCase[] = [
  {
    id: "paloalto.newly-registered-domain", title: "Allowed traffic to a newly-registered domain", sourceId: "paloalto", kinds: ["TRAFFIC", "THREAT"],
    severity: "medium", mitre: ["T1071.001", "T1583.001"],
    description: "PAN-DB puts domains registered in the last ~32 days in the newly-registered-domain category. Malware C2, phishing kits and droppers live on fresh domains, so an internal host completing a session to one deserves a look at the host and the process behind it.",
    logic: "PAN-OS / SPL: sourcetype=pan:traffic OR sourcetype=pan:threat category=\"newly-registered-domain\" action IN (allow, alert) | stats count values(misc) by src, srcuser, dst",
    match: { all: [{ field: "category", op: "eq", value: "newly-registered-domain" }, { field: "action", op: "in", value: ALLOWED }] },
    falsePositives: ["Marketing campaign sites and freshly launched SaaS tenants", "Domains re-registered by the legitimate owner"],
  },
  {
    id: "paloalto.c2-spyware-signature", title: "Anti-Spyware C2 signature matched", sourceId: "paloalto", kinds: ["THREAT"],
    severity: "critical", mitre: ["T1071", "T1071.001"],
    description: "A THREAT log with subtype spyware / thr_category command-and-control means the Anti-Spyware profile recognised the session as malware phoning home. Even when the action is reset-both, the source host is very likely infected and must be investigated on the endpoint.",
    logic: "PAN-OS: ( log_subtype eq spyware ) or ( thr_category eq command-and-control ) | SPL: sourcetype=pan:threat (log_subtype=spyware OR thr_category IN (command-and-control, dns-c2)) | table receive_time src srcuser dst threatid action",
    match: { any: [{ field: "subtype", op: "eq", value: "spyware" }, { field: "thr_category", op: "in", value: ["command-and-control", "dns-c2", "backdoor"] }] },
    falsePositives: ["Security research / sandbox hosts deliberately detonating samples", "Over-broad custom spyware signatures"],
  },
  {
    id: "paloalto.beaconing", title: "Beaconing: repeated sessions from one host to one external server", sourceId: "paloalto", kinds: ["TRAFFIC", "THREAT"],
    severity: "medium", mitre: ["T1071.001", "T1573"],
    description: "Implants check in on a timer. Six or more allowed sessions from the same src to the same external dst within an hour — especially with near-identical bytes_sent and a risky category — is a classic beacon pattern.",
    logic: "SPL: sourcetype=pan:traffic action=allow to=untrust | bin _time span=1h | stats count dc(bytes_sent) as sizes by src dst _time | where count>=6",
    match: { all: [{ field: "to", op: "eq", value: "untrust" }, { field: "action", op: "in", value: ALLOWED }] },
    threshold: { groupBy: ["src", "dst"], count: 6, windowSec: 3600 },
    falsePositives: ["Software update agents, telemetry and monitoring clients", "Chat / collaboration keep-alives"],
  },
  {
    id: "paloalto.large-outbound-transfer", title: "Large outbound transfer (≥100 MB sent)", sourceId: "paloalto", kinds: ["TRAFFIC"],
    severity: "high", mitre: ["T1048", "T1567.002"],
    description: "TRAFFIC end logs carry bytes_sent (client→server). A single session that uploads 100 MB or more to the internet — particularly to file-sharing apps (mega, ftp, ssh) or an unsanctioned SaaS — is a primary exfiltration indicator. Use start + elapsed to place the upload window.",
    logic: "PAN-OS: ( zone.dst eq untrust ) and ( bytes.sent geq 104857600 ) | SPL: sourcetype=pan:traffic to=untrust bytes_sent>=104857600 | eval ratio=bytes_sent/bytes_received | table start elapsed src srcuser dst app bytes_sent ratio",
    match: { all: [{ field: "to", op: "eq", value: "untrust" }, { field: "bytes_sent", op: "gte", value: 104857600 }, { field: "action", op: "eq", value: "allow" }] },
    falsePositives: ["Sanctioned cloud backup jobs", "Large uploads by media / engineering teams to approved storage"],
  },
  {
    id: "paloalto.inbound-critical-exploit", title: "Critical IPS signature on inbound traffic", sourceId: "paloalto", kinds: ["THREAT"],
    severity: "critical", mitre: ["T1190"],
    description: "A vulnerability-subtype THREAT log with severity critical coming from the untrust zone is an exploitation attempt against an exposed service (Log4Shell, VPN appliance RCE …). Check whether the action blocked it and whether the target shows follow-on activity.",
    logic: "PAN-OS: ( subtype eq vulnerability ) and ( severity eq critical ) and ( zone.src eq untrust ) | SPL: sourcetype=pan:threat log_subtype=vulnerability severity=critical from=untrust",
    match: { all: [{ field: "subtype", op: "eq", value: "vulnerability" }, { field: "severity", op: "eq", value: "critical" }, { field: "from", op: "eq", value: "untrust" }] },
    falsePositives: ["Authorised external vulnerability scans / penetration tests"],
  },
  {
    id: "paloalto.port-scan", title: "Port scan: one source denied on many destination ports", sourceId: "paloalto", kinds: ["TRAFFIC"],
    severity: "medium", mitre: ["T1046", "T1595.001"],
    description: "Ten or more distinct dport values denied/dropped for the same src within five minutes is horizontal/vertical scanning — reconnaissance before an attack.",
    logic: "SPL: sourcetype=pan:traffic action IN (deny, drop) | bin _time span=5m | stats dc(dport) as ports values(dst) by src _time | where ports>=10",
    match: { field: "action", op: "in", value: ["deny", "drop", "reset-both", "reset-client", "reset-server"] },
    threshold: { groupBy: ["src"], count: 10, windowSec: 300, distinct: "dport" },
    falsePositives: ["Internal vulnerability scanners", "Misconfigured monitoring probing closed ports"],
  },
  {
    id: "paloalto.deny-then-allow", title: "External source denied, then allowed", sourceId: "paloalto", kinds: ["TRAFFIC"],
    severity: "medium", mitre: ["T1190", "T1133"],
    description: "The same external src first hits a deny rule and within the hour gets an allowed session: the attacker probed until finding an exposed service. Review which rule allowed it.",
    logic: "SPL: sourcetype=pan:traffic from=untrust | stats dc(action) as verdicts values(action) values(dport) values(rule) by src | where verdicts>=2",
    match: { field: "from", op: "eq", value: "untrust" },
    threshold: { groupBy: ["src"], count: 2, windowSec: 3600, distinct: "action" },
    falsePositives: ["Partners whose traffic is allowed on one port and denied on others"],
  },
  {
    id: "paloalto.url-block-malicious", title: "URL Filtering blocked a malicious category", sourceId: "paloalto", kinds: ["THREAT"],
    severity: "medium", mitre: ["T1189", "T1566.002"],
    description: "A THREAT/url log with action block-url and a category such as malware, phishing, command-and-control or newly-registered-domain shows a user or process reached for a known-bad URL. The block worked, but the source host may already be compromised (what generated the request?).",
    logic: "PAN-OS: ( subtype eq url ) and ( action eq block-url ) and ( category eq malware or category eq phishing … ) | SPL: sourcetype=pan:threat log_subtype=url action=block-url category IN (malware, phishing, command-and-control, newly-registered-domain)",
    match: { all: [{ field: "subtype", op: "eq", value: "url" }, { field: "action", op: "eq", value: "block-url" }, { field: "category", op: "in", value: ["malware", "phishing", "command-and-control", "grayware", "newly-registered-domain", "dynamic-dns"] }] },
    falsePositives: ["Users clicking ads that redirect through blocked domains", "Mis-categorised domains (submit a change request to PAN-DB)"],
  },
  {
    id: "paloalto.high-risk-country", title: "Allowed session to/from a high-risk country", sourceId: "paloalto", kinds: ["TRAFFIC", "THREAT"],
    severity: "medium", mitre: ["T1071", "T1133"],
    description: "srcloc / dstloc carry the GeoIP country. Allowed traffic with a country the business has no presence in (sanctioned or high-abuse regions) is a common triage pivot for C2 and remote-access abuse.",
    logic: "SPL: sourcetype=pan:* action IN (allow, alert) (dstloc IN (\"Russian Federation\", Iran, \"North Korea\", Belarus, China) OR srcloc IN (…))",
    match: { all: [{ field: "action", op: "in", value: ALLOWED }, { any: [{ field: "dstloc", op: "in", value: HIGH_RISK_COUNTRIES }, { field: "srcloc", op: "in", value: HIGH_RISK_COUNTRIES }] }] },
    falsePositives: ["Legitimate overseas vendors or travelling staff"],
  },
  {
    id: "paloalto.executable-from-risky-category", title: "Executable or script downloaded from a risky URL category", sourceId: "paloalto", kinds: ["THREAT"],
    severity: "high", mitre: ["T1105", "T1204.002"],
    description: "File-subtype THREAT logs record files crossing the firewall (filetype, filedigest = SHA-256). A PE or script coming from an unknown / newly-registered / malware category site is a typical first-stage download — pivot on filedigest in the EDR.",
    logic: "SPL: sourcetype=pan:threat log_subtype=file filetype IN (pe, script) category IN (unknown, newly-registered-domain, malware, shareware-and-freeware) | table src srcuser misc filedigest category",
    match: { all: [{ field: "subtype", op: "eq", value: "file" }, { field: "filetype", op: "in", value: ["pe", "script", "iso"] }, { field: "category", op: "in", value: ["unknown", "newly-registered-domain", "malware", "shareware-and-freeware", "shareware-download", "computer-and-internet-info"] }] },
    falsePositives: ["Developers downloading tools from small project sites", "Installers from CDNs that PAN-DB has not categorised yet"],
  },
  {
    id: "paloalto.inbound-rdp-allowed", title: "Inbound RDP from the internet allowed", sourceId: "paloalto", kinds: ["TRAFFIC"],
    severity: "high", mitre: ["T1133", "T1021.001"],
    description: "An allowed TRAFFIC log from the untrust zone on dport 3389 (app ms-rdp) means Remote Desktop is exposed to the internet — the top initial-access vector for ransomware crews.",
    logic: "PAN-OS: ( zone.src eq untrust ) and ( app eq ms-rdp or port.dst eq 3389 ) and ( action eq allow )",
    match: { all: [{ field: "from", op: "eq", value: "untrust" }, { field: "action", op: "eq", value: "allow" }, { any: [{ field: "dport", op: "eq", value: "3389" }, { field: "app", op: "eq", value: "ms-rdp" }] }] },
    falsePositives: ["Approved vendor jump hosts restricted by source address"],
  },
];

export const source: NativeSource = { schema, fromTelemetry, useCases };
