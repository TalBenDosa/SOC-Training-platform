/**
 * Cisco Secure Firewall Threat Defense (FTD 7.x) security-event syslog —
 * 430001 intrusion, 430002 connection start, 430003 connection end, 430004 file —
 * rendered per docs/log-schemas/fw-cisco.md: a FLAT object with the Cisco key
 * names exactly as emitted (incl. the space in "Prefilter Policy"), all values
 * strings, plus header parts `timestamp`, `device_id`, `Level`, `Message_number`.
 * `rawLine` = `<ts> <device> : %FTD-<Level>-<id>: Key: Value, Key: Value …`.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { KindSchema, NativeCtx, NativeLog, NativeSource, SourceSchema, UseCase } from "../types";
import { APPS, CATEGORIES, egressIp, extractFacts, isSnat, isoZ, natPort, sessionNumber, threatNumber, type FwFacts, type Sev } from "./firewall-shared";

const HDR = ["timestamp", "device_id", "Level", "Message_number"];
const IDS = ["DeviceUUID", "InstanceID", "FirstPacketSecond", "ConnectionID"];
const PATH = ["IngressInterface", "EgressInterface", "IngressZone", "EgressZone", "IngressVRF", "EgressVRF"];
const CONN_OPT = ["AccessControlRuleReason", "SrcPort", "DstPort", "ICMPType", "ICMPCode", ...PATH, "ACPolicy", "AccessControlRuleName", "Prefilter Policy", "NAPPolicy", "SSLPolicy",
  "User", "ApplicationProtocol", "Client", "ClientVersion", "WebApplication", "UserAgent", "ClientAppDetector", "InitiatorBytes", "ResponderBytes",
  "InitiatorPackets", "ResponderPackets", "ConnectionDuration", "URL", "URLCategory", "URLReputation", "ReferencedHost", "HTTPReferer", "HTTPResponse",
  "URLSICategory", "IPReputationSICategory", "DNSSICategory", "SecIntMatchingIP", "DNSQuery", "DNSRecordType", "DNSResponseType", "DNS_TTL", "DNS_Sinkhole",
  "NAT_InitiatorIP", "NAT_InitiatorPort", "NAT_ResponderIP", "NAT_ResponderPort", "SSLServerName", "SSLVersion", "SSLCipherSuite", "SSLActualAction", "SSLFlowStatus"];
const conn = (): KindSchema => ({ required: [...HDR, "EventPriority", ...IDS, "AccessControlRuleAction", "SrcIP", "DstIP", "Protocol"], optional: CONN_OPT });

export const schema: SourceSchema = {
  sourceId: "cisco_ftd",
  category: "firewall",
  card: "fw-cisco.md",
  product: "Cisco Secure Firewall Threat Defense",
  format: "syslog",
  vendorMatch: ["firepower", "cisco ftd", "threat defense", "cisco secure firewall"],
  telemetrySources: ["firewall", "ids"],
  kinds: {
    "430001": {
      required: [...HDR, ...IDS, "SrcIP", "DstIP", "Protocol", "Priority", "GID", "SID", "Revision", "Message"],
      optional: ["SrcPort", "DstPort", ...PATH, "Classification", "User", "ApplicationProtocol", "Client", "WebApplication", "IntrusionPolicy", "ACPolicy", "AccessControlRuleName", "NAPPolicy", "InlineResult"],
    },
    "430002": conn(),
    "430003": conn(),
    // 430004 (file event) — card §3.3 is brief: we emit only the documented file keys
    // (no SHA_Disposition / ThreatName, whose wording is UNVERIFIED) plus the connection identity.
    "430004": {
      required: [...HDR, ...IDS, "SrcIP", "DstIP", "FileDirection", "FileAction", "FileName", "FileSHA256"],
      optional: ["SrcPort", "DstPort", "Protocol", ...PATH, "FileType", "FilePolicy", "FileSandboxStatus", "URI", "SHA_Disposition", "ThreatName", "ApplicationProtocol", "Client", "User", "ACPolicy", "AccessControlRuleName"],
    },
  },
};

export function kindOf(record: Record<string, unknown>): string | null {
  const m = String(record.Message_number ?? "");
  return schema.kinds[m] && "DeviceUUID" in record ? m : null;
}

// ── helpers ──────────────────────────────────────────────────────────────────
type Rec = Record<string, string>;
function ifaces(f: FwFacts): [string, string] {
  if (f.dir === "outbound") return ["inside", "outside"];
  if (f.dir === "internal") return ["inside", "servers"];
  return ["outside", [80, 443, 8080, 8443, 25].includes(f.dport) ? "dmz" : "inside"];
}
function urlRep(cat: string | undefined): string {
  if (cat && ["malware", "command-and-control", "phishing"].includes(cat)) return "Untrusted";
  if (cat && ["newly-registered-domain", "newly-observed-domain", "unknown", "dynamic-dns"].includes(cat)) return "Questionable";
  if (cat === "online-storage-and-backup") return "Neutral";
  return "Favorable";
}
/** OpenAppID protocol; HTTP App-ID seen on 443/8443 is TLS on the wire. */
function appProto(f: FwFacts): string | undefined {
  const p = APPS[f.app]?.ftdProto;
  if (!p) return undefined;
  return p === "HTTP" && [443, 8443].includes(f.dport) ? "HTTPS" : p;
}
function head(f: FwFacts, ctx: NativeCtx, msg: string): Rec {
  return {
    timestamp: isoZ(f.timeMs), device_id: f.host?.role === "device" ? f.host.name : "FTD-HQ-01", Level: "1", Message_number: msg,
  };
}
function ids(f: FwFacts, ctx: NativeCtx, r: Rec): void {
  r.DeviceUUID = ctx.uuid(`${ctx.companyId}:ftd:device`);
  r.InstanceID = String(ctx.int(`${f.ev.id}:ftd:inst`, 1, 8));
  r.FirstPacketSecond = isoZ(f.timeMs - f.elapsed * 1000);
  r.ConnectionID = String(sessionNumber(f, ctx, 1000, 65535));
}
function tuple(f: FwFacts, r: Rec): void {
  r.SrcIP = f.src; r.DstIP = f.dst;
  if (f.proto !== "icmp") { r.SrcPort = String(f.sport); r.DstPort = String(f.dport); }
  r.Protocol = f.proto;
}
function path(f: FwFacts, r: Rec, vrf = true): void {
  const [i, o] = ifaces(f);
  r.IngressInterface = i; r.EgressInterface = o; r.IngressZone = i.toUpperCase(); r.EgressZone = o.toUpperCase();
  if (vrf) { r.IngressVRF = "Global"; r.EgressVRF = "Global"; }
}
function user(f: FwFacts, ctx: NativeCtx): string {
  return f.user && f.dir !== "inbound" ? `${ctx.netbios}\\${f.user.sam}` : "No Authentication Required";
}
function client(f: FwFacts, r: Rec): void {
  if (f.userAgent && /Chrome\/([\d.]+)/.test(f.userAgent) && f.cls !== "traffic") {
    r.UserAgent = f.userAgent; r.Client = "Chrome"; r.ClientVersion = /Chrome\/([\d.]+)/.exec(f.userAgent)![1];
  } else if (f.app === "ssl" || APPS[f.app]?.ftdProto === "HTTPS") r.Client = "SSL client";
}

function connection(f: FwFacts, ctx: NativeCtx): Rec {
  const end = !f.blocked && !f.startOnly;
  const r = head(f, ctx, end ? "430003" : "430002");
  const si = f.blocked && f.siCategory && f.cls !== "url";
  r.EventPriority = si ? "High" : "Low";
  ids(f, ctx, r);
  r.AccessControlRuleAction = f.blocked ? "Block" : "Allow";
  if (si) r.AccessControlRuleReason = "IP Block";
  tuple(f, r); path(f, r);
  r.ACPolicy = "HQ-Access-Policy";
  if (!si) r.AccessControlRuleName = f.rule;
  r["Prefilter Policy"] = "Default Prefilter Policy";
  r.User = user(f, ctx);
  client(f, r);
  const a = APPS[f.app];
  if (appProto(f) && !(f.blocked && !f.url)) r.ApplicationProtocol = appProto(f)!;
  if (a?.ftdWebApp && !f.blocked) r.WebApplication = a.ftdWebApp;
  if (end) r.ConnectionDuration = String(f.elapsed);
  if (f.blocked && f.cls === "url") {
    r.InitiatorPackets = String(ctx.int(`${f.ev.id}:ip`, 3, 6)); r.ResponderPackets = "2";
    r.InitiatorBytes = String(ctx.int(`${f.ev.id}:ib`, 520, 900)); r.ResponderBytes = "132";
  } else if (f.blocked) {
    r.InitiatorPackets = "1"; r.ResponderPackets = "0"; r.InitiatorBytes = f.proto === "udp" ? "74" : "66"; r.ResponderBytes = "0";
  } else {
    r.InitiatorPackets = String(f.pktsOut); r.ResponderPackets = String(f.pktsIn);
    r.InitiatorBytes = String(f.bytesOut); r.ResponderBytes = String(f.bytesIn);
  }
  r.NAPPolicy = "Balanced Security and Connectivity";
  if (f.referer) r.HTTPReferer = f.referer;
  if (f.domain && f.blocked) r.ReferencedHost = f.domain;
  if (f.domain) {
    const cat = (f.category && CATEGORIES[f.category]) || CATEGORIES["computer-and-internet-info"];
    if (f.blocked) { r.URL = f.url ?? `https://${f.domain}`; r.URLCategory = cat.talos; r.URLReputation = urlRep(f.category); }
    else { r.URLCategory = cat.talos; r.URLReputation = urlRep(f.category); r.URL = f.url ?? `https://${f.domain}`; }
  }
  if (si) { r.IPReputationSICategory = f.siCategory!; r.SecIntMatchingIP = f.dir === "inbound" ? "Source" : "Destination"; }
  if (!f.blocked && isSnat(f)) {
    r.NAT_InitiatorIP = egressIp(ctx); r.NAT_InitiatorPort = String(natPort(f, ctx));
    r.NAT_ResponderIP = f.dst; r.NAT_ResponderPort = String(f.dport);
  }
  if (end && r.ApplicationProtocol) r.ClientAppDetector = "AppID";
  return r;
}

const CLASSIFICATION: Record<string, string> = {
  c2: "A Network Trojan was Detected", exploit: "Attempted User Privilege Gain", bruteforce: "Misc Attack",
  scan: "Detection of a Network Scan", sqli: "Web Application Attack",
};
const PRIO: Record<Sev, string> = { critical: "1", high: "1", medium: "2", low: "3", informational: "3" };
function intrusion(f: FwFacts, ctx: NativeCtx): Rec {
  const t = f.threat!;
  const r = head(f, ctx, "430001");
  ids(f, ctx, r); tuple(f, r); path(f, r, false);
  // Snort classtype priorities: network-scan detections are never priority 1.
  r.Priority = t.kind === "scan" ? (PRIO[t.severity] === "1" ? "2" : "3") : PRIO[t.severity];
  r.GID = "1";
  r.SID = String(Number(t.id) || threatNumber(t.name, ctx, 50000, 65000));
  r.Revision = String(ctx.int(`ftd:rev:${t.name}`, 1, 12));
  r.Message = t.name;
  r.Classification = CLASSIFICATION[t.kind];
  r.User = user(f, ctx);
  if (appProto(f)) r.ApplicationProtocol = appProto(f)!;
  r.IntrusionPolicy = "HQ-Inline-IPS";
  r.ACPolicy = "HQ-Access-Policy";
  r.AccessControlRuleName = f.rule;
  r.NAPPolicy = "Balanced Security and Connectivity";
  r.InlineResult = f.blocked ? "Dropped" : "Would have dropped";
  r.IngressVRF = "Global"; r.EgressVRF = "Global";
  return r;
}

const FILETYPE: Record<string, string> = { exe: "MSEXE", dll: "MSEXE", iso: "ISO", zip: "ZIP", pdf: "PDF" };
function fileEvent(f: FwFacts, ctx: NativeCtx): Rec {
  const file = f.file!;
  const r = head(f, ctx, "430004");
  ids(f, ctx, r); tuple(f, r); path(f, r, false);
  const upload = f.dir === "inbound" || f.method === "PUT" || f.method === "POST";
  r.FileDirection = upload ? "Upload" : "Download";
  r.FileAction = f.blocked ? "Block" : ["exe", "dll", "js", "ps1", "vbs", "hta", "iso"].includes(file.ext ?? "") ? "Malware Cloud Lookup" : "Detect";
  r.FileName = file.name;
  if (FILETYPE[file.ext ?? ""]) r.FileType = FILETYPE[file.ext!];
  if (file.sha256) r.FileSHA256 = file.sha256;
  r.FilePolicy = "HQ-File-Policy";
  if (f.url) r.URI = f.url;
  if (appProto(f)) r.ApplicationProtocol = appProto(f)!;
  r.User = user(f, ctx);
  r.ACPolicy = "HQ-Access-Policy";
  r.AccessControlRuleName = f.rule;
  return r;
}

export function toRawLine(r: Record<string, unknown>): string {
  const body = Object.entries(r).filter(([key]) => !HDR.includes(key)).map(([key, v]) => `${key}: ${v}`).join(", ");
  return `${r.timestamp} ${r.device_id} : %FTD-${r.Level}-${r.Message_number}: ${body}`;
}

function fromTelemetry(ev: TelemetryEvent, ctx: NativeCtx): NativeLog | null {
  const f = extractFacts(ev, ctx, schema.vendorMatch);
  if (!f) return null;
  if (f.cls === "admin") return null; // FTD platform/admin syslog is outside the 43000x card.
  let record: Rec;
  if (f.cls === "threat") record = intrusion(f, ctx);
  else if (f.cls === "file" && f.file?.sha256) record = fileEvent(f, ctx);
  else record = connection(f, ctx);
  return { sourceId: "cisco_ftd", kind: record.Message_number, format: "syslog", record, rawLine: toRawLine(record), timeMs: f.timeMs };
}

// ── use cases ────────────────────────────────────────────────────────────────
const MALICIOUS_CATS = ["Malware Sites", "Phishing", "Newly Seen Domains", "Malicious Sites", "Uncategorized"];
export const useCases: UseCase[] = [
  {
    id: "cisco_ftd.intrusion-priority1-inbound", title: "Priority-1 intrusion event from the outside", sourceId: "cisco_ftd", kinds: ["430001"],
    severity: "critical", mitre: ["T1190"],
    description: "430001 with Priority 1 arriving on the OUTSIDE zone is an exploit attempt against a published service (e.g. SID 58722 Log4j). InlineResult Dropped = blocked; \"Would have dropped\" = the IPS is only detecting and the payload reached the server.",
    logic: "FMC: Analysis › Intrusions › Events, Priority = high, Ingress Security Zone = OUTSIDE | SPL: sourcetype=cisco:ftd message_id=430001 Priority=1 IngressZone=OUTSIDE | table _time SrcIP DstIP SID Message InlineResult",
    match: { all: [{ field: "Priority", op: "eq", value: "1" }, { field: "IngressZone", op: "eq", value: "OUTSIDE" }] },
    falsePositives: ["Authorised external pen-tests / scanners"],
  },
  {
    id: "cisco_ftd.intrusion-outbound-trojan", title: "Intrusion rule: internal host speaking a C2 / trojan protocol", sourceId: "cisco_ftd", kinds: ["430001"],
    severity: "critical", mitre: ["T1071", "T1071.001"],
    description: "An intrusion event on a connection initiated from INSIDE to OUTSIDE, classified \"A Network Trojan was Detected\", means an implant is calling home. The SrcIP host is compromised regardless of InlineResult.",
    logic: "SPL: sourcetype=cisco:ftd message_id=430001 IngressZone=INSIDE EgressZone=OUTSIDE (Classification=\"A Network Trojan was Detected\" OR Message=\"MALWARE-CNC*\")",
    match: { all: [{ field: "IngressZone", op: "eq", value: "INSIDE" }, { field: "EgressZone", op: "eq", value: "OUTSIDE" }, { field: "Classification", op: "eq", value: "A Network Trojan was Detected" }] },
    falsePositives: ["Malware-analysis sandboxes on the inside network"],
  },
  {
    id: "cisco_ftd.security-intelligence-block", title: "Security Intelligence block (IP / URL / DNS feed)", sourceId: "cisco_ftd", kinds: ["430002"],
    severity: "medium", mitre: ["T1071", "T1090.003"],
    description: "AccessControlRuleReason IP Block / URL Block / DNS Block means the connection matched a Talos Security-Intelligence feed (Tor exit nodes, CnC, malware, scanners). The SI category (IPReputationSICategory / URLSICategory) tells you which feed; SecIntMatchingIP which side matched.",
    logic: "SPL: sourcetype=cisco:ftd message_id=430002 AccessControlRuleReason IN (\"IP Block\", \"URL Block\", \"DNS Block\") | stats count by SrcIP DstIP IPReputationSICategory URLSICategory",
    match: { field: "AccessControlRuleReason", op: "in", value: ["IP Block", "URL Block", "DNS Block"] },
    falsePositives: ["Shared hosting IPs that once hosted malware"],
  },
  {
    id: "cisco_ftd.url-block-malicious", title: "URL-category block to a malicious category", sourceId: "cisco_ftd", kinds: ["430002"],
    severity: "medium", mitre: ["T1189", "T1566.002"],
    description: "A 430002 Block whose URLCategory is Malware Sites / Phishing / Newly Seen Domains (or URLReputation Untrusted): a user or process tried to reach a bad URL. Blocked connections are logged only at start (430002).",
    logic: "SPL: sourcetype=cisco:ftd message_id=430002 AccessControlRuleAction=Block (URLCategory IN (\"Malware Sites\", Phishing, \"Newly Seen Domains\") OR URLReputation=Untrusted)",
    match: { all: [{ field: "AccessControlRuleAction", op: "in", value: ["Block", "Block with reset"] }, { any: [{ field: "URLCategory", op: "in", value: MALICIOUS_CATS }, { field: "URLReputation", op: "eq", value: "Untrusted" }] }] },
    falsePositives: ["Ad-network redirects", "Mis-categorised domains"],
  },
  {
    id: "cisco_ftd.newly-seen-domain-allowed", title: "Allowed connection to a Newly Seen Domain", sourceId: "cisco_ftd", kinds: ["430002", "430003"],
    severity: "medium", mitre: ["T1071.001", "T1583.001"],
    description: "Talos puts brand-new domains in \"Newly Seen Domains\" (reputation usually Questionable). An allowed connection to one from a workstation is a C2 / payload-hosting lead.",
    logic: "SPL: sourcetype=cisco:ftd AccessControlRuleAction=Allow URLCategory=\"Newly Seen Domains\" | stats count by SrcIP User URL",
    match: { all: [{ field: "AccessControlRuleAction", op: "eq", value: "Allow" }, { field: "URLCategory", op: "eq", value: "Newly Seen Domains" }] },
    falsePositives: ["New SaaS tenants and marketing domains"],
  },
  {
    id: "cisco_ftd.large-outbound-transfer", title: "Large upload: InitiatorBytes ≥ 100 MB to OUTSIDE", sourceId: "cisco_ftd", kinds: ["430003"],
    severity: "high", mitre: ["T1048", "T1567.002"],
    description: "FTD counts bytes by role: InitiatorBytes = sent by the host that opened the connection. An internal initiator sending ≥100 MB to OUTSIDE (WebApplication MEGA, FTP, SFTP …) is an exfiltration indicator; FirstPacketSecond + ConnectionDuration give the window.",
    logic: "SPL: sourcetype=cisco:ftd message_id=430003 IngressZone=INSIDE EgressZone=OUTSIDE InitiatorBytes>=104857600 | table FirstPacketSecond ConnectionDuration SrcIP User DstIP WebApplication InitiatorBytes ResponderBytes",
    match: { all: [{ field: "EgressZone", op: "eq", value: "OUTSIDE" }, { field: "InitiatorBytes", op: "gte", value: 104857600 }] },
    falsePositives: ["Approved backup / partner file transfers"],
  },
  {
    id: "cisco_ftd.port-scan", title: "Port scan: many blocked destination ports from one source", sourceId: "cisco_ftd", kinds: ["430002"],
    severity: "medium", mitre: ["T1046", "T1595.001"],
    description: "Ten or more distinct DstPort values blocked for the same SrcIP in five minutes is scanning.",
    logic: "SPL: sourcetype=cisco:ftd message_id=430002 AccessControlRuleAction=Block | bin _time span=5m | stats dc(DstPort) as ports by SrcIP _time | where ports>=10",
    match: { field: "AccessControlRuleAction", op: "in", value: ["Block", "Block with reset"] },
    threshold: { groupBy: ["SrcIP"], count: 10, windowSec: 300, distinct: "DstPort" },
    falsePositives: ["Vulnerability scanners"],
  },
  {
    id: "cisco_ftd.beaconing", title: "Beaconing: repeated connections from one host to one external server", sourceId: "cisco_ftd", kinds: ["430002", "430003"],
    severity: "medium", mitre: ["T1071.001", "T1573"],
    description: "Six or more allowed connections (new ConnectionIDs) from the same SrcIP to the same DstIP within an hour, with tiny symmetric byte counts and a Questionable reputation, is a beacon.",
    logic: "SPL: sourcetype=cisco:ftd message_id=430003 AccessControlRuleAction=Allow EgressZone=OUTSIDE | bin _time span=1h | stats count by SrcIP DstIP _time | where count>=6",
    match: { all: [{ field: "AccessControlRuleAction", op: "eq", value: "Allow" }, { field: "EgressZone", op: "eq", value: "OUTSIDE" }] },
    threshold: { groupBy: ["SrcIP", "DstIP"], count: 6, windowSec: 3600 },
    falsePositives: ["Update agents, telemetry clients"],
  },
  {
    id: "cisco_ftd.inbound-remote-admin-multi-host", title: "Same external source reaching SSH/RDP on several internal hosts", sourceId: "cisco_ftd", kinds: ["430002", "430003"],
    severity: "high", mitre: ["T1110.001", "T1133", "T1021.004"],
    description: "One OUTSIDE SrcIP allowed to SSH (22) or RDP (3389) on two or more different DstIPs within 15 minutes: credential guessing or spraying across exposed management services.",
    logic: "SPL: sourcetype=cisco:ftd AccessControlRuleAction=Allow IngressZone=OUTSIDE DstPort IN (22, 3389) | bin _time span=15m | stats dc(DstIP) as hosts values(DstIP) by SrcIP _time | where hosts>=2",
    match: { all: [{ field: "AccessControlRuleAction", op: "eq", value: "Allow" }, { field: "IngressZone", op: "eq", value: "OUTSIDE" }, { field: "DstPort", op: "in", value: ["22", "3389"] }] },
    threshold: { groupBy: ["SrcIP"], count: 2, windowSec: 900, distinct: "DstIP" },
    falsePositives: ["Managed-service provider jump hosts"],
  },
  {
    id: "cisco_ftd.executable-download", title: "Executable file downloaded through the firewall", sourceId: "cisco_ftd", kinds: ["430004"],
    severity: "medium", mitre: ["T1105", "T1204.002"],
    description: "File event 430004 with FileType MSEXE and FileDirection Download: a Windows executable entered the network. Pivot on FileSHA256 in the EDR and check the URI's domain age.",
    logic: "SPL: sourcetype=cisco:ftd message_id=430004 FileType=MSEXE FileDirection=Download | table _time SrcIP User FileName FileSHA256 URI",
    match: { all: [{ field: "FileDirection", op: "eq", value: "Download" }, { field: "FileType", op: "in", value: ["MSEXE", "ISO"] }] },
    falsePositives: ["Software updates and IT deployments from vendor sites"],
  },
  {
    id: "cisco_ftd.deny-then-allow", title: "Outside source blocked, then allowed", sourceId: "cisco_ftd", kinds: ["430002", "430003"],
    severity: "medium", mitre: ["T1190", "T1133"],
    description: "The same OUTSIDE SrcIP gets both a Block and an Allow within an hour — probing that found an open service. AccessControlRuleName shows which rule let it in.",
    logic: "SPL: sourcetype=cisco:ftd IngressZone=OUTSIDE | stats dc(AccessControlRuleAction) as verdicts values(AccessControlRuleAction) values(DstPort) by SrcIP | where verdicts>=2",
    match: { field: "IngressZone", op: "eq", value: "OUTSIDE" },
    threshold: { groupBy: ["SrcIP"], count: 2, windowSec: 3600, distinct: "AccessControlRuleAction" },
    falsePositives: ["Partners allowed on one service only"],
  },
];

export const source: NativeSource = { schema, fromTelemetry, useCases };
