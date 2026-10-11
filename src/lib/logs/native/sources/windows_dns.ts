/**
 * Microsoft Windows DNS Server — native module (card: docs/log-schemas/dns-windows.md).
 *
 * Record: the `Microsoft-Windows-DNSServer/Analytical` event as a FLAT object — Event
 * XML `System` names (ProviderName, EventID, … Computer, UserID) + every `EventData`
 * `Data Name` unchanged; EventData values are strings, System numerics are numbers,
 * exactly as the card shows. A query with a known outcome is rendered as event 257
 * (RESPONSE_SUCCESS, carries RCODE); a query with no authored outcome as event 256
 * (QUERY_RECEIVED). `rawLine` = the same transaction as a DNS **debug log** line
 * (server-local time, `(len)label(0)` wire name), as the card's §4.4.
 *
 * Category-wide: Infoblox-authored (and vendor-less) DNS events render here too — the
 * facts (client, name, type, rcode, answer) are vendor-neutral. Windows DNS has no RPZ
 * concept, so an Infoblox RPZ action is shown only through its effect (RCODE).
 */
import type { NativeSource, NativeLog, KindSchema, UseCase, NativeCtx } from "../types";
import type { TelemetryEvent } from "@/lib/sim/types";
import { dnsFacts, QTYPE_NUM, RCODE_NUM, serverIpFor, debugStamp, dnsMessage, SUSPICIOUS_TLDS, LOOKALIKE_RE } from "./_dnsShared";

const SYSTEM = ["ProviderName", "EventID", "Version", "Level", "Task", "Opcode", "Keywords", "TimeCreated", "EventRecordID", "ProcessID", "ThreadID", "Channel", "Computer", "UserID"];
// Card samples carry the original line under "raw" (platform representation "+ raw").
const RAW = ["raw"];

const kinds: Record<string, KindSchema> = {
  // QUERY_RECEIVED
  "256": {
    required: [...SYSTEM, "TCP", "InterfaceIP", "Source", "RD", "QNAME", "QTYPE", "XID", "Port", "Flags", "ServerScope", "CacheScope", "BufferSize", "PacketData"],
    optional: [...RAW, "PolicyName"],
  },
  // RESPONSE_SUCCESS
  "257": {
    required: [...SYSTEM, "TCP", "InterfaceIP", "Destination", "AA", "AD", "QNAME", "QTYPE", "XID", "DNSSEC", "RCODE", "Port", "Flags", "Scope", "Zone", "PolicyName", "BufferSize", "PacketData"],
    optional: [...RAW],
  },
  // RECURSE_QUERY_OUT
  "260": {
    required: [...SYSTEM, "TCP", "Destination", "InterfaceIP", "RD", "QNAME", "QTYPE", "XID", "Port", "Flags", "ServerScope", "CacheScope", "PolicyName", "BufferSize", "PacketData"],
    optional: [...RAW],
  },
  // Audit: record created (admin) / via dynamic update. Data Name spellings are UNVERIFIED on the card
  // (positional templates) — kept for card-sample validation only; the converter never emits audit events.
  "515": { required: [...SYSTEM, "Type", "NAME", "TTL", "RDATA", "Zone"], optional: [...RAW, "BufferSize", "ZoneScope", "VirtualizationID"] },
  "519": { required: [...SYSTEM, "Type", "NAME", "TTL", "RDATA", "Zone", "Source"], optional: [...RAW, "BufferSize", "ZoneScope", "VirtualizationID"] },
  // Debug log (dns.log) row — keys are the file header's column names.
  debug: {
    required: ["Date", "Time", "Thread ID", "Context", "Internal packet identifier", "UDP/TCP indicator", "Send/Receive indicator", "Remote IP", "Xid (hex)", "Query/Response", "Opcode", "Flags (hex)", "Flags (char codes)", "ResponseCode", "Question Type", "Question Name"],
    optional: [...RAW],
  },
};

export function kindOf(record: Record<string, unknown>): string | null {
  if (record.ProviderName === "Microsoft-Windows-DNSServer" && record.EventID !== undefined) {
    const k = String(record.EventID);
    return kinds[k] ? k : null;
  }
  if ("Question Name" in record && "Context" in record) return "debug";
  return null;
}

/** Windows DNS server FQDN for the company (stable): DC01.<domain>. */
function serverName(ctx: NativeCtx): string { return `DC01.${ctx.domain}`; }

/** "(14)qxkzjvbtrwpmhd(3)com(0)" */
function wireName(qname: string): string {
  return qname.split(".").filter(Boolean).map(l => `(${l.length})${l}`).join("") + "(0)";
}
function isoTicks(ts: string): string {
  const d = new Date(ts).toISOString(); // 2026-10-01T05:14:03.482Z
  return d.replace(/\.(\d{3})Z$/, (_, ms) => `.${ms}${"0000"}Z`);
}
const FLAGS_RESPONSE: Record<string, number> = { NOERROR: 0x8180, FORMERR: 0x8181, SERVFAIL: 0x8182, NXDOMAIN: 0x8183, NOTIMP: 0x8184, REFUSED: 0x8185 };

function fromTelemetry(ev: TelemetryEvent, ctx: NativeCtx): NativeLog | null {
  const f = dnsFacts(ev);
  if (!f) return null;
  const timeMs = Date.parse(ev.ts);
  const qtype = QTYPE_NUM[f.qtype];
  const xid = ctx.int(`${ev.id}:xid`, 1, 65535);
  const port = f.clientPort ?? ctx.int(`${ev.id}:sport`, 49152, 65535);
  const iface = serverIpFor(f, ctx);
  const internal = f.qname.toLowerCase().endsWith(ctx.domain.toLowerCase());
  const pid = ctx.int(`${ctx.companyId}:dns.exe:pid`, 1800, 3400);
  const tid = ctx.int(`${ev.id}:tid`, 2000, 6000);
  const system = {
    ProviderName: "Microsoft-Windows-DNSServer",
    Version: 0, Level: 4, Task: 1, Opcode: 0, Keywords: "0x8000000000000001",
    TimeCreated: isoTicks(ev.ts),
    EventRecordID: 80_000_000 + ctx.int(`${ev.id}:rec`, 0, 9_999_999),
    ProcessID: pid, ThreadID: tid,
    Channel: "Microsoft-Windows-DNSServer/Analytical",
    Computer: serverName(ctx),
    UserID: "S-1-5-18",
  };
  const tcp = f.transport === "TCP" ? "1" : "0";
  const dbg = debugStamp(timeMs, ctx.companyId);
  const thread = ctx.hex(`${ctx.companyId}:dns:thread:${tid}`, 4).toUpperCase();
  const pkt = `000002B1${ctx.hex(`${ev.id}:pkt`, 8).toUpperCase()}`;
  const xidHex = xid.toString(16).padStart(4, "0");
  const remote = f.clientIp.padEnd(15, " ");

  if (f.rcode) {
    const flags = FLAGS_RESPONSE[f.rcode] ?? 0x8180;
    const msg = dnsMessage({ xid, flags, qname: f.qname, qtype, answer: f.rcode === "NOERROR" ? f.answer : undefined, ttl: f.ttl });
    const record = {
      ...system, EventID: 257,
      TCP: tcp, InterfaceIP: iface, Destination: f.clientIp,
      AA: internal ? "1" : "0", AD: "0",
      QNAME: `${f.qname}.`, QTYPE: String(qtype), XID: String(xid), DNSSEC: "0",
      RCODE: String(RCODE_NUM[f.rcode]), Port: String(port), Flags: String(flags),
      Scope: "Default", Zone: internal ? ctx.domain : "..Cache", PolicyName: "NULL",
      BufferSize: String(msg.size), PacketData: msg.hex,
    };
    const chars = internal ? "ADR" : "DR";
    const rawLine = `${dbg.date} ${dbg.time} ${thread} PACKET  ${pkt} ${f.transport} Snd ${remote} ${xidHex} R Q [${flags.toString(16).padStart(4, "0")}   ${chars.padEnd(3, " ")}${f.rcode.padStart(8, " ")}] ${f.qtype.padEnd(6, " ")} ${wireName(f.qname)}`;
    return { sourceId: "windows_dns", kind: "257", format: "xml", record, rawLine, timeMs };
  }
  const msg = dnsMessage({ xid, flags: 0x0100, qname: f.qname, qtype });
  const record = {
    ...system, EventID: 256,
    TCP: tcp, InterfaceIP: iface, Source: f.clientIp, RD: "1",
    QNAME: `${f.qname}.`, QTYPE: String(qtype), XID: String(xid), Port: String(port), Flags: "256",
    ServerScope: "Default", CacheScope: "Default", BufferSize: String(msg.size), PacketData: msg.hex,
  };
  const rawLine = `${dbg.date} ${dbg.time} ${thread} PACKET  ${pkt} ${f.transport} Rcv ${remote} ${xidHex}   Q [0001   D   NOERROR] ${f.qtype.padEnd(6, " ")} ${wireName(f.qname)}`;
  return { sourceId: "windows_dns", kind: "256", format: "xml", record, rawLine, timeMs };
}

const useCases: UseCase[] = [
  {
    id: "windows_dns.dga_nxdomain_burst", title: "DGA-like NXDOMAIN burst from one client", sourceId: "windows_dns", kinds: ["257"],
    severity: "high", mitre: ["T1568.002", "T1071.004"],
    description: "Malware with a domain-generation algorithm tries dozens of random-looking domains until one resolves to its C2. On the DNS server this is one client (Destination of the 257 response) receiving many NXDOMAIN (RCODE 3) answers for DIFFERENT names in a few minutes. Map the client IP to a host via DHCP/EDR, then look for the one name that did resolve.",
    logic: "KQL: WindowsDnsAnalytical | where EventID == 257 and RCODE == \"3\" | summarize dcount(QNAME) by Destination, bin(TimeGenerated, 5m) | where dcount_QNAME >= 10",
    match: { all: [{ field: "EventID", op: "eq", value: 257 }, { field: "RCODE", op: "eq", value: "3" }] },
    threshold: { groupBy: ["Destination"], count: 10, windowSec: 300, distinct: "QNAME" },
    falsePositives: ["Misconfigured software retrying a decommissioned hostname (same name repeated, not distinct names)", "Browser DNS-prefetch of typo'd links", "Security scanners resolving lists of test domains"],
  },
  {
    id: "windows_dns.txt_tunneling", title: "Long encoded label in a TXT query (DNS tunneling)", sourceId: "windows_dns", kinds: ["256", "257", "260"],
    severity: "high", mitre: ["T1071.004", "T1048.003"],
    description: "DNS tunnels pack data into subdomain labels (base32/hex, close to the 63-char label limit) and pull commands back in TXT answers. A TXT query (QTYPE 16) whose first label is 40+ characters of a base32/hex alphabet is the classic shape. Event 260 then shows which external name server the DC contacted on the client's behalf.",
    logic: "KQL: WindowsDnsAnalytical | where EventID in (256,257,260) and QTYPE == \"16\" | where QNAME matches regex @\"^[a-z0-9]{40,}\\.\"",
    match: { all: [{ field: "QTYPE", op: "eq", value: "16" }, { field: "QNAME", op: "regex", value: "^[a-z0-9]{40,}\\." }] },
    falsePositives: ["Anti-virus / reputation services that query hashes as TXT (e.g. *.avqs.mcafee.com)", "DKIM/SPF lookups by mail relays (short labels, not encoded)"],
  },
  {
    id: "windows_dns.very_long_qname", title: "Abnormally long query name (any type)", sourceId: "windows_dns", kinds: ["256", "257", "260"],
    severity: "medium", mitre: ["T1071.004"],
    description: "Legitimate host names are rarely longer than ~60 characters. A QNAME of 80+ characters is either data being smuggled out in labels or an encoded beacon; tunnels that use A/AAAA records instead of TXT are caught by length alone.",
    logic: "KQL: WindowsDnsAnalytical | where strlen(QNAME) >= 80",
    match: { field: "QNAME", op: "regex", value: "^.{80,}$" },
    falsePositives: ["CDN / cloud storage names with long hashes", "Kerberos SRV lookups in large forests"],
  },
  {
    id: "windows_dns.suspicious_tld_resolved", title: "Successful lookup of a high-abuse TLD", sourceId: "windows_dns", kinds: ["257"],
    severity: "medium", mitre: ["T1071.001", "T1583.001"],
    description: "Cheap, rarely-moderated TLDs (.xyz, .top, .tk, .zip …) host a large share of phishing and C2 infrastructure. A NOERROR answer means the client got an IP for it — check the client's proxy/firewall traffic to that IP and the domain's age.",
    logic: "KQL: WindowsDnsAnalytical | where EventID == 257 and RCODE == \"0\" | where QNAME matches regex @\"\\.(xyz|top|tk|zip|…)\\.$\"",
    match: { all: [{ field: "RCODE", op: "eq", value: "0" }, { field: "QNAME", op: "regex", value: `\\.(${SUSPICIOUS_TLDS})\\.$` }] },
    falsePositives: ["Marketing / analytics vendors on new gTLDs", "Developers testing on personal domains"],
  },
  {
    id: "windows_dns.lookalike_domain", title: "Lookup of a brand look-alike domain", sourceId: "windows_dns", kinds: ["256", "257"],
    severity: "medium", mitre: ["T1566.002", "T1583.001"],
    description: "Phishing kits register names like <company>-sso.com or <company>-portal.eu so the link looks internal. Any client resolving a hyphenated 'service word' domain that is not the company's own zone deserves a look at what sent the user there (mail, chat, ad).",
    logic: "KQL: WindowsDnsAnalytical | where QNAME matches regex @\"-(sso|login|portal|helpdesk|vpn|…)\\.\" and not(QNAME endswith \"<corp-domain>.\")",
    match: { field: "QNAME", op: "regex", value: LOOKALIKE_RE },
    falsePositives: ["Legitimate vendor SSO portals (vendor-sso.com) — allow-list after review"],
  },
  {
    id: "windows_dns.recursion_txt_external_ns", title: "DC recursing a TXT query to an external name server", sourceId: "windows_dns", kinds: ["260"],
    severity: "medium", mitre: ["T1071.004"],
    description: "Event 260 (RECURSE_QUERY_OUT) shows the DNS server itself forwarding a client's TXT query to an outside authoritative server (Destination). For a tunnel this is the attacker's name server — block that IP/NS at the firewall and hunt for other clients that reached it.",
    logic: "KQL: WindowsDnsAnalytical | where EventID == 260 and QTYPE == \"16\" | summarize count() by Destination, QNAME",
    match: { all: [{ field: "EventID", op: "eq", value: 260 }, { field: "QTYPE", op: "eq", value: "16" }] },
    falsePositives: ["Mail relays resolving SPF/DKIM TXT records through the DC"],
  },
  {
    id: "windows_dns.adidns_wpad_record", title: "WPAD / wildcard record created in AD-integrated DNS", sourceId: "windows_dns", kinds: ["515", "519"],
    severity: "high", mitre: ["T1557.001", "T1584.002"],
    description: "Any authenticated user can add records to AD-integrated zones by default (ADIDNS). Attackers add `wpad`, `isatap` or `*` records pointing at their host to intercept proxy auto-discovery and harvest NTLM hashes. Audit events 515/519 record who (UserID / Source) created what (NAME, RDATA).",
    logic: "KQL: WindowsDnsAudit | where EventID in (515, 519) and NAME matches regex @\"^(wpad|isatap|\\*)\\.\"",
    match: { field: "NAME", op: "regex", value: "^(wpad|isatap|\\*)\\." },
    falsePositives: ["A documented proxy-auto-config deployment by the network team (check the change ticket)"],
  },
];

export const source: NativeSource = {
  schema: {
    sourceId: "windows_dns", category: "dns", card: "dns-windows.md", product: "Microsoft Windows DNS Server",
    format: "xml", vendorMatch: ["windows dns", "microsoft dns"], telemetrySources: ["dns"], kinds,
  },
  fromTelemetry,
  useCases,
};
