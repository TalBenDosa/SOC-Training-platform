/**
 * Infoblox NIOS DNS — native module (card: docs/log-schemas/dns-infoblox.md).
 *
 * NIOS members send BIND `named` lines over syslog. Three record shapes, each a FLAT
 * object with the card's key names, plus `rawLine` = the syslog line rebuilt from the
 * same values:
 *   - "query"    — query log (category `queries`): who asked what (no answer, no RCODE);
 *   - "response" — response log (category `responses`): RCODE + answer RRs;
 *   - "rpz"      — RPZ hit in CEF (category `rpz`): a policy rewrite (block) of the name.
 * A platform DNS event with an authored outcome renders as "response"; with an authored
 * blocking RPZ action (NXDOMAIN / NODATA / DROP / Local-Data) as "rpz"; otherwise
 * "query". PASSTHRU is an allow-list match, not a block — such events render as their
 * ordinary response line so the answer stays visible.
 *
 * Category-wide: Windows-DNS-authored and vendor-less DNS events render here too.
 */
import type { NativeSource, NativeLog, KindSchema, UseCase, NativeCtx } from "../types";
import type { TelemetryEvent } from "@/lib/sim/types";
import { dnsFacts, syslogStamp, bindStamp, serverIpFor, SUSPICIOUS_TLDS, LOOKALIKE_RE } from "./_dnsShared";

const HDR = ["timestamp", "hostname", "program", "pid"];
const kinds: Record<string, KindSchema> = {
  query: {
    required: [...HDR, "client_ctx", "client_ip", "client_port", "qname", "qclass", "qtype", "flags", "server_ip"],
    optional: ["raw"],
  },
  response: {
    required: [...HDR, "client_ip", "client_port", "protocol", "qname", "qclass", "qtype", "rcode", "flags", "answers"],
    optional: ["raw"],
  },
  rpz: {
    required: [...HDR, "CEFVersion", "DeviceVendor", "DeviceProduct", "DeviceVersion", "SignatureID", "Name", "Severity", "app", "dst", "src", "spt", "view", "qtype", "msg", "CAT"],
    optional: ["raw"],
  },
};

export function kindOf(record: Record<string, unknown>): string | null {
  if (record.DeviceVendor === "Infoblox" && record.CAT === "RPZ") return "rpz";
  if (record.program !== "named") return null;
  if ("rcode" in record) return "response";
  if ("server_ip" in record && "qname" in record) return "query";
  return null;
}

const NIOS_VERSION = "9.0.4-50212-a1c3e8f02b77";
const BLOCK_ACTIONS = new Set(["NXDOMAIN", "NODATA", "DROP", "LOCAL-DATA", "TCP-ONLY"]);
const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

function memberName(serverName: string | undefined, ctx: NativeCtx): string {
  return serverName ?? `ns1.${ctx.domain}`;
}

function answerRR(qname: string, qtype: string, answer: string, ttl: number): string {
  if (qtype === "TXT") return `${qname} ${ttl} IN TXT "${answer}";`;
  if ((qtype === "A" && IPV4.test(answer)) || qtype === "AAAA") return `${qname} ${ttl} IN ${qtype} ${answer};`;
  if (qtype === "A" && !IPV4.test(answer)) return `${qname} ${ttl} IN CNAME ${answer}.;`;
  if (qtype === "MX" || qtype === "CNAME" || qtype === "PTR" || qtype === "NS") return `${qname} ${ttl} IN ${qtype} ${answer}.;`;
  return `${qname} ${ttl} IN ${qtype} ${answer};`;
}

function fromTelemetry(ev: TelemetryEvent, ctx: NativeCtx): NativeLog | null {
  const f = dnsFacts(ev);
  if (!f) return null;
  const timeMs = Date.parse(ev.ts);
  const hostname = memberName(f.serverName, ctx);
  const pid = String(ctx.int(`${ctx.companyId}:${hostname}:named`, 1200, 9800));
  const port = String(f.clientPort ?? ctx.int(`${ev.id}:sport`, 49152, 65535));
  const serverIp = serverIpFor(f, ctx, 53);
  const timestamp = syslogStamp(timeMs, ctx.companyId);
  const hdr = { timestamp, hostname, program: "named", pid };
  const prefix = (pri: number) => `<${pri}>${timestamp} ${hostname} named[${pid}]: `;

  if (f.rpzAction && BLOCK_ACTIONS.has(f.rpzAction)) {
    const action = f.rpzAction === "LOCAL-DATA" ? "Local-Data" : f.rpzAction;
    const sev = ev.severity === "critical" ? "8" : "7";
    const view = f.view ?? "_default";
    const msg = `rpz QNAME ${action} rewrite ${f.qname} [${f.qtype}] via ${f.qname}.soc-block.rpz`;
    const record = {
      ...hdr, CEFVersion: "0", DeviceVendor: "Infoblox", DeviceProduct: "NIOS", DeviceVersion: NIOS_VERSION,
      SignatureID: "RPZ-QNAME", Name: action, Severity: sev,
      app: "DNS", dst: serverIp, src: f.clientIp, spt: port, view, qtype: f.qtype, msg, CAT: "RPZ",
    };
    const rawLine = `${prefix(29)}CEF:0|Infoblox|NIOS|${NIOS_VERSION}|RPZ-QNAME|${action}|${sev}|app=DNS dst=${serverIp} src=${f.clientIp} spt=${port} view=${view} qtype=${f.qtype} msg="${msg}" CAT=RPZ`;
    return { sourceId: "infoblox", kind: "rpz", format: "cef", record, rawLine, timeMs };
  }

  if (f.rcode) {
    const flags = "+ED";
    const answers = f.rcode === "NOERROR" && f.answer ? answerRR(f.qname, f.qtype, f.answer, f.ttl ?? 300) : "";
    const record = {
      ...hdr, client_ip: f.clientIp, client_port: port, protocol: f.transport,
      qname: f.qname, qclass: "IN", qtype: f.qtype, rcode: f.rcode, flags, answers,
    };
    const rawLine = `${prefix(30)}${bindStamp(timeMs, ctx.companyId)} client ${f.clientIp}#${port}: ${f.transport}: query: ${f.qname} IN ${f.qtype} response: ${f.rcode} ${flags}${answers ? ` ${answers}` : ""}`;
    return { sourceId: "infoblox", kind: "response", format: "syslog", record, rawLine, timeMs };
  }

  const clientCtx = `@0x7f3a${ctx.hex(`${ev.id}:ctx`, 8)}`;
  const flags = f.qtype === "TXT" ? "+" : "+E(0)K";
  const record = {
    ...hdr, client_ctx: clientCtx, client_ip: f.clientIp, client_port: port,
    qname: f.qname, qclass: "IN", qtype: f.qtype, flags, server_ip: serverIp,
  };
  const rawLine = `${prefix(30)}client ${clientCtx} ${f.clientIp}#${port} (${f.qname}): query: ${f.qname} IN ${f.qtype} ${flags} (${serverIp})`;
  return { sourceId: "infoblox", kind: "query", format: "syslog", record, rawLine, timeMs };
}

const useCases: UseCase[] = [
  {
    id: "infoblox.dga_nxdomain_burst", title: "DGA-like NXDOMAIN burst from one client", sourceId: "infoblox", kinds: ["response"],
    severity: "high", mitre: ["T1568.002"],
    description: "A domain-generation algorithm walks through random names until one resolves to the live C2. In the NIOS response log that is one client_ip collecting NXDOMAIN for many distinct qnames within minutes; the single NOERROR among them gives the C2 IP to pivot on in firewall/proxy logs.",
    logic: "SPL: index=dns sourcetype=infoblox:dns rcode=NXDOMAIN | bin _time span=5m | stats dc(qname) as names by client_ip, _time | where names >= 10",
    match: { field: "rcode", op: "eq", value: "NXDOMAIN" },
    threshold: { groupBy: ["client_ip"], count: 10, windowSec: 300, distinct: "qname" },
    falsePositives: ["Software retrying a retired hostname (one name, not many)", "Email security gateways checking random sender domains"],
  },
  {
    id: "infoblox.txt_tunneling", title: "Encoded label in a TXT query (DNS tunneling)", sourceId: "infoblox", kinds: ["query", "response"],
    severity: "high", mitre: ["T1071.004", "T1048.003"],
    description: "Tunnels carry data in long base32/hex subdomain labels and receive commands in TXT answers. A TXT query whose first label is 40+ characters — often with an incrementing sequence label under one parent domain — is the signature. The DNS server is the only place that shows the internal client; the firewall only sees the resolver.",
    logic: "SPL: index=dns sourcetype=infoblox:dns qtype=TXT | regex qname=\"^[a-z0-9]{40,}\\.\" | stats count dc(qname) by client_ip",
    match: { all: [{ field: "qtype", op: "eq", value: "TXT" }, { field: "qname", op: "regex", value: "^[a-z0-9]{40,}\\." }] },
    falsePositives: ["AV/reputation lookups that encode file hashes as TXT queries to the vendor's zone"],
  },
  {
    id: "infoblox.rpz_block_threat", title: "RPZ blocked a known-malicious domain", sourceId: "infoblox", kinds: ["rpz"],
    severity: "high", mitre: ["T1071.001", "T1568"],
    description: "An RPZ rewrite (CEF Name = NXDOMAIN / NODATA …) means the client tried to resolve a name on a threat feed or the SOC's block zone. The block stopped this lookup, but the host is running something that knows the domain — find the process (Sysmon 22 / EDR DNS) and check for earlier, unblocked variants. `msg … via <zone>` names the feed that caught it.",
    logic: "SPL: index=dns sourcetype=infoblox:rpz CAT=RPZ Name!=PASSTHRU Severity>=7 | stats count values(msg) by src",
    match: { all: [{ field: "CAT", op: "eq", value: "RPZ" }, { field: "Name", op: "neq", value: "PASSTHRU" }, { field: "Severity", op: "gte", value: 7 }] },
    falsePositives: ["Feed false positive on a shared-hosting / CDN name", "Security staff researching a domain from a workstation"],
  },
  {
    id: "infoblox.rpz_passthru", title: "RPZ allow-list (PASSTHRU) match", sourceId: "infoblox", kinds: ["rpz"],
    severity: "low", mitre: [],
    description: "PASSTHRU means a name matched an allow-list rule and was NOT blocked. Useful context: if a blocked feed domain also sits on the allow-list, the allow-list entry is hiding it — review who added it.",
    logic: "SPL: index=dns sourcetype=infoblox:rpz Name=PASSTHRU | stats count by msg",
    match: { field: "Name", op: "eq", value: "PASSTHRU" },
    falsePositives: ["Expected for sanctioned vendor domains"],
  },
  {
    id: "infoblox.suspicious_tld_resolved", title: "Successful lookup of a high-abuse TLD", sourceId: "infoblox", kinds: ["response"],
    severity: "medium", mitre: ["T1071.001", "T1583.001"],
    description: "A NOERROR answer for a name under a cheap, abuse-heavy TLD (.xyz, .top, .tk …). Check domain age / reputation and whether the client then connected to the returned IP.",
    logic: "SPL: index=dns sourcetype=infoblox:dns rcode=NOERROR | regex qname=\"\\.(xyz|top|tk|zip|…)$\"",
    match: { all: [{ field: "rcode", op: "eq", value: "NOERROR" }, { field: "qname", op: "regex", value: `\\.(${SUSPICIOUS_TLDS})$` }] },
    falsePositives: ["Ad-tech and analytics vendors on new gTLDs"],
  },
  {
    id: "infoblox.lookalike_domain", title: "Lookup of a brand look-alike domain", sourceId: "infoblox",
    severity: "medium", mitre: ["T1566.002", "T1583.001"],
    description: "Phishing kits use names like <brand>-sso.com / <brand>-portal.eu so a link looks internal. A client resolving such a name (or RPZ rewriting it) should be tied back to the email or message that carried the link.",
    logic: "SPL: index=dns sourcetype=infoblox:* | eval n=coalesce(qname, msg) | regex n=\"-(sso|login|portal|helpdesk|vpn|…)\\.\"",
    match: { any: [{ field: "qname", op: "regex", value: LOOKALIKE_RE }, { field: "msg", op: "regex", value: LOOKALIKE_RE }] },
    falsePositives: ["Legitimate vendor SSO portals — allow-list after review"],
  },
];

export const source: NativeSource = {
  schema: {
    sourceId: "infoblox", category: "dns", card: "dns-infoblox.md", product: "Infoblox NIOS DNS",
    format: "syslog", vendorMatch: ["infoblox"], telemetrySources: ["dns"], kinds,
  },
  fromTelemetry,
  useCases,
};
