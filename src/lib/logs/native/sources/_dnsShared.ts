/**
 * Shared helpers for the DNS-server sources (windows_dns, infoblox).
 *
 * Both modules render the SAME vendor-neutral DNS facts (client IP, query name,
 * type, response code, answer) — this file extracts those facts once from a
 * TelemetryEvent (structured `dns{}` / `network{}` plus the legacy `raw` keys the
 * corpus uses: `infoblox.*`, `dns.question.*`, `dns.answers.*`, `source.ip` …),
 * and holds the server-local clock used by the text-native lines (Windows DNS
 * debug log, BIND/NIOS syslog), which are stamped in server LOCAL time.
 */
import { companyTimeZone } from "../ctx";
import type { NativeCtx } from "../types";
import type { TelemetryEvent } from "@/lib/sim/types";

export interface DnsFacts {
  clientIp: string;
  clientPort?: number;
  /** Query name exactly as authored (no trailing dot). */
  qname: string;
  /** Type mnemonic, upper-case (A, AAAA, TXT …). */
  qtype: string;
  /** NOERROR / NXDOMAIN / SERVFAIL / REFUSED — undefined when the event carries no response. */
  rcode?: string;
  /** Answer data (IP for A/AAAA, text for TXT, name for CNAME). */
  answer?: string;
  ttl?: number;
  /** IP of the DNS server that received the query, when authored. */
  serverIp?: string;
  /** DNS server name, when authored (infoblox.member / host.name of the resolver). */
  serverName?: string;
  /** RPZ action authored on the event (NXDOMAIN, PASSTHRU, NODATA …); "none" is dropped. */
  rpzAction?: string;
  transport: "UDP" | "TCP";
  /** Infoblox view authored on the event. */
  view?: string;
}

const s = (v: unknown): string | undefined =>
  v === undefined || v === null || v === "" ? undefined : Array.isArray(v) ? (v.length ? String(v[0]) : undefined) : String(v);

export const QTYPE_NUM: Record<string, number> = {
  A: 1, NS: 2, CNAME: 5, SOA: 6, NULL: 10, PTR: 12, MX: 15, TXT: 16, AAAA: 28, SRV: 33, HTTPS: 65, AXFR: 252, ANY: 255,
};
export const RCODE_NUM: Record<string, number> = { NOERROR: 0, FORMERR: 1, SERVFAIL: 2, NXDOMAIN: 3, NOTIMP: 4, REFUSED: 5 };

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

/**
 * Pull the DNS facts out of a platform event. Returns null when the event is not a
 * single DNS transaction (e.g. an aggregate "baseline" summary) or has no client IP /
 * query name — a DNS server log line cannot exist without either.
 */
export function dnsFacts(ev: TelemetryEvent): DnsFacts | null {
  const raw = ev.raw ?? {};
  // Aggregate summaries ("top domains for this host") are not a DNS transaction.
  if (s(raw["event.action"]) === "dns_baseline_aggregate" || raw["dns.top_domains"] !== undefined) return null;
  const qname = s(ev.dns?.query) ?? s(raw["infoblox.query_name"]) ?? s(raw["dns.question.name"]) ?? s(ev.network?.domain);
  const clientIp = s(raw["infoblox.client_ip"]) ?? s(ev.src_ip) ?? s(raw["source.ip"]);
  if (!qname || !clientIp || !IPV4.test(clientIp)) return null;
  const qtype = (s(ev.dns?.query_type) ?? s(raw["infoblox.query_type"]) ?? s(raw["dns.question.type"]) ?? "A").toUpperCase();
  const rcode = (s(ev.dns?.rcode) ?? s(raw["infoblox.rcode"]) ?? s(raw["infoblox.response_code"]) ?? s(raw["dns.response_code"]))?.toUpperCase();
  const answer = s(ev.dns?.response) ?? s(raw["infoblox.answer"]) ?? s(raw["dns.answers.data"]) ?? s(raw["dns.resolved_ip"]);
  const ttlRaw = s(raw["infoblox.ttl"]) ?? s(raw["dns.answers.ttl"]);
  const rpz = s(raw["infoblox.rpz_policy"]);
  const transport = (s(raw["infoblox.transport"]) ?? "UDP").toUpperCase() === "TCP" ? "TCP" : "UDP";
  // A dst_ip on a DNS event is the resolver the client asked (e.g. 10.10.20.5).
  const serverIp = ev.dst_ip && IPV4.test(ev.dst_ip) && (ev.dst_port === undefined || ev.dst_port === 53) ? ev.dst_ip : undefined;
  return {
    clientIp,
    clientPort: ev.src_port,
    qname: qname.replace(/\.$/, ""),
    qtype: QTYPE_NUM[qtype] !== undefined ? qtype : "A",
    rcode: rcode && RCODE_NUM[rcode] !== undefined ? rcode : rcode ? "NOERROR" : undefined,
    answer,
    ttl: ttlRaw !== undefined && !isNaN(Number(ttlRaw)) ? Number(ttlRaw) : undefined,
    serverIp,
    serverName: s(raw["infoblox.member"]),
    rpzAction: rpz && rpz.toLowerCase() !== "none" ? rpz.toUpperCase() : undefined,
    transport,
    view: s(raw["infoblox.view"]),
  };
}

/** The company DNS server's interface IP: authored, else the client's /16 with .0.10 (stable per site). */
export function serverIpFor(f: DnsFacts, ctx: NativeCtx, last = 10): string {
  if (f.serverIp) return f.serverIp;
  const [a, b] = f.clientIp.split(".");
  return `${a}.${b}.0.${last}`;
}

// ── Server-local clock ───────────────────────────────────────────────────────
/**
 * The debug log, BIND and auditd syslog are stamped in the servers' local time —
 * the company's own zone (ctx.ts), with real DST rules via Intl.
 */
const fmtCache = new Map<string, Intl.DateTimeFormat>();
export function localParts(timeMs: number, companyId: string) {
  const timeZone = companyTimeZone(companyId);
  let f = fmtCache.get(timeZone);
  if (!f) {
    f = new Intl.DateTimeFormat("en-US", { timeZone, hourCycle: "h23", year: "numeric", month: "numeric", day: "numeric", hour: "numeric", minute: "numeric", second: "numeric" });
    fmtCache.set(timeZone, f);
  }
  const p: Record<string, number> = {};
  for (const x of f.formatToParts(new Date(timeMs))) if (x.type !== "literal") p[x.type] = Number(x.value);
  return { year: p.year, month: p.month, day: p.day, h: p.hour % 24, mi: p.minute, sec: p.second, ms: ((timeMs % 1000) + 1000) % 1000 };
}
const MON = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const p2 = (n: number) => String(n).padStart(2, "0");
const p3 = (n: number) => String(n).padStart(3, "0");
/** RFC 3164 syslog stamp, e.g. "Oct  1 08:14:03". */
export function syslogStamp(timeMs: number, companyId: string): string {
  const t = localParts(timeMs, companyId);
  return `${MON[t.month - 1]} ${String(t.day).padStart(2, " ")} ${p2(t.h)}:${p2(t.mi)}:${p2(t.sec)}`;
}
/** BIND's own in-message stamp, e.g. "01-Oct-2026 08:14:03.541". */
export function bindStamp(timeMs: number, companyId: string): string {
  const t = localParts(timeMs, companyId);
  return `${p2(t.day)}-${MON[t.month - 1]}-${t.year} ${p2(t.h)}:${p2(t.mi)}:${p2(t.sec)}.${p3(t.ms)}`;
}
/** Windows DNS debug-log date/time columns, en-US locale: "10/1/2026", "8:14:03 AM". */
export function debugStamp(timeMs: number, companyId: string): { date: string; time: string } {
  const t = localParts(timeMs, companyId);
  const h12 = t.h % 12 === 0 ? 12 : t.h % 12;
  return { date: `${t.month}/${t.day}/${t.year}`, time: `${h12}:${p2(t.mi)}:${p2(t.sec)} ${t.h < 12 ? "AM" : "PM"}` };
}

// ── DNS wire encoding (Windows PacketData) ───────────────────────────────────
function u16(n: number): number[] { return [(n >> 8) & 0xff, n & 0xff]; }
function u32(n: number): number[] { return [(n >>> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff]; }
function nameBytes(qname: string): number[] {
  const out: number[] = [];
  for (const label of qname.split(".").filter(Boolean)) {
    out.push(label.length & 0xff);
    for (const ch of label) out.push(ch.charCodeAt(0) & 0xff);
  }
  out.push(0);
  return out;
}
/**
 * The DNS message as it crossed the wire (header + question [+ one answer]) — the
 * Windows Analytical `PacketData` hex. The answer RR is included for A (IPv4) and TXT
 * answers; other answer types are left out (ANCOUNT 0), as in the card sample.
 */
export function dnsMessage(o: { xid: number; flags: number; qname: string; qtype: number; answer?: string; ttl?: number }): { hex: string; size: number } {
  const ans: number[] = [];
  if (o.answer && o.qtype === 1 && IPV4.test(o.answer)) {
    ans.push(0xc0, 0x0c, ...u16(1), ...u16(1), ...u32(o.ttl ?? 300), ...u16(4), ...o.answer.split(".").map(Number));
  } else if (o.answer && o.qtype === 16) {
    const txt = o.answer.slice(0, 255);
    ans.push(0xc0, 0x0c, ...u16(16), ...u16(1), ...u32(o.ttl ?? 0), ...u16(txt.length + 1), txt.length, ...[...txt].map(c => c.charCodeAt(0) & 0xff));
  }
  const bytes = [...u16(o.xid), ...u16(o.flags), ...u16(1), ...u16(ans.length ? 1 : 0), ...u16(0), ...u16(0), ...nameBytes(o.qname), ...u16(o.qtype), ...u16(1), ...ans];
  return { hex: `0x${bytes.map(b => b.toString(16).padStart(2, "0")).join("").toUpperCase()}`, size: bytes.length };
}

/** Shared detection vocabulary for the DNS use cases. */
export const SUSPICIOUS_TLDS = "xyz|top|tk|gq|cf|ml|ga|zip|mov|click|link|cyou|icu|buzz|rest|monster|su";
/** Typosquat / brand look-alike pattern: an internal-sounding service word glued to a domain with a hyphen. */
export const LOOKALIKE_RE = "-(sso|login|logon|portal|helpdesk|vpn|okta|o365|m365|auth|secure|verify|update-svc)\\.";
