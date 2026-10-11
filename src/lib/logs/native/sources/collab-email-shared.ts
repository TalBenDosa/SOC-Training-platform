/**
 * Shared helpers for the Email & Collaboration native modules
 * (m365, google_workspace, defender_o365, proofpoint).
 *
 * The platform's legacy `ev.raw` maps hold the same facts under many key
 * spellings (`data.office365.X`, bare `X`, `email.*`, `pps.*`, `gws.*`, ...).
 * These helpers read a fact from any of them so a converter can carry evidence
 * values over verbatim, and derive stable per-entity identifiers.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { NativeCtx } from "../types";

export type Raw = Record<string, unknown>;

const PREFIXES = ["", "data.office365.", "o365.", "o365.audit.", "pps.", "gws.", "gws.parameters."];

/** First non-empty raw value among the given keys (each tried bare and with the known legacy prefixes). */
export function rv(raw: Raw | undefined, ...keys: string[]): unknown {
  if (!raw) return undefined;
  for (const k of keys) {
    for (const p of PREFIXES) {
      const v = raw[p + k];
      if (v !== undefined && v !== null && v !== "") return v;
    }
  }
  return undefined;
}
/** Same as {@link rv} but as a trimmed string (undefined when absent). */
export function rs(raw: Raw | undefined, ...keys: string[]): string | undefined {
  const v = rv(raw, ...keys);
  if (v === undefined) return undefined;
  if (Array.isArray(v)) return v.map(String).join(", ");
  const s = String(v).trim();
  return s === "" ? undefined : s;
}

export const isEmail = (s: string | undefined): s is string => !!s && /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(s);
export const domainOf = (email: string | undefined) => (email && email.includes("@") ? email.split("@")[1].toLowerCase() : undefined);
export const localOf = (email: string) => email.split("@")[0];
export const isGuid = (s: string | undefined) => !!s && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s);

/** The acting user's email (structured fields first, then the raw map). */
export function userEmail(ev: TelemetryEvent): string | undefined {
  const cands = [ev.user?.email, ev.user_email, rs(ev.raw, "UserId", "user.email", "user.name", "actorEmail", "actor.email", "MailboxOwnerUPN")];
  return cands.find(isEmail);
}

/** Strip a ":port" / brackets from an Exchange-style client IP. */
export function bareIp(s: string | undefined): string | undefined {
  if (!s) return undefined;
  let v = s.trim();
  const br = /^\[([^\]]+)\](?::\d+)?$/.exec(v);
  if (br) return br[1];
  if (/^\d{1,3}(\.\d{1,3}){3}:\d+$/.test(v)) v = v.replace(/:\d+$/, "");
  return v;
}

/** Client IP of the actor: structured src_ip, else the raw map. */
export function clientIp(ev: TelemetryEvent): string | undefined {
  return ev.src_ip ?? bareIp(rs(ev.raw, "ClientIP", "ClientIPAddress", "ActorIpAddress", "source.ip", "ipAddress", "clickIP"));
}

export function isPrivateIp(ip: string | undefined): boolean {
  if (!ip) return false;
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)/.test(ip);
}

/** "2026-09-29T07:41:12" — UTC, no zone, no ms (M365 Management Activity API). */
export function isoNoMs(ts: string): string {
  return new Date(Date.parse(ts)).toISOString().slice(0, 19);
}
/** "2026-09-29T07:41:12.418Z" — UTC with ms. */
export function isoMs(ts: string): string {
  return new Date(Date.parse(ts)).toISOString();
}
/** "2026-09-29T07:41:12.4471823Z" — 7 fractional digits (Advanced Hunting). Keeps the event's ms, adds 4 seeded digits. */
export function iso7(ts: string, ctx: NativeCtx, seed: string, addSec = 0): string {
  const d = new Date(Date.parse(ts) + addSec * 1000).toISOString(); // ...ss.mmmZ
  return `${d.slice(0, 23)}${String(ctx.int(seed, 0, 9999)).padStart(4, "0")}Z`;
}

/** Stable per-entity seeds (never per event) so ids correlate across a story. */
export const entitySeed = (ctx: NativeCtx, kind: string, value: string) => `${ctx.companyId}:${kind}:${value.toLowerCase()}`;

/** Microsoft PUID-style key (16 hex upper), stable per user. */
export function puid(ctx: NativeCtx, email: string): string {
  return `10032001${ctx.hex(entitySeed(ctx, "puid", email), 8).toUpperCase()}`;
}
/** Entra object id, stable per user. */
export function aadObjectId(ctx: NativeCtx, email: string): string {
  return ctx.uuid(entitySeed(ctx, "aadoid", email));
}
/** On-prem-synced SID, stable per company + user. */
export function userSid(ctx: NativeCtx, email: string): string {
  const c = (n: number) => ctx.int(`${ctx.companyId}:domsid:${n}`, 1_000_000_000, 3_999_999_999);
  return `S-1-5-21-${c(1)}-${c(2)}-${c(3)}-${ctx.int(entitySeed(ctx, "rid", email), 1105, 98000)}`;
}

/** Tenant-short name for SharePoint hosts ("nexacorp" → nexacorp.sharepoint.com). */
export function spTenant(ctx: NativeCtx, email?: string): string {
  const d = domainOf(email) ?? ctx.domain;
  return d.split(".")[0].replace(/[^a-z0-9]/gi, "").toLowerCase();
}

/** Signed int64 as a decimal string (Google uniqueQualifier). */
export function int64Str(ctx: NativeCtx, seed: string): string {
  const hi = ctx.int(`${seed}:hi`, 0, 0x3fffffff);
  const lo = ctx.int(`${seed}:lo`, 0, 0x3fffffff);
  const big = (BigInt(hi) << 33n) + (BigInt(lo) << 3n) + BigInt(ctx.int(`${seed}:x`, 0, 7));
  return (ctx.int(`${seed}:sign`, 0, 1) ? -big : big).toString();
}
/** Decimal digit string of length n (first digit non-zero). */
export function digits(ctx: NativeCtx, seed: string, n: number): string {
  let s = "";
  let i = 0;
  while (s.length < n) s += String(ctx.int(`${seed}#${i++}`, 0, 999_999_999)).padStart(9, "0");
  return (String(ctx.int(`${seed}#lead`, 1, 9)) + s).slice(0, n);
}
const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
export function b64ish(ctx: NativeCtx, seed: string, n: number): string {
  let s = "";
  for (let i = 0; i < n; i++) s += B64[ctx.int(`${seed}#${i}`, 0, B64.length - 1)];
  return s;
}

// ── Email facts ──────────────────────────────────────────────────────────────

export interface Attachment { name: string; sha256?: string; size?: number; mime?: string; ext?: string }
export interface EmailFacts {
  from?: string;            // header From address (P2)
  fromDisplay?: string;
  mailFrom?: string;        // envelope sender (P1 / Return-Path)
  to: string[];             // recipients
  headerTo?: string;        // To header (may differ from envelope recipient — Bcc case)
  replyTo?: string;
  subject?: string;
  internetMessageId?: string;
  networkMessageId?: string;
  senderIp?: string;
  attachments: Attachment[];
  urls: string[];
  spf?: string; dkim?: string; dmarc?: string; compauth?: string;
  direction: "Inbound" | "Outbound" | "Intra-org";
  /** Threat verdict words found in the event: Phish / Malware / Spam. */
  threats: string[];
  xmailer?: string;
  sizeBytes?: number;
  language?: string;
  deliveryAction?: string;
  deliveryLocation?: string;
}

const lc = (s?: string) => (s ? s.toLowerCase() : undefined);
function addrFromHeader(h?: string): string | undefined {
  if (!h) return undefined;
  const m = /<([^>]+@[^>]+)>/.exec(h);
  if (m) return m[1];
  return isEmail(h.trim()) ? h.trim() : undefined;
}
function displayFromHeader(h?: string): string | undefined {
  if (!h) return undefined;
  const m = /^\s*"?([^"<]+?)"?\s*</.exec(h);
  return m ? m[1].trim() : undefined;
}
const num = (v: unknown) => (v === undefined || v === null || v === "" || isNaN(Number(v)) ? undefined : Number(v));

/** Normalise every legacy spelling of a mail event into one fact set. */
export function emailFacts(ev: TelemetryEvent): EmailFacts {
  const r = ev.raw ?? {};
  const headerFrom = rs(r, "email.headers.from", "headerFrom", "P2Sender");
  // Header From (P2) first; the envelope sender ("sender", P1) only as a last resort.
  const hdr = rs(r, "email.from.address", "SenderFromAddress", "fromAddress");
  const from = hdr ?? rs(r, "P2Sender", "Sender", "email.sender.address", "sender");
  const fromAddr = addrFromHeader(hdr) ?? addrFromHeader(headerFrom) ?? addrFromHeader(from) ?? from;
  const mailFrom = addrFromHeader(rs(r, "email.headers.return_path", "P1Sender", "SenderMailFromAddress", "email.sender.address", "pps.sender")) ?? fromAddr;
  const toRaw = rs(r, "RecipientEmailAddress", "email.to.address", "recipient", "Recipients", "RecipientAddress", "to", "MailboxOwnerUPN");
  const user = userEmail(ev);
  const envelopeTo = user ?? (toRaw ? toRaw.split(/[;,]\s*/)[0] : undefined);
  const to = envelopeTo ? [envelopeTo] : [];
  const headerTo = rs(r, "email.to.address", "to");

  // Attachments (several legacy shapes).
  const atts: Attachment[] = [];
  const pushAtt = (name?: string, sha?: string, size?: unknown, mime?: string, ext?: string) => {
    if (!name) return;
    for (const n of name.split(/,\s*/).filter(Boolean)) {
      if (atts.some(a => a.name === n)) continue;
      const e = ext ?? (n.includes(".") ? n.split(".").pop()!.toLowerCase() : undefined);
      atts.push({ name: n, sha256: sha, size: num(size), mime, ext: e });
    }
  };
  pushAtt(rs(r, "email.attachments.file.name"), rs(r, "email.attachments.file.hash.sha256"), rv(r, "email.attachments.file.size"),
    rs(r, "email.attachments.file.mime_type"), rs(r, "email.attachments.file.extension"));
  pushAtt(rs(r, "attachment.0.name"), rs(r, "attachment.0.sha256"), undefined, rs(r, "attachment.0.mime_type"));
  pushAtt(rs(r, "AttachmentData.FileName"), rs(r, "AttachmentData.SHA256"));
  pushAtt(rs(r, "AttachmentName"), rs(r, "AttachmentSha256"));
  pushAtt(rs(r, "email.attachment.name"), undefined, atts.length === 0 ? rv(r, "file.size") : undefined);
  pushAtt(rs(r, "AttachmentNames"));
  if (atts.length === 0 && ev.file?.name && /^email_/.test(ev.event_type)) pushAtt(ev.file.name, ev.file.sha256, ev.file.size);
  if (atts.length === 1 && !atts[0].sha256) atts[0].sha256 = ev.file?.sha256 ?? ev.process?.hash?.sha256;

  // URLs.
  const urls: string[] = [];
  for (const u of [ev.network?.url, rs(r, "email.url"), rs(r, "email.links"), rs(r, "urls[0]"), rs(r, "url")]) {
    if (u && /^https?:\/\//i.test(u) && !urls.includes(u)) urls.push(u);
  }

  const auth = (k: string) => lc(rs(r, `email.${k}`, `${k}.result`, `${k}_result`, `pps.${k}`));
  let threats: string[] = [];
  const tt = rs(r, "ThreatTypes", "ThreatType", "Verdict", "threat.category", "classification");
  if (tt && !/^none$/i.test(tt)) {
    if (/phish/i.test(tt)) threats.push("Phish");
    if (/malware/i.test(tt)) threats.push("Malware");
    if (/spam/i.test(tt)) threats.push("Spam");
  }
  threats = [...new Set(threats)];

  const dirRaw = lc(rs(r, "email.direction", "Directionality", "EmailDirection", "direction"));
  const fromDom = domainOf(fromAddr);
  const toDom = domainOf(to[0]);
  let direction: EmailFacts["direction"] = "Inbound";
  if (dirRaw === "outbound" || ev.event_type === "email_sent") direction = fromDom && toDom && fromDom === toDom ? "Intra-org" : "Outbound";
  else if (dirRaw === "intra-org" || (fromDom && toDom && fromDom === toDom)) direction = "Intra-org";
  if (ev.event_type === "email_sent") {
    const rcpt = rs(r, "email.to.address", "RecipientAddress", "to");
    const rd = domainOf(rcpt);
    direction = rd && fromDom && rd === fromDom ? "Intra-org" : "Outbound";
  }

  return {
    from: fromAddr,
    fromDisplay: rs(r, "email.from.display_name", "SenderDisplayName") ?? displayFromHeader(headerFrom),
    mailFrom,
    to,
    headerTo: ev.event_type === "email_sent" ? rs(r, "email.to.address", "RecipientAddress", "to") : headerTo,
    replyTo: addrFromHeader(rs(r, "email.headers.reply_to", "headerReplyTo")),
    subject: rs(r, "email.subject", "Subject", "subject", "Item.Subject"),
    internetMessageId: rs(r, "InternetMessageId", "email.message_id", "email.headers.message_id", "messageID", "message_id", "messageId"),
    networkMessageId: rs(r, "NetworkMessageId"),
    senderIp: bareIp(rs(r, "SenderIp", "SenderIPv4", "senderIP", "email.headers.x_originating_ip")) ?? (ev.event_type === "email_clicked" ? undefined : ev.src_ip) ?? bareIp(rs(r, "source.ip", "ClientIP")),
    attachments: atts,
    urls,
    spf: auth("spf"), dkim: auth("dkim"), dmarc: lc(rs(r, "email.dmarc", "dmarc.result", "dmarc_result", "DmarcResult", "pps.dmarc")),
    compauth: lc(rs(r, "email.auth.compauth")),
    direction,
    threats,
    xmailer: rs(r, "email.headers.x_mailer"),
    sizeBytes: num(rv(r, "email.size_bytes", "message_size_bytes", "MessageSizeBytes", "Item.SizeInBytes")) ?? (atts.length ? undefined : num(rv(r, "file.size"))),
    language: rs(r, "EmailLanguage"),
    deliveryAction: rs(r, "DeliveryAction"),
    deliveryLocation: rs(r, "DeliveryLocation", "OriginalDeliveryLocation"),
  };
}

/** A deterministic RFC 5322 Message-ID for a mail that has none in the authored event. */
export function syntheticMessageId(ctx: NativeCtx, ev: TelemetryEvent, fromDomain?: string): string {
  const stamp = new Date(Date.parse(ev.ts)).toISOString().replace(/[-:T]/g, "").slice(0, 14);
  return `<${stamp}.${ctx.hex(`${ev.id}:mid`, 10).toUpperCase()}@${fromDomain ?? "mail.example.net"}>`;
}

/** Is this mail event malicious in the story (phish / malware / BEC), as opposed to clean traffic? */
export function isThreatMail(ev: TelemetryEvent, f: EmailFacts): boolean {
  if (ev.expected_verdict === "fp" || ev.is_baseline) return false;
  if (f.threats.some(t => t === "Phish" || t === "Malware")) return true;
  if (ev.mitre_technique && /^T1566|^T1534|^T1204/.test(ev.mitre_technique)) return true;
  if (ev.expected_verdict === "tp") return true;
  return false;
}

/** All string leaves of a value (for evidence searches in tests and for kindOf helpers). */
export function deepStrings(v: unknown, out: string[] = []): string[] {
  if (typeof v === "string") out.push(v);
  else if (typeof v === "number" || typeof v === "boolean") out.push(String(v));
  else if (Array.isArray(v)) for (const x of v) deepStrings(x, out);
  else if (v && typeof v === "object") for (const x of Object.values(v)) deepStrings(x, out);
  return out;
}
