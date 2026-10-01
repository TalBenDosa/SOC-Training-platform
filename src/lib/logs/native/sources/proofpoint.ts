/**
 * Proofpoint TAP — SIEM API v2 (/v2/siem/all, format=json).
 * Card: docs/log-schemas/email-proofpoint.md
 *
 * One log = one element of messagesDelivered / messagesBlocked / clicksPermitted /
 * clicksBlocked; the array is the kind (no eventType field is injected). Wire-format
 * quirks per the card: `cluster` (not clusterId), `fromAddress` array,
 * `completelyRewritten` boolean, lower-case `classification` / `threatType`,
 * `campaignID` + `threatUrl` inside threatsInfoMap vs `campaignId` + `threatURL` on
 * clicks, message `recipient` array vs click `recipient` string.
 *
 * TAP's SIEM API only reports messages and clicks that involve a known threat, so a
 * clean / baseline mail returns null here (never faked as a "threat"). Post-delivery
 * removals (ZAP / admin remediation) and outbound mail have no TAP SIEM record → null.
 *
 * Identity: GUID is stable per Internet Message-ID, so a message and its clicks share
 * it; threatID is stable per indicator (URL / attachment SHA256 / sender), so every
 * message and click of one threat share it.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { KindSchema, NativeCtx, NativeLog, NativeSource, SourceSchema, UseCase } from "../types";
import {
  b64ish, digits, domainOf, emailFacts, entitySeed, isThreatMail, isoMs, rs, rv, syntheticMessageId, userEmail, type EmailFacts, type Raw,
} from "./collab-email-shared";

// ── Schema ───────────────────────────────────────────────────────────────────

const MSG_REQ = ["GUID", "QID", "messageID", "messageTime", "sender", "senderIP", "recipient", "threatsInfoMap"];
const MSG_OPT = [
  "id", "cluster", "fromAddress", "headerFrom", "headerReplyTo", "replyToAddress", "toAddresses", "ccAddresses", "subject", "messageSize",
  "xmailer", "spamScore", "phishScore", "malwareScore", "impostorScore", "completelyRewritten", "modulesRun", "policyRoutes",
  "quarantineFolder", "quarantineRule",
  "messageParts", "messageParts[].disposition", "messageParts[].filename", "messageParts[].contentType", "messageParts[].oContentType",
  "messageParts[].md5", "messageParts[].sha256", "messageParts[].sandboxStatus",
  "threatsInfoMap[].threatID", "threatsInfoMap[].threat", "threatsInfoMap[].threatType", "threatsInfoMap[].classification",
  "threatsInfoMap[].threatStatus", "threatsInfoMap[].threatTime", "threatsInfoMap[].threatUrl", "threatsInfoMap[].campaignID",
  "threatsInfoMap[].actors", "threatsInfoMap[].detectionType",
];
// senderIP is optional on clicks: a click authored without its message cannot know the sending MTA.
const CLICK_REQ = ["id", "GUID", "messageID", "url", "classification", "clickTime", "clickIP", "recipient", "sender", "threatID", "threatStatus", "threatTime", "threatURL"];
const CLICK_OPT = ["senderIP", "userAgent", "campaignId"];
const msgKind: KindSchema = { required: MSG_REQ, optional: MSG_OPT };
const clickKind: KindSchema = { required: CLICK_REQ, optional: CLICK_OPT };

const schema: SourceSchema = {
  sourceId: "proofpoint",
  category: "email_security",
  card: "email-proofpoint.md",
  product: "Proofpoint Targeted Attack Protection (TAP)",
  format: "json",
  vendorMatch: ["proofpoint"],
  telemetrySources: ["email_gateway"],
  kinds: { messagesDelivered: msgKind, messagesBlocked: msgKind, clicksPermitted: clickKind, clicksBlocked: clickKind },
};

const ARRAYS = ["messagesDelivered", "messagesBlocked", "clicksPermitted", "clicksBlocked"] as const;
/**
 * Classify a TAP object. A `/v2/siem/all` response → the first non-empty array. A bare
 * object: clicks are blocked when clicked at/after conviction (clickTime ≥ threatTime),
 * messages are blocked when they carry a quarantineFolder.
 */
export function kindOf(record: Record<string, unknown>): string | null {
  if ("queryEndTime" in record) {
    for (const a of ARRAYS) if (Array.isArray(record[a]) && (record[a] as unknown[]).length) return a;
    return null;
  }
  if ("clickTime" in record) return Date.parse(String(record.clickTime)) >= Date.parse(String(record.threatTime)) ? "clicksBlocked" : "clicksPermitted";
  if ("GUID" in record && "messageTime" in record) return record.quarantineFolder ? "messagesBlocked" : "messagesDelivered";
  return null;
}

// ── Helpers ──────────────────────────────────────────────────────────────────

const RISKY_EXT = /^(docm|xlsm|pptm|doc|xls|html?|shtml|svg|zip|rar|7z|iso|img|exe|scr|js|vbs|hta|lnk|one)$/i;
const MIME: Record<string, string> = {
  pdf: "application/pdf", html: "text/html", htm: "text/html", svg: "image/svg+xml", zip: "application/zip",
  docm: "application/vnd.ms-word.document.macroEnabled.12", xlsm: "application/vnd.ms-excel.sheet.macroEnabled.12",
  docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  exe: "application/x-dosexec", iso: "application/x-iso9660-image",
};

const guidFor = (ctx: NativeCtx, imid: string) => b64ish(ctx, entitySeed(ctx, "ppguid", imid), 32);
const threatIdFor = (ctx: NativeCtx, indicator: string) => /^[0-9a-f]{64}$/i.test(indicator) ? indicator.toLowerCase() : ctx.hex(entitySeed(ctx, "ppthreat", indicator), 64);
const threatUrl = (ctx: NativeCtx, id: string) => `https://threatinsight.proofpoint.com/${ctx.uuid(`${ctx.companyId}:pporg`)}/threat/email/${id}`;
/**
 * Conviction time of an indicator. Delivered messages / permitted clicks were seen BEFORE
 * conviction; anchoring it to the next half-hour boundary (+ a per-indicator offset) gives
 * the message and the clicks of the same half-hour the same threatTime.
 */
function convictionAfter(ctx: NativeCtx, t: number, indicator: string): string {
  const half = 30 * 60_000;
  return new Date(Math.floor(t / half) * half + half + ctx.int(entitySeed(ctx, "ppconv", indicator), 60, 600) * 1000).toISOString();
}

interface Threat { indicator: string; type: "url" | "attachment" | "message"; classification: "phish" | "malware" | "spam" | "impostor" }
function threatsOf(ev: TelemetryEvent, f: EmailFacts): Threat[] {
  const out: Threat[] = [];
  const malware = f.threats.includes("Malware");
  const risky = f.attachments.filter(a => malware || RISKY_EXT.test(a.ext ?? ""));
  for (const a of risky) out.push({ indicator: a.sha256 ?? a.name, type: "attachment", classification: "malware" });
  for (const u of f.urls) out.push({ indicator: u, type: "url", classification: malware && !risky.length ? "malware" : "phish" });
  if (!out.length) {
    const bec = !!f.replyTo && domainOf(f.replyTo) !== domainOf(f.from) || /T1534|T1656/.test(ev.mitre_technique ?? "") ||
      /impersonat|bec\b|ceo|lookalike|look-alike|display name/i.test(ev.description ?? "");
    if (f.from) out.push({ indicator: f.from, type: "message", classification: bec ? "impostor" : "phish" });
  }
  return out;
}

function isBlocked(ev: TelemetryEvent): boolean {
  const raw: Raw = ev.raw ?? {};
  const outcome = `${rs(raw, "DeliveryAction") ?? ""} ${rs(raw, "action_result", "event.outcome", "pps.action") ?? ""}`.toLowerCase();
  return ev.event_type === "email_blocked" || ev.event_type === "email_quarantined" || /block|quarantin|reject/.test(outcome);
}

// ── Converter ────────────────────────────────────────────────────────────────

function fromTelemetry(ev: TelemetryEvent, ctx: NativeCtx): NativeLog | null {
  const raw: Raw = ev.raw ?? {};
  const f = emailFacts(ev);
  const user = userEmail(ev) ?? f.to[0];
  if (!user) return null;
  const imid = f.internetMessageId ?? syntheticMessageId(ctx, ev, domainOf(f.from));
  const t = Date.parse(ev.ts);
  const out = (kind: string, record: Record<string, unknown>): NativeLog => ({ sourceId: "proofpoint", kind, format: "json", record, timeMs: t });

  // ── Click (URL Defense) ──
  if (ev.event_type === "email_clicked") {
    const url = f.urls[0] ?? ev.network?.url;
    if (!url) return null;
    const blocked = /block/i.test(rs(raw, "clickStatus") ?? "");
    const tid = threatIdFor(ctx, url);
    const rec: Record<string, unknown> = {
      id: ctx.uuid(`${ev.id}:click`),
      GUID: guidFor(ctx, imid),
      messageID: imid,
      url,
      classification: f.threats.includes("Malware") ? "malware" : "phish",
      clickTime: isoMs(ev.ts),
      clickIP: ev.src_ip ?? rs(raw, "clickIP"),
      userAgent: ev.network?.user_agent ?? rs(raw, "userAgent"),
      recipient: user,
      sender: f.mailFrom ?? f.from,
      senderIP: rs(raw, "senderIP"),
      threatID: tid,
      threatStatus: "active",
      threatTime: blocked ? new Date(t - ctx.int(`${ev.id}:conv`, 300, 3600) * 1000).toISOString() : convictionAfter(ctx, t, url),
      threatURL: threatUrl(ctx, tid),
      campaignId: null,
    };
    if (!rec.clickIP || !rec.sender) return null;
    for (const k of Object.keys(rec)) if (rec[k] === undefined) delete rec[k];
    return out(blocked ? "clicksBlocked" : "clicksPermitted", rec);
  }

  // ── Message ──
  if (!["email_received", "email_blocked", "email_quarantined"].includes(ev.event_type)) return null; // outbound: no TAP SIEM record
  if (ev.event_type === "email_quarantined" && (rs(raw, "ActionType", "Action") || rs(raw, "ActionTrigger"))) return null; // post-delivery removal (TRAP, not TAP SIEM)
  if (f.direction !== "Inbound") return null;
  if (!isThreatMail(ev, f)) return null; // TAP SIEM only reports threat-associated messages
  // Authored as "no verdict at delivery" by the other gateway (ThreatType None): no TAP threat event either.
  if (!f.threats.length && /^none$/i.test(rs(raw, "ThreatType", "ThreatTypes") ?? "")) return null;
  const threats = threatsOf(ev, f);
  if (!threats.length || !f.senderIp) return null;
  const blocked = isBlocked(ev);
  const mseed = entitySeed(ctx, "ppmsg", `${imid}|${user}`);
  const malware = threats.some(x => x.classification === "malware");
  const impostor = threats.some(x => x.classification === "impostor");
  const phish = threats.some(x => x.classification === "phish");
  const num = (k: string) => { const v = rv(raw, k); return v === undefined || isNaN(Number(v)) ? undefined : Number(v); };
  const display = f.fromDisplay;
  const parts: Array<Record<string, unknown>> = [
    { disposition: "inline", filename: "text.txt", contentType: "text/plain", oContentType: "text/plain", md5: ctx.hex(`${mseed}:txt:md5`, 32), sha256: ctx.hex(`${mseed}:txt:sha`, 64), sandboxStatus: null },
    { disposition: "inline", filename: "text.html", contentType: "text/html", oContentType: "text/html", md5: ctx.hex(`${mseed}:html:md5`, 32), sha256: ctx.hex(`${mseed}:html:sha`, 64), sandboxStatus: null },
  ];
  for (const a of f.attachments) {
    const mime = a.mime ?? MIME[a.ext ?? ""] ?? "application/octet-stream";
    const isThreat = threats.some(x => x.type === "attachment" && x.indicator === (a.sha256 ?? a.name));
    parts.push({
      disposition: "attached", filename: a.name, contentType: mime, oContentType: mime,
      md5: ctx.hex(entitySeed(ctx, "ppmd5", `${imid}|${a.name}`), 32),
      // Authored hash when present; otherwise a stable per-attachment value (the authored event carries none).
      sha256: a.sha256 ?? ctx.hex(entitySeed(ctx, "ppsha", `${imid}|${a.name}`), 64),
      sandboxStatus: isThreat ? (blocked || malware ? "threat" : "clean") : /^(pdf|docx|xlsx)$/i.test(a.ext ?? "") ? "clean" : "unsupported",
    });
  }
  const tinfo = threats.map(x => {
    const indicator = x.type === "attachment" ? String(parts.find(pp => pp.filename === x.indicator || pp.sha256 === x.indicator)?.sha256 ?? x.indicator) : x.indicator;
    const id = threatIdFor(ctx, indicator);
    return {
      threatID: id, threat: indicator, threatType: x.type, classification: x.classification, threatStatus: "active",
      threatTime: blocked ? new Date(t + ctx.int(`${mseed}:tt`, 15, 90) * 1000).toISOString() : convictionAfter(ctx, t, indicator),
      threatUrl: threatUrl(ctx, id), campaignID: null,
    };
  });
  const rec: Record<string, unknown> = {
    GUID: guidFor(ctx, imid),
    QID: rs(raw, "QID") ?? `48${b64ish(ctx, `${mseed}:qid`, 4)}${digits(ctx, `${mseed}:qidn`, 6)}`,
    id: ctx.uuid(`${ev.id}:ppid`),
    cluster: `${ctx.companyId}_hosted`,
    messageID: imid,
    messageTime: isoMs(ev.ts),
    sender: f.mailFrom ?? f.from,
    senderIP: f.senderIp,
    fromAddress: f.from ? [f.from] : [],
    headerFrom: rs(raw, "headerFrom") ?? (display ? `"${display}" <${f.from}>` : f.from),
    headerReplyTo: f.replyTo ? (display ? `"${display}" <${f.replyTo}>` : f.replyTo) : null,
    replyToAddress: f.replyTo ? [f.replyTo] : [],
    recipient: [user],
    toAddresses: [f.headerTo && f.headerTo.includes("@") ? f.headerTo : user],
    ccAddresses: [],
    subject: f.subject ?? "",
    messageSize: f.sizeBytes ?? (f.attachments.reduce((n, a) => n + (a.size ?? 0), 0) + ctx.int(`${mseed}:size`, 3500, 60000)),
    xmailer: f.xmailer ?? null,
    spamScore: num("spamScore") ?? ctx.int(`${mseed}:spam`, 0, 25),
    phishScore: num("phishScore") ?? (phish ? ctx.int(`${mseed}:phish`, blocked ? 85 : 40, blocked ? 100 : 79) : 0),
    malwareScore: malware ? (blocked ? 100 : ctx.int(`${mseed}:mal`, 40, 79)) : 0,
    impostorScore: impostor ? ctx.int(`${mseed}:imp`, 80, 99) : 0,
    completelyRewritten: f.urls.length > 0,
    modulesRun: ["access", "av", "zerohour", "spf", "dkimv", "spam", "dmarc", "pdr", ...(f.attachments.length ? ["sandbox"] : []), "urldefense"],
    policyRoutes: Array.isArray(rv(raw, "policyRoutes")) ? (rv(raw, "policyRoutes") as unknown[]).map(String) : ["default_inbound"],
    // Value strings for quarantineFolder / quarantineRule are UNVERIFIED in the card (populated on messagesBlocked).
    quarantineFolder: blocked ? (malware ? "Attachment Defense" : impostor ? "Impostor" : "Phish") : null,
    quarantineRule: blocked ? (malware ? "module.sandbox.threat" : impostor ? "module.spam.impostor" : "module.spam.phish") : null,
    messageParts: parts,
    threatsInfoMap: tinfo,
  };
  if (!rec.sender) return null;
  return out(blocked ? "messagesBlocked" : "messagesDelivered", rec);
}

// ── Use cases ────────────────────────────────────────────────────────────────

const useCases: UseCase[] = [
  {
    id: "proofpoint.click-permitted",
    title: "User click on a malicious URL was permitted",
    sourceId: "proofpoint", kinds: ["clicksPermitted"], severity: "high", mitre: ["T1204.001", "T1566.002"],
    description: "clicksPermitted with classification phish / malware: URL Defense let the user through (typically clickTime < threatTime — the URL was convicted after the click). Assume the credentials were entered: check the identity provider for sign-ins from new IPs after clickTime and reset the account.",
    logic: "Splunk (TA-proofpoint-tap):\nsourcetype=\"pps:tap:click\" eventtype=clicksPermitted classification IN (phish, malware)\n| eval before_conviction=if(strptime(clickTime,\"%FT%T.%3NZ\")<strptime(threatTime,\"%FT%T.%3NZ\"),1,0)\n| table clickTime recipient clickIP url threatTime before_conviction GUID",
    match: { field: "classification", op: "in", value: ["phish", "malware"] },
    falsePositives: ["Security team testing a known-bad URL from an analysis workstation"],
  },
  {
    id: "proofpoint.click-blocked",
    title: "Click on a convicted URL was blocked",
    sourceId: "proofpoint", kinds: ["clicksBlocked"], severity: "medium", mitre: ["T1204.001"],
    description: "clicksBlocked: the user tried to open a URL already convicted. Nothing was compromised by this click, but the user is engaging with the campaign — check for other clicks on the same threatID / GUID and whether the message is still in mailboxes.",
    logic: "Splunk: sourcetype=\"pps:tap:click\" eventtype=clicksBlocked | stats count values(recipient) by threatID url",
    match: { field: "threatStatus", op: "eq", value: "active" },
    falsePositives: ["Repeated clicks by an analyst investigating the message"],
  },
  {
    id: "proofpoint.threat-delivered",
    title: "Message with an active phish / malware threat was delivered",
    sourceId: "proofpoint", kinds: ["messagesDelivered"], severity: "high", mitre: ["T1566"],
    description: "messagesDelivered with threatsInfoMap[].threatStatus=active and classification phish or malware: the threat reached the inbox (often convicted after delivery — threatTime > messageTime). Pull the message (TRAP / CLEAR) and hunt clicks on the same GUID.",
    logic: "Splunk: sourcetype=\"pps:tap:message\" eventtype=messagesDelivered | spath threatsInfoMap{}.classification | search threatsInfoMap{}.threatStatus=active threatsInfoMap{}.classification IN (phish, malware)",
    match: { all: [{ field: "threatsInfoMap[].threatStatus", op: "eq", value: "active" }, { field: "threatsInfoMap[].classification", op: "in", value: ["phish", "malware"] }] },
    falsePositives: ["Threats later marked falsePositive (threatStatus changes)"],
  },
  {
    id: "proofpoint.impostor-bec",
    title: "Impostor (BEC) message",
    sourceId: "proofpoint", kinds: ["messagesDelivered", "messagesBlocked"], severity: "high", mitre: ["T1566", "T1656"],
    description: "classification impostor or impostorScore ≥ 80: a display-name / look-alike sender, frequently with a Reply-To on a free-mail domain. No link or attachment is needed for the fraud — confirm whether the recipient replied or acted on payment instructions.",
    logic: "Splunk: sourcetype=\"pps:tap:message\" (impostorScore>=80 OR threatsInfoMap{}.classification=impostor) | table messageTime headerFrom headerReplyTo recipient{} subject impostorScore",
    match: { any: [{ field: "impostorScore", op: "gte", value: 80 }, { field: "threatsInfoMap[].classification", op: "eq", value: "impostor" }] },
    falsePositives: ["Executives mailing from personal accounts"],
  },
  {
    id: "proofpoint.sandbox-malicious-attachment",
    title: "Attachment convicted by the sandbox",
    sourceId: "proofpoint", kinds: ["messagesDelivered", "messagesBlocked"], severity: "high", mitre: ["T1566.001"],
    description: "messageParts[].sandboxStatus=threat or an attachment threat with classification malware. Use the part sha256 / threatID to find every recipient and any endpoint that executed the file.",
    logic: "Splunk: sourcetype=\"pps:tap:message\" (messageParts{}.sandboxStatus=threat OR (threatsInfoMap{}.threatType=attachment threatsInfoMap{}.classification=malware))",
    match: { any: [
      { field: "messageParts[].sandboxStatus", op: "eq", value: "threat" },
      { all: [{ field: "threatsInfoMap[].threatType", op: "eq", value: "attachment" }, { field: "threatsInfoMap[].classification", op: "eq", value: "malware" }] },
    ] },
    falsePositives: ["Pentest payloads sent under an approved engagement"],
  },
  {
    id: "proofpoint.delivered-then-clicked",
    title: "Threat message delivered and then clicked",
    sourceId: "proofpoint", kinds: ["messagesDelivered", "clicksPermitted"], severity: "critical", mitre: ["T1566.002", "T1204.001"],
    description: "A messagesDelivered event and a clicksPermitted event share the same GUID within 24 h: the full initial-access chain is in TAP. Highest priority: the user opened the lure and the click went through.",
    logic: "Splunk:\nsourcetype=pps:tap:* (eventtype=messagesDelivered OR eventtype=clicksPermitted)\n| stats dc(eventtype) as kinds values(recipient) values(clickIP) by GUID | where kinds=2",
    match: { any: [{ field: "messageTime", op: "exists" }, { field: "clickTime", op: "exists" }] },
    threshold: { groupBy: ["GUID"], count: 2, windowSec: 86400, distinct: "clickTime" },
    falsePositives: ["Analyst click on a delivered sample"],
  },
];

export const source: NativeSource = { schema, fromTelemetry, useCases };
