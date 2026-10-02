/**
 * Microsoft Defender for Office 365 — Advanced Hunting email tables, delivered
 * through the Defender XDR Streaming API (Event Hub / Storage).
 * Card: docs/log-schemas/email-defender-o365.md
 *
 * One log = one element of the streaming `records[]` array:
 *   { time, tenantId, category: "AdvancedHunting-<Table>", properties: { <Advanced Hunting row> } }
 * The row keys are the table's column names; DetectionMethods / ConfidenceLevel /
 * AuthenticationDetails / AdditionalFields / UrlChain stay JSON-encoded STRINGS;
 * Timestamp has 7 fractional digits + "Z". LatestDeliveryLocation / LatestDeliveryAction
 * are not part of streaming records and are never emitted (the card samples D1/D6/D8
 * are query-API rows that do carry them; they are accepted as optional).
 *
 * fromTelemetry() returns the primary row of an event (EmailEvents for a delivery /
 * block, UrlClickEvents for a click, EmailPostDeliveryEvents for a ZAP / remediation).
 * The EmailUrlInfo / EmailAttachmentInfo rows of the same message are produced by
 * {@link companionLogs} (same NetworkMessageId + ReportId) — the NativeSource contract
 * returns one log per event (see final report).
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { KindSchema, NativeCtx, NativeLog, NativeSource, SourceSchema, UseCase } from "../types";
import {
  aadObjectId, domainOf, emailFacts, entitySeed, isThreatMail, iso7, rs, syntheticMessageId, userEmail, type EmailFacts, type Raw,
} from "./collab-email-shared";

// ── Schema ───────────────────────────────────────────────────────────────────

const ENV_REQ = ["time", "tenantId", "category"];
const ENV_OPT = ["operationName"]; // present in real streaming records, not in the doc snippet (UNVERIFIED) — accepted, never emitted
const P = (cols: string[]) => cols.map(c => `properties.${c}`);
const kind = (req: string[], opt: string[]): KindSchema => ({ required: [...ENV_REQ, ...P(req)], optional: [...ENV_OPT, ...P(opt)] });

const EMAIL_EVENTS_OPT = [
  "SenderMailFromAddress", "SenderDisplayName", "SenderObjectId", "SenderMailFromDomain", "SenderFromDomain", "SenderIPv4", "SenderIPv6",
  "RecipientObjectId", "Subject", "EmailClusterId", "ThreatTypes", "ThreatNames", "DetectionMethods", "ConfidenceLevel", "BulkComplaintLevel",
  "EmailAction", "EmailActionPolicy", "EmailActionPolicyGuid", "AuthenticationDetails", "AttachmentCount", "UrlCount", "EmailLanguage",
  "Connectors", "OrgLevelAction", "OrgLevelPolicy", "UserLevelAction", "UserLevelPolicy", "AdditionalFields", "LatestDeliveryLocation",
  "LatestDeliveryAction", "OriginalThreatTypes", "OriginalDetectionMethods", "OriginalConfidenceLevel", "DistributionList",
  "ExchangeTransportRule", "ForwardingInformation", "Context", "To", "Cc", "ThreatClassification", "RecipientDomain", "EmailSize",
  "IsFirstContact", "Topics",
];
const schema: SourceSchema = {
  sourceId: "defender_o365",
  category: "email_security",
  card: "email-defender-o365.md",
  product: "Microsoft Defender for Office 365",
  format: "json",
  vendorMatch: ["defender for office", "microsoft defender for office 365", "mdo"],
  telemetrySources: ["email_gateway"],
  kinds: {
    EmailEvents: kind(["Timestamp", "NetworkMessageId", "InternetMessageId", "SenderFromAddress", "RecipientEmailAddress", "EmailDirection", "DeliveryAction", "DeliveryLocation", "ReportId"], EMAIL_EVENTS_OPT),
    EmailUrlInfo: kind(["Timestamp", "NetworkMessageId", "Url", "UrlDomain", "ReportId"], ["UrlLocation", "UrlChainId", "UrlChainPosition"]),
    EmailAttachmentInfo: kind(["Timestamp", "NetworkMessageId", "RecipientEmailAddress", "FileName", "ReportId"],
      ["SenderFromAddress", "SenderDisplayName", "SenderObjectId", "RecipientObjectId", "FileType", "FileExtension", "SHA256", "FileSize", "ThreatTypes", "ThreatNames", "DetectionMethods", "AdditionalFields"]),
    UrlClickEvents: kind(["Timestamp", "Url", "ActionType", "AccountUpn", "ReportId"],
      ["Workload", "NetworkMessageId", "ThreatTypes", "DetectionMethods", "IPAddress", "IsClickedThrough", "UrlChain", "AppName", "AppVersion", "SourceId"]),
    EmailPostDeliveryEvents: kind(["Timestamp", "NetworkMessageId", "Action", "ActionType", "RecipientEmailAddress", "ReportId"],
      ["InternetMessageId", "ActionTrigger", "ActionResult", "DeliveryLocation", "ThreatTypes", "DetectionMethods", "SenderFromAddress", "EmailDirection", "SourceLocation"]),
  },
};

/** Classify a streaming record, a `{records:[…]}` envelope, or a bare Advanced Hunting row. */
export function kindOf(record: Record<string, unknown>): string | null {
  if (Array.isArray(record.records)) return record.records.length ? kindOf(record.records[0] as Record<string, unknown>) : null;
  if (typeof record.category === "string") {
    const k = record.category.replace(/^AdvancedHunting-/, "");
    return schema.kinds[k] ? k : null;
  }
  if ("AccountUpn" in record && "ActionType" in record) return "UrlClickEvents";
  if ("Action" in record && "ActionType" in record) return "EmailPostDeliveryEvents";
  if ("FileName" in record) return "EmailAttachmentInfo";
  if ("Url" in record && "UrlDomain" in record) return "EmailUrlInfo";
  if ("DeliveryAction" in record) return "EmailEvents";
  return null;
}

// ── Helpers ──────────────────────────────────────────────────────────────────

const MAIL_EVENTS = new Set(["email_received", "email_blocked", "email_quarantined", "email_clicked", "email_sent"]);

/** NetworkMessageId: authored value, else stable per Internet Message-ID (so the message, its clicks and its ZAP share it). */
export function networkMessageId(ctx: NativeCtx, f: EmailFacts, ev: TelemetryEvent): string {
  // NetworkMessageId is assigned by the tenant's Exchange Online — an authored value is re-keyed per
  // tenant (still one value per message), so two companies never show the same message id.
  const seed = f.networkMessageId ? entitySeed(ctx, "nmid-authored", f.networkMessageId)
    : f.internetMessageId ? entitySeed(ctx, "nmid", f.internetMessageId) : `${ev.id}:nmid`;
  const u = ctx.uuid(seed);
  return `${u.slice(0, 24)}08dc${ctx.hex(`${seed}:t`, 8)}`;
}
function internetMessageId(ctx: NativeCtx, f: EmailFacts, ev: TelemetryEvent): string {
  return f.internetMessageId ?? syntheticMessageId(ctx, ev, domainOf(f.from));
}
const reportIdFor = (ctx: NativeCtx, nmid: string, rcpt: string, n: number) => `${nmid}-${ctx.int(entitySeed(ctx, "rid1", `${nmid}|${rcpt}`), 1_000_000_000, 1_999_999_999)}${ctx.int(entitySeed(ctx, "rid2", `${nmid}|${rcpt}`), 100_000_000, 999_999_999)}-${n}`;

function detectionMethods(raw: Raw, f: EmailFacts, threats: string[]): string {
  if (!threats.length) return "";
  const tech = rs(raw, "ThreatsAndDetectionTech");
  if (tech) {
    const o: Record<string, string[]> = {};
    for (const part of tech.split("|")) { const m = /^\s*(\w+):\s*(.+)$/.exec(part); if (m) (o[m[1]] ??= []).push(m[2].trim()); }
    if (o.Phish && threats.includes("Malware") && !threats.includes("Phish")) return JSON.stringify({ Malware: ["File detonation"] });
    if (Object.keys(o).length) return JSON.stringify(o);
  }
  const dm = rs(raw, "DetectionMethods", "DetectionMethod");
  const o: Record<string, string[]> = {};
  for (const t of threats) {
    if (dm && !/^none$/i.test(dm)) o[t] = [dm];
    else if (t === "Malware") o[t] = ["File detonation"];
    else if (t === "Phish") o[t] = [f.urls.length ? "URL malicious reputation" : f.attachments.length ? "File detonation reputation" : "Advanced filter"];
    else o[t] = ["Mixed analysis detection"];
  }
  return JSON.stringify(o);
}
function authDetails(f: EmailFacts): string {
  const n = (v?: string) => (v ? v.toLowerCase() : "none");
  const comp = f.compauth ?? (f.dmarc === "pass" ? "pass" : f.dmarc === "fail" ? "fail" : f.spf === "pass" || f.dkim === "pass" ? "softpass" : "none");
  return JSON.stringify({ SPF: n(f.spf), DKIM: n(f.dkim), DMARC: n(f.dmarc), CompAuth: comp });
}
function location(v: string | undefined, action: string): string {
  if (v) {
    if (/^inbox/i.test(v)) return "Inbox/folder";
    if (/quarantine/i.test(v)) return "Quarantine";
    if (/junk/i.test(v)) return "Junk folder";
    if (/deleted/i.test(v)) return "Deleted items folder";
    if (/external|on-prem/i.test(v)) return "On-premises/external";
  }
  return action === "Blocked" ? "Quarantine" : action === "Junked" ? "Junk folder" : "Inbox/folder";
}

interface Msg { f: EmailFacts; user: string; nmid: string; imid: string; ts: string; reportId: string; threats: string[]; dm: string }

/** Attachment types that carry a payload (archives, executables, scripts, macro documents, disk images). */
const WEAPON_EXT = /^(zip|rar|7z|gz|iso|img|vhd|vhdx|exe|scr|dll|com|msi|js|jse|vbs|vbe|wsf|hta|lnk|bat|cmd|ps1|docm|xlsm|pptm|dotm|one)$/i;
/**
 * The verdict Defender reaches on the message. A lure whose weapon is an attached payload (no link)
 * is a Malware verdict from Safe Attachments detonation — "Phish" is for credential-harvest links /
 * forms and impersonation, not for a ZIP that drops a trojan.
 */
function verdictOf(f: EmailFacts): string[] {
  const t = [...f.threats];
  if (t.includes("Phish") && !t.includes("Malware") && !f.urls.length && f.attachments.some(a => WEAPON_EXT.test(a.ext ?? "")))
    return t.map(x => (x === "Phish" ? "Malware" : x));
  return t;
}
function message(ev: TelemetryEvent, ctx: NativeCtx): Msg | null {
  const f = emailFacts(ev);
  const user = userEmail(ev) ?? f.to[0];
  if (!user) return null;
  const nmid = networkMessageId(ctx, f, ev);
  const threats = verdictOf(f);
  return { f, user, nmid, imid: internetMessageId(ctx, f, ev), ts: iso7(ev.ts, ctx, `${ev.id}:ts`), reportId: reportIdFor(ctx, nmid, user, 1), threats, dm: detectionMethods(ev.raw ?? {}, f, threats) };
}

function envelope(ctx: NativeCtx, ev: TelemetryEvent, table: string, row: Record<string, unknown>): Record<string, unknown> {
  const t = new Date(Date.parse(ev.ts) + ctx.int(`${ev.id}:${table}:lag`, 2, 9) * 1000).toISOString().slice(0, 19);
  return { time: `${t}.0000000Z`, tenantId: ctx.tenant.azureTenantId, category: `AdvancedHunting-${table}`, properties: row };
}

// ── Converter ────────────────────────────────────────────────────────────────

function fromTelemetry(ev: TelemetryEvent, ctx: NativeCtx): NativeLog | null {
  if (!MAIL_EVENTS.has(ev.event_type)) return null;
  const raw: Raw = ev.raw ?? {};
  const m = message(ev, ctx);
  if (!m) return null;
  const { f, user, nmid } = m;
  const out = (table: string, row: Record<string, unknown>): NativeLog =>
    ({ sourceId: "defender_o365", kind: table, format: "json", record: envelope(ctx, ev, table, row), timeMs: Date.parse(ev.ts) });

  // ── Safe Links click ──
  if (ev.event_type === "email_clicked") {
    const url = f.urls[0] ?? ev.network?.url;
    if (!url) return null;
    const status = (rs(raw, "clickStatus", "pps.clickStatus", "action_result") ?? "permitted").toLowerCase();
    const blocked = /block/.test(status);
    const knownBad = threatsAtClick(ev, f);
    const row: Record<string, unknown> = {
      Timestamp: m.ts, Url: url, ActionType: blocked ? "ClickBlocked" : "ClickAllowed", AccountUpn: user, Workload: "Email",
      NetworkMessageId: nmid, ThreatTypes: knownBad ? "Phish" : "", DetectionMethods: knownBad ? JSON.stringify({ Phish: ["URL detonation reputation"] }) : "",
    };
    if (ev.src_ip) row.IPAddress = ev.src_ip;
    row.IsClickedThrough = !blocked && knownBad;
    row.UrlChain = JSON.stringify([url]);
    row.ReportId = ctx.uuid(`${ev.id}:click`);
    return out("UrlClickEvents", row);
  }

  // ── Post-delivery remediation / ZAP ──
  const postAction = rs(raw, "ActionType", "Action");
  const trigger = rs(raw, "ActionTrigger");
  if (ev.event_type === "email_quarantined" && (postAction || trigger)) {
    const zap = /zap/i.test(trigger ?? "") || /zap|zero-hour/i.test(ev.description ?? "");
    const malware = m.threats.includes("Malware") && !m.threats.includes("Phish");
    const threats = m.threats.length ? m.threats : ["Phish"];
    return out("EmailPostDeliveryEvents", {
      Timestamp: m.ts, NetworkMessageId: nmid, InternetMessageId: m.imid,
      Action: postAction ?? (zap ? "Moved to quarantine" : "Soft delete"),
      ActionType: zap ? (malware ? "Malware ZAP" : "Phish ZAP") : "Manual remediation",
      ActionTrigger: zap ? "SpecialAction" : "AdminAction",
      ActionResult: rs(raw, "ActionResult") ?? "Success",
      RecipientEmailAddress: user,
      DeliveryLocation: location(rs(raw, "DeliveryLocation"), "Blocked"),
      ThreatTypes: threats.join(", "),
      DetectionMethods: detectionMethods(raw, f, threats),
      ReportId: ctx.uuid(`${ev.id}:pde`),
      SenderFromAddress: f.from ?? "",
      EmailDirection: f.direction,
      SourceLocation: "Inbox",
    });
  }

  // ── EmailEvents (delivery verdict) ──
  return out("EmailEvents", emailEventsRow(ev, ctx, m));
}

/** Whether Safe Links already knew the clicked URL was bad (authored verdict on the click event). */
function threatsAtClick(ev: TelemetryEvent, f: EmailFacts): boolean {
  return f.threats.includes("Phish") || /malicious|phish/i.test(rs(ev.raw, "url.malicious_detected", "classification") ?? "");
}

/** EmailEvents DeliveryAction of the message as authored. */
function deliveryAction(ev: TelemetryEvent): string {
  const raw: Raw = ev.raw ?? {};
  const outcome = (rs(raw, "action_result", "event.outcome", "pps.action") ?? "").toLowerCase();
  const action = rs(raw, "DeliveryAction") ?? (ev.event_type === "email_blocked" || ev.event_type === "email_quarantined" || /block|quarantin/.test(outcome) ? "Blocked" : "Delivered");
  return /^(Delivered|Junked|Blocked|Replaced)$/.test(action) ? action : /deliver/i.test(action) ? "Delivered" : "Blocked";
}
/**
 * Default MDO policy quarantines a Malware / high-confidence Phish verdict. A message the story
 * DELIVERS with no override in the event (transport-rule allow, Org/User-level allow) was therefore
 * clean at delivery — the verdict was missed (the card's "delivered clean, convicted later" case) and
 * the conviction belongs to a later ZAP record.
 */
function deliveredClean(ev: TelemetryEvent, m: Msg): boolean {
  const raw: Raw = ev.raw ?? {};
  const etr = /transport rule/i.test(rs(raw, "block.reason") ?? "");
  return deliveryAction(ev) === "Delivered" && !etr && !rs(raw, "OrgLevelAction", "UserLevelAction") && m.threats.some(t => t === "Malware" || t === "Phish");
}

function emailEventsRow(ev: TelemetryEvent, ctx: NativeCtx, m: Msg): Record<string, unknown> {
  const raw: Raw = ev.raw ?? {};
  const { f, user, nmid } = m;
  const action = deliveryAction(ev);
  const loc = location(rs(raw, "DeliveryLocation", "OriginalDeliveryLocation"), action);
  const etr = /transport rule/i.test(rs(raw, "block.reason") ?? "");
  const cleanAtDelivery = deliveredClean(ev, m);
  const threats = cleanAtDelivery ? m.threats.filter(t => t === "Spam") : m.threats;
  const malware = threats.includes("Malware");
  const phish = threats.includes("Phish");
  let emailAction = "No action taken";
  let policy = "";
  if (action === "Blocked") { emailAction = "Send to quarantine"; policy = malware ? (f.attachments.length ? "Safe Attachments" : "Antimalware") : phish ? "Antispam phishing" : "Antispam"; }
  else if (action === "Junked") { emailAction = "Move message to junk mail folder"; policy = phish ? "Antispam phishing" : "Antispam"; }
  const scl = rs(raw, "SpamConfidenceLevel");
  const conf: Record<string, string> = {};
  if (phish) conf.Phish = rs(raw, "PhishConfidenceLevel") && !/none/i.test(rs(raw, "PhishConfidenceLevel")!) ? rs(raw, "PhishConfidenceLevel")! : "High";
  if (!malware) conf.Spam = scl ?? (threats.includes("Spam") ? "5" : "1");
  const internalSender = domainOf(f.from) === domainOf(user);
  const size = f.sizeBytes ?? (f.attachments.reduce((n, a) => n + (a.size ?? 0), 0) + ctx.int(`${ev.id}:sz`, 3500, 60000));
  const row: Record<string, unknown> = {
    Timestamp: m.ts,
    NetworkMessageId: nmid,
    InternetMessageId: m.imid,
    SenderMailFromAddress: f.mailFrom ?? f.from ?? "",
    SenderFromAddress: f.from ?? "",
    SenderDisplayName: f.fromDisplay ?? "",
    SenderObjectId: internalSender && f.from ? aadObjectId(ctx, f.from) : "",
    SenderMailFromDomain: domainOf(f.mailFrom ?? f.from) ?? "",
    SenderFromDomain: domainOf(f.from) ?? "",
    SenderIPv4: f.senderIp && /^\d{1,3}(\.\d{1,3}){3}$/.test(f.senderIp) ? f.senderIp : "",
    SenderIPv6: f.senderIp && f.senderIp.includes(":") ? f.senderIp : "",
    RecipientEmailAddress: user,
    RecipientObjectId: aadObjectId(ctx, user),
    Subject: f.subject ?? "",
    EmailClusterId: 3019480000000 + ctx.int(entitySeed(ctx, "cluster", `${f.from ?? ""}|${f.subject ?? ""}`), 1, 9_999_999),
    EmailDirection: f.direction,
    DeliveryAction: action,
    DeliveryLocation: loc,
    ThreatTypes: threats.join(", "),
    ThreatNames: malware ? malwareName(f) : "",
    DetectionMethods: cleanAtDelivery ? detectionMethods(raw, f, threats) : m.dm,
    ConfidenceLevel: JSON.stringify(conf),
    BulkComplaintLevel: 0,
    EmailAction: emailAction,
    EmailActionPolicy: policy,
    EmailActionPolicyGuid: policy ? ctx.uuid(`${ctx.companyId}:policy:${policy}`) : "",
    AuthenticationDetails: authDetails(f),
    AttachmentCount: Number(rs(raw, "AttachmentCount") ?? f.attachments.length),
    UrlCount: Number(rs(raw, "UrlCount") ?? f.urls.length),
    EmailLanguage: f.language ?? "en",
    Connectors: "",
    OrgLevelAction: rs(raw, "OrgLevelAction") ?? (etr && action === "Delivered" ? "Allow" : ""),
    OrgLevelPolicy: rs(raw, "OrgLevelPolicy") ?? (etr && action === "Delivered" ? "Exchange transport rule" : ""),
    UserLevelAction: rs(raw, "UserLevelAction") ?? "",
    UserLevelPolicy: rs(raw, "UserLevelPolicy") ?? "",
    ReportId: m.reportId,
    AdditionalFields: "{}",
    OriginalThreatTypes: threats.join(", "),
    OriginalDetectionMethods: cleanAtDelivery ? detectionMethods(raw, f, threats) : m.dm,
    OriginalConfidenceLevel: JSON.stringify(conf),
    To: f.headerTo ?? user,
    Cc: "",
    RecipientDomain: domainOf(user) ?? "",
    EmailSize: size,
    IsFirstContact: isThreatMail(ev, f) ? 1 : 0,
  };
  return row;
}
function malwareName(f: EmailFacts): string {
  const ext = f.attachments[0]?.ext ?? "";
  if (/^(html?|svg|shtml)$/.test(ext)) return "Trojan:HTML/Phish.SMG!MTB";
  if (/^(docm|xlsm|pptm|doc|xls)$/.test(ext)) return "TrojanDownloader:O97M/Donoff!MTB";
  if (/^(zip|rar|7z|iso|img)$/.test(ext)) return "Trojan:Win32/Wacatac.B!ml";
  return "Trojan:Script/Phonzy.A!ml";
}

/**
 * EmailUrlInfo + EmailAttachmentInfo rows of the message an EmailEvents row
 * describes (same NetworkMessageId / ReportId / Timestamp). Empty for clicks
 * and post-delivery events.
 */
export function companionLogs(ev: TelemetryEvent, ctx: NativeCtx): NativeLog[] {
  if (!MAIL_EVENTS.has(ev.event_type) || ev.event_type === "email_clicked") return [];
  const raw: Raw = ev.raw ?? {};
  if (ev.event_type === "email_quarantined" && (rs(raw, "ActionType", "Action") || rs(raw, "ActionTrigger"))) return [];
  const m = message(ev, ctx);
  if (!m) return [];
  const out: NativeLog[] = [];
  const wrap = (table: string, row: Record<string, unknown>) =>
    out.push({ sourceId: "defender_o365", kind: table, format: "json", record: envelope(ctx, ev, table, row), timeMs: Date.parse(ev.ts) });
  m.f.urls.forEach(url => {
    let host = "";
    try { host = new URL(url).hostname; } catch { /* keep empty */ }
    wrap("EmailUrlInfo", { Timestamp: m.ts, NetworkMessageId: m.nmid, Url: url, UrlDomain: host, UrlLocation: "Body", UrlChainId: "", UrlChainPosition: 0, ReportId: m.reportId });
  });
  const malware = m.threats.includes("Malware") && !deliveredClean(ev, m);
  for (const a of m.f.attachments) {
    wrap("EmailAttachmentInfo", {
      Timestamp: m.ts, NetworkMessageId: m.nmid, SenderFromAddress: m.f.from ?? "", SenderDisplayName: m.f.fromDisplay ?? "", SenderObjectId: "",
      RecipientEmailAddress: m.user, RecipientObjectId: aadObjectId(ctx, m.user), FileName: a.name, FileType: a.ext ?? "", FileExtension: a.ext ?? "",
      SHA256: a.sha256 ?? "", FileSize: a.size ?? ctx.int(`${ev.id}:att:${a.name}`, 9000, 450000),
      ThreatTypes: malware ? "Malware" : "", ThreatNames: malware ? malwareName(m.f) : "",
      DetectionMethods: malware ? JSON.stringify({ Malware: ["File detonation"] }) : "", ReportId: m.reportId, AdditionalFields: "{}",
    });
  }
  return out;
}

// ── Use cases ────────────────────────────────────────────────────────────────

const useCases: UseCase[] = [
  {
    id: "defender_o365.phish-clicked-after-delivery",
    title: "User clicked a link in a message that is (now) known phish",
    sourceId: "defender_o365", kinds: ["EmailEvents", "UrlClickEvents"], severity: "high", mitre: ["T1566.002", "T1204.001"],
    description: "Joins, per NetworkMessageId, an EmailEvents row carrying a Phish verdict (at delivery or after re-verdict) with an allowed Safe Links click. \"Delivered clean, clicked, convicted later\" is exactly the case Safe Links could not stop — check the clicker's sign-ins (AccountUpn + IPAddress) right after the click.",
    logic: "Defender KQL:\nEmailEvents | where ThreatTypes has \"Phish\" | distinct NetworkMessageId, RecipientEmailAddress\n| join kind=inner (UrlClickEvents | where ActionType == \"ClickAllowed\") on NetworkMessageId\n| project Timestamp, AccountUpn, Url, IPAddress, IsClickedThrough",
    match: { any: [
      { all: [{ field: "category", op: "eq", value: "AdvancedHunting-EmailEvents" }, { field: "properties.ThreatTypes", op: "contains", value: "Phish" }] },
      { all: [{ field: "category", op: "eq", value: "AdvancedHunting-UrlClickEvents" }, { field: "properties.ActionType", op: "eq", value: "ClickAllowed" }] },
    ] },
    threshold: { groupBy: ["properties.NetworkMessageId"], count: 2, windowSec: 86400, distinct: "category" },
    falsePositives: ["Security staff detonating reported messages from an analysis mailbox"],
  },
  {
    id: "defender_o365.safe-links-click-through",
    title: "User clicked through a Safe Links warning page",
    sourceId: "defender_o365", kinds: ["UrlClickEvents"], severity: "high", mitre: ["T1204.001"],
    description: "IsClickedThrough=true: Safe Links showed the warning page and the user pressed \"Continue anyway\". Treat the account as possibly phished — check sign-ins from new IPs minutes later.",
    logic: "Defender KQL:\nUrlClickEvents | where IsClickedThrough == true | project Timestamp, AccountUpn, Url, ThreatTypes, IPAddress, NetworkMessageId",
    match: { field: "properties.IsClickedThrough", op: "eq", value: true },
    falsePositives: ["Analysts verifying a reported URL from a sandbox"],
  },
  {
    id: "defender_o365.malicious-attachment",
    title: "Malware detected in an email attachment",
    sourceId: "defender_o365", kinds: ["EmailEvents", "EmailAttachmentInfo"], severity: "high", mitre: ["T1566.001"],
    description: "ThreatTypes contains Malware on the message or on an attachment row (Safe Attachments detonation / antimalware). Use SHA256 + SenderFromAddress to scope the campaign and confirm that every copy is in quarantine (DeliveryLocation / EmailPostDeliveryEvents).",
    logic: "Defender KQL:\nEmailAttachmentInfo | where ThreatTypes has \"Malware\"\n| join kind=inner (EmailEvents | project NetworkMessageId, RecipientEmailAddress, DeliveryAction, DeliveryLocation) on NetworkMessageId",
    match: { field: "properties.ThreatTypes", op: "contains", value: "Malware" },
    falsePositives: ["Test files (EICAR) sent by the security team"],
  },
  {
    id: "defender_o365.risky-attachment-type-delivered",
    title: "HTML / SVG / macro / archive attachment delivered",
    sourceId: "defender_o365", kinds: ["EmailAttachmentInfo"], severity: "medium", mitre: ["T1566.001", "T1027.006"],
    description: "Attachments with FileExtension html/htm/shtml/svg (HTML smuggling, credential forms), docm/xlsm (macros) or zip/iso/img reaching mailboxes. Not malicious by default — hunt for first-contact senders and inspect the file.",
    logic: "Defender KQL:\nEmailAttachmentInfo | where FileExtension in~ (\"html\",\"htm\",\"shtml\",\"svg\",\"docm\",\"xlsm\",\"zip\",\"iso\",\"img\")\n| join (EmailEvents | where DeliveryAction == \"Delivered\") on NetworkMessageId",
    match: { field: "properties.FileExtension", op: "in", value: ["html", "htm", "shtml", "svg", "docm", "xlsm", "pptm", "zip", "iso", "img"] },
    falsePositives: ["Vendors sending signed macro workbooks", "Zipped invoices from known suppliers"],
  },
  {
    id: "defender_o365.impersonation-bec",
    title: "User / domain impersonation (BEC) verdict",
    sourceId: "defender_o365", kinds: ["EmailEvents"], severity: "high", mitre: ["T1566", "T1656"],
    description: "DetectionMethods \"Impersonation user/domain\" or EmailActionPolicy Anti-phishing impersonation: a display name or domain imitating an executive / partner. Even when junked, check whether the recipient replied (outbound mail to the Reply-To) and whether the same sender reached others.",
    logic: "Defender KQL:\nEmailEvents | where DetectionMethods has \"Impersonation\" or EmailActionPolicy has \"impersonation\"\n| project Timestamp, SenderFromAddress, SenderDisplayName, RecipientEmailAddress, DeliveryLocation",
    match: { any: [{ field: "properties.DetectionMethods", op: "icontains", value: "impersonation" }, { field: "properties.EmailActionPolicy", op: "icontains", value: "impersonation" }] },
    falsePositives: ["Executives writing from personal addresses (add to impersonation allow list)"],
  },
  {
    id: "defender_o365.post-delivery-zap",
    title: "Message removed after delivery (ZAP / remediation)",
    sourceId: "defender_o365", kinds: ["EmailPostDeliveryEvents"], severity: "medium", mitre: ["T1566"],
    description: "Phish ZAP / Malware ZAP or a manual remediation pulled a message that had already been delivered. Everything that happened between delivery and the ZAP (opens, clicks, attachment launches) still needs investigation — the removal does not undo it.",
    logic: "Defender KQL:\nEmailPostDeliveryEvents | where ActionType in (\"Phish ZAP\",\"Malware ZAP\",\"Manual remediation\")\n| join kind=leftouter UrlClickEvents on NetworkMessageId",
    match: { field: "properties.ActionType", op: "in", value: ["Phish ZAP", "Malware ZAP", "Manual remediation"] },
    falsePositives: ["Bulk clean-up of spam campaigns by admins"],
  },
  {
    id: "defender_o365.delivered-dmarc-fail",
    title: "Inbound mail delivered despite DMARC failure",
    sourceId: "defender_o365", kinds: ["EmailEvents"], severity: "medium", mitre: ["T1566", "T1585.002"],
    description: "AuthenticationDetails shows DMARC fail but the message was Delivered to the inbox (no quarantine / junk). Spoofed senders of your own or partner domains land here when DMARC policy is p=none or an override allowed it.",
    logic: "Defender KQL:\nEmailEvents | where EmailDirection == \"Inbound\" and DeliveryAction == \"Delivered\"\n| extend a = parse_json(AuthenticationDetails) | where tostring(a.DMARC) == \"fail\"",
    match: { all: [
      { field: "properties.EmailDirection", op: "eq", value: "Inbound" },
      { field: "properties.DeliveryAction", op: "eq", value: "Delivered" },
      { field: "properties.AuthenticationDetails", op: "contains", value: "\"DMARC\":\"fail\"" },
    ] },
    falsePositives: ["Mailing-list / forwarding services that break DKIM", "Partners with broken DMARC records"],
  },
];

export const source: NativeSource = { schema, fromTelemetry, useCases };
