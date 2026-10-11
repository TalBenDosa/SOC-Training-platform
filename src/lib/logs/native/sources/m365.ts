/**
 * Microsoft 365 Unified Audit Log — Office 365 Management Activity API.
 * Card: docs/log-schemas/collab-m365.md
 *
 * One log = one audit record exactly as a content blob delivers it: a flat
 * PascalCase object, integers for RecordType / UserType / LogonType /
 * AzureActiveDirectoryEventType, CreationTime "YYYY-MM-DDThh:mm:ss" (UTC, no Z,
 * no ms), {Name,Value} arrays for Parameters / ExtendedProperties /
 * OperationProperties / DeviceProperties.
 *
 * Scope decisions (documented nulls):
 *  - Entra ID sign-in / directory-audit events authored in the Graph / Azure
 *    Monitor shape (azure.signinlogs.*, azure.auditlogs.*) belong to the `entra`
 *    module → null. Entra events authored as UAL records (RT 8 / 15) render here.
 *  - Mail-flow events (MessageDelivered, SpamFiltered, Defender TIMailData RT 28)
 *    are not Unified Audit Log mailbox/admin records — they are email-security
 *    telemetry (defender_o365 / proofpoint) → null.
 *  - Purview DLP (DlpRuleMatch / DLP.All), Copilot (RT 261), Graph-only calls
 *    (MailFolders.List, CalendarEvents.List), endpoint print jobs: the card does
 *    not document these record schemas → null.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { KindSchema, NativeCtx, NativeLog, NativeSource, SourceSchema, UseCase } from "../types";
import {
  aadObjectId, b64ish, bareIp, clientIp, digits, domainOf, entitySeed, isEmail, isGuid, isoNoMs, isPrivateIp,
  localOf, puid, rs, rv, spTenant, userEmail, userSid, type Raw,
} from "./collab-email-shared";
import { aadSessionId } from "./_identity-common";
import { egressIp } from "./firewall-shared";

// ── Schema ───────────────────────────────────────────────────────────────────

const COMMON_REQ = ["Id", "RecordType", "CreationTime", "Operation", "OrganizationId", "UserType", "UserKey", "Workload", "UserId"];
const COMMON_OPT = [
  "Version", "ResultStatus", "ObjectId", "ClientIP", "Scope",
  "AppAccessContext.AADSessionId", "AppAccessContext.APIId", "AppAccessContext.ClientAppId", "AppAccessContext.ClientAppName",
  "AppAccessContext.CorrelationId", "AppAccessContext.UniqueTokenId", "AppAccessContext.IssuedAtTime",
];
const EXO_TOKEN = ["OrganizationName", "OriginatingServer", "TokenObjectId", "TokenTenantId", "AppId", "ClientAppId", "ExternalAccess"];
const MAILBOX = [
  ...EXO_TOKEN, "LogonType", "InternalLogonType", "MailboxGuid", "MailboxOwnerUPN", "MailboxOwnerSid", "MailboxOwnerMasterAccountSid",
  "LogonUserSid", "LogonUserDisplayName", "ClientInfoString", "ClientIPAddress", "ClientProcessName", "ClientVersion",
  "ClientMachineName", "SessionId", "OperationProperties", "OperationProperties[].Name", "OperationProperties[].Value",
];
const ITEM = ["Item.Id", "Item.Subject", "Item.ParentFolder.Id", "Item.ParentFolder.Path", "Item.InternetMessageId", "Item.Attachments", "Item.SizeInBytes", "Item.ImmutableId"];
const SP_BASE = [
  "Site", "ItemType", "EventSource", "SourceName", "UserAgent", "MachineDomainInfo", "MachineId", "ListId", "ListItemUniqueId",
  "WebId", "CorrelationId", "ApplicationId", "ApplicationDisplayName", "IsManagedDevice", "DeviceDisplayName", "GeoLocation",
  "SiteUrl", "SourceRelativeUrl", "SourceFileName", "SourceFileExtension", "DestinationRelativeUrl", "DestinationFileName",
  "DestinationFileExtension", "UserSharedWith", "SharingType", "SensitivityLabelId",
];
const AAD = [
  "AzureActiveDirectoryEventType", "Actor", "Actor[].ID", "Actor[].Type", "Target", "Target[].ID", "Target[].Type",
  "ActorContextId", "TargetContextId", "ActorIpAddress", "InterSystemsId", "IntraSystemId",
  "ExtendedProperties", "ExtendedProperties[].Name", "ExtendedProperties[].Value",
  "ModifiedProperties", "ModifiedProperties[].Name", "ModifiedProperties[].NewValue", "ModifiedProperties[].OldValue", "SupportTicketId",
];
const k = (optional: string[]): KindSchema => ({ required: COMMON_REQ, optional: [...COMMON_OPT, ...optional] });

const schema: SourceSchema = {
  sourceId: "m365",
  category: "collab",
  card: "collab-m365.md",
  product: "Microsoft 365 Unified Audit Log",
  format: "json",
  vendorMatch: ["microsoft 365 unified audit log", "exchange online", "sharepoint online"],
  telemetrySources: ["o365", "sharepoint", "exchange", "dlp", "teams"],
  kinds: {
    ExchangeAdmin: k([
      ...EXO_TOKEN, "ModifiedObjectResolvedName", "Parameters", "Parameters[].Name", "Parameters[].Value",
      "ModifiedProperties", "ModifiedProperties[].Name", "ModifiedProperties[].NewValue", "ModifiedProperties[].OldValue",
      // Card S4 carries SessionId on an OWA cmdlet record (UNVERIFIED) — accepted, never emitted.
      "SessionId",
    ]),
    ExchangeItem: k([...MAILBOX, ...ITEM]),
    ExchangeItemAggregated: k([
      ...MAILBOX, "OperationCount", "Folders", "Folders[].Id", "Folders[].Path",
      "Folders[].FolderItems[].Id", "Folders[].FolderItems[].ImmutableId", "Folders[].FolderItems[].InternetMessageId", "Folders[].FolderItems[].SizeInBytes",
    ]),
    SharePointFileOperation: k(SP_BASE),
    SharePointSharingOperation: k([...SP_BASE, "TargetUserOrGroupName", "TargetUserOrGroupType", "EventData", "UniqueSharingId"]),
    AzureActiveDirectory: k(AAD),
    AzureActiveDirectoryStsLogon: k([...AAD, "ApplicationId", "DeviceProperties", "DeviceProperties[].Name", "DeviceProperties[].Value", "ErrorCode", "LogonError"]),
    // Common schema only — the card documents Workload "MicrosoftTeams" but not the Teams-specific columns.
    MicrosoftTeams: k([]),
  },
};

const RT_KIND: Record<number, string> = {
  1: "ExchangeAdmin", 2: "ExchangeItem", 6: "SharePointFileOperation", 8: "AzureActiveDirectory", 14: "SharePointSharingOperation",
  15: "AzureActiveDirectoryStsLogon", 25: "MicrosoftTeams", 50: "ExchangeItemAggregated",
};

/** Classify a native UAL record (by RecordType). */
export function kindOf(record: Record<string, unknown>): string | null {
  const rt = Number(record.RecordType);
  return RT_KIND[rt] ?? null;
}

// ── Operation resolution ─────────────────────────────────────────────────────

const EXO_ADMIN = new Set(["New-InboxRule", "Set-InboxRule", "Set-Mailbox", "Add-MailboxPermission"]);
const EXO_ITEM = new Set(["Send", "SendAs", "SendOnBehalf", "Create", "Update", "HardDelete", "SoftDelete", "MoveToDeletedItems", "MailboxLogin"]);
const SP_FILE = new Set(["FileAccessed", "FileDownloaded", "FileUploaded", "FileModified", "FileDeleted", "FileSyncDownloadedFull", "FilePreviewed"]);
const SP_SHARE = new Set(["SharingSet", "AnonymousLinkCreated", "AnonymousLinkUsed", "SharingInvitationCreated", "SecureLinkCreated", "AddedToSecureLink"]);
const AAD_STS = new Set(["UserLoggedIn", "UserLoginFailed"]);
const AAD_DIR = new Set([
  "Add member to role.", "Consent to application.", "Add OAuth2PermissionGrant.", "Add service principal.", "Update user.",
  "Reset user password.", "Change user password.", "Add application.", "Invite external user.", "Update conditional access policy.",
]);
const TEAMS = new Set(["MessageSent", "MessageCreatedHasLink", "TeamsSessionStarted"]);

const ACTION_MAP: Record<string, string> = {
  filedownloaded: "FileDownloaded", fileaccessed: "FileAccessed", "bulk-download": "FileDownloaded", mailitemsaccessed: "MailItemsAccessed",
  mailboxlogin: "MailboxLogin", emailsent: "Send", "email-sent": "Send", chatmessagesent: "MessageSent",
  "sharepoint-file-modified": "FileModified", "logged-in": "UserLoggedIn", "logon-failed": "UserLoginFailed",
};

/** M365 Operation name of an event (raw Operation, mapped event.action, or event_type fallback). */
export function resolveOperation(ev: TelemetryEvent): string | undefined {
  const r = ev.raw ?? {};
  let op = rs(r, "Operation");
  if (op) {
    if (op === "SendMail") return "Send";
    if (AAD_DIR.has(`${op}.`)) return `${op}.`;
    return op;
  }
  const act = rs(r, "event.action");
  if (act && ACTION_MAP[act.toLowerCase()]) return ACTION_MAP[act.toLowerCase()];
  if (act) return undefined; // an action we cannot map (DLP_PolicyTriggered, PrintJobSubmitted, MessageReceived …)
  switch (ev.event_type) {
    case "sharepoint_download": op = "FileDownloaded"; break;
    case "sharepoint_access": op = "FileAccessed"; break;
    case "sharepoint_share": op = "SharingInvitationCreated"; break;
    case "email_sent": op = "Send"; break;
    case "teams_message": op = "MessageSent"; break;
    case "auth_success": op = "UserLoggedIn"; break;
    case "auth_failure": op = "UserLoginFailed"; break;
  }
  return op;
}

const ENTRA_VENDOR = /entra|azure ad|azure active directory/i;

// ── Helpers ──────────────────────────────────────────────────────────────────

const USER_TYPE: Record<string, number> = { regular: 0, reserved: 1, admin: 2, dcadmin: 3, system: 4, application: 5, serviceprincipal: 6, guest: 10 };
function userType(raw: Raw, actor: string): number {
  if (isGuid(actor)) return 5;
  const v = rs(raw, "UserType");
  if (v === undefined) return 0;
  if (/^\d+$/.test(v)) return Number(v);
  return USER_TYPE[v.toLowerCase()] ?? 0;
}
const LOGON_TYPE: Record<string, number> = { owner: 0, admin: 1, delegated: 2, transport: 3, systemservice: 4, bestaccess: 5, delegatedadmin: 6 };
function logonType(raw: Raw): number {
  const v = rs(raw, "LogonType");
  if (v === undefined) return 0;
  if (/^\d+$/.test(v)) return Number(v);
  return LOGON_TYPE[v.toLowerCase()] ?? 0;
}
const failed = (raw: Raw, ev: TelemetryEvent) =>
  /^(false|failed|failure)$/i.test(rs(raw, "ResultStatus") ?? "") || ev.event_type === "auth_failure" || ev.event_type === "mfa_denied";
const tf = (v: string) => (/^true$/i.test(v) ? "True" : /^false$/i.test(v) ? "False" : v);

function orgName(ctx: NativeCtx, email?: string) { return `${spTenant(ctx, email)}.onmicrosoft.com`; }
function originatingServer(ctx: NativeCtx, mailbox: string): string {
  const s = entitySeed(ctx, "exosrv", mailbox);
  const pre = ["DB9PR04MB", "AM6PR04MB", "LO2P265MB", "VI1PR08MB", "PA4PR08MB", "CH2PR12MB"][ctx.int(s, 0, 5)];
  return `${pre}${digits(ctx, `${s}:n`, 4)} (15.20.${ctx.int(`${s}:b`, 7400, 8299)}.0${ctx.int(`${s}:r`, 10, 39)})`;
}
function exoDn(ctx: NativeCtx, mailbox: string): string {
  const s = `${ctx.companyId}:exodn`;
  const region = ["EURPR", "NAMPR", "GBRPR"][ctx.int(s, 0, 2)];
  return `${region}${String(ctx.int(`${s}:a`, 1, 9)).padStart(2, "0")}A${String(ctx.int(`${s}:b`, 1, 30)).padStart(3, "0")}.prod.outlook.com/Microsoft Exchange Hosted Organizations/${orgName(ctx, mailbox)}/${localOf(mailbox)}`;
}
function sessionSeed(ctx: NativeCtx, user: string, ip?: string) { return entitySeed(ctx, "session", `${user}|${ip ?? "-"}`); }
function exoClientIp(ctx: NativeCtx, ev: TelemetryEvent, ip?: string): string | undefined {
  if (!ip) return undefined;
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(ip) ? `${ip}:${ctx.int(`${ev.id}:port`, 49152, 65535)}` : ip;
}
function defaultUa(ctx: NativeCtx, user: string): string {
  const v = ctx.int(entitySeed(ctx, "uaver", user), 124, 131);
  return ctx.int(entitySeed(ctx, "uaedge", user), 0, 1)
    ? `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${v}.0.0.0 Safari/537.36 Edg/${v}.0.0.0`
    : `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${v}.0.0.0 Safari/537.36`;
}
function geoResidency(ctx: NativeCtx): string {
  return ["medcore", "globallogis", "quantumbank"].includes(ctx.companyId) ? "EUR" : "NAM";
}

// ── Parameter extraction (every legacy shape → [{Name,Value}]) ──────────────

type NV = { Name: string; Value: string };
function extractParams(raw: Raw): NV[] {
  const out: NV[] = [];
  const add = (n: unknown, v: unknown) => {
    if (n === undefined || n === null || v === undefined || v === null) return;
    let val = typeof v === "string" ? v : JSON.stringify(v);
    if (/^\s*\[.*\]\s*$/.test(val)) { try { const a = JSON.parse(val); if (Array.isArray(a)) val = a.map(String).join(";"); } catch { /* keep */ } }
    out.push({ Name: String(n), Value: val });
  };
  // Indexed: Parameters[0].Name / Parameters[0].Value
  for (let i = 0; i < 20; i++) {
    const n = rv(raw, `Parameters[${i}].Name`);
    if (n === undefined) break;
    add(n, rv(raw, `Parameters[${i}].Value`));
  }
  const whole = rv(raw, "Parameters");
  if (Array.isArray(whole)) for (const p of whole as Array<Record<string, unknown>>) add(p.Name, p.Value);
  else if (typeof whole === "string") {
    const s = whole.trim();
    if (s.startsWith("[")) { try { for (const p of JSON.parse(s) as Array<Record<string, unknown>>) add(p.Name, p.Value); } catch { /* ignore */ } }
    else for (const part of s.split(/;\s*/)) { const m = /^([A-Za-z]+)=(.*)$/.exec(part.trim()); if (m) add(m[1], m[2]); }
  }
  // Single pair: Parameters.Name + Parameters.Value
  const pv = rv(raw, "Parameters.Value");
  if (pv !== undefined) add(rv(raw, "Parameters.Name"), pv);
  else {
    // Dotted map: Parameters.Name (rule name) + Parameters.<Param>
    for (const [key, v] of Object.entries(raw)) {
      const m = /^(?:data\.office365\.)?Parameters\.([A-Za-z]+)$/.exec(key);
      if (m) add(m[1], v);
    }
  }
  // Set-Mailbox authored with ModifiedProperties[i]
  for (let i = 0; i < 20; i++) {
    const n = rv(raw, `ModifiedProperties[${i}].Name`);
    if (n === undefined) break;
    add(n, rv(raw, `ModifiedProperties[${i}].NewValue`));
  }
  // Legacy top-level keys
  const top = (key: string, name = key, skipFalse = false) => {
    const v = rs(raw, key);
    if (v === undefined || (skipFalse && /^false$/i.test(v))) return;
    if (!out.some(p => p.Name === name)) add(name, v);
  };
  top("RuleName", "Name");
  for (const p of ["ForwardTo", "RedirectTo", "ForwardAsAttachmentTo", "MoveToFolder", "ForwardingSmtpAddress", "SubjectContainsWords", "SubjectOrBodyContainsWords"]) top(p);
  for (const p of ["DeleteMessage", "MarkAsRead", "StopProcessingRules"]) top(p, p, true);
  const cond = rs(raw, "Conditions", "RuleCondition");
  if (cond) { const m = /^From:\s*(.+)$/i.exec(cond); if (m && !out.some(p => p.Name === "From")) add("From", m[1]); }
  return out;
}

const INBOX_PARAMS = ["AlwaysDeleteOutlookRulesBlob", "Force", "Identity", "Name", "From", "SubjectContainsWords", "BodyContainsWords",
  "SubjectOrBodyContainsWords", "ForwardTo", "RedirectTo", "ForwardAsAttachmentTo", "MoveToFolder", "DeleteMessage", "MarkAsRead", "StopProcessingRules"];
const MAILBOX_PARAMS = ["Identity", "ForwardingSmtpAddress", "ForwardingAddress", "DeliverToMailboxAndForward"];
const PERM_PARAMS = ["Identity", "User", "AccessRights", "InheritanceType", "AutoMapping"];
function orderParams(ps: NV[], allowed: string[]): NV[] {
  const seen = new Map<string, NV>();
  for (const p of ps) if (allowed.includes(p.Name) && !seen.has(p.Name)) seen.set(p.Name, { Name: p.Name, Value: tf(p.Value) });
  return allowed.filter(n => seen.has(n)).map(n => seen.get(n)!);
}

// ── Converter ────────────────────────────────────────────────────────────────

function fromTelemetry(ev: TelemetryEvent, ctx: NativeCtx): NativeLog | null {
  const raw: Raw = ev.raw ?? {};
  const hasUal = Object.keys(raw).some(k2 => k2.startsWith("data.office365.")) || raw.Operation !== undefined;
  if (ENTRA_VENDOR.test(ev.vendor ?? "") && !hasUal) return null;
  const op = resolveOperation(ev);
  if (!op) return null;

  const user = userEmail(ev);
  const rawUserId = rs(raw, "UserId");
  const actor = (rawUserId && (isEmail(rawUserId) || isGuid(rawUserId))) ? rawUserId : user;
  if (!actor) return null;
  // M365 is SaaS: a user on the office LAN reaches it through the company's NAT egress, so the
  // record carries that public address — the private one only tells us the device is on-site.
  const lanIp = clientIp(ev);
  const ip = lanIp && isPrivateIp(lanIp) ? egressIp(ctx) : lanIp;
  const timeMs = Date.parse(ev.ts);
  const out = (kind: string, record: Record<string, unknown>): NativeLog => ({ sourceId: "m365", kind, format: "json", record, timeMs });
  const keyFor = (rt: number) => {
    if (isGuid(actor)) return actor;
    const p = puid(ctx, actor);
    if (rt === 8 || rt === 15) return `${p}@${domainOf(actor)}`;
    if (rt === 6 || rt === 14) return `i:0h.f|membership|${p.toLowerCase()}@live.com`;
    if (rt === 25) return aadObjectId(ctx, actor);
    return p;
  };
  const head = (rt: number, workload: string, result?: string) => {
    const h: Record<string, unknown> = {
      CreationTime: isoNoMs(ev.ts),
      Id: ctx.uuid(`${ev.id}:ualid`),
      Operation: op,
      OrganizationId: ctx.tenant.azureTenantId,
      RecordType: rt,
    };
    if (result !== undefined) h.ResultStatus = result;
    h.UserKey = keyFor(rt);
    h.UserType = userType(raw, actor);
    h.Version = 1;
    h.Workload = workload;
    return h;
  };
  const isFail = failed(raw, ev);
  const sess = sessionSeed(ctx, user ?? actor, ip);

  // Exchange token context (RT 1 / 2 / 50)
  const exoToken = (mailbox: string) => ({
    AppId: rs(raw, "AppId", "application.id") ?? "00000002-0000-0ff1-ce00-000000000000",
    ClientAppId: "",
    ExternalAccess: false,
    OrganizationName: orgName(ctx, mailbox),
    OriginatingServer: originatingServer(ctx, mailbox),
    TokenObjectId: isEmail(actor) ? aadObjectId(ctx, actor) : actor,
    TokenTenantId: ctx.tenant.azureTenantId,
  });

  // ── ExchangeAdmin (RT 1) ──
  if (EXO_ADMIN.has(op)) {
    const owner = user ?? actor;
    const params = extractParams(raw);
    let ordered: NV[];
    let objectId: string;
    if (op === "New-InboxRule" || op === "Set-InboxRule") {
      const name = params.find(p => p.Name === "Name")?.Value;
      const base = orderParams(params, INBOX_PARAMS).filter(p => !(op === "Set-InboxRule" && p.Name === "Name"));
      ordered = op === "New-InboxRule"
        ? [{ Name: "AlwaysDeleteOutlookRulesBlob", Value: "False" }, { Name: "Force", Value: "False" }, ...base.filter(p => p.Name !== "AlwaysDeleteOutlookRulesBlob" && p.Name !== "Force")]
        : [...(name ? [{ Name: "Identity", Value: `${owner}\\${name}` }] : []), ...base.filter(p => p.Name !== "Identity")];
      objectId = name ? `${owner}\\${name}` : owner;
    } else if (op === "Set-Mailbox") {
      const ps = orderParams(params, MAILBOX_PARAMS).map(p => p.Name === "ForwardingSmtpAddress" && !/^smtp:/i.test(p.Value) ? { ...p, Value: `smtp:${p.Value}` } : p);
      ordered = [{ Name: "Identity", Value: owner }, ...ps.filter(p => p.Name !== "Identity")];
      objectId = exoDn(ctx, owner);
    } else {
      ordered = orderParams(params, PERM_PARAMS);
      const target = ordered.find(p => p.Name === "Identity")?.Value ?? owner;
      objectId = exoDn(ctx, target);
    }
    const rec: Record<string, unknown> = head(1, "Exchange", isFail ? "False" : "True");
    if (ip) rec.ClientIP = exoClientIp(ctx, ev, ip);
    rec.ObjectId = objectId;
    rec.UserId = actor;
    Object.assign(rec, exoToken(owner));
    rec.Parameters = ordered;
    return out("ExchangeAdmin", rec);
  }

  // ── Mailbox records (RT 2 / 50) ──
  const mailboxCommon = (mailbox: string) => {
    const appId = rs(raw, "application.id");
    const ctxObj: Record<string, unknown> = {
      // The Entra session this token belongs to (the sign-in's sessionId) and when it was issued
      // (the sign-in — threadIdentityContext — never before it).
      AADSessionId: rs(raw, "AppAccessContext.AADSessionId") ?? aadSessionId(ctx, user ?? actor, ip, ev.ts),
      IssuedAtTime: rs(raw, "AppAccessContext.IssuedAtTime") ?? isoNoMs(new Date(timeMs - ctx.int(`${ev.id}:iat`, 60, 1800) * 1000).toISOString()),
      UniqueTokenId: b64ish(ctx, `${ev.id}:uti`, 22),
    };
    if (appId) { ctxObj.ClientAppId = appId; const an = rs(raw, "application.name"); if (an) ctxObj.ClientAppName = an; }
    return {
      ...exoToken(mailbox),
      ClientIPAddress: ip,
      ClientInfoString: rs(raw, "ClientInfoString") ?? (appId || /graph|rest/i.test(rs(raw, "authentication.method") ?? "") ? "Client=REST;Client=RESTSystem;;" : "Client=OWA;Action=ViaProxy"),
      InternalLogonType: 0,
      LogonType: logonType(raw),
      LogonUserSid: isEmail(actor) ? userSid(ctx, actor) : undefined,
      MailboxGuid: rs(raw, "MailboxGuid") ?? ctx.uuid(entitySeed(ctx, "mbxguid", mailbox)),
      MailboxOwnerSid: userSid(ctx, mailbox),
      MailboxOwnerUPN: mailbox,
      SessionId: rs(raw, "SessionId") ?? ctx.uuid(`${sess}:exo`),
      AppAccessContext: ctxObj,
    };
  };
  const clean = (o: Record<string, unknown>) => { for (const key of Object.keys(o)) if (o[key] === undefined) delete o[key]; return o; };

  if (op === "MailItemsAccessed") {
    const mailbox = rs(raw, "MailboxOwnerUPN") ?? user ?? actor;
    const access = rs(raw, "OperationProperties.MailAccessType", "MailAccessType", "mail.access_type") === "Sync" ? "Sync" : "Bind";
    const throttled = /^true$/i.test(rs(raw, "OperationProperties.IsThrottled", "IsThrottled") ?? "") ? "True" : "False";
    const folderPaths = (rs(raw, "Folders.Path", "Folders[0].Path") ?? rs(raw, "mail.folder", "mail.folder_accessed") ?? "Inbox")
      .split(/,\s*/).map(p => (p.startsWith("\\") ? p : `\\${p}`));
    const imids: string[] = [];
    for (const key of ["Folders[0].FolderItems[0].InternetMessageId", "AccessedItems[0].InternetMessageId", "Folders[0].FolderItems[1].InternetMessageId"]) {
      const v = rs(raw, key); if (v) imids.push(v);
    }
    const countRaw = Number(rs(raw, "OperationCount") ?? NaN);
    const folders = folderPaths.map((path, fi) => {
      const fid = `LgAAAAD${b64ish(ctx, entitySeed(ctx, "folder", `${mailbox}|${path}`), 50)}AAAB`;
      const f: Record<string, unknown> = { Id: fid, Path: path };
      if (access === "Bind" && fi === 0) {
        const n = Math.max(imids.length, Math.min(isNaN(countRaw) ? 2 : countRaw, 3));
        f.FolderItems = Array.from({ length: n }, (_, i) => {
          const seed = `${ev.id}:fi:${i}`;
          const imm = `LgAAAAB${b64ish(ctx, seed, 30)}AAAJ`;
          const srv = originatingServer(ctx, `ext${i}:${ev.id}`).split(" ")[0];
          return {
            Id: `RgAAAAD${b64ish(ctx, `${seed}:id`, 60)}AAAJ`,
            ImmutableId: imm,
            InternetMessageId: imids[i] ?? `<${srv}${ctx.hex(`${seed}:m`, 20).toUpperCase()}@${srv}.eurprd04.prod.outlook.com>`,
            SizeInBytes: ctx.int(`${seed}:sz`, 4200, 260000),
          };
        });
      }
      return f;
    });
    const items = folders.reduce((n, f) => n + ((f.FolderItems as unknown[] | undefined)?.length ?? 0), 0);
    const rec = head(50, "Exchange", isFail ? "Failed" : "Succeeded");
    rec.UserId = actor;
    Object.assign(rec, clean(mailboxCommon(mailbox)));
    rec.OperationProperties = [{ Name: "MailAccessType", Value: access }, { Name: "IsThrottled", Value: throttled }];
    rec.OperationCount = isNaN(countRaw) ? Math.max(items, 1) : countRaw;
    rec.Folders = folders;
    return out("ExchangeItemAggregated", clean(rec));
  }

  if (EXO_ITEM.has(op)) {
    const mailbox = rs(raw, "MailboxOwnerUPN") ?? user ?? actor;
    const rec = head(2, "Exchange", isFail ? "Failed" : "Succeeded");
    if (ip) rec.ClientIP = ip;
    rec.UserId = actor;
    Object.assign(rec, clean(mailboxCommon(mailbox)));
    if (op !== "MailboxLogin") {
      const subject = rs(raw, "Item.Subject", "email.subject", "Subject");
      const att = rs(raw, "email.attachment.name", "Item.AttachmentFileNames", "email.attachments.file.name");
      const parent = rs(raw, "Item.ParentFolder.Path") ?? (op === "Create" ? "\\Calendar" : op.startsWith("Send") ? "\\Sent Items" : "\\Inbox");
      const seed = `${ev.id}:item`;
      const item: Record<string, unknown> = {
        Id: `RgAAAAD${b64ish(ctx, `${seed}:id`, 60)}AAAJ`,
        ParentFolder: { Id: `LgAAAAD${b64ish(ctx, entitySeed(ctx, "folder", `${mailbox}|${parent}`), 50)}AAAB`, Path: parent },
      };
      if (subject) item.Subject = subject;
      if (op !== "Create") {
        const srv = originatingServer(ctx, mailbox).split(" ")[0];
        item.InternetMessageId = rs(raw, "email.message_id", "InternetMessageId", "Item.InternetMessageId") ??
          `<${srv}${ctx.hex(`${seed}:m`, 20).toUpperCase()}@${srv}.eurprd04.prod.outlook.com>`;
      }
      const size = Number(rs(raw, "Item.SizeInBytes", "email.size_bytes", "MessageSizeBytes", "file.size") ?? NaN);
      if (att) item.Attachments = att.split(/,\s*/).map(a => `${a} (${isNaN(size) ? ctx.int(`${seed}:as:${a}`, 20000, 900000) : size}b)`).join("; ");
      if (!isNaN(size)) item.SizeInBytes = size;
      item.ImmutableId = `LgAAAAB${b64ish(ctx, `${seed}:imm`, 30)}AAAJ`;
      rec.Item = item;
    }
    return out("ExchangeItem", clean(rec));
  }

  // ── SharePoint / OneDrive (RT 6 / 14) ──
  if (SP_FILE.has(op) || SP_SHARE.has(op)) {
    const t = spTenant(ctx, user ?? actor);
    const fileUrl = [rs(raw, "ObjectId"), ev.file?.path].find(u => !!u && /^https?:\/\/.+\.[A-Za-z0-9]{2,5}$/.test(u));
    const fileName = ev.file?.name ?? rs(raw, "SourceFileName", "file.name", "ItemName") ?? (fileUrl ? decodeURI(fileUrl.split("/").pop()!) : undefined);
    let rawRel = rs(raw, "SourceRelativeUrl");
    let siteUrl = rs(raw, "SiteUrl") ?? rs(raw, "cloud.resource.name") ?? (fileUrl ? fileUrl.replace(/^(https?:\/\/[^/]+\/(?:sites|teams|personal)\/[^/]+\/).*$/, "$1") : undefined);
    // Authored relative URLs sometimes start with the site path ("sites/Sales-Operations/Shared Documents/…").
    const relSite = rawRel ? /^\/?((?:sites|teams|personal)\/[^/]+)\/(.+)$/.exec(rawRel) : null;
    if (relSite) { siteUrl = siteUrl ?? `/${relSite[1]}`; rawRel = relSite[2]; }
    let subPath: string | undefined;
    if (siteUrl) {
      if (!/^https?:\/\//.test(siteUrl)) siteUrl = siteUrl.startsWith("/") ? `https://${t}.sharepoint.com${siteUrl}` : `https://${siteUrl}`;
      const m = /^(https?:\/\/[^/]+\/(?:sites|teams|personal)\/[^/]+)(?:\/(.*))?$/.exec(siteUrl.replace(/\/$/, ""));
      if (m) { siteUrl = `${m[1]}/`; subPath = m[2] || undefined; }
      else siteUrl = siteUrl.endsWith("/") ? siteUrl : `${siteUrl}/`;
    } else siteUrl = `https://${t}.sharepoint.com/sites/Shared/`;
    const oneDrive = /-my\.sharepoint\.com|\/personal\//.test(siteUrl);
    const rel = rawRel ?? (subPath ? (/^(Shared Documents|Documents)/.test(subPath) ? subPath : `${oneDrive ? "Documents" : "Shared Documents"}/${subPath}`) : oneDrive ? "Documents" : "Shared Documents");
    const objectId = fileUrl ?? (fileName ? `${siteUrl}${rel}/${fileName}` : `${siteUrl}${rel}`);
    const share = SP_SHARE.has(op);
    let shareOp = op;
    if (share && op === "SharingInvitationCreated" && /^true$/i.test(rs(raw, "EventData.IsGuestLink") ?? "")) shareOp = "AnonymousLinkCreated";
    const rt = share ? 14 : 6;
    const rec: Record<string, unknown> = head(rt, oneDrive ? "OneDrive" : "SharePoint");
    rec.Operation = shareOp;
    delete rec.ResultStatus;
    if (ip) rec.ClientIP = ip;
    rec.ObjectId = objectId;
    rec.UserId = actor;
    const siteSeed = entitySeed(ctx, "spsite", siteUrl);
    rec.CorrelationId = rs(raw, "CorrelationId") ?? ctx.uuid(`${ev.id}:corr`);
    rec.EventSource = "SharePoint";
    rec.ItemType = fileName ? "File" : "Folder";
    rec.ListId = rs(raw, "ListId") ?? ctx.uuid(`${siteSeed}:list`);
    rec.ListItemUniqueId = rs(raw, "ListItemUniqueId") ?? ctx.uuid(`${siteSeed}:item:${fileName ?? rel}`);
    rec.Site = rs(raw, "Site") ?? ctx.uuid(`${siteSeed}:site`);
    rec.UserAgent = rs(raw, "UserAgent") ?? ev.network?.user_agent ??
      (op === "FileSyncDownloadedFull" ? "Microsoft SkyDriveSync 23.146.0715.0001 ship; Windows NT 10.0 (19045)" : defaultUa(ctx, user ?? actor));
    rec.WebId = rs(raw, "WebId") ?? ctx.uuid(`${siteSeed}:web`);
    rec.GeoLocation = geoResidency(ctx);
    const managed = rs(raw, "IsManagedDevice");
    rec.IsManagedDevice = managed !== undefined ? /^true$/i.test(managed) : isPrivateIp(lanIp);
    if (ev.hostname && !ev.hostname.includes(".")) rec.DeviceDisplayName = ev.hostname;
    const appId = rs(raw, "application.id");
    if (appId) { rec.ApplicationId = appId; const an = rs(raw, "application.name"); if (an) rec.ApplicationDisplayName = an; }
    if (share) {
      const target = rs(raw, "TargetUserOrGroupName");
      if (target) rec.TargetUserOrGroupName = target;
      const ttype = rs(raw, "TargetUserOrGroupType");
      if (ttype) rec.TargetUserOrGroupType = ttype;
      rec.EventData = `<Type>${/edit/i.test(rs(raw, "EventData.PermissionLevel") ?? "") ? "Edit" : "View"}</Type>`;
      if (shareOp !== "SharingInvitationCreated") rec.UniqueSharingId = ctx.uuid(`${ev.id}:share`);
    }
    if (fileName) {
      if (fileName.includes(".")) rec.SourceFileExtension = fileName.split(".").pop()!.toLowerCase();
      rec.SourceFileName = fileName;
    }
    rec.SiteUrl = siteUrl;
    rec.SourceRelativeUrl = rel;
    return out(share ? "SharePointSharingOperation" : "SharePointFileOperation", rec);
  }

  // ── Azure AD STS logon (RT 15) ──
  if (AAD_STS.has(op)) {
    if (!isEmail(actor)) return null;
    const fail = op === "UserLoginFailed";
    const oid = aadObjectId(ctx, actor);
    const ua = rs(raw, "UserAgent") ?? ev.network?.user_agent ?? defaultUa(ctx, actor);
    const errNo = rs(raw, "ErrorNumber");
    const ext: NV[] = [{ Name: "ResultStatusDetail", Value: fail ? "Success" : "Redirect" }, { Name: "UserAgent", Value: ua }];
    if (!fail) ext.push({ Name: "UserAuthenticationMethod", Value: "1" });
    ext.push({ Name: "RequestType", Value: fail ? "Login:login" : "OAuth2:Authorize" });
    if (!fail) ext.push({ Name: "KeepMeSignedIn", Value: "True" });
    const rec: Record<string, unknown> = head(15, "AzureActiveDirectory", fail ? "Failed" : "Succeeded");
    if (ip) rec.ClientIP = ip;
    rec.ObjectId = "00000002-0000-0ff1-ce00-000000000000";
    rec.UserId = actor;
    rec.AzureActiveDirectoryEventType = 1;
    rec.ExtendedProperties = ext;
    rec.ModifiedProperties = [];
    rec.Actor = [{ ID: oid, Type: 0 }, { ID: actor, Type: 5 }, ...(fail ? [] : [{ ID: puid(ctx, actor), Type: 3 }])];
    rec.ActorContextId = ctx.tenant.azureTenantId;
    if (ip) rec.ActorIpAddress = ip;
    rec.InterSystemsId = ctx.uuid(`${ev.id}:isid`);
    rec.IntraSystemId = ctx.uuid(`${ev.id}:intra`);
    rec.SupportTicketId = "";
    rec.Target = [{ ID: "00000002-0000-0ff1-ce00-000000000000", Type: 0 }];
    rec.TargetContextId = ctx.tenant.azureTenantId;
    rec.ApplicationId = rs(raw, "ApplicationId") ?? "4765445b-32c6-49b0-83e6-1d93765276ca";
    if (!fail) {
      const managed = isPrivateIp(lanIp);
      rec.DeviceProperties = [
        { Name: "OS", Value: "Windows10" },
        { Name: "BrowserType", Value: /Edg\//.test(ua) ? "Edge" : "Chrome" },
        { Name: "IsCompliant", Value: managed ? "True" : "False" },
        { Name: "IsCompliantAndManaged", Value: managed ? "True" : "False" },
        { Name: "SessionId", Value: rs(raw, "azure.signinlogs.properties.sessionId", "AppAccessContext.AADSessionId") ?? aadSessionId(ctx, actor, ip, ev.ts) },
      ];
    } else {
      const err: Record<string, string> = { "50126": "InvalidUserNameOrPassword", "50053": "IdsLocked", "50074": "UserStrongAuthClientAuthNRequiredInterrupt", "50076": "UserStrongAuthClientAuthNRequiredInterrupt" };
      rec.LogonError = ev.event_type === "mfa_denied" ? "UserStrongAuthClientAuthNRequiredInterrupt" : err[errNo ?? ""] ?? "InvalidUserNameOrPassword";
    }
    return out("AzureActiveDirectoryStsLogon", rec);
  }

  // ── Azure AD directory audit (RT 8) ──
  if (AAD_DIR.has(op)) {
    if (!isEmail(actor)) return null;
    const oid = aadObjectId(ctx, actor);
    const target = rs(raw, "ObjectId", "target.user.email", "azure.auditlogs.target_user.upn") ?? (user && user !== actor ? user : undefined);
    const appId = rs(raw, "application.id", "oauth.app.id", "AppId") ?? (isGuid(rs(raw, "Target[0].ID")) ? rs(raw, "Target[0].ID") : undefined);
    const extVal = (name: string) => { for (let i = 0; i < 10; i++) if (rs(raw, `ExtendedProperties[${i}].Name`) === name) return rs(raw, `ExtendedProperties[${i}].Value`); return undefined; };
    const appName = rs(raw, "application.name", "oauth.app.name") ?? extVal("AppDisplayName") ?? (appId ? undefined : rs(raw, "Target[0].ID"));
    const category = /role/i.test(op) ? "RoleManagement" : /application|consent|oauth|service principal/i.test(op) ? "ApplicationManagement" : /policy/i.test(op) ? "Policy" : "UserManagement";
    const corr = ctx.uuid(`${ev.id}:corr`);
    let objectId = target ?? actor;
    let targetName = target ?? actor;
    const mods: Array<{ Name: string; NewValue: string; OldValue: string }> = [];
    const targets: Array<{ ID: string; Type: number }> = [];
    if (op === "Consent to application." && appId) {
      const scopes = (rs(raw, "oauth.consent.scopes_granted", "iam.permission") ?? extVal("Permissions") ?? "").split(/[|,\s]+/).filter(Boolean);
      const admin = /^true$/i.test(rs(raw, "oauth.consent.is_admin_consent") ?? "") || extVal("ConsentType") === "AllPrincipals";
      const allP = /^true$/i.test(rs(raw, "oauth.consent.tenant_wide") ?? "") || extVal("ConsentType") === "AllPrincipals";
      const resource = ctx.uuid(`${ctx.companyId}:graph-sp`);
      mods.push(
        { Name: "ConsentContext.IsAdminConsent", NewValue: admin ? "True" : "False", OldValue: "" },
        { Name: "ConsentContext.IsAppOnly", NewValue: "False", OldValue: "" },
        { Name: "ConsentContext.OnBehalfOfAll", NewValue: allP ? "True" : "False", OldValue: "" },
        { Name: "ConsentContext.Tags", NewValue: "WindowsAzureActiveDirectoryIntegratedApp", OldValue: "" },
      );
      if (scopes.length) mods.push({
        Name: "ConsentAction.Permissions",
        NewValue: `[] => [[Id: ${b64ish(ctx, `${ev.id}:grant`, 32)}, ClientId: ${appId}, PrincipalId: ${allP ? "" : oid}, ResourceId: ${resource}, ConsentType: ${allP ? "AllPrincipals" : "Principal"}, Scope:  ${scopes.join(" ")}, CreatedDateTime: , LastModifiedDateTime ]]; `,
        OldValue: "",
      });
      const redirect = rs(raw, "oauth.app.redirect_uris") ?? extVal("ReplyUrls");
      mods.push({ Name: "TargetId.ServicePrincipalNames", NewValue: redirect ? `${appId};${redirect}` : appId, OldValue: "" });
      objectId = `ServicePrincipal_${appId}`;
      targetName = appName ?? appId;
      targets.push({ ID: `ServicePrincipal_${appId}`, Type: 2 }, { ID: appId, Type: 2 }, { ID: "ServicePrincipal", Type: 2 });
      if (appName) targets.push({ ID: appName, Type: 1 });
      targets.push({ ID: appId, Type: 4 });
    } else if (op === "Add application." && appId) {
      objectId = `Application_${appId}`;
      targetName = appName ?? appId;
      targets.push({ ID: `Application_${appId}`, Type: 2 }, { ID: appId, Type: 2 }, { ID: "Application", Type: 2 });
      if (appName) targets.push({ ID: appName, Type: 1 });
    } else if (op === "Add member to role.") {
      const role = rs(raw, "azure.role.name", "Role.DisplayName", "role.name") ?? "Global Administrator";
      const tmpl = ROLE_TEMPLATES[role];
      mods.push({ Name: "Role.ObjectID", NewValue: ctx.uuid(`${ctx.companyId}:role:${role}`), OldValue: "" }, { Name: "Role.DisplayName", NewValue: role, OldValue: "" });
      if (tmpl) mods.push({ Name: "Role.TemplateId", NewValue: tmpl, OldValue: "" });
      if (role === "Global Administrator") mods.push({ Name: "Role.WellKnownObjectName", NewValue: "TenantAdmins", OldValue: "" });
    } else {
      for (let i = 0; i < 10; i++) {
        const n = rs(raw, `ModifiedProperties[${i}].Name`);
        if (!n) break;
        mods.push({ Name: n, NewValue: rs(raw, `ModifiedProperties[${i}].NewValue`) ?? "", OldValue: rs(raw, `ModifiedProperties[${i}].OldValue`) ?? "" });
      }
      if (op === "Update conditional access policy." && rs(raw, "Target[0].ID")) { objectId = rs(raw, "Target[0].ID")!; targetName = objectId; }
    }
    if (!targets.length) {
      if (isEmail(objectId)) {
        const toid = aadObjectId(ctx, objectId);
        targets.push({ ID: `User_${toid}`, Type: 2 }, { ID: toid, Type: 2 }, { ID: "User", Type: 2 }, { ID: objectId, Type: 5 }, { ID: puid(ctx, objectId), Type: 3 });
      } else targets.push({ ID: objectId, Type: 1 });
    }
    const fail = /^(failure|failed|false)$/i.test(rs(raw, "ResultStatus") ?? "");
    const rec: Record<string, unknown> = head(8, "AzureActiveDirectory", fail ? "Failure" : "Success");
    if (ip) rec.ClientIP = ip;
    rec.ObjectId = objectId;
    rec.UserId = actor;
    rec.AzureActiveDirectoryEventType = 1;
    rec.ExtendedProperties = [
      { Name: "additionalDetails", Value: ev.network?.user_agent ? JSON.stringify({ "User-Agent": ev.network.user_agent }) : "{}" },
      { Name: "extendedAuditEventCategory", Value: /consent|service principal/i.test(op) ? "ServicePrincipal" : /application/i.test(op) ? "Application" : /policy/i.test(op) ? "Policy" : "User" },
      { Name: "resultType", Value: fail ? "Failure" : "Success" },
      { Name: "auditEventCategory", Value: category },
      { Name: "actorUPN", Value: actor },
      { Name: "targetName", Value: targetName },
      { Name: "correlationId", Value: corr },
    ];
    rec.ModifiedProperties = mods;
    rec.Actor = [{ ID: actor, Type: 5 }, { ID: puid(ctx, actor), Type: 3 }, { ID: `User_${oid}`, Type: 2 }, { ID: oid, Type: 2 }, { ID: "User", Type: 2 }];
    rec.ActorContextId = ctx.tenant.azureTenantId;
    if (ip) rec.ActorIpAddress = ip;
    rec.InterSystemsId = corr;
    rec.IntraSystemId = ctx.uuid(`${ev.id}:intra`);
    rec.SupportTicketId = "";
    rec.Target = targets;
    rec.TargetContextId = ctx.tenant.azureTenantId;
    return out("AzureActiveDirectory", rec);
  }

  // ── Microsoft Teams (RT 25, common schema only) ──
  if (TEAMS.has(op)) {
    if (!isEmail(actor)) return null;
    const rec: Record<string, unknown> = head(25, "MicrosoftTeams", "Succeeded");
    if (ip) rec.ClientIP = ip;
    rec.UserId = actor;
    return out("MicrosoftTeams", rec);
  }

  return null;
}

/** Public role template ids (identical in every tenant). */
const ROLE_TEMPLATES: Record<string, string> = {
  "Global Administrator": "62e90394-69f5-4237-9190-012177145e10",
  "Exchange Administrator": "29232cdf-9323-42fd-ade2-1d097af3e4de",
  "Privileged Role Administrator": "e8611ab8-c189-46e8-94e1-60213ab1f814",
  "Security Administrator": "194ae4cb-b126-40b2-bd5b-6091b380977d",
  "SharePoint Administrator": "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",
  "User Administrator": "fe930be7-5e62-47db-91af-98c3a49a38b1",
  "Helpdesk Administrator": "729827e3-9c14-49f7-bb1b-9608f156bbb8",
  "Application Administrator": "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
  "Cloud Application Administrator": "158c047a-c907-4556-b7ef-446551a6b5f7",
  "Authentication Administrator": "c4e39bd9-1100-46d3-8c65-fb160da0071f",
};

// ── Use cases ────────────────────────────────────────────────────────────────

const RFC1918 = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"];
const FORWARD_PARAMS = ["ForwardTo", "RedirectTo", "ForwardAsAttachmentTo"];
const CONSUMER_MAIL = "@(gmail\\.com|googlemail\\.com|outlook\\.com|hotmail\\.com|live\\.com|yahoo\\.|proton\\.me|protonmail\\.com|tutanota\\.com|tuta\\.io|gmx\\.|mail\\.ru|yandex\\.|icloud\\.com|aol\\.com|zoho\\.com)";
const FIRST_PARTY_APPS = [
  "00000002-0000-0ff1-ce00-000000000000", // Office 365 Exchange Online
  "00000003-0000-0ff1-ce00-000000000000", // SharePoint Online
  "d3590ed6-52b3-4102-aeff-aad2292ab01c", // Microsoft Office
  "27922004-5251-4030-b22d-91ecd9a37ea4", // Outlook Mobile
  "5d661950-3475-41cd-a2c3-d671a3162bc1", // Outlook (new)
];

const useCases: UseCase[] = [
  {
    id: "m365.inbox-rule-forward-and-hide",
    title: "Inbox rule forwards mail and hides it from the owner (BEC)",
    sourceId: "m365", kinds: ["ExchangeAdmin"], severity: "critical", mitre: ["T1114.003", "T1564.008"],
    description: "A New-InboxRule / Set-InboxRule that both forwards (ForwardTo / RedirectTo / ForwardAsAttachmentTo) and hides the evidence (DeleteMessage, MoveToFolder, MarkAsRead) is the classic business-email-compromise persistence: the attacker keeps receiving the finance thread while the victim never sees the replies. Check the ClientIP, the rule Name (\".\", \"..\" are tells) and the session that created it.",
    logic: "Sentinel KQL:\nOfficeActivity | where Operation in (\"New-InboxRule\",\"Set-InboxRule\")\n| mv-expand p = todynamic(Parameters) | summarize names = make_set(tostring(p.Name)) by Id, UserId, ClientIP, TimeGenerated\n| where names has_any (\"ForwardTo\",\"RedirectTo\",\"ForwardAsAttachmentTo\") and names has_any (\"DeleteMessage\",\"MoveToFolder\",\"MarkAsRead\")",
    match: { all: [
      { field: "Operation", op: "in", value: ["New-InboxRule", "Set-InboxRule"] },
      { field: "Parameters[].Name", op: "in", value: FORWARD_PARAMS },
      { field: "Parameters[].Name", op: "in", value: ["DeleteMessage", "MoveToFolder", "MarkAsRead"] },
    ] },
    falsePositives: ["Users who auto-file and forward newsletters to a personal archive", "Shared-mailbox triage rules created by IT (check the change ticket)"],
  },
  {
    id: "m365.inbox-rule-external-forward",
    title: "Inbox rule forwards to a consumer / anonymous mail provider",
    sourceId: "m365", kinds: ["ExchangeAdmin"], severity: "high", mitre: ["T1114.003"],
    description: "Inbox rules that forward to a personal or anonymous provider (gmail, outlook.com, proton.me, tutanota …) move company mail outside every control. In production replace the provider list with \"recipient domain not in accepted domains\".",
    logic: "Sentinel KQL:\nOfficeActivity | where Operation in (\"New-InboxRule\",\"Set-InboxRule\")\n| mv-expand p = todynamic(Parameters) | where tostring(p.Name) in (\"ForwardTo\",\"RedirectTo\",\"ForwardAsAttachmentTo\")\n| where tostring(p.Value) matches regex @\"@(gmail\\.com|outlook\\.com|proton\\.me|protonmail\\.com|tutanota\\.com|…)\"",
    match: { all: [
      { field: "Operation", op: "in", value: ["New-InboxRule", "Set-InboxRule"] },
      { field: "Parameters[].Name", op: "in", value: FORWARD_PARAMS },
      { field: "Parameters[].Value", op: "regex", value: CONSUMER_MAIL },
    ] },
    falsePositives: ["Approved leave-coverage forwarding with an HR / IT ticket", "Employees forwarding on-call alerts to a personal phone mailbox"],
  },
  {
    id: "m365.inbox-rule-obscure-name",
    title: "Inbox rule with a punctuation-only name",
    sourceId: "m365", kinds: ["ExchangeAdmin"], severity: "medium", mitre: ["T1564.008"],
    description: "Attackers name rules \".\", \"..\", \",\" or similar so they are invisible in the Outlook rules list. A rule Name made only of punctuation / whitespace is a strong BEC tell on its own.",
    logic: "Sentinel KQL:\nOfficeActivity | where Operation in (\"New-InboxRule\",\"Set-InboxRule\")\n| mv-expand p = todynamic(Parameters) | where tostring(p.Name) == \"Name\" and tostring(p.Value) matches regex @\"^[\\p{P}\\s]{1,3}$\"",
    match: { all: [
      { field: "Operation", op: "in", value: ["New-InboxRule", "Set-InboxRule"] },
      { field: "Parameters[].Value", op: "regex", value: "^[.,;:'\"\\s\\u2024\\u2025\\u2026_-]{1,3}$" },
    ] },
    falsePositives: ["Rarely legitimate — confirm with the mailbox owner"],
  },
  {
    id: "m365.mailbox-smtp-forwarding",
    title: "Mailbox-level SMTP forwarding enabled (Set-Mailbox -ForwardingSmtpAddress)",
    sourceId: "m365", kinds: ["ExchangeAdmin"], severity: "high", mitre: ["T1114.003"],
    description: "Set-Mailbox with ForwardingSmtpAddress forwards EVERY message the mailbox receives to that address — no rule shows in Outlook. Validate the destination domain and who ran the cmdlet from which ClientIP.",
    logic: "Sentinel KQL:\nOfficeActivity | where Operation == \"Set-Mailbox\"\n| where Parameters has \"ForwardingSmtpAddress\" | extend Dest = extract(@\"smtp:([^\\\"]+)\", 1, Parameters)",
    match: { all: [{ field: "Operation", op: "eq", value: "Set-Mailbox" }, { field: "Parameters[].Name", op: "eq", value: "ForwardingSmtpAddress" }] },
    falsePositives: ["Approved leave / sabbatical forwarding (check HR ticket)", "Migration projects forwarding to a new tenant"],
  },
  {
    id: "m365.mailbox-fullaccess-granted",
    title: "FullAccess granted on another user's mailbox",
    sourceId: "m365", kinds: ["ExchangeAdmin"], severity: "high", mitre: ["T1098.002"],
    description: "Add-MailboxPermission -AccessRights FullAccess lets the grantee (User) read the target mailbox (Identity) indefinitely, surviving password resets of the victim. Watch especially for grants on executive / finance mailboxes and for AutoMapping False (hides the mailbox from the grantee's Outlook).",
    logic: "Sentinel KQL:\nOfficeActivity | where Operation == \"Add-MailboxPermission\" | where Parameters has \"FullAccess\"\n| project TimeGenerated, UserId, ClientIP, Parameters",
    match: { all: [{ field: "Operation", op: "eq", value: "Add-MailboxPermission" }, { field: "Parameters[].Value", op: "eq", value: "FullAccess" }] },
    falsePositives: ["Executive assistants given delegate access through a change request", "Litigation / HR investigations run by Exchange admins"],
  },
  {
    id: "m365.mailitemsaccessed-external-sync",
    title: "Whole-folder mail Sync from an external IP",
    sourceId: "m365", kinds: ["ExchangeItemAggregated"], severity: "high", mitre: ["T1114.002"],
    description: "MailItemsAccessed with MailAccessType=Sync means a client downloaded entire folders. From a non-corporate IP — especially right after a risky sign-in — it is mailbox exfiltration. Pivot on SessionId / AppAccessContext.AADSessionId to the sign-in that issued the token.",
    logic: "Sentinel KQL:\nOfficeActivity | where Operation == \"MailItemsAccessed\"\n| where OperationProperties has '\"MailAccessType\",\"Value\":\"Sync\"' and not(ipv4_is_private(ClientIPAddress))",
    match: { all: [
      { field: "Operation", op: "eq", value: "MailItemsAccessed" },
      { field: "OperationProperties[].Value", op: "eq", value: "Sync" },
      { field: "ClientIPAddress", op: "notCidr", value: RFC1918 },
    ] },
    falsePositives: ["A user setting up Outlook on a new home PC (expect one Sync per folder, then Binds)", "Approved mail-archiving services"],
  },
  {
    id: "m365.mailitemsaccessed-new-ip-app",
    title: "Mail read by a third-party app or from an external IP",
    sourceId: "m365", kinds: ["ExchangeItemAggregated"], severity: "medium", mitre: ["T1114.002", "T1528"],
    description: "MailItemsAccessed where the reading client is not a first-party Microsoft app (AppId / AppAccessContext.ClientAppId) or the ClientIPAddress is outside the corporate ranges. Baseline per user: a new IP or a new app reading mail minutes after a consent grant or a token-replay sign-in is the signal.",
    logic: "Sentinel KQL:\nlet known = OfficeActivity | where TimeGenerated between (ago(30d)..ago(1d)) and Operation==\"MailItemsAccessed\" | distinct UserId, ClientIPAddress, AppId;\nOfficeActivity | where TimeGenerated > ago(1d) and Operation==\"MailItemsAccessed\"\n| join kind=leftanti known on UserId, ClientIPAddress, AppId",
    match: { all: [
      { field: "Operation", op: "eq", value: "MailItemsAccessed" },
      { any: [
        { field: "AppId", op: "nin", value: FIRST_PARTY_APPS },
        { field: "AppAccessContext.ClientAppId", op: "exists" },
        { field: "ClientIPAddress", op: "notCidr", value: RFC1918 },
      ] },
    ] },
    falsePositives: ["Users travelling or on home broadband", "Sanctioned CRM / archiving apps (allow-list their AppId)"],
  },
  {
    id: "m365.sharepoint-mass-download",
    title: "Mass file download from SharePoint / OneDrive",
    sourceId: "m365", kinds: ["SharePointFileOperation"], severity: "high", mitre: ["T1530", "T1213.002"],
    description: "One account downloading 50+ distinct files within 10 minutes. Compare with the user's baseline, check UserAgent (browser vs sync client vs scripts) and IsManagedDevice; a departing employee or a stolen session typically shows here.",
    logic: "Sentinel KQL:\nOfficeActivity | where Operation in (\"FileDownloaded\",\"FileSyncDownloadedFull\")\n| summarize files = dcount(OfficeObjectId) by UserId, ClientIP, bin(TimeGenerated, 10m) | where files >= 50",
    match: { field: "Operation", op: "in", value: ["FileDownloaded", "FileSyncDownloadedFull"] },
    threshold: { groupBy: ["UserId"], count: 50, windowSec: 600, distinct: "ObjectId" },
    falsePositives: ["OneDrive sync client first-time sync on a new laptop", "Approved data migrations / eDiscovery exports"],
  },
  {
    id: "m365.anonymous-link-created",
    title: "Anonymous (\"Anyone\") sharing link created",
    sourceId: "m365", kinds: ["SharePointSharingOperation"], severity: "medium", mitre: ["T1567", "T1537"],
    description: "AnonymousLinkCreated means anyone holding the URL can open the file without signing in. On sensitive libraries (Finance, HR, exports) it is a common exfiltration step; check EventData (View/Edit) and whether AnonymousLinkUsed follows from foreign IPs.",
    logic: "Sentinel KQL:\nOfficeActivity | where Operation == \"AnonymousLinkCreated\" | project TimeGenerated, UserId, ClientIP, OfficeObjectId, EventData",
    match: { field: "Operation", op: "eq", value: "AnonymousLinkCreated" },
    falsePositives: ["Marketing teams publishing public collateral", "Tenants where Anyone links are an accepted practice"],
  },
  {
    id: "m365.oauth-consent-mail-file-scopes",
    title: "User consented an OAuth app to mail / file scopes",
    sourceId: "m365", kinds: ["AzureActiveDirectory"], severity: "high", mitre: ["T1528", "T1550.001"],
    description: "\"Consent to application.\" whose ConsentAction.Permissions include Mail.Read/ReadWrite/Send, Files.ReadWrite.All or full_access_as_app gives an app a token to the user's mail and files that survives password resets. Look at the app name (look-alike of a known brand?), IsAdminConsent / OnBehalfOfAll and MailItemsAccessed by that AppId afterwards.",
    logic: "Sentinel KQL:\nOfficeActivity | where Operation == \"Consent to application.\"\n| mv-expand m = todynamic(ModifiedProperties) | where tostring(m.Name) == \"ConsentAction.Permissions\"\n| where tostring(m.NewValue) has_any (\"Mail.Read\",\"Mail.ReadWrite\",\"Mail.Send\",\"Files.ReadWrite.All\",\"full_access_as_app\")",
    match: { all: [
      { field: "Operation", op: "eq", value: "Consent to application." },
      { field: "ModifiedProperties[].NewValue", op: "regex", value: "Mail\\.(Read|ReadWrite|Send)|Files\\.ReadWrite\\.All|full_access_as_app|MailboxSettings\\.ReadWrite" },
    ] },
    falsePositives: ["Approved productivity add-ins (allow-list by ClientId)", "Admin-reviewed consent workflow approvals"],
  },
  {
    id: "m365.privileged-role-granted",
    title: "Privileged directory role granted",
    sourceId: "m365", kinds: ["AzureActiveDirectory"], severity: "high", mitre: ["T1098.003"],
    description: "\"Add member to role.\" for Global / Privileged Role / Exchange / Security / SharePoint Administrator. Confirm a change ticket or PIM activation; grants to service accounts or from an unusual ClientIP are escalation / persistence.",
    logic: "Sentinel KQL:\nOfficeActivity | where Operation == \"Add member to role.\"\n| mv-expand m = todynamic(ModifiedProperties) | where tostring(m.Name) == \"Role.DisplayName\"\n| where tostring(m.NewValue) has_any (\"Global Administrator\",\"Privileged Role Administrator\",\"Exchange Administrator\",\"Security Administrator\",\"SharePoint Administrator\")",
    match: { all: [
      { field: "Operation", op: "eq", value: "Add member to role." },
      { field: "ModifiedProperties[].NewValue", op: "regex", value: "Global Administrator|Privileged Role Administrator|Exchange Administrator|Security Administrator|SharePoint Administrator|Application Administrator" },
    ] },
    falsePositives: ["Planned admin onboarding with a ticket", "PIM-managed activations recorded as role adds"],
  },
  {
    id: "m365.login-failure-spray",
    title: "Password spray: many accounts failing from one IP",
    sourceId: "m365", kinds: ["AzureActiveDirectoryStsLogon"], severity: "high", mitre: ["T1110.003"],
    description: "UserLoginFailed (LogonError InvalidUserNameOrPassword) for 5+ distinct accounts from the same ClientIP within 10 minutes is a password spray; follow up with UserLoggedIn from that IP.",
    logic: "Sentinel KQL:\nOfficeActivity | where Operation == \"UserLoginFailed\"\n| summarize users = dcount(UserId) by ClientIP, bin(TimeGenerated, 10m) | where users >= 5",
    match: { field: "Operation", op: "eq", value: "UserLoginFailed" },
    threshold: { groupBy: ["ClientIP"], count: 5, windowSec: 600, distinct: "UserId" },
    falsePositives: ["A mis-configured shared kiosk or legacy app using stale credentials", "NAT egress of a large office during a password-change campaign"],
  },
];

export const source: NativeSource = { schema, fromTelemetry, useCases };
