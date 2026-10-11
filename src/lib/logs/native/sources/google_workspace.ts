/**
 * Google Workspace — Admin SDK Reports API `activities` (admin#reports#activity).
 * Card: docs/log-schemas/collab-google-workspace.md
 *
 * One log = one Activity resource: nested id{}, actor{}, events[] with
 * parameters[] carrying exactly ONE typed value key (value | intValue as a
 * string | boolValue | multiValue | messageValue | multiMessageValue);
 * id.time RFC 3339 with ms; uniqueQualifier a signed int64 string.
 *
 * Category-wide rendering: M365 / Entra-authored events are rendered as their
 * Google equivalent ONLY where the card's equivalence table says a true (or
 * near-true) equivalent exists:
 *   UserLoggedIn/UserLoginFailed → login_success/login_failure,
 *   FileDownloaded/FileAccessed → drive download/view,
 *   AnonymousLinkCreated → change_document_visibility, Sharing* → change_user_access,
 *   Consent to application. (per-user) → token authorize,
 *   Add member to role. → GRANT_ADMIN_PRIVILEGE / ASSIGN_ROLE,
 *   Set-Mailbox -ForwardingSmtpAddress (out of domain) → email_forwarding_out_of_domain,
 *   password reset/change → CHANGE_PASSWORD / password_edit.
 * Returns null (no Google equivalent — never faked): New-InboxRule / Set-InboxRule /
 * UpdateInboxRules (Gmail user filters have no Reports API event — this also
 * covers the platform's authored "CREATE_GMAIL_FILTER"), Add-MailboxPermission
 * (Gmail delegation has no documented event), MailItemsAccessed / MailboxLogin
 * (no session / Bind-Sync equivalent), admin tenant-wide consent, Teams, Copilot,
 * DLP, calendar (app not in the card), mail-log *search results* (not audit records).
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { KindSchema, NativeCtx, NativeLog, NativeSource, SourceSchema, UseCase } from "../types";
import {
  b64ish, clientIp, digits, domainOf, emailFacts, entitySeed, int64Str, isEmail, isGuid, isoMs, isPrivateIp, rs, userEmail, type Raw,
} from "./collab-email-shared";
import { resolveOperation } from "./m365";
import { egressIp } from "./firewall-shared";

// ── Schema ───────────────────────────────────────────────────────────────────

const REQ = ["kind", "id.time", "id.uniqueQualifier", "id.applicationName", "id.customerId", "etag", "events[].type", "events[].name"];
const OPT = [
  "actor.email", "actor.profileId", "actor.callerType", "actor.key",
  "actor.applicationInfo.oauthClientId", "actor.applicationInfo.applicationName", "actor.applicationInfo.impersonation",
  "ownerDomain", "ipAddress", "networkInfo.ipAsn", "networkInfo.ipAsn[]", "networkInfo.regionCode", "networkInfo.subdivisionCode",
  "events[].parameters[].name", "events[].parameters[].value", "events[].parameters[].intValue", "events[].parameters[].boolValue",
  "events[].parameters[].multiValue", "events[].parameters[].multiValue[]", "events[].parameters[].multiIntValue[]",
  "resourceDetails[].id", "resourceDetails[].title", "resourceDetails[].type", "resourceDetails[].relation",
  "resourceDetails[].appliedLabels", "resourceDetails[].ownerDetails",
];
// messageValue / multiMessageValue are recursive typed-parameter containers.
const kindSchema: KindSchema = { required: REQ, optional: OPT, openPrefixes: ["events[].parameters[].messageValue", "events[].parameters[].multiMessageValue"] };
const APPS = ["login", "user_accounts", "drive", "token", "admin", "gmail", "gemini_in_workspace_apps"] as const;

const schema: SourceSchema = {
  sourceId: "google_workspace",
  category: "collab",
  card: "collab-google-workspace.md",
  product: "Google Workspace (Admin SDK Reports API)",
  format: "json",
  vendorMatch: ["google workspace", "g suite", "gsuite"],
  telemetrySources: ["gws", "o365", "sharepoint", "exchange", "teams"],
  kinds: Object.fromEntries(APPS.map(a => [a, kindSchema])),
};

export function kindOf(record: Record<string, unknown>): string | null {
  const app = (record.id as Record<string, unknown> | undefined)?.applicationName;
  return typeof app === "string" && (APPS as readonly string[]).includes(app) ? app : null;
}

// ── Typed parameters ─────────────────────────────────────────────────────────

type Param = Record<string, unknown>;
function p(name: string, v: unknown): Param | null {
  if (v === undefined || v === null || v === "") return null;
  if (typeof v === "boolean") return { name, boolValue: v };
  if (typeof v === "number") return { name, intValue: String(Math.trunc(v)) };
  if (Array.isArray(v)) return { name, multiValue: v.map(String) };
  return { name, value: String(v) };
}
const params = (...ps: Array<Param | null>) => ps.filter((x): x is Param => x !== null);
const msg = (name: string, inner: Param[]): Param => ({ name, messageValue: { parameter: inner } });

// ── Mappings ─────────────────────────────────────────────────────────────────

function docType(name?: string, raw?: string): string {
  if (raw) return raw;
  const ext = name && name.includes(".") ? name.split(".").pop()!.toLowerCase() : "";
  const m: Record<string, string> = {
    xlsx: "msexcel", xls: "msexcel", xlsm: "msexcel", csv: "unknown", docx: "msword", doc: "msword", docm: "msword",
    pptx: "mspowerpoint", ppt: "mspowerpoint", pdf: "pdf", txt: "txt", jpg: "jpeg", jpeg: "jpeg", png: "png", mp4: "mp4",
  };
  return ext ? m[ext] ?? "unknown" : "document";
}
const SCOPE_MAP: Array<[RegExp, string, string]> = [
  [/^Mail\./i, "https://mail.google.com/", "GMAIL"],
  [/^Files\.|^Sites\./i, "https://www.googleapis.com/auth/drive", "DRIVE"],
  [/^Calendars?\./i, "https://www.googleapis.com/auth/calendar", "CALENDAR"],
  [/^Contacts\./i, "https://www.googleapis.com/auth/contacts.readonly", "OTHER"],
  [/^User\.Read|^profile$|^email$/i, "https://www.googleapis.com/auth/userinfo.email", "IDENTITY"],
  [/^openid$/i, "openid", "IDENTITY"],
];
function bucketOf(scope: string): string {
  if (/mail\.google\.com|gmail/i.test(scope)) return "GMAIL";
  if (/\/auth\/drive/i.test(scope)) return "DRIVE";
  if (/calendar/i.test(scope)) return "CALENDAR";
  if (/userinfo|openid/i.test(scope)) return "IDENTITY";
  return "OTHER";
}
/** Microsoft role → Google admin event (true equivalents only). */
const ROLE_MAP: Record<string, string> = {
  "Helpdesk Administrator": "_HELP_DESK_ADMIN_ROLE", "Password Administrator": "_HELP_DESK_ADMIN_ROLE",
  "User Administrator": "_USER_MANAGEMENT_ADMIN_ROLE", "Groups Administrator": "_GROUPS_ADMIN_ROLE",
};

const ENTRA = /entra|azure ad|azure active directory/i;

// ── Converter ────────────────────────────────────────────────────────────────

interface Built { app: string; type: string; name: string; parameters?: Param[]; actor?: string; appInfo?: { id?: string; name: string }; noIp?: boolean }

function fromTelemetry(ev: TelemetryEvent, ctx: NativeCtx): NativeLog | null {
  const b = ev.source === "gws" ? fromGws(ev, ctx) : fromMicrosoft(ev, ctx);
  if (!b) return null;
  const actor = b.actor ?? userEmail(ev);
  if (!actor || !isEmail(actor)) return null;
  const raw: Raw = ev.raw ?? {};
  // Google is SaaS: an office-LAN client reaches it through the company's NAT egress, never with its private address.
  const lanIp = b.noIp ? undefined : clientIp(ev);
  const ip = lanIp && isPrivateIp(lanIp) ? egressIp(ctx) : lanIp;
  const record: Record<string, unknown> = {
    kind: "admin#reports#activity",
    id: { time: isoMs(ev.ts), uniqueQualifier: int64Str(ctx, `${ev.id}:uq`), applicationName: b.app, customerId: ctx.tenant.googleCustomerId },
    etag: `"${b64ish(ctx, `${b.app}:etag`, 27)}/${b64ish(ctx, `${ev.id}:etag`, 27)}"`,
    actor: {
      callerType: "USER",
      email: actor,
      profileId: `1${digits(ctx, entitySeed(ctx, "gprofile", actor), 20)}`,
      ...(b.appInfo ? { applicationInfo: { oauthClientId: b.appInfo.id ?? oauthClientId(ctx, b.appInfo.name), applicationName: b.appInfo.name } } : {}),
    },
    ownerDomain: domainOf(actor) ?? ctx.domain,
  };
  if (ip) {
    record.ipAddress = ip;
    const region = rs(raw, "source.geo.country_iso_code", "azure.signinlogs.location.country_or_region");
    const asn = Number(rs(raw, "source.as.number", "azure.signinlogs.properties.autonomousSystemNumber") ?? NaN);
    if ((region && /^[A-Z]{2}$/.test(region)) || !isNaN(asn)) {
      record.networkInfo = { ...(!isNaN(asn) ? { ipAsn: [asn] } : {}), ...(region && /^[A-Z]{2}$/.test(region) ? { regionCode: region } : {}) };
    }
  }
  const event: Record<string, unknown> = { type: b.type, name: b.name };
  if (b.parameters && b.parameters.length) event.parameters = b.parameters;
  record.events = [event];
  return { sourceId: "google_workspace", kind: b.app, format: "json", record, timeMs: Date.parse(ev.ts) };
}

function oauthClientId(ctx: NativeCtx, appName: string): string {
  const s = entitySeed(ctx, "gclient", appName);
  return `${digits(ctx, s, 12)}-${b64ish(ctx, `${s}:b`, 32).toLowerCase()}.apps.googleusercontent.com`;
}

function siteOf(url?: string): string | undefined {
  const m = url ? /(?:^|\/)(?:sites|teams)\/([^/]+)/.exec(url) : null;
  return m ? decodeURIComponent(m[1]) : undefined;
}

function driveAccess(ev: TelemetryEvent, ctx: NativeCtx, name: string, fileName: string, location?: string, rawDocType?: string): Param[] {
  const site = siteOf(location);
  const owner = site ? `${site} Shared` : userEmail(ev);
  const docSeed = entitySeed(ctx, "gdoc", `${location ?? ""}|${fileName}`);
  return params(
    p("primary_event", true), p("billable", true), p("owner_is_shared_drive", !!site), p("owner", owner),
    site ? p("shared_drive_id", `0A${b64ish(ctx, entitySeed(ctx, "gsd", site), 17)}`) : null,
    p("doc_id", `1${b64ish(ctx, docSeed, 43)}`), p("doc_type", docType(fileName, rawDocType)), p("is_encrypted", false),
    p("doc_title", fileName), p("visibility", "shared_internally"), p("originating_app_id", "691301496089"),
    p("actor_is_collaborator_account", false),
  );
}

function gmailDelivery(ev: TelemetryEvent, ctx: NativeCtx, sent: boolean): Built | null {
  const f = emailFacts(ev);
  const user = userEmail(ev);
  if (!user) return null;
  const imid = f.internetMessageId ?? `<${b64ish(ctx, `${ev.id}:gmid`, 40)}@mail.gmail.com>`;
  const src = sent ? user : f.from;
  const dst = sent ? (f.headerTo ?? f.to[0]) : user;
  const linkDomains = [...new Set([...f.urls.map(u => { try { return new URL(u).hostname; } catch { return ""; } }), ev.network?.domain].filter((d): d is string => !!d && d !== domainOf(src)))];
  const inner = params(
    p("rfc2822_message_id", imid), p("subject", f.subject),
    src ? msg("source", params(p("address", src), p("from_header_address", src))) : null,
    f.senderIp ? msg("connection_info", params(p("client_ip", f.senderIp))) : null, // submitting client (sent) or connecting MTA (received)
    dst ? { name: "destination", multiMessageValue: dst.split(/[;,]\s*/).map(a => ({ parameter: [{ name: "address", value: a }] })) } : null,
    p("is_spam", f.threats.includes("Spam")),
    linkDomains.length ? p("link_domain", linkDomains) : null,
    f.attachments.length ? { name: "attachment", multiMessageValue: f.attachments.map(a => ({ parameter: params(p("file_name", a.name), p("sha256", a.sha256)) })) } : null,
  );
  // G10 layout — nesting of message_info is UNVERIFIED in the card (only Gmail record available for mail flow).
  return {
    app: "gmail", type: "delivery_type", name: "delivery", actor: user, noIp: true,
    parameters: [msg("event_info", params(p("mail_event_type", sent ? 1 : 2), p("success", true))), msg("message_info", inner)],
  };
}

/** Native Google-authored events (legacy raw shapes + Reports-API-shaped raw). */
function fromGws(ev: TelemetryEvent, ctx: NativeCtx): Built | null {
  const raw: Raw = ev.raw ?? {};
  const eventName = rs(raw, "gws.eventName", "eventName");
  if (eventName === "CREATE_GMAIL_FILTER") return null; // no Reports API event for user Gmail filters
  if (eventName === "message_sent") return gmailDelivery(ev, ctx, true);
  if (eventName) return null; // calendar.event.created … (application not documented in the card)

  const app = rs(raw, "gws.id.applicationName");
  const type = rs(raw, "gws.event.type");
  if (app && type) {
    const name = rs(raw, "gws.event.name") ?? type;
    const ps: Param[] = [];
    for (const [key, v] of Object.entries(raw)) {
      const m = /^gws\.parameters\.(.+)$/.exec(key);
      if (!m) continue;
      // change_user_access old/new value are plain strings in the native API (card §3.4).
      const val = Array.isArray(v) && name === "change_user_access" && (m[1] === "old_value" || m[1] === "new_value") ? v[0] : v;
      const pp = p(m[1], val);
      if (pp) ps.push(pp);
    }
    // gemini_in_workspace_apps parameter names come from the authored event (app params not expanded in the card).
    return { app, type, name, parameters: ps };
  }

  const appName = rs(raw, "application.name");
  const appId = rs(raw, "application.id");
  const appInfo = appName ? { id: appId && /googleusercontent/.test(appId) ? appId : undefined, name: appName } : undefined;
  const clientId = appInfo ? (appInfo.id ?? oauthClientId(ctx, appInfo.name)) : undefined;
  switch (type) {
    case "message_delivered": return gmailDelivery(ev, ctx, false);
    case "email_log_search": return null; // an admin search result, not an audit record
    case "authorize": {
      const scopes = (rs(raw, "gws.parameters.scope", "parameters.scope") ?? "").split(/[,\s]+/).filter(Boolean);
      return { app: "token", type: "auth", name: "authorize", parameters: tokenAuthorize(clientId!, appName!, scopes) };
    }
    case "revoke":
      return { app: "token", type: "auth", name: "revoke", parameters: params(p("client_id", clientId), p("app_name", appName), p("client_type", "WEB")) };
    case "gmail.messages.list":
    case "gmail.messages.get":
      return {
        app: "token", type: "auth", name: "activity",
        parameters: params(p("client_id", clientId), p("app_name", appName), p("api_name", "gmail"),
          p("method_name", type === "gmail.messages.list" ? "gmail.users.messages.list" : "gmail.users.messages.get"),
          p("num_response_bytes", ctx.int(`${ev.id}:bytes`, 2048, 98304)), p("product_bucket", "GMAIL")),
      };
    case "drive.export": {
      const fileName = rs(raw, "storage.object.name") ?? ev.file?.name;
      if (!fileName) return null;
      const loc = rs(raw, "storage.bucket.name");
      const sharedDrive = loc ? /Shared Drive:\s*(.+)$/.exec(loc)?.[1] : undefined;
      return { app: "drive", type: "access", name: "download", appInfo, parameters: driveAccess(ev, ctx, "download", fileName, sharedDrive ? `/sites/${sharedDrive}` : undefined) };
    }
  }
  return null;
}

function tokenAuthorize(clientId: string, appName: string, scopes: string[]): Param[] {
  return params(
    p("client_id", clientId), p("app_name", appName), p("client_type", "WEB"),
    scopes.length ? { name: "scope_data", multiMessageValue: scopes.map(s => ({ parameter: [{ name: "scope_name", value: s }, { name: "product_bucket", multiValue: [bucketOf(s)] }] })) } : null,
    scopes.length ? p("scope", scopes) : null,
  );
}

/** M365 / Entra-authored events → Google equivalent, or null. */
function fromMicrosoft(ev: TelemetryEvent, ctx: NativeCtx): Built | null {
  const raw: Raw = ev.raw ?? {};
  const vendor = ev.vendor ?? "";
  if (/defender|purview|graph security/i.test(vendor) && !["auth_success", "auth_failure"].includes(ev.event_type)) {
    // Defender mail verdicts are email-security telemetry; Purview / Graph-Security records are DLP / app-token reads.
    if (!/FileDownloaded|FileAccessed/.test(rs(raw, "event.action", "Operation") ?? "")) return null;
  }
  const op = resolveOperation(ev) ?? (ENTRA.test(vendor) ? (ev.event_type === "auth_success" || ev.event_type === "mfa_challenge" ? "UserLoggedIn"
    : ev.event_type === "auth_failure" || ev.event_type === "mfa_denied" ? "UserLoginFailed" : undefined) : undefined);
  const entraAudit = rs(raw, "azure.auditlogs.operationName", "azure.operation");
  const opName = op ?? entraAudit;
  if (!opName) return null;
  const user = userEmail(ev);

  // Logins
  if (opName === "UserLoggedIn" || opName === "UserLoginFailed") {
    const fail = opName === "UserLoginFailed" || ev.event_type === "auth_failure" || ev.event_type === "mfa_denied";
    const authDetail = `${ev.authentication?.method ?? ""} ${ev.authentication?.mfa_type ?? ""} ${rs(raw, "azure.authenticationDetails.authenticationMethodDetail") ?? ""}`;
    const mfa = ev.event_type === "mfa_challenge" || ev.event_type === "mfa_denied" || /authenticator|push|mfa|otp|fido/i.test(authDetail);
    const methods = ev.event_type === "mfa_denied" ? ["google_prompt"] : mfa ? ["password", "google_prompt"] : ["password"];
    const suspicious = (ev.severity === "high" || ev.severity === "critical") && ev.expected_verdict !== "fp";
    return {
      app: "login", type: "login", name: fail ? "login_failure" : "login_success",
      parameters: fail
        ? params(p("login_type", "google_password"), p("login_challenge_method", methods), ev.event_type === "mfa_denied" ? null : p("login_failure_type", "login_failure_invalid_password"))
        : params(p("login_type", "google_password"), p("login_challenge_method", methods), p("is_suspicious", suspicious)),
    };
  }

  // Drive access
  const fileOps: Record<string, string> = { FileDownloaded: "download", FileSyncDownloadedFull: "download", FileAccessed: "view", FilePreviewed: "preview", FileModified: "edit", FileUploaded: "upload" };
  if (fileOps[opName]) {
    const fileName = ev.file?.name ?? rs(raw, "SourceFileName", "file.name", "ItemName");
    if (!fileName) return null; // a Drive access event always names one document
    const location = rs(raw, "SiteUrl", "cloud.resource.name", "SourceRelativeUrl", "ObjectId") ?? ev.file?.path;
    const appName = rs(raw, "application.name");
    return { app: "drive", type: "access", name: fileOps[opName], appInfo: appName ? { name: appName } : undefined, parameters: driveAccess(ev, ctx, fileOps[opName], fileName, location) };
  }

  // Sharing
  if (opName === "AnonymousLinkCreated" || ((opName === "SharingInvitationCreated" || opName === "SharingSet" || opName === "AddedToSecureLink") && user)) {
    const fileName = ev.file?.name ?? rs(raw, "SourceFileName", "file.name");
    if (!fileName || !user) return null;
    const location = rs(raw, "ObjectId", "SiteUrl") ?? ev.file?.path;
    const docSeed = entitySeed(ctx, "gdoc", `${location ?? ""}|${fileName}`);
    const common = params(p("owner_is_shared_drive", !!siteOf(location)), p("owner", siteOf(location) ? `${siteOf(location)} Shared` : user),
      p("doc_id", `1${b64ish(ctx, docSeed, 43)}`), p("doc_type", docType(fileName)), p("is_encrypted", false), p("doc_title", fileName),
      p("originating_app_id", "691301496089"), p("actor_is_collaborator_account", false));
    if (opName === "AnonymousLinkCreated") {
      return { app: "drive", type: "acl_change", name: "change_document_visibility", parameters: [
        ...params(p("primary_event", true), p("billable", true), p("visibility_change", "external"), p("target_domain", "all"),
          p("old_value", ["private"]), p("new_value", ["people_with_link"]), p("old_visibility", "private"), p("visibility", "people_with_link")), ...common] };
    }
    const target = rs(raw, "TargetUserOrGroupName");
    if (!target || !isEmail(target)) return null;
    const external = domainOf(target) !== domainOf(user);
    return { app: "drive", type: "acl_change", name: "change_user_access", parameters: [
      ...params(p("primary_event", true), p("billable", true), p("visibility_change", external ? "external" : "internal"), p("target_user", target),
        p("old_value", "none"), p("new_value", /edit/i.test(rs(raw, "EventData.PermissionLevel") ?? "") ? "can_edit" : "can_view"),
        p("old_visibility", "shared_internally"), p("visibility", external ? "shared_externally" : "shared_internally")), ...common] };
  }

  // OAuth consent (per-user only)
  if (opName === "Consent to application." || opName === "Consent to application") {
    const ext = (n: string) => { for (let i = 0; i < 10; i++) if (rs(raw, `ExtendedProperties[${i}].Name`) === n) return rs(raw, `ExtendedProperties[${i}].Value`); return undefined; };
    if (/^true$/i.test(rs(raw, "oauth.consent.is_admin_consent") ?? "") || ext("ConsentType") === "AllPrincipals") return null; // tenant-wide: no 1:1 token event
    if (/^(failure|failed)$/i.test(rs(raw, "ResultStatus") ?? "")) return null;
    const appName = rs(raw, "application.name", "oauth.app.name") ?? ext("AppDisplayName");
    if (!appName || !user) return null;
    const ms = (rs(raw, "oauth.consent.scopes_granted", "iam.permission") ?? ext("Permissions") ?? "").split(/[|,\s]+/).filter(Boolean);
    const scopes: string[] = [];
    for (const s of ms) for (const [re, g] of SCOPE_MAP) if (re.test(s) && !scopes.includes(g)) scopes.push(g);
    if (!scopes.includes("openid")) scopes.push("openid");
    return { app: "token", type: "auth", name: "authorize", parameters: tokenAuthorize(oauthClientId(ctx, appName), appName, scopes) };
  }

  // Admin role grant
  if (/^Add member to role\.?$/.test(opName)) {
    const role = rs(raw, "azure.role.name", "Role.DisplayName");
    const target = rs(raw, "azure.target.upn", "ObjectId", "target.user.email") ?? user;
    const actor = rs(raw, "azure.actor.upn", "UserId") ?? user;
    if (!role || !target || !isEmail(target)) return null;
    if (role === "Global Administrator" || role === "Privileged Role Administrator") {
      return { app: "admin", type: "USER_SETTINGS", name: "GRANT_ADMIN_PRIVILEGE", actor, parameters: params(p("USER_EMAIL", target)) };
    }
    if (!ROLE_MAP[role]) return null;
    return { app: "admin", type: "DELEGATED_ADMIN_SETTINGS", name: "ASSIGN_ROLE", actor, parameters: params(p("ROLE_NAME", ROLE_MAP[role]), p("USER_EMAIL", target), p("ORG_UNIT_NAME", "/")) };
  }

  // Mailbox forwarding (user-level, out of domain only)
  if (opName === "Set-Mailbox") {
    const blob = JSON.stringify(raw);
    const m = /smtp:([^\s"'\\;,]+@[^\s"'\\;,]+)/i.exec(blob) ?? /ForwardingSmtpAddress[^@]*?([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})/.exec(blob);
    const dest = m?.[1];
    if (!dest || !user || domainOf(dest) === domainOf(user)) return null;
    return { app: "user_accounts", type: "email_forwarding_change", name: "email_forwarding_out_of_domain", parameters: params(p("email_forwarding_destination_address", dest)) };
  }

  // Passwords
  if (/^Reset (user )?password/i.test(opName)) {
    const actor = rs(raw, "UserId", "azure.auditlogs.properties.initiatedBy.user.userPrincipalName");
    const target = rs(raw, "ObjectId", "target.user.email", "azure.auditlogs.properties.targetResources[0].userPrincipalName") ?? user;
    if (!actor || !isEmail(actor) || !target || !isEmail(target) || isGuid(target)) return null;
    return { app: "admin", type: "USER_SETTINGS", name: "CHANGE_PASSWORD", actor, parameters: params(p("USER_EMAIL", target)) };
  }
  if (/^Change user password\.?$/.test(opName)) return { app: "user_accounts", type: "password_change", name: "password_edit" };

  // Mail (sent / received) → Gmail delivery log
  if (opName === "Send" || ev.event_type === "email_sent") return gmailDelivery(ev, ctx, true);
  if (/^(MessageDelivered)$/.test(opName)) return gmailDelivery(ev, ctx, false);
  return null;
}

// ── Use cases ────────────────────────────────────────────────────────────────

const PERSONAL = "@(gmail\\.com|googlemail\\.com|outlook\\.com|hotmail\\.com|yahoo\\.|proton\\.me|protonmail\\.com|tutanota\\.com|gmx\\.|icloud\\.com|mail\\.ru|yandex\\.)";
const useCases: UseCase[] = [
  {
    id: "google_workspace.suspicious-login-then-2sv-disabled",
    title: "Suspicious login followed by 2-Step Verification being turned off",
    sourceId: "google_workspace", kinds: ["login", "user_accounts"], severity: "critical", mitre: ["T1078.004", "T1556.006"],
    description: "Google flagged a sign-in (account_warning suspicious_login) and within the hour the same account disabled 2SV (2sv_disable). An attacker removing the second factor to keep access is the textbook account-takeover sequence; reset the password, revoke sessions (RESET_SIGNIN_COOKIES) and re-enrol 2SV.",
    logic: "BigQuery / Reports API:\nactivity | where id.applicationName in ('login','user_accounts') and events.name in ('suspicious_login','2sv_disable')\n| group by actor.email within 1h | having count(distinct events.name) = 2",
    match: { field: "events[].name", op: "in", value: ["suspicious_login", "2sv_disable"] },
    threshold: { groupBy: ["actor.email"], count: 2, windowSec: 3600, distinct: "events[].name" },
    falsePositives: ["User replacing a lost phone while travelling (confirm with the user out-of-band)"],
  },
  {
    id: "google_workspace.suspicious-login",
    title: "Google flagged a login as suspicious",
    sourceId: "google_workspace", kinds: ["login"], severity: "high", mitre: ["T1078.004"],
    description: "login_success with is_suspicious=true, or an account_warning (suspicious_login / suspicious_programmatic_login). Pivot on ipAddress / networkInfo.regionCode and the actor's next actions (2SV, forwarding, OAuth grants, Drive).",
    logic: "Reports API: applicationName=login AND ((eventName=login_success AND is_suspicious=true) OR eventName IN (suspicious_login, suspicious_programmatic_login))",
    match: { any: [
      { field: "events[].name", op: "in", value: ["suspicious_login", "suspicious_programmatic_login", "suspicious_login_less_secure_app"] },
      { all: [{ field: "events[].name", op: "eq", value: "login_success" }, { field: "events[].parameters[].boolValue", op: "eq", value: true }] },
    ] },
    falsePositives: ["Legitimate travel or a new ISP", "VPN egress in an unusual country"],
  },
  {
    id: "google_workspace.out-of-domain-forwarding",
    title: "Automatic forwarding to an address outside the domain",
    sourceId: "google_workspace", kinds: ["user_accounts", "login"], severity: "high", mitre: ["T1114.003"],
    description: "email_forwarding_out_of_domain: every new message is copied to email_forwarding_destination_address. Right after a suspicious login it is mailbox exfiltration; also check the destination against approved leave arrangements.",
    logic: "Reports API: applicationName=user_accounts eventName=email_forwarding_out_of_domain | table id.time actor.email ipAddress email_forwarding_destination_address",
    match: { field: "events[].name", op: "eq", value: "email_forwarding_out_of_domain" },
    falsePositives: ["Approved forwarding during leave (HR ticket)", "Mailbox migrations"],
  },
  {
    id: "google_workspace.oauth-mail-drive-scopes",
    title: "OAuth app authorized with full Gmail / Drive scopes",
    sourceId: "google_workspace", kinds: ["token"], severity: "high", mitre: ["T1528"],
    description: "token authorize granting https://mail.google.com/ or …/auth/drive to a third-party app (client_id / app_name). Such grants survive password resets; follow the same client_id in token activity events to see what it pulled.",
    logic: "Reports API: applicationName=token eventName=authorize AND scope IN ('https://mail.google.com/','https://www.googleapis.com/auth/drive', 'https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/drive.readonly')",
    match: { all: [
      { field: "events[].name", op: "eq", value: "authorize" },
      { field: "events[].parameters[].multiValue[]", op: "regex", value: "^https://mail\\.google\\.com/$|/auth/gmail\\.|/auth/drive(\\.readonly)?$" },
    ] },
    falsePositives: ["Admin-approved backup / e-signature apps (allow-list client_id)"],
  },
  {
    id: "google_workspace.mass-drive-download",
    title: "Mass Drive download by one account",
    sourceId: "google_workspace", kinds: ["drive"], severity: "high", mitre: ["T1530", "T1213"],
    description: "50+ primary download events from one actor within 10 minutes (count only primary_event=true). Check ipAddress, actor.applicationInfo (an app pulling files?) and whether the documents are outside the user's normal work.",
    logic: "Reports API / BigQuery:\ndrive | where events.name = 'download' and primary_event = true\n| summarize count() by actor.email, bin(id.time, 10m) | where count_ >= 50",
    match: { all: [{ field: "events[].name", op: "eq", value: "download" }, { field: "events[].parameters[].name", op: "eq", value: "primary_event" }] },
    threshold: { groupBy: ["actor.email"], count: 50, windowSec: 600 },
    falsePositives: ["Drive for desktop initial sync", "Approved Takeout / migration"],
  },
  {
    id: "google_workspace.public-link",
    title: "Document opened to anyone with the link / the web",
    sourceId: "google_workspace", kinds: ["drive"], severity: "medium", mitre: ["T1567", "T1537"],
    description: "change_document_visibility to people_with_link or public_on_the_web (visibility_change=external) makes the file readable without a Google account. Check doc_title / owner and whether the actor just signed in from a new IP.",
    logic: "Reports API: applicationName=drive eventName=change_document_visibility AND new_value IN ('people_with_link','public_on_the_web')",
    match: { all: [
      { field: "events[].name", op: "eq", value: "change_document_visibility" },
      { field: "events[].parameters[].multiValue[]", op: "in", value: ["people_with_link", "public_on_the_web"] },
    ] },
    falsePositives: ["Marketing publishing public material"],
  },
  {
    id: "google_workspace.external-share-personal",
    title: "Document shared with a personal / free-mail account",
    sourceId: "google_workspace", kinds: ["drive"], severity: "medium", mitre: ["T1537"],
    description: "change_user_access with visibility_change=external and a target_user on a consumer provider: a common insider / ATO exfiltration path that leaves no download trail.",
    logic: "Reports API: applicationName=drive eventName=change_user_access visibility_change=external AND target_user matches '@(gmail|outlook|proton…)'",
    match: { all: [
      { field: "events[].name", op: "eq", value: "change_user_access" },
      { field: "events[].parameters[].value", op: "regex", value: PERSONAL },
    ] },
    falsePositives: ["Sharing with contractors who use personal accounts (should use guest / visitor sharing)"],
  },
  {
    id: "google_workspace.admin-privilege-granted",
    title: "Super-admin / admin role granted",
    sourceId: "google_workspace", kinds: ["admin"], severity: "high", mitre: ["T1098.003"],
    description: "GRANT_ADMIN_PRIVILEGE (makes USER_EMAIL a super admin) or ASSIGN_ROLE with ROLE_NAME _SEED_ADMIN_ROLE. Verify against a change ticket; grants to service or newly-created accounts are escalation / persistence.",
    logic: "Reports API: applicationName=admin AND (eventName=GRANT_ADMIN_PRIVILEGE OR (eventName=ASSIGN_ROLE AND ROLE_NAME='_SEED_ADMIN_ROLE'))",
    match: { any: [
      { field: "events[].name", op: "eq", value: "GRANT_ADMIN_PRIVILEGE" },
      { all: [{ field: "events[].name", op: "eq", value: "ASSIGN_ROLE" }, { field: "events[].parameters[].value", op: "eq", value: "_SEED_ADMIN_ROLE" }] },
    ] },
    falsePositives: ["Planned admin onboarding"],
  },
  {
    id: "google_workspace.login-failure-burst",
    title: "Many accounts failing to log in from one IP",
    sourceId: "google_workspace", kinds: ["login"], severity: "medium", mitre: ["T1110.003"],
    description: "login_failure for 5+ distinct actor.email from one ipAddress in 10 minutes — password spraying against Google accounts.",
    logic: "Reports API: applicationName=login eventName=login_failure | stats dc(actor.email) by ipAddress span=10m | where dc >= 5",
    match: { field: "events[].name", op: "eq", value: "login_failure" },
    threshold: { groupBy: ["ipAddress"], count: 5, windowSec: 600, distinct: "actor.email" },
    falsePositives: ["Shared NAT of a large office after a password policy change"],
  },
];

export const source: NativeSource = { schema, fromTelemetry, useCases };
