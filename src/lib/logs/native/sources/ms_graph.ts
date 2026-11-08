/**
 * Microsoft Graph Security alerts as a SIEM indexes them (card: docs/log-schemas/siem-ms-graph-alerts.md).
 *
 * One record is one alerts_v2 `alert` (learn.microsoft.com/graph/api/resources/security-alert) as the
 * Wazuh Microsoft Graph module delivers it: the alert under `data.ms-graph`, with `resource` and
 * `relationship` added, `data.integration` = "ms-graph" and decoder json-msgraph. Evidence entries are
 * the documented derived types of alertEvidence, built only from what the event contains.
 *
 * Applies only to a product detection of a Microsoft product (stack.ts microsoftProductOf), in a
 * session whose stack carries detection_feed. Anything else returns null.
 *
 * An alert never carries the answer. The input is the public payload: the answer fields are dropped
 * on entry, so a corpus event and its public body render alike. Every alert is status "new" and
 * unclassified, every evidence verdict is "unknown", no evidence role states a conclusion, and
 * incidentId is per alert, because a shared one would group an attack's alerts as benign alerts
 * never are. A benign and an attack detection have the same shape.
 *
 * Ids: an alert keeps the AlertId of the Defender AlertEvidence row of the same event (same seeds),
 * so the two records join. Device, user and process ids are the ones the other Microsoft records print.
 */
import { deviceKey } from "./mde";
import type { TelemetryEvent } from "@/lib/sim/types";
import { techniqueById } from "@/lib/mitre/attack";
import { microsoftProductOf, type MicrosoftProduct, type Stack } from "../stack";
import type { KindSchema, NativeCtx, NativeLog, NativeSource, UseCase } from "../types";
import { imagePath } from "./_cs-s1-common";
import {
  TACTICS, TECHNIQUES, baseOf, dirOf, effectiveAction, fixPath, imageName, isPrivate, isServer, isSystemUser, isoFrac, tacticOf,
} from "./_edr_mde_sophos_common";
import { displayNameOf, userEmail } from "./_identity-common";
import { accountSid, hostKey, imageHashes, procPid, sha1Of, type ProcScope } from "./_proc-identity";
import { aadObjectId } from "./collab-email-shared";
import { source as defenderO365 } from "./defender_o365";
import { edrFacts, type EdrFacts, type EdrProc } from "./edr-normalize";
import { source as mde } from "./mde";

// ── Schema ──────────────────────────────────────────────────────────────────

const M = (xs: string[]) => xs.map(x => `data.ms-graph.${x}`);
const E = (xs: string[]) => M(xs.map(x => `evidence[].${x}`));
const FILE = ["fileName", "filePath", "fileSize", "filePublisher", "signer", "issuer", "md5", "sha1", "sha256"];
const ACCOUNT = ["accountName", "domainName", "userSid", "azureAdUserId", "userPrincipalName", "displayName"];
const SENDER = ["emailAddress", "displayName", "domainName"];

const ALERTS_V2: KindSchema = {
  required: ["timestamp", "decoder.name", "data.integration", ...M([
    "@odata.type", "id", "providerAlertId", "incidentId", "status", "severity", "classification", "determination", "serviceSource",
    "detectionSource", "detectorId", "tenantId", "title", "description", "category", "categories", "alertWebUrl", "incidentWebUrl",
    "mitreTechniques", "createdDateTime", "lastUpdateDateTime", "firstActivityDateTime", "lastActivityDateTime", "comments", "evidence",
    "systemTags", "resource", "relationship",
  ])],
  optional: [
    ...M(["productName", "recommendedActions", "assignedTo", "actorDisplayName", "threatDisplayName", "threatFamilyName", "resolvedDateTime",
      "alertPolicyId", "investigationState", "additionalData", "customDetails"]),
    ...E(["@odata.type", "createdDateTime", "verdict", "remediationStatus", "remediationStatusDetails", "roles", "detailedRoles", "tags",
      "detectionStatus", "mdeDeviceId"]),
    // deviceEvidence
    ...E(["azureAdDeviceId", "deviceDnsName", "hostName", "ntDomain", "dnsDomain", "osPlatform", "healthStatus", "riskScore", "onboardingStatus",
      "defenderAvStatus", "ipInterfaces", "loggedOnUsers", "loggedOnUsers[].accountName", "loggedOnUsers[].domainName"]),
    // userEvidence, mailboxEvidence, processEvidence
    ...E(ACCOUNT.map(x => `userAccount.${x}`)),
    ...E(["displayName", "primaryAddress", "upn"]),
    ...E(["processId", "parentProcessId", "processCommandLine", "processCreationDateTime", "parentProcessCreationDateTime",
      "parentProcessImageFile", ...FILE.map(x => `imageFile.${x}`), ...FILE.map(x => `parentProcessImageFile.${x}`)]),
    // fileEvidence, ipEvidence, urlEvidence
    ...E(FILE.map(x => `fileDetails.${x}`)),
    ...E(["ipAddress", "countryLetterCode", "url"]),
    // analyzedMessageEvidence
    ...E(["networkMessageId", "internetMessageId", "subject", "language", "senderIp", "recipientEmailAddress", "antiSpamDirection", "deliveryAction",
      "deliveryLocation", "urn", "threats", "threatDetectionMethods", "urls", "urlCount", "attachmentsCount", "receivedDateTime",
      ...SENDER.map(x => `p1Sender.${x}`), ...SENDER.map(x => `p2Sender.${x}`)]),
  ],
};

/** Classify an indexed record: the module adds `relationship` to every record it sends. */
export function kindOf(record: Record<string, unknown>): string | null {
  const data = record.data as { integration?: unknown; "ms-graph"?: { relationship?: unknown } } | undefined;
  return data?.integration === "ms-graph" && data["ms-graph"]?.relationship === "alerts_v2" ? "alerts_v2" : null;
}

// ── Products ────────────────────────────────────────────────────────────────

interface Product { serviceSource: string; detectionSource: string; productName: string; description: string; recommendedActions: string }

/**
 * serviceSource: microsoft.graph.security serviceSource enum (enums-security). detectionSource:
 * the detectionSource enum (security-detectionsource). Sources per row in the card. productName is
 * not enumerated by the documentation; these are the products' display names.
 */
const PRODUCTS: Record<MicrosoftProduct, Product> = {
  defender_endpoint: {
    serviceSource: "microsoftDefenderForEndpoint", detectionSource: "microsoftDefenderForEndpoint", productName: "Microsoft Defender for Endpoint",
    description: "Microsoft Defender for Endpoint raised this alert on activity recorded on the device.",
    recommendedActions: "Review the device timeline around the alert time and the process tree of the activity. Decide from those records whether the activity was expected.",
  },
  entra_id_protection: {
    serviceSource: "azureAdIdentityProtection", detectionSource: "azureAdIdentityProtection", productName: "Microsoft Entra ID Protection",
    description: "Microsoft Entra ID Protection raised this alert on sign-in or account activity.",
    recommendedActions: "Review the user's sign-ins and directory changes around the alert time. Confirm with the user whether the activity was theirs.",
  },
  defender_office: {
    serviceSource: "microsoftDefenderForOffice365", detectionSource: "microsoftDefenderForOffice365", productName: "Microsoft Defender for Office 365",
    description: "Microsoft Defender for Office 365 raised this alert on a message or a click.",
    recommendedActions: "Review the message, its sender and its URLs, and who else received it.",
  },
  defender_cloud_apps: {
    serviceSource: "microsoftDefenderForCloudApps", detectionSource: "cloudAppSecurity", productName: "Microsoft Defender for Cloud Apps",
    description: "Microsoft Defender for Cloud Apps raised this alert on activity in a cloud application.",
    recommendedActions: "Review the user's activity in the application around the alert time. Confirm whether it matches the user's normal work.",
  },
  defender_identity: {
    serviceSource: "microsoftDefenderForIdentity", detectionSource: "microsoftDefenderForIdentity", productName: "Microsoft Defender for Identity",
    description: "Microsoft Defender for Identity raised this alert on activity seen on a domain controller.",
    recommendedActions: "Review the account and the source device of the activity on the domain controller.",
  },
  defender_cloud: {
    serviceSource: "microsoftDefenderForCloud", detectionSource: "microsoftDefenderForCloud", productName: "Microsoft Defender for Cloud",
    description: "Microsoft Defender for Cloud raised this alert on activity on a cloud resource.",
    recommendedActions: "Review the resource and the operations on it around the alert time.",
  },
  purview_dlp: {
    serviceSource: "dataLossPrevention", detectionSource: "microsoftDataLossPrevention", productName: "Microsoft Purview Data Loss Prevention",
    description: "A Microsoft Purview Data Loss Prevention policy matched this activity.",
    recommendedActions: "Review the policy match, the content and the destination. Confirm whether the transfer had a business reason.",
  },
  insider_risk: {
    // serviceSource has no member for Insider Risk Management; detectionSource has one.
    serviceSource: "unknown", detectionSource: "microsoftInsiderRiskManagement", productName: "Microsoft Purview Insider Risk Management",
    description: "Microsoft Purview Insider Risk Management raised this alert on user activity.",
    recommendedActions: "Review the user's activity and the policy that matched it.",
  },
  // The SIEM analytics of a session that reads Graph (an XDR session, the only one with
  // detection_feed) are XDR's own rules, not a Microsoft service: Graph's serviceSource for a
  // source outside its enum is "unknown" (owner, 2026-11-08: nothing presents XDR as Sentinel).
  sentinel: {
    serviceSource: "unknown", detectionSource: "scheduledAlerts", productName: "XDR Analytics",
    description: "An XDR analytics rule raised this alert.",
    recommendedActions: "Review the events the rule matched and the entities they name.",
  },
  defender_xdr: {
    serviceSource: "microsoft365Defender", detectionSource: "microsoft365Defender", productName: "Microsoft 365 Defender",
    description: "Microsoft 365 Defender correlated signals from several products into this alert.",
    recommendedActions: "Review each signal and the entities they share.",
  },
};

/** Sentinel's own detection technologies (detectionSource enum), by what raised the row. */
function sentinelDetection(ev: TelemetryEvent): string {
  if (ev.event_type === "threat_intel_match") return "microsoftDefenderThreatIntelligenceAnalytics";
  if (ev.source === "ueba" || /ueba|anomal/i.test(ev.event_type)) return "builtInMl";
  return "scheduledAlerts";
}

/** Every category in the stack is Microsoft's: the module decides on the event, the session's stack on sourceFor. */
const MICROSOFT_STACK: Stack = { edr: "mde", idp: "entra", collab: "m365", email_security: "defender_o365" };

const SEVERITY: Record<string, string> = { critical: "high", high: "high", medium: "medium", low: "low", informational: "informational", info: "informational" };

/** alert name per event type when the row names none (the same names the Sentinel workspace gives). */
const TYPE_NAME: Record<string, string> = {
  auth_success: "Sign-in flagged by the identity provider", auth_failure: "Failed sign-in flagged by the identity provider", privilege_escalation: "Elevated privileges assigned",
  group_modify: "Group membership changed", account_modify: "Account properties changed", account_create: "New account created", role_assignment: "Role assignment changed",
  process_create: "Process flagged by endpoint protection", file_create: "File flagged by endpoint protection", net_connection: "Connection flagged by network protection",
  email_received: "Message flagged by mail protection", cloud_api_call: "Cloud API call flagged", policy_modification: "Security policy changed",
};

const LOCATION: Record<string, string> = {
  "Inbox/folder": "inbox", Quarantine: "quarantine", "Junk folder": "junkFolder", "Deleted items": "deletedFolder", External: "external",
  "On-premises/external": "external", Failed: "failed", Dropped: "dropped", Forwarded: "forwarded",
};

// ── Helpers ─────────────────────────────────────────────────────────────────

/** Fields the public payload never carries (buildTimeline TEAM_ANSWER_FIELDS and the story's own marks). */
const ANSWER_FIELDS = ["expected_verdict", "fp_explanation", "incident_id", "edr_scope", "is_baseline", "it_verify_result", "it_verify_message", "it_context",
  "supports_inject", "feed_origin", "attack_name", "bonus_attack", "auto_contained", "tier"];
function publicOf(ev: TelemetryEvent): TelemetryEvent {
  const out = { ...ev } as unknown as Record<string, unknown>;
  for (const k of ANSWER_FIELDS) delete out[k];
  return out as unknown as TelemetryEvent;
}

const rawText = (ev: TelemetryEvent, ...keys: string[]): string | undefined => {
  const r = (ev.raw ?? {}) as Record<string, unknown>;
  for (const k of keys) { const v = r[k]; if (typeof v === "string" && v.trim()) return v.trim(); }
  return undefined;
};

/** Alert category: the tactic the alert states, in Graph's token form. */
function categoryOf(ev: TelemetryEvent, f: EdrFacts): string {
  const named = ev.mitre_tactic ?? tacticOf(f);
  const byName = named ? TACTICS[named]?.token ?? Object.values(TACTICS).find(t => t.id === named)?.token : undefined;
  if (byName) return byName;
  const known = ev.mitre_technique ? TECHNIQUES[ev.mitre_technique]?.[1] : undefined;
  const token = known ? TACTICS[known]?.token : undefined;
  const tacticId = ev.mitre_technique ? techniqueById(ev.mitre_technique)?.tactic : undefined;
  return token ?? (tacticId ? Object.values(TACTICS).find(t => t.id === tacticId)?.token : undefined) ?? "SuspiciousActivity";
}

function titleOf(ev: TelemetryEvent, row: Record<string, unknown> | undefined): string {
  const named = rawText(ev, "AlertName", "DisplayName", "purview.Title", "azure.alert.displayName", "data.ms-graph.title", "data.ms-graph.displayName")
    ?? (typeof row?.Title === "string" ? row.Title : undefined)
    ?? rawText(ev, "alert.name") ?? ev.rule?.name;
  if (named) return named;
  const policy = rawText(ev, "PolicyDetails.PolicyName", "PolicyDetails[0].PolicyName", "data.office365.PolicyDetails.PolicyName", "data.office365.PolicyDetails[0].PolicyName", "purview.PolicyName", "policy.name", "dlp.policy.name");
  if (policy) return `DLP policy (${policy}) matched`;
  const technique = ev.mitre_technique ? techniqueById(ev.mitre_technique)?.name : undefined;
  return technique ?? TYPE_NAME[ev.event_type] ?? "Suspicious activity";
}

function osPlatform(host: string, os: EdrFacts["os"]): string {
  if (os === "Lin") return "Linux";
  if (os === "Mac") return "macOS";
  return isServer(host) ? "WindowsServer2022" : "Windows11";
}

interface Account { accountName: string | null; domainName: string | null; userSid: string | null; azureAdUserId: string | null; userPrincipalName: string | null; displayName: string | null }

function accountFor(ev: TelemetryEvent, ctx: NativeCtx, f: EdrFacts, name: string, email: string | undefined): Account {
  const system = isSystemUser(name);
  const upn = system ? null : email ?? `${name.toLowerCase()}@${ctx.domain}`;
  return {
    accountName: name,
    domainName: system ? "NT AUTHORITY" : f.userDomain ?? ctx.netbios,
    userSid: f.os === "Win" ? (name === f.user ? f.sid : undefined) ?? accountSid(ctx, name, upn ?? undefined) : null,
    azureAdUserId: upn ? aadObjectId(ctx, upn) : null,
    userPrincipalName: upn,
    displayName: displayNameOf(ev, upn ?? undefined) ?? name,
  };
}

/** The account the event names, and the account its process ran as when that is another one (a service as SYSTEM). */
function accountsOf(ev: TelemetryEvent, ctx: NativeCtx, f: EdrFacts): { account: Account | null; runAs: Account | null } {
  const email = [userEmail(ev), f.userEmail].find(e => e?.includes("@"));
  const name = email?.split("@")[0] ?? f.user;
  const account = name ? accountFor(ev, ctx, f, name, email) : null;
  const runAs = f.user && f.user.toLowerCase() !== name?.toLowerCase() ? accountFor(ev, ctx, f, f.user, undefined) : account;
  return { account, runAs };
}

function fileDetails(ctx: NativeCtx, path: string | undefined, name: string | undefined, sha256: string | undefined, md5: string | undefined, size: number | undefined) {
  const ident = sha256 ?? path?.toLowerCase() ?? name?.toLowerCase() ?? "";
  return {
    sha1: ident ? sha1Of(ctx, ident) : null, sha256: sha256 ?? null, md5: md5 ?? null,
    fileName: name ?? baseOf(path) ?? null, filePath: dirOf(path) ?? null, fileSize: size ?? null,
    filePublisher: null, signer: null, issuer: null,
  };
}

/** A process's image as the Defender records print it: canonical path, the fleet hash of a binary with no story hash. */
function imageOf(ctx: NativeCtx, p: EdrProc) {
  const name = imageName(p);
  const path = (name ? imagePath({ ...p, name }) : undefined) ?? fixPath(p.path);
  const fleet = path && /[\\/]/.test(path) ? imageHashes(ctx, path) : null;
  return fileDetails(ctx, path, name, p.sha256 ?? fleet?.sha256, p.md5 ?? (p.sha256 ? undefined : fleet?.md5), undefined);
}

// ── Evidence ────────────────────────────────────────────────────────────────

function evidenceOf(ev: TelemetryEvent, ctx: NativeCtx, f: EdrFacts, product: MicrosoftProduct, severity: string, created: string, seed: (p: string) => string): Record<string, unknown>[] {
  const entry = (type: string, fields: Record<string, unknown>, roles: string[] = []) => ({
    "@odata.type": `#microsoft.graph.security.${type}`, createdDateTime: created,
    // Documented unset values: nothing here says what the entity turned out to be.
    verdict: "unknown", remediationStatus: "none", remediationStatusDetails: null,
    roles, detailedRoles: [] as string[], tags: [] as string[], ...fields,
  });
  const out: Record<string, unknown>[] = [];
  const { account, runAs } = accountsOf(ev, ctx, f);
  const host = f.host;
  const mdeDeviceId = host ? ctx.hex(`${ctx.companyId}:${deviceKey(host)}`, 40) : null;
  // What the product did: stated alike for a true alert and a false one.
  const action = effectiveAction(ev, f);
  const detectionStatus = action === "detected" ? "detected" : "blocked";

  if (host) {
    const short = host.split(".")[0];
    const hostIp = [f.hostIp, ctx.hostIps?.get(hostKey(host)), ev.src_ip].find(ip => isPrivate(ip));
    out.push(entry("deviceEvidence", {
      mdeDeviceId,
      azureAdDeviceId: ctx.uuid(`${ctx.companyId}:entra-device:${host}`),
      deviceDnsName: host.includes(".") ? host : `${host}.${ctx.domain}`,
      hostName: short,
      ntDomain: ctx.netbios,
      dnsDomain: ctx.domain,
      osPlatform: osPlatform(host, f.os),
      healthStatus: "active",
      riskScore: severity,
      onboardingStatus: "onboarded",
      defenderAvStatus: "updated",
      ipInterfaces: hostIp ? [hostIp] : [],
      loggedOnUsers: account?.accountName ? [{ accountName: account.accountName, domainName: account.domainName }] : [],
    }));
  }
  if (account) out.push(entry("userEvidence", { userAccount: account }));
  if (account?.userPrincipalName && (product === "defender_office" || /^email_/.test(ev.event_type) || ev.source === "exchange")) {
    out.push(entry("mailboxEvidence", { displayName: account.displayName, primaryAddress: account.userPrincipalName, upn: account.userPrincipalName, userAccount: account }));
  }

  const procName = imageName(f.proc);
  const filePath = f.file.path && !/^memory:/i.test(f.file.path) ? f.file.path : undefined;
  const sameImage = !!(procName && filePath && baseOf(filePath)?.toLowerCase() === procName.toLowerCase());
  if (host && procName) {
    const scope: ProcScope = { host, os: f.os, timeMs: f.timeMs, user: f.user ?? f.userEmail?.split("@")[0] };
    const parentName = imageName(f.parent);
    const image = imageOf(ctx, f.proc);
    out.push(entry("processEvidence", {
      detectionStatus, mdeDeviceId,
      processId: procPid(ctx, scope, f.proc) ?? null,
      parentProcessId: parentName ? procPid(ctx, scope, f.parent) ?? null : null,
      processCommandLine: f.proc.cmdline ?? null,
      processCreationDateTime: isoFrac(f.proc.startMs ?? f.timeMs - 1, 7, ctx, seed("pct")),
      parentProcessCreationDateTime: f.parent.startMs ? isoFrac(f.parent.startMs, 7, ctx, seed("ppct")) : null,
      imageFile: sameImage && f.file.sha256 ? { ...image, sha256: f.proc.sha256 ?? f.file.sha256, sha1: sha1Of(ctx, f.proc.sha256 ?? f.file.sha256) } : image,
      parentProcessImageFile: parentName ? imageOf(ctx, f.parent) : null,
      userAccount: runAs,
    }));
  }
  if (!sameImage && (filePath || f.file.name || f.file.sha256)) {
    out.push(entry("fileEvidence", {
      detectionStatus, mdeDeviceId,
      fileDetails: fileDetails(ctx, filePath, f.file.name, f.file.sha256, f.file.md5, f.file.size),
    }));
  }

  const ip = (value: string | undefined, role: string) => {
    if (value && !out.some(e => e.ipAddress === value)) out.push(entry("ipEvidence", { ipAddress: value, countryLetterCode: role === "source" && /^[A-Z]{2}$/.test(ev.geo?.country ?? "") ? ev.geo!.country : null }, [role]));
  };
  ip(ev.src_ip ?? f.net.localIp, "source");
  ip(ev.dst_ip ?? f.net.remoteIp, "destination");
  for (const url of new Set([f.net.url, ev.network?.url, f.net.domain, ev.network?.domain, f.dns.query, ev.dns?.query])) {
    if (url) out.push(entry("urlEvidence", { url }));
  }

  if (product === "defender_office") {
    const message = analyzedMessage(ev, ctx);
    if (message) {
      for (const url of message.urls) if (!out.some(e => e.url === url)) out.push(entry("urlEvidence", { url }));
      for (const a of message.attachments) {
        out.push(entry("fileEvidence", { detectionStatus, mdeDeviceId: null, fileDetails: fileDetails(ctx, undefined, a.name, a.sha256, undefined, a.size) }));
      }
      out.push(entry("analyzedMessageEvidence", message.evidence));
    }
  }
  return out;
}

/** The message of an email alert: the EmailEvents row of the same event and its URL and attachment rows, in Graph's terms. */
function analyzedMessage(ev: TelemetryEvent, ctx: NativeCtx) {
  const log = defenderO365.fromTelemetry(ev, ctx);
  const m = (log?.record as { properties?: Record<string, unknown> } | undefined)?.properties;
  if (log?.kind !== "EmailEvents" || !m) return null;
  const rows = (table: string) => (defenderO365.companions?.(ev, ctx) ?? []).filter(l => l.kind === table).map(l => (l.record as { properties: Record<string, unknown> }).properties);
  const text = (k: string) => (typeof m[k] === "string" && m[k] ? (m[k] as string) : null);
  const list = (k: string) => (text(k) ?? "").split(/\s*,\s*/).filter(Boolean);
  const sender = (from: string | null, domain: string | null) => ({ emailAddress: from, displayName: text("SenderDisplayName"), domainName: domain });
  const urls = [...new Set(rows("EmailUrlInfo").map(r => r.Url).filter((u): u is string => typeof u === "string" && !!u))];
  const attachments = rows("EmailAttachmentInfo").map(r => ({ name: r.FileName as string | undefined, sha256: r.SHA256 as string | undefined, size: r.FileSize as number | undefined }));
  return {
    urls, attachments,
    evidence: {
      networkMessageId: text("NetworkMessageId"), internetMessageId: text("InternetMessageId"), subject: text("Subject"), language: "en",
      senderIp: text("SenderIPv4"), recipientEmailAddress: text("RecipientEmailAddress"),
      antiSpamDirection: (text("EmailDirection") ?? "inbound").toLowerCase().replace("-", ""),
      deliveryAction: (text("DeliveryAction") ?? "delivered").toLowerCase(),
      deliveryLocation: LOCATION[text("DeliveryLocation") ?? ""] ?? "inbox",
      urn: null, threats: list("ThreatTypes"), threatDetectionMethods: list("DetectionMethods"), urls,
      urlCount: urls.length, attachmentsCount: attachments.length, receivedDateTime: text("Timestamp"),
      p1Sender: sender(text("SenderMailFromAddress"), text("SenderMailFromDomain")), p2Sender: sender(text("SenderFromAddress"), text("SenderFromDomain")),
    },
  };
}

// ── Conversion ──────────────────────────────────────────────────────────────

function fromTelemetry(input: TelemetryEvent, ctx: NativeCtx): NativeLog | null {
  const ev = publicOf(input);
  const product = microsoftProductOf(ev, MICROSOFT_STACK);
  if (!product) return null;
  const f = edrFacts(ev);
  const timeMs = Date.parse(ev.ts);
  const seed = (p: string) => `${ev.id}:ms-graph:${p}`;
  const facts = PRODUCTS[product];

  // A Defender for Endpoint alert is the alert its AlertEvidence row names: one id, title, severity and category.
  const evidenceRow = product === "defender_endpoint" ? mde.fromTelemetry(ev, ctx) : null;
  const row = evidenceRow?.kind === "AlertEvidence" ? (evidenceRow.record as { properties: Record<string, unknown> }).properties : undefined;

  const id = typeof row?.AlertId === "string" ? row.AlertId
    : `da${ctx.int(`${ev.id}:mde:alert:a`, 100_000_000, 999_999_999)}${ctx.int(`${ev.id}:mde:alert:b`, 100_000_000, 999_999_999)}_${ctx.int(`${ev.id}:mde:alert:c`, -2_147_483_648, 2_147_483_647)}`;
  const incidentId = String(1_000 + parseInt(ctx.hex(seed("incident"), 8), 16) % 99_999_000);
  const title = titleOf(ev, row);
  const severity = SEVERITY[String(row?.Severity ?? ev.severity ?? "medium").toLowerCase()] ?? "medium";
  let category = categoryOf(ev, f);
  if (row) { try { category = (JSON.parse(String(row.Categories ?? "[]")) as string[])[0] ?? category; } catch { /* keep */ } }

  const serviceSource = facts.serviceSource;
  const detectionSource = product === "sentinel" ? sentinelDetection(ev)
    : product === "defender_endpoint" && (row?.DetectionSource === "Antivirus" || ev.source === "av") ? "antivirus" : facts.detectionSource;
  const createdMs = timeMs + ctx.int(seed("lag"), 1_000, 6_000);
  const created = isoFrac(createdMs, 7, ctx, seed("created"));
  const family = typeof row?.ThreatFamily === "string" ? row.ThreatFamily : null;
  const defenderThreat = f.detection?.name && /^[A-Za-z]+:[A-Za-z0-9]+\//.test(f.detection.name) ? f.detection.name : null;
  const tenant = ctx.tenant.azureTenantId;

  const alert: Record<string, unknown> = {
    "@odata.type": "#microsoft.graph.security.alert",
    id,
    providerAlertId: id,
    incidentId,
    status: "new",
    severity,
    classification: "unknown",
    determination: "unknown",
    serviceSource,
    detectionSource,
    productName: facts.productName,
    detectorId: ctx.uuid(`global:ms-graph-detector:${serviceSource}:${title}`),
    tenantId: tenant,
    title,
    description: facts.description,
    recommendedActions: facts.recommendedActions,
    category,
    categories: [category],
    assignedTo: null,
    alertWebUrl: `https://security.microsoft.com/alerts/${id}?tid=${tenant}`,
    incidentWebUrl: `https://security.microsoft.com/incidents/${incidentId}?tid=${tenant}`,
    actorDisplayName: null,
    threatDisplayName: defenderThreat ?? family,
    threatFamilyName: family,
    resource: "security",
    relationship: "alerts_v2",
    // The technique the product tags on the row, as the feed row itself shows it (mitreVisible).
    mitreTechniques: ev.mitre_technique ? [ev.mitre_technique] : [],
    createdDateTime: created,
    lastUpdateDateTime: isoFrac(createdMs + ctx.int(seed("update"), 200, 900), 7, ctx, seed("updated")),
    resolvedDateTime: null,
    firstActivityDateTime: isoFrac(timeMs, 3, ctx, seed("first")),
    lastActivityDateTime: isoFrac(timeMs, 3, ctx, seed("last")),
    alertPolicyId: null,
    investigationState: "unknown",
    additionalData: {},
    customDetails: {},
    comments: [],
    evidence: evidenceOf(ev, ctx, f, product, severity, created, seed),
    systemTags: [],
  };

  return {
    sourceId: "ms_graph", kind: "alerts_v2", format: "json", timeMs,
    record: {
      timestamp: new Date(createdMs + ctx.int(seed("poll"), 2_000, 9_000)).toISOString().replace("Z", "+0000"),
      decoder: { name: "json-msgraph" },
      data: { integration: "ms-graph", "ms-graph": alert },
    },
  };
}

// ── Use cases (Wazuh dashboard DQL over data.ms-graph.*, and the Graph filter behind them) ──

const useCases: UseCase[] = [
  {
    id: "ms_graph.new-high-severity-alert",
    title: "New high-severity alert from a Microsoft product",
    sourceId: "ms_graph", kinds: ["alerts_v2"], severity: "high", mitre: [],
    description: "A Microsoft product raised a high-severity alert that nobody has triaged. Graph has no critical severity, so high is the top of the queue. The alert says what the product saw, not what happened: open the raw logs of its evidence before judging it.",
    logic: "// Wazuh DQL\ndata.integration: \"ms-graph\" and data.ms-graph.relationship: \"alerts_v2\" and data.ms-graph.status: \"new\" and data.ms-graph.severity: \"high\"\n\n// Microsoft Graph\nGET /security/alerts_v2?$filter=status eq 'new' and severity eq 'high'",
    match: { all: [{ field: "data.ms-graph.status", op: "eq", value: "new" }, { field: "data.ms-graph.severity", op: "eq", value: "high" }] },
    falsePositives: ["Sanctioned security testing and known test files", "A second alert for activity a case already covers"],
  },
  {
    id: "ms_graph.credential-access-alert",
    title: "Alert in the Credential Access category",
    sourceId: "ms_graph", kinds: ["alerts_v2"], severity: "high", mitre: ["T1003", "T1555", "T1539"],
    description: "Any Microsoft product reporting credential theft: LSASS access, browser credential stores, stolen session cookies. A stolen credential works from anywhere, so check the account's sign-ins even when the process on the device was stopped.",
    logic: "// Wazuh DQL\ndata.integration: \"ms-graph\" and data.ms-graph.category: \"CredentialAccess\"",
    match: { field: "data.ms-graph.category", op: "eq", value: "CredentialAccess" },
    falsePositives: ["Authorised penetration tests", "Password managers and backup agents reading credential stores"],
  },
  {
    id: "ms_graph.identity-protection-alert",
    title: "Entra ID Protection alert",
    sourceId: "ms_graph", kinds: ["alerts_v2"], severity: "medium", mitre: ["T1078.004"],
    description: "Entra ID Protection flagged a sign-in or an account. Pivot on the userEvidence entry to the sign-in logs: the raw sign-in shows the client, the location and whether MFA was really completed.",
    logic: "// Wazuh DQL\ndata.integration: \"ms-graph\" and data.ms-graph.serviceSource: \"azureAdIdentityProtection\"\n\n// Microsoft Graph\nGET /security/alerts_v2?$filter=serviceSource eq 'azureAdIdentityProtection'",
    match: { field: "data.ms-graph.serviceSource", op: "eq", value: "azureAdIdentityProtection" },
    falsePositives: ["Business travel and new corporate VPN egress addresses"],
  },
  {
    id: "ms_graph.dlp-policy-alert",
    title: "Purview DLP policy alert",
    sourceId: "ms_graph", kinds: ["alerts_v2"], severity: "medium", mitre: ["T1567.002"],
    description: "A Purview Data Loss Prevention policy matched. The alert names the policy; the destination and the content are in the audit record behind it.",
    logic: "// Wazuh DQL\ndata.integration: \"ms-graph\" and data.ms-graph.serviceSource: \"dataLossPrevention\"",
    match: { field: "data.ms-graph.serviceSource", op: "eq", value: "dataLossPrevention" },
    falsePositives: ["Approved transfers to a partner the policy does not exempt yet"],
  },
  {
    id: "ms_graph.antivirus-detection",
    title: "Defender Antivirus detection",
    sourceId: "ms_graph", kinds: ["alerts_v2"], severity: "low", mitre: ["T1204.002"],
    description: "The detection came from the antivirus engine, not from behaviour analysis (detectionSource antivirus). Check whether the process evidence says detected or blocked: a detected file may still have run.",
    logic: "// Wazuh DQL\ndata.integration: \"ms-graph\" and data.ms-graph.detectionSource: \"antivirus\"",
    match: { field: "data.ms-graph.detectionSource", op: "eq", value: "antivirus" },
    falsePositives: ["EICAR test files", "Admin tools classified as potentially unwanted software"],
  },
  {
    id: "ms_graph.repeated-alerts-one-category",
    title: "Three alerts in one category within an hour",
    sourceId: "ms_graph", kinds: ["alerts_v2"], severity: "medium", mitre: [],
    description: "Three different alerts of one attack stage in an hour. One product noticing one thing is an alert; several detectors agreeing is a pattern worth a case. Compare their evidence entries for a shared device or account.",
    logic: "// Wazuh DQL, then group in the dashboard\ndata.integration: \"ms-graph\" and data.ms-graph.status: \"new\"\n| stats dc(data.ms-graph.title) by data.ms-graph.category span=1h\n| where dc >= 3",
    match: { field: "data.ms-graph.status", op: "eq", value: "new" },
    threshold: { groupBy: ["data.ms-graph.category"], count: 3, windowSec: 3600, distinct: "data.ms-graph.title" },
    falsePositives: ["Mass rollout of an admin tool", "A red-team exercise"],
  },
];

export const source: NativeSource = {
  schema: {
    sourceId: "ms_graph",
    category: "detection_feed",
    card: "siem-ms-graph-alerts.md",
    product: "Microsoft Graph Security",
    format: "json",
    vendorMatch: ["microsoft", "defender", "entra", "azure ad", "azure active directory", "purview"],
    telemetrySources: ["edr", "av", "o365", "exchange", "sharepoint", "email_gateway", "okta", "mfa", "iam", "cloud_azure", "dlp", "ad", "siem", "ueba"],
    kinds: { alerts_v2: ALERTS_V2 },
  },
  fromTelemetry,
  useCases,
};
