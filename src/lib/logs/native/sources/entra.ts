/**
 * Microsoft Entra ID — native module (card: docs/log-schemas/idp-entra-id.md).
 *
 * Shapes: Graph **beta `signIn`** (kind "signIn") and Graph **v1.0
 * `directoryAudit`** (kind "directoryAudit"), one object per event, no
 * `{"value":[…]}` wrapper and no Azure Monitor envelope.
 *
 * Renders Entra-authored events AND other IdPs' events (Okta) where Entra has a
 * true equivalent record: an Okta login → an Entra interactive sign-in, an Okta
 * Verify push deny → a 500121 sign-in, an Okta lockout → a 50053 sign-in, an Okta
 * factor enrollment → "User registered security info", an Okta admin-privilege
 * grant → "Add member to role". Okta records with no Entra counterpart (push
 * sent, API token, rate-limit, logout, app assignment) return null.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { NativeCtx, NativeLog, NativeSource, SourceSchema, UseCase } from "../types";
import {
  asnOf, b62, geoOf, identityFacts, isoFrac, isPrivateIp, nameFromLogin, rawAny, rawStr, rawWithPrefix, uaOf,
  type IdFacts, type MfaMethod,
} from "./_identity-common";

// ── schema ───────────────────────────────────────────────────────────────────

const SIGNIN_REQUIRED = [
  "id", "createdDateTime", "userDisplayName", "userPrincipalName", "userId", "appId", "appDisplayName", "ipAddress", "clientAppUsed",
  "correlationId", "conditionalAccessStatus", "isInteractive", "riskDetail", "riskLevelAggregated", "riskLevelDuringSignIn", "riskState",
  "resourceDisplayName", "resourceId", "status.errorCode", "status.failureReason", "status.additionalDetails",
  "deviceDetail.deviceId", "deviceDetail.displayName", "deviceDetail.operatingSystem", "deviceDetail.browser", "deviceDetail.isCompliant",
  "deviceDetail.isManaged", "deviceDetail.trustType", "location.city", "location.state", "location.countryOrRegion",
];
const SIGNIN_OPTIONAL = [
  "userType", "autonomousSystemNumber", "userAgent", "originalRequestId", "signInEventTypes", "authenticationProtocol", "incomingTokenType",
  "authenticationRequirement", "authenticationMethodsUsed", "tokenIssuerName", "tokenIssuerType", "processingTimeInMilliseconds",
  "riskEventTypes_v2", "resourceTenantId", "homeTenantId", "homeTenantName", "signInIdentifier", "signInIdentifierType",
  "servicePrincipalId", "servicePrincipalName", "servicePrincipalCredentialKeyId", "clientCredentialType", "sessionId", "uniqueTokenIdentifier",
  "crossTenantAccessType", "flaggedForReview", "isTenantRestricted",
  "location.geoCoordinates", "location.geoCoordinates.altitude", "location.geoCoordinates.latitude", "location.geoCoordinates.longitude",
  // Arrays: the bare path is needed for the (common) empty array; element keys listed for documentation.
  "appliedConditionalAccessPolicies", "appliedConditionalAccessPolicies[].id", "appliedConditionalAccessPolicies[].displayName",
  "appliedConditionalAccessPolicies[].enforcedGrantControls", "appliedConditionalAccessPolicies[].enforcedSessionControls",
  "appliedConditionalAccessPolicies[].result", "appliedConditionalAccessPolicies[].conditionsSatisfied", "appliedConditionalAccessPolicies[].conditionsNotSatisfied",
  "appliedConditionalAccessPolicies[].includeRulesSatisfied", "appliedConditionalAccessPolicies[].excludeRulesSatisfied",
  "authenticationProcessingDetails", "authenticationProcessingDetails[].key", "authenticationProcessingDetails[].value",
  "networkLocationDetails", "networkLocationDetails[].networkType", "networkLocationDetails[].networkNames",
  "authenticationDetails", "authenticationDetails[].authenticationStepDateTime", "authenticationDetails[].authenticationMethod",
  "authenticationDetails[].authenticationMethodDetail", "authenticationDetails[].succeeded", "authenticationDetails[].authenticationStepResultDetail",
  "authenticationDetails[].authenticationStepRequirement",
  // UNVERIFIED element shape (card 4.3 note) — kept because the card's samples carry it.
  "authenticationRequirementPolicies", "authenticationRequirementPolicies[].requirementProvider", "authenticationRequirementPolicies[].detail",
  "sessionLifetimePolicies",
];
const AUDIT_REQUIRED = ["id", "category", "correlationId", "result", "resultReason", "activityDisplayName", "activityDateTime", "loggedByService", "operationType", "initiatedBy", "targetResources"];
const AUDIT_OPTIONAL = [
  "initiatedBy.user", "initiatedBy.user.id", "initiatedBy.user.displayName", "initiatedBy.user.userPrincipalName", "initiatedBy.user.ipAddress",
  "initiatedBy.app", "initiatedBy.app.appId", "initiatedBy.app.displayName", "initiatedBy.app.servicePrincipalId", "initiatedBy.app.servicePrincipalName",
  "targetResources[].id", "targetResources[].displayName", "targetResources[].type", "targetResources[].userPrincipalName", "targetResources[].groupType",
  "targetResources[].modifiedProperties", "targetResources[].modifiedProperties[].displayName", "targetResources[].modifiedProperties[].oldValue",
  "targetResources[].modifiedProperties[].newValue",
  "additionalDetails", "additionalDetails[].key", "additionalDetails[].value",
];

const schema: SourceSchema = {
  sourceId: "entra",
  category: "idp",
  card: "idp-entra-id.md",
  product: "Microsoft Entra ID",
  format: "json",
  vendorMatch: ["entra", "azure ad", "azure active directory"],
  telemetrySources: ["o365", "cloud_azure", "iam", "mfa", "okta"],
  kinds: {
    signIn: { required: SIGNIN_REQUIRED, optional: SIGNIN_OPTIONAL },
    // The two "initiatedBy" branches are documented as object-or-null; the bare paths cover null.
    directoryAudit: { required: AUDIT_REQUIRED, optional: AUDIT_OPTIONAL },
  },
};

/** Classify a native Entra record (used to validate card samples). */
export function kindOf(record: Record<string, unknown>): string | null {
  if ("properties" in record || "operationName" in record || "resultType" in record) return null; // Azure Monitor envelope — not the platform standard
  if ("activityDisplayName" in record && "targetResources" in record) return "directoryAudit";
  if ("createdDateTime" in record && "userPrincipalName" in record) return "signIn";
  return null;
}

// ── reference data ───────────────────────────────────────────────────────────

const APPS: Record<string, string> = {
  "Microsoft Office": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
  "OfficeHome": "4765445b-32c6-49b0-83e6-1d93765276ca",
  "Azure Portal": "c44b4083-3bb0-49c1-b47d-974e53cbdf3c",
  "Microsoft Authentication Broker": "29d9ed98-a469-4536-ade2-f981bc1d605e",
  "Office 365 Exchange Online": "00000002-0000-0ff1-ce00-000000000000",
  "Office 365 SharePoint Online": "00000003-0000-0ff1-ce00-000000000000",
  "Microsoft Graph": "00000003-0000-0000-c000-000000000000",
  "Windows Azure Service Management API": "797f4846-ba00-4fd7-ba43-dac1f8f63013",
  "Microsoft Teams": "1fec8e78-bce4-4aaf-ab1b-5451cc387264",
  "One Outlook Web": "9199bf20-a13f-4107-85dc-02114787ef48",
};
const APP_ALIASES: Record<string, string> = {
  "microsoft 365": "OfficeHome", "office 365": "OfficeHome", "exchange online": "Office 365 Exchange Online", "sharepoint online": "Office 365 SharePoint Online",
  "outlook": "Office 365 Exchange Online", "owa": "One Outlook Web", "azure portal": "Azure Portal", "teams": "Microsoft Teams",
};
const ROLE_TEMPLATES: Record<string, string> = {
  "Global Administrator": "62e90394-69f5-4237-9190-012177145e10",
  "Privileged Role Administrator": "e8611ab8-c189-46e8-94e1-60213ab1f814",
  "Helpdesk Administrator": "729827e3-9c14-49f7-bb1b-9608f156bbb8",
  "Authentication Administrator": "c4e39bd9-1100-46d3-8c65-fb160da0071f",
  "Application Administrator": "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
  "Security Administrator": "194ae4cb-b126-40b2-bd5b-6091b380977d",
  "User Administrator": "fe930be7-5e62-47db-91af-98c3a49a38b1",
  "Exchange Administrator": "29232cdf-9323-42fd-ade2-1d097af3e4de",
};
const STATUS: Record<number, [string, string | null]> = {
  0: ["Other.", null],
  50126: ["Error validating credentials due to invalid username or password.", "The user didn't enter the right credentials. It's expected to see some number of these errors in your logs due to users making mistakes."],
  50053: ["Account is locked because user tried to sign in too many times with an incorrect user ID or password.", null],
  50034: ["The user account does not exist in the directory.", null],
  50057: ["User account is disabled.", "The account has been disabled by an administrator."],
  50055: ["The password is expired.", null],
  50074: ["Strong Authentication is required.", "This is an expected part of the login flow, where a user is asked if they want to set up MFA."],
  50076: ["Due to a configuration change made by your administrator, or because you moved to a new location, you must use multi-factor authentication to access the resource.", null],
  50072: ["User needs to enroll for second factor authentication (interrupt)", null],
  500121: ["Authentication failed during strong authentication request.", "The user didn't complete the MFA prompt. They may have decided not to authenticate, timed out while doing other work, or has an issue with their authentication setup."],
  53003: ["Access has been blocked by Conditional Access policies. The access policy does not allow token issuance.", null],
};
const CODE_FOR: Record<string, number> = {
  bad_password: 50126, locked: 50053, malicious_ip: 50053, no_user: 50034, disabled: 50057, expired: 50055,
  mfa_required: 50074, mfa_registration: 50072, mfa_denied: 500121, ca_block: 53003, other: 50126,
};
const LEGACY_CLIENTS = ["Exchange ActiveSync", "IMAP4", "POP3", "Authenticated SMTP", "MAPI Over HTTP", "Exchange Web Services", "Other clients"];
const MFA_METHOD: Record<MfaMethod, { step: string; used: string; detail: string }> = {
  push: { step: "Mobile app notification", used: "Authenticator App", detail: "Microsoft Authenticator" },
  totp: { step: "Software OATH token", used: "Software OATH token", detail: "Authenticator app code" },
  sms: { step: "SMS", used: "SMS", detail: "+X XXXXXXXX54" },
  voice: { step: "Voice", used: "Voice", detail: "+X XXXXXXXX54" },
  fido: { step: "FIDO2 security key", used: "FIDO", detail: "YubiKey 5 NFC" },
  token: { step: "Previously satisfied", used: "Password", detail: "" },
};

// ── helpers ──────────────────────────────────────────────────────────────────

const userId = (ctx: NativeCtx, upn: string) => ctx.uuid(`${ctx.companyId}:entra-user:${upn}`);
const graphId = (ctx: NativeCtx, seed: string) => { const u = ctx.uuid(seed); return `${u.slice(0, -4)}${u.slice(-4, -2)}00`; };

function appOf(ctx: NativeCtx, name?: string): { appId: string; appDisplayName: string } {
  const n = name ? (APPS[name] ? name : APP_ALIASES[name.toLowerCase()] ?? name) : "OfficeHome";
  return { appId: APPS[n] ?? ctx.uuid(`${ctx.companyId}:entra-app:${n}`), appDisplayName: n };
}
function resourceOf(ctx: NativeCtx, app: string, raw?: string): { resourceId: string; resourceDisplayName: string } {
  const n = raw && raw !== "Microsoft 365" ? (APPS[raw] ? raw : APP_ALIASES[raw.toLowerCase()] ?? raw) :
    app === "Azure Portal" ? "Windows Azure Service Management API" : app === "Microsoft Office" ? "Microsoft Graph" :
      app === "One Outlook Web" ? "Office 365 Exchange Online" : app;
  return { resourceId: APPS[n] ?? ctx.uuid(`${ctx.companyId}:entra-app:${n}`), resourceDisplayName: n };
}
/** Primary UPN: facts → legacy Windows-shaped raw on Entra-labelled events → null (Entra always logs a UPN). */
function upnOf(ev: TelemetryEvent, ctx: NativeCtx, f: IdFacts): string | undefined {
  if (f.email) return f.email.includes("@") ? f.email : `${f.email}@${ctx.domain}`;
  const sam = rawStr(ev, "winlog.event_data.TargetUserName", "target.user.name");
  return sam ? `${sam.toLowerCase()}@${ctx.domain}` : undefined;
}
const jsonStr = (v: string) => JSON.stringify(v);

// ── signIn ───────────────────────────────────────────────────────────────────

function renderSignIn(ev: TelemetryEvent, ctx: NativeCtx, f: IdFacts, upn: string, opts: { code: number; interactive?: boolean; appName?: string }): NativeLog {
  const p = rawWithPrefix(ev, "azure.signinlogs.properties.");
  const ip = f.ip ?? "";
  const geo = geoOf(ev, ctx, ip);
  const asn = asnOf(ev, geo, ip);
  const ua = uaOf(ev);
  const code = opts.code;
  const ok = code === 0;
  const interactive = opts.interactive ?? f.interactive;
  const legacyRaw = rawStr(ev, "azure.signinlogs.properties.clientAppUsed", "azure.signinlogs.client_app_used", "azure.clientAppUsed", "azure.client_app");
  const clientAppUsed = legacyRaw && (legacyRaw === "Browser" || legacyRaw === "Mobile Apps and Desktop clients" || LEGACY_CLIENTS.includes(legacyRaw)) ? legacyRaw :
    ua.scripted ? "Mobile Apps and Desktop clients" : "Browser";
  const legacy = LEGACY_CLIENTS.includes(clientAppUsed);
  const protocol = rawStr(ev, "azure.signinlogs.properties.authenticationProtocol") ?? (legacy || (ua.scripted && !ok) ? "ropc" : interactive ? "oAuth2" : "none");
  const app = appOf(ctx, opts.appName ?? f.appName ?? rawStr(ev, "azure.signinlogs.properties.appDisplayName", "azure.signinlogs.app_display_name", "azure.appDisplayName"));
  const res = resourceOf(ctx, app.appDisplayName, rawStr(ev, "azure.signinlogs.properties.resourceDisplayName", "azure.signinlogs.resource_display_name"));
  const passwordOk = code !== 50126 && code !== 50034 && code !== 50057 && code !== 50053 && code !== 50055;
  const mfaReached = passwordOk && (f.mfaUsed || code === 500121 || code === 50074 || code === 50076 || code === 50072);
  const method = MFA_METHOD[f.mfaMethod ?? "push"];
  const t0 = Date.parse(ev.ts);
  const stepTime = (deltaMs: number) => isoFrac(new Date(t0 - deltaMs).toISOString(), 0);
  // Risk
  let risk = f.risk;
  let reasons = [...f.riskReasons];
  if (asn.isProxy && !reasons.includes("anonymizedIPAddress")) reasons.push("anonymizedIPAddress");
  if (reasons.length && risk === "none") risk = "medium";
  if (!reasons.length && risk !== "none") reasons = ["unfamiliarFeatures"];
  const riskDuring = (rawStr(ev, "azure.signinlogs.properties.riskLevelDuringSignIn", "azure.signinlogs.risk_level_during_signin") ?? risk).toLowerCase();
  const riskAgg = (rawStr(ev, "azure.signinlogs.properties.riskLevelAggregated", "azure.signinlogs.risk_level_aggregated", "azure.riskLevelAggregated") ?? riskDuring).toLowerCase();
  const riskState = rawStr(ev, "azure.signinlogs.properties.riskState", "azure.signinlogs.risk_state") ?? (riskDuring !== "none" || riskAgg !== "none" ? "atRisk" : "none");
  const norm = (v: string) => (["none", "low", "medium", "high", "hidden"].includes(v) ? v : v === "critical" ? "high" : "none");
  // Device
  const corp = isPrivateIp(ip) && !ua.scripted;
  const managed = f.managedDevice ?? (corp && !!ev.hostname);
  const devId = rawStr(ev, "azure.signinlogs.properties.deviceDetail.deviceId", "azure.signinlogs.device_detail.device_id");
  const deviceDetail = {
    deviceId: devId && !/not registered/i.test(devId) ? devId : managed ? ctx.uuid(`${ctx.companyId}:entra-device:${ev.hostname ?? upn}`) : "",
    displayName: rawStr(ev, "azure.signinlogs.properties.deviceDetail.displayName") ?? (managed ? ev.hostname ?? "" : ""),
    operatingSystem: rawStr(ev, "azure.signinlogs.properties.deviceDetail.operatingSystem", "azure.signinlogs.device_detail.operating_system", "azure.deviceDetail.operatingSystem") ?? ua.entraOs,
    browser: rawStr(ev, "azure.signinlogs.properties.deviceDetail.browser", "azure.signinlogs.device_detail.browser") ?? ua.entraBrowser,
    isCompliant: f.compliantDevice ?? managed,
    isManaged: managed,
    trustType: rawStr(ev, "azure.signinlogs.properties.deviceDetail.trustType") ?? (managed ? "Azure AD joined" : ""),
  };
  // Conditional Access
  const rawCa = rawStr(ev, "azure.signinlogs.properties.conditionalAccessStatus", "azure.signinlogs.conditional_access_status", "data.office365.ConditionalAccessStatus", "azure.conditional_access.status");
  const caStatus = code === 53003 || code === 500121 ? "failure" : rawCa && ["success", "failure", "notApplied"].includes(rawCa) ? rawCa : mfaReached && ok ? "success" : "notApplied";
  const rawPolicies = rawAny(ev, "azure.signinlogs.properties.appliedConditionalAccessPolicies");
  const policy = (name: string, grant: string[], result: string, satisfied: string) => ({
    id: ctx.uuid(`${ctx.companyId}:ca:${name}`), displayName: name, enforcedGrantControls: grant, enforcedSessionControls: [] as string[], result,
    conditionsSatisfied: result === "notApplied" ? "none" : satisfied, conditionsNotSatisfied: result === "notApplied" ? "application" : "none",
    includeRulesSatisfied: [] as string[], excludeRulesSatisfied: [] as string[],
  });
  const policies = Array.isArray(rawPolicies) ? rawPolicies :
    code === 53003 ? [legacy ? policy("Block legacy authentication", ["Block"], "failure", "application,users,clientType") : policy("Require compliant device", ["RequireCompliantDevice"], "failure", "application,users")] :
      mfaReached ? [policy("Require MFA - All users", ["Mfa"], ok ? "success" : code === 500121 ? "failure" : "success", "application,users")] :
        !passwordOk ? [] : [policy("Require MFA - Admin portals", [], "notApplied", "none")];
  // Authentication steps
  const rawSteps = rawAny(ev, "azure.signinlogs.properties.authenticationDetails");
  const steps: Record<string, unknown>[] = Array.isArray(rawSteps) ? rawSteps as Record<string, unknown>[] : [];
  if (!steps.length) {
    steps.push({
      authenticationStepDateTime: stepTime(mfaReached ? 18_000 : 0), authenticationMethod: "Password", authenticationMethodDetail: "Password in the cloud",
      succeeded: passwordOk, authenticationStepResultDetail: passwordOk ? "Correct password" : code === 50053 ? "Account is locked" : "Invalid username or password or Invalid on-premise username or password.",
      authenticationStepRequirement: "Primary authentication",
    });
    if (mfaReached && code !== 50074 && code !== 50076) {
      const sso = f.mfaMethod === "token" || (!interactive && ok);
      steps.push({
        authenticationStepDateTime: stepTime(0), authenticationMethod: sso ? "Previously satisfied" : method.step, authenticationMethodDetail: sso ? null : method.detail,
        succeeded: ok, authenticationStepResultDetail: sso ? "MFA requirement satisfied by claim in the token" : ok ? "MFA successfully completed" :
          code === 50072 ? "MFA registration required" : "MFA denied; user declined the authentication",
        authenticationStepRequirement: "Multifactor authentication",
      });
    }
  }
  const methodsUsed = !passwordOk ? [] : ok && mfaReached && steps.length > 1 && steps[1].authenticationMethod !== "Previously satisfied" ? ["Password", method.used] : ["Password"];
  const rawCode = p["status.errorCode"];
  const errorCode = typeof rawCode === "number" ? rawCode : code;
  const [failureReason, defaultDetails] = STATUS[errorCode] ?? [rawStr(ev, "azure.signinlogs.resultDescription", "azure.signinlogs.result_description") ?? "Other.", null];
  const sessionId = ok ? (f.sessionId ?? ctx.uuid(`${ctx.companyId}:entra-session:${upn}:${ip}:${ev.ts.slice(0, 10)}`)) : "";
  const id = rawStr(ev, "azure.signinlogs.properties.id") ?? graphId(ctx, `${ev.id}:signin`);
  const record: Record<string, unknown> = {
    id,
    createdDateTime: isoFrac(ev.ts, 0),
    userDisplayName: f.displayName ?? nameFromLogin(upn),
    userPrincipalName: upn,
    userId: userId(ctx, upn),
    userType: upn.includes("#ext#") ? "guest" : "member",
    appId: app.appId,
    appDisplayName: app.appDisplayName,
    ipAddress: ip,
    ...(asn.asn !== null ? { autonomousSystemNumber: asn.asn } : {}),
    clientAppUsed,
    userAgent: ua.raw,
    correlationId: f.correlationId ?? ctx.uuid(`${ev.id}:corr`),
    originalRequestId: id,
    conditionalAccessStatus: caStatus,
    isInteractive: interactive,
    signInEventTypes: [interactive ? "interactiveUser" : "nonInteractiveUser"],
    authenticationProtocol: protocol,
    incomingTokenType: rawStr(ev, "azure.signinlogs.properties.incomingTokenType") ?? "none",
    authenticationRequirement: mfaReached ? "multiFactorAuthentication" : "singleFactorAuthentication",
    authenticationMethodsUsed: methodsUsed,
    tokenIssuerName: "",
    tokenIssuerType: "AzureAD",
    processingTimeInMilliseconds: code === 500121 ? ctx.int(`${ev.id}:pt`, 30_000, 62_000) : mfaReached ? ctx.int(`${ev.id}:pt`, 9_000, 24_000) : ctx.int(`${ev.id}:pt`, 60, 260),
    riskDetail: rawStr(ev, "azure.signinlogs.properties.riskDetail", "azure.signinlogs.risk_detail") ?? "none",
    riskLevelAggregated: norm(riskAgg),
    riskLevelDuringSignIn: norm(riskDuring),
    riskState,
    riskEventTypes_v2: reasons,
    ...res,
    resourceTenantId: ctx.tenant.azureTenantId,
    homeTenantId: ctx.tenant.azureTenantId,
    homeTenantName: "",
    signInIdentifier: upn,
    signInIdentifierType: "userPrincipalName",
    servicePrincipalId: "",
    sessionId,
    uniqueTokenIdentifier: `${b62(ctx, `${ev.id}:uti`, 20)}AA`,
    crossTenantAccessType: "none",
    flaggedForReview: false,
    isTenantRestricted: false,
    status: { errorCode, failureReason, additionalDetails: ok && mfaReached ? (steps[1]?.authenticationStepResultDetail === "MFA requirement satisfied by claim in the token" ? "MFA requirement satisfied by claim in the token" : "MFA completed in Azure AD") : defaultDetails },
    deviceDetail,
    location: { city: geo.city, state: geo.state, countryOrRegion: geo.iso, geoCoordinates: { altitude: null, latitude: geo.lat, longitude: geo.lon } },
    appliedConditionalAccessPolicies: policies,
    authenticationProcessingDetails: legacy || ua.scripted ? [{ key: "Legacy TLS (TLS 1.0, 1.1, 3DES)", value: "False" }] : interactive ? [{ key: "Login Hint Present", value: "False" }] : [],
    networkLocationDetails: isPrivateIp(ip) ? [{ networkType: "trustedNamedLocation", networkNames: ["Corporate HQ"] }] : [],
    authenticationDetails: steps,
    authenticationRequirementPolicies: mfaReached ? [{ requirementProvider: "multiConditionalAccess", detail: "Conditional Access" }] : [],
    sessionLifetimePolicies: [],
  };
  return { sourceId: "entra", kind: "signIn", format: "json", record, timeMs: Date.parse(ev.ts) };
}

// ── directoryAudit ───────────────────────────────────────────────────────────

interface AuditSpec {
  activity: string; category: string; service: string; operationType: string;
  initiator: { upn: string; ip?: string } | { app: string } | null;
  targets: Record<string, unknown>[];
  resultReason?: string;
  additional?: { key: string; value: string }[];
}
function renderAudit(ev: TelemetryEvent, ctx: NativeCtx, f: IdFacts, s: AuditSpec): NativeLog {
  const corr = f.correlationId ?? ctx.uuid(`${ev.id}:audit-corr`);
  const prefix = s.service === "Authentication Methods" ? "AuthMethods" : s.service === "Conditional Access" ? "IPCGraph" : s.service === "Invited Users" ? "B2B" : "Directory";
  const id = rawStr(ev, "azure.auditlogs.properties.id") ?? `${prefix}_${corr}_${b62(ctx, `${ev.id}:aid`, 5).toUpperCase()}_${ctx.int(`${ev.id}:aid#`, 172000000, 179999999)}`;
  const ok = f.success;
  const initiatedBy = s.initiator === null ? { app: null, user: null } :
    "upn" in s.initiator ? { app: null, user: { id: userId(ctx, s.initiator.upn), displayName: null, userPrincipalName: s.initiator.upn, ipAddress: s.initiator.ip ?? "" } } :
      { app: { appId: ctx.uuid(`${ctx.companyId}:entra-app:${s.initiator.app}`), displayName: s.initiator.app, servicePrincipalId: ctx.uuid(`${ctx.companyId}:entra-sp:${s.initiator.app}`), servicePrincipalName: null }, user: null };
  const record: Record<string, unknown> = {
    id,
    category: s.category,
    correlationId: corr,
    result: ok ? "success" : "failure",
    resultReason: rawStr(ev, "azure.auditlogs.properties.resultReason", "data.office365.ResultStatusDetail") ?? s.resultReason ?? "",
    activityDisplayName: s.activity,
    activityDateTime: isoFrac(ev.ts, 7, ev.id),
    loggedByService: rawStr(ev, "azure.auditlogs.properties.loggedByService") ?? s.service,
    operationType: rawStr(ev, "azure.auditlogs.properties.operationType") ?? s.operationType,
    initiatedBy,
    targetResources: s.targets,
    additionalDetails: s.additional ?? [],
  };
  return { sourceId: "entra", kind: "directoryAudit", format: "json", record, timeMs: Date.parse(ev.ts) };
}
const userTarget = (ctx: NativeCtx, upn: string, mods: Record<string, unknown>[] = [], display: string | null = null) =>
  ({ id: userId(ctx, upn), displayName: display, type: "User", userPrincipalName: upn, groupType: null, modifiedProperties: mods });
const mod = (displayName: string, newValue: string | null, oldValue: string | null = null) => ({ displayName, oldValue, newValue });
function uaDetail(ev: TelemetryEvent): { key: string; value: string }[] {
  const v = rawStr(ev, "azure.auditlogs.properties.additionalDetails[0].value") ?? uaOf(ev).raw;
  return [{ key: "User-Agent", value: v }];
}
function rawModified(ev: TelemetryEvent): Record<string, unknown>[] {
  const out: Record<string, unknown>[] = [];
  for (let i = 0; i < 6; i++) {
    const a = `azure.auditlogs.properties.targetResources[0].modifiedProperties[${i}].`;
    const b = `data.office365.ModifiedProperties[${i}].`;
    const name = rawStr(ev, `${a}displayName`, `${b}Name`);
    if (!name) continue;
    out.push(mod(name, rawStr(ev, `${a}newValue`, `${b}NewValue`) ?? null, rawStr(ev, `${a}oldValue`, `${b}OldValue`) ?? null));
  }
  return out;
}

function auditFor(ev: TelemetryEvent, ctx: NativeCtx, f: IdFacts): NativeLog | null {
  const actor = f.email ? (f.email.includes("@") ? f.email : `${f.email}@${ctx.domain}`) : undefined;
  const ip = rawStr(ev, "azure.auditlogs.properties.initiatedBy.user.ipAddress", "data.office365.ActorIpAddress", "data.office365.ClientIP") ?? f.ip;
  const me = actor ? { upn: actor, ip } : null;
  switch (f.action) {
    case "factor_enroll": {
      if (!actor) return null;
      const viaOktaDevice = f.deviceName ? ` (${f.deviceName})` : "";
      return renderAudit(ev, ctx, f, { activity: "User registered security info", category: "UserManagement", service: "Authentication Methods", operationType: "Add",
        initiator: me, targets: [userTarget(ctx, actor, [], f.displayName ?? nameFromLogin(actor))],
        resultReason: f.mfaMethod === "totp" ? "User registered Software OATH token" : `User registered Authenticator App with Notification and Code${viaOktaDevice}` });
    }
    case "factor_reset": case "factor_deactivate": {
      const target = f.targetEmail ?? actor;
      if (!target || !actor) return null;
      const native = f.nativeName === "Admin deleted security info" || f.nativeName === "Update user" ? f.nativeName : "Update user";
      const mods = rawModified(ev);
      return renderAudit(ev, ctx, f, { activity: native, category: "UserManagement", service: native === "Update user" ? "Core Directory" : "Authentication Methods",
        operationType: "Update", initiator: me,
        targets: [userTarget(ctx, target, mods.length ? mods : [mod("StrongAuthenticationMethod", "[]", JSON.stringify([{ MethodType: "PhoneAppNotification", Default: true }]))])],
        additional: uaDetail(ev) });
    }
    case "role_grant": {
      const target = f.targetEmail ?? actor;
      if (!target || !actor) return null;
      const role = !f.roleName || /super|org(anization)? admin/i.test(f.roleName) ? "Global Administrator" : f.roleName;
      const tpl = ROLE_TEMPLATES[role] ?? ctx.uuid(`role-template:${role}`);
      const mods = [mod("Role.ObjectID", jsonStr(ctx.uuid(`${ctx.companyId}:role:${role}`))), mod("Role.DisplayName", jsonStr(role)), mod("Role.TemplateId", jsonStr(tpl))];
      if (role === "Global Administrator") mods.push(mod("Role.WellKnownObjectName", jsonStr("TenantAdmins")));
      return renderAudit(ev, ctx, f, { activity: "Add member to role", category: "RoleManagement", service: "Core Directory", operationType: "Assign",
        initiator: me, targets: [userTarget(ctx, target, mods)] });
    }
    case "group_add": {
      const target = f.targetEmail ?? actor;
      if (!target || !actor) return null;
      const group = f.groupName ?? "Security Group";
      const gid = ctx.uuid(`${ctx.companyId}:group:${group}`);
      return renderAudit(ev, ctx, f, { activity: "Add member to group", category: "GroupManagement", service: "Core Directory", operationType: "Assign", initiator: me,
        targets: [userTarget(ctx, target, [mod("Group.ObjectID", jsonStr(gid)), mod("Group.DisplayName", jsonStr(group))]),
          { id: gid, displayName: null, type: "Group", userPrincipalName: null, groupType: "unknownFutureValue", modifiedProperties: [] }] });
    }
    case "consent": {
      const app = f.appName ?? "Unknown application";
      const appId = rawStr(ev, "application.id", "oauth.app.id", "data.office365.Target[0].ID") ?? ctx.uuid(`${ctx.companyId}:entra-app:${app}`);
      const sp = ctx.uuid(`${ctx.companyId}:entra-sp:${app}`);
      const allPrincipals = f.targetName === "AllPrincipals";
      const principal = actor ? userId(ctx, actor) : "";
      const scopes = f.scopes ?? "";
      const perm = `[] => [[Id: ${b62(ctx, `${ev.id}:grant`, 43)}, ClientId: ${sp}, PrincipalId: ${allPrincipals ? "" : principal}, ResourceId: ${ctx.uuid(`${ctx.companyId}:entra-sp:Microsoft Graph`)}, ConsentType: ${allPrincipals ? "AllPrincipals" : "Principal"}, Scope: ${scopes}, CreatedDateTime: , LastModifiedDateTime ]]; `;
      return renderAudit(ev, ctx, f, { activity: "Consent to application", category: "ApplicationManagement", service: "Core Directory", operationType: "Assign",
        initiator: me ?? { app }, targets: [{ id: sp, displayName: app, type: "ServicePrincipal", userPrincipalName: null, groupType: null, modifiedProperties: [
          mod("ConsentContext.IsAdminConsent", jsonStr(allPrincipals ? "True" : "False")), mod("ConsentContext.IsAppOnly", jsonStr("False")),
          mod("ConsentContext.OnBehalfOfAll", jsonStr(allPrincipals ? "True" : "False")), mod("ConsentContext.Tags", jsonStr("WindowsAzureActiveDirectoryIntegratedApp")),
          mod("ConsentAction.Permissions", jsonStr(perm)), mod("TargetId.ServicePrincipalNames", jsonStr(appId)),
        ] }], additional: [...uaDetail(ev), { key: "AppId", value: appId }] });
    }
    case "app_register": {
      if (!actor) return null;
      const app = f.appName ?? "Unnamed application";
      const appId = rawStr(ev, "application.id", "oauth.app.id", "azure.auditlogs.target_resources.id") ?? ctx.uuid(`${ctx.companyId}:entra-app:${app}`);
      const redirect = rawStr(ev, "oauth.app.redirect_uris");
      const mods = [mod("AppId", JSON.stringify([appId])), mod("DisplayName", JSON.stringify([app])), mod("AvailableToOtherTenants", JSON.stringify([true]))];
      if (redirect) mods.push(mod("AppAddress", JSON.stringify([{ AddressType: 0, Address: redirect, ReplyAddressClientType: 1, ReplyAddressIndex: null, IsReplyAddressDefault: false }])));
      return renderAudit(ev, ctx, f, { activity: "Add application", category: "ApplicationManagement", service: "Core Directory", operationType: "Add", initiator: me,
        targets: [{ id: ctx.uuid(`${ctx.companyId}:entra-appobj:${app}`), displayName: app, type: "Application", userPrincipalName: null, groupType: null, modifiedProperties: mods }],
        additional: uaDetail(ev) });
    }
    case "password_reset": {
      const target = f.targetEmail ?? actor;
      if (!target) return null;
      const name = f.nativeName ?? "Reset password";
      return renderAudit(ev, ctx, f, { activity: name, category: "UserManagement", service: name === "Reset password (by admin)" ? "Self-service Password Management" : "Core Directory",
        operationType: "Update", initiator: actor ? me : null, targets: [userTarget(ctx, target)] });
    }
    case "password_change": {
      if (!actor) return null;
      return renderAudit(ev, ctx, f, { activity: "Change user password", category: "UserManagement", service: "Core Directory", operationType: "Update", initiator: me, targets: [userTarget(ctx, actor)] });
    }
    case "ca_policy_update": {
      const name = f.targetName ?? "Conditional Access policy";
      return renderAudit(ev, ctx, f, { activity: "Update conditional access policy", category: "Policy", service: "Conditional Access", operationType: "Update",
        initiator: me, targets: [{ id: ctx.uuid(`${ctx.companyId}:ca:${name}`), displayName: name, type: "Policy", userPrincipalName: null, groupType: null, modifiedProperties: rawModified(ev) }] });
    }
    case "guest_invite": {
      if (!actor) return null;
      const guest = f.targetEmail ?? "guest#EXT#@" + ctx.domain;
      return renderAudit(ev, ctx, f, { activity: "Invite external user", category: "UserManagement", service: "Invited Users", operationType: "Add", initiator: me,
        targets: [{ id: ctx.uuid(`${ctx.companyId}:guest:${guest}`), displayName: null, type: "User", userPrincipalName: guest, groupType: null, modifiedProperties: rawModified(ev) }] });
    }
    default: return null;
  }
}

// ── conversion ───────────────────────────────────────────────────────────────

function fromTelemetry(ev: TelemetryEvent, ctx: NativeCtx): NativeLog | null {
  // CyberArk (and any other PAM) "iam" records are not identity-provider events.
  if (/cyberark|beyondtrust|delinea|thycotic/i.test(ev.vendor ?? "")) return null;
  const f = identityFacts(ev);
  if (!f) return null;
  switch (f.action) {
    case "signin": case "mfa": {
      const upn = upnOf(ev, ctx, f);
      if (!upn) return null; // Entra never writes a sign-in without the attempted UPN.
      const code = f.errorCode ?? (f.success ? 0 : CODE_FOR[f.failure ?? "bad_password"]);
      return renderSignIn(ev, ctx, f, upn, { code });
    }
    case "lockout": {
      const upn = upnOf(ev, ctx, f);
      return upn ? renderSignIn(ev, ctx, f, upn, { code: 50053 }) : null;
    }
    case "policy": {
      const upn = upnOf(ev, ctx, f);
      if (!upn) return null;
      if (f.decision === "DENY") return renderSignIn(ev, ctx, f, upn, { code: 53003 });
      if (f.decision === "CHALLENGE") return renderSignIn(ev, ctx, { ...f, mfaUsed: true }, upn, { code: 50074 });
      return null; // an ALLOW evaluation is part of the following sign-in record, not a record of its own
    }
    case "threat": {
      // Entra blocks a known-malicious IP with sign-in error 50053; a log-only ThreatInsight hit has no Entra record.
      const upn = upnOf(ev, ctx, f);
      return f.decision === "DENY" && upn ? renderSignIn(ev, ctx, { ...f, riskReasons: ["maliciousIPAddress"], risk: "high" }, upn, { code: 50053 }) : null;
    }
    case "token_grant": case "sso": {
      const upn = upnOf(ev, ctx, f);
      return upn ? renderSignIn(ev, ctx, { ...f, mfaUsed: true, mfaMethod: "token" }, upn, { code: 0, interactive: f.action === "sso", appName: f.appName }) : null;
    }
    case "factor_enroll": case "factor_reset": case "factor_deactivate": case "role_grant": case "group_add": case "consent":
    case "app_register": case "password_reset": case "password_change": case "ca_policy_update": case "guest_invite":
      return auditFor(ev, ctx, f);
    default:
      // push_sent, token_create/revoke, app_assign, session_end, risk_change, rate_limit, directory_read:
      // Entra writes no signIn/directoryAudit record for these (Graph directory reads live in
      // MicrosoftGraphActivityLogs; Identity-Protection risk changes in riskDetections).
      return null;
  }
}

// ── use cases ────────────────────────────────────────────────────────────────

const RFC1918 = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"];
const useCases: UseCase[] = [
  {
    id: "entra.password_spray", title: "Password spray — many accounts failing from one IP", sourceId: "entra", kinds: ["signIn"], severity: "high", mitre: ["T1110.003"],
    description: "One client IP fails sign-in (50126 bad password / 50053 locked) for many different users inside 10 minutes. A spray tries one or two common passwords against many accounts to stay under per-user lockout thresholds.",
    logic: "KQL (Graph signIns): SigninLogs | where ResultType in (50126, 50053) | summarize Users=dcount(UserPrincipalName) by IPAddress, bin(TimeGenerated, 10m) | where Users >= 5",
    match: { field: "status.errorCode", op: "in", value: [50126, 50053] },
    threshold: { groupBy: ["ipAddress"], count: 5, windowSec: 600, distinct: "userPrincipalName" },
    falsePositives: ["NAT'd office egress after a password-policy change", "A misconfigured service retrying an old password for several service accounts"],
  },
  {
    id: "entra.brute_force", title: "Brute force against a single account", sourceId: "entra", kinds: ["signIn"], severity: "high", mitre: ["T1110.001"],
    description: "Ten or more bad-password failures (50126) for the same user inside 10 minutes.",
    logic: "KQL: SigninLogs | where ResultType == 50126 | summarize Fails=count() by UserPrincipalName, bin(TimeGenerated, 10m) | where Fails >= 10",
    match: { field: "status.errorCode", op: "eq", value: 50126 },
    threshold: { groupBy: ["userPrincipalName"], count: 10, windowSec: 600 },
    falsePositives: ["A phone or mail client still using an old password after a reset"],
  },
  {
    id: "entra.bruteforce_then_success", title: "Failed passwords followed by a success from the same external IP", sourceId: "entra", kinds: ["signIn"], severity: "high", mitre: ["T1110", "T1078.004"],
    description: "The same user and the same non-corporate IP produce both bad-password failures (50126) and a successful sign-in (0) within 30 minutes — the guess eventually worked. Check the password step (authenticationDetails) and whether MFA was required.",
    logic: "KQL: SigninLogs | where IPAddress !startswith \"10.\" | where ResultType in (0, 50126) | summarize Results=make_set(ResultType) by UserPrincipalName, IPAddress, bin(TimeGenerated, 30m) | where Results has \"0\" and Results has \"50126\"",
    match: { all: [{ field: "status.errorCode", op: "in", value: [0, 50126] }, { field: "ipAddress", op: "notCidr", value: RFC1918 }, { field: "isInteractive", op: "eq", value: true }] },
    threshold: { groupBy: ["userPrincipalName", "ipAddress"], count: 2, windowSec: 1800, distinct: "status.errorCode" },
    falsePositives: ["A travelling user mistyping the password once at a hotel"],
  },
  {
    id: "entra.mfa_fatigue", title: "MFA push fatigue — repeated MFA denials", sourceId: "entra", kinds: ["signIn"], severity: "high", mitre: ["T1621"],
    description: "Three or more 500121 results (MFA denied / not completed) for one user inside 10 minutes. The password step succeeded, so the attacker already has the password and is spamming pushes hoping the user taps Approve.",
    logic: "KQL: SigninLogs | where ResultType == 500121 | summarize Denials=count(), IPs=make_set(IPAddress) by UserPrincipalName, bin(TimeGenerated, 10m) | where Denials >= 3",
    match: { field: "status.errorCode", op: "eq", value: 500121 },
    threshold: { groupBy: ["userPrincipalName"], count: 3, windowSec: 600 },
    falsePositives: ["A user with a broken Authenticator registration timing out repeatedly"],
  },
  {
    id: "entra.mfa_fatigue_approved", title: "MFA denials followed by an approval from the same IP", sourceId: "entra", kinds: ["signIn"], severity: "critical", mitre: ["T1621", "T1078.004"],
    description: "A user denies MFA (500121) and then a multi-factor sign-in succeeds from the same external IP within 30 minutes — the fatigue attack worked. Revoke sessions and reset the password.",
    logic: "KQL: SigninLogs | where IPAddress !startswith \"10.\" | where ResultType == 500121 or (ResultType == 0 and AuthenticationRequirement == \"multiFactorAuthentication\") | summarize Results=make_set(ResultType) by UserPrincipalName, IPAddress, bin(TimeGenerated, 30m) | where array_length(Results) >= 2",
    match: { all: [{ field: "ipAddress", op: "notCidr", value: RFC1918 }, { any: [{ field: "status.errorCode", op: "eq", value: 500121 },
      { all: [{ field: "status.errorCode", op: "eq", value: 0 }, { field: "authenticationRequirement", op: "eq", value: "multiFactorAuthentication" }] }] }] },
    threshold: { groupBy: ["userPrincipalName", "ipAddress"], count: 2, windowSec: 1800, distinct: "status.errorCode" },
    falsePositives: ["A user who accidentally denied once and then approved their own login"],
  },
  {
    id: "entra.risky_signin_success", title: "Successful sign-in flagged medium/high risk by Identity Protection", sourceId: "entra", kinds: ["signIn"], severity: "high", mitre: ["T1078.004"],
    description: "A sign-in succeeded although Entra ID Protection rated it medium or high risk in real time (riskLevelDuringSignIn) or offline (riskLevelAggregated = high). Look at riskEventTypes_v2 for why.",
    logic: "KQL: SigninLogs | where ResultType == 0 | where RiskLevelDuringSignIn in (\"medium\",\"high\") or RiskLevelAggregated == \"high\"",
    match: { all: [{ field: "status.errorCode", op: "eq", value: 0 }, { any: [{ field: "riskLevelDuringSignIn", op: "in", value: ["medium", "high"] }, { field: "riskLevelAggregated", op: "eq", value: "high" }] }] },
    falsePositives: ["A new laptop or a first trip abroad (unfamiliarFeatures)"],
  },
  {
    id: "entra.anonymous_proxy_signin", title: "Sign-in from an anonymizer or known-malicious IP", sourceId: "entra", kinds: ["signIn"], severity: "high", mitre: ["T1090.003", "T1078.004"],
    description: "Identity Protection tagged the sign-in with anonymizedIPAddress (Tor / anonymous VPN) or maliciousIPAddress.",
    logic: "KQL: SigninLogs | mv-expand RiskEventTypes_V2 | where RiskEventTypes_V2 in (\"anonymizedIPAddress\",\"maliciousIPAddress\")",
    match: { field: "riskEventTypes_v2[]", op: "in", value: ["anonymizedIPAddress", "maliciousIPAddress"] },
    falsePositives: ["Privacy VPN used by a remote employee", "Security team testing through Tor"],
  },
  {
    id: "entra.unfamiliar_location_signin", title: "Successful sign-in from a new country / unlikely travel", sourceId: "entra", kinds: ["signIn"], severity: "medium", mitre: ["T1078.004"],
    description: "A successful sign-in carries unlikelyTravel or unfamiliarFeatures — the country, ASN or device differ from the user's history. Compare location.countryOrRegion and autonomousSystemNumber with the user's last 30 days.",
    logic: "KQL: SigninLogs | where ResultType == 0 | mv-expand RiskEventTypes_V2 | where RiskEventTypes_V2 in (\"unlikelyTravel\",\"unfamiliarFeatures\") | project TimeGenerated, UserPrincipalName, IPAddress, Location, AutonomousSystemNumber",
    match: { all: [{ field: "status.errorCode", op: "eq", value: 0 }, { field: "riskEventTypes_v2[]", op: "in", value: ["unlikelyTravel", "unfamiliarFeatures"] }] },
    falsePositives: ["Business travel", "Mobile carrier IPs that geolocate to a neighbouring country"],
  },
  {
    id: "entra.admin_role_added", title: "User added to a privileged directory role", sourceId: "entra", kinds: ["directoryAudit"], severity: "high", mitre: ["T1098.003"],
    description: "Add member to role succeeded. Global Administrator, Privileged Role Administrator and similar roles give tenant-wide control — confirm a change ticket and who (initiatedBy) did it from where (ipAddress).",
    logic: "KQL: AuditLogs | where OperationName startswith \"Add member to role\" and Result == \"success\" | extend Role=tostring(TargetResources[0].modifiedProperties[1].newValue)",
    match: { all: [{ field: "activityDisplayName", op: "startsWith", value: "Add member to role" }, { field: "result", op: "eq", value: "success" }] },
    falsePositives: ["Planned PIM activation by an approved admin"],
  },
  {
    id: "entra.oauth_broad_consent", title: "OAuth consent granted with broad mail/file scopes", sourceId: "entra", kinds: ["directoryAudit"], severity: "high", mitre: ["T1528", "T1550.001"],
    description: "Consent to application whose permission string grants mailbox or tenant-wide file access (Mail.Read*, Mail.Send, Files.ReadWrite.All, offline_access…). This is the illicit-consent pattern: the app keeps access even after a password reset.",
    logic: "KQL: AuditLogs | where OperationName == \"Consent to application\" | extend Perms=tostring(TargetResources[0].modifiedProperties) | where Perms has_any (\"Mail.Read\",\"Mail.ReadWrite\",\"Mail.Send\",\"Files.ReadWrite.All\",\"full_access_as_app\",\"Directory.ReadWrite.All\")",
    match: { all: [{ field: "activityDisplayName", op: "eq", value: "Consent to application" },
      { field: "targetResources[].modifiedProperties[].newValue", op: "regex", value: "Mail\\.Read|Mail\\.ReadWrite|Mail\\.Send|Files\\.ReadWrite\\.All|full_access_as_app|Directory\\.ReadWrite\\.All" }] },
    falsePositives: ["An approved mail-archiving or e-signature app"],
  },
  {
    id: "entra.mfa_method_registered_external", title: "New MFA method registered from outside the corporate network", sourceId: "entra", kinds: ["directoryAudit"], severity: "high", mitre: ["T1098.005"],
    description: "User registered security info from a non-corporate IP. Right after a risky sign-in this is persistence: the attacker adds their own Authenticator so they no longer need the victim to approve pushes. Join on the user to the preceding risky signIn.",
    logic: "KQL: AuditLogs | where OperationName == \"User registered security info\" | extend UPN=tostring(InitiatedBy.user.userPrincipalName), IP=tostring(InitiatedBy.user.ipAddress) | where not(ipv4_is_private(IP)) | join kind=inner (SigninLogs | where RiskLevelDuringSignIn in (\"medium\",\"high\") | project UPN=UserPrincipalName, RiskyTime=TimeGenerated) on UPN | where TimeGenerated between (RiskyTime .. RiskyTime + 1h)",
    match: { all: [{ field: "activityDisplayName", op: "eq", value: "User registered security info" }, { field: "initiatedBy.user.ipAddress", op: "notCidr", value: RFC1918 }] },
    falsePositives: ["A user setting up a new phone from home after a device replacement"],
  },
  {
    id: "entra.legacy_auth_valid_password", title: "Legacy-auth sign-in with a correct password blocked by CA", sourceId: "entra", kinds: ["signIn"], severity: "medium", mitre: ["T1078.004", "T1110"],
    description: "Conditional Access blocked a legacy protocol (53003), but the password step succeeded — the attacker holds a valid password. Reset it.",
    logic: "KQL: SigninLogs | where ResultType == 53003 and ClientAppUsed in (\"Exchange ActiveSync\",\"IMAP4\",\"POP3\",\"Authenticated SMTP\",\"Other clients\") | where AuthenticationDetails has '\"succeeded\":true'",
    match: { all: [{ field: "status.errorCode", op: "eq", value: 53003 }, { field: "authenticationDetails[].succeeded", op: "eq", value: true }] },
    falsePositives: ["An old phone mail client of a legitimate user"],
  },
  {
    id: "entra.sp_credentials_added", title: "Credentials added to a service principal", sourceId: "entra", kinds: ["directoryAudit"], severity: "high", mitre: ["T1098.001"],
    description: "Add service principal credentials — a new secret or certificate lets whoever holds it sign in as the application, bypassing user MFA.",
    logic: "KQL: AuditLogs | where OperationName in (\"Add service principal credentials\",\"Update application – Certificates and secrets management\")",
    match: { field: "activityDisplayName", op: "eq", value: "Add service principal credentials" },
    falsePositives: ["Scheduled secret rotation by the app owner"],
  },
  {
    id: "entra.ca_policy_changed", title: "Conditional Access policy modified", sourceId: "entra", kinds: ["directoryAudit"], severity: "medium", mitre: ["T1556.009"],
    description: "A Conditional Access policy was updated. Attackers add exclusions (their device, IP or account) to slip past MFA / compliant-device rules.",
    logic: "KQL: AuditLogs | where LoggedByService == \"Conditional Access\" and OperationName has \"policy\"",
    match: { field: "activityDisplayName", op: "eq", value: "Update conditional access policy" },
    falsePositives: ["Change-managed policy tuning by the identity team"],
  },
];

export const source: NativeSource = { schema, fromTelemetry, useCases };
