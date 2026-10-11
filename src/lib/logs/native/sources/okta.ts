/**
 * Okta — System Log native module (card: docs/log-schemas/idp-okta.md).
 *
 * One LogEvent per event, exactly as `GET /api/v1/logs` returns it (no array
 * wrapper): alphabetical top-level keys, documented nulls kept, `published` with
 * milliseconds, `version: "0"`, `debugContext.debugData` values always strings
 * with camelCase keys. The org is modelled as an **Identity Engine** org, so a
 * rejected Okta Verify push is `user.authentication.auth_via_mfa` FAILURE /
 * INVALID_CREDENTIALS with `pushOnlyResponseType: OV_RESPONSE_DENY` (card §6) —
 * legacy authored types such as `user.mfa.okta_verify.push_response` are
 * re-expressed that way.
 *
 * Also renders Entra-authored sign-ins / audits where Okta has a true
 * equivalent (sign-in → user.session.start, 500121 → auth_via_mfa FAILURE,
 * 53003 → policy.evaluate_sign_on DENY, "User registered security info" →
 * user.mfa.factor.activate, "Add member to role" → user.account.privilege.grant).
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { NativeCtx, NativeLog, NativeSource, SourceSchema, UseCase } from "../types";
import { egressIp } from "./firewall-shared";
import {
  asnOf, b62, COMPANY_HQ, geoOf, identityFacts, isoFrac, isPrivateIp, nameFromLogin, oktaId, rawStr, uaOf,
  type IdFacts, type MfaMethod,
} from "./_identity-common";

// ── schema ───────────────────────────────────────────────────────────────────

const ENVELOPE_REQUIRED = [
  "actor.id", "actor.type", "actor.alternateId", "actor.displayName", "actor.detailEntry",
  "authenticationContext.authenticationProvider", "authenticationContext.authenticationStep", "authenticationContext.credentialProvider",
  "authenticationContext.credentialType", "authenticationContext.externalSessionId", "authenticationContext.interface", "authenticationContext.issuer",
  "client.device", "client.id", "client.ipAddress", "client.userAgent.rawUserAgent", "client.userAgent.os", "client.userAgent.browser", "client.zone",
  "debugContext.debugData", "device", "displayMessage", "eventType", "legacyEventType", "outcome.result", "outcome.reason", "published",
  "request.ipChain", "securityContext.asNumber", "securityContext.asOrg", "securityContext.domain", "securityContext.isProxy", "securityContext.isp",
  "severity", "target", "transaction.detail", "transaction.id", "transaction.type", "uuid", "version",
];
const GEO = ["city", "country", "geolocation.lat", "geolocation.lon", "postalCode", "state"];
const ENVELOPE_OPTIONAL = [
  ...GEO.map(g => `client.geographicalContext.${g}`),
  "actor.detailEntry.methodTypeUsed",
  "authenticationContext.issuer.id", "authenticationContext.issuer.type",
  "device.id", "device.name", "device.os_platform", "device.os_version", "device.managed", "device.registered", "device.device_integrator",
  "device.disk_encryption_type", "device.screen_lock_type", "device.jailbreak", "device.secure_hardware_present",
  "request.ipChain[].ip", "request.ipChain[].version", "request.ipChain[].source", ...GEO.map(g => `request.ipChain[].geographicalContext.${g}`),
  "target[].id", "target[].type", "target[].alternateId", "target[].displayName", "target[].detailEntry", "target[].changeDetails",
  "transaction.detail.requestApiTokenId",
];
/** Event types this module emits — every one is named on the card (catalog-verified) except where noted. */
const EVENT_TYPES = [
  "user.session.start", "user.session.end", "user.authentication.auth_via_mfa", "user.authentication.sso", "system.push.send_factor_verify_push",
  "policy.evaluate_sign_on", "security.threat.detected", "user.account.lock", "user.mfa.factor.activate", "user.mfa.factor.deactivate",
  "user.mfa.factor.reset_all", "group.user_membership.add", "application.user_membership.add", "user.account.privilege.grant",
  "system.api_token.create", "system.api_token.revoke",
  // Classic-engine only (card 3.4) — validated for completeness, never emitted by this OIE model.
  "user.mfa.okta_verify.deny_push",
  // Not on the card: official catalog event type ("OAuth2 access token is granted"); same LogEvent envelope. UNVERIFIED displayMessage.
  "app.oauth2.as.token.grant",
];
const kinds = Object.fromEntries(EVENT_TYPES.map(t => [t, { required: ENVELOPE_REQUIRED, optional: ENVELOPE_OPTIONAL, openPrefixes: ["debugContext.debugData"] }]));

const schema: SourceSchema = {
  sourceId: "okta",
  category: "idp",
  card: "idp-okta.md",
  product: "Okta Workforce Identity (System Log)",
  format: "json",
  vendorMatch: ["okta"],
  telemetrySources: ["okta", "mfa", "o365", "cloud_azure", "iam"],
  kinds,
};

export function kindOf(record: Record<string, unknown>): string | null {
  const t = record.eventType;
  return typeof t === "string" && t in kinds ? t : null;
}

// ── reference values ─────────────────────────────────────────────────────────

const DISPLAY: Record<string, string> = {
  "user.session.start": "User login to Okta",
  "user.session.end": "User logout from Okta",
  "user.authentication.auth_via_mfa": "Authentication of user via MFA",
  "user.authentication.sso": "User single sign on to app",
  "system.push.send_factor_verify_push": "Push notification sent for verification",
  "policy.evaluate_sign_on": "Evaluation of sign-on policy",
  "security.threat.detected": "Request from suspicious actor",
  "user.account.lock": "Max sign in attempts exceeded",
  "user.mfa.factor.activate": "Activate factor or authenticator enrollment method for user",
  "user.mfa.factor.deactivate": "Reset factor for user",
  "user.mfa.factor.reset_all": "Reset all factors for user",
  "group.user_membership.add": "Add user to group membership",
  "application.user_membership.add": "Add user to application membership",
  "user.account.privilege.grant": "Grant user privilege",
  "system.api_token.create": "Create API token",
  "system.api_token.revoke": "Revoke API token",
  "app.oauth2.as.token.grant": "OAuth2 access token is granted",
};
const FACTOR: Partial<Record<MfaMethod, { factor: string; enrollment: string; prefix: string; method?: string }>> = {
  push: { factor: "OKTA_VERIFY_PUSH", enrollment: "Okta Verify", prefix: "opf", method: "Get a push notification" },
  totp: { factor: "SOFT_TOKEN", enrollment: "Google Authenticator", prefix: "uft" },
  sms: { factor: "SMS_FACTOR", enrollment: "Phone", prefix: "sms" },
  fido: { factor: "FIDO_WEBAUTHN", enrollment: "Security Key or Biometric", prefix: "fwf" },
};
const BEHAVIOR_KEYS = ["New Geo-Location", "New Device", "New IP", "New State", "New Country", "Velocity", "New City"];

// ── helpers ──────────────────────────────────────────────────────────────────

const userOktaId = (ctx: NativeCtx, email: string) => oktaId(ctx, "00u", `${ctx.companyId}:okta-user:${email}`);
/** Time-based (v1-shaped) UUID, deterministic. */
function uuidV1(ctx: NativeCtx, seed: string): string {
  const h = ctx.hex(seed, 32);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-11f1-${((parseInt(h[12], 16) & 3) | 8).toString(16)}${h.slice(13, 16)}-${h.slice(16, 28)}`;
}
function userRef(ctx: NativeCtx, email: string | undefined, name?: string, type = "User") {
  if (!email) return { alternateId: "unknown", detailEntry: null, displayName: "unknown", id: "unknown", type };
  return { alternateId: email, detailEntry: null, displayName: name ?? nameFromLogin(email), id: userOktaId(ctx, email), type };
}
function behaviorsString(positive: Set<string>): string {
  return `{${BEHAVIOR_KEYS.map(k => `${k}=${positive.has(k) ? "POSITIVE" : "NEGATIVE"}`).join(", ")}}`;
}

interface Render {
  eventType: string;
  result: string;
  reason: string | null;
  severity?: "INFO" | "WARN";
  actor: Record<string, unknown>;
  target: Record<string, unknown>[] | null;
  /** True for events written before a session exists (failed password, spray, lockout). */
  preSession?: boolean;
  authProvider?: boolean;
  requestUri?: string;
  debug?: Record<string, string>;
  device?: Record<string, unknown> | null;
  legacy?: string | null;
}

function render(ev: TelemetryEvent, ctx: NativeCtx, f: IdFacts, r: Render): NativeLog {
  // A person's action always carries the client address — with none authored, the
  // company's egress (the same one its firewalls NAT to). Only Okta's own system
  // actions have no client, and then no geo either.
  // Okta is SaaS: it never sees a corporate user's private address. A sign-in from inside the
  // network arrives from the company's egress (NAT) address — real geo / ASN — and the org's
  // "Corporate HQ" network zone is defined on that egress, so client.zone names it.
  const egress = egressIp(ctx);
  const ip = isPrivateIp(f.ip) ? egress : f.ip ?? (r.actor?.type === "User" ? egress : null);
  const geo = geoOf(ev, ctx, ip ?? undefined);
  const asn = asnOf(ev, geo, ip ?? undefined);
  const ua = uaOf(ev);
  const corporate = !!ip && ip === egress;
  const geoCtx = !ip ? { city: null, country: null, geolocation: { lat: null, lon: null }, postalCode: null, state: null } :
    { city: geo.city, country: geo.country, geolocation: { lat: geo.lat, lon: geo.lon }, postalCode: geo.postal, state: geo.state };
  const email = f.email;
  const sid = r.preSession ? "unknown" :
    (f.sessionId ?? `102${b62(ctx, `${ctx.companyId}:okta-sid:${email ?? "?"}:${ip ?? "?"}:${ev.ts.slice(0, 10)}`, 22)}`);
  const tx = f.transactionId ?? `${b62(ctx, `${ev.id}:okta-tx`, 23)}AAA${b62(ctx, `${ev.id}:okta-tx2`, 1)}`;
  const uri = rawStr(ev, "okta.debugContext.debugData.requestUri") ?? r.requestUri ?? "/api/v1/authn";
  const debugData: Record<string, string> = { requestId: tx, requestUri: uri, url: `${uri}?`, ...(r.debug ?? {}) };
  const failure = r.result !== "SUCCESS" && r.result !== "ALLOW";
  const record: Record<string, unknown> = {
    actor: r.actor,
    authenticationContext: {
      authenticationProvider: r.authProvider ? "FACTOR_PROVIDER" : null, authenticationStep: 0,
      credentialProvider: r.authProvider ? "OKTA_CREDENTIAL_PROVIDER" : null, credentialType: null,
      externalSessionId: sid, interface: null, issuer: null,
    },
    client: {
      device: ua.device,
      geographicalContext: geoCtx,
      id: null,
      ipAddress: ip,
      userAgent: { browser: ua.oktaBrowser, os: ua.oktaOs, rawUserAgent: ua.raw },
      zone: corporate ? "Corporate HQ" : "null",
    },
    debugContext: { debugData: Object.fromEntries(Object.entries(debugData).sort(([a], [b]) => a.localeCompare(b))) },
    device: r.device ?? null,
    displayMessage: DISPLAY[r.eventType],
    eventType: r.eventType,
    legacyEventType: r.legacy ?? null,
    outcome: { reason: r.reason, result: r.result },
    published: isoFrac(ev.ts, 3),
    request: { ipChain: ip ? [{ geographicalContext: geoCtx, ip, source: null, version: ip.includes(":") ? "V6" : "V4" }] : [] },
    securityContext: { asNumber: asn.asn, asOrg: asn.asOrg, domain: asn.domain, isProxy: corporate ? false : asn.isProxy, isp: asn.isp },
    severity: r.severity ?? (failure || r.eventType === "user.account.lock" || r.eventType === "security.threat.detected" ? "WARN" : "INFO"),
    target: r.target,
    transaction: { detail: {}, id: tx, type: "WEB" },
    uuid: uuidV1(ctx, `${ev.id}:okta-uuid`),
    version: "0",
  };
  return { sourceId: "okta", kind: r.eventType, format: "json", record, timeMs: Date.parse(ev.ts) };
}

/**
 * debugData risk/behaviour enrichment for sign-in-type events. Authored behaviours / risk win
 * key by key; what the story did not state is what Okta's engines conclude from the request
 * itself: an address outside the head-office country (not the corporate egress) is a new
 * country / geo-location / IP; an anonymizer is a new IP and location; a scripted client or a
 * high risk is a new device. The user's own baseline sign-ins (is_baseline, or an informational
 * context row with no technique) are their usual pattern — all NEGATIVE. Risk with none authored: anonymizer, or a new location on a new
 * device → HIGH; a new location → MEDIUM; otherwise LOW.
 */
function riskDebug(ev: TelemetryEvent, ctx: NativeCtx, f: IdFacts, withBehaviors: boolean): Record<string, string> {
  const out: Record<string, string> = {};
  const egress = egressIp(ctx);
  const ip = isPrivateIp(f.ip) ? egress : f.ip;
  const geo = geoOf(ev, ctx, ip);
  const asn = asnOf(ev, geo, ip);
  const corporate = !ip || ip === egress;
  const proxy = !corporate && asn.isProxy;
  const foreign = !corporate && geo.iso !== (COMPANY_HQ[ctx.companyId] ?? "IL");
  const authored = new Map<string, boolean>();
  if (f.behaviors) for (const m of f.behaviors.matchAll(/([A-Za-z -]+)=(POSITIVE|NEGATIVE)/g)) authored.set(m[1].trim(), m[2] === "POSITIVE");
  const derived = new Set<string>();
  // The account's usual pattern: a baseline row, or an informational context row with no technique.
  const usual = ev.is_baseline || (ev.severity === "informational" && !ev.mitre_technique && ev.expected_verdict !== "tp" && ev.expected_verdict !== "escalate");
  if (!usual) {
    if (foreign) ["New Geo-Location", "New IP", "New State", "New Country", "New City"].forEach(k => derived.add(k));
    if (proxy) ["New Geo-Location", "New IP"].forEach(k => derived.add(k));
    if (uaOf(ev).scripted || f.risk === "high") derived.add("New Device");
    if (f.riskReasons.includes("unlikelyTravel")) derived.add("Velocity");
  }
  const positive = new Set(BEHAVIOR_KEYS.filter(k => authored.get(k) ?? derived.has(k)));
  if (withBehaviors && (f.behaviors || f.risk !== "none" || foreign || proxy)) out.behaviors = behaviorsString(positive);
  const newLoc = positive.has("New Country") || positive.has("New Geo-Location");
  const level = f.risk !== "none" ? f.risk : proxy || (newLoc && positive.has("New Device")) ? "high" : newLoc ? "medium" : "low";
  const reasons = [newLoc || proxy || level !== "low" ? "Anomalous Location" : "", positive.has("New Device") || (level === "high" && !proxy) ? "Anomalous Device" : ""].filter(Boolean);
  out.risk = level === "low" ? "{level=LOW}" : `{reasons=${reasons.join(", ")}, level=${level.toUpperCase()}}`;
  out.threatSuspected = f.threatSuspected ? "true" : "false";
  return out;
}
const deviceHashes = (ctx: NativeCtx, f: IdFacts, ev: TelemetryEvent) => ({
  deviceFingerprint: ctx.hex(`${ctx.companyId}:okta-fp:${f.email}:${uaOf(ev).raw}`, 32),
  dtHash: ctx.hex(`${ctx.companyId}:okta-dt:${f.email}:${uaOf(ev).raw}`, 64),
});
function enrollmentTarget(ctx: NativeCtx, email: string | undefined, method: MfaMethod | undefined, withDetail: boolean, seed = "") {
  const fx = FACTOR[method ?? "push"] ?? FACTOR.push!;
  return {
    alternateId: "unknown",
    detailEntry: withDetail && fx.method ? { methodTypeUsed: fx.method, methodUsedVerifiedProperties: "[USER_PRESENCE]" } : null,
    displayName: fx.enrollment, id: oktaId(ctx, fx.prefix, `${ctx.companyId}:okta-factor:${email}:${fx.factor}${seed}`), type: "AuthenticatorEnrollment",
  };
}

// ── conversion ───────────────────────────────────────────────────────────────

function fromTelemetry(ev: TelemetryEvent, ctx: NativeCtx): NativeLog | null {
  if (/cyberark|beyondtrust|delinea|thycotic/i.test(ev.vendor ?? "")) return null;
  const f = identityFacts(ev);
  if (!f) return null;
  const me = () => userRef(ctx, f.email, f.displayName);
  const signinFailReason = (fr: IdFacts["failure"]) => fr === "locked" ? "LOCKED_OUT" : fr === "no_user" || fr === "disabled" || fr === "expired" || fr === "other" ? "VERIFICATION_ERROR" : "INVALID_CREDENTIALS";

  // Entra-shaped sign-in outcomes that are separate record types in Okta.
  if (f.action === "signin" && !f.success) {
    if (f.failure === "mfa_denied") f.action = "mfa";
    else if (f.failure === "mfa_required" || f.failure === "mfa_registration") { f.action = "policy"; f.decision = "CHALLENGE"; }
    else if (f.failure === "ca_block") { f.action = "policy"; f.decision = "DENY"; }
    else if (f.failure === "malicious_ip") { f.action = "threat"; f.decision = "DENY"; }
  }
  if (f.action === "signin" && f.success && !rawStr(ev, "okta.eventType") && ev.event_type === "mfa_challenge") f.action = "mfa";

  switch (f.action) {
    case "signin": {
      if (f.success) {
        return render(ev, ctx, f, { eventType: "user.session.start", result: "SUCCESS", reason: null, actor: me(), target: null, legacy: "core.user_auth.login_success",
          requestUri: uaOf(ev).scripted ? "/api/v1/authn" : "/idp/idx/authenticators/poll",
          debug: { ...riskDebug(ev, ctx, f, true), ...deviceHashes(ctx, f, ev) } });
      }
      return render(ev, ctx, f, { eventType: "user.session.start", result: "FAILURE", reason: signinFailReason(f.failure), actor: me(), target: null, preSession: true,
        legacy: "core.user_auth.login_failed", requestUri: uaOf(ev).scripted ? "/api/v1/authn" : "/idp/idx/identify",
        debug: { threatSuspected: f.threatSuspected ? "true" : "false" } });
    }
    case "mfa": {
      const method = f.mfaMethod ?? "push";
      const fx = FACTOR[method];
      const debug: Record<string, string> = {
        authnRequestId: b62(ctx, `${ctx.companyId}:okta-authn:${f.email}:${f.ip}:${ev.ts.slice(0, 13)}`, 27),
        ...deviceHashes(ctx, f, ev), factorIntent: "LOGIN", promptingPolicyTypes: "[OKTA_SIGN_ON]",
        ...riskDebug(ev, ctx, f, true),
      };
      delete debug.deviceFingerprint;
      if (fx) debug.factor = fx.factor;
      if (method === "push") debug.pushOnlyResponseType = f.success ? "OV_RESPONSE_APPROVE" : "OV_RESPONSE_DENY";
      return render(ev, ctx, f, { eventType: "user.authentication.auth_via_mfa", result: f.success ? "SUCCESS" : "FAILURE", reason: f.success ? null : "INVALID_CREDENTIALS",
        actor: me(), target: [userRef(ctx, f.email, f.displayName), enrollmentTarget(ctx, f.email, method, true)], authProvider: true,
        legacy: f.success ? "core.user.factor.attempt_success" : "core.user.factor.attempt_fail", requestUri: "/idp/idx/authenticators/poll", debug });
    }
    case "push_sent": {
      const debug: Record<string, string> = {};
      const rd = riskDebug(ev, ctx, f, true);
      if (rd.behaviors) debug.behaviors = rd.behaviors;
      return render(ev, ctx, f, { eventType: "system.push.send_factor_verify_push", result: "SUCCESS", reason: null, actor: me(),
        target: [enrollmentTarget(ctx, f.email, "push", false)], requestUri: "/idp/idx/challenge", debug });
    }
    case "policy": {
      if (!f.email) return null; // a policy is always evaluated for an identified user (card §6)
      const d = f.decision ?? "ALLOW";
      const pid = oktaId(ctx, "00p", `${ctx.companyId}:okta-policy:global`);
      const rule = d === "DENY" ? "Deny unmanaged devices outside Corporate HQ" : "Require MFA outside Corporate HQ";
      return render(ev, ctx, f, { eventType: "policy.evaluate_sign_on", result: d, reason: `Sign-on policy evaluation resulted in ${d}`, actor: me(),
        target: [{ alternateId: "unknown", detailEntry: { policyType: "OktaSignOn" }, displayName: "Default Policy", id: pid, type: "PolicyEntity" },
          { alternateId: pid, detailEntry: null, displayName: rule, id: oktaId(ctx, "0pr", `${ctx.companyId}:okta-rule:${rule}`), type: "PolicyRule" }],
        severity: d === "DENY" ? "WARN" : "INFO", requestUri: "/idp/idx/identify", debug: { ...riskDebug(ev, ctx, f, true), ...deviceHashes(ctx, f, ev) } });
    }
    case "lockout": {
      if (!f.email) return null;
      return render(ev, ctx, f, { eventType: "user.account.lock", result: "SUCCESS", reason: null, actor: me(), target: [userRef(ctx, f.email, f.displayName)],
        preSession: true, legacy: "core.user_auth.account_locked", requestUri: "/api/v1/authn", debug: { threatSuspected: f.threatSuspected === false ? "false" : "true" } });
    }
    case "threat": {
      return render(ev, ctx, f, { eventType: "security.threat.detected", result: f.decision === "DENY" ? "DENY" : "ALLOW",
        reason: rawStr(ev, "okta.outcome.reason") && !/BLOCKED_BY/i.test(rawStr(ev, "okta.outcome.reason")!) ? rawStr(ev, "okta.outcome.reason")! : /stuffing/i.test(ev.description ?? "") || /T1110\.004/.test(ev.mitre_technique ?? "") ? "Credential Stuffing" : "Password Spray",
        actor: userRef(ctx, undefined), target: null, preSession: true, requestUri: "/api/v1/authn", debug: { threatSuspected: "true" } });
    }
    case "factor_enroll": {
      if (!f.email) return null;
      const platform = (f.devicePlatform ?? "").toUpperCase();
      const phone = ctx.int(`${ctx.companyId}:okta-dev:${f.email}:${ev.id}`, 0, 1) === 0 ? { name: "Pixel 8", os: "ANDROID", ver: "15" } : { name: "iPhone 15", os: "IOS", ver: "18.5" };
      const dev = f.deviceName ? { name: f.deviceName, os: platform || "WINDOWS", ver: platform === "MACOS" ? "15.5" : "10.0.22631" } : phone;
      return render(ev, ctx, f, { eventType: "user.mfa.factor.activate", result: "SUCCESS", reason: null, actor: me(),
        target: [userRef(ctx, f.email, f.displayName), enrollmentTarget(ctx, f.email, f.mfaMethod ?? "push", false, `:${ev.id}`)],
        legacy: "core.user.factor.activate", requestUri: "/idp/idx/challenge/poll", debug: { dtHash: deviceHashes(ctx, f, ev).dtHash },
        device: { device_integrator: null, disk_encryption_type: "USER", id: oktaId(ctx, "guo", `${ctx.companyId}:okta-device:${f.email}:${dev.name}`), jailbreak: false,
          managed: false, name: dev.name, os_platform: dev.os, os_version: dev.ver, registered: true, screen_lock_type: "BIOMETRIC", secure_hardware_present: true } });
    }
    case "factor_reset": case "factor_deactivate": {
      const target = f.targetEmail ?? f.email;
      if (!target) return null;
      const tid = userOktaId(ctx, target);
      const all = f.action === "factor_reset";
      return render(ev, ctx, f, { eventType: all ? "user.mfa.factor.reset_all" : "user.mfa.factor.deactivate", result: "SUCCESS", reason: null, actor: me(),
        target: all ? [userRef(ctx, target)] : [userRef(ctx, target), enrollmentTarget(ctx, target, f.mfaMethod, false)],
        legacy: all ? "core.user.factor.reset_all" : null,
        requestUri: all ? `/api/v1/users/${tid}/lifecycle/reset_factors` : `/api/v1/users/${tid}/factors/${enrollmentTarget(ctx, target, f.mfaMethod, false).id}` });
    }
    case "group_add": {
      const target = f.targetEmail ?? f.email;
      if (!target || !f.groupName) return null;
      const gid = oktaId(ctx, "00g", `${ctx.companyId}:okta-group:${f.groupName}`);
      return render(ev, ctx, f, { eventType: "group.user_membership.add", result: "SUCCESS", reason: null, actor: me(),
        target: [userRef(ctx, target), { alternateId: "unknown", detailEntry: null, displayName: f.groupName, id: gid, type: "UserGroup" }],
        legacy: "core.user_group_member.user_add", requestUri: `/api/v1/groups/${gid}/users/${userOktaId(ctx, target)}` });
    }
    case "app_assign": {
      const target = f.targetEmail ?? f.email;
      if (!target || !f.appName) return null;
      const aid = oktaId(ctx, "0oa", `${ctx.companyId}:okta-app:${f.appName}`);
      return render(ev, ctx, f, { eventType: "application.user_membership.add", result: "SUCCESS", reason: null, actor: me(),
        target: [{ ...userRef(ctx, target), id: oktaId(ctx, "0ua", `${ctx.companyId}:okta-appuser:${target}:${f.appName}`), type: "AppUser" },
          { alternateId: f.appName, detailEntry: { signOnModeType: "SAML_2_0" }, displayName: f.appName, id: aid, type: "AppInstance" }, userRef(ctx, target)],
        legacy: "app.generic.provision.assign_user_to_app", requestUri: `/api/v1/apps/${aid}/users` });
    }
    case "role_grant": {
      const target = f.targetEmail ?? f.email;
      if (!target) return null;
      const role = !f.roleName ? "Super Administrator" : /global administrator|super/i.test(f.roleName) ? "Super Administrator" : f.roleName;
      // debugData.privilegeGranted: the granted admin role (key used by Okta's own hunting guidance; debugData is free-form).
      return render(ev, ctx, f, { eventType: "user.account.privilege.grant", result: "SUCCESS", reason: null, actor: me(), target: [userRef(ctx, target)],
        requestUri: `/api/v1/users/${userOktaId(ctx, target)}/roles`, debug: { privilegeGranted: role } });
    }
    case "token_create": case "token_revoke": {
      const name = f.targetName ?? "API token";
      const tid = oktaId(ctx, "00T", `${ctx.companyId}:okta-token:${name}`);
      return render(ev, ctx, f, { eventType: f.action === "token_create" ? "system.api_token.create" : "system.api_token.revoke", result: "SUCCESS", reason: null,
        actor: me(), target: [{ alternateId: "unknown", detailEntry: null, displayName: name, id: tid, type: "Token" }],
        legacy: f.action === "token_create" ? "api.token.create" : null, requestUri: f.action === "token_create" ? "/api/internal/tokens" : `/api/internal/tokens/${tid}` });
    }
    case "token_grant": case "sso": {
      if (!f.appName) return null;
      const aid = oktaId(ctx, "0oa", `${ctx.companyId}:okta-app:${f.appName}`);
      return render(ev, ctx, f, { eventType: f.action === "sso" ? "user.authentication.sso" : "app.oauth2.as.token.grant", result: "SUCCESS", reason: null, actor: me(),
        target: [{ alternateId: f.appName, detailEntry: null, displayName: f.appName, id: aid, type: "AppInstance" }],
        requestUri: f.action === "sso" ? `/app/${f.appName.toLowerCase().replace(/[^a-z0-9]+/g, "")}/${aid}/sso/saml` : "/oauth2/v1/token" });
    }
    case "session_end":
      return render(ev, ctx, f, { eventType: "user.session.end", result: "SUCCESS", reason: null, actor: me(), target: null, requestUri: "/login/signout" });
    default:
      // consent / app_register / password_* / ca_policy_update / guest_invite / risk_change are Entra concepts with
      // no Okta System Log equivalent on the card; rate-limit events and Graph directory reads are not on the card.
      return null;
  }
}

// ── use cases ────────────────────────────────────────────────────────────────

const SESSION_FAIL = { all: [{ field: "eventType", op: "eq", value: "user.session.start" }, { field: "outcome.result", op: "eq", value: "FAILURE" }, { field: "outcome.reason", op: "eq", value: "INVALID_CREDENTIALS" }] } as const;
const PUSH_MFA = { all: [{ field: "eventType", op: "eq", value: "user.authentication.auth_via_mfa" }, { field: "debugContext.debugData.factor", op: "eq", value: "OKTA_VERIFY_PUSH" }] } as const;
const useCases: UseCase[] = [
  {
    id: "okta.password_spray", title: "Password spray — many users failing from one IP", sourceId: "okta", kinds: ["user.session.start"], severity: "high", mitre: ["T1110.003"],
    description: "user.session.start FAILURE / INVALID_CREDENTIALS for five or more different actor.alternateId values from one client.ipAddress in 10 minutes. Confirm with securityContext.asOrg (hosting provider?), a non-browser rawUserAgent and security.threat.detected.",
    logic: "Okta System Log / SPL: index=okta eventType=\"user.session.start\" outcome.result=FAILURE outcome.reason=INVALID_CREDENTIALS | bin _time span=10m | stats dc(actor.alternateId) AS users BY client.ipAddress, _time | where users>=5",
    match: SESSION_FAIL as unknown as UseCase["match"],
    threshold: { groupBy: ["client.ipAddress"], count: 5, windowSec: 600, distinct: "actor.alternateId" },
    falsePositives: ["Shared egress IP after a forced password change", "Load-test or IAM migration scripts"],
  },
  {
    id: "okta.brute_force", title: "Brute force against one account", sourceId: "okta", kinds: ["user.session.start"], severity: "high", mitre: ["T1110.001"],
    description: "Ten or more INVALID_CREDENTIALS failures for the same user inside 10 minutes.",
    logic: "SPL: index=okta eventType=\"user.session.start\" outcome.reason=INVALID_CREDENTIALS | bin _time span=10m | stats count BY actor.alternateId, _time | where count>=10",
    match: SESSION_FAIL as unknown as UseCase["match"],
    threshold: { groupBy: ["actor.alternateId"], count: 10, windowSec: 600 },
    falsePositives: ["A device with a cached old password retrying in the background"],
  },
  {
    id: "okta.bruteforce_then_success", title: "Failed passwords then a successful login from the same external IP", sourceId: "okta", kinds: ["user.session.start"], severity: "high", mitre: ["T1110", "T1078.004"],
    description: "The same user and the same IP outside any named network zone produce INVALID_CREDENTIALS failures and a SUCCESS within 30 minutes.",
    logic: "SPL: index=okta eventType=\"user.session.start\" client.zone=\"null\" (outcome.result=SUCCESS OR outcome.reason=INVALID_CREDENTIALS) | bin _time span=30m | stats dc(outcome.result) AS r BY actor.alternateId, client.ipAddress, _time | where r=2",
    match: { all: [{ field: "client.zone", op: "eq", value: "null" }, { any: [{ field: "outcome.result", op: "eq", value: "SUCCESS" }, { field: "outcome.reason", op: "eq", value: "INVALID_CREDENTIALS" }] },
      { field: "actor.alternateId", op: "neq", value: "unknown" }] },
    threshold: { groupBy: ["actor.alternateId", "client.ipAddress"], count: 2, windowSec: 1800, distinct: "outcome.result" },
    falsePositives: ["A remote employee mistyping the password once"],
  },
  {
    id: "okta.mfa_push_fatigue", title: "MFA push fatigue — repeated Okta Verify denials", sourceId: "okta", kinds: ["user.authentication.auth_via_mfa"], severity: "high", mitre: ["T1621"],
    description: "Three or more auth_via_mfa FAILURE events with factor OKTA_VERIFY_PUSH (pushOnlyResponseType OV_RESPONSE_DENY) for one user in 10 minutes. In an Identity Engine org this is how a rejected push is logged; denies never lock the account.",
    logic: "SPL: index=okta eventType=\"user.authentication.auth_via_mfa\" debugContext.debugData.factor=OKTA_VERIFY_PUSH outcome.result=FAILURE | bin _time span=10m | stats count BY actor.alternateId, _time | where count>=3",
    match: { all: [...PUSH_MFA.all, { field: "outcome.result", op: "eq", value: "FAILURE" }] } as unknown as UseCase["match"],
    threshold: { groupBy: ["actor.alternateId"], count: 3, windowSec: 600 },
    falsePositives: ["A user who keeps getting pushes from a stale browser tab and rejects them"],
  },
  {
    id: "okta.mfa_push_fatigue_approved", title: "Okta Verify denials followed by an approval in the same session", sourceId: "okta", kinds: ["user.authentication.auth_via_mfa"], severity: "critical", mitre: ["T1621", "T1078.004"],
    description: "Within one authenticationContext.externalSessionId the push was both denied (FAILURE) and finally approved (SUCCESS) — the attacker's fatigue campaign succeeded.",
    logic: "SPL: index=okta eventType=\"user.authentication.auth_via_mfa\" debugContext.debugData.factor=OKTA_VERIFY_PUSH | stats dc(outcome.result) AS r values(client.ipAddress) BY authenticationContext.externalSessionId | where r=2",
    match: PUSH_MFA as unknown as UseCase["match"],
    threshold: { groupBy: ["authenticationContext.externalSessionId"], count: 2, windowSec: 1800, distinct: "outcome.result" },
    falsePositives: ["A user who rejected one accidental prompt, then approved their own login"],
  },
  {
    id: "okta.threatinsight", title: "Okta ThreatInsight flagged the request", sourceId: "okta", kinds: ["security.threat.detected", "user.session.start"], severity: "high", mitre: ["T1110.003", "T1110.004"],
    description: "security.threat.detected (outcome.reason names the attack, e.g. Password Spray) or a user.session.start with debugData.threatSuspected = \"true\". The IP is on Okta's cross-tenant attack list.",
    logic: "SPL: index=okta (eventType=\"security.threat.detected\" OR debugContext.debugData.threatSuspected=\"true\")",
    match: { any: [{ field: "eventType", op: "eq", value: "security.threat.detected" }, { field: "debugContext.debugData.threatSuspected", op: "eq", value: "true" }] },
    falsePositives: ["Shared mobile-carrier NAT ranges occasionally listed"],
  },
  {
    id: "okta.anonymous_proxy_login", title: "Successful login through an anonymizing proxy", sourceId: "okta", kinds: ["user.session.start"], severity: "high", mitre: ["T1090.003", "T1078.004"],
    description: "user.session.start SUCCESS where securityContext.isProxy is true (Tor exit, anonymous VPN, residential proxy network).",
    logic: "SPL: index=okta eventType=\"user.session.start\" outcome.result=SUCCESS securityContext.isProxy=true",
    match: { all: [{ field: "outcome.result", op: "eq", value: "SUCCESS" }, { field: "securityContext.isProxy", op: "eq", value: true }] },
    falsePositives: ["Approved corporate VPN egress that Okta classifies as a proxy"],
  },
  {
    id: "okta.new_country_risky_login", title: "Login from a new country / anomalous location", sourceId: "okta", kinds: ["user.session.start", "policy.evaluate_sign_on"], severity: "medium", mitre: ["T1078.004"],
    description: "Okta's behaviour engine marked New Country or New Geo-Location as POSITIVE, or the risk engine scored the login HIGH. Compare client.geographicalContext.country and securityContext.asOrg with the user's 90-day baseline.",
    logic: "SPL: index=okta eventType IN (\"user.session.start\",\"policy.evaluate_sign_on\") (debugContext.debugData.behaviors=\"*New Country=POSITIVE*\" OR debugContext.debugData.risk=\"*level=HIGH*\")",
    match: { any: [{ field: "debugContext.debugData.behaviors", op: "contains", value: "New Country=POSITIVE" }, { field: "debugContext.debugData.behaviors", op: "contains", value: "New Geo-Location=POSITIVE" },
      { field: "debugContext.debugData.risk", op: "contains", value: "level=HIGH" }] },
    falsePositives: ["Business travel", "A user's first login from a new home ISP"],
  },
  {
    id: "okta.admin_privilege_granted", title: "Okta administrator privilege granted", sourceId: "okta", kinds: ["user.account.privilege.grant"], severity: "high", mitre: ["T1098.003"],
    description: "user.account.privilege.grant — a user received an Okta admin role (see debugData.privilegeGranted). A self-grant (actor = target) or a grant from a risky session is a takeover signal.",
    logic: "SPL: index=okta eventType=\"user.account.privilege.grant\" | table _time actor.alternateId target{}.alternateId debugContext.debugData.privilegeGranted client.ipAddress",
    match: { field: "eventType", op: "eq", value: "user.account.privilege.grant" },
    falsePositives: ["Planned on-boarding of a new IT administrator"],
  },
  {
    id: "okta.admin_group_membership", title: "User added to an admin / privileged Okta group", sourceId: "okta", kinds: ["group.user_membership.add"], severity: "medium", mitre: ["T1098.007"],
    description: "group.user_membership.add into a group whose name suggests admin or production-deploy rights.",
    logic: "SPL: index=okta eventType=\"group.user_membership.add\" target{}.displayName IN (\"*Admin*\",\"*Deployer*\",\"*Privileged*\")",
    match: { all: [{ field: "eventType", op: "eq", value: "group.user_membership.add" }, { field: "target[].displayName", op: "regex", value: "admin|deploy|privileg|super" }] },
    falsePositives: ["Change-ticketed role promotion"],
  },
  {
    id: "okta.mfa_factor_enrolled_external", title: "New MFA factor enrolled from outside the corporate zone", sourceId: "okta", kinds: ["user.mfa.factor.activate"], severity: "high", mitre: ["T1098.005"],
    description: "user.mfa.factor.activate from an IP in no named network zone. Minutes after a risky login (same externalSessionId) this is attacker persistence: their own Okta Verify on their own device.",
    logic: "SPL: index=okta eventType=\"user.mfa.factor.activate\" client.zone=\"null\" | join authenticationContext.externalSessionId [search index=okta eventType=\"user.session.start\" debugContext.debugData.risk=\"*HIGH*\"]",
    match: { all: [{ field: "eventType", op: "eq", value: "user.mfa.factor.activate" }, { field: "client.zone", op: "eq", value: "null" }] },
    falsePositives: ["A remote employee enrolling a replacement phone from home"],
  },
  {
    id: "okta.factor_reset", title: "Admin reset / removed another user's MFA factors", sourceId: "okta", kinds: ["user.mfa.factor.reset_all", "user.mfa.factor.deactivate"], severity: "medium", mitre: ["T1556.006", "T1098"],
    description: "user.mfa.factor.reset_all / deactivate. Legitimate after a help-desk ticket; malicious when done from a hijacked admin session to prepare another account takeover.",
    logic: "SPL: index=okta eventType IN (\"user.mfa.factor.reset_all\",\"user.mfa.factor.deactivate\") | table _time actor.alternateId target{}.alternateId client.ipAddress client.zone",
    match: { field: "eventType", op: "in", value: ["user.mfa.factor.reset_all", "user.mfa.factor.deactivate"] },
    falsePositives: ["Lost-phone procedure performed by the help desk"],
  },
  {
    id: "okta.api_token_created", title: "Okta API token created", sourceId: "okta", kinds: ["system.api_token.create"], severity: "medium", mitre: ["T1098.001", "T1528"],
    description: "system.api_token.create. A token carries its creator's admin rights and survives password resets — check who created it, from where, and revoke unknown tokens.",
    logic: "SPL: index=okta eventType=\"system.api_token.create\"",
    match: { field: "eventType", op: "eq", value: "system.api_token.create" },
    falsePositives: ["A new integration set up by the identity team"],
  },
  {
    id: "okta.lockout_burst", title: "Several accounts locked out from one IP", sourceId: "okta", kinds: ["user.account.lock"], severity: "high", mitre: ["T1110.003"],
    description: "Three or more user.account.lock events from one client.ipAddress in 30 minutes — collateral damage of a spray, not users mistyping.",
    logic: "SPL: index=okta eventType=\"user.account.lock\" | bin _time span=30m | stats dc(target{}.alternateId) AS locked BY client.ipAddress, _time | where locked>=3",
    match: { field: "eventType", op: "eq", value: "user.account.lock" },
    threshold: { groupBy: ["client.ipAddress"], count: 3, windowSec: 1800, distinct: "actor.alternateId" },
    falsePositives: ["A broken SSO integration replaying stale credentials"],
  },
];

export const source: NativeSource = { schema, fromTelemetry, useCases };
