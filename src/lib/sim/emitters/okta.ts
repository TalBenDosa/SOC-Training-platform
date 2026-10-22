/**
 * Okta Identity Cloud log EMITTERS.
 *
 * The SaaS identity plane — the tenant's OWN System Log view of every sign-in,
 * failure, MFA challenge, push response and rate-limit warning (a customer
 * firewall never sees this traffic). This is where password-spray, credential-
 * stuffing, impossible-travel and MFA-fatigue scenarios live.
 *
 * Same contract as the endpoint emitters: a typed call renders a complete
 * TelemetryEvent whose raw block uses only registry-valid Okta fields (the okta./
 * data.okta. prefixes + the shared ECS fields), with the user drawn from the
 * company fabric and the sign-in geography resolved deterministically from the
 * source IP (@/lib/geo/resolveGeo) unless the caller pins it. Okta is
 * control-plane (source:"okta") and carries no process.
 */
import type { TelemetryEvent, Severity, EventType } from "../types";
import { resolve, type Ctx } from "./_core";
import { hashString } from "../rng";
import { knownGeoForIp } from "@/lib/geo/resolveGeo";

const VENDOR = "Okta";

interface OktaGeo { country?: string; city?: string; latitude?: number; longitude?: number }

interface OktaCtx extends Ctx {
  /** sign-in origin (external attacker, or the user's egress). REQUIRED — Okta is
   *  identity, so the IP is the evidence, not a host address. */
  srcIp: string;
  displayName?: string;
  userTitle?: string;              // analyst-facing role chip (user_title)
  geo?: OktaGeo;                    // else resolved deterministically from srcIp
  userAgent?: string;
  os?: string;
  browser?: string;                // e.g. "CHROME"
  deviceType?: string;             // okta.client.device (default "Computer")
  asn?: number | string;
  asOrg?: string;
  isp?: string;
  domain?: string;                 // okta.securityContext.domain (the ISP/hosting domain)
  isProxy?: boolean;
  threatSuspected?: boolean;
  sessionId?: string;              // externalSessionId
  transactionId?: string;
  severity?: Severity;
  mitre?: string;
  tactic?: string;
  description?: string;
}

function displayFrom(email: string): string {
  const local = email.includes("@") ? email.split("@")[0] : email;
  return local.split(/[.\-_]/).map(s => s ? s[0].toUpperCase() + s.slice(1) : s).join(" ").trim() || local;
}
function geoOf(o: OktaCtx): OktaGeo | undefined {
  if (o.geo) return o.geo;
  const k = knownGeoForIp(o.srcIp);
  return k ? { country: k.country, city: k.city, latitude: k.lat, longitude: k.lon } : undefined;
}

interface BuildArgs {
  eventType: string;               // okta.eventType
  event_type: EventType;
  outcomeResult: "SUCCESS" | "FAILURE" | "CHALLENGE" | "ALLOW" | "DENY";
  ecsOutcome: "success" | "failure" | "unknown";
  reason?: string;
  displayMessage: string;
  authMethod: string;
  mfa?: boolean;
  factor?: string;
  requestUri?: string;             // debugContext.debugData.requestUri (Identity Engine path)
  pushResponse?: "OV_RESPONSE_APPROVE" | "OV_RESPONSE_DENY"; // debugData.pushOnlyResponseType
  credentialType?: string;         // PASSWORD | OTP
  targetAuthenticator?: string;    // e.g. "Okta Verify"
  oktaSeverity?: "INFO" | "WARN" | "ERROR";
  defaultSeverity: Severity;
  description: string;
  system?: boolean;                // a SystemPrincipal event (no user identity)
  extraRaw?: Record<string, string>;
}

function build(o: OktaCtx, a: BuildArgs): TelemetryEvent {
  const r = resolve(o);
  const email = a.system ? undefined : (r.email ?? `${r.bareUser}@example.com`);
  const geo = geoOf(o);
  const actorId = a.system ? undefined : `00u${hashString(`okta:${email}`).toString(36).slice(0, 17)}`;
  const sessionId = o.sessionId ?? `102${hashString(`sess:${o.id}`).toString(36).slice(0, 17)}`;
  const txId = o.transactionId ?? Buffer.from(`tx${hashString(o.id)}`).toString("base64").slice(0, 12);
  return {
    id: o.id, ts: o.ts, source: "okta", vendor: VENDOR, event_type: a.event_type,
    severity: o.severity ?? a.defaultSeverity, src_ip: o.srcIp, dst_port: 443, protocol: "tcp",
    user_email: email, user_title: o.userTitle, mitre_technique: o.mitre, mitre_tactic: o.tactic, incident_id: o.incidentId,
    geo, authentication: { method: a.authMethod, result: a.ecsOutcome === "success" ? "success" : "failure", ...(a.factor ? { mfa_type: a.factor } : {}) },
    description: a.description,
    raw: {
      "okta.eventType": a.eventType,
      "okta.displayMessage": a.displayMessage,
      "okta.outcome.result": a.outcomeResult,
      ...(a.reason ? { "okta.outcome.reason": a.reason } : {}),
      "okta.severity": a.oktaSeverity ?? "INFO",
      ...(actorId ? { "okta.actor.id": actorId } : {}),
      "okta.actor.type": a.system ? "SystemPrincipal" : "User",
      ...(email ? { "okta.actor.alternateId": email } : {}),
      "okta.actor.displayName": a.system ? "Okta System" : (o.displayName ?? displayFrom(email!)),
      "okta.client.ipAddress": o.srcIp,
      ...(o.userAgent ? { "okta.client.userAgent.rawUserAgent": o.userAgent } : {}),
      ...(o.os ? { "okta.client.userAgent.os": o.os } : {}),
      ...(o.browser ? { "okta.client.userAgent.browser": o.browser } : {}),
      ...(a.system ? {} : { "okta.client.device": o.deviceType ?? "Computer" }),
      ...(geo?.country ? { "okta.client.geographicalContext.country": geo.country } : {}),
      ...(geo?.city ? { "okta.client.geographicalContext.city": geo.city } : {}),
      ...(o.asn !== undefined ? { "okta.securityContext.asNumber": String(o.asn) } : {}),
      ...(o.asOrg ? { "okta.securityContext.asOrg": o.asOrg } : {}),
      ...((o.isp ?? o.asOrg) ? { "okta.securityContext.isp": (o.isp ?? o.asOrg)! } : {}),
      ...(o.domain ? { "okta.securityContext.domain": o.domain } : {}),
      "okta.securityContext.isProxy": String(o.isProxy ?? false),
      // authenticationStep is always 0 in the System Log (deprecated field, card idp-okta section 3.1).
      ...(a.system ? {} : { "okta.authenticationContext.authenticationStep": "0" }),
      ...(a.credentialType ? { "okta.authenticationContext.credentialType": a.credentialType } : {}),
      ...(a.system ? {} : { "okta.authenticationContext.externalSessionId": sessionId }),
      ...(a.targetAuthenticator ? { "okta.target.0.type": "AuthenticatorEnrollment", "okta.target.0.displayName": a.targetAuthenticator } : {}),
      "okta.transaction.id": txId,
      "okta.debugContext.debugData.requestUri": a.requestUri ?? "/idp/idx/identify",
      ...(o.threatSuspected !== undefined ? { "okta.debugContext.debugData.threatSuspected": String(o.threatSuspected) } : {}),
      ...(a.factor ? { "okta.debugContext.debugData.factor": a.factor } : {}),
      ...(a.pushResponse ? { "okta.debugContext.debugData.pushOnlyResponseType": a.pushResponse } : {}),
      ...(a.extraRaw ?? {}),
      "event.action": a.eventType,
      "event.outcome": a.ecsOutcome,
      "source.ip": o.srcIp,
      ...(geo?.country ? { "source.geo.country_name": geo.country } : {}),
      ...(geo?.city ? { "source.geo.city_name": geo.city } : {}),
      ...(email ? { "target.user.name": email, "target.user.email": email, "user.email": email } : {}),
      "authentication.method": a.authMethod,
      "authentication.status": a.ecsOutcome === "success" ? "success" : "failure",
      ...(a.mfa !== undefined ? { "authentication.mfa": String(a.mfa) } : {}),
      ...(a.factor ? { "authentication.factor": a.factor } : {}),
    },
  };
}

// ── Successful sign-in ────────────────────────────────────────────────────────────────
export interface OktaSignInOpts extends OktaCtx {
  mfaUsed?: boolean;
  factor?: string;
  /** Deprecated: the System Log always writes authenticationStep 0. Accepted, ignored. */
  authStep?: number;
}
export function oktaSignIn(o: OktaSignInOpts): TelemetryEvent {
  return build(o, {
    eventType: "user.session.start", event_type: "auth_success", outcomeResult: "SUCCESS", ecsOutcome: "success",
    displayMessage: "User login to Okta", authMethod: o.mfaUsed ? "MFA" : "PASSWORD",
    mfa: o.mfaUsed, factor: o.mfaUsed ? (o.factor ?? "OKTA_VERIFY_PUSH") : undefined,
    credentialType: o.mfaUsed ? "OTP" : undefined,
    defaultSeverity: "medium",
    description: o.description ?? `Okta sign-in success for ${o.user ?? "the user"} from ${o.srcIp}`,
  });
}

// ── Failed sign-in (spray / stuffing). user.session.start FAILURE reasons are INVALID_CREDENTIALS,
//    VERIFICATION_ERROR or LOCKED_OUT (card idp-okta section 3.3). "The password was accepted and the
//    transaction moved on to the second factor" is NOT a failure in Okta: it is the sign-on policy
//    answering CHALLENGE (policy.evaluate_sign_on). reason "MFA_REQUIRED" (the legacy spelling of that
//    tell) renders that record.
export interface OktaAuthFailureOpts extends OktaCtx {
  reason?: string;                 // default INVALID_CREDENTIALS; "MFA_REQUIRED" renders policy.evaluate_sign_on CHALLENGE
  /** Deprecated: the System Log always writes authenticationStep 0. Accepted, ignored. */
  authStep?: number;
}
export function oktaAuthFailure(o: OktaAuthFailureOpts): TelemetryEvent {
  if (o.reason === "MFA_REQUIRED") return oktaPolicyChallenge(o);
  const reason = o.reason ?? "INVALID_CREDENTIALS";
  return build(o, {
    eventType: "user.session.start", event_type: "auth_failure", outcomeResult: "FAILURE", ecsOutcome: "failure",
    reason, displayMessage: "User login to Okta", authMethod: "PASSWORD",
    credentialType: "PASSWORD", defaultSeverity: "low", oktaSeverity: "WARN",
    description: o.description ?? `Okta sign-in FAILURE (${reason}) for ${o.user ?? "the user"} from ${o.srcIp}`,
  });
}

// ── Sign-on policy evaluation: the password was right and the policy demands the second factor ──
export function oktaPolicyChallenge(o: OktaCtx): TelemetryEvent {
  return build(o, {
    eventType: "policy.evaluate_sign_on", event_type: "mfa_challenge", outcomeResult: "CHALLENGE", ecsOutcome: "unknown",
    reason: "Sign-on policy evaluation resulted in CHALLENGE", displayMessage: "Evaluation of sign-on policy", authMethod: "PASSWORD",
    defaultSeverity: "medium", requestUri: "/idp/idx/identify",
    description: o.description ?? `Okta sign-on policy CHALLENGE for ${o.user ?? "the user"} from ${o.srcIp}`,
  });
}

// ── MFA factor: challenge issued / push approved / push rejected (fatigue) ─────────────
export interface OktaMfaOpts extends OktaCtx {
  result: "challenge" | "approved" | "denied" | "sent";
  factor?: string;                 // default OKTA_VERIFY_PUSH
}
export function oktaMfa(o: OktaMfaOpts): TelemetryEvent {
  const factor = o.factor ?? "OKTA_VERIFY_PUSH";
  // Real Identity Engine event types (card idp-okta sections 1 and 3.3): a push sent is
  // system.push.send_factor_verify_push SUCCESS; the user's answer is user.authentication.auth_via_mfa,
  // SUCCESS with OV_RESPONSE_APPROVE or FAILURE / INVALID_CREDENTIALS with OV_RESPONSE_DENY; the
  // "second factor required" step is the sign-on policy answering CHALLENGE.
  if (o.result === "challenge") return oktaPolicyChallenge(o);
  const push = factor === "OKTA_VERIFY_PUSH";
  const m = {
    sent:     { et: "system.push.send_factor_verify_push", ev: "mfa_push_sent" as EventType, out: "SUCCESS" as const, ecs: "success" as const, msg: "Send factor verify push", reason: undefined, sev: "medium" as Severity, oktaSev: "INFO" as const, resp: undefined, uri: "/idp/idx/challenge" },
    approved: { et: "user.authentication.auth_via_mfa",    ev: "mfa_challenge" as EventType, out: "SUCCESS" as const, ecs: "success" as const, msg: "Authentication of user via MFA", reason: undefined, sev: "medium" as Severity, oktaSev: "INFO" as const, resp: push ? "OV_RESPONSE_APPROVE" as const : undefined, uri: "/idp/idx/authenticators/poll" },
    denied:   { et: "user.authentication.auth_via_mfa",    ev: "mfa_denied" as EventType,    out: "FAILURE" as const, ecs: "failure" as const, msg: "Authentication of user via MFA", reason: "INVALID_CREDENTIALS", sev: "high" as Severity, oktaSev: "WARN" as const, resp: push ? "OV_RESPONSE_DENY" as const : undefined, uri: "/idp/idx/authenticators/poll" },
  }[o.result];
  return build(o, {
    eventType: m.et, event_type: m.ev, outcomeResult: m.out, ecsOutcome: m.ecs, reason: m.reason,
    displayMessage: m.msg, authMethod: "MFA", mfa: true, factor, credentialType: o.result === "sent" ? undefined : "OTP",
    targetAuthenticator: "Okta Verify", oktaSeverity: m.oktaSev, defaultSeverity: m.sev, pushResponse: m.resp, requestUri: m.uri,
    description: o.description ?? `Okta MFA ${o.result} (${factor}) for ${o.user ?? "the user"} from ${o.srcIp}`,
  });
}

// ── System event (rate-limit warning, etc.) — no user identity ────────────────────────
export interface OktaSystemOpts extends OktaCtx {
  eventType: string;               // e.g. "system.org.rate_limit.warning"
  displayMessage: string;
  event_type?: EventType;          // default "http_blocked"
  outcome?: "SUCCESS" | "FAILURE";
  thresholds?: Record<string, string>;  // debugData.threshold / timeSpan / timeUnit …
}
export function oktaSystem(o: OktaSystemOpts): TelemetryEvent {
  const extra: Record<string, string> = {};
  for (const [k, v] of Object.entries(o.thresholds ?? {})) extra[`okta.debugContext.debugData.${k}`] = v;
  return build(o, {
    eventType: o.eventType, event_type: o.event_type ?? "http_blocked",
    outcomeResult: o.outcome ?? "SUCCESS", ecsOutcome: (o.outcome ?? "SUCCESS") === "SUCCESS" ? "success" : "failure",
    displayMessage: o.displayMessage, authMethod: "N/A", oktaSeverity: "WARN",
    defaultSeverity: o.severity ?? "low", system: true, extraRaw: extra,
    description: o.description ?? `Okta system event: ${o.displayMessage}`,
  });
}
