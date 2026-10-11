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
  outcomeResult: "SUCCESS" | "FAILURE" | "CHALLENGE" | "DENIED";
  ecsOutcome: "success" | "failure" | "unknown";
  reason?: string;
  displayMessage: string;
  authMethod: string;
  mfa?: boolean;
  factor?: string;
  authStep?: number;               // authenticationContext.authenticationStep
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
      ...(a.authStep !== undefined ? { "okta.authenticationContext.authenticationStep": String(a.authStep) } : {}),
      ...(a.credentialType ? { "okta.authenticationContext.credentialType": a.credentialType } : {}),
      ...(a.event_type.startsWith("mfa") || a.authStep ? { "okta.authenticationContext.externalSessionId": sessionId } : {}),
      ...(a.targetAuthenticator ? { "okta.target.0.type": "AuthenticatorEnrollment", "okta.target.0.displayName": a.targetAuthenticator } : {}),
      "okta.transaction.id": txId,
      "okta.debugContext.debugData.requestUri": "/api/v1/authn",
      ...(o.threatSuspected !== undefined ? { "okta.debugContext.debugData.threatSuspected": String(o.threatSuspected) } : {}),
      ...(a.factor ? { "okta.debugContext.debugData.factor": a.factor } : {}),
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
  authStep?: number;
}
export function oktaSignIn(o: OktaSignInOpts): TelemetryEvent {
  return build(o, {
    eventType: "user.session.start", event_type: "auth_success", outcomeResult: "SUCCESS", ecsOutcome: "success",
    displayMessage: "User login to Okta", authMethod: o.mfaUsed ? "MFA" : "PASSWORD",
    mfa: o.mfaUsed, factor: o.mfaUsed ? (o.factor ?? "OKTA_VERIFY_PUSH") : undefined,
    authStep: o.authStep ?? (o.mfaUsed ? 1 : undefined), credentialType: o.mfaUsed ? "OTP" : undefined,
    defaultSeverity: "medium",
    description: o.description ?? `Okta sign-in success for ${o.user ?? "the user"} from ${o.srcIp}`,
  });
}

// ── Failed sign-in (spray / stuffing) — set reason:"MFA_REQUIRED" + authStep:1 for the
//    tell that the PASSWORD was finally accepted and the transaction reached the factor.
export interface OktaAuthFailureOpts extends OktaCtx {
  reason?: string;                 // default INVALID_CREDENTIALS
  authStep?: number;               // 0 = password rejected; 1 = password accepted, MFA required
}
export function oktaAuthFailure(o: OktaAuthFailureOpts): TelemetryEvent {
  const reason = o.reason ?? "INVALID_CREDENTIALS";
  return build(o, {
    eventType: "user.session.start", event_type: "auth_failure", outcomeResult: "FAILURE", ecsOutcome: "failure",
    reason, displayMessage: "User login to Okta", authMethod: "PASSWORD",
    authStep: o.authStep ?? 0, credentialType: "PASSWORD", defaultSeverity: "low",
    description: o.description ?? `Okta sign-in FAILURE (${reason}) for ${o.user ?? "the user"} from ${o.srcIp}`,
  });
}

// ── MFA factor: challenge issued / push approved / push rejected (fatigue) ─────────────
export interface OktaMfaOpts extends OktaCtx {
  result: "challenge" | "approved" | "denied" | "sent";
  factor?: string;                 // default OKTA_VERIFY_PUSH
}
export function oktaMfa(o: OktaMfaOpts): TelemetryEvent {
  const factor = o.factor ?? "OKTA_VERIFY_PUSH";
  const m = {
    sent:      { et: "system.push.send_factor_verify_push", ev: "mfa_push_sent" as EventType, out: "SUCCESS" as const, ecs: "success" as const, msg: "Send factor verify push", reason: undefined, sev: "medium" as Severity, oktaSev: "INFO" as const },
    challenge: { et: "user.authentication.auth_via_mfa",    ev: "mfa_challenge" as EventType, out: "CHALLENGE" as const, ecs: "unknown" as const, msg: "Authentication of user via MFA", reason: undefined, sev: "medium" as Severity, oktaSev: "INFO" as const },
    approved:  { et: "user.authentication.auth_via_mfa",    ev: "mfa_challenge" as EventType, out: "SUCCESS" as const, ecs: "success" as const, msg: "Authentication of user via MFA", reason: undefined, sev: "medium" as Severity, oktaSev: "INFO" as const },
    denied:    { et: "user.mfa.okta_verify.push_response",  ev: "mfa_denied" as EventType,    out: "DENIED" as const, ecs: "failure" as const, msg: "MFA push notification denied", reason: "USER_REJECTED_PUSH", sev: "high" as Severity, oktaSev: "WARN" as const },
  }[o.result];
  return build(o, {
    eventType: m.et, event_type: m.ev, outcomeResult: m.out, ecsOutcome: m.ecs, reason: m.reason,
    displayMessage: m.msg, authMethod: "MFA", mfa: true, factor, authStep: 1, credentialType: "OTP",
    targetAuthenticator: "Okta Verify", oktaSeverity: m.oktaSev, defaultSeverity: m.sev,
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
