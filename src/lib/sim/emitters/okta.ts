/**
 * Okta Identity Cloud log EMITTERS.
 *
 * The SaaS identity plane — the tenant's OWN System Log view of every sign-in,
 * failure, and MFA challenge (a customer firewall never sees this traffic). This
 * is where password-spray, impossible-travel and MFA-fatigue scenarios live.
 *
 * Same contract as the endpoint emitters: a typed call renders a complete
 * TelemetryEvent whose raw block uses only registry-valid Okta fields (the okta./
 * data.okta. prefixes + the shared ECS fields event./source./target.user./
 * authentication.*), with the user drawn from the company fabric and the sign-in
 * geography resolved DETERMINISTICALLY from the source IP (@/lib/geo/resolveGeo),
 * so one IP always reads as one place — the same rule the feed and the
 * threat-intel pivot use.
 *
 * Okta is control-plane (source:"okta"), so these events carry no process.
 */
import type { TelemetryEvent, Severity } from "../types";
import { resolve, type Ctx } from "./_core";
import { hashString } from "../rng";
import { knownGeoForIp } from "@/lib/geo/resolveGeo";

const VENDOR = "Okta";

interface OktaGeo { country?: string; city?: string; latitude?: number; longitude?: number }

interface OktaCtx extends Ctx {
  /** sign-in origin (external attacker, or the user's egress). REQUIRED — Okta is
   *  identity, so the IP is the evidence, not a host address. */
  srcIp: string;
  displayName?: string;             // okta.actor.displayName; derived from the email if omitted
  geo?: OktaGeo;                    // else resolved deterministically from srcIp
  userAgent?: string;
  os?: string;                     // okta.client.userAgent.os
  browser?: string;                // okta.client.userAgent.browser (e.g. "CHROME")
  deviceType?: string;             // okta.client.device (e.g. "Computer")
  asn?: number | string;           // okta.securityContext.asNumber
  asOrg?: string;                  // okta.securityContext.asOrg / isp
  isp?: string;
  isProxy?: boolean;
  sessionId?: string;              // okta.authenticationContext.externalSessionId
  app?: string;                    // the target app (SSO)
  severity?: Severity;
  mitre?: string;
  tactic?: string;
  description?: string;
}

// Title-case a dotted login local part → a display name ("m.ben-david" → "M Ben-David").
function displayFrom(email: string): string {
  const local = email.includes("@") ? email.split("@")[0] : email;
  return local.split(/[.\-_]/).map(s => s ? s[0].toUpperCase() + s.slice(1) : s).join(" ").trim() || local;
}

function geoOf(o: OktaCtx): OktaGeo | undefined {
  if (o.geo) return o.geo;
  const k = knownGeoForIp(o.srcIp);
  return k ? { country: k.country, city: k.city, latitude: k.lat, longitude: k.lon } : undefined;
}

// Shared renderer for every Okta System Log record.
function build(o: OktaCtx, args: {
  eventType: string; event_type: TelemetryEvent["event_type"]; outcome: "SUCCESS" | "FAILURE";
  reason?: string; displayMessage: string; authMethod: string; mfa?: boolean; factor?: string;
  defaultSeverity: Severity; description: string;
}): TelemetryEvent {
  const r = resolve(o);
  const email = r.email ?? `${r.bareUser}@example.com`;
  const geo = geoOf(o);
  const actorId = `00u${hashString(`okta:${email}`).toString(36).slice(0, 17)}`;
  const sessionId = o.sessionId ?? `102${hashString(`sess:${o.id}`).toString(36).slice(0, 17)}`;
  const ecsOutcome = args.outcome === "SUCCESS" ? "success" : "failure";
  return {
    id: o.id, ts: o.ts, source: "okta", vendor: VENDOR, event_type: args.event_type,
    severity: o.severity ?? args.defaultSeverity, src_ip: o.srcIp, dst_port: 443, protocol: "tcp",
    user_email: email, mitre_technique: o.mitre, mitre_tactic: o.tactic, incident_id: o.incidentId,
    geo, authentication: { method: args.authMethod, result: ecsOutcome, ...(args.factor ? { mfa_type: args.factor } : {}) },
    description: args.description,
    raw: {
      "okta.eventType": args.eventType,
      "okta.displayMessage": args.displayMessage,
      "okta.outcome.result": args.outcome,
      ...(args.reason ? { "okta.outcome.reason": args.reason } : {}),
      "okta.severity": args.outcome === "FAILURE" ? "INFO" : "INFO",
      "okta.actor.id": actorId,
      "okta.actor.type": "User",
      "okta.actor.alternateId": email,
      "okta.actor.displayName": o.displayName ?? displayFrom(email),
      "okta.client.ipAddress": o.srcIp,
      ...(o.userAgent ? { "okta.client.userAgent.rawUserAgent": o.userAgent } : {}),
      ...(o.os ? { "okta.client.userAgent.os": o.os } : {}),
      ...(o.browser ? { "okta.client.userAgent.browser": o.browser } : {}),
      "okta.client.device": o.deviceType ?? "Computer",
      ...(geo?.country ? { "okta.client.geographicalContext.country": geo.country } : {}),
      ...(geo?.city ? { "okta.client.geographicalContext.city": geo.city } : {}),
      ...(o.asn !== undefined ? { "okta.securityContext.asNumber": String(o.asn) } : {}),
      ...(o.asOrg ? { "okta.securityContext.asOrg": o.asOrg } : {}),
      ...(o.isp ?? o.asOrg ? { "okta.securityContext.isp": o.isp ?? o.asOrg! } : {}),
      "okta.securityContext.isProxy": String(o.isProxy ?? false),
      "okta.authenticationContext.externalSessionId": sessionId,
      ...(args.mfa !== undefined ? { "okta.authenticationContext.credentialType": args.mfa ? "OTP" : "PASSWORD" } : {}),
      ...(o.app ? { "okta.target.0.displayName": o.app, "okta.target.0.type": "AppInstance" } : {}),
      "okta.debugContext.debugData.requestUri": "/api/v1/authn",
      "event.action": args.eventType,
      "event.outcome": ecsOutcome,
      "source.ip": o.srcIp,
      ...(geo?.country ? { "source.geo.country_name": geo.country } : {}),
      ...(geo?.city ? { "source.geo.city_name": geo.city } : {}),
      "target.user.name": email,
      "target.user.email": email,
      "user.email": email,
      "authentication.method": args.authMethod,
      "authentication.status": ecsOutcome,
      ...(args.mfa !== undefined ? { "authentication.mfa": String(args.mfa) } : {}),
      ...(args.factor ? { "authentication.factor": args.factor } : {}),
    },
  };
}

// ── Successful sign-in (user.session.start / SSO) ────────────────────────────────────
export interface OktaSignInOpts extends OktaCtx {
  mfaUsed?: boolean;               // true → an MFA factor was satisfied this sign-in
  factor?: string;                // e.g. "OKTA_VERIFY_PUSH", "GOOGLE_OTP"
}
export function oktaSignIn(o: OktaSignInOpts): TelemetryEvent {
  return build(o, {
    eventType: "user.session.start", event_type: "auth_success", outcome: "SUCCESS",
    displayMessage: "User login to Okta", authMethod: o.mfaUsed ? "MFA" : "PASSWORD",
    mfa: o.mfaUsed, factor: o.mfaUsed ? (o.factor ?? "OKTA_VERIFY_PUSH") : undefined,
    defaultSeverity: "medium",
    description: o.description ?? `Okta sign-in success for ${o.user ?? "the user"} from ${o.srcIp}`,
  });
}

// ── Failed sign-in (password spray / brute force / stuffing) ──────────────────────────
export interface OktaAuthFailureOpts extends OktaCtx {
  reason?: string;                // okta.outcome.reason (default INVALID_CREDENTIALS)
}
export function oktaAuthFailure(o: OktaAuthFailureOpts): TelemetryEvent {
  return build(o, {
    eventType: "user.session.start", event_type: "auth_failure", outcome: "FAILURE",
    reason: o.reason ?? "INVALID_CREDENTIALS", displayMessage: "User login to Okta",
    authMethod: "PASSWORD", defaultSeverity: "low",
    description: o.description ?? `Okta sign-in FAILURE (${o.reason ?? "INVALID_CREDENTIALS"}) for ${o.user ?? "the user"} from ${o.srcIp}`,
  });
}

// ── MFA factor challenge (push sent / approved / denied — MFA-fatigue) ─────────────────
export interface OktaMfaOpts extends OktaCtx {
  result: "sent" | "approved" | "denied";
  factor?: string;                // default OKTA_VERIFY_PUSH
}
export function oktaMfa(o: OktaMfaOpts): TelemetryEvent {
  const factor = o.factor ?? "OKTA_VERIFY_PUSH";
  const map = {
    sent:     { et: "system.push.send_factor_verify_push", ev: "mfa_push_sent" as const, outcome: "SUCCESS" as const, msg: "Send factor verify push", reason: undefined },
    approved: { et: "user.authentication.auth_via_mfa",    ev: "mfa_challenge" as const, outcome: "SUCCESS" as const, msg: "Authentication of user via MFA", reason: undefined },
    denied:   { et: "user.mfa.okta_verify.deny_push",      ev: "mfa_denied" as const,    outcome: "FAILURE" as const, msg: "User rejected Okta push verify", reason: "USER_REJECTED" },
  }[o.result];
  return build(o, {
    eventType: map.et, event_type: map.ev, outcome: map.outcome, reason: map.reason,
    displayMessage: map.msg, authMethod: "MFA", mfa: true, factor,
    defaultSeverity: o.result === "denied" ? "high" : "medium",
    description: o.description ?? `Okta MFA ${o.result} (${factor}) for ${o.user ?? "the user"} from ${o.srcIp}`,
  });
}
