/**
 * Microsoft Entra ID (Azure AD) sign-in log EMITTER.
 *
 * The Microsoft identity plane — the Entra sign-in log an analyst reads for
 * impossible-travel, token-replay, MFA, conditional-access and password-spray
 * cases on a Microsoft-stack tenant. Same contract as the other emitters: a
 * typed call renders a complete TelemetryEvent whose raw block uses only
 * registry-valid Entra fields (the azure.signinlogs. prefix + GeoLocation.*),
 * with the user drawn from the company fabric and the sign-in geography resolved
 * DETERMINISTICALLY from the source IP (@/lib/geo/resolveGeo) so one IP always
 * reads as one place — the same rule the feed and the threat-intel pivot use.
 *
 * Entra sign-ins are surfaced under source:"o365" (the tenant's unified log),
 * carry no process, and match the shape the existing packs author by hand.
 */
import type { TelemetryEvent, Severity } from "../types";
import { resolve, type Ctx } from "./_core";
import { hashString } from "../rng";
import { knownGeoForIp } from "@/lib/geo/resolveGeo";

const VENDOR = "Microsoft Entra ID";

interface EntraGeo { country?: string; city?: string; latitude?: number; longitude?: number; countryCode?: string }

// Entra sign-in failure result codes (resultType) → human resultDescription.
const ERROR_DESC: Record<string, string> = {
  "50126": "Error validating credentials due to invalid username or password.",
  "50074": "Strong Authentication is required.",
  "50053": "Account is locked because the user tried to sign in too many times with an incorrect ID or password.",
  "50055": "The password is expired.",
  "53003": "Access has been blocked by Conditional Access policies.",
  "50158": "External security challenge was not satisfied.",
};

// Rough ISO-2 for the countries the fabric/KNOWN_GEO use (display only).
const ISO2: Record<string, string> = {
  "United Kingdom": "GB", "United States": "US", "Israel": "IL", "Netherlands": "NL",
  "Germany": "DE", "Switzerland": "CH", "Russia": "RU", "China": "CN", "Ukraine": "UA",
  "France": "FR", "Nigeria": "NG", "India": "IN", "Brazil": "BR", "Hong Kong": "HK",
  "Romania": "RO", "Bulgaria": "BG", "Iceland": "IS", "Singapore": "SG",
};

export interface EntraSignInOpts extends Ctx {
  srcIp: string;
  displayName?: string;             // userDisplayName
  userTitle?: string;
  result?: "success" | "failure";   // default success
  errorCode?: string;               // resultType on failure (default 50126)
  app?: string;                     // appDisplayName (default "Office 365 Exchange Online")
  appId?: string;
  resource?: string;                // resourceDisplayName
  mfa?: boolean;                    // authenticationRequirement multiFactor vs singleFactor
  isInteractive?: boolean;          // default true
  managed?: boolean;                // deviceDetail.isManaged
  compliant?: boolean;              // deviceDetail.isCompliant
  deviceId?: string;
  os?: string;                      // deviceDetail.operatingSystem
  browser?: string;                 // deviceDetail.browser
  trustType?: string;               // deviceDetail.trustType (e.g. "Azure AD joined")
  userAgent?: string;
  asn?: number | string;            // autonomousSystemNumber
  riskLevel?: "none" | "low" | "medium" | "high";
  riskDetail?: string;
  riskEventTypes?: string[];        // riskEventTypes_v2 (e.g. unfamiliarFeatures, anonymizedIPAddress)
  conditionalAccess?: "success" | "failure" | "notApplicable";
  sessionId?: string;
  deviceName?: string;              // deviceDetail.displayName
  incomingTokenType?: string;       // e.g. "primaryRefreshToken" — the token-replay tell
  tokenIssuerType?: string;         // e.g. "AzureAD" | "ADFSFederated"
  tokenIssuerName?: string;         // federation issuer URI (ADFSFederated sign-ins)
  federatedTokenId?: string;        // pairs a cloud sign-in with an on-prem AD FS issuance
  authenticationProtocol?: string;  // e.g. "saml20"
  authStepResultDetail?: string;    // authenticationDetails step detail (e.g. MFA-by-claim)
  userId?: string;
  geo?: EntraGeo;                   // else resolved deterministically from srcIp
  severity?: Severity;
  mitre?: string;
  tactic?: string;
  description?: string;
}

function geoOf(o: EntraSignInOpts): EntraGeo | undefined {
  if (o.geo) return o.geo;
  const k = knownGeoForIp(o.srcIp);
  return k ? { country: k.country, city: k.city, latitude: k.lat, longitude: k.lon } : undefined;
}

export function entraSignIn(o: EntraSignInOpts): TelemetryEvent {
  const r = resolve(o);
  const email = r.email ?? `${r.bareUser}@example.com`;
  const success = (o.result ?? "success") === "success";
  const geo = geoOf(o);
  const iso2 = geo?.countryCode ?? (geo?.country ? ISO2[geo.country] ?? "" : "");
  const errorCode = success ? "0" : (o.errorCode ?? "50126");
  const app = o.app ?? "Office 365 Exchange Online";
  const authReq = o.mfa ? "multiFactorAuthentication" : "singleFactorAuthentication";
  const corr = `${hashString(`corr:${o.id}`).toString(16).padStart(8, "0")}-0000-0000-0000-000000000000`;
  const signInId = `${hashString(`sid:${o.id}`).toString(16).padStart(8, "0")}-1111-2222-3333-444455556666`;
  const ecsOutcome = success ? "success" : "failure";
  return {
    id: o.id, ts: o.ts, source: "o365", vendor: VENDOR,
    event_type: success ? "auth_success" : "auth_failure",
    severity: o.severity ?? (success ? "medium" : "low"),
    src_ip: o.srcIp, user_email: email, user_title: o.userTitle, mitre_technique: o.mitre, mitre_tactic: o.tactic,
    incident_id: o.incidentId, geo,
    authentication: { method: o.mfa ? "MFA" : "Password", result: ecsOutcome, ...(o.mfa ? { mfa_type: "Authenticator" } : {}) },
    description: o.description ?? `Entra sign-in ${success ? "success" : `failure (${errorCode})`} for ${email} from ${o.srcIp}`,
    raw: {
      "azure.signinlogs.operationName": "Sign-in activity",
      "azure.signinlogs.category": "SignInLogs",
      "azure.signinlogs.resultType": errorCode,
      "azure.signinlogs.resultDescription": success ? "" : (ERROR_DESC[errorCode] ?? "Sign-in failed."),
      "azure.signinlogs.properties.id": signInId,
      "azure.signinlogs.properties.correlationId": corr,
      "azure.signinlogs.properties.createdDateTime": o.ts,
      "azure.signinlogs.properties.userPrincipalName": email,
      "azure.signinlogs.properties.userDisplayName": o.displayName ?? r.bareUser,
      ...(o.userId ? { "azure.signinlogs.properties.userId": o.userId } : {}),
      "azure.signinlogs.properties.appDisplayName": app,
      ...(o.appId ? { "azure.signinlogs.properties.appId": o.appId } : {}),
      ...(o.resource ? { "azure.signinlogs.properties.resourceDisplayName": o.resource } : {}),
      "azure.signinlogs.properties.clientAppUsed": "Browser",
      "azure.signinlogs.properties.ipAddress": o.srcIp,
      "azure.signinlogs.properties.isInteractive": String(o.isInteractive ?? true),
      ...(o.asn !== undefined ? { "azure.signinlogs.properties.autonomousSystemNumber": String(o.asn) } : {}),
      ...(geo?.city ? { "azure.signinlogs.properties.location.city": geo.city } : {}),
      ...(iso2 ? { "azure.signinlogs.properties.location.countryOrRegion": iso2 } : {}),
      ...(geo?.latitude != null ? { "azure.signinlogs.properties.location.geoCoordinates.latitude": geo.latitude } : {}),
      ...(geo?.longitude != null ? { "azure.signinlogs.properties.location.geoCoordinates.longitude": geo.longitude } : {}),
      ...(o.userAgent ? { "azure.signinlogs.properties.userAgent": o.userAgent } : {}),
      "azure.signinlogs.properties.authenticationRequirement": authReq,
      "azure.signinlogs.properties.conditionalAccessStatus": o.conditionalAccess ?? (success ? "success" : "notApplicable"),
      "azure.signinlogs.properties.deviceDetail.deviceId": o.deviceId ?? "",
      ...(o.deviceName ? { "azure.signinlogs.properties.deviceDetail.displayName": o.deviceName } : {}),
      "azure.signinlogs.properties.deviceDetail.isManaged": String(o.managed ?? false),
      "azure.signinlogs.properties.deviceDetail.isCompliant": String(o.compliant ?? false),
      ...(o.os ? { "azure.signinlogs.properties.deviceDetail.operatingSystem": o.os } : {}),
      ...(o.browser ? { "azure.signinlogs.properties.deviceDetail.browser": o.browser } : {}),
      ...(o.trustType ? { "azure.signinlogs.properties.deviceDetail.trustType": o.trustType } : {}),
      "azure.signinlogs.properties.riskLevelDuringSignIn": o.riskLevel ?? "none",
      ...(o.riskDetail ? { "azure.signinlogs.properties.riskDetail": o.riskDetail } : {}),
      ...(o.riskEventTypes ? { "azure.signinlogs.properties.riskEventTypes_v2": o.riskEventTypes } : {}),
      "azure.signinlogs.properties.riskState": (o.riskLevel && o.riskLevel !== "none") ? "atRisk" : "none",
      ...(o.sessionId ? { "azure.signinlogs.properties.sessionId": o.sessionId } : {}),
      ...(o.incomingTokenType ? { "azure.signinlogs.properties.incomingTokenType": o.incomingTokenType } : {}),
      "azure.signinlogs.properties.tokenIssuerType": o.tokenIssuerType ?? "AzureAD",
      ...(o.tokenIssuerName ? { "azure.signinlogs.properties.tokenIssuerName": o.tokenIssuerName } : {}),
      ...(o.federatedTokenId ? { "azure.signinlogs.properties.federatedTokenId": o.federatedTokenId } : {}),
      ...(o.authenticationProtocol ? { "azure.signinlogs.properties.authenticationProtocol": o.authenticationProtocol } : {}),
      ...(o.authStepResultDetail ? { "azure.signinlogs.properties.authenticationDetails.authenticationStepResultDetail": o.authStepResultDetail } : {}),
      "azure.signinlogs.properties.status.errorCode": errorCode,
      // Shared geo (what the feed enrichment + threat-intel pivot read).
      ...(geo?.country ? { "GeoLocation.country_name": geo.country } : {}),
      ...(geo?.city ? { "GeoLocation.city_name": geo.city } : {}),
      ...(geo?.latitude != null ? { "GeoLocation.latitude": geo.latitude } : {}),
      ...(geo?.longitude != null ? { "GeoLocation.longitude": geo.longitude } : {}),
      // event.outcome / user.email are NOT valid Entra fields (the vendor carries
      // outcome in resultType and identity in userPrincipalName); source.ip is a
      // shared common field, kept so cross-source IP pivots still resolve.
      "source.ip": o.srcIp,
    },
  };
}
