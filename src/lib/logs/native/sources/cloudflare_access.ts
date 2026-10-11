/**
 * Cloudflare Zero Trust — Access authentication events (Logpush dataset `access_requests`).
 * Card: docs/log-schemas/ztna-cloudflare-access.md
 *
 * JSON-native: the full 15-field flat object, timestamp_format=rfc3339 (UTC, "Z").
 * Kind = Action ("login" / "logout").
 *
 * Rendering of the platform's VPN events (cross-vendor — the corpus has no Cloudflare-authored
 * events): a remote-access login becomes the WARP client's Access login
 * (AppDomain `<team>.cloudflareaccess.com/warp`, the device-enrolment application), a logout
 * becomes Action=logout. Returns null for:
 *   - authentication failures / MFA challenge / MFA denied — Access delegates authentication to the
 *     IdP (SAML/OIDC), so password guessing and MFA prompts are logged by the IdP; an Access
 *     `Allowed:false` record means the IdP step SUCCEEDED and Access policy denied, which is a
 *     different fact than a wrong password;
 *   - events without the client IP (every record carries IPAddress).
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { NativeCtx, NativeLog, NativeSource, SourceSchema, UseCase } from "../types";
import { vpnFacts, homeCountry, isoSec, emailDomain, HIGH_RISK_ISO, type VpnFacts } from "./remote-access-shared";

export const CF_KEYS = [
  "Action", "Allowed", "AppDomain", "AppUUID", "Connection", "Country", "CreatedAt", "Email", "IPAddress",
  "PurposeJustificationPrompt", "PurposeJustificationResponse", "RayID", "TemporaryAccessApprovers",
  "TemporaryAccessDuration", "UserUID",
];

const schema: SourceSchema = {
  sourceId: "cloudflare_access",
  // Category "vpn" (not "ztna"): the platform picks ONE remote-access product per session and
  // this module renders the same TelemetryEvent.source="vpn" events as the VPN modules.
  category: "vpn",
  card: "ztna-cloudflare-access.md",
  product: "Cloudflare Zero Trust Access",
  format: "ndjson",
  vendorMatch: ["cloudflare"],
  telemetrySources: ["vpn"],
  kinds: {
    login: { required: CF_KEYS, optional: [] },
    logout: { required: CF_KEYS, optional: [] },
  },
};

export function kindOf(record: Record<string, unknown>): string | null {
  return record.Action === "login" || record.Action === "logout" ? record.Action : null;
}

const IDP_CONNECTION: Record<string, string> = { rocketstack: "okta" };

function build(ev: TelemetryEvent, f: VpnFacts, ctx: NativeCtx): Record<string, unknown> | null {
  if (f.phase !== "login" && f.phase !== "logout") return null; // IdP-side facts (SAML/OIDC)
  if (!f.publicIp) return null;
  const email = f.id.email ?? (f.id.sam ? `${f.id.sam}@${emailDomain(ev, ctx)}` : undefined);
  if (!email) return null;
  const appDomain = `${ctx.org}.cloudflareaccess.com/warp`;
  return {
    Action: f.phase === "login" ? "login" : "logout",
    Allowed: true,
    AppDomain: appDomain,
    AppUUID: ctx.uuid(`${ctx.companyId}:cf-app:${appDomain}`),
    Connection: IDP_CONNECTION[ctx.companyId] ?? "azureAD",
    Country: (f.country ?? homeCountry(ctx)).iso.toLowerCase(),
    CreatedAt: isoSec(Date.parse(ev.ts)),
    Email: email,
    IPAddress: f.publicIp,
    PurposeJustificationPrompt: "",
    PurposeJustificationResponse: "",
    RayID: ctx.hex(`${ev.id}:cf-ray`, 16),
    TemporaryAccessApprovers: [],
    TemporaryAccessDuration: 0,
    UserUID: ctx.uuid(`${ctx.companyId}:cf-user:${email.toLowerCase()}`),
  };
}

function fromTelemetry(ev: TelemetryEvent, ctx: NativeCtx): NativeLog | null {
  const f = vpnFacts(ev);
  if (!f) return null;
  const record = build(ev, f, ctx);
  if (!record) return null;
  return { sourceId: "cloudflare_access", kind: String(record.Action), format: "ndjson", record, timeMs: Date.parse(ev.ts) };
}

const useCases: UseCase[] = [
  {
    id: "cloudflare_access.denied_after_idp_success_burst",
    title: "Repeated Access denials for an identity that passed the IdP",
    sourceId: "cloudflare_access",
    kinds: ["login"],
    severity: "high",
    mitre: ["T1078", "T1550.004"],
    description: "Three or more Action=login records with Allowed=false for the same Email inside 10 minutes. The Email is only filled in after the IdP step succeeded, so these are valid credentials (or a stolen session) being stopped by Access policy — geo, device posture or group. Treat the account as compromised and check the IdP sign-in for the same IPAddress.",
    logic: "SPL: index=cloudflare sourcetype=cloudflare:access Action=login Allowed=false Email=* | bin _time span=10m | stats count values(AppDomain) values(Country) values(IPAddress) BY Email _time | where count>=3",
    match: { all: [{ field: "Allowed", op: "eq", value: false }, { field: "Email", op: "exists" }] },
    threshold: { groupBy: ["Email"], count: 3, windowSec: 600 },
    falsePositives: ["Traveling employee repeatedly blocked by a country rule", "Device posture agent broken after an update"],
  },
  {
    id: "cloudflare_access.login_high_risk_country",
    title: "Allowed Access login from a high-risk country",
    sourceId: "cloudflare_access",
    kinds: ["login"],
    severity: "high",
    mitre: ["T1078", "T1133"],
    description: "Allowed=true login whose Country (lower-case ISO-2 as Cloudflare logs it) is a country where the company has no staff. Correlate IPAddress with the IdP sign-in (MFA details live there) and look at what the identity did next in Gateway/HTTP logs.",
    logic: "SPL: index=cloudflare sourcetype=cloudflare:access Action=login Allowed=true Country IN (ru, by, cn, kp, ir, ng, sy) | table CreatedAt Email IPAddress Country AppDomain Connection",
    match: { all: [{ field: "Allowed", op: "eq", value: true }, { field: "Country", op: "in", value: HIGH_RISK_ISO.map(c => c.toLowerCase()) }] },
    falsePositives: ["Approved travel", "Personal VPN egress"],
  },
  {
    id: "cloudflare_access.concurrent_logins_two_countries",
    title: "Same Access user allowed from two countries within 2 hours",
    sourceId: "cloudflare_access",
    kinds: ["login"],
    severity: "high",
    mitre: ["T1078"],
    description: "Allowed logins for the same UserUID from two different Country values within 2 hours — impossible travel. Compare the two IPAddress values: a hosting-provider ASN on the second one is an attacker relay.",
    logic: "SPL: index=cloudflare sourcetype=cloudflare:access Action=login Allowed=true | stats dc(Country) AS countries values(Country) values(IPAddress) BY UserUID Email span=2h | where countries>1",
    match: { field: "Allowed", op: "eq", value: true },
    threshold: { groupBy: ["UserUID"], count: 2, windowSec: 2 * 3600, distinct: "Country" },
    falsePositives: ["Mobile carrier egress in a neighbouring country"],
  },
  {
    id: "cloudflare_access.one_time_pin_login",
    title: "Access login with one-time PIN (bypasses the corporate IdP)",
    sourceId: "cloudflare_access",
    kinds: ["login"],
    severity: "medium",
    mitre: ["T1078", "T1556"],
    description: "Connection=onetimepin: the user received a PIN by e-mail instead of signing in through the corporate IdP, so the IdP's MFA and conditional access never ran. For an employee mailbox that is itself compromised, OTP turns mailbox access into application access.",
    logic: "SPL: index=cloudflare sourcetype=cloudflare:access Action=login Allowed=true Connection=onetimepin | table CreatedAt Email IPAddress Country AppDomain",
    match: { all: [{ field: "Connection", op: "eq", value: "onetimepin" }, { field: "Allowed", op: "eq", value: true }] },
    falsePositives: ["Contractor applications that intentionally use OTP for external users"],
  },
  {
    id: "cloudflare_access.temporary_access_granted",
    title: "Temporary (approved) access to a sensitive application",
    sourceId: "cloudflare_access",
    kinds: ["login"],
    severity: "low",
    mitre: ["T1078"],
    description: "TemporaryAccessDuration > 0 — someone requested and was granted time-boxed access to a protected app. Verify the PurposeJustificationResponse references a real, approved change ticket in the ITSM.",
    logic: "SPL: index=cloudflare sourcetype=cloudflare:access TemporaryAccessDuration>0 | table CreatedAt Email AppDomain PurposeJustificationResponse TemporaryAccessApprovers{} TemporaryAccessDuration",
    match: { field: "TemporaryAccessDuration", op: "gt", value: 0 },
    falsePositives: ["Routine approved maintenance"],
  },
];

export const source: NativeSource = { schema, fromTelemetry, useCases };
