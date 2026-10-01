/**
 * Zscaler Private Access (ZPA) — Log Streaming Service, default JSON templates.
 * Card: docs/log-schemas/ztna-zscaler-zpa.md
 *
 * JSON-native, flat PascalCase objects. Two log types:
 *   user_status   (zpn_auth_log)  — one record per Client Connector session
 *   user_activity (zpn_trans_log) — one record per application connection
 *
 * Rendering of the platform's VPN events (cross-vendor — the corpus has no ZPA-authored
 * events): a remote-access login becomes the User Status record of a Client Connector
 * session (ZPN_STATUS_AUTHENTICATED); a logout becomes the session's closing User Status
 * record (TimestampUnAuthentication + byte totals).
 * Returns null for:
 *   - authentication failures / MFA challenge / MFA denied — ZPA authenticates through SAML,
 *     so password guessing and MFA prompts are logged by the IdP (Entra/Okta), never by ZPA;
 *   - events without the client's public IP (every LSS session record carries PublicIP).
 * User Activity is documented in the schema (card samples, use cases) but no platform
 * VPN event describes a per-application connection, so none is fabricated.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { NativeCtx, NativeLog, NativeSource, SourceSchema, UseCase } from "../types";
import {
  vpnFacts, company, homeCountry, ctime, isoMs, b64id, corpDeviceName, unmanagedDeviceName, osFamily, emailDomain, userKey,
  HIGH_RISK_ISO, type VpnFacts,
} from "./remote-access-shared";

export const USER_STATUS_KEYS = [
  "LogTimestamp", "Customer", "Username", "SessionID", "SessionStatus", "Version", "ZEN", "CertificateCN", "PrivateIP",
  "PublicIP", "Latitude", "Longitude", "CountryCode", "TimestampAuthentication", "TimestampUnAuthentication",
  "TotalBytesRx", "TotalBytesTx", "Idp", "Hostname", "Platform", "ClientType", "TrustedNetworks", "TrustedNetworksNames",
  "SAMLAttributes", "PosturesHit", "PosturesMiss", "ZENLatitude", "ZENLongitude", "ZENCountryCode", "FQDNRegistered",
  "FQDNRegisteredError",
];
export const USER_ACTIVITY_KEYS = [
  "LogTimestamp", "Customer", "SessionID", "ConnectionID", "InternalReason", "ConnectionStatus", "IPProtocol",
  "DoubleEncryption", "Username", "ServicePort", "ClientPublicIP", "ClientPrivateIP", "ClientLatitude", "ClientLongitude",
  "ClientCountryCode", "ClientZEN", "Policy", "Connector", "ConnectorZEN", "ConnectorIP", "ConnectorPort", "Host",
  "Application", "AppGroup", "Server", "ServerIP", "ServerPort", "PolicyProcessingTime", "CAProcessingTime",
  "ConnectorZENSetupTime", "ConnectionSetupTime", "ServerSetupTime", "AppLearnTime", "TimestampConnectionStart",
  "TimestampConnectionEnd", "TimestampCATx", "TimestampCARx", "TimestampAppLearnStart", "TimestampZENFirstRxClient",
  "TimestampZENFirstTxClient", "TimestampZENLastRxClient", "TimestampZENLastTxClient", "TimestampConnectorZENSetupComplete",
  "TimestampZENFirstRxConnector", "TimestampZENFirstTxConnector", "TimestampZENLastRxConnector", "TimestampZENLastTxConnector",
  "ZENTotalBytesRxClient", "ZENBytesRxClient", "ZENTotalBytesTxClient", "ZENBytesTxClient", "ZENTotalBytesRxConnector",
  "ZENBytesRxConnector", "ZENTotalBytesTxConnector", "ZENBytesTxConnector", "Idp", "ClientToClient",
];

const schema: SourceSchema = {
  sourceId: "zscaler_zpa",
  // Category "vpn" (not "ztna"): the platform picks ONE remote-access product per session and
  // this module renders the same TelemetryEvent.source="vpn" events as the VPN modules.
  category: "vpn",
  card: "ztna-zscaler-zpa.md",
  product: "Zscaler Private Access",
  format: "json",
  vendorMatch: ["zscaler private access", "zpa"],
  telemetrySources: ["vpn"],
  kinds: {
    user_status: { required: USER_STATUS_KEYS, optional: [] },
    user_activity: { required: USER_ACTIVITY_KEYS, optional: [] },
  },
};

export function kindOf(record: Record<string, unknown>): string | null {
  if (typeof record.SessionStatus === "string") return "user_status";
  if (typeof record.ConnectionStatus === "string") return "user_activity";
  return null;
}

const POSTURES = "CrowdStrike-ZTA,Domain-Joined,Disk-Encrypted";
const secIso = (ms: number) => isoMs(Math.floor(ms / 1000) * 1000);

function build(ev: TelemetryEvent, f: VpnFacts, ctx: NativeCtx): Record<string, unknown> | null {
  if (f.phase !== "login" && f.phase !== "logout") return null; // SAML: auth/MFA outcomes live in the IdP log
  if (!f.publicIp) return null;
  const email = f.id.email ?? (f.id.sam ? `${f.id.sam}@${emailDomain(ev, ctx)}` : undefined);
  if (!email) return null;
  const co = company(ctx);
  const ms = Date.parse(ev.ts);
  const country = f.country ?? homeCountry(ctx);
  const key = userKey(f);
  const host = f.clientHost ?? (f.clientUnmanaged ? unmanagedDeviceName(ctx, `${ctx.companyId}:${key}:${f.publicIp}`) : corpDeviceName(ctx, key));
  const lat = ev.geo?.latitude ?? country.lat;
  const lon = ev.geo?.longitude ?? country.lon;
  const dept = ev.user?.department;
  const oldClient = f.clientUnmanaged || /1909/.test(f.clientOs ?? "");
  const authenticated = f.phase === "login";
  const dur = f.durationSec;
  return {
    LogTimestamp: ctime(ms + 2000),
    Customer: co.name,
    Username: email,
    SessionID: b64id(ctx, `${ctx.companyId}:zpa-session:${email}:${f.publicIp}`, 20),
    SessionStatus: authenticated ? "ZPN_STATUS_AUTHENTICATED" : "ZPN_STATUS_DISCONNECTED", // DISCONNECTED value UNVERIFIED (card §3)
    Version: oldClient ? "4.2.1.212" : "4.4.0.379",
    ZEN: country.zen,
    CertificateCN: `C-${ctx.hex(`${ctx.companyId}:zpa-cert:${host}`, 10)}.${email}`,
    PrivateIP: `192.168.${ctx.int(`${ctx.companyId}:lan3:${host}`, 0, 50)}.${ctx.int(`${ctx.companyId}:lan4:${host}`, 2, 250)}`,
    PublicIP: f.publicIp,
    Latitude: lat,
    Longitude: lon,
    CountryCode: country.iso,
    TimestampAuthentication: authenticated ? secIso(ms) : dur !== undefined ? secIso(ms - dur * 1000) : "",
    TimestampUnAuthentication: authenticated ? "" : secIso(ms),
    TotalBytesRx: authenticated ? 0 : (f.bytesFromClient ?? ctx.int(`${ev.id}:zpa-rx`, 1_000_000, 20_000_000)),
    TotalBytesTx: authenticated ? 0 : (f.bytesToClient ?? ctx.int(`${ev.id}:zpa-tx`, 5_000_000, 80_000_000)),
    Idp: co.idp,
    Hostname: host,
    Platform: osFamily(f.clientOs),
    ClientType: "zpn_client_type_zapp",
    TrustedNetworks: "",
    TrustedNetworksNames: "",
    SAMLAttributes: dept ? `department:${dept},email:${email}` : `email:${email}`,
    PosturesHit: f.clientUnmanaged ? "" : POSTURES,
    PosturesMiss: f.clientUnmanaged ? POSTURES : "",
    ZENLatitude: Math.trunc(country.lat),
    ZENLongitude: Math.trunc(country.lon),
    ZENCountryCode: country.iso,
    FQDNRegistered: "0",
    FQDNRegisteredError: "CUSTOMER_NOT_ENABLED",
  };
}

function fromTelemetry(ev: TelemetryEvent, ctx: NativeCtx): NativeLog | null {
  const f = vpnFacts(ev);
  if (!f) return null;
  const record = build(ev, f, ctx);
  if (!record) return null;
  return { sourceId: "zscaler_zpa", kind: "user_status", format: "json", record, timeMs: Date.parse(ev.ts) };
}

const useCases: UseCase[] = [
  {
    id: "zscaler_zpa.policy_block_burst",
    title: "ZPA access-policy blocks across many private apps (internal discovery)",
    sourceId: "zscaler_zpa",
    kinds: ["user_activity"],
    severity: "high",
    mitre: ["T1046", "T1135", "T1021"],
    description: "One Username is rejected by ZPA access policy (InternalReason=BRK_MT_SETUP_FAIL_REJECTED_BY_POLICY, ConnectionStatus=close) for five or more different Host values within 10 minutes. A user who only needs the CRM does not try domain controllers, file shares and admin ports — this is someone mapping what the stolen session can reach.",
    logic: "SPL: index=zpa sourcetype=zscalerlss-zpa-app InternalReason=BRK_MT_SETUP_FAIL_REJECTED_BY_POLICY | bin _time span=10m | stats dc(Host) AS hosts values(Host) values(ServicePort) BY Username SessionID _time | where hosts>=5",
    match: { field: "InternalReason", op: "eq", value: "BRK_MT_SETUP_FAIL_REJECTED_BY_POLICY" },
    threshold: { groupBy: ["Username"], count: 5, windowSec: 600, distinct: "Host" },
    falsePositives: ["Application segments re-scoped after a policy change (many users blocked at once, not one)", "IT staff whose group membership was just removed"],
  },
  {
    id: "zscaler_zpa.session_from_high_risk_country",
    title: "ZPA Client Connector session from a high-risk country",
    sourceId: "zscaler_zpa",
    kinds: ["user_status"],
    severity: "high",
    mitre: ["T1078", "T1133"],
    description: "A User Status record with SessionStatus=ZPN_STATUS_AUTHENTICATED whose CountryCode (geo of PublicIP) is a country where the company has no staff. SSO succeeded, so the attacker holds a valid IdP session — pivot on Username into the IdP sign-in log and on SessionID into User Activity to see what was accessed.",
    logic: "SPL: index=zpa sourcetype=zscalerlss-zpa-auth SessionStatus=ZPN_STATUS_AUTHENTICATED CountryCode IN (RU, BY, CN, KP, IR, NG, SY) | table _time Username PublicIP CountryCode Hostname PosturesMiss SessionID",
    match: { all: [{ field: "SessionStatus", op: "eq", value: "ZPN_STATUS_AUTHENTICATED" }, { field: "CountryCode", op: "in", value: HIGH_RISK_ISO }] },
    falsePositives: ["Approved travel", "Traffic exiting a personal VPN in that country"],
  },
  {
    id: "zscaler_zpa.concurrent_sessions_two_countries",
    title: "Same user holds ZPA sessions from two countries",
    sourceId: "zscaler_zpa",
    kinds: ["user_status"],
    severity: "high",
    mitre: ["T1078"],
    description: "Two authenticated User Status records for the same Username with different CountryCode within 4 hours (different SessionID, PublicIP and usually Hostname). Concurrent sessions from two countries = impossible travel; the one on the unfamiliar device is the attacker.",
    logic: "SPL: index=zpa sourcetype=zscalerlss-zpa-auth SessionStatus=ZPN_STATUS_AUTHENTICATED | stats dc(CountryCode) AS countries values(CountryCode) values(PublicIP) values(Hostname) BY Username span=4h | where countries>1",
    match: { field: "SessionStatus", op: "eq", value: "ZPN_STATUS_AUTHENTICATED" },
    threshold: { groupBy: ["Username"], count: 2, windowSec: 4 * 3600, distinct: "CountryCode" },
    falsePositives: ["Mobile device roaming abroad while the laptop stays home"],
  },
  {
    id: "zscaler_zpa.posture_failed_session",
    title: "ZPA session from a device failing posture checks",
    sourceId: "zscaler_zpa",
    kinds: ["user_status"],
    severity: "medium",
    mitre: ["T1078", "T1133"],
    description: "An authenticated session whose PosturesMiss lists failed device-posture profiles (EDR running, domain-joined, disk encrypted). The credentials are valid but the device is not a managed corporate machine.",
    logic: "SPL: index=zpa sourcetype=zscalerlss-zpa-auth SessionStatus=ZPN_STATUS_AUTHENTICATED PosturesMiss!=\"\" | table _time Username Hostname Platform PosturesMiss PublicIP CountryCode",
    match: { all: [{ field: "SessionStatus", op: "eq", value: "ZPN_STATUS_AUTHENTICATED" }, { field: "PosturesMiss", op: "exists" }] },
    falsePositives: ["Corporate laptop whose EDR agent is mid-upgrade", "Approved BYOD with relaxed posture"],
  },
  {
    id: "zscaler_zpa.unmanaged_hostname",
    title: "ZPA session from a default-named (unmanaged) Windows host",
    sourceId: "zscaler_zpa",
    kinds: ["user_status"],
    severity: "medium",
    mitre: ["T1078"],
    description: "Hostname is a Windows default (DESKTOP-xxxxxxx / WIN-xxxxxxx). Corporate devices follow the naming standard, so this Client Connector runs on a personal machine or an attacker VM.",
    logic: "SPL: index=zpa sourcetype=zscalerlss-zpa-auth (Hostname=\"DESKTOP-*\" OR Hostname=\"WIN-*\") | table _time Username Hostname PublicIP CountryCode Version",
    match: { all: [{ field: "SessionStatus", op: "eq", value: "ZPN_STATUS_AUTHENTICATED" }, { field: "Hostname", op: "regex", value: "^(DESKTOP|WIN)-" }] },
    falsePositives: ["Freshly imaged laptop before rename"],
  },
  {
    id: "zscaler_zpa.bulk_download_private_app",
    title: "More than 1 GB delivered to a ZPA client from one private app connection",
    sourceId: "zscaler_zpa",
    kinds: ["user_activity"],
    severity: "high",
    mitre: ["T1039", "T1530"],
    description: "ZENTotalBytesTxClient (bytes the broker delivered to the client) exceeds 1 GB on a single application connection — bulk download from a file server or database through ZTNA. Check the session's country and device (User Status via SessionID) and whether the user normally touches that Application.",
    logic: "SPL: index=zpa sourcetype=zscalerlss-zpa-app ZENTotalBytesTxClient>1000000000 | eval GB=round(ZENTotalBytesTxClient/1024/1024/1024,2) | table _time Username ClientCountryCode Application Host ServerPort GB SessionID",
    match: { field: "ZENTotalBytesTxClient", op: "gt", value: 1_000_000_000 },
    falsePositives: ["Engineers pulling large build artefacts or VM images", "Backup admins restoring data"],
  },
];

export const source: NativeSource = { schema, fromTelemetry, useCases };
