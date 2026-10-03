/**
 * Shared helpers for the IDENTITY native modules (entra, okta, windows_security,
 * cyberark). NOT a source module (no `source` export) — the leading underscore
 * marks it as a helper.
 *
 * The core idea: every identity TelemetryEvent — whatever vendor authored it —
 * is reduced to vendor-neutral {@link IdFacts} (who, from where, what happened,
 * how it ended). Each IdP module then renders those facts in its own native
 * shape. That is what lets an Okta-authored MFA-fatigue story be shown as Entra
 * sign-ins and vice versa, while still returning null where the other product
 * has no truthful equivalent record.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { knownGeoForIp } from "@/lib/geo/resolveGeo";
import type { NativeCtx } from "../types";

// ── raw-map access ───────────────────────────────────────────────────────────

/** First non-empty legacy raw value among the given keys (arrays/objects returned as-is). */
export function rawAny(ev: TelemetryEvent, ...keys: string[]): unknown {
  const r = ev.raw ?? {};
  for (const k of keys) {
    const v = (r as Record<string, unknown>)[k];
    if (v !== undefined && v !== null && v !== "") return v;
  }
  return undefined;
}
/** Same as {@link rawAny} but stringified (numbers/booleans → string). */
export function rawStr(ev: TelemetryEvent, ...keys: string[]): string | undefined {
  const v = rawAny(ev, ...keys);
  if (v === undefined) return undefined;
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  return undefined;
}
/** Raw keys starting with a prefix, prefix stripped. */
export function rawWithPrefix(ev: TelemetryEvent, prefix: string): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(ev.raw ?? {})) if (k.startsWith(prefix)) out[k.slice(prefix.length)] = v;
  return out;
}
export const truthy = (v: unknown) => v === true || v === "true" || v === "True" || v === "1";
export const falsy = (v: unknown) => v === false || v === "false" || v === "False" || v === "0";

// ── people ───────────────────────────────────────────────────────────────────

/** The primary user's email/UPN for an identity event (lower-cased, as IdPs store it). */
export function userEmail(ev: TelemetryEvent): string | undefined {
  const v = ev.user?.email ?? ev.user_email ??
    rawStr(ev, "user.email", "okta.actor.alternateId", "okta.actor.login",
      "azure.signinlogs.properties.userPrincipalName", "azure.signinlogs.user_principal_name", "azure.userPrincipalName",
      "data.office365.UserId", "azure.actor.upn", "target.user.email");
  return v && v.includes("@") ? v.toLowerCase() : v?.toLowerCase();
}
/** "dana.levi@x" → "Dana Levi"; "j.smith" → "J Smith"; "svc-backup" → "svc-backup". */
export function nameFromLogin(login: string): string {
  const local = login.split("@")[0].split("\\").pop() ?? login;
  if (/^(svc|adm|admin|it|ops|helpdesk|ceo|cfo|root)[-_.]?/i.test(local) && !/^[a-z]+\.[a-z-]+$/i.test(local)) return local;
  return local.split(/[._]/).filter(Boolean).map(p => p.split("-").map(s => s.charAt(0).toUpperCase() + s.slice(1)).join("-")).join(" ");
}
export function displayNameOf(ev: TelemetryEvent, email?: string): string | undefined {
  const raw = ev.user?.full_name ?? rawStr(ev, "okta.actor.displayName", "azure.signinlogs.properties.userDisplayName", "azure.signinlogs.user_display_name");
  if (raw && raw !== "Okta System" && !raw.includes("Token")) return raw;
  return email ? nameFromLogin(email) : undefined;
}

// ── network / geo ────────────────────────────────────────────────────────────

export function isPrivateIp(ip?: string): boolean {
  if (!ip) return false;
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|::1|fc|fd)/i.test(ip);
}
export interface CountryInfo { iso: string; name: string; city: string; state: string; lat: number; lon: number; postal: string; asn: number; asOrg: string; isp: string; asDomain: string; hosting: boolean }
const C = (iso: string, name: string, city: string, state: string, lat: number, lon: number, postal: string, asn: number, asOrg: string, isp: string, asDomain: string, hosting = false): CountryInfo =>
  ({ iso, name, city, state, lat, lon, postal, asn, asOrg, isp, asDomain, hosting });
/** Countries the platform's stories use (ISO 3166-1 alpha-2 ↔ the full English name Okta prints). */
export const COUNTRIES: CountryInfo[] = [
  C("IL", "Israel", "Tel Aviv", "Tel Aviv", 32.0809, 34.7806, "61000", 12849, "hot-net internet services ltd.", "hot-net internet services ltd.", "hot.net.il"),
  C("NL", "Netherlands", "Amsterdam", "North Holland", 52.374, 4.8897, "1012", 9009, "m247 europe srl", "m247 ltd", "m247.com", true),
  C("RU", "Russia", "Moscow", "Moscow", 55.7522, 37.6156, "101000", 49505, "selectel ltd.", "selectel", "selectel.ru", true),
  C("CN", "China", "Shenzhen", "Guangdong", 22.5455, 114.0683, "518000", 4134, "chinanet", "china telecom", "chinatelecom.cn", true),
  C("US", "United States", "New York", "New York", 40.7143, -74.006, "10001", 14061, "digitalocean, llc", "digitalocean", "digitalocean.com", true),
  C("GB", "United Kingdom", "London", "England", 51.5085, -0.1257, "EC1A", 2856, "british telecommunications plc", "bt", "bt.com"),
  C("DE", "Germany", "Frankfurt am Main", "Hesse", 50.1155, 8.6842, "60311", 24940, "hetzner online gmbh", "hetzner online gmbh", "hetzner.com", true),
  C("NG", "Nigeria", "Lagos", "Lagos", 6.4541, 3.3947, "100001", 37148, "globacom limited", "globacom", "gloworld.com"),
  C("RO", "Romania", "Bucharest", "Bucuresti", 44.4323, 26.1063, "010011", 9009, "m247 europe srl", "m247 ltd", "m247.com", true),
  C("UA", "Ukraine", "Kyiv", "Kyiv City", 50.4547, 30.5238, "01001", 15895, "kyivstar pjsc", "kyivstar", "kyivstar.net"),
  C("MD", "Moldova", "Chisinau", "Chisinau Municipality", 47.0056, 28.8575, "2001", 8926, "moldtelecom sa", "moldtelecom", "moldtelecom.md"),
  C("IS", "Iceland", "Reykjavik", "Capital Region", 64.1355, -21.8954, "101", 200651, "flokinet ehf", "flokinet ehf", "flokinet.is", true),
  C("PL", "Poland", "Warsaw", "Mazovia", 52.2298, 21.0118, "00-001", 212238, "datacamp limited", "datacamp limited", "datacamp.co.uk", true),
  C("BE", "Belgium", "Brussels", "Brussels Capital", 50.8505, 4.3488, "1000", 5432, "proximus nv", "proximus", "proximus.be"),
  C("SG", "Singapore", "Singapore", "Central Singapore", 1.2897, 103.8501, "018956", 4773, "singtel", "singtel mobile", "singtel.com"),
  C("CH", "Switzerland", "Zurich", "Zurich", 47.3667, 8.55, "8001", 3303, "swisscom (schweiz) ag", "swisscom", "swisscom.ch"),
  C("FR", "France", "Paris", "Ile-de-France", 48.8534, 2.3488, "75001", 16276, "ovh sas", "ovh sas", "ovh.net", true),
  C("SE", "Sweden", "Stockholm", "Stockholm", 59.3326, 18.0649, "111 20", 42708, "glesys ab", "glesys", "glesys.se", true),
  C("IN", "India", "Mumbai", "Maharashtra", 19.0728, 72.8826, "400001", 9829, "bsnl", "bsnl", "bsnl.in"),
  C("BR", "Brazil", "Sao Paulo", "Sao Paulo", -23.5475, -46.6361, "01000", 28573, "claro nxt telecomunicacoes ltda", "claro", "claro.com.br"),
  C("IR", "Iran", "Tehran", "Tehran", 35.6944, 51.4215, "11369", 58224, "iran telecommunication company pjs", "tci", "tci.ir"),
  C("KP", "North Korea", "Pyongyang", "Pyongyang", 39.0339, 125.7543, "", 131279, "ryugyong-dong", "star joint venture co. ltd.", "star.net.kp"),
  C("TR", "Turkey", "Istanbul", "Istanbul", 41.0138, 28.9497, "34000", 9121, "turk telekom", "turk telekom", "turktelekom.com.tr"),
  C("ES", "Spain", "Madrid", "Madrid", 40.4165, -3.7026, "28001", 3352, "telefonica de espana", "telefonica", "telefonica.es"),
  C("IT", "Italy", "Milan", "Lombardy", 45.4643, 9.1895, "20121", 3269, "telecom italia", "tim", "telecomitalia.it"),
  C("CA", "Canada", "Toronto", "Ontario", 43.7001, -79.4163, "M5H", 812, "rogers communications canada inc.", "rogers", "rogers.com"),
  C("AE", "United Arab Emirates", "Dubai", "Dubai", 25.0772, 55.3093, "", 5384, "emirates telecommunications corporation", "etisalat", "etisalat.ae"),
  C("JP", "Japan", "Tokyo", "Tokyo", 35.6895, 139.6917, "100-0001", 2516, "kddi corporation", "kddi", "kddi.com"),
  C("AT", "Austria", "Vienna", "Vienna", 48.2085, 16.3721, "1010", 8447, "a1 telekom austria ag", "a1", "a1.net"),
  C("CZ", "Czechia", "Prague", "Prague", 50.0880, 14.4208, "110 00", 5610, "o2 czech republic", "o2", "o2.cz"),
  C("LT", "Lithuania", "Vilnius", "Vilnius", 54.6892, 25.2798, "01100", 8764, "telia lietuva, ab", "telia", "telia.lt"),
  C("BG", "Bulgaria", "Sofia", "Sofia-Capital", 42.6975, 23.3242, "1000", 8866, "vivacom", "vivacom", "vivacom.bg"),
  C("HK", "Hong Kong", "Hong Kong", "Central and Western", 22.2783, 114.1747, "", 4760, "hkt limited", "hkt", "hkt.com"),
];
const COUNTRY_ALIASES: Record<string, string> = {
  "uk": "GB", "great britain": "GB", "england": "GB", "usa": "US", "united states of america": "US", "the netherlands": "NL",
  "holland": "NL", "russian federation": "RU", "czech republic": "CZ", "republic of moldova": "MD", "uae": "AE", "korea, north": "KP",
};
export function countryInfo(v?: string): CountryInfo | undefined {
  if (!v) return undefined;
  const s = v.trim();
  const up = s.toUpperCase();
  return COUNTRIES.find(c => c.iso === up) ??
    COUNTRIES.find(c => c.name.toLowerCase() === s.toLowerCase()) ??
    (COUNTRY_ALIASES[s.toLowerCase()] ? COUNTRIES.find(c => c.iso === COUNTRY_ALIASES[s.toLowerCase()]) : undefined);
}
/** Head-office country per training company (where corporate egress / private IPs geolocate). */
// Where each company is headquartered (companyProfilesMeta `hq`): NexaCorp is London.
export const COMPANY_HQ: Record<string, string> = { nexacorp: "GB", rocketstack: "IL", medcore: "NL", globallogis: "DE", quantumbank: "CH" };

export interface GeoFacts { iso: string; country: string; city: string; state: string; lat: number; lon: number; postal: string }

/**
 * Network owners of the address ranges the stories use as anonymizers — a Tor exit or an
 * anonymous-VPN range is `isProxy` / `anonymizedIPAddress` in every row that shows it, with the
 * operator's ASN (never the HQ's home ISP). Location stays with the platform's shared IP→geo map
 * (lib/geo/resolveGeo), so the feed, the threat-intel drawer and the IdP records agree.
 */
interface NetOwner { prefixes: string[]; asn: number; asOrg: string; isp: string; domain: string; anonymous: boolean }
const NET_OWNERS: NetOwner[] = [
  { prefixes: ["185.220.100.", "185.220.101.", "185.220.102.", "185.220.103."], asn: 60729, asOrg: "stiftung erneuerbare freiheit", isp: "tor exit node", domain: "torservers.net", anonymous: true },
  { prefixes: ["23.129.64."], asn: 396507, asOrg: "emerald onion", isp: "tor exit node", domain: "emeraldonion.org", anonymous: true },
  { prefixes: ["171.25.193."], asn: 198093, asOrg: "foreningen for digitala fri- och rattigheter", isp: "tor exit node", domain: "dfri.se", anonymous: true },
  { prefixes: ["146.70."], asn: 9009, asOrg: "m247 europe srl", isp: "m247 ltd", domain: "m247.com", anonymous: true },
  { prefixes: ["138.199."], asn: 212238, asOrg: "datacamp limited", isp: "datacamp limited", domain: "datacamp.co.uk", anonymous: true },
];
function netOwnerOf(ip?: string): NetOwner | undefined {
  return ip ? NET_OWNERS.find(o => o.prefixes.some(p => ip.startsWith(p))) : undefined;
}

/** Location the event's author wrote for its client IP (structured geo first, then any vendor raw key). */
export function authoredGeo(ev: TelemetryEvent): { country?: string; city?: string; latitude?: number; longitude?: number } {
  const country = ev.geo?.country ?? rawStr(ev, "GeoLocation.country_name", "source.geo.country_name", "source.geo.country_iso_code",
    "okta.client.geographicalContext.country", "azure.signinlogs.properties.location.countryOrRegion", "azure.signinlogs.location.country_or_region",
    "azure.location.country", "geo.country");
  const city = ev.geo?.city ?? rawStr(ev, "GeoLocation.city_name", "source.geo.city_name", "okta.client.geographicalContext.city",
    "azure.signinlogs.properties.location.city", "azure.signinlogs.location.city", "azure.location.city");
  const latitude = num(ev.geo?.latitude ?? rawAny(ev, "GeoLocation.location.lat", "GeoLocation.latitude", "azure.signinlogs.properties.location.geoCoordinates.latitude", "azure.signinlogs.location.geo_coordinates.latitude"));
  const longitude = num(ev.geo?.longitude ?? rawAny(ev, "GeoLocation.location.lon", "GeoLocation.longitude", "azure.signinlogs.properties.location.geoCoordinates.longitude", "azure.signinlogs.location.geo_coordinates.longitude"));
  return { country, city, latitude, longitude };
}

/**
 * Geo for the event's client IP: authored geo → the platform's deterministic per-IP map
 * (knownGeoForIp, the same one the feed's GeoLocation enrichment uses) → company HQ (private
 * IPs, the corporate egress and any address the story never placed). One IP, one place.
 */
export function geoOf(ev: TelemetryEvent, ctx: NativeCtx, ip?: string): GeoFacts {
  const a = authoredGeo(ev);
  const known = !a.country && ip && !isPrivateIp(ip) ? knownGeoForIp(ip) : null;
  let ci = countryInfo(a.country) ?? (known ? countryInfo(known.country) : undefined);
  if (!ci) ci = countryInfo(COMPANY_HQ[ctx.companyId] ?? "IL");
  const c = ci as CountryInfo;
  // The shared map labels some cities for analysts ("San Francisco (Cloudflare)", "Tor Exit — Unknown"); an IdP prints a city.
  const knownCity = known && countryInfo(known.country) === c && !/unknown/i.test(known.city) ? known.city.replace(/\s*\(.*\)$/, "") : undefined;
  const cityRaw = a.city ?? knownCity;
  const lat = a.latitude ?? (knownCity ? known!.lat : undefined);
  const lon = a.longitude ?? (knownCity ? known!.lon : undefined);
  const state = rawStr(ev, "azure.signinlogs.properties.location.state", "GeoLocation.region_name") ?? (cityRaw && cityRaw !== c.city ? cityRaw : c.state);
  return { iso: c.iso, country: c.name, city: cityRaw ?? c.city, state, lat: lat ?? c.lat, lon: lon ?? c.lon, postal: c.postal };
}
function num(v: unknown): number | undefined {
  if (typeof v === "number" && isFinite(v)) return v;
  if (typeof v === "string" && v.trim() !== "" && isFinite(Number(v))) return Number(v);
  return undefined;
}

export interface AsnFacts { asn: number | null; asOrg: string | null; isp: string | null; domain: string | null; isProxy: boolean }
/** Network owner of the client IP: authored (structured geo, then Okta / Entra raw) → known operator ranges → the country's carrier. */
export function asnOf(ev: TelemetryEvent, geo: GeoFacts, ip?: string): AsnFacts {
  if (isPrivateIp(ip)) return { asn: null, asOrg: null, isp: null, domain: null, isProxy: false };
  const owner = netOwnerOf(ip);
  const proxyRaw = ev.geo?.anonymous ?? rawAny(ev, "okta.securityContext.isProxy");
  const asnRaw = ev.geo?.asn !== undefined ? String(ev.geo.asn) : rawStr(ev, "okta.securityContext.asNumber", "azure.signinlogs.properties.autonomousSystemNumber");
  const c = countryInfo(geo.iso)!;
  const orgRaw = ev.geo?.as_org ?? rawStr(ev, "okta.securityContext.asOrg");
  const asOrg = orgRaw ?? owner?.asOrg ?? c.asOrg;
  const isp = ev.geo?.isp ?? rawStr(ev, "okta.securityContext.isp") ?? orgRaw ?? owner?.isp ?? c.isp;
  const asn = asnRaw ? Number(asnRaw.replace(/^AS/i, "")) : owner?.asn ?? c.asn;
  const reasons = (rawStr(ev, "okta.debugContext.debugData.riskReasons") ?? "") + " " + (ev.description ?? "");
  const isProxy = proxyRaw !== undefined ? truthy(proxyRaw) : owner ? owner.anonymous :
    /\b(tor|anonymi[sz]\w*|vpn exit|commercial vpn|proxy)\b/i.test(reasons) && !/office vpn|company vpn|corporate vpn|known egress/i.test(reasons);
  return { asn: isFinite(asn) ? asn : c.asn, asOrg: asOrg.toLowerCase(), isp: isp.toLowerCase(), domain: rawStr(ev, "okta.securityContext.domain") ?? (orgRaw ? c.asDomain : owner?.domain ?? c.asDomain), isProxy };
}

// ── user agents ──────────────────────────────────────────────────────────────

export interface UaFacts { raw: string; oktaBrowser: string; oktaOs: string; device: "Computer" | "Mobile" | "Unknown"; entraBrowser: string; entraOs: string; scripted: boolean }
export const DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
export function uaOf(ev: TelemetryEvent): UaFacts {
  const raw = ev.network?.user_agent ?? rawStr(ev, "okta.client.userAgent.rawUserAgent", "azure.signinlogs.properties.userAgent", "user_agent.original")
    ?? (/python-requests/i.test(rawStr(ev, "azure.signinlogs.device_detail.browser") ?? "") ? rawStr(ev, "azure.signinlogs.device_detail.browser")! : undefined)
    ?? DEFAULT_UA;
  return parseUa(raw);
}
export function parseUa(raw: string): UaFacts {
  const py = /python-requests\/([\d.]+)/i.exec(raw);
  if (py) { const [maj, min] = py[1].split("."); return { raw, oktaBrowser: "UNKNOWN", oktaOs: "Unknown", device: "Unknown", entraBrowser: `Python Requests ${maj}.${min ?? "0"}`, entraOs: "", scripted: true }; }
  if (/curl\/|Go-http-client|okhttp|PowerShell/i.test(raw)) return { raw, oktaBrowser: "UNKNOWN", oktaOs: "Unknown", device: "Unknown", entraBrowser: "", entraOs: "", scripted: true };
  let oktaOs = "Unknown", entraOs = "";
  let device: UaFacts["device"] = "Computer";
  if (/iPhone|iPad|iOS/i.test(raw)) { oktaOs = "iOS"; entraOs = "Ios"; device = "Mobile"; }
  else if (/Android/i.test(raw)) { oktaOs = "Android"; entraOs = "Android"; device = "Mobile"; }
  else if (/Windows NT 10/i.test(raw)) { oktaOs = "Windows 10"; entraOs = "Windows10"; }
  else if (/Mac OS X|Macintosh/i.test(raw)) { oktaOs = "Mac OS X"; entraOs = "MacOs"; }
  else if (/Linux/i.test(raw)) { oktaOs = "Linux"; entraOs = "Linux"; }
  let oktaBrowser = "UNKNOWN", entraBrowser = "";
  const edge = /Edg\/([\d.]+)/.exec(raw), chrome = /Chrome\/([\d.]+)/.exec(raw), ff = /Firefox\/([\d.]+)/.exec(raw), saf = /Version\/([\d.]+).*Safari/.exec(raw);
  const short = (v: string, n: number) => v.split(".").slice(0, n).join(".");
  if (edge) { oktaBrowser = "EDGE"; entraBrowser = `Edge ${short(edge[1], 3)}`; }
  else if (chrome) { oktaBrowser = "CHROME"; entraBrowser = `Chrome ${short(chrome[1], 3)}`; }
  else if (ff) { oktaBrowser = "FIREFOX"; entraBrowser = `Firefox ${short(ff[1], 2)}`; }
  else if (saf) { oktaBrowser = "SAFARI"; entraBrowser = `Safari ${short(saf[1], 2)}`; }
  else if (/Okta Verify/i.test(raw)) { device = "Mobile"; }
  return { raw, oktaBrowser, oktaOs, device, entraBrowser, entraOs, scripted: false };
}

// ── time ─────────────────────────────────────────────────────────────────────

/** ISO with exactly `digits` fractional digits and "Z" (Windows 7, Entra audits 7, Okta 3). */
export function isoFrac(ts: string, digits: number, padSeed = ""): string {
  const d = new Date(Date.parse(ts));
  const base = d.toISOString().slice(0, 19);
  if (digits === 0) return `${base}Z`;
  const ms = d.toISOString().slice(20, 23);
  let extra = "";
  for (let i = 0; extra.length < digits - 3; i++) extra += String((padSeed.charCodeAt(i % Math.max(1, padSeed.length)) * (i + 7)) % 10);
  return `${base}.${(ms + extra).slice(0, digits)}Z`;
}
export const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

// ── vendor-neutral identity facts ────────────────────────────────────────────

export type IdAction =
  | "signin" | "mfa" | "push_sent" | "policy" | "lockout" | "threat"
  | "factor_enroll" | "factor_reset" | "factor_deactivate"
  | "role_grant" | "group_add" | "app_assign" | "consent" | "app_register"
  | "token_create" | "token_revoke" | "token_grant" | "sso" | "session_end"
  | "password_reset" | "password_change" | "ca_policy_update" | "guest_invite" | "risk_change"
  | "rate_limit" | "directory_read";

export type FailReason = "bad_password" | "mfa_denied" | "mfa_required" | "mfa_registration" | "ca_block" | "locked" | "disabled" | "no_user" | "expired" | "malicious_ip" | "other";
export type MfaMethod = "push" | "totp" | "sms" | "voice" | "fido" | "token";

export interface IdFacts {
  action: IdAction;
  /** Vendor-native action name as authored (Okta eventType / Entra activity), when the author used a real one. */
  nativeName?: string;
  success: boolean;
  /** For policy evaluations / threat events: ALLOW | CHALLENGE | DENY. */
  decision?: "ALLOW" | "CHALLENGE" | "DENY";
  failure?: FailReason;
  /** Entra status.errorCode when the author supplied one. */
  errorCode?: number;
  email?: string;
  displayName?: string;
  /** Object acted on in admin events (user email), group / role / app names. */
  targetEmail?: string;
  targetName?: string;
  roleName?: string;
  groupName?: string;
  appName?: string;
  scopes?: string;
  ip?: string;
  mfaUsed: boolean;
  mfaMethod?: MfaMethod;
  interactive: boolean;
  risk: "none" | "low" | "medium" | "high";
  riskReasons: string[];
  behaviors?: string;
  threatSuspected?: boolean;
  sessionId?: string;
  correlationId?: string;
  transactionId?: string;
  clientApp?: string;
  protocol?: string;
  legacyAuth: boolean;
  deviceName?: string;
  devicePlatform?: string;
  managedDevice?: boolean;
  compliantDevice?: boolean;
}

const OP = (ev: TelemetryEvent) => (rawStr(ev, "data.office365.Operation", "azure.auditlogs.properties.activityDisplayName", "azure.auditlogs.operationName",
  "azure.operation", "azure.activitylogs.operationName") ?? "").replace(/\.$/, "").trim();

function riskOf(ev: TelemetryEvent): IdFacts["risk"] {
  const v = (rawStr(ev, "okta.debugContext.debugData.riskLevel", "okta.risk.level", "azure.signinlogs.properties.riskLevelDuringSignIn",
    "azure.signinlogs.risk_level_during_signin", "azure.signinlogs.risk_level_aggregated", "azure.riskLevelAggregated", "risk.level") ?? "").toLowerCase();
  if (v === "critical" || v === "high") return "high";
  if (v === "medium") return "medium";
  if (v === "low") return "low";
  return "none";
}
const REASON_MAP: [RegExp, string][] = [
  [/impossible|velocity|unlikely|travel/i, "unlikelyTravel"], [/tor|anonymi/i, "anonymizedIPAddress"],
  [/iphighrisk|threatintel|malicious/i, "maliciousIPAddress"], [/newdevice|anomalous device|unfamiliar|new device/i, "unfamiliarFeatures"],
  [/leaked/i, "leakedCredentials"], [/suspiciousip/i, "suspiciousIPAddress"],
];
function riskReasonsOf(ev: TelemetryEvent): string[] {
  const out = new Set<string>();
  const v2 = rawAny(ev, "azure.signinlogs.properties.riskEventTypes_v2");
  if (Array.isArray(v2)) for (const x of v2) out.add(String(x));
  const rr = rawStr(ev, "okta.debugContext.debugData.riskReasons");
  if (rr) for (const part of rr.split(/[,;]/)) for (const [re, name] of REASON_MAP) if (re.test(part)) out.add(name);
  return [...out];
}

function errorCodeOf(ev: TelemetryEvent): number | undefined {
  const v = rawStr(ev, "azure.signinlogs.properties.status.errorCode", "azure.signinlogs.resultType", "azure.resultType",
    "data.office365.ErrorNumber", "azure.error_code");
  if (v === undefined || !/^\d+$/.test(v)) return undefined;
  return Number(v);
}
export function failureFromCode(code: number | undefined): FailReason | undefined {
  switch (code) {
    case undefined: case 0: return undefined;
    case 50126: return "bad_password";
    case 50053: return "locked";
    case 50034: return "no_user";
    case 50057: return "disabled";
    case 50055: return "expired";
    case 50074: case 50076: case 50079: return "mfa_required";
    case 50072: return "mfa_registration";
    case 500121: case 50158: return "mfa_denied";
    case 53003: return "ca_block";
    default: return "other";
  }
}
function failureFromText(t: string): FailReason | undefined {
  if (/lock/i.test(t)) return "locked";
  if (/denied|declin|reject/i.test(t)) return "mfa_denied";
  if (/did not complete the mfa|mfa required|mfarequired|strong auth/i.test(t)) return "mfa_required";
  if (/disabled/i.test(t)) return "disabled";
  if (/does not exist|doesn't exist|no such user|unknown user/i.test(t)) return "no_user";
  if (/conditional access|not managed|blocked/i.test(t)) return "ca_block";
  if (/password|credential/i.test(t)) return "bad_password";
  return undefined;
}
function mfaMethodOf(ev: TelemetryEvent): MfaMethod | undefined {
  const t = [ev.authentication?.mfa_type, ev.authentication?.method, rawStr(ev, "okta.debugContext.debugData.factor", "authentication.factor", "authentication.mfa",
    "azure.authenticationDetails.authenticationMethodDetail", "azure.authenticationDetails.authenticationMethod"), ev.description].filter(Boolean).join(" ");
  if (/push|authenticator|OKTA_VERIFY|phoneappnotification/i.test(t)) return "push";
  if (/fido|webauthn|security key|passkey/i.test(t)) return "fido";
  if (/totp|google_otp|otp|oath|code/i.test(t)) return "totp";
  if (/sms/i.test(t)) return "sms";
  if (/phone call|voice/i.test(t)) return "voice";
  return undefined;
}

/**
 * Classify any identity TelemetryEvent (Okta / Entra / UAL-shaped / generic) into
 * vendor-neutral facts. Returns null for events that are not identity actions
 * (mail, files, Copilot, ARM operations …).
 */
export function identityFacts(ev: TelemetryEvent): IdFacts | null {
  const oktaType = rawStr(ev, "okta.eventType");
  const op = OP(ev);
  const desc = ev.description ?? "";
  const email = userEmail(ev);
  const base = (action: IdAction, success: boolean, extra: Partial<IdFacts> = {}): IdFacts => {
    const errorCode = errorCodeOf(ev);
    const risk = riskOf(ev);
    const ua = rawStr(ev, "azure.signinlogs.properties.clientAppUsed", "azure.signinlogs.client_app_used", "azure.clientAppUsed", "azure.client_app");
    const interactiveRaw = rawAny(ev, "azure.signinlogs.properties.isInteractive", "azure.signinlogs.is_interactive");
    const managed = rawAny(ev, "azure.signinlogs.properties.deviceDetail.isManaged", "azure.signinlogs.device_detail.is_managed", "okta.device.managed");
    const compliant = rawAny(ev, "azure.signinlogs.properties.deviceDetail.isCompliant", "azure.signinlogs.device_detail.is_compliant", "azure.deviceDetail.isCompliant");
    const legacyClient = ua && !/^(Browser|Mobile Apps and Desktop clients)$/i.test(ua) ? ua : undefined;
    return {
      action, success, email, displayName: displayNameOf(ev, email), ip: ev.src_ip ?? rawStr(ev, "source.ip", "okta.client.ipAddress", "data.office365.ClientIP", "data.office365.ActorIpAddress", "azure.signinlogs.properties.ipAddress"),
      mfaUsed: false, interactive: interactiveRaw === undefined ? !/non-interactive|noninteractive/i.test(desc) : truthy(interactiveRaw),
      risk, riskReasons: riskReasonsOf(ev), behaviors: rawStr(ev, "okta.debugContext.debugData.behaviors"),
      threatSuspected: rawAny(ev, "okta.debugContext.debugData.threatSuspected") !== undefined ? truthy(rawAny(ev, "okta.debugContext.debugData.threatSuspected")) : undefined,
      sessionId: rawStr(ev, "azure.signinlogs.properties.sessionId", "okta.authenticationContext.externalSessionId", "data.office365.SessionId"),
      correlationId: rawStr(ev, "azure.signinlogs.properties.correlationId", "azure.signinlogs.correlation_id", "azure.auditlogs.properties.correlationId", "azure.auditlogs.correlation_id"),
      transactionId: rawStr(ev, "okta.transaction.id"),
      clientApp: ua, legacyAuth: !!legacyClient, errorCode,
      managedDevice: managed === undefined ? undefined : truthy(managed), compliantDevice: compliant === undefined ? undefined : truthy(compliant),
      ...extra,
    };
  };

  // 1) Okta-authored (eventType known)
  if (oktaType) {
    const res = (rawStr(ev, "okta.outcome.result") ?? (ev.event_type.includes("fail") || ev.event_type === "mfa_denied" ? "FAILURE" : "SUCCESS")).toUpperCase();
    const reason = rawStr(ev, "okta.outcome.reason") ?? "";
    const tgtAlt = rawStr(ev, "okta.target.alternateId", "target.user.email");
    const tgtName = rawStr(ev, "okta.target.displayName", "okta.target.0.displayName");
    const method = mfaMethodOf(ev);
    switch (oktaType) {
      case "user.session.start":
        if (res === "SUCCESS") return base("signin", true, { nativeName: oktaType, mfaUsed: !!method || /mfa|push approved|otp/i.test(desc), mfaMethod: method });
        if (res === "DENY") return base("policy", false, { decision: "DENY", failure: "ca_block" });
        if (/MFA_REQUIRED/i.test(reason)) return base("policy", true, { decision: "CHALLENGE", failure: "mfa_required" });
        return base("signin", false, { nativeName: oktaType, failure: /LOCKED/i.test(reason) ? "locked" : /VERIFICATION/i.test(reason) ? "other" : "bad_password" });
      case "user.authentication.auth_via_mfa":
        if (res === "CHALLENGE") return base("push_sent", true, { mfaUsed: true, mfaMethod: method ?? "push" });
        return base("mfa", res === "SUCCESS", { nativeName: oktaType, mfaUsed: true, mfaMethod: method ?? "push", failure: res === "SUCCESS" ? undefined : "mfa_denied" });
      case "user.mfa.okta_verify.push_response": case "user.mfa.okta_verify.deny_push":
        return base("mfa", res === "SUCCESS" && oktaType !== "user.mfa.okta_verify.deny_push", { mfaUsed: true, mfaMethod: "push", failure: res === "SUCCESS" ? undefined : "mfa_denied" });
      case "system.push.send_factor_verify_push": return base("push_sent", true, { nativeName: oktaType, mfaUsed: true, mfaMethod: "push" });
      case "policy.evaluate_sign_on": return base("policy", res !== "DENY", { nativeName: oktaType, decision: (res === "DENY" || res === "CHALLENGE" ? res : "ALLOW") as IdFacts["decision"] });
      case "user.account.lock": case "user.account.lock.limit":
        return base("lockout", true, { nativeName: "user.account.lock", email: tgtAlt?.toLowerCase() ?? email, displayName: tgtAlt ? nameFromLogin(tgtAlt) : displayNameOf(ev, email), failure: "locked" });
      case "security.threat.detected": return base("threat", res !== "DENY", { nativeName: oktaType, decision: res === "DENY" ? "DENY" : "ALLOW", threatSuspected: true, failure: res === "DENY" ? "malicious_ip" : undefined });
      case "user.mfa.factor.activate": case "device.enrollment.create":
        return base("factor_enroll", true, { nativeName: oktaType === "device.enrollment.create" ? undefined : oktaType, mfaMethod: method ?? "push",
          deviceName: oktaType === "device.enrollment.create" ? tgtName : undefined, devicePlatform: rawStr(ev, "okta.target.0.detailEntry.platform") });
      case "user.mfa.factor.deactivate":
        return base("factor_deactivate", true, { nativeName: oktaType, targetEmail: tgtAlt?.toLowerCase(), mfaMethod: method, email: rawStr(ev, "okta.actor.alternateId")?.toLowerCase() ?? email });
      case "user.mfa.factor.reset_all":
        return base("factor_reset", true, { nativeName: oktaType, targetEmail: tgtAlt?.toLowerCase(), email: rawStr(ev, "okta.actor.alternateId")?.toLowerCase() ?? email });
      case "group.user_membership.add":
        return base("group_add", true, { nativeName: oktaType, targetEmail: tgtAlt?.toLowerCase(), groupName: tgtName, email: rawStr(ev, "okta.actor.alternateId")?.toLowerCase() ?? email });
      case "application.user_membership.add":
        return base("app_assign", true, { nativeName: oktaType, targetEmail: tgtAlt?.toLowerCase(), appName: tgtName });
      case "user.account.privilege.grant":
        return base("role_grant", true, { nativeName: oktaType, targetEmail: tgtAlt?.toLowerCase() ?? email, roleName: tgtName, email: rawStr(ev, "okta.actor.alternateId")?.toLowerCase() ?? email });
      case "system.api_token.create": return base("token_create", true, { nativeName: oktaType, targetName: tgtName });
      case "system.api_token.revoke": return base("token_revoke", true, { nativeName: oktaType, targetName: rawStr(ev, "okta.actor.displayName") ?? tgtName });
      case "app.oauth2.as.token.grant": return base("token_grant", true, { nativeName: oktaType, appName: tgtName, interactive: false });
      case "user.authentication.sso": return base("sso", true, { nativeName: oktaType, appName: tgtName });
      case "user.session.end": return base("session_end", true, { nativeName: oktaType });
      case "system.org.rate_limit.warning": case "system.org.rate_limit.violation": case "application.integration.rate_limit_exceeded":
        return base("rate_limit", true, { nativeName: oktaType });
      default: return null;
    }
  }

  // 2) Entra / M365-authored audits
  const lop = op.toLowerCase();
  const ok = !/fail/i.test(rawStr(ev, "data.office365.ResultStatus", "azure.auditlogs.properties.result", "event.outcome") ?? "success");
  if (lop === "microsoft.graph/users/read") return base("directory_read", true);
  if (lop === "add application") return base("app_register", ok, { nativeName: "Add application", appName: rawStr(ev, "application.name", "oauth.app.name", "azure.auditlogs.target_resources.display_name") ?? extProp(ev, "AppDisplayName") ?? /named ([\w .-]+?) (?:was|app)/.exec(desc)?.[1] });
  if (lop === "consent to application") {
    const scopes = rawStr(ev, "oauth.consent.scopes_granted")?.replace(/\|/g, " ") ?? extProp(ev, "Permissions") ?? /consent to ([\w.]+(?:,? (?:and )?[\w.]+)*)/i.exec(desc)?.[1]?.replace(/,? and |, /g, " ");
    return base("consent", ok, { nativeName: "Consent to application", appName: rawStr(ev, "application.name", "oauth.app.name") ?? extProp(ev, "AppDisplayName") ?? /app (?:named )?([A-Z][\w ]+?) (?:requested|consent|app)/.exec(desc)?.[1], scopes,
      targetName: extProp(ev, "ConsentType") === "AllPrincipals" || truthy(rawAny(ev, "oauth.consent.tenant_wide")) ? "AllPrincipals" : "Principal" });
  }
  if (lop.startsWith("update conditional access policy")) return base("ca_policy_update", ok, { nativeName: "Update conditional access policy", targetName: rawStr(ev, "data.office365.Target[0].ID") });
  if (lop.startsWith("reset") && lop.includes("password")) return base("password_reset", ok, { nativeName: op === "Reset user password" ? "Reset user password" : op.includes("(by admin)") ? "Reset password (by admin)" : "Reset password",
    targetEmail: rawStr(ev, "target.user.email", "azure.auditlogs.properties.targetResources[0].userPrincipalName")?.toLowerCase() ?? email, email: rawStr(ev, "azure.auditlogs.properties.initiatedBy.user.userPrincipalName")?.toLowerCase() ?? email });
  if (lop.startsWith("change user password")) return base("password_change", ok, { nativeName: "Change user password" });
  if (lop.startsWith("invite external user")) return base("guest_invite", ok, { nativeName: "Invite external user", targetEmail: rawStr(ev, "data.office365.Target[0].ID") });
  if (lop === "set user risk level") return base("risk_change", ok);
  if (lop === "user registered security info") return base("factor_enroll", ok, { nativeName: "User registered security info", mfaMethod: registeredMethodOf(ev) ?? mfaMethodOf(ev) ?? "push" });
  if (lop === "admin deleted security info" || (lop === "update user" && /StrongAuthentication/i.test(JSON.stringify(ev.raw ?? {})))) {
    return base("factor_reset", ok, { nativeName: op, targetEmail: rawStr(ev, "azure.auditlogs.properties.targetResources[0].userPrincipalName")?.toLowerCase() ?? email,
      email: rawStr(ev, "azure.auditlogs.properties.initiatedBy.user.userPrincipalName")?.toLowerCase() ?? email });
  }
  if (lop === "add member to role") return base("role_grant", ok, { nativeName: "Add member to role", roleName: rawStr(ev, "azure.role.name"),
    targetEmail: rawStr(ev, "azure.target.upn")?.toLowerCase() ?? email, email: rawStr(ev, "azure.actor.upn")?.toLowerCase() ?? email });
  if (lop === "add member to group") return base("group_add", ok, { nativeName: "Add member to group" });

  // 3) Entra-authored sign-ins (signinlogs / UAL logon / shorthand)
  const isSignin = /^(userloggedin|userloginfailed|sign-in activity)$/.test(lop) || rawAny(ev, "azure.signinlogs.resultType", "azure.signinlogs.properties.id", "azure.signinlogs.user_principal_name",
    "azure.operationName", "azure.sign_in_event_types", "azure.error_code", "azure.signinlogs.properties.status.errorCode") !== undefined ||
    rawStr(ev, "event.action") === "MFA_PushDenied";
  if (isSignin || ["auth_success", "auth_failure", "mfa_denied", "mfa_challenge", "account_lockout"].includes(ev.event_type)) {
    const code = errorCodeOf(ev);
    const extDetail = extProp(ev, "ResultStatusDetail") ?? "";
    const method = mfaMethodOf(ev);
    let failure = failureFromCode(code);
    if (!failure && /MfaDeniedByUser/i.test(extDetail)) failure = "mfa_denied";
    if (!failure && /MFARequired/i.test(extDetail)) failure = "mfa_required";
    const failed = code !== undefined ? code !== 0 : (ev.event_type === "auth_failure" || ev.event_type === "mfa_denied" || ev.event_type === "account_lockout" ||
      /fail/i.test(rawStr(ev, "data.office365.ResultStatus", "event.outcome") ?? "") || rawStr(ev, "event.action") === "MFA_PushDenied");
    if (failed && !failure) failure = ev.event_type === "mfa_denied" || rawStr(ev, "event.action") === "MFA_PushDenied" ? "mfa_denied" :
      ev.event_type === "account_lockout" ? "locked" : failureFromText(desc + " " + (rawStr(ev, "azure.failure_reason") ?? "")) ?? "bad_password";
    const mfaish = ev.event_type === "mfa_challenge" || ev.event_type === "mfa_denied" || failure === "mfa_denied" || !!method ||
      /multiFactorAuthentication/.test(rawStr(ev, "azure.signinlogs.properties.authenticationRequirement", "azure.signinlogs.authentication_requirement") ?? "") ||
      /\bmfa\b|two-factor|authenticator|push/i.test(desc);
    // An "MFA push" event with no answer yet (mfa_challenge that only says a push was received)
    if (ev.event_type === "mfa_challenge" && /received an mfa push|push notification while/i.test(desc) && !/approv/i.test(desc)) return base("push_sent", true, { mfaUsed: true, mfaMethod: method ?? "push" });
    const legacy = rawStr(ev, "azure.client_app", "azure.signinlogs.properties.clientAppUsed");
    return base(failure === "mfa_denied" ? "mfa" : failure === "locked" && ev.event_type === "account_lockout" ? "lockout" : "signin", !failed, {
      failure, errorCode: code, mfaUsed: mfaish && failure !== "bad_password" && failure !== "no_user" && failure !== "disabled", mfaMethod: method ?? (mfaish ? "push" : undefined),
      protocol: legacy && /ActiveSync|IMAP|POP|SMTP/i.test(legacy) ? "ropc" : undefined,
      appName: rawStr(ev, "azure.signinlogs.properties.appDisplayName", "azure.signinlogs.app_display_name", "azure.appDisplayName") ?? appFromDesc(desc),
    });
  }
  if (ev.event_type === "role_assignment" || ev.event_type === "privilege_escalation") return base("role_grant", true, { roleName: /(Global Administrator|[A-Z][\w ]+ Admin(?:istrator)?)/.exec(desc)?.[1] });
  return null;
}
/**
 * The method a "User registered security info" audit added, from the authored reason / the NEW
 * StrongAuthenticationMethod entries (the last one added) — not the method the user had before.
 */
function registeredMethodOf(ev: TelemetryEvent): MfaMethod | undefined {
  const reason = rawStr(ev, "azure.auditlogs.properties.resultReason", "data.office365.ResultStatusDetail") ?? "";
  const mods = Object.entries(ev.raw ?? {}).filter(([k]) => /modifiedProperties\[\d+\]\.newValue$|ModifiedProperties\[\d+\]\.NewValue$/.test(k)).map(([, v]) => String(v)).join(" ");
  const added = [...mods.matchAll(/"MethodType"\s*:\s*"?(\w+)/g)].pop()?.[1] ?? "";
  const t = `${reason} ${added}`;
  if (/oath|software token|authenticator app code/i.test(t)) return "totp";
  if (/fido|security key|passkey/i.test(t)) return "fido";
  if (/sms|text message/i.test(t)) return "sms";
  if (/phone call|voice|TwoWayVoice/i.test(t)) return "voice";
  if (/authenticator|PhoneAppNotification|PhoneAppOTP|notification/i.test(t)) return "push";
  return undefined;
}
function extProp(ev: TelemetryEvent, name: string): string | undefined {
  const r = ev.raw ?? {};
  for (let i = 0; i < 8; i++) {
    if (r[`data.office365.ExtendedProperties[${i}].Name`] === name) return rawStr(ev, `data.office365.ExtendedProperties[${i}].Value`);
  }
  if (r["data.office365.ExtendedProperties.Name"] === name) return rawStr(ev, "data.office365.ExtendedProperties.Value");
  return undefined;
}
function appFromDesc(desc: string): string | undefined {
  const m = /signed in to (Microsoft Office|Exchange Online|SharePoint Online|Microsoft Teams|the Azure Portal|Azure portal|Outlook mobile|Microsoft 365|Salesforce|Workday|ServiceNow|GitHub Enterprise)/i.exec(desc);
  if (!m) return undefined;
  const v = m[1].toLowerCase();
  if (v.includes("exchange") || v.includes("outlook")) return "Office 365 Exchange Online";
  if (v.includes("sharepoint")) return "Office 365 SharePoint Online";
  if (v.includes("teams")) return "Microsoft Teams";
  if (v.includes("azure")) return "Azure Portal";
  if (v === "microsoft 365") return "OfficeHome";
  return m[1];
}

/** Okta-style 20-char object id with a type prefix, stable per seed. */
export function oktaId(ctx: NativeCtx, prefix: string, seed: string): string {
  const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const h = ctx.hex(seed, 40);
  let s = "";
  for (let i = 0; s.length < 20 - prefix.length; i++) s += alphabet[parseInt(h.slice(i * 2 % 40, i * 2 % 40 + 2), 16) % alphabet.length];
  return prefix + s;
}
/** Base62 token of length n (Okta request ids / session ids, Entra uniqueTokenIdentifier). */
export function b62(ctx: NativeCtx, seed: string, n: number): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  const h = ctx.hex(seed, Math.max(2, n) * 2);
  let s = "";
  for (let i = 0; i < n; i++) s += alphabet[parseInt(h.slice(i * 2, i * 2 + 2), 16) % 62];
  return s;
}

// ── stable identity ids (one value per user / per session, in every Microsoft record) ──

/** Entra object id of a user — the SAME value in Entra sign-ins / audits, the UAL (TokenObjectId, UserKey) and MDO (RecipientObjectId). */
export function entraObjectId(ctx: NativeCtx, upn: string): string {
  return ctx.uuid(`${ctx.companyId}:aadoid:${upn.toLowerCase()}`);
}
/**
 * Entra session id when the story authored none: one per user + client IP + day — the sign-in's
 * `sessionId` and the UAL's `AppAccessContext.AADSessionId` of what that session then did agree.
 */
export function aadSessionId(ctx: NativeCtx, upn: string, ip: string | undefined, ts: string): string {
  return ctx.uuid(`${ctx.companyId}:entra-session:${upn.toLowerCase()}:${ip ?? "-"}:${ts.slice(0, 10)}`);
}

// ── story-level threading ────────────────────────────────────────────────────

/** Rows whose src_ip is the CLIENT an IdP / SaaS / VPN gateway saw (not a mail relay, not a firewall 5-tuple). */
const CLIENT_SOURCES = new Set(["okta", "o365", "mfa", "gws", "vpn", "exchange", "sharepoint", "teams"]);
const isClientRow = (e: TelemetryEvent) => CLIENT_SOURCES.has(e.source) && !["email_received", "email_blocked", "email_quarantined"].includes(e.event_type);
const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
function clientIpOf(e: TelemetryEvent): string | undefined {
  const v = e.src_ip ?? rawStr(e, "okta.client.ipAddress", "azure.signinlogs.properties.ipAddress", "data.office365.ClientIP", "data.office365.ActorIpAddress", "source.ip", "data.remip");
  const ip = v?.trim().replace(/^\[([^\]]+)\](:\d+)?$/, "$1").replace(/^(\d{1,3}(?:\.\d{1,3}){3}):\d+$/, "$1");
  return ip && IPV4.test(ip) ? ip : undefined;
}
const emailOf = (e: TelemetryEvent) => (e.user?.email ?? e.user_email ?? rawStr(e, "okta.actor.alternateId", "azure.signinlogs.properties.userPrincipalName", "data.office365.UserId"))?.toLowerCase();
const OKTA_SID = "okta.authenticationContext.externalSessionId";
const ENTRA_SID = "azure.signinlogs.properties.sessionId";
/** An Okta row that belongs to an authenticated (or authenticating) session — not a failed password, a lockout or a ThreatInsight block. */
function oktaSessionRow(e: TelemetryEvent): boolean {
  const t = rawStr(e, "okta.eventType");
  if (!t || t === "user.account.lock" || t === "user.account.lock.limit" || t === "security.threat.detected") return false;
  if (t === "user.session.start") return /SUCCESS/i.test(rawStr(e, "okta.outcome.result") ?? "SUCCESS") || /MFA_REQUIRED/i.test(rawStr(e, "okta.outcome.reason") ?? "");
  return true;
}

/**
 * Story-level consistency for identity / SaaS / VPN rows, applied when a story is instantiated
 * (attackStories.instantiateStory). A renderer only ever sees one row; these facts span rows:
 *
 *  • one place and one network owner per client IP — the location / ASN / anonymizer flag the
 *    story authored for an address (first in time) is carried to every row of that address, so
 *    an MFA approval never sits in Tel Aviv while its sign-in sits in Warsaw;
 *  • one Okta session per login flow — a user's rows from one address less than an hour apart
 *    share the session id of the flow's first session-bearing row (sign-in, MFA, policy);
 *  • Entra / UAL linkage — sign-ins of a flow with no authored Entra session take the flow's
 *    authored one; a UAL record carries that session (AADSessionId) and a token issued at the
 *    latest sign-in before it (never before the flow's first sign-in);
 *  • mail — a sender who already mailed the recipient earlier in the story is not a first contact.
 *
 * Authored values on a row are kept, except where they contradict the address or the flow.
 */
export function threadIdentityContext(events: TelemetryEvent[]): TelemetryEvent[] {
  const order = events.map((e, i) => ({ e, i, t: Date.parse(e.ts) })).sort((a, b) => (a.t - b.t) || (a.i - b.i));
  const out = events.slice();

  // 1) one geo / network owner per client IP
  type Net = { asn?: number; as_org?: string; isp?: string; anonymous?: boolean };
  const NET_KEYS = ["asn", "as_org", "isp", "anonymous"] as const;
  const canon = new Map<string, { geo: ReturnType<typeof authoredGeo>; net: Net }>();
  for (const { e } of order) {
    if (!isClientRow(e)) continue;
    const ip = clientIpOf(e);
    if (!ip || isPrivateIp(ip)) continue;
    const g = authoredGeo(e);
    const proxyRaw = e.geo?.anonymous ?? rawAny(e, "okta.securityContext.isProxy");
    const n: Net = {
      asn: e.geo?.asn ?? num(rawStr(e, "okta.securityContext.asNumber", "azure.signinlogs.properties.autonomousSystemNumber")?.replace(/^AS/i, "")),
      as_org: e.geo?.as_org ?? rawStr(e, "okta.securityContext.asOrg"), isp: e.geo?.isp ?? rawStr(e, "okta.securityContext.isp"),
      anonymous: proxyRaw === undefined ? undefined : truthy(proxyRaw),
    };
    const c = canon.get(ip) ?? { geo: {}, net: {} };
    if (!c.geo.country && g.country) c.geo = { ...g };
    else if (g.country && countryInfo(g.country) === countryInfo(c.geo.country) && !c.geo.city && g.city) c.geo = { ...c.geo, city: g.city, latitude: g.latitude, longitude: g.longitude };
    for (const k of NET_KEYS) if (c.net[k] === undefined && n[k] !== undefined) (c.net as Record<string, unknown>)[k] = n[k];
    canon.set(ip, c);
  }
  for (const { e, i } of order) {
    if (!isClientRow(e)) continue;
    const ip = clientIpOf(e);
    const c = ip ? canon.get(ip) : undefined;
    if (!c || (!c.geo.country && NET_KEYS.every(k => c.net[k] === undefined))) continue;
    const geo: NonNullable<TelemetryEvent["geo"]> = { ...(e.geo ?? {}) };
    if (c.geo.country) {
      const same = countryInfo(authoredGeo(e).country) === countryInfo(c.geo.country);
      geo.country = c.geo.country;
      if (c.geo.city || !same) geo.city = c.geo.city;
      if (c.geo.latitude !== undefined || !same) { geo.latitude = c.geo.latitude; geo.longitude = c.geo.longitude; }
    }
    for (const k of NET_KEYS) if (c.net[k] !== undefined) (geo as Record<string, unknown>)[k] = c.net[k];
    for (const k of Object.keys(geo) as (keyof typeof geo)[]) if (geo[k] === undefined) delete geo[k];
    if (JSON.stringify(geo) !== JSON.stringify(e.geo ?? {})) out[i] = { ...out[i], geo };
  }

  // 2) login flows: one user, one client IP, rows less than an hour apart (time order)
  const FLOW_GAP = 60 * 60_000;
  type Row = { i: number; t: number };
  const flows: Row[][] = [];
  const open = new Map<string, Row[]>();
  for (const { i, t } of order) {
    const e = out[i];
    if (!isClientRow(e)) continue;
    const user = emailOf(e), ip = clientIpOf(e);
    if (!user || !ip) continue;
    const key = `${user}|${ip}`;
    const cur = open.get(key);
    if (cur && t - cur[cur.length - 1].t <= FLOW_GAP) cur.push({ i, t });
    else { const f = [{ i, t }]; flows.push(f); open.set(key, f); }
  }
  for (const flow of flows) {
    // Okta: every session-bearing row carries the first one's session id.
    const oktaRows = flow.filter(r => oktaSessionRow(out[r.i]));
    const oktaSid = oktaRows.map(r => rawStr(out[r.i], OKTA_SID)).find(Boolean);
    if (oktaSid) for (const r of oktaRows) {
      if (rawStr(out[r.i], OKTA_SID) !== oktaSid) out[r.i] = { ...out[r.i], raw: { ...(out[r.i].raw ?? {}), [OKTA_SID]: oktaSid } };
    }
    // Entra / UAL: sign-ins with no authored session take the flow's; what the session then did in
    // M365 carries that session (AADSessionId) and a token issued at the latest sign-in before it.
    const AAD = "data.office365.AppAccessContext.AADSessionId", IAT = "data.office365.AppAccessContext.IssuedAtTime";
    const entraSid = flow.filter(r => identityFacts(out[r.i])?.success).map(r => rawStr(out[r.i], ENTRA_SID)).find(Boolean) ?? flow.map(r => rawStr(out[r.i], ENTRA_SID)).find(Boolean);
    const signIns = flow.filter(r => { const e = out[r.i]; const f = !rawStr(e, "okta.eventType") ? identityFacts(e) : null; return !!f && f.success && (f.action === "signin" || f.action === "mfa"); });
    for (const r of flow) {
      const e = out[r.i];
      const raw = { ...(e.raw ?? {}) } as Record<string, unknown>;
      const keys = Object.keys(raw);
      const entraShaped = keys.some(k => k.startsWith("azure.signinlogs."));
      const ual = !entraShaped && !signIns.includes(r) && keys.some(k => k.startsWith("data.office365."));
      let changed = false;
      // A successful sign-in keeps an authored session of its own; a failed / interrupted step of the
      // flow has none in Entra, and shown as Okta it belongs to the session the flow then opened.
      const ok = identityFacts(e)?.success;
      if (entraSid && entraShaped && (ok ? !rawStr(e, ENTRA_SID) : rawStr(e, ENTRA_SID) !== entraSid)) { raw[ENTRA_SID] = entraSid; changed = true; }
      if (ual && entraSid && rawStr(e, AAD) !== entraSid) { raw[AAD] = entraSid; changed = true; }
      const last = signIns.filter(s => s.t <= r.t).pop();
      const iat = rawStr(e, IAT);
      if (ual && last && (!iat || Date.parse(`${iat.replace(/Z$/, "")}Z`) < signIns[0].t)) { raw[IAT] = new Date(last.t).toISOString().slice(0, 19); changed = true; }
      if (changed) out[r.i] = { ...e, raw };
    }
  }

  // 3) mail: a sender who already mailed this recipient earlier in the story is no first contact.
  const mailed = new Set<string>();
  for (const { i } of order) {
    const e = out[i];
    if (e.event_type !== "email_received") continue;
    const from = rawStr(e, "email.from.address", "data.office365.SenderFromAddress", "data.office365.Sender", "SenderFromAddress", "pps.sender")?.toLowerCase();
    const to = emailOf(e) ?? rawStr(e, "email.to.address")?.toLowerCase();
    if (!from || !to) continue;
    const pair = `${from}|${to}`;
    if (mailed.has(pair) && rawStr(e, "IsFirstContact", "data.office365.IsFirstContact") === undefined) out[i] = { ...e, raw: { ...(e.raw ?? {}), IsFirstContact: "0" } };
    mailed.add(pair);
  }
  return out;
}
