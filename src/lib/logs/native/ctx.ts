import { COMPANY_ASSETS } from "@/lib/sim/companyProfilesMeta";
import type { NativeCtx } from "./types";

/** FNV-1a 32-bit. */
function fnv(s: string): number {
  let h = 2166136261 >>> 0;
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); }
  return h >>> 0;
}
/** murmur3 32-bit finaliser — full avalanche, so consecutive chunks look independent. */
function fmix32(x: number): number {
  x ^= x >>> 16; x = Math.imul(x, 0x85ebca6b);
  x ^= x >>> 13; x = Math.imul(x, 0xc2b2ae35);
  x ^= x >>> 16;
  return x >>> 0;
}
/** Deterministic hex string of `len` chars from a seed (never Math.random). */
export function seededHex(seed: string, len: number): string {
  // A plain FNV of "seed#0", "seed#1"… only differs in the last byte, which left a
  // visible repeating pattern in hashes / GUIDs. Mix the seed state per chunk instead.
  const a = fnv(seed), b = fnv(`${seed}\u0001`);
  let out = "";
  let i = 0;
  while (out.length < len) {
    out += fmix32((a + Math.imul(i + 1, 0x9e3779b9)) ^ fmix32(b + i)).toString(16).padStart(8, "0");
    i++;
  }
  return out.slice(0, len);
}
export function seededUuid(seed: string): string {
  const h = seededHex(seed, 32);
  // RFC 4122 v4 shape (version + variant nibbles), deterministic.
  const v = ((parseInt(h[16], 16) & 0x3) | 0x8).toString(16);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-${v}${h.slice(17, 20)}-${h.slice(20, 32)}`;
}
export function seededInt(seed: string, min: number, max: number): number {
  return min + (fnv(seed) % (max - min + 1));
}
const digits = (seed: string, n: number) => {
  let s = ""; let i = 0;
  while (s.length < n) s += String(fnv(`${seed}~${i++}`) % 1_000_000_000).padStart(9, "0");
  return s.slice(0, n).replace(/^0/, "1");
};

// Domain + NetBIOS come from the company asset registry — the same email domain and realm
// the authored content uses (the renderers had drifted: medcore-health.org vs
// @medcorehealth.org mail, QBANK vs QUANTUMBANK). Time zone = the HQ's (companyProfilesMeta).
const TIME_ZONES: Record<string, string> = {
  nexacorp: "Europe/London",      // London, UK
  rocketstack: "UTC",             // cloud-native, servers on UTC
  medcore: "Europe/Amsterdam",    // Amsterdam, Netherlands
  globallogis: "Europe/Berlin",   // Frankfurt, Germany
  quantumbank: "Europe/Zurich",   // Zurich, Switzerland
};
const DOMAINS: Record<string, { domain: string; netbios: string; timeZone: string }> = Object.fromEntries(
  Object.keys(TIME_ZONES).map(id => {
    const a = COMPANY_ASSETS[id];
    return [id, { domain: a?.domain ?? `${id}.com`, netbios: a?.netbios ?? id.toUpperCase().slice(0, 15), timeZone: TIME_ZONES[id] }];
  }),
);

/** The company's NetBIOS domain — one realm per tenant everywhere. */
export function companyNetbios(companyId: string): string {
  return DOMAINS[companyId]?.netbios ?? companyId.toUpperCase().slice(0, 15);
}

/** IANA time zone of a company's on-prem servers (where its logs are stamped in local time). */
export function companyTimeZone(companyId: string): string {
  return DOMAINS[companyId]?.timeZone ?? "UTC";
}

/**
 * Seeds whose value is a fact about the world, not about a tenant — a file's hash, a public
 * domain's address, a vendor's signature / app / pattern / indicator id, an OS image's build hash.
 * The same in every company, so a payload hash or a C2 address carries over between stacks.
 * (rhex-style helpers wrap a seed as "<i>|<seed>|…", hence the "|" alternative.)
 */
const GLOBAL_SEED = /(^|\|)(sha1:|img:|dom:|threat:|s1:indicator:|role-template:|ftd:rev:|fgt:appid:|cp:appid:|cp:prot:|crowdstrike:pattern:|global:)|:authenticode(\||$)/;
/**
 * Every other seed is scoped to the tenant: an id seeded from an event id alone (a session id, a NAT
 * source port, an alert / threat id, a trace id …) would otherwise be identical in two companies
 * playing the same story — visible side by side in team / multi-company mode.
 */
const tenantSeed = (companyId: string, seed: string) => (GLOBAL_SEED.test(seed) ? seed : `${companyId}\u0002${seed}`);

/** Build the per-company context; identifiers are stable for a company across every session. */
export function makeCtx(companyId: string, overrides: Partial<Pick<NativeCtx, "domain" | "netbios">> = {}): NativeCtx {
  const d = DOMAINS[companyId] ?? { domain: `${companyId}.com`, netbios: companyId.toUpperCase().slice(0, 15), timeZone: "UTC" };
  const domain = overrides.domain ?? d.domain;
  return {
    companyId,
    org: domain.split(".")[0],
    domain,
    netbios: overrides.netbios ?? d.netbios,
    timeZone: d.timeZone,
    tenant: {
      awsAccountId: digits(`${companyId}:aws`, 12),
      azureTenantId: seededUuid(`${companyId}:aad`),
      azureSubscriptionId: seededUuid(`${companyId}:sub`),
      gcpProjectId: `${companyId}-prod-${seededHex(`${companyId}:gcp`, 6)}`,
      googleCustomerId: `C0${seededHex(`${companyId}:gws`, 7)}`,
      oktaOrg: `${companyId}.okta.com`,
      crowdstrikeCid: seededHex(`${companyId}:cid`, 32),
    },
    hex: (seed, len) => seededHex(tenantSeed(companyId, seed), len),
    uuid: seed => seededUuid(tenantSeed(companyId, seed)),
    int: (seed, min, max) => seededInt(tenantSeed(companyId, seed), min, max),
  };
}
