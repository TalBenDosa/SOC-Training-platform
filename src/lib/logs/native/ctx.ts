import type { NativeCtx } from "./types";

/** FNV-1a 32-bit. */
function fnv(s: string): number {
  let h = 2166136261 >>> 0;
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); }
  return h >>> 0;
}
/** Deterministic hex string of `len` chars from a seed (never Math.random). */
export function seededHex(seed: string, len: number): string {
  let out = "";
  let i = 0;
  while (out.length < len) out += fnv(`${seed}#${i++}`).toString(16).padStart(8, "0");
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

const DOMAINS: Record<string, { domain: string; netbios: string }> = {
  nexacorp: { domain: "nexacorp.com", netbios: "NEXACORP" },
  rocketstack: { domain: "rocketstack.io", netbios: "ROCKETSTACK" },
  medcore: { domain: "medcore-health.org", netbios: "MEDCORE" },
  globallogis: { domain: "globallogis.eu", netbios: "GLOBALLOGIS" },
  quantumbank: { domain: "quantumbank.com", netbios: "QBANK" },
};

/** Build the per-company context; identifiers are stable for a company across every session. */
export function makeCtx(companyId: string, overrides: Partial<Pick<NativeCtx, "domain" | "netbios">> = {}): NativeCtx {
  const d = DOMAINS[companyId] ?? { domain: `${companyId}.com`, netbios: companyId.toUpperCase().slice(0, 15) };
  return {
    companyId,
    domain: overrides.domain ?? d.domain,
    netbios: overrides.netbios ?? d.netbios,
    tenant: {
      awsAccountId: digits(`${companyId}:aws`, 12),
      azureTenantId: seededUuid(`${companyId}:aad`),
      azureSubscriptionId: seededUuid(`${companyId}:sub`),
      gcpProjectId: `${companyId}-prod-${seededHex(`${companyId}:gcp`, 6)}`,
      googleCustomerId: `C0${seededHex(`${companyId}:gws`, 7)}`,
      oktaOrg: `${companyId}.okta.com`,
      crowdstrikeCid: seededHex(`${companyId}:cid`, 32),
    },
    hex: seededHex,
    uuid: seededUuid,
    int: seededInt,
  };
}
