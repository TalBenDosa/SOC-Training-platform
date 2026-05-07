/**
 * Realistic IOC primitives — domains, IPs, hashes, URLs.
 * All values are synthetic but structurally identical to what an analyst sees in production.
 */
import { rng, pick, hashString } from "./rng";

export const MALICIOUS_TLDS = [".xyz", ".top", ".click", ".support", ".cyou", ".live", ".cf", ".ru", ".tk"];
export const SUSPICIOUS_KEYWORDS = ["secure", "login", "update", "verify", "drive", "msoffice", "support", "billing", "auth", "office365", "okta-auth"];
export const C2_HOSTS = ["cdn-static-edge", "telemetry-api", "metrics-collector", "node-relay", "sync-worker", "update-svc"];

export const KNOWN_GOOD_DOMAINS = [
  "microsoft.com","login.microsoftonline.com","office.com","outlook.office.com",
  "google.com","accounts.google.com","github.com","slack.com",
  "okta.com","cryotech.io","aws.amazon.com",
];

export const TOR_EXIT_SAMPLE_IPS = [
  "185.220.101.4","199.249.230.66","51.75.64.23","23.129.64.130","192.42.116.176",
];

// Country codes weighted toward APT origin patterns for realism
export const ATTACK_COUNTRIES = ["RU","CN","KP","IR","BY","UA","US","NL","DE","BR","IN","VN"];

export function makeSha256(seed: string): string {
  // Synthetic but realistic hex hash - deterministic per seed
  const r = rng(hashString(seed));
  let s = "";
  for (let i = 0; i < 64; i++) s += Math.floor(r() * 16).toString(16);
  return s;
}

export function makeMd5(seed: string): string {
  const r = rng(hashString(seed) ^ 0xdeadbeef);
  let s = ""; for (let i = 0; i < 32; i++) s += Math.floor(r() * 16).toString(16);
  return s;
}

export function makePublicIp(r: () => number): string {
  // Avoid private ranges
  let a = Math.floor(r() * 223) + 1;
  while (a === 10 || a === 127 || a === 172 || a === 192 || a === 169) a = Math.floor(r() * 223) + 1;
  return `${a}.${Math.floor(r()*256)}.${Math.floor(r()*256)}.${Math.floor(r()*254)+1}`;
}

export function makeMaliciousDomain(seed: number): string {
  const r = rng(seed);
  const kw = pick(r, SUSPICIOUS_KEYWORDS);
  const noise = Math.floor(r() * 100000).toString(36);
  const tld = pick(r, MALICIOUS_TLDS);
  return `${kw}-${noise}${tld}`;
}

export function makeC2Domain(seed: number): string {
  const r = rng(seed);
  const host = pick(r, C2_HOSTS);
  const noise = Math.floor(r() * 1e6).toString(16);
  const tlds = [".com", ".net", ".io", ".app", ".cloud"];
  return `${host}-${noise}${pick(r, tlds)}`;
}

export function makeDgaDomain(seed: number): string {
  // Random consonant-vowel pattern - typical DGA shape
  const r = rng(seed);
  const v = "aeiou", c = "bcdfghjklmnpqrstvwxyz";
  const len = 10 + Math.floor(r() * 8);
  let s = "";
  for (let i = 0; i < len; i++) s += (i % 2 ? v : c)[Math.floor(r() * (i % 2 ? v.length : c.length))];
  return `${s}.com`;
}

export function makePhishingUrl(seed: number): string {
  const r = rng(seed);
  const dom = makeMaliciousDomain(seed);
  const path = pick(r, [
    "/login/o365/auth", "/verify/account", "/secure/document", "/drive/share/preview",
    "/auth/session/refresh", "/billing/invoice/view"
  ]);
  const id = Math.floor(r() * 1e8).toString(16);
  return `https://${dom}${path}?id=${id}`;
}
