/**
 * R5 Addresses.
 *  - Every public IPv4 a row shows is a documentation address (192.0.2.0/24, 198.51.100.0/24,
 *    203.0.113.0/24), the kept 185.220.101.45, or an address of a well-known service range
 *    (Microsoft, Google, AWS, Cloudflare, Akamai, Zscaler, Fastly, Apple, public resolvers).
 *    One violation per address per scope (company feed, scenario, room, EDR case).
 *  - Each company's own public egress (COMPANY_ASSETS office IP) is a documentation address.
 * Blind spots (README): whether a well-known-range address is used for that service, internal
 * subnets per company, NAT coherence.
 */
import { COMPANY_ASSETS } from "@/lib/sim/companyProfilesMeta";
import type { Checker, LogRow, Violation } from "../types";
import { inCidr, isDocIPv4, isPrivateIPv4, isSpecialIPv4, rowIps } from "../util";
import { COMPANIES } from "../collectors/live";

export const KEPT_IP = "185.220.101.45";

const SERVICE_RANGES: [string, string][] = [
  // Microsoft (Azure, Microsoft 365, Entra)
  ...["13.64.0.0/11", "13.104.0.0/14", "20.0.0.0/8", "23.96.0.0/13", "40.64.0.0/10", "40.125.0.0/17", "51.4.0.0/15", "51.104.0.0/15", "52.96.0.0/12", "52.112.0.0/14",
    "52.136.0.0/13", "65.52.0.0/14", "104.40.0.0/13", "104.208.0.0/13", "131.253.0.0/16", "137.116.0.0/15", "157.54.0.0/15", "157.56.0.0/14", "191.232.0.0/13", "204.79.197.0/24"].map(c => ["Microsoft", c] as [string, string]),
  // Google
  ...["8.8.8.8/32", "8.8.4.4/32", "8.34.208.0/20", "34.64.0.0/10", "35.184.0.0/13", "35.192.0.0/12", "64.233.160.0/19", "66.102.0.0/20", "66.249.64.0/19", "72.14.192.0/18",
    "74.125.0.0/16", "108.177.0.0/17", "142.250.0.0/15", "172.217.0.0/16", "172.253.0.0/16", "173.194.0.0/16", "209.85.128.0/17", "216.58.192.0/19", "216.239.32.0/19"].map(c => ["Google", c] as [string, string]),
  // AWS
  ...["3.0.0.0/9", "13.32.0.0/12", "15.177.0.0/16", "18.128.0.0/9", "34.192.0.0/10", "35.152.0.0/13", "44.192.0.0/10", "50.16.0.0/14", "52.0.0.0/11", "52.32.0.0/11", "52.192.0.0/11",
    "54.64.0.0/10", "54.128.0.0/10", "54.192.0.0/12", "99.77.0.0/16", "176.32.96.0/19", "205.251.192.0/19"].map(c => ["AWS", c] as [string, string]),
  // Cloudflare
  ...["1.1.1.1/32", "1.0.0.1/32", "104.16.0.0/13", "104.24.0.0/14", "141.101.64.0/18", "162.158.0.0/15", "172.64.0.0/13", "188.114.96.0/20", "198.41.128.0/17"].map(c => ["Cloudflare", c] as [string, string]),
  // Akamai, Zscaler, Fastly, Apple, GitHub, resolvers
  ...["2.16.0.0/13", "23.0.0.0/12", "23.32.0.0/11", "104.64.0.0/10", "184.24.0.0/13"].map(c => ["Akamai", c] as [string, string]),
  ...["136.226.0.0/16", "147.161.0.0/16", "165.225.0.0/16"].map(c => ["Zscaler", c] as [string, string]),
  ["Fastly", "151.101.0.0/16"], ["Apple", "17.0.0.0/8"], ["GitHub", "140.82.112.0/20"], ["GitHub", "185.199.108.0/22"],
  ["Quad9", "9.9.9.9/32"], ["OpenDNS", "208.67.222.0/23"],
];

export function serviceOf(ip: string): string | undefined {
  return SERVICE_RANGES.find(([, c]) => inCidr(ip, c))?.[0];
}
export const isPublicNonDoc = (ip: string) => !isPrivateIPv4(ip) && !isSpecialIPv4(ip) && !isDocIPv4(ip) && ip !== KEPT_IP;

const scopeOf = (r: LogRow) => (r.surface === "live" || r.surface === "team" || r.surface === "xdr" ? `${r.surface}:${r.company}` : `${r.surface}:${r.storyId}`);

export const r5: Checker = c => {
  const out: Violation[] = [];
  const seen = new Set<string>();
  for (const r of c.rows) {
    for (const { key, ip } of rowIps(r)) {
      if (!isPublicNonDoc(ip) || serviceOf(ip)) continue;
      const scope = scopeOf(r);
      const k = `${scope}|${ip}`;
      if (seen.has(k)) continue;
      seen.add(k);
      out.push({ surface: r.surface, rule: "R5", rowId: `${scope}:${ip}`, detail: `public address ${ip} is not a documentation address`, company: r.company, storyId: r.storyId, example: `${r.rowId} ${key || "(text)"}` });
    }
  }
  for (const id of COMPANIES) {
    const ip = COMPANY_ASSETS[id]?.office?.ip;
    if (ip && !isDocIPv4(ip)) out.push({ surface: "live", rule: "R5", rowId: `config:${id}`, detail: `company egress ${ip} is not a documentation address`, company: id, example: "src/lib/sim/companyProfilesMeta.ts COMPANY_ASSETS.office.ip" });
  }
  return out;
};
