/**
 * The company asset FABRIC — one deterministic source of truth for the identities and
 * assets a generated log line should carry.
 *
 * The platform's recurring credibility bug is drift: a host, IP, user or domain typed
 * by hand in one event that doesn't match another, or a QuantumBank attack that opens
 * on a NexaCorp workstation. The cure is to stop typing those values and DRAW them —
 * every host, IP and identity comes from COMPANY_ASSETS (companyProfilesMeta.ts) through
 * the helpers here, keyed by a stable seed so the same seed always yields the same
 * asset. The vendor emitters (emitters/*) build on this so a whole scenario reads as one
 * company's estate, and the EDR console and SIEM feed show the same host + IP for the
 * same incident.
 */
import { COMPANY_ASSETS, type CompanyAssets, type RosterUser } from "./companyProfilesMeta";
import { hashString } from "./rng";

export type HostRole = "workstation" | "server" | "dc" | "fileServer" | "any";

export function assetsFor(companyId: string | undefined): CompanyAssets | undefined {
  return companyId ? COMPANY_ASSETS[companyId] : undefined;
}

/** Deterministic pick from a list by a seed string. */
function pickBy<T>(arr: readonly T[], seed: string, fallback: T): T {
  return arr.length ? arr[hashString(seed) % arr.length] : fallback;
}

const IS_SERVER = /(^SRV|SERVER|^DC[-_]|prod|EMR|FILE|SAP|ERP|WMS|APP|ADMIN|BACKUP|LINUX)/i;
const IS_WORKSTATION = /^(WS|WKS|LAP|NRS|WH|macbook)/i;

/** A company-native hostname, optionally constrained to a role, stable per seed. */
export function pickHost(companyId: string | undefined, seed: string, role: HostRole = "any"): string {
  const a = assetsFor(companyId);
  if (!a) return "endpoint";
  if (role === "dc") return a.dc;
  if (role === "fileServer") return a.fileServer;
  let pool = a.hosts;
  if (role === "server") pool = a.hosts.filter(h => IS_SERVER.test(h));
  else if (role === "workstation") pool = a.hosts.filter(h => IS_WORKSTATION.test(h));
  if (!pool.length) pool = a.hosts;
  return pickBy(pool, seed, a.hosts[0] ?? "endpoint");
}

/** A company-native user (login name, title, and email), stable per seed. */
export function pickUser(companyId: string | undefined, seed: string): RosterUser & { email: string } {
  const a = assetsFor(companyId);
  const fallback: RosterUser = { name: "j.doe", title: "Employee" };
  const u = a ? pickBy(a.roster, seed, a.roster[0] ?? fallback) : fallback;
  return { ...u, email: `${u.name}@${a?.domain ?? "example.com"}` };
}

/** A company service account (svc-*), stable per seed. */
export function pickServiceAccount(companyId: string | undefined, seed: string): string {
  const a = assetsFor(companyId);
  return a ? pickBy(a.serviceAccounts, seed, a.serviceAccounts[0] ?? "svc-backup") : "svc-backup";
}

/** An in-subnet internal IP for the company, stable per seed (last octet 10–249). */
export function ipFor(companyId: string | undefined, seed: string): string {
  const a = assetsFor(companyId);
  const subnet = a?.subnet ?? "10.0.0";
  return `${subnet}.${10 + (hashString(seed) % 240)}`;
}

/** Render a login name as this company's NetBIOS realm form: NEXACORP\r.avraham. */
export function netbiosUser(companyId: string | undefined, name: string): string {
  const a = assetsFor(companyId);
  const bare = name.includes("@") ? name.split("@")[0] : name;
  if (bare.includes("\\")) return bare;
  return a ? `${a.netbios}\\${bare}` : bare;
}

/** The company's DNS/email domain (for building email addresses / FQDNs). */
export function domainOf(companyId: string | undefined): string {
  return assetsFor(companyId)?.domain ?? "example.com";
}
