/**
 * Shared plumbing for the vendor log emitters (crowdstrike / sentinelone / mde …).
 *
 * The vendors differ only in their raw-block dialect and their disposition vocabulary.
 * Everything else — resolving a company-native host / user / IP from the asset fabric,
 * the deterministic sensor id and PID, the default on-disk paths, the severity label —
 * is identical, and lives here so each vendor module writes ONLY its own field mapping.
 */
import type { Severity } from "../types";
import { hashString } from "../rng";
import { pickHost, pickUser, ipFor, netbiosUser } from "../fabric";
import { makeSha256 } from "../iocs";

/** Caller context common to every emitter. Explicit host/user/ip win; else the fabric. */
export interface Ctx {
  id: string;
  ts: string;
  companyId?: string;
  host?: string;
  /** login name or email; rendered DOMAIN\user in the raw block */
  user?: string;
  srcIp?: string;
  incidentId?: string;
}

export interface Resolved {
  host: string;
  bareUser: string;
  email: string | undefined;
  domainUser: string;
  srcIp: string;
  sensorId: string;   // agent/sensor uuid — stable per host
}

/** Resolve identity + asset for an event, drawing from the fabric when not given. */
export function resolve(c: Ctx): Resolved {
  const host = c.host ?? pickHost(c.companyId, c.id, "workstation");
  const ru = c.user
    ? { name: c.user.includes("@") ? c.user.split("@")[0] : c.user, email: c.user.includes("@") ? c.user : undefined }
    : pickUser(c.companyId, c.id);
  const bareUser = ru.name;
  const email = "email" in ru ? ru.email : undefined;
  return {
    host,
    bareUser,
    email,
    domainUser: netbiosUser(c.companyId, bareUser),
    srcIp: c.srcIp ?? ipFor(c.companyId, host),   // keyed by host → same host, same IP
    sensorId: makeSha256(`sensor:${host}`).slice(0, 32),
  };
}

/** A stable decimal PID from a seed. */
export function pidFrom(seed: string): number {
  return 1000 + (hashString(`pid:${seed}`) % 63000);
}

/** Human severity label most EDRs print. */
export const SEV_NAME: Record<Severity, string> = {
  critical: "Critical", high: "High", medium: "Medium", low: "Low", informational: "Informational",
};

/** Default download path for a dropped payload, and default system path for a LOLBin. */
export const downloadsPath = (user: string, name: string) => `C:\\Users\\${user}\\Downloads\\${name}`;
export const systemPath = (name: string) => `C:\\Windows\\System32\\${name}`;

/** Deterministic hash for a payload when the author didn't pin one. */
export const hashFor = (seed: string) => makeSha256(seed);
