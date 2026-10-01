/**
 * Shared helpers for the Cloud native modules
 * (aws_cloudtrail, aws_guardduty, aws_vpcflow, azure_activity, gcp_audit, k8s_audit).
 *
 * The platform's legacy `ev.raw` maps hold the same facts under many spellings —
 * CloudTrail as `aws.cloudtrail.userIdentity.arn` / `aws.cloudtrail.request_parameters.*`,
 * GuardDuty as `aws.guardduty.*` or `aws.guardduty.finding.*`, Azure as
 * `azure.activitylogs.*` / `azure.alert.*` / `azure.open_ai.*`, K8s as
 * `kubernetes.audit.*`. These helpers read a fact from any spelling so a converter
 * carries evidence over verbatim, and derive stable per-entity identifiers.
 *
 * NONE of these legacy keys are ever written into a native record — they are the
 * SIEM-normalised input, not the source's native format ("no schema mixing").
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { NativeCtx } from "../types";

export type Raw = Record<string, unknown>;

/** First non-empty raw value among the given exact keys. */
export function rv(raw: Raw | undefined, ...keys: string[]): unknown {
  if (!raw) return undefined;
  for (const k of keys) {
    const v = raw[k];
    if (v !== undefined && v !== null && v !== "") return v;
  }
  return undefined;
}
/** Same as {@link rv} but as a trimmed string (undefined when absent). */
export function rs(raw: Raw | undefined, ...keys: string[]): string | undefined {
  const v = rv(raw, ...keys);
  if (v === undefined) return undefined;
  if (Array.isArray(v)) return v.map(String).join(", ");
  const s = String(v).trim();
  return s === "" ? undefined : s;
}
/** Same as {@link rv} but coerced to a finite number (undefined when absent/non-numeric). */
export function rn(raw: Raw | undefined, ...keys: string[]): number | undefined {
  const v = rv(raw, ...keys);
  if (v === undefined) return undefined;
  const n = typeof v === "number" ? v : Number(String(v).replace(/[, ]/g, ""));
  return Number.isFinite(n) ? n : undefined;
}
/** Boolean from a raw value that may be a real boolean or the strings "true"/"false". */
export function rb(raw: Raw | undefined, ...keys: string[]): boolean | undefined {
  const v = rv(raw, ...keys);
  if (v === undefined) return undefined;
  if (typeof v === "boolean") return v;
  const s = String(v).toLowerCase();
  if (s === "true") return true;
  if (s === "false") return false;
  return undefined;
}

/** Every raw key under a dotted prefix, mapped to its value with the prefix stripped. */
export function underPrefix(raw: Raw | undefined, prefix: string): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (!raw) return out;
  for (const [k, val] of Object.entries(raw)) {
    if (k.startsWith(prefix) && k.length > prefix.length) out[k.slice(prefix.length)] = val;
  }
  return out;
}

/** The acting user's email (structured fields first, then the raw map). */
export function userEmail(ev: TelemetryEvent): string | undefined {
  const cands = [ev.user?.email, ev.user_email];
  return cands.find(c => typeof c === "string" && c.includes("@"));
}

export function isPrivateIp(ip: string | undefined): boolean {
  if (!ip) return false;
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.)/.test(ip);
}

/** "2026-09-30T14:22:10Z" — UTC, no fractional seconds (CloudTrail eventTime). */
export function isoZ(ts: string): string {
  return new Date(Date.parse(ts)).toISOString().replace(/\.\d{3}Z$/, "Z");
}
/** "2026-09-30T14:22:10.418Z" — UTC with milliseconds (GuardDuty, Defender alerts). */
export function isoMs(ts: string): string {
  return new Date(Date.parse(ts)).toISOString();
}
/** "2026-09-30T14:22:10.4471823Z" — 7 fractional digits (Azure Event-Hub / GCP). Keeps the event ms, adds 4 seeded digits. */
export function iso7(ts: string, ctx: NativeCtx, seed: string, addSec = 0): string {
  const d = new Date(Date.parse(ts) + addSec * 1000).toISOString();
  return `${d.slice(0, 23)}${String(ctx.int(seed, 0, 9999)).padStart(4, "0")}Z`;
}
/** "2026-09-30T14:22:10.0000000Z" — 7 fractional digits, all from the event ms (Defender for Cloud UTC fields). */
export function iso7z(ts: string, addSec = 0): string {
  const d = new Date(Date.parse(ts) + addSec * 1000).toISOString();
  return `${d.slice(0, 23)}0000Z`;
}

/** Stable per-entity seed (never per event) so ids correlate across a story. */
export const entitySeed = (ctx: NativeCtx, kind: string, value: string) => `${ctx.companyId}:${kind}:${value.toLowerCase()}`;

/** 12-digit AWS account id — from the event if present, else stable per company. */
export function awsAccountId(ev: TelemetryEvent, ctx: NativeCtx): string {
  const fromRaw = rs(ev.raw, "aws.cloudtrail.userIdentity.accountId", "aws.cloudtrail.recipientAccountId",
    "cloud.account.id", "aws.guardduty.accountId", "aws.guardduty.finding.accountId", "accountId");
  if (fromRaw && /^\d{12}$/.test(fromRaw)) return fromRaw;
  return ctx.tenant.awsAccountId;
}

/** AWS region — from the event if present, else a default. IAM/STS global events belong in us-east-1. */
export function awsRegion(ev: TelemetryEvent, globalService = false): string {
  const r = rs(ev.raw, "aws.cloudtrail.awsRegion", "cloud.region", "aws.guardduty.region") ?? ev.cloud?.region;
  if (globalService) return "us-east-1";
  return r ?? "us-east-1";
}
