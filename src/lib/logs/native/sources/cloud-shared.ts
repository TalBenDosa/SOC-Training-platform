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

// ── AWS accounts, partitions, regions ─────────────────────────────────────────

/** AWS-documentation placeholder accounts (never a real tenant): replaced by the record's account. */
const PLACEHOLDER_ACCOUNTS = new Set(["123456789012", "111122223333", "444455556666", "000000000000", "210987654321"]);
/** A real-looking 12-digit account id (not a docs placeholder, not a 9-digit typo). */
export function isRealAccount(a: string | undefined): a is string {
  return !!a && /^\d{12}$/.test(a) && !PLACEHOLDER_ACCOUNTS.has(a);
}
/** The account segment of an ARN (`arn:<partition>:<service>:<region>:<account>:…`). */
export function arnAccount(arn: string | undefined): string | undefined {
  if (!arn || !arn.startsWith("arn:")) return undefined;
  return arn.split(":")[4] || undefined;
}

/**
 * The account a CloudTrail record / GuardDuty finding belongs to (`recipientAccountId`,
 * finding `accountId`): an explicitly authored record account first, then the account
 * that owns the authored role / user / resource ARNs, else the company's own account.
 * `userIdentity.accountId` alone is never used: for a cross-account call it is the
 * CALLER's account, and the company does not receive another organisation's trail.
 */
export function awsAccountId(ev: TelemetryEvent, ctx: NativeCtx): string {
  const raw = ev.raw;
  const direct = [rs(raw, "aws.cloudtrail.recipientAccountId"), rs(raw, "aws.guardduty.accountId", "aws.guardduty.finding.accountId"), rs(raw, "cloud.account.id"), rs(raw, "accountId")];
  for (const a of direct) if (isRealAccount(a)) return a;
  const arns = [
    /AssumeRole/.test(rs(raw, "aws.cloudtrail.eventName") ?? "") ? rs(raw, "aws.cloudtrail.requestParameters.roleArn", "aws.cloudtrail.request_parameters.role_arn") : undefined,
    rs(raw, "aws.cloudtrail.userIdentity.arn", "aws.cloudtrail.user_identity.arn"),
    rs(raw, "aws.cloudtrail.userIdentity.sessionContext.sessionIssuer.arn"),
    rs(raw, "aws.cloudtrail.requestParameters.resourceArn"),
    rs(raw, "aws.guardduty.arn", "aws.guardduty.finding.arn"),
  ];
  for (const arn of arns) { const a = arnAccount(arn); if (isRealAccount(a)) return a; }
  return ctx.tenant.awsAccountId;
}

export type AwsPartition = "aws" | "aws-us-gov" | "aws-cn";
/** The record is from AWS GovCloud (US): labelled so, or authored with a GovCloud region / ARN. */
export function isGovCloud(ev: TelemetryEvent): boolean {
  const region = rs(ev.raw, "aws.cloudtrail.awsRegion", "cloud.region", "aws.guardduty.region", "aws.guardduty.finding.region") ?? ev.cloud?.region;
  return /GovCloud/i.test(`${ev.vendor ?? ""} ${ev.description ?? ""}`) || !!region?.startsWith("us-gov-") ||
    Object.values(ev.raw ?? {}).some(v => typeof v === "string" && v.startsWith("arn:aws-us-gov:"));
}
/** Partition of a region (GovCloud / China have their own ARN partition). */
export function awsPartition(region: string): AwsPartition {
  return region.startsWith("us-gov-") ? "aws-us-gov" : region.startsWith("cn-") ? "aws-cn" : "aws";
}

/**
 * AWS region of the record — the authored one, else the partition's home region.
 * Global services (IAM, Organizations, sign-in …) record in the partition's home region
 * (us-east-1 / us-gov-west-1); a GovCloud record never carries a commercial region.
 */
export function awsRegion(ev: TelemetryEvent, globalService = false): string {
  const r = rs(ev.raw, "aws.cloudtrail.awsRegion", "cloud.region", "aws.guardduty.region", "aws.guardduty.finding.region") ?? ev.cloud?.region;
  if (isGovCloud(ev)) return !globalService && r?.startsWith("us-gov-") ? r : "us-gov-west-1";
  if (r?.startsWith("cn-")) return globalService ? "cn-north-1" : r;
  if (globalService) return "us-east-1";
  return r ?? "us-east-1";
}

/**
 * Re-home every ARN / bare account id in a native record onto the record's partition
 * and account: a GovCloud record never shows `arn:aws:`, and a docs-placeholder account
 * (123456789012) never sits next to the real one. Real foreign accounts are kept.
 */
export function rehomeArns<T>(value: T, partition: AwsPartition, acct: string, region?: string): T {
  const fix = (s: string): string => {
    if (s.startsWith("arn:")) {
      const p = s.split(":");
      if (p.length >= 5 && /^aws(-us-gov|-cn)?$/.test(p[1])) {
        p[1] = partition;
        // A regional resource of a GovCloud / China record sits in that partition's region.
        if (region && p[3] && awsPartition(p[3]) !== partition) p[3] = region;
        if (p[4] && /^\d+$/.test(p[4]) && !isRealAccount(p[4])) p[4] = acct;
        return p.join(":");
      }
      return s;
    }
    return PLACEHOLDER_ACCOUNTS.has(s) ? acct : s;
  };
  const walk = (v: unknown): unknown => {
    if (typeof v === "string") return fix(v);
    if (Array.isArray(v)) return v.map(walk);
    if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, walk(x)]));
    return v;
  };
  return walk(value) as T;
}

/** eventSource (service endpoint) of an AWS API name. */
export function awsServiceFor(en: string): string {
  if (en === "ConsoleLogin" || en === "CheckMfa") return "signin.amazonaws.com";
  if (/^(Get|List|Put|Delete|Head|Copy|Create)?(Bucket|Object)/.test(en) || /Bucket|PublicAccessBlock/.test(en)) return "s3.amazonaws.com";
  if (/^(AssumeRole|GetCallerIdentity|GetSessionToken|GetFederationToken|AssumeRoleWithSAML|AssumeRoleWithWebIdentity|DecodeAuthorizationMessage)/.test(en)) return "sts.amazonaws.com";
  if (/^(Create|Delete|Attach|Detach|Put|Update|List|Get)?(User|Role|Policy|AccessKey|Group|AssumeRolePolicy|LoginProfile|AccountPasswordPolicy|MFADevice|InstanceProfile|SAMLProvider|OpenIDConnectProvider)/.test(en)) return "iam.amazonaws.com";
  if (/^(Stop|Start)Logging|^(Delete|Create|Update|Put|Get)?(Trail|EventSelectors)/.test(en)) return "cloudtrail.amazonaws.com";
  if (/Secret/.test(en)) return "secretsmanager.amazonaws.com";
  if (/^(Invoke|Converse|Put|Get|Delete|Create).*Model|^(Invoke|Converse)/.test(en)) return "bedrock.amazonaws.com";
  if (/Alarm|MetricData/.test(en)) return "monitoring.amazonaws.com";
  if (/^(Decrypt|Encrypt|GenerateDataKey|ScheduleKeyDeletion|DisableKey)/.test(en)) return "kms.amazonaws.com";
  if (/DBInstance|DBCluster|DBSnapshot/.test(en)) return "rds.amazonaws.com";
  if (/^(Run|Describe|Terminate|Start|Stop|Authorize|Revoke|Create|Delete|Modify)?.*(Instances?|SecurityGroup|Vpcs?|Snapshots?|Volumes?|FlowLogs|KeyPair|Image)/.test(en)) return "ec2.amazonaws.com";
  return "ec2.amazonaws.com";
}

// ── AWS principals (shared by CloudTrail userIdentity and GuardDuty accessKeyDetails) ──

const hx = (ctx: NativeCtx, kind: string, value: string, len: number) => ctx.hex(entitySeed(ctx, kind, value), len).toUpperCase();
/** IAM user id (AIDA…, 21 chars) — one per user name. */
export const awsUserId = (ctx: NativeCtx, user: string) => "AIDA" + hx(ctx, "awsuser", user, 17);
/** Long-term access key of an IAM user (AKIA…, 20 chars). `n` > 1 = a second key of the same user. */
export const awsUserKey = (ctx: NativeCtx, user: string, n = 1) => "AKIA" + hx(ctx, "awsak", n > 1 ? `${user}#${n}` : user, 16);
/** Role id (AROA…, 21 chars) — one per role name. */
export const awsRoleId = (ctx: NativeCtx, role: string) => "AROA" + hx(ctx, "awsrole", role, 17);
/** Temporary key of a role session (ASIA…) — the same key for every call of one role/session. */
export const awsSessionKey = (ctx: NativeCtx, role: string, session: string) => "ASIA" + hx(ctx, "awssess", `${role}/${session}`, 16);

/** IAM Identity Center permission-set role of a human user (the company's SSO landing role). */
export const ssoRoleName = (ctx: NativeCtx, acct: string) => `AWSReservedSSO_PlatformAdmin_${ctx.hex(entitySeed(ctx, "ssoperm", acct), 16)}`;

/** Service / workload accounts (never a person signing in through the IdP). */
const SERVICE_NAME = /(^|[-._])(svc|service|ci|cd|pipeline|deploy|deployer|backup|bot|automation|admin|terraform|jenkins|github|gitlab|runner|sync|monitor|monitoring|batch|etl|api|app|system|scanner|lambda|ops|release|build|artifacts|reporting|export|import|readonly|integration|sa)([-._@]|\d|$)/i;
/** A person's mailbox local part (first.last / f.last), as opposed to a service account. */
export function isHumanLogin(local: string): boolean {
  return /^[a-z]+([._-][a-z]+)+$/i.test(local) && !SERVICE_NAME.test(local);
}

export type AwsPrincipalType = "IAMUser" | "AssumedRole" | "Root" | "FederatedUser" | "AWSService" | "AWSAccount" | "SAMLUser" | "WebIdentityUser" | "Anonymous" | "Unknown";
export interface AwsPrincipal {
  type: AwsPrincipalType;
  /** IAMUser / FederatedUser / SAML / web-identity user name. */
  userName?: string;
  /** AssumedRole: the role (session issuer) and the session name. */
  roleName?: string;
  rolePath?: string;
  session?: string;
  accountId: string;
  accessKeyId?: string;
  principalId?: string;
  arn?: string;
  /** AssumedRole session context (authored values only; the renderer fills the rest). */
  issuerArn?: string;
  issuerPrincipalId?: string;
  creationDate?: string;
  mfaAuthenticated?: string;
  ec2RoleDelivery?: string;
  identityProvider?: string;
  invokedBy?: string;
  /** True when nothing on the event names the principal (the renderer had to fall back). */
  fallback: boolean;
}

const roleFromArn = (arn: string | undefined): { role?: string; path?: string; session?: string } => {
  if (!arn) return {};
  const ar = /:assumed-role\/(.+)\/([^/]+)$/.exec(arn);
  if (ar) return { role: ar[1].split("/").pop(), session: ar[2] };
  const r = /:role\/(.+)$/.exec(arn);
  if (r) { const parts = r[1].split("/"); const role = parts.pop()!; return { role, path: parts.length ? `/${parts.join("/")}/` : undefined }; }
  return {};
};

/**
 * The calling AWS principal as the event authored it — the type, names, ids and keys it
 * carries (CloudTrail `userIdentity.*`, GuardDuty `resource.accessKeyDetails.*`), with
 * only the gaps derived, from stable per-entity seeds so a user / role session / key is the
 * SAME identity on every row of a story. A person with no authored AWS identity reaches AWS
 * through the company IdP (IAM Identity Center session), never as an IAM user with an AKIA key.
 */
export function awsPrincipal(ev: TelemetryEvent, ctx: NativeCtx, acct: string): AwsPrincipal {
  const raw = ev.raw;
  const U = (k: string, ...alt: string[]) => rs(raw, `aws.cloudtrail.userIdentity.${k}`, ...alt);
  const GD = (k: string) => rs(raw, `aws.guardduty.resource.accessKeyDetails.${k}`, `aws.guardduty.finding.resource.accessKeyDetails.${k}`);
  let type = (U("type", "aws.cloudtrail.user_identity.type") ?? GD("userType")) as string | undefined;
  if (type === "Service") type = "AWSService";
  if (type === "Role") type = "AssumedRole";
  const arn = U("arn", "aws.cloudtrail.user_identity.arn");
  const userName = U("userName", "aws.cloudtrail.user_identity.user_name");
  const gdUser = GD("userName");
  const issuerArn = U("sessionContext.sessionIssuer.arn");
  const issuerName = U("sessionContext.sessionIssuer.userName", "aws.cloudtrail.user_identity.session_issuer.user_name");
  const principalId = U("principalId") ?? GD("principalId");
  const accessKeyId = U("accessKeyId") ?? GD("accessKeyId");
  const email = userEmail(ev);
  const local = email?.split("@")[0];

  if (!type) {
    if (arn?.includes(":assumed-role/") || arn?.includes(":role/") || issuerName || issuerArn) type = "AssumedRole";
    else if (arn?.endsWith(":root")) type = "Root";
    else if (arn?.includes(":federated-user/")) type = "FederatedUser";
    else if (arn?.includes(":user/") || userName || accessKeyId?.startsWith("AKIA")) type = "IAMUser";
    else if (local) type = isHumanLogin(local) ? "AssumedRole" : "IAMUser";
  }
  const base = {
    accountId: acct, principalId, accessKeyId,
    creationDate: U("sessionContext.attributes.creationDate"), mfaAuthenticated: U("sessionContext.attributes.mfaAuthenticated"),
    ec2RoleDelivery: U("sessionContext.ec2RoleDelivery"), identityProvider: U("identityProvider"), invokedBy: U("invokedBy"),
  };
  switch (type) {
    case "AssumedRole": {
      const fromArn = roleFromArn(arn);
      const fromIssuer = roleFromArn(issuerArn);
      let roleName = issuerName ?? fromIssuer.role ?? fromArn.role ?? gdUser;
      let session = fromArn.session ?? (principalId?.includes(":") ? principalId.split(":").slice(1).join(":") : undefined);
      let rolePath = fromIssuer.path ?? fromArn.path;
      let fallback = false;
      if (!roleName && local) {
        // A person → the IdP's Identity Center session; a workload → its own role.
        if (isHumanLogin(local)) { roleName = ssoRoleName(ctx, acct); rolePath = "/aws-reserved/sso.amazonaws.com/"; session = session ?? email; }
        else roleName = local.endsWith("-role") ? local : `${local}-role`;
      }
      if (!roleName) { roleName = "unknown-role"; fallback = true; }
      if (!session) session = local ?? roleName;
      if (!rolePath && roleName.startsWith("AWSReservedSSO_")) rolePath = "/aws-reserved/sso.amazonaws.com/";
      return { ...base, type: "AssumedRole", roleName, rolePath, session, issuerArn, issuerPrincipalId: U("sessionContext.sessionIssuer.principalId"), fallback };
    }
    case "Root": return { ...base, type: "Root", fallback: false };
    case "AWSService": return { ...base, type: "AWSService", fallback: false };
    case "AWSAccount": return { ...base, type: "AWSAccount", accountId: U("accountId") ?? acct, fallback: false };
    case "Anonymous": return { ...base, type: "Anonymous", fallback: false };
    case "FederatedUser": {
      const name = userName ?? arn?.split("/").pop() ?? local ?? "unknown";
      return { ...base, type: "FederatedUser", userName: name, fallback: !userName && !arn && !local };
    }
    case "SAMLUser": case "WebIdentityUser":
      return { ...base, type, userName: userName ?? email ?? local, fallback: !userName && !email };
    default: {
      const name = userName ?? arn?.split("/").pop() ?? gdUser ?? local;
      return { ...base, type: "IAMUser", userName: name ?? "unknown", arn, fallback: !name };
    }
  }
}

/** "Sep 30, 2026 2:21:30 AM" — the date format IAM / STS responseElements use in CloudTrail. */
export function awsLongDate(ms: number): string {
  const d = new Date(ms);
  const mon = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"][d.getUTCMonth()];
  const h = d.getUTCHours(), h12 = h % 12 === 0 ? 12 : h % 12;
  const p2 = (n: number) => String(n).padStart(2, "0");
  return `${mon} ${d.getUTCDate()}, ${d.getUTCFullYear()} ${h12}:${p2(d.getUTCMinutes())}:${p2(d.getUTCSeconds())} ${h < 12 ? "AM" : "PM"}`;
}

/**
 * Stable creation time of a role session that has no authored one: the session was
 * issued shortly before the 6-hour window the call falls in (instance-role / SSO
 * credentials live hours, not one call), so every call of the session shares it.
 */
export function sessionCreationDate(ctx: NativeCtx, ts: string, role: string, session: string): string {
  const t = Date.parse(ts);
  const block = Math.floor(t / 21_600_000) * 21_600_000;
  const back = ctx.int(entitySeed(ctx, "sesscreated", `${role}/${session}/${block}`), 4 * 60, 50 * 60);
  return isoZ(new Date(block - back * 1000).toISOString());
}
