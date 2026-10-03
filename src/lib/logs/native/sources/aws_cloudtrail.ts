/**
 * AWS CloudTrail — native source module.
 *
 * Card: docs/log-schemas/cloud-aws-cloudtrail.md. Native format = the bare
 * CloudTrail event object (what the `Records[]` array holds), nested exactly as
 * AWS delivers it, native camelCase keys. No `aws.cloudtrail.*` ECS flattening,
 * no Wazuh `data.*` envelope ("no schema mixing", Tal 2026-10-01).
 *
 * Identity consistency: the same IAM user / role → the same principalId / arn /
 * accessKeyId across a story. Values already present in the event survive verbatim
 * (that is what a student quotes); only the gaps are filled deterministically from
 * ctx, seeded by the entity (so a key correlates across every event it touched).
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { KindSchema, NativeCtx, NativeLog, NativeSource, SourceSchema, UseCase } from "../types";
import {
  arnAccount, awsAccountId, awsLongDate, awsPartition, awsPrincipal, awsRegion, awsRoleId, awsServiceFor, awsSessionKey,
  awsUserId, awsUserKey, entitySeed, isoZ, isPrivateIp, isRealAccount, rb, rehomeArns, rn, rs, rv, sessionCreationDate,
  underPrefix, userEmail, type AwsPartition, type AwsPrincipal,
} from "./cloud-shared";

// ── schema ───────────────────────────────────────────────────────────────────

/** Top-level + userIdentity leaf fields a CloudTrail API-call event may carry. */
const API_OPTIONAL = [
  "errorCode", "errorMessage", "apiVersion", "readOnly", "managementEvent", "eventCategory",
  "recipientAccountId", "requestID", "sharedEventID", "vpcEndpointId", "vpcEndpointAccountId",
  "sessionCredentialFromConsole", "sourceIPAddress", "userAgent",
  "tlsDetails.tlsVersion", "tlsDetails.cipherSuite", "tlsDetails.clientProvidedHostHeader",
  "resources[].ARN", "resources[].accountId", "resources[].type",
  "userIdentity.type", "userIdentity.principalId", "userIdentity.arn", "userIdentity.accountId",
  "userIdentity.accessKeyId", "userIdentity.userName", "userIdentity.invokedBy", "userIdentity.credentialId",
  "userIdentity.identityProvider", "userIdentity.sourceIdentity",
  "userIdentity.sessionContext.sessionIssuer.type", "userIdentity.sessionContext.sessionIssuer.principalId",
  "userIdentity.sessionContext.sessionIssuer.arn", "userIdentity.sessionContext.sessionIssuer.accountId",
  "userIdentity.sessionContext.sessionIssuer.userName",
  "userIdentity.sessionContext.attributes.creationDate", "userIdentity.sessionContext.attributes.mfaAuthenticated",
  "userIdentity.sessionContext.ec2RoleDelivery", "userIdentity.sessionContext.webIdFederationData",
];
const API_REQUIRED = ["eventVersion", "userIdentity", "eventTime", "eventSource", "eventName", "awsRegion", "eventID", "eventType"];
/** Free-form sub-objects — their inner keys are API-specific, not schema-checked. */
const OPEN = ["requestParameters", "responseElements", "additionalEventData", "serviceEventDetails", "addendum", "insightDetails", "userIdentity.onBehalfOf", "userIdentity.webIdFederationData"];

const apiKind = (): KindSchema => ({ required: API_REQUIRED, optional: API_OPTIONAL, openPrefixes: OPEN });

const kinds: Record<string, KindSchema> = {
  AwsApiCall: apiKind(),
  AwsConsoleSignIn: apiKind(),
  AwsServiceEvent: { required: ["eventVersion", "eventTime", "eventSource", "eventName", "awsRegion", "eventID", "eventType"], optional: [...API_OPTIONAL, "serviceEventDetails"], openPrefixes: OPEN },
  AwsCloudTrailInsight: { required: ["eventVersion", "eventTime", "awsRegion", "eventID", "eventType", "eventCategory", "insightDetails"], optional: ["recipientAccountId", "sharedEventID"], openPrefixes: ["insightDetails"] },
};

const schema: SourceSchema = {
  sourceId: "aws_cloudtrail",
  category: "cloud",
  card: "cloud-aws-cloudtrail.md",
  product: "AWS CloudTrail",
  format: "json",
  vendorMatch: ["cloudtrail"],
  telemetrySources: ["cloudtrail"],
  kinds,
};

/** Classify a native CloudTrail record (used to validate card samples). */
export function kindOf(record: Record<string, unknown>): string | null {
  const et = record["eventType"];
  if (typeof et === "string" && kinds[et]) return et;
  if (record["insightDetails"] || record["eventCategory"] === "Insight") return "AwsCloudTrailInsight";
  if (record["eventName"] === "ConsoleLogin") return "AwsConsoleSignIn";
  if (record["eventName"] && record["eventSource"]) return "AwsApiCall";
  return null;
}

// ── conversion ────────────────────────────────────────────────────────────────

/** Services whose events are recorded in the partition's home region (STS is regional: it records the caller's region). */
const GLOBAL_SOURCES = new Set(["iam.amazonaws.com", "organizations.amazonaws.com", "cloudfront.amazonaws.com", "route53.amazonaws.com", "signin.amazonaws.com"]);
const READONLY_RE = /^(Get|List|Describe|Head|BatchGet|Lookup|Select|Search|View)/;
const DATA_EVENTS = new Set(["GetObject", "PutObject", "DeleteObject", "DeleteObjects", "HeadObject", "CopyObject", "SelectObjectContent", "GetObjectAcl", "GetObjectTagging", "ListObjects", "ListObjectsV2", "RestoreObject", "UploadPart"]);
/** STS calls that mint credentials — their responseElements carry the new key even though the name starts with Get. */
const CRED_ISSUING = new Set(["GetSessionToken", "GetFederationToken"]);

/** Turn flattened `a.b.0.c` keys into the nested objects / arrays CloudTrail really delivers. */
function unflatten(flat: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [path, val] of Object.entries(flat)) {
    const parts = path.split(".");
    let cur: Record<string, unknown> | unknown[] = out;
    parts.forEach((p, i) => {
      const last = i === parts.length - 1;
      const key: string | number = Array.isArray(cur) ? Number(p) : p;
      if (last) { (cur as Record<string | number, unknown>)[key] = val; return; }
      const nextIsIdx = /^\d+$/.test(parts[i + 1]);
      const existing = (cur as Record<string | number, unknown>)[key];
      if (!existing || typeof existing !== "object") (cur as Record<string | number, unknown>)[key] = nextIsIdx ? [] : {};
      cur = (cur as Record<string | number, unknown>)[key] as Record<string, unknown> | unknown[];
    });
  }
  return out;
}
/** Deep merge — `over` wins on every leaf it carries (authored values beat derived ones). */
function merge(base: Record<string, unknown>, over: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = { ...base };
  for (const [k, v] of Object.entries(over)) {
    const b = out[k];
    out[k] = v && typeof v === "object" && !Array.isArray(v) && b && typeof b === "object" && !Array.isArray(b)
      ? merge(b as Record<string, unknown>, v as Record<string, unknown>) : v;
  }
  return out;
}

/** snake_case legacy request keys → the native camelCase CloudTrail parameter names. */
const SNAKE_PARAM: Record<string, string> = {
  db_instance_id: "dBInstanceIdentifier", storage_encrypted: "storageEncrypted", trail_name: "trailName",
  event_selectors: "eventSelectors", path_prefix: "pathPrefix", role_arn: "roleArn", role_session_name: "roleSessionName",
  user_name: "userName", policy_arn: "policyArn", bucket_name: "bucketName", secret_id: "secretId",
};
const camel = (k: string) => SNAKE_PARAM[k] ?? k.replace(/_([a-z])/g, (_, c: string) => c.toUpperCase());

/** Merge the legacy request/response keys (flattened, snake_case or a JSON string) into a native sub-object. */
function collectParams(raw: Record<string, unknown> | undefined, flatPrefixes: string[], jsonKey: string): Record<string, unknown> | undefined {
  const flat: Record<string, unknown> = {};
  for (const prefix of flatPrefixes) {
    for (const [k, v] of Object.entries(underPrefix(raw, prefix))) flat[prefix.includes("_") ? k.split(".").map(camel).join(".") : k] = v;
  }
  const out = unflatten(flat);
  const jsonStr = rs(raw, jsonKey);
  if (jsonStr && jsonStr.startsWith("{")) {
    try { for (const [k, v] of Object.entries(JSON.parse(jsonStr) as Record<string, unknown>)) out[camel(k)] = v; } catch { /* keep flattened only */ }
  }
  return Object.keys(out).length ? out : undefined;
}

/** A plausible base64 blob (SAML name qualifiers, session tokens) from a seed — no Node Buffer (runs in the browser). */
function b64(ctx: NativeCtx, seed: string, bytes: number): string {
  const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const hex = ctx.hex(seed, bytes * 2);
  const by = Array.from({ length: bytes }, (_, i) => parseInt(hex.slice(i * 2, i * 2 + 2), 16));
  let s = "";
  for (let i = 0; i < by.length; i += 3) {
    const n = (by[i] << 16) | ((by[i + 1] ?? 0) << 8) | (by[i + 2] ?? 0);
    s += A[(n >> 18) & 63] + A[(n >> 12) & 63] + (i + 1 < by.length ? A[(n >> 6) & 63] : "=") + (i + 2 < by.length ? A[n & 63] : "=");
  }
  return s;
}

/** The native `userIdentity` of the calling principal (authored values verbatim, gaps from per-entity seeds). */
function buildUserIdentity(ev: TelemetryEvent, ctx: NativeCtx, pr: AwsPrincipal, part: AwsPartition, es: string, isSignIn: boolean): Record<string, unknown> {
  const acct = pr.accountId;
  switch (pr.type) {
    case "AssumedRole": {
      const role = pr.roleName!, session = pr.session!;
      const authoredRoleId = pr.principalId?.split(":")[0];
      const roleId = pr.issuerPrincipalId ?? (authoredRoleId?.startsWith("AROA") ? authoredRoleId : awsRoleId(ctx, role));
      const sc: Record<string, unknown> = {
        sessionIssuer: {
          type: "Role", principalId: roleId,
          arn: pr.issuerArn ?? `arn:${part}:iam::${acct}:role${pr.rolePath ?? "/"}${role}`,
          accountId: acct, userName: role,
        },
        attributes: {
          creationDate: pr.creationDate ?? sessionCreationDate(ctx, ev.ts, role, session),
          mfaAuthenticated: pr.mfaAuthenticated ?? "false",
        },
      };
      // An EC2 instance-profile session is named after the instance and delivered by IMDSv2.
      const ec2 = pr.ec2RoleDelivery ?? (/^i-[0-9a-f]{8,17}$/.test(session) ? "2.0" : undefined);
      if (ec2) sc.ec2RoleDelivery = ec2;
      return {
        type: "AssumedRole",
        principalId: pr.principalId?.includes(":") ? pr.principalId : `${roleId}:${session}`,
        // The session lives in the role's own account — the record's account.
        arn: `arn:${part}:sts::${acct}:assumed-role/${role}/${session}`,
        accountId: acct,
        accessKeyId: pr.accessKeyId ?? awsSessionKey(ctx, role, session),
        sessionContext: sc,
      };
    }
    case "Root":
      return { type: "Root", principalId: acct, arn: `arn:${part}:iam::${acct}:root`, accountId: acct, ...(isSignIn ? { accessKeyId: "" } : pr.accessKeyId ? { accessKeyId: pr.accessKeyId } : {}) };
    case "AWSService":
      return { type: "AWSService", invokedBy: pr.invokedBy ?? es };
    case "AWSAccount":
      return { type: "AWSAccount", principalId: pr.principalId ?? ("AIDA" + ctx.hex(entitySeed(ctx, "awsextprincipal", pr.accountId), 17).toUpperCase()), accountId: pr.accountId };
    case "Anonymous":
      return { type: "Anonymous", accountId: "anonymous", arn: "anonymous" };
    case "SAMLUser": {
      const name = pr.userName ?? "unknown";
      const idp = pr.identityProvider ?? b64(ctx, entitySeed(ctx, "samlidp", acct), 20);
      return { type: "SAMLUser", principalId: `${b64(ctx, entitySeed(ctx, "samlsubj", `${acct}:${name}`), 20)}:${name}`, userName: name, identityProvider: idp };
    }
    case "WebIdentityUser": {
      const name = pr.userName ?? "unknown";
      const idp = pr.identityProvider ?? "token.actions.githubusercontent.com";
      return { type: "WebIdentityUser", principalId: pr.principalId ?? `arn:${part}:iam::${acct}:oidc-provider/${idp}:sts.amazonaws.com:${name}`, userName: name, identityProvider: idp, accountId: acct };
    }
    case "FederatedUser": {
      const name = pr.userName!;
      return { type: "FederatedUser", principalId: pr.principalId ?? `${acct}:${name}`, arn: `arn:${part}:sts::${acct}:federated-user/${name}`, accountId: acct, accessKeyId: pr.accessKeyId ?? awsSessionKey(ctx, "federated", name) };
    }
    default: {
      // IAMUser — a long-term AKIA key (a console sign-in carries none).
      const name = pr.userName ?? "unknown";
      const ownAcct = isRealAccount(arnAccount(pr.arn)) ? arnAccount(pr.arn)! : acct;
      const path = pr.arn && /:user(\/.+)?\/[^/]+$/.test(pr.arn) ? (/:user(\/.*\/)[^/]+$/.exec(pr.arn)?.[1] ?? "/") : "/";
      return {
        type: "IAMUser",
        principalId: pr.principalId ?? awsUserId(ctx, name),
        arn: `arn:${part}:iam::${ownAcct}:user${path}${name}`,
        accountId: ownAcct,
        accessKeyId: isSignIn ? "" : pr.accessKeyId ?? awsUserKey(ctx, name),
        userName: name,
      };
    }
  }
}

/** The caller's name as a session name for the credentials it requests. */
function callerSessionName(pr: AwsPrincipal): string | undefined {
  if (pr.type === "AssumedRole") return pr.session;
  return pr.userName;
}

/**
 * responseElements the API really returns (when the event authored none): the new key of
 * CreateAccessKey, the temporary credentials + assumed-role user of AssumeRole*, the user of
 * CreateUser, the instances of RunInstances … — derived from the SAME per-entity seeds the later
 * rows use, so the key / session minted here is the one a student follows into the next calls.
 * Read-only calls log none.
 */
function buildResponse(en: string, ev: TelemetryEvent, ctx: NativeCtx, pr: AwsPrincipal, part: AwsPartition, acct: string, region: string,
  req: Record<string, unknown>, failed: boolean): Record<string, unknown> | null {
  const t = Date.parse(ev.ts);
  const created = awsLongDate(t);
  const str = (v: unknown) => (typeof v === "string" && v.trim() ? v.trim() : undefined);
  const token = (seed: string) => `IQoJb3JpZ2luX2VjE${b64(ctx, entitySeed(ctx, "ststoken", seed), 45)}`;
  if (en === "ConsoleLogin") return { ConsoleLogin: failed ? "Failure" : "Success" };
  if (failed) return null;

  if (/^AssumeRole/.test(en)) {
    const roleArn = str(req.roleArn);
    if (!roleArn) return null;
    const role = roleArn.split("/").pop()!;
    const roleAcct = isRealAccount(arnAccount(roleArn)) ? arnAccount(roleArn)! : acct;
    const session = str(req.roleSessionName) ?? callerSessionName(pr) ?? role;
    const duration = typeof req.durationSeconds === "number" ? req.durationSeconds : Number(req.durationSeconds) || 3600;
    const out: Record<string, unknown> = {
      credentials: { accessKeyId: awsSessionKey(ctx, role, session), sessionToken: token(`${role}/${session}`), expiration: awsLongDate(t + duration * 1000) },
      assumedRoleUser: { assumedRoleId: `${awsRoleId(ctx, role)}:${session}`, arn: `arn:${part}:sts::${roleAcct}:assumed-role/${role}/${session}` },
    };
    if (en === "AssumeRoleWithSAML") {
      const provider = str(req.principalArn) ?? "";
      const okta = /okta/i.test(provider);
      Object.assign(out, {
        subject: session, subjectType: "persistent",
        issuer: okta ? `http://www.okta.com/exk${ctx.hex(entitySeed(ctx, "oktaapp", provider), 17)}` : `https://sts.windows.net/${ctx.tenant.azureTenantId}/`,
        audience: "https://signin.aws.amazon.com/saml",
        nameQualifier: pr.identityProvider ?? b64(ctx, entitySeed(ctx, "samlidp", acct), 20),
      });
    } else if (en === "AssumeRoleWithWebIdentity") {
      const idp = pr.identityProvider ?? "token.actions.githubusercontent.com";
      Object.assign(out, { subjectFromWebIdentityToken: pr.userName ?? session, provider: `arn:${part}:iam::${roleAcct}:oidc-provider/${idp}`, audience: "sts.amazonaws.com" });
    }
    return out;
  }
  if (en === "GetSessionToken") {
    const who = callerSessionName(pr) ?? "session";
    const duration = Number(req.durationSeconds) || 43200;
    return { credentials: { accessKeyId: awsSessionKey(ctx, "sts-session", who), sessionToken: token(`gst/${who}`), expiration: awsLongDate(t + duration * 1000) } };
  }
  if (en === "GetFederationToken") {
    const name = str(req.name) ?? callerSessionName(pr) ?? "federated";
    return {
      credentials: { accessKeyId: awsSessionKey(ctx, "federated", name), sessionToken: token(`fed/${name}`), expiration: awsLongDate(t + (Number(req.durationSeconds) || 43200) * 1000) },
      federatedUser: { federatedUserId: `${acct}:${name}`, arn: `arn:${part}:sts::${acct}:federated-user/${name}` },
    };
  }
  if (en === "CreateAccessKey") {
    const target = str(req.userName) ?? (pr.type === "IAMUser" ? pr.userName : undefined);
    if (!target) return null;
    // A second key for the caller itself must differ from the key it is calling with.
    const self = pr.type === "IAMUser" && pr.userName === target;
    return { accessKey: { userName: target, accessKeyId: awsUserKey(ctx, target, self ? 2 : 1), status: "Active", createDate: created } };
  }
  if (en === "CreateUser") {
    const name = str(req.userName);
    if (!name) return null;
    const path = str(req.path) ?? "/";
    return { user: { path, userName: name, userId: awsUserId(ctx, name), arn: `arn:${part}:iam::${acct}:user${path}${name}`, createDate: created } };
  }
  if (en === "CreateRole") {
    const name = str(req.roleName);
    if (!name) return null;
    const path = str(req.path) ?? "/";
    return { role: { path, roleName: name, roleId: awsRoleId(ctx, name), arn: `arn:${part}:iam::${acct}:role${path}${name}`, createDate: created } };
  }
  if (en === "CreateLoginProfile") {
    const name = str(req.userName) ?? pr.userName;
    if (!name) return null;
    return { loginProfile: { userName: name, createDate: created, passwordResetRequired: req.passwordResetRequired === true } };
  }
  if (en === "RunInstances") {
    const set = (req.instancesSet as { items?: Record<string, unknown>[] } | undefined)?.items?.[0] ?? {};
    const count = Math.max(1, Math.min(8, Number(set.minCount ?? req.minCount ?? 1) || 1));
    const type = str(req.instanceType) ?? str(set.instanceType) ?? "t3.medium";
    const imageId = str(set.imageId) ?? str(req.imageId) ?? `ami-${ctx.hex(entitySeed(ctx, "ami", region), 17)}`;
    const seed = `${ev.id}:run`;
    return {
      requestId: ctx.uuid(seed + ":rid"),
      reservationId: `r-${ctx.hex(seed + ":res", 17)}`,
      ownerId: acct,
      groupSet: {},
      instancesSet: { items: Array.from({ length: count }, (_, i) => ({
        instanceId: `i-${ctx.hex(`${seed}:${i}`, 17)}`, imageId, instanceType: type,
        instanceState: { code: 0, name: "pending" },
        launchTime: t, placement: { availabilityZone: `${region}${"abc"[i % 3]}`, tenancy: "default" },
        monitoring: { state: "disabled" },
      })) },
    };
  }
  return null;
}

/** An authored placeholder id (docs `…EXAMPLE` ids, a 4-letter prefix that is not AWS's). */
const placeholderId = (v: unknown, prefix: string) => typeof v === "string" && (v.includes("EXAMPLE") || !new RegExp(`^${prefix}[A-Z0-9]{12,}$`).test(v));

function fromTelemetry(ev: TelemetryEvent, ctx: NativeCtx): NativeLog | null {
  const raw = ev.raw ?? {};
  // Not a CloudTrail record: Bedrock model-invocation logs (CloudWatch Logs), GuardDuty findings, GitHub audit.
  if (raw["schemaType"] === "ModelInvocationLog") return null;
  if (rv(raw, "aws.guardduty.type", "aws.guardduty.finding.type", "aws.guardduty.id")) return null;
  if (Object.keys(raw).some(k => k.startsWith("github."))) return null;

  const en = rs(raw, "aws.cloudtrail.eventName", "event.action") ?? ev.cloud?.api_call;
  if (!en) return null; // no API name → cannot render a CloudTrail event truthfully
  const es = rs(raw, "aws.cloudtrail.eventSource") ?? (ev.cloud?.service ? `${ev.cloud.service.replace(/\.amazonaws\.com$/, "")}.amazonaws.com` : awsServiceFor(en));

  const acct = awsAccountId(ev, ctx);
  const global = GLOBAL_SOURCES.has(es);
  const region = awsRegion(ev, global);
  const part = awsPartition(region);
  const isSignIn = en === "ConsoleLogin";

  // ── who called ──
  const reqAuthored = collectParams(raw, ["aws.cloudtrail.requestParameters.", "aws.cloudtrail.request_parameters."], "aws.cloudtrail.request_parameters");
  const req: Record<string, unknown> = { ...(reqAuthored ?? {}) };
  let pr = awsPrincipal(ev, ctx, acct);
  const authoredType = rs(raw, "aws.cloudtrail.userIdentity.type", "aws.cloudtrail.user_identity.type");
  if (!authoredType && en === "AssumeRoleWithSAML") pr = { ...pr, type: "SAMLUser", userName: rs(raw, "aws.cloudtrail.userIdentity.userName") ?? userEmail(ev) ?? pr.userName };
  if (!authoredType && en === "AssumeRoleWithWebIdentity") pr = { ...pr, type: "WebIdentityUser" };
  // A cross-account AssumeRole is logged in the role owner's account with the caller as AWSAccount.
  const callerAcct = rs(raw, "aws.cloudtrail.userIdentity.accountId");
  const roleArnAcct = arnAccount(typeof req.roleArn === "string" ? req.roleArn : undefined);
  if (en === "AssumeRole" && !rs(raw, "aws.cloudtrail.userIdentity.arn") && isRealAccount(callerAcct) && isRealAccount(roleArnAcct) && callerAcct !== roleArnAcct) {
    pr = { ...pr, type: "AWSAccount", accountId: callerAcct, fallback: false };
  }
  const ui = buildUserIdentity(ev, ctx, pr, part, es, isSignIn);

  const isService = pr.type === "AWSService";
  const srcIp = ev.src_ip ?? rs(raw, "aws.cloudtrail.sourceIPAddress", "source.ip");
  const ua = isService ? String(ui.invokedBy) : rs(raw, "aws.cloudtrail.userAgent", "user_agent.original") ?? "aws-cli/2.17.60 md/awscrt#0.21.2 ua/2.0 os/linux#5.15.0 lang/python#3.11.4";

  const eventType = isSignIn ? "AwsConsoleSignIn" : (rs(raw, "aws.cloudtrail.eventType") ?? "AwsApiCall");
  const isData = DATA_EVENTS.has(en);
  const errorCode = rs(raw, "aws.cloudtrail.errorCode");
  const errorMessage = rs(raw, "aws.cloudtrail.errorMessage");
  // A failed console sign-in carries only errorMessage ("Failed authentication"), no errorCode.
  const failed = !!errorCode || (isSignIn && (!!errorMessage || /^(denied|blocked|fail)/i.test(rs(raw, "action_result", "event.outcome") ?? "")));

  // ── request ──
  if (typeof req.alarmNames === "string") req.alarmNames = [req.alarmNames];
  if (typeof req.eventSelectors === "string") { try { req.eventSelectors = JSON.parse(req.eventSelectors); } catch { /* keep the authored text */ } }
  if (en === "CopyObject" && (req.sourceBucket || req.destinationBucket)) {
    const { sourceBucket, destinationBucket, ...rest } = req;
    Object.keys(req).forEach(k => delete req[k]);
    Object.assign(req, { bucketName: destinationBucket ?? rest.bucketName, ...rest, ...(sourceBucket ? { "x-amz-copy-source": `${sourceBucket}/${rest.key ?? ""}`.replace(/\/$/, "") } : {}) });
  }
  if (en === "AssumeRole" && req.roleArn && !req.roleSessionName) req.roleSessionName = callerSessionName(pr) ?? String(req.roleArn).split("/").pop();
  if (en === "CreateAccessKey" && !req.userName && pr.type === "IAMUser") req.userName = pr.userName;

  // ── response ──
  const respAuthored = collectParams(raw, ["aws.cloudtrail.responseElements."], "aws.cloudtrail.responseElements");
  const contentLength = respAuthored?.contentLength;
  let responseElements: Record<string, unknown> | null;
  if ((READONLY_RE.test(en) && !CRED_ISSUING.has(en)) || isData) {
    responseElements = null; // read-only and S3 data calls log no response body
  } else {
    const derived = buildResponse(en, ev, ctx, pr, part, acct, region, req, failed);
    let authored = respAuthored;
    if (authored && en === "CreateUser") {
      const u = authored.user as Record<string, unknown> | undefined;
      if (u && placeholderId(u.userId, "AIDA")) { const { userId: _drop, ...keep } = u; authored = { ...authored, user: keep }; }
    }
    responseElements = derived || authored ? merge(derived ?? {}, authored ?? {}) : null;
  }

  // additionalEventData — carry byte counters (the exfil-volume pivot) + S3 signature metadata.
  const bytesOut = rn(raw, "aws.cloudtrail.additional_event_data.bytes_transferred_out", "aws.cloudtrail.additionalEventData.bytesTransferredOut") ?? ev.network?.bytes_out
    ?? rn(raw, "s3.bytes_transferred", "storage.object.size", "transfer.bytes", "network.bytes_out")
    ?? (isData && typeof contentLength === "number" ? contentLength : undefined);
  const additionalEventData: Record<string, unknown> = {};
  if (es === "s3.amazonaws.com") { additionalEventData.SignatureVersion = "SigV4"; additionalEventData.AuthenticationMethod = "AuthHeader"; }
  if (bytesOut !== undefined) { additionalEventData.bytesTransferredIn = ev.network?.bytes_in ?? 0; additionalEventData.bytesTransferredOut = bytesOut; }
  if (isSignIn) {
    additionalEventData.LoginTo = part === "aws-us-gov" ? "https://console.amazonaws-us-gov.com/console/home" : "https://console.aws.amazon.com/console/home";
    additionalEventData.MobileVersion = "No";
    additionalEventData.MFAUsed = rs(raw, "aws.cloudtrail.additionalEventData.MFAUsed") ?? "No";
  }

  const record: Record<string, unknown> = {
    eventVersion: "1.11",
    userIdentity: ui,
    eventTime: isoZ(ev.ts),
    eventSource: es,
    eventName: en,
    awsRegion: region,
    sourceIPAddress: isService ? String(ui.invokedBy) : srcIp ?? "AWS Internal",
    userAgent: ua,
    requestParameters: Object.keys(req).length ? req : null,
    responseElements,
    requestID: rs(raw, "aws.cloudtrail.requestID", "aws.cloudtrail.request_id") ?? ctx.uuid(ev.id + ":req"),
    eventID: ctx.uuid(ev.id + ":evid"),
    readOnly: rb(raw, "aws.cloudtrail.readOnly") ?? READONLY_RE.test(en),
    eventType,
    managementEvent: rb(raw, "aws.cloudtrail.managementEvent") ?? !isData,
    recipientAccountId: acct,
    eventCategory: isData ? "Data" : "Management",
  };
  if (Object.keys(additionalEventData).length) record.additionalEventData = additionalEventData;
  if (errorCode) record.errorCode = errorCode;
  if (errorMessage) record.errorMessage = errorMessage;

  // resources[] for S3 object access and STS AssumeRole.
  const bucket = rs(raw, "aws.cloudtrail.requestParameters.bucketName", "aws.cloudtrail.s3.bucket_name", "s3.bucket", "aws.s3.bucket.name") ?? (typeof req.bucketName === "string" ? req.bucketName : undefined);
  const key = rs(raw, "aws.cloudtrail.requestParameters.key", "storage.object.name") ?? (typeof req.key === "string" ? req.key : undefined);
  if (bucket && isData) {
    const resources: Record<string, unknown>[] = [];
    if (key) resources.push({ type: "AWS::S3::Object", ARN: `arn:${part}:s3:::${bucket}/${key}` });
    resources.push({ accountId: acct, type: "AWS::S3::Bucket", ARN: `arn:${part}:s3:::${bucket}` });
    record.resources = resources;
  }
  const roleArn = typeof req.roleArn === "string" ? req.roleArn : undefined;
  if (roleArn && /AssumeRole/.test(en)) record.resources = [{ ARN: roleArn, accountId: isRealAccount(arnAccount(roleArn)) ? arnAccount(roleArn) : acct, type: "AWS::IAM::Role" }];

  // tlsDetails — present for direct API calls (absent for AWS-service-invoked / anonymous).
  if (ui.type !== "Anonymous" && !isService && !ua.endsWith(".amazonaws.com")) {
    const svc = es.replace(/\.amazonaws\.com$/, "");
    const host = global ? (part === "aws-us-gov" && svc === "iam" ? "iam.us-gov.amazonaws.com" : es)
      : svc === "s3" && bucket ? `${bucket}.s3.${region}.amazonaws.com` : `${svc}.${region}.amazonaws.com`;
    record.tlsDetails = {
      tlsVersion: "TLSv1.3", cipherSuite: "TLS_AES_128_GCM_SHA256",
      clientProvidedHostHeader: rs(raw, "aws.cloudtrail.tlsDetails.clientProvidedHostHeader") ?? host,
    };
  }
  // A private source address only reaches a public AWS endpoint through an interface VPC endpoint.
  const vpce = rs(raw, "aws.cloudtrail.vpcEndpointId") ?? (srcIp && isPrivateIp(srcIp) && !isService ? `vpce-${ctx.hex(entitySeed(ctx, "vpce", `${acct}:${es}`), 17)}` : undefined);
  if (vpce) { record.vpcEndpointId = vpce; record.vpcEndpointAccountId = acct; }

  return { sourceId: "aws_cloudtrail", kind: eventType, format: "json", record: rehomeArns(record, part, acct, region), timeMs: Date.parse(ev.ts) };
}

// ── use cases ─────────────────────────────────────────────────────────────────

const PRIVATE = ["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12", "169.254.0.0/16", "100.64.0.0/10"];

const useCases: UseCase[] = [
  {
    id: "aws_cloudtrail.trail_disabled",
    title: "CloudTrail logging disabled or tampered",
    sourceId: "aws_cloudtrail", severity: "critical", mitre: ["T1562.008", "T1562.001"],
    description: "StopLogging / DeleteTrail / UpdateTrail / PutEventSelectors on cloudtrail.amazonaws.com — an attacker blinding the audit trail to cover later actions.",
    logic: "SPL: eventSource=cloudtrail.amazonaws.com eventName IN (StopLogging,DeleteTrail,UpdateTrail,PutEventSelectors)",
    match: { all: [{ field: "eventSource", op: "eq", value: "cloudtrail.amazonaws.com" }, { field: "eventName", op: "in", value: ["StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors"] }] },
    falsePositives: ["Planned trail re-configuration by a cloud engineer during a logging migration (check the change ticket)."],
  },
  {
    id: "aws_cloudtrail.bedrock_logging_disabled",
    title: "Bedrock model-invocation logging disabled",
    sourceId: "aws_cloudtrail", severity: "high", mitre: ["T1562.008"],
    description: "DeleteModelInvocationLoggingConfiguration on bedrock.amazonaws.com — turns off prompt/response capture so later model abuse leaves only metadata (an LLMjacking defense-evasion step).",
    logic: "SPL: eventSource=bedrock.amazonaws.com eventName=DeleteModelInvocationLoggingConfiguration",
    match: { all: [{ field: "eventSource", op: "eq", value: "bedrock.amazonaws.com" }, { field: "eventName", op: "eq", value: "DeleteModelInvocationLoggingConfiguration" }] },
    falsePositives: ["A platform team intentionally changing Bedrock logging configuration (should come from an SSO/console session, not a long-term AKIA key)."],
  },
  {
    id: "aws_cloudtrail.root_console_login",
    title: "Root account console sign-in",
    sourceId: "aws_cloudtrail", severity: "high", mitre: ["T1078.004"],
    kinds: ["AwsConsoleSignIn"],
    description: "A ConsoleLogin by the account root identity. Root should never be used for day-to-day work; any root sign-in is investigated.",
    logic: "SPL: eventName=ConsoleLogin userIdentity.type=Root",
    match: { all: [{ field: "eventName", op: "eq", value: "ConsoleLogin" }, { field: "userIdentity.type", op: "eq", value: "Root" }] },
    falsePositives: ["A documented break-glass root login for billing / account recovery."],
  },
  {
    id: "aws_cloudtrail.console_login_no_mfa",
    title: "Console sign-in without MFA",
    sourceId: "aws_cloudtrail", severity: "medium", mitre: ["T1078.004", "T1556"],
    kinds: ["AwsConsoleSignIn"],
    description: "A ConsoleLogin where additionalEventData.MFAUsed is No — a single-factor sign-in, weak against credential theft; alarming from a new IP.",
    logic: "SPL: eventName=ConsoleLogin additionalEventData.MFAUsed=No",
    match: { all: [{ field: "eventName", op: "eq", value: "ConsoleLogin" }, { field: "additionalEventData.MFAUsed", op: "eq", value: "No" }] },
    falsePositives: ["Accounts legitimately exempt from MFA (service break-glass) — rare and should be eliminated."],
  },
  {
    id: "aws_cloudtrail.key_recon_external",
    title: "Credential validation / recon from an external IP",
    sourceId: "aws_cloudtrail", severity: "medium", mitre: ["T1078.004", "T1580"],
    description: "GetCallerIdentity (or other Get*/List*/Describe* recon) from a non-corporate public IP — a classic first move after an access key is stolen.",
    logic: "SPL: eventName IN (GetCallerIdentity,ListBuckets,ListSecrets,ListRoles,DescribeInstances) NOT cidr(sourceIPAddress, RFC1918)",
    match: { all: [
      { field: "eventName", op: "in", value: ["GetCallerIdentity", "ListBuckets", "ListSecrets", "ListRoles", "DescribeInstances", "DescribeVpcs"] },
      { field: "sourceIPAddress", op: "notCidr", value: PRIVATE },
    ] },
    falsePositives: ["Engineers or CI running the AWS CLI from a home / cloud IP that is not on the known corporate list."],
  },
  {
    id: "aws_cloudtrail.external_ip_api_burst",
    title: "API burst from a single external IP (stolen-key activity)",
    sourceId: "aws_cloudtrail", severity: "high", mitre: ["T1078.004", "T1580"],
    description: "Four or more distinct API actions from the same external IP within 10 minutes — the recon → collection → persistence tempo of a compromised credential, correlated by sourceIPAddress.",
    logic: "SPL: NOT cidr(sourceIPAddress, RFC1918) | stats dc(eventName) by sourceIPAddress | where dc>=4 (10m window)",
    match: { field: "sourceIPAddress", op: "notCidr", value: PRIVATE },
    threshold: { groupBy: ["sourceIPAddress"], count: 4, windowSec: 600, distinct: "eventName" },
    falsePositives: ["A developer or automation host, outside the corporate range, legitimately exercising many APIs."],
  },
  {
    id: "aws_cloudtrail.s3_public_exposure",
    title: "S3 bucket exposed publicly",
    sourceId: "aws_cloudtrail", severity: "critical", mitre: ["T1530", "T1567.002"],
    description: "A bucket policy / ACL change granting public (Principal \"*\") read, or removal of the Block-Public-Access guardrail — the step that makes exfiltrated data reachable by anyone.",
    logic: "SPL: eventName IN (DeleteBucketPublicAccessBlock,DeletePublicAccessBlock) OR (PutBucketPolicy AND requestParameters contains Principal:*)",
    match: { any: [
      { field: "eventName", op: "in", value: ["DeleteBucketPublicAccessBlock", "DeletePublicAccessBlock"] },
      { all: [{ field: "eventName", op: "in", value: ["PutBucketPolicy", "PutBucketAcl"] }, { any: [
        { field: "requestParameters.AllowPublicRead", op: "eq", value: true },
        { field: "requestParameters.policy.Principal", op: "eq", value: "*" },
        { field: "requestParameters.policy", op: "regex", value: "\\\"Principal\\\"\\s*:\\s*\\\"\\*\\\"" },
        { field: "requestParameters.policyDocument", op: "regex", value: "\\\"Principal\\\"\\s*:\\s*\\\"\\*\\\"" },
      ] }] },
    ] },
    falsePositives: ["A bucket intentionally hosting public static assets (CDN origin) — confirm the data classification of the bucket."],
  },
  {
    id: "aws_cloudtrail.s3_mass_exfil",
    title: "Large S3 object egress to an external IP",
    sourceId: "aws_cloudtrail", severity: "high", mitre: ["T1530", "T1567.002"],
    kinds: ["AwsApiCall"],
    description: "A GetObject data event transferring a large volume out (≥40 MB) to a non-corporate public IP — the network footprint of bulk data theft from S3.",
    logic: "SPL: eventName=GetObject eventCategory=Data additionalEventData.bytesTransferredOut>=40000000 NOT cidr(sourceIPAddress, RFC1918)",
    match: { all: [
      { field: "eventName", op: "eq", value: "GetObject" },
      { field: "additionalEventData.bytesTransferredOut", op: "gte", value: 40_000_000 },
      { field: "sourceIPAddress", op: "notCidr", value: PRIVATE },
    ] },
    falsePositives: ["A pre-approved bulk data export or migration run from a corporate public egress IP (check the change ticket / data-transfer request)."],
  },
  {
    id: "aws_cloudtrail.iam_persistence",
    title: "IAM persistence / privilege escalation",
    sourceId: "aws_cloudtrail", severity: "critical", mitre: ["T1136.003", "T1098.001", "T1098.003"],
    description: "CreateUser / CreateAccessKey, attaching AdministratorAccess, or re-writing a role trust policy to an external account — attacker-planted standing access that survives session expiry.",
    logic: "SPL: eventSource=iam.amazonaws.com (eventName IN (CreateUser,CreateAccessKey) OR (eventName=AttachUserPolicy requestParameters.policyArn=*AdministratorAccess) OR eventName=UpdateAssumeRolePolicy)",
    match: { all: [{ field: "eventSource", op: "eq", value: "iam.amazonaws.com" }, { any: [
      { field: "eventName", op: "in", value: ["CreateUser", "CreateAccessKey", "UpdateAssumeRolePolicy"] },
      { all: [{ field: "eventName", op: "in", value: ["AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy"] }, { field: "requestParameters.policyArn", op: "icontains", value: "AdministratorAccess" }] },
    ] }] },
    falsePositives: ["Identity-team provisioning of a new user / key via an approved IaC pipeline (correlate with the pipeline identity and ticket)."],
  },
  {
    id: "aws_cloudtrail.secret_access_burst",
    title: "Secrets Manager mass secret retrieval",
    sourceId: "aws_cloudtrail", severity: "high", mitre: ["T1552.005", "T1555.006"],
    description: "The same identity reading multiple distinct secrets (GetSecretValue) within minutes — credential harvesting at machine tempo rather than one application reading its one secret.",
    logic: "SPL: eventName=GetSecretValue | stats dc(requestParameters.secretId) by userIdentity.arn | where dc>=2 (10m window)",
    match: { field: "eventName", op: "eq", value: "GetSecretValue" },
    threshold: { groupBy: ["userIdentity.arn"], count: 2, windowSec: 600, distinct: "requestParameters.secretId" },
    falsePositives: ["A deployment / rotation job that legitimately reads several secrets in one run (correlate with the CI identity)."],
  },
  {
    id: "aws_cloudtrail.bedrock_abuse",
    title: "Bedrock model access expanded by a service key (LLMjacking)",
    sourceId: "aws_cloudtrail", severity: "high", mitre: ["T1078.004"],
    description: "PutFoundationModelEntitlement / CreateFoundationModelAgreement / PutUseCaseForModelAccess on bedrock.amazonaws.com — console-style model-access actions issued by an automation key, the self-service step of LLMjacking before mass InvokeModel.",
    logic: "SPL: eventSource=bedrock.amazonaws.com eventName IN (PutFoundationModelEntitlement,CreateFoundationModelAgreement,PutUseCaseForModelAccess)",
    match: { all: [{ field: "eventSource", op: "eq", value: "bedrock.amazonaws.com" }, { field: "eventName", op: "in", value: ["PutFoundationModelEntitlement", "CreateFoundationModelAgreement", "PutUseCaseForModelAccess"] }] },
    falsePositives: ["A platform engineer enabling a new Bedrock model through the console (SSO session, browser user agent) rather than a scripted key."],
  },
];

export const source: NativeSource = { schema, fromTelemetry, useCases };
