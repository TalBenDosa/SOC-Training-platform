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
import { awsAccountId, awsRegion, entitySeed, isoZ, rb, rn, rs, rv, underPrefix } from "./cloud-shared";

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

const GLOBAL_SOURCES = new Set(["iam.amazonaws.com", "sts.amazonaws.com", "organizations.amazonaws.com", "cloudfront.amazonaws.com", "route53.amazonaws.com", "signin.amazonaws.com"]);
const READONLY_RE = /^(Get|List|Describe|Head|BatchGet|Lookup|Select|Search|View)/;
const DATA_EVENTS = new Set(["GetObject", "PutObject", "DeleteObject", "HeadObject", "SelectObjectContent", "GetObjectAcl", "GetObjectTagging"]);

/** eventSource for an API name when the event didn't record one. */
function sourceFor(en: string): string {
  if (/^(Get|List|Put|Delete|Head|Copy|Create)?(Bucket|Object)/.test(en) || /Bucket/.test(en)) return "s3.amazonaws.com";
  if (/^(Create|Delete|Attach|Detach|Put|Update|List|Get)?(User|Role|Policy|AccessKey|Group|AssumeRolePolicy|LoginProfile)/.test(en) || /^(ListRoles|ListUsers|CreateUser|CreateAccessKey|AttachUserPolicy|AttachRolePolicy|PutUserPolicy|PutRolePolicy|UpdateAssumeRolePolicy|CreateLoginProfile)$/.test(en)) return "iam.amazonaws.com";
  if (/^(AssumeRole|GetCallerIdentity|GetSessionToken|GetFederationToken|AssumeRoleWithSAML|AssumeRoleWithWebIdentity)/.test(en)) return "sts.amazonaws.com";
  if (/^(Run|Describe|Terminate|Start|Stop|Authorize|Revoke)?.*(Instances|SecurityGroup|Vpc|Snapshot|Volume)/.test(en)) return "ec2.amazonaws.com";
  if (/^(Stop|Start)Logging|^(Delete|Create|Update|Put)?(Trail|EventSelectors)/.test(en)) return "cloudtrail.amazonaws.com";
  if (/Secret/.test(en)) return "secretsmanager.amazonaws.com";
  if (/^(Invoke|Converse|Put|Get|Delete|Create).*Model|^(Invoke|Converse)/.test(en)) return "bedrock.amazonaws.com";
  if (/Alarm/.test(en)) return "monitoring.amazonaws.com";
  return "ec2.amazonaws.com";
}

function buildUserIdentity(ev: TelemetryEvent, ctx: NativeCtx, acct: string): Record<string, unknown> {
  const raw = ev.raw;
  const email = ev.user?.email ?? ev.user_email;
  let type = rs(raw, "aws.cloudtrail.userIdentity.type");
  const rawArn = rs(raw, "aws.cloudtrail.userIdentity.arn");
  const rawUser = rs(raw, "aws.cloudtrail.userIdentity.userName");
  if (!type) type = rawArn?.includes(":assumed-role/") ? "AssumedRole" : "IAMUser";

  const ui: Record<string, unknown> = { type };
  // Identity name: preserve the native userName; else derive from the acting user.
  const name = rawUser ?? (email ? email.split("@")[0] : undefined);
  const entity = (rawArn ?? rawUser ?? name ?? email ?? ev.id);
  const idSeed = entitySeed(ctx, "awsprincipal", entity);

  if (type === "AssumedRole") {
    const issuerName = rs(raw, "aws.cloudtrail.userIdentity.sessionContext.sessionIssuer.userName", "aws.cloudtrail.user_identity.session_issuer.user_name") ?? "service-role";
    const session = rawArn?.split("/").pop() ?? name ?? issuerName;
    const roleId = "AROA" + ctx.hex(entitySeed(ctx, "awsrole", issuerName), 17).toUpperCase();
    ui.principalId = rs(raw, "aws.cloudtrail.userIdentity.principalId") ?? `${roleId}:${session}`;
    ui.arn = rawArn ?? `arn:aws:sts::${acct}:assumed-role/${issuerName}/${session}`;
    ui.accountId = rs(raw, "aws.cloudtrail.userIdentity.accountId") ?? acct;
    ui.accessKeyId = rs(raw, "aws.cloudtrail.userIdentity.accessKeyId") ?? ("ASIA" + ctx.hex(idSeed, 16).toUpperCase());
    const sc: Record<string, unknown> = {
      sessionIssuer: {
        type: "Role", principalId: roleId,
        arn: rs(raw, "aws.cloudtrail.userIdentity.sessionContext.sessionIssuer.arn") ?? `arn:aws:iam::${acct}:role/${issuerName}`,
        accountId: acct, userName: issuerName,
      },
      attributes: {
        creationDate: rs(raw, "aws.cloudtrail.userIdentity.sessionContext.attributes.creationDate") ?? isoZ(ev.ts),
        mfaAuthenticated: rs(raw, "aws.cloudtrail.userIdentity.sessionContext.attributes.mfaAuthenticated") ?? "false",
      },
    };
    const ec2 = rs(raw, "aws.cloudtrail.userIdentity.sessionContext.ec2RoleDelivery");
    if (ec2) (sc as Record<string, unknown>).ec2RoleDelivery = ec2;
    ui.sessionContext = sc;
  } else if (type === "Anonymous") {
    ui.accountId = "anonymous";
    ui.arn = "anonymous";
  } else if (type === "Root") {
    ui.principalId = acct;
    ui.arn = `arn:aws:iam::${acct}:root`;
    ui.accountId = acct;
  } else {
    // IAMUser (default)
    const userId = "AIDA" + ctx.hex(idSeed, 17).toUpperCase();
    ui.principalId = rs(raw, "aws.cloudtrail.userIdentity.principalId") ?? userId;
    ui.arn = rawArn ?? `arn:aws:iam::${acct}:user/${name ?? "unknown"}`;
    ui.accountId = rs(raw, "aws.cloudtrail.userIdentity.accountId") ?? acct;
    const ak = rs(raw, "aws.cloudtrail.userIdentity.accessKeyId");
    if (ak || rv(raw, "aws.cloudtrail.eventName")) ui.accessKeyId = ak ?? ("AKIA" + ctx.hex(idSeed + ":ak", 16).toUpperCase());
    if (name) ui.userName = name;
  }
  return ui;
}

/** Merge the legacy request/response/additional keys into a native sub-object. */
function collectParams(raw: Record<string, unknown> | undefined, flatPrefix: string, jsonKey: string): Record<string, unknown> | undefined {
  const out: Record<string, unknown> = {};
  Object.assign(out, underPrefix(raw, flatPrefix));
  const jsonStr = rs(raw, jsonKey);
  if (jsonStr && jsonStr.startsWith("{")) {
    try { Object.assign(out, JSON.parse(jsonStr)); } catch { /* keep flattened only */ }
  }
  return Object.keys(out).length ? out : undefined;
}

function fromTelemetry(ev: TelemetryEvent, ctx: NativeCtx): NativeLog | null {
  const raw = ev.raw ?? {};
  // Not a CloudTrail record: Bedrock model-invocation logs (CloudWatch Logs), GuardDuty findings, GitHub audit.
  if (raw["schemaType"] === "ModelInvocationLog") return null;
  if (rv(raw, "aws.guardduty.type", "aws.guardduty.finding.type", "aws.guardduty.id")) return null;
  if (Object.keys(raw).some(k => k.startsWith("github."))) return null;

  const en = rs(raw, "aws.cloudtrail.eventName", "event.action") ?? ev.cloud?.api_call;
  if (!en) return null; // no API name → cannot render a CloudTrail event truthfully
  const es = rs(raw, "aws.cloudtrail.eventSource") ?? ev.cloud?.service ?? sourceFor(en);

  const acct = awsAccountId(ev, ctx);
  const global = GLOBAL_SOURCES.has(es);
  const region = awsRegion(ev, global);
  const ui = buildUserIdentity(ev, ctx, acct);
  const srcIp = ev.src_ip ?? rs(raw, "aws.cloudtrail.sourceIPAddress", "source.ip");
  const ua = rs(raw, "aws.cloudtrail.userAgent", "user_agent.original") ?? "aws-cli/2.17.60 md/awscrt#0.21.2 ua/2.0 os/linux#5.15.0 lang/python#3.11.4";

  const isSignIn = en === "ConsoleLogin";
  const eventType = isSignIn ? "AwsConsoleSignIn" : (rs(raw, "aws.cloudtrail.eventType") ?? "AwsApiCall");
  const isData = DATA_EVENTS.has(en);

  const req = collectParams(raw, "aws.cloudtrail.requestParameters.", "aws.cloudtrail.request_parameters");
  const req2 = collectParams(raw, "aws.cloudtrail.request_parameters.", "__none__");
  const requestParameters = req || req2 ? { ...(req2 ?? {}), ...(req ?? {}) } : null;
  const resp = collectParams(raw, "aws.cloudtrail.responseElements.", "aws.cloudtrail.responseElements");

  // additionalEventData — carry byte counters (the exfil-volume pivot) + S3 signature metadata.
  const bytesOut = rn(raw, "aws.cloudtrail.additional_event_data.bytes_transferred_out") ?? ev.network?.bytes_out ?? rn(raw, "s3.bytes_transferred", "storage.object.size", "transfer.bytes", "network.bytes_out");
  const additionalEventData: Record<string, unknown> = {};
  if (es === "s3.amazonaws.com") { additionalEventData.SignatureVersion = "SigV4"; additionalEventData.AuthenticationMethod = "AuthHeader"; }
  if (bytesOut !== undefined) { additionalEventData.bytesTransferredIn = ev.network?.bytes_in ?? 0; additionalEventData.bytesTransferredOut = bytesOut; }
  if (isSignIn) {
    additionalEventData.LoginTo = "https://console.aws.amazon.com/console/home";
    additionalEventData.MobileVersion = "No";
    additionalEventData.MFAUsed = rs(raw, "aws.cloudtrail.additionalEventData.MFAUsed") ?? "No";
  }

  const errorCode = rs(raw, "aws.cloudtrail.errorCode");
  const errorMessage = rs(raw, "aws.cloudtrail.errorMessage");

  const record: Record<string, unknown> = {
    eventVersion: "1.11",
    userIdentity: ui,
    eventTime: isoZ(ev.ts),
    eventSource: es,
    eventName: en,
    awsRegion: region,
    sourceIPAddress: srcIp ?? "AWS Internal",
    userAgent: ua,
    requestParameters: requestParameters,
    responseElements: resp ?? null,
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
  const bucket = rs(raw, "aws.cloudtrail.requestParameters.bucketName", "aws.cloudtrail.s3.bucket_name", "s3.bucket", "aws.s3.bucket.name");
  const key = rs(raw, "aws.cloudtrail.requestParameters.key", "storage.object.name");
  if (bucket && isData) {
    const resources: Record<string, unknown>[] = [];
    if (key) resources.push({ type: "AWS::S3::Object", ARN: `arn:aws:s3:::${bucket}/${key}` });
    resources.push({ accountId: acct, type: "AWS::S3::Bucket", ARN: `arn:aws:s3:::${bucket}` });
    record.resources = resources;
  }
  const roleArn = rs(raw, "aws.cloudtrail.requestParameters.roleArn");
  if (roleArn && /AssumeRole/.test(en)) record.resources = [{ ARN: roleArn, accountId: acct, type: "AWS::IAM::Role" }];

  // tlsDetails — present for direct API calls (absent for AWS-service-invoked / anonymous).
  if (ui.type !== "Anonymous" && !ua.endsWith(".amazonaws.com")) {
    record.tlsDetails = {
      tlsVersion: "TLSv1.3", cipherSuite: "TLS_AES_128_GCM_SHA256",
      clientProvidedHostHeader: rs(raw, "aws.cloudtrail.tlsDetails.clientProvidedHostHeader") ?? `${es}`,
    };
  }
  const vpce = rs(raw, "aws.cloudtrail.vpcEndpointId");
  if (vpce) record.vpcEndpointId = vpce;

  return { sourceId: "aws_cloudtrail", kind: eventType, format: "json", record, timeMs: Date.parse(ev.ts) };
}

// ── use cases ─────────────────────────────────────────────────────────────────

const PRIVATE = ["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12", "169.254.0.0/16", "100.64.0.0/10"];
const GPU_TYPES = "^(p[2-9]|p1[0-9]|g[3-9]|dl1|trn1|inf[0-9]|a2-|a3-)";

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
    id: "aws_cloudtrail.cryptomining_gpu",
    title: "Crypto-mining — oversized GPU instances launched",
    sourceId: "aws_cloudtrail", severity: "high", mitre: ["T1578.002", "T1496"],
    kinds: ["AwsApiCall"],
    description: "RunInstances requesting GPU/accelerated instance types (p*/g*/trn/inf) — the compute footprint of crypto-mining on stolen credentials.",
    logic: "SPL: eventName=RunInstances requestParameters.instanceType IN (p3.*,g4dn.*,g5.*,...)",
    match: { all: [{ field: "eventName", op: "eq", value: "RunInstances" }, { any: [
      { field: "requestParameters.instanceType", op: "regex", value: GPU_TYPES },
      { field: "requestParameters.instancesSet.items[].instanceType", op: "regex", value: GPU_TYPES },
    ] }] },
    falsePositives: ["Legitimate ML training / rendering workloads that use GPU instances (verify the owning team and tags)."],
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
