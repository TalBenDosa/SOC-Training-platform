/**
 * AWS fidelity checks (AWS log review 2026-11-22): what a CloudTrail record, a GuardDuty finding and a VPC
 * Flow Log line look like in a real AWS account, and how the AWS rows of ONE story must hang together for
 * the analyst's pivots to work (a key minted in the story is the key used after it, a GuardDuty finding
 * names a key / IP / API the story's CloudTrail shows, one company one account).
 *
 * Test-only. Used by awsFidelity.test.ts. Every check returns findings; the test expects none.
 */
type R = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

export interface AwsFinding { kind: string; where: string; detail: string }

const REGIONS = new Set(["us-east-1", "us-east-2", "us-west-1", "us-west-2", "ca-central-1", "ca-west-1", "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-central-2", "eu-north-1", "eu-south-1", "eu-south-2", "il-central-1", "me-south-1", "me-central-1", "ap-south-1", "ap-south-2", "ap-southeast-1", "ap-southeast-2", "ap-southeast-3", "ap-southeast-4", "ap-northeast-1", "ap-northeast-2", "ap-northeast-3", "ap-east-1", "sa-east-1", "af-south-1", "mx-central-1", "us-gov-west-1", "us-gov-east-1"]);
const GLOBAL = new Set(["iam.amazonaws.com", "organizations.amazonaws.com", "cloudfront.amazonaws.com", "route53.amazonaws.com", "signin.amazonaws.com"]);
const READONLY_RE = /^(Get|List|Describe|Head|BatchGet|Lookup|Select|Search|View)/;
/** Read-only calls whose names do not start with a read verb. */
const READONLY_EXTRA = new Set(["Decrypt", "Scan", "Query", "ApplyGuardrail", "GenerateDataKey", "GenerateDataKeyWithoutPlaintext"]);
const ISO_CT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const IP = /^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-f:]+$/i;
/** GuardDuty finding types AWS has retired (still seen in old blog posts). */
const RETIRED_GD = /ObjectRead\.Unusual|IAMUser\/(AdministrativePermissions|UserPermissions|ResourcePermissions|NetworkPermissions)|Stealth:IAMUser\/LoggingConfigurationModified/;
/** Cross-account by design: the request names another account's resource. */
const CROSS_ACCOUNT_API = /AssumeRole|PutBucketPolicy|UpdateAssumeRolePolicy|PutRolePolicy|CreateRole|ModifySnapshotAttribute|ModifyImageAttribute|PutResourcePolicy|CreateGrant|AddPermission|CopySnapshot|ShareSnapshot/;

export function checkCloudTrail(r: R, where: string, out: AwsFinding[]): void {
  const add = (kind: string, detail: string) => out.push({ kind, where, detail });
  const ui = r.userIdentity ?? {};
  const acct = r.recipientAccountId;
  if (!["1.08", "1.09", "1.10", "1.11"].includes(r.eventVersion)) add("CT_VERSION", String(r.eventVersion));
  if (!ISO_CT.test(r.eventTime ?? "")) add("CT_TIME_FORMAT", String(r.eventTime));
  if (!REGIONS.has(r.awsRegion)) add("CT_REGION", String(r.awsRegion));
  if (GLOBAL.has(r.eventSource) && r.awsRegion !== "us-east-1" && !String(r.awsRegion).startsWith("us-gov")) add("CT_GLOBAL_REGION", `${r.eventSource} in ${r.awsRegion}`);
  if (!/^\d{12}$/.test(acct ?? "")) add("CT_ACCOUNT", String(acct));
  if (!/\.amazonaws\.com$/.test(r.eventSource ?? "")) add("CT_EVENTSOURCE", String(r.eventSource));
  if (r.eventType === "AwsApiCall" && !READONLY_EXTRA.has(r.eventName)) {
    const ro = READONLY_RE.test(r.eventName) && !["GetSessionToken", "GetFederationToken"].includes(r.eventName);
    if (r.readOnly !== ro) add("CT_READONLY", `${r.eventName} readOnly=${r.readOnly}`);
  }
  if (ui.type !== "AWSService" && !(IP.test(r.sourceIPAddress ?? "") || r.sourceIPAddress === "AWS Internal")) add("CT_SOURCE_IP", String(r.sourceIPAddress));
  switch (ui.type) {
    case "IAMUser":
      if (!/^AIDA[A-Z0-9]{17}$/.test(ui.principalId ?? "")) add("CT_IAMUSER_PRINCIPALID", String(ui.principalId));
      if (r.eventName !== "ConsoleLogin" && !/^(AKIA|ASIA)[A-Z0-9]{16}$/.test(ui.accessKeyId ?? "")) add("CT_IAMUSER_KEY", String(ui.accessKeyId));
      if (ui.userName === "unknown") add("CT_UNKNOWN_IDENTITY", `${r.eventName} by user/unknown`);
      if (/^AKIA/.test(ui.accessKeyId ?? "") && /Mozilla/.test(r.userAgent ?? "")) add("CT_CONSOLE_WITH_LONG_TERM_KEY", `${r.eventName} from a browser with ${ui.accessKeyId}`);
      break;
    case "AssumedRole": {
      if (!/^AROA[A-Z0-9]{17}:.+$/.test(ui.principalId ?? "")) add("CT_ROLE_PRINCIPALID", String(ui.principalId));
      if (!/^ASIA[A-Z0-9]{16}$/.test(ui.accessKeyId ?? "")) add("CT_ROLE_KEY", String(ui.accessKeyId));
      const sess = (ui.arn ?? "").split("/").pop();
      if (!String(ui.principalId).endsWith(`:${sess}`)) add("CT_ROLE_SESSION_MISMATCH", `${ui.principalId} vs ${ui.arn}`);
      if (!["true", "false"].includes(ui.sessionContext?.attributes?.mfaAuthenticated)) add("CT_MFA_STRING", String(ui.sessionContext?.attributes?.mfaAuthenticated));
      const cd = Date.parse(ui.sessionContext?.attributes?.creationDate ?? "");
      if (!(cd <= Date.parse(r.eventTime))) add("CT_SESSION_AFTER_EVENT", `${ui.sessionContext?.attributes?.creationDate} > ${r.eventTime}`);
      break;
    }
  }
  if (ui.accountId && acct && ui.accountId !== acct && !["AWSAccount", "Anonymous"].includes(ui.type)) add("CT_CALLER_ACCOUNT_DIFFERS", `${ui.accountId} != ${acct} (${r.eventName})`);
  const json = JSON.stringify(r);
  for (const m of json.matchAll(/arn:aws[\w-]*:[a-z0-9-]+:[a-z0-9-]*:\d{12}:[^"\\]+/g)) {
    const a = /:(\d{12}):/.exec(m[0])?.[1];
    if (a && a !== acct && !/:layer:/.test(m[0]) && !CROSS_ACCOUNT_API.test(r.eventName)) add("CT_FOREIGN_ACCOUNT_ARN", `${m[0]} in ${r.eventName}`);
    const reg = /^arn:aws[\w-]*:[a-z0-9-]+:([a-z0-9-]+):\d{12}:/.exec(m[0])?.[1];
    if (reg && !REGIONS.has(reg)) add("CT_ARN_REGION", m[0]);
    if (/:kms:[^:]+:\d{12}:key\//.test(m[0]) && !/:key\/(mrk-)?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(m[0])) add("CT_KMS_KEY_ARN", m[0]);
  }
  if (/arn:aws-us-gov:/.test(json) && !String(r.awsRegion).startsWith("us-gov")) add("CT_PARTITION_MIX", `${r.eventName} ${r.awsRegion}`);
  if (r.errorCode) {
    if (r.responseElements && r.eventName !== "ConsoleLogin") add("CT_ERROR_WITH_RESPONSE", `${r.errorCode} ${r.eventName}`);
    if (/^(AccessDenied|.*UnauthorizedOperation)$/.test(r.errorCode) && /is not authorized to perform/.test(r.errorMessage ?? "") && ui.arn && !r.errorMessage.includes(ui.arn)) add("CT_ERRMSG_PRINCIPAL", `${String(r.errorMessage).slice(0, 120)} | caller ${ui.arn}`);
  }
  if (r.eventName === "ConsoleLogin") {
    if (r.eventSource !== "signin.amazonaws.com") add("CT_CONSOLE_SOURCE", r.eventSource);
    if (!/^(Success|Failure)$/.test(r.responseElements?.ConsoleLogin ?? "")) add("CT_CONSOLE_RESULT", JSON.stringify(r.responseElements));
  }
  if (r.eventSource === "s3.amazonaws.com") {
    const rp = r.requestParameters ?? {};
    if (!rp.Host && !rp.host) add("CT_S3_NO_HOST_PARAM", r.eventName);
    if (r.eventCategory === "Data" && !rp.bucketName) add("CT_S3_NO_BUCKET", r.eventName);
    if (r.eventCategory === "Data" && /Object$/.test(r.eventName) && !rp.key) add("CT_S3_NO_KEY", r.eventName);
    if (typeof rp.bucketName === "string" && !/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(rp.bucketName)) add("CT_S3_BUCKET_NAME", rp.bucketName);
  }
  const rp = r.requestParameters;
  if (rp && typeof rp === "object") for (const k of Object.keys(rp)) if (/_/.test(k) && !/^x-amz/.test(k)) add("CT_SNAKE_PARAM", `${r.eventName}.${k}`);
}

export function checkGuardDuty(r: R, where: string, storyCt: R[], out: AwsFinding[]): void {
  const add = (kind: string, detail: string) => out.push({ kind, where, detail });
  const t = String(r.type);
  if (r.schemaVersion !== "2.0") add("GD_SCHEMA", String(r.schemaVersion));
  if (!REGIONS.has(r.region)) add("GD_REGION", r.region);
  if (RETIRED_GD.test(t)) add("GD_RETIRED_TYPE", t);
  const sev = Number(r.severity);
  if (!(sev >= 1 && sev <= (/^AttackSequence:/.test(t) ? 10 : 8.9))) add("GD_SEVERITY_RANGE", `${t} severity ${r.severity}`);
  if (!/^arn:aws[\w-]*:guardduty:[a-z0-9-]+:\d{12}:detector\/[0-9a-f]{32}\/finding\/[0-9a-f]{32}$/.test(r.arn ?? "")) add("GD_ARN", String(r.arn));
  if (!(Date.parse(r.createdAt) <= Date.parse(r.updatedAt))) add("GD_TIMES", `${r.createdAt} / ${r.updatedAt}`);
  const svc = r.service ?? {};
  if (svc.eventFirstSeen && svc.eventLastSeen && Date.parse(svc.eventFirstSeen) > Date.parse(svc.eventLastSeen)) add("GD_SEEN_ORDER", `${svc.eventFirstSeen} > ${svc.eventLastSeen}`);
  const rt = r.resource?.resourceType;
  const expect = /:IAMUser\//.test(t) ? "AccessKey" : /:EC2\//.test(t) ? "Instance" : /:S3\//.test(t) ? "S3Bucket" : /:Kubernetes\//.test(t) ? "EKSCluster" : null;
  if (expect && rt !== expect) add("GD_RESOURCE_TYPE", `${t} -> ${rt}, expected ${expect}`);
  if (/:IAMUser\//.test(t) && svc.action?.actionType !== "AWS_API_CALL") add("GD_ACTION_TYPE", `${t} -> ${svc.action?.actionType}`);
  if (storyCt.length) {
    const key = r.resource?.accessKeyDetails?.accessKeyId;
    if (key && !storyCt.some(c => c.userIdentity?.accessKeyId === key)) add("GD_KEY_NOT_IN_CLOUDTRAIL", `${t} key ${key}`);
    const ip = svc.action?.awsApiCallAction?.remoteIpDetails?.ipAddressV4;
    if (ip && /:IAMUser\//.test(t) && !storyCt.some(c => c.sourceIPAddress === ip)) add("GD_IP_NOT_IN_CLOUDTRAIL", `${t} ip ${ip}`);
    const api = svc.action?.awsApiCallAction?.api;
    if (api && /:IAMUser\//.test(t) && !storyCt.some(c => c.eventName === api)) add("GD_API_NOT_IN_CLOUDTRAIL", `${t} api ${api}`);
  }
}

/** The AWS rows of one story, in story order: a minted key is used after, one account, the right home region. */
export function checkStory(storyId: string, ct: R[], out: AwsFinding[], homeRegion?: string): void {
  const add = (kind: string, detail: string) => out.push({ kind, where: storyId, detail });
  if (ct.length < 2) return;
  const accts = new Set(ct.map(c => c.recipientAccountId));
  if (accts.size > 2) add("STORY_MANY_ACCOUNTS", [...accts].join(","));
  for (const c of ct) {
    const minted = c.responseElements?.credentials?.accessKeyId ?? c.responseElements?.accessKey?.accessKeyId;
    if (!minted) continue;
    const later = ct.filter(x => Date.parse(x.eventTime) > Date.parse(c.eventTime));
    if (later.length && !later.some(x => x.userIdentity?.accessKeyId === minted)) add("STORY_MINTED_KEY_UNUSED", `${c.eventName} minted ${minted}; later rows use ${[...new Set(later.map(x => x.userIdentity?.accessKeyId))].join(",")}`);
  }
  if (homeRegion) for (const c of ct) {
    if (!GLOBAL.has(c.eventSource) && c.awsRegion !== homeRegion && !/bedrock|ses\.|sts\./.test(c.eventSource)) add("STORY_OUTSIDE_HOME_REGION", `${c.eventName} in ${c.awsRegion} (home ${homeRegion})`);
  }
}

export function checkFlowLine(line: string, where: string, out: AwsFinding[]): void {
  const add = (kind: string, detail: string) => out.push({ kind, where, detail });
  const f = line.trim().split(/\s+/);
  if (f.length < 14) { add("FLOW_FIELDS", line.slice(0, 120)); return; }
  const [ver, acct, eni, , , , , proto, , , start, end, action, status] = f;
  if (ver !== "2") add("FLOW_VERSION", ver);
  if (!/^\d{12}$/.test(acct)) add("FLOW_ACCOUNT", acct);
  if (!/^eni-[0-9a-f]{8,17}$/.test(eni)) add("FLOW_ENI", eni);
  if (!["6", "17", "1", "-"].includes(proto)) add("FLOW_PROTO", proto);
  if (!(Number(start) <= Number(end))) add("FLOW_TIME", `${start}>${end}`);
  if (!["ACCEPT", "REJECT", "-"].includes(action)) add("FLOW_ACTION", action);
  if (!["OK", "NODATA", "SKIPDATA"].includes(status)) add("FLOW_STATUS", status);
}
