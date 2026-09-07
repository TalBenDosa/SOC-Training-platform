/**
 * AWS CloudTrail + GuardDuty log EMITTERS.
 *
 * The cloud control-plane audit trail — every API call an analyst reads for S3
 * exfiltration, IAM privilege-escalation, console sign-in, AssumeRole abuse,
 * secret theft and trail-tampering — plus the GuardDuty findings raised on top of
 * it. Same contract as the other emitters: a typed call renders a complete
 * TelemetryEvent whose raw block uses only registry-valid fields (the
 * aws.cloudtrail. / aws.guardduty. prefixes + the shared aws./cloud. fields),
 * in the AUTHENTIC CloudTrail camelCase schema (eventName, userIdentity.*,
 * requestParameters.*, additional_event_data.*). The caller's IP is the evidence;
 * geography is resolved deterministically from it (@/lib/geo/resolveGeo).
 *
 * Both ride source:"cloudtrail" and carry no process. GuardDuty is vendor
 * "AWS GuardDuty" (an alias of the aws-cloudtrail registry key).
 */
import type { TelemetryEvent, Severity, EventType } from "../types";
import type { Ctx } from "./_core";
import { knownGeoForIp } from "@/lib/geo/resolveGeo";

const VENDOR = "AWS CloudTrail";
const GD_VENDOR = "AWS GuardDuty";

// eventName → the AWS service source that emits it.
function sourceForEvent(name: string): string {
  const n = name.toLowerCase();
  if (/object|bucket|s3/.test(n)) return "s3.amazonaws.com";
  if (/user|policy|accesskey|role|group|login profile/i.test(n)) return "iam.amazonaws.com";
  if (name === "ConsoleLogin" || /assumerole|getsessiontoken|getfederation/i.test(n)) return name === "ConsoleLogin" ? "signin.amazonaws.com" : "sts.amazonaws.com";
  if (/instance|securitygroup|ec2|volume|snapshot/i.test(n)) return "ec2.amazonaws.com";
  if (/secret/i.test(n)) return "secretsmanager.amazonaws.com";
  if (/trail|logging|eventselector/i.test(n)) return "cloudtrail.amazonaws.com";
  if (/key|kms|decrypt|encrypt/i.test(n)) return "kms.amazonaws.com";
  return "monitoring.amazonaws.com";
}

// eventName → the platform EventType the feed/console reason over.
function eventTypeFor(name: string, outcome: "success" | "failure"): EventType {
  if (name === "ConsoleLogin") return outcome === "success" ? "auth_success" : "auth_failure";
  const n = name.toLowerCase();
  if (/getobject|putobject|listobjects|deleteobject|copyobject/.test(n)) return "cloud_storage_access";
  if (/createuser|createaccesskey|attachuserpolicy|putuserpolicy|adduser|createrole|attachrolepolicy|createloginprofile|updateassumerolepolicy/i.test(n)) return "cloud_role_change";
  if (/stoplogging|deletetrail|puteventselectors|updatetrail/i.test(n)) return "audit_log_cleared";
  return "cloud_api_call";
}

export interface CloudTrailOpts extends Ctx {
  eventName: string;                // e.g. "GetObject", "PutBucketPolicy", "ConsoleLogin"
  eventSource?: string;             // derived from eventName when omitted
  srcIp: string;                    // sourceIPAddress
  region?: string;                  // default us-east-1
  accountId?: string;
  actorType?: "IAMUser" | "AssumedRole" | "Root" | "AWSService" | "WebIdentityUser";
  actorName?: string;               // IAM user / role name (or the OIDC subject for WebIdentityUser)
  arn?: string;                     // userIdentity.arn
  accessKeyId?: string;             // userIdentity.accessKeyId
  sessionIssuerName?: string;       // sessionContext.sessionIssuer.userName (AssumedRole)
  userAgent?: string;
  outcome?: "success" | "failure";
  errorCode?: string;               // e.g. "AccessDenied" (failure)
  mfa?: boolean;                    // ConsoleLogin with MFA
  s3Bucket?: string;
  s3Key?: string;
  ec2Instance?: string;
  bytes?: number;                   // additional_event_data.bytes_transferred_out
  readOnly?: boolean;               // aws.cloudtrail.readOnly
  managementEvent?: boolean;        // aws.cloudtrail.managementEvent
  awsEventType?: string;            // aws.cloudtrail.eventType (default "AwsApiCall")
  userTitle?: string;
  /** requestParameters.* / additional_event_data.* / vpcEndpointId / sessionContext.* … */
  extra?: Record<string, string | number>;
  geo?: { country?: string; city?: string };
  mitre?: string;
  tactic?: string;
  severity?: Severity;
  description?: string;
}

export function cloudTrailEvent(o: CloudTrailOpts): TelemetryEvent {
  const outcome = o.outcome ?? "success";
  const region = o.region ?? "us-east-1";
  const account = o.accountId ?? "418772153604";
  const eventSource = o.eventSource ?? sourceForEvent(o.eventName);
  const actorName = o.actorName ?? "svc-deploy";
  const actorType = o.actorType ?? "IAMUser";
  const geo = o.geo ?? (() => { const k = knownGeoForIp(o.srcIp); return k ? { country: k.country, city: k.city } : undefined; })();
  const errorCode = outcome === "failure" ? (o.errorCode ?? "AccessDenied") : undefined;
  return {
    id: o.id, ts: o.ts, source: "cloudtrail", vendor: VENDOR, event_type: eventTypeFor(o.eventName, outcome),
    severity: o.severity ?? "medium", src_ip: o.srcIp, user_email: undefined, user_title: o.userTitle,
    mitre_technique: o.mitre, mitre_tactic: o.tactic, incident_id: o.incidentId, geo,
    description: o.description ?? `${actorName} called ${o.eventName} (${eventSource}) — ${outcome}`,
    raw: {
      "aws.cloudtrail.eventName": o.eventName,
      "aws.cloudtrail.eventSource": eventSource,
      "aws.cloudtrail.awsRegion": region,
      "aws.cloudtrail.userIdentity.type": actorType,
      ...(actorName && actorType !== "AssumedRole" ? { "aws.cloudtrail.userIdentity.userName": actorName } : {}),
      ...(o.arn ? { "aws.cloudtrail.userIdentity.arn": o.arn } : {}),
      ...(o.accessKeyId ? { "aws.cloudtrail.userIdentity.accessKeyId": o.accessKeyId } : {}),
      "aws.cloudtrail.userIdentity.accountId": account,
      ...(actorType === "AssumedRole" && o.sessionIssuerName ? {
        "aws.cloudtrail.userIdentity.sessionContext.sessionIssuer.userName": o.sessionIssuerName,
        "aws.cloudtrail.userIdentity.sessionContext.sessionIssuer.type": "Role",
      } : {}),
      ...(o.s3Bucket ? { "aws.cloudtrail.requestParameters.bucketName": o.s3Bucket } : {}),
      ...(o.s3Key ? { "aws.cloudtrail.requestParameters.key": o.s3Key } : {}),
      ...(o.ec2Instance ? { "aws.cloudtrail.requestParameters.instanceId": o.ec2Instance } : {}),
      ...(o.bytes !== undefined ? { "aws.cloudtrail.additional_event_data.bytes_transferred_out": String(o.bytes) } : {}),
      "aws.cloudtrail.sourceIPAddress": o.srcIp,
      ...(o.userAgent ? { "aws.cloudtrail.userAgent": o.userAgent } : {}),
      "aws.cloudtrail.eventType": o.awsEventType ?? "AwsApiCall",
      ...(o.readOnly !== undefined ? { "aws.cloudtrail.readOnly": String(o.readOnly) } : {}),
      ...(o.managementEvent !== undefined ? { "aws.cloudtrail.managementEvent": String(o.managementEvent) } : {}),
      ...(errorCode ? { "aws.cloudtrail.errorCode": errorCode } : {}),
      ...(o.mfa !== undefined ? { "aws.cloudtrail.additionalEventData.MFAUsed": o.mfa ? "Yes" : "No" } : {}),
      "cloud.provider": "aws",
      "cloud.account.id": account,
      "cloud.region": region,
      "event.outcome": outcome,
      "source.ip": o.srcIp,
      ...(o.extra ?? {}),
    },
  };
}

// ── GuardDuty finding ─────────────────────────────────────────────────────────────────
// A GuardDuty finding raised on top of the CloudTrail/VPC/DNS data plane. Vendor
// "AWS GuardDuty" (an alias of aws-cloudtrail), so the aws.guardduty.* prefix validates.
export interface GuardDutyFindingOpts extends Ctx {
  findingType: string;              // e.g. "Exfiltration:S3/ObjectRead.Unusual"
  gdSeverity: number;               // GuardDuty 1-10 severity score
  title: string;
  srcIp?: string;                   // remoteIpDetails.ipAddressV4
  api?: string;                     // awsApiCallAction.api
  serviceName?: string;             // awsApiCallAction.serviceName
  callerType?: string;              // "Remote IP" | …
  remoteCountry?: string;
  asnOrg?: string;
  resourceType?: string;            // "S3Bucket" | "AccessKey" | "Instance" | …
  bucketName?: string;
  effectivePermission?: string;     // s3BucketDetails.publicAccess.effectivePermission
  userType?: string;                // accessKeyDetails.userType
  userName?: string;                // accessKeyDetails.userName
  accessKeyId?: string;
  count?: number;                   // service.count
  region?: string;
  accountId?: string;
  isDetection?: boolean;            // default true
  eventType?: EventType;            // default "cloud_api_call"
  extra?: Record<string, string | number>;
  mitre?: string;
  tactic?: string;
  severity?: Severity;
  description?: string;
}
export function guardDutyFinding(o: GuardDutyFindingOpts): TelemetryEvent {
  const region = o.region ?? "us-east-1";
  const account = o.accountId ?? "418772153604";
  const geo = o.remoteCountry ? { country: o.remoteCountry } : (o.srcIp ? (() => { const k = knownGeoForIp(o.srcIp!); return k ? { country: k.country, city: k.city } : undefined; })() : undefined);
  return {
    id: o.id, ts: o.ts, source: "cloudtrail", vendor: GD_VENDOR, event_type: o.eventType ?? "cloud_api_call",
    severity: o.severity ?? (o.gdSeverity >= 7 ? "high" : "medium"), src_ip: o.srcIp,
    mitre_technique: o.mitre, mitre_tactic: o.tactic, is_detection: o.isDetection ?? true, incident_id: o.incidentId, geo,
    description: o.description ?? `GuardDuty raised ${o.findingType} (severity ${o.gdSeverity})`,
    raw: {
      "aws.guardduty.type": o.findingType,
      "aws.guardduty.severity": String(o.gdSeverity),
      "aws.guardduty.title": o.title,
      "aws.guardduty.service.action.actionType": "AWS_API_CALL",
      ...(o.api ? { "aws.guardduty.service.action.awsApiCallAction.api": o.api } : {}),
      ...(o.serviceName ? { "aws.guardduty.service.action.awsApiCallAction.serviceName": o.serviceName } : {}),
      ...(o.callerType ? { "aws.guardduty.service.action.awsApiCallAction.callerType": o.callerType } : {}),
      ...(o.srcIp ? { "aws.guardduty.service.action.awsApiCallAction.remoteIpDetails.ipAddressV4": o.srcIp } : {}),
      ...(o.remoteCountry ? { "aws.guardduty.service.action.awsApiCallAction.remoteIpDetails.country.countryName": o.remoteCountry } : {}),
      ...(o.asnOrg ? { "aws.guardduty.service.action.awsApiCallAction.remoteIpDetails.organization.asnOrg": o.asnOrg } : {}),
      ...(o.resourceType ? { "aws.guardduty.resource.resourceType": o.resourceType } : {}),
      ...(o.bucketName ? { "aws.guardduty.resource.s3BucketDetails.name": o.bucketName } : {}),
      ...(o.effectivePermission ? { "aws.guardduty.resource.s3BucketDetails.publicAccess.effectivePermission": o.effectivePermission } : {}),
      ...(o.userType ? { "aws.guardduty.resource.accessKeyDetails.userType": o.userType } : {}),
      ...(o.userName ? { "aws.guardduty.resource.accessKeyDetails.userName": o.userName } : {}),
      ...(o.accessKeyId ? { "aws.guardduty.resource.accessKeyDetails.accessKeyId": o.accessKeyId } : {}),
      ...(o.count !== undefined ? { "aws.guardduty.service.count": String(o.count) } : {}),
      "cloud.account.id": account,
      "cloud.region": region,
      ...(o.extra ?? {}),
    },
  };
}
