/**
 * AWS CloudTrail log EMITTER.
 *
 * The cloud control-plane audit trail — every API call an analyst reads for S3
 * exfiltration, IAM privilege-escalation, console sign-in, AssumeRole abuse,
 * secret theft and trail-tampering. Same contract as the other emitters: a typed
 * call renders a complete TelemetryEvent whose raw block uses only registry-valid
 * CloudTrail fields (the aws.cloudtrail. prefix + the shared aws./cloud./event./
 * api.* fields). The caller's IP is the evidence; geography is resolved
 * deterministically from it (@/lib/geo/resolveGeo) so a pivot never contradicts
 * the feed.
 *
 * CloudTrail is source:"cloudtrail" and carries no process.
 */
import type { TelemetryEvent, Severity, EventType } from "../types";
import type { Ctx } from "./_core";
import { knownGeoForIp } from "@/lib/geo/resolveGeo";

const VENDOR = "AWS CloudTrail";

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
  eventName: string;                // e.g. "GetObject", "CreateAccessKey", "ConsoleLogin"
  eventSource?: string;             // derived from eventName when omitted
  srcIp: string;                    // sourceIPAddress
  region?: string;                  // default us-east-1
  accountId?: string;
  actorType?: "IAMUser" | "AssumedRole" | "Root" | "AWSService";
  actorName?: string;               // IAM user / role name
  userAgent?: string;
  outcome?: "success" | "failure";
  errorCode?: string;               // e.g. "AccessDenied" (failure)
  mfa?: boolean;                    // ConsoleLogin with MFA
  s3Bucket?: string;
  s3Key?: string;
  ec2Instance?: string;
  bytes?: number;
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
    severity: o.severity ?? "medium", src_ip: o.srcIp, user_email: undefined,
    mitre_technique: o.mitre, mitre_tactic: o.tactic, incident_id: o.incidentId, geo,
    description: o.description ?? `${actorName} called ${o.eventName} (${eventSource}) — ${outcome}`,
    raw: {
      "aws.cloudtrail.event_name": o.eventName,
      "aws.cloudtrail.event_source": eventSource,
      "aws.region": region,
      "aws.account.id": account,
      ...(actorType === "IAMUser" || actorType === "AssumedRole" ? { "aws.iam.user.name": actorName } : {}),
      ...(o.s3Bucket ? { "aws.s3.bucket.name": o.s3Bucket } : {}),
      ...(o.ec2Instance ? { "aws.ec2.instance.id": o.ec2Instance } : {}),
      "cloud.provider": "aws",
      "cloud.region": region,
      "cloud.account.id": account,
      "cloud.service.name": eventSource.split(".")[0],
      "event.action": o.eventName,
      "event.category": eventSource.startsWith("s3") ? "file" : eventSource.startsWith("iam") ? "iam" : "api",
      "event.outcome": outcome,
      ...(errorCode ? { "event.reason": errorCode } : {}),
      "api.method": "POST",
      ...(o.mfa !== undefined ? { "authentication.mfa": String(o.mfa) } : {}),
      ...(errorCode ? { "authentication.failure_reason": errorCode } : {}),
      "source.ip": o.srcIp,
      ...(o.userAgent ? { "user_agent.original": o.userAgent } : {}),
    },
  };
}
