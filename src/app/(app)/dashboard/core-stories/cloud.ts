/**
 * Cloud stories.
 *
 *  1. core-s3-ssec-extortion (AWS): a leaked long-lived key lists buckets, overwrites objects with SSE-C
 *     through CopyObject, sets a seven-day expiry and leaves a note (Codefinger, January 2025).
 *  2. core-ebs-snapshot-share (AWS): a volume snapshot shared with an outside account through
 *     ModifySnapshotAttribute, then deleted.
 *  3. core-azure-cloud-extortion (Azure): the Storm-0501 chain from a Global Administrator with no MFA
 *     to elevateAccess, Owner, storage keys, AzCopy exfiltration, deletion of recovery resources and an
 *     encryption scope with a customer key.
 */
import type { Severity, TelemetryEvent } from "@/lib/sim/types";
import { cloudTrailEvent, guardDutyFinding } from "@/lib/sim/emitters/cloudtrail";
import { entraAudit, entraSignIn } from "@/lib/sim/emitters/entra";
import { makeCtx } from "@/lib/logs/native/ctx";
import { AWS_COMPANIES, AZURE_COMPANIES, OFFICE_EGRESS, clock, incident, lookalike, type CoreStoryDef } from "./_kit";

const CLI = "aws-cli/2.17.20 Python/3.11.9 Linux/6.8.0-45-generic exe/x86_64.ubuntu.24";

// ── 1. S3 extortion with customer keys ───────────────────────────────────────
function s3Ssec(): TelemetryEvent[] {
  const T = clock("2026-10-16T01:12:00Z");
  const cx = "rocketstack";
  const ip = "203.0.113.210";
  const key = "AKIAIOSFCORE1EXAMPLE";
  const user = "svc-report-sync";
  const arn = `arn:aws:iam::418772153604:user/${user}`;
  const bucket = "customer-exports-prod";
  const a = { companyId: cx, srcIp: ip, actorName: user, arn, accessKeyId: key, userAgent: CLI };
  return incident("inc:core-s3-ssec:1", [
    lookalike(cloudTrailEvent({
      companyId: cx, id: "css01", ts: T(0), srcIp: "10.20.4.11", actorType: "AssumedRole", sessionIssuerName: "terraform-apply", actorName: "terraform-apply", eventName: "PutBucketLifecycle", eventSource: "s3.amazonaws.com", s3Bucket: "build-artifacts-ci", severity: "low",
      extra: { "aws.cloudtrail.requestParameters.LifecycleConfiguration.Rule.Expiration.Days": "90" },
      description: "CloudTrail PutBucketLifecycle on build-artifacts-ci by the terraform-apply role from 10.20.4.11, objects expire after 90 days.",
    }), "Infrastructure-as-code change: the Terraform role sets a 90-day retention on a build bucket during its normal pipeline run."),
    cloudTrailEvent({ ...a, id: "css02", ts: T(1500), eventName: "GetCallerIdentity", eventSource: "sts.amazonaws.com", readOnly: true, severity: "medium", mitre: "T1078.004", tactic: "Initial Access",
      description: "CloudTrail GetCallerIdentity by the svc-report-sync access key from 203.0.113.210, user agent aws-cli on Linux." }),
    cloudTrailEvent({ ...a, id: "css03", ts: T(1530), eventName: "ListBuckets", eventSource: "s3.amazonaws.com", readOnly: true, severity: "medium", mitre: "T1619", tactic: "Discovery",
      description: "CloudTrail ListBuckets by svc-report-sync from 203.0.113.210." }),
    cloudTrailEvent({ ...a, id: "css04", ts: T(1600), eventName: "ListObjects", eventSource: "s3.amazonaws.com", s3Bucket: bucket, readOnly: true, managementEvent: false, severity: "medium", mitre: "T1619", tactic: "Discovery",
      description: "CloudTrail data event: ListObjects on customer-exports-prod by svc-report-sync from 203.0.113.210." }),
    cloudTrailEvent({ ...a, id: "css05", ts: T(1680), eventName: "CopyObject", eventSource: "s3.amazonaws.com", s3Bucket: bucket, s3Key: "exports/2026/q3/accounts-full.parquet", readOnly: false, managementEvent: false, severity: "critical", mitre: "T1486", tactic: "Impact",
      extra: { "aws.cloudtrail.requestParameters.x-amz-copy-source": `${bucket}/exports/2026/q3/accounts-full.parquet`, "aws.cloudtrail.requestParameters.x-amz-server-side-encryption-customer-algorithm": "AES256", "aws.cloudtrail.additionalEventData.SSEApplied": "SSE_C" },
      description: "CloudTrail data event: CopyObject on customer-exports-prod overwrote exports/2026/q3/accounts-full.parquet in place, SSEApplied SSE_C, by svc-report-sync from 203.0.113.210." }),
    cloudTrailEvent({ ...a, id: "css06", ts: T(1681), eventName: "CopyObject", eventSource: "s3.amazonaws.com", s3Bucket: bucket, s3Key: "exports/2026/q3/invoices-full.parquet", readOnly: false, managementEvent: false, severity: "critical", mitre: "T1486", tactic: "Impact",
      extra: { "aws.cloudtrail.requestParameters.x-amz-copy-source": `${bucket}/exports/2026/q3/invoices-full.parquet`, "aws.cloudtrail.requestParameters.x-amz-server-side-encryption-customer-algorithm": "AES256", "aws.cloudtrail.additionalEventData.SSEApplied": "SSE_C" },
      description: "CloudTrail data event: CopyObject on customer-exports-prod overwrote exports/2026/q3/invoices-full.parquet in place, SSEApplied SSE_C." }),
    { ...guardDutyFinding({
      companyId: cx, id: "css07", ts: T(2100), findingType: "Impact:S3/AnomalousBehavior.Write", gdSeverity: 5, title: "An IAM entity invoked an S3 API that attempts to write data in a suspicious way.", srcIp: ip, api: "CopyObject", serviceName: "s3.amazonaws.com", callerType: "Remote IP",
      resourceType: "S3Bucket", bucketName: bucket, userType: "IAMUser", userName: user, accessKeyId: key, count: 1820, severity: "medium", mitre: "T1486", tactic: "Impact",
      description: "GuardDuty Impact:S3/AnomalousBehavior.Write on customer-exports-prod, IAM user svc-report-sync, 1820 CopyObject requests from 203.0.113.210.",
    }), edr_scope: "non_edr" as const },
    cloudTrailEvent({ ...a, id: "css08", ts: T(2400), eventName: "PutBucketLifecycle", eventSource: "s3.amazonaws.com", s3Bucket: bucket, severity: "critical", mitre: "T1485", tactic: "Impact",
      extra: { "aws.cloudtrail.requestParameters.LifecycleConfiguration.Rule.Expiration.Days": "7" },
      description: "CloudTrail PutBucketLifecycle on customer-exports-prod by svc-report-sync from 203.0.113.210, all objects expire after 7 days." }),
    cloudTrailEvent({ ...a, id: "css09", ts: T(2460), eventName: "PutObject", eventSource: "s3.amazonaws.com", s3Bucket: bucket, s3Key: "exports/READ_ME_RECOVER.txt", readOnly: false, managementEvent: false, severity: "high", mitre: "T1486", tactic: "Impact",
      description: "CloudTrail data event: PutObject of exports/READ_ME_RECOVER.txt to customer-exports-prod by svc-report-sync from 203.0.113.210." }),
  ]);
}

// ── 2. Snapshot sharing as exfiltration ──────────────────────────────────────
function ebsSnapshotShare(): TelemetryEvent[] {
  const T = clock("2026-10-17T03:44:00Z");
  const cx = "rocketstack";
  const ip = "203.0.113.211";
  const key = "AKIAIOSFCORE2EXAMPLE";
  const user = "n.haddad";
  const arn = `arn:aws:iam::418772153604:user/${user}`;
  const a = { companyId: cx, srcIp: ip, actorName: user, arn, accessKeyId: key, userAgent: CLI };
  const vol = "vol-0a91c4e27bd3f6108", snap = "snap-07de41b9c2a06f3e1";
  const outside = "730416259183", drAccount = "418772153699";
  return incident("inc:core-ebs-share:1", [
    lookalike(cloudTrailEvent({
      companyId: cx, id: "ceb01", ts: T(0), srcIp: "10.20.4.30", actorType: "AssumedRole", sessionIssuerName: "backup-dr-copy", actorName: "backup-dr-copy", eventName: "ModifySnapshotAttribute", eventSource: "ec2.amazonaws.com", severity: "low",
      extra: { "aws.cloudtrail.requestParameters.snapshotId": "snap-01bc77d3e4a2f9c05", "aws.cloudtrail.requestParameters.attributeType": "CREATE_VOLUME_PERMISSION", "aws.cloudtrail.requestParameters.createVolumePermission.add.items.userId": drAccount },
      description: "CloudTrail ModifySnapshotAttribute by the backup-dr-copy role from 10.20.4.30, snapshot snap-01bc77d3e4a2f9c05 shared with account 418772153699.",
    }), "The nightly disaster-recovery job shares backups with the company's own recovery account 418772153699, from the backup role inside the VPC."),
    cloudTrailEvent({ ...a, id: "ceb02", ts: T(1800), eventName: "DescribeVolumes", eventSource: "ec2.amazonaws.com", readOnly: true, severity: "medium", mitre: "T1580", tactic: "Discovery",
      description: "CloudTrail DescribeVolumes by IAM user n.haddad from 203.0.113.211, user agent aws-cli on Linux." }),
    cloudTrailEvent({ ...a, id: "ceb03", ts: T(1860), eventName: "CreateSnapshot", eventSource: "ec2.amazonaws.com", severity: "medium", mitre: "T1578.001", tactic: "Defense Impairment",
      extra: { "aws.cloudtrail.requestParameters.volumeId": vol, "aws.cloudtrail.responseElements.snapshotId": snap },
      description: "CloudTrail CreateSnapshot of vol-0a91c4e27bd3f6108 by n.haddad from 203.0.113.211, snapshot snap-07de41b9c2a06f3e1." }),
    cloudTrailEvent({ ...a, id: "ceb04", ts: T(2520), eventName: "ModifySnapshotAttribute", eventSource: "ec2.amazonaws.com", severity: "high", mitre: "T1537", tactic: "Exfiltration",
      extra: { "aws.cloudtrail.requestParameters.snapshotId": snap, "aws.cloudtrail.requestParameters.attributeType": "CREATE_VOLUME_PERMISSION", "aws.cloudtrail.requestParameters.createVolumePermission.add.items.userId": outside },
      description: "CloudTrail ModifySnapshotAttribute by n.haddad from 203.0.113.211, snapshot snap-07de41b9c2a06f3e1 shared with account 730416259183." }),
    { ...guardDutyFinding({
      companyId: cx, id: "ceb05", ts: T(2700), findingType: "Exfiltration:IAMUser/AnomalousBehavior", gdSeverity: 8, title: "An API commonly used to collect data from an AWS environment was invoked in an anomalous way.", srcIp: ip, api: "ModifySnapshotAttribute", serviceName: "ec2.amazonaws.com", callerType: "Remote IP",
      resourceType: "AccessKey", userType: "IAMUser", userName: user, accessKeyId: key, severity: "high", mitre: "T1537", tactic: "Exfiltration",
      description: "GuardDuty Exfiltration:IAMUser/AnomalousBehavior, IAM user n.haddad, API ModifySnapshotAttribute from 203.0.113.211.",
    }), edr_scope: "non_edr" as const },
    cloudTrailEvent({ ...a, id: "ceb06", ts: T(7200), eventName: "DeleteSnapshot", eventSource: "ec2.amazonaws.com", severity: "high", mitre: "T1070", tactic: "Stealth",
      extra: { "aws.cloudtrail.requestParameters.snapshotId": snap },
      description: "CloudTrail DeleteSnapshot of snap-07de41b9c2a06f3e1 by n.haddad from 203.0.113.211." }),
  ]);
}

// ── 3. Azure extortion (Storm-0501 chain) ────────────────────────────────────
function azureExtortion(): TelemetryEvent[] {
  const T = clock("2026-10-18T00:20:00Z");
  const cx = "nexacorp";
  const admin = "svc-cloudops@nexacorp.com";
  const ip = "203.0.113.212";
  const sub = makeCtx(cx).tenant.azureSubscriptionId;
  const rg = "PROD-DATA-RG", account = "prodfinancedata01", archive = "prodarchive01", vault = "kv-tmp-2f7c91", loc = "westeurope";
  const adminObjectId = "c7a4e1d0-3b92-4f6e-8d15-6e20b9f4a173";
  const ownerRole = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635";
  const act = (o: { id: string; ts: string; op: string; provider: string; type: string; name: string; rg?: string; caller?: string; ip?: string; severity?: Severity; mitre?: string; tactic?: string; description: string; subscriptionScope?: boolean; directory?: boolean; body?: unknown; evidenceRole?: string }): TelemetryEvent => {
    const group = o.rg ?? rg;
    const rid = o.directory ? "/providers/Microsoft.Authorization" : o.subscriptionScope ? `/SUBSCRIPTIONS/${sub.toUpperCase()}` : `/SUBSCRIPTIONS/${sub.toUpperCase()}/RESOURCEGROUPS/${group}/PROVIDERS/${o.provider}/${o.type}/${o.name.toUpperCase()}`;
    const caller = o.caller ?? admin, callerIp = o.ip ?? ip;
    return {
      id: o.id, ts: o.ts, source: "cloud_azure", vendor: "Azure Activity Log", event_type: "cloud_api_call", severity: o.severity ?? "high", user_email: caller, src_ip: callerIp,
      ...(o.mitre ? { mitre_technique: o.mitre } : {}), ...(o.tactic ? { mitre_tactic: o.tactic } : {}), description: o.description,
      raw: {
        "azure.activitylogs.operationName": o.op, "azure.activitylogs.event_category": "Administrative", "azure.activitylogs.resultType": "Success", "azure.activitylogs.resultSignature": "Succeeded.OK", "azure.activitylogs.level": "Information",
        "azure.activitylogs.callerIpAddress": callerIp, "azure.activitylogs.identity.claims_initiated_by_user.name": caller, "azure.resource.id": rid,
        // A directory-level action is logged with no subscription or resource group.
        ...(o.directory ? {} : { "azure.resource.group": group, "azure.resource.provider": o.provider, "azure.resource.name": o.name.toUpperCase(), "azure.subscription_id": sub }),
        ...(o.body ? { "azure.activitylogs.properties.requestbody": JSON.stringify(o.body) } : {}),
        ...(o.evidenceRole ? { "azure.activitylogs.identity.authorization.evidence.role": o.evidenceRole, "azure.activitylogs.identity.authorization.evidence.principalType": "User" } : {}),
        "cloud.provider": "azure", "cloud.region": loc,
      },
    };
  };
  const dfc = (o: { id: string; ts: string; name: string; type: string; text: string; severity: Severity; mitre: string; tactic: string; intent: string; entity: string; description: string }): TelemetryEvent => ({
    id: o.id, ts: o.ts, source: "cloud_azure", vendor: "Microsoft Defender for Cloud", event_type: "cloud_api_call", severity: o.severity, user_email: admin, src_ip: ip, is_detection: true, edr_scope: "non_edr", mitre_technique: o.mitre, mitre_tactic: o.tactic, description: o.description,
    raw: {
      "azure.alert.displayName": o.name, "azure.alert.alertType": o.type, "azure.alert.severity": o.severity === "medium" ? "Medium" : "High", "azure.alert.status": "Active", "azure.alert.intent": o.intent, "azure.alert.description": o.text, "azure.alert.compromisedEntity": o.entity,
      "azure.alert.productName": "Microsoft Defender for Cloud", "azure.alert.vendorName": "Microsoft", "azure.alert.extendedProperties.Client IP address": ip, "azure.subscription_id": sub, "azure.resource.group": rg, "azure.resource.name": o.entity, "cloud.provider": "azure", "cloud.region": loc, "event.kind": "alert", "source.ip": ip,
    },
  });
  return incident("inc:core-az-extortion:1", [
    lookalike(act({
      id: "caz01", ts: T(0), op: "MICROSOFT.COMPUTE/SNAPSHOTS/DELETE", provider: "MICROSOFT.COMPUTE", type: "SNAPSHOTS", name: "app-disk-snap-2026-07", rg: "DEV-APP-RG", caller: "d.romero@nexacorp.com", ip: OFFICE_EGRESS, severity: "low",
      description: "Azure Activity: snapshot app-disk-snap-2026-07 deleted in DEV-APP-RG by d.romero from the office egress.",
    }), "Monthly clean-up of expired development snapshots by a named cloud engineer from the office, on a development resource group."),
    entraSignIn({
      companyId: cx, id: "caz02", ts: T(3000), user: admin, srcIp: ip, app: "Azure Portal", isInteractive: true, os: "Windows Server 2022", browser: "Chrome 149.0.0", managed: true, trustType: "Hybrid Azure AD joined", severity: "high", mitre: "T1078.004", tactic: "Initial Access",
      description: "Entra ID sign-in for svc-cloudops to Azure Portal from 203.0.113.212, authenticationRequirement singleFactorAuthentication, on a hybrid-joined server.",
    }),
    entraAudit({
      companyId: cx, id: "caz03", ts: T(3120), operationName: "User registered security info", category: "UserManagement", loggedByService: "Authentication Methods", operationType: "Add", initiatedByUpn: admin, initiatedByIp: ip, targetUpn: admin, severity: "high", mitre: "T1098.005", tactic: "Persistence",
      extra: { "azure.auditlogs.properties.resultReason": "User registered Authenticator App with Notification and Code" },
      description: "Entra ID audit: svc-cloudops registered an authenticator app from 203.0.113.212.",
    }),
    act({ id: "caz04", ts: T(3300), op: "MICROSOFT.AUTHORIZATION/ELEVATEACCESS/ACTION", provider: "MICROSOFT.AUTHORIZATION", type: "ELEVATEACCESS", name: "action", directory: true, severity: "critical", mitre: "T1098.003", tactic: "Privilege Escalation",
      description: "Azure Activity: Microsoft.Authorization/elevateAccess/action by svc-cloudops from 203.0.113.212." }),
    act({ id: "caz05", ts: T(3360), op: "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE", provider: "MICROSOFT.AUTHORIZATION", type: "ROLEASSIGNMENTS", name: "owner-assignment", subscriptionScope: true, severity: "critical", mitre: "T1098.003", tactic: "Privilege Escalation",
      evidenceRole: "User Access Administrator", body: { Id: "5f2c8a14-6e0b-4d97-a3c1-8b47e2d09f61", Properties: { PrincipalId: adminObjectId, PrincipalType: "User", RoleDefinitionId: `/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/${ownerRole}`, Scope: "/subscriptions/{subscriptionId}" } },
      description: "Azure Activity: role assignment write by svc-cloudops at subscription scope, Owner assigned to svc-cloudops." }),
    dfc({ id: "caz06", ts: T(3420), name: "Suspicious elevate access operation", type: "ARM_AnomalousElevateAccess", text: "A suspicious Elevate Access operation was identified for a principal that rarely invokes it.", severity: "medium", mitre: "T1098.003", tactic: "Privilege Escalation", intent: "PrivilegeEscalation", entity: admin,
      description: "Defender for Cloud alert: Suspicious elevate access operation, svc-cloudops from 203.0.113.212." }),
    act({ id: "caz07", ts: T(3600), op: "MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE", provider: "MICROSOFT.STORAGE", type: "STORAGEACCOUNTS", name: account, mitre: "T1686.001", tactic: "Defense Impairment",
      body: { properties: { publicNetworkAccess: "Enabled", networkAcls: { defaultAction: "Allow", bypass: "AzureServices", ipRules: [], virtualNetworkRules: [] } } },
      description: `Azure Activity: storage account ${account} updated by svc-cloudops, networkAcls defaultAction Allow.` }),
    act({ id: "caz08", ts: T(3660), op: "MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION", provider: "MICROSOFT.STORAGE", type: "STORAGEACCOUNTS", name: account, mitre: "T1552", tactic: "Credential Access",
      description: `Azure Activity: access keys listed for storage account ${account} by svc-cloudops from 203.0.113.212.` }),
    dfc({ id: "caz09", ts: T(6300), name: "Unusual amount of data extracted from a storage account", type: "Storage.Blob_DataExfiltration.AmountOfDataAnomaly", text: "An unusual amount of data was extracted from this storage account, client application AzCopy.", severity: "high", mitre: "T1530", tactic: "Collection", intent: "Exfiltration", entity: account,
      description: `Defender for Cloud alert: Unusual amount of data extracted from storage account ${account}, client AzCopy, 203.0.113.212.` }),
    act({ id: "caz10", ts: T(7200), op: "MICROSOFT.AUTHORIZATION/LOCKS/DELETE", provider: "MICROSOFT.AUTHORIZATION", type: "LOCKS", name: "do-not-delete-prod", mitre: "T1490", tactic: "Impact",
      description: "Azure Activity: resource lock do-not-delete-prod removed in PROD-DATA-RG by svc-cloudops." }),
    act({ id: "caz11", ts: T(7260), op: "MICROSOFT.COMPUTE/SNAPSHOTS/DELETE", provider: "MICROSOFT.COMPUTE", type: "SNAPSHOTS", name: "fin-sql-disk-snap-daily", severity: "critical", mitre: "T1490", tactic: "Impact",
      description: "Azure Activity: snapshot fin-sql-disk-snap-daily deleted in PROD-DATA-RG by svc-cloudops from 203.0.113.212." }),
    act({ id: "caz12", ts: T(7320), op: "MICROSOFT.STORAGE/STORAGEACCOUNTS/DELETE", provider: "MICROSOFT.STORAGE", type: "STORAGEACCOUNTS", name: account, severity: "critical", mitre: "T1485", tactic: "Impact",
      description: `Azure Activity: storage account ${account} deleted by svc-cloudops from 203.0.113.212.` }),
    act({ id: "caz13", ts: T(7500), op: "MICROSOFT.KEYVAULT/VAULTS/WRITE", provider: "MICROSOFT.KEYVAULT", type: "VAULTS", name: vault, mitre: "T1486", tactic: "Impact",
      description: "Azure Activity: key vault kv-tmp-2f7c91 created in PROD-DATA-RG by svc-cloudops from 203.0.113.212." }),
    act({ id: "caz14", ts: T(7620), op: "MICROSOFT.STORAGE/STORAGEACCOUNTS/ENCRYPTIONSCOPES/WRITE", provider: "MICROSOFT.STORAGE", type: `STORAGEACCOUNTS/${archive.toUpperCase()}/ENCRYPTIONSCOPES`, name: "scope-ext01", severity: "critical", mitre: "T1486", tactic: "Impact",
      body: { properties: { source: "Microsoft.KeyVault", keyVaultProperties: { keyUri: `https://${vault}.vault.azure.net/keys/ext-key-01` } } },
      description: `Azure Activity: encryption scope scope-ext01 written on storage account ${archive} by svc-cloudops, using a key held in ${vault}.` }),
  ]);
}

export const CLOUD_STORIES: CoreStoryDef[] = [
  { id: "core-s3-ssec-extortion", title: "S3 Extortion: Objects Rewritten with Customer Keys, Seven-Day Expiry", complexity: "advanced", companies: AWS_COMPANIES, events: s3Ssec() },
  { id: "core-ebs-snapshot-share", title: "Volume Snapshot Shared with an Outside AWS Account", complexity: "core", companies: AWS_COMPANIES, events: ebsSnapshotShare() },
  { id: "core-azure-cloud-extortion", title: "Azure Extortion: Elevated Access, Storage Theft, Recovery Deleted, Customer Key", complexity: "advanced", companies: AZURE_COMPANIES, events: azureExtortion() },
];
