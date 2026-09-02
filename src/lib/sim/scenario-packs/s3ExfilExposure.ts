/**
 * Scenario pack: "Exposed Bucket — S3 Made Public, Then Emptied" (INTERMEDIATE)
 *
 * A cloud data-theft case that never touches an endpoint and lives entirely in
 * AWS CloudTrail and GuardDuty. An operator holding an over-permissioned,
 * leaked IAM access key (a long-lived key that belonged to a reporting service
 * account) weakens a production S3 bucket's protections and then drains it.
 *
 * TEACHING ARC — origin vs. blast radius:
 *   ORIGIN (CloudTrail *management* events): the config-change that made the
 *   theft possible. PutBucketPublicAccessBlock turns off Block Public Access,
 *   PutBucketPolicy attaches an allow-anyone policy, PutBucketAcl grants the
 *   AllUsers group READ. These three writes, driven by an IAMUser access key
 *   from an address OUTSIDE AWS, are where the incident actually begins.
 *
 *   BLAST RADIUS (CloudTrail *data* events + GuardDuty): once the bucket is
 *   reachable, ListObjectsV2 enumerates it and a GetObject burst pulls the
 *   objects down — again from outside AWS. GuardDuty raises the anonymous-access
 *   finding on the policy change and the object-read finding on the drain.
 *
 * THE KEY TELL: the from-outside-AWS sourceIPAddress. A GitHub-runner range, a
 * VPC endpoint, or an AWS service principal is where the deploy/backup traffic
 * normally originates; here every management write and every object read carries
 * an internet source address on an IAMUser access key.
 *
 * BENIGN CONTROL (s3exfil_00): the night before, the real backup/data-pipeline
 * role reads the SAME bucket at high volume — hundreds of GetObject — but from
 * WITHIN AWS over an S3 VPC endpoint, as an expected assumed-role session, with
 * no public-access change anywhere near it. Same "many GetObject" shape,
 * opposite verdict. The lesson: a bucket read is not an incident; a bucket read
 * from outside AWS after its protections were stripped is.
 *
 * SOURCES (registry key aws-cloudtrail): vendors "AWS CloudTrail" (management +
 * data events) and "AWS GuardDuty" (findings, aws.guardduty.* prefix). Both ride
 * the platform's `source: "cloudtrail"` LogSource.
 *
 * NOTE: register in scenarios.ts with difficulty "intermediate". The
 * ScenarioBundle itself carries no difficulty field.
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";

export function buildS3ExfilExposureScenario(
  scenarioId = "s3-exfil-exposure-2026",
): ScenarioBundle {
  const B = new Date("2026-08-31T03:00:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const SEC = 1_000;

  // One incident — the whole chain is a single bucket-exposure case.
  const INCIDENT = "inc:s3exfil:1";

  // The account and the bucket that holds regulated data.
  const awsAccount = "612498330517";
  const region = "us-east-1";
  const bucket = "medcore-patient-exports-prod";

  // The abused credential: a long-lived IAM access key for a reporting service
  // account, over-permissioned and leaked. Every attacker action rides it.
  const iamUser = "reporting-export-svc";
  const accessKeyId = "AKIA4MC2X7QF9ZB3RLTD";
  const iamUserArn = `arn:aws:iam::${awsAccount}:user/${iamUser}`;
  // The operator's external address — outside AWS, the whole tell.
  const attackerIp = "91.242.217.35";

  // The benign control: the real backup / data-pipeline role reading the same
  // bucket the expected way — an assumed-role session, from inside AWS over an
  // S3 VPC endpoint, with no public-access change.
  const backupRole = "medcore-backup-replicator";
  const backupAssumedArn = `arn:aws:sts::${awsAccount}:assumed-role/${backupRole}/backup-2026-08-30`;
  const backupPrivateIp = "10.0.42.17";
  const vpcEndpointId = "vpce-0a1b2c3d4e5f6a7b8";

  // A content hash of one drained object — concrete evidence of what left.
  const objectSha = makeSha256("s3exfil_patient_exports_object_2026");

  const events: TelemetryEvent[] = [
    // ─────────────────────────────────────────────────────────────────────
    // 0. BENIGN CONTROL — the sanctioned high-volume read of the SAME bucket.
    //    The backup role pulling objects from inside AWS over a VPC endpoint,
    //    no public-access change. Same "many GetObject" shape as the attack.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "s3exfil_00_benign_backup",
      ts: "2026-08-30T02:15:00.000Z",
      source: "cloudtrail",
      vendor: "AWS CloudTrail",
      event_type: "cloud_api_call",
      user_title: "Automated Service",
      src_ip: backupPrivateIp,
      severity: "informational",
      expected_verdict: "fp",
      fp_explanation:
        "This is the control the whole scenario is measured against. The SAME bucket is read at high volume — a nightly job pulling hundreds of objects — but every difference that matters points the other way: the caller is the expected medcore-backup-replicator assumed-role session (not a standalone access key), the traffic originates INSIDE AWS over an S3 VPC endpoint (vpcEndpointId set, a private 10.x source address), and nothing anywhere near it touched the bucket's public-access settings. An analyst who alerts on 'a lot of GetObject on the exports bucket' will flag this and be wrong — the read volume is normal for backup; what makes the later activity an incident is where it came from and what preceded it.",
      description:
        "GetObject at volume on medcore-patient-exports-prod by the medcore-backup-replicator role over VPC endpoint vpce-0a1b2c3d4e5f6a7b8, sourced from the private address 10.0.42.17 — the nightly replication job.",
      raw: {
        "aws.cloudtrail.eventName": "GetObject",
        "aws.cloudtrail.eventSource": "s3.amazonaws.com",
        "aws.cloudtrail.awsRegion": region,
        "aws.cloudtrail.userIdentity.type": "AssumedRole",
        "aws.cloudtrail.userIdentity.arn": backupAssumedArn,
        "aws.cloudtrail.userIdentity.sessionContext.sessionIssuer.userName": backupRole,
        "aws.cloudtrail.userIdentity.sessionContext.sessionIssuer.type": "Role",
        "aws.cloudtrail.requestParameters.bucketName": bucket,
        "aws.cloudtrail.requestParameters.key": "exports/2026-08-29/patients-000417.parquet",
        "aws.cloudtrail.vpcEndpointId": vpcEndpointId,
        "aws.cloudtrail.additional_event_data.bytes_transferred_out": "10485760",
        "aws.cloudtrail.sourceIPAddress": backupPrivateIp,
        "aws.cloudtrail.userAgent": "aws-sdk-java/2.25.11 Linux/5.15 vendor/Amazon.com",
        "aws.cloudtrail.eventType": "AwsApiCall",
        "aws.cloudtrail.readOnly": "true",
        "aws.cloudtrail.managementEvent": "false",
        "cloud.account.id": awsAccount,
        "cloud.region": region,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 1. FIRST USE OF THE LEAKED KEY — ListBuckets from an external address.
    //    An IAMUser access key enumerating the account's buckets, from an
    //    internet source. The stolen-credential foothold (T1078.004).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "s3exfil_01_list_buckets",
      ts: T(0),
      source: "cloudtrail",
      vendor: "AWS CloudTrail",
      event_type: "cloud_api_call",
      user_title: "Service Account",
      src_ip: attackerIp,
      severity: "high",
      mitre_technique: "T1078.004",
      mitre_tactic: "Initial Access",
      incident_id: INCIDENT,
      description:
        "ListBuckets on account 612498330517 by the reporting-export-svc access key AKIA4MC2X7QF9ZB3RLTD from 91.242.217.35 — the first call this long-lived key has made from an internet address.",
      raw: {
        "aws.cloudtrail.eventName": "ListBuckets",
        "aws.cloudtrail.eventSource": "s3.amazonaws.com",
        "aws.cloudtrail.awsRegion": region,
        "aws.cloudtrail.userIdentity.type": "IAMUser",
        "aws.cloudtrail.userIdentity.userName": iamUser,
        "aws.cloudtrail.userIdentity.arn": iamUserArn,
        "aws.cloudtrail.userIdentity.accessKeyId": accessKeyId,
        "aws.cloudtrail.userIdentity.accountId": awsAccount,
        "aws.cloudtrail.sourceIPAddress": attackerIp,
        "aws.cloudtrail.userAgent": "aws-cli/2.15.30 Python/3.11.6 Linux/6.5 exe/x86_64",
        "aws.cloudtrail.eventType": "AwsApiCall",
        "aws.cloudtrail.readOnly": "true",
        "aws.cloudtrail.managementEvent": "true",
        "cloud.account.id": awsAccount,
        "cloud.region": region,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 2. CONFIG ORIGIN #1 — PutBucketPublicAccessBlock turns OFF Block Public
    //    Access. All four account-level guards flipped to false. The single
    //    change that lets a public policy take effect (T1562.007).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "s3exfil_02_disable_bpa",
      ts: T(3 * MIN),
      source: "cloudtrail",
      vendor: "AWS CloudTrail",
      event_type: "cloud_api_call",
      user_title: "Service Account",
      src_ip: attackerIp,
      severity: "critical",
      mitre_technique: "T1562.007",
      mitre_tactic: "Defense Evasion",
      incident_id: INCIDENT,
      description:
        "PutBucketPublicAccessBlock on medcore-patient-exports-prod set all four BlockPublicAcls / IgnorePublicAcls / BlockPublicPolicy / RestrictPublicBuckets flags to false, by the reporting-export-svc key from 91.242.217.35.",
      raw: {
        "aws.cloudtrail.eventName": "PutBucketPublicAccessBlock",
        "aws.cloudtrail.eventSource": "s3.amazonaws.com",
        "aws.cloudtrail.awsRegion": region,
        "aws.cloudtrail.userIdentity.type": "IAMUser",
        "aws.cloudtrail.userIdentity.userName": iamUser,
        "aws.cloudtrail.userIdentity.arn": iamUserArn,
        "aws.cloudtrail.userIdentity.accessKeyId": accessKeyId,
        "aws.cloudtrail.requestParameters.bucketName": bucket,
        "aws.cloudtrail.requestParameters.PublicAccessBlockConfiguration.BlockPublicAcls": "false",
        "aws.cloudtrail.requestParameters.PublicAccessBlockConfiguration.IgnorePublicAcls": "false",
        "aws.cloudtrail.requestParameters.PublicAccessBlockConfiguration.BlockPublicPolicy": "false",
        "aws.cloudtrail.requestParameters.PublicAccessBlockConfiguration.RestrictPublicBuckets": "false",
        "aws.cloudtrail.sourceIPAddress": attackerIp,
        "aws.cloudtrail.userAgent": "aws-cli/2.15.30 Python/3.11.6 Linux/6.5 exe/x86_64",
        "aws.cloudtrail.eventType": "AwsApiCall",
        "aws.cloudtrail.readOnly": "false",
        "aws.cloudtrail.managementEvent": "true",
        "cloud.account.id": awsAccount,
        "cloud.region": region,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 3. CONFIG ORIGIN #2 — PutBucketPolicy attaches an allow-anyone policy
    //    (Principal "*", s3:GetObject on the whole bucket). Now anonymous.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "s3exfil_03_public_policy",
      ts: T(3 * MIN + 40 * SEC),
      source: "cloudtrail",
      vendor: "AWS CloudTrail",
      event_type: "cloud_api_call",
      user_title: "Service Account",
      src_ip: attackerIp,
      severity: "critical",
      mitre_technique: "T1562.007",
      mitre_tactic: "Defense Evasion",
      incident_id: INCIDENT,
      description:
        "PutBucketPolicy on medcore-patient-exports-prod attached a statement with Principal \"*\" allowing s3:GetObject on every object, by the reporting-export-svc key from 91.242.217.35.",
      raw: {
        "aws.cloudtrail.eventName": "PutBucketPolicy",
        "aws.cloudtrail.eventSource": "s3.amazonaws.com",
        "aws.cloudtrail.awsRegion": region,
        "aws.cloudtrail.userIdentity.type": "IAMUser",
        "aws.cloudtrail.userIdentity.userName": iamUser,
        "aws.cloudtrail.userIdentity.arn": iamUserArn,
        "aws.cloudtrail.userIdentity.accessKeyId": accessKeyId,
        "aws.cloudtrail.requestParameters.bucketName": bucket,
        "aws.cloudtrail.requestParameters.bucketPolicy.Statement.0.Effect": "Allow",
        "aws.cloudtrail.requestParameters.bucketPolicy.Statement.0.Principal": "*",
        "aws.cloudtrail.requestParameters.bucketPolicy.Statement.0.Action": "s3:GetObject",
        "aws.cloudtrail.requestParameters.bucketPolicy.Statement.0.Resource": `arn:aws:s3:::${bucket}/*`,
        "aws.cloudtrail.sourceIPAddress": attackerIp,
        "aws.cloudtrail.userAgent": "aws-cli/2.15.30 Python/3.11.6 Linux/6.5 exe/x86_64",
        "aws.cloudtrail.eventType": "AwsApiCall",
        "aws.cloudtrail.readOnly": "false",
        "aws.cloudtrail.managementEvent": "true",
        "cloud.account.id": awsAccount,
        "cloud.region": region,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 4. CONFIG ORIGIN #3 — PutBucketAcl grants the AllUsers group READ, a
    //    second, ACL-level path to the same open state (T1562.007).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "s3exfil_04_public_acl",
      ts: T(4 * MIN),
      source: "cloudtrail",
      vendor: "AWS CloudTrail",
      event_type: "cloud_api_call",
      user_title: "Service Account",
      src_ip: attackerIp,
      severity: "high",
      mitre_technique: "T1562.007",
      mitre_tactic: "Defense Evasion",
      incident_id: INCIDENT,
      description:
        "PutBucketAcl on medcore-patient-exports-prod added a grant giving the AllUsers group (http://acs.amazonaws.com/groups/global/AllUsers) READ, by the reporting-export-svc key from 91.242.217.35.",
      raw: {
        "aws.cloudtrail.eventName": "PutBucketAcl",
        "aws.cloudtrail.eventSource": "s3.amazonaws.com",
        "aws.cloudtrail.awsRegion": region,
        "aws.cloudtrail.userIdentity.type": "IAMUser",
        "aws.cloudtrail.userIdentity.userName": iamUser,
        "aws.cloudtrail.userIdentity.accessKeyId": accessKeyId,
        "aws.cloudtrail.requestParameters.bucketName": bucket,
        "aws.cloudtrail.requestParameters.AccessControlPolicy.AccessControlList.Grant.Grantee.URI":
          "http://acs.amazonaws.com/groups/global/AllUsers",
        "aws.cloudtrail.requestParameters.AccessControlPolicy.AccessControlList.Grant.Permission": "READ",
        "aws.cloudtrail.sourceIPAddress": attackerIp,
        "aws.cloudtrail.userAgent": "aws-cli/2.15.30 Python/3.11.6 Linux/6.5 exe/x86_64",
        "aws.cloudtrail.eventType": "AwsApiCall",
        "aws.cloudtrail.readOnly": "false",
        "aws.cloudtrail.managementEvent": "true",
        "cloud.account.id": awsAccount,
        "cloud.region": region,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 5. GuardDuty — the anonymous-access finding on the policy change. Alert
    //    grade: the bucket now grants access to anyone (T1562.007).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "s3exfil_05_gd_anon_access",
      ts: T(9 * MIN),
      source: "cloudtrail",
      vendor: "AWS GuardDuty",
      event_type: "cloud_api_call",
      src_ip: attackerIp,
      severity: "high",
      mitre_technique: "T1562.007",
      mitre_tactic: "Defense Evasion",
      incident_id: INCIDENT,
      is_detection: true,   // GuardDuty flags the bucket as anonymously accessible
      edr_scope: "non_edr", // cloud control-plane only — no host to walk; investigated in SIEM / cloud
      description:
        "GuardDuty raised Policy:S3/BucketAnonymousAccessGranted (severity 8) on medcore-patient-exports-prod: the bucket's policy now grants access to the AllUsers group after the reporting-export-svc key changed it.",
      raw: {
        "aws.guardduty.type": "Policy:S3/BucketAnonymousAccessGranted",
        "aws.guardduty.severity": "8",
        "aws.guardduty.title": "S3 bucket medcore-patient-exports-prod grants access to the internet through a bucket policy",
        "aws.guardduty.service.action.actionType": "AWS_API_CALL",
        "aws.guardduty.service.action.awsApiCallAction.api": "PutBucketPolicy",
        "aws.guardduty.service.action.awsApiCallAction.serviceName": "s3.amazonaws.com",
        "aws.guardduty.service.action.awsApiCallAction.callerType": "Remote IP",
        "aws.guardduty.service.action.awsApiCallAction.remoteIpDetails.ipAddressV4": attackerIp,
        "aws.guardduty.service.action.awsApiCallAction.remoteIpDetails.organization.asnOrg": "Serverius Holding B.V.",
        "aws.guardduty.resource.resourceType": "S3Bucket",
        "aws.guardduty.resource.s3BucketDetails.name": bucket,
        "aws.guardduty.resource.s3BucketDetails.publicAccess.effectivePermission": "PUBLIC",
        "aws.guardduty.resource.accessKeyDetails.userType": "IAMUser",
        "aws.guardduty.resource.accessKeyDetails.userName": iamUser,
        "aws.guardduty.resource.accessKeyDetails.accessKeyId": accessKeyId,
        "aws.guardduty.service.count": "1",
        "cloud.account.id": awsAccount,
        "cloud.region": region,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 6. THE BLAST RADIUS BEGINS — ListObjectsV2 enumerates the now-open
    //    bucket from the external address (T1619 — Cloud Storage Object
    //    Discovery, not the broader T1580 Cloud Infrastructure Discovery,
    //    since this is specifically object enumeration inside a bucket).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "s3exfil_06_list_objects",
      ts: T(11 * MIN),
      source: "cloudtrail",
      vendor: "AWS CloudTrail",
      event_type: "cloud_api_call",
      user_title: "Service Account",
      src_ip: attackerIp,
      severity: "high",
      mitre_technique: "T1619",
      mitre_tactic: "Discovery",
      incident_id: INCIDENT,
      description:
        "ListObjectsV2 on medcore-patient-exports-prod returned 20,000 keys to the reporting-export-svc key from 91.242.217.35 — a full index of the exports prefix ahead of the download.",
      raw: {
        "aws.cloudtrail.eventName": "ListObjectsV2",
        "aws.cloudtrail.eventSource": "s3.amazonaws.com",
        "aws.cloudtrail.awsRegion": region,
        "aws.cloudtrail.userIdentity.type": "IAMUser",
        "aws.cloudtrail.userIdentity.userName": iamUser,
        "aws.cloudtrail.userIdentity.accessKeyId": accessKeyId,
        "aws.cloudtrail.requestParameters.bucketName": bucket,
        "aws.cloudtrail.requestParameters.prefix": "exports/",
        "aws.cloudtrail.requestParameters.maxKeys": "1000",
        "aws.cloudtrail.additional_event_data.keys_returned": "20000",
        "aws.cloudtrail.sourceIPAddress": attackerIp,
        "aws.cloudtrail.userAgent": "aws-cli/2.15.30 Python/3.11.6 Linux/6.5 exe/x86_64",
        "aws.cloudtrail.eventType": "AwsApiCall",
        "aws.cloudtrail.readOnly": "true",
        "aws.cloudtrail.managementEvent": "false",
        "cloud.account.id": awsAccount,
        "cloud.region": region,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 7. THE DRAIN — a GetObject burst pulls the objects down from outside
    //    AWS. The payoff: regulated data leaving via the S3 REST API (T1530).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "s3exfil_07_getobject_burst",
      ts: T(12 * MIN),
      source: "cloudtrail",
      vendor: "AWS CloudTrail",
      event_type: "cloud_api_call",
      user_title: "Service Account",
      src_ip: attackerIp,
      severity: "critical",
      mitre_technique: "T1530",
      mitre_tactic: "Collection",
      incident_id: INCIDENT,
      description:
        "GetObject repeated across the exports/ prefix on medcore-patient-exports-prod by the reporting-export-svc key from 91.242.217.35 — 20,000 objects, 41 GB returned over eight minutes.",
      raw: {
        "aws.cloudtrail.eventName": "GetObject",
        "aws.cloudtrail.eventSource": "s3.amazonaws.com",
        "aws.cloudtrail.awsRegion": region,
        "aws.cloudtrail.userIdentity.type": "IAMUser",
        "aws.cloudtrail.userIdentity.userName": iamUser,
        "aws.cloudtrail.userIdentity.accessKeyId": accessKeyId,
        "aws.cloudtrail.requestParameters.bucketName": bucket,
        "aws.cloudtrail.requestParameters.key": "exports/2026-08-30/patients-000001.parquet",
        "aws.cloudtrail.additional_event_data.bytes_transferred_out": "44023414784",
        "aws.cloudtrail.additional_event_data.objects_returned": "20000",
        "aws.cloudtrail.additional_event_data.object_sha256": objectSha,
        "aws.cloudtrail.sourceIPAddress": attackerIp,
        "aws.cloudtrail.userAgent": "aws-cli/2.15.30 Python/3.11.6 Linux/6.5 exe/x86_64",
        "aws.cloudtrail.eventType": "AwsApiCall",
        "aws.cloudtrail.readOnly": "true",
        "aws.cloudtrail.managementEvent": "false",
        "cloud.account.id": awsAccount,
        "cloud.region": region,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 8. THE DETECTION — GuardDuty flags the object-read as anomalous data
    //    egress over the S3 API. This is what opens the ticket (T1567).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "s3exfil_08_gd_object_read",
      ts: T(20 * MIN),
      source: "cloudtrail",
      vendor: "AWS GuardDuty",
      event_type: "cloud_api_call",
      src_ip: attackerIp,
      severity: "critical",
      mitre_technique: "T1567",
      mitre_tactic: "Exfiltration",
      incident_id: INCIDENT,
      is_detection: true,   // the object-read finding that opens the incident
      edr_scope: "non_edr", // cloud control-plane only — no host process to walk
      description:
        "GuardDuty raised Exfiltration:S3/ObjectRead.Unusual (severity 8) on medcore-patient-exports-prod: the reporting-export-svc identity read objects at a volume and from a location outside its established pattern, sourced from 91.242.217.35.",
      raw: {
        "aws.guardduty.type": "Exfiltration:S3/ObjectRead.Unusual",
        "aws.guardduty.severity": "8",
        "aws.guardduty.title": "An IAM identity invoked an S3 API to read objects from medcore-patient-exports-prod from a remote host",
        "aws.guardduty.service.action.actionType": "AWS_API_CALL",
        "aws.guardduty.service.action.awsApiCallAction.api": "GetObject",
        "aws.guardduty.service.action.awsApiCallAction.serviceName": "s3.amazonaws.com",
        "aws.guardduty.service.action.awsApiCallAction.callerType": "Remote IP",
        "aws.guardduty.service.action.awsApiCallAction.remoteIpDetails.ipAddressV4": attackerIp,
        "aws.guardduty.service.action.awsApiCallAction.remoteIpDetails.country.countryName": "Netherlands",
        "aws.guardduty.service.action.awsApiCallAction.remoteIpDetails.organization.asnOrg": "Serverius Holding B.V.",
        "aws.guardduty.resource.resourceType": "S3Bucket",
        "aws.guardduty.resource.s3BucketDetails.name": bucket,
        "aws.guardduty.resource.accessKeyDetails.userType": "IAMUser",
        "aws.guardduty.resource.accessKeyDetails.userName": iamUser,
        "aws.guardduty.resource.accessKeyDetails.accessKeyId": accessKeyId,
        "aws.guardduty.service.count": "20000",
        "cloud.account.id": awsAccount,
        "cloud.region": region,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 9. GuardDuty — the anomalous-API-behavior finding on the same key,
    //    tying the enumeration + reads into a single discovery pattern (T1526).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "s3exfil_09_gd_anomalous",
      ts: T(21 * MIN),
      source: "cloudtrail",
      vendor: "AWS GuardDuty",
      event_type: "cloud_api_call",
      src_ip: attackerIp,
      severity: "high",
      mitre_technique: "T1526",
      mitre_tactic: "Discovery",
      incident_id: INCIDENT,
      description:
        "GuardDuty raised Discovery:S3/AnomalousBehavior (severity 6) on the reporting-export-svc key: an S3 API pattern — bucket listing then broad object listing — outside the key's established behaviour, from 91.242.217.35.",
      raw: {
        "aws.guardduty.type": "Discovery:S3/AnomalousBehavior",
        "aws.guardduty.severity": "6",
        "aws.guardduty.title": "An IAM identity invoked S3 APIs to enumerate medcore-patient-exports-prod from a remote host",
        "aws.guardduty.service.action.actionType": "AWS_API_CALL",
        "aws.guardduty.service.action.awsApiCallAction.api": "ListObjectsV2",
        "aws.guardduty.service.action.awsApiCallAction.serviceName": "s3.amazonaws.com",
        "aws.guardduty.service.action.awsApiCallAction.callerType": "Remote IP",
        "aws.guardduty.service.action.awsApiCallAction.remoteIpDetails.ipAddressV4": attackerIp,
        "aws.guardduty.resource.resourceType": "AccessKey",
        "aws.guardduty.resource.accessKeyDetails.userType": "IAMUser",
        "aws.guardduty.resource.accessKeyDetails.userName": iamUser,
        "aws.guardduty.resource.accessKeyDetails.accessKeyId": accessKeyId,
        "aws.guardduty.service.count": "2",
        "cloud.account.id": awsAccount,
        "cloud.region": region,
      },
    },
  ];

  const iocs: IOC[] = [
    {
      type: "ip",
      value: attackerIp, // 91.242.217.35 — the external source of every management write and read
      first_seen: T(0),
      last_seen: T(21 * MIN),
      reputation: "malicious",
      tags: ["external", "internet-source", "leaked-key-use"],
    },
    {
      type: "user",
      value: iamUser, // reporting-export-svc — the over-permissioned, leaked access-key identity
      first_seen: T(0),
      last_seen: T(21 * MIN),
      reputation: "suspicious",
      tags: ["iam-user", "over-permissioned", "leaked-key"],
    },
    {
      type: "sha256",
      value: objectSha, // content hash of a drained export object
      first_seen: T(12 * MIN),
      last_seen: T(12 * MIN),
      reputation: "unknown",
      tags: ["exported-object", "regulated-data"],
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "s3q1",
      xp: 60,
      kind: "single",
      prompt:
        "The GetObject burst (s3exfil_07) and the benign backup read (s3exfil_00) both pull thousands of objects from the same bucket. Reading the two records against each other, what marks s3exfil_07 as the malicious one?",
      hint: "Compare the caller identity and where each request came from — an internet address versus a private path into the account.",
      options: [
        { value: "outside_vs_vpce", label: "s3exfil_07 comes from an internet address on a standalone access key, while s3exfil_00 is the expected role reaching the bucket through a VPC endpoint from a private in-account address" },
        { value: "volume_alone", label: "s3exfil_07 returns more objects, and any GetObject call that touches more than ten thousand keys in one window is malicious purely on the count regardless of the caller" },
        { value: "key_name", label: "s3exfil_07 names a .parquet object under the exports prefix, and reading a data-export file format is what distinguishes theft from an ordinary backup" },
        { value: "region_diff", label: "s3exfil_07 ran in a different AWS region from the backup job, and a region mismatch between two reads of one bucket is the only reliable tell" },
      ],
      answer: "outside_vs_vpce",
      explanation:
        "Volume is a red herring here — the backup job legitimately reads the whole bucket every night, so 'a lot of GetObject' describes both records. The separation is the caller and the path: s3exfil_00 is the medcore-backup-replicator assumed-role session arriving over an S3 VPC endpoint (vpcEndpointId set) from a private 10.x address, entirely inside AWS; s3exfil_07 is a standalone IAMUser access key calling from 91.242.217.35, an internet address. A deploy or backup workload has a predictable in-account origin, so a bucket read from the public internet on a long-lived key is the tell. (b) makes a raw count the verdict, which would flag the nightly backup too. (c) reads the object format as evidence — the backup reads the same files. (d) invents a region mismatch; every call is us-east-1.",
    },
    {
      id: "s3q2",
      xp: 65,
      kind: "single",
      prompt:
        "Before any object was read, three management events (s3exfil_02, s3exfil_03, s3exfil_04) touched the bucket. Which of these was the change that actually let an unauthenticated request reach the objects?",
      hint: "One account-level guard has to be off before a permissive bucket policy or ACL can take effect at all.",
      options: [
        { value: "bpa_off", label: "PutBucketPublicAccessBlock setting all four block flags to false — with Block Public Access on, the permissive policy and ACL that followed would have been overridden and denied" },
        { value: "list_objects", label: "ListObjectsV2 enumerating the exports prefix, because listing the keys is what exposes the objects to an outside caller in the first place" },
        { value: "getobject", label: "The GetObject burst itself, since each individual read re-grants public permission on the object it returns before serving it" },
        { value: "gd_finding", label: "The GuardDuty Policy:S3/BucketAnonymousAccessGranted finding, because raising the finding is the step that switches the bucket into its public state" },
      ],
      answer: "bpa_off",
      explanation:
        "Block Public Access is an account/bucket-level override that sits above policies and ACLs: while it is on, a Principal \"*\" policy or an AllUsers ACL is ignored and public requests are denied. So the enabling change is s3exfil_02, PutBucketPublicAccessBlock flipping all four guards (BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets) to false — only then do the policy (s3exfil_03) and ACL (s3exfil_04) take effect. (b) is a read of the bucket, not a permission change. (c) misreads GetObject — it grants nothing, it consumes the access already opened. (d) inverts cause and effect: GuardDuty reports the state, it does not create it.",
    },
    {
      id: "s3q3",
      xp: 60,
      kind: "single",
      prompt:
        "The reporting-export-svc key is a real service credential that runs jobs in this account every day, so its activity is expected. Which single observation shows this particular run was not that service doing its job?",
      hint: "Look at the sourceIPAddress carried on the management writes and the reads, and compare it with where this key's work normally originates.",
      options: [
        { value: "internet_source", label: "Every management write and every read on the key carries an internet sourceIPAddress rather than the in-account origin the service normally uses — the same remote host GuardDuty keyed both of its findings on" },
        { value: "key_disabled", label: "The access key had already been disabled in IAM, so any call it made proves the credential was being replayed after revocation" },
        { value: "mfa_absent", label: "The calls carried no MFA context, and a service key making S3 calls without an MFA claim is by itself proof of misuse" },
        { value: "root_identity", label: "The calls were made by the account root user rather than the service key, which is never used for automated S3 work" },
      ],
      answer: "internet_source",
      explanation:
        "The identity being legitimate is exactly why the origin is the discriminator. This key's real work runs inside AWS, but here the ListBuckets, the three bucket-config writes, the ListObjectsV2 and the GetObject burst all carry sourceIPAddress 91.242.217.35 — an internet address — and that same remote host is what both GuardDuty findings (s3exfil_08 and s3exfil_09) report on. (b) is false: nothing shows the key was disabled; it was active. (c) over-reads MFA — service keys routinely call without an MFA claim, so its absence is not a verdict. (d) is wrong: userIdentity.type is IAMUser for the reporting-export-svc key throughout, not root.",
    },
    {
      id: "s3q4",
      xp: 55,
      kind: "single",
      prompt:
        "GuardDuty produced two findings on this bucket — Policy:S3/BucketAnonymousAccessGranted and Exfiltration:S3/ObjectRead.Unusual. What does each one tell you about a different stage of the incident?",
      hint: "One finding fires on a configuration change; the other fires on the objects actually being pulled down.",
      options: [
        { value: "config_then_read", label: "The first fires on the config write that opened the store, the second on the records then being drained out — the origin and then the resulting loss, read in that sequence" },
        { value: "same_event", label: "Both findings describe the identical event and GuardDuty simply emitted it twice, so only one of the two needs to be triaged and the other can be closed as a duplicate" },
        { value: "read_first", label: "The object-read finding fires first and causes the anonymous-access finding, because reading objects is what forces AWS to mark the bucket policy as public afterwards" },
        { value: "unrelated", label: "The two findings are on unrelated resources — one on an EC2 instance and one on the bucket — and should be tracked as two separate incidents entirely" },
      ],
      answer: "config_then_read",
      explanation:
        "The two findings map cleanly onto the two halves of the case. Policy:S3/BucketAnonymousAccessGranted (s3exfil_05) fires on the PutBucketPolicy change — the origin, the moment the bucket became reachable by anyone. Exfiltration:S3/ObjectRead.Unusual (s3exfil_08) fires on the GetObject burst — the blast radius, the data actually leaving. Read together they give you both where it began and what was lost. (b) is wrong — they key on different APIs (PutBucketPolicy vs GetObject) at different times. (c) reverses the causal order. (d) is false: both name the same S3 bucket resource and the same access key.",
    },
    {
      id: "s3q5",
      xp: 70,
      kind: "single",
      prompt:
        "You are scoping containment. A leaked IAM access key was used from the internet to open the bucket and read roughly 41 GB of regulated exports. Which response matches the evidence?",
      hint: "Think about the credential still in the attacker's hands, the bucket left in an open state, and the exposure of everything the key could reach — not only the one prefix you watched being read.",
      options: [
        { value: "revoke_close_assess", label: "Disable and rotate the reporting-export-svc key, re-enable Block Public Access and strip the public policy and ACL, then scope the exposure to every object the key could reach and open a data-loss review for the regulated records" },
        { value: "block_ip_only", label: "Block 91.242.217.35 at the edge; because the leaked key was only ever seen from that one address, blocking it fully contains the incident and no credential change is needed" },
        { value: "delete_object", label: "Delete the single patients-000001.parquet object named in the GetObject record, since removing the file that was read closes the exposure and the rest of the bucket was never at risk" },
        { value: "rotate_backup", label: "Rotate the medcore-backup-replicator role that appears in the benign nightly read, as it is the identity that had standing access to the exports bucket all along" },
      ],
      answer: "revoke_close_assess",
      explanation:
        "The credential is still live and the bucket is still open, so containment has to do three things at once: kill the key (disable then rotate reporting-export-svc so the leaked secret stops working), return the bucket to a safe state (re-enable Block Public Access and remove the public policy and ACL from s3exfil_03/04), and scope the loss to everything the key's permissions reach — not just the one object in the log line — while starting the regulated-data review. (b) leaves a working leaked key in play and the bucket public. (c) under-scopes to a single file when 20,000 objects were listed and read. (d) targets the benign backup identity, which did nothing wrong and is not the leaked credential.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "Exposed Bucket — S3 Made Public, Then Emptied",
    threat_actor: "Operator abusing a leaked, over-permissioned IAM access key",
    attack_kind: "cloud_data_exfiltration",
    briefing:
      "GuardDuty raised a high-severity finding: objects in a production S3 bucket were read in bulk from an internet address, and the same bucket was flagged as granting anonymous access. That bucket holds regulated records and is never meant to be reachable publicly. Work out how the bucket became open, which credential drove the changes, and how much data left before you contain it.",
    narrative: `The bucket medcore-patient-exports-prod holds regulated data exports and is meant to be reachable only from inside the account — the nightly backup job reads it over an S3 VPC endpoint, and nothing else should touch it. That backup read is the one legitimate comparison in the data: the medcore-backup-replicator role, an assumed-role session, pulling hundreds of objects from a private 10.x address the night before, with the bucket's protections fully intact.

The incident begins with a credential that should never have left the account. A long-lived IAM access key for the reporting-export-svc service account was leaked and over-permissioned. At 03:00 that key made its first call from 91.242.217.35 — an internet address — a ListBuckets to survey the account. Three minutes later it began stripping the bucket's protections: PutBucketPublicAccessBlock flipped all four Block Public Access guards to false, PutBucketPolicy attached a statement allowing anyone (Principal "*") to read every object, and PutBucketAcl granted the AllUsers group READ. With Block Public Access off, those permissive grants took effect and the bucket was open to the world.

GuardDuty caught the policy change and raised Policy:S3/BucketAnonymousAccessGranted at 03:09. Meanwhile the same key enumerated the bucket with ListObjectsV2 — 20,000 keys under the exports prefix — and from 03:12 ran a GetObject burst that pulled those objects down, 41 GB over eight minutes, every request sourced from 91.242.217.35. At 03:20 GuardDuty raised Exfiltration:S3/ObjectRead.Unusual on the drain, and a minute later Discovery:S3/AnomalousBehavior tied the enumeration and reads together as one out-of-pattern run on the key.

Read as a whole, the case has a clean shape: the CloudTrail management events are the origin — the config change that opened the bucket — and the object reads plus the GuardDuty findings are the blast radius. The constant across every step is the from-outside-AWS source address on a service key whose real work never leaves the account.`,
    learning_objectives: [
      "Separate a malicious bulk S3 read from a legitimate high-volume one using the caller identity and source path (an internet address on a standalone key vs an assumed role over a VPC endpoint), not the object count",
      "Identify the CloudTrail management events (PutBucketPublicAccessBlock, PutBucketPolicy, PutBucketAcl) as the config-change origin, and understand why disabling Block Public Access is the change that lets the others take effect",
      "Use sourceIPAddress and userIdentity to prove a service key was driven from outside the account, and connect that to the GuardDuty anonymous-access and object-read findings",
      "Read GuardDuty S3 findings (BucketAnonymousAccessGranted, ObjectRead.Unusual, AnomalousBehavior) as markers of distinct incident stages rather than duplicates",
      "Scope containment for a leaked cloud access key — revoke and rotate the credential, restore the bucket's protections, and treat everything the key could reach as exposed",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: "2026-08-30T02:15:00.000Z", phase: "Baseline", action: `${backupRole} reads ${bucket} over VPC endpoint from inside AWS — nightly backup (control case)` },
      { ts: T(0), phase: "Initial Access", action: `Leaked ${iamUser} access key first used from ${attackerIp} — ListBuckets (T1078.004)` },
      { ts: T(3 * MIN), phase: "Defense Evasion", action: "PutBucketPublicAccessBlock — all four Block Public Access guards set false (T1562.007)" },
      { ts: T(3 * MIN + 40 * SEC), phase: "Defense Evasion", action: "PutBucketPolicy — Principal \"*\" allowed s3:GetObject on the bucket (T1562.007)" },
      { ts: T(4 * MIN), phase: "Defense Evasion", action: "PutBucketAcl — AllUsers group granted READ (T1562.007)" },
      { ts: T(9 * MIN), phase: "Detection", action: `GuardDuty Policy:S3/BucketAnonymousAccessGranted on ${bucket}` },
      { ts: T(11 * MIN), phase: "Discovery", action: `ListObjectsV2 — 20,000 keys enumerated from ${attackerIp} (T1619)` },
      { ts: T(12 * MIN), phase: "Collection", action: `GetObject burst — 20,000 objects, 41 GB pulled from ${attackerIp} (T1530)` },
      { ts: T(20 * MIN), phase: "Detection", action: "GuardDuty Exfiltration:S3/ObjectRead.Unusual — the drain flagged (T1567)" },
      { ts: T(21 * MIN), phase: "Detection", action: "GuardDuty Discovery:S3/AnomalousBehavior — enumeration + reads correlated on the key (T1526)" },
    ],
    questions,
  };
}
