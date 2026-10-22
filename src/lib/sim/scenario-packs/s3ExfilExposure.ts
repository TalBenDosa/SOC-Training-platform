/**
 * Scenario pack: "Exposed Bucket, S3 Made Public, Then Emptied" (INTERMEDIATE)
 *
 * A cloud data-theft case that never touches an endpoint and lives entirely in
 * AWS CloudTrail and GuardDuty. An operator holding an over-permissioned,
 * leaked IAM access key (a long-lived key that belonged to a reporting service
 * account) weakens a production S3 bucket's protections and then drains it.
 *
 * TEACHING ARC, origin vs. blast radius:
 *   ORIGIN (CloudTrail *management* events): the config-change that made the
 *   theft possible. PutBucketPublicAccessBlock turns off Block Public Access,
 *   PutBucketPolicy attaches an allow-anyone policy, PutBucketAcl grants the
 *   AllUsers group READ. These three writes, driven by an IAMUser access key
 *   from an address OUTSIDE AWS, are where the incident actually begins.
 *
 *   BLAST RADIUS (CloudTrail *data* events + GuardDuty): once the bucket is
 *   reachable, ListObjectsV2 enumerates it and a GetObject burst pulls the
 *   objects down, again from outside AWS. GuardDuty raises the anonymous-access
 *   finding on the policy change and the object-read finding on the drain.
 *
 * THE KEY TELL: the from-outside-AWS sourceIPAddress. A GitHub-runner range, a
 * VPC endpoint, or an AWS service principal is where the deploy/backup traffic
 * normally originates; here every management write and every object read carries
 * an internet source address on an IAMUser access key.
 *
 * BENIGN CONTROL (s3exfil_00): the night before, the real backup/data-pipeline
 * role reads the SAME bucket at high volume, GetObject after GetObject, but from
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
import { cloudTrailEvent, guardDutyFinding } from "@/lib/sim/emitters/cloudtrail";
import { githubAudit } from "@/lib/sim/emitters/github";
import { awsCloudWatchAlarm } from "./awsCloudWatchAlarm";

export function buildS3ExfilExposureScenario(
  scenarioId = "s3-exfil-exposure-2026",
): ScenarioBundle {
  const B = new Date("2026-08-31T03:00:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const SEC = 1_000;

  // One incident, the whole chain is a single bucket-exposure case.
  const INCIDENT = "inc:s3exfil:1";

  // The account and the bucket that holds regulated data.
  const awsAccount = "612498330517";
  const region = "us-east-1";
  const bucket = "medcore-patient-exports-prod";

  // The abused credential: a long-lived IAM access key for a reporting service
  // account, over-permissioned and leaked. Every attacker action rides it.
  const iamUser = "reporting-export-svc";
  const accessKeyId = "AKIA4MC2X7QF9EXAMPLE";
  const iamUserArn = `arn:aws:iam::${awsAccount}:user/${iamUser}`;
  // The operator's external address, outside AWS, the whole tell.
  const attackerIp = "91.242.217.35";

  // The benign control: the real backup / data-pipeline role reading the same
  // bucket the expected way, an assumed-role session, from inside AWS over an
  // S3 VPC endpoint, with no public-access change.
  const backupRole = "medcore-backup-replicator";
  const backupAssumedArn = `arn:aws:sts::${awsAccount}:assumed-role/${backupRole}/backup-2026-08-30`;
  const backupPrivateIp = "10.0.42.17";
  const vpcEndpointId = "vpce-0a1b2c3d4e5f6a7b8";

  const cx = "medcore" as const;
  const awsCli = "aws-cli/2.15.30 Python/3.11.6 Linux/6.5 exe/x86_64";
  // The second internet address that uses the opened bucket without any credential.
  const anonIp = "45.155.205.233";

  // An unauthenticated S3 request: CloudTrail records userIdentity.accountId "anonymous" and no user, ARN or key.
  const asAnonymous = (e: TelemetryEvent): TelemetryEvent => {
    const raw = Object.assign({}, e.raw);
    for (const k of ["aws.cloudtrail.userIdentity.userName", "aws.cloudtrail.userIdentity.arn", "aws.cloudtrail.userIdentity.accessKeyId"]) delete raw[k];
    raw["aws.cloudtrail.userIdentity.type"] = "AWSAccount";
    raw["aws.cloudtrail.userIdentity.accountId"] = "anonymous";
    raw["aws.cloudtrail.userIdentity.arn"] = "anonymous";
    return { ...e, raw, user_title: undefined };
  };
  // One GetObject by the leaked key (a representative record of the burst: one object, a realistic size).
  const keyGet = (id: string, at: number, key: string, bytes: number, description: string): TelemetryEvent => cloudTrailEvent({
    companyId: cx, id, ts: T(at), eventName: "GetObject", srcIp: attackerIp, region, accountId: awsAccount,
    actorType: "IAMUser", actorName: iamUser, arn: iamUserArn, accessKeyId, s3Bucket: bucket, s3Key: key, bytes,
    readOnly: true, managementEvent: false, awsEventType: "AwsApiCall", userAgent: awsCli, userTitle: "Service Account",
    mitre: "T1530", tactic: "Collection", severity: "high", incidentId: INCIDENT, description,
  });
  // One GetObject by the nightly backup role: same session, same prefix, its usual size.
  const backupGet = (id: string, ts: string, key: string, description?: string): TelemetryEvent => cloudTrailEvent({
    companyId: cx, id, ts, eventName: "GetObject",
    srcIp: backupPrivateIp, region, accountId: awsAccount, actorType: "AssumedRole", sessionIssuerName: backupRole, arn: backupAssumedArn,
    s3Bucket: bucket, s3Key: key, bytes: 10_485_760, readOnly: true, managementEvent: false,
    userAgent: "aws-sdk-java/2.25.11 Linux/5.15 vendor/Amazon.com", userTitle: "Automated Service", severity: "informational",
    extra: { "aws.cloudtrail.vpcEndpointId": vpcEndpointId },
    description: description ?? `GetObject on ${bucket} by the ${backupRole} role over VPC endpoint ${vpcEndpointId}, from the private address ${backupPrivateIp}.`,
  });

  const events: TelemetryEvent[] = [
    // 0. BENIGN CONTROL, the sanctioned high-volume read (backup role, VPC endpoint): three consecutive objects.
    {
      ...backupGet("s3exfil_00_benign_backup", "2026-08-30T02:15:00.000Z", "exports/2026-08-29/patients-000417.parquet",
        "GetObject at volume on medcore-patient-exports-prod by the medcore-backup-replicator role over VPC endpoint vpce-0a1b2c3d4e5f6a7b8, sourced from the private address 10.0.42.17, the nightly replication job."),
      expected_verdict: "fp",
      fp_explanation: "This is the control the whole scenario is measured against. The SAME bucket is read at high volume, a nightly job pulling its export objects one after another, but every difference that matters points the other way: the caller is the expected medcore-backup-replicator assumed-role session (not a standalone access key), the traffic originates INSIDE AWS over an S3 VPC endpoint (vpcEndpointId set, a private 10.x source address), and nothing anywhere near it touched the bucket's public-access settings. An analyst who alerts on 'a lot of GetObject on the exports bucket' will flag this and be wrong, the read volume is normal for backup; what makes the later activity an incident is where it came from and what preceded it.",
    },
    backupGet("s3exfil_00b_benign_backup", "2026-08-30T02:15:02.000Z", "exports/2026-08-29/patients-000418.parquet"),
    backupGet("s3exfil_00c_benign_backup", "2026-08-30T02:15:05.000Z", "exports/2026-08-29/patients-000419.parquet"),

    // 0d. WHERE THE KEY LEAKED, a public repository commit trips GitHub secret scanning two days earlier.
    githubAudit({
      companyId: cx, id: "s3exfil_00d_secret_scanning", ts: "2026-08-28T11:42:00.000Z", action: "secret_scanning_alert.create", actor: "github-secret-scanning",
      org: "medcore", repo: "medcore/reporting-tools", visibility: "public", category: "configuration", eventType: "cloud_api_call", severity: "high",
      incidentId: INCIDENT, mitre: "T1552.001", tactic: "Credential Access",
      extra: { "github.secret_type": "aws_access_key_id", "github.alert_number": 7 },
      description: "GitHub secret scanning opened an alert on the public repository medcore/reporting-tools: a committed AWS access key ID.",
    }),

    // 1. FIRST USE OF THE LEAKED KEY, GetCallerIdentity from an external address (the usual first call), then ListBuckets (T1078.004).
    cloudTrailEvent({
      companyId: cx, id: "s3exfil_00e_get_caller_identity", ts: T(-90 * SEC), eventName: "GetCallerIdentity", eventSource: "sts.amazonaws.com", srcIp: attackerIp, region, accountId: awsAccount,
      actorType: "IAMUser", actorName: iamUser, arn: iamUserArn, accessKeyId, readOnly: true, managementEvent: true, userAgent: awsCli,
      userTitle: "Service Account", mitre: "T1078.004", tactic: "Initial Access", severity: "medium", incidentId: INCIDENT,
      description: "GetCallerIdentity by the reporting-export-svc access key AKIA4MC2X7QF9EXAMPLE from 91.242.217.35, a check of what the key is.",
    }),
    cloudTrailEvent({
      companyId: cx, id: "s3exfil_01_list_buckets", ts: T(0), eventName: "ListBuckets", srcIp: attackerIp, region, accountId: awsAccount,
      actorType: "IAMUser", actorName: iamUser, arn: iamUserArn, accessKeyId, readOnly: true, managementEvent: true, userAgent: awsCli,
      userTitle: "Service Account", mitre: "T1078.004", tactic: "Initial Access", severity: "high", incidentId: INCIDENT,
      description: "ListBuckets on account 612498330517 by the reporting-export-svc access key AKIA4MC2X7QF9EXAMPLE from 91.242.217.35, the first call this long-lived key has made from an internet address.",
    }),

    // 2. CONFIG ORIGIN #1, PutBucketPublicAccessBlock turns OFF Block Public Access (T1686.001).
    cloudTrailEvent({
      companyId: cx, id: "s3exfil_02_disable_bpa", ts: T(3 * MIN), eventName: "PutBucketPublicAccessBlock", srcIp: attackerIp, region, accountId: awsAccount,
      actorType: "IAMUser", actorName: iamUser, arn: iamUserArn, accessKeyId, s3Bucket: bucket, readOnly: false, managementEvent: true, userAgent: awsCli,
      userTitle: "Service Account", mitre: "T1686.001", tactic: "Defense Impairment", severity: "critical", incidentId: INCIDENT,
      extra: {
        "aws.cloudtrail.requestParameters.PublicAccessBlockConfiguration.BlockPublicAcls": "false",
        "aws.cloudtrail.requestParameters.PublicAccessBlockConfiguration.IgnorePublicAcls": "false",
        "aws.cloudtrail.requestParameters.PublicAccessBlockConfiguration.BlockPublicPolicy": "false",
        "aws.cloudtrail.requestParameters.PublicAccessBlockConfiguration.RestrictPublicBuckets": "false",
      },
      description: "PutBucketPublicAccessBlock on medcore-patient-exports-prod set all four BlockPublicAcls / IgnorePublicAcls / BlockPublicPolicy / RestrictPublicBuckets flags to false, by the reporting-export-svc key from 91.242.217.35.",
    }),

    // 3. CONFIG ORIGIN #2, PutBucketPolicy attaches an allow-anyone policy (T1686.001).
    cloudTrailEvent({
      companyId: cx, id: "s3exfil_03_public_policy", ts: T(3 * MIN + 40 * SEC), eventName: "PutBucketPolicy", srcIp: attackerIp, region, accountId: awsAccount,
      actorType: "IAMUser", actorName: iamUser, arn: iamUserArn, accessKeyId, s3Bucket: bucket, readOnly: false, managementEvent: true, userAgent: awsCli,
      userTitle: "Service Account", mitre: "T1686.001", tactic: "Defense Impairment", severity: "critical", incidentId: INCIDENT,
      extra: {
        "aws.cloudtrail.requestParameters.bucketPolicy.Statement.0.Effect": "Allow",
        "aws.cloudtrail.requestParameters.bucketPolicy.Statement.0.Principal": "*",
        "aws.cloudtrail.requestParameters.bucketPolicy.Statement.0.Action": "s3:GetObject",
        "aws.cloudtrail.requestParameters.bucketPolicy.Statement.0.Resource": `arn:aws:s3:::${bucket}/*`,
      },
      description: "PutBucketPolicy on medcore-patient-exports-prod attached a statement with Principal \"*\" allowing s3:GetObject on every object, by the reporting-export-svc key from 91.242.217.35.",
    }),

    // 4. CONFIG ORIGIN #3, PutBucketAcl grants the AllUsers group READ (T1686.001).
    cloudTrailEvent({
      companyId: cx, id: "s3exfil_04_public_acl", ts: T(4 * MIN), eventName: "PutBucketAcl", srcIp: attackerIp, region, accountId: awsAccount,
      actorType: "IAMUser", actorName: iamUser, arn: iamUserArn, accessKeyId, s3Bucket: bucket, readOnly: false, managementEvent: true, userAgent: awsCli,
      userTitle: "Service Account", mitre: "T1686.001", tactic: "Defense Impairment", severity: "high", incidentId: INCIDENT,
      extra: {
        "aws.cloudtrail.requestParameters.AccessControlPolicy.AccessControlList.Grant.Grantee.URI": "http://acs.amazonaws.com/groups/global/AllUsers",
        "aws.cloudtrail.requestParameters.AccessControlPolicy.AccessControlList.Grant.Permission": "READ",
      },
      description: "PutBucketAcl on medcore-patient-exports-prod added a grant giving the AllUsers group (http://acs.amazonaws.com/groups/global/AllUsers) READ, by the reporting-export-svc key from 91.242.217.35.",
    }),

    // 4b. THE OPENING IS USED, an unauthenticated GetObject from a second internet address (T1530).
    asAnonymous(cloudTrailEvent({
      companyId: cx, id: "s3exfil_04b_anonymous_get", ts: T(7 * MIN + 10 * SEC), eventName: "GetObject", srcIp: anonIp, region, accountId: awsAccount,
      actorType: "AWSService", s3Bucket: bucket, s3Key: "exports/2026-08-30/patients-000002.parquet", bytes: 2_201_170,
      readOnly: true, managementEvent: false, awsEventType: "AwsApiCall", userAgent: "curl/8.4.0", severity: "high",
      mitre: "T1530", tactic: "Collection", incidentId: INCIDENT,
      description: "An unauthenticated GetObject (userIdentity accountId anonymous) on medcore-patient-exports-prod from 45.155.205.233: the bucket answered a request carrying no credential.",
    })),

    // 5. GuardDuty, the anonymous-access finding on the policy change, and the BPA finding.
    {
      ...guardDutyFinding({
        companyId: cx, id: "s3exfil_05_gd_anon_access", ts: T(9 * MIN), findingType: "Policy:S3/BucketAnonymousAccessGranted", gdSeverity: 8,
        title: "S3 bucket medcore-patient-exports-prod grants access to the internet through a bucket policy", srcIp: attackerIp, region, accountId: awsAccount,
        api: "PutBucketPolicy", serviceName: "s3.amazonaws.com", callerType: "Remote IP", asnOrg: "Serverius Holding B.V.",
        resourceType: "S3Bucket", bucketName: bucket, effectivePermission: "PUBLIC", userType: "IAMUser", userName: iamUser, accessKeyId, count: 1,
        mitre: "T1686.001", tactic: "Defense Impairment", severity: "high", incidentId: INCIDENT,
        description: "GuardDuty raised Policy:S3/BucketAnonymousAccessGranted (severity 8) on medcore-patient-exports-prod: the bucket's policy now grants access to the AllUsers group after the reporting-export-svc key changed it.",
      }),
      edr_scope: "non_edr",
    },
    {
      ...guardDutyFinding({
        companyId: cx, id: "s3exfil_05b_gd_bpa_disabled", ts: T(8 * MIN), findingType: "Policy:S3/BucketBlockPublicAccessDisabled", gdSeverity: 2,
        title: "Amazon S3 Block Public Access was disabled for medcore-patient-exports-prod", srcIp: attackerIp, region, accountId: awsAccount,
        api: "PutBucketPublicAccessBlock", serviceName: "s3.amazonaws.com", callerType: "Remote IP", asnOrg: "Serverius Holding B.V.",
        resourceType: "S3Bucket", bucketName: bucket, userType: "IAMUser", userName: iamUser, accessKeyId, count: 1,
        mitre: "T1686.001", tactic: "Defense Impairment", severity: "low", incidentId: INCIDENT,
        description: "GuardDuty raised Policy:S3/BucketBlockPublicAccessDisabled (severity 2) after Block Public Access was turned off on the bucket.",
      }),
      edr_scope: "non_edr",
    },

    // 6. THE BLAST RADIUS BEGINS, ListObjectsV2 enumerates the now-open bucket in pages of up to 1,000 keys (T1619).
    cloudTrailEvent({
      companyId: cx, id: "s3exfil_06_list_objects", ts: T(11 * MIN), eventName: "ListObjectsV2", srcIp: attackerIp, region, accountId: awsAccount,
      actorType: "IAMUser", actorName: iamUser, arn: iamUserArn, accessKeyId, s3Bucket: bucket, readOnly: true, managementEvent: false, userAgent: awsCli,
      userTitle: "Service Account", mitre: "T1619", tactic: "Discovery", severity: "high", incidentId: INCIDENT,
      extra: { "aws.cloudtrail.requestParameters.prefix": "exports/", "aws.cloudtrail.requestParameters.maxKeys": "1000" },
      description: "ListObjectsV2 on medcore-patient-exports-prod over the exports/ prefix by the reporting-export-svc key from 91.242.217.35, the first page of the index.",
    }),
    cloudTrailEvent({
      companyId: cx, id: "s3exfil_06b_list_objects_page2", ts: T(11 * MIN + 20 * SEC), eventName: "ListObjectsV2", srcIp: attackerIp, region, accountId: awsAccount,
      actorType: "IAMUser", actorName: iamUser, arn: iamUserArn, accessKeyId, s3Bucket: bucket, readOnly: true, managementEvent: false, userAgent: awsCli,
      userTitle: "Service Account", mitre: "T1619", tactic: "Discovery", severity: "high", incidentId: INCIDENT,
      extra: { "aws.cloudtrail.requestParameters.prefix": "exports/", "aws.cloudtrail.requestParameters.maxKeys": "1000", "aws.cloudtrail.requestParameters.continuation-token": "1Ahp7wFQTh8eNjoGRXH7vGGZbNAQ" },
      description: "The next page of the same listing, continued with a continuation token.",
    }),
    cloudTrailEvent({
      companyId: cx, id: "s3exfil_06c_list_objects_page3", ts: T(11 * MIN + 40 * SEC), eventName: "ListObjectsV2", srcIp: attackerIp, region, accountId: awsAccount,
      actorType: "IAMUser", actorName: iamUser, arn: iamUserArn, accessKeyId, s3Bucket: bucket, readOnly: true, managementEvent: false, userAgent: awsCli,
      userTitle: "Service Account", mitre: "T1619", tactic: "Discovery", severity: "high", incidentId: INCIDENT,
      extra: { "aws.cloudtrail.requestParameters.prefix": "exports/", "aws.cloudtrail.requestParameters.maxKeys": "1000", "aws.cloudtrail.requestParameters.continuation-token": "1Zk3Qm9aPd2uYtB6sXc0LVwH8eRn" },
      description: "A further page of the listing, again with a continuation token.",
    }),

    // 7. THE DRAIN, GetObject calls pull the objects down from outside AWS (T1530); the volume is in the metric and GuardDuty.
    keyGet("s3exfil_07_getobject_burst", 12 * MIN, "exports/2026-08-30/patients-000001.parquet", 2_201_170,
      "One of the GetObject calls across the exports/ prefix on medcore-patient-exports-prod by the reporting-export-svc key from 91.242.217.35."),
    keyGet("s3exfil_07b_getobject", 12 * MIN + 1 * SEC, "exports/2026-08-30/patients-000003.parquet", 2_198_342,
      "The next GetObject, one second later, on the next object of the same prefix."),
    keyGet("s3exfil_07c_getobject", 12 * MIN + 2 * SEC, "exports/2026-08-30/patients-000004.parquet", 2_204_911,
      "And the next, one second after that."),

    // 8. THE DETECTION, GuardDuty flags the object-read as anomalous egress (T1567); CloudWatch's bytes metric agrees.
    {
      ...guardDutyFinding({
        companyId: cx, id: "s3exfil_08_gd_object_read", ts: T(20 * MIN), findingType: "Exfiltration:S3/ObjectRead.Unusual", gdSeverity: 8,
        title: "An IAM identity invoked an S3 API to read objects from medcore-patient-exports-prod from a remote host", srcIp: attackerIp, region, accountId: awsAccount,
        api: "GetObject", serviceName: "s3.amazonaws.com", callerType: "Remote IP", remoteCountry: "Netherlands", asnOrg: "Serverius Holding B.V.",
        resourceType: "S3Bucket", bucketName: bucket, userType: "IAMUser", userName: iamUser, accessKeyId, count: 20000,
        mitre: "T1567", tactic: "Exfiltration", severity: "high", incidentId: INCIDENT,
        description: "GuardDuty raised Exfiltration:S3/ObjectRead.Unusual (severity 8) on medcore-patient-exports-prod: the reporting-export-svc identity read objects at a volume and from a location outside its established pattern, sourced from 91.242.217.35.",
      }),
      edr_scope: "non_edr",
    },
    awsCloudWatchAlarm({
      id: "s3exfil_08b_cloudwatch_bytes", ts: T(20 * MIN + 30 * SEC), accountId: awsAccount, region, incidentId: INCIDENT,
      alarmName: "S3-BytesDownloaded-medcore-patient-exports-prod", metric: "BytesDownloaded", threshold: 5_000_000_000, actualValue: 44_023_414_784,
      description: "The CloudWatch alarm on the bucket's BytesDownloaded request metric entered ALARM: 44,023,414,784 bytes in the evaluation window against a threshold of 5,000,000,000.",
    }),

    // 9. GuardDuty, the anomalous-API-behavior finding on the same key (T1526).
    guardDutyFinding({
      companyId: cx, id: "s3exfil_09_gd_anomalous", ts: T(21 * MIN), findingType: "Discovery:S3/AnomalousBehavior", gdSeverity: 6,
      title: "An IAM identity invoked S3 APIs to enumerate medcore-patient-exports-prod from a remote host", srcIp: attackerIp, region, accountId: awsAccount,
      api: "ListObjectsV2", serviceName: "s3.amazonaws.com", callerType: "Remote IP", resourceType: "AccessKey",
      userType: "IAMUser", userName: iamUser, accessKeyId, count: 20,
      mitre: "T1526", tactic: "Discovery", severity: "medium", incidentId: INCIDENT,
      description: "GuardDuty raised Discovery:S3/AnomalousBehavior (severity 6) on the reporting-export-svc key: an S3 API pattern, bucket listing then broad object listing, outside the key's established behaviour, from 91.242.217.35.",
    }),
  ];

  // Declared in the order the records happened, whichever product wrote them.
  events.sort((a, b) => a.ts.localeCompare(b.ts));

  const iocs: IOC[] = [
    {
      type: "ip",
      value: attackerIp, // 91.242.217.35, the external source of every management write and key-driven read
      first_seen: T(-90 * SEC),
      last_seen: T(21 * MIN),
      reputation: "malicious",
      tags: ["external", "internet-source", "leaked-key-use"],
    },
    {
      type: "ip",
      value: anonIp, // 45.155.205.233, reads the opened bucket without any credential
      first_seen: T(7 * MIN + 10 * SEC),
      last_seen: T(7 * MIN + 10 * SEC),
      reputation: "malicious",
      tags: ["external", "anonymous-access"],
    },
    {
      type: "user",
      value: iamUser, // reporting-export-svc, the over-permissioned, leaked access-key identity
      first_seen: T(-90 * SEC),
      last_seen: T(21 * MIN),
      reputation: "suspicious",
      tags: ["iam-user", "over-permissioned", "leaked-key"],
    },
    {
      type: "user",
      value: accessKeyId, // AKIA4MC2X7QF9EXAMPLE, the leaked access key id
      first_seen: "2026-08-28T11:42:00Z",
      last_seen: T(21 * MIN),
      reputation: "malicious",
      tags: ["access-key", "public-repository-leak"],
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "s3q1",
      xp: 60,
      kind: "single",
      prompt:
        "The GetObject burst (s3exfil_07) and the benign backup read (s3exfil_00) both pull many objects from the same bucket, one GetObject after another. Reading the two records against each other, what marks s3exfil_07 as the malicious one?",
      hint: "Compare the caller identity and where each request came from, an internet address versus a private path into the account.",
      options: [
        { value: "outside_vs_vpce", label: "s3exfil_07 is a standalone access key calling from an internet address, while s3exfil_00 is the expected role reaching the bucket through a VPC endpoint from a private in-account address" },
        { value: "volume_alone", label: "s3exfil_07 returns far more objects in a shorter window than the nightly job, and a read of that size against a regulated bucket is enough on its own to call it exfiltration, whoever the caller is" },
        { value: "key_name", label: "s3exfil_07 requests .parquet files under exports/, and pulling a data-export file format rather than backup snapshots is what separates theft from the replication job's reads" },
        { value: "region_diff", label: "s3exfil_07 was served from a different AWS region than the replication job, and a region mismatch between two reads of the same bucket is the clearest sign an unapproved second party is involved" },
      ],
      answer: "outside_vs_vpce",
      explanation:
        "Volume is a red herring here, the backup job legitimately reads the whole bucket every night, so 'a lot of GetObject' describes both records. The separation is the caller and the path: s3exfil_00 is the medcore-backup-replicator assumed-role session arriving over an S3 VPC endpoint (vpcEndpointId set) from a private 10.x address, entirely inside AWS; s3exfil_07 is a standalone IAMUser access key calling from 91.242.217.35, an internet address. A deploy or backup workload has a predictable in-account origin, so a bucket read from the public internet on a long-lived key is the tell. (b) makes a raw count the verdict, which would flag the nightly backup too. (c) reads the object format as evidence, the backup reads the same files. (d) invents a region mismatch; every call is us-east-1. The totals do not live in a single CloudTrail record: each GetObject is one object, and the volume is carried by the CloudWatch BytesDownloaded alarm (44 GB) and the GuardDuty finding count (20,000 objects).",
    },
    {
      id: "s3q2",
      xp: 65,
      kind: "single",
      prompt:
        "Before any object was read, three management events (s3exfil_02, s3exfil_03, s3exfil_04) touched the bucket. Which of these was the change that actually let an unauthenticated request reach the objects?",
      hint: "One account-level guard has to be off before a permissive bucket policy or ACL can take effect at all.",
      options: [
        { value: "bpa_off", label: "PutBucketPublicAccessBlock setting all four block flags to false, while Block Public Access was on, the permissive policy and ACL that followed would have been overridden" },
        { value: "list_objects", label: "ListObjectsV2 enumerating the exports/ prefix, because returning the 20,000 key names to the caller is the step that publishes each object's location and makes it fetchable from outside" },
        { value: "getobject", label: "The GetObject burst itself, since S3 evaluates each anonymous read by re-granting public permission on the object it serves, so the reads are what actually switched the exposure on" },
        { value: "gd_finding", label: "The GuardDuty Policy:S3/BucketAnonymousAccessGranted finding, because GuardDuty applies the PUBLIC effective permission it reports, and that switch is what let outside requests in" },
      ],
      answer: "bpa_off",
      explanation:
        "Block Public Access is an account/bucket-level override that sits above policies and ACLs: while it is on, a Principal \"*\" policy or an AllUsers ACL is ignored and public requests are denied. So the enabling change is s3exfil_02, PutBucketPublicAccessBlock flipping all four guards (BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets) to false, only then do the policy (s3exfil_03) and ACL (s3exfil_04) take effect. The unauthenticated GetObject in s3exfil_04b (accountId anonymous, a second internet address) is the proof: once Block Public Access was off, the bucket answered a request carrying no credential at all. (b) is a read of the bucket, not a permission change. (c) misreads GetObject, it grants nothing, it consumes the access already opened. (d) inverts cause and effect: GuardDuty reports the state, it does not create it.",
    },
    {
      id: "s3q3",
      xp: 60,
      kind: "single",
      prompt:
        "The reporting-export-svc key is a real service credential that runs jobs in this account every day, so its activity is expected. Which single observation shows this particular run was not that service doing its job?",
      hint: "Look at the sourceIPAddress carried on the management writes and the reads, and compare it with where this key's work normally originates.",
      options: [
        { value: "internet_source", label: "Every write and read on the key carries an internet sourceIPAddress instead of the service's usual in-account origin, the same remote host both GuardDuty findings were raised on" },
        { value: "key_disabled", label: "The access key had already been deactivated in IAM before these calls, so every request it made in this window proves the credential was being replayed by someone after revocation" },
        { value: "mfa_absent", label: "The calls carried no MFA context in their session attributes, and a service key making bucket-configuration writes without an MFA claim is by itself proof the key was misused" },
        { value: "root_identity", label: "The bucket-configuration writes were made by the account root user rather than the service key, and root is not used for automated S3 work, so the service could not have done this" },
      ],
      answer: "internet_source",
      explanation:
        "The identity being legitimate is exactly why the origin is the discriminator. This key's real work runs inside AWS, but here the GetCallerIdentity, the ListBuckets, the three bucket-config writes, the ListObjectsV2 pages and the key-driven GetObject calls all carry sourceIPAddress 91.242.217.35, an internet address, and that same remote host is what the GuardDuty findings (s3exfil_08 and s3exfil_09) report on. The only other address is the one that read the opened bucket anonymously, and it never used the key. (b) is false: nothing shows the key was disabled; it was active. (c) over-reads MFA, service keys routinely call without an MFA claim, so its absence is not a verdict. (d) is wrong: userIdentity.type is IAMUser for the reporting-export-svc key throughout, not root.",
    },
    {
      id: "s3q4",
      xp: 55,
      kind: "single",
      prompt:
        "GuardDuty produced two findings on this bucket, Policy:S3/BucketAnonymousAccessGranted and Exfiltration:S3/ObjectRead.Unusual. What does each one tell you about a different stage of the incident?",
      hint: "One finding fires on a configuration change; the other fires on the objects actually being pulled down.",
      options: [
        { value: "config_then_read", label: "The first fires on the config write that opened the store, the second on the records then being drained out, the origin, then the resulting loss" },
        { value: "same_event", label: "Both findings describe the identical event and GuardDuty simply emitted it twice, so only one of the two needs to be triaged and the other can be closed as a duplicate" },
        { value: "read_first", label: "The object-read finding fires first and causes the anonymous-access finding, because reading objects is what forces AWS to mark the bucket policy as public afterwards" },
        { value: "unrelated", label: "The two findings are on unrelated resources, one on an EC2 instance profile and one on the bucket, so they should be tracked and escalated as two separate incidents" },
      ],
      answer: "config_then_read",
      explanation:
        "The two findings map cleanly onto the two halves of the case. Policy:S3/BucketAnonymousAccessGranted (s3exfil_05) fires on the PutBucketPolicy change, the origin, the moment the bucket became reachable by anyone. Exfiltration:S3/ObjectRead.Unusual (s3exfil_08) fires on the GetObject burst, the blast radius, the data actually leaving. Read together they give you both where it began and what was lost. (b) is wrong, they key on different APIs (PutBucketPolicy vs GetObject) at different times. (c) reverses the causal order. (d) is false: both name the same S3 bucket resource and the same access key.",
    },
    {
      id: "s3q5",
      xp: 70,
      kind: "single",
      prompt:
        "You are scoping containment. A leaked IAM access key was used from the internet to open the bucket and read roughly 41 GB of regulated exports. Which response matches the evidence?",
      hint: "Think about the credential still in the attacker's hands, the bucket left in an open state, and the exposure of everything the key could reach, not only the one prefix you watched being read.",
      options: [
        { value: "revoke_close_assess", label: "Disable and rotate the reporting-export-svc key, restore Block Public Access and remove the public policy and ACL, then treat everything the key could reach as exposed and open a data-loss review" },
        { value: "block_ip_only", label: "Block 91.242.217.35 at the perimeter and in the bucket policy; since the leaked key was only ever seen from that one address, cutting it off contains the incident without a credential change" },
        { value: "delete_object", label: "Delete the patients-000001.parquet object named in the GetObject record and restore it from backup, since the file shown in the log is the exposed item and the rest of the bucket was not read" },
        { value: "rotate_backup", label: "Rotate the medcore-backup-replicator role credentials and review its VPC endpoint policy, since that role holds standing access to the exports bucket and is the likelier source of the leak" },
      ],
      answer: "revoke_close_assess",
      explanation:
        "The credential is still live and the bucket is still open, so containment has to do three things at once: kill the key (disable then rotate reporting-export-svc so the leaked secret stops working), return the bucket to a safe state (re-enable Block Public Access and remove the public policy and ACL from s3exfil_03/04), and scope the loss to everything the key's permissions reach, not just the one object in the log line, while starting the regulated-data review. (b) leaves a working leaked key in play and the bucket public. (c) under-scopes to a single file when 20,000 objects were listed and read. (d) targets the benign backup identity, which did nothing wrong and is not the leaked credential.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "GuardDuty finding on MedCore's patient exports bucket",
    threat_actor: "Operator abusing a leaked, over-permissioned IAM access key",
    attack_kind: "cloud_data_exfiltration",
    briefing:
      "GuardDuty raised a High finding on medcore-patient-exports-prod, a production bucket of regulated records that is never meant to be reachable publicly. Work out how it was exposed, which credential was involved and how much left.",
    narrative: `The bucket medcore-patient-exports-prod holds regulated data exports and is meant to be reachable only from inside the account, the nightly backup job reads it over an S3 VPC endpoint, and nothing else should touch it. That backup read is the one legitimate comparison in the data: the medcore-backup-replicator role, an assumed-role session, pulling its export objects one after another from a private 10.x address the night before, with the bucket's protections fully intact.

The incident begins with a credential that should never have left the account. A long-lived IAM access key for the reporting-export-svc service account was committed to a public repository, medcore/reporting-tools, on 28 August, and GitHub secret scanning raised an alert at 11:42; the key was over-permissioned and was never rotated. On 31 August at 02:58 that key made its first calls from 91.242.217.35, an internet address: a GetCallerIdentity to check what it was, and at 03:00 a ListBuckets to survey the account. Three minutes later it began stripping the bucket's protections: PutBucketPublicAccessBlock flipped all four Block Public Access guards to false, PutBucketPolicy attached a statement allowing anyone (Principal "*") to read every object, and PutBucketAcl granted the AllUsers group READ. With Block Public Access off, those permissive grants took effect and the bucket was open to the world. It was used at once: at 03:07 a GetObject with accountId anonymous, from a second address (45.155.205.233) and no credential at all, was answered.

GuardDuty caught the changes (Policy:S3/BucketBlockPublicAccessDisabled at 03:08 and Policy:S3/BucketAnonymousAccessGranted at 03:09). Meanwhile the same key enumerated the bucket with ListObjectsV2, page after page of up to 1,000 keys under the exports prefix, and from 03:12 ran GetObject calls that pulled those objects down, every request sourced from 91.242.217.35. One CloudTrail record carries one object; the scale is in the aggregates: GuardDuty counted 20,000 object reads and the CloudWatch BytesDownloaded alarm on the bucket reached 44,023,414,784 bytes (41 GB) by 03:20. At 03:20 GuardDuty raised Exfiltration:S3/ObjectRead.Unusual on the drain, and a minute later Discovery:S3/AnomalousBehavior tied the enumeration and reads together as one out-of-pattern run on the key.

Read as a whole, the case has a clean shape: the CloudTrail management events are the origin, the config change that opened the bucket, and the object reads plus the GuardDuty findings are the blast radius. The constant across every step is the from-outside-AWS source address on a service key whose real work never leaves the account.`,
    learning_objectives: [
      "Separate a malicious bulk S3 read from a legitimate high-volume one using the caller identity and source path (an internet address on a standalone key vs an assumed role over a VPC endpoint), not the object count",
      "Identify the CloudTrail management events (PutBucketPublicAccessBlock, PutBucketPolicy, PutBucketAcl) as the config-change origin, and understand why disabling Block Public Access is the change that lets the others take effect",
      "Use sourceIPAddress and userIdentity to prove a service key was driven from outside the account, and connect that to the GuardDuty anonymous-access and object-read findings",
      "Read GuardDuty S3 findings (BucketAnonymousAccessGranted, ObjectRead.Unusual, AnomalousBehavior) as markers of distinct incident stages rather than duplicates",
      "Scope containment for a leaked cloud access key, revoke and rotate the credential, restore the bucket's protections, and treat everything the key could reach as exposed",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: "2026-08-30T02:15:00.000Z", phase: "Baseline", action: `${backupRole} reads ${bucket} over VPC endpoint from inside AWS, nightly backup (control case)` },
      { ts: "2026-08-28T11:42:00.000Z", phase: "Credential Access", action: `${iamUser} access key committed to the public repository medcore/reporting-tools; secret scanning alerts (T1552.001)` },
      { ts: T(-90 * SEC), phase: "Initial Access", action: `Leaked ${iamUser} access key first used from ${attackerIp}, GetCallerIdentity, then ListBuckets at 03:00 (T1078.004)` },
      { ts: T(3 * MIN), phase: "Defense Impairment", action: "PutBucketPublicAccessBlock, all four Block Public Access guards set false (T1686.001, formerly T1562.007)" },
      { ts: T(3 * MIN + 40 * SEC), phase: "Defense Impairment", action: "PutBucketPolicy, Principal \"*\" allowed s3:GetObject on the bucket (T1686.001)" },
      { ts: T(4 * MIN), phase: "Defense Impairment", action: "PutBucketAcl, AllUsers group granted READ (T1686.001)" },
      { ts: T(7 * MIN + 10 * SEC), phase: "Collection", action: `Unauthenticated GetObject (accountId anonymous) from a second internet address: the open bucket is used (T1530)` },
      { ts: T(9 * MIN), phase: "Detection", action: `GuardDuty Policy:S3/BucketAnonymousAccessGranted on ${bucket}` },
      { ts: T(11 * MIN), phase: "Discovery", action: `ListObjectsV2, the exports/ prefix indexed page by page from ${attackerIp} (T1619)` },
      { ts: T(12 * MIN), phase: "Collection", action: `GetObject calls pull the objects from ${attackerIp}; 20,000 reads, 41 GB in total (T1530)` },
      { ts: T(20 * MIN), phase: "Detection", action: "GuardDuty Exfiltration:S3/ObjectRead.Unusual, the drain flagged; the CloudWatch BytesDownloaded alarm confirms 41 GB (T1567)" },
      { ts: T(21 * MIN), phase: "Detection", action: "GuardDuty Discovery:S3/AnomalousBehavior, enumeration + reads correlated on the key (T1526)" },
    ],
    questions,
  };
}
