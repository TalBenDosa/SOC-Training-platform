import type { TelemetryEvent } from "@/lib/sim/types";

// ── Event 1: Exposed access key used for S3 data theft from Tor exit node ─────
const exposedKeyS3ExfilEvent: TelemetryEvent = {
  id: "evt-aws-s3-exfil-001",
  ts: "2026-06-11T03:14:22.000Z",
  source: "cloudtrail",
  vendor: "AWS CloudTrail",
  event_type: "cloud_storage_access",
  severity: "critical",
  user_email: "svc-deploy@nexacorp.com",
  src_ip: "185.220.101.47",
  geo: { country: "Netherlands", city: "Amsterdam" },
  description: "IAM user access key used from a Tor exit node to download objects from a private S3 bucket containing customer records",
  mitre_technique: "T1530",
  mitre_tactic: "Collection",
  raw: {
    "aws.cloudtrail.eventName": "GetObject",
    "aws.cloudtrail.eventSource": "s3.amazonaws.com",
    "aws.cloudtrail.awsRegion": "us-east-1",
    "aws.cloudtrail.userIdentity.type": "IAMUser",
    "aws.cloudtrail.userIdentity.arn": "arn:aws:iam::482915007733:user/svc-deploy",
    "aws.cloudtrail.userIdentity.accountId": "482915007733",
    "aws.cloudtrail.userIdentity.accessKeyId": "AKIAIOSFODNN7EXAMPLE",
    "aws.cloudtrail.userIdentity.userName": "svc-deploy",
    "aws.cloudtrail.sourceIPAddress": "185.220.101.47",
    "aws.cloudtrail.userAgent": "aws-cli/2.13.0 Python/3.11.4 Linux/5.15.0",
    "aws.cloudtrail.requestParameters.bucketName": "nexacorp-customer-records",
    "aws.cloudtrail.requestParameters.key": "exports/customers_full_2026Q2.csv",
    "aws.cloudtrail.responseElements": null,
    "aws.cloudtrail.errorCode": "",
    "aws.cloudtrail.errorMessage": "",
    "aws.cloudtrail.requestID": "8F2A1B3C4D5E6F70",
    "aws.cloudtrail.eventType": "AwsApiCall",
    "aws.cloudtrail.managementEvent": false,
    "aws.cloudtrail.readOnly": true,
    "cloud.account.id": "482915007733",
    "cloud.region": "us-east-1",
    "action_result": "allowed",
  },
};

// ── Event 1b: Attacker disables the CloudTrail trail (defense evasion) ────────
const cloudTrailStopLoggingEvent: TelemetryEvent = {
  id: "evt-aws-stoplogging-001",
  ts: "2026-06-11T04:02:09.000Z",
  source: "cloudtrail",
  vendor: "AWS CloudTrail",
  event_type: "cloud_api_call",
  severity: "critical",
  user_email: "svc-deploy@nexacorp.com",
  src_ip: "185.220.101.47",
  geo: { country: "Netherlands", city: "Amsterdam" },
  description: "The organisation's primary CloudTrail trail was stopped via StopLogging, minutes before a burst of EC2 RunInstances calls: a classic move to blind the SOC before the noisy part of the attack",
  mitre_technique: "T1562.008",
  mitre_tactic: "Defense Evasion",
  raw: {
    "aws.cloudtrail.eventName": "StopLogging",
    "aws.cloudtrail.eventSource": "cloudtrail.amazonaws.com",
    "aws.cloudtrail.awsRegion": "us-east-1",
    "aws.cloudtrail.userIdentity.type": "IAMUser",
    "aws.cloudtrail.userIdentity.arn": "arn:aws:iam::482915007733:user/svc-deploy",
    "aws.cloudtrail.userIdentity.accountId": "482915007733",
    "aws.cloudtrail.userIdentity.accessKeyId": "AKIAIOSFODNN7EXAMPLE",
    "aws.cloudtrail.userIdentity.userName": "svc-deploy",
    "aws.cloudtrail.sourceIPAddress": "185.220.101.47",
    "aws.cloudtrail.userAgent": "aws-cli/2.13.0 Python/3.11.4 Linux/5.15.0",
    "aws.cloudtrail.requestParameters.name": "nexacorp-primary-trail",
    "aws.cloudtrail.responseElements": null,
    "aws.cloudtrail.errorCode": "",
    "aws.cloudtrail.errorMessage": "",
    "aws.cloudtrail.requestID": "1C2D3E4F5A6B7C80",
    "aws.cloudtrail.eventType": "AwsApiCall",
    "aws.cloudtrail.managementEvent": true,
    "aws.cloudtrail.readOnly": false,
    "cloud.account.id": "482915007733",
    "cloud.region": "us-east-1",
    "action_result": "allowed",
  },
};

// ── Event 2: IMDS credential theft -> IAM privilege escalation via new policy version
const imdsPrivEscEvent: TelemetryEvent = {
  id: "evt-aws-privesc-001",
  ts: "2026-06-11T03:41:07.000Z",
  source: "cloudtrail",
  vendor: "AWS CloudTrail",
  event_type: "cloud_role_change",
  severity: "critical",
  user_email: "svc-deploy@nexacorp.com",
  src_ip: "185.220.101.47",
  geo: { country: "Netherlands", city: "Amsterdam" },
  description: "Temporary credentials stolen from an EC2 instance's metadata service were used to attach a new AdministratorAccess policy version to the instance role",
  mitre_technique: "T1078.004",
  mitre_tactic: "Privilege Escalation",
  raw: {
    "aws.cloudtrail.eventName": "CreatePolicyVersion",
    "aws.cloudtrail.eventSource": "iam.amazonaws.com",
    "aws.cloudtrail.awsRegion": "us-east-1",
    "aws.cloudtrail.userIdentity.type": "AssumedRole",
    "aws.cloudtrail.userIdentity.arn": "arn:aws:sts::482915007733:assumed-role/ec2-webapp-role/i-0a1b2c3d4e5f67890",
    "aws.cloudtrail.userIdentity.accountId": "482915007733",
    "aws.cloudtrail.userIdentity.sessionContext.sessionIssuer.type": "Role",
    "aws.cloudtrail.userIdentity.sessionContext.sessionIssuer.arn": "arn:aws:iam::482915007733:role/ec2-webapp-role",
    "aws.cloudtrail.sourceIPAddress": "185.220.101.47",
    "aws.cloudtrail.userAgent": "aws-cli/2.13.0 Python/3.11.4 Linux/5.15.0",
    "aws.cloudtrail.requestParameters.policyArn": "arn:aws:iam::482915007733:policy/ec2-webapp-policy",
    "aws.cloudtrail.requestParameters.setAsDefault": true,
    "aws.cloudtrail.requestParameters.policyDocument": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}",
    "aws.cloudtrail.responseElements.policyVersion.versionId": "v7",
    "aws.cloudtrail.responseElements.policyVersion.isDefaultVersion": true,
    "aws.cloudtrail.errorCode": "",
    "aws.cloudtrail.errorMessage": "",
    "aws.cloudtrail.requestID": "3C9D8E7F6A5B4C31",
    "aws.cloudtrail.eventType": "AwsApiCall",
    "aws.cloudtrail.managementEvent": true,
    "aws.cloudtrail.readOnly": false,
    "cloud.account.id": "482915007733",
    "cloud.region": "us-east-1",
    "action_result": "allowed",
  },
};

// ── Event 3 (analyst_choice): GetCallerIdentity — the classic FP trap ─────────
const getCallerIdentityEvent: TelemetryEvent = {
  id: "evt-aws-gci-001",
  ts: "2026-06-11T07:00:04.000Z",
  source: "cloudtrail",
  vendor: "AWS CloudTrail",
  event_type: "cloud_api_call",
  severity: "low",
  src_ip: "10.20.4.15",
  hostname: "ip-10-20-4-15.ec2.internal",
  description: "STS GetCallerIdentity call in account 482915007733, flagged by the post-incident STS watch rule",
  raw: {
    "aws.cloudtrail.eventName": "GetCallerIdentity",
    "aws.cloudtrail.eventSource": "sts.amazonaws.com",
    "aws.cloudtrail.awsRegion": "us-east-1",
    "aws.cloudtrail.userIdentity.type": "AssumedRole",
    "aws.cloudtrail.userIdentity.arn": "arn:aws:sts::482915007733:assumed-role/deploy-pipeline-task-role/ea849af94d36b625870067199d251860",
    "aws.cloudtrail.userIdentity.accountId": "482915007733",
    "aws.cloudtrail.sourceIPAddress": "10.20.4.15",
    "aws.cloudtrail.userAgent": "aws-sdk-go/1.44.0 (go1.20.3; linux; amd64) exec-env/AWS_ECS_FARGATE",
    "aws.cloudtrail.requestParameters": {},
    "aws.cloudtrail.responseElements": null,
    "aws.cloudtrail.errorCode": "",
    "aws.cloudtrail.errorMessage": "",
    "aws.cloudtrail.requestID": "1A2B3C4D5E6F7081",
    "aws.cloudtrail.eventType": "AwsApiCall",
    "aws.cloudtrail.managementEvent": true,
    "aws.cloudtrail.readOnly": true,
    "cloud.account.id": "482915007733",
    "cloud.region": "us-east-1",
    "action_result": "allowed",
  },
};

// ── Event 4 (flag task): CloudTrail disabled + crypto-mining EC2 launch ───────
// eslint-disable-next-line @typescript-eslint/no-unused-vars -- authored attack-event, not yet wired into a room task
const cloudTrailDisabledEvent: TelemetryEvent = {
  id: "evt-aws-ct-stop-001",
  ts: "2026-06-11T04:02:51.000Z",
  source: "cloudtrail",
  vendor: "AWS CloudTrail",
  event_type: "cloud_api_call",
  severity: "critical",
  user_email: "svc-deploy@nexacorp.com",
  src_ip: "185.220.101.47",
  geo: { country: "Netherlands", city: "Amsterdam" },
  description: "The primary CloudTrail logging trail was stopped shortly before large EC2 GPU instances were launched in an unused region",
  mitre_technique: "T1562.008",
  mitre_tactic: "Defense Evasion",
  raw: {
    "aws.cloudtrail.eventName": "StopLogging",
    "aws.cloudtrail.eventSource": "cloudtrail.amazonaws.com",
    "aws.cloudtrail.awsRegion": "ap-southeast-1",
    "aws.cloudtrail.userIdentity.type": "AssumedRole",
    "aws.cloudtrail.userIdentity.arn": "arn:aws:sts::482915007733:assumed-role/ec2-webapp-role/i-0a1b2c3d4e5f67890",
    "aws.cloudtrail.userIdentity.accountId": "482915007733",
    "aws.cloudtrail.sourceIPAddress": "185.220.101.47",
    "aws.cloudtrail.userAgent": "aws-cli/2.13.0 Python/3.11.4 Linux/5.15.0",
    "aws.cloudtrail.requestParameters.name": "nexacorp-primary-trail",
    "aws.cloudtrail.responseElements": null,
    "aws.cloudtrail.errorCode": "",
    "aws.cloudtrail.errorMessage": "",
    "aws.cloudtrail.requestID": "7E6D5C4B3A291807",
    "aws.cloudtrail.eventType": "AwsApiCall",
    "aws.cloudtrail.managementEvent": true,
    "aws.cloudtrail.readOnly": false,
    "cloud.account.id": "482915007733",
    "cloud.region": "ap-southeast-1",
    "action_result": "allowed",
  },
};

const awsSecurityRoom = {
  id: "aws-security",
  title: "AWS Security for SOC Analysts",
  description:
    "Go from zero AWS knowledge to confidently investigating real AWS attacks. Learn the core services (IAM, S3, EC2, VPC), how CloudTrail logs every API call, how GuardDuty and VPC Flow Logs detect threats, and how to triage the most common AWS incidents: exposed access keys, IAM privilege escalation, public S3 buckets, disabled logging, crypto-mining, and stolen instance credentials.",
  difficulty: "intermediate" as const,
  category: "Cloud Security",
  estimatedMinutes: 75,
  xp: 340,
  icon: "☁️",
  prerequisites: ["cloud-security-monitoring"],
  tasks: [
    // ── Reading 1: What is AWS + core services ─────────────────────────────
    {
      type: "reading" as const,
      id: "aws-r1",
      heading: "What Is AWS, and Why Does a SOC Analyst Need to Know It?",
      content:
        `Imagine your company used to own a building: its own servers, its own network cables, its own air-conditioned server room with a security guard at the door. Everything lived on-premises, and your IT team was fully responsible for the physical hardware. **AWS (Amazon Web Services)** is the opposite model: instead of owning the building, your company rents computing power, storage, and networking from Amazon's data centers, over the internet, and pays only for what it uses. This is called **cloud computing**.\n\n` +
        `AWS is the largest cloud provider in the world (competitors include Microsoft Azure and Google Cloud Platform). Thousands of organizations (from three-person startups to Fortune 500 banks) run some or all of their infrastructure on AWS. If your organization uses AWS, then a meaningful share of the "servers," "databases," and "networks" a SOC analyst needs to protect no longer sit in a physical room down the hall. They exist as configurations inside an AWS account, reachable from anywhere on the internet by anyone who has the right credentials.\n\n` +
        `**Why this matters for security**: in a traditional data center, a locked door and a firewall did a lot of the work for you. In AWS, the "walls" are replaced by **permissions**, who is allowed to call which API, from where, to do what. This is why identity and access control become the single most important security boundary in the cloud. A mistake in a permission setting can expose a database to the entire internet in seconds, with no physical barrier at all standing in the way.\n\n` +
        `**The Core AWS Building Blocks You Must Know**\n\n` +
        `- **IAM (Identity and Access Management)**: the system that controls WHO can do WHAT in your AWS account. Think of it as the master keyring and the rulebook for every lock in the building. IAM manages users, groups, roles, and the policies (permission documents) attached to them.\n\n` +
        `- **S3 (Simple Storage Service)**: object storage, organized into containers called **buckets**. Think of an S3 bucket as a company filing cabinet in the cloud: you can store documents, backups, log files, or exported customer data. Buckets can be configured private (only authorized identities can read them) or, dangerously, public (anyone on the internet can read them).\n\n` +
        `- **EC2 (Elastic Compute Cloud)**: virtual servers ("instances") that run applications, exactly like a physical server would, except they can be created or destroyed in seconds through an API call rather than a hardware purchase order.\n\n` +
        `- **VPC (Virtual Private Cloud)**: a private, isolated network inside AWS, similar to the LAN (local network) in an office building. A VPC has subnets, route tables, and security groups (virtual firewalls) that control which traffic is allowed in and out.\n\n` +
        `**The SOC Analyst's Job in AWS**\n\n` +
        `Just like you would investigate a suspicious Windows logon or an unusual firewall connection on-premises, in AWS you investigate suspicious **API calls**. Every single action taken in an AWS account, from "create a user" to "download a file" to "launch a server," is an API call, and every API call is (or should be) logged. Your job is to read those logs, recognize what's normal, and catch what is not.`,
      codeExample:
        "ON-PREMISES vs AWS: THE MENTAL MODEL SHIFT\n" +
        "=======================================================\n" +
        "On-Premises Concept        AWS Equivalent\n" +
        "-------------------------------------------------------\n" +
        "Physical server            EC2 instance\n" +
        "File server / NAS          S3 bucket\n" +
        "Office LAN + firewall      VPC + Security Groups\n" +
        "Active Directory users     IAM users / roles\n" +
        "Windows Security Event Log CloudTrail\n" +
        "Network IDS/IPS            GuardDuty\n" +
        "Firewall traffic logs      VPC Flow Logs\n" +
        "Locked server room door    IAM policy / permissions\n" +
        "=======================================================\n\n" +
        "CORE AWS SERVICES A SOC ANALYST MUST KNOW\n" +
        "=======================================================\n" +
        "Service   Full Name                  What It Does\n" +
        "-------------------------------------------------------\n" +
        "IAM       Identity & Access Mgmt      Who can do what\n" +
        "S3        Simple Storage Service      Object/file storage\n" +
        "EC2       Elastic Compute Cloud       Virtual servers\n" +
        "VPC       Virtual Private Cloud       Private network\n" +
        "=======================================================",
      checkpoint: {
        question: "An S3 bucket's access policy was changed yesterday, and you need to know which identity made the change and from which IP address. Which source answers that directly?",
        options: [
          "CloudTrail events",
          "GuardDuty findings",
          "VPC Flow Log records",
          "The IAM policy editor",
        ],
        answer: 0,
        explanation: "Changing a bucket policy is an API call, and CloudTrail records every API call, who (userIdentity), from where (sourceIPAddress) and when; policy changes are management events, which are logged by default. GuardDuty findings only appear when GuardDuty judges something anomalous, so a routine-looking change may produce no finding at all. VPC Flow Log records carry IP addresses, ports and byte counts but no identity and no API action. The IAM policy editor shows what a policy says now, not who changed it or from where (and a bucket policy lives on the bucket, not in IAM).",
      },
    },

    // ── Reading 2: CloudTrail — the audit log ───────────────────────────────
    {
      type: "reading" as const,
      id: "aws-r2",
      heading: "CloudTrail: The Audit Log That Records Every Single API Call",
      content:
        `If AWS is a building full of rooms, **CloudTrail** is the security camera system that records every single time anyone opens a door, turns a key, or touches anything, who did it, from where, at what time, and what happened as a result. CloudTrail is AWS's native audit-logging service, and it is, without exaggeration, the single most important log source for any SOC analyst working with AWS.\n\n` +
        `**What CloudTrail Records**\n\n` +
        `Nearly every action taken in an AWS account, whether performed by a human through the web console, a script using the AWS CLI (Command Line Interface), or an application using the AWS SDK: generates an **API call**, and CloudTrail logs it as an **event**. This includes: logging in, creating a user, changing a permission, launching a server, downloading a file from S3, deleting a database, and thousands of other actions.\n\n` +
        `Each CloudTrail event captures the same core questions a detective would ask:\n\n` +
        `- **Who** did it: the identity (IAM user, role, or root account) via aws.cloudtrail.userIdentity fields\n` +
        `- **What** they did: the specific API action, via aws.cloudtrail.eventName (e.g. GetObject, CreateUser, RunInstances)\n` +
        `- **Where** they did it from: aws.cloudtrail.sourceIPAddress\n` +
        `- **When** it happened: the event timestamp\n` +
        `- **What service** was targeted: aws.cloudtrail.eventSource (e.g. s3.amazonaws.com, iam.amazonaws.com)\n` +
        `- **Did it succeed**: aws.cloudtrail.errorCode (empty means success; a populated error code like AccessDenied means the action was rejected)\n\n` +
        `**Management Events vs Data Events**\n\n` +
        `CloudTrail splits activity into two categories. **Management events** are control-plane actions, creating resources, changing permissions, starting or stopping services (e.g. CreateUser, StopLogging, RunInstances). These are logged by default. **Data events** are high-volume operations on the data itself, most commonly reading or writing individual objects inside an S3 bucket (e.g. GetObject, PutObject) or invoking a Lambda function. Data events are NOT logged by default because of their volume and cost: an organization must explicitly turn on S3 data event logging. This is a critical fact for a SOC analyst: if your organization has not enabled S3 data events, you may have zero visibility into who downloaded which file from a bucket, even though you can see that the bucket itself was created or its permissions were changed.\n\n` +
        `**Why Attackers Try to Kill CloudTrail**\n\n` +
        `Because CloudTrail is the camera system, one of the very first things a sophisticated attacker with sufficient permissions will try to do is turn it off, using the StopLogging API call, or deleting the trail entirely, or modifying the S3 bucket that stores the logs so they can no longer be written. This is why StopLogging, DeleteTrail, UpdateTrail, and PutBucketPolicy against the CloudTrail log bucket should always be treated as a critical severity event: a defender's camera going dark, mid-investigation, is one of the strongest signals of malicious intent in all of cloud security (MITRE T1562.008. Impair Defenses: Disable Cloud Logs). Be precise about what goes dark: StopLogging halts that trail's delivery, the S3 log archive, the SIEM feed, and every data event the trail was collecting. It does NOT erase CloudTrail Event History (the built-in, 90-day record of management events that exists independently of any trail), and GuardDuty keeps analysing its own independent copy of the CloudTrail stream. Those two sources are how you reconstruct the blind window afterwards.\n\n` +
        `**Where CloudTrail Logs Go**\n\n` +
        `By default, CloudTrail writes JSON log files to an S3 bucket roughly every 5 minutes. Most organizations also forward these events in near-real-time to a SIEM (Security Information and Event Management) platform, which is what allows a SOC analyst to search, alert, and correlate CloudTrail activity the same way they would with a Windows Event Log or a firewall log.`,
      codeExample:
        "SAMPLE CLOUDTRAIL EVENT (SIMPLIFIED JSON)\n" +
        "=======================================================\n" +
        "{\n" +
        "  \"eventTime\": \"2026-06-11T03:14:22Z\",\n" +
        "  \"eventName\": \"GetObject\",\n" +
        "  \"eventSource\": \"s3.amazonaws.com\",\n" +
        "  \"awsRegion\": \"us-east-1\",\n" +
        "  \"sourceIPAddress\": \"185.220.101.47\",\n" +
        "  \"userAgent\": \"aws-cli/2.13.0\",\n" +
        "  \"userIdentity\": {\n" +
        "    \"type\": \"IAMUser\",\n" +
        "    \"arn\": \"arn:aws:iam::482915007733:user/svc-deploy\",\n" +
        "    \"accessKeyId\": \"AKIAIOSFODNN7EXAMPLE\"\n" +
        "  },\n" +
        "  \"requestParameters\": {\n" +
        "    \"bucketName\": \"nexacorp-customer-records\",\n" +
        "    \"key\": \"exports/customers_full_2026Q2.csv\"\n" +
        "  },\n" +
        "  \"errorCode\": \"\"\n" +
        "}\n" +
        "=======================================================\n\n" +
        "MANAGEMENT EVENTS vs DATA EVENTS\n" +
        "=======================================================\n" +
        "Type              Logged by Default?   Examples\n" +
        "-------------------------------------------------------\n" +
        "Management Events  YES                  CreateUser,\n" +
        "                                        RunInstances,\n" +
        "                                        StopLogging,\n" +
        "                                        AttachRolePolicy\n" +
        "Data Events         NO (must enable)     GetObject,\n" +
        "                                        PutObject,\n" +
        "                                        InvokeFunction\n" +
        "=======================================================",
    },

    // ── Reading 3: IAM policies & roles ─────────────────────────────────────
    {
      type: "reading" as const,
      id: "aws-r3",
      heading: "IAM Policies and Roles: How Permissions Actually Work",
      content:
        `Think of an office building where every employee carries a keycard. The keycard itself does nothing on its own. What matters is which doors it has been programmed to open. In AWS, the keycard is an **identity** (an IAM user, or a temporary identity called a role), and the "which doors it opens" list is a **policy**: a JSON document that explicitly states what actions are Allowed or Denied on which resources.\n\n` +
        `**IAM Users vs IAM Roles**\n\n` +
        `An **IAM user** represents a long-term identity, typically a person or a service that needs permanent credentials (a username/password for console access, and/or an access key ID + secret access key for programmatic access via CLI or SDK). Access keys do not expire on their own, which is exactly why a leaked access key is so dangerous: unless someone notices and revokes it, it can be used indefinitely.\n\n` +
        `An **IAM role** is different: it is an identity with no long-term credentials attached at all. Instead, anyone (or anything, like an EC2 instance, a Lambda function, or another AWS account) who is allowed to "assume" the role receives **temporary credentials** that automatically expire, typically within 1 to 12 hours. Roles are the recommended way to grant permissions to applications running on EC2 instances, because there is no static secret sitting on disk waiting to be stolen, although, as you'll see later in this room, the temporary credentials themselves can still be stolen while they are valid.\n\n` +
        `**Anatomy of an IAM Policy**\n\n` +
        `A policy is a JSON document with, at minimum, an Effect (Allow or Deny), an Action (the specific API call(s) covered, e.g. s3:GetObject), and a Resource (which specific object(s) the policy applies to, e.g. a specific bucket ARN or * for everything). Two more elements matter for security even though they are optional: a Condition, which restricts WHEN an Allow applies, for example, only from a specific source IP range (aws:SourceIp), or only when the caller authenticated with MFA (aws:MultiFactorAuthPresent), and, on resource-based policies (a policy attached directly to a resource like an S3 bucket rather than to an identity), a Principal that names WHICH identity the rule applies to. Conditions are a common security guardrail, which is exactly why an attacker who edits a policy will often strip the Condition out: a CreatePolicyVersion that quietly removes an aws:SourceIp or MFA condition can turn a tightly-scoped, IP-locked permission into one usable from anywhere, so a SOC analyst comparing an old and new policy version should always check whether a protective Condition disappeared, not just whether the Action or Resource got broader.\n\n` +
        `**The Most Dangerous Policy Pattern**\n\n` +
        `A policy that grants "Action": "*", "Resource": "*" with "Effect": "Allow" is the cloud equivalent of a master key that opens every door in the building, the safe, and the server room. It is functionally equivalent to full Administrator access. SOC analysts should always treat the creation or attachment of such a policy as a high-priority event requiring investigation, especially when it is created moments after suspicious activity, or attached to a role that should have narrow, task-specific permissions (like a role meant only to serve a web application).\n\n` +
        `**IAM Privilege Escalation**\n\n` +
        `A well-known category of AWS attack is **IAM privilege escalation**, where an attacker who has compromised a low-privileged identity abuses permissions they DO have (often overlooked ones, like iam:CreatePolicyVersion, iam:AttachUserPolicy, or iam:PassRole) to grant themselves far greater access than intended. For example, if a compromised identity is allowed to create a new version of an existing IAM policy, and that policy is attached to a role or user, the attacker can create a new version of the policy that grants full admin rights, even though they were never directly granted the "attach an admin policy" permission. This is exactly the second CloudTrail event you will investigate later in this room.`,
      codeExample:
        "IAM POLICY DOCUMENT ANATOMY\n" +
        "=======================================================\n" +
        "{\n" +
        "  \"Version\": \"2012-10-17\",\n" +
        "  \"Statement\": [\n" +
        "    {\n" +
        "      \"Effect\": \"Allow\",\n" +
        "      \"Action\": \"s3:GetObject\",\n" +
        "      \"Resource\": \"arn:aws:s3:::nexacorp-reports/*\"\n" +
        "    }\n" +
        "  ]\n" +
        "}\n" +
        "  Effect:    Allow or Deny\n" +
        "  Action:    which API calls this applies to\n" +
        "  Resource:  which specific AWS resource(s)\n" +
        "  Condition: OPTIONAL -- WHEN the rule applies (e.g.\n" +
        "             only from a set source IP, or only if\n" +
        "             MFA is present). Attackers strip these.\n" +
        "  Principal: OPTIONAL -- on resource-based policies,\n" +
        "             WHICH identity the rule applies to\n" +
        "=======================================================\n\n" +
        "IAM USER vs IAM ROLE\n" +
        "=======================================================\n" +
        "                IAM User              IAM Role\n" +
        "-------------------------------------------------------\n" +
        "Credentials     Long-term             Temporary\n" +
        "                (access key)          (auto-expires,\n" +
        "                                       1-12 hours)\n" +
        "Typical use     Human or legacy       EC2 instances,\n" +
        "                service account       Lambda, cross-\n" +
        "                                      account access\n" +
        "Risk if leaked  High -- works until   Lower, but still\n" +
        "                manually revoked      dangerous while\n" +
        "                                      valid\n" +
        "=======================================================\n\n" +
        "COMMON PRIVILEGE-ESCALATION PERMISSIONS TO WATCH\n" +
        "=======================================================\n" +
        "iam:CreatePolicyVersion    Rewrite a policy to add *,*\n" +
        "iam:AttachUserPolicy       Attach AdministratorAccess\n" +
        "iam:AttachRolePolicy       Attach admin policy to a role\n" +
        "iam:PassRole               Hand a powerful role to a\n" +
        "                           new/compromised service\n" +
        "iam:CreateAccessKey        Mint new long-term creds for\n" +
        "                           any user\n" +
        "=======================================================",
      checkpoint: {
        question: "A role's temporary session credentials and an IAM user's access key are leaked in the same public repository. Why does the reading rate the role credentials as the lower, but still real, risk?",
        options: [
          "They expire on their own, so the attacker's window closes even if no one revokes them",
          "They are tied to the instance that requested them, so an attacker elsewhere cannot use them",
          "CloudTrail does not record calls made with role credentials, so attackers rarely bother with them",
          "Role credentials carry read-only permissions unless an administrator widens them",
        ],
        answer: 0,
        explanation: "Role credentials are temporary and expire automatically (typically within hours), so the exposure window is bounded; an IAM user's access key never expires on its own and works until someone deactivates it. They are still a real risk because they work for anyone who holds them until they expire. “Tied to the instance that requested them” is the misconception the IMDS-theft event in this room disproves: the stolen role session is used from a Tor exit node. “CloudTrail does not record calls made with role credentials” is false: AssumedRole activity is logged like any other identity's. “Read-only permissions” confuses temporary with weak: a role session has whatever its role's policies grant, which can be full admin.",
      },
    },

    // ── Reading 4: GuardDuty, VPC Flow Logs, S3 buckets, IMDS ───────────────
    {
      type: "reading" as const,
      id: "aws-r4",
      heading: "GuardDuty, VPC Flow Logs, S3 Bucket Exposure, and IMDS Credential Theft",
      content:
        `Beyond CloudTrail, three more AWS-native sources and one very specific attack technique come up constantly in real SOC investigations.\n\n` +
        `**GuardDuty: AWS's Built-In Threat Detection Engine**\n\n` +
        `**GuardDuty** is AWS's managed threat-detection service. Think of it as a built-in Intrusion Detection System (IDS) for your cloud account. GuardDuty continuously analyzes CloudTrail events, VPC Flow Logs, and DNS query logs, and automatically raises findings using known threat-intelligence patterns and machine learning models, without the SOC having to write a single detection rule. Example GuardDuty finding types include UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration (stolen EC2 instance credentials being used from outside AWS), CryptoCurrency:EC2/BitcoinTool.B!DNS (an EC2 instance communicating with known crypto-mining pool domains), and Recon:IAMUser/MaliciousIPCaller (API calls originating from an IP address on AWS's threat intelligence list). GuardDuty findings feel similar to an EDR alert: they come pre-scored with a severity and a plain-English description, which makes them an excellent starting point for a Tier-1 analyst, but the underlying CloudTrail and Flow Log events are still where the deep investigation happens.\n\n` +
        `**VPC Flow Logs: NetFlow for AWS**\n\n` +
        `**VPC Flow Logs** capture metadata about the IP traffic flowing to and from network interfaces within a VPC. Source IP, destination IP, source port, destination port, protocol, number of bytes, and whether the traffic was ACCEPTed or REJECTed. This is conceptually identical to firewall traffic logs or NetFlow data on-premises. Flow Logs do not capture packet content (no payload, no URLs), only the connection metadata. They are essential for spotting things like an EC2 instance suddenly making outbound connections to an unfamiliar IP on an unusual port (a sign of C2 traffic or crypto-mining pool communication) or a database port (like 3306 or 5432) unexpectedly receiving connections from the public internet.\n\n` +
        `**Public S3 Buckets: The Classic Cloud Data Breach**\n\n` +
        `An S3 bucket is private by default, but a misconfigured **bucket policy** or **ACL (Access Control List)** can make some or all objects in it readable by "anyone in the world" (in AWS terms, this is often represented as the principal Principal: "*" with no conditions, or granting access to the special group AllUsers). Because S3 buckets have predictable URL patterns, attackers and researchers actively scan the internet for exposed buckets. Publicly-exposed buckets containing customer PII, database backups, or source code are one of the most common and most damaging categories of real-world cloud data breaches, and they often generate no alert at all unless the organization has specifically enabled a check like AWS Config's s3-bucket-public-read-prohibited rule or a GuardDuty S3 Protection finding.\n\n` +
        `**IMDS Credential Theft: Stealing an EC2 Instance's Temporary Keys**\n\n` +
        `Every EC2 instance can reach a special, non-routable internal address, 169.254.169.254. Called the **Instance Metadata Service (IMDS)**. Applications running on the instance use IMDS to retrieve information about the instance itself, including, critically, the temporary access key, secret key, and session token for whatever IAM role is attached to that instance. This is convenient (no credentials need to be hard-coded into the application) but it creates a powerful attack path: if an attacker can trick a vulnerable application into making an unintended outbound HTTP request to that internal address (a technique called **SSRF (Server-Side Request Forgery)**) they can retrieve the instance's live IAM role credentials and then use them from anywhere on the internet, exactly as if they had stolen a password. This is precisely how the IAM privilege-escalation event later in this room begins: an attacker used stolen IMDS credentials from outside AWS to call the IAM API directly. AWS's newer IMDSv2 (which requires a session token obtained via a special PUT request) significantly raises the difficulty of this attack, but IMDSv1 remains enabled on many older or misconfigured instances.`,
      codeExample:
        "VPC FLOW LOG RECORD FORMAT (default v2)\n" +
        "=======================================================\n" +
        "version account-id interface-id srcaddr dstaddr srcport\n" +
        "dstport protocol packets bytes start end action log-status\n" +
        "\n" +
        "Example -- REJECTED inbound connection to a database port:\n" +
        "2 482915007733 eni-0a1b2c3d 45.142.212.10 10.20.4.30\n" +
        "51422 5432 6 1 40 1749612000 1749612060 REJECT OK\n" +
        "  (unexpected external IP tried reaching Postgres 5432 --\n" +
        "   blocked by security group, but still worth reviewing)\n" +
        "=======================================================\n\n" +
        "IMDS CREDENTIAL THEFT FLOW (SSRF -> STOLEN KEYS)\n" +
        "=======================================================\n" +
        "1. Attacker finds an SSRF flaw in a public-facing web app\n" +
        "   running on an EC2 instance\n" +
        "2. App is tricked into requesting:\n" +
        "   http://169.254.169.254/latest/meta-data/iam/\n" +
        "   security-credentials/ec2-webapp-role\n" +
        "3. IMDS returns live AccessKeyId + SecretAccessKey +\n" +
        "   SessionToken for the attached IAM role\n" +
        "4. Attacker copies these into their OWN aws-cli, from\n" +
        "   their OWN external IP address\n" +
        "5. CloudTrail now shows the role's actions coming from\n" +
        "   an external IP -- a massive red flag, since\n" +
        "   legitimate EC2-role activity normally originates\n" +
        "   from AWS's own internal address ranges\n" +
        "=======================================================",
    },

    // ── Question 1 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "aws-q1",
      question:
        "Your organization has never explicitly enabled 'S3 data event logging.' A file was downloaded from a private S3 bucket last night. Which statement is TRUE?",
      options: [
        "CloudTrail records S3 GetObject calls automatically alongside bucket creation and permission changes, with no extra configuration",
        "The GetObject data event was most likely not logged, although bucket-level management events would still appear",
        "S3 server access logging is enabled by default and captures the download, so CloudTrail is not needed for object-level visibility",
        "VPC Flow Logs record the object key and bytes read, so the download is visible in network telemetry instead",
      ],
      answer: 1,
      explanation:
        "Data events (like GetObject and PutObject on individual S3 objects) are NOT logged by CloudTrail by default because of their high volume: an organization must explicitly enable S3 data event logging on a trail. Management events (like creating the bucket, changing its policy, or enabling versioning) ARE logged by default. This gap is one of the most common visibility blind spots in real AWS environments, and a SOC analyst should always confirm whether data events are enabled before assuming 'no GetObject events' means 'no one downloaded anything.' S3 server access logging is a separate feature that is OFF by default, so it cannot be assumed to have captured the download. VPC Flow Logs record only IP addresses, ports and byte counts (never URLs or S3 object keys) so they cannot show which object was read. One nuance: if GuardDuty S3 Protection is enabled, GuardDuty reads its own independent stream of S3 data events and does NOT need data events on your trail, so it can still raise a finding, but the trail's S3 archive and your SIEM feed will have no record of the GetObject itself.",
      xp: 20,
    },

    // ── Question 2 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "aws-q2",
      question:
        "CloudTrail shows a successful PutBucketPolicy call on the bucket nexacorp-marketing-exports. The new policy adds one statement: Effect Allow, Principal '*', Action s3:GetObject on every object in the bucket, with no Condition. What does this change do?",
      options: [
        "Lets every IAM identity in NexaCorp's own account read the objects, but no one outside that account",
        "Lets anyone on the internet read every object in the bucket, with no AWS credentials needed at all",
        "Nothing on its own; the objects become public only once an ACL also grants the AllUsers group",
        "Lets any signed-in AWS user from any account read the objects, but not anonymous internet visitors",
      ],
      answer: 1,
      explanation:
        "In a bucket policy, Principal '*' with no Condition means anyone in the world, so this statement makes every object anonymously downloadable: the classic public-bucket exposure from the reading, and nothing will alert on it unless a check such as AWS Config's s3-bucket-public-read-prohibited rule or GuardDuty is watching. (Because the call succeeded, nothing such as S3 Block Public Access stopped the public statement.) “Every IAM identity in NexaCorp's own account” confuses '*' with the account's own principals; limiting access to one account needs that account named as the Principal or a Condition. “Only once an ACL also grants AllUsers” is wrong because a bucket policy or an ACL can each expose the bucket on its own. “Any signed-in AWS user” describes a different, narrower grant; '*' with no Condition does not require any AWS sign-in.",
      xp: 25,
    },

    // ── Question 3 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "aws-q3",
      question:
        "CloudTrail shows CreatePolicyVersion with setAsDefault true on reports-reader-policy. Compared with the previous version, the Action (s3:GetObject) and the Resource (the reports bucket) are unchanged; the only difference is that the Condition limiting aws:SourceIp to NexaCorp's office range is gone. How should you treat this change?",
      options: [
        "As routine: the Action and Resource are unchanged, so the identity has gained no new permissions",
        "As a possible escalation: the same permission now works from any IP address, not just the office",
        "As routine: a Condition only labels the log entry for reviewers; it does not restrict the Allow",
        "As low risk: only a policy granting '*' on '*' counts as dangerous, and this one is still scoped",
      ],
      answer: 1,
      explanation:
        "A Condition restricts when an Allow applies, so removing an aws:SourceIp Condition turns an office-only permission into one usable from anywhere: exactly what an attacker holding a stolen key needs, and the pattern the reading warns about when comparing an old and new policy version. “The Action and Resource are unchanged” checks only two of the elements that matter; the reading says to check whether a protective Condition disappeared, not just whether the Action or Resource got broader. “A Condition only labels the log entry” misdescribes Conditions: they are part of the permission itself. “Only a policy granting '*' on '*' counts as dangerous” treats the most extreme pattern as the only one; quietly widening where a permission works is also escalation.",
      xp: 20,
    },

    // ── Log Analysis 1: Exposed access key -> S3 exfil ──────────────────────
    {
      type: "log_analysis" as const,
      id: "aws-la1",
      heading: "Investigating an Exposed Access Key Used for S3 Data Theft",
      context:
        "You are a SOC analyst at NexaCorp. A GuardDuty finding fired overnight for anomalous S3 access. The IAM user in question, svc-deploy, is a service account whose long-term access key is normally only ever used from NexaCorp's build server (a fixed internal IP). A developer accidentally committed this access key to a public GitHub repository three days ago. Review the CloudTrail event below, generated at 03:14 UTC.",
      event: exposedKeyS3ExfilEvent,
      questions: [
        {
          question:
            "Look at the aws.cloudtrail.userIdentity fields of this GetObject event (source 185.220.101.47, a known Tor exit node in the Netherlands). Why does the identity TYPE matter for scoping this incident?",
          options: [
            "IAMUser means a person signed in to the console, so start with that person's password and MFA history",
            "A long-term access key works until someone deactivates it, so all three days since the leak are in scope",
            "Like other AWS credentials, it expires within hours, so only last night's calls need to be reviewed",
            "Type matters less than the source: scope the review to calls from the Tor IP 185.220.101.47 alone",
          ],
          answer: 1,
          explanation:
            "An IAMUser identity calling the API with an access key (accessKeyId AKIA..., aws-cli user agent) is using a long-term credential that never expires on its own. The key leaked on GitHub three days ago, so every call it made since then is in scope, and it stays usable until NexaCorp deactivates it. “A person signed in to the console” misreads the type: IAMUser also covers service accounts like svc-deploy that only use access keys, and this call came from the CLI with a key, not a console session. “Expires within hours” describes a role's temporary credentials, not an IAM user's access key. “Scope the review to calls from the Tor IP alone” misses that the key works from any address; an attacker can switch exit nodes, so you scope by the key, not by one IP.",
          xp: 25,
        },
        {
          question:
            "Read the outcome fields of this GetObject call on the object exports/customers_full_2026Q2.csv. What actually happened?",
          options: [
            "An attempt only: responseElements is null, so no object content was returned to the caller",
            "It succeeded: the file was downloaded, so treat this as confirmed exfiltration, not an attempt",
            "It succeeded, but readOnly true means only the object's metadata was read, not its contents",
            "It succeeded as a normal job: it used svc-deploy's usual key and the standard aws-cli agent",
          ],
          answer: 1,
          explanation:
            "aws.cloudtrail.errorCode is empty and action_result is 'allowed', so the GetObject call succeeded: the customer export was downloaded, and this is confirmed exfiltration, not an attempt. “responseElements is null” is not a failure signal: CloudTrail never logs the object's content in a GetObject record, and a failed call would carry an errorCode such as AccessDenied. “readOnly true means only the object's metadata was read” misreads the flag: readOnly only says the call changed nothing, and GetObject is the call that downloads the object itself. “A normal job” ignores the context: the key is the one leaked on GitHub, and it is being used from a Tor exit node instead of the build server's fixed internal IP.",
          xp: 25,
        },
        {
          question:
            "What should the analyst's immediate containment plan be for this confirmed key exposure and download?",
          options: [
            "Block 185.220.101.47 with a network ACL and security group, then watch the key for any further use",
            "Deactivate the key now, review every call it made since the GitHub leak, and open incident response",
            "Issue the build server a new key first, and keep the old key active until the deploy job is updated",
            "Purge the key from the GitHub history and force-push the repository clean, then close as remediated",
          ],
          answer: 1,
          explanation:
            "A leaked long-term key must stop working immediately, and deactivating it does that while staying reversible. Because the key has been public for three days, every call it made since the leak needs reviewing (including the bucket's data events), and confirmed customer-data access means formal incident response and possibly breach notification. “Block 185.220.101.47 with a network ACL and security group” cannot stop API calls to S3, which are authorised by the credential, not by VPC network rules, and the attacker can simply switch IPs. “Keep the old key active until the deploy job is updated” is rotation in the wrong order: the stolen key stays usable while you wait. “Purge the key from the GitHub history” removes nothing the attacker already copied; the key itself is still valid.",
          xp: 25,
        },
      ],
    },

    // ── Log Analysis 2: IMDS theft -> IAM privilege escalation ──────────────
    {
      type: "log_analysis" as const,
      id: "aws-la2",
      heading: "Investigating IAM Privilege Escalation via Stolen Instance Credentials",
      context:
        "Continuing the same incident timeline: 27 minutes after the S3 exfiltration event, CloudTrail recorded a second suspicious event. This time from a completely different identity type, targeting the IAM service instead of S3. The source IP is the same Tor exit node seen earlier. Review the event below.",
      event: imdsPrivEscEvent,
      questions: [
        {
          question:
            "Read the aws.cloudtrail.userIdentity fields of this CreatePolicyVersion call and compare its aws.cloudtrail.sourceIPAddress with the S3 event. What do they tell you about where these credentials came from?",
          options: [
            "A second IAM user's key leaked too; AssumedRole is how CloudTrail labels any user calling from the CLI",
            "The EC2 instance's role session (named after its instance ID) was stolen and is being used outside AWS",
            "The instance made the call itself via a proxy, since role credentials are bound to the instance holding them",
            "A Lambda function's routine call; the session suffix is a function invocation ID, not an instance ID",
          ],
          answer: 1,
          explanation:
            "The type is AssumedRole, the session issuer is ec2-webapp-role, and the session name i-0a1b2c3d4e5f67890 is an EC2 instance ID: the standard naming for an instance-profile session, whose credentials come from IMDS. Those credentials are being used from 185.220.101.47, the same Tor exit node as the S3 event, so the attacker has stolen the instance's role credentials (likely via SSRF against IMDS) and is using them from outside AWS. “A second IAM user's key” misreads the type: an IAM user's key shows as IAMUser with a user ARN, while AssumedRole means temporary role credentials. “Role credentials are bound to the instance holding them” is the misconception that makes theft possible to miss: they are bearer credentials, usable by anyone who holds them, from anywhere. “A Lambda function's routine call” misreads the suffix: 'i-' plus 17 hex characters is an instance ID, and the call came from a Tor exit node, not from inside AWS.",
          xp: 25,
        },
        {
          question:
            "Read the request and response parameters of this CreatePolicyVersion call against ec2-webapp-policy, which is normally scoped narrowly to the web app's own needs. What is the effect of the call?",
          options: [
            "A new admin-level version was saved, but it stays inactive until someone sets it as the default",
            "The '*' on '*' version is active at once, so everything the policy is attached to now has admin rights",
            "Only the role session that made the call gains admin rights; the policy's other attachments are unchanged",
            "Nothing yet: the role still needs iam:AttachRolePolicy before the broader version can grant it anything",
          ],
          answer: 1,
          explanation:
            "The request carries setAsDefault true and the response shows versionId v7 with isDefaultVersion true, so the new Action '*' / Resource '*' document is the version IAM enforces from that moment. Every user or role ec2-webapp-policy is attached to now has admin-equivalent rights. “Stays inactive until someone sets it as the default” would be true without setAsDefault, but this call set it, as isDefaultVersion confirms. “Only the role session that made the call” misunderstands managed policies: the policy is one shared object, so its new version applies to every identity it is attached to. “Still needs iam:AttachRolePolicy” is the point of this technique: rewriting a policy that is already attached escalates privileges without ever attaching a new one.",
          xp: 25,
        },
        {
          question:
            "Given both events are now confirmed and tied to the same attacker, what is the correct escalation path?",
          options: [
            "Open two incidents, one per service, so the S3 and IAM owners can each contain their own part",
            "One active compromise: revoke the role's sessions, deactivate the key, roll back v7, isolate the instance",
            "Deactivate the svc-deploy key now, but hold the role actions until the IMDS theft is proven, to protect the web app",
            "Terminate the EC2 instance and delete ec2-webapp-role, so the stolen session and the policy change go with them",
          ],
          answer: 1,
          explanation:
            "Two credentials, one attacker IP and an admin-level policy change add up to one active account compromise. Contain every path at once: revoke the ec2-webapp-role's active sessions (stolen role credentials cannot be deactivated like a key), deactivate the svc-deploy key, restore the previous policy version in place of v7, isolate the instance and snapshot its volumes, then audit every change this identity and IP made across the account, since an attacker with admin rights may have created backdoor users, keys or roles. “Open two incidents, one per service” splits the correlation that proves this is a single intrusion and slows containment. “Hold the role actions until the IMDS theft is proven” leaves an admin-level stolen session live while you wait; the evidence already justifies containment. “Terminate the EC2 instance and delete ec2-webapp-role” destroys the instance's volatile evidence and the role's history, and it does not undo v7, which stays the default on a policy that may be attached elsewhere.",
          xp: 30,
        },
      ],
    },

    // ── Analyst Choice: GetCallerIdentity FP trap ────────────────────────────
    {
      type: "analyst_choice" as const,
      id: "aws-ac1",
      heading: "Verdict: Is This STS GetCallerIdentity Call Suspicious?",
      scenario:
        "A SIEM correlation rule that watches all STS activity in AWS account 482915007733 for 72 hours after a confirmed compromise flagged the API call below: the same account involved in your earlier investigation. By the time it fired, the incident had been contained: the leaked key deactivated, the ec2-webapp-role's sessions revoked, and the compromised instance isolated. Asset notes: deploy-pipeline-task-role is the role NexaCorp's ECS Fargate deployment task assumes (its session name is the task ID); that pipeline is scheduled daily at 07:00 UTC; and the VPC reaches STS through an interface endpoint, so calls from inside it are recorded with their private source address. Read the identity, source address, user agent, time and action in the event, then decide: is this event suspicious?",
      event: getCallerIdentityEvent,
      correct_verdict: "false_positive",
      explanation:
        "This is a textbook false positive. GetCallerIdentity is one of the most benign, common API calls in all of AWS. It simply asks 'who am I authenticated as?' and is frequently called automatically at the start of scripts, SDK initializations, and CI/CD pipeline runs to confirm the correct identity is active before doing real work (it is often literally the first API call an AWS SDK or Terraform run makes). Here, the caller is the pipeline's own ECS task role (deploy-pipeline-task-role, with a task-ID session name), not the compromised ec2-webapp-role, and the source IP (10.20.4.15, an internal private address) and user agent (aws-sdk-go, exec-env/AWS_ECS_FARGATE) are consistent with that Fargate task; the call landed at 07:00:04 UTC, when the pipeline is scheduled to start; and a private source address is expected because the VPC reaches STS through an interface endpoint. Routine, internal, automated infrastructure activity, completely different from the external Tor IP seen during the actual compromise. The action itself is also read-only (aws.cloudtrail.readOnly: true) and management-plane only; it cannot read data, change permissions, or modify any resource. Correlation rules that alert purely because 'this account was involved in a past incident' will generate significant noise unless they also weigh source IP, time since containment, and the sensitivity of the specific action.",
      fp_trap:
        "It is tempting to escalate this immediately because it lands in the SAME account, inside the watch window of a serious confirmed compromise. But account and timing alone are not enough context. GetCallerIdentity is read-only, cannot change anything, is called constantly by legitimate automation, and here originates from a trusted internal IP after remediation was already completed. Escalating every single subsequent API call in a previously-compromised account, without evaluating the specific action and source, leads to alert fatigue and wastes investigation time that should go toward genuinely risky actions (like write/management operations or external source IPs).",
      xp: 30,
    },

    // ── Matching: AWS service <-> what it does / what log it produces ──────
    {
      type: "matching" as const,
      id: "aws-m1",
      heading: "Match Each AWS Service to What It Does and What Log It Produces",
      instructions:
        "Match each AWS service or log source on the left to its correct description on the right.",
      pairs: [
        {
          id: "iam",
          left: "IAM (Identity and Access Management)",
          right: "Controls who can do what: manages users, roles, and permission policies; changes appear as management events in CloudTrail",
        },
        {
          id: "s3",
          left: "S3 (Simple Storage Service)",
          right: "Object storage organized into buckets; file downloads/uploads only appear in CloudTrail if S3 data event logging is explicitly enabled",
        },
        {
          id: "ec2",
          left: "EC2 (Elastic Compute Cloud)",
          right: "Virtual servers ('instances'); each instance can reach IMDS at 169.254.169.254 to retrieve its attached IAM role's temporary credentials",
        },
        {
          id: "cloudtrail",
          left: "CloudTrail",
          right: "Records every API call made in the account (who, what, when, from where); the primary audit-log source for AWS investigations",
        },
        {
          id: "guardduty",
          left: "GuardDuty",
          right: "Managed threat-detection service that analyzes CloudTrail, VPC Flow Logs, and DNS logs to automatically raise pre-scored findings",
        },
        {
          id: "vpcflow",
          left: "VPC Flow Logs",
          right: "Records network connection metadata (source/dest IP, port, protocol, bytes, accept/reject): the AWS equivalent of NetFlow or firewall traffic logs",
        },
      ],
      explanation:
        "These six services form the backbone of nearly every AWS security investigation. IAM defines the permission boundaries; EC2 and S3 are the most commonly attacked resource types; CloudTrail is the ground-truth audit log for almost every investigation; GuardDuty is the automated first-pass detector that surfaces likely threats without manual rule-writing; and VPC Flow Logs fill in the network-layer picture that CloudTrail (an API-call log, not a packet log) cannot show. A SOC analyst who understands what each source does (and, just as importantly, what each source does NOT capture by default) can quickly identify visibility gaps during an investigation.",
      xp: 40,
    },

    // ── Reading 5: How to read/investigate CloudTrail in a SIEM ─────────────
    {
      type: "reading" as const,
      id: "aws-r5",
      heading: "How to Read and Investigate CloudTrail Events in a SIEM",
      content:
        `Once CloudTrail events are forwarded into a SIEM, they typically appear as structured fields prefixed with something like aws.cloudtrail.*: the exact same fields you have been reviewing throughout this room. Knowing which fields to pull first, and in what order, turns a wall of JSON into a fast, repeatable investigation workflow.\n\n` +
        `**Step 1: Establish the WHO**\n\n` +
        `Start with aws.cloudtrail.userIdentity.type and aws.cloudtrail.userIdentity.arn. Is this an IAMUser (long-term credentials. Check when the access key was created and whether it has ever been exposed) or an AssumedRole (temporary credentials. Check which role, and whether the session name looks like an EC2 instance ID, a Lambda name, or something unexpected)? The identity tells you what kind of credential compromise you might be dealing with.\n\n` +
        `**Step 2: Establish the WHERE**\n\n` +
        `Check aws.cloudtrail.sourceIPAddress. Is it an internal AWS IP (typically in the private ranges used by EC2/ECS/Lambda within your VPC), a known corporate office IP, or an unfamiliar external address? Cross-reference against threat intelligence, Tor exit nodes, known malicious IP lists, and unusual countries for your organization are all red flags. Also check aws.cloudtrail.userAgent: legitimate automation tools have consistent, expected user agents (aws-cli/x.x.x, aws-sdk-go, Terraform); a mismatched or unusual user agent for a given identity's normal behavior is worth investigating.\n\n` +
        `**Step 3: Establish the WHAT and the OUTCOME**\n\n` +
        `Read aws.cloudtrail.eventName and aws.cloudtrail.eventSource together. This tells you the exact action and which service it targeted. Then always check aws.cloudtrail.errorCode: an empty value means the call succeeded; a populated value (AccessDenied, UnauthorizedOperation, NoSuchEntity) means it was rejected. A flood of AccessDenied errors from one identity is a strong signal of an attacker probing for working permissions, even though none of those individual calls "succeeded," the pattern itself is the alert.\n\n` +
        `**Step 4: Pivot and Correlate**\n\n` +
        `Once you have one suspicious event, pivot in your SIEM on the same aws.cloudtrail.sourceIPAddress and the same user_identity.arn across a wider time window (hours to days). Attackers rarely perform just one action. Look for the full sequence: initial access (how the credential was obtained), reconnaissance (calls like ListBuckets, DescribeInstances, GetCallerIdentity used to map out the account), privilege escalation (IAM policy changes), and the actual objective (data access, resource creation, or logging tampering). Also check aws.cloudtrail.awsRegion, attackers sometimes deliberately operate in a region your organization doesn't normally use, hoping it receives less monitoring attention.\n\n` +
        `**Step 5: Weigh Severity by Action Type, Not Just Identity**\n\n` +
        `As you saw in the GetCallerIdentity false-positive exercise, the same identity can generate both benign and critical events. Always weigh: is this a read-only/management_event or a state-changing action (aws.cloudtrail.readOnly: true vs false)? Does it touch IAM, logging configuration, or security groups (high blast radius) versus routine describe/list calls (low blast radius)? A fast mental checklist (WHO, WHERE, WHAT, OUTCOME, PATTERN) is enough to triage the overwhelming majority of CloudTrail-based alerts within the first few minutes.`,
      codeExample:
        "CLOUDTRAIL TRIAGE CHECKLIST\n" +
        "=======================================================\n" +
        "1. WHO    aws.cloudtrail.userIdentity.type / .arn\n" +
        "          -> IAMUser (long-term key) or AssumedRole\n" +
        "             (temporary, auto-expiring)?\n" +
        "\n" +
        "2. WHERE  aws.cloudtrail.sourceIPAddress / user_agent\n" +
        "          -> internal AWS range, known office IP, or\n" +
        "             unfamiliar/malicious external IP?\n" +
        "\n" +
        "3. WHAT   aws.cloudtrail.eventName + event_source\n" +
        "          -> exact action + which service\n" +
        "\n" +
        "4. OUTCOME aws.cloudtrail.errorCode\n" +
        "          -> empty = succeeded, populated = denied/failed\n" +
        "          -> a FLOOD of AccessDenied = attacker probing\n" +
        "\n" +
        "5. PATTERN pivot on same source_ip / arn across time\n" +
        "          -> recon -> privesc -> objective sequence?\n" +
        "=======================================================\n\n" +
        "EXAMPLE SIEM / ATHENA-STYLE QUERY\n" +
        "=======================================================\n" +
        "SELECT eventTime, eventName, eventSource,\n" +
        "       sourceIPAddress, userIdentity.arn, errorCode\n" +
        "FROM cloudtrail_logs\n" +
        "WHERE sourceIPAddress = '185.220.101.47'\n" +
        "  AND eventTime BETWEEN '2026-06-11T00:00:00Z'\n" +
        "                     AND '2026-06-11T12:00:00Z'\n" +
        "ORDER BY eventTime ASC;\n" +
        "=======================================================",
      checkpoint: {
        question: "Two events from the same AssumedRole session arrive in the same minute: DescribeInstances (readOnly: true) and AuthorizeSecurityGroupIngress, which adds an inbound rule to a security group (readOnly: false). Applying Step 5, which do you triage first?",
        options: [
          "The security-group change: it alters state on a high-blast-radius control",
          "DescribeInstances: recon reveals intent, so it outranks any single change",
          "Neither first: the same session made both, so they share one priority",
          "Whichever was logged first, since CloudTrail order sets the priority",
        ],
        answer: 0,
        explanation: "Step 5 says to weigh severity by action type: a state-changing call (readOnly false) on a security group has a high blast radius, because it can open the network to the attacker, while a describe/list call changes nothing. “Recon reveals intent, so it outranks any single change” gets the order backwards: recon is worth noting and pivoting on, but the change is what can do damage now. “The same session made both, so they share one priority” is the mistake Step 5 warns about: the same identity can generate both benign and critical events. “Whichever was logged first” uses arrival order, which says nothing about impact.",
      },
    },

    // ── Log Analysis: CloudTrail disabled (defense evasion) — precedes the flag ──
    {
      type: "log_analysis" as const,
      id: "aws-la-stoplogging",
      heading: "Defense Evasion: The Trail Goes Quiet",
      context:
        "At 04:02 UTC: minutes before a burst of EC2 RunInstances calls the team expected from the crypto-mining stage. This single management event landed in CloudTrail. Read it before the trail's own events stop arriving.",
      event: cloudTrailStopLoggingEvent,
      questions: [
        {
          question:
            "Read this event's outcome and event-type fields. Why is this one call more urgent than almost anything else in the feed?",
          options: [
            "It deleted the trail's existing log files, so the earlier S3 and IAM events are now gone for good",
            "It succeeded and stops the trail delivering events, so what follows never reaches the archive or SIEM",
            "It pauses data events only; RunInstances and other management events still reach the trail and SIEM",
            "It shows a blocked attempt: readOnly false with an empty errorCode marks a write that AWS refused",
          ],
          answer: 1,
          explanation:
            "StopLogging (T1562.008, Impair Defenses) stops the trail from delivering API activity. The empty errorCode plus action_result 'allowed' confirm it succeeded, and managementEvent:true / readOnly:false mark it as a state-changing control-plane action. From this timestamp on, the trail delivers nothing, management AND data events, so the attacker's crypto-mining RunInstances calls never reach the S3 archive or the SIEM feed. The disabling itself is the alert to chase: re-enable logging, pivot to the sources the attacker did not switch off (CloudTrail Event History, which keeps 90 days of management events independently of any trail; GuardDuty, which reads its own CloudTrail stream; VPC Flow Logs; billing) to reconstruct the blind window, and treat the identity that issued it as compromised. “Deleted the trail's existing log files” overstates it: StopLogging stops new delivery, and the files already written to S3 remain. “Pauses data events only” is wrong because the whole trail stops, management events included. “A blocked attempt” misreads the fields: an empty errorCode means success, and readOnly false only means the call changes state.",
          xp: 25,
        },
      ],
    },

    // ── Flag: extract value from raw CloudTrail block ───────────────────────
    {
      type: "flag" as const,
      id: "aws-f1",
      prompt:
        "Your first containment step after the event above is to switch logging back on, so you need to know exactly which trail the attacker turned off. Enter the name of that trail as it appears in the event.",
      answer: "nexacorp-primary-trail",
      hint: "The StopLogging record says which trail it targeted in the parameters of the request.",
      xp: 25,
    },

    // ── Reading 6 (bonus context for the flag event): crypto-mining + CloudTrail disable ──
    {
      type: "reading" as const,
      id: "aws-r6",
      heading: "Crypto-Mining on EC2 and Why Disabling CloudTrail Is the Ultimate Red Flag",
      content:
        `The event referenced in the flag question above ties together two of the most common real-world AWS attack patterns: **CloudTrail tampering** and **unauthorized crypto-mining**.\n\n` +
        `**Crypto-Mining on Stolen AWS Resources**\n\n` +
        `Cryptocurrency mining requires enormous, sustained compute power: exactly what a compromised AWS account can provide for free (from the attacker's perspective) until the bill arrives or someone notices. A very common pattern following any kind of AWS credential theft is for the attacker to launch a large number of powerful, often GPU-accelerated or compute-optimized EC2 instances (large instance types like p3.16xlarge or c5.24xlarge), frequently in a region the victim organization does not normally use, and frequently across MULTIPLE regions simultaneously to maximize compute before detection. These instances then run mining software that connects outbound to a crypto-mining pool. The financial impact can be severe. Tens of thousands of dollars in compute charges can accumulate within just a few hours. This maps to GuardDuty's CryptoCurrency:EC2/BitcoinTool.B!DNS finding type, and is often first noticed via an unexpected AWS billing alert rather than a security alert.\n\n` +
        `**Why StopLogging Right Before Mass EC2 Launches Is So Significant**\n\n` +
        `In the event you just analyzed, the attacker called StopLogging against the account's primary CloudTrail trail moments before (in a real incident) launching a wave of expensive EC2 instances. This is a deliberate, calculated sequence: disable the audit trail first, THEN perform the high-impact, high-cost action, specifically so that RunInstances calls for the crypto-mining fleet never reach the trail's S3 archive or the SIEM, where the SOC's real-time alerting lives. (They are not truly invisible: CloudTrail Event History still keeps 90 days of management events independently of any trail, and GuardDuty keeps analysing its own CloudTrail stream, which is exactly where you go to reconstruct what happened during the blind window.) This exact ordering (StopLogging followed by a burst of resource-creation activity) is one of the highest-confidence indicators of malicious intent in all of AWS security, because there is essentially no legitimate business reason to disable your own audit trail moments before doing something expensive.\n\n` +
        `**Defensive Best Practices Every SOC Should Verify**\n\n` +
        `- Enable CloudTrail log file validation, which cryptographically detects if log files have been tampered with or deleted after the fact\n` +
        `- Store CloudTrail logs in a separate AWS account with restrictive permissions, so that even a fully-compromised "production" account cannot delete or modify the log history\n` +
        `- Alert immediately and unconditionally on StopLogging, DeleteTrail, and UpdateTrail API calls, regardless of which identity performed them\n` +
        `- Enable GuardDuty account-wide, including S3 Protection and Malware Protection features\n` +
        `- Set AWS Budgets billing alerts to catch runaway compute costs (a crypto-mining fleet) even if the security alerting layer is somehow bypassed`,
      codeExample:
        "ATTACK SEQUENCE: STOLEN CREDS -> DISABLE LOGGING -> MINE CRYPTO\n" +
        "=======================================================\n" +
        "03:14  GetObject         S3 exfil using leaked IAM user key\n" +
        "03:41  CreatePolicyVersion  Privilege escalation via IMDS\n" +
        "                            theft (AssumedRole)\n" +
        "04:02  StopLogging       Primary CloudTrail trail disabled\n" +
        "04:05+ RunInstances      Burst of large/GPU EC2 instances\n" +
        "                         launched in ap-southeast-1\n" +
        "                         (unused region) -- crypto-mining\n" +
        "=======================================================\n\n" +
        "WHY THIS ORDER MATTERS\n" +
        "=======================================================\n" +
        "Disabling logging BEFORE the expensive/damaging action is\n" +
        "a premeditated pattern -- almost never a false positive.\n" +
        "SOC rule of thumb: StopLogging / DeleteTrail / UpdateTrail\n" +
        "= automatic CRITICAL severity, page on-call immediately.\n" +
        "=======================================================",
    },

    // ── Reading 7: Containment — the missing final step ─────────────────────
    {
      type: "reading" as const,
      id: "aws-r7",
      heading: "Containing a Compromised AWS Identity",
      content:
        `You have now read CloudTrail events end to end, traced a stolen credential from an IMDS SSRF theft through privilege escalation and a StopLogging call, and confirmed with high confidence that a specific IAM identity is compromised. Every reading in this room up to this point has been about investigation, recognizing WHAT happened. But recognizing compromise is not the end of the job. The moment you can say "this access key is stolen and actively being used by an attacker," a SOC analyst has to act, immediately, before the investigation is even finished. This reading covers the concrete containment steps for a compromised AWS identity or instance: the part of the job that comes right after everything you've already learned.\n\n` +
        `**Step 1: Deactivate the Access Key, Don't Delete It**\n\n` +
        `If the compromised identity is an IAM user with a long-term access key, your very first action should be:\n\n` +
        `aws iam update-access-key --access-key-id <KEY_ID> --status Inactive --user-name <USER>\n\n` +
        `This immediately stops the key from authenticating to any AWS API: the attacker's next API call, using that same key, will fail with an InvalidClientTokenId or similar error. Critically, this command DEACTIVATES the key rather than deletes it. Deletion (aws iam delete-access-key) is destructive and irreversible: if you misidentified the key and it actually belongs to a production workload, a deleted key cannot be restored. You can only issue a new one and redeploy it everywhere. Deletion also removes the key's IAM metadata (its creation date and last-used time, service and region), which is useful context during the forensic follow-up. (Historical CloudTrail records are NOT affected either way. Every past event keeps its accessKeyId.) Deactivating first buys you the same protective effect (the key can no longer be used) while staying fully reversible and keeping the key's IAM metadata available to the investigation. Deletion comes later, as part of cleanup, once the investigation is complete.\n\n` +
        `**Step 2: Freeze the Identity's Permissions**\n\n` +
        `Deactivating a single access key stops that specific credential, but if the identity has other active credentials (a second access key, an active console session, or MFA-authenticated access), you need to freeze the identity itself. Two common approaches: attach an explicit, highest-precedence deny-all policy directly to the user or role (an inline policy with "Effect": "Deny", "Action": "*", "Resource": "*" overrides every other Allow the identity has, because in IAM an explicit Deny always wins), or detach the identity's existing managed and inline policies entirely so it retains no permissions at all. Either approach effectively freezes the identity in place without deleting it, which matters, because you still need the identity to exist so you can review its policy history and attached permissions as part of the investigation. Stolen role credentials (such as an instance's IMDS-issued keys) cannot be deactivated like an access key, so for a role you also use the IAM console's Revoke active sessions action, which attaches a deny-all policy with an aws:TokenIssueTime condition so that every session credential issued before that moment stops working.\n\n` +
        `**Step 3: Rotate Credentials Once Contained**\n\n` +
        `Once the immediate threat is stopped and the investigation has enough evidence, complete the credential rotation: delete the old, now-deactivated access key, issue the legitimate user or service a brand-new key pair, and (if the identity uses console access) force a password reset and, where applicable, force MFA (Multi-Factor Authentication) re-registration so any device the attacker may have paired during the compromise is invalidated. Only rotate after containment and evidence collection are done; rotating too early, before you've captured what you need from the old key's history, can throw away useful investigative context.\n\n` +
        `**Step 4: Isolate, Don't Terminate, a Compromised EC2 Instance**\n\n` +
        `If the compromise involves an EC2 instance (for example, the instance whose IMDS credentials were stolen via SSRF), the instinct to immediately terminate it is understandable but wrong. Terminating an instance destroys volatile evidence (running processes, network connections, and in-memory malware artifacts) that you may need to fully understand how the attacker got in and what else they touched. Instead, isolate the instance by swapping its security group to a dedicated isolation/quarantine security group that denies all inbound and outbound traffic except a narrow allow rule for the forensics team's IP address (to permit remote acquisition and analysis). This stops the instance from being used for further attack activity or lateral movement while keeping it running and preserved for analysis.\n\n` +
        `**Step 5: Preserve Evidence Before Any Destructive Action**\n\n` +
        `Before you isolate, and certainly before you ever terminate or rebuild an EC2 instance, take an EBS (Elastic Block Store) snapshot of its attached volumes. A snapshot captures the exact disk state at that moment, including any malware, dropped files, or modified configuration the attacker left behind: evidence that termination, or even certain in-place remediation steps, can permanently lose. This single step (snapshot first, remediate second) is the difference between having forensic evidence available six weeks into an investigation and having none at all.\n\n` +
        `**This Is the General IR Pattern, Applied to AWS**\n\n` +
        `If this sequence (isolate first, fully understand the scope, THEN eradicate and rebuild) sounds familiar, it should: it's the same containment discipline covered in this platform's Incident Response Methodology room, just applied specifically to AWS identities and EC2 instances instead of on-premises endpoints. Deactivating a key instead of deleting it, and isolating an instance instead of terminating it, are both the cloud-specific expression of the same underlying rule: contain the threat without destroying the evidence you'll need to close out the incident properly.`,
      codeExample:
        "AWS CONTAINMENT SEQUENCE FOR A COMPROMISED IDENTITY\n" +
        "=======================================================\n" +
        "1. DEACTIVATE the key (do NOT delete yet):\n" +
        "   aws iam update-access-key \\\n" +
        "     --access-key-id AKIAIOSFODNN7EXAMPLE \\\n" +
        "     --status Inactive \\\n" +
        "     --user-name svc-deploy\n" +
        "\n" +
        "2. FREEZE remaining permissions:\n" +
        "   - Attach an explicit deny-all inline policy, OR\n" +
        "   - Detach all managed/inline policies from the identity\n" +
        "   (an explicit Deny always overrides any Allow in IAM)\n" +
        "\n" +
        "3. ROTATE once contained + evidence captured:\n" +
        "   aws iam delete-access-key --access-key-id <OLD_KEY_ID> \\\n" +
        "     --user-name svc-deploy\n" +
        "   aws iam create-access-key --user-name svc-deploy\n" +
        "   -> force MFA re-registration if console access exists\n" +
        "\n" +
        "4. ISOLATE (not terminate) a compromised EC2 instance:\n" +
        "   aws ec2 modify-instance-attribute \\\n" +
        "     --instance-id i-0a1b2c3d4e5f6g7h8 \\\n" +
        "     --groups sg-isolation0000000\n" +
        "   (isolation SG: no inbound/outbound except forensics IP)\n" +
        "\n" +
        "5. PRESERVE evidence BEFORE any destructive step:\n" +
        "   aws ec2 create-snapshot \\\n" +
        "     --volume-id vol-0f1e2d3c4b5a6978 \\\n" +
        "     --description \"forensic snapshot - pre-remediation\"\n" +
        "=======================================================\n\n" +
        "WHY ORDER MATTERS\n" +
        "=======================================================\n" +
        "Deactivate before delete  -> reversible, key metadata kept\n" +
        "Isolate before terminate  -> volatile evidence survives\n" +
        "Snapshot before remediate -> disk state survives\n" +
        "Rotate only after containment + evidence is captured\n" +
        "=======================================================",
      checkpoint: {
        question: "A SOC analyst confirms an IAM user's access key is compromised and actively being used by an attacker. What is the correct first action, and why?",
        options: [
          "Delete the key at once, because a deleted key is gone for good and the attacker cannot reuse it",
          "Deactivate the key: it stops working at once, stays reversible, and its IAM metadata is kept",
          "Leave the key active until the investigation ends, so the attacker's activity can still be observed",
          "Issue the service a new key first, then deactivate the old one once the new key is deployed",
        ],
        answer: 1,
        explanation: "Deactivating the key stops it from authenticating just as effectively as deleting it, but it is reversible (if the key turns out to belong to a production workload you can re-enable it) and it keeps the key's IAM metadata, such as last-used time and service, available to the investigation. Past CloudTrail events keep their accessKeyId either way. “Delete the key at once” blocks the attacker too, but it is irreversible, so a misidentified production key cannot be restored, and its IAM metadata is lost; deletion belongs to cleanup. “Leave the key active until the investigation ends” keeps an attacker's credential live; containment runs in parallel with the investigation, not after it. “Issue the service a new key first” is rotation before containment: the stolen key keeps working while the new one is deployed.",
      },
    },
  ],
};

export default [awsSecurityRoom];
