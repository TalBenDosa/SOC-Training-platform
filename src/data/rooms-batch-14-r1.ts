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
    "aws.cloudtrail.event_name": "GetObject",
    "aws.cloudtrail.event_source": "s3.amazonaws.com",
    "aws.cloudtrail.aws_region": "us-east-1",
    "aws.cloudtrail.user_identity.type": "IAMUser",
    "aws.cloudtrail.user_identity.arn": "arn:aws:iam::482915007733:user/svc-deploy",
    "aws.cloudtrail.user_identity.account_id": "482915007733",
    "aws.cloudtrail.user_identity.access_key_id": "AKIAIOSFODNN7EXAMPLE",
    "aws.cloudtrail.user_identity.user_name": "svc-deploy",
    "aws.cloudtrail.source_ip_address": "185.220.101.47",
    "aws.cloudtrail.user_agent": "aws-cli/2.13.0 Python/3.11.4 Linux/5.15.0",
    "aws.cloudtrail.request_parameters.bucketName": "nexacorp-customer-records",
    "aws.cloudtrail.request_parameters.key": "exports/customers_full_2026Q2.csv",
    "aws.cloudtrail.response_elements": null,
    "aws.cloudtrail.error_code": "",
    "aws.cloudtrail.error_message": "",
    "aws.cloudtrail.request_id": "8F2A1B3C4D5E6F70",
    "aws.cloudtrail.event_type": "AwsApiCall",
    "aws.cloudtrail.management_event": false,
    "aws.cloudtrail.read_only": true,
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
    "aws.cloudtrail.event_name": "CreatePolicyVersion",
    "aws.cloudtrail.event_source": "iam.amazonaws.com",
    "aws.cloudtrail.aws_region": "us-east-1",
    "aws.cloudtrail.user_identity.type": "AssumedRole",
    "aws.cloudtrail.user_identity.arn": "arn:aws:sts::482915007733:assumed-role/ec2-webapp-role/i-0a1b2c3d4e5f67890",
    "aws.cloudtrail.user_identity.account_id": "482915007733",
    "aws.cloudtrail.user_identity.session_context.session_issuer.type": "Role",
    "aws.cloudtrail.user_identity.session_context.session_issuer.arn": "arn:aws:iam::482915007733:role/ec2-webapp-role",
    "aws.cloudtrail.source_ip_address": "185.220.101.47",
    "aws.cloudtrail.user_agent": "aws-cli/2.13.0 Python/3.11.4 Linux/5.15.0",
    "aws.cloudtrail.request_parameters.policyArn": "arn:aws:iam::482915007733:policy/ec2-webapp-policy",
    "aws.cloudtrail.request_parameters.setAsDefault": true,
    "aws.cloudtrail.request_parameters.policyDocument": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}",
    "aws.cloudtrail.response_elements.policyVersion.versionId": "v7",
    "aws.cloudtrail.response_elements.policyVersion.isDefaultVersion": true,
    "aws.cloudtrail.error_code": "",
    "aws.cloudtrail.error_message": "",
    "aws.cloudtrail.request_id": "3C9D8E7F6A5B4C31",
    "aws.cloudtrail.event_type": "AwsApiCall",
    "aws.cloudtrail.management_event": true,
    "aws.cloudtrail.read_only": false,
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
  user_email: "svc-deploy@nexacorp.com",
  src_ip: "10.20.4.15",
  hostname: "ip-10-20-4-15.ec2.internal",
  description: "STS GetCallerIdentity call made from an internal EC2 instance shortly after a scheduled deployment pipeline run",
  raw: {
    "aws.cloudtrail.event_name": "GetCallerIdentity",
    "aws.cloudtrail.event_source": "sts.amazonaws.com",
    "aws.cloudtrail.aws_region": "us-east-1",
    "aws.cloudtrail.user_identity.type": "AssumedRole",
    "aws.cloudtrail.user_identity.arn": "arn:aws:sts::482915007733:assumed-role/ec2-webapp-role/i-0a1b2c3d4e5f67890",
    "aws.cloudtrail.user_identity.account_id": "482915007733",
    "aws.cloudtrail.source_ip_address": "10.20.4.15",
    "aws.cloudtrail.user_agent": "aws-sdk-go/1.44.0 (go1.20.3; linux; amd64) exec-env/AWS_ECS_FARGATE",
    "aws.cloudtrail.request_parameters": {},
    "aws.cloudtrail.response_elements": null,
    "aws.cloudtrail.error_code": "",
    "aws.cloudtrail.error_message": "",
    "aws.cloudtrail.request_id": "1A2B3C4D5E6F7081",
    "aws.cloudtrail.event_type": "AwsApiCall",
    "aws.cloudtrail.management_event": true,
    "aws.cloudtrail.read_only": true,
    "cloud.account.id": "482915007733",
    "cloud.region": "us-east-1",
    "action_result": "allowed",
  },
};

// ── Event 4 (flag task): CloudTrail disabled + crypto-mining EC2 launch ───────
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
    "aws.cloudtrail.event_name": "StopLogging",
    "aws.cloudtrail.event_source": "cloudtrail.amazonaws.com",
    "aws.cloudtrail.aws_region": "ap-southeast-1",
    "aws.cloudtrail.user_identity.type": "AssumedRole",
    "aws.cloudtrail.user_identity.arn": "arn:aws:sts::482915007733:assumed-role/ec2-webapp-role/i-0a1b2c3d4e5f67890",
    "aws.cloudtrail.user_identity.account_id": "482915007733",
    "aws.cloudtrail.source_ip_address": "185.220.101.47",
    "aws.cloudtrail.user_agent": "aws-cli/2.13.0 Python/3.11.4 Linux/5.15.0",
    "aws.cloudtrail.request_parameters.name": "nexacorp-primary-trail",
    "aws.cloudtrail.response_elements": null,
    "aws.cloudtrail.error_code": "",
    "aws.cloudtrail.error_message": "",
    "aws.cloudtrail.request_id": "7E6D5C4B3A291807",
    "aws.cloudtrail.event_type": "AwsApiCall",
    "aws.cloudtrail.management_event": true,
    "aws.cloudtrail.read_only": false,
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
  xp: 315,
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
        `AWS is the largest cloud provider in the world (competitors include Microsoft Azure and Google Cloud Platform). Thousands of organizations — from three-person startups to Fortune 500 banks — run some or all of their infrastructure on AWS. If your organization uses AWS, then a meaningful share of the "servers," "databases," and "networks" a SOC analyst needs to protect no longer sit in a physical room down the hall. They exist as configurations inside an AWS account, reachable from anywhere on the internet by anyone who has the right credentials.\n\n` +
        `**Why this matters for security**: in a traditional data center, a locked door and a firewall did a lot of the work for you. In AWS, the "walls" are replaced by **permissions** — who is allowed to call which API, from where, to do what. This is why identity and access control become the single most important security boundary in the cloud. A mistake in a permission setting can expose a database to the entire internet in seconds, with no physical barrier at all standing in the way.\n\n` +
        `**The Core AWS Building Blocks You Must Know**\n\n` +
        `- **IAM (Identity and Access Management)** — the system that controls WHO can do WHAT in your AWS account. Think of it as the master keyring and the rulebook for every lock in the building. IAM manages users, groups, roles, and the policies (permission documents) attached to them.\n\n` +
        `- **S3 (Simple Storage Service)** — object storage, organized into containers called **buckets**. Think of an S3 bucket as a company filing cabinet in the cloud: you can store documents, backups, log files, or exported customer data. Buckets can be configured private (only authorized identities can read them) or, dangerously, public (anyone on the internet can read them).\n\n` +
        `- **EC2 (Elastic Compute Cloud)** — virtual servers ("instances") that run applications, exactly like a physical server would, except they can be created or destroyed in seconds through an API call rather than a hardware purchase order.\n\n` +
        `- **VPC (Virtual Private Cloud)** — a private, isolated network inside AWS, similar to the LAN (local network) in an office building. A VPC has subnets, route tables, and security groups (virtual firewalls) that control which traffic is allowed in and out.\n\n` +
        `**The SOC Analyst's Job in AWS**\n\n` +
        `Just like you would investigate a suspicious Windows logon or an unusual firewall connection on-premises, in AWS you investigate suspicious **API calls** — every single action taken in an AWS account, from "create a user" to "download a file" to "launch a server," is an API call, and every API call is (or should be) logged. Your job is to read those logs, recognize what's normal, and catch what is not.`,
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
    },

    // ── Reading 2: CloudTrail — the audit log ───────────────────────────────
    {
      type: "reading" as const,
      id: "aws-r2",
      heading: "CloudTrail: The Audit Log That Records Every Single API Call",
      content:
        `If AWS is a building full of rooms, **CloudTrail** is the security camera system that records every single time anyone opens a door, turns a key, or touches anything — who did it, from where, at what time, and what happened as a result. CloudTrail is AWS's native audit-logging service, and it is, without exaggeration, the single most important log source for any SOC analyst working with AWS.\n\n` +
        `**What CloudTrail Records**\n\n` +
        `Nearly every action taken in an AWS account — whether performed by a human through the web console, a script using the AWS CLI (Command Line Interface), or an application using the AWS SDK — generates an **API call**, and CloudTrail logs it as an **event**. This includes: logging in, creating a user, changing a permission, launching a server, downloading a file from S3, deleting a database, and thousands of other actions.\n\n` +
        `Each CloudTrail event captures the same core questions a detective would ask:\n\n` +
        `- **Who** did it — the identity (IAM user, role, or root account) via aws.cloudtrail.user_identity fields\n` +
        `- **What** they did — the specific API action, via aws.cloudtrail.event_name (e.g. GetObject, CreateUser, RunInstances)\n` +
        `- **Where** they did it from — aws.cloudtrail.source_ip_address\n` +
        `- **When** it happened — the event timestamp\n` +
        `- **What service** was targeted — aws.cloudtrail.event_source (e.g. s3.amazonaws.com, iam.amazonaws.com)\n` +
        `- **Did it succeed** — aws.cloudtrail.error_code (empty means success; a populated error code like AccessDenied means the action was rejected)\n\n` +
        `**Management Events vs Data Events**\n\n` +
        `CloudTrail splits activity into two categories. **Management events** are control-plane actions — creating resources, changing permissions, starting or stopping services (e.g. CreateUser, StopLogging, RunInstances). These are logged by default. **Data events** are high-volume operations on the data itself, most commonly reading or writing individual objects inside an S3 bucket (e.g. GetObject, PutObject) or invoking a Lambda function. Data events are NOT logged by default because of their volume and cost — an organization must explicitly turn on S3 data event logging. This is a critical fact for a SOC analyst: if your organization has not enabled S3 data events, you may have zero visibility into who downloaded which file from a bucket, even though you can see that the bucket itself was created or its permissions were changed.\n\n` +
        `**Why Attackers Try to Kill CloudTrail**\n\n` +
        `Because CloudTrail is the camera system, one of the very first things a sophisticated attacker with sufficient permissions will try to do is turn it off — using the StopLogging API call, or deleting the trail entirely, or modifying the S3 bucket that stores the logs so they can no longer be written. This is why StopLogging, DeleteTrail, UpdateTrail, and PutBucketPolicy against the CloudTrail log bucket should always be treated as a critical severity event — a defender's camera going dark, mid-investigation, is one of the strongest signals of malicious intent in all of cloud security (MITRE T1562.008 — Impair Defenses: Disable Cloud Logs).\n\n` +
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
        `Think of an office building where every employee carries a keycard. The keycard itself does nothing on its own — what matters is which doors it has been programmed to open. In AWS, the keycard is an **identity** (an IAM user, or a temporary identity called a role), and the "which doors it opens" list is a **policy** — a JSON document that explicitly states what actions are Allowed or Denied on which resources.\n\n` +
        `**IAM Users vs IAM Roles**\n\n` +
        `An **IAM user** represents a long-term identity — typically a person or a service that needs permanent credentials (a username/password for console access, and/or an access key ID + secret access key for programmatic access via CLI or SDK). Access keys do not expire on their own, which is exactly why a leaked access key is so dangerous: unless someone notices and revokes it, it can be used indefinitely.\n\n` +
        `An **IAM role** is different: it is an identity with no long-term credentials attached at all. Instead, anyone (or anything — like an EC2 instance, a Lambda function, or another AWS account) who is allowed to "assume" the role receives **temporary credentials** that automatically expire, typically within 1 to 12 hours. Roles are the recommended way to grant permissions to applications running on EC2 instances, because there is no static secret sitting on disk waiting to be stolen — although, as you'll see later in this room, the temporary credentials themselves can still be stolen while they are valid.\n\n` +
        `**Anatomy of an IAM Policy**\n\n` +
        `A policy is a JSON document with, at minimum, an Effect (Allow or Deny), an Action (the specific API call(s) covered, e.g. s3:GetObject), and a Resource (which specific object(s) the policy applies to, e.g. a specific bucket ARN or * for everything).\n\n` +
        `**The Most Dangerous Policy Pattern**\n\n` +
        `A policy that grants "Action": "*", "Resource": "*" with "Effect": "Allow" is the cloud equivalent of a master key that opens every door in the building, the safe, and the server room — it is functionally equivalent to full Administrator access. SOC analysts should always treat the creation or attachment of such a policy as a high-priority event requiring investigation, especially when it is created moments after suspicious activity, or attached to a role that should have narrow, task-specific permissions (like a role meant only to serve a web application).\n\n` +
        `**IAM Privilege Escalation**\n\n` +
        `A well-known category of AWS attack is **IAM privilege escalation** — where an attacker who has compromised a low-privileged identity abuses permissions they DO have (often overlooked ones, like iam:CreatePolicyVersion, iam:AttachUserPolicy, or iam:PassRole) to grant themselves far greater access than intended. For example, if a compromised identity is allowed to create a new version of an existing IAM policy, and that policy is attached to a role or user, the attacker can create a new version of the policy that grants full admin rights — even though they were never directly granted the "attach an admin policy" permission. This is exactly the second CloudTrail event you will investigate later in this room.`,
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
    },

    // ── Reading 4: GuardDuty, VPC Flow Logs, S3 buckets, IMDS ───────────────
    {
      type: "reading" as const,
      id: "aws-r4",
      heading: "GuardDuty, VPC Flow Logs, S3 Bucket Exposure, and IMDS Credential Theft",
      content:
        `Beyond CloudTrail, three more AWS-native sources and one very specific attack technique come up constantly in real SOC investigations.\n\n` +
        `**GuardDuty: AWS's Built-In Threat Detection Engine**\n\n` +
        `**GuardDuty** is AWS's managed threat-detection service — think of it as a built-in Intrusion Detection System (IDS) for your cloud account. GuardDuty continuously analyzes CloudTrail events, VPC Flow Logs, and DNS query logs, and automatically raises findings using known threat-intelligence patterns and machine learning models — without the SOC having to write a single detection rule. Example GuardDuty finding types include UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration (stolen EC2 instance credentials being used from outside AWS), CryptoCurrency:EC2/BitcoinTool.B!DNS (an EC2 instance communicating with known crypto-mining pool domains), and Recon:IAMUser/MaliciousIPCaller (API calls originating from an IP address on AWS's threat intelligence list). GuardDuty findings feel similar to an EDR alert: they come pre-scored with a severity and a plain-English description, which makes them an excellent starting point for a Tier-1 analyst, but the underlying CloudTrail and Flow Log events are still where the deep investigation happens.\n\n` +
        `**VPC Flow Logs: NetFlow for AWS**\n\n` +
        `**VPC Flow Logs** capture metadata about the IP traffic flowing to and from network interfaces within a VPC — source IP, destination IP, source port, destination port, protocol, number of bytes, and whether the traffic was ACCEPTed or REJECTed. This is conceptually identical to firewall traffic logs or NetFlow data on-premises. Flow Logs do not capture packet content (no payload, no URLs) — only the connection metadata. They are essential for spotting things like an EC2 instance suddenly making outbound connections to an unfamiliar IP on an unusual port (a sign of C2 traffic or crypto-mining pool communication) or a database port (like 3306 or 5432) unexpectedly receiving connections from the public internet.\n\n` +
        `**Public S3 Buckets: The Classic Cloud Data Breach**\n\n` +
        `An S3 bucket is private by default, but a misconfigured **bucket policy** or **ACL (Access Control List)** can make some or all objects in it readable by "anyone in the world" (in AWS terms, this is often represented as the principal Principal: "*" with no conditions, or granting access to the special group AllUsers). Because S3 buckets have predictable URL patterns, attackers and researchers actively scan the internet for exposed buckets. Publicly-exposed buckets containing customer PII, database backups, or source code are one of the most common and most damaging categories of real-world cloud data breaches — and they often generate no alert at all unless the organization has specifically enabled a check like AWS Config's s3-bucket-public-read-prohibited rule or a GuardDuty S3 Protection finding.\n\n` +
        `**IMDS Credential Theft: Stealing an EC2 Instance's Temporary Keys**\n\n` +
        `Every EC2 instance can reach a special, non-routable internal address — 169.254.169.254 — called the **Instance Metadata Service (IMDS)**. Applications running on the instance use IMDS to retrieve information about the instance itself, including, critically, the temporary access key, secret key, and session token for whatever IAM role is attached to that instance. This is convenient (no credentials need to be hard-coded into the application) but it creates a powerful attack path: if an attacker can trick a vulnerable application into making an unintended outbound HTTP request to that internal address — a technique called **SSRF (Server-Side Request Forgery)** — they can retrieve the instance's live IAM role credentials and then use them from anywhere on the internet, exactly as if they had stolen a password. This is precisely how the IAM privilege-escalation event later in this room begins: an attacker used stolen IMDS credentials from outside AWS to call the IAM API directly. AWS's newer IMDSv2 (which requires a session token obtained via a special PUT request) significantly raises the difficulty of this attack, but IMDSv1 remains enabled on many older or misconfigured instances.`,
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
        "CloudTrail will still show a GetObject event because all S3 activity is logged by default",
        "The GetObject data event was very likely NOT logged, even though the bucket-level management events (like creating or deleting the bucket) would still appear",
        "S3 does not support any logging at all, so this activity can never be investigated",
        "GuardDuty automatically captures the file download regardless of CloudTrail settings",
      ],
      answer: 1,
      explanation:
        "Data events (like GetObject and PutObject on individual S3 objects) are NOT logged by CloudTrail by default because of their high volume — an organization must explicitly enable S3 data event logging on a trail. Management events (like creating the bucket, changing its policy, or enabling versioning) ARE logged by default. This gap is one of the most common visibility blind spots in real AWS environments, and a SOC analyst should always confirm whether data events are enabled before assuming 'no GetObject events' means 'no one downloaded anything.'",
      xp: 20,
    },

    // ── Question 2 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "aws-q2",
      question:
        "An EC2 instance has an IAM role attached. A SOC analyst notices that role's temporary credentials being used to call the AWS API from a source IP address in Germany, while the EC2 instance itself is confirmed still running normally inside AWS in us-east-1. What does this most likely indicate?",
      options: [
        "This is completely normal — IAM role credentials automatically work from any location worldwide",
        "The instance's temporary credentials were stolen (for example via an SSRF attack against IMDS) and are now being used by an attacker from outside AWS",
        "AWS load-balances API traffic through European data centers, so the source IP is expected to vary",
        "The role must be misconfigured to allow multi-region access, which is a normal setting",
      ],
      answer: 1,
      explanation:
        "Temporary role credentials retrieved via the Instance Metadata Service (IMDS) are meant to be used only by that instance. Legitimate use of an EC2 instance role's credentials should originate from AWS's own internal network — not from an external IP address in another country. Seeing the same role's credentials used from an unexpected external IP is the classic signature of instance credential theft (often via SSRF against IMDS), and it is exactly the GuardDuty finding type UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration is designed to catch.",
      xp: 25,
    },

    // ── Question 3 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "aws-q3",
      question:
        "Which CloudTrail event name should ALWAYS be treated as critical severity and investigated immediately, regardless of who performed it?",
      options: [
        "DescribeInstances — listing EC2 instances",
        "StopLogging — disabling the CloudTrail trail that records account activity",
        "GetCallerIdentity — checking which identity is currently authenticated",
        "ListBuckets — listing the names of S3 buckets in the account",
      ],
      answer: 1,
      explanation:
        "StopLogging turns off CloudTrail's recording of account activity — the equivalent of an intruder disabling the security cameras before continuing their break-in. It maps to MITRE T1562.008 (Impair Defenses: Disable Cloud Logs) and should always trigger a critical-severity alert. DescribeInstances, GetCallerIdentity, and ListBuckets are read-only, extremely common, and usually benign background activity generated constantly by both humans and automated tooling.",
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
            "The event shows aws.cloudtrail.user_identity.type as 'IAMUser' with access_key_id 'AKIAIOSFODNN7EXAMPLE', calling GetObject from source IP 185.220.101.47 (a known Tor exit node in the Netherlands). Why is the identity TYPE itself an important clue here?",
          options: [
            "IAMUser identities always indicate malicious activity, unlike AssumedRole identities which are always safe",
            "Because svc-deploy is an IAM user (not a role), it authenticates with a long-lived access key rather than short-lived temporary credentials — meaning this leaked key will keep working indefinitely until someone manually revokes it",
            "IAMUser type events are never logged by CloudTrail, so this event must be an error",
            "The identity type has no bearing on the investigation — only the source IP matters",
          ],
          answer: 1,
          explanation:
            "IAM users authenticate with long-term access keys that do not expire on their own. Because svc-deploy's key was leaked on GitHub three days ago, an attacker has had three days to find and use it, and it will remain valid until NexaCorp explicitly deactivates or rotates it. This is precisely why leaked IAM user access keys are far more dangerous than leaked temporary role credentials, which auto-expire within hours.",
          xp: 25,
        },
        {
          question:
            "The request targeted bucket 'nexacorp-customer-records', object key 'exports/customers_full_2026Q2.csv', with action_result 'allowed' and an empty error_code. What does this tell the analyst about the outcome of the request?",
          options: [
            "The request failed because error_code is empty, which normally means AccessDenied",
            "The request succeeded — an empty error_code combined with action_result 'allowed' confirms the object was actually downloaded, meaning customer data has likely already left the environment",
            "The request is still pending and AWS has not processed it yet",
            "The bucket name proves this was an internal, authorized backup job",
          ],
          answer: 1,
          explanation:
            "In CloudTrail, a populated error_code (like AccessDenied or NoSuchBucket) indicates the call failed; an EMPTY error_code means the call succeeded. Combined with action_result 'allowed', this confirms the GetObject call completed successfully — the customers_full_2026Q2.csv file was actually downloaded by the attacker. This should be treated as a confirmed data exfiltration event, not just an attempted one.",
          xp: 25,
        },
        {
          question:
            "What should the analyst's immediate containment actions be for this confirmed key exposure and exfiltration?",
          options: [
            "Wait until business hours to notify the developer who leaked the key on GitHub",
            "Immediately deactivate/delete the exposed access key, rotate to a new key, review the bucket's full data-event history for the past several days, and begin breach-notification / incident-response procedures given confirmed customer data access",
            "Simply delete the CSV file from the bucket so it can no longer be downloaded again",
            "Block the source IP 185.220.101.47 at the VPC security group level and consider the incident closed",
          ],
          answer: 1,
          explanation:
            "A confirmed leaked long-lived key requires immediate credential invalidation — deactivating/deleting the exposed access key stops it from being used again, regardless of source IP (blocking one Tor exit node does nothing, since the attacker can trivially use a different one). The analyst must also pull the full data-event history to determine the full scope of what else may have been accessed over the past three days (since the leak), and because confirmed customer PII was downloaded, this likely triggers formal incident response and potentially regulatory breach-notification obligations.",
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
        "Continuing the same incident timeline: 27 minutes after the S3 exfiltration event, CloudTrail recorded a second suspicious event — this time from a completely different identity type, targeting the IAM service instead of S3. The source IP is the same Tor exit node seen earlier. Review the event below.",
      event: imdsPrivEscEvent,
      questions: [
        {
          question:
            "This event shows user_identity.type 'AssumedRole' with arn 'arn:aws:sts::482915007733:assumed-role/ec2-webapp-role/i-0a1b2c3d4e5f67890', calling CreatePolicyVersion from the SAME external Tor IP as the earlier S3 event. What does the '/i-0a1b2c3d4e5f67890' suffix and the AssumedRole type tell you?",
          options: [
            "This is unrelated to the earlier incident — AssumedRole activity is always safe background automation",
            "The suffix is the EC2 instance ID that assumed the ec2-webapp-role. Because these are temporary role credentials, and they are now being used from an external Tor IP rather than from inside AWS, this strongly indicates the instance's IMDS-issued credentials were stolen (likely via SSRF) and are being reused by the same attacker seen in the earlier S3 event",
            "The suffix indicates this is a scheduled, automated Lambda function execution",
            "AssumedRole credentials cannot be used outside of the AWS Management Console, so this event must be spoofed",
          ],
          answer: 1,
          explanation:
            "The ARN format arn:aws:sts::ACCOUNT:assumed-role/ROLE_NAME/SESSION_NAME shows that EC2 instance i-0a1b2c3d4e5f67890 assumed ec2-webapp-role — its session name is literally the instance ID, which is standard for EC2 instance-profile role sessions. These temporary credentials should only ever be used from within AWS's own network. Seeing them called from 185.220.101.47 (the same Tor exit node as the earlier S3 exfiltration event) strongly ties both events to the same attacker, and confirms the attacker pivoted from the leaked svc-deploy key to also stealing this EC2 instance's role credentials — likely via an SSRF vulnerability that reached the IMDS endpoint.",
          xp: 25,
        },
        {
          question:
            "The request_parameters show policyDocument granting \"Action\": \"*\", \"Resource\": \"*\" with Effect Allow, and setAsDefault: true, targeting policy 'ec2-webapp-policy' which is normally scoped narrowly for the web app's own needs. Why is CreatePolicyVersion combined with setAsDefault=true especially dangerous here?",
          options: [
            "CreatePolicyVersion only creates a draft that has no effect until manually approved by an AWS administrator",
            "Setting setAsDefault to true makes this new, wide-open '*:*' version become the ACTIVE version of the policy immediately — instantly granting full administrator-equivalent access to anything (user or role) the ec2-webapp-policy is attached to, without ever needing the iam:AttachAdministratorAccess permission directly",
            "This action only affects the policy's documentation/description, not its actual permissions",
            "setAsDefault only applies to S3 bucket policies, not IAM policies, so this parameter is irrelevant here",
          ],
          answer: 1,
          explanation:
            "This is a textbook IAM privilege escalation technique. The attacker did not need permission to directly attach AdministratorAccess — they only needed iam:CreatePolicyVersion on a policy they already had access to modify. By creating a new version with wide-open Action:* / Resource:* and immediately setting it as the default (active) version, the attacker instantly elevated the ec2-webapp-role (and anything else using that policy) to full administrative control of the AWS account, all while appearing to make a routine policy update.",
          xp: 25,
        },
        {
          question:
            "Given both events are now confirmed and tied to the same attacker, what is the correct escalation path?",
          options: [
            "Treat this as two separate, unrelated low-priority tickets since they involve different AWS services",
            "Escalate immediately as a confirmed, active cloud account compromise — revoke the ec2-webapp-role's active sessions and the leaked access key, roll back the malicious policy version, isolate/terminate the compromised EC2 instance, and audit all IAM changes made from this identity and IP across the account",
            "Only rotate the S3 access key, since the IAM policy change is a normal part of infrastructure-as-code deployments",
            "No action needed — CreatePolicyVersion calls are reversible by AWS automatically within 24 hours",
          ],
          answer: 1,
          explanation:
            "This is now a confirmed, escalating cloud account compromise: exfiltrated customer data plus an active privilege-escalation attempt granting admin-equivalent access, from the same external attacker infrastructure. This requires full incident response: revoke the ec2-webapp-role's active credentials (which forces AWS to issue new ones and invalidates anything the attacker holds), deactivate the leaked svc-deploy access key, roll back or delete the malicious '*:*' policy version, isolate and forensically image the compromised EC2 instance (likely the source of the original SSRF/IMDS compromise), and audit every IAM and resource change made by this identity and this source IP across the entire account, since a fully-escalated attacker could have created backdoor users, new access keys, or additional roles.",
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
        "A SIEM correlation rule flagged an STS API call made by the same svc-deploy / ec2-webapp-role identity involved in your earlier investigation. This new event, however, occurred routinely at 07:00 UTC — well after the incident was contained, credentials rotated, and the compromised instance terminated — and originates from an internal AWS IP address (10.20.4.15), not from the Tor exit node. The action is GetCallerIdentity, called automatically by an AWS SDK during a scheduled deployment pipeline run. Is this event suspicious?",
      event: getCallerIdentityEvent,
      correct_verdict: "false_positive",
      explanation:
        "This is a textbook false positive. GetCallerIdentity is one of the most benign, common API calls in all of AWS — it simply asks 'who am I authenticated as?' and is frequently called automatically at the start of scripts, SDK initializations, and CI/CD pipeline runs to confirm the correct identity is active before doing real work (it is often literally the first API call an AWS SDK or Terraform run makes). Here, the source IP (10.20.4.15, an internal EC2 private address) and user agent (aws-sdk-go, exec-env/AWS_ECS_FARGATE) both indicate routine, internal, automated infrastructure activity — completely different from the external Tor IP seen during the actual compromise. The action itself is also read-only (read_only: true) and management-plane only; it cannot read data, change permissions, or modify any resource. Correlation rules that alert purely because 'this identity was involved in a past incident' will generate significant noise unless they also weigh source IP, time since containment, and the sensitivity of the specific action.",
      fp_trap:
        "It is tempting to escalate this immediately because the SAME identity (svc-deploy / ec2-webapp-role) was involved in a serious confirmed compromise earlier. But identity alone is not enough context — GetCallerIdentity is read-only, cannot change anything, is called constantly by legitimate automation, and here originates from a trusted internal IP after remediation was already completed. Escalating every single subsequent API call from a previously-compromised identity, without evaluating the specific action and source, leads to alert fatigue and wastes investigation time that should go toward genuinely risky actions (like write/management operations or external source IPs).",
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
          right: "Controls who can do what — manages users, roles, and permission policies; changes appear as management events in CloudTrail",
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
          right: "Records network connection metadata (source/dest IP, port, protocol, bytes, accept/reject) — the AWS equivalent of NetFlow or firewall traffic logs",
        },
      ],
      explanation:
        "These six services form the backbone of nearly every AWS security investigation. IAM defines the permission boundaries; EC2 and S3 are the most commonly attacked resource types; CloudTrail is the ground-truth audit log for almost every investigation; GuardDuty is the automated first-pass detector that surfaces likely threats without manual rule-writing; and VPC Flow Logs fill in the network-layer picture that CloudTrail (an API-call log, not a packet log) cannot show. A SOC analyst who understands what each source does — and, just as importantly, what each source does NOT capture by default — can quickly identify visibility gaps during an investigation.",
      xp: 40,
    },

    // ── Reading 5: How to read/investigate CloudTrail in a SIEM ─────────────
    {
      type: "reading" as const,
      id: "aws-r5",
      heading: "How to Read and Investigate CloudTrail Events in a SIEM",
      content:
        `Once CloudTrail events are forwarded into a SIEM, they typically appear as structured fields prefixed with something like aws.cloudtrail.* — the exact same fields you have been reviewing throughout this room. Knowing which fields to pull first, and in what order, turns a wall of JSON into a fast, repeatable investigation workflow.\n\n` +
        `**Step 1 — Establish the WHO**\n\n` +
        `Start with aws.cloudtrail.user_identity.type and aws.cloudtrail.user_identity.arn. Is this an IAMUser (long-term credentials — check when the access key was created and whether it has ever been exposed) or an AssumedRole (temporary credentials — check which role, and whether the session name looks like an EC2 instance ID, a Lambda name, or something unexpected)? The identity tells you what kind of credential compromise you might be dealing with.\n\n` +
        `**Step 2 — Establish the WHERE**\n\n` +
        `Check aws.cloudtrail.source_ip_address. Is it an internal AWS IP (typically in the private ranges used by EC2/ECS/Lambda within your VPC), a known corporate office IP, or an unfamiliar external address? Cross-reference against threat intelligence — Tor exit nodes, known malicious IP lists, and unusual countries for your organization are all red flags. Also check aws.cloudtrail.user_agent: legitimate automation tools have consistent, expected user agents (aws-cli/x.x.x, aws-sdk-go, Terraform); a mismatched or unusual user agent for a given identity's normal behavior is worth investigating.\n\n` +
        `**Step 3 — Establish the WHAT and the OUTCOME**\n\n` +
        `Read aws.cloudtrail.event_name and aws.cloudtrail.event_source together — this tells you the exact action and which service it targeted. Then always check aws.cloudtrail.error_code: an empty value means the call succeeded; a populated value (AccessDenied, UnauthorizedOperation, NoSuchEntity) means it was rejected. A flood of AccessDenied errors from one identity is a strong signal of an attacker probing for working permissions — even though none of those individual calls "succeeded," the pattern itself is the alert.\n\n` +
        `**Step 4 — Pivot and Correlate**\n\n` +
        `Once you have one suspicious event, pivot in your SIEM on the same aws.cloudtrail.source_ip_address and the same user_identity.arn across a wider time window (hours to days). Attackers rarely perform just one action — look for the full sequence: initial access (how the credential was obtained), reconnaissance (calls like ListBuckets, DescribeInstances, GetCallerIdentity used to map out the account), privilege escalation (IAM policy changes), and the actual objective (data access, resource creation, or logging tampering). Also check aws.cloudtrail.aws_region — attackers sometimes deliberately operate in a region your organization doesn't normally use, hoping it receives less monitoring attention.\n\n` +
        `**Step 5 — Weigh Severity by Action Type, Not Just Identity**\n\n` +
        `As you saw in the GetCallerIdentity false-positive exercise, the same identity can generate both benign and critical events. Always weigh: is this a read-only/management_event or a state-changing action (aws.cloudtrail.read_only: true vs false)? Does it touch IAM, logging configuration, or security groups (high blast radius) versus routine describe/list calls (low blast radius)? A fast mental checklist — WHO, WHERE, WHAT, OUTCOME, PATTERN — is enough to triage the overwhelming majority of CloudTrail-based alerts within the first few minutes.`,
      codeExample:
        "CLOUDTRAIL TRIAGE CHECKLIST\n" +
        "=======================================================\n" +
        "1. WHO    aws.cloudtrail.user_identity.type / .arn\n" +
        "          -> IAMUser (long-term key) or AssumedRole\n" +
        "             (temporary, auto-expiring)?\n" +
        "\n" +
        "2. WHERE  aws.cloudtrail.source_ip_address / user_agent\n" +
        "          -> internal AWS range, known office IP, or\n" +
        "             unfamiliar/malicious external IP?\n" +
        "\n" +
        "3. WHAT   aws.cloudtrail.event_name + event_source\n" +
        "          -> exact action + which service\n" +
        "\n" +
        "4. OUTCOME aws.cloudtrail.error_code\n" +
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
    },

    // ── Flag: extract value from raw CloudTrail block ───────────────────────
    {
      type: "flag" as const,
      id: "aws-f1",
      prompt:
        "Review the event above where the CloudTrail logging trail was stopped shortly before crypto-mining EC2 instances were expected to launch. What is the exact value of the aws.cloudtrail.request_parameters.name field — i.e. the name of the trail that was disabled? Enter it exactly as shown.",
      answer: "nexacorp-primary-trail",
      hint: "Look inside the raw block of the StopLogging event for the request_parameters.name field — this identifies which specific CloudTrail trail the attacker disabled.",
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
        `Cryptocurrency mining requires enormous, sustained compute power — exactly what a compromised AWS account can provide for free (from the attacker's perspective) until the bill arrives or someone notices. A very common pattern following any kind of AWS credential theft is for the attacker to launch a large number of powerful, often GPU-accelerated or compute-optimized EC2 instances (large instance types like p3.16xlarge or c5.24xlarge), frequently in a region the victim organization does not normally use, and frequently across MULTIPLE regions simultaneously to maximize compute before detection. These instances then run mining software that connects outbound to a crypto-mining pool. The financial impact can be severe — tens of thousands of dollars in compute charges can accumulate within just a few hours. This maps to GuardDuty's CryptoCurrency:EC2/BitcoinTool.B!DNS finding type, and is often first noticed via an unexpected AWS billing alert rather than a security alert.\n\n` +
        `**Why StopLogging Right Before Mass EC2 Launches Is So Significant**\n\n` +
        `In the event you just analyzed, the attacker called StopLogging against the account's primary CloudTrail trail moments before (in a real incident) launching a wave of expensive EC2 instances. This is a deliberate, calculated sequence: disable the audit trail first, THEN perform the high-impact, high-cost action, specifically so that RunInstances calls for the crypto-mining fleet either go completely unrecorded, or at minimum are not forwarded to the SIEM in real time. This exact ordering — StopLogging followed by a burst of resource-creation activity — is one of the highest-confidence indicators of malicious intent in all of AWS security, because there is essentially no legitimate business reason to disable your own audit trail moments before doing something expensive.\n\n` +
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
  ],
};

export default [awsSecurityRoom];
