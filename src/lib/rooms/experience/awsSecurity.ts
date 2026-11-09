import type { RoomExperience } from "./types";

// "Operation Root Account" for the "aws-security" room.
// Script: docs/campaign/101-aws-security.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Westmarch Biotech (fictional), not the graded tasks' NexaCorp records.
// Signature: Read the Policy. IAM policy JSON read line by line: a spotdiff of a reviewed
// least-privilege version beside the over-broad live one, a trace over GuardDuty findings and
// CloudTrail, and a five-rung KQL hunt over AWSCloudTrail. Room 83 covers the control plane common
// to all clouds; this room stays on AWS's own services.
// Game mix: defuse + hunt + spotdiff. Other labs: anatomy, inspect, match, sequence, sort, trace,
// worksheet. Every GuardDuty finding named here is a live type, checked against the retired list.
//
// Task order changed. The source lists r1, r2, r3, r4, q1, q2, q3, la1, la2, ac1, m1, r5,
// la-stoplogging, f1, r6, r7: four readings in a row, and ac1 before StopLogging although ac1
// says the incident is already contained. New order:
//   r1, r2, q1 | r3, q3, r4, q2, m1 | la1, la2 | la-stoplogging, f1, r6 | r7, ac1, r5
// ac1 (a verdict, 30 XP) moves to the boss station, after r7 and after every event it refers
// back to. r5 stays after ac1 because its Step 5 states ac1's verdict outright. r6 stays right
// after f1 ("the flag question above"), f1 right after its event ("the event above"), and la2
// stays the second event ("the second CloudTrail event" in r3). No flag says "Log Analysis N".
//
// Lab data differs from the graded tasks: the stolen credentials come out of a debug route on a
// Lambda function, not a public repository or a metadata request, so the session name is a
// function name, not an instance ID (la2). The long-term key is svc-qc-uploader, never
// svc-deploy. Addresses are 198.51.100.77 and 203.0.113.91, never a Tor exit. The data leaves by
// a replication rule, never a GetObject (la1). The policy is widened in place, with a Condition
// gutted to match every Region, never one removed from an unchanged Action and Resource (q3). The
// star in the bucket lab sits on s3:PutObject behind a VPC endpoint Condition (q2). The
// policy-version call sets setAsDefault false on a CI policy (la2). The logging record is
// PutBucketLogging on a bucket, never StopLogging on a trail (la-stoplogging, f1). The watch
// alerts are Terraform, a name-match rule and a secret read, never an STS call (ac1).

export const AWS_SECURITY: RoomExperience = {
  roomId: "aws-security",
  codename: "Operation Root Account",
  theme: "rootaccount",
  handler: { name: "Eun-ji Falk", role: "Cloud Incident Responder, Westmarch Biotech" },
  briefing: [
    "Westmarch Biotech. One gene therapy, ten days from its filing with the regulator, and one AWS account holding every sequencing run behind it.",
    "Last night a private bucket began copying itself to an account nobody at Westmarch has ever heard of.",
    "Nobody signed in as root. Eun-ji Falk, Cloud Incident Responder, suspects nobody had to.",
    "Find the right record, read the policy line by line, follow the credentials, and find out what was left behind.",
  ],
  mission: "Pick the record that answers each question, read IAM and bucket policies line by line, follow a stolen session through GuardDuty and CloudTrail, work out what still sees a darkened log, call the alerts on the watch list, then hunt for the way back in.",
  estimate: "~70 min",
  look: { primary: "#7ee0c3", secondary: "#f5b971", warn: "#ff5b61" },
  scene: "facilityrootaccount",
  layout: "facility",
  stations: [
    {
      id: "bucket",
      label: "The Bucket",
      topic: "What AWS is · IAM, S3, EC2, VPC · CloudTrail · management and data events",
      tagline: "It is copying itself. Who told it to?",
      building: "archive",
      taskIds: ["aws-r1", "aws-r2", "aws-q1"],
    },
    {
      id: "policy",
      label: "The Policy",
      topic: "Users, roles and keys · policy JSON · Condition · bucket policies · GuardDuty · IMDS",
      tagline: "Read it line by line",
      building: "vault",
      taskIds: ["aws-r3", "aws-q3", "aws-r4", "aws-q2", "aws-m1"],
    },
    {
      id: "credentials",
      label: "The Credentials",
      topic: "Scoping a credential · reading a role session · policy versions · what is still open",
      tagline: "How far back, and how many ways in?",
      building: "lab",
      taskIds: ["aws-la1", "aws-la2"],
    },
    {
      id: "darktrail",
      label: "The Dark Trail",
      topic: "Logging calls · what each one stops · crypto-mining on stolen compute · defensive controls",
      tagline: "Something just went quiet",
      building: "control",
      taskIds: ["aws-la-stoplogging", "aws-f1", "aws-r6"],
    },
    {
      id: "root",
      label: "Root Account",
      topic: "Freezing an identity · weighing an alert · reading CloudTrail in a SIEM",
      tagline: "What can still act for them?",
      building: "ticket",
      taskIds: ["aws-r7", "aws-ac1", "aws-r5"],
      boss: true,
    },
  ],
  personas: {
    "aws-q1": { name: "Eun-ji Falk", role: "Cloud Incident Responder", line: "Legal wants to know what that log can prove. Think before you answer." },
    "aws-q3": { name: "Eun-ji Falk", role: "Cloud Incident Responder", line: "Two versions of one policy. Tell me how you'd log the change." },
    "aws-q2": { name: "Eun-ji Falk", role: "Cloud Incident Responder", line: "The call went through. Say what it did, in plain words." },
    "aws-m1": { name: "Eun-ji Falk", role: "Cloud Incident Responder", line: "A new responder starts Monday. Draw them the map." },
    "aws-la1": { name: "Eun-ji Falk", role: "Cloud Incident Responder", line: "An old case of mine. Take the fields in order." },
    "aws-la2": { name: "Eun-ji Falk", role: "Cloud Incident Responder", line: "Same night, same case. Keep reading." },
    "aws-la-stoplogging": { name: "Eun-ji Falk", role: "Cloud Incident Responder", line: "One more record from that night. Read it closely." },
    "aws-f1": { name: "Eun-ji Falk", role: "Cloud Incident Responder", line: "I need it spelled exactly as the record spells it." },
    "aws-ac1": { name: "Eun-ji Falk", role: "Cloud Incident Responder", line: "It hit the rule. Your call, and write down why." },
  },
  briefings: {
    // ── Reading 1: the services and which record answers what ──
    "aws-r1": [
      {
        kind: "sort",
        title: "Which Record Answers the Question?",
        prompt: "Thursday, 07:10. Eun-ji Falk has Westmarch's team on a call, and everyone is asking at once. Each record answers some questions and not others. Sort each question to the one that can answer it.",
        primer: {
          title: "Four services, three records",
          points: [
            "**IAM** (Identity and Access Management) decides who may do what. **S3** (Simple Storage Service) keeps files, called objects, in buckets. **EC2** (Elastic Compute Cloud) runs virtual servers, called instances. A **VPC** (Virtual Private Cloud) is the private network around them.",
            "Every action in AWS is an **API call**. A console click, a CLI (command line) command and an application's SDK call all end up as one.",
            "**CloudTrail** records API calls: who, what, when, from which address, and whether it worked.",
            "**VPC Flow Logs** record network connections: addresses, ports, protocol, bytes, ACCEPT or REJECT.",
            "**GuardDuty** is a detector. It reads those two sources plus DNS query logs and raises scored **findings**.",
          ],
          example: {
            label: "One download, three records",
            lines: [
              "An instance fetches a patch from 198.51.100.23 over the internet.",
              "VPC Flow Logs: 10.40.2.19 to 198.51.100.23, port 443, 8,412,090 bytes, ACCEPT.",
              "CloudTrail: nothing. A download from the internet isn't an AWS API call.",
              "GuardDuty: a finding only if that address is on a threat list.",
            ],
          },
        },
        buckets: [
          { id: "trail", label: "CloudTrail" },
          { id: "flow", label: "VPC Flow Logs" },
          { id: "gd", label: "GuardDuty" },
        ],
        items: [
          { id: "a", text: "Which identity launched instance i-07c3de19f4ab2260e at 02:14?", bucket: "trail", why: "RunInstances is an API call, so CloudTrail holds the caller and the address it came from." },
          { id: "b", text: "How many bytes left 10.40.2.19 for 198.51.100.23 last night?", bucket: "flow", why: "Bytes between two addresses is a flow record. CloudTrail never sees that traffic." },
          { id: "c", text: "Has anyone called the API from an address on a threat list this week?", bucket: "gd", why: "GuardDuty checks callers against threat lists and raises Recon:IAMUser/MaliciousIPCaller when an address on one lists or describes resources." },
          { id: "d", text: "Was port 5432 on the lab database reached from the internet?", bucket: "flow", why: "Destination port plus ACCEPT or REJECT is exactly what a flow record holds." },
          { id: "e", text: "Who created the IAM user temp-contractor2, and when?", bucket: "trail", why: "CreateUser is a management call. CloudTrail keeps the who, the when and the address." },
          { id: "f", text: "Did any instance look up a known mining-pool domain?", bucket: "gd", why: "GuardDuty reads DNS query logs. That lookup raises CryptoCurrency:EC2/BitcoinTool.B!DNS." },
          { id: "g", text: "Did the security group stop traffic from 203.0.113.50 reaching the instance?", bucket: "flow", why: "A REJECT in the flow log shows the traffic was stopped. It carries the addresses and the port, not who wrote the rule." },
          { id: "h", text: "Which role deleted the snapshot of the LIMS database volume?", bucket: "trail", why: "DeleteSnapshot is an API call with an identity on it. LIMS is the Laboratory Information Management System." },
        ],
      },
    ],

    // ── Reading 2: CloudTrail ──
    "aws-r2": [
      {
        kind: "sort",
        title: "Recorded by Default, or Only If Switched On?",
        prompt: "Before Eun-ji promises anyone an answer, work out what a trail records on its own and what it only records when someone asks it to. Sort each call.",
        primer: {
          title: "Two kinds of CloudTrail event",
          points: [
            "Every event answers the same questions: who (`userIdentity`), what (`eventName`), which service (`eventSource`), from where (`sourceIPAddress`), when (`eventTime`), and did it work (`errorCode`).",
            "**Management events** act on resources themselves: creating them, changing their settings and permissions. They are logged by default.",
            "**Data events** are operations on what is inside a resource, at very high volume. They are off until someone turns them on, and they are billed.",
            "Turning them on works from that moment forward. CloudTrail can't go back for a call it wasn't collecting.",
          ],
          example: {
            label: "One function, two kinds of event",
            lines: [
              "`CreateFunction`: a new Lambda function exists. Management event.",
              "`Invoke`: that function ran once. Data event, recorded only if enabled for it.",
            ],
          },
        },
        buckets: [
          { id: "mgmt", label: "Recorded by default" },
          { id: "data", label: "Only if data events are on" },
        ],
        items: [
          { id: "a", text: "CreateBucket", bucket: "mgmt", why: "It creates a resource. Management event." },
          { id: "b", text: "PutObject on one file in a bucket", bucket: "data", why: "It writes what is inside the bucket, not the bucket. Data event." },
          { id: "c", text: "PutBucketReplication", bucket: "mgmt", why: "It changes a bucket's configuration, so it is a management event, even though the data moves later." },
          { id: "d", text: "DeleteObject on one file in a bucket", bucket: "data", why: "One object, inside the bucket. Data event." },
          { id: "e", text: "RunInstances", bucket: "mgmt", why: "It creates instances. Management event." },
          { id: "f", text: "Invoke on a Lambda function", bucket: "data", why: "Using the function, not changing it. Data event." },
          { id: "g", text: "UpdateFunctionCode", bucket: "mgmt", why: "It changes the function itself. Management event." },
          { id: "h", text: "CopyObject inside a bucket", bucket: "data", why: "It works on objects, so it is a data event." },
        ],
      },
      {
        kind: "anatomy",
        title: "Read One CloudTrail Record",
        prompt: "This is the record that started the morning. Someone wrote a replication rule on wm-seq-runs, the bucket holding the sequencing runs, and every new run now copies itself to a bucket in another account. Scan each field.",
        source: "CloudTrail · westmarch-prod (444455556666) · eu-west-1",
        fields: [
          { key: "eventTime", value: "2026-11-05T01:12:44Z", label: "When", note: "Always UTC." },
          { key: "eventSource", value: "s3.amazonaws.com", label: "Which service", note: "Read it together with eventName." },
          { key: "eventName", value: "PutBucketReplication", label: "What", note: "Writes a replication rule on a bucket. From then on S3 copies new objects by itself, using a role the rule names." },
          { key: "userIdentity.type", value: "AssumedRole", label: "Kind of identity", note: "Temporary credentials from a role, not a person's sign-in." },
          { key: "userIdentity.arn", value: "arn:aws:sts::444455556666:assumed-role/wm-lims-sync-role/wm-lims-sync", label: "Who", note: "Role first, then session name. A Lambda function's session carries the function's name." },
          { key: "sourceIPAddress", value: "198.51.100.77", label: "From where", note: "The address the request arrived from." },
          { key: "userAgent", value: "aws-cli/2.15.30 Python/3.11.8 Linux/6.5.0", label: "Client", note: "The tool, as the caller reported it." },
          { key: "requestParameters.bucketName", value: "wm-seq-runs", label: "Target", note: "The bucket the rule was written on." },
          { key: "requestParameters.ReplicationConfiguration.Rule.Destination.Account", value: "777788889999", label: "Destination account", note: "Where the copies go. Westmarch's account ends in 6666." },
          { key: "errorCode", value: "(empty)", label: "Outcome", note: "Empty means the call went through. A refused call carries a code here, such as AccessDenied." },
          { key: "readOnly", value: "false", label: "Changes state?", note: "false: this call changes something." },
          { key: "managementEvent", value: "true", label: "Kind of event", note: "A management event, so it is in the trail by default." },
        ],
        summary: "A session on a Lambda function's role, calling from 198.51.100.77 with the AWS CLI, wrote a rule that sends new runs to account 777788889999, and S3 accepted it.",
      },
    ],

    // ── Reading 3: credentials and policies ──
    "aws-r3": [
      {
        kind: "inspect",
        title: "Two Credentials, Two Lifetimes",
        prompt: "Eun-ji found the way in. A debug route on the LIMS sync function printed its environment variables to anyone who asked. Two credentials were in that output, and they don't behave alike. Open each line.",
        primer: {
          title: "Users, roles and keys",
          points: [
            "An **IAM user** is a long-term identity for a person or a service, with a password, an access key, or both.",
            "An **IAM role** has no long-term credentials. Whatever may assume it gets **temporary credentials** from AWS STS (Security Token Service).",
            "Roles are the recommended way to give permissions to code, because no static secret sits on disk.",
          ],
          example: {
            label: "How each one shows up in CloudTrail",
            lines: [
              "`userIdentity.type: IAMUser`, `accessKeyId: AKIA...`: a named user and a long-term key.",
              "`userIdentity.type: AssumedRole`, `accessKeyId: ASIA...`: a role session and temporary keys.",
            ],
          },
        },
        artifact: "GET /debug/env · wm-lims-sync · response body",
        items: [
          { id: "region", text: "AWS_REGION=eu-west-1", tag: "Setting", tone: "trust", note: "Plain configuration. Nothing here opens anything." },
          { id: "fn", text: "AWS_LAMBDA_FUNCTION_NAME=wm-lims-sync", tag: "Setting", tone: "info", note: "The function's name. It is also the session name you saw in the CloudTrail record." },
          { id: "sess", text: "AWS_ACCESS_KEY_ID=ASIAI44QH8DHBEXAMPLE", tag: "Temporary", tone: "warn", note: "ASIA marks a temporary key from STS. Lambda puts one in every function's environment. STS set this one's end time to 11:40 UTC on Thursday." },
          { id: "tok", text: "AWS_SESSION_TOKEN=IQoJb3JpZ2luX2VjEXAMPLE", tag: "Session token", tone: "warn", note: "Temporary keys need this token. It travels with them, and nothing in a request says which machine sent it." },
          { id: "qc", text: "QC_UPLOAD_KEY_ID=AKIAJ7KQ2MPLVEXAMPLE", tag: "Long-term", tone: "warn", note: "AKIA marks a long-term access key, here for the IAM user svc-qc-uploader. IAM shows Status: Active, created 2024-08-19, and no end date. update-access-key can set Status to Inactive, so the key can't authenticate, and can set it back. Its last-used data stays in IAM either way." },
          { id: "db", text: "LIMS_DB_HOST=lims-db.wm.internal.example", tag: "Setting", tone: "trust", note: "An internal name. Useful to an intruder as a map, but it opens nothing by itself." },
        ],
      },
      {
        kind: "spotdiff",
        title: "Reviewed Policy or Live Policy?",
        prompt: "A session is only as strong as the role behind it, so read the role. Security reviewed version 3 of wm-lims-sync-policy. Someone widened it during a migration, and version 4 is what runs today. Find every line that grants more than the reviewed copy.",
        primer: {
          title: "Read a statement in parts",
          points: [
            "A **policy** is a JSON document holding one or more statements. Each has an **Effect** (Allow or Deny), an **Action** (the API calls it covers) and a **Resource** (what those calls may touch, written as an ARN, an Amazon Resource Name).",
            "A **Condition** sets when an Allow applies: from where, with MFA (multi-factor authentication) or not, in which Region.",
            "`*` in an Action or a Resource means all of them. `s3:*` is every S3 action.",
            "Read for what the job needs, then ask what each line gives beyond that.",
          ],
          example: {
            label: "One statement read aloud",
            lines: [
              "`\"Action\": \"sqs:SendMessage\"`: one call.",
              "`\"Resource\": \"arn:aws:sqs:eu-west-1:444455556666:wm-orders\"`: one queue.",
              "`\"Condition\": {\"Bool\": {\"aws:SecureTransport\": \"true\"}}`: only over TLS.",
              "Aloud: this identity may send to this one queue, over an encrypted connection.",
            ],
          },
        },
        goodTitle: "wm-lims-sync-policy · v3 · reviewed",
        suspectTitle: "wm-lims-sync-policy · v4 · default, live",
        good: [
          "\"Version\": \"2012-10-17\",",
          "\"Statement\": [",
          "{ \"Sid\": \"ReadRunInputs\", \"Effect\": \"Allow\",",
          "  \"Action\": [\"s3:GetObject\", \"s3:ListBucket\"],",
          "  \"Resource\": [\"arn:aws:s3:::wm-seq-runs\", \"arn:aws:s3:::wm-seq-runs/input/*\"],",
          "  \"Condition\": {\"StringEquals\": {\"aws:RequestedRegion\": \"eu-west-1\"}} },",
          "{ \"Sid\": \"WriteResults\", \"Effect\": \"Allow\",",
          "  \"Action\": \"s3:PutObject\",",
          "  \"Resource\": \"arn:aws:s3:::wm-seq-runs/results/*\" },",
          "{ \"Sid\": \"PassDrRole\", \"Effect\": \"Allow\",",
          "  \"Action\": \"iam:PassRole\",",
          "  \"Resource\": \"arn:aws:iam::444455556666:role/wm-dr-replication-role\" }",
          "]",
        ],
        suspect: [
          "\"Version\": \"2012-10-17\",",
          "\"Statement\": [",
          "{ \"Sid\": \"ReadInputsMigration\", \"Effect\": \"Allow\",",
          "  \"Action\": [\"s3:ListBucket\", \"s3:GetObject\"],",
          "  \"Resource\": [\"arn:aws:s3:::wm-seq-runs\", \"arn:aws:s3:::wm-seq-runs/input/*\"],",
          "  \"Condition\": {\"StringLike\": {\"aws:RequestedRegion\": \"*\"}} },",
          "{ \"Sid\": \"WriteResults\", \"Effect\": \"Allow\",",
          "  \"Action\": \"s3:*\",",
          "  \"Resource\": \"*\" },",
          "{ \"Sid\": \"PassDrRole\", \"Effect\": \"Allow\",",
          "  \"Action\": \"iam:PassRole\",",
          "  \"Resource\": \"arn:aws:iam::444455556666:role/wm-dr-replication-role\" }",
          "]",
        ],
        diffs: [
          { line: 5, why: "The Condition is still there, and it reads like a limit. `*` matches every Region, so it limits nothing." },
          { line: 7, why: "`s3:*` is every S3 action: bucket policies, replication rules, deletes. The job only ever wrote results." },
          { line: 8, why: "`*` is every resource, so every bucket in the account, not one folder. Read it with the line above: all of S3, everywhere." },
        ],
        decoys: [
          { line: 2, why: "A Sid is a label for humans. IAM doesn't evaluate it." },
          { line: 3, why: "Order inside an Action list means nothing. The same two actions." },
        ],
        hud: "Tap the lines that grant more than the reviewed version",
        sameLine: "That line is the same in both versions.",
        winTitle: "Every widened line found",
        howTo: ["Read the reviewed version beside the live one, line by line.", "Tap each line that lets the role do more.", "A line that grants nothing extra costs a life."],
        lesson: "Read every statement three ways: what (Action), on what (Resource), and when (Condition). The job needed one bucket's folders. The live version gives all of S3, on every bucket, and the statement doing it is still called WriteResults.",
      },
    ],

    // ── Reading 4: buckets, findings, metadata ──
    "aws-r4": [
      {
        kind: "anatomy",
        title: "Read One Bucket Statement",
        prompt: "Eun-ji opens every bucket policy in the account. This one is on wm-instrument-feeds, where the sequencers upload, and it has a star in it. Read it before anyone panics.",
        primer: {
          title: "A policy can live on the resource",
          points: [
            "An **identity-based policy** is attached to a user or role. A **resource-based policy** is attached to the thing itself, like a bucket.",
            "A resource-based policy must say who it is for, in a **Principal** element.",
            "A bucket is private by default. Two things can open it: a **bucket policy**, and an **ACL** (Access Control List).",
          ],
          example: {
            label: "Who a resource policy can name",
            lines: [
              "`\"Principal\": {\"AWS\": \"arn:aws:iam::777788889999:role/partner-reader\"}`: one role in one other account.",
              "`\"Principal\": {\"Service\": \"cloudtrail.amazonaws.com\"}`: one AWS service.",
            ],
          },
        },
        source: "S3 · wm-instrument-feeds · Bucket policy",
        fields: [
          { key: "Sid", value: "SequencersUploadThroughEndpoint", label: "Label", note: "For humans. IAM doesn't evaluate it." },
          { key: "Effect", value: "Allow", label: "Effect" },
          { key: "Principal", value: "*", label: "Who", note: "Every caller there is: any AWS account, and requests with no credentials at all." },
          { key: "Action", value: "s3:PutObject", label: "What", note: "s3:PutObject uploads an object. Its partner, s3:GetObject, downloads one. This statement doesn't grant that." },
          { key: "Resource", value: "arn:aws:s3:::wm-instrument-feeds/incoming/*", label: "On what", note: "One folder of one bucket." },
          { key: "Condition", value: "{\"StringEquals\": {\"aws:SourceVpce\": \"vpce-0b7e1d3a95c2f4468\"}}", label: "When", note: "Only requests through this VPC endpoint match. In this statement it is the one thing narrowing that Principal." },
        ],
        summary: "Any caller may write to incoming/, as long as the request comes through Westmarch's own endpoint. The star looks wide, and the Condition is what holds it to one network path.",
      },
      {
        kind: "match",
        title: "Read the Finding Name",
        prompt: "GuardDuty names each finding so that you can read it before you open it. Match each name to what it reports.",
        primer: {
          title: "How a finding is named",
          points: [
            "The pattern is `ThreatPurpose:ResourceType/ThreatFamilyName`: why, on what, and which kind.",
            "A finding comes scored for severity, with a plain-English description. That makes it a fast place to start.",
            "It starts the work and doesn't finish it. The detail is in the CloudTrail events and Flow Log records behind it.",
          ],
          example: {
            label: "Reading one name",
            lines: [
              "`PenTest:S3/KaliLinux`",
              "Purpose: penetration-testing tools. Resource: S3. Family: an S3 call from a machine running Kali Linux.",
            ],
          },
        },
        pairs: [
          { id: "a", left: "Recon:IAMUser/MaliciousIPCaller", right: "An address on a threat list is listing or describing resources", why: "Recon says looking around. MaliciousIPCaller says the caller is on a threat list." },
          { id: "b", left: "CryptoCurrency:EC2/BitcoinTool.B!DNS", right: "An instance is looking up domains tied to crypto-mining", why: "The !DNS ending means the evidence came from DNS query logs." },
          { id: "c", left: "Policy:S3/BucketBlockPublicAccessDisabled", right: "A bucket's public-access safety setting was turned off", why: "Policy findings flag a setting. The bucket isn't necessarily public yet, so its policy and ACLs need checking." },
          { id: "d", left: "Stealth:S3/ServerAccessLoggingDisabled", right: "A bucket stopped writing its web request logs", why: "Stealth findings cover logging going away." },
          { id: "e", left: "Policy:IAMUser/RootCredentialUsage", right: "The root user's sign-in credentials made a request", why: "Low severity by default, because the root user has legitimate jobs. Still worth asking who it was." },
          { id: "f", left: "UnauthorizedAccess:IAMUser/ResourceCredentialExfiltration.OutsideAWS", right: "Credentials issued to a Lambda function or ECS task were used from outside AWS", why: "ResourceCredential means a function or a task. EC2 has its own twin, InstanceCredentialExfiltration.OutsideAWS." },
        ],
      },
      {
        kind: "sequence",
        title: "How a Metadata Request Becomes a Stolen Session",
        prompt: "The debug route explains this incident. Eun-ji is still worried about the other classic way in, because the LIMS web portal runs on EC2 and allows the old metadata service. Put the attack in the order it happens.",
        primer: {
          title: "The address every instance can reach",
          points: [
            "Every EC2 instance can reach the **Instance Metadata Service** (IMDS) at 169.254.169.254, an address that only works from the instance itself.",
            "If a role is attached to the instance, IMDS serves that role's temporary credentials.",
            "**SSRF** (Server-Side Request Forgery) is a flaw that makes a server send a request the attacker chose.",
          ],
        },
        items: [
          { id: "use", text: "The credentials are loaded on another machine", note: "They are ordinary keys now. An access key, a secret key and a session token are all a caller needs." },
          { id: "url", text: "An attacker gives the form an address under 169.254.169.254", note: "The request now comes from the server, so IMDS answers it." },
          { id: "log", text: "CloudTrail records the role's session calling from that other machine's address", note: "An instance's role session is named after the instance, so `i-` and 17 hex characters in the ARN point to EC2." },
          { id: "form", text: "A web form fetches any URL a user types in", note: "That is the flaw: the server does the fetching and doesn't check where it points." },
          { id: "keys", text: "A second request returns the role's keys and session token", note: "Path: /latest/meta-data/iam/security-credentials/ plus the role's name." },
          { id: "role", text: "IMDS answers with the name of the attached role", note: "The first request only lists the role name." },
        ],
        order: ["form", "url", "role", "keys", "use", "log"],
        doneNote: "IMDSv2 needs a token from a PUT request first, which a simple URL-fetching flaw usually can't send. HttpTokens: required turns the old version off.",
      },
    ],

    // ── Drills before the first graded event ──
    "aws-la1": [
      {
        kind: "worksheet",
        title: "Set the Scope",
        prompt: "The svc-qc-uploader key has been in that debug output since the route went live on Monday at 09:30. Nobody looked at it until Wednesday night's alert. Work out what the review has to cover.",
        primer: {
          title: "Scope by the credential",
          points: [
            "Nothing ends a long-term key except a person, so time alone never closes the window.",
            "The review opens when the credential was exposed, which is often long before the first alert.",
            "Filter on `userIdentity.accessKeyId`. An address only tells you about one stop on the route.",
          ],
          example: {
            label: "Same logic, away from a keyboard",
            lines: [
              "A building pass goes missing on 1 March. The first odd entry is on 20 March.",
              "Review every door that pass opened since the 1st, not since the 20th.",
            ],
          },
        },
        caption: "CloudTrail · userIdentity.accessKeyId = AKIAJ7KQ2MPLVEXAMPLE · QC runner address 198.51.100.41",
        columns: ["eventTime", "eventName", "sourceIPAddress", "awsRegion"],
        rows: [
          ["11-02 08:15", "ListBuckets", "198.51.100.41", "eu-west-1"],
          ["11-02 14:02", "DescribeVolumes", "198.51.100.41", "eu-west-1"],
          ["11-03 02:40", "ListBuckets", "203.0.113.91", "eu-west-1"],
          ["11-03 02:41", "DescribeVolumes", "203.0.113.91", "eu-west-1"],
          ["11-04 11:18", "DescribeVolumes", "198.51.100.41", "eu-west-1"],
          ["11-04 22:51", "ListBuckets", "198.51.100.77", "eu-west-1"],
          ["11-04 22:52", "DescribeVolumes", "198.51.100.77", "eu-west-1"],
          ["11-05 02:01", "DescribeRegions", "198.51.100.77", "eu-west-1"],
          ["11-05 02:05", "RunInstances", "198.51.100.77", "sa-east-1"],
          ["11-05 02:06", "RunInstances", "198.51.100.77", "ap-southeast-2"],
          ["11-05 02:06", "RunInstances", "198.51.100.77", "ca-central-1"],
        ],
        questions: [
          { id: "open", q: "On Monday, at what time does the review window open? (HH:MM)", hint: "Not the first row, and not the alert.", answer: ["09:30", "9:30"], why: "The window opens when the key became readable by someone else: the moment the route went live. The 08:15 call is before it." },
          { id: "out", q: "Inside that window, how many calls came from somewhere other than the QC runner?", hint: "Count every row that isn't 198.51.100.41, and don't stop at one address.", answer: ["8", "eight"], why: "Two from 203.0.113.91 and six from 198.51.100.77. The key moved between addresses, and the filter on the key caught both." },
          { id: "miss", q: "How many of those would a review starting at Wednesday's 22:51 alert have missed?", hint: "Look at Tuesday.", answer: ["2", "two"], why: "Tuesday's two calls from 203.0.113.91 came 44 hours before anyone looked. They are also the earliest sign of whoever held the key." },
        ],
      },
      {
        kind: "sequence",
        title: "A Token Sent to the Wrong Person",
        miss: "Not yet. Stop the credential, keep the log, then work out what it touched.",
        prompt: "Eun-ji keeps the notes from last spring, when an API token for Westmarch's sample-tracking service, a vendor's site at tracking.vendor.example, was emailed to the wrong person. The notes got shuffled. Put that day's steps back in the order they should run.",
        items: [
          { id: "open", text: "Open an incident and call the privacy officer", note: "The service holds patient sample IDs. Once a read of those is confirmed, it is an incident, with people to tell." },
          { id: "revoke", text: "Revoke the token on the service's admin page", note: "The service checks the token on every request, wherever it comes from. So the service is the one place it can be stopped." },
          { id: "finish", text: "Issue a new token to the lab team and ask the recipient to delete the email", note: "Clean-up, once the old token is dead and the review is done." },
          { id: "export", text: "Export the service's access log", note: "That log ages out after 30 days. Keep a copy before anything else changes." },
          { id: "review", text: "List what the token touched, back to the hour it left the building", note: "The window opens at the exposure." },
        ],
        order: ["revoke", "export", "review", "open", "finish"],
        doneNote: "Stop the credential, keep the evidence, widen the review, tell who needs telling, then tidy up.",
      },
      {
        kind: "sort",
        title: "Can You Take It Back?",
        prompt: "Eun-ji keeps a card by the keyboard for bad nights: before any containment command, know whether it can be undone. Sort these.",
        primer: {
          title: "Know your way back",
          points: [
            "While the facts are still coming in, prefer a move you can undo.",
          ],
          example: {
            label: "Ask one question of any command",
            lines: [
              "`aws lambda put-function-concurrency --reserved-concurrent-executions 0`: the function stops running. `delete-function-concurrency` brings it back.",
              "`aws rds delete-db-snapshot`: the snapshot is gone. No command returns it.",
            ],
          },
        },
        buckets: [
          { id: "back", label: "You can go back" },
          { id: "gone", label: "No way back" },
        ],
        items: [
          { id: "a", text: "aws ec2 modify-instance-attribute --groups sg-quarantine", bucket: "back", why: "The old security group can go back on, and the instance kept running the whole time." },
          { id: "b", text: "aws ec2 terminate-instances", bucket: "gone", why: "Running processes, connections and memory go with the instance." },
          { id: "c", text: "aws iam put-role-policy (a deny-all inline policy)", bucket: "back", why: "delete-role-policy removes it. The role, its attachments and its history are untouched." },
          { id: "d", text: "aws iam delete-role", bucket: "gone", why: "A new role with the same name gets a new internal ID, so trust policies naming the old one stop matching." },
          { id: "e", text: "aws ec2 create-snapshot", bucket: "back", why: "It copies a volume and changes nothing on it." },
          { id: "f", text: "aws ec2 delete-volume", bucket: "gone", why: "Unless a snapshot exists, the disk's evidence is gone." },
          { id: "g", text: "aws iam set-default-policy-version", bucket: "back", why: "Both versions stay stored. Only which one IAM enforces changes." },
          { id: "h", text: "aws iam delete-policy-version", bucket: "gone", why: "That version's text is gone, and with it the easiest proof of what the policy granted." },
        ],
      },
    ],

    // ── Drills before the second graded event ──
    "aws-la2": [
      {
        kind: "trace",
        title: "Follow the Session",
        prompt: "Thursday, 09:20. GuardDuty has had all night with what the account did. Start from the findings, then follow the session through CloudTrail. Click the row that answers each question.",
        primer: {
          title: "Read a role session",
          points: [
            "In a role session's ARN, the part after the role is the **session name**: `assumed-role/<role>/<session>`.",
            "It shows what asked for the credentials. Lambda uses the function name, ECS (Elastic Container Service) the task ID, EC2 the instance ID.",
            "So the question for any session is whether this address and this client fit that name.",
          ],
          example: {
            label: "Reading one ARN",
            lines: [
              "`arn:aws:sts::444455556666:assumed-role/wm-report-role/wm-report-builder`",
              "Role wm-report-role, session wm-report-builder: the Lambda function of that name.",
              "Called from the VPC's NAT address with a Boto3 client inside Lambda, it fits.",
            ],
          },
        },
        lead: "Role wm-lims-sync-role, account 444455556666. The function's own calls leave through 198.51.100.40.",
        steps: [
          {
            id: "finding",
            ask: "Which finding says a credential has left the resource it was issued to?",
            source: "GuardDuty · Findings · last 24 hours",
            columns: ["Severity", "Finding type", "Resource", "Count", "Last seen"],
            rows: [
              ["High", "UnauthorizedAccess:IAMUser/ResourceCredentialExfiltration.OutsideAWS", "wm-lims-sync-role", "8", "11-05 03:14"],
              ["Low", "Stealth:S3/ServerAccessLoggingDisabled", "wm-seq-runs", "1", "11-05 01:20"],
              ["High", "Exfiltration:IAMUser/AnomalousBehavior", "wm-lims-sync-role", "1", "11-05 01:12"],
              ["Low", "Discovery:IAMUser/AnomalousBehavior", "svc-qc-uploader", "2", "11-04 22:52"],
              ["Low", "Policy:IAMUser/RootCredentialUsage", "Root", "1", "11-04 16:22"],
            ],
            answer: 0,
            why: "ResourceCredentialExfiltration.OutsideAWS: credentials issued to a Lambda function or ECS task, used from outside AWS. The root row is Finance opening a tax invoice on Wednesday afternoon, one of the few jobs that needs the root user.",
            learned: "wm-lims-sync-role credentials were used outside AWS, 8 calls, last at 03:14.",
          },
          {
            id: "outside",
            ask: "Which of these calls didn't come from the function?",
            source: "CloudTrail · userIdentity.arn contains wm-lims-sync-role",
            columns: ["eventTime", "eventName", "sourceIPAddress", "userAgent", "errorCode"],
            rows: [
              ["11-05 00:20:07", "GetBucketLocation", "198.51.100.40", "Boto3/1.34.84 exec-env/AWS_Lambda_python3.12", ""],
              ["11-05 00:40:19", "PutBucketTagging", "198.51.100.40", "Boto3/1.34.84 exec-env/AWS_Lambda_python3.12", ""],
              ["11-05 01:03:15", "ListBuckets", "198.51.100.77", "aws-cli/2.15.30 Python/3.11.8 Linux/6.5.0", ""],
              ["11-05 01:30:02", "GetBucketLocation", "198.51.100.40", "Boto3/1.34.84 exec-env/AWS_Lambda_python3.12", ""],
            ],
            answer: 2,
            why: "Same role, same session name. The function runs Boto3 inside Lambda and leaves through its NAT address. This one is the AWS CLI on 198.51.100.77.",
            learned: "First outside call: 01:03:15 from 198.51.100.77, with the AWS CLI.",
          },
          {
            id: "second",
            ask: "Pivot on the address. Which row is a different identity?",
            source: "CloudTrail · sourceIPAddress = 198.51.100.77 · 11-05 00:00 to 02:03",
            columns: ["eventTime", "eventName", "userIdentity.type", "userIdentity.arn", "errorCode"],
            rows: [
              ["11-05 01:03:15", "ListBuckets", "AssumedRole", "...assumed-role/wm-lims-sync-role/wm-lims-sync", ""],
              ["11-05 01:09:40", "GetBucketReplication", "AssumedRole", "...assumed-role/wm-lims-sync-role/wm-lims-sync", "ReplicationConfigurationNotFoundError"],
              ["11-05 01:12:44", "PutBucketReplication", "AssumedRole", "...assumed-role/wm-lims-sync-role/wm-lims-sync", ""],
              ["11-05 01:20:02", "PutBucketLogging", "AssumedRole", "...assumed-role/wm-lims-sync-role/wm-lims-sync", ""],
              ["11-05 02:01:12", "DescribeRegions", "IAMUser", "...user/svc-qc-uploader", ""],
            ],
            answer: 4,
            why: "An IAM user's long-term key, from the same address, in the same night. Both credentials sat in the same debug output.",
            learned: "Same address, two identities: one intruder, two credentials to close.",
          },
          {
            id: "moving",
            ask: "Which of these calls is still moving data out?",
            source: "CloudTrail · wm-lims-sync session · readOnly = false · until 02:00",
            columns: ["eventTime", "eventName", "sourceIPAddress", "requestParameters", "errorCode"],
            rows: [
              ["11-05 01:20:02", "PutBucketLogging", "198.51.100.77", "{\"bucketName\":\"wm-seq-runs\",\"BucketLoggingStatus\":{}}", ""],
              ["11-05 01:12:44", "PutBucketReplication", "198.51.100.77", "{\"bucketName\":\"wm-seq-runs\",\"Destination\":{\"Account\":\"777788889999\"}}", ""],
              ["11-05 00:40:19", "PutBucketTagging", "198.51.100.40", "{\"bucketName\":\"wm-seq-runs\"}", ""],
              ["11-05 00:15:51", "PutBucketTagging", "198.51.100.40", "{\"bucketName\":\"wm-seq-runs\"}", ""],
            ],
            answer: 1,
            why: "A replication rule is a standing instruction. S3 applies it to each new object until someone removes it.",
            learned: "PutBucketReplication at 01:12:44 is what moves the data.",
          },
        ],
      },
      {
        kind: "anatomy",
        title: "Read One Policy Version Call",
        prompt: "Last month's trail has a call on a different policy: Terraform wrote a new version of wm-ci-deploy-policy. Eun-ji asks one question. Did this change anyone's permissions?",
        primer: {
          title: "Why IAM housekeeping can be a climb",
          points: [
            "**Privilege escalation** in AWS often uses permissions that look like housekeeping: `iam:CreatePolicyVersion`, `iam:AttachUserPolicy`, `iam:PassRole`.",
            "A customer managed policy keeps up to five versions. Exactly one is the **default**, and that is the one IAM enforces.",
            "Whoever may write a version of a policy decides what every identity holding that policy can do.",
          ],
          example: {
            label: "Two other ways up",
            lines: [
              "`iam:AttachUserPolicy`: attach a stronger managed policy to yourself.",
              "`iam:PassRole`: hand a stronger role to a service you control.",
            ],
          },
        },
        source: "CloudTrail · westmarch-prod · iam.amazonaws.com",
        fields: [
          { key: "eventName", value: "CreatePolicyVersion", label: "What", note: "Stores a new version of a customer managed policy." },
          { key: "userIdentity.arn", value: "arn:aws:sts::444455556666:assumed-role/terraform-ci-role/run-8841", label: "Who", note: "The CI role, on a session named after the pipeline run." },
          { key: "requestParameters.policyArn", value: "arn:aws:iam::444455556666:policy/wm-ci-deploy-policy", label: "Which policy", note: "One object, attached here to three roles. Its default version applies to all of them." },
          { key: "requestParameters.setAsDefault", value: "false", label: "Enforce it now?", note: "Whether this call also makes the new version the default. Here it doesn't." },
          { key: "responseElements.policyVersion.versionId", value: "v6", label: "Version written", note: "Version numbers count up, even after old versions are deleted." },
          { key: "responseElements.policyVersion.isDefaultVersion", value: "false", label: "IAM's answer", note: "The response confirms what the request asked for: v6 is stored, not enforced." },
          { key: "errorCode", value: "(empty)", label: "Outcome", note: "The call went through." },
        ],
        summary: "A new version exists and nobody's permissions changed. IAM keeps enforcing v5 for all three roles until a SetDefaultPolicyVersion call, or a CreatePolicyVersion with the flag set, moves the default.",
      },
      {
        kind: "defuse",
        title: "What's Still Open at 10:02",
        prompt: "10:02. Eun-ji reads out what is still open, one line at a time, and each line closes at a different layer. Cut the one wire that fits.",
        device: "westmarch-prod · live containment",
        seconds: 100,
        rounds: [
          {
            id: "key",
            state: "The svc-qc-uploader key last called at 02:06 from 198.51.100.77. The QC runners use the same key, and the review still needs its last-used data.",
            wires: [
              { id: "delete", label: "Run delete-access-key" },
              { id: "env", label: "Take it out of the function's environment" },
              { id: "inactive", label: "Set the key to Inactive" },
            ],
            cut: "inactive",
            hint: "Which move stops it now and can still be undone?",
            why: "update-access-key --status Inactive stops the key on its next call, --status Active restores it, and IAM keeps its last-used data. delete-access-key stops it too, with no way back: the metadata goes, and a key you misjudged has to be reissued everywhere. Deletion belongs to clean-up. The environment only holds Westmarch's copy, not the one already out there.",
          },
          {
            id: "instance",
            state: "wm-lims-web, the EC2 instance behind the LIMS portal, ran the same debug build and has odd outbound traffic.",
            wires: [
              { id: "reboot", label: "Reboot it to clear anything in memory" },
              { id: "snap", label: "Snapshot its volumes, then swap in the quarantine security group" },
              { id: "term", label: "Terminate it and launch a clean copy" },
            ],
            cut: "snap",
            hint: "You want it cut off and you want to study it later.",
            why: "A snapshot keeps the disk as it was. A quarantine security group blocks new connections while processes and memory stay available to forensics. Check the odd traffic really stopped: connections already tracked can run on until they time out. Rebooting and terminating both lose the memory.",
          },
          {
            id: "session",
            state: "The stolen wm-lims-sync session last called at 03:14 from 203.0.113.91. STS says it stays valid until 11:40.",
            wires: [
              { id: "wait", label: "Wait: it dies at 11:40 anyway" },
              { id: "revoke", label: "Revoke the role's active sessions" },
              { id: "patch", label: "Deploy a function without the debug route" },
            ],
            cut: "revoke",
            hint: "A session has no Inactive switch. What can reach every session already issued?",
            why: "Revoke active sessions attaches an inline policy, AWSRevokeOlderSessions, denying everything to credentials issued before that moment. Patching closes the door for next time, but the stolen copy still works, and 98 minutes is a long time with s3:* on *.",
          },
          {
            id: "rule",
            state: "The session is dead. wm-seq-runs is still copying new runs to account 777788889999.",
            wires: [
              { id: "none", label: "Nothing more: the session was revoked" },
              { id: "dest", label: "Delete the destination bucket" },
              { id: "remove", label: "Remove the replication rule" },
            ],
            cut: "remove",
            hint: "Whose identity does the copying now?",
            why: "Replication runs as S3, using the role the rule names, not as the session that wrote it. So it outlives the session. DeleteBucketReplication stops it. The destination isn't Westmarch's to delete.",
          },
          {
            id: "version",
            state: "wm-lims-sync-policy v4 is the default, v3 is the reviewed version, and tonight's sync still has to run.",
            wires: [
              { id: "default", label: "Set v3 as the default version" },
              { id: "delete", label: "Delete v4" },
              { id: "detach", label: "Detach the policy from the role" },
            ],
            cut: "default",
            hint: "Which move changes what IAM enforces, keeps the job alive, and keeps the evidence?",
            why: "SetDefaultPolicyVersion changes what IAM enforces at once, on every identity holding the policy, and v4 stays stored as evidence. IAM refuses to delete a default version anyway, and detaching stops tonight's sync.",
          },
        ],
        lesson: "One intruder can hold a session, a key, a policy, a standing rule and a machine at once, and each closes at its own layer. Closing one does nothing for the next.",
      },
    ],

    // ── Drills before the logging event ──
    "aws-la-stoplogging": [
      {
        kind: "anatomy",
        title: "Read One Logging Change",
        prompt: "The 01:20 call looks boring. It is the kind Eun-ji reads first. S3 server access logging was recording requests to wm-seq-runs, and this call touched it.",
        source: "CloudTrail · westmarch-prod · s3.amazonaws.com",
        fields: [
          { key: "eventName", value: "PutBucketLogging", label: "What", note: "Sets where a bucket writes its server access logs, if anywhere." },
          { key: "requestParameters.bucketName", value: "wm-seq-runs", label: "Target", note: "A call names its target in requestParameters. The key depends on the API: bucketName for S3, name for a CloudTrail trail, policyArn for IAM." },
          { key: "requestParameters.BucketLoggingStatus", value: "{}", label: "New setting", note: "No target bucket given, so the bucket stops writing access logs." },
          { key: "errorCode", value: "(empty)", label: "Outcome", note: "Empty: S3 accepted the change." },
          { key: "readOnly", value: "false", label: "Changes state?", note: "This call changes a setting." },
          { key: "managementEvent", value: "true", label: "Kind of event", note: "Bucket configuration, so a management event." },
        ],
        summary: "One short call and the bucket's own request log stops. GuardDuty scored it Low as Stealth:S3/ServerAccessLoggingDisabled. ATT&CK files this kind of move under Defense Impairment (TA0112), and a Low score says nothing about how much it matters to you.",
      },
      {
        kind: "inspect",
        title: "Which Camera Goes Dark?",
        prompt: "Eun-ji keeps a list of the calls that touch logging, because each one darkens something different. Open each one and see what it touches, and what keeps running with no trail at all.",
        artifact: "Eun-ji's watch list · logging calls and independent sources",
        items: [
          { id: "stop", text: "StopLogging", tag: "CloudTrail", tone: "warn", note: "Recording pauses on one trail until someone calls StartLogging." },
          { id: "del", text: "DeleteTrail", tag: "CloudTrail", tone: "warn", note: "The trail's configuration is removed. Files it wrote earlier live in S3, so deleting them would be a separate call on that bucket." },
          { id: "sel", text: "PutEventSelectors", tag: "CloudTrail", tone: "warn", note: "Changes which events a trail collects. It can drop data events and leave management events flowing." },
          { id: "upd", text: "UpdateTrail", tag: "CloudTrail", tone: "warn", note: "Can turn a multi-Region trail into a single-Region one, or point it at a different bucket." },
          { id: "flow", text: "DeleteFlowLogs", tag: "VPC", tone: "warn", note: "Flow records stop for that VPC, subnet or network interface." },
          { id: "det", text: "DeleteDetector", tag: "GuardDuty", tone: "warn", note: "Turns GuardDuty off in that Region and removes its existing findings." },
          { id: "hist", text: "CloudTrail Event History", tag: "Keeps running", tone: "trust", note: "90 days of management events in each Region, kept whether or not a trail exists. Data events aren't included." },
          { id: "gd", text: "GuardDuty's CloudTrail stream", tag: "Keeps running", tone: "trust", note: "GuardDuty reads its own independent stream of CloudTrail events, not your trail. Pausing a trail doesn't blind it." },
          { id: "bill", text: "The bill", tag: "Keeps running", tone: "trust", note: "Compute costs arrive however quiet the logs are. Often the first sign of a mining fleet." },
        ],
      },
    ],

    // ── Reading 6: mining and defensive controls ──
    "aws-r6": [
      {
        kind: "worksheet",
        title: "Price the Fleet",
        prompt: "The svc-qc-uploader key had EC2 rights for the QC runners. At 02:05 it started launching. Westmarch works in eu-west-1 and nowhere else. Add up what it cost before the 09:05 billing alert.",
        primer: {
          title: "Why stolen keys turn into mining",
          points: [
            "Mining needs huge, sustained compute, and someone else's account pays for it.",
            "The pattern: large GPU or compute-optimised instances, in Regions the victim doesn't use, often several at once.",
            "The instances connect outbound to a mining pool, which GuardDuty reports as `CryptoCurrency:EC2/BitcoinTool.B!DNS`.",
            "The cost is often noticed first, as a billing alert. When a trail is stopped moments before a burst of `RunInstances`, read the two as one plan.",
          ],
          example: {
            label: "How to price a launch",
            lines: [
              "4 instances at USD 2 an hour cost USD 8 an hour.",
              "Left running for 10 hours, that is USD 80. Size and hours do the damage.",
            ],
          },
        },
        caption: "CloudTrail · RunInstances by svc-qc-uploader · rate from Westmarch's price sheet",
        columns: ["eventTime", "awsRegion", "instanceType", "Instances", "USD per hour each"],
        rows: [
          ["11-05 02:05:33", "sa-east-1", "g4dn.12xlarge", "12", "6"],
          ["11-05 02:06:10", "ap-southeast-2", "g5.24xlarge", "10", "9"],
          ["11-05 02:06:41", "ca-central-1", "c5.24xlarge", "8", "4"],
        ],
        questions: [
          { id: "count", q: "How many instances did the key launch in all?", hint: "Add the Instances column.", answer: ["30", "thirty"], why: "12 + 10 + 8. Three Regions, none of them Westmarch's." },
          { id: "rate", q: "What did the fleet cost per hour, in USD?", hint: "Instances times rate, for each row, then add.", answer: ["194", "$194", "USD 194"], why: "72 + 90 + 32 = 194 an hour." },
          { id: "total", q: "Round it to 7 hours, from 02:05 to the 09:05 alert. What was the bill so far, in USD?", hint: "Hourly cost times hours.", answer: ["1358", "1,358", "$1358", "$1,358", "USD 1358"], why: "194 x 7 = 1,358. This is a modest fleet. Larger ones reach tens of thousands in hours." },
        ],
      },
      {
        kind: "match",
        title: "Who Would Have Caught It?",
        prompt: "Eun-ji writes the review now, while everyone remembers. Match each control to what it would have done for Westmarch.",
        pairs: [
          { id: "a", left: "CloudTrail log file validation", right: "Proves afterwards whether delivered log files were changed or deleted", why: "It uses signed digest files, so tampering with a log shows." },
          { id: "b", left: "Logs stored in a separate account", right: "Keeps the record out of reach of a compromised production account", why: "Even with `s3:*` on `*` in production, that bucket sits in another account." },
          { id: "c", left: "An alert on StopLogging, DeleteTrail and UpdateTrail", right: "Pages someone whichever identity made the call", why: "No exceptions, because an attacker can be using any identity." },
          { id: "d", left: "GuardDuty on in every Region", right: "Raises a finding in a Region nobody works in", why: "GuardDuty is enabled Region by Region. A mining fleet goes where the sensors aren't." },
          { id: "e", left: "S3 Protection and Malware Protection in GuardDuty", right: "Adds object-level and malware detection on top of the base detector", why: "These are extra protection plans, and they have to be on." },
          { id: "f", left: "An AWS Budgets alert", right: "Catches runaway compute spend when security alerting stays silent", why: "It works from the bill, so a quiet log doesn't stop it." },
        ],
      },
    ],

    // ── Reading 7: containing an identity ──
    "aws-r7": [
      {
        kind: "anatomy",
        title: "Read the Revoke Policy",
        prompt: "The stolen session is dead, and this is what killed it. Eun-ji asks you to read it the way you read the others, because everything else that morning hangs on knowing what it does and doesn't touch.",
        primer: {
          title: "Freeze, then rotate",
          points: [
            "To freeze an identity, attach an inline policy that denies everything, or detach what it has. It still exists, so its policy history stays readable.",
            "An explicit **Deny** beats every Allow, wherever the Allow comes from.",
            "**Rotate last.** Once it's contained and the evidence is captured: remove the old credential, issue a new one, reset the password, and make any MFA device register again.",
          ],
          example: {
            label: "A Deny with a narrow aim",
            lines: [
              "`{\"Effect\": \"Deny\", \"Action\": \"s3:DeleteBucket\", \"Resource\": \"*\"}`",
              "Whatever else this identity is allowed, it can't delete a bucket.",
            ],
          },
        },
        source: "IAM · wm-lims-sync-role · Inline policy AWSRevokeOlderSessions",
        fields: [
          { key: "Effect", value: "Deny", label: "Effect", note: "An explicit Deny. No Allow on the role can outweigh it." },
          { key: "Action", value: "*", label: "What", note: "Every action." },
          { key: "Resource", value: "*", label: "On what", note: "Every resource." },
          { key: "Condition", value: "{\"DateLessThan\": {\"aws:TokenIssueTime\": \"2026-11-05T10:03:27Z\"}}", label: "When", note: "Only credentials issued before this moment. A session issued after it isn't affected, which is why tonight's function run still works." },
          { key: "Principal", value: "(none)", label: "Who", note: "Attached to the role, so it applies to the role's sessions. An identity-based policy has no Principal." },
        ],
        summary: "Every session of this role issued before 10:03:27 is denied everything, and new sessions work. aws:TokenIssueTime only exists on temporary credentials, so this policy never touches a long-term key.",
      },
    ],

    // ── Boss drill: the decisive signal, on other alerts ──
    "aws-ac1": [
      {
        kind: "defuse",
        title: "Did It Fire Right, and Was It Allowed?",
        prompt: "Eun-ji set up extra rules after the incident, and Friday's queue is full of them. Before you take the old case on the desk, clear four alerts from Westmarch. For each one, read what is known and cut the one wire that fits.",
        primer: {
          title: "Three answers to one alert",
          points: [
            "**True positive:** the rule fired on what it was built to catch, and the activity is malicious.",
            "**Benign true positive:** the rule fired on what it was built to catch, and the activity is real but authorised.",
            "**False positive:** the rule fired on something it was never meant to match.",
            "So there are two separate questions. Did the rule do its job? And was this activity authorised? Answer the second from the record and from what is written down about the asset: identity, address, client, time, ticket.",
          ],
          example: {
            label: "One door sensor, three nights",
            lines: [
              "Forced at 03:00 by an intruder: true positive.",
              "Opened at 03:00 by the duty engineer on a logged call-out: benign true positive.",
              "Tripped at 03:00 by a draught: false positive.",
            ],
          },
        },
        device: "Friday watch list · four alerts",
        seconds: 100,
        rounds: [
          {
            id: "tf",
            state: "Rule: new S3 replication rule. PutBucketReplication on wm-dr-backups by terraform-ci-role/run-9127, from 198.51.100.42, the CI runner's NAT address, client Terraform/1.9.8. CHG-4417 names this bucket and the DR account.",
            wires: [
              { id: "tp", label: "Escalate" },
              { id: "btp", label: "Close as benign true positive" },
              { id: "fp", label: "Close as false positive, tune the rule" },
            ],
            cut: "btp",
            hint: "Did a replication rule really get written? Then who said it could be?",
            why: "A real replication rule was written, so the detection worked and the rule needs no tuning. The role, address, client and change record all agree, so it was authorised. Close it and cite CHG-4417.",
          },
          {
            id: "name",
            state: "Rule: any identity with \"root\" in its name. Hit: IAM user root-cause-bot, the reliability team's dashboard reader, calling ListDashboards. The rule's query is userIdentity.userName contains \"root\".",
            wires: [
              { id: "btp", label: "Close as benign true positive" },
              { id: "tp", label: "Escalate" },
              { id: "fp", label: "Close as false positive, tune the rule" },
            ],
            cut: "fp",
            hint: "What was this rule meant to catch? Is that what it caught?",
            why: "The rule was built for the root user, whose userIdentity.type is Root. It matched a word in a name instead. The rule is what's wrong, so fix the query.",
          },
          {
            id: "secret",
            state: "Rule: secret read by a role. GetSecretValue by wm-report-role/wm-report-builder, readOnly true. The function reads this secret nightly at 02:00 from 198.51.100.40. This call came at 03:12 from 203.0.113.140, client aws-cli/2.15.30.",
            wires: [
              { id: "tp", label: "Escalate" },
              { id: "fp", label: "Close as false positive, tune the rule" },
              { id: "btp", label: "Close as benign true positive" },
            ],
            cut: "tp",
            hint: "The identity fits. Do the other fields?",
            why: "Right role, right secret, and every other field is wrong: the hour, the address, the client. readOnly true only means nothing was changed. The caller now holds the secret.",
          },
          {
            id: "ticket",
            state: "Rule: bucket policy change. PutBucketPolicy by terraform-ci-role/run-9130, from 198.51.100.42. CHG-4432 approves a change to wm-press-kit. The record's requestParameters.bucketName is wm-batch-records.",
            wires: [
              { id: "btp", label: "Close as benign true positive" },
              { id: "tp", label: "Escalate" },
              { id: "fp", label: "Close as false positive, tune the rule" },
            ],
            cut: "tp",
            hint: "Read the ticket against the record, field by field.",
            why: "The role and address are the usual ones, and the ticket is real, but it covers a different bucket. An approval only authorises what it names. Ask the change owner, and treat it as live until they answer.",
          },
        ],
        lesson: "A rule can be right and the activity fine. A familiar identity can still be the worst thing in the queue. Keep the two questions apart, and let the fields, not the mood of the week, decide.",
      },
    ],

    // ── Reading 5: reading CloudTrail in a SIEM, and the last hunt ──
    "aws-r5": [
      {
        kind: "sort",
        title: "Weigh the Call",
        prompt: "A morning's CloudTrail is thousands of rows, so Eun-ji reads by weight. Sort each call by what it can do, and read the readOnly value on the card.",
        primer: {
          title: "Five checks, then weigh it",
          points: [
            "**WHO:** `userIdentity.type` and `arn`. A long-term user, or a role session? **WHERE:** `sourceIPAddress`, `userAgent` and `awsRegion`. Do they fit that identity?",
            "**WHAT and OUTCOME:** `eventName`, `eventSource`, `errorCode`. **PATTERN:** pivot on the same identity and address across hours or days.",
            "A wall of `AccessDenied` from one identity is a signal in itself: someone is testing what a credential can do.",
            "**Blast radius** is how far a change reaches. `readOnly: false` says state changed, and the service and action say how far that goes.",
          ],
          example: {
            label: "Two changes, two reaches",
            lines: [
              "`UpdateAccountPasswordPolicy`, readOnly false: applies to every IAM user in the account.",
              "`PutBucketTagging`, readOnly false: one label on one bucket.",
            ],
          },
        },
        buckets: [
          { id: "wide", label: "Changes state, wide reach" },
          { id: "small", label: "Changes state, small reach" },
          { id: "look", label: "Only reads" },
        ],
        items: [
          { id: "a", text: "PutUserPolicy · readOnly false", bucket: "wide", why: "It rewrites what an identity may do. IAM changes reach as far as the identity does." },
          { id: "b", text: "ListRoles · readOnly true", bucket: "look", why: "Changes nothing. Worth noting as reconnaissance, and worth a pivot." },
          { id: "c", text: "DeleteFlowLogs · readOnly false", bucket: "wide", why: "It removes a record for a whole VPC. Logging changes reach everything you would have seen." },
          { id: "d", text: "CreateTags · readOnly false", bucket: "small", why: "It writes a label on one resource and grants nothing." },
          { id: "e", text: "ModifySnapshotAttribute · readOnly false, shared with another account", bucket: "wide", why: "It hands a disk's whole contents to another account." },
          { id: "f", text: "DescribeVolumes · readOnly true", bucket: "look", why: "Changes nothing. One of the commonest calls in any account." },
          { id: "g", text: "PutMetricAlarm · readOnly false, a new low-disk alarm", bucket: "small", why: "It adds one monitoring alarm and touches no permission." },
          { id: "h", text: "GetBucketAcl · readOnly true", bucket: "look", why: "It reads a setting and changes nothing." },
        ],
      },
      {
        kind: "hunt",
        title: "Did They Leave a Way Back?",
        prompt: "Eun-ji's last question. The stolen session is dead, the svc-qc-uploader key is Inactive, the fleet is gone, the replication rule is removed, and bucket logging is back on. So is anything still standing that wouldn't need a credential? Build the hunt one line at a time. Every result you see is what that line really returns.",
        primer: {
          title: "CloudTrail as a table",
          points: [
            "In a SIEM, CloudTrail is a table. `AWSCloudTrail` is Microsoft Sentinel's name for it, in KQL (Kusto Query Language). The fields are the ones you know: `UserIdentityArn`, `SourceIpAddress`, `ReadOnly`, `ErrorCode`.",
            "Each line filters what the line above returned.",
            "`==` matches exactly. `has` finds a whole term inside a value. `startswith` matches how a value begins. `!in` leaves out a list. `isempty()` is true when a column is blank.",
          ],
          example: {
            label: "A short hunt on another table",
            lines: [
              "`AWSVPCFlow`",
              "`| where Action == \"REJECT\"`",
              "`| where DstPort == 22`",
              "Each line narrows the one above: refused connections to SSH.",
            ],
          },
        },
        language: "KQL",
        console: "Logs",
        start: "AWSCloudTrail",
        goal: "one row: the change that still stands",
        tables: [
          {
            name: "AWSCloudTrail",
            note: "CloudTrail events.",
            columns: ["TimeGenerated", "EventName", "EventSource", "UserIdentityType", "UserIdentityArn", "SourceIpAddress", "ReadOnly", "ErrorCode", "RequestParameters"],
            rows: [
              ["11-05 00:15", "PutBucketTagging", "s3.amazonaws.com", "AssumedRole", "arn:aws:sts::444455556666:assumed-role/wm-lims-sync-role/wm-lims-sync", "198.51.100.40", "false", "", "{\"bucketName\":\"wm-seq-runs\"}"],
              ["11-05 00:20", "GetBucketLocation", "s3.amazonaws.com", "AssumedRole", "arn:aws:sts::444455556666:assumed-role/wm-lims-sync-role/wm-lims-sync", "198.51.100.40", "true", "", "{\"bucketName\":\"wm-seq-runs\"}"],
              ["11-05 00:40", "PutBucketTagging", "s3.amazonaws.com", "AssumedRole", "arn:aws:sts::444455556666:assumed-role/wm-lims-sync-role/wm-lims-sync", "198.51.100.40", "false", "", "{\"bucketName\":\"wm-seq-runs\"}"],
              ["11-05 01:03", "ListBuckets", "s3.amazonaws.com", "AssumedRole", "arn:aws:sts::444455556666:assumed-role/wm-lims-sync-role/wm-lims-sync", "198.51.100.77", "true", "", "null"],
              ["11-05 01:09", "GetBucketReplication", "s3.amazonaws.com", "AssumedRole", "arn:aws:sts::444455556666:assumed-role/wm-lims-sync-role/wm-lims-sync", "198.51.100.77", "true", "ReplicationConfigurationNotFoundError", "{\"bucketName\":\"wm-seq-runs\"}"],
              ["11-05 01:12", "PutBucketReplication", "s3.amazonaws.com", "AssumedRole", "arn:aws:sts::444455556666:assumed-role/wm-lims-sync-role/wm-lims-sync", "198.51.100.77", "false", "", "{\"bucketName\":\"wm-seq-runs\",\"Account\":\"777788889999\"}"],
              ["11-05 01:20", "PutBucketLogging", "s3.amazonaws.com", "AssumedRole", "arn:aws:sts::444455556666:assumed-role/wm-lims-sync-role/wm-lims-sync", "198.51.100.77", "false", "", "{\"bucketName\":\"wm-seq-runs\"}"],
              ["11-05 01:30", "GetBucketLocation", "s3.amazonaws.com", "AssumedRole", "arn:aws:sts::444455556666:assumed-role/wm-lims-sync-role/wm-lims-sync", "198.51.100.40", "true", "", "{\"bucketName\":\"wm-seq-runs\"}"],
              ["11-05 02:01", "DescribeRegions", "ec2.amazonaws.com", "IAMUser", "arn:aws:iam::444455556666:user/svc-qc-uploader", "198.51.100.77", "true", "", "null"],
              ["11-05 02:05", "RunInstances", "ec2.amazonaws.com", "IAMUser", "arn:aws:iam::444455556666:user/svc-qc-uploader", "198.51.100.77", "false", "", "{\"instanceType\":\"g4dn.12xlarge\"}"],
              ["11-05 02:06", "RunInstances", "ec2.amazonaws.com", "IAMUser", "arn:aws:iam::444455556666:user/svc-qc-uploader", "198.51.100.77", "false", "", "{\"instanceType\":\"g5.24xlarge\"}"],
              ["11-05 02:06", "RunInstances", "ec2.amazonaws.com", "IAMUser", "arn:aws:iam::444455556666:user/svc-qc-uploader", "198.51.100.77", "false", "", "{\"instanceType\":\"c5.24xlarge\"}"],
              ["11-05 03:10", "GetBucketPolicy", "s3.amazonaws.com", "AssumedRole", "arn:aws:sts::444455556666:assumed-role/wm-lims-sync-role/wm-lims-sync", "203.0.113.91", "true", "NoSuchBucketPolicy", "{\"bucketName\":\"wm-cohort-archive\"}"],
              ["11-05 03:12", "PutBucketPolicy", "s3.amazonaws.com", "AssumedRole", "arn:aws:sts::444455556666:assumed-role/wm-lims-sync-role/wm-lims-sync", "203.0.113.91", "false", "", "{\"bucketName\":\"wm-cohort-archive\",\"Principal\":{\"AWS\":\"arn:aws:iam::777788889999:root\"}}"],
              ["11-05 03:12", "PutBucketPolicy", "s3.amazonaws.com", "AssumedRole", "arn:aws:sts::444455556666:assumed-role/wm-lims-sync-role/wm-lims-sync", "203.0.113.91", "false", "AccessDenied", "{\"bucketName\":\"wm-audit-logs\"}"],
              ["11-05 03:14", "CreateAccessKey", "iam.amazonaws.com", "AssumedRole", "arn:aws:sts::444455556666:assumed-role/wm-lims-sync-role/wm-lims-sync", "203.0.113.91", "false", "AccessDenied", "{\"userName\":\"svc-qc-uploader\"}"],
              ["11-05 04:30", "PutBucketPolicy", "s3.amazonaws.com", "AssumedRole", "arn:aws:sts::444455556666:assumed-role/terraform-ci-role/run-8902", "198.51.100.42", "false", "", "{\"bucketName\":\"wm-press-kit\"}"],
            ],
          },
          {
            name: "AWSGuardDuty",
            note: "GuardDuty findings.",
            columns: ["TimeGenerated", "ActivityType", "Severity", "Title"],
            rows: [
              ["11-05 01:13", "Exfiltration:IAMUser/AnomalousBehavior", "8", "Anomalous exfiltration API call"],
              ["11-05 01:21", "Stealth:S3/ServerAccessLoggingDisabled", "2", "Server access logging disabled"],
            ],
          },
        ],
        rungs: [
          {
            id: "who", ask: "Line 2: follow the credential.",
            choices: [
              { id: "a", text: '| where SourceIpAddress == "198.51.100.77"', why: "That follows one address. It picks up the other identity's calls too, and every row from 203.0.113.91 is missing.", apply: { op: "where", col: "SourceIpAddress", test: "eq", value: "198.51.100.77" } },
              { id: "b", text: '| where UserIdentityArn has "wm-lims-sync-role"', right: true, why: "Every call on this role, from any address. Twelve rows, and that includes the function's own.", apply: { op: "where", col: "UserIdentityArn", test: "has", value: "wm-lims-sync-role" } },
              { id: "c", text: '| where UserIdentityType == "IAMUser"', why: "That is the other credential. A role session's type is AssumedRole.", apply: { op: "where", col: "UserIdentityType", test: "eq", value: "IAMUser" } },
            ],
          },
          {
            id: "where", ask: "Line 3: take out the function's own traffic.",
            choices: [
              { id: "a", text: '| where SourceIpAddress == "203.0.113.91"', why: "That keeps one outside address and drops the night's other. You know two. You may not know all of them.", apply: { op: "where", col: "SourceIpAddress", test: "eq", value: "203.0.113.91" } },
              { id: "b", text: '| where UserIdentityType == "AssumedRole"', why: "Every row here is already AssumedRole, so nothing moved. The function's own calls are still in the result.", apply: { op: "where", col: "UserIdentityType", test: "eq", value: "AssumedRole" } },
              { id: "c", text: '| where SourceIpAddress !in ("198.51.100.40")', right: true, why: "Removing the one address you can vouch for keeps every address you can't. Eight rows left, the same eight GuardDuty counted.", apply: { op: "where", col: "SourceIpAddress", test: "notin", value: ["198.51.100.40"] } },
            ],
          },
          {
            id: "state", ask: "Line 4: keep the calls that changed something.",
            choices: [
              { id: "a", text: "| where ReadOnly == true", why: "Those are the lookups: useful for intent, but none of them left anything behind.", apply: { op: "where", col: "ReadOnly", test: "eq", value: "true" } },
              { id: "b", text: "| where ReadOnly == false", right: true, why: "State-changing calls only. Five rows.", apply: { op: "where", col: "ReadOnly", test: "eq", value: "false" } },
              { id: "c", text: '| where EventName startswith "Get"', why: "A name filter is a guess at meaning, and these are reads again. ReadOnly already says it.", apply: { op: "where", col: "EventName", test: "startswith", value: "Get" } },
            ],
          },
          {
            id: "worked", ask: "Line 5: keep the ones that worked.",
            choices: [
              { id: "a", text: '| where EventSource == "iam.amazonaws.com"', why: "CreateAccessKey looks like the backdoor, but read its ErrorCode: AccessDenied. A refused call left nothing.", apply: { op: "where", col: "EventSource", test: "eq", value: "iam.amazonaws.com" } },
              { id: "b", text: '| where ErrorCode == "AccessDenied"', why: "Those are the refusals. They show what the intruder wanted, not what they got.", apply: { op: "where", col: "ErrorCode", test: "eq", value: "AccessDenied" } },
              { id: "c", text: "| where isempty(ErrorCode)", right: true, why: "A blank ErrorCode means the call went through. Three rows.", apply: { op: "where", col: "ErrorCode", test: "eq", value: "" } },
            ],
          },
          {
            id: "left", ask: "Line 6: the rule and the logging were fixed yesterday. Keep what nobody has dealt with.",
            choices: [
              { id: "a", text: '| where EventName !in ("PutBucketReplication", "PutBucketLogging")', right: true, why: "One row: PutBucketPolicy on wm-cohort-archive, naming account 777788889999. Nobody had opened that bucket all week.", apply: { op: "where", col: "EventName", test: "notin", value: ["PutBucketReplication", "PutBucketLogging"] } },
              { id: "b", text: '| where RequestParameters has "wm-seq-runs"', why: "Those are the two you already fixed.", apply: { op: "where", col: "RequestParameters", test: "has", value: "wm-seq-runs" } },
              { id: "c", text: '| where RequestParameters has "777788889999"', why: "Two rows, and one is the rule you removed. Filter on what is still open, not on what looks familiar.", apply: { op: "where", col: "RequestParameters", test: "has", value: "777788889999" } },
            ],
          },
        ],
        expect: 1,
        lesson: "A bucket policy doesn't care that a session died. It names an account, and it keeps granting until someone removes it. After any compromise, hunt for the state-changing calls that worked, on the credential and not on one address, because that is where the way back lives. Nobody touched the root account. With s3:* on *, nobody had to.",
      },
    ],
  },
};
