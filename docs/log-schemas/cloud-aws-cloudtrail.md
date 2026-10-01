# AWS CloudTrail — log schema card

CloudTrail records AWS API activity. It is a **JSON-native** source. Show each event as the
JSON object AWS delivers, nested exactly as documented. Do **not** flatten into `aws.cloudtrail.*`
(ECS/Elastic) or wrap it in a Wazuh `data.*` envelope.

## 1. Official sources

- CloudTrail record contents (every top-level field, types, optionality, enums):
  https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html
  — confirmed `eventVersion` current = **1.11**; `eventType`, `eventCategory`, `readOnly` (boolean, not string),
  `managementEvent`, `tlsDetails`, `sessionCredentialFromConsole`, `addendum`, `sharedEventID`, `vpcEndpointId`,
  `vpcEndpointAccountId`, `serviceEventDetails`, `edgeDeviceDetails`, `eventContext`.
- `userIdentity` element (all types, `sessionContext`, `sessionIssuer`, `webIdFederationData`,
  `onBehalfOf`, `credentialId`, `invokedBy`, `assumedRoot`, `ec2RoleDelivery`, `sourceIdentity`):
  https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html
- Console sign-in events (ConsoleLogin success/failure, root, MFA, `additionalEventData`):
  https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-aws-console-sign-in-events.html
- S3 CloudTrail entries & data events (`additionalEventData` keys, `resources[]`):
  https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-understanding-s3-entries.html ,
  https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-request-identification.html
- Delivery/timing (90-day Event history; ~5-min S3 delivery; file-name format):
  https://docs.aws.amazon.com/awscloudtrail/latest/userguide/how-cloudtrail-works.html
- Real per-API sample shapes cross-checked against elastic/integrations raw test inputs
  (`packages/aws/data_stream/cloudtrail/_dev/test/pipeline/*.log`) and panther-labs/panther-analysis
  (`rules/aws_cloudtrail_rules/*.yml`).

## 2. Native format & delivery

- **To S3 (a trail):** gzipped JSON. The file is an object `{"Records":[ {event}, {event}, ... ]}` —
  an array of event objects. File key:
  `s3://<bucket>/AWSLogs/<accountId>/CloudTrail/<region>/<YYYY>/<MM>/<DD>/<accountId>_CloudTrail_<region>_<YYYYMMDD>T<HHmm>Z_<16-char-hash>.json.gz`
- **To CloudWatch Logs / Event history / EventBridge:** one event object per record (no `Records` wrapper).
- **We standardise on the single bare event object** (what the `Records[]` array holds). For the SOC platform
  show the object exactly as below. When a scenario needs the S3 shape, wrap one or more objects in `{"Records":[ ... ]}`.
- Timing: Event history keeps 90 days. Trails deliver to S3 ~every 5 min; a given event typically lands within
  ~5 min of the call but can be delayed (an `addendum` with `reason:"DELIVERY_DELAY"` may appear).
- `eventTime` is the API-completion time at the service endpoint (UTC, `YYYY-MM-DDTHH:MM:SSZ`), **not** delivery time.

## 3. Core field reference (top level)

| Field | Type | Notes / enum |
|---|---|---|
| `eventVersion` | string | Current `1.11`; older real events carry `1.05`–`1.10`. Keep the version consistent with which fields are present (e.g. `tlsDetails` is 1.08+; `eventCategory`/`readOnly` are 1.07+/1.01+). |
| `userIdentity` | object | See §3a. Always present. |
| `eventTime` | string | UTC ISO8601 basic, e.g. `2026-09-30T14:22:10Z`. |
| `eventSource` | string | `<service>.amazonaws.com`. Real forms: `s3.amazonaws.com`, `iam.amazonaws.com`, `sts.amazonaws.com`, `ec2.amazonaws.com`, `signin.amazonaws.com`, `cloudtrail.amazonaws.com`, `secretsmanager.amazonaws.com`, `bedrock.amazonaws.com`, `kms.amazonaws.com`, `monitoring.amazonaws.com` (CloudWatch). |
| `eventName` | string | The API action, e.g. `GetObject`, `ConsoleLogin`, `AssumeRole`, `CreateUser`. |
| `awsRegion` | string | e.g. `us-east-1`. |
| `sourceIPAddress` | string | Caller IP. For AWS-service callers it is the service DNS name (e.g. `config.amazonaws.com`) or `AWS Internal`. |
| `userAgent` | string | e.g. `aws-cli/2.17.60 md/awscrt#0.21.2 ...`, `Boto3/1.35.50 ...`, `console.amazonaws.com`, `signin.amazonaws.com`, a browser UA for console actions. |
| `errorCode` | string (opt) | Only on failures. Examples: `AccessDenied`, `Client.UnauthorizedOperation`, `UnauthorizedOperation`, `AccessDeniedException`, `NoSuchBucket`, `InvalidUserID.NotFound`, `Client.RequestLimitExceeded`, `VpceAccessDenied` (network events). |
| `errorMessage` | string (opt) | Human-readable failure reason. |
| `requestParameters` | object/null | API-specific. `null` for ConsoleLogin. |
| `responseElements` | object/null | `null` for read-only APIs. |
| `additionalEventData` | object (opt) | Non-request/response data. S3 keys, ConsoleLogin keys — see §3b. |
| `requestID` | string (opt) | Service-generated request id. Absent on some sign-in events. |
| `eventID` | string | GUID, unique per event (UUID format). |
| `readOnly` | **boolean** (opt) | `true`/`false` — **never** a string `"true"`. 1.01+. |
| `eventType` | string | `AwsApiCall` \| `AwsServiceEvent` \| `AwsConsoleAction` \| `AwsConsoleSignIn` \| `AwsCloudTrailInsight`. (`AwsVpceEvent(s)` for network activity events.) |
| `managementEvent` | boolean (opt) | `true` for management, `false` for data events. 1.06+. |
| `eventCategory` | string | `Management` \| `Data` \| `Insight` \| `NetworkActivity`. 1.07+. |
| `recipientAccountId` | string | 12-digit account that received the event (may differ from `userIdentity.accountId` on cross-account). |
| `resources` | array (opt) | For data events and some management events. Each: `{"ARN":..., "accountId":..., "type":"AWS::<svc>::<type>"}`. |
| `apiVersion` | string (opt) | API version for the call. |
| `tlsDetails` | object (opt) | `{tlsVersion, cipherSuite, clientProvidedHostHeader}`. 1.08+. Absent if the call was made by an AWS service on your behalf. |
| `sessionCredentialFromConsole` | string (opt) | Only shown when `"true"` (console-originated session). |
| `vpcEndpointId` | string (opt) | e.g. `vpce-16a4477f` when the call traversed a VPC endpoint. |
| `sharedEventID` | string (opt) | GUID shared across accounts for one cross-account action. |
| `addendum` | object (opt) | `{reason: DELIVERY_DELAY|UPDATED_DATA|SERVICE_OUTAGE, updatedFields?, originalRequestID?, originalEventID?}`. |
| `serviceEventDetails` | object (opt) | Present when `eventType=AwsServiceEvent`. |
| `insightDetails` | object (opt) | Present when `eventType=AwsCloudTrailInsight` / `eventCategory=Insight`. |

### 3a. `userIdentity`

`type` enum: `Root`, `IAMUser`, `AssumedRole`, `Role`, `FederatedUser`, `AWSAccount`, `AWSService`,
`IdentityCenterUser`, `SAMLUser`, `WebIdentityUser`, `Directory`, `Unknown`.

Common fields: `type`, `principalId`, `arn`, `accountId`, `accessKeyId`, `userName`, `invokedBy`,
`sessionContext`, `onBehalfOf`, `credentialId`, `identityProvider` (SAML/WebIdentity).

- **IAMUser** principalId = `AIDA...` (21 chars). accessKeyId used = `AKIA...` (long-term).
- **AssumedRole / role session** principalId = `AROA...:<sessionName>`; `arn` =
  `arn:aws:sts::<acct>:assumed-role/<RoleName>/<sessionName>`; accessKeyId = `ASIA...` (temporary).
  Carries `sessionContext.sessionIssuer` (the role) + `attributes{creationDate, mfaAuthenticated}`.
- `sessionContext.attributes.mfaAuthenticated` = `"true"`/`"false"` (**string**).
- `sessionContext.ec2RoleDelivery` = `"1.0"` (IMDSv1) / `"2.0"` (IMDSv2) when creds came from EC2 IMDS.
- Access-key prefixes: `AKIA`=IAM user long-term, `ASIA`=temporary/STS, `AIDA`=IAM user unique id,
  `AROA`=role unique id, `ANPA`/`ANVA` other. Redacted/omitted → `""`.

### 3b. `additionalEventData` — common keys

- **S3:** `SignatureVersion` (`SigV2`/`SigV4`), `CipherSuite`, `AuthenticationMethod`
  (`AuthHeader`/`QueryString`), `x-amz-id-2`, `bytesTransferredIn`, `bytesTransferredOut`, `aclRequired` (`Yes`).
- **ConsoleLogin:** `LoginTo` (URL), `MobileVersion` (`Yes`/`No`), `MFAUsed` (`Yes`/`No`), `MFAIdentifier` (MFA ARN when used).

---

## 4. Realistic samples — coherent attack chains

### Attack chain A — leaked access key → recon → S3 exfil → public exposure → IAM persistence → defense evasion
Account `123456789012`, compromised IAM user `svc-deploy`, attacker IP `203.0.113.77`.

**A1 — `GetCallerIdentity` from a foreign IP (attacker validating the stolen key)**
```json
{
  "eventVersion": "1.11",
  "userIdentity": {
    "type": "IAMUser",
    "principalId": "AIDA2QXCZ4R7KJ6PLMN3A",
    "arn": "arn:aws:iam::123456789012:user/svc-deploy",
    "accountId": "123456789012",
    "accessKeyId": "AKIA2QXCZ4R7KJ6PLMN3",
    "userName": "svc-deploy"
  },
  "eventTime": "2026-09-30T02:14:07Z",
  "eventSource": "sts.amazonaws.com",
  "eventName": "GetCallerIdentity",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.77",
  "userAgent": "Boto3/1.34.12 md/Botocore#1.34.12 ua/2.0 os/linux#5.15.0 lang/python#3.11.4",
  "requestParameters": null,
  "responseElements": null,
  "requestID": "7b1f0e9c-4c1a-49d2-9a2b-6f2b1d9a7e01",
  "eventID": "0a2e5d4b-1f33-4c88-9bb1-2c4e6a8f0d12",
  "readOnly": true,
  "eventType": "AwsApiCall",
  "managementEvent": true,
  "recipientAccountId": "123456789012",
  "eventCategory": "Management",
  "tlsDetails": {
    "tlsVersion": "TLSv1.3",
    "cipherSuite": "TLS_AES_128_GCM_SHA256",
    "clientProvidedHostHeader": "sts.us-east-1.amazonaws.com"
  }
}
```

**A2 — `ListBuckets` enumeration (same key, same IP)**
```json
{
  "eventVersion": "1.11",
  "userIdentity": {
    "type": "IAMUser",
    "principalId": "AIDA2QXCZ4R7KJ6PLMN3A",
    "arn": "arn:aws:iam::123456789012:user/svc-deploy",
    "accountId": "123456789012",
    "accessKeyId": "AKIA2QXCZ4R7KJ6PLMN3",
    "userName": "svc-deploy"
  },
  "eventTime": "2026-09-30T02:15:40Z",
  "eventSource": "s3.amazonaws.com",
  "eventName": "ListBuckets",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.77",
  "userAgent": "Boto3/1.34.12 md/Botocore#1.34.12 ua/2.0 os/linux#5.15.0 lang/python#3.11.4",
  "requestParameters": { "host": ["s3.us-east-1.amazonaws.com"] },
  "responseElements": null,
  "additionalEventData": { "SignatureVersion": "SigV4", "AuthenticationMethod": "AuthHeader" },
  "requestID": "V9Z2K4C8TQ1N7PX3",
  "eventID": "1d4f8c2a-7e55-4b19-8a6c-3f9b0e1c7d44",
  "readOnly": true,
  "eventType": "AwsApiCall",
  "managementEvent": true,
  "recipientAccountId": "123456789012",
  "eventCategory": "Management",
  "tlsDetails": {
    "tlsVersion": "TLSv1.3",
    "cipherSuite": "TLS_AES_128_GCM_SHA256",
    "clientProvidedHostHeader": "s3.amazonaws.com"
  }
}
```

**A3 — `GetObject` bulk download (S3 data event, `eventCategory:Data`, `managementEvent:false`, bytes transferred)**
```json
{
  "eventVersion": "1.11",
  "userIdentity": {
    "type": "IAMUser",
    "principalId": "AIDA2QXCZ4R7KJ6PLMN3A",
    "arn": "arn:aws:iam::123456789012:user/svc-deploy",
    "accountId": "123456789012",
    "accessKeyId": "AKIA2QXCZ4R7KJ6PLMN3",
    "userName": "svc-deploy"
  },
  "eventTime": "2026-09-30T02:17:02Z",
  "eventSource": "s3.amazonaws.com",
  "eventName": "GetObject",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.77",
  "userAgent": "aws-cli/2.17.60 md/awscrt#0.21.2 ua/2.0 os/linux#5.15.0 lang/python#3.11.4 md/command#s3.cp",
  "requestParameters": {
    "bucketName": "nexacorp-customer-exports",
    "Host": "nexacorp-customer-exports.s3.us-east-1.amazonaws.com",
    "key": "2026/pii/customers_full.csv.gz"
  },
  "responseElements": null,
  "additionalEventData": {
    "SignatureVersion": "SigV4",
    "CipherSuite": "TLS_AES_128_GCM_SHA256",
    "AuthenticationMethod": "AuthHeader",
    "bytesTransferredIn": 0,
    "bytesTransferredOut": 48213770,
    "x-amz-id-2": "HTb5ENhNh4c3y4pyC9yiVAYEdnllRj1vNGSoBWz3YlXkK0DQ4bpt8BjuihpNQhDNBAqsCFxH+yE"
  },
  "requestID": "7FQJXG8C228Y7NNK",
  "eventID": "c1a7e2b9-3d44-4f1e-9c10-5a7b2e8f6011",
  "readOnly": true,
  "resources": [
    { "type": "AWS::S3::Object", "ARN": "arn:aws:s3:::nexacorp-customer-exports/2026/pii/customers_full.csv.gz" },
    { "accountId": "123456789012", "type": "AWS::S3::Bucket", "ARN": "arn:aws:s3:::nexacorp-customer-exports" }
  ],
  "eventType": "AwsApiCall",
  "managementEvent": false,
  "recipientAccountId": "123456789012",
  "eventCategory": "Data",
  "tlsDetails": {
    "tlsVersion": "TLSv1.3",
    "cipherSuite": "TLS_AES_128_GCM_SHA256",
    "clientProvidedHostHeader": "nexacorp-customer-exports.s3.us-east-1.amazonaws.com"
  }
}
```

**A4 — `PutBucketPolicy` making the bucket public (write, `responseElements` present)**
```json
{
  "eventVersion": "1.11",
  "userIdentity": {
    "type": "IAMUser",
    "principalId": "AIDA2QXCZ4R7KJ6PLMN3A",
    "arn": "arn:aws:iam::123456789012:user/svc-deploy",
    "accountId": "123456789012",
    "accessKeyId": "AKIA2QXCZ4R7KJ6PLMN3",
    "userName": "svc-deploy"
  },
  "eventTime": "2026-09-30T02:19:48Z",
  "eventSource": "s3.amazonaws.com",
  "eventName": "PutBucketPolicy",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.77",
  "userAgent": "aws-cli/2.17.60 md/command#s3api.put-bucket-policy",
  "requestParameters": {
    "bucketName": "nexacorp-customer-exports",
    "Host": "nexacorp-customer-exports.s3.us-east-1.amazonaws.com",
    "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"PublicRead\",\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::nexacorp-customer-exports/*\"}]}"
  },
  "responseElements": null,
  "additionalEventData": { "SignatureVersion": "SigV4", "CipherSuite": "TLS_AES_128_GCM_SHA256", "AuthenticationMethod": "AuthHeader" },
  "requestID": "8ACD1172EACDD221",
  "eventID": "d2b9f1c0-6a7e-42aa-8f33-0c9d7e2a1b55",
  "readOnly": false,
  "resources": [
    { "accountId": "123456789012", "type": "AWS::S3::Bucket", "ARN": "arn:aws:s3:::nexacorp-customer-exports" }
  ],
  "eventType": "AwsApiCall",
  "managementEvent": true,
  "recipientAccountId": "123456789012",
  "eventCategory": "Management",
  "tlsDetails": {
    "tlsVersion": "TLSv1.3",
    "cipherSuite": "TLS_AES_128_GCM_SHA256",
    "clientProvidedHostHeader": "nexacorp-customer-exports.s3.us-east-1.amazonaws.com"
  }
}
```

**A5 — `DeleteBucketPublicAccessBlock` (removing the public-access guardrail)**
```json
{
  "eventVersion": "1.11",
  "userIdentity": {
    "type": "IAMUser", "principalId": "AIDA2QXCZ4R7KJ6PLMN3A",
    "arn": "arn:aws:iam::123456789012:user/svc-deploy", "accountId": "123456789012",
    "accessKeyId": "AKIA2QXCZ4R7KJ6PLMN3", "userName": "svc-deploy"
  },
  "eventTime": "2026-09-30T02:19:12Z",
  "eventSource": "s3.amazonaws.com",
  "eventName": "DeleteBucketPublicAccessBlock",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.77",
  "userAgent": "aws-cli/2.17.60 md/command#s3api.delete-public-access-block",
  "requestParameters": { "bucketName": "nexacorp-customer-exports", "host": "nexacorp-customer-exports.s3.amazonaws.com", "publicAccessBlock": "" },
  "responseElements": null,
  "requestID": "ABC123DEF456GHIJ",
  "eventID": "ee3c71d0-2b1a-4ce7-9df0-7a1c0e4b9d20",
  "readOnly": false,
  "eventType": "AwsApiCall",
  "managementEvent": true,
  "recipientAccountId": "123456789012",
  "eventCategory": "Management",
  "vpcEndpointId": "vpce-0a1b2c3d4e5f67890"
}
```

**A6 — `CreateUser` (IAM persistence: attacker makes a backdoor user)**
```json
{
  "eventVersion": "1.11",
  "userIdentity": {
    "type": "IAMUser", "principalId": "AIDA2QXCZ4R7KJ6PLMN3A",
    "arn": "arn:aws:iam::123456789012:user/svc-deploy", "accountId": "123456789012",
    "accessKeyId": "AKIA2QXCZ4R7KJ6PLMN3", "userName": "svc-deploy"
  },
  "eventTime": "2026-09-30T02:21:00Z",
  "eventSource": "iam.amazonaws.com",
  "eventName": "CreateUser",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.77",
  "userAgent": "aws-cli/2.17.60 md/command#iam.create-user",
  "requestParameters": { "userName": "support-sync" },
  "responseElements": {
    "user": {
      "path": "/", "userName": "support-sync",
      "userId": "AIDA2QXCZ4R7KJ6QRST9Z",
      "arn": "arn:aws:iam::123456789012:user/support-sync",
      "createDate": "Sep 30, 2026 2:21:00 AM"
    }
  },
  "requestID": "4b2c7a1e-9f0d-4a3b-8e21-6c7d2f1a0b33",
  "eventID": "f0a1b2c3-d4e5-46f7-8899-0a1b2c3d4e5f",
  "readOnly": false,
  "eventType": "AwsApiCall",
  "managementEvent": true,
  "recipientAccountId": "123456789012",
  "eventCategory": "Management",
  "tlsDetails": { "tlsVersion": "TLSv1.3", "cipherSuite": "TLS_AES_128_GCM_SHA256", "clientProvidedHostHeader": "iam.amazonaws.com" }
}
```

**A7 — `CreateAccessKey` for the backdoor user**
```json
{
  "eventVersion": "1.11",
  "userIdentity": {
    "type": "IAMUser", "principalId": "AIDA2QXCZ4R7KJ6PLMN3A",
    "arn": "arn:aws:iam::123456789012:user/svc-deploy", "accountId": "123456789012",
    "accessKeyId": "AKIA2QXCZ4R7KJ6PLMN3", "userName": "svc-deploy"
  },
  "eventTime": "2026-09-30T02:21:30Z",
  "eventSource": "iam.amazonaws.com",
  "eventName": "CreateAccessKey",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.77",
  "userAgent": "aws-cli/2.17.60 md/command#iam.create-access-key",
  "requestParameters": { "userName": "support-sync" },
  "responseElements": {
    "accessKey": {
      "userName": "support-sync",
      "accessKeyId": "AKIA2QXCZ4R7KJ6UVWX5",
      "status": "Active",
      "createDate": "Sep 30, 2026 2:21:30 AM"
    }
  },
  "requestID": "5c3d8b2f-0a1e-4b4c-9f32-7d8e3a2b1c44",
  "eventID": "a1b2c3d4-e5f6-4788-99aa-bbccddeeff00",
  "readOnly": false,
  "eventType": "AwsApiCall",
  "managementEvent": true,
  "recipientAccountId": "123456789012",
  "eventCategory": "Management"
}
```

**A8 — `AttachUserPolicy` granting AdministratorAccess (privilege escalation)**
```json
{
  "eventVersion": "1.11",
  "userIdentity": {
    "type": "IAMUser", "principalId": "AIDA2QXCZ4R7KJ6PLMN3A",
    "arn": "arn:aws:iam::123456789012:user/svc-deploy", "accountId": "123456789012",
    "accessKeyId": "AKIA2QXCZ4R7KJ6PLMN3", "userName": "svc-deploy"
  },
  "eventTime": "2026-09-30T02:22:05Z",
  "eventSource": "iam.amazonaws.com",
  "eventName": "AttachUserPolicy",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.77",
  "userAgent": "aws-cli/2.17.60 md/command#iam.attach-user-policy",
  "requestParameters": {
    "userName": "support-sync",
    "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
  },
  "responseElements": null,
  "requestID": "15b731e5-03ff-47bc-aa3e-3c34c9398b25",
  "eventID": "48a0efc2-e7b5-48d0-a3d7-38c44cd15525",
  "readOnly": false,
  "eventType": "AwsApiCall",
  "managementEvent": true,
  "recipientAccountId": "123456789012",
  "eventCategory": "Management",
  "tlsDetails": { "tlsVersion": "TLSv1.3", "cipherSuite": "TLS_AES_128_GCM_SHA256", "clientProvidedHostHeader": "iam.amazonaws.com" }
}
```

**A9 — `StopLogging` (defense evasion: turning off the trail)**
```json
{
  "eventVersion": "1.11",
  "userIdentity": {
    "type": "IAMUser", "principalId": "AIDA2QXCZ4R7KJ6PLMN3A",
    "arn": "arn:aws:iam::123456789012:user/svc-deploy", "accountId": "123456789012",
    "accessKeyId": "AKIA2QXCZ4R7KJ6PLMN3", "userName": "svc-deploy"
  },
  "eventTime": "2026-09-30T02:23:11Z",
  "eventSource": "cloudtrail.amazonaws.com",
  "eventName": "StopLogging",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.77",
  "userAgent": "aws-cli/2.17.60 md/command#cloudtrail.stop-logging",
  "requestParameters": { "name": "arn:aws:cloudtrail:us-east-1:123456789012:trail/org-audit-trail" },
  "responseElements": null,
  "requestID": "6d4e9c3a-1b2f-4c5d-8e43-9f0a4b3c2d55",
  "eventID": "b2c3d4e5-f6a7-4899-aabb-ccddeeff0011",
  "readOnly": false,
  "eventType": "AwsApiCall",
  "managementEvent": true,
  "recipientAccountId": "123456789012",
  "eventCategory": "Management"
}
```

### Attack chain B — crypto-mining via oversized GPU instances

**B1 — `RunInstances` launching GPU instances (`g4dn.12xlarge`) — truncated responseElements**
```json
{
  "eventVersion": "1.11",
  "userIdentity": {
    "type": "AssumedRole",
    "principalId": "AROA2QXCZ4R7KABCDEF12:i-0a1b2c3d4e5f60718",
    "arn": "arn:aws:sts::123456789012:assumed-role/ec2-ci-runner/i-0a1b2c3d4e5f60718",
    "accountId": "123456789012",
    "accessKeyId": "ASIA2QXCZ4R7KJ6YZAB7",
    "sessionContext": {
      "sessionIssuer": {
        "type": "Role", "principalId": "AROA2QXCZ4R7KABCDEF12",
        "arn": "arn:aws:iam::123456789012:role/ec2-ci-runner",
        "accountId": "123456789012", "userName": "ec2-ci-runner"
      },
      "attributes": { "creationDate": "2026-09-30T02:40:11Z", "mfaAuthenticated": "false" },
      "ec2RoleDelivery": "2.0"
    }
  },
  "eventTime": "2026-09-30T02:41:55Z",
  "eventSource": "ec2.amazonaws.com",
  "eventName": "RunInstances",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.77",
  "userAgent": "aws-cli/2.17.60 md/command#ec2.run-instances",
  "requestParameters": {
    "instancesSet": { "items": [ { "imageId": "ami-0abcdef1234567890", "minCount": 8, "maxCount": 8 } ] },
    "instanceType": "g4dn.12xlarge",
    "monitoring": { "enabled": false }
  },
  "responseElements": {
    "reservationId": "r-0f1e2d3c4b5a69780",
    "ownerId": "123456789012",
    "instancesSet": { "items": [ { "instanceId": "i-02468ace13579bdf0", "instanceType": "g4dn.12xlarge", "instanceState": { "code": 0, "name": "pending" } } ] }
  },
  "requestID": "ffd44d98-cea5-4b4a-9c38-b2aee9f73489",
  "eventID": "5e1fb8e0-231d-4527-a146-d051e37d0d4f",
  "readOnly": false,
  "eventType": "AwsApiCall",
  "managementEvent": true,
  "recipientAccountId": "123456789012",
  "eventCategory": "Management",
  "tlsDetails": { "tlsVersion": "TLSv1.3", "cipherSuite": "TLS_AES_128_GCM_SHA256", "clientProvidedHostHeader": "ec2.us-east-1.amazonaws.com" }
}
```

### Other high-value singletons

**C1 — `GetSecretValue` (Secrets Manager; read-only data of Management category)**
```json
{
  "eventVersion": "1.11",
  "userIdentity": {
    "type": "AssumedRole",
    "principalId": "AROA2QXCZ4R7KABCDEF12:i-0a1b2c3d4e5f60718",
    "arn": "arn:aws:sts::123456789012:assumed-role/ec2-ci-runner/i-0a1b2c3d4e5f60718",
    "accountId": "123456789012", "accessKeyId": "ASIA2QXCZ4R7KJ6YZAB7",
    "sessionContext": {
      "sessionIssuer": { "type": "Role", "principalId": "AROA2QXCZ4R7KABCDEF12", "arn": "arn:aws:iam::123456789012:role/ec2-ci-runner", "accountId": "123456789012", "userName": "ec2-ci-runner" },
      "attributes": { "creationDate": "2026-09-30T02:40:11Z", "mfaAuthenticated": "false" },
      "ec2RoleDelivery": "2.0"
    }
  },
  "eventTime": "2026-09-30T02:45:03Z",
  "eventSource": "secretsmanager.amazonaws.com",
  "eventName": "GetSecretValue",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.77",
  "userAgent": "aws-cli/2.17.60 md/command#secretsmanager.get-secret-value",
  "requestParameters": { "secretId": "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db/master-AbCdEf" },
  "responseElements": null,
  "requestID": "0b0c8a1a-497a-4758-a6fc-c046970dfb58",
  "eventID": "f1a49924-6ba3-4340-9d21-bc98f090fc09",
  "readOnly": true,
  "eventType": "AwsApiCall",
  "managementEvent": true,
  "recipientAccountId": "123456789012",
  "eventCategory": "Management",
  "tlsDetails": { "tlsVersion": "TLSv1.3", "cipherSuite": "TLS_AES_128_GCM_SHA256", "clientProvidedHostHeader": "secretsmanager.us-east-1.amazonaws.com" }
}
```

**C2 — `ConsoleLogin` failure (IAM user, brute-force attempt)**
```json
{
  "eventVersion": "1.11",
  "userIdentity": {
    "type": "IAMUser",
    "principalId": "AIDA2QXCZ4R7KJ6PLMN3A",
    "accountId": "123456789012",
    "accessKeyId": "",
    "userName": "svc-deploy"
  },
  "eventTime": "2026-09-30T02:05:44Z",
  "eventSource": "signin.amazonaws.com",
  "eventName": "ConsoleLogin",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.77",
  "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
  "errorMessage": "Failed authentication",
  "requestParameters": null,
  "responseElements": { "ConsoleLogin": "Failure" },
  "additionalEventData": {
    "LoginTo": "https://console.aws.amazon.com/console/home",
    "MobileVersion": "No",
    "MFAUsed": "No"
  },
  "eventID": "66c97220-2b7d-43b6-a7a0-7f2b1aebae9c",
  "readOnly": false,
  "eventType": "AwsConsoleSignIn",
  "managementEvent": true,
  "recipientAccountId": "123456789012",
  "eventCategory": "Management",
  "tlsDetails": { "tlsVersion": "TLSv1.3", "cipherSuite": "TLS_AES_128_GCM_SHA256", "clientProvidedHostHeader": "us-east-1.signin.aws.amazon.com" }
}
```

**C3 — `UpdateAssumeRolePolicy` (trust-policy backdoor: add attacker account to a role's trust)**
```json
{
  "eventVersion": "1.11",
  "userIdentity": {
    "type": "IAMUser", "principalId": "AIDA2QXCZ4R7KJ6PLMN3A",
    "arn": "arn:aws:iam::123456789012:user/svc-deploy", "accountId": "123456789012",
    "accessKeyId": "AKIA2QXCZ4R7KJ6PLMN3", "userName": "svc-deploy"
  },
  "eventTime": "2026-09-30T02:22:40Z",
  "eventSource": "iam.amazonaws.com",
  "eventName": "UpdateAssumeRolePolicy",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.77",
  "userAgent": "aws-cli/2.17.60 md/command#iam.update-assume-role-policy",
  "requestParameters": {
    "roleName": "ec2-ci-runner",
    "policyDocument": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::999988887777:root\"},\"Action\":\"sts:AssumeRole\"}]}"
  },
  "responseElements": null,
  "requestID": "200661bf-fe5a-46c4-b098-d57a761c741b",
  "eventID": "c3d4e5f6-a7b8-4999-aabb-ccddeeff0022",
  "readOnly": false,
  "eventType": "AwsApiCall",
  "managementEvent": true,
  "recipientAccountId": "123456789012",
  "eventCategory": "Management"
}
```

**C4 — `AssumeRole` (STS) producing temporary creds; note `resources[]` + response creds redaction**
```json
{
  "eventVersion": "1.11",
  "userIdentity": {
    "type": "IAMUser", "principalId": "AIDA2QXCZ4R7KJ6PLMN3A",
    "arn": "arn:aws:iam::123456789012:user/svc-deploy", "accountId": "123456789012",
    "accessKeyId": "AKIA2QXCZ4R7KJ6PLMN3", "userName": "svc-deploy"
  },
  "eventTime": "2026-09-30T02:40:11Z",
  "eventSource": "sts.amazonaws.com",
  "eventName": "AssumeRole",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.77",
  "userAgent": "aws-cli/2.17.60 md/command#sts.assume-role",
  "requestParameters": {
    "roleArn": "arn:aws:iam::123456789012:role/ec2-ci-runner",
    "roleSessionName": "ci-session"
  },
  "responseElements": {
    "credentials": { "accessKeyId": "ASIA2QXCZ4R7KJ6YZAB7", "expiration": "Sep 30, 2026 3:40:11 AM", "sessionToken": "IQoJb3JpZ2luX2VjE...EXAMPLE...TOKEN" },
    "assumedRoleUser": { "assumedRoleId": "AROA2QXCZ4R7KABCDEF12:ci-session", "arn": "arn:aws:sts::123456789012:assumed-role/ec2-ci-runner/ci-session" }
  },
  "requestID": "b96b0e4e-e561-11e9-8b3f-7b396d0e9c21",
  "eventID": "1917948f-3042-46ec-98e2-62865abc1234",
  "resources": [
    { "ARN": "arn:aws:iam::123456789012:role/ec2-ci-runner", "accountId": "123456789012", "type": "AWS::IAM::Role" }
  ],
  "readOnly": true,
  "eventType": "AwsApiCall",
  "managementEvent": true,
  "recipientAccountId": "123456789012",
  "eventCategory": "Management"
}
```

**C5 — Bedrock `InvokeModel` (AI usage/abuse; eventSource `bedrock.amazonaws.com`)**
```json
{
  "eventVersion": "1.11",
  "userIdentity": {
    "type": "AssumedRole",
    "principalId": "AROA2QXCZ4R7KABCDEF12:i-0a1b2c3d4e5f60718",
    "arn": "arn:aws:sts::123456789012:assumed-role/ec2-ci-runner/i-0a1b2c3d4e5f60718",
    "accountId": "123456789012", "accessKeyId": "ASIA2QXCZ4R7KJ6YZAB7",
    "sessionContext": {
      "sessionIssuer": { "type": "Role", "principalId": "AROA2QXCZ4R7KABCDEF12", "arn": "arn:aws:iam::123456789012:role/ec2-ci-runner", "accountId": "123456789012", "userName": "ec2-ci-runner" },
      "attributes": { "creationDate": "2026-09-30T02:40:11Z", "mfaAuthenticated": "false" },
      "ec2RoleDelivery": "2.0"
    }
  },
  "eventTime": "2026-09-30T02:50:22Z",
  "eventSource": "bedrock.amazonaws.com",
  "eventName": "InvokeModel",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.77",
  "userAgent": "Boto3/1.35.50 md/Botocore#1.35.50 ua/2.0 os/linux#6.8.0 lang/python#3.12.3",
  "requestParameters": { "modelId": "anthropic.claude-3-5-sonnet-20240620-v1:0" },
  "responseElements": null,
  "requestID": "aff6f361-1ef0-4460-97af-26528a80b511",
  "eventID": "3d67c35a-eef1-4d64-9620-77af8f372ae7",
  "readOnly": true,
  "eventType": "AwsApiCall",
  "managementEvent": true,
  "recipientAccountId": "123456789012",
  "eventCategory": "Management",
  "tlsDetails": { "tlsVersion": "TLSv1.3", "cipherSuite": "TLS_AES_128_GCM_SHA256", "clientProvidedHostHeader": "bedrock-runtime.us-east-1.amazonaws.com" }
}
```

**C6 — Insight event (`eventType: AwsCloudTrailInsight`, `eventCategory: Insight`)**
```json
{
  "eventVersion": "1.11",
  "eventTime": "2026-09-30T02:22:00Z",
  "awsRegion": "us-east-1",
  "eventID": "41ed77ca-d659-b45a-8e9a-74e504300007",
  "eventType": "AwsCloudTrailInsight",
  "recipientAccountId": "123456789012",
  "sharedEventID": "e672c2b1-e71a-4779-f96c-02da7bb30d2e",
  "insightDetails": {
    "state": "Start",
    "eventSource": "iam.amazonaws.com",
    "eventName": "AttachUserPolicy",
    "insightType": "ApiCallRateInsight",
    "insightContext": {
      "statistics": { "baseline": { "average": 0.0 }, "insight": { "average": 6.0 }, "insightDuration": 1 },
      "attributions": [
        { "attribute": "userIdentityArn", "insight": [ { "value": "arn:aws:iam::123456789012:user/svc-deploy", "average": 6.0 } ], "baseline": [] }
      ]
    }
  },
  "eventCategory": "Insight"
}
```

---

## 5. Investigation notes (analyst pivots)

- **`userIdentity.accessKeyId`** — the strongest pivot for a leaked key. Filter all events by this value to
  trace everything one key touched. `ASIA...` means temporary (STS) creds — pivot further via `sessionContext`.
- **`userIdentity.arn` / `sessionContext.sessionIssuer.arn`** — the acting principal and, for role sessions,
  the originating role. `sessionContext.attributes.creationDate` ties a session back to the `AssumeRole` event.
- **`sourceIPAddress` + `userAgent`** — foreign IP + SDK/Boto user agent on an identity that normally uses the
  console (or the reverse) is a classic compromise signal. `console.amazonaws.com`/`signin.amazonaws.com` as
  UA/source means the action was taken through the console.
- **`eventID`** uniquely identifies an event; **`requestID`** ties the event to an AWS Support trace and to the
  service's own logs; **`sharedEventID`** links the two copies of a cross-account action.
- **GuardDuty → CloudTrail correlation:** a GuardDuty finding's `service.action.awsApiCallAction.api`,
  `resource.accessKeyDetails.accessKeyId`, `remoteIpDetails.ipAddressV4`, and `eventFirstSeen/eventLastSeen`
  map directly onto CloudTrail `eventName`, `userIdentity.accessKeyId`, `sourceIPAddress`, and `eventTime`.
  Use them to pull the exact CloudTrail events behind a finding.
- **Delivery timing:** `eventTime` is call time; the log may arrive minutes later. Don't treat the S3 object
  mtime (or an SIEM ingest time) as the event time. A late event may carry an `addendum` with `DELIVERY_DELAY`.
- **`readOnly`** and **`eventCategory`** quickly separate recon/read (GetObject, Describe*, List*, Get*) from
  state changes (Put*, Create*, Delete*, Attach*, Stop*). Data-plane object access is `eventCategory:Data`,
  `managementEvent:false`, and only present if S3/Lambda/DynamoDB data events were enabled.
- **Anonymous S3 access** shows `userIdentity.accountId` = `anonymous` (ARN also `anonymous`).

## 6. Common mistakes / non-existent fields

- **Do not** flatten to `aws.cloudtrail.flattened.*` or `aws.cloudtrail.user_identity.*` (that is the Elastic ECS
  mapping, not CloudTrail). Keep the native nested object with the native camelCase keys.
- **Do not** wrap the event in a Wazuh `{"data": {...}, "rule": {...}, "agent": {...}}` envelope.
- `readOnly` and `managementEvent` are **booleans**, not strings (`true`, not `"true"`).
  By contrast `sessionContext.attributes.mfaAuthenticated` and `sessionCredentialFromConsole` **are** strings
  (`"true"`/`"false"`), and the S3 `additionalEventData.MFAUsed`/`aclRequired` are `"Yes"`/`"No"`.
- `eventSource` is `s3.amazonaws.com`, **not** `aws.s3` or `S3`. ConsoleLogin's source is
  `signin.amazonaws.com`, not `iam.amazonaws.com`.
- The S3 `additionalEventData` byte key is **`x-amz-id-2`** (hyphens), not `xAmzId2`; counters are
  `bytesTransferredIn`/`bytesTransferredOut` (numbers).
- `responseElements` is `null` for read-only APIs — don't invent response bodies on `Get*`/`List*`/`Describe*`.
- `tlsDetails` is **absent** when an AWS service made the call on your behalf (look at `userIdentity.invokedBy`
  / `userAgent` ending in `.amazonaws.com`). Don't add it to service-invoked events.
- `eventType` for a sign-in is `AwsConsoleSignIn` (not `AwsApiCall`); for a trail/service event it's
  `AwsServiceEvent`. Insights use `AwsCloudTrailInsight` + `eventCategory:Insight`.
- `principalId` for a role session is `AROA...:<sessionName>` — don't drop the `:sessionName`. IAM user ids
  start `AIDA`; access keys `AKIA` (long-term) / `ASIA` (temporary) — don't mix them.
- Account ids are **12 digits** and strings. ARNs for assumed roles use the `sts::` service and
  `assumed-role/<role>/<session>`, while the role's own ARN uses `iam::` and `role/<role>`.
