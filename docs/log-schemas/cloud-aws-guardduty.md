# Amazon GuardDuty findings — log schema card

GuardDuty emits **findings** as JSON. It is a JSON-native source. Show the finding as the JSON object
GuardDuty produces (the `GetFindings`/export shape), or wrapped in its EventBridge envelope. Do **not**
flatten to `aws.guardduty.*` (ECS) or wrap in a Wazuh `data.*` envelope.

## 1. Official sources

- Finding details / resource & service structure:
  https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings-summary.html
- EventBridge envelope + aggregation/frequency:
  https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings_eventbridge.html
  — confirmed envelope: `version, id, detail-type ("GuardDuty Finding"), source ("aws.guardduty"), account, time, region, resources[], detail{finding}`.
- Severity ranges: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings-severity.html
  — **Critical 9.0–10.0, High 7.0–8.9, Medium 4.0–6.9, Low 1.0–3.9** (values 1.0–10.0).
- Finding type taxonomy (exact type strings + default severities):
  https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html
- API object schemas (exact field names/types):
  `Service`, `Resource`, `AwsApiCallAction`, `NetworkConnectionAction`, `S3BucketDetail`, `RemoteIpDetails`
  under https://docs.aws.amazon.com/guardduty/latest/APIReference/
- Full filter-attribute path list (authoritative nested field names):
  https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_filter-findings.html
- Sample findings cross-checked against elastic/integrations `packages/aws/data_stream/guardduty` raw test
  inputs and panther-labs/panther-analysis `rules/aws_guardduty_rules/*.yml`.

## 2. Native format & delivery

- **EventBridge (near-real-time):** the finding JSON is in `detail`, inside the AWS event envelope.
- **S3 export / `GetFindings` API:** the bare finding object (what sits in `detail`). Export files are
  gzipped JSON, one finding per object/line.
- **We standardise on the bare finding object**, and show the EventBridge envelope only when a scenario needs it.
- Aggregation: a finding has a stable `id`; repeat activity of the same type updates the same finding
  (`updatedAt`, `service.count`, `eventLastSeen` increase). New unique finding → new EventBridge event in
  near-real-time; subsequent occurrences are batched (default every 6h; admin can set 15 min / 1 h / 6 h).
- GuardDuty keeps findings 90 days.

## 3. Core field reference

### Top-level finding
| Field | Type | Notes |
|---|---|---|
| `schemaVersion` | string | e.g. `2.0`. |
| `accountId` | string | 12-digit account the finding is for. |
| `region` | string | e.g. `us-east-1`. |
| `partition` | string | `aws`. |
| `id` | string | Finding id (hex). |
| `arn` | string | `arn:aws:guardduty:<region>:<acct>:detector/<detectorId>/finding/<id>`. |
| `type` | string | Finding type taxonomy (see §3c). |
| `resource` | object | The affected resource — exactly one detail sub-object (see §3a). |
| `service` | object | Detection details, action, evidence, counts (see §3b). |
| `severity` | number | 1.0–10.0 (see ranges above). |
| `createdAt` | string | ISO8601 with millis, e.g. `2026-09-30T02:17:30.224Z`. |
| `updatedAt` | string | Last update time. |
| `title` | string | Short human summary. |
| `description` | string | Longer description. |

### 3a. `resource`
`resource.resourceType` enum: `AccessKey`, `Instance`, `S3Bucket`, `S3Object`, `EKSCluster`, `ECSCluster`,
`Container`, `KubernetesCluster`, `RDSDBInstance`, `RDSLimitlessDB`, `Lambda`. Exactly one matching detail object:

- `accessKeyDetails`: `{accessKeyId, principalId, userType (Root|IAMUser|AssumedRole|Role|FederatedUser|...), userName}`.
- `instanceDetails`: `{instanceId, instanceType, launchTime, platform, iamInstanceProfile{arn,id},
  networkInterfaces[{privateIpAddress, publicIp, subnetId, vpcId, securityGroups[{groupName,groupId}], ...}],
  tags[{key,value}], instanceState, availabilityZone, imageId, imageDescription, outpostArn?}`.
- `s3BucketDetails` (**array**): `[{arn, name, type (Source|Destination), createdAt, owner{id},
  tags[{key,value}], defaultServerSideEncryption{encryptionType, kmsMasterKeyArn},
  publicAccess{effectivePermission (PUBLIC|NOT_PUBLIC|UNKNOWN), permissionConfiguration{bucketLevelPermissions{...}, accountLevelPermissions{blockPublicAccess{...}}}}}]`.
- `eksClusterDetails`, `kubernetesDetails{kubernetesUserDetails{username,uid,groups[]}, kubernetesWorkloadDetails}`,
  `rdsDbInstanceDetails`, `rdsDbUserDetails`, `containerDetails`, `lambdaDetails` for the respective types.

### 3b. `service`
`{serviceName:"guardduty", detectorId, action{...}, resourceRole (ACTOR|TARGET), additionalInfo{...},
evidence{threatIntelligenceDetails[{threatNames[], threatListName}]} | null, eventFirstSeen, eventLastSeen,
archived (bool), count (int), featureName?, detection?}`.

`action.actionType` enum and its sub-object:
| actionType | sub-object |
|---|---|
| `AWS_API_CALL` | `awsApiCallAction` |
| `NETWORK_CONNECTION` | `networkConnectionAction` |
| `DNS_REQUEST` | `dnsRequestAction` |
| `PORT_PROBE` | `portProbeAction` |
| `KUBERNETES_API_CALL` | `kubernetesApiCallAction` |
| `RDS_LOGIN_ATTEMPT` | `rdsLoginAttemptAction` |

- `awsApiCallAction`: `{api, serviceName, callerType (Remote IP|Domain), remoteIpDetails{...} | domainDetails{domain},
  affectedResources{"AWS::<svc>::<type>":"<arn>"}, errorCode?, userAgent?, remoteAccountDetails{accountId,affiliated}?}`.
- `networkConnectionAction`: `{connectionDirection (INBOUND|OUTBOUND|UNKNOWN), protocol (TCP|UDP|...), blocked (bool),
  localPortDetails{port,portName}, remotePortDetails{port,portName}, localIpDetails{ipAddressV4},
  remoteIpDetails{...}, localNetworkInterface}`.
- `dnsRequestAction`: `{domain, protocol, blocked (bool)}`.
- `portProbeAction`: `{blocked, portProbeDetails[{localPortDetails{port,portName}, localIpDetails{ipAddressV4}, remoteIpDetails{...}}]}`.
- `kubernetesApiCallAction`: `{requestUri, verb, sourceIPs[], userAgent, remoteIpDetails{...}, statusCode, parameters?}`.

`remoteIpDetails` (reused everywhere): `{ipAddressV4, ipAddressV6?, city{cityName}, country{countryName, countryCode?},
geoLocation{lat, lon}, organization{asn, asnOrg, isp, org}}`.

`additionalInfo` is variable; sample/demo data carries `{"sample": true}` (and `value`, `type:"default"`).
Real findings carry threat/anomaly keys, e.g. `threatListName`, `threatName`, `unusualBehavior`, `recentApiCalls`.

### 3c. Finding type taxonomy (exact strings; default severity)
Format: `ThreatPurpose:ResourceType/ThreatFamilyName.Variant`. Key SOC-relevant types:

- IAM / CloudTrail: `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` (High),
  `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS` (High),
  `CredentialAccess:IAMUser/AnomalousBehavior` (Medium), `Exfiltration:IAMUser/AnomalousBehavior` (High),
  `PrivilegeEscalation:IAMUser/AnomalousBehavior` (Medium), `Persistence:IAMUser/AnomalousBehavior` (Medium),
  `Discovery:IAMUser/AnomalousBehavior` (Low), `Recon:IAMUser/MaliciousIPCaller` (Medium),
  `Recon:IAMUser/TorIPCaller` (Medium), `UnauthorizedAccess:IAMUser/MaliciousIPCaller` (Medium),
  `Stealth:IAMUser/CloudTrailLoggingDisabled` (Low), `Stealth:IAMUser/PasswordPolicyChange` (Low),
  `Policy:IAMUser/RootCredentialUsage` (Low), `PenTest:IAMUser/KaliLinux` (Medium),
  `UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B` (Medium).
- S3: `Policy:S3/BucketAnonymousAccessGranted` (High), `Policy:S3/BucketPublicAccessGranted` (High),
  `Policy:S3/BucketBlockPublicAccessDisabled` (Low), `Exfiltration:S3/AnomalousBehavior` (High),
  `Exfiltration:S3/MaliciousIPCaller` (High), `Discovery:S3/AnomalousBehavior` (Low),
  `Impact:S3/AnomalousBehavior.Delete` (High), `PenTest:S3/KaliLinux` (Medium),
  `Stealth:S3/ServerAccessLoggingDisabled` (Low).
- EC2 (DNS/VPC flow source): `CryptoCurrency:EC2/BitcoinTool.B!DNS` (High), `CryptoCurrency:EC2/BitcoinTool.B` (High),
  `Backdoor:EC2/C&CActivity.B!DNS` (High), `Trojan:EC2/BlackholeTraffic!DNS` (Medium),
  `Trojan:EC2/DNSDataExfiltration` (High), `UnauthorizedAccess:EC2/SSHBruteForce` (Low),
  `UnauthorizedAccess:EC2/RDPBruteForce` (Low), `UnauthorizedAccess:EC2/TorClient` (High),
  `Recon:EC2/PortProbeUnprotectedPort` (Low), `Impact:EC2/PortSweep` (High), `Backdoor:EC2/Spambot` (Medium).
- Kubernetes (EKS audit): `Persistence:Kubernetes/SuccessfulAnonymousAccess` (High),
  `Execution:Kubernetes/ExecInKubeSystemPod` (Medium),
  `PrivilegeEscalation:Kubernetes/AnomalousBehavior.WorkloadDeployed!PrivilegedContainer` (High),
  `CredentialAccess:Kubernetes/AnomalousBehavior.SecretsAccessed` (Medium),
  `Policy:Kubernetes/AnonymousAccessGranted` (High), `Discovery:Kubernetes/TorIPCaller` (Medium).
- Attack sequences (Extended Threat Detection, Critical): `AttackSequence:IAM/CompromisedCredentials`,
  `AttackSequence:S3/CompromisedData`, `AttackSequence:EKS/CompromisedCluster`.

### EventBridge envelope
```json
{
  "version": "0",
  "id": "cd2d702e-ab31-411b-9344-793ce56b1bc7",
  "detail-type": "GuardDuty Finding",
  "source": "aws.guardduty",
  "account": "123456789012",
  "time": "2026-09-30T02:30:00Z",
  "region": "us-east-1",
  "resources": [],
  "detail": {}
}
```

---

## 4. Realistic samples (coherent with the CloudTrail chain, account 123456789012)

### G1 — Leaked key used from a foreign IP: `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS`
Correlates to the CloudTrail `GetCallerIdentity`/`ListBuckets` from `203.0.113.77`.
```json
{
  "schemaVersion": "2.0",
  "accountId": "123456789012",
  "region": "us-east-1",
  "partition": "aws",
  "id": "a6b0c2d4e6f8a0b2c4d6e8f0a2b4c6d8",
  "arn": "arn:aws:guardduty:us-east-1:123456789012:detector/d6012345678912345678912349f831b8/finding/a6b0c2d4e6f8a0b2c4d6e8f0a2b4c6d8",
  "type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
  "resource": {
    "resourceType": "AccessKey",
    "accessKeyDetails": {
      "accessKeyId": "ASIA2QXCZ4R7KJ6YZAB7",
      "principalId": "AROA2QXCZ4R7KABCDEF12:i-0a1b2c3d4e5f60718",
      "userType": "AssumedRole",
      "userName": "ec2-ci-runner"
    }
  },
  "service": {
    "serviceName": "guardduty",
    "detectorId": "d6012345678912345678912349f831b8",
    "action": {
      "actionType": "AWS_API_CALL",
      "awsApiCallAction": {
        "api": "ListBuckets",
        "serviceName": "s3.amazonaws.com",
        "callerType": "Remote IP",
        "remoteIpDetails": {
          "ipAddressV4": "203.0.113.77",
          "organization": { "asn": "209242", "asnOrg": "Cloudflare London, LLC", "isp": "Cloudflare", "org": "Cloudflare" },
          "country": { "countryName": "Netherlands", "countryCode": "NL" },
          "city": { "cityName": "Amsterdam" },
          "geoLocation": { "lat": 52.374, "lon": 4.8897 }
        }
      }
    },
    "resourceRole": "TARGET",
    "additionalInfo": { "recentApiCalls": [ { "api": "GetCallerIdentity", "count": 1 }, { "api": "ListBuckets", "count": 1 } ] },
    "evidence": null,
    "eventFirstSeen": "2026-09-30T02:14:07.000Z",
    "eventLastSeen": "2026-09-30T02:16:40.000Z",
    "archived": false,
    "count": 2
  },
  "severity": 8,
  "createdAt": "2026-09-30T02:17:30.224Z",
  "updatedAt": "2026-09-30T02:18:05.934Z",
  "title": "Credentials created exclusively for an EC2 instance are being used from an external IP address.",
  "description": "AWS credentials created for the EC2 instance i-0a1b2c3d4e5f60718 role ec2-ci-runner are being used from a remote host 203.0.113.77 outside of AWS."
}
```

### G2 — S3 bulk read from malicious IP: `Exfiltration:S3/MaliciousIPCaller`
Correlates to the CloudTrail `GetObject` data events.
```json
{
  "schemaVersion": "2.0",
  "accountId": "123456789012",
  "region": "us-east-1",
  "partition": "aws",
  "id": "b7c1d3e5f7a9b1c3d5e7f9a1b3c5d7e9",
  "arn": "arn:aws:guardduty:us-east-1:123456789012:detector/d6012345678912345678912349f831b8/finding/b7c1d3e5f7a9b1c3d5e7f9a1b3c5d7e9",
  "type": "Exfiltration:S3/MaliciousIPCaller",
  "resource": {
    "resourceType": "S3Bucket",
    "accessKeyDetails": {
      "accessKeyId": "AKIA2QXCZ4R7KJ6PLMN3",
      "principalId": "AIDA2QXCZ4R7KJ6PLMN3A",
      "userType": "IAMUser",
      "userName": "svc-deploy"
    },
    "s3BucketDetails": [
      {
        "arn": "arn:aws:s3:::nexacorp-customer-exports",
        "name": "nexacorp-customer-exports",
        "type": "Destination",
        "createdAt": "2025-03-11T09:02:00.000Z",
        "owner": { "id": "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90" },
        "defaultServerSideEncryption": { "encryptionType": "SSE-S3" },
        "publicAccess": {
          "effectivePermission": "NOT_PUBLIC",
          "permissionConfiguration": {
            "bucketLevelPermissions": { "accessControlList": { "allowsPublicReadAccess": false, "allowsPublicWriteAccess": false }, "bucketPolicy": { "allowsPublicReadAccess": false, "allowsPublicWriteAccess": false }, "blockPublicAccess": { "ignorePublicAcls": true, "restrictPublicBuckets": true, "blockPublicAcls": true, "blockPublicPolicy": true } }
          }
        }
      }
    ]
  },
  "service": {
    "serviceName": "guardduty",
    "detectorId": "d6012345678912345678912349f831b8",
    "action": {
      "actionType": "AWS_API_CALL",
      "awsApiCallAction": {
        "api": "GetObject",
        "serviceName": "s3.amazonaws.com",
        "callerType": "Remote IP",
        "remoteIpDetails": {
          "ipAddressV4": "203.0.113.77",
          "organization": { "asn": "209242", "asnOrg": "Cloudflare London, LLC", "isp": "Cloudflare", "org": "Cloudflare" },
          "country": { "countryName": "Netherlands" },
          "city": { "cityName": "Amsterdam" },
          "geoLocation": { "lat": 52.374, "lon": 4.8897 }
        }
      }
    },
    "resourceRole": "TARGET",
    "additionalInfo": { "threatListName": "ProofPoint", "threatName": "Scanner" },
    "evidence": { "threatIntelligenceDetails": [ { "threatNames": [ "Scanner" ], "threatListName": "ProofPoint" } ] },
    "eventFirstSeen": "2026-09-30T02:17:02.000Z",
    "eventLastSeen": "2026-09-30T02:18:55.000Z",
    "archived": false,
    "count": 37
  },
  "severity": 8,
  "createdAt": "2026-09-30T02:19:10.000Z",
  "updatedAt": "2026-09-30T02:19:10.000Z",
  "title": "An S3 API commonly used to collect data from an S3 bucket was invoked from an IP address on a threat list.",
  "description": "An S3 API GetObject was invoked on bucket nexacorp-customer-exports from a known malicious IP address 203.0.113.77."
}
```

### G3 — Bucket made public: `Policy:S3/BucketAnonymousAccessGranted`
Correlates to the CloudTrail `PutBucketPolicy`.
```json
{
  "schemaVersion": "2.0",
  "accountId": "123456789012",
  "region": "us-east-1",
  "partition": "aws",
  "id": "c8d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0",
  "arn": "arn:aws:guardduty:us-east-1:123456789012:detector/d6012345678912345678912349f831b8/finding/c8d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0",
  "type": "Policy:S3/BucketAnonymousAccessGranted",
  "resource": {
    "resourceType": "S3Bucket",
    "accessKeyDetails": { "accessKeyId": "AKIA2QXCZ4R7KJ6PLMN3", "principalId": "AIDA2QXCZ4R7KJ6PLMN3A", "userType": "IAMUser", "userName": "svc-deploy" },
    "s3BucketDetails": [
      {
        "arn": "arn:aws:s3:::nexacorp-customer-exports",
        "name": "nexacorp-customer-exports",
        "type": "Destination",
        "owner": { "id": "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90" },
        "publicAccess": { "effectivePermission": "PUBLIC", "permissionConfiguration": { "bucketLevelPermissions": { "bucketPolicy": { "allowsPublicReadAccess": true, "allowsPublicWriteAccess": false }, "blockPublicAccess": { "ignorePublicAcls": false, "restrictPublicBuckets": false, "blockPublicAcls": false, "blockPublicPolicy": false } } } }
      }
    ]
  },
  "service": {
    "serviceName": "guardduty",
    "detectorId": "d6012345678912345678912349f831b8",
    "action": {
      "actionType": "AWS_API_CALL",
      "awsApiCallAction": {
        "api": "PutBucketPolicy",
        "serviceName": "s3.amazonaws.com",
        "callerType": "Remote IP",
        "remoteIpDetails": { "ipAddressV4": "203.0.113.77", "organization": { "asn": "209242", "asnOrg": "Cloudflare London, LLC", "isp": "Cloudflare", "org": "Cloudflare" }, "country": { "countryName": "Netherlands" }, "city": { "cityName": "Amsterdam" }, "geoLocation": { "lat": 52.374, "lon": 4.8897 } }
      }
    },
    "resourceRole": "TARGET",
    "additionalInfo": {},
    "evidence": null,
    "eventFirstSeen": "2026-09-30T02:19:48.000Z",
    "eventLastSeen": "2026-09-30T02:19:48.000Z",
    "archived": false,
    "count": 1
  },
  "severity": 8,
  "createdAt": "2026-09-30T02:20:30.000Z",
  "updatedAt": "2026-09-30T02:20:30.000Z",
  "title": "An S3 bucket policy was modified to grant access to anonymous users.",
  "description": "An S3 bucket policy on nexacorp-customer-exports was modified to allow public/anonymous read access."
}
```

### G4 — IAM privilege escalation: `PrivilegeEscalation:IAMUser/AnomalousBehavior`
Correlates to the CloudTrail `AttachUserPolicy` AdministratorAccess (note `callerType:"Domain"` is also valid when
the call was proxied by a service like CloudFormation; here the attacker called IAM directly).
```json
{
  "schemaVersion": "2.0",
  "accountId": "123456789012",
  "region": "us-east-1",
  "partition": "aws",
  "id": "d9e3f5a7b9c1d3e5f7a9b1c3d5e7f9a1",
  "arn": "arn:aws:guardduty:us-east-1:123456789012:detector/d6012345678912345678912349f831b8/finding/d9e3f5a7b9c1d3e5f7a9b1c3d5e7f9a1",
  "type": "PrivilegeEscalation:IAMUser/AnomalousBehavior",
  "resource": {
    "resourceType": "AccessKey",
    "accessKeyDetails": { "accessKeyId": "AKIA2QXCZ4R7KJ6PLMN3", "principalId": "AIDA2QXCZ4R7KJ6PLMN3A", "userType": "IAMUser", "userName": "svc-deploy" }
  },
  "service": {
    "serviceName": "guardduty",
    "detectorId": "d6012345678912345678912349f831b8",
    "action": {
      "actionType": "AWS_API_CALL",
      "awsApiCallAction": {
        "api": "AttachUserPolicy",
        "serviceName": "iam.amazonaws.com",
        "callerType": "Remote IP",
        "affectedResources": { "AWS::IAM::User": "arn:aws:iam::123456789012:user/support-sync" },
        "remoteIpDetails": { "ipAddressV4": "203.0.113.77", "organization": { "asn": "209242", "asnOrg": "Cloudflare London, LLC", "isp": "Cloudflare", "org": "Cloudflare" }, "country": { "countryName": "Netherlands" }, "city": { "cityName": "Amsterdam" }, "geoLocation": { "lat": 52.374, "lon": 4.8897 } }
      }
    },
    "resourceRole": "TARGET",
    "additionalInfo": { "anomalies": { "anomalousAPIs": [ "iam:AttachUserPolicy", "iam:CreateUser", "iam:CreateAccessKey" ] } },
    "evidence": null,
    "eventFirstSeen": "2026-09-30T02:21:00.000Z",
    "eventLastSeen": "2026-09-30T02:22:05.000Z",
    "archived": false,
    "count": 3
  },
  "severity": 6,
  "createdAt": "2026-09-30T02:22:40.000Z",
  "updatedAt": "2026-09-30T02:22:40.000Z",
  "title": "APIs commonly used in PrivilegeEscalation tactics were invoked by user svc-deploy, under anomalous circumstances.",
  "description": "IAM user svc-deploy invoked a series of privilege-escalation APIs (CreateUser, CreateAccessKey, AttachUserPolicy AdministratorAccess) that deviate from its established baseline."
}
```

### G5 — Crypto-mining C2 DNS from an EC2 instance: `CryptoCurrency:EC2/BitcoinTool.B!DNS`
```json
{
  "schemaVersion": "2.0",
  "accountId": "123456789012",
  "region": "us-east-1",
  "partition": "aws",
  "id": "e1f4a6b8c0d2e4f6a8b0c2d4e6f8a0b2",
  "arn": "arn:aws:guardduty:us-east-1:123456789012:detector/d6012345678912345678912349f831b8/finding/e1f4a6b8c0d2e4f6a8b0c2d4e6f8a0b2",
  "type": "CryptoCurrency:EC2/BitcoinTool.B!DNS",
  "resource": {
    "resourceType": "Instance",
    "instanceDetails": {
      "instanceId": "i-02468ace13579bdf0",
      "instanceType": "g4dn.12xlarge",
      "launchTime": "2026-09-30T02:42:10.000Z",
      "platform": null,
      "iamInstanceProfile": { "arn": "arn:aws:iam::123456789012:instance-profile/ec2-ci-runner", "id": "AIPA2QXCZ4R7KPROFILE1" },
      "networkInterfaces": [ { "networkInterfaceId": "eni-0a1b2c3d4e5f60718", "privateIpAddress": "10.0.3.47", "publicIp": "54.160.22.9", "subnetId": "subnet-0abc12345", "vpcId": "vpc-0def67890", "securityGroups": [ { "groupName": "ci-sg", "groupId": "sg-0123456789abcdef0" } ], "privateDnsName": "ip-10-0-3-47.ec2.internal" } ],
      "tags": [ { "key": "Name", "value": "ci-runner-gpu" } ],
      "instanceState": "running",
      "availabilityZone": "us-east-1d",
      "imageId": "ami-0abcdef1234567890"
    }
  },
  "service": {
    "serviceName": "guardduty",
    "detectorId": "d6012345678912345678912349f831b8",
    "action": {
      "actionType": "DNS_REQUEST",
      "dnsRequestAction": { "domain": "xmr.pool-mine.example", "protocol": "UDP", "blocked": false }
    },
    "resourceRole": "ACTOR",
    "additionalInfo": { "threatListName": "ProofPoint", "value": "{\"threatListName\":\"ProofPoint\"}", "type": "default" },
    "evidence": { "threatIntelligenceDetails": [ { "threatNames": [ "CryptoCurrency:Bitcoin" ], "threatListName": "ProofPoint" } ] },
    "eventFirstSeen": "2026-09-30T02:44:19.000Z",
    "eventLastSeen": "2026-09-30T03:02:20.000Z",
    "archived": false,
    "count": 12
  },
  "severity": 8,
  "createdAt": "2026-09-30T02:45:19.000Z",
  "updatedAt": "2026-09-30T03:02:20.000Z",
  "title": "EC2 instance i-02468ace13579bdf0 is querying a domain name associated with bitcoin mining activity.",
  "description": "EC2 instance i-02468ace13579bdf0 is querying a domain name that is associated with bitcoin or other cryptocurrency mining activity."
}
```

### G6 — EKS exec into kube-system pod: `Execution:Kubernetes/ExecInKubeSystemPod`
```json
{
  "schemaVersion": "2.0",
  "accountId": "123456789012",
  "region": "us-east-1",
  "partition": "aws",
  "id": "f2a5b7c9d1e3f5a7b9c1d3e5f7a9b1c3",
  "arn": "arn:aws:guardduty:us-east-1:123456789012:detector/d6012345678912345678912349f831b8/finding/f2a5b7c9d1e3f5a7b9c1d3e5f7a9b1c3",
  "type": "Execution:Kubernetes/ExecInKubeSystemPod",
  "resource": {
    "resourceType": "EKSCluster",
    "eksClusterDetails": { "name": "nexacorp-prod", "arn": "arn:aws:eks:us-east-1:123456789012:cluster/nexacorp-prod", "createdAt": 1726500000.0, "vpcId": "vpc-0def67890", "status": "ACTIVE", "tags": [] },
    "kubernetesDetails": {
      "kubernetesUserDetails": { "username": "kubernetes-admin", "uid": "aws-iam-authenticator:123456789012:AIDA2QXCZ4R7KJ6PLMN3A", "groups": [ "system:masters", "system:authenticated" ] },
      "kubernetesWorkloadDetails": { "name": "coredns-7f6b8c9d4-abcde", "type": "pods", "namespace": "kube-system" }
    }
  },
  "service": {
    "serviceName": "guardduty",
    "detectorId": "d6012345678912345678912349f831b8",
    "action": {
      "actionType": "KUBERNETES_API_CALL",
      "kubernetesApiCallAction": {
        "requestUri": "/api/v1/namespaces/kube-system/pods/coredns-7f6b8c9d4-abcde/exec",
        "verb": "create",
        "sourceIPs": [ "203.0.113.77" ],
        "userAgent": "kubectl/v1.30.0 (linux/amd64)",
        "remoteIpDetails": { "ipAddressV4": "203.0.113.77", "organization": { "asn": "209242", "asnOrg": "Cloudflare London, LLC", "isp": "Cloudflare", "org": "Cloudflare" }, "country": { "countryName": "Netherlands" }, "city": { "cityName": "Amsterdam" }, "geoLocation": { "lat": 52.374, "lon": 4.8897 } },
        "statusCode": 101
      }
    },
    "resourceRole": "TARGET",
    "additionalInfo": {},
    "evidence": null,
    "eventFirstSeen": "2026-09-30T03:10:11.000Z",
    "eventLastSeen": "2026-09-30T03:10:11.000Z",
    "archived": false,
    "count": 1
  },
  "severity": 5,
  "createdAt": "2026-09-30T03:11:00.000Z",
  "updatedAt": "2026-09-30T03:11:00.000Z",
  "title": "Exec was invoked on a pod in the kube-system namespace on cluster nexacorp-prod.",
  "description": "A command was executed inside a pod within the kube-system namespace on EKS cluster nexacorp-prod, which is uncommon and can indicate malicious activity."
}
```

---

## 5. Investigation notes

- **GuardDuty is a signal, CloudTrail is the evidence.** Pivot from a finding to the raw calls via:
  `resource.accessKeyDetails.accessKeyId` → CloudTrail `userIdentity.accessKeyId`;
  `service.action.awsApiCallAction.api` → CloudTrail `eventName`;
  `remoteIpDetails.ipAddressV4` → CloudTrail `sourceIPAddress`;
  `service.eventFirstSeen`/`eventLastSeen` → CloudTrail `eventTime` window.
- `resourceRole` = `TARGET` (your resource was acted upon) vs `ACTOR` (your resource initiated — e.g. an EC2
  instance beaconing out, as in G5). For EC2 network/DNS findings the instance is usually the ACTOR.
- `service.count` + `eventLastSeen` rising on the same `id` = repeat activity folded into one finding; don't
  treat each EventBridge delivery as a new incident.
- `additionalInfo.sample: true` (and `GeneratedFinding*` placeholder strings) mark **sample/demo** findings —
  exclude them from real alerting. Real findings never carry `sample: true`.
- `severity` is numeric; map to bands (Critical ≥9, High 7–8.9, Medium 4–6.9, Low 1–3.9). `AttackSequence:*`
  findings are Critical and bundle several correlated signals (`service.featureName: "Correlation"`).
- `callerType` = `Remote IP` → look at `remoteIpDetails`; `Domain` → look at `domainDetails.domain` (call came
  via an AWS service such as `cloudformation.amazonaws.com`, which changes who the real actor is).

## 6. Common mistakes / non-existent fields

- **Do not** flatten to `aws.guardduty.*` or wrap in a Wazuh envelope. Keep the native nested finding.
- `severity` is a **number** (e.g. `8`, `5`, `2.5`), **not** a string `"High"`. The words
  Critical/High/Medium/Low are derived from the numeric bands, not stored in the finding.
- `service.archived`, `*.blocked`, `publicAccess...allowsPublicReadAccess` are **booleans**; `service.count`
  and port numbers are **integers**.
- `s3BucketDetails` is an **array**, even for one bucket. `resource.resourceType` is a single string
  (`AccessKey`, not `IAMUser`) and selects exactly one detail object.
- The action sub-object name must match `actionType`: `AWS_API_CALL`→`awsApiCallAction`,
  `NETWORK_CONNECTION`→`networkConnectionAction`, `DNS_REQUEST`→`dnsRequestAction`,
  `PORT_PROBE`→`portProbeAction`, `KUBERNETES_API_CALL`→`kubernetesApiCallAction`,
  `RDS_LOGIN_ATTEMPT`→`rdsLoginAttemptAction`. Don't put a `networkConnectionAction` under an `AWS_API_CALL`.
- Finding `type` strings are exact and case-sensitive, with `:` and `/` separators and sometimes `!DNS` / `.B`
  suffixes (e.g. `CryptoCurrency:EC2/BitcoinTool.B!DNS`). Don't paraphrase them.
- `connectionDirection` is `INBOUND`/`OUTBOUND`/`UNKNOWN`; `effectivePermission` is
  `PUBLIC`/`NOT_PUBLIC`/`UNKNOWN`; `resourceRole` is `ACTOR`/`TARGET` — all uppercase enums.
- The EventBridge envelope `detail-type` is exactly `"GuardDuty Finding"` and `source` is `"aws.guardduty"`.
  The finding itself lives in `detail`, not at the top level, when shown in EventBridge form.
