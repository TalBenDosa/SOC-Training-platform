# Google Cloud Audit Logs — log schema card

GCP Cloud Audit Logs are **JSON-native**: each entry is a Cloud Logging `LogEntry` whose `protoPayload` is a
`google.cloud.audit.AuditLog`. Show the full `LogEntry` exactly as delivered; do **not** flatten to ECS
`gcp.audit.*` or wrap in a Wazuh `data.*` envelope.

## 1. Official sources

- Understanding audit logs (logName formats, sample LogEntry, severity, redaction, data-access disabled by default):
  https://docs.cloud.google.com/logging/docs/audit/understanding-audit-logs
- AuditLog message + nested types (AuthenticationInfo, AuthorizationInfo, RequestMetadata):
  https://docs.cloud.google.com/logging/docs/reference/audit/auditlog/rest/Shared.Types/AuditLog
- IAM audit-logging examples (CreateServiceAccountKey, serviceAccountKeyName, GenerateAccessToken delegation):
  https://docs.cloud.google.com/iam/docs/audit-logging/examples-service-accounts
- Entry shapes (SetIamPolicy with policyDelta, compute.instances.insert, storage.objects.get, k8s on GKE)
  cross-checked against elastic/integrations `gcp/data_stream/audit` raw test inputs.

## 2. Native format & delivery

- Each log entry is a Cloud Logging **`LogEntry`**. The audit payload is in
  `protoPayload` with `@type` = `type.googleapis.com/google.cloud.audit.AuditLog`.
- **Four audit log types**, distinguished by `logName`:
  - Admin Activity: `projects/<PROJECT_ID>/logs/cloudaudit.googleapis.com%2Factivity`
  - Data Access: `projects/<PROJECT_ID>/logs/cloudaudit.googleapis.com%2Fdata_access`
  - System Event: `projects/<PROJECT_ID>/logs/cloudaudit.googleapis.com%2Fsystem_event`
  - Policy Denied: `projects/<PROJECT_ID>/logs/cloudaudit.googleapis.com%2Fpolicy`
  (`%2F` is a URL-encoded `/`; folder/org/billingAccount variants use those prefixes.)
- **Delivery:** entries are written to Cloud Logging and can be routed (via a **sink**) to Pub/Sub, BigQuery, or
  Cloud Storage. Exported to Storage as newline-delimited JSON `LogEntry` objects. SIEMs typically pull from
  Pub/Sub.
- **Data Access logs are disabled by default** (except BigQuery data-access, which is always on). Admin Activity
  and System Event are always on and free.
- **We standardise on the full `LogEntry`** (with `protoPayload`, `resource`, `severity`, `timestamp`,
  `receiveTimestamp`, `logName`, `insertId`, `operation?`, `labels?`).

## 3. Core field reference

### LogEntry (top level)
| Field | Type | Notes |
|---|---|---|
| `logName` | string | One of the four formats above; identifies the audit type. |
| `protoPayload` | object | The AuditLog (see below). `@type` = `type.googleapis.com/google.cloud.audit.AuditLog`. |
| `resource` | object | `{type, labels{...}}` — the monitored resource, e.g. `type:"gce_instance"`, `"gcs_bucket"`, `"service_account"`, `"project"`, `"k8s_cluster"`; labels like `project_id`, `zone`, `instance_id`, `bucket_name`, `location`, `cluster_name`, `email_id`. |
| `severity` | string | `DEFAULT, DEBUG, INFO, NOTICE, WARNING, ERROR, CRITICAL, ALERT, EMERGENCY`. Admin Activity ≈ `NOTICE`; Data Access ≈ `INFO`; denied/error ≈ `ERROR`. |
| `timestamp` | string | RFC3339 UTC, when the event occurred. |
| `receiveTimestamp` | string | When Cloud Logging received it (ingest delay). |
| `insertId` | string | Unique per entry (dedup key). |
| `operation` | object (opt) | `{id, producer, first, last}` — groups multi-entry operations. |
| `labels` | object (opt) | For GKE/k8s: `authorization.k8s.io/decision`, `authorization.k8s.io/reason`. |

### protoPayload = AuditLog
| Field | Type | Notes |
|---|---|---|
| `@type` | string | `type.googleapis.com/google.cloud.audit.AuditLog`. |
| `serviceName` | string | API service, e.g. `iam.googleapis.com`, `cloudresourcemanager.googleapis.com`, `compute.googleapis.com`, `storage.googleapis.com`, `iamcredentials.googleapis.com`, `container.googleapis.com`, `k8s.io`. |
| `methodName` | string | The operation, e.g. `SetIamPolicy`, `google.iam.admin.v1.CreateServiceAccountKey`, `v1.compute.instances.insert`, `storage.objects.get`, `GenerateAccessToken`, `io.k8s.core.v1.pods.create`. |
| `resourceName` | string | Full resource path acted on. |
| `resourceLocation` | object (opt) | `{currentLocations:[...]}`. |
| `numResponseItems` | string/int (opt) | For list/read ops. |
| `status` | object | `{}` on success; `{code, message}` on failure (gRPC code; 7=PERMISSION_DENIED, 0=OK). |
| `authenticationInfo` | object | Who called — see below. |
| `authorizationInfo` | array | Each `{resource, permission, granted (bool), resourceAttributes{...}, permissionType?}`. |
| `requestMetadata` | object | `{callerIp, callerSuppliedUserAgent, callerNetwork?, requestAttributes{time, auth}, destinationAttributes{}}`. |
| `request` | object (opt) | API-specific request; carries its own `@type`. |
| `response` | object (opt) | API-specific response; own `@type`. |
| `metadata` | object (opt) | Service-specific extra context. |
| `serviceData` | object (opt) | Legacy per-service data; IAM policy changes carry `serviceData.policyDelta.bindingDeltas[{action:ADD|REMOVE, member, role}]`. |
| `policyViolationInfo` | object (opt) | Present on Policy Denied entries. |

### authenticationInfo
`{principalEmail, principalSubject?, serviceAccountKeyName?, serviceAccountDelegationInfo[?],
authoritySelector?, thirdPartyPrincipal?}`.
- `principalEmail` — the caller (user or `*.iam.gserviceaccount.com` service account). May be **redacted/absent**
  for some Data Access reads and external callers.
- `serviceAccountKeyName` — `//iam.googleapis.com/projects/<p>/serviceAccounts/<sa>/keys/<keyId>` when a SA key
  authenticated the request (key-based auth; strong compromise pivot).
- `serviceAccountDelegationInfo[]` — present when the call used impersonated/short-lived creds; each entry has
  `firstPartyPrincipal.principalEmail` (or `thirdPartyPrincipal`) = the human/identity behind the impersonation.

### requestMetadata
`callerIp` (may be `gce-internal-ip` or `private` when redacted), `callerSuppliedUserAgent`
(e.g. `google-cloud-sdk gcloud/...`, `kubectl/v1.30.0 ...`, `Go-http-client/2.0,gzip(gfe)`), `requestAttributes.time`.

---

## 4. Realistic samples (project `nexacorp-prod`, attacker SA `made-up-ci@nexacorp-prod.iam.gserviceaccount.com`, IP `203.0.113.77`)

### GC1 — SetIamPolicy granting Owner to an attacker SA (priv-esc / persistence; policyDelta shows the change)
```json
{
  "insertId": "-30102re2sad8",
  "logName": "projects/nexacorp-prod/logs/cloudaudit.googleapis.com%2Factivity",
  "protoPayload": {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    "authenticationInfo": {
      "principalEmail": "made-up-ci@nexacorp-prod.iam.gserviceaccount.com",
      "principalSubject": "serviceAccount:made-up-ci@nexacorp-prod.iam.gserviceaccount.com"
    },
    "authorizationInfo": [
      {
        "granted": true,
        "permission": "resourcemanager.projects.setIamPolicy",
        "permissionType": "ADMIN_WRITE",
        "resource": "projects/nexacorp-prod",
        "resourceAttributes": { "name": "projects/nexacorp-prod", "service": "cloudresourcemanager.googleapis.com", "type": "cloudresourcemanager.googleapis.com/Project" }
      }
    ],
    "methodName": "SetIamPolicy",
    "request": {
      "@type": "type.googleapis.com/google.iam.v1.SetIamPolicyRequest",
      "resource": "nexacorp-prod",
      "policy": { "bindings": [ { "members": [ "user:attacker@evil.example" ], "role": "roles/owner" } ], "etag": "BwYnObHBOBA=" }
    },
    "response": { "@type": "type.googleapis.com/google.iam.v1.Policy", "etag": "BwYnQ8iRtu0=" },
    "serviceData": {
      "@type": "type.googleapis.com/google.iam.v1.logging.AuditData",
      "policyDelta": { "bindingDeltas": [ { "action": "ADD", "member": "user:attacker@evil.example", "role": "roles/owner" } ] }
    },
    "requestMetadata": {
      "callerIp": "203.0.113.77",
      "callerSuppliedUserAgent": "google-cloud-sdk gcloud/501.0.0 command/gcloud.projects.add-iam-policy-binding invocation-id/e9e9e4b6 environment/None client-os/LINUX,gzip(gfe)",
      "requestAttributes": { "time": "2026-09-30T02:33:40.942393Z", "auth": {} },
      "destinationAttributes": {}
    },
    "resourceName": "projects/nexacorp-prod",
    "serviceName": "cloudresourcemanager.googleapis.com",
    "status": {}
  },
  "receiveTimestamp": "2026-09-30T02:33:41.785498724Z",
  "resource": { "labels": { "project_id": "nexacorp-prod" }, "type": "project" },
  "severity": "NOTICE",
  "timestamp": "2026-09-30T02:33:40.942393Z"
}
```

### GC2 — CreateServiceAccountKey (persistence: minting a long-lived SA key)
```json
{
  "insertId": "k1a2b3c4d5e6",
  "logName": "projects/nexacorp-prod/logs/cloudaudit.googleapis.com%2Factivity",
  "protoPayload": {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    "authenticationInfo": { "principalEmail": "made-up-ci@nexacorp-prod.iam.gserviceaccount.com" },
    "authorizationInfo": [ { "granted": true, "permission": "iam.serviceAccountKeys.create", "permissionType": "ADMIN_WRITE", "resourceAttributes": {} } ],
    "methodName": "google.iam.admin.v1.CreateServiceAccountKey",
    "request": {
      "@type": "type.googleapis.com/google.iam.admin.v1.CreateServiceAccountKeyRequest",
      "name": "projects/-/serviceAccounts/deploy-sa@nexacorp-prod.iam.gserviceaccount.com",
      "private_key_type": 2
    },
    "requestMetadata": {
      "callerIp": "203.0.113.77",
      "callerSuppliedUserAgent": "google-cloud-sdk gcloud/501.0.0 command/gcloud.iam.service-accounts.keys.create,gzip(gfe)",
      "requestAttributes": { "time": "2026-09-30T02:35:12.100000Z", "auth": {} },
      "destinationAttributes": {}
    },
    "resourceName": "projects/-/serviceAccounts/114729384756102938475",
    "serviceName": "iam.googleapis.com",
    "status": {}
  },
  "receiveTimestamp": "2026-09-30T02:35:12.551702143Z",
  "resource": { "labels": { "email_id": "deploy-sa@nexacorp-prod.iam.gserviceaccount.com", "project_id": "nexacorp-prod", "unique_id": "114729384756102938475" }, "type": "service_account" },
  "severity": "NOTICE",
  "timestamp": "2026-09-30T02:35:11.293368631Z"
}
```

### GC3 — GenerateAccessToken (impersonation / credential access; Data Access log)
```json
{
  "insertId": "15djrryd6bap",
  "logName": "projects/nexacorp-prod/logs/cloudaudit.googleapis.com%2Fdata_access",
  "operation": { "first": true, "id": "op-genaccess-1", "last": true, "producer": "iamcredentials.googleapis.com" },
  "protoPayload": {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    "authenticationInfo": { "principalEmail": "made-up-ci@nexacorp-prod.iam.gserviceaccount.com" },
    "authorizationInfo": [ { "granted": true, "permission": "iam.serviceAccounts.getAccessToken", "permissionType": "ADMIN_READ", "resourceAttributes": {} } ],
    "metadata": { "identityDelegationChain": [ "projects/-/serviceAccounts/deploy-sa@nexacorp-prod.iam.gserviceaccount.com" ] },
    "methodName": "GenerateAccessToken",
    "request": { "@type": "type.googleapis.com/google.iam.credentials.v1.GenerateAccessTokenRequest", "name": "projects/-/serviceAccounts/deploy-sa@nexacorp-prod.iam.gserviceaccount.com" },
    "requestMetadata": {
      "callerIp": "203.0.113.77",
      "callerSuppliedUserAgent": "google-cloud-sdk gcloud/501.0.0,gzip(gfe)",
      "requestAttributes": { "time": "2026-09-30T02:36:55.301834867Z", "auth": {} },
      "destinationAttributes": {}
    },
    "resourceName": "projects/-/serviceAccounts/114729384756102938475",
    "serviceName": "iamcredentials.googleapis.com",
    "status": {}
  },
  "receiveTimestamp": "2026-09-30T02:36:56.551702143Z",
  "resource": { "labels": { "email_id": "deploy-sa@nexacorp-prod.iam.gserviceaccount.com", "project_id": "nexacorp-prod", "unique_id": "114729384756102938475" }, "type": "service_account" },
  "severity": "INFO",
  "timestamp": "2026-09-30T02:36:55.293368631Z"
}
```

### GC4 — storage.objects.get (data exfil read; Data Access log, principal may be redacted on reads)
```json
{
  "insertId": "4pyr6eegiuw1",
  "logName": "projects/nexacorp-prod/logs/cloudaudit.googleapis.com%2Fdata_access",
  "protoPayload": {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    "authenticationInfo": {
      "principalEmail": "deploy-sa@nexacorp-prod.iam.gserviceaccount.com",
      "serviceAccountKeyName": "//iam.googleapis.com/projects/nexacorp-prod/serviceAccounts/deploy-sa@nexacorp-prod.iam.gserviceaccount.com/keys/c71e040fb4b71d798ce4baca14e15ab62115aaef",
      "serviceAccountDelegationInfo": [ { "firstPartyPrincipal": { "principalEmail": "made-up-ci@nexacorp-prod.iam.gserviceaccount.com" } } ]
    },
    "authorizationInfo": [ { "granted": true, "permission": "storage.objects.get", "resource": "projects/_/buckets/nexacorp-customer-exports/objects/pii/customers_full.csv.gz", "resourceAttributes": {} } ],
    "methodName": "storage.objects.get",
    "requestMetadata": {
      "callerIp": "203.0.113.77",
      "callerSuppliedUserAgent": "google-cloud-sdk gsutil/5.27,gzip(gfe)",
      "requestAttributes": { "time": "2026-09-30T02:38:08.205760711Z", "auth": {} },
      "destinationAttributes": {}
    },
    "resourceLocation": { "currentLocations": [ "us-central1" ] },
    "resourceName": "projects/_/buckets/nexacorp-customer-exports/objects/pii/customers_full.csv.gz",
    "serviceName": "storage.googleapis.com",
    "status": {}
  },
  "receiveTimestamp": "2026-09-30T02:38:08.699785539Z",
  "resource": { "labels": { "bucket_name": "nexacorp-customer-exports", "location": "us-central1", "project_id": "nexacorp-prod" }, "type": "gcs_bucket" },
  "severity": "INFO",
  "timestamp": "2026-09-30T02:38:08.199407722Z"
}
```

### GC5 — compute.instances.insert (crypto-mining VM creation; Admin Activity, multiple authorizationInfo)
```json
{
  "insertId": "-w5vrlhdm7gk",
  "logName": "projects/nexacorp-prod/logs/cloudaudit.googleapis.com%2Factivity",
  "operation": { "first": true, "id": "operation-1790648000-abcd", "producer": "compute.googleapis.com" },
  "protoPayload": {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    "authenticationInfo": {
      "principalEmail": "made-up-ci@nexacorp-prod.iam.gserviceaccount.com",
      "serviceAccountKeyName": "//iam.googleapis.com/projects/nexacorp-prod/serviceAccounts/deploy-sa@nexacorp-prod.iam.gserviceaccount.com/keys/c71e040fb4b71d798ce4baca14e15ab62115aaef"
    },
    "authorizationInfo": [
      { "granted": true, "permission": "compute.instances.create", "permissionType": "ADMIN_WRITE", "resource": "projects/nexacorp-prod/zones/us-central1-a/instances/miner-01", "resourceAttributes": { "name": "projects/nexacorp-prod/zones/us-central1-a/instances/miner-01", "service": "compute", "type": "compute.instances" } },
      { "granted": true, "permission": "compute.instances.setServiceAccount", "permissionType": "ADMIN_WRITE", "resource": "projects/nexacorp-prod/zones/us-central1-a/instances/miner-01", "resourceAttributes": {} }
    ],
    "methodName": "v1.compute.instances.insert",
    "request": {
      "@type": "type.googleapis.com/compute.instances.insert",
      "name": "miner-01",
      "machineType": "https://www.googleapis.com/compute/v1/projects/nexacorp-prod/zones/us-central1-a/machineTypes/a2-highgpu-4g"
    },
    "requestMetadata": {
      "callerIp": "203.0.113.77",
      "callerSuppliedUserAgent": "google-cloud-sdk gcloud/501.0.0 command/gcloud.compute.instances.create,gzip(gfe)",
      "requestAttributes": { "time": "2026-09-30T02:42:13.966817Z", "auth": {} },
      "destinationAttributes": {}
    },
    "resourceName": "projects/nexacorp-prod/zones/us-central1-a/instances/miner-01",
    "response": { "@type": "type.googleapis.com/operation", "operationType": "insert", "status": "RUNNING" },
    "serviceName": "compute.googleapis.com"
  },
  "receiveTimestamp": "2026-09-30T02:42:14.634438657Z",
  "resource": { "labels": { "instance_id": "2525602744967966726", "project_id": "nexacorp-prod", "zone": "us-central1-a" }, "type": "gce_instance" },
  "severity": "NOTICE",
  "timestamp": "2026-09-30T02:42:13.176899Z"
}
```

### GC6 — PERMISSION_DENIED (recon hitting a wall; Admin Activity, status.code=7)
```json
{
  "insertId": "deniedx1",
  "logName": "projects/nexacorp-prod/logs/cloudaudit.googleapis.com%2Factivity",
  "protoPayload": {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    "authenticationInfo": { "principalEmail": "made-up-ci@nexacorp-prod.iam.gserviceaccount.com" },
    "authorizationInfo": [ { "granted": false, "permission": "iam.serviceAccounts.list", "permissionType": "ADMIN_READ", "resourceAttributes": {} } ],
    "methodName": "google.iam.admin.v1.ListServiceAccounts",
    "requestMetadata": { "callerIp": "203.0.113.77", "callerSuppliedUserAgent": "google-cloud-sdk gcloud/501.0.0,gzip(gfe)", "requestAttributes": { "time": "2026-09-30T02:31:00Z", "auth": {} }, "destinationAttributes": {} },
    "resourceName": "projects/nexacorp-prod",
    "serviceName": "iam.googleapis.com",
    "status": { "code": 7, "message": "Permission 'iam.serviceAccounts.list' denied on resource (or it may not exist)." }
  },
  "receiveTimestamp": "2026-09-30T02:31:00.5Z",
  "resource": { "labels": { "project_id": "nexacorp-prod" }, "type": "project" },
  "severity": "ERROR",
  "timestamp": "2026-09-30T02:31:00.1Z"
}
```

---

## 5. Investigation notes

- **Pivots:** actor = `protoPayload.authenticationInfo.principalEmail`; key-based auth =
  `authenticationInfo.serviceAccountKeyName` (a stolen SA key leaves this on every call — strong IOC);
  impersonation chain = `authenticationInfo.serviceAccountDelegationInfo[].firstPartyPrincipal.principalEmail`
  (the human behind a service-account action); source = `requestMetadata.callerIp` + `callerSuppliedUserAgent`;
  action = `serviceName` + `methodName`; target = `resourceName`; `insertId` dedups.
- **IAM changes:** read `serviceData.policyDelta.bindingDeltas[]` (ADD/REMOVE member+role) rather than diffing the
  full `request.policy`/`response` — the delta is the actual grant. A `roles/owner`/`roles/editor` ADD to an
  external or odd member is the priv-esc signal.
- **Log type tells you a lot:** `.../activity` = control-plane changes (always on); `.../data_access` = reads
  of data/credentials (off by default — presence means it was enabled, and `storage.objects.get` /
  `GenerateAccessToken` here are the exfil/impersonation steps); `.../policy` = denied by org policy / VPC-SC;
  `.../system_event` = GCP-initiated.
- **`status`:** `{}` = success; `{code:7,...}` = PERMISSION_DENIED (recon/misconfig); `authorizationInfo.granted`
  per-permission shows exactly which permission was allowed/denied.
- **Redaction:** `principalEmail` can be absent on some data-access reads / external callers; `callerIp` can be
  `gce-internal-ip` or `private`. Don't assume a missing field = no actor.
- **GKE on GCP:** k8s API calls appear as audit entries with `serviceName:"k8s.io"`, `methodName` like
  `io.k8s.core.v1.pods.create`, `resource.type:"k8s_cluster"`, and `labels["authorization.k8s.io/decision"]`.
  For deeper k8s field detail (verbs, objectRef, impersonation) see the Kubernetes audit card.
- **Timing:** `timestamp` = event time; `receiveTimestamp` = ingest time (the gap is Logging delay). Use
  `timestamp` to line up with CloudTrail/Azure.

## 6. Common mistakes / non-existent fields

- **Do not** flatten to `gcp.audit.*` / `json.protoPayload.*` (Elastic ECS) or wrap in a Wazuh `data.*` envelope.
  Keep the full `LogEntry` with `protoPayload` nested.
- `protoPayload.@type` is required and must be exactly
  `type.googleapis.com/google.cloud.audit.AuditLog`. `request`/`response` carry their own `@type`.
- `logName` uses the **URL-encoded** `%2F`, not a literal `/`, before `activity`/`data_access`/`system_event`/`policy`.
- `status` on success is `{}` (empty object), **not** `{code:0}` in most entries and **not** `"Success"`.
  Failures use gRPC codes (7 = PERMISSION_DENIED), not HTTP codes.
- `authorizationInfo` is an **array** (one entry per permission checked), each with a boolean `granted`.
  `permissionType` (`ADMIN_READ`/`ADMIN_WRITE`/`DATA_READ`/`DATA_WRITE`) is present on newer entries but optional.
- `authenticationInfo.serviceAccountKeyName` is the full `//iam.googleapis.com/.../keys/<id>` resource name, not
  just a key id. Don't shorten it.
- `methodName` formats are service-specific and exact: IAM uses `google.iam.admin.v1.CreateServiceAccountKey`,
  Resource Manager uses bare `SetIamPolicy`, Compute uses `v1.compute.instances.insert`, Storage uses
  `storage.objects.get`, GKE uses `io.k8s.*`. Don't normalize them to one style.
- `resource` (the LogEntry monitored resource) is different from `protoPayload.resourceName`. Keep both.
- Severity is the Cloud Logging enum (`NOTICE`/`INFO`/`ERROR`...), not a number and not GuardDuty-style bands.
