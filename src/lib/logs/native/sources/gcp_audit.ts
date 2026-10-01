/**
 * Google Cloud Audit Logs — native source module.
 *
 * Card: docs/log-schemas/cloud-gcp-audit.md. Native format = a Cloud Logging
 * `LogEntry` whose `protoPayload` is a `google.cloud.audit.AuditLog`, nested exactly
 * as delivered. No `gcp.audit.*` ECS flattening, no Wazuh envelope.
 *
 * The platform has no authored GCP telemetry today (`cloud_gcp` is empty). This
 * module therefore (a) validates the card's samples and (b) provides a CROSS-CLOUD
 * render: an AWS-authored CloudTrail event is shown as the equivalent GCP audit
 * entry ONLY where a true equivalent exists (S3→GCS, IAM policy→SetIamPolicy,
 * access-key→service-account key, AssumeRole→GenerateAccessToken, RunInstances→
 * compute.instances.insert, GetSecretValue→AccessSecretVersion). Where no GCP
 * equivalent exists (StopLogging, ConsoleLogin, CloudWatch…), it returns null.
 *
 * `protoPayload.request/response/metadata/serviceData` are per-service free-form
 * and declared as open sub-objects.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { KindSchema, NativeCtx, NativeLog, NativeSource, SourceSchema, UseCase } from "../types";
import { entitySeed, rs, rv } from "./cloud-shared";

const kinds: Record<string, KindSchema> = {
  AuditLog: {
    required: ["logName", "protoPayload", "resource", "severity", "timestamp", "receiveTimestamp", "insertId"],
    optional: ["operation", "labels", "resource.type"],
    openPrefixes: ["protoPayload", "resource.labels", "operation", "labels"],
  },
};

const schema: SourceSchema = {
  sourceId: "gcp_audit",
  category: "cloud",
  card: "cloud-gcp-audit.md",
  product: "Google Cloud Audit Logs",
  format: "json",
  vendorMatch: ["gcp", "google cloud"],
  telemetrySources: ["cloud_gcp"],
  kinds,
};

export function kindOf(record: Record<string, unknown>): string | null {
  const pp = record["protoPayload"];
  if (pp && typeof pp === "object" && (pp as Record<string, unknown>)["@type"] === "type.googleapis.com/google.cloud.audit.AuditLog") return "AuditLog";
  return null;
}

// ── cross-cloud mapping (AWS CloudTrail eventName → GCP audit method) ───────────

interface Mapped {
  serviceName: string;
  methodName: string;
  permission: string;
  resourceType: string;
  dataAccess: boolean;
  /** build resourceName + labels + serviceData from the AWS event */
  shape: (ev: TelemetryEvent, proj: string) => { resourceName: string; labels: Record<string, unknown>; serviceData?: Record<string, unknown>; request?: Record<string, unknown> };
}

const MAP: Record<string, Mapped> = {
  GetObject: { serviceName: "storage.googleapis.com", methodName: "storage.objects.get", permission: "storage.objects.get", resourceType: "gcs_bucket", dataAccess: true,
    shape: (ev) => { const b = bucketOf(ev); return { resourceName: `projects/_/buckets/${b.bucket}/objects/${b.key}`, labels: { bucket_name: b.bucket, project_id: "", location: "us-central1" } }; } },
  PutObject: { serviceName: "storage.googleapis.com", methodName: "storage.objects.create", permission: "storage.objects.create", resourceType: "gcs_bucket", dataAccess: true,
    shape: (ev) => { const b = bucketOf(ev); return { resourceName: `projects/_/buckets/${b.bucket}/objects/${b.key}`, labels: { bucket_name: b.bucket, project_id: "" } }; } },
  CopyObject: { serviceName: "storage.googleapis.com", methodName: "storage.objects.create", permission: "storage.objects.create", resourceType: "gcs_bucket", dataAccess: true,
    shape: (ev) => { const b = bucketOf(ev); return { resourceName: `projects/_/buckets/${b.bucket}/objects/${b.key}`, labels: { bucket_name: b.bucket, project_id: "" } }; } },
  ListBuckets: { serviceName: "storage.googleapis.com", methodName: "storage.buckets.list", permission: "storage.buckets.list", resourceType: "project", dataAccess: false,
    shape: (_ev, proj) => ({ resourceName: `projects/${proj}`, labels: { project_id: proj } }) },
  GetSecretValue: { serviceName: "secretmanager.googleapis.com", methodName: "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion", permission: "secretmanager.versions.access", resourceType: "audited_resource", dataAccess: true,
    shape: (ev, proj) => { const sid = (rs(ev.raw, "aws.cloudtrail.requestParameters.secretId") ?? "prod/secret").split(":").pop()!.split("/").pop()!; return { resourceName: `projects/${proj}/secrets/${sid}/versions/latest`, labels: { project_id: proj } }; } },
  AttachUserPolicy: iamPolicyMap(), PutUserPolicy: iamPolicyMap(), AttachRolePolicy: iamPolicyMap(), PutRolePolicy: iamPolicyMap(), UpdateAssumeRolePolicy: iamPolicyMap(),
  CreateAccessKey: { serviceName: "iam.googleapis.com", methodName: "google.iam.admin.v1.CreateServiceAccountKey", permission: "iam.serviceAccountKeys.create", resourceType: "service_account", dataAccess: false,
    shape: (ev, proj) => { const u = rs(ev.raw, "aws.cloudtrail.requestParameters.userName") ?? "svc"; return { resourceName: `projects/-/serviceAccounts/${u}@${proj}.iam.gserviceaccount.com`, labels: { project_id: proj, email_id: `${u}@${proj}.iam.gserviceaccount.com` } }; } },
  CreateUser: { serviceName: "iam.googleapis.com", methodName: "google.iam.admin.v1.CreateServiceAccount", permission: "iam.serviceAccounts.create", resourceType: "service_account", dataAccess: false,
    shape: (ev, proj) => { const u = rs(ev.raw, "aws.cloudtrail.requestParameters.userName") ?? "svc"; return { resourceName: `projects/${proj}`, labels: { project_id: proj, email_id: `${u}@${proj}.iam.gserviceaccount.com` } }; } },
  AssumeRole: { serviceName: "iamcredentials.googleapis.com", methodName: "GenerateAccessToken", permission: "iam.serviceAccounts.getAccessToken", resourceType: "service_account", dataAccess: true,
    shape: (ev, proj) => ({ resourceName: `projects/-/serviceAccounts/deploy-sa@${proj}.iam.gserviceaccount.com`, labels: { project_id: proj, email_id: `deploy-sa@${proj}.iam.gserviceaccount.com` } }) },
  RunInstances: { serviceName: "compute.googleapis.com", methodName: "v1.compute.instances.insert", permission: "compute.instances.create", resourceType: "gce_instance", dataAccess: false,
    shape: (ev, proj) => { const it = rs(ev.raw, "aws.cloudtrail.request_parameters.instanceType", "aws.cloudtrail.requestParameters.instanceType") ?? "n1"; const gpu = /^(p|g|a2|a3|dl|trn|inf)/.test(it); return { resourceName: `projects/${proj}/zones/us-central1-a/instances/miner-01`, labels: { project_id: proj, zone: "us-central1-a", instance_id: "2525602744967966726" }, request: { "@type": "type.googleapis.com/compute.instances.insert", name: "miner-01", machineType: `https://www.googleapis.com/compute/v1/projects/${proj}/zones/us-central1-a/machineTypes/${gpu ? "a2-highgpu-4g" : "e2-standard-4"}` } }; } },
};

function iamPolicyMap(): Mapped {
  return {
    serviceName: "cloudresourcemanager.googleapis.com", methodName: "SetIamPolicy", permission: "resourcemanager.projects.setIamPolicy", resourceType: "project", dataAccess: false,
    shape: (ev, proj) => {
      const pol = rs(ev.raw, "aws.cloudtrail.requestParameters.policyArn") ?? "";
      const member = (ev.user?.email ?? ev.user_email) ? `user:${ev.user?.email ?? ev.user_email}` : "serviceAccount:attacker@external.iam.gserviceaccount.com";
      const role = /AdministratorAccess/i.test(pol) || /UpdateAssumeRolePolicy/i.test(String(rs(ev.raw, "aws.cloudtrail.eventName"))) ? "roles/owner" : "roles/editor";
      return { resourceName: `projects/${proj}`, labels: { project_id: proj }, serviceData: { "@type": "type.googleapis.com/google.iam.v1.logging.AuditData", policyDelta: { bindingDeltas: [{ action: "ADD", member, role }] } } };
    },
  };
}

function bucketOf(ev: TelemetryEvent): { bucket: string; key: string } {
  return {
    bucket: rs(ev.raw, "aws.cloudtrail.requestParameters.bucketName", "aws.cloudtrail.s3.bucket_name", "s3.bucket") ?? "data-bucket",
    key: rs(ev.raw, "aws.cloudtrail.requestParameters.key", "storage.object.name") ?? "object",
  };
}

// ── conversion ────────────────────────────────────────────────────────────────

function microTs(ts: string, ctx: NativeCtx, seed: string, fracDigits: number, addMs = 0): string {
  const d = new Date(Date.parse(ts) + addMs).toISOString(); // ...mmmZ (3 frac)
  const base = d.slice(0, 23); // includes .mmm
  const extra = String(ctx.int(seed, 0, 999999)).padStart(6, "0").slice(0, fracDigits - 3);
  return `${base}${extra}Z`;
}

function fromTelemetry(ev: TelemetryEvent, ctx: NativeCtx): NativeLog | null {
  const raw = ev.raw ?? {};
  // Native GCP event (none in the corpus today) — pass through its own fields.
  if (rv(raw, "gcp.audit.methodName", "protoPayload.methodName")) {
    // Not exercised by current data; fall through to cross-cloud path is not applicable.
  }
  // Cross-cloud: render an AWS CloudTrail event as its GCP equivalent, where one exists.
  const en = rs(raw, "aws.cloudtrail.eventName", "event.action") ?? ev.cloud?.api_call;
  if (!en) return null;
  const m = MAP[en];
  if (!m) return null; // no true GCP equivalent → decline (never fake)

  const proj = ctx.tenant.gcpProjectId;
  const shaped = m.shape(ev, proj);
  if (shaped.labels.project_id === "") shaped.labels.project_id = proj;

  const principal = ev.user?.email ?? ev.user_email ?? `${(rs(raw, "aws.cloudtrail.userIdentity.userName") ?? "svc")}@${proj}.iam.gserviceaccount.com`;
  const denied = !!rs(raw, "aws.cloudtrail.errorCode") && rs(raw, "aws.cloudtrail.errorCode") !== "";
  const ip = ev.src_ip ?? rs(raw, "aws.cloudtrail.sourceIPAddress", "source.ip");

  const authenticationInfo: Record<string, unknown> = { principalEmail: principal };
  if (principal.endsWith(".iam.gserviceaccount.com")) authenticationInfo.serviceAccountKeyName = `//iam.googleapis.com/projects/${proj}/serviceAccounts/${principal}/keys/${ctx.hex(entitySeed(ctx, "gcpkey", principal), 40)}`;

  const protoPayload: Record<string, unknown> = {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    authenticationInfo,
    authorizationInfo: [{ granted: !denied, permission: m.permission, permissionType: m.dataAccess ? "DATA_READ" : "ADMIN_WRITE", resourceAttributes: {} }],
    methodName: m.methodName,
    requestMetadata: {
      callerIp: ip ?? "private",
      callerSuppliedUserAgent: rs(raw, "aws.cloudtrail.userAgent") ?? "google-cloud-sdk gcloud/501.0.0,gzip(gfe)",
      requestAttributes: { time: microTs(ev.ts, ctx, ev.id + ":rt", 6), auth: {} },
      destinationAttributes: {},
    },
    resourceName: shaped.resourceName,
    serviceName: m.serviceName,
    status: denied ? { code: 7, message: `Permission '${m.permission}' denied on resource (or it may not exist).` } : {},
  };
  if (shaped.request) protoPayload.request = shaped.request;
  if (shaped.serviceData) protoPayload.serviceData = shaped.serviceData;

  const logName = `projects/${proj}/logs/cloudaudit.googleapis.com%2F${m.dataAccess ? "data_access" : "activity"}`;
  const record: Record<string, unknown> = {
    insertId: ctx.hex(ev.id + ":insert", 12),
    logName,
    protoPayload,
    receiveTimestamp: microTs(ev.ts, ctx, ev.id + ":recv", 9, 500),
    resource: { type: m.resourceType, labels: shaped.labels },
    severity: denied ? "ERROR" : m.dataAccess ? "INFO" : "NOTICE",
    timestamp: microTs(ev.ts, ctx, ev.id + ":ts", 6),
  };

  return { sourceId: "gcp_audit", kind: "AuditLog", format: "json", record, timeMs: Date.parse(ev.ts) };
}

// ── use cases ─────────────────────────────────────────────────────────────────

const useCases: UseCase[] = [
  {
    id: "gcp_audit.setiam_privileged",
    title: "IAM policy grants Owner / Editor",
    sourceId: "gcp_audit", severity: "critical", mitre: ["T1098"],
    description: "SetIamPolicy whose policyDelta ADDs a member to roles/owner or roles/editor — privilege escalation / persistence; read serviceData.policyDelta.bindingDeltas (the actual grant), not the full policy.",
    logic: "SPL: methodName=SetIamPolicy AND protoPayload.serviceData.policyDelta.bindingDeltas{}.role IN (roles/owner,roles/editor)",
    match: { all: [{ field: "protoPayload.methodName", op: "eq", value: "SetIamPolicy" }, { any: [
      { field: "protoPayload.serviceData.policyDelta.bindingDeltas[].role", op: "in", value: ["roles/owner", "roles/editor"] },
    ] }] },
    falsePositives: ["Org admin legitimately granting a role via an approved access request (check the member and ticket)."],
  },
  {
    id: "gcp_audit.service_account_key_created",
    title: "Service-account key created",
    sourceId: "gcp_audit", severity: "high", mitre: ["T1098.001"],
    description: "CreateServiceAccountKey mints a long-lived SA key — a classic persistence foothold that outlives short-lived credentials; such keys should be rare and short-lived.",
    logic: "SPL: methodName=\"*CreateServiceAccountKey\"",
    match: { field: "protoPayload.methodName", op: "icontains", value: "CreateServiceAccountKey" },
    falsePositives: ["A controlled provisioning flow that must mint an SA key (prefer workload identity; verify the owner)."],
  },
  {
    id: "gcp_audit.impersonation",
    title: "Service-account impersonation (GenerateAccessToken)",
    sourceId: "gcp_audit", severity: "high", mitre: ["T1134.001"],
    description: "GenerateAccessToken on iamcredentials.googleapis.com — one identity minting short-lived credentials for another SA; the delegation chain / caller is the real actor behind later actions.",
    logic: "SPL: serviceName=iamcredentials.googleapis.com methodName=GenerateAccessToken",
    match: { all: [{ field: "protoPayload.serviceName", op: "eq", value: "iamcredentials.googleapis.com" }, { field: "protoPayload.methodName", op: "eq", value: "GenerateAccessToken" }] },
    falsePositives: ["Legitimate CI/CD impersonating a deploy SA (expected; baseline the caller/target pair)."],
  },
  {
    id: "gcp_audit.gcs_object_read",
    title: "Cloud Storage object read (data access)",
    sourceId: "gcp_audit", severity: "medium", mitre: ["T1530"],
    description: "storage.objects.get in the Data Access log — a read of object data. Data Access logging is off by default, so its presence plus a sensitive bucket / external caller is the exfil signal.",
    logic: "SPL: methodName=storage.objects.get",
    match: { field: "protoPayload.methodName", op: "eq", value: "storage.objects.get" },
    falsePositives: ["Applications that legitimately read objects (scope by principal, bucket and caller IP)."],
  },
  {
    id: "gcp_audit.gpu_compute_insert",
    title: "GPU compute instance created (crypto-mining)",
    sourceId: "gcp_audit", severity: "high", mitre: ["T1578.002", "T1496"],
    description: "compute.instances.insert requesting a GPU/accelerator machine type (a2-highgpu / a3 / g2) — the compute footprint of crypto-mining on compromised GCP credentials.",
    logic: "SPL: methodName=\"*compute.instances.insert\" request.machineType=\"*a2-highgpu*\"|\"*a3-*\"|\"*g2-*\"",
    match: { all: [{ field: "protoPayload.methodName", op: "icontains", value: "compute.instances.insert" }, { field: "protoPayload.request.machineType", op: "regex", value: "(a2-highgpu|a2-ultragpu|a3-|g2-)" }] },
    falsePositives: ["Legitimate ML/HPC workloads using GPU machine types (verify the owning project/team)."],
  },
  {
    id: "gcp_audit.permission_denied",
    title: "Permission denied (recon hitting a wall)",
    sourceId: "gcp_audit", severity: "low", mitre: ["T1087"],
    description: "status.code = 7 (PERMISSION_DENIED) — a principal attempting an action it is not authorised for; a burst of these from one principal is reconnaissance / privilege probing.",
    logic: "SPL: protoPayload.status.code=7",
    match: { field: "protoPayload.status.code", op: "eq", value: 7 },
    falsePositives: ["Benign misconfiguration where an app lacks a permission it expects (fix the binding)."],
  },
  {
    id: "gcp_audit.sa_key_auth",
    title: "Call authenticated by a service-account key",
    sourceId: "gcp_audit", severity: "medium", mitre: ["T1552.004"],
    description: "A request carrying authenticationInfo.serviceAccountKeyName — a stolen SA key leaves this on every call it makes, a strong IOC to pivot on across the audit trail.",
    logic: "SPL: protoPayload.authenticationInfo.serviceAccountKeyName=*",
    match: { field: "protoPayload.authenticationInfo.serviceAccountKeyName", op: "exists" },
    falsePositives: ["Workloads that still authenticate with SA keys instead of workload identity (migrate them)."],
  },
];

export const source: NativeSource = { schema, fromTelemetry, useCases };
