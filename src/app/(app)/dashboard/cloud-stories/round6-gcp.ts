/**
 * Cloud round, Google Cloud (round6.ts): six families, each with a single-player variant and a Team Training
 * variant that share no people, addresses, buckets, service accounts or plot.
 *
 *  1. cloud-gcp-setiampolicy-owner  an outside account becomes project Owner through SetIamPolicy
 *       - solo  cloud-gcp-owner-to-outside-account  an SRE's Okta session from a hosting address adds a personal
 *               mailbox as Owner; that account then lists the project and mints a service-account key.
 *       - team  cloud-gcp-ci-key-grants-owner       a leaked CI service-account key, used from outside, grants Owner
 *               to a service account of another organization's project, which then reads secrets and storage.
 *  2. cloud-gcp-bucket-public  a bucket opened to everyone, where reads of public objects leave no audit entry
 *       - solo  cloud-gcp-backup-bucket-opened      public access prevention turned off and allUsers added on the
 *               database export bucket, then removed again forty minutes later.
 *       - team  cloud-gcp-dataops-key-opens-bucket  a data pipeline key from outside lists buckets and gives
 *               allAuthenticatedUsers read on the weekly customer backups.
 *  3. cloud-gcp-actas-deploy  privilege escalation through a service the caller deploys as a stronger identity
 *       - solo  cloud-gcp-run-deploy-as-admin       an engineer's session deploys a Cloud Run service that runs as
 *               the deployment admin account; that account is then used from outside.
 *       - team  cloud-gcp-function-as-data-admin    a deploy key deploys a Cloud Function as the warehouse admin
 *               account, which reads a secret and customer tables, then the function is deleted.
 *  4. cloud-gcp-startup-script  code put on a VM through its metadata
 *       - solo  cloud-gcp-startup-script-batch-vm   a startup script added to a batch VM and the VM reset: the
 *               script runner fetches a binary and installs a service.
 *       - team  cloud-gcp-project-ssh-key           a project-wide SSH key added with a stolen key, then SSH
 *               sessions on two VMs and an archive copied out.
 *  5. cloud-gcp-bigquery-export  warehouse data leaving the company's projects
 *       - solo  cloud-gcp-bigquery-extract-outside  a product manager's session queries customer tables and runs
 *               extract jobs into a bucket of no company project.
 *       - team  cloud-gcp-dataset-shared-outside    a dataset shared with a personal mailbox, which then queries it
 *               from outside, and the share removed again.
 *  6. cloud-gcp-logging-tamper  the audit stream to the SOC narrowed or cut
 *       - solo  cloud-gcp-log-exclusion-secrets     an exclusion and a sink filter drop Secret Manager reads, then a
 *               key is minted (Admin Activity entries cannot be excluded).
 *       - team  cloud-gcp-siem-sink-deleted         the SIEM export sink deleted, the stream goes silent, and what
 *               happened in the gap is read back from Cloud Logging.
 *
 * Effects only. Native shape: the Cloud Logging LogEntry with a google.cloud.audit.AuditLog protoPayload (card
 * docs/log-schemas/cloud-gcp-audit.md), authored through the gcp.audit.* inputs the gcp_audit module reads.
 * Data Access entries (data_access log) only where Google writes them: BigQuery always, Cloud Storage and Secret
 * Manager when enabled, never for objects readable by allUsers / allAuthenticatedUsers.
 */
import type { Severity, TelemetryEvent } from "@/lib/sim/types";
import type { AiStoryDef } from "../ai-stories/wave2";
import { csNetwork, csProcess, csFile } from "@/lib/sim/emitters/crowdstrike";
import { oktaSignIn } from "@/lib/sim/emitters/okta";
import { makeSha256 } from "@/lib/sim/iocs";
import { benign, sentinel, ticket, withIncident } from "../ai-stories/wave4-shared";

const CO = "rocketstack";
const PROJ = "rocketstack-platform-prod";
const OFFICE = "198.51.100.220";
const CI_EGRESS = "192.0.2.139";       // the CI runners' NAT address (benign rows only)
const at = (base: string) => { const b = Date.parse(base); return (min: number) => new Date(b + min * 60_000).toISOString(); };
const gcloud = (cmd: string, inv: string, os = "LINUX") =>
  `google-cloud-sdk gcloud/501.0.0 command/gcloud.${cmd} invocation-id/${inv} environment/None environment-version/None client-os/${os} interactive/True from-script/False python/3.12.4,gzip(gfe)`;
const UA_TF = "Terraform/1.9.8 (+https://www.terraform.io) Terraform-Plugin-SDK/2.33.0 terraform-provider-google/6.10.0,gzip(gfe)";
const UA_BQ = "google-cloud-bigquery/3.26.0 gl-python/3.12.4 grpc/1.66.2 gax/2.21.0 gapic/3.26.0,gzip(gfe)";
const UA_PY = "google-api-python-client/2.149.0 (gzip),gzip(gfe)";
const UA_CHROME = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36,gzip(gfe)";
const sa = (name: string) => `${name}@${PROJ}.iam.gserviceaccount.com`;

/** One Cloud Audit Logs entry, authored through the inputs the gcp_audit module renders. */
function g(o: {
  id: string; ts: string; principal: string; ip: string; service: string; method: string; resource: string; resourceType?: string;
  permission: string; log?: "activity" | "data_access"; granted?: boolean; ua: string; items?: number; keyName?: string;
  person?: boolean; extra?: Record<string, string | number>; severity: Severity; mitre?: string; tactic?: string; description: string;
  /** A SIEM rule on the audit stream fires on this entry (the row the SOC is paged on). */
  detect?: boolean;
}): TelemetryEvent {
  return {
    id: o.id, ts: o.ts, source: "cloud_gcp", vendor: "GCP Cloud Audit Logs", event_type: "cloud_api_call", severity: o.severity,
    ...(o.person !== false && !o.principal.endsWith(".gserviceaccount.com") ? { user_email: o.principal } : {}),
    src_ip: o.ip, ...(o.mitre ? { mitre_technique: o.mitre } : {}), ...(o.tactic ? { mitre_tactic: o.tactic } : {}),
    ...(o.detect ? { is_detection: true } : {}),
    description: o.description,
    raw: {
      "gcp.audit.type": "type.googleapis.com/google.cloud.audit.AuditLog",
      "gcp.audit.log_name": `projects/${PROJ}/logs/cloudaudit.googleapis.com%2F${o.log ?? "activity"}`,
      "gcp.audit.service_name": o.service,
      "gcp.audit.method_name": o.method,
      "gcp.audit.resource_name": o.resource,
      ...(o.resourceType ? { "gcp.audit.resource_type": o.resourceType } : {}),
      "gcp.audit.authentication_info.principal_email": o.principal,
      ...(o.keyName ? { "gcp.audit.authentication_info.service_account_key_name": o.keyName } : {}),
      "gcp.audit.request_metadata.caller_ip": o.ip,
      "gcp.audit.request_metadata.caller_supplied_user_agent": o.ua,
      "gcp.audit.authorization_info.permission": o.permission,
      "gcp.audit.authorization_info.granted": o.granted === false ? "false" : "true",
      ...(o.items !== undefined ? { "gcp.audit.num_response_items": String(o.items) } : {}),
      "gcp.project.id": PROJ,
      ...(o.extra ?? {}),
    },
  };
}
/** The binding change a SetIamPolicy carries (serviceData.policyDelta in the native entry). */
const delta = (action: "ADD" | "REMOVE", role: string, member: string) => ({
  "gcp.audit.service_data.policy_delta.binding_deltas[0].action": action,
  "gcp.audit.service_data.policy_delta.binding_deltas[0].role": role,
  "gcp.audit.service_data.policy_delta.binding_deltas[0].member": member,
});
const keyOf = (account: string, hex: string) => `//iam.googleapis.com/projects/${PROJ}/serviceAccounts/${account}/keys/${hex}`;
const newKey = (account: string, hex: string) => ({
  "gcp.audit.request.private_key_type": "TYPE_GOOGLE_CREDENTIALS_FILE",
  "gcp.audit.response.name": `projects/${PROJ}/serviceAccounts/${account}/keys/${hex}`,
  "gcp.audit.response.key_type": "USER_MANAGED",
  "gcp.audit.response.key_algorithm": "KEY_ALG_RSA_2048",
});

// ══════════════════════════════════════════════════════════════════════════════
// 1. cloud-gcp-setiampolicy-owner
// ══════════════════════════════════════════════════════════════════════════════
function ownerToOutsideAccount(): TelemetryEvent[] {
  const T = at("2026-11-10T19:00:00Z");
  const sre = "n.shapiro@rocketstack.io", atk = "192.0.2.120", outIp = "192.0.2.121";
  const outside = "backup.ops.7731@gmail.example";
  const proj = `projects/${PROJ}`;
  const keyHex = "5e0d81c3a9f24b6e8d17c42fa0b39e1d6c85f702";
  return withIncident([
    benign(g({ id: "g6o01", ts: T(-540), principal: sre, ip: OFFICE, service: "cloudresourcemanager.googleapis.com", method: "SetIamPolicy", resource: proj, resourceType: "project",
      permission: "resourcemanager.projects.setIamPolicy", ua: gcloud("projects.add-iam-policy-binding", "3f1c0a92"), severity: "medium", extra: delta("ADD", "roles/editor", "group:sre-oncall@rocketstack.io"),
      description: `SetIamPolicy on the production project by ${sre} from the office: roles/editor added for the group sre-oncall@rocketstack.io.` }),
      "The on-call group's planned editor grant (change CHG0072140): a company group, from the office, during working hours, and no outside account involved."),
    oktaSignIn({ companyId: CO, id: "g6o02", ts: T(0), user: sre, srcIp: atk, mfaUsed: true, factor: "OKTA_VERIFY_PUSH", asn: 9009, asOrg: "M247 Europe SRL", os: "Linux", browser: "CHROME",
      severity: "medium", mitre: "T1078.004", tactic: "Initial Access", description: `Okta sign-in for ${sre} from ${atk} (AS9009, a hosting provider) with an Okta Verify push approved at 21:00 local time.` }),
    g({ id: "g6o03", ts: T(4), principal: sre, ip: atk, service: "cloudresourcemanager.googleapis.com", method: "GetIamPolicy", resource: proj, resourceType: "project", log: "data_access",
      permission: "resourcemanager.projects.getIamPolicy", ua: gcloud("projects.get-iam-policy", "a81d22e4"), severity: "low", mitre: "T1069", tactic: "Discovery",
      description: `GetIamPolicy on the production project by ${sre} from ${atk}.` }),
    g({ id: "g6o04", detect: true, ts: T(6), principal: sre, ip: atk, service: "cloudresourcemanager.googleapis.com", method: "SetIamPolicy", resource: proj, resourceType: "project",
      permission: "resourcemanager.projects.setIamPolicy", ua: gcloud("projects.add-iam-policy-binding", "c07e9b13"), severity: "critical", mitre: "T1098.003", tactic: "Persistence",
      extra: delta("ADD", "roles/owner", `user:${outside}`),
      description: `SetIamPolicy on the production project by ${sre} from ${atk}: roles/owner added for user:${outside}, a personal mailbox outside the company.` }),
    g({ id: "g6o05", ts: T(19), principal: outside, ip: outIp, service: "compute.googleapis.com", method: "v1.compute.instances.aggregatedList", resource: proj, resourceType: "gce_instance", log: "data_access",
      permission: "compute.instances.list", ua: UA_CHROME, items: 23, severity: "medium", mitre: "T1580", tactic: "Discovery",
      description: `${outside} listed every Compute Engine instance in the project from ${outIp}, in the Cloud Console: 23 instances.` }),
    g({ id: "g6o06", ts: T(21), principal: outside, ip: outIp, service: "storage.googleapis.com", method: "storage.buckets.list", resource: proj, resourceType: "project", log: "data_access",
      permission: "storage.buckets.list", ua: UA_CHROME, items: 17, severity: "medium", mitre: "T1619", tactic: "Discovery",
      description: `${outside} listed the project's Cloud Storage buckets from ${outIp}: 17 buckets.` }),
    g({ id: "g6o07", ts: T(24), principal: outside, ip: outIp, service: "iam.googleapis.com", method: "google.iam.admin.v1.ListServiceAccounts", resource: proj, resourceType: "project", log: "data_access",
      permission: "iam.serviceAccounts.list", ua: UA_CHROME, items: 14, severity: "medium", mitre: "T1087.004", tactic: "Discovery",
      description: `${outside} listed the project's service accounts from ${outIp}: 14 accounts.` }),
    g({ id: "g6o08", ts: T(27), principal: outside, ip: outIp, service: "iam.googleapis.com", method: "google.iam.admin.v1.CreateServiceAccountKey", resource: `projects/-/serviceAccounts/${sa("svc-deploy")}`, resourceType: "service_account",
      permission: "iam.serviceAccountKeys.create", ua: UA_CHROME, severity: "high", mitre: "T1098.001", tactic: "Persistence", extra: newKey(sa("svc-deploy"), keyHex),
      description: `${outside} created a key for the service account svc-deploy from ${outIp}: a JSON key file that works without any sign-in.` }),
    g({ id: "g6o09", ts: T(33), principal: sa("svc-deploy"), ip: outIp, keyName: keyOf(sa("svc-deploy"), keyHex),
      service: "secretmanager.googleapis.com", method: "google.cloud.secretmanager.v1.SecretManagerService.ListSecrets", resource: proj, resourceType: "audited_resource", log: "data_access",
      permission: "secretmanager.secrets.list", ua: UA_PY, items: 31, severity: "high", mitre: "T1555.006", tactic: "Credential Access",
      description: `The new svc-deploy key, used from ${outIp}, listed the project's secrets: 31 entries.` }),
  ], "inc:g6:owner-outside");
}

function ciKeyGrantsOwner(): TelemetryEvent[] {
  const T = at("2026-11-11T02:10:00Z");
  const ci = sa("ci-pipeline"), ext = "sync-agent@ext-tools-4471.iam.gserviceaccount.com";
  const atk = "192.0.2.122", extIp = "192.0.2.123";
  const ciKey = keyOf(ci, "8a4f1c27e90b3d65f2a1c8e4b7d09f3a61e5c2d8");
  const proj = `projects/${PROJ}`;
  return withIncident([
    benign(g({ id: "g6c01", ts: T(-420), principal: ci, ip: CI_EGRESS, keyName: ciKey, service: "cloudresourcemanager.googleapis.com", method: "SetIamPolicy", resource: proj, resourceType: "project",
      permission: "resourcemanager.projects.setIamPolicy", ua: UA_TF, severity: "medium", extra: delta("ADD", "roles/run.invoker", `serviceAccount:${sa("api-gateway")}`),
      description: "SetIamPolicy on the production project by ci-pipeline from the CI runners' address through Terraform: roles/run.invoker added for the api-gateway service account." }),
      "The nightly Terraform apply: the CI account from its runners' NAT address, a narrow role for one of the project's own service accounts, matching the merged infrastructure change."),
    g({ id: "g6c02", ts: T(0), principal: ci, ip: atk, keyName: ciKey, service: "cloudresourcemanager.googleapis.com", method: "GetIamPolicy", resource: proj, resourceType: "project", log: "data_access",
      permission: "resourcemanager.projects.getIamPolicy", ua: UA_PY, severity: "medium", mitre: "T1078.004", tactic: "Initial Access",
      description: `GetIamPolicy on the production project by ci-pipeline, with its user-managed key, from ${atk}. The account has only ever been used from the CI runners.` }),
    g({ id: "g6c03", ts: T(1), principal: ci, ip: atk, keyName: ciKey, service: "iam.googleapis.com", method: "google.iam.admin.v1.ListServiceAccounts", resource: proj, resourceType: "project", log: "data_access",
      permission: "iam.serviceAccounts.list", ua: UA_PY, items: 14, severity: "low", mitre: "T1087.004", tactic: "Discovery",
      description: `ci-pipeline listed the project's service accounts from ${atk}.` }),
    g({ id: "g6c04", detect: true, ts: T(3), principal: ci, ip: atk, keyName: ciKey, service: "cloudresourcemanager.googleapis.com", method: "SetIamPolicy", resource: proj, resourceType: "project",
      permission: "resourcemanager.projects.setIamPolicy", ua: UA_PY, severity: "critical", mitre: "T1098.003", tactic: "Persistence", extra: delta("ADD", "roles/owner", `serviceAccount:${ext}`),
      description: `SetIamPolicy on the production project by ci-pipeline from ${atk}: roles/owner added for ${ext}, a service account of another organization's project.` }),
    g({ id: "g6c05", ts: T(11), principal: ext, ip: extIp, service: "secretmanager.googleapis.com", method: "google.cloud.secretmanager.v1.SecretManagerService.ListSecrets", resource: proj, resourceType: "audited_resource", log: "data_access",
      permission: "secretmanager.secrets.list", ua: UA_PY, items: 31, person: false, severity: "high", mitre: "T1555.006", tactic: "Credential Access",
      description: `${ext} listed the project's secrets from ${extIp}.` }),
    g({ id: "g6c06", ts: T(12), principal: ext, ip: extIp, service: "secretmanager.googleapis.com", method: "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion", resource: `${proj}/secrets/payments-db-password/versions/latest`, resourceType: "audited_resource", log: "data_access",
      permission: "secretmanager.versions.access", ua: UA_PY, person: false, severity: "high", mitre: "T1555.006", tactic: "Credential Access",
      description: `${ext} read the latest version of the secret payments-db-password from ${extIp}.` }),
    g({ id: "g6c07", ts: T(12.5), principal: ext, ip: extIp, service: "secretmanager.googleapis.com", method: "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion", resource: `${proj}/secrets/stripe-live-api-key/versions/latest`, resourceType: "audited_resource", log: "data_access",
      permission: "secretmanager.versions.access", ua: UA_PY, person: false, severity: "high", mitre: "T1555.006", tactic: "Credential Access",
      description: `${ext} read the latest version of the secret stripe-live-api-key from ${extIp}.` }),
    g({ id: "g6c08", ts: T(16), principal: ext, ip: extIp, service: "storage.googleapis.com", method: "storage.objects.list", resource: "projects/_/buckets/rs-invoices-archive", resourceType: "gcs_bucket", log: "data_access",
      permission: "storage.objects.list", ua: UA_PY, items: 4120, person: false, severity: "medium", mitre: "T1619", tactic: "Discovery",
      description: `${ext} listed the bucket rs-invoices-archive from ${extIp}: 4,120 objects.` }),
    g({ id: "g6c09", ts: T(18), principal: ext, ip: extIp, service: "storage.googleapis.com", method: "storage.objects.get", resource: "projects/_/buckets/rs-invoices-archive/objects/2026/10/invoices-2026-10.tar.gz", resourceType: "gcs_bucket", log: "data_access",
      permission: "storage.objects.get", ua: UA_PY, person: false, severity: "high", mitre: "T1530", tactic: "Collection",
      description: `${ext} read the object 2026/10/invoices-2026-10.tar.gz from rs-invoices-archive from ${extIp}.` }),
  ], "inc:g6:ci-owner");
}

// ══════════════════════════════════════════════════════════════════════════════
// 2. cloud-gcp-bucket-public
// ══════════════════════════════════════════════════════════════════════════════
function backupBucketOpened(): TelemetryEvent[] {
  const T = at("2026-11-12T20:30:00Z");
  const ops = "j.lee@rocketstack.io", atk = "192.0.2.124";
  const bucket = "projects/_/buckets/rs-db-exports";
  return withIncident([
    benign(g({ id: "g6b01", ts: T(-600), principal: "r.cohen@rocketstack.io", ip: OFFICE, service: "storage.googleapis.com", method: "storage.setIamPermissions", resource: "projects/_/buckets/rs-site-assets", resourceType: "gcs_bucket",
      permission: "storage.buckets.setIamPolicy", ua: gcloud("storage.buckets.add-iam-policy-binding", "6b2e0d71", "MACOSX"), severity: "medium", extra: delta("ADD", "roles/storage.objectViewer", "allUsers"),
      description: "storage.setIamPermissions on the bucket rs-site-assets by r.cohen from the office: roles/storage.objectViewer added for allUsers." }),
      "The public website assets bucket, opened to everyone by design (images and stylesheets the site serves), from the office under the web team's change."),
    oktaSignIn({ companyId: CO, id: "g6b02", ts: T(0), user: ops, srcIp: atk, mfaUsed: true, factor: "OKTA_VERIFY_PUSH", asn: 14061, asOrg: "DigitalOcean, LLC", os: "Windows", browser: "CHROME",
      severity: "medium", mitre: "T1078.004", tactic: "Initial Access", description: `Okta sign-in for ${ops} from ${atk} (AS14061, a hosting provider) with an Okta Verify push.` }),
    g({ id: "g6b03", ts: T(5), principal: ops, ip: atk, service: "storage.googleapis.com", method: "storage.objects.list", resource: bucket, resourceType: "gcs_bucket", log: "data_access",
      permission: "storage.objects.list", ua: UA_CHROME, items: 212, severity: "low", mitre: "T1619", tactic: "Discovery",
      description: `${ops} listed rs-db-exports (the database export bucket) from ${atk} in the Cloud Console: 212 objects.` }),
    g({ id: "g6b04", ts: T(8), principal: ops, ip: atk, service: "storage.googleapis.com", method: "storage.buckets.update", resource: bucket, resourceType: "gcs_bucket",
      permission: "storage.buckets.update", ua: UA_CHROME, severity: "high", mitre: "T1685.002", tactic: "Defense Impairment",
      extra: { "gcp.audit.request.iam_configuration.public_access_prevention": "inherited" },
      description: `${ops} changed rs-db-exports from ${atk}: public access prevention from enforced to inherited, which lets an allUsers grant take effect.` }),
    g({ id: "g6b05", ts: T(9), principal: ops, ip: atk, service: "storage.googleapis.com", method: "storage.setIamPermissions", resource: bucket, resourceType: "gcs_bucket",
      permission: "storage.buckets.setIamPolicy", ua: UA_CHROME, severity: "critical", mitre: "T1530", tactic: "Collection", extra: delta("ADD", "roles/storage.objectViewer", "allUsers"),
      description: `storage.setIamPermissions on rs-db-exports by ${ops} from ${atk}: roles/storage.objectViewer added for allUsers. Every object in the bucket is now readable by anyone with its name, and those reads leave no audit entry.` }),
    g({ id: "g6b06", ts: T(49), principal: ops, ip: atk, service: "storage.googleapis.com", method: "storage.setIamPermissions", resource: bucket, resourceType: "gcs_bucket",
      permission: "storage.buckets.setIamPolicy", ua: UA_CHROME, severity: "high", mitre: "T1070", tactic: "Stealth", extra: delta("REMOVE", "roles/storage.objectViewer", "allUsers"),
      description: `storage.setIamPermissions on rs-db-exports by ${ops} from ${atk}, forty minutes later: the allUsers binding removed again.` }),
    g({ id: "g6b07", ts: T(50), principal: ops, ip: atk, service: "storage.googleapis.com", method: "storage.buckets.update", resource: bucket, resourceType: "gcs_bucket",
      permission: "storage.buckets.update", ua: UA_CHROME, severity: "high", mitre: "T1070", tactic: "Stealth",
      extra: { "gcp.audit.request.iam_configuration.public_access_prevention": "enforced" },
      description: `${ops} set public access prevention on rs-db-exports back to enforced from ${atk}.` }),
    sentinel({ id: "g6b08", ts: T(58), srcIp: atk, entity: "rs-db-exports", severity: "high", eventType: "cloud_api_call", mitre: "T1530", tactic: "Collection",
      alertName: "GCS bucket opened to allUsers and closed within an hour",
      detail: "An allUsers or allAuthenticatedUsers binding was added to a bucket and removed again within 60 minutes by the same principal.",
      startTime: T(9), endTime: T(49),
      extendedProperties: { Bucket: "rs-db-exports", Principal: ops, "Caller IP": atk, "Open for (minutes)": 40, Objects: 212 },
      description: `SIEM analytic: rs-db-exports was readable by anyone for 40 minutes, opened and closed by ${ops} from ${atk}.` }),
  ], "inc:g6:bucket-open");
}

function dataopsKeyOpensBucket(): TelemetryEvent[] {
  const T = at("2026-11-13T03:40:00Z");
  const dataops = sa("svc-dataops"), atk = "192.0.2.125";
  const key = keyOf(dataops, "c3d09e71b2a46f58e1d7039c4b2a85f6e0d913b7");
  const bucket = "projects/_/buckets/rs-customer-backups-weekly";
  return withIncident([
    benign(g({ id: "g6d01", ts: T(-200), principal: dataops, ip: CI_EGRESS, keyName: key, service: "storage.googleapis.com", method: "storage.objects.create", resource: `${bucket}/objects/2026-11-12/customers.avro`, resourceType: "gcs_bucket", log: "data_access",
      permission: "storage.objects.create", ua: UA_PY, severity: "informational",
      description: "svc-dataops wrote 2026-11-12/customers.avro into rs-customer-backups-weekly from the CI runners' address." }),
      "The weekly backup job itself: the pipeline account writing its own export from the CI runners at its scheduled time."),
    g({ id: "g6d02", ts: T(0), principal: dataops, ip: atk, keyName: key, service: "storage.googleapis.com", method: "storage.buckets.list", resource: `projects/${PROJ}`, resourceType: "project", log: "data_access",
      permission: "storage.buckets.list", ua: UA_PY, items: 17, severity: "medium", mitre: "T1078.004", tactic: "Initial Access",
      description: `svc-dataops, with its user-managed key, listed the project's buckets from ${atk}. The account has only ever been used from the CI runners.` }),
    g({ id: "g6d03", ts: T(2), principal: dataops, ip: atk, keyName: key, service: "storage.googleapis.com", method: "storage.getIamPermissions", resource: bucket, resourceType: "gcs_bucket", log: "data_access",
      permission: "storage.buckets.getIamPolicy", ua: UA_PY, severity: "low", mitre: "T1069", tactic: "Discovery",
      description: `svc-dataops read the IAM policy of rs-customer-backups-weekly from ${atk}.` }),
    g({ id: "g6d04", detect: true, ts: T(3), principal: dataops, ip: atk, keyName: key, service: "storage.googleapis.com", method: "storage.setIamPermissions", resource: bucket, resourceType: "gcs_bucket",
      permission: "storage.buckets.setIamPolicy", ua: UA_PY, severity: "critical", mitre: "T1530", tactic: "Collection", extra: delta("ADD", "roles/storage.objectViewer", "allAuthenticatedUsers"),
      description: `storage.setIamPermissions on rs-customer-backups-weekly by svc-dataops from ${atk}: roles/storage.objectViewer added for allAuthenticatedUsers, meaning any Google account in the world.` }),
    g({ id: "g6d05", ts: T(4), principal: dataops, ip: atk, keyName: key, service: "storage.googleapis.com", method: "storage.objects.list", resource: bucket, resourceType: "gcs_bucket", log: "data_access",
      permission: "storage.objects.list", ua: UA_PY, items: 58, severity: "medium", mitre: "T1619", tactic: "Discovery",
      description: `svc-dataops listed rs-customer-backups-weekly from ${atk}: 58 weekly exports. The reads that follow through the public grant are not in the audit log.` }),
    g({ id: "g6d06", ts: T(71), principal: dataops, ip: atk, keyName: key, service: "storage.googleapis.com", method: "storage.setIamPermissions", resource: bucket, resourceType: "gcs_bucket",
      permission: "storage.buckets.setIamPolicy", ua: UA_PY, severity: "high", mitre: "T1070", tactic: "Stealth", extra: delta("REMOVE", "roles/storage.objectViewer", "allAuthenticatedUsers"),
      description: `svc-dataops removed the allAuthenticatedUsers binding from rs-customer-backups-weekly from ${atk}, 68 minutes after adding it.` }),
    g({ id: "g6d07", ts: T(73), principal: dataops, ip: atk, keyName: key, service: "iam.googleapis.com", method: "google.iam.admin.v1.ListServiceAccountKeys", resource: `projects/-/serviceAccounts/${dataops}`, resourceType: "service_account", log: "data_access",
      permission: "iam.serviceAccountKeys.list", ua: UA_PY, items: 2, severity: "medium", mitre: "T1087.004", tactic: "Discovery",
      description: `svc-dataops listed its own keys from ${atk}: two user-managed keys.` }),
  ], "inc:g6:dataops-bucket");
}

// ══════════════════════════════════════════════════════════════════════════════
// 3. cloud-gcp-actas-deploy
// ══════════════════════════════════════════════════════════════════════════════
function runDeployAsAdmin(): TelemetryEvent[] {
  const T = at("2026-11-14T16:20:00Z");
  const eng = "s.amir@rocketstack.io", atk = "192.0.2.126", useIp = "192.0.2.127";
  const admin = sa("deploy-admin"), app = sa("run-app");
  const svc = `projects/${PROJ}/locations/europe-west1/services`;
  const keyHex = "91b7c3e0d24f65a8c1e9073b5d2f8a46e0c17d93";
  return withIncident([
    benign(g({ id: "g6r01", ts: T(-300), principal: sa("ci-pipeline"), ip: CI_EGRESS, service: "run.googleapis.com", method: "google.cloud.run.v2.Services.UpdateService", resource: `${svc}/checkout-api`, resourceType: "audited_resource",
      permission: "run.services.update", ua: gcloud("run.deploy", "1d7e4a08"), severity: "low", extra: { "gcp.audit.request.service.template.service_account": app },
      description: "ci-pipeline deployed a new revision of the Cloud Run service checkout-api from the CI runners, running as run-app." }),
      "An ordinary release: the CI account deploys checkout-api as its usual low-privilege runtime account, run-app."),
    oktaSignIn({ companyId: CO, id: "g6r02", ts: T(0), user: eng, srcIp: atk, mfaUsed: true, factor: "OKTA_VERIFY_PUSH", asn: 16276, asOrg: "OVH SAS", os: "Linux", browser: "CHROME",
      severity: "medium", mitre: "T1078.004", tactic: "Initial Access", description: `Okta sign-in for ${eng} from ${atk} (AS16276, a hosting provider) with an Okta Verify push.` }),
    g({ id: "g6r03", ts: T(6), principal: eng, ip: atk, service: "iam.googleapis.com", method: "google.iam.admin.v1.ListServiceAccounts", resource: `projects/${PROJ}`, resourceType: "project", log: "data_access",
      permission: "iam.serviceAccounts.list", ua: gcloud("iam.service-accounts.list", "7c2b9f40"), items: 14, severity: "low", mitre: "T1087.004", tactic: "Discovery",
      description: `${eng} listed the project's service accounts from ${atk}.` }),
    g({ id: "g6r04", ts: T(9), principal: eng, ip: atk, service: "run.googleapis.com", method: "google.cloud.run.v2.Services.CreateService", resource: `${svc}/metrics-sidecar`, resourceType: "audited_resource",
      permission: "run.services.create", ua: gcloud("run.deploy", "e4f19a27"), severity: "high", mitre: "T1548.005", tactic: "Privilege Escalation",
      extra: { "gcp.audit.request.service.template.service_account": admin, "gcp.audit.request.service.template.containers[0].image": "europe-docker.pkg.dev/ops-mirror-2291/pub/metrics-sidecar:1.4" },
      description: `${eng} created the Cloud Run service metrics-sidecar from ${atk}, running as deploy-admin (a service account with project-wide admin roles) and pulling its image from a registry outside the company's projects. Deploying as that account requires iam.serviceAccounts.actAs on it.` }),
    g({ id: "g6r05", ts: T(9.5), principal: eng, ip: atk, service: "run.googleapis.com", method: "google.cloud.run.v1.Services.SetIamPolicy", resource: `${svc}/metrics-sidecar`, resourceType: "audited_resource",
      permission: "run.services.setIamPolicy", ua: gcloud("run.services.add-iam-policy-binding", "0b8e6d55"), severity: "high", mitre: "T1098.003", tactic: "Persistence", extra: delta("ADD", "roles/run.invoker", "allUsers"),
      description: `${eng} made metrics-sidecar callable by anyone (roles/run.invoker for allUsers) from ${atk}.` }),
    g({ id: "g6r06", detect: true, ts: T(17), principal: admin, ip: useIp, service: "iam.googleapis.com", method: "google.iam.admin.v1.CreateServiceAccountKey", resource: `projects/-/serviceAccounts/${admin}`, resourceType: "service_account",
      permission: "iam.serviceAccountKeys.create", ua: UA_PY, severity: "critical", mitre: "T1098.001", tactic: "Persistence", extra: newKey(admin, keyHex),
      description: `deploy-admin created a key for itself, called from ${useIp}: the account's access token left the Cloud Run service and is being used from outside.` }),
    g({ id: "g6r07", ts: T(22), principal: admin, ip: useIp, keyName: keyOf(admin, keyHex), service: "cloudresourcemanager.googleapis.com", method: "SetIamPolicy", resource: `projects/${PROJ}`, resourceType: "project",
      permission: "resourcemanager.projects.setIamPolicy", ua: UA_PY, severity: "critical", mitre: "T1098.003", tactic: "Persistence", extra: delta("ADD", "roles/iam.serviceAccountTokenCreator", `user:${eng}`),
      description: `deploy-admin, with its new key from ${useIp}, gave ${eng} roles/iam.serviceAccountTokenCreator on the whole project.` }),
    g({ id: "g6r08", ts: T(25), principal: admin, ip: useIp, keyName: keyOf(admin, keyHex), service: "storage.googleapis.com", method: "storage.objects.get", resource: "projects/_/buckets/rs-tf-state/objects/prod/default.tfstate", resourceType: "gcs_bucket", log: "data_access",
      permission: "storage.objects.get", ua: UA_PY, severity: "high", mitre: "T1552.001", tactic: "Credential Access",
      description: `deploy-admin read prod/default.tfstate from the Terraform state bucket from ${useIp}. State files hold resource secrets in clear text.` }),
  ], "inc:g6:run-actas");
}

function functionAsDataAdmin(): TelemetryEvent[] {
  const T = at("2026-11-15T01:05:00Z");
  const builder = sa("svc-release"), data = sa("bq-data-admin"), atk = "192.0.2.128", fnEgress = "192.0.2.129";
  const builderKey = keyOf(builder, "2f6a0c91e8b47d35a1c09e6f4b28d7c3e5a10f84");
  const fn = `projects/${PROJ}/locations/europe-west3/functions/report-cache-warmer`;
  return withIncident([
    benign(g({ id: "g6f01", ts: T(-600), principal: builder, ip: CI_EGRESS, keyName: builderKey, service: "cloudfunctions.googleapis.com", method: "google.cloud.functions.v2.FunctionService.UpdateFunction",
      resource: `projects/${PROJ}/locations/europe-west3/functions/invoice-pdf-render`, resourceType: "audited_resource", permission: "cloudfunctions.functions.update", ua: UA_TF, severity: "low",
      extra: { "gcp.audit.request.function.service_config.service_account_email": sa("fn-render") },
      description: "svc-release updated the Cloud Function invoice-pdf-render from the CI runners through Terraform, running as fn-render." }),
      "The routine function release: the release account from the CI runners, its function running as its own narrow account."),
    g({ id: "g6f02", ts: T(0), principal: builder, ip: atk, keyName: builderKey, service: "iam.googleapis.com", method: "google.iam.admin.v1.ListServiceAccounts", resource: `projects/${PROJ}`, resourceType: "project", log: "data_access",
      permission: "iam.serviceAccounts.list", ua: UA_PY, items: 14, severity: "medium", mitre: "T1078.004", tactic: "Initial Access",
      description: `svc-release, with its user-managed key, listed the project's service accounts from ${atk}. The key has only ever been used from the CI runners.` }),
    g({ id: "g6f03", detect: true, ts: T(2), principal: builder, ip: atk, keyName: builderKey, service: "cloudfunctions.googleapis.com", method: "google.cloud.functions.v2.FunctionService.CreateFunction", resource: fn, resourceType: "audited_resource",
      permission: "cloudfunctions.functions.create", ua: UA_PY, severity: "high", mitre: "T1548.005", tactic: "Privilege Escalation",
      extra: { "gcp.audit.request.function.service_config.service_account_email": data, "gcp.audit.request.function.build_config.runtime": "python312" },
      description: `svc-release created the Cloud Function report-cache-warmer from ${atk}, running as bq-data-admin, the warehouse administrator account. svc-release holds iam.serviceAccounts.actAs on it for the release pipeline.` }),
    g({ id: "g6f04", ts: T(9), principal: data, ip: fnEgress, service: "secretmanager.googleapis.com", method: "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion", resource: `projects/${PROJ}/secrets/warehouse-export-hmac/versions/latest`, resourceType: "audited_resource", log: "data_access",
      permission: "secretmanager.versions.access", ua: UA_PY, person: false, severity: "high", mitre: "T1555.006", tactic: "Credential Access",
      description: `bq-data-admin read the secret warehouse-export-hmac, called from ${fnEgress}. The function was created seven minutes earlier.` }),
    g({ id: "g6f05", ts: T(10), principal: data, ip: fnEgress, service: "bigquery.googleapis.com", method: "google.cloud.bigquery.v2.JobService.InsertJob", resource: `projects/${PROJ}/jobs/job_rcw_7c41e2`, resourceType: "audited_resource", log: "data_access",
      permission: "bigquery.jobs.create", ua: UA_BQ, person: false, severity: "high", mitre: "T1213", tactic: "Collection",
      extra: { "gcp.audit.metadata.job_insertion.job.job_stats.query_stats.total_processed_bytes": 18_204_441_088 },
      description: `bq-data-admin ran a query job that read about 18 GB of the customers dataset, called from ${fnEgress}.` }),
    g({ id: "g6f06", ts: T(11), principal: data, ip: fnEgress, service: "bigquery.googleapis.com", method: "google.cloud.bigquery.v2.TableDataService.List", resource: `projects/${PROJ}/datasets/customers/tables/accounts_pii`, resourceType: "audited_resource", log: "data_access",
      permission: "bigquery.tables.getData", ua: UA_BQ, person: false, severity: "high", mitre: "T1213", tactic: "Collection",
      description: `bq-data-admin read rows of customers.accounts_pii directly through tabledata.list, called from ${fnEgress}.` }),
    g({ id: "g6f07", ts: T(19), principal: builder, ip: atk, keyName: builderKey, service: "cloudfunctions.googleapis.com", method: "google.cloud.functions.v2.FunctionService.DeleteFunction", resource: fn, resourceType: "audited_resource",
      permission: "cloudfunctions.functions.delete", ua: UA_PY, severity: "high", mitre: "T1070", tactic: "Stealth",
      description: `svc-release deleted report-cache-warmer from ${atk}, seventeen minutes after creating it.` }),
  ], "inc:g6:fn-actas");
}

// ══════════════════════════════════════════════════════════════════════════════
// 4. cloud-gcp-startup-script
// ══════════════════════════════════════════════════════════════════════════════
function startupScriptBatchVm(): TelemetryEvent[] {
  const T = at("2026-11-16T22:10:00Z");
  const ops = "m.ben-david@rocketstack.io", atk = "192.0.2.130", c2 = "192.0.2.131";
  const vm = { host: "gce-batch-04", ip: "10.132.0.14" };
  const inst = `projects/${PROJ}/zones/europe-west1-b/instances/gce-batch-04`;
  const runner = "/usr/bin/google_metadata_script_runner";
  const bin = "/var/tmp/.kworkerd";
  const binSha = makeSha256("g6:startup:kworkerd");
  const vmProc = (o: Omit<Parameters<typeof csProcess>[0], "companyId" | "host" | "srcIp" | "user">) => csProcess({ companyId: CO, host: vm.host, srcIp: vm.ip, user: null, runAsUser: "root", ...o });
  return withIncident([
    benign(g({ id: "g6s01", ts: T(-900), principal: sa("ci-pipeline"), ip: CI_EGRESS, service: "compute.googleapis.com", method: "v1.compute.instances.setMetadata", resource: `projects/${PROJ}/zones/europe-west1-b/instances/gce-report-02`, resourceType: "gce_instance",
      permission: "compute.instances.setMetadata", ua: UA_TF, severity: "medium", extra: { "gcp.audit.request.metadata.items[0].key": "startup-script" },
      description: "ci-pipeline set the startup-script metadata key on gce-report-02 from the CI runners through Terraform (the monitoring agent install)." }),
      "The planned monitoring-agent rollout: Terraform from the CI runners writes the startup script the infrastructure repository holds, on a reporting VM."),
    oktaSignIn({ companyId: CO, id: "g6s02", ts: T(0), user: ops, srcIp: atk, mfaUsed: true, factor: "OKTA_VERIFY_PUSH", asn: 51167, asOrg: "Contabo GmbH", os: "Linux", browser: "FIREFOX",
      severity: "medium", mitre: "T1078.004", tactic: "Initial Access", description: `Okta sign-in for ${ops} from ${atk} (AS51167, a hosting provider) with an Okta Verify push.` }),
    g({ id: "g6s03", detect: true, ts: T(5), principal: ops, ip: atk, service: "compute.googleapis.com", method: "v1.compute.instances.setMetadata", resource: inst, resourceType: "gce_instance",
      permission: "compute.instances.setMetadata", ua: gcloud("compute.instances.add-metadata", "5a90d3c6"), severity: "high", mitre: "T1651", tactic: "Execution",
      extra: { "gcp.audit.request.metadata.items[0].key": "startup-script" },
      description: `${ops} added a startup-script metadata key to the VM gce-batch-04 from ${atk}. No change in the infrastructure repository writes it.` }),
    g({ id: "g6s04", ts: T(6), principal: ops, ip: atk, service: "compute.googleapis.com", method: "v1.compute.instances.reset", resource: inst, resourceType: "gce_instance",
      permission: "compute.instances.reset", ua: gcloud("compute.instances.reset", "f27c1e84"), severity: "high", mitre: "T1651", tactic: "Execution",
      description: `${ops} reset gce-batch-04 from ${atk}, one minute later: the VM reboots and runs its startup script.` }),
    vmProc({ id: "g6s05", ts: T(8), pid: 1188, processName: "google_metadata_script_runner", processPath: runner, parentName: "systemd", parentPid: 1,
      cmdline: `${runner} startup`, signed: true, severity: "medium", mitre: "T1651", tactic: "Execution",
      description: "The guest agent's script runner ran the instance's startup script on gce-batch-04 as root." }),
    vmProc({ id: "g6s06", ts: T(8.2), pid: 1204, processName: "curl", processPath: "/usr/bin/curl", parentName: "google_metadata_script_runner", parentPid: 1188,
      cmdline: `curl -fsSL -o ${bin} https://pkg-mirror.telemetry-cdn.example/agent/linux-amd64`, signed: true, severity: "high", mitre: "T1105", tactic: "Command and Control",
      description: "The startup script ran curl as root to download a binary into /var/tmp/.kworkerd from pkg-mirror.telemetry-cdn.example." }),
    csNetwork({ companyId: CO, id: "g6s06b", ts: T(8.3), host: vm.host, srcIp: vm.ip, user: null, remoteIp: "192.0.2.247", remotePort: 443, application: "tls", domain: "pkg-mirror.telemetry-cdn.example",
      processName: "curl", processPath: "/usr/bin/curl", pid: 1204, parentName: "google_metadata_script_runner", parentPid: 1188, bytesOut: 1_204, bytesIn: 4_830_112,
      severity: "high", mitre: "T1105", tactic: "Command and Control", description: "curl on gce-batch-04 fetched about 4.8 MB from pkg-mirror.telemetry-cdn.example (192.0.2.247) over TLS." }),
    csFile({ companyId: CO, id: "g6s07", ts: T(8.4), host: vm.host, srcIp: vm.ip, user: null, path: bin, sha256: binSha, size: 4_812_288, action: "file_create",
      actorProcess: "curl", actorPath: "/usr/bin/curl", actorPid: 1204, actorParentName: "google_metadata_script_runner", actorParentPid: 1188, runAsUser: "root",
      severity: "high", mitre: "T1105", tactic: "Command and Control", description: "curl wrote /var/tmp/.kworkerd (4.8 MB, an ELF binary named like a kernel thread) on gce-batch-04." }),
    csFile({ companyId: CO, id: "g6s08", ts: T(8.6), host: vm.host, srcIp: vm.ip, user: null, path: "/etc/systemd/system/kworkerd.service", sha256: makeSha256("g6:startup:unit"), size: 284, action: "file_create",
      actorProcess: "google_metadata_script_runner", actorPath: runner, actorPid: 1188, actorParentName: "systemd", actorParentPid: 1, runAsUser: "root",
      severity: "high", mitre: "T1543", tactic: "Persistence", description: "The startup script wrote a systemd unit, kworkerd.service, that starts /var/tmp/.kworkerd at boot." }),
    vmProc({ id: "g6s09", ts: T(9), pid: 1312, processName: ".kworkerd", processPath: bin, parentName: "systemd", parentPid: 1,
      cmdline: bin, sha256: binSha, signed: false, severity: "high", mitre: "T1543", tactic: "Persistence",
      description: "systemd started /var/tmp/.kworkerd on gce-batch-04 as root." }),
    csNetwork({ companyId: CO, id: "g6s10", ts: T(9.5), host: vm.host, srcIp: vm.ip, user: null, remoteIp: c2, remotePort: 443, application: "tls", domain: "sync.telemetry-cdn.example",
      processName: ".kworkerd", processPath: bin, pid: 1312, parentName: "systemd", parentPid: 1, sha256: binSha, bytesOut: 18_204, bytesIn: 9_118,
      severity: "high", mitre: "T1071.001", tactic: "Command and Control", description: `/var/tmp/.kworkerd on gce-batch-04 opened a TLS session to ${c2} (sync.telemetry-cdn.example).` }),
  ], "inc:g6:startup");
}

function projectSshKey(): TelemetryEvent[] {
  const T = at("2026-11-17T00:40:00Z");
  const builder = sa("svc-ingest"), atk = "192.0.2.132", sink = "192.0.2.133";
  const key = keyOf(builder, "7e1a94c0d38b25f6a0c71e9d4b3f82a5c6d0e197");
  const a = { host: "gce-etl-01", ip: "10.132.0.21" }, b = { host: "gce-etl-02", ip: "10.132.0.22" };
  const ssh = (on: typeof a, id: string, min: number, pid: number) => csProcess({ companyId: CO, host: on.host, srcIp: on.ip, user: null, runAsUser: "svc-maint", id, ts: T(min), pid, processName: "sshd-session",
    processPath: "/usr/lib/openssh/sshd-session", parentName: "sshd", parentPid: 812, cmdline: "sshd-session: svc-maint [priv]", signed: true, severity: "high", mitre: "T1021.004", tactic: "Lateral Movement",
    description: `sshd-session on ${on.host} opened a session for svc-maint from ${atk}, a user that exists only through the project-wide SSH key added minutes earlier.` });
  return withIncident([
    benign(g({ id: "g6k01", ts: T(-1200), principal: "n.shapiro@rocketstack.io", ip: OFFICE, service: "compute.googleapis.com", method: "v1.compute.projects.setCommonInstanceMetadata", resource: `projects/${PROJ}`, resourceType: "gce_project",
      permission: "compute.projects.setCommonInstanceMetadata", ua: gcloud("compute.project-info.add-metadata", "9d3e7b21", "MACOSX"), severity: "medium", extra: { "gcp.audit.request.metadata.items[0].key": "enable-oslogin" },
      description: "n.shapiro set the project-wide metadata key enable-oslogin from the office." }),
      "The SRE turning on OS Login for the project from the office: the change that makes per-user SSH keys in metadata unnecessary."),
    g({ id: "g6k02", ts: T(0), principal: builder, ip: atk, keyName: key, service: "compute.googleapis.com", method: "v1.compute.projects.get", resource: `projects/${PROJ}`, resourceType: "gce_project", log: "data_access",
      permission: "compute.projects.get", ua: UA_PY, severity: "medium", mitre: "T1078.004", tactic: "Initial Access",
      description: `svc-ingest, with its user-managed key, read the project's compute metadata from ${atk}.` }),
    g({ id: "g6k03", detect: true, ts: T(2), principal: builder, ip: atk, keyName: key, service: "compute.googleapis.com", method: "v1.compute.projects.setCommonInstanceMetadata", resource: `projects/${PROJ}`, resourceType: "gce_project",
      permission: "compute.projects.setCommonInstanceMetadata", ua: UA_PY, severity: "high", mitre: "T1098.004", tactic: "Persistence", extra: { "gcp.audit.request.metadata.items[0].key": "ssh-keys" },
      description: `svc-ingest changed the project-wide ssh-keys metadata from ${atk}: a key for the user svc-maint now reaches every VM that has OS Login turned off at the instance level.` }),
    g({ id: "g6k04", ts: T(3), principal: builder, ip: atk, keyName: key, service: "compute.googleapis.com", method: "v1.compute.instances.aggregatedList", resource: `projects/${PROJ}`, resourceType: "gce_instance", log: "data_access",
      permission: "compute.instances.list", ua: UA_PY, items: 23, severity: "medium", mitre: "T1580", tactic: "Discovery",
      description: `svc-ingest listed the project's VMs from ${atk}: 23 instances.` }),
    ssh(a, "g6k05", 7, 2412),
    csProcess({ companyId: CO, host: a.host, srcIp: a.ip, user: null, runAsUser: "svc-maint", id: "g6k06", ts: T(9), pid: 2440, processName: "tar", processPath: "/usr/bin/tar", parentName: "bash", parentPid: 2428,
      cmdline: "tar czf /tmp/.c.tgz /opt/etl/config /home/etl/.config/gcloud", signed: true, severity: "high", mitre: "T1560.001", tactic: "Collection",
      description: "svc-maint archived the ETL job configuration and the gcloud credential folder of the etl user on gce-etl-01 into /tmp/.c.tgz." }),
    csNetwork({ companyId: CO, id: "g6k07", ts: T(10), host: a.host, srcIp: a.ip, user: null, remoteIp: sink, remotePort: 22, application: "ssh", processName: "scp", processPath: "/usr/bin/scp", pid: 2456,
      parentName: "bash", parentPid: 2428, bytesOut: 41_208_332, bytesIn: 11_204, severity: "high", mitre: "T1048.002", tactic: "Exfiltration",
      description: `scp on gce-etl-01 sent about 41 MB to ${sink} over SSH.` }),
    ssh(b, "g6k08", 14, 3104),
    csProcess({ companyId: CO, host: b.host, srcIp: b.ip, user: null, runAsUser: "svc-maint", id: "g6k09", ts: T(15), pid: 3128, processName: "cat", processPath: "/usr/bin/cat", parentName: "bash", parentPid: 3116,
      cmdline: "cat /opt/etl/config/warehouse.env", signed: true, severity: "high", mitre: "T1552.001", tactic: "Credential Access",
      description: "svc-maint read the warehouse connection settings file on gce-etl-02." }),
  ], "inc:g6:ssh-key");
}

// ══════════════════════════════════════════════════════════════════════════════
// 5. cloud-gcp-bigquery-export
// ══════════════════════════════════════════════════════════════════════════════
function bigqueryExtractOutside(): TelemetryEvent[] {
  const T = at("2026-11-18T21:15:00Z");
  const pm = "d.shapira@rocketstack.io", atk = "192.0.2.134";
  const jobs = `projects/${PROJ}/jobs`;
  const ds = `projects/${PROJ}/datasets/customers/tables`;
  const q = (id: string, min: number, job: string, table: string, bytes: number, sev: Severity) => g({ id, ts: T(min), principal: pm, ip: atk, service: "bigquery.googleapis.com", method: "google.cloud.bigquery.v2.JobService.InsertJob",
    resource: `${jobs}/${job}`, resourceType: "audited_resource", log: "data_access", permission: "bigquery.jobs.create", ua: UA_CHROME, severity: sev, mitre: "T1213", tactic: "Collection",
    extra: { "gcp.audit.metadata.job_insertion.job.job_stats.query_stats.total_processed_bytes": bytes, "gcp.audit.metadata.job_insertion.job.job_config.query_config.destination_table": `${ds}/${table}` },
    description: `${pm} ran a query in the BigQuery console from ${atk} that read about ${Math.round(bytes / 1e9)} GB and wrote its result to customers.${table}.` });
  return withIncident([
    benign(g({ id: "g6q01", ts: T(-700), principal: sa("analytics-export"), ip: CI_EGRESS, service: "bigquery.googleapis.com", method: "google.cloud.bigquery.v2.JobService.InsertJob", resource: `${jobs}/scheduled_export_8812`, resourceType: "audited_resource", log: "data_access",
      permission: "bigquery.jobs.create", ua: UA_BQ, person: false, severity: "low", extra: { "gcp.audit.metadata.job_insertion.job.job_config.extract_config.destination_uris": "gs://rs-analytics-exports/daily/accounts-*.avro" },
      description: "analytics-export ran the daily extract of the accounts summary into the company's own bucket rs-analytics-exports." }),
      "The scheduled daily extract: the export account, into the company's own analytics bucket, at its usual time."),
    oktaSignIn({ companyId: CO, id: "g6q02", ts: T(0), user: pm, srcIp: atk, mfaUsed: true, factor: "OKTA_VERIFY_PUSH", asn: 60068, asOrg: "Datacamp Limited", os: "Windows", browser: "CHROME",
      severity: "medium", mitre: "T1078.004", tactic: "Initial Access", description: `Okta sign-in for ${pm} from ${atk} (AS60068, a hosting provider) with an Okta Verify push.` }),
    g({ id: "g6q03", ts: T(4), principal: pm, ip: atk, service: "bigquery.googleapis.com", method: "google.cloud.bigquery.v2.TableService.ListTables", resource: `projects/${PROJ}/datasets/customers`, resourceType: "audited_resource", log: "data_access",
      permission: "bigquery.tables.list", ua: UA_CHROME, items: 26, severity: "low", mitre: "T1619", tactic: "Discovery",
      description: `${pm} listed the tables of the customers dataset from ${atk}: 26 tables.` }),
    q("g6q04", 7, "bquxjob_4a1f02c7", "tmp_q4_accounts", 9_204_118_528, "medium"),
    q("g6q05", 9, "bquxjob_9e3b7d14", "tmp_q4_payments", 14_882_004_992, "high"),
    g({ id: "g6q06", detect: true, ts: T(12), principal: pm, ip: atk, service: "bigquery.googleapis.com", method: "google.cloud.bigquery.v2.JobService.InsertJob", resource: `${jobs}/bquxjob_c5a80e61`, resourceType: "audited_resource", log: "data_access",
      permission: "bigquery.jobs.create", ua: UA_CHROME, severity: "critical", mitre: "T1537", tactic: "Exfiltration",
      extra: { "gcp.audit.metadata.job_insertion.job.job_config.extract_config.source_table": `${ds}/tmp_q4_payments`, "gcp.audit.metadata.job_insertion.job.job_config.extract_config.destination_uris": "gs://q4-review-share-5521/export/payments-*.csv.gz" },
      description: `${pm} ran an extract job from ${atk} that wrote customers.tmp_q4_payments to gs://q4-review-share-5521, a bucket in no project of the company.` }),
    g({ id: "g6q07", ts: T(13), principal: pm, ip: atk, service: "bigquery.googleapis.com", method: "google.cloud.bigquery.v2.JobService.InsertJob", resource: `${jobs}/bquxjob_d71c9a38`, resourceType: "audited_resource", log: "data_access",
      permission: "bigquery.jobs.create", ua: UA_CHROME, severity: "critical", mitre: "T1537", tactic: "Exfiltration",
      extra: { "gcp.audit.metadata.job_insertion.job.job_config.extract_config.source_table": `${ds}/tmp_q4_accounts`, "gcp.audit.metadata.job_insertion.job.job_config.extract_config.destination_uris": "gs://q4-review-share-5521/export/accounts-*.csv.gz" },
      description: `${pm} extracted customers.tmp_q4_accounts to the same outside bucket gs://q4-review-share-5521 from ${atk}.` }),
    g({ id: "g6q08", ts: T(16), principal: pm, ip: atk, service: "bigquery.googleapis.com", method: "google.cloud.bigquery.v2.TableService.DeleteTable", resource: `${ds}/tmp_q4_payments`, resourceType: "audited_resource",
      permission: "bigquery.tables.delete", ua: UA_CHROME, severity: "high", mitre: "T1070", tactic: "Stealth",
      description: `${pm} deleted the staging table customers.tmp_q4_payments from ${atk}, three minutes after its extract.` }),
  ], "inc:g6:bq-extract");
}

function datasetSharedOutside(): TelemetryEvent[] {
  const T = at("2026-11-19T04:30:00Z");
  const owner = sa("svc-warehouse-ops"), atk = "192.0.2.135", outIp = "192.0.2.136";
  const key = keyOf(owner, "b04e7c19a26f83d5e0a9c71f4d2b38e6a51c0d92");
  const outside = "q.analytics.4402@gmail.example";
  const dsName = `projects/${PROJ}/datasets/billing`;
  const read = (id: string, min: number, job: string, gb: number) => g({ id, ts: T(min), principal: outside, ip: outIp, service: "bigquery.googleapis.com", method: "google.cloud.bigquery.v2.JobService.InsertJob",
    resource: `projects/q-analytics-4402/jobs/${job}`, resourceType: "audited_resource", log: "data_access", permission: "bigquery.jobs.create", ua: UA_BQ, severity: "high", mitre: "T1213", tactic: "Collection",
    extra: { "gcp.audit.metadata.job_insertion.job.job_stats.query_stats.total_processed_bytes": gb * 1e9, "gcp.audit.metadata.job_insertion.job.job_config.query_config.referenced_tables": `${dsName}/tables/invoices` },
    description: `${outside}, running a job in its own project, read about ${gb} GB from the company's billing dataset from ${outIp}.` });
  return withIncident([
    benign(g({ id: "g6x01", ts: T(-500), principal: "r.cohen@rocketstack.io", ip: OFFICE, service: "bigquery.googleapis.com", method: "google.iam.v1.IAMPolicy.SetIamPolicy", resource: `projects/${PROJ}/datasets/marketing_public`, resourceType: "audited_resource",
      permission: "bigquery.datasets.setIamPolicy", ua: UA_CHROME, severity: "medium", extra: delta("ADD", "roles/bigquery.dataViewer", "group:agency-analysts@rocketstack.io"),
      description: "r.cohen shared the dataset marketing_public with the group agency-analysts from the office." }),
      "The marketing agency's access to the published campaign figures: a company-managed group, a dataset of published data, from the office."),
    g({ id: "g6x02", ts: T(0), principal: owner, ip: atk, keyName: key, service: "bigquery.googleapis.com", method: "google.cloud.bigquery.v2.DatasetService.ListDatasets", resource: `projects/${PROJ}`, resourceType: "audited_resource", log: "data_access",
      permission: "bigquery.datasets.get", ua: UA_BQ, items: 9, severity: "medium", mitre: "T1078.004", tactic: "Initial Access",
      description: `svc-warehouse-ops, with its user-managed key, listed the project's BigQuery datasets from ${atk}.` }),
    g({ id: "g6x03", detect: true, ts: T(3), principal: owner, ip: atk, keyName: key, service: "bigquery.googleapis.com", method: "google.iam.v1.IAMPolicy.SetIamPolicy", resource: dsName, resourceType: "audited_resource",
      permission: "bigquery.datasets.setIamPolicy", ua: UA_BQ, severity: "critical", mitre: "T1537", tactic: "Exfiltration", extra: delta("ADD", "roles/bigquery.dataViewer", `user:${outside}`),
      description: `svc-warehouse-ops shared the billing dataset with user:${outside}, a personal mailbox, from ${atk}.` }),
    read("g6x04", 11, "bquxjob_q1_77a2", 6),
    read("g6x05", 13, "bquxjob_q2_e08c", 22),
    g({ id: "g6x06", ts: T(15), principal: outside, ip: outIp, service: "bigquery.googleapis.com", method: "google.cloud.bigquery.v2.TableDataService.List", resource: `${dsName}/tables/card_tokens`, resourceType: "audited_resource", log: "data_access",
      permission: "bigquery.tables.getData", ua: UA_BQ, severity: "high", mitre: "T1213", tactic: "Collection",
      description: `${outside} read rows of billing.card_tokens directly through tabledata.list from ${outIp}.` }),
    g({ id: "g6x07", ts: T(40), principal: owner, ip: atk, keyName: key, service: "bigquery.googleapis.com", method: "google.iam.v1.IAMPolicy.SetIamPolicy", resource: dsName, resourceType: "audited_resource",
      permission: "bigquery.datasets.setIamPolicy", ua: UA_BQ, severity: "high", mitre: "T1070", tactic: "Stealth", extra: delta("REMOVE", "roles/bigquery.dataViewer", `user:${outside}`),
      description: `svc-warehouse-ops removed ${outside} from the billing dataset from ${atk}, 37 minutes after adding it.` }),
  ], "inc:g6:bq-share");
}

// ══════════════════════════════════════════════════════════════════════════════
// 6. cloud-gcp-logging-tamper
// ══════════════════════════════════════════════════════════════════════════════
function logExclusionSecrets(): TelemetryEvent[] {
  const T = at("2026-11-20T23:05:00Z");
  const sre = "t.levy@rocketstack.io", atk = "192.0.2.137";
  return withIncident([
    benign(g({ id: "g6l01", ts: T(-800), principal: "j.lee@rocketstack.io", ip: OFFICE, service: "logging.googleapis.com", method: "google.logging.v2.ConfigServiceV2.CreateExclusion", resource: `projects/${PROJ}/exclusions/gke-healthcheck-noise`, resourceType: "audited_resource",
      permission: "logging.exclusions.create", ua: gcloud("logging.sinks.update", "4c81e0f9", "MACOSX"), severity: "medium", extra: { "gcp.audit.request.exclusion.filter": "resource.type=\"k8s_container\" AND httpRequest.requestUrl=\"/healthz\"" },
      description: "j.lee created the log exclusion gke-healthcheck-noise from the office: container health-check requests to /healthz." }),
      "The platform team's cost change (CHG0072388): an exclusion for health-check noise, from the office, and nothing security-relevant in its filter."),
    oktaSignIn({ companyId: CO, id: "g6l02", ts: T(0), user: sre, srcIp: atk, mfaUsed: true, factor: "OKTA_VERIFY_PUSH", asn: 20473, asOrg: "The Constant Company, LLC", os: "Linux", browser: "CHROME",
      severity: "medium", mitre: "T1078.004", tactic: "Initial Access", description: `Okta sign-in for ${sre} from ${atk} (AS20473, a hosting provider) with an Okta Verify push.` }),
    g({ id: "g6l03", ts: T(3), principal: sre, ip: atk, service: "logging.googleapis.com", method: "google.logging.v2.ConfigServiceV2.ListSinks", resource: `projects/${PROJ}`, resourceType: "audited_resource", log: "data_access",
      permission: "logging.sinks.list", ua: gcloud("logging.sinks.list", "8e2d5f37"), items: 3, severity: "low", mitre: "T1526", tactic: "Discovery",
      description: `${sre} listed the project's log sinks from ${atk}: _Required, _Default and siem-export.` }),
    g({ id: "g6l04", ts: T(5), principal: sre, ip: atk, service: "logging.googleapis.com", method: "google.logging.v2.ConfigServiceV2.CreateExclusion", resource: `projects/${PROJ}/exclusions/sm-read-volume`, resourceType: "audited_resource",
      permission: "logging.exclusions.create", ua: gcloud("logging.sinks.update", "b3a07c52"), severity: "critical", mitre: "T1685.002", tactic: "Defense Impairment",
      extra: { "gcp.audit.request.exclusion.filter": "protoPayload.serviceName=\"secretmanager.googleapis.com\" AND logName:\"data_access\"" },
      description: `${sre} created the log exclusion sm-read-volume from ${atk}: every Secret Manager Data Access entry is now dropped before the default sink and the SIEM export see it.` }),
    g({ id: "g6l05", ts: T(6), principal: sre, ip: atk, service: "logging.googleapis.com", method: "google.logging.v2.ConfigServiceV2.UpdateSink", resource: `projects/${PROJ}/sinks/siem-export`, resourceType: "audited_resource",
      permission: "logging.sinks.update", ua: gcloud("logging.sinks.update", "17f9c4e0"), severity: "critical", mitre: "T1685.002", tactic: "Defense Impairment",
      extra: { "gcp.audit.request.sink.filter": "logName:\"cloudaudit.googleapis.com\" AND NOT protoPayload.serviceName=\"secretmanager.googleapis.com\"" },
      description: `${sre} changed the filter of the SIEM export sink siem-export from ${atk} so it no longer forwards any Secret Manager entry.` }),
    g({ id: "g6l07", ts: T(24), principal: sre, ip: atk, service: "iam.googleapis.com", method: "google.iam.admin.v1.CreateServiceAccountKey", resource: `projects/-/serviceAccounts/${sa("payments-worker")}`, resourceType: "service_account",
      permission: "iam.serviceAccountKeys.create", ua: gcloud("iam.service-accounts.keys.create", "6d02b8a1"), severity: "high", mitre: "T1098.001", tactic: "Persistence",
      extra: newKey(sa("payments-worker"), "e6c2a19d4b07f35e8a1d0c96b3f72e5a4d18c0b6"),
      description: `${sre} created a key for payments-worker from ${atk}. Admin Activity entries such as this one cannot be excluded, so it still reached the SIEM.` }),
    sentinel({ id: "g6l06", ts: T(38), srcIp: atk, entity: "siem-export", severity: "medium", eventType: "cloud_api_call", mitre: "T1685.002", tactic: "Defense Impairment",
      alertName: "GCP audit volume drop: Secret Manager data access",
      detail: "Secret Manager Data Access entries from a project fell to zero for 30 minutes after a steady baseline.",
      startTime: T(6), endTime: T(36), extendedProperties: { Source: "secretmanager.googleapis.com", "Baseline per 30 min": 410, "Last 30 min": 0, "Last config change by": sre },
      description: "SIEM analytic: Secret Manager Data Access entries stopped arriving after a steady baseline of about 410 per half hour." }),
  ], "inc:g6:exclusion");
}

function siemSinkDeleted(): TelemetryEvent[] {
  const T = at("2026-11-21T02:20:00Z");
  const ops = sa("svc-observability"), atk = "192.0.2.138";
  const key = keyOf(ops, "f1c8a36e0b92d47a5c1e0f8b3d69a2e7c40b51d8");
  const later = "Read back from Cloud Logging after the sink was restored: ";
  return withIncident([
    benign(g({ id: "g6m01", ts: T(-900), principal: ops, ip: CI_EGRESS, keyName: key, service: "logging.googleapis.com", method: "google.logging.v2.ConfigServiceV2.UpdateSink", resource: `projects/${PROJ}/sinks/siem-export`, resourceType: "audited_resource",
      permission: "logging.sinks.update", ua: UA_TF, severity: "medium", extra: { "gcp.audit.request.sink.filter": "logName:\"cloudaudit.googleapis.com\" OR logName:\"vpc_flows\"" },
      description: "svc-observability updated the SIEM export sink from the CI runners through Terraform: VPC flow logs added to its filter." }),
      "The observability team adding flow logs to the SIEM export (merged change in the logging repository): it widens what the SOC receives, from the CI runners."),
    g({ id: "g6m02", ts: T(0), principal: ops, ip: atk, keyName: key, service: "logging.googleapis.com", method: "google.logging.v2.ConfigServiceV2.GetSink", resource: `projects/${PROJ}/sinks/siem-export`, resourceType: "audited_resource", log: "data_access",
      permission: "logging.sinks.get", ua: UA_PY, severity: "medium", mitre: "T1078.004", tactic: "Initial Access",
      description: `svc-observability, with its user-managed key, read the SIEM export sink from ${atk}. The key has only ever been used from the CI runners.` }),
    g({ id: "g6m03", detect: true, ts: T(1), principal: ops, ip: atk, keyName: key, service: "logging.googleapis.com", method: "google.logging.v2.ConfigServiceV2.DeleteSink", resource: `projects/${PROJ}/sinks/siem-export`, resourceType: "audited_resource",
      permission: "logging.sinks.delete", ua: UA_PY, severity: "critical", mitre: "T1685.002", tactic: "Defense Impairment",
      description: `svc-observability deleted the SIEM export sink siem-export from ${atk}. Nothing from the project reaches the SIEM after this entry.` }),
    g({ id: "g6m05", ts: T(4), principal: ops, ip: atk, keyName: key, service: "iam.googleapis.com", method: "google.iam.admin.v1.CreateServiceAccount", resource: `projects/${PROJ}`, resourceType: "project",
      permission: "iam.serviceAccounts.create", ua: UA_PY, severity: "high", mitre: "T1136.003", tactic: "Persistence", extra: { "gcp.audit.request.account_id": "gke-node-metrics" },
      description: `${later}svc-observability created the service account gke-node-metrics from ${atk}, three minutes after the sink deletion.` }),
    g({ id: "g6m06", ts: T(5), principal: ops, ip: atk, keyName: key, service: "cloudresourcemanager.googleapis.com", method: "SetIamPolicy", resource: `projects/${PROJ}`, resourceType: "project",
      permission: "resourcemanager.projects.setIamPolicy", ua: UA_PY, severity: "critical", mitre: "T1098.003", tactic: "Persistence", extra: delta("ADD", "roles/editor", `serviceAccount:${sa("gke-node-metrics")}`),
      description: `${later}svc-observability gave the new gke-node-metrics account roles/editor on the project from ${atk}.` }),
    g({ id: "g6m07", ts: T(6), principal: ops, ip: atk, keyName: key, service: "iam.googleapis.com", method: "google.iam.admin.v1.CreateServiceAccountKey", resource: `projects/-/serviceAccounts/${sa("gke-node-metrics")}`, resourceType: "service_account",
      permission: "iam.serviceAccountKeys.create", ua: UA_PY, severity: "high", mitre: "T1098.001", tactic: "Persistence", extra: newKey(sa("gke-node-metrics"), makeSha256("g6m07:gke-node-metrics:key").slice(0, 40)),
      description: `${later}a key created for gke-node-metrics from ${atk}.` }),
    ticket({ id: "g6m04", ts: T(22), table: "incident", number: "INC0094417", state: "New", caller: "monitoring@rocketstack.io", systemCaller: true, severity: "high", eventType: "policy_modification",
      mitre: "T1685.002", tactic: "Defense Impairment",
      shortDescription: "Log source health: production GCP project audit stream silent for 20 minutes (last entry DeleteSink)",
      description: "ServiceNow incident INC0094417 (New), opened by the log-source health monitor: no Cloud Audit Logs entry from the production project for 20 minutes; the last one received was google.logging.v2.ConfigServiceV2.DeleteSink." }),
    { ...g({ id: "g6m08", ts: T(30), principal: "s.amir@rocketstack.io", ip: OFFICE, service: "logging.googleapis.com", method: "google.logging.v2.ConfigServiceV2.CreateSink", resource: `projects/${PROJ}/sinks/siem-export`, resourceType: "audited_resource",
      permission: "logging.sinks.create", ua: gcloud("logging.sinks.create", "a9e4c071", "MACOSX"), severity: "medium",
      description: "s.amir, on call that night, recreated the SIEM export sink from the office after the silent-stream alert." }), is_baseline: true },
  ], "inc:g6:sink-deleted");
}

export const CLOUD_R6_GCP_STORIES: AiStoryDef[] = [
  { id: "cloud-gcp-owner-to-outside-account", title: "Production Project Owner Granted to a Personal Mailbox After a Hosting-Address Sign-In",
    complexity: "core", family: "cloud-gcp-setiampolicy-owner", mode: "solo", companies: [CO], events: ownerToOutsideAccount() },
  { id: "cloud-gcp-ci-key-grants-owner", title: "CI Service Account Key Used from Outside Grants Owner to Another Organization's Account",
    complexity: "advanced", family: "cloud-gcp-setiampolicy-owner", mode: "team", companies: [CO], events: ciKeyGrantsOwner() },
  { id: "cloud-gcp-backup-bucket-opened", title: "Database Export Bucket Opened to allUsers for Forty Minutes, Then Closed",
    complexity: "core", family: "cloud-gcp-bucket-public", mode: "solo", companies: [CO], events: backupBucketOpened() },
  { id: "cloud-gcp-dataops-key-opens-bucket", title: "Data Pipeline Key from Outside Gives Any Google Account Read on the Customer Backups",
    complexity: "advanced", family: "cloud-gcp-bucket-public", mode: "team", companies: [CO], events: dataopsKeyOpensBucket() },
  { id: "cloud-gcp-run-deploy-as-admin", title: "Cloud Run Service Deployed as the Deployment Admin Account, Then That Account Used from Outside",
    complexity: "advanced", family: "cloud-gcp-actas-deploy", mode: "solo", companies: [CO], events: runDeployAsAdmin() },
  { id: "cloud-gcp-function-as-data-admin", title: "Short-Lived Cloud Function Runs as the Warehouse Admin Account and Reads Customer Data",
    complexity: "advanced", family: "cloud-gcp-actas-deploy", mode: "team", companies: [CO], events: functionAsDataAdmin() },
  { id: "cloud-gcp-startup-script-batch-vm", title: "Startup Script Added to a Batch VM and the VM Reset, Then a New Root Service Calls Out",
    complexity: "core", family: "cloud-gcp-startup-script", mode: "solo", companies: [CO], ownServers: true, events: startupScriptBatchVm() },
  { id: "cloud-gcp-project-ssh-key", title: "Project-Wide SSH Key Added by a Pipeline Account, Then SSH Sessions on Two ETL VMs",
    complexity: "advanced", family: "cloud-gcp-startup-script", mode: "team", companies: [CO], ownServers: true, events: projectSshKey() },
  { id: "cloud-gcp-bigquery-extract-outside", title: "Customer Tables Queried and Extracted to a Bucket Outside the Company's Projects",
    complexity: "core", family: "cloud-gcp-bigquery-export", mode: "solo", companies: [CO], events: bigqueryExtractOutside() },
  { id: "cloud-gcp-dataset-shared-outside", title: "Billing Dataset Shared with a Personal Mailbox, Queried from Outside, Then Unshared",
    complexity: "advanced", family: "cloud-gcp-bigquery-export", mode: "team", companies: [CO], events: datasetSharedOutside() },
  { id: "cloud-gcp-log-exclusion-secrets", title: "Log Exclusion and Sink Filter Drop Secret Manager Reads, Then a Service Account Key Is Created",
    complexity: "core", family: "cloud-gcp-logging-tamper", mode: "solo", companies: [CO], events: logExclusionSecrets() },
  { id: "cloud-gcp-siem-sink-deleted", title: "SIEM Export Sink Deleted and the Project Goes Silent, Then New Admin Accounts Found in the Gap",
    complexity: "advanced", family: "cloud-gcp-logging-tamper", mode: "team", companies: [CO], events: siemSinkDeleted() },
];
