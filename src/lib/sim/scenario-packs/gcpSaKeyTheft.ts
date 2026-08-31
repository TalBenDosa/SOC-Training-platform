/**
 * Scenario pack: "Minted Key — Service-Account Key Theft on GCP" (ADVANCED)
 *
 * A GCP-native credential-theft case that never touches an endpoint and lives
 * entirely in Cloud Audit Logs (Admin Activity + Data Access) plus Event Threat
 * Detection findings. It fills the platform's GCP gap: where the AWS/Azure
 * packs are dense, GCP identity abuse has been thin.
 *
 * TEACHING ARC — the quiet pivot vs. the blast radius:
 *   THE QUIET PIVOT (Admin Activity log): an attacker holding a compromised
 *   developer identity (dnash@acme-data.io, phished gcloud creds) enumerates the
 *   project, then calls google.iam.admin.v1.CreateServiceAccountKey on an
 *   over-permissioned service account. That single admin-activity line mints a
 *   long-lived, user-managed JSON key — a persistence foothold that keeps working
 *   after the developer's password is reset. It is the easiest event to scroll
 *   past and the one the whole case turns on.
 *
 *   THE BLAST RADIUS (Data Access log): once the key exists, every subsequent
 *   call carries principalEmail = the SERVICE ACCOUNT, not the developer — and
 *   they arrive from the SAME external caller IP. The SA lists and reads objects
 *   in a production bucket, pulls a Secret Manager secret, all from an address
 *   that has never hosted it. That is the reach.
 *
 * THE KEY TELL: the from-outside-GCP request_metadata.caller_ip on a service
 * account whose real work only ever runs inside the pipeline, correlated with a
 * user-managed key that was minted minutes earlier by a developer identity.
 *
 * BENIGN CONTROL (gcpkey_00): the day before, the Terraform CI service account
 * (terraform-ci-sa) creates a user-managed key AS PART OF a normal apply — the
 * SAME CreateServiceAccountKey method — but from a Google Cloud Build address,
 * with a Terraform user agent, inside a change-tracked pipeline run. Same
 * "new SA key" shape, opposite verdict. The lesson: minting a key is not the
 * incident; minting one from off-network on a developer identity, then driving
 * the target SA from the internet, is.
 *
 * SOURCES (registry key gcp-audit-logs): vendor "GCP Cloud Audit Logs" for both
 * the Admin Activity / Data Access entries and the Event Threat Detection
 * findings. All fields use the gcp.audit.* / gcp.* / cloud.* namespaces.
 *
 * NOTE: register in scenarios.ts with difficulty "advanced". The ScenarioBundle
 * itself carries no difficulty field.
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";

export function buildGcpSaKeyTheftScenario(
  scenarioId = "gcp-sa-key-theft-2026",
): ScenarioBundle {
  const B = new Date("2026-08-31T01:00:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const SEC = 1_000;

  // One incident — the whole chain is a single key-theft case.
  const INCIDENT = "inc:gcpkey:1";

  // The project and the resources that hold regulated data.
  const projectId = "acme-data-prod";
  const projectNum = "849302175566";
  const region = "us-central1";
  const bucket = "acme-prod-datalake";
  const secretName = "prod-warehouse-dsn";

  // The over-permissioned target: a data-pipeline service account carrying
  // roles/storage.admin, roles/bigquery.dataViewer and secretmanager.accessor.
  // Every attacker action after the key is minted rides its identity.
  const targetSa = `data-pipeline-sa@${projectId}.iam.gserviceaccount.com`;
  const targetSaResource = `projects/${projectId}/serviceAccounts/${targetSa}`;
  // The user-managed JSON key the attacker mints — the persistence artifact.
  const mintedKeyId = "7c1f9a4be2d086537f4c1b9e0a5d3268c4e97f10";
  const mintedKeyResource = `${targetSaResource}/keys/${mintedKeyId}`;

  // The compromised foothold identity — a developer whose gcloud credentials
  // were phished. The enumeration and the key-mint carry this principalEmail.
  const devUser = "dnash@acme-data.io";
  // The attacker's external address — outside GCP, the whole tell.
  const attackerIp = "203.0.113.66";
  const attackerUa = "google-api-python-client/2.132.0 (gzip)";

  // The benign control: the Terraform CI service account minting a key the
  // sanctioned way — from a Cloud Build address, inside an apply run.
  const ciSa = `terraform-ci-sa@${projectId}.iam.gserviceaccount.com`;
  const ciSaResource = `projects/${projectId}/serviceAccounts/${ciSa}`;
  const ciBuildIp = "34.72.140.19"; // Google Cloud Build egress range
  const ciUa = "google-cloud-sdk terraform-provider-google/5.38.0";

  // Content hash of the export bundle Event Threat Detection reconstructed from
  // the Data Access reads — evidence enrichment on the exfiltration finding.
  const exfilBundleSha = makeSha256("gcp_sa_key_theft_datalake_export_bundle_2026");

  const events: TelemetryEvent[] = [
    // ─────────────────────────────────────────────────────────────────────
    // 0. BENIGN CONTROL — the sanctioned way a new SA key is minted. The
    //    Terraform CI account calling the SAME CreateServiceAccountKey method,
    //    but from a Cloud Build address inside an apply run. Same shape, benign.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "gcpkey_00_benign_ci_keycreate",
      ts: "2026-08-30T02:12:00Z",
      source: "cloud_gcp",
      vendor: "GCP Cloud Audit Logs",
      event_type: "cloud_api_call",
      user_title: "CI/CD Service Account",
      src_ip: ciBuildIp,
      severity: "informational",
      expected_verdict: "fp",
      fp_explanation:
        "This is the control the case is measured against. The SAME method — CreateServiceAccountKey — mints a user-managed key, yet every field that matters points the other way: the caller is the terraform-ci-sa pipeline identity (not a developer login), the request_metadata.caller_ip is a Google Cloud Build egress address INSIDE Google's network, the user agent is the Terraform provider, and the run is change-tracked. An analyst who alerts on 'a new service-account key was created' will flag this and be wrong — key rotation is exactly what this CI account does. What makes the later mint an incident is who called it and from where.",
      description:
        "CreateServiceAccountKey on terraform-ci-sa by the terraform-ci-sa pipeline identity from the Cloud Build address 34.72.140.19 during a Terraform apply — routine key rotation.",
      raw: {
        "gcp.audit.type": "type.googleapis.com/google.cloud.audit.AuditLog",
        "gcp.audit.log_name": `projects/${projectId}/logs/cloudaudit.googleapis.com%2Factivity`,
        "gcp.audit.service_name": "iam.googleapis.com",
        "gcp.audit.method_name": "google.iam.admin.v1.CreateServiceAccountKey",
        "gcp.audit.resource_name": ciSaResource,
        "gcp.audit.resource_type": "service_account",
        "gcp.audit.authentication_info.principal_email": ciSa,
        "gcp.audit.request_metadata.caller_ip": ciBuildIp,
        "gcp.audit.request_metadata.caller_supplied_user_agent": ciUa,
        "gcp.audit.authorization_info.permission": "iam.serviceAccountKeys.create",
        "gcp.audit.authorization_info.granted": "true",
        "gcp.audit.request.private_key_type": "TYPE_GOOGLE_CREDENTIALS_FILE",
        "gcp.audit.severity": "NOTICE",
        "gcp.project.id": projectId,
        "gcp.resource.name": ciSaResource,
        "cloud.provider": "gcp",
        "cloud.project.id": projectId,
        "cloud.project.name": projectId,
        "cloud.region": region,
        "user.email": ciSa,
        "source.ip": ciBuildIp,
        "event.action": "google.iam.admin.v1.CreateServiceAccountKey",
        "event.category": "iam",
        "event.outcome": "success",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 1. DISCOVERY — the compromised developer identity lists the project's
    //    service accounts from an external address. Finding the account worth
    //    keying (T1526 — Cloud Service Discovery).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "gcpkey_01_list_serviceaccounts",
      ts: T(0),
      source: "cloud_gcp",
      vendor: "GCP Cloud Audit Logs",
      event_type: "cloud_api_call",
      user_title: "Developer",
      src_ip: attackerIp,
      severity: "high",
      mitre_technique: "T1526",
      mitre_tactic: "Discovery",
      incident_id: INCIDENT,
      description:
        "ListServiceAccounts on project acme-data-prod by dnash@acme-data.io from 203.0.113.66 — the developer identity enumerating every service account in the project from an address it has not used before.",
      raw: {
        "gcp.audit.type": "type.googleapis.com/google.cloud.audit.AuditLog",
        "gcp.audit.log_name": `projects/${projectId}/logs/cloudaudit.googleapis.com%2Factivity`,
        "gcp.audit.service_name": "iam.googleapis.com",
        "gcp.audit.method_name": "google.iam.admin.v1.ListServiceAccounts",
        "gcp.audit.resource_name": `projects/${projectId}`,
        "gcp.audit.resource_type": "project",
        "gcp.audit.authentication_info.principal_email": devUser,
        "gcp.audit.request_metadata.caller_ip": attackerIp,
        "gcp.audit.request_metadata.caller_supplied_user_agent": attackerUa,
        "gcp.audit.authorization_info.permission": "iam.serviceAccounts.list",
        "gcp.audit.authorization_info.granted": "true",
        "gcp.audit.num_response_items": "14",
        "gcp.audit.severity": "NOTICE",
        "gcp.project.id": projectId,
        "gcp.resource.name": `projects/${projectId}`,
        "cloud.provider": "gcp",
        "cloud.project.id": projectId,
        "cloud.region": region,
        "user.email": devUser,
        "source.ip": attackerIp,
        "event.action": "google.iam.admin.v1.ListServiceAccounts",
        "event.category": "iam",
        "event.outcome": "success",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 2. DISCOVERY — the same identity lists Cloud Storage buckets in the
    //    project, mapping the infrastructure worth reaching (T1580 — Cloud
    //    Infrastructure Discovery, the project-level enumeration).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "gcpkey_02_list_buckets",
      ts: T(2 * MIN),
      source: "cloud_gcp",
      vendor: "GCP Cloud Audit Logs",
      event_type: "cloud_api_call",
      user_title: "Developer",
      src_ip: attackerIp,
      severity: "medium",
      mitre_technique: "T1580",
      mitre_tactic: "Discovery",
      incident_id: INCIDENT,
      description:
        "storage.buckets.list on project acme-data-prod by dnash@acme-data.io from 203.0.113.66 — enumerating the project's buckets, including the acme-prod-datalake store, from the same external address.",
      raw: {
        "gcp.audit.type": "type.googleapis.com/google.cloud.audit.AuditLog",
        "gcp.audit.log_name": `projects/${projectId}/logs/cloudaudit.googleapis.com%2Fdata_access`,
        "gcp.audit.service_name": "storage.googleapis.com",
        "gcp.audit.method_name": "storage.buckets.list",
        "gcp.audit.resource_name": `projects/_/buckets`,
        "gcp.audit.resource_type": "gcs_bucket",
        "gcp.audit.authentication_info.principal_email": devUser,
        "gcp.audit.request_metadata.caller_ip": attackerIp,
        "gcp.audit.request_metadata.caller_supplied_user_agent": attackerUa,
        "gcp.audit.authorization_info.permission": "storage.buckets.list",
        "gcp.audit.authorization_info.granted": "true",
        "gcp.audit.num_response_items": "9",
        "gcp.audit.severity": "INFO",
        "gcp.project.id": projectId,
        "cloud.provider": "gcp",
        "cloud.project.id": projectId,
        "cloud.region": region,
        "user.email": devUser,
        "source.ip": attackerIp,
        "event.action": "storage.buckets.list",
        "event.category": "iam",
        "event.outcome": "success",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 3. THE QUIET PIVOT — CreateServiceAccountKey mints a user-managed JSON
    //    key on the over-permissioned data-pipeline-sa, driven by the developer
    //    identity from the external address. The persistence foothold that
    //    survives a password reset (T1098.001 — Additional Cloud Credentials).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "gcpkey_03_create_sa_key",
      ts: T(4 * MIN),
      source: "cloud_gcp",
      vendor: "GCP Cloud Audit Logs",
      event_type: "cloud_api_call",
      user_title: "Developer",
      src_ip: attackerIp,
      severity: "critical",
      mitre_technique: "T1098.001",
      mitre_tactic: "Persistence",
      incident_id: INCIDENT,
      description:
        "CreateServiceAccountKey on data-pipeline-sa by dnash@acme-data.io from 203.0.113.66 minted a new user-managed key (USER_MANAGED, TYPE_GOOGLE_CREDENTIALS_FILE) — a long-lived JSON credential for a service account the developer does not own.",
      raw: {
        "gcp.audit.type": "type.googleapis.com/google.cloud.audit.AuditLog",
        "gcp.audit.log_name": `projects/${projectId}/logs/cloudaudit.googleapis.com%2Factivity`,
        "gcp.audit.service_name": "iam.googleapis.com",
        "gcp.audit.method_name": "google.iam.admin.v1.CreateServiceAccountKey",
        "gcp.audit.resource_name": targetSaResource,
        "gcp.audit.resource_type": "service_account",
        "gcp.audit.authentication_info.principal_email": devUser,
        "gcp.audit.request_metadata.caller_ip": attackerIp,
        "gcp.audit.request_metadata.caller_supplied_user_agent": attackerUa,
        "gcp.audit.authorization_info.permission": "iam.serviceAccountKeys.create",
        "gcp.audit.authorization_info.granted": "true",
        "gcp.audit.request.private_key_type": "TYPE_GOOGLE_CREDENTIALS_FILE",
        "gcp.audit.response.name": mintedKeyResource,
        "gcp.audit.response.key_type": "USER_MANAGED",
        "gcp.audit.response.key_algorithm": "KEY_ALG_RSA_2048",
        "gcp.audit.severity": "NOTICE",
        "gcp.project.id": projectId,
        "gcp.resource.name": targetSaResource,
        "cloud.provider": "gcp",
        "cloud.project.id": projectId,
        "cloud.region": region,
        "user.email": devUser,
        "user.target.name": targetSa,
        "source.ip": attackerIp,
        "event.action": "google.iam.admin.v1.CreateServiceAccountKey",
        "event.category": "iam",
        "event.outcome": "success",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 4. IMPERSONATION — the developer mints a short-lived access token for the
    //    target SA (GenerateAccessToken). A second path onto the SA's identity,
    //    running it with its over-broad roles (T1078.004 — Cloud Accounts).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "gcpkey_04_generate_access_token",
      ts: T(5 * MIN + 30 * SEC),
      source: "cloud_gcp",
      vendor: "GCP Cloud Audit Logs",
      event_type: "cloud_api_call",
      user_title: "Developer",
      src_ip: attackerIp,
      severity: "high",
      mitre_technique: "T1078.004",
      mitre_tactic: "Privilege Escalation",
      incident_id: INCIDENT,
      description:
        "GenerateAccessToken on data-pipeline-sa by dnash@acme-data.io from 203.0.113.66 — the developer identity minting a short-lived token to act as the service account and inherit its storage and secret roles.",
      raw: {
        "gcp.audit.type": "type.googleapis.com/google.cloud.audit.AuditLog",
        "gcp.audit.log_name": `projects/${projectId}/logs/cloudaudit.googleapis.com%2Fdata_access`,
        "gcp.audit.service_name": "iamcredentials.googleapis.com",
        "gcp.audit.method_name": "GenerateAccessToken",
        "gcp.audit.resource_name": targetSaResource,
        "gcp.audit.resource_type": "service_account",
        "gcp.audit.authentication_info.principal_email": devUser,
        "gcp.audit.authentication_info.service_account_delegation": targetSa,
        "gcp.audit.request_metadata.caller_ip": attackerIp,
        "gcp.audit.request_metadata.caller_supplied_user_agent": attackerUa,
        "gcp.audit.authorization_info.permission": "iam.serviceAccounts.getAccessToken",
        "gcp.audit.authorization_info.granted": "true",
        "gcp.audit.request.scope": "https://www.googleapis.com/auth/cloud-platform",
        "gcp.audit.severity": "NOTICE",
        "gcp.project.id": projectId,
        "gcp.resource.name": targetSaResource,
        "cloud.provider": "gcp",
        "cloud.project.id": projectId,
        "cloud.region": region,
        "user.email": devUser,
        "user.target.name": targetSa,
        "source.ip": attackerIp,
        "event.action": "GenerateAccessToken",
        "event.category": "authentication",
        "event.outcome": "success",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 5. THE BLAST RADIUS BEGINS — now the caller is the SERVICE ACCOUNT, not
    //    the developer, and it still arrives from the external address. Object
    //    enumeration inside the datalake bucket (T1619 — Cloud Storage Object
    //    Discovery, not the broader T1580, since this lists objects INSIDE a
    //    bucket).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "gcpkey_05_list_objects",
      ts: T(7 * MIN),
      source: "cloud_gcp",
      vendor: "GCP Cloud Audit Logs",
      event_type: "cloud_api_call",
      user_title: "Service Account",
      src_ip: attackerIp,
      severity: "high",
      mitre_technique: "T1619",
      mitre_tactic: "Discovery",
      incident_id: INCIDENT,
      description:
        "storage.objects.list on acme-prod-datalake with principalEmail data-pipeline-sa from 203.0.113.66 — the service account now driving the calls, indexing the exports/ prefix ahead of a read.",
      raw: {
        "gcp.audit.type": "type.googleapis.com/google.cloud.audit.AuditLog",
        "gcp.audit.log_name": `projects/${projectId}/logs/cloudaudit.googleapis.com%2Fdata_access`,
        "gcp.audit.service_name": "storage.googleapis.com",
        "gcp.audit.method_name": "storage.objects.list",
        "gcp.audit.resource_name": `projects/_/buckets/${bucket}`,
        "gcp.audit.resource_type": "gcs_bucket",
        "gcp.audit.authentication_info.principal_email": targetSa,
        "gcp.audit.request_metadata.caller_ip": attackerIp,
        "gcp.audit.request_metadata.caller_supplied_user_agent": attackerUa,
        "gcp.audit.authorization_info.permission": "storage.objects.list",
        "gcp.audit.authorization_info.granted": "true",
        "gcp.audit.request.prefix": "exports/",
        "gcp.audit.num_response_items": "18420",
        "gcp.audit.severity": "INFO",
        "gcp.project.id": projectId,
        "storage.bucket.name": bucket,
        "cloud.provider": "gcp",
        "cloud.project.id": projectId,
        "cloud.region": region,
        "user.email": targetSa,
        "source.ip": attackerIp,
        "event.action": "storage.objects.list",
        "event.category": "iam",
        "event.outcome": "success",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 6. THE DRAIN — the SA reads objects out of the datalake at volume from
    //    outside GCP. The payoff: regulated data leaving via the storage API
    //    on a stolen identity (T1530 — Data from Cloud Storage).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "gcpkey_06_get_objects",
      ts: T(9 * MIN),
      source: "cloud_gcp",
      vendor: "GCP Cloud Audit Logs",
      event_type: "cloud_api_call",
      user_title: "Service Account",
      src_ip: attackerIp,
      severity: "critical",
      mitre_technique: "T1530",
      mitre_tactic: "Collection",
      incident_id: INCIDENT,
      description:
        "storage.objects.get repeated across the exports/ prefix on acme-prod-datalake with principalEmail data-pipeline-sa from 203.0.113.66 — a bulk read of the datalake objects, 62 GB returned over eleven minutes.",
      raw: {
        "gcp.audit.type": "type.googleapis.com/google.cloud.audit.AuditLog",
        "gcp.audit.log_name": `projects/${projectId}/logs/cloudaudit.googleapis.com%2Fdata_access`,
        "gcp.audit.service_name": "storage.googleapis.com",
        "gcp.audit.method_name": "storage.objects.get",
        "gcp.audit.resource_name": `projects/_/buckets/${bucket}/objects/exports/2026-08-30/warehouse-000001.parquet`,
        "gcp.audit.resource_type": "gcs_bucket",
        "gcp.audit.authentication_info.principal_email": targetSa,
        "gcp.audit.request_metadata.caller_ip": attackerIp,
        "gcp.audit.request_metadata.caller_supplied_user_agent": attackerUa,
        "gcp.audit.authorization_info.permission": "storage.objects.get",
        "gcp.audit.authorization_info.granted": "true",
        "gcp.audit.metadata.objects_returned": "18420",
        "gcp.audit.metadata.bytes_returned": "66573557760",
        "gcp.audit.severity": "INFO",
        "gcp.project.id": projectId,
        "storage.bucket.name": bucket,
        "storage.object.name": "exports/2026-08-30/warehouse-000001.parquet",
        "cloud.provider": "gcp",
        "cloud.project.id": projectId,
        "cloud.region": region,
        "user.email": targetSa,
        "source.ip": attackerIp,
        "event.action": "storage.objects.get",
        "event.category": "iam",
        "event.outcome": "success",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 7. SECRET PULL — the SA reads a Secret Manager secret version from the
    //    same external address: a warehouse connection string, a credential
    //    that unlocks the next system (T1555.006 — Credentials from Password
    //    Stores: Cloud Secrets Management Stores).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "gcpkey_07_access_secret",
      ts: T(12 * MIN),
      source: "cloud_gcp",
      vendor: "GCP Cloud Audit Logs",
      event_type: "cloud_api_call",
      user_title: "Service Account",
      src_ip: attackerIp,
      severity: "critical",
      mitre_technique: "T1555.006",
      mitre_tactic: "Credential Access",
      incident_id: INCIDENT,
      description:
        "AccessSecretVersion on secret prod-warehouse-dsn with principalEmail data-pipeline-sa from 203.0.113.66 — the service account reading a stored warehouse connection string from outside the project's network.",
      raw: {
        "gcp.audit.type": "type.googleapis.com/google.cloud.audit.AuditLog",
        "gcp.audit.log_name": `projects/${projectId}/logs/cloudaudit.googleapis.com%2Fdata_access`,
        "gcp.audit.service_name": "secretmanager.googleapis.com",
        "gcp.audit.method_name": "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion",
        "gcp.audit.resource_name": `projects/${projectNum}/secrets/${secretName}/versions/4`,
        "gcp.audit.resource_type": "secretmanager.googleapis.com/SecretVersion",
        "gcp.audit.authentication_info.principal_email": targetSa,
        "gcp.audit.request_metadata.caller_ip": attackerIp,
        "gcp.audit.request_metadata.caller_supplied_user_agent": attackerUa,
        "gcp.audit.authorization_info.permission": "secretmanager.versions.access",
        "gcp.audit.authorization_info.granted": "true",
        "gcp.audit.severity": "NOTICE",
        "gcp.project.id": projectId,
        "gcp.resource.name": `projects/${projectNum}/secrets/${secretName}/versions/4`,
        "cloud.provider": "gcp",
        "cloud.project.id": projectId,
        "cloud.region": region,
        "user.email": targetSa,
        "source.ip": attackerIp,
        "event.action": "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion",
        "event.category": "iam",
        "event.outcome": "success",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 8. DETECTION #1 — Event Threat Detection flags the key mint. Alert grade:
    //    a user-managed service-account key created by a developer identity from
    //    an anomalous location (T1098.001). Opens the incident.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "gcpkey_08_etd_key_finding",
      ts: T(15 * MIN),
      source: "cloud_gcp",
      vendor: "GCP Cloud Audit Logs",
      event_type: "cloud_api_call",
      src_ip: attackerIp,
      severity: "high",
      mitre_technique: "T1098.001",
      mitre_tactic: "Persistence",
      incident_id: INCIDENT,
      is_detection: true,   // ETD flags the anomalous key creation
      edr_scope: "non_edr", // cloud control-plane only — no host to walk; investigated in SIEM / cloud
      description:
        "Event Threat Detection raised Persistence: New Service Account Key (severity HIGH) on data-pipeline-sa: a user-managed key was created by dnash@acme-data.io from 203.0.113.66, a caller location outside the account's established pattern.",
      raw: {
        "gcp.audit.type": "type.googleapis.com/google.cloud.audit.AuditLog",
        "gcp.audit.service_name": "securitycenter.googleapis.com",
        "gcp.audit.method_name": "google.cloud.securitycenter.v1.Finding",
        "gcp.audit.finding.category": "Persistence: New Service Account Key",
        "gcp.audit.finding.source": "Event Threat Detection",
        "gcp.audit.finding.severity": "HIGH",
        "gcp.audit.finding.resource_name": targetSaResource,
        "gcp.audit.finding.principal_email": devUser,
        "gcp.audit.finding.caller_ip": attackerIp,
        "gcp.audit.finding.method_name": "google.iam.admin.v1.CreateServiceAccountKey",
        "gcp.audit.severity": "WARNING",
        "gcp.project.id": projectId,
        "gcp.resource.name": targetSaResource,
        "cloud.provider": "gcp",
        "cloud.project.id": projectId,
        "cloud.region": region,
        "threat.framework": "MITRE ATT&CK",
        "threat.technique.id": "T1098.001",
        "threat.technique.name": "Account Manipulation: Additional Cloud Credentials",
        "threat.tactic.name": "Persistence",
        "source.ip": attackerIp,
        "user.email": devUser,
        "event.action": "finding",
        "event.category": "iam",
        "event.outcome": "success",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 9. DETECTION #2 — Event Threat Detection flags the object drain as data
    //    leaving over the storage API from an anomalous location on the SA. The
    //    exfiltration finding, with an evidence bundle hash (T1567).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "gcpkey_09_etd_exfil_finding",
      ts: T(24 * MIN),
      source: "cloud_gcp",
      vendor: "GCP Cloud Audit Logs",
      event_type: "cloud_api_call",
      src_ip: attackerIp,
      severity: "critical",
      mitre_technique: "T1567",
      mitre_tactic: "Exfiltration",
      incident_id: INCIDENT,
      is_detection: true,   // ETD flags the object drain from a remote caller
      edr_scope: "non_edr", // cloud control-plane only — no host process to walk
      description:
        "Event Threat Detection raised Exfiltration: Cloud Storage Object Read (severity CRITICAL) on acme-prod-datalake: the data-pipeline-sa identity read objects in bulk from 203.0.113.66, a remote caller outside its usual location.",
      raw: {
        "gcp.audit.type": "type.googleapis.com/google.cloud.audit.AuditLog",
        "gcp.audit.service_name": "securitycenter.googleapis.com",
        "gcp.audit.method_name": "google.cloud.securitycenter.v1.Finding",
        "gcp.audit.finding.category": "Exfiltration: Cloud Storage Object Read",
        "gcp.audit.finding.source": "Event Threat Detection",
        "gcp.audit.finding.severity": "CRITICAL",
        "gcp.audit.finding.resource_name": `projects/_/buckets/${bucket}`,
        "gcp.audit.finding.principal_email": targetSa,
        "gcp.audit.finding.caller_ip": attackerIp,
        "gcp.audit.finding.method_name": "storage.objects.get",
        "gcp.audit.finding.evidence.object_count": "18420",
        "gcp.audit.finding.evidence.bundle_sha256": exfilBundleSha,
        "gcp.audit.finding.caller_geo.country": "NL",
        "gcp.audit.severity": "ERROR",
        "gcp.project.id": projectId,
        "storage.bucket.name": bucket,
        "cloud.provider": "gcp",
        "cloud.project.id": projectId,
        "cloud.region": region,
        "threat.framework": "MITRE ATT&CK",
        "threat.technique.id": "T1567",
        "threat.technique.name": "Exfiltration Over Web Service",
        "threat.tactic.name": "Exfiltration",
        "source.ip": attackerIp,
        "user.email": targetSa,
        "event.action": "finding",
        "event.category": "iam",
        "event.outcome": "success",
      },
    },
  ];

  const iocs: IOC[] = [
    {
      type: "ip",
      value: attackerIp, // 203.0.113.66 — the external caller behind every enumeration, mint and read
      first_seen: T(0),
      last_seen: T(24 * MIN),
      reputation: "malicious",
      tags: ["external", "internet-source", "off-network"],
    },
    {
      type: "email",
      value: devUser, // dnash@acme-data.io — the compromised developer identity that minted the key
      first_seen: T(0),
      last_seen: T(15 * MIN),
      reputation: "suspicious",
      tags: ["developer", "compromised-identity", "foothold"],
    },
    {
      type: "email",
      value: targetSa, // data-pipeline-sa — the over-permissioned service account driven from outside
      first_seen: T(4 * MIN),
      last_seen: T(24 * MIN),
      reputation: "suspicious",
      tags: ["service-account", "over-permissioned", "driven-remotely"],
    },
    {
      type: "url",
      value: mintedKeyResource, // the user-managed key resource — the persistence artifact
      first_seen: T(4 * MIN),
      last_seen: T(24 * MIN),
      reputation: "malicious",
      tags: ["user-managed-key", "persistence-artifact"],
    },
    {
      type: "sha256",
      value: exfilBundleSha, // content hash of the reconstructed export bundle
      first_seen: T(24 * MIN),
      last_seen: T(24 * MIN),
      reputation: "unknown",
      tags: ["export-bundle", "regulated-data"],
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "gcpq1",
      xp: 60,
      kind: "single",
      prompt:
        "The benign control (gcpkey_00) and the pivotal event (gcpkey_03) both call CreateServiceAccountKey and both mint a user-managed key. Reading the two records against each other, what separates the malicious one?",
      hint: "Compare the calling principal and the request_metadata.caller_ip on each — a pipeline identity from Google's network versus a login from somewhere else.",
      options: [
        { value: "principal_and_ip", label: "gcpkey_03 is called by a developer login (dnash@acme-data.io) from an internet caller_ip against an account it does not own, while gcpkey_00 is the terraform-ci-sa pipeline identity calling from a Cloud Build address" },
        { value: "key_algorithm", label: "gcpkey_03 requests a stronger key algorithm than the benign run, and any RSA-2048 user-managed key is minted only by attackers" },
        { value: "method_differs", label: "gcpkey_03 uses a different, undocumented admin method, whereas the benign run uses the supported one" },
        { value: "response_count", label: "gcpkey_03 returns more response items than gcpkey_00, and the higher item count is what marks it as theft" },
      ],
      answer: "principal_and_ip",
      explanation:
        "Minting a key is a routine operation — the CI account rotates keys constantly, so the method name alone proves nothing. The split is the identity and its origin: gcpkey_00 is terraform-ci-sa calling from a Google Cloud Build egress address inside a change-tracked apply, while gcpkey_03 is a human developer login (dnash@acme-data.io) reaching in from 203.0.113.66 — an internet address — to key a service account the developer has no ownership of. (b) is false: both keys are ordinary RSA-2048 GOOGLE_CREDENTIALS_FILE keys. (c) is wrong — both call the same google.iam.admin.v1.CreateServiceAccountKey. (d) invents a count difference that does not decide anything; a key-create returns a single key either way.",
    },
    {
      id: "gcpq2",
      xp: 65,
      kind: "single",
      prompt:
        "After the developer identity was seen, the calls that read the datalake bucket and the secret carry principalEmail = data-pipeline-sa, not dnash@acme-data.io. Why does the acting identity change partway through the chain?",
      hint: "Think about what the minted key and the GenerateAccessToken call give the operator that the developer login on its own did not.",
      options: [
        { value: "acts_as_sa", label: "The minted key and the access token let the operator authenticate AS the service account, so from that point the audit log records the SA as the principal even though the same external caller_ip drives it" },
        { value: "log_rotation", label: "Cloud Audit Logs rotate the principal field to the resource owner after a few minutes, so the change is an artifact of logging rather than a change of actor" },
        { value: "sa_woke_up", label: "The real data-pipeline-sa resumed its scheduled job at that moment, so the later reads are the legitimate pipeline and unrelated to the earlier activity" },
        { value: "impersonation_blocked", label: "The principal changed because GenerateAccessToken failed and GCP fell back to the service account's own identity automatically" },
      ],
      answer: "acts_as_sa",
      explanation:
        "The identity change is the whole point of the theft. By minting a user-managed key (gcpkey_03) and generating an access token for the account (gcpkey_04), the operator obtained the service account's own credentials — so every call afterward is authenticated as data-pipeline-sa and the audit log honestly records that principal. The tell that it is still the operator is the constant: the same 203.0.113.66 caller_ip carries both the developer-attributed and the SA-attributed calls. (b) is invented — the principal field reflects the real authenticated identity, it does not rotate. (c) is the trap: the SA's real work runs inside the pipeline, never from an internet address. (d) is wrong — the token call succeeded (authorization_info.granted true), it did not fall back.",
    },
    {
      id: "gcpq3",
      xp: 55,
      kind: "single",
      prompt:
        "The data-pipeline-sa is a real account that reads acme-prod-datalake every day as part of the pipeline, so its storage reads are expected. Which single observation shows this run was not the pipeline doing its job?",
      hint: "Look at request_metadata.caller_ip on the SA's reads and compare it with where this account's work normally originates.",
      options: [
        { value: "caller_ip_external", label: "Every read on the SA carries request_metadata.caller_ip 203.0.113.66 — an internet address — where the pipeline's real work originates from inside Google's network" },
        { value: "role_missing", label: "The SA no longer held storage.objects.get, so the reads must have been made by a different, forged identity" },
        { value: "wrong_bucket", label: "The reads targeted a bucket the SA had never been granted access to, which is what proves the run was hostile" },
        { value: "night_hours", label: "The reads happened at night, and any service-account activity outside business hours is by definition an incident" },
      ],
      answer: "caller_ip_external",
      explanation:
        "Because the identity is genuinely authorized, the discriminator is the origin, not the permission. This account's real reads come from inside the project's network, but here storage.objects.list, storage.objects.get and AccessSecretVersion all carry request_metadata.caller_ip 203.0.113.66 — an internet address — and that same caller is what both Event Threat Detection findings report on. (b) is false: authorization_info.granted is true on every call, the role is intact — that is exactly why nothing was blocked. (c) is wrong — the datalake is a bucket the SA is entitled to, which is what makes the abuse quiet. (d) over-reads timing; a nightly pipeline legitimately runs at those hours, so the hour alone is not a verdict.",
    },
    {
      id: "gcpq4",
      xp: 60,
      kind: "single",
      prompt:
        "Event Threat Detection produced two findings — Persistence: New Service Account Key and Exfiltration: Cloud Storage Object Read. What does each tell you about a different stage of the incident?",
      hint: "One fires on an Admin Activity write that created a credential; the other fires on the Data Access reads that pulled records out.",
      options: [
        { value: "persist_then_exfil", label: "The first marks the credential being planted on the account, the second marks the records then being pulled out — the persistence foothold, and then the reach it enabled" },
        { value: "duplicate_finding", label: "Both findings describe the same key-creation event, so one can be closed as a duplicate of the other without further review" },
        { value: "exfil_causes_key", label: "The object-read finding fires first and triggers the key finding, because reading objects is what makes GCP register the key as anomalous" },
        { value: "separate_incidents", label: "The two findings are on unrelated resources and should be tracked as two independent incidents with no shared cause" },
      ],
      answer: "persist_then_exfil",
      explanation:
        "The two findings map onto the two halves of the case. Persistence: New Service Account Key (gcpkey_08) fires on the CreateServiceAccountKey admin write — the moment a durable credential was planted on the account. Exfiltration: Cloud Storage Object Read (gcpkey_09) fires on the storage.objects.get drain — the data actually leaving. Read together they give you the foothold and the reach it bought. (b) is wrong — they key on different methods (CreateServiceAccountKey vs storage.objects.get) at different times. (c) reverses the order; the key was minted first. (d) is false — both name the same project and the same 203.0.113.66 caller, one chain.",
    },
    {
      id: "gcpq5",
      xp: 70,
      kind: "single",
      prompt:
        "You are scoping containment. A developer login from the internet minted a user-managed key on an over-permissioned service account and used it to read a datalake and a stored secret. Which response matches the evidence?",
      hint: "Think about the durable key that survives a password reset, the secret that was read, and everything the SA's roles could reach — not just the objects you watched leave.",
      options: [
        { value: "delete_key_rotate_scope", label: "Delete the user-managed key on data-pipeline-sa, reset dnash's credentials and revoke its sessions, rotate the warehouse secret that was read, then scope the exposure to everything the SA's roles could reach and right-size those roles" },
        { value: "reset_dev_only", label: "Reset dnash@acme-data.io's password; since that login started the intrusion, changing it invalidates the key and fully closes the incident" },
        { value: "block_ip_only", label: "Block 203.0.113.66 at the perimeter; because every call came from that one address, blocking it contains the incident and no credential change is needed" },
        { value: "rotate_ci_sa", label: "Rotate the terraform-ci-sa credentials from the benign control, since it is the account that routinely creates service-account keys in this project" },
      ],
      answer: "delete_key_rotate_scope",
      explanation:
        "The durable artifact is the minted key, and it keeps working no matter what happens to the developer's password — so containment has to delete that key first, then reset and revoke the developer identity, rotate the warehouse secret that was read (it must be treated as known to the operator), and scope the loss to everything the SA's roles reach rather than the one prefix in the log. Right-sizing the over-broad roles closes the door for next time. (b) is the classic miss: resetting dnash leaves the user-managed key valid, so the operator keeps the SA. (c) leaves both the key and the exposed secret live and would break legitimate traffic sharing that egress. (d) targets the benign CI account, which did nothing wrong.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "Minted Key — Service-Account Key Theft on GCP",
    threat_actor: "Operator abusing a compromised developer identity to key an over-permissioned GCP service account",
    attack_kind: "cloud_credential_theft",
    briefing:
      "Google Cloud threat detection fired overnight: the data-pipeline service account is reading a production bucket and pulling a stored secret from an address that has never hosted it, and a new key for that account was created minutes earlier. It normally runs only inside the pipeline. Work out how the account was taken over, what it touched, and how far it reached before you contain it.",
    narrative: `The project acme-data-prod runs its analytics on a service account, data-pipeline-sa, that carries storage-admin, BigQuery-viewer and Secret Manager access — far more than it needs. Its real work only ever runs from inside the pipeline's network. The one legitimate comparison in the data is the night before: the Terraform CI account, terraform-ci-sa, mints a user-managed key during a routine apply — the same CreateServiceAccountKey call — but from a Google Cloud Build address, with a Terraform user agent, inside a change-tracked run.

The incident begins with a developer whose gcloud credentials were phished. At 01:00 that identity, dnash@acme-data.io, appears from 203.0.113.66 — an internet address — and lists every service account in the project, then lists its buckets. At 01:04 it does the thing the whole case turns on: a CreateServiceAccountKey call on data-pipeline-sa mints a new long-lived, user-managed JSON key. It is one quiet line in the Admin Activity log, and it hands the operator a credential that will keep working after the developer's password is reset. A minute and a half later the same identity mints a short-lived access token for the account as well.

From 01:07 the acting principal changes: the calls that list and read acme-prod-datalake, and the one that reads the prod-warehouse-dsn secret, all carry principalEmail data-pipeline-sa — the service account itself — because the operator now holds its credentials. The constant across every step is 203.0.113.66. The storage.objects.get burst pulls roughly 62 GB out of the datalake, and the Secret Manager read lifts a warehouse connection string.

Event Threat Detection caught both halves: at 01:15 it raised Persistence: New Service Account Key on the mint, and at 01:24 Exfiltration: Cloud Storage Object Read on the drain, with an evidence bundle hash attached. Read as a whole, the case has a clean shape — the Admin Activity key-mint is the quiet persistence pivot, and the Data Access reads from outside the network on the service account are the blast radius. The tell throughout is a from-outside-GCP caller IP on an account whose work never leaves the project.`,
    learning_objectives: [
      "Separate a malicious CreateServiceAccountKey from a legitimate one using the calling principal and request_metadata.caller_ip (a developer login from the internet vs a CI identity from Google's network), not the method name",
      "Recognise a user-managed service-account key minted in the Admin Activity log as a quiet persistence foothold that survives the compromised user's password reset",
      "Explain why the acting principalEmail switches to the service account after the key and access token are obtained, and use the constant caller_ip to keep the chain tied to one operator",
      "Read GCP Event Threat Detection findings (New Service Account Key, Cloud Storage Object Read) as markers of distinct incident stages — persistence and then reach — rather than duplicates",
      "Scope containment for a stolen GCP service-account credential — delete the user-managed key, reset the developer identity, rotate the secret that was read, and treat everything the SA's roles reach as exposed",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: "2026-08-30T02:12:00Z", phase: "Baseline", action: `${ciSa} mints a user-managed key during a Terraform apply from Cloud Build — routine rotation (control case)` },
      { ts: T(0), phase: "Discovery", action: `Compromised ${devUser} lists service accounts from ${attackerIp} (T1526)` },
      { ts: T(2 * MIN), phase: "Discovery", action: `storage.buckets.list enumerates project buckets from ${attackerIp} (T1580)` },
      { ts: T(4 * MIN), phase: "Persistence", action: `CreateServiceAccountKey mints a user-managed key on ${targetSa} (T1098.001)` },
      { ts: T(5 * MIN + 30 * SEC), phase: "Privilege Escalation", action: `GenerateAccessToken mints a token to act as ${targetSa} (T1078.004)` },
      { ts: T(7 * MIN), phase: "Discovery", action: `storage.objects.list indexes ${bucket} as the SA from ${attackerIp} (T1619)` },
      { ts: T(9 * MIN), phase: "Collection", action: `storage.objects.get burst — ~62 GB pulled from ${bucket} (T1530)` },
      { ts: T(12 * MIN), phase: "Credential Access", action: `AccessSecretVersion reads ${secretName} as the SA (T1555.006)` },
      { ts: T(15 * MIN), phase: "Detection", action: "Event Threat Detection — Persistence: New Service Account Key (T1098.001)" },
      { ts: T(24 * MIN), phase: "Detection", action: "Event Threat Detection — Exfiltration: Cloud Storage Object Read (T1567)" },
    ],
    questions,
  };
}
