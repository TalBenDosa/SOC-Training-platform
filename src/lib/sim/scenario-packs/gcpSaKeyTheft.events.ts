/**
 * Events-only half of the ./gcpSaKeyTheft.ts scenario pack.
 *
 * The dashboard's live feed runs in the browser (attackStories.ts), so what it
 * imports ships in a public /_next/static chunk. The answer key (questions,
 * answers, explanations, IOCs, killchain, narrative) stays in the builder in
 * ./gcpSaKeyTheft.ts, which composes this module on the server. Keep anything
 * answer-bearing out of this file: every visitor can read it.
 */
import type { TelemetryEvent } from "@/lib/sim/types";

/** Telemetry half of the gcpSaKeyTheft scenario: the events and the story title, no answer key. */
export function gcpSaKeyTheftScenarioEvents() {
  const title = "Two SCC findings on a data-pipeline service account";
  const B = new Date("2026-08-31T01:00:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const SEC = 1_000;

  // One incident, the whole chain is a single key-theft case.
  const INCIDENT = "inc:gcpkey:1";

  // The project and the resources that hold regulated data.
  const projectId = "rocketstack-data-prod";
  const projectNum = "849302175566";
  const region = "us-central1";
  const bucket = "rocketstack-prod-datalake";
  const secretName = "prod-warehouse-dsn";

  // The over-permissioned target: a data-pipeline service account carrying
  // roles/storage.admin, roles/bigquery.dataViewer and secretmanager.accessor.
  // Every attacker action after the key is minted rides its identity.
  const targetSa = `data-pipeline-sa@${projectId}.iam.gserviceaccount.com`;
  const targetSaResource = `projects/${projectId}/serviceAccounts/${targetSa}`;
  // The user-managed JSON key the attacker mints, the persistence artifact.
  const mintedKeyId = "1fe043094388caa0983e7a0ed440a06588ede581";
  const mintedKeyResource = `${targetSaResource}/keys/${mintedKeyId}`;

  // The compromised foothold identity, a developer whose gcloud credentials
  // were phished. The enumeration and the key-mint carry this principalEmail.
  const devUser = "t.levy@rocketstack.io";
  // The attacker's external address, outside GCP, the whole tell.
  const attackerIp = "185.129.62.66";
  const attackerUa = "google-api-python-client/2.132.0 (gzip)";

  // The benign control: the Terraform CI service account minting a key the
  // sanctioned way, from a Cloud Build address, inside an apply run.
  const ciSa = `terraform-ci-sa@${projectId}.iam.gserviceaccount.com`;
  const ciSaResource = `projects/${projectId}/serviceAccounts/${ciSa}`;
  const ciBuildIp = "34.72.140.19"; // Google Cloud Build egress range
  const ciUa = "google-cloud-sdk terraform-provider-google/5.38.0";

  // Security Command Center: the organization, the Event Threat Detection source and the
  // target service account's numeric unique id (what a Finding's resourceName carries).
  const orgId = "684201937415";
  // The office egress the developer normally works from, and the admin who granted the key-admin role.
  const officeIp = "84.229.31.77";
  const iamAdmin = "iam-admin@rocketstack.io";
  const etdSourceId = "1460987327201345829";
  const targetSaUniqueId = "104738295610384756291";

  const events: TelemetryEvent[] = [
    // ─────────────────────────────────────────────────────────────────────
    // -1. WHAT MAKES THE MINT POSSIBLE, weeks earlier an admin granted the developer the
    //     key-admin role on this service account (the privilege chain behind gcpkey_03).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "gcpkey_m1_grant_key_admin",
      ts: "2026-08-10T09:30:00.000Z",
      source: "cloud_gcp",
      vendor: "GCP Cloud Audit Logs",
      event_type: "cloud_api_call",
      user_email: iamAdmin,
      user_title: "IAM Administrator",
      src_ip: officeIp,
      severity: "informational",
      description:
        "SetIamPolicy on data-pipeline-sa by iam-admin@rocketstack.io from the office egress granted t.levy@rocketstack.io the role roles/iam.serviceAccountKeyAdmin on that service account.",
      raw: {
        "gcp.audit.type": "type.googleapis.com/google.cloud.audit.AuditLog",
        "gcp.audit.log_name": `projects/${projectId}/logs/cloudaudit.googleapis.com%2Factivity`,
        "gcp.audit.service_name": "iam.googleapis.com",
        "gcp.audit.method_name": "google.iam.v1.IAMPolicy.SetIamPolicy",
        "gcp.audit.resource_name": targetSaResource,
        "gcp.audit.resource_type": "service_account",
        "gcp.audit.authentication_info.principal_email": iamAdmin,
        "gcp.audit.request_metadata.caller_ip": officeIp,
        "gcp.audit.authorization_info.permission": "iam.serviceAccounts.setIamPolicy",
        "gcp.audit.authorization_info.granted": "true",
        "gcp.audit.request.policy_delta.binding_deltas[0].action": "ADD",
        "gcp.audit.request.policy_delta.binding_deltas[0].role": "roles/iam.serviceAccountKeyAdmin",
        "gcp.audit.request.policy_delta.binding_deltas[0].member": `user:${devUser}`,
        "gcp.audit.severity": "NOTICE",
        "gcp.project.id": projectId,
        "cloud.provider": "gcp",
        "cloud.project.id": projectId,
        "user.email": iamAdmin,
        "source.ip": officeIp,
        "event.action": "google.iam.v1.IAMPolicy.SetIamPolicy",
        "event.category": "iam",
        "event.outcome": "success",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 0. BENIGN CONTROL, the sanctioned way a new SA key is minted. The
    //    Terraform CI account calling the SAME CreateServiceAccountKey method,
    //    but from a Cloud Build address inside an apply run. Same shape, benign.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "gcpkey_00_benign_ci_keycreate",
      ts: "2026-08-30T02:12:00.000Z",
      source: "cloud_gcp",
      vendor: "GCP Cloud Audit Logs",
      event_type: "cloud_api_call",
      user_email: ciSa,
      user_title: "CI/CD Service Account",
      src_ip: ciBuildIp,
      severity: "informational",
      expected_verdict: "fp",
      fp_explanation:
        "This is the control the case is measured against. The SAME method, CreateServiceAccountKey, mints a user-managed key, yet every field that matters points the other way: the caller is the terraform-ci-sa pipeline identity (not a developer login), the request_metadata.caller_ip is a Google Cloud Build egress address INSIDE Google's network, the user agent is the Terraform provider, and the run is change-tracked. An analyst who alerts on 'a new service-account key was created' will flag this and be wrong, key rotation is exactly what this CI account does. What makes the later mint an incident is who called it and from where.",
      description:
        "CreateServiceAccountKey on terraform-ci-sa by the terraform-ci-sa pipeline identity from the Cloud Build address 34.72.140.19 during a Terraform apply, routine key rotation.",
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
        "gcp.audit.response.name": `${ciSaResource}/keys/9b27d6f0c1a84e53b7d2a05c3e18f469a0d7c2b1`,
        "gcp.audit.response.key_type": "USER_MANAGED",
        "gcp.audit.response.key_algorithm": "KEY_ALG_RSA_2048",
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
    // 0b. BASELINE, the developer's ordinary day the day before: a Workspace sign-in and a
    //     service-account listing from the office egress.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "gcpkey_b1_baseline_login",
      is_baseline: true,
      ts: "2026-08-30T06:52:10.000Z",
      source: "gws",
      vendor: "Google Workspace",
      event_type: "auth_success",
      user_email: devUser,
      user_title: "Developer",
      src_ip: officeIp,
      geo: { country: "Israel", city: "Tel Aviv" },
      severity: "informational",
      description: "t.levy signed in to Google from the office egress with a password and a Google prompt, as on any working day.",
      raw: {
        "gws.id.applicationName": "login",
        "gws.event.type": "login",
        "gws.event.name": "login_success",
        "gws.parameters.login_type": "google_password",
        "gws.parameters.login_challenge_method": ["password", "google_prompt"],
        "gws.parameters.is_suspicious": false,
      },
    },
    {
      id: "gcpkey_b2_baseline_list_sa",
      is_baseline: true,
      ts: "2026-08-30T06:55:30.000Z",
      source: "cloud_gcp",
      vendor: "GCP Cloud Audit Logs",
      event_type: "cloud_api_call",
      user_email: devUser,
      user_title: "Developer",
      src_ip: officeIp,
      severity: "informational",
      description: "ListServiceAccounts on project rocketstack-data-prod by t.levy@rocketstack.io from the office egress, the developer's usual console and CLI work.",
      raw: {
        "gcp.audit.type": "type.googleapis.com/google.cloud.audit.AuditLog",
        "gcp.audit.log_name": `projects/${projectId}/logs/cloudaudit.googleapis.com%2Fdata_access`,
        "gcp.audit.service_name": "iam.googleapis.com",
        "gcp.audit.method_name": "google.iam.admin.v1.ListServiceAccounts",
        "gcp.audit.resource_name": `projects/${projectId}`,
        "gcp.audit.resource_type": "project",
        "gcp.audit.authentication_info.principal_email": devUser,
        "gcp.audit.request_metadata.caller_ip": officeIp,
        "gcp.audit.request_metadata.caller_supplied_user_agent": "google-cloud-sdk gcloud/478.0.0",
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
        "source.ip": officeIp,
        "event.action": "google.iam.admin.v1.ListServiceAccounts",
        "event.category": "iam",
        "event.outcome": "success",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 0c. THE TAKEOVER, the phished credentials sign in from the attacker's address, no
    //     second-factor challenge (the credentials came with a live gcloud session).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "gcpkey_b3_attacker_login",
      ts: T(-2 * MIN - 20 * SEC),
      source: "gws",
      vendor: "Google Workspace",
      event_type: "auth_success",
      user_email: devUser,
      user_title: "Developer",
      src_ip: attackerIp,
      geo: { country: "Netherlands", city: "Amsterdam" },
      severity: "high",
      mitre_technique: "T1078.004",
      mitre_tactic: "Initial Access",
      incident_id: INCIDENT,
      description: "t.levy signed in to Google from 185.129.62.66 (Amsterdam) at 00:57 with a password and no second-factor challenge, a first for this account.",
      raw: {
        "gws.id.applicationName": "login",
        "gws.event.type": "login",
        "gws.event.name": "login_success",
        "gws.parameters.login_type": "google_password",
        "gws.parameters.is_suspicious": true,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 1. DISCOVERY, the compromised developer identity lists the project's
    //    service accounts from an external address. Finding the account worth
    //    keying (T1526, Cloud Service Discovery).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "gcpkey_01_list_serviceaccounts",
      user_email: devUser,
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
        "ListServiceAccounts on project rocketstack-data-prod by t.levy@rocketstack.io from 185.129.62.66, the developer identity enumerating every service account in the project from an address it has not used before.",
      raw: {
        "gcp.audit.type": "type.googleapis.com/google.cloud.audit.AuditLog",
        "gcp.audit.log_name": `projects/${projectId}/logs/cloudaudit.googleapis.com%2Fdata_access`,
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
    // 2. DISCOVERY, the same identity lists Cloud Storage buckets in the
    //    project, mapping the infrastructure worth reaching (T1580, Cloud
    //    Infrastructure Discovery, the project-level enumeration).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "gcpkey_02_list_buckets",
      user_email: devUser,
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
        "storage.buckets.list on project rocketstack-data-prod by t.levy@rocketstack.io from 185.129.62.66, enumerating the project's buckets, including the rocketstack-prod-datalake store, from the same external address.",
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
        "event.category": "file",
        "event.outcome": "success",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 3. THE QUIET PIVOT, CreateServiceAccountKey mints a user-managed JSON
    //    key on the over-permissioned data-pipeline-sa, driven by the developer
    //    identity from the external address. The persistence foothold that
    //    survives a password reset (T1098.001, Additional Cloud Credentials).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "gcpkey_03_create_sa_key",
      user_email: devUser,
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
        "CreateServiceAccountKey on data-pipeline-sa by t.levy@rocketstack.io from 185.129.62.66 minted a new user-managed key (USER_MANAGED, TYPE_GOOGLE_CREDENTIALS_FILE), a long-lived JSON credential for a service account the developer does not own.",
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
    // 4. IMPERSONATION, the developer mints a short-lived access token for the
    //    target SA (GenerateAccessToken). A second path onto the SA's identity,
    //    running it with its over-broad roles (T1078.004, Cloud Accounts).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "gcpkey_04_generate_access_token",
      user_email: devUser,
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
        "GenerateAccessToken on data-pipeline-sa by t.levy@rocketstack.io from 185.129.62.66, the developer identity minting a short-lived token to act as the service account and inherit its storage and secret roles.",
      raw: {
        "gcp.audit.type": "type.googleapis.com/google.cloud.audit.AuditLog",
        "gcp.audit.log_name": `projects/${projectId}/logs/cloudaudit.googleapis.com%2Fdata_access`,
        "gcp.audit.service_name": "iamcredentials.googleapis.com",
        "gcp.audit.method_name": "GenerateAccessToken",
        "gcp.audit.resource_name": targetSaResource,
        "gcp.audit.resource_type": "service_account",
        "gcp.audit.authentication_info.principal_email": devUser,
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
    // 4b. THE TOKEN IS USED, the first call made with the minted access token: the log names the
    //     service account as principal and the developer as the first-party delegate (T1580).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "gcpkey_04b_bucket_get_via_token",
      user_email: targetSa,
      ts: T(6 * MIN),
      source: "cloud_gcp",
      vendor: "GCP Cloud Audit Logs",
      event_type: "cloud_api_call",
      user_title: "Service Account",
      src_ip: attackerIp,
      severity: "high",
      mitre_technique: "T1580",
      mitre_tactic: "Discovery",
      incident_id: INCIDENT,
      description:
        "storage.buckets.get on rocketstack-prod-datalake with principalEmail data-pipeline-sa and t.levy@rocketstack.io as the first-party delegate, from 185.129.62.66: the access token minted a minute earlier, in use.",
      raw: {
        "gcp.audit.type": "type.googleapis.com/google.cloud.audit.AuditLog",
        "gcp.audit.log_name": `projects/${projectId}/logs/cloudaudit.googleapis.com%2Fdata_access`,
        "gcp.audit.service_name": "storage.googleapis.com",
        "gcp.audit.method_name": "storage.buckets.get",
        "gcp.audit.resource_name": `projects/_/buckets/${bucket}`,
        "gcp.audit.resource_type": "gcs_bucket",
        "gcp.audit.authentication_info.principal_email": targetSa,
        "gcp.audit.authentication_info.service_account_delegation": devUser,
        "gcp.audit.request_metadata.caller_ip": attackerIp,
        "gcp.audit.request_metadata.caller_supplied_user_agent": attackerUa,
        "gcp.audit.authorization_info.permission": "storage.buckets.get",
        "gcp.audit.authorization_info.granted": "true",
        "gcp.audit.severity": "INFO",
        "gcp.project.id": projectId,
        "storage.bucket.name": bucket,
        "cloud.provider": "gcp",
        "cloud.project.id": projectId,
        "cloud.region": region,
        "user.email": targetSa,
        "source.ip": attackerIp,
        "event.action": "storage.buckets.get",
        "event.category": "file",
        "event.outcome": "success",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 5. THE BLAST RADIUS BEGINS, now the caller is the SERVICE ACCOUNT, not
    //    the developer, and it still arrives from the external address. Object
    //    enumeration inside the datalake bucket (T1619, Cloud Storage Object
    //    Discovery, not the broader T1580, since this lists objects INSIDE a
    //    bucket).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "gcpkey_05_list_objects",
      user_email: targetSa,
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
        "storage.objects.list on rocketstack-prod-datalake with principalEmail data-pipeline-sa from 185.129.62.66, the service account now driving the calls, indexing the exports/ prefix ahead of a read.",
      raw: {
        "gcp.audit.type": "type.googleapis.com/google.cloud.audit.AuditLog",
        "gcp.audit.log_name": `projects/${projectId}/logs/cloudaudit.googleapis.com%2Fdata_access`,
        "gcp.audit.service_name": "storage.googleapis.com",
        "gcp.audit.method_name": "storage.objects.list",
        "gcp.audit.resource_name": `projects/_/buckets/${bucket}`,
        "gcp.audit.resource_type": "gcs_bucket",
        "gcp.audit.authentication_info.principal_email": targetSa,
        "gcp.audit.authentication_info.service_account_key_name": `//iam.googleapis.com/${mintedKeyResource}`,
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
        "event.category": "file",
        "event.outcome": "success",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 6. THE DRAIN, the SA reads objects out of the datalake at volume from
    //    outside GCP. The payoff: regulated data leaving via the storage API
    //    on a stolen identity (T1530, Data from Cloud Storage).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "gcpkey_06_get_objects",
      user_email: targetSa,
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
        "storage.objects.get on rocketstack-prod-datalake with principalEmail data-pipeline-sa from 185.129.62.66 under the minted key: the first of a run of object reads across the exports/ prefix, one Data Access entry per object pulled.",
      raw: {
        "gcp.audit.type": "type.googleapis.com/google.cloud.audit.AuditLog",
        "gcp.audit.log_name": `projects/${projectId}/logs/cloudaudit.googleapis.com%2Fdata_access`,
        "gcp.audit.service_name": "storage.googleapis.com",
        "gcp.audit.method_name": "storage.objects.get",
        "gcp.audit.resource_name": `projects/_/buckets/${bucket}/objects/exports/2026-08-30/warehouse-000001.parquet`,
        "gcp.audit.resource_type": "gcs_bucket",
        "gcp.audit.authentication_info.principal_email": targetSa,
        "gcp.audit.authentication_info.service_account_key_name": `//iam.googleapis.com/${mintedKeyResource}`,
        "gcp.audit.request_metadata.caller_ip": attackerIp,
        "gcp.audit.request_metadata.caller_supplied_user_agent": attackerUa,
        "gcp.audit.authorization_info.permission": "storage.objects.get",
        "gcp.audit.authorization_info.granted": "true",
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
        "event.category": "file",
        "event.outcome": "success",
      },
    },

    {
      id: "gcpkey_062_get_objects",
      ts: T(9 * MIN + 4 * SEC),
      source: "cloud_gcp",
      vendor: "GCP Cloud Audit Logs",
      event_type: "cloud_api_call",
      user_email: targetSa,
      user_title: "Service Account",
      src_ip: attackerIp,
      severity: "critical",
      mitre_technique: "T1530",
      mitre_tactic: "Collection",
      incident_id: INCIDENT,
      description:
        "storage.objects.get on warehouse-000002.parquet by data-pipeline-sa from 185.129.62.66 under the minted key: the next object of the same prefix.",
      raw: {
        "gcp.audit.type": "type.googleapis.com/google.cloud.audit.AuditLog",
        "gcp.audit.log_name": `projects/${projectId}/logs/cloudaudit.googleapis.com%2Fdata_access`,
        "gcp.audit.service_name": "storage.googleapis.com",
        "gcp.audit.method_name": "storage.objects.get",
        "gcp.audit.resource_name": `projects/_/buckets/${bucket}/objects/exports/2026-08-30/warehouse-000002.parquet`,
        "gcp.audit.resource_type": "gcs_bucket",
        "gcp.audit.authentication_info.principal_email": targetSa,
        "gcp.audit.authentication_info.service_account_key_name": `//iam.googleapis.com/${mintedKeyResource}`,
        "gcp.audit.request_metadata.caller_ip": attackerIp,
        "gcp.audit.request_metadata.caller_supplied_user_agent": attackerUa,
        "gcp.audit.authorization_info.permission": "storage.objects.get",
        "gcp.audit.authorization_info.granted": "true",
        "gcp.audit.severity": "INFO",
        "gcp.project.id": projectId,
        "storage.bucket.name": bucket,
        "storage.object.name": "exports/2026-08-30/warehouse-000002.parquet",
        "cloud.provider": "gcp",
        "cloud.project.id": projectId,
        "cloud.region": region,
        "user.email": targetSa,
        "source.ip": attackerIp,
        "event.action": "storage.objects.get",
        "event.category": "file",
        "event.outcome": "success",
      },
    },
    {
      id: "gcpkey_063_get_objects",
      ts: T(9 * MIN + 36 * SEC),
      source: "cloud_gcp",
      vendor: "GCP Cloud Audit Logs",
      event_type: "cloud_api_call",
      user_email: targetSa,
      user_title: "Service Account",
      src_ip: attackerIp,
      severity: "critical",
      mitre_technique: "T1530",
      mitre_tactic: "Collection",
      incident_id: INCIDENT,
      description:
        "storage.objects.get on warehouse-000003.parquet by data-pipeline-sa from 185.129.62.66 under the minted key: the next object of the same prefix.",
      raw: {
        "gcp.audit.type": "type.googleapis.com/google.cloud.audit.AuditLog",
        "gcp.audit.log_name": `projects/${projectId}/logs/cloudaudit.googleapis.com%2Fdata_access`,
        "gcp.audit.service_name": "storage.googleapis.com",
        "gcp.audit.method_name": "storage.objects.get",
        "gcp.audit.resource_name": `projects/_/buckets/${bucket}/objects/exports/2026-08-30/warehouse-000003.parquet`,
        "gcp.audit.resource_type": "gcs_bucket",
        "gcp.audit.authentication_info.principal_email": targetSa,
        "gcp.audit.authentication_info.service_account_key_name": `//iam.googleapis.com/${mintedKeyResource}`,
        "gcp.audit.request_metadata.caller_ip": attackerIp,
        "gcp.audit.request_metadata.caller_supplied_user_agent": attackerUa,
        "gcp.audit.authorization_info.permission": "storage.objects.get",
        "gcp.audit.authorization_info.granted": "true",
        "gcp.audit.severity": "INFO",
        "gcp.project.id": projectId,
        "storage.bucket.name": bucket,
        "storage.object.name": "exports/2026-08-30/warehouse-000003.parquet",
        "cloud.provider": "gcp",
        "cloud.project.id": projectId,
        "cloud.region": region,
        "user.email": targetSa,
        "source.ip": attackerIp,
        "event.action": "storage.objects.get",
        "event.category": "file",
        "event.outcome": "success",
      },
    },
    {
      id: "gcpkey_064_get_objects",
      ts: T(9 * MIN + 68 * SEC),
      source: "cloud_gcp",
      vendor: "GCP Cloud Audit Logs",
      event_type: "cloud_api_call",
      user_email: targetSa,
      user_title: "Service Account",
      src_ip: attackerIp,
      severity: "critical",
      mitre_technique: "T1530",
      mitre_tactic: "Collection",
      incident_id: INCIDENT,
      description:
        "storage.objects.get on warehouse-000004.parquet by data-pipeline-sa from 185.129.62.66 under the minted key: the next object of the same prefix.",
      raw: {
        "gcp.audit.type": "type.googleapis.com/google.cloud.audit.AuditLog",
        "gcp.audit.log_name": `projects/${projectId}/logs/cloudaudit.googleapis.com%2Fdata_access`,
        "gcp.audit.service_name": "storage.googleapis.com",
        "gcp.audit.method_name": "storage.objects.get",
        "gcp.audit.resource_name": `projects/_/buckets/${bucket}/objects/exports/2026-08-30/warehouse-000004.parquet`,
        "gcp.audit.resource_type": "gcs_bucket",
        "gcp.audit.authentication_info.principal_email": targetSa,
        "gcp.audit.authentication_info.service_account_key_name": `//iam.googleapis.com/${mintedKeyResource}`,
        "gcp.audit.request_metadata.caller_ip": attackerIp,
        "gcp.audit.request_metadata.caller_supplied_user_agent": attackerUa,
        "gcp.audit.authorization_info.permission": "storage.objects.get",
        "gcp.audit.authorization_info.granted": "true",
        "gcp.audit.severity": "INFO",
        "gcp.project.id": projectId,
        "storage.bucket.name": bucket,
        "storage.object.name": "exports/2026-08-30/warehouse-000004.parquet",
        "cloud.provider": "gcp",
        "cloud.project.id": projectId,
        "cloud.region": region,
        "user.email": targetSa,
        "source.ip": attackerIp,
        "event.action": "storage.objects.get",
        "event.category": "file",
        "event.outcome": "success",
      },
    },
    {
      id: "gcpkey_065_get_objects",
      ts: T(9 * MIN + 100 * SEC),
      source: "cloud_gcp",
      vendor: "GCP Cloud Audit Logs",
      event_type: "cloud_api_call",
      user_email: targetSa,
      user_title: "Service Account",
      src_ip: attackerIp,
      severity: "critical",
      mitre_technique: "T1530",
      mitre_tactic: "Collection",
      incident_id: INCIDENT,
      description:
        "storage.objects.get on warehouse-000005.parquet by data-pipeline-sa from 185.129.62.66 under the minted key: the next object of the same prefix.",
      raw: {
        "gcp.audit.type": "type.googleapis.com/google.cloud.audit.AuditLog",
        "gcp.audit.log_name": `projects/${projectId}/logs/cloudaudit.googleapis.com%2Fdata_access`,
        "gcp.audit.service_name": "storage.googleapis.com",
        "gcp.audit.method_name": "storage.objects.get",
        "gcp.audit.resource_name": `projects/_/buckets/${bucket}/objects/exports/2026-08-30/warehouse-000005.parquet`,
        "gcp.audit.resource_type": "gcs_bucket",
        "gcp.audit.authentication_info.principal_email": targetSa,
        "gcp.audit.authentication_info.service_account_key_name": `//iam.googleapis.com/${mintedKeyResource}`,
        "gcp.audit.request_metadata.caller_ip": attackerIp,
        "gcp.audit.request_metadata.caller_supplied_user_agent": attackerUa,
        "gcp.audit.authorization_info.permission": "storage.objects.get",
        "gcp.audit.authorization_info.granted": "true",
        "gcp.audit.severity": "INFO",
        "gcp.project.id": projectId,
        "storage.bucket.name": bucket,
        "storage.object.name": "exports/2026-08-30/warehouse-000005.parquet",
        "cloud.provider": "gcp",
        "cloud.project.id": projectId,
        "cloud.region": region,
        "user.email": targetSa,
        "source.ip": attackerIp,
        "event.action": "storage.objects.get",
        "event.category": "file",
        "event.outcome": "success",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 7. SECRET PULL, the SA reads a Secret Manager secret version from the
    //    same external address: a warehouse connection string, a credential
    //    that unlocks the next system (T1555.006, Credentials from Password
    //    Stores: Cloud Secrets Management Stores).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "gcpkey_07_access_secret",
      user_email: targetSa,
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
        "AccessSecretVersion on secret prod-warehouse-dsn with principalEmail data-pipeline-sa from 185.129.62.66, the service account reading a stored warehouse connection string from outside the project's network.",
      raw: {
        "gcp.audit.type": "type.googleapis.com/google.cloud.audit.AuditLog",
        "gcp.audit.log_name": `projects/${projectId}/logs/cloudaudit.googleapis.com%2Fdata_access`,
        "gcp.audit.service_name": "secretmanager.googleapis.com",
        "gcp.audit.method_name": "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion",
        "gcp.audit.resource_name": `projects/${projectNum}/secrets/${secretName}/versions/4`,
        "gcp.audit.resource_type": "secretmanager.googleapis.com/SecretVersion",
        "gcp.audit.authentication_info.principal_email": targetSa,
        "gcp.audit.authentication_info.service_account_key_name": `//iam.googleapis.com/${mintedKeyResource}`,
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
    // 8. DETECTION #1, Event Threat Detection flags the key mint. Alert grade:
    //    a user-managed service-account key created by a developer identity from
    //    an anomalous location (T1098.001). Opens the incident.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "gcpkey_08_etd_key_finding",
      ts: T(15 * MIN),
      source: "cloud_gcp",
      vendor: "Google Security Command Center",
      event_type: "cloud_api_call", // cloud detections are typed as the API activity they flag (as GuardDuty findings are)
      user_email: devUser,
      src_ip: attackerIp,
      severity: "low",
      mitre_technique: "T1098.001",
      mitre_tactic: "Persistence",
      incident_id: INCIDENT,
      is_detection: true,
      edr_scope: "non_edr", // cloud control-plane only, no host process to walk
      description:
        "Event Threat Detection raised Persistence: Service Account Key Created (severity LOW) on data-pipeline-sa: a user-managed key was created by t.levy@rocketstack.io from 185.129.62.66.",
      raw: {
        // Security Command Center Pub/Sub notification: an Event Threat Detection Finding.
        "notificationConfigName": `organizations/${orgId}/notificationConfigs/scc-to-siem`,
        "finding.name": `organizations/${orgId}/sources/${etdSourceId}/findings/08${projectNum}`,
        "finding.parent": `organizations/${orgId}/sources/${etdSourceId}`,
        "finding.resourceName": `//iam.googleapis.com/projects/${projectId}/serviceAccounts/${targetSaUniqueId}`,
        "finding.state": "ACTIVE",
        "finding.category": "Persistence: Service Account Key Created",
        "finding.severity": "LOW",
        "finding.findingClass": "THREAT",
        "finding.eventTime": T(15 * MIN),
        "finding.createTime": T(15 * MIN),
        "finding.access.principalEmail": devUser,
        "finding.access.callerIp": attackerIp,
        "finding.access.callerIpGeo.regionCode": "NL",
        "finding.access.serviceName": "iam.googleapis.com",
        "finding.access.methodName": "google.iam.admin.v1.CreateServiceAccountKey",
        "finding.mitreAttack.primaryTactic": "PERSISTENCE",
        "finding.mitreAttack.primaryTechniques": ["ACCOUNT_MANIPULATION"],
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 9. DETECTION #2, Event Threat Detection flags the object drain as data
    //    leaving over the storage API from an anomalous location on the SA. The
    //    exfiltration finding, with an evidence bundle hash (T1567).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "gcpkey_09_etd_new_geography",
      ts: T(24 * MIN),
      source: "cloud_gcp",
      vendor: "Google Security Command Center",
      event_type: "cloud_api_call", // cloud detections are typed as the API activity they flag (as GuardDuty findings are)
      user_email: targetSa,
      src_ip: attackerIp,
      severity: "low",
      mitre_technique: "T1078.004",
      mitre_tactic: "Persistence",
      incident_id: INCIDENT,
      is_detection: true,
      edr_scope: "non_edr", // cloud control-plane only, no host process to walk
      description:
        "Event Threat Detection raised Persistence: New Geography (severity LOW) on data-pipeline-sa: the service account made calls from 185.129.62.66 in the Netherlands, a location it has never operated from.",
      raw: {
        // Security Command Center Pub/Sub notification: an Event Threat Detection Finding.
        "notificationConfigName": `organizations/${orgId}/notificationConfigs/scc-to-siem`,
        "finding.name": `organizations/${orgId}/sources/${etdSourceId}/findings/09${projectNum}`,
        "finding.parent": `organizations/${orgId}/sources/${etdSourceId}`,
        "finding.resourceName": `//iam.googleapis.com/projects/${projectId}/serviceAccounts/${targetSaUniqueId}`,
        "finding.state": "ACTIVE",
        "finding.category": "Persistence: New Geography",
        "finding.severity": "LOW",
        "finding.findingClass": "THREAT",
        "finding.eventTime": T(24 * MIN),
        "finding.createTime": T(24 * MIN),
        "finding.access.principalEmail": targetSa,
        "finding.access.callerIp": attackerIp,
        "finding.access.callerIpGeo.regionCode": "NL",
        "finding.access.serviceName": "storage.googleapis.com",
        "finding.access.methodName": "storage.objects.get",
        "finding.mitreAttack.primaryTactic": "PERSISTENCE",
        "finding.mitreAttack.primaryTechniques": ["VALID_ACCOUNTS"],
      },
    },
  ];

  return { title, events, B, T, MIN, SEC, INCIDENT, projectId, projectNum, region, bucket, secretName, targetSa, targetSaResource, mintedKeyId, mintedKeyResource, devUser, attackerIp, attackerUa, ciSa, ciSaResource, ciBuildIp, ciUa, orgId, etdSourceId, targetSaUniqueId };
}
