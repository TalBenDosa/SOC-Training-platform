/**
 * Events-only half of the ./azureManagedIdentityAbuse.ts scenario pack.
 *
 * The dashboard's live feed runs in the browser (attackStories.ts), so what it
 * imports ships in a public /_next/static chunk. The answer key (questions,
 * answers, explanations, IOCs, killchain, narrative) stays in the builder in
 * ./azureManagedIdentityAbuse.ts, which composes this module on the server. Keep anything
 * answer-bearing out of this file: every visitor can read it.
 */
import type { TelemetryEvent } from "@/lib/sim/types";

/** Telemetry half of the azureManagedIdentityAbuse scenario: the events and the story title, no answer key. */
export function azureManagedIdentityAbuseScenarioEvents() {
  const title = "Azure App-Registration Credential Abuse — the Quiet Secret-Add Behind a Cloud Data-Access Alert";
  const B = new Date("2026-08-29T01:12:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const SEC = 1_000;

  // One incident — the whole cloud chain is a single case.
  const INCIDENT = "inc:amia:1";

  // Tenant / directory identifiers.
  const tenantId = "8b1e9d42-5a7c-4f30-9c21-6de0f4a7b3c8";
  const subId = "2c4e6a80-1f3b-4d59-8e07-9a1c5b2d6f43";
  const subName = "prod-analytics-sub";
  const resourceGroup = "rg-billing-prod";

  // The abused, over-permissioned app registration / service principal. It is a
  // legitimate production integration that already holds Contributor on the
  // subscription and access to the billing Key Vault — exactly the identity an
  // operator wants to borrow.
  const app = {
    displayName: "svc-billing-connector",
    appId: "d94a6f21-3b8e-4c17-a5d2-9f0e1c7b4a63",       // client / application id
    spId: "5f2c7a19-0d4b-4e83-9a61-7c3e8b5d2f04",         // service principal object id
    appObjectId: "1a7d3e90-6c22-4b58-8f14-2e9a0b7c5d31",  // app registration object id
  };
  // The attacker-appended client secret (its keyId, as recorded in the audit log).
  const newKeyId = "b7e42c8a-19f6-4d03-a5e1-8c2b9f7d0e63";

  // The compromised workload identity that appends the secret. It holds an
  // application-write permission and is driven from the attacker's address.
  const workloadMi = {
    displayName: "webjob-ingest-prod",
    spId: "9d0c1a54-2f7b-4e60-8c39-1a5b7d2e6f08",
  };

  // The attacker's external address — appears on the credential-add, the SP
  // sign-ins, and every Azure Activity operation.
  const attackerIp = "45.155.205.211";

  // The Key Vault and Storage account the identity reaches.
  const keyVault = "kv-billing-prod";
  const storageAccount = "stbillingprod01";

  // The benign control: a platform engineer rotating the CI/CD Terraform SP's
  // secret through an approved change. Same operation, opposite verdict.
  const engineer = { user: "d.almeida@nexacorp.com", title: "Platform Engineer" };
  const terraformSp = {
    displayName: "sp-terraform-cicd",
    appId: "6f2b8c14-7a90-4d3e-9b52-0c8a1f6d4e27",
    spId: "3a9e5d70-1c62-4f84-8a05-7b2d9c1e6f43",
  };
  const ciRunnerIp = "13.107.42.14"; // Azure DevOps hosted-agent egress (known automation)

  const events: TelemetryEvent[] = [
    // ─────────────────────────────────────────────────────────────────────
    // 0. BENIGN CONTROL — a sanctioned client-secret rotation.
    //    The SAME "Add service principal credentials" operation as the attack,
    //    but by a named engineer, on the CI/CD Terraform SP, from the known
    //    pipeline runner, under an approved change. This is the comparison case.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "amia_00_benign_rotation",
      ts: "2026-08-27T14:20:00.000Z",
      source: "o365",
      vendor: "Microsoft Entra ID",
      event_type: "account_modify",
      user_email: engineer.user,
      user_title: engineer.title,
      src_ip: ciRunnerIp,
      severity: "informational",
      expected_verdict: "fp",
      mitre_technique: "T1098.001",
      mitre_tactic: "Persistence",
      it_verify_result: "confirmed",
      it_verify_message:
        "Change CHG-2211: quarterly rotation of the Terraform CI/CD service-principal secret, approved and executed by Platform Engineering.",
      description:
        "Platform engineer d.almeida added a new client secret to the CI/CD Terraform service principal sp-terraform-cicd from the Azure DevOps hosted-agent address, under approved change CHG-2211.",
      fp_explanation:
        "This is the control case for the whole scenario — a legitimate secret rotation that has the identical audit shape to the attack. Three attributes make it sanctioned. The Actor is a named human (d.almeida) on a recorded change (CHG-2211), not a workload identity. The ActorIpAddress is the known Azure DevOps hosted-agent egress the billing pipeline always uses. And the target is sp-terraform-cicd, the SP whose secret Platform Engineering rotates every quarter. The intrusion later runs the SAME 'Add service principal credentials' operation, but its actor is a workload identity, its address is unfamiliar, and there is no change behind it. An analyst who alerts on 'a secret was added to an app' alone will flag this and be wrong.",
      raw: {
        // O365 Unified Audit Log + Entra ID Audit Log — Add service principal credentials
        "data.office365.Id": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
        "data.office365.RecordType": "8",
        "data.office365.CreationTime": "2026-08-27T14:20:00Z",
        "data.office365.Operation": "Add service principal credentials.",
        "data.office365.Workload": "AzureActiveDirectory",
        "data.office365.AzureActiveDirectoryEventType": "1",
        "data.office365.ResultStatus": "Success",
        "data.office365.UserId": engineer.user,
        "data.office365.UserType": "0",
        "data.office365.ActorIpAddress": ciRunnerIp,
        "data.office365.Actor.ID": engineer.user,
        "data.office365.Actor.Type": "5",
        "data.office365.Target.ID": terraformSp.spId,
        "data.office365.Target.Type": "2",
        "data.office365.ObjectId": terraformSp.appId,
        "data.office365.OrganizationId": tenantId,
        "data.office365.ApplicationId": "1b730954-1685-4b74-9bfd-dac224a7b894",
        "data.office365.ServicePrincipalId": terraformSp.spId,
        "data.office365.ModifiedProperties":
          '[{"Name":"KeyDescription","NewValue":"[KeyIdentifier=1f0a7c3e-58b2-4d91-a6e4-0c9b2f7d3a18,KeyType=Password,KeyUsage=Verify,DisplayName=terraform-cicd-2026Q3]"}]',
        "azure.auditlogs.operationName": "Add service principal credentials.",
        "azure.auditlogs.category": "ApplicationManagement",
        "azure.auditlogs.result_signature": "Success",
        "azure.auditlogs.identity": engineer.user,
        "azure.auditlogs.target_resources.display_name": terraformSp.displayName,
        "azure.auditlogs.target_resources.type": "ServicePrincipal",
        "azure.auditlogs.target_resources.id": terraformSp.spId,
        "GeoLocation.country_name": "United States",
        "GeoLocation.city_name": "Washington",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 1. THE QUIET PIVOT — a new client secret is appended to the existing,
    //    over-permissioned app registration svc-billing-connector. Stealthy
    //    persistence: no new app, no consent. Driven by the compromised
    //    workload identity from the attacker's address (T1098.001).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "amia_01_add_sp_credential",
      ts: T(0),
      source: "o365",
      vendor: "Microsoft Entra ID",
      event_type: "account_modify",
      src_ip: attackerIp,
      severity: "high",
      mitre_technique: "T1098.001",
      mitre_tactic: "Persistence",
      incident_id: INCIDENT,
      description:
        "A new client secret was appended to the existing app registration svc-billing-connector. The 'Add service principal credentials' record shows it was initiated by an application, the workload identity webjob-ingest-prod, not by the pipeline or the engineers who own svc-billing-connector.",
      raw: {
        "data.office365.Id": "c3d4e5f6-a1b2-4c3d-8e5f-6a1b2c3d4e5f",
        "data.office365.RecordType": "8",
        "data.office365.CreationTime": "2026-08-29T01:12:00Z",
        "data.office365.Operation": "Add service principal credentials.",
        "data.office365.Workload": "AzureActiveDirectory",
        "data.office365.AzureActiveDirectoryEventType": "1",
        "data.office365.ResultStatus": "Success",
        "data.office365.UserId": `${workloadMi.displayName}@${tenantId}`,
        "data.office365.UserType": "4",
        "data.office365.ActorIpAddress": attackerIp,
        "data.office365.Actor.ID": workloadMi.spId,
        "data.office365.Actor.Type": "2",
        "data.office365.Target.ID": app.spId,
        "data.office365.Target.Type": "2",
        "data.office365.ObjectId": app.appId,
        "data.office365.OrganizationId": tenantId,
        "data.office365.ServicePrincipalId": app.spId,
        "data.office365.ModifiedProperties":
          `[{"Name":"KeyDescription","NewValue":"[KeyIdentifier=${newKeyId},KeyType=Password,KeyUsage=Verify,DisplayName=extension]"}]`,
        "data.office365.ExtendedProperties.Name": "additionalDetails",
        "data.office365.ExtendedProperties.Value": `{"appId":"${app.appId}"}`,
        "azure.auditlogs.operationName": "Add service principal credentials.",
        "azure.auditlogs.category": "ApplicationManagement",
        "azure.auditlogs.result_signature": "Success",
        "azure.auditlogs.identity": workloadMi.displayName,
        "azure.auditlogs.properties.initiatedBy.app.displayName": workloadMi.displayName,
        "azure.auditlogs.target_resources.display_name": app.displayName,
        "azure.auditlogs.target_resources.type": "ServicePrincipal",
        "azure.auditlogs.target_resources.id": app.spId,
        "GeoLocation.country_name": "Netherlands",
        "GeoLocation.city_name": "Amsterdam",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 2. NON-INTERACTIVE SP SIGN-IN TO MICROSOFT GRAPH — the freshly-added
    //    secret is used. ServicePrincipalSignInLogs, no user, no MFA, no
    //    interactivity (T1078.004).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "amia_02_sp_signin_graph",
      ts: T(3 * MIN),
      source: "o365",
      vendor: "Microsoft Entra ID",
      event_type: "auth_success",
      src_ip: attackerIp,
      severity: "high",
      mitre_technique: "T1078.004",
      mitre_tactic: "Stealth",
      incident_id: INCIDENT,
      description:
        "svc-billing-connector authenticated to Microsoft Graph as a service principal from 45.155.205.211. The sign-in is non-interactive, presents a client secret, and carries no user and no MFA.",
      authentication: { method: "clientSecret", result: "success" },
      cloud: { provider: "Microsoft", service: "Microsoft Graph", api_call: "token", region: "global", resource: "Microsoft Graph" },
      raw: {
        "azure.signinlogs.category": "ServicePrincipalSignInLogs",
        "azure.signinlogs.operationName": "Sign-in activity",
        "azure.signinlogs.resultType": "0",
        "azure.signinlogs.result_description": "Success",
        "azure.signinlogs.correlation_id": "d4e5f6a1-b2c3-4d4e-8f6a-1b2c3d4e5f6a",
        "azure.signinlogs.service_principal_id": app.spId,
        "azure.signinlogs.service_principal_name": app.displayName,
        "azure.signinlogs.app_id": app.appId,
        "azure.signinlogs.resource_display_name": "Microsoft Graph",
        "azure.signinlogs.resource_identity": "00000003-0000-0000-c000-000000000000",
        "azure.signinlogs.token_issuer_type": "AzureAD",
        "azure.signinlogs.credential_type": "ClientSecret",
        "azure.signinlogs.service_principal_credential_key_id": newKeyId,
        "azure.signinlogs.is_interactive": "false",
        "azure.signinlogs.conditional_access_status": "notApplied",
        "azure.signinlogs.ip_address": attackerIp,
        "azure.signinlogs.tenant_id": tenantId,
        "GeoLocation.country_name": "Netherlands",
        "GeoLocation.city_name": "Amsterdam",
        "GeoLocation.latitude": "52.3702",
        "GeoLocation.longitude": "4.8952",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 3. NON-INTERACTIVE SP SIGN-IN TO AZURE RESOURCE MANAGER — the same
    //    identity acquires a management-plane token (T1078.004).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "amia_03_sp_signin_arm",
      ts: T(4 * MIN),
      source: "o365",
      vendor: "Microsoft Entra ID",
      event_type: "auth_success",
      src_ip: attackerIp,
      severity: "high",
      mitre_technique: "T1078.004",
      mitre_tactic: "Stealth",
      incident_id: INCIDENT,
      description:
        "svc-billing-connector acquired a token for the Azure Resource Manager API (Windows Azure Service Management API) from the same address, again as a non-interactive service-principal sign-in.",
      authentication: { method: "clientSecret", result: "success" },
      cloud: { provider: "Microsoft", service: "Azure Resource Manager", api_call: "token", region: "global", resource: "Windows Azure Service Management API" },
      raw: {
        "azure.signinlogs.category": "ServicePrincipalSignInLogs",
        "azure.signinlogs.operationName": "Sign-in activity",
        "azure.signinlogs.resultType": "0",
        "azure.signinlogs.result_description": "Success",
        "azure.signinlogs.correlation_id": "e5f6a1b2-c3d4-4e5f-8a1b-2c3d4e5f6a1b",
        "azure.signinlogs.service_principal_id": app.spId,
        "azure.signinlogs.service_principal_name": app.displayName,
        "azure.signinlogs.app_id": app.appId,
        "azure.signinlogs.resource_display_name": "Windows Azure Service Management API",
        "azure.signinlogs.resource_identity": "797f4846-ba00-4fd7-ba43-dac1f8f63013",
        "azure.signinlogs.token_issuer_type": "AzureAD",
        "azure.signinlogs.credential_type": "ClientSecret",
        "azure.signinlogs.service_principal_credential_key_id": newKeyId,
        "azure.signinlogs.is_interactive": "false",
        "azure.signinlogs.conditional_access_status": "notApplied",
        "azure.signinlogs.ip_address": attackerIp,
        "azure.signinlogs.tenant_id": tenantId,
        "GeoLocation.country_name": "Netherlands",
        "GeoLocation.city_name": "Amsterdam",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 4. SUBSCRIPTION ENUMERATION — Azure Activity read operations mapping the
    //    subscription and its resource groups (T1526).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "amia_04_subscription_enum",
      ts: T(6 * MIN),
      source: "cloud_azure",
      vendor: "Azure Activity Log",
      event_type: "cloud_api_call",
      src_ip: attackerIp,
      severity: "medium",
      mitre_technique: "T1526",
      mitre_tactic: "Discovery",
      incident_id: INCIDENT,
      description:
        "The svc-billing-connector token was used to list the subscription and its resource groups in prod-analytics-sub — Microsoft.Resources/subscriptions/resourceGroups/read from 45.155.205.211.",
      cloud: { provider: "Microsoft", service: "Azure Resource Manager", api_call: "Microsoft.Resources/subscriptions/resourceGroups/read", region: "westeurope", resource: subName },
      raw: {
        "azure.activitylogs.operationName": "Microsoft.Resources/subscriptions/resourceGroups/read",
        "azure.activitylogs.event_category": "Administrative",
        "azure.activitylogs.resultType": "Success",
        "azure.activitylogs.resultSignature": "Succeeded.OK",
        "azure.activitylogs.callerIpAddress": attackerIp,
        "azure.activitylogs.identity.claims.appid": app.appId,
        "azure.activitylogs.identity.claims.objectidentifier": app.spId,
        "azure.activitylogs.identity.authorization.evidence.role": "Contributor",
        "azure.activitylogs.identity.authorization.evidence.principalType": "ServicePrincipal",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 5. ROLE ASSIGNMENT WRITE — the identity grants a standing role, turning a
    //    borrowed token into durable access (T1098.003).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "amia_05_role_assignment",
      ts: T(9 * MIN),
      source: "cloud_azure",
      vendor: "Azure Activity Log",
      event_type: "role_assignment",
      src_ip: attackerIp,
      severity: "critical",
      mitre_technique: "T1098.003",
      mitre_tactic: "Persistence",
      incident_id: INCIDENT,
      description:
        "A Microsoft.Authorization/roleAssignments/write assigned the Key Vault Secrets Officer role to svc-billing-connector at the rg-billing-prod scope — the identity granting itself standing access to the vault.",
      cloud: { provider: "Microsoft", service: "Azure RBAC", api_call: "Microsoft.Authorization/roleAssignments/write", region: "westeurope", resource: resourceGroup },
      raw: {
        "azure.activitylogs.operationName": "Microsoft.Authorization/roleAssignments/write",
        "azure.activitylogs.event_category": "Administrative",
        "azure.activitylogs.resultType": "Success",
        "azure.activitylogs.resultSignature": "Succeeded.OK",
        "azure.activitylogs.callerIpAddress": attackerIp,
        "azure.activitylogs.identity.claims.appid": app.appId,
        "azure.activitylogs.identity.claims.objectidentifier": app.spId,
        "azure.resource.group": resourceGroup,
        "azure.resource.provider": "Microsoft.Authorization",
        "azure.resource.name": "roleAssignments/5c3d8b2f-0a1e-4b4c-9f32-7d8e3a2b1c44",
        "azure.activitylogs.identity.authorization.evidence.role": "Contributor",
        "azure.activitylogs.identity.authorization.evidence.principalType": "ServicePrincipal",
        // The role granted (Key Vault Secrets Officer) and to whom, as the request body records it.
        "azure.activitylogs.properties.requestbody":
          `{"Id":"5c3d8b2f-0a1e-4b4c-9f32-7d8e3a2b1c44","Properties":{"PrincipalId":"${app.spId}","PrincipalType":"ServicePrincipal","RoleDefinitionId":"/providers/Microsoft.Authorization/roleDefinitions/b86a8fe4-44ce-4948-aee5-eccb2c155cd7","Scope":"/subscriptions/{subscriptionId}/resourceGroups/${resourceGroup}"}}`,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 6. KEY VAULT SECRET READ — data-plane retrieval of a stored secret
    //    (T1555.006 — Cloud Secrets Management Stores).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "amia_06_keyvault_secret_read",
      ts: T(12 * MIN),
      source: "cloud_azure",
      vendor: "Azure Activity Log",
      event_type: "cloud_api_call",
      src_ip: attackerIp,
      severity: "critical",
      mitre_technique: "T1555.006",
      mitre_tactic: "Credential Access",
      incident_id: INCIDENT,
      description:
        "A Microsoft.KeyVault/vaults/secrets/read retrieved the secret 'sql-conn-prod' from the vault kv-billing-prod, by svc-billing-connector from 45.155.205.211.",
      cloud: { provider: "Microsoft", service: "Key Vault", api_call: "Microsoft.KeyVault/vaults/secrets/read", region: "westeurope", resource: keyVault },
      raw: {
        "azure.activitylogs.operationName": "Microsoft.KeyVault/vaults/secrets/read",
        "azure.activitylogs.event_category": "Administrative",
        "azure.activitylogs.resultType": "Success",
        "azure.activitylogs.resultSignature": "Succeeded.OK",
        "azure.activitylogs.callerIpAddress": attackerIp,
        "azure.activitylogs.identity.claims.appid": app.appId,
        "azure.activitylogs.identity.claims.objectidentifier": app.spId,
        "azure.resource.group": resourceGroup,
        "azure.resource.provider": "Microsoft.KeyVault",
        "azure.resource.name": `vaults/${keyVault}/secrets/sql-conn-prod`,
        "azure.activitylogs.identity.authorization.evidence.role": "Key Vault Secrets Officer",
        "azure.activitylogs.identity.authorization.evidence.principalType": "ServicePrincipal",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 7. STORAGE ACCOUNT KEY LISTING — the identity lists the account keys for
    //    stbillingprod01, the keys that open its blob data (T1530).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "amia_07_storage_listkeys",
      ts: T(15 * MIN),
      source: "cloud_azure",
      vendor: "Azure Activity Log",
      event_type: "cloud_storage_access",
      src_ip: attackerIp,
      severity: "critical",
      mitre_technique: "T1530",
      mitre_tactic: "Collection",
      incident_id: INCIDENT,
      description:
        "A Microsoft.Storage/storageAccounts/listKeys/action returned the access keys for the storage account stbillingprod01 — the keys that grant direct read of its blob containers.",
      cloud: { provider: "Microsoft", service: "Azure Storage", api_call: "Microsoft.Storage/storageAccounts/listKeys/action", region: "westeurope", resource: storageAccount },
      raw: {
        "azure.activitylogs.operationName": "Microsoft.Storage/storageAccounts/listKeys/action",
        "azure.activitylogs.event_category": "Administrative",
        "azure.activitylogs.resultType": "Success",
        "azure.activitylogs.resultSignature": "Succeeded.OK",
        "azure.activitylogs.callerIpAddress": attackerIp,
        "azure.activitylogs.identity.claims.appid": app.appId,
        "azure.activitylogs.identity.claims.objectidentifier": app.spId,
        "azure.resource.group": resourceGroup,
        "azure.resource.provider": "Microsoft.Storage",
        "azure.resource.name": `storageAccounts/${storageAccount}`,
        "azure.activitylogs.identity.authorization.evidence.role": "Contributor",
        "azure.activitylogs.identity.authorization.evidence.principalType": "ServicePrincipal",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 8. THE CORROBORATING ALERT — a Microsoft Graph Security incident ties the
    //    non-interactive service-principal sign-ins to the vault and storage
    //    access. This is the alert-grade row that opens the ticket. Control
    //    plane only → edr_scope "non_edr": there is no host to pivot to.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "amia_08_graph_incident",
      ts: T(22 * MIN),
      source: "cloud_azure",
      vendor: "Microsoft Graph Security",
      event_type: "ueba_anomaly",
      severity: "critical",
      mitre_technique: "T1098.001",
      mitre_tactic: "Persistence",
      incident_id: INCIDENT,
      is_detection: true,   // the alert-grade detection that opens the incident
      edr_scope: "non_edr", // control-plane only — no endpoint, no process tree to walk
      description:
        "Microsoft Graph Security raised an incident for svc-billing-connector: an application credential was added, then the identity signed in non-interactively from a new location and reached Key Vault and Storage in prod-analytics-sub.",
      raw: {
        "data.ms-graph.id": "3f7a1e88-6b20-4c95-9d13-8e0a2c4b7f61",
        "data.ms-graph.displayName":
          "Service principal added credentials and accessed subscription resources",
        "data.ms-graph.severity": "high",
        "data.ms-graph.status": "inProgress",
        "data.ms-graph.classification": "unknown",
        "data.ms-graph.determination": "unknown",
        "data.ms-graph.createdDateTime": "2026-08-29T01:34:00Z",
        "data.ms-graph.lastUpdateDateTime": "2026-08-29T01:34:20Z",
        "data.ms-graph.tenantId": tenantId,
        "data.ms-graph.incidentWebUrl":
          "https://security.microsoft.com/incidents/inc-2026-0829-4471",
        "data.ms-graph.resource": app.displayName,
        "data.ms-graph.systemTags": "ServicePrincipal;NewCredential;NonInteractiveSignIn;KeyVaultAccess",
        "data.ms-graph.comments": "Correlated Entra audit, service-principal sign-in and Azure Activity signals.",
        "rule.description": "Application credential added followed by resource access from a new location",
        "rule.groups": "azure,entra_id,service_principal",
      },
    },
  ];

  return { title, events, B, T, MIN, SEC, INCIDENT, tenantId, subId, subName, resourceGroup, app, newKeyId, workloadMi, attackerIp, keyVault, storageAccount, engineer, terraformSp, ciRunnerIp };
}
