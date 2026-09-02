/**
 * Scenario pack: "Azure App-Registration Credential Abuse — a Quiet Secret-Add
 * that a Later Data-Access Alert Traces Back To"
 *
 * ADVANCED tier. A cloud-only privilege-escalation intrusion with NO host
 * telemetry — there is no endpoint to isolate and no process tree to walk. The
 * whole case lives in three control-plane logs: the Microsoft Entra ID audit and
 * sign-in logs, the Azure Activity (Azure Monitor) log, and a corroborating
 * Microsoft Graph Security incident.
 *
 * THE FOOTHOLD IS OUT OF SCOPE. The attacker already controls a workload whose
 * managed identity (a service principal) holds a permission to write application
 * credentials in the tenant. What they do with it is the exercise. The quiet
 * pivot is a single Entra audit line — "Add service principal credentials" — that
 * appends a new client secret to an EXISTING, over-permissioned app registration,
 * svc-billing-connector, which already carries Contributor on the prod
 * subscription and access to its Key Vault. That one secret-add is stealthy
 * persistence: no new app is registered, no consent prompt fires, nothing looks
 * created. Minutes later the same identity authenticates non-interactively to
 * Microsoft Graph and to Azure Resource Manager, enumerates the subscription,
 * grants itself a role, and reads Key Vault secrets and Storage account keys.
 *
 * THE TEACHING SPINE: the loud event is the data access (Key Vault / Storage);
 * the event that EXPLAINS it is the earlier credential-add. An analyst who starts
 * at the data-access alert has to walk BACKWARD to the Entra audit log to find how
 * a billing-pipeline identity came to be signing in from an unfamiliar address at
 * all. The credential-add is the join.
 *
 * THE BENIGN CONTROL (evt 0): a platform engineer rotating the client secret of
 * the CI/CD Terraform service principal through an approved change window. It is
 * the SAME operation — "Add service principal credentials" — with the opposite
 * verdict. The discriminators are actor provenance (a named human on an approved
 * change vs a workload identity driven from an unfamiliar address), the source
 * address, and whether a change record exists — NOT the operation name, which is
 * identical in both.
 *
 * SOURCES (only three registry vendors): azure-ad (Microsoft Entra ID — audit
 * "Add service principal credentials" and service-principal sign-in logs),
 * azure-monitor (Azure Activity Log — role assignment, Key Vault and Storage
 * data-plane operations, subscription enumeration), microsoft-graph-security (the
 * corroborating security incident that opens the ticket).
 *
 * NOTE: register in scenarios.ts with difficulty "advanced". The ScenarioBundle
 * itself carries no difficulty field.
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";

export function buildAzureManagedIdentityAbuseScenario(
  scenarioId = "azure-managed-identity-abuse-2026",
): ScenarioBundle {
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
          '[{"Name":"KeyDescription","NewValue":"[KeyIdentifier=1f0a...;KeyType=Password;KeyUsage=Verify;DisplayName=terraform-cicd-2026Q3]"}]',
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
        "A new client secret was appended to the existing app registration svc-billing-connector. The 'Add service principal credentials' record shows the actor is the workload identity webjob-ingest-prod, from 45.155.205.211 — not the pipeline that owns the app.",
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
          `[{"Name":"KeyDescription","NewValue":"[KeyIdentifier=${newKeyId};KeyType=Password;KeyUsage=Verify;DisplayName=extension]"}]`,
        "data.office365.ExtendedProperties.Name": "additionalDetails",
        "data.office365.ExtendedProperties.Value": `{"appId":"${app.appId}"}`,
        "azure.auditlogs.operationName": "Add service principal credentials.",
        "azure.auditlogs.category": "ApplicationManagement",
        "azure.auditlogs.result_signature": "Success",
        "azure.auditlogs.identity": workloadMi.displayName,
        "azure.auditlogs.initiated_by.app.appId": workloadMi.spId,
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
      mitre_tactic: "Defense Evasion",
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
      mitre_tactic: "Defense Evasion",
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
        "azure.operation.name": "Microsoft.Resources/subscriptions/resourceGroups/read",
        "azure.result_type": "Success",
        "azure.subscription.id": subId,
        "azure.tenant.id": tenantId,
        "azure.activitylogs.category": "Administrative",
        "azure.activitylogs.identity_name": app.displayName,
        "azure.activitylogs.identity_claim_appid": app.appId,
        "azure.activitylogs.properties.principalId": app.spId,
        "azure.activitylogs.properties.principalType": "ServicePrincipal",
        "event.action": "Microsoft.Resources/subscriptions/resourceGroups/read",
        "event.category": "administrative",
        "event.outcome": "success",
        "cloud.provider": "Azure",
        "cloud.region": "westeurope",
        "cloud.resource.type": "Microsoft.Resources/subscriptions/resourceGroups",
        "source.ip": attackerIp,
        "user.id": app.spId,
        "user.name": app.displayName,
        "user.type": "ServicePrincipal",
        "threat.technique.id": "T1526",
        "threat.technique.name": "Cloud Service Discovery",
        "threat.tactic.name": "Discovery",
        "threat.tactic.id": "TA0007",
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
        "azure.operation.name": "Microsoft.Authorization/roleAssignments/write",
        "azure.result_type": "Success",
        "azure.subscription.id": subId,
        "azure.tenant.id": tenantId,
        "azure.resource.group": resourceGroup,
        "azure.activitylogs.category": "Administrative",
        "azure.activitylogs.identity_name": app.displayName,
        "azure.activitylogs.identity_claim_appid": app.appId,
        "azure.activitylogs.properties.principalId": app.spId,
        "azure.activitylogs.properties.principalType": "ServicePrincipal",
        "azure.activitylogs.properties.roleDefinitionId":
          `/subscriptions/${subId}/providers/Microsoft.Authorization/roleDefinitions/b86a8fe4-44ce-4948-aee5-eccb2c155cd7`,
        "azure.activitylogs.properties.scope":
          `/subscriptions/${subId}/resourceGroups/${resourceGroup}`,
        "event.action": "Microsoft.Authorization/roleAssignments/write",
        "event.category": "authorization",
        "event.outcome": "success",
        "iam.role.name": "Key Vault Secrets Officer",
        "iam.action": "Microsoft.Authorization/roleAssignments/write",
        "cloud.provider": "Azure",
        "cloud.region": "westeurope",
        "cloud.resource.type": "Microsoft.Authorization/roleAssignments",
        "cloud.resource.name": resourceGroup,
        "source.ip": attackerIp,
        "user.id": app.spId,
        "user.name": app.displayName,
        "user.type": "ServicePrincipal",
        "user.target.name": app.displayName,
        "threat.technique.id": "T1098.003",
        "threat.technique.name": "Account Manipulation: Additional Cloud Roles",
        "threat.tactic.name": "Persistence",
        "threat.tactic.id": "TA0003",
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
      vendor: "Azure Monitor",
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
        "azure.operation.name": "Microsoft.KeyVault/vaults/secrets/read",
        "azure.result_type": "Success",
        "azure.subscription.id": subId,
        "azure.tenant.id": tenantId,
        "azure.resource.group": resourceGroup,
        "azure.activitylogs.category": "DataPlaneRequest",
        "azure.activitylogs.identity_claim_appid": app.appId,
        "azure.activitylogs.properties.id":
          `https://${keyVault}.vault.azure.net/secrets/sql-conn-prod`,
        "event.action": "Microsoft.KeyVault/vaults/secrets/read",
        "event.category": "dataplane",
        "event.outcome": "success",
        "cloud.provider": "Azure",
        "cloud.region": "westeurope",
        "cloud.resource.type": "Microsoft.KeyVault/vaults",
        "cloud.resource.name": keyVault,
        "source.ip": attackerIp,
        "user.id": app.spId,
        "user.name": app.displayName,
        "user.type": "ServicePrincipal",
        "threat.technique.id": "T1555.006",
        "threat.technique.name": "Credentials from Password Stores: Cloud Secrets Management Stores",
        "threat.tactic.name": "Credential Access",
        "threat.tactic.id": "TA0006",
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
        "azure.operation.name": "Microsoft.Storage/storageAccounts/listKeys/action",
        "azure.result_type": "Success",
        "azure.subscription.id": subId,
        "azure.tenant.id": tenantId,
        "azure.resource.group": resourceGroup,
        "azure.activitylogs.category": "Administrative",
        "azure.activitylogs.identity_name": app.displayName,
        "azure.activitylogs.identity_claim_appid": app.appId,
        "azure.activitylogs.properties.resource": storageAccount,
        "event.action": "Microsoft.Storage/storageAccounts/listKeys/action",
        "event.category": "administrative",
        "event.outcome": "success",
        "cloud.provider": "Azure",
        "cloud.region": "westeurope",
        "cloud.resource.type": "Microsoft.Storage/storageAccounts",
        "cloud.resource.name": storageAccount,
        "storage.bucket.name": storageAccount,
        "source.ip": attackerIp,
        "user.id": app.spId,
        "user.name": app.displayName,
        "user.type": "ServicePrincipal",
        "threat.technique.id": "T1530",
        "threat.technique.name": "Data from Cloud Storage",
        "threat.tactic.name": "Collection",
        "threat.tactic.id": "TA0009",
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

  const iocs: IOC[] = [
    {
      type: "ip",
      value: attackerIp, // 45.155.205.211 — drives the credential-add, sign-ins and Azure operations
      first_seen: T(0),
      last_seen: T(22 * MIN),
      reputation: "malicious",
      tags: ["external", "sign-in-source", "control-plane"],
    },
    {
      type: "user",
      value: app.displayName, // svc-billing-connector — the borrowed, over-permissioned identity
      first_seen: T(0),
      last_seen: T(15 * MIN),
      reputation: "suspicious",
      tags: ["service-principal", "over-permissioned", "affected-identity"],
    },
    {
      type: "user",
      value: app.appId, // the app (client) id of the abused registration
      first_seen: T(0),
      last_seen: T(15 * MIN),
      reputation: "suspicious",
      tags: ["app-registration", "client-id"],
    },
    {
      type: "user",
      value: workloadMi.spId, // webjob-ingest-prod — the compromised workload identity that added the secret
      first_seen: T(0),
      last_seen: T(0),
      reputation: "suspicious",
      tags: ["workload-identity", "actor", "application-writer"],
    },
    {
      type: "user",
      value: newKeyId, // the attacker-added client-secret keyId
      first_seen: T(0),
      last_seen: T(22 * MIN),
      reputation: "malicious",
      tags: ["added-secret", "key-id", "persistence"],
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "amia_q1",
      xp: 55,
      kind: "single",
      prompt:
        "The alert that opened the ticket is the data access to Key Vault and Storage. Reading backward, which earlier event is the one that EXPLAINS how svc-billing-connector came to be signing in from an unfamiliar address at all?",
      hint: "The identity had to gain a usable authentication factor before it could sign in. Which audit line gave it one?",
      options: [
        { value: "cred_add", label: "amia_01 — 'Add service principal credentials' appended a new client secret to the svc-billing-connector app registration" },
        { value: "role", label: "amia_05 — the roleAssignments/write that granted the Key Vault Secrets Officer role at the resource-group scope" },
        { value: "graph_signin", label: "amia_02 — the non-interactive service-principal sign-in to Microsoft Graph from the new address" },
        { value: "subenum", label: "amia_04 — the subscriptions/resourceGroups/read that enumerated the prod-analytics subscription" },
      ],
      answer: "cred_add",
      explanation:
        "A service principal can only sign in if it holds a usable credential. amia_01 is where the intruder gave it one — a new client secret appended to the EXISTING app registration through 'Add service principal credentials'. That is the quiet pivot: no new app is registered and no consent prompt fires, so nothing looks created, yet from that moment the identity can authenticate from anywhere. Every later step — the sign-ins, the role grant, the vault and storage reads — depends on it. The role assignment (amia_05) widened what the identity could do but came after it was already signing in. The Graph sign-in (amia_02) is the first USE of the secret, not its origin. The subscription enumeration (amia_04) is downstream reconnaissance. The credential-add is the join that ties the loud data-access alert back to a cause.",
    },
    {
      id: "amia_q2",
      xp: 65,
      kind: "single",
      prompt:
        "The benign control (amia_00) and the intrusion's pivot (amia_01) are BOTH the 'Add service principal credentials' operation with ResultStatus Success. Which combination of fields separates the malicious one from the sanctioned rotation?",
      hint: "Compare the Actor type and identity, the ActorIpAddress, and whether a change record backs each one.",
      options: [
        { value: "actor_ip_change", label: "The actor is a workload identity (Actor.Type 2) from an unfamiliar address, and no change record backs it — the benign one is a named engineer from the known pipeline runner under CHG-2211" },
        { value: "operation", label: "The malicious record uses a different Operation value, which is how the audit log flags an unauthorized credential add" },
        { value: "result", label: "The malicious record carries ResultStatus Failure, showing the tenant rejected the credential before it could be used" },
        { value: "target_app", label: "Only the malicious record targets an app registration at all; the benign rotation modifies a user account, not a service principal" },
      ],
      answer: "actor_ip_change",
      explanation:
        "The operation is identical in both — that is the whole point, and why the Operation value proves nothing on its own. The discriminators are provenance and authorization. In amia_00 the Actor is a named human (d.almeida) on a recorded change (CHG-2211), from the Azure DevOps hosted-agent address the billing pipeline always uses. In amia_01 the Actor is the workload identity webjob-ingest-prod (Actor.Type 2, a service principal), from 45.155.205.211, with no change behind it. (b) is false — both read 'Add service principal credentials.'; there is no separate 'unauthorized' operation. (c) is false — the malicious record is ResultStatus Success; it worked. (d) is false — both target service principals; the benign one modifies sp-terraform-cicd.",
    },
    {
      id: "amia_q3",
      xp: 60,
      kind: "single",
      prompt:
        "Events amia_02 and amia_03 are sign-ins for svc-billing-connector. Which fields establish that these are service-principal (application) sign-ins rather than a user logging in?",
      hint: "Look at the sign-in log category, whether a user or a service_principal_id is present, and the interactivity flag.",
      options: [
        { value: "sp_category", label: "The category is ServicePrincipalSignInLogs, the records carry a service_principal_id and app_id with no user, and is_interactive is false" },
        { value: "mfa_fail", label: "The records show an MFA challenge that was satisfied, which only application sign-ins can perform" },
        { value: "user_upn", label: "They carry a user_principal_name ending in the tenant domain, which is the marker of an application identity" },
        { value: "conditional", label: "conditional_access_status is 'success', proving a Conditional Access policy evaluated an interactive user session" },
      ],
      answer: "sp_category",
      explanation:
        "Service-principal sign-ins are logged in their own category, ServicePrincipalSignInLogs, distinct from interactive and non-interactive USER sign-ins. The records identify the actor by service_principal_id and app_id, carry no user principal, and set is_interactive to false — an application authenticating with a client secret, not a person at a prompt. (b) is wrong: application-only sign-ins do not perform MFA — there is no human to challenge, which is exactly why a stolen secret is powerful. (c) inverts the truth — a user_principal_name is the marker of a USER sign-in; these have none. (d) misreads the field: conditional_access_status is 'notApplied' here, and CA policies targeting users do not evaluate a service-principal token in the first place.",
    },
    {
      id: "amia_q4",
      xp: 60,
      kind: "single",
      prompt:
        "Among the Azure Activity operations, which one turned a borrowed, time-limited token into durable standing access — the step that most changes the blast radius if left in place?",
      hint: "Distinguish the operations that only READ from the one that changes who is authorized going forward.",
      options: [
        { value: "role_write", label: "Microsoft.Authorization/roleAssignments/write — it granted the identity a standing role that survives the current token" },
        { value: "kv_read", label: "Microsoft.KeyVault/vaults/secrets/read — reading one secret is the most durable form of access in the chain" },
        { value: "list_keys", label: "Microsoft.Storage/storageAccounts/listKeys/action — listing keys permanently rewrites the storage account's access model" },
        { value: "rg_read", label: "Microsoft.Resources/subscriptions/resourceGroups/read — enumerating resource groups establishes lasting control of the subscription" },
      ],
      answer: "role_write",
      explanation:
        "roleAssignments/write is the only operation here that changes authorization state. It grants svc-billing-connector a standing role (Key Vault Secrets Officer) that persists independently of the current access token — revoke the token and the role remains, which is why it is the durable-access step and a containment priority. The secret read (kv_read) and key listing (list_keys) exfiltrate data the identity could already reach; damaging, but they do not expand future entitlement. Enumeration (rg_read) only observes. When scoping containment you remove the added secret AND unwind this role assignment; leaving the role in place hands the operator lasting access even after the secret is revoked.",
    },
    {
      id: "amia_q5",
      xp: 75,
      kind: "multi",
      prompt:
        "You are scoping containment. Select the TWO actions that actually cut off this identity's access and undo the persistence it established.",
      hint: "One action neutralises the authentication factor the attacker added; the other reverses the standing entitlement they granted themselves.",
      options: [
        { value: "revoke_secret", label: "Remove the attacker-added client secret (keyId b7e42c8a…) from svc-billing-connector and revoke its active tokens" },
        { value: "undo_role", label: "Reverse the roleAssignments/write and rotate the Key Vault secret and Storage keys the identity read" },
        { value: "block_ip_only", label: "Block 45.155.205.211 at the network edge — cutting the address ends the incident on its own" },
        { value: "reset_engineer", label: "Reset the platform engineer d.almeida's password, since amia_00 shows that account adding a service-principal secret" },
      ],
      answer: ["revoke_secret", "undo_role"],
      explanation:
        "Two things must be undone: the factor the attacker added and the entitlement they granted. Removing the attacker-added client secret (keyId b7e42c8a…) and revoking the identity's tokens kills the authentication path, and reversing the roleAssignments/write plus rotating the exposed Key Vault secret and Storage keys removes the standing access and the credentials already read. Blocking 45.155.205.211 alone (c) fails because the added secret works from any address and the role assignment survives regardless of source IP — it is a useful stop-gap, not containment. Resetting d.almeida (d) targets the BENIGN control: amia_00 is a sanctioned rotation by a named engineer on an approved change, and the malicious secret-add (amia_01) was performed by the workload identity webjob-ingest-prod, not by that person.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "Azure App-Registration Credential Abuse — the Quiet Secret-Add Behind a Cloud Data-Access Alert",
    threat_actor: "Cloud intrusion operator abusing a compromised workload identity (post-foothold)",
    attack_kind: "cloud_privilege_escalation",
    briefing:
      "Microsoft Graph Security raised a High incident in the nexacorp tenant: the automation identity svc-billing-connector began authenticating from an unfamiliar address and reached Key Vault and Storage in the prod-analytics subscription within minutes. It normally runs only from the billing release pipeline. Work out how it started signing in from there, what it read, and how far it went before you contain it.",
    narrative: `The operator already controlled a workload in the nexacorp tenant whose managed identity, webjob-ingest-prod, held a permission to write application credentials. How they reached that workload is out of scope; what they did with the permission is the case.

At 01:12 they used it for the quiet pivot. An Entra audit line — "Add service principal credentials" — appended a new client secret to an EXISTING app registration, svc-billing-connector, driven from 45.155.205.211. Nothing looked created: no new app, no consent prompt. But svc-billing-connector was over-permissioned — it already held Contributor on the prod subscription and access to the billing Key Vault — and it now had a secret the operator controlled.

Three minutes later that secret was used. svc-billing-connector authenticated to Microsoft Graph, then to Azure Resource Manager, as non-interactive service-principal sign-ins with no user and no MFA. The identity enumerated the prod-analytics subscription and its resource groups, then ran a roleAssignments/write to grant itself the Key Vault Secrets Officer role at the rg-billing-prod scope — turning a borrowed token into standing access. It read the secret sql-conn-prod out of kv-billing-prod, and listed the account keys for the storage account stbillingprod01, the keys that open its blob data.

The one legitimate comparison in the data is two days earlier: platform engineer d.almeida rotating the CI/CD Terraform service principal's secret through approved change CHG-2211, from the known pipeline runner. Identical operation, opposite meaning — the difference is the actor, the address, and the change record behind it. Microsoft Graph Security correlated the credential-add, the non-interactive sign-ins and the Azure Activity into one incident at 01:34, and that is the alert on the queue.`,
    learning_objectives: [
      "Trace a cloud data-access alert (Key Vault / Storage) BACKWARD through Azure Activity and service-principal sign-ins to the Entra audit 'Add service principal credentials' event that enabled it",
      "Recognise that appending a client secret or certificate to an existing, over-permissioned app registration is stealthy persistence — no new app, no consent — and read the Actor, ActorIpAddress and target fields that characterise it",
      "Identify a service-principal (application) sign-in from the ServicePrincipalSignInLogs category, the service_principal_id / app_id fields, and the absence of a user and of MFA",
      "Distinguish the Azure Activity operation that grants standing access (Microsoft.Authorization/roleAssignments/write) from the operations that only read data (secrets/read, listKeys, subscriptions read)",
      "Separate a malicious credential-add from a sanctioned secret rotation using actor provenance, source address and the presence of a change record — not the operation name, which is identical — and scope containment to the added secret AND the role it granted",
    ],
    alerts: [], // attached by the catalogue wiring
    events,
    iocs,
    killchain: [
      { ts: "2026-08-27T14:20:00.000Z", phase: "Baseline", action: `Platform engineer rotates ${terraformSp.displayName}'s client secret under approved change CHG-2211 — the sanctioned, attributable path (T1098.001)` },
      { ts: T(0), phase: "Persistence", action: `New client secret appended to the existing ${app.displayName} app registration by ${workloadMi.displayName} (T1098.001)` },
      { ts: T(3 * MIN), phase: "Defense Evasion", action: `${app.displayName} signs in non-interactively to Microsoft Graph with the new secret (T1078.004)` },
      { ts: T(4 * MIN), phase: "Defense Evasion", action: "Same identity acquires an Azure Resource Manager token (T1078.004)" },
      { ts: T(6 * MIN), phase: "Discovery", action: `Subscription and resource groups enumerated in ${subName} (T1526)` },
      { ts: T(9 * MIN), phase: "Persistence", action: `roleAssignments/write grants Key Vault Secrets Officer at ${resourceGroup} scope — standing access (T1098.003)` },
      { ts: T(12 * MIN), phase: "Credential Access", action: `Secret sql-conn-prod read from ${keyVault} (T1555.006)` },
      { ts: T(15 * MIN), phase: "Collection", action: `Account keys listed for storage account ${storageAccount} (T1530)` },
      { ts: T(22 * MIN), phase: "Detection", action: "Microsoft Graph Security correlates the credential-add, sign-ins and Azure Activity into one incident" },
    ],
    questions,
  };
}
