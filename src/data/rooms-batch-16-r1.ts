import type { TelemetryEvent } from "@/lib/sim/types";

// ── Event 1 (log_analysis): over-privileged managed identity used to read Key Vault secrets ──
const managedIdentityKeyVaultEvent: TelemetryEvent = {
  id: "evt-azure-mi-kv-001",
  ts: "2026-06-15T02:11:04.000Z",
  source: "cloud_azure",
  vendor: "Azure Activity Log",
  event_type: "cloud_storage_access",
  severity: "critical",
  user_email: "svc-webapp-mi@nexacorp.onmicrosoft.com",
  src_ip: "203.0.113.44",
  geo: { country: "Romania", city: "Bucharest" },
  description: "A system-assigned managed identity attached to a public-facing web app was used to retrieve a high-value secret from Key Vault, from a source IP outside Azure's own network ranges",
  mitre_technique: "T1552.005",
  mitre_tactic: "Credential Access",
  raw: {
    "azure.activitylogs.operationName": "SECRETS.GET",
    "azure.activitylogs.resourceProviderValue": "Microsoft.KeyVault",
    "azure.activitylogs.resourceId": "/subscriptions/8f3a9c2e-4b1d-4e7a-9c6f-1a2b3c4d5e6f/resourceGroups/nexacorp-prod-rg/providers/Microsoft.KeyVault/vaults/nexacorp-prod-kv",
    "azure.activitylogs.subscriptionId": "8f3a9c2e-4b1d-4e7a-9c6f-1a2b3c4d5e6f",
    "azure.activitylogs.resultType": "Success",
    "azure.activitylogs.resultSignature": "200",
    "azure.activitylogs.identity.claims.appid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
    "azure.activitylogs.identity.claims.idtyp": "app",
    "azure.activitylogs.identity.authorization.evidence.principalType": "ServicePrincipal",
    "azure.activitylogs.identity.claims.xms_mirid": "/subscriptions/8f3a9c2e-4b1d-4e7a-9c6f-1a2b3c4d5e6f/resourcegroups/nexacorp-prod-rg/providers/Microsoft.Web/sites/nexacorp-webapp",
    "azure.activitylogs.identity.authorization.evidence.principalId": "b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e",
    "azure.activitylogs.identity.authorization.evidence.role": "Key Vault Secrets User",
    "azure.activitylogs.caller": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
    "azure.activitylogs.callerIpAddress": "203.0.113.44",
    "azure.activitylogs.category": "AuditEvent",
    "azure.activitylogs.level": "Informational",
    "azure.keyvault.OperationName": "SecretGet",
    "azure.keyvault.identity.claim.appid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
    "azure.keyvault.requestUri": "https://nexacorp-prod-kv.vault.azure.net/secrets/sql-connection-string",
    "azure.keyvault.httpStatusCode": 200,
    "cloud.provider": "azure",
    "cloud.subscription_id": "8f3a9c2e-4b1d-4e7a-9c6f-1a2b3c4d5e6f",
    "action_result": "allowed",
  },
};

// ── Event 2 (log_analysis): NSG rule opened RDP to the internet + inbound flow accepted ──
const nsgRdpExposureEvent: TelemetryEvent = {
  id: "evt-azure-nsg-rdp-001",
  ts: "2026-06-15T02:34:51.000Z",
  source: "cloud_azure",
  vendor: "Azure NSG Flow Logs",
  event_type: "net_connection",
  severity: "critical",
  user_email: "svc-webapp-mi@nexacorp.onmicrosoft.com",
  src_ip: "203.0.113.44",
  dst_ip: "10.40.2.15",
  dst_port: 3389,
  protocol: "TCP",
  geo: { country: "Romania", city: "Bucharest" },
  description: "A Network Security Group rule allowing inbound RDP from Any source was added minutes before an external IP successfully connected to port 3389 on a production virtual machine",
  mitre_technique: "T1021.001",
  mitre_tactic: "Lateral Movement",
  raw: {
    "azure.activitylogs.operationName": "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE",
    "azure.activitylogs.resourceProviderValue": "Microsoft.Network",
    "azure.activitylogs.resourceId": "/subscriptions/8f3a9c2e-4b1d-4e7a-9c6f-1a2b3c4d5e6f/resourceGroups/nexacorp-prod-rg/providers/Microsoft.Network/networkSecurityGroups/nexacorp-prod-vm-nsg/securityRules/allow-rdp-temp",
    "azure.activitylogs.resultType": "Success",
    "azure.activitylogs.identity.claims.appid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
    "azure.activitylogs.identity.authorization.evidence.principalType": "ServicePrincipal",
    "azure.activitylogs.identity.claims.xms_mirid": "/subscriptions/8f3a9c2e-4b1d-4e7a-9c6f-1a2b3c4d5e6f/resourcegroups/nexacorp-prod-rg/providers/Microsoft.Web/sites/nexacorp-webapp",
    "azure.activitylogs.caller": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
    "azure.activitylogs.callerIpAddress": "203.0.113.44",
    "azure.activitylogs.properties.requestbody": "{\"properties\":{\"direction\":\"Inbound\",\"access\":\"Allow\",\"protocol\":\"Tcp\",\"sourcePortRange\":\"*\",\"destinationPortRange\":\"3389\",\"sourceAddressPrefix\":\"*\",\"destinationAddressPrefix\":\"10.40.2.15\",\"priority\":100}}",
    "azure.nsgflowlogs.rule": "allow-rdp-temp",
    "azure.nsgflowlogs.mac": "00-0D-3A-1F-4C-2B",
    "azure.nsgflowlogs.flowTuples": "1781490891,203.0.113.44,10.40.2.15,51422,3389,T,I,A,B",
    "azure.nsgflowlogs.nsgResourceId": "/subscriptions/8f3a9c2e-4b1d-4e7a-9c6f-1a2b3c4d5e6f/resourceGroups/nexacorp-prod-rg/providers/Microsoft.Network/networkSecurityGroups/nexacorp-prod-vm-nsg",
    "cloud.provider": "azure",
    "cloud.subscription_id": "8f3a9c2e-4b1d-4e7a-9c6f-1a2b3c4d5e6f",
    "action_result": "allowed",
  },
};

// ── Event 3 (analyst_choice): scheduled automation service principal vs suspicious lookalike ──
const automationServicePrincipalEvent: TelemetryEvent = {
  id: "evt-azure-sp-automation-001",
  ts: "2026-06-15T06:00:09.000Z",
  source: "cloud_azure",
  vendor: "Azure Activity Log",
  event_type: "cloud_api_call",
  severity: "low",
  user_email: "sp-nightly-backup@nexacorp.onmicrosoft.com",
  src_ip: "10.40.1.9",
  hostname: "aut-nexacorp-runbook-worker",
  description: "A registered service principal used by the nightly backup Automation Runbook listed storage account keys as part of a scheduled, ticketed backup job",
  raw: {
    "azure.activitylogs.operationName": "MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION",
    "azure.activitylogs.resourceProviderValue": "Microsoft.Storage",
    "azure.activitylogs.resourceId": "/subscriptions/8f3a9c2e-4b1d-4e7a-9c6f-1a2b3c4d5e6f/resourceGroups/nexacorp-backup-rg/providers/Microsoft.Storage/storageAccounts/nexacorpbackupsa",
    "azure.activitylogs.resultType": "Success",
    "azure.activitylogs.identity.claims.appid": "c3d4e5f6-a7b8-4c9d-0e1f-2a3b4c5d6e7f",
    "azure.activitylogs.identity.claims.idtyp": "app",
    "azure.activitylogs.identity.authorization.evidence.principalType": "ServicePrincipal",
    "azure.activitylogs.identity.authorization.evidence.role": "Storage Account Key Operator Service Role",
    "azure.activitylogs.caller": "c3d4e5f6-a7b8-4c9d-0e1f-2a3b4c5d6e7f",
    "azure.activitylogs.callerIpAddress": "10.40.1.9",
    "azure.activitylogs.category": "Administrative",
    "azure.activitylogs.level": "Informational",
    "cloud.provider": "azure",
    "cloud.subscription_id": "8f3a9c2e-4b1d-4e7a-9c6f-1a2b3c4d5e6f",
    "action_result": "allowed",
  },
};

// ── Event 4 (flag task): storage account public blob access enabled + SAS token abuse ──
// eslint-disable-next-line @typescript-eslint/no-unused-vars -- authored attack-event, not yet wired into a room task
const storagePublicSasEvent: TelemetryEvent = {
  id: "evt-azure-storage-sas-001",
  ts: "2026-06-15T02:55:37.000Z",
  source: "cloud_azure",
  vendor: "Azure Activity Log",
  event_type: "cloud_role_change",
  severity: "critical",
  user_email: "svc-webapp-mi@nexacorp.onmicrosoft.com",
  src_ip: "203.0.113.44",
  geo: { country: "Romania", city: "Bucharest" },
  description: "Blob container public access was changed to allow anonymous read access shortly after a long-lived Shared Access Signature token was generated for the same storage account",
  mitre_technique: "T1530",
  mitre_tactic: "Collection",
  raw: {
    "azure.activitylogs.operationName": "MICROSOFT.STORAGE/STORAGEACCOUNTS/BLOBSERVICES/CONTAINERS/WRITE",
    "azure.activitylogs.resourceProviderValue": "Microsoft.Storage",
    "azure.activitylogs.resourceId": "/subscriptions/8f3a9c2e-4b1d-4e7a-9c6f-1a2b3c4d5e6f/resourceGroups/nexacorp-prod-rg/providers/Microsoft.Storage/storageAccounts/nexacorpprodsa/blobServices/default/containers/customer-exports",
    "azure.activitylogs.subscriptionId": "8f3a9c2e-4b1d-4e7a-9c6f-1a2b3c4d5e6f",
    "azure.activitylogs.resultType": "Success",
    "azure.activitylogs.identity.claims.appid": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
    "azure.activitylogs.identity.authorization.evidence.principalType": "ServicePrincipal",
    "azure.activitylogs.identity.claims.xms_mirid": "/subscriptions/8f3a9c2e-4b1d-4e7a-9c6f-1a2b3c4d5e6f/resourcegroups/nexacorp-prod-rg/providers/Microsoft.Web/sites/nexacorp-webapp",
    "azure.activitylogs.caller": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
    "azure.activitylogs.callerIpAddress": "203.0.113.44",
    "azure.activitylogs.properties.requestbody": "{\"properties\":{\"publicAccess\":\"Container\"}}",
    "cloud.provider": "azure",
    "cloud.subscription_id": "8f3a9c2e-4b1d-4e7a-9c6f-1a2b3c4d5e6f",
    "action_result": "allowed",
  },
};

const azureSecurityRoom = {
  id: "azure-security",
  title: "Azure IaaS Security for SOC Analysts",
  description:
    "Learn to investigate Microsoft Azure's cloud infrastructure layer as a SOC analyst. Beyond Entra ID sign-ins and M365 mailboxes. Cover Azure's resource model (subscriptions, resource groups, RBAC role assignments, managed identities, service principals), the Azure Activity Log as the control-plane audit trail, Network Security Groups and NSG Flow Logs, Key Vault secret access, Storage Account exposure and SAS token abuse, VM run-command abuse, and Microsoft Defender for Cloud with Azure Monitor/Log Analytics (KQL) as the detection surface. Azure concepts are mapped throughout against the AWS and GCP equivalents you may already know.",
  difficulty: "intermediate" as const,
  category: "Cloud Security",
  estimatedMinutes: 70,
  xp: 345,
  icon: "🔷",
  prerequisites: ["cloud-security-monitoring"],
  tasks: [
    // ── Reading 1: What is Azure IaaS + resource model ──────────────────────
    {
      type: "reading" as const,
      id: "azure-r1",
      heading: "What Is Azure, and How Is Its Resource Model Organized?",
      content:
        `**Microsoft Azure** is Microsoft's cloud computing platform: the second-largest public cloud provider after AWS, and a very common choice for organizations already invested in Microsoft technology (Windows Server, Active Directory, Office 365). If your organization uses Azure, a meaningful share of the servers, databases, and storage a SOC analyst must protect exist as configurations inside an Azure subscription rather than in a physical server room.\n\n` +
        `This room focuses specifically on Azure's **infrastructure layer**: the virtual machines, storage accounts, networks, and secrets vaults that make up Azure IaaS (Infrastructure as a Service) and PaaS (Platform as a Service). Note that Azure AD/Entra ID sign-ins, Conditional Access, and mailbox/M365 activity are covered in a separate identity-focused room. Here, the focus is the cloud infrastructure an attacker touches once they already have a foothold, or is trying to reach.\n\n` +
        `**The Azure Resource Hierarchy**\n\n` +
        `Everything in Azure sits inside a **subscription**: the basic unit of billing and access management, and the closest Azure equivalent to an AWS account or a GCP project. Inside a subscription, resources (virtual machines, storage accounts, key vaults, networks) are organized into **resource groups**. Logical containers that group related resources together, typically by application or environment (for example, nexacorp-prod-rg holding every resource for the production web application). Subscriptions can be grouped under **management groups** for large organizations, similar to how AWS Organizations groups multiple accounts or how GCP folders group projects.\n\n` +
        `**Why Resource Groups Matter for Investigation**\n\n` +
        `Every Azure resource has a full **resourceId** path that always follows the same pattern: /subscriptions/{subscription-id}/resourceGroups/{resource-group-name}/providers/{provider-namespace}/{resource-type}/{resource-name}. This single string tells a SOC analyst exactly which subscription, which resource group, which Azure service (the "provider," such as Microsoft.Storage or Microsoft.KeyVault), and which specific resource were touched. It is the Azure equivalent of an AWS ARN (Amazon Resource Name) or a GCP resource name, and you will see it in nearly every log you investigate in this room.\n\n` +
        `**RBAC: How Permissions Actually Work in Azure**\n\n` +
        `Azure uses **RBAC (Role-Based Access Control)** to control who can do what. A **role assignment** binds three things together: a **security principal** (a user, group, managed identity, or service principal), a **role definition** (a set of allowed actions, such as the built-in Contributor, Reader, or Key Vault Secrets User roles), and a **scope** (the subscription, resource group, or individual resource the assignment applies to). This three-part model, principal + role + scope, is the single most important concept for understanding both legitimate access and privilege-escalation attacks in Azure, and it maps conceptually to an AWS IAM policy attached to a user, group, or role, though Azure's built-in roles are more standardized out of the box than AWS's fully custom JSON policies.`,
      codeExample:
        "AZURE <-> AWS/GCP TERMINOLOGY CHEAT SHEET\n" +
        "=======================================================\n" +
        "Azure Concept              AWS Equivalent    GCP Equivalent\n" +
        "-------------------------------------------------------\n" +
        "Subscription                AWS Account       Project\n" +
        "Resource Group              (no direct equiv- Folder (loose)\n" +
        "                             alent; tags/OUs)\n" +
        "Management Group            AWS Organizations Organization\n" +
        "Virtual Machine (VM)         EC2 instance      Compute Engine\n" +
        "Storage Account/Blob         S3 bucket         Cloud Storage\n" +
        "  Container                                    bucket\n" +
        "Virtual Network (VNet)       VPC               VPC\n" +
        "Network Security Group (NSG) Security Group    Firewall rule\n" +
        "RBAC Role Assignment         IAM Policy        IAM Binding\n" +
        "Managed Identity             IAM Role (EC2)    Service Account\n" +
        "Service Principal            IAM User/App      Service Account\n" +
        "Azure Activity Log           CloudTrail        Cloud Audit Logs\n" +
        "Microsoft Defender for Cloud GuardDuty         Security Command\n" +
        "                                                Center\n" +
        "=======================================================\n\n" +
        "AZURE RESOURCE ID FORMAT (every resource has one)\n" +
        "=======================================================\n" +
        "/subscriptions/{subscription-id}\n" +
        "  /resourceGroups/{resource-group-name}\n" +
        "  /providers/{provider-namespace}/{resource-type}/{name}\n" +
        "\n" +
        "Example:\n" +
        "/subscriptions/8f3a9c2e-4b1d-4e7a-9c6f-1a2b3c4d5e6f\n" +
        "  /resourceGroups/nexacorp-prod-rg\n" +
        "  /providers/Microsoft.KeyVault/vaults/nexacorp-prod-kv\n" +
        "=======================================================",
      checkpoint: {
        question:
          "An alert's resourceId is '/subscriptions/8f3a9c2e-…/resourceGroups/nexacorp-prod-rg/providers/Microsoft.KeyVault/vaults/nexacorp-prod-kv'. Which part names the billing and access-management boundary: the AWS-account equivalent you will investigate within?",
        options: [
          "The resource group, nexacorp-prod-rg",
          "The subscription, 8f3a9c2e-…",
          "The provider, Microsoft.KeyVault",
          "The vault name, nexacorp-prod-kv",
        ],
        answer: 1,
        explanation:
          "Every Azure resource ID starts with /subscriptions/{id}: the subscription is the basic unit of billing and access management, equivalent to an AWS account or GCP project. The resource group is a logical container inside that subscription, grouping related resources: useful for scoping, but not the account boundary. Microsoft.KeyVault is the provider namespace, which only says what kind of resource this is. nexacorp-prod-kv is the individual resource itself.",
      },
    },

    // ── Reading 2: Azure Activity Log vs CloudTrail/Cloud Audit Logs ────────
    {
      type: "reading" as const,
      id: "azure-r2",
      heading: "Azure Activity Log: The Control-Plane Audit Trail",
      content:
        `The **Azure Activity Log** is Azure's native audit-logging service for **control-plane** operations. Every create, update, delete, or role-assignment action taken against a subscription's resources, whether performed through the Azure Portal, the Azure CLI, PowerShell, or an ARM/Bicep deployment template. If you already know AWS CloudTrail or GCP Cloud Audit Logs, the Activity Log fills the same role, but the terminology and structure differ enough to trip up an analyst moving between clouds.\n\n` +
        `**Key Fields in the Activity Log**\n\n` +
        `Each Activity Log entry captures: azure.activitylogs.operationName (the specific action, formatted as PROVIDER/RESOURCETYPE/ACTION, such as Microsoft.Storage/storageAccounts/blobServices/containers/write), azure.activitylogs.resourceId (the full path identifying exactly which resource was touched), azure.activitylogs.caller (the object ID of the identity that performed the action), azure.activitylogs.callerIpAddress (the source IP), azure.activitylogs.resultType (Success or Failure. Azure's equivalent of an empty vs populated error_code in CloudTrail), and azure.activitylogs.identity.claims (a set of claims describing the authenticated identity, including whether it is a user, a managed identity, or a service principal).\n\n` +
        `**Critical Terminology Contrast for Analysts Coming from AWS/GCP**\n\n` +
        `Where CloudTrail calls actions "management events" and "data events," and GCP Cloud Audit Logs splits activity into "Admin Activity" and "Data Access" logs, Azure instead splits its logging into entirely separate log categories that must each be understood on their own terms: the **Activity Log** (subscription-level control-plane actions, always on, retained 90 days by default), **Azure AD / Entra ID logs** (identity sign-ins and directory changes. Covered in a separate room), **Resource-specific diagnostic logs** (deep, service-level logs like NSG Flow Logs, Key Vault audit events, or Storage Analytics logs. These must be explicitly enabled per-resource via **diagnostic settings**, similar to how S3 data events must be explicitly enabled in CloudTrail), and **Azure Monitor / Log Analytics** (the query and correlation layer that all of the above can be forwarded into, queried using **KQL**, Kusto Query Language).\n\n` +
        `**The Most Common Azure Visibility Gap**\n\n` +
        `Just as an organization must explicitly enable S3 data event logging in AWS, an Azure subscription must have **diagnostic settings** configured on each individual resource (a specific Key Vault, a specific NSG, a specific Storage Account) to forward that resource's detailed activity into Log Analytics or a SIEM. The Activity Log alone will show you that a role assignment was created or that a container's public-access setting was changed (control-plane actions), but it will NOT show you which specific secret was read inside a Key Vault, or which specific blob was downloaded from a Storage Account, unless diagnostic logging has been explicitly turned on for that resource. A SOC analyst investigating an Azure incident should always confirm which diagnostic settings are enabled before concluding "no data plane activity" means "nothing happened."`,
      codeExample:
        "AZURE LOGGING LAYERS (NOT ONE SINGLE LOG!)\n" +
        "=======================================================\n" +
        "Layer                    What It Captures         Default?\n" +
        "-------------------------------------------------------\n" +
        "Activity Log             Control-plane ops on     YES\n" +
        "                         subscription resources    (90 days)\n" +
        "                         (create/update/delete/\n" +
        "                          role assignment)\n" +
        "\n" +
        "Entra ID Sign-in/Audit   Identity sign-ins and     YES\n" +
        "Logs                     directory changes         (separate\n" +
        "                                                    room)\n" +
        "\n" +
        "Resource Diagnostic      Deep, per-resource data-  NO -- must\n" +
        "Logs (NSG Flow, Key      plane detail (secret      enable per\n" +
        "Vault audit, Storage     reads, blob downloads,    resource via\n" +
        "Analytics)               network flows)            diagnostic\n" +
        "                                                    settings\n" +
        "=======================================================\n\n" +
        "SAMPLE AZURE ACTIVITY LOG ENTRY (SIMPLIFIED)\n" +
        "=======================================================\n" +
        "{\n" +
        "  \"operationName\": \"MICROSOFT.KEYVAULT/VAULTS/WRITE\",\n" +
        "  \"resourceId\": \"/subscriptions/.../vaults/nexacorp-prod-kv\",\n" +
        "  \"caller\": \"a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d\",\n" +
        "  \"callerIpAddress\": \"203.0.113.44\",\n" +
        "  \"resultType\": \"Success\",\n" +
        "  \"identity\": { \"claims\": { \"idtyp\": \"app\" } }\n" +
        "}\n" +
        "=======================================================",
    },

    // ── Reading 3: Managed identities & service principals ──────────────────
    {
      type: "reading" as const,
      id: "azure-r3",
      heading: "Managed Identities and Service Principals: Azure's Non-Human Identities",
      content:
        `Just as AWS lets an EC2 instance assume an IAM role, and GCP lets a VM run as a service account, Azure gives every resource that needs to authenticate to other Azure services one of two mechanisms: a **managed identity** or a **service principal**.\n\n` +
        `**Managed Identity: Azure's "No Secrets to Steal" Identity**\n\n` +
        `A **managed identity** is an identity automatically created and managed by Azure AD for an Azure resource: most commonly a virtual machine, an App Service (web app), or an Azure Function. There are two flavors: a **system-assigned managed identity** is tied to the lifecycle of a single resource (created and deleted along with it), while a **user-assigned managed identity** is created independently and can be attached to multiple resources at once. The entire point of a managed identity is that the application code never handles a password or a secret. Azure automatically issues short-lived tokens behind the scenes, retrieved from a local, non-routable endpoint on the resource itself, conceptually identical to how an EC2 instance retrieves temporary IAM role credentials from AWS's IMDS at 169.254.169.254.\n\n` +
        `**Service Principal: The Identity Behind an "App Registration"**\n\n` +
        `A **service principal** is the local, tenant-specific representation of an **application registration** in Azure AD. It is what lets an application, a script, a CI/CD pipeline, or an automation Runbook authenticate to Azure APIs. Unlike a managed identity, a service principal typically authenticates with either a **client secret** (a long-lived password-like value, which can be leaked exactly like an AWS IAM user access key) or a **certificate**. Service principals are the identity type behind most third-party integrations, Terraform deployments, and scheduled automation jobs, and, like an over-permissioned AWS IAM user or a GCP service account with a downloaded JSON key, an over-privileged or leaked service principal is one of the most common paths to a serious Azure compromise.\n\n` +
        `**Why This Distinction Matters When Reading a Log**\n\n` +
        `In the Azure Activity Log, the azure.activitylogs.identity.claims.idtyp field of "app" tells you the caller is a non-human identity (either a managed identity or service principal). Do NOT expect azure.activitylogs.identity.authorization.evidence.principalType to tell them apart: in Azure RBAC a managed identity IS a service principal, so both show principalType "ServicePrincipal" (the valid values are User, Group, ServicePrincipal, ForeignGroup and Device). The tells are elsewhere: a managed identity's token carries an xms_mirid claim (azure.activitylogs.identity.claims.xms_mirid) naming the Azure resource it belongs to, which an app-registration service principal's token does not; in Entra ID the service principal object's servicePrincipalType reads "ManagedIdentity" rather than "Application"; and its sign-ins land in the managed identity sign-in log (AADManagedIdentitySignInLogs) rather than the service principal sign-in log (AADServicePrincipalSignInLogs). This distinction directly changes your investigation path: a managed identity has no credential that can be independently leaked or phished (the risk is entirely about which permissions it was over-granted, and whether the resource it's attached to was compromised), whereas a service principal's client secret CAN be leaked on GitHub, in a CI/CD log, or in a configuration file, exactly like an AWS access key.\n\n` +
        `**The Over-Privileged Managed Identity Problem**\n\n` +
        `A very common real-world misconfiguration is granting a managed identity attached to a public-facing web application far broader RBAC permissions than the application actually needs, for example, granting Key Vault Secrets User (or worse, Contributor) scoped to the entire resource group, when the application only ever needs to read one specific secret. If that public-facing application is ever compromised (through a web vulnerability, a dependency confusion attack, or a leaked deployment credential), the attacker inherits every permission the managed identity holds, turning a single web app vulnerability into a much wider blast radius across Key Vaults, storage accounts, or other resources in the same resource group.`,
      codeExample:
        "MANAGED IDENTITY vs SERVICE PRINCIPAL\n" +
        "=======================================================\n" +
        "                  Managed Identity     Service Principal\n" +
        "-------------------------------------------------------\n" +
        "Credential        None -- Azure auto-  Client secret or\n" +
        "                  issues short-lived   certificate (can\n" +
        "                  tokens internally    be leaked/stolen)\n" +
        "\n" +
        "Typical use       VM, App Service,     CI/CD pipelines,\n" +
        "                  Azure Function       Terraform, 3rd-party\n" +
        "                  calling other        integrations,\n" +
        "                  Azure services       automation Runbooks\n" +
        "\n" +
        "identity.claims   idtyp: app,          idtyp: app,\n" +
        "                  xms_mirid present    no xms_mirid\n" +
        "evidence          ServicePrincipal     ServicePrincipal\n" +
        "  .principalType  (same value!)\n" +
        "Entra SP object   servicePrincipalType servicePrincipalType\n" +
        "                  ManagedIdentity      Application\n" +
        "\n" +
        "Risk if attached   Attacker inherits    Leaked secret works\n" +
        "resource is        every RBAC role     from ANYWHERE until\n" +
        "compromised        the identity holds  rotated (like an\n" +
        "                                       AWS access key)\n" +
        "=======================================================",
      checkpoint: {
        question:
          "Two Activity Log events both show principalType 'ServicePrincipal' and idtyp 'app'. The first token carries an xms_mirid claim naming a web app; the second has no xms_mirid. What does that tell you?",
        options: [
          "Both are app registrations: principalType 'ServicePrincipal' settles it",
          "The first is a managed identity; the second is likely an app registration",
          "The first is a user acting through the web app; the second is an identity",
          "Both are managed identities: no xms_mirid just means a VM-hosted identity",
        ],
        answer: 1,
        explanation:
          "Managed identities are service principals too, so principalType reads 'ServicePrincipal' for both. It cannot tell them apart. The xms_mirid claim is what marks a managed identity: it names the Azure resource the identity is attached to. No xms_mirid points to an app registration, which typically authenticates with a client secret or certificate that can leak (confirm via the Entra object's servicePrincipalType). 'principalType settles it' is the trap. 'A user acting through the web app' is wrong because idtyp 'app' marks a non-human caller. 'No xms_mirid means a VM-hosted identity' is wrong: managed identities on VMs, functions and other resources carry xms_mirid too, naming their own resource.",
      },
    },

    // ── Reading 4: NSGs, NSG Flow Logs, Storage exposure, SAS tokens ────────
    {
      type: "reading" as const,
      id: "azure-r4",
      heading: "Network Security Groups, Storage Exposure, and SAS Token Abuse",
      content:
        `Three attack surfaces come up constantly in real Azure IaaS investigations: misconfigured network security rules, publicly exposed storage, and abused access tokens.\n\n` +
        `**Network Security Groups (NSGs): Azure's Virtual Firewall**\n\n` +
        `A **Network Security Group (NSG)** is Azure's virtual firewall, attached to a subnet or a network interface, that controls inbound and outbound traffic using ordered allow/deny rules: the direct equivalent of an AWS Security Group or a GCP VPC firewall rule. Each NSG rule specifies a direction (Inbound/Outbound), an access decision (Allow/Deny), a protocol, a source/destination address prefix, and a destination port range, along with a numeric priority (lower numbers are evaluated first). A dangerously common misconfiguration is a rule with sourceAddressPrefix "*" (meaning "any source on the internet") allowing a sensitive port like 3389 (RDP) or 22 (SSH) or 1433 (SQL Server). Effectively opening a direct door from the entire internet to a production server.\n\n` +
        `**NSG Flow Logs: Azure's NetFlow**\n\n` +
        `**NSG Flow Logs** record the actual connections that were evaluated by an NSG's rules. Source IP, destination IP, source port, destination port, protocol, and whether the flow was Allowed (A) or Denied (D). Conceptually identical to AWS VPC Flow Logs or GCP VPC Flow Logs. The flowTuples field packs this information into a compact comma-separated format: timestamp, source IP, destination IP, source port, destination port, protocol, flow direction (Inbound/Outbound), and the allow/deny decision. A SOC analyst correlates an NSG rule CHANGE (from the Activity Log) with the actual TRAFFIC that flowed as a result (from NSG Flow Logs) to confirm whether a risky rule was just created, or was created AND actively exploited.\n\n` +
        `**Storage Account Public Exposure**\n\n` +
        `An Azure **Storage Account** holds **blob containers** (similar to S3 buckets or Cloud Storage buckets), and each container has a **public access level** setting: Private (no anonymous access), Blob (anonymous read access to individual blobs if you know the exact URL), or Container (anonymous read access AND the ability to list every blob in the container, the most dangerous setting). Changing this setting to Container on a container holding customer exports or backups is one of the most common and damaging real-world Azure misconfigurations, directly analogous to a public S3 bucket or a public GCS bucket.\n\n` +
        `**SAS Tokens: Azure's Scoped, Shareable Access Keys**\n\n` +
        `A **SAS (Shared Access Signature) token** is a signed URL parameter that grants time-limited, scoped access to a storage resource without sharing the storage account's master key. Useful for giving a partner or an application temporary access to a single container. However, a SAS token generated with overly broad permissions (rwdl. Read, write, delete, list) and a far-future expiry (months or years away instead of hours) behaves exactly like a long-lived, hard-to-revoke credential: anyone who obtains the URL has full access until the token's expiry date, and unlike an Azure AD credential, a SAS token cannot always be individually revoked without regenerating the storage account's underlying access keys (which breaks every other SAS token issued from those keys too). A newly-generated SAS token with a multi-year expiry, especially one appearing alongside a container's public-access setting being widened, is a strong signal of deliberate data-exposure setup, whether by a careless administrator or an attacker preparing for exfiltration.`,
      codeExample:
        "NSG RULE ANATOMY\n" +
        "=======================================================\n" +
        "{\n" +
        "  \"direction\": \"Inbound\",\n" +
        "  \"access\": \"Allow\",\n" +
        "  \"protocol\": \"Tcp\",\n" +
        "  \"sourceAddressPrefix\": \"*\",      <- ANY internet source\n" +
        "  \"destinationPortRange\": \"3389\",  <- RDP\n" +
        "  \"priority\": 100                  <- evaluated first\n" +
        "}\n" +
        "=======================================================\n\n" +
        "NSG FLOW LOG TUPLE FORMAT\n" +
        "=======================================================\n" +
        "timestamp,srcIP,dstIP,srcPort,dstPort,protocol,\n" +
        "  direction,decision\n" +
        "\n" +
        "Example:\n" +
        "1718418891,203.0.113.44,10.40.2.15,51422,3389,T,I,A\n" +
        "  -> TCP inbound from 203.0.113.44 to port 3389, ALLOWED\n" +
        "=======================================================\n\n" +
        "STORAGE CONTAINER PUBLIC ACCESS LEVELS\n" +
        "=======================================================\n" +
        "Level        Anonymous Read Individual Blob?  List All?\n" +
        "-------------------------------------------------------\n" +
        "Private      NO                               NO\n" +
        "Blob         YES (if exact URL known)          NO\n" +
        "Container    YES                               YES (worst)\n" +
        "=======================================================",
      checkpoint: {
        question:
          "A container's public access level is set to 'Blob'. What can an anonymous outsider who knows none of the file names do?",
        options: [
          "List every blob in the container and download any of them",
          "List the blob names, but not download any file contents",
          "Read a blob only if they already know its exact URL",
          "Nothing at all, unless they also hold a SAS token",
        ],
        answer: 2,
        explanation:
          "'Blob' level allows anonymous read of an individual blob, but only if you know its exact URL. Anonymous listing is not allowed, so an outsider with no file names has nothing to request. 'List and download everything' describes the 'Container' level, the worst setting. 'List names but not download' reverses how 'Blob' works: reading is allowed, listing is not. 'Nothing without a SAS token' describes 'Private'; with 'Blob', a known URL is enough, no token needed.",
      },
    },

    // ── Reading 5: VM run-command abuse & resource enumeration ─────────────
    {
      type: "reading" as const,
      id: "azure-r5",
      heading: "VM Run-Command and Custom Script Extension Abuse, and Resource Enumeration",
      content:
        `Beyond identity and network misconfigurations, attackers with sufficient RBAC permissions on an Azure subscription have a uniquely powerful tool available: the ability to execute arbitrary code directly on a virtual machine, without ever needing to log in through SSH or RDP.\n\n` +
        `**VM Run Command: Remote Code Execution Through the Control Plane**\n\n` +
        `Azure's **Run Command** feature (operation name Microsoft.Compute/virtualMachines/runCommand/action) lets anyone with the right RBAC role (most commonly Contributor or Virtual Machine Contributor on the VM) execute a PowerShell or Bash script directly on the VM's operating system through the Azure control plane, using the Azure VM Agent installed on nearly every VM by default. Because this happens through the Azure Resource Manager API rather than through the network, it completely bypasses network-layer defenses like NSGs, firewalls, or even the requirement to know the VM's actual login credentials. If an attacker compromises an identity with Contributor rights on a subscription or resource group (for example, through a stolen service principal secret or an over-privileged managed identity), they can use Run Command to execute code on every VM in scope: a devastating lateral movement and code-execution primitive that many defenders don't think to monitor at the control-plane layer.\n\n` +
        `**Custom Script Extension: The Same Risk, Deployed at VM Creation**\n\n` +
        `The **Custom Script Extension** (Microsoft.Compute/virtualMachines/extensions/write with a publisher of Microsoft.Compute.CustomScriptExtension) achieves a very similar outcome. It downloads and executes a script on a VM, typically used legitimately during VM provisioning to install software or apply configuration. An attacker with Contributor-level access can attach a malicious Custom Script Extension to an existing, already-running production VM at any time, not just at creation, making unexpected extension installations on a long-running VM a strong signal worth investigating.\n\n` +
        `**Azure Resource Enumeration: The Reconnaissance Phase**\n\n` +
        `Just as an AWS attacker runs DescribeInstances and ListBuckets, or a GCP attacker runs compute.instances.list, an attacker who has gained any foothold in an Azure subscription will typically enumerate what they have access to using read-only calls: listing role assignments (Microsoft.Authorization/roleAssignments/read) to understand their own and others' permissions, listing Key Vaults and their secrets' names (though not values, without explicit Get permission), listing storage accounts and their keys, and listing virtual machines and their network configurations. A burst of read-only "list" and "get" operations across many different resource types, from a single identity in a short time window, is a classic reconnaissance pattern. Individually benign, but suspicious in aggregate, especially from an identity that does not normally perform broad enumeration.\n\n` +
        `**Microsoft Defender for Cloud: Azure's Built-In Threat Detector**\n\n` +
        `**Microsoft Defender for Cloud** (formerly Azure Security Center) is Azure's native Cloud Security Posture Management (CSPM) and threat-detection service: the rough equivalent of AWS GuardDuty combined with AWS Security Hub, or GCP's Security Command Center. It continuously assesses subscriptions against security best practices (flagging things like publicly exposed storage containers, NSGs allowing unrestricted RDP/SSH, or Key Vaults without diagnostic logging enabled) and separately raises real-time threat alerts (such as "Suspicious Azure Resource Manager operation" or unusual Run Command execution) using both rule-based detections and machine-learning models trained on Microsoft's threat intelligence. Just like GuardDuty findings, Defender for Cloud alerts arrive pre-scored with a severity and description, making them a strong Tier-1 starting point, but the underlying Activity Log and diagnostic log entries remain where the deep investigation happens.\n\n` +
        `**Azure Monitor and Log Analytics: The Query Layer**\n\n` +
        `**Azure Monitor** is the umbrella platform that collects logs and metrics across a subscription, and **Log Analytics** is its query engine, using **KQL (Kusto Query Language)**: a SQL-like language optimized for searching and correlating large volumes of time-series log data. A SOC analyst uses KQL to pivot across the Activity Log, NSG Flow Logs, Key Vault diagnostic logs, and VM guest logs all in one place, exactly the way a SIEM analyst would write a correlation search across CloudTrail and VPC Flow Logs in AWS.`,
      codeExample:
        "VM RUN COMMAND: CONTROL-PLANE CODE EXECUTION\n" +
        "=======================================================\n" +
        "operationName: MICROSOFT.COMPUTE/VIRTUALMACHINES/\n" +
        "               RUNCOMMAND/ACTION\n" +
        "\n" +
        "Requires: Contributor or Virtual Machine Contributor\n" +
        "          RBAC role on the target VM\n" +
        "\n" +
        "Bypasses: NSGs, network firewalls, SSH/RDP credentials\n" +
        "          entirely -- executes via Azure control plane,\n" +
        "          not the network\n" +
        "=======================================================\n\n" +
        "EXAMPLE KQL QUERY -- PIVOT ON A SUSPICIOUS CALLER\n" +
        "=======================================================\n" +
        "AzureActivity\n" +
        "| where CallerIpAddress == \"203.0.113.44\"\n" +
        "| where TimeGenerated between\n" +
        "    (datetime(2026-06-15T00:00:00Z) ..\n" +
        "     datetime(2026-06-15T12:00:00Z))\n" +
        "| project TimeGenerated, OperationNameValue,\n" +
        "          ResourceId, ActivityStatusValue, Caller\n" +
        "| order by TimeGenerated asc\n" +
        "=======================================================",
      checkpoint: {
        question:
          "A VM's NSG blocks all inbound traffic and nobody outside IT knows its admin password. Yet the Activity Log shows RUNCOMMAND/ACTION on it by an identity with Contributor rights, followed by a new local account appearing on the VM. How was that possible?",
        options: [
          "The caller must also have had the VM's admin password to log in before running it",
          "Run Command executes through the Azure control plane, so NSGs and VM logins don't apply",
          "The NSG must have been detached first, since its rules would block the VM agent",
          "Run Command creates accounts itself as part of its built-in diagnostic command set",
        ],
        answer: 1,
        explanation:
          "Run Command goes through the Azure Resource Manager API and the VM Agent, not the network, so NSG rules, firewalls and the VM's own login credentials never come into play. Anyone with Contributor or Virtual Machine Contributor rights on the VM can push a script, which is why the new local account could appear. 'Needed the admin password' misses the point: Run Command needs no login at all. 'The NSG was detached' is not required: NSGs govern network traffic, not the control-plane path. 'Built-in diagnostics create accounts' is wrong: Run Command executes whatever script the caller supplies, and that script created the account.",
      },
    },

    // ── Question 1 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "azure-q1",
      question:
        "A SOC analyst confirms the Azure Activity Log shows a Key Vault's access policy was updated (a control-plane event), but wants to know exactly WHICH secret was read and WHEN. The Activity Log alone does not show this. What is the most likely reason, and what should the analyst do?",
      options: [
        "Secret reads are written only to the Entra ID sign-in logs, since vault authentication counts as a sign-in event rather than a resource-access event",
        "The Activity Log records control-plane operations only; secret-level reads need diagnostic settings enabled on that vault to send audit events to Log Analytics",
        "Secret reads reach the Activity Log only for the Premium (HSM-backed) tier, so the analyst should first check whether the vault is Standard or Premium",
        "Data-plane audit records stay on the platform side, so the analyst must request the secret-access history from Microsoft support",
      ],
      answer: 1,
      explanation:
        "Just as AWS requires explicitly enabling S3 data event logging to see individual GetObject calls, Azure requires diagnostic settings to be configured on a specific resource (here, the Key Vault) to forward detailed data-plane events like individual secret reads into Log Analytics or a SIEM. The Activity Log by itself only captures control-plane (management) actions such as changing an access policy or creating the vault, not what happens to the data inside it. Secret reads are not permanently unavailable (they show up once diagnostic logging is enabled), they don't require a Microsoft support case (the customer can enable this themselves), and they are logged under Key Vault's own diagnostic logs, not Azure AD sign-in logs.",
      xp: 20,
    },

    // ── Question 2 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "azure-q2",
      question:
        "A suspicious Activity Log event shows idtyp 'app' and principalType 'ServicePrincipal', and carries no xms_mirid claim; looking the object up in Entra ID, its servicePrincipalType is 'Application' (an app registration). What is the KEY investigative difference versus an event whose token carried an xms_mirid claim and whose Entra object is of servicePrincipalType 'ManagedIdentity'?",
      options: [
        "Both authenticate with portable client secrets, so the difference is naming; the steps (rotate the secret, review sign-ins) are the same for each",
        "An app registration's secret or certificate can leak and be reused anywhere; a managed identity has none, so its risk sits in its host and its roles",
        "A managed identity is limited to read-only operations against Azure resources, while an app registration can also perform writes",
        "Service principals are reserved for Microsoft first-party services, so one in an event is a platform component; customer-created managed identities are the ones to scrutinize",
      ],
      answer: 1,
      explanation:
        "This distinction changes the entire investigation path. A leaked app-registration client secret works from anywhere, exactly like a leaked AWS IAM access key, until it's rotated, so you hunt for where it leaked and rotate it. A managed identity has no portable secret to steal: an attacker can only abuse it by compromising the resource (VM, web app, function) it's attached to and using its token, so you investigate that host and the identity's role assignments. 'Both use portable secrets' is wrong for managed identities, which have no secret to rotate. 'Managed identities are read-only' is false: they can do anything their RBAC roles allow, writes included. 'Service principals are Microsoft first-party only' is wrong: customers create app registrations all the time, and those are exactly what leak.",
      xp: 20,
    },

    // ── Question 3 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "azure-q3",
      question:
        "You see a burst of read-only operations (roleAssignments/read, vaults/read, storageAccounts/listKeys/action, virtualMachines/read) across dozens of different resources, all from one service principal that normally only ever calls one specific API. How should a SOC analyst interpret this pattern?",
      options: [
        "Low priority: every call is read-only, and read-only Resource Manager calls are not a stage of an attack sequence, so note it and close",
        "Likely reconnaissance: one identity enumerating many resource types is common early attacker behavior; the anomaly is its breadth and deviation from the identity's baseline",
        "Most likely a broken automation retry loop, since stolen credentials are used for targeted write actions rather than broad reads; check the pipeline's last deployment first",
        "Expected output of a posture-management scan that enumerates resources under a service principal, so suppress it without checking that principal's baseline",
      ],
      answer: 1,
      explanation:
        "Broad, read-only enumeration across many unrelated resource types, especially from an identity whose normal behavior is narrow and predictable, is a textbook reconnaissance signature: the cloud equivalent of an attacker who has gained a foothold running 'whoami' and mapping out what they can reach before taking further action. It should not be dismissed just because the individual calls are read-only; the anomaly is in the pattern and deviation from baseline, not any single call.",
      xp: 25,
    },

    // ── Log Analysis 1: Managed identity Key Vault secret access ────────────
    {
      type: "log_analysis" as const,
      id: "azure-la1",
      heading: "Investigating Managed Identity Access to a Key Vault Secret",
      context:
        "You are a SOC analyst at NexaCorp. A Microsoft Defender for Cloud alert fired for anomalous Key Vault access. The managed identity in question is attached to a public-facing web application and normally operates entirely from within NexaCorp's Azure virtual network. Review the event below, generated at 02:11 UTC.",
      event: managedIdentityKeyVaultEvent,
      questions: [
        {
          question:
            "The event's identity.claims.xms_mirid names the web app (nexacorp-webapp) (marking the caller as that app's managed identity) with role 'Key Vault Secrets User', calling SECRETS.GET from callerIpAddress 203.0.113.44. Why is the source IP the most important anomaly here, given the identity type?",
          options: [
            "It adds little: managed identity tokens are built to be used from any network",
            "Its token belongs to the web app, so a call from outside the app's addresses suggests theft",
            "It points to a logging fault, since callerIpAddress is left blank for managed identities",
            "It is expected: Key Vault calls are routed through Microsoft's CDN on public IPs",
          ],
          answer: 1,
          explanation:
            "A managed identity's token is issued to the resource it is attached to (here, the web app) and should be used by that resource itself, from its VNet or its own known outbound IPs. A Key Vault call from 203.0.113.44, outside those addresses, suggests the web app was compromised and its token was taken and reused elsewhere, like stolen EC2 instance credentials used from outside AWS. 'Built to be used from any network' confuses a managed identity with an app registration's portable secret. 'callerIpAddress is blank for managed identities' is false: the field is populated here, as it is for any caller. 'Routed through a CDN' is invented; Key Vault records the real client address.",
          xp: 25,
        },
        {
          question:
            "The requestUri names secrets/sql-connection-string, the Key Vault operation is SecretGet, and httpStatusCode is 200. What does that tell you about the outcome?",
          options: [
            "The secret's metadata was listed; a 200 here does not mean its value came back",
            "The secret's value was returned, so treat the database credentials it holds as exposed",
            "Key Vault received the request, but whether any value was returned cannot be known",
            "The read worked, but a connection string is low value because it holds no password",
          ],
          answer: 1,
          explanation:
            "SecretGet on a named secret (…/secrets/sql-connection-string) with HTTP 200 means Key Vault returned that secret's value to the caller: a completed read, not an attempt. Treat the database credentials inside it as compromised. 'Metadata was listed' describes a different operation (SecretList, against /secrets without a name). 'Received but unknown' misreads 200: for SecretGet, success is the return of the value. 'Low value' is wrong, SQL connection strings commonly embed the database username and password.",
          xp: 25,
        },
        {
          question:
            "What should the analyst's immediate containment actions be?",
          options: [
            "Leave it to the monthly rotation cycle, which will rotate this secret along with the rest",
            "Rotate the secret and its DB credential, narrow the identity's role, and investigate the web app",
            "Delete the Key Vault and build a new one, since every secret it held is now permanently lost",
            "Block 203.0.113.44 at the edge and close, since the attacker can no longer reach the vault",
          ],
          answer: 1,
          explanation:
            "A confirmed secret read needs the secret and the database credential behind it rotated now, the managed identity's role narrowed, the web app investigated for how its token was taken, and the vault's diagnostic logs reviewed for any other secrets the identity read. Waiting for the monthly rotation leaves a working database credential in the attacker's hands for weeks. Deleting the vault destroys evidence and breaks every app that uses it, while the stolen value still works until it is rotated. Blocking one IP does little: the attacker can change address, the compromised web app can still hand out tokens, and the stolen credential is still valid.",
          xp: 30,
        },
      ],
    },

    // ── Log Analysis 2: NSG RDP exposure + successful inbound connection ────
    {
      type: "log_analysis" as const,
      id: "azure-la2",
      heading: "Investigating an NSG Rule Change That Exposed RDP to the Internet",
      context:
        "Continuing the same incident timeline: 23 minutes after the Key Vault access, the Azure Activity Log recorded a network security rule change on the production VM's NSG, from the SAME managed identity involved in the earlier event (besides Key Vault Secrets User, the identity also holds an over-broad Contributor role on the resource group, which is what lets it edit NSG rules). The NSG flow log for that VM is shown alongside the change. Review the event below.",
      event: nsgRdpExposureEvent,
      questions: [
        {
          question:
            "Read the requestbody of the new rule 'allow-rdp-temp'. What does this rule do to the VM's exposure?",
          options: [
            "'*' covers hosts inside the VNet, so RDP stays reachable from internal addresses",
            "'*' means any internet address and 3389 is RDP, so remote desktop is open to the world",
            "Priority 100 is evaluated last, so the rule will rarely match before the existing rules do",
            "It opens 3389 outbound from the VM, so inbound connections to the VM are not affected",
          ],
          answer: 1,
          explanation:
            "sourceAddressPrefix '*' is Azure's wildcard for any source (including every host on the internet) and destinationPortRange 3389 is RDP, a remote-access service constantly targeted by password guessing. So the rule opens remote desktop on 10.40.2.15 to the whole world. A VNet-only rule would use a prefix such as 'VirtualNetwork' or a private range, not '*'. Priority works the other way round: lower numbers are evaluated FIRST, so 100 makes this rule win over most existing rules. The direction is 'Inbound', so it governs connections coming in to the VM, not traffic leaving it.",
          xp: 25,
        },
        {
          question:
            "Decode the azure.nsgflowlogs.flowTuples value in this event. What does it show?",
          options: [
            "An outbound RDP connection from the VM to 203.0.113.44 that the NSG denied",
            "An inbound TCP connection from 203.0.113.44 to 10.40.2.15:3389 that was allowed",
            "That a matching rule exists; flow logs cannot show that traffic really flowed",
            "An inbound attempt that was blocked, with 'A' marking that an alert was raised",
          ],
          answer: 1,
          explanation:
            "The tuple format is timestamp, source IP, destination IP, source port, destination port, protocol, direction, decision (version-2 logs add a flow state; the trailing B means the flow began). So: TCP (T), inbound (I), from 203.0.113.44 port 51422 to 10.40.2.15 port 3389, allowed (A). 203.0.113.44 is the same external IP that read the Key Vault secret: the attacker opened the door and then walked through it. 'Outbound and denied' misreads I and A: I is inbound, and the source is the external IP. 'That a rule exists' is wrong. Flow logs record actual flows. 'A marks an alert' is a misreading: A is the Allow decision (D would be Deny).",
          xp: 25,
        },
        {
          question:
            "Given both the Key Vault secret theft and the successful RDP connection are now tied to the same attacker and the same compromised managed identity, what is the correct escalation path?",
          options: [
            "Hand it to the infrastructure team as a config ticket, since NSG rule edits are routine work",
            "Escalate as a multi-stage compromise: remove the rule, isolate the VM, curb the identity, investigate",
            "Revoke the identity's Key Vault access, and treat the NSG change as separate network work",
            "Delete the RDP rule and close the case, with that door shut, the attacker has no way back in",
          ],
          answer: 1,
          explanation:
            "One compromised identity stole a secret, opened RDP to a production VM, and the same external IP then connected: an active, multi-stage compromise. Remove the rule, isolate the VM (without deleting it), cut back the identity's roles and rotate what it could reach, investigate what happened on the VM after the RDP session, and audit everything else the identity and resource group expose. 'A routine config ticket' ignores that the change came from a compromised identity and was used minutes later. 'Key Vault access only' leaves the identity's Contributor rights and the open RDP path in place. 'Delete the rule and close' ignores that the attacker already logged on to the VM and may have left persistence there.",
          xp: 30,
        },
      ],
    },

    // ── Analyst Choice: scheduled automation service principal FP trap ──────
    {
      type: "analyst_choice" as const,
      id: "azure-ac1",
      heading: "Verdict: Is This Service Principal's Storage Key Listing Suspicious?",
      scenario:
        "A SIEM correlation rule flagged a 'listKeys' action against a production storage account, since storage account keys grant full read/write access to all data in the account. The event below occurred at 06:00 UTC, performed by service principal 'sp-nightly-backup', from an internal Azure automation worker IP (10.40.1.9). Checking the change calendar, you find standing change CHG0041823 covering the nightly backup automation for nexacorpbackupsa, scheduled to run daily at 06:00 UTC. Is this event suspicious?",
      event: automationServicePrincipalEvent,
      correct_verdict: "false_positive",
      explanation:
        "This is a textbook false positive. The service principal sp-nightly-backup is calling listKeys, a sensitive action, but every contextual signal points to legitimate, expected automation: the source IP (10.40.1.9) is an internal Azure Automation Runbook worker, not an external address; the RBAC role held is the narrowly-scoped 'Storage Account Key Operator Service Role' (built specifically for this kind of automation, not a broad Contributor/Owner role); the timing (06:00 UTC) matches a recurring nightly schedule; and the change calendar holds an approved standing change (CHG0041823) for this exact recurring backup job. Correlation rules that alert purely on 'sensitive action name' without considering source, role scope, timing pattern, and change-management context will generate significant noise on routine automation.",
      fp_trap:
        "It's tempting to escalate immediately because listKeys against a storage account is a genuinely powerful, sensitive action. Full data access hinges on those keys. But treating every listKeys call as equally risky regardless of WHO called it, FROM WHERE, WITH WHAT ROLE, and WHETHER it matches an approved recurring schedule leads to alert fatigue. The distinguishing signals here, narrowly-scoped role, internal automation IP, consistent recurring timing, and a referenced change ticket. Are exactly what should be checked before escalating any sensitive-but-routine automation action, contrasted directly with the earlier Key Vault event where the SAME kind of sensitive action came from an external IP with no legitimate business context.",
      xp: 30,
    },

    // ── Matching: Azure concept <-> AWS/GCP equivalent ──────────────────────
    {
      type: "matching" as const,
      id: "azure-m1",
      heading: "Match Each Azure Concept to Its AWS/GCP Equivalent",
      instructions:
        "Match each Azure concept on the left to the closest AWS or GCP equivalent and its role on the right.",
      pairs: [
        {
          id: "subscription",
          left: "Subscription",
          right: "Equivalent to an AWS Account or a GCP Project: the basic unit of billing, access management, and the boundary a SOC analyst typically investigates within",
        },
        {
          id: "resourcegroup",
          left: "Resource Group",
          right: "A logical container grouping related resources (VMs, storage, networks) by application or environment: AWS/GCP have no single direct equivalent, relying more on tags or naming conventions",
        },
        {
          id: "managedidentity",
          left: "Managed Identity",
          right: "Equivalent to an AWS EC2 instance role or a GCP service account attached to a VM. Issues short-lived tokens automatically with no extractable long-term secret",
        },
        {
          id: "serviceprincipal",
          left: "Service Principal",
          right: "Equivalent to an AWS IAM user or a GCP service account key. Authenticates with a client secret or certificate that can be leaked and reused from anywhere",
        },
        {
          id: "nsg",
          left: "Network Security Group (NSG)",
          right: "Equivalent to an AWS Security Group or a GCP VPC firewall rule: a virtual firewall controlling inbound/outbound traffic to a subnet or network interface",
        },
        {
          id: "activitylog",
          left: "Azure Activity Log",
          right: "Equivalent to AWS CloudTrail or GCP Cloud Audit Logs: the control-plane audit trail recording every management operation performed on subscription resources",
        },
        {
          id: "defenderforcloud",
          left: "Microsoft Defender for Cloud",
          right: "Equivalent to AWS GuardDuty plus Security Hub, or GCP Security Command Center. Automated posture assessment and threat detection with pre-scored alerts",
        },
      ],
      explanation:
        "SOC analysts frequently move between AWS, Azure, and GCP tickets in the same shift, and confusing terminology across clouds is a common, costly mistake. Recognizing that a managed identity behaves like an EC2 instance role (no extractable secret) while a service principal behaves like an IAM user or downloaded service-account key (a leakable secret) is exactly the kind of cross-cloud pattern-matching that speeds up triage: the underlying attack techniques (credential theft, privilege escalation, public data exposure, disabled logging) are strikingly similar across all three providers, even when every name is different.",
      xp: 40,
    },

    // ── Reading 6: SIEM triage workflow for Azure ────────────────────────────
    {
      type: "reading" as const,
      id: "azure-r6",
      heading: "How to Triage an Azure Activity Log Alert in a SIEM",
      content:
        `Once Azure Activity Log, NSG Flow Log, and Key Vault diagnostic events are forwarded into a SIEM, they typically appear as structured fields prefixed with azure.activitylogs.*, azure.nsgflowlogs.*, or azure.keyvault.*: the exact fields you've been reviewing throughout this room. A consistent triage workflow turns these into a fast, repeatable investigation.\n\n` +
        `**Step 1: Establish the WHO**\n\n` +
        `Start with azure.activitylogs.identity.claims.idtyp and azure.activitylogs.identity.authorization.evidence.principalType. Is this a human user (principalType User) or a non-human identity (principalType ServicePrincipal, which covers BOTH managed identities and app registrations)? For a non-human identity, check for an azure.activitylogs.identity.claims.xms_mirid claim, or look the object up in Entra ID (servicePrincipalType ManagedIdentity vs Application). A managed identity has no extractable secret: the risk is over-granted permissions or a compromised host resource; an app-registration service principal authenticates with a client secret or certificate, check whether it could have been leaked, and when it was last rotated. Then check azure.activitylogs.caller: the object ID of the specific identity involved, which you can pivot on across the full timeline.\n\n` +
        `**Step 2: Establish the WHERE**\n\n` +
        `Check azure.activitylogs.callerIpAddress. Is it within your organization's known Azure VNet ranges, a known corporate office IP, or an unfamiliar external address? For managed identities specifically, ANY external IP is highly suspicious, since their tokens are meant to be used only by the specific resource they're attached to, from within Azure's own infrastructure.\n\n` +
        `**Step 3: Establish the WHAT and the OUTCOME**\n\n` +
        `Read azure.activitylogs.operationName together with azure.activitylogs.resourceId. This tells you the exact action (in the PROVIDER/RESOURCETYPE/ACTION format) and precisely which resource, resource group, and subscription were affected. Then check azure.activitylogs.resultType: 'Success' means the action completed, 'Failure' means it was rejected. A flood of 'Failure' results from one identity across many different resources is a strong signal of an attacker probing for working permissions.\n\n` +
        `**Step 4: Pivot and Correlate Across Log Layers**\n\n` +
        `Because Azure splits logging across the Activity Log (control-plane), resource diagnostic logs (data-plane detail), and NSG Flow Logs (network-layer), a single attacker action often only becomes fully clear when you correlate all three: an Activity Log entry might show an NSG rule was CHANGED, while NSG Flow Logs show whether that new rule was actually EXPLOITED with real traffic. Pivot on the same azure.activitylogs.caller and azure.activitylogs.callerIpAddress across a wide time window (hours to days) to reconstruct the full attack sequence: initial access (how the identity/credential was obtained), reconnaissance (broad read-only listing calls), privilege escalation or lateral movement (role assignment changes, NSG rule changes, Run Command executions), and the actual objective (secret theft, data exfiltration, or resource abuse).\n\n` +
        `**Step 5: Weigh Severity by Role Scope and Action Sensitivity, Not Just Identity Type**\n\n` +
        `As shown in the automation service-principal false-positive exercise, the same kind of sensitive action (like listing storage keys) can be entirely routine or a serious compromise depending on context. Always weigh: does the identity's assigned RBAC role match the narrow scope needed for this specific action (like the automation-specific Storage Account Key Operator Service Role), or does it hold broad Contributor/Owner permissions far beyond what the action requires? Does the timing match an established, recurring pattern, or is it a one-off deviation? A fast mental checklist (WHO, WHERE, WHAT, OUTCOME, PATTERN) triages the overwhelming majority of Azure Activity Log alerts within the first few minutes, the same way it does for CloudTrail or GCP Cloud Audit Logs.`,
      codeExample:
        "AZURE ACTIVITY LOG TRIAGE CHECKLIST\n" +
        "=======================================================\n" +
        "1. WHO    azure.activitylogs.identity.claims.idtyp /\n" +
        "          .authorization.evidence.principalType\n" +
        "          -> User, or ServicePrincipal (covers BOTH)\n" +
        "          -> xms_mirid claim present = managed identity\n" +
        "             (no leakable secret); absent = app\n" +
        "             registration (leakable client secret)\n" +
        "\n" +
        "2. WHERE  azure.activitylogs.callerIpAddress\n" +
        "          -> known VNet/office range, or unfamiliar\n" +
        "             external IP? (ANY external IP for a managed\n" +
        "             identity is highly suspicious)\n" +
        "\n" +
        "3. WHAT   azure.activitylogs.operationName + resourceId\n" +
        "          -> exact action + which resource/RG/subscription\n" +
        "\n" +
        "4. OUTCOME azure.activitylogs.resultType\n" +
        "          -> Success or Failure; a FLOOD of Failures =\n" +
        "             attacker probing for working permissions\n" +
        "\n" +
        "5. PATTERN pivot on same caller / callerIpAddress across\n" +
        "          Activity Log + NSG Flow Logs + diagnostic logs\n" +
        "          -> recon -> privesc/lateral movement -> objective?\n" +
        "=======================================================\n\n" +
        "EXAMPLE KQL CORRELATION QUERY\n" +
        "=======================================================\n" +
        "AzureActivity\n" +
        "| where Caller == \"a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d\"\n" +
        "| where TimeGenerated between\n" +
        "    (datetime(2026-06-15T00:00:00Z) ..\n" +
        "     datetime(2026-06-15T06:00:00Z))\n" +
        "| project TimeGenerated, OperationNameValue, ResourceId,\n" +
        "          ActivityStatusValue, CallerIpAddress\n" +
        "| order by TimeGenerated asc\n" +
        "=======================================================",
    },

    // ── Log Analysis: blob container opened + long-lived SAS — precedes the flag ──
    {
      type: "log_analysis" as const,
      id: "azure-la-storage",
      heading: "Data Exposure: A Container Is Opened to the World",
      context:
        "Twenty minutes after the RDP connection, the same managed identity made this storage change. Read it before answering the question and the flag.",
      event: storagePublicSasEvent,
      questions: [
        {
          question:
            "The requestbody sets publicAccess to 'Container' on the customer-exports container, and resultType is Success. What does this mean for the data inside it?",
          options: [
            "The container's name and metadata are exposed; the files themselves stay private",
            "Anyone can now list and read every blob in it anonymously, with no sign-in or token",
            "Anonymous reads still need a valid SAS token, so the files stay safe unless one leaks",
            "Files can be read by someone who knows a blob's exact URL, but not listed",
          ],
          answer: 1,
          explanation:
            "'Container' is the most open public-access level: anonymous users can list every blob in the container and read any of them, with no credential at all, and resultType Success means the change took effect. Close public access at once, then review the storage logs for anonymous reads of customer-exports to learn what was taken. 'Only metadata' understates it: the blobs themselves are readable. 'Still needs a SAS token' confuses public access with SAS: public access needs no token at all. 'Readable with the exact URL but not listed' describes the 'Blob' level, which does not allow listing; 'Container' does.",
          xp: 25,
        },
      ],
    },

    // ── Flag: extract value from raw storage/SAS event ──────────────────────
    {
      type: "flag" as const,
      id: "azure-f1",
      prompt:
        "To shut off any SAS tokens the attacker signed with the account keys, you will need to rotate the keys of the storage account that holds the exposed container. From the event above, enter the name of that storage account.",
      answer: "nexacorpprodsa",
      hint: "Every Azure resource ID lists the parent resources on its path, from the subscription down to the resource itself.",
      xp: 25,
    },

    // ── Reading 7 (bonus context for the flag event): SAS token abuse chain ──
    {
      type: "reading" as const,
      id: "azure-r7",
      heading: "Why a Long-Lived SAS Token Plus Public Container Access Is a Deliberate Exfiltration Setup",
      content:
        `The event referenced in the flag question above ties together two Azure-specific attack techniques that, combined, represent one of the most damaging and hardest-to-fully-remediate storage exposure patterns in Azure.\n\n` +
        `**Why SAS Tokens Are Especially Dangerous When Combined With Public Access**\n\n` +
        `On their own, a public container (public access level 'Container') already allows anyone who discovers its URL to read and list every blob inside it: no credential required at all. Generating a SAS token with broad permissions (rwdl: read, write, delete, list) and a multi-year expiry on TOP of that public exposure is redundant from a pure "can an outsider read this data" perspective, but it serves a different, more dangerous purpose: it gives the attacker (or anyone they share the token URL with) WRITE and DELETE capability as well, not just read, meaning data can be tampered with, ransomed, or destroyed, not merely stolen. In a real incident, seeing both a public-access change AND a long-lived, broad-permission SAS token generated close together for the same storage account is a strong indicator of deliberate, premeditated exposure: an attacker maximizing both data theft and data-integrity impact.\n\n` +
        `**Why SAS Tokens Are Especially Hard to Remediate**\n\n` +
        `Unlike an Azure AD credential or a role assignment, a SAS token generated from a storage account's account-level keys cannot always be individually revoked: the token is a cryptographically signed string, valid until its stated expiry, that Azure has no built-in way to invalidate on its own. The only way to fully invalidate an account-key-based SAS token before its expiry is to **regenerate the storage account's access keys** that the token was signed with, but doing so immediately breaks every OTHER legitimate SAS token and any application still using those same keys, making incident response here a genuine tradeoff between fully closing the exposure and causing a broader operational outage. This is precisely why security teams increasingly push for **stored access policies** (which CAN be revoked independently, by deleting the policy) or **Azure AD-based access** (user delegation SAS tokens, which respect Azure AD token lifetimes and Conditional Access policies) instead of raw account-key-based SAS tokens.\n\n` +
        `**Defensive Best Practices Every SOC Should Verify**\n\n` +
        `- Enable diagnostic logging on every Storage Account and Key Vault so that individual blob and secret access is actually visible, not just control-plane changes\n` +
        `- Alert immediately on any storage container public-access level change to 'Blob' or 'Container', regardless of which identity performed it\n` +
        `- Alert on SAS token generation with an expiry beyond a defined threshold (e.g. more than 24-48 hours) or with write/delete permissions when only read access is needed\n` +
        `- Prefer Azure AD-based access (user delegation SAS or RBAC) over account-key-based SAS tokens wherever possible, since Azure AD access can be revoked immediately and audited per-identity\n` +
        `- Enable Microsoft Defender for Storage, which specifically detects anomalous access patterns and public exposure of sensitive data`,
      codeExample:
        "ATTACK SEQUENCE: MANAGED IDENTITY THEFT -> NSG EXPOSURE -> STORAGE EXFIL\n" +
        "=======================================================\n" +
        "02:11  SECRETS.GET          Key Vault secret stolen via\n" +
        "                            compromised managed identity\n" +
        "02:34  SECURITYRULES/WRITE  NSG rule opened RDP to the\n" +
        "                            internet from same identity\n" +
        "02:5x  Inbound RDP ALLOW    Attacker connects to VM via\n" +
        "                            the newly-opened NSG rule\n" +
        "02:55  CONTAINERS/WRITE     Storage container public access\n" +
        "                            widened to 'Container', plus a\n" +
        "                            long-lived, broad-permission\n" +
        "                            SAS token generated\n" +
        "=======================================================\n\n" +
        "WHY THIS ORDER MATTERS\n" +
        "=======================================================\n" +
        "Each step expanded the attacker's foothold: identity ->\n" +
        "network access -> data exposure. SOC rule of thumb: any\n" +
        "public-access widening PLUS a long-lived SAS token on the\n" +
        "SAME storage account, generated close together, should be\n" +
        "treated as deliberate exfiltration staging, not routine\n" +
        "configuration drift.\n" +
        "=======================================================",
      checkpoint: {
        question:
          "The attacker holds a SAS token for nexacorpprodsa, signed with an account key and valid until 2027. You have already set the container back to Private. What actually invalidates the token now?",
        options: [
          "Delete the container it points to, so the signed URL has nothing left to return",
          "Let Defender for Storage handle it, since it revokes risky SAS tokens on detection",
          "Regenerate the account key that signed it, which also breaks every app using that key",
          "Nothing more, setting the container to Private already cancelled tokens issued for it",
        ],
        answer: 2,
        explanation:
          "Account-key-based SAS tokens are cryptographically signed strings that Azure cannot individually revoke. The only way to invalidate one before its expiry is regenerating the underlying storage account access keys, but that breaks every other SAS token and application relying on those same keys, forcing a tradeoff between closing the exposure and causing an outage. Deleting the resource does not invalidate the token itself (a same-named resource created before expiry would again be reachable). Defender for Storage detects and alerts on anomalous access. It does not automatically revoke credentials. And a SAS token's cryptographic validity is independent of the container's public-access level, so reverting to Private does nothing to the token itself.",
      },
    },

    // ── Reading 8: Containment actions once identity compromise is confirmed ─
    {
      type: "reading" as const,
      id: "azure-r8",
      heading: "Containing a Compromised Azure Identity",
      content:
        `Every reading in this room so far has built toward one skill: reading the Azure Activity Log, NSG Flow Logs, and Storage/Key Vault diagnostic events well enough to CONFIRM that a specific identity (a user, a managed identity, or a service principal) has been compromised. But confirming compromise is not the end of the job. Once a SOC analyst has enough evidence to say "this identity is compromised," the next question is immediate and practical: what do you actually DO about it, right now, in Azure?\n\n` +
        `**Revoke Sessions and Tokens, Not Just the Password**\n\n` +
        `The single most common containment mistake is resetting a compromised user's password and stopping there. A password reset does NOT invalidate a token or session that Azure AD/Entra ID already issued before the reset: a stolen refresh token, or an already-authenticated browser session, can keep working against Microsoft Graph, Azure Resource Manager, or Outlook Web Access for as long as that token remains valid, completely independent of whether the password changes. To actually cut off an attacker holding a live token, an analyst must explicitly **revoke the user's sessions**. In the Microsoft Entra admin center, this is the "Revoke sessions" action on a user's profile. From PowerShell, the legacy cmdlet is Revoke-AzureADUserAllRefreshToken -ObjectId <user-object-id>, though Microsoft has been retiring the older AzureAD PowerShell module in favor of Microsoft Graph PowerShell: the modern equivalent is Revoke-MgUserSignInSession -UserId <user-object-id> (Microsoft's documented replacement in the AzureAD-to-Graph cmdlet map). Either command invalidates every refresh token and session cookie issued to that user, meaning any application holding a stolen refresh token is forced to re-authenticate, and re-authentication will now fail once the password has also been reset and any registered MFA method the attacker added has been removed. One caveat: access tokens already issued stay valid until they expire (typically about an hour) unless the target service supports Continuous Access Evaluation (CAE), which can cut them off within minutes, so revocation is fast, but not instantaneous for every token.\n\n` +
        `**Disable the Account or Kill the Credential**\n\n` +
        `For a compromised human user, disabling the account outright (in the Entra admin center, or via PowerShell with Set-AzureADUser -ObjectId <user-object-id> -AccountEnabled $false, or the Graph equivalent Update-MgUser -UserId <user-object-id> -AccountEnabled:$false) is often faster and more certain than a password reset alone, especially as an immediate first move while the rest of the investigation continues. For a compromised **service principal**, there is no password to reset in the human sense, the equivalent action is to reset or remove its credential: delete the leaked client secret or certificate from the app registration (or add a new one and revoke the old), so nothing authenticating with the old secret can obtain a new token, regardless of how many systems or scripts had it cached.\n\n` +
        `**Isolate a Compromised VM Without Destroying It**\n\n` +
        `If the compromised identity is a managed identity attached to a virtual machine, or if the VM itself shows signs of compromise (unexpected run-command executions, unfamiliar processes, outbound connections to unfamiliar IPs): the correct network containment move is to apply a **Network Security Group rule** that denies all inbound and outbound traffic except from the forensics team's known IP range, at the highest priority (lowest priority number) so it is evaluated before any existing rule. Critically, do NOT delete or deallocate the VM. Deleting the VM destroys the exact evidence (memory state, running processes, disk contents) the investigation needs, and a deallocated VM loses its RAM contents entirely. Isolating the VM at the network layer stops the attacker from doing further damage or exfiltrating more data while leaving the machine itself intact for forensic imaging.\n\n` +
        `**Preserve Evidence Before Any Destructive Step**\n\n` +
        `Before applying any remediation step that could alter or destroy the VM's state (reimaging it, restoring from an old backup, or even rebooting it) take a **disk snapshot** of its OS disk and any attached data disks. A snapshot is a point-in-time, read-only copy that preserves exactly what the disk looked like at the moment of containment, and it can be attached to a separate forensic VM for offline analysis without touching the original, still-isolated machine. Skipping this step is one of the most common and costly incident-response mistakes: an analyst who reimages a compromised VM before snapshotting it has permanently destroyed the disk evidence needed to answer "how did the attacker get in, and what did they touch?"\n\n` +
        `**The Same Pattern You've Already Learned: Applied to Azure**\n\n` +
        `This sequence (isolate first, fully understand the scope, THEN eradicate) is the same incident-response pattern taught generally in this platform's Incident Response Methodology room. Here it is applied specifically to Azure: revoke tokens/sessions and disable the identity or kill its credential (stop the attacker from acting further as that identity), isolate the compromised VM at the network layer without deleting it (stop further damage while preserving evidence), snapshot before any destructive remediation (preserve the evidence), and only then move to eradication, removing malicious role assignments, rotating every credential the compromised identity could have touched, and rebuilding from a known-clean image rather than "cleaning" a machine that was already fully controlled by an attacker.`,
      codeExample:
        "AZURE IDENTITY COMPROMISE: CONTAINMENT CHECKLIST\n" +
        "=======================================================\n" +
        "1. REVOKE SESSIONS/TOKENS (do this FIRST -- a password\n" +
        "   reset alone does NOT invalidate an already-issued token)\n" +
        "   Entra admin center: user profile -> \"Revoke sessions\"\n" +
        "   PowerShell (legacy, being retired):\n" +
        "     Revoke-AzureADUserAllRefreshToken -ObjectId <user-id>\n" +
        "   PowerShell (Microsoft Graph, current):\n" +
        "     Revoke-MgUserSignInSession -UserId <user-id>\n" +
        "\n" +
        "2. DISABLE THE ACCOUNT / KILL THE CREDENTIAL\n" +
        "   Compromised user:\n" +
        "     Set-AzureADUser -ObjectId <user-id> -AccountEnabled $false\n" +
        "     (Graph equivalent: Update-MgUser -AccountEnabled:$false)\n" +
        "   Compromised service principal:\n" +
        "     Remove/rotate the leaked client secret or certificate\n" +
        "     on the app registration\n" +
        "\n" +
        "3. ISOLATE, DON'T DELETE, A COMPROMISED VM\n" +
        "   Apply an NSG rule at highest priority:\n" +
        "     direction: Inbound + Outbound\n" +
        "     access: Deny\n" +
        "     sourceAddressPrefix / destinationAddressPrefix: *\n" +
        "     EXCEPT an explicit Allow rule (lower priority number)\n" +
        "     for the forensics team's IP range only\n" +
        "   Do NOT delete or deallocate the VM -- deallocating loses\n" +
        "   RAM contents, deleting destroys the disk entirely.\n" +
        "\n" +
        "4. PRESERVE EVIDENCE BEFORE ANY DESTRUCTIVE STEP\n" +
        "   Take a disk snapshot of the OS disk + data disks BEFORE\n" +
        "   reimaging, restoring, or rebooting.\n" +
        "\n" +
        "5. ONLY THEN: eradicate -- remove malicious role assignments,\n" +
        "   rotate every credential the identity could have touched,\n" +
        "   rebuild from a known-clean image.\n" +
        "=======================================================",
      checkpoint: {
        question:
          "An analyst resets a compromised user's password at 09:00 and closes the task. At 09:40 Graph calls under that user are still arriving from the attacker's IP. What is the most likely explanation?",
        options: [
          "The reset has not replicated yet: Entra password changes take hours to apply",
          "A refresh token or session issued before the reset was never revoked, so it still works",
          "The attacker guessed the new password, because a reset always ends all existing sessions",
          "The calls come from a service principal, since user tokens die with a password change",
        ],
        answer: 1,
        explanation:
          "A password reset does not invalidate tokens or sessions issued before it. A stolen refresh token keeps working against Graph, Azure Resource Manager or Outlook Web Access until it is explicitly revoked: 'Revoke sessions' in the Entra admin center, or Revoke-MgUserSignInSession. (Even after revocation, an access token already issued can work until it expires, about an hour, unless the service supports Continuous Access Evaluation.) 'Replication takes hours' is not the cause: the new password applies quickly; the old tokens simply do not depend on it. 'Guessed the new password' rests on the false belief that a reset ends sessions. 'A service principal' is contradicted by the calls running as the user.",
      },
    },
  ],
};

export default [azureSecurityRoom];
