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
    "azure.activitylogs.identity.authorization.evidence.principalType": "ManagedIdentity",
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
    "azure.activitylogs.identity.authorization.evidence.principalType": "ManagedIdentity",
    "azure.activitylogs.caller": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
    "azure.activitylogs.callerIpAddress": "10.40.2.15",
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
    "azure.activitylogs.properties.changeTicket": "CHG0041823 - Approved nightly backup automation, recurring 06:00 UTC",
    "cloud.provider": "azure",
    "cloud.subscription_id": "8f3a9c2e-4b1d-4e7a-9c6f-1a2b3c4d5e6f",
    "action_result": "allowed",
  },
};

// ── Event 4 (flag task): storage account public blob access enabled + SAS token abuse ──
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
    "azure.activitylogs.identity.authorization.evidence.principalType": "ManagedIdentity",
    "azure.activitylogs.caller": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
    "azure.activitylogs.callerIpAddress": "203.0.113.44",
    "azure.activitylogs.properties.requestbody": "{\"properties\":{\"publicAccess\":\"Container\"}}",
    "azure.storage.sasTokenExpiry": "2027-06-15T00:00:00Z",
    "azure.storage.sasTokenPermissions": "rwdl",
    "azure.storage.accountName": "nexacorpprodsa",
    "azure.storage.containerName": "customer-exports",
    "cloud.provider": "azure",
    "cloud.subscription_id": "8f3a9c2e-4b1d-4e7a-9c6f-1a2b3c4d5e6f",
    "action_result": "allowed",
  },
};

const azureSecurityRoom = {
  id: "azure-security",
  title: "Azure IaaS Security for SOC Analysts",
  description:
    "Learn to investigate Microsoft Azure's cloud infrastructure layer as a SOC analyst — beyond Entra ID sign-ins and M365 mailboxes. Cover Azure's resource model (subscriptions, resource groups, RBAC role assignments, managed identities, service principals), the Azure Activity Log as the control-plane audit trail, Network Security Groups and NSG Flow Logs, Key Vault secret access, Storage Account exposure and SAS token abuse, VM run-command abuse, and Microsoft Defender for Cloud with Azure Monitor/Log Analytics (KQL) as the detection surface. Azure concepts are mapped throughout against the AWS and GCP equivalents you may already know.",
  difficulty: "intermediate" as const,
  category: "Cloud Security",
  estimatedMinutes: 70,
  xp: 675,
  icon: "🔷",
  prerequisites: ["cloud-security-monitoring"],
  tasks: [
    // ── Reading 1: What is Azure IaaS + resource model ──────────────────────
    {
      type: "reading" as const,
      id: "azure-r1",
      heading: "What Is Azure, and How Is Its Resource Model Organized?",
      content:
        `**Microsoft Azure** is Microsoft's cloud computing platform — the second-largest public cloud provider after AWS, and a very common choice for organizations already invested in Microsoft technology (Windows Server, Active Directory, Office 365). If your organization uses Azure, a meaningful share of the servers, databases, and storage a SOC analyst must protect exist as configurations inside an Azure subscription rather than in a physical server room.\n\n` +
        `This room focuses specifically on Azure's **infrastructure layer** — the virtual machines, storage accounts, networks, and secrets vaults that make up Azure IaaS (Infrastructure as a Service) and PaaS (Platform as a Service). Note that Azure AD/Entra ID sign-ins, Conditional Access, and mailbox/M365 activity are covered in a separate identity-focused room — here, the focus is the cloud infrastructure an attacker touches once they already have a foothold, or is trying to reach.\n\n` +
        `**The Azure Resource Hierarchy**\n\n` +
        `Everything in Azure sits inside a **subscription** — the basic unit of billing and access management, and the closest Azure equivalent to an AWS account or a GCP project. Inside a subscription, resources (virtual machines, storage accounts, key vaults, networks) are organized into **resource groups** — logical containers that group related resources together, typically by application or environment (for example, nexacorp-prod-rg holding every resource for the production web application). Subscriptions can be grouped under **management groups** for large organizations, similar to how AWS Organizations groups multiple accounts or how GCP folders group projects.\n\n` +
        `**Why Resource Groups Matter for Investigation**\n\n` +
        `Every Azure resource has a full **resourceId** path that always follows the same pattern: /subscriptions/{subscription-id}/resourceGroups/{resource-group-name}/providers/{provider-namespace}/{resource-type}/{resource-name}. This single string tells a SOC analyst exactly which subscription, which resource group, which Azure service (the "provider," such as Microsoft.Storage or Microsoft.KeyVault), and which specific resource were touched — it is the Azure equivalent of an AWS ARN (Amazon Resource Name) or a GCP resource name, and you will see it in nearly every log you investigate in this room.\n\n` +
        `**RBAC: How Permissions Actually Work in Azure**\n\n` +
        `Azure uses **RBAC (Role-Based Access Control)** to control who can do what. A **role assignment** binds three things together: a **security principal** (a user, group, managed identity, or service principal), a **role definition** (a set of allowed actions, such as the built-in Contributor, Reader, or Key Vault Secrets User roles), and a **scope** (the subscription, resource group, or individual resource the assignment applies to). This three-part model — principal + role + scope — is the single most important concept for understanding both legitimate access and privilege-escalation attacks in Azure, and it maps conceptually to an AWS IAM policy attached to a user, group, or role, though Azure's built-in roles are more standardized out of the box than AWS's fully custom JSON policies.`,
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
    },

    // ── Reading 2: Azure Activity Log vs CloudTrail/Cloud Audit Logs ────────
    {
      type: "reading" as const,
      id: "azure-r2",
      heading: "Azure Activity Log: The Control-Plane Audit Trail",
      content:
        `The **Azure Activity Log** is Azure's native audit-logging service for **control-plane** operations — every create, update, delete, or role-assignment action taken against a subscription's resources, whether performed through the Azure Portal, the Azure CLI, PowerShell, or an ARM/Bicep deployment template. If you already know AWS CloudTrail or GCP Cloud Audit Logs, the Activity Log fills the same role, but the terminology and structure differ enough to trip up an analyst moving between clouds.\n\n` +
        `**Key Fields in the Activity Log**\n\n` +
        `Each Activity Log entry captures: azure.activitylogs.operationName (the specific action, formatted as PROVIDER/RESOURCETYPE/ACTION, such as Microsoft.Storage/storageAccounts/blobServices/containers/write), azure.activitylogs.resourceId (the full path identifying exactly which resource was touched), azure.activitylogs.caller (the object ID of the identity that performed the action), azure.activitylogs.callerIpAddress (the source IP), azure.activitylogs.resultType (Success or Failure — Azure's equivalent of an empty vs populated error_code in CloudTrail), and azure.activitylogs.identity.claims (a set of claims describing the authenticated identity, including whether it is a user, a managed identity, or a service principal).\n\n` +
        `**Critical Terminology Contrast for Analysts Coming from AWS/GCP**\n\n` +
        `Where CloudTrail calls actions "management events" and "data events," and GCP Cloud Audit Logs splits activity into "Admin Activity" and "Data Access" logs, Azure instead splits its logging into entirely separate log categories that must each be understood on their own terms: the **Activity Log** (subscription-level control-plane actions, always on, retained 90 days by default), **Azure AD / Entra ID logs** (identity sign-ins and directory changes — covered in a separate room), **Resource-specific diagnostic logs** (deep, service-level logs like NSG Flow Logs, Key Vault audit events, or Storage Analytics logs — these must be explicitly enabled per-resource via **diagnostic settings**, similar to how S3 data events must be explicitly enabled in CloudTrail), and **Azure Monitor / Log Analytics** (the query and correlation layer that all of the above can be forwarded into, queried using **KQL**, Kusto Query Language).\n\n` +
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
        `A **managed identity** is an identity automatically created and managed by Azure AD for an Azure resource — most commonly a virtual machine, an App Service (web app), or an Azure Function. There are two flavors: a **system-assigned managed identity** is tied to the lifecycle of a single resource (created and deleted along with it), while a **user-assigned managed identity** is created independently and can be attached to multiple resources at once. The entire point of a managed identity is that the application code never handles a password or a secret — Azure automatically issues short-lived tokens behind the scenes, retrieved from a local, non-routable endpoint on the resource itself, conceptually identical to how an EC2 instance retrieves temporary IAM role credentials from AWS's IMDS at 169.254.169.254.\n\n` +
        `**Service Principal: The Identity Behind an "App Registration"**\n\n` +
        `A **service principal** is the local, tenant-specific representation of an **application registration** in Azure AD — it is what lets an application, a script, a CI/CD pipeline, or an automation Runbook authenticate to Azure APIs. Unlike a managed identity, a service principal typically authenticates with either a **client secret** (a long-lived password-like value, which can be leaked exactly like an AWS IAM user access key) or a **certificate**. Service principals are the identity type behind most third-party integrations, Terraform deployments, and scheduled automation jobs — and, like an over-permissioned AWS IAM user or a GCP service account with a downloaded JSON key, an over-privileged or leaked service principal is one of the most common paths to a serious Azure compromise.\n\n` +
        `**Why This Distinction Matters When Reading a Log**\n\n` +
        `In the Azure Activity Log, the azure.activitylogs.identity.claims.idtyp field of "app" tells you the caller is a non-human identity (either a managed identity or service principal), while azure.activitylogs.identity.authorization.evidence.principalType explicitly states which one — "ManagedIdentity" or "ServicePrincipal". This distinction directly changes your investigation path: a managed identity has no credential that can be independently leaked or phished (the risk is entirely about which permissions it was over-granted, and whether the resource it's attached to was compromised), whereas a service principal's client secret CAN be leaked on GitHub, in a CI/CD log, or in a configuration file, exactly like an AWS access key.\n\n` +
        `**The Over-Privileged Managed Identity Problem**\n\n` +
        `A very common real-world misconfiguration is granting a managed identity attached to a public-facing web application far broader RBAC permissions than the application actually needs — for example, granting Key Vault Secrets User (or worse, Contributor) scoped to the entire resource group, when the application only ever needs to read one specific secret. If that public-facing application is ever compromised (through a web vulnerability, a dependency confusion attack, or a leaked deployment credential), the attacker inherits every permission the managed identity holds — turning a single web app vulnerability into a much wider blast radius across Key Vaults, storage accounts, or other resources in the same resource group.`,
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
        "  .principalType   ManagedIdentity      ServicePrincipal\n" +
        "\n" +
        "Risk if attached   Attacker inherits    Leaked secret works\n" +
        "resource is        every RBAC role     from ANYWHERE until\n" +
        "compromised        the identity holds  rotated (like an\n" +
        "                                       AWS access key)\n" +
        "=======================================================",
    },

    // ── Reading 4: NSGs, NSG Flow Logs, Storage exposure, SAS tokens ────────
    {
      type: "reading" as const,
      id: "azure-r4",
      heading: "Network Security Groups, Storage Exposure, and SAS Token Abuse",
      content:
        `Three attack surfaces come up constantly in real Azure IaaS investigations: misconfigured network security rules, publicly exposed storage, and abused access tokens.\n\n` +
        `**Network Security Groups (NSGs): Azure's Virtual Firewall**\n\n` +
        `A **Network Security Group (NSG)** is Azure's virtual firewall, attached to a subnet or a network interface, that controls inbound and outbound traffic using ordered allow/deny rules — the direct equivalent of an AWS Security Group or a GCP VPC firewall rule. Each NSG rule specifies a direction (Inbound/Outbound), an access decision (Allow/Deny), a protocol, a source/destination address prefix, and a destination port range, along with a numeric priority (lower numbers are evaluated first). A dangerously common misconfiguration is a rule with sourceAddressPrefix "*" (meaning "any source on the internet") allowing a sensitive port like 3389 (RDP) or 22 (SSH) or 1433 (SQL Server) — effectively opening a direct door from the entire internet to a production server.\n\n` +
        `**NSG Flow Logs: Azure's NetFlow**\n\n` +
        `**NSG Flow Logs** record the actual connections that were evaluated by an NSG's rules — source IP, destination IP, source port, destination port, protocol, and whether the flow was Allowed (A) or Denied (D) — conceptually identical to AWS VPC Flow Logs or GCP VPC Flow Logs. The flowTuples field packs this information into a compact comma-separated format: timestamp, source IP, destination IP, source port, destination port, protocol, flow direction (Inbound/Outbound), and the allow/deny decision. A SOC analyst correlates an NSG rule CHANGE (from the Activity Log) with the actual TRAFFIC that flowed as a result (from NSG Flow Logs) to confirm whether a risky rule was just created, or was created AND actively exploited.\n\n` +
        `**Storage Account Public Exposure**\n\n` +
        `An Azure **Storage Account** holds **blob containers** (similar to S3 buckets or Cloud Storage buckets), and each container has a **public access level** setting: Private (no anonymous access), Blob (anonymous read access to individual blobs if you know the exact URL), or Container (anonymous read access AND the ability to list every blob in the container — the most dangerous setting). Changing this setting to Container on a container holding customer exports or backups is one of the most common and damaging real-world Azure misconfigurations, directly analogous to a public S3 bucket or a public GCS bucket.\n\n` +
        `**SAS Tokens: Azure's Scoped, Shareable Access Keys**\n\n` +
        `A **SAS (Shared Access Signature) token** is a signed URL parameter that grants time-limited, scoped access to a storage resource without sharing the storage account's master key — useful for giving a partner or an application temporary access to a single container. However, a SAS token generated with overly broad permissions (rwdl — read, write, delete, list) and a far-future expiry (months or years away instead of hours) behaves exactly like a long-lived, hard-to-revoke credential: anyone who obtains the URL has full access until the token's expiry date, and unlike an Azure AD credential, a SAS token cannot always be individually revoked without regenerating the storage account's underlying access keys (which breaks every other SAS token issued from those keys too). A newly-generated SAS token with a multi-year expiry, especially one appearing alongside a container's public-access setting being widened, is a strong signal of deliberate data-exposure setup — whether by a careless administrator or an attacker preparing for exfiltration.`,
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
    },

    // ── Reading 5: VM run-command abuse & resource enumeration ─────────────
    {
      type: "reading" as const,
      id: "azure-r5",
      heading: "VM Run-Command and Custom Script Extension Abuse, and Resource Enumeration",
      content:
        `Beyond identity and network misconfigurations, attackers with sufficient RBAC permissions on an Azure subscription have a uniquely powerful tool available: the ability to execute arbitrary code directly on a virtual machine, without ever needing to log in through SSH or RDP.\n\n` +
        `**VM Run Command: Remote Code Execution Through the Control Plane**\n\n` +
        `Azure's **Run Command** feature (operation name Microsoft.Compute/virtualMachines/runCommand/action) lets anyone with the right RBAC role — most commonly Contributor or Virtual Machine Contributor on the VM — execute a PowerShell or Bash script directly on the VM's operating system through the Azure control plane, using the Azure VM Agent installed on nearly every VM by default. Because this happens through the Azure Resource Manager API rather than through the network, it completely bypasses network-layer defenses like NSGs, firewalls, or even the requirement to know the VM's actual login credentials. If an attacker compromises an identity with Contributor rights on a subscription or resource group (for example, through a stolen service principal secret or an over-privileged managed identity), they can use Run Command to execute code on every VM in scope — a devastating lateral movement and code-execution primitive that many defenders don't think to monitor at the control-plane layer.\n\n` +
        `**Custom Script Extension: The Same Risk, Deployed at VM Creation**\n\n` +
        `The **Custom Script Extension** (Microsoft.Compute/virtualMachines/extensions/write with a publisher of Microsoft.Compute.CustomScriptExtension) achieves a very similar outcome — it downloads and executes a script on a VM, typically used legitimately during VM provisioning to install software or apply configuration. An attacker with Contributor-level access can attach a malicious Custom Script Extension to an existing, already-running production VM at any time, not just at creation, making unexpected extension installations on a long-running VM a strong signal worth investigating.\n\n` +
        `**Azure Resource Enumeration: The Reconnaissance Phase**\n\n` +
        `Just as an AWS attacker runs DescribeInstances and ListBuckets, or a GCP attacker runs compute.instances.list, an attacker who has gained any foothold in an Azure subscription will typically enumerate what they have access to using read-only calls: listing role assignments (Microsoft.Authorization/roleAssignments/read) to understand their own and others' permissions, listing Key Vaults and their secrets' names (though not values, without explicit Get permission), listing storage accounts and their keys, and listing virtual machines and their network configurations. A burst of read-only "list" and "get" operations across many different resource types, from a single identity in a short time window, is a classic reconnaissance pattern — individually benign, but suspicious in aggregate, especially from an identity that does not normally perform broad enumeration.\n\n` +
        `**Microsoft Defender for Cloud: Azure's Built-In Threat Detector**\n\n` +
        `**Microsoft Defender for Cloud** (formerly Azure Security Center) is Azure's native Cloud Security Posture Management (CSPM) and threat-detection service — the rough equivalent of AWS GuardDuty combined with AWS Security Hub, or GCP's Security Command Center. It continuously assesses subscriptions against security best practices (flagging things like publicly exposed storage containers, NSGs allowing unrestricted RDP/SSH, or Key Vaults without diagnostic logging enabled) and separately raises real-time threat alerts (such as "Suspicious Azure Resource Manager operation" or unusual Run Command execution) using both rule-based detections and machine-learning models trained on Microsoft's threat intelligence. Just like GuardDuty findings, Defender for Cloud alerts arrive pre-scored with a severity and description, making them a strong Tier-1 starting point — but the underlying Activity Log and diagnostic log entries remain where the deep investigation happens.\n\n` +
        `**Azure Monitor and Log Analytics: The Query Layer**\n\n` +
        `**Azure Monitor** is the umbrella platform that collects logs and metrics across a subscription, and **Log Analytics** is its query engine, using **KQL (Kusto Query Language)** — a SQL-like language optimized for searching and correlating large volumes of time-series log data. A SOC analyst uses KQL to pivot across the Activity Log, NSG Flow Logs, Key Vault diagnostic logs, and VM guest logs all in one place, exactly the way a SIEM analyst would write a correlation search across CloudTrail and VPC Flow Logs in AWS.`,
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
    },

    // ── Question 1 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "azure-q1",
      question:
        "A SOC analyst confirms the Azure Activity Log shows a Key Vault's access policy was updated (a control-plane event), but wants to know exactly WHICH secret was read and WHEN. The Activity Log alone does not show this. What is the most likely reason, and what should the analyst do?",
      options: [
        "Azure never logs individual secret reads under any circumstances — this information is permanently unavailable",
        "The Activity Log only records control-plane (management) operations by default; secret-level read events require diagnostic settings to be explicitly enabled on that specific Key Vault to forward detailed audit events into Log Analytics",
        "The analyst must contact Microsoft Support directly, as this data is never accessible to customers",
        "Secret reads are recorded in Azure AD sign-in logs instead, not in any Key Vault-related log",
      ],
      answer: 1,
      explanation:
        "Just as AWS requires explicitly enabling S3 data event logging to see individual GetObject calls, Azure requires diagnostic settings to be configured on a specific resource (here, the Key Vault) to forward detailed data-plane events like individual secret reads into Log Analytics or a SIEM. The Activity Log by itself only captures control-plane (management) actions such as changing an access policy or creating the vault — not what happens to the data inside it.",
      xp: 20,
    },

    // ── Question 2 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "azure-q2",
      question:
        "An analyst sees azure.activitylogs.identity.claims.idtyp: 'app' and azure.activitylogs.identity.authorization.evidence.principalType: 'ServicePrincipal' on a suspicious event. What is the KEY investigative difference versus if this had instead shown principalType: 'ManagedIdentity'?",
      options: [
        "There is no difference — both identity types behave identically in every respect",
        "A service principal typically authenticates with a client secret or certificate that can be independently leaked (e.g. committed to a code repository) and reused from anywhere, whereas a managed identity has no such extractable credential — its risk is entirely about over-granted permissions and the security of the resource it's attached to",
        "Managed identities can only be used for read-only operations, while service principals can only perform write operations",
        "Service principals are exclusively used by Microsoft's own internal services and can be ruled out as a compromise vector",
      ],
      answer: 1,
      explanation:
        "This distinction changes the entire investigation path. A leaked service principal client secret works from anywhere, exactly like a leaked AWS IAM access key, until it's rotated. A managed identity has no portable secret to steal — an attacker can only abuse it by compromising the specific resource (VM, web app, function) it's attached to, or by exploiting the fact that it was granted excessive permissions in the first place.",
      xp: 20,
    },

    // ── Question 3 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "azure-q3",
      question:
        "You see a burst of read-only operations (roleAssignments/read, vaults/read, storageAccounts/listKeys/action, virtualMachines/read) across dozens of different resources, all from one service principal that normally only ever calls one specific API. How should a SOC analyst interpret this pattern?",
      options: [
        "Ignore it completely — all of these operations are individually read-only and therefore can never be part of an attack",
        "This is a classic reconnaissance pattern: an identity enumerating what it has access to across many resource types is a common early-stage attacker behavior, even though no single call is destructive on its own — the anomaly is in the breadth and deviation from that identity's normal behavior",
        "This confirms the service principal's credentials have definitely NOT been compromised, since no write operations occurred",
        "This pattern only ever occurs during planned infrastructure audits and should be automatically suppressed",
      ],
      answer: 1,
      explanation:
        "Broad, read-only enumeration across many unrelated resource types, especially from an identity whose normal behavior is narrow and predictable, is a textbook reconnaissance signature — the cloud equivalent of an attacker who has gained a foothold running 'whoami' and mapping out what they can reach before taking further action. It should not be dismissed just because the individual calls are read-only; the anomaly is in the pattern and deviation from baseline, not any single call.",
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
            "The event shows azure.activitylogs.identity.authorization.evidence.principalType as 'ManagedIdentity' with role 'Key Vault Secrets User', calling SECRETS.GET from callerIpAddress 203.0.113.44. Why is the source IP the most important anomaly here, given the identity type?",
          options: [
            "Managed identities are designed to be used from any IP address worldwide, so the source IP is irrelevant",
            "Managed identities issue tokens that are meant to be used only from within Azure's own infrastructure serving that specific resource — legitimate use should originate from the web app's own outbound IP or Azure's internal ranges, not from an external, unfamiliar public IP like 203.0.113.44",
            "The source IP field is only populated for human users, never for managed identities, so this must be a logging error",
            "This IP being external is expected because all Key Vault traffic is routed through Microsoft's global CDN, which uses public IPs",
          ],
          answer: 1,
          explanation:
            "A managed identity's tokens are scoped to the resource they're attached to (here, a public-facing web app) and are meant to be used by that resource itself, from within Azure's infrastructure. Seeing the identity's token used to call Key Vault from an external IP like 203.0.113.44 — rather than the web app's expected outbound IP — is a strong signal the web application itself has been compromised and its managed identity token is being exfiltrated and reused externally, similar to stolen EC2 IMDS credentials being used from outside AWS.",
          xp: 25,
        },
        {
          question:
            "The requestUri shows 'https://nexacorp-prod-kv.vault.azure.net/secrets/sql-connection-string' with httpStatusCode 200 and azure.activitylogs.resultType 'Success'. What does this confirm about the outcome?",
          options: [
            "The request failed, since a 200 status code always indicates an error in Azure APIs",
            "The request succeeded — the attacker (via the compromised web app's managed identity) successfully retrieved the actual value of the sql-connection-string secret, meaning database credentials have very likely been compromised",
            "A 200 status code only confirms the request was received, not that any data was returned",
            "resultType 'Success' only applies to control-plane operations, not to Key Vault secret retrieval",
          ],
          answer: 1,
          explanation:
            "An HTTP 200 status combined with resultType 'Success' on a SecretGet/SECRETS.GET operation confirms the secret value was actually returned to the caller — this is not a failed or denied attempt. Because the secret is named sql-connection-string, the analyst should treat the underlying database credentials as compromised and assume the attacker can now directly access the database itself.",
          xp: 25,
        },
        {
          question:
            "What should the analyst's immediate containment actions be?",
          options: [
            "Wait for a scheduled monthly secret-rotation cycle before taking any action",
            "Immediately rotate the sql-connection-string secret (and the underlying database credential it represents), restrict or remove the managed identity's Key Vault Secrets User role to only the minimum required scope, investigate the web app itself for the initial compromise vector (e.g. a vulnerability that allowed token exfiltration), and review Key Vault access logs for any other secrets the same identity may have retrieved",
            "Simply delete the Key Vault, since it is now considered fully compromised",
            "Block callerIpAddress 203.0.113.44 at the network layer and consider the incident resolved, since Key Vault access is control-plane only and cannot be abused further",
          ],
          answer: 1,
          explanation:
            "A confirmed secret compromise requires immediate credential rotation of the exposed secret (and whatever system it authenticates to, here a database), scoping down the managed identity's over-broad role assignment, root-causing how the web app itself was compromised (since that's how the attacker reached the managed identity's token in the first place), and auditing the full scope of what else the same identity accessed. Blocking a single IP does nothing since the attacker can trivially rotate infrastructure, and the underlying web app compromise plus leaked secret both remain live risks until addressed.",
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
        "Continuing the same incident timeline: 23 minutes after the Key Vault access, the Azure Activity Log recorded a network security rule change on the production VM's NSG, from the SAME managed identity involved in the earlier event. NSG Flow Logs shortly after show a successful inbound connection matching the new rule. Review the event below.",
      event: nsgRdpExposureEvent,
      questions: [
        {
          question:
            "The requestbody shows direction 'Inbound', access 'Allow', destinationPortRange '3389', sourceAddressPrefix '*', and priority 100 for a new rule named 'allow-rdp-temp', created by the same managed identity as the Key Vault event. Why is sourceAddressPrefix '*' combined with destinationPortRange '3389' especially dangerous?",
          options: [
            "Port 3389 is a harmless, commonly-used web port with no special sensitivity",
            "sourceAddressPrefix '*' means ANY IP address on the entire internet is allowed to attempt this connection, and port 3389 is RDP (Remote Desktop Protocol) — this rule effectively opens direct remote-desktop access to the VM from anywhere in the world",
            "The priority value of 100 means this rule has the LOWEST possible priority and will almost never be evaluated",
            "This rule only affects outbound traffic, so inbound connections are unaffected",
          ],
          answer: 1,
          explanation:
            "sourceAddressPrefix '*' is Azure's wildcard for 'any source,' meaning the rule allows connections from literally any internet-connected host. Port 3389 is RDP, a highly sensitive remote-access protocol frequently targeted by brute-force and credential-stuffing attacks. Additionally, priority 100 is a LOW number, and Azure NSG rules evaluate lower priority numbers FIRST — meaning this permissive rule would be evaluated before more restrictive higher-priority-number rules, making it highly likely to take effect immediately.",
          xp: 25,
        },
        {
          question:
            "The NSG Flow Log flowTuples field reads '1781490891,203.0.113.44,10.40.2.15,51422,3389,T,I,A' — decode this and explain its significance given the earlier Key Vault event.",
          options: [
            "This shows an outbound denied connection with no relevance to the investigation",
            "This decodes to a TCP (T) inbound (I) connection from 203.0.113.44 (the SAME external IP seen abusing the managed identity's Key Vault access) to 10.40.2.15 on port 3389, and it was ALLOWED (A) — confirming the attacker didn't just open the door, they walked through it and successfully connected to the VM's RDP port",
            "The flow log only proves the rule exists; it cannot show whether any actual network traffic occurred",
            "This IP address belongs to NexaCorp's internal network, so the connection is expected and benign",
          ],
          answer: 1,
          explanation:
            "The flowTuples format is timestamp,srcIP,dstIP,srcPort,dstPort,protocol,direction,decision. Decoding it: TCP, Inbound, from 203.0.113.44 to 10.40.2.15 on port 3389, Allowed. Critically, 203.0.113.44 is the exact same external IP that abused the managed identity's Key Vault access minutes earlier, tying both events to the same attacker and confirming they didn't just create a permissive rule — they actively exploited it to reach the VM's RDP service.",
          xp: 25,
        },
        {
          question:
            "Given both the Key Vault secret theft and the successful RDP connection are now tied to the same attacker and the same compromised managed identity, what is the correct escalation path?",
          options: [
            "Treat this as a routine network configuration change ticket, since NSG rule modifications happen frequently in normal operations",
            "Escalate immediately as an active, multi-stage cloud compromise: remove or restrict the malicious NSG rule, isolate the affected VM from the network, rotate the managed identity's permissions and any credentials it exposed, forensically investigate the VM for what the attacker did after connecting via RDP, and audit all other resources reachable by the same identity and resource group",
            "Only revoke the Key Vault access, since the NSG rule change is unrelated infrastructure work",
            "No further action is needed since Microsoft Defender for Cloud will automatically remediate the NSG rule within 24 hours"
          ],
          answer: 1,
          explanation:
            "This is now a confirmed, multi-stage active compromise: a compromised managed identity was used first to steal a Key Vault secret, then to open a network path (RDP) into a production VM, which was then actively connected to from the same external attacker IP. This requires full incident response: immediately remove/restrict the malicious NSG rule, isolate the VM to stop further attacker access, rotate every credential the managed identity could reach, forensically examine the VM for post-RDP-access activity (webshells, new accounts, persistence), and audit the full blast radius of what else this identity and resource group expose.",
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
        "A SIEM correlation rule flagged a 'listKeys' action against a production storage account, since storage account keys grant full read/write access to all data in the account. The event below occurred at 06:00 UTC, performed by service principal 'sp-nightly-backup', from an internal Azure automation worker IP (10.40.1.9), with a linked change-ticket reference in the event properties. Is this event suspicious?",
      event: automationServicePrincipalEvent,
      correct_verdict: "false_positive",
      explanation:
        "This is a textbook false positive. The service principal sp-nightly-backup is calling listKeys — a sensitive action — but every contextual signal points to legitimate, expected automation: the source IP (10.40.1.9) is an internal Azure Automation Runbook worker, not an external address; the RBAC role held is the narrowly-scoped 'Storage Account Key Operator Service Role' (built specifically for this kind of automation, not a broad Contributor/Owner role); the timing (06:00 UTC) matches a recurring nightly schedule; and the event properties reference an approved change ticket (CHG0041823) for this exact recurring backup job. Correlation rules that alert purely on 'sensitive action name' without considering source, role scope, timing pattern, and change-management context will generate significant noise on routine automation.",
      fp_trap:
        "It's tempting to escalate immediately because listKeys against a storage account is a genuinely powerful, sensitive action — full data access hinges on those keys. But treating every listKeys call as equally risky regardless of WHO called it, FROM WHERE, WITH WHAT ROLE, and WHETHER it matches an approved recurring schedule leads to alert fatigue. The distinguishing signals here — narrowly-scoped role, internal automation IP, consistent recurring timing, and a referenced change ticket — are exactly what should be checked before escalating any sensitive-but-routine automation action, contrasted directly with the earlier Key Vault event where the SAME kind of sensitive action came from an external IP with no legitimate business context.",
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
          right: "Equivalent to an AWS Account or a GCP Project — the basic unit of billing, access management, and the boundary a SOC analyst typically investigates within",
        },
        {
          id: "resourcegroup",
          left: "Resource Group",
          right: "A logical container grouping related resources (VMs, storage, networks) by application or environment — AWS/GCP have no single direct equivalent, relying more on tags or naming conventions",
        },
        {
          id: "managedidentity",
          left: "Managed Identity",
          right: "Equivalent to an AWS EC2 instance role or a GCP service account attached to a VM — issues short-lived tokens automatically with no extractable long-term secret",
        },
        {
          id: "serviceprincipal",
          left: "Service Principal",
          right: "Equivalent to an AWS IAM user or a GCP service account key — authenticates with a client secret or certificate that can be leaked and reused from anywhere",
        },
        {
          id: "nsg",
          left: "Network Security Group (NSG)",
          right: "Equivalent to an AWS Security Group or a GCP VPC firewall rule — a virtual firewall controlling inbound/outbound traffic to a subnet or network interface",
        },
        {
          id: "activitylog",
          left: "Azure Activity Log",
          right: "Equivalent to AWS CloudTrail or GCP Cloud Audit Logs — the control-plane audit trail recording every management operation performed on subscription resources",
        },
        {
          id: "defenderforcloud",
          left: "Microsoft Defender for Cloud",
          right: "Equivalent to AWS GuardDuty plus Security Hub, or GCP Security Command Center — automated posture assessment and threat detection with pre-scored alerts",
        },
      ],
      explanation:
        "SOC analysts frequently move between AWS, Azure, and GCP tickets in the same shift, and confusing terminology across clouds is a common, costly mistake. Recognizing that a managed identity behaves like an EC2 instance role (no extractable secret) while a service principal behaves like an IAM user or downloaded service-account key (a leakable secret) is exactly the kind of cross-cloud pattern-matching that speeds up triage — the underlying attack techniques (credential theft, privilege escalation, public data exposure, disabled logging) are strikingly similar across all three providers, even when every name is different.",
      xp: 40,
    },

    // ── Reading 6: SIEM triage workflow for Azure ────────────────────────────
    {
      type: "reading" as const,
      id: "azure-r6",
      heading: "How to Triage an Azure Activity Log Alert in a SIEM",
      content:
        `Once Azure Activity Log, NSG Flow Log, and Key Vault diagnostic events are forwarded into a SIEM, they typically appear as structured fields prefixed with azure.activitylogs.*, azure.nsgflowlogs.*, or azure.keyvault.* — the exact fields you've been reviewing throughout this room. A consistent triage workflow turns these into a fast, repeatable investigation.\n\n` +
        `**Step 1 — Establish the WHO**\n\n` +
        `Start with azure.activitylogs.identity.claims.idtyp and azure.activitylogs.identity.authorization.evidence.principalType. Is this a human user, a ManagedIdentity (no extractable secret — the risk is over-granted permissions or a compromised host resource), or a ServicePrincipal (authenticates with a client secret or certificate — check whether it could have been leaked, and when it was last rotated)? Then check azure.activitylogs.caller — the object ID of the specific identity involved, which you can pivot on across the full timeline.\n\n` +
        `**Step 2 — Establish the WHERE**\n\n` +
        `Check azure.activitylogs.callerIpAddress. Is it within your organization's known Azure VNet ranges, a known corporate office IP, or an unfamiliar external address? For managed identities specifically, ANY external IP is highly suspicious, since their tokens are meant to be used only by the specific resource they're attached to, from within Azure's own infrastructure.\n\n` +
        `**Step 3 — Establish the WHAT and the OUTCOME**\n\n` +
        `Read azure.activitylogs.operationName together with azure.activitylogs.resourceId — this tells you the exact action (in the PROVIDER/RESOURCETYPE/ACTION format) and precisely which resource, resource group, and subscription were affected. Then check azure.activitylogs.resultType: 'Success' means the action completed, 'Failure' means it was rejected. A flood of 'Failure' results from one identity across many different resources is a strong signal of an attacker probing for working permissions.\n\n` +
        `**Step 4 — Pivot and Correlate Across Log Layers**\n\n` +
        `Because Azure splits logging across the Activity Log (control-plane), resource diagnostic logs (data-plane detail), and NSG Flow Logs (network-layer), a single attacker action often only becomes fully clear when you correlate all three: an Activity Log entry might show an NSG rule was CHANGED, while NSG Flow Logs show whether that new rule was actually EXPLOITED with real traffic. Pivot on the same azure.activitylogs.caller and azure.activitylogs.callerIpAddress across a wide time window (hours to days) to reconstruct the full attack sequence: initial access (how the identity/credential was obtained), reconnaissance (broad read-only listing calls), privilege escalation or lateral movement (role assignment changes, NSG rule changes, Run Command executions), and the actual objective (secret theft, data exfiltration, or resource abuse).\n\n` +
        `**Step 5 — Weigh Severity by Role Scope and Action Sensitivity, Not Just Identity Type**\n\n` +
        `As shown in the automation service-principal false-positive exercise, the same kind of sensitive action (like listing storage keys) can be entirely routine or a serious compromise depending on context. Always weigh: does the identity's assigned RBAC role match the narrow scope needed for this specific action (like the automation-specific Storage Account Key Operator Service Role), or does it hold broad Contributor/Owner permissions far beyond what the action requires? Does the timing match an established, recurring pattern, or is it a one-off deviation? A fast mental checklist — WHO, WHERE, WHAT, OUTCOME, PATTERN — triages the overwhelming majority of Azure Activity Log alerts within the first few minutes, the same way it does for CloudTrail or GCP Cloud Audit Logs.`,
      codeExample:
        "AZURE ACTIVITY LOG TRIAGE CHECKLIST\n" +
        "=======================================================\n" +
        "1. WHO    azure.activitylogs.identity.claims.idtyp /\n" +
        "          .authorization.evidence.principalType\n" +
        "          -> ManagedIdentity (no leakable secret) or\n" +
        "             ServicePrincipal (leakable client secret)?\n" +
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

    // ── Flag: extract value from raw storage/SAS event ──────────────────────
    {
      type: "flag" as const,
      id: "azure-f1",
      prompt:
        "Review the event above where blob container public access was changed shortly after a long-lived SAS token was generated for the storage account. What is the exact value of the azure.storage.containerName field — i.e. the name of the container whose public access was widened? Enter it exactly as shown.",
      answer: "customer-exports",
      hint: "Look inside the raw block of the storage/SAS event for the azure.storage.containerName field — this identifies which specific blob container the attacker exposed.",
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
        `On their own, a public container (public access level 'Container') already allows anyone who discovers its URL to read and list every blob inside it — no credential required at all. Generating a SAS token with broad permissions (rwdl: read, write, delete, list) and a multi-year expiry on TOP of that public exposure is redundant from a pure "can an outsider read this data" perspective, but it serves a different, more dangerous purpose: it gives the attacker (or anyone they share the token URL with) WRITE and DELETE capability as well, not just read — meaning data can be tampered with, ransomed, or destroyed, not merely stolen. In a real incident, seeing both a public-access change AND a long-lived, broad-permission SAS token generated close together for the same storage account is a strong indicator of deliberate, premeditated exposure — an attacker maximizing both data theft and data-integrity impact.\n\n` +
        `**Why SAS Tokens Are Especially Hard to Remediate**\n\n` +
        `Unlike an Azure AD credential or a role assignment, a SAS token generated from a storage account's account-level keys cannot always be individually revoked — the token is a cryptographically signed string, valid until its stated expiry, that Azure has no built-in way to invalidate on its own. The only way to fully invalidate an account-key-based SAS token before its expiry is to **regenerate the storage account's access keys** that the token was signed with — but doing so immediately breaks every OTHER legitimate SAS token and any application still using those same keys, making incident response here a genuine tradeoff between fully closing the exposure and causing a broader operational outage. This is precisely why security teams increasingly push for **stored access policies** (which CAN be revoked independently, by deleting the policy) or **Azure AD-based access** (user delegation SAS tokens, which respect Azure AD token lifetimes and Conditional Access policies) instead of raw account-key-based SAS tokens.\n\n` +
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
    },
  ],
};

export default [azureSecurityRoom];
