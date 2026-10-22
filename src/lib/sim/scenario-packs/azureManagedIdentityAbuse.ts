import type { ScenarioBundle, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { azureManagedIdentityAbuseScenarioEvents } from "./azureManagedIdentityAbuse.events";
/**
 * Scenario pack: "Azure App-Registration Credential Abuse, a Quiet Secret-Add
 * that a Later Data-Access Alert Traces Back To"
 *
 * ADVANCED tier. A cloud-only privilege-escalation intrusion with NO host
 * telemetry, there is no endpoint to isolate and no process tree to walk. The
 * whole case lives in three control-plane logs: the Microsoft Entra ID audit and
 * sign-in logs, the Azure Activity (Azure Monitor) log, and a corroborating
 * Microsoft Graph Security incident.
 *
 * THE FOOTHOLD IS OUT OF SCOPE. The attacker already controls a workload whose
 * managed identity (a service principal) holds a permission to write application
 * credentials in the tenant. What they do with it is the exercise. The quiet
 * pivot is a single Entra audit line, "Add service principal credentials", that
 * appends a new client secret to an EXISTING, over-permissioned app registration,
 * svc-billing-connector, which already carries Owner on the prod
 * subscription. That one secret-add is stealthy
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
 * the SAME operation, "Add service principal credentials", with the opposite
 * verdict. The discriminators are actor provenance (a named human on an approved
 * change vs a workload identity driven from an unfamiliar address), the source
 * address, and whether a change record exists, NOT the operation name, which is
 * identical in both.
 *
 * SOURCES (only three registry vendors): azure-ad (Microsoft Entra ID, audit
 * "Add service principal credentials" and service-principal sign-in logs),
 * azure-monitor (Azure Activity Log, role assignment, Key Vault and Storage
 * data-plane operations, subscription enumeration), microsoft-graph-security (the
 * corroborating security incident that opens the ticket).
 *
 * NOTE: register in scenarios.ts with difficulty "advanced". The ScenarioBundle
 * itself carries no difficulty field.
 */


export function buildAzureManagedIdentityAbuseScenario(
  scenarioId = "azure-managed-identity-abuse-2026",
): ScenarioBundle {
  const { title, events, T, MIN, SEC, subName, resourceGroup, app, newKeyId, workloadMi, attackerIp, keyVault, storageAccount, engineer, terraformSp } = azureManagedIdentityAbuseScenarioEvents();

  const iocs: IOC[] = [
    {
      type: "ip",
      value: attackerIp, // 45.155.205.211, drives the credential-add, sign-ins and Azure operations
      first_seen: T(0),
      last_seen: T(22 * MIN),
      reputation: "malicious",
      tags: ["external", "caller-address"],
    },
    {
      type: "user",
      value: app.displayName, // svc-billing-connector, the borrowed, over-permissioned identity
      first_seen: T(0),
      last_seen: T(19 * MIN),
      reputation: "suspicious",
      tags: ["service-principal", "affected-identity"],
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
      value: workloadMi.spId, // webjob-ingest-prod, the compromised workload identity that added the secret
      first_seen: T(-30 * SEC),
      last_seen: T(0),
      reputation: "suspicious",
      tags: ["workload-identity", "actor"],
    },
    {
      type: "user",
      value: newKeyId, // the attacker-added client-secret keyId
      first_seen: T(0),
      last_seen: T(22 * MIN),
      reputation: "malicious",
      tags: ["key-id", "client-secret"],
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
        { value: "cred_add", label: "The 'Add service principal credentials' record that appended a new client secret to svc-billing-connector" },
        { value: "role", label: "The roleAssignments/write granting Key Vault Secrets Officer at rg-billing-prod, which authorised the outside sign-ins" },
        { value: "graph_signin", label: "The first non-interactive service-principal sign-in to Microsoft Graph, where the new address first shows up" },
        { value: "subenum", label: "The resourceGroups/read enumeration of prod-analytics-sub, the earliest Azure Activity record in the whole chain" },
      ],
      answer: "cred_add",
      explanation:
        "A service principal can only sign in if it holds a usable credential. amia_01 is where the intruder gave it one, a new client secret appended to the EXISTING app registration through 'Add service principal credentials'. That is the quiet pivot: no new app is registered and no consent prompt fires, so nothing looks created, yet from that moment the identity can authenticate from anywhere. Every later step, the sign-ins, the role grant, the vault and storage reads, depends on it. The role assignment (amia_05) widened what the identity could do but came after it was already signing in. The Graph sign-in (amia_02) is the first USE of the secret, not its origin. The subscription enumeration (amia_04) is downstream reconnaissance. The credential-add is the join that ties the loud data-access alert back to a cause.",
    },
    {
      id: "amia_q2",
      xp: 65,
      kind: "single",
      prompt:
        "The benign control (amia_00) and the intrusion's pivot (amia_01) are BOTH the 'Add service principal credentials' operation with ResultStatus Success. Which combination of fields separates the malicious one from the sanctioned rotation?",
      hint: "Compare the Actor type and identity, the ActorIpAddress, and whether a change record backs each one.",
      options: [
        { value: "actor_ip_change", label: "Actor is a workload identity (Actor.Type 2) from an unknown address with no change behind it; the benign add is a named engineer under CHG-2211" },
        { value: "operation", label: "The malicious record carries a different Operation value, which is how the Entra audit log labels a credential add it deems unauthorized" },
        { value: "result", label: "The malicious record carries ResultStatus Failure, showing the tenant rejected the credential add before the secret could ever be used" },
        { value: "target_app", label: "Only the malicious record targets an app registration; the benign rotation modifies a user account's password profile, not a service principal" },
      ],
      answer: "actor_ip_change",
      explanation:
        "The operation is identical in both, that is the whole point, and why the Operation value proves nothing on its own. The discriminators are provenance and authorization. In amia_00 the Actor is a named human (d.almeida) on a recorded change (CHG-2211), from the Azure DevOps hosted-agent address the billing pipeline always uses. In amia_01 the Actor is the workload identity webjob-ingest-prod (Actor.Type 2, a service principal), from 45.155.205.211, with no change behind it. (b) is false, both read 'Add service principal credentials.'; there is no separate 'unauthorized' operation. (c) is false, the malicious record is ResultStatus Success; it worked. (d) is false, both target service principals; the benign one modifies sp-terraform-cicd.",
    },
    {
      id: "amia_q3",
      xp: 60,
      kind: "single",
      prompt:
        "Events amia_02 and amia_03 are sign-ins for svc-billing-connector. Which fields establish that these are service-principal (application) sign-ins rather than a user logging in?",
      hint: "Look at the sign-in log category, whether a user or a service_principal_id is present, and the interactivity flag.",
      options: [
        { value: "sp_category", label: "Category ServicePrincipalSignInLogs, a service_principal_id and app_id with no user attached, and is_interactive set to false" },
        { value: "mfa_fail", label: "The records show an MFA challenge that was satisfied, a step only application sign-ins holding a client secret can complete" },
        { value: "user_upn", label: "They carry a user_principal_name ending in the tenant domain, which is how Entra marks an application identity in the sign-in log" },
        { value: "conditional", label: "conditional_access_status reads 'success', proving a user-targeted Conditional Access policy evaluated and passed these sessions" },
      ],
      answer: "sp_category",
      explanation:
        "Service-principal sign-ins are logged in their own category, ServicePrincipalSignInLogs, distinct from interactive and non-interactive USER sign-ins. The records identify the actor by service_principal_id and app_id, carry no user principal, and set is_interactive to false, an application authenticating with a client secret, not a person at a prompt. (b) is wrong: application-only sign-ins do not perform MFA, there is no human to challenge, which is exactly why a stolen secret is powerful. (c) inverts the truth, a user_principal_name is the marker of a USER sign-in; these have none. (d) misreads the field: conditional_access_status is 'notApplied' here, and CA policies targeting users do not evaluate a service-principal token in the first place.",
    },
    {
      id: "amia_q4",
      xp: 60,
      kind: "single",
      prompt:
        "Among the Azure Activity operations, which one turned a borrowed, time-limited token into durable standing access, the step that most changes the blast radius if left in place?",
      hint: "Distinguish the operations that only READ from the one that changes who is authorized going forward.",
      options: [
        { value: "role_write", label: "Microsoft.Authorization/roleAssignments/write, it granted the identity a standing role that survives the current token" },
        { value: "kv_read", label: "SecretGet in the Key Vault diagnostic log, reading one secret is the most durable form of access in the chain" },
        { value: "list_keys", label: "Microsoft.Storage/storageAccounts/listKeys/action, listing keys permanently rewrites the storage account's access model" },
        { value: "rg_read", label: "Microsoft.Resources/subscriptions/resourceGroups/read, enumerating resource groups establishes lasting control of the subscription" },
      ],
      answer: "role_write",
      explanation:
        "roleAssignments/write is the only operation here that changes authorization state. It grants svc-billing-connector a standing role (Key Vault Secrets Officer) that persists independently of the current access token, revoke the token and the role remains, which is why it is the durable-access step and a containment priority. The secret read (kv_read) and key listing (list_keys) exfiltrate data the identity could already reach; damaging, but they do not expand future entitlement. Enumeration (rg_read) only observes. When scoping containment you remove the added secret AND unwind this role assignment; leaving the role in place hands the operator lasting access even after the secret is revoked.",
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
        { value: "block_ip_only", label: "Block 45.155.205.211 at the network edge, cutting the address ends the incident on its own" },
        { value: "reset_engineer", label: "Reset the platform engineer d.almeida's password, since the audit log shows that account adding a service-principal secret" },
      ],
      answer: ["revoke_secret", "undo_role"],
      explanation:
        "Two things must be undone: the factor the attacker added and the entitlement they granted. Removing the attacker-added client secret (keyId b7e42c8a…) and revoking the identity's tokens kills the authentication path, and reversing the roleAssignments/write plus rotating the exposed Key Vault secret and Storage keys removes the standing access and the credentials already read. Blocking 45.155.205.211 alone (c) fails because the added secret works from any address and the role assignment survives regardless of source IP, it is a useful stop-gap, not containment. Resetting d.almeida (d) targets the BENIGN control: amia_00 is a sanctioned rotation by a named engineer on an approved change, and the malicious secret-add (amia_01) was performed by the workload identity webjob-ingest-prod, not by that person.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "Cloud intrusion operator abusing a compromised workload identity (post-foothold)",
    attack_kind: "cloud_privilege_escalation",
    briefing:
      "Microsoft Graph Security raised a High incident in the nexacorp tenant: the automation identity svc-billing-connector began authenticating from an unfamiliar address and reached Key Vault and Storage in the prod-analytics subscription within minutes. It normally runs only from the billing release pipeline. Work out how it started signing in from there, what it read, and how far it went before you contain it.",
    narrative: `The operator already controlled a workload in the nexacorp tenant whose managed identity, webjob-ingest-prod, held a permission to write application credentials. How they reached that workload is out of scope; what they did with the permission is the case. The one trace of it is a token mismatch: at 01:11:30 the managed identity was issued a Microsoft Graph token at its own Azure address (20.50.73.84), and thirty seconds later that identity's token was in use from 45.155.205.211, an address no Azure workload of the tenant uses.

At 01:12 they used it for the quiet pivot. An Entra audit line, "Add service principal credentials", appended a new client secret to an EXISTING app registration, svc-billing-connector, driven from 45.155.205.211. Nothing looked created: no new app, no consent prompt. But svc-billing-connector was over-permissioned: it already held Owner on the prod subscription, and it now had a secret the operator controlled. Its normal pattern, visible on 27 and 28 August, is a 03:05 sign-in from the Azure DevOps hosted agent 13.107.42.14 with its long-lived secret.

Three minutes later that secret was used. svc-billing-connector authenticated to Microsoft Graph, then to Azure Resource Manager, as non-interactive service-principal sign-ins with no user and no MFA. The identity enumerated the prod-analytics subscription and its resource groups, then ran a roleAssignments/write to grant itself the Key Vault Secrets Officer role at the rg-billing-prod scope, turning a borrowed token into standing access. Owner is a control-plane role, so to reach the vault the roleAssignments/write was needed; the vault's own diagnostic log then records a SecretGet of sql-conn-prod out of kv-billing-prod. The identity listed the account keys for the storage account stbillingprod01, and the storage blob log shows those keys being used from the same address to list the billing-exports container and read a ledger file.

The one legitimate comparison in the data is two days earlier: platform engineer d.almeida rotating the CI/CD Terraform service principal's secret through approved change CHG-2211, from the known pipeline runner. Identical operation, opposite meaning, the difference is the actor, the address, and the change record behind it. Microsoft Graph Security correlated the credential-add, the non-interactive sign-ins and the Azure Activity into one incident at 01:34, and that is the alert on the queue.`,
    learning_objectives: [
      "Trace a cloud data-access alert (Key Vault / Storage) BACKWARD through Azure Activity and service-principal sign-ins to the Entra audit 'Add service principal credentials' event that enabled it",
      "Recognise that appending a client secret or certificate to an existing, over-permissioned app registration is stealthy persistence, no new app, no consent, and read the Actor, ActorIpAddress and target fields that characterise it",
      "Identify a service-principal (application) sign-in from the ServicePrincipalSignInLogs category, the service_principal_id / app_id fields, and the absence of a user and of MFA",
      "Distinguish the Azure Activity operation that grants standing access (Microsoft.Authorization/roleAssignments/write) from the operations that only read data (SecretGet, listKeys, subscriptions read)",
      "Separate a malicious credential-add from a sanctioned secret rotation using actor provenance, source address and the presence of a change record, not the operation name, which is identical, and scope containment to the added secret AND the role it granted",
    ],
    alerts: [], // attached by the catalogue wiring
    events,
    iocs,
    killchain: [
      { ts: "2026-08-27T14:20:00.000Z", phase: "Baseline", action: `Platform engineer rotates ${terraformSp.displayName}'s client secret under approved change CHG-2211, the sanctioned, attributable path (T1098.001)` },
      { ts: T(-30 * SEC), phase: "Foothold", action: `${workloadMi.displayName} is issued a Microsoft Graph token at its Azure address 20.50.73.84; seconds later the identity acts from ${attackerIp}` },
      { ts: T(0), phase: "Persistence", action: `New client secret appended to the existing ${app.displayName} app registration by ${workloadMi.displayName} (T1098.001)` },
      { ts: T(3 * MIN), phase: "Stealth", action: `${app.displayName} signs in non-interactively to Microsoft Graph with the new secret (T1078.004)` },
      { ts: T(4 * MIN), phase: "Stealth", action: "Same identity acquires an Azure Resource Manager token (T1078.004)" },
      { ts: T(6 * MIN), phase: "Discovery", action: `Subscription and resource groups enumerated in ${subName} (T1526)` },
      { ts: T(9 * MIN), phase: "Persistence", action: `roleAssignments/write grants Key Vault Secrets Officer at ${resourceGroup} scope, standing access (T1098.003)` },
      { ts: T(12 * MIN), phase: "Credential Access", action: `SecretGet of sql-conn-prod on ${keyVault} in the vault diagnostic log (T1555.006)` },
      { ts: T(15 * MIN), phase: "Collection", action: `Account keys listed for storage account ${storageAccount} (T1530)` },
      { ts: T(19 * MIN), phase: "Collection", action: `Account key used to list and read blobs in billing-exports from ${attackerIp} (T1530)` },
      { ts: T(22 * MIN), phase: "Detection", action: "Microsoft Graph Security correlates the credential-add, sign-ins and Azure Activity into one incident" },
    ],
    questions,
  };
}
