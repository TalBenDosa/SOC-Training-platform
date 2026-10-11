# Azure Activity Log + Microsoft Defender for Cloud alerts — log schema card

Both are **JSON-native**. Azure delivers the Activity Log in two documented shapes — the **REST/portal schema**
and the **storage-account/Event-Hub (resource-log) schema**. Microsoft Defender for Cloud alerts are a separate
JSON (the `Microsoft.Security/.../alerts` resource). Show each exactly as the source delivers; do **not** flatten
to ECS `azure.activitylogs.*` or wrap in a Wazuh `data.*` envelope.

## 1. Official sources

- Activity Log event schema (categories, severity, all properties, Administrative/Security samples, and the
  storage/Event-Hub mapping + sample): https://learn.microsoft.com/en-us/azure/azure-monitor/platform/activity-log-schema
- RBAC change activity log entries (role-assignment write, `properties.requestbody/entity/message/hierarchy`):
  https://learn.microsoft.com/en-us/azure/role-based-access-control/change-history-report
- Defender for Cloud alert resource schema + sample + enums (severity/status/intent/resourceIdentifiers/entities):
  https://learn.microsoft.com/en-us/rest/api/defenderforcloud/alerts/get-subscription-level?view=rest-defenderforcloud-2022-01-01
- Defender alert catalogues (exact alert `alertType` strings + MITRE + severity):
  https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-azure-key-vault ,
  https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-resource-manager
- Storage/Event-Hub record shape cross-checked against elastic/integrations `azure/data_stream/activitylogs`
  raw test inputs.

## 2. Native format & delivery

- **Portal / `az monitor activity-log` / Azure Monitor REST:** the "REST schema" — fields like
  `operationName`/`category`/`resourceType`/`status` are **objects** `{value, localizedValue}`.
- **Streamed to a Storage Account or Event Hub (the usual SIEM path):** the "resource-log schema" — a line is
  `{"records":[ {event}, ... ]}` (JSON Lines since 2018-11-01). Here `category`, `operationName`, `resultType`,
  `resultSignature`, `callerIpAddress`, `identity`, `level`, `time` are **flat strings/objects** (no
  `{value, localizedValue}` wrapping). This is what most SOCs ingest.
- **We standardise on the resource-log (Event-Hub/storage) shape** for Activity Log, since that is what a SIEM
  receives. Keep the REST shape only when a scenario is explicitly about the portal JSON blade.
- **Defender for Cloud alerts:** the alert ARM resource JSON (`id/name/type/properties{...}`). They also surface
  in the Activity Log `Security` category and can be exported (continuous export → Event Hub / Log Analytics).

### Field mapping REST ↔ resource-log
| resource-log property | REST schema property |
|---|---|
| `time` | `eventTimestamp` |
| `resourceId` | `resourceId` |
| `operationName` | `operationName.value` |
| `category` | part of operation / `properties.eventCategory` (else `Administrative`) |
| `resultType` | `status.value` |
| `resultSignature` | `subStatus.value` |
| `resultDescription` | `description` |
| `callerIpAddress` | `httpRequest.clientIpAddress` |
| `correlationId` | `correlationId` |
| `identity` | `claims` + `authorization` |
| `level` | `level` |
| `properties` | `properties` |

## 3. Core field reference

### Activity Log — resource-log (Event-Hub/storage) record
| Field | Type | Notes / values |
|---|---|---|
| `time` | string | UTC ISO8601 with 7 fractional digits, e.g. `2026-09-30T02:22:31.3810679Z`. |
| `resourceId` | string | ARM id of the impacted resource (often UPPERCASE in Event-Hub output). `subscriptionId`, `resourceGroupName`, `resourceType` are inferred from it. |
| `operationName` | string | e.g. `MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE`, `Microsoft.KeyVault/vaults/secrets/read`. |
| `category` | string | `Administrative` \| `Security` \| `ServiceHealth` \| `ResourceHealth` \| `Alert` \| `Autoscale` \| `Recommendation` \| `Policy`. |
| `resultType` | string | `Start` \| `Accept` \| `Success` \| `Failure` \| `Started` \| `Succeeded` \| `Failed` (status). |
| `resultSignature` | string | e.g. `Started.`, `Succeeded.Created`, `Failed.Forbidden`. |
| `resultDescription` | string (opt) | Free-text description. |
| `durationMs` | number | Often `0` for Administrative. |
| `callerIpAddress` | string | Caller IP (absent for some service-initiated events). |
| `correlationId` | string | GUID; shared across events of one operation. |
| `level` | string/number | `Critical` \| `Error` \| `Warning` \| `Informational`/`Information`. (In some sign-in streams a numeric `Level` like `4` appears.) |
| `location` | string | Where the event was processed (e.g. `global`) — not the resource location. |
| `identity` | object | `{authorization{action, scope, evidence{role, roleAssignmentScope, roleAssignmentId, roleDefinitionId, principalId, principalType}}, claims{...JWT claims...}}`. The `claims` map includes `name`, the `.../upn` and `.../name` claims (the caller UPN), `appid`, `ipaddr`, `http://schemas.microsoft.com/identity/claims/objectidentifier`, `http://schemas.microsoft.com/identity/claims/tenantid`, etc. |
| `properties` | object | Category-specific. For Administrative: `{statusCode, serviceRequestId, eventCategory:"Administrative", entity, message, hierarchy:"<tenantId>/<subscriptionId>", requestbody?, responseBody?}`. |

Administrative RBAC detail: `properties.requestbody` is a JSON **string** describing the role assignment
(`{"Id":...,"Properties":{"PrincipalId":...,"PrincipalType":"User","RoleDefinitionId":"/providers/Microsoft.Authorization/roleDefinitions/<guid>","Scope":...}}`).
`identity.authorization.action` for RBAC = `Microsoft.Authorization/roleAssignments/write` (or `/delete`,
`/roleDefinitions/write`). `caller` (REST schema) / `identity.claims` UPN = who did it.

### Defender for Cloud alert (`properties` of the alert resource)
Top: `id` (ARM id), `name` (systemAlertId), `type` = `Microsoft.Security/Locations/alerts`.
`properties`:
| Field | Type | Values |
|---|---|---|
| `alertDisplayName` | string | Human title. |
| `alertType` | string | Stable detection id, e.g. `KV_ListGetAnomaly`, `ARM_MicroBurst.AzKeyVaultSecretsREST`, `VM_EICAR`. |
| `description` | string | What was detected. |
| `severity` | enum | `Informational` \| `Low` \| `Medium` \| `High`. |
| `status` | enum | `Active` \| `InProgress` \| `Resolved` \| `Dismissed`. |
| `intent` | enum (MITRE) | `Unknown, PreAttack, InitialAccess, Persistence, PrivilegeEscalation, DefenseEvasion, CredentialAccess, Discovery, LateralMovement, Execution, Collection, Exfiltration, CommandAndControl, Impact, Probing, Exploitation`. |
| `startTimeUtc`/`endTimeUtc` | date-time | Activity window. |
| `timeGeneratedUtc`/`processingEndTimeUtc` | date-time | Alert generation times. |
| `compromisedEntity` | string | Resource most related (e.g. VM / vault name). |
| `remediationSteps` | string[] | Recommended actions. |
| `resourceIdentifiers` | array | `{type:"AzureResource", azureResourceId}` and/or `{type:"LogAnalytics", agentId, workspaceId, workspaceResourceGroup, workspaceSubscriptionId}`. |
| `entities` | array | Each `{type:"ip"|"account"|"host"|"process"|...}` plus type-specific fields (ip: `address`, `location{...}`). |
| `extendedProperties` | object | Free key/value detail. |
| `techniques`/`subTechniques` | string[] | MITRE ATT&CK IDs (e.g. `T1059`, `T1059.001`). |
| `isIncident` | boolean | True if a correlated incident. |
| `productName` | string | e.g. `Azure Security Center` / `Microsoft Defender for Cloud`. |
| `vendorName` | string | `Microsoft`. |

Defender alert `alertType` strings relevant to the cloud chain (from the catalogues):
`KV_SuspiciousIPAccess`, `KV_ListGetAnomaly` (secret listing+get, Credential Access, Medium),
`KV_PutGetAnomaly`, `KV_OperationVolumeAnomaly`, `ARM_OperationFromSuspiciousIP` (Execution, Medium),
`ARM_MicroBurst.AzKeyVaultSecretsREST` (High), `ARM_AnomalousRBACRoleAssignment` (Lateral Movement/Defense
Evasion), `ARM_PrivilegedRoleDefinitionCreation`, `ARM_AnomalousOperation.PrivilegeEscalation`,
`ARM_SuspiciousComputeCreation` (crypto-mining, Impact, Medium).

---

## 4. Realistic samples (tenant `aaaabbbb-0000-cccc-1111-dddd2222eeee`, subscription `11112222-3333-4444-5555-666677778888`)

### AZ1 — Activity Log (resource-log shape): Key Vault secret read (attacker dumping secrets)
```json
{
  "time": "2026-09-30T02:30:12.4455667Z",
  "resourceId": "/SUBSCRIPTIONS/11112222-3333-4444-5555-666677778888/RESOURCEGROUPS/PROD-RG/PROVIDERS/MICROSOFT.KEYVAULT/VAULTS/NEXACORP-KV/SECRETS/DB-MASTER",
  "operationName": "Microsoft.KeyVault/vaults/secrets/read",
  "category": "Administrative",
  "resultType": "Success",
  "resultSignature": "Succeeded.OK",
  "durationMs": 12,
  "callerIpAddress": "203.0.113.77",
  "correlationId": "7a1c0e4b-9d20-4ce7-8df0-2b1a4ce79df0",
  "identity": {
    "authorization": {
      "action": "Microsoft.KeyVault/vaults/secrets/read",
      "scope": "/subscriptions/11112222-3333-4444-5555-666677778888/resourceGroups/prod-rg/providers/Microsoft.KeyVault/vaults/nexacorp-kv/secrets/db-master",
      "evidence": { "role": "Key Vault Secrets User", "roleAssignmentScope": "/subscriptions/11112222-3333-4444-5555-666677778888", "principalId": "99998888-7777-6666-5555-444433332222", "principalType": "User" }
    },
    "claims": {
      "appid": "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
      "ipaddr": "203.0.113.77",
      "name": "Dana Levy",
      "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn": "dana.levy@nexacorp.com",
      "http://schemas.microsoft.com/identity/claims/objectidentifier": "99998888-7777-6666-5555-444433332222",
      "http://schemas.microsoft.com/identity/claims/tenantid": "aaaabbbb-0000-cccc-1111-dddd2222eeee"
    }
  },
  "level": "Informational",
  "location": "global",
  "properties": {
    "statusCode": "OK",
    "serviceRequestId": "f0a1b2c3-d4e5-46f7-8899-0a1b2c3d4e5f",
    "eventCategory": "Administrative",
    "entity": "/subscriptions/11112222-3333-4444-5555-666677778888/resourceGroups/prod-rg/providers/Microsoft.KeyVault/vaults/nexacorp-kv/secrets/db-master",
    "message": "Microsoft.KeyVault/vaults/secrets/read",
    "hierarchy": "aaaabbbb-0000-cccc-1111-dddd2222eeee/11112222-3333-4444-5555-666677778888"
  }
}
```

### AZ2 — Activity Log: role assignment write (privilege escalation / persistence)
```json
{
  "time": "2026-09-30T02:33:41.1262430Z",
  "resourceId": "/SUBSCRIPTIONS/11112222-3333-4444-5555-666677778888/RESOURCEGROUPS/PROD-RG/PROVIDERS/MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/5c3d8b2f-0a1e-4b4c-9f32-7d8e3a2b1c44",
  "operationName": "Microsoft.Authorization/roleAssignments/write",
  "category": "Administrative",
  "resultType": "Success",
  "resultSignature": "Succeeded.Created",
  "durationMs": 0,
  "callerIpAddress": "203.0.113.77",
  "correlationId": "aaaa0000-bb11-2222-33cc-444444dddddd",
  "identity": {
    "authorization": {
      "action": "Microsoft.Authorization/roleAssignments/write",
      "scope": "/subscriptions/11112222-3333-4444-5555-666677778888"
    },
    "claims": {
      "name": "Dana Levy",
      "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn": "dana.levy@nexacorp.com",
      "appid": "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
      "ipaddr": "203.0.113.77"
    }
  },
  "level": "Informational",
  "location": "global",
  "properties": {
    "statusCode": "Created",
    "serviceRequestId": "ffff5555-aa66-7777-88bb-999999cccccc",
    "eventCategory": "Administrative",
    "entity": "/subscriptions/11112222-3333-4444-5555-666677778888/resourceGroups/prod-rg/providers/Microsoft.Authorization/roleAssignments/5c3d8b2f-0a1e-4b4c-9f32-7d8e3a2b1c44",
    "message": "Microsoft.Authorization/roleAssignments/write",
    "hierarchy": "aaaabbbb-0000-cccc-1111-dddd2222eeee/11112222-3333-4444-5555-666677778888",
    "requestbody": "{\"Id\":\"5c3d8b2f-0a1e-4b4c-9f32-7d8e3a2b1c44\",\"Properties\":{\"PrincipalId\":\"abcdabcd-1111-2222-3333-eeeeeeeeeeee\",\"PrincipalType\":\"ServicePrincipal\",\"RoleDefinitionId\":\"/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635\",\"Scope\":\"/subscriptions/11112222-3333-4444-5555-666677778888\"}}"
  }
}
```
(RoleDefinitionId `8e3af657-a8ff-443c-a75c-2fe8c4bcb635` = the built-in **Owner** role.)

### AZ3 — Activity Log: VM Run Command (remote code execution on a VM)
```json
{
  "time": "2026-09-30T02:40:05.7781234Z",
  "resourceId": "/SUBSCRIPTIONS/11112222-3333-4444-5555-666677778888/RESOURCEGROUPS/PROD-RG/PROVIDERS/MICROSOFT.COMPUTE/VIRTUALMACHINES/WEB01",
  "operationName": "Microsoft.Compute/virtualMachines/runCommand/action",
  "category": "Administrative",
  "resultType": "Start",
  "resultSignature": "Started.",
  "durationMs": 0,
  "callerIpAddress": "203.0.113.77",
  "correlationId": "6d4e9c3a-1b2f-4c5d-8e43-9f0a4b3c2d55",
  "identity": {
    "authorization": { "action": "Microsoft.Compute/virtualMachines/runCommand/action", "scope": "/subscriptions/11112222-3333-4444-5555-666677778888/resourceGroups/prod-rg/providers/Microsoft.Compute/virtualMachines/web01" },
    "claims": { "name": "Dana Levy", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn": "dana.levy@nexacorp.com", "ipaddr": "203.0.113.77" }
  },
  "level": "Informational",
  "location": "global",
  "properties": {
    "eventCategory": "Administrative",
    "entity": "/subscriptions/11112222-3333-4444-5555-666677778888/resourceGroups/prod-rg/providers/Microsoft.Compute/virtualMachines/web01",
    "message": "Microsoft.Compute/virtualMachines/runCommand/action",
    "hierarchy": "aaaabbbb-0000-cccc-1111-dddd2222eeee/11112222-3333-4444-5555-666677778888"
  }
}
```

### AZ4 — Defender for Cloud alert: anomalous secret listing+get in Key Vault
```json
{
  "id": "/subscriptions/11112222-3333-4444-5555-666677778888/resourceGroups/prod-rg/providers/Microsoft.Security/locations/eastus/alerts/2518770965529163669_7a1c0e4b9d20",
  "name": "2518770965529163669_7a1c0e4b9d20",
  "type": "Microsoft.Security/Locations/alerts",
  "properties": {
    "alertDisplayName": "Suspicious secret listing and query in a key vault",
    "alertType": "KV_ListGetAnomaly",
    "description": "A user or service principal performed an anomalous Secret List followed by one or more Secret Get operations on nexacorp-kv. This pattern is typically associated with secret dumping.",
    "severity": "Medium",
    "status": "Active",
    "intent": "CredentialAccess",
    "startTimeUtc": "2026-09-30T02:29:50.0000000Z",
    "endTimeUtc": "2026-09-30T02:31:10.0000000Z",
    "timeGeneratedUtc": "2026-09-30T02:34:02.0000000Z",
    "processingEndTimeUtc": "2026-09-30T02:34:05.1200000Z",
    "compromisedEntity": "nexacorp-kv",
    "productName": "Microsoft Defender for Cloud",
    "vendorName": "Microsoft",
    "remediationSteps": [ "Review the Key Vault access policies and RBAC assignments.", "Rotate the secrets that were read.", "Investigate the caller identity dana.levy@nexacorp.com and IP 203.0.113.77." ],
    "resourceIdentifiers": [
      { "type": "AzureResource", "azureResourceId": "/subscriptions/11112222-3333-4444-5555-666677778888/resourceGroups/prod-rg/providers/Microsoft.KeyVault/vaults/nexacorp-kv" }
    ],
    "entities": [
      { "type": "ip", "address": "203.0.113.77", "location": { "countryCode": "nl", "city": "amsterdam", "latitude": 52.374, "longitude": 4.8897, "asn": 209242 } },
      { "type": "account", "name": "dana.levy@nexacorp.com", "aadUserId": "99998888-7777-6666-5555-444433332222" }
    ],
    "extendedProperties": { "resourceType": "Key Vault", "Secrets accessed": "3" },
    "intent": "CredentialAccess",
    "techniques": [ "T1552", "T1555" ],
    "isIncident": false,
    "systemAlertId": "2518770965529163669_7a1c0e4b9d20"
  }
}
```

### AZ5 — Defender for Cloud alert: suspicious compute creation (crypto-mining)
```json
{
  "id": "/subscriptions/11112222-3333-4444-5555-666677778888/providers/Microsoft.Security/locations/eastus/alerts/2518770965529200001_cmine",
  "name": "2518770965529200001_cmine",
  "type": "Microsoft.Security/Locations/alerts",
  "properties": {
    "alertDisplayName": "Suspicious creation of compute resources detected",
    "alertType": "ARM_SuspiciousComputeCreation",
    "description": "Defender for Resource Manager identified a suspicious creation of compute resources in your subscription. The scale is higher than previously observed and can indicate crypto mining by a compromised principal.",
    "severity": "Medium",
    "status": "Active",
    "intent": "Impact",
    "startTimeUtc": "2026-09-30T02:41:00.0000000Z",
    "endTimeUtc": "2026-09-30T02:44:00.0000000Z",
    "timeGeneratedUtc": "2026-09-30T02:46:10.0000000Z",
    "compromisedEntity": "prod-rg",
    "productName": "Microsoft Defender for Cloud",
    "vendorName": "Microsoft",
    "remediationSteps": [ "Review newly created virtual machines / scale sets in prod-rg.", "If unauthorized, delete them and investigate the principal." ],
    "resourceIdentifiers": [ { "type": "AzureResource", "azureResourceId": "/subscriptions/11112222-3333-4444-5555-666677778888/resourceGroups/prod-rg" } ],
    "entities": [ { "type": "account", "name": "dana.levy@nexacorp.com" } ],
    "intent": "Impact",
    "techniques": [ "T1496" ],
    "isIncident": false,
    "systemAlertId": "2518770965529200001_cmine"
  }
}
```

---

## 5. Investigation notes

- **Who/where/what pivots:** caller identity = `identity.claims[".../upn"]` / `identity.claims.name` (REST: `caller`);
  IP = `callerIpAddress` (REST: `httpRequest.clientIpAddress` / `identity.claims.ipaddr`);
  what = `operationName` + `identity.authorization.action`; target = `resourceId` / `properties.entity`.
- **`correlationId`** links all events of one operation (e.g. the `Start` and the `Succeeded`/`Failed` pair, or a
  multi-step role assignment). Pivot on it to assemble the full action.
- **`resultType`/`resultSignature`** separate attempts from successes: a `write` with `resultType:"Start"` then a
  second record `Success`/`Failure` is normal; a lone `Failure`/`Forbidden` burst = probing.
- **RBAC abuse:** `Microsoft.Authorization/roleAssignments/write` to a privileged `RoleDefinitionId` (Owner
  `8e3af657-...`, Contributor `b24988ac-6180-42a0-ab88-20f7382dd24c`, User Access Administrator
  `18d7d88d-d35e-4fb5-a5c3-7773c20a72d9`) is the key persistence/priv-esc signal — read `properties.requestbody`.
- **Defender alert → Activity Log correlation:** the alert's `resourceIdentifiers.azureResourceId`,
  `compromisedEntity`, `entities[ip].address`, and `startTimeUtc/endTimeUtc` map onto Activity Log `resourceId`,
  `callerIpAddress`, and `time`. Pull the underlying Key Vault `secrets/read`, roleAssignment `write`, or VM
  `runCommand` events behind an alert.
- **Severity differs by source:** Activity Log `level` is operational (Informational/Warning/Error/Critical);
  Defender alert `severity` is risk (Informational/Low/Medium/High). Don't conflate them.

## 6. Common mistakes / non-existent fields

- **Two schemas, don't mix them.** In the resource-log/Event-Hub shape `operationName`, `category`,
  `resultType` are **plain strings**. In the REST/portal shape they are `{value, localizedValue}` objects, and
  the time field is `eventTimestamp` (not `time`), status is `status.value`, substatus is `subStatus.value`.
  Pick one shape per event; don't emit `operationName` as both a string and an object.
- `resourceId` in Event-Hub output is frequently **UPPERCASE** — that's normal, not a corruption.
- `hierarchy` is `"<tenantId>/<subscriptionId>"` (a string), and `properties.requestbody` is a **JSON string**,
  not a nested object — keep it escaped.
- Defender `severity` values are `Informational/Low/Medium/High` (not numeric, not `Warning`). `status` is
  `Active/InProgress/Resolved/Dismissed`. `intent` uses the MITRE-tactic enum spelling (`CredentialAccess`,
  `PrivilegeEscalation`, `LateralMovement` — one word, PascalCase).
- `alertType` is the stable id (`KV_ListGetAnomaly`, `ARM_SuspiciousComputeCreation`), separate from
  `alertDisplayName` (the human title). Don't swap them.
- Defender alert `entities` and `resourceIdentifiers` are **arrays**; each entity carries a `type` plus
  type-specific fields (ip entity → `address`, not `ip`). `resourceIdentifiers` types are exactly
  `AzureResource` / `LogAnalytics`.
- **Do not** flatten to `azure.activitylogs.*` / `azure.signinlogs.*` (that is the Elastic ECS integration,
  not Azure's own schema) and **do not** wrap in a Wazuh `data.*` envelope.
- Not every event has `callerIpAddress` (service-/platform-initiated events, ResourceHealth) — leave it absent
  rather than inventing an IP.
