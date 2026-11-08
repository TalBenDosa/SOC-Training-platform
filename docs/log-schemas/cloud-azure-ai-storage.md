# Azure OpenAI, Prompt Shields and Azure Blob Storage: log schema card

How the Azure AI workload of a RAG assistant reaches the SIEM, and the Log Analytics table each record
lands in inside the XDR console. Checked 2026-11-08 (Sdema review I2).

## 1. Official sources

- Azure OpenAI monitoring and data reference (resource log categories Audit, RequestResponse, Trace,
  AzureOpenAIRequestUsage; all land in AzureDiagnostics):
  https://learn.microsoft.com/azure/foundry/openai/monitor-openai-reference and
  https://learn.microsoft.com/azure/foundry-classic/openai/how-to/monitor-openai
  (the sample KQL projects `Category, OperationName, DurationMs, ResultSignature, properties_s`).
- A raw RequestResponse record, as Azure writes it (Elastic Azure OpenAI integration sample):
  `{"Tenant":"eastus","callerIpAddress":"81.2.69.***","category":"RequestResponse","durationMs":102,
  "event":"ShoeboxCallResult","location":"eastus","operationName":"…","properties":"{\"apiName\":…,
  \"requestTime\":638481757794854611,\"requestLength\":2,\"responseTime\":…,\"responseLength\":113,
  \"objectId\":\"\"}","resultSignature":"200","time":"…"}`.
- Guardrail annotations (Prompt Shields user prompt attack / indirect attack: detected, filtered):
  https://learn.microsoft.com/azure/foundry-classic/openai/concepts/content-filter-annotations
- Content Safety Prompt Shields API response (`userPromptAnalysis.attackDetected`,
  `documentsAnalysis[].attackDetected`): Azure AI Content Safety quickstart for Prompt Shields.
- ApiManagementGatewayLogs columns: https://learn.microsoft.com/azure/azure-monitor/reference/tables/apimanagementgatewaylogs
- StorageBlobLogs columns: https://learn.microsoft.com/azure/azure-monitor/reference/tables/storagebloblogs

## 2. Native format and delivery

| Record | Feed raw | XDR table |
|---|---|---|
| Azure OpenAI RequestResponse | `azure.open_ai.*` (the Elastic integration names) | `AzureDiagnostics` |
| Prompt Shields verdict | the API Management gateway log of the app's `text:shieldPrompt` call | `ApiManagementGatewayLogs` |
| Blob operations | the StorageBlobLogs row itself | `StorageBlobLogs` |
| Defender for Cloud AI alert | `azure.alert.*` | `SecurityAlert` (see siem-sentinel-securityalert) |

### Azure OpenAI in AzureDiagnostics
`Category` RequestResponse, `OperationName` (ChatCompletions_Create …), `ResultSignature` (HTTP status as a
string), `DurationMs`, `CallerIPAddress` (last octet masked, `198.51.100.***`), `CorrelationId`,
`event_s` ShoeboxCallResult, `location_s` and `Tenant_s` (both the region), `Resource` (account name, upper
case), `ResourceGroup`, `SubscriptionId`, `ResourceId` (upper case ARM id), `ResourceProvider`
MICROSOFT.COGNITIVESERVICES, `ResourceType` ACCOUNTS, and `properties_s`, a JSON string:
`apiName`, `requestTime` / `responseTime` (.NET ticks), `requestLength` / `responseLength` (bytes),
`objectId` (Entra object id of a caller that signs in with Entra ID, empty with an API key), `streamType`,
`modelDeploymentName`, `modelName`, `modelVersion`.

**Not in the record:** prompt or completion text, token counts, the end user. Response SIZE is the signal.
The workspace adds a week of the deployment's ordinary calls (baseline.ts) so "is 15 KB unusual for this
deployment" has an answer; the hunt `cloud-azure-openai-oversized-completions` compares every call with
its deployment's median.

### Prompt Shields
Azure AI Content Safety writes no per-request verdict in its resource log (only metadata and RAI metrics:
Harmful Volume Detected, Blocked Volume). A verdict is visible where the response is logged: here the
app's API Management gateway with backend response logging on. `BackendResponseBody` holds the Prompt
Shields response, for example `{"userPromptAnalysis":{"attackDetected":false},"documentsAnalysis":[{"attackDetected":true}]}`.
The benign check and the flagged check carry the same columns; only the value differs.

### StorageBlobLogs
`CallerIpAddress` includes the client port (`203.0.113.47:52114`), `StatusCode` is a string,
`AuthenticationType` OAuth / SAS / DelegationSas / AccountKey / Anonymous, `ObjectKey` and
`UserAgentHeader` are quoted. An OAuth request carries `RequesterObjectId`, `RequesterTenantId`,
`RequesterAppId`, `RequesterAudience`, `RequesterTokenIssuer` and `AuthorizationDetails` (the RBAC action,
role definition and principal that allowed it). `GetUserDelegationKey` (action
`Microsoft.Storage/storageAccounts/blobServices/generateUserDelegationKey/action`) is the key a user
delegation SAS is signed with; a write with that SAS logs `DelegationSas`.

## 3. Investigation notes

- Who could write the uploaded file: the `GetUserDelegationKey` row before the `PutBlob` names the
  identity that signs upload links (`RequesterObjectId`), the `PutBlob` names the address that used it.
- An Azure OpenAI completion's caller is the gateway or the app (masked); the end user is only in a
  Defender for Cloud AI alert (`End user ID`, `End user IP address`) when the app passes a user security
  context. An anonymous chat names opaque end-user ids, never an employee.
- Entity pivots: an IP reaches StorageBlobLogs (`CallerIpAddress has`), AzureDiagnostics and the gateway
  log; an Azure resource reaches AzureDiagnostics (`Resource =~`), StorageBlobLogs (`AccountName`) and
  the gateway (`BackendUrl has`).

## 4. Fields that do NOT exist

- No `promptshields.*`, `gateway.*`, `DocumentAttack` field in any Azure log: those were this platform's
  own names and are retired for this story.
- No `Caller_s` or `Message` on an Azure OpenAI RequestResponse row.
- `RequesterTenantId` is the Entra tenant, never the subscription id.
- UNVERIFIED: the exact `streamType` spelling (`Streaming` is confirmed; the non-streaming value is kept as
  the emitter writes it).
