# Microsoft Sentinel SecurityAlert (and Defender for Cloud alerts in it): log schema card

A SIEM alert in the feed is the SecurityAlert row of the product that raised it. In the XDR console the
same row keeps what the product wrote. Checked 2026-11-08 (Sdema review I1).

## 1. Official sources

- SecurityAlert schema: https://learn.microsoft.com/azure/sentinel/security-alert-schema and
  https://learn.microsoft.com/azure/azure-monitor/reference/tables/securityalert
- Entities: https://learn.microsoft.com/azure/sentinel/entities-reference
- Defender for Cloud AI alerts (alert types `AI.Azure_*`): https://learn.microsoft.com/azure/defender-for-cloud/alerts-ai-workloads

## 2. Columns that carry the evidence

- `ExtendedProperties`: a JSON string. A scheduled rule writes its own keys (counts, query period, the
  account a rule measured); Defender for Cloud writes the alert's extended properties (Model deployment
  name, End user ID, End user IP address, Grounding document …). The XDR row keeps every key the feed
  alert states (`ExtendedProperties.<Name>` and `azure.alert.extendedProperties.<Name>`) next to the
  workspace's own (`Analytic Rule Ids`, Graph ids).
- `Entities`: a JSON string, an array of typed entities (`$id`, `Type` host / account / ip / file /
  azure-resource …). The XDR row keeps the entities the product wrote. An account's `AadUserId` is the
  person's Entra object id, the same one their SigninLogs / AuditLogs rows carry (entraObjectId).
- `StartTime` / `EndTime`: the first and last activity the alert covers, both at or before
  `TimeGenerated`. `TenantId` is the tenant the workspace's other Microsoft rows name.
- `ProductName` / `ProviderName` / `ProductComponentName`: scheduled rule `Azure Sentinel` /
  `ASI Scheduled Alerts` / `Scheduled Alerts`; Defender for Cloud Apps `Microsoft Cloud App Security` /
  `MCAS`; Defender for Endpoint `Microsoft Defender Advanced Threat Protection` / `MDATP`.
  `DetectionProductName` is not a SecurityAlert column.

## 3. Events of an alert

"Events" on an alert with no log of its own (a correlation, a Defender for Cloud alert, an analytic the
feed carries) runs the evidence query: the evidence tables (SigninLogs, AuditLogs, OfficeActivity,
SecurityEvent, StorageBlobLogs, AzureDiagnostics, ApiManagementGatewayLogs, AzureActivity, Device*
tables, CommonSecurityLog …) filtered to the alert's entities inside its lookback, never the alert row
itself. Without a stated span the lookback is one hour. The span shown is the one the product wrote when
it lies inside the shift; otherwise the span of the evidence rows.

## 4. Feed event_type

The event_type of a Sentinel alert follows what its rule watched (sentinel.ts SENTINEL_SUBJECT_EVENT), the
same vocabulary for an attack and a benign alert. `risk_score_change` is an entity risk score update, not
an analytics alert.
