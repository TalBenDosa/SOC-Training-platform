# Microsoft Sentinel SecurityAlert (and Defender for Cloud alerts in it): log schema card

A SIEM alert in the feed is the SecurityAlert row of the product that raised it. In the XDR console the
same row keeps what the product wrote. Checked 2026-11-08 (Sdema review I1).

## 1. Official sources

- SecurityAlert schema: https://learn.microsoft.com/azure/sentinel/security-alert-schema and
  https://learn.microsoft.com/azure/azure-monitor/reference/tables/securityalert
- Entities: https://learn.microsoft.com/azure/sentinel/entities-reference
- Defender for Cloud AI alerts (alert types `AI.Azure_*`): https://learn.microsoft.com/azure/defender-for-cloud/alerts-ai-workloads

## 2. Columns that carry the evidence

- `ExtendedProperties`: a JSON string. A scheduled rule writes its own fixed keys (`Query Period`,
  `Trigger Operator`, `Trigger Threshold`, `Search Query Results Overall Count`, `Analytic Rule Ids`,
  `Analytic Rule Name`); the fields its author surfaces are `Custom Details`, itself a JSON string of
  arrays (`{"SourceEDRVendor":["CrowdStrike Falcon"]}`, keys letters and digits only). Defender for
  Cloud writes the alert's extended properties (Model deployment name, End user ID, End user IP address,
  Grounding document …) as its own keys.
- `AlertType`: a scheduled / NRT analytic's alerts carry `<workspace id>_<analytic rule id>` (two GUIDs);
  a product's alerts carry the product's own type (`SuspiciousPowerShellCommandLine`). Never the alert
  name with its spaces removed.
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

## 5. Samples (as Log Analytics returns the row)

`Entities`, `ExtendedProperties` and `Techniques` are JSON strings; `Tactics` is a comma-separated
string. A scheduled analytic names its rule in `ExtendedProperties` ("Analytic Rule Ids", "Analytic Rule
Name"). Values below are fictional.

A scheduled analytics rule:

```json
{
  "TimeGenerated": "2026-11-09T09:41:12.000Z",
  "TenantId": "3f9c1a52-7d4e-4b8a-9c21-6e0f5d7a2b10",
  "Type": "SecurityAlert",
  "SourceSystem": "Detection",
  "DisplayName": "Password spray against many accounts from one address",
  "AlertName": "Password spray against many accounts from one address",
  "AlertSeverity": "Medium",
  "Description": "One address failed sign-ins for 14 accounts in 10 minutes.",
  "ProviderName": "ASI Scheduled Alerts",
  "VendorName": "Microsoft",
  "ProductName": "Azure Sentinel",
  "ProductComponentName": "Scheduled Alerts",
  "AlertType": "6f1c2e84-9b3d-4a57-8e20-d41a7c9b3f06_5b0e8c3a-1f6d-4e72-9a48-7c2d0b6e1f95",
  "SystemAlertId": "8d2e6b14-3c7a-4f19-a5e0-91b4c2d7e6f3",
  "VendorOriginalId": "c41a7e92-6b3d-4d58-8f20-5e9a1c3b7d64",
  "Status": "New",
  "ConfidenceLevel": "Unknown",
  "StartTime": "2026-11-09T09:28:40.000Z",
  "EndTime": "2026-11-09T09:36:05.000Z",
  "ProcessingEndTime": "2026-11-09T09:41:12.000Z",
  "IsIncident": false,
  "CompromisedEntity": "203.0.113.77",
  "Tactics": "CredentialAccess",
  "Techniques": "[\"T1110\"]",
  "Entities": "[{\"$id\":\"2\",\"Type\":\"ip\",\"Address\":\"203.0.113.77\"}]",
  "ExtendedProperties": "{\"Query Period\":\"00:10:00\",\"Trigger Operator\":\"GreaterThan\",\"Trigger Threshold\":\"0\",\"Search Query Results Overall Count\":\"14\",\"Analytic Rule Ids\":\"[\\\"5b0e8c3a-1f6d-4e72-9a48-7c2d0b6e1f95\\\"]\",\"Analytic Rule Name\":\"Password spray against many accounts from one address\"}"
}
```

A Defender for Endpoint alert forwarded by the connector:

```json
{
  "TimeGenerated": "2026-11-09T10:02:51.000Z",
  "TenantId": "3f9c1a52-7d4e-4b8a-9c21-6e0f5d7a2b10",
  "Type": "SecurityAlert",
  "SourceSystem": "Detection",
  "DisplayName": "Suspicious PowerShell command line",
  "AlertName": "Suspicious PowerShell command line",
  "AlertSeverity": "High",
  "ProviderName": "MDATP",
  "VendorName": "Microsoft",
  "ProductName": "Microsoft Defender Advanced Threat Protection",
  "AlertType": "SuspiciousPowerShellCommandLine",
  "SystemAlertId": "e7b3c9d1-4a2f-4b86-9e15-2d8c6a0f3b47",
  "VendorOriginalId": "da637912345678901234_-1234567890",
  "Status": "New",
  "ConfidenceLevel": "Unknown",
  "StartTime": "2026-11-09T09:58:14.000Z",
  "EndTime": "2026-11-09T09:58:14.000Z",
  "ProcessingEndTime": "2026-11-09T10:02:51.000Z",
  "IsIncident": false,
  "CompromisedEntity": "WS-FIN-0412",
  "Tactics": "Execution",
  "Techniques": "[\"T1059.001\"]",
  "Entities": "[{\"$id\":\"2\",\"Type\":\"host\",\"HostName\":\"WS-FIN-0412\",\"DnsDomain\":\"corp.example\",\"FQDN\":\"WS-FIN-0412.corp.example\"},{\"$id\":\"3\",\"Type\":\"account\",\"Name\":\"r.alvarez\",\"UPNSuffix\":\"corp.example\",\"AadUserId\":\"9a1f4c7e-2b3d-4e5f-8a6b-0c1d2e3f4a5b\"},{\"$id\":\"4\",\"Type\":\"process\",\"CommandLine\":\"powershell.exe -nop -w hidden -enc SQBFAFgA\"}]",
  "ExtendedProperties": "{\"MicrosoftDefenderAtp.Category\":\"Execution\",\"MicrosoftDefenderAtp.InvestigationState\":\"PendingApproval\"}",
  "AlertLink": "https://security.microsoft.com/alerts/da637912345678901234_-1234567890"
}
```
