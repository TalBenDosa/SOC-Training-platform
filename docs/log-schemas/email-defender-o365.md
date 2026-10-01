# Microsoft Defender for Office 365 — Advanced Hunting email tables (native schema card)

Category: Email security · Vendor: Microsoft · Tables: `EmailEvents`, `EmailUrlInfo`, `EmailAttachmentInfo`, `UrlClickEvents`, `EmailPostDeliveryEvents`
Rule reminder: each log is ONE Advanced Hunting row rendered as a flat JSON object whose keys are the table's column
names exactly (PascalCase). No ECS/Elastic `m365_defender.*` flattening, no Wazuh `data.*`, no Graph-alert wrapping.
Several columns hold **JSON-encoded strings** (`DetectionMethods`, `AuthenticationDetails`, `ConfidenceLevel`,
`AdditionalFields`, `UrlChain`) — they stay strings, they are not expanded into nested objects.

---

## 1. Official sources

| URL | What it confirmed |
|---|---|
| https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table | All `EmailEvents` columns and types (Timestamp, NetworkMessageId, InternetMessageId, SenderMailFromAddress, SenderFromAddress, SenderDisplayName, SenderObjectId, SenderMailFromDomain, SenderFromDomain, SenderIPv4, SenderIPv6, RecipientEmailAddress, RecipientObjectId, Subject, EmailClusterId, EmailDirection, DeliveryAction, DeliveryLocation, ThreatTypes, ThreatNames, DetectionMethods, ConfidenceLevel, BulkComplaintLevel, EmailAction, EmailActionPolicy, EmailActionPolicyGuid, AuthenticationDetails, AttachmentCount, UrlCount, EmailLanguage, Connectors, OrgLevelAction/Policy, UserLevelAction/Policy, ReportId, AdditionalFields, LatestDeliveryLocation, LatestDeliveryAction, OriginalThreatTypes, OriginalDetectionMethods, OriginalConfidenceLevel, DistributionList, ExchangeTransportRule, ForwardingInformation, Context, To, Cc, ThreatClassification, RecipientDomain, EmailSize, IsFirstContact, Topics); enum lists for EmailDirection, DeliveryAction, DeliveryLocation, EmailAction, EmailActionPolicy; Latest* columns not in Streaming API; streaming emits a new record on every verdict/location change. |
| https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailurlinfo-table | Columns Timestamp, NetworkMessageId, Url, UrlDomain, UrlLocation, UrlChainId, UrlChainPosition, ReportId; `UrlLocation` value `QRCode` for QR-extracted URLs. |
| https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailattachmentinfo-table | Columns Timestamp, NetworkMessageId, SenderFromAddress, SenderDisplayName, SenderObjectId, RecipientEmailAddress, RecipientObjectId, FileName, FileType, FileExtension, SHA256 (often empty), FileSize, ThreatTypes, ThreatNames, DetectionMethods, ReportId, AdditionalFields. |
| https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-urlclickevents-table | Columns Timestamp, Url, ActionType, AccountUpn, Workload (`Email`/`Office`/`Teams`), NetworkMessageId, ThreatTypes, DetectionMethods, IPAddress, IsClickedThrough (bool), UrlChain, ReportId, AppName, AppVersion, SourceId; Log-Analytics-only TenantId/Type/SourceSystem/TimeGenerated; `ActionType == "ClickAllowed"` example. |
| https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailpostdeliveryevents-table | Columns Timestamp, NetworkMessageId, InternetMessageId, Action, ActionType (`Manual remediation`, `Phish ZAP`, `Malware ZAP`), ActionTrigger, ActionResult, RecipientEmailAddress, DeliveryLocation, ThreatTypes, DetectionMethods, ReportId, SenderFromAddress, EmailDirection, SourceLocation. |
| https://learn.microsoft.com/en-us/defender-xdr/streaming-api-event-hub | Streaming envelope `{"records":[{"time","tenantId","category":"AdvancedHunting-<Table>","properties":{<row>}}]}`. |
| https://techcommunity.microsoft.com/blog/microsoftdefenderforoffice365blog/introducing-the-urlclickevents-table-in-advanced-hunting-with-microsoft-defender/3295096 and https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules | `UrlClickEvents.ActionType` values seen in practice: `ClickAllowed`, `ClickBlocked`, `ClickBlockedByTenantPolicy`, `UrlScanInProgress`, `UrlErrorPage`. |
| https://learn.microsoft.com/en-us/defender-office-365/remediate-malicious-email-delivered-office-365 | Remediation actions surfaced as `LatestDeliveryAction` / post-delivery `Action`: Soft delete, Hard delete, Move to junk, Move to inbox, Move to deleted items, (Moved to) quarantine. |

---

## 2. Native format & delivery

- **Query path**: Defender portal Advanced Hunting, or API (`POST https://api.security.microsoft.com/api/advancedhunting/run`, or Graph `security/runHuntingQuery`) → `{"Schema":[...], "Results":[ {row}, ... ]}`. Each row is a flat object keyed by column name.
- **Streaming path**: Streaming API → Event Hub / Storage: `{"records":[{"time": "...", "tenantId": "...", "category": "AdvancedHunting-EmailEvents", "properties": {row}}]}`. `LatestDeliveryLocation`/`LatestDeliveryAction` are absent in streaming; one email can produce several records (delivery, then ZAP re-verdict).
- **Sentinel** (`EmailEvents` table in Log Analytics) adds `TenantId`, `TimeGenerated`, `Type`, `SourceSystem` — that is an ingestion envelope, not part of the Defender row.
- **We standardise on**: the Advanced Hunting **row** (keys = column names), `Timestamp` as ISO 8601 UTC with 7 fractional digits + `Z` (`2026-09-29T07:12:05.4471823Z`). Empty string columns are `""`; absent numeric columns `null`. Streaming envelope shown once (D9) for reference.

---

## 3. Core field reference

### 3.1 EmailEvents (one row per message × recipient × verdict change)

| Column | Type | Values / format |
|---|---|---|
| `Timestamp` | datetime | |
| `NetworkMessageId` | string (GUID) | Microsoft-generated; same for all recipients of one message. **Primary join key.** |
| `InternetMessageId` | string | RFC 5322 `Message-ID` incl. `<>`. |
| `SenderMailFromAddress` / `SenderMailFromDomain` | string | envelope (P1, Return-Path). |
| `SenderFromAddress` / `SenderFromDomain` / `SenderDisplayName` | string | header From (P2). |
| `SenderObjectId`, `RecipientObjectId` | string | Entra object ids (empty for external). |
| `SenderIPv4` / `SenderIPv6` | string | last relaying MTA. |
| `RecipientEmailAddress`, `RecipientDomain` | string | after DL expansion. |
| `Subject` | string | |
| `EmailClusterId` | long | |
| `EmailDirection` | string | `Inbound`, `Outbound`, `Intra-org` |
| `DeliveryAction` | string | `Delivered`, `Junked`, `Blocked`, `Replaced` |
| `DeliveryLocation` | string | `Inbox/folder`, `Junk folder`, `Quarantine`, `On-premises/external`, `Deleted items folder`, `Failed`, `Dropped` (doc lists them as Inbox/Folder, On-premises/External, Junk, Quarantine, Failed, Dropped, Deleted items — exact casing in data UNVERIFIED; we use the left-hand strings) |
| `ThreatTypes` | string | comma-separated: `Phish`, `Malware`, `Spam` (e.g. `"Phish, Spam"`); empty if clean |
| `ThreatNames` | string | malware detection names |
| `DetectionMethods` | string (JSON) | `{"Phish":["URL detonation reputation","URL malicious reputation"]}`, `{"Malware":["File detonation"]}`, `{"Phish":["Impersonation user"]}`, `{"Spam":["Mixed analysis detection"]}` (keys = threat type, values = method list; method names representative) |
| `ConfidenceLevel` | string (JSON) | `{"Phish":"High"}`, `{"Spam":"5"}` style — exact layout UNVERIFIED; SCL meaning: -1 skipped, 0/1 not spam, 5/6 spam, 9 high-confidence spam; phish = `High`/`Low` |
| `BulkComplaintLevel` | int | 0–9 |
| `EmailAction` | string | `No action taken`, `Move message to junk mail folder`, `Add X-header`, `Modify subject`, `Redirect message`, `Delete message`, `Send to quarantine`, `Bcc message` |
| `EmailActionPolicy` | string | `Antispam high-confidence`, `Antispam`, `Antispam bulk mail`, `Antispam phishing`, `Anti-phishing domain impersonation`, `Anti-phishing user impersonation`, `Anti-phishing spoof`, `Anti-phishing graph impersonation`, `Antimalware`, `Safe Attachments`, `Enterprise Transport Rules (ETR)` |
| `EmailActionPolicyGuid` | string | |
| `AuthenticationDetails` | string (JSON) | `{"SPF":"pass","DKIM":"pass","DMARC":"pass","CompAuth":"pass"}`; values `pass`/`fail`/`softfail`/`none`/`temperror`/`permerror`/`neutral` |
| `AttachmentCount`, `UrlCount` | int | |
| `EmailLanguage` | string | `en`, `he` ... |
| `Connectors`, `OrgLevelAction`, `OrgLevelPolicy`, `UserLevelAction`, `UserLevelPolicy`, `ExchangeTransportRule`, `DistributionList`, `Context` | string | policy/override context (e.g. OrgLevelAction `Allow`/`Block`, UserLevelPolicy `Sender block list`) |
| `ForwardingInformation` | string (JSON array) | forwarding user + type |
| `LatestDeliveryLocation` / `LatestDeliveryAction` | string | current state after ZAP/remediation (not in streaming). Action values seen: `Delivered`, `Blocked`, `Junked`, `Moved to quarantine`, `Soft delete`, `Hard delete`, `Quarantine release` — UNVERIFIED list |
| `OriginalThreatTypes` / `OriginalDetectionMethods` / `OriginalConfidenceLevel` | string | verdict at delivery time |
| `To`, `Cc` | string | header addresses |
| `ThreatClassification` | string | newer column |
| `EmailSize` | long | bytes |
| `IsFirstContact` | int | 1/0 |
| `Topics` | string | newer column |
| `ReportId` | string | event id; format UNVERIFIED |
| `AdditionalFields` | string (JSON) | |

### 3.2 EmailUrlInfo
`Timestamp`, `NetworkMessageId`, `Url`, `UrlDomain`, `UrlLocation` (`Body`, `Attachment`, `Subject`, `QRCode`, `CloudAttachment` — only `QRCode` explicitly documented; rest UNVERIFIED), `UrlChainId`, `UrlChainPosition` (int, root = 0), `ReportId`.

### 3.3 EmailAttachmentInfo
`Timestamp`, `NetworkMessageId`, `SenderFromAddress`, `SenderDisplayName`, `SenderObjectId`, `RecipientEmailAddress`, `RecipientObjectId`, `FileName`, `FileType`, `FileExtension`, `SHA256` (may be empty), `FileSize` (long), `ThreatTypes`, `ThreatNames`, `DetectionMethods`, `ReportId`, `AdditionalFields`.

### 3.4 UrlClickEvents (Safe Links)
`Timestamp`, `Url`, `ActionType` (`ClickAllowed`, `ClickBlocked`, `ClickBlockedByTenantPolicy`, `UrlScanInProgress`, `UrlErrorPage`), `AccountUpn`, `Workload` (`Email`, `Office`, `Teams`), `NetworkMessageId`, `ThreatTypes`, `DetectionMethods`, `IPAddress`, `IsClickedThrough` (bool — user pressed "Continue anyway" on the warning page), `UrlChain` (string, JSON array of redirect hops), `ReportId` (same value for the block + click-through pair), `AppName`, `AppVersion`, `SourceId`.

### 3.5 EmailPostDeliveryEvents
`Timestamp`, `NetworkMessageId`, `InternetMessageId`, `Action` (e.g. `Moved to quarantine`, `Moved to junk folder`, `Soft delete`, `Hard delete`), `ActionType` (`Manual remediation`, `Phish ZAP`, `Malware ZAP`), `ActionTrigger` (e.g. `AdminAction`, `SpecialAction` — UNVERIFIED value strings), `ActionResult` (e.g. `Success`, `Error`), `RecipientEmailAddress`, `DeliveryLocation`, `ThreatTypes`, `DetectionMethods`, `ReportId`, `SenderFromAddress`, `EmailDirection`, `SourceLocation`.

---

## 4. Realistic samples (fictitious tenant `nexacorp.com`)

Story A: a DocuSign-lure phish from look-alike domain `docusign-esign.net` is delivered to Dana Levi (clean at delivery),
she clicks through the Safe Links warning, then Phish ZAP quarantines it.
Story B: an HTML-smuggling attachment is blocked by Safe Attachments.
Story C: a CEO-impersonation (BEC) mail is junked by anti-phishing user impersonation.

### D1 — EmailEvents: phish delivered to Inbox (Story A)
```json
{
  "Timestamp": "2026-09-29T07:12:05.4471823Z",
  "NetworkMessageId": "a7d3c1e9-5b2f-4e86-0c9a-08dce04f7b31",
  "InternetMessageId": "<20260929071158.9F2C41A07B@mta3.docusign-esign.net>",
  "SenderMailFromAddress": "bounce-7731@docusign-esign.net",
  "SenderFromAddress": "dse@docusign-esign.net",
  "SenderDisplayName": "DocuSign via Finance",
  "SenderObjectId": "",
  "SenderMailFromDomain": "docusign-esign.net",
  "SenderFromDomain": "docusign-esign.net",
  "SenderIPv4": "203.0.113.45",
  "SenderIPv6": "",
  "RecipientEmailAddress": "dana.levi@nexacorp.com",
  "RecipientObjectId": "6a1f3c9e-55d2-4b8a-9e07-c2d4f8a1b3e6",
  "Subject": "Please review and sign: Q3 Vendor Payment Authorization",
  "EmailClusterId": 3019485172634,
  "EmailDirection": "Inbound",
  "DeliveryAction": "Delivered",
  "DeliveryLocation": "Inbox/folder",
  "ThreatTypes": "",
  "ThreatNames": "",
  "DetectionMethods": "",
  "ConfidenceLevel": "{\"Spam\":\"1\"}",
  "BulkComplaintLevel": 0,
  "EmailAction": "No action taken",
  "EmailActionPolicy": "",
  "EmailActionPolicyGuid": "",
  "AuthenticationDetails": "{\"SPF\":\"pass\",\"DKIM\":\"pass\",\"DMARC\":\"pass\",\"CompAuth\":\"pass\"}",
  "AttachmentCount": 0,
  "UrlCount": 2,
  "EmailLanguage": "en",
  "Connectors": "",
  "OrgLevelAction": "",
  "OrgLevelPolicy": "",
  "UserLevelAction": "",
  "UserLevelPolicy": "",
  "ReportId": "a7d3c1e9-5b2f-4e86-0c9a-08dce04f7b31-12847193650283746519-1",
  "AdditionalFields": "{}",
  "LatestDeliveryLocation": "Quarantine",
  "LatestDeliveryAction": "Moved to quarantine",
  "OriginalThreatTypes": "",
  "OriginalDetectionMethods": "",
  "OriginalConfidenceLevel": "{\"Spam\":\"1\"}",
  "DistributionList": "",
  "ExchangeTransportRule": "",
  "ForwardingInformation": "",
  "Context": "",
  "To": "dana.levi@nexacorp.com",
  "Cc": "",
  "ThreatClassification": "",
  "RecipientDomain": "nexacorp.com",
  "EmailSize": 38214,
  "IsFirstContact": 1,
  "Topics": ""
}
```
(Look-alike domains owned by the attacker often PASS SPF/DKIM/DMARC — authentication pass ≠ legitimate.)

### D2 — EmailUrlInfo: URLs in the D1 message
```json
{
  "Timestamp": "2026-09-29T07:12:05.4471823Z",
  "NetworkMessageId": "a7d3c1e9-5b2f-4e86-0c9a-08dce04f7b31",
  "Url": "https://docusign-esign.net/envelope/review?id=Q3-VPA-88231&u=dana.levi%40nexacorp.com",
  "UrlDomain": "docusign-esign.net",
  "UrlLocation": "Body",
  "UrlChainId": "",
  "UrlChainPosition": 0,
  "ReportId": "a7d3c1e9-5b2f-4e86-0c9a-08dce04f7b31-12847193650283746519-1"
}
```

### D3 — UrlClickEvents: user clicks through the Safe Links warning (Story A)
```json
{
  "Timestamp": "2026-09-29T07:34:48.1903364Z",
  "Url": "https://docusign-esign.net/envelope/review?id=Q3-VPA-88231&u=dana.levi%40nexacorp.com",
  "ActionType": "ClickAllowed",
  "AccountUpn": "dana.levi@nexacorp.com",
  "Workload": "Email",
  "NetworkMessageId": "a7d3c1e9-5b2f-4e86-0c9a-08dce04f7b31",
  "ThreatTypes": "Phish",
  "DetectionMethods": "{\"Phish\":[\"URL detonation reputation\"]}",
  "IPAddress": "198.51.100.24",
  "IsClickedThrough": true,
  "UrlChain": "[\"https://docusign-esign.net/envelope/review?id=Q3-VPA-88231&u=dana.levi%40nexacorp.com\",\"https://login-microsoftonline.docusign-esign.net/common/oauth2/authorize\"]",
  "ReportId": "f3b9a2c7-1d4e-4f68-8a05-6c2e9d7b1f40",
  "AppName": "Outlook",
  "AppVersion": "16.0.18025.20160",
  "SourceId": "OutlookDesktop"
}
```
(The paired blocked-page record shares the same `ReportId`. `AppName`/`SourceId` value strings are UNVERIFIED.)

### D4 — EmailEvents: re-verdict record after detonation (streaming emits a second row, Story A)
```json
{
  "Timestamp": "2026-09-29T07:36:10.8820517Z",
  "NetworkMessageId": "a7d3c1e9-5b2f-4e86-0c9a-08dce04f7b31",
  "InternetMessageId": "<20260929071158.9F2C41A07B@mta3.docusign-esign.net>",
  "SenderMailFromAddress": "bounce-7731@docusign-esign.net",
  "SenderFromAddress": "dse@docusign-esign.net",
  "SenderDisplayName": "DocuSign via Finance",
  "SenderObjectId": "",
  "SenderMailFromDomain": "docusign-esign.net",
  "SenderFromDomain": "docusign-esign.net",
  "SenderIPv4": "203.0.113.45",
  "SenderIPv6": "",
  "RecipientEmailAddress": "dana.levi@nexacorp.com",
  "RecipientObjectId": "6a1f3c9e-55d2-4b8a-9e07-c2d4f8a1b3e6",
  "Subject": "Please review and sign: Q3 Vendor Payment Authorization",
  "EmailClusterId": 3019485172634,
  "EmailDirection": "Inbound",
  "DeliveryAction": "Delivered",
  "DeliveryLocation": "Inbox/folder",
  "ThreatTypes": "Phish",
  "ThreatNames": "",
  "DetectionMethods": "{\"Phish\":[\"URL detonation reputation\",\"URL malicious reputation\"]}",
  "ConfidenceLevel": "{\"Phish\":\"High\",\"Spam\":\"1\"}",
  "BulkComplaintLevel": 0,
  "EmailAction": "Send to quarantine",
  "EmailActionPolicy": "Antispam phishing",
  "EmailActionPolicyGuid": "2c8e4a1f-9d3b-4f75-a6e0-1b7d3c9f5e28",
  "AuthenticationDetails": "{\"SPF\":\"pass\",\"DKIM\":\"pass\",\"DMARC\":\"pass\",\"CompAuth\":\"pass\"}",
  "AttachmentCount": 0,
  "UrlCount": 2,
  "EmailLanguage": "en",
  "Connectors": "",
  "OrgLevelAction": "",
  "OrgLevelPolicy": "",
  "UserLevelAction": "",
  "UserLevelPolicy": "",
  "ReportId": "a7d3c1e9-5b2f-4e86-0c9a-08dce04f7b31-12847193650283746519-2",
  "AdditionalFields": "{}",
  "OriginalThreatTypes": "",
  "OriginalDetectionMethods": "",
  "OriginalConfidenceLevel": "{\"Spam\":\"1\"}",
  "To": "dana.levi@nexacorp.com",
  "Cc": "",
  "RecipientDomain": "nexacorp.com",
  "EmailSize": 38214,
  "IsFirstContact": 1
}
```

### D5 — EmailPostDeliveryEvents: Phish ZAP moves it to quarantine (Story A)
```json
{
  "Timestamp": "2026-09-29T07:36:41.2275908Z",
  "NetworkMessageId": "a7d3c1e9-5b2f-4e86-0c9a-08dce04f7b31",
  "InternetMessageId": "<20260929071158.9F2C41A07B@mta3.docusign-esign.net>",
  "Action": "Moved to quarantine",
  "ActionType": "Phish ZAP",
  "ActionTrigger": "SpecialAction",
  "ActionResult": "Success",
  "RecipientEmailAddress": "dana.levi@nexacorp.com",
  "DeliveryLocation": "Quarantine",
  "ThreatTypes": "Phish",
  "DetectionMethods": "{\"Phish\":[\"URL detonation reputation\",\"URL malicious reputation\"]}",
  "ReportId": "d81c5e3a-7f2b-4a96-b0d4-3e9a1c7f5b62",
  "SenderFromAddress": "dse@docusign-esign.net",
  "EmailDirection": "Inbound",
  "SourceLocation": "Inbox"
}
```

### D6 — EmailEvents: HTML-smuggling attachment blocked by Safe Attachments (Story B)
```json
{
  "Timestamp": "2026-09-30T10:02:19.6634071Z",
  "NetworkMessageId": "c2e8b4f1-9a3d-4c57-1e6b-08dce1a3d9f4",
  "InternetMessageId": "<CAOq7v2Wk9xR3mT5pL1aZ8nB4dH6jF2sY0uE7cQ9iG3o@mail.gmail.com>",
  "SenderMailFromAddress": "accounts.payable.vendor44@gmail.com",
  "SenderFromAddress": "accounts.payable.vendor44@gmail.com",
  "SenderDisplayName": "Accounts Payable",
  "SenderObjectId": "",
  "SenderMailFromDomain": "gmail.com",
  "SenderFromDomain": "gmail.com",
  "SenderIPv4": "209.85.218.47",
  "SenderIPv6": "",
  "RecipientEmailAddress": "yael.cohen@nexacorp.com",
  "RecipientObjectId": "1e7c3a9f-4b2d-4f86-a0e5-9c3d7b1f2a64",
  "Subject": "Remittance advice 30-09-2026",
  "EmailClusterId": 3019485903317,
  "EmailDirection": "Inbound",
  "DeliveryAction": "Blocked",
  "DeliveryLocation": "Quarantine",
  "ThreatTypes": "Malware",
  "ThreatNames": "Trojan:HTML/Phish.SMG!MTB",
  "DetectionMethods": "{\"Malware\":[\"File detonation\"]}",
  "ConfidenceLevel": "",
  "BulkComplaintLevel": 0,
  "EmailAction": "Send to quarantine",
  "EmailActionPolicy": "Safe Attachments",
  "EmailActionPolicyGuid": "7b3d9f1e-2c6a-4e84-b5d0-8f1a3c7e9d26",
  "AuthenticationDetails": "{\"SPF\":\"pass\",\"DKIM\":\"pass\",\"DMARC\":\"pass\",\"CompAuth\":\"pass\"}",
  "AttachmentCount": 1,
  "UrlCount": 0,
  "EmailLanguage": "en",
  "Connectors": "",
  "OrgLevelAction": "",
  "OrgLevelPolicy": "",
  "UserLevelAction": "",
  "UserLevelPolicy": "",
  "ReportId": "c2e8b4f1-9a3d-4c57-1e6b-08dce1a3d9f4-9038471625503917284-1",
  "AdditionalFields": "{}",
  "LatestDeliveryLocation": "Quarantine",
  "LatestDeliveryAction": "Blocked",
  "OriginalThreatTypes": "Malware",
  "OriginalDetectionMethods": "{\"Malware\":[\"File detonation\"]}",
  "OriginalConfidenceLevel": "",
  "To": "yael.cohen@nexacorp.com",
  "Cc": "",
  "RecipientDomain": "nexacorp.com",
  "EmailSize": 412887,
  "IsFirstContact": 1
}
```

### D7 — EmailAttachmentInfo: the blocked attachment (Story B)
```json
{
  "Timestamp": "2026-09-30T10:02:19.6634071Z",
  "NetworkMessageId": "c2e8b4f1-9a3d-4c57-1e6b-08dce1a3d9f4",
  "SenderFromAddress": "accounts.payable.vendor44@gmail.com",
  "SenderDisplayName": "Accounts Payable",
  "SenderObjectId": "",
  "RecipientEmailAddress": "yael.cohen@nexacorp.com",
  "RecipientObjectId": "1e7c3a9f-4b2d-4f86-a0e5-9c3d7b1f2a64",
  "FileName": "Remittance_30092026.html",
  "FileType": "html",
  "FileExtension": "html",
  "SHA256": "4f9a2c7e1b3d5f8a0c2e4b6d8f1a3c5e7b9d2f4a6c8e0b1d3f5a7c9e2b4d6f80",
  "FileSize": 398112,
  "ThreatTypes": "Malware",
  "ThreatNames": "Trojan:HTML/Phish.SMG!MTB",
  "DetectionMethods": "{\"Malware\":[\"File detonation\"]}",
  "ReportId": "c2e8b4f1-9a3d-4c57-1e6b-08dce1a3d9f4-9038471625503917284-1",
  "AdditionalFields": "{}"
}
```

### D8 — EmailEvents: CEO impersonation (BEC) junked by user-impersonation protection (Story C)
```json
{
  "Timestamp": "2026-09-30T13:47:52.3018846Z",
  "NetworkMessageId": "e5a1d7c3-2f9b-4b68-3d0e-08dce1c45a27",
  "InternetMessageId": "<0102019243b7e1a4-8c2f-4d1e-9a7b-3f5e1c9d2b84-000000@eu-west-1.amazonses.com>",
  "SenderMailFromAddress": "0102019243b7e1a4@eu-west-1.amazonses.com",
  "SenderFromAddress": "ronen.shapira.ceo@nexacorp-exec.com",
  "SenderDisplayName": "Ronen Shapira",
  "SenderObjectId": "",
  "SenderMailFromDomain": "eu-west-1.amazonses.com",
  "SenderFromDomain": "nexacorp-exec.com",
  "SenderIPv4": "54.240.4.17",
  "SenderIPv6": "",
  "RecipientEmailAddress": "yael.cohen@nexacorp.com",
  "RecipientObjectId": "1e7c3a9f-4b2d-4f86-a0e5-9c3d7b1f2a64",
  "Subject": "Urgent - confidential wire today",
  "EmailClusterId": 3019486110274,
  "EmailDirection": "Inbound",
  "DeliveryAction": "Junked",
  "DeliveryLocation": "Junk folder",
  "ThreatTypes": "Phish",
  "ThreatNames": "",
  "DetectionMethods": "{\"Phish\":[\"Impersonation user\"]}",
  "ConfidenceLevel": "{\"Phish\":\"High\"}",
  "BulkComplaintLevel": 0,
  "EmailAction": "Move message to junk mail folder",
  "EmailActionPolicy": "Anti-phishing user impersonation",
  "EmailActionPolicyGuid": "9e1b5d3f-7a2c-4c96-b8d0-2f4a6c8e1b37",
  "AuthenticationDetails": "{\"SPF\":\"pass\",\"DKIM\":\"pass\",\"DMARC\":\"none\",\"CompAuth\":\"softpass\"}",
  "AttachmentCount": 0,
  "UrlCount": 0,
  "EmailLanguage": "en",
  "Connectors": "",
  "OrgLevelAction": "",
  "OrgLevelPolicy": "",
  "UserLevelAction": "",
  "UserLevelPolicy": "",
  "ReportId": "e5a1d7c3-2f9b-4b68-3d0e-08dce1c45a27-4471928305516620937-1",
  "AdditionalFields": "{}",
  "LatestDeliveryLocation": "Junk folder",
  "LatestDeliveryAction": "Junked",
  "OriginalThreatTypes": "Phish",
  "OriginalDetectionMethods": "{\"Phish\":[\"Impersonation user\"]}",
  "OriginalConfidenceLevel": "{\"Phish\":\"High\"}",
  "To": "yael.cohen@nexacorp.com",
  "Cc": "",
  "RecipientDomain": "nexacorp.com",
  "EmailSize": 6120,
  "IsFirstContact": 1
}
```

### D9 — Streaming API envelope (Event Hub) carrying a UrlClickEvents row
```json
{
  "records": [
    {
      "time": "2026-09-29T07:34:52.0000000Z",
      "tenantId": "4f1c2b7e-9a3d-4c8e-b2f6-7d1e0a9c5b31",
      "operationName": "Publish",
      "category": "AdvancedHunting-UrlClickEvents",
      "properties": {
        "Timestamp": "2026-09-29T07:34:48.1903364Z",
        "Url": "https://docusign-esign.net/envelope/review?id=Q3-VPA-88231&u=dana.levi%40nexacorp.com",
        "ActionType": "ClickBlocked",
        "AccountUpn": "dana.levi@nexacorp.com",
        "Workload": "Email",
        "NetworkMessageId": "a7d3c1e9-5b2f-4e86-0c9a-08dce04f7b31",
        "ThreatTypes": "Phish",
        "DetectionMethods": "{\"Phish\":[\"URL detonation reputation\"]}",
        "IPAddress": "198.51.100.24",
        "IsClickedThrough": false,
        "UrlChain": "[\"https://docusign-esign.net/envelope/review?id=Q3-VPA-88231&u=dana.levi%40nexacorp.com\"]",
        "ReportId": "f3b9a2c7-1d4e-4f68-8a05-6c2e9d7b1f40"
      }
    }
  ]
}
```
(`operationName:"Publish"` is commonly present in real streaming records but is not in the doc's schema snippet — UNVERIFIED. This is the warning-page block that precedes D3; same `ReportId`.)

---

## 5. Investigation notes (pivots)

- **NetworkMessageId** joins `EmailEvents` ↔ `EmailUrlInfo` ↔ `EmailAttachmentInfo` ↔ `UrlClickEvents` ↔ `EmailPostDeliveryEvents` (one id per message; combine with `RecipientEmailAddress` for per-recipient state).
- **InternetMessageId** joins out of Defender: M365 UAL `MailItemsAccessed` `FolderItems[].InternetMessageId`, Proofpoint `messageID`, Gmail `rfc2822_message_id`.
- **Click → identity**: `UrlClickEvents.AccountUpn` + `IPAddress` + `Timestamp` → Entra sign-ins / UAL `UserLoggedIn` from a new IP minutes later = credential phish success.
- **Re-verdict**: compare `OriginalThreatTypes` vs `ThreatTypes`, and `DeliveryLocation` vs `LatestDeliveryLocation` — "delivered clean, later ZAPped" is the case where users clicked before protection caught up.
- **Campaign scope**: `EmailClusterId`, `SenderFromDomain`, `SenderIPv4`, `UrlDomain`, `SHA256` → all recipients; `EmailPostDeliveryEvents` shows which copies were actually removed (`ActionResult`).
- **Auth anomalies**: parse `AuthenticationDetails` JSON — `DMARC:fail` + display-name match on an exec = spoof; `pass` on a look-alike domain = impersonation, not spoof.

## 6. Common mistakes / fields that do NOT exist

- No `SenderIP`/`SenderIPAddress` (it is `SenderIPv4`/`SenderIPv6`), no `Recipient`/`Sender` short names, no `Verdict`, `Severity`, `Action` in `EmailEvents` (`Action` exists only in `EmailPostDeliveryEvents`).
- `Url` does not exist in `EmailEvents` (URLs are in `EmailUrlInfo`); `FileName`/`SHA256` do not exist in `EmailEvents` (they are in `EmailAttachmentInfo`).
- `UrlClickEvents` has `AccountUpn` and `IPAddress` — not `UserId`, `RecipientEmailAddress`, `ClientIP`.
- Retired columns `PhishFilterVerdict`, `MalwareFilterVerdict`, `PhishDetectionMethod`, `MalwareDetectionMethod` must not be generated (consolidated into `ThreatTypes`/`DetectionMethods`).
- `ThreatTypes` is a plain comma-separated string, not an array; `DetectionMethods`/`AuthenticationDetails` are JSON **strings**, not nested objects.
- `IsClickedThrough` is a boolean; `ActionType` values are `ClickAllowed`/`ClickBlocked`/... (not `Allowed`, `Blocked`, `Permitted`).
- `EmailPostDeliveryEvents.ActionType` is only `Manual remediation`, `Phish ZAP`, `Malware ZAP` — no `Spam ZAP`/`User reported` rows in this table.
- Do not attach `DeviceName`, `DeviceId`, `InitiatingProcess*` (endpoint tables) to email rows.
