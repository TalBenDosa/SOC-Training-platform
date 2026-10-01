# Microsoft 365 Unified Audit Log — Office 365 Management Activity API (native schema card)

Category: Email & Collaboration · Vendor: Microsoft · Workloads covered: `Exchange`, `SharePoint`, `OneDrive`, `AzureActiveDirectory`
Rule reminder: records are shown exactly as the Management Activity API returns them (flat PascalCase JSON
object per audit record). No `data.office365.*` (Wazuh) envelope, no `o365.audit.*` / ECS (Elastic) flattening,
no Sentinel `OfficeActivity` column renames (`Client_IPAddress`, `OfficeWorkload`, `UserId_` ...).

---

## 1. Official sources

| URL | What it confirmed |
|---|---|
| https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema | Common schema (Id, RecordType, CreationTime, Operation, OrganizationId, UserType, UserKey, Workload, ResultStatus, ObjectId, UserId, ClientIP, Scope, AppAccessContext); full `RecordType` enum; `UserType` enum; Exchange admin schema (Parameters, ModifiedProperties, ExternalAccess, OriginatingServer, OrganizationName); Exchange mailbox schema (LogonType enum, MailboxOwnerUPN, ClientInfoString, ClientIPAddress, SessionId, OperationProperties, Item, Folders, AffectedItems); aggregated mailbox record (OperationCount, Folders[].FolderItems[]); SharePoint base / file-operation / sharing schemas; Azure AD base / STS logon schemas (ExtendedProperties, DeviceProperties, LogonError, ErrorCode, Actor/Target IdentityTypeValuePair). |
| https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-reference | Delivery model: subscriptions per content type (`Audit.Exchange`, `Audit.SharePoint`, `Audit.AzureActiveDirectory`, `Audit.General`, `DLP.All`), `/subscriptions/content` returns blob URIs; each blob is a JSON **array** of audit records. |
| https://learn.microsoft.com/en-us/purview/audit-log-investigate-accounts | `MailItemsAccessed`: Bind vs Sync in `OperationProperties` (`MailAccessType`), 2-minute bind aggregation into `Folders` with `InternetMessageId`, `OperationCount`, dedup keys (ClientIPAddress, ClientInfoString, ParentFolder, LogonType, MailAccessType, SessionId). |
| https://learn.microsoft.com/en-us/purview/audit-log-activities | Friendly-name ↔ `Operation` mapping (FileDownloaded, FileAccessed, SharingSet, AnonymousLinkCreated, SharingInvitationCreated, New-InboxRule, Set-InboxRule, UpdateInboxRules, Set-Mailbox, Add-MailboxPermission, Consent to application., Add member to role.). |
| https://github.com/elastic/integrations/tree/main/packages/o365/data_stream/audit/_dev/test/pipeline | Real raw records (`event.original`) for UserLoggedIn / UserLoginFailed (RecordType 15), Consent to application. (RecordType 8, ModifiedProperties `ConsentContext.*` / `ConsentAction.Permissions`), Add-MailboxPermission (ExchangeAdmin, `ResultStatus:"True"`), AnonymousLinkCreated (RecordType 14, `EventData:"<Type>Edit</Type>"`, `UniqueSharingId`), FileAccessed (RecordType 6), MailItemsAccessed (RecordType 50, `Folders[].FolderItems[]`, `AppAccessContext`, `OperationProperties`). |
| https://learn.microsoft.com/en-us/powershell/module/exchange/new-inboxrule , .../set-mailbox | Cmdlet parameter names that appear verbatim in `Parameters[]` (ForwardTo, RedirectTo, ForwardAsAttachmentTo, DeleteMessage, MoveToFolder, MarkAsRead, StopProcessingRules, SubjectOrBodyContainsWords, From; ForwardingSmtpAddress, DeliverToMailboxAndForward). |

---

## 2. Native format & delivery

- **Transport**: `GET https://manage.office.com/api/v1.0/{tenantId}/activity/feed/subscriptions/content?contentType=Audit.Exchange` → list of content blobs → `GET {contentUri}` → **JSON array** of audit records. Each record is one flat object; nested only where the schema says so (`Parameters`, `ExtendedProperties`, `ModifiedProperties`, `Actor`, `Target`, `Item`, `Folders`, `AppAccessContext`, `OperationProperties`, `DeviceProperties`).
- The same JSON is the `AuditData` column of `Search-UnifiedAuditLog` and the "Export" in Purview Audit.
- **We standardise on**: one audit record = one JSON object, keys exactly as below, `RecordType` / `UserType` / `LogonType` / `AzureActiveDirectoryEventType` as **integers**, `CreationTime` as `YYYY-MM-DDThh:mm:ss` (UTC, **no `Z`, no milliseconds** — that is how the API emits it).
  - Note: some collectors (and Elastic test fixtures) carry numbers as strings (`"RecordType":"15"`). The API documents them as enums/Int32; integers are the canonical form we use.
- Inside `ExtendedProperties` / `Parameters` / `DeviceProperties` every value is a **string** (`{"Name":"KeepMeSignedIn","Value":"False"}`).

---

## 3. Core field reference

### 3.1 Common schema (every record)

| Field | Type | Notes |
|---|---|---|
| `Id` | GUID string | Unique per record. |
| `RecordType` | int | See 3.2. |
| `CreationTime` | string `YYYY-MM-DDThh:mm:ss` | UTC, no zone suffix. |
| `Operation` | string | Exact operation name (case and trailing dot matter: `Consent to application.`). |
| `OrganizationId` | GUID string | Tenant id. |
| `UserType` | int | 0 Regular, 1 Reserved, 2 Admin, 3 DcAdmin, 4 System, 5 Application, 6 ServicePrincipal, 7 CustomPolicy, 8 SystemPolicy, 9 PartnerTechnician, 10 Guest. |
| `UserKey` | string | PUID / SID / app id depending on workload. |
| `Workload` | string | `Exchange`, `SharePoint`, `OneDrive`, `AzureActiveDirectory`, `MicrosoftTeams`, `SecurityComplianceCenter`, `ThreatIntelligence` ... |
| `ResultStatus` | string | Doc enum: `Succeeded` / `PartiallySucceeded` / `Failed` (STS logons RT 15, mailbox RT 2/50). **Exchange admin cmdlets (RT 1) emit `"True"` / `"False"`**; **AAD directory audits (RT 8) emit `"Success"` / `"Failure"`** (both observed in real records). SharePoint file ops often omit it. |
| `ObjectId` | string | File URL, mailbox identity, rule identity, target app id ... |
| `UserId` | string | UPN of actor (can be `NT AUTHORITY\SYSTEM (...)` or `S-1-5-18` for system actions). |
| `ClientIP` | string | IPv4/IPv6; Exchange records may carry a port (`203.0.113.77:51934`) or bracketed IPv6. |
| `Scope` | int | 0 Online, 1 Onprem (often absent). |
| `AppAccessContext` | object | `AADSessionId`, `APIId`, `ClientAppId`, `ClientAppName`, `CorrelationId`, `UniqueTokenId`, `IssuedAtTime`. Documented as a collection; observed as a single object in real Exchange records. |
| `Version` | int/string | Usually `1` (present in real records, not in the doc table). |

### 3.2 RecordType values used in this category

| Value | Name | Typical operations |
|---|---|---|
| 1 | ExchangeAdmin | `New-InboxRule`, `Set-InboxRule`, `Set-Mailbox`, `Add-MailboxPermission`, `New-TransportRule`, `Add-RecipientPermission` |
| 2 | ExchangeItem | `Send`, `SendAs`, `SendOnBehalf`, `Create`, `Update`, `UpdateInboxRules`, `HardDelete`, `SoftDelete`, `MoveToDeletedItems` |
| 3 | ExchangeItemGroup | `MoveToDeletedItems`, `SoftDelete`, `HardDelete` (bulk), `Move` |
| 4 | SharePoint | site/admin events |
| 6 | SharePointFileOperation | `FileAccessed`, `FileDownloaded`, `FileUploaded`, `FileModified`, `FileDeleted`, `FileSyncDownloadedFull`, `FilePreviewed` |
| 7 | OneDrive | |
| 8 | AzureActiveDirectory | `Add member to role.`, `Consent to application.`, `Add OAuth2PermissionGrant.`, `Add service principal.`, `Update user.`, `Reset user password.` |
| 9 | AzureActiveDirectoryAccountLogon | deprecated |
| 14 | SharePointSharingOperation | `SharingSet`, `AnonymousLinkCreated`, `AnonymousLinkUsed`, `SharingInvitationCreated`, `SecureLinkCreated`, `AddedToSecureLink` |
| 15 | AzureActiveDirectoryStsLogon | `UserLoggedIn`, `UserLoginFailed` |
| 28 | ThreatIntelligence | Defender for Office 365 phish/malware events |
| 41 | ThreatIntelligenceUrl | Safe Links click events |
| 50 | ExchangeItemAggregated | `MailItemsAccessed`, `AttachmentAccess` |

### 3.3 Exchange admin schema (RecordType 1)

`ModifiedObjectResolvedName` (string), `Parameters` (array of `{Name,Value}` — every cmdlet parameter actually passed),
`ModifiedProperties` (array), `ExternalAccess` (bool — true = run by Microsoft datacenter / service), `OriginatingServer`
(string, e.g. `"AM6PR04MB5211 (15.20.7409.032)"`), `OrganizationName`, `TokenObjectId`, `TokenTenantId`, `AppId`, `ClientAppId`.

Key `Parameters[].Name` values:
- `New-InboxRule` / `Set-InboxRule`: `Name`, `Identity` (Set-), `From`, `SubjectContainsWords`, `BodyContainsWords`, `SubjectOrBodyContainsWords`, `ForwardTo`, `RedirectTo`, `ForwardAsAttachmentTo`, `MoveToFolder`, `DeleteMessage`, `MarkAsRead`, `StopProcessingRules`, `AlwaysDeleteOutlookRulesBlob`, `Force`.
- `Set-Mailbox` (forwarding): `Identity`, `ForwardingSmtpAddress` (value `smtp:user@domain`), `ForwardingAddress` (internal recipient), `DeliverToMailboxAndForward` (`True`/`False`).
- `Add-MailboxPermission`: `Identity`, `User`, `AccessRights` (`FullAccess`), `InheritanceType`, `AutoMapping`.

### 3.4 Exchange mailbox schema (RecordType 2 / 3 / 50)

| Field | Type | Notes |
|---|---|---|
| `LogonType` | int | 0 Owner, 1 Admin, 2 Delegated, 3 Transport, 4 SystemService, 5 BestAccess, 6 DelegatedAdmin. |
| `InternalLogonType` | int | Internal. |
| `MailboxGuid`, `MailboxOwnerUPN`, `MailboxOwnerSid`, `MailboxOwnerMasterAccountSid` | string | Owner of the mailbox touched. |
| `LogonUserSid`, `LogonUserDisplayName` | string | Who acted. |
| `ExternalAccess` | bool | |
| `ClientInfoString` | string | e.g. `Client=OWA;Action=ViaProxy`, `Client=REST;Client=RESTSystem;;`, `Client=MSExchangeRPC`, `Client=WebServices;...`. |
| `ClientIPAddress` | string | Client IP for mailbox events (MailItemsAccessed records may carry this **instead of** `ClientIP`). |
| `ClientProcessName`, `ClientVersion`, `ClientMachineName` | string | Outlook desktop details. |
| `SessionId` | GUID string | Exchange session — main pivot for "attacker session vs owner session". |
| `AppId`, `ClientAppId` | string | Calling app. |
| `OperationProperties` | array `{Name,Value}` | `MailAccessType` (`Bind`/`Sync`), `IsThrottled` (`True`/`False`). |
| `Item` | object | `Id`, `Subject`, `ParentFolder{Id,Path}`, `InternetMessageId`, `Attachments`, `SizeInBytes`, `ImmutableId`. |
| `Folders` (RT 50) | array | `{Id, Path, FolderItems:[{Id, ImmutableId, InternetMessageId, SizeInBytes}]}` |
| `OperationCount` (RT 50) | int | Number of aggregated operations. |
| `AffectedItems`, `Folder`, `DestFolder`, `CrossMailboxOperations` (RT 3) | | Bulk ops. |

### 3.5 SharePoint / OneDrive schema (RecordType 6 / 14)

Base: `Site` (GUID), `ItemType` (string: `File`, `Folder`, `Web`, `Site`, `List`, ... — emitted as string name), `EventSource` (`SharePoint`/`ObjectModel`),
`SourceName`, `UserAgent`, `MachineDomainInfo`, `MachineId`, `ListId`, `ListItemUniqueId`, `WebId`, `CorrelationId`, `ApplicationId`, `ApplicationDisplayName`, `IsManagedDevice`, `DeviceDisplayName`, `GeoLocation` (SharePoint geo, e.g. `EUR` — this is the data-residency geo, NOT IP geolocation).
File ops: `SiteUrl`, `SourceRelativeUrl`, `SourceFileName`, `SourceFileExtension`, `DestinationRelativeUrl`, `DestinationFileName`, `DestinationFileExtension`, `UserSharedWith`, `SharingType`, `SensitivityLabelId`.
Sharing ops: `TargetUserOrGroupName`, `TargetUserOrGroupType` (`Member`/`Guest`/`SharePointGroup`/`SecurityGroup`/`Partner`), `EventData` (XML snippet string, e.g. `<Type>View</Type>` / `<Type>Edit</Type>`), `UniqueSharingId`.

### 3.6 Azure AD schemas (RecordType 8 / 15)

| Field | Type | Notes |
|---|---|---|
| `AzureActiveDirectoryEventType` | int | 0 AccountLogon, 1 AzureApplicationAuditEvent (logons in RT 15 carry `1` in real data). |
| `Actor`, `Target` | array `{ID, Type}` | `Type` is int per IdentityType: 0 Claim, 1 Name, 2 Other, 3 PUID, 4 SPN, 5 UPN. |
| `ActorContextId`, `TargetContextId` | GUID | Tenant ids. |
| `ActorIpAddress` | string | |
| `InterSystemsId`, `IntraSystemId` | GUID | `IntraSystemId` = Entra request id (joins to Entra sign-in log `id`/correlation). |
| `ExtendedProperties` | array `{Name,Value}` | Logons: `UserAgent`, `RequestType` (`OAuth2:Authorize`, `OAuth2:Token`, `Login:login`, `Login:reprocess`, `SAS:ProcessAuth`), `ResultStatusDetail` (`Success`, `Redirect`, `UserError`), `UserAuthenticationMethod`, `KeepMeSignedIn`. Directory audits: `resultType`, `auditEventCategory`, `actorUPN`, `targetName`, `additionalDetails`, `correlationId` ... |
| `ModifiedProperties` | array `{Name,NewValue,OldValue}` | Role / consent details. |
| `ApplicationId` (RT 15) | GUID | App the user signed in to. |
| `DeviceProperties` (RT 15) | array `{Name,Value}` | `OS`, `BrowserType`, `IsCompliant`, `IsCompliantAndManaged`, `SessionId`, `DeviceTrustType`. |
| `ErrorCode` / `LogonError` (RT 15) | string | `LogonError` e.g. `InvalidUserNameOrPassword`, `UserStrongAuthClientAuthNRequiredInterrupt`, `IdsLocked`. Real records frequently carry `ErrorNumber` (e.g. `"50126"`) — UNVERIFIED as a documented field; we use `LogonError` (documented and observed) and may add `ErrorNumber`. |
| `SupportTicketId` | string | Usually empty. |

---

## 4. Realistic samples (fictitious tenant `nexacorp.com`, OrganizationId `4f1c2b7e-9a3d-4c8e-b2f6-7d1e0a9c5b31`)

Story: Dana Levi (`dana.levi@nexacorp.com`) is phished; attacker signs in from `203.0.113.77`, reads mail, creates a
forwarding rule, sets mailbox forwarding, consents a malicious app; separately an insider mass-downloads SharePoint files
and an anonymous link is created; an admin role is granted.

### S1 — Suspicious successful sign-in (RecordType 15, `UserLoggedIn`)
```json
{
  "CreationTime": "2026-09-29T07:41:12",
  "Id": "8c3e5a1d-2b7f-4e90-a6c4-1f0d9b2e7a55",
  "Operation": "UserLoggedIn",
  "OrganizationId": "4f1c2b7e-9a3d-4c8e-b2f6-7d1e0a9c5b31",
  "RecordType": 15,
  "ResultStatus": "Succeeded",
  "UserKey": "10032001A4F7C2D9@nexacorp.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ClientIP": "203.0.113.77",
  "ObjectId": "00000002-0000-0ff1-ce00-000000000000",
  "UserId": "dana.levi@nexacorp.com",
  "AzureActiveDirectoryEventType": 1,
  "ExtendedProperties": [
    { "Name": "ResultStatusDetail", "Value": "Redirect" },
    { "Name": "UserAgent", "Value": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36" },
    { "Name": "UserAuthenticationMethod", "Value": "1" },
    { "Name": "RequestType", "Value": "OAuth2:Authorize" },
    { "Name": "KeepMeSignedIn", "Value": "True" }
  ],
  "ModifiedProperties": [],
  "Actor": [
    { "ID": "6a1f3c9e-55d2-4b8a-9e07-c2d4f8a1b3e6", "Type": 0 },
    { "ID": "dana.levi@nexacorp.com", "Type": 5 },
    { "ID": "10032001A4F7C2D9", "Type": 3 }
  ],
  "ActorContextId": "4f1c2b7e-9a3d-4c8e-b2f6-7d1e0a9c5b31",
  "ActorIpAddress": "203.0.113.77",
  "InterSystemsId": "b7d2e9a4-1c3f-4a6e-8b5d-0e9f7c2a1d43",
  "IntraSystemId": "e4a91c07-3b5d-4f28-9a6e-7c1d2b0f5a00",
  "SupportTicketId": "",
  "Target": [
    { "ID": "00000002-0000-0ff1-ce00-000000000000", "Type": 0 }
  ],
  "TargetContextId": "4f1c2b7e-9a3d-4c8e-b2f6-7d1e0a9c5b31",
  "ApplicationId": "4765445b-32c6-49b0-83e6-1d93765276ca",
  "DeviceProperties": [
    { "Name": "OS", "Value": "Windows10" },
    { "Name": "BrowserType", "Value": "Chrome" },
    { "Name": "IsCompliant", "Value": "False" },
    { "Name": "IsCompliantAndManaged", "Value": "False" },
    { "Name": "SessionId", "Value": "0b5e7d21-9c4a-4f3e-a8d6-2e1b7c9f4a10" }
  ]
}
```

### S2 — Failed sign-in, wrong password (RecordType 15, `UserLoginFailed`)
```json
{
  "CreationTime": "2026-09-29T07:38:55",
  "Id": "1d7b9e3c-4a2f-4c61-b8e5-9f0a3d6c2b71",
  "Operation": "UserLoginFailed",
  "OrganizationId": "4f1c2b7e-9a3d-4c8e-b2f6-7d1e0a9c5b31",
  "RecordType": 15,
  "ResultStatus": "Failed",
  "UserKey": "10032001A4F7C2D9@nexacorp.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ClientIP": "203.0.113.77",
  "ObjectId": "00000002-0000-0ff1-ce00-000000000000",
  "UserId": "dana.levi@nexacorp.com",
  "AzureActiveDirectoryEventType": 1,
  "ExtendedProperties": [
    { "Name": "ResultStatusDetail", "Value": "Success" },
    { "Name": "UserAgent", "Value": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36" },
    { "Name": "RequestType", "Value": "Login:login" }
  ],
  "ModifiedProperties": [],
  "Actor": [
    { "ID": "6a1f3c9e-55d2-4b8a-9e07-c2d4f8a1b3e6", "Type": 0 },
    { "ID": "dana.levi@nexacorp.com", "Type": 5 }
  ],
  "ActorContextId": "4f1c2b7e-9a3d-4c8e-b2f6-7d1e0a9c5b31",
  "ActorIpAddress": "203.0.113.77",
  "InterSystemsId": "c2a8f4d1-7e3b-4d95-a0c6-5b9e1f7d3a28",
  "IntraSystemId": "9f3c1a6e-2d8b-4e70-b5a4-1c7e9d0b3f00",
  "SupportTicketId": "",
  "Target": [
    { "ID": "00000002-0000-0ff1-ce00-000000000000", "Type": 0 }
  ],
  "TargetContextId": "4f1c2b7e-9a3d-4c8e-b2f6-7d1e0a9c5b31",
  "ApplicationId": "4765445b-32c6-49b0-83e6-1d93765276ca",
  "LogonError": "InvalidUserNameOrPassword"
}
```

### S3 — Attacker reads mail: `MailItemsAccessed` Bind from the attacker session (RecordType 50)
```json
{
  "CreationTime": "2026-09-29T07:46:03",
  "Id": "f2b6c9d4-8e1a-4b37-9c50-3d7e2a1f6b84",
  "Operation": "MailItemsAccessed",
  "OrganizationId": "4f1c2b7e-9a3d-4c8e-b2f6-7d1e0a9c5b31",
  "RecordType": 50,
  "ResultStatus": "Succeeded",
  "UserKey": "10032001A4F7C2D9",
  "UserType": 0,
  "Version": 1,
  "Workload": "Exchange",
  "UserId": "dana.levi@nexacorp.com",
  "AppId": "00000002-0000-0ff1-ce00-000000000000",
  "ClientAppId": "",
  "ClientIPAddress": "203.0.113.77",
  "ClientInfoString": "Client=OWA;Action=ViaProxy",
  "ExternalAccess": false,
  "InternalLogonType": 0,
  "LogonType": 0,
  "LogonUserSid": "S-1-5-21-2847193650-1937465028-3618204957-41873",
  "MailboxGuid": "a3e7c1d9-5b2f-4e86-9a0c-7d4b1f3e6c25",
  "MailboxOwnerSid": "S-1-5-21-2847193650-1937465028-3618204957-41873",
  "MailboxOwnerUPN": "dana.levi@nexacorp.com",
  "OperationProperties": [
    { "Name": "MailAccessType", "Value": "Bind" },
    { "Name": "IsThrottled", "Value": "False" }
  ],
  "OrganizationName": "nexacorp.onmicrosoft.com",
  "OriginatingServer": "DB9PR04MB8462 (15.20.8005.017)",
  "SessionId": "7e2d4b91-c6a3-4f58-8b1e-0a9c3d5f2e67",
  "TokenObjectId": "6a1f3c9e-55d2-4b8a-9e07-c2d4f8a1b3e6",
  "TokenTenantId": "4f1c2b7e-9a3d-4c8e-b2f6-7d1e0a9c5b31",
  "AppAccessContext": {
    "AADSessionId": "0b5e7d21-9c4a-4f3e-a8d6-2e1b7c9f4a10",
    "IssuedAtTime": "2026-09-29T07:41:12",
    "UniqueTokenId": "Xk3vR8bQ0E2wT6nYp1LmAA"
  },
  "OperationCount": 3,
  "Folders": [
    {
      "Id": "LgAAAAD8xQ3vR1mTSq7aK9dE2bFwAQBh5uQ2kVnLTZcY0pWxR3sAAAAAAEMAAAB",
      "Path": "\\Inbox",
      "FolderItems": [
        {
          "Id": "RgAAAAD8xQ3vR1mTSq7aK9dE2bFwBwBh5uQ2kVnLTZcY0pWxR3sAAAAAAEMAABh5uQ2kVnLTZcY0pWxR3sAAAKz1aAAAJ",
          "ImmutableId": "LgAAAABh5uQ2kVnLTZcY0pWxR3sAAAKz1aAAAJ",
          "InternetMessageId": "<DB9PR04MB84621A7F3E2C9D0B5F6A1E3C9F81A@DB9PR04MB8462.eurprd04.prod.outlook.com>",
          "SizeInBytes": 48213
        },
        {
          "Id": "RgAAAAD8xQ3vR1mTSq7aK9dE2bFwBwBh5uQ2kVnLTZcY0pWxR3sAAAAAAEMAABh5uQ2kVnLTZcY0pWxR3sAAAKz1bAAAJ",
          "ImmutableId": "LgAAAABh5uQ2kVnLTZcY0pWxR3sAAAKz1bAAAJ",
          "InternetMessageId": "<AM0PR02MB5571C93E1B7A4F2D8E6C0B9A3D71E@AM0PR02MB5571.eurprd02.prod.outlook.com>",
          "SizeInBytes": 215774
        },
        {
          "Id": "RgAAAAD8xQ3vR1mTSq7aK9dE2bFwBwBh5uQ2kVnLTZcY0pWxR3sAAAAAAEMAABh5uQ2kVnLTZcY0pWxR3sAAAKz1cAAAJ",
          "ImmutableId": "LgAAAABh5uQ2kVnLTZcY0pWxR3sAAAKz1cAAAJ",
          "InternetMessageId": "<PA4PR08MB7059E2D41C8B3A97F05E6D1B2C40A@PA4PR08MB7059.eurprd08.prod.outlook.com>",
          "SizeInBytes": 9862
        }
      ]
    }
  ]
}
```

### S4 — BEC inbox rule: forward finance mail externally and delete (RecordType 1, `New-InboxRule` via OWA)
```json
{
  "CreationTime": "2026-09-29T07:52:40",
  "Id": "3a9d1f7e-6c2b-4e85-b0d3-8f1a5c7e2d96",
  "Operation": "New-InboxRule",
  "OrganizationId": "4f1c2b7e-9a3d-4c8e-b2f6-7d1e0a9c5b31",
  "RecordType": 1,
  "ResultStatus": "True",
  "UserKey": "10032001A4F7C2D9",
  "UserType": 0,
  "Version": 1,
  "Workload": "Exchange",
  "ClientIP": "203.0.113.77:50412",
  "ObjectId": "dana.levi@nexacorp.com\\..",
  "UserId": "dana.levi@nexacorp.com",
  "AppId": "00000002-0000-0ff1-ce00-000000000000",
  "ClientAppId": "",
  "ExternalAccess": false,
  "OrganizationName": "nexacorp.onmicrosoft.com",
  "OriginatingServer": "DB9PR04MB8462 (15.20.8005.017)",
  "TokenObjectId": "6a1f3c9e-55d2-4b8a-9e07-c2d4f8a1b3e6",
  "TokenTenantId": "4f1c2b7e-9a3d-4c8e-b2f6-7d1e0a9c5b31",
  "Parameters": [
    { "Name": "AlwaysDeleteOutlookRulesBlob", "Value": "False" },
    { "Name": "Force", "Value": "False" },
    { "Name": "Name", "Value": ".." },
    { "Name": "SubjectOrBodyContainsWords", "Value": "invoice;payment;wire;bank details" },
    { "Name": "ForwardTo", "Value": "ap-desk.nexacorp@outlook.com" },
    { "Name": "DeleteMessage", "Value": "True" },
    { "Name": "MarkAsRead", "Value": "True" },
    { "Name": "StopProcessingRules", "Value": "True" }
  ],
  "SessionId": "7e2d4b91-c6a3-4f58-8b1e-0a9c3d5f2e67"
}
```
Note: `SessionId` on admin-schema records is not in the ExchangeAdmin doc table but appears on OWA-originated cmdlet records — UNVERIFIED; drop it if strict doc conformance is required. Rules created in **Outlook desktop** arrive instead as RecordType 2 `UpdateInboxRules` with rule details in `OperationProperties` (RuleName, RuleActions, RuleCondition) — UNVERIFIED property names.

### S5 — Mailbox-level forwarding to external (RecordType 1, `Set-Mailbox`)
```json
{
  "CreationTime": "2026-09-29T07:55:18",
  "Id": "c7e1a4b9-2d6f-4a30-9e85-1b3d7f0c5a42",
  "Operation": "Set-Mailbox",
  "OrganizationId": "4f1c2b7e-9a3d-4c8e-b2f6-7d1e0a9c5b31",
  "RecordType": 1,
  "ResultStatus": "True",
  "UserKey": "10032001A4F7C2D9",
  "UserType": 0,
  "Version": 1,
  "Workload": "Exchange",
  "ClientIP": "203.0.113.77:50447",
  "ObjectId": "EURPR04A007.prod.outlook.com/Microsoft Exchange Hosted Organizations/nexacorp.onmicrosoft.com/dana.levi",
  "UserId": "dana.levi@nexacorp.com",
  "AppId": "00000002-0000-0ff1-ce00-000000000000",
  "ClientAppId": "",
  "ExternalAccess": false,
  "OrganizationName": "nexacorp.onmicrosoft.com",
  "OriginatingServer": "DB9PR04MB8462 (15.20.8005.017)",
  "TokenObjectId": "6a1f3c9e-55d2-4b8a-9e07-c2d4f8a1b3e6",
  "TokenTenantId": "4f1c2b7e-9a3d-4c8e-b2f6-7d1e0a9c5b31",
  "Parameters": [
    { "Name": "Identity", "Value": "dana.levi@nexacorp.com" },
    { "Name": "ForwardingSmtpAddress", "Value": "smtp:ap-desk.nexacorp@outlook.com" },
    { "Name": "DeliverToMailboxAndForward", "Value": "True" }
  ]
}
```

### S6 — Malicious OAuth app consent with broad scopes (RecordType 8, `Consent to application.`)
```json
{
  "CreationTime": "2026-09-29T08:03:27",
  "Id": "5b8e2c1f-9a4d-4f76-a3b0-6d2e9c7f1a58",
  "Operation": "Consent to application.",
  "OrganizationId": "4f1c2b7e-9a3d-4c8e-b2f6-7d1e0a9c5b31",
  "RecordType": 8,
  "ResultStatus": "Success",
  "UserKey": "10032001A4F7C2D9@nexacorp.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ClientIP": "203.0.113.77",
  "ObjectId": "ServicePrincipal_9d4f2a7c-3e1b-4c85-b6a0-2f7e1d9c3b54",
  "UserId": "dana.levi@nexacorp.com",
  "AzureActiveDirectoryEventType": 1,
  "ExtendedProperties": [
    { "Name": "additionalDetails", "Value": "{\"User-Agent\":\"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36\"}" },
    { "Name": "extendedAuditEventCategory", "Value": "ServicePrincipal" },
    { "Name": "resultType", "Value": "Success" },
    { "Name": "auditEventCategory", "Value": "ApplicationManagement" },
    { "Name": "actorUPN", "Value": "dana.levi@nexacorp.com" },
    { "Name": "targetName", "Value": "DocuSign Secure Viewer" },
    { "Name": "correlationId", "Value": "a1c7e3d9-4b2f-4e60-8d5a-9f3b1c7e2d04" }
  ],
  "ModifiedProperties": [
    { "Name": "ConsentContext.IsAdminConsent", "NewValue": "False", "OldValue": "" },
    { "Name": "ConsentContext.IsAppOnly", "NewValue": "False", "OldValue": "" },
    { "Name": "ConsentContext.OnBehalfOfAll", "NewValue": "False", "OldValue": "" },
    { "Name": "ConsentContext.Tags", "NewValue": "WindowsAzureActiveDirectoryIntegratedApp", "OldValue": "" },
    { "Name": "ConsentAction.Permissions", "NewValue": "[] => [[Id: Kp7xQ2v1d0O8W3nA5fYbJ8JcX2t4m6R9, ClientId: 9d4f2a7c-3e1b-4c85-b6a0-2f7e1d9c3b54, PrincipalId: 6a1f3c9e-55d2-4b8a-9e07-c2d4f8a1b3e6, ResourceId: 2b7e4c1a-8d3f-4a95-b0e6-1c9d7f3a5e28, ConsentType: Principal, Scope:  Mail.ReadWrite Mail.Send Files.ReadWrite.All offline_access User.Read, CreatedDateTime: , LastModifiedDateTime ]]; ", "OldValue": "" },
    { "Name": "TargetId.ServicePrincipalNames", "NewValue": "9d4f2a7c-3e1b-4c85-b6a0-2f7e1d9c3b54;https://docsign-viewer.app", "OldValue": "" }
  ],
  "Actor": [
    { "ID": "dana.levi@nexacorp.com", "Type": 5 },
    { "ID": "10032001A4F7C2D9", "Type": 3 },
    { "ID": "User_6a1f3c9e-55d2-4b8a-9e07-c2d4f8a1b3e6", "Type": 2 },
    { "ID": "6a1f3c9e-55d2-4b8a-9e07-c2d4f8a1b3e6", "Type": 2 },
    { "ID": "User", "Type": 2 }
  ],
  "ActorContextId": "4f1c2b7e-9a3d-4c8e-b2f6-7d1e0a9c5b31",
  "InterSystemsId": "a1c7e3d9-4b2f-4e60-8d5a-9f3b1c7e2d04",
  "IntraSystemId": "3f6b9d2e-7c1a-4e58-b4d0-8a2c5e1f7b39",
  "SupportTicketId": "",
  "Target": [
    { "ID": "ServicePrincipal_9d4f2a7c-3e1b-4c85-b6a0-2f7e1d9c3b54", "Type": 2 },
    { "ID": "9d4f2a7c-3e1b-4c85-b6a0-2f7e1d9c3b54", "Type": 2 },
    { "ID": "ServicePrincipal", "Type": 2 },
    { "ID": "DocuSign Secure Viewer", "Type": 1 },
    { "ID": "9d4f2a7c-3e1b-4c85-b6a0-2f7e1d9c3b54", "Type": 4 }
  ],
  "TargetContextId": "4f1c2b7e-9a3d-4c8e-b2f6-7d1e0a9c5b31"
}
```
Note: directory-audit (RT 8) records use `ResultStatus` `Success`/`Failure` in practice (value comes from the Entra audit `resultType`).

### S7 — Mass download from SharePoint (RecordType 6, `FileDownloaded`; one of ~600 records in 9 minutes)
```json
{
  "CreationTime": "2026-09-30T18:12:47",
  "Id": "e9a3c7d1-4f2b-4b86-a5e0-7c1d9f3b2a64",
  "Operation": "FileDownloaded",
  "OrganizationId": "4f1c2b7e-9a3d-4c8e-b2f6-7d1e0a9c5b31",
  "RecordType": 6,
  "UserKey": "i:0h.f|membership|10032001b8c4e1f7@live.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "SharePoint",
  "ClientIP": "198.51.100.42",
  "ObjectId": "https://nexacorp.sharepoint.com/sites/Finance/Shared Documents/Payroll/2026/Payroll_Q3_2026.xlsx",
  "UserId": "omer.katz@nexacorp.com",
  "CorrelationId": "4c1ea8a1-60d2-9000-b7f3-2e9d5c1a7f83",
  "EventSource": "SharePoint",
  "ItemType": "File",
  "ListId": "8b2d6f1e-3a9c-4e57-b0d4-6c1f8e2a9d35",
  "ListItemUniqueId": "1f7c3e9a-5d2b-4a80-9c6e-3b1d7f5a2e94",
  "Site": "6e3b9d1f-2c7a-4f85-a0e4-9d2b7c1f5e38",
  "UserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0",
  "WebId": "2a9f5c1e-7b3d-4e62-8f0a-5c3e1d9b7a26",
  "GeoLocation": "EUR",
  "IsManagedDevice": false,
  "SourceFileExtension": "xlsx",
  "SiteUrl": "https://nexacorp.sharepoint.com/sites/Finance/",
  "SourceFileName": "Payroll_Q3_2026.xlsx",
  "SourceRelativeUrl": "Shared Documents/Payroll/2026"
}
```

### S8 — Anonymous ("Anyone") link created (RecordType 14, `AnonymousLinkCreated`)
```json
{
  "CreationTime": "2026-09-30T18:25:09",
  "Id": "2d6f9b3e-8c1a-4e74-b5d0-1a7e3c9f2b86",
  "Operation": "AnonymousLinkCreated",
  "OrganizationId": "4f1c2b7e-9a3d-4c8e-b2f6-7d1e0a9c5b31",
  "RecordType": 14,
  "UserKey": "i:0h.f|membership|10032001b8c4e1f7@live.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "OneDrive",
  "ClientIP": "198.51.100.42",
  "ObjectId": "https://nexacorp-my.sharepoint.com/personal/omer_katz_nexacorp_com/Documents/export/customers_full_2026.zip",
  "UserId": "omer.katz@nexacorp.com",
  "CorrelationId": "9e4fa8a1-1083-9000-c2d6-7b3f1e9a5c47",
  "EventSource": "SharePoint",
  "ItemType": "File",
  "ListId": "5c8e2a7f-1d3b-4f96-a0c4-8e2d6b1f3a79",
  "ListItemUniqueId": "7a1d5f3c-9e2b-4c68-b4a0-2f6e8d1c9b53",
  "Site": "3b7e1d9f-4a2c-4e85-9d06-1f5c7a3e2b98",
  "UserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0",
  "WebId": "8f2c6a1e-3d9b-4e70-a5c1-6b9e2d4f7a13",
  "EventData": "<Type>View</Type>",
  "SourceFileExtension": "zip",
  "SiteUrl": "https://nexacorp-my.sharepoint.com/personal/omer_katz_nexacorp_com/",
  "SourceFileName": "customers_full_2026.zip",
  "SourceRelativeUrl": "Documents/export",
  "UniqueSharingId": "c4e8a2f6-1b7d-4d93-8e5a-0f3c9b6d2e71"
}
```

### S9 — Admin privilege granted: Global Administrator (RecordType 8, `Add member to role.`)
```json
{
  "CreationTime": "2026-09-30T21:04:51",
  "Id": "7f3b1d9e-2a6c-4e58-91d4-5c8a2e7f3b06",
  "Operation": "Add member to role.",
  "OrganizationId": "4f1c2b7e-9a3d-4c8e-b2f6-7d1e0a9c5b31",
  "RecordType": 8,
  "ResultStatus": "Success",
  "UserKey": "10032001C1D8E5A3@nexacorp.com",
  "UserType": 0,
  "Version": 1,
  "Workload": "AzureActiveDirectory",
  "ClientIP": "203.0.113.77",
  "ObjectId": "svc-backup@nexacorp.com",
  "UserId": "it.admin@nexacorp.com",
  "AzureActiveDirectoryEventType": 1,
  "ExtendedProperties": [
    { "Name": "additionalDetails", "Value": "{}" },
    { "Name": "extendedAuditEventCategory", "Value": "User" },
    { "Name": "resultType", "Value": "Success" },
    { "Name": "auditEventCategory", "Value": "RoleManagement" },
    { "Name": "actorUPN", "Value": "it.admin@nexacorp.com" },
    { "Name": "targetName", "Value": "svc-backup@nexacorp.com" },
    { "Name": "correlationId", "Value": "6d2a9f4c-1e7b-4c53-a8d0-3f9b5e1c7a24" }
  ],
  "ModifiedProperties": [
    { "Name": "Role.ObjectID", "NewValue": "e1b3d7f9-6c2a-4f48-b5e0-8a1d3c7f9e52", "OldValue": "" },
    { "Name": "Role.DisplayName", "NewValue": "Global Administrator", "OldValue": "" },
    { "Name": "Role.TemplateId", "NewValue": "62e90394-69f5-4237-9190-012177145e10", "OldValue": "" },
    { "Name": "Role.WellKnownObjectName", "NewValue": "TenantAdmins", "OldValue": "" }
  ],
  "Actor": [
    { "ID": "it.admin@nexacorp.com", "Type": 5 },
    { "ID": "10032001C1D8E5A3", "Type": 3 },
    { "ID": "User_3c9e1a7f-5b2d-4e86-a0c4-7f1d3b9e5a62", "Type": 2 },
    { "ID": "3c9e1a7f-5b2d-4e86-a0c4-7f1d3b9e5a62", "Type": 2 },
    { "ID": "User", "Type": 2 }
  ],
  "ActorContextId": "4f1c2b7e-9a3d-4c8e-b2f6-7d1e0a9c5b31",
  "InterSystemsId": "6d2a9f4c-1e7b-4c53-a8d0-3f9b5e1c7a24",
  "IntraSystemId": "b2e8c4a1-9f3d-4b76-8e5a-1d7c3f9b2e04",
  "SupportTicketId": "",
  "Target": [
    { "ID": "User_9a5c3e1f-7d2b-4f84-b6a0-2e8d4c1f7b39", "Type": 2 },
    { "ID": "9a5c3e1f-7d2b-4f84-b6a0-2e8d4c1f7b39", "Type": 2 },
    { "ID": "User", "Type": 2 },
    { "ID": "svc-backup@nexacorp.com", "Type": 5 },
    { "ID": "10032001E7F2A9C4", "Type": 3 }
  ],
  "TargetContextId": "4f1c2b7e-9a3d-4c8e-b2f6-7d1e0a9c5b31"
}
```
(`62e90394-69f5-4237-9190-012177145e10` is the real, public role template id of Global Administrator.)

### S10 — Attacker grants self FullAccess to the CFO mailbox (RecordType 1, `Add-MailboxPermission`)
```json
{
  "CreationTime": "2026-09-30T21:09:33",
  "Id": "4e9c2a7f-1d5b-4f83-b0e6-9a3c7e1d5f28",
  "Operation": "Add-MailboxPermission",
  "OrganizationId": "4f1c2b7e-9a3d-4c8e-b2f6-7d1e0a9c5b31",
  "RecordType": 1,
  "ResultStatus": "True",
  "UserKey": "10032001C1D8E5A3",
  "UserType": 2,
  "Version": 1,
  "Workload": "Exchange",
  "ClientIP": "203.0.113.77:50988",
  "ObjectId": "EURPR04A007.prod.outlook.com/Microsoft Exchange Hosted Organizations/nexacorp.onmicrosoft.com/yael.cohen",
  "UserId": "it.admin@nexacorp.com",
  "AppId": "fb78d390-0c51-40cd-8e17-fdbfab77341b",
  "ClientAppId": "",
  "ExternalAccess": false,
  "OrganizationName": "nexacorp.onmicrosoft.com",
  "OriginatingServer": "DB9PR04MB8462 (15.20.8005.017)",
  "TokenObjectId": "3c9e1a7f-5b2d-4e86-a0c4-7f1d3b9e5a62",
  "TokenTenantId": "4f1c2b7e-9a3d-4c8e-b2f6-7d1e0a9c5b31",
  "Parameters": [
    { "Name": "Identity", "Value": "yael.cohen@nexacorp.com" },
    { "Name": "User", "Value": "svc-backup@nexacorp.com" },
    { "Name": "AccessRights", "Value": "FullAccess" },
    { "Name": "InheritanceType", "Value": "All" },
    { "Name": "AutoMapping", "Value": "False" }
  ]
}
```
(`fb78d390-0c51-40cd-8e17-fdbfab77341b` = Microsoft Exchange REST API Based PowerShell — the app id real EXO PowerShell v3 sessions show; UNVERIFIED that it always populates `AppId` here.)

---

## 5. Investigation notes (pivots)

- **Session pivot**: Entra `SessionId` (in `DeviceProperties` of RT 15) = `AppAccessContext.AADSessionId` on Exchange/SharePoint records → ties a specific sign-in to the mail reads / rules it produced. Exchange `SessionId` groups all mailbox activity of one Exchange session (owner's Outlook vs attacker's OWA in the same mailbox).
- **IP pivot**: `ClientIP` (strip `:port`), `ActorIpAddress`, `ClientIPAddress`. The UAL has **no geolocation fields** — enrich IPs yourself.
- **Mail-item pivot**: `Folders[].FolderItems[].InternetMessageId` / `Item.InternetMessageId` ↔ Defender `EmailEvents.InternetMessageId` ↔ Proofpoint `messageID`.
- **Rule-creation pivot**: `Operation in (New-InboxRule, Set-InboxRule, UpdateInboxRules, Set-Mailbox)` + `Parameters` containing `ForwardTo|RedirectTo|ForwardAsAttachmentTo|ForwardingSmtpAddress|DeleteMessage|MoveToFolder`; rule names like `.`, `..`, `,` are classic BEC tells.
- **Consent pivot**: `Consent to application.` → `ModifiedProperties[ConsentAction.Permissions]` scopes; `ConsentContext.IsAdminConsent=True` + `OnBehalfOfAll=True` = tenant-wide grant. Follow with `Add OAuth2PermissionGrant.` / `Add app role assignment to service principal.`
- **Exfil pivot**: count `FileDownloaded` / `FileSyncDownloadedFull` per `UserId` per 10 min; check `UserAgent` (sync client vs browser vs `python-requests`), `IsManagedDevice`.
- **Correlation keys**: `IntraSystemId` (Entra request id), `CorrelationId` (SharePoint), `InterSystemsId`.

---

## 6. M365 ↔ Google Workspace equivalence (do not fake an equivalent)

| M365 operation | Google Workspace equivalent | Equivalence |
|---|---|---|
| `UserLoggedIn` / `UserLoginFailed` | `login` app: `login_success` / `login_failure` | True equivalent. |
| Entra risk detection (not in UAL itself) | `login` app `account_warning`: `suspicious_login`, `suspicious_programmatic_login` | Partial: Google emits the warning as an audit event; M365 UAL does not carry risk levels. |
| per-user MFA disable (`Disable Strong Authentication.` / `Update user.` StrongAuthentication* props — UNVERIFIED names) | `user_accounts`/`login` `2sv_disable`; admin `TURN_OFF_2_STEP_VERIFICATION` | Partial. |
| `New-InboxRule` / `Set-InboxRule` / `UpdateInboxRules` | **None in Reports API** for user-created Gmail filters (UNVERIFIED that no event exists; none is documented). | **No equivalent — do not invent a Google "filter created" event.** |
| `Set-Mailbox -ForwardingSmtpAddress` (user/attacker-set) | `user_accounts`/`login` `email_forwarding_out_of_domain` (`email_forwarding_destination_address`) | Near-true (user-level auto-forward to another domain). |
| `MailItemsAccessed` (Bind/Sync, SessionId) | `gmail` app `delivery` events with `event_info.mail_event_type` 7/31/32/33 (opened/viewed/downloaded/app-accessed) | Partial; no Exchange-style SessionId, no Bind/Sync, needs Enterprise/Education Plus tier. |
| `Add-MailboxPermission FullAccess` | Gmail delegation — no documented dedicated Reports API event | No reliable equivalent. |
| `FileDownloaded` / `FileAccessed` | `drive` `download` / `view` | True. |
| `AnonymousLinkCreated` | `drive` `change_document_visibility` → `people_with_link` / `public_on_the_web` | True. |
| `SharingSet` / `SharingInvitationCreated` (guest) | `drive` `change_user_access` (`target_user`, `new_value`) | True. |
| `Consent to application.` | `token` `authorize` (`client_id`, `app_name`, `scope`) | True for user consent; admin tenant-wide consent has no 1:1 token event (Google uses admin `API_CLIENT`/domain-wide delegation settings — UNVERIFIED event names). |
| `Add member to role.` | `admin` `ASSIGN_ROLE` (`ROLE_NAME`) / `GRANT_ADMIN_PRIVILEGE` | True. |
| — | `login` `gov_attack_warning` | **No M365 equivalent.** |

## 7. Common mistakes / fields that do NOT exist

- No `data.office365.*`, `o365.audit.*`, `event.action`, `source.ip`, `user.name` wrappers. Keys are the bare PascalCase names.
- No `GeoLocation.country_name`, `Country`, `City`, `RiskLevel`, `RiskScore`, `Severity`, `AlertId` in UAL records (SharePoint `GeoLocation` is a data-residency code like `EUR`, not IP geo).
- No `UserPrincipalName`, `IPAddress`, `SourceIP`, `EventName`, `ActionType` — use `UserId`, `ClientIP`, `Operation`.
- There is no `Operation:"InboxRuleCreated"` / `"MailForwardingEnabled"` / `"FileDownload"` / `"OAuthConsent"`. Exact names: `New-InboxRule`, `Set-Mailbox`, `FileDownloaded`, `Consent to application.` (with trailing dot), `Add member to role.`.
- `LogonType` and `UserType` are integers, not strings like `"Owner"`/`"Regular"`.
- Exchange admin `ResultStatus` is `"True"`/`"False"`, not `"Succeeded"`.
- `Parameters` is an array of `{Name,Value}` pairs, never a dict (`"Parameters":{"ForwardTo":...}` is wrong).
- `MailItemsAccessed` is RecordType **50** (not 2) and lists items under `Folders[].FolderItems[]`, not `Item`.
- `CreationTime` has no `Z` and no milliseconds; do not render Entra-style `2026-09-29T07:41:12.345Z` here.
- Do not mix in Entra sign-in-log (Graph `signIns`) fields such as `riskLevelDuringSignIn`, `conditionalAccessStatus`, `location.city` — that is a different source (see the Entra card).
