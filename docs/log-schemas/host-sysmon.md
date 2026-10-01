# Microsoft Sysinternals Sysmon (Windows) — Microsoft-Windows-Sysmon/Operational

Category: Host telemetry. Vendor: Microsoft (Sysinternals). Native format: Windows Event Log (EVTX) XML — `System` + `EventData` named `Data` elements (text-native).
Platform representation: **flat JSON** = `System` element/attribute names + every `EventData` `Data Name` unchanged (Sysmon's exact PascalCase spelling), values as strings as rendered in the XML.

---

## 1. Official sources

| Source | What it confirmed |
|---|---|
| https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon | Event IDs 1–29 + 255 and names (1 ProcessCreate, 2 FileCreateTime, 3 NetworkConnect, 5 ProcessTerminate, 6 DriverLoad, 7 ImageLoad, 8 CreateRemoteThread, 9 RawAccessRead, 10 ProcessAccess, 11 FileCreate, 12/13/14 RegistryEvent, 15 FileCreateStreamHash, 17/18 PipeEvent, 19/20/21 WmiEvent, 22 DNSEvent, 23 FileDelete (archived), 24 ClipboardChange, 25 ProcessTampering, 26 FileDeleteDetected, 27 FileBlockExecutable, 29 FileExecutableDetected); channel `Applications and Services Logs/Microsoft/Windows/Sysmon/Operational`; UtcTime timestamps; registry abbreviations `HKLM`/`HKU`/`HKCR`; hash algos MD5/SHA1/SHA256/IMPHASH; `ProcessGuid` for correlation; `sysmon -s` prints the schema; current config `schemaversion="4.82"`. |
| https://github.com/elastic/integrations/blob/main/packages/windows/data_stream/sysmon_operational/_dev/test/pipeline/test-events.json | Real `event_data` key sets per event ID (verbatim field names): **1** `RuleName,UtcTime,ProcessGuid,ProcessId,Image,FileVersion,Description,Product,Company,OriginalFileName,CommandLine,CurrentDirectory,User,LogonGuid,LogonId,TerminalSessionId,IntegrityLevel,Hashes,ParentProcessGuid,ParentProcessId,ParentImage,ParentCommandLine,ParentUser`; **3** `UtcTime,ProcessGuid,ProcessId,Image,User,Protocol,Initiated,SourceIsIpv6,SourceIp,SourceHostname,SourcePort,SourcePortName,DestinationIsIpv6,DestinationIp,DestinationHostname,DestinationPort,DestinationPortName`; **7** `ImageLoaded,FileVersion,Description,Product,Company,OriginalFileName,Hashes,Signed,Signature,SignatureStatus`; **8** `SourceProcessGuid,SourceProcessId,SourceImage,TargetProcessGuid,TargetProcessId,TargetImage,NewThreadId,StartAddress,StartModule,StartFunction`; **10** `SourceProcessGUID,SourceProcessId,SourceThreadId,SourceImage,TargetProcessGUID,TargetProcessId,TargetImage,GrantedAccess,CallTrace`; **11** `TargetFilename,CreationUtcTime`; **13** `EventType,TargetObject,Details`; **22** `QueryName,QueryStatus,QueryResults`; **23** `Hashes,IsExecutable,Archived,TargetFilename`; **26**. |
| OSSEM-DD Sysmon dictionaries (https://github.com/OTRF/OSSEM-DD) and ultimatewindowssecurity encyclopedia | Field meanings; `ParentUser` (event 1), `SourceUser`/`TargetUser` (events 8/10) in recent schema; `GrantedAccess` access-mask meanings. |
| https://github.com/OTRF/Security-Datasets (Mordor) | Real attack recordings used to confirm value shapes (LSASS access mask `0x1010`, Office spawning a script host, etc.). |

## 2. Native format and delivery

- Collected via WEF/WEC, Winlogbeat/NXLog/agents, or EDR/SIEM connectors. Provider `Microsoft-Windows-Sysmon`, GUID `{5770385F-C22A-43E0-BF4C-06F5698FFBD9}`, channel `Microsoft-Windows-Sysmon/Operational`, `Security UserID="S-1-5-18"`, `Task` = event ID, `Level` 4, `Keywords` `0x8000000000000000`.
- Value conventions: `UtcTime` = `YYYY-MM-DD HH:MM:SS.mmm` (UTC, space not `T`, no `Z`); GUIDs in braces `{....}`; `Hashes` = comma-joined `ALGO=hex` (`SHA256=...,IMPHASH=...`) or a bare SHA-256/SHA-1 depending on `HashAlgorithms`; `IntegrityLevel` `Low`/`Medium`/`High`/`System`; booleans `true`/`false`; `GrantedAccess` a `0x`-mask; `QueryStatus` a decimal DNS/Win32 status (`0` = success, `9003` = NXDOMAIN/DNS_ERROR_RCODE_NAME_ERROR); `QueryResults` a `;`-separated list with `type:` prefixes.
- **We standardise on:** flat JSON — `ProviderName`, `EventID`, `Version`, `Level`, `Task`, `Opcode`, `Keywords`, `TimeCreated`, `EventRecordID`, `ProcessID` (Sysmon service pid, from `Execution`), `ThreadID`, `Channel`, `Computer`, `UserID`, then every `EventData` name as-is. Plus `raw` (the rendered EVTX XML) where useful.

## 3. Core field reference (SOC-relevant events)

**Event 1 ProcessCreate:** `UtcTime, ProcessGuid, ProcessId, Image, FileVersion, Description, Product, Company, OriginalFileName, CommandLine, CurrentDirectory, User, LogonGuid, LogonId, TerminalSessionId, IntegrityLevel, Hashes, ParentProcessGuid, ParentProcessId, ParentImage, ParentCommandLine, ParentUser`. `User` = account that ran it (`DOMAIN\user`); `ProcessGuid`/`ParentProcessGuid` link the tree.

**Event 3 NetworkConnect:** `Protocol` (`tcp`/`udp`), `Initiated` (`true` = outbound), `SourceIp/SourcePort`, `DestinationIp/DestinationPort/DestinationHostname/DestinationPortName`, `Image`, `User`. Disabled by default; connection tied to a process via `ProcessGuid`.

**Event 22 DNSEvent:** `QueryName`, `QueryStatus` (`0` ok), `QueryResults` (`type: <ip/cname>;...`), `Image`, `ProcessGuid`, `ProcessId`, `User`. This is the only Windows source that ties a DNS lookup to the requesting process.

**Event 10 ProcessAccess:** `SourceImage`/`SourceProcessGUID`/`SourceProcessId`, `TargetImage`/`TargetProcessGUID`/`TargetProcessId`, `GrantedAccess` (access mask), `CallTrace` (module+offset chain). LSASS read for credential theft = `TargetImage` ends `lsass.exe` with `GrantedAccess` containing `0x10` (VM_READ) / `0x1010` / `0x1410` / `0x1fffff`.

**Event 11 FileCreate:** `Image`, `TargetFilename`, `CreationUtcTime`, `User`. Dropper/download artifacts, especially under `%AppData%`, `%Temp%`, `%ProgramData%`, Startup.

**Event 12/13/14 RegistryEvent:** `EventType` (`CreateKey`/`SetValue`/`DeleteValue`/`RenameKey`), `TargetObject` (abbreviated path), `Details` (value for 13), `Image`. Run-key persistence etc.

**Event 7 ImageLoad / 8 CreateRemoteThread / 23/26 FileDelete / 15 FileCreateStreamHash:** see field list in §1. Event 15 `Contents`/`Hash` capture the Zone.Identifier "mark of the web".

## 4. Realistic samples

### 4.1 Office spawning an encoded PowerShell child (macro execution) — Event 1
```json
{"ProviderName": "Microsoft-Windows-Sysmon", "EventID": 1, "Version": 5, "Level": 4, "Task": 1, "Opcode": 0, "Keywords": "0x8000000000000000", "TimeCreated": "2026-10-01T05:33:12.4471180Z", "EventRecordID": 774120391, "ProcessID": 2996, "ThreadID": 3980, "Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "NXC-WS-1188.corp.nexacorp.local", "UserID": "S-1-5-18",
 "RuleName": "technique_id=T1059.001,technique_name=PowerShell",
 "UtcTime": "2026-10-01 05:33:12.447",
 "ProcessGuid": "{a1b2c3d4-9f10-6711-5a00-000000002e00}",
 "ProcessId": "9112",
 "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
 "FileVersion": "10.0.22621.1 (WinBuild.160101.0800)",
 "Description": "Windows PowerShell",
 "Product": "Microsoft Windows Operating System",
 "Company": "Microsoft Corporation",
 "OriginalFileName": "PowerShell.EXE",
 "CommandLine": "powershell.exe -nop -w hidden -ep bypass -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA...",
 "CurrentDirectory": "C:\\Users\\maya.peretz\\Documents\\",
 "User": "CORP\\maya.peretz",
 "LogonGuid": "{a1b2c3d4-8e20-6711-4f32-120000000000}",
 "LogonId": "0x12324F",
 "TerminalSessionId": "2",
 "IntegrityLevel": "Medium",
 "Hashes": "SHA256=908B64B1971A979C7E3E8CE4621945CBA84854CB98D76367B791A6E22B5F6D53,IMPHASH=A7CEFACDDA74B13F4E22F4D369B1E4C9",
 "ParentProcessGuid": "{a1b2c3d4-9e55-6711-5900-000000002e00}",
 "ParentProcessId": "8044",
 "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
 "ParentCommandLine": "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\" /n \"C:\\Users\\maya.peretz\\Downloads\\Invoice_Sept2026.docm\"",
 "ParentUser": "CORP\\maya.peretz"}
```
The `-enc` value is base64 UTF-16LE; here it decodes to the start of a `New-Object Net.WebClient` download expression. (The sample string is truncated — a full working payload is deliberately not reproduced.) Detection signal: `ParentImage` = WINWORD, child `powershell.exe` with `-nop -w hidden -ep bypass -enc`.

### 4.2 The PowerShell resolves its C2 domain — Event 22 (DNS)
```json
{"ProviderName": "Microsoft-Windows-Sysmon", "EventID": 22, "Version": 5, "Level": 4, "Task": 22, "Opcode": 0, "Keywords": "0x8000000000000000", "TimeCreated": "2026-10-01T05:33:12.9120044Z", "EventRecordID": 774120402, "ProcessID": 2996, "ThreadID": 3980, "Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "NXC-WS-1188.corp.nexacorp.local", "UserID": "S-1-5-18",
 "RuleName": "-",
 "UtcTime": "2026-10-01 05:33:12.912",
 "ProcessGuid": "{a1b2c3d4-9f10-6711-5a00-000000002e00}",
 "ProcessId": "9112",
 "QueryName": "cdn-telemetry-sync.net",
 "QueryStatus": "0",
 "QueryResults": "type:  5 cdn-telemetry-sync.net.edgekey.net;::ffff:192.0.2.90;",
 "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
 "User": "CORP\\maya.peretz"}
```

### 4.3 Outbound C2 connection — Event 3 (NetworkConnect)
```json
{"ProviderName": "Microsoft-Windows-Sysmon", "EventID": 3, "Version": 5, "Level": 4, "Task": 3, "Opcode": 0, "Keywords": "0x8000000000000000", "TimeCreated": "2026-10-01T05:33:13.1034771Z", "EventRecordID": 774120410, "ProcessID": 2996, "ThreadID": 3980, "Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "NXC-WS-1188.corp.nexacorp.local", "UserID": "S-1-5-18",
 "RuleName": "-",
 "UtcTime": "2026-10-01 05:33:13.103",
 "ProcessGuid": "{a1b2c3d4-9f10-6711-5a00-000000002e00}",
 "ProcessId": "9112",
 "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
 "User": "CORP\\maya.peretz",
 "Protocol": "tcp",
 "Initiated": "true",
 "SourceIsIpv6": "false",
 "SourceIp": "10.20.31.52",
 "SourceHostname": "NXC-WS-1188.corp.nexacorp.local",
 "SourcePort": "52210",
 "SourcePortName": "-",
 "DestinationIsIpv6": "false",
 "DestinationIp": "192.0.2.90",
 "DestinationHostname": "cdn-telemetry-sync.net",
 "DestinationPort": "443",
 "DestinationPortName": "https"}
```

### 4.4 Payload drop in %AppData% — Event 11 (FileCreate)
```json
{"ProviderName": "Microsoft-Windows-Sysmon", "EventID": 11, "Version": 2, "Level": 4, "Task": 11, "Opcode": 0, "Keywords": "0x8000000000000000", "TimeCreated": "2026-10-01T05:33:13.4418802Z", "EventRecordID": 774120418, "ProcessID": 2996, "ThreadID": 3980, "Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "NXC-WS-1188.corp.nexacorp.local", "UserID": "S-1-5-18",
 "RuleName": "technique_id=T1105,technique_name=Ingress Tool Transfer",
 "UtcTime": "2026-10-01 05:33:13.441",
 "ProcessGuid": "{a1b2c3d4-9f10-6711-5a00-000000002e00}",
 "ProcessId": "9112",
 "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
 "TargetFilename": "C:\\Users\\maya.peretz\\AppData\\Roaming\\Microsoft\\Windows\\svchost_update.exe",
 "CreationUtcTime": "2026-10-01 05:33:13.440",
 "User": "CORP\\maya.peretz"}
```

### 4.5 Credential theft — LSASS access, GrantedAccess 0x1010 — Event 10 (ProcessAccess)
```json
{"ProviderName": "Microsoft-Windows-Sysmon", "EventID": 10, "Version": 3, "Level": 4, "Task": 10, "Opcode": 0, "Keywords": "0x8000000000000000", "TimeCreated": "2026-10-01T05:34:02.7781190Z", "EventRecordID": 774120655, "ProcessID": 2996, "ThreadID": 3980, "Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "NXC-WS-1188.corp.nexacorp.local", "UserID": "S-1-5-18",
 "RuleName": "technique_id=T1003.001,technique_name=LSASS Memory",
 "UtcTime": "2026-10-01 05:34:02.778",
 "SourceProcessGUID": "{a1b2c3d4-9f55-6711-5b00-000000002e00}",
 "SourceProcessId": "9344",
 "SourceThreadId": "9348",
 "SourceImage": "C:\\Users\\maya.peretz\\AppData\\Roaming\\Microsoft\\Windows\\svchost_update.exe",
 "TargetProcessGUID": "{a1b2c3d4-6a11-6711-0c00-000000000400}",
 "TargetProcessId": "748",
 "TargetImage": "C:\\Windows\\System32\\lsass.exe",
 "GrantedAccess": "0x1010",
 "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+9d4c4|C:\\Windows\\System32\\KERNELBASE.dll+2d20e|UNKNOWN(00007FF8B2110000)"}
```
Signal: `TargetImage` = `lsass.exe`, `GrantedAccess 0x1010` (PROCESS_VM_READ|PROCESS_QUERY_INFORMATION) from a non-system `SourceImage`, with an `UNKNOWN` frame in `CallTrace` (unbacked memory = injected/reflective code).

### 4.6 Run-key persistence — Event 13 (RegistryEvent Value Set)
```json
{"ProviderName": "Microsoft-Windows-Sysmon", "EventID": 13, "Version": 2, "Level": 4, "Task": 13, "Opcode": 0, "Keywords": "0x8000000000000000", "TimeCreated": "2026-10-01T05:34:05.0021044Z", "EventRecordID": 774120702, "ProcessID": 2996, "ThreadID": 3980, "Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "NXC-WS-1188.corp.nexacorp.local", "UserID": "S-1-5-18",
 "RuleName": "technique_id=T1547.001,technique_name=Registry Run Keys",
 "EventType": "SetValue",
 "UtcTime": "2026-10-01 05:34:05.002",
 "ProcessGuid": "{a1b2c3d4-9f55-6711-5b00-000000002e00}",
 "ProcessId": "9344",
 "Image": "C:\\Users\\maya.peretz\\AppData\\Roaming\\Microsoft\\Windows\\svchost_update.exe",
 "TargetObject": "HKU\\S-1-5-21-3841920571-2209614458-1736201947-1142\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdateSvc",
 "Details": "\"C:\\Users\\maya.peretz\\AppData\\Roaming\\Microsoft\\Windows\\svchost_update.exe\"",
 "User": "CORP\\maya.peretz"}
```

## 5. Investigation notes

- **ProcessGuid is the spine.** It is globally unique (unlike reused PIDs). A child's `ParentProcessGuid` = the parent's `ProcessGuid`; events 3/11/12-14/22 carry the actor's `ProcessGuid`. Reconstruct the whole chain (1 WINWORD -> 1 powershell -> 22 DNS -> 3 connect -> 11 drop -> 1 svchost_update -> 10 LSASS -> 13 Run key) by walking GUIDs.
- **Parent/child anomalies (event 1):** Office/`outlook.exe`/`mshta.exe` -> `powershell.exe`/`cmd.exe`/`wscript.exe`; `-enc`, `-w hidden`, `-ep bypass`, `IEX`, `FromBase64String` in `CommandLine`; `IntegrityLevel` jumps; signed LOLBins (`rundll32`, `regsvr32`, `mshta`) with odd args.
- **DNS (22) & network (3):** `QueryName` ties a lookup to `Image`/`ProcessGuid` — correlate to Windows/Infoblox DNS server logs (same name, time) and to firewall/proxy for `DestinationIp`. `Initiated=true` + unusual `Image` on 443/unusual ports = beaconing.
- **LSASS (10):** filter `TargetImage` endswith `lsass.exe`; triage by `GrantedAccess` (0x1010/0x1410/0x143a/0x1fffff) and `CallTrace` containing `UNKNOWN`/non-module offsets; `SourceImage` identifies the tool.
- **Hashes:** `Hashes` (MD5/SHA256/IMPHASH) pivot to AV/EDR verdicts, VirusTotal, and the proxy `md5`/sandbox verdict for the same file.
- **Cross-source:** `Computer` + `User` + time join Sysmon to Windows Security 4624/4688, EDR, and the VPN/proxy that put the user on the box.

## 6. Common mistakes / fields that do NOT exist

- Field names are PascalCase Sysmon spellings: `CommandLine`, `ParentImage`, `DestinationIp`, `QueryName`, `GrantedAccess`, `TargetFilename`. No `process.command_line`, `dest_ip`, `dns.question.name`, `cmdline`.
- `UtcTime` uses a space and no `Z` (`2026-10-01 05:34:05.002`); the `System/TimeCreated` attribute is ISO with `Z` — they are different fields.
- Event 10 uses `SourceProcessGUID`/`TargetProcessGUID` (uppercase `GUID`), while event 1/3 use `ProcessGuid` (lowercase `uid`) — Sysmon is inconsistent on purpose; keep it exact.
- `GrantedAccess` is a hex mask string (`0x1010`), not a right name.
- Event 3 does not include a hostname of the *source* process's user beyond `User`; `DestinationHostname` is only present if Sysmon resolved it (can be empty).
- `ProcessId` under `System/Execution` is the Sysmon service PID, not the event's subject — the subject PID is the `EventData` `ProcessId`.
- `Hashes` content depends on the `HashAlgorithms` config; don't assume all four are present.
- Sysmon has no "alert"/"verdict"/"severity" field — it is raw telemetry; detection is downstream (the `RuleName` only reflects the local config's rule tag).
- Don't output Elastic `winlog.event_data.*` wrapping or a Wazuh `data.win.*` envelope — show the flat native field names.
