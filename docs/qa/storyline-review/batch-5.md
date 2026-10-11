# Storyline review — batch 5

Reviewer stance: Tier-3 / IR lead. Every event read in full (authored fields, raw, native record and rawLine). No crypto-themed storyline in this batch.

## Summary

| id | verdict | recognised | crypto | detect | e2e | logs | one-line reason |
|---|---|---|---|---|---|---|---|
| medcore-chain-b | FIX | 4 | no | 2 | 2 | 2 | Insider-theft concept is fine, but 2/4 natives are null and the core evidence (94 files, USB, 3,800 records, no SNI) exists only in prose. No DLP/USB alert. |
| medcore-chain-c | FIX | 4 | no | 3 | 2 | 2 | The VPN fail→success opener is good. Nothing ties the VPN session to 192.168.10.67, there's no logon to PACS, and the "exfil" in the title has no egress event. |
| medcore-chain-d | FIX | 5 | no | 4 | 2 | 2 | Recognised ASA brute-force pattern. But the RDP record shows the public attacker IP inside the LAN, lockouts exist only in prose, and the chain stops at RDP. |
| globallogis-chain-a | FIX | 4 | no | 3 | 2 | 2 | Good macro-phish opener. The xlsm hash equals the powershell hash, Excel is missing from the lineage, the PtH claim has no evidence and the WMS IP is never tied to the host. |
| globallogis-chain-b | FIX | 4 | no | 4 | 2 | 3 | The Mimikatz alert is a real opener, but the tool was quarantined and its creds are still used. No initial access, a session/logon-type mismatch, and no process→upload link. |
| globallogis-chain-c | FIX | 4 | no | 3 | 2 | 1 | Sysmon card is empty. An 11 GB single PutObject is impossible and the external-account CloudTrail would not be visible to the org. Logon type 2 is paired with a remote IP. |
| globallogis-chain-d | FIX | 5 | no | 3 | 3 | 3 | Clean IP pivot (brute force→root→dropper). No host-side failures and no IPS alert. Stops at the download, which is thin for "advanced". |
| quantumbank-chain-a | REPLACE | 3 | no | 3 | 1 | 2 | The MFA fatigue (cloud) and the Outlook-spawned beacon (endpoint) are causally unlinked. The same IP is geolocated to Moldova, then Zurich. The "existing session" has a different session id. |
| quantumbank-chain-b | FIX | 3 | no | 3 | 2 | 2 | The PAM checkout is never used. ModifyDBInstance cannot disable RDS encryption, and eventSource=ec2 is wrong. No logon to ADMIN01. |
| quantumbank-chain-c | REPLACE | 2 | no | 2 | 1 | 1 | Titled "rogue trading" but the story is an external hijack, and no log shows the shared session. ZIA logs the attacker's internet IP, byte sizes are impossible, and an AWS key appears from nowhere. |
| quantumbank-chain-d | FIX | 4 | no | 4 | 3 | 2 | Spray→ATO→wire is recognised. Geo contradictions in the Okta records. ZIA cannot log an external attacker. No SSO, MFA or payment-system evidence. |
| rocketstack-cred-stuffing | FIX | 5 | no | 4 | 3 | 3 | Strong Okta stuffing→MFA-enrol chain. The ThreatInsight block contradicts later successes from the same IP. AWS is reached as an IAMUser with an AKIA key with no explanation. The FortiGate record "sees" SaaS traffic. GitHub native is null. |
| qb-swift-wire-fraud | FIX | 4 | no | 3 | 2 | 2 | Recognised concept. WINWORD opens an .xlsm, a self-describing stealer cmdline, a Tor IP geolocated to Zurich, no path to ADMIN01, GovCloud contradictions, 11 techniques. |
| qb-fraud-monitoring-tampering | FIX | 3 | no | 3 | 2 | 2 | Insider disables fraud alarms. CloudTrail account/region/session contradictions, no AssumeRole tying CyberArk to AWS, duplicate PIDs, 3 null natives. |
| qb-cyberark-mule-payout | FIX | 3 | no | 3 | 2 | 2 | Beneficiary injection plus structuring. Account takeover vs insider is ambiguous. The Data API record logs SQL text as a management event. A single batch POST contradicts "over 40 min". Invented PAN threat. |
| rs-cicd-pipeline-poisoning | FIX | 5 | no | 4 | 3 | 2 | Strong poisoned-pipeline/IMDS story. GuardDuty fires before first use with the wrong principal. CreateAccessKey actor is "unknown" and the new key id is missing. The workflow "completes" before its steps. |
| rs-terraform-iac-backdoor | FIX | 4 | no | 3 | 2 | 2 | Recognised trust-policy backdoor. The GuardDuty finding type is wrong. Post-AssumeRole identities sit in the attacker's account. The FortiGate egress record makes no sense. |
| rs-oauth-consent-chaining | FIX | 4 | no | 3 | 2 | 2 | Recognised consent phishing. client_id differs between events, the credential evidence is prose-only, there's a gap from Okta API token to SAML, and the AssumeRoleWithSAML identity is wrong. |

---

## medcore-chain-b — Insider Data Theft — Patient Records via USB
- **Verdict**: FIX
- **Recognised**: 4. Insider data theft from a clinical SharePoint to USB plus cloud upload. Anchors: T1213.002, T1052.001, T1567/T1041, CERT insider-threat healthcare cases. The T1087.002 directory dump is off-narrative for a departing nurse.
- **Crypto**: no.
- **Detectable**: 2. A real SOC gets a Purview DLP / Defender for Cloud Apps mass-download alert, an S1 Device Control USB alert, or a firewall large-upload threshold. Only the threshold-style mc_b4 is present as real evidence. mc_b2 is a bare legacy raw with no alert.
- **End-to-end**: 2. mc_b1 (user, ClientIP 192.168.10.45) → mc_b2 (host WS-MED-045, same IP) → mc_b4 (same src IP). The pivots work by IP only.
  - Missing: file names and hashes linking SharePoint→USB.
  - Missing: the process that made the 1.8 GB upload (browser? rclone?).
  - Missing: destination domain/SNI, needed to decide containment.
  - mc_b3 has no host and no product card.
- **Log reliability**: 2.
  - mc_b1: native `Operation=FileDownloaded` with `ItemType=Folder` is a single folder event. UAL emits one FileDownloaded per file, so "94" is only in the description and the invented raw `data.office365.ItemsDownloaded`. `ClientIP` for SharePoint Online would be the NAT egress (xlatesrc 62.19.176.10), not RFC1918.
  - mc_b2: `native: null`. No file names, hashes, count or bus type. `usb.vendor`/`usb.serial` aren't S1 field names, and S1 USB activity comes from Device Control events. All evidence is in prose.
  - mc_b3: `native: null`. `azure.activitylogs.operationName=Microsoft.Graph/users/read` doesn't exist: Graph reads aren't in the Azure Activity log (they'd be in MicrosoftGraphActivityLogs). "3,800 records" is prose-only.
  - mc_b4: 1.93 GB in `elapsed=5` s (≈3 Gbps from a workstation) is implausible. "No matching TLS SNI" isn't in the record (Check Point has no SNI field here; it would need an App Control/HTTPS Inspection log).
- **Fixes**:
  - mc_b1: emit N FileDownloaded records (or one plus SourceFileName samples). Set ClientIP to the NAT IP.
  - mc_b2: render a native S1 Device Control/File Creation card with `tgt.file.path=F:\PatientRecords\*.pdf`, the device serial and the file count.
  - Replace mc_b3 with a Purview DLP `DlpRuleMatch` (PHI, USB channel) or drop it.
  - mc_b4: duration ≥ 300 s, and add a URL-filtering/HTTPS log carrying the destination domain.

## medcore-chain-c — VPN Compromise → PACS Medical Imaging Exfil
- **Verdict**: FIX
- **Recognised**: 4. VPN password spray/brute force → valid account → file-share collection. Anchors: T1110.003, T1133, T1039, and VPN-led healthcare intrusions (Akira/LockBit DFIR reports).
- **Crypto**: no.
- **Detectable**: 3. ASA 113005 bursts followed by 113039 success from the same foreign IP is the real SIEM correlation, and it's present (mc_c1/mc_c2). mc_c4 carries an S1 "indicator" only in raw.
- **End-to-end**: 2. mc_c1→mc_c2 pivot on IP 45.141.215.66.
  - mc_c2→mc_c3 is broken: there's no ASA 722051 "IPv4 Address <x> assigned to session" tying the session to 192.168.10.67. That address sits in the user-workstation subnet, not a VPN pool.
  - No 4624 type 10/3 on SRV-MEDCORE-PACS01 explains how the user ran robocopy on the server.
  - No egress event, so "exfil" in the title is unsupported.
  - DUO-RADIUS is in the tunnel group but there's no Duo/MFA record (how was MFA passed?).
- **Log reliability**: 2.
  - mc_c1: native is a single 113005. "12 failures" is prose-only, which is acceptable if several rows are emitted.
  - mc_c3: `native: null` for Windows Security. `ServiceName` in 4769 is an account name (e.g., `SRV-MEDCORE-PACS01$`), not an SPN. `TicketEncryptionType 0x17` (RC4) from a modern client misleads toward Kerberoasting. Severity "high" for a routine TGS.
  - mc_c4: robocopy runs on PACS01 copying its own share `\\SRV-MEDCORE-PACS01\DICOM\2026` to local `C:\Temp\backup`. That is local staging, not exfil. Raw pid 5512/5511 ≠ native 17716/18220. `s1.indicator.name=SUSPICIOUS_BULK_COPY` isn't an S1 indicator, and "22 GB / 8841 files" isn't in the native record.
- **Fixes**:
  - Add an ASA 722051 (assigned IP 10.x VPN pool) and use that IP in mc_c3/mc_c4.
  - Add a Duo auth-success or push record.
  - Render mc_c3 natively with ServiceName=`SRV-MEDCORE-PACS01$` and EncType 0x12.
  - Add a 4624 type 10 on PACS01 from the VPN IP.
  - Change mc_c4 to robocopy from the analyst's VPN host pulling `\\PACS01\DICOM` (T1039), then add an egress record (FW/proxy large upload).
  - Or retitle to drop "Exfil".

## medcore-chain-d — Cisco VPN Brute Force → Clinical Account Compromise
- **Verdict**: FIX
- **Recognised**: 5. Brute force against Cisco ASA/AnyConnect without MFA → valid account → RDP. Anchors: Akira/LockBit 2023 (Cisco PSIRT, CVE-2023-20269 advisory), T1110.001/.003, T1133, T1021.001.
- **Crypto**: no.
- **Detectable**: 4. The 113005 burst then 113039 success from the same RU IP is present. Masked `user = *****` is real ASA behaviour.
- **End-to-end**: 2. mc_d1/d2→d3 pivot on IP 194.165.16.72.
  - mc_d4 can't be pivoted from the VPN session: no assigned-IP record.
  - No 4624 type 10 on WS-NURS-022 (which user logged on?).
  - Nothing happens after RDP (no objective, scope or impact). Too shallow for "advanced".
- **Log reliability**: 2.
  - mc_d1: "55 failures against 9 usernames" can't be derived from masked records.
  - mc_d2: lockouts of dr.dejong/l.bakker appear in no log (would be DC 4740).
  - Raw `reason: Authentication Failed` ≠ native `AAA failure`.
  - mc_d3: l.willems isn't among the users the narrative implies were targeted, which is fine for a spray. Add a 113004 success for the AAA step.
  - mc_d4: S1 `src.ip.address=194.165.16.72` INCOMING to an internal desktop is impossible behind AnyConnect (it would be the pool address), and it contradicts its own description ("the VPN address assigned"). `REMOTE_DESKTOP_SESSION_FROM_VPN_RANGE` isn't an S1 indicator.
- **Fixes**:
  - Emit multiple 113005 rows plus DC 4740 lockout records.
  - Add a 722051 assigned IP (e.g., 10.43.200.17) and use it as src in mc_d4.
  - Add a 4624 type 10 (TargetUserName l.willems, IpAddress pool IP) on WS-NURS-022.
  - Add 2–3 follow-on events (discovery/credential access on the nurse station) or downgrade to "core".

## globallogis-chain-a — Finance Phishing → WMS Server Compromise → FTP Exfil
- **Verdict**: FIX
- **Recognised**: 4. Macro-laden invoice phish → PowerShell loader → lateral movement → FTP exfil. Anchors: T1566.001, T1059.001, T1021/T1550.002, T1048.003, Emotet/QakBot-style finance lures.
- **Crypto**: no.
- **Detectable**: 3. The Sophos behavioural detection (gl_a2) is a real first alert. MDO would also flag the DMARC-fail lookalike.
- **End-to-end**: 2. gl_a1 (user) → gl_a2 (user/host/IP 10.50.2.88) → gl_a3 (IP 10.50.2.88 → SRV-GL-WMS01) → gl_a4 (src 10.50.5.10).
  - Nothing in this story ties 10.50.5.10 to SRV-GL-WMS01.
  - No C2/stage-2 download after the EncodedCommand.
  - No credential-theft event to justify T1550.002.
  - No process on WMS01 running ftp, and nothing staged.
- **Log reliability**: 2.
  - gl_a1: `SPF=pass` + `DKIM=fail` + `DMARC=fail` with MailFrom domain == From domain is contradictory (aligned SPF pass ⇒ DMARC pass). `SenderIPv4` is empty. `EmailLanguage en` for a German body. The attachment name exists only in raw (needs an EmailAttachmentInfo row). Raw `Operation=MessageDelivered` isn't a UAL operation.
  - gl_a2: the xlsm `file.sha256` equals the powershell.exe `process.hash`/native `process_sha256`, which is impossible. Lineage shows parent `cmd.exe`, no EXCEL.EXE, despite the description. Raw pid 5541 ≠ native 1084. `Troj/DocDl-ADEF` is a static document detection name attached to a behavioural process detection.
  - gl_a3: `native: null`. No TargetUserName/IpAddress/LogonProcess/KeyLength, so nothing PtH-specific. It's k.schmidt's own account from her own PC, which looks benign.
  - gl_a4: 148 MB counted on the FTP control connection (DstPort 21). Data flows on a separate FTP-data session.
- **Fixes**:
  - gl_a1: set DMARC pass or make the From domain spoof globallogis.de. Fill SenderIPv4 and add an EmailAttachmentInfo row with the xlsm SHA256.
  - gl_a2: distinct xlsm hash, add EXCEL.EXE as grandparent, and add a stage-2 network event.
  - gl_a3: render natively and either drop T1550.002 or add an LSASS-access event plus a PtH-pattern 4624 (NTLM, KeyLength 0, different account).
  - Add a WMS01 process event (`ftp.exe -s:` / `curl -T`) that names the host/IP.
  - gl_a4: log the FTP-data session (passive high port) with the bytes.

## globallogis-chain-b — Warehouse Terminal Malware → ERP Lateral Movement
- **Verdict**: FIX
- **Recognised**: 4. Mimikatz on an endpoint → service-account reuse → DB dump → exfil. Anchors: T1003.001, T1078.002, T1005, T1041, and ransomware-precursor DFIR reports.
- **Crypto**: no.
- **Detectable**: 4. The Sophos credential-theft detection (gl_b1) is exactly what fires first.
- **End-to-end**: 2. gl_b1 (WH-TERM-012, 10.50.10.12) → gl_b2 (svc-wms from WH-TERM-012) → gl_b3 (WMS01) → gl_b4 (10.50.5.10).
  - No initial access: how did a domain Administrator session end up running a tool from C:\Temp on a terminal?
  - gl_b1 says quarantined, so how were svc-wms creds obtained? There's no second successful dump.
  - No process on WMS01 creating the 890 MB upload, and orders.csv → upload is unproven.
  - Title says ERP, logs say WMS.
- **Log reliability**: 3.
  - gl_b1: raw pid 7100 ≠ native 14384. The detection name "PUA.Tool.Mimikatz" is atypical (Sophos uses ATK/Mimikatz-*).
  - gl_b2: `native: null`, no TargetUserName/IpAddress in raw.
  - gl_b3: Sysmon `TerminalSessionId=3` (interactive) contradicts the gl_b2 type-3 network logon. "1.2 million rows" is prose-only.
  - gl_b4: 933 MB in `ConnectionDuration=8` (~930 Mbps over WAN) is implausible. "No prior traffic" is prose.
- **Fixes**:
  - Add an initial-access event (RDP 4624 type 10 into WH-TERM-012 from an external/VPN IP, or a malicious download).
  - gl_b1: make it detect-only, or add a second detection showing the dump succeeded.
  - gl_b2: render natively, or change to type 10 to match the session.
  - Add a WMS01 process (`rclone`/`curl` uploading orders.csv) with the destination IP.
  - gl_b4: duration ≥ 120 s. Retitle to WMS.

## globallogis-chain-c — Disgruntled Employee — Bulk Customer Database Theft
- **Verdict**: FIX
- **Recognised**: 4. Departing-insider data theft plus sabotage (wiper). Anchors: T1052.001, T1567.002, T1485, CERT insider-sabotage cases.
- **Crypto**: no.
- **Detectable**: 3. The Sophos wiper detection (gl_c4) is the real alert, but it comes last. The after-hours logon (gl_c1) is a UEBA cue. No DLP/USB alert.
- **End-to-end**: 2. gl_c1 (user, 10.50.1.45) → gl_c2/gl_c4 (WMS01) → gl_c3 (10.50.1.45).
  - Archive creation is missing: an 11 GB "compressed" archive is larger than the 9.2 GB source.
  - No USB device-connect event.
  - No link from the archive to the S3 upload host.
- **Log reliability**: 1.
  - gl_c1: `LogonType 2` (console) with a remote src_ip is a contradiction, and native is null.
  - gl_c2: the native Sysmon EID 1 is hollow: `CommandLine` has no arguments, `User "-"`, `ParentImage "-"`, zero ParentProcessGuid, `CurrentDirectory "-"`. The trainee sees no source, no destination and no user. Raw `usb.serial`/`file.destination`/`file.size` aren't Sysmon fields.
  - gl_c3:
    - Single PutObject max is 5 GB, so 11.8 GB needs CreateMultipartUpload/UploadPart.
    - `bytesTransferredOut` on an upload should be `bytesTransferredIn`.
    - `sourceIPAddress` is RFC1918.
    - "External account" contradicts `recipientAccountId` = the same account as the user. A personal external bucket's data events would not appear in the company trail at all.
    - `userAgent os/linux` from a Windows user host.
  - gl_c4: raw pid 8100 ≠ native 13404. The `net stop` evidence is only in raw `process.parent.command_line`.
- **Fixes**:
  - gl_c1: type 10 (RDP) from 10.50.1.45, native.
  - gl_c2: regenerate Sysmon with the full `robocopy \\SRV-GL-WMS01\customers E:\backup /E`, User, ParentImage, and add a Sysmon/Kernel-PnP USB insertion event.
  - gl_c3: make it multipart (CompleteMultipartUpload), with an object size below the source or a compression event.
  - gl_c3, visibility: either the bucket is company-owned (drop "external account") or replace with a proxy/CASB upload to s3.amazonaws.com.
  - gl_c4: native parent cmdline.

## globallogis-chain-d — SSH Brute Force → Linux Server Root Compromise
- **Verdict**: FIX
- **Recognised**: 5. Internet-exposed SSH brute force → root → payload download. Anchors: T1110.001, T1078.003, T1059.004, T1105, mass SSH-bruting botnets.
- **Crypto**: no. The payload `ld` is unnamed. In the wild these droppers are often miners, so keep any future description of the payload non-crypto (botnet/backdoor).
- **Detectable**: 3. Realistic first alerts are a Firepower IPS SSH brute-force event, or auditd/sshd failures, or the Sophos runtime detection (gl_d4, present). Only connection logs show the brute force.
- **End-to-end**: 3. The IP 45.142.212.100 pivot works across gl_d1→d2→d3→d4. Root cause is visible (OUTSIDE-IN-MGMT allows 22 from the internet).
  - Missing: host-side failed auths, the outcome on SRV-GL-LINUX01, execution of /tmp/.hidden, persistence (authorized_keys/cron) and outbound C2.
- **Log reliability**: 3.
  - gl_d1/d2: each native is a single 430003. The counts (86/43) are prose-only.
  - gl_d3: good USER_AUTH. Add USER_LOGIN/USER_START.
  - gl_d4: the Sophos Central alert lacks the command line and file hash. The cmdline exists only in the authored `process` block.
- **Fixes**:
  - Add a Firepower intrusion event (SSH brute force) and auditd USER_AUTH res=failed rows.
  - Add auditd EXECVE for /tmp/.hidden, a persistence change (authorized_keys write) and an outbound connection.
  - gl_d4: add the cmdline/SHA256 to the native record.

## quantumbank-chain-a — MFA Fatigue → Cobalt Strike → Core Banking Session Takeover
- **Verdict**: REPLACE
- **Recognised**: 3. MFA fatigue (Uber 2022, Lapsus$; T1621) and Cobalt Strike are both real, but this combination is not a coherent kill chain.
- **Crypto**: no.
- **Detectable**: 3. Okta risk (qb_a1), the Falcon detection (qb_a2) and the PAN C2 block (qb_a3) are real alert types.
- **End-to-end**: 1.
  - The attacker's Okta session from Moldova (qb_a1/a4) can't explain OUTLOOK.EXE spawning a beacon on the victim's own workstation (qb_a2). No email delivery event, and no reason the identity attack yields endpoint code execution.
  - C2 is blocked (qb_a3), yet the "takeover" proceeds from the attacker IP anyway.
  - The halves link only by username.
- **Log reliability**: 2.
  - qb_a1: the 13 denied/ignored pushes don't exist as events. "14 pushes" is prose. Raw riskLevel CRITICAL ≠ native HIGH.
  - qb_a2: the detection is "DLL injection" but the evidence is a fake svchost from Temp. `CobaltStrike.beacon.v4` appears only in raw. raw pid 9912 ≠ native 468.
  - qb_a4: the same IP 91.234.100.22 is geolocated to Zurich/swisscom AS3303 (vs Chisinau/moldtelecom in qb_a1). The description says "existing session" but `externalSessionId` differs from qb_a1. A token grant is routine SSO, so T1528 isn't evidenced.
- **Fixes (rewrite)**: pick one chain.
  - (a) Pure identity: push-bombing events (`system.push.send_factor_verify_push` ×N, `user.mfa.okta_verify.deny_push` ×N, then success), new-device session, `app.auth.sso` to CoreBanking, a downstream app action, and session revocation.
  - (b) Endpoint: phishing delivery → Outlook-spawned loader → beacon → C2 → token theft.
  - Fix the geo consistency and session ids.

## quantumbank-chain-b — CyberArk Vault Abuse — Unauthorized Privilege Escalation
- **Verdict**: FIX
- **Recognised**: 3. Privileged-access misuse by an insider (T1078.002, T1567, T1070.001). Plausible, but it's really insider data theft, not "privilege escalation".
- **Crypto**: no.
- **Detectable**: 3. The Zscaler DLP block (qb_b3) and the Falcon log-clear prevention (qb_b4) are real alerts.
- **End-to-end**: 2. The user pivot links all four events.
  - The checked-out svc-db-admin is never used (no SQL/Windows logon by it).
  - qb_b2 uses the user's own IAM user, unrelated to the checkout.
  - No source for the PDF (no DB query/export).
  - No logon to SRV-QB-ADMIN01 before wevtutil.
- **Log reliability**: 2.
  - qb_b1: `native: null`. `ca.ticket_required/ticket_provided` are invented. CyberArk Vault CEF carries Reason/TicketID in `cs` fields.
  - qb_b2:
    - `eventSource ec2.amazonaws.com` for ModifyDBInstance (should be rds).
    - snake_case `db_instance_id`/`storage_encrypted` instead of `dBInstanceIdentifier`.
    - StorageEncrypted can't be turned off on an existing instance, so the action is impossible.
    - Private sourceIPAddress, and a Linux CLI agent from a Windows user.
    - T1565.001 doesn't match.
  - qb_b3: `devicehostname None` breaks the host pivot. serverip/clientpublicIP use RFC 5737 documentation ranges.
- **Fixes**:
  - Replace qb_b2 with an MSSQL audit (svc-db-admin login from 10.100.1.20 + `SELECT * FROM TradePositions` / bcp export).
  - Add a PSM/4624 type 10 on ADMIN01 for l.brunner.
  - Native CyberArk CEF for qb_b1 ("Retrieve password", Reason field empty).
  - qb_b3: fill devicehostname.
  - Retitle to "PAM Abuse → Data Theft".

## quantumbank-chain-c — Rogue Trading — Market Manipulation via Authorized Account
- **Verdict**: REPLACE
- **Recognised**: 2. "Rogue trading/market manipulation" is a trade-surveillance/compliance case, not a SOC detection. The events describe an external web-session hijack instead. T1563 (RDP/SSH session hijack) is the wrong technique; it should be T1539/T1550.004.
- **Crypto**: no.
- **Detectable**: 2. The claimed detection (one Okta session used from two IPs) is absent. qb_c1 is a normal HQ login.
- **End-to-end**: 1.
  - No Amsterdam Okta/app event shares session 102TnZ8….
  - The AWS IAM key in qb_c4 has no origin.
  - No cookie-theft root cause.
- **Log reliability**: 1.
  - qb_c1: raw IP 10.100.1.44 vs native 77.181.84.10. `New IP=POSITIVE` from the corporate HQ zone.
  - qb_c2/c3: Zscaler ZIA logging an attacker at 188.166.44.12 ("Road Warrior") is impossible: ZIA only sees bank-managed clients. `responsesize 24339` for "10,000 positions" (~2 bytes each) and `requestsize 8931` for 623 orders are implausible. Order counts and values appear only in raw.
  - qb_c4: `arn …:user/unknown`. Region us-east-1 vs eu-central-2 used elsewhere. No object key.
- **Fixes**: rebuild as AiTM/session-cookie theft:
  - Phish/AiTM proxy sign-in, then an Okta session from a new ASN with the same `externalSessionId` (or `user.session.context.change`).
  - Corebanking app/WAF log from the external IP.
  - Bulk API export with realistic sizes.
  - Session revoke.
  - Drop the trading-manipulation framing and the orphan AWS event.

## quantumbank-chain-d — SWIFT Password Spray → Core Banking Session Hijack
- **Verdict**: FIX
- **Recognised**: 4. Password spray → valid account → fraudulent payment. Anchors: T1110.003, T1078, T1657, SWIFT CSP threat scenarios (Bangladesh Bank lineage). The title says "session hijack" but the story is spray → login.
- **Crypto**: no.
- **Detectable**: 4. Okta failure burst and lockout (qb_d1/d2), then a new-device success (qb_d3), are real alerts.
- **End-to-end**: 3. The IP 5.188.210.100 pivot works throughout.
  - Missing: MFA (password-only for a SWIFT operator?), `app.auth.sso` to the payment app, and the payment-system record of the transfer and its approval.
- **Log reliability**: 2.
  - qb_d2: the native geo is Zurich/swisscom for the RU IP (vs Moscow/Selectel in d1).
  - qb_d3: city "Saint Petersburg" with Moscow lat/lon/postcode. `New IP=NEGATIVE`, `New Country=NEGATIVE` for a never-seen RU IP. Raw credentialType PASSWORD vs native null.
  - qb_d4: ZIA "Road Warrior" logging an external attacker IP is impossible. The amount and beneficiary appear only in raw.
- **Fixes**:
  - Correct the geo/behaviors in d2/d3.
  - Add an MFA event (bypass: policy gap, or `user.mfa.factor.activate`).
  - Add `app.auth.sso` to SWIFT-Gateway.
  - Replace d4 with a payment-gateway/SWIFT Alliance audit record (operator, amount, beneficiary BIC, MT103 ref) or WAF/reverse-proxy logs.
  - Retitle.

## rocketstack-cred-stuffing — Credential Stuffing → Device Persistence → AWS/GitHub Theft
- **Verdict**: FIX
- **Recognised**: 5. Credential stuffing → account takeover → attacker MFA enrollment → cloud/code access. Anchors: T1110.004, T1098.005, T1213.003, Okta 2023 stuffing advisories, Scattered Spider, the Snowflake 2024 no-MFA ATOs.
- **Crypto**: no.
- **Detectable**: 4. Okta `security.threat.detected` (ThreatInsight, bf_02) plus a new factor from a risky IP (bf_06) are top-tier real alerts.
- **End-to-end**: 3. The IP 89.248.171.44 links all events.
  - How the Okta session became an `IAMUser` with long-term AKIA keys in AWS (bf_07) is unexplained. With Okta SSO you'd see AssumeRoleWithSAML and an AssumedRole identity.
  - How the GitHub token was obtained (bf_08) is unexplained.
  - ops-admin lockout is a side thread.
- **Log reliability**: 3.
  - bf_02 says ThreatInsight denied the IP at 11:32, yet bf_06 (11:33, Okta) succeeds from it. That's a contradiction.
  - bf_04:
    - native `direction=outgoing` vs raw incoming.
    - A FortiGate can't see attacker→Okta (SaaS) traffic. dstip 62.221.124.42 DMZ implies a different target.
    - `profile protect_client` on inbound, and `msg "applications3:"` is app-control format.
    - The signature name/ID look invented.
  - bf_01: AS4134 chinanet for 89.248.x (a NL range).
  - bf_07: ListRoles `responseElements` would be null (List calls aren't logged). `roles_count` invented. `path_prefix` should be `pathPrefix`. AWS documentation placeholders (account 123456789012, requestID a1b2c3d4-…).
  - bf_08: GitHub `native: null`. `source: cloudtrail`. Field names don't match the GitHub audit schema (`actor_ip`, `programmatic_access_type` ok). An "Okta SSO" OAuth app isn't how GitHub SAML works.
- **Fixes**:
  - Make bf_02 a per-request deny that doesn't block the already-issued session, or move the block after bf_08.
  - Delete bf_04 or retarget it to the company's own web login.
  - Insert `app.auth.sso` (AWS) + AssumeRoleWithSAML, and make bf_07's identity AssumedRole.
  - Add GitHub `personal_access_token.request_created`/`oauth_authorization.create` before bf_08 and render GitHub natively.
  - Fix the ASN and placeholders.

## qb-swift-wire-fraud — SWIFT Wire-Fraud — Vendor Payment Redirect
- **Verdict**: FIX
- **Recognised**: 4. Phish → infostealer → session-cookie replay → privileged checkout → payment-file tampering → anti-forensics. Anchors: Bangladesh Bank/Lazarus SWIFT intrusions, T1539, T1550.004, T1565.002-style transaction manipulation.
- **Crypto**: no.
- **Detectable**: 3.
  - qbwf1/qbwf3 are ProcessRollup2 telemetry, not detections. Falcon would raise an Office→encoded-PowerShell detection; it's absent.
  - Real alerts present: qbwf9 (Falcon prevention) and qbwf10 (PAN threat).
  - Okta risk on qbwf4.
- **End-to-end**: 2. WKS-QB-055 → 194.36.189.20 → p.meier → Okta → CyberArk → ADMIN01.
  - No email delivery (initial access).
  - No prior legitimate p.meier session to prove cookie replay.
  - No hop from the Tor-sourced session into SRV-QB-ADMIN01 (no PSM/4624).
  - The checked-out account is `svc-swift-app@corebanking-app01` but is used on ADMIN01.
  - ADMIN01 beacons to the WKS C2 (qbwf10) without any infection event on ADMIN01.
  - The AWS keys in qbwf11 have no origin.
- **Log reliability**: 2.
  - qbwf1: WINWORD.EXE opening an .xlsm (should be EXCEL.EXE).
  - qbwf3: the cmdline `--dump-cookies --target=okta…` self-labels the malware, so the conclusion leaks in the log. The description states "dumped … cookie".
  - qbwf4: Tor exit 185.220.101.77 geolocated to Zurich/swisscom with `New Geo-Location=NEGATIVE`. Cookie replay wouldn't produce `user.session.start`.
  - qbwf5/qbwf8: `native: null`. Invented `cyberark.ticket.*`, `recording_missing`. Description says "hijacked".
  - qbwf6: replaces the literal token 'BENEFICIARY_IBAN', which is unrealistic.
  - qbwf7: the amount/IBAN in the query string of a POST, user None. Also redundant with the file tampering: two fraud mechanisms.
  - qbwf10: `Generic-Wire-Fraud-C2(86603)` isn't a PAN threat. The description leaks "wire-fraud C2".
  - qbwf11: "GovCloud" but region us-east-1 and `arn:aws`. `user/unknown`.
- **Fixes**:
  - Add MDO EmailEvents + EmailAttachmentInfo, and use EXCEL.EXE.
  - Add a Falcon detection on qbwf1.
  - Neutral stealer name/cmdline plus a Falcon `BrowserCookie`/file-access event on the Chrome Cookies DB.
  - Add p.meier's legitimate session, then a session-context change from Tor with the correct geo.
  - Render CyberArk natively.
  - Add a PSM-RDP connection → 4624 type 10 on ADMIN01.
  - Drop qbwf7 (keep file tampering) or move the amount into the request body via the payment-app log.
  - Use a real PAN category (e.g., EDL "known C2").
  - Fix qbwf11's partition/region or drop it.
  - Trim the MITRE list.

## qb-fraud-monitoring-tampering — Fraud-Monitoring Tampering — Alarm Threshold Manipulation
- **Verdict**: FIX
- **Recognised**: 3. Insider impairs fraud detection, moves money, then restores (T1562.001, T1657, T1070). A real insider-fraud pattern, but bank fraud monitoring as CloudWatch metric alarms is atypical (normally Actimize/FICO rule changes).
- **Crypto**: no.
- **Detectable**: 3. Realistic alerts are a CloudTrail alarm-modification rule, a Splunk "forwarder stopped / host silent" alert, and Okta off-hours/new device. All are present only as raw telemetry, with no alert record.
- **End-to-end**: 2. l.brunner (Okta, 10.100.1.20) → CyberArk checkout → AWS role session → ADMIN01 → wire → restore.
  - No AssumeRole showing who assumed `qb-fraud-monitor-role`.
  - CyberArk account `@qb-siem01` vs actions on ADMIN01.
  - No logon on ADMIN01.
  - The wire carries no user/beneficiary owner.
- **Log reliability**: 2.
  - qbft3/4/7: arn account 552134008821 ≠ accountId 208340629191. sessionIssuer `role/service-role` ≠ qb-fraud-monitor-role.
  - qbft3/4/7: the "same session" has three different `creationDate`s, and the regions are us-gov-west-1 then us-east-1.
  - GovCloud with the `arn:aws` partition. `alarmNames` should be an array. PutMetricAlarm lacks the required metric/comparison fields.
  - qbft8: `RawProcessId 4704` and `TargetProcessId 280830039545` are identical to qbft5 (copy-paste).
  - qbft2/qbft9: `native: null`, invented fields.
  - qbft6: amount in the URL query, user None.
- **Fixes**:
  - Add sts:AssumeRole (CyberArk-brokered or the l.brunner principal) and align account/partition/region and session creationDate.
  - Unique PIDs for qbft8.
  - Native CyberArk CEF.
  - Add a PSM connection/4624 on ADMIN01.
  - Replace qbft6 with a core-banking payment audit record naming the initiator.
  - Optionally re-host the tampering on a fraud-rules engine audit log.

## qb-cyberark-mule-payout — CyberArk PAM Abuse → Money-Mule Payout (Structuring)
- **Verdict**: FIX
- **Recognised**: 3. Beneficiary master-data tampering bypassing maker-checker, then sub-threshold payouts. A real banking-fraud pattern (T1565.001, T1657), but whether this is account takeover or insider is unresolved.
- **Crypto**: no. The payout is a fiat wire to an RO IBAN.
- **Detectable**: 3. Present as real alerts: Okta medium risk (qbmp1), Falcon prevention (qbmp8), PAN threat (qbmp9). Structuring would really come from AML transaction monitoring, which is absent.
- **End-to-end**: 2.
  - Okta login from external 89.44.168.201, then CyberArk from internal 10.100.1.44 with no VPN/ZTNA link (and .44 is a.keller's IP in another story).
  - The PSM-RDP target is corebanking-db01, but the DB change is made via aws-cli from the user IP and the wires come from ADMIN01.
  - The step-up push "40 seconds later" isn't logged.
- **Log reliability**: 2.
  - qbmp1: the RO-range IP is geolocated to Zurich/swisscom.
  - qbmp2/3/7: `native: null`. "Recording disabled" per session isn't something a user can toggle in PSM.
  - qbmp4:
    - The RDS Data API is a CloudTrail data event (`managementEvent` should be false), and SQL text isn't recorded.
    - Region us-east-1 vs resource eu-central-2.
    - Account mismatches. GovCloud with `arn:aws`.
  - qbmp6: a single batch POST at 13:36 contradicts "11 wires over the next 40 minutes". Amounts appear in the query string.
  - qbmp9: `MoneyMule-Network-Infra(86038)` isn't a PAN threat, and the description leaks the conclusion.
- **Fixes**:
  - Decide ATO (add Okta push events + VPN assigned IP) or insider (internal login).
  - Move the beneficiary insert to a DB audit (SQL Server Audit/pgAudit on corebanking-db01 via the PSM session).
  - Emit 11 separate payment-system records.
  - Native CyberArk.
  - Replace the PAN threat name with an EDL/URL-category hit.
  - Fix the AWS fields or drop AWS.

## rs-cicd-pipeline-poisoning — CI/CD Pipeline Poisoning — Self-Hosted GitHub Actions Runner
- **Verdict**: FIX
- **Recognised**: 5. Poisoned pipeline execution on a self-hosted runner → IMDS credential theft → cloud persistence/data theft. Anchors: OWASP CICD-SEC-4, Codecov 2021 (curl|bash), the PyTorch self-hosted runner research, tj-actions 2025, T1552.005.
- **Crypto**: no.
- **Detectable**: 4. GuardDuty `InstanceCredentialExfiltration.OutsideAWS` (rscp5) is the real high-fidelity first alert, and it's present.
- **End-to-end**: 3. PR merge (rscp1) → workflow (rscp2) → bash/IMDS on SRV-PROD-001 (rscp3/4) → GuardDuty/CloudTrail via 185.220.101.42 (rscp5–9) → egress block (rscp10) → Falcon (rscp11).
  - Missing: PR author/review (was j.lee compromised?), the runner's download (port 80) and the allowed credential-exfil connection.
  - rscp7/rscp8 actor = `user/unknown` instead of the stolen role session.
  - The new access key id isn't in rscp7, so rscp9's "new standing key" can't be verified.
- **Log reliability**: 2.
  - rscp1/rscp2: `native: null`. The audit log contains no diff (`github.workflow.diff_added_lines` invented). `workflow_run.completed` is a webhook, not an audit action.
  - Time contradiction: rscp2 shows the run completed at 09:04, before its steps at 09:04:30/09:05:10.
  - rscp3: the `curl … | bash` cmdline attributed to the bash process (it belongs to the `sh -c` parent). Raw pid 41210 ≠ native 28039.
  - rscp5:
    - The resource is `IAMUser svc-account` with an AKIA key; it should be the AssumedRole/ASIA key from rscp6.
    - Its api is ListBuckets with no matching CloudTrail event.
    - It fires at 09:07, before the first credential use (09:09).
    - remoteIpDetails all "Unknown".
  - rscp6: arn account 247316892041 ≠ accountId 677005474693. sessionIssuer `role/service-role`.
  - rscp7: `responseElements null` (should carry `accessKey.accessKeyId`).
  - rscp10: raw logid/level ≠ native. The description says "threat intel flagged", but the log is a policy deny.
- **Fixes**:
  - Native GitHub audit for `pull_request.merge` (+ `pull_request_review.submit`) and `workflows.completed_workflow_run` after the steps.
  - Put the cmdline on the `sh -c` parent.
  - GuardDuty resource = AssumedRole ASIAEB01…, api GetCallerIdentity, timestamp ≥ 09:09, with geo/ASN.
  - rscp7/8 identity = the stolen role session, and rscp7 responseElements = the new AKIA id used in rscp9.
  - Add the allowed outbound connections from 172.16.10.50.

## rs-terraform-iac-backdoor — IaC Backdoor — Poisoned Terraform Trust Policy
- **Verdict**: FIX
- **Recognised**: 4. Malicious IaC change backdooring an IAM role trust policy for cross-account assume. Anchors: Pacu `iam__backdoor_assume_role`, T1098.003/T1098, T1199, T1530.
- **Crypto**: no.
- **Detectable**: 3. The real detections here are IAM Access Analyzer "external access" findings, a CloudTrail UpdateAssumeRolePolicy rule, and GuardDuty S3 anomaly (rstb8, real type). The rstb3 finding is not real for this activity.
- **End-to-end**: 2. PR (rstb1) → CI apply from 172.16.10.50 (rstb2) → AssumeRole from 91.234.100.55 (rstb4) → S3/Secrets (rstb5/6).
  - The identity pivot breaks: post-assume events show the attacker's own account identity, not `assumed-role/rocketstack-prod-admin/<session>`.
  - AssumeRole `responseElements` are null, so there's no ASIA id to follow.
  - The remediation (rstb9) doesn't revert the trust policy in AWS.
- **Log reliability**: 2.
  - rstb1: `native: null`, invented diff field.
  - rstb2: account mismatch (247316892041 vs 677005474693). Terraform user agent should be `APN/1.0 HashiCorp/1.0 Terraform/…`, not aws-cli.
  - rstb3: `PrivilegeEscalation:IAMUser/AdministrativePermissions` doesn't describe trust-policy changes. The resource is IAMUser svc-account/AKIA and the api is ListBuckets, both contradicting rstb2.
  - rstb4: `recipientAccountId 999999999999` means this is the attacker's copy; the victim's trail would record recipient = victim.
  - rstb5/6: identity in 999999999999 (rstb6 `user/unknown`). The bucket accountId is 999999999999.
  - rstb7: a FortiGate deny from the VPC NAT to 91.234.100.55 is illogical. S3 reads by an external principal never traverse the company NAT. sentbyte 0 vs "large transfer". "IPS signature" vs a policy deny.
  - rstb8: bucket `rocketstack-customer-data` ≠ `rocketstack-prod-customer-data`. api ListBuckets.
- **Fixes**:
  - Native GitHub audit (+ review event).
  - rstb3: replace with an Access Analyzer finding (`isPublic=false`, principal 999999999999, resource rocketstack-prod-admin).
  - rstb4: recipient = victim account, with responseElements.assumedRoleUser + credentials.accessKeyId.
  - rstb5/6: identity = that assumed-role session.
  - Delete rstb7.
  - rstb8: align the bucket and api.
  - Add a CloudTrail UpdateAssumeRolePolicy revert in the remediation.

## rs-oauth-consent-chaining — SaaS OAuth Consent-Chaining → AWS Federation Abuse
- **Verdict**: FIX
- **Recognised**: 4. Malicious OAuth app consent → mailbox/Drive harvesting → credential in email → IdP abuse → cloud. Anchors: T1528, T1114.002, T1552.001, Midnight Blizzard OAuth abuse, Workspace consent-phishing campaigns. The Okta-token→AWS hop is the weak part.
- **Crypto**: no.
- **Detectable**: 3. Realistic alerts would be a Workspace "risky/unverified app granted sensitive scopes" alert, the Okta rate-limit warning (rsoc5) and GuardDuty `TorIPCaller` (absent).
- **End-to-end**: 2. Consent (rsoc1) → Drive/Gmail access (rsoc2–4) → Okta token use from 185.220.101.90 (rsoc5) → AssumeRoleWithSAML (rsoc6) → S3 (rsoc7).
  - An Okta SSWS API token can't mint a SAML assertion. You'd need admin actions (`group.user_membership.add` to the AWS app group, `user.account.reset_password`, or an attacker user), then `app.auth.sso` to AWS, and none are logged.
  - The SAML subject isn't in rsoc6.
  - rsoc7's identity doesn't name the federated role.
- **Log reliability**: 2.
  - rsoc1: the `client_id` 748213906655-a1b2c3d4… (placeholder-like) differs from the 283281115684-… used in rsoc2–4/8, which breaks the app pivot.
  - rsoc3/rsoc4: the Gmail query, subject and sender appear only in raw. The token "activity" log doesn't record them, so the "plaintext Okta token" is prose-only.
  - rsoc5: `native: null`. API-token calls are logged with the token-owner User as actor, not AppInstance, and GET reads aren't logged per call.
  - rsoc6: AssumeRoleWithSAML `userIdentity` should be `SAMLUser` (principalId `<idp>:<nameid>`, identityProvider), not IAMUser `user/unknown` AKIA. Role account 247316892041 vs recipient 677005474693. `responseElements` null.
  - rsoc7: identity `assumed-role/service-role/service-role`. The description says "listed buckets" but there's no ListBuckets.
  - rsoc9: native actor "unknown" for an admin action.
- **Fixes**:
  - Unify client_id.
  - Add Workspace Gmail-log events (`gmail` app, `message_info.subject`, `message_id`) for the token email.
  - Add Okta admin events made with the token (e.g., `group.user_membership.add` to "AWS-Admins") and `app.auth.sso` for AWS from 185.220.101.90.
  - Fix rsoc6's identity to SAMLUser with the subject, plus responseElements.assumedRoleUser.
  - Make rsoc7's identity `assumed-role/rocketstack-okta-federated-admin/<user>`.
  - Render rsoc5 natively (`system.org.rate_limit.warning`).

---

## Cross-cutting observations

1. **Systemic defects in the AWS CloudTrail/GuardDuty native generator** break the identity pivots in ~9 storylines (fix once, in the generator):
   - `userIdentity` defaults to IAMUser `arn:…:user/unknown` with a random AKIA.
   - The assumed-role arn account ≠ `accountId`, and sessionIssuer is always `role/service-role`.
   - `responseElements` is always null, which loses the CreateAccessKey/AssumeRole/AssumeRoleWithSAML key ids.
   - "GovCloud" vendor with the `arn:aws` partition and us-east-1. Region drifts within one session.
   - GuardDuty resource is always IAMUser `svc-account` + api ListBuckets + "Unknown" geo, regardless of finding type.
2. **The connecting evidence is in prose or in null native cards.**
   - Counts and decisive facts live only in descriptions or invented raw keys: 94 files, 12/55/89 failures, 14 pushes, 1.2M rows, lockouts, the Gmail query, email subjects.
   - `native: null` hits exactly the glue events (Windows 4624/4769, SentinelOne, CyberArk, GitHub audit, some Okta).
   - The glue records themselves are often missing: VPN assigned-IP (ASA 722051), 4624 type 10 on the target host, Okta `app.auth.sso` to AWS/CyberArk/GitHub, sts:AssumeRole, the process that made a large upload.
   - Net effect: trainees can find the alert but can't walk host↔IP↔user↔key to root cause.
3. **Product-scope and enrichment contradictions, concentrated in QuantumBank.**
   - Okta native geo/ASN falls back to Zurich/swisscom for foreign IPs (qb_a4, qb_d2, qbwf4, qbmp1).
   - Zscaler ZIA logs external attackers' sessions and core-banking/SWIFT APIs, with amounts in POST query strings.
   - Network firewalls "see" SaaS or S3 traffic they never carry (rocketstack bf_04, rstb7).
   - Invented PAN threat names (`Generic-Wire-Fraud-C2`, `MoneyMule-Network-Infra`), and the same ending reused three times (wevtutil cl Security killed on SRV-QB-ADMIN01).
   - The QB fraud cluster needs a native payment-system/core-banking audit source (initiator, amount, beneficiary) instead of ZIA, and CyberArk needs a native CEF card.
