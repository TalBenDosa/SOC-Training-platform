# Storyline review — batch 3

Reviewer stance: Tier-3 / IR lead. Every event of the 18 files was read in full (description, authored fields, raw, native record/rawLine).

## Summary

| id | verdict | recognised | crypto | detect | e2e | logs | one-line reason |
|---|---|---|---|---|---|---|---|
| k8s-pod-escape | FIX | 5 | no | 3 | 3 | 2 | The SCARLETEEL-style chain is sound, but the identity and account IDs contradict each other. No GuardDuty or Falcon detection is present, there is no initial token theft, and nothing links the pod to the node. |
| oauth-consent | FIX | 5 | no | 3 | 3 | 2 | A textbook illicit consent grant, but it confuses delegated identity with app identity, uses invented Graph "operations" and a Microsoft-owned IP as the attacker, has 4 null natives and no lure email. |
| kerberoasting | FIX | 5 | no | 4 | 3 | 2 | The 4769/RC4 core is right, but all 11 native records are null, 4662 is misused as an LDAP log, the MDI alert fires before its query, there is no endpoint evidence and the payload is a dead end. |
| dns-tunneling | FIX | 4 | no | 4 | 3 | 3 | The Sysmon 22 core is good. The PAN log contradicts the resolver path, the update.exe hash and PID differ between records, update.exe is never executed, the root cause is missing and "dnscat2" appears only in prose. |
| lolbins | FIX | 4 | no | 4 | 3 | 3 | A kitchen-sink of 6 LOLBins and 5 payloads, mostly never executed. srvhost.dll has no origin, and a systemic initiating-process hash mismatch breaks pivots. |
| bruteforce-single | FIX | 5 | no | 4 | 4 | 3 | A solid exposed-RDP brute-force chain. The firewall zones and rule contradict each other, 8 of 10 natives are null, and the CrowdStrike row renders as MDE with a different SID and LogonId. |
| okta-password-burst | FIX | 5 | no | 4 | 4 | 3 | Good teaching ("password guessed, MFA held"). But behaviors show NEGATIVE for a first-seen Iceland IP, and two descriptions don't match the native eventType. |
| gws-phish-attachment | FIX | 4 | no | 5 | 4 | 3 | An AMOS-style HTML-smuggled DMG. osascript is killed at :24, yet a POST that needs a typed password goes out at :25. The two detections conflict and the HTML-open step is missing. |
| fake-browser-update | FIX | 5 | no | 5 | 4 | 4 | A faithful SocGholish chain. Minor issues: CrowdStrike rows render as MDE, FileOriginUrl is null and the initiating-process hash doesn't match. |
| trojanized-keylogger | FIX | 4 | no | 4 | 3 | 2 | The description says "elevated", but the records show Medium integrity and no admin rights while Program Files is written. Installer→file and process→POST attribution is missing from the native records, and the keylogger alert appears twice. |
| bundled-cryptominer | REMOVE | 4 | yes | 4 | 4 | 3 | Crypto-themed: the incident is a coinminer (T1496, stratum pool, wallet in the command line). |
| seo-poisoned-installer | FIX | 5 | no | 4 | 4 | 3 | A Nitrogen/Rhadamanthys-style malvertising case. The referer is not an ad click, explorer runs at High integrity, and the "prevented" alert contradicts exfiltration that already completed. |
| iso-container-smuggling | FIX | 4 | no | 4 | 3 | 2 | The core premise ("MOTW doesn't propagate into an ISO") has been outdated since the Nov-2022 patch. FortiGate and CrowdStrike rows render as PAN and MDE, the delivery vector is missing and update.dat is unused. |
| drive-by-browser-miner | REMOVE | 3 | yes | 3 | 3 | 2 | Crypto-themed: in-browser cryptojacking. |
| clickfix-fake-captcha | FIX | 5 | no | 5 | 4 | 3 | Strong and current. Bugs: a process is its own parent in evt_cfc_05, the RunMRU event and the sysupd32 download are missing, and some attribution exists only in prose. |
| clipboard-clipper | REMOVE | 3 | yes | 4 | 3 | 3 | Crypto-themed: a crypto-wallet clipper delivered through "CryptoTrackerLite". |
| scheduled-task-persistence | FIX | 3 | no | 3 | 4 | 4 | A clean Sysmon GUID chain. The next-day "logon" reuses the same LogonId and LogonGuid, there is no 4698 or TaskScheduler 106 event, and the payload's origin is missing. |
| impossible-travel-basic | FIX | 5 | no | 5 | 4 | 3 | An excellent AiTM→BEC story. It lacks the proxy sign-in that created the stolen session, uses the wrong token type (PRT), the VPN vendor doesn't match its native card, and the Zscaler and VPN IPs disagree. |

---

## k8s-pod-escape — FIX
- **Recognised 5**: T1609, T1611, T1552.005, T1580, T1530, T1610, T1136.003 and T1098.003. This is the SCARLETEEL (Sysdig 2023) and TeamTNT/Kinsing pattern: K8s exec → container escape → IMDS creds → S3 → IAM backdoor.
- **Crypto**: no.
- **Detectable 3**: In practice the first alerts would be GuardDuty `Discovery:Kubernetes/TorIPCaller`, `PrivilegeEscalation:Kubernetes/PrivilegedContainer` and `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS`, plus a Falcon "container escape" detection. None of them is present. The rows are raw telemetry only (k8s_02 is a ProcessRollup2, not a detection, although its description says "CrowdStrike detected").
- **End-to-end 3**: The intended path is k8s_01 (exec from 185.220.101.47) → 01b (privileged spec) → 02/03/04 on the node → 05–08 using the creds from the same IP → 09 privileged pod → 10/11 IAM user with admin.
  - Missing: how ci-deploy-token was obtained (the root cause).
  - Missing: any field tying pod `api-prod-7f8b9c` to node `eks-node-i-0abc123` or to container `a3f7b1c9d2e8` (`spec.nodeName` or `status.containerStatuses[].containerID` would do it).
  - Missing: `CreateAccessKey` for the backdoor user. Without it the user can't be used programmatically, so the scope is incomplete.
- **Log reliability 2**:
  - The identity differs per row:
    - k8s_01: `user.username` = "ci-deploy-token", groups `system:serviceaccounts`.
    - k8s_01b: "system:serviceaccount:cicd:ci-deploy".
    - k8s_09: "ci-deploy-token", groups only `system:authenticated`.
    - "ci-deploy-token" is not a valid service-account username format.
  - userAgent changes between rows: kubectl v1.28.2 in 01, v1.30.0 in 01b and 09.
  - k8s_01b: `level`="Request" yet the record carries `responseObject`, which only appears at RequestResponse level. `event_type` "k8s_rbac" is wrong for a pod GET.
  - k8s_05 vs 06–11: `userIdentity.arn` uses account 123456789012 while `accountId`/`recipientAccountId` = 677005474693 in the same record.
  - k8s_05–11: `sessionIssuer.arn` "role/service-role" ≠ eks-node-role. `attributes.creationDate` equals eventTime on every call; it should be fixed at the 02:48 credential issue. Instance ID `i-0abc123` is not a valid length. aws-cli is 2.13.0 in 05 but 2.17.60 in 06+.
  - k8s_06: "returning 14 buckets" appears only in prose (`responseElements` null).
  - k8s_08: byte count in `responseElements.contentLength`; real GetObject uses `additionalEventData.bytesTransferredOut`.
  - k8s_09: create `requestURI` includes the pod name (a POST goes to …/pods). The image is named `backdoor:latest`, which leaks the conclusion.
  - k8s_10: native `responseElements` uses flattened keys ("user.userId") instead of nested JSON.
  - k8s_04: native null.
  - k8s_01: description asserts "a known Tor exit node", which is enrichment and not in the record.
- **Fixes**:
  - One identity everywhere: `system:serviceaccount:cicd:ci-deploy`, with consistent groups and UA.
  - Add `spec.nodeName: eks-node-i-0abc123` and `containerStatuses[0].containerID: containerd://a3f7b1c9d2e8…` to 01b's responseObject and set level=RequestResponse.
  - Use one AWS account ID everywhere. Set sessionIssuer to `role/eks-node-role` and creationDate to 02:48:00. Use a 17-hex instance ID.
  - Add a GuardDuty InstanceCredentialExfiltration.OutsideAWS finding (~02:50) and a Falcon detection for k8s_02.
  - Add CreateAccessKey after k8s_11.
  - Rename the image (e.g. `metrics-agent:1.2`).
  - Give k8s_04 a native record (or drop it, since k8s_03 already covers IMDS).
  - Add an initial-access row (e.g. CI token found in a public repo, or first use of the token from a new IP).

## oauth-consent — FIX
- **Recognised 5**: T1528 illicit consent grant, which Microsoft documents. Used by Midnight Blizzard/APT29 and in Proofpoint-reported campaigns, followed by mailbox collection (T1114) and forwarding.
- **Crypto**: no.
- **Detectable 3**: Real first alerts would be Defender XDR/MDCA "Suspicious inbox forwarding rule", App Governance "unusual app/high-privilege consent", or Entra "Risky OAuth app". Only a non-native DLP row (oauth_08) and a non-native UEBA row (oauth_09) exist.
- **End-to-end 3**: The intended path is consent (01) → mail access (02) → rule (04) → SharePoint (05) → admin-consent attempt (07) → DLP/UEBA.
  - Missing: the lure email or click that led j.chen to consent.
  - Missing: a j.chen sign-in from 207.154.110.53 to tie the consent IP to the user.
  - Missing: any evidence mail was actually forwarded (message trace).
  - Missing: the Graph activity with the attacker's real IP.
- **Log reliability 2**:
  - oauth_10: "Add application." would not appear in the victim tenant. A multi-tenant attacker app shows up as "Add service principal" at consent time. Native null.
  - oauth_02/03/04/05/06: `ClientIPAddress` 40.99.8.12 is a Microsoft Exchange Online address, yet oauth_09 calls it a source "with no prior history". Graph app access would carry the attacker IP.
  - oauth_02: `ClientInfoString` "Client=OWA;Action=ViaProxy" contradicts Graph app access. The description says 1,247 items, but `OperationCount`=2 with 2 FolderItems.
  - oauth_03 and oauth_06: "MailFolders.List" and "CalendarEvents.List" are not UAL operations (they belong in MicrosoftGraphActivityLogs). Both natives are null.
  - oauth_04 and oauth_05: consent is delegated (`ConsentType: Principal`), so actions run as the user and `UserId` should be j.chen, not the app ID. oauth_04 `AppId` = Exchange (00000002-…), not the app. oauth_05 says "312 files" but the record is one FileAccessed on a Folder (raw says File) with an Edge browser UserAgent.
  - oauth_07: `initiatedBy.app` is "Unknown application" d9bcb1bc… and the target is "Unknown application", not Productivity Suite Pro. Apps don't request admin consent themselves; a user does.
  - oauth_08: SharePoint DLP uses `ExchangeMetaData.Attachment` (should be SharePointMetaData.FileName/FilePathUrl). An "approved apps only" condition is not a Purview DLP SharePoint condition. Native null.
  - oauth_09: invented generic UEBA fields (`behavior.score`). Native null.
  - Forwarding domain productivity-suite.pro vs reply URL productivty-suite.com: two attacker domains with no explanation.
- **Fixes**:
  - Replace oauth_10 with an "Add service principal" row at 22:14 on 06-13 (before consent).
  - Add a phishing email (EmailEvents/EmailUrlInfo) to j.chen and an Entra sign-in from 207.154.110.53.
  - Use one attacker IP (non-Microsoft) on every app-driven row.
  - Set UserId = j.chen on 02/04/05/06 and keep AppId = a3f9…. Set ClientInfoString to Graph/REST. Make OperationCount match 1,247.
  - Convert 03/06 to MicrosoftGraphActivityLogs records or drop them.
  - Fix oauth_07 to a user-initiated admin-consent attempt by j.chen with the correct app display name.
  - Swap oauth_08 for a Defender XDR alert "Suspicious inbox forwarding rule" or an App Governance alert (native).
  - Add a message-trace row showing mail forwarded externally.

## kerberoasting — FIX
- **Recognised 5**: T1558.003 after T1087.002 LDAP SPN discovery. A standard precursor in ransomware DFIR reports (Conti/BlackBasta, The DFIR Report). xp_cmdshell abuse with a service account is common.
- **Crypto**: no.
- **Detectable 4**: MDI "Suspected Kerberos SPN exposure" (external ID 2410) or "Security principal reconnaissance (LDAP)", plus a Sentinel RC4-TGS volume rule. A Sentinel correlation is present (kerb_06), and an MDI-like row exists but with a wrong alert name.
- **End-to-end 3**: The path is WS-DEV-4412/m.cohen logon → LDAP SPN enum → 3× 4769 RC4 → Sentinel → svc-mssql Type 10 to srv-db01 → Type 3 to srv-file01 → x