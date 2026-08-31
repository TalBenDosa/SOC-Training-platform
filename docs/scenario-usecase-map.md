# HACK THE SOC — Scenario Use-Case Map & Coverage

*Living map of the training scenarios (`/scenarios`), the coverage they provide, and where the gaps used to be. Updated after the P1–P4 use-case expansion took the platform from 43 → **67 scenarios**.*

---

## Part 1 — Coverage snapshot (the numbers)

| Dimension | Reality |
|---|---|
| **Total scenarios** | **67** (43 in `scenario-packs/*.ts` + ~24 inline in `scenarios.ts`) |
| **Difficulty** | 21 beginner · **21 intermediate** · 22 advanced · 3 expert |
| **MITRE tactics (14 enterprise + ICS)** | All 14 enterprise tactics well-represented; ATT&CK-for-ICS now touched (OT scenario) |
| **Data sources** | 30+ distinct `source` types across 50+ real vendors |
| **Benign controls** | Every one of the 24 new scenarios ships a benign look-alike ("scary ≠ malicious") |
| **SOC-scope** | Every scenario is driven by SIEM-fed console telemetry; the gradeable task is analyst triage → verdict |

**Difficulty curve — before vs after the expansion:**

| Tier | Was (43) | Now (67) | Change |
|---|---|---|---|
| Beginner | 20 | 21 | +1 |
| **Intermediate** | **7** | **21** | **+14** ← the steep beginner→advanced jump is fixed |
| Advanced | 14 | 22 | +8 |
| Expert | 2 | 3 | +1 (golden-saml) |

---

## Part 2 — The 24 new scenarios (P1–P4 expansion)

Every one carries a **benign control event** as its discriminator, verified technique↔tactic MITRE pairings, and passed a full practical-playthrough QA (scores 90–99/100). All 24 were confirmed SOC-dedicated: telemetry an analyst sees in their consoles, and a triage→verdict task.

### P1 — the biggest gaps (5)
| Slug | Tier | Sources | Fills |
|---|---|---|---|
| `windows-privesc-token` | Intermediate | CrowdStrike, Sysmon, Win Security | **Privilege Escalation** (was only 2 MITRE tags) — SeImpersonate → named-pipe potato → SYSTEM → SAM |
| `linux-privesc-suid` | Intermediate | auditd, Falcon | Priv-Esc + Linux — www-data → root via SUID `find` (GTFOBins) → `/etc/shadow` → uid-0 backdoor |
| `lateral-movement-pth` | Intermediate | Win Security, Sysmon, Falcon | **Lateral Movement** (was thin) — Pass-the-Hash → file server → second hop to DC |
| `insider-dlp-usb-cloud` | Intermediate | Purview DLP, MDE, Zscaler | **DLP** (was 3 events) — departing analyst, USB + Dropbox, Audit-mode ("allowed ≠ benign") |
| `nac-rogue-device` | Beginner | Cisco ISE, DHCP | **NAC** (was absent) — laptop MAC-spoofs a printer → ISE OUI/fingerprint mismatch → CoA quarantine |

### P2 — modern threats & source diversity (7)
| Slug | Tier | Sources | Fills |
|---|---|---|---|
| `macos-stealer-dmg` | Intermediate | CrowdStrike (Mac), Zscaler, MDE | **macOS** — Atomic/AMOS stealer via cracked DMG → Keychain + cookies + wallet |
| `sqli-db-exfil` | Advanced | Imperva WAF, IBM Guardium, SQL Audit | **DB monitoring** — follow SQLi past the WAF into the DB (248k-row dump + xp_cmdshell) |
| `azure-managed-identity-abuse` | Advanced | Entra, Azure Activity, Graph | **Azure-native** — app-registration secret-add → subscription enum → Key Vault/Storage |
| `cicd-supply-chain` | Advanced | GitHub Audit, CloudTrail, GuardDuty | **Supply-chain depth** — poisoned workflow → OIDC → assume AWS role → S3/Secrets |
| `ueba-compromised-account` | Intermediate | Sentinel UEBA, Entra, M365 | **UEBA** (was 1 event) — anomaly-driven hunt from a risk score, not an alert |
| `vishing-rmm` | Intermediate | CrowdStrike, Zscaler, ServiceNow | **Social-eng** — fake IT call → signed AnyDesk → hands-on-keyboard ("signed ≠ authorized") |
| `pam-vault-abuse` | Advanced | CyberArk, AD, Sysmon | **PAM** (was absent) — off-hours vault checkout, no dual-control, used outside PSM |

### P3 — rounding out breadth (6)
| Slug | Tier | Sources | Fills |
|---|---|---|---|
| `destructive-wiper` | Advanced | CrowdStrike, Sysmon, MDE | **Impact variety** — wiper ≠ ransomware (no key, no note, no recovery path) |
| `s3-exfil-exposure` | Intermediate | CloudTrail, GuardDuty | **AWS-native depth** — public-bucket config change → bulk GetObject → GuardDuty |
| `golden-saml` | **Expert** | Entra, AD, Sentinel | **Identity depth** — steal AD FS token-signing key → forge SAML (no matching IdP auth) |
| `gws-oauth-marketplace` | Intermediate | Google Workspace | **GWS depth** — broad-scope OAuth consent → API mail/Drive exfil, survives password reset |
| `threat-intel-hunt` | Intermediate | Recorded Future, Win DNS, Zscaler, Falcon | **Threat-intel** (was 1 event) — IOC feed → sweep → confirmed live beacon (+ a stale false hit) |
| `container-escape-cryptomining` | Advanced | K8s audit, CrowdStrike | **K8s runtime** — privileged pod → `nsenter` node breakout → XMRig miner |

### P4 — breadth polish (6)
| Slug | Tier | Sources | Fills |
|---|---|---|---|
| `mobile-mdm-compromise` | Intermediate | Intune, Entra | **Mobile/MDM** — smishing → rooted device → corp access via a Conditional-Access gap |
| `gcp-sa-key-theft` | Advanced | GCP Audit Logs | **GCP-native** — mint SA key → impersonate SA → read datalake + Secret Manager |
| `macos-tcc-pkg` | Intermediate | CrowdStrike (Mac) | **macOS depth** — malicious .pkg root script → TCC.db rewrite → LaunchDaemon persistence |
| `email-bomb-helpdesk` | Intermediate | MDO, CrowdStrike, ServiceNow | **Ransomware precursor** — inbox flood → fake-IT call → Quick Assist takeover (Black Basta TTP) |
| `ot-network-anomaly` | Advanced | Zeek, Suricata | **OT/ICS** — IT→OT pivot, Modbus WRITE to a PLC from an unauthorized host (network-only visibility) |
| `bec-wire-fraud` | Intermediate | MDO, M365, ServiceNow | **Deepfake/BEC** — lookalike-domain CFO wire request + voice-clone call (impersonation ≠ ATO) |

---

## Part 3 — Full mapping (all 67, by family)

### A · Phishing, email-borne & BEC (7)
`phishing-malware-basic` (B) · `phishing-to-cloud-exfil` (I) · `bec-mailbox-rule` (B) · `gws-phishing-attachment` (B) · `oauth-consent-grant-phishing` (E) · `aitm-token-theft` (A) · **`bec-wire-fraud` (I) — NEW**

### B · Endpoint malware / user-driven initial access (12)
`usb-malware-basic` (B) · `bundled-cryptominer` (B) · `seo-poisoned-installer` (B) · `clickfix-fake-captcha` (B) · `trojanized-installer-keylogger` (B) · `fake-browser-update` (B) · `drive-by-browser-miner` (B) · `iso-container-smuggling` (B) · `infostealer-session-theft` (I) · `clipboard-clipper` (B) · **`macos-stealer-dmg` (I) — NEW** · **`macos-tcc-pkg` (I) — NEW**

### C · Ransomware, extortion & destruction (4)
`ransomware-lockbit` (A) · `esxi-ransomware` (E) · `exfil-first-extortion` (A) · **`destructive-wiper` (A) — NEW**

### D · Identity, account takeover & mobile (10)
`mfa-fatigue-ato` (B) · `impossible-travel-basic` (B) · `aitm-token-theft` (A) · `helpdesk-mfa-reset` (I) · `rogue-admin-account` (B) · `oauth-app-persistence` (A) · **`ueba-compromised-account` (I) — NEW** · **`golden-saml` (E) — NEW** · **`mobile-mdm-compromise` (I) — NEW**

### E · Active Directory / credential theft (6)
`kerberoasting` (A) · `asrep-roasting` (I) · `dcsync-golden-ticket` (A) · `ntlm-relay-responder` (A) · `brute-force-single-account` (B) · `okta-password-burst` (B)

### F · Privilege escalation & lateral movement (4) — NEW FAMILY
**`windows-privesc-token` (I)** · **`linux-privesc-suid` (I)** · **`lateral-movement-pth` (I)** · **`pam-vault-abuse` (A)** — all NEW

### G · Cloud & container (10)
`cloud-cryptomining` (I) · `k8s-pod-escape-imds` (A) · `oauth-app-persistence` (A) · **`azure-managed-identity-abuse` (A)** · **`cicd-supply-chain` (A)** · **`s3-exfil-exposure` (I)** · **`gws-oauth-marketplace` (I)** · **`container-escape-cryptomining` (A)** · **`gcp-sa-key-theft` (A)** — 6 NEW

### H · Web / perimeter exploitation (3)
`web-shell-sqli` (A) · `edge-vpn-cve-exploit` (A) · **`sqli-db-exfil` (A) — NEW** (WAF → DB layer)

### I · C2, exfiltration & threat hunting (4)
`dns-tunneling` (A) · `exfil-first-extortion` (A) · `lolbins` (A) · **`threat-intel-hunt` (I) — NEW**

### J · Insider, supply-chain, physical & social-engineering (6)
`insider-threat-finance` (I) · `supply-chain-vendor-update` (A) · **`insider-dlp-usb-cloud` (I)** · **`nac-rogue-device` (B)** · **`vishing-rmm` (I)** · **`email-bomb-helpdesk` (I)** — 4 NEW

### K · OT / ICS (1) — NEW FAMILY
**`ot-network-anomaly` (A) — NEW** (IT→OT pivot, seen through passive network sensors)

### L · Multi-stage · triage / false-positive · persistence (overlap)
`multi-host-intrusion` (A) · `backup-agent-false-positive` (B) · `software-install-false-positive` (B) · `scheduled-task-persistence` (B) · `oauth-app-persistence` · `rogue-admin-account`

---

## Part 4 — Gap analysis: what the expansion closed

### 🔴 MITRE tactic gaps → CLOSED
- **Privilege Escalation** — was 2 tags total. Now a dedicated family (Windows token, Linux SUID, PAM, cloud IAM via Azure MI).
- **Lateral Movement** — was thin/embedded. Now a focused Pass-the-Hash case + reinforced across PAM/Golden SAML.
- **Impact** — was ransomware-only. Now includes a true wiper (destruction ≠ extortion) and resource-hijacking (cryptomining/container).
- **ICS tactics** — now touched via the OT scenario (ATT&CK-for-ICS: Lateral Movement, Discovery, Impair Process Control).

### 🔴 Data-source gaps → CLOSED
- **NAC** (Cisco ISE), **DLP** (Purview), **DB activity monitoring** (Guardium/SQL Audit/Imperva), **UEBA** (Sentinel), **macOS** (CrowdStrike Mac — stealer + TCC), **Azure-native** (Entra/Activity/Graph), **GCP-native** (Cloud Audit), **CI/CD** (GitHub Audit), **PAM** (CyberArk), **Google Workspace** (OAuth), **Threat Intel** (Recorded Future), **Kubernetes runtime** (K8s audit + Falcon), **Mobile/MDM** (Intune), **OT/ICS network** (Zeek/Suricata) — all now exercised with real registered vendor fields.

### 🟡 Difficulty gap → CLOSED
- Intermediate went 7 → 21 (+14). The beginner→advanced cliff is now a gradient.

---

## Part 5 — Status: use-case map fully built out

The prioritized map (P1–P4) is **complete** — all recommended use cases have been built, integrated, QA'd and shipped. The platform now covers the large majority of the attack surface a SOC analyst meets, across enterprise + cloud + identity + endpoint + email + network + OT.

Possible **future** themes (not gaps — new breadth, only if desired):

| Theme | Note |
|---|---|
| Deeper mobile (Android malware families, MDM policy tamper) | Mobile is now 1 scenario; room to deepen |
| GCP/Azure parity with AWS depth | Each cloud now has ≥1 native case; AWS remains deepest |
| Additional OT/ICS protocols (DNP3, S7comm, historian tamper) | OT is now 1 scenario; a whole matrix exists |
| Emerging AI-era threats (prompt-injection on internal copilots, model/data poisoning) | New estate entirely |
| Freshness cadence (quarterly refresh tied to current CISA advisories / DFIR reports) | Process, not a scenario |

**Net position:** 67 scenarios, all 14 enterprise MITRE tactics well-represented (plus ICS), 30+ data sources exercised with authentic vendor fields, a smooth difficulty curve, a benign control in every new scenario, and every scenario confirmed as a genuine SOC analyst investigation. Further growth is content-authoring on the existing infrastructure, not new plumbing.
