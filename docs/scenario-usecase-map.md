# HACK THE SOC — Scenario Use-Case Map & Coverage

*Living map of the training scenarios (`/scenarios`), the coverage they provide, and where the gaps used to be. Updated after the P1–P3 use-case expansion took the platform from 43 → **61 scenarios**.*

---

## Part 1 — Coverage snapshot (the numbers)

| Dimension | Reality |
|---|---|
| **Total scenarios** | **61** (37 in `scenario-packs/*.ts` + ~24 inline in `scenarios.ts`) |
| **Difficulty** | 21 beginner · **17 intermediate** · 20 advanced · **3 expert** |
| **MITRE tactics (14 enterprise)** | All 14 touched; the former thin tactics (Privilege Escalation, Lateral Movement, Impact-variety) are now properly represented |
| **Data sources** | 30+ distinct `source` types across 50+ real vendors |
| **Benign controls** | Every one of the 18 new scenarios ships a benign look-alike ("scary ≠ malicious") |

**Difficulty curve — before vs after the expansion:**

| Tier | Was (43) | Now (61) | Change |
|---|---|---|---|
| Beginner | 20 | 21 | +1 |
| **Intermediate** | **7** | **17** | **+10** ← the steep beginner→advanced jump is fixed |
| Advanced | 14 | 20 | +6 |
| Expert | 2 | 3 | +1 (golden-saml) |

---

## Part 2 — The 18 new scenarios (P1–P3 expansion)

Every one carries a **benign control event** as its discriminator, verified technique↔tactic MITRE pairings, and passed a full practical-playthrough QA (scores 90–99/100).

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

---

## Part 3 — Full mapping (all 61, by family)

### A · Phishing & email-borne (6)
`phishing-malware-basic` (B) · `phishing-to-cloud-exfil` (I) · `bec-mailbox-rule` (B) · `gws-phishing-attachment` (B) · `oauth-consent-grant-phishing` (E) · `aitm-token-theft` (A)

### B · Endpoint malware / user-driven initial access (11)
`usb-malware-basic` (B) · `bundled-cryptominer` (B) · `seo-poisoned-installer` (B) · `clickfix-fake-captcha` (B) · `trojanized-installer-keylogger` (B) · `fake-browser-update` (B) · `drive-by-browser-miner` (B) · `iso-container-smuggling` (B) · `infostealer-session-theft` (I) · `clipboard-clipper` (B) · **`macos-stealer-dmg` (I) — NEW**

### C · Ransomware, extortion & destruction (4)
`ransomware-lockbit` (A) · `esxi-ransomware` (E) · `exfil-first-extortion` (A) · **`destructive-wiper` (A) — NEW** (destruction, not extortion)

### D · Identity & account takeover (8)
`mfa-fatigue-ato` (B) · `impossible-travel-basic` (B) · `aitm-token-theft` (A) · `helpdesk-mfa-reset` (I) · `rogue-admin-account` (B) · `oauth-app-persistence` (A) · **`ueba-compromised-account` (I) — NEW** · **`golden-saml` (E) — NEW**

### E · Active Directory / credential theft (6)
`kerberoasting` (A) · `asrep-roasting` (I) · `dcsync-golden-ticket` (A) · `ntlm-relay-responder` (A) · `brute-force-single-account` (B) · `okta-password-burst` (B)

### F · Privilege escalation & lateral movement (4) — NEW FAMILY
**`windows-privesc-token` (I)** · **`linux-privesc-suid` (I)** · **`lateral-movement-pth` (I)** · **`pam-vault-abuse` (A)** — all NEW (this family barely existed before)

### G · Cloud & container (8)
`cloud-cryptomining` (I) · `k8s-pod-escape-imds` (A) · `oauth-app-persistence` (A) · **`azure-managed-identity-abuse` (A) — NEW** · **`cicd-supply-chain` (A) — NEW** · **`s3-exfil-exposure` (I) — NEW** · **`gws-oauth-marketplace` (I) — NEW** · **`container-escape-cryptomining` (A) — NEW**

### H · Web / perimeter exploitation (3)
`web-shell-sqli` (A) · `edge-vpn-cve-exploit` (A) · **`sqli-db-exfil` (A) — NEW** (WAF → DB layer)

### I · C2, exfiltration & threat hunting (4)
`dns-tunneling` (A) · `exfil-first-extortion` (A) · `lolbins` (A) · **`threat-intel-hunt` (I) — NEW**

### J · Insider, supply-chain & physical (5)
`insider-threat-finance` (I) · `supply-chain-vendor-update` (A) · **`insider-dlp-usb-cloud` (I) — NEW** · **`nac-rogue-device` (B) — NEW** · **`vishing-rmm` (I) — NEW** (social-engineering foothold)

### K · Multi-stage · triage / false-positive · persistence (overlap)
`multi-host-intrusion` (A) · `backup-agent-false-positive` (B) · `software-install-false-positive` (B) · `scheduled-task-persistence` (B) · `oauth-app-persistence` · `rogue-admin-account`

---

## Part 4 — Gap analysis: what the expansion closed

### 🔴 MITRE tactic gaps → CLOSED
- **Privilege Escalation** — was 2 tags total. Now a dedicated family: Windows token impersonation, Linux SUID, PAM abuse, cloud IAM escalation (Azure MI).
- **Lateral Movement** — was thin/embedded. Now a focused Pass-the-Hash case + reinforced across PAM/Golden SAML.
- **Impact** — was ransomware-only. Now includes a true wiper (destruction ≠ extortion) and resource-hijacking (cryptomining/container).

### 🔴 Data-source gaps → CLOSED
- **NAC** (Cisco ISE), **DLP-centric** (Purview), **DB activity monitoring** (Guardium/SQL Audit/Imperva), **UEBA** (Sentinel), **macOS** (CrowdStrike Mac), **Azure-native** (Entra/Activity/Graph), **CI/CD** (GitHub Audit), **PAM** (CyberArk), **Google Workspace** (OAuth/Marketplace), **Threat Intel** (Recorded Future), **Kubernetes runtime** (K8s audit + Falcon) — all now exercised by at least one scenario, each with real registered vendor fields.

### 🟡 Difficulty gap → CLOSED
- Intermediate went 7 → 17 (+10). The beginner→advanced cliff is now a gradient.

---

## Part 5 — What remains (candidate P4, optional)

The core map is complete. Remaining opportunities are breadth-polish, not gaps:

| Idea | Fills | Tier |
|---|---|---|
| Mobile / MDM (Intune) compromise | Mobile is still ~1 scenario | Intermediate |
| GCP-native abuse (service-account key theft) | GCP lighter than AWS/Azure | Advanced |
| macOS TCC bypass / malicious `.pkg` | Deepen macOS beyond the stealer | Intermediate |
| Email bombing → help-desk social-eng chain | Modern ransomware precursor | Intermediate |
| OT/ICS or IoT anomaly | Entirely new estate | Advanced |
| Deepfake / BEC voice-clone wire fraud | Emerging finance threat | Intermediate |

**Net position:** 61 scenarios, all 14 MITRE tactics well-represented, 30+ data sources exercised with authentic vendor fields, a smooth difficulty curve, and a benign control in every new scenario to teach "scary ≠ malicious." The existing field-reference library already supports every recommended future source, so further growth is content-authoring, not new infrastructure.
