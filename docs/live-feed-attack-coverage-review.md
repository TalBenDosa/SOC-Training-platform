# Live Feed — Attack Coverage Review

_Reviewer: the live-feed scenario author. Date: 2026-08. Method: full inventory of `attackStories.ts` (the story registry that drives the dashboard) cross-referenced against the 2025–2026 threat landscape (DBIR 2025, CrowdStrike/Mandiant/CISA reporting)._

The live dashboard picks **one 10-event attack story per session per company** and injects it, in order, among benign noise. The story's MITRE techniques are the incident-report grader's ground truth. So "what attacks exist" = the story registry. This review asks: **does that registry teach what a real SOC analyst actually sees in 2025–2026?**

---

## 1. What exists today — 62 stories

| Tier | Count | What's in it |
|------|-------|--------------|
| **Foundation** (easy) | 18 | Single-host, single-user initial-access & commodity malware: phishing-malware, USB, browser-extension, tech-support scam, cracked software, malicious macro, brute-force (single acct), Okta password burst, GWS phishing attachment, fake browser update, trojanized keylogger, bundled cryptominer, **SEO-poisoned installer, ISO/MotW smuggling, drive-by miner, ClickFix fake-CAPTCHA, clipboard clipper, scheduled-task persistence** |
| **Core** (medium) | 24 | Insider, impossible travel (×2), rogue admin, + **20 generic per-company "chain-a/b/c/d"** (5 companies × 4) |
| **Advanced** (hard) | 20 | phishing→exfil, BEC (mailbox rule), ransomware, OAuth consent, cloud crypto-mining, DCSync, supply-chain, MFA fatigue, AS-REP roasting, NTLM relay, K8s pod escape, kerberoasting, DNS tunnelling, LOLBins, ESXi ransomware, webshell RCE, Linux cryptominer, AiTM token theft, cred-stuffing |

**Tactic coverage (by story count):** Initial Access 17, Credential Access 15, Execution 14, Persistence 10, Collection 8, Defense Evasion 7, C2 7, Discovery 6, Impact 6, Exfiltration 5, **Lateral Movement 3, Privilege Escalation 1, Reconnaissance 1**.

**Detection sources used:** edr (44), firewall (33), o365 (19), ad (17), siem (15), cloudtrail (14), okta (10), proxy (9), plus specialised (waf, db_monitor, k8s_audit, linux_audit, dlp, ueba, dns, sysmon, iam, vpn, email_gateway, gws, threat_intel, av).

**Verdict:** initial-access and identity/AD coverage is genuinely strong and — after this quarter's foundation additions — current. The gaps are (a) the **middle-to-late kill chain** (privesc, lateral movement, exfil-as-the-objective) and (b) **four of the biggest real-world 2025 attack shapes**, which are absent.

---

## 2. Guiding questions I asked myself

1. **If I printed the DBIR 2025 top initial-access vectors, does the feed teach each one?** Credentials ✅, phishing ✅, **vulnerability/edge-device exploitation ❌** (the #2 vector, 20% of breaches — not represented).
2. **Would an analyst trained _only_ on this feed recognise a Scattered Spider intrusion** (help-desk call → MFA reset → SSO/VDI takeover)? **No** — the defining identity attack of 2024–2025 isn't here.
3. **Does the ransomware content teach the 2021 model or the 2025 model?** The **2021 model** (encrypt-and-extort). The 2025 model is **exfiltration-first, encryption-optional** — and it's the harder, more common one to detect.
4. **Where does a real Tier-2 analyst spend the day** — scoping lateral movement, proving privilege escalation, tracing exfil — **and does the feed exercise those?** Only thinly (3 lateral, 1 privesc stories).
5. **Is there a signature-blind attack at every tier** (business-logic, low-and-slow, living-off-the-land) so students learn detection isn't a red alert? Partly (LOLBins, insider) — could be stronger.
6. **Does each company's feed reflect its industry's real threat model?** Under-used — the 20 core "chain-a/b/c/d" stories are generic, not industry-shaped (healthcare/finance/logistics/SaaS).
7. **For every attack, is there a plausible benign twin** the same session (a hard false positive)? This is a benign-side question the feed handles via FP decoys — worth auditing per tier separately.
8. **Is the newest attack content within ~12 months of the real campaign it mirrors?** Foundation tier yes (ClickFix etc.); the core generic chains, no.

---

## 3. What we're missing — the four big 2025–2026 gaps (grounded)

### GAP 1 — Infostealer → session/credential theft (the #1 real credential source)
The 2025 DBIR found **54% of ransomware victims had their credentials in an infostealer log first**, and infostealer logs held company creds on **30% of managed and 46% of unmanaged devices**. Infostealers (Lumma, RedLine, Vidar, StealC) are _the_ dominant way credentials enter the criminal supply chain. We have credential *attacks* (spray/stuffing/AiTM) but **no story where an infostealer harvests browser-saved passwords + session cookies**, the cookie is replayed to bypass MFA, and the account is taken over. This is the single highest-value gap — it's the front door to almost everything else. _(clipboard-clipper is adjacent but is a clipper, not a stealer.)_

### GAP 2 — Edge-device / VPN exploitation (DBIR's #2 initial-access vector)
Exploitation of edge/VPN devices grew **~8× year-over-year** and is now the **dominant initial-access vector for ransomware operators** — Ivanti (CVE-2025-22457, UNC5221), Fortinet (symlink persistence surviving the patch), Citrix, Palo Alto, Check Point. **VPN compromise was the confirmed entry path in 73% of network intrusions.** Every company in the sim has `firewall`/`vpn` sources — yet there is **no CVE-exploitation-of-the-edge story**. `webshell-rce` covers a web app, not the perimeter appliance. This is a glaring omission given how real it is.

### GAP 3 — Exfiltration-first ("encryption-optional") extortion
By Q3 2025, **96% of ransomware attacks involved data exfiltration**, exfil-**only** attacks rose 23–450%, and encryption appeared in **only 50%** of attacks (a six-year low). Cl0p (Cleo/MOVEit file-transfer mass theft) and newer crews extort with **no encryption at all**. Our three ransomware stories (`ransomware`, `esxi-ransomware`, LockBit) all teach *encryption*. We are missing the dominant modern shape: **mass file staging → rclone/MEGA/S3 exfil → extortion, no encryptor**. This is also *harder* to detect (no dramatic file-rename storm), so it's exactly the Tier-2 skill worth teaching.

### GAP 4 — Help-desk social engineering / MFA-reset (Scattered Spider)
Help-desk voice phishing was used in **almost every observed 2025 Scattered Spider incident** to compromise Entra ID / SSO / VDI — impersonate an employee, get the help desk to reset the password + MFA, enrol an attacker device, walk in. Plus **SIM-swap** and **MFA push-bombing**. We have `mfa-fatigue` and `aitm-token-theft`, but **not the help-desk/identity-reset chain** — the defining enterprise-identity attack of the era (MGM, Caesars, Okta). It's detectable via the ITSM ticket + the new-device MFA enrolment + the anomalous SSO logon, so it's very teachable.

### Secondary gaps
- **BYOVD / EDR tampering** — the near-universal ransomware precursor (load a vulnerable driver, kill the EDR). No story treats "the EDR went quiet" as the signal.
- **Cloud data theft** — leaked IAM key / secret-in-CI → S3/Blob bulk download. We have cloud crypto-mining and K8s escape, but not *data theft from cloud storage*.
- **File-transfer appliance mass-exfil (Cl0p/MOVEit/Cleo)** — overlaps GAP 2+3.
- **Quishing (QR-code phishing) & callback/BazarCall phishing** — the 2024–2025 phishing evolution; our phishing is attachment/link only.
- **Privilege escalation as a first-class story** — token theft, UAC bypass, GPO abuse, cloud role-assignment escalation.

---

## 4. What should be added — prioritised

### P0 — the four big-gap stories (build first)
| Story | Tier | Sources | Core techniques |
|-------|------|---------|-----------------|
| **infostealer-session-theft** | core | edr, o365/okta, proxy | T1555.003 (browser creds), T1539 (steal cookie), T1550.004 (web session cookie replay), account takeover |
| **edge-vpn-cve-exploit** | advanced | firewall/vpn, edr, siem | T1190 (exploit public-facing app), T1133 (external remote services), post-exploit foothold + config/cred theft |
| **exfil-first-extortion** | advanced | edr, proxy, dlp, cloudtrail | T1074 (staging), T1567.002 (exfil to cloud/rclone), T1486 *optional/absent*, extortion — the "no encryptor" case |
| **helpdesk-mfa-reset** | core | ITSM/soar, o365/okta (Entra), edr | T1656 (impersonation), T1621 (MFA request generation), T1098.005 (device registration), anomalous SSO |

### P1 — round out the kill chain + high-value modern TTPs
- **byovd-edr-kill** (advanced): T1068 vulnerable driver + T1562.001 disable security tools — "the sensor went silent."
- **cloud-data-theft** (advanced): leaked key / secret-in-CI → T1552.001/.004 → T1530 bulk S3/Blob download.
- **lateral-movement-psexec** (core): a *dedicated* SMB/PsExec + Pass-the-Hash movement story (4624 type 3, 7045, admin$), because lateral movement is under-taught (3 stories).
- **privesc-token-theft** (core): T1134 token manipulation / T1548 UAC bypass — privesc is nearly absent (1 story).

### P2 — freshness & breadth
- **quishing** (foundation) and **callback-phishing/BazarCall** (foundation): phishing-vector variety.
- **Industry-shaped core stories** — replace ~4 of the generic `*-chain-*` with named, industry-true scenarios: medcore→EMR/medical-device data theft; quantumbank→wire-transfer/SWIFT fraud; globallogis→OT/logistics disruption or GPS spoofing; rocketstack→source-code/customer-data theft via CI.

---

## 5. How to improve the existing

1. **Modernise the ransomware trio.** Make `ransomware`/`esxi-ransomware` *double-extortion* (exfil **before** encrypt, so students see the staging + upload, not just the file-rename storm). Add the exfil-first variant as its own story (P0 above).
2. **Rework the 20 generic `*-chain-a/b/c/d` core stories.** In the inventory, most carry **no `mitre_tactic` tags** and read as generic filler — they're the weakest content in the registry. Either (a) tag them with real tactics and sharpen each into a distinct, current TTP, or (b) retire the weakest and replace with the P0/P1 named scenarios. This is the biggest single quality lever in the core tier.
3. **Rebalance tactics toward the middle of the kill chain.** Add Lateral Movement, Privilege Escalation, and Exfiltration-as-objective stories (P0/P1) so a session can require *scoping* and *tracing*, not just *spotting the initial alert* — that's where Tier-2 competence actually lives.
4. **Diversify detection sources.** Bring NDR/Zeek, ITDR, CASB, and email-security-gateway signals into more stories; several tactics are only ever shown through EDR+firewall, which under-trains multi-source correlation.
5. **Add a "benign twin" per new attack.** For each new attack story, ensure a plausible benign event exists in the same pool that shares surface features (e.g. edge-VPN exploit vs. a legitimate VPN firmware update) so students practise the true-positive/false-positive call, not pattern-matching.
6. **Set a freshness cadence.** Tag each story with the real campaign/CVE year it mirrors; review the registry quarterly and retire/refresh anything > 18 months behind the live threatscape. (The `soc-realism-threatscape` agent can feed this.)

---

## 6. One-paragraph bottom line

The feed's **initial-access and identity/AD coverage is strong and current**; its weaknesses are the **middle-to-late kill chain** (privesc, lateral movement, exfil-as-goal) and **four attack shapes that dominate real 2025–2026 SOC work but are absent**: infostealer-driven session theft, edge/VPN CVE exploitation, exfiltration-first extortion, and help-desk MFA-reset (Scattered Spider). Building those four (P0) and modernising the ransomware + generic-chain content would move the feed from "teaches the textbook" to "teaches this year's SOC."

---

### Sources
- [Verizon 2025 DBIR — credentials #1, vuln-exploitation #2, ransomware 44%](https://www.verizon.com/business/resources/articles/credential-stuffing-attacks-2025-dbir-research/) · [SpyCloud breakdown](https://spycloud.com/blog/verizon-2025-data-breach-report-insights/) · [Descope: credentials still #1](https://www.descope.com/blog/post/dbir-2025)
- [Scattered Spider help-desk TTPs (Push Security)](https://pushsecurity.com/blog/scattered-spider-defending-against-help-desk-scams) · [ReliaQuest](https://reliaquest.com/blog/scattered-spider-cyber-attacks-using-phishing-social-engineering-2025/) · [CrowdStrike](https://www.crowdstrike.com/en-us/blog/crowdstrike-services-observes-scattered-spider-escalate-attacks/) · [MITRE ATT&CK G1015](https://attack.mitre.org/groups/G1015/)
- [Exfiltration-first extortion / encryption-optional (Halcyon)](https://www.halcyon.ai/blog/ransomware-data-exfiltration-encryption-optional) · [Morphisec](https://www.morphisec.com/blog/ransomware-without-encryption-why-pure-exfiltration-attacks-are-surging-and-why-theyre-so-hard-to-catch/) · [Analyst1](https://analyst1.com/ransomware-extortion-activity/)
- [Edge/VPN device exploitation surge (CyberScoop/Ivanti)](https://cyberscoop.com/ivanti-exploited-vulnerabilities-network-edge-devices-kev-list/) · [Ransomware gangs target Palo Alto/Fortinet/Citrix/Check Point VPNs](https://cybersecuritynews.com/ransomware-gangs-attack-vpn/) · [Picus: UNC5221 CVE-2025-22457](https://www.picussecurity.com/resource/blog/unc5221-cve-2025-22457-ivanti-connect-secure)
