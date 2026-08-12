# HACK THE SOC — סילבוס מלא של הפלטפורמה

> מסמך זה נוצר אוטומטית מתוך קוד המקור החי של הפלטפורמה (לא מתוכנן/מסמך ישן) — `src/data/roomsMeta.ts`, `src/lib/quizzes/*.ts`, `src/lib/sim/scenarios.ts`, `src/lib/sim/scenario-packs/*.ts`, `src/lib/edr/investigations.ts`. עודכן 2026-08-12.

## איך הלמידה בנויה — 4 שכבות

| שכבה | מה זה | איפה |
|---|---|---|
| **1. תיאוריה** | חדרי למידה (Learning Rooms) — קריאה + משימות אינטראקטיביות מדורגות (question / log_analysis / analyst_choice / matching / ordering / query_fill / flag) | `/rooms` |
| **2. מבחן ידע** | שאלוני MCQ עצמאיים לחיזוק אוצר מילים ומושגים | `/quizzes` |
| **3. תרגול חי** | Dashboard SOC חי — פיד לוגים אמיתי, תקיפה מוסתרת אחת בכל פעם, כתיבת דו״ח אירוע (rubric דטרמיניסטי, ציון עובר 60/100) | `/dashboard` |
| **4. חקירת Endpoint** | קונסולת EDR — נפתחת רק מתוך משמרת פעילה, מציגה את עץ התהליכים האמיתי של התקיפה שרצה בפיד | נפתח מתוך `/dashboard` |
| **תרגול נוסף** | תרחישי חקירה עצמאיים (Scenarios) — לוגים + שאלות פתוחות עם ניקוד | `/scenarios` |

---

## חלק א׳ — חדרי למידה (Learning Rooms): 88 חדרים ב-13 קטגוריות

מקרא רמת קושי: 🟢 beginner · 🟡 intermediate · 🔴 advanced

### Foundations — יסודות (4)
- 🟢 Introduction to Cybersecurity
- 🟢 Encoding, Encryption & Hashing — What They Actually Are
- 🟢 Timestamps, Timezones & Building a Timeline
- 🟢 Security Products: What Each One Sees and What It Does

### Network Security — אבטחת רשת (12)
- 🟢 Networking Fundamentals
- 🟢 Common Network Protocols
- 🟢 Firewall & Network Security
- 🟡 Network Protocols Deep Dive
- 🟡 Firewalls: From Packet Filter to NGFW
- 🟡 Network Access Control: Zero Trust at the Port
- 🔴 TCP/IP Internals for Analysts
- 🔴 DNS Internals, Tunneling & Abuse
- 🔴 TLS & Encrypted Traffic Analysis
- 🔴 Windows Protocols & Lateral Movement
- 🔴 Email Protocols & Header Forensics
- 🔴 Tunneling, Proxies & C2 Channels

### Endpoint Security — אבטחת קצה (10)
- 🟢 Windows Fundamentals for SOC Analysts
- 🟢 Linux Fundamentals for SOC Analysts
- 🟢 Endpoint Security Fundamentals
- 🟡 Microsoft Defender XDR
- 🟡 CrowdStrike Falcon
- 🟡 SentinelOne Singularity
- 🟡 Antivirus vs EDR vs XDR: Endpoint Security Evolution
- 🟡 Persistence: How Attackers Survive a Reboot
- 🔴 Windows Privilege Escalation & UAC Bypass
- 🔴 Investigating an EDR Detection — End to End

### SIEM (8)
- 🟢 Log Management Fundamentals
- 🟡 SIEM Fundamentals
- 🟡 Wazuh SIEM Fundamentals
- 🟡 Microsoft Sentinel Fundamentals
- 🟡 Writing Detection Rules & Tuning
- 🟡 Log Sources & SIEM Integration
- 🔴 Detection Engineering Fundamentals
- 🔴 Use Case Development

### Log Analysis — ניתוח לוגים (5)
- 🟢 Anatomy of a Log Entry
- 🟡 Windows Event Logs
- 🟡 Linux Log Analysis
- 🟡 VPN Monitoring
- 🟡 Firewall Log Analysis

### Threat Detection — זיהוי איומים (9)
- 🟢 Cyber Kill Chain
- 🟡 Email Security
- 🟡 Phishing Analysis
- 🟡 DNS Investigation
- 🟡 Authentication & Identity Monitoring
- 🟡 Credential Attacks in the Logs
- 🔴 Privileged Access Monitoring
- 🔴 Unusual Attacks and Edge-Case Use Cases
- 🔴 Tracing Lateral Movement

### Threat Intelligence — מודיעין איומים (7)
- 🟢 MITRE ATT&CK Framework
- 🟢 Malware Types and What Each One Wants
- 🟡 Malware Analysis Fundamentals
- 🟡 IOC Analysis & Threat Pivoting
- 🟡 Threat Intelligence Fundamentals
- 🟡 OSINT Fundamentals
- 🔴 Threat Hunting Fundamentals

### Identity — זהות (6)
- 🟢 Identity Basics: Credentials, Sessions & MFA
- 🟡 Active Directory Fundamentals
- 🟡 Entra ID (Azure AD) Security
- 🟡 Remote Email Collection & Malicious Inbox Rules
- 🟡 Device Registration Abuse & MFA Persistence
- 🔴 Kerberos & Windows Authentication Deep Dive

### Cloud Security — אבטחת ענן (8)
- 🟡 Microsoft 365 Security
- 🟡 Exchange Online Security
- 🟡 SharePoint & Teams Security Monitoring
- 🟡 AWS Security for SOC Analysts
- 🟡 Google Cloud Platform (GCP) Security Essentials
- 🟡 Azure IaaS Security for SOC Analysts
- 🔴 Cloud Security Monitoring
- 🔴 Kubernetes & Container Security

### Incident Response — תגובה לאירועים (5)
- 🟡 Incident Response Methodology
- 🟡 Investigation Methodology
- 🟡 Running the Playbook — and Knowing When to Stop
- 🟡 How to Investigate an Alert — The 7-Step Analyst Workflow
- 🟡 Writing the Incident Report — Documentation That Holds Up

### SOC Operations — תפעול SOC (8)
- 🟢 SOC Structure & Analyst Roles
- 🟢 The Analyst Mindset: How to Think and Ask the Right Questions
- 🟢 Asset Context: Why the Same Alert Is Not the Same Alert
- 🟡 Alert Triage
- 🟡 Reporting & Documentation
- 🟡 Customer Communication
- 🟡 Escalation Procedures
- 🟡 SOAR and Security Automation

### Forensics — פורנזיקה (2)
- 🟡 Digital Forensics Basics
- 🔴 Memory & Disk Forensics for Analysts

### Application Security — אבטחת אפליקציות (2)
- 🟢 How Web Applications Work — and How They Break
- 🔴 Reading a Web Attack in the Logs

### Data Security — אבטחת מידע (1)
- 🟡 Data Loss Prevention (DLP) for SOC Analysts

### Vulnerability Management — ניהול חולשות (1)
- 🟡 Vulnerability Management for SOC Analysts

---

## חלק ב׳ — שאלונים (Quizzes): 20 שאלונים

### Foundations
- 🟢 Cybersecurity Foundations
- 🟢 Security Models & Core Principles — CIA triad, least privilege, Zero Trust, AAA, defense in depth

### Network
- 🟢 Protocols & Ports for Analysts — SMB, RDP, Kerberos, DNS, SSH, LDAP, SMTP, WinRM
- 🟢 Network Security & Firewalls

### SOC Fundamentals
- 🟢 Security Tools & the Defensive Stack — FW, IDS/IPS, AV/EDR, SIEM, SOAR, WAF, DLP, VPN, NAC, XDR
- 🟢 SOC Operations & Alert Triage
- 🟡 Incident Response
- 🟡 Log Analysis & SIEM

### Threat Framework
- 🟢 Attack Types & Threat Actors — phishing/whaling, ransomware, APT, insider, DDoS, supply chain, MITM
- 🟡 MITRE ATT&CK Framework

### Endpoint Security
- 🟡 Endpoint Security & EDR

### Identity
- 🔴 Active Directory & Kerberos Security

### Threat Detection
- 🟡 Email Security & Phishing Analysis

### Threat Intelligence
- 🔴 Threat Intelligence

### Cloud Security
- 🔴 Cloud & Identity Security

### SIEM
- 🔴 Detection Engineering & Rule Writing

### Data Security
- 🟡 Data Loss Prevention (DLP) Triage

### Application Security
- 🔴 Web Application Attacks & WAF

### Forensics
- 🔴 Digital Forensics & Evidence Handling

### Vulnerability Management
- 🟡 Vulnerability Management for SOC

---

## חלק ג׳ — תרגול חי (SOC Dashboard)

5 "חברות" (סביבות SOC נפרדות, כל אחת עם ארכיטקטורת SIEM שונה):

| חברה | תחום | ארכיטקטורה |
|---|---|---|
| NexaCorp Financial Ltd. | פיננסים | AD / O365 / EDR מלא |
| MedCore Regional Hospital | בריאות | EMR, PACS, VPN |
| GlobalLogis Distribution SA | לוגיסטיקה | Linux, WMS, ERP |
| RocketStack Technologies | הייטק/SaaS | Okta, AWS, K8s, GWS |
| QuantumBank Corp. | בנקאות | CyberArk, SWIFT, Cobalt Strike playbooks |

**מאגר סיפורי תקיפה** (~35+ תרחישים, נבחרים אקראית לפי רמת קושי וארכיטקטורת החברה):
- **Foundation** (מתחילים): phishing-malware, usb-malware, browser-extension, tech-support-scam, cracked-software, malicious-macro, bruteforce-single, okta-password-burst, gws-phish-attachment, fake-browser-update, trojanized-keylogger, bundled-cryptominer
- **Core** (בינוני): insider-threat, impossible-travel, impossible-travel-basic, rogue-admin-account
- **Advanced** (מתקדם): BEC, ransomware, OAuth abuse, cryptomining, DCSync, supply-chain, MFA fatigue, AS-REP roasting, NTLM relay, K8s pod escape, OAuth consent phishing, Kerberoasting, DNS tunneling, LOLBins, ESXi ransomware, web-shell RCE, Linux SSH cryptominer, AiTM token theft
- **שרשראות ייעודיות לכל חברה** (4 לכל אחת, 20 סה"כ): למשל אצל NexaCorp — Phishing→Key Vault Exfil, BEC השתלטות מנכ״ל, גניבת מודלים ע"י עובד; אצל QuantumBank — MFA Fatigue→Cobalt Strike→Core Banking Takeover

**מנגנון:** תקיפה **אחת** בכל פעם, מתגלה בהדרגה (2-3 דקות עד השלב הראשון, 2-4 דקות בין שלבים), חייבת דו״ח עובר (≥60/100) לפני שהבאה נדרכת. פיד לא רץ בלי Start Training.

---

## חלק ד׳ — קונסולת EDR (Endpoint Investigation)

נגישה **רק** מתוך משמרת חיה ב-Dashboard ("Investigate in EDR"). 2 מסלולים:
1. **חי** — נוצר אוטומטית מהתקיפה שרצה כרגע בפיד (עץ תהליכים אמיתי מהטלמטריה)
2. **5 מקרים סטטיים** מוכנים מראש:
   - Phishing beacon (Agent Tesla) — FIN-WS-07
   - PsExec שפיר (False Positive) — RES-SRV-02
   - LockBit 3.0 Ransomware — FS-SRV-04
   - גניבת אישורים / Mimikatz (LSASS dump) — IT-ADM-02
   - Linux Cryptominer (XMRig מוסווה כ-kworker) — prod-web-03

---

## חלק ה׳ — תרחישי חקירה עצמאיים (Scenarios)

**14 חבילות scenario-pack** מלוטשות-יד, מדויקות-ספק:
aitmTokenTheft · backupFalsePositive · bruteForceSingleAccount · bundledCryptominer · esxiRansomware · fakeBrowserUpdate · gwsPhishingAttachment · impossibleTravelBasic · linuxSshCryptominer · oktaPasswordBurst · rogueAdminAccount · softwareInstallFalsePositive · trojanizedInstallerKeylogger · webShellRce

**+21 תרחישי בסיס** נוספים ב-`scenarios.ts` (משמשים גם את ה-Dashboard וגם כתרגילים עצמאיים): BEC, Ransomware, OAuth abuse, Insider Threat, Impossible Travel, Phishing→Malware, USB Malware, Browser Extension Malware, Tech Support Scam, Cracked Software, Malicious Macro, Kerberoasting, DNS Tunneling, LOLBins, Cloud Cryptomining, DCSync, Supply Chain, MFA Fatigue, AS-REP Roasting, NTLM Relay, OAuth Consent Phishing.

כל תרחיש: briefing → לוגים → שאלות פתוחות/MCQ מדורגות → debrief מלא (narrative + killchain + IOCs).

---

## סיכום מספרים

| רכיב | כמות |
|---|---|
| חדרי למידה | 88 |
| שאלונים | 20 (≈250 שאלות) |
| חברות Dashboard | 5 |
| סיפורי תקיפה חיים | ~35+ (כולל שרשראות ייעודיות לחברה) |
| קונסולת EDR — מקרים סטטיים | 5 (+ יצירה חיה בלתי מוגבלת) |
| חבילות תרחישים עצמאיות | 14 + 21 תרחישי בסיס |

---

## פערים ידועים (עדיין לא בפלטפורמה)

מתועד ב-backlog הפנימי (SEV-3.x) ובמחקר הריאליזם:
- **Capstone exam + תעודה** ("Final Shift" — סימולציית משמרת אחת עם 10-15 התראות, החלטת Close/Investigate/Escalate/Report)
- **Regex + כתיבת שאילתות SIEM (KQL/SPL) מאפס** — חדר ייעודי
- **Sigma rules + YARA rules** — כתיבת חתימות זיהוי
- **PowerShell להגנה + Python לאנליסט** — אוטומציה והעשרה
- **ניתוח PCAP מעשי** (Wireshark/Zeek hands-on)
- **חקירת IR בענן** (CloudTrail-driven incident, לא רק ניטור)
- 16 טכניקות MITRE שמופיעות בתרגול החי אך אין להן חדר תיאוריה תואם
