# HACK THE SOC — סילבוס מפורט: כל שיעור, כל תת-נושא (Learning Path)

> נוצר אוטומטית מכותרות ה-sections האמיתיות בתוך `BUILTIN_LESSONS` (`src/data/builtinLessons.ts`, מרכיב את `pathLessons-a..g.ts` + `attackTypeLessons.ts` + `playbookLessons.ts`). כל שורה כאן קיימת בפועל בפלטפורמה. משלים את [PLATFORM-SYLLABUS-DETAILED.md](PLATFORM-SYLLABUS-DETAILED.md) (חדרים). עודכן 2026-08-12.

**הבדל מהותי מהחדרים:** ה-Learning Path הוא 24 "קפסולות עומק" ארוכות (כ-5 סעיפים עשירים לכל שיעור, עם דוגמת קוד/לוג ו-quiz בסוף) שבנויות כמסלול לינארי אחד מ-0 ידע ועד חוקר אירועים — לא ספריית נושאים כמו החדרים. סדר ההופעה במסלול קבוע ומכוון פדגוגית (ר' `builtinLessons.ts`).

מקרא: 🟢 beginner · 🟡 intermediate · 🔴 advanced

---

## סדר המסלול (24 שיעורים, לינארי)

1. 🟢 What a SOC Is and What a Security Analyst Actually Does All Day
2. 🟢 How Computers and Networks Actually Work: A Ground-Up Primer
3. 🟢 What a Log Is, Where Logs Come From, and How to Read One
4. 🟡 The Windows You'll Investigate: Processes, Services, Registry, Accounts
5. 🟡 Windows Event Log Analysis (Security + Sysmon Event IDs)
6. 🟡 Authentication and Identity: Kerberos, NTLM
7. 🟡 Linux for SOC Analysts
8. 🟡 SIEM Fundamentals: How an Alert Is Born and How to Triage It
9. 🟡 EDR Explained
10. 🟡 Protocols and Communication Standards for Threat Detection
11. 🟡 The Attacker's Map: MITRE ATT&CK and the Cyber Kill Chain
12. 🟢 Phishing Email Analysis and Investigation Workflow
13. 🟡 Malware for Analysts: Families, Behaviors, Triage
14. 🔴 Command-and-Control and Data Exfiltration
15. 🟡 The Analyst Mindset: Hypothesis-Driven Investigation
16. 🔴 The Investigation Workflow: Alert to Root Cause and Containment
17. 🟡 Writing the Incident Report
18-23. **סדרת סוגי-תקיפה** (ר' למטה)
24. 🟢 SOC Playbooks — Following the Steps, and Knowing When Not To

---

## שיעורי הליבה (Core) — לפי נושא

**🟢 What a SOC Is and What a Security Analyst Actually Does All Day** (SOC Fundamentals)
- What a Security Operations Center Actually Is
- The Analyst Tiers and the Alert Lifecycle
- A Day on Shift: The Queue and the Benign / Suspicious / Malicious Decision
- The Questions a Good Analyst Asks Every Single Alert
- From Alert to Handoff: Documentation, Escalation, and Why It Matters

**🟢 How Computers and Networks Actually Work: A Ground-Up Primer** (Networking Fundamentals)
- Hosts, IP Addresses, and Ports
- Public vs Private IP, NAT, and Why It Shows Up in Your Logs
- TCP vs UDP and the Life of a Connection
- The Network Layers in Plain Language
- Reading a Connection Log: What to Look At and What to Ask

**🟢 What a Log Is, Where Logs Come From, and How to Read One** (Log Analysis)
- What a Log Line Actually Is
- Where Logs Come From
- Raw vs Parsed, Structured vs Unstructured
- How to Read an Unfamiliar Log
- From Log to Question: Turning Fields Into Investigation Leads

**🟡 The Windows You'll Investigate: Processes, Services, the Registry, and Accounts** (Windows Fundamentals)
- Processes and the Parent-Child Tree
- Services, Scheduled Tasks, and How Windows Starts Programs
- The Registry and Autoruns
- Accounts, Privileges, and Integrity Levels
- What Normal Looks Like — and the LOLBins That Break It

**🟡 Windows Event Log Analysis for Threat Detection** (Windows Forensics)
- Critical Security Event IDs Every Analyst Must Know
- Sysmon Event IDs for Deep Endpoint Visibility
- Detecting Privilege Escalation and Valid-Account Abuse (T1078)
- Pass-the-Hash, Golden Ticket, and Kerberos Attack Detection
- Building a Cohesive Windows Detection Strategy

**🟡 Authentication and Identity: How Logons, Kerberos, and NTLM Really Work** (Active Directory)
- What Active Directory Is
- How a Logon Really Works: Kerberos
- NTLM and Why It's Still Around
- Logon Types and Reading Authentication Logs
- How Attackers Abuse Authentication — and What to Ask

**🟡 Linux for SOC Analysts: Files, Users, Processes, and the Logs That Matter**
- The Linux Filesystem and Where Things Live
- Users, sudo, and Privilege
- Processes, Shells, and Persistence
- The Logs That Matter: syslog, auth.log, and auditd
- Reading Linux Attack Artifacts — What to Ask

**🟡 SIEM Fundamentals: How an Alert Is Born and How to Triage It** ⭐
- What a SIEM Is and the Ingestion Pipeline
- How an Alert Is Born: Detection Rules and Correlation
- True Positive, False Positive, and the Triage Decision
- **Querying for Triage: KQL and SPL Basics** ← כבר קיים כאן ברמת שיעור!
- Enrichment and Escalation: Turning an Alert Into a Verdict

**🟡 EDR Explained: What Endpoint Detection Sees and How to Read It**
- EDR vs Antivirus: What Changed
- The Telemetry EDR Collects
- Detections vs Preventions
- Reading an EDR Detection Across Vendors
- Response Actions and the Questions Before You Isolate

**🟡 Protocols and Communication Standards Every SOC Analyst Must Know**
- TCP/IP Stack Fundamentals for Threat Detection
- DNS Abuse and Tunneling Detection (T1071.004)
- HTTP and HTTPS Traffic Analysis for C2 Detection
- SMB Protocol and Lateral Movement Detection (T1021.002)
- Building a Cross-Protocol Hunting Methodology

**🟡 The Attacker's Map: MITRE ATT&CK and the Cyber Kill Chain**
- The Cyber Kill Chain: The Stages of an Intrusion
- MITRE ATT&CK: Tactics, Techniques, and Procedures
- Using ATT&CK During Triage
- From Technique to Hunt
- Why Mapping Matters for Reporting and Coverage

**🟢 Phishing Email Analysis and Investigation Workflow (Microsoft Defender XDR)**
- Reading Email Headers Like a Forensic Investigator
- SPF, DKIM, and DMARC Authentication Deep Dive
- Attachment Sandboxing and Malicious Payload Analysis
- URL Detonation and Credential Harvesting Page Analysis
- Business Email Compromise and End-to-End Investigation

**🟡 Malware for Analysts: Families, Behaviors, and Triage Without Reverse Engineering**
- The Malware Families You'll Meet
- Behavior Over Signatures: What Malware Does on a Host
- Hashes, Sandboxes, and Reputation
- Extracting and Pivoting on IOCs
- When to Contain, When to Escalate — the Questions

**🔴 Command-and-Control and Data Exfiltration**
- What Command-and-Control Is and Why Attackers Need It
- Beaconing: The Rhythm That Gives C2 Away
- Common C2 Channels and Their Fingerprints
- Staging and Exfiltration: How Data Actually Leaves
- Detecting Exfil: Byte Ratios, Volume, Destinations, and DLP — What to Ask

**🟡 The Analyst Mindset: How to Think, Ask the Right Questions, and Form a Hypothesis**
- Investigation Is Hypothesis-Driven, Not Checkbox-Driven
- The Six Questions: Who, What, When, Where, How, and So-What
- Fact vs Assumption: Anchoring on Evidence
- Baselining: You Cannot Spot Abnormal Without Knowing Normal
- Cognitive Biases and When to Escalate

**🔴 The Investigation Workflow: From Alert to Root Cause and Containment**
- The Lifecycle: Triage, Validate, Scope, Contain, Eradicate, Recover
- Validating the Alert: True Positive or False Positive, Fast
- Scoping: How Far Did It Go?
- Building the Timeline
- Containment and Handoff Decisions — What to Ask Before You Act

**🟡 Writing the Incident Report: Turning an Investigation Into Something Others Can Act On**
- Why the Report Is the Product
- Anatomy of a Good Incident Report
- Writing for Two Audiences: Executives and Responders
- Evidence Discipline: Never Invent, Always Cite
- Common Report Mistakes and a Reusable Template

**🟢 SOC Playbooks — Following the Steps, and Knowing When Not To**
- What a Playbook Is — and What It Is Not
- The Anatomy of a Playbook: Collect, Decide, Act
- Executing One End to End: A Compromised Account
- When to Deviate — and Why Silence Is the Real Failure
- How Playbooks Improve, and What SOAR Should and Should Not Automate

---

## סדרת סוגי-תקיפה (Attack-Type Lessons, 6)

**🟡 Credential Attacks: Brute Force, Spraying, Stuffing and Theft**
- Brute Force: Many Passwords, One Account
- Password Spraying: One Password, Many Accounts (T1110.003)
- Credential Stuffing: The Password Was Never Guessed (T1110.004)
- Credential Theft: No Guessing at All (T1003, T1555)
- MFA, Lockout Policy, and Service Accounts: Where the Controls Hold and Where They Break

**🟡 Lateral Movement: How One Host Becomes the Whole Network**
- Why Attackers Move — and What They're Actually Looking For
- SMB and Admin Shares: The Classic PsExec Pattern (T1021.002)
- RDP, WinRM, and WMI: Interactive and Remote-Execution Movement (T1021.001/.006)
- Pass-the-Hash and Pass-the-Ticket: Moving Without Ever Knowing the Password (T1550.002/.003)
- Detecting the Pattern: Why Who-Talks-to-Whom Beats Any Single Event

**🟡 Web Application Attacks: From Injection to Web Shell**
- How a Web Request Works, and Where Each Attack Fits
- SQL Injection: Union, Blind, and Time-Based
- Cross-Site Scripting: Reflected, Stored, and DOM-Based
- Path Traversal, LFI, and SSRF: When the Server Fetches on the Attacker's Behalf
- Reading Status Codes as Evidence, and File Upload to Web Shell (T1505.003, T1059)

**🟢 Social Engineering: Attacking the Human Layer**
- The Psychology: Authority, Urgency, Reciprocity, and Fear
- Spear Phishing and Vishing: Same Manipulation, Different Channel (T1566.001/.002, T1598)
- The Scattered Spider Playbook: Help-Desk Impersonation and MFA Reset
- Smishing and QR-Code Phishing (Quishing)
- MFA Fatigue and Pretexting: Manipulation, Not a Technical Exploit (T1621)

**🔴 The Ransomware Lifecycle: From Access to Extortion**
- Initial Access: Phishing, Exposed Services, and Exploited Edge Devices
- Dwell, Discovery, and Credential Access
- Lateral Movement Toward Domain Admin
- The Pre-Encryption Window: Your Last Real Chance (T1490, T1562.001, T1070.001)
- Encryption, Double Extortion, and the RaaS Affiliate Model

**🟡 Insider Threat and Data Exfiltration**
- Three Different Problems Wearing One Label
- Exfiltration Channels
- What DLP Catches, and What It Structurally Cannot
- Behavioural Indicators and the Pre-Departure Pattern
- The Ethical and Legal Weight of Investigating a Named Employee

---

## תובנות מהמיפוי — רלוונטי לתוכנית א׳ (תוספות לחדרים)

1. **KQL/SPL כבר קיים ברמת שיעור** (`SIEM Fundamentals: How an Alert Is Born`, סעיף "Querying for Triage: KQL and SPL Basics") — אבל **אין חדר מקביל** שמלמד את זה בעומק. כשמוסיפים לחדר SIEM Fundamentals את תת-הנושא, כדאי ליישר קו עם השפה/הדוגמאות שכבר קיימות בשיעור הזה כדי שהמסלול לא יסתור את עצמו.
2. **אין שיעור ל-Cloud** (AWS/Azure/GCP/M365) בכלל ב-Learning Path — כל התוכן הענני נמצא רק בחדרים. פער אמיתי בציר הלינארי.
3. **אין שיעור Malware Analysis בעומק טכני** (Sigma/YARA) — השיעור `Malware for Analysts` נשאר ברמת "hashes, sandboxes, reputation" בלי כתיבת חתימה בפועל — תואם בדיוק לפער שזיהינו בחדרים.
4. **אין תת-נושא PowerShell הגנתי** גם בשיעור Windows Fundamentals (`local-lesson-7`) — רק "LOLBins That Break It" (הצד ההתקפי).
5. **הרשומה של Digital Forensics, Vulnerability Management, DLP, Threat Hunting, OSINT, Application Security** — קיימות כחדרים אך **אין להן שיעור מקביל** ב-Learning Path הלינארי בכלל.
