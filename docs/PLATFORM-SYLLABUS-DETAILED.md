# HACK THE SOC — סילבוס מפורט: כל חדר, כל תת-נושא

> נוצר אוטומטית מה-headings האמיתיים בתוך כל חדר בקוד המקור (`src/data/rooms-batch-*.ts`, דרך `ROOMS`, לא ניחוש). כל שורה כאן היא כותרת reading אמיתית שקיימת בפלטפורמה היום. משלים את [PLATFORM-SYLLABUS.md](PLATFORM-SYLLABUS.md) (רשימת חדרים) ואת [TIER1-TIER2-GAP-BREAKDOWN.md](TIER1-TIER2-GAP-BREAKDOWN.md) (נושאים חדשים מומלצים). עודכן 2026-08-12.

מקרא: 🟢 beginner · 🟡 intermediate · 🔴 advanced

---

## Foundations — יסודות (4 חדרים)

**🟢 Introduction to Cybersecurity**
- What Is Cybersecurity?
- The CIA Triad: The Three Pillars of Security
- Real-World Impact & Starting Your Cybersecurity Career

**🟢 Encoding, Encryption & Hashing — What They Actually Are**
- Three Different Jobs, Constantly Confused
- Encoding: Base64, Hex, and URL-Encoding — Not Security
- Hashing, Part 1: What It Is, and Why It's One-Way
- Hashing, Part 2: The Properties That Make It Useful
- The Four Things a SOC Analyst Actually Uses Hashing For
- The Critical Limits of a Hash
- Encryption: Reversible — But Only With a Key
- What an Analyst Can — and Can't — See Inside TLS Without Decrypting It

**🟢 Timestamps, Timezones & Building a Timeline**
- Timestamp Formats You'll Actually Meet
- UTC vs Local Time: The Discipline of Stating the Zone
- Clock Skew, NTP, and Why Your Three Sources Disagree
- Building a Timeline: Normalize, Order, and Don't Trust Detection Order
- Practical Traps: DST, No-Year Logs, Duplicate Events, and Timestomping

**🟢 Security Products: What Each One Sees and What It Does**
- The Detection Surface: Every Product Sits Somewhere
- Antivirus and EDR/XDR: On the Host, But Not on Every Host
- If EDR Can't See the Hypervisor, What Can? vCenter and ESXi Logs
- NGFW: Inline, App-Aware, and Blind Once TLS Is On
- IDS vs IPS: The Pair Everyone Confuses
- WAF: In Front of the App, Blocking by Rule
- Secure Web Gateway and Email Security Gateway: Watching What Users Touch
- NDR, DLP, and Identity Protection/CASB: Metadata, Content, and Identity Signals
- SIEM and SOAR: Seeing Only What Reaches Them

---

## Network Security — אבטחת רשת (12 חדרים)

**🟢 Networking Fundamentals**
- What Is a Network? The OSI Model & IP Addressing
- TCP vs UDP, Ports, and the Three-Way Handshake
- Routing, Switching, NAT, and the SOC Analyst Perspective

**🟢 Common Network Protocols**
- HTTP/HTTPS, DNS, and DHCP — The Web's Foundation
- SSH, SMB, RDP, FTP, and Email Protocols
- Protocol Security: Which Protocols Are Dangerous and Why

**🟢 Firewall & Network Security**
- Firewall Types: From Packet Filtering to NGFW
- IDS, IPS, DMZ, Network Segmentation, and WAF
- Reading Firewall Logs: What Every Field Means

**🟡 Network Protocols Deep Dive**
- The OSI Model and TCP/IP: How Network Communication Is Organized
- IP Addressing: How Computers Find Each Other on a Network
- TCP: The Protocol That Guarantees Delivery
- UDP: Speed Without Guarantees
- DNS: The Internet's Phone Book — How Names Become IP Addresses
- HTTP and HTTPS: The Protocol of the Web
- TLS/SSL: How Encryption Protects Data in Transit
- ICMP, ARP, and Other Essential Protocols
- The SOC Analyst Port Reference: 50 Ports You Must Know
- How Attackers Abuse Protocols: C2, DNS Tunneling, and Protocol Attacks

**🟡 Firewalls: From Packet Filter to NGFW**
- What Is a Firewall? History and Purpose
- Generation 1: Stateless Packet Filtering and Access Control Lists
- Generation 2: Stateful Inspection and the Connection Tracking Revolution
- Generation 3: Deep Packet Inspection and Application Awareness
- Next-Generation Firewalls: What NGFW Actually Means
- How Firewall Rules Work: Building and Reading a Rule Base
- Network Zones and DMZ Architecture
- SSL/TLS Inspection: Breaking Encryption to See Inside
- Palo Alto vs FortiGate vs Check Point: Market Leaders Compared
- Reading Firewall Logs in Your SIEM: Field-by-Field Analysis

**🟡 Network Access Control: Zero Trust at the Port**
- What Is NAC and the Problem It Solves
- The Three Components of NAC: Supplicant, Authenticator, Server
- 802.1X: The Authentication Protocol That Powers NAC
- RADIUS: The Authentication Server That Makes the Decision
- Device Posture Assessment: Checking Health Before Granting Full Access
- VLANs and How NAC Uses Them for Segmentation
- Cisco ISE: The Enterprise NAC Standard
- Aruba ClearPass: The Multi-Vendor Alternative
- NAC in Zero Trust Architecture and Cloud Environments
- NAC Bypass Techniques and Detection Strategies

**🔴 TCP/IP Internals for Analysts**
- The TCP Header, Its Flags, and the Full Connection State Machine
- RST vs FIN: Graceful Close, Abrupt Abort, and Injected Resets
- Scan Signatures: SYN, FIN, NULL, XMAS, ACK, and Full-Connect Scans
- Fragmentation, TTL, and Window Size: Fingerprinting the OS Behind an IP
- Reading Flow Records vs. Full Packet Captures
- Retransmissions, Duplicate ACKs, and Spotting Blocked or Beaconing Traffic at Scale

**🔴 DNS Internals, Tunneling & Abuse**
- The Full DNS Resolution Path, End to End
- DNS Record Types Beyond A/AAAA, and Why DoH/DoT Blind Your Monitoring
- DNS Tunneling: How Data Hides Inside Queries, and the Statistics That Reveal It
- DGA Malware vs. Legitimate CDN Randomness: Telling Them Apart
- Fast-Flux DNS and Sinkholes
- The Exact Fields: Sysmon Event 22 (DNS Query) and Zeek dns.log

**🔴 TLS & Encrypted Traffic Analysis**
- The TLS Handshake, Step by Step (TLS 1.2 vs. TLS 1.3)
- SNI — the Last Cleartext Field — and Certificate Chain Validation
- JA3, JA3S, and JARM Fingerprinting
- Detecting C2 Inside TLS Without Decryption
- When TLS Interception Is (and Isn't) Possible
- TLS Version and Cipher Suite Choice as a Fingerprint of the Software Behind a Connection

**🔴 Windows Protocols & Lateral Movement**
- SMB Protocol Internals: Signing, Sessions, and Administrative Shares
- The Kerberos Ticket Flow at the Field Level: AS-REQ, AS-REP, TGS-REQ, TGS-REP
- Kerberoasting, AS-REP Roasting, and Pass-the-Ticket: What Changes at the Wire Level
- NTLM Challenge-Response: Type 1/2/3 Messages, and Why Relay Works
- LDAP Reconnaissance: The Queries BloodHound and Attackers Actually Send
- DCERPC and Named Pipes: The Machinery Behind PsExec, WMI, and Service-Based Lateral Movement

**🔴 Email Protocols & Header Forensics**
- The SMTP Conversation, Step by Step
- Envelope-From vs. Header-From: the Core of Email Spoofing
- Reading the Full Received-Header Chain — Bottom to Top Is Chronological
- SPF Mechanics in Depth: Qualifiers, the 10-Lookup Limit, and Why SPF Can Pass on a Phish
- DKIM Mechanics: Signature Fields, Canonicalization, and Why Forwarding Can Break It
- DMARC Alignment, Policy Enforcement, and ARC

**🔴 Tunneling, Proxies & C2 Channels**
- SSH Port Forwarding: Local, Remote, and Dynamic (SOCKS)
- SOCKS Proxies and Reverse Shells
- ICMP and DNS Tunneling Mechanics, Revisited for Throughput and Detection
- HTTP(S) Beaconing Math: Interval, Jitter, and Statistical Detection
- Living-off-the-Land Tunneling Tools: ngrok, Chisel, and plink
- Putting It Together: A Tunneling Investigation Playbook

---

## Endpoint Security — אבטחת קצה (10 חדרים)

**🟢 Windows Fundamentals for SOC Analysts**
- Windows Architecture, File System, and User Accounts
- The Windows Registry: A SOC Analyst's Map to Persistence
- Processes, PowerShell, LOLBins, and Attacker Techniques

**🟢 Linux Fundamentals for SOC Analysts**
- Linux — The Invisible OS Running the Internet
- Users, File Permissions, and the sudo System
- Processes, Cron Jobs, SSH — Attacker Persistence on Linux

**🟢 Endpoint Security Fundamentals**
- From Antivirus to EDR — The Evolution of Endpoint Security
- EDR Deep Dive — What It Collects and What Analysts Do With It
- How to Read an EDR Alert — A Step-by-Step Approach

**🟡 Microsoft Defender XDR**
- Microsoft Defender XDR — The Unified Security Platform
- Investigating Incidents in Microsoft Defender XDR
- Advanced Hunting with KQL — Proactive Threat Hunting

**🟡 CrowdStrike Falcon**
- What Is CrowdStrike Falcon — and How Does It Work?
- The Falcon Console: Where SOC Analysts Work
- Real Time Response (RTR) and Common Attack Scenarios

**🟡 SentinelOne Singularity**
- SentinelOne Singularity: The Autonomous Security Platform
- The SentinelOne Console: Threats, Investigation, and Response
- SentinelOne XDR and Detecting Ransomware

**🟡 Antivirus vs EDR vs XDR: Endpoint Security Evolution**
- The History of Endpoint Security: From 1987 to Today
- How Traditional Antivirus Signature Detection Works
- Beyond Signatures: Heuristics, Sandboxing, and Machine Learning in AV
- Why AV Is Not Enough: Fileless Malware and Living-Off-the-Land Attacks
- What Is EDR? Endpoint Detection and Response Explained
- How EDR Hooks the Operating System: Kernel Drivers and ETW
- CrowdStrike Falcon: Architecture, Detection, and Log Fields
- SentinelOne: AI-Native Detection and Storyline Technology
- Microsoft Defender XDR: The Microsoft Security Ecosystem
- AV vs EDR vs XDR vs MDR: Complete Comparison and SOC Implications

**🔴 Windows Privilege Escalation & UAC Bypass**
- Integrity Levels: Low, Medium, High, System
- SeDebugPrivilege and Reaching LSASS Memory
- UAC Bypass: The fodhelper / computerdefaults Registry Hijack
- Token Manipulation, SeImpersonatePrivilege, and the Potato Family
- Unquoted Service Paths, Weak Service Permissions, and Reading an Integrity Jump

**🟡 Persistence: How Attackers Survive a Reboot**
- Registry Run Keys and the Startup Folder (T1547.001)
- Scheduled Tasks (T1053.005) and Cron (T1053.003)
- Windows Services (T1543.003)
- BITS Jobs (T1197) and WMI Event Subscriptions
- Cloud-Account and OAuth Persistence (T1136.003)
- Why Persistence Changes the Incident

**🔴 Investigating an EDR Detection — End to End**
- Why the Detection Is the Doorway, Not the Whole Story
- Anatomy of a Detection: The Fields That Actually Carry the Story
- The Investigation Workflow: Six Steps From Detection to Verdict
- Reading the Process Tree: Parents, Children, and the Anomalies That Matter
- Sibling Alerts: Why One Host Rarely Fires Just One Detection
- Severity Reassessment: Why the Tool's Severity Isn't the Analyst's Verdict
- Pivoting and Scoping: Hash Reputation, Network Activity, and the Rest of the Fleet

---

## SIEM (8 חדרים)

**🟢 Log Management Fundamentals**
- What Are Logs? The Digital CCTV of IT Systems
- Log Collection, Normalisation, and the Log Lifecycle
- Log Tampering, Log Retention, and SIEM vs. Log Aggregators

**🟡 SIEM Fundamentals**
- What is a SIEM? Your SOC's Air Traffic Control
- How SIEM Correlation Rules Work
- True Positives, False Positives, and Alert Fatigue

**🟡 Wazuh SIEM Fundamentals**
- Wazuh Architecture — Open-Source SIEM and XDR
- Wazuh Decoders and Rules — How Detection Works
- FIM, SCA, Active Response, and Wazuh Dashboards

**🟡 Microsoft Sentinel Fundamentals**
- Microsoft Sentinel — Cloud-Native SIEM and SOAR
- KQL — Kusto Query Language Basics
- Analytics Rules, Incidents, and SOAR Playbooks

**🟡 Writing Detection Rules & Tuning**
- Detection Engineering: Rule Anatomy & Logic Types
- Sigma Rules: Vendor-Neutral Detection Format
- Alert Tuning: Reducing Noise Without Losing Coverage

**🟡 Log Sources & SIEM Integration**
- Log Sources & Transport Protocols: Where Logs Come From
- Log Collection Agents & Processing Pipelines
- Parsing, Normalization & Integration Challenges

**🔴 Detection Engineering Fundamentals**
- What Detection Engineering Is — Rules That Catch Bad Actors
- Sigma Rules, Detection Logic Types, and the MITRE ATT&CK Framework
- The Rule Lifecycle — From Writing to Retirement

**🔴 Use Case Development**
- What Is a Use Case — and Why Does Every SOC Need Them?
- MITRE ATT&CK as a Use Case Framework and Writing Sigma Rules
- Maintaining Use Cases Over Time

---

## Log Analysis — ניתוח לוגים (5 חדרים)

**🟢 Anatomy of a Log Entry**
- The Five Questions Every Log Answers
- Plain Syslog: The Oldest Format You Will Still See Every Day
- Key=Value: Why FortiGate and Palo Alto Logs Are Built to Be Grepped
- JSON: Nested Fields and Why a Field Name Has Dots In It
- CSV/W3C and CEF/LEEF: Spreadsheets and SIEM-Normalised Formats
- Field Naming Chaos, and Why a SIEM Normalises Everything
- Severity Is a Vendor Opinion, Not a Fact
- What Is Not in the Log: Reading Absence of Evidence Correctly

**🟡 Windows Event Logs**
- Windows Event Logs — The System's Black Box
- Critical Security Event IDs Every SOC Analyst Must Know
- Attack Patterns in Event Logs and How to Build Detections

**🟡 Linux Log Analysis**
- The Linux Logging Ecosystem — Where Every Event Gets Written
- SSH Attack Detection — Reading the Patterns in auth.log
- Common Attack Indicators in Linux Logs

**🟡 VPN Monitoring**
- What VPN Logs Actually Tell You
- Impossible Travel, Brute Force, and Other VPN Attack Patterns
- Building a VPN Monitoring Detection Strategy

**🟡 Firewall Log Analysis**
- Understanding Firewall Logs: The Security Guard's Logbook
- Detecting Threats in Firewall Logs: Scans, Beacons, and Inbound Attacks
- Firewall Investigation Methodology and Rule Analysis

---

## Threat Detection — זיהוי איומים (9 חדרים)

**🟢 Cyber Kill Chain**
- What Is the Cyber Kill Chain?
- The 7 Stages: From Reconnaissance to Actions on Objectives
- Breaking the Chain: How Defenders Fight Back

**🟡 Email Security**
- How Email Works — Architecture and Headers
- Email Authentication — SPF, DKIM, and DMARC
- Email Attacks and the SOC Analysis Workflow

**🟡 Phishing Analysis**
- Email Headers: The Return Address on a Letter You Should Never Trust
- URLs, Attachments, and the Anatomy of a Phishing Kit
- Phishing Investigation Workflow: From Alert to Verdict

**🟡 DNS Investigation**
- DNS: The Phone Book That Logs Every Call
- DNS Attack Techniques: DGA, Tunnelling, Fast Flux, and Typosquatting
- DNS Investigation Workflow: From NXDOMAIN Storm to Confirmed Malware

**🟡 Authentication & Identity Monitoring**
- How Authentication Works — and How Attackers Abuse It
- Password Spray vs Credential Stuffing — Spot the Difference
- Building an Authentication Investigation — Step by Step

**🔴 Privileged Access Monitoring**
- What Privileged Accounts Are and Why Attackers Love Them
- "Permitted" Is Not "Authorised" — The Question Behind Every Privileged Alert
- Key Windows Events for Privileged Activity Detection
- Privilege Escalation Kill Chain — What the Attacker Does Step by Step
- When a Compromised Service Account Reaches a Database: xp_cmdshell Abuse

**🔴 Unusual Attacks and Edge-Case Use Cases**
- Supply Chain and Dependency Confusion: The Attack Nobody Watches For
- Insider Threat: Low-and-Slow Theft That Never Trips a Threshold
- Third-Party Compromise: Magecart-Style Skimmers and Trusted MSP Tools
- Shadow IT and OAuth Consent Phishing: Attacks With No Malware At All
- Living-off-the-Land, VPN False Positives, and Business-Logic Abuse
- Building an Analyst Instinct for the Cases That Don't Look Like Attacks

**🟡 Credential Attacks in the Logs**
- Four Attacks, One Symptom: Repeated Failed Logons
- Reading a 4625: The Fields That Actually Distinguish an Attack

**🔴 Tracing Lateral Movement**
- What One Host's Logs Can and Can't Tell You
- Privilege Realism: What ADMIN$ and a New Service Actually Prove

---

## Threat Intelligence — מודיעין איומים (7 חדרים)

**🟢 MITRE ATT&CK Framework**
- What Is MITRE ATT&CK? The World's Attack Encyclopedia
- The 14 Tactics: ATT&CK's Attack Roadmap
- Using ATT&CK in Your SOC Career

**🟡 Malware Analysis Fundamentals**
- What Is Malware Analysis — and Why Do SOC Analysts Need It?
- Static Analysis: Examining Malware Without Running It
- Dynamic Analysis: Running Malware Safely in a Sandbox

**🟡 IOC Analysis & Threat Pivoting**
- What Are IOCs — and Which Ones Actually Matter?
- VirusTotal and the OSINT Analyst Toolkit
- IOC Pivoting: Turning One Clue Into a Full Picture

**🟡 Threat Intelligence Fundamentals**
- What Is Cyber Threat Intelligence — And Why Is 'Intelligence' Different From 'Information'?
- Threat Actors, APT Groups, and the Platforms That Track Them
- How CTI Feeds Into Daily SOC Operations

**🟡 OSINT Fundamentals**
- What Is OSINT and Why Do SOC Analysts Need It?
- The SOC Analyst's OSINT Toolkit: Shodan, URLScan, WHOIS, and More
- Passive vs. Active OSINT — and Why Analyst OPSEC Matters

**🔴 Threat Hunting Fundamentals**
- What is Threat Hunting — and Why Does It Matter?
- How to Build a Hunt Hypothesis
- Hunting Specific TTPs and the Analyst's Toolbox

**🟢 Malware Types and What Each One Wants**
- What Malware Actually Wants: Propagation vs Payload
- Dropper vs Loader vs Stager: The Distinction Juniors Miss
- RAT / Backdoor: Interactive Control, and Why Beaconing Is the Detectable Part
- Infostealer: Grab and Leave — Why the Response Is Revocation, Not Cleanup
- Ransomware: Encryption for Extortion, and Why Pre-Encryption Indicators Are the Actionable Part
- Wiper vs Ransomware, and Cryptominers: 'Just Resource Theft' Is a Mistake
- Hiding From the SOC — and When Not to Bother Escalating At All

---

## Identity — זהות (6 חדרים)

**🟡 Active Directory Fundamentals**
- What Is Active Directory — and Why Does Every Company Use It?
- Kerberos Authentication — How AD Proves Who You Are
- AD Attack Techniques and SOC Monitoring
- AS-REP Roasting — Attacking Accounts With Pre-Authentication Disabled
- LLMNR/NBT-NS Poisoning and NTLM Relay — Stealing Authentication Without Cracking Anything

**🟡 Entra ID (Azure AD) Security**
- Entra ID Fundamentals: Cloud Identity vs On-Premises AD
- Conditional Access Policies & Authentication Flow
- Entra ID Protection, PIM, and Identity Attack Patterns

**🔴 Kerberos & Windows Authentication Deep Dive**
- The Kerberos Exchange: AS-REQ, AS-REP, TGS-REQ, TGS-REP
- TGT vs TGS, and Exactly Which Host Logs What
- Encryption Types: 0x12 vs 0x17, and Why a Downgrade Is the Signal
- Service Principal Names, and Why Any User Can Request a Ticket for One
- Kerberoasting vs AS-REP Roasting: Two Attacks That Look Similar and Aren't
- Overpass-the-Hash, and Why Golden and Silver Tickets Skip the KDC Entirely

**🟢 Identity Basics: Credentials, Sessions & MFA**
- Authentication vs Authorization: Proving Who You Are vs What You're Allowed to Do
- The Three Factors — and Why Two of the Same Kind Isn't MFA
- What a Credential Actually Is — and Why a Password Hash Counts Too
- Sessions and Tokens — the Idea That Unlocks the Modern Attacks
- Why Resetting the Password Isn't Enough — the Correct Containment Order
- MFA — What It Proves, and What It Doesn't
- Account Types — Why a Service Account Is a Different Kind of Risk
- Reading an Authentication Log — Success, Failure, and the Pattern Between Them

**🟡 Remote Email Collection & Malicious Inbox Rules**
- Remote Email Collection: What an Attacker Wants After the Takeover
- Reading the Unified Audit Log: MailItemsAccessed, ClientInfoString and SessionId
- Malicious Inbox Rules: How Attackers Make Access Outlast the Login
- Correlating the Session, Not Just the Event
- Legitimate Remote Mailbox Access — Delegates, Migrations, and Mobile Sync

**🟡 Device Registration Abuse & MFA Persistence**
- Account Manipulation: Why Registering a Device Beats Stealing Another Password
- Self-Service Registration and the Entra ID Audit Fields That Prove It
- Why a Password Reset Alone Does Not Fix This
- Reading the Timing: What Separates Suspicious Registration From Routine
- Legitimate Registration — New Phones, Planned Refreshes, and Helpdesk Assistance

---

## Cloud Security — אבטחת ענן (8 חדרים)

**🟡 Microsoft 365 Security**
- Microsoft 365 Security Ecosystem & Secure Score
- Defender for Office 365: Email Security Deep Dive
- M365 Audit Logs & Key Operations to Monitor

**🟡 Exchange Online Security**
- How Exchange Online Works — The Journey of Every Email
- Email Authentication — SPF, DKIM, and DMARC Explained
- Detecting BEC Attacks and Monitoring Exchange Online

**🟡 SharePoint & Teams Security Monitoring**
- SharePoint Online & OneDrive — How Data Lives in Microsoft 365
- Microsoft Teams Security Risks and Monitoring
- DLP and Insider Threat Detection in Microsoft 365

**🔴 Cloud Security Monitoring**
- Cloud Audit Logs — The CCTV of the Cloud
- IAM Attacks, S3 Exfiltration, and EC2 Metadata Abuse
- Building a Cloud Security Investigation — AWS Focus

**🟡 AWS Security for SOC Analysts**
- What Is AWS, and Why Does a SOC Analyst Need to Know It?
- CloudTrail: The Audit Log That Records Every Single API Call
- IAM Policies and Roles: How Permissions Actually Work
- GuardDuty, VPC Flow Logs, S3 Bucket Exposure, and IMDS Credential Theft
- How to Read and Investigate CloudTrail Events in a SIEM
- Crypto-Mining on EC2 and Why Disabling CloudTrail Is the Ultimate Red Flag

**🟡 Google Cloud Platform (GCP) Security Essentials**
- What Is GCP, and How Does It Map to What You Already Know?
- Cloud IAM and Service Accounts: GCP's Permission Model
- Cloud Audit Logs and Security Command Center: GCP's Audit Trail and Threat Detector
- The Six Attacks Every GCP-Facing SOC Analyst Must Recognize
- How to Read and Investigate GCP Audit Log Events in a SIEM
- Metadata-Server Theft, Unauthorized Key Creation, and Why the Order of Events Matters

**🔴 Kubernetes & Container Security**
- Containers Are Not Virtual Machines — Why That Matters for Security
- Privileged Pods and the hostPID / hostNetwork / hostPath Escape Hatches
- Kubernetes RBAC and Reading the Audit Log Like a SOC Analyst
- From Compromised Container to Stolen Cloud Credentials — The Full Chain

**🟡 Azure IaaS Security for SOC Analysts**
- What Is Azure, and How Is Its Resource Model Organized?
- Azure Activity Log: The Control-Plane Audit Trail
- Managed Identities and Service Principals: Azure's Non-Human Identities
- Network Security Groups, Storage Exposure, and SAS Token Abuse
- VM Run-Command and Custom Script Extension Abuse, and Resource Enumeration
- How to Triage an Azure Activity Log Alert in a SIEM
- Why a Long-Lived SAS Token Plus Public Container Access Is a Deliberate Exfiltration Setup

---

## Incident Response — תגובה לאירועים (5 חדרים)

**🟡 Incident Response Methodology**
- What Is a Security Incident? And the PICERL Framework for Responding to One
- Identification and Containment — Finding the Fire and Stopping It from Spreading
- Eradication, Recovery, and Lessons Learned — Cleaning Up and Getting Smarter

**🟡 Investigation Methodology**
- The Investigation Mindset and the Lifecycle
- Timeline Analysis and Evidence Pivoting
- SIEM Investigation Workflow and Case Management

**🟡 Running the Playbook — and Knowing When to Stop**
- What a Playbook Is For — and the One Thing It Cannot Know
- The Scope Gate: Where a Playbook Checks Its Own Assumption
- Deviating Properly, and Why Your Ticket Is a Feedback Loop

**🟡 How to Investigate an Alert — The 7-Step Analyst Workflow**
- Why Investigations Need a Workflow, and Why the First 15 Minutes Matter
- Step 2 — Scope: The Step You Return to Again and Again
- Step 3 — Collect and Preserve, in the Right Order
- Step 4 — Reconstruct the Timeline; Step 5 — Map to ATT&CK and Find Root Cause
- Step 6 — Document; Step 7 — Report and Hand Off

**🟡 Writing the Incident Report — Documentation That Holds Up**
- Two Audiences, One Incident: Why Every Report Has Two Halves
- The Anatomy of a Complete Incident Report
- Writing IOCs and the Technical Timeline
- Defensibility, Chain of Custody, and Writing as You Go
- Root Cause and Recommendations: From Vague to Actionable

---

## SOC Operations — תפעול SOC (8 חדרים)

**🟢 SOC Structure & Analyst Roles**
- What Is a Security Operations Center (SOC)?
- The SOC Tier Model: T1, T2, and T3 Analysts
- The SOC Toolbox: SIEM, EDR, SOAR, and More

**🟡 Alert Triage**
- What Is Alert Triage? The First and Most Important Skill of a SOC Analyst
- The 5-Step Triage Methodology: From Alert to Decision in Minutes
- Recognising False Positives, Knowing When to Escalate, and Writing Good Tickets

**🟡 Reporting & Documentation**
- Why Documentation Is the SOC's Most Important Habit
- SOC Metrics, KPIs, and the Shift Handover Report
- Legal Hold, Evidence Preservation, and Ticketing Systems

**🟡 Customer Communication**
- The SOC-as-a-Service Model and Why Client Communication Is Critical
- SLA Requirements, Notification Timelines, and Communication Channels
- SLA Breaches, After-Action Reviews, and Building Client Trust

**🟡 Escalation Procedures**
- The SOC Tier Structure: Tier 1, 2, and 3 Explained
- When to Escalate, When NOT to Escalate, and How to Do It Right
- Escalating to External Parties and Staying Engaged After Escalation

**🟢 The Analyst Mindset: How to Think and Ask the Right Questions**
- What Does It Mean to "Think Like an Analyst"?
- Forming a Hypothesis and the "So What?" Chain
- The Question Framework: What to Ask of Every Single Alert
- You Cannot Spot Abnormal Until You Know Normal
- Cognitive Biases That Quietly Sabotage Analysts
- Separating Fact From Assumption — and Knowing When to Stop

**🟡 SOAR and Security Automation**
- What Is SOAR, and How Is It Different From a SIEM?
- Playbooks, Workflows, and Enrichment Automation
- Automated Containment — and Why the Human Approval Gate Matters
- Case Management, Auto-Triage, Measuring Value, and the Danger of Over-Automation

**🟢 Asset Context: Why the Same Alert Is Not the Same Alert**
- The Same Alert, Three Assets
- What Makes an Asset Critical
- Blast Radius: What Else Does the Attacker Reach From Here?
- Exposure: Internet-Facing, Internal-Only, and Segmented
- Business Context Beats Technical Severity
- The CMDB Problem, Honestly
- Practical Prioritisation: Combining Severity, Criticality, and Confidence

---

## Forensics — פורנזיקה (2 חדרים)

**🟡 Digital Forensics Basics**
- What is Digital Forensics — and the Order of Volatility
- Memory Forensics — What Lives in RAM
- Disk Forensics and Timeline Reconstruction

**🔴 Memory & Disk Forensics for Analysts**
- Live Acquisition Without Contaminating the Scene
- What a Memory Image Yields That Disk Structurally Cannot
- Hashing and Chain of Custody, Applied to Live Acquisition
- Timeline Building Beyond the $MFT: $UsnJrnl, $LogFile, and Cross-Source Correlation
- Anti-Forensics: What Event 1102, Timestomping, and Shadow-Copy Deletion Still Leave Behind
- The Real Tension: Preserving Evidence vs Containing an Active Intrusion

---

## Application Security — אבטחת אפליקציות (2 חדרים)

**🟢 How Web Applications Work — and How They Break**
- What Actually Happens When You Open a Web Page
- The Trust Boundary: Nothing the Browser Sends Is Yours
- The Attack Classes, and Where Each One Lands on the Path
- The WAF: What It Sees, What It Misses, and the X-Forwarded-For Problem

**🔴 Reading a Web Attack in the Logs**
- Reading an IIS Access Log: Status Codes and What 'Worked' Actually Means
- Why You Need Both the WAF Record and the Web-Server Record for the Same Request

---

## Data Security — אבטחת מידע (1 חדר)

**🟡 Data Loss Prevention (DLP) for SOC Analysts**
- What Is DLP, and Why It Matters
- The Three DLP Channels: Endpoint, Network, Cloud/Email
- Sensitive Data Types: What DLP Is Built to Catch
- How DLP Classifiers Work: Regex, Keywords, Fingerprinting, and Confidence
- DLP Actions: Audit, Warn/Justify, Block, and Encrypt
- Investigating a DLP Alert: Malicious, Well-Meaning, or False Positive?

---

## Vulnerability Management — ניהול חולשות (1 חדר)

**🟡 Vulnerability Management for SOC Analysts**
- CVE, CWE, and CVSS Are Three Different Questions
- Inside a CVSS Score: Base, Temporal, and Environmental Metrics
- Why CVSS Alone Prioritizes Badly — EPSS and the CISA KEV Catalog
- Authenticated vs Unauthenticated Scanning, and Asset Context
- Confirming a False Positive, Choosing a Remediation Path, and Where the SOC's Job Ends

---

*מסמך זה נוצר על ידי סקריפט חד-פעמי (`scripts/extract-room-subtopics.mjs`, לא חלק משער התוכן) שקורא את `ROOMS` האמיתי ומחלץ את כותרות ה-reading tasks. אם התוכן ישתנה, יש להריץ מחדש: `npx tsx scripts/extract-room-subtopics.mjs`.*
