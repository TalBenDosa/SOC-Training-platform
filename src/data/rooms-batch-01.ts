/**
 * Learning Rooms — Batch 01
 * Foundational curriculum: Cybersecurity Intro, SOC Structure,
 * Cyber Kill Chain, and MITRE ATT&CK Framework.
 *
 * Audience: Absolute beginners with ZERO prior cybersecurity or IT background.
 * Every concept is explained from scratch with real-world analogies.
 */

import type { TelemetryEvent } from "@/lib/sim/types";

// ---------------------------------------------------------------------------
// Room 1 — Introduction to Cybersecurity
// ---------------------------------------------------------------------------

const introToCyberEvent: TelemetryEvent = {
  id: "evt-intro-001",
  ts: "2024-03-15T14:22:07.441Z",
  source: "av",
  vendor: "Microsoft Defender",
  event_type: "av_detection",
  severity: "high",
  hostname: "DESKTOP-HR-042",
  user_email: "sarah.jones@acmecorp.com",
  description: "Malware detected on HR workstation during email attachment open",
  mitre_technique: "T1566.001",
  mitre_tactic: "Initial Access",
  raw: {
    EventID: 1116,
    DetectionSource: "NIS",
    ThreatName: "Trojan:Win32/Emotet.AL!MTB",
    ThreatID: "2147812831",
    Severity: "High",
    Action: "Quarantine",
    ActionSuccess: true,
    FilePath: "C:\\Users\\sarah.jones\\AppData\\Local\\Temp\\invoice_Q1_2024.exe",
    FileSize: 284672,
    SHA256: "4a9f3b2c1d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2",
    MD5: "d41d8cd98f00b204e9800998ecf8427e",
    ProcessName: "outlook.exe",
    ProcessPID: 4892,
    OriginUrl: "http://invoice-portal-acme.ru/download/invoice_Q1_2024.exe",
    ThreatCategory: "Trojan",
    DetectionTime: "2024-03-15T14:22:07.441Z",
    ProductVersion: "4.18.24020.7",
    SignatureVersion: "1.407.0.0",
    EngineVersion: "1.1.24020.9",
    UserName: "ACMECORP\\sarah.jones",
    ComputerName: "DESKTOP-HR-042",
    AdditionalActionsBitmask: 0,
    RemediationUser: "NT AUTHORITY\\SYSTEM",
    ErrorCode: "0x00000000",
    ErrorDescription: "The operation completed successfully.",
  },
};

const introRoom = {
  id: "intro-cybersecurity",
  title: "Introduction to Cybersecurity",
  description:
    "Start your cybersecurity journey from scratch. Learn what cybersecurity is, why it matters, the CIA Triad, types of attackers, common attack techniques, and how a career in cybersecurity begins.",
  difficulty: "beginner" as const,
  category: "Foundations",
  estimatedMinutes: 40,
  xp: 300,
  icon: "🛡️",
  prerequisites: [],
  tasks: [
    // ------------------------------------------------------------------
    // Reading 1 — What Is Cybersecurity?
    // ------------------------------------------------------------------
    {
      type: "reading" as const,
      id: "intro-cyber-r1",
      heading: "What Is Cybersecurity?",
      content: `Imagine you own a house. You lock the front door, install window latches, maybe add a burglar alarm, and put a fence around the garden. All of these measures exist to protect your house, your family, and your valuables from unwanted visitors. Now imagine that same concept — but applied to computers, networks, and data. That, in essence, is **cybersecurity**.

**Cybersecurity** is the practice of protecting computers, servers, mobile devices, networks, and data from theft, damage, and unauthorized access. Just as a physical house has multiple layers of security (lock, alarm, fence, neighbourhood watch), a digital system uses multiple layers of defence to keep attackers out.

**Why does this matter?** We live in a world where almost everything runs on computers. Your bank account, your medical records, the power grid in your city, the traffic lights on your street, and even your microwave — all are increasingly connected to digital networks. If an attacker can break into these systems, they can steal money, expose private information, shut down hospitals, or even cause physical harm.

**A very brief history.** Cybersecurity was not always a big concern. In the early days of computing (1970s–1980s), computers were expensive, rare, and mostly isolated from each other. The first computer worm — called the **Morris Worm** — appeared in 1988 and infected roughly 6,000 machines (about 10% of the entire internet at the time). That incident shocked the world and gave birth to the modern cybersecurity industry.

Today, the numbers are staggering:
- A cyberattack happens every **39 seconds** worldwide.
- The global cost of cybercrime is expected to reach **$10.5 trillion per year** by 2025.
- In 2020, the **SolarWinds** breach compromised 18,000 organisations, including the US Treasury and Department of Homeland Security, by hiding malware inside a software update.
- In 2021, the **Colonial Pipeline** ransomware attack caused fuel shortages across the US East Coast and cost the company $4.4 million in ransom.

**The digital attack surface** is everything that can be targeted by an attacker: every computer, every server, every phone, every application, every employee's email inbox. The larger and more complex an organisation's technology environment, the bigger its attack surface.

**What does a cybersecurity professional do?** Just like a security guard patrols a building, a cybersecurity analyst monitors digital systems for signs of intruders. They review logs (records of activity), investigate suspicious events, and respond when an attack is detected. The entry-level role into this world is the **SOC (Security Operations Center) Analyst** — the role you are training for right now.

**Key takeaway:** Cybersecurity is not magic — it is a structured discipline built on understanding how attackers think and how defenders respond. You do not need to be a hacker or a software engineer to start. You need curiosity, attention to detail, and the ability to analyse information. This course will build those skills from the ground up.`,
    },

    // ------------------------------------------------------------------
    // Reading 2 — The CIA Triad and Types of Threats
    // ------------------------------------------------------------------
    {
      type: "reading" as const,
      id: "intro-cyber-r2",
      heading: "The CIA Triad: The Three Pillars of Security",
      content: `Every security decision in cybersecurity — from designing a password policy to responding to a breach — is guided by three core principles called the **CIA Triad**. The CIA Triad stands for **Confidentiality**, **Integrity**, and **Availability**. These three properties define what it means for information to be "secure."

**1. Confidentiality — Only the right people can see the data**
Think about your medical records. You want only your doctor and you to see them — not your employer, not a stranger, not a hacker. Confidentiality means that information is accessible only to those who are authorised to see it. When confidentiality is violated, private data becomes public. Examples of confidentiality attacks: a hacker steals a company's customer database and publishes credit card numbers online; an employee emails a sensitive spreadsheet to the wrong recipient.

**2. Integrity — The data hasn't been tampered with**
Imagine you send someone a contract that says "pay me $1,000." Now imagine an attacker intercepts that contract and changes it to "$100,000" before the recipient reads it. Integrity means that data has not been modified, corrupted, or falsified — by an attacker or even accidentally. Integrity attacks are particularly dangerous in healthcare (changed medication dosages), finance (altered transaction amounts), and legal documents.

**3. Availability — The system is up and running when you need it**
If your bank's online system goes down on payday, that is an availability failure. Availability means that systems and data are accessible to authorised users when they need them. **DDoS attacks** (Distributed Denial of Service — explained below) are the classic availability attack: flooding a server with so much fake traffic that it cannot respond to real users.

**A real-world example combining all three:** A hospital's patient record system must be:
- **Confidential** — only nurses and doctors can view patient records, not visitors
- **Integral** — doctors must trust that the prescription data has not been altered
- **Available** — doctors need access to records 24/7, especially in emergencies

Now let's look at **who attacks these systems**.

**Types of Threat Actors (people who attack)**

- **Script Kiddies** — Beginners who use pre-written hacking tools created by others. They often do not fully understand what they are doing. Low skill, but can still cause damage.
- **Cybercriminals** — Organised groups motivated by financial gain. They run ransomware operations, steal credit card data, and sell access to breached networks. The **LockBit** ransomware group is a well-known example.
- **Hacktivists** — Attackers motivated by political or social causes. The group **Anonymous** is a famous example — they have attacked government websites to protest policies.
- **Nation-State Actors** — Government-sponsored hackers conducting espionage, sabotage, or influence operations. **APT29** (also called "Cozy Bear") is linked to Russian intelligence and was behind the SolarWinds attack.
- **Insider Threats** — Employees (current or former) who intentionally or accidentally cause harm. An angry employee copying customer data before resigning, or a careless employee clicking a phishing link, are both insider threats.

**Types of Attacks**

- **Phishing** — A fake email designed to trick you into clicking a malicious link or revealing your password. Like a fake letter from your bank asking you to "verify your account."
- **Ransomware** — Malware that encrypts (locks) your files and demands a ransom to unlock them. Colonial Pipeline paid $4.4 million in Bitcoin to get their systems back.
- **DDoS (Distributed Denial of Service)** — Flooding a server with millions of fake requests until it crashes, like thousands of prank callers jamming a phone line so real customers cannot get through.
- **Man-in-the-Middle (MitM)** — An attacker secretly positions themselves between two communicating parties and intercepts or alters the messages. Like a dishonest postal worker reading and resealing your letters.
- **Social Engineering** — Manipulating people (not systems) into revealing information or taking actions. A classic example: calling someone and pretending to be from IT support to get their password.`,
    },

    // ------------------------------------------------------------------
    // Reading 3 — Why Cybersecurity Matters & Career Paths
    // ------------------------------------------------------------------
    {
      type: "reading" as const,
      id: "intro-cyber-r3",
      heading: "Real-World Impact & Starting Your Cybersecurity Career",
      content: `Understanding cybersecurity in the abstract is useful. Understanding it through real events makes it stick. Let's look at two landmark breaches that changed the industry forever.

**Case Study 1: SolarWinds (2020)**
SolarWinds makes software called **Orion** that thousands of organisations use to monitor their IT networks. In 2020, attackers (later attributed to Russian intelligence, APT29) compromised SolarWinds' own software build process and inserted malicious code into an Orion update. When organisations installed the update — trusting SolarWinds as a legitimate vendor — they unknowingly installed a backdoor. Over 18,000 organisations were affected, including the US Treasury, the Department of Homeland Security, and major tech companies. This attack is called a **supply chain attack**: instead of attacking a target directly, the attacker compromises a trusted supplier.

**Case Study 2: Colonial Pipeline (2021)**
Colonial Pipeline operates the largest fuel pipeline in the United States, carrying 45% of the East Coast's fuel supply. In May 2021, a ransomware group called **DarkSide** gained access using a compromised VPN (Virtual Private Network — a secure remote access tool) password. They encrypted critical systems and demanded ransom. The company proactively shut down pipeline operations, causing fuel shortages across the southeastern US. Panic buying led to long queues at petrol stations. Colonial paid $4.4 million in Bitcoin, though US authorities later recovered about $2.3 million of it.

**Key lesson from both:** Modern attacks often exploit the weakest link — a trusted software update, a reused password, a single employee clicking the wrong email. Cybersecurity is not purely a technology problem; it is a human problem.

**The Scale of the Problem**
- IBM's 2023 Cost of a Data Breach Report found the average data breach costs **$4.45 million**.
- The healthcare industry has the highest breach costs of any sector.
- It takes organisations an average of **204 days** just to *detect* a breach, and another 73 days to contain it — nearly a full year of an attacker being inside before anything is done.
- The global shortage of cybersecurity professionals was estimated at **3.5 million unfilled jobs** in 2023.

**Career Paths in Cybersecurity**
Cybersecurity is a broad field. Here are the main tracks:

- **SOC Analyst (your starting point)** — Monitor alerts, investigate suspicious events, escalate threats. The most common entry-level role.
- **Penetration Tester (Ethical Hacker)** — Hired to attack an organisation's own systems to find weaknesses before criminals do.
- **Incident Responder** — Called in when a breach is confirmed. They investigate what happened, contain the damage, and help restore operations.
- **Threat Intelligence Analyst** — Tracks hacker groups, monitors the dark web, and publishes intelligence about upcoming threats.
- **Security Engineer** — Builds and maintains the security tools and infrastructure (firewalls, SIEM systems, etc.).
- **GRC Analyst (Governance, Risk, and Compliance)** — Ensures the organisation follows laws, regulations, and internal policies.
- **Cloud Security Engineer** — Specialises in securing cloud environments (AWS, Azure, GCP).

The SOC Analyst role is the gateway. It gives you exposure to real attacks, real tools, and real investigation skills. Most other cybersecurity careers draw on experience gained in a SOC. That is why this training platform is built around the SOC Analyst experience.

**What you will learn in this course:**
- How attackers think and operate (Kill Chain, MITRE ATT&CK)
- How a SOC is organised and how analysts work
- How to read and analyse real security logs
- How to detect and respond to common attacks
- Hands-on experience with realistic scenarios

You are about to join one of the most in-demand, dynamic, and impactful professions in the world. Let's get started.`,
    },

    // ------------------------------------------------------------------
    // Question 1
    // ------------------------------------------------------------------
    {
      type: "question" as const,
      id: "intro-cyber-q1",
      question:
        "A hospital's patient records system goes offline during surgery because attackers flooded it with fake traffic. Which principle of the CIA Triad has been violated?",
      options: [
        "Confidentiality — private records became public",
        "Integrity — the medical data was altered by attackers",
        "Availability — authorised users cannot access the system when needed",
        "Authentication — users cannot prove their identity",
      ],
      answer: 2,
      explanation:
        "Availability means that systems and data must be accessible to authorised users when they need them. Flooding a server with fake traffic (a DDoS attack) makes it unavailable — violating Availability. Confidentiality (data secrecy) and Integrity (data accuracy) are separate principles and were not violated in this scenario.",
      xp: 20,
    },

    // ------------------------------------------------------------------
    // Question 2
    // ------------------------------------------------------------------
    {
      type: "question" as const,
      id: "intro-cyber-q2",
      question:
        "Which type of threat actor is most likely responsible for the SolarWinds attack, where attackers hid malware inside a legitimate software update to spy on government agencies?",
      options: [
        "Script Kiddie — they used pre-written hacking tools",
        "Hacktivist — they were protesting a government policy",
        "Nation-State Actor — government-sponsored espionage operation",
        "Cybercriminal — they were motivated by financial gain",
      ],
      answer: 2,
      explanation:
        "The SolarWinds attack was attributed to APT29, a group linked to Russian intelligence — making it a Nation-State Actor operation. The goal was espionage (spying on US government agencies), not financial gain. Script kiddies lack the sophistication for this type of complex supply-chain attack. Hacktivists are motivated by political protest, not espionage.",
      xp: 20,
    },

    // ------------------------------------------------------------------
    // Question 3 — Scenario Based
    // ------------------------------------------------------------------
    {
      type: "question" as const,
      id: "intro-cyber-q3",
      question:
        "Sarah receives an email that appears to be from her bank. It says: 'Urgent: Your account has been suspended. Click here to verify your identity.' She clicks the link and enters her username and password on what looks like her bank's website. What type of attack is this?",
      options: [
        "DDoS attack — attackers overwhelmed the bank's servers",
        "Ransomware attack — Sarah's files have been encrypted",
        "Phishing attack — she was tricked into giving up her credentials",
        "Man-in-the-Middle attack — the attacker intercepted her connection",
      ],
      answer: 2,
      explanation:
        "This is a textbook Phishing attack. The attacker created a fake email pretending to be from a trusted source (the bank) and a fake website to harvest Sarah's login credentials. Phishing exploits trust and urgency — key psychological tactics. DDoS attacks crash servers; ransomware encrypts files; MitM attacks intercept real communications — none of those fit this scenario.",
      xp: 25,
    },

    // ------------------------------------------------------------------
    // Log Analysis Task
    // ------------------------------------------------------------------
    {
      type: "log_analysis" as const,
      id: "intro-cyber-la1",
      heading: "Analysing Your First Security Alert",
      context:
        "You are a Tier-1 SOC Analyst at ACME Corp. Your SIEM (Security Information and Event Management) dashboard just flagged an alert from Microsoft Defender — the antivirus software installed on employee workstations. Review the log event below and answer the questions. Focus on the key fields: ThreatName, FilePath, OriginUrl, Action, and ActionSuccess.",
      event: introToCyberEvent,
      questions: [
        {
          question:
            "Looking at the log, what action did Microsoft Defender take when it detected the threat?",
          options: [
            "It deleted the file permanently from the hard drive",
            "It quarantined the file (isolated it so it cannot run)",
            "It allowed the file to run and monitored it",
            "It sent an alert but took no automatic action",
          ],
          answer: 1,
          explanation:
            'The "Action" field shows "Quarantine" and "ActionSuccess" is true. Quarantine means Defender moved the file to a secure, isolated location where it cannot execute or spread. This is different from deletion — the file still exists in quarantine for forensic review. The event confirms the action succeeded.',
          xp: 20,
        },
        {
          question:
            "The OriginUrl field shows where the file was downloaded from. What does this URL suggest about the nature of the attack?",
          options: [
            "The file came from a trusted corporate server (acmecorp.com)",
            "The file came from a suspicious external domain (invoice-portal-acme.ru) likely used for phishing",
            "The file was created locally by the user and never downloaded",
            "The URL shows the file came from Microsoft's official update servers",
          ],
          answer: 1,
          explanation:
            "The OriginUrl is 'http://invoice-portal-acme.ru/download/invoice_Q1_2024.exe'. The .ru domain is a Russian country code top-level domain (ccTLD). The domain 'invoice-portal-acme' mimics ACME Corp's name to appear legitimate — a classic phishing tactic called typosquatting. The file name 'invoice_Q1_2024.exe' is designed to look like a legitimate invoice. This strongly indicates a spear-phishing attack targeting ACME Corp employees.",
          xp: 25,
        },
        {
          question:
            "The ProcessName field shows 'outlook.exe'. What does this tell you about how the user encountered the malicious file?",
          options: [
            "The malware was delivered through a USB drive inserted into the computer",
            "The malware was downloaded through a web browser",
            "The malware came as an email attachment opened in Microsoft Outlook",
            "The malware was installed by a system administrator",
          ],
          answer: 2,
          explanation:
            "outlook.exe is the process name for Microsoft Outlook — the email client. The fact that Outlook was the parent process when the malicious file was executed tells us the user opened an email attachment that triggered the malware. This is consistent with the phishing origin URL and the filename (invoice_Q1_2024.exe), which was designed to trick the user into thinking it was a legitimate invoice.",
          xp: 20,
        },
      ],
    },

    // ------------------------------------------------------------------
    // Matching Task — CIA Triad
    // ------------------------------------------------------------------
    {
      type: "matching" as const,
      id: "intro-cyber-m1",
      heading: "Match the CIA Triad",
      instructions: "Match each security pillar on the left to its correct definition on the right. Click a pillar, then click its definition.",
      pairs: [
        {
          id: "conf",
          left: "Confidentiality",
          right: "Only authorized people can read the data — enforced with encryption and access controls",
        },
        {
          id: "integ",
          left: "Integrity",
          right: "Data cannot be secretly changed — verified with hashing and digital signatures",
        },
        {
          id: "avail",
          left: "Availability",
          right: "Systems must work when needed — protected by backups, redundancy, and DDoS mitigation",
        },
      ],
      explanation: "The CIA Triad is the foundation of every security program. Confidentiality ensures secrets stay secret. Integrity ensures data has not been tampered with. Availability ensures systems are up when users need them. A real attack almost always targets at least one of these three — ransomware targets Availability, data theft targets Confidentiality, and log-tampering targets Integrity.",
      xp: 30,
    },

    // ------------------------------------------------------------------
    // Question 4 — Additional
    // ------------------------------------------------------------------
    {
      type: "question" as const,
      id: "intro-cyber-q4",
      question:
        "The global shortage of cybersecurity professionals was estimated at 3.5 million unfilled jobs in 2023. Which entry-level role is considered the most common starting point for a cybersecurity career?",
      options: [
        "Penetration Tester — ethical hackers who attack systems to find weaknesses",
        "SOC Analyst — monitors alerts and investigates suspicious events in a Security Operations Center",
        "Security Engineer — builds and maintains security infrastructure",
        "CISO (Chief Information Security Officer) — leads the entire security strategy",
      ],
      answer: 1,
      explanation:
        "The SOC (Security Operations Center) Analyst is the most common entry-level cybersecurity role. SOC Analysts monitor security tools, triage alerts, and investigate incidents. The role provides exposure to real attacks and real tools, which is why most other cybersecurity careers build on SOC experience. CISO is a senior executive role, not entry-level. Penetration testing and security engineering typically require more experience.",
      xp: 15,
    },
  ],
};

// ---------------------------------------------------------------------------
// Room 2 — SOC Structure & Analyst Roles
// ---------------------------------------------------------------------------

const socStructureEvent: TelemetryEvent = {
  id: "evt-soc-001",
  ts: "2024-04-08T03:47:22.118Z",
  source: "ad",
  vendor: "Windows Security",
  event_type: "auth_failure",
  severity: "medium",
  hostname: "DC01-CORP",
  user_email: "jsmith@globalbank.com",
  description: "Multiple failed login attempts detected — possible brute-force",
  mitre_technique: "T1110",
  mitre_tactic: "Credential Access",
  src_ip: "185.220.101.47",
  raw: {
    EventID: 4625,
    SubjectUserSid: "S-1-0-0",
    SubjectUserName: "-",
    SubjectDomainName: "-",
    TargetUserName: "jsmith",
    TargetDomainName: "GLOBALBANK",
    Status: "0xC000006D",
    FailureReason: "Unknown user name or bad password",
    SubStatus: "0xC000006A",
    LogonType: 3,
    LogonTypeName: "Network",
    WorkstationName: "-",
    TransmittedServices: "-",
    LmPackageName: "-",
    KeyLength: 0,
    ProcessId: "0x0",
    ProcessName: "-",
    IpAddress: "185.220.101.47",
    IpPort: 54312,
    FailureCount: 47,
    TimeWindow: "00:02:33",
    FailuresPerMinute: 18,
    AlertThreshold: 10,
    AuthenticationPackageName: "NTLM",
    KeywordFlags: "Audit Failure",
    Computer: "DC01-CORP.globalbank.com",
    TimeCreated: "2024-04-08T03:47:22.118Z",
    RecordNumber: 1047382,
    ActivityId: "{a3b4c5d6-e7f8-9012-3456-7890abcdef12}",
    Channel: "Security",
    Provider: "Microsoft-Windows-Security-Auditing",
    GeoLocation_Country: "Netherlands",
    GeoLocation_City: "Amsterdam",
    GeoLocation_ISP: "Tor Exit Node",
    PreviousFailures: [
      "03:45:10 - 185.220.101.47",
      "03:45:14 - 185.220.101.47",
      "03:45:18 - 185.220.101.47",
    ],
  },
};

const socStructureRoom = {
  id: "soc-structure",
  title: "SOC Structure & Analyst Roles",
  description:
    "Learn how a Security Operations Center (SOC) is organised, the three-tier analyst model, the tools analysts use every day, and what life looks like in a 24/7 security team.",
  difficulty: "beginner" as const,
  category: "SOC Operations",
  estimatedMinutes: 38,
  xp: 320,
  icon: "🏢",
  prerequisites: ["intro-cybersecurity"],
  tasks: [
    // ------------------------------------------------------------------
    // Reading 1 — What Is a SOC?
    // ------------------------------------------------------------------
    {
      type: "reading" as const,
      id: "soc-struct-r1",
      heading: "What Is a Security Operations Center (SOC)?",
      content: `Imagine a city's **emergency services dispatch center** — the room full of operators who answer 999/911 calls, coordinate police, fire, and ambulance responses, and keep a constant eye on the city's safety. They work in shifts around the clock. When something small comes in, a single operator handles it. When something major happens — a multi-car accident, a building fire — multiple teams are called in and operations escalate rapidly.

A **Security Operations Center (SOC)** is exactly that, but for an organisation's digital environment. It is a dedicated facility — often a physical room with large screens showing dashboards — staffed by cybersecurity analysts who monitor the organisation's computer systems, networks, and data 24 hours a day, 7 days a week, 365 days a year.

**The SOC's primary mission** is to detect, analyse, and respond to cybersecurity incidents before they cause serious harm. Every email sent, every login attempted, every file moved, every network connection made within the organisation generates a **log** (a digital record). The SOC collects these millions of logs every day and uses specialised software — called a **SIEM** (Security Information and Event Management — pronounced "sim") — to automatically flag suspicious patterns.

**What does a SOC actually do?**
- **Monitor** — Continuously watch dashboards and alerts for suspicious activity
- **Triage** — Quickly assess whether an alert is a real threat (True Positive) or a harmless false alarm (False Positive)
- **Investigate** — Dig deeper into confirmed threats: who did what, when, from where
- **Contain** — Stop an active attack from spreading (e.g., isolate an infected machine from the network)
- **Remediate** — Clean up after an incident: remove malware, reset compromised accounts, patch vulnerabilities
- **Report** — Document everything: what happened, how it was detected, how it was handled

**Types of SOCs**
Not every organisation builds their own SOC from scratch. There are several models:

- **In-House SOC** — The organisation employs its own team of security analysts. Expensive, but gives full control. Common in large banks, government agencies, and healthcare systems.
- **MSSP (Managed Security Service Provider)** — The organisation outsources security monitoring to a specialist company. The MSSP monitors multiple clients simultaneously, making it cost-effective for smaller organisations.
- **Virtual SOC (vSOC)** — No physical location. Analysts work remotely, connecting to centralised security tools via the internet. Became common during the COVID-19 pandemic.
- **Hybrid SOC** — A mix: the organisation handles critical monitoring in-house but outsources overflow or specialist tasks to an MSSP.

**Key SOC metrics**
Every SOC is measured on performance. Two critical metrics are:
- **MTTD (Mean Time to Detect)** — The average time between when an attack begins and when the SOC discovers it. According to IBM, the global average was 204 days in 2023. A good SOC aims for hours or days, not months.
- **MTTR (Mean Time to Respond)** — The average time from detection to containment. Faster is always better — every minute an attacker is inside costs money and damages trust.

**The SOC and the rest of the organisation**
The SOC does not operate in isolation. It works closely with:
- IT teams (who manage and fix systems)
- Legal and Compliance teams (who deal with regulations and breach notification requirements)
- Human Resources (when insider threats are involved)
- Executive Leadership (who need to be briefed during major incidents)
- Law Enforcement (for serious criminal attacks)

Think of the SOC as the **nervous system** of an organisation's security — constantly receiving signals, processing information, and triggering responses.`,
    },

    // ------------------------------------------------------------------
    // Reading 2 — The Tier Model
    // ------------------------------------------------------------------
    {
      type: "reading" as const,
      id: "soc-struct-r2",
      heading: "The SOC Tier Model: T1, T2, and T3 Analysts",
      content: `A busy SOC can receive thousands of alerts every day. It would be impossible — and inefficient — for one person to handle all of them with the same level of depth. Instead, SOCs use a **tiered model** to match the complexity of a threat to the skill level of the analyst handling it. Think of it like a hospital emergency room: a nurse handles minor injuries, a doctor handles more serious cases, and a specialist surgeon is called in for complex operations.

**Tier 1 (T1) — Alert Triage Analyst**
This is the entry-level position and where most security careers begin. Tier 1 analysts are the front line — they are the first to see every alert that comes into the SOC.

Responsibilities of a T1 Analyst:
- Monitor the SIEM dashboard continuously for new alerts
- **Triage** each alert: is this a real threat (True Positive) or a false alarm (False Positive)?
- Collect initial data: which computer was involved? Which user? What time? What IP address?
- Open a ticket in the ticketing system (tools like ServiceNow or Jira) to document the alert
- Follow **playbooks** — step-by-step response procedures for common alert types
- Escalate to Tier 2 when the alert is confirmed as a real threat or is too complex to resolve quickly

A T1 analyst might handle 20–50 alerts per shift. The vast majority will turn out to be false positives — tuning this signal-to-noise ratio is one of the SOC's most important ongoing tasks.

**Tier 2 (T2) — Incident Response Analyst**
T2 analysts receive escalations from T1. They are more experienced and have deeper technical skills. Where a T1 analyst confirms that something is wrong, a T2 analyst figures out *exactly* what is wrong and starts the response.

Responsibilities of a T2 Analyst:
- Perform deep-dive investigation into confirmed incidents
- Correlate data from multiple sources: endpoint logs, network logs, identity logs, email logs
- Determine the scope: how many systems are affected? Has the attacker moved laterally (spread to other systems)?
- Implement containment measures: isolate infected machines, block malicious IP addresses, disable compromised accounts
- Coordinate with IT teams to remediate affected systems
- Escalate to Tier 3 for advanced persistent threats, novel malware, or nation-state level attacks

**Tier 3 (T3) — Threat Hunter / Senior Analyst**
T3 analysts are the most experienced and skilled members of the SOC. They do not just react to alerts — they proactively hunt for threats that automated tools have missed.

Responsibilities of a T3 Analyst:
- **Threat hunting** — actively searching through logs and system data for signs of hidden attackers who have evaded detection
- Analyse novel malware using reverse engineering techniques
- Build new detection rules in the SIEM to catch future attacks
- Conduct purple team exercises (simulating attacks to test defences)
- Mentor T1 and T2 analysts
- Lead response to major, complex incidents

**Other Key Roles in the SOC**

- **SOC Manager** — Oversees the entire team. Manages staffing, shift scheduling, escalation procedures, and executive reporting. Accountable for MTTD and MTTR metrics.
- **Threat Intelligence Analyst** — Monitors the broader threat landscape. Tracks known hacker groups (like APT29, LockBit), subscribes to threat feeds, and publishes internal intelligence reports to help analysts know what to look for.
- **Incident Response Specialist** — Called in for major breaches. Specialises in forensic investigation, evidence preservation, and legal coordination.
- **Malware Analyst** — Dissects malicious software to understand how it works, what it does, and how to detect and remove it.

**Shift Work and Handoffs**
Because threats do not take weekends off, SOCs operate 24x7. Analysts work rotating shifts: morning, afternoon, and night. At the end of each shift, outgoing analysts brief incoming analysts on:
- Open incidents in progress
- Escalated tickets awaiting action
- Any changes in the threat landscape

This handoff process is critical. Poor handoffs have allowed attackers to operate undetected during the gap between shifts. Good SOCs use structured handoff templates to ensure nothing is missed.`,
    },

    // ------------------------------------------------------------------
    // Reading 3 — Tools of the Trade
    // ------------------------------------------------------------------
    {
      type: "reading" as const,
      id: "soc-struct-r3",
      heading: "The SOC Toolbox: SIEM, EDR, SOAR, and More",
      content: `A SOC analyst's job is made possible by a powerful suite of specialised tools. Understanding what each tool does — and how they work together — is fundamental to working effectively in a SOC. Think of the tools as different instruments in an orchestra: each plays its own role, but together they create a complete picture.

**SIEM — Security Information and Event Management**
The SIEM is the **brain and central hub** of the SOC. It is a software platform that collects log data from every source in the organisation — firewalls, servers, workstations, cloud services, applications — and centralises it in one place. The SIEM then applies correlation rules to automatically detect suspicious patterns and generate alerts.

Popular SIEM products: **Microsoft Sentinel**, **Splunk**, **IBM QRadar**, **Elastic SIEM**, **Exabeam**.

Example: The SIEM notices that user "jsmith" failed to log in 47 times in 2 minutes from an IP address in the Netherlands (a country where ACME Corp has no offices) — and then succeeded on the 48th attempt. No individual log shows anything alarming. But the SIEM correlates all 48 events and fires a "brute-force login followed by success" alert.

**EDR — Endpoint Detection and Response**
**Endpoints** are devices like laptops, desktops, and servers. EDR tools are software agents installed directly on these devices that monitor everything happening on them in real time: every process started, every file created, every network connection made.

Popular EDR products: **CrowdStrike Falcon**, **Microsoft Defender for Endpoint (MDE)**, **SentinelOne**, **Carbon Black**.

Where an antivirus (AV) tool looks for known malware signatures (like recognising a criminal by their photo), an EDR watches *behaviour* (like recognising a criminal by the way they act). An EDR can catch attacks that use brand-new malware with no known signature.

**SOAR — Security Orchestration, Automation, and Response**
A SOAR platform automates repetitive tasks in the SOC. Instead of an analyst manually clicking through 10 steps to check whether an IP address is malicious, a SOAR **playbook** does it automatically in seconds: look up the IP in threat intelligence databases, check if the user has logged in from that IP before, quarantine the device if the IP is confirmed malicious — all without human intervention.

Popular SOAR products: **Palo Alto XSOAR**, **Splunk SOAR**, **Microsoft Sentinel's automation rules**.

**TIP — Threat Intelligence Platform**
A TIP aggregates intelligence from multiple sources about known malicious actors, IP addresses, domains, and malware. When an analyst sees a suspicious IP address, they "look it up" in the TIP to see if it has been linked to known attacks.

Popular TIP products: **MISP**, **ThreatConnect**, **Recorded Future**, **Mandiant Advantage**.

**Ticketing System**
Every alert handled in the SOC is documented in a ticketing system. This creates an audit trail, enables management to track workload, and ensures nothing falls through the cracks.

Common ticketing systems: **ServiceNow**, **Jira**, **TheHive** (open-source, popular in SOCs).

**How the tools work together — an example:**
1. An attacker sends a phishing email to an employee.
2. The **email gateway** (e.g., Microsoft Defender for Office 365) scans it and flags the attachment as suspicious. It sends a log to the SIEM.
3. The employee clicks through anyway. The **EDR** on their laptop detects that the attachment spawned a suspicious process and blocks it, sending an alert to the SIEM.
4. The **SIEM** correlates the email gateway log and the EDR alert, recognises the pattern as a phishing attack, and creates a high-severity alert.
5. The **SOAR** automatically looks up the sender's domain in the **TIP**, confirms it is a known malicious domain, and triggers a playbook: block the domain on the email gateway, quarantine the user's device, and open a **ticket** in ServiceNow.
6. A T1 analyst reviews the automatically-created ticket and confirms the automated response was appropriate. The incident is escalated to T2 for full investigation.

That entire sequence — from first email to automated response — might happen in under 60 seconds in a mature SOC. This is why tooling matters.`,
    },

    // ------------------------------------------------------------------
    // Question 1
    // ------------------------------------------------------------------
    {
      type: "question" as const,
      id: "soc-struct-q1",
      question:
        "Your SIEM generates 500 alerts during an overnight shift. A Tier-1 analyst's first job is to process these alerts. What is the primary activity a T1 analyst performs on each alert?",
      options: [
        "Reverse engineer the malware associated with each alert",
        "Triage the alert — determine whether it is a real threat (True Positive) or a false alarm (False Positive)",
        "Immediately escalate every alert to Tier-3 for expert analysis",
        "Write a new detection rule in the SIEM to prevent the alert from appearing again",
      ],
      answer: 1,
      explanation:
        "Triage is the T1 analyst's core function. The word 'triage' comes from medicine (sorting patients by urgency) — in a SOC it means quickly assessing each alert to decide whether it represents a real threat or a harmless false positive. T1 analysts follow playbooks to perform this assessment efficiently. Writing new detection rules is a T3/senior analyst task; reverse engineering malware is a specialist task; blindly escalating everything would overwhelm T2/T3.",
      xp: 20,
    },

    // ------------------------------------------------------------------
    // Question 2
    // ------------------------------------------------------------------
    {
      type: "question" as const,
      id: "soc-struct-q2",
      question:
        "MTTD stands for Mean Time to Detect. According to IBM's 2023 Cost of a Data Breach Report, what was the global average MTTD?",
      options: [
        "4 hours — most breaches are detected within a working day",
        "14 days — about two weeks from intrusion to detection",
        "204 days — nearly seven months from intrusion to detection",
        "365 days — attackers typically remain undetected for a full year",
      ],
      answer: 2,
      explanation:
        "The global average MTTD was 204 days in 2023 — meaning attackers were inside organisations for nearly seven months before being discovered. This is a shocking figure that highlights the importance of proactive threat hunting (a T3 function) and tuning SIEM detection rules. A high MTTD means attackers have more time to steal data, move laterally, and cause damage before anyone notices.",
      xp: 20,
    },

    // ------------------------------------------------------------------
    // Question 3
    // ------------------------------------------------------------------
    {
      type: "question" as const,
      id: "soc-struct-q3",
      question:
        "A SOC is investigating a confirmed ransomware outbreak. The malware has spread to 12 workstations and the attacker's tools are still running. Which tier of analyst is best suited to lead this response, and why?",
      options: [
        "Tier 1 — they handle all incoming alerts and should manage this case",
        "Tier 2 — they handle escalated incidents and can determine scope and implement containment",
        "The SIEM system — it can automatically resolve ransomware outbreaks",
        "The SOC Manager — they should personally investigate every serious incident",
      ],
      answer: 1,
      explanation:
        "A confirmed, active, multi-system ransomware outbreak is a serious incident requiring deep investigation — this is Tier-2 territory. T2 analysts perform deep-dive investigations, determine scope (how many systems are affected), and implement containment (e.g., isolating infected machines from the network). The SIEM detects; it does not remediate. The SOC Manager oversees team operations but does not personally handle every investigation. If the attack is extremely sophisticated (e.g., nation-state level), T2 would escalate to T3.",
      xp: 25,
    },

    // ------------------------------------------------------------------
    // Log Analysis Task
    // ------------------------------------------------------------------
    {
      type: "log_analysis" as const,
      id: "soc-struct-la1",
      heading: "T1 Analyst Scenario: Reviewing an Authentication Alert",
      context:
        "You are a Tier-1 SOC analyst at GlobalBank. It is 3:47 AM and your SIEM has fired an alert. The log below is a Windows Security Event from the Domain Controller (DC01-CORP) — the central server that manages all user logins. Review the event fields carefully and answer the questions as if you are triaging this alert in real time.",
      event: socStructureEvent,
      questions: [
        {
          question:
            "The FailureCount field shows 47 failed login attempts in 2 minutes 33 seconds (FailuresPerMinute: 18). What type of attack does this pattern strongly suggest?",
          options: [
            "Phishing attack — the user clicked a malicious link in an email",
            "Ransomware attack — the attacker is encrypting files on the server",
            "Brute-force / credential stuffing attack — automated tool is rapidly trying many passwords",
            "Insider threat — an employee is deliberately causing login failures",
          ],
          answer: 2,
          explanation:
            "18 failed login attempts per minute is a rate no human can achieve manually — this is automated. A brute-force attack uses software to rapidly try thousands of username/password combinations. At this rate, a tool is systematically trying different passwords for the 'jsmith' account. The AlertThreshold was 10 failures per minute — the SIEM fired the alert when the attacker's rate exceeded that threshold.",
          xp: 20,
        },
        {
          question:
            "The IpAddress field shows '185.220.101.47' and the GeoLocation_ISP field shows 'Tor Exit Node'. What does this tell you, and how should it affect your triage decision?",
          options: [
            "Tor is a legitimate corporate VPN — this is normal employee remote access",
            "Tor is an anonymisation network used to hide attacker identity — this is a significant indicator of malicious intent",
            "The IP address belongs to GlobalBank's office in Amsterdam — this is an employee working from there",
            "Tor exit nodes are used by Microsoft for system updates — this is expected traffic",
          ],
          answer: 1,
          explanation:
            "The Tor (The Onion Router) network is commonly used by attackers to anonymise their traffic and hide their true location. While Tor has legitimate uses (journalists, activists), seeing a Tor Exit Node as the source of 47 failed login attempts against a bank's domain controller at 3:47 AM is a very strong indicator of a malicious attack — not legitimate employee access. This finding would significantly raise the severity of your triage assessment.",
          xp: 25,
        },
      ],
    },

    // ------------------------------------------------------------------
    // Matching Task — SOC Tools and Functions
    // ------------------------------------------------------------------
    {
      type: "matching" as const,
      id: "soc-struct-m1",
      heading: "Match SOC Tools to Their Primary Function",
      instructions: "Every SOC relies on a core toolset. Match each tool on the left to the job it performs on the right.",
      pairs: [
        {
          id: "siem",
          left: "SIEM",
          right: "Collects logs from every source and correlates them into unified alerts",
        },
        {
          id: "edr",
          left: "EDR",
          right: "Records every process, file, and network action on endpoint devices",
        },
        {
          id: "soar",
          left: "SOAR",
          right: "Automates repetitive triage steps — IP lookups, ticket creation, device isolation",
        },
        {
          id: "fw",
          left: "Firewall / IPS",
          right: "Inspects and blocks network traffic between network zones",
        },
      ],
      explanation: "SOC analysts work with all four of these tools daily. The SIEM is the central console — it is usually the first alert an analyst sees. EDR provides deep endpoint visibility so you can see exactly what a process did. SOAR reduces manual work on repetitive tasks. The Firewall / IPS is both a preventative control and a log source that tells you who talked to whom on the network.",
      xp: 25,
    },

    // ------------------------------------------------------------------
    // Question 4 — Additional
    // ------------------------------------------------------------------
    {
      type: "question" as const,
      id: "soc-struct-q4",
      question:
        "Which SOC tool would an analyst use to automatically look up a suspicious IP address in threat intelligence databases, quarantine a device, and open a ticket — all without manually clicking through each step?",
      options: [
        "SIEM (Security Information and Event Management) — it collects and correlates logs",
        "EDR (Endpoint Detection and Response) — it monitors processes on individual devices",
        "SOAR (Security Orchestration, Automation, and Response) — it automates repetitive response tasks via playbooks",
        "TIP (Threat Intelligence Platform) — it stores intelligence about known malicious actors",
      ],
      answer: 2,
      explanation:
        "SOAR platforms automate repetitive SOC tasks through 'playbooks' — predefined sequences of actions that trigger automatically when certain conditions are met. Instead of an analyst spending 10 minutes manually checking an IP and opening a ticket, the SOAR does it in seconds. This dramatically reduces MTTR (Mean Time to Respond) and frees analysts to focus on tasks that require human judgment. SIEM collects logs; EDR monitors endpoints; TIP provides threat intelligence — none of these automate response actions.",
      xp: 15,
    },
  ],
};

// ---------------------------------------------------------------------------
// Room 3 — Cyber Kill Chain
// ---------------------------------------------------------------------------

const killChainEvent: TelemetryEvent = {
  id: "evt-ckc-001",
  ts: "2024-05-22T02:11:44.003Z",
  source: "firewall",
  vendor: "Palo Alto Networks",
  event_type: "net_connection",
  severity: "critical",
  hostname: "WORKSTATION-FIN-07",
  user_email: "carlos.mendez@targetcorp.com",
  description: "Outbound connection to known C2 infrastructure — high beacon frequency",
  mitre_technique: "T1071.001",
  mitre_tactic: "Command and Control",
  src_ip: "10.20.5.107",
  dst_ip: "91.92.248.115",
  dst_port: 443,
  protocol: "HTTPS",
  geo: {
    country: "Russia",
    city: "Moscow",
    latitude: 55.7558,
    longitude: 37.6173,
  },
  raw: {
    rule: "ALLOW_OUTBOUND_WEB",
    action: "allow",
    app: "ssl",
    category: "web-browsing",
    from: "trust",
    to: "untrust",
    inbound_if: "ethernet1/1",
    outbound_if: "ethernet1/2",
    src: "10.20.5.107",
    dst: "91.92.248.115",
    dport: 443,
    sport: 54921,
    proto: "6",
    bytes: 2048,
    bytes_sent: 512,
    bytes_received: 1536,
    packets: 12,
    pkts_sent: 4,
    pkts_received: 8,
    session_id: "2847391",
    flags: "0x400000",
    start: "2024-05-22T02:11:44.003Z",
    elapsed: 30,
    repeatcount: 1,
    app_category: "general-internet",
    threat_name: "Suspicious-TLS-Beacon-Pattern",
    threat_id: "30001",
    threat_category: "network-traffic-anomaly",
    severity: "critical",
    direction: "client-to-server",
    tls_version: "TLSv1.3",
    tls_cipher: "TLS_AES_256_GCM_SHA384",
    ja3_hash: "51c64c77e60f3980eea90869b68c58a8",
    beacon_interval_seconds: 30,
    beacon_jitter_percent: 10,
    total_beacons_last_hour: 121,
    domain: "updates.microsoft-cdn-services.net",
    domain_age_days: 14,
    dns_category: "newly_registered_domain",
    url_filtering_category: "malware",
    serial: "009401002233",
    vsys: "vsys1",
    logtype: "THREAT",
  },
};

const killChainRoom = {
  id: "cyber-kill-chain",
  title: "Cyber Kill Chain",
  description:
    "Master the Cyber Kill Chain — Lockheed Martin's 7-stage model of how cyber attacks unfold from initial planning to final impact. Learn to identify and disrupt attacks at every stage.",
  difficulty: "beginner" as const,
  category: "Threat Detection",
  estimatedMinutes: 42,
  xp: 350,
  icon: "⛓️",
  prerequisites: ["intro-cybersecurity", "soc-structure"],
  tasks: [
    // ------------------------------------------------------------------
    // Reading 1 — What Is the Kill Chain?
    // ------------------------------------------------------------------
    {
      type: "reading" as const,
      id: "ckc-r1",
      heading: "What Is the Cyber Kill Chain?",
      content: `Imagine you want to rob a bank. You would not just walk in and demand money — you would plan carefully. First, you would **research** the bank (when does it open? where are the cameras?). Then you would **prepare your tools** (get a getaway car, acquire disguises). Then you would **execute the robbery** in stages. A detective investigating the robbery would find evidence at each stage of your planning and execution — and if they had caught any clue early enough, they could have stopped the crime before it happened.

Cyber attacks work the same way. Attackers — whether they are lone criminals or sophisticated nation-state groups — follow a predictable sequence of steps when conducting an attack. Understanding this sequence gives defenders seven opportunities to detect and stop an attack before it achieves its goal.

**The Cyber Kill Chain** was developed by **Lockheed Martin** — one of the world's largest defence contractors — and published in a 2011 white paper titled "Intelligence-Driven Computer Network Defense." The framework was adapted from military targeting models used in conventional warfare ("kill chain" is a military term for the sequence of actions from identifying a target to destroying it).

**The core insight:** Every successful cyberattack must complete all stages of the kill chain to achieve its objective. If a defender can **break the chain** at *any* stage, the attack fails. This is fundamentally different from the older mindset of "build a wall and keep attackers out" — instead, it assumes attackers will get past some defences and focuses on detecting and disrupting them at every possible stage.

**The 7 Stages of the Cyber Kill Chain**

1. **Reconnaissance** — Research and information gathering
2. **Weaponization** — Building the attack tool
3. **Delivery** — Getting the weapon to the target
4. **Exploitation** — Triggering the attack
5. **Installation** — Establishing a foothold
6. **Command and Control (C2)** — Setting up remote control
7. **Actions on Objectives** — Achieving the final goal

Let's explore each stage with a real-world example: the **SolarWinds attack by APT29** (Russia's SVR intelligence service), which is widely considered one of the most sophisticated cyberattacks in history.

**Limitations of the Kill Chain**
The Kill Chain model is powerful but not perfect. It was designed primarily for perimeter-based, external attacks — and has some well-known limitations:
- **Insider threats** do not follow the kill chain — an employee with direct access skips most stages
- **Lateral movement** (an attacker spreading within a network after initial access) is not explicitly modelled
- **Cloud and SaaS attacks** may look very different from the traditional kill chain
- The model is **linear** — real attacks often involve multiple kill chains or iterations

Despite these limitations, the Cyber Kill Chain remains one of the most influential frameworks in cybersecurity and is used in threat intelligence, incident response, and detection engineering worldwide. It laid the groundwork for more modern frameworks like MITRE ATT&CK, which we will cover in Room 4.`,
    },

    // ------------------------------------------------------------------
    // Reading 2 — The 7 Stages In Depth
    // ------------------------------------------------------------------
    {
      type: "reading" as const,
      id: "ckc-r2",
      heading: "The 7 Stages: From Reconnaissance to Actions on Objectives",
      content: `Let's walk through each stage of the Cyber Kill Chain using the SolarWinds attack as our example. APT29 (also known as "Cozy Bear") is a Russian intelligence cyber unit that conducted this attack from roughly 2019 to 2020.

**Stage 1: Reconnaissance**
*The attacker learns about the target.*

Reconnaissance is the intelligence-gathering phase. Attackers research their target to identify:
- Which software and technologies does the target use?
- Who are the key employees? (LinkedIn, company websites)
- What vulnerabilities exist in the target's public-facing systems?
- Who are the target's trusted vendors and suppliers?

**SolarWinds example:** APT29 identified that SolarWinds' Orion software was used by thousands of high-value targets (US government agencies, Fortune 500 companies). They researched SolarWinds' software development process to understand how updates were built and distributed.

*Defensive actions at this stage:* Minimise publicly available information about your internal systems (don't advertise your tech stack); use web application firewalls to block automated scanning tools; monitor for reconnaissance patterns.

**Stage 2: Weaponization**
*The attacker builds or acquires their weapon.*

In this stage, the attacker creates the malicious tool they will use to attack. This might be custom malware written from scratch, a modified version of existing hacking tools, or simply a phishing email template paired with a malicious document.

**SolarWinds example:** APT29 created **SUNBURST** — a sophisticated backdoor program designed to look like a legitimate part of the Orion software. They spent months engineering it to evade detection, including a 14-day dormancy period (it would not activate for two weeks after installation, to avoid triggering automated sandboxes).

*Defensive actions:* Intelligence about attacker tools from threat intelligence feeds; code signing (verifying that software has not been tampered with).

**Stage 3: Delivery**
*The weapon reaches the target.*

This is how the attacker gets their malicious tool in front of the victim. Common delivery mechanisms include phishing emails, malicious websites, infected USB drives, and — as in SolarWinds — **supply chain compromise** (hiding malware in a legitimate software update).

**SolarWinds example:** APT29 compromised SolarWinds' software build system. When SolarWinds released an Orion update (version 2019.4 through 2020.2.1), the update contained SUNBURST. When 18,000 organisations installed the legitimate-looking update, they unknowingly installed the backdoor.

*Defensive actions:* Email filtering; user security awareness training; software supply chain verification (cryptographic hashes to verify update integrity).

**Stage 4: Exploitation**
*The weapon is triggered.*

Exploitation is when the malicious code executes. In the SolarWinds case, exploitation was automatically triggered when IT administrators installed the Orion update — the SUNBURST code ran as part of the installation process.

*Defensive actions:* Patch management (keeping systems up to date); disabling macros in Office documents; endpoint protection platforms.

**Stage 5: Installation**
*The attacker establishes a persistent foothold.*

After exploitation, attackers typically install mechanisms to maintain access — even if the system is rebooted or the user changes their password. This is called **persistence**. Common techniques include:
- Creating new Windows **scheduled tasks**
- Adding **registry run keys** (code that automatically runs when Windows starts)
- Installing a **web shell** on a web server (a backdoor disguised as a web page)
- Creating **new user accounts** with administrator privileges

**SolarWinds example:** SUNBURST installed itself as a service within the SolarWinds Orion application, ensuring it would run automatically with every Orion startup.

*Defensive actions:* Monitor for new scheduled tasks; registry change detection; EDR tools that track persistence mechanisms.

**Stage 6: Command and Control (C2)**
*The attacker sets up a remote control channel.*

With malware installed, the attacker needs a way to issue commands to the compromised system and receive data from it. The C2 channel is essentially a remote control for the infected machine.

Modern C2 channels are designed to blend in with legitimate traffic. **APT29** had SUNBURST communicate over HTTPS (the same protocol used by normal web browsing) to disguise C2 traffic as regular internet activity.

Popular C2 frameworks used by both attackers and penetration testers include: **Cobalt Strike**, **Metasploit**, **Havoc**, **Sliver**.

*Defensive actions:* DNS monitoring for unusual domains; monitoring for beaconing behaviour (regular outbound connections at fixed intervals); network segmentation; traffic inspection.

**Stage 7: Actions on Objectives**
*The attacker achieves their goal.*

The final stage is when the attacker does what they came to do. Goals vary by attacker type:
- **Cybercriminals:** Encrypt files (ransomware), steal financial data, sell access to other criminals
- **Nation-states:** Exfiltrate sensitive documents, conduct espionage, sabotage infrastructure
- **Hacktivists:** Deface websites, leak internal documents (doxing)
- **Insiders:** Delete data, plant backdoors for future use

**SolarWinds example:** APT29 used SUNBURST to conduct espionage — accessing internal emails, documents, and communications of US government agencies. They were inside some networks for over a year before being discovered.

*Defensive actions:* Data loss prevention (DLP) systems; monitoring for large data transfers; user behaviour analytics (UEBA) to detect anomalous access patterns.`,
    },

    // ------------------------------------------------------------------
    // Reading 3 — Breaking the Chain
    // ------------------------------------------------------------------
    {
      type: "reading" as const,
      id: "ckc-r3",
      heading: "Breaking the Chain: How Defenders Fight Back",
      content: `The Cyber Kill Chain's most important insight is this: **defenders don't need to stop 100% of attacks — they need to break the chain at one stage, anywhere**. An attacker who completes Stage 6 (Command and Control) but is caught and blocked before Stage 7 (Actions on Objectives) has failed. The damage is minimal; the defender wins.

This changes how security teams think about defence. Rather than asking "how do we stop every attack from ever happening?" (impossible), they ask "where can we detect and disrupt attacks most effectively?" (achievable).

**The concept of Defence in Depth**
Just as a medieval castle had multiple defensive layers (moat, drawbridge, walls, inner keep, guards), a mature security architecture has controls at every stage of the kill chain. This is called **Defence in Depth** (DiD) — no single control is relied upon; multiple layers ensure that even if one fails, others catch the attacker.

**A Kill Chain defence matrix:**

| Stage | Attacker Action | Defender Control |
|---|---|---|
| Reconnaissance | OSINT scanning, target research | Web scrubbing, honeypots |
| Weaponization | Building malware | Threat intelligence |
| Delivery | Phishing email, malicious update | Email filtering, supply chain controls |
| Exploitation | Code execution | Patch management, EDR |
| Installation | Malware persistence | Registry/task monitoring, AV |
| C2 | Beacon to attacker server | DNS monitoring, NGFW |
| Actions on Objectives | Data theft, encryption | DLP, UEBA, backup systems |

**Comparing the Kill Chain to other frameworks**

The Kill Chain is not the only way to model attacker behaviour. Two other important frameworks are:

**The Diamond Model of Intrusion Analysis** — Developed in 2013, this model focuses on the *relationship* between four elements of every intrusion: Adversary (who is attacking), Infrastructure (what they are using), Capability (the tools and techniques), and Victim (the target). Where the Kill Chain shows you *when* something happens, the Diamond Model helps you understand *who* is doing it and *why*.

**MITRE ATT&CK** — We will cover this in depth in Room 4, but briefly: MITRE ATT&CK is a much more granular framework that catalogues hundreds of specific attack techniques. If the Kill Chain is a roadmap of a road trip (7 major stops), MITRE ATT&CK is a detailed turn-by-turn GPS with hundreds of alternative routes. The Kill Chain answers "which phase of the attack are we in?" while ATT&CK answers "which specific technique is the attacker using?"

**When to use the Kill Chain in your SOC career:**
- When writing **incident reports** — you map each observed attacker action to a kill chain stage, which helps communicate what happened clearly to non-technical management
- When building **detection rules** — asking "which kill chain stage does this SIEM rule cover?" helps ensure your detection coverage spans the whole chain
- When doing **threat hunting** — if you know an attacker has reached Stage 5 (Installation), you know to look for Stage 6 (C2) beaconing behaviour next
- When communicating with **executives** — the kill chain narrative ("the attacker got in through a phishing email, spent 3 months establishing persistence, and was caught before they could steal data") tells a compelling story that non-technical leaders can understand`,
    },

    // ------------------------------------------------------------------
    // Question 1
    // ------------------------------------------------------------------
    {
      type: "question" as const,
      id: "ckc-q1",
      question:
        "An attacker sends a fake invoice email to an accountant. The email contains a Word document with malicious macros. When the accountant opens the document and enables macros, the malware executes. Which Kill Chain stage does the attacker move into when the accountant enables the macros?",
      options: [
        "Stage 2 — Weaponization (the attacker is building the malicious document)",
        "Stage 3 — Delivery (the email is reaching the victim's inbox)",
        "Stage 4 — Exploitation (the malicious macro code executes on the victim's system)",
        "Stage 5 — Installation (the malware is installing persistence mechanisms)",
      ],
      answer: 2,
      explanation:
        "Exploitation is the moment the malicious code actually runs on the victim's system. When the accountant opens the document and enables macros, the attacker's code triggers — this is exploitation. Weaponization (Stage 2) happened earlier when the attacker created the malicious document. Delivery (Stage 3) happened when the email arrived in the inbox. Installation (Stage 5) would come next — after exploitation, the malware typically installs itself for persistence.",
      xp: 20,
    },

    // ------------------------------------------------------------------
    // Question 2
    // ------------------------------------------------------------------
    {
      type: "question" as const,
      id: "ckc-q2",
      question:
        "A threat hunter notices that a workstation on the company network is making an outbound HTTPS connection to an external server every exactly 30 seconds, around the clock — even at 3 AM when no employees are working. What Kill Chain stage is this most consistent with, and what should the hunter do?",
      options: [
        "Stage 1 — Reconnaissance. The attacker is scanning the company network.",
        "Stage 3 — Delivery. A phishing email attachment is being downloaded.",
        "Stage 6 — Command and Control. The regular 30-second intervals ('beaconing') suggest malware communicating with an attacker's C2 server.",
        "Stage 7 — Actions on Objectives. Data is being exfiltrated continuously.",
      ],
      answer: 2,
      explanation:
        "Regular, automated connections at fixed intervals — called 'beaconing' — are the hallmark of Command and Control (C2) malware. The malware checks in with the attacker's server at regular intervals to receive new instructions. The 30-second interval, continuing through the night when no user is active, is impossible human behaviour and strongly suggests automated malware. The threat hunter should immediately investigate the destination IP, isolate the workstation, and escalate to Tier-2 for full incident response.",
      xp: 25,
    },

    // ------------------------------------------------------------------
    // Question 3 — Scenario Based
    // ------------------------------------------------------------------
    {
      type: "question" as const,
      id: "ckc-q3",
      question:
        "During a forensic investigation, analysts find that an attacker created a new Windows Scheduled Task called 'WindowsUpdateHelper' that runs a malicious script every time the system starts. The script connects back to an external server. Which Kill Chain stage does this creation of a Scheduled Task represent?",
      options: [
        "Stage 2 — Weaponization (creating the malicious tool)",
        "Stage 4 — Exploitation (triggering the initial attack)",
        "Stage 5 — Installation (establishing persistence on the system)",
        "Stage 6 — Command and Control (communicating with the attacker's server)",
      ],
      answer: 2,
      explanation:
        "Creating a Scheduled Task designed to run automatically on system startup is a classic persistence technique — this is Stage 5 (Installation). The attacker is ensuring their malware survives reboots and maintains access even if the user changes their password. The naming ('WindowsUpdateHelper') is deliberate camouflage — making the task look like a legitimate Windows component. Note that the script also connects to an external server, which is Stage 6 (C2), but the *scheduled task creation itself* is the Installation/persistence action.",
      xp: 25,
    },

    // ------------------------------------------------------------------
    // Log Analysis Task
    // ------------------------------------------------------------------
    {
      type: "log_analysis" as const,
      id: "ckc-la1",
      heading: "Kill Chain in Action: Identifying C2 Communication",
      context:
        "You are a threat hunter at TargetCorp. Your SIEM has flagged a critical-severity network event from your Palo Alto Networks next-generation firewall (NGFW). The firewall detected suspicious outbound traffic from a finance department workstation. Review the log carefully — pay particular attention to the destination IP geolocation and the beacon_interval_seconds / total_beacons_last_hour fields.",
      event: killChainEvent,
      questions: [
        {
          question:
            "The firewall log shows 'beacon_interval_seconds: 30' and 'total_beacons_last_hour: 121' — the workstation connects to the same external IP roughly every 30 seconds, all day. Which Kill Chain stage does this pattern represent?",
          options: [
            "Stage 3 — Delivery. This is a phishing email attachment being downloaded.",
            "Stage 5 — Installation. The workstation is creating a scheduled task on disk.",
            "Stage 6 — Command and Control. Regular, machine-speed connections at a fixed interval ('beaconing') indicate malware checking in with an attacker-controlled server.",
            "Stage 7 — Actions on Objectives. This traffic pattern shows data actively being exfiltrated.",
          ],
          answer: 2,
          explanation:
            "A 'beacon' is a periodic check-in a compromised host makes to its Command and Control (C2) server, waiting for further instructions. No legitimate user-driven application connects to the same external IP every 30 seconds around the clock — that regularity is the signature of automated malware, not human browsing. 121 beacons in one hour at a fixed 30-second interval is textbook Stage 6 (Command and Control) behaviour, not Delivery (getting the payload in), Installation (persistence on disk), or Actions on Objectives (the final goal itself).",
          xp: 25,
        },
        {
          question:
            "The domain field shows 'updates.microsoft-cdn-services.net' and dns_category shows 'newly_registered_domain' (registered only 14 days ago). The destination IP geolocates to Moscow, Russia. What technique is the attacker using, and what is the significance of the domain name?",
          options: [
            "The domain is legitimate — Microsoft CDN servers are sometimes located in Russia",
            "The attacker is using domain squatting and typosquatting — the domain mimics Microsoft's naming to evade detection, while the recent registration and Russian IP confirm it is malicious infrastructure",
            "The 14-day domain age indicates the attacker is a beginner who just started this operation today",
            "Newly registered domains are automatically safe because they have no reputation history",
          ],
          answer: 1,
          explanation:
            "The domain 'updates.microsoft-cdn-services.net' is designed to look like a legitimate Microsoft CDN (Content Delivery Network) domain — a technique called 'typosquatting' or 'domain impersonation'. The attacker hopes that security tools scanning network traffic will see 'microsoft' in the domain name and assume it is legitimate. However, the 14-day registration age (legitimate Microsoft infrastructure is years old), the Russian geolocation of the IP, and the firewall's 'malware' URL category all expose the deception. Real Microsoft CDN servers do not use third-party .net domains like this.",
          xp: 20,
        },
      ],
    },

    // ------------------------------------------------------------------
    // Ordering Task — Cyber Kill Chain Stages
    // ------------------------------------------------------------------
    {
      type: "ordering" as const,
      id: "ckc-o1",
      heading: "Order the Cyber Kill Chain",
      instructions: "Arrange the 7 stages of the Lockheed Martin Cyber Kill Chain in the correct sequence — from the very first attacker action to the final goal. Select an item, then click its numbered slot.",
      items: [
        { id: "recon",     text: "Reconnaissance — researching the target: employees, technologies, IP ranges" },
        { id: "weapon",    text: "Weaponization — building the attack tool: malicious macro, exploit payload" },
        { id: "delivery",  text: "Delivery — sending the weapon to the target: phishing email, watering hole" },
        { id: "exploit",   text: "Exploitation — triggering the vulnerability to execute code on the victim" },
        { id: "install",   text: "Installation — planting a backdoor or RAT to survive reboots" },
        { id: "c2",        text: "Command and Control — malware beacons out to the attacker for instructions" },
        { id: "actions",   text: "Actions on Objectives — the attacker achieves their goal: data theft, encryption" },
      ],
      correct_order: ["recon", "weapon", "delivery", "exploit", "install", "c2", "actions"],
      explanation: "The Kill Chain must follow this exact sequence because each stage enables the next. You cannot deliver a weapon before you have built it, and you cannot exfiltrate data before you have C2 communication. This is why defenders focus on early stages — stopping Delivery (blocking the phishing email) prevents all 4 later stages from ever happening. Attackers who are disrupted at Delivery or Exploitation must restart from the beginning.",
      xp: 30,
    },

    // ------------------------------------------------------------------
    // Question 4 — Additional
    // ------------------------------------------------------------------
    {
      type: "question" as const,
      id: "ckc-q4",
      question:
        "The Cyber Kill Chain is a powerful framework but has acknowledged limitations. Which of the following is a recognised weakness of the Kill Chain model?",
      options: [
        "It was created by a private company (Lockheed Martin) and therefore cannot be used by government agencies",
        "It only applies to ransomware attacks and cannot model other types of threats",
        "It does not adequately model insider threats, because an authorised user with direct access can skip most of the early stages",
        "It requires a minimum of 3 analysts to use correctly and is too complex for small SOC teams",
      ],
      answer: 2,
      explanation:
        "The Cyber Kill Chain's biggest limitation is its poor coverage of insider threats. An employee with legitimate access to systems can skip Stages 1–5 entirely and jump straight to Stage 7 (Actions on Objectives) — walking straight to a file server and copying sensitive data, for example. The Kill Chain was designed with external attackers in mind. MITRE ATT&CK and the UEBA (User and Entity Behaviour Analytics) framework are better tools for detecting insider threats. This limitation is important for SOC analysts to understand so they do not over-rely on any single framework.",
      xp: 15,
    },
  ],
};

// ---------------------------------------------------------------------------
// Room 4 — MITRE ATT&CK Framework
// ---------------------------------------------------------------------------

const mitreAttackEvent: TelemetryEvent = {
  id: "evt-mitre-001",
  ts: "2024-06-10T09:33:15.772Z",
  source: "ad",
  vendor: "Microsoft Entra ID",
  event_type: "auth_failure",
  severity: "high",
  hostname: "ENTRA-CLOUD",
  user_email: "admin.service@fintech-global.com",
  description: "Password spray attack detected — single password tried against many accounts",
  mitre_technique: "T1110.003",
  mitre_tactic: "Credential Access",
  src_ip: "5.188.206.201",
  geo: {
    country: "Ukraine",
    city: "Kyiv",
    latitude: 50.4501,
    longitude: 30.5234,
  },
  raw: {
    OperationName: "Sign-in activity",
    ResultType: "50126",
    ResultDescription: "Invalid username or password",
    CallerIpAddress: "5.188.206.201",
    CorrelationId: "b7c8d9e0-f1a2-b3c4-d5e6-f7a8b9c0d1e2",
    InitiatedBy: {
      user: {
        id: null,
        displayName: null,
        userPrincipalName: null,
        ipAddress: "5.188.206.201",
      },
    },
    TargetResources: [
      { userPrincipalName: "alice.brown@fintech-global.com" },
      { userPrincipalName: "bob.smith@fintech-global.com" },
      { userPrincipalName: "carol.white@fintech-global.com" },
      { userPrincipalName: "david.jones@fintech-global.com" },
      { userPrincipalName: "emily.davis@fintech-global.com" },
      { userPrincipalName: "admin.service@fintech-global.com" },
      { userPrincipalName: "helpdesk@fintech-global.com" },
      { userPrincipalName: "hr.manager@fintech-global.com" },
    ],
    PasswordAttempted: "Winter2024!",
    UniqueAccountsTargeted: 8,
    UniquePasswordsUsed: 1,
    AttemptsPerAccount: 1,
    TotalAttempts: 8,
    TimeWindowMinutes: 3,
    AuthenticationMethod: "UsernamePassword",
    ClientAppUsed: "Browser",
    DeviceDetail: {
      operatingSystem: "Linux",
      browser: "Python-Requests/2.31.0",
    },
    ConditionalAccessStatus: "notApplied",
    IsInteractive: false,
    TokenIssuerType: "AzureAD",
    UserAgent: "python-requests/2.31.0",
    Location: {
      city: "Kyiv",
      countryOrRegion: "UA",
      geoCoordinates: {
        latitude: 50.4501,
        longitude: 30.5234,
      },
    },
    RiskState: "atRisk",
    RiskLevel: "high",
    RiskDetail: "adminConfirmedSigninCompromised",
    DetectionSource: "MicrosoftCloudAppSecurity",
    AlertId: "ALERT-2024-061047832",
  },
};

const mitreAttackRoom = {
  id: "mitre-attack",
  title: "MITRE ATT&CK Framework",
  description:
    "Learn the MITRE ATT&CK framework — the world's most comprehensive catalogue of real-world attack techniques. Understand how to use it for threat detection, threat hunting, and building better defences.",
  difficulty: "beginner" as const,
  category: "Threat Intelligence",
  estimatedMinutes: 45,
  xp: 380,
  icon: "🎯",
  prerequisites: ["intro-cybersecurity", "soc-structure", "cyber-kill-chain"],
  tasks: [
    // ------------------------------------------------------------------
    // Reading 1 — What Is MITRE ATT&CK?
    // ------------------------------------------------------------------
    {
      type: "reading" as const,
      id: "mitre-r1",
      heading: "What Is MITRE ATT&CK? The World's Attack Encyclopedia",
      content: `Imagine a library with thousands of books, each describing a specific technique a burglar might use to break into a house: picking the lock, breaking a window, bribing a security guard, copying a key, disabling the alarm system, hiding in the delivery van... Each book covers one technique in detail: how it works, what tools the burglar uses, what evidence they leave behind, and how to stop it.

**MITRE ATT&CK** is exactly that library — but for cyberattacks.

**MITRE** (pronounced "My-ter") is a US non-profit research organisation that works with government, industry, and academia. In 2013, MITRE began systematically documenting real cyberattack techniques observed in the wild — specifically looking at what attackers do *after* they get inside a network (post-compromise behaviour). The resulting database was published as **ATT&CK** — which stands for **Adversarial Tactics, Techniques, and Common Knowledge**.

The key word is "Common Knowledge" — the entire database is **free and publicly available** at attack.mitre.org. This is revolutionary: before ATT&CK, knowledge about attacker techniques was scattered across private threat intelligence reports, academic papers, and individual analysts' experience. ATT&CK standardised the language and made it accessible to the entire security community.

**How big is it?**
As of 2024, ATT&CK for Enterprise (the version covering Windows, macOS, Linux, and cloud environments) contains:
- **14 Tactics** (the high-level attacker goals)
- **202 Techniques** (specific methods to achieve each goal)
- **435 Sub-techniques** (more specific variations of techniques)
- **Profiles for 137+ threat actor groups** (documented real-world adversary behaviour)

**Why is ATT&CK better than just the Kill Chain?**
The Cyber Kill Chain (from Room 3) gives you 7 broad phases. ATT&CK gives you granular detail. If the Kill Chain says "Stage 6: Command and Control," ATT&CK has an entire category of C2 techniques with dozens of entries: Web Protocols (T1071.001), DNS (T1071.004), Application Layer Protocol (T1071), and more — each with detection guidance, mitigation advice, and real attacker examples.

**Three ATT&CK matrices**
ATT&CK is organised into three separate matrices for different environments:
- **ATT&CK for Enterprise** — Windows, macOS, Linux, and cloud environments. This is what most SOC analysts use daily.
- **ATT&CK for Mobile** — Android and iOS devices
- **ATT&CK for ICS** — Industrial Control Systems (power plants, water treatment, manufacturing)

**The standard notation**
Every technique in ATT&CK has a unique ID:
- Techniques: **T1566** (Phishing), **T1110** (Brute Force)
- Sub-techniques: **T1566.001** (Phishing: Spearphishing Attachment), **T1110.003** (Brute Force: Password Spraying)

When you see "T1566.001" in a log, an alert, or a threat intelligence report, you know exactly which attack technique is being referenced. This standardised language is one of ATT&CK's greatest contributions — security teams across the world now speak the same vocabulary.`,
    },

    // ------------------------------------------------------------------
    // Reading 2 — The 14 Tactics and How to Read a Technique
    // ------------------------------------------------------------------
    {
      type: "reading" as const,
      id: "mitre-r2",
      heading: "The 14 Tactics: ATT&CK's Attack Roadmap",
      content: `ATT&CK is organised into **Tactics** and **Techniques**. Here is the crucial distinction:

- **Tactic** = the attacker's *goal* at a given moment (the "why")
- **Technique** = the *method* the attacker uses to achieve that goal (the "how")
- **Sub-technique** = a more specific variant of a technique

**Think of it like cooking:** The Tactic is "feed your guests" (the goal). The Technique is "make pasta" (one method to achieve the goal). The Sub-technique is "make spaghetti carbonara" (a specific variant of pasta).

**The 14 ATT&CK Tactics (in order of attack progression)**

**1. Reconnaissance (TA0043)**
The attacker gathers information before attacking: scanning for open ports, researching employees on LinkedIn, looking for known vulnerabilities in the target's software. Example technique: T1595 Active Scanning.

**2. Resource Development (TA0042)**
The attacker prepares their infrastructure: registering attack domains, acquiring VPS servers, building or purchasing malware. Example technique: T1583 Acquire Infrastructure.

**3. Initial Access (TA0001)**
The attacker gets their first foothold inside the target environment. Example techniques: T1566 Phishing, T1190 Exploit Public-Facing Application, T1078 Valid Accounts.

**4. Execution (TA0002)**
The attacker runs malicious code. Example techniques: T1059 Command and Scripting Interpreter (e.g., PowerShell), T1204 User Execution (tricking a user into running something).

**5. Persistence (TA0003)**
The attacker ensures they can get back in even if the system restarts or their access is discovered. Example techniques: T1053 Scheduled Task/Job, T1547 Boot or Logon Autostart Execution.

**6. Privilege Escalation (TA0004)**
The attacker gains higher permissions (e.g., becoming a system administrator). Example techniques: T1548 Abuse Elevation Control Mechanism, T1055 Process Injection.

**7. Defence Evasion (TA0005)**
The attacker hides their activity to avoid detection. Example techniques: T1036 Masquerading (disguising malware as legitimate software), T1070 Indicator Removal (clearing log files).

**8. Credential Access (TA0006)**
The attacker steals account credentials (usernames and passwords). Example techniques: T1110 Brute Force, T1003 OS Credential Dumping (tools like Mimikatz dump password hashes from memory).

**9. Discovery (TA0007)**
The attacker learns about the internal network after getting in: finding other systems, discovering which users have administrator rights, mapping the network. Example technique: T1083 File and Directory Discovery.

**10. Lateral Movement (TA0008)**
The attacker moves from their initial beachhead to other systems in the network, spreading their access. Example techniques: T1021 Remote Services (using RDP, SSH), T1550 Use Alternate Authentication Material (Pass-the-Hash attacks).

**11. Collection (TA0009)**
The attacker gathers the data they plan to steal. Example techniques: T1560 Archive Collected Data (compressing files before exfiltration), T1074 Data Staged.

**12. Command and Control (TA0011)**
The attacker communicates with their implants (same as Kill Chain Stage 6). Example techniques: T1071 Application Layer Protocol, T1573 Encrypted Channel.

**13. Exfiltration (TA0010)**
The attacker sends stolen data out of the network to their own infrastructure. Example techniques: T1048 Exfiltration Over Alternative Protocol, T1041 Exfiltration Over C2 Channel.

**14. Impact (TA0040)**
The attacker achieves their destructive goal: encrypting files (ransomware), wiping data, disrupting services. Example techniques: T1486 Data Encrypted for Impact (ransomware), T1529 System Shutdown/Reboot.

**How to read an ATT&CK technique page**
Every ATT&CK technique entry at attack.mitre.org contains:
- **Name and ID:** e.g., T1566.001 — Phishing: Spearphishing Attachment
- **Description:** What the technique is and how it is used
- **Procedure Examples:** Real documented cases of this technique used by specific threat groups
- **Detections:** How to detect this technique (log sources, SIEM rules, behavioural indicators)
- **Mitigations:** How to prevent or minimise the technique's effectiveness
- **Threat Group associations:** Which real-world attacker groups have been observed using this technique`,
    },

    // ------------------------------------------------------------------
    // Reading 3 — Using ATT&CK in a SOC
    // ------------------------------------------------------------------
    {
      type: "reading" as const,
      id: "mitre-r3",
      heading: "Using ATT&CK in Your SOC Career",
      content: `Knowing ATT&CK exists is one thing. Knowing how to *use* it is what separates a good analyst from a great one. Let's walk through how SOC professionals use ATT&CK every day.

**1. ATT&CK Navigator — Your Coverage Map**
The **ATT&CK Navigator** (available at mitre-attack.github.io/attack-navigator) is a free interactive tool that displays the entire ATT&CK matrix as a colour-coded grid. You can colour techniques according to:
- Which techniques your SIEM rules currently detect (coverage map)
- Which techniques a specific threat group uses (adversary emulation)
- Which techniques were observed in a recent incident (incident mapping)

**Practical use:** A SOC team can colour all the techniques covered by their current SIEM rules, then see at a glance which areas have no coverage — "blind spots" where an attacker could operate undetected. This helps prioritise where to build new detection rules.

**2. Threat Actor Profiles**
ATT&CK maintains detailed profiles of known threat groups. Let's look at **APT29 (Cozy Bear)** — the Russian intelligence group behind SolarWinds:

The APT29 profile on attack.mitre.org shows 40+ documented techniques, including:
- T1195.002 (Compromise Software Supply Chain) — the SolarWinds technique
- T1078 (Valid Accounts) — using stolen credentials
- T1071.001 (Web Protocols) — C2 over HTTPS
- T1027 (Obfuscated Files or Information) — hiding malware in legitimate code

When your organisation learns that APT29 is targeting your industry sector, you can immediately load the APT29 profile into ATT&CK Navigator and see exactly which techniques you need to detect. Then you build or tune SIEM rules for those specific techniques. This is **threat-informed defence** — letting the attacker's known playbook guide your defensive priorities.

**3. Detection Engineering**
Every ATT&CK technique includes detection guidance: which log sources to monitor, what behavioural indicators to look for, and often links to example SIEM queries. Detection engineers use this to build new detection rules systematically, ensuring rules are grounded in real attacker behaviour rather than guesswork.

**Example:** Technique T1110.003 (Password Spraying — the technique in today's log exercise) states that detection involves monitoring for "many failed authentication attempts across many different accounts from a single source IP in a short time window." This directly translates into a SIEM rule.

**4. Incident Response and Reporting**
During and after an incident, analysts use ATT&CK to document *exactly* what the attacker did:
- "The attacker used T1566.001 (Spearphishing Attachment) for Initial Access"
- "They used T1053.005 (Scheduled Task) for Persistence"
- "They used T1003.001 (LSASS Memory Dumping) for Credential Access"

This ATT&CK-tagged incident report is valuable for multiple reasons:
- Makes the report understandable to any security professional worldwide (common language)
- Enables the organisation to tune detections specifically for the attacker's observed TTPs (Tactics, Techniques, and Procedures)
- Can be shared with threat intelligence communities to help other organisations defend against the same attacker

**5. A worked example: Using ATT&CK on the log in this room**
The log event for this room's exercise shows a Microsoft Entra ID (formerly Azure AD) alert for **T1110.003 — Password Spraying**. Let's apply the ATT&CK framework:

- **Tactic:** Credential Access (TA0006) — The attacker's goal is to steal credentials
- **Technique:** T1110 — Brute Force
- **Sub-technique:** T1110.003 — Password Spraying

What is Password Spraying? Instead of trying many passwords against one account (which would lock it out), the attacker tries *one common password* against *many accounts*. This evades account lockout policies. In the log, you will see the attacker tried "Winter2024!" against 8 different accounts — classic spray behaviour.

ATT&CK's mitigation guidance for T1110.003 includes:
- Implement **Multi-Factor Authentication (MFA)** — even if the password is stolen, the attacker cannot log in without the second factor
- Enforce **account lockout policies** that detect spray patterns
- Monitor for many failures across accounts from a single IP
- Use **Conditional Access** to block logins from unusual locations or devices

This is the ATT&CK framework in action: observation → identification → detection → mitigation.`,
    },

    // ------------------------------------------------------------------
    // Question 1
    // ------------------------------------------------------------------
    {
      type: "question" as const,
      id: "mitre-q1",
      question:
        "In ATT&CK terminology, what is the difference between a Tactic and a Technique? Choose the most accurate answer.",
      options: [
        "Tactics are used by advanced attackers; techniques are used by beginners",
        "A Tactic is the attacker's high-level goal (the 'why'), while a Technique is the specific method used to achieve that goal (the 'how')",
        "Tactics are defensive actions taken by SOC analysts; techniques are offensive actions taken by attackers",
        "Tactics are numbered with T (e.g., T1566); techniques are numbered with TA (e.g., TA0001)",
      ],
      answer: 1,
      explanation:
        "In ATT&CK, Tactics (numbered TA0001 through TA0043) represent the attacker's objectives — what they are trying to accomplish at each stage of their operation. Techniques (numbered T1001, T1002, etc.) are the specific methods used to achieve those objectives. Sub-techniques add further specificity. For example, the Tactic might be 'Credential Access' (steal passwords) and the Technique might be 'T1110.003 Password Spraying' (a specific method of stealing passwords). Note: Tactics use the TA prefix; Techniques use T — the opposite of option D.",
      xp: 20,
    },

    // ------------------------------------------------------------------
    // Question 2
    // ------------------------------------------------------------------
    {
      type: "question" as const,
      id: "mitre-q2",
      question:
        "Which of the 14 ATT&CK tactics is most concerned with what happens AFTER an attacker has encrypted a company's files for ransom — the final destructive goal of their operation?",
      options: [
        "Initial Access (TA0001) — getting the first foothold into the network",
        "Persistence (TA0003) — ensuring the attacker can maintain long-term access",
        "Exfiltration (TA0010) — stealing and removing data from the network",
        "Impact (TA0040) — disrupting, destroying, or manipulating systems and data",
      ],
      answer: 3,
      explanation:
        "Impact (TA0040) is the final ATT&CK tactic, covering actions that directly harm the target's systems, data, or operations. Data Encrypted for Impact (T1486) is the specific technique for ransomware encryption. Impact includes other destructive actions like wiping disks, deleting backups, and disrupting services. Exfiltration (TA0010) covers stealing data — which is sometimes done before ransomware deployment, but the encryption itself falls under Impact.",
      xp: 20,
    },

    // ------------------------------------------------------------------
    // Question 3
    // ------------------------------------------------------------------
    {
      type: "question" as const,
      id: "mitre-q3",
      question:
        "Your SOC manager wants to improve your team's defences against APT29, a Russian threat group known to be targeting your industry. Which ATT&CK tool would you use to visualise which of APT29's known techniques are already covered by your detection rules — and which techniques represent blind spots?",
      options: [
        "The ATT&CK technique detail page — read each of APT29's 40+ technique descriptions manually",
        "ATT&CK Navigator — an interactive matrix tool that lets you colour-code techniques by coverage and adversary profile",
        "The Kill Chain framework — map APT29's stages to the 7 Kill Chain phases",
        "A SOAR playbook — automate the APT29 profile analysis and generate a report",
      ],
      answer: 1,
      explanation:
        "ATT&CK Navigator (available free at mitre-attack.github.io/attack-navigator) is specifically designed for this use case. You can load APT29's threat actor profile to see all their known techniques highlighted in the matrix, then overlay your current detection coverage to instantly visualise gaps. This 'coverage map' view is one of the most valuable outputs of ATT&CK Navigator for a SOC team. Reading 40+ technique pages manually (option A) would work but is extremely inefficient — that's exactly the problem Navigator solves.",
      xp: 25,
    },

    // ------------------------------------------------------------------
    // Log Analysis Task
    // ------------------------------------------------------------------
    {
      type: "log_analysis" as const,
      id: "mitre-la1",
      heading: "Identifying an ATT&CK Technique From a Log",
      context:
        "You are a Tier-2 SOC analyst at Fintech-Global. Microsoft Entra ID (your cloud identity platform — formerly called Azure AD) has fired a high-severity alert. The log below shows authentication activity. Your job is to identify the ATT&CK technique being used, understand why this pattern is dangerous, and determine what mitigation ATT&CK recommends. Pay close attention to the PasswordAttempted, UniqueAccountsTargeted, UniquePasswordsUsed, and AttemptsPerAccount fields.",
      event: mitreAttackEvent,
      questions: [
        {
          question:
            "The log shows UniquePasswordsUsed: 1 (one password) and UniqueAccountsTargeted: 8 (eight different accounts), with AttemptsPerAccount: 1. This pattern — one password tried across many accounts — is the defining characteristic of which ATT&CK sub-technique?",
          options: [
            "T1110.001 — Password Guessing: many passwords tried against one account until it locks out",
            "T1110.002 — Password Cracking: offline cracking of password hash files",
            "T1110.003 — Password Spraying: one common password tried across many accounts to evade lockout policies",
            "T1078 — Valid Accounts: using previously stolen credentials to log in",
          ],
          answer: 2,
          explanation:
            "T1110.003 (Password Spraying) is defined by the exact pattern in this log: a single password ('Winter2024!') tried across many different accounts (8 accounts), with only one attempt per account. This evades account lockout policies — most systems lock an account after 5–10 failed attempts with *different* passwords. By trying only once per account, the attacker flies under the lockout threshold. This is why Password Spraying is so effective against organisations that don't monitor across-account failure patterns.",
          xp: 25,
        },
        {
          question:
            "The UserAgent field shows 'python-requests/2.31.0' and IsInteractive is false. What do these fields tell you about the nature of this attack?",
          options: [
            "A legitimate Python developer at the company is testing the login API as part of normal software development",
            "The authentication attempts are automated — a Python script is performing the spray, not a human manually typing at a keyboard",
            "The attack is being performed from a company-managed device running Python development tools",
            "The 'python-requests' user agent confirms this is a penetration tester conducting an authorised test",
          ],
          answer: 1,
          explanation:
            "A real browser like Chrome or Edge would show a user agent string like 'Mozilla/5.0...' — not 'python-requests/2.31.0'. The python-requests library is a popular Python HTTP library used in scripts and automation. Combined with IsInteractive: false (meaning this is not a human typing in a browser window) and the systematic targeting of 8 accounts, this confirms the attack is fully automated. An attacker is running a Python script that programmatically sends login requests at machine speed. This is the standard tooling for automated credential attacks.",
          xp: 20,
        },
        {
          question:
            "According to ATT&CK's mitigation guidance for T1110.003, which control would have made this password spray attack completely ineffective, even if the attacker correctly guessed a user's password?",
          options: [
            "A stronger password policy requiring 12+ characters — longer passwords are harder to guess",
            "Multi-Factor Authentication (MFA) — requires a second verification step beyond just the password",
            "Account lockout after 5 failed attempts — would have locked the 8 accounts being targeted",
            "Blocking the Python-requests user agent at the firewall — prevents automated spraying tools",
          ],
          answer: 1,
          explanation:
            "Multi-Factor Authentication (MFA) is the most effective mitigation for password-based attacks. Even if an attacker successfully guesses 'Winter2024!' as a user's password, MFA requires a second factor (phone push notification, authenticator app code, hardware token) that the attacker does not have. Without the second factor, the stolen password is useless. This is why ATT&CK lists MFA as the primary mitigation for T1110.003. Account lockout (option C) would not help here because the attacker only tried each account once. User agent blocking (option D) is easily defeated by changing the user agent string in the script.",
          xp: 25,
        },
      ],
    },

    // ------------------------------------------------------------------
    // Matching Task — MITRE ATT&CK Tactics
    // ------------------------------------------------------------------
    {
      type: "matching" as const,
      id: "mitre-m1",
      heading: "Match ATT&CK Tactics to Their Definitions",
      instructions: "ATT&CK organizes attacker techniques into 14 tactics — each representing a goal. Match these 5 tactics to the correct definition.",
      pairs: [
        {
          id: "ia",
          left: "Initial Access",
          right: "Gaining the very first foothold in the environment — via phishing, exploiting a public app, or stolen credentials",
        },
        {
          id: "pers",
          left: "Persistence",
          right: "Surviving reboots and password resets — scheduled tasks, registry run keys, new admin accounts",
        },
        {
          id: "lm",
          left: "Lateral Movement",
          right: "Moving from the initial victim machine to other systems inside the network",
        },
        {
          id: "coll",
          left: "Collection",
          right: "Gathering files, emails, and credentials that will later be stolen",
        },
        {
          id: "exfil",
          left: "Exfiltration",
          right: "Transferring stolen data out of the organization — via cloud storage, email, or DNS tunneling",
        },
      ],
      explanation: "Understanding ATT&CK tactics is how SOC analysts classify what an attacker is doing at each moment. The sequence is intentional: attackers need Initial Access before Lateral Movement, and must complete Collection before Exfiltration. In a SIEM alert, each MITRE technique maps to exactly one tactic — which tells you what phase of the attack you have detected and what is likely to come next.",
      xp: 30,
    },

    // ------------------------------------------------------------------
    // Question 4 — Additional
    // ------------------------------------------------------------------
    {
      type: "question" as const,
      id: "mitre-q4",
      question:
        "A SOC analyst is writing an incident report about a breach where the attacker: (1) sent a phishing email, (2) used stolen credentials to move between servers, and (3) dumped the customer database. The analyst wants to use ATT&CK technique IDs in the report. Match each attacker action to its most likely ATT&CK tactic:",
      options: [
        "Phishing = Impact; Credential use = Exfiltration; Database dump = Initial Access",
        "Phishing = Initial Access; Credential use = Lateral Movement; Database dump = Collection",
        "Phishing = Reconnaissance; Credential use = Persistence; Database dump = Exfiltration",
        "Phishing = Execution; Credential use = Privilege Escalation; Database dump = Impact",
      ],
      answer: 1,
      explanation:
        "Phishing (T1566) falls under Initial Access (TA0001) — it's how the attacker first enters the environment. Using stolen credentials to move between servers falls under Lateral Movement (TA0008) — specifically T1021 Remote Services or T1550 Use Alternate Authentication Material. Dumping a database (gathering data that will be stolen) falls under Collection (TA0009) — specifically T1005 Data from Local System or T1213 Data from Information Repositories. Exfiltration (TA0010) would cover actually *sending* the data outside the network, which comes after Collection.",
      xp: 20,
    },
  ],
};

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

const rooms = [introRoom, socStructureRoom, killChainRoom, mitreAttackRoom];

export default rooms;
