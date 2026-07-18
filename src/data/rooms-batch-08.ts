/**
 * Learning Rooms — Batch 08
 *
 * Four intermediate-level rooms covering:
 *   1. Threat Intelligence Fundamentals (CTI)
 *   2. OSINT Fundamentals
 *   3. Incident Response Methodology (PICERL)
 *   4. Alert Triage
 *
 * Audience: absolute beginners — every term is explained from scratch with
 * real-world analogies before technical depth is introduced.
 */

import type { TelemetryEvent } from "@/lib/sim/types";

// ---------------------------------------------------------------------------
// Room 1 — Threat Intelligence Fundamentals
// ---------------------------------------------------------------------------

const threatIntelligence = {
  id: "threat-intelligence",
  title: "Threat Intelligence Fundamentals",
  description:
    "Learn what Cyber Threat Intelligence (CTI) is, why it matters, and how SOC analysts use threat feeds, MISP, ISACs, and standardized formats like STIX/TAXII to stay ahead of attackers. Covers intelligence lifecycle, APT naming conventions, and practical CTI operations.",
  difficulty: "intermediate" as const,
  category: "Threat Intelligence",
  estimatedMinutes: 50,
  xp: 500,
  icon: "🕵️",
  prerequisites: ["mitre-attack", "ioc-analysis"],
  tasks: [

    // ── Reading 1: What Is CTI & Intelligence Types ─────────────────────────
    {
      type: "reading" as const,
      id: "threat-intel-r1",
      heading: "What Is Cyber Threat Intelligence — And Why Is 'Intelligence' Different From 'Information'?",
      content: `Every day your company's firewall blocks thousands of connections, your antivirus scans millions of files, and your SIEM generates hundreds of alerts. All of that is **information** — raw facts sitting in a database. By itself, raw information is not very useful. You cannot act on "connection blocked from 185.220.101.45" unless you know: *Who owns that IP? Is it linked to a known attacker? Which companies have they targeted? What do they do after they get in?*

When you take raw information, apply **analysis**, add **context**, and produce something an analyst can act on — that is **intelligence**. The difference is the same as the difference between a weather sensor reading "wind speed: 120 km/h" and a meteorologist telling you "Hurricane Helene will make landfall in Miami on Thursday — evacuate coastal zones now." The sensor gives information. The meteorologist gives intelligence.

**Cyber Threat Intelligence (CTI)** is the discipline of collecting information about attackers — who they are, what tools they use, who they target, and how they behave — and turning it into actionable guidance that helps defenders make better decisions.

---

**The Four Types of CTI**

CTI comes in four flavours, aimed at different audiences inside an organisation:

**1. Strategic Intelligence**
High-level, non-technical summaries of the threat landscape written for executives and board members. Example: "Nation-state actors from country X are increasingly targeting financial institutions in Europe, motivated by sanctions evasion. Expect phishing campaigns targeting wire transfer processes." No IP addresses or malware hashes here — just business-relevant risk context. The audience is the CISO, CEO, and board of directors.

**2. Operational Intelligence**
Information about specific attacker **campaigns** — ongoing attack operations with a defined objective, target set, and timeframe. Example: "APT29 is currently running a phishing campaign targeting law firms handling mergers and acquisitions. They are using macro-enabled Word documents dropped via spear-phishing emails." Aimed at SOC managers and IR teams so they can prepare playbooks and tune detection. Think of it as "know your enemy's current plan."

**3. Tactical Intelligence**
Details about attacker **TTPs** (Tactics, Techniques, and Procedures) — the specific methods attackers use step by step. This maps directly to the MITRE ATT&CK framework. Example: "APT29 uses spear-phishing with malicious attachments (T1566.001), then executes a PowerShell downloader (T1059.001), establishes persistence via scheduled tasks (T1053.005), and exfiltrates data over HTTPS to Dropbox (T1567.002)." Aimed at security engineers and detection teams who write SIEM rules and EDR detections.

**4. Technical Intelligence**
The lowest-level, most concrete type: actual **Indicators of Compromise (IOCs)**. IP addresses, domain names, file hashes, email addresses, URLs. These are machine-readable and feed directly into firewalls, SIEMs, and endpoint tools as block rules. Example: "Block outbound connections to 185.220.101.45 and DNS queries for sunburst.evildomain.com." Technical intelligence has a short shelf life — attackers rotate IPs and domains quickly.

---

**The Intelligence Lifecycle**

Intelligence is not a one-time lookup. It is a continuous cycle:

- **Planning**: What questions do we need answered? (e.g., "Are we being targeted by ransomware groups?")
- **Collection**: Gather data from feeds, dark web, honeypots, industry partners, OSINT
- **Processing**: Clean, translate, and de-duplicate raw data into a usable format
- **Analysis**: Apply analyst expertise — what does this data mean? What is the attacker likely to do next?
- **Dissemination**: Deliver intelligence to the right audience in the right format (executive brief vs. SIEM rule)
- **Feedback**: Consumers of intelligence tell producers whether it was useful — this improves future collection

Think of it like a restaurant kitchen: ingredients (raw data) → prep cook (processing) → head chef (analysis) → waiter (dissemination) → customer feedback → chef adjusts the menu.`,
    },

    // ── Reading 2: Threat Actors, APT Naming & CTI Platforms ────────────────
    {
      type: "reading" as const,
      id: "threat-intel-r2",
      heading: "Threat Actors, APT Groups, and the Platforms That Track Them",
      content: `Not all attackers are equal. CTI analysts classify threat actors by their motivation, resources, and level of sophistication. Understanding who is likely to attack you — and why — is just as important as knowing their technical tools.

---

**Threat Actor Categories**

**Nation-State APTs (Advanced Persistent Threats)**
The most sophisticated and well-resourced attackers. Backed by governments and intelligence agencies. They have large teams, custom malware development, and years-long patience. They target government agencies, critical infrastructure, defence contractors, pharmaceutical companies, and financial institutions. Their goals include espionage, sabotage, and intellectual property theft.

The word "persistent" is key — they do not smash and grab. They enter quietly, live undetected for months (average attacker dwell time before detection is 197 days), and slowly achieve their objectives.

**Cybercriminal Groups**
Financially motivated. Their business model is usually ransomware (encrypt your files, demand payment), BEC (Business Email Compromise — impersonate the CEO to trick finance into wiring money), or selling stolen credit card data. They are often organised like a real company, with HR, support, and software development teams. Groups like LockBit and BlackCat operate "Ransomware-as-a-Service" (RaaS) — they provide the malware and infrastructure, and affiliates do the attacking in exchange for a cut of the ransom.

**Hacktivists**
Ideologically motivated. They want to make a political statement, expose wrongdoing, or protest an organisation's actions. They typically use DDoS attacks, website defacement, or data dumps. Anonymous is the most well-known hacktivist collective.

**Script Kiddies**
Low-skill attackers who run tools or exploit code written by others without understanding how they work. They cause nuisance but rarely achieve sophisticated objectives. They are opportunistic — they scan the internet for known vulnerabilities and hit whatever responds.

---

**APT Naming Conventions**

The same threat actor often has different names from different security companies. This is confusing at first, but you will get used to it.

**CrowdStrike** names APTs by animal + nationality:
- **BEAR** = Russia (Fancy Bear = APT28, Cozy Bear = APT29)
- **PANDA** = China (Gothic Panda, Stone Panda)
- **KITTEN** = Iran (Charming Kitten, Phosphorus)
- **CHOLLIMA** = North Korea (Labyrinth Chollima = Lazarus Group)

**MITRE** uses numbered designations: **APT28** (Russian GRU), **APT29** (Russian SVR/FSB), **APT41** (Chinese dual espionage/crime group), **APT34** (Iranian MOIS).

**Mandiant/Google** (formerly FireEye) uses UNC groups for uncategorised clusters and named groups like **FIN7** (cybercriminal), **FIN11** (ransomware).

**Microsoft** has moved to weather-themed names: **Midnight Blizzard** (Russia), **Volt Typhoon** (China), **Peach Sandstorm** (Iran).

---

**CTI Sharing Platforms & Feeds**

**MISP (Malware Information Sharing Platform)** is an open-source platform for sharing structured threat intelligence. Organisations share IOCs, malware samples, and attack details with trusted partners. Data is organised into "events" with "attributes" (individual IOCs). MISP is widely used by CERTs, ISACs, and companies worldwide.

**ISACs (Information Sharing & Analysis Centers)** are industry-specific groups where organisations share threat intelligence with competitors in the same sector. They exist because sharing helps everyone defend against the same threat actors:
- **FS-ISAC**: Financial Services — banks and payment processors sharing info on banking trojans and fraud campaigns
- **H-ISAC**: Healthcare — hospitals sharing ransomware indicators
- **E-ISAC**: Energy — utilities sharing ICS attack information

**Open Source / Free Feeds**:
- **CISA Known Exploited Vulnerabilities (KEV)**: US government list of CVEs actively exploited in the wild — if it's on this list, patch it now
- **AlienVault OTX (Open Threat Exchange)**: Community-contributed IOC feeds covering malware, phishing, C2 servers
- **Abuse.ch**: Tracks malware distribution infrastructure — URLhaus (malicious URLs), MalwareBazaar (file samples), Feodo Tracker (banking trojan C2s)

**Commercial Feeds**:
- **Recorded Future**: Real-time threat intelligence platform with dark web monitoring
- **Mandiant Advantage**: Campaign tracking, malware analysis, vulnerability intelligence
- **CrowdStrike Intelligence**: Adversary intelligence focused on APT tracking

**STIX/TAXII** are the standard formats for sharing CTI:
- **STIX** (Structured Threat Information Expression): A JSON-based language for describing threat actors, campaigns, TTPs, IOCs, and relationships between them
- **TAXII** (Trusted Automated eXchange of Indicator Information): The protocol used to transfer STIX data between organisations — like HTTP is for web browsing, TAXII is for threat intel

Together, STIX/TAXII enable automated, machine-readable threat intelligence sharing between platforms, so an IOC discovered by one organisation can be automatically imported into another organisation's SIEM within minutes.`,
    },

    // ── Reading 3: CTI in SOC Operations ────────────────────────────────────
    {
      type: "reading" as const,
      id: "threat-intel-r3",
      heading: "How CTI Feeds Into Daily SOC Operations",
      content: `Cyber Threat Intelligence is only valuable if it changes what defenders do. Let's look at exactly how CTI integrates into a modern SOC.

---

**IOC Matching in the SIEM**

The most direct use of CTI is importing technical IOCs (IPs, domains, hashes) into your SIEM and running them against log data in real time. When a firewall log shows an outbound connection to an IP that your threat intel platform has flagged as a known APT29 command-and-control (C2) server, the SIEM fires an alert immediately.

This is called an **IOC hit** or **threat intel match**. It collapses what would otherwise require forensic investigation into a near-instant alert — the work of identifying the malicious IP has already been done by analysts at CrowdStrike, CISA, or a partner organisation who shared the indicator.

**Confidence and TLP Ratings**
Not all IOCs are equal. Each indicator should carry a **confidence score** (high / medium / low) and a **TLP (Traffic Light Protocol)** classification:
- **TLP:RED** — share only with named recipients, do not post publicly
- **TLP:AMBER** — share within your organisation and with trusted partners
- **TLP:GREEN** — share within the broader community
- **TLP:WHITE/CLEAR** — unrestricted, can be published publicly

A high-confidence IOC from a government source (e.g., CISA KEV) carries more weight than a low-confidence community-submitted indicator from OTX.

---

**Threat Hunting with CTI**

Beyond reactive alerting, CTI enables proactive **threat hunting** — analysts going looking for signs of compromise rather than waiting for an alert to fire.

A CTI report says: "APT41 uses scheduled tasks named 'WindowsUpdate' in C:\\Windows\\Temp\\ for persistence." A threat hunter takes that TTP and writes a SIEM query: "Show me any scheduled task creation where the task name contains 'WindowsUpdate' and the file path contains Temp." If results come back, the hunter investigates whether the organisation has already been compromised — even if no alert fired because the attacker bypassed existing detection rules.

This is why tactical intelligence (TTPs) has longer shelf life than technical intelligence (IOCs). Attackers rotate IPs every few days, but they tend to reuse the same techniques across many campaigns.

---

**Enriching Alerts With CTI Context**

When a SOC analyst opens a high-severity alert, the first question is "is this real?" CTI enrichment dramatically speeds up that determination. A good SIEM/SOAR platform will automatically query threat intel platforms when an alert fires and attach context:

- "Source IP 185.220.101.45 — known C2 for APT29, first seen 2024-12-13, associated with SolarWinds SUNBURST campaign, confidence: HIGH, source: CISA KEV"

That context transforms a vague "suspicious outbound connection" alert into a confirmed, high-priority incident requiring immediate containment.

---

**Feeding CTI Back Into Detection Engineering**

CTI analysts and detection engineers work together. When a new APT campaign is reported, detection engineers translate the attacker's TTPs into new SIEM correlation rules and EDR detections — so the next time that technique is used, the SOC catches it automatically.

This is called the **detect → learn → improve** loop, and CTI is the fuel that drives it. Without good threat intelligence, your detection rules only catch attacks you have already seen. With good CTI, you can detect attacks before they reach your organisation.`,
    },

    // ── Question 1 ──────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "threat-intel-q1",
      question: "A CISO asks for a briefing on geopolitical risk from nation-state hackers targeting your industry sector. Which type of CTI should you prepare?",
      options: [
        "Technical intelligence — share a list of malicious IP addresses and file hashes",
        "Tactical intelligence — provide a detailed breakdown of the attacker's MITRE ATT&CK techniques",
        "Strategic intelligence — a high-level summary of threat landscape, actor motivations, and business risk",
        "Operational intelligence — describe a specific ongoing phishing campaign targeting your company",
      ],
      answer: 2,
      explanation: "Strategic intelligence is designed for executive audiences like a CISO or board. It explains threat landscape, geopolitical context, and business risk without technical details like IPs or hashes. Technical intelligence is for SIEM rules, tactical is for detection engineers, and operational is for SOC managers running specific incident responses.",
      xp: 30,
    },

    // ── Question 2 ──────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "threat-intel-q2",
      question: "CrowdStrike labels a Russian APT group as 'FANCY BEAR.' What is the MITRE ATT&CK designation for this same group?",
      options: [
        "APT34",
        "APT41",
        "APT29",
        "APT28",
      ],
      answer: 3,
      explanation: "Fancy Bear = APT28 (Russian GRU military intelligence). Cozy Bear = APT29 (Russian SVR/FSB intelligence services). APT34 is Iranian, APT41 is Chinese. Different vendors use different names for the same group — knowing the naming conventions helps you correlate intelligence across reports from different sources.",
      xp: 30,
    },

    // ── Question 3 ──────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "threat-intel-q3",
      question: "What is TLP:AMBER in the Traffic Light Protocol (TLP) framework?",
      options: [
        "The indicator is fully public and can be shared with anyone, including on social media",
        "The indicator can be shared within your organisation and with trusted partner organisations, but not publicly",
        "The indicator is restricted to only the named recipients in the original report",
        "The indicator applies only to amber-coloured network traffic in the SIEM",
      ],
      answer: 1,
      explanation: "TLP:AMBER means share within your organisation and with trusted partners (clients, sector peers) who need it to protect themselves — but do NOT post it publicly. TLP:WHITE/CLEAR is fully public. TLP:RED is named-recipients only. TLP is widely used in threat intel sharing to prevent sensitive IOCs from being leaked to attackers who monitor public feeds.",
      xp: 30,
    },

    // ── Log Analysis: IOC Hit ────────────────────────────────────────────────
    {
      type: "log_analysis" as const,
      id: "threat-intel-la1",
      heading: "IOC Hit — CISA Known Exploited Vulnerabilities Feed Match",
      context: "You are a Tier-1 SOC analyst. The SIEM has fired a Priority-1 alert at 09:47 UTC. Your threat intelligence platform automatically enriched the alert with data from the CISA KEV feed and CrowdStrike Intelligence. The matched event is below. Your job is to understand what happened and determine the correct response.",
      event: {
        id: "evt-ti-001",
        ts: "2025-06-24T09:47:13Z",
        source: "threat_intel",
        event_type: "ioc_hit",
        severity: "critical",
        hostname: "CORP-DC01",
        src_ip: "185.220.101.45",
        dst_ip: "10.0.1.55",
        description: "Outbound connection matched CISA KEV threat intel feed — APT29 C2 infrastructure",
        mitre_technique: "T1071.001",
        raw: {
          "rule.name": "CISA KEV IOC Match",
          "rule.level": "13",
          "data.indicator": "185.220.101.45",
          "data.indicator_type": "ip",
          "data.confidence": "high",
          "data.source": "CISA Known Exploited Vulnerabilities",
          "data.campaign": "APT29 SolarWinds",
          "data.actor": "Cozy Bear",
          "data.first_seen": "2024-12-13",
          "data.tlp": "WHITE",
          "data.description": "C2 server associated with SolarWinds SUNBURST supply chain compromise",
          "matched.srcip": "185.220.101.45",
          "matched.dstip": "10.0.1.55",
          "matched.hostname": "CORP-DC01",
        },
      } satisfies TelemetryEvent,
      questions: [
        {
          question: "The alert shows that CORP-DC01 (IP 10.0.1.55) has a connection TO 185.220.101.45. Given that CORP-DC01 is the company's domain controller, what is the most accurate assessment of this alert?",
          options: [
            "This is a False Positive — domain controllers regularly connect to external IPs for Windows updates",
            "This is a low-priority alert because the TLP rating is WHITE, meaning it is public knowledge",
            "This is a critical True Positive — a domain controller communicating with a known APT29 C2 server is a confirmed high-severity incident",
            "This needs more investigation because confidence is only 'high' and not 'certain'",
          ],
          answer: 2,
          explanation: "A domain controller (the most sensitive server in an Active Directory environment) communicating with a known APT29 C2 server that is listed in the CISA KEV database with HIGH confidence is a critical incident. Domain controllers do NOT legitimately connect to external internet IPs. TLP:WHITE means it can be shared publicly — it does not reduce severity. 'High' confidence from a government source (CISA) is more than sufficient to treat this as a True Positive.",
          xp: 50,
        },
        {
          question: "What is the FIRST action you should take after confirming this is a True Positive?",
          options: [
            "Delete the malware files from CORP-DC01 immediately",
            "Wait 24 hours to collect more evidence before escalating",
            "Isolate CORP-DC01 from the network and escalate to Tier-2/IR team immediately",
            "Send an email to the threat actor at the C2 IP address asking them to stop",
          ],
          answer: 2,
          explanation: "Network isolation (via EDR or manual VLAN change) stops the active C2 communication immediately, containing the breach. Then escalate to the IR team — this is a P1 incident involving the domain controller and a known nation-state actor. You do NOT delete files first (that destroys forensic evidence). You do NOT wait — every minute the attacker has C2 access they can exfiltrate more data or move laterally.",
          xp: 50,
        },
      ],
    },

    // ── Flag Task ────────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "threat-intel-flag1",
      prompt: `The IOC alert above references the actor "Cozy Bear." This actor is tracked by MITRE ATT&CK under a numbered APT designation. Based on what you learned in this room, what is the MITRE ATT&CK group ID for Cozy Bear? Enter just the designation (e.g. "APT##").`,
      answer: "APT29",
      hint: "CrowdStrike calls them COZY BEAR. MITRE uses a numbered system. This group is from Russia's SVR/FSB intelligence services. The number is 29.",
      xp: 60,
    },

    // ── Question 4 ──────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "threat-intel-q4",
      question: "What is MISP and what is its primary purpose?",
      options: [
        "A commercial endpoint detection tool made by Microsoft for blocking malware",
        "An open-source threat intelligence sharing platform where organisations exchange IOCs, malware events, and attack attributes with trusted partners",
        "A vulnerability scanner that finds open ports on company servers",
        "A firewall management system for blocking malicious IP addresses",
      ],
      answer: 1,
      explanation: "MISP (Malware Information Sharing Platform) is an open-source platform for structured threat intelligence sharing. Organisations create 'events' containing 'attributes' (IOCs like IPs, hashes, domains) and share them with trusted partner organisations, ISACs, and CERTs. It is widely used by national CERTs, financial institutions, and government agencies worldwide. It is NOT an endpoint tool, scanner, or firewall.",
      xp: 30,
    },

    // ── Question 5 ──────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "threat-intel-q5",
      question: "Your company is a hospital. You want to join an industry-specific threat intelligence sharing group to receive early warning about ransomware targeting healthcare. Which ISAC should you join?",
      options: [
        "FS-ISAC (Financial Services)",
        "E-ISAC (Energy)",
        "H-ISAC (Health)",
        "MS-ISAC (Multi-State)",
      ],
      answer: 2,
      explanation: "H-ISAC (Health Information Sharing and Analysis Center) is the dedicated ISAC for the healthcare sector — hospitals, pharmaceutical companies, health insurers, and medical device makers. FS-ISAC is for financial services, E-ISAC is for energy and utilities, and MS-ISAC is for state, local, tribal, and territorial governments.",
      xp: 30,
    },
  ],
};

// ---------------------------------------------------------------------------
// Room 2 — OSINT Fundamentals
// ---------------------------------------------------------------------------

const osintFundamentals = {
  id: "osint-fundamentals",
  title: "OSINT Fundamentals",
  description:
    "Master Open Source Intelligence techniques used by SOC analysts to investigate threat actors, enrich IOCs, and research attacker infrastructure — all from publicly available sources. Covers Shodan, Censys, URLScan, WHOIS, Maltego, and analyst OPSEC.",
  difficulty: "intermediate" as const,
  category: "Threat Intelligence",
  estimatedMinutes: 45,
  xp: 450,
  icon: "🔭",
  prerequisites: ["threat-intelligence"],
  tasks: [

    // ── Reading 1: What Is OSINT & Why SOC Analysts Use It ──────────────────
    {
      type: "reading" as const,
      id: "osint-r1",
      heading: "What Is OSINT and Why Do SOC Analysts Need It?",
      content: `Imagine you receive an alert: your company's laptop "LAPTOP-JSMITH" just made an outbound connection to an IP address you have never seen before — 185.220.101.47. Is this harmless? Is this the laptop downloading a Windows update? Or is it a compromised machine calling home to an attacker's server?

To answer that question, you need to investigate the IP address. And you need to do it quickly — without alerting the attacker that you noticed. This is where **OSINT** comes in.

**OSINT** stands for **Open Source Intelligence** — the practice of gathering information from publicly available sources to support an investigation or decision. "Open source" does not mean software — it means the information is openly accessible to anyone without hacking, bribing, or breaking any law.

OSINT sources include:
- Websites, news articles, and social media
- Government databases and company registries
- Internet scanning services that index public-facing servers
- Domain registration records (WHOIS)
- Historical DNS data
- Certificate transparency logs
- Search engine caches and archived web pages

---

**Why Do SOC Analysts Use OSINT?**

SOC analysts use OSINT primarily for three purposes:

**1. IOC Enrichment**
When an alert fires, OSINT tools let you instantly look up unknown IPs, domains, or file hashes to determine if they are known malicious. This takes a vague alert like "connection to unknown external IP" and turns it into "connection to a Tor exit node associated with the Lazarus Group."

**2. Threat Actor Research**
When you are investigating a targeted attack, OSINT lets you research the attacker's infrastructure. If you identify one malicious domain, OSINT can reveal 30 related domains hosted on the same server — giving you a much fuller picture of the attack and enabling you to block all of them proactively.

**3. Attacker Reconnaissance Awareness**
Understanding what OSINT tools reveal about YOUR organisation is critical. Attackers use the same tools before attacking you. They search Shodan for exposed servers, look up your employees on LinkedIn, and find email addresses on Hunter.io. Knowing what attackers can see lets you reduce your attack surface.

---

**OSINT Categories**

OSINT investigations typically target one or more of these categories:

- **Infrastructure OSINT**: IP addresses, domain names, ASN (Autonomous System Number — the identifier for a block of IPs), hosting providers, open ports, running services, TLS certificates
- **People OSINT**: Names, email addresses, usernames, phone numbers, employment history, social media profiles
- **Organisation OSINT**: Company structure, subsidiaries, employees, technology stack, job postings (which reveal what software the company uses)
- **Geolocation OSINT**: IP-based geolocation, image metadata (EXIF data), landmarks in photos
- **Social Media OSINT**: Public posts, accounts, connections, communities on Twitter/X, LinkedIn, GitHub, Reddit

For SOC analysts, infrastructure OSINT is the most frequently used category — you are mostly investigating IPs, domains, and attacker server infrastructure.`,
    },

    // ── Reading 2: Key OSINT Tools ───────────────────────────────────────────
    {
      type: "reading" as const,
      id: "osint-r2",
      heading: "The SOC Analyst's OSINT Toolkit: Shodan, URLScan, WHOIS, and More",
      content: `SOC analysts have a powerful set of free and commercial OSINT tools at their disposal. Here are the most important ones and exactly how you use each one in a real investigation.

---

**Shodan (shodan.io) — The Google for Internet-Connected Devices**

Shodan is a search engine — but instead of indexing web pages like Google, it continuously scans the entire public internet and indexes what it finds: open ports, running services, software versions, TLS certificates, operating systems, and device types.

Think of it like a map of every "open door" on the internet. If a company accidentally left its database server exposed on TCP port 5432, Shodan found it.

**SOC analyst uses:**
- Look up a suspicious IP: "What services are running on this IP? Who owns it? What ASN?" An IP running port 443 with a suspicious certificate and flagged in Shodan's malware C2 database is almost certainly malicious
- Identify attacker infrastructure: Find other IPs with the same TLS certificate, same banner text, or same open port combination — these are likely part of the same attacker-controlled network
- Pivot from one IOC to many: If you know one C2 IP, Shodan can reveal 20 more on the same ASN

Key Shodan fields: \`org\` (organisation/ISP), \`asn\`, \`os\` (operating system detected), \`ssl.cert.subject.cn\` (certificate common name), \`port\`, \`hostnames\`.

---

**Censys (censys.io)**

Similar to Shodan. Censys is particularly strong on TLS certificate analysis. If an attacker uses a self-signed certificate with a specific common name (like \`CN=*.evil-c2.com\`), Censys can find all IPs worldwide using that same certificate — letting you map the attacker's entire server infrastructure from a single IOC.

---

**URLScan.io — Safely Analyse Malicious URLs**

Never visit a suspicious URL in your normal browser. URLScan.io lets you submit a URL and it visits it in a sandboxed browser, capturing screenshots, network requests, DOM content, and any files downloaded. You see everything the page does — without any risk to your system.

**SOC analyst use:** You receive a phishing email with a link. Before clicking anything, submit the URL to URLScan and see exactly what the phishing page looks like, what credentials it harvests, and what domain it sends stolen data to.

---

**WHOIS — Domain Registration Lookup**

When a domain was registered, by whom, with what registrar, using what contact email — all of this information is (or was, before privacy protection became common) available via WHOIS lookups. Even with privacy protection, you can often determine:
- Registration date (newly registered domain = higher suspicion)
- Registrar name
- Nameservers (attackers often use specific fast-flux DNS or bullet-proof hosting providers)
- Expiry date (attackers often register domains for short periods)

Tools: \`whois\` command on Linux, \`who.is\`, \`domaintools.com\`.

---

**DNSDumpster — Passive DNS Intelligence**

DNSDumpster shows all DNS records associated with a domain — A records (IPs), MX records (mail servers), TXT records, subdomains. You can map an attacker's entire domain infrastructure without ever connecting to their servers.

---

**Maltego — Visual Link Analysis**

Maltego is the most powerful OSINT tool for complex investigations. It visualises relationships between entities — IP addresses, domains, email addresses, people, organisations, phone numbers — as a graph. You can see at a glance how all the pieces connect.

In Maltego, you start with one IOC (say, a malicious domain), run automated "transforms" (API queries to WHOIS, Shodan, VirusTotal, etc.), and watch the graph expand. You might discover: the domain → is hosted at IP → which also hosts 5 other domains → one of which → shares a WHOIS email with → a known threat actor's old infrastructure.

---

**OSINT Framework (osintframework.com)**

A curated, constantly updated directory of OSINT tools organised by category. When you need to find a specific tool (say, "how do I look up someone's username across platforms?"), osintframework.com is your starting point.`,
    },

    // ── Reading 3: Passive vs Active OSINT & OPSEC ───────────────────────────
    {
      type: "reading" as const,
      id: "osint-r3",
      heading: "Passive vs. Active OSINT — and Why Analyst OPSEC Matters",
      content: `There is an important distinction in OSINT that every SOC analyst must understand: the difference between **passive** and **active** investigation. Getting this wrong could alert the attacker that you are on to them.

---

**Passive OSINT: Looking Without Touching**

Passive OSINT involves collecting information that has already been indexed or cached by third parties — you never send a single packet to the target's infrastructure. The attacker has no way of knowing you are investigating them.

Examples of passive OSINT:
- Looking up an IP on Shodan (Shodan already scanned it; your lookup is just reading their database)
- Checking WHOIS records for a domain
- Searching VirusTotal for a file hash
- Looking at cached web pages on archive.org (Wayback Machine)
- Reading DNS records from a third-party passive DNS service
- Reading public social media profiles without logging in

**When to use:** Almost always. Passive OSINT is your default mode. It is safe, legal, and leaves no trace.

---

**Active OSINT: Making Direct Contact**

Active OSINT involves directly querying the target's infrastructure — sending packets to the attacker's IP, making HTTP requests to their server, or running a port scan. This leaves traces in the attacker's server logs. A sophisticated attacker monitoring their server might notice your investigation IP and react — by taking down the C2, changing infrastructure, or even targeting you back.

Examples of active OSINT:
- Port scanning an IP with nmap
- Visiting a suspected phishing URL in your own browser
- Making direct HTTP requests to an attacker-controlled API
- Sending a test email to see if a domain's mail server is live

**When to use:** Only when passive OSINT has been exhausted, you have a specific need, and you are aware of the risks. In most SOC triage scenarios, passive OSINT is sufficient.

---

**Analyst OPSEC (Operational Security)**

When you investigate an attacker — especially a sophisticated nation-state APT — you need to protect your own identity and organisation. This is called **analyst OPSEC**.

Why? Because if you look up a threat actor's domain on your company's network, your company's IP appears in the attacker's server logs (if the tool you used made any direct request). A sophisticated attacker might recognise it as a security firm and change tactics.

**OPSEC best practices for OSINT analysts:**

- **Use a VPN or Tor** when performing any active investigation so your real IP is not exposed
- **Isolated browser/VM**: Use a dedicated virtual machine that is not connected to your corporate network for investigative browsing
- **Avoid attribution**: Do not log into personal accounts (Google, LinkedIn) while investigating — this links your investigation to your identity
- **Use intermediary tools**: Tools like URLScan, Any.run, and Joe Sandbox visit malicious URLs on your behalf in isolated environments
- **Sock puppet accounts**: Some threat intelligence teams maintain fake social media accounts (with carefully built histories) specifically for investigating dark web forums and attacker communities

---

**Practical Example: Investigating a C2 IP**

Here is how an analyst would OSINT-investigate a suspicious IP step by step:

1. **VirusTotal lookup** (passive): Is the IP already flagged by any vendor? What URLs and files are associated with it?
2. **Shodan lookup** (passive): What services are running? Who is the hosting provider? Is the ASN known for bulletproof hosting?
3. **WHOIS lookup** (passive): When was any associated domain registered? By which registrar?
4. **URLScan** (passive/sandboxed): If there is a domain, what does the website show?
5. **Maltego pivot** (passive): Are there related domains or IPs on the same infrastructure?
6. **ThreatFox/Abuse.ch** (passive): Is this IP in any C2 tracking databases?

Only after exhausting passive research would an analyst consider any active step.`,
    },

    // ── Question 1 ──────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "osint-q1",
      question: "A SOC analyst receives an alert for an outbound connection to an unfamiliar IP address. What is the FIRST OSINT step to take?",
      options: [
        "Port-scan the suspicious IP with nmap to identify what services are running",
        "Personally visit any website hosted on the IP using your work laptop's browser",
        "Look up the IP on Shodan and VirusTotal (passive OSINT) to determine its reputation and owner",
        "Call the ISP that owns the IP and ask them to disconnect it",
      ],
      answer: 2,
      explanation: "Always start with passive OSINT — it leaves no trace and gives you immediate context. Shodan reveals what services run on the IP and who owns it. VirusTotal shows whether any security vendors have flagged it as malicious. Port scanning (active OSINT) would alert the target. Visiting the IP in your work browser is dangerous and could expose your corporate IP. Calling an ISP is a legal/law enforcement process, not analyst OSINT.",
      xp: 30,
    },

    // ── Question 2 ──────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "osint-q2",
      question: "You discover that a malicious domain used in a phishing attack has a TLS certificate with `CN=login.secure-banking-portal.net`. You search Censys for other IPs using this same certificate CN. What is this investigation technique called?",
      options: [
        "Hash pivoting — using the certificate hash to find related domains",
        "Certificate pivoting — using shared TLS certificate attributes to map attacker infrastructure",
        "DNS poisoning — manipulating DNS records to redirect traffic",
        "Shodan scanning — actively scanning IPs owned by the attacker",
      ],
      answer: 1,
      explanation: "Certificate pivoting means using a shared TLS certificate attribute (like a CN, organisation name, or certificate fingerprint) to find all IPs and domains using the same certificate. Attackers often reuse certificates across their infrastructure, so this technique can reveal an entire botnet or C2 network from a single domain. Censys is the best tool for this because it indexes TLS certificate data for the entire internet.",
      xp: 30,
    },

    // ── Question 3 ──────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "osint-q3",
      question: "An analyst wants to safely examine what a suspicious phishing URL renders — screenshots, what scripts it loads, and where it sends stolen credentials — WITHOUT risking their own machine. Which tool is best suited for this?",
      options: [
        "Shodan — to scan the server hosting the phishing URL",
        "WHOIS — to look up the domain registration information",
        "URLScan.io — which visits the URL in a sandboxed browser and captures all behaviour",
        "Maltego — which visits the URL and creates a visual graph of the phishing page",
      ],
      answer: 2,
      explanation: "URLScan.io visits the URL in an isolated, sandboxed browser environment and captures: a screenshot of the page, all network requests made (revealing where credentials are sent), DOM content, JavaScript behaviour, and any files downloaded. The analyst never risks their own machine. Shodan scans servers but doesn't render web pages. WHOIS gives registration data. Maltego is for link-analysis graphs, not web-page behaviour analysis.",
      xp: 30,
    },

    // ── Log Analysis: C2 Connection Discovered via OSINT ────────────────────
    {
      type: "log_analysis" as const,
      id: "osint-la1",
      heading: "Firewall Alert — Outbound Connection to IP Identified as Tor Exit Node via OSINT",
      context: "You are a Tier-1 SOC analyst. The firewall has logged an outbound HTTPS connection from an internal laptop. You ran the destination IP through Shodan and the results have been automatically appended to the log. Analyse the enriched event below and answer the questions.",
      event: {
        id: "evt-osint-001",
        ts: "2025-06-24T11:23:44Z",
        source: "firewall",
        event_type: "net_connection",
        severity: "high",
        hostname: "LAPTOP-JSMITH",
        src_ip: "10.0.1.55",
        dst_ip: "185.220.101.47",
        description: "Outbound HTTPS connection — destination enriched with Shodan OSINT data",
        mitre_technique: "T1090.003",
        raw: {
          "data.srcip": "10.0.1.55",
          "data.dstip": "185.220.101.47",
          "data.dstport": "443",
          "data.proto": "TCP",
          "data.bytes_sent": "4096",
          "data.bytes_received": "2048",
          "data.action": "allow",
          "data.hostname": "LAPTOP-JSMITH",
          "shodan.os": "Linux",
          "shodan.org": "Tor Project",
          "shodan.open_ports": ["80", "443", "8080"],
          "shodan.ssl_subject": "CN=*.onion-router.net",
        },
      } satisfies TelemetryEvent,
      questions: [
        {
          question: "According to the Shodan enrichment data, what kind of server is at 185.220.101.47, and what does this tell you about the traffic?",
          options: [
            "A Windows update server — the connection is expected and benign",
            "A Tor exit node — outbound HTTPS traffic from a corporate laptop through Tor is suspicious and indicates the user or malware is attempting to anonymise their traffic",
            "A company file server — this is a normal internal network connection",
            "A DNS server — this is a normal DNS lookup on port 443",
          ],
          answer: 1,
          explanation: "Shodan data shows shodan.org: Tor Project and shodan.ssl_subject: CN=*.onion-router.net. A Tor exit node is the last server in the Tor anonymisation network before traffic reaches the public internet. Corporate laptops should never connect to Tor nodes during normal business activity. This could mean: (a) the user is bypassing corporate monitoring, or (b) malware on the laptop is using Tor to hide C2 communications. Both scenarios require investigation.",
          xp: 50,
        },
        {
          question: "The Shodan flag task below asks which organisation the destination IP belongs to. Based on the Shodan enrichment data in this log, what is your answer?",
          options: [
            "Microsoft Corporation",
            "Amazon Web Services",
            "Tor Project",
            "Cloudflare Inc.",
          ],
          answer: 2,
          explanation: "The field shodan.org: Tor Project directly answers this question. Shodan's org field shows the organisation that owns the IP block according to ARIN/RIPE/APNIC registration records. The Tor Project is the nonprofit that operates the Tor anonymisation network.",
          xp: 50,
        },
      ],
    },

    // ── Flag Task ────────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "osint-flag1",
      prompt: `Based on the Shodan enrichment data in the log analysis above, what organisation does the destination IP 185.220.101.47 belong to? Enter the exact organisation name as it appears in the Shodan data.`,
      answer: "Tor Project",
      hint: "Look at the `shodan.org` field in the raw log data from the log analysis task above.",
      xp: 60,
    },

    // ── Question 4 ──────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "osint-q4",
      question: "What is the difference between passive and active OSINT, and why does it matter for analyst OPSEC?",
      options: [
        "Passive OSINT is more expensive and requires commercial subscriptions; active OSINT uses free tools",
        "Passive OSINT queries pre-indexed third-party data and leaves no trace on the target's infrastructure; active OSINT makes direct contact with the target and can reveal the analyst's IP address to the attacker",
        "Passive OSINT is only used by government agencies; active OSINT is used by private security firms",
        "There is no meaningful difference — both methods carry equal risk to the analyst",
      ],
      answer: 1,
      explanation: "The key difference is whether you make direct contact with the target. Passive OSINT (WHOIS lookups, Shodan searches, VirusTotal queries) uses data already collected by third parties — the target never sees your IP. Active OSINT (port scanning, directly visiting a URL, making HTTP requests to an attacker's server) generates traffic that appears in the attacker's logs. A sophisticated attacker could notice an investigation and change their infrastructure. This is why analysts protect their real IP with VPNs, Tor, or sandboxed tools when doing active OSINT.",
      xp: 30,
    },
  ],
};

// ---------------------------------------------------------------------------
// Room 3 — Incident Response Methodology
// ---------------------------------------------------------------------------

const incidentResponseMethodology = {
  id: "incident-response-methodology",
  title: "Incident Response Methodology",
  description:
    "Master the structured approach to handling cybersecurity incidents from first detection to post-incident review. Covers the SANS PICERL framework, NIST SP 800-61, IR team roles, evidence preservation, containment strategies, and chain of custody.",
  difficulty: "intermediate" as const,
  category: "Incident Response",
  estimatedMinutes: 55,
  xp: 550,
  icon: "🚨",
  prerequisites: ["alert-triage"],
  tasks: [

    // ── Reading 1: What Is an Incident? PICERL Overview ──────────────────────
    {
      type: "reading" as const,
      id: "ir-method-r1",
      heading: "What Is a Security Incident? And the PICERL Framework for Responding to One",
      content: `Every day, thousands of security **events** occur in an organisation: a user logs in, a firewall blocks a connection, a file is modified. Most events are completely normal. Some events are unusual enough to generate **alerts** — they match a rule in your SIEM or EDR. Most alerts, on investigation, turn out to be false alarms (false positives).

But sometimes, an alert represents something real and serious: an actual attack in progress, a breach, or data loss. When that happens, you have an **incident**.

**The Hierarchy:**
- **Event**: Any observable occurrence (log entry). Neutral.
- **Alert**: An event that matches a detection rule. Needs investigation.
- **Incident**: A confirmed security breach or attack that requires a structured response.

The difference between an alert and an incident is the **analyst's determination** — based on triage and evidence. An alert that you confirm is a real attack becomes an incident.

---

**What Is Incident Response (IR)?**

Incident Response is the structured, documented process an organisation follows when a security incident occurs. Without a process, people panic, evidence gets destroyed, the wrong people make decisions, and the attacker has more time.

With a good IR process:
- The right people are mobilised immediately
- Evidence is preserved for forensics and legal proceedings
- The attacker is contained before they cause more damage
- Systems are cleaned and restored from known-good state
- The organisation learns from the incident to prevent recurrence

---

**The SANS PICERL Framework**

The SANS Institute's 6-phase framework, known by the acronym **PICERL**, is the most widely used operational IR model:

**P — Preparation**
Before any incident occurs. Build your defences, train your team, write your playbooks. This is the phase that determines how well everything else goes.

**I — Identification**
Detect that an incident has occurred and determine its scope. Is this a single compromised laptop, or has the attacker moved through the entire network?

**C — Containment**
Stop the attack from spreading. Isolate infected systems. Block attacker communication. This is emergency surgery — stop the bleeding before you do anything else.

**E — Eradication**
Remove the attacker from the environment entirely. Delete malware, close backdoors, patch the vulnerability they exploited, reset all compromised credentials.

**R — Recovery**
Restore systems to full operational status. Reconnect previously isolated systems. Restore from clean backups if needed. Verify clean before reconnecting.

**L — Lessons Learned**
After the incident: what happened? Why did it succeed? What can we do differently? Document everything in a post-incident report.

---

**NIST SP 800-61 (4-Phase Model)**

NIST's framework (now in Revision 3, updated April 2025) uses 4 broader phases:
1. **Preparation**
2. **Detection & Analysis** (combines PICERL's Identification)
3. **Containment, Eradication & Recovery** (combines three PICERL phases)
4. **Post-Incident Activity** (Lessons Learned)

Both frameworks describe the same process — PICERL is more granular for operational use, NIST is better for policy and compliance frameworks. In practice, most SOC teams use PICERL operationally.

---

**IR Team Roles**

A typical Incident Response team includes:
- **IR Lead (Incident Commander)**: Makes final decisions, owns the investigation timeline
- **Tier-2/Tier-3 Analysts**: Technical investigation, forensics, malware analysis
- **Communications Lead**: Notifies management, external parties, regulators
- **Legal/Compliance Representative**: Assesses regulatory notification requirements (GDPR 72-hour rule, SEC breach reporting)
- **Threat Intelligence Analyst**: Provides attacker attribution and campaign context
- **System Owners**: Business teams responsible for affected systems who can confirm what "normal" looks like

The **RACI matrix** (Responsible, Accountable, Consulted, Informed) defines who does what for every task in the IR playbook, so there is no confusion during a high-stress incident.`,
    },

    // ── Reading 2: Identification & Containment ──────────────────────────────
    {
      type: "reading" as const,
      id: "ir-method-r2",
      heading: "Identification and Containment — Finding the Fire and Stopping It from Spreading",
      content: `The two most time-critical phases of incident response are Identification and Containment. Speed matters enormously — every minute an attacker has active access in your environment is a minute they can exfiltrate more data, move to more systems, or install additional backdoors.

---

**Phase 2: Identification**

Identification is about answering three questions as fast as possible:

**1. Is this actually an incident?**
Confirm the alert is a True Positive. Look at the evidence — logs, EDR telemetry, network captures. Has an attacker definitely gained access, or is this a false alarm?

**2. How did it happen?**
What was the initial attack vector? Phishing email? Exploited VPN vulnerability? Brute-forced credentials? Understanding the entry point is critical because you need to close it during eradication.

**3. How far have they spread?**
This is called **scope assessment**. The attacker may have started on one workstation but have already moved laterally to five servers. You need to know the full blast radius before you can contain effectively.

**Incident Severity Classification**

Not all incidents are equal. Most organisations use a priority system:
- **P1 (Critical)**: Active breach, ransomware spreading, crown jewel systems compromised, attacker has domain admin rights. All hands on deck. Immediate executive notification.
- **P2 (High)**: Single system compromised, no confirmed lateral movement, sensitive data at risk. Senior analysts engaged. Management notified.
- **P3 (Medium)**: Suspicious activity confirmed but limited scope. Standard SOC analyst response.
- **P4 (Low)**: Minor policy violation, single malware detection on non-critical system. Routine response.

**Evidence Preservation — CRITICAL Rule**

One of the most common mistakes in incident response is **turning off the affected computer first**. This destroys volatile memory (RAM), which contains running processes, open network connections, decryption keys in memory, and attacker tools that haven't been written to disk.

**The rule: capture memory before anything else.**

If the system must be preserved for forensics, the correct order is:
1. Capture a memory dump (RAM image) using tools like WinPMEM, DumpIt, or the EDR's built-in memory acquisition
2. Capture network state (open connections, listening ports)
3. Capture running processes
4. Then — only then — consider isolating or powering down

For ransomware specifically: **do NOT power off** a system mid-encryption. This can corrupt files, making decryption impossible even if you pay the ransom.

---

**Phase 3: Containment**

Containment is your emergency response. Think of it like a house fire — before you investigate what caused it, you call the fire brigade and stop it from burning down the entire street.

**Short-Term Containment (Emergency)**

The goal: stop the attacker's active access and prevent lateral movement RIGHT NOW.

- **Network isolation via EDR**: Modern EDR platforms (CrowdStrike, SentinelOne, Microsoft Defender XDR) can isolate a machine from the network with a single button click from the SOC console. The machine can still communicate with the EDR cloud but is blocked from all other network traffic. This stops C2 communication and lateral movement immediately.
- **VLAN change**: Network engineering team moves the compromised machine to a quarantine VLAN
- **Firewall block**: Block the attacker's external IPs and C2 domains at the perimeter firewall

**Long-Term Containment (Stabilisation)**

Once the immediate fire is out, implement durable controls:
- Reset all passwords for compromised accounts (and any account that could have been stolen from the compromised system)
- Revoke all sessions and tokens associated with compromised accounts
- Block all identified C2 indicators across all security controls

**Communication During Containment**

While technical teams are containing the incident, the communications lead must notify:
- **Executive management** (CEO, CISO): What happened, current status, business impact
- **Legal team**: Was personal data accessed? Are there regulatory notification obligations?
- **Affected business units**: What systems are down and for how long
- In some cases: **regulators**, **cyber insurance carrier**, **law enforcement**`,
    },

    // ── Reading 3: Eradication, Recovery & Lessons Learned ───────────────────
    {
      type: "reading" as const,
      id: "ir-method-r3",
      heading: "Eradication, Recovery, and Lessons Learned — Cleaning Up and Getting Smarter",
      content: `After the fire is contained, three phases remain: removing the attacker completely (Eradication), restoring normal operations (Recovery), and ensuring the same incident never happens again (Lessons Learned).

---

**Phase 4: Eradication**

Eradication means making sure the attacker is completely gone — no backdoors, no persistence mechanisms, no malware hiding anywhere. This is more thorough than it sounds, because sophisticated attackers install multiple persistence mechanisms to maintain access even if one is removed.

**Eradication checklist:**

- **Remove all malware**: Quarantine and delete all identified malicious files. Use EDR's "full disk scan" with updated signatures post-incident.
- **Remove persistence mechanisms**: Scheduled tasks, registry run keys, startup folder entries, WMI subscriptions, browser extensions, modified services, boot sector malware. Attackers love persistence — assume there are multiple.
- **Close the initial access vector**: Patch the vulnerability that was exploited, revoke the stolen credentials, disable the phishing template, block the initial delivery domain.
- **Reset ALL compromised credentials**: Not just the user whose account was breached — any account the attacker could have accessed from the compromised systems. For a compromised domain controller, this means resetting the KRBTGT account (which invalidates all Kerberos tickets) and potentially resetting all domain account passwords.
- **Rebuild if uncertain**: If there is any doubt about whether a system is fully clean — especially a critical server — rebuild it from scratch from a known-clean image rather than trying to clean it. It is faster than a forensic hunt and guarantees cleanliness.

**Eradication for Ransomware:**
Ransomware incidents require particular care. The ransomware binary itself must be removed, but also: the initial dropper, any reconnaissance tools, the C2 communication mechanism, and any data staging locations used before encryption began.

---

**Phase 5: Recovery**

Recovery is restoring affected systems to full production operation — but doing it safely.

**Recovery steps:**
1. **Verify systems are clean** before reconnecting to the network. Run EDR scans, check persistence locations, verify no suspicious processes running.
2. **Restore from clean backups** if data was encrypted (ransomware) or corrupted. The backup must pre-date the initial compromise — not just the ransomware trigger date. Many ransomware groups lurk in the network for weeks before encrypting, so backups from 24 hours ago may already be compromised.
3. **Reconnect to network incrementally**: Bring systems back online one group at a time, not all at once. Monitor closely for signs of re-infection.
4. **Enhanced monitoring**: For 30-90 days post-recovery, apply heightened monitoring to all affected systems and similar systems in the environment. Re-infection within weeks of recovery is common if eradication was incomplete.

---

**Phase 6: Lessons Learned**

The final phase — and the one that prevents the next incident.

Within 24-72 hours after the incident is resolved, the IR team holds a **post-incident review** meeting. This is NOT a blame session. It is a factual analysis of what happened and how to improve.

The post-incident report should cover:
- **Timeline**: When did the attack begin? When was it detected? When was it contained?
- **Root cause**: What was the fundamental vulnerability or failure that enabled the attack? (e.g., unpatched VPN, no MFA on VPN, phishing simulation training not done in 18 months)
- **Detection gap**: Why did it take X hours/days to detect? What log sources were missing? What rule didn't fire?
- **What worked well**: Parts of the response that went smoothly
- **What needs improvement**: Process failures, communication breakdowns, tool limitations
- **Action items with owners and deadlines**: Specific changes to make — patch this CVE by date X, implement MFA by date Y, add this detection rule by date Z

---

**Chain of Custody**

If the incident may result in legal action (criminal prosecution, civil litigation, regulatory enforcement), every piece of evidence must be handled under **chain of custody** protocols:
- Document who collected each evidence item, when, and how
- Store evidence in tamper-evident sealed containers (physical) or cryptographically hashed (digital)
- Track every time evidence changes hands
- Never work directly on original evidence — always work on verified forensic copies

Break chain of custody, and the evidence may be inadmissible in court.`,
    },

    // ── Question 1 ──────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "ir-method-q1",
      question: "A SOC analyst discovers an infected workstation is actively encrypting files on a network share. Before isolating the machine, what should happen FIRST according to IR best practices?",
      options: [
        "Power off the machine immediately to stop the encryption",
        "Capture a memory dump (RAM image) to preserve volatile evidence such as running processes and decryption keys",
        "Delete the ransomware binary identified by the EDR to stop the encryption",
        "Format the hard drive to prevent data exfiltration",
      ],
      answer: 1,
      explanation: "Memory (RAM) contains volatile evidence that is lost forever when the machine powers off: running malware processes, encryption keys in memory, open network connections to C2, and attacker tools that never touched disk. Capturing RAM first preserves this critical forensic evidence. Powering off destroys it. Deleting files may not stop a running process and destroys evidence. Formatting is destructive and premature. After capturing memory, THEN isolate the machine via EDR network isolation.",
      xp: 35,
    },

    // ── Question 2 ──────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "ir-method-q2",
      question: "During a post-incident review, the team discovers the attacker had been in the network for 45 days before detection. The company's backup retention policy only keeps 30 days of backups. What is the critical problem this creates during Recovery?",
      options: [
        "No problem — 30-day backups are sufficient; you can restore from any backup created in the past month",
        "All available backups may already be compromised because the attacker was present before the oldest backup was taken; restoring from them could reintroduce the attacker's tools",
        "The only issue is that 30-day backups take longer to restore than 7-day backups",
        "Backup age does not matter for recovery — you only need to restore the most recent backup",
      ],
      answer: 1,
      explanation: "If the attacker was in the network for 45 days and backups only go back 30 days, ALL available backups were created AFTER the initial compromise. The attacker may have already placed backdoors, modified files, or added persistence mechanisms that are baked into every available backup. Restoring from any of these backups could immediately re-introduce the attacker. This is a critical lesson: backup retention must exceed realistic attacker dwell times, and during recovery, the pre-compromise date must be verified before choosing a backup.",
      xp: 35,
    },

    // ── Question 3 ──────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "ir-method-q3",
      question: "What does the 'Identification' phase of PICERL focus on?",
      options: [
        "Removing all malware and backdoors from compromised systems",
        "Determining whether an incident has occurred, how it happened, and the full scope of compromise",
        "Restoring systems from clean backups and reconnecting them to the network",
        "Writing the post-incident report and identifying lessons learned",
      ],
      answer: 1,
      explanation: "Identification (the I in PICERL) is about detection and scoping: confirm this is a real incident (not a false positive), determine the initial attack vector (how they got in), and map the full blast radius (which systems are affected). Without thorough identification, containment will be incomplete because you will miss compromised systems. Removing malware is Eradication. Restoring systems is Recovery. Post-incident review is Lessons Learned.",
      xp: 35,
    },

    // ── Log Analysis: P1 Ransomware Alert ────────────────────────────────────
    {
      type: "log_analysis" as const,
      id: "ir-method-la1",
      heading: "P1 Incident — Active Ransomware Detected on File Server",
      context: "You are an on-call Tier-2 SOC analyst. It is 14:32 UTC on a Tuesday. Your pager fires with a P1 alert. The EDR agent on SRV-FILE01 has generated this critical alert. Read the alert carefully and answer the questions to guide the incident response.",
      event: {
        id: "evt-ir-001",
        ts: "2025-06-24T14:32:11Z",
        source: "edr",
        event_type: "edr_alert",
        severity: "critical",
        hostname: "SRV-FILE01",
        description: "Active ransomware detected — LockBit 3.0 — network shares affected",
        mitre_technique: "T1486",
        raw: {
          "s1.threatName": "Ransom.LockBit3.0",
          "s1.classification": "Malicious",
          "s1.processName": "svchost.exe",
          "s1.processPath": "C:\\Windows\\Temp\\svchost.exe",
          "s1.fileCount_renamed": "15847",
          "s1.extensionAdded": ".lockbit",
          "s1.agentComputerName": "SRV-FILE01",
          "s1.affectedVolumes": "C:\\,D:\\,\\\\SRV-NAS01\\shared",
          "s1.networkShares_accessed": "3",
          "s1.action": "Quarantine",
          "s1.timestamp": "2025-06-24T14:32:11Z",
          "rule.priority": "P1",
          "rule.description": "Active ransomware — network shares affected",
        },
      } satisfies TelemetryEvent,
      questions: [
        {
          question: "The ransomware process is `svchost.exe` in `C:\\Windows\\Temp\\`. Why is this location a critical red flag, even though `svchost.exe` is a legitimate Windows process?",
          options: [
            "Legitimate svchost.exe always runs from C:\\Windows\\Temp\\ — this is normal Windows behaviour",
            "Legitimate svchost.exe runs from C:\\Windows\\System32\\. A svchost.exe in C:\\Windows\\Temp\\ is almost certainly malware masquerading as a system process by using the same name",
            "The file location does not matter — only the file name determines if it is legitimate",
            "C:\\Windows\\Temp\\ is a protected Windows folder — no malware can write files there",
          ],
          answer: 1,
          explanation: "The legitimate Windows svchost.exe (Service Host) ALWAYS runs from C:\\Windows\\System32\\. Malware authors frequently copy their malicious executable into C:\\Windows\\Temp\\ and name it 'svchost.exe' to blend in with normal process lists. This is called a living-off-the-land technique or process masquerading. Any svchost.exe running from Temp, AppData, or any path other than System32 is almost certainly malicious. The EDR caught this exact pattern.",
          xp: 50,
        },
        {
          question: "The alert shows `s1.affectedVolumes: C:\\, D:\\, \\\\SRV-NAS01\\shared` and `s1.networkShares_accessed: 3`. What does this tell you about the scope of this incident?",
          options: [
            "The ransomware is contained to the local C: drive only — no network spread has occurred",
            "The ransomware has already spread to two local drives AND is actively encrypting files on at least one network share (SRV-NAS01), making this a multi-system P1 incident requiring immediate containment of both SRV-FILE01 and SRV-NAS01",
            "Three network shares were accessed but not encrypted — no action is needed yet",
            "This is normal file server activity — servers routinely access network shares",
          ],
          answer: 1,
          explanation: "The ransomware has already encrypted files on C:\\ and D:\\ (SRV-FILE01's local drives) AND is reaching across the network to encrypt \\\\SRV-NAS01\\shared — a NAS (Network Attached Storage) device. This means at minimum TWO servers are affected. The `s1.fileCount_renamed: 15847` shows that 15,847 files have already been renamed with the .lockbit extension — encryption is well underway. This is a P1 multi-system incident. Both SRV-FILE01 and SRV-NAS01 must be immediately isolated.",
          xp: 50,
        },
      ],
    },

    // ── Flag Task ────────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "ir-method-flag1",
      prompt: `In the PICERL incident response framework, which phase involves isolating an infected server from the network to prevent the attacker from spreading to additional systems? Enter the single word phase name.`,
      answer: "Containment",
      hint: "It is the third phase of PICERL. Think of it like stopping a fire from spreading to adjacent buildings before you put it out.",
      xp: 60,
    },

    // ── Question 4 ──────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "ir-method-q4",
      question: "Your IR team has completed eradication of a compromised domain controller. The attacker had Domain Admin access. What is the specific Active Directory account you MUST reset to invalidate ALL existing Kerberos tickets in the domain?",
      options: [
        "The Administrator account",
        "The Guest account",
        "The KRBTGT account",
        "The Schema Admin account",
      ],
      answer: 2,
      explanation: "The KRBTGT account is the Kerberos Ticket Granting Ticket service account. Its password is used to sign all Kerberos tickets in the domain. If an attacker has domain admin access, they can create 'Golden Tickets' — forged Kerberos tickets signed with the KRBTGT hash that allow indefinite access. Resetting the KRBTGT password (twice, due to Active Directory replication) invalidates ALL existing Kerberos tickets across the domain, forcing re-authentication. This is a mandatory step after any domain controller compromise.",
      xp: 35,
    },

    // ── Question 5 ──────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "ir-method-q5",
      question: "What is the purpose of a post-incident Lessons Learned meeting, and when should it be held?",
      options: [
        "To assign blame to the analyst who missed the initial alert; held 6 months after the incident",
        "To factually analyse the timeline, root cause, and detection gaps — identifying specific improvements to prevent recurrence; held within 24-72 hours after the incident is resolved",
        "To inform the media about the incident and apologise for the breach; held immediately during the active incident",
        "To review the company's financial losses from the incident; held by the finance team only",
      ],
      answer: 1,
      explanation: "A Lessons Learned meeting is a blameless, factual review: what happened, why it happened, what the timeline was, why detection took as long as it did, and what specific changes will prevent recurrence. It should happen within 24-72 hours post-resolution while memories are fresh. It produces concrete action items with owners and deadlines. It is NOT a blame session — assigning blame creates a culture where people hide incidents rather than reporting them. The CISO, IR lead, technical analysts, communications, and affected business owners should all attend.",
      xp: 35,
    },
  ],
};

// ---------------------------------------------------------------------------
// Room 4 — Alert Triage
// ---------------------------------------------------------------------------

const alertTriage = {
  id: "alert-triage",
  title: "Alert Triage",
  description:
    "Master the systematic process that defines Tier-1 SOC analyst work: taking a raw security alert from the SIEM and determining within minutes whether it is a real attack (True Positive), a false alarm (False Positive), or something requiring escalation. Covers the 5-step methodology, enrichment, context gathering, and documentation.",
  difficulty: "intermediate" as const,
  category: "SOC Operations",
  estimatedMinutes: 50,
  xp: 500,
  icon: "⚡",
  prerequisites: ["siem-fundamentals"],
  tasks: [

    // ── Reading 1: What Is Alert Triage? ────────────────────────────────────
    {
      type: "reading" as const,
      id: "alert-triage-r1",
      heading: "What Is Alert Triage? The First and Most Important Skill of a SOC Analyst",
      content: `It is 09:00 AM on a Monday morning. You sit down at your SOC workstation, open the SIEM dashboard, and see 127 unreviewed alerts from the weekend. Some are real attacks. Most are probably false alarms. Your job for the next several hours is **alert triage**.

Alert triage is the systematic process of examining each security alert, gathering enough context to determine what it actually represents, and deciding what to do with it — close it as a false positive, escalate it as a confirmed incident, or mark it for further investigation.

Think of it like a hospital emergency room triage nurse. Dozens of patients walk in. The nurse doesn't treat everyone in the order they arrived — they quickly assess each person's condition and prioritise: this person is having a heart attack → immediate ICU; this person has a sprained ankle → can wait. SOC triage works the same way: quickly assess each alert, prioritise, and route appropriately.

---

**Why Triage Is So Challenging**

Modern SIEMs generate enormous alert volumes. A typical mid-size company might receive 1,000-10,000 SIEM alerts per day. A large enterprise can receive 100,000+. No team of analysts can thoroughly investigate every single alert — there simply isn't time.

This creates two failure modes:
- **Alert fatigue**: Analysts become overwhelmed, start clicking "close" on alerts without looking, and miss real attacks
- **Analysis paralysis**: Analysts spend too long on each alert and the queue never clears

Good triage is fast but rigorous. A skilled Tier-1 analyst should be able to triage most alerts in 3-10 minutes. Genuinely complex alerts get escalated to Tier-2 for deeper investigation.

---

**True Positive vs. False Positive vs. Benign True Positive**

Every alert ends up in one of these categories:

**True Positive (TP)**: The alert detected a real attack or security incident. Action required: escalate to incident response.

**False Positive (FP)**: The alert triggered, but the underlying activity is completely benign. The detection rule fired incorrectly. Action required: close the alert. Consider requesting a rule tune to reduce future noise.

**Benign True Positive (BTP)**: The alert fired correctly — the event technically matches the rule — but the activity is legitimate. Example: an IT admin running a port scan for inventory purposes triggers an IDS signature. The rule works, the scan is real, but it is authorised. Action required: close with documentation. Consider adding the admin's activity to an exclusion list.

**Indeterminate**: You cannot make a confident determination with the available evidence. Action required: request additional data, escalate to Tier-2, or open a threat hunting task.

---

**The Alert Priority Matrix**

Not all True Positives are equally urgent. Priority is determined by three factors:

1. **Alert Severity**: How serious does the detection rule rate this activity? (Critical / High / Medium / Low)
2. **Asset Criticality**: How important is the affected system? (Crown jewel like domain controller = very high; contractor laptop = lower)
3. **User Risk**: Is the affected user a privileged account, executive, or known-risky user?

**Priority = Severity × Asset Criticality × User Risk**

A "medium" severity alert on a domain controller with a service account is higher priority than a "high" severity alert on a decommissioned test server. Context is everything.`,
    },

    // ── Reading 2: The 5-Step Triage Methodology ─────────────────────────────
    {
      type: "reading" as const,
      id: "alert-triage-r2",
      heading: "The 5-Step Triage Methodology: From Alert to Decision in Minutes",
      content: `Every experienced SOC analyst develops a mental checklist they run through every time they open a new alert. Here is a formalised version of that process — the 5-step triage methodology.

---

**Step 1: Understand What the Rule Triggered On**

Before looking at any evidence, read the alert name and description carefully. Ask yourself: "What specific activity was this rule designed to detect?"

Good alert names tell you what the rule detected: **"Brute Force Authentication — 347 failures in 5 minutes from same source IP"** tells you far more than just **"Authentication Alert."**

Understanding the rule's intent helps you immediately know what evidence to look for. A brute force rule → look at the source IP, number of targets, and success/failure ratio. A malware detection rule → look at the process path, parent process, and file hash.

---

**Step 2: Examine the Evidence (Read the Raw Log)**

Open the raw log event that triggered the alert. Read every field. This is the ground truth — the actual data the system recorded when the event happened.

Key fields to look at:
- **Source IP and Destination IP**: Internal or external? Known IP or first seen?
- **User account**: Domain account, service account, or local account? Privileged?
- **Timestamp**: Business hours or 3 AM on a Sunday? Attacker activity often happens at unusual times.
- **Action**: What did the system do? Was a file actually executed, or just written? Did the login succeed, or just attempted?
- **Process details** (for EDR alerts): What is the process path? What is the parent process? Malware running from Temp folder = very suspicious. Word.exe spawning PowerShell = very suspicious.

---

**Step 3: Enrich With Context**

A raw log field like "source IP: 203.0.113.45" is not enough on its own. Enrich it:
- Is this IP in any threat intel feeds? (Malicious, neutral, or associated with a known threat actor?)
- What country does it geolocate to? (Is the user known to work from that country?)
- What is the affected host's role? (Is it a server, workstation, VIP laptop, or test machine?)
- What is the affected user's department and role? (Is this a finance user, IT admin, or contractor?)
- Have there been other recent alerts for this user or host? (Is this part of a pattern?)

Many modern SIEMs and SOAR platforms automatically enrich alerts with this context. But even automated enrichment should be reviewed by the analyst — automation can be wrong.

---

**Step 4: Assess the Potential Impact**

If this alert IS a real attack, how bad would it be? Ask yourself:
- What could the attacker actually do from this position?
- What data, systems, or accounts are at risk?
- Is this an early-stage attack (reconnaissance, initial access) or a late-stage attack (lateral movement, data exfiltration)?

A failed SSH brute force against a non-critical server from a known scanner IP = low impact even if real. A successful login with domain admin credentials from a Russian IP at 3 AM = catastrophic if real. Impact assessment guides how much time you spend triaging.

---

**Step 5: Make a Decision**

After steps 1-4, you should have enough information to make a determination:

**Close as False Positive**: The activity is benign. Document your reasoning ("IT admin running scheduled script per change ticket CHG-4421"). Consider requesting a rule tune.

**Close as Benign True Positive**: The rule fired correctly but the activity is authorised. Document who approved the activity.

**Escalate as True Positive**: This is a real attack or confirmed suspicious activity requiring incident response. Create a P1/P2/P3 ticket, write a triage summary (what you found and why it is suspicious), and hand off to Tier-2.

**Escalate as Indeterminate**: You need more data (additional logs, forensics, threat hunting). Document what you have and what additional investigation is needed.

Never make a determination without documenting your reasoning. If you close an alert and it later turns out to be an attack, you need to be able to show your logic.`,
    },

    // ── Reading 3: False Positive Patterns, Escalation, and Documentation ────
    {
      type: "reading" as const,
      id: "alert-triage-r3",
      heading: "Recognising False Positives, Knowing When to Escalate, and Writing Good Tickets",
      content: `Experience makes triage faster. After a few months in a SOC, analysts develop pattern recognition — they instantly know certain alert patterns are almost always false positives, while other patterns are almost always real. Here is a structured overview of the most common scenarios.

---

**Common False Positive Patterns**

**IT Admin Scripts**
Your detection rule fires on "PowerShell script with base64-encoded commands" — and attackers do use base64-encoded PowerShell. But so does legitimate IT automation. If the alert came from a known IT admin's workstation at 10 AM on a weekday, the parent process is their RMM tool (e.g., Datto, ConnectWise), and there is a change ticket for scheduled maintenance — this is almost certainly a false positive.

**Security Scanners**
Your IDS fires on "Port Scan Detected" — that is exactly what a port scan looks like. But your company runs vulnerability scans every Wednesday night from a known scanner IP (say, your Nessus scanner at 10.0.0.50). Check the source IP before investigating further. Many orgs add scanner IPs to allowlists to avoid noise.

**Legacy Systems and Stale Configurations**
A server generates 500 failed authentication alerts per day because it is running an old service that uses a password that was changed six months ago. The service keeps retrying. This generates constant noise until someone fixes the service account configuration. Recognise this pattern — it's a failed auth from an internal IP with no variation in timing (every 5 minutes, same account, same server).

**Business Applications With Odd Behaviour**
Many legitimate applications look suspicious to security tools. File backup software enumerates and copies thousands of files — similar to ransomware. DLP tools monitor clipboard and email — similar to spyware. HR software accesses employee records in bulk — similar to data exfiltration. Know your environment and its legitimate tools.

---

**True Positive Indicators**

When you see these, treat the alert as highly suspicious:

- **External source IP, especially from a country where the user doesn't work**
- **Successful login after many failures** (brute force that succeeded)
- **Unusual process parent-child relationship** (Word.exe spawning cmd.exe spawning PowerShell)
- **Known malicious indicator match** (IP or hash in threat intel feeds)
- **Activity at abnormal time** (3 AM login for a 9-5 employee)
- **Admin activity from a non-admin account suddenly using elevated privileges**
- **Process or file in an unusual path** (executable in Temp, AppData, or Windows\System32\\ impersonators)
- **Lateral movement indicators** (same user account authenticating to 20 different servers in 5 minutes)

---

**When to Escalate**

Escalate to Tier-2 or the IR team when:
- You have confirmed True Positive indicators and the severity is P1 or P2
- The affected asset is a crown jewel (domain controller, financial system, executive laptop)
- You are uncertain and have spent 15+ minutes without a determination
- The incident scope appears to involve multiple systems
- The alert involves any regulated data (personal data under GDPR, cardholder data under PCI-DSS, PHI under HIPAA)

When escalating, always include:
- Alert ID and timestamp
- What you found (brief timeline of events)
- Why you believe it is a True Positive (the specific indicators)
- Recommended immediate action (isolate X, block Y, reset Z)

---

**Writing Good Triage Documentation**

Every alert closure — whether False Positive or True Positive — requires documentation. A well-written triage note includes:

1. **What triggered**: Which rule, what event
2. **What you investigated**: Which logs, which tools you used, what queries you ran
3. **What you found**: The key evidence and context
4. **Your determination**: TP/FP/BTP and why
5. **Actions taken**: Alert closed, ticket created, escalated to X at Y time
6. **Recommended tuning**: If FP, should the rule be tuned to exclude this pattern?

Good documentation protects you, helps your colleagues understand past alerts, and builds the institutional knowledge that makes the whole SOC better over time.`,
    },

    // ── Question 1 ──────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "alert-triage-q1",
      question: "You open your alert queue Monday morning and see 100 alerts from the same host (WORKSTATION-KLEE) all fired over the weekend. What should you do FIRST?",
      options: [
        "Investigate each of the 100 alerts individually in the order they arrived",
        "Close all 100 alerts immediately because high volume from one host is always a false positive",
        "Look at one representative alert first, then check if the host appears in any other alert types — understanding the pattern lets you triage the entire cluster efficiently",
        "Escalate all 100 alerts to Tier-2 immediately without reviewing any of them",
      ],
      answer: 2,
      explanation: "When you see many alerts from the same host, look at the pattern before diving into individual alerts. Open 2-3 representative samples — are they all the same rule, same source IP, same time pattern? A quick SIEM pivot ('all alerts for WORKSTATION-KLEE in last 7 days') gives you the full picture in one view. This might reveal: it's all the same rule firing repeatedly (a repeated failed auth from a service account) OR it's multiple different alert types pointing to an active attack. Understanding the pattern first makes the entire cluster triageable in minutes instead of hours.",
      xp: 30,
    },

    // ── Question 2 ──────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "alert-triage-q2",
      question: "An alert fires: 'PowerShell with base64-encoded command detected — workstation LAPTOP-MSMITH.' You look at the raw log and see: source = LAPTOP-MSMITH, user = msmith, parent process = msmith's RMM tool (Datto RMM), time = 14:32 Tuesday (business hours), there is a change ticket in ServiceNow for 'IT audit script 14:00-15:00'. What is your determination?",
      options: [
        "True Positive — all PowerShell with base64 encoding is a confirmed attacker technique and must be escalated",
        "Benign True Positive — the rule correctly detected base64 PowerShell, but the activity is authorised IT administration with a matching change ticket",
        "False Positive — the detection rule should never have fired because this is an IT admin machine",
        "Indeterminate — you need 30 more minutes of investigation before making any determination",
      ],
      answer: 1,
      explanation: "This is a Benign True Positive (BTP): the detection rule worked correctly (base64 PowerShell IS a suspicious technique), but the activity is legitimate — it is a known IT admin's RMM tool running an authorised script during business hours with a matching change ticket. Close with BTP documentation. Optionally recommend adding this specific RMM's process path to an exclusion in the detection rule to reduce future noise. Do NOT mark as False Positive (the rule is working as intended — it just needs tuning for authorised patterns).",
      xp: 30,
    },

    // ── Question 3 ──────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "alert-triage-q3",
      question: "During triage, which combination of factors should make you MOST suspicious that an alert is a True Positive requiring escalation?",
      options: [
        "Internal source IP, business hours, known user account, no threat intel hits, matched vulnerability scanner pattern",
        "External IP from a country the user has never worked from, successful login after 200 failed attempts, login time 03:14 AM, no previous alerts for this account",
        "PowerShell detection from an IT admin's machine during scheduled maintenance window with change ticket",
        "Failed login from internal server that uses an outdated service account password",
      ],
      answer: 1,
      explanation: "Option B has multiple True Positive indicators stacked together: external IP (not internal company IP), foreign country the user has never worked from (geolocation anomaly), successful login AFTER 200 failures (brute force that worked), and 03:14 AM timing (user is asleep, not at their desk). Any one of these alone would raise suspicion — all four together is almost certainly a successful credential stuffing or brute force attack. This needs immediate escalation. Options A, C, and D all describe benign false positive patterns.",
      xp: 30,
    },

    // ── Log Analysis: Password Spray vs. Legitimate Lockout ──────────────────
    {
      type: "log_analysis" as const,
      id: "alert-triage-la1",
      heading: "Triage Scenario — 347 Failed Logins: Password Spray or Legitimate Issue?",
      context: "You are a Tier-1 SOC analyst. The SIEM has fired a 'Brute Force Authentication' alert. 347 failed logins for the 'administrator' account have occurred in a 5-minute window. The raw Windows Security Event log is below. This is your triage exercise — determine whether this is a password spray attack or a legitimate administrative issue.",
      event: {
        id: "evt-triage-001",
        ts: "2025-06-24T03:14:22Z",
        source: "windows_security",
        event_type: "auth_failure",
        severity: "high",
        hostname: "CORP-DC01",
        src_ip: "203.0.113.45",
        dst_ip: "10.0.1.2",
        user_email: "administrator@corp.local",
        description: "347 failed authentication attempts in 5-minute window from single external IP",
        mitre_technique: "T1110.003",
        raw: {
          "event.code": "4625",
          "winlog.event_data.TargetUserName": "administrator",
          "winlog.event_data.LogonType": "3",
          "winlog.event_data.SubStatus": "0xC000006A",
          "winlog.event_data.IpAddress": "203.0.113.45",
          "winlog.event_data.WorkstationName": "",
          "GeoLocation.country_name": "Russia",
          "GeoLocation.city_name": "Moscow",
          "rule.name": "Brute Force Authentication",
          "rule.count": "347",
          "rule.timewindow": "300",
          "winlog.channel": "Security",
        },
      } satisfies TelemetryEvent,
      questions: [
        {
          question: "Analyse the raw log fields. Which THREE specific indicators most strongly suggest this is a genuine password spray / brute force attack rather than a legitimate issue?",
          options: [
            "LogonType 3 (network logon) from IP 203.0.113.45 geolocating to Moscow Russia; 347 failures in 300 seconds from a SINGLE external source IP; the target account is 'administrator' — the highest-privilege account in Windows",
            "The Windows event code 4625 is logged — this code only appears during cyberattacks and never during legitimate logon failures",
            "SubStatus 0xC000006A means the account is locked out, which only happens during authorised security testing",
            "LogonType 3 is only used by administrators doing maintenance work, so this must be an IT team running tests",
          ],
          answer: 0,
          explanation: "The three strongest True Positive indicators: (1) External IP from Russia — no legitimate admin logs into a domain controller from Russia via a network logon; (2) 347 failures in 300 seconds from ONE external IP — this is the textbook pattern of an automated brute force tool trying passwords as fast as possible; (3) The target is 'administrator' — the built-in Windows account with highest privileges. Attackers specifically target this account because compromising it gives full control. Note: Event 4625 is a normal Windows failed logon event that appears every time ANY logon fails — it is not attack-specific. SubStatus 0xC000006A means 'wrong password' (not lockout). LogonType 3 is a standard network logon type.",
          xp: 50,
        },
        {
          question: "Based on your triage, what determination do you make and what is your recommended immediate action?",
          options: [
            "False Positive — close the alert, this is probably an IT admin who forgot their password",
            "Benign True Positive — close with documentation, the brute force rule is working as expected",
            "True Positive — escalate as P2 incident; recommend blocking 203.0.113.45 at the perimeter firewall and enabling geo-blocking for Russia on RDP/SMB ports immediately",
            "Indeterminate — wait 24 hours to see if the attacker succeeds before taking action",
          ],
          answer: 2,
          explanation: "This is a True Positive. The indicators are clear: external Russian IP, automated high-volume attack targeting the administrator account. Escalate as P2 (high) immediately — it has not yet succeeded but the risk is critical. Recommended immediate actions: (1) Block 203.0.113.45 at the perimeter firewall NOW; (2) Check whether any authentication from this IP has ever SUCCEEDED (look in the SIEM for Event ID 4624 from this IP — if found, escalate to P1); (3) Consider geo-blocking Russia on RDP port 3389 and SMB port 445; (4) Ensure the administrator account has a strong password and MFA enforced. Never wait to see if an attacker succeeds before acting.",
          xp: 50,
        },
      ],
    },

    // ── Flag Task ────────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "alert-triage-flag1",
      prompt: `The brute force alert in the log analysis above involves repeated failed logins against a single account from a single source IP. The MITRE ATT&CK framework sub-technique for this specific type of attack (password spraying-style single-account brute force from one source) is visible in the event's mitre_technique field. Enter the exact MITRE ATT&CK sub-technique ID (format: T####.###).`,
      answer: "T1110.003",
      hint: "Look at the `mitre_technique` field in the raw log event above. T1110 is the parent technique (Brute Force). The .003 sub-technique is for targeting a specific type of password attack.",
      xp: 60,
    },

    // ── Question 4 ──────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "alert-triage-q4",
      question: "When writing triage documentation to close an alert as a False Positive, which information is MOST important to include?",
      options: [
        "Only the alert ID and 'closed as FP' — no further documentation needed",
        "A detailed explanation of what the rule detected, what evidence you examined, why you determined it is benign, and whether the rule should be tuned",
        "The name of your supervisor so they can be contacted if anyone questions the closure",
        "The customer's financial data that triggered the alert, for reference",
      ],
      answer: 1,
      explanation: "Good FP documentation must include: what the rule detected (event details), what you investigated (SIEM queries, tools used, additional context), your reasoning for determining benign (specific evidence), and a tuning recommendation if this FP pattern will recur. This serves three purposes: (1) protects you if the determination is questioned; (2) helps colleagues understand the pattern if they see it again; (3) gives detection engineers the information they need to tune the rule and reduce future noise. 'Closed as FP' with no explanation is not acceptable.",
      xp: 30,
    },

    // ── Question 5 ──────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "alert-triage-q5",
      question: "A Tier-1 analyst has spent 20 minutes triaging an alert involving an internal server making unusual external connections. The analyst cannot determine whether it is legitimate software behaviour or malware. The server hosts the company's main customer database. What should the analyst do?",
      options: [
        "Close the alert as a False Positive since the analyst cannot confirm it is an attack after 20 minutes of investigation",
        "Continue investigating for several more hours until certain",
        "Escalate to Tier-2 as Indeterminate, documenting what was found, noting that the asset is a crown jewel (customer database server), and recommending deeper forensic investigation",
        "Ask a colleague to look at the alert but do not create a ticket — verbal communication is sufficient",
      ],
      answer: 2,
      explanation: "When you cannot make a confident determination, and especially when the affected asset is high-value (a customer database is a crown jewel), escalate to Tier-2 as Indeterminate. Include everything you have found so far so Tier-2 does not duplicate your work. The 15-20 minute guideline exists to prevent alert fatigue — if you cannot resolve it quickly, it probably requires deeper forensic expertise. Never close an Indeterminate alert on a crown jewel asset as a FP without expert review. Always document escalations in tickets — verbal communication creates no audit trail.",
      xp: 30,
    },
  ],
};

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

const rooms = [
  threatIntelligence,
  osintFundamentals,
  incidentResponseMethodology,
  alertTriage,
];

export default rooms;
