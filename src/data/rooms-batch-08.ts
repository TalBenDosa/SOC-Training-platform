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
  xp: 310,
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
      checkpoint: {
        question: "After a month of use, the detection team tells the CTI team: “half the IPs in your feed were already dead when they reached our SIEM — send fewer, fresher ones.” Which phase of the intelligence lifecycle is this message?",
        options: [
          "Processing",
          "Dissemination",
          "Feedback",
          "Analysis",
        ],
        answer: 2,
        explanation: "Feedback is the consumers of intelligence telling the producers whether it was useful, so that future collection improves — exactly what the detection team is doing. Processing is the producers cleaning and de-duplicating raw data before analysis; removing stale IPs could happen there later, but the message itself is not processing. Dissemination is delivering intelligence to the audience; the complaint is about something already delivered. Analysis is the producer working out what the data means, not the consumer reporting back.",
      },
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

The word "persistent" is key — they do not smash and grab. They enter quietly, stay undetected for as long as they can, and slowly achieve their objectives. Industry dwell-time figures (Mandiant M-Trends is the most-cited source) have fallen sharply over the last decade — from roughly 200 days in the mid-2010s to a global median measured in days-to-weeks in recent reports — mostly because EDR and ransomware's own noisiness force the issue. Do not read that as "the problem is solved": the median is dragged down by loud, fast ransomware, while a patient espionage actor with good operational security is exactly the case that still sits undetected for months.

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

**Mandiant/Google** (formerly FireEye) created the numbered **APT##** designations: **APT28** (Russian GRU), **APT29** (Russian SVR), **APT41** (Chinese dual espionage/crime group), **APT34** (Iranian MOIS). It also uses UNC groups for uncategorised clusters and FIN groups like **FIN7** (cybercriminal), **FIN11** (ransomware).

**MITRE ATT&CK** reuses common names such as APT28/APT29 as group names, but assigns its own **Group IDs**: APT28 = **G0007**, APT29 = **G0016**. When someone asks for the ATT&CK *ID*, they mean the G-number.

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
      checkpoint: {
        question: "A partner ISAC tells you: “We publish our indicators as STIX objects on a TAXII server — point your SIEM at it.” What are the two parts of that sentence?",
        options: [
          "STIX is the transport protocol; TAXII is the JSON format the indicators are written in",
          "STIX describes the threat data; TAXII is the protocol that moves it between platforms",
          "STIX and TAXII are two competing formats; your SIEM has to support one of the two",
          "STIX is the indicator's sharing level; TAXII is the server that enforces that level",
        ],
        answer: 1,
        explanation: "STIX is the JSON-based language that describes actors, campaigns, TTPs and IOCs; TAXII is the protocol that transfers that STIX data between organisations, the way HTTP carries web pages. The first option swaps the two roles. They are not competing formats: they work together, one as content and one as transport. The sharing level of an indicator is set by TLP, not by STIX, and TAXII does not enforce sharing restrictions.",
      },
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
Not all IOCs are equal. Each indicator should carry a **confidence score** (high / medium / low) and a **TLP (Traffic Light Protocol)** classification. TLP tells you exactly how far you are allowed to pass something on — and getting it wrong is how an organisation ends up publishing an indicator that tips off the very actor it was tracking. The current standard is **TLP 2.0** (FIRST.org), which has five levels:

- **TLP:RED** — for named recipients only. Do not share outside the individuals you received it from, not even with the rest of your team.
- **TLP:AMBER+STRICT** — share **within your organisation only**. This level exists specifically to say "not your clients, not your partners, not your sector peers" — the restriction that plain AMBER leaves ambiguous.
- **TLP:AMBER** — share within your organisation *and* with its clients, on a need-to-know basis, so they can protect themselves. (Not sector peers — that is GREEN.)
- **TLP:GREEN** — share within the broader community and with peer organisations, but not on a public channel.
- **TLP:CLEAR** — unrestricted, can be published publicly.

One historical note that matters, because you will still meet it in older feeds and documents: TLP 2.0 **retired TLP:WHITE and replaced it with TLP:CLEAR**, and added AMBER+STRICT at the same time. If you receive something marked TLP:WHITE, it is using the pre-2022 scheme — treat it as TLP:CLEAR, and be aware the sender's tooling may be out of date in other ways too.

The distinction between AMBER and AMBER+STRICT is the one that trips people up in practice, and it is exactly the one that matters in an MSSP or a multi-client SOC: plain AMBER lets you warn your clients, AMBER+STRICT does not.

A high-confidence IOC from a government source (e.g., a CISA joint cybersecurity advisory or CISA's Automated Indicator Sharing (AIS) feed) carries more weight than a low-confidence community-submitted indicator from OTX.

---

**Threat Hunting with CTI**

Beyond reactive alerting, CTI enables proactive **threat hunting** — analysts going looking for signs of compromise rather than waiting for an alert to fire.

A CTI report says: "APT41 uses scheduled tasks named 'WindowsUpdate' in C:\\Windows\\Temp\\ for persistence." A threat hunter takes that TTP and writes a SIEM query: "Show me any scheduled task creation where the task name contains 'WindowsUpdate' and the file path contains Temp." If results come back, the hunter investigates whether the organisation has already been compromised — even if no alert fired because the attacker bypassed existing detection rules.

This is why tactical intelligence (TTPs) has longer shelf life than technical intelligence (IOCs). Attackers rotate IPs every few days, but they tend to reuse the same techniques across many campaigns.

---

**Enriching Alerts With CTI Context**

When a SOC analyst opens a high-severity alert, the first question is "is this real?" CTI enrichment dramatically speeds up that determination. A good SIEM/SOAR platform will automatically query threat intel platforms when an alert fires and attach context:

- "Source IP 185.220.101.45 — known C2 for APT29, first seen 2024-12-13, associated with SolarWinds SUNBURST campaign, confidence: HIGH, source: CISA joint cybersecurity advisory (via AIS)"

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
      question: "The board is setting next year's security budget and asks the CISO: “Which kinds of attackers are likely to come after a company like ours, why, and what would it cost us?” Which CTI product answers that question?",
      options: [
        "Technical intelligence — the current blocklist of IPs, domains and hashes tied to those groups",
        "Tactical intelligence — the ATT&CK techniques those groups use, mapped to our detection coverage",
        "Strategic intelligence — a non-technical view of likely actors, their motives and the business risk",
        "Operational intelligence — details of the campaign those groups are running against our sector now",
      ],
      answer: 2,
      explanation: "The question is about likely adversaries, their motives and business impact for a budget decision — strategic intelligence, written for the CISO and board without IPs or hashes. A blocklist of IPs and hashes is technical intelligence for firewalls and the SIEM, and it goes stale in days. An ATT&CK-to-coverage map is tactical intelligence for detection engineers: useful, but it does not tell the board why or at what cost. Details of one current campaign are operational intelligence for SOC managers and IR teams preparing playbooks, not a year-long risk view.",
      xp: 30,
    },

    // ── Question 2 ──────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "threat-intel-q2",
      question: "Two reports land the same morning: CrowdStrike's on FANCY BEAR and Mandiant's on APT29. Your manager asks whether to merge them into one actor profile in your threat intel platform. What is the correct call?",
      options: [
        "Merge them — both are Russian BEAR groups, so APT29 is Mandiant's name for Fancy Bear",
        "Merge them — vendors name the same actor differently, and these two names are one group",
        "Keep them apart — APT## marks Mandiant's criminal groups, so APT29 is not state-run",
        "Keep them apart — Fancy Bear is APT28 (GRU); APT29 is Cozy Bear (SVR), a different group",
      ],
      answer: 3,
      explanation: "Fancy Bear is APT28 (Russian GRU); Cozy Bear is APT29 (Russian SVR). Both are Russian, which is why the first option is tempting, but sharing a nationality and the BEAR suffix does not make them one actor. The second option states a true principle (vendors do give one actor several names) and applies it to the wrong pair. The third is wrong on the facts: Mandiant's APT## numbers are its nation-state designations, and FIN## is its separate label for financially motivated groups. Merging the two profiles would mix two actors' TTPs and indicators.",
      xp: 30,
    },

    // ── Question 3 ──────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "threat-intel-q3",
      question: "You work in an MSSP's SOC. A partner sends you a report on a phishing kit hitting your sector, marked TLP:AMBER (TLP 2.0). Which onward sharing does that label allow?",
      options: [
        "Posting the IOCs in your ISAC's members-only channel so sector peers can block them",
        "Warning the affected clients you protect, on a need-to-know basis, and no one wider",
        "Discussing it only with the analysts named on the partner's original distribution",
        "Using it inside your own SOC only; your clients may not be told about it at all",
      ],
      answer: 1,
      explanation: "TLP:AMBER allows sharing within your organisation and with its clients, on a need-to-know basis, so they can protect themselves. Sharing with sector peers in an ISAC channel is what TLP:GREEN allows; AMBER does not reach that far. Keeping it to the named recipients is TLP:RED. Keeping it inside your own SOC with no client warning is TLP:AMBER+STRICT, the level created to remove exactly the client sharing that plain AMBER permits, and the distinction that matters most in an MSSP.",
      xp: 30,
    },

    // ── Log Analysis: IOC Hit ────────────────────────────────────────────────
    {
      type: "log_analysis" as const,
      id: "threat-intel-la1",
      heading: "IOC Hit — CISA Automated Indicator Sharing (AIS) Feed Match",
      context: "You are a Tier-1 SOC analyst. The SIEM has fired a Priority-1 alert at 09:47 UTC. Your threat intelligence platform automatically enriched the alert with data from CISA's Automated Indicator Sharing (AIS) feed and CrowdStrike Intelligence. You also pulled the firewall records for the same flow: the sessions were allowed, they recur roughly every 5 minutes since 09:12 UTC, and more bytes left CORP-DC01 than came back. The matched event is below. Your job is to understand what happened and determine the correct response.",
      event: {
        id: "evt-ti-001",
        ts: "2025-06-24T09:47:13Z",
        source: "threat_intel",
        event_type: "ioc_hit",
        severity: "critical",
        hostname: "CORP-DC01",
        src_ip: "10.0.1.55",
        dst_ip: "185.220.101.45",
        description: "Outbound connection matched CISA AIS threat intel feed — APT29 C2 infrastructure",
        mitre_technique: "T1071.001",
        raw: {
          "rule.name": "CISA AIS IOC Match",
          "rule.level": "13",
          "data.indicator": "185.220.101.45",
          "data.indicator_type": "ip",
          "data.confidence": "high",
          "data.source": "CISA Automated Indicator Sharing (AIS)",
          "data.campaign": "APT29 SolarWinds",
          "data.actor": "Cozy Bear",
          "data.first_seen": "2024-12-13",
          "data.tlp": "CLEAR",
          "data.description": "C2 server associated with SolarWinds SUNBURST supply chain compromise",
          "matched.srcip": "10.0.1.55",
          "matched.dstip": "185.220.101.45",
          "matched.hostname": "CORP-DC01",
        },
      } satisfies TelemetryEvent,
      questions: [
        {
          question: "CORP-DC01 (10.0.1.55) is the company's domain controller, and the alert shows it connecting OUT to 185.220.101.45. Using the alert and the firewall records described above, what is the most accurate assessment?",
          options: [
            "False Positive — domain controllers routinely reach the internet for Windows updates",
            "Low priority — TLP:CLEAR marks the indicator as public, so it is probably stale",
            "Critical True Positive — allowed, repeating DC sessions to a high-confidence C2 IOC",
            "Hold at Tier-1 until a second intel feed corroborates the IOC, then raise severity",
          ],
          answer: 2,
          explanation: "Two independent things line up: a high-confidence government-sourced indicator for APT29 C2, and your own firewall records showing the domain controller's sessions to it were allowed, recur every ~5 minutes, and send out more than they receive — a beacon-like pattern. On the most sensitive server in Active Directory, that is a critical incident. Updates do not explain it: a DC fetches patches from internal WSUS or Microsoft update endpoints, not from an IP listed as C2. TLP:CLEAR is a rule about how widely the intelligence may be shared; it says nothing about the indicator's age or the incident's severity. Waiting for a second feed is the wrong move here, because your own logs already corroborate the match; validation means checking the session evidence, which you have done, not collecting more feeds while the beacon keeps running.",
          xp: 50,
        },
        {
          question: "What is the FIRST action you should take after confirming this is a True Positive?",
          options: [
            "Reset the krbtgt password twice right away, then block the IP at the firewall",
            "Take a full disk image of CORP-DC01 first, before any containment step begins",
            "Contain CORP-DC01's C2 path, coordinated with the AD owner, and escalate to IR now",
            "Block 185.220.101.45 at the perimeter firewall and close the alert as contained",
          ],
          answer: 2,
          explanation: "The first job is to cut the active C2 channel and get IR involved, because a nation-state actor on a domain controller is an incident, not a ticket. On a DC, containment needs care: fully isolating the only domain controller can break authentication across the domain, so coordinate with the AD owner and IR, and if full isolation is not possible, contain the C2 path with firewall rules first. Resetting krbtgt is an eradication step: done before scoping, it alerts the actor and does not stop the beacon. A full disk image is valuable evidence, but taking it before containment leaves the C2 session open for hours. Blocking only the one IP and closing the alert ignores everything the actor may already have done on the DC, and they can switch to a new C2 address.",
          xp: 50,
        },
      ],
    },

    // ── Flag Task ────────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "threat-intel-flag1",
      prompt: `Your detection engineers want to pull the technique profile of the actor behind the IOC alert above straight from MITRE ATT&CK, and their tooling looks groups up by ATT&CK ID, not by name. Identify the actor from the alert's enrichment, then enter that group's MITRE ATT&CK Group ID (format: G####).`,
      answer: "G0016",
      hint: "Two steps: find which actor the enrichment fields attribute the indicator to, then recall how Reading 2 says ATT&CK identifies a group, as opposed to the names vendors use.",
      xp: 60,
    },

    // ── Question 4 ──────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "threat-intel-q4",
      question: "A partner CERT invites your SOC to its MISP community. Which description of what you would be joining is accurate?",
      options: [
        "A paid commercial feed: the vendor's analysts curate IOCs and you consume them read-only",
        "An open-source platform where members share IOCs as events and attributes with partners",
        "The transport protocol that carries STIX bundles from one organisation's platform to another",
        "A sector-membership body, like FS-ISAC, that admits only organisations from one industry",
      ],
      answer: 1,
      explanation: "MISP is an open-source threat-intelligence sharing platform: organisations create “events” made up of “attributes” (individual IOCs) and share them with trusted partners, CERTs and ISACs, and members can contribute as well as consume. A curated, read-only paid feed describes commercial services such as Recorded Future or Mandiant Advantage. The protocol that carries STIX data between platforms is TAXII, not MISP. An ISAC is a sector-based sharing group; ISACs often run MISP instances, but MISP itself is the software, not a membership body limited to one industry.",
      xp: 30,
    },

    // ── Question 5 ──────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "threat-intel-q5",
      question: "Your company is a hospital. Leadership wants early warning when ransomware crews start hitting OTHER hospitals — what the attackers did and which indicators to watch — shared by sector peers under agreed sharing rules. Which source is built for that?",
      options: [
        "AlienVault OTX community pulses",
        "The CISA KEV vulnerability catalog",
        "H-ISAC member sharing channels",
        "Abuse.ch Feodo Tracker C2 lists",
      ],
      answer: 2,
      explanation: "An ISAC is where organisations in the same sector share threat intelligence with each other, and H-ISAC is the healthcare one: hospitals sharing ransomware indicators and what they saw. AlienVault OTX is a useful community feed, but contributors come from anywhere and it is not a peer group of hospitals working under agreed sharing rules. CISA KEV lists CVEs known to be exploited; it tells you what to patch, not what is hitting other hospitals this week. Feodo Tracker lists banking-trojan C2 servers: real indicators, but not sector early warning.",
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
  xp: 280,
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
      checkpoint: {
        question: "For the LAPTOP-JSMITH alert, you look up which hosting provider owns 185.220.101.47, which ports it exposes, and which TLS certificate it presents. Which OSINT category is that work?",
        options: [
          "Organisation OSINT",
          "Infrastructure OSINT",
          "Geolocation OSINT",
          "People OSINT",
        ],
        answer: 1,
        explanation: "Owner, ASN, hosting provider, open ports, services and TLS certificates of an IP are all Infrastructure OSINT, the category SOC analysts use most. Organisation OSINT is about a company's structure, staff, technology stack and job postings; a hosting provider's name turns up in your lookup, but you are researching the server, not the company. Geolocation OSINT places an IP or photo on a map, and it does not cover ports or certificates. People OSINT targets names, emails and usernames.",
      },
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
      checkpoint: {
        question: "A phishing email links to invoice-portal-update.com. You want to know how long ago the domain was registered and through which registrar. Which tool answers that directly?",
        options: [
          "Shodan",
          "URLScan.io",
          "WHOIS",
          "Censys",
        ],
        answer: 2,
        explanation: "WHOIS returns a domain's registration record: creation date, registrar, nameservers and expiry. Even with privacy protection hiding the owner, the registration date and registrar usually remain, and a newly registered domain raises suspicion. Shodan indexes what is running on IPs (ports, services, banners), not who registered a domain or when. URLScan.io renders the page in a sandbox to show what it does, not its registration history. Censys is strongest at finding servers that share a TLS certificate, not at reading registration records.",
      },
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

**In between — "active by proxy":** Sandbox URL scanners such as URLScan.io and Any.run fetch the URL *live* from their own infrastructure, so the attacker's server DOES see a request — just not from your IP. On URLScan, scans are also **Public** by default, visible to anyone (including the actor) and able to leak victim-specific tokens embedded in the URL; use **Unlisted** or **Private** visibility. The same rule applies to files: *search* VirusTotal for a hash (passive), but don't *upload* a sample unless policy allows it — uploads are visible to other subscribers, and actors watch for their own samples.

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
4. **URLScan** (active by proxy — use an Unlisted/Private scan): If there is a domain, what does the website show?
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
        "Port-scan the IP from a SOC jump host to see which services it is running now",
        "Submit the IP to a Public URLScan scan to see what its web service serves",
        "Look the IP up in Shodan and VirusTotal for existing ownership and reputation data",
        "Block the IP and close the alert, since blocking makes looking it up unnecessary",
      ],
      answer: 2,
      explanation: "Start with passive OSINT: Shodan and VirusTotal have already collected data on the IP, so your lookup sends nothing to it and gives you ownership, services and reputation in seconds. A port scan is active OSINT: it touches the target and shows up in its logs, whichever host it comes from, and is a last resort once passive sources are exhausted. A URLScan submission is active by proxy, because URLScan fetches the target live, and a Public scan also publishes the result where the actor can see it. Blocking without looking leaves the real question unanswered — what on the laptop made the connection, and is the host compromised?",
      xp: 30,
    },

    // ── Question 2 ──────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "osint-q2",
      question: "You discover that a malicious domain used in a phishing attack has a TLS certificate with `CN=login.secure-banking-portal.net`. You search Censys for other IPs using this same certificate CN. What is this investigation technique called?",
      options: [
        "Passive DNS pivoting — tracing which domains resolved to that same IP over time",
        "Certificate pivoting — finding other servers that present the same TLS certificate",
        "WHOIS pivoting — finding other domains registered with the same contact email",
        "Active scanning — probing the attacker's IP range to enumerate its other servers",
      ],
      answer: 1,
      explanation: "Searching Censys for other IPs that present the same certificate CN is certificate pivoting: attackers often reuse one certificate across their servers, so a single phishing domain can reveal the wider infrastructure. Passive DNS pivoting is a different, also valid technique, but it starts from an IP's resolution history, not from a certificate attribute. WHOIS pivoting starts from shared registration details such as a contact email, as in the Maltego example. Nothing here is active: Censys has already scanned and indexed the certificates, so your search sends no packets to the attacker.",
      xp: 30,
    },

    // ── Question 3 ──────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "osint-q3",
      question: "A targeted phishing email links to https://hr-docs-review.net/login?emp=70415, where 70415 is the recipient's employee number. You want to see what the page renders and where its form sends credentials. How should you run the URLScan.io check?",
      options: [
        "As a Public scan, so other defenders can find the result and block the domain too",
        "Skip URLScan and open the link in your own browser over the corporate VPN instead",
        "As an Unlisted or Private scan, because the URL carries a victim-specific token",
        "Any visibility works — URLScan is passive, so the actor's server sees no request",
      ],
      answer: 2,
      explanation: "URLScan is the right tool, but it is active by proxy: it fetches the URL live from its own infrastructure, so the actor's server does see a request. A Public scan also publishes the full URL, including the employee number, where anyone, the actor included, can find it, which confirms the target and tips off the actor. Use Unlisted or Private visibility. Sharing the domain with other defenders is a fair goal, but it can be done later through proper channels, without the victim token. Opening the link yourself is active OSINT from your own machine and puts it at risk; a VPN only changes the source IP. The last option is the misconception the room corrects: sandbox scanners are not passive.",
      xp: 30,
    },

    // ── Log Analysis: C2 Connection Discovered via OSINT ────────────────────
    {
      type: "log_analysis" as const,
      id: "osint-la1",
      heading: "Firewall Alert — Outbound HTTPS to an Unfamiliar IP, Enriched via Shodan",
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
          "shodan.org": "Stiftung Erneuerbare Freiheit",
          "shodan.tags": ["tor"],
          "shodan.open_ports": ["80", "443", "8080"],
          "shodan.ssl_subject": "CN=*.onion-router.net",
        },
      } satisfies TelemetryEvent,
      questions: [
        {
          question: "Read the Shodan enrichment fields. What kind of server is at 185.220.101.47, and what does that tell you about the laptop's traffic?",
          options: [
            "An ordinary Linux web host (ports 80/443/8080) — routine browsing, little to investigate",
            "A Tor relay — a corporate laptop talking to Tor suggests traffic being deliberately hidden",
            "A Tor onion service — the *.onion-router.net certificate shows it hosts a .onion website",
            "A privacy-VPN gateway run by a foundation — the user is probably on a personal VPN",
          ],
          answer: 1,
          explanation: "Shodan tags the IP as “tor”, and the network owner (shodan.org) is Stiftung Erneuerbare Freiheit, a foundation that runs Tor relays. A corporate laptop has no business reason to talk to Tor infrastructure: either the user is bypassing monitoring, or malware is using Tor to hide its C2. Both need investigation. To confirm the IP is an exit relay, the authoritative check is the Tor Project's own exit list or its ExoneraTor lookup. Reading only os and open_ports, as in the first option, ignores the tor tag. The certificate name does not make it an onion service: onion services are reached inside the Tor network, not at a public IP over plain HTTPS, and *.onion-router.net is the relay's own certificate. Nothing in the fields says VPN — guessing from a foundation's name instead of from the tag is a misreading.",
          xp: 50,
        },
        {
          question: "Shodan says Tor. You want more context on 185.220.101.47 before deciding how far to take the investigation, without tipping anyone off. Which next step fits the room's passive-first approach?",
          options: [
            "Port-scan 185.220.101.47 from the SOC subnet to confirm which Tor ports are open",
            "Treat shodan.org as proof the IP is the Tor Project's own server and stop the OSINT",
            "Check VirusTotal and ThreatFox for the IP before anything touches it directly",
            "Run a Public URLScan of https://185.220.101.47 to see what the server serves",
          ],
          answer: 2,
          explanation: "VirusTotal and ThreatFox/Abuse.ch are passive: they return what others have already recorded about the IP (vendor flags, related files and URLs, C2 tracking) without sending it a packet. That is the room's order of work, with active steps only after passive sources are exhausted. A port scan is active OSINT: your SOC subnet would appear in the relay operator's logs, and Shodan already lists the open ports. The org field names the organisation that holds the IP block — here a foundation that runs Tor relays, not the Tor Project, which writes the software while independent operators run the relays — so it proves nothing about the server on its own. A URLScan is active by proxy, and a Public scan publishes your interest for anyone to see.",
          xp: 50,
        },
      ],
    },

    // ── Flag Task ────────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "osint-flag1",
      prompt: `You want to run a certificate pivot on the server in the log above — searching Censys for other servers that present the same TLS certificate name. Find the certificate in the Shodan enrichment and enter the domain you would search for, without the "CN=" prefix and without the "*." wildcard.`,
      answer: "onion-router.net",
      hint: "Only one shodan.* field describes the server's TLS certificate, and its value is written in certificate-subject format (attribute=value).",
      xp: 60,
    },

    // ── Question 4 ──────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "osint-q4",
      question: "You are investigating a phishing email that carries both an attachment and a link. Which of these steps is fully passive — nothing reaches the actor's servers, and nothing new about your investigation becomes visible to the actor?",
      options: [
        "Submitting the email's link to URLScan.io as a Private scan to see the landing page",
        "Searching VirusTotal for the attachment's SHA-256 hash and the reports already there",
        "Uploading the attachment to VirusTotal to see how many engines detect it today",
        "Opening the link in an isolated VM routed through a VPN, so your own IP stays hidden",
      ],
      answer: 1,
      explanation: "Searching VirusTotal for a hash only reads what is already in its database: no packet reaches the actor, and the actor learns nothing. A Private URLScan stops the result being published, but URLScan still fetches the URL live, so the actor's server sees a request — active by proxy. Uploading the file makes the sample visible to other VirusTotal subscribers, and actors watch for their own samples, so it can reveal your investigation even though no packet reaches their server. A VM behind a VPN is good OPSEC for active work, but it is still active: the actor's server logs your visit, just from a different IP.",
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
  xp: 335,
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

NIST's classic 4-phase model (SP 800-61 Rev 2) uses 4 broader phases:
1. **Preparation**
2. **Detection & Analysis** (combines PICERL's Identification)
3. **Containment, Eradication & Recovery** (combines three PICERL phases)
4. **Post-Incident Activity** (Lessons Learned)

Note: Revision 3 (April 2025) reorganised incident response around the six functions of the Cybersecurity Framework 2.0 — Govern, Identify, Protect, Detect, Respond, Recover — rather than these fixed phases. The 4-phase model is still the clearest way to learn the mechanics and maps cleanly onto Rev 3's Detect/Respond/Recover, so it is how this room teaches it.

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
      checkpoint: {
        question: "According to the reading, what does the 'C' stand for in the SANS PICERL framework?",
        options: [
          "Communication",
          "Containment",
          "Correlation",
          "Coordination",
        ],
        answer: 1,
        explanation: "PICERL stands for Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned. Containment is the 'stop the bleeding' phase — isolating infected systems before doing anything else.",
      },
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

**The rule: never power off or reimage before memory is captured — but don't confuse powering off with isolating.**

**EDR network isolation** cuts the host off from the network while leaving it **powered on**, so RAM stays intact. If the system must be preserved for forensics, the correct order is:
1. **Isolate** the host via EDR network isolation — immediately, if the attack is actively spreading (encrypting shares, moving laterally). Every minute of delay is more damage, and isolation costs you no volatile evidence.
2. Capture a memory dump (RAM image) using tools like WinPMEM, DumpIt, or the EDR's built-in memory acquisition
3. Capture network state (open connections, listening ports) and running processes
4. Then — only then — consider powering down or reimaging

(If nothing is actively spreading, some teams capture memory and live network connections *before* isolating, to see the C2 sessions in action. During active spread, isolate first.)

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
      checkpoint: {
        question: "According to the reading, what is the critical rule about evidence preservation when responding to a compromised system?",
        options: [
          "Power off the machine immediately to stop the attack",
          "Never power off or reimage before capturing memory (RAM) — isolate instead, since powering off destroys volatile evidence",
          "Wait for legal approval before touching the machine at all",
          "Reimage the system immediately to restore service",
        ],
        answer: 1,
        explanation: "Turning off the machine first destroys volatile RAM — running processes, open connections, and decryption keys. EDR network isolation does not: the host stays powered on. So the order is: isolate (immediately if the attack is spreading), capture memory, then network state and processes, and only then consider powering down or reimaging.",
      },
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
      question: "A SOC analyst discovers an infected workstation is actively encrypting files on a network share. What should happen FIRST according to IR best practices?",
      options: [
        "Power off the machine immediately to stop the encryption",
        "Isolate it via EDR network isolation, which stops the spread but keeps it powered on, then capture memory",
        "Delete the ransomware binary the EDR identified to stop the encryption",
        "Reset the affected user's password to cut off the attacker's session",
      ],
      answer: 1,
      explanation: "The attack is actively spreading to a network share, so stopping the spread comes first — and EDR network isolation does that without costing any evidence: the host stays powered on, so RAM (running malware processes, encryption keys, attacker tools that never touched disk) is still there to capture right afterwards. Powering off would also stop the encryption but destroys that volatile evidence (and can corrupt half-encrypted files). Deleting the binary may not stop the running process and destroys evidence. Resetting the user's password does nothing to a process already running on the host. Isolate, then capture memory (CISA #StopRansomware Guide: immediately isolate impacted systems).",
      xp: 35,
    },

    // ── Question 2 ──────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "ir-method-q2",
      question: "During a post-incident review, the team discovers the attacker had been in the network for 45 days before detection. The company's backup retention policy only keeps 30 days of backups. What is the critical problem this creates during Recovery?",
      options: [
        "A 30-day window is an accepted standard, so any backup from the last month can be restored safely",
        "Every available backup may already hold the attacker's footholds, so restoring could reintroduce them",
        "The only issue is operational: older backups take longer to restore than a fresh one",
        "Backup age does not matter — restore from whichever backup is newest when recovery begins",
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
            "svchost.exe routinely runs from C:\\Windows\\Temp\\ during Windows Update cycles",
            "Legitimate svchost.exe runs from C:\\Windows\\System32\\; one in Temp is almost certainly malware masquerading under that name",
            "Only the process name matters when judging legitimacy; the file path is irrelevant",
            "C:\\Windows\\Temp\\ is write-protected, so malware cannot normally place files there",
          ],
          answer: 1,
          explanation: "The legitimate Windows svchost.exe (Service Host) ALWAYS runs from C:\\Windows\\System32\\. Malware authors frequently copy their malicious executable into C:\\Windows\\Temp\\ and name it 'svchost.exe' to blend in with normal process lists. This is called Masquerading (MITRE T1036.005 — Match Legitimate Name or Location). Note it is the opposite of living-off-the-land, which abuses the genuine built-in binaries; here a malicious file merely wears a system name. Any svchost.exe running from Temp, AppData, or any path other than System32 is almost certainly malicious. The EDR caught this exact pattern.",
          xp: 50,
        },
        {
          question: "The alert shows `s1.affectedVolumes: C:\\, D:\\, \\\\SRV-NAS01\\shared` and `s1.networkShares_accessed: 3`. What does this tell you about the scope of this incident?",
          options: [
            "Activity is confined to SRV-FILE01's C: drive; the D: drive and share fields are informational",
            "Ransomware hit both local drives and is encrypting a network share (SRV-NAS01) — a multi-system P1; contain SRV-FILE01 and SRV-NAS01",
            "The shares were only enumerated and never encrypted, so no further containment is needed",
            "This is normal file-server activity — servers routinely enumerate and access network shares",
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
        "To find which analyst missed the initial alert and decide corrective action; held within a month",
        "To analyse the timeline, root cause and detection gaps and agree improvements; held within 24-72 hours of resolution",
        "To brief leadership and legal on regulatory notification duties; held during the active incident",
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
  xp: 310,
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
      checkpoint: {
        question: "Two alerts arrive together: a High-severity malware alert on a lab VM that is scheduled to be rebuilt tonight, and a Medium-severity alert on the CFO's laptop, signed in with an account that approves payments. Which do you open first?",
        options: [
          "The High alert — rule severity sets the order before any other factor is weighed",
          "The Medium alert — asset criticality and user risk outweigh the severity gap here",
          "Whichever fired first — the queue is worked in arrival order so nothing is skipped",
          "Neither yet — set the priority once each alert is confirmed as a True Positive",
        ],
        answer: 1,
        explanation: "Priority combines severity, asset criticality and user risk. The CFO's laptop and a payment-approving account score high on both of the last two, while a lab VM about to be rebuilt scores low on asset criticality, so the Medium alert comes first. Severity is only one of the three factors, so it cannot set the order alone. Working strictly in arrival order is the habit triage exists to replace: the ER nurse does not treat patients in the order they walked in. Priority decides which alert you triage first, so it has to be set before you know whether either is a True Positive.",
      },
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

**Close as False Positive**: The rule logic itself misfired — the activity does not actually match what the rule is meant to detect (e.g., a "credential dumping" rule matching a backup tool that only read a file with a similar name). Document your reasoning and request a rule tune.

**Close as Benign True Positive**: The rule fired correctly but the activity is authorised. Document who approved the activity (e.g., "IT admin running scheduled script per change ticket CHG-4421").

**Escalate as True Positive**: This is a real attack or confirmed suspicious activity requiring incident response. Create a P1/P2/P3 ticket, write a triage summary (what you found and why it is suspicious), and hand off to Tier-2.

**Escalate as Indeterminate**: You need more data (additional logs, forensics, threat hunting). Document what you have and what additional investigation is needed.

Never make a determination without documenting your reasoning. If you close an alert and it later turns out to be an attack, you need to be able to show your logic.`,
      checkpoint: {
        question: "You have read every field of the raw 4625 event. Now you are looking up the source IP's reputation and geolocation and checking the target user's department. Which step are you in, and what comes next?",
        options: [
          "Step 2, Examine the evidence — next you enrich the IP and the user",
          "Step 4, Assess the impact — next you make and document a decision",
          "Step 3, Enrich with context — next you assess the potential impact",
          "Step 1, Understand the rule — next you open and read the raw log",
        ],
        answer: 2,
        explanation: "Reputation, geolocation and the user's department are context added on top of the raw fields — Step 3, Enrich with context. The next step is Step 4: if this is real, how bad would it be? Step 2 is what you just finished (reading the raw event), so you are past it. Step 4 is the step after this one: impact assessment uses the context you are gathering now. Step 1 is reading the rule name and intent, which comes before opening the raw log.",
      },
    },

    // ── Reading 3: False Positive Patterns, Escalation, and Documentation ────
    {
      type: "reading" as const,
      id: "alert-triage-r3",
      heading: "Recognising False Positives, Knowing When to Escalate, and Writing Good Tickets",
      content: `Experience makes triage faster. After a few months in a SOC, analysts develop pattern recognition — they instantly know certain alert patterns are almost always false positives, while other patterns are almost always real. Here is a structured overview of the most common scenarios.

---

**Common Benign Patterns (False Positives and Benign True Positives)**

These patterns produce alerts that turn out not to be attacks. Label them carefully: if the rule matched real, authorised activity (an approved script, a scheduled scan), it is a **Benign True Positive**; reserve **False Positive** for cases where the rule logic itself misfired.

**IT Admin Scripts**
Your detection rule fires on "PowerShell script with base64-encoded commands" — and attackers do use base64-encoded PowerShell. But so does legitimate IT automation. If the alert came from a known IT admin's workstation at 10 AM on a weekday, the parent process is their RMM tool (e.g., Datto, ConnectWise), and there is a change ticket for scheduled maintenance — this is almost certainly a Benign True Positive (authorised activity that the rule correctly detected), not an attack.

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

When you escalate a credential attack, name its shape with the right MITRE ATT&CK sub-technique of Brute Force (T1110): **T1110.001 Password Guessing** (many passwords against one account), **T1110.003 Password Spraying** (one or a few passwords against many accounts, kept under the lockout threshold) and **T1110.004 Credential Stuffing** (username/password pairs leaked from other breaches).

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
        "Work through the 100 alerts one at a time, in arrival order, so none is missed",
        "Isolate WORKSTATION-KLEE at once, then begin reading the alerts in the queue",
        "Sample a few alerts, then pivot on the host to see which rules and patterns repeat",
        "Open the highest-severity alert, then close the other 99 as its duplicates",
      ],
      answer: 2,
      explanation: "With many alerts from one host, find the pattern before diving into individual alerts. Open two or three representative samples (same rule? same source? same timing?) and pivot in the SIEM on all alerts for WORKSTATION-KLEE in the last 7 days. That shows whether it is one rule firing over and over, such as a service account retrying a stale password, or several different alert types that together point to an active attack. Going one by one in arrival order is the analysis-paralysis trap: hours on a cluster that one pivot could explain. Isolating before you know what the alerts are is the right tool at the wrong time: it may cut off a user over a noisy rule. The highest-severity alert is a good place to start, but closing the rest unread as duplicates could throw away the different alert types that reveal an attack.",
      xp: 30,
    },

    // ── Question 2 ──────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "alert-triage-q2",
      question: "An alert fires: 'PowerShell with base64-encoded command detected — workstation LAPTOP-MSMITH.' You look at the raw log and see: source = LAPTOP-MSMITH, user = msmith (IT operations), parent process = the IT team's Datto RMM agent, time = 14:32 Tuesday (business hours), and a ServiceNow change ticket for msmith reads 'IT audit script 14:00-15:00'. What is your determination?",
      options: [
        "True Positive — encoded PowerShell is a known attacker technique, so escalate it",
        "Benign True Positive — the rule matched real activity, and that work is ticketed",
        "False Positive — the rule misfired, because the activity is legitimate IT work",
        "Indeterminate — timing and a parent process alone cannot clear an alert, escalate",
      ],
      answer: 1,
      explanation: "This is a Benign True Positive: the rule did exactly what it was built to do — it detected base64-encoded PowerShell, and that PowerShell really ran — but the activity is authorised: an IT-operations user, the team's RMM agent as parent, inside the window of a matching change ticket. Close it with BTP documentation (who approved it, which ticket), and consider a narrow exclusion for this RMM path. Calling it a True Positive treats the technique as the verdict; attackers do use encoded PowerShell, but so does IT automation, and the context here explains it. It is not a False Positive, because the rule did not misfire: FP is for rule logic that matched something it was not meant to detect. Indeterminate misreads the evidence: you are not relying on timing and parent process alone, because the change ticket ties this exact activity to an approved task.",
      xp: 30,
    },

    // ── Question 3 ──────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "alert-triage-q3",
      question: "Four authentication alerts are waiting, and each has at least one worrying detail. Which one shows the strongest True Positive signals and should be escalated first?",
      options: [
        "Internal 10.0.4.12: a 4625 every 5 min for a week, same service account, same server",
        "External IP, new country for this user: 2 failures then a success, at 03:10 local time",
        "Nessus host 10.0.0.50: 400 ports swept at 23:00 Wednesday, scan window on the calendar",
        "User's own VPN laptop: six 4625s then a success at 02:00, during an on-call week",
      ],
      answer: 1,
      explanation: "The second alert stacks the strongest signals: an external source, a country this user has never worked from, a success right after failures, and a time when the user would normally be asleep. Only two failures is not reassuring; it can mean the attacker already had a nearly correct password, and the success is what matters. The first alert is high-volume but has the legacy pattern: internal source, fixed 5-minute rhythm, one account, one server — a service retrying a stale password. The scanner sweep looks like an attack and runs at night, but it comes from the known scanner IP inside its scheduled window, which makes it a Benign True Positive. The night-time failures-then-success on the user's own VPN laptop during an on-call week has a plausible innocent explanation (an on-call engineer mistyping a password at 02:00), so it is worth a check but ranks below an external login from a new country.",
      xp: 30,
    },

    // ── Log Analysis: Brute-Force Password Guessing vs. Legitimate Lockout ────
    {
      type: "log_analysis" as const,
      id: "alert-triage-la1",
      heading: "Triage Scenario — 347 Failed Logins Against a Single Account",
      context: "You are a Tier-1 SOC analyst. The SIEM has fired a 'Brute Force Authentication' alert. 347 failed logins for the 'administrator' account have occurred in a 5-minute window. The raw Windows Security Event log is below. This is your triage exercise — determine whether this is a genuine attack or a legitimate administrative issue, and be precise about WHICH kind of credential attack it is.",
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
        // T1110.001 (Password Guessing), NOT T1110.003 (Password Spraying).
        // Spraying is ONE password against MANY accounts to stay under lockout
        // thresholds; this is the opposite shape — many passwords against ONE
        // account. The distinction is taught in auth-identity-monitoring and
        // use-case-development, and this room must not contradict them.
        mitre_technique: "T1110.001",
        vendor: "Windows Security",
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
          question: "Analyse the raw log fields. Which set of THREE indicators most strongly supports a genuine brute-force attack rather than a legitimate issue?",
          options: [
            "External 203.0.113.45 (Moscow); 347 failures in 300 s from it; target is 'administrator'",
            "Event code 4625; SubStatus 0xC000006A (bad password); logged in the Security channel",
            "LogonType 3; the failures were recorded on CORP-DC01; rule name 'Brute Force Authentication'",
            "Moscow geolocation; 347 failures in 300 s; WorkstationName is blank on the attempts",
          ],
          answer: 0,
          explanation: "The strongest set is external source in Moscow, 347 failures in 300 seconds from that one IP, and the built-in 'administrator' account as the target. An external IP making network logons against CORP-DC01 should not happen at all, the rate is far too fast for a human typing, and attackers go after 'administrator' because it gives full control. The second set is all non-diagnostic: 4625 is logged for every failed logon, 0xC000006A only says the password was wrong, and the channel is where every such event is stored. The third set mixes context with the alert's own label: LogonType 3 is an ordinary network logon, the DC tells you how much is at stake (impact) rather than whether it is an attack, and the rule name is what you are trying to verify, not evidence for it. The fourth shares two strong indicators but swaps the privileged target for a blank WorkstationName, which is common on network logons and proves little on its own.\n\nName it precisely: this is password GUESSING — many passwords against one account. It is NOT password spraying, which is the opposite shape: one password against many accounts, deliberately staying under the lockout threshold. The volume here (347 attempts on a single account in five minutes) is the exact loud pattern a sprayer works to avoid.",
          xp: 50,
        },
        {
          question: "Based on your triage, what determination do you make and what is your recommended immediate action?",
          options: [
            "False Positive — a service with a stale stored password is retrying; close and request a tune",
            "Benign True Positive — most likely an authorised external pen test; close with documentation",
            "True Positive — escalate, block 203.0.113.45, and search for any 4624 success from that IP",
            "Indeterminate — no logon has succeeded yet, so hold containment and keep watching the account",
          ],
          answer: 2,
          explanation: "This is a True Positive: an external IP, a machine-speed burst of failures, and the most privileged account as the target. Escalate now and act: block 203.0.113.45 at the perimeter, and search for any successful logon (Event 4624) from that IP — a success would make this a confirmed compromise of the administrator account and raise the urgency further. Then ask why CORP-DC01 accepts network logons from the internet at all: the real fix is to remove that external exposure and require VPN, not to geo-block one country. The stale-password pattern does not fit: it comes from an internal server at a steady rhythm, not 347 attempts in five minutes from an external IP. A pen test would be a Benign True Positive only with evidence such as an approved engagement and a known tester IP, and there is none here, so assuming one is a guess. Indeterminate is wrong because the evidence is already conclusive; waiting for a success means acting after the account is lost.",
          xp: 50,
        },
      ],
    },

    // ── Flag Task ────────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "alert-triage-flag1",
      prompt: `Your escalation ticket for the brute-force alert above needs the precise MITRE ATT&CK sub-technique of Brute Force (T1110). Work out the attack's shape from the raw fields — how many accounts were targeted, and how many attempts were made against them — and enter the matching sub-technique ID (format: T####.###).`,
      answer: "T1110.001",
      hint: "Compare the number of distinct target accounts with the attempt count, then use the Brute Force sub-technique list in Reading 3.",
      xp: 60,
    },

    // ── Question 4 ──────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "alert-triage-q4",
      question: "When writing triage documentation to close an alert as a False Positive, which information is MOST important to include?",
      options: [
        "The alert ID, closure time and verdict — the SIEM already keeps all the evidence",
        "What triggered, what you checked, why it is benign, and whether the rule needs a tune",
        "The ticket numbers of earlier alerts from this rule that were also closed as FPs",
        "The full raw log pasted into the ticket, so reviewers can re-derive the verdict",
      ],
      answer: 1,
      explanation: "A False Positive closure note needs your reasoning, not just the outcome: what triggered, which logs and tools you checked, the specific evidence that makes it benign, and a tuning recommendation if the pattern will recur. That protects you if the call is questioned, helps colleagues who meet the pattern again, and gives detection engineers what they need to fix the rule. ID, time and verdict alone record the decision, not why it was right. Earlier FP closures from the same rule show history, but a pattern of past closures is not evidence that this alert is benign. Pasting the raw log keeps the evidence but leaves every reviewer to redo your analysis: the note must say what the evidence means.",
      xp: 30,
    },

    // ── Question 5 ──────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "alert-triage-q5",
      question: "A Tier-1 analyst has spent 20 minutes triaging an alert involving an internal server making unusual external connections. The analyst cannot determine whether it is legitimate software behaviour or malware. The server hosts the company's main customer database. What should the analyst do?",
      options: [
        "Close it as a False Positive, since 20 minutes of triage found no confirmed attack",
        "Keep investigating alone until the cause is certain, to avoid a needless escalation",
        "Escalate to Tier-2 as Indeterminate, documenting findings and the crown-jewel asset",
        "Isolate the database server now, then close the alert as a contained True Positive",
      ],
      answer: 2,
      explanation: "When you cannot reach a confident determination, and especially on a crown-jewel asset like the main customer database, escalate as Indeterminate and include everything you found so Tier-2 does not repeat your work. The reading's guideline is to escalate once you have spent 15+ minutes without a determination. Not finding proof of an attack is not proof of benign activity, so closing it as a False Positive turns uncertainty into a verdict. Investigating alone for hours is the analysis-paralysis failure mode; escalating an uncertain crown-jewel alert is exactly what escalation is for. Isolating the customer database on an unconfirmed alert could take the business offline, and calling it a contained True Positive claims a verdict you do not have. Containment decisions on an asset like this belong with Tier-2/IR.",
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
