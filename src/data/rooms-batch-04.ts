/**
 * Learning Rooms — Batch 04
 * SIEM Track: Log Management, SIEM Fundamentals, Wazuh, Microsoft Sentinel
 *
 * Four progressive rooms covering the full SIEM stack from raw logs to
 * cloud-native detection. Suitable for absolute beginners — every concept
 * is introduced with a real-world analogy before the technical definition.
 */

import type { TelemetryEvent } from "@/lib/sim/types";

// ---------------------------------------------------------------------------
// Task type re-exports (mirrors rooms.ts to keep rooms-batch-04 self-contained)
// ---------------------------------------------------------------------------

interface ReadingTask {
  type: "reading";
  id: string;
  heading: string;
  content: string;
  codeExample?: string;
  checkpoint?: {
    question: string;
    options: string[];
    answer: number;
    explanation?: string;
  };
}

interface QuestionTask {
  type: "question";
  id: string;
  question: string;
  options: string[];
  answer: number;
  explanation: string;
  xp: number;
}

interface LogAnalysisTask {
  type: "log_analysis";
  id: string;
  heading: string;
  context: string;
  event: TelemetryEvent;
  questions: {
    question: string;
    options: string[];
    answer: number;
    explanation: string;
    xp: number;
  }[];
}

interface FlagTask {
  type: "flag";
  id: string;
  prompt: string;
  answer: string;
  hint?: string;
  xp: number;
}

interface QueryFillTask {
  type: "query_fill";
  id: string;
  heading: string;
  language: "kql" | "spl";
  context: string;
  template: string;
  blanks: { id: string; answers: string[]; placeholder?: string }[];
  explanation: string;
  xp: number;
}

interface AnalystChoiceTask {
  type: "analyst_choice";
  id: string;
  heading: string;
  scenario: string;
  event: TelemetryEvent;
  correct_verdict: "true_positive" | "false_positive" | "escalate" | "informational";
  explanation: string;
  fp_trap?: string;
  xp: number;
}

type RoomTask = ReadingTask | QuestionTask | LogAnalysisTask | FlagTask | QueryFillTask | AnalystChoiceTask;

interface Room {
  id: string;
  title: string;
  description: string;
  difficulty: "beginner" | "intermediate" | "advanced";
  category: string;
  estimatedMinutes: number;
  xp: number;
  icon: string;
  prerequisites: string[];
  tasks: RoomTask[];
}

// ---------------------------------------------------------------------------
// Room 1 — Log Management Fundamentals
// ---------------------------------------------------------------------------

const logManagement: Room = {
  id: "log-management",
  title: "Log Management Fundamentals",
  description:
    "Learn what logs are, where they come from, how they are collected and normalised, and why they are the foundation of every SOC. No prior cybersecurity knowledge required.",
  difficulty: "beginner",
  category: "SIEM",
  estimatedMinutes: 35,
  xp: 185,
  icon: "📂",
  // "No prior cybersecurity knowledge required" (see description) — so it must NOT
  // sit behind linux-log-analysis (intermediate: SSH brute-force, auditd, cron
  // persistence). That inversion forced a beginner to analyse Linux logs before
  // the room that teaches what a log even is. Gate on the entry room only.
  prerequisites: ["intro-cybersecurity"],
  tasks: [
    // ----- Reading 1: What is a log? ----------------------------------------
    {
      type: "reading",
      id: "log-mgmt-r1",
      heading: "What Are Logs? The Digital CCTV of IT Systems",
      content: `Imagine your office building has CCTV cameras recording everything that happens: who came in the front door at what time, which rooms they entered, when the fire alarm was triggered. If something bad happens — a theft, an accident — you review the footage to understand exactly what occurred and who was involved.

**Computer systems do the same thing with logs.**

A **log** (also called a log entry or log record) is a written record of something that happened on a computer system. Every time a user logs in, a file is opened, a network connection is made, or a system setting changes — a log entry is created. These entries are saved to log files that security teams can search later.

**Why do logs exist?**

Logs were originally created for IT troubleshooting. If a web server crashed, engineers would read its logs to find out why. Over time, security teams realised that logs are also an incredible source of evidence for detecting attacks, investigating breaches, and proving compliance with regulations.

**What is in a single log entry?**

Every log entry typically contains:

- **Timestamp** — exactly when the event happened (e.g., 2025-06-24T14:32:11Z)
- **Source** — which device or application generated the record (e.g., LAPTOP-SALES-01)
- **Event type** — what happened (e.g., "user login", "file deleted", "firewall blocked connection")
- **Actor** — who or what caused the event (e.g., j.smith@company.com)
- **Details** — additional context (e.g., the IP address used, the filename, the destination port)

**The four main log sources in a corporate environment:**

- **Endpoints** — Windows PCs, Linux servers, and macOS machines all generate logs. Windows logs go to the Windows Event Log; Linux logs typically go to /var/log/. These tell you what processes ran, who logged in, and what files changed.
- **Network devices** — Firewalls, routers, and switches log every allowed and blocked network connection. These tell you what traffic moved between which IP addresses.
- **Applications** — Web servers (Apache, Nginx), databases (SQL Server, MySQL), and SaaS services (Microsoft 365, Salesforce) log user activity and errors.
- **Cloud platforms** — AWS CloudTrail records every API call made in an AWS account. Azure Activity Logs and Azure AD Sign-In Logs do the same for Microsoft cloud services.

**Common log formats:**

Logs come in many different formats depending on the vendor and application. The most common ones you will see in a SOC are:

- **Plain-text Syslog** — the oldest and most widespread format. A single line per event, human-readable but inconsistently structured. Example: \`Jun 24 14:32:11 fw01 kernel: DROP IN=eth0 SRC=185.220.101.45 DST=10.0.0.5\`
- **Structured JSON** — modern applications write logs as JSON objects with named fields. Easy for machines to parse. Example: \`{"timestamp":"2025-06-24T14:32:11Z","user":"j.smith","action":"login","result":"success"}\`
- **CEF (Common Event Format)** — a standard created by ArcSight/Micro Focus, widely used by security appliances. Looks like: \`CEF:0|Palo Alto|PAN-OS|10.1|TRAFFIC|Traffic log|3|src=10.1.1.5 dst=8.8.8.8\`
- **LEEF (Log Event Extended Format)** — similar to CEF, created by IBM QRadar. Used by many network appliances.

The key challenge is that every vendor uses a slightly different format. A firewall from Palo Alto logs in a different structure than a firewall from Fortinet. A Windows login event looks nothing like a Linux SSH login. This is why **log normalisation** exists — we will cover that next.`,
      checkpoint: {
        question:
          "According to the reading, what standard created by ArcSight/Micro Focus is a common log format used by security appliances?",
        options: ["CEF (Common Event Format)", "ECS (Elastic Common Schema)", "Plain-text Syslog", "JSON"],
        answer: 0,
        explanation:
          "CEF (Common Event Format) is the ArcSight/Micro Focus standard widely used by security appliances. LEEF is IBM QRadar's similar format, and ECS is a normalisation schema rather than a source log format.",
      },
    } satisfies ReadingTask,

    // ----- Reading 2: Log collection and normalisation ----------------------
    {
      type: "reading",
      id: "log-mgmt-r2",
      heading: "Log Collection, Normalisation, and the Log Lifecycle",
      content: `Now that we know what logs are, we need to understand how they travel from thousands of devices scattered across an organisation into one central place where analysts can search them.

**Log Collection Methods**

There are three primary ways to collect logs:

**1. Agent-based collection** — a small software program (called an agent) is installed on each endpoint. The agent reads local log files and ships them to a central server in real time. Examples:
- **Winlogbeat** — reads Windows Event Logs and sends them to Elasticsearch
- **Filebeat** — reads any log file on Linux or Windows and ships it
- **osquery** — turns the operating system into a queryable database, ideal for EDR-style visibility

Agents give you the richest, most reliable collection but require software deployment on every machine.

**2. Agentless collection (Syslog)** — network devices like firewalls and switches cannot have software installed on them. Instead, they are configured to send logs via the **Syslog protocol** over **UDP or TCP port 514** to a central log collector (often called a syslog server). Simple, low-overhead, but logs can be lost if the network drops.

**3. API polling** — cloud services (Microsoft 365, AWS, Okta) expose APIs that the SIEM can call periodically to retrieve logs. For example, Microsoft Sentinel calls the Microsoft Graph Security API every few minutes to pull new Azure AD sign-in events.

**Log Normalisation: Speaking the Same Language**

Imagine you receive incident reports written in English, Hebrew, and Arabic. To compare them, you first need to translate everything into one language. Log normalisation does exactly that for log data.

**Normalisation** converts logs from different vendors into a single, consistent field structure. A Windows login event and a Linux SSH login event both represent "a user authenticated to a system" — but the raw fields look completely different:

- Windows: \`EventID=4624, TargetUserName=j.smith, IpAddress=10.1.1.5, LogonType=3\`
- Linux SSH: \`sshd[1234]: Accepted publickey for j.smith from 10.1.1.5 port 54321\`

After normalisation, both become something like: \`{"event.category":"authentication","user.name":"j.smith","source.ip":"10.1.1.5","event.outcome":"success"}\`

The most widely adopted normalisation standard is **ECS — Elastic Common Schema**. ECS defines standard field names (user.name, source.ip, event.type, etc.) that mean the same thing regardless of the original log source. When all logs use ECS, a single search query works across Windows, Linux, firewall, and cloud logs simultaneously.

**The Log Lifecycle**

Logs do not live forever. They go through a defined lifecycle:

1. **Generate** — the source device creates the log entry
2. **Collect** — an agent or syslog server picks it up
3. **Normalise** — fields are mapped to a common schema
4. **Store** — logs are written to an index or database (e.g., Elasticsearch, Splunk)
5. **Analyse** — analysts and automated rules search the stored logs
6. **Retain** — logs are kept for a minimum period required by regulation
7. **Delete** — logs are safely purged when the retention period expires

**Retention Requirements**

How long must logs be kept? It depends on the regulations your organisation is subject to:

- **GDPR (EU data protection)** — no fixed minimum, but typically 12 months for security logs. Data must not be kept longer than necessary.
- **PCI-DSS (payment card industry)** — at least **12 months**, with the most recent 3 months immediately available for analysis.
- **HIPAA (US healthcare)** — security-related records must be kept for **6 years**.
- **SOX (US financial reporting)** — audit logs must be kept for **7 years**.

Storing logs is expensive. A busy environment can generate **millions of events per day**. Log volume is measured in **EPS — Events Per Second**. A small organisation might generate 500 EPS; a large enterprise can exceed 100,000 EPS. At 1,000 EPS with an average event size of 500 bytes, you accumulate approximately **43 GB of raw log data per day**. SIEMs typically compress and index logs, reducing storage by 70-80%, but retention costs are still significant and must be budgeted carefully.`,
    } satisfies ReadingTask,

    // ----- Question 1 -------------------------------------------------------
    {
      type: "question",
      id: "log-mgmt-q1",
      question:
        "A SOC team collects logs from firewalls, Windows endpoints, and Linux servers. Each source uses a different field name for the source IP address. Which process converts these different field names into a single standard field called 'source.ip'?",
      options: [
        "Log collection",
        "Log normalisation",
        "Log retention",
        "Log deletion",
      ],
      answer: 1,
      explanation:
        "Log normalisation maps inconsistent vendor-specific field names (srcip, src_address, IpAddress, etc.) into a single standardised schema such as ECS. This allows analysts to write one search query that works across all log sources simultaneously.",
      xp: 20,
    } satisfies QuestionTask,

    // ----- Question 2: storage calculation ----------------------------------
    {
      type: "question",
      id: "log-mgmt-q2",
      question:
        "Your environment generates 1,000 events per second (EPS). Each event averages 500 bytes. How many bytes of raw log data are generated in a single day (86,400 seconds)?",
      options: [
        "500,000 bytes (500 KB)",
        "86,400,000 bytes (86.4 MB)",
        "43,200,000,000 bytes (43.2 GB)",
        "500,000,000,000 bytes (500 GB)",
      ],
      answer: 2,
      explanation:
        "1,000 EPS × 500 bytes × 86,400 seconds = 43,200,000,000 bytes = approximately 43.2 GB per day of raw uncompressed logs. After SIEM compression (typically 70-80%), storage drops to roughly 8-13 GB per day, but this still adds up quickly over months of retention.",
      xp: 25,
    } satisfies QuestionTask,

    // ----- Reading 3: Log tampering and SIEM vs. aggregator ----------------
    {
      type: "reading",
      id: "log-mgmt-r3",
      heading: "Log Tampering, Log Retention, and SIEM vs. Log Aggregators",
      content: `**Why Attackers Delete Logs**

Imagine a burglar who, after robbing a house, goes back and destroys all the CCTV footage before leaving. Sophisticated attackers do exactly this — they attempt to delete or modify log files to hide the evidence of their intrusion.

This is called **log tampering** or **log clearing**. On Windows systems, the Security Event Log can be cleared using the Event Viewer or via the command line. When this happens, Windows itself records a special event:

- **Event ID 1102** — "The audit log was cleared." This event appears in the Security channel and records which user account cleared the log.
- **Event ID 104** — The System log was cleared (slightly different channel).

On Linux, attackers may delete or modify files in /var/log/ — for example, deleting /var/log/auth.log to remove SSH login records, or editing /var/log/wtmp to remove evidence of their session.

**How do we defend against log tampering?**

The key defence is **centralised, immutable log storage**. If every log is immediately shipped to a remote log server that the attacker cannot access, deleting the local logs on the compromised machine does not help the attacker — all the evidence is already safely stored elsewhere. This is why collecting and forwarding logs in real time is a security requirement, not just an operational convenience.

Some organisations use **WORM storage** (Write Once, Read Many) or cloud-based log storage with immutability policies, making it technically impossible to alter or delete stored logs.

**SIEM vs. Log Aggregator: What is the Difference?**

A **log aggregator** (sometimes called a log management platform) is a system that collects, stores, and lets you search logs. Examples include Graylog and basic Elasticsearch deployments. A log aggregator answers the question: *"Show me all logs from server X between 2pm and 3pm."*

A **SIEM** (Security Information and Event Management) does everything a log aggregator does, but adds a critical layer on top: **automated detection and correlation**. A SIEM answers a very different question: *"Are there any patterns across all my logs that indicate an attack is happening right now?"*

The key capabilities that a SIEM adds beyond simple log storage are:

- **Correlation rules** — automatically detect patterns across multiple events (e.g., "5 failed logins followed by a successful login from the same IP within 10 minutes")
- **Alerting** — generate real-time alerts when suspicious patterns are detected
- **Dashboards** — visual overviews of security posture, top threat sources, alert trends
- **Case management** — link related alerts into a single incident for investigation
- **Threat intelligence integration** — automatically flag known malicious IPs, domains, and file hashes
- **MITRE ATT&CK mapping** — classify detections against the industry-standard attack framework

In summary: a log aggregator is a **storage and search engine**. A SIEM is a **detection and investigation platform** built on top of log storage.`,
      checkpoint: {
        question:
          "According to the reading, which Windows Event ID is generated when the Security audit log is cleared?",
        options: ["Event ID 1102", "Event ID 4624", "Event ID 104", "Event ID 4720"],
        answer: 0,
        explanation:
          "Event ID 1102 — 'The audit log was cleared' — fires in the Security channel and records which account cleared it. Event ID 104 is the equivalent for the System log, not Security.",
      },
    } satisfies ReadingTask,

    // ----- Log Analysis: audit log cleared ----------------------------------
    {
      type: "log_analysis",
      id: "log-mgmt-la1",
      heading: "Suspicious: Security Audit Log Cleared",
      context:
        "You are a junior SOC analyst. A SIEM alert has fired and you are reviewing the underlying log event. A Windows server has generated a security event that the SIEM flagged as high severity. Review the event fields carefully and answer the questions below.",
      event: {
        id: "log-mgmt-evt-001",
        ts: "2025-06-24T03:17:44Z",
        source: "windows_security",
        event_type: "audit_log_cleared",
        severity: "high",
        hostname: "DC01-CORP",
        description: "Security audit log was cleared on domain controller",
        mitre_technique: "T1070.001",
        vendor: "Windows Security",
        raw: {
          "event.code": "1102",
          "winlog.event_data.SubjectUserName": "svc-helpdesk02",
          "winlog.event_data.SubjectDomainName": "CORP",
          "winlog.event_data.SubjectLogonId": "0x3E4F2A",
          "winlog.channel": "Security",
          "winlog.provider_name": "Microsoft-Windows-Eventlog",
          "winlog.computer_name": "DC01-CORP",
          "event.created": "2025-06-24T03:17:44.112Z",
          "event.action": "audit-log-cleared",
          "log.level": "information",
        },
      } satisfies TelemetryEvent,
      questions: [
        {
          question:
            "What Windows Event ID was generated, and what does it indicate?",
          options: [
            "Event ID 4625 — a failed login attempt",
            "Event ID 1102 — the Security audit log was cleared",
            "Event ID 4688 — a new process was created",
            "Event ID 4728 — a user was added to a security group",
          ],
          answer: 1,
          explanation:
            "The raw field 'event.code: 1102' maps to Windows Event ID 1102, which is specifically generated when the Security audit log is cleared. This is a high-confidence indicator of an attacker attempting to destroy evidence after a compromise.",
          xp: 25,
        },
        {
          question:
            "The event occurred at 03:17 UTC on a domain controller. Which field tells you the account responsible for clearing the log?",
          options: [
            "winlog.channel",
            "winlog.computer_name",
            "winlog.event_data.SubjectUserName",
            "winlog.provider_name",
          ],
          answer: 2,
          explanation:
            "The 'winlog.event_data.SubjectUserName' field contains 'svc-helpdesk02' — the account that cleared the log. The unusual account name, combined with the 3am timing on a domain controller, makes this highly suspicious. A legitimate IT admin would rarely clear Security logs on a DC at 3am.",
          xp: 25,
        },
        {
          question:
            "What is the best immediate action for a SOC analyst upon seeing this alert?",
          options: [
            "Mark it as a false positive — log clearing is a normal admin task",
            "Escalate to Tier 2 or incident response — this is a potential active compromise on a domain controller",
            "Wait 24 hours to see if more events appear",
            "Reboot the domain controller to clear any malware",
          ],
          answer: 1,
          explanation:
            "Log clearing on a domain controller (DC) at 3am by an account named 'svc-helpdesk02' is an extremely high-confidence indicator of malicious activity. DCs are the most sensitive servers in a Windows environment. This must be escalated immediately — do not wait, and do not reboot (rebooting would destroy volatile memory evidence).",
          xp: 30,
        },
      ],
    } satisfies LogAnalysisTask,

    // ----- Flag: Event ID for log clearing ----------------------------------
    {
      type: "flag",
      id: "log-mgmt-flag1",
      prompt:
        "According to the log analysis above, which Windows Event ID specifically records that the Security audit log has been cleared? Enter only the numeric ID.",
      answer: "1102",
      hint: "Check the 'event.code' field in the raw log data from the previous task.",
      xp: 20,
    } satisfies FlagTask,

    // ----- Question 3 -------------------------------------------------------
    {
      type: "question",
      id: "log-mgmt-q3",
      question:
        "An organisation processes healthcare data in the United States and must comply with HIPAA. For how many years must they retain security-related audit logs?",
      options: ["1 year", "3 years", "6 years", "10 years"],
      answer: 2,
      explanation:
        "HIPAA (Health Insurance Portability and Accountability Act) requires that documentation related to security policies and procedures — including audit logs — be retained for 6 years from creation or from the date it was last in effect. This is significantly longer than PCI-DSS (1 year) or GDPR (typically 1 year for security logs).",
      xp: 20,
    } satisfies QuestionTask,

    // ----- Question 4 -------------------------------------------------------
    {
      type: "question",
      id: "log-mgmt-q4",
      question:
        "Which log collection method is most appropriate for a Palo Alto firewall that cannot have third-party software installed on it?",
      options: [
        "Agent-based — installing Filebeat directly onto PAN-OS through its underlying Linux shell",
        "Agentless Syslog — the firewall sends logs to a remote syslog server over UDP/TCP port 514",
        "Manual CSV export from the PAN-OS web UI each morning, the only method that preserves original timestamps",
        "API polling from the analyst's laptop, since the PAN-OS XML API needs no key or credentials",
      ],
      answer: 1,
      explanation:
        "Network appliances like firewalls, switches, and routers cannot have agents installed on them. The standard approach is agentless syslog — the device is configured to forward log messages to a remote syslog server over UDP (default) or TCP port 514. Most enterprise SIEMs include a built-in syslog listener for this purpose.",
      xp: 20,
    } satisfies QuestionTask,
  ],
};

// ---------------------------------------------------------------------------
// Room 2 — SIEM Fundamentals
// ---------------------------------------------------------------------------

const siemFundamentals: Room = {
  id: "siem-fundamentals",
  title: "SIEM Fundamentals",
  description:
    "Understand what a SIEM does, how correlation rules turn raw logs into alerts, what alert fatigue is, and how SOC analysts triage detections. Builds directly on the log management room.",
  difficulty: "intermediate",
  category: "SIEM",
  estimatedMinutes: 50,
  xp: 170,
  icon: "🔭",
  prerequisites: ["log-management", "log-entry-anatomy"],
  tasks: [
    // ----- Reading 1: What is a SIEM? ---------------------------------------
    {
      type: "reading",
      id: "siem-fund-r1",
      heading: "What is a SIEM? Your SOC's Air Traffic Control",
      content: `Imagine you are an air traffic controller at a major international airport. Hundreds of planes are in the air at any moment. You cannot watch the sky with your eyes — instead, you watch a radar screen that shows every aircraft, its altitude, speed, and trajectory. If two planes are on a collision course, an alarm fires immediately so you can intervene. You do not wait for a crash — you detect the dangerous pattern before it becomes a disaster.

**A SIEM is air traffic control for your IT environment.**

**SIEM** stands for **Security Information and Event Management**. It is the central platform that every modern SOC is built around. A SIEM ingests log data from every source in the organisation — endpoints, firewalls, cloud services, applications — and continuously analyses that data to detect threats in real time.

**The six core functions of a SIEM:**

1. **Log aggregation** — collecting logs from all sources into a single platform. Instead of logging into dozens of different systems to look for threats, analysts have one place to search.

2. **Normalisation** — converting inconsistent log formats (Windows Event Log, syslog, JSON, CEF) into a common schema so that searches work across all sources at once.

3. **Correlation** — the most powerful feature. The SIEM applies detection rules that look for patterns across multiple events. A single failed login is not an alert. But 50 failed logins against 12 different accounts from the same IP within 60 seconds — that is a rule that fires an alert for Password Spray (MITRE T1110.003).

4. **Alerting** — when a correlation rule matches, the SIEM generates an alert with all relevant context (which user, which IP, which timeframe, how many events matched) and notifies the SOC team.

5. **Dashboarding** — visual dashboards give the SOC situational awareness: current alert count by severity, top offending IPs, authentication failure trends, geographic origin of logins.

6. **Reporting** — automated compliance reports showing that the organisation is monitoring what regulations require (PCI-DSS requires log review, for example).

**Popular SIEMs in the industry (2024-2026):**

- **Splunk Enterprise Security** — the market leader for large enterprises. Powerful query language (SPL). Expensive but extremely capable.
- **Microsoft Sentinel** — cloud-native SIEM built into Azure. Ideal for Microsoft-heavy environments. Uses KQL (Kusto Query Language).
- **IBM QRadar** — long-established enterprise SIEM, strong in financial services and government sectors.
- **Elastic SIEM** — built on the Elastic Stack (Elasticsearch, Kibana). Open-core, highly customisable.
- **Wazuh** — fully open-source SIEM and XDR platform. No licensing cost. Popular in smaller organisations and for training (we cover this in the next room).

**SIEM architecture — how data flows:**

Raw log → **Ingestion layer** (agents, syslog, APIs) → **Parsing** (decode the format, extract fields) → **Indexing** (write to searchable storage) → **Correlation engine** (apply detection rules in real time) → **Alert** (notify SOC) → **Investigation** (analyst reviews in SIEM UI)

The entire pipeline from a log being generated on an endpoint to an alert appearing in the SOC analyst's queue typically takes 30 seconds to 5 minutes, depending on the SIEM and configuration.`,
      checkpoint: {
        question:
          "According to the reading, which of the six core SIEM functions is described as 'the most powerful feature' — applying detection rules that look for patterns across multiple events?",
        options: ["Dashboarding", "Correlation", "Reporting", "Log aggregation"],
        answer: 1,
        explanation:
          "Correlation is called out as the most powerful SIEM function — it's what turns a single, meaningless failed login into a Password Spray alert by spotting the pattern across many events.",
      },
    } satisfies ReadingTask,

    // ----- Reading 2: Correlation rules and detection types ----------------
    {
      type: "reading",
      id: "siem-fund-r2",
      heading: "How SIEM Correlation Rules Work",
      content: `A SIEM without detection rules is just an expensive log search engine. The magic happens in the **correlation engine** — the component that continuously evaluates detection rules against incoming events.

**What is a correlation rule?**

A correlation rule is a logical condition that says: "If you see *this pattern* in the logs, generate an alert." Rules can range from trivial (flag any event with severity=critical) to sophisticated (detect lateral movement by correlating authentication events across three different systems within a 10-minute window).

**The four main detection rule types:**

**1. Threshold rules**
Fire when a count exceeds a limit within a time window.
- Example: "More than 10 failed SSH logins to any single host within 5 minutes."
- Use case: brute force detection, account lockout pre-cursor detection.
- Weakness: can be evaded by slow, "low and slow" attacks that stay below the threshold.

**2. Trend/rate-of-change rules**
Fire when the volume of an event type changes significantly compared to baseline.
- Example: "DNS query volume from workstation WS-FINANCE-07 is 500% above its 7-day average."
- Use case: detecting DNS tunnelling, data exfiltration, C2 beaconing.
- Strength: catches attacks that are designed to stay below absolute thresholds.

**3. Sequence/chained rules (multi-stage correlation)**
Fire when a specific sequence of events occurs within a time window — even across different log sources.
- Example: Reconnaissance scan detected (IDS) → authentication failure (Windows) → successful login (Windows) → large file copy to external IP (DLP) within 2 hours = potential intrusion-to-exfiltration chain.
- Use case: kill chain detection, detecting attackers who move slowly between stages.
- This is where SIEM truly outshines simple log search — no single tool can see the full chain.

**4. Statistical anomaly / ML-based rules**
Fire when behaviour deviates significantly from a learned baseline.
- Example: User who always logs in from Tel Aviv suddenly logs in from Beijing 30 minutes later (impossible travel).
- Example: File server access volume for a user spikes to 10x their normal average on a Tuesday morning (ransomware pre-cursor).
- Use case: detecting compromised accounts, insider threats, novel attack techniques that have no known signature.

**Anatomy of a SIEM alert:**

When a rule fires, it creates an alert containing:
- **Rule name and description** — e.g., "Password Spray Detected — Multiple accounts targeted"
- **Severity** — Critical / High / Medium / Low / Informational
- **Matched events** — the actual log entries that triggered the rule
- **Timeline** — when the pattern started and ended
- **Affected entities** — the user accounts, hostnames, and IP addresses involved
- **MITRE ATT&CK technique** — the standardised attack technique ID (e.g., T1110.003 — Password Spraying)

**MITRE ATT&CK in the SIEM**

The MITRE ATT&CK framework is a knowledge base of adversary tactics and techniques observed in real attacks. Modern SIEMs tag each detection rule with the corresponding MITRE technique. This allows SOC teams to see, on a dashboard, which parts of the attack lifecycle they have good detection coverage for and which areas are blind spots.`,
    } satisfies ReadingTask,

    // ----- Question 1 -------------------------------------------------------
    {
      type: "question",
      id: "siem-fund-q1",
      question:
        "A SIEM rule fires when more than 20 failed login attempts occur against different accounts from the same source IP within 60 seconds. What type of detection rule is this?",
      options: [
        "Statistical anomaly rule",
        "Sequence / chained rule",
        "Threshold rule",
        "Trend / rate-of-change rule",
      ],
      answer: 2,
      explanation:
        "This is a threshold rule — it fires when a count (20 failed logins) exceeds a defined limit within a time window (60 seconds). Threshold rules are the simplest and most common type of SIEM detection rule and are ideal for brute force and password spray detection.",
      xp: 20,
    } satisfies QuestionTask,

    // ----- Reading 3: Alert fatigue and TP/FP/FN ---------------------------
    {
      type: "reading",
      id: "siem-fund-r3",
      heading: "True Positives, False Positives, and Alert Fatigue",
      content: `Every SOC analyst deals with one of the hardest problems in security: distinguishing real attacks from innocent activity that merely *looks* suspicious. Getting this wrong in either direction has serious consequences.

**The three alert outcomes:**

**True Positive (TP)** — The alert fired AND there really is a security incident. The detection is correct. This is the outcome you want. Example: The SIEM fires a "password spray" alert and investigation confirms an attacker from a Tor exit node was attempting to guess passwords. ✓ Correct detection.

**False Positive (FP)** — The alert fired BUT there is no actual security incident. The detection is wrong. Example: The "password spray" alert fires because a developer accidentally ran a script that locked themselves out of 12 test accounts during load testing. The rule fired correctly based on the pattern, but the activity was benign.

**False Negative (FN)** — The alert did NOT fire but there WAS a real attack. These are the most dangerous outcome — you are being attacked and do not know it. Example: An attacker performs a "low and slow" password spray — trying only 2 attempts per account over 8 hours to stay below your threshold. The SIEM never alerts. The attack succeeds silently.

**Why balance matters:**

Setting detection rules requires balancing sensitivity against specificity:
- Rules that are **too sensitive** (low thresholds) generate too many false positives → alert fatigue
- Rules that are **too specific** (high thresholds) miss real attacks → false negatives

**Alert fatigue:**

Alert fatigue occurs when SOC analysts are overwhelmed by a high volume of alerts — especially false positives. When analysts receive hundreds of low-quality alerts per shift, they begin to:
- Dismiss alerts without proper investigation
- Miss real threats buried in the noise
- Experience burnout and leave the profession

Studies have found that some large SOC environments generate thousands of alerts per day, with false positive rates exceeding 50-70%. A 2022 industry survey found that 45% of SOC analysts consider "too many alerts" the biggest challenge in their role.

**How to reduce alert fatigue — rule tuning:**

SIEM rules must be continuously **tuned** based on your specific environment:

1. **Whitelist known-good activity** — if your vulnerability scanner runs every Monday morning and always triggers the port scan rule, add an exception for its IP address.
2. **Adjust thresholds** — if the "failed login" rule fires 200 times a day because of a service account with an expired password, raise the threshold or create an exception for that account.
3. **Aggregate similar alerts** — group 50 related alerts into a single incident rather than showing them individually.
4. **Risk-score entities** — prioritise alerts involving high-value targets (domain controllers, finance systems, CEO accounts) over low-value ones.
5. **Review and retire stale rules** — rules written years ago for systems that no longer exist still generate alerts. Remove them.

Good rule tuning is an ongoing process, not a one-time task. A mature SOC has a dedicated team or process for continuous rule review.`,
      checkpoint: {
        question:
          "According to the reading, what is a False Negative (FN)?",
        options: [
          "An alert fired but there was no real security incident",
          "An alert fired and correctly identified a real security incident",
          "No alert fired even though a real attack was happening",
          "An alert fired twice for the same underlying event",
        ],
        answer: 2,
        explanation:
          "A False Negative means a real attack occurred but the SIEM never alerted on it — the most dangerous outcome, because the organisation is being attacked and doesn't know it. A False Positive is the opposite: an alert fires but nothing bad actually happened.",
      },
    } satisfies ReadingTask,

    // ----- Log Analysis: password spray SIEM alert -------------------------
    {
      type: "log_analysis",
      id: "siem-fund-la1",
      heading: "SIEM Alert: Password Spray Detected",
      context:
        "You are a SOC Tier 1 analyst. A high-severity alert has just appeared in your SIEM queue. The SIEM has correlated multiple authentication events and generated this alert. Review all the fields carefully before answering.",
      event: {
        id: "siem-fund-evt-001",
        ts: "2025-06-24T11:47:02Z",
        source: "siem",
        event_type: "ids_signature",
        severity: "high",
        src_ip: "185.220.101.45",
        description:
          "Correlation rule fired: multiple failed authentications targeting multiple accounts from single source",
        mitre_technique: "T1110.003",
        vendor: "Wazuh",
        raw: {
          "rule.name": "Password Spray Detected",
          "rule.level": "12",
          "rule.description":
            "Multiple failed logins from single source in 60 seconds",
          "data.srcip": "185.220.101.45",
          "data.failed_count": "47",
          "data.target_accounts": "12",
          "data.timewindow": "60s",
          "rule.mitre.technique": "T1110.003",
          "rule.groups": ["authentication", "attack"],
          "data.country": "Netherlands",
          "data.isp": "Tor Network Exit Node",
        },
      } satisfies TelemetryEvent,
      questions: [
        {
          question:
            "Based on the raw log fields, how many failed login attempts were detected in the 60-second window?",
          options: ["12 attempts", "47 attempts", "60 attempts", "1 attempt"],
          answer: 1,
          explanation:
            "The field 'data.failed_count: 47' shows 47 failed login attempts in 60 seconds. The 'data.target_accounts: 12' field tells us these attempts were spread across 12 different user accounts — a classic password spray pattern (few attempts per account to avoid lockout, many accounts targeted).",
          xp: 20,
        },
        {
          question:
            "The source IP is flagged as a Tor network exit node from the Netherlands. What does this contextual information suggest about this alert?",
          options: [
            "It is almost certainly a false positive — VPN users often use Tor",
            "It increases the likelihood this is a true positive — attackers use Tor to hide their real location",
            "Tor exit nodes are whitelisted by most organisations so this alert should be closed",
            "The Netherlands is in the EU so this is likely GDPR-related testing",
          ],
          answer: 1,
          explanation:
            "Tor exit nodes are used by attackers to anonymise their traffic and are a well-known indicator of malicious intent, especially in combination with authentication failures. While individual Tor users may be legitimate, 47 failed logins across 12 accounts from a Tor exit node is an extremely high-confidence password spray indicator. This alert should be escalated as a True Positive for investigation.",
          xp: 25,
        },
        {
          question:
            "Which MITRE ATT&CK technique does this attack map to, and what is the correct technique ID shown in the log?",
          options: [
            "T1078 — Valid Accounts",
            "T1110.001 — Password Guessing",
            "T1110.003 — Password Spraying",
            "T1566 — Phishing",
          ],
          answer: 2,
          explanation:
            "The raw field 'rule.mitre.technique: T1110.003' maps to MITRE ATT&CK T1110.003 — Password Spraying. Password spraying is distinct from brute force (T1110.001): instead of trying many passwords against one account, the attacker tries one or a few common passwords against many accounts to avoid lockout policies.",
          xp: 25,
        },
      ],
    } satisfies LogAnalysisTask,

    // ----- Flag: failed login count -----------------------------------------
    {
      type: "flag",
      id: "siem-fund-flag1",
      prompt:
        "From the Password Spray alert log above, what is the exact value in the 'data.failed_count' field? Enter only the number.",
      answer: "47",
      hint: "Look at the raw log fields in the log_analysis task above. The field name is 'data.failed_count'.",
      xp: 15,
    } satisfies FlagTask,

    // ----- Question 2 -------------------------------------------------------
    {
      type: "question",
      id: "siem-fund-q2",
      question:
        "A SOC team has a rule that fires every time a user downloads more than 50 MB in an hour from SharePoint. The rule fires 200 times per day, but after investigation, 190 of those are the automated backup service. What is the correct action?",
      options: [
        "Delete the rule — it generates too many false positives",
        "Tune the rule by adding a whitelist exception for the backup service account so it no longer triggers",
        "Raise the severity of the rule so analysts notice real incidents faster",
        "Alert fatigue is unavoidable — train analysts to work faster",
      ],
      answer: 1,
      explanation:
        "The correct response is rule tuning: add an exception for the known-good backup service account. This eliminates 190 false positives per day while keeping the rule active for all other accounts. Deleting the rule would create false negatives (real data exfiltration would go undetected). Alert fatigue is solvable through tuning — it is not an unavoidable condition.",
      xp: 20,
    } satisfies QuestionTask,

    // ----- Question 3 -------------------------------------------------------
    {
      type: "question",
      id: "siem-fund-q3",
      question:
        "An attacker successfully steals credentials and accesses your VPN, but the SIEM never fires an alert because the login looked legitimate. What type of detection outcome is this?",
      options: [
        "True Positive — the alert fired correctly",
        "False Positive — the alert fired but there was no attack",
        "False Negative — an attack occurred but no alert fired",
        "True Negative — no alert fired and there was no attack",
      ],
      answer: 2,
      explanation:
        "This is a False Negative — the most dangerous outcome in security operations. The attack was real, but the SIEM failed to detect it. False negatives occur when detection rules are too conservative, attacker techniques are unknown, or the attacker used legitimate credentials that mimic normal user behaviour. Reducing false negatives requires adding behavioural detection rules (UEBA) on top of signature-based rules.",
      xp: 20,
    } satisfies QuestionTask,

    // ----- Reading 4: writing a basic search query -------------------------
    {
      type: "reading",
      id: "siem-fund-r4",
      heading: "Writing a Basic Search Query: KQL and SPL",
      content: `Correlation rules are powerful, but they only catch the patterns someone already thought to write a rule for. The moment you are actually looking at an alert, your job stops being "wait for the SIEM to tell me something" and becomes "ask the SIEM a new question, right now, that nobody pre-built a rule for." An alert names a suspicious IP address, and your first instinct is: did this IP touch any other account? A helpdesk ticket says a laptop is behaving strangely, and you need to know: show me every logon this user had today. No correlation rule exists for either of those — they are one-off questions born out of the specific alert in front of you. This is why every SOC analyst, from day one, has to be able to hand-write a basic search query.

**Two languages, one job**

The two query languages you will meet most often are **KQL** (Kusto Query Language — used by Microsoft Sentinel and Microsoft Defender) and **SPL** (Search Processing Language — used by Splunk). They look different on the page, but they are answering the exact same kind of question. Take a common triage question: "which accounts had a failed Windows logon in the last hour?"

In KQL:
\`\`\`
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(1h)
| summarize FailCount = count() by Account
\`\`\`

In SPL:
\`\`\`
index=windows EventCode=4625 earliest=-1h
| stats count by Account
\`\`\`

Same question, same answer, different syntax. KQL builds the query as a pipeline of separate lines — start with the table (SecurityEvent), narrow it with where, narrow it again by time, then summarize. SPL front-loads its filtering into the base search itself: index=windows picks the data source, EventCode=4625 is the filter condition, and earliest=-1h is the time scope, all on one line, before the pipe hands the filtered results to stats for the count. Splunk analysts and Sentinel analysts are doing identical mental work; they are just typing it differently.

**The shared anatomy: filter, scope, aggregate**

Strip away the vendor syntax and every triage query — in any SIEM you will ever touch — follows the same three-step shape:

1. **Filter** to the events that actually matter (a table/index and a condition — EventID == 4625, or EventCode=4625).
2. **Scope** to a time range (ago(1h) in KQL, earliest=-1h in SPL). Skip this step and you are searching the entire retention period of your SIEM by accident.
3. **Aggregate or summarize** into something a human can read in one glance — a count grouped by account, by IP, by host — rather than scrolling through thousands of raw rows one at a time.

Learn this three-step shape once and you can transfer it to any query language a future job throws at you. The keywords change; the shape does not.

**Why scoping matters: query performance**

A SIEM can hold billions of events across every index and every retention day it stores. A query that forgets to specify a time range and forgets to specify an index or table — a bare search for a username, say — forces the SIEM to scan everything, which can mean minutes of wait time on a live investigation, unnecessary load on shared infrastructure other analysts are also querying, and in some cloud-billed SIEMs, real financial cost per gigabyte scanned. The fix is always the same habit: name your index or table first, add a time range immediately, and only then build up your filters and aggregations. A scoped query over the last hour of one index returns in seconds; the same logic run unscoped across all time and all indexes can take the SIEM minutes to finish — an eternity when an incident is actively unfolding.`,
      checkpoint: {
        question:
          "According to the reading, what three-step pattern do both KQL and SPL follow when you write a triage query, regardless of vendor syntax?",
        options: [
          "Aggregate first, then scope to a time range, then filter the results",
          "Filter to the relevant events, scope to a time range, then aggregate or summarize",
          "Scope to a time range, aggregate the results, then filter by severity",
          "Filter by severity, aggregate by host, then scope to a time range",
        ],
        answer: 1,
        explanation:
          "The reading's shared anatomy is filter to what matters, scope the time range, then aggregate or summarize into a readable shape — matching where/EventID then TimeGenerated then summarize in KQL, and the base search terms then earliest= then stats in SPL. The other orderings don't match either language: aggregating before you've filtered or scoped scans (and counts) far more data than necessary, which is exactly the performance problem the reading warns about.",
      },
    } satisfies ReadingTask,

    // ----- Query Fill: build the KQL query yourself -------------------------
    {
      type: "query_fill",
      id: "siem-fund-qf1",
      heading: "Write It Yourself: Count Failed Logons Per Account",
      language: "kql",
      context:
        "The reading just showed you the same triage question answered in KQL and SPL side by side. Now build the KQL version yourself. A shift-lead question just landed in your queue: \"How many failed Windows logons did each account have in the last hour?\" Fill in the blanks to build that query from the SecurityEvent table.",
      template:
        "SecurityEvent\n| where EventID == {{eventid}}\n| where TimeGenerated > ago({{window}})\n| summarize {{aggregation}} by Account",
      blanks: [
        { id: "eventid", answers: ["4625"], placeholder: "event ID for a failed logon" },
        { id: "window", answers: ["1h"], placeholder: "time window" },
        { id: "aggregation", answers: ["FailCount = count()", "count()"], placeholder: "aggregation expression" },
      ],
      explanation:
        "4625 is the Windows Security Event ID for a failed logon attempt — 4624 is its easily-confused twin, a successful logon. ago(1h) scopes TimeGenerated to the last hour, the same relative-time shorthand you saw in the reading (30m, 1h, 24h, 7d all work). summarize ... by Account groups every matching failure row by account and counts them, turning a flat list of raw events into the exact shape a triage answer needs: how many failures per account. This is the identical logic the reading's SPL example reached with stats count by Account — same three steps, different keywords.",
      xp: 25,
    } satisfies QueryFillTask,
  ],
};

// ---------------------------------------------------------------------------
// Room 3 — Wazuh SIEM Fundamentals
// ---------------------------------------------------------------------------

const wazuhFundamentals: Room = {
  id: "wazuh-fundamentals",
  title: "Wazuh SIEM Fundamentals",
  description:
    "Explore Wazuh, the leading open-source SIEM and XDR platform. Learn its architecture, how agents collect data, how decoders and rules work, and how to interpret real Wazuh alerts.",
  difficulty: "intermediate",
  category: "SIEM",
  estimatedMinutes: 55,
  xp: 155,
  icon: "🔐",
  prerequisites: ["siem-fundamentals", "security-products-behaviour"],
  tasks: [
    // ----- Reading 1: Wazuh architecture ------------------------------------
    {
      type: "reading",
      id: "wazuh-r1",
      heading: "Wazuh Architecture — Open-Source SIEM and XDR",
      content: `**What is Wazuh?**

Wazuh (pronounced "Wah-zoo") is a free, open-source security platform that combines SIEM, EDR (Endpoint Detection and Response), and compliance capabilities in a single product. Unlike commercial SIEMs that cost tens of thousands of dollars per year in licensing, Wazuh is completely free and can be deployed by anyone — making it the most popular SIEM for training, small-to-medium organisations, and security professionals learning the field.

Wazuh was originally a fork of OSSEC (Open Source HIDS Security), an older host-based intrusion detection system. The Wazuh team modernised the platform significantly, adding a cloud-scale indexer, a rich web dashboard, and a comprehensive rule library covering hundreds of attack techniques.

**The four core components of Wazuh:**

**1. Wazuh Agent**
A lightweight software agent installed on every endpoint you want to monitor (Windows, Linux, macOS, Solaris, AIX). The agent:
- Reads local log files and ships them to the Wazuh Manager in real time
- Monitors file changes (File Integrity Monitoring / FIM)
- Checks system configuration against security benchmarks (Security Configuration Assessment / SCA)
- Runs rootcheck scans to detect kernel-level modifications
- Executes active response scripts when triggered by the manager
- Communicates with the Wazuh Manager over **TCP port 1514** (encrypted)

Agents are identified by a unique **agent ID** (e.g., "001") and a friendly name (e.g., "linux-srv-01"). The manager tracks the health and connection status of all agents in real time.

**2. Wazuh Manager**
The central brain of the platform. The Manager:
- Receives raw log data from all agents
- Runs the **analysis engine** — applying decoders and rules to every event
- Generates alerts when rule conditions are matched
- Stores alert metadata
- Manages agent configuration (remotely pushes config files to agents)
- Hosts the **active response** engine that can trigger automated countermeasures

The Manager listens on TCP 1514 (agent communication) and TCP 55000 (API for the dashboard).

**3. Wazuh Indexer (OpenSearch)**
After the Manager generates an alert, the alert is sent to the **Wazuh Indexer** — an OpenSearch cluster (OpenSearch is the open-source fork of Elasticsearch). The Indexer stores and indexes all alerts and enriched events, enabling fast search, filtering, and analytics across millions of records.

**4. Wazuh Dashboard (Kibana-based)**
A web-based visualisation interface built on OpenSearch Dashboards (forked from Kibana). Analysts use the dashboard to:
- View real-time alert feeds
- Search and filter historical events
- View compliance dashboards (PCI-DSS, HIPAA, GDPR, CIS, NIST)
- Monitor agent health and connectivity
- Investigate file integrity changes
- Review vulnerability scan results

**The data flow in Wazuh:**

Endpoint event → **Agent collects it** → ships over TCP 1514 → **Manager receives it** → decoder parses the raw log → rule engine evaluates it → if rule matches, **alert generated** → alert forwarded to **Indexer** → stored and indexed → visible in **Dashboard**

This full pipeline typically completes in under 5 seconds from event generation to alert appearing in the dashboard.`,
      checkpoint: {
        question: "According to the reading, which TCP port does the Wazuh Agent use to communicate with the Wazuh Manager?",
        options: ["TCP 1514", "TCP 55000", "TCP 514", "TCP 443"],
        answer: 0,
        explanation:
          "Agents communicate with the Manager over TCP port 1514 (encrypted). TCP 55000 is the separate API port the dashboard uses to talk to the Manager.",
      },
    } satisfies ReadingTask,

    // ----- Reading 2: Decoders and rules ------------------------------------
    {
      type: "reading",
      id: "wazuh-r2",
      heading: "Wazuh Decoders and Rules — How Detection Works",
      content: `The detection engine in Wazuh is built from two distinct layers: **decoders** and **rules**. Understanding how they work together is fundamental to using Wazuh effectively as a SOC analyst.

**Step 1: Decoders — Parsing Raw Logs into Structured Fields**

When a raw log message arrives at the Wazuh Manager, it looks something like this:

\`Jun 24 14:32:11 srv01 sshd[2341]: Failed password for invalid user admin from 185.220.101.45 port 54321 ssh2\`

This is just a string of text. The Wazuh Manager needs to extract meaning from it — who was the user? what IP? what action? That is the job of a **decoder**.

A decoder is an XML file that uses:
- **Prematch** — a regular expression to quickly identify which log format this is (e.g., "does this line contain 'sshd'?")
- **Regex** — a pattern to extract specific fields from the log text
- **Order** — the names to give each extracted field

After decoding, Wazuh has structured fields like:
- \`data.srcuser = admin\`
- \`data.srcip = 185.220.101.45\`
- \`data.program_name = sshd\`
- \`data.dstport = 54321\`

Wazuh ships with hundreds of built-in decoders covering Apache, Nginx, MySQL, Windows Event Log, sshd, sudo, useradd, and many more. You can also write custom decoders for proprietary applications.

**Step 2: Rules — Matching Decoded Events to Known Patterns**

Once a log is decoded into structured fields, the rule engine evaluates every active rule against those fields. A Wazuh rule is also an XML file with:
- **Rule ID** — a unique number (0–999999)
- **Level** — severity from 0 to 15 (see below)
- **Description** — human-readable description of what the rule detects
- **Match/field conditions** — the conditions that must be true to trigger the rule
- **Groups** — categories like "authentication_failures", "attack", "syslog"
- **Frequency** — how many times the condition must occur (for multi-event rules)
- **Timeframe** — the time window for frequency-based rules (in seconds)

**Wazuh Rule Severity Levels:**

| Level | Range | Meaning |
|-------|-------|---------|
| Ignored | 0 | No alert generated. Used to suppress noise. |
| Low informational | 1–3 | System events with no security relevance. |
| Low | 4–6 | Minor events worth logging but not alerting on. |
| Medium | 7–11 | Events that should be investigated. |
| High | 12–14 | Serious security events requiring prompt attention. |
| Critical | 15 | Maximum severity — immediate response required. |

By default, Wazuh writes an alert for any rule that fires at **level 3 or above** — this is the \`log_alert_level\` setting in \`ossec.conf\` (its default value is 3, *not* 7). Events below that level are still decoded and matched, and can be sent to the archives, but they fall below the default alerting threshold and so do not appear as alerts in the dashboard. Many teams raise \`log_alert_level\` (to 5, 7, or higher) to cut noise — but that is a tuning choice each site makes, not the out-of-the-box default.

**Rule ID ranges — learn these rather than memorising individual numbers.** Wazuh groups its built-in rules into blocks by log source, and the block is far more durable knowledge than any single ID:

| Range | Covers |
|---|---|
| 5100-5299 | Linux system / kernel |
| 5300-5999 | Authentication — sshd, PAM, sudo, user and group changes |
| 18100-18999 | Windows event log |
| 31100-31999 | Web server (Apache/Nginx/IIS) — includes web attack signatures |
| 60000-61999 | Windows Sysmon and rootcheck |
| 80000+ | Integrations and vendor-specific decoders |
| 100000+ | Reserved for YOUR custom rules — never write below this |

That last row is the one that actually bites people: custom rules must live at 100000 or above, because anything lower can be overwritten when you upgrade the ruleset.

Some representative built-in rules you will meet often:

- **5710** — sshd: attempt to log in using a non-existent user
- **5503** — PAM: user login failed
- **31103** — Web server attack: SQL injection attempt (successful SQLi escalates to **31106**)
- **60104** — Rootkit detection by rootcheck

**Always confirm the exact ID against your own instance before you build anything on it.** Rule IDs and their descriptions shift between ruleset versions, and every organisation runs a slightly different mix of built-in and custom rules. Two commands settle it in seconds: **/var/ossec/bin/wazuh-logtest** lets you paste a raw log line and see precisely which rule fires and at what level, and the rule files under **/var/ossec/ruleset/rules/** are plain XML you can grep. An analyst who knows how to *look up* the rule that fired is far more useful than one who memorised a list that was accurate for one version two years ago.

**Rule inheritance (parent/child rules):**

Wazuh rules are hierarchical. A parent rule matches the general event type (e.g., "this is a sshd authentication event"). Child rules then match more specific conditions on top of the parent. This layered approach allows complex detection logic without needing to repeat common conditions in every rule.

For example:
- Parent rule 5700: "sshd authentication event detected" (fires on any SSH-related log)
- Child rule 5710: "Failed login for non-existent user" (only fires if parent matched AND user does not exist)
- Child rule 5712: "sshd: brute force trying to get access to the system" (only fires if parent matched AND failures exceed the frequency threshold in the timeframe)`,
      checkpoint: {
        question: "According to the reading, what is the DEFAULT value of Wazuh's `log_alert_level` — the level at or above which a rule produces a dashboard alert out of the box?",
        options: ["Level 3", "Level 5", "Level 7", "Level 12"],
        answer: 0,
        explanation:
          "The default `log_alert_level` in `ossec.conf` is 3, so by default any rule firing at level 3 or above becomes a visible alert. A common tuning step is to raise it (to 5, 7, or higher) to cut noise, but that is a per-site choice — not the out-of-the-box default. Assuming '7' is the default is a frequent and costly mistake.",
      },
    } satisfies ReadingTask,

    // ----- Question 1 -------------------------------------------------------
    {
      type: "question",
      id: "wazuh-q1",
      question:
        "A Wazuh rule with level 15 fires on a monitored endpoint. What does level 15 indicate in the Wazuh severity scale?",
      options: [
        "Low severity — informational event, no action needed",
        "Medium severity — investigate when time permits",
        "High severity — serious event requiring prompt attention",
        "Critical severity — the maximum level, requiring immediate response",
      ],
      answer: 3,
      explanation:
        "In Wazuh's 0-15 severity scale, level 15 is the maximum — Critical. It indicates an event of the highest severity requiring immediate response. Levels 12-14 are High, 7-11 are Medium, 4-6 are Low, and 0-3 are informational or ignored. By default (`log_alert_level` = 3) any rule at level 3 or above becomes a visible alert in the dashboard; many teams then raise that threshold to cut noise, but 3 — not 7 — is the out-of-the-box default.",
      xp: 20,
    } satisfies QuestionTask,

    // ----- Reading 3: FIM, SCA, and Active Response -------------------------
    {
      type: "reading",
      id: "wazuh-r3",
      heading: "FIM, SCA, Active Response, and Wazuh Dashboards",
      content: `Wazuh goes beyond simple log analysis. It includes several additional security capabilities that make it a comprehensive platform for endpoint security monitoring.

**File Integrity Monitoring (FIM)**

FIM is one of Wazuh's most powerful features. It continuously monitors files and directories for any changes — creation, modification, deletion, or permission changes. This is critical because:

- Attackers often modify system files or configuration files after gaining access
- Malware frequently drops files into sensitive locations
- Compliance frameworks (PCI-DSS 11.5, HIPAA) require FIM on systems handling sensitive data

By default, Wazuh monitors critical Linux files including:
- /etc/passwd — user account database (adding new users)
- /etc/shadow — password hashes
- /etc/sudoers — which users can run commands as root
- /etc/group — group memberships
- /bin/ and /sbin/ — system binaries
- /usr/bin/ — user executable binaries

On Windows, Wazuh monitors sensitive registry keys and the system32 directory.

When a monitored file changes, Wazuh generates a FIM alert containing:
- The file path that changed
- The type of change (content modified, permission changed, owner changed, etc.)
- The SHA256 hash before and after the change
- The user account that made the change (where available)

FIM alerts on /etc/passwd or /etc/sudoers on a Linux server should always be investigated — adding a new user or granting sudo access are classic post-exploitation actions.

**Security Configuration Assessment (SCA)**

SCA performs periodic compliance checks against security benchmarks — most commonly the **CIS (Center for Internet Security) Benchmarks**. These benchmarks define secure configuration standards for operating systems, applications, and cloud services.

Wazuh runs SCA scans and reports:
- Which benchmark checks passed
- Which checks failed (and the exact configuration that failed)
- A compliance score (percentage of checks passed)
- Remediation guidance for each failure

SCA is invaluable for hardening new systems and demonstrating compliance to auditors.

**Active Response — Automated Countermeasures**

Active Response is Wazuh's ability to automatically execute actions on the endpoint when a rule fires. Common active response scripts include:

- **Firewall block** — automatically block a source IP using iptables/ufw when a brute force rule fires
- **Process kill** — automatically terminate a process when a malware detection rule fires
- **Account disable** — disable a user account when credential theft indicators appear
- **Custom scripts** — any action you can script (send a Slack message, open a ServiceNow ticket, isolate the host from the network)

Active Response is powerful but must be used carefully — an incorrectly tuned rule combined with an aggressive active response can block legitimate users or disrupt business operations.

**Wazuh Dashboards — What the SOC Analyst Sees**

The Wazuh Dashboard includes several built-in sections:

- **Overview** — real-time alert counts by severity, top alert categories, agent health summary
- **Security Events** — searchable alert feed with all details, filterable by agent, rule group, severity
- **Integrity Monitoring** — all FIM alerts, searchable by file path or host
- **Vulnerabilities** — CVE-based vulnerability assessment (Wazuh cross-references installed software with CVE databases)
- **MITRE ATT&CK** — visualises your alert coverage across the ATT&CK framework matrix
- **Regulatory Compliance** — pre-built dashboards for PCI-DSS, HIPAA, GDPR, NIST 800-53, CIS
- **Agents** — list of all monitored endpoints with connectivity status, OS, last alert time`,
      checkpoint: {
        question: "According to the reading, which file does Wazuh's File Integrity Monitoring (FIM) watch by default that would alert on a new Linux user account being added?",
        options: ["/etc/passwd", "/var/log/syslog", "/proc/version", "/tmp/.cache"],
        answer: 0,
        explanation:
          "/etc/passwd is one of the critical files monitored by default FIM; adding a new user modifies it, and a FIM alert on /etc/passwd or /etc/sudoers should always be investigated as a possible post-exploitation action.",
      },
    } satisfies ReadingTask,

    // ----- Log Analysis: new privileged user --------------------------------
    {
      type: "log_analysis",
      id: "wazuh-la1",
      heading: "Wazuh Alert: New User Added to Linux System",
      context:
        "You are a SOC analyst monitoring a Linux production server through Wazuh. A high-severity alert just fired on your dashboard. The server is a critical application server that should never have new user accounts added outside of approved change management windows. Review the alert and answer the questions.",
      event: {
        id: "wazuh-evt-001",
        ts: "2025-06-24T02:44:17Z",
        source: "siem",
        event_type: "edr_alert",
        severity: "high",
        hostname: "linux-srv-01",
        description: "Wazuh: New user account added to the system",
        mitre_technique: "T1136.001",
        raw: {
          "rule.id": "5903",
          "rule.level": "12",
          "rule.description": "New user added to the system",
          "rule.groups": ["adduser", "syslog"],
          "data.dstuser": "sysmgr_svc",
          "data.srcuser": "root",
          "data.program_name": "useradd",
          "agent.name": "linux-srv-01",
          "agent.id": "001",
          "manager.name": "wazuh-manager",
          "decoder.name": "adduser",
          "full_log":
            "Jun 24 02:44:17 linux-srv-01 useradd[8821]: new user: name=sysmgr_svc, UID=1337, GID=1337, home=/home/sysmgr_svc, shell=/bin/bash",
        },
      } satisfies TelemetryEvent,
      questions: [
        {
          question:
            "What Wazuh rule ID fired, and what is its rule level? What does this level mean?",
          options: [
            "Rule 5710, level 7 — medium severity SSH failure",
            "Rule 5903, level 12 — high severity, requiring prompt attention",
            "Rule 60104, level 15 — critical rootkit detection",
            "Rule 5501, level 5 — low severity authentication failure",
          ],
          answer: 1,
          explanation:
            "Read it straight off the alert: `rule.id` is 5903 and `rule.level` is 12, and the alert helpfully carries `rule.description` — 'New user added to the system' — so you never have to remember what a given ID means. That is the habit worth building. Rule IDs shift between ruleset versions, so an analyst who reads the description field (or runs `wazuh-logtest` to confirm which rule fires) will be right in any environment, while one who memorised a list will eventually be confidently wrong.\n\nThe level is what sets your urgency: 12 sits in Wazuh's High band (12-14), well above the default alerting threshold (`log_alert_level` = 3). Combine that with the context — an unplanned account creation on a critical application server at 02:44 AM, outside any approved change window — and this is worth waking someone for, whatever the account happens to be called.",
          xp: 25,
        },
        {
          question:
            "The 'full_log' field shows the raw syslog line. What was the shell assigned to the new account 'sysmgr_svc'?",
          options: ["/bin/false (no login shell)", "/bin/nologin", "/bin/bash (fully interactive shell)", "/bin/sh"],
          answer: 2,
          explanation:
            "The full_log field shows 'shell=/bin/bash' — a fully interactive shell. This is significant: legitimate service accounts (like database or web server accounts) are typically given /bin/false or /bin/nologin to prevent interactive logins. Assigning /bin/bash to a newly created, unapproved account at 2am strongly indicates this account was created by an attacker for persistent backdoor access.",
          xp: 30,
        },
        {
          question:
            "Which Wazuh capability would alert you if an attacker later modified /etc/sudoers to give 'sysmgr_svc' root privileges?",
          options: [
            "Security Configuration Assessment (SCA)",
            "Active Response",
            "File Integrity Monitoring (FIM)",
            "Rootcheck",
          ],
          answer: 2,
          explanation:
            "File Integrity Monitoring (FIM) monitors /etc/sudoers as one of its default protected files. Any modification to this file — including adding a line granting sudo access to a new account — would immediately generate a FIM alert with the before/after hash, the changed content, and the user who made the change.",
          xp: 25,
        },
      ],
    } satisfies LogAnalysisTask,

    // ----- Flag: rule level -------------------------------------------------
    {
      type: "flag",
      id: "wazuh-flag1",
      prompt:
        "From the Wazuh alert above, what is the numeric value in the 'rule.level' field? Enter only the number.",
      answer: "12",
      hint: "Look at the raw log fields in the Wazuh alert. The field is 'rule.level'.",
      xp: 15,
    } satisfies FlagTask,

    // ----- Question 2 -------------------------------------------------------
    {
      type: "question",
      id: "wazuh-q2",
      question:
        "A Wazuh decoder processes a raw Linux syslog line and extracts fields like 'data.srcip', 'data.srcuser', and 'data.program_name'. What happens to these extracted fields NEXT in the Wazuh processing pipeline?",
      options: [
        "They are written straight to the dashboard's Discover view, which is what assigns each event its alert level",
        "They are encrypted with the agent key and sent to the Wazuh Indexer, which runs the rule engine at index time",
        "They are evaluated against the rule engine — each active rule checks whether its conditions match the extracted fields",
        "They are forwarded back to the Wazuh Agent, which stores them in local_rules.xml on the endpoint",
      ],
      answer: 2,
      explanation:
        "After a decoder extracts structured fields from a raw log, the Wazuh analysis engine evaluates ALL active rules against those fields. If a rule's conditions match (e.g., data.program_name == 'useradd' AND data.dstuser is set), the rule fires and generates an alert. Decoders parse; rules detect. The two steps are sequential and inseparable in Wazuh's pipeline.",
      xp: 20,
    } satisfies QuestionTask,

    // ----- Question 3 -------------------------------------------------------
    {
      type: "question",
      id: "wazuh-q3",
      question:
        "Your organisation wants Wazuh to automatically block an attacker's IP address in the Linux firewall (iptables) when a brute force rule fires. Which Wazuh feature provides this capability?",
      options: [
        "File Integrity Monitoring (FIM)",
        "Security Configuration Assessment (SCA)",
        "Active Response",
        "OpenSearch Indexer",
      ],
      answer: 2,
      explanation:
        "Active Response is Wazuh's automated countermeasure system. When a specified rule fires, Wazuh can trigger scripts on the monitored endpoint — including the built-in 'firewall-drop' script that blocks the source IP using iptables. Active responses can run on the agent that generated the alert, on a different agent, or on the Wazuh Manager itself.",
      xp: 20,
    } satisfies QuestionTask,
  ],
};

// ---------------------------------------------------------------------------
// Room 4 — Microsoft Sentinel Fundamentals
// ---------------------------------------------------------------------------

const sentinelFundamentals: Room = {
  id: "sentinel-fundamentals",
  title: "Microsoft Sentinel Fundamentals",
  description:
    "Learn Microsoft Sentinel, the cloud-native SIEM and SOAR built into Azure. Understand data connectors, Log Analytics tables, KQL queries, analytics rules, and incident management.",
  difficulty: "intermediate",
  category: "SIEM",
  estimatedMinutes: 55,
  xp: 230,
  icon: "☁️",
  prerequisites: ["siem-fundamentals", "security-products-behaviour"],
  tasks: [
    // ----- Reading 1: Sentinel architecture and connectors ------------------
    {
      type: "reading",
      id: "sentinel-r1",
      heading: "Microsoft Sentinel — Cloud-Native SIEM and SOAR",
      content: `**What is Microsoft Sentinel?**

Microsoft Sentinel (formerly called Azure Sentinel) is Microsoft's cloud-native **SIEM and SOAR** (Security Orchestration, Automation and Response) platform, built entirely inside Microsoft Azure. Unlike traditional SIEMs that you deploy on physical servers or virtual machines in your own data centre, Sentinel runs as a fully managed cloud service — no infrastructure to manage, no software to patch, no hardware to buy.

This "cloud-native" architecture means Sentinel scales automatically. Whether you are ingesting 1,000 events per day from a small organisation or 10 billion events per day from a Fortune 500 enterprise, Sentinel scales to handle it without any manual intervention.

**Sentinel is the SIEM of choice for organisations that:**
- Are Microsoft-heavy (use Azure, Microsoft 365, Azure AD / Entra ID, Defender products)
- Want to avoid managing on-premises SIEM infrastructure
- Want deep native integration with the Microsoft security ecosystem
- Need cloud-scale log storage without managing Elasticsearch or OpenSearch clusters

**Core Sentinel concepts:**

**Log Analytics Workspace**
Everything in Sentinel is built on top of a **Log Analytics Workspace** — an Azure resource that acts as a managed database for log data. When you ingest logs into Sentinel, they are stored in the Log Analytics Workspace in structured tables. You can query those tables using KQL (we cover this shortly). Think of the workspace as Sentinel's "hard drive."

**Data Connectors**
Data connectors are the mechanisms by which Sentinel ingests log data from different sources. There are three categories:

1. **Native Microsoft connectors** — one-click setup for Microsoft services. Examples:
   - Azure Active Directory / Entra ID (sign-in logs, audit logs)
   - Microsoft 365 Defender (endpoint, email, identity, cloud app alerts)
   - Microsoft Defender for Endpoint (device events, alerts)
   - Azure Activity (all Azure resource operations)
   - Office 365 (Exchange, SharePoint, Teams activity)

2. **Partner / third-party connectors** — pre-built connectors for common security vendors. Examples:
   - Palo Alto Networks firewalls
   - Fortinet FortiGate
   - Cisco ASA / Firepower
   - CrowdStrike Falcon
   - Okta
   - AWS CloudTrail (via S3)

3. **Custom connectors** — for sources with no pre-built connector:
   - **Syslog connector** — any device that sends syslog over TCP/UDP
   - **CEF connector** — devices sending Common Event Format logs
   - **HTTP Data Collector API** — custom applications can POST JSON logs via REST API
   - **Azure Event Hubs** — for high-volume streaming data

**Log Tables in Sentinel**

Each data connector populates specific tables in the Log Analytics Workspace. Key tables every SOC analyst must know:

| Table Name | Content |
|-----------|---------|
| **SecurityEvent** | Windows Security Event Log (Event IDs 4624, 4625, 4688, etc.) |
| **Syslog** | Linux syslog messages from agents or syslog forwarders |
| **SignInLogs** | Azure Active Directory / Entra ID sign-in events |
| **AuditLogs** | Azure AD directory changes (user create/delete, group changes, role assignments) |
| **OfficeActivity** | Microsoft 365 activity (Exchange, SharePoint, Teams, OneDrive) |
| **DeviceEvents** | Microsoft Defender for Endpoint raw events |
| **DeviceAlertEvents** | MDE alert-level events |
| **AzureActivity** | Azure resource management operations (create VM, delete storage, etc.) |
| **Heartbeat** | Agent health check-ins from connected VMs |
| **SecurityAlert** | Alerts from Microsoft security products (Defender, Sentinel analytics rules) |
| **SecurityIncident** | Sentinel incidents (grouped alerts) |

Knowing which table to query is the first step in any Sentinel investigation. A Windows failed login? Query SecurityEvent. A suspicious Azure AD login? Query SignInLogs.`,
      checkpoint: {
        question: "According to the reading, which Sentinel table would you query to investigate a suspicious Azure AD sign-in?",
        options: ["SignInLogs", "SecurityEvent", "Syslog", "Heartbeat"],
        answer: 0,
        explanation:
          "SignInLogs holds Azure Active Directory / Entra ID sign-in events. SecurityEvent is for Windows Security Event Log data (like 4624/4625), which is a different source entirely.",
      },
    } satisfies ReadingTask,

    // ----- Reading 2: KQL basics -------------------------------------------
    {
      type: "reading",
      id: "sentinel-r2",
      heading: "KQL — Kusto Query Language Basics",
      content: `**What is KQL?**

KQL (Kusto Query Language) is the query language used in Microsoft Sentinel (and other Azure services like Azure Monitor). Just as SQL is used to query relational databases, KQL is used to query log data in Sentinel's Log Analytics Workspace. KQL is designed specifically for time-series log data and is extremely fast, even across billions of records.

A KQL query reads from left to right, like a pipeline. Each step takes the results from the previous step and transforms or filters them. Steps are separated by the pipe character ( | ).

**KQL building blocks — the essential operators:**

**1. Table selection (always the first line)**
\`\`\`
SecurityEvent
\`\`\`
Start with the table name. This returns ALL records from SecurityEvent. All subsequent operators narrow or transform this result.

**2. where — filter rows**
\`\`\`
SecurityEvent
| where EventID == 4625
\`\`\`
Returns only rows where the EventID column equals 4625 (Windows failed login). You can combine conditions:
\`\`\`
SecurityEvent
| where EventID == 4625 and IpAddress != "-"
\`\`\`

**3. project — select specific columns**
\`\`\`
SecurityEvent
| where EventID == 4625
| project TimeGenerated, Account, IpAddress, Computer
\`\`\`
Returns only the four specified columns instead of all 50+ columns in SecurityEvent. Makes results cleaner.

**4. summarize — aggregate and count**
\`\`\`
SecurityEvent
| where EventID == 4625
| summarize FailureCount = count() by Account
\`\`\`
Groups rows by the Account column and counts how many failures per account. \`count()\` is the most common aggregation — others include \`sum()\`, \`avg()\`, \`dcount()\` (distinct count), \`max()\`, \`min()\`.

**5. Time filters — where TimeGenerated**
\`\`\`
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4625
\`\`\`
\`ago(1h)\` means "1 hour ago from now." You can use \`ago(24h)\`, \`ago(7d)\`, \`ago(30m)\`. The TimeGenerated column is always the authoritative timestamp for when an event was ingested into Sentinel.

**6. sort / order by**
\`\`\`
SecurityEvent
| where EventID == 4625
| summarize FailureCount = count() by Account
| sort by FailureCount desc
\`\`\`
Orders results by FailureCount in descending order (largest first).

**7. top — return the top N results**
\`\`\`
SecurityEvent
| where EventID == 4625
| summarize FailureCount = count() by IpAddress
| top 10 by FailureCount
\`\`\`
Returns the 10 IP addresses with the most failed logins. Shorthand for sort + take.

**Putting it all together — a realistic investigation query:**
\`\`\`
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625
| where IpAddress !in ("10.0.0.1", "10.0.0.2")
| summarize FailureCount = count(), DistinctAccounts = dcount(Account) by IpAddress
| where FailureCount > 20
| sort by FailureCount desc
\`\`\`
This query finds all source IPs that generated more than 20 failed Windows logins in the past 24 hours, excluding your known internal scanners, showing how many distinct accounts each IP tried. This is a manual password spray investigation query.

**Key KQL tips:**
- KQL is **case-sensitive** for column values but **case-insensitive** for operators and function names
- \`==\` is exact match; \`=~\` is case-insensitive match; \`contains\` is substring; \`startswith\` is prefix
- The pipe \`|\` must always be on the same line as or at the start of the next operator
- String literals use double quotes: \`"value"\`
- Run queries in the Sentinel Logs blade or in the Log Analytics Workspace directly`,
      checkpoint: {
        question: "According to the reading, which KQL function means '1 hour ago from now' when filtering on TimeGenerated?",
        options: ["ago(1h)", "timerange(1h)", "past(1h)", "since(1h)"],
        answer: 0,
        explanation:
          "ago(1h) is the KQL function for a relative time offset; the same pattern works for ago(24h), ago(7d), ago(30m), and so on.",
      },
    } satisfies ReadingTask,

    // ----- Question 1 -------------------------------------------------------
    {
      type: "question",
      id: "sentinel-q1",
      question:
        "A SOC analyst wants to find all failed Windows logins (Event ID 4625) in Sentinel from the past 6 hours. Which KQL query correctly achieves this?",
      options: [
        "SELECT * FROM SecurityEvent WHERE EventID = 4625 AND time > -6h",
        "SecurityEvent | where EventID == 4625 | where TimeGenerated > ago(6h)",
        "SignInLogs | where EventID == 4625 | filter time > 6h",
        "SecurityEvent | filter EventID = '4625' | timerange 6h",
      ],
      answer: 1,
      explanation:
        "The correct KQL syntax is: start with the table name (SecurityEvent), then use pipe-separated operators. 'where EventID == 4625' filters for failed logins, and 'where TimeGenerated > ago(6h)' filters for the past 6 hours. Option A uses SQL syntax (not valid in KQL). Option C uses the wrong table (SignInLogs is for Azure AD, not Windows Security Events) and wrong syntax. Option D uses invalid KQL syntax.",
      xp: 25,
    } satisfies QuestionTask,

    // ----- Reading 3: Analytics rules and incident management ---------------
    {
      type: "reading",
      id: "sentinel-r3",
      heading: "Analytics Rules, Incidents, and SOAR Playbooks",
      content: `**Analytics Rules — How Sentinel Detects Threats**

Analytics rules are Sentinel's automated detection engine. They continuously run KQL queries against your ingested logs and generate alerts (and incidents) when suspicious patterns are found.

There are four types of analytics rules:

**1. Scheduled rules**
The most common and flexible type. You write a KQL query that Sentinel runs on a defined schedule (every 5 minutes, every hour, every 12 hours). If the query returns any results above your threshold, Sentinel creates an alert.

Example rule: "Run this query every 5 minutes, looking back at the last 15 minutes. If any IP address has more than 20 failed logins across more than 5 accounts, create a High severity alert."

You configure:
- **Query** — the KQL detection logic
- **Query scheduling** — how often to run (minimum 5 minutes)
- **Lookback period** — how far back the query searches each run
- **Alert threshold** — minimum result count to trigger an alert
- **Alert grouping** — how to group multiple matches into fewer alerts (e.g., group by source IP)
- **Entity mapping** — which query fields map to Sentinel entity types (Account, IP, Host, File, URL)
- **MITRE ATT&CK mapping** — tag the rule with the relevant technique

**2. NRT (Near Real Time) rules**
Similar to scheduled rules but run every minute (much faster than minimum 5-minute scheduled rules). Ideal for time-sensitive detections like malware execution. Limited to simpler KQL queries.

**3. Fusion rules (ML-based correlation)**
Microsoft's machine learning engine that correlates alerts from multiple Microsoft security products to detect multi-stage attacks. Fusion automatically chains together low-severity signals from Defender, Azure AD, and other sources to surface sophisticated attacks that individual rules would miss. This is Sentinel's equivalent of SIEM "multi-stage correlation."

**4. Anomaly rules (ML-based)**
Pre-built Microsoft ML models that establish behavioural baselines for users, devices, and services, then alert when behaviour deviates significantly. Examples: impossible travel detection, abnormal process execution, unusual data access volume.

**From Alert to Incident**

In Sentinel, the hierarchy is: **Log event → Alert → Incident**

- A **log event** is a raw record (one row in SecurityEvent)
- An **alert** is generated when an analytics rule matches events
- An **incident** groups related alerts into a single case for investigation

When multiple alerts are related (same user, same IP, within a short timeframe), Sentinel automatically groups them into a single incident using **alert grouping** rules. This dramatically reduces alert fatigue — instead of 50 individual alerts, you see 1 incident with all 50 alerts linked inside.

Each incident has:
- **Title** and **description** (from the analytics rule)
- **Severity** — Critical / High / Medium / Low / Informational
- **Status** — New → Active → Closed
- **Owner** — the analyst assigned to investigate
- **Evidence** — all linked alerts and their underlying events
- **Entities** — the users, IPs, hosts, and files involved
- **Timeline** — chronological view of all related events
- **MITRE ATT&CK** — the techniques detected
- **Comments** — analyst investigation notes
- **Tasks** — checklist items for the investigation workflow

**SOAR Playbooks — Automated Response**

Sentinel's SOAR capability uses **Azure Logic Apps** as playbooks. A playbook is a workflow automation that can be triggered automatically when an incident is created.

Examples of what playbooks can do:
- **Auto-isolate a host** — call the Microsoft Defender for Endpoint API to isolate a compromised machine from the network
- **Disable a user account** — call the Azure AD API to disable a user account when credential theft is detected
- **Notify the SOC** — send a Teams message or email with incident details to the on-call analyst
- **Create a ticket** — automatically open a ServiceNow or Jira ticket for the incident
- **Enrich with threat intelligence** — query VirusTotal or other threat intel sources and add the results to the incident
- **Block an IP** — call the firewall API to block a malicious source IP

Playbooks can run **automatically** (triggered by an analytics rule) or **manually** (an analyst clicks "Run playbook" during investigation). They dramatically reduce response time for common, well-understood incidents.

**Sentinel Workbooks — Dashboards**

Workbooks are Sentinel's built-in dashboards, built on Azure Monitor Workbooks. Sentinel includes dozens of pre-built workbooks including:
- Azure Active Directory Sign-in and Audit logs overview
- Microsoft 365 activity overview
- Defender for Endpoint alert summary
- Network traffic analysis
- Threat Intelligence overview
- MITRE ATT&CK coverage map`,
      checkpoint: {
        question: "According to the reading, what is the correct hierarchy of concepts in Microsoft Sentinel?",
        options: [
          "Incident → Alert → Log event",
          "Log event → Alert → Incident",
          "Alert → Log event → Incident",
          "Log event → Incident → Alert",
        ],
        answer: 1,
        explanation:
          "The hierarchy flows from raw data up: a log event is a single row, an analytics rule matching events generates an alert, and related alerts are grouped together into a single incident for investigation.",
      },
    } satisfies ReadingTask,

    // ----- Log Analysis: Sentinel SecurityEvent 4625 -----------------------
    {
      type: "log_analysis",
      id: "sentinel-la1",
      heading: "Sentinel: Windows Failed Authentication Event",
      context:
        "You are investigating a Sentinel incident flagged as a potential brute force attack. You have drilled down from the incident into the underlying log events and are looking at one individual SecurityEvent entry. The event came through the Windows Security Events data connector. Review the raw fields and answer the questions.",
      event: {
        id: "sentinel-evt-001",
        ts: "2025-06-24T14:32:11Z",
        source: "windows_security",
        event_type: "auth_failure",
        severity: "medium",
        hostname: "CORP-WS-042",
        user_email: "j.smith@corp.com",
        src_ip: "185.220.101.45",
        description:
          "Windows Security Event 4625 — failed network logon for account j.smith",
        mitre_technique: "T1110.001",
        raw: {
          TimeGenerated: "2025-06-24T14:32:11Z",
          EventID: "4625",
          EventSourceName: "Microsoft-Windows-Security-Auditing",
          Account: "j.smith",
          AccountDomain: "CORP",
          IpAddress: "185.220.101.45",
          LogonType: "3",
          SubStatus: "0xC000006A",
          WorkstationName: "DESKTOP-7GQK21",
          Channel: "Security",
          Computer: "CORP-WS-042",
          Activity: "4625 - An account failed to log on.",
        },
      } satisfies TelemetryEvent,
      questions: [
        {
          question:
            "Which Sentinel table does this Windows Security Event 4625 (failed login) come from?",
          options: ["SignInLogs", "AuditLogs", "SecurityEvent", "OfficeActivity"],
          answer: 2,
          explanation:
            "Windows Security Event Log entries — including failed logins (4625), successful logins (4624), process creation (4688), and all other Windows Security channel events — are stored in the 'SecurityEvent' table in Sentinel. SignInLogs is for Azure AD / Entra ID cloud logins. AuditLogs is for Azure AD directory changes. OfficeActivity is for Microsoft 365 (Exchange, SharePoint, Teams).",
          xp: 20,
        },
        {
          question:
            "The SubStatus field shows '0xC000006A'. This is a Windows authentication sub-status code. What does 0xC000006A indicate?",
          options: [
            "Account does not exist (unknown username)",
            "Account is disabled",
            "Wrong password was provided for a valid account",
            "Account is expired",
          ],
          answer: 2,
          explanation:
            "Windows sub-status code 0xC000006A means 'User logon with misspelled or bad password' — the username exists but the wrong password was provided. This is significant: it means the attacker knows the username 'j.smith' is a valid account. Compare this to 0xC0000064 (user name does not exist) or 0xC0000072 (account disabled). Knowing the sub-status helps analysts understand the stage of a brute force attack.",
          xp: 30,
        },
        {
          question:
            "LogonType 3 appears in the event. What does Logon Type 3 mean in Windows authentication?",
          options: [
            "Interactive logon — user physically sat at the machine and entered credentials",
            "Service logon — a Windows service started using a service account",
            "Network logon — authentication over the network (e.g., SMB, RDP, mapped drive)",
            "Cached credentials logon — offline login using cached domain credentials",
          ],
          answer: 2,
          explanation:
            "Windows Logon Type 3 is a Network logon — the authentication request came over the network rather than at the physical console. This type is used by SMB (file shares), RDP network-level authentication, and many remote access methods. The source IP 185.220.101.45, an external address unrelated to the corporate network, combined with LogonType 3 and a WorkstationName that does not match any known corporate asset, confirms this is a remote network-based authentication attempt from outside the organisation.",
          xp: 25,
        },
      ],
    } satisfies LogAnalysisTask,

    // ----- Flag: table name -------------------------------------------------
    {
      type: "flag",
      id: "sentinel-flag1",
      prompt:
        "In Microsoft Sentinel, which Log Analytics table stores Windows Security Event Log entries — including failed logins (EventID 4625) and successful logins (EventID 4624)? Enter the exact table name.",
      answer: "SecurityEvent",
      hint: "This table is mentioned in the Reading 1 table of Sentinel log tables, and confirmed in the log analysis explanation above.",
      xp: 20,
    } satisfies FlagTask,

    // ----- Question 2 -------------------------------------------------------
    {
      type: "question",
      id: "sentinel-q2",
      question:
        "A Sentinel analytics rule runs every 5 minutes and looks back at the last 15 minutes of SignInLogs. It detects a user account logging in from two countries 30 minutes apart (impossible travel). What type of analytics rule would be MOST appropriate for this detection?",
      options: [
        "Scheduled rule with a custom KQL query calculating geolocation distance and time difference",
        "NRT (Near Real Time) rule running every 1 minute",
        "Fusion rule — this is automatically handled by Microsoft's ML",
        "Both A and C are appropriate — Scheduled rules for custom logic, Fusion for automatic ML detection",
      ],
      answer: 3,
      explanation:
        "Both approaches work: Microsoft's Fusion ML engine automatically detects impossible travel as an anomaly without any custom configuration. However, you can also write your own Scheduled analytics rule using KQL to detect it with custom thresholds (e.g., alert only if the distance implies >900 km/h travel). In production environments, many organisations use both — Fusion for broad coverage and a custom scheduled rule with organisation-specific thresholds for higher-confidence alerts.",
      xp: 25,
    } satisfies QuestionTask,

    // ----- Question 3 -------------------------------------------------------
    {
      type: "question",
      id: "sentinel-q3",
      question:
        "A SOC analyst wants to see the top 5 user accounts with the most failed logins in the past 24 hours in Sentinel. Which KQL query is correct?",
      options: [
        "SecurityEvent | where EventID == 4625 | where TimeGenerated > ago(24h) | summarize FailCount = count() by Account | top 5 by FailCount",
        "SELECT Account, COUNT(*) FROM SecurityEvent WHERE EventID=4625 GROUP BY Account LIMIT 5",
        "SignInLogs | where ResultType != 0 | top 5 by Account",
        "SecurityEvent | filter EventID=4625 | groupby Account | top 5",
      ],
      answer: 0,
      explanation:
        "The correct KQL query chains the operators correctly: (1) start with SecurityEvent table, (2) filter for EventID 4625 using 'where', (3) apply time filter with ago(24h), (4) summarize with count() grouped by Account, (5) return top 5 by count. Option B is SQL syntax. Option C uses the wrong table and wrong failed login indicator (SignInLogs uses ResultType, not EventID). Option D uses invalid KQL syntax.",
      xp: 25,
    } satisfies QuestionTask,

    // ----- Query Fill: write the KQL yourself -------------------------------
    {
      type: "query_fill",
      id: "sentinel-queryfill-1",
      heading: "Write It Yourself: Failed Logins in the Last Hour",
      language: "kql",
      context:
        "You've read plenty of finished KQL queries this room — now write one. A colleague asks: \"Which accounts had a failed Windows logon in the last hour?\" Fill in the blanks to build that query from the SecurityEvent table.",
      template:
        "SecurityEvent\n| where EventID == {{eventid}}\n| where TimeGenerated > ago({{window}})\n| project TimeGenerated, {{account}}, Computer, IpAddress",
      blanks: [
        { id: "eventid", answers: ["4625"], placeholder: "event ID" },
        { id: "window",  answers: ["1h"], placeholder: "time window" },
        { id: "account", answers: ["Account", "TargetAccount"], placeholder: "account column" },
      ],
      explanation:
        "4625 is the Windows Security Event ID for a failed logon. ago(1h) scopes TimeGenerated to the last hour — KQL's relative-time shorthand (1h, 30m, 7d). SecurityEvent's account column is named Account (some schema versions expose TargetAccount) — project narrows the output to just what a triage analyst needs to see per row.",
      xp: 30,
    } satisfies QueryFillTask,

    // ----- Analyst Choice: password-spray-shaped alert from a vuln scanner --
    {
      type: "analyst_choice",
      id: "sentinel-ac1",
      heading: "Verdict: Mass Failed Logons Across Many Accounts From One Source",
      scenario:
        "At 03:00 AM, a Sentinel scheduled analytics rule fires: 260 failed Windows logons (Event ID 4625) across 14 distinct user accounts, all originating from a single source IP (10.30.8.14), within a 10-minute window. This is exactly the query pattern taught earlier in this room for detecting password spray. IT change management confirms 10.30.8.14 is the internal Qualys vulnerability scanner (scanner-qualys01), running its monthly authenticated credential-validation scan against the Windows subnet 10.30.8.0/24, per the standing compliance-scanning schedule (change record CHG0052210). What is your verdict?",
      event: {
        id: "sentinel-ac1-evt-001",
        ts: "2025-08-03T03:00:00Z",
        source: "siem",
        vendor: "Microsoft Sentinel",
        event_type: "auth_failure",
        severity: "high",
        description:
          "Scheduled analytics rule 'Multiple failed logons across many accounts from a single source' fired: 260 Event ID 4625 failures across 14 distinct accounts from one source IP within a 10-minute window",
        mitre_technique: "T1110.003",
        mitre_tactic: "Credential Access",
        it_verify_result: "confirmed",
        it_verify_message:
          "CHG0052210: 10.30.8.14 (scanner-qualys01) is the internal Qualys vulnerability scanner performing its scheduled monthly authenticated credential-validation scan against 10.30.8.0/24.",
        raw: {
          // Real Sentinel SecurityAlert shape: top-level AlertName/AlertSeverity,
          // with the scheduled rule's aggregate output under ExtendedProperties.*
          // (rule-author-defined keys — the documented Sentinel convention).
          AlertName: "Multiple failed logons across many accounts from a single source",
          AlertSeverity: "High",
          "alert.description": "260 failed logons (Event ID 4625) across 14 distinct accounts from source 10.30.8.14 within a 10-minute window",
          "event.code": "4625",
          "source.ip": "10.30.8.14",
          "ExtendedProperties.FailureCount": "260",
          "ExtendedProperties.DistinctAccountCount": "14",
          "ExtendedProperties.TimeWindowMinutes": "10",
          "ExtendedProperties.SubStatusDistribution": "0xC000006A:242, 0xC0000064:18",
          "ExtendedProperties.LogonTypeDistribution": "3:260",
          "ExtendedProperties.AffectedComputerCount": "14",
        },
      } satisfies TelemetryEvent,
      correct_verdict: "false_positive",
      explanation:
        "The raw numbers here — 260 failures, 14 distinct accounts, one source IP, all network logons (LogonType 3) — are exactly the statistical shape this room's KQL reading taught you to build a password-spray detection around (summarize FailureCount, DistinctAccounts by IpAddress). But 10.30.8.14 is an internal, allocated address belonging to the organisation's own vulnerability scanner, not an unrecognised external host, and IT verification directly confirms a scheduled, approved authenticated scan covering this exact time window. Authenticated vulnerability scanners deliberately attempt logons with lists of credentials to test password-policy compliance, producing a near-identical statistical fingerprint to a real password spray. With source ownership and change-ticket confirmation both checked, this is expected internal scanning activity, not an attack.",
      fp_trap:
        "This alert is a textbook case of a detection rule correctly matching its pattern while still being a false positive, because the rule only measures shape (many accounts, one source, many failures) and cannot see intent. Declaring 'true positive' the moment the numbers match the taught query — without checking whether the source IP belongs to a known internal scanner and whether a change record explains it — is exactly the alert-fatigue trap that erodes trust in a detection program. If 10.30.8.14 had instead been an external or unrecognised IP with no matching change ticket, the correct verdict would be true_positive or escalate.",
      xp: 30,
    } satisfies AnalystChoiceTask,
  ],
};

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

const rooms: Room[] = [
  logManagement,
  siemFundamentals,
  wazuhFundamentals,
  sentinelFundamentals,
];

export default rooms;
