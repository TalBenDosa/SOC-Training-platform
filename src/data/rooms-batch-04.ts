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
          "A firewall forwards lines that begin CEF:0|Fortinet|FortiGate| followed by more pipe-separated header fields and then key=value pairs such as src=10.1.1.5. Which log format is the collector receiving?",
        options: ["CEF (Common Event Format)", "LEEF (Log Event Extended Format)", "Plain-text syslog (RFC 3164)", "ECS (Elastic Common Schema)"],
        answer: 0,
        explanation:
          "The CEF:0| prefix, followed by pipe-separated vendor, product and version fields and then key=value extensions, is the ArcSight/Micro Focus Common Event Format. LEEF is IBM QRadar's similar format, but its lines begin LEEF:, not CEF:. Plain-text syslog has no fixed pipe-separated header (a CEF line often travels inside a syslog message, but the payload format is still CEF). ECS is a normalisation schema applied after collection, not a format a firewall sends.",
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

**3. API polling** — cloud services (Microsoft 365, AWS, Okta) expose APIs that the SIEM can call periodically to retrieve logs. For example, a SIEM connector calls the Office 365 Management Activity API (or the Okta System Log API) every few minutes to pull new audit events. (Entra ID sign-in logs reach Microsoft Sentinel differently — they are streamed in through Azure diagnostic settings, not polled.)

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
        "Log enrichment",
        "Log correlation",
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
- **Event ID 104** — A non-Security event log (System, Application, etc.) was cleared. This record is written to the System channel.

The 1102 record also carries a **SubjectLogonId** — a hex number that identifies the exact logon session of the account that cleared the log. Searching other events for that same value (starting with the 4624 logon that opened the session) shows what the account did in that one session, not everything it has ever done.

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
          "DC01-CORP forwards its Security log to the SIEM in real time. An attacker then clears the Security log on the DC itself. What evidence does the analyst still have?",
        options: [
          "Every event forwarded before the clear, plus the 1102 that records who cleared it",
          "Nothing from before the clear, because clearing the log also purges forwarded copies",
          "Event ID 104 records, which Windows writes in place of the cleared events",
          "Post-clear events alone, since forwarding starts over with the new, empty log",
        ],
        answer: 0,
        explanation:
          "Central collection is the defence the reading describes: events already shipped to the SIEM are out of the attacker's reach, and the 1102 written after the clear is forwarded too. Clearing a local log cannot reach copies already stored on another server. Event ID 104 is a separate record for clearing a non-Security log; it does not replace the cleared events. Forwarding does not reset history either — only the local copy was emptied.",
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
            "This 1102 record sits in the Security channel — the very log that was just cleared. Why is it there at all?",
          options: [
            "The clear failed partway, so this record survived from before the clear",
            "Windows writes 1102 into the emptied Security log right after it is cleared",
            "1102 is stored in the System channel, which the attacker did not clear",
            "Clearing hides events in Event Viewer, but the old records stay on disk",
          ],
          answer: 1,
          explanation:
            "Windows records the clearing itself: as soon as the Security log is emptied, it writes Event ID 1102 (winlog.channel: Security) into the fresh log, naming the account that cleared it. A partial failure would leave the older events in place, which is not what 1102 means. This record's channel is Security, not System — the System-channel event for clearing other logs is 104. Clearing really does empty the local log; the defence is having already forwarded the events elsewhere.",
          xp: 25,
        },
        {
          question:
            "You want to see what svc-helpdesk02 did during the same logon session that cleared the log — not everything the account has ever done. Which field do you search other events for?",
          options: [
            "winlog.event_data.SubjectUserName",
            "winlog.event_data.SubjectDomainName",
            "winlog.event_data.SubjectLogonId",
            "event.created",
          ],
          answer: 2,
          explanation:
            "SubjectLogonId (0x3E4F2A) identifies one logon session; searching for it — starting with the 4624 that opened the session — returns only the actions taken in that session. SubjectUserName would return every session the account has ever had: useful later, but it answers a broader question. SubjectDomainName (CORP) matches every account in the domain. event.created is a timestamp; a time window alone would mix in other users' activity on the DC.",
          xp: 25,
        },
        {
          question:
            "What is the best immediate action for a SOC analyst upon seeing this alert?",
          options: [
            "Close it as a false positive — admins routinely clear logs during maintenance",
            "Escalate to Tier 2 or IR — possible active compromise of a domain controller",
            "Wait for a second suspicious event on the DC before escalating",
            "Reset the svc-helpdesk02 password and close the ticket as remediated",
          ],
          answer: 1,
          explanation:
            "Clearing the Security log on a domain controller at 3am, from an account named like a service account (svc-helpdesk02), is a strong sign of an attacker covering their tracks on the most sensitive server in the domain, so escalate to Tier 2 or IR now. Closing it as maintenance needs evidence, such as an approved change, that is not here. Waiting for a second event gives the attacker more time on the DC. Resetting the password and closing treats one symptom and skips the investigation into what the account did before it cleared the log.",
          xp: 30,
        },
      ],
    } satisfies LogAnalysisTask,

    // ----- Flag: Event ID for log clearing ----------------------------------
    {
      type: "flag",
      id: "log-mgmt-flag1",
      prompt:
        "Suppose the attacker had also cleared the System log on DC01-CORP. Which Windows Event ID would you search for to prove that second clearing? Enter only the numeric ID.",
      answer: "104",
      hint: "It is not the Security-channel event shown in the log above.",
      xp: 20,
    } satisfies FlagTask,

    // ----- Question 3 -------------------------------------------------------
    {
      type: "question",
      id: "log-mgmt-q3",
      question:
        "A US hospital group must comply with HIPAA and also takes card payments, so PCI-DSS applies too. Using the retention requirements in the reading, what is the minimum time its security audit logs should be kept?",
      options: [
        "12 months, because PCI-DSS is the more specific logging rule",
        "3 months, the period PCI-DSS requires immediately available",
        "6 years, because the longer of the two requirements applies",
        "7 years, because healthcare follows the SOX audit-log rule",
      ],
      answer: 2,
      explanation:
        "When two regulations apply, the logs must satisfy both, so the longer period wins: 6 years under HIPAA (its 6-year documentation rule is commonly applied to security audit logs) versus 12 months under PCI-DSS. Keeping only 12 months satisfies PCI-DSS but not HIPAA. 3 months is only how much PCI-DSS wants immediately searchable, not the total retention. SOX's 7 years covers US financial reporting, not healthcare.",
      xp: 20,
    } satisfies QuestionTask,

    // ----- Question 4 -------------------------------------------------------
    {
      type: "question",
      id: "log-mgmt-q4",
      question:
        "Which log collection method is most appropriate for a Palo Alto firewall that cannot have third-party software installed on it?",
      options: [
        "Agent-based — install Filebeat on PAN-OS through its underlying Linux shell",
        "Agentless syslog — the firewall forwards logs to a remote syslog server on port 514",
        "Scheduled CSV export — an admin exports logs from the PAN-OS web UI each morning",
        "SNMP polling — the SIEM reads traffic and threat logs from the firewall's MIB",
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
          "Aggregation has already put every failed login in one place, and normalisation has given them a common user field. Which SIEM function recognises 47 failures against 12 accounts from one IP, within a minute, as a single attack pattern?",
        options: ["Alerting", "Correlation", "Dashboarding", "Reporting"],
        answer: 1,
        explanation:
          "Correlation applies detection rules across many events and spots the pattern; the reading calls it the most powerful function. Alerting comes after correlation: it notifies the SOC once a rule has matched, but it does not do the matching. Dashboarding shows trends for situational awareness and reporting produces compliance summaries; neither decides that separate events form an attack.",
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
        "A SIEM rule fires when a single source IP produces more than 20 failed logins against different accounts within 60 seconds — far more than any normal user generates. What type of detection rule is this?",
      options: [
        "Statistical anomaly rule",
        "Sequence / chained rule",
        "Threshold rule",
        "Trend / rate-of-change rule",
      ],
      answer: 2,
      explanation:
        "It is a threshold rule: a fixed count (20) inside a fixed time window (60 seconds). The 'far more than normal' wording is a trap — a statistical anomaly rule compares behaviour with a learned baseline, while this rule uses a number someone chose. A trend rule fires on a percentage change against a baseline (for example 500% above the 7-day average), and a sequence rule needs different events in a set order (scan, then failure, then success). Threshold rules are simple and common, but slow attacks that stay under the count evade them.",
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
          "The password-spray rule fires on 12 failed logins. Investigation shows a developer's load-test script locked out 12 test accounts. The rule matched exactly the pattern it was written for. How should the alert be classified?",
        options: [
          "True Positive — the rule matched its pattern correctly",
          "False Negative — the rule fired on the wrong activity",
          "False Positive — the pattern matched but nothing malicious happened",
          "True Negative — no harm was done, so nothing was detected",
        ],
        answer: 2,
        explanation:
          "A False Positive is an alert with no real security incident behind it — even when the rule did exactly what it was written to do. 'True Positive' judges the rule's logic instead of the outcome; a TP needs a real incident. A False Negative is the opposite failure: a real attack with no alert. A True Negative means no alert and no attack, but an alert did fire here.",
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
            "The rule tags this alert T1110.003, but a colleague wants to re-tag it. Which mapping do data.failed_count and data.target_accounts support?",
          options: [
            "T1110.001 Password Guessing — 47 different passwords tried against the accounts",
            "T1110.003 Password Spraying — a few attempts each, spread across many accounts",
            "T1078 Valid Accounts — the attacker already knows twelve real usernames",
            "T1110 Brute Force (parent) — the counts cannot tell the sub-techniques apart",
          ],
          answer: 1,
          explanation:
            "47 failures over 12 accounts is about 4 attempts per account: few tries each, many accounts — the spray pattern this room describes, which stays under per-account lockout. Password Guessing (T1110.001) is the reverse shape: many passwords against one account. Valid Accounts (T1078) applies once an attacker logs in with working credentials; every attempt here failed. The parent T1110 (Brute Force) is correct but less precise — the two counts are exactly what lets you pick the sub-technique.",
          xp: 20,
        },
        {
          question:
            "data.isp identifies the source as a Tor exit node. How should that enrichment change your view of the alert?",
          options: [
            "Lower priority — privacy-minded staff often use Tor, so the source tells you little",
            "It raises confidence of a true positive alongside the spray-shaped counts",
            "Lower priority — a shared VPN egress for remote staff would look exactly like this",
            "No change — enrichment describes the source and should not affect the verdict",
          ],
          answer: 1,
          explanation:
            "Anonymised infrastructure plus a spray-shaped burst (47 failures across 12 accounts in 60 seconds) points to a true positive and supports escalation. Staff Tor use is possible, but one employee would not produce failures across 12 accounts in a minute. The ISP field names Tor, not a corporate VPN, so treating it as staff egress misreads the log. Enrichment exists to change confidence — ignoring source reputation throws away evidence.",
          xp: 25,
        },
        {
          question:
            "The alert shows only failures. What should you search for next to judge how serious this spray is?",
          options: [
            "Failed logins from other Tor exit nodes over the past 30 days",
            "The rule's change history, to see who last edited its threshold",
            "Successful logins to the 12 targeted accounts after 11:47 UTC",
            "Failed logins for the 12 accounts, to confirm the count of 47",
          ],
          answer: 2,
          explanation:
            "A spray only matters if one guess worked, so the decisive pivot is a success for any targeted account after the burst — the failure-then-success pattern a sequence rule looks for. Other Tor sources may be worth a hunt later, but they do not tell you whether this spray succeeded. The rule's edit history is a tuning question. Recounting the failures only confirms what the alert already says.",
          xp: 25,
        },
      ],
    } satisfies LogAnalysisTask,

    // ----- Flag: failed login count -----------------------------------------
    {
      type: "flag",
      id: "siem-fund-flag1",
      prompt:
        "Using the counts in the Password Spray alert, how many failed attempts did each targeted account receive on average? Round to the nearest whole number and enter only the number.",
      answer: "4",
      hint: "Two fields in the alert describe the total and how widely it was spread.",
      xp: 15,
    } satisfies FlagTask,

    // ----- Question 2 -------------------------------------------------------
    {
      type: "question",
      id: "siem-fund-q2",
      question:
        "A SOC team has a rule that fires every time a user downloads more than 50 MB in an hour from SharePoint. The rule fires 200 times per day, but after investigation, 190 of those are the automated backup service. What is the correct action?",
      options: [
        "Delete the rule and rely on DLP alerts, since it produces mostly false positives",
        "Tune the rule — exclude the backup service account so it stops triggering",
        "Raise the rule's severity so analysts pay closer attention to real incidents",
        "Leave it unchanged and have analysts close the backup alerts each day",
      ],
      answer: 1,
      explanation:
        "The correct response is rule tuning: add an exception for the known-good backup service account. This eliminates 190 false positives per day while keeping the rule active for all other accounts. Deleting the rule would create false negatives (real data exfiltration would go undetected). Raising the severity makes 190 known-benign alerts louder, not rarer. Leaving it unchanged keeps analysts closing the same backup alerts every day — the alert fatigue the reading warns about. Alert fatigue is solvable through tuning.",
      xp: 20,
    } satisfies QuestionTask,

    // ----- Question 3 -------------------------------------------------------
    {
      type: "question",
      id: "siem-fund-q3",
      question:
        "An attacker successfully steals credentials and accesses your VPN, but the SIEM never fires an alert because the login looked legitimate. What type of detection outcome is this?",
      options: [
        "True Positive — the attacker was eventually found",
        "False Positive — the login looked fine but was not",
        "False Negative — a real attack produced no alert",
        "True Negative — the rule behaved as designed for a valid login",
      ],
      answer: 2,
      explanation:
        "This is a False Negative — the most dangerous outcome in security operations. A True Positive needs an alert to have fired, however the attack was later found. A False Positive is an alert with no real attack — the reverse case. 'The rule behaved as designed' does not make it a True Negative, because a real attack did happen. The attack was real, but the SIEM failed to detect it. False negatives occur when detection rules are too conservative, attacker techniques are unknown, or the attacker used legitimate credentials that mimic normal user behaviour. Reducing false negatives requires adding behavioural detection rules (UEBA) on top of signature-based rules.",
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
| stats count by Account_Name
\`\`\`

Same question, same answer, different syntax. KQL builds the query as a pipeline of separate lines — start with the table (SecurityEvent), narrow it with where, narrow it again by time, then summarize. SPL front-loads its filtering into the base search itself: index=windows picks the data source, EventCode=4625 is the filter condition, and earliest=-1h is the time scope, all on one line, before the pipe hands the filtered results to stats for the count. Splunk analysts and Sentinel analysts are doing identical mental work; they are just typing it differently. (One Splunk detail: the Windows add-on extracts the account as Account_Name, and on a 4625 that field holds two values — the subject and the target account — so production searches often group by the CIM field user instead.)

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
        { id: "window", answers: ["1h", "60m"], placeholder: "time window" },
        { id: "aggregation", answers: ["FailCount = count()", "FailCount=count()", "count()", "Failures = count()", "Failures=count()", "FailureCount = count()", "FailureCount=count()", "FailedLogons = count()", "FailedLogons=count()", "Count = count()", "Count=count()"], placeholder: "aggregation expression" },
      ],
      explanation:
        "4625 is the Windows Security Event ID for a failed logon attempt — 4624 is its easily-confused twin, a successful logon. ago(1h) (or the equivalent ago(60m)) scopes TimeGenerated to the last hour, the same relative-time shorthand you saw in the reading (30m, 1h, 24h, 7d all work). The alias before count() is your choice — FailCount = count(), Failures = count() or a bare count() all work. summarize ... by Account groups every matching failure row by account and counts them, turning a flat list of raw events into the exact shape a triage answer needs: how many failures per account. This is the identical logic the reading's SPL example reached with stats count by Account_Name — same three steps, different keywords.",
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
        question: "On the Wazuh dashboard, agent 001 (linux-srv-01) shows as Disconnected, while the dashboard itself still loads data from the Manager normally. A firewall change was just made between linux-srv-01 and the Manager. Which port has most likely been blocked?",
        options: ["TCP 1514", "TCP 55000", "TCP 514", "TCP 443"],
        answer: 0,
        explanation:
          "Agents talk to the Manager over TCP 1514 (encrypted), so a block there disconnects the agent while everything else keeps working. TCP 55000 is the Manager's API used by the dashboard — that path is still working in this scenario. TCP 514 is classic syslog for agentless devices, not the Wazuh agent channel, and 443 serves the dashboard's web interface.",
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
- \`data.srcport = 54321\` (the SSH client's source port — the "port 54321" in the sshd message)

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
| 500-599 | Wazuh internal — rootcheck (e.g. 510) and file-integrity/syscheck (e.g. 550, 554) |
| 60000-61999 | Windows eventchannel — Security, System and Sysmon channels |
| 80000+ | Integrations and vendor-specific decoders |
| 100000+ | Reserved for YOUR custom rules — never write below this |

That last row is the one that actually bites people: custom rules must live at 100000 or above, because anything lower can be overwritten when you upgrade the ruleset.

Some representative built-in rules you will meet often:

- **5710** — sshd: attempt to log in using a non-existent user
- **5503** — PAM: user login failed
- **31103** — Web server attack: SQL injection attempt (successful SQLi escalates to **31106**)
- **510** — Host-based anomaly detection event (rootcheck)

**Always confirm the exact ID against your own instance before you build anything on it.** Rule IDs and their descriptions shift between ruleset versions, and every organisation runs a slightly different mix of built-in and custom rules. Two commands settle it in seconds: **/var/ossec/bin/wazuh-logtest** lets you paste a raw log line and see precisely which rule fires and at what level, and the rule files under **/var/ossec/ruleset/rules/** are plain XML you can grep. An analyst who knows how to *look up* the rule that fired is far more useful than one who memorised a list that was accurate for one version two years ago.

**Rule inheritance (parent/child rules):**

Wazuh rules are hierarchical. A parent rule matches the general event type (e.g., "this is a sshd authentication event"). Child rules then match more specific conditions on top of the parent. This layered approach allows complex detection logic without needing to repeat common conditions in every rule.

For example:
- Parent rule 5700: "sshd authentication event detected" (fires on any SSH-related log)
- Child rule 5710: "Failed login for non-existent user" (only fires if parent matched AND user does not exist)
- Child rule 5712: "sshd: brute force trying to get access to the system" (only fires if parent matched AND failures exceed the frequency threshold in the timeframe)`,
      checkpoint: {
        question: "A custom rule fires at level 4 on agent 001, but no alert appears on the dashboard. On a fresh lab install of Wazuh, the same rule's level-4 alerts do appear. Which explanation fits best?",
        options: [
          "This site raised log_alert_level above 4; the default of 3 would show it",
          "Level 4 sits in the Low band, which Wazuh does not alert on by default",
          "The default alerting threshold is level 7, so level 4 events go to the archives instead",
          "Level 4 alerts wait until the rule's frequency count has been reached",
        ],
        answer: 0,
        explanation:
          "By default `log_alert_level` in `ossec.conf` is 3, so a level-4 rule produces a visible alert — which is why the lab install shows it. When it disappears on one site, that site has raised the threshold (to 5, 7 or higher) to cut noise. The Low band (4–6) is above the default threshold of 3, so the default does alert on it. 7 is a common tuned value, not the default — assuming otherwise is a frequent mistake. Frequency only applies to rules built with frequency/timeframe, and would behave the same on the lab install.",
      },
    } satisfies ReadingTask,

    // ----- Question 1 -------------------------------------------------------
    {
      type: "question",
      id: "wazuh-q1",
      question:
        "Two alerts arrive together on the same server: rule A at level 12 and rule B at level 15. How should you read them on Wazuh's severity scale?",
      options: [
        "Both are Critical; Wazuh treats every level from 12 up as one band",
        "Rule A is Medium and rule B is High; Critical is reserved for level 16",
        "Both are High; the level reflects how many times each rule has fired",
        "Rule A is High; rule B is Critical, the maximum level, so it goes first",
      ],
      answer: 3,
      explanation:
        "Wazuh levels run 0–15: 12–14 is High and 15 alone is Critical, the maximum, so rule B takes priority. 12 is High, not Critical, so the two are not one band. There is no level 16 — 15 is the top of the scale. A rule's level is fixed in its definition; it describes severity, not how often the rule fired. (Levels 7-11 are Medium, 4-6 are Low, and 0-3 are informational or ignored.) By default (`log_alert_level` = 3) any rule at level 3 or above becomes a visible alert in the dashboard; many teams then raise that threshold to cut noise, but 3 — not 7 — is the out-of-the-box default.",
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

FIM alerts on /etc/passwd or /etc/sudoers on a Linux server should always be investigated — adding a new user or granting sudo access are classic post-exploitation actions. When you review a new account, also check its login shell: service accounts are normally created with a non-login shell such as /usr/sbin/nologin or /bin/false, so a new "service" account given /bin/bash can be used for interactive logins — a common backdoor pattern.

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
        question: "An attacker runs useradd to create a new local account on a Linux server. Which file's change would FIM report as the account appears?",
        options: ["/etc/passwd", "/etc/sudoers", "/var/log/auth.log", "/usr/bin/useradd"],
        answer: 0,
        explanation:
          "New accounts are written to /etc/passwd, one of the files FIM watches by default, so FIM reports the change. /etc/sudoers only changes if the account is later given sudo rights. /var/log/auth.log is a log that Wazuh reads through log analysis, not a watched configuration file. Running /usr/bin/useradd does not modify the binary itself, so FIM would see no change there.",
      },
    } satisfies ReadingTask,

    // ----- Log Analysis: new privileged user --------------------------------
    {
      type: "log_analysis",
      id: "wazuh-la1",
      heading: "Wazuh Alert: New User Added to Linux System",
      context:
        "You are a SOC analyst monitoring a Linux production server through Wazuh. An alert just fired on your dashboard. The server is a critical application server that should never have new user accounts added outside of approved change management windows. Review the alert and answer the questions.",
      event: {
        id: "wazuh-evt-001",
        ts: "2025-06-24T02:44:17Z",
        source: "siem",
        event_type: "edr_alert",
        severity: "medium",
        hostname: "linux-srv-01",
        description: "Wazuh: New user account added to the system",
        mitre_technique: "T1136.001",
        raw: {
          "rule.id": "5902",
          "rule.level": "8",
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
            "The alert's rule.level is 8. How should that level shape your response, given what the context says about this server?",
          options: [
            "Low priority — levels below 12 can wait for the next routine review",
            "Medium band, but the server's context makes it urgent: escalate it",
            "Treat it as Critical — creating a user is the riskiest change on Linux",
            "Close it — the level already accounts for context, so 8 means routine",
          ],
          answer: 1,
          explanation:
            "Level 8 sits in Wazuh's Medium band (7–11): events that should be investigated. A rule's level is generic — the same on every server — so it cannot know that this is a critical application server where new accounts appear only in approved change windows. An unplanned account at 02:44 on that server is worth escalating whatever the level says. Medium alerts do need an analyst, so ignoring everything below 12 is wrong. The level is not Critical either: only 15 is. And a level does not include business context — adding it is the analyst's job, using `rule.description` (New user added to the system) and what you know about the server.",
          xp: 25,
        },
        {
          question:
            "Which detail in full_log most strongly suggests sysmgr_svc is not an ordinary service account?",
          options: [
            "home=/home/sysmgr_svc — a home directory marks it as a human user's account",
            "data.srcuser=root — legitimate admins do not run useradd as root",
            "shell=/bin/bash — service accounts normally get a non-login shell",
            "UID=1337 — UIDs of 1000 and above are reserved for system services",
          ],
          answer: 2,
          explanation:
            "Service accounts are normally given a non-login shell such as /usr/sbin/nologin or /bin/false; /bin/bash lets this new 'service' account log in interactively — a common backdoor pattern, especially at 02:44 outside any change window. useradd creates a home directory for many kinds of account, so a home path alone proves little. Running useradd as root is normal, because it needs root. UIDs from 1000 up are ordinary user accounts, not reserved for services, so 1337 is not the tell.",
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
        "Using the reading's table of rule-ID ranges, which built-in range does the rule in this alert belong to? Enter the lower bound of that range (numbers only).",
      answer: "5300",
      hint: "Wazuh groups its built-in rule IDs into blocks by log source.",
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
        "A frequency/timeframe rule such as 5712",
      ],
      answer: 2,
      explanation:
        "Active Response is Wazuh's automated countermeasure system. A frequency/timeframe rule such as 5712 (SSH brute force) detects the attack and raises the alert, but detecting is not blocking — Active Response is what acts on that alert. FIM watches files and SCA checks configuration against benchmarks; neither blocks traffic. When a specified rule fires, Wazuh can trigger scripts on the monitored endpoint — including the built-in 'firewall-drop' script that blocks the source IP using iptables. Active responses can run on the agent that generated the alert, on a different agent, or on the Wazuh Manager itself.",
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
| **SigninLogs** | Azure Active Directory / Entra ID sign-in events |
| **AuditLogs** | Azure AD directory changes (user create/delete, group changes, role assignments) |
| **OfficeActivity** | Microsoft 365 activity (Exchange, SharePoint, Teams, OneDrive) |
| **DeviceEvents** | Microsoft Defender for Endpoint raw events |
| **DeviceAlertEvents** | MDE alert-level events |
| **AzureActivity** | Azure resource management operations (create VM, delete storage, etc.) |
| **Heartbeat** | Agent health check-ins from connected VMs |
| **SecurityAlert** | Alerts from Microsoft security products (Defender, Sentinel analytics rules) |
| **SecurityIncident** | Sentinel incidents (grouped alerts) |

Knowing which table to query is the first step in any Sentinel investigation. A Windows failed login? Query SecurityEvent. A suspicious Azure AD login? Query SigninLogs.

**Reading a 4625 row in SecurityEvent:** two columns do most of the triage work. **LogonType** says how the logon was attempted — 2 = interactive at the keyboard, 3 = network (for example an SMB share or mapped drive), 5 = a service starting, 10 = a full RDP session. **SubStatus** says why it failed — 0xC000006A = wrong password for an account that exists, 0xC0000064 = the username does not exist, 0xC0000072 = the account is disabled.`,
      checkpoint: {
        question: "A user reports MFA prompts they never requested, right after someone tried their Microsoft 365 password from abroad. Which table shows those cloud sign-in attempts?",
        options: ["SigninLogs", "SecurityEvent", "OfficeActivity", "AuditLogs"],
        answer: 0,
        explanation:
          "Entra ID (Azure AD) sign-ins, including failed and MFA-challenged ones, are in SigninLogs. SecurityEvent holds Windows Security log events from servers and workstations, not cloud sign-ins. OfficeActivity records what users do inside Exchange, SharePoint and Teams after they are signed in. AuditLogs records directory changes such as new users or role assignments.",
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
\`ago(1h)\` means "1 hour ago from now." You can use \`ago(24h)\`, \`ago(7d)\`, \`ago(30m)\`. TimeGenerated is the record's event time — when the event was generated at the source (or received by the agent), not when it landed in Sentinel. Ingestion time is a separate value you read with \`ingestion_time()\`; logs can arrive minutes late (ingestion delay), which is why scheduled rules use a lookback that overlaps the run interval.

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
- KQL is **case-sensitive** for table names, column names, operators and functions — \`SecurityEvent | Where ...\` fails because the operator is \`where\`
- String matching depends on the operator: \`==\` is an exact, case-sensitive match; \`=~\` is a case-insensitive match; \`has\`, \`contains\` and \`startswith\` are case-insensitive (their \`_cs\` variants are case-sensitive)
- The pipe \`|\` must always be on the same line as or at the start of the next operator
- String literals use double quotes: \`"value"\`
- Run queries in the Sentinel Logs blade or in the Log Analytics Workspace directly`,
      checkpoint: {
        question: "A scheduled rule runs every 5 minutes and filters TimeGenerated > ago(5m). One connector's events reach Sentinel about 3 minutes after they happen, and some of them never trigger the rule. What is the most likely reason?",
        options: [
          "TimeGenerated is event time, so late rows land in a window that already ran",
          "TimeGenerated is ingestion time, so late rows get stamped too new to match",
          "ago(5m) counts back from when the rule was created, not from each run",
          "KQL drops rows whose ingestion delay is longer than the lookback window",
        ],
        answer: 0,
        explanation:
          "TimeGenerated is when the event happened at the source. An event from 14:04 that lands at 14:07 is not there for the 14:05 run, and the 14:10 run only looks back to 14:05 — so it is never evaluated. The fix the reading describes is a lookback that overlaps the run interval. If TimeGenerated were ingestion time, late rows would simply match the next run. ago() is relative to the moment the query runs. KQL does not drop late rows; they are stored and searchable, just outside this rule's window.",
      },
    } satisfies ReadingTask,

    // ----- Question 1 -------------------------------------------------------
    {
      type: "question",
      id: "sentinel-q1",
      question:
        "A SOC analyst wants to find all failed Windows logins (Event ID 4625) in Sentinel from the past 6 hours. Which KQL query correctly achieves this?",
      options: [
        "SecurityEvent | where EventID == 4625 | where TimeGenerated < ago(6h)",
        "SecurityEvent | where EventID == 4625 | where TimeGenerated > ago(6h)",
        "SigninLogs | where EventID == 4625 | where TimeGenerated > ago(6h)",
        "SecurityEvent | Where EventID == 4625 | Where TimeGenerated > ago(6h)",
      ],
      answer: 1,
      explanation:
        "Start with the SecurityEvent table, filter with where EventID == 4625, and keep rows newer than six hours ago with TimeGenerated > ago(6h). Using < ago(6h) inverts the window and returns everything OLDER than six hours. SigninLogs holds Entra ID sign-ins and has no EventID column; Windows failed logons live in SecurityEvent. 'Where' with a capital W fails, because KQL operators are case-sensitive.",
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
            "You want every other failed Windows logon from 185.220.101.45 across all servers and workstations, not just this one. Which table do you query?",
          options: ["SigninLogs", "AuditLogs", "SecurityEvent", "OfficeActivity"],
          answer: 2,
          explanation:
            "Windows Security events from every connected Windows machine — including 4625 failed logons — land in one table, SecurityEvent, so a single query filtered on IpAddress finds them all. SigninLogs is the right pivot for this IP's cloud sign-ins, but not for Windows logons. AuditLogs holds Entra ID directory changes, and OfficeActivity holds Microsoft 365 user activity.",
          xp: 20,
        },
        {
          question:
            "SubStatus is 0xC000006A. What does that tell you about the attacker's position against j.smith?",
          options: [
            "They are guessing usernames, and j.smith does not exist in the domain",
            "They cannot succeed, because the j.smith account is disabled",
            "They have a valid username and are guessing its password",
            "They were locked out, so further attempts are being refused",
          ],
          answer: 2,
          explanation:
            "0xC000006A means the account exists but the password was wrong: the attacker has a real username and only needs the password, which makes a later success more dangerous. A non-existent username would be 0xC0000064, and a disabled account 0xC0000072. A lockout has its own failure code (0xC0000234), which this event does not show.",
          xp: 30,
        },
        {
          question:
            "LogonType is 3 and IpAddress is an internet address. What does that combination tell you about how the attempt reached CORP-WS-042?",
          options: [
            "Someone at CORP-WS-042's own keyboard typed j.smith's password",
            "A Windows service on CORP-WS-042 started with stored credentials",
            "It arrived over the network, so this workstation is reachable from outside",
            "It used cached credentials while the workstation was offline",
          ],
          answer: 2,
          explanation:
            "LogonType 3 is a network logon, such as SMB access to a share. Coming from 185.220.101.45, it means an external host could reach a network service on this workstation — an exposure worth raising in its own right. A person at the keyboard logs LogonType 2, a service starting logs LogonType 5, and cached offline logons use LogonType 11. (A full RDP session is LogonType 10; only RDP's Network Level Authentication pre-check appears as type 3.)",
          xp: 25,
        },
      ],
    } satisfies LogAnalysisTask,

    // ----- Flag: table name -------------------------------------------------
    {
      type: "flag",
      id: "sentinel-flag1",
      prompt:
        "In the 4625 event above, which column holds the address you would pivot on to find every other attempt by the same attacker? Enter the exact column name.",
      answer: "IpAddress",
      hint: "Not the machine that was targeted, and not the name the attacker's machine reported about itself.",
      xp: 20,
    } satisfies FlagTask,

    // ----- Question 2 -------------------------------------------------------
    {
      type: "question",
      id: "sentinel-q2",
      question:
        "You want a Sentinel detection that runs every 5 minutes, looks back at the last 1 hour of SigninLogs, and flags a user account signing in from two countries 30 minutes apart (impossible travel) using your own distance and time thresholds. What type of analytics rule is MOST appropriate for this detection?",
      options: [
        "Scheduled rule with a custom KQL query for distance and time between sign-ins",
        "NRT (Near Real Time) rule, so the travel alert fires within a minute",
        "Fusion rule — its ML engine detects impossible travel from raw sign-in logs",
        "Microsoft Security rule — it turns raw SigninLogs records into incidents",
      ],
      answer: 0,
      explanation:
        "A Scheduled rule is the right tool: it runs a custom KQL query on a schedule (here every 5 minutes over a 1-hour lookback, which is long enough to see two sign-ins 30 minutes apart) and lets you set your own thresholds, e.g. alert only if the distance implies >900 km/h travel. An NRT rule runs every minute over a very short window and is meant for single-event, low-latency detections, not a comparison of sign-ins spread over half an hour. Fusion does not detect impossible travel itself: it is a correlation engine that chains alerts that already exist (for example an 'atypical travel' alert from Entra ID Protection or an 'impossible travel' alert from Defender for Cloud Apps) into multi-stage incidents. A Microsoft Security rule only creates incidents from alerts raised by other Microsoft security products; it does not query raw SigninLogs. Built-in behavioural detection of unusual travel comes from Anomaly rules/UEBA or Entra ID Protection, not from Fusion.",
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
        "SecurityEvent | where EventID == 4625 | where TimeGenerated > ago(24h) | summarize count() by Account | top 5 by Account",
        "SigninLogs | where ResultType != 0 | where TimeGenerated > ago(24h) | summarize FailCount = count() by Account | top 5 by FailCount",
        "SecurityEvent | where EventID == 4625 | where TimeGenerated > ago(24h) | summarize FailCount = count() by Computer | top 5 by FailCount",
      ],
      answer: 0,
      explanation:
        "The correct query filters SecurityEvent to 4625, scopes to 24 hours, counts failures per Account, then takes the top 5 by that count. 'top 5 by Account' sorts by the account name, not by how many failures it has. Grouping by Computer answers a different question — which hosts saw the most failures. The SigninLogs query reads Entra ID sign-ins, not Windows failed logons (4625 lives in SecurityEvent), and that table has no Account column.",
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
        { id: "window",  answers: ["1h", "60m"], placeholder: "time window" },
        { id: "account", answers: ["Account", "TargetAccount", "TargetUserName"], placeholder: "account column" },
      ],
      explanation:
        "4625 is the Windows Security Event ID for a failed logon. ago(1h) scopes TimeGenerated to the last hour — KQL's relative-time shorthand (1h, 30m, 7d). SecurityEvent's account column is named Account; TargetAccount and TargetUserName also hold the target account and are accepted. ago(60m) is the same window as ago(1h). project narrows the output to just what a triage analyst needs to see per row.",
      xp: 30,
    } satisfies QueryFillTask,

    // ----- Analyst Choice: password-spray-shaped alert from a vuln scanner --
    {
      type: "analyst_choice",
      id: "sentinel-ac1",
      heading: "Verdict: Mass Failed Logons Across Many Accounts From One Source",
      scenario:
        "At 03:00 AM, a Sentinel scheduled analytics rule fires: 260 failed Windows logons (Event ID 4625) across 14 distinct user accounts, all from a single source IP (10.30.8.14), within a 10-minute window. Before you decide, check who owns 10.30.8.14 and whether anything explains activity from it at this hour — the IT verification note under the alert is your asset and change-record lookup. What is your verdict?",
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
