import type { TelemetryEvent } from "@/lib/sim/types";

// ─── Room 1: Detection Rules & Tuning ────────────────────────────────────────

const detectionRulesTuningRoom = {
  id: "detection-rules-tuning",
  title: "Writing Detection Rules & Tuning",
  description:
    "Learn how to write effective detection rules, understand Sigma rule format, and tune alerts to eliminate false positives without missing real threats.",
  difficulty: "intermediate" as const,
  category: "SIEM",
  estimatedMinutes: 50,
  xp: 280,
  icon: "⚙️",
  prerequisites: ["siem-fundamentals"],
  tasks: [
    // ── Reading 1: Rule Anatomy & Detection Types ──────────────────────────
    {
      type: "reading" as const,
      id: "det-rules-r1",
      heading: "Detection Engineering: Rule Anatomy & Logic Types",
      content: `## What Problem Are We Solving?

A SOC without detection rules is like a bank with no alarm system. You have cameras (logs), but nothing tells you when something suspicious happens. **Detection engineering** is the discipline of writing rules that automatically flag suspicious activity so analysts can investigate.

The goal is simple but hard to achieve: **detect real attacker behavior while ignoring normal business activity**. Write a rule too broadly and you drown in false alarms. Write it too narrowly and real attacks slip through.

---

## Anatomy of a Detection Rule

Every detection rule, regardless of what SIEM you use, has these core components:

- **Name** — a short, descriptive label: "Password Spray via Azure AD Sign-in Failures"
- **Description** — what the rule detects and why it matters
- **Severity** — Critical / High / Medium / Low (drives how urgently analysts respond)
- **Data Source** — which log type feeds this rule (Azure AD sign-in logs, Windows Security Events, firewall logs, etc.)
- **Detection Logic** — the actual filter or query that identifies suspicious events
- **Time Window** — the period over which the logic is evaluated (last 5 minutes, last 1 hour)
- **Grouping / Entity** — what to group results by (e.g., group by source IP address)
- **Threshold** — how many matches trigger an alert (>10 failures = alert)

Think of a rule as a recipe: the ingredients are your log fields, the cooking time is your time window, and the finished dish is the alert.

---

## Detection Logic Types

**1. Threshold Detection**
The simplest type. Count events and alert when a number is exceeded.

*Example:* More than 10 failed logins from the same IP address within 5 minutes → possible brute force attack.

*Strength:* Easy to write and understand.
*Weakness:* Attackers can slow down ("low and slow") to stay below the threshold.

---

**2. Sequence Detection (also called "chained" detection)**
Detects event A followed by event B within a time window. The sequence matters.

*Example:* Multiple failed logins (event A) followed by a successful login (event B) from the same IP within 30 minutes → possible credential stuffing attack (attacker eventually found a valid password).

*Strength:* Reduces false positives — the failed logins alone are not an alert, but success after failures is very suspicious.
*Weakness:* More complex to write; requires correlation across multiple events.

---

**3. Correlation Detection**
Links events from multiple, different data sources together to see the bigger picture.

*Example:* Phishing email received (email security log) + user clicks malicious link (email security log) + PowerShell executed on that user's machine 5 minutes later (EDR log) + new admin account created (Active Directory log) → this is a complete attack chain.

*Strength:* High-confidence alerts. When multiple sources agree, it's almost certainly real.
*Weakness:* Requires all data sources to be integrated into the SIEM.

---

**4. Anomaly Detection**
Compares current behavior to a learned **baseline** and alerts when there is a significant **deviation**.

*Example:* A user normally downloads 50 MB of files per day. Today they downloaded 15 GB at 2 AM. The rule doesn't look for a specific action — it flags the unusual volume.

*Strength:* Can catch novel attacks that don't match known signatures.
*Weakness:* Requires time to build a baseline (weeks/months). Generates false positives during unusual-but-legitimate events (end of quarter data exports, IT migrations).

---

## Writing a Detection Rule Step by Step

The professional workflow for creating a new detection rule:

1. **Hypothesis** — Start with an attacker behavior: "An attacker trying to guess passwords will generate many failed logins."
2. **Data Source** — Find the log that captures this: Azure AD sign-in logs, Windows Event ID 4625.
3. **Logic** — Write a query: filter for failed logins, group by source IP.
4. **Threshold** — Decide the number: alert on >10 failures in 5 minutes.
5. **Test** — Run the query against historical data. Are results reasonable?
6. **Deploy** — Enable the rule in the SIEM.
7. **Monitor** — Watch the first alerts. Are they real threats or noise?
8. **Tune** — Adjust the threshold, add exceptions for known-good sources.`,
    },

    // ── Reading 2: Sigma Rules ─────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "det-rules-r2",
      heading: "Sigma Rules: Vendor-Neutral Detection Format",
      content: `## The Problem Sigma Solves

Imagine you write a brilliant detection rule for password spray attacks in Splunk's query language (SPL). Your colleague uses Microsoft Sentinel (KQL). Another team uses Elastic SIEM (EQL). Three different languages, three rewrites of the same rule. That's wasted work — and detection coverage gaps when someone forgets to port a rule.

**Sigma** is a vendor-neutral, open-source detection rule format. You write a rule once in YAML format, then use converters to translate it into Splunk SPL, Microsoft Sentinel KQL, Elastic EQL, IBM QRadar AQL, and more. Think of it like a universal recipe card that any chef (SIEM platform) can follow.

Sigma is maintained by the open-source community and thousands of free rules are available at github.com/SigmaHQ/sigma — covering virtually every known attack technique in the MITRE ATT&CK framework.

---

## Sigma Rule Structure

A Sigma rule is a YAML file with these key sections:

\`\`\`yaml
title: Password Spray via Azure AD Sign-in Failures
id: 8f8a9d4e-1b2c-3d4e-5f6g-7h8i9j0k1l2m
status: stable
description: Detects multiple failed logins from the same IP address in a short
  time window, indicating a possible password spray attack against Azure AD.
references:
  - https://attack.mitre.org/techniques/T1110/003/
author: SOC Team
date: 2024/01/15
tags:
  - attack.credential_access
  - attack.t1110.003
logsource:
  product: azure
  service: signinlogs
detection:
  selection:
    ResultType: 50126              # Azure AD error code for invalid credentials
  filter:
    UserPrincipalName|endswith:
      - '@servicenow.com'          # Exclude service accounts from monitoring
  condition: selection and not filter | count(UserPrincipalName) by IPAddress > 10
  timeframe: 5m
falsepositives:
  - Users legitimately forgetting their passwords
  - Automated scripts with hardcoded old credentials
level: medium
\`\`\`

---

## Breaking Down the Key Sections

**\`logsource\`** — tells the converter which log type this rule applies to. "product: azure, service: signinlogs" means Azure AD sign-in logs. The converter knows how to find this data in each SIEM.

**\`detection\`** — the heart of the rule, with three parts:
- \`selection\`: what to match (ResultType 50126 = invalid credentials in Azure AD)
- \`filter\`: what to exclude (service accounts from servicenow.com)
- \`condition\`: the logic combining selection + filter + threshold

**\`condition\` syntax examples:**
- \`selection\` — match any event matching "selection"
- \`selection and not filter\` — match selection but exclude filter
- \`selection | count() > 10\` — match only when count exceeds 10
- \`event1 | near event2\` — event1 near event2 in time (sequence)

**\`level\`** — the rule's severity: informational / low / medium / high / critical.

**\`tags\`** — ATT&CK technique tags, used to track ATT&CK framework coverage.

---

## Sigma Rule for Password Spray — What It Detects

The rule above detects the **T1110.003 — Password Spraying** technique:
- An attacker tries one common password (like "Summer2024!") against many accounts
- Each account shows a ResultType 50126 (invalid credentials) in Azure AD
- The attacker uses the same IP address, hoping to stay below per-account lockout thresholds
- Our rule groups failures by IP: if one IP causes >10 failures in 5 minutes → alert

This is why the condition uses \`count(UserPrincipalName) by IPAddress\` — we count distinct usernames per IP, because spray attacks target many users from one IP (unlike brute force, which targets one user with many passwords).

---

## Converting Sigma to Your SIEM

Once you have a Sigma rule, tools like \`sigma-cli\` can convert it:

\`sigma convert -t splunk sigma_rule.yml\`  → Splunk SPL query
\`sigma convert -t sentinel sigma_rule.yml\` → Microsoft Sentinel KQL query

This means you can download hundreds of community Sigma rules and deploy them to your SIEM in minutes, instead of rewriting them from scratch.`,
    },

    // ── Reading 3: Tuning Methodology ─────────────────────────────────────
    {
      type: "reading" as const,
      id: "det-rules-r3",
      heading: "Alert Tuning: Reducing Noise Without Losing Coverage",
      content: `## The Alert Fatigue Problem

Picture a smoke detector so sensitive it goes off every time you make toast. You start ignoring it — and then when there's a real fire, you ignore that too. This is **alert fatigue**: when a SOC receives too many false alarms, analysts stop trusting the alerts, and real threats get missed.

According to industry surveys, SOC analysts receive an average of 1,000–10,000 alerts per day. Studies show that up to 50% of those alerts are false positives. Tuning is the practice of making your detection rules smarter — reducing noise while keeping real threat detection intact.

---

## Why False Positives Happen

**Rule too broad:** "Alert on any PowerShell execution" — but IT admins use PowerShell legitimately hundreds of times per day.

**Missing context:** "Alert on any file downloaded by PowerShell" — but the Windows Update service (svc-wsus) uses PowerShell to download patches from microsoft.com every night.

**No asset context:** "Alert on any admin login outside business hours" — but your on-call engineer legitimately logs in at 2 AM during an incident.

**Threshold too low:** "Alert if >3 failed logins" — but users forget passwords constantly, especially on Mondays.

---

## Tuning Methodology: Step by Step

**Step 1: Identify the false positive pattern**
When an alert fires that's clearly benign, ask: What makes this different from a real threat? Is it the user? The source hostname? The destination URL? The time of day?

**Step 2: Add an exception (allow list)**
Most SIEMs let you add exclusions:
- *User exception:* Exclude user "svc-wsus" from PowerShell download rule
- *IP exception:* Exclude the IT admin's IP range from outside-hours login rule
- *Hostname exception:* Exclude "WSUS-SERVER-01" from patch management alerts
- *URL exception:* Exclude microsoft.com/windows.com from suspicious download rules

**Step 3: Increase the threshold (carefully)**
If >3 failures is too sensitive, try >10 failures. But document why — you don't want to miss a slow attacker who tries exactly 9 times.

**Step 4: Add context to the condition**
Instead of "PowerShell downloaded a file" → try "PowerShell downloaded a file AND the file extension is .exe or .ps1 AND the source URL is not in the approved list."

---

## Risk-Based Alerting

Not all alerts need the same urgency. **Risk-based alerting** multiplies threat indicators together:

**Alert Priority = Severity × Asset Criticality × Confidence**

Example:
- Low confidence PowerShell alert on a developer's laptop = LOW priority
- Same alert on the Domain Controller = HIGH priority (critical asset)
- Same alert, but with known-malicious IP = CRITICAL (high confidence)

This means the same detection rule can generate different priority alerts depending on who it fires for.

---

## Measuring Rule Quality

Good detection rules have measurable quality metrics:

**True Positive Rate (TPR) / Recall:** Of all real attacks, what % did the rule catch? (Higher = better coverage)

**False Positive Rate (FPR):** Of all alerts, what % were false alarms? (Lower = less noise)

**Precision:** Of all alerts, what % were real threats? (Higher = more trustworthy alerts)

The goal is **high precision AND high recall** — but these naturally conflict. Making a rule more sensitive catches more attacks (high recall) but also generates more false positives (low precision). Tuning is the art of finding the right balance.

---

## The Use Case Lifecycle

Detection rules are not "set and forget." They follow a lifecycle:

1. **Design** — Identify the attacker behavior (hypothesis)
2. **Build** — Write the rule
3. **Test** — Validate against historical data
4. **Deploy** — Enable in production
5. **Monitor** — Watch early alerts for noise
6. **Tune** — Add exceptions, adjust thresholds
7. **Retire** — Remove rules for retired data sources or superseded by better rules

Microsoft Sentinel provides built-in tuning recommendations — it uses machine learning to analyze your historical incidents and suggests specific entities (users, IPs, hostnames) to exclude from rules that repeatedly generate false positives.

---

## ATT&CK Coverage Mapping

A mature SOC tracks which ATT&CK techniques they have detection rules for. This is called **ATT&CK coverage mapping**. If your rules cover 150 of 600+ ATT&CK techniques, you have about 25% coverage — and you know exactly which techniques attackers could use undetected. This drives your detection engineering roadmap.`,
    },

    // ── Question 1 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "det-rules-q1",
      question:
        "An analyst notices that a password spray detection rule fires 200 times per day — mostly for users who forgot their passwords on Monday mornings. What is the BEST first step to reduce false positives?",
      options: [
        "Delete the rule entirely to stop the noise",
        "Add an exception list to exclude known IT helpdesk support tickets",
        "Investigate all 200 alerts manually every day",
        "Lower the threshold from 10 failures to 5 failures",
      ],
      answer: 1,
      explanation:
        "Adding an exception list (allow list) is the correct tuning approach. Monday-morning password resets after weekends are a well-known legitimate pattern. You can exclude specific user groups (e.g., users who opened a helpdesk ticket), or tune the threshold to be higher on Monday mornings. Deleting the rule entirely removes protection. Investigating all 200 alerts manually is unsustainable and defeats the purpose of automation. Lowering the threshold to 5 would make it even noisier, not less.",
      xp: 30,
    },

    // ── Question 2 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "det-rules-q2",
      question:
        "A SOC detection rule fires when: (1) a user receives a phishing email, AND (2) that same user runs PowerShell within 10 minutes. Which detection logic type does this represent?",
      options: [
        "Threshold detection",
        "Anomaly detection",
        "Sequence detection",
        "Signature detection",
      ],
      answer: 2,
      explanation:
        "This is sequence detection (also called chained detection). It requires event A (phishing email received) to be followed by event B (PowerShell execution) within a time window. The sequence matters — PowerShell alone is not an alert, and a phishing email alone is not an alert, but the combination in sequence is a high-confidence indicator of compromise.",
      xp: 30,
    },

    // ── Question 3 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "det-rules-q3",
      question:
        "What is the main advantage of writing detection rules in Sigma format instead of directly in your SIEM's native query language?",
      options: [
        "Sigma rules run faster than native SIEM queries",
        "Sigma rules are encrypted and cannot be stolen by attackers",
        "Sigma rules are vendor-neutral and can be converted to any SIEM platform's query language",
        "Sigma rules automatically block attacks without analyst review",
      ],
      answer: 2,
      explanation:
        "Sigma's key benefit is vendor neutrality. A rule written in Sigma YAML can be converted to Splunk SPL, Microsoft Sentinel KQL, Elastic EQL, IBM QRadar AQL, and many other formats using conversion tools. This means you can share detection logic across teams with different SIEMs, use community rules from SigmaHQ without rewriting them, and migrate SIEM platforms without losing your detection library.",
      xp: 30,
    },

    // ── Log Analysis: EDR Alert — Tuning Scenario ─────────────────────────
    {
      type: "log_analysis" as const,
      id: "det-rules-la1",
      heading: "Analyze This EDR Alert: Real Threat or False Positive?",
      context:
        "Your EDR (Endpoint Detection & Response) system fired an alert titled 'Suspicious PowerShell Download'. The rule triggers whenever PowerShell downloads a file from the internet. Examine the alert details below and determine whether this is a real threat or a false positive that needs tuning.",
      event: {
        id: "evt-det-rules-001",
        ts: "2025-06-24T02:14:33Z",
        source: "edr" as const,
        event_type: "edr_alert" as const,
        severity: "high" as const,
        hostname: "WSUS-SERVER-01",
        user_email: "svc-wsus@corp.com",
        description: "PowerShell downloading file from internet",
        mitre_technique: "T1059.001",
        raw: {
          "rule.name": "Suspicious PowerShell Download",
          "rule.level": "10",
          "rule.description":
            "PowerShell downloading file from internet — possible malware dropper or C2 staging",
          "data.cmdline":
            "powershell.exe -Command Invoke-WebRequest -Uri https://updates.microsoft.com/kb123456.msp -OutFile C:\\Windows\\Temp\\update.msp",
          "data.user": "svc-wsus",
          "data.hostname": "WSUS-SERVER-01",
          "data.process.parent": "wuauserv.exe",
          "data.file.extension": ".msp",
          "data.network.dst_domain": "updates.microsoft.com",
          "rule.groups": ["powershell", "download", "network"],
          "alert.context":
            "svc-wsus is the Windows Server Update Services service account. WSUS-SERVER-01 is the internal patch management server. It downloads Microsoft patches nightly at 02:00 UTC.",
        },
      } as TelemetryEvent,
      questions: [
        {
          question:
            "Looking at the user ('svc-wsus'), hostname ('WSUS-SERVER-01'), destination domain ('updates.microsoft.com'), and time (02:14 UTC), what is your assessment of this alert?",
          options: [
            "Critical threat — PowerShell downloading .msp files is always malicious",
            "False positive — this is the Windows Update service downloading a legitimate Microsoft patch on the patch management server",
            "Needs escalation — the .msp file extension is highly suspicious",
            "False positive but acceptable — no action needed since it happens at night",
          ],
          answer: 1,
          explanation:
            "This is a classic false positive. All the context indicators point to legitimate activity: svc-wsus is the Windows Update Service Account (not a human user), WSUS-SERVER-01 is the dedicated patch management server (as named), updates.microsoft.com is Microsoft's legitimate update domain, the parent process is wuauserv.exe (Windows Update service), and the timing (02:14 AM) matches the nightly patch download schedule. The rule is correct to flag 'PowerShell download' generically, but it lacks context awareness.",
          xp: 40,
        },
        {
          question:
            "What specific change should you make to this detection rule to prevent this false positive from recurring, while still catching real malicious PowerShell downloads?",
          options: [
            "Delete the rule — it produces too many false positives",
            "Change the severity from High to Low",
            "Add an exception to exclude user 'svc-wsus' AND hostname 'WSUS-SERVER-01' AND destination domain 'updates.microsoft.com'",
            "Increase the detection threshold to only alert after 100 download attempts",
          ],
          answer: 2,
          explanation:
            "The correct tuning approach is to add a specific exception (allow list entry) that excludes this exact legitimate combination: service account 'svc-wsus' on host 'WSUS-SERVER-01' downloading from 'updates.microsoft.com'. Using all three conditions together prevents attackers from abusing the exception — they would need to be on that specific machine, using that specific account, AND downloading from Microsoft's domain. Never use broad exceptions like 'exclude all PowerShell' or 'exclude svc-wsus everywhere'.",
          xp: 40,
        },
      ],
    },

    // ── Question 4 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "det-rules-q4",
      question:
        "In the context of detection rule quality, what does 'True Positive Rate' (also called Recall) measure?",
      options: [
        "The percentage of alerts that are real threats (precision)",
        "The percentage of real attacks that the rule successfully detected",
        "The number of alerts generated per hour",
        "The speed at which the rule processes log events",
      ],
      answer: 1,
      explanation:
        "True Positive Rate (Recall) = of all real attacks that actually occurred, what percentage did the rule catch? A 100% TPR means no attacks went undetected. Note this is different from Precision, which measures 'of all alerts fired, what percentage were real threats?'. A good rule has high precision (low false positive rate) AND high recall (low miss rate) — but tuning for one often trades off against the other.",
      xp: 30,
    },

    // ── Question 5 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "det-rules-q5",
      question:
        "Which MITRE ATT&CK technique does a 'Password Spray' attack fall under?",
      options: [
        "T1078 — Valid Accounts",
        "T1110.001 — Password Guessing",
        "T1110.003 — Password Spraying",
        "T1566 — Phishing",
      ],
      answer: 2,
      explanation:
        "Password Spraying is specifically categorized as T1110.003 in the MITRE ATT&CK framework. T1110 is the parent technique 'Brute Force', with sub-techniques: .001 Password Guessing (many passwords, one account), .002 Password Cracking (offline hash cracking), .003 Password Spraying (one password, many accounts), and .004 Credential Stuffing (username:password pairs from breaches). Spraying avoids account lockouts by trying only 1-3 passwords per account.",
      xp: 30,
    },

    // ── Flag Task ─────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "det-rules-flag1",
      prompt:
        "You are tuning a detection rule for PowerShell downloads. The rule keeps firing on the WSUS server downloading Microsoft patches. What is the standard term for the configuration you add to a detection rule to prevent specific known-good activity from triggering an alert? (Two common equivalent terms are accepted — enter either one.)",
      answer: "exception list",
      hint: "It's sometimes also called a 'whitelist' or 'allow list'. You're telling the rule: 'I already know about this activity, and it is safe — ignore it.'",
      xp: 50,
    },
  ],
};

// ─── Room 2: Log Sources & SIEM Integration ───────────────────────────────────

const logSourcesIntegrationRoom = {
  id: "log-sources-integration",
  title: "Log Sources & SIEM Integration",
  description:
    "Understand where security logs come from, how they travel to your SIEM, and what happens when they arrive — parsing, normalization, and integration challenges.",
  difficulty: "intermediate" as const,
  category: "SIEM",
  estimatedMinutes: 45,
  xp: 250,
  icon: "🔌",
  prerequisites: ["log-management"],
  tasks: [
    // ── Reading 1: Log Sources & Transport Formats ─────────────────────────
    {
      type: "reading" as const,
      id: "log-src-r1",
      heading: "Log Sources & Transport Protocols: Where Logs Come From",
      content: `## The Security Data Universe

Your SIEM is only as good as what feeds it. Before you can detect threats, you need to collect logs from every relevant corner of your organization's environment. Security logs come from six major categories of sources:

**Endpoint logs** — workstations, laptops, servers. Windows Event Logs (Security, System, Application), PowerShell logs, process execution logs from EDR tools like CrowdStrike or Microsoft Defender.

**Network logs** — firewalls, routers, switches, proxies, IDS/IPS systems. These record traffic flows, blocked connections, and detected signatures.

**Identity logs** — Active Directory, Azure Entra ID, Okta, LDAP. Who authenticated, when, from where, and whether it succeeded.

**Cloud logs** — AWS CloudTrail, Azure Activity Log, GCP Audit Logs. API calls, resource creation/deletion, configuration changes in cloud environments.

**Application logs** — web servers (Apache/Nginx access logs), databases (SQL audit logs), business applications (ERP, CRM). Custom application events.

**Security tool logs** — your EDR, AV, DLP, WAF, email security, and vulnerability scanner all generate their own alerts and events.

---

## Log Transport Protocols

Once a log exists, it needs to travel to your SIEM. The three classic protocols are:

**Syslog (UDP/TCP port 514)**
The original Unix logging standard, born in 1980. Syslog is the most universal protocol — virtually every network device (firewalls, switches, routers) and Unix/Linux system supports it. A Syslog message has three parts:
- **PRI** (Priority): a number encoding Facility (what type of system generated this) × Severity (how urgent)
- **Header**: timestamp and hostname
- **MSG**: the actual log content

RFC 3164 (older "BSD Syslog") and RFC 5424 (modern structured Syslog) are the two standards. Many vendors implement their own flavor of Syslog, making parsing challenging.

*Syslog weakness:* UDP Syslog has no delivery guarantee — if your SIEM is overloaded, log messages are simply dropped. TCP Syslog is more reliable.

---

**CEF — Common Event Format**
Developed by ArcSight (HP), now the dominant standard for security appliances. CEF messages are always sent over Syslog, but with a standardized structure inside the message body:

\`CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|Extension\`

Real example from a Palo Alto firewall:
\`CEF:0|Palo Alto Networks|PAN-OS|10.1|threat|general|7|rt=2025-06-24T14:32:11Z src=185.220.101.45 dst=10.0.1.50 spt=54321 dpt=22 proto=TCP act=block cs1=block-ssh-brute cs1Label=RuleName\`

Breaking it down:
- \`CEF:0\` — CEF format version 0
- \`Palo Alto Networks\` — vendor
- \`PAN-OS\` — product
- \`10.1\` — product version
- \`threat\` — event class (threat detected)
- \`general\` — event name
- \`7\` — severity (0-10 scale)
- Extension fields: \`rt\` (receive time), \`src\` (source IP), \`dst\` (destination IP), \`spt\` (source port), \`dpt\` (destination port), \`proto\` (protocol), \`act\` (action), \`cs1\` (custom string 1 = rule name)

CEF has a fixed set of standard fields plus custom extension fields (cs1-cs6, cn1-cn3, etc.). The \`cs1Label\` field tells you what \`cs1\` means.

---

**LEEF — Log Event Extended Format**
IBM QRadar's equivalent to CEF. Same idea — structured format over Syslog — but different syntax. LEEF uses tabs as field separators and has slightly different field naming.

---

**JSON over HTTPS**
Modern cloud services (Azure, AWS, Okta, Office 365) deliver logs via REST APIs in JSON format. Instead of Syslog, your SIEM polls an API endpoint or receives a webhook, and the log arrives as a JSON object. This is increasingly the dominant format for cloud-native security logs.`,
    },

    // ── Reading 2: Collection Agents & Pipelines ───────────────────────────
    {
      type: "reading" as const,
      id: "log-src-r2",
      heading: "Log Collection Agents & Processing Pipelines",
      content: `## Why You Need a Collection Agent

Raw logs sit on the machine that generated them. To get them to your centralized SIEM, you need something to pick them up and send them over the network. Enter **log collection agents** — lightweight software installed on source systems or on dedicated log aggregator servers.

Think of agents like postal workers: the log is the letter, the agent picks it up from the mailbox (log file or event channel) and delivers it to the central sorting office (SIEM).

---

## Major Log Collection Agents

**Winlogbeat (Elastic)**
Specifically designed to ship Windows Event Logs to Elasticsearch or OpenSearch (the Elastic SIEM stack). It reads from Windows Event Log channels (Security, System, Application, PowerShell, Sysmon) and forwards them over HTTPS. Configuration is simple: specify which channels to monitor and where to send them.

*Use case:* Collecting Windows Security Event logs (Event ID 4624 logins, 4625 failures, 4688 process creation) for a SOC.

---

**Filebeat (Elastic)**
A more general-purpose agent from the same Elastic family. Instead of reading Windows Event channels, it tails log files — any text file written by any application. It can parse Apache access logs, Nginx logs, application logs, syslogs, and hundreds more via pre-built modules.

*Use case:* Shipping web server access logs or Linux auth logs (/var/log/auth.log) to Elastic SIEM.

---

**NXLog**
A universal log shipper for both Windows and Linux. More feature-rich than Winlogbeat/Filebeat — it can receive Syslog, read Windows Event Logs, parse custom log formats, convert between formats (e.g., Windows events → CEF), and forward to multiple destinations simultaneously.

*Use case:* Organizations with mixed Windows/Linux/network device environments. Often used to receive Syslog from network devices and forward to a SIEM.

---

**Fluentd and Logstash**
These are **log pipeline** tools rather than simple shippers — they collect, parse, filter, enrich, and route logs.

- **Logstash** (part of the Elastic Stack) reads logs, applies grok patterns to parse unstructured text into structured fields, enriches with GeoIP data, and outputs to Elasticsearch.
- **Fluentd** is a CNCF open-source alternative, popular in Kubernetes environments.

*Use case:* When you need to transform logs — normalize timestamps, extract fields from log messages, add geographic information to IP addresses, route different log types to different destinations.

---

**Wazuh Agent**
A multi-purpose security agent that does more than just collect logs. It performs:
- Log collection (Windows, Linux, macOS)
- File Integrity Monitoring (FIM) — alerts when files are modified
- Security Configuration Assessment (SCA) — checks system security settings
- Active Response — can automatically block IPs or terminate processes

*Use case:* Open-source SOC environments that want an integrated log collection + lightweight EDR capability.

---

## Microsoft Sentinel Data Connectors

Microsoft Sentinel has 200+ built-in data connectors that simplify integration:
- **Native connectors**: Azure AD, Office 365, Microsoft Defender — one click to enable, no agent required
- **CEF connector**: Install the Log Analytics agent on a Linux server that acts as a Syslog/CEF collector; network devices send to this server, which forwards to Sentinel
- **API-based connectors**: Pull logs from cloud services (AWS CloudTrail, Okta, Salesforce) via scheduled API polling
- **Custom connectors**: Send any data via the Log Analytics Data Collector API in JSON format

---

## The Log Pipeline Flow

End-to-end, a log's journey looks like this:

1. **Event occurs** on source system (login attempt, file downloaded, network connection)
2. **Log written** to local log file or Windows Event Log channel
3. **Agent reads** the log and forwards it (Syslog, CEF, JSON, or proprietary protocol)
4. **Collector/aggregator** receives the log (optional intermediate step for high-volume environments)
5. **Parser** processes the raw log message and extracts structured fields
6. **Enrichment** adds context: GeoIP lookup on the source IP, asset inventory lookup for the hostname
7. **SIEM indexes** the structured, enriched log event for searching and rule evaluation
8. **Detection rules** run against the indexed data and generate alerts`,
    },

    // ── Reading 3: Parsing, Normalization & Integration ────────────────────
    {
      type: "reading" as const,
      id: "log-src-r3",
      heading: "Parsing, Normalization & Integration Challenges",
      content: `## The Normalization Problem

Here's a real-world headache for every SOC engineer: you have three security products all logging the same concept — "source IP address." But they each call it something different:

- Palo Alto firewall: \`src\`
- Cisco ASA: \`srcip\`
- Fortinet FortiGate: \`srcip\` or \`src_ip\`
- Windows Security Event: \`IpAddress\`
- Elastic Common Schema (ECS): \`source.ip\`
- AWS CloudTrail: \`sourceIPAddress\`

If you want to search across all these sources at once (e.g., "find all events from IP 185.220.101.45"), you'd need to remember every vendor's field name. That's impossibly complex.

**Normalization** solves this by mapping all these vendor-specific field names to a common schema. Popular schemas include:
- **Elastic Common Schema (ECS)** — used in Elasticsearch/Kibana
- **Open Cybersecurity Schema Framework (OCSF)** — industry consortium standard
- **Sentinel ASIM (Advanced Security Information Model)** — Microsoft's normalization layer

After normalization, every log from every vendor has \`source.ip\`, \`destination.ip\`, \`user.name\`, \`event.action\`, etc. — the same field names regardless of source.

---

## Common Parsing Challenges

**Multi-line events**: Some logs span multiple lines (Java stack traces, Windows EVTX XML format). The parser must know where one event ends and the next begins.

**Timestamps without timezone**: "2025-06-24 14:32:11" — is that UTC? EST? Local server time? If you ingest logs from servers in different time zones without normalizing to UTC, your timeline analysis will be wrong. Always standardize to UTC at ingestion time.

**Character encoding issues**: Logs may contain non-ASCII characters (special characters in usernames, file paths with spaces). Encoding mismatches cause corrupt log entries.

**Escaped characters in strings**: A log message containing quotes, backslashes, or commas can break simple parsers. The CEF format, for example, requires escaping \`|\`, \`=\`, and \`\\\` characters.

**Vendor-specific severity scales**: Palo Alto uses 1-5 (informational/low/medium/high/critical). CEF uses 0-10. Windows uses 0-16 (Level field). Syslog uses 0-7 (Emergency through Debug). Your SIEM must map all of these to a common severity scale.

---

## Integration Testing: Verifying Logs Flow Correctly

After setting up a new log source integration, you must verify it works:

1. **Check the log count**: In your SIEM, query for events from the new source. Do you see the expected volume?

2. **Check field parsing**: Pick a sample event and verify the key fields (source IP, destination IP, user, action) are extracted correctly — not buried in the raw message.

3. **Check timestamps**: Verify the event timestamp in the SIEM matches the original event time. Timezone issues are a common problem.

4. **Check coverage**: Simulate or find a known event type and verify it appears in the SIEM. For example, generate a failed login and confirm it appears within 5 minutes.

5. **Check gaps**: Look for "dead hours" — periods with zero events from the source when you'd expect activity. This may indicate connectivity issues, agent crashes, or buffer overflows.

---

## Integration Verification: The Test Event Method

For firewall integrations, many SOC engineers use a "canary" technique:
1. Create a firewall rule that blocks a specific test IP
2. Attempt a connection from that IP
3. Verify the block event appears in the SIEM within 60 seconds

If the test event appears: integration is working. If not: check the agent status, network connectivity between the device and the collector, firewall rules on the Syslog port (514 UDP/TCP), and SIEM parsing rules.`,
    },

    // ── Question 1 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "log-src-q1",
      question:
        "Which log transport format uses this structure: 'CEF:Version|Vendor|Product|Version|EventClassID|Name|Severity|Extension'?",
      options: [
        "Syslog RFC 5424",
        "Common Event Format (CEF)",
        "Log Event Extended Format (LEEF)",
        "JSON over HTTPS",
      ],
      answer: 1,
      explanation:
        "CEF (Common Event Format) uses exactly this pipe-delimited header structure, developed by ArcSight. The header has 7 fixed pipe-separated fields (version, vendor, product, product version, event class ID, event name, severity), followed by the extension section containing key=value pairs. CEF messages are typically transported over Syslog (UDP/TCP 514). LEEF is IBM QRadar's competing format with tab-separated fields. RFC 5424 Syslog has its own structured data format using bracket notation.",
      xp: 30,
    },

    // ── Question 2 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "log-src-q2",
      question:
        "Why is log normalization important in a SIEM that receives logs from multiple vendors?",
      options: [
        "It encrypts logs to protect sensitive data",
        "It compresses logs to save storage space",
        "It maps vendor-specific field names to a common schema so logs can be searched and correlated across sources using the same field names",
        "It automatically deletes logs older than 90 days to meet compliance requirements",
      ],
      answer: 2,
      explanation:
        "Normalization solves the field naming inconsistency problem. Palo Alto calls the source IP 'src', Cisco calls it 'srcip', Windows calls it 'IpAddress', and ECS calls it 'source.ip'. Without normalization, you'd need to write queries with every vendor's field name. With normalization, all sources use 'source.ip' and you can search across all vendors at once. This is essential for correlation rules that span multiple log sources.",
      xp: 30,
    },

    // ── Question 3 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "log-src-q3",
      question:
        "A Windows endpoint is generating Security Event Logs that you want to ship to an Elasticsearch SIEM. Which agent is purpose-built for this task?",
      options: [
        "Fluentd — it is the most popular log shipper for Windows",
        "Winlogbeat — specifically designed to ship Windows Event Logs to Elastic/OpenSearch",
        "NXLog — it is the only agent that reads Windows Event Logs",
        "Logstash — it reads Windows Event Logs and parses them",
      ],
      answer: 1,
      explanation:
        "Winlogbeat is specifically designed by Elastic to read Windows Event Log channels (Security, System, Application, PowerShell, Sysmon) and ship them to Elasticsearch or OpenSearch. It's the purpose-built tool for this exact use case. While NXLog and Logstash can also handle Windows Event Logs, Winlogbeat is the right tool for this specific scenario. Fluentd is more common in Linux/container environments, and Logstash is a pipeline processor (it typically receives from an agent like Winlogbeat, not directly from Windows Event Logs).",
      xp: 30,
    },

    // ── Log Analysis: CEF Firewall Log ─────────────────────────────────────
    {
      type: "log_analysis" as const,
      id: "log-src-la1",
      heading: "Parse This CEF Log: Palo Alto Firewall",
      context:
        "A Palo Alto Networks firewall is configured to send its threat logs to your SIEM via Syslog in CEF format. The following raw log arrived at your Syslog collector. Your task is to parse the CEF fields and answer questions about the event.",
      event: {
        id: "evt-log-src-001",
        ts: "2025-06-24T14:32:11Z",
        source: "siem" as const,
        event_type: "edr_alert" as const,
        severity: "high" as const,
        hostname: "palo-alto-01",
        src_ip: "185.220.101.45",
        dst_ip: "10.0.1.50",
        description: "SSH brute force blocked by firewall — CEF format log",
        raw: {
          message:
            "CEF:0|Palo Alto Networks|PAN-OS|10.1|threat|general|7|rt=2025-06-24T14:32:11Z src=185.220.101.45 dst=10.0.1.50 spt=54321 dpt=22 proto=TCP act=block cs1=block-ssh-brute cs1Label=RuleName",
          "log.source": "syslog",
          "syslog.hostname": "palo-alto-01",
          "log.format": "CEF",
          "cef.version": "0",
          "cef.device_vendor": "Palo Alto Networks",
          "cef.device_product": "PAN-OS",
          "cef.device_version": "10.1",
          "cef.event_class_id": "threat",
          "cef.name": "general",
          "cef.severity": "7",
        },
      } as TelemetryEvent,
      questions: [
        {
          question:
            "Looking at the raw CEF message, what action did the firewall take on this connection?",
          options: [
            "allow — the connection was permitted",
            "block — the connection was denied",
            "reset — the connection was terminated after being established",
            "monitor — the connection was logged but not blocked",
          ],
          answer: 1,
          explanation:
            "The CEF extension field 'act=block' tells us the firewall action was 'block'. In CEF format, 'act' is the standard field for 'device action'. The firewall blocked the connection from external IP 185.220.101.45 to internal server 10.0.1.50 on destination port 22 (SSH). The rule that triggered is named 'block-ssh-brute' (from cs1=block-ssh-brute, cs1Label=RuleName), confirming this is a brute force blocking rule.",
          xp: 40,
        },
        {
          question:
            "In the CEF format, what does the 'cs1' field represent, and how do you know what it means?",
          options: [
            "cs1 is the source country — it is always the country of the source IP",
            "cs1 is a custom string field — the 'cs1Label=RuleName' field tells you that in this log, cs1 contains the firewall rule name",
            "cs1 is the CEF severity level — values 1 through 10",
            "cs1 is always the username of the user who triggered the event",
          ],
          answer: 1,
          explanation:
            "CEF supports up to 6 custom string fields (cs1 through cs6) whose meaning varies by vendor and event type. The corresponding 'cs1Label' field exists specifically to tell the reader what cs1 contains in this particular log. Here, cs1Label=RuleName means cs1 contains the firewall rule name, which is 'block-ssh-brute'. This pattern (csN + csNLabel) is a core part of CEF design — you always check the Label field to understand what the numbered custom field means.",
          xp: 40,
        },
      ],
    },

    // ── Flag Task ─────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "log-src-flag1",
      prompt:
        "Parse the CEF message below and find the destination port number:\n\n`CEF:0|Palo Alto Networks|PAN-OS|10.1|threat|general|7|rt=2025-06-24T14:32:11Z src=185.220.101.45 dst=10.0.1.50 spt=54321 dpt=22 proto=TCP act=block cs1=block-ssh-brute cs1Label=RuleName`\n\nThe destination port (dpt) is the port on the TARGET server that the attacker was trying to connect to. Enter just the number.",
      answer: "22",
      hint: "In CEF extension fields, 'dpt' stands for destination port. Look for 'dpt=<number>' in the extension section after the 7th pipe character.",
      xp: 50,
    },

    // ── Question 4 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "log-src-q4",
      question:
        "Your SIEM receives Syslog events from a Linux server in Tokyo. The log timestamps show '14:30:00' but the analyst in London (UTC) needs accurate timeline analysis. What is the best practice for handling timestamps in log ingestion?",
      options: [
        "Leave timestamps as-is — the analyst should manually add the time difference",
        "Delete the timestamp from the log and use the time the SIEM received it",
        "Normalize all timestamps to UTC at the point of ingestion, preserving the original timezone information in a separate field",
        "Ignore timestamps — they are not important for security analysis",
      ],
      answer: 2,
      explanation:
        "Normalizing all timestamps to UTC at ingestion is the industry best practice. Security analysis — especially for correlation across sources — requires a single consistent time reference. If server A in Tokyo is UTC+9 and server B in London is UTC+0, events need to be on the same timeline to detect that A's suspicious login happened 5 minutes before B's privilege escalation. Deleting timestamps loses forensic data. Manual adjustment is error-prone. Many SIEMs store the original timestamp in a raw field while normalizing the indexed timestamp to UTC.",
      xp: 30,
    },
  ],
};

// ─── Room 3: Microsoft 365 Security ──────────────────────────────────────────

const microsoft365SecurityRoom = {
  id: "microsoft-365-security",
  title: "Microsoft 365 Security",
  description:
    "Master the Microsoft 365 security ecosystem: Defender for Office 365, email security, audit logs, and the key SOC monitoring activities for M365 environments.",
  difficulty: "intermediate" as const,
  category: "Cloud Security",
  estimatedMinutes: 50,
  xp: 280,
  icon: "🏢",
  prerequisites: ["siem-fundamentals"],
  tasks: [
    // ── Reading 1: M365 Ecosystem & Secure Score ───────────────────────────
    {
      type: "reading" as const,
      id: "m365-sec-r1",
      heading: "Microsoft 365 Security Ecosystem & Secure Score",
      content: `## Why Microsoft 365 Security Matters to SOC Analysts

Microsoft 365 (M365) is the world's most widely used business productivity suite — hundreds of millions of people use Outlook email, SharePoint, Teams, OneDrive, and Word every day. For attackers, this makes M365 a high-value target. For SOC analysts, M365 is one of the most important environments to monitor because:

- Business Email Compromise (BEC) attacks cost billions annually and operate entirely through email
- Credential theft through phishing is the #1 initial access technique
- Data exfiltration often happens through SharePoint/OneDrive external sharing
- OAuth consent phishing exploits the M365 app permission model
- Admin account compromise gives attackers access to the entire organization

---

## The Microsoft Security Stack

Microsoft has built a comprehensive security ecosystem that integrates tightly with M365. As a SOC analyst, you'll encounter these products:

**Microsoft Defender for Office 365 (MDO)** — protects email (Outlook/Exchange) from phishing, malware, and business email compromise. Has two plans with different feature sets.

**Microsoft Defender for Endpoint (MDE)** — endpoint detection and response (EDR) for Windows, Mac, Linux, Android, iOS. Formerly "Microsoft Defender ATP."

**Microsoft Defender for Identity (MDI)** — monitors Active Directory Domain Controllers for identity-based attacks (Kerberoasting, Pass-the-Hash, DCSync).

**Microsoft Defender for Cloud Apps (MDCA)** — formerly Microsoft Cloud App Security (MCAS). Cloud Access Security Broker (CASB) that monitors SaaS app usage and data in the cloud.

**Microsoft Sentinel** — Microsoft's cloud-native SIEM/SOAR. Collects logs from all the above plus hundreds of third-party sources.

**Microsoft Entra ID (formerly Azure AD)** — identity platform, authentication, Conditional Access.

**Microsoft Purview** — compliance, data governance, information protection (DLP, sensitivity labels, audit logs).

The unified portal at **security.microsoft.com** (Microsoft Defender portal) brings incidents, alerts, and investigation tools for all these products together in one interface.

---

## Microsoft Secure Score

**Microsoft Secure Score** is a measurement of your organization's security posture, displayed as a number (e.g., 342/800). Think of it like a credit score for security — higher is better.

Secure Score works by evaluating your M365 configuration against best practices and awarding points for each recommendation you've implemented. Examples of Secure Score improvements:
- Enable MFA for all admin accounts (+10 points)
- Enable Safe Links in Defender for Office 365 (+15 points)
- Block legacy authentication protocols (+20 points)
- Enable Microsoft Defender for Endpoint on all devices (+30 points)

Each recommendation shows: current status, how many points it's worth, and step-by-step implementation instructions.

**Why it matters for SOC:** Secure Score gives you a prioritized list of security improvements. If your score is 30% and MFA is not enabled for admins, that's your highest-priority action — not because Microsoft said so, but because unprotected admin accounts are the most common path to total organizational compromise.

---

## The Microsoft 365 Defender Portal (security.microsoft.com)

Your primary SOC workspace for M365. Key sections:

**Incidents** — correlated alerts across all Defender products. An incident might combine: phishing email detected + user clicked the link + malware executed on endpoint + lateral movement detected. One incident, full attack story.

**Alerts** — individual alerts from each Defender product before they're correlated into incidents.

**Hunting** — advanced threat hunting with KQL queries across email, endpoint, identity, and cloud app data.

**Email & Collaboration** — email flow, quarantine management, attack simulation training.

**Threat Intelligence** — threat actor profiles, campaign information, vulnerability data.`,
    },

    // ── Reading 2: Defender for Office 365 & Email Security ───────────────
    {
      type: "reading" as const,
      id: "m365-sec-r2",
      heading: "Defender for Office 365: Email Security Deep Dive",
      content: `## Email: The #1 Attack Vector

Studies consistently show that 90%+ of cyberattacks begin with a phishing email. Email security is therefore one of the most critical controls in any organization's security stack. Microsoft Defender for Office 365 (MDO) is Microsoft's answer — a set of email security capabilities built directly into Exchange Online (M365's email service).

---

## MDO Plan 1 vs Plan 2

MDO comes in two licensing tiers:

**Plan 1 (included in M365 Business Premium):**
- Anti-phishing policies (impersonation protection)
- Anti-spam and anti-malware filtering
- Safe Attachments (attachment sandboxing)
- Safe Links (URL rewriting)
- Spoof intelligence

**Plan 2 (enterprise add-on or included in M365 E5):**
Everything in Plan 1, plus:
- Attack Simulator — lets you run phishing simulation campaigns against your own users to measure awareness
- Threat Trackers — track emerging threats specific to your organization
- Campaign Views — see the full picture of phishing campaigns targeting your organization
- Automated Investigation and Response (AIR)

---

## Safe Attachments: Sandboxing Email Attachments

When a user receives an email with an attachment, Safe Attachments checks it by:

1. **Routing the attachment to a cloud sandbox** — an isolated virtual machine
2. **Opening and executing the file** in the sandbox environment
3. **Observing behavior** — does it try to phone home? Download additional malware? Modify system files?
4. **Making a verdict**: clean / blocked / replaced

This process takes a few seconds to minutes. During that time, the email is held in the "detonation" queue. If clean, it's delivered normally. If malicious, it's blocked and the user receives a notification.

*Key insight:* Traditional antivirus checks file signatures (known patterns). Safe Attachments checks behavior — it can detect brand-new "zero-day" malware that has never been seen before because it watches what the file actually does.

---

## Safe Links: Time-of-Click URL Protection

Phishing emails often include links to malicious websites. Safe Links protects users in two ways:

1. **URL rewriting at delivery time**: The original URL (https://malicious.site/harvest) is replaced with an MDO-wrapped URL (https://safelinks.protection.outlook.com/?url=https://malicious.site/harvest...). The original URL is now hidden inside the wrapper.

2. **Time-of-click checking**: When the user clicks the link, the wrapper URL resolves to MDO's servers. MDO re-checks the destination URL at that moment — because sometimes URLs are legitimate when the email arrives but switch to malicious content later (this is called a "delayed detonation" attack). If the URL is now malicious, the user sees a warning page instead of the malicious site.

*Key log event:* When MDO Safe Links blocks a click, it generates a "URLClickBlocked" event in the audit log — critical for SOC investigation when a user reports they "clicked something suspicious."

---

## Anti-Phishing Policies: Impersonation Protection

MDO's anti-phishing policies specifically protect against:

**User impersonation**: An attacker sends email appearing to come from your CEO (e.g., from "ceo@corp-company.com" instead of "ceo@corp.com" — one character different). MDO compares display names and domains against your configured protected users list.

**Domain impersonation**: Protecting against typosquatted domains (corp-company.com, c0rp.com). MDO checks if the sender domain closely resembles your organization's domains.

**Spoof intelligence**: Legitimate emails often come from third-party services (payroll, marketing) on behalf of your domain. Spoof intelligence learns which external senders are legitimate and blocks impersonators.

---

## Email Quarantine

Emails that MDO determines are malicious or suspicious are placed in **quarantine** rather than delivered to the user's inbox. As a SOC analyst, you'll use quarantine to:
- Review quarantined emails to verify they're truly malicious
- Release false positives (legitimate emails incorrectly quarantined)
- Export message headers for forensic analysis
- Track who released what from quarantine (audit trail)

The quarantine is accessible at security.microsoft.com → Email & Collaboration → Review → Quarantine.`,
    },

    // ── Reading 3: M365 Audit Logs & SOC Monitoring ────────────────────────
    {
      type: "reading" as const,
      id: "m365-sec-r3",
      heading: "M365 Audit Logs & Key Operations to Monitor",
      content: `## The Unified Audit Log (UAL)

Microsoft 365 records security-relevant user and admin activities in the **Unified Audit Log (UAL)** — a single log stream that covers:

- Exchange Online (email): who sent, received, forwarded, deleted what
- SharePoint and OneDrive: file access, sharing, download
- Azure Active Directory / Entra ID: user creation, role assignments, sign-ins
- Microsoft Teams: chat messages, file sharing
- Microsoft Purview / Compliance: DLP policy matches, sensitivity label changes
- Admin activities: configuration changes, policy modifications

**Where to find it:** Microsoft Purview compliance portal (compliance.microsoft.com) → Audit → Audit search. Or via the Microsoft Graph API for programmatic access.

**Retention:** By default, audit logs are retained for 90 days (M365 E3/E5 plans can extend to 1 year or 10 years). This is critical for incident response — if an attacker was in your environment for 6 months and you only have 90 days of logs, you've lost evidence.

---

## Key M365 Operations SOC Analysts Monitor

**1. New-InboxRule — Email Forwarding Rules**
Operation name in the audit log: \`New-InboxRule\` or \`Set-InboxRule\`

This is one of the most critical signals for **Business Email Compromise (BEC)**. After compromising an email account, attackers create inbox rules to:
- Forward all incoming email to an external address (attacker-controlled)
- Delete forwarded emails so the victim doesn't notice
- Filter for emails containing "invoice," "payment," "wire transfer" — the attacker only forwards financially relevant emails

An inbox forwarding rule to an external email domain (ProtonMail, Gmail) should be treated as a high-priority alert.

---

**2. Add member to role — Admin Role Assignment**
Operation name: \`Add member to role\`

If an attacker compromises a regular user account and then adds that account (or a backdoor account they created) to the Global Administrator role, they have full control of the entire tenant. This operation should generate an immediate alert.

---

**3. MailItemsAccessed — Mass Email Read**
Operation name: \`MailItemsAccessed\`

Records every time mail items are accessed by a client. Useful for detecting attacker reconnaissance — if a compromised account suddenly accesses thousands of emails in an hour (far more than a human could read), that's a red flag.

Note: MailItemsAccessed is only available with Microsoft 365 E5 or E5 Compliance licensing.

---

**4. FileDownloaded — Bulk Data Download**
Operation name: \`FileDownloaded\`

Records SharePoint and OneDrive file downloads. A user downloading 500 files in 10 minutes is a data exfiltration indicator. Correlate with DLP alerts for sensitive files.

---

**5. Consent to application — OAuth App Consent**
Operation name: \`Consent to application\`

OAuth consent phishing is a sophisticated attack: the attacker sends a phishing email with a link to a legitimate-looking Microsoft app registration. When the victim clicks "Accept" to grant permissions, the attacker's malicious app gets access to the victim's email, contacts, and files — without needing the victim's password.

Alert on any OAuth app consent that grants high-permission scopes (Mail.Read, Files.ReadWrite.All, Mail.ReadWrite) — especially from external applications and non-admin users.

---

**6. Set-Mailbox (ForwardingSmtpAddress) — Server-Side Forwarding**
Different from inbox rules — this sets forwarding at the mailbox level (admin-level change). Silently copies all email to an external address. Attackers with admin access use this instead of inbox rules.

---

## M365 + Microsoft Sentinel Integration

Microsoft Sentinel's native Office 365 connector ingests audit log events automatically. Built-in analytics rules in Sentinel detect:
- Forwarding rules to external domains
- Mass file downloads
- Suspicious inbox rules (keyword filters like "invoice")
- Admin consent grants
- User account creation outside business hours

The Sentinel rule fires → creates an incident → analyst investigates → works the incident in the M365 Defender portal for remediation (disable account, remove forwarding rule, revoke app consent).`,
    },

    // ── Question 1 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "m365-sec-q1",
      question:
        "An attacker compromises a Finance Manager's M365 account. The first thing they do is create an inbox rule. What is the most likely purpose of this inbox rule in a Business Email Compromise (BEC) attack?",
      options: [
        "To set an out-of-office auto-reply to hide the compromise from the attacker",
        "To forward incoming emails about invoices and payments to an external attacker-controlled email address, while deleting the forwarded copies",
        "To change the Finance Manager's email signature to include the attacker's bank account details",
        "To block all incoming emails so the victim cannot receive security alerts",
      ],
      answer: 1,
      explanation:
        "In BEC attacks, attackers create inbox forwarding rules for two purposes: (1) to silently monitor the victim's email for financial conversations involving invoices, wire transfers, or payment requests, and (2) to delete forwarded copies so the victim doesn't see extra copies of emails and doesn't notice the compromise. The 'DeleteMessage: true' parameter in New-InboxRule events is a major red flag. This gives attackers the information they need to send realistic impersonation emails at exactly the right moment in a financial transaction.",
      xp: 30,
    },

    // ── Question 2 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "m365-sec-q2",
      question:
        "What does Microsoft Defender for Office 365 Safe Attachments do that traditional antivirus scanning cannot?",
      options: [
        "It scans attachments faster than traditional AV",
        "It opens and executes attachments in an isolated sandbox to observe behavior, detecting zero-day malware with no known signature",
        "It prevents all attachments from being delivered, regardless of content",
        "It encrypts all attachments to protect sensitive data in transit",
      ],
      answer: 1,
      explanation:
        "Traditional antivirus works by comparing file contents to a database of known malware signatures. It can't detect brand-new malware that isn't in the signature database (zero-day malware). Safe Attachments uses behavioral analysis — it actually runs the attachment in an isolated cloud sandbox and watches what it does. If the file tries to connect to a command-and-control server, download additional payloads, or modify system files — behaviors characteristic of malware — it's detected and blocked, even if no one has ever seen this specific malware before.",
      xp: 30,
    },

    // ── Question 3 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "m365-sec-q3",
      question:
        "A SOC analyst is investigating a suspected account compromise. Which M365 audit log operation would help them determine if the attacker accessed thousands of emails to gather intelligence after the compromise?",
      options: [
        "New-InboxRule — shows inbox rules the attacker created",
        "MailItemsAccessed — records every mail item access, revealing mass email reading activity",
        "FileDownloaded — shows files the attacker downloaded from SharePoint",
        "Add member to role — shows privilege escalation",
      ],
      answer: 1,
      explanation:
        "MailItemsAccessed records every access to mail items, including by REST API clients (which attackers often use to programmatically read email). Normally, a human reads maybe 50-100 emails per day. If MailItemsAccessed shows thousands of emails accessed within an hour by an API client from an unusual IP address, that's a strong indicator that an attacker is programmatically dumping the mailbox for intelligence. Note that MailItemsAccessed requires E5 licensing and must be enabled explicitly.",
      xp: 30,
    },

    // ── Log Analysis: M365 Inbox Rule Creation ─────────────────────────────
    {
      type: "log_analysis" as const,
      id: "m365-sec-la1",
      heading: "Analyze This M365 Audit Log: Suspicious Inbox Rule",
      context:
        "Your Microsoft Sentinel fired an alert: 'Inbox Forwarding Rule Created to External Domain'. The alert was triggered by a New-InboxRule operation in the Office 365 Unified Audit Log. Examine the event below to understand what happened.",
      event: {
        id: "evt-m365-001",
        ts: "2025-06-24T03:47:22Z",
        source: "o365" as const,
        event_type: "account_modify" as const,
        severity: "high" as const,
        user_email: "j.chen@corp.com",
        src_ip: "185.220.101.45",
        description:
          "New inbox forwarding rule created — mail being forwarded to external address with deletion of originals",
        mitre_technique: "T1114.003",
        vendor: "Microsoft 365 Unified Audit Log",
        raw: {
          "data.office365.Operation": "New-InboxRule",
          "data.office365.UserId": "j.chen@corp.com",
          "data.office365.ClientIPAddress": "185.220.101.45",
          "data.office365.Workload": "Exchange",
          "data.office365.ResultStatus": "True",
          "data.office365.OrganizationName": "corp.com",
          "data.office365.Parameters": [
            { Name: "ForwardTo", Value: "d.morrison1988@protonmail.com" },
            { Name: "DeleteMessage", Value: "true" },
            { Name: "Name", Value: "..." },
            { Name: "AlwaysDeleteOutlookRulesBlob", Value: "false" },
          ],
          "rule.description": "New-InboxRule operation detected",
          "rule.groups": ["exchange", "audit"],
          "geoip.country_name": "Russia",
          "geoip.city_name": "Moscow",
        },
      } as TelemetryEvent,
      questions: [
        {
          question:
            "This audit log shows a New-InboxRule was created by j.chen@corp.com. What two parameters make this rule particularly dangerous from a BEC perspective?",
          options: [
            "The rule name is '...' (hidden) and the workload is Exchange",
            "ForwardTo is set to an external ProtonMail address AND DeleteMessage is set to true — email silently forwarded and deleted",
            "The IP address is unusual and the operation happened in the middle of the night",
            "The OrganizationName is corp.com and the ResultStatus is True",
          ],
          answer: 1,
          explanation:
            "The two most dangerous parameters are (1) ForwardTo: d.morrison1988@protonmail.com — a ProtonMail address (anonymous, external) suggests attacker control rather than legitimate business forwarding, and (2) DeleteMessage: true — the rule deletes the original email after forwarding, meaning the account owner won't see duplicates in their inbox and may not notice the compromise. Together, these create a silent interception of all incoming email. The unusual IP and timing are additional suspicious indicators but are secondary to the rule parameters themselves.",
          xp: 40,
        },
        {
          question:
            "The source IP 185.220.101.45 is from Moscow, Russia. The user j.chen@corp.com is a Finance Manager who works in New York. What should the SOC analyst do FIRST?",
          options: [
            "Wait 24 hours to see if any financial damage occurs before acting",
            "Send j.chen@corp.com an email asking if they created this rule",
            "Immediately disable j.chen's account, revoke active sessions, remove the forwarding rule, and begin incident response — this is a confirmed BEC indicator",
            "Delete the forwarding rule only and close the alert as resolved",
          ],
          answer: 2,
          explanation:
            "This is a confirmed Business Email Compromise indicator requiring immediate response. The combination of: external login from Russia (impossible travel for a NYC employee), creation of a forwarding rule to a ProtonMail address with message deletion — this is the textbook BEC pattern. Immediate actions: (1) Disable the user account to lock out the attacker, (2) Revoke all active sessions (sign out all devices), (3) Remove the malicious inbox rule, (4) Reset the password, (5) Investigate what emails were forwarded. Emailing the compromised account risks alerting the attacker who is reading those emails. Waiting allows continued damage.",
          xp: 40,
        },
      ],
    },

    // ── Flag Task ─────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "m365-sec-flag1",
      prompt:
        "Examine the M365 audit log event above. An attacker set up email forwarding so that all of j.chen@corp.com's incoming email is secretly sent to the attacker. What is the external email address that mail is being forwarded to? (Enter the exact email address from the log)",
      answer: "d.morrison1988@protonmail.com",
      hint: "Look at the Parameters array in the raw log. Find the parameter with Name='ForwardTo' and read its Value field.",
      xp: 50,
    },

    // ── Question 4 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "m365-sec-q4",
      question:
        "What is 'OAuth consent phishing' in the context of Microsoft 365 attacks?",
      options: [
        "An attacker sends a phishing email that steals the victim's OAuth password through a fake login page",
        "An attacker tricks a user into granting permissions to a malicious OAuth application, which then has access to the user's M365 data without needing the user's password",
        "An attacker intercepts OAuth tokens in transit using a man-in-the-middle attack",
        "An attacker creates fake OAuth documentation to confuse developers",
      ],
      answer: 1,
      explanation:
        "OAuth consent phishing is particularly dangerous because it bypasses password theft entirely. The attacker registers a malicious application (legitimate-looking name like 'Microsoft Teams File Sync') in Azure AD, then sends a phishing link. When the victim clicks 'Accept' to grant app permissions, the app gains long-term API access to the victim's mailbox, files, and contacts — using the legitimate OAuth standard. The victim never enters their password. MFA does not prevent this attack. Detection requires monitoring 'Consent to application' operations in the audit log, especially for high-privilege scopes like Mail.ReadWrite or Files.ReadWrite.All.",
      xp: 30,
    },

    // ── Question 5 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "m365-sec-q5",
      question:
        "Microsoft Secure Score shows your organization at 35/100. Which of the following recommendations would be the HIGHEST security priority to implement first?",
      options: [
        "Enable the Microsoft Teams meeting lobby feature",
        "Require multi-factor authentication (MFA) for all administrator accounts",
        "Configure custom sensitivity labels for internal documents",
        "Enable the 'Do Not Forward' email option for all users",
      ],
      answer: 1,
      explanation:
        "Requiring MFA for administrator accounts is universally recognized as the single highest-impact security control. Administrator accounts have the power to modify security policies, create accounts, and access all data. A compromised admin account without MFA can lead to total tenant takeover. Microsoft's own research indicates that MFA blocks over 99.9% of automated credential-stuffing attacks. Secure Score heavily weights MFA for admins because the risk of unprotected admin accounts is so severe. Teams lobby features, sensitivity labels, and email options are all valuable but are lower priority than protecting the accounts with the most power.",
      xp: 30,
    },
  ],
};

// ─── Room 4: Entra ID (Azure AD) Security ────────────────────────────────────

const entraIdRoom = {
  id: "entra-id",
  title: "Entra ID (Azure AD) Security",
  description:
    "Master identity security monitoring with Microsoft Entra ID: understand Conditional Access, sign-in log analysis, Identity Protection, and common identity-based attack patterns.",
  difficulty: "intermediate" as const,
  category: "Identity",
  estimatedMinutes: 55,
  xp: 280,
  icon: "🆔",
  prerequisites: ["active-directory", "microsoft-365-security"],
  tasks: [
    // ── Reading 1: Entra ID Fundamentals ───────────────────────────────────
    {
      type: "reading" as const,
      id: "entra-r1",
      heading: "Entra ID Fundamentals: Cloud Identity vs On-Premises AD",
      content: `## What is Entra ID?

**Microsoft Entra ID** (formerly Azure Active Directory, Azure AD) is Microsoft's cloud-based identity and access management service. Think of it as the "cloud version" of the traditional Windows Active Directory that organizations have used for decades to manage who can log into what.

Every Microsoft 365 tenant has an Entra ID tenant behind it. When a user logs into Outlook on the web, Teams, SharePoint, or Azure — they're authenticating against Entra ID, not traditional on-premises Active Directory.

As of 2023, Microsoft rebranded "Azure Active Directory" to "Microsoft Entra ID." You'll see both names in documentation, security tools, and job descriptions — they refer to the same product.

---

## Entra ID vs On-Premises Active Directory: Key Differences

Understanding the differences helps you understand what threats apply to each environment:

| Feature | On-Premises Active Directory | Entra ID (Cloud) |
|---|---|---|
| **Primary protocol** | Kerberos + NTLM | SAML 2.0 / OpenID Connect (OIDC) / OAuth 2.0 |
| **Authentication flow** | Users authenticate to Domain Controllers | Users authenticate to Microsoft's cloud |
| **Attack surface** | Domain Controllers (DCSync, Pass-the-Hash, Kerberoasting) | Cloud endpoints (password spray, token theft, OAuth abuse) |
| **Management** | Group Policy (GPO), AD Users and Computers | Azure Portal, Microsoft Entra admin center |
| **Location** | Your own servers in your data center | Microsoft's global cloud infrastructure |
| **Join model** | Domain-joined machines | Azure AD Joined / Hybrid Joined / Registered |

**Hybrid environments** (the most common real-world setup) use both: on-premises AD for legacy systems and Entra ID for cloud services. Azure AD Connect (now "Microsoft Entra Connect") synchronizes user accounts between the two systems.

---

## Key Entra ID Concepts

**Tenant** — Your organization's dedicated Entra ID instance. It has a unique ID (GUID) and a primary domain (e.g., corp.onmicrosoft.com or corp.com). Everything in your Entra ID — users, groups, apps, policies — belongs to your tenant.

**Application Registration** — When you build or configure an application to use Entra ID for authentication, you create an App Registration. This gives the app a client ID, and you configure what permissions it needs to access M365 APIs.

**Service Principal** — The "instance" of an App Registration in a specific tenant. When you grant an enterprise app access to your tenant, a Service Principal is created. Service principals are used by automation, scripts, and background services to authenticate without a human user.

**Managed Identity** — A special type of Service Principal used by Azure resources (VMs, Functions, Logic Apps). The Azure platform manages the credential automatically — no password to steal, no secret to rotate. This is the modern secure way for Azure services to authenticate.

---

## Authentication Methods in Entra ID

Users can authenticate to Entra ID using multiple methods, ranging from least secure to most secure:

**Password only** — Basic username + password. Vulnerable to phishing, credential stuffing, brute force. Should not be used alone for sensitive access.

**Password + SMS OTP** — Adds a one-time code sent via text message. Better than password alone, but SMS can be intercepted or SIM-swapped.

**Microsoft Authenticator App (TOTP or Push)** — A dedicated authentication app on the user's phone. TOTP (Time-based One-Time Password) generates a 6-digit code that changes every 30 seconds. Push sends a push notification — "Approve this sign-in?" The push method is vulnerable to MFA fatigue attacks (see threats section).

**FIDO2 Security Keys** — Physical hardware keys (YubiKey, Titan Key). The highest security — requires physical possession of the key and is fully phishing-resistant. Cannot be stolen via a remote attack.

**Windows Hello for Business** — Biometric authentication (fingerprint, face recognition) tied to the specific device. Phishing-resistant because authentication is device-bound.

**Passwordless Phone Sign-In** — Open the Authenticator app, tap your account, use fingerprint or PIN. No password ever entered = nothing to phish.

For SOC analysts, the authentication method matters when investigating an incident. A sign-in protected by FIDO2 is almost certainly legitimate (attacker would need the physical key). A sign-in with just a password is much easier to fake.`,
    },

    // ── Reading 2: Conditional Access & Sign-in Logs ───────────────────────
    {
      type: "reading" as const,
      id: "entra-r2",
      heading: "Conditional Access Policies & Authentication Flow",
      content: `## What is Conditional Access?

Imagine your office building has a security checkpoint. A regular employee just shows their badge and walks in. But if someone arrives at 3 AM, or arrives from an unfamiliar country, or is trying to access the server room — they might need to show additional ID or get approval.

**Conditional Access (CA)** is Entra ID's equivalent: smart, context-aware authentication policies that decide how much proof of identity someone must provide based on the circumstances of their sign-in attempt.

Traditional access control says: "If you have a password, you're in." Conditional Access says: "If you have a password AND your device is compliant AND you're signing in from the US AND it's business hours → you're in. Otherwise → require MFA OR block the sign-in."

---

## Conditional Access: Conditions and Controls

A Conditional Access policy has two parts: **Conditions** (when it applies) and **Grant Controls** (what it requires).

**Conditions (triggers):**
- **User or group**: Apply to all users, specific users, or specific groups (e.g., all Finance users)
- **Application**: Apply when accessing specific apps (e.g., only when signing into Salesforce)
- **Location**: IP address ranges or named locations (e.g., corporate offices). Block sign-ins from high-risk countries.
- **Device platform**: Windows, iOS, Android, macOS
- **Device compliance**: Require Intune-managed and compliant devices
- **Sign-in risk**: Integration with Entra ID Protection — apply stricter controls when risk is Medium or High
- **User risk**: If Entra ID Protection flags a user as a risky user

**Grant Controls (what to require):**
- **Require MFA** — force multi-factor authentication
- **Require compliant device** — require the device to be enrolled in Intune and meet security policies
- **Require Hybrid Azure AD Joined device** — require the device to be joined to both on-prem AD and Entra ID
- **Block access** — deny access entirely (used for high-risk locations or non-compliant states)
- **Require terms of use** — force acknowledgment of acceptable use policy

**Session Controls:**
- Sign-in frequency (require re-authentication every X hours)
- Persistent browser session (allow/deny staying signed in)

---

## Real-World Conditional Access Policy Examples

**Policy 1: "Require MFA for all external sign-ins"**
- Condition: All users, all apps, location = NOT corporate IP ranges
- Grant: Require MFA

*Effect:* Employees in the office can sign in with password only (trusted network). Working from home or a coffee shop requires MFA.

**Policy 2: "Block legacy authentication"**
- Condition: All users, all apps, client apps = Exchange ActiveSync / Other clients (legacy)
- Grant: Block

*Effect:* Old email clients (Outlook 2010, some IMAP clients) that don't support MFA are blocked. This closes a huge attack surface — attackers love legacy authentication because MFA can't be enforced on it.

**Policy 3: "Require compliant device for high-value data access"**
- Condition: Finance group, SharePoint + OneDrive apps
- Grant: Require compliant device

*Effect:* Finance users can only access financial data from company-managed, compliant devices. Personal phones or unmanaged laptops are blocked.

---

## Entra ID Sign-In Logs: What They Capture

The sign-in logs at Entra admin center → Monitoring → Sign-in logs are one of the most important data sources for SOC analysts investigating identity threats. Each sign-in record captures:

**Identity fields:**
- \`UserPrincipalName\` — who signed in (email@corp.com)
- \`UserId\` — GUID of the user
- \`AppDisplayName\` — what application they were signing into (Office 365, Azure Portal, Salesforce)
- \`ClientAppUsed\` — browser / Mobile App / Exchange ActiveSync / Other client

**Location and device fields:**
- \`IPAddress\` — source IP of the sign-in attempt
- \`Location\` — city, state, country derived from IP
- \`DeviceDetail\` — device ID, OS, browser

**Authentication fields:**
- \`AuthenticationRequirement\` — Single factor or Multi factor
- \`Status\` — Success or Failure
- \`ErrorCode\` — numeric code explaining failures

**Key error codes every SOC analyst must know:**
- **50126** — Invalid username or password (credential is wrong)
- **50076** — MFA required but not performed (Conditional Access kicked in)
- **50053** — Account is locked out (too many failed attempts triggered lockout)
- **50057** — Account is disabled
- **70044** — Session expired (token lifetime exceeded)
- **65001** — User hasn't consented to the application

**Risk fields (from Identity Protection):**
- \`RiskLevelAggregated\` — None / Low / Medium / High
- \`RiskState\` — atRisk / remediated / dismissed / confirmedSafe / confirmedCompromised`,
    },

    // ── Reading 3: Identity Protection, Attacks & Monitoring ──────────────
    {
      type: "reading" as const,
      id: "entra-r3",
      heading:
        "Entra ID Protection, PIM, and Identity Attack Patterns",
      content: `## Microsoft Entra ID Protection

**Entra ID Protection** (formerly Azure AD Identity Protection) is a risk-based identity security service. It uses machine learning and Microsoft's global threat intelligence to detect suspicious sign-in behavior and automatically apply remediation.

**Risk Policies:**
- **Sign-in risk policy**: Detects suspicious characteristics of a specific sign-in (new location, anonymous IP, atypical travel, malware-linked IPs). Risk levels: Low, Medium, High.
- **User risk policy**: Tracks the overall risk of a user account over time (leaked credentials found on dark web, multiple risky sign-ins, suspicious behavior patterns).

**Automatic Remediation:**
You can configure ID Protection to automatically:
- **Block** high-risk sign-ins (access denied until IT investigates)
- **Require MFA** for medium-risk sign-ins
- **Require password reset** when user risk is high (credentials may be compromised)

**Risky Sign-in Detections:**
- **Impossible travel**: Sign-ins from two geographically distant locations within a time period impossible to travel between (e.g., New York at 9:00 AM, London at 10:00 AM)
- **Unfamiliar sign-in properties**: Signing in from a new country, new device, or new IP range for the first time
- **Anonymous IP**: Sign-in from Tor exit nodes or known VPN/proxy services
- **Malware linked IP**: Sign-in from an IP known to be used by botnets
- **Leaked credentials**: Microsoft detects the user's username/password listed on dark web paste sites or breach databases

---

## Privileged Identity Management (PIM)

**PIM** addresses one of the biggest security problems in organizations: **standing privilege**. Many organizations give admin accounts their elevated permissions permanently. If that account is compromised, the attacker immediately has admin access.

PIM implements **just-in-time (JIT) access**: privileged roles are not assigned permanently. Instead, eligible users must *activate* the role when they need it, for a limited time, with optional approval and MFA requirements.

**How it works:**
1. User is made "eligible" for Global Administrator (not assigned)
2. When they need to do admin work, they go to PIM and click "Activate"
3. They enter a justification ("Applying emergency patch to tenant security policy")
4. Optionally, their manager approves the request
5. The role is assigned for 1-8 hours, then automatically expires
6. An audit log records exactly when, why, and what they did

**SOC monitoring for PIM:**
- Alert on PIM role activations outside business hours
- Alert on multiple PIM activations in a short window (attacker trying to quickly gather privileges)
- Alert on PIM role activation approvals being bypassed

---

## Key Identity Attack Patterns

**1. Password Spray (T1110.003)**
Attacker tries one common password across many accounts to avoid lockouts. In Azure AD context, attackers target the cloud authentication endpoint (/common/oauth2/token). Detectable in sign-in logs as many 50126 errors across different UserPrincipalNames from the same IP.

**2. MFA Fatigue (Push Bombing)**
Attacker already has the victim's username and password (from a breach or phishing). They repeatedly trigger MFA push notifications to the victim's phone. The victim, annoyed by constant notifications, eventually taps "Approve" to make them stop. Detection: many MFA push notifications within a short period, especially at odd hours.

**3. OAuth Consent Phishing (T1528 — Steal Application Access Token)**
Described in detail in the M365 Security room. Specifically in Entra ID, look for consent events in the audit log with high-permission scopes.

**4. Token Theft (Pass-the-Token / T1550.001 — Use Alternate Authentication Material: Application Access Token)**
Rather than stealing passwords, sophisticated attackers steal the OAuth access tokens that are issued after successful authentication. If they steal a valid token, they can make API calls as the victim without needing MFA (since MFA already happened when the token was issued). Detectable via unusual API calls from different IP addresses than the original sign-in.

**5. Impossible Travel (Indicator, not attack)**
When sign-in logs show authentication from two locations too far apart to travel between in the time elapsed. Strong indicator of account compromise — or legitimate VPN use (false positive).

---

## Key Audit Log Operations in Entra ID

**User management events:**
- \`Add user\` — new user account created
- \`Delete user\` — account deleted
- \`Reset user password\` — password was reset (by admin or via self-service)
- \`Update user\` — account properties modified

**Role and privilege events:**
- \`Add member to role\` — user added to privileged role (Global Admin, Security Admin, etc.)
- \`Remove member from role\` — privileges revoked
- \`Add eligible member to role in PIM\` — PIM eligibility granted

**Application events:**
- \`Add application\` — new app registration created
- \`Consent to application\` — user or admin consented to an app
- \`Update application\` — app permissions modified

**Policy events:**
- \`Update conditional access policy\` — Conditional Access was modified
- \`Add conditional access policy\` — new policy created
- \`Delete conditional access policy\` — policy removed (potential security reduction)`,
    },

    // ── Question 1 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "entra-q1",
      question:
        "What is the main security advantage of Microsoft Entra ID Privileged Identity Management (PIM)?",
      options: [
        "It encrypts privileged user accounts so attackers cannot read their passwords",
        "It replaces standing privilege with just-in-time access — admin roles are only active for a limited time when explicitly needed, reducing the window of exposure",
        "It prevents admins from logging in outside business hours",
        "It automatically enables MFA for all privileged accounts",
      ],
      answer: 1,
      explanation:
        "PIM's key benefit is eliminating 'standing privilege' — the dangerous situation where admin accounts have elevated permissions 24/7, meaning a compromise at any moment gives instant admin access. With PIM, even if an admin account is compromised, the attacker only gets whatever role the account currently has (which may be none, if PIM hasn't been activated). Admins activate their roles on-demand with justification and time limits. This dramatically reduces the attack surface. PIM also provides a complete audit trail of every privileged action.",
      xp: 30,
    },

    // ── Question 2 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "entra-q2",
      question:
        "An Entra ID sign-in log shows ErrorCode 50126 for an account. What does this mean?",
      options: [
        "MFA was required but the user did not complete it",
        "The user's account has been disabled by an administrator",
        "The username or password is incorrect — authentication credentials failed",
        "The user's session has expired and they need to re-authenticate",
      ],
      answer: 2,
      explanation:
        "Error code 50126 in Azure AD / Entra ID means 'Invalid username or password, or invalid on-premises username or password.' This is the standard credential failure code. When you see many 50126 errors in sign-in logs targeting many different accounts from the same IP address, this is the signature pattern for a password spray attack. Important to distinguish: 50053 is account locked, 50076 is MFA required (this appears when a sign-in succeeds but Conditional Access demands MFA), 50057 is account disabled.",
      xp: 30,
    },

    // ── Question 3 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "entra-q3",
      question:
        "What is 'MFA Fatigue' (also called Push Bombing) and why does it work?",
      options: [
        "An attack where the attacker exhausts the victim's MFA app battery by generating many requests",
        "An attack where the attacker already has the victim's password and repeatedly sends MFA push notifications until the frustrated victim taps 'Approve' to make them stop",
        "An attack where the attacker reuses an old MFA code (replay attack)",
        "An attack where the attacker changes the victim's phone number to redirect MFA SMS codes",
      ],
      answer: 1,
      explanation:
        "MFA Fatigue exploits human psychology, not technology. The attacker already knows the victim's username and password (perhaps from a data breach). They begin the login process repeatedly, triggering MFA push notifications to the victim's phone. The victim receives alerts saying 'Approve sign-in?' — sometimes at 2 AM, many times in a row. Eventually, the victim taps Approve to stop the notifications, believing it may be a glitch. The attacker immediately has access. Microsoft has introduced 'number matching' in the Authenticator app to combat this — the user must type the number shown on screen, making accidental approvals harder. Conditional Access with 'block access if sign-in risk is high' can also prevent this.",
      xp: 30,
    },

    // ── Log Analysis: Entra ID Risky Sign-In ──────────────────────────────
    {
      type: "log_analysis" as const,
      id: "entra-la1",
      heading: "Analyze This Entra ID Sign-In Log: Impossible Travel Alert",
      context:
        "Entra ID Protection has flagged a high-risk sign-in event. The sign-in attempt was for a CEO-level account (ceo@corp.com). Examine the log details below and answer the investigation questions.",
      event: {
        id: "evt-entra-001",
        ts: "2025-06-24T08:33:17Z",
        source: "cloud_azure" as const,
        event_type: "auth_failure" as const,
        severity: "critical" as const,
        user_email: "ceo@corp.com",
        src_ip: "223.73.88.12",
        description:
          "High-risk sign-in failure — CEO account targeted from unusual geographic location with risky IP",
        mitre_technique: "T1078",
        vendor: "Microsoft 365 Unified Audit Log",
        raw: {
          "data.office365.Operation": "UserLoginFailed",
          "data.office365.UserId": "ceo@corp.com",
          "data.office365.ActorIpAddress": "223.73.88.12",
          "data.office365.ErrorNumber": "50126",
          "data.office365.Workload": "AzureActiveDirectory",
          "data.office365.AzureActiveDirectoryEventType": 1,
          "GeoLocation.country_name": "China",
          "GeoLocation.city_name": "Shanghai",
          "GeoLocation.latitude": 31.2304,
          "GeoLocation.longitude": 121.4737,
          "data.office365.ExtendedProperties": [
            { Name: "RiskLevel", Value: "High" },
            { Name: "RiskDetail", Value: "ImpossibleTravel" },
            { Name: "UserAgent", Value: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
            { Name: "RequestType", Value: "Login:login" },
            { Name: "ResultStatusDetail", Value: "InvalidUserNameOrPassword" },
          ],
          "rule.description": "UserLoginFailed operation detected",
          "rule.level": "15",
          "rule.groups": ["identity", "azuread"],
        },
      } as TelemetryEvent,
      questions: [
        {
          question:
            "The CEO's account shows a failed login from Shanghai, China. The CEO was confirmed to be in New York at the time of this event. Which Entra ID Protection risk detection type does this trigger?",
          options: [
            "Leaked credentials — the password was found on the dark web",
            "Anonymous IP — the sign-in is from a Tor exit node",
            "Impossible travel — the sign-in is from a location too far away to reach in the time since the last sign-in",
            "Malware-linked IP — the source IP is in a botnet blocklist",
          ],
          answer: 2,
          explanation:
            "The ExtendedProperties in this log confirm 'RiskDetail: ImpossibleTravel'. This risk detection fires when Entra ID Protection calculates that it's physically impossible for the user to be in both their normal location (New York) and the new location (Shanghai) within the time elapsed between sign-ins. Typically this means the second sign-in is from a different person — either an attacker using stolen credentials, or someone sharing credentials. The other options (leaked credentials, anonymous IP, malware IP) are other valid detection types but are not indicated by this specific log.",
          xp: 40,
        },
        {
          question:
            "The ErrorNumber in this log is 50126. The sign-in FAILED. Does this mean the CEO's account is safe and no further investigation is needed?",
          options: [
            "Yes — the attack failed, so there is no incident to investigate",
            "No — a failed attempt from a high-risk location still indicates the attacker has the CEO's username. They may try again, and successful logins to other services with the same credentials should be checked. Password reset is recommended.",
            "Yes — Entra ID automatically blocked and banned the source IP",
            "No — but only because the CEO is a high-value target; for regular users a failed login would be safe to ignore",
          ],
          answer: 1,
          explanation:
            "A failed login (50126 = invalid credentials) from China does NOT mean all is well. The attacker at minimum knows the CEO's username (email address). The failure could mean: (1) the attacker has an old password that recently changed, (2) the attacker is spraying common passwords, or (3) they have the correct password but MFA blocked them. Required actions: (1) Alert the CEO, (2) Verify the CEO has not traveled to China (confirm impossible travel), (3) Force password reset as a precaution, (4) Check if any OTHER services the CEO uses with the same credentials show successful logins, (5) Enable Conditional Access to block sign-ins from high-risk countries.",
          xp: 40,
        },
      ],
    },

    // ── Flag Task ─────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "entra-flag1",
      prompt:
        "Look at the Entra ID sign-in log above. A failed login attempt was made against the CEO's account. According to the GeoLocation fields in the log, which country did this sign-in attempt originate from?",
      answer: "China",
      hint: "Look at the GeoLocation fields in the raw log data. The field 'GeoLocation.country_name' contains the answer.",
      xp: 50,
    },

    // ── Question 4 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "entra-q4",
      question:
        "A Conditional Access policy is configured: Conditions = All users + All cloud apps + Location = 'Untrusted locations'. Grant control = 'Require MFA'. An employee tries to sign in from a hotel in Paris (not a corporate office). What happens?",
      options: [
        "The sign-in is blocked with no option to authenticate",
        "The sign-in proceeds with just username and password because the policy only applies to admins",
        "The user is prompted for MFA in addition to their password. If they complete MFA, they get access. If they skip MFA, they are blocked.",
        "The policy only applies during business hours, so the result depends on the time",
      ],
      answer: 2,
      explanation:
        "With this Conditional Access policy, the hotel network (not a corporate IP range = 'untrusted location') triggers the condition. The grant control 'Require MFA' means access is granted only after the user proves their identity with a second factor. The sign-in flow: user enters username and password → Entra ID evaluates CA policies → location is untrusted → MFA is required → user gets an MFA prompt → if completed successfully, access is granted. If MFA is not completed (user lacks their phone, refuses), the sign-in is denied. The policy applies to ALL users, not just admins, and location conditions are time-independent.",
      xp: 30,
    },

    // ── Question 5 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "entra-q5",
      question:
        "In Entra ID's tenant model, what is a 'Service Principal'?",
      options: [
        "A backup administrator account created for emergency access",
        "The instance of an application registration within a specific tenant — used by applications and automation to authenticate with Entra ID without a human user",
        "A special user account that cannot be deleted or modified",
        "A network firewall rule that controls which applications can access Entra ID",
      ],
      answer: 1,
      explanation:
        "A Service Principal is the 'local identity' of an application within a tenant. When you register an application in Entra ID (create an App Registration), it creates a Service Principal in your tenant representing that app. The Service Principal is what the application uses to authenticate — it has its own credentials (client secret or certificate) separate from any user. In a multi-tenant scenario, the same application registration can have Service Principals in multiple tenants. SOC relevance: attackers who compromise a Service Principal credential can make API calls as that application, bypassing per-user MFA and Conditional Access policies that apply to human users.",
      xp: 30,
    },
  ],
};

// ─── Export ───────────────────────────────────────────────────────────────────

const rooms = [
  detectionRulesTuningRoom,
  logSourcesIntegrationRoom,
  microsoft365SecurityRoom,
  entraIdRoom,
];

export default rooms;
