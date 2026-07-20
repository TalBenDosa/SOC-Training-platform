import type { TelemetryEvent } from "@/lib/sim/types";

const rooms = [
  // ─── Room 1: Use Case Development ───────────────────────────────────────────
  {
    id: "use-case-development",
    title: "Use Case Development",
    description:
      "Learn how to build, test, document, and maintain detection use cases — the engine that powers every SOC alert. Go from raw threat idea to deployed Sigma rule.",
    difficulty: "advanced",
    category: "SIEM",
    estimatedMinutes: 50,
    xp: 155,
    icon: "📐",
    prerequisites: ["siem-fundamentals", "mitre-attack"],
    tasks: [
      // ── Reading 1 ─────────────────────────────────────────────────────────
      {
        type: "reading",
        id: "ucd-read-1",
        heading: "What Is a Use Case — and Why Does Every SOC Need Them?",
        content:
          `Imagine you manage security at a large museum. You can't watch every painting at once, so instead you set up specific, deliberate triggers: "If someone touches the painting, the alarm sounds." "If a door opens after midnight, a guard is paged." Each rule is a **use case** — a documented scenario with a clear trigger, a defined data source, and an expected response.\n\n` +
          `In a SOC, a **use case** (also called a detection use case or detection rule) is exactly the same concept applied to cybersecurity. It is a formally documented detection scenario that tells your SIEM: "If this specific pattern of behavior appears in these specific logs, create an alert of this severity and assign it to the on-call analyst."\n\n` +
          `Without use cases, a SIEM is just an expensive log storage system. With well-crafted use cases, it becomes a 24/7 watchdog that never blinks.\n\n` +
          `**What makes up a use case?**\n\n` +
          `Every use case has six core components:\n\n` +
          `- **Hypothesis**: A plain-English statement of what attacker behavior you are trying to detect. Example: "An attacker using PowerShell with Base64 encoding to run hidden commands."\n` +
          `- **Data Source**: Which logs feed this detection. Example: Windows Sysmon process creation logs, EDR telemetry.\n` +
          `- **Detection Logic**: The actual filter or query — the rules written in your SIEM's query language or as a Sigma rule.\n` +
          `- **Severity**: How dangerous is this if it's real? (Critical, High, Medium, Low)\n` +
          `- **Response Playbook**: What should the analyst do when this fires? (Investigate → isolate → escalate?)\n` +
          `- **Exceptions / Suppressions**: Known-good patterns that should NOT trigger an alert (e.g., your IT team runs encoded PowerShell legitimately during patching).\n\n` +
          `**The Use Case Lifecycle**\n\n` +
          `Use cases don't just appear — they go through a structured lifecycle:\n\n` +
          `1. **Identify the Threat**: Start with a real threat relevant to your organization. Example: ransomware groups targeting your industry.\n` +
          `2. **Map to a Data Source**: Which logs would capture this behavior? If you don't have the right logs, you can't detect it.\n` +
          `3. **Write Detection Logic**: Draft the query or rule.\n` +
          `4. **Test with Real Data**: Run the rule against historical logs or synthetic attack data. Does it catch the attack? Does it generate too many false positives?\n` +
          `5. **Tune**: Adjust thresholds, add exceptions, refine conditions.\n` +
          `6. **Document**: Write it up formally in the Use Case Registry.\n` +
          `7. **Deploy**: Push to production SIEM.\n` +
          `8. **Maintain**: Revisit when the environment changes, new log sources arrive, or the attack technique evolves.\n\n` +
          `**Why "if it's not documented, it doesn't exist"**\n\n` +
          `A use case that lives only in one analyst's head is a liability. When that analyst leaves, the detection disappears with them. A Use Case Registry — a shared document or database tracking every detection your SOC runs — ensures continuity, auditability, and the ability to answer a simple but critical question: "Are we detecting this threat?"\n\n` +
          `Think of the registry as your museum's master alarm list. Any guard, any night, can open the binder and see exactly what each alarm does and what to do when it triggers.`,
      },
      // ── Reading 2 ─────────────────────────────────────────────────────────
      {
        type: "reading",
        id: "ucd-read-2",
        heading: "MITRE ATT&CK as a Use Case Framework and Writing Sigma Rules",
        content:
          `Think of **MITRE ATT&CK** as the world's most comprehensive cookbook for attacker behavior. Just as a chef's cookbook catalogs every known recipe, ATT&CK catalogs every known attacker technique — from how they first get into a network (Initial Access) to how they steal data and leave (Exfiltration). As of 2025, the Enterprise matrix covers 14 Tactics and over 200 Techniques.\n\n` +
          `For use case developers, ATT&CK is the starting point for almost every detection. Instead of guessing what to detect, you can systematically walk through the matrix and ask: "For each technique an attacker might use against us, do we have a detection use case?"\n\n` +
          `**Prioritizing Use Cases with ATT&CK**\n\n` +
          `You can't build a use case for every single ATT&CK technique — there are too many, and you may not have the right log sources for all of them. Prioritization matters:\n\n` +
          `- **Threat intelligence**: Which techniques are the threat groups targeting your industry actually using? A bank should prioritize FIN7 techniques; a hospital should prioritize ransomware groups that target healthcare.\n` +
          `- **Your existing visibility**: You can only detect what you can see. Prioritize techniques that your current log sources can observe.\n` +
          `- **Highest impact**: A technique that leads directly to ransomware deployment or data theft deserves more detection coverage than a low-impact reconnaissance technique.\n\n` +
          `**Sigma Rules: Vendor-Neutral Detection Logic**\n\n` +
          `One of the biggest problems in detection engineering is vendor lock-in: you write a detection rule in Splunk's SPL query language, and now it's useless if you switch to Microsoft Sentinel (which uses KQL) or Elastic (which uses EQL). Enter **Sigma**.\n\n` +
          `Sigma is an open, vendor-neutral rule format written in YAML. A Sigma rule describes detection logic in abstract terms, and converter tools (like sigmac or pySigma) translate it into the query language of your specific SIEM.\n\n` +
          `A basic Sigma rule has these sections:\n\n` +
          `- **title**: Human-readable name (e.g., "Encoded PowerShell Command Execution")\n` +
          `- **id**: A unique UUID for tracking\n` +
          `- **status**: experimental, test, or stable\n` +
          `- **description**: What the rule detects\n` +
          `- **references**: CVE links, blog posts, ATT&CK technique ID\n` +
          `- **logsource**: Which product/category/service the logs come from\n` +
          `- **detection**: The actual logic — what field values trigger the alert\n` +
          `- **falsepositives**: Known benign triggers to be aware of\n` +
          `- **level**: critical / high / medium / low\n\n` +
          `**Testing Use Cases with Real Attack Data**\n\n` +
          `Writing a rule is only half the job. Before you deploy to production, you must test it:\n\n` +
          `- **Unit testing**: Run the rule against a small dataset where you know the ground truth (attacks that should fire, benign events that should not).\n` +
          `- **Red team exercises**: Have your red team or penetration testers simulate the attack. Did your rule fire? If not, why not?\n` +
          `- **Purple team exercises**: Red team + Blue team working together — the red team performs each ATT&CK technique deliberately, and the blue team checks whether their rules caught it in near-real-time.\n` +
          `- **Replay testing**: Collect real attack logs from past incidents or public threat research datasets and replay them through your detection pipeline.\n\n` +
          `A use case that has never been tested against real attack data is just a hypothesis. Testing is what turns it into a reliable detection.`,
      },
      // ── Reading 3 ─────────────────────────────────────────────────────────
      {
        type: "reading",
        id: "ucd-read-3",
        heading: "Maintaining Use Cases Over Time",
        content:
          `Here's a problem every SOC eventually faces: a use case that worked perfectly six months ago is now generating hundreds of false positives — or worse, silently missing real attacks. Why? Because **environments change**.\n\n` +
          `Think of your detection rules like the smoke detectors in a building. When the building was first constructed, they were installed in the right places and configured correctly. But over the years, the building changes: new kitchens are added, ventilation patterns shift, and the old detectors start going off every time someone makes toast. Someone needs to regularly check whether the detectors are still in the right places and properly calibrated.\n\n` +
          `**Reasons Use Cases Decay**\n\n` +
          `- **New log sources added**: Your organization deploys a new endpoint security tool. Its logs have different field names than the old tool. Detection rules that relied on the old field names break silently.\n` +
          `- **New software deployed**: A new business application runs legitimate processes that look exactly like the attacker behavior your rule was designed to catch.\n` +
          `- **Organizational changes**: A merger brings in thousands of new users, new IP ranges, and new patterns of activity that weren't in the baseline when the rule was tuned.\n` +
          `- **Attacker technique evolution**: Attackers read the same security blog posts you do. If a detection technique is published publicly, sophisticated groups will modify their tools to evade it.\n` +
          `- **Threshold drift**: A rule that fires when more than 5 failed logins occur in 10 minutes may have been fine when you had 200 users. With 2,000 users, you may need to adjust the thresholds or add per-account rather than global counting.\n\n` +
          `**Use Case Maintenance Best Practices**\n\n` +
          `- **Quarterly reviews**: Set a calendar reminder every quarter to review your top-50 use cases. Are they still firing correctly? Are false positive rates acceptable?\n` +
          `- **Track false positive rates**: If a rule fires 100 times a week and 99 of those are false positives, it is actively harming your SOC by wasting analyst time. Document FP rates in the Use Case Registry.\n` +
          `- **Subscribe to threat intelligence**: When a new attacker group emerges or a new technique is published, trigger a review of related use cases.\n` +
          `- **Post-incident review**: After every real incident, ask: "Did our use cases catch this? Which ones fired? Which ones should have fired but didn't?" Use incidents as a forcing function to improve coverage.\n` +
          `- **Version control your rules**: Store Sigma rules in a git repository. This gives you a complete history of changes, the ability to roll back a broken rule, and the ability to review who changed what.\n\n` +
          `**The Use Case Registry**\n\n` +
          `Your Use Case Registry should track, at minimum:\n\n` +
          `- Unique rule ID (e.g., UC-ENDPOINT-0089)\n` +
          `- Rule name and description\n` +
          `- MITRE ATT&CK technique(s) it covers\n` +
          `- Data sources required\n` +
          `- Current status (active, disabled, in-testing)\n` +
          `- Severity and priority\n` +
          `- False positive rate (weekly average)\n` +
          `- Last reviewed date\n` +
          `- Owner (who is responsible for maintaining this rule)\n` +
          `- Linked playbook or runbook\n\n` +
          `A well-maintained Use Case Registry is one of the clearest signs of a mature SOC. When an auditor or executive asks "Are you detecting technique X?", you can answer immediately — yes, rule UC-ENDPOINT-0089 covers it, it was last tested on this date, and it fires with this accuracy.`,
      },
      // ── Question 1 ────────────────────────────────────────────────────────
      {
        type: "question",
        id: "ucd-q1",
        question:
          "A SOC analyst writes a detection rule in their SIEM's query language but never documents it anywhere. Six months later, the analyst leaves the company. What is the PRIMARY risk?",
        options: [
          "The SIEM will automatically delete undocumented rules after 30 days",
          "The detection coverage disappears with the analyst because it was never formalized in the Use Case Registry",
          "The rule will generate too many false positives without documentation",
          "Other analysts will accidentally trigger the rule and cause outages",
        ],
        answer: 1,
        explanation:
          "Undocumented detection rules are a major SOC risk. When the analyst who created the rule leaves, nobody else knows it exists, what it does, how it should behave, or how to maintain it. Over time the rule may silently break, generate noise, or miss attacks — and no one will know why. This is why every use case must be formally documented in a Use Case Registry.",
        xp: 20,
      },
      // ── Question 2 ────────────────────────────────────────────────────────
      {
        type: "question",
        id: "ucd-q2",
        question:
          "What is the main advantage of writing detection logic as a Sigma rule instead of directly in a SIEM's native query language (like Splunk SPL or Microsoft Sentinel KQL)?",
        options: [
          "Sigma rules run faster and generate fewer false positives",
          "Sigma rules are vendor-neutral and can be converted to any SIEM's query language",
          "Sigma rules are automatically approved by MITRE ATT&CK",
          "Sigma rules can only be written by Tier 3 analysts",
        ],
        answer: 1,
        explanation:
          "Sigma is a vendor-neutral, open rule format written in YAML. The same Sigma rule can be converted to Splunk SPL, Microsoft Sentinel KQL, Elastic EQL, or many other formats using converter tools. This avoids vendor lock-in and makes it easy to share detection logic with the broader security community.",
        xp: 20,
      },
      // ── Question 3 ────────────────────────────────────────────────────────
      {
        type: "question",
        id: "ucd-q3",
        question:
          "Your use case for detecting brute-force attacks fires when 5 failed logins occur within 10 minutes from a single account. After a company merger, the rule now generates 500 false-positive alerts per day — all from legitimate password resets for newly onboarded users. What should you do FIRST?",
        options: [
          "Disable the rule permanently to stop the noise",
          "Escalate every alert to Tier 3 for manual investigation",
          "Tune the rule — adjust the threshold, add an exception for the onboarding process, or scope it to exclude known-good IP ranges for the migration period",
          "Delete the rule and start over from scratch",
        ],
        answer: 2,
        explanation:
          "This is a classic example of use case decay due to an organizational change (merger). The correct response is to tune the rule, not disable it. Tuning options include raising the threshold, adding exceptions for the migration period, or excluding the known-good IP range used for bulk password resets. Disabling the rule entirely would leave you blind to real brute-force attacks.",
        xp: 25,
      },
      // ── Log Analysis ──────────────────────────────────────────────────────
      {
        type: "log_analysis",
        id: "ucd-log-1",
        heading: "Analyzing an Alert from a Newly Deployed Use Case",
        context:
          "Your team just deployed a new use case called 'Encoded PowerShell Execution' (rule ID: UC-ENDPOINT-0089). Minutes after deployment, it fires on a workstation. Examine the telemetry event below and answer the questions about the alert.",
        event: {
          id: "evt-ucd-001",
          ts: "2026-06-24T09:14:37.882Z",
          source: "siem",
          event_type: "edr_alert",
          hostname: "WS-FINANCE-042",
          severity: "high",
          raw: {
            "rule.name": "Encoded-PowerShell-Exec",
            "rule.id": "UC-ENDPOINT-0089",
            "rule.category": "Execution",
            "rule.level": 7,
            "rule.mitre_technique": "T1059.001",
            "rule.description":
              "Detects execution of PowerShell with Base64-encoded command arguments, a common technique used by attackers to obfuscate malicious payloads.",
            "rule.status": "new",
            "process.name": "powershell.exe",
            "process.pid": 9248,
            "process.parent_name": "cmd.exe",
            "process.parent_pid": 8812,
            "process.cmdline":
              "powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAvAHAAYQB5AGwAbwBhAGQALgBwAHMAMQAnACkA",
            "process.working_dir": "C:\\Windows\\Temp",
            "host.name": "WS-FINANCE-042",
            "host.ip": "10.10.5.42",
            "host.os": "Windows 10 22H2",
            "user.name": "m.torres",
            "user.domain": "CORP",
            "event.action": "Process Created",
            "event.created": "2026-06-24T09:14:37.882Z",
          },
        } as TelemetryEvent,
        questions: [
          {
            question:
              "Which command-line flag in the process.cmdline field is the specific indicator that triggered use case UC-ENDPOINT-0089 (Encoded PowerShell Execution)?",
            options: [
              "-NoProfile",
              "-NonInteractive",
              "-WindowStyle Hidden",
              "-enc",
            ],
            answer: 3,
            explanation:
              "The -enc flag (short for -EncodedCommand) is the PowerShell parameter that accepts a Base64-encoded command string. Attackers use this to obfuscate their payloads — the encoded blob after -enc decodes to a command that downloads and executes a payload from 192.168.1.100. The other flags (-NoProfile, -NonInteractive, -WindowStyle Hidden) are also suspicious but are not the specific trigger for the 'Encoded PowerShell Execution' use case.",
            xp: 25,
          },
          {
            question:
              "The process is running from C:\\Windows\\Temp and its parent is cmd.exe. Why does this combination increase the severity of this alert?",
            options: [
              "C:\\Windows\\Temp is a protected directory that requires admin rights to access",
              "cmd.exe is a deprecated program that should never run PowerShell",
              "Legitimate PowerShell scripts typically run from application or user directories, not Temp; and spawning PowerShell from cmd.exe is a common attacker pattern for staging and executing payloads",
              "The parent-child relationship between cmd.exe and powershell.exe is blocked by default firewall rules",
            ],
            answer: 2,
            explanation:
              "The combination of working directory (C:\\Windows\\Temp), parent process (cmd.exe), and encoded command is a classic attacker staging pattern. Legitimate enterprise scripts run from known directories like C:\\Scripts\\ or the application's own folder. Attackers use Temp because it is writable by all users and often overlooked. This combination of contextual indicators elevates confidence that this is malicious rather than a false positive.",
            xp: 25,
          },
        ],
      },
      // ── Matching Task — ATT&CK Technique to Use Case ─────────────────────────
      {
        type: "matching" as const,
        id: "ucd-m1",
        heading: "Match the Observable Behavior to its ATT&CK Technique",
        instructions: "A well-built use case starts with an observable behavior and maps it to an ATT&CK technique. Match each detection observable on the left to the correct ATT&CK technique ID and name on the right.",
        pairs: [
          {
            id: "ps_enc",
            left: "PowerShell launched with Base64 argument (-enc or -EncodedCommand)",
            right: "T1027 — Obfuscated Files or Information",
          },
          {
            id: "lsass",
            left: "Process accessing LSASS.exe memory with GrantedAccess 0x1FFFFF",
            right: "T1003.001 — OS Credential Dumping: LSASS Memory",
          },
          {
            id: "spray",
            left: "Single password attempted against 50+ different accounts within 10 minutes",
            right: "T1110.003 — Brute Force: Password Spraying",
          },
          {
            id: "sched",
            left: "New scheduled task created with action path inside %TEMP% or %APPDATA%",
            right: "T1053.005 — Scheduled Task/Job: Scheduled Task",
          },
          {
            id: "beacon",
            left: "Outbound HTTPS to same destination every 4-5 minutes with tiny payload size",
            right: "T1071.001 — Application Layer Protocol: Web Protocols (C2)",
          },
        ],
        explanation: "Mapping observables to ATT&CK techniques is the foundation of use case development. A good use case starts with 'what can I actually see in logs?' and maps that observable to ATT&CK. This matters because: (1) it tells you whether you have log coverage for that technique; (2) it enables MITRE ATT&CK Navigator heatmaps showing your detection gaps; (3) it provides standardized language for reporting across teams. The mapping is not always 1:1 — some techniques (like T1059 Command and Scripting Interpreter) appear in dozens of use cases depending on the specific command interpreter used.",
        xp: 40,
      },
    ],
  },

  // ─── Room 2: Reporting & Documentation ──────────────────────────────────────
  {
    id: "reporting-documentation",
    title: "Reporting & Documentation",
    description:
      "Master the art of SOC documentation — incident tickets, shift handovers, management reports, and the key metrics that show whether your SOC is performing.",
    difficulty: "intermediate",
    category: "SOC Operations",
    estimatedMinutes: 35,
    xp: 115,
    icon: "📝",
    prerequisites: ["alert-triage", "soc-structure"],
    tasks: [
      // ── Reading 1 ─────────────────────────────────────────────────────────
      {
        type: "reading",
        id: "rep-read-1",
        heading: "Why Documentation Is the SOC's Most Important Habit",
        content:
          `Imagine two doctors. The first doctor treats a patient, figures out the diagnosis, gives the right medication — but writes nothing down. When a different doctor sees the same patient next week, they have to start from scratch. The second doctor documents everything: symptoms, tests, diagnosis, treatment, and follow-up plan. When any doctor in the hospital sees this patient later, they have the full picture instantly.\n\n` +
          `In a SOC, **documentation is the equivalent of the medical record**. If an analyst investigates an alert, finds it's a real attack, takes action — but writes nothing down — then for all practical purposes, it didn't happen. There's no audit trail, no knowledge transfer, no way for a colleague on the next shift to pick up where they left off.\n\n` +
          `There's a saying that's become standard in the security world: **"If it's not documented, it didn't happen."** This matters for several concrete reasons:\n\n` +
          `- **Legal and regulatory compliance**: If you're ever involved in a breach notification, a lawsuit, or a regulatory audit, investigators will want to see your incident records. Without documentation, you have no evidence of what you did.\n` +
          `- **Shift continuity**: SOC analysts work in shifts — 8-hour, 10-hour, or 12-hour rotations. Without a proper handover record, critical context is lost every time the shift changes.\n` +
          `- **Knowledge transfer**: When a junior analyst investigates a complex attack, detailed notes allow senior analysts to review the work and junior analysts to learn from the feedback.\n` +
          `- **Trend analysis**: Documented incidents reveal patterns over time. If you see the same phishing campaign targeting your users three times in a month, documentation is what lets you spot that pattern.\n\n` +
          `**The Anatomy of an Incident Ticket**\n\n` +
          `Every SOC uses a ticketing system (common ones include ServiceNow, Jira, TheHive, and Splunk SOAR). When an alert is escalated to an incident, a ticket is created. A well-written incident ticket contains:\n\n` +
          `- **Incident ID**: A unique identifier (e.g., INC-2026-4892) for tracking\n` +
          `- **Severity**: How serious is this? (P1/Critical, P2/High, P3/Medium, P4/Low)\n` +
          `- **Category**: Type of incident (Malware, Phishing, Unauthorized Access, Data Exfiltration, etc.)\n` +
          `- **Timeline**: Every action taken, with exact timestamps\n` +
          `- **Affected Systems**: Hostnames, IP addresses, user accounts involved\n` +
          `- **Indicators of Compromise (IOCs)**: Malicious file hashes, IP addresses, domains found\n` +
          `- **Actions Taken**: What did the analyst do? (Isolated host, blocked IP, reset password, etc.)\n` +
          `- **Root Cause**: What was the original source? (Phishing email, unpatched vulnerability, stolen credentials?)\n` +
          `- **Resolution**: How was the incident closed?\n` +
          `- **Lessons Learned**: What could be done better next time?\n\n` +
          `**Writing Good Analyst Notes**\n\n` +
          `The gold standard for analyst notes answers: **Who? What? When? Where? Why? How?** — the same questions a journalist would ask. Example of a bad note: "Investigated alert. Looks malicious." Example of a good note: "At 09:14 UTC, WS-FINANCE-042 (user: m.torres) executed an encoded PowerShell command spawned by cmd.exe from C:\\Windows\\Temp. The Base64 payload decoded to a download cradle fetching from 192.168.1.100/payload.ps1. Isolated the host at 09:31 UTC pending malware analysis."`,
      },
      // ── Reading 2 ─────────────────────────────────────────────────────────
      {
        type: "reading",
        id: "rep-read-2",
        heading: "SOC Metrics, KPIs, and the Shift Handover Report",
        content:
          `Think of a car's dashboard. It doesn't tell you every mechanical detail of the engine — it gives you the key numbers you need to make decisions: speed, fuel level, engine temperature. If any of those numbers goes into the red, you know there's a problem that needs attention.\n\n` +
          `SOC managers need the same kind of dashboard. They use **Key Performance Indicators (KPIs)** — specific, measurable numbers that tell them at a glance whether the SOC is functioning well.\n\n` +
          `**The Most Important SOC KPIs**\n\n` +
          `- **MTTD — Mean Time to Detect**: How long, on average, from when an attack begins until your SOC detects it. Lower is better. Industry benchmark for mature SOCs: under 1 hour for high-severity threats.\n` +
          `- **MTTR — Mean Time to Respond**: How long from when an alert is detected until the threat is contained and the incident is resolved. This includes investigation, decision-making, and remediation. Lower is better.\n` +
          `- **Alert Volume**: How many alerts did the SIEM generate? Increasing alert volume may indicate a new attack campaign — or too many noisy rules.\n` +
          `- **False Positive (FP) Rate**: What percentage of alerts turned out to be non-malicious? An FP rate above 90% is a sign of poorly tuned detection rules. Analyst time is being wasted.\n` +
          `- **Escalation Rate**: What percentage of Tier 1 tickets were escalated to Tier 2? Unusually high escalation rates may indicate Tier 1 needs more training.\n` +
          `- **Open Tickets**: How many incidents are currently unresolved? A growing backlog is a warning sign.\n` +
          `- **SLA Compliance**: Are you meeting your Service Level Agreement commitments? (e.g., P1 incidents must be acknowledged within 15 minutes)\n\n` +
          `**The Shift Handover Report**\n\n` +
          `At the end of every shift, the outgoing analyst writes a **Shift Handover Report** for the incoming team. Think of it like a relay race — you don't just drop the baton, you make sure the next runner knows exactly where they are and what they're running toward.\n\n` +
          `A good shift handover report covers:\n\n` +
          `- **Summary of the shift**: How many alerts? Any major incidents?\n` +
          `- **Open cases**: List of all unresolved tickets with their current status and what was done\n` +
          `- **Things to watch**: Patterns or suspicious activity that didn't rise to the level of an incident but deserves monitoring\n` +
          `- **Environmental notes**: Any planned maintenance, known outages, or system changes that may generate false positives\n` +
          `- **Handover items**: Any specific tasks for the incoming shift ("Please follow up with the IT team about host isolation for INC-2026-4892")\n\n` +
          `**Writing for Management: The Executive Summary**\n\n` +
          `When a significant incident occurs, leadership needs to be informed — but they don't need (or want) every technical detail. An executive summary has two layers:\n\n` +
          `1. **Executive Summary (1 page)**: Written in plain language. What happened? What was affected? What did we do? What is the current risk? What are we doing to prevent it from happening again?\n` +
          `2. **Technical Appendix**: Full details for security staff — timeline, IOCs, forensic findings, log evidence.\n\n` +
          `The cardinal rule: **never bury the key finding.** Put the most important information first. An executive who reads only the first paragraph should still understand the severity of the situation.`,
      },
      // ── Reading 3 ─────────────────────────────────────────────────────────
      {
        type: "reading",
        id: "rep-read-3",
        heading: "Legal Hold, Evidence Preservation, and Ticketing Systems",
        content:
          `Imagine a car accident. Emergency responders arrive and help the injured. But someone also takes photographs, makes measurements, and preserves physical evidence before it can be disturbed. Why? Because later, lawyers, insurance companies, and courts will need that evidence to determine what happened and who is responsible.\n\n` +
          `Cybersecurity incidents are no different. During a serious breach, the logs, forensic images, and communications you preserve — and the way you preserve them — may become evidence in a criminal investigation, a civil lawsuit, or a regulatory proceeding. This is the concept of **legal hold**.\n\n` +
          `**Legal Hold Basics**\n\n` +
          `A **legal hold** (also called a litigation hold) is a directive that certain data must not be modified, deleted, or destroyed because it may be relevant to a legal proceeding. In a SOC context:\n\n` +
          `- When you suspect a serious breach, immediately notify your legal team\n` +
          `- Do NOT delete or overwrite any logs — even "routine" log rotation must be paused for affected systems\n` +
          `- Document the chain of custody for any forensic evidence (who collected it, when, how it was stored)\n` +
          `- Use forensic tools that preserve evidence integrity (creating cryptographic hashes of disk images to prove they weren't modified)\n` +
          `- Be careful about what you write in communications — in a legal proceeding, even informal Slack messages can be discoverable\n\n` +
          `**Common Ticketing Systems in SOC**\n\n` +
          `Different organizations use different tools to track incidents. Knowing the major platforms helps you hit the ground running in any SOC:\n\n` +
          `- **ServiceNow**: Enterprise-grade IT Service Management (ITSM) platform widely used in large corporations. Has strong workflow automation and integration capabilities. Some analysts find it heavy and complex for pure SOC work.\n` +
          `- **Jira**: Originally a software development project tracker, Jira is commonly used in organizations with strong DevOps or IT cultures. Flexible but requires custom configuration for SOC workflows.\n` +
          `- **TheHive**: An open-source security incident response platform built specifically for SOC teams. Integrates natively with MISP (threat intelligence) and Cortex (automated analysis). Favorite of many MSSP and government SOCs.\n` +
          `- **Splunk SOAR (formerly Phantom)**: Combines ticketing with Security Orchestration, Automation, and Response (SOAR) capabilities. Enables automated playbooks that perform investigation steps without analyst intervention.\n\n` +
          `**The Incident Report as a Learning Tool**\n\n` +
          `After every significant incident, the team should conduct a **post-incident review** (also called a post-mortem or lessons learned session). The goal is NOT to assign blame — it is to systematically improve:\n\n` +
          `- What detection rule caught this (or should have caught it)?\n` +
          `- Was the response fast enough? Where were the delays?\n` +
          `- Did the playbook cover this scenario, or did we improvise?\n` +
          `- What process or technical control would have prevented this?\n` +
          `- What are the concrete action items to prevent recurrence?\n\n` +
          `The final incident report — with its executive summary, technical timeline, IOCs, root cause analysis, and lessons learned — is the primary deliverable from this process. It should be stored securely (incidents may be classified) and accessible to future analysts so that the organization learns from each incident rather than repeating the same mistakes.`,
      },
      // ── Question 1 ────────────────────────────────────────────────────────
      {
        type: "question",
        id: "rep-q1",
        question:
          "An analyst responds to a ransomware incident, successfully contains it, and closes the ticket with only the note: 'Ransomware. Cleaned up.' What is the PRIMARY problem with this documentation?",
        options: [
          "The ticket should have been assigned to a different analyst",
          "The note doesn't answer who/what/when/where/why/how — it provides no timeline, no IOCs, no affected systems, no root cause, and no lessons learned",
          "The word 'Ransomware' should be capitalized differently in the ticketing system",
          "The ticket was closed too quickly without Tier 3 approval",
        ],
        answer: 1,
        explanation:
          "Good incident documentation must answer the six key questions: Who was affected? What happened? When did each event occur? Where did it happen (which systems)? Why did it happen (root cause)? How was it resolved? The note 'Ransomware. Cleaned up.' answers none of these questions. Future analysts, auditors, and legal teams would have no usable record of the incident.",
        xp: 15,
      },
      // ── Question 2 ────────────────────────────────────────────────────────
      {
        type: "question",
        id: "rep-q2",
        question: "What does MTTD stand for, and what does it measure?",
        options: [
          "Mean Time to Destroy — how long it takes to wipe a compromised system",
          "Mean Time to Detect — the average time from when an attack begins until the SOC identifies it",
          "Mean Tickets to Determine — the average number of tickets reviewed before escalating",
          "Mean Time to Document — the average time analysts spend writing incident reports",
        ],
        answer: 1,
        explanation:
          "MTTD (Mean Time to Detect) measures the average elapsed time between when an attack or intrusion actually begins and when the SOC first identifies it. A lower MTTD means threats are caught earlier, before attackers can do more damage. It is one of the most important SOC effectiveness metrics, along with MTTR (Mean Time to Respond/Resolve).",
        xp: 15,
      },
      // ── Question 3 ────────────────────────────────────────────────────────
      {
        type: "question",
        id: "rep-q3",
        question:
          "Your SOC's SIEM generates 10,000 alerts in a week. After investigation, analysts determine that 9,200 of those alerts were false positives. What is the false positive rate, and what does this indicate?",
        options: [
          "0.8% — this is excellent and means detection rules are highly accurate",
          "92% — this is very high and indicates poorly tuned detection rules that are wasting significant analyst time",
          "8% — this is a normal false positive rate and requires no action",
          "10,000% — the total alert count should be divided by the number of analysts",
        ],
        answer: 1,
        explanation:
          "9,200 false positives out of 10,000 total alerts = 92% false positive rate. This is extremely high and a sign of serious problems with detection rule tuning. Analysts spending 92% of their time investigating false alarms cannot adequately respond to real threats. SOC teams typically aim for a false positive rate below 50%, with mature programs targeting much lower. The correct response is to review and tune the noisiest rules.",
        xp: 20,
      },
      // ── Log Analysis ──────────────────────────────────────────────────────
      {
        type: "log_analysis",
        id: "rep-log-1",
        heading: "Reading a Resolved Incident Ticket",
        context:
          "Below is a telemetry event representing a resolved incident ticket as logged in the SIEM. This is the kind of record that appears when an analyst closes an incident. Read all fields carefully — they tell the full story of the incident lifecycle.",
        event: {
          id: "evt-rep-001",
          ts: "2026-06-24T11:45:00.000Z",
          source: "siem",
          event_type: "edr_alert",
          hostname: "TICKETING-SYS-01",
          severity: "high",
          raw: {
            "ticket.id": "INC-2026-4892",
            "ticket.status": "Resolved",
            "ticket.severity": "High",
            "ticket.category": "Malware",
            "ticket.created_at": "2026-06-24T09:14:00.000Z",
            "ticket.resolved_at": "2026-06-24T11:39:00.000Z",
            "ticket.analyst": "j.smith",
            "ticket.summary":
              "Encoded PowerShell execution detected on WS-FINANCE-042. Investigation confirmed download cradle fetching Cobalt Strike beacon from 192.168.1.100. Host was isolated and reimaged.",
            "ticket.affected_hosts": ["WS-FINANCE-042"],
            "ticket.iocs_found": [
              "192.168.1.100",
              "payload.ps1",
              "beacon_x64.dll",
              "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ],
            "ticket.actions_taken": [
              "Host isolated from network at 09:31 UTC",
              "Memory dump collected at 09:45 UTC",
              "Malicious IP 192.168.1.100 blocked in firewall at 09:52 UTC",
              "Host reimaged at 11:00 UTC",
              "User m.torres credentials reset at 11:20 UTC",
            ],
            "ticket.root_cause": "User executed malicious attachment from phishing email",
            "ticket.mttd_minutes": 23,
            "ticket.mttr_minutes": 145,
            "ticket.lessons_learned":
              "Anti-phishing training for finance department. Consider blocking macro execution in Office documents.",
          },
        } as TelemetryEvent,
        questions: [
          {
            question:
              "According to the ticket, what was the root cause of this incident?",
            options: [
              "An unpatched vulnerability in Windows that allowed remote code execution",
              "A misconfigured firewall rule that allowed traffic from 192.168.1.100",
              "The user executed a malicious attachment from a phishing email",
              "An insider threat — the analyst j.smith deliberately installed the malware",
            ],
            answer: 2,
            explanation:
              "The ticket.root_cause field clearly states: 'User executed malicious attachment from phishing email.' This is one of the most common root causes for malware incidents. The phishing email delivered an attachment that, when opened, executed the encoded PowerShell command that downloaded the Cobalt Strike beacon.",
            xp: 15,
          },
          {
            question:
              "The ticket shows ticket.mttd_minutes = 23 and ticket.mttr_minutes = 145. If the incident was created at 09:14 UTC, approximately what time was the host isolated from the network?",
            options: [
              "09:14 UTC — immediately upon alert creation",
              "09:31 UTC — as stated in the actions_taken field",
              "11:39 UTC — when the ticket was resolved",
              "11:00 UTC — when the host was reimaged",
            ],
            answer: 1,
            explanation:
              "The ticket.actions_taken field explicitly states 'Host isolated from network at 09:31 UTC.' This was approximately 17 minutes after the alert was created at 09:14 UTC — a reasonable response time for a High severity incident. The MTTD of 23 minutes means the attack started about 23 minutes before 09:14, which places the initial compromise around 08:51 UTC.",
            xp: 20,
          },
        ],
      },
      // ── Analyst Choice — Incident Severity Classification ─────────────────────
      {
        type: "analyst_choice" as const,
        id: "rep-ac1",
        heading: "Verdict: What Severity Should This Incident Be Reported At?",
        scenario: "You are writing the post-incident report. The incident involved: a phishing email that bypassed filters, one user clicked and credential was stolen, attacker logged in for 22 minutes and accessed 3 SharePoint document libraries. No data was exfiltrated (DLP shows 0 uploads). The attacker's session was terminated when MFA was revoked. MTTR was 145 minutes (SLA is 120 minutes). The affected user was a junior marketing analyst with no access to sensitive financial or PII data. How should you classify this incident?",
        event: {
          id: "evt-rep-ac-001",
          ts: "2026-06-18T16:30:00.000Z",
          source: "soar" as const,
          vendor: "Microsoft Sentinel",
          event_type: "edr_alert" as const,
          severity: "medium" as const,
          hostname: "SOAR-PLATFORM-01",
          user_email: "p.nguyen@contoso.com",
          description: "Incident closure review — credential theft, brief access, no exfiltration, SLA breach",
          mitre_technique: "T1566.001",
          mitre_tactic: "Initial Access",
          raw: {
            "ticket.id": "INC-2026-0847",
            "ticket.title": "Credential Theft via Phishing — Marketing Analyst",
            "ticket.status": "pending_closure",
            "ticket.created": "2026-06-18T14:05:00Z",
            "ticket.resolved": "2026-06-18T16:30:00Z",
            "ticket.mttr_minutes": 145,
            "ticket.sla_target_minutes": 120,
            "ticket.sla_breached": true,
            "ticket.minutes_over_sla": 25,
            "incident.affected_users": 1,
            "incident.affected_systems": 0,
            "incident.data_exfiltrated": false,
            "incident.dlp_uploads": 0,
            "incident.attacker_dwell_minutes": 22,
            "incident.user_clearance": "standard",
            "incident.user_data_access": "marketing_collateral_only",
            "containment.mfa_revoked": true,
            "containment.password_reset": true,
            "containment.session_terminated": true,
          },
        },
        correct_verdict: "escalate",
        explanation: "Escalation (to a supervisor or senior analyst for sign-off) is correct before closing this incident. Here is why: (1) The SLA was breached by 25 minutes — this must be documented, and most organizations require management sign-off before closing any SLA breach incident. Closing without noting the breach would be a reporting integrity failure. (2) Even though no data was exfiltrated and no sensitive data was accessible, the 22-minute attacker session requires documentation of everything accessed — some documents in SharePoint may have contained more than standard marketing materials. (3) A post-incident review should be triggered to understand why the phishing email bypassed filters. The correct severity for the report is P3 (low business impact) but the SLA breach elevates the process requirement.",
        fp_trap: "It is tempting to call this 'informational' because: no sensitive data was accessed, no exfiltration occurred, and the attacker was contained in 22 minutes. But the SLA breach (145 vs 120 minutes) is a contractual/compliance finding that requires documentation and management acknowledgment before closing — it cannot be silently ignored in the report.",
        xp: 30,
      },
    ],
  },

  // ─── Room 3: Customer Communication ─────────────────────────────────────────
  {
    id: "customer-communication",
    title: "Customer Communication",
    description:
      "Learn how to communicate security incidents to clients clearly, on time, and without jargon — a critical skill for analysts working in Managed Security Service Providers (MSSPs).",
    difficulty: "intermediate",
    category: "SOC Operations",
    estimatedMinutes: 30,
    xp: 115,
    icon: "📞",
    prerequisites: ["alert-triage", "soc-structure"],
    tasks: [
      // ── Reading 1 ─────────────────────────────────────────────────────────
      {
        type: "reading",
        id: "cc-read-1",
        heading: "The SOC-as-a-Service Model and Why Client Communication Is Critical",
        content:
          `Imagine you hire a home security company to watch your house while you're on vacation. Their job is to monitor your cameras, respond to alarms, and call the police if needed. But here's the thing: it's still YOUR house. If something goes wrong, you need to know about it — fast, clearly, and in terms you can act on. "We observed a Category 3 perimeter intrusion with lateral propagation indicators" is not helpful. "Someone broke a window and may be inside your house" is.\n\n` +
          `This is the core challenge of SOC communication when serving clients. Many security operations centers operate in a **SOC-as-a-Service** or **MSSP (Managed Security Service Provider)** model, where a single SOC team monitors and protects dozens or even hundreds of different client organizations. Each of those clients is essentially saying: "Watch my house. Tell me if something goes wrong. And please don't make me learn your security language to understand what you're telling me."\n\n` +
          `**Why Client Communication Skills Matter**\n\n` +
          `An analyst who can detect attacks but can't communicate them clearly is only half-effective. Consider the consequences of poor communication:\n\n` +
          `- A client who doesn't understand the severity of an incident may not take the required remediation actions (like isolating infected machines or resetting passwords)\n` +
          `- Delayed notification may violate SLA commitments and damage the trust relationship\n` +
          `- Technical jargon can create confusion and panic — or, conversely, false reassurance\n` +
          `- A poorly-written advisory can mislead a client into thinking the situation is under control when it isn't\n\n` +
          `**Translating Technical Language to Business Language**\n\n` +
          `This is one of the most important skills you will develop as a SOC analyst. Here are real examples of translation:\n\n` +
          `- DON'T SAY: "We detected T1055 Process Injection via hollowing on endpoint HOST-014."\n` +
          `  DO SAY: "Malware was found on one of your computers (HOST-014). It was hiding inside legitimate Windows software to avoid detection. We've isolated this computer from your network."\n\n` +
          `- DON'T SAY: "A C2 beacon was detected with 30-second jitter calling back to IOC 185.220.101.47."\n` +
          `  DO SAY: "A computer on your network was secretly communicating with an attacker's server every 30 seconds. This is how attackers maintain control after a breach. We've blocked this communication."\n\n` +
          `- DON'T SAY: "We observed lateral movement via PtH from WKSTN-042 to SRV-DC-01."\n` +
          `  DO SAY: "After gaining access to one employee's computer, the attacker attempted to spread to your main server. We stopped this before they reached it."\n\n` +
          `The key principle: **lead with impact and actions taken, not with technical mechanics**. The client needs to know: what happened to ME, what risk am I facing NOW, and what do I need to DO.`,
      },
      // ── Reading 2 ─────────────────────────────────────────────────────────
      {
        type: "reading",
        id: "cc-read-2",
        heading: "SLA Requirements, Notification Timelines, and Communication Channels",
        content:
          `An **SLA** (Service Level Agreement) is the contractual promise between the SOC and its client. It specifies exactly what the SOC will deliver and when. For incident notification, SLAs typically look like this:\n\n` +
          `- **P1 (Critical)**: A major active threat — ransomware spreading, confirmed data breach, CEO's account compromised. SLA requirement: **phone call within 15 minutes** of confirmation. This is a "wake someone up at 3am" event.\n` +
          `- **P2 (High)**: A confirmed threat that has been contained but requires client action — a single infected machine, a phishing campaign targeting employees. SLA requirement: **email notification within 1 hour**.\n` +
          `- **P3 (Medium)**: Suspicious activity requiring investigation — anomalous login from an unusual country, failed brute-force attempts. SLA requirement: **ticket update within 4 hours**.\n` +
          `- **P4 (Low)**: Informational findings — a vulnerability scan result, a policy violation. SLA requirement: **included in the weekly report**.\n\n` +
          `**Choosing the Right Communication Channel**\n\n` +
          `The severity of the incident dictates the communication method:\n\n` +
          `- **Phone call**: Reserved for P1/Critical. A phone call ensures the message is received immediately and allows for two-way conversation. Email can sit in an inbox for hours. For a ransomware infection actively spreading, hours matter enormously.\n` +
          `- **Email**: Good for P2/High and detailed follow-ups. Provides a written record, can include attachments (advisory documents, IOC lists), and doesn't require the recipient to be available immediately.\n` +
          `- **Ticket/portal update**: For P3/Medium and P4/Low. Clients can check at their convenience. Also used for ongoing incident updates even after the initial phone call.\n` +
          `- **Escalation bridge / war room**: For major P1 incidents involving multiple stakeholders, a video/phone conference may be established so the SOC team, client security team, and client leadership can all participate in the response simultaneously.\n\n` +
          `**Handling Client Pushback**\n\n` +
          `Not every client reaction to a security alert is "thank you, please proceed." Common pushback scenarios and how to handle them:\n\n` +
          `- **"Are you sure it's real? We don't want an overreaction."** — Walk through your evidence calmly and specifically. "Yes, we are confident. Here is why: [specific IOC evidence]. The risk of delaying action is [specific consequence]." Don't be intimidated by pushback — if you've done the analysis and you're confident, hold your ground professionally.\n` +
          `- **"Can you wait until business hours to isolate the machine? The user needs it."** — Explain the business risk of waiting. "If we wait, the malware may spread to additional systems, potentially including [shared drives / the file server / email]. We recommend isolating now and providing the user with a temporary device."\n` +
          `- **"This must be a false positive. Our systems are secure."** — Empathize but stay factual. "We understand this is unexpected. We've reviewed the evidence carefully and have high confidence this is a real incident. We recommend [action] and can walk you through the evidence if helpful."\n\n` +
          `**Drafting a Client Security Advisory**\n\n` +
          `After a P1 or P2 incident, a formal advisory is sent to the client. Structure:\n\n` +
          `1. **Incident Summary**: One paragraph, plain English, describing what happened\n` +
          `2. **Severity and Impact**: What systems were affected? Was data accessed?\n` +
          `3. **Actions Taken by SOC**: What we already did\n` +
          `4. **Actions Required by Client**: What the client must do now\n` +
          `5. **Current Risk Status**: Is the threat contained, or is there still active risk?\n` +
          `6. **Next Steps**: What happens next in the investigation/remediation`,
      },
      // ── Reading 3 ─────────────────────────────────────────────────────────
      {
        type: "reading",
        id: "cc-read-3",
        heading: "SLA Breaches, After-Action Reviews, and Building Client Trust",
        content:
          `No SOC operates perfectly 100% of the time. Analysts get overwhelmed during peak hours. Phone calls go unanswered. A P1 incident is misclassified as P2 initially. These things happen. What separates excellent SOC teams from average ones is how they handle the aftermath of a mistake.\n\n` +
          `An **SLA breach** occurs when the SOC fails to meet a contractual commitment. For example, if the SLA requires a P1 phone call within 15 minutes of incident confirmation, and the call happened at 18 minutes — that's a breach. Even a 3-minute breach is a breach.\n\n` +
          `**What to Do When an SLA Is Breached**\n\n` +
          `1. **Acknowledge it proactively**: Don't wait for the client to notice. Contact the client as soon as you realize the breach occurred and explain what happened.\n` +
          `2. **Apologize sincerely and specifically**: "We understand that our SLA requires a P1 notification call within 15 minutes. Our call came at 18 minutes. We apologize for the 3-minute delay. Here is what happened: [reason]." Vague apologies ("We're sorry for any inconvenience") feel dismissive.\n` +
          `3. **Explain the reason without making excuses**: There's a difference between an explanation and an excuse. An explanation helps the client understand and trust that you're analyzing the failure. An excuse sounds like you're deflecting responsibility.\n` +
          `4. **Describe corrective actions**: What are you doing to prevent this from happening again? "We are adjusting our P1 escalation workflow to include an automated page to the on-call lead if no phone call is logged within 12 minutes."\n\n` +
          `**The After-Action Review (AAR)**\n\n` +
          `After any significant incident, the SOC should offer the client an **After-Action Review** — a structured meeting to walk through what happened and what was learned. This is not a blame session; it is a collaborative improvement exercise.\n\n` +
          `AAR agenda:\n` +
          `- What happened? (Timeline review)\n` +
          `- What did we do well? (Acknowledge successes)\n` +
          `- What could have gone better? (Honest assessment)\n` +
          `- What are the action items going forward? (Concrete, assigned, with deadlines)\n\n` +
          `**Building Long-Term Client Trust**\n\n` +
          `Client trust is the most valuable asset in a SOC-as-a-Service relationship. Technical skills matter, but trust is what keeps clients renewing contracts and recommending your SOC to others. Trust is built through:\n\n` +
          `- **Consistency**: Every interaction — whether it's a P1 response or a routine monthly report — is handled with the same professionalism and care\n` +
          `- **Transparency**: Clients should never feel like they're being kept in the dark. Even when you don't have complete answers, communicate what you know and what you're doing to find out more\n` +
          `- **Proactivity**: Don't wait for clients to ask for status updates. Provide them on a cadence. If you notice something concerning that isn't quite at alert threshold yet, tell them\n` +
          `- **Competence**: Demonstrate your expertise by providing context that helps clients understand their risk posture — not just "here's an alert" but "here's what this means for your business"\n\n` +
          `Remember: from the client's perspective, their SOC is their most important security partner. They've trusted you with the most sensitive information about their systems. Every interaction is an opportunity to reinforce — or undermine — that trust.`,
      },
      // ── Question 1 ────────────────────────────────────────────────────────
      {
        type: "question",
        id: "cc-q1",
        question:
          "A client's CEO account has been confirmed compromised and is actively being used to send wire transfer requests. According to standard SLA tiers, which notification method should you use and what is the typical time requirement?",
        options: [
          "Send a P4 email and include it in the weekly report",
          "Update the ticket and wait for the client to check the portal",
          "Make a P1 phone call immediately — typically within 15 minutes of confirmation",
          "Send a P3 ticket update within 4 hours",
        ],
        answer: 2,
        explanation:
          "A compromised CEO account being used for wire transfer requests is a P1/Critical incident — an active threat with direct financial impact. The correct response is an immediate phone call, typically required within 15 minutes of confirmation under most MSSP SLAs. Email and ticket updates are too slow for a situation where every minute of delay could result in fraudulent financial transactions being completed.",
        xp: 15,
      },
      // ── Question 2 ────────────────────────────────────────────────────────
      {
        type: "question",
        id: "cc-q2",
        question:
          "An analyst drafts this client notification: 'We detected T1078 Valid Account usage with impossible travel IOA across your tenant.' What is the main problem with this notification?",
        options: [
          "The notification is too long and should be shorter",
          "T1078 is not a real MITRE ATT&CK technique",
          "The notification uses technical jargon (T1078, IOA, impossible travel) that most business contacts won't understand — it should be translated to plain language describing the impact",
          "The notification should include the analyst's personal phone number",
        ],
        answer: 2,
        explanation:
          "Client notifications should always be written in plain business language. Most client contacts (IT managers, executives, business owners) are not security specialists. 'T1078 Valid Account usage with impossible travel IOA' means nothing to them. A better version: 'We detected that one of your user accounts logged in from New York and Tokyo within the same hour — which is physically impossible. This is a strong indicator the account's credentials have been stolen. We have blocked the account pending investigation.'",
        xp: 20,
      },
      // ── Question 3 ────────────────────────────────────────────────────────
      {
        type: "question",
        id: "cc-q3",
        question:
          "A client says: 'We don't want you to isolate the infected machine. Our CFO needs it for a board presentation tomorrow morning.' What is the BEST response from the SOC analyst?",
        options: [
          "Immediately comply — the client's business needs always take absolute priority over security concerns",
          "Ignore the client and isolate the machine anyway without telling them",
          "Explain the specific business risk of leaving the machine connected (potential spread, data exposure), offer alternatives (temporary device for the CFO), and document the client's decision if they insist on waiting",
          "Escalate to Tier 3 and let them handle the client conversation",
        ],
        answer: 2,
        explanation:
          "The SOC's job is to protect the client, which sometimes means clearly communicating risks the client may not want to hear. The correct approach is to explain the specific risk of waiting (the malware could spread to file servers, steal board presentation materials, or compromise additional accounts), propose alternatives (can the CFO use a clean loaner device for the presentation?), and if the client insists on accepting the risk, document their decision in writing. This protects the client's autonomy while ensuring they make an informed choice.",
        xp: 20,
      },
      // ── Log Analysis ──────────────────────────────────────────────────────
      {
        type: "log_analysis",
        id: "cc-log-1",
        heading: "Analyzing an SLA Breach Event",
        context:
          "The SIEM has logged a client notification SLA tracking event for Acme Corp. This event was generated by the SOAR platform when it detected that a P1 incident notification did not occur within the required timeframe. Examine the details carefully.",
        event: {
          id: "evt-cc-001",
          ts: "2026-06-24T09:32:00.000Z",
          source: "siem",
          event_type: "edr_alert",
          hostname: "SOAR-PLATFORM-01",
          severity: "high",
          raw: {
            "sla.client_name": "Acme Corp",
            "sla.incident_id": "INC-2026-4892",
            "sla.severity": "P1",
            "sla.notification_required_minutes": 15,
            "sla.notification_sent_minutes": 18,
            "sla.breach": true,
            "sla.breach_reason":
              "Assigned analyst (r.cohen) was on a phone call with a different client (INC-2026-4881) when the P1 was confirmed. The P1 escalation pager was not acknowledged within the backup window.",
            "notification.channel": "phone",
            "notification.recipient": "client.security@acme.com",
            "notification.sent_at": "2026-06-24T09:32:00.000Z",
            "notification.confirmed_at": "2026-06-24T09:14:00.000Z",
            "notification.content_summary":
              "Informed client of active malware infection on WS-FINANCE-042. Confirmed host isolation action. Requested client to initiate internal IR protocol.",
            "escalation.backup_analyst_paged": "t.brooks",
            "escalation.backup_response_time_minutes": 18,
          },
        } as TelemetryEvent,
        questions: [
          {
            question:
              "According to the SLA log, why did the P1 notification breach occur?",
            options: [
              "The analyst forgot to check the ticketing system for new P1 incidents",
              "The assigned analyst was on a call with a different client when the P1 was confirmed, and the backup escalation pager was not acknowledged in time",
              "The client's phone was turned off and calls could not be received",
              "The SOAR platform experienced a technical outage that delayed notification",
            ],
            answer: 1,
            explanation:
              "The sla.breach_reason field clearly explains: analyst r.cohen was on a call with INC-2026-4881 (another client) when INC-2026-4892 was confirmed as P1. The P1 escalation pager was not acknowledged within the backup window, leading to the backup analyst (t.brooks) eventually making the call — but 3 minutes too late. This is a process gap: when the primary analyst is unavailable, the backup notification chain must trigger automatically and faster.",
            xp: 15,
          },
          {
            question:
              "The SLA required notification within 15 minutes (sla.notification_required_minutes). The notification was sent at 18 minutes (sla.notification_sent_minutes). By how many minutes was the SLA breached?",
            options: ["1 minute", "2 minutes", "3 minutes", "5 minutes"],
            answer: 2,
            explanation:
              "18 minutes (actual) minus 15 minutes (required) = 3 minutes over SLA. While this may seem small, SLA contracts are typically binary — either you met the requirement or you didn't. A 3-minute breach is still a formal SLA breach that must be acknowledged, documented, and remediated through process improvements to prevent recurrence.",
            xp: 15,
          },
        ],
      },
      // ── Analyst Choice — Customer SLA Notification ────────────────────────────
      {
        type: "analyst_choice" as const,
        id: "cc-ac1",
        heading: "Verdict: Does This Require an Immediate Customer SLA Notification?",
        scenario: "18:07 UTC. You are an MSSP analyst. Your client GlobalFinance Inc. experienced a confirmed ransomware detection on one workstation. The endpoint was isolated by EDR at 18:04 UTC. The attacker had access for approximately 6 minutes before isolation. No file encryption was confirmed by EDR (the ransomware was caught before encryption started). Your MSSP contract with GlobalFinance states: 'Tier 1 (Critical) incidents must be communicated to the client within 15 minutes of confirmation.' It is now 18:07 UTC — 3 minutes since isolation. What do you do?",
        event: {
          id: "evt-cc-ac-001",
          ts: "2026-06-19T18:07:22.000Z",
          source: "soar" as const,
          vendor: "ServiceNow ITSM",
          event_type: "edr_alert" as const,
          severity: "critical" as const,
          hostname: "WKSTN-GF-FINANCE-07",
          user_email: "d.levy@globalfinance.com",
          description: "Ransomware detected and isolated pre-encryption — SLA notification clock started at 18:04",
          mitre_technique: "T1486",
          mitre_tactic: "Impact",
          raw: {
            "client.name": "GlobalFinance Inc.",
            "client.tier": "enterprise",
            "incident.type": "ransomware",
            "incident.confirmed_at": "2026-06-19T18:04:00Z",
            "incident.current_time": "2026-06-19T18:07:22Z",
            "incident.minutes_since_confirmation": 3.37,
            "incident.classification": "T1 Critical",
            "edr.action": "isolated",
            "edr.encryption_confirmed": false,
            "edr.threat_name": "Ransom:Win64/BlackCat.B",
            "edr.attacker_dwell_minutes": 6,
            "sla.notification_required_minutes": 15,
            "sla.time_remaining_minutes": 11.63,
            "sla.clock_started": "2026-06-19T18:04:00Z",
            "sla.notification_sent": false,
          },
        },
        correct_verdict: "escalate",
        explanation: "Escalation to your supervisor and immediate start of the SLA notification process is correct. You have 11.6 minutes left before the SLA clock runs out. Even though the ransomware was stopped before encryption, a confirmed ransomware detection on a client endpoint IS a Tier 1 Critical incident per the contract — the fact that encryption was prevented does not downgrade the classification. The right sequence: (1) Start drafting the client notification now; (2) Alert your team lead so they can approve and send; (3) Document the timeline precisely because the client will ask. Waiting until you know more risks SLA breach — the contract says 'within 15 minutes of confirmation', not 'within 15 minutes of fully understanding the scope'.",
        fp_trap: "Because no files were encrypted and the attack was contained in 6 minutes, it is tempting to classify this as Informational or wait for more information before notifying the client. But MSSP contracts are precise: T1 Critical = ransomware detection, period. The containment outcome (good news) is included in the notification — it is not a reason to delay or skip it.",
        xp: 30,
      },
    ],
  },

  // ─── Room 4: Escalation Procedures ──────────────────────────────────────────
  {
    id: "escalation-procedures",
    title: "Escalation Procedures",
    description:
      "Understand when and how to escalate security incidents through the SOC tier structure — from initial Tier 1 triage all the way to external parties like CISA and law enforcement.",
    difficulty: "intermediate",
    category: "SOC Operations",
    estimatedMinutes: 35,
    xp: 130,
    icon: "🚨",
    prerequisites: ["alert-triage", "incident-response-methodology"],
    tasks: [
      // ── Reading 1 ─────────────────────────────────────────────────────────
      {
        type: "reading",
        id: "esc-read-1",
        heading: "The SOC Tier Structure: Tier 1, 2, and 3 Explained",
        content:
          `Think of a hospital emergency department. When you walk in with a potential emergency, a **triage nurse** (the first person you see) does a quick assessment: How serious is this? Can we handle it here, or does this patient need a specialist? Most patients are treated by general ER doctors. The complex cases go to specialists. The rarest, most critical cases may go to the Chief of Surgery or be transferred to a specialized trauma center.\n\n` +
          `A SOC uses the same principle. The **tier structure** distributes work by complexity and expertise:\n\n` +
          `**Tier 1 — Triage and Initial Analysis**\n\n` +
          `Tier 1 analysts are the triage nurses of the SOC. Their primary job is to monitor the SIEM alert queue, perform initial investigation, and make a quick determination: Is this a real threat or a false positive? Does this need more investigation?\n\n` +
          `Tier 1 responsibilities:\n` +
          `- Monitor the SIEM alert queue continuously\n` +
          `- Review and categorize incoming alerts (true positive, false positive, benign)\n` +
          `- Perform initial triage: look up IOCs in threat intelligence, review the alert context, check if the affected system is a known sensitive system\n` +
          `- Close clear false positives with documentation\n` +
          `- Create incident tickets for confirmed or suspected malicious activity\n` +
          `- Escalate confirmed or complex incidents to Tier 2\n\n` +
          `Tier 1 analysts typically work with predefined playbooks — step-by-step guides for investigating each type of alert. They don't have the authority to take high-impact actions like isolating servers or engaging law enforcement.\n\n` +
          `**Tier 2 — Deep Investigation**\n\n` +
          `Tier 2 analysts receive escalated incidents from Tier 1 and conduct in-depth forensic investigation. They have more experience, deeper technical skills, and broader access to security tools.\n\n` +
          `Tier 2 responsibilities:\n` +
          `- Deep-dive forensic analysis of compromised systems\n` +
          `- Malware analysis (static and dynamic)\n` +
          `- Correlation of activity across multiple systems to understand attack scope\n` +
          `- Host isolation authority — they can approve isolating endpoints from the network\n` +
          `- Communication with system owners and IT teams\n` +
          `- Developing containment and remediation plans\n` +
          `- Escalating to Tier 3 when the incident exceeds their scope\n\n` +
          `**Tier 3 — Threat Hunting and Forensics**\n\n` +
          `Tier 3 are the specialists — senior threat hunters, incident responders, and forensic experts. They handle the most complex investigations and proactively hunt for threats that haven't triggered any alerts yet.\n\n` +
          `Tier 3 responsibilities:\n` +
          `- Major incident response leadership\n` +
          `- Advanced malware reverse engineering\n` +
          `- Threat hunting across the environment\n` +
          `- Attribution research (which threat actor is this?)\n` +
          `- Developing new detection use cases based on findings\n` +
          `- Engagement with external parties (law enforcement, regulatory bodies, external IR firms)\n` +
          `- Executive communication during major incidents\n\n` +
          `The tier structure isn't about hierarchy for its own sake — it's about **efficiency and expertise matching**. If every alert went straight to Tier 3, the most experienced analysts would spend all day closing false positives. The tier structure ensures each analyst is working on problems matched to their skill level.`,
      },
      // ── Reading 2 ─────────────────────────────────────────────────────────
      {
        type: "reading",
        id: "esc-read-2",
        heading: "When to Escalate, When NOT to Escalate, and How to Do It Right",
        content:
          `Imagine a 911 emergency dispatcher. Their job is to route calls to the right resource: police, fire, ambulance — or sometimes, to explain to the caller that their situation doesn't actually require emergency services. A dispatcher who sends a fire truck to every call, whether it's a house fire or a cat in a tree, wastes resources and slows response to real emergencies. A dispatcher who under-routes and fails to send help to genuine emergencies can cost lives.\n\n` +
          `Escalation decisions work the same way. **Under-escalation** (keeping an incident at Tier 1 when it needs Tier 2 expertise) means the incident may not receive adequate response. **Over-escalation** (escalating every alert regardless of severity) floods Tier 2 with noise and trains them to deprioritize escalations from you.\n\n` +
          `**When to Escalate (Tier 1 → Tier 2)**\n\n` +
          `Escalate when:\n` +
          `- You have **confirmed malicious activity** — not just a suspicion, but clear evidence (a malicious file hash, confirmed C2 communication, confirmed lateral movement)\n` +
          `- The **scope exceeds your authority** — you need to isolate a server, but Tier 1 doesn't have that authority\n` +
          `- The investigation requires **specialized skills or tools** you don't have access to\n` +
          `- Multiple systems are involved — this suggests an active campaign, not an isolated incident\n` +
          `- **Legal or regulatory implications** are likely (data breach with PII, ransomware, suspected insider threat)\n` +
          `- The incident involves **sensitive systems** (domain controllers, financial systems, C-suite executives' devices)\n` +
          `- You've been investigating for the time limit specified in your playbook (usually 30-60 minutes) and cannot reach a conclusion\n\n` +
          `**When NOT to Escalate**\n\n` +
          `Do NOT escalate when:\n` +
          `- You have **confirmed it's a false positive** with clear evidence — document and close it yourself\n` +
          `- The alert is **covered by a playbook you can execute** yourself\n` +
          `- The activity is **benign and explained** (a scheduled task, a known admin tool, a patch management process)\n` +
          `- You're escalating because you're **uncertain** but haven't done the investigation steps in the playbook yet — do your playbook first\n\n` +
          `**How to Escalate Effectively**\n\n` +
          `A bad escalation: "Hey, got a weird alert on ticket INC-2026-4892. Can you look at it?"\n\n` +
          `A good escalation includes:\n` +
          `1. **Incident ID and title**: So Tier 2 can find it immediately\n` +
          `2. **What you found**: A concise summary of your investigation and findings\n` +
          `3. **Why you're escalating**: Exactly what requires Tier 2 attention\n` +
          `4. **Timeline**: When did the activity start? When did you detect it?\n` +
          `5. **Affected systems**: Hostnames, IP addresses, user accounts\n` +
          `6. **IOCs discovered**: Malicious file hashes, IPs, domains\n` +
          `7. **Actions taken so far**: What have you already done?\n` +
          `8. **Recommended next steps**: What do you think Tier 2 should do? (They may disagree, but showing your thinking demonstrates competence)\n\n` +
          `**Escalation Bridges for Major Incidents**\n\n` +
          `For P1 incidents affecting many systems, an **escalation bridge** (a conference call or video meeting with all stakeholders) may be established. All relevant parties join: the SOC Tier 2/3 lead, the client's security team, IT operations, and sometimes legal and executive stakeholders. The bridge allows real-time coordination during the chaos of a major incident. Think of it as a war room — everyone in the same (virtual) room, working the problem together.`,
      },
      // ── Reading 3 ─────────────────────────────────────────────────────────
      {
        type: "reading",
        id: "esc-read-3",
        heading: "Escalating to External Parties and Staying Engaged After Escalation",
        content:
          `Some incidents are too big, too complex, or have legal implications that require bringing in parties outside your own organization. Knowing when and how to escalate externally is an advanced skill — but even Tier 1 analysts should understand when to alert their managers that external escalation may be needed.\n\n` +
          `**External Escalation Parties**\n\n` +
          `- **CISA (Cybersecurity and Infrastructure Security Agency)**: The US government's primary cybersecurity agency. Organizations in critical infrastructure (energy, healthcare, financial services, water, transportation) are expected to report significant cyber incidents to CISA. CISA can provide technical assistance, share threat intelligence, and coordinate with law enforcement.\n\n` +
          `- **FBI and Law Enforcement**: If an incident involves criminal activity (ransomware, financial fraud, espionage, child exploitation material discovered on a system), the FBI's Internet Crime Complaint Center (IC3) or local FBI field office may need to be notified. Law enforcement involvement affects how you handle evidence — you must preserve chain of custody.\n\n` +
          `- **National CERTs (Computer Emergency Response Teams)**: Most countries have a national CERT. In a cross-border incident, working with the relevant national CERT can help with attribution, blocking, and legal processes in other jurisdictions.\n\n` +
          `- **External Incident Response Firms**: Organizations that have been severely compromised may bring in specialist firms (like Mandiant, CrowdStrike Services, or Palo Alto Unit 42) for large-scale forensic investigation that exceeds the internal team's capacity.\n\n` +
          `- **Insurance Carrier**: If the organization has cyber insurance, the insurance carrier must typically be notified promptly after a significant incident. Many carriers have their own IR firms they will deploy. Failing to notify in time can invalidate the claim.\n\n` +
          `- **Regulatory Bodies**: Depending on the industry, incidents may need to be reported to regulators — the SEC, FTC, state attorneys general, GDPR supervisory authorities in EU, and others. Each has specific notification timelines (GDPR: 72 hours; some US state laws: as little as 30 days).\n\n` +
          `**Staying Engaged After Escalation**\n\n` +
          `One of the most common mistakes junior analysts make after escalating is mentally disengaging from the incident — "I handed it off, someone else is dealing with it now." This is wrong for several reasons:\n\n` +
          `- **You have context no one else does**: You investigated this first. You know what the alert looked like, what you checked, what seemed unusual. That context is valuable even after escalation.\n` +
          `- **Tier 2 may have questions**: Be available to answer them. Don't disappear into your other alerts and become unreachable.\n` +
          `- **You should be learning**: Watching how Tier 2 handles the investigation and what they find is one of the best learning opportunities in a SOC. Stay involved as an observer if they'll allow it.\n` +
          `- **Handover your notes, not the incident**: Hand over the context, but remain a resource. The incident belongs to the whole team until it's closed.\n\n` +
          `**24/7 Escalation Contacts and Runbooks**\n\n` +
          `Every SOC must maintain a current, tested escalation contact list covering:\n` +
          `- Tier 2 on-call rotation (with backup contacts)\n` +
          `- SOC Manager (24/7 reachable)\n` +
          `- Legal counsel (after-hours emergency contact)\n` +
          `- Cyber insurance carrier (24/7 incident hotline)\n` +
          `- Key client security contacts\n` +
          `- External IR firm retainer contact\n\n` +
          `These contacts must be tested quarterly — a phone number that's been disconnected for six months is worthless at 2am during a ransomware outbreak. Runbooks (step-by-step procedural guides) for each escalation scenario ensure that even a brand-new analyst can follow the correct process under pressure.`,
      },
      // ── Question 1 ────────────────────────────────────────────────────────
      {
        type: "question",
        id: "esc-q1",
        question:
          "A Tier 1 analyst receives an alert about a single failed login attempt on a user account. The analyst checks the playbook: this is a known false positive pattern during the company's morning VPN authentication (many users retry once if they mistype their password). What should the analyst do?",
        options: [
          "Immediately escalate to Tier 2 — any authentication failure could indicate a brute-force attack",
          "Escalate to Tier 3 and open a full forensic investigation",
          "Document the investigation finding and close the ticket as a false positive — escalating every single failed login would flood Tier 2 with noise",
          "Call the affected user and demand an explanation for the failed login",
        ],
        answer: 2,
        explanation:
          "A single failed login that matches a known false positive pattern documented in the playbook does not need escalation. The Tier 1 analyst's job is to filter noise — confirming that this alert matches the known pattern, documenting the finding, and closing it. Escalating every failed login to Tier 2 is a classic example of over-escalation that degrades team efficiency. Escalation is for confirmed threats or situations exceeding Tier 1 authority.",
        xp: 15,
      },
      // ── Question 2 ────────────────────────────────────────────────────────
      {
        type: "question",
        id: "esc-q2",
        question:
          "What is the PRIMARY purpose of an 'escalation bridge' in a major P1 incident?",
        options: [
          "A network bridge device that physically separates the attacker's traffic from clean traffic",
          "A conference call or war room meeting that brings all relevant stakeholders together for real-time coordination during a major incident",
          "A document template used to formally hand over an incident from Tier 1 to Tier 2",
          "A backup SIEM system that activates when the primary SIEM is overwhelmed",
        ],
        answer: 1,
        explanation:
          "An escalation bridge is a term for a war room call — a conference call or video meeting that gathers all relevant parties (SOC leads, client security team, IT operations, sometimes legal and executives) to coordinate response in real time. It's used during P1 major incidents where many decisions need to be made simultaneously and rapid communication is critical. The term 'bridge' comes from telephone conferencing terminology.",
        xp: 15,
      },
      // ── Question 3 ────────────────────────────────────────────────────────
      {
        type: "question",
        id: "esc-q3",
        question:
          "A Tier 1 analyst confirms active ransomware spreading across 12 endpoints. The analyst escalates to Tier 2. After handing over the ticket, what should the Tier 1 analyst do?",
        options: [
          "Log off and end their shift — the incident has been handed to Tier 2 so it's no longer their responsibility",
          "Remain available as a resource, provide context to Tier 2 when asked, and use the experience as a learning opportunity — while continuing to monitor the alert queue for related activity",
          "Immediately call the client directly to inform them, bypassing the Tier 2 and Tier 3 chain of command",
          "Delete their investigation notes to avoid confusing Tier 2 with conflicting information",
        ],
        answer: 1,
        explanation:
          "Escalation transfers ownership, not responsibility for being a resource. The Tier 1 analyst who first investigated the incident has valuable context that Tier 2 will need. They should remain available, answer questions, and continue monitoring the alert queue for related indicators (ransomware campaigns often trigger multiple alerts). Disappearing after escalation is one of the most common and most harmful habits in SOC work. Additionally, watching Tier 2 handle a complex investigation is invaluable for professional development.",
        xp: 20,
      },
      // ── Log Analysis ──────────────────────────────────────────────────────
      {
        type: "log_analysis",
        id: "esc-log-1",
        heading: "Analyzing a Tier 1 to Tier 2 Escalation Event",
        context:
          "The SIEM has logged an escalation event. A Tier 1 analyst has escalated an active incident to Tier 2. Examine the escalation record carefully — this represents best practice for how escalations should be documented.",
        event: {
          id: "evt-esc-001",
          ts: "2026-06-24T09:45:00.000Z",
          source: "siem",
          event_type: "edr_alert",
          hostname: "SOAR-PLATFORM-01",
          severity: "critical",
          raw: {
            "escalation.from_tier": 1,
            "escalation.to_tier": 2,
            "escalation.incident_id": "INC-2026-4892",
            "escalation.reason":
              "Confirmed ransomware encryption on 12 hosts, requires isolation authority. Maze ransomware variant identified by EDR (beacon_x64.dll + maze-ransomware.exe). C2 traffic to 185.220.101.47:443. Tier 1 playbook exhausted.",
            "escalation.analyst": "r.cohen",
            "escalation.timestamp": "2026-06-24T09:45:00.000Z",
            "escalation.severity": "P1",
            "escalation.affected_hosts_count": 12,
            "escalation.iocs": [
              "maze-ransomware.exe",
              "185.220.101.47",
              "beacon_x64.dll",
              "sha256:a87ff679a2f3e71d9181a67b7542122c",
            ],
            "escalation.actions_taken_by_tier1": [
              "Alert acknowledged at 09:14 UTC",
              "IOCs looked up in threat intel — confirmed Maze ransomware",
              "Ticket INC-2026-4892 created at 09:17 UTC",
              "Client notification sent at 09:32 UTC (P1 SLA — 18 min, 3 min breach)",
              "Identified 12 affected hosts via SIEM correlation",
              "Attempted to block C2 IP 185.220.101.47 — requires Tier 2 firewall authority",
            ],
            "escalation.analyst_notes":
              "Ransomware appears to have originated from WS-FINANCE-042 (initial execution at 09:14 UTC) and spread laterally via SMB shares. All 12 affected hosts are on the FINANCE VLAN (10.10.5.0/24). Domain controller SRV-DC-01 is NOT yet affected. Recommend immediate VLAN isolation to contain spread before DC is compromised.",
          },
        } as TelemetryEvent,
        questions: [
          {
            question:
              "According to the escalation log, why did Tier 1 analyst r.cohen escalate this incident to Tier 2? Select the MOST complete answer.",
            options: [
              "Because the analyst was not sure if it was a real incident",
              "Because confirmed ransomware encryption was active on 12 hosts and isolation authority (to block at the firewall and isolate the VLAN) exceeds Tier 1 authority — and the Tier 1 playbook was exhausted",
              "Because the analyst wanted to go on break and needed someone else to watch the ticket",
              "Because the client had not yet been notified and only Tier 2 can call clients",
            ],
            answer: 1,
            explanation:
              "The escalation.reason field is explicit: confirmed ransomware on 12 hosts, isolation authority required (blocking at the firewall and potentially isolating a VLAN are high-impact actions that require Tier 2 authorization), and the Tier 1 playbook was exhausted. This is a textbook correct escalation — the analyst confirmed the threat, documented what they found, took the actions within their authority (creating the ticket, client notification, threat intel lookup), and escalated when they hit the boundary of their authorization.",
            xp: 20,
          },
          {
            question:
              "The analyst notes mention that 'Domain controller SRV-DC-01 is NOT yet affected.' Why is this information critical to include in the escalation?",
            options: [
              "It's not important — once ransomware is on 12 hosts, the domain controller doesn't matter",
              "The domain controller holds the master keys to the entire environment — if ransomware reaches it, it can encrypt credentials for all users and potentially spread to every system. Its current clean status defines the containment priority and urgency.",
              "Domain controllers automatically block ransomware, so this note is just confirming the domain controller is doing its job",
              "This information should not be in the escalation — it could create panic if Tier 2 reads it",
            ],
            answer: 1,
            explanation:
              "The Domain Controller (DC) is arguably the most critical server in a Windows environment. It controls authentication for all user accounts and systems. If ransomware reaches the DC, it can: encrypt the Active Directory database (rendering all logins impossible), use DC credentials to spread to every server in the domain, and make recovery dramatically more difficult. The analyst's note that the DC is 'NOT yet affected' tells Tier 2: you still have time, but VLAN isolation is urgent. This is precisely the kind of context that makes an escalation excellent rather than just adequate.",
            xp: 25,
          },
        ],
      },
      // ── Analyst Choice — Escalation Tier Decision ─────────────────────────────
      {
        type: "analyst_choice" as const,
        id: "esc-ac1",
        heading: "Verdict: Handle It Yourself or Escalate to Tier 2?",
        scenario: "02:30 AM. You are a Tier-1 analyst on night shift. You confirmed active ransomware on 12 hosts — file encryption is in progress. You have already: blocked the C2 IP at the firewall, submitted isolation commands via EDR for all 12 hosts (7 confirmed isolated, 5 pending). You can see 3 more hosts just started exhibiting the same pattern. You are the only analyst on shift. Your Tier-2 on-call is available but it will wake them at 2:30 AM. The MSSP runbook says 'escalate T1 incidents immediately after confirmation'. What is your verdict?",
        event: {
          id: "evt-esc-ac-001",
          ts: "2026-06-21T02:30:44.000Z",
          source: "soar" as const,
          vendor: "Palo Alto Cortex XSOAR",
          event_type: "edr_alert" as const,
          severity: "critical" as const,
          hostname: "SOAR-CONSOLE-01",
          user_email: "night-analyst@mssp.com",
          description: "Active ransomware spreading — 12 confirmed hosts, 3 new, T1 solo analyst at 2:30 AM",
          mitre_technique: "T1486",
          mitre_tactic: "Impact",
          raw: {
            "incident.type": "ransomware_active",
            "incident.confirmed_at": "2026-06-21T02:22:00Z",
            "escalation.affected_hosts_count": 12,
            "escalation.new_hosts_last_5min": 3,
            "escalation.isolation_completed": 7,
            "escalation.isolation_pending": 5,
            "escalation.c2_ip_blocked": true,
            "escalation.c2_ip": "185.220.101.47",
            "escalation.lateral_movement_active": true,
            "analyst.shift": "night",
            "analyst.tier": "T1",
            "analyst.on_shift_count": 1,
            "runbook.t1_escalation_trigger": "confirmed_critical_incident",
            "runbook.escalation_required": true,
            "tier2.oncall.available": true,
            "tier2.oncall.name": "r.goldberg@mssp.com",
            "rule.name": "Ransomware_Active_Spread_Critical",
            "rule.level": 15,
          },
        },
        correct_verdict: "escalate",
        explanation: "Escalate immediately — this is the textbook Tier-2 escalation scenario. The runbook explicitly requires escalation for confirmed T1 incidents. With active lateral movement spreading to 3 new hosts, you are a solo Tier-1 analyst managing 15 affected hosts at 2:30 AM — the scope is exceeding what a single analyst can effectively handle. Tier-2 will: (a) take incident command; (b) coordinate with the client's IT team for domain-wide isolation; (c) trigger crisis communication; (d) begin forensic investigation. The concern about 'waking someone at 2:30 AM' is exactly the feeling that causes incidents to spiral — T2 on-call signed up to be woken for exactly this situation. 'I already blocked C2 and isolated some hosts' is a good briefing to give T2, not a reason to delay the call.",
        fp_trap: "You've already taken good containment steps (C2 blocked, isolation commands sent) and might feel the situation is 'under control'. But 5 hosts are still pending isolation, 3 new hosts just appeared, and you are alone at 2:30 AM. The runbook exists precisely because in high-pressure situations, solo analysts underestimate scope. Escalation is not admitting failure — it is the correct process for a T1 Critical incident.",
        xp: 35,
      },
    ],
  },
];

export default rooms;
