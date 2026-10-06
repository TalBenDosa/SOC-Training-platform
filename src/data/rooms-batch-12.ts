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
        checkpoint: {
          question: "According to the reading, what are the six core components of a use case?",
          options: [
            "Hypothesis, Data Source, Detection Logic, Severity, Response Playbook, Exceptions",
            "Hypothesis, Data Source, Detection Logic, Unit Testing, Tuning, Deployment",
            "Rule ID, ATT&CK Technique, Data Sources, Status, False-Positive Rate, Owner",
            "Title, Logsource, Detection Logic, False Positives, Severity Level, ATT&CK Tags",
          ],
          answer: 0,
          explanation:
            "The reading's six components are Hypothesis, Data Source, Detection Logic, Severity, Response Playbook and Exceptions/Suppressions. “Hypothesis ... Testing, Tuning, Deployment” mixes in stages of the use-case lifecycle, which describe how a use case is built, not what it contains. “Rule ID ... Owner” lists fields of the Use Case Registry that tracks use cases. “Title, Logsource, Detection ...” are sections of a Sigma rule, which is only one way to express the Detection Logic component.",
        },
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
        checkpoint: {
          question: "According to the reading, what problem does Sigma solve for detection engineers?",
          options: [
            "It tests each rule against production traffic, so red- and purple-team validation is no longer needed",
            "It gives a vendor-neutral YAML format that converters turn into each SIEM's own query language",
            "It replaces ATT&CK as the technique catalogue, because each rule carries its own tactic taxonomy",
            "It makes rules run faster, because the SIEM executes the YAML instead of its native query language",
          ],
          answer: 1,
          explanation:
            "The reading frames Sigma's job as ending vendor lock-in: write the logic once in YAML, and converters such as pySigma translate it for Splunk, Sentinel or Elastic. “Tests each rule against production traffic” is wrong — the same reading says every rule still needs unit, red-team, purple-team or replay testing. “Replaces ATT&CK” reverses the relationship: rules reference ATT&CK technique IDs rather than replacing the catalogue. “Makes rules run faster” is wrong because the SIEM runs the converted native query, never the YAML.",
        },
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
          "The SIEM purges rules with no documented owner once the creating account is deactivated, so the detection stops running",
          "Detection coverage is lost with the analyst, because the logic, purpose and tuning were never formalized in a Use Case Registry",
          "The rule's alerts will route to the departed analyst's deactivated mailbox, so every future alert is silently dropped",
          "Other analysts will edit the rule without understanding it and push a conflicting version that overloads the SIEM",
        ],
        answer: 1,
        explanation:
          "The reading's point is “if it's not documented, it doesn't exist”: when the author leaves, nobody knows the rule exists, what it is for, or how to maintain it. As the environment changes, it decays unnoticed, and nobody can answer “are we detecting this threat?”. The other options invent platform behaviour. “The SIEM purges rules with no documented owner” and “alerts will route to the departed analyst's deactivated mailbox” are not how SIEM rules work, and neither is the risk the reading describes. “Other analysts will edit the rule ... overloads the SIEM” is a change-control worry, not the loss of knowledge that undocumented rules cause.",
        xp: 20,
      },
      // ── Question 2 ────────────────────────────────────────────────────────
      {
        type: "question",
        id: "ucd-q2",
        question:
          "You are writing the Sigma version of the Encoded PowerShell use case. Your IT team legitimately runs encoded PowerShell during patching, and you want analysts to know to rule that out first — WITHOUT changing what the rule matches. Which Sigma section does this go in?",
        options: [
          "detection — add the patching scripts there so the rule records them as known activity",
          "falsepositives — list the IT patching scripts as a known benign trigger to check first",
          "references — link the IT patching runbook so analysts can look up the scripts later",
          "logsource — scope the rule to the IT team's patch servers so their logs are labelled",
        ],
        answer: 1,
        explanation:
          "Reading 2 defines `falsepositives` as known benign triggers to be aware of — documentation for the analyst that leaves the matching logic untouched. “detection” is where the field values that trigger the alert live, so anything placed there changes what fires, which the stem rules out. “references” holds CVE links, blog posts and ATT&CK IDs about the threat, not triage guidance. “logsource” selects which product or category of logs the rule searches; changing it would alter (and here, break) what the rule matches.",
        xp: 20,
      },
      // ── Question 3 ────────────────────────────────────────────────────────
      {
        type: "question",
        id: "ucd-q3",
        question:
          "Your use case for detecting brute-force attacks fires when 5 failed logins occur within 10 minutes from a single account. After a company merger, the rule now generates 500 false-positive alerts per day — all from legitimate password resets for newly onboarded users. What should you do FIRST?",
        options: [
          "Disable the rule for the duration of the onboarding wave, then re-enable it once password-reset volume returns to normal",
          "Route the daily alert batch to Tier 3 for manual review until the merger's onboarding wave completes and volume subsides",
          "Tune the rule: add a scoped exception for the onboarding reset process or adjust the threshold, keeping it live",
          "Rewrite the detection from scratch with a fixed threshold of 50 failures, and retire the original use case immediately",
        ],
        answer: 2,
        explanation:
          "A merger is one of the reading's named causes of use-case decay, and the lifecycle's answer is to tune: a scoped exception for the onboarding reset flow, or an adjusted threshold, keeps the detection running. “Disable the rule for the duration of the onboarding wave” leaves you blind to real brute force exactly when new, unfamiliar accounts are most exposed. “Route the daily alert batch to Tier 3” buries senior analysts in 500 known false positives instead of fixing the cause. “Rewrite the detection from scratch with a fixed threshold of 50” overcorrects: a fixed 50 would miss most real attacks, and an untested rewrite skips the lifecycle.",
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
              "Triage later shows that your IT patching tool also launches encoded PowerShell on every workstation each Tuesday, flooding UC-ENDPOINT-0089. Which suppression cuts that noise WITHOUT blinding the rule to an alert like this one?",
            options: [
              "Suppress any alert where the parent process is cmd.exe, since patching scripts are usually started from a shell",
              "Suppress alerts from hosts outside the IT department, since only IT is expected to run encoded PowerShell",
              "Suppress alerts whose command line includes -WindowStyle Hidden, since patch jobs run without a visible window",
              "Suppress only the patching tool's own parent process and service account, scoped to its patch window",
            ],
            answer: 3,
            explanation:
              "A good exception describes the known-good activity as narrowly as possible: the patch tool's specific parent process and account, inside its window. Anything else still alerts, including this event. “Parent process is cmd.exe” would silence this very alert, whose parent is cmd.exe. “Hosts outside the IT department” is backwards — it would suppress WS-FINANCE-042, where this alert fired. “-WindowStyle Hidden” would also hide this event, which uses exactly that flag. Every exclusion is a potential blind spot, so it should be scoped to what was observed and documented in the registry.",
            xp: 25,
          },
          {
            question:
              "The process is running from C:\\Windows\\Temp and its parent is cmd.exe. Why does this combination increase the severity of this alert?",
            options: [
              "Running from C:\\Windows\\Temp shows the process already holds admin rights, so privilege escalation has happened",
              "A cmd.exe parent shows the user typed this at a prompt by hand, which points to a deliberate insider action",
              "Real scripts rarely run from Temp, and cmd.exe starting hidden, encoded PowerShell is a common staging chain",
              "Temp is where browsers save downloads, so the working directory proves the user opened a phishing attachment",
            ],
            answer: 2,
            explanation:
              "Legitimate enterprise scripts run from known script or application folders. A writable Temp directory plus a cmd.exe parent launching hidden, encoded PowerShell is a common attacker staging chain, so the context raises confidence beyond the -enc match alone. “Already holds admin rights” is wrong: ordinary users can write to and run from Temp, which is exactly why attackers use it. “Typed this at a prompt by hand” misreads the parent: scripts, macros and droppers start cmd.exe all the time. “Temp is where browsers save downloads” is false — browsers use the user's Downloads folder, and the working directory alone proves nothing about phishing.",
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
            right: "T1027.010 — Obfuscated Files or Information: Command Obfuscation",
          },
          {
            id: "lsass",
            left: "Process opening a full-access handle to LSASS.exe memory (GrantedAccess 0x1FFFFF = PROCESS_ALL_ACCESS)",
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
        explanation: "Mapping observables to ATT&CK techniques is the foundation of use case development. A good use case starts with 'what can I actually see in logs?' and maps that observable to ATT&CK. This matters because: (1) it tells you whether you have log coverage for that technique; (2) it enables MITRE ATT&CK Navigator heatmaps showing your detection gaps; (3) it provides standardized language for reporting across teams. The mapping is not always 1:1 — some techniques (like T1059 Command and Scripting Interpreter) appear in dozens of use cases depending on the specific command interpreter used. The encoded-PowerShell observable is an example: the obfuscation itself maps to T1027.010, while the same use case (UC-ENDPOINT-0089 in the log analysis) is also tagged T1059.001 for the PowerShell execution it rides on — both tags are correct.",
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
        checkpoint: {
          question: "An analyst isolates an infected host and stops the attack, but writes nothing in the ticket. Based on the reading, why is this treated as a serious failure even though the threat is gone?",
          options: [
            "With no record there is no audit trail, evidence or handover, so in practice the response did not happen",
            "The containment is not technically complete until a ticket entry confirms the host isolation",
            "It only distorts the shift's KPI dashboard, since uncounted incidents make the alert volume look lower",
            "It breaks the rule that a contained incident needs a verbal handover to the shift lead before closure",
          ],
          answer: 0,
          explanation:
            "The reading's rule is “if it's not documented, it didn't happen”: without a written record there is no audit trail or legal evidence, no shift continuity and no knowledge transfer. Containment is a technical state of the host, not something a ticket entry completes. The KPI effect is real but minor next to the lost evidence and context. The reading never says a verbal handover replaces documentation; the handover itself is a written report.",
        },
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
          `- **SLA Compliance**: Are you meeting your Service Level Agreement commitments? (e.g., P1 incidents must be acknowledged within 15 minutes). A breached SLA is itself a reportable finding: most SOCs do not let the assigned analyst close a ticket whose SLA was breached on their own — the breach must be recorded in the ticket and the ticket escalated to a shift lead or SOC manager for review and sign-off before closure, even when the underlying incident is fully contained.\n\n` +
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
        checkpoint: {
          question: "According to the reading, what does MTTD (Mean Time to Detect) measure?",
          options: [
            "How long from when an alert is detected until the incident is fully contained",
            "How long, on average, from when an attack begins until the SOC detects it",
            "How many alerts the SIEM generates per day",
            "The percentage of alerts that turn out to be false positives",
          ],
          answer: 1,
          explanation:
            "MTTD measures the time from when an attack actually begins until the SOC detects it. MTTR (Mean Time to Respond) is the separate metric covering detection through containment and resolution.",
        },
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
      // ── Reading 4 ─────────────────────────────────────────────────────────
      {
        type: "reading",
        id: "rep-read-4",
        heading: "SOC Metrics in Practice: MTTA, MTTR, Dwell Time, and What 'Good' Looks Like",
        content:
          `Picture the dashboard analogy from before, but now zoom into three of the most cited numbers on it: MTTA, MTTR, and dwell time. These three metrics tell very different stories, and mixing them up is one of the most common mistakes new analysts make when reading a report — or a vendor's marketing deck.\n\n` +
          `**MTTA — Mean Time to Acknowledge**\n\n` +
          `MTTA measures the gap between two moments: when an alert is generated, and when an analyst actually looks at it — opens it, starts triaging, effectively says "I am on this." The formula is simple:\n\n` +
          `MTTA = (time the alert was acknowledged) − (time the alert was generated)\n\n` +
          `A short MTTA means alerts aren't sitting untouched in a queue. A long MTTA is often the first sign of a staffing gap, alert fatigue, or a shift-coverage problem — nobody was actively watching the queue when the alert came in.\n\n` +
          `**MTTR — Mean Time to Respond (or Resolve — know the difference)**\n\n` +
          `This is where new analysts get tripped up, because "MTTR" is used to mean two different things depending on which vendor dashboard or which report you're reading:\n\n` +
          `- Mean Time to Respond: from alert generation until the analyst takes the FIRST containment action (isolating a host, disabling an account, blocking an IP).\n` +
          `- Mean Time to Resolve: from alert generation until the incident is FULLY closed — remediation complete, ticket closed, root cause documented.\n\n` +
          `Both are legitimate metrics, but they measure different things and can differ by hours or even days on the very same incident. Whenever you see an MTTR figure in a report, ask which definition is being used before comparing it to another team's number or to an SLA target — comparing a "first action" MTTR against someone else's "fully resolved" MTTR will make one team look far better than it actually is.\n\n` +
          `**Dwell Time — the hardest number to measure honestly**\n\n` +
          `Dwell time differs from MTTA and MTTR in an important way: it does not start at the alert. It starts at the attacker's actual first foothold — the moment a phishing attachment was opened, a vulnerable service was exploited, or a stolen credential was first used.\n\n` +
          `Dwell Time = (time of detection) − (time of the attacker's actual initial compromise)\n\n` +
          `The honest problem with dwell time is that you usually don't know the true initial-compromise timestamp until well into the investigation — sometimes only during a deep forensic timeline reconstruction, days later, once the team traces the attacker's activity backward through logs that predate the alert itself. Early in an incident, any dwell-time figure you quote is a working estimate, not a fact, and it should be revised as the investigation timeline gets refined.\n\n` +
          `**Worked Example**\n\n` +
          `Timeline reconstructed for a single incident:\n\n` +
          `- 08:02 UTC — user opens a phishing attachment (later confirmed, during investigation, to be the true initial compromise)\n` +
          `- 09:47 UTC — SIEM correlation rule fires an alert for suspicious lateral movement from that user's workstation\n` +
          `- 09:52 UTC — the on-shift analyst opens the alert and begins triage\n` +
          `- 10:20 UTC — the analyst isolates the workstation, containing the threat\n\n` +
          `From these four timestamps:\n\n` +
          `- MTTA = 09:52 − 09:47 = 5 minutes\n` +
          `- MTTR (Respond) = 10:20 − 09:47 = 33 minutes\n` +
          `- Dwell Time = 09:47 − 08:02 = 1 hour 45 minutes\n\n` +
          `Notice that the attacker had nearly two hours of unnoticed access before the SIEM ever fired an alert — and that gap, not the analyst's 5-minute acknowledgment time, is usually the number that matters most to leadership, because it's the window the attacker actually had to move laterally, escalate privileges, or exfiltrate data.\n\n` +
          `**What "Good" Looks Like — Without Fake Precision**\n\n` +
          `Be skeptical of any single figure presented as "the industry average" for these metrics. Dwell time in particular varies enormously by sector, attacker sophistication, and how mature the organization's detection program is, so a bare number quoted without context tells you almost nothing. As a general rule of thumb, mature SOC programs commonly aim for MTTA measured in minutes rather than hours for Critical-severity alerts, and MTTR targets vary widely depending on incident type, organization size, and which definition of "resolve" is being used. Treat any precise-sounding statistic you encounter in a vendor report or conference talk with healthy skepticism, and always ask exactly what was measured before comparing it to your own numbers.\n\n` +
          `**Why This Matters for the Reports You'll Write**\n\n` +
          `These aren't abstract numbers — they're exactly what SLA commitments are built around (recall the P1-acknowledgment target from the earlier reading), and exactly what belongs in a shift handover report for any incident still open at the end of your shift: when it was detected, when it was acknowledged, what's been done so far, and — once known — when the attacker's actual foothold began. A handover that carries those timestamps forward lets the next analyst immediately see how the clock is running against the SLA, instead of having to reconstruct the timeline themselves.`,
        checkpoint: {
          question:
            "An alert is generated at 14:10. An analyst opens and begins triaging it at 14:16. Based on the reading's definition, what is the MTTA for this alert?",
          options: ["10 minutes", "16 minutes", "6 minutes", "24 minutes"],
          answer: 2,
          explanation:
            "MTTA = time acknowledged − time generated = 14:16 − 14:10 = 6 minutes. The other options confuse MTTA with the raw clock times shown (14:10 and 14:16) or simply pick an unrelated figure — MTTA is always the difference between the two timestamps, not either timestamp on its own.",
        },
      },
      // ── Question 1 ────────────────────────────────────────────────────────
      {
        type: "question",
        id: "rep-q1",
        question:
          "An analyst responds to a ransomware incident, successfully contains it, and closes the ticket with only the note: 'Ransomware. Cleaned up.' What is the PRIMARY problem with this documentation?",
        options: [
          "It does not name the ransomware family, which the ticket needs before the incident can be categorised",
          "It records no timeline, affected systems, IOCs, actions or root cause, so the record cannot be audited",
          "It belongs in the shift handover report instead, since a contained incident no longer needs a full ticket",
          "It lacks the plain-language executive summary, which has to be written into the ticket before closure",
        ],
        answer: 1,
        explanation:
          "A ticket note must answer Who, What, When, Where, Why and How. “Ransomware. Cleaned up.” answers none of them, so auditors, legal and the next analyst have no usable record. The ransomware family is a useful detail, but the category (Malware) can be set without it, and its absence is not the main gap. Contained incidents still need a full ticket; the handover report only summarises open work. The executive summary is a separate management deliverable for significant incidents, not a field of the ticket note.",
        xp: 15,
      },
      // ── Question 2 ────────────────────────────────────────────────────────
      {
        type: "question",
        id: "rep-q2",
        question:
          "Forensics later shows a stolen VPN credential was first used at 06:40 UTC. The SIEM alert fired at 08:10, the analyst opened it at 08:25, and the account was disabled at 08:55. Using Reading 4's definitions, what is the dwell time for this incident?",
        options: [
          "15 minutes",
          "1 hour 30 minutes",
          "2 hours 15 minutes",
          "45 minutes",
        ],
        answer: 1,
        explanation:
          "Dwell time = detection − actual initial compromise = 08:10 − 06:40 = 1 hour 30 minutes. “15 minutes” is the MTTA (08:25 − 08:10). “45 minutes” is MTTR in the respond sense (08:55 − 08:10, alert to first containment). “2 hours 15 minutes” runs from the compromise to containment, which is not one of the reading's metrics, because dwell time stops at detection.",
        xp: 15,
      },
      // ── Question 3 ────────────────────────────────────────────────────────
      {
        type: "question",
        id: "rep-q3",
        question:
          "Your SOC's SIEM generates 10,000 alerts in a week. After investigation, analysts determine that 9,200 of those alerts were false positives. What is the false positive rate, and what does this indicate?",
        options: [
          "0.8% — computed by dividing the 800 true positives by ten thousand, which shows very few false alarms",
          "92% — most alert volume is noise, which indicates poorly tuned rules that waste significant analyst time",
          "92% — normal for a mature SOC, because broad rules deliberately trade precision for coverage and need no tuning",
          "8% — the share of alerts that were true positives, which indicates accurate rules that need little tuning",
        ],
        answer: 1,
        explanation:
          "9,200 false positives out of 10,000 alerts = 92%. Reading 2 says an FP rate above 90% is a sign of poorly tuned rules that waste analyst time, so the response is to review and tune the noisiest rules. “0.8%” divides the wrong numbers (800 is the true-positive count, and 800/10,000 is 8%, not 0.8%). “8%” is the true-positive share, not the FP rate. “Normal for a mature SOC” contradicts the reading: a rate this high is a tuning problem, not a deliberate design choice.",
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
              "sha256:f7b63c44b8e2b9971038b203697077bd8efb008c439bc08d79ca702884769afd",
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
              "Legal asks whether this ticket could support a later legal proceeding. Based on Reading 3, which gap in the ticket matters most for that purpose?",
            options: [
              "The IOC list names the C2 address, and IOCs should be removed from a ticket once legal is involved",
              "The root cause names the user's action, which a blameless review requires to be taken out of the record",
              "The memory dump has no recorded collector, hash or storage location, so its chain of custody is unproven",
              "The lessons_learned field is too brief to count as the post-incident review the ticket requires",
            ],
            answer: 2,
            explanation:
              "Reading 3 says that for evidence that may reach a legal proceeding you must document chain of custody (who collected it, when, how it was stored) and hash forensic images to prove integrity. The ticket only says “Memory dump collected at 09:45 UTC”, with no collector, hash or storage location. IOCs are core ticket content and are not removed for legal hold. “Blameless” describes how a post-incident review is run, not deleting facts from the record. The lessons-learned entry is brief, but the post-incident review is a separate process, and its length does not affect whether the evidence holds up.",
            xp: 15,
          },
          {
            question:
              "Treat ticket.created_at as the alert time. Reading 4 warns that “MTTR” can mean Respond or Resolve. Which definition does ticket.mttr_minutes = 145 match, and how long after creation did the first containment action happen?",
            options: [
              "Respond: 145 min runs from ticket creation to the first containment step, the host isolation",
              "Resolve: 145 min runs from creation to resolution; first containment came 17 min in",
              "Resolve: 145 min runs from creation to resolution; first containment came 23 min in",
              "Resolve: 145 min runs from creation to resolution; first containment came 38 min in",
            ],
            answer: 1,
            explanation:
              "09:14 → 11:39 (resolved_at) is 145 minutes, so the ticket's MTTR is the Resolve definition. The first containment action was “Host isolated from network at 09:31 UTC”, 17 minutes after creation, which is the Respond figure. The Respond reading fails because isolation was at 09:31, not 145 minutes in. “23 min” reuses ticket.mttd_minutes, which measures time before detection, not time to containment. “38 min” points to the firewall block at 09:52, which came after the host had already been isolated.",
            xp: 20,
          },
        ],
      },
      // ── Analyst Choice — Incident Severity Classification ─────────────────────
      {
        type: "analyst_choice" as const,
        id: "rep-ac1",
        heading: "Verdict: What Should Happen Before This Ticket Is Closed?",
        scenario: "You are writing the post-incident report. The incident involved: a phishing email that bypassed filters, one user clicked and credential was stolen, attacker logged in for 22 minutes and accessed 3 SharePoint document libraries. No data was exfiltrated (DLP shows 0 uploads). The attacker's session was terminated when MFA was revoked. MTTR was 145 minutes (SLA is 120 minutes). The affected user was a junior marketing analyst with no access to sensitive financial or PII data. The ticket is now in pending_closure and you are the assigned analyst. What should you do with this ticket before it is closed?",
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
            "incident.affected_systems": 1,
            "incident.resources_accessed": "SharePoint Online — 3 document libraries",
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
        explanation: "Escalation (to a supervisor or senior analyst for sign-off) is correct before closing this incident. Here is why: (1) The SLA was breached by 25 minutes — this must be documented, and (as Reading 2 explains) most organizations require shift-lead or management sign-off before closing any SLA-breach incident. Simply classifying it as a true positive and closing it yourself skips that required review. Closing without noting the breach would be a reporting integrity failure. (2) Even though no data was exfiltrated and no sensitive data was accessible, the 22-minute attacker session requires documentation of everything accessed — some documents in SharePoint may have contained more than standard marketing materials. (3) A post-incident review should be triggered to understand why the phishing email bypassed filters. The correct severity for the report is P3 (low business impact) but the SLA breach elevates the process requirement.",
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
        checkpoint: {
          question: "You must rewrite “C2 beacon with 30-second jitter to 185.220.101.47” for a client's IT manager. Which principle from the reading should guide the rewrite?",
          options: [
            "Keep the ATT&CK technique ID in the text so the client's team can look the activity up",
            "Lead with the impact and the actions already taken, not with the technical mechanics",
            "Keep the internal alert's wording so the client sees exactly what the SOC detected",
            "Walk through the attack chain step by step before saying what the SOC did about it",
          ],
          answer: 1,
          explanation:
            "The reading's rule is to lead with impact and actions taken: what happened to the client, what risk they face now and what to do. Technique IDs and the internal alert wording are the jargon the translation is meant to remove. Starting with the step-by-step attack chain buries the impact and the actions, which the client needs first.",
        },
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
        checkpoint: {
          question: "You confirm ransomware actively spreading across a client's file servers. Under the reading's SLA tiers, how must the client be notified?",
          options: [
            "In the next weekly report",
            "Ticket update within 4 hours",
            "Email within 1 hour",
            "Phone call within 15 minutes",
          ],
          answer: 3,
          explanation:
            "Actively spreading ransomware is P1 (Critical), which requires a phone call within 15 minutes of confirmation. A call reaches the client immediately and allows two-way conversation. “Email within 1 hour” is the P2 tier, for a threat that is already contained; an email can sit unread for hours. The 4-hour ticket update is P3, and the weekly report is P4.",
        },
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
          "Twenty minutes ago the client reset its CEO's password after a phishing report, and you opened the ticket as P2 (contained, client action needed). You now see the CEO's mailbox still sending wire-transfer requests from an unfamiliar session. How should you notify the client?",
        options: [
          "Keep it at P2 and email the client within the hour, since the password reset already contained the account",
          "Add the new evidence to the P2 ticket in the portal so the client's team sees it at its next check",
          "Re-classify it as P1 and phone the client within 15 minutes, because the compromise is still active",
          "Re-classify it as P1 and email the details to the CEO, so the warning and the evidence stay in writing",
        ],
        answer: 2,
        explanation:
          "The reset did not end the compromise: the mailbox is still being used for fraud, so this is now an active P1 (CEO account compromised, direct financial impact). P1 requires a phone call within 15 minutes of confirmation. Staying at P2 relies on a containment that has visibly failed. A portal update is the P3/P4 channel and could sit unread. Email is too slow for P1, and sending it to the CEO's mailbox, which the attacker is using, could warn the attacker instead of the client.",
        xp: 15,
      },
      // ── Question 2 ────────────────────────────────────────────────────────
      {
        type: "question",
        id: "cc-q2",
        question:
          "An analyst drafts this client notification: 'We detected T1078 Valid Account usage with impossible travel IOA across your tenant.' What is the main problem with this notification?",
        options: [
          "It omits the full IOC list and the detection rule ID, which the client's team needs before it can act",
          "It reports the detection before the SOC finished investigating, so it should wait until scope is known",
          "It is written in jargon (T1078, IOA) a business contact won't follow; it should state the impact plainly",
          "It names the technique but not the SIEM product that raised it, so the client cannot verify the finding",
        ],
        answer: 2,
        explanation:
          "Client notifications should lead with impact in plain language. “T1078 Valid Account usage with impossible travel IOA” means nothing to most client contacts. A better version: “One of your accounts signed in from New York and Tokyo within the same hour, which is physically impossible, so its password has likely been stolen. We have blocked the account while we investigate.” IOC lists and rule IDs belong in the technical follow-up, not the first notice. Holding the notice until scope is known risks breaching the SLA; the reading's transparency principle is to say what you know now. The SIEM product name gives the client nothing to act on.",
        xp: 20,
      },
      // ── Question 3 ────────────────────────────────────────────────────────
      {
        type: "question",
        id: "cc-q3",
        question:
          "A client says: 'We don't want you to isolate the infected machine. Our CFO needs it for a board presentation tomorrow morning.' What is the BEST response from the SOC analyst?",
        options: [
          "Agree to wait until after the presentation, but raise the ticket to P1 and watch the machine closely overnight",
          "Isolate the machine anyway as policy requires, and tell the client afterwards in the end-of-shift report",
          "Explain the concrete risk of waiting, recommend isolating now, and offer the CFO a temporary device",
          "Pass the conversation to Tier 3, since pushback on a containment decision is outside Tier 1's remit",
        ],
        answer: 2,
        explanation:
          "Reading 2's guidance for “can you wait until business hours?” is to explain the business risk of waiting (spread to shared drives, the file server or email), recommend isolating now, and offer the user a temporary device. Agreeing to wait leaves an infected machine connected all night; watching it more closely does not stop the spread. Isolating without telling the client ignores that it is the client's environment and damages trust. Handling client pushback professionally is part of the analyst's communication job, and the reading does not route it to Tier 3.",
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
            "notification.recipient": "Acme Corp security on-call line",
            "notification.sent_at": "2026-06-24T09:32:00.000Z",
            "incident.confirmed_at": "2026-06-24T09:14:00.000Z",
            "notification.content_summary":
              "Informed client of active malware infection on WS-FINANCE-042. Confirmed host isolation action. Requested client to initiate internal IR protocol.",
            "escalation.backup_analyst_paged": "t.brooks",
            "escalation.backup_response_time_minutes": 18,
          },
        } as TelemetryEvent,
        questions: [
          {
            question:
              "Read sla.breach_reason together with the escalation.* fields. Which corrective action would most directly have prevented this breach?",
            options: [
              "Coach r.cohen to check the queue more often, since the P1 sat unnoticed in the queue during the shift",
              "Auto-page an on-call lead if no P1 call is logged by about minute 12, before the 15-minute limit",
              "Move P1 notices from phone to email, so a busy analyst can send them in between other client calls",
              "Raise the P1 notification SLA to 20 minutes, since the backup analyst needed 18 minutes to respond",
            ],
            answer: 1,
            explanation:
              "The log shows a chain failure, not a monitoring failure: r.cohen was busy on another client's call, and the backup page to t.brooks went unacknowledged until minute 18. Reading 3's corrective action targets exactly this gap: page the on-call lead automatically if no P1 call is logged within 12 minutes. Coaching r.cohen misreads the log, because the P1 was not missed; the analyst was occupied. Switching P1 to email contradicts Reading 2, where P1 requires a phone call because email can sit unread. Relaxing the SLA hides the process gap instead of fixing it.",
            xp: 15,
          },
          {
            question:
              "Using the incident confirmation time in the log and the P1 notification limit, by what UTC time did the client call have to be made to meet the SLA?",
            options: ["09:26 UTC", "09:32 UTC", "09:29 UTC", "09:47 UTC"],
            answer: 2,
            explanation:
              "The P1 clock starts at confirmation: incident.confirmed_at 09:14 + 15 minutes = 09:29 UTC. The call went out at 09:32 (notification.sent_at), 3 minutes late, and even a 3-minute breach is a breach. “09:32” is the actual send time, not the deadline. “09:26” is the 12-minute auto-page point from Reading 3's corrective action. “09:47” wrongly starts the 15 minutes from the send time instead of from confirmation.",
            xp: 15,
          },
        ],
      },
      // ── Analyst Choice — Customer SLA Notification ────────────────────────────
      {
        type: "analyst_choice" as const,
        id: "cc-ac1",
        heading: "Verdict: Does This Require an Immediate Customer SLA Notification?",
        scenario: "18:07 UTC. You are an MSSP analyst. Your client GlobalFinance Inc. experienced a confirmed ransomware detection on one workstation. The endpoint was isolated by EDR at 18:04 UTC. The attacker had access for approximately 6 minutes before isolation. No file encryption was confirmed by EDR (the ransomware was caught before encryption started). Your MSSP contract with GlobalFinance defines P1 (Critical) to include any confirmed ransomware detection on a client endpoint, and states: 'P1 incidents must be communicated to the client within 15 minutes of confirmation.' The detection was confirmed when EDR isolated the host. It is now 18:07 UTC. What do you do?",
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
            "edr.action": "isolated",
            "edr.encryption_confirmed": false,
            "edr.threat_name": "Ransom:Win64/BlackCat.B",
            "edr.attacker_dwell_minutes": 6,
            "sla.notification_required_minutes": 15,
            "sla.clock_started": "2026-06-19T18:04:00Z",
            "sla.notification_sent": false,
          },
        },
        correct_verdict: "escalate",
        explanation: "Escalation to your supervisor and immediate start of the SLA notification process is correct. The clock started at 18:04 (sla.clock_started), so the call is due by 18:19 and fewer than 12 minutes remain. Even though the ransomware was stopped before encryption, a confirmed ransomware detection on a client endpoint IS a P1 (Critical) incident under this contract — the fact that encryption was prevented does not downgrade the classification. The right sequence: (1) Start drafting the client notification now; (2) Alert your team lead so they can approve and send; (3) Document the timeline precisely because the client will ask. Waiting until you know more risks SLA breach — the contract says 'within 15 minutes of confirmation', not 'within 15 minutes of fully understanding the scope'.",
        fp_trap: "Because no files were encrypted and the attack was contained in 6 minutes, it is tempting to classify this as Informational or wait for more information before notifying the client. But MSSP contracts are precise: under this one, P1 (Critical) = any confirmed ransomware detection, period. The containment outcome (good news) is included in the notification — it is not a reason to delay or skip it.",
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
        checkpoint: {
          question: "A Tier 1 analyst confirms malware on a finance server and wants it cut off from the network. According to the reading, which role typically approves that isolation?",
          options: [
            "Tier 1, under its playbook",
            "Tier 2",
            "Tier 3, as incident lead",
            "The SOC manager",
          ],
          answer: 1,
          explanation:
            "The reading lists host isolation authority under Tier 2's responsibilities. Tier 1 works from predefined playbooks but does not have authority for high-impact actions such as isolating servers, so it escalates. Tier 3 leads major incidents and external engagement, but routine isolation approval sits with Tier 2. The reading does not assign isolation approval to the SOC manager.",
        },
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
        checkpoint: {
          question: "According to the reading, what is the correct action when you are uncertain about an alert but have not yet completed the investigation steps in your playbook?",
          options: [
            "Escalate to Tier 2 right away, since an uncertain alert is safer in more experienced hands",
            "Close it as benign with a short note, since an unconfirmed alert does not justify a ticket",
            "Work through the playbook's investigation steps first, then decide whether to escalate",
            "Hand it to the next shift with your notes, so a fresh analyst can take a look at it",
          ],
          answer: 2,
          explanation:
            "The reading lists escalating out of uncertainty, before finishing your own playbook steps, as a “when NOT to escalate” case: do the playbook first. Escalating right away is the over-escalation that floods Tier 2 and teaches them to deprioritise you. Closing as benign skips the investigation; Tier 1 closes only clear false positives with evidence. Passing it to the next shift delays the investigation without adding anything.",
        },
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
          "Escalate to Tier 2, since any failed login could be the first event of a brute-force attack",
          "Escalate to Tier 3 for a forensic check that rules out account takeover before closure",
          "Document that it matches the playbook's known pattern and close it as a false positive",
          "Ask the user to confirm the attempt was theirs, and keep the ticket open until they reply",
        ],
        answer: 2,
        explanation:
          "A single failed login that matches a false-positive pattern documented in the playbook is a “when NOT to escalate” case: Tier 1 documents the match and closes it. Escalating to Tier 2 on a single failure is over-escalation; a brute-force pattern would show many failures, not one retry. Tier 3 handles major incidents and hunting, not routine triage. Contacting the user adds delay and an open ticket for a pattern the playbook already explains.",
        xp: 15,
      },
      // ── Question 2 ────────────────────────────────────────────────────────
      {
        type: "question",
        id: "esc-q2",
        question:
          "Ransomware is hitting 40 of a client's servers. The SOC's Tier 2/3 lead, the client's security team, IT operations and legal all need to make decisions at the same time. What does the reading recommend setting up?",
        options: [
          "A shared incident ticket in the client's ITSM, which each team updates in turn as it works",
          "An escalation bridge: a live call or war room where all parties coordinate in real time",
          "A formal Tier 1 to Tier 2 handover note listing status, IOCs and the actions taken so far",
          "An after-action review with all stakeholders to agree on the timeline and the action items",
        ],
        answer: 1,
        explanation:
          "For P1 incidents affecting many systems, the reading recommends an escalation bridge: a conference call or video meeting where the SOC leads, the client's security team, IT operations and sometimes legal and executives coordinate in real time. A shared ticket is updated in turn, which is too slow when decisions are needed simultaneously. A handover note moves the case between tiers but does not bring the stakeholders together. An after-action review happens after the incident, not during it.",
        xp: 15,
      },
      // ── Question 3 ────────────────────────────────────────────────────────
      {
        type: "question",
        id: "esc-q3",
        question:
          "A Tier 1 analyst confirms active ransomware spreading across 12 endpoints. The analyst escalates to Tier 2. After handing over the ticket, what should the Tier 1 analyst do?",
        options: [
          "Return to other alerts and leave the case alone, since Tier 2 now owns it and has the full ticket",
          "Stay reachable for Tier 2's questions, watch for related alerts, and follow how the case develops",
          "Phone the client with the ransomware details now, since early notice outranks the escalation chain",
          "Give Tier 2 only the confirmed conclusion, keeping uncertain early findings out of the handover",
        ],
        answer: 1,
        explanation:
          "Reading 3 says to hand over your notes, not the incident: the first analyst has context nobody else has, Tier 2 may have questions, and following the case is a learning opportunity. Ransomware campaigns also tend to trigger related alerts. Mentally disengaging once Tier 2 owns the case is the common mistake the reading warns about. Phoning the client yourself bypasses the escalation chain and the agreed notification process. Holding back uncertain findings removes the context that makes your handover valuable; Tier 2 can judge it.",
        xp: 20,
      },
      // ── Log Analysis ──────────────────────────────────────────────────────
      {
        type: "log_analysis",
        id: "esc-log-1",
        heading: "Analyzing a Tier 1 to Tier 2 Escalation Event",
        context:
          "The SIEM has logged an escalation event. A Tier 1 analyst has escalated an active incident to Tier 2. Examine the escalation record carefully — judge both what it contains and when it was sent, using the timestamps in the Tier 1 actions list.",
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
              "sha256:1cdaef0f9aa0119f255bb61080ca2d875a2847f27ca55bb1d32b2a89334cae40",
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
              "Compare escalation.timestamp with the times in escalation.actions_taken_by_tier1. By the reading's escalation criteria, what is the main weakness of this escalation?",
            options: [
              "It came too early: Tier 1 should have finished blocking the C2 address before handing the case over",
              "It came too late: ransomware was confirmed by about 09:17, yet Tier 2 was only engaged at 09:45",
              "It went to the wrong tier: a named ransomware family should go straight to Tier 3 for attribution",
              "It lacked detail: the record gives Tier 2 no IOCs or affected-host scope to start containment",
            ],
            answer: 1,
            explanation:
              "Threat intel confirmed Maze ransomware before the ticket was created at 09:17. That met several escalation triggers at once: confirmed malicious activity, ransomware with legal implications, and a scope that needed isolation authority Tier 1 lacks. Yet the escalation went out at 09:45, leaving about half an hour of active spread to 12 hosts. “Too early” is wrong because the record itself shows the C2 block needs Tier 2 firewall authority. Attribution is Tier 3 work, but escalation still runs Tier 1 → Tier 2, and containment comes first. “Lacked detail” misreads the record, which lists IOCs, 12 hosts, the VLAN and a recommendation.",
            xp: 20,
          },
          {
            question:
              "The analyst notes mention that 'Domain controller SRV-DC-01 is NOT yet affected.' Why is this information critical to include in the escalation?",
            options: [
              "It shows the attack is confined to workstations, so server-side checks can wait until containment ends",
              "The DC controls authentication for the whole domain, so its clean status sets how urgent the VLAN isolation is",
              "It allows the incident to be downgraded from P1, since the most critical server is still unaffected",
              "It shows the SMB spread is limited to the FINANCE VLAN, so no hosts outside it need monitoring",
            ],
            answer: 1,
            explanation:
              "Domain controllers are listed among the sensitive systems that drive escalation, because they control authentication for every account and system. An attacker who reaches a DC with domain-admin rights can push ransomware to every machine in the domain and destroy Active Directory itself, which makes recovery far harder. “NOT yet affected” tells Tier 2 there is still a window, which is why the analyst recommends immediate VLAN isolation. It does not mean servers can wait or that the P1 can be downgraded: 12 hosts are encrypting and the DC is the next prize. The FINANCE VLAN note describes where the spread is now, not a guarantee that it stops there.",
            xp: 25,
          },
        ],
      },
      // ── Analyst Choice — Escalation Tier Decision ─────────────────────────────
      {
        type: "analyst_choice" as const,
        id: "esc-ac1",
        heading: "Verdict: Handle It Yourself or Escalate to Tier 2?",
        scenario: "02:30 AM. You are a Tier-1 analyst on night shift. You confirmed active ransomware on 12 hosts at 02:22 — file encryption is in progress. You have opened the incident ticket and matched the IOCs in threat intel. The EDR's automatic prevention policy has isolated 7 of the 12 hosts; 5 are still connected, and 3 more hosts just started showing the same pattern. The C2 address is still reachable. You are the only analyst on shift. Your Tier-2 on-call is reachable, but calling now means waking them at 2:30 AM; the day shift starts at 07:00. What is your verdict?",
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
            "escalation.c2_ip_blocked": false,
            "escalation.c2_ip": "185.220.101.47",
            "escalation.lateral_movement_active": true,
            "analyst.shift": "night",
            "analyst.tier": "T1",
            "analyst.on_shift_count": 1,
            "tier2.oncall.available": true,
            "tier2.oncall.name": "r.goldberg@mssp.com",
            "rule.name": "Ransomware_Active_Spread_Critical",
            "rule.level": 15,
          },
        },
        correct_verdict: "escalate",
        explanation: "Escalate immediately — this meets several of the reading's escalation triggers at once: confirmed malicious activity (ransomware, which also carries legal implications), multiple systems involved and still spreading (3 new hosts in 5 minutes), and actions needed that exceed Tier-1 authority (isolating the 5 remaining and 3 new hosts, blocking the C2 address at the firewall). Tier-2 will: (1) take incident command; (2) approve and drive isolation and the C2 block; (3) trigger client and crisis communication; (4) begin forensic investigation. The concern about 'waking someone at 2:30 AM' is exactly the feeling that causes incidents to spiral — T2 on-call exists to be woken for this. Waiting for the 07:00 day shift would leave more than four hours of active encryption. 'EDR already isolated 7 hosts' is a good briefing to give T2, not a reason to delay the call.",
        fp_trap: "The EDR has already isolated 7 hosts and you have opened the ticket, so it can feel as if the situation is 'under control'. But 5 hosts are still connected, 3 new hosts just appeared, the C2 address is still reachable, and the actions that remain need authority Tier-1 does not hold. Solo analysts under pressure tend to underestimate scope. Escalation is not admitting failure — it is the correct process for a confirmed P1 ransomware incident.",
        xp: 35,
      },
    ],
  },
];

export default rooms;
