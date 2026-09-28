import type { AuthoredPathLesson } from "./types";

/** Authored Learning Path content - group "th1". Keys: "<pathSlug>--<lessonSlug>". */
export const lessons_th1: Record<string, AuthoredPathLesson> = {
  "threat-hunter--ttp-based-hunting": {
    "pages": [
      {
        "pageNumber": 1,
        "title": "What Threat Hunting Is (and Isn't)",
        "body": "Every SOC (Security Operations Center) runs on detections: rules that watch logs and raise an alert when a known-bad pattern appears. Threat hunting is different. It is the proactive, human-led search for adversary activity that has already gotten past those rules - attackers who are inside the environment right now but have not tripped a single alert. Where alert triage answers \"what did the SIEM (Security Information and Event Management) flag?\", hunting answers a harder question: \"what is the SIEM not seeing?\"\n\n### An analogy to start\n\nThink of it like building security. A fire alarm (your SIEM/EDR - Endpoint Detection and Response - detections) reacts the instant it senses smoke: that is detection. A fire marshal who walks the building looking for exposed wiring, blocked exits, and overloaded circuits before any alarm ever goes off: that is hunting. The marshal does not wait for a sensor to fire; they go looking for the conditions that would let a fire start undetected.\n\n### Three disciplines beginners confuse\n\nThreat hunting sits between three disciplines. Alert triage is reactive: it starts when a rule fires and ends when a verdict is reached. Incident response is also reactive: it starts once a genuine compromise is confirmed and focuses on containment and recovery. Threat hunting is proactive: it starts with a hunter's own hypothesis, runs whether or not any alert exists, and it is just as successful when it finds nothing as when it finds an active intrusion, because \"nothing found\" still tells you your coverage is holding.\n\n### IOC versus IOA\n\nHunting also differs by the type of evidence it chases. An IOC (Indicator of Compromise) is forensic evidence that an attack already happened: a specific malicious file hash, IP address, or domain. An IOA (Indicator of Attack) is evidence of the behavior itself while it happens: a process spawning a shell, credentials being dumped from memory, regardless of which specific tool or infrastructure the attacker used. Effective hunting leans heavily on IOAs, because behavior is far harder for an attacker to change than any single indicator. The rest of this lesson builds on that idea: hunting organized around attacker behavior, using the industry's shared vocabulary for that behavior, MITRE ATT&CK.",
        "keyPoints": [
          "Threat hunting is proactive and hypothesis-driven; alert triage and incident response are reactive.",
          "A hunt that finds nothing is still a success - it confirms detection coverage for that hypothesis.",
          "IOCs (Indicators of Compromise) are forensic after-the-fact artifacts; IOAs (Indicators of Attack) are behavioral evidence of an attack in progress.",
          "Hunting is most durable when built around attacker behavior (IOAs), not fragile artifacts like hashes or IPs."
        ]
      },
      {
        "pageNumber": 2,
        "title": "Why TTPs, Not IOCs: The Pyramid of Pain",
        "body": "The single most important reason experienced hunters organize their work around TTPs (Tactics, Techniques, and Procedures) rather than indicators is a model called the Pyramid of Pain, published by security researcher David Bianco in 2013. It ranks six kinds of evidence from trivial for an attacker to change (bottom) to painful for an attacker to change (top): hash values, IP addresses, domain names, network/host artifacts, tools, and finally TTPs at the very top.\n\n### Why the bottom of the pyramid is fragile\n\nA detection built on a file hash breaks the instant the attacker recompiles their malware - one changed byte produces a completely different hash. An IP address is even more fragile; attackers rent new infrastructure in minutes. A TTP describes the attacker's actual tradecraft: the technique of dumping credentials from a specific process, the technique of hiding a scheduled task, the technique of tunneling command-and-control (C2) traffic over DNS. Changing that forces the attacker to redesign part of their operation, which costs them real time and money. This is exactly why intelligence-driven hunting is built on TTPs: it produces coverage that survives an attacker swapping tools or infrastructure.\n\n### MITRE ATT&CK: turning \"TTP\" into a shared vocabulary\n\nMITRE ATT&CK is the framework that turns \"TTP\" from a vague idea into a shared, queryable vocabulary. Its Enterprise matrix organizes attacker behavior into 14 tactics - columns representing the attacker's goal at each stage of an intrusion, such as Initial Access, Execution, Persistence, Privilege Escalation, Credential Access, Lateral Movement, and Exfiltration. Underneath each tactic sit techniques (and finer sub-techniques) describing specific methods of achieving that goal, each with a stable identifier such as T1003 (OS Credential Dumping) or T1053 (Scheduled Task/Job). A procedure is the concrete, real-world instance: the exact command line, tool, or malware family a specific threat actor used to execute that technique.\n\nTactics answer why an attacker did something; techniques answer how; procedures answer exactly what happened this time. Together, they are the TTPs that give a hunt its structure - and its name in this lesson.",
        "keyPoints": [
          "The Pyramid of Pain (David Bianco, 2013) ranks evidence from trivial (hashes) to painful (TTPs) for an attacker to change.",
          "TTP-based hunts survive tool and infrastructure changes because they target the attacker's actual tradecraft.",
          "MITRE ATT&CK Enterprise organizes attacker goals into 14 tactics, with techniques and sub-techniques underneath each, identified by stable IDs like T1003.",
          "Tactic answers why, technique answers how, procedure answers the exact real-world instance of that technique."
        ],
        "codeExample": "// Reading an ATT&CK identifier\nT1003        Technique:       OS Credential Dumping\nT1003.001    Sub-technique:   LSASS Memory\nTactic:      Credential Access\nProcedure:   A threat group used the comsvcs.dll MiniDump export\n             to dump LSASS (Local Security Authority Subsystem\n             Service) memory to disk"
      },
      {
        "pageNumber": 3,
        "title": "Anatomy of a TTP-Based Hunt",
        "body": "MITRE's own guidance on TTP-based hunting lays out a repeatable methodology that turns \"let's hunt for credential dumping\" into a structured, documented process instead of an afternoon of ad hoc searching. The methodology has five practical stages.\n\n### The five stages\n\nFirst, select a technique of interest. Good sources for this selection are current threat intelligence relevant to your industry, gaps surfaced by a coverage-gap analysis (the subject of a later lesson in this module), or findings from a recent red team or purple team exercise. Second, study the technique's real procedures. Every technique page on the ATT&CK website lists documented procedure examples - the specific tools and command patterns real threat groups have used - plus a Detection section describing the data sources and behavioral clues defenders have used to catch it before.\n\nThird, determine what data is needed and whether you actually have it. A hunt for T1003.001 (OS Credential Dumping: LSASS Memory) needs process-creation and process-access telemetry from your EDR or Sysmon; if that data source is not collected, the hunt cannot proceed until that gap is closed. Fourth, build and run the query, iterating on it against real data - a first pass almost always returns far more noise than signal, and refining the filter conditions is most of the actual hunting work. Fifth, investigate every hit using the same disciplined questions any analyst applies to an alert: is this normal for this entity, what exactly triggered the match, and what happened before and after it.\n\n### The step that makes it count\n\nThe stage that separates hunting from a one-off exercise is what comes after: operationalization. A hunt that finds real technique usage, or even one that finds nothing but proves the data source works, should be converted into a standing detection rule (often written in Sigma, a vendor-neutral rule format) so the next occurrence is caught automatically. A hunt that is run once and forgotten provides no lasting value; a hunt that becomes a detection compounds in value every day after.",
        "keyPoints": [
          "MITRE's TTP-based hunting methodology: select a technique, study its documented procedures, confirm data availability, build/refine the query, then investigate every hit.",
          "Every ATT&CK technique page lists real procedure examples and a Detection section describing what has caught it before.",
          "A hunt must confirm the needed data source is actually collected before it can prove or disprove the hypothesis.",
          "The highest-value outcome of a hunt is operationalizing it into a standing detection rule."
        ]
      },
      {
        "pageNumber": 4,
        "title": "Intel-Driven Hunting: From CTI Report to Hunt",
        "body": "Threat intelligence (often shortened to CTI, Cyber Threat Intelligence) is one of the two main triggers for a TTP-based hunt - the other being a coverage gap discovered internally. An intel-driven hunt starts with a report: a CISA (Cybersecurity and Infrastructure Security Agency) advisory, a vendor threat report, or an internal analysis of a campaign targeting your sector, describing what a specific threat actor did. The hunter's job is to translate that narrative into ATT&CK technique IDs and then into queries against your own telemetry.\n\n### A realistic example\n\nConsider an advisory describing an intrusion set that gains initial access through a phishing attachment, then establishes persistence using a Registry Run key, and later executes encoded PowerShell commands to download a second-stage payload. Mapped to ATT&CK, this becomes T1566.001 (Phishing: Spearphishing Attachment) for initial access, T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder) for persistence, and T1059.001 (Command and Scripting Interpreter: PowerShell) for execution. Each of those three IDs becomes its own mini-hunt with its own hypothesis.\n\n### STIX, TAXII, and the discipline that matters more than the format\n\nStructured threat intelligence often arrives in a machine-readable format called STIX (Structured Threat Information eXpression), shared between organizations over a protocol called TAXII (Trusted Automated Exchange of Intelligence Information); at a smaller scale it may simply be a PDF advisory a hunter reads and manually maps to ATT&CK IDs. Either way, the discipline is the same: never hunt directly on the narrative (\"phishing happened\"); hunt on the technique and its documented procedure (\"a PowerShell process was spawned by an Office application process, with an encoded command-line argument\").\n\nThis is also where hunting connects back to detection coverage. If your organization has never seen the specific malware family named in the advisory, that IOC-level detail is nearly worthless - it is unlikely to reappear unchanged. The technique, however, is far more likely to recur in a future, differently-tooled attack against the same industry. Intel-driven hunting is valuable precisely because it hunts one level up from the specific campaign, at the level of technique, where the Pyramid of Pain says the real, lasting value lives.",
        "keyPoints": [
          "Intel-driven hunts translate a CTI (Cyber Threat Intelligence) report's narrative into ATT&CK technique IDs before writing any query.",
          "STIX (Structured Threat Information eXpression) and TAXII (Trusted Automated Exchange of Intelligence Information) are standard formats/protocols for sharing threat intel.",
          "Hunt on the technique and documented procedure, not the narrative - a technique is more likely to recur than a specific IOC.",
          "One advisory describing an intrusion set often decomposes into several separate technique-level hypotheses."
        ]
      },
      {
        "pageNumber": 5,
        "title": "Worked Hunt: T1003.001, LSASS Memory Credential Dumping",
        "body": "Time to run an actual hunt end to end. LSASS (Local Security Authority Subsystem Service) is the Windows process that holds credentials, including cached password hashes and Kerberos tickets, in memory so a logged-in user does not have to re-authenticate constantly. T1003.001 (OS Credential Dumping: LSASS Memory) is the technique of reading that memory to extract those credentials, and it is one of the most consistently valuable hunts in any Windows environment because so many post-exploitation toolkits rely on it.\n\n### From procedure to hypothesis\n\nThe documented procedures for this technique include using the legitimate Windows utility comsvcs.dll (via its MiniDump export) to write LSASS memory to disk, using Task Manager's \"Create dump file\" option on lsass.exe, or using a well-known third-party credential-dumping tool. Because these procedures vary, the strongest hunt hypothesis is behavioral, not tool-specific: look for any process requesting a high level of memory access to lsass.exe, regardless of which process is doing the requesting.\n\n### The data this hunt needs\n\nThe data needed is process-access telemetry: which process opened a handle to which other process, and with what access rights. In Microsoft Defender for Endpoint's advanced hunting schema, this level of detail appears in the DeviceProcessEvents table, capturing process creation events with the initiating process and its command line. The convention across EDR tools is that a full-access request appears as access mask 0x1FFFFF (PROCESS_ALL_ACCESS on Windows).\n\n### Running the query and applying judgment\n\nA first-pass query filters DeviceProcessEvents for any process with a command line referencing lsass in combination with dump-related keywords, then narrows out expected noise such as the legitimate Windows Error Reporting service or approved backup/EDR agents that periodically touch LSASS as part of normal operation. Every surviving hit gets the same five-question treatment from earlier training: is this process and account normal for this host, what exactly is the command line doing, what happened immediately before and after, is any other host showing the same pattern, and what is the impact if this is real.",
        "keyPoints": [
          "LSASS (Local Security Authority Subsystem Service) holds credentials in memory; T1003.001 targets it directly.",
          "Because procedures for this technique vary, the strongest hypothesis targets the behavior, not one specific tool.",
          "DeviceProcessEvents in Microsoft Defender for Endpoint's advanced hunting schema supplies the process-creation telemetry this hunt needs.",
          "A full-access handle request to a process is conventionally represented as access mask 0x1FFFFF (PROCESS_ALL_ACCESS)."
        ],
        "codeExample": "DeviceProcessEvents\n| where Timestamp > ago(7d)\n| where FileName in~ (\"rundll32.exe\", \"taskmgr.exe\", \"procdump.exe\")\n| where ProcessCommandLine has \"lsass\"\n    and (ProcessCommandLine has \"comsvcs\"\n         or ProcessCommandLine has \"MiniDump\"\n         or ProcessCommandLine has \"full\")\n| where InitiatingProcessFileName !in~ (\"MsMpEng.exe\", \"SenseIR.exe\")\n| project Timestamp, DeviceName, AccountName, FileName,\n    ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine\n| order by Timestamp desc"
      },
      {
        "pageNumber": 6,
        "title": "From Hunt to Detection: Maturity and the PEAK Framework",
        "body": "A single successful hunt is a good day's work. A hunting program that consistently gets better is a different achievement, and two models describe how to measure and structure that progress.\n\n### The Hunting Maturity Model\n\nDavid Bianco (the same researcher behind the Pyramid of Pain) also created the Hunting Maturity Model while at the security company Sqrrl. It describes five levels, HM0 through HM4. At HM0, an organization has no real hunting capability and relies entirely on automated alerts from its SIEM, antivirus, and IDS/IPS (Intrusion Detection/Prevention System). HM1 introduces some threat intelligence consumption, but hunts are still largely reactive to that intel rather than hypothesis-driven. HM2 organizations run hunts using a documented, repeatable procedure, roughly where the methodology from this lesson operates. HM3 organizations build custom, advanced data analysis techniques of their own rather than relying only on published procedures. HM4, the top level, is functionally the same as HM3 but with one critical addition: automation. Every successful hunting process is operationalized into an automated detection, freeing hunters to spend their time on the next unknown.\n\n### The PEAK framework\n\nMore recently, Splunk's SURGe research team published the PEAK framework: Prepare, Execute, Act with Knowledge, a vendor-neutral structure for running individual hunts. In Prepare, hunters select a topic, research it, and plan the hunt's scope. In Execute, they dig into the actual data and analysis. In Act (with Knowledge), they document findings, automate anything repeatable, and communicate results, and that accumulated knowledge feeds directly into the next cycle's Prepare phase. PEAK also names three hunt types: hypothesis-based hunts (the TTP-driven kind built in this lesson), baseline hunts (statistical, covered in this module's aggregation lesson), and model-assisted hunts (built on analytics or machine-learning output).\n\nNeither model is a bureaucratic exercise for its own sake; both exist to answer one honest question: is this hunting program actually getting better, or just staying busy?",
        "keyPoints": [
          "The Hunting Maturity Model (David Bianco, Sqrrl) runs HM0 (alerts only) through HM4 (successful hunts automated into standing detections).",
          "The PEAK framework (Splunk SURGe) structures each hunt into Prepare, Execute, and Act with Knowledge.",
          "PEAK defines three hunt types: hypothesis-based, baseline (statistical), and model-assisted (analytics/ML-driven).",
          "Program maturity is measured by whether successful hunts get automated into detections, not by hunt volume."
        ]
      },
      {
        "pageNumber": 7,
        "title": "The TTP-Based Hunting Loop, End to End",
        "body": "Everything covered in this lesson fits into a single repeating loop, and seeing it as a diagram makes the dependencies between stages clear. The loop begins outside the SOC entirely, with threat intelligence or an internally discovered technique gap, and ends by feeding directly back into that same starting point, stronger than before.\n\n### Walking the loop\n\nThe loop starts with a trigger: either an external CTI report naming a threat actor's TTPs, or an internal coverage-gap analysis flagging a technique your stack cannot currently see. That trigger is mapped to one or more specific ATT&CK technique IDs. Each technique is turned into a formal hypothesis, the subject of the next lesson in this module, naming the suspected behavior, the data source needed to test it, and the detection logic that would confirm or refute it. The hypothesis becomes a query, run against the relevant telemetry. Every hit is investigated using the standard analyst questions. If a hit confirms genuine adversary activity, it becomes an incident and follows the organization's incident response process. If the hunt confirms the technique is not present but the query logic is sound, the most valuable next step is to operationalize the query into a standing Sigma detection rule, so the same technique is caught automatically in the future.\n\n### Closing the loop\n\nEither outcome, a confirmed finding or a clean, well-documented negative result, gets written up and fed back into the organization's knowledge base: threat intel notes, updated detection coverage records, and lessons for scoping the next hunt. That feedback is what closes the loop, and is also what separates a mature hunting program from a team running one-off queries with no memory between them.\n\nNotice that nowhere in this loop does a hunter wait for an alert. The trigger, at every stage, comes from intelligence or curiosity about a gap, never from the SIEM tapping the hunter on the shoulder.",
        "keyPoints": [
          "The hunting loop starts outside the SOC: a CTI report or an internally found coverage gap, never a SIEM alert.",
          "Every hunt ends in documentation, whether it finds a confirmed incident or a clean negative result.",
          "A confirmed finding escalates through incident response; a clean result should still be operationalized into a standing detection.",
          "Feeding results back into organizational knowledge advances hunting maturity from one-off queries to a repeatable program."
        ],
        "codeExample": "flowchart TD\n    A[CTI report or coverage gap] --> B[Map to ATT&CK technique ID]\n    B --> C[Form hypothesis: TTP + data source + detection logic]\n    C --> D[Build and run query]\n    D --> E[Investigate every hit]\n    E -->|Confirmed adversary activity| F[Escalate as incident]\n    E -->|No evidence, query sound| G[Operationalize as Sigma detection rule]\n    F --> H[Document findings]\n    G --> H\n    H --> A"
      },
      {
        "pageNumber": 8,
        "title": "Common Pitfalls and the Analyst Mindset",
        "body": "Knowing the methodology is not the same as executing it well. A handful of mistakes account for most failed or wasted hunts, and recognizing them in your own work is worth more than memorizing any framework name.\n\n### Four pitfalls to watch for\n\nThe first pitfall is hunting on IOCs instead of TTPs out of convenience. A hunt built around \"does this specific malicious hash appear anywhere in our environment\" is fast to write and almost always comes back empty, not necessarily because the technique is absent, but because the specific artifact was never present in the first place, or the attacker changed it before you looked. Anchor hunts on behavior, and treat any IOC you do have as one supporting clue rather than the whole hypothesis.\n\nThe second pitfall is failing to document negative results. A hunt that finds nothing is not a wasted afternoon; it is evidence that your data source and detection logic held up under a real test, exactly the kind of coverage confidence a gap analysis depends on. Treating \"found nothing\" as \"nothing to write up\" throws away that value entirely.\n\nThe third pitfall is starting a hunt without a testable hypothesis, such as \"let's just look at PowerShell activity and see what stands out.\" Unbounded exploration like this rarely reaches a clear conclusion and cannot be graded as a success or failure because there was no defined success criterion to begin with. The next lesson in this module builds the structured hypothesis format that prevents exactly this failure mode.\n\nThe fourth pitfall is boiling the ocean: choosing a hunt scope so broad, such as \"hunt for lateral movement across the whole environment for the last year,\" that the query never finishes or the result set is unmanageable. Time-boxing a hunt is what keeps it executable in a single sitting.\n\nEvery pitfall here has the same root cause: skipping the structure. The methodology in this lesson exists precisely because unstructured hunting rarely survives contact with a real, noisy production environment.",
        "keyPoints": [
          "IOC-only hunts risk false confidence; anchor on behavior instead of a single hash or address.",
          "A hunt that finds nothing is still valuable and must be documented; it confirms coverage.",
          "A hunt without a stated, testable hypothesis cannot be reproduced or graded as success or failure.",
          "Time-box every hunt's scope to avoid an unmanageable 'boil the ocean' query."
        ]
      }
    ],
    "quiz": [
      {
        "question": "A hunter can spend this week's hunt budget on either (1) searching for one specific malware hash named in a vendor report, or (2) searching for the registry-key persistence behavior that same malware family uses. Per the Pyramid of Pain, which produces more lasting detection value?",
        "options": [
          {
            "label": "The hash search, since a unique hash produces zero false positives",
            "value": "b"
          },
          {
            "label": "The behavior search, since a hash changes trivially but replacing an entire persistence technique costs the attacker real effort",
            "value": "a"
          },
          {
            "label": "Neither, since hunts should only run after a SIEM alert has already fired",
            "value": "c"
          },
          {
            "label": "The hash search, since MITRE ATT&CK itself is organized around indicators of compromise",
            "value": "d"
          }
        ],
        "answer": "a",
        "explanation": "The Pyramid of Pain places hashes at the bottom (trivial for an attacker to change) and TTPs at the top (painful to change), so behavior-based hunts produce far more durable value. Claiming a unique hash guarantees zero false positives is wrong regardless, and a hash becomes worthless the moment the sample is recompiled. Hunting is proactive and does not wait for a SIEM alert to fire first. MITRE ATT&CK is organized around tactics, techniques, and procedures, not indicators of compromise."
      },
      {
        "question": "A threat group's specific command, launched by winword.exe, used an encoded PowerShell one-liner to download a payload - this maps to ATT&CK sub-technique T1059.001. Which ATT&CK term describes this exact, real-world observation?",
        "options": [
          {
            "label": "The tactic, because Execution is the category this behavior belongs to",
            "value": "a"
          },
          {
            "label": "The sub-technique, because T1059.001 already identifies PowerShell specifically",
            "value": "c"
          },
          {
            "label": "The procedure, because it is the exact real-world instance of how this group carried out the technique",
            "value": "b"
          },
          {
            "label": "The data source, because winword.exe is what generated the telemetry",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "A procedure is the concrete, real-world instance of a technique: the specific command, tool, and launching process used this one time. The tactic describes the higher-level goal (Execution), already implied by the sub-technique ID, not the specific observation itself. Restating that T1059.001 identifies PowerShell doesn't answer what this specific instance is called, since that ID was already given in the question. A data source is where the evidence was found, not what the observation itself is called."
      },
      {
        "question": "A hunter has a new CTI report naming a technique but has not yet checked whether the required log source is being collected. Per the TTP-based hunting methodology in this lesson, what should happen before the hunter writes and runs the query?",
        "options": [
          {
            "label": "Nothing - writing the query first is the fastest way to learn whether the data exists",
            "value": "a"
          },
          {
            "label": "Escalate immediately to incident response, since any newly named technique implies an active compromise",
            "value": "b"
          },
          {
            "label": "Confirm the needed data source is actually collected, since the hunt cannot prove or disprove anything without it",
            "value": "c"
          },
          {
            "label": "Skip straight to writing a Sigma detection rule, since that is the real goal of any hunt",
            "value": "d"
          }
        ],
        "answer": "c",
        "explanation": "The methodology's third stage is confirming the required data is actually available before building the query - a hunt against a data source that was never collected cannot meaningfully test the hypothesis at all. Running the query first wastes effort if the data source turns out to be missing. A named technique in a CTI report is not itself evidence of compromise, so escalating immediately is premature. Writing a detection rule only makes sense after the hunt has actually been run and validated, not as a substitute for confirming data availability first."
      },
      {
        "question": "A hunter runs a well-scoped hunt for T1003.001 across all endpoints for the last 30 days and finds zero suspicious LSASS access, with the required telemetry confirmed to be flowing the whole time. What should the hunter do with this result?",
        "options": [
          {
            "label": "Discard it silently, since a hunt that finds nothing produced no useful information",
            "value": "a"
          },
          {
            "label": "Document it as a confirmed compromise finding, since LSASS is always a high-risk process",
            "value": "b"
          },
          {
            "label": "Document the negative result, since it demonstrates the data source and detection logic held up under a real test",
            "value": "d"
          },
          {
            "label": "Rerun the exact same query every hour until it eventually finds something",
            "value": "c"
          }
        ],
        "answer": "d",
        "explanation": "A clean, well-scoped negative result with confirmed data collection is genuine evidence of coverage and belongs in the hunt log. Discarding it silently throws away that value. Zero matching events is the opposite of a confirmed finding, so treating it as one would be a mistake. Rerunning the identical query on a tight loop adds no new information once the window has already been fully covered."
      },
      {
        "question": "A SOC has been manually re-running the same successful hunting query every month by hand for over a year, without ever turning it into an automated rule. Per David Bianco's Hunting Maturity Model, what is missing to reach the top level, HM4?",
        "options": [
          {
            "label": "Nothing, since manually re-running a proven query is itself the definition of HM4",
            "value": "c"
          },
          {
            "label": "Threat intelligence consumption, since HM4 is defined purely by how much CTI a team reads",
            "value": "b"
          },
          {
            "label": "Automation - operationalizing the successful hunting process into a standing detection instead of manual repetition",
            "value": "a"
          },
          {
            "label": "A larger SIEM budget, since HM4 is determined by tooling spend rather than process maturity",
            "value": "d"
          }
        ],
        "answer": "a",
        "explanation": "HM4 differs from HM3 by exactly one thing: successful hunting processes get automated into standing detections, freeing hunters from repeating the same manual work. Manual monthly repetition on its own is characteristic of a lower maturity level, not HM4. Framing HM4 purely around CTI consumption is inaccurate - that is more characteristic of HM1. Bianco's model measures process maturity, not tooling budget."
      }
    ]
  },
  "threat-hunter--hypothesis-framework": {
    "pages": [
      {
        "pageNumber": 1,
        "title": "Why 'I'll Just Look Around' Fails",
        "body": "Ask an experienced hunter what separates a productive afternoon from a wasted one, and the answer is almost always the same: whether the hunt started from a real hypothesis. A hypothesis, borrowed directly from the scientific method, is a specific, testable statement that can be proven or disproven by evidence, not a vague intention to \"look for bad stuff.\"\n\n### Three ways unstructured hunting fails\n\nUnstructured hunting - opening a SIEM (Security Information and Event Management) or EDR (Endpoint Detection and Response) console and browsing recent PowerShell activity \"to see what looks weird\" - feels productive because it keeps a hunter busy, but it fails in three specific ways. First, it has no defined success criterion: there is no way to know when the hunt is finished, because nothing was ever defined as an answer. Second, it cannot be reproduced: another hunter, or even the same hunter next month, cannot repeat the exact search because it was never written down as a precise, bounded query. Third, and most damaging for a hunting program's credibility, it cannot be credited toward detection coverage. A structured coverage-gap analysis (the subject of a later lesson) needs to know exactly which ATT&CK techniques have been actively hunted and cleared - an unstructured browsing session leaves no defensible record of what was actually checked.\n\n### What a hypothesis fixes\n\nA hypothesis fixes all three problems by forcing precision up front. Instead of \"look for weird PowerShell,\" a hypothesis states something like: \"if an attacker is using PowerShell to download a second-stage payload on our finance-department endpoints, evidence would appear as an encoded command-line argument launched by an Office application within the last 14 days.\" That single sentence already defines what to search, where to search it, and what a positive result looks like, which means it also defines what a clean negative result looks like, and that a hunter one week later could rerun exactly the same test.\n\nThe rest of this lesson builds the specific template professional hunting teams use to write hypotheses this precisely, every time.",
        "keyPoints": [
          "A hunting hypothesis is a specific, testable statement, not a vague intention to 'look for bad stuff.'",
          "Unstructured hunting has no success criterion, cannot be reproduced, and cannot be credited toward documented coverage.",
          "A well-formed hypothesis defines what to search, where to search it, and what a positive and negative result look like.",
          "Precision up front is what makes a hunt reproducible by another analyst later."
        ]
      },
      {
        "pageNumber": 2,
        "title": "The Three Types of Hunting Hypotheses",
        "body": "Not every hunt starts the same way, and the PEAK framework (Prepare, Execute, Act with Knowledge, developed by Splunk's SURGe research team) usefully names three distinct hunt types based on where the starting idea comes from. Recognizing which type you are running shapes how you write the hypothesis itself.\n\n### Hypothesis-based hunts\n\nA hypothesis-based hunt starts from external or internal intelligence: a CTI (Cyber Threat Intelligence) report naming a threat actor's TTPs (Tactics, Techniques, and Procedures), a specific MITRE ATT&CK technique flagged by a coverage-gap analysis, or a finding from a recent red team exercise. This is the type built in the previous lesson of this module - the hypothesis names a specific technique and asks whether evidence of it exists in your environment.\n\n### Baseline hunts\n\nA baseline hunt (sometimes called an anomaly-based hunt) starts differently: instead of a named technique, it starts from a statistical question about what is normal. \"What does typical outbound data volume look like per user, and who deviates from it this week?\" is a baseline hunt - it does not presuppose which technique an attacker might be using, only that unusual behavior, whatever its cause, is worth a second look. This type leans heavily on the aggregation and grouping techniques (summarize, bin(), percentile functions) covered later in this module, because \"normal\" and \"deviation\" are statistical concepts that require counting and comparing large numbers of events.\n\n### Model-assisted hunts\n\nA model-assisted hunt starts from the output of an analytics model or machine-learning system, for example a UEBA (User and Entity Behavior Analytics) platform's risk score, or a clustering algorithm that groups similar login patterns together and flags the smallest, most unusual cluster. The hunter's job here is not to build the model but to investigate what it surfaces and decide whether the flagged behavior is genuinely suspicious.\n\nAll three types still need the same disciplined hypothesis structure covered on the next page - only the starting spark differs. A hunt that begins with a UEBA risk score still must be narrowed into a specific, testable statement before a hunter starts querying, or it falls into exactly the unstructured trap from the previous page.",
        "keyPoints": [
          "PEAK (Splunk SURGe) names three hunt types: hypothesis-based (intel/TTP-driven), baseline (statistical), and model-assisted (analytics/ML-driven).",
          "A baseline hunt starts from a statistical question about normal behavior rather than a named ATT&CK technique.",
          "A model-assisted hunt starts from a UEBA (User and Entity Behavior Analytics) system's output, which the hunter then validates.",
          "Whichever type sparks a hunt, it still needs one specific, testable hypothesis before querying begins."
        ]
      },
      {
        "pageNumber": 3,
        "title": "Anatomy of a Well-Formed Hypothesis",
        "body": "Professional hunting teams write hypotheses using the same three components every time, regardless of hunt type. Leaving any one of the three out is what turns a hunt back into unstructured browsing.\n\n### Component one: the suspected behavior\n\nThe first component is the suspected adversary behavior, stated as a specific ATT&CK technique or sub-technique wherever possible, not a vague category like \"malware\" or \"suspicious activity.\" \"An attacker is using scheduled tasks for persistence\" is vague; \"an attacker is creating a scheduled task via schtasks.exe with a non-standard executable path, matching T1053.005 (Scheduled Task/Job: Scheduled Task)\" is specific enough to search for.\n\n### Component two: the data source\n\nThe second component is the data source needed to test it. This must name the actual table, log type, or telemetry feed, not just \"the SIEM\" in the abstract. For a scheduled-task hypothesis, the data source is process-creation telemetry capturing schtasks.exe command lines, which in Microsoft Defender's advanced hunting schema lives in the DeviceProcessEvents table. Naming the exact data source up front forces the hunter to confront, before running anything, whether that data source is actually being collected, precisely the coverage question a later lesson in this module addresses directly.\n\n### Component three: the detection logic\n\nThe third component is the detection logic, the specific behavioral indicator, field, or value combination that would confirm or refute the hypothesis. For the scheduled-task example, that might be: a schtasks.exe process whose /tr (task-run) argument points to a path outside Program Files or System32, or whose command line includes both /create and /ru SYSTEM (running as the highest-privilege local account).\n\nPut together, these three components form a template worth memorizing: \"If [suspected behavior/TTP] is occurring, evidence would appear as [specific detection logic] in [named data source].\" Every hypothesis in this module fits that shape. Missing the technique makes the hunt untargeted; missing the data source makes it unverifiable whether you even have visibility; missing the detection logic makes it impossible to know when you have actually found something.",
        "keyPoints": [
          "A well-formed hypothesis has three components: the suspected behavior/TTP, the specific data source, and the detection logic.",
          "Name the exact table or telemetry feed for the data source, not just 'the SIEM.'",
          "Detection logic must be a specific field, value, or combination, not a vague sense of 'suspicious.'",
          "Template: 'If [TTP] is occurring, evidence would appear as [detection logic] in [data source].'"
        ]
      },
      {
        "pageNumber": 4,
        "title": "Worked Example: Building a Hypothesis for Kerberoasting (T1558.003)",
        "body": "Applying the three-component template to a real, high-value technique makes the framework concrete. Kerberoasting is T1558.003 (Steal or Forge Kerberos Tickets: Kerberoasting), sitting under the Credential Access tactic in MITRE ATT&CK. It works because any authenticated domain user can request a Kerberos service ticket for any service with a registered SPN (Service Principal Name), and that ticket is encrypted with a key derived from the service account's password. An attacker requests tickets for every SPN-registered service account they can find, then cracks the returned tickets offline, without ever touching the target service.\n\n### Building the three components\n\nComponent one, the suspected behavior: an authenticated user is requesting an unusually high number of Kerberos service tickets for SPN-registered accounts, particularly tickets using weaker RC4 encryption rather than modern AES, since RC4-encrypted tickets are far faster to crack offline.\n\nComponent two, the data source: Windows Security Event ID 4769 (\"A Kerberos service ticket was requested\"), generated on domain controllers and, in a Sentinel-connected environment, ingested into the SecurityEvent table. This raises the coverage question from the previous page: is Event ID 4769 auditing even enabled, and is the domain controller's Security log actually being forwarded? Many environments do not enable this auditing by default because of its volume, so confirming this data source exists is itself a meaningful first step.\n\nComponent three, the detection logic: within the SecurityEvent table, a 4769 event where TicketEncryptionType equals 0x17 (RC4-HMAC), where the ServiceName field is not a machine account (does not end in a dollar sign) and is not krbtgt, and where a single requesting Account generates several such requests against different ServiceName values within a short time window.\n\n### Assembling the sentence\n\nAssembled into the template: \"If an attacker is Kerberoasting SPN-registered accounts (T1558.003), evidence would appear as a single Account requesting multiple RC4-encrypted (TicketEncryptionType 0x17) service tickets for different non-machine ServiceName values within a short window, in the SecurityEvent table's 4769 events.\" That sentence is now precise enough to become the query built later in this lesson.",
        "keyPoints": [
          "Kerberoasting (T1558.003, Credential Access) abuses the fact that any authenticated user can request a ticket for any SPN-registered account.",
          "Windows Security Event ID 4769 is the core data source, ingested into the SecurityEvent table in Sentinel.",
          "RC4 encryption (TicketEncryptionType 0x17) on a 4769 event is the classic high-confidence indicator.",
          "Confirming that 4769 auditing is actually enabled is itself part of building the hypothesis."
        ]
      },
      {
        "pageNumber": 5,
        "title": "Writing Testable, Falsifiable Hunt Statements",
        "body": "A hypothesis is only useful if it can come back false. This property, falsifiability, is borrowed directly from the scientific method, and it is the single test that separates a genuinely structured hunt from one that only looks structured on paper.\n\n### What makes a hypothesis falsifiable\n\nA falsifiable hypothesis names a specific, bounded condition that either does or does not appear in the data. \"Something might be wrong with our PowerShell usage\" is not falsifiable: no query result could ever definitively prove or disprove it, because it names no specific behavior. \"An attacker is executing base64-encoded PowerShell commands launched by an Office application on finance-department endpoints in the last 14 days\" is falsifiable: the query either returns matching events or it returns none, and either outcome is a real, usable answer.\n\n### Scoping decisions that falsifiability forces\n\nFalsifiability also forces useful scoping decisions up front. A hypothesis should state a bounded time window (the last 14 days, not \"ever\"), a bounded asset population where relevant (finance-department endpoints, not the entire fleet, if the intel being hunted is specific to that population), and a specific data source. Each boundary keeps the hunt executable in a single sitting and keeps a negative result meaningful; a hunt across \"everything, forever\" that finds nothing proves very little, because it was too unfocused to have been a fair test.\n\n### Weak versus strong hypotheses\n\n| Weak hypothesis | Why it fails | Strong hypothesis |\n| --- | --- | --- |\n| \"Check for suspicious logins\" | No technique, no data source, no bounded condition | \"If credential-stuffing is occurring against our VPN, evidence would appear as 10+ failed logins across 5+ distinct accounts from one source IP within 10 minutes, in VPN authentication logs\" |\n| \"Look for malware on endpoints\" | Not falsifiable; any finding or non-finding is unclear | \"If T1003.001 LSASS dumping is occurring, evidence would appear as a process requesting full access to lsass.exe, in DeviceProcessEvents over the last 7 days\" |\n\nA hunter who cannot state, before running a single query, what a clean negative result would look like has not yet finished writing the hypothesis; they have only named a topic.",
        "keyPoints": [
          "Falsifiability means the hypothesis must be able to come back false, a genuinely useful negative result.",
          "Every hypothesis should state a bounded time window and, where relevant, a bounded asset population.",
          "'Check for suspicious activity' is a topic, not a hypothesis - it names no falsifiable condition.",
          "Before running a query, a hunter should be able to state what a clean negative result would look like."
        ]
      },
      {
        "pageNumber": 6,
        "title": "From Hypothesis to KQL Query",
        "body": "A well-formed hypothesis translates almost directly into a query, because every clause of the hypothesis maps to a filter condition. This is deliberate: the discipline of writing the three-component template pays off here, as the hardest part of writing the query has effectively already been done in plain English.\n\n### Reading the hypothesis clause by clause\n\nTake the Kerberoasting hypothesis assembled two pages ago: \"a single Account requesting multiple RC4-encrypted service tickets for different non-machine ServiceName values within a short window, in the SecurityEvent table's 4769 events.\" Reading it clause by clause: \"the SecurityEvent table's 4769 events\" becomes the table and the EventID filter; \"RC4-encrypted\" becomes a filter on TicketEncryptionType; \"non-machine ServiceName\" becomes an exclusion filter on names ending in a dollar sign and on the built-in krbtgt account; \"a single Account requesting multiple... within a short window\" becomes a summarize (aggregation) grouped by Account and a time bucket, counting distinct ServiceName values and total requests.\n\n### From plain English to KQL\n\nIn KQL (Kusto Query Language, used by Microsoft Sentinel and Microsoft Defender), that becomes a runnable query. Notice how directly each line traces back to a clause of the hypothesis sentence - that traceability is what makes the finished query defensible and easy for another hunter to review.\n\nOnce this query returns results, each hit still gets investigated with the standard analyst questions: is this Account's ticket-requesting pattern normal for this host or service admin, is this ServiceName actually meant to be queried this way by a legitimate scanning tool, and what happened on that host or account in the time surrounding the spike. A query returning rows is a lead, not an automatic confirmed incident.\n\nIf the query returns nothing across the full 30-day window and Event ID 4769 auditing is confirmed enabled, that is the falsifiable negative result the hypothesis promised: real evidence that this technique was not observed, worth documenting exactly as covered in the next section of this lesson.",
        "keyPoints": [
          "Each clause of a well-formed hypothesis maps almost directly to a filter or aggregation in the query.",
          "KQL (Kusto Query Language) is the query language used by Microsoft Sentinel and Microsoft Defender advanced hunting.",
          "A hit returned by the query is a lead, not a confirmed incident - it still requires the standard analyst questions.",
          "A clean negative result across the full time window, with the data source confirmed, is the falsifiable answer promised."
        ],
        "codeExample": "SecurityEvent\n| where EventID == 4769\n| where TicketEncryptionType == \"0x17\"\n| where ServiceName !endswith \"$\" and ServiceName != \"krbtgt\"\n| summarize RequestCount = count(), DistinctServices = dcount(ServiceName)\n    by Account, bin(TimeGenerated, 10m)\n| where RequestCount >= 4 or DistinctServices >= 3\n| order by RequestCount desc"
      },
      {
        "pageNumber": 7,
        "title": "Documenting and Closing Out a Hunt",
        "body": "A hunt is not finished when the query stops returning new insight; it is finished when it has been written down in a form someone else could act on or repeat. Every professional hunting team keeps a hunt log, and the fields it captures mirror the structure built throughout this lesson.\n\n### What a hunt log records\n\nA solid hunt log entry records the hypothesis exactly as written (all three components), the specific query or queries run, the time period covered, and the outcome. The outcome is written honestly as one of three states: a confirmed finding (with the evidence and the incident ticket it was escalated into), a clean negative result (with the data source's collection confirmed, so the negative result is trustworthy rather than a blind spot), or an inconclusive result (data source gaps or noisy results prevented a clear answer, which itself becomes an action item).\n\n### Why documentation matters\n\nDocumentation is not paperwork for its own sake; it does three specific jobs. It lets a coverage-gap analysis credit a technique as \"actively hunted and cleared\" for a given time window, which is otherwise impossible to prove after the fact. It lets another hunter avoid re-running an identical hunt from scratch, either by picking up where the last one left off or by improving the query rather than starting over. And it creates an audit trail that satisfies both internal review and, in regulated industries, external compliance questions about proactive detection activity.\n\n### The follow-up field\n\nThe final field in most hunt logs is follow-up action: does this hunt's query get operationalized into a standing Sigma detection rule (the highest-value outcome), does it reveal a data-source gap that needs to be closed before the hunt can be trusted, or does it simply get scheduled to rerun on a cadence, such as monthly, to keep watching for the same technique going forward. A hunt log without a stated follow-up action is a hunt log that will be read once and never acted on.",
        "keyPoints": [
          "A hunt log records the full hypothesis, the exact query run, the time period covered, and an honest outcome.",
          "Outcomes are one of three states: confirmed finding, clean negative, or inconclusive.",
          "Documentation lets a coverage-gap analysis credit a technique as actively hunted, and lets hunters avoid duplicating work.",
          "Every hunt log entry should end with a stated follow-up action: operationalize, close a gap, or schedule a rerun."
        ]
      },
      {
        "pageNumber": 8,
        "title": "The Hypothesis Lifecycle, Visualized",
        "body": "Pulling every stage from this lesson into one picture shows how a hunt moves from a loose idea to a documented, reusable asset. Each arrow in the diagram below corresponds to a specific page you have just worked through.\n\n### Walking the diagram\n\nAn idea enters the lifecycle from one of the three sources covered earlier: threat intelligence naming a TTP, a statistical question about normal behavior, or an analytics/UEBA system's flagged output. That idea gets formalized into the three-component template: behavior, data source, detection logic, and immediately checked for falsifiability and proper scoping. Only once it passes that check does it become a query, which is run and refined against real data.\n\nEvery hit the query returns is investigated with the standard analyst questions. From there the lifecycle branches three ways, matching the honest outcome categories from the hunt log: a confirmed finding escalates into the incident response process; a clean negative result (with the data source confirmed collected) gets documented as coverage; and an inconclusive result, usually caused by a data-source gap or by noise the query could not filter out, becomes its own follow-up item, often feeding directly into the coverage-gap analysis covered in the next lesson of this module.\n\n### Why this is a loop, not a line\n\nWhichever branch a hunt takes, it ends the same way: written into the hunt log, and fed back into the organization's pool of ideas for the next hunt. A confirmed finding might reveal a related technique worth hunting next; a data-source gap discovered along the way becomes its own hunt or its own logging project; even a clean result narrows what future hunters need to re-check. This lifecycle is a closed loop, not a straight line, exactly like the TTP-based hunting loop from the previous lesson, because a hypothesis-driven hunt is simply that loop's middle stage made explicit and rigorous.",
        "keyPoints": [
          "The hypothesis lifecycle is a closed loop: ideas come from intel, baselines, or analytics output, and outcomes feed back into future hunts.",
          "A hypothesis must pass a falsifiability and scoping check before it becomes a query.",
          "Outcomes branch three ways: confirmed findings escalate, clean negatives document coverage, inconclusive results feed the gap analysis.",
          "This lifecycle is the TTP-based hunting loop from the previous lesson, with its hypothesis stage made explicit."
        ],
        "codeExample": "flowchart TD\n    A[Idea: intel, baseline question, or model output] --> B[Formalize: behavior + data source + detection logic]\n    B --> C{Falsifiable and properly scoped?}\n    C -->|No| B\n    C -->|Yes| D[Build and run query]\n    D --> E[Investigate every hit]\n    E -->|Confirmed adversary activity| F[Escalate to incident response]\n    E -->|Clean negative, data source confirmed| G[Document as coverage]\n    E -->|Inconclusive: gap or noise| H[Feed into coverage-gap analysis]\n    F --> I[Hunt log entry]\n    G --> I\n    H --> I\n    I --> A"
      }
    ],
    "quiz": [
      {
        "question": "Which of these hunting hypotheses is properly falsifiable?",
        "options": [
          {
            "label": "Something seems off with recent logins",
            "value": "a"
          },
          {
            "label": "There might be malware somewhere on the network",
            "value": "c"
          },
          {
            "label": "If credential-stuffing is occurring against the VPN, evidence would appear as 10+ failed logins across 5+ accounts from one IP within 10 minutes",
            "value": "b"
          },
          {
            "label": "Check whether anything unusual happened this month",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "A falsifiable hypothesis names a specific, bounded condition the data either does or does not show, so the query result is a real, usable answer either way. The other three options name no specific technique, data source, or bounded condition, so no query result could definitively prove or disprove any of them."
      },
      {
        "question": "A hunter writes: 'An attacker might be persisting via scheduled tasks.' Which component of a well-formed hypothesis is still missing before this can become a real hunt?",
        "options": [
          {
            "label": "Nothing is missing - naming the general technique is all that is required",
            "value": "a"
          },
          {
            "label": "The specific data source and detection logic that would confirm or refute this in real data",
            "value": "c"
          },
          {
            "label": "An incident response escalation plan, since every hypothesis must include one",
            "value": "b"
          },
          {
            "label": "A machine-learning model to automatically confirm the finding",
            "value": "d"
          }
        ],
        "answer": "c",
        "explanation": "This statement only names a general behavior; it is missing the specific data source (which table or log) and the detection logic (which field/value combination would confirm it) that the three-component template requires. An escalation plan and a machine-learning model are not part of the hypothesis template at all, and the technique is stated too vaguely to say nothing is missing."
      },
      {
        "question": "A hunter starts a hunt not from a threat intel report, but from the question: 'What does normal outbound data volume look like per user, and who deviates this week?' Which PEAK hunt type is this?",
        "options": [
          {
            "label": "A hypothesis-based hunt, since it still requires a hypothesis",
            "value": "a"
          },
          {
            "label": "A baseline hunt, since it starts from a statistical question about normal behavior rather than a named technique",
            "value": "d"
          },
          {
            "label": "A model-assisted hunt, since it involves numbers and statistics",
            "value": "c"
          },
          {
            "label": "None of PEAK's hunt types cover this kind of question",
            "value": "b"
          }
        ],
        "answer": "d",
        "explanation": "PEAK defines a baseline hunt as one that starts from a statistical question about what is normal, rather than from a named ATT&CK technique. Hypothesis-based hunts start from intel naming a specific TTP, not a hunter's own statistical question. Model-assisted hunts start from an analytics or machine-learning system's output, not a hunter's own statistical question. PEAK does define this hunt type, so ruling it out entirely is incorrect."
      },
      {
        "question": "In the Kerberoasting hypothesis built in this lesson, why does the filter TicketEncryptionType == \"0x17\" matter specifically?",
        "options": [
          {
            "label": "It identifies the busiest domain controller in the environment",
            "value": "c"
          },
          {
            "label": "It flags AES-encrypted tickets, which are effectively impossible to crack offline",
            "value": "b"
          },
          {
            "label": "It flags RC4-encrypted tickets, which crack far faster offline than the modern AES alternative",
            "value": "a"
          },
          {
            "label": "It identifies tickets requested specifically by the built-in krbtgt account",
            "value": "d"
          }
        ],
        "answer": "a",
        "explanation": "0x17 is the RC4-HMAC encryption type, and RC4-encrypted service tickets crack far faster offline than AES-encrypted ones, making them the classic high-confidence Kerberoasting indicator. This field identifies encryption type, not which domain controller was used. AES tickets are harder, not impossible, to crack, and that is not what this filter flags. The krbtgt account is explicitly excluded from this hunt, not identified by this filter."
      },
      {
        "question": "A hunter runs a well-scoped hunt across 30 days, finds no matching events, and confirms the required data source was collecting properly the whole time. How should this be recorded in the hunt log?",
        "options": [
          {
            "label": "As a confirmed incident, since any hunt for a credential-theft technique implies compromise",
            "value": "a"
          },
          {
            "label": "It should not be recorded at all, since nothing was found",
            "value": "c"
          },
          {
            "label": "As a clean negative result, which counts as documented coverage for that technique and time window",
            "value": "b"
          },
          {
            "label": "As inconclusive, since a hunt can only be conclusive when it finds something",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "A well-scoped hunt with confirmed data collection and zero matches is a clean, falsifiable negative result, and it should be documented as coverage for that technique and window. It is not a confirmed incident, since no evidence of the behavior was found. Leaving it unrecorded throws away that coverage value. It would only be inconclusive if the data source or query quality could not be confirmed, which is not the case here."
      }
    ]
  },
  "threat-hunter--coverage-gaps": {
    "pages": [
      {
        "pageNumber": 1,
        "title": "What a 'Coverage Gap' Actually Means",
        "body": "Every hunter has run a query that returned nothing and felt a flash of relief, until the harder question sets in: does this zero mean the technique truly is not present, or does it mean the hunt was blind the entire time? A coverage gap is the honest name for that ambiguity, and learning to spot it is what separates a confident negative result from a false sense of safety.\n\n### Visibility versus detection\n\nThe key distinction this entire lesson is built around is visibility versus detection. Visibility means the raw data needed to see a technique is actually being collected somewhere: logs are generated, forwarded, and stored. Detection means something is actually watching that data and would raise an alert or support a hunt query against it. A gap can exist at either layer, and they require completely different fixes.\n\n### A building-security analogy\n\nA building's security cameras are visibility: if they are not installed in a hallway, nothing that happens there is ever recorded, no matter how attentive the security team is. A person actually watching the camera feed is detection: even with perfect camera coverage, an unwatched feed catches nothing. A gap can be \"no camera in this hallway\" (a visibility gap, where even a perfect analyst cannot investigate data that was never captured) or \"camera recording, nobody watching\" (a detection gap, where the data exists but no rule or hunter is looking at it). Fixing the first requires installing a new camera; fixing the second requires assigning someone to watch, or building an automated alert on the existing feed.\n\n### Translating back to a SOC\n\nTranslated back to a SOC (Security Operations Center): a visibility gap means a log source is not enabled or not forwarded, for example Kerberos ticket-request auditing (Event ID 4769) never turned on for a domain controller. A detection gap means the log source is flowing fine, but no analytic rule, Sigma detection, or standing hunt query is watching it for the technique in question. The rest of this lesson builds a structured way to find both kinds of gaps before an attacker finds them first.",
        "keyPoints": [
          "Visibility (is the data collected?) and detection (is anything watching it?) are two separate layers, and a gap can exist at either.",
          "A visibility gap means the raw log source is missing or not forwarded; a detection gap means data exists but nothing watches it.",
          "A zero-result hunt is only trustworthy evidence of safety if the required data source's visibility has been separately confirmed.",
          "The two gap types require different fixes: enabling/forwarding a log source versus writing or scheduling a detection."
        ]
      },
      {
        "pageNumber": 2,
        "title": "Mapping Your Stack to ATT&CK: The DeTT&CT Approach",
        "body": "Knowing that visibility and detection are separate concepts is only useful if there is a structured way to measure both, consistently, across every technique in MITRE ATT&CK. DeTT&CT (Detect Tactics, Techniques & Combat Threats) is an open-source framework created at the Cyber Defence Center of the bank Rabobank specifically to fill that gap.\n\n### How DeTT&CT structures the problem\n\nDeTT&CT works by having a defender describe their environment in three structured layers: the data sources they collect (and score each one's quality across dimensions like completeness of device coverage, field completeness, timeliness, retention period, and consistency of logging across similar systems), the visibility this data provides against each ATT&CK technique, and the actual detections (rules, analytics, alerts) built on top of that data for each technique. Scoring log source quality matters because a data source that technically exists but is missing key fields, arrives hours late, or is only enabled on a fraction of relevant hosts provides much weaker real visibility than the same data source fully and consistently deployed.\n\n### From scores to a heatmap\n\nThe output of this exercise is a set of scores per ATT&CK technique that can be rendered directly onto the ATT&CK Navigator, the official web-based tool for visualizing and color-coding the ATT&CK matrix. The result is a heatmap: every technique cell shaded by how well it is covered, letting a whole team see at a glance which parts of the matrix are strong, partially covered, or entirely dark.\n\n### A note on data sources in current ATT&CK\n\nIn the ATT&CK v18 release (October 2025) MITRE deprecated Data Sources and replaced the old one-line detection notes on each technique with structured Detection Strategies and Analytics; Data Components (things like Process Creation or Command Execution) were kept and reworked, and each Analytic now points to the log sources and data components it needs. That does not remove the underlying need this lesson addresses; it simply means the mapping between what a technique requires you to log and which of your log sources actually captures that is now a task defenders and frameworks like DeTT&CT own directly.",
        "keyPoints": [
          "DeTT&CT (created at Rabobank's Cyber Defence Center) scores log source quality, visibility, and detection separately, then maps them onto ATT&CK.",
          "Log source quality dimensions include device completeness, field completeness, timeliness, retention, and consistency.",
          "The output renders as a heatmap in ATT&CK Navigator, the official tool for visualizing the ATT&CK matrix.",
          "ATT&CK v18 (October 2025) deprecated Data Sources and introduced Detection Strategies and Analytics; Data Components were kept and now hang off each Analytic."
        ]
      },
      {
        "pageNumber": 3,
        "title": "Data Source Coverage: What Are You Actually Logging?",
        "body": "Turning the DeTT&CT concept into something concrete means being able to name, for any given ATT&CK technique, exactly which table or log type in your own SIEM would capture evidence of it. This table maps common categories of telemetry to real tables used in Microsoft Sentinel and Microsoft Defender's advanced hunting schema, the same tables referenced throughout this module.\n\n### A practical mapping table\n\n| What you need to see | Real table / log source | Example technique it supports |\n| --- | --- | --- |\n| Process creation and command lines | DeviceProcessEvents (Defender for Endpoint) | T1059 Command and Scripting Interpreter |\n| Network connections from a host | DeviceNetworkEvents (Defender for Endpoint) | T1071 Application Layer Protocol (C2) |\n| File writes and modifications | DeviceFileEvents (Defender for Endpoint) | T1105 Ingress Tool Transfer |\n| Interactive and remote logons | DeviceLogonEvents or SecurityEvent, EventID 4624/4625 | T1078 Valid Accounts |\n| Kerberos ticket requests | SecurityEvent, EventID 4769 | T1558.003 Kerberoasting |\n| Cloud identity sign-ins | SigninLogs (Microsoft Entra ID) | T1110 Brute Force |\n| Cloud/O365 mailbox and file actions | OfficeActivity | T1114 Email Collection |\n\n### Two traps in a real environment\n\nTwo things stand out when this table is built for a real environment rather than a training example. First, several techniques depend on more than one row; a full lateral-movement hunt via a compromised account typically needs both SigninLogs (did the account authenticate somewhere new) and DeviceLogonEvents (did that authentication reach an endpoint). Second, and this is the trap this lesson exists to catch, simply having a table appear as \"connected\" in a SIEM's data-connector list does not guarantee useful coverage; a connector can be enabled while the specific event type a hunt needs, like 4769 auditing on domain controllers, was never turned on at the source. Confirming coverage means running a simple presence check against the exact table and field a hypothesis depends on, not just checking that the connector exists in a settings page. The next page walks through exactly that check on a real example.",
        "keyPoints": [
          "Map each hypothesis's required evidence to a specific table, not a general log category.",
          "Some techniques require correlating more than one table to be fully covered.",
          "A connector appearing 'enabled' does not guarantee the specific event type a hunt needs was ever turned on at the source.",
          "A simple count/presence query against the exact required table and field is the fastest way to check visibility."
        ],
        "codeExample": "// Confirm a data source is actually flowing before trusting a hunt built on it\nSecurityEvent\n| where TimeGenerated > ago(7d)\n| where EventID == 4769\n| summarize EventCount = count(), Hosts = dcount(Computer)\n// If EventCount is 0, this is a VISIBILITY gap, not a clean negative result"
      },
      {
        "pageNumber": 4,
        "title": "Worked Example: Finding a Gap for Kerberoasting Detection",
        "body": "Return to the Kerberoasting hypothesis built in the previous lesson: it depends entirely on Windows Security Event ID 4769 reaching the SecurityEvent table. This page walks through exactly how a hunter discovers whether that dependency is a visibility gap before ever trusting a clean result from that hunt.\n\n### Running the check\n\nThe check itself is simple: run a broad query counting any 4769 events across the full domain controller population for a recent window, with no other filters applied yet. If that count comes back at zero, or comes back non-zero but only from one or two domain controllers out of a much larger population, the hunter has found a visibility gap, not evidence of safety. The likely cause is one of two things. Either the audit policy itself is not configured (Windows does not log Kerberos service ticket requests unless \"Audit Kerberos Service Ticket Operations\" is explicitly enabled in the domain's advanced audit policy, and many organizations never turn this on because of its volume), or the audit policy is enabled and events are being generated locally, but the log forwarding pipeline (via the Azure Monitor Agent or a legacy Log Analytics agent) is not configured to collect that specific event on those specific hosts.\n\n### Why this matters for the previous lesson's negative result\n\nThis is precisely the scenario the previous lesson's negative-result discussion warned about: a hunter who ran the Kerberoasting query, got zero rows, and documented \"no evidence of Kerberoasting\" without first confirming 4769 was even flowing would have recorded a false sense of safety as if it were a genuine finding. The correct hunt log entry in this scenario is not \"clean negative\"; it is \"inconclusive: visibility gap identified,\" with a clear next action: enable Kerberos service ticket auditing on all domain controllers, confirm the forwarding pipeline picks it up, and only then rerun the original hunt with confidence in its result.\n\nThis single worked example is the entire purpose of a coverage-gap analysis in miniature: before trusting any hunt's silence, confirm the data source that silence depends on was actually listening.",
        "keyPoints": [
          "A broad, unfiltered count of the exact event type a hunt depends on is the fastest way to test a prior 'clean' result.",
          "Windows does not generate Event ID 4769 unless 'Audit Kerberos Service Ticket Operations' is explicitly enabled.",
          "Even with local auditing enabled, a missing or misconfigured forwarding agent can prevent the event from ever reaching the SIEM.",
          "A hunt result should be logged as 'inconclusive: visibility gap' rather than 'clean negative' when the data source isn't confirmed flowing."
        ]
      },
      {
        "pageNumber": 5,
        "title": "Heatmaps and Navigator: Visualizing Gaps",
        "body": "Once individual gaps like the Kerberoasting example are found one at a time, a SOC (Security Operations Center) needs a way to see the whole picture at once: every ATT&CK technique relevant to the environment, colored by how well it is actually covered. This is exactly what ATT&CK Navigator, MITRE's official web-based visualization tool, is built for.\n\n### Reading a Navigator layer\n\nNavigator renders the full ATT&CK matrix as a grid: tactics across the top as columns, techniques listed underneath each one. A \"layer\" in Navigator is a saved set of colors and scores applied to that grid, and a defender, often using output generated by a tool like DeTT&CT, applies a color scheme representing coverage: a common convention shades a technique red or dark when there is no visibility at all, yellow or orange when visibility exists but no detection is built on it yet, and green when both visibility and an active detection are confirmed present. A hunter or detection engineer can look at this single heatmap and immediately see, for example, that the entire Lateral Movement tactic column is mostly yellow (data exists, but almost nothing is actively watching it), while Credential Access is a healthier mix of green and yellow with one glaring red cell where Kerberoasting coverage turned out to depend on that missing 4769 auditing.\n\n### Layers over time, and purple team validation\n\nLayers are not static snapshots; mature teams regenerate them on a schedule, often quarterly, and keep prior layers for comparison, so leadership can see coverage improving, or newly regressing, for example after a log source gets accidentally disabled during an infrastructure change. This before/after comparison, often called a heatmap delta, is also the standard way purple team exercises prove their value: a red team simulates specific techniques, the blue team's real-time detection (or lack of it) gets scored, and the Navigator layer is regenerated to show exactly which cells moved from red or yellow to green as a direct result of the exercise.\n\nNavigator's visual format turns an abstract, hard-to-communicate idea, \"our detection coverage is uneven,\" into a single picture a SOC manager or a board can actually act on.",
        "keyPoints": [
          "ATT&CK Navigator renders the whole matrix as a grid, with 'layers' storing a saved coverage color scheme.",
          "Common convention: red/dark = no visibility, yellow = visibility without detection, green = both visibility and detection confirmed.",
          "Regenerating and comparing layers over time (a 'heatmap delta') shows whether coverage is genuinely improving or has regressed.",
          "Purple team exercises commonly use a before/after Navigator layer comparison to prove which technique coverage improved."
        ]
      },
      {
        "pageNumber": 6,
        "title": "Prioritizing Which Gaps to Close First",
        "body": "A realistic coverage-gap analysis across the full ATT&CK matrix will surface far more gaps than any team can close at once, so prioritization is not optional; it is the actual skill this lesson is building toward. Three factors, used together, drive a defensible priority order.\n\n### Three prioritization factors\n\nThe first factor is relevance: which techniques are actually used by threat actors that target your specific industry and region, based on current threat intelligence, rather than every technique in the matrix treated as equally likely. A regional healthcare provider and a global financial institution face genuinely different adversaries, and ATT&CK groups (documented threat actor profiles on the ATT&CK website, each listing the specific techniques that group has been observed using) are a direct source for this kind of targeting.\n\nThe second factor is criticality of the affected assets: a visibility gap on a decommissioned test server matters far less than the identical gap on a domain controller, a database holding customer records, or an internet-facing application. The same technique gap can justify very different urgency depending purely on what it would expose if exploited.\n\nThe third factor is cost and feasibility of closing the gap: some gaps close cheaply, such as flipping on an existing audit policy setting that a domain controller already supports, as in the Kerberoasting example, while others require a new log source connector, additional storage/ingestion cost, or a vendor tool that has not yet been procured. A cheap fix on a relevant, critical gap is an obvious first move; an expensive fix on a low-relevance, low-criticality gap can reasonably wait.\n\n### Feeding the backlog\n\nCombining these three factors produces a working backlog, not unlike the hunt backlog built in the previous lesson of this module; in fact, the two backlogs directly feed each other. A gap discovered during a hunt becomes a line item here; a gap closed here often becomes the trigger for the next scheduled hunt, once the newly enabled data source has had time to accumulate a useful baseline.",
        "keyPoints": [
          "Prioritize gaps using relevance to actual threat actors, criticality of affected assets, and cost/feasibility of the fix.",
          "ATT&CK's documented threat actor group profiles are a direct source for which techniques are relevant to your organization.",
          "The same technical gap can justify very different urgency depending on whether it affects a test server or a domain controller.",
          "The coverage-gap backlog and the hunt backlog from the previous lesson feed each other directly."
        ]
      },
      {
        "pageNumber": 7,
        "title": "From Data Source to Full Coverage: The Decision Path",
        "body": "Every technique in the ATT&CK matrix ultimately lands in one of four coverage states, and reaching the correct state requires answering the same sequence of questions each time, a decision path worth having memorized rather than reasoned through from scratch for every technique.\n\n### The four-question path\n\nThe first question is whether a relevant data source exists in the environment at all. If no source exists, the technique is entirely dark: no camera in the hallway, using the earlier analogy, and closing this gap means onboarding a new log source or enabling new auditing before anything else is possible. If a source does exist, the second question is whether its quality is sufficient, using the DeTT&CT dimensions from earlier in this lesson: is it deployed across the relevant device population, are the necessary fields actually populated, does it arrive with acceptable timeliness. A source that technically exists but fails this check still leaves the technique effectively uncovered, just for a subtler reason than total absence.\n\nAssuming the data clears both checks, the third question is whether an actual detection exists on top of it: a standing analytic rule, a Sigma detection, or a scheduled recurring hunt. Data with no detection sitting on top of it is a genuine gap, just one layer higher than a missing data source, the \"camera recording, nobody watching\" case. Only once a detection exists does the fourth and final question apply: is it actually tuned well enough to be trusted, or does it generate so many false positives that analysts have started ignoring it, which functionally reproduces a detection gap even though a rule technically fires.\n\n### Different states, different fixes\n\nEach of these four states maps directly onto Navigator's coloring scheme from earlier in this lesson, and each requires a different remediation: onboard a source, improve its quality, build a detection, or tune an existing one. Treating all coverage problems as the same kind of problem is what leads teams to throw generic effort at a well-defined, layered issue.",
        "keyPoints": [
          "Every ATT&CK technique's coverage lands in one of four states: no data source, insufficient quality, data but no detection, or untuned detection.",
          "Each state requires a different fix: onboarding, quality improvement, building a detection, or tuning.",
          "A detection so noisy that analysts ignore it functions the same as having no detection at all.",
          "This decision path is the practical, repeatable version of the visibility-versus-detection distinction from earlier in this lesson."
        ],
        "codeExample": "flowchart TD\n    A[Does a relevant data source exist?] -->|No| B[Onboard log source / enable auditing]\n    A -->|Yes| C[Is data source quality sufficient?]\n    C -->|No| D[Improve deployment / fix collection]\n    C -->|Yes| E[Does an active detection or scheduled hunt exist?]\n    E -->|No| F[Build Sigma rule or schedule recurring hunt]\n    E -->|Yes| G[Is the detection well-tuned and trusted?]\n    G -->|No, too noisy| H[Tune the detection]\n    G -->|Yes| I[Fully covered - green in Navigator]"
      },
      {
        "pageNumber": 8,
        "title": "From Gap to Action: Closing the Loop",
        "body": "Identifying a gap is only half the job; the other half is closing it in a way that produces a verifiable, lasting change rather than a one-time fix that quietly regresses later. This final page walks through what closing each type of gap actually looks like in practice, using the Kerberoasting example as the throughline for the whole lesson.\n\n### Closing a visibility gap\n\nClosing a visibility gap means changing what gets logged at the source and confirming it arrives centrally. For the domain controller example, this means enabling \"Audit Kerberos Service Ticket Operations\" (and, more broadly, reviewing the domain's advanced audit policy against what current hunts and detections actually require), then confirming the forwarding configuration is picking up that specific Windows Security event ID on every domain controller, not just one. The verification step matters as much as the configuration change; the same presence-check query from earlier in this lesson, rerun after the change, is what proves the fix actually worked rather than just assuming it did.\n\n### Closing a detection gap, and using compensating controls\n\nClosing a detection gap, once visibility is confirmed, means either operationalizing a hunt query into a standing Sigma rule (as covered in the first lesson of this module) or scheduling the hunt to rerun on a fixed cadence if a full standing detection is not yet justified by alert volume or false-positive risk. Where a full fix is not immediately feasible, perhaps the new log source needs budget approval that will take months, a compensating control can bridge the gap: a more limited, host-based EDR (Endpoint Detection and Response) behavioral rule that catches a narrower slice of the same technique using data that is already available, accepting reduced coverage as a temporary trade-off rather than leaving the technique completely dark.\n\n### Feeding the improvement back\n\nEvery gap closed this way should update the same Navigator layer covered earlier, so the improvement is visible, and should feed back into the prioritized backlog from the previous page; closing one gap often reveals the next one behind it, which is exactly why this is a continuous process, not a one-time project.",
        "keyPoints": [
          "Closing a visibility gap requires both a source-side configuration change and a verification query confirming the fix worked.",
          "Closing a detection gap means operationalizing a hunt into a standing rule, or scheduling a recurring hunt.",
          "A compensating control can temporarily bridge a gap that cannot be fully closed right away.",
          "Coverage-gap closure is continuous: update the Navigator layer, feed the backlog, and expect new gaps to surface."
        ]
      }
    ],
    "quiz": [
      {
        "question": "A SOC has Windows Security Event ID 4769 auditing fully enabled and forwarded from every domain controller, but no rule or hunt has ever been built to examine those events for Kerberoasting patterns. In DeTT&CT terms, what does this environment have?",
        "options": [
          {
            "label": "Full coverage, since the data itself is sufficient",
            "value": "a"
          },
          {
            "label": "Visibility without detection - the data exists, but nothing is actively watching it for this technique",
            "value": "c"
          },
          {
            "label": "Detection without visibility, since Kerberos is a well-known technique",
            "value": "b"
          },
          {
            "label": "Neither visibility nor detection, since no alert has ever fired",
            "value": "d"
          }
        ],
        "answer": "c",
        "explanation": "The data source is confirmed collected (visibility), but no rule or hunt watches it for this technique (no detection) - exactly the 'camera recording, nobody watching' case. Data alone is not full coverage. Detection without visibility is impossible here since the data does exist. Visibility is present even though no alert has fired yet."
      },
      {
        "question": "What is the main purpose of the DeTT&CT framework?",
        "options": [
          {
            "label": "To replace MITRE ATT&CK with a simpler, smaller technique list",
            "value": "a"
          },
          {
            "label": "To score log source quality, visibility, and detection separately for each ATT&CK technique and visualize the result as a heatmap",
            "value": "d"
          },
          {
            "label": "To automatically write Sigma detection rules without any human review",
            "value": "c"
          },
          {
            "label": "To generate threat intelligence reports for executive audiences",
            "value": "b"
          }
        ],
        "answer": "d",
        "explanation": "DeTT&CT scores log source quality, visibility, and detection as three separate layers against the ATT&CK matrix and renders the result as an ATT&CK Navigator heatmap. It does not replace ATT&CK, automatically write rules, or generate executive threat-intelligence reports - it is a coverage-measurement framework."
      },
      {
        "question": "A hunter needs to test a hypothesis about process-level command-line activity on Windows endpoints monitored by Microsoft Defender for Endpoint. Which table should the hunt query?",
        "options": [
          {
            "label": "SigninLogs",
            "value": "c"
          },
          {
            "label": "OfficeActivity",
            "value": "b"
          },
          {
            "label": "DeviceProcessEvents",
            "value": "a"
          },
          {
            "label": "CommonSecurityLog",
            "value": "d"
          }
        ],
        "answer": "a",
        "explanation": "DeviceProcessEvents is Microsoft Defender for Endpoint's table for process creation and command-line telemetry. SigninLogs covers Entra ID sign-ins, OfficeActivity covers O365 audit events, and CommonSecurityLog covers CEF-formatted network/firewall logs - none of the other three capture endpoint process command lines."
      },
      {
        "question": "A hunter runs a Kerberoasting hunt against the SecurityEvent table and gets zero results. Before documenting this as a clean negative, what should the hunter check first?",
        "options": [
          {
            "label": "Whether the ATT&CK Navigator layer has been updated this quarter",
            "value": "a"
          },
          {
            "label": "Whether Event ID 4769 is actually being generated and forwarded from the domain controllers in scope",
            "value": "b"
          },
          {
            "label": "Whether a purple team exercise has been scheduled",
            "value": "c"
          },
          {
            "label": "Whether the query used KQL instead of a different query language",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "A zero-result hunt is only trustworthy if the required data source (Event ID 4769) is confirmed to be generated and actually forwarded; otherwise the zero reflects a visibility gap, not safety. Navigator layer freshness and purple team scheduling don't verify this specific data source. The query language used is unrelated to whether the underlying data exists."
      },
      {
        "question": "Two coverage gaps are found: one affects a technique used by threat actors that specifically target your industry, on a critical asset; the other affects a technique with no reported relevance to your sector, on a decommissioned test server. Which factors justify prioritizing the first gap?",
        "options": [
          {
            "label": "Alphabetical order of the technique names",
            "value": "a"
          },
          {
            "label": "Relevance to actual threat actors targeting your industry and the criticality of the affected asset",
            "value": "c"
          },
          {
            "label": "Whichever gap was discovered first chronologically",
            "value": "b"
          },
          {
            "label": "Whichever gap has the shortest ATT&CK technique ID number",
            "value": "d"
          }
        ],
        "answer": "c",
        "explanation": "This lesson's prioritization model weighs relevance to actual threat actors and asset criticality (alongside cost/feasibility), and the first gap scores higher on both. Alphabetical order, discovery order, and ID length all have no bearing on actual risk and are not part of the prioritization model."
      }
    ]
  },
  "threat-hunter--kql-joins": {
    "pages": [
      {
        "pageNumber": 1,
        "title": "Why Hunters Need to Join Tables",
        "body": "Almost every interesting hunt hypothesis in this module has depended on a single table: SecurityEvent for Kerberoasting, DeviceProcessEvents for LSASS access. Real investigations are rarely that clean. Confirming that a risky sign-in actually reached an endpoint, or that a process seen on one host also ran on twenty others, requires combining rows from two different tables based on a shared key: the account name, the device ID, the source IP. In KQL (Kusto Query Language), this is the job of the join family of operators.\n\n### The core idea\n\nThe core idea is the same one used in relational databases for decades, adapted to KQL's pipe-based syntax: take a left table (the one the query is already working with) and a right table, and combine rows from each side wherever a specified key column matches. The general shape is LeftTable | join kind=<flavor> (RightTable) on <key>, where the on clause names the column (or columns) both sides should be matched by.\n\n### A motivating case\n\nConsider a concrete motivating case: a sign-in log shows a high-risk authentication for a user account, but a sign-in log alone cannot say what that user's laptop actually did afterward. Correlating SigninLogs (Microsoft Entra ID sign-in events) with DeviceLogonEvents or DeviceProcessEvents (Microsoft Defender for Endpoint's endpoint telemetry) on a shared identity field is what turns \"someone signed in from a suspicious location\" into \"and forty seconds later, that same account launched an encoded PowerShell command on a laptop,\" a dramatically stronger, more defensible finding than either table could produce alone.\n\nThe rest of this lesson covers the specific join flavors KQL supports, when to reach for the lighter-weight lookup operator instead, and how to pull in data that has not even been ingested into a table yet using externaldata, three tools every hunter eventually needs once a hunt outgrows a single table.",
        "keyPoints": [
          "Correlating a hunt hypothesis across two tables often turns a weak signal into a defensible finding.",
          "KQL's join family follows the pattern LeftTable | join kind=<flavor> (RightTable) on <key>.",
          "The on clause names the shared column both tables should be matched on.",
          "This lesson also covers lookup (small reference-table enrichment) and externaldata (data not yet ingested)."
        ]
      },
      {
        "pageNumber": 2,
        "title": "The join Operator: Syntax and Flavors",
        "body": "KQL supports several named join flavors, and choosing the right one changes not just performance but which rows actually survive into the result, getting this wrong is one of the most common silent mistakes in hunting queries.\n\n### innerunique and inner\n\ninnerunique is the default flavor if kind is not specified at all. It returns rows where the key matches on both sides, but first removes duplicate keys from the left table, keeping only one representative row per distinct left key before joining. This default exists because it performs well for the common case of correlating two event streams on a shared correlation ID, but it is also the flavor most likely to silently drop rows a hunter did not intend to lose, always specify kind explicitly in a hunting query rather than relying on the unstated default. inner returns only rows where the key matches on both sides, without the left-side deduplication; every matching combination of left and right rows survives.\n\n### leftouter and the semi/anti family\n\nleftouter keeps every row from the left table regardless of whether a match exists on the right, filling right-side columns with nulls when there is no match; this is the natural choice when the goal is to enrich events with extra detail if it exists, but never drop an event just because the right table had nothing for it. rightouter and fullouter mirror leftouter from the other side or from both sides at once. Two flavors do not return columns from the right table at all, and exist purely to test presence or absence: leftsemi returns left rows that do have a match on the right (a filter, not an enrichment), and leftanti returns left rows that do not have a match on the right, the single most useful flavor for a hunting question phrased as \"find everything on this list that is NOT on that other list,\" covered with a worked example on the next page.\n\n| Flavor | Rows returned | Typical hunting use |\n| --- | --- | --- |\n| innerunique (default) | Matches only, left keys deduplicated first | Fast correlation on a unique ID; specify explicitly to avoid surprises |\n| inner | Matches only, no dedup | Every matching combination needed |\n| leftouter | All left rows, nulls where no match | Enrich without ever dropping an event |\n| leftsemi | Left rows WITH a match (no right columns) | Filter: keep only what's on a list |\n| leftanti | Left rows WITHOUT a match (no right columns) | Find what's missing from a list |",
        "keyPoints": [
          "innerunique is KQL's default join flavor and silently deduplicates the left table's keys first; specify kind explicitly.",
          "leftouter keeps every left-side row even without a match, filling unmatched right-side columns with null.",
          "leftsemi and leftanti test presence or absence without returning right-table columns.",
          "Use $left.Column == $right.Column in the on clause when the two tables' key columns have different names."
        ],
        "codeExample": "// Explicit join syntax - always state kind, never rely on the default\nLeftTable\n| join kind=leftouter (RightTable) on SharedColumn\n\n// When column names differ between tables, use $left / $right\nLeftTable\n| join kind=inner (RightTable) on $left.UserPrincipalName == $right.AccountName"
      },
      {
        "pageNumber": 3,
        "title": "Worked Example: Correlating a Risky Sign-in With Endpoint Activity",
        "body": "Putting the join operator to work on the motivating scenario from earlier in this lesson: a high-risk sign-in has been flagged in SigninLogs, and the hunt needs to know whether that same account did anything notable on an endpoint shortly afterward.\n\n### Building the query\n\nThe left table is the filtered sign-in events, narrowed down first; filtering before joining is not just good practice, it is essential for performance, since joining two enormous unfiltered tables is one of the slowest operations KQL can run. The right table is DeviceProcessEvents, similarly narrowed to a relevant time window before the join executes. Because SigninLogs identifies the user as UserPrincipalName and DeviceProcessEvents identifies the account as AccountName, the join's on clause needs the $left/$right syntax from the previous page rather than a plain shared column name.\n\nleftouter is the right flavor here: the goal is to see the risky sign-in whether or not matching endpoint activity exists, since \"no matching endpoint activity within the window\" is itself a meaningful, reportable outcome; using inner instead would silently drop every risky sign-in that had no endpoint match at all, hiding exactly the cases a hunter most needs to see and decide on.\n\n### Reading the results\n\nReading the resulting rows, a hunter applies the same standard questions from earlier training: for sign-ins where a process match did appear, is that specific process and command line normal for this user and device, and how tight is the time gap between the sign-in and the process launch, a gap of seconds is far more suspicious than a gap of hours, since it suggests an attacker acting immediately on stolen credentials rather than routine, unrelated activity landing in the same window by coincidence. For sign-ins with no match, the hunter still records that outcome, since a genuinely malicious sign-in with zero device follow-up over several hours might indicate the account is cloud-only or federated to an application with no traditional endpoint footprint, worth its own investigation thread rather than being dismissed.",
        "keyPoints": [
          "Filter and project both tables before joining - an unfiltered join across large tables is one of the slowest KQL operations.",
          "leftouter is the right flavor when 'no match found' is itself a meaningful result worth reporting.",
          "A short time gap between a suspicious sign-in and subsequent endpoint activity is more suggestive of attacker follow-through.",
          "$left/$right syntax is required whenever the join key has different column names in each table."
        ],
        "codeExample": "let RiskySignins =\n    SigninLogs\n    | where TimeGenerated > ago(1d)\n    | where RiskLevelDuringSignIn == \"high\"\n    | project SigninTime = TimeGenerated, UserPrincipalName, IPAddress, Location;\nRiskySignins\n| join kind=leftouter (\n    DeviceProcessEvents\n    | where Timestamp > ago(1d)\n    | project ProcTime = Timestamp, DeviceName, AccountName, ProcessCommandLine\n) on $left.UserPrincipalName == $right.AccountName\n| extend GapMinutes = datetime_diff(\"minute\", ProcTime, SigninTime)\n| where isnull(ProcTime) or GapMinutes between (0 .. 30)\n| project SigninTime, UserPrincipalName, IPAddress, DeviceName, ProcTime, ProcessCommandLine, GapMinutes"
      },
      {
        "pageNumber": 4,
        "title": "leftanti and leftsemi: Finding What's Missing",
        "body": "Some of the most efficient hunting questions are phrased as absence rather than presence: not \"show me suspicious activity\" but \"show me everything that is NOT accounted for on a known-good list.\" leftanti and leftsemi exist for exactly this kind of question, and they are frequently faster than the equivalent filter written with the where and in operators, especially against a large reference list, because KQL can optimize the join itself rather than evaluating a giant in(...) clause row by row.\n\n### A realistic hunting example\n\nAn organization maintains a Microsoft Sentinel watchlist (a curated reference table, uploaded once and kept updated, ideal for exactly this kind of lookup list) of every account authorized to hold a Service Principal Name and therefore expected to appear in Kerberos ticket-request logs as a legitimate ServiceName. A hunter wants to know whether any 4769 events target a ServiceName that is not on that authorized list at all, a strong signal of either shadow IT (an undocumented service account someone created without approval) or a more deliberate attempt to request tickets for an account nobody is tracking.\n\n### Choosing the right flavor\n\nleftanti answers this directly: take the 4769 events as the left table, the authorized-services watchlist as the right table, join on ServiceName, and leftanti returns exactly the left rows with no match, the untracked accounts. leftsemi would answer the opposite, related question: which 4769 events do match an account on the authorized list, useful when the goal is instead to filter down to only known, expected activity for a separate baseline analysis.\n\nThe key distinguishing feature of both flavors, worth remembering precisely because it differs from every other join flavor covered so far: neither one returns any columns from the right table at all. They are pure filters on the left table's existing rows, based purely on whether a match exists, which is also exactly why they tend to run faster than a join flavor that has to carry right-side columns through the result.",
        "keyPoints": [
          "leftanti returns left-side rows with NO match on the right table; leftsemi returns left-side rows WITH a match.",
          "Both flavors efficiently answer 'what is missing from (or present on) a reference list,' often faster than where...in(...).",
          "A Microsoft Sentinel watchlist is a curated reference table well suited to this kind of join, using its SearchKey column.",
          "Finding a ServiceName not on an authorized watchlist can surface shadow IT or untracked service accounts."
        ],
        "codeExample": "SecurityEvent\n| where EventID == 4769\n| where TimeGenerated > ago(1d)\n| join kind=leftanti (\n    _GetWatchlist(\"authorized-spn-services\")\n) on $left.ServiceName == $right.SearchKey\n// Result: 4769 events for ServiceName values NOT on the authorized watchlist"
      },
      {
        "pageNumber": 5,
        "title": "The lookup Operator: Lightweight Enrichment",
        "body": "join is general-purpose, but KQL provides a second, more specialized operator, lookup, built specifically for the common hunting pattern of enriching a large \"fact\" table (millions of raw events) with a small \"dimension\" table (a compact reference list), exactly the watchlist scenario from the previous page. The syntax is FactTable | lookup kind=(leftouter|inner) (DimensionTable) on Attributes, and it supports only those two flavors, a smaller set than the full join operator, because its purpose is narrower and more specific by design.\n\n### Why choose lookup over join\n\nThe practical difference from join, in everyday hunting terms, is intent and expected shape rather than raw capability: lookup signals to anyone reading the query that the right-hand table is expected to be small and mostly static, a list of authorized service accounts, known-good IP ranges, VIP user accounts, or a threat-intelligence indicator list, rather than another large, growing event stream. Reaching for lookup instead of join when enriching against exactly this kind of reference table also documents that intent clearly for the next hunter who reads the query.\n\n### Watchlists as the classic dimension table\n\nMicrosoft Sentinel watchlists, introduced briefly on the previous page, are the most common dimension table a hunter enriches against day to day, using the built-in _GetWatchlist('watchlist-name') function together with the watchlist's defined SearchKey column as the join attribute. A concrete example: enriching every high-risk sign-in with whether its source IP address appears on a maintained \"known malicious infrastructure\" watchlist, so that a match can be flagged and prioritized automatically, rather than requiring a hunter to manually cross-reference each IP address one at a time.\n\nkind=leftouter is by far the more common flavor for this enrichment pattern, for the same reason leftouter was chosen in the sign-in correlation example earlier: an event without a watchlist match is still worth seeing in the results, with a null in the enrichment column signaling clearly that no match was found, rather than the event disappearing from the results entirely.",
        "keyPoints": [
          "lookup is a specialized version of join, intended for enriching a large fact table with a small, mostly static dimension table.",
          "lookup supports only kind=leftouter or kind=inner, a smaller set of flavors than join.",
          "Microsoft Sentinel watchlists are the most common dimension table for lookup, joined on the watchlist's SearchKey column.",
          "kind=leftouter keeps every event even without a watchlist match, surfacing a null rather than dropping the event."
        ],
        "codeExample": "SigninLogs\n| where RiskLevelDuringSignIn == \"high\"\n| where TimeGenerated > ago(1d)\n| lookup kind=leftouter (\n    _GetWatchlist(\"known-malicious-ips\")\n) on $left.IPAddress == $right.SearchKey\n| project TimeGenerated, UserPrincipalName, IPAddress, ThreatCategory"
      },
      {
        "pageNumber": 6,
        "title": "externaldata: Pulling in Data Not Yet Ingested",
        "body": "Every enrichment source covered so far, another Sentinel table, a watchlist, assumes the reference data has already been loaded into the platform. Sometimes a hunter needs to test a hypothesis against a fresh list that has not been onboarded anywhere yet: a CSV of indicators just received from a threat intelligence vendor, sitting in a blob storage container, needed for one hunt today rather than a permanent watchlist next week.\n\n### Reading data straight from storage\n\nThe externaldata operator solves exactly this case, reading data directly from external storage, commonly Azure Blob Storage or Azure Data Lake Storage, without requiring it to be ingested into a table first. The syntax declares the expected schema up front: externaldata (ColumnName: ColumnType [, ...]) [StorageLocation] with (format = \"csv\"), where the storage location is typically a URL, often including a SAS (Shared Access Signature) token that grants time-limited, scoped access to that specific blob.\n\n### Protecting the credential in the URL\n\nBecause a SAS token is a credential and should never appear in plain text inside query history or shared queries, KQL supports prefixing the string literal with h, as in h@\"https://...\", which marks it as a secret literal and causes Kusto to redact it from stored query text and logs, a habit worth building immediately, since forgetting it means a credential ends up sitting in a query history table indefinitely.\n\n### A stopgap, not a permanent fix\n\nexternaldata is deliberately a stopgap, not a replacement for a proper watchlist or data connector: it works well for a single hunt run today, but it re-reads the external file on every execution rather than caching it, so it is markedly slower and less efficient for anything run repeatedly. In practice, a hunter who finds themselves reaching for the same externaldata source across more than one or two hunts should treat that as a signal to onboard it as a proper watchlist instead, the same \"close the gap properly, don't just patch around it\" principle covered in the coverage-gaps lesson earlier in this module.",
        "keyPoints": [
          "externaldata reads a file directly from external storage without first ingesting it into a table, using a declared schema.",
          "Prefix a storage URL containing a SAS token with h@ so Kusto redacts it from query history and logs.",
          "externaldata re-reads the file on every execution, fine for a one-off hunt but inefficient for repeated use.",
          "A source reused across several hunts should be onboarded as a proper watchlist instead of staying an externaldata call."
        ],
        "codeExample": "let FreshIOCs = externaldata(Indicator: string, IndicatorType: string)\n    [h@\"https://ctistorage.blob.core.windows.net/feeds/latest-iocs.csv?<SAS-token>\"]\n    with (format=\"csv\", ignoreFirstRecord=true);\nDeviceNetworkEvents\n| where Timestamp > ago(1d)\n| join kind=inner (FreshIOCs) on $left.RemoteIP == $right.Indicator"
      },
      {
        "pageNumber": 7,
        "title": "Performance Considerations When Joining at Scale",
        "body": "A join that runs fine against a small sample dataset can time out or return misleading partial results against a full production data volume if a few well-documented performance principles are ignored. These matter to a hunter specifically because a slow or failed query is not just an inconvenience; it can silently truncate results in a way that looks like a clean negative but is actually a performance limit being hit.\n\n### Filter and project before joining\n\nThe first principle, already mentioned earlier in this lesson but worth restating as a rule rather than a tip: filter and project both sides of a join down to only the rows and columns actually needed before the join executes, not after. A where clause placed after a join has already forced KQL to combine far more data than necessary; the same where clause placed before the join, on each side individually, dramatically reduces the amount of data the join engine has to process.\n\n### Table order and broadcast hints\n\nThe second principle is table order: Microsoft's own documentation notes that for best performance, the smaller of the two tables should be placed on the left side of the join wherever the size difference is known in advance, since KQL's default join strategy is optimized around that assumption. When the size difference is very large, KQL supports an explicit hint, hint.strategy=broadcast, which tells the engine to distribute the small table to every compute node rather than shuffling the much larger table across the cluster, a meaningful speedup for the common hunting pattern of joining a small watchlist or IOC list against a huge fact table.\n\n### Being explicit about flavor at scale\n\nThe third principle is being explicit about join flavor, already covered earlier, but doubly important at scale: innerunique's default deduplication behavior against a large left table can silently discard rows a hunter never intended to lose, and discovering this after a hunt has already been documented as a clean negative is a far worse outcome than a query that runs a few seconds slower with an explicit, intentional flavor.",
        "keyPoints": [
          "Filter and project both sides of a join before it runs - a where clause after the join has already forced unnecessary data through.",
          "Place the smaller table on the left when the size difference is known, and use hint.strategy=broadcast for small-vs-huge joins.",
          "A slow or resource-limited join can silently produce incomplete results that look like a clean negative.",
          "Always specify the join kind explicitly at scale - the default innerunique's silent deduplication is easy to miss."
        ],
        "codeExample": "// Explicit performance hint for a small dimension table joined against a huge fact table\nDeviceNetworkEvents\n| where Timestamp > ago(1d)\n| join kind=inner hint.strategy=broadcast (\n    _GetWatchlist(\"known-malicious-ips\")\n) on $left.RemoteIP == $right.SearchKey"
      },
      {
        "pageNumber": 8,
        "title": "Choosing the Right Correlation Tool",
        "body": "With join, its flavors, lookup, and externaldata all covered, the practical challenge shifts from knowing the syntax to knowing which tool fits a given hunting question. This final page distills that choice into a single decision path worth keeping close at hand during real hunts.\n\n### The decision path\n\nThe first question is whether the reference data is already inside the platform, as an existing Sentinel table or a maintained watchlist, or whether it lives externally in a file that has not been ingested anywhere. If it is external and this is a one-off need, externaldata is the right tool, with the clear caveat from earlier in this lesson that a source reused repeatedly should graduate into a proper watchlist instead of staying an externaldata call forever.\n\nIf the reference data is already inside the platform, the next question is its size and role: is it a small, largely static reference list (a watchlist of authorized accounts, known-bad IPs, VIP users) being used to enrich a much larger stream of events? If so, lookup is the natural, self-documenting choice, since it signals exactly that intent to any hunter reading the query later.\n\nIf instead both sides are comparably large event tables, correlating identity sign-ins with endpoint activity, as in the worked example earlier in this lesson, the general-purpose join operator is the right tool, and the specific flavor still depends on the question being asked: leftouter to keep every left row and surface non-matches as meaningful results, inner when only genuine matches on both sides matter, and leftanti or leftsemi when the question is really about presence or absence on a list rather than about pulling in additional columns at all.\n\nNone of these tools replace the judgment covered throughout this module: a returned row from any of them is still a lead requiring the standard analyst questions, not an automatic verdict.",
        "keyPoints": [
          "Choose externaldata for a one-off correlation against a file not yet ingested; graduate repeated needs into a watchlist.",
          "Choose lookup when enriching a large event stream against a small, mostly static reference table.",
          "Choose join, with an explicit flavor, when correlating two comparably large event tables against each other.",
          "Whichever tool produces a hit, it is still a lead requiring the standard analyst questions, not an automatic verdict."
        ],
        "codeExample": "flowchart TD\n    A[Is the reference data already in the platform?] -->|No, external file| B[externaldata for a one-off hunt]\n    A -->|Yes| C{Small, mostly static reference list?}\n    C -->|Yes| D[lookup kind=leftouter/inner against a watchlist]\n    C -->|No, comparable-size event tables| E{What is the question?}\n    E -->|Keep every left row, show non-matches| F[join kind=leftouter]\n    E -->|Only true matches on both sides| G[join kind=inner]\n    E -->|Presence or absence on a list| H[join kind=leftsemi or leftanti]\n    B --> I[Investigate every hit with standard analyst questions]\n    D --> I\n    F --> I\n    G --> I\n    H --> I"
      }
    ],
    "quiz": [
      {
        "question": "A hunter writes a query using '| join (RightTable) on SharedKey' without specifying kind. What is a risk of relying on this default behavior in a hunting query?",
        "options": [
          {
            "label": "The query will fail to run, since kind is a required parameter",
            "value": "a"
          },
          {
            "label": "The default innerunique flavor deduplicates the left table's keys first, which can silently drop rows the hunter didn't intend to lose",
            "value": "d"
          },
          {
            "label": "The default flavor always returns every row from both tables regardless of a match",
            "value": "c"
          },
          {
            "label": "The default flavor only works when both tables have identically named columns",
            "value": "b"
          }
        ],
        "answer": "d",
        "explanation": "innerunique is KQL's default join flavor and deduplicates the left table's keys before joining, which can silently discard rows a hunter needed - always specify kind explicitly. kind is optional, not required, so the query still runs regardless. The default does not behave like a full outer join returning every row, and it does not require identical column names, since $left/$right syntax handles differing names."
      },
      {
        "question": "A hunter wants to find every ServiceName in recent Kerberos ticket-request events (Event ID 4769) that does NOT appear on a watchlist of authorized service accounts. Which join flavor directly answers this question?",
        "options": [
          {
            "label": "leftouter, since it returns every row regardless of a match",
            "value": "c"
          },
          {
            "label": "leftsemi, since it returns rows that DO have a match",
            "value": "b"
          },
          {
            "label": "leftanti, since it returns rows that have NO match on the right table",
            "value": "a"
          },
          {
            "label": "fullouter, since it returns every combination from both tables",
            "value": "d"
          }
        ],
        "answer": "a",
        "explanation": "leftanti returns exactly the left rows with no match on the right table, which is precisely 'what is missing from the list.' leftouter returns all rows including matches, not just the missing ones. leftsemi is the opposite - it returns only matches. fullouter returns every combination from both sides, not a targeted absence check."
      },
      {
        "question": "Why would a hunter choose the lookup operator instead of the general-purpose join operator when enriching sign-in events with a watchlist of known-malicious IP addresses?",
        "options": [
          {
            "label": "lookup supports more join flavors than join does",
            "value": "a"
          },
          {
            "label": "lookup is purpose-built for enriching a large event table against a small, mostly static reference table, documenting that intent clearly",
            "value": "b"
          },
          {
            "label": "lookup is the only operator in KQL capable of reading from a Sentinel watchlist",
            "value": "c"
          },
          {
            "label": "lookup automatically escalates any match into an incident ticket",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "lookup exists specifically for the fact-table/dimension-table enrichment pattern and signals that intent to future readers of the query. It actually supports fewer flavors than join, not more. join can also read from a watchlist via _GetWatchlist(). Neither lookup nor join automatically creates tickets - that still requires analyst judgment."
      },
      {
        "question": "A hunter receives a fresh CSV of indicators from a threat intelligence vendor, stored in Azure Blob Storage, and needs to test it against network logs for a single hunt today. What is the appropriate KQL tool, and what is the tradeoff of using it repeatedly?",
        "options": [
          {
            "label": "The lookup operator; it has no tradeoffs at any scale",
            "value": "a"
          },
          {
            "label": "The externaldata operator; it re-reads the file on every execution, so a repeatedly used source should become a watchlist instead",
            "value": "c"
          },
          {
            "label": "The join operator with kind=fullouter; it requires no external storage access",
            "value": "b"
          },
          {
            "label": "A Sigma rule; KQL cannot read from external storage at all",
            "value": "d"
          }
        ],
        "answer": "c",
        "explanation": "externaldata is built exactly for reading a file not yet ingested, but it re-reads that file every time the query runs, making it inefficient for repeated use - a good candidate for graduating into a proper watchlist. lookup reads from an already-ingested dimension table, not raw blob storage. join with fullouter still needs a queryable table, not a raw file. KQL can in fact read external storage directly via externaldata."
      },
      {
        "question": "A hunter's join between DeviceNetworkEvents and a small IP watchlist is running very slowly against a full day of production traffic. Which change is most directly supported by this lesson's guidance?",
        "options": [
          {
            "label": "Remove the where clause entirely so KQL can optimize the query automatically",
            "value": "a"
          },
          {
            "label": "Filter and project both tables down to only needed rows/columns before the join, and place the smaller table appropriately",
            "value": "d"
          },
          {
            "label": "Switch the query language from KQL to a different language, since KQL cannot join large tables",
            "value": "c"
          },
          {
            "label": "Increase the time window to a full year so the query has more context",
            "value": "b"
          }
        ],
        "answer": "d",
        "explanation": "Filtering and projecting before the join, plus placing the smaller table appropriately (or using hint.strategy=broadcast), are exactly the performance principles this lesson covers. Removing the where clause would make the join slower, not faster. KQL is fully capable of joining large tables when written efficiently. Widening the time window increases the data volume and would make the slow query worse, not better."
      }
    ]
  },
  "threat-hunter--kql-aggregations": {
    "pages": [
      {
        "pageNumber": 1,
        "title": "From Raw Events to Behavioral Signal",
        "body": "Every individual log line answers a narrow question: did this one logon succeed, did this one process launch, did this one connection reach this one destination. Almost none of the \"is this normal for this entity\" judgment from earlier analyst training can be made from a single row alone; it requires looking at many rows together and asking how this one compares to the pattern. Aggregation is the KQL (Kusto Query Language) mechanism that turns thousands or millions of individual events into that kind of comparable, group-level signal, and it is the foundation this whole lesson builds on.\n\n### The summarize operator\n\nThe core tool is the summarize operator. Its basic shape is TableName | summarize AggregationFunction(Column) by GroupingColumn, and it works in two parts that must both be understood to use it correctly. The by clause defines the groups; for example, by Account groups every subsequent calculation separately for each distinct account value in the data. The aggregation function defines what gets calculated within each of those groups: count() counts rows, sum() adds a numeric column, avg() computes a mean, and many others exist for different questions.\n\n### The mistake that hides in plain sight\n\nA critical, easy-to-miss detail: omitting the by clause entirely does not produce an error; it silently collapses the entire table into a single row, aggregating across everything at once rather than per entity. A hunter who means to count logon attempts per account but forgets by Account will get one number for the whole environment, which answers a completely different, usually far less useful question, without any warning that something went wrong.\n\nThe rest of this lesson works through the specific aggregation functions a hunter reaches for most often: count and dcount, bin() for time bucketing, and arg_max() for finding a specific representative row per group, each grounded in a real hunting scenario rather than in the abstract.",
        "keyPoints": [
          "summarize groups rows via a by clause and reduces each group to a single row using a function like count(), sum(), or avg().",
          "Aggregation turns individual events into the group-level, per-entity comparisons that 'is this normal for this entity' requires.",
          "Omitting the by clause silently aggregates the entire table into one row instead of one row per entity.",
          "This lesson builds toward count/dcount, bin(), and arg_max() as core tools for anomaly detection and baselining."
        ]
      },
      {
        "pageNumber": 2,
        "title": "Counting and Distinct Counting: count() vs dcount()",
        "body": "The two most frequently used aggregation functions in hunting queries look deceptively similar but answer genuinely different questions, and confusing them produces subtly wrong conclusions rather than an obvious error.\n\n### Two different questions\n\ncount() counts rows: every matching event, including duplicates and repeats. summarize count() by Account answers \"how many total events did this account generate,\" which includes counting the same destination hit five times if it happened five times. dcount() counts distinct values of a specified expression; summarize dcount(RemoteIP) by AccountName answers a different question entirely: \"how many different destinations did this account reach,\" treating five connections to the same IP as one, not five.\n\n### Why the distinction matters for hunting\n\nThis distinction matters directly for a classic hunting scenario: identifying command-and-control (C2) beaconing or data staging by looking for accounts or hosts reaching an unusually large number of distinct external destinations, versus accounts generating an unusually high volume of total connections to a small, stable set of destinations, which usually signals something entirely different, such as a normal, high-frequency application dependency on one API endpoint. Using count() where dcount() was needed can make a frequently-contacted legitimate address look identical, in the output, to a beacon's destination, when what the hunter actually wanted to know was how many distinct destinations were touched, not the volume against any one of them.\n\nOne implementation detail worth knowing: dcount() does not compute an exact count for very large datasets by default; it uses an approximation algorithm (HyperLogLog) that trades a small amount of accuracy for dramatically better performance at scale. For most hunting purposes this approximation is close enough to be actionable, but KQL allows an optional accuracy parameter, as in dcount(Column, 2), to request a more precise (and more resource-intensive) estimate when a borderline result needs a tighter number before a decision is made.",
        "keyPoints": [
          "count() counts every matching row including repeats; dcount() counts distinct values, treating repeats as one.",
          "A host reaching many distinct destinations and a host generating heavy repeated traffic to one destination usually indicate very different situations.",
          "dcount() uses an approximation algorithm (HyperLogLog) by default; dcount(Column, 2) requests a more precise estimate.",
          "There is no separate 'dcountby' function in KQL - the pattern is always summarize dcount(column) by groupingColumn."
        ],
        "codeExample": "DeviceNetworkEvents\n| where Timestamp > ago(1d)\n| summarize\n    TotalConnections = count(),\n    DistinctDestinations = dcount(RemoteIP)\n    by DeviceName\n| where DistinctDestinations > 50\n| order by DistinctDestinations desc"
      },
      {
        "pageNumber": 3,
        "title": "bin(): Bucketing Time for Trend and Volume Analysis",
        "body": "Grouping by an exact timestamp is almost never useful, since real timestamps carry millisecond precision and essentially every row would form its own group of one. bin() solves this by rounding a value, almost always a timestamp, though it works on any numeric value, down to the nearest multiple of a specified size, turning a continuous stream of exact instants into a manageable, fixed-width set of buckets.\n\n### How bin() reshapes a timestamp\n\nbin(TimeGenerated, 1h) rounds every timestamp down to the start of its containing hour, so every event that happened between 09:00:00 and 09:59:59 lands in the same bucket, labeled 09:00:00. Used inside a summarize's by clause, this converts \"count how many failed logons happened, exactly, at each individual timestamp\" (nearly meaningless) into \"count how many failed logons happened per hour\" (immediately readable as a trend line, and immediately useful for spotting an unusual spike).\n\n### A direct hunting application\n\nA direct hunting application: detecting a burst of failed authentications against a single account, a classic signature of password-guessing or brute-force activity (MITRE ATT&CK technique T1110, Brute Force). Grouping by both the account and an hourly time bucket together, rather than by account alone, preserves the timing information a pure count would flatten away; an account with 30 failed logons evenly spread across a normal month looks nothing like 30 failed logons in a single hour, even though a plain count() by Account alone would report the same total for both. The bin() bucket is what lets a threshold like \"more than 20 failures\" be applied meaningfully per time window rather than accidentally across an account's entire multi-month history.\n\nBucket size is itself a deliberate hunting decision, not an arbitrary default: bin(TimeGenerated, 5m) suits detecting a fast, automated burst; bin(TimeGenerated, 1d) suits spotting a slower drift in daily volume over weeks. Choosing a bucket too coarse can smear a genuine spike across a wider window and hide it below a threshold; choosing one too fine can fragment a real pattern into buckets too small to individually cross any meaningful threshold.",
        "keyPoints": [
          "bin() rounds a value, typically a timestamp, down to the nearest multiple of a chosen size, creating fixed, comparable buckets.",
          "Grouping by an entity and a time bucket preserves timing, so a burst within one hour is distinguishable from months.",
          "Bucket size is a deliberate choice: too coarse smears and hides a spike, too fine fragments a real pattern.",
          "T1110 (Brute Force) is the classic technique a per-hour failed-logon count grouped by account and time bucket catches."
        ],
        "codeExample": "SigninLogs\n| where ResultType != \"0\"\n| summarize FailCount = count() by UserPrincipalName, bin(TimeGenerated, 1h)\n| where FailCount > 20\n| order by FailCount desc"
      },
      {
        "pageNumber": 4,
        "title": "arg_max() and arg_min(): Finding the Most Extreme Row Per Group",
        "body": "Sometimes the question is not \"how many\" but \"which specific row\": the most recent event for each entity, or the single largest value and everything that came with it. count() and dcount() cannot answer this, because they collapse a group down to a number and discard every other column along the way. arg_max() and arg_min() exist specifically to preserve a full row while still operating within a summarize's grouping logic.\n\n### How arg_max works\n\narg_max(ExpressionToMaximize, *) returns, for each group defined by the by clause, the complete row where ExpressionToMaximize is largest; the asterisk tells KQL to keep every other column from that winning row, not just the maximized expression itself. arg_min() is the same idea in reverse, returning the row where the expression is smallest.\n\n### The classic \"latest state\" pattern\n\nThe single most common hunting use of arg_max() is finding \"the latest known state\" of an entity: the most recent logon event per account, the most recent process seen per device, the most recent sign-in location per user. summarize arg_max(TimeGenerated, *) by TargetUserName, run against a logon-event table, returns exactly one row per account, its single most recent logon, with every other column (the device, the source IP, the logon type) intact from that specific, most-recent event.\n\nThis pattern is genuinely different from filtering with a where clause on a time range: a where clause can narrow the whole table to \"the last hour,\" but it still leaves potentially many rows per account within that hour. arg_max() collapses each account down to exactly one representative row, chosen specifically because it is the most recent, which is exactly the shape needed to build a clean, one-row-per-entity summary table, useful both as a fast dedup technique and as the practical first step toward the entity-baselining work covered elsewhere in this learning path, where a per-entity summary of recent behavior becomes the input to statistical comparison against that entity's own history.",
        "keyPoints": [
          "arg_max(Expr, *) returns the full row where Expr is largest within each group, keeping every other column.",
          "The classic use is 'latest event per entity': summarize arg_max(TimeGenerated, *) by EntityColumn.",
          "arg_max() differs from a where time filter: it collapses each group to exactly one representative row.",
          "arg_min() is the same logic in reverse, returning the row where the expression is smallest."
        ],
        "codeExample": "SecurityEvent\n| where EventID == 4624\n| where TimeGenerated > ago(1d)\n| summarize arg_max(TimeGenerated, *) by TargetUserName\n| project TargetUserName, TimeGenerated, IpAddress, LogonType, Computer"
      },
      {
        "pageNumber": 5,
        "title": "Building a Behavioral Baseline With Percentile Functions",
        "body": "Counting, bucketing by time, and pulling the latest row per entity all still leave one question unanswered: what counts as a normal amount of something for a given entity, such that a hunter can say a specific value is an outlier relative to that entity's own history, rather than relative to an arbitrary fixed number picked without evidence. Percentile functions are the tool that answers exactly this, and they connect this lesson directly to the entity-baselining work that goes deeper elsewhere in this learning path.\n\n### percentile() in practice\n\npercentile(Column, N) returns the value below which N percent of the group's values fall. percentile(SentBytes, 95) by Account, run across 30 days of network activity, returns each account's 95th-percentile daily outbound data volume, the threshold that account's own normal traffic only exceeds 5 percent of the time. This is a meaningfully different, and usually far more defensible, threshold than a single fixed number like \"flag anything over 500 megabytes,\" because a fixed number treats every account identically regardless of whether it normally sends 10 megabytes a day or 400.\n\n### The two-stage baseline-then-compare pattern\n\nThe practical hunting workflow built on this function has two stages. First, calculate each entity's own historical percentile threshold over a representative training window, such as the trailing 30 days, and store it. Second, on each new day, compare that day's actual value against the entity's own stored threshold from stage one, and flag entities that exceed their personal baseline rather than a single environment-wide cutoff. percentiles() (plural) computes several percentile values from one pass over the data at once, useful for seeing, for example, an entity's 50th, 90th, and 99th percentile side by side to understand the overall shape of its normal behavior rather than a single cutoff point.\n\nThis two-stage baseline-then-compare pattern is deliberately introduced here at a conceptual level; the deeper mechanics of building and maintaining these baselines at scale are the focus of the dedicated entity-baselining lab elsewhere in this learning path.",
        "keyPoints": [
          "percentile(Column, N) returns the value below which N percent of a group's data falls, per-entity.",
          "A per-entity percentile baseline is usually more defensible than one fixed number applied to every account or host.",
          "percentiles() (plural) computes several percentile values at once, showing an entity's overall behavior shape.",
          "The practical pattern is two-stage: calculate each entity's baseline over a training window, then compare new activity against it."
        ],
        "codeExample": "DeviceNetworkEvents\n| where Timestamp between (ago(30d) .. ago(1d))\n| summarize BytesSentP95 = percentile(SentBytes, 95) by DeviceName"
      },
      {
        "pageNumber": 6,
        "title": "Worked Hunt: Detecting Beaconing With summarize",
        "body": "Command-and-control (C2) beaconing, malware periodically checking in with an attacker-controlled server for new instructions, has a distinctive statistical signature that combines several of this lesson's tools at once: a host contacting the same, small number of external destinations repeatedly, at suspiciously regular time intervals, over an extended period.\n\n### Combining the tools\n\nThe hunt starts by grouping network events by the source device and destination, using bin() to bucket time into a chosen window, and counting connections in each bucket with count(), the same combination of tools covered independently earlier in this lesson, now applied together against one hypothesis. A host with genuine beaconing malware tends to show a fairly consistent connection count per bucket over many consecutive buckets, to the same small handful of destinations, rather than the bursty, irregular pattern typical of a human browsing the web or an application making occasional, event-driven calls.\n\n### Why timing consistency is the sharper signal\n\nConsistency of timing is the harder, more specific signal to compute directly in a single summarize pass, and real detection pipelines often calculate the standard deviation of the time gaps between successive connections as a separate step after this initial aggregation; a low standard deviation relative to the average gap indicates suspiciously regular, machine-like timing, which is far more characteristic of a beacon following a fixed check-in schedule than of organic human or even normal application traffic. This lesson introduces the aggregation building blocks that make that calculation possible; the full statistical trend-detection functions built specifically for this kind of interval analysis are covered in the time-series lesson later in this module.\n\nEven without that deeper statistical step, the basic aggregation query below is already a genuinely useful first-pass hunt: it surfaces every device/destination pair with a high connection count concentrated in a small number of hourly buckets, which a hunter can then manually inspect for the telltale regular cadence, narrowing a huge raw network log down to a short, reviewable list of real beaconing candidates.",
        "keyPoints": [
          "Beaconing produces a distinctive pattern: repeated connections to the same small set of destinations, spread evenly across many time buckets.",
          "Combining bin(), count(), and dcount() in one summarize turns a huge raw network log into a short, reviewable candidate list.",
          "Regular timing (low variance between connection intervals) is the sharpest beaconing signal, computed as a follow-up step.",
          "This query is a first-pass filter, not a final verdict - every candidate still needs manual review for a regular cadence."
        ],
        "codeExample": "DeviceNetworkEvents\n| where Timestamp > ago(2d)\n| summarize\n    ConnectionCount = count(),\n    ActiveHourBuckets = dcount(bin(Timestamp, 1h))\n    by DeviceName, RemoteIP\n| where ActiveHourBuckets >= 12 and ConnectionCount >= 24\n| order by ActiveHourBuckets desc"
      },
      {
        "pageNumber": 7,
        "title": "A Bridge to Time-Series: make-series",
        "body": "Every aggregation covered so far in this lesson produces one summary row per group: a total, a distinct count, a single representative row, a percentile threshold. Some hunting questions instead need an ordered sequence of values over time for a single entity, ready for functions that specifically analyze trends, seasonality, and anomalies within that sequence rather than a single aggregated snapshot.\n\n### The shape make-series produces\n\nmake-series is the operator that produces exactly this shape. Where summarize by bin(TimeGenerated, 1h) produces one row per bucket, spread across potentially many output rows, make-series instead produces one row per entity, with the values across all time buckets packed into a single ordered array column, the specific format that KQL's time-series analysis functions expect as their input.\n\n### Why this shape is useful\n\nThe practical value of this shape becomes clear with series_decompose_anomalies(), a function that takes exactly this kind of array and automatically separates a genuine trend and seasonal pattern from statistically unusual spikes within it, flagging the anomalous points without a hunter needing to manually define a fixed threshold at all, a meaningfully different, often more sensitive approach than the fixed or percentile-based thresholds covered earlier in this lesson, particularly for data with a strong daily or weekly rhythm, such as login volume that is naturally much lower on weekends.\n\nThis page exists specifically as a bridge rather than a full treatment: make-series and the anomaly-detection functions built on top of it are covered in depth, with complete worked examples, in the dedicated time-series analysis lesson later in this module. The connection worth carrying forward is direct: make-series is built from the exact same underlying idea as bin() and summarize covered throughout this lesson, grouping values into time buckets, reshaped specifically for feeding into a different, more specialized family of analysis functions.",
        "keyPoints": [
          "make-series produces one row per entity with an ordered array of values across time buckets.",
          "series_decompose_anomalies() separates trend and seasonal pattern from genuine anomalies without a manually defined fixed threshold.",
          "make-series is built on the same bucketing idea as bin() and summarize, reshaped for time-series analysis functions.",
          "Full time-series analysis is covered in depth in the dedicated time-series analysis lesson later in this module."
        ],
        "codeExample": "let TimeRange = 30d;\nDeviceNetworkEvents\n| where Timestamp > ago(TimeRange)\n| where DeviceName == \"FIN-PC7\"\n| make-series ConnectionCount = count() default = 0\n    on Timestamp from ago(TimeRange) to now() step 1h"
      },
      {
        "pageNumber": 8,
        "title": "Choosing the Right Aggregation Tool",
        "body": "With count(), dcount(), bin(), arg_max(), and percentile() all covered, the practical question during a real hunt is which one fits the question being asked. Matching the tool to the question up front avoids two common failure modes: computing a number that technically runs without error but answers something other than what was intended, and reaching for a heavier tool, like make-series and full time-series decomposition, when a simpler summarize would have answered the question directly.\n\n### Matching tool to question\n\nStart with the shape of the question. If it is \"how many events happened,\" count() is the tool. If it is \"how many distinct values of something occurred,\" distinct destinations, distinct accounts, distinct source IPs, dcount() is the tool, and it is almost always the more informative choice than count() whenever the question is really about variety rather than volume.\n\nIf the question involves a trend or burst over time, wrap the grouping in bin() to bucket the events by time first, regardless of which aggregation function is applied within each bucket. If the question is \"give me the one row representing the latest (or most extreme) state of each entity,\" arg_max() (or arg_min()) is the tool, remembering the asterisk to keep the full row rather than just the maximized value.\n\nIf the question is about establishing what is statistically normal for a specific entity, so that today's value can be judged an outlier against that entity's own history rather than an arbitrary fixed number, percentile() is the tool. And if the question requires analyzing the shape of a sequence over time, detecting seasonality, decomposing a trend, or automatically flagging anomalies within an ordered series, that is the signal to reach for make-series and the deeper time-series functions covered in a later lesson, rather than trying to force the answer out of summarize alone.",
        "keyPoints": [
          "Match the aggregation tool to the shape of the question: volume (count), variety (dcount), trend/burst (bin), latest row (arg_max).",
          "percentile() answers 'what is normal for this entity'; make-series answers 'what is the shape of this sequence over time.'",
          "Reaching for a heavier tool like make-series before a simpler summarize answers the question directly adds unnecessary complexity.",
          "This decision path complements, rather than replaces, the judgment every hit still requires from the standard analyst questions."
        ],
        "codeExample": "flowchart TD\n    A[What does the question actually ask?] -->|How many events?| B[count()]\n    A -->|How many distinct values?| C[dcount()]\n    A -->|Trend or burst over time?| D[bin Timestamp, size inside summarize]\n    A -->|Latest or most extreme row per entity?| E[arg_max or arg_min]\n    A -->|What is normal for this entity?| F[percentile / percentiles]\n    A -->|Shape of a sequence over time?| G[make-series plus time-series functions]"
      },
      {
        "pageNumber": 9,
        "title": "Common Aggregation Mistakes and How to Avoid Them",
        "body": "A short list of mistakes accounts for most incorrect or misleading aggregation queries, and every one of them produces a query that runs successfully and returns a plausible-looking result; none of them throw an error, which is exactly what makes them dangerous.\n\n### The four mistakes\n\nThe first mistake, already flagged earlier in this lesson but worth repeating as the single most common error: forgetting the by clause entirely. summarize count() with no by clause collapses the whole table into one number, silently answering a completely different question than summarize count() by Account was meant to ask. Always double-check that a by clause is present whenever the intent is a per-entity result.\n\nThe second mistake is treating dcount() as an exact count in every context. Its default HyperLogLog-based approximation is close enough for the overwhelming majority of hunting decisions, but a borderline result sitting right at a threshold deserves the higher-accuracy parameter, as in dcount(Column, 2), before a hunter commits to a verdict based on a number that might be off by a meaningful margin at the edge of a decision.\n\nThe third mistake is using arg_max() without the asterisk, writing arg_max(TimeGenerated) alone instead of arg_max(TimeGenerated, *). The version without the asterisk returns only the maximized timestamp value itself, discarding every other column from that row, exactly the information a hunter usually needs from the \"latest row\" pattern, silently lost.\n\nThe fourth mistake is performance-related but produces the same kind of silent, misleading result covered in the previous lesson on joins: running summarize across an enormous, unfiltered time range. Aggregating a full year of raw events with no upstream where clause is far slower than necessary and, depending on query limits, can silently truncate before scanning the full intended range; always filter with where on a bounded time range before summarizing, exactly as recommended for join earlier in this module.\n\nEvery mistake on this list shares the same root cause as the pitfalls covered in the very first lesson of this module: skipping a step of the discipline because the query still runs and still returns something plausible-looking is not the same as it answering the question actually being asked.",
        "keyPoints": [
          "Forgetting the by clause silently collapses the whole table into one row instead of one row per entity.",
          "dcount()'s default approximation is fine for most decisions, but a borderline result deserves dcount(Column, 2).",
          "arg_max(Column) without the trailing asterisk discards every other column from the winning row - use arg_max(Column, *).",
          "Filter with where on a bounded time range before summarizing; an unfiltered aggregation over a huge range is slow and risky."
        ]
      }
    ],
    "quiz": [
      {
        "question": "A hunter runs summarize TotalConnections = count() by DeviceName and separately summarize DistinctDestinations = dcount(RemoteIP) by DeviceName against the same network log. One device shows 500 for TotalConnections but only 2 for DistinctDestinations. What does this most likely indicate?",
        "options": [
          {
            "label": "The device reached 500 different external destinations, a strong sign of scanning activity",
            "value": "b"
          },
          {
            "label": "The device made many repeated connections to only two distinct destinations, unlike a host spreading connections across many destinations",
            "value": "a"
          },
          {
            "label": "The query contains an error, since count() and dcount() should always return the same number",
            "value": "c"
          },
          {
            "label": "The device is a domain controller, since only domain controllers generate high connection volume",
            "value": "d"
          }
        ],
        "answer": "a",
        "explanation": "500 total connections against only 2 distinct destinations means heavy, repeated traffic to a small, stable set of targets - the opposite of a host spreading connections across many distinct destinations. count() and dcount() measure different things and routinely differ, so that alone is not an error. Nothing about this pattern identifies the host as a domain controller specifically."
      },
      {
        "question": "A hunter wants to detect a burst of 25 failed logons for one account within a single hour, distinguishing it from the same account having 25 failed logons spread evenly across an entire month. Which technique makes this distinction possible?",
        "options": [
          {
            "label": "summarize count() by UserPrincipalName alone, with no time grouping",
            "value": "a"
          },
          {
            "label": "summarize count() by UserPrincipalName, bin(TimeGenerated, 1h), which groups counts into hourly buckets per account",
            "value": "b"
          },
          {
            "label": "dcount(UserPrincipalName), since distinct counting reveals timing patterns",
            "value": "c"
          },
          {
            "label": "arg_max(TimeGenerated, *) by UserPrincipalName, since it returns only the most recent failure",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "Adding bin(TimeGenerated, 1h) to the by clause preserves timing, so a burst concentrated in one hour produces a high count in one bucket, distinguishable from the same total spread across many buckets. Counting by account alone reports the same total either way. dcount() on the account column does not reveal timing at all. arg_max() returns a single latest row, not a count over a window."
      },
      {
        "question": "A hunter wants exactly one row per account, showing that account's single most recent logon event with every other field (device, IP, logon type) intact. Which aggregation should they use?",
        "options": [
          {
            "label": "summarize count() by TargetUserName",
            "value": "a"
          },
          {
            "label": "summarize arg_max(TimeGenerated, *) by TargetUserName",
            "value": "c"
          },
          {
            "label": "summarize dcount(TimeGenerated) by TargetUserName",
            "value": "b"
          },
          {
            "label": "summarize percentile(TimeGenerated, 95) by TargetUserName",
            "value": "d"
          }
        ],
        "answer": "c",
        "explanation": "arg_max(TimeGenerated, *) by TargetUserName returns the full row with the maximum (most recent) TimeGenerated for each account, keeping every other column via the asterisk. count() returns only a number, no row detail. dcount() counts distinct timestamps, not the latest one. percentile() is meant for numeric distributions, not for selecting a specific representative row."
      },
      {
        "question": "Why might a hunter prefer summarize percentile(SentBytes, 95) by DeviceName over a single fixed threshold like 'flag anything over 500 megabytes' for every device?",
        "options": [
          {
            "label": "A fixed threshold always runs faster, regardless of accuracy",
            "value": "a"
          },
          {
            "label": "Percentile-based thresholds are calculated per entity, so a device that normally sends far more or less data gets a threshold suited to its own history",
            "value": "d"
          },
          {
            "label": "percentile() and a fixed threshold always produce identical results in practice",
            "value": "c"
          },
          {
            "label": "Fixed thresholds cannot be written in KQL at all",
            "value": "b"
          }
        ],
        "answer": "d",
        "explanation": "A per-entity percentile threshold accounts for the fact that different devices have very different normal traffic volumes, making outlier detection far more accurate than one number applied to everyone. Query speed is not the reason this lesson gives for preferring percentile(). The two approaches routinely produce different results. Fixed thresholds are perfectly valid KQL, just less precise for this purpose than a per-entity baseline."
      },
      {
        "question": "A hunter writes summarize count() intending to count failed logons per account, but forgets to add a by clause. What happens when this query runs?",
        "options": [
          {
            "label": "KQL throws a syntax error and refuses to run the query",
            "value": "b"
          },
          {
            "label": "The query silently returns one single count for the entire table instead of one count per account",
            "value": "a"
          },
          {
            "label": "KQL automatically infers the intended by clause from the where filter",
            "value": "c"
          },
          {
            "label": "The query returns the same result as if by Account had been included",
            "value": "d"
          }
        ],
        "answer": "a",
        "explanation": "Omitting the by clause is valid KQL syntax, but it collapses the entire table into a single aggregated row rather than one row per account - a silent, plausible-looking wrong answer. There is no syntax error thrown, KQL does not infer grouping from where clauses, and the result is a different shape entirely from the intended per-account breakdown."
      }
    ]
  }
};
