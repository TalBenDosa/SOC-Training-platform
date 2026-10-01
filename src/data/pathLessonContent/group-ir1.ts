import type { AuthoredPathLesson } from "./types";

/** Authored Learning Path content — group "ir1". Keys: "<pathSlug>--<lessonSlug>". */
export const lessons_ir1: Record<string, AuthoredPathLesson> = {
  "incident-responder--ir-phases-overview": {
    "pages": [
      {
        "pageNumber": 1,
        "title": "What incident response is (and why it needs a lifecycle)",
        "body": "When a hospital emergency room receives a patient, the staff does not improvise. They follow a triage protocol: assess severity, stabilize, diagnose, treat, discharge, and review the case afterward. Incident response (**IR**) works the same way for cybersecurity: a structured, repeatable process for handling a security event so the organization reacts consistently under pressure instead of guessing in the moment.\n\n### Event vs. incident\nTwo terms that are easy to blur but matter operationally:\n- An **event** is any observable occurrence in a system — a login, a file write, a network connection. Most events are benign.\n- An **incident** is an event (or set of events) that violates security policy or threatens the confidentiality, integrity, or availability of information — for example, a confirmed malware execution or unauthorized access to a database.\n\nNot every alert is an incident, and not every incident starts with an alert. Part of the analyst's job is deciding which events cross that line.\n\n### Who does this work\nThe team responsible for handling incidents goes by several names depending on the organization: **CSIRT** (Computer Security Incident Response Team), **CIRT** (Cyber Incident Response Team), or simply the **IR team**. This team may be a dedicated group, a rotation of SOC (Security Operations Center) analysts, or a hybrid with outside help — covered later in this lesson.\n\n### Why a formal lifecycle matters\nWithout a documented process, incident handling degrades into ad hoc firefighting: evidence gets destroyed by well-meaning admins who \"just reboot the server,\" containment happens too late or too aggressively, and nobody captures what was learned. A formal lifecycle — the subject of this lesson — gives every responder, regardless of experience level, a shared map: what phase are we in, what should happen next, and who owns that decision.\n\nThe two most widely taught IR lifecycles are **NIST SP 800-61** (the U.S. National Institute of Standards and Technology's incident handling guide) and the **SANS PICERL** model. This lesson walks through both, the roles that staff them, and how the phases connect to the deeper lessons that follow in this path.",
        "keyPoints": [
          "An event is any observable occurrence; an incident is an event that violates policy or threatens confidentiality, integrity, or availability",
          "CSIRT/CIRT/IR team are common names for the group that owns incident handling",
          "A documented lifecycle prevents ad hoc firefighting: lost evidence, premature containment, and no captured lessons",
          "NIST SP 800-61 and SANS PICERL are the two dominant IR lifecycle models covered in this path"
        ]
      },
      {
        "pageNumber": 2,
        "title": "NIST SP 800-61: the four-phase lifecycle",
        "body": "**NIST SP 800-61** (\"Computer Security Incident Handling Guide\") is the most widely referenced U.S. government framework for incident response. Its Revision 2 defines a **four-phase lifecycle** that most enterprise IR programs — and every remaining lesson in this module — are built around:\n\n1. **Preparation** — building the capability before anything happens: policies, playbooks, tooling, training, communication plans.\n2. **Detection and Analysis** — recognizing that an incident may be occurring and determining its nature and scope.\n3. **Containment, Eradication, and Recovery** — NIST treats these as one combined phase, since in practice teams cycle through containing, removing, and restoring iteratively rather than in a strict straight line.\n4. **Post-Incident Activity** — capturing lessons learned and feeding them back into Preparation.\n\nThe critical design detail is that the lifecycle is a **loop, not a line**: Post-Incident Activity feeds directly back into Preparation, so every incident should leave the organization better prepared for the next one.\n\n### The 2025 update: SP 800-61 Revision 3\nIn April 2025, NIST published **SP 800-61 Revision 3**, subtitled \"Incident Response Recommendations and Considerations for Cybersecurity Risk Management: A CSF 2.0 Community Profile,\" which formally withdrew Revision 2. Rather than a standalone four-phase process, Revision 3 maps incident response activities across all six **CSF 2.0** (NIST Cybersecurity Framework 2.0) functions: **Govern, Identify, Protect, Detect, Respond, Recover** — treating IR as woven through the entire risk management lifecycle rather than a separate discipline that starts only when Detect fires.\n\nIn practice, both models describe the same work; Revision 3 broadens the frame (governance and proactive hardening count as IR work too), while the four-phase model from Revision 2 remains the clearest way to teach the tactical, in-the-moment sequence a responder follows during an active incident. This path uses the four-phase structure as the backbone because it maps cleanly onto what an analyst actually does, module by module.",
        "codeExample": "flowchart TD\n    A[Preparation] --> B[Detection and Analysis]\n    B --> C[Containment, Eradication, and Recovery]\n    C --> D[Post-Incident Activity]\n    D -->|Lessons learned feed back| A",
        "keyPoints": [
          "NIST SP 800-61 Rev. 2 defines four phases: Preparation; Detection and Analysis; Containment, Eradication, and Recovery; Post-Incident Activity",
          "NIST treats Containment, Eradication, and Recovery as one combined, iterative phase — not three strict sequential steps",
          "The lifecycle loops: Post-Incident Activity feeds back into Preparation",
          "SP 800-61 Revision 3 (April 2025) withdrew Rev. 2 and reframed IR across all six CSF 2.0 functions (Govern, Identify, Protect, Detect, Respond, Recover)"
        ]
      },
      {
        "pageNumber": 3,
        "title": "SANS PICERL: the six-step model",
        "body": "Alongside NIST, the **SANS Institute** (a private cybersecurity research and training organization) teaches a six-step model known by the acronym **PICERL**:\n\n| Step | Meaning |\n|---|---|\n| **P** | Preparation |\n| **I** | Identification |\n| **C** | Containment |\n| **E** | Eradication |\n| **R** | Recovery |\n| **L** | Lessons Learned |\n\nPICERL is functionally the same journey as NIST's four phases, just split more finely. Where NIST bundles Containment, Eradication, and Recovery into one phase, PICERL calls them out as three distinct, sequential steps — which many practitioners find easier to brief to stakeholders because each step has a clear, singular deliverable (isolate the threat, remove it, restore normal operations).\n\n### Mapping the two models\n| NIST SP 800-61 (Rev. 2) | SANS PICERL |\n|---|---|\n| Preparation | Preparation |\n| Detection and Analysis | Identification |\n| Containment, Eradication, and Recovery | Containment → Eradication → Recovery |\n| Post-Incident Activity | Lessons Learned |\n\nNeither model is \"more correct\" — they describe the same underlying discipline from different granularities. NIST's grouping reflects how real incidents actually run (you rarely finish containing before you start eradicating); PICERL's separation reflects how a team plans and reports on the work. This path's next four lessons follow the PICERL granularity — Detection & Analysis, Containment, Eradication & Recovery, Post-Incident Review — because breaking Containment/Eradication/Recovery into distinct lessons lets each get the depth it deserves.\n\n### Why the mapping matters for you\nWhen you join a SOC, you will hear both vocabularies used interchangeably, sometimes in the same meeting. Knowing that \"Identification\" in a PICERL-trained colleague's vocabulary means the same territory as \"Detection and Analysis\" in a NIST-trained colleague's vocabulary prevents confusion during a live incident bridge call, when precision of language matters most.",
        "codeExample": "timeline\n    title SANS PICERL Incident Lifecycle\n    Preparation : IR plan, tooling, training\n    Identification : Alert triage, scope confirmation\n    Containment : Isolate affected systems\n    Eradication : Remove root cause\n    Recovery : Restore normal operations\n    Lessons Learned : Postmortem, playbook updates",
        "keyPoints": [
          "PICERL = Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned",
          "PICERL separates what NIST bundles into one Containment/Eradication/Recovery phase into three distinct steps",
          "NIST 'Detection and Analysis' maps to PICERL 'Identification'; NIST 'Post-Incident Activity' maps to PICERL 'Lessons Learned'",
          "Both models describe the same discipline at different levels of granularity — expect to hear both vocabularies in a real SOC"
        ]
      },
      {
        "pageNumber": 4,
        "title": "Preparation: building the capability before you need it",
        "body": "Preparation is the phase every other phase depends on, and it happens continuously, not just once. If detection tooling, documented procedures, and trained people are not in place before an incident starts, every later phase runs slower and with more mistakes.\n\n### What Preparation includes\n- **Incident response plan (IRP)** — the organization's top-level policy document: who has authority to declare an incident, escalation paths, legal/regulatory notification obligations, and roles (covered on the next page).\n- **Playbooks** — scenario-specific, step-by-step response procedures (phishing, ransomware, insider threat). Lesson 6 of this module builds one in depth.\n- **Tooling readiness** — a SIEM (Security Information and Event Management platform that centralizes and correlates logs), EDR (Endpoint Detection and Response — endpoint agents that monitor process, file, and network activity for malicious behavior) coverage across critical hosts, forensic imaging tools, and a tested backup/restore process.\n- **Communication plan** — internal escalation contacts, legal counsel, external PR/communications, and — where required — regulator or law enforcement contacts, all defined *before* the pressure of an active incident.\n- **Training and exercises** — tabletop exercises that walk the team through simulated scenarios without touching production, so the first time someone follows the playbook is not during a real fire.\n- **The \"jump bag\"** — a literal or virtual incident response kit: clean forensic media, statically-compiled collection tools, network diagrams, and contact lists, ready to grab.\n\n### Why this phase never \"finishes\"\nPreparation both opens the lifecycle and receives its feedback loop from Post-Incident Activity (lesson 5 of this module). Every real incident exposes preparation gaps — a missing log source, an outdated contact list, a playbook that did not cover the actual attack path. A mature IR program treats Preparation as a living backlog that gets funded and revised after every incident, not a binder written once and left on a shelf.\n\nAn organization can be excellent at Preparation and still have a bad day — but an organization with poor Preparation guarantees a bad day gets worse.",
        "keyPoints": [
          "Preparation covers the IR plan, playbooks, tooling readiness (SIEM/EDR coverage), communication plan, training, and a ready incident response kit",
          "SIEM centralizes and correlates logs; EDR monitors endpoint process/file/network activity for malicious behavior",
          "Tabletop exercises let a team rehearse a playbook before a real incident forces them to follow it for the first time",
          "Preparation is continuously refreshed by the Post-Incident Activity feedback loop, not a one-time deliverable"
        ]
      },
      {
        "pageNumber": 5,
        "title": "IR team roles and responsibilities",
        "body": "Incident response is not one job — it is a set of roles that may be filled by one overworked analyst in a small shop or by a dozen specialists on a major breach. Knowing the roles matters even if you personally only ever fill one of them, because you need to know who to call.\n\n### Core roles\n- **Incident Commander (IC)** — owns the incident end to end: makes the final call on containment actions, coordinates across teams, and is the single point of decision authority during the response. The IC does not have to be the most senior technical person — they need to be the clearest communicator and decision-maker under pressure.\n- **IR Analyst (Tier 1/2/3)** — performs the hands-on technical work: triage, log analysis, host investigation. Tier 1 typically handles initial alert triage; Tier 2/3 handle deep investigation and complex incidents, mirroring standard SOC tiering.\n- **Forensic Analyst** — performs deep host/memory/disk analysis when root cause or full scope is unclear, often working from forensic images rather than live systems to preserve evidence integrity.\n- **Threat Intelligence Analyst** — enriches the incident with context: is this IOC (Indicator of Compromise) associated with a known threat actor, campaign, or MITRE ATT&CK technique?\n- **Communications/PR Liaison** — manages messaging to employees, customers, media, and regulators, ensuring the organization speaks with one accurate voice.\n- **Legal Counsel** — advises on regulatory notification deadlines (e.g., breach notification laws), evidence handling for potential litigation, and law enforcement engagement.\n- **Management Sponsor / Executive Owner** — authorizes resourcing, business-impact tradeoffs (e.g., taking a revenue-generating system offline), and external disclosure decisions.\n- **IT/Infrastructure Owner** — the subject-matter expert on the affected system who executes technical changes (isolating a host, resetting an account) under the IC's direction.\n\n### Why role clarity matters mid-incident\nDuring a live incident, the worst failure mode is not lack of skill — it is confusion over who has authority to make a call. If two people both believe they can authorize taking a production database offline, or nobody believes they can, response slows exactly when speed matters most. A documented RACI (Responsible, Accountable, Consulted, Informed) for these roles, defined during Preparation, removes that ambiguity before it costs time.",
        "keyPoints": [
          "The Incident Commander owns final decision authority and coordination — not necessarily the most senior technical person",
          "IR Analyst tiers (1/2/3) mirror standard SOC tiering: initial triage through deep investigation",
          "Forensic analysts work from preserved images to protect evidence integrity; threat intel analysts add campaign/actor context",
          "Legal, communications, and executive roles are essential non-technical seats at the table, not afterthoughts"
        ]
      },
      {
        "pageNumber": 6,
        "title": "Team models and staffing options",
        "body": "Beyond individual roles, NIST SP 800-61 describes structural models for how an IR team is organized across an organization, plus staffing choices for who fills those seats.\n\n### Team structure models\n- **Central team model** — a single team handles incident response for the entire organization, regardless of business unit or geography. Works well for small-to-medium organizations with centralized IT.\n- **Distributed team model** — multiple teams each cover a defined slice of the organization (a business unit, a region, a subsidiary), typically reporting up to one coordinating authority. Suits large or geographically dispersed organizations.\n- **Coordinating team model** — a central team provides guidance, threat intelligence, and coordination to largely autonomous distributed teams, without direct authority over them. Common in loosely federated organizations (e.g., a holding company with independently-operated subsidiaries) or at a national level (a national CERT coordinating with sector-specific teams).\n\n### Staffing options\n- **Fully in-house** — all IR staff are employees. Maximum institutional knowledge and control; requires sustained investment in headcount, tooling, and 24/7 coverage.\n- **Partially outsourced** — an internal team handles day-to-day triage, with an external **MSSP** (Managed Security Service Provider) or specialist **DFIR** (Digital Forensics and Incident Response) retainer firm engaged for surge capacity, deep forensics, or major incidents.\n- **Fully outsourced** — an external provider handles the entire IR function, common for smaller organizations without the budget or scale to justify a dedicated in-house team.\n\n### Choosing a model\nThe right choice depends on organization size, geographic spread, regulatory environment, and budget — there is no universally \"correct\" answer. A hospital network with facilities across five states might run a distributed model with a central coordinating SOC; a single-site manufacturer might retain a DFIR firm on standby rather than staff a 24/7 team it cannot fully utilize. What matters for an analyst is recognizing which model your organization uses, because it determines who you escalate to and how fast that escalation can move.",
        "keyPoints": [
          "Central model: one team for the whole organization. Distributed model: multiple teams per business unit/region under one authority",
          "Coordinating model: a central team advises largely autonomous distributed teams without direct command authority",
          "Staffing ranges from fully in-house to partially outsourced (MSSP/DFIR retainer for surge capacity) to fully outsourced",
          "The right model depends on size, geography, regulation, and budget — know which one your organization runs"
        ]
      },
      {
        "pageNumber": 7,
        "title": "From event to incident: activation and escalation",
        "body": "This lesson closes by connecting the lifecycle to the next one: how does a SOC actually decide that \"Detection and Analysis\" has started, and who gets pulled in?\n\n### Trigger criteria\nMost organizations define, during Preparation, explicit **activation criteria** — conditions under which an analyst must formally declare an incident and invoke the IR plan, rather than continuing routine alert handling. Typical triggers include:\n- Confirmed malware execution on a host with access to sensitive data\n- Unauthorized access to a privileged account (e.g., a Domain Admin credential used from an unrecognized location)\n- Evidence of data exfiltration\n- A ransomware note or file encryption activity\n- A critical system outage with signs of malicious cause\n\n### The escalation chain\nA typical escalation path looks like this: a SIEM correlation rule or EDR detection generates an alert → a Tier 1 SOC analyst performs initial triage → if the alert appears to be a true positive matching activation criteria, the analyst escalates to the on-call Incident Commander or Tier 2/3 analyst → the IC formally declares an incident, which starts the clock on the response SLA (Service Level Agreement) and pulls in the roles from the previous page as needed.\n\n### Severity drives who gets pulled in\nNot every declared incident needs the full roster. A contained single-host malware infection with no data access might only need an IR analyst and the IT system owner. A confirmed ransomware outbreak spanning multiple business units needs the Incident Commander, legal counsel, communications, and executive sponsor engaged within the first hour. The next lesson, **Detection and Analysis**, covers exactly how severity and scope get assessed — including the incident classification matrix that formalizes this decision instead of leaving it to gut feeling.\n\nGetting activation criteria wrong in either direction is costly: too loose, and every false positive triggers a costly full incident response; too strict, and real incidents get treated as routine tickets until the damage has already spread.",
        "keyPoints": [
          "Activation criteria are pre-defined conditions (confirmed malware, privileged account misuse, exfiltration signs, ransomware indicators) that trigger formal incident declaration",
          "A typical escalation chain runs from SIEM/EDR alert to Tier 1 triage to Incident Commander declaration",
          "Formal declaration starts the response SLA clock and determines which IR roles get activated",
          "Severity and scope — covered next in Detection and Analysis — determine how much of the IR roster is needed"
        ]
      },
      {
        "pageNumber": 8,
        "title": "Worked example: a phishing incident across the lifecycle",
        "body": "To make the four phases concrete, walk through a single incident at a fictional company, NexaCorp, end to end.\n\n### Preparation (weeks before)\nNexaCorp's SOC already has: EDR deployed on all endpoints, a documented phishing playbook, an on-call rotation for the Incident Commander role, and a tested process for resetting Microsoft 365 credentials. None of this was built during the incident — it existed already.\n\n### Detection and Analysis (hour 0)\nAn employee in Finance reports a suspicious email requesting an urgent wire transfer. Simultaneously, the EDR platform flags an unusual PowerShell process spawned from Microsoft Outlook on the same employee's laptop. A Tier 1 analyst pulls the raw alert, confirms the email contained a malicious link, and finds the PowerShell activity connected outbound to an unfamiliar external IP address. This matches activation criteria (confirmed malicious execution plus network egress); the analyst escalates.\n\n### Containment, Eradication, and Recovery (hour 1–24)\nThe Incident Commander is paged. The affected laptop is isolated from the network via the EDR console (short-term containment) while the analyst confirms no lateral movement occurred. The employee's account credentials are reset and active sessions revoked. The malicious payload and its persistence mechanism are removed from the isolated host; the host is then re-imaged as a precaution before reconnecting to the network (eradication). The laptop rejoins the network under enhanced monitoring for 72 hours (recovery).\n\n### Post-Incident Activity (day 3–10)\nThe team holds a lessons-learned meeting. They discover the phishing email bypassed the email filter because it used a newly registered domain not yet on any threat intelligence blocklist. The action item: subscribe to a newly-registered-domain intelligence feed and tighten the email filter's sensitivity threshold — directly feeding back into Preparation for the next incident.\n\nNotice how each phase in this walkthrough maps directly onto the NIST four-phase structure — and how naturally the loop closes back to Preparation, exactly as the lifecycle diagram on page 2 described.",
        "keyPoints": [
          "A single realistic incident touches every phase of the lifecycle in sequence, with Containment/Eradication/Recovery often overlapping in practice",
          "Preparation work (EDR deployment, playbooks, tested reset procedures) directly determines how fast Detection and Containment can move",
          "Short-term containment (isolate the host) happens before eradication (remove the payload) and recovery (reconnect under monitoring)",
          "Post-Incident Activity findings become concrete Preparation improvements — closing the loop"
        ]
      }
    ],
    "quiz": [
      {
        "question": "A SOC analyst notices a laptop made an outbound connection to an unfamiliar IP address. On its own, this is best described as which of the following?",
        "options": [
          {
            "label": "An incident, because any unusual network connection automatically violates policy",
            "value": "a"
          },
          {
            "label": "An event, until it is confirmed to violate policy or threaten confidentiality, integrity, or availability",
            "value": "b"
          },
          {
            "label": "A precursor that can be ignored since no data loss has been confirmed yet",
            "value": "c"
          },
          {
            "label": "A false positive, since EDR tools frequently misclassify normal traffic",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "By definition, an event is any observable occurrence; it only becomes an incident once it is confirmed to violate policy or threaten confidentiality, integrity, or availability. A single unusual connection needs analysis before that determination can be made — it isn't automatically an incident, and dismissing it outright as either irrelevant or a false positive skips the analysis step entirely."
      },
      {
        "question": "Which pairing correctly matches a NIST SP 800-61 phase to its SANS PICERL equivalent?",
        "options": [
          {
            "label": "NIST 'Detection and Analysis' corresponds to PICERL 'Identification'",
            "value": "a"
          },
          {
            "label": "NIST 'Preparation' corresponds to PICERL 'Lessons Learned'",
            "value": "b"
          },
          {
            "label": "NIST 'Post-Incident Activity' corresponds to PICERL 'Containment'",
            "value": "c"
          },
          {
            "label": "NIST combines Containment, Eradication, and Recovery, which PICERL calls 'Identification'",
            "value": "d"
          }
        ],
        "answer": "a",
        "explanation": "NIST's 'Detection and Analysis' phase and PICERL's 'Identification' step cover the same work: recognizing and scoping a potential incident. Preparation maps to Preparation (not Lessons Learned) in both models, Post-Incident Activity maps to Lessons Learned (not Containment), and PICERL splits Containment, Eradication, and Recovery into three separate steps rather than folding them into 'Identification.'"
      },
      {
        "question": "During a major ransomware incident, two team members disagree about whether a production database server should be taken offline. Which role's job is it to make the final call?",
        "options": [
          {
            "label": "The Forensic Analyst, since they have the deepest technical access to the host",
            "value": "a"
          },
          {
            "label": "The Incident Commander, who holds final decision authority and coordinates the response",
            "value": "b"
          },
          {
            "label": "The Threat Intelligence Analyst, since they best understand the attacker's intent",
            "value": "c"
          },
          {
            "label": "Whichever analyst escalated the alert first",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "The Incident Commander's defining responsibility is owning the incident end to end and making the final decision under pressure, precisely to resolve situations like conflicting opinions on a containment tradeoff. Forensic and threat intelligence analysts provide input the IC weighs, but neither role carries decision authority, and authority is not assigned based on who escalated first."
      },
      {
        "question": "A holding company wants its independently-run subsidiaries to keep their own incident response teams, while a central group shares threat intelligence and guidance without direct command authority over them. Which IR team structure is this?",
        "options": [
          {
            "label": "Central team model",
            "value": "a"
          },
          {
            "label": "Distributed team model",
            "value": "b"
          },
          {
            "label": "Coordinating team model",
            "value": "c"
          },
          {
            "label": "Fully outsourced model",
            "value": "d"
          }
        ],
        "answer": "c",
        "explanation": "The coordinating team model fits exactly this scenario: a central team advises and shares intelligence with largely autonomous teams but does not hold direct authority over them. The central model uses one team for the whole organization, the distributed model has multiple teams reporting up to one authority, and 'fully outsourced' is a staffing choice, not a structural model."
      },
      {
        "question": "What was the key reason NIST withdrew SP 800-61 Revision 2 and published Revision 3 in April 2025?",
        "options": [
          {
            "label": "To replace the four-phase lifecycle with SANS PICERL as the new federal standard",
            "value": "a"
          },
          {
            "label": "To reframe incident response as activity spanning all six CSF 2.0 functions rather than a standalone process",
            "value": "b"
          },
          {
            "label": "To remove Preparation as a formal phase since tooling now automates it",
            "value": "c"
          },
          {
            "label": "To mandate that all incidents be fully outsourced to certified DFIR firms",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "Revision 3 is subtitled 'A CSF 2.0 Community Profile' and maps incident response recommendations across all six CSF 2.0 functions — Govern, Identify, Protect, Detect, Respond, and Recover — rather than treating IR as a separate standalone process. It did not adopt PICERL as a federal standard, did not remove Preparation, and made no staffing mandate about outsourcing."
      }
    ]
  },
  "incident-responder--detection-and-analysis": {
    "pages": [
      {
        "pageNumber": 1,
        "title": "Where detections come from",
        "body": "Detection and Analysis is where the incident response lifecycle actually begins for most analysts — the moment something surfaces that might be worth an incident. Before an analyst can triage anything, they need to know where signals come from.\n\n### Primary detection sources\n- **SIEM** (Security Information and Event Management) — a platform that ingests logs from many sources (firewalls, servers, applications, identity providers) and applies correlation rules to surface suspicious patterns a human would never spot by reading raw logs one at a time. Examples: Splunk, Microsoft Sentinel, Elastic Security.\n- **EDR** (Endpoint Detection and Response) — agents installed on endpoints (laptops, servers) that monitor process execution, file activity, and network connections in real time and apply behavioral detection logic. Examples: CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne.\n- **IDS/IPS** (Intrusion Detection/Prevention System) — network-based sensors that inspect traffic against signatures or anomaly models (e.g., Suricata, Snort).\n- **Threat intelligence feeds** — external sources of known-bad indicators (malicious IPs, domains, file hashes) that can be matched against internal telemetry.\n- **User reports** — an employee reporting a suspicious email or unexpected system behavior remains one of the highest-value detection sources in most organizations, because humans catch social engineering that technical controls miss.\n- **Vulnerability scanning and audit findings** — not detections of active compromise, but signals of exposure that inform how seriously to weigh other alerts on the same asset.\n\n### Detections rarely arrive alone\nA mature SOC correlates across these sources rather than treating each as an isolated queue. A single EDR alert for a suspicious PowerShell command becomes far more actionable when paired with a SIEM-correlated failed-then-successful login from an unusual geography on the same account, minutes apart. This lesson builds the workflow for turning any of these raw signals into a scoped, classified, and — where warranted — escalated incident, continuing directly from where the previous lesson's activation criteria left off.",
        "keyPoints": [
          "SIEM correlates logs from many sources to surface patterns; EDR monitors endpoint process/file/network behavior directly",
          "IDS/IPS inspect network traffic against signatures or anomaly models",
          "User reports remain one of the highest-value detection sources because humans catch social engineering technical controls miss",
          "A mature SOC correlates across sources rather than triaging each alert queue in isolation"
        ]
      },
      {
        "pageNumber": 2,
        "title": "Precursors vs. indicators",
        "body": "NIST SP 800-61 draws a specific distinction that shapes how an analyst prioritizes: precursors versus indicators.\n\n### Precursors\nA precursor is a sign that an incident may occur in the future. Precursors are rare in practice but valuable when they appear, because they offer a chance to act before any compromise happens. Examples:\n- A new, high-severity vulnerability is publicly disclosed for software the organization runs (a **CVE**, or Common Vulnerabilities and Exposures entry) before any exploitation attempt is observed\n- A threat intelligence report naming the organization's sector as a current target of an active campaign\n- Reconnaissance activity detected against the organization's external perimeter — port scans, DNS enumeration\n\n### Indicators\nAn indicator is a sign that an incident may have already occurred or may be occurring now. Indicators are far more common and are what most SOC alert queues are built around. Examples:\n- An EDR alert for a known malicious process hash executing on a host\n- A SIEM correlation rule firing on multiple failed logon attempts (Windows Event ID 4625) followed by a success (Event ID 4624) on a privileged account\n- A file integrity monitoring alert for an unexpected change to a critical system binary\n- An IDS alert matching a signature for known command-and-control (**C2**) traffic\n\n### Why the distinction matters operationally\nPrecursors give you the option to move into preventive action — patch the vulnerability, harden the exposed service — before Detection and Analysis of an actual incident is even needed. Indicators mean you may already be behind: something has happened, and the job now is figuring out what, how far, and how urgently to act. An analyst who confuses the two can either waste containment resources on a precursor that hasn't materialized into anything, or fail to recognize that a \"just a scan\" precursor has, over the following days, become the reconnaissance phase of an active intrusion whose indicators are now appearing elsewhere in the environment.",
        "codeExample": "# Raw indicator: Windows Security Event ID 4688 (process creation)\n# captured on a domain-joined workstation with command-line auditing enabled\nEventID: 4688\nNewProcessName: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\nCommandLine: powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATw...\nParentProcessName: C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE\nSubjectUserName: j.reyes\nTimeCreated: 2026-09-14T14:22:07Z",
        "keyPoints": [
          "A precursor signals an incident may occur in the future (a new CVE, a targeted threat report, external recon)",
          "An indicator signals an incident may already be occurring or have occurred (malicious process execution, brute-force-then-success logon pattern)",
          "Windows Event ID 4625 is a failed logon; 4624 is a successful logon — the pattern together is a classic indicator",
          "Confusing the two misdirects resources: over-reacting to a precursor, or under-reacting to an indicator hiding in what looked like routine recon"
        ]
      },
      {
        "pageNumber": 3,
        "title": "Initial triage: from alert to validated finding",
        "body": "Every alert starts as a hypothesis, not a fact. Triage is the structured process of proving or disproving that hypothesis using raw telemetry, before committing to an incident declaration.\n\n### The triage workflow\n1. Read the alert, not just the title. Understand exactly what condition fired — which field, which threshold, which rule logic.\n2. Pull the underlying raw event. SIEM/EDR alerts are summaries; the raw log record (a Windows Event ID 4688 process creation, a Sysmon Event ID 1 process-create event, an EDR process telemetry record) contains the detail needed to judge legitimacy: full command line, parent process, file hash, signer, and network destination.\n3. Check enrichment context. Is the process signed by a trusted publisher? Is the destination IP or domain known-malicious in threat intelligence? Is this behavior normal for this specific host's role (a developer's laptop running PowerShell is less surprising than a domain controller running it interactively)?\n4. Classify: true positive, false positive, or benign-but-worth-tuning. A true positive confirms malicious or policy-violating activity. A false positive means the detection logic fired incorrectly. A benign positive is technically accurate detection of activity that turns out to be authorized (IT running a legitimate remote administration script) — worth tuning the rule, but not an incident.\n5. Escalate or close with documentation, either way leaving a clear record for the next analyst or an auditor.\n\n### A concrete pivot\nOn Microsoft Defender for Endpoint or Microsoft Sentinel, an analyst investigating a suspicious PowerShell alert would pivot into the DeviceProcessEvents table — the advanced hunting schema table that records every process launch collected from onboarded endpoints — using KQL (Kusto Query Language), the query language used across Microsoft Sentinel and Microsoft 365 Defender advanced hunting.",
        "codeExample": "// KQL — pull full process lineage for a suspicious PowerShell execution\nDeviceProcessEvents\n| where DeviceName == \"FIN-LT-0417\"\n| where FileName =~ \"powershell.exe\"\n| where Timestamp between (datetime(2026-09-14T14:00:00Z) .. datetime(2026-09-14T15:00:00Z))\n| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,\n          InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256\n| order by Timestamp asc",
        "keyPoints": [
          "Triage means proving or disproving an alert's hypothesis with raw telemetry before declaring an incident",
          "Raw events (Event ID 4688, Sysmon Event ID 1, EDR process records) carry the command line, parent process, hash, and signer detail summaries omit",
          "Outcomes are true positive, false positive, or benign-but-worth-tuning — each requires documentation",
          "DeviceProcessEvents (Microsoft Defender for Endpoint / Sentinel advanced hunting) records every process launch and is a standard pivot point for KQL triage"
        ]
      },
      {
        "pageNumber": 4,
        "title": "Scope assessment: how far does this go?",
        "body": "Once an alert is confirmed as a true positive, the next question is not \"how do we fix it\" — that is the subject of the following two lessons — but \"how big is it.\" Declaring an incident against the wrong scope wastes the response effort: containing one host while three others remain compromised accomplishes nothing.\n\n### Pivoting on identifiers\nScope assessment works by taking every confirmed indicator from the initial finding and searching the environment for its recurrence elsewhere:\n- File hash (typically SHA-256) — has this exact malicious binary executed on any other host?\n- Source or destination IP/domain — has any other host communicated with the same command-and-control infrastructure?\n- Compromised account — has this account authenticated from anywhere else, accessed anything else, or been used to create new accounts or grant new permissions?\n- Registry key, scheduled task, or service name — persistence mechanisms are often reused verbatim across multiple compromised hosts by the same toolkit.\n\n### A concrete pivot query\nA Splunk analyst pivoting on a confirmed malicious file hash across the environment, searching the Sysmon Operational log sourcetype, might run a search like the one below, using the standard SPL (Search Processing Language) pipe syntax to filter, then tabulate results by host and account.\n\n### Why scope assessment happens before a containment decision\nThe next lesson in this module, Containment strategies, depends entirely on an accurate answer to this page's question. An Incident Commander deciding how aggressively to isolate systems needs to know whether they are dealing with one host or ten before choosing between a narrow, low-disruption action and a broader, more disruptive one. Rushing to contain before scope is understood risks the worst of both outcomes: either isolating far more of the environment than necessary (unnecessary business disruption) or isolating too little, leaving a parallel foothold active and undetected while the team declares victory too early. Scope assessment is therefore not a bureaucratic delay before the \"real\" response begins — it is itself part of the response, and skipping it is one of the most common ways a well-intentioned team under-scopes an incident.",
        "codeExample": "index=endpoint sourcetype=\"XmlWinEventLog:Microsoft-Windows-Sysmon/Operational\" EventCode=1\n  Hashes=\"*1d6ef17dbba9352b61a03b8735a7aaf1413de32c873edb32a69901d49679831d*\"\n| stats count min(_time) as first_seen max(_time) as last_seen by ComputerName, User\n| sort - count",
        "keyPoints": [
          "Scope assessment answers 'how far does this go' by re-searching the environment for every confirmed indicator",
          "Pivot identifiers include file hash, C2 IP/domain, the compromised account, and reused persistence artifacts (registry keys, scheduled tasks)",
          "Declaring an incident against too narrow a scope leaves other compromised hosts untouched",
          "Sysmon Event ID 1 (process creation, including file hash) is a standard field to pivot on in a Splunk-based hunt"
        ]
      },
      {
        "pageNumber": 5,
        "title": "Incident classification and severity",
        "body": "Once scope is understood, the incident needs a formal severity classification. This is what turns \"an analyst's gut feeling\" into a repeatable, auditable decision that determines response urgency and which IR roles get pulled in — directly extending the activation-criteria discussion from the previous lesson.\n\n### A public reference model: CISA's incident categorization\nThe U.S. **CISA** (Cybersecurity and Infrastructure Security Agency) Federal Incident Notification Guidelines score incidents along three independent dimensions:\n\n| Dimension | What it measures | Example levels |\n|---|---|---|\n| **Functional Impact** | Effect on the ability to deliver business/mission services | None, minimal impact to non-critical services, denial of critical services / loss of control |\n| **Information Impact** | Type of data lost, altered, or exposed | No impact, suspected breach, privacy data breach, core credential compromise |\n| **Recoverability** | Resources needed to recover | Regular (predictable, existing resources), Supplemented (needs additional resources), Extended (needs external assistance), Not Recoverable |\n\nScoring across all three dimensions — rather than a single \"severity 1-4\" number — avoids the trap of under-rating an incident that has low immediate functional impact but a severe information impact (e.g., quiet, ongoing exfiltration of customer data with no visible service disruption at all).\n\n### Building an internal classification matrix\nMost organizations translate this into an internal matrix (commonly Sev1 through Sev4) that maps combinations of functional/information impact and recoverability to a required response time and escalation tier. For example: any incident scored as a privacy data breach automatically triggers legal counsel involvement regardless of functional impact, because notification law deadlines run from discovery, not from business disruption.\n\n### Why this belongs in Detection and Analysis, not later\nClassification happens here, before Containment, because the classification directly determines how aggressively to contain: a Sev1 \"denial of critical services\" incident may justify disruptive short-term containment (discussed next lesson) that a Sev4 \"minimal impact\" incident would not.",
        "keyPoints": [
          "CISA's model scores incidents on three independent axes: Functional Impact, Information Impact, and Recoverability",
          "A low-functional-impact incident can still be severe if Information Impact is high (e.g., quiet data exfiltration with no visible outage)",
          "Internal Sev1-Sev4 matrices translate these axes into required response time and which roles are escalated",
          "Classification happens during Detection and Analysis because it directly shapes how aggressive the next phase's containment decision should be"
        ]
      },
      {
        "pageNumber": 6,
        "title": "Documentation and evidence handling during analysis",
        "body": "Everything an analyst does during Detection and Analysis either strengthens or weakens the evidentiary and operational record the rest of the response depends on. This matters even before any containment action is taken.\n\n### What to capture, continuously\n- **Timeline** — a running log of every observed event with precise timestamps (and time zone), including when the analyst first saw it, not just when it occurred.\n- **Chain of custody** — for any artifact collected (a memory image, a suspicious file, a log export), a record of who collected it, when, how, and who has had access since, so it can later withstand scrutiny in a legal or regulatory context if needed.\n- **Actions taken** — every query run, every system touched, every account checked, logged with timestamps. This protects the analyst as much as it documents the incident: if a system breaks during investigation, the record shows whether the investigation caused it.\n- **Working hypothesis and confidence** — analysts should record not just facts but their current theory of what happened and how confident they are, so a colleague taking over mid-shift does not have to start from zero.\n\n### Where this lives\nMost SOCs use a dedicated case management or ticketing system (rather than scattered chat messages or personal notes) specifically so this record is centralized, timestamped automatically, and survives staff turnover on a multi-day incident. A typical entry captures the who/what/when/where/how of a single analytical step.\n\n### Why this discipline pays off later\nThe post-incident review (a later lesson in this module) depends entirely on the quality of this record — a vague timeline makes root cause analysis guesswork. And if the incident escalates to litigation or regulatory reporting, undocumented or inconsistent evidence handling can undermine the organization's position regardless of how well the technical response was actually executed.",
        "codeExample": "Case #IR-2026-0914  |  Analyst: m.chen  |  2026-09-14T14:31Z\nAction: Queried DeviceProcessEvents for DeviceName=FIN-LT-0417, 14:00-15:00Z\nResult: Confirmed encoded PowerShell spawned from OUTLOOK.EXE at 14:22:07Z\nHypothesis: Malicious link in phishing email led to payload execution (confidence: high)\nEvidence collected: process command line (above), SHA256 of dropped payload\nNext step: pivot SHA256 across fleet to confirm scope before containment decision",
        "keyPoints": [
          "A continuous timeline, chain of custody for artifacts, and a logged record of every analyst action are essential outputs of this phase",
          "Chain of custody records who collected an artifact, when, and who accessed it since — required if evidence must withstand legal scrutiny",
          "Recording a working hypothesis and confidence level lets a colleague pick up an investigation mid-shift without restarting",
          "Documentation quality here directly determines how effective the later post-incident root cause analysis can be"
        ]
      },
      {
        "pageNumber": 7,
        "title": "Detection engineering: writing the rule that catches it next time",
        "body": "Analysis is not only about the current incident — it is also the feedback loop that improves future detection. A common Detection and Analysis deliverable is a new or tuned detection rule, often authored in **Sigma**, a generic, open, YAML-based signature format for describing detections in a way that can be translated into the query language of many different SIEM platforms.\n\n### Anatomy of a Sigma rule\nA Sigma rule has a logsource (what data it applies to), a detection block (the matching logic, made of one or more named selections plus a condition), and metadata mapping it to context like a MITRE ATT&CK technique ID.\n\n### Worked example\nSuppose the phishing incident from earlier pages revealed that the malicious PowerShell used the -enc flag (a real PowerShell parameter that runs a Base64-encoded command, commonly used by attackers to obscure command content from casual log review and simple string-matching detections) launched from Outlook. A tuned Sigma rule to catch this pattern going forward, mapped to MITRE ATT&CK technique T1059.001 (PowerShell, under the Execution tactic):\n\n### Why the analyst writes this, not just a detection engineering team\nIn many SOCs, the analyst who lived through the triage is the person best placed to draft the first version of a new rule, precisely because they know exactly which field distinguished the malicious activity from the flood of legitimate PowerShell usage elsewhere in the environment. A dedicated detection engineering function typically reviews, tunes for false positives, and formally deploys the rule — but the raw insight usually starts with the analyst who did the initial analysis. This is also why the falsepositives field in a Sigma rule matters as much as the detection logic itself: an honest accounting of what legitimate activity could trigger the rule is what lets detection engineering tune it responsibly rather than either ignoring likely noise or rejecting a genuinely useful rule outright.",
        "codeExample": "title: Encoded PowerShell Spawned from Outlook\nid: 8f1c2a4e-7b3d-4c9a-9e2f-1a6d5c8b3f70\nstatus: experimental\ndescription: Detects PowerShell launched with an encoded command whose parent process is Outlook\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection_parent:\n    ParentImage|endswith: '\\OUTLOOK.EXE'\n  selection_proc:\n    Image|endswith: '\\powershell.exe'\n  selection_flag:\n    CommandLine|contains:\n      - '-enc'\n      - '-EncodedCommand'\n  condition: selection_parent and selection_proc and selection_flag\nfalsepositives:\n  - Legitimate mail-merge or add-in automation scripts (rare)\nlevel: high\ntags:\n  - attack.execution\n  - attack.t1059.001",
        "keyPoints": [
          "Sigma is a vendor-neutral, YAML-based detection format translatable into many SIEM query languages",
          "A Sigma rule combines a logsource, one or more detection selections, a condition, and metadata like ATT&CK technique tags",
          "MITRE ATT&CK T1059.001 (PowerShell) sits under the Execution tactic and is a common tag for encoded-command detections",
          "Writing or tuning a detection rule based on what an incident revealed is itself a Detection and Analysis deliverable, closing the loop for the next occurrence"
        ]
      },
      {
        "pageNumber": 8,
        "title": "Worked example: reconstructing a lateral movement timeline",
        "body": "Bring the phase together with a fuller walkthrough at NexaCorp, continuing the phishing scenario introduced in the previous lesson, but now focused specifically on the Detection and Analysis work rather than the whole lifecycle.\n\n### The alert\nAt 14:22 UTC, Microsoft Defender for Endpoint raises an alert titled \"Suspicious PowerShell command line\" on host FIN-LT-0417, assigned to Finance analyst J. Reyes. Severity: Medium (Defender's own initial scoring, before human triage).\n\n### Triage\nThe analyst pulls the DeviceProcessEvents record (page 3's query) and confirms an encoded PowerShell command spawned from OUTLOOK.EXE — consistent with a malicious link or attachment. The decoded command downloads a secondary payload from an external IP address in the documentation range 203.0.113.44, a strong indicator this is not benign automation.\n\n### Scope assessment\nPivoting on the destination IP across DeviceNetworkEvents (Defender's network connection table), the analyst finds a second host, FIN-LT-0512, also connected to 203.0.113.44 six minutes later — but from a completely different account. Pivoting further on that account in DeviceLogonEvents reveals it authenticated to FIN-LT-0512 immediately after a Kerberos ticket request from FIN-LT-0417, a pattern consistent with credential reuse enabling lateral movement between the two hosts.\n\n### Classification\nGiven two hosts affected, a privileged-adjacent account involved, and outbound C2 communication confirmed on both, the analyst classifies this as Sev2 under NexaCorp's internal matrix — Information Impact: suspected breach; Functional Impact: minimal so far — and escalates to the on-call Incident Commander with the full timeline attached.\n\nThis is exactly the handoff point where the next lesson, Containment strategies, picks up: two confirmed-compromised hosts and a live decision about how aggressively to isolate them.",
        "keyPoints": [
          "A single alert's initial severity score from the tool is a starting point, not the final classification — human triage and scope assessment refine it",
          "DeviceNetworkEvents and DeviceLogonEvents extend the same pivot methodology from process events to network and authentication activity",
          "Evidence of the same C2 IP contacted by a second host, tied to credential reuse, is what elevates single-host suspicion into a multi-host lateral movement finding",
          "The scoped, classified, and documented finding is the direct handoff artifact into the Containment phase"
        ]
      }
    ],
    "quiz": [
      {
        "question": "A vulnerability scanner reports a newly disclosed critical CVE affecting a public-facing web server, with no signs of exploitation yet. How should this be classified under NIST's terminology?",
        "options": [
          {
            "label": "An incident, since any critical CVE automatically qualifies as one",
            "value": "a"
          },
          {
            "label": "A precursor, since it signals an incident may occur in the future rather than one already occurring",
            "value": "b"
          },
          {
            "label": "An indicator, since vulnerability data always implies active compromise",
            "value": "c"
          },
          {
            "label": "A false positive, since scanners frequently overstate severity",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "A newly disclosed CVE with no observed exploitation is a textbook precursor — a sign an incident may occur in the future, giving the team a chance to patch before anything happens. It is not an incident (no confirmed impact yet), not an indicator (indicators point to activity already occurring), and dismissing it as a scanner false positive ignores that the vulnerability itself is real regardless of exploitation status."
      },
      {
        "question": "During triage, an analyst finds that a detection rule correctly fired on a PowerShell script that turns out to be an authorized remote administration tool used by the IT team. How should this be classified?",
        "options": [
          {
            "label": "A false positive, since the alert should not have fired at all",
            "value": "a"
          },
          {
            "label": "A true positive requiring immediate incident declaration",
            "value": "b"
          },
          {
            "label": "A benign positive — the detection was technically accurate but the activity is authorized, so the rule may need tuning rather than an incident being declared",
            "value": "c"
          },
          {
            "label": "A precursor, since it could indicate a future incident",
            "value": "d"
          }
        ],
        "answer": "c",
        "explanation": "This is a benign positive: the rule detected exactly what it was built to detect, and the detection logic was not wrong — the activity is simply authorized. That distinguishes it from a false positive (where the logic itself misfired) and from a true positive requiring escalation. It is not a precursor, since nothing here points to a future incident."
      },
      {
        "question": "An incident causes no visible service outage, but an analyst confirms customer records were quietly exfiltrated over several days. Under CISA's three-dimension incident categorization, which combination best reflects this incident?",
        "options": [
          {
            "label": "High Functional Impact, low Information Impact",
            "value": "a"
          },
          {
            "label": "Low Functional Impact, high Information Impact",
            "value": "b"
          },
          {
            "label": "Low Functional Impact, low Information Impact, since there was no outage",
            "value": "c"
          },
          {
            "label": "The scenario cannot be scored because no recovery has occurred yet",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "This is exactly the scenario the three-dimension model is designed to catch: Functional Impact is low because services stayed up, but Information Impact is high because sensitive data was exposed. Scoring only Functional Impact (as a single severity number would) would badly under-rate this incident; Recoverability is a separate, independent third dimension and is not required to score the other two."
      },
      {
        "question": "While investigating a confirmed malicious process on one host, an analyst wants to check whether the same threat has spread elsewhere in the environment. Which of the following is the most direct pivot to answer that question?",
        "options": [
          {
            "label": "Searching for the same file hash and C2 destination IP/domain across other endpoints",
            "value": "a"
          },
          {
            "label": "Re-reading the original alert's title more carefully",
            "value": "b"
          },
          {
            "label": "Waiting for the SIEM to automatically generate a related alert on other hosts",
            "value": "c"
          },
          {
            "label": "Escalating directly to the Incident Commander without further investigation",
            "value": "d"
          }
        ],
        "answer": "a",
        "explanation": "Scope assessment works by pivoting on confirmed identifiers — file hash, C2 IP/domain, compromised account, or reused persistence artifacts — to search for the same indicators elsewhere in the environment. Re-reading the alert title adds no new information, waiting passively assumes correlation that may not exist, and escalating without a scope assessment leaves the Incident Commander without the information needed to size the response."
      },
      {
        "question": "A Sigma rule is written with logsource category 'process_creation', a selection matching PowerShell processes with an encoded command flag, and a condition combining that with a parent process of Outlook. What is the primary purpose of tagging this rule with attack.t1059.001?",
        "options": [
          {
            "label": "To specify which SIEM vendor's query syntax the rule must be translated into",
            "value": "a"
          },
          {
            "label": "To link the detection to MITRE ATT&CK's PowerShell technique for context and cross-tool consistency",
            "value": "b"
          },
          {
            "label": "To set the rule's false-positive tolerance threshold automatically",
            "value": "c"
          },
          {
            "label": "To register the rule as a precursor rather than an indicator",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "ATT&CK technique tags like attack.t1059.001 give a Sigma rule shared context — anyone reading it, regardless of which SIEM eventually runs it, immediately knows it targets the PowerShell execution technique. Sigma is vendor-neutral by design and does not use ATT&CK tags to select a target platform, set false-positive thresholds, or classify precursor versus indicator status."
      }
    ]
  },
  "incident-responder--containment-strategies": {
    "pages": [
      {
        "pageNumber": 1,
        "title": "What containment is trying to accomplish",
        "body": "Picking up exactly where the previous lesson left off — a scoped, classified incident handed to the Incident Commander — containment is the first action-oriented phase of the response. Its goal is deceptively simple to state and genuinely hard to execute well: stop the incident from getting worse, without destroying the evidence needed to understand it or causing more business damage than the incident itself.\n\n### Containment is not eradication\nA common mistake for newer analysts is to try to \"fix\" the problem immediately — deleting a suspicious file, killing a process, rebooting a server. Containment is deliberately narrower than that: it limits the *spread and impact* of an incident. Removing the root cause is eradication, covered in the next lesson. Acting too early to eradicate before containment and evidence preservation are complete can destroy the forensic trail needed to know whether the response actually worked, or whether the attacker still has another foothold nobody has found yet.\n\n### The core tension every containment decision faces\nEvery containment action trades off three competing concerns:\n- **Speed** — the longer a compromised host or account stays active, the more damage or lateral movement can occur.\n- **Evidence preservation** — some containment actions (powering off a host) destroy volatile evidence (data in memory) that could reveal exactly how the attacker got in or what they took.\n- **Business continuity** — isolating a production system has a real cost; the containment decision must weigh that cost against the risk of leaving it connected.\n\n### What this lesson covers\nThis lesson works through the short-term versus long-term containment distinction, the specific mechanisms available at the host, network, and account level, and the decision-making process an Incident Commander uses to choose between them — directly setting up the Eradication and Recovery lesson that follows, where the root cause actually gets removed.",
        "keyPoints": [
          "Containment limits the spread and impact of a confirmed incident — it does not remove the root cause (that is eradication)",
          "Acting to eradicate before containment and evidence preservation are complete risks destroying the forensic trail",
          "Every containment decision trades off speed, evidence preservation, and business continuity",
          "This lesson sets up the mechanisms and decision framework the Incident Commander uses before eradication begins"
        ]
      },
      {
        "pageNumber": 2,
        "title": "Short-term vs. long-term containment",
        "body": "NIST SP 800-61 frames containment along a timeline: short-term actions that buy time immediately, and long-term actions that sustain a safe posture while eradication work proceeds.\n\n### Short-term containment\nShort-term containment is the immediate action to stop active damage, typically executed within minutes to hours of confirming a true positive. Examples: isolating an infected host from the network, disabling a single compromised account, blocking outbound traffic to a known command-and-control (C2) domain at the firewall. The goal is narrow and urgent — stop this specific bleeding right now.\n\n### Long-term containment\nLong-term containment is the more sustained posture applied while eradication proceeds, often over hours to days: temporary network segmentation of a broader zone, enhanced monitoring on adjacent systems, applying emergency configuration changes or virtual patches, and tightening account or firewall policies beyond the single affected host. The goal is to keep the organization operating safely while the deeper cleanup work in the next lesson happens.\n\n### A decision framework\n| Factor | Short-term | Long-term |\n|---|---|---|\n| Timeline | Minutes to hours | Hours to days |\n| Goal | Stop immediate damage | Maintain safe operations during cleanup |\n| Typical actions | Isolate host, disable account, block IP | Segment zone, add monitoring, patch, tighten policy |\n| Evidence priority | Preserve volatile data before or during action | Full imaging, ongoing collection |\n| Key risk | Tipping off the adversary; losing volatile evidence | Prolonged exposure if too slow to escalate to eradication |\n\nAn incident commander typically applies short-term containment first, buying the time needed to properly plan eradication, then layers on long-term containment measures if eradication will take longer than a few hours — which it usually does for anything beyond a single-host, single-account incident.",
        "keyPoints": [
          "Short-term containment acts in minutes to hours to stop immediate damage (isolate a host, disable an account, block a C2 IP)",
          "Long-term containment sustains safe operations over hours to days while eradication is planned and executed (segmentation, added monitoring, virtual patching)",
          "The tradeoff table (timeline, goal, actions, evidence priority, risk) is a standard decision aid for the Incident Commander",
          "Short-term containment typically comes first, buying time to plan the deeper eradication work"
        ]
      },
      {
        "pageNumber": 3,
        "title": "Host isolation: cutting off a compromised endpoint",
        "body": "The single most common short-term containment action is isolating a compromised endpoint from the network while leaving it running (rather than powering it off, which destroys volatile memory evidence).\n\n### EDR-based isolation\nModern EDR platforms provide a built-in isolation action that an analyst can trigger remotely, without physical access to the machine:\n- **CrowdStrike Falcon** calls this **Network Containment**: the host remains reachable by the Falcon platform itself (so responders can still run remote investigative commands) but is blocked from all other network communication. This is issued via the Falcon console or the Hosts API's device-actions endpoint using the \"contain\" action.\n- **Microsoft Defender for Endpoint** provides an **Isolate device** machine action via its REST API, with an IsolationType parameter of Full (blocks all network communication except to the Defender cloud service) or Selective (blocks most processes but allows some, such as an approved remote-access tool, for investigation).\n\n### A concrete API call\nCalling the Defender for Endpoint isolation API looks like this — note that the isolation is reversible (a corresponding \"unisolate\" action exists) and requires a permission role for active remediation actions, an intentional friction point so isolation cannot be triggered accidentally:\n\n### Why isolation, not shutdown\nPowering a host off would also stop the bleeding, but it destroys the contents of RAM and can trigger any anti-forensic or destructive logic a more sophisticated payload has been built to run on shutdown. Remote network isolation achieves the same immediate goal — the host can no longer talk to the attacker's infrastructure or spread laterally — while keeping the machine running and reachable for the platform's own agent, so an analyst can still pull live process, memory, and file information from it during the investigation that follows. This is why EDR-based isolation, rather than a physical unplug or a forced shutdown, is the default first choice for host-level containment in almost every modern SOC.",
        "codeExample": "POST https://api.security.microsoft.com/api/machines/1e5bc9d7e413ddd7902c2932e418702b84d0cc07/isolate\nContent-Type: application/json\n\n{\n  \"Comment\": \"Isolating host FIN-LT-0417 due to confirmed C2 communication - Case IR-2026-0914\",\n  \"IsolationType\": \"Full\"\n}",
        "keyPoints": [
          "EDR-based isolation blocks network communication remotely while leaving the host powered on, preserving volatile memory evidence",
          "CrowdStrike Falcon calls this Network Containment, triggered via the console or the Hosts API 'contain' device action",
          "Microsoft Defender for Endpoint's Isolate device API supports Full isolation (all traffic blocked except to Defender's cloud) or Selective (some approved tools still allowed)",
          "Isolation actions are reversible and access-controlled, so they cannot be triggered accidentally"
        ]
      },
      {
        "pageNumber": 4,
        "title": "Network-level containment: segmentation and traffic blocking",
        "body": "When the threat is broader than a single host, or EDR coverage does not reach every affected asset, containment moves to the network layer.\n\n### Common network-layer actions\n- **Firewall blocking** — adding a rule to deny outbound traffic to a known-malicious IP address or domain, cutting off C2 communication even for hosts without EDR coverage.\n- **DNS sinkholing** — redirecting DNS resolution for a malicious domain to a controlled, non-routable address, preventing any host on the network from reaching it regardless of how the connection was initiated.\n- **VLAN quarantine** — moving an affected host or segment into an isolated VLAN (Virtual Local Area Network) with no route to sensitive internal resources, commonly automated through **NAC** (Network Access Control) systems.\n- **Egress filtering** — tightening what internal hosts are allowed to reach on the internet at all, useful as a long-term containment measure when the full extent of C2 infrastructure is not yet known.\n\n### MITRE D3FEND context\nMITRE's **D3FEND** framework (a defensive counterpart to ATT&CK, cataloging defensive techniques) names this category of action **Network Isolation (D3-NI)**: preventing hosts from accessing non-essential network resources. Mapping a containment action back to a D3FEND technique is useful for documentation and for measuring how well an organization's tooling actually supports each defensive category, independent of any specific vendor's naming.\n\n### A concrete firewall block\nA short-term containment action blocking a confirmed C2 destination at a perimeter firewall, expressed in generic access-control-list style syntax:",
        "codeExample": "# Perimeter firewall rule - block outbound to confirmed C2 host\n# Case IR-2026-0914, added 2026-09-14T14:55Z, reviewed for removal after eradication\ndeny ip any host 203.0.113.44 log\ndeny udp any host 203.0.113.44 eq 53 log\n# 203.0.113.0/24 is a documentation range used here for illustration",
        "keyPoints": [
          "Firewall blocking and DNS sinkholing cut off C2 communication network-wide, including hosts without EDR coverage",
          "VLAN quarantine, often automated via NAC (Network Access Control), isolates a host or segment from sensitive internal resources",
          "MITRE D3FEND names this defensive category Network Isolation (D3-NI) — a vendor-neutral way to document the action taken",
          "Egress filtering as a longer-term measure helps when the full extent of C2 infrastructure is still being discovered"
        ]
      },
      {
        "pageNumber": 5,
        "title": "Account-level containment: disabling and credential actions",
        "body": "When a user or service account is confirmed compromised, containment must address the identity itself, not just the endpoint it was used from — an attacker with valid credentials can simply authenticate from a different host.\n\n### Core account containment actions\n- **Disable the account** — immediately prevents any further authentication. In a Microsoft Entra ID (formerly Azure Active Directory) environment, this is done by setting the account's accountEnabled property to false via the Microsoft Graph API, or through the equivalent admin console action.\n- **Revoke active sessions and tokens** — disabling an account does not automatically terminate sessions or access tokens already issued; a separate \"revoke sessions\" action is needed to force re-authentication everywhere, including any OAuth tokens granted to third-party applications.\n- **Reset credentials** — a password reset closes the door the attacker used, but must be paired with session revocation above, since a still-valid session token can outlive a password change.\n- **Scope carefully for service accounts** — disabling a service account can break production systems that depend on it; containment for these often requires coordinating with the system owner (from lesson 1's IR roles) before acting, or using a narrower control like restricting the account's allowed source IPs instead.\n\n### A concrete Graph API call\nDisabling a compromised user account via the Microsoft Graph API:\n\n### Ordering matters\nA common mistake is resetting the password first and assuming the incident is contained, when the correct order is closer to: disable the account, revoke sessions and tokens, then reset the credential once the account is ready to be safely re-enabled. Disabling first stops any new activity immediately while the more thorough session-revocation and reset steps are completed, rather than leaving a window where the account is still fully usable under its old, still-valid session even after the password itself has changed.",
        "codeExample": "PATCH https://graph.microsoft.com/v1.0/users/j.reyes@nexacorp.example\nContent-Type: application/json\nAuthorization: Bearer {access_token}\n\n{\n  \"accountEnabled\": false\n}",
        "keyPoints": [
          "Disabling an account (accountEnabled=false via Microsoft Graph API in Entra ID) prevents new authentications but does not end existing sessions",
          "Revoking active sessions/tokens is a separate, necessary step alongside disabling the account or resetting the password",
          "A password reset alone can be bypassed by an already-issued, still-valid session token",
          "Service account containment needs coordination with the system owner, since disabling one can break production dependencies"
        ]
      },
      {
        "pageNumber": 6,
        "title": "Making the call: risk, evidence, and the adversary's awareness",
        "body": "Choosing a containment action is a judgment call the Incident Commander makes with incomplete information, weighing several real risks against each other.\n\n### Business impact\nIsolating a host or disabling an account has a cost. Taking a production order-processing server offline during a peak sales period is a different decision than isolating an idle developer laptop at 2 a.m. The Incident Commander weighs this against the risk of continued compromise, often in direct consultation with the business/system owner and, for major incidents, the executive sponsor introduced in lesson 1.\n\n### Evidence preservation before acting\nSome containment actions destroy evidence. Powering off a host erases the contents of RAM (Random Access Memory), which can hold encryption keys, malware that never touches disk, and other volatile artifacts (Random Access Memory is a computer's working memory — it loses its contents when power is cut, unlike a hard drive). Where a forensic investigation will matter, best practice is to capture a memory image before or during isolation, not instead of it — modern EDR-based network isolation does not require powering off the host, so this tradeoff is far less severe than it was a decade ago.\n\n### Tipping off the adversary\nAn overly visible or premature containment action — disabling every potentially-related account at once, or blocking every IP an attacker has ever touched — can alert a sophisticated adversary that they have been detected, prompting them to accelerate damage (deploy ransomware immediately) or go quiet and re-establish a hidden foothold elsewhere before containment is complete. This is why scope assessment (from the previous lesson) matters so much: acting on an incomplete picture can contain the wrong 80% while leaving the adversary's real foothold untouched and now forewarned.\n\n### The practical rule of thumb\nContain what you are confident about immediately (a single confirmed host or account), continue investigating in parallel for anything still uncertain, and escalate the containment scope as confirmation grows — rather than waiting for total certainty, which the adversary does not wait for either.",
        "keyPoints": [
          "Containment decisions weigh business impact against the risk of continued compromise, typically with the system owner and executive sponsor",
          "Powering off a host destroys volatile RAM evidence; EDR-based network isolation avoids this tradeoff by keeping the host running but disconnected",
          "Premature or overly broad containment can tip off a sophisticated adversary, prompting acceleration or a hidden pivot",
          "A practical approach: contain what is confirmed immediately, keep investigating in parallel, and expand containment as confidence grows"
        ]
      },
      {
        "pageNumber": 7,
        "title": "Communicating and recording containment actions",
        "body": "A containment action taken but not recorded or communicated creates its own operational risk — someone else on the team, unaware isolation is already in place, may waste time re-diagnosing a known issue, or a well-meaning administrator may \"fix\" a host by reconnecting it to the network before eradication is complete.\n\n### What to record for every containment action\n- Exact action taken (e.g., \"Full network isolation via Microsoft Defender for Endpoint,\" \"accountEnabled set to false via Graph API\")\n- Timestamp and the analyst or system that executed it\n- The specific evidence or justification that triggered the decision\n- Expected duration or the condition under which it will be lifted\n- Who approved it, for actions with meaningful business impact\n\n### Change control and stakeholder notification\nContainment actions on business-critical systems typically go through an abbreviated change-control process even during an active incident — not to slow down the response, but to ensure the system owner, on-call operations team, and any dependent teams know a change is happening and why, before they discover it as an unexplained outage. NexaCorp's IR plan, for example, requires the Incident Commander to notify the affected system's owner and the on-call operations bridge within 15 minutes of any containment action affecting a production system.\n\n### Why this connects forward\nThis record becomes a critical input to two things covered in upcoming lessons: eradication planning needs to know exactly what containment is already in place before deciding what more to remove, and the post-incident review needs an accurate containment timeline to assess whether the response was fast enough and proportionate — neither of which is possible if containment actions were taken informally and never logged.",
        "codeExample": "Case #IR-2026-0914 — Containment Action Log\n2026-09-14T14:58Z | m.chen  | Action: Full isolation, DeviceId 1e5bc9d7...\n                             | Justification: confirmed C2 comms to 203.0.113.44\n                             | Approved by: on-call IC (s.patel) | Duration: until eradication complete\n2026-09-14T15:04Z | m.chen  | Action: accountEnabled=false, j.reyes@nexacorp.example\n                             | Justification: credential reuse observed on FIN-LT-0512\n                             | Approved by: on-call IC (s.patel) | Sessions revoked: yes",
        "keyPoints": [
          "Every containment action needs a recorded justification, timestamp, executor, expected duration, and approval where business impact is meaningful",
          "Abbreviated change control during an incident notifies system owners before they discover a change as an unexplained outage",
          "An accurate containment log tells the eradication team exactly what is already in place before they act",
          "The post-incident review depends on this record to assess whether containment was timely and proportionate"
        ]
      },
      {
        "pageNumber": 8,
        "title": "Worked example: a ransomware precursor decision tree",
        "body": "Bring the phase together with a scenario that forces a real containment tradeoff: a single host shows the earliest signs of ransomware activity, and the Incident Commander must decide how broadly to act before knowing the full scope.\n\n### The trigger\nAt 02:14 UTC, EDR on a file server (FS-CORP-02) flags mass file-rename activity consistent with ransomware encryption behavior, along with a new scheduled task created moments earlier for persistence. No user is logged in interactively — this appears to be an automated process, a strong signal of an active, not merely attempted, compromise.\n\n### The decision tree\nThe Incident Commander works through a structured set of questions rather than reacting to fear alone: Is this host connected to shared storage other hosts also write to? (Yes — a departmental file share.) Is there evidence of the same behavior on any other host yet? (Not confirmed, but not yet checked either.) Is the encryption actively in progress or already complete? (Still in progress, based on rising file-modification counts.)\n\n### The decision\nGiven active, in-progress encryption on a host connected to shared storage, the Incident Commander chooses immediate short-term containment: full EDR network isolation of FS-CORP-02, plus a long-term containment step — temporarily restricting write access to the shared storage volume from all hosts — while the scope assessment (following the previous lesson's methodology) checks every host that has recently written to that share for the same indicators. This buys time without yet declaring a wider outage, and is reversible within minutes once scope is confirmed either way.\n\n### Why this was the right shape of decision\nNotice the Incident Commander did not isolate the entire department's hosts on a hunch, nor did they wait for full scope confirmation before acting on the one host with unambiguous, active evidence — exactly the \"contain what's confirmed, investigate what isn't\" principle from page 6, applied under real time pressure.",
        "keyPoints": [
          "A structured decision tree — connectivity, spread evidence, and stage of attack — beats reacting to fear alone under time pressure",
          "Active, in-progress ransomware encryption on shared storage justifies immediate short-term containment (isolate the host) plus a long-term measure (restrict share write access)",
          "Containment scope should match confirmed evidence, expanding only as the parallel scope assessment confirms more",
          "This case demonstrates the full decision framework from this lesson applied under realistic time pressure"
        ]
      }
    ],
    "quiz": [
      {
        "question": "An analyst confirms a single host is communicating with a known C2 (command-and-control) server. Which action is best described as long-term containment rather than short-term?",
        "options": [
          {
            "label": "Isolating the specific host via the EDR platform's network containment action",
            "value": "a"
          },
          {
            "label": "Temporarily segmenting the broader network zone and adding enhanced monitoring while eradication is planned",
            "value": "b"
          },
          {
            "label": "Blocking the C2 IP address at the perimeter firewall within minutes of discovery",
            "value": "c"
          },
          {
            "label": "Disabling the single account observed making the connection",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "Segmenting a broader zone and adding monitoring while eradication is planned is the defining example of long-term containment — a sustained posture maintained over hours to days. Isolating the specific host, blocking the C2 IP immediately, and disabling the one confirmed account are all short-term actions taken within minutes to hours to stop immediate damage."
      },
      {
        "question": "Why does modern EDR-based network isolation reduce the historical tradeoff between containment speed and evidence preservation?",
        "options": [
          {
            "label": "It automatically captures a full disk image before isolating the host",
            "value": "a"
          },
          {
            "label": "It keeps the host powered on and connected to the EDR platform while blocking other network traffic, preserving volatile memory instead of erasing it by powering off",
            "value": "b"
          },
          {
            "label": "It disables the need for a memory capture entirely in every case",
            "value": "c"
          },
          {
            "label": "It only works on hosts that have already been reimaged",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "EDR-based isolation like CrowdStrike's Network Containment or Microsoft Defender for Endpoint's Isolate device keeps the host running and reachable by the security platform while cutting off other network communication — avoiding the RAM-erasing effect of powering off a host. It does not automatically capture a disk image, does not eliminate the value of memory capture in cases where deep forensics matter, and has nothing to do with reimaging status."
      },
      {
        "question": "A compromised user's password has just been reset, but the Incident Commander is told the attacker may still have access. What is the most likely explanation?",
        "options": [
          {
            "label": "The account was never actually compromised in the first place",
            "value": "a"
          },
          {
            "label": "An already-issued session token or active access token was not revoked, so it can remain valid even after the password change",
            "value": "b"
          },
          {
            "label": "Password resets have no security effect against any attacker",
            "value": "c"
          },
          {
            "label": "The Microsoft Graph API does not support password resets",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "A password reset closes the authentication door, but any session or access token already issued before the reset can remain valid until it is explicitly revoked — which is why session/token revocation is a required companion action, not an optional extra. The scenario doesn't imply the account was never compromised, password resets are clearly effective against future logins, and the Graph API does support password administration."
      },
      {
        "question": "During a ransomware precursor on a shared file server, the Incident Commander isolates only that one server rather than isolating every host in the department. What principle does this reflect?",
        "options": [
          {
            "label": "Containing what is confirmed immediately while continuing to investigate what isn't yet confirmed, rather than waiting for full certainty or over-reacting on a hunch",
            "value": "a"
          },
          {
            "label": "A policy that ransomware incidents never require containing more than one host",
            "value": "b"
          },
          {
            "label": "A rule that EDR tools can only isolate one host per hour",
            "value": "c"
          },
          {
            "label": "Avoiding containment entirely until eradication is fully planned",
            "value": "d"
          }
        ],
        "answer": "a",
        "explanation": "The worked example demonstrates the core decision principle from this lesson: act immediately on what is confirmed by strong evidence, while the scope assessment continues in parallel to determine whether broader containment is warranted. There is no such blanket ransomware policy or EDR rate limit, and delaying all containment until eradication is planned would leave active damage unaddressed."
      },
      {
        "question": "What is the primary reason a containment action on a production system should still go through an abbreviated change-control notification during an active incident?",
        "options": [
          {
            "label": "Change control is legally mandatory for every security action regardless of urgency",
            "value": "a"
          },
          {
            "label": "It ensures the system owner and on-call operations team know a change is happening and why, before they discover it as an unexplained outage",
            "value": "b"
          },
          {
            "label": "It gives the attacker time to notice the containment action is coming",
            "value": "c"
          },
          {
            "label": "It replaces the need to log the containment action anywhere else",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "The purpose is coordination: notifying the system owner and operations team prevents confusion, wasted troubleshooting, or a well-meaning reversal of the containment action by someone unaware it was deliberate. It is not a blanket legal mandate independent of context, it does not intentionally give the adversary warning, and it supplements rather than replaces the containment action log covered on the same page."
      }
    ]
  },
  "incident-responder--eradication-and-recovery": {
    "pages": [
      {
        "pageNumber": 1,
        "title": "From containment to eradication: removing the root cause",
        "body": "Containment, from the previous lesson, stops the bleeding. Eradication closes the wound: removing the actual cause of the incident so it cannot simply resume once containment measures are eventually lifted. Recovery, the second half of this lesson, is the careful process of returning to normal operations without reopening that wound.\n\n### Eradication is not the same as \"cleaning up\"\nA narrow malware removal (deleting one file, killing one process) can feel like eradication while leaving the true root cause untouched — a stolen credential still valid, a vulnerable service still unpatched, a secondary backdoor never discovered. NIST SP 800-61 treats Containment, Eradication, and Recovery as one combined, iterative phase precisely because in practice a team often has to expand containment again after eradication work reveals a wider foothold than first understood.\n\n### What \"root cause\" actually means here\nRoot cause is the answer to \"how did the attacker get in and stay in,\" not just \"what did the attacker do once inside.\" For the phishing/lateral-movement scenario carried through this module's earlier lessons, the malicious PowerShell execution was a symptom; the root cause included the phishing email bypassing the mail filter and a reused local administrator credential that enabled movement between hosts. Eradication has to address both, or the same attacker (or the next one) walks through the same door.\n\n### What this lesson covers\nThis lesson works through the concrete mechanics of eradication — malware and persistence removal, the reimage-versus-clean decision, credential resets, and vulnerability remediation — and then the recovery mechanics that bring systems safely back online: validating a clean state, phased restoration, and the monitoring that watches for reinfection during the vulnerable window right after recovery.",
        "keyPoints": [
          "Eradication removes the actual root cause of an incident; containment only limits its spread while that work happens",
          "Root cause means how the attacker got in and stayed in, not just what they did once inside",
          "NIST treats Containment, Eradication, and Recovery as one iterative phase because eradication work often reveals the need to expand containment again",
          "This lesson covers eradication mechanics, the reimage-vs-clean decision, and the recovery process that follows"
        ]
      },
      {
        "pageNumber": 2,
        "title": "Removing malware and persistence mechanisms",
        "body": "Eradication work typically has two layers: removing the active malicious code, and removing the mechanisms an attacker uses to survive a reboot or a partial cleanup — known as **persistence**.\n\n### Common persistence mechanisms to check\n- **Registry Run keys** — entries under keys like HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run that launch a program automatically at logon (MITRE ATT&CK technique **T1547.001**, Registry Run Keys / Startup Folder, under the Persistence tactic).\n- **Scheduled tasks** — a task created to re-launch a payload on a schedule or at startup (MITRE ATT&CK technique **T1053.005**, Scheduled Task, under both Execution and Persistence tactics).\n- **Services** — a malicious or hijacked Windows service configured to start automatically.\n- **Startup folder items** — shortcuts or scripts placed in a user's or the all-users Startup folder.\n\n### MITRE ATT&CK mitigation guidance\nMITRE ATT&CK's mitigation **M1042 (Disable or Remove Feature or Program)** directly addresses this stage of eradication: disabling or removing unnecessary or abused software, features, and services to eliminate the mechanism an attacker relied on, spanning legacy protocols, unneeded scripting engines, and — relevant here — the specific persistence artifact itself.\n\n### A concrete removal example\nRemoving a malicious scheduled task and a Run key entry discovered during the investigation, using PowerShell's built-in cmdlets:\n\n### Search broadly, not just where the alert pointed\nA common eradication mistake is removing only the exact artifact the original alert named, without checking for sibling persistence mechanisms the same toolkit commonly installs as a backup. Many malware families deliberately create more than one persistence path specifically so that removing any single one leaves the infection intact; a thorough eradication step reviews all four categories above for every affected host, even when the initial detection only flagged one of them.",
        "codeExample": "# Remove a malicious scheduled task discovered during triage\nUnregister-ScheduledTask -TaskName \"WindowsUpdateHelper\" -Confirm:$false\n\n# Remove a malicious Registry Run key persistence entry\nRemove-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" -Name \"SecurityHealthSvc2\"\n\n# Confirm the malicious file is gone and quarantined by the EDR agent, not merely deleted by hand\nGet-MpThreatDetection | Where-Object { $_.Resources -like \"*WindowsUpdateHelper*\" }",
        "keyPoints": [
          "Persistence mechanisms (Registry Run keys, scheduled tasks, services, Startup folder items) let malware survive a reboot and must be found and removed, not just the initial payload",
          "MITRE ATT&CK T1547.001 covers Registry Run Keys/Startup Folder; T1053.005 covers Scheduled Task persistence",
          "MITRE ATT&CK mitigation M1042 (Disable or Remove Feature or Program) is the general mitigation category for removing the abused mechanism",
          "Confirming removal through the EDR platform's own detection record, not just manual deletion, provides an auditable eradication record"
        ]
      },
      {
        "pageNumber": 3,
        "title": "Reimage or clean? Making the call",
        "body": "One of the most consequential eradication decisions is whether to surgically remove the identified malicious artifacts from a running system, or to wipe the host and reinstall the operating system from a known-good image — reimaging.\n\n### When targeted cleaning is reasonable\n- The malware and its persistence mechanisms are fully identified and well understood (a known commodity malware family, not a custom or unknown toolkit).\n- EDR telemetry gives high confidence about exactly what executed and what it touched, with no signs of kernel-level or firmware-level tampering.\n- The host has low business criticality, or downtime for a full reimage is genuinely worse than the residual risk of a targeted clean.\n\n### When reimaging is the right call\n- **Rootkits or bootkits** — malware that operates below the operating system (in the boot process or kernel) can hide from normal detection tools entirely; only a full wipe reliably removes it.\n- **Uncertain scope** — if the investigation cannot conclusively rule out additional, undiscovered footholds, a partial clean risks leaving something behind.\n- **High-value or high-trust systems** — domain controllers, certificate authorities, and other systems whose compromise has outsized downstream trust implications are typically reimaged rather than cleaned, even at higher cost, because the cost of being wrong is so much higher.\n- **Regulatory or contractual requirements** — some compliance frameworks or cyber-insurance policies specify reimaging as the required response for certain incident classes.\n\n### The practical default\nMany mature SOCs adopt \"reimage unless there is a clear, well-understood reason not to\" as their default posture for any host with a confirmed active compromise, precisely because the cost of confidently getting eradication wrong (a lingering backdoor discovered weeks later) is almost always higher than the cost of a conservative reimage. Targeted cleaning is reserved for cases where reimaging is genuinely impractical (a specialized system with no rebuild path available quickly) or the malware is unambiguously well-understood.",
        "keyPoints": [
          "Targeted cleaning is reasonable only when the malware and persistence are fully understood and scope is confidently bounded",
          "Rootkits/bootkits, uncertain scope, and high-trust systems (domain controllers, certificate authorities) generally call for a full reimage",
          "Some compliance frameworks or cyber-insurance policies mandate reimaging for certain incident classes",
          "Many SOCs default to 'reimage unless clearly unnecessary' because the cost of an incomplete eradication is usually higher than a conservative rebuild"
        ]
      },
      {
        "pageNumber": 4,
        "title": "Credential resets and account hardening",
        "body": "Malware removal alone does nothing if the attacker still holds valid credentials. Eradication must address every credential the investigation shows was likely exposed — and, for the most severe cases, credentials that underpin the entire identity infrastructure.\n\n### Scoping the reset\n- **Directly compromised accounts** — reset immediately, following the containment steps already applied (account disable, session revocation) from the previous lesson.\n- **Accounts with shared or reused credentials** — if investigation shows a password was reused across systems (a common root cause enabling lateral movement), every system sharing that credential needs a reset, not just the one where compromise was confirmed.\n- **Service accounts and API keys** touched by the compromised host or account during the incident window.\n\n### The extreme case: krbtgt reset\nIn a domain compromise scenario severe enough to raise concern about a **Golden Ticket** attack (a forged Kerberos ticket-granting ticket that can impersonate any user indefinitely, built by an attacker who has stolen the domain's krbtgt account password hash), the recommended remediation is resetting the krbtgt account's password **twice**, with a gap between resets. This is necessary because Active Directory's Kerberos implementation keeps the current and previous password hash both valid briefly to avoid breaking tickets issued during the transition — a single reset alone would not fully invalidate a forged ticket built from the prior hash.\n\n### A concrete example\nResetting the krbtgt account password using the Active Directory PowerShell module (this is an intentionally disruptive, high-impact action reserved for confirmed domain-level compromise, never a routine step):",
        "codeExample": "# Reset the krbtgt account password (Active Directory PowerShell module)\n# Perform this twice, with a scheduled gap, per Microsoft's Golden Ticket remediation guidance\n$newPassword = ConvertTo-SecureString -String (New-Guid).Guid -AsPlainText -Force\nSet-ADAccountPassword -Identity krbtgt -Reset -NewPassword $newPassword -Server dc01.nexacorp.example\n\n# General account containment applied more broadly during eradication scoping\nGet-ADUser -Filter { PasswordLastSet -lt \"2026-09-01\" -and Enabled -eq $true } -Properties PasswordLastSet |\n  Select-Object SamAccountName, PasswordLastSet",
        "keyPoints": [
          "Eradication must reset every credential shown by the investigation to be exposed, including accounts affected only through password reuse",
          "A Golden Ticket attack relies on a stolen krbtgt password hash to forge Kerberos tickets that impersonate any user indefinitely",
          "Remediating a Golden Ticket risk requires resetting the krbtgt password twice, with a gap, because AD briefly accepts both the current and previous hash",
          "Credential-scope decisions during eradication connect directly to MITRE ATT&CK mitigation M1027 (Password Policies)"
        ]
      },
      {
        "pageNumber": 5,
        "title": "Closing the gap: patching and hardening",
        "body": "If the incident exploited a vulnerability or a misconfiguration rather than (or in addition to) a phishing-delivered payload, eradication is incomplete until that underlying weakness is closed — otherwise the same entry point remains available even after every implanted artifact is removed.\n\n### What this covers\n- **Vulnerability remediation** — applying the vendor patch for an exploited CVE (Common Vulnerabilities and Exposures entry), or, where a patch is not yet available, a vendor-recommended workaround.\n- **Configuration hardening** — closing an exposed service, removing an unnecessary open port, or fixing an overly permissive firewall or cloud storage access policy that enabled initial access or lateral movement.\n- **Compensating controls** — where the ideal fix (a full patch, a legacy application rewrite) is not immediately feasible, a compensating control (a virtual patch at a web application firewall, restricting the vulnerable service to a narrow set of source IPs) reduces exploitability in the interim.\n\n### Applying MITRE ATT&CK mitigation categories\nTwo mitigation IDs recur constantly in eradication and hardening work:\n- **M1042 (Disable or Remove Feature or Program)** — covered on page 2 for persistence, but equally applicable here: disabling an unnecessary legacy protocol (such as SMBv1) that enabled the initial exploit removes the attack surface entirely rather than just patching around it.\n- **M1027 (Password Policies)** — enforcing password complexity, rotation, and reuse prevention, directly relevant when weak or reused credentials contributed to the root cause identified on the previous page.\n\n### Why this step is easy to skip — and why skipping it is dangerous\nUnder incident pressure, teams often stop once the immediate malicious activity is gone, treating patching as a \"routine IT\" follow-up rather than part of eradication itself. But if the vulnerability that enabled initial access is never closed, the organization has removed one attacker's toolkit while leaving the door they used wide open for the next one — including, in some documented cases, the same threat actor returning through the identical unpatched entry point within weeks.",
        "keyPoints": [
          "Eradication is incomplete if the vulnerability or misconfiguration that enabled initial access is never closed",
          "Compensating controls (virtual patching, IP restriction) reduce exploitability when the ideal fix is not immediately feasible",
          "M1042 (Disable or Remove Feature or Program) and M1027 (Password Policies) are the two MITRE ATT&CK mitigations most often invoked during eradication hardening",
          "Treating patching as separate 'routine IT' work rather than part of eradication risks the same entry point being reused"
        ]
      },
      {
        "pageNumber": 6,
        "title": "Recovery: bringing systems back safely",
        "body": "Recovery is the deliberate process of restoring normal operations once eradication is complete — and it is a distinct discipline from eradication, not just \"turning things back on.\"\n\n### Validating a clean state before reconnecting\nBefore any host rejoins the network, the team confirms eradication actually worked: a fresh EDR scan shows no remaining detections, persistence checks (page 2's registry/scheduled task review) come back clean, and — for a reimaged host — the rebuild used a verified, uncompromised base image rather than a backup that might itself be tainted.\n\n### Recoverability planning\nCISA's incident categorization (introduced in the Detection and Analysis lesson) includes a **Recoverability** dimension that is directly relevant to planning this phase:\n\n| Recoverability level | Meaning |\n|---|---|\n| Regular | Recovery time is predictable using existing resources |\n| Supplemented | Recovery time is predictable but requires additional resources |\n| Extended | Recovery time is unpredictable; external assistance is needed |\n| Not Recoverable | Recovery is not possible (e.g., data destroyed with no viable backup) |\n\nClassifying recoverability early — ideally as part of the original Detection and Analysis classification — shapes realistic expectations and resourcing for the recovery phase rather than discovering the true recovery cost only once eradication is already underway.\n\n### Phased restoration\nRather than reconnecting every affected system simultaneously, mature recovery plans restore in phases: the most business-critical, highest-confidence-clean systems first, under close monitoring, before extending to lower-priority systems — so that if reinfection or an undiscovered foothold does surface, it is caught on a small, closely-watched population rather than across the entire restored fleet at once.",
        "keyPoints": [
          "Recovery validates eradication actually worked — clean EDR scan, clean persistence check, verified-clean base image for reimaged hosts — before reconnecting",
          "CISA's Recoverability dimension (Regular, Supplemented, Extended, Not Recoverable) sets realistic expectations for how long and how resource-intensive recovery will be",
          "Recoverability is ideally classified early, during Detection and Analysis, not discovered only once eradication is underway",
          "Phased restoration reconnects the most critical, highest-confidence systems first under close monitoring before extending further"
        ]
      },
      {
        "pageNumber": 7,
        "title": "Monitoring during recovery: watching for reinfection",
        "body": "The period immediately after a system rejoins production is the highest-risk window of the entire recovery process — exactly when many teams are most tempted to relax, having just finished the hard work of eradication.\n\n### Why heightened monitoring matters here specifically\nEradication decisions are made on the best available evidence, but that evidence can be incomplete. A dormant, undiscovered secondary backdoor, a credential the investigation missed, or a persistence mechanism using a technique the tooling does not detect by default can all survive eradication and reactivate once the host is back online and attractive again. Enhanced monitoring during recovery exists specifically to catch that scenario quickly, before it becomes a second incident.\n\n### What enhanced monitoring typically includes\n- **Extended EDR alerting sensitivity** on the recovered host for a defined window (commonly 72 hours to two weeks depending on incident severity), sometimes including detection rules tuned specifically to the techniques observed in this incident.\n- **Network traffic review** for any recurrence of the original C2 indicators or similar patterns, even after the specific IP or domain has been blocked, since a resilient attacker infrastructure often has backup addresses.\n- **Account activity review** for the affected accounts, watching specifically for the same anomalous pattern (unusual location, unusual time, unusual resource access) that originally revealed the incident.\n- **A defined \"all clear\" criterion and date**, agreed in advance, rather than leaving the monitoring period open-ended and easy to quietly let lapse.\n\n### A concrete example\nNexaCorp's IR plan requires 10 business days of elevated monitoring on any host or account involved in a Sev2 or higher incident, with a daily review of DeviceProcessEvents and sign-in logs for that specific asset, reported to the Incident Commander until the monitoring window closes and is formally signed off — turning an easy-to-forget verbal intention into a tracked commitment with an owner and an end date.",
        "keyPoints": [
          "The window right after recovery is the highest-risk period, since eradication evidence can be incomplete and a hidden foothold may reactivate",
          "Enhanced monitoring includes extended EDR sensitivity, network traffic review, and account activity review, typically for a defined window matched to incident severity",
          "A defined 'all clear' date and sign-off, agreed in advance, prevents the monitoring period from quietly lapsing unmonitored",
          "Tying the monitoring commitment to a tracked owner and end date (rather than a verbal intention) is what makes it operationally reliable"
        ]
      },
      {
        "pageNumber": 8,
        "title": "Worked example: full eradication and recovery after the lateral movement incident",
        "body": "Continuing the scenario carried through this module: the two-host lateral movement incident at NexaCorp, now moving from the confirmed containment state (both hosts isolated, the shared account disabled) into eradication and recovery.\n\n### Eradication\nThe forensic review confirms both FIN-LT-0417 and FIN-LT-0512 ran the same encoded PowerShell payload with an identical persistence scheduled task. Given the confirmed lateral movement and the use of a locally shared administrator credential — a root cause with organization-wide implications, since that same local administrator password pattern is likely reused on other Finance department laptops — the Incident Commander decides on full reimaging for both hosts rather than targeted cleaning, applying the \"reimage unless clearly unnecessary\" default from page 3. The shared local administrator password is rotated across the entire Finance device fleet, not just the two confirmed hosts, since the root cause (reused local admin credentials) extends beyond the two hosts actually seen compromised.\n\n### Recovery\nBoth reimaged hosts are validated clean (fresh EDR scan, no persistence artifacts, base image confirmed uncompromised) before rejoining the network. Given the confirmed but contained scope, NexaCorp classifies this as Regular recoverability — predictable recovery using existing resources, no external assistance needed. Both hosts reconnect first, under the enhanced monitoring described on the previous page, before the broader Finance fleet's credential rotation is verified complete over the following two business days.\n\n### Enhanced monitoring\nPer the Sev2 policy, both hosts and the previously-compromised account receive 10 business days of elevated DeviceProcessEvents and sign-in log review. No recurrence is observed, and the case is formally closed on day 11 with sign-off from the Incident Commander — feeding directly into the Post-Incident Review, the subject of the next lesson, which examines why the phishing email bypassed the mail filter in the first place and why local administrator credentials were reused across the fleet.",
        "keyPoints": [
          "Identical persistence artifacts across two hosts, plus lateral movement via a locally shared credential, justified full reimaging over targeted cleaning",
          "Root cause remediation extended beyond the two confirmed hosts to the entire Finance fleet sharing the same local administrator credential pattern",
          "Recovery classification (Regular recoverability) and phased, monitored reconnection followed directly from the eradication scope decided",
          "A formally closed case with sign-off, after the monitoring window, is the clean handoff point into the Post-Incident Review"
        ]
      }
    ],
    "quiz": [
      {
        "question": "An analyst deletes a malicious executable from a compromised host and considers the incident eradicated. What is most likely still missing from this eradication?",
        "options": [
          {
            "label": "Nothing — deleting the malicious file is sufficient to complete eradication",
            "value": "a"
          },
          {
            "label": "A check for persistence mechanisms (registry Run keys, scheduled tasks, services) and the underlying root cause that let the file execute in the first place",
            "value": "b"
          },
          {
            "label": "A recovery classification under the CISA Recoverability dimension",
            "value": "c"
          },
          {
            "label": "Approval from the communications/PR liaison",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "Deleting the file addresses the symptom, but persistence mechanisms and the actual root cause (how the attacker got in and stayed in — a phishing bypass, a reused credential, an unpatched vulnerability) are what make eradication complete; missing them means the incident can simply resume. Recoverability classification belongs to the recovery step, not eradication itself, and this action needs no PR sign-off."
      },
      {
        "question": "During eradication of a confirmed rootkit-based compromise on a critical server, which approach is most appropriate?",
        "options": [
          {
            "label": "Targeted cleaning, since it always preserves more business continuity than reimaging",
            "value": "a"
          },
          {
            "label": "Full reimaging, since rootkits operate below normal detection tools and can rarely be reliably removed by targeted cleaning alone",
            "value": "b"
          },
          {
            "label": "No action, since rootkits are undetectable and cannot be remediated",
            "value": "c"
          },
          {
            "label": "Simply changing the administrator password and leaving the operating system as-is",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "Rootkits and bootkits operate below the operating system and can hide from standard detection and cleanup tools, which is exactly why a full reimage is the recommended approach for this case, even at higher short-term cost. Targeted cleaning is not reliable here, rootkits being hard to detect doesn't mean they're impossible to remediate, and a password change alone leaves the actual rootkit in place."
      },
      {
        "question": "Why must the krbtgt account password be reset twice, with a gap between resets, when remediating a suspected Golden Ticket attack?",
        "options": [
          {
            "label": "Active Directory requires two resets purely as a UI limitation of the password reset tool",
            "value": "a"
          },
          {
            "label": "Active Directory keeps the current and previous password hash both valid briefly, so a single reset would not fully invalidate a ticket forged from the prior hash",
            "value": "b"
          },
          {
            "label": "The first reset only applies to the Recovery phase, and the second applies to Eradication",
            "value": "c"
          },
          {
            "label": "Two resets are required only if the domain has more than one domain controller",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "Because Active Directory's Kerberos implementation briefly accepts both the current and previous krbtgt password hash to avoid breaking tickets in transition, a single reset leaves a forged Golden Ticket built from the prior hash still valid until the second reset fully retires it. This has nothing to do with a UI limitation, a phase-based split between resets, or the number of domain controllers."
      },
      {
        "question": "An incident is scored as 'Extended' recoverability under CISA's model. What does this tell the recovery team?",
        "options": [
          {
            "label": "Recovery is impossible and the affected data or systems cannot be restored",
            "value": "a"
          },
          {
            "label": "Recovery time is predictable and can be handled entirely with existing internal resources",
            "value": "b"
          },
          {
            "label": "Recovery time is unpredictable and will likely require external assistance beyond the team's current resources",
            "value": "c"
          },
          {
            "label": "The incident does not need to be classified for Functional or Information Impact",
            "value": "d"
          }
        ],
        "answer": "c",
        "explanation": "'Extended' recoverability specifically means recovery time is unpredictable and external assistance is likely needed — distinct from 'Not Recoverable' (impossible), 'Regular' (predictable, existing resources), and 'Supplemented' (predictable, but needing additional resources). Recoverability is scored independently of, not as a replacement for, Functional and Information Impact."
      },
      {
        "question": "Two weeks after a host is fully eradicated and reconnected to the network, a dormant backdoor the original investigation missed reactivates. What IR practice from this lesson is specifically designed to catch this scenario as early as possible?",
        "options": [
          {
            "label": "Applying a compensating control instead of a full patch",
            "value": "a"
          },
          {
            "label": "The reimage-versus-clean decision made during eradication",
            "value": "b"
          },
          {
            "label": "Enhanced monitoring during recovery, with a defined window and 'all clear' sign-off, rather than assuming eradication succeeded with no further check",
            "value": "c"
          },
          {
            "label": "Resetting the krbtgt account password twice",
            "value": "d"
          }
        ],
        "answer": "c",
        "explanation": "Enhanced monitoring during recovery exists precisely because eradication evidence can be incomplete; a defined monitoring window with alerting on the recovered asset is what catches a reactivating dormant backdoor quickly rather than letting it run for weeks undetected. A compensating control, the reimage-vs-clean decision, and a krbtgt reset are all eradication-stage actions that don't provide ongoing detection after recovery."
      }
    ]
  },
  "incident-responder--post-incident-review": {
    "pages": [
      {
        "pageNumber": 1,
        "title": "Why the incident isn't over when the systems come back online",
        "body": "It is tempting to treat a resolved incident as finished the moment recovery from the previous lesson is complete: systems are back online, monitoring shows no recurrence, everyone is exhausted and ready to move on. NIST SP 800-61 explicitly disagrees, naming this **Post-Incident Activity** as its own formal phase — SANS PICERL calls the same work **Lessons Learned** — precisely because skipping it guarantees the organization learns nothing structural from what just happened, and is equally unprepared for the next, similar incident.\n\n### What a postmortem is\nA **postmortem** (sometimes called a \"post-incident review\" or \"after-action review\") is a structured examination of an incident after it is resolved, conducted specifically to answer: what happened, why did it happen, how well did the response work, and what should change. The term borrows from medicine — a postmortem examination determines cause of death to prevent similar deaths in the future — and the analogy holds well for security: the goal is never to assign blame, only to understand mechanism.\n\n### Why this is not optional, even under time pressure\nEvery incident consumes real analyst time and organizational goodwill; skipping the review to \"get back to normal work\" trades a small amount of near-term time savings for a much larger cost: the same root cause (an unpatched vulnerability, a reused credential, a missing detection rule) remaining in place until it causes the next incident. The closing lesson of this module, IR playbooks, depends directly on what this lesson produces — playbooks only improve when postmortem findings get fed back into them.\n\n### What this lesson covers\nThis lesson builds the practical mechanics of running an effective post-incident review: the lessons-learned meeting itself, root cause analysis techniques, the blameless culture that makes honest analysis possible, how to write the incident report for different audiences, and the metrics and feedback loops that turn a one-time discussion into lasting organizational improvement.",
        "keyPoints": [
          "NIST calls this phase Post-Incident Activity; SANS PICERL calls it Lessons Learned — both treat it as a required, formal phase, not an optional wrap-up",
          "A postmortem examines what happened, why, how well the response worked, and what should change — never to assign blame",
          "Skipping the review trades a small time savings now for the much larger cost of the same root cause causing a future incident",
          "This lesson's output directly feeds the next lesson's playbook-building work"
        ]
      },
      {
        "pageNumber": 2,
        "title": "Running the lessons-learned meeting",
        "body": "The lessons-learned meeting is the central event of this phase — a structured discussion, not an informal debrief over coffee, with a defined agenda and outcome.\n\n### Timing\nNIST guidance recommends holding this meeting within a reasonably short window after the incident closes — commonly within two weeks — while details are still fresh in participants' memory but after the pressure of active response has passed enough for calm, honest reflection. Waiting too long lets memory fade and urgency evaporate; meeting too soon (before recovery and monitoring are truly complete) risks discussing an incident that isn't actually finished yet.\n\n### Who attends\nEvery role that touched the incident: the Incident Commander, the IR analysts who performed triage and containment, the system owner(s) of affected assets, and — for incidents with legal, regulatory, or communications dimensions — representatives from those functions as well. Attendance should be framed as valuable input, not as being called to account.\n\n### A structured agenda\n1. **Timeline review** — walk through the incident timeline (built continuously during Detection and Analysis, as covered earlier in this module) chronologically, confirming accuracy with everyone present.\n2. **What worked well** — deliberately asked first, to reinforce that the meeting is not purely a critique session.\n3. **What didn't work or was slower than it should have been** — specific, concrete gaps: a missing log source, an outdated contact list, a playbook step that didn't match reality.\n4. **Root cause discussion** — covered in depth on the next page.\n5. **Action items** — each with a specific owner and a due date, not a vague aspiration.\n\n### The output\nA written report (this lesson's later page covers structure) and a tracked list of action items that feed into Preparation — closing the lifecycle loop described in the very first lesson of this module.",
        "codeExample": "Lessons-Learned Meeting — Case IR-2026-0914\nHeld: 2026-09-24 (10 days post-closure)  |  Facilitator: s.patel (Incident Commander)\nAttendees: m.chen (IR Analyst), j.reyes (affected user), it-finance-lead, security-eng-lead\n\nAgenda:\n1. Timeline review (confirmed accurate, no disputed timestamps)\n2. What worked: EDR isolation triggered within 6 minutes of confirmed indicator\n3. Gaps: mail filter did not flag newly-registered sender domain; local admin\n         credential reused across Finance fleet enabled lateral movement\n4. Root cause: see 5 Whys analysis (attached)\n5. Action items: see tracked backlog (attached), 4 items, all owners assigned",
        "keyPoints": [
          "The meeting is best held within about two weeks of closure — fresh enough to recall detail, late enough that response pressure has passed",
          "Attendance should include every role that touched the incident, framed as valuable input rather than being called to account",
          "A structured agenda starts with the timeline, deliberately asks what worked well before what didn't, then root cause and action items",
          "Every action item needs a specific owner and due date, feeding back into Preparation"
        ]
      },
      {
        "pageNumber": 3,
        "title": "Root cause analysis: getting past the symptom",
        "body": "The single most common failure mode in a post-incident review is stopping at the first plausible explanation instead of digging to the actual root cause — the underlying condition that, if left unaddressed, will produce the same category of incident again.\n\n### The 5 Whys technique\nA simple, widely used technique: ask \"why\" repeatedly (commonly five times, though the exact count is just a heuristic) until the answer reaches something structural and actionable rather than a surface-level symptom.\n\nExample, continuing this module's phishing/lateral-movement incident:\n1. Why did the attacker gain code execution? Because an employee clicked a malicious link in a phishing email.\n2. Why did the phishing email reach the employee? Because the mail filter did not flag the sender's domain as malicious.\n3. Why didn't the mail filter flag it? Because the domain was newly registered and not yet present in any threat intelligence feed the filter consults.\n4. Why does the filter rely only on reputation feeds rather than domain-age signals? Because domain-age-based scoring was never configured as a filtering criterion.\n5. Why was domain-age scoring never configured? Because no one had evaluated the mail filter's full capability set since initial deployment two years earlier.\n\nStopping at step 1 (\"the employee clicked a bad link\") leads to an action item like \"retrain the employee\" — arguably useful, but weak, because the same email would likely have reached the next employee and produced the same result. Reaching step 5 produces a structural fix: schedule a recurring review of security tooling configuration against current capability, which prevents an entire category of future gaps, not just this one.\n\n### Contributing factors vs. root cause\nMost real incidents have multiple contributing factors, not one single root cause — in this example, both the mail filter gap and the reused local administrator credential (covered in the eradication lesson) independently contributed to how far the incident spread. A thorough root cause analysis identifies all of them rather than stopping once any single plausible explanation is found, since fixing only one still leaves the others available for the next incident.",
        "keyPoints": [
          "The 5 Whys technique repeatedly asks 'why' past the first symptom until reaching a structural, actionable root cause",
          "Stopping too early produces weak fixes (retrain one employee); reaching the structural cause produces fixes that prevent an entire category of future incidents",
          "Most real incidents have multiple independent contributing factors, not a single root cause",
          "A thorough analysis identifies all contributing factors, since fixing only one leaves the others available for the next incident"
        ]
      },
      {
        "pageNumber": 4,
        "title": "Blameless postmortems: why psychological safety produces better analysis",
        "body": "A **blameless postmortem** is one where the explicit goal is understanding the systems and processes that allowed an incident to happen, rather than identifying an individual to hold responsible for a mistake. This is not a soft or optional cultural nicety — it directly determines whether the root cause analysis on the previous page can even happen honestly.\n\n### Why blame suppresses the information you need\nIf an employee who clicked a phishing link, or an analyst who missed an early indicator, expects to be blamed or disciplined for raising what happened, the predictable organizational response is that people stop volunteering that information. Future near-misses go unreported, details get quietly omitted from incident write-ups, and the organization loses exactly the visibility it needs to prevent recurrence — trading the short-term satisfaction of assigning blame for a long-term loss of the honest reporting that makes prevention possible.\n\n### What blameless framing looks like in practice\n- Language in the meeting and the report focuses on actions and conditions (\"the mail filter did not flag this domain,\" \"the on-call rotation had no coverage between 2 and 4 a.m.\") rather than people (\"the analyst missed it,\" \"the employee should have known better\").\n- The facilitator (often the Incident Commander) actively redirects the discussion if it drifts toward individual fault, reframing toward the system or process gap that made the individual action possible or likely.\n- Action items target processes, tooling, and training programs — not individual performance reviews or discipline.\n\n### Blameless does not mean accountability-free\nThis distinction matters: blameless does not mean nobody is accountable for fixing anything. It means the accountability is for *implementing the fix* (an assigned action item with an owner and a due date, from page 2), not for having been involved in the incident in the first place. An engineer who missed a config error is not punished for having missed it, but is very likely the right person to own fixing the process gap that let it happen unnoticed.",
        "keyPoints": [
          "Blameless postmortems focus on the systems and conditions that allowed an incident, not on identifying an individual to blame",
          "Fear of blame suppresses honest reporting, which is exactly the information needed to prevent recurrence",
          "Blameless framing uses action/condition language rather than person-focused language, and redirects discussion away from individual fault",
          "Blameless does not mean accountability-free — it shifts accountability to implementing the fix, not to having been involved in the incident"
        ]
      },
      {
        "pageNumber": 5,
        "title": "Writing the incident report for different audiences",
        "body": "The written incident report is the durable artifact that outlives the meeting — read by people who were not in the room, sometimes months or years later during an audit, a regulatory inquiry, or a similar future incident.\n\n### A standard structure\n- **Executive summary** — a short, non-technical overview: what happened, what was the impact, is it resolved, what is being done to prevent recurrence. Written for readers who will read only this section.\n- **Timeline** — the detailed, timestamped sequence of detection, analysis, containment, eradication, and recovery actions.\n- **Impact assessment** — using the classification dimensions from the Detection and Analysis lesson (Functional Impact, Information Impact, Recoverability), stated plainly rather than assumed familiar.\n- **Root cause and contributing factors** — the output of the 5 Whys or equivalent analysis from page 3.\n- **Response evaluation** — what worked, what was slow, and why, drawn directly from the lessons-learned meeting.\n- **Recommendations and action items** — specific, owned, dated.\n\n### Tailoring for the audience\nA single report rarely serves every reader well. Most mature SOCs produce (or clearly section) two versions:\n- An **executive/board-level version** emphasizing business impact, risk, cost, and the organization's response posture, deliberately light on technical jargon.\n- A **technical version** for the SOC, IT, and engineering teams, with full technical detail — specific hosts, commands, indicators of compromise, and technique references — that a future analyst or auditor can act on directly.\n\n### A practical habit\nWrite the executive summary last, even though it appears first in the document — it is far easier to summarize accurately once the full technical detail has been assembled, and writing it last avoids the common trap of a summary that oversimplifies or omits a detail the rest of the report later contradicts.",
        "codeExample": "Incident Report — Case IR-2026-0914 (Structure)\n1. Executive Summary          (1 paragraph, non-technical, written last)\n2. Timeline                   (timestamped, phase-labeled)\n3. Impact Assessment          (Functional / Information Impact, Recoverability)\n4. Root Cause & Contributing Factors\n5. Response Evaluation        (what worked, what was slow, why)\n6. Recommendations & Action Items (owner + due date per item)\nAppendix: technical IOCs, affected hosts/accounts, ATT&CK technique references",
        "keyPoints": [
          "A standard report structure includes an executive summary, timeline, impact assessment, root cause, response evaluation, and owned action items",
          "The impact assessment should reuse the classification dimensions (Functional Impact, Information Impact, Recoverability) established during Detection and Analysis",
          "Executive and technical audiences typically need separately tailored versions or sections of the same report",
          "Writing the executive summary last, after the full technical detail is assembled, avoids a summary that contradicts the report's own findings"
        ]
      },
      {
        "pageNumber": 6,
        "title": "Metrics and the detection feedback loop",
        "body": "Beyond a single incident's narrative, post-incident review is also where an organization measures whether it is getting better at incident response over time, and where individual incident findings feed structural improvements to detection capability.\n\n### Core IR metrics\n- **MTTD (Mean Time to Detect)** — the average time between when an incident actually began and when it was first detected.\n- **MTTC (Mean Time to Contain)** — the average time between detection and effective containment.\n- **MTTR** — used in this context to mean **Mean Time to Recovery** (or, in some organizations, Mean Time to Respond) — the average time between detection and full restoration of normal operations.\n\nTracking these over many incidents (not judging any single incident against them, which risks pressuring people to cut corners) reveals whether process and tooling investments are actually paying off — a declining MTTC trend after adopting EDR-based isolation, for instance, is a concrete, defensible justification for that investment when budget is being decided.\n\n### Feeding detection engineering\nA postmortem often reveals a **detection gap** — the incident's early indicators existed in available telemetry but no rule caught them, or the organization lacked visibility into a data source entirely. This is where a tool like **DeTT&CT** (Detect Tactics, Techniques & Combat Threats) becomes useful: an open framework and toolset that scores an organization's log source quality, visibility, and detection coverage against MITRE ATT&CK techniques, making it possible to point at exactly which techniques from this incident had weak or missing coverage, and prioritize closing that specific gap rather than guessing.\n\n### Feeding organizational maturity assessment\nAt a broader level, recurring postmortem findings — repeated tooling gaps, repeated process breakdowns — are exactly the kind of evidence used in a **SOC-CMM** (Security Operations Center Capability Maturity Model) self-assessment, a free framework that scores a SOC across five domains (business, people, process, technology, services) to identify where investment would most improve overall capability, rather than treating each incident's findings as isolated one-off fixes.",
        "keyPoints": [
          "MTTD, MTTC, and MTTR track detection, containment, and recovery speed as trends across many incidents, not judgments of any single one",
          "DeTT&CT scores detection coverage and data source quality against MITRE ATT&CK techniques, turning 'we missed this' into a prioritized, technique-specific gap to close",
          "SOC-CMM assesses SOC maturity across five domains (business, people, process, technology, services) using recurring findings as evidence",
          "Metrics and gap frameworks turn isolated postmortem findings into structural, prioritized investment decisions"
        ]
      },
      {
        "pageNumber": 7,
        "title": "Turning lessons into durable action",
        "body": "A postmortem that produces a well-written report and a thoughtful meeting but no completed action items has, in practical terms, failed at its purpose. This page covers what makes the difference between lessons that get discussed and lessons that actually change the organization.\n\n### Tracking to closure\nAction items belong in the same tracked system the organization uses for other committed work (a ticketing or project-tracking system), not a document that gets filed and forgotten. Each item needs an owner, a due date, and a defined \"done\" criterion specific enough that closure isn't a judgment call. The Incident Commander or a designated owner typically reviews outstanding postmortem action items on a recurring cadence (monthly is common) until every item is closed.\n\n### Concrete categories of action items\n- **Detection rule updates** — writing or tuning a Sigma rule (as demonstrated in the Detection and Analysis lesson) for the specific gap the incident revealed.\n- **Playbook updates** — revising the relevant playbook so the next responder benefits directly from what this incident taught; the next lesson in this module covers playbook construction and maintenance in depth.\n- **Tooling and configuration changes** — the mail filter domain-age scoring example from page 3, or closing an exposed service identified during eradication.\n- **Training** — targeted, specific training tied to an actual gap (a tabletop exercise rehearsing the exact scenario that revealed a coordination weakness), not generic annual awareness training used as a catch-all fix.\n- **Policy or process changes** — updating escalation criteria, communication plans, or team structure where the incident revealed a structural gap rather than a one-off mistake.\n\n### Closing the loop\nThis is the literal mechanism behind the lifecycle loop described at the start of this module: Post-Incident Activity feeding back into Preparation is not a metaphor — it is this specific, tracked list of action items landing in the same systems, playbooks, and tooling backlogs that Preparation owns and maintains.",
        "keyPoints": [
          "Action items belong in the organization's real tracked work system, each with an owner, due date, and specific closure criterion",
          "Common categories include detection rule updates, playbook revisions, tooling/configuration changes, targeted training, and policy changes",
          "Generic annual training is a weak substitute for training targeted at the specific gap an incident revealed",
          "This tracked backlog is the literal mechanism by which Post-Incident Activity feeds back into Preparation, closing the lifecycle loop"
        ]
      },
      {
        "pageNumber": 8,
        "title": "Worked example: the postmortem outcome for the phishing/lateral-movement incident",
        "body": "Closing out the incident carried through this entire module, here is what a complete, well-run post-incident review actually produced for NexaCorp's Case IR-2026-0914.\n\n### The meeting\nHeld 10 days after closure, attended by the Incident Commander, the IR analyst, the affected employee, the Finance IT lead, and a security engineering representative. The timeline was confirmed accurate against the continuously-maintained record from Detection and Analysis. The team explicitly noted what worked well first: EDR isolation triggered within 6 minutes of the confirmed indicator, well inside NexaCorp's internal target.\n\n### Root cause analysis\nThe 5 Whys walkthrough from page 3 identified the structural root cause: the mail filter had never been evaluated for domain-age scoring capability since initial deployment. In parallel, the eradication team's finding — a shared local administrator credential across the Finance device fleet — was documented as a second, independent contributing factor, exactly as page 3 describes: multiple contributing factors, not one root cause.\n\n### The action items produced\n1. Configure domain-age scoring in the mail filter (owner: security engineering, due in 2 weeks)\n2. Eliminate shared local administrator credentials across the Finance fleet using a managed local admin password solution (owner: IT infrastructure, due in 30 days)\n3. Update the phishing playbook to include the DeviceNetworkEvents pivot that identified the second affected host (owner: IR lead, due in 1 week) — feeding directly into the next lesson\n4. Add a Sigma detection rule for encoded PowerShell spawned from Outlook, as drafted in the Detection and Analysis lesson (owner: detection engineering, due in 1 week)\n\n### Why this counts as a successful postmortem\nEvery item has an owner and a date; none of them is \"retrain the employee\" as a standalone fix; and item 3 explicitly hands off to the next lesson, IR playbooks, which is exactly where a postmortem's findings are supposed to land.",
        "keyPoints": [
          "A well-run postmortem confirms the timeline, names what worked well, and identifies all contributing factors, not just one",
          "The resulting action items span tooling configuration, credential management, playbook updates, and detection engineering — each with an owner and date",
          "None of the fixes rely solely on individual retraining, reflecting the blameless, systems-focused approach from page 4",
          "The playbook-update action item is the direct handoff into the next lesson's subject matter"
        ]
      }
    ],
    "quiz": [
      {
        "question": "A team resolves an incident, restores all systems, and immediately moves on without holding a formal review. According to NIST SP 800-61 and SANS PICERL, what has been skipped?",
        "options": [
          {
            "label": "Nothing — the incident lifecycle ends once recovery is complete",
            "value": "a"
          },
          {
            "label": "A required phase: NIST's Post-Incident Activity, which SANS PICERL calls Lessons Learned",
            "value": "b"
          },
          {
            "label": "Only an optional courtesy meeting with no defined place in either framework",
            "value": "c"
          },
          {
            "label": "The Containment phase, which should have happened after Recovery",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "Both frameworks treat this as a formal, required phase — NIST's Post-Incident Activity and SANS PICERL's Lessons Learned — not an optional add-on after the 'real' lifecycle ends at recovery. It is not an optional courtesy, and Containment is an earlier phase in both models, not one that follows Recovery."
      },
      {
        "question": "Using the 5 Whys technique on a credential-theft incident, the first answer is 'the attacker phished an employee's password.' Which follow-up best continues genuine root cause analysis rather than stopping too early?",
        "options": [
          {
            "label": "Recording 'retrain the employee' as the only action item and closing the review",
            "value": "a"
          },
          {
            "label": "Asking why the phishing email reached the employee's inbox and why the authentication method allowed a single password to grant access without an additional factor",
            "value": "b"
          },
          {
            "label": "Ending the analysis, since the attacker's phishing technique is itself the root cause",
            "value": "c"
          },
          {
            "label": "Assigning blame to the employee in the incident report to close the loop",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "Continuing to ask why (why did the email get through, why was a single password sufficient for authentication) is exactly how 5 Whys reaches structural, actionable causes instead of stopping at the first surface-level explanation. Recording only 'retrain the employee,' treating the phishing technique itself as the root cause, or assigning blame all stop the analysis prematurely and produce weak or counterproductive fixes."
      },
      {
        "question": "In a blameless postmortem, why is the discussion framed around conditions ('the on-call rotation had no coverage between 2 and 4 a.m.') rather than individuals ('the on-call analyst missed the alert')?",
        "options": [
          {
            "label": "Because no individual is ever responsible for fixing anything in a blameless process",
            "value": "a"
          },
          {
            "label": "Because blaming individuals suppresses honest reporting of near-misses and details, losing the visibility needed to prevent recurrence",
            "value": "b"
          },
          {
            "label": "Because conditions-based language is required by law in every jurisdiction",
            "value": "c"
          },
          {
            "label": "Because it removes the need to write action items at all",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "Blame-focused language predictably makes people stop volunteering information about near-misses and mistakes, which directly undermines the honest analysis a postmortem depends on. Blameless does not mean nobody is accountable — it shifts accountability to implementing the fix — and it is not a legal requirement, nor does it remove the need for action items, which remain central to the process."
      },
      {
        "question": "A SOC tracks MTTC (Mean Time to Contain) across many incidents over a year and observes it declining after adopting EDR-based network isolation. What is the correct way to interpret this metric?",
        "options": [
          {
            "label": "As a judgment of any single analyst's individual performance on their most recent incident",
            "value": "a"
          },
          {
            "label": "As a trend across many incidents that provides defensible evidence the tooling investment is improving containment speed",
            "value": "b"
          },
          {
            "label": "As a replacement for holding lessons-learned meetings on individual incidents",
            "value": "c"
          },
          {
            "label": "As a measure of Information Impact rather than response speed",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "MTTD/MTTC/MTTR are meant to be tracked as trends across many incidents, providing evidence of whether process and tooling changes are actually working — not as a judgment of any individual's performance on one case, which risks pressuring people to cut corners. They don't replace incident-specific lessons-learned meetings, and they measure response speed, not Information Impact (a separate classification dimension)."
      },
      {
        "question": "A postmortem reveals that an incident's early indicators existed in available logs but no detection rule caught them. Which tool referenced in this lesson is specifically designed to help prioritize closing that kind of gap?",
        "options": [
          {
            "label": "SOC-CMM, which is used for retraining individual analysts",
            "value": "a"
          },
          {
            "label": "DeTT&CT, which scores detection coverage and data source quality against MITRE ATT&CK techniques",
            "value": "b"
          },
          {
            "label": "The krbtgt password reset procedure",
            "value": "c"
          },
          {
            "label": "The CISA Recoverability classification",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "DeTT&CT is built exactly for this purpose: scoring an organization's visibility and detection coverage against specific MITRE ATT&CK techniques, so a postmortem finding like 'we had the data but no rule fired' becomes a prioritized, technique-specific gap to close. SOC-CMM assesses overall SOC maturity rather than technique-level detection gaps, the krbtgt reset is an eradication action unrelated to detection coverage, and Recoverability is a CISA impact-classification dimension, not a detection-gap tool."
      }
    ]
  },
  "incident-responder--ir-playbooks": {
    "pages": [
      {
        "pageNumber": 1,
        "title": "Playbook vs. plan: two different documents with two different jobs",
        "body": "This closing lesson of the module builds the artifact that every previous lesson has been pointing toward: the incident response **playbook** — and the tooling and testing discipline that keeps playbooks accurate rather than aspirational documents nobody actually follows.\n\n### The IR plan is strategic; the playbook is tactical\nThe **incident response plan (IRP)**, introduced in lesson 1's Preparation discussion, is the organization's top-level policy: who has authority to declare an incident, the team roles and escalation chain, communication and legal obligations. It applies to every incident regardless of type.\n\nA **playbook** is scenario-specific and tactical: a step-by-step procedure for handling one particular category of incident — phishing, ransomware, a compromised cloud account, a distributed denial-of-service attack. Where the IRP answers \"who has authority and how do we escalate,\" a playbook answers \"given this specific kind of incident, what exactly do we do, in what order, and who does it.\"\n\n### Why the distinction matters\nAn organization with only an IRP and no playbooks forces every responder to reinvent the tactical approach from first principles during every single incident — exactly the ad hoc firefighting this entire module has been building tools to avoid. An organization with only playbooks and no IRP has detailed tactics but no clear authority structure when a playbook doesn't cleanly cover what's actually happening, which is common, since real incidents rarely match a playbook's assumptions perfectly. Mature programs need both, with the playbook always operating inside the IRP's authority and escalation structure rather than replacing it.\n\n### What this lesson builds\nWorking through the anatomy of a playbook, decision trees that make branching logic explicit, SOAR (Security Orchestration, Automation and Response) integration that turns some playbook steps into automated actions, common playbook categories, and — critically — how to actually test a playbook against realistic behavior before trusting it during a real incident.",
        "keyPoints": [
          "The IR plan (IRP) is strategic and applies to every incident: authority, roles, escalation, legal/communications obligations",
          "A playbook is tactical and scenario-specific: a step-by-step procedure for one incident category (phishing, ransomware, cloud account compromise)",
          "Playbooks without an IRP lack clear authority when reality diverges from the playbook's assumptions; an IRP without playbooks forces reinvention every incident",
          "A playbook always operates inside the IRP's authority structure, not as a replacement for it"
        ]
      },
      {
        "pageNumber": 2,
        "title": "Anatomy of a playbook",
        "body": "A well-constructed playbook has a consistent internal structure, regardless of which incident category it covers, so responders can navigate any playbook in the library the same way under pressure.\n\n### Standard components\n- **Trigger and scope** — what specific conditions cause this playbook to be invoked (tying directly back to the activation criteria from lesson 1), and what it explicitly does and does not cover.\n- **Roles** — who is expected to be involved for this specific scenario, referencing the general IR roles from lesson 1 but naming the specific responsibilities for this playbook (e.g., \"the Finance system owner must be reachable within 15 minutes for a Business Email Compromise playbook\").\n- **Phase-by-phase actions** — concrete steps organized by the lifecycle phases from earlier lessons: what to check during Detection and Analysis, what containment options apply and their specific triggers, what eradication typically involves for this scenario, and expected recovery steps.\n- **Decision points** — explicit branches where the next action depends on a specific finding (covered in depth on the next page).\n- **Escalation criteria** — the specific conditions under which this playbook's default owner should escalate further, e.g., to the Incident Commander or executive sponsor.\n- **Communication templates** — pre-drafted language for common notifications (informing affected users, a holding statement for customers), so the team is not drafting sensitive communications from scratch under pressure.\n\n### A structural skeleton\nA skeleton view of a phishing response playbook's structure, before the branching decision logic is added on the next page:",
        "codeExample": "Playbook: Phishing Response\nTrigger: Confirmed malicious email delivered and at least one recipient interacted with it\nScope: Covers credential-harvesting and payload-delivery phishing; excludes pure spam/scam\n        reports with no confirmed interaction (handled via standard user-report triage)\nRoles: IR Analyst (lead), affected user's manager (notification), IT (mailbox/account actions)\nEscalation: Escalate to Incident Commander if more than 3 recipients interacted, or if any\n            interaction involved a privileged account\n\nPhase actions:\n  Detection & Analysis: pull message headers, check sandboxing verdict, review\n                         DeviceProcessEvents for any process spawned from the mail client\n  Containment: see decision tree (next page)\n  Eradication: purge the message org-wide, block sender domain, rotate any exposed credential\n  Recovery: re-enable affected account(s) after credential rotation and session revocation\n\nCommunication template: \"user-notification-phishing-v3\", \"customer-holding-statement-v2\"",
        "keyPoints": [
          "A playbook's standard components: trigger/scope, roles, phase-by-phase actions, decision points, escalation criteria, and communication templates",
          "Trigger and scope explicitly state what the playbook does and does not cover, avoiding ambiguity about when to use it",
          "Phase-by-phase actions map each lifecycle phase from earlier lessons to concrete steps specific to this incident category",
          "Pre-drafted communication templates avoid drafting sensitive messaging from scratch under time pressure"
        ]
      },
      {
        "pageNumber": 3,
        "title": "Decision trees: making branching logic explicit",
        "body": "Real incidents rarely follow a single straight-line procedure — the right next action depends on what is actually found. A **decision tree** makes that branching logic explicit and visual, rather than leaving it buried in prose that a stressed responder has to parse during an active incident.\n\n### Why explicit branching matters\nProse instructions like \"assess the scope and contain appropriately\" sound reasonable when writing a playbook calmly in advance, but provide almost no actual guidance to a responder at 2 a.m. facing a specific, ambiguous situation. A decision tree forces the playbook author to think through the actual branches in advance — during Preparation, when there's time to think clearly — rather than leaving that thinking to be done live during the incident.\n\n### A worked decision tree\nContinuing the phishing playbook from the previous page, here is the containment decision logic as an explicit flowchart, covering the branch points a responder actually faces: how many recipients interacted, and whether a privileged account was involved.\n\n### Keep decision points few and concrete\nA decision tree with too many branches becomes as hard to follow under pressure as unstructured prose, defeating its own purpose. Effective playbook authors limit branch points to the handful of factors that genuinely change the response — here, recipient count and account privilege level — rather than trying to enumerate every conceivable variation of the scenario. Anything more nuanced than the tree can capture is exactly the kind of judgment call that belongs to the Incident Commander's escalation path, not to an ever-more-complicated diagram.",
        "codeExample": "flowchart TD\n    A[Confirmed malicious phishing email] --> B{How many recipients interacted?}\n    B -->|1 recipient, standard account| C[Isolate affected host, disable account,\nrotate credentials]\n    B -->|2-3 recipients| D[Isolate all affected hosts,\nescalate to Tier 2 analyst]\n    B -->|4+ recipients or unknown scope| E[Escalate to Incident Commander,\norg-wide mail purge]\n    C --> F{Privileged account involved?}\n    D --> F\n    E --> F\n    F -->|Yes| G[Escalate to Incident Commander regardless of recipient count,\nreview privileged account activity log]\n    F -->|No| H[Continue standard containment,\nmonitor for 72 hours]",
        "keyPoints": [
          "A decision tree makes the branching logic of a playbook explicit, rather than leaving ambiguous judgment calls to a stressed responder mid-incident",
          "Working through the branches during Preparation (calm, in advance) is far more reliable than improvising them live",
          "Decision points should be tied to concrete, checkable conditions (recipient count, account privilege level), not vague criteria",
          "A single decision tree can combine multiple branch factors (scope and account sensitivity) into one coherent escalation path"
        ]
      },
      {
        "pageNumber": 4,
        "title": "SOAR integration: automating the mechanical steps",
        "body": "**SOAR** (Security Orchestration, Automation and Response) is a category of platform that connects a playbook's individual steps to automated actions across security tools, rather than requiring an analyst to manually execute each API call demonstrated earlier in this module (EDR isolation, account disabling) by hand every time.\n\n### What SOAR actually does\nA SOAR platform lets a team encode a playbook's mechanical steps as an automated workflow: when a specific trigger condition is met, the platform can automatically call the EDR platform's isolation API, the identity provider's account-disable API, or a ticketing system's case-creation API — the same underlying actions covered earlier in this module (the Microsoft Defender for Endpoint isolate call and the Microsoft Graph accountEnabled update from the Containment lesson), but executed by orchestration logic rather than a human typing each request.\n\n### Human-in-the-loop approval gates\nFull automation is not appropriate for every step. Mature SOAR playbooks distinguish between:\n- **Fully automated steps** — low-risk, easily-reversible, high-confidence actions (enriching an alert with threat intelligence lookups, creating a case ticket, pulling additional log context).\n- **Human-in-the-loop steps** — higher-impact or less-reversible actions (isolating a production host, disabling an executive's account) that the SOAR platform prepares and stages but requires a human analyst to explicitly approve before executing.\n\nThis mirrors the \"approval for meaningful business impact\" principle from the Containment lesson — SOAR does not remove that judgment requirement, it just removes the manual, repetitive work around it, so the analyst's attention is spent on the actual decision rather than on typing the same API call structure correctly under time pressure.\n\n### A representative automation hook\nA SOAR playbook step definition showing a human-in-the-loop approval gate before an isolation action executes, expressed as a simplified workflow action:",
        "codeExample": "{\n  \"step\": \"isolate_host\",\n  \"trigger\": \"confirmed_malicious_process_and_c2_beacon\",\n  \"action\": {\n    \"integration\": \"microsoft_defender_for_endpoint\",\n    \"api_call\": \"POST /api/machines/{deviceId}/isolate\",\n    \"parameters\": { \"IsolationType\": \"Full\" }\n  },\n  \"approval_required\": true,\n  \"approver_role\": \"incident_commander\",\n  \"on_approval_timeout_minutes\": 15,\n  \"on_timeout_action\": \"escalate_to_secondary_approver\"\n}",
        "keyPoints": [
          "SOAR platforms connect playbook steps to automated actions across security tools (EDR, identity provider, ticketing) rather than requiring manual API calls each time",
          "Low-risk, reversible steps (enrichment, ticket creation) suit full automation; high-impact steps (host isolation, disabling an executive's account) need human-in-the-loop approval",
          "SOAR does not remove the approval judgment required for meaningful business-impact actions — it removes the manual, repetitive execution work around it",
          "A well-designed automation hook includes an approval requirement, an approver role, and a timeout/escalation path if no one responds"
        ]
      },
      {
        "pageNumber": 5,
        "title": "Common playbook categories",
        "body": "Most SOC playbook libraries cover a recurring core set of incident categories, each with a distinct enough response pattern to justify its own dedicated playbook rather than a single generic template.\n\n| Playbook type | Distinct focus |\n|---|---|\n| Phishing | Message-based delivery; containment often centers on account/credential and mailbox-wide purge actions |\n| Ransomware | Time-critical; heavy emphasis on immediate isolation, backup verification, and the reimage-vs-clean decision from the Eradication lesson |\n| Insider threat | Requires HR and legal involvement early; evidence handling and confidentiality of the investigation itself are heightened concerns |\n| Data exfiltration | Focus on identifying what left the environment and through what channel, closely tied to the Information Impact classification dimension |\n| Distributed denial-of-service (DDoS) | Availability-focused; containment relies on upstream network/CDN mitigation rather than host-level actions |\n| Business Email Compromise (BEC) | Financial fraud via impersonation or compromised executive mailboxes; often requires rapid coordination with finance and banking partners to attempt a wire-transfer recall |\n\n### Why not one universal playbook\nA single generic \"incident playbook\" fails in practice because the actual decision points, roles, and urgency differ meaningfully by category. A ransomware playbook needs backup-verification steps a phishing playbook never touches; a BEC playbook needs a banking-partner contact a DDoS playbook has no use for. Forcing every incident category through one generic template produces a document too vague to be actionable for any specific scenario — the same failure mode as the \"assess the scope and contain appropriately\" prose problem from the previous page, just at the level of the whole playbook rather than a single step.\n\n### Coverage as a deliberate roadmap\nBuilding this library is itself a Preparation-phase project: a mature program maintains a prioritized roadmap of which playbook to build or update next, driven partly by which incident categories the organization's threat model considers most likely, and partly — as the next page covers — by testing results that reveal where existing playbooks have gaps.",
        "keyPoints": [
          "Common playbook categories include phishing, ransomware, insider threat, data exfiltration, DDoS, and Business Email Compromise (BEC)",
          "Each category has response patterns distinct enough (backup verification for ransomware, banking-partner contact for BEC) to justify its own dedicated playbook",
          "A single generic playbook is too vague to be actionable for any specific incident category",
          "Playbook library coverage is a deliberate Preparation-phase roadmap, prioritized by threat model and testing results"
        ]
      },
      {
        "pageNumber": 6,
        "title": "Testing playbooks before you need them",
        "body": "A playbook that has never been tested against realistic conditions is a hypothesis, not a validated procedure. This module has emphasized throughout that documentation alone is not enough — testing closes that gap.\n\n### Tabletop and purple team exercises\n- A **tabletop exercise** walks the team through a simulated scenario verbally or on paper, without touching any real system: \"Assume this alert fires; what do you do first?\" This is low-cost and good for validating roles, communication, and decision-tree logic without any technical risk.\n- A **purple team exercise** goes further: a red team (offensive) member actually performs specific attacker techniques against a test or controlled environment while the blue team (defensive) responds in real time, with both sides collaborating afterward to identify what was and wasn't detected or handled correctly.\n\n### Automated adversary emulation tools\nTwo widely used open tools make realistic technical testing repeatable rather than a rare, expensive, fully-manual exercise:\n- **Atomic Red Team** — an open-source library of small, individual test procedures (\"atomic tests\"), each mapped to a specific MITRE ATT&CK technique, that safely reproduces a narrow piece of adversary behavior (such as a specific persistence technique or credential access method) so defenders can verify their detection actually fires, without needing a full-scale simulated breach.\n- **MITRE CALDERA** — an adversary emulation framework, built on top of ATT&CK, that can chain multiple techniques together into a longer automated sequence, more closely simulating an actual multi-stage intrusion than a single atomic test, and includes a plugin that can invoke Atomic Red Team tests as part of a broader emulation.\n\n### Connecting testing to the playbook itself\nThe point of running an Atomic Red Team test for T1059.001 (PowerShell, the same technique from this module's Detection and Analysis lesson) is not just confirming the detection rule fires — it is confirming that once it fires, the phishing or relevant playbook's documented response steps actually work end to end against a realistic trigger, catching gaps like a decision tree branch that references a system that no longer exists, or an escalation contact who has since left the team.",
        "codeExample": "# Atomic Red Team — invoke a specific atomic test for T1059.001 (PowerShell)\n# in a controlled test environment, to verify the detection rule from the\n# Detection and Analysis lesson actually fires end-to-end\nInvoke-AtomicTest T1059.001 -TestNumbers 1 -GetPrereqs\nInvoke-AtomicTest T1059.001 -TestNumbers 1\n\n# MITRE CALDERA - conceptual ability reference chaining multiple techniques\n# in a single automated operation against a test environment\n{\n  \"operation_name\": \"phishing-followon-chain\",\n  \"abilities\": [\"T1566.001-simulated-delivery\", \"T1059.001-encoded-command\", \"T1053.005-scheduled-task\"]\n}",
        "keyPoints": [
          "Tabletop exercises validate roles, communication, and decision logic verbally, at low cost and no technical risk",
          "Purple team exercises have a red team execute real techniques while the blue team responds live, then jointly review what was caught",
          "Atomic Red Team provides small, ATT&CK-mapped 'atomic tests' to verify a specific detection fires without a full simulated breach",
          "MITRE CALDERA chains multiple techniques into a longer automated emulation, more closely resembling a real multi-stage intrusion"
        ]
      },
      {
        "pageNumber": 7,
        "title": "Maintaining playbooks over time",
        "body": "A playbook is only as good as its last update. This page connects directly back to the previous lesson: the post-incident review is the primary mechanism that keeps playbooks accurate rather than slowly drifting out of sync with reality.\n\n### Version control and review cadence\nPlaybooks should be version-controlled documents (tracked revisions, a clear changelog, a named owner) rather than a static file passed around by email, so a responder can trust they are reading the current version during an actual incident, and so changes can be reviewed and audited like any other critical operational document. Beyond incident-driven updates, most mature programs also schedule a periodic review (commonly annual, or after any major infrastructure change) even for playbooks that haven't been triggered by a real incident recently, since the underlying environment — tools, contacts, system architecture — changes even when incidents don't happen.\n\n### The postmortem-to-playbook pipeline\nRecall the action item from the previous lesson's worked example: \"update the phishing playbook to include the DeviceNetworkEvents pivot that identified the second affected host.\" This is the concrete mechanism by which a single incident's specific finding becomes a permanent improvement available to every future responder who opens that playbook — precisely the lifecycle loop this entire module has traced from Preparation through Post-Incident Activity and back again.\n\n### Mapping coverage with DeTT&CT\nBeyond individual incident-driven fixes, a playbook library's overall coverage can be assessed the same way detection coverage was assessed in the previous lesson: using DeTT&CT to identify which MITRE ATT&CK techniques the organization has weak detection or response coverage for, then prioritizing new playbook development or existing playbook updates against that same gap analysis — so playbook investment follows evidence of actual risk rather than guesswork or whichever incident happened most recently to be memorable.\n\n### A version log example\nA simple changelog entry format that keeps the update history auditable:",
        "codeExample": "Playbook: Phishing Response — Changelog\nv3.1 (2026-09-24) — Added DeviceNetworkEvents pivot step to scope-assessment section\n                     (source: postmortem action item, Case IR-2026-0914)\n                     Owner: IR lead | Reviewed by: security-eng-lead\nv3.0 (2026-06-01) — Annual scheduled review; updated escalation contact list\nv2.4 (2026-02-14) — Added communication template for customer holding statement",
        "keyPoints": [
          "Playbooks should be version-controlled with a named owner and auditable changelog, not passed around informally",
          "Beyond incident-driven updates, a periodic scheduled review keeps playbooks current with environment changes even absent a triggering incident",
          "The postmortem action-item pipeline is the concrete mechanism converting one incident's specific finding into a permanent improvement for every future responder",
          "DeTT&CT-style gap analysis can prioritize playbook investment by actual coverage risk rather than by which incident happened to be most recently memorable"
        ]
      },
      {
        "pageNumber": 8,
        "title": "Worked example: the phishing playbook, start to finish",
        "body": "To close both this lesson and the module, walk through the complete, updated phishing playbook (version 3.1, following the changelog from the previous page) as a responder would actually use it during a new incident at NexaCorp.\n\n### Trigger fires\nA user reports a suspicious email; simultaneously, Microsoft Defender for Endpoint flags an encoded PowerShell execution from Outlook on the reporting user's laptop — the same pattern from this module's running scenario, now caught faster because of the Sigma rule the earlier postmortem produced.\n\n### Automated SOAR steps execute immediately\nPer the automation hook from page 4, the SOAR platform automatically enriches the alert with threat intelligence context on the sender domain, creates a case ticket, and pulls the DeviceNetworkEvents and DeviceProcessEvents history for the affected host — all fully automated, no approval needed, because these are low-risk enrichment actions.\n\n### The decision tree is walked\nThe analyst follows the page 3 decision tree: one recipient interacted, standard (non-privileged) account. That routes to: isolate the affected host, disable the account, rotate credentials — the analyst approves the staged isolation action within the 15-minute SOAR timeout window from page 4's automation hook.\n\n### The updated scope-assessment step catches the second host\nPer the v3.1 changelog update, the playbook now explicitly directs the analyst to pivot on the confirmed C2 indicator through DeviceNetworkEvents before closing scope assessment — exactly the step added after the previous incident's postmortem. This time, it is checked as a standard playbook step rather than something an analyst has to think to do on their own, and it correctly finds no second affected host, allowing the team to close the scope assessment with confidence rather than lingering uncertainty.\n\n### The loop, complete\nThis is the entire module's argument made concrete: Preparation built the playbook; Detection and Analysis and Containment executed it faster and more completely than the first time; and when this incident eventually reaches its own post-incident review, whatever gap it reveals will update the playbook once more for the next responder.",
        "keyPoints": [
          "A mature playbook combines automated SOAR enrichment steps, an explicit decision tree for containment routing, and human approval gates for high-impact actions",
          "Postmortem-driven playbook updates directly change how the next incident is handled, not just how it is documented afterward",
          "Following a previously-added step (the DeviceNetworkEvents pivot) as a standard part of the playbook, rather than relying on an analyst to independently think of it, is the concrete value of playbook maintenance",
          "This worked example demonstrates the full module's lifecycle loop operating in practice: Preparation, Detection and Analysis, Containment, and Post-Incident Activity all connected through one maintained playbook"
        ]
      }
    ],
    "quiz": [
      {
        "question": "What is the key functional difference between an organization's incident response plan (IRP) and one of its playbooks?",
        "options": [
          {
            "label": "The IRP is strategic and applies to every incident (authority, roles, escalation); a playbook is tactical and scenario-specific (step-by-step actions for one incident category)",
            "value": "a"
          },
          {
            "label": "The IRP only covers ransomware, while playbooks cover every other incident type",
            "value": "b"
          },
          {
            "label": "Playbooks replace the need for an IRP once an organization has built enough of them",
            "value": "c"
          },
          {
            "label": "The IRP is optional documentation, while playbooks are the only legally required artifact",
            "value": "d"
          }
        ],
        "answer": "a",
        "explanation": "The IRP sets organization-wide authority, roles, and escalation that apply regardless of incident type, while a playbook provides the tactical, step-by-step procedure for one specific category of incident, operating inside the IRP's authority structure. The IRP is not ransomware-specific, playbooks do not replace the need for an IRP's authority structure, and the IRP is not merely optional documentation while playbooks are not the only legally required artifact."
      },
      {
        "question": "A SOAR playbook step automatically enriches an alert with threat intelligence and creates a case ticket with no human approval required, while a separate step to isolate a production host requires explicit Incident Commander approval before executing. What principle explains this difference?",
        "options": [
          {
            "label": "SOAR platforms cannot technically automate any host isolation action",
            "value": "a"
          },
          {
            "label": "Low-risk, reversible actions suit full automation, while higher-impact, less-reversible actions require a human-in-the-loop approval gate",
            "value": "b"
          },
          {
            "label": "Approval gates are only used for playbook categories other than phishing",
            "value": "c"
          },
          {
            "label": "Enrichment actions are always slower to execute than isolation actions",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "This reflects the core SOAR design principle from this lesson: full automation fits low-risk, easily-reversible actions, while higher-impact actions like isolating a production host require a human-in-the-loop approval gate before executing, mirroring the same business-impact judgment from the Containment lesson. SOAR platforms can technically automate isolation calls (as the API example shows), the distinction is not tied to a specific playbook category, and the difference isn't about execution speed."
      },
      {
        "question": "A team wants to verify that a specific detection rule for an encoded-PowerShell technique actually fires, without running a full simulated breach. Which tool is best suited to this narrow, targeted verification?",
        "options": [
          {
            "label": "A tabletop exercise, which is entirely verbal with no technical execution",
            "value": "a"
          },
          {
            "label": "Atomic Red Team, which provides small, ATT&CK-mapped atomic tests for verifying a specific technique's detection",
            "value": "b"
          },
          {
            "label": "SOC-CMM, which assesses overall organizational maturity rather than individual detections",
            "value": "c"
          },
          {
            "label": "The krbtgt password reset procedure",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "Atomic Red Team is designed exactly for this: small, individually-executable tests mapped to specific MITRE ATT&CK techniques, letting a team verify one detection fires without staging a full breach simulation. A tabletop exercise has no technical execution at all, SOC-CMM measures broader organizational maturity rather than a single detection, and a krbtgt reset is an unrelated eradication action."
      },
      {
        "question": "After a postmortem identifies that a playbook was missing a scope-assessment step that would have caught a second affected host sooner, what is the correct next action according to this lesson?",
        "options": [
          {
            "label": "Discuss the finding in the meeting and rely on analysts to remember it informally next time",
            "value": "a"
          },
          {
            "label": "Add the step to the version-controlled playbook with a tracked changelog entry, so every future responder benefits from the fix automatically",
            "value": "b"
          },
          {
            "label": "Wait for the annual scheduled review before making any change to the playbook",
            "value": "c"
          },
          {
            "label": "Discard the playbook entirely and rely only on the IR plan going forward",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "The postmortem-to-playbook pipeline described in this lesson works by actually updating the version-controlled playbook with a tracked changelog entry, so the improvement is built into the procedure itself rather than depending on individual memory. Waiting for an annual review delays a known, actionable fix unnecessarily, and discarding the playbook in favor of the IRP alone abandons the tactical detail the IRP was never designed to provide."
      },
      {
        "question": "Why does this lesson recommend maintaining separate playbooks for categories like ransomware, insider threat, and Business Email Compromise (BEC) rather than one generic incident playbook?",
        "options": [
          {
            "label": "Because regulations require a minimum number of separate playbook documents",
            "value": "a"
          },
          {
            "label": "Because each category has decision points, roles, and urgency distinct enough (backup verification for ransomware, banking-partner coordination for BEC) that a single generic template becomes too vague to be actionable for any of them",
            "value": "b"
          },
          {
            "label": "Because SOAR platforms cannot process more than one playbook type per organization",
            "value": "c"
          },
          {
            "label": "Because only ransomware and phishing are common enough to justify dedicated playbooks",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "The distinct decision points, roles, and urgency across categories — ransomware's backup verification, BEC's banking-partner coordination, insider threat's early HR/legal involvement — mean a single generic playbook would be too vague to give any of them actionable guidance, the same failure mode as vague prose instructions at the single-step level. This isn't a regulatory minimum, SOAR platforms handle multiple playbook types without issue, and the lesson names several categories beyond just ransomware and phishing as worth dedicated playbooks."
      }
    ]
  }
};
