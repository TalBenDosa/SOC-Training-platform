import type { Quiz } from "./data";

// ─── Learning Path module quizzes ─────────────────────────────────────────────
// One quiz per Learning Path module (Tal, 2026-10-14: "multiple-choice quizzes that match
// the taught material, on the Quizzes page"). Every question was written from one page of
// that module's own lessons; the citation (lesson key, page, verbatim quote) is kept in
// learningPathSources.json and learningPathQuizzes.test.ts re-proves it on every change.
// Independently reviewed: answer picked cold from the lesson = key; one correct option.
// Explanations name options by content (the page shuffles them).

export const QUIZZES_LEARNING_PATH: Quiz[] = [
  {
    "slug": "lp-alert-triage",
    "title": "SOC Analyst · Alert Triage",
    "description": "Knowledge check for the Learning Path module \"Alert Triage\" (SOC Analyst path). Every question comes from these lessons: Reading EDR alerts, Process trees in depth, Severity vs. risk score, Containment basics.",
    "difficulty": "Beginner",
    "category": "SOC Operations",
    "icon": "🚨",
    "estimatedMinutes": 12,
    "questions": [
      {
        "id": "lp-alert-triage-q01",
        "question": "A Defender row shows FileName powershell.exe and InitiatingProcessFileName cmd.exe, which looks like routine admin tooling. Which field shows the process one level above cmd.exe, and why is it worth pulling?",
        "options": [
          "InitiatingProcessCommandLine, because it lists every ancestor of the process in the row",
          "SHA1, because the hash of cmd.exe identifies whichever process originally launched it",
          "InitiatingProcessParentFileName, since attackers hide chains behind harmless-looking hops",
          "FileName, because it names the oldest ancestor in the chain rather than the new process itself"
        ],
        "answer": 2,
        "explanation": "InitiatingProcessParentFileName names the grandparent, and the lesson warns that attackers chain legitimate-looking hops to make the immediate parent look more innocuous than the full chain. InitiatingProcessCommandLine is only the parent's own command line, not a list of ancestors. SHA1 identifies a file, not its launcher. FileName names the new process itself.",
        "xp": 15
      },
      {
        "id": "lp-alert-triage-q02",
        "question": "An alert shows powershell.exe with -EncodedCommand and a parent of explorer.exe. The parent's own creation time shows it started six hours ago and has been idle since. How should the analyst read this normal-looking parent?",
        "options": [
          "As possible parent spoofing (T1134.004), since an idle explorer.exe would not launch a fresh payload",
          "As reassurance, since explorer.exe is the normal parent of applications that a user launches",
          "As svchost.exe masquerading, since any unexpected parent of a shell means a fake service host",
          "As unusable evidence, since the existence of spoofing makes lineage fields worthless for triage"
        ],
        "answer": 0,
        "explanation": "A spoofed parent still shows a legitimate name, so the analyst checks the claimed parent's creation time and recent activity, which here do not support it having just launched a new payload. Treating explorer.exe as reassurance ignores that mismatch. The svchost.exe rule is about services.exe being the parent of svchost.exe, not about shells. Spoofing does not make lineage useless, it means a too-normal parent beside alarming behavior needs scrutiny.",
        "xp": 20
      },
      {
        "id": "lp-alert-triage-q03",
        "question": "A Falcon CommandLine ends with -enc followed by a long base64 string. A colleague says it is encrypted, so nothing can be learned until someone finds the key. What does this module teach?",
        "options": [
          "The colleague is right, since an encoded command cannot be read without the attacker's key",
          "Only the EDR vendor can decode it, so a formal support case must be opened before any verdict is reached",
          "The flag is malicious by itself, so the decoding step can be skipped and the host isolated",
          "Base64 is reversible encoding and not encryption, so decode it to see the script before a verdict"
        ],
        "answer": 3,
        "explanation": "The lesson states that a skilled analyst decodes the base64, a standard and reversible encoding rather than encryption, to see what the script does before forming a verdict. No key is needed, so the colleague is wrong, and the vendor is not required. The flag is also not malicious alone, because admins use these flags too, so skipping the decode would be premature.",
        "xp": 15
      },
      {
        "id": "lp-alert-triage-q04",
        "question": "The same suspicious PowerShell pattern fires in Falcon on an intern's laptop and on the CFO's laptop. What will the Severity and SeverityName fields most likely show, and what follows for the analyst?",
        "options": [
          "The CFO detection gets a higher numeric Severity, since Falcon scores the owner's job role automatically",
          "Both carry the same values, so the analyst must supply the asset and identity context personally",
          "The intern detection gets a lower SeverityName, since Falcon severity reflects how unusual the account is",
          "Both carry the same values, so they can be queued equally because severity already measures impact"
        ],
        "answer": 1,
        "explanation": "Falcon's Severity and SeverityName describe the detected pattern and typically stay identical for the same pattern on different hosts. That leaves the analyst to supply asset and identity context through the Correlate step. Falcon does not score job roles or account baselines in these fields, and identical labels do not mean identical impact, so queuing them equally would be a prioritization mistake.",
        "xp": 20
      },
      {
        "id": "lp-alert-triage-q05",
        "question": "An analyst reviews this Splunk search: index=risk | stats sum(risk_score) as total_risk by risk_object, risk_object_type | where total_risk >= 80 | sort - total_risk. What does its output list?",
        "options": [
          "Single risk events whose own severity label is High, ranked by how recently each occurred",
          "Only hosts with an active Falcon detection above Severity 80, with users left out",
          "Every alert that an analyst has already reviewed and closed as a True Positive this week",
          "Entities whose summed risk score contributions reached 80 or more, highest total first"
        ],
        "answer": 3,
        "explanation": "The search sums risk score contributions per entity, which is how Risk-Based Alerting builds one running score for a user, host, or other asset, and then keeps the entities at or above the threshold. It does not look at single events, it is not limited to hosts, and it has nothing to do with Falcon's Severity field or with verdicts on closed alerts.",
        "xp": 15
      },
      {
        "id": "lp-alert-triage-q06",
        "question": "A workstation is already running a ransomware encryption routine when the analyst uses Falcon's Network Contain. What should the analyst expect?",
        "options": [
          "Spread and attacker communication stop, but the encryption already running locally can continue",
          "All malicious activity halts at once, because isolation freezes every process on the host",
          "The EDR agent loses its link to the console, so no live queries can be run on the host",
          "Memory contents are wiped as with a shutdown, so volatile evidence must be taken before containing"
        ],
        "answer": 0,
        "explanation": "Isolation cuts the network path but does not stop local activity, so a running encryption routine continues while spread and C2 are cut off. It does not freeze processes. Network Contain deliberately keeps the agent's connection to the vendor cloud, and it preserves memory, which is the reason to isolate instead of powering off.",
        "xp": 15
      },
      {
        "id": "lp-alert-triage-q07",
        "question": "A confirmed phish gave an attacker a signed-in Entra ID session for jsmith. Which identity containment sequence matches this module?",
        "options": [
          "Reset the password, re-enable the account at once, then revoke tokens after the user reports a problem",
          "Reset the password only, since the new credential invalidates every session and token already issued",
          "Disable or force sign-out, revoke sessions and tokens, reset the password, re-enable after eradication",
          "Revoke tokens, re-enable the account, reset the password, then disable it again after eradication"
        ],
        "answer": 2,
        "explanation": "Disabling first stops the attacker from re-authenticating while the rest is done, revoking sessions and tokens removes artifacts a reset leaves alive, the reset gives a credential the attacker never held, and re-enabling waits for eradication. A reset alone leaves already-issued sessions and tokens valid. The other orders re-enable the account too early.",
        "xp": 15
      },
      {
        "id": "lp-alert-triage-q08",
        "question": "A Tier 1 analyst sees one workstation beaconing to a C2 server, and the SIEM hints that other hosts may be involved but they are not yet mapped. Why might isolating this first host immediately be a poor choice?",
        "options": [
          "Isolation destroys the volatile memory on the host, so evidence needed for scoping would be lost",
          "It can tip the attacker off, who may speed up destructive actions on hosts not yet identified",
          "Network Contain applies to servers, so a workstation would stay connected to the C2 server",
          "Network Contain on a workstation needs a manager sign-off that a Tier 1 analyst cannot get"
        ],
        "answer": 1,
        "explanation": "In an active multi-host intrusion the first isolation can reveal that the defenders know, and the attacker may trigger destructive steps such as ransomware early on hosts not yet found, so the timing is a judgment call for Tier 2, Tier 3, or an IR lead. Isolation preserves memory, it works on workstations, and Tier 1 analysts generally can contain a single host under a playbook.",
        "xp": 20
      },
      {
        "id": "lp-alert-triage-q09",
        "question": "An older threat report lists Defense Evasion for a behavior that your Falcon console labels Tactic: Stealth. A teammate says the console is mislabeling it. What explains the difference?",
        "options": [
          "Falcon invents its own tactic names, so the report is the only reliable ATT&CK source",
          "Stealth is a technique under Defense Evasion, so both labels are valid at different levels",
          "Defense Evasion was kept for log tampering, and Stealth now covers only phishing delivery",
          "ATT&CK v19 renamed Defense Evasion to Stealth, and tool and log tampering moved to Defense Impairment"
        ],
        "answer": 3,
        "explanation": "The Falcon console follows ATT&CK v19, which renamed the old tactic and created Defense Impairment for tool and log tampering, so older reports still show the previous name. Falcon does not invent tactic names, Stealth is a tactic and not a technique, and it has nothing to do with phishing delivery.",
        "xp": 15
      },
      {
        "id": "lp-alert-triage-q10",
        "question": "An analyst clicks Network Contain on a laptop that happens to be offline, and the console shows the action as requested. What should the analyst do before reporting the host as contained?",
        "options": [
          "Report it as contained now, since an issued command is enforced at the moment it is sent",
          "Close the ticket and let the next shift notice if the host ever reconnects to the network",
          "Confirm the console shows Contained or Isolated, since an offline host applies it on reconnect",
          "Re-run the command on other hosts, since a pending state shows this host was not compromised"
        ],
        "answer": 2,
        "explanation": "Containment tools can fail silently, and an isolation command issued to an offline endpoint only applies once it reconnects, so the analyst must verify the Contained or Isolated status and not just that the action was requested. Reporting it as contained overstates the facts, closing the ticket abandons verification, and a pending state says nothing about whether the host was compromised.",
        "xp": 15
      }
    ]
  },
  {
    "slug": "lp-mitre-attack",
    "title": "SOC Analyst · MITRE ATT&CK",
    "description": "Knowledge check for the Learning Path module \"MITRE ATT&CK\" (SOC Analyst path). Every question comes from these lessons: Tactics & techniques, Mapping alerts to ATT&CK, Coverage thinking.",
    "difficulty": "Intermediate",
    "category": "Threat Framework",
    "icon": "🗺️",
    "estimatedMinutes": 12,
    "questions": [
      {
        "id": "lp-mitre-attack-q01",
        "question": "During an intrusion, the attacker stops the EDR sensor and halts log forwarding on a server. Using the ATT&CK v19 Enterprise tactic list, which tactic describes this goal?",
        "options": [
          "TA0005 Stealth, the tactic for avoiding detection by hiding or blending into normal activity",
          "TA0112 Defense Impairment, the tactic for disabling or degrading security tools and logging",
          "TA0040 Impact, the tactic for manipulating, interrupting, or destroying systems and data",
          "TA0007 Discovery, the tactic for learning about the surrounding environment and its systems"
        ],
        "answer": 1,
        "explanation": "Stopping a sensor and halting log forwarding disables security tools and logging, which v19 places under TA0112 Defense Impairment. TA0005 Stealth is about hiding, a different and quieter goal, and the split exists because breaking defenses is a louder act. Impact targets systems and data, and Discovery only learns about the environment.",
        "xp": 15
      },
      {
        "id": "lp-mitre-attack-q02",
        "question": "Last month an LSASS memory dump was done with Mimikatz, and this month the same behavior was done with procdump. How should the technique mapping change?",
        "options": [
          "Create a new technique ID for procdump, since every tool needs its own separate mapping",
          "Move the alert to a different tactic, since the tool decides which goal is actually served",
          "Drop the mapping, since T1003.001 applies only when Mimikatz is the tool involved",
          "Keep T1003.001, since it describes the behavior of dumping LSASS memory and not the tool"
        ],
        "answer": 3,
        "explanation": "A technique ID describes a behavior, and tools such as Mimikatz or procdump are procedures or software under it. The mapping stays T1003.001 when the tool changes. The tool does not decide the tactic, and T1003.001 is not limited to one tool, so a new ID or dropping the mapping would break consistent metrics.",
        "xp": 15
      },
      {
        "id": "lp-mitre-attack-q03",
        "question": "An intrusion shows Discovery, then Lateral Movement, then Discovery again on the new host, then Credential Access. A new analyst says this cannot be real ATT&CK activity because tactics run in one fixed order. What is the best answer?",
        "options": [
          "It is normal: matrix order is a guide, and intrusions often revisit earlier tactics",
          "It is an error, since Credential Access has to be recorded before Discovery",
          "It suggests two merged intrusions, since one intrusion uses each tactic once",
          "It is normal only for ICS matrices, while Enterprise intrusions follow matrix order"
        ],
        "answer": 0,
        "explanation": "ATT&CK does not require attackers to move through tactics in strict order, and revisiting Discovery after moving to a new host is a common pattern. The left-to-right layout is only a mental map of likely phases. The other options invent a fixed order, a ban on repeating tactics, or a difference between domains that the module does not teach.",
        "xp": 20
      },
      {
        "id": "lp-mitre-attack-q04",
        "question": "An EDR alert shows rundll32.exe opening lsass.exe with GrantedAccess 0x1FFFFF. No file was written and no network connection was seen. A junior analyst calls it benign because nothing was dropped. What best matches the module?",
        "options": [
          "Benign, since a signed Windows utility with no file or network activity cannot steal credentials",
          "T1059.001 PowerShell under Execution, since rundll32.exe is a scripting interpreter",
          "T1003.001 under Credential Access, since a broad handle into lsass.exe is the dumping fingerprint",
          "T1053.005 under Persistence, since the access mask shows that a task was registered"
        ],
        "answer": 2,
        "explanation": "LSASS holds credential material in memory, and a broad access mask from a process with no reason to request it is the classic fingerprint of credential dumping, so the mapping is T1003.001 under TA0006 Credential Access. Credential dumping from memory needs no dropped file or network traffic. rundll32.exe is not a scripting interpreter and an access mask says nothing about scheduled tasks.",
        "xp": 15
      },
      {
        "id": "lp-mitre-attack-q05",
        "question": "An analyst's escalation note says only: Technique T1003.001. The receiving Tier 2 analyst asks what is missing. Which addition does the module call for?",
        "options": [
          "The manager's name and the shift, so ownership of the ticket can be traced later",
          "The tactic and the evidence supporting the mapping, such as the access value and time",
          "A second, unrelated technique ID, so every note carries at least two mappings",
          "The vendor severity label alone, because it already replaces technique evidence"
        ],
        "answer": 1,
        "explanation": "A properly documented entry pairs each ID with a one-line summary, its tactic, and the evidence that supports the mapping, because a bare ID is nearly as unhelpful as no mapping. Ownership details are not what makes a mapping usable, no rule requires two IDs per note, and a severity label does not describe which behavior was seen.",
        "xp": 20
      },
      {
        "id": "lp-mitre-attack-q06",
        "question": "A threat report says observed activity is consistent with G0016, and the SOC wants to compare that actor's techniques with its own coverage. Where does the analyst find the actor's technique list?",
        "options": [
          "The Software catalog, because S-prefixed entries list the threat actors that use each tool",
          "The matrix columns, because each tactic column is owned by exactly one named threat group",
          "The T1059 sub-technique list, because it documents every group's use of PowerShell",
          "The ATT&CK Groups page for G0016, which lists techniques with evidence of use by that actor"
        ],
        "answer": 3,
        "explanation": "G-prefixed IDs belong to Groups, and each group page documents the techniques ATT&CK has evidence the actor used. That list can then be set beside a coverage layer. Software entries describe tools, tactic columns are not owned by groups, and T1059 sub-techniques describe interpreters and not actors.",
        "xp": 15
      },
      {
        "id": "lp-mitre-attack-q07",
        "question": "NexaCorp's coverage table shows T1059.001 PowerShell as Partial: Sysmon Event ID 1 is collected, but no rule looks for encoded or obfuscated commands. Which kind of work closes this gap?",
        "options": [
          "Detection engineering: write a rule on the data already collected, as visibility exists",
          "A logging change: collect new telemetry, since the organization cannot see PowerShell activity",
          "Response staffing: add overnight analysts, since nobody reviews the existing alerts",
          "No work, since a Partial status means the technique is covered well enough to ignore"
        ],
        "answer": 0,
        "explanation": "The data source exists, so visibility is fine, and what is missing is a detection built on it. That is a detection-engineering item and not a logging problem. No rule exists yet, so there is nothing for overnight analysts to review, and Partial marks a real, fixable gap rather than a reason to ignore it.",
        "xp": 15
      },
      {
        "id": "lp-mitre-attack-q08",
        "question": "While working an intrusion, an analyst could not read what an encoded PowerShell command did because Event ID 4104 was not enabled on the servers. Which gap request follows the module's guidance?",
        "options": [
          "Please improve our PowerShell detection, because this incident showed that we are weak there",
          "Buy a second EDR product, because a different vendor would decode the encoded script",
          "Enable Event ID 4104 script block logging on the servers to close the T1059.001 visibility gap",
          "Raise the severity of PowerShell alerts, so analysts spend longer on each encoded command"
        ],
        "answer": 2,
        "explanation": "An actionable gap report names the exact missing log source and ties it to the technique it closes. The vague request gives engineers nothing to implement. Another product does not address a log source that is simply switched off, and raising severity changes labels but does not add visibility into decoded script content.",
        "xp": 15
      },
      {
        "id": "lp-mitre-attack-q09",
        "question": "Two open gaps compete for this quarter. Gap A is a rare but catastrophic technique with zero visibility. Gap B is a common but low-impact technique that already has partial detection. Which does the module's reasoning favor?",
        "options": [
          "Gap B, because prevalence is the deciding factor and common techniques should be closed first",
          "Gap B, because partial coverage means it is nearly finished and therefore cheaper to complete",
          "Neither, because coverage work should wait until a real incident shows which technique matters",
          "Gap A, because blast radius and the size of the current gap can outweigh low prevalence"
        ],
        "answer": 3,
        "explanation": "Prioritization weighs prevalence, blast radius, and gap size together, so a rare, catastrophic, zero-visibility technique can outrank a common, low-impact one with partial detection. Prevalence alone is not the rule and cheapness is not one of the three factors. Waiting for an incident is also wrong, because the module treats coverage review as a recurring process informed by threat intelligence, not something postponed until a breach.",
        "xp": 20
      },
      {
        "id": "lp-mitre-attack-q10",
        "question": "In a DeTT&CT review, the team scores a data source low because field names differ across log forwarders. How does that score affect the techniques that depend on the data source?",
        "options": [
          "Their detection scores fall at once, because DeTT&CT merges visibility and detection into one number",
          "They inherit a weaker visibility score, even before anyone checks whether a detection rule exists",
          "They are removed from the Navigator layer, because poor data quality makes a technique irrelevant",
          "Nothing changes until an analyst writes a rule, since visibility is only scored after detection"
        ],
        "answer": 1,
        "explanation": "DeTT&CT propagates data source quality into a per-technique visibility score, before and separately from any detection scoring. It keeps the two scores deliberately distinct, so detection does not fall automatically. Techniques are not removed from layers for poor data, and visibility is not scored after rules exist.",
        "xp": 20
      }
    ]
  },
  {
    "slug": "lp-investigation-workflow",
    "title": "SOC Analyst · Investigation",
    "description": "Knowledge check for the Learning Path module \"Investigation\" (SOC Analyst path). Every question comes from these lessons: Building timelines, Pivoting on entities, Verdict workflows.",
    "difficulty": "Beginner",
    "category": "SOC Operations",
    "icon": "🔍",
    "estimatedMinutes": 12,
    "questions": [
      {
        "id": "lp-investigation-workflow-q01",
        "question": "An email gateway line reads 09-28 12:14:02 (device in UTC+3) for the delivery of invoice_Q3.docm. An EDR line reads 2026-09-28T09:26:41Z for powershell.exe -enc spawned by WINWORD.EXE. How long after delivery did PowerShell run?",
        "options": [
          "About 2 hours 47 minutes before delivery, so the order is impossible and the EDR clock is wrong",
          "About 3 hours after delivery, since the time zone offset is the true gap between the events",
          "It cannot be computed, since sources with different formats can never share one timeline",
          "About 12 minutes 39 seconds, after converting the gateway time from UTC+3 to 09:14:02Z"
        ],
        "answer": 3,
        "explanation": "Converting the gateway's local UTC+3 time to UTC gives 09:14:02Z, and 09:26:41Z minus 09:14:02Z is 12 minutes 39 seconds. Comparing the raw times without converting produces the impossible-looking order in the first option. The offset is not the gap between events, and normalization exists precisely so that different formats can be compared.",
        "xp": 15
      },
      {
        "id": "lp-investigation-workflow-q02",
        "question": "An analyst sees an on-premises event at 09:41 UTC, then pivots to the Microsoft 365 Unified Audit Log with a search window of 09:40 to 09:45. Nothing appears, though cloud activity is strongly suspected. What is a likely reason and fix?",
        "options": [
          "Cloud audit logs can lag by several minutes, so the search window should be wider",
          "Cloud logs use local time with no zone marker, so every event is shifted by hours",
          "The audit log keeps no UTC timestamps, so it cannot be joined to on-premises data",
          "The EDR agent deleted the cloud events, so a gap must be recorded in the timeline"
        ],
        "answer": 0,
        "explanation": "Cloud audit logs have their own ingestion delay, so an event can appear minutes after it happened, and the pivot window must allow for that. Microsoft 365 and AWS CloudTrail logs use ISO 8601 UTC, so a zone problem is not the explanation. An EDR agent does not manage cloud audit data, and nothing in the evidence suggests a deletion or a gap.",
        "xp": 15
      },
      {
        "id": "lp-investigation-workflow-q03",
        "question": "A report's fact table says: dropper.exe was present on WKS-4471 from 14 to 21 September. The EDR agent was not deployed during that period, but the file was seen before and after it. What is the problem?",
        "options": [
          "Nothing, since a file seen before and after a gap is proven to have been present throughout",
          "It states an inference as confirmed fact, so it should be labeled as an inference",
          "The gap should have been left out, since unlogged periods are never mentioned in a timeline",
          "The entry must be deleted, since inference is forbidden anywhere in an investigation report"
        ],
        "answer": 1,
        "explanation": "Inference from surrounding evidence is allowed, but it must be labeled as inference and not written as a logged fact, because mixing the two is a serious credibility risk. Presence throughout the gap is not proven. Gaps should be marked explicitly and not hidden, and inference is not forbidden, only required to be labeled.",
        "xp": 20
      },
      {
        "id": "lp-investigation-workflow-q04",
        "question": "The analyst suspects that rjones' stolen credential was also used against cloud applications. Which Microsoft Sentinel table extends the account pivot to show that reuse?",
        "options": [
          "DeviceProcessEvents, because it records every process launched under the account",
          "DeviceLogonEvents, because it shows which account was logged onto a given device",
          "SigninLogs, because it records each cloud authentication with source IP and app",
          "DeviceFileEvents, because it shows files created by the account across the fleet"
        ],
        "answer": 2,
        "explanation": "SigninLogs records Azure AD / Entra ID sign-in activity with account, source IP, location, and application, which on-premises Windows logs alone would never reveal. DeviceLogonEvents shows which account was logged onto a device, which is the earlier host-side step. DeviceProcessEvents and DeviceFileEvents describe processes and files and say nothing about cloud authentication.",
        "xp": 15
      },
      {
        "id": "lp-investigation-workflow-q05",
        "question": "Pivoting on 203.0.113.45, the analyst finds that WHOIS shows a fresh VPS registered three days before the attack and passive DNS shows it only ever hosted portal-cdn-sync.example. Three hosts connected to it. How should the result be read?",
        "options": [
          "As a small, high-confidence set of related hosts, so all three are strong scoping candidates",
          "As a large, low-confidence set, because every IP pivot returns noise from shared infrastructure",
          "As inconclusive, because WHOIS and passive DNS cannot help separate attacker infrastructure",
          "As proof that the three hosts are fully compromised, so no further evidence is needed"
        ],
        "answer": 0,
        "explanation": "A narrow, dedicated attacker IP, such as a freshly registered VPS hosting only the malicious domain, gives a small and high-confidence result. Noise comes from shared infrastructure, which this IP is not. WHOIS and passive DNS are exactly the enrichment that separates the two cases. High confidence still means candidates for scoping, not proof of full compromise.",
        "xp": 20
      },
      {
        "id": "lp-investigation-workflow-q06",
        "question": "Two other hosts hold copies of the dropper. On host B it was renamed but is otherwise unchanged, and on host C the attacker altered a single byte. A SHA256 pivot is run fleet-wide. What will it find?",
        "options": [
          "Both hosts, since a hash identifies the file family even after its content changes",
          "Neither host, since attackers rename files and renaming always changes the hash",
          "Only host C, since a changed file is always the first thing a hash pivot flags",
          "Only host B, since renaming keeps the hash and any byte change alters it"
        ],
        "answer": 3,
        "explanation": "A SHA256 hash is computed from the exact bytes, so renaming leaves it unchanged and the pivot finds host B, while a single altered byte gives a completely different hash that the pivot misses on host C. The hash does not identify a file family, renaming does not alter content, and a changed file is not flagged by the original hash.",
        "xp": 20
      },
      {
        "id": "lp-investigation-workflow-q07",
        "question": "An analyst closes an alert as Benign Positive with the note: expected activity. Which supporting evidence does the module say belongs in a Benign Positive note?",
        "options": [
          "A full list of IOCs, mapped technique IDs, and every confirmed affected host and account",
          "The root cause of the flawed rule logic and the rule fix that was requested",
          "The scope of the activity and its authorization, such as a change ticket reference",
          "A statement of the evidence that is missing, with a date or trigger to revisit the alert"
        ],
        "answer": 2,
        "explanation": "Benign Positive notes are scope-and-authorization-focused, for example the approved change that explains the activity. Extensive IOC and host lists belong to True Positive notes, root cause and a requested fix belong to False Positive notes, and a statement of missing evidence with a revisit trigger belongs to Undetermined.",
        "xp": 10
      },
      {
        "id": "lp-investigation-workflow-q08",
        "question": "Two hours into scoping, each new pivot still turns up previously unseen hosts, and the time budget has run out. What does the module recommend?",
        "options": [
          "Stop the investigation entirely, since the time box means the incident is out of scope",
          "Escalate with scope labeled provisional, and keep investigating alongside response actions",
          "Keep pivoting silently until no new host appears, and escalate only when the scope is final",
          "Close the ticket as Undetermined, since a scope that is still growing is unfit to document"
        ],
        "answer": 1,
        "explanation": "The time box is a point to escalate with the best current understanding of scope, labeled provisional, while deeper investigation and the response actions already justified continue in parallel. Stopping abandons an active incident. Waiting for a final scope delays containment, and Undetermined is for missing evidence, not for an investigation that is still finding more.",
        "xp": 15
      },
      {
        "id": "lp-investigation-workflow-q09",
        "question": "A rule that flags unusual outbound scanning traffic fires on scans from a range owned by the approved penetration-testing team during a scheduled test. Which verdict fits, and is the rule's logic the problem?",
        "options": [
          "Benign Positive: the rule worked as designed on authorized activity, so its logic is fine",
          "False Positive: the rule's logic is wrong, so it should be rewritten to ignore all scanning",
          "True Positive: the scanning is malicious by nature, so the testers' hosts should be isolated",
          "Undetermined: classifying the scans first requires a call to the testing team's manager"
        ],
        "answer": 0,
        "explanation": "The rule correctly fired on genuine scanning that turned out to be authorized, which is the definition of a Benign Positive, so the right response is a narrow suppression and not a rewrite. A False Positive means the rule logic itself is wrong. Treating the test as a True Positive ignores the authorization, and Undetermined is for cases where the evidence cannot support a call, which is not the situation here.",
        "xp": 15
      },
      {
        "id": "lp-investigation-workflow-q10",
        "question": "After a host pivot confirms malware on WKS-2210, the analyst closes the ticket as True Positive listing only that host. The user and domain pivots were never run. What is the main risk?",
        "options": [
          "The verdict label is wrong, since malware on a single host belongs in the Undetermined class",
          "The closing note will be too long, since True Positive notes need the least supporting detail",
          "The ticket may undercount affected hosts and accounts, giving a false sense of resolution",
          "Containment must be undone, since containment is only allowed after the ticket is closed"
        ],
        "answer": 2,
        "explanation": "Closing as True Positive before the scoping pivots are complete can leave the true extent unknown and undercount affected hosts and accounts, producing a false sense of resolution. The verdict category itself is right, since malicious activity was confirmed. True Positive notes need the most detail and not the least, and containment is justified as soon as the evidence supports it.",
        "xp": 20
      }
    ]
  },
  {
    "slug": "lp-hunt-methodology",
    "title": "Threat Hunter · Hunt Methodology",
    "description": "Knowledge check for the Learning Path module \"Hunt Methodology\" (Threat Hunter path). Every question comes from these lessons: TTP-based hunting, Hypothesis framework, Coverage gaps.",
    "difficulty": "Intermediate",
    "category": "Threat Detection",
    "icon": "🎯",
    "estimatedMinutes": 12,
    "questions": [
      {
        "id": "lp-hunt-methodology-q01",
        "question": "An advisory lists four things about an intrusion: a malware file hash, a command-and-control IP address, a C2 domain name, and the technique of dumping credentials from LSASS memory. According to the Pyramid of Pain, which would cost the attacker the most effort to change?",
        "options": [
          "The malware file hash, since it uniquely identifies the sample",
          "The C2 IP address, since rented infrastructure takes time to replace",
          "The credential dumping technique, since tradecraft is costly to redo",
          "The C2 domain name, since a new domain must be registered first"
        ],
        "answer": 2,
        "explanation": "The Pyramid of Pain puts TTPs at the very top because changing tradecraft forces the attacker to redesign part of the operation. A hash breaks with one changed byte, and an IP address can be replaced with rented infrastructure in minutes, so the file hash and the C2 IP sit on the cheap bottom rungs. Domain names also rank below tools and TTPs, so the C2 domain is wrong too.",
        "xp": 15
      },
      {
        "id": "lp-hunt-methodology-q02",
        "question": "A hunter runs a Kerberoasting query (Event ID 4769) over 30 days and gets zero rows. Before writing anything in the hunt log, she runs an unfiltered count of 4769 events across all domain controllers, and that count is also zero. How should the hunt be logged?",
        "options": [
          "Inconclusive: visibility gap, then enable ticket auditing and rerun the hunt",
          "Clean negative: the query ran successfully and found no Kerberoasting",
          "Inconclusive: detection gap, so build a rule to watch the 4769 events",
          "Skip the entry, because a hunt that found nothing is not worth documenting"
        ],
        "answer": 0,
        "explanation": "A count of zero shows the data source is not confirmed flowing, so the empty hunt result cannot be trusted. The lesson says to log inconclusive: visibility gap, then enable Kerberos service ticket auditing, confirm forwarding, and rerun. A clean negative is only trustworthy when collection is confirmed. A detection gap means data exists with nothing watching it, but here there is no data for a rule to read, and skipping the entry is the documented pitfall of throwing away a negative or inconclusive result.",
        "xp": 20
      },
      {
        "id": "lp-hunt-methodology-q03",
        "question": "A hunter writes: If an attacker is using scheduled tasks for persistence (T1053.005), evidence would appear as schtasks.exe creating a task whose /tr argument points outside Program Files or System32. Which component of a well-formed hypothesis is still missing?",
        "options": [
          "The suspected behavior, which should stay a general category such as persistence",
          "The detection logic, because a /tr path is not a specific value to test",
          "An incident ticket, because every hypothesis must link one before a hunt starts",
          "The data source, meaning the exact table or feed holding schtasks.exe command lines"
        ],
        "answer": 3,
        "explanation": "The statement names a technique and a concrete value to test, but not where to look. The data source must name the exact table or feed, here process-creation telemetry in DeviceProcessEvents, so the hunter can confirm it is actually collected. The behavior is already specific (T1053.005), and the lesson warns against general categories, so a is wrong. The /tr path is a concrete detection value, so b is wrong. An incident ticket belongs to a confirmed-finding log entry, not to the hypothesis template.",
        "xp": 15
      },
      {
        "id": "lp-hunt-methodology-q04",
        "question": "A junior hunter plans a single query to hunt for lateral movement across the whole environment for the last year. What is the main problem with this plan?",
        "options": [
          "Lateral movement is not an ATT&CK tactic, so it cannot be hunted",
          "The scope is so broad the query may never finish, so time-box it",
          "Hunts are only valid when they follow a SIEM alert on the same behavior",
          "A single year of data is too little, so the window must be extended"
        ],
        "answer": 1,
        "explanation": "This is the boil-the-ocean pitfall: a scope so broad that the query never finishes or the result set is unmanageable. The fix is to time-box and bound the hunt. Lateral movement is an ATT&CK tactic, so a is wrong. Hunting is proactive and does not wait for an alert, so c is wrong. A longer window would make the problem worse, so d is wrong.",
        "xp": 15
      },
      {
        "id": "lp-hunt-methodology-q05",
        "question": "A UEBA platform assigns a user a high risk score and a hunter wants to start from it. What do the lessons say must happen before querying begins?",
        "options": [
          "Nothing, because a risk score already counts as a testable hypothesis",
          "Escalate to incident response, since a high score confirms compromise",
          "Narrow the flag into one specific, testable statement of behavior",
          "Wait until a SIEM rule fires on the same user before hunting starts"
        ],
        "answer": 2,
        "explanation": "A hunt that starts from a UEBA risk score is a model-assisted hunt, and like every hunt type it must be narrowed into a specific, testable statement before querying, or it falls into the unstructured trap. A risk score is a lead rather than a hypothesis, so a is wrong, and it does not confirm a compromise, so b is wrong. Hunting is proactive and does not depend on a SIEM rule firing first, so d is wrong.",
        "xp": 15
      },
      {
        "id": "lp-hunt-methodology-q06",
        "question": "A SOC runs its hunts from a written, repeatable procedure that any hunter can follow. The team has not built its own custom analysis techniques and does not automate successful hunts. Which Hunting Maturity Model level fits best?",
        "options": [
          "HM2",
          "HM1",
          "HM3",
          "HM4"
        ],
        "answer": 0,
        "explanation": "HM2 organizations run hunts using a documented, repeatable procedure. HM1 is defined by consuming threat intelligence with hunts that stay reactive to it, so b does not match a written procedure. HM3 requires custom analysis techniques of the team's own, and HM4 adds automation of successful hunts, and the scenario rules out both.",
        "xp": 15
      },
      {
        "id": "lp-hunt-methodology-q07",
        "question": "A Sigma rule runs on fully collected Kerberos ticket data, but it fires hundreds of times a day and analysts have started closing every alert unread. Which coverage state is this?",
        "options": [
          "No data source exists, so a new log source must be onboarded",
          "Data quality is insufficient, so device coverage needs improving",
          "Data exists with no detection, so a new rule must be built",
          "An untuned detection, so the noisy rule needs tuning"
        ],
        "answer": 3,
        "explanation": "The data is collected and a detection exists, so the problem is the fourth question on the decision path: is it tuned well enough to be trusted? A detection so noisy that analysts ignore it functionally reproduces a detection gap, and the fix is tuning. No data source, insufficient data quality, and data with no detection describe the first three states, which the scenario rules out because the data is fully collected and a rule already exists.",
        "xp": 20
      },
      {
        "id": "lp-hunt-methodology-q08",
        "question": "Two gaps are on the backlog. Gap 1: Kerberos ticket auditing is off on the domain controllers, fixable by enabling an existing policy setting, and the sector's known threat actors use Kerberoasting. Gap 2: a missing log connector for a decommissioned test server, which needs new ingestion budget. Which should be closed first?",
        "options": [
          "Gap 2, because new connectors always take priority over policy changes",
          "Gap 1, because it is relevant, affects critical assets, and is cheap to fix",
          "Neither, until a purple team exercise proves both gaps can be exploited",
          "Gap 2, because a test server is easier to monitor than a domain controller"
        ],
        "answer": 1,
        "explanation": "Gap 1 scores well on all three prioritization factors: it is relevant to the threat actors targeting the sector, it sits on critical assets (domain controllers), and the fix is cheap. Gap 2 is low relevance, low criticality, and expensive, so it can reasonably wait. The claim that new connectors always outrank policy changes is invented, waiting for a purple team exercise adds a precondition the lessons never require, and calling a test server easier to monitor ignores asset criticality.",
        "xp": 20
      },
      {
        "id": "lp-hunt-methodology-q09",
        "question": "In an ATT&CK Navigator layer, most of the Lateral Movement column is yellow. Using the common color convention from the lessons, what does that tell the team?",
        "options": [
          "Those techniques have no log source at all and are completely dark",
          "Those techniques are fully covered by both visibility and detection",
          "Data exists for those techniques, but almost nothing is watching it",
          "Those techniques were validated by a purple team exercise this quarter"
        ],
        "answer": 2,
        "explanation": "In the common convention, yellow means visibility without detection: the data is collected but little or nothing is actively watching it. Red or dark means no log source at all, and green means full coverage by both visibility and a confirmed detection. Color alone does not say a purple team exercise validated the techniques; that would show up as a before and after layer comparison.",
        "xp": 15
      },
      {
        "id": "lp-hunt-methodology-q10",
        "question": "An advisory says an intrusion set used a phishing attachment, then a Registry Run key for persistence, then encoded PowerShell to fetch a second stage. What should the hunter do first?",
        "options": [
          "Map each behavior to an ATT&CK technique ID and write a hypothesis for each",
          "Hunt on the narrative by searching mail logs for the phrase phishing happened",
          "Search every host for the malware family name that the report mentions",
          "Hold off until one of the behaviors finally triggers a SIEM alert"
        ],
        "answer": 0,
        "explanation": "The advisory decomposes into T1566.001, T1547.001, and T1059.001, and each of those IDs becomes its own mini-hunt with its own hypothesis. Searching mail logs for the narrative phrase is the mistake the lesson warns against, since the hunt should target the technique and its documented procedure. Searching for the malware family name chases an IOC-level detail unlikely to reappear unchanged, and holding off until a SIEM alert fires contradicts the proactive nature of hunting.",
        "xp": 15
      }
    ]
  },
  {
    "slug": "lp-query-languages",
    "title": "Threat Hunter · KQL & SPL",
    "description": "Knowledge check for the Learning Path module \"KQL & SPL\" (Threat Hunter path). Every question comes from these lessons: KQL: Joins and lookups, KQL: Aggregations, Entity baselining, Time series analysis.",
    "difficulty": "Intermediate",
    "category": "SIEM",
    "icon": "🧮",
    "estimatedMinutes": 12,
    "questions": [
      {
        "id": "lp-query-languages-q01",
        "question": "A hunter joins high-risk sign-ins (left) to DeviceProcessEvents (right) with kind=inner and sees only a handful of rows. Which statement is correct?",
        "options": [
          "The join returned every sign-in, so the sign-ins that are missing carried no risk at all",
          "Sign-ins with no endpoint match were silently dropped, and leftouter would have kept them with nulls",
          "Only the sign-ins with no endpoint match were returned, which is what inner is meant to show",
          "Missing sign-ins prove those accounts never touched an endpoint, so no further review is needed"
        ],
        "answer": 1,
        "explanation": "inner returns only rows that match on both sides, so risky sign-ins with no endpoint activity vanish, and leftouter would have kept them with null right-side columns so the absence itself is visible. The claim that the missing sign-ins carried no risk is wrong because the missing rows are exactly those that did not match. The claim that inner returns only the non-matches reverses inner, which returns matches. Concluding that those accounts never touched an endpoint is wrong because a sign-in with no device follow-up may point to a cloud-only or federated account that deserves its own investigation thread.",
        "xp": 20
      },
      {
        "id": "lp-query-languages-q02",
        "question": "A hunter must tag 2 million high-risk sign-in events with whether IPAddress appears on a 300-row known-malicious-IP watchlist, keeping every event even when there is no match. Which approach do the lessons favor?",
        "options": [
          "join kind=leftanti against the watchlist, which returns the details of each match",
          "externaldata against the watchlist, since the list is small enough to read directly",
          "join with the default kind, since defaults are optimized for enrichment",
          "lookup kind=leftouter against the watchlist, joined on its SearchKey column"
        ],
        "answer": 3,
        "explanation": "lookup is built for enriching a large fact table with a small, mostly static dimension table such as a watchlist, and kind=leftouter keeps every event with a null when there is no match. join kind=leftanti returns only left rows with no match and no right-side columns, so it cannot show match details. externaldata is for files that have not been ingested, and the watchlist already is. The default join kind is innerunique, which deduplicates left keys and drops unmatched rows.",
        "xp": 15
      },
      {
        "id": "lp-query-languages-q03",
        "question": "A hunter has a blob storage URL that includes a SAS token and wants to read the file once with externaldata for a single hunt. How should the URL string be written?",
        "options": [
          "Prefixed with h@ so Kusto redacts it from query history and logs",
          "Stored in a watchlist first, because externaldata cannot accept a URL",
          "Left as plain text, since Kusto already redacts every URL it receives",
          "Passed to a lookup operator, which hides credentials automatically"
        ],
        "answer": 0,
        "explanation": "A SAS token is a credential, and prefixing the string literal with h@ marks it as a secret so Kusto redacts it from stored query text and logs. Storing it in a watchlist first is unnecessary because externaldata is designed to read a URL directly without ingesting the file first. Leaving it as plain text would keep the credential in query history indefinitely, and the lookup operator enriches from an ingested table and has no role in hiding credentials.",
        "xp": 10
      },
      {
        "id": "lp-query-languages-q04",
        "question": "A hunter wants failed logon counts per account but writes summarize count() with no by clause. What does the query return?",
        "options": [
          "A syntax error that names the missing by clause",
          "One row per account with the count of its failed logons",
          "A single row counting the whole table, with no warning",
          "One row for every distinct timestamp found in the table"
        ],
        "answer": 2,
        "explanation": "Omitting the by clause does not raise an error; it silently collapses the entire table into one row, so the hunter gets one environment-wide number instead of a per-account result. The syntax error answer is wrong because no error is produced. One row per account is what summarize count() by Account would return, and one row per timestamp would require a by clause naming the timestamp.",
        "xp": 15
      },
      {
        "id": "lp-query-languages-q05",
        "question": "Two accounts both show count() = 30 failed logons over 30 days when grouped by account alone. One had them spread evenly across the month, and the other had all 30 within a single hour. Which change lets the query tell them apart?",
        "options": [
          "Replace count() with dcount(), which treats repeated failures as one",
          "Group by account and bin(TimeGenerated, 1h), then threshold each bucket",
          "Add arg_max(TimeGenerated, *) so only the latest failure per account is kept",
          "Remove the by clause so totals are compared across the whole table"
        ],
        "answer": 1,
        "explanation": "Grouping by both the account and a time bucket preserves timing, so 30 failures in one hour exceeds a per-bucket threshold while 30 spread over a month does not. Switching to dcount() would collapse repeated failures and hide the burst. arg_max(TimeGenerated, *) returns one latest row per account and discards the volume information, and removing the by clause collapses everything into a single row.",
        "xp": 20
      },
      {
        "id": "lp-query-languages-q06",
        "question": "Which expression returns, for each TargetUserName, the most recent logon event together with its IpAddress and LogonType columns?",
        "options": [
          "summarize arg_max(TimeGenerated) by TargetUserName",
          "summarize arg_min(TimeGenerated, *) by TargetUserName",
          "summarize dcount(TimeGenerated) by TargetUserName",
          "summarize arg_max(TimeGenerated, *) by TargetUserName"
        ],
        "answer": 3,
        "explanation": "arg_max with the asterisk returns the whole row where TimeGenerated is largest for each account, so the device, source IP, and logon type stay intact. arg_max(TimeGenerated) without the asterisk returns only the maximized timestamp and discards every other column. arg_min returns the oldest row rather than the latest, and dcount returns only a number of distinct values.",
        "xp": 15
      },
      {
        "id": "lp-query-languages-q07",
        "question": "A hunter builds a per-user baseline over the last 30 days up to now. One user has quietly doubled their activity during the past two weeks. What is the likely effect when today's activity is compared with that baseline?",
        "options": [
          "The escalation is absorbed into the baseline, so it looks normal and goes unflagged",
          "The join fails outright, because the baseline and recent windows overlap",
          "The percentile is recalculated for every row, so the flag fires twice as often",
          "The user is excluded automatically as a new account with no usable history"
        ],
        "answer": 0,
        "explanation": "Including the recent weeks in the baseline window poisons the baseline: it teaches the query that the escalation is normal, so the deviation is hidden. The lesson avoids this by leaving a gap, for example a baseline window that ends 7 days ago. The join does not fail on overlapping windows, percentile is computed per group rather than recalculated per row, and nothing in the lesson excludes an established user as a new account.",
        "xp": 20
      },
      {
        "id": "lp-query-languages-q08",
        "question": "Account A normally sends about 10 MB a day and account B about 400 MB. A rule flags anything over 500 MB. On one day account A sends 200 MB. How does the per-account approach, percentile(SentBytes, 95) by Account, compare with the fixed rule?",
        "options": [
          "Neither flags it, because 200 MB is below the fixed cutoff and below A's own p95",
          "Only the fixed rule flags it, since percentile baselines ignore single large days",
          "Only the per-account baseline flags it, since 200 MB far exceeds A's normal",
          "Both flag it, because a fixed rule and a percentile agree on large values like this"
        ],
        "answer": 2,
        "explanation": "A fixed 500 MB number treats every account identically, so it misses a 200 MB day for an account whose normal traffic is 10 MB. A per-account 95th percentile is the level that account's own traffic exceeds only 5 percent of the time, so 200 MB is far above A's normal and gets flagged. 'Neither flags it' is wrong because 200 MB is not below A's own p95, and 'only the fixed rule flags it' is wrong because the fixed rule cannot flag a value under its cutoff. 'Both flag it' is wrong because the two approaches measure against different thresholds.",
        "xp": 15
      },
      {
        "id": "lp-query-languages-q09",
        "question": "A host always spikes in process creation at 9 AM on workdays. After running series_decompose(), a separate burst of process creation appears at 3 AM. Where does the 3 AM burst show up?",
        "options": [
          "In the seasonal component, because every spike belongs to the daily cycle",
          "In the trend component, because a burst changes the slow underlying direction",
          "In the baseline component, because baseline is the average of all points",
          "In the residual component, because no seasonal pattern explains it"
        ],
        "answer": 3,
        "explanation": "The recurring 9 AM spike is absorbed into the seasonal component, which leaves the residual clean enough that a burst with no seasonal explanation stands out there. The 3 AM burst is not part of the repeating daily cycle, so it is not seasonal, and it is a short event rather than a slow shift in direction, so it is not trend. The baseline is seasonal plus trend, an expectation of normal rather than an average that would contain the anomaly.",
        "xp": 20
      },
      {
        "id": "lp-query-languages-q10",
        "question": "A team computed a decomposition model once on January data and never refreshed it. In October an attacker slowly escalates outbound volume and nothing alerts. What do the lessons recommend?",
        "options": [
          "Increase the make-series step to one day so slow changes are smoothed away",
          "Recompute make-series on a moving lookback window, such as the trailing 14 days",
          "Replace decomposition with a fixed threshold, since a fixed number does not drift",
          "Extend the baseline to include the attacker's recent weeks so they are captured"
        ],
        "answer": 1,
        "explanation": "A sliding window recomputes make-series on a moving lookback period refreshed on a schedule, so the comparison point stays recent while a sustained deviation can still cross the anomaly threshold. Increasing the step to one day smooths away patterns and makes drift harder to see. A fixed threshold is blind to slow cumulative drift, and pulling the attacker's weeks into the baseline is baseline poisoning, which teaches the model that the escalation is normal.",
        "xp": 15
      }
    ]
  },
  {
    "slug": "lp-sigma-and-detection",
    "title": "Threat Hunter · Sigma & Detection",
    "description": "Knowledge check for the Learning Path module \"Sigma & Detection\" (Threat Hunter path). Every question comes from these lessons: Sigma syntax basics, Backend conversion, Test data generation.",
    "difficulty": "Intermediate",
    "category": "Threat Detection",
    "icon": "🧪",
    "estimatedMinutes": 12,
    "questions": [
      {
        "id": "lp-sigma-and-detection-q01",
        "question": "A team wants to validate its detections against a chain of attacker actions that spans several hosts in one operation. Which test data source do the lessons say fits best?",
        "options": [
          "Atomic Red Team, because each atomic test mirrors an entire campaign",
          "splunk/attack_data, because it replays captured operations across live hosts",
          "MITRE CALDERA, because it automates multi-step, multi-host emulation operations",
          "Manually crafted fixtures, because they can simulate every host in a chain"
        ],
        "answer": 2,
        "explanation": "CALDERA runs chained abilities across deployed agents as part of an operation, which is what a multi-step, multi-host chain needs. Atomic Red Team tests are small, single-technique tests, so they do not mirror a whole campaign. splunk/attack_data is a collection of already-captured datasets organized by technique, not a live replay across hosts, and manually crafted fixtures are best for edge cases and clean negatives.",
        "xp": 15
      },
      {
        "id": "lp-sigma-and-detection-q02",
        "question": "A Sigma selection requires Image ending in powershell.exe, plus a CommandLine containing either -enc or -EncodedCommand (two values listed under one field). Which event matches?",
        "options": [
          "powershell.exe with a command line containing -EncodedCommand",
          "cmd.exe with a command line containing -enc or -EncodedCommand",
          "powershell.exe with a command line containing only -NoProfile",
          "powershell.exe launched with a command line field that is empty"
        ],
        "answer": 0,
        "explanation": "Fields in one selection map are combined with AND, and the two values under CommandLine are combined with OR, so the image must end in powershell.exe and the command line must contain at least one of the two listed flags. The cmd.exe event has the right flag but the wrong image, so the AND fails. The -NoProfile event and the empty command line event have the right image but neither listed flag, so the OR fails.",
        "xp": 15
      },
      {
        "id": "lp-sigma-and-detection-q03",
        "question": "A rule uses CommandLine|base64offset|contains with the value IEX to catch PowerShell -EncodedCommand payloads. It converts cleanly and passes sigma check, yet it never fires on a real encoded-PowerShell attack. What is missing?",
        "options": [
          "The windash modifier, because the dash in the flag is always replaced",
          "The re modifier, because encoded payloads need regular expressions",
          "A second selection identifier, because one identifier cannot hold base64",
          "The wide modifier before base64offset, to match UTF-16LE encoding"
        ],
        "answer": 3,
        "explanation": "PowerShell converts the script to UTF-16LE before base64 encoding it, so IEX appears as SQBFAFgA rather than the plain-text encoding that base64offset alone searches for. Adding wide ahead of base64offset fixes it, and sigma check cannot catch this because the YAML is structurally valid. The windash modifier only handles dash variants in flags, the re modifier is for regular expressions, and one identifier can hold base64 fragments without needing a second selection.",
        "xp": 20
      },
      {
        "id": "lp-sigma-and-detection-q04",
        "question": "Why does the module's example rule stay at category: process_creation and product: windows instead of adding service: sysmon?",
        "options": [
          "service is not a valid logsource sub-field, so it would fail validation",
          "It stays convertible against both Sysmon and native Windows auditing pipelines",
          "logsource itself translates field names, so extra detail would be redundant",
          "Sigma allows only one logsource sub-field to be used in any single rule"
        ],
        "answer": 1,
        "explanation": "Leaving the rule at category plus product lets a conversion pipeline decide the mapping, so the same YAML can target Sysmon Event ID 1 or native Windows auditing Event ID 4688. service is a valid logsource sub-field, and logsource does not translate field names itself, the pipeline does. Sigma allows category, product, and service to be combined as precisely as a rule needs, so the one-sub-field limit is invented.",
        "xp": 10
      },
      {
        "id": "lp-sigma-and-detection-q05",
        "question": "An analyst converts the module's rule with the sysmon pipeline and deploys it, but the environment ingests only native Windows Security events. The query runs without errors yet never matches anything. What is the most likely cause?",
        "options": [
          "The sysmon pipeline targeted fields and a table that native Security events lack",
          "The base64offset modifier only renders in SPL, so the KQL payload clause came out empty",
          "The logsource needs service: sysmon before any pipeline can map the rule's fields",
          "Native Security events log process creation as Event ID 1, which the query skips"
        ],
        "answer": 0,
        "explanation": "The sysmon pipeline maps the rule onto Sysmon-style fields and tables, so in an environment that ingests only native Windows Security events those fields stay unmapped and the query runs without error but never matches. The claim that base64offset only renders in SPL is wrong, because it converts for every target the lessons show, including KQL, where the payload clause holds the base64 variants. The rule's logsource is deliberately left without service: sysmon so it can be converted against several pipelines, and native Windows auditing records process creation as Event ID 4688, not Event ID 1, which is Sysmon's.",
        "xp": 20
      },
      {
        "id": "lp-sigma-and-detection-q06",
        "question": "A colleague reviews converted SPL and sees SQBFAFgA, kARQBYA, and JAEUAWA in the payload clause where the rule listed IEX. He wants to rewrite the clause with the plain word IEX. What is right?",
        "options": [
          "Rewrite it, because plain words match more reliably than base64 fragments do",
          "Rewrite it, because the backend corrupts payload values during conversion",
          "Leave it, because the modifiers turned IEX into the base64 variants it needs",
          "Leave it, because the splunk_windows pipeline rewrites values into Splunk format"
        ],
        "answer": 2,
        "explanation": "wide and base64offset turn each value into three base64 variants of its UTF-16LE form, one per byte alignment, so those fragments are the correct result. The plain word IEX would never match inside an encoded command, so rewriting the clause for either stated reason, reliability or backend corruption, would break the detection. Crediting the splunk_windows pipeline is wrong because a pipeline maps field names and tables, not rule values; the transformation here comes from the modifiers.",
        "xp": 20
      },
      {
        "id": "lp-sigma-and-detection-q07",
        "question": "A hunter wants one Elastic query for this behavior: a process spawns a second process, which then makes a network connection. Which conversion target fits best?",
        "options": [
          "lucene, because it has native support for multi-event sequences",
          "eql, because it natively expresses a sequence of related events",
          "esql, because it is the simplest target to read and debug",
          "splunk, because savedsearches output stores sequences natively"
        ],
        "answer": 1,
        "explanation": "eql is the Elastic target with native support for sequences of related events, which is what a spawn-then-connect chain is. lucene has no native multi-event sequences, and it is lucene, not esql, that is simplest to read and debug. Splunk is not an Elastic target, and the savedsearches format only changes how a Splunk search is packaged.",
        "xp": 15
      },
      {
        "id": "lp-sigma-and-detection-q08",
        "question": "Both fixtures use -EncodedCommand. The positive fixture fires the converted rule, and so does the negative fixture, whose payload decodes to unrelated text. What does this show?",
        "options": [
          "The rule works as intended, because both fixtures use the flag it targets",
          "The positive fixture is faulty, because it should not trigger the rule",
          "The rule has a false negative, because it also fires on the benign sample",
          "The rule is over-broad, because a look-alike negative also triggers it"
        ],
        "answer": 3,
        "explanation": "A negative fixture exists to prove the rule is not simply any PowerShell with an encoded command. If the look-alike with an unrelated payload still fires, the rule is over-broad and will produce false positives. Saying the rule works as intended is wrong because the flag alone should not be enough to trigger a well-written rule, and blaming the positive fixture points at the wrong fixture. Calling it a false negative uses the wrong term, since a false negative is a miss, not an extra match.",
        "xp": 20
      },
      {
        "id": "lp-sigma-and-detection-q09",
        "question": "A CI pipeline runs sigma check, then sigma convert for each target, then deploys to production alerting. According to the lessons, what is missing?",
        "options": [
          "A second sigma check after deployment, since conversion can invalidate the YAML",
          "Execution against the production index, so live events can serve as fixtures",
          "Loading fixtures into a test backend, then executing and asserting on results",
          "Manual approval by the rule author, which replaces the need for any testing"
        ],
        "answer": 2,
        "explanation": "A pipeline that stops at conversion has validated the rule but has not proven it detects anything, so it needs load, execute, and assert stages that fail the build when a positive does not fire or a negative does. A second sigma check after deployment does not test detection behavior. Executing against the production index risks polluting real data or triggering a real alert, which is why test backends are disposable or test-scoped, and manual author approval is not evidence that the rule works.",
        "xp": 15
      },
      {
        "id": "lp-sigma-and-detection-q10",
        "question": "A rule correctly detects encoded PowerShell, but its tags list only attack.execution and no technique tag. What is the consequence for coverage reporting?",
        "options": [
          "Per-technique coverage tooling cannot credit it, so the technique looks uncovered",
          "The rule fails sigma check, because a tags list must always contain a technique ID",
          "The rule stops firing, because the converter filters rules on technique tags",
          "The rule is credited to every technique listed under the Execution tactic"
        ],
        "answer": 0,
        "explanation": "Coverage tooling and ATT&CK Navigator heatmaps rely on technique tags to compute per-technique coverage, so a rule without one is invisible to that analysis even though its logic works. tags are optional, so sigma check does not require a technique ID, and tags do not affect whether the converted query fires. A tactic tag says what stage of an intrusion the rule relates to, not which individual techniques it covers, so the rule is not credited to every Execution technique.",
        "xp": 15
      }
    ]
  },
  {
    "slug": "lp-ir-lifecycle",
    "title": "Incident Responder · IR Lifecycle (NIST)",
    "description": "Knowledge check for the Learning Path module \"IR Lifecycle (NIST)\" (Incident Responder path). Every question comes from these lessons: IR phases overview, Detection & Analysis, Containment strategies, Eradication & recovery, Post-incident review, IR playbooks.",
    "difficulty": "Advanced",
    "category": "Incident Response",
    "icon": "🔥",
    "estimatedMinutes": 12,
    "questions": [
      {
        "id": "lp-ir-lifecycle-q01",
        "question": "While eradicating malware from a laptop, an analyst finds a second backdoor on a neighboring host that was never contained. How does the NIST SP 800-61 phase structure treat this situation?",
        "options": [
          "As a new incident that must restart the whole lifecycle from Preparation",
          "As a failure of Post-Incident Activity that the lessons-learned meeting must then fix",
          "As expected iteration inside one combined phase, so containment is expanded again",
          "As proof that PICERL's three separate steps are more accurate than NIST's model"
        ],
        "answer": 2,
        "explanation": "NIST treats Containment, Eradication, and Recovery as one iterative phase precisely because eradication work often reveals a wider foothold, so the team loops back and expands containment. It is not a new incident that restarts Preparation, and Post-Incident Activity comes after recovery rather than fixing gaps found mid-response. PICERL splits the steps for planning and reporting, but neither model is more correct; they describe the same discipline at different granularity.",
        "xp": 15
      },
      {
        "id": "lp-ir-lifecycle-q02",
        "question": "A SIEM correlation rule fires on six failed logons (Windows Event ID 4625) followed by one success (Event ID 4624) on a Domain Admin account. How should the analyst classify this signal?",
        "options": [
          "An indicator, so the team may already be behind and should triage and scope it",
          "A precursor, so there is still time to harden the account before anything happens",
          "A benign positive, because the successful logon shows the credential was authorized",
          "Routine event noise, because failed logons are common on busy admin accounts"
        ],
        "answer": 0,
        "explanation": "Failed-then-successful logons on a privileged account are the classic indicator pattern: a sign an incident may already be occurring, so the job is to work out what happened, how far it went, and how urgent it is. A precursor points to a future incident (a new CVE, a targeted-sector report, external reconnaissance), which would leave time to harden. A benign positive requires evidence of authorized activity, which a successful logon does not provide. Dismissing the pattern as routine noise skips triage of exactly the indicator the lesson names.",
        "xp": 15
      },
      {
        "id": "lp-ir-lifecycle-q03",
        "question": "A Splunk search on a confirmed malicious SHA-256 in Sysmon Event ID 1 returns three hosts, but the Incident Commander plans to isolate only the host named in the original alert. What is the main risk of acting on that narrow scope?",
        "options": [
          "The isolated host's EDR agent will lose contact with the platform and stop reporting back",
          "The hash pivot is invalid because Sysmon Event ID 1 does not record file hashes",
          "Isolation will power the host off and erase the volatile memory evidence on it",
          "Parallel footholds on the other two hosts stay active while the team declares victory"
        ],
        "answer": 3,
        "explanation": "Scope assessment exists because isolating too little leaves a parallel foothold active and undetected while the team believes the incident is handled. The other two hosts executing the same hash are exactly that. The claim that the EDR agent loses contact is wrong, because EDR isolation keeps a host reachable by its platform. The claim that Sysmon Event ID 1 does not record hashes is wrong, because it does record the file hash (the lesson's own pivot uses it), and the claim that isolation powers the host off and erases memory is wrong, because EDR isolation keeps the host powered on.",
        "xp": 20
      },
      {
        "id": "lp-ir-lifecycle-q04",
        "question": "A production batch job runs under a service account that the analyst has just confirmed is compromised. What is the best containment approach?",
        "options": [
          "Disable it at once and let the batch job fail, since speed outweighs continuity here",
          "Coordinate with the system owner, or restrict the account's allowed source IPs instead",
          "Reset the password only, because a new password also ends the account's active sessions",
          "Leave it untouched until the post-incident review decides who should own it"
        ],
        "answer": 1,
        "explanation": "Disabling a service account can break the production systems that depend on it, so containment usually means coordinating with the system owner (the IT/Infrastructure owner role) or using a narrower control such as restricting allowed source IPs. Disabling at once and accepting the outage ignores the business-continuity side of the containment tradeoff. A password reset alone does not end existing sessions or tokens, and a still-valid session token can outlive a password change. Waiting for the post-incident review leaves a confirmed compromise active, which breaks the rule to contain what is confirmed immediately.",
        "xp": 15
      },
      {
        "id": "lp-ir-lifecycle-q05",
        "question": "A domain controller shows confirmed compromise, and a manager wants a targeted clean to avoid downtime. A fresh EDR scan after the cleaning shows no detections. What does the module recommend?",
        "options": [
          "Reimage it, because high-trust systems are rebuilt rather than cleaned, even at higher cost",
          "Keep the clean, because a fresh EDR scan with no detections proves nothing is left behind",
          "Keep the clean, because a domain controller is too critical to take offline for a rebuild",
          "Reimage it only if the cyber-insurance policy happens to name domain controllers"
        ],
        "answer": 0,
        "explanation": "Domain controllers and certificate authorities carry outsized downstream trust, so the cost of an incomplete clean is far higher than the cost of a rebuild, and they are typically reimaged even at higher cost. A clean scan does not prove absence of a rootkit or an undiscovered foothold, which can hide from normal tools. Downtime on a critical, high-trust system is exactly the cost the lesson says is worth paying, because being wrong is more expensive. Insurance requirements are one possible driver of reimaging, not a condition for it.",
        "xp": 20
      },
      {
        "id": "lp-ir-lifecycle-q06",
        "question": "A draft postmortem lists 'the mail filter missed a newly registered domain' as the only root cause, although the eradication team found a shared local administrator password across the fleet. What is wrong with the draft?",
        "options": [
          "Nothing, because a postmortem should settle on one root cause for each incident",
          "The credential finding belongs only in the eradication ticket, not in the postmortem",
          "It stops early, so fixing only the filter leaves the shared password open for next time",
          "It should name the employee who clicked the phishing link as the single root cause"
        ],
        "answer": 2,
        "explanation": "Most real incidents have several independent contributing factors, and a thorough analysis lists all of them because fixing only one leaves the others available for the next incident. Here the filter gap and the reused local administrator credential both mattered. Settling on a single root cause is the failure mode the lesson warns against. The credential finding belongs in the postmortem because it shaped how far the incident spread. Naming the employee contradicts the blameless, systems-focused approach.",
        "xp": 15
      },
      {
        "id": "lp-ir-lifecycle-q07",
        "question": "After a Sev2 incident, a manager proposes grading each analyst on whether that one incident's time to contain beat the MTTC target. Which use of MTTD, MTTC, and MTTR does the module support?",
        "options": [
          "Use the single slowest incident as the permanent benchmark for the whole team",
          "Track them as trends across many incidents instead of grading any one incident",
          "Stop timestamping containment steps so the numbers cannot be used against analysts",
          "Replace them with the CISA Recoverability dimension, which already measures speed"
        ],
        "answer": 1,
        "explanation": "The metrics reveal whether tooling and process investments are paying off only when tracked over many incidents; judging a single incident against them pressures people to cut corners. A single slowest incident is not a meaningful benchmark. Stopping timestamping would break the containment log that the post-incident review depends on. CISA Recoverability describes the resources needed to recover, not the speed of detection or containment.",
        "xp": 10
      },
      {
        "id": "lp-ir-lifecycle-q08",
        "question": "While building a phishing playbook, an author drafts the step 'assess the scope and contain appropriately'. Which rewrite best follows the module's guidance on decision points?",
        "options": [
          "Add several paragraphs of prose explaining what appropriate containment means",
          "Expand the tree until it enumerates every conceivable variation of the scenario",
          "Delete the step and leave the judgment to whoever is on shift at the time",
          "Branch on checkable conditions such as recipient count and account privilege level"
        ],
        "answer": 3,
        "explanation": "Decision points work when they are tied to a few concrete, checkable conditions, so a responder at 2 a.m. can follow a branch instead of interpreting vague prose. More prose still gives almost no usable guidance. Enumerating every variation makes the tree as hard to follow as prose, which defeats its purpose. Leaving it to whoever is on shift is the improvisation that playbooks exist to remove; nuance beyond the tree belongs to the Incident Commander's escalation path.",
        "xp": 15
      },
      {
        "id": "lp-ir-lifecycle-q09",
        "question": "A Tier 1 analyst confirms a true positive showing ransomware note creation and file encryption activity on a file server. According to the typical escalation chain, what should happen next?",
        "options": [
          "Tier 1 declares the incident alone and immediately starts the lessons-learned clock",
          "Tier 1 holds the finding until the scope assessment is fully complete and reviewed",
          "Escalate to the on-call IC, whose formal declaration starts the response SLA clock",
          "Close it as a benign positive and queue a tuning request for the detection rule instead"
        ],
        "answer": 2,
        "explanation": "Ransomware activity matches the activation criteria, so the analyst escalates to the on-call Incident Commander (or Tier 2/3), and the IC's formal declaration starts the response SLA clock and pulls in the needed roles. Tier 1 does not declare alone, and the lessons-learned clock is unrelated. Holding the finding until scope is complete delays the response when speed matters most. Ransomware encryption is not authorized activity, so it cannot be a benign positive.",
        "xp": 15
      },
      {
        "id": "lp-ir-lifecycle-q10",
        "question": "Forty reimaged laptops have been validated clean, and the plan is to reconnect them all at once on Friday evening. Which recovery approach does the module recommend instead?",
        "options": [
          "Restore in phases, starting with the most critical clean systems, under close monitoring",
          "Reconnect everything at once so any reinfection is visible fleet-wide immediately",
          "Restore the lowest-value systems first so that any reinfection harms the business least",
          "Skip the monitoring window, since a freshly validated image cannot be reinfected"
        ],
        "answer": 0,
        "explanation": "Phased restoration reconnects the most business-critical, highest-confidence-clean systems first under close monitoring, so a reinfection or hidden foothold surfaces on a small, watched population. Reconnecting everything at once exposes the whole restored fleet if something was missed. Starting with the lowest-value systems reverses the recommended order. Skipping monitoring is wrong because evidence can be incomplete and a dormant backdoor may reactivate after hosts return.",
        "xp": 10
      }
    ]
  },
  {
    "slug": "lp-forensics-101",
    "title": "Incident Responder · Forensics 101",
    "description": "Knowledge check for the Learning Path module \"Forensics 101\" (Incident Responder path). Every question comes from these lessons: Triage acquisition, Timeline analysis, Memory forensics basics.",
    "difficulty": "Advanced",
    "category": "Forensics",
    "icon": "🧬",
    "estimatedMinutes": 12,
    "questions": [
      {
        "id": "lp-forensics-101-q01",
        "question": "An EDR alert shows process injection on a production database server that must keep running a finance batch job overnight. What should the responder do in the first minutes?",
        "options": [
          "Pull the power cord immediately so the attacker loses access, then image the disk",
          "Isolate the host at the network layer and leave it powered on so memory stays intact",
          "Wait until the batch window closes before starting any collection or isolation",
          "Reimage the server from a known-good backup to remove the injected code at once"
        ],
        "answer": 1,
        "explanation": "Network-layer isolation cuts the attacker's C2 channel while the system and its memory stay intact, which fits both the volatility priorities and the business constraint. Pulling the power throws away everything above data on disk, including the injected code in memory and active connections. Waiting for the batch window leaves C2 open while volatile data decays. Reimaging destroys the evidence before any of it has been collected.",
        "xp": 15
      },
      {
        "id": "lp-forensics-101-q02",
        "question": "Volatility 3 output for a memory image of WKS-207 shows: windows.pstree lists winword.exe (PID 2760) as the parent of powershell.exe (PID 4412); windows.malfind flags PID 4412 with a PAGE_EXECUTE_READWRITE region and an MZ header; windows.netscan shows PID 4412 ESTABLISHED to 198.51.100.23:443; windows.handles for PID 4412 shows no handle to LSASS. What is the most time-critical response?",
        "options": [
          "Reset every domain credential first, because LSASS must already have been dumped",
          "Close it as a false positive, because a malfind hit alone is never proof",
          "Image the disk first and leave the network connection open until it finishes",
          "Sever the C2 channel and eradicate the injected code, with credential reset less urgent"
        ],
        "answer": 3,
        "explanation": "An unbacked RWX region with an MZ header, a Word-to-PowerShell lineage, and an established outbound connection together support injection with active command and control, while the absence of an LSASS handle means credential theft is not confirmed at the moment of acquisition. Severing C2 and eradicating the injected code is therefore the priority. Resetting everything first assumes credential theft the evidence does not show. A malfind hit is a strong indicator, and here follow-up evidence confirms it. Leaving a live C2 connection open while imaging the disk ignores the fast-changing state.",
        "xp": 20
      },
      {
        "id": "lp-forensics-101-q03",
        "question": "A firewall log (UTC) records an outbound connection to 198.51.100.23 at 06:14:30. The workstation's EDR console, set to local time (UTC+3), shows powershell.exe launching at 09:14:20. How should the analyst read these two events?",
        "options": [
          "As near-simultaneous: once both are normalized to UTC they are about ten seconds apart",
          "As three hours apart, so the connection cannot have come from that process launch at all",
          "As proof that the workstation clock was tampered with, since the times differ",
          "As uncorrelatable until NTP logs prove which of the two clocks was accurate"
        ],
        "answer": 0,
        "explanation": "Normalizing 09:14:20 local time (UTC+3) gives 06:14:20 UTC, ten seconds before the firewall connection, which is a plausible causal sequence. Reading the raw clock values as three hours apart is exactly the false narrative that skipped normalization creates. A timezone offset is not evidence of tampering. NTP cross-checks are for residual clock skew that remains after normalization, and nothing here suggests skew.",
        "xp": 15
      },
      {
        "id": "lp-forensics-101-q04",
        "question": "A file named svchost32.exe in a user's temp folder shows a Birth time of 2019-03-12, matching the OS install date. The $UsnJrnl records a file-create entry for it at 2026-03-11 22:47 UTC. What does this most likely mean?",
        "options": [
          "The journal is unreliable, because a file's own timestamps are the authoritative record of creation",
          "The file was copied from another volume, which preserved its original Modified time",
          "The file's timestamps were backdated, and the journal shows the real creation time",
          "A parser gap in plaso produced the journal entry, so the file's own dates still stand"
        ],
        "answer": 2,
        "explanation": "The $UsnJrnl records the actual sequence of filesystem operations and is much harder to backdate than a file's own MACB fields, so a recent create entry contradicting an old Birth time points to timestomping (T1070.006). A copy from another volume would give a new Birth time and an old Modified time, not an old Birth time. Reversing the trust order is the opposite of the lesson. Parser gaps produce missing events, not extra conflicting ones.",
        "xp": 20
      },
      {
        "id": "lp-forensics-101-q05",
        "question": "An examiner captures RAM with WinPmem, copies the image to a shared analysis server, and only then computes its SHA-256 hash. What is the problem with this sequence?",
        "options": [
          "MD5 should have been used, since SHA-256 hashes are not accepted for memory images",
          "RAM images cannot be hashed at all, because memory keeps changing after capture",
          "The image should have been hashed before acquisition so it could be compared after",
          "Hashing after the copy weakens the argument that the copy matches the original"
        ],
        "answer": 3,
        "explanation": "The hash is the evidence's fingerprint, so it must be computed the moment the image finishes writing and recorded in the custody log before any copy, otherwise the copy's match to the original is harder to defend. SHA-256 is the standard choice, with MD5 only recorded sometimes for legacy compatibility. The captured image is an ordinary file and can be hashed. Live RAM cannot be hashed before it is acquired, so the pre-acquisition comparison applies to disks, not to this memory image.",
        "xp": 15
      },
      {
        "id": "lp-forensics-101-q06",
        "question": "An examiner is about to run Volatility 3 on host01_memory.raw, which sits in the chain-of-custody evidence store. What is the correct handling?",
        "options": [
          "Run it against a copy and keep the original untouched in the evidence store",
          "Run it against the original, because Volatility never modifies a memory image",
          "Run it against the original only after re-hashing it to confirm its integrity",
          "Run it against whichever file is faster to reach, as long as the work is logged"
        ],
        "answer": 0,
        "explanation": "Analysis belongs on a copy so the original stays untouched for re-analysis or independent verification, the same rule that applies to disk images. Assuming the tool is harmless, or re-hashing before touching the original, still puts the evidence at risk and breaks the working-copy rule. Choosing a file for convenience ignores the rule entirely, and logging does not replace it.",
        "xp": 15
      },
      {
        "id": "lp-forensics-101-q07",
        "question": "You are handed host01_memory.raw with no notes about the Windows build it came from. Which command should you run first?",
        "options": [
          "python vol.py -f host01_memory.raw windows.malfind",
          "python vol.py -f host01_memory.raw windows.info",
          "python vol.py -f host01_memory.raw windows.hashdump",
          "python vol.py -f host01_memory.raw windows.netscan"
        ],
        "answer": 1,
        "explanation": "windows.info confirms the operating system and build the image represents, which determines the symbol table and which plugins are relevant, so it is the sensible first step. windows.malfind belongs to the injection-scanning step after the process survey. windows.hashdump is a credential step reserved for suspected credential theft. windows.netscan checks network activity for processes already flagged earlier in the workflow.",
        "xp": 15
      },
      {
        "id": "lp-forensics-101-q08",
        "question": "windows.malfind flags a PAGE_EXECUTE_READWRITE region with no backing file inside the process of a developer's IDE that runs a JIT runtime. The hex preview shows no MZ header. What is the best next step?",
        "options": [
          "Close the finding as a false positive, since legitimate JIT compilers sometimes allocate RWX memory",
          "Declare the host compromised, because any writable-executable region proves injection",
          "Treat it as a lead: examine the region and pull cmdline, dlllist, and netscan for that PID",
          "Ignore it unless windows.psscan finds the process and windows.pslist does not list it"
        ],
        "answer": 2,
        "explanation": "A malfind hit is a strong indicator but not automatic proof, because some legitimate software such as certain JIT compilers can also allocate RWX memory. The right move is follow-up: inspect the region and gather command line, loaded modules, and network context before deciding. Closing it at once or declaring compromise at once both treat the hit as a verdict. The pslist versus psscan comparison finds hidden processes and is a separate question from whether injected code exists.",
        "xp": 20
      },
      {
        "id": "lp-forensics-101-q09",
        "question": "A responder runs netstat -ano from the suspect host's own System32 folder and saves the output to C:\\triage on the same disk. What does the lesson say to change?",
        "options": [
          "Run trusted tools from read-only media, write the output to external storage, and hash it",
          "Skip network collection, since a later disk image will record those connections anyway",
          "Image the disk first and collect the network connections at the end of triage",
          "Keep the output in C:\\triage but compress it so it takes less space on the source disk"
        ],
        "answer": 0,
        "explanation": "Live triage should run trusted tools from read-only media, never the host's own possibly replaced binaries, write output to external storage rather than the source disk, and hash every output file immediately. Network connections are volatile and are lost rather than preserved on disk, so skipping network collection in favor of a later disk image throws that evidence away. Imaging the disk first is also wrong, because fast-changing state such as network connections should be captured first and a C2 connection may be gone by the time a disk image finishes. Compressing the output in C:\\triage still lands it on the source disk, which the lesson says never to write to.",
        "xp": 15
      },
      {
        "id": "lp-forensics-101-q10",
        "question": "A plaso timeline of a workstation holds about three million rows. The phishing email was delivered at 09:05 UTC on 2026-03-10. How should the analyst start narrowing it?",
        "options": [
          "Keyword-search every indicator across the whole unfiltered file and read the hits top to bottom",
          "Bracket a date range around the delivery time first, then narrow by source type and pivot",
          "Export every row to a spreadsheet and scroll chronologically from the first row",
          "Filter to registry events only, so persistence changes are reviewed before anything else"
        ],
        "answer": 1,
        "explanation": "Bracketing the known incident window is the single biggest way to cut timeline noise, and the layered order is then source type, keyword pivots, and tight reading around each pivot. Searching the unfiltered file and reading hits top to bottom skips the biggest reduction. Scrolling a multi-million-row spreadsheet is noise, not analysis. Filtering to registry events first skips the time-window step and assumes persistence is the question, when the source-type filter should follow the question being asked.",
        "xp": 15
      }
    ]
  },
  {
    "slug": "lp-comms-and-reporting",
    "title": "Incident Responder · Comms & Reporting",
    "description": "Knowledge check for the Learning Path module \"Comms & Reporting\" (Incident Responder path). Every question comes from these lessons: Exec briefings, Customer notifications, Postmortems.",
    "difficulty": "Advanced",
    "category": "Incident Response",
    "icon": "📣",
    "estimatedMinutes": 12,
    "questions": [
      {
        "id": "lp-comms-and-reporting-q01",
        "question": "NexaCorp's SOC detected ransomware on three finance servers 30 minutes ago and has contained it. Which opening line best follows the BLUF principle for the CEO briefing?",
        "options": [
          "At 02:14 UTC EDR flagged winword.exe spawning powershell.exe on a finance workstation.",
          "We are confident the incident will be fully resolved well before the end of the day.",
          "Ransomware is contained on three finance servers and no customer data exposure is confirmed.",
          "The full technical timeline and the registry keys involved are attached below for review."
        ],
        "answer": 2,
        "explanation": "BLUF leads with the most important conclusion: the current status and whether impact is confirmed. Opening with the detection narrative buries the lede behind background. Promising full resolution by the end of the day over-promises before scope is confirmed and risks credibility. Leading with raw technical timeline and registry keys is excessive detail for an executive audience.",
        "xp": 15
      },
      {
        "id": "lp-comms-and-reporting-q02",
        "question": "On Monday at 09:00 UTC an analyst confirms that a compromised service account read a database holding EU customers' personal data. The intrusion began three weeks earlier, and full scoping will take another week. When should the analyst tell the legal and privacy teams?",
        "options": [
          "Immediately, because the 72-hour clock runs from awareness and may already be running",
          "After scoping finishes, so legal receives a complete and final set of facts",
          "Never, since three weeks after the intrusion began is too late for the 72-hour rule",
          "After the affected customers have been notified, so legal can review the final draft letter"
        ],
        "answer": 0,
        "explanation": "GDPR Article 33's clock starts when the organization becomes aware of the breach, not when it began, so confirming plausible personal data involvement is the trigger to reach legal and privacy teams at once. Waiting for complete scoping can burn the 72-hour window. The three-week gap since the intrusion start is irrelevant to when the clock starts. Notifying customers first inverts the process: individual notice under Article 34 applies only to high-risk breaches and is decided by legal and privacy, not drafted by the analyst.",
        "xp": 20
      },
      {
        "id": "lp-comms-and-reporting-q03",
        "question": "A draft postmortem says: 'The on-call analyst was careless and missed the 03:12 alert.' Which rewrite best fits a blameless postmortem?",
        "options": [
          "The on-call analyst missed the alert and has been asked to complete extra triage training.",
          "Nobody is accountable for the miss, so no follow-up action will be recorded.",
          "The analyst's shift record is attached so that leadership can judge the miss.",
          "What about our alert volume, triage process, or tooling made the 03:12 alert easy to miss?"
        ],
        "answer": 3,
        "explanation": "A blameless framing asks what about alert volume, triage process, tooling, or training made it likely that any analyst in that position would miss the alert, which points toward a real fix. Extra training for one person is still person-focused and is a vague catch-all. Blameless does not mean accountability-free, so recording no follow-up is wrong. Attaching a shift record turns the postmortem into a performance review, which it is not.",
        "xp": 15
      },
      {
        "id": "lp-comms-and-reporting-q04",
        "question": "In the first briefing the scope is unknown, but a responder suspects up to 12,000 customer email addresses were taken. A colleague suggests calling it 'a minor issue' to keep everyone calm. What should the responder do?",
        "options": [
          "Agree, and issue a correction later if the scope turns out to be larger",
          "Report the confirmed facts and the uncertainty plainly, even if the news is unwelcome",
          "Say nothing until the investigation is complete and every number is certain",
          "Send the full technical timeline instead, so executives can judge for themselves later"
        ],
        "answer": 1,
        "explanation": "Accurate framing delivered calmly serves the audience better than a falsely reassuring one, because downplaying impact can create legal and ethical exposure when executives make regulatory or customer-facing decisions on a wrong picture. Agreeing and correcting later is exactly that downplaying. Silence is wrong because 'we are still assessing scope' is a legitimate, honest bottom line. A raw technical timeline is excessive detail that obscures the message.",
        "xp": 15
      },
      {
        "id": "lp-comms-and-reporting-q05",
        "question": "A breach affects customers in the EU and in three US states. The response lead proposes tracking one combined notification deadline. What does the module say about that approach?",
        "options": [
          "It works, provided the team follows the longest and most lenient framework's timeline",
          "It works, provided the team applies the 72-hour GDPR deadline to every notification",
          "It fails; each framework needs its own clock, trigger, deadline, and recipients",
          "It works, because US state laws and GDPR share one trigger and one deadline"
        ],
        "answer": 2,
        "explanation": "A multi-jurisdiction incident runs multiple independent clocks, each started by the trigger in its own framework, so each needs its own tracked deadline and recipients. Defaulting to the most lenient timeline risks missing a shorter deadline, applying the strictest everywhere wastes response capacity, and the frameworks do not share one trigger or deadline (GDPR uses a 72-hour target from awareness, US states commonly use expedient-notice language that varies).",
        "xp": 15
      },
      {
        "id": "lp-comms-and-reporting-q06",
        "question": "A postmortem action item reads: 'Tune the PowerShell detection rule. Owner: Detection Engineering team. Due: 2026-04-15.' What should be changed?",
        "options": [
          "Assign it to the whole SOC so that everyone feels responsible for the result",
          "Replace the team name with one named individual who drives the item to completion",
          "Remove the due date, because deadlines discourage honest discussion in the postmortem",
          "Move it out of the tracking system and into the meeting notes for visibility"
        ],
        "answer": 1,
        "explanation": "Every action item needs exactly one named owner, because a team name diffuses accountability until nobody in particular feels responsible. Assigning it to the whole SOC diffuses it even further. The due date is correct, since SMART items are time-bound. Action items belong in a tracked system with leadership visibility, not buried in meeting notes.",
        "xp": 15
      },
      {
        "id": "lp-comms-and-reporting-q07",
        "question": "An analyst confirms that customer personal data above the agreed threshold was exposed and is unsure whether to brief the board. What does the module suggest the team rely on?",
        "options": [
          "Pre-agreed escalation triggers, such as confirmed customer data exposure",
          "A judgment call made under pressure about whether the incident feels board-worthy",
          "A rule that every incident must reach the board, so that nothing is ever missed",
          "Waiting for the next scheduled postmortem to decide who should have been told"
        ],
        "answer": 0,
        "explanation": "Confirmed customer data exposure above a threshold is one of the pre-agreed escalation triggers, so the team escalates consistently without a judgment call. Relying on a feeling under pressure is the failure the triggers are meant to prevent. Escalating everything creates noise that drowns out genuinely board-worthy incidents. A postmortem happens after resolution, far too late for an active escalation decision.",
        "xp": 15
      },
      {
        "id": "lp-comms-and-reporting-q08",
        "question": "The exfiltrated database backup was encrypted. Which technical fact should the analyst establish for legal, because it most affects whether the notification obligation could be reduced or removed?",
        "options": [
          "Whether the SIEM rated the original alert as High severity or Critical",
          "Whether all of the affected customers live in a single US state",
          "Whether the incident was already escalated to the executive team",
          "Whether anything suggests the encryption key was also compromised"
        ],
        "answer": 3,
        "explanation": "Many frameworks reduce or remove the notification obligation when data was properly encrypted and the key was not exposed, so whether the key was also compromised is the decisive technical fact. Alert severity and internal escalation status describe the response, not the exposure. A single-state footprint narrows which laws apply but does not by itself reduce the obligation the way properly protected encryption can.",
        "xp": 20
      },
      {
        "id": "lp-comms-and-reporting-q09",
        "question": "Over a year, three separate incidents trace back to the same unpatched VPN appliance, even though an earlier postmortem produced an action item to patch it. Which postmortem metric does this pattern illustrate, and what should the team check?",
        "options": [
          "Higher MTTD, so the detection rules need retuning before anything else is checked",
          "A single outlier skewing the average, so the team should ignore the pattern for now",
          "Recurrence rate, so check whether the old action item was done and fixed the root cause",
          "MTTR, so the team should focus on speeding up containment of future VPN incidents"
        ],
        "answer": 2,
        "explanation": "Recurrence rate tracks whether the same or similar root causes keep appearing, which suggests earlier action items either were not completed or did not address the real root cause, so those items are the first thing to check. MTTD and MTTR measure detection and response speed, not repeated causes. Three incidents from one cause is a pattern, not a single outlier skewing an average.",
        "xp": 20
      },
      {
        "id": "lp-comms-and-reporting-q10",
        "question": "A draft postmortem notes that an incident was contained only because an unrelated maintenance window had already isolated the affected network segment. Where should this observation go, and why?",
        "options": [
          "Under Where we got lucky, because it exposes a gap a future incident may not escape",
          "Under What went well, because the segment did end up isolated before damage spread",
          "Nowhere, because nothing worse happened, so there is nothing to document in the report",
          "Under What went poorly, because the response team must have been too slow to act"
        ],
        "answer": 0,
        "explanation": "Containment that depended on an unrelated maintenance window reveals a genuine gap the next incident may hit without the same lucky circumstance, which is exactly what the Where we got lucky section surfaces. Listing it as what went well would reinforce something that did not actually come from the response. Omitting it because no harm occurred discards the most valuable insight. Nothing in the situation shows the team was slow, so What went poorly is unsupported.",
        "xp": 20
      }
    ]
  },
  {
    "slug": "lp-sigma-mastery",
    "title": "Detection Engineer · Sigma Mastery",
    "description": "Knowledge check for the Learning Path module \"Sigma Mastery\" (Detection Engineer path). Every question comes from these lessons: Sigma selection patterns, Sigma modifiers, Coverage testing.",
    "difficulty": "Advanced",
    "category": "Threat Detection",
    "icon": "📐",
    "estimatedMinutes": 12,
    "questions": [
      {
        "id": "lp-sigma-mastery-q01",
        "question": "A rule's selection requires ParentImage to end with winword.exe and lists three values for Image: powershell.exe, cmd.exe and wscript.exe. An event arrives with ParentImage ending in explorer.exe and Image ending in powershell.exe. What does the selection do with this event?",
        "options": [
          "It matches, because one of the three listed Image values is present",
          "It does not match, because the ParentImage field fails and fields are ANDed",
          "It matches, because values on different fields are combined with OR",
          "It does not match, because powershell.exe must appear with cmd.exe"
        ],
        "answer": 1,
        "explanation": "Different fields inside one selection are ANDed, so ParentImage must match its target and Image must match one of the listed values. Here ParentImage fails, so the whole selection fails. Saying it matches because one Image value is present ignores the AND between fields, saying values on different fields are ORed is simply wrong, and requiring powershell.exe to appear with cmd.exe invents a rule that listed Image values must all appear together (a list on one field is ORed).",
        "xp": 15
      },
      {
        "id": "lp-sigma-mastery-q02",
        "question": "A rule defines selection_a, selection_b and selection_c, and its condition is 'all of selection*'. An event satisfies selection_a and selection_c but not selection_b. What happens, and what would '1 of selection*' have done?",
        "options": [
          "The alert fires, because two of three blocks counts as a majority",
          "The alert fires, because 'all of selection*' means OR across the group",
          "No alert, and '1 of selection*' would also have stayed silent",
          "No alert, but '1 of selection*' would have fired on this event"
        ],
        "answer": 3,
        "explanation": "'all of selection*' is AND across the group, so one failing block (selection_b) means no alert. '1 of selection*' is OR across the group, so a single matching block is enough and it would have fired. The 'two of three is a majority' answer invents a majority rule, the claim that 'all of selection*' means OR swaps the meanings of the two shorthands, and the claim that '1 of selection*' would also stay silent is wrong because OR across the group needs only one match.",
        "xp": 15
      },
      {
        "id": "lp-sigma-mastery-q03",
        "question": "A rule excludes NexaCorp's patch agent with a filter that matches only Image ending in agent.exe. What is the main risk of building the filter this way, and what makes it stronger?",
        "options": [
          "Malware named agent.exe inherits the exclusion; add path, parent and a hash",
          "The filter fails sigma check, because every filter must carry a file hash value",
          "The rule alerts twice per event, because filters duplicate the selection",
          "The condition ignores filter blocks, so only a second rule can exclude it"
        ],
        "answer": 0,
        "explanation": "A single-field filter can silently blind the rule if an attacker names a malicious binary like the excluded tool. Strong filters combine path, parent process and ideally a file hash so the exception only matches the real agent. The claim that sigma check requires a hash in every filter is invented, the claim that filters cause duplicate alerts is invented, and the claim that the condition ignores filter blocks is wrong because 'selection and not filter' is exactly how filters are applied.",
        "xp": 20
      },
      {
        "id": "lp-sigma-mastery-q04",
        "question": "A rule matches Image equal to the full 64-bit Program Files path of a vendor tool. On some hosts the same tool is installed under Program Files (x86) and the rule never fires there. Which change follows the module's guidance?",
        "options": [
          "Duplicate the rule once for every host that uses a different directory",
          "Lower the level field so the missed hosts matter less in the queue",
          "Match the distinctive path suffix with endswith or contains instead",
          "Switch the logsource product to linux so both paths are covered"
        ],
        "answer": 2,
        "explanation": "Hard-coded literal paths miss the x86 and per-user install variants, so the lesson recommends contains or endswith on the distinctive suffix. Duplicating the rule per host creates drifting copies, lowering the level changes severity without fixing the miss, and switching the logsource product to linux would point the rule at the wrong platform entirely.",
        "xp": 15
      },
      {
        "id": "lp-sigma-mastery-q05",
        "question": "A rule uses the selection ServiceName|re: '^svc(update|helper)[0-9]{2,4}$' and never fires on a malware service named SVCUpdate42. What is the most likely cause and the fix?",
        "options": [
          "Regex anchors are unsupported, so replace re with contains",
          "Regex is case-sensitive by default, so add the i flag as re|i",
          "The s flag is required whenever a value contains digits",
          "Service names are never logged, so use the exists modifier"
        ],
        "answer": 1,
        "explanation": "The pattern is written in lowercase and regex matching is case-sensitive by default, so SVCUpdate42 does not match. Adding the i flag (re|i) makes it case-insensitive. Replacing re with contains is wrong because anchors are a core re feature, the s flag answer confuses the dotall flag with digit handling, and the exists answer invents a logging claim and misuses exists, which only checks presence.",
        "xp": 15
      },
      {
        "id": "lp-sigma-mastery-q06",
        "question": "A hunter writes CommandLine|base64offset|contains: 'Net.WebClient' to catch encoded PowerShell, but it never fires on a confirmed malicious -EncodedCommand sample. What is missing?",
        "options": [
          "The windash modifier, because the encoded payload contains dash characters",
          "The cased modifier, because base64 text is always treated as case-sensitive",
          "The fieldref modifier, to compare the encoded payload with ParentImage",
          "The wide modifier first, since PowerShell encodes to UTF-16LE before base64"
        ],
        "answer": 3,
        "explanation": "PowerShell converts the script to UTF-16LE before base64-encoding it, so the value must go through wide before base64offset (wide|base64offset). Without it the precomputed variants are of the plain-text form and never appear in a real encoded command. windash only helps with the flag, not the payload; cased and fieldref do not address encoding at all.",
        "xp": 20
      },
      {
        "id": "lp-sigma-mastery-q07",
        "question": "An analyst pastes the Sigma selection Image|endswith: 'powershell.exe' into a Microsoft Defender Advanced Hunting query as a filter on a column called Image and gets an unknown-column error. What explains this?",
        "options": [
          "Image is a Sigma generic name; a pipeline maps it to FolderPath and FileName",
          "Defender stores no process data at all, so no field could ever match it here",
          "The endswith modifier is unsupported by backends, so only contains can be used",
          "Sigma field names must be written in lowercase before KQL can accept them"
        ],
        "answer": 0,
        "explanation": "Image belongs to Sigma's generic taxonomy, not to any product schema. A pySigma pipeline translates it, and in Defender one Sigma field can become more than one real field (FolderPath and FileName). The claim that Defender stores no process data is false because Defender exposes process events, the claim that backends cannot convert endswith is false because it is a standard modifier, and the lowercase requirement invents a casing rule.",
        "xp": 15
      },
      {
        "id": "lp-sigma-mastery-q08",
        "question": "A new LSASS rule matches all three malicious samples in the test corpus, but it also fires on a benign sample where WerFault.exe opens lsass.exe after a crash. What is the correct verdict and next step?",
        "options": [
          "Pass, because matching every malicious sample is the only requirement",
          "Fail, because the selection must be broadened so more samples match",
          "Fail, because it must be tightened or filtered for the benign case, then retested",
          "Pass, because benign samples are only checked after production rollout"
        ],
        "answer": 2,
        "explanation": "A rule passes local testing only when it matches every positive sample and none of the negative ones. Matching a negative sample means the selection needs tightening or a filter (such as one for WerFault.exe), followed by a retest. Both 'Pass' verdicts ignore the negative-sample requirement, and broadening the selection applies the fix for the opposite problem, since broadening is for a rule that misses positive samples.",
        "xp": 15
      },
      {
        "id": "lp-sigma-mastery-q09",
        "question": "A team has written and tagged a rule for T1003.001 and it passes sigma check, but it has never been run against any sample or live telemetry. Where does the technique sit on the lab's ordinal coverage scale?",
        "options": [
          "0, no coverage, because the rule has never run on live telemetry",
          "1, a rule exists and is tagged but remains unvalidated",
          "2, validated and deployed, because sigma check passed",
          "3, confirmed, because the rule carries an ATT&CK tag"
        ],
        "answer": 1,
        "explanation": "Score 1 is a rule that has been written and tagged but not tested against real telemetry. Score 0 is wrong because a rule does exist, score 2 is wrong because sigma check validates syntax only and says nothing about matching real data, and score 3 is wrong because a tag does not confirm detection; level 3 needs live telemetry or a purple-team exercise.",
        "xp": 15
      },
      {
        "id": "lp-sigma-mastery-q10",
        "question": "An engineer proposes writing a Sigma rule for a technique shown as uncovered on the heatmap, but the organization has no log source that would ever record that behavior. What should happen first?",
        "options": [
          "Write the rule anyway and mark it validated once sigma check passes",
          "Tag the technique as covered by a related rule to keep the heatmap green",
          "Export the gap to STIX so another tool can detect the behavior instead",
          "Log it as a telemetry gap, since no rule can close it without a source"
        ],
        "answer": 3,
        "explanation": "A rule cannot detect behavior that no telemetry source records, so the gap needs a telemetry investment first. Writing the rule anyway and marking it validated creates false confidence, tagging the technique as covered by a related rule misreports coverage (and green only means tested against available samples), and exporting the gap to STIX misunderstands sigma2stix, which only converts existing rule tags into a machine-readable format.",
        "xp": 20
      }
    ]
  },
  {
    "slug": "lp-telemetry-sources",
    "title": "Detection Engineer · Telemetry Sources",
    "description": "Knowledge check for the Learning Path module \"Telemetry Sources\" (Detection Engineer path). Every question comes from these lessons: EDR vs Sysmon, O365 Unified Audit Log, CloudTrail for detection.",
    "difficulty": "Advanced",
    "category": "Log Analysis",
    "icon": "📡",
    "estimatedMinutes": 12,
    "questions": [
      {
        "id": "lp-telemetry-sources-q01",
        "question": "A new administrator installs Sysmon on every endpoint but deploys no configuration file. Weeks later the SOC finds almost nothing useful in the Sysmon channel. What explains this?",
        "options": [
          "Sysmon only starts logging once an EDR agent is installed on the same host",
          "Sysmon writes to the Security channel, which the SOC never collected",
          "With no configuration Sysmon logs very little; the XML file sets what is captured",
          "Sysmon needs a cloud analytics backend before it can record process creation"
        ],
        "answer": 2,
        "explanation": "Sysmon out of the box with no configuration logs very little of value, because the XML configuration file determines what is captured. The idea that it needs an EDR agent first is wrong since Sysmon runs independently of any EDR, the Security channel claim is wrong because it logs to its own Microsoft-Windows-Sysmon/Operational channel, and the cloud backend claim confuses Sysmon with an EDR, whose cloud backend is what Sysmon lacks.",
        "xp": 15
      },
      {
        "id": "lp-telemetry-sources-q02",
        "question": "A threat hunter needs value-level registry changes on workstations, including changes that never triggered any detection. The fleet has a licensed EDR agent and no Sysmon. What is the most relevant limitation?",
        "options": [
          "The EDR may forward only detection-tied changes; Sysmon can capture it all",
          "Registry activity is never recorded by any Windows telemetry source at all",
          "EDR agents record every registry write but keep it for only 24 hours",
          "Registry events are Sysmon Event ID 1, which an EDR agent cannot read"
        ],
        "answer": 0,
        "explanation": "Some EDR agents throttle or summarize high-volume registry telemetry and forward only changes tied to a detection, whereas Sysmon's RegistryEvent IDs can be configured to capture the full raw stream. The claim that no Windows source records registry activity is false because Sysmon records registry events, the 24-hour retention limit is invented, and the Event ID 1 answer is wrong because Event ID 1 is Process Creation, not registry activity.",
        "xp": 15
      },
      {
        "id": "lp-telemetry-sources-q03",
        "question": "A rule was validated against Sysmon data and then converted through a pySigma pipeline for Microsoft Defender for Endpoint. The team wants to deploy it to both sources. What should happen before deployment?",
        "options": [
          "Nothing more, since a successful conversion proves identical behavior",
          "Re-run it only on the Sysmon data it was first validated on",
          "Rewrite it by hand in KQL and discard the original Sigma source",
          "Test it on every deployed backend, since field mappings can differ"
        ],
        "answer": 3,
        "explanation": "A rule should be tested against every backend an organization has deployed, because field-mapping differences can change real-world behavior even after a clean conversion. Doing nothing more assumes the mapping is perfect, re-running only on the Sysmon data re-checks the source that was already validated and never tests the converted Defender query, and rewriting by hand in KQL throws away the portability that writing against Sigma's generic taxonomy provides.",
        "xp": 15
      },
      {
        "id": "lp-telemetry-sources-q04",
        "question": "Your FileDownloaded volume rule stays quiet, yet an insider copied an entire document library to a laptop using the OneDrive sync client. Which UAL operation records this activity and should be correlated?",
        "options": [
          "FileAccessed, because syncing simply opens the files for viewing",
          "FileSyncDownloadedFull, a full download through the sync client",
          "MailboxLogin, because the sync client signs in to the mailbox",
          "Add-MailboxPermission, because syncing a library grants access"
        ],
        "answer": 1,
        "explanation": "FileSyncDownloadedFull is the full download made through the OneDrive sync client, distinct from a browser download and often used for bulk replication of a document library. FileAccessed is a weaker open-or-view signal, and MailboxLogin and Add-MailboxPermission are mailbox operations unrelated to SharePoint or OneDrive file sync.",
        "xp": 15
      },
      {
        "id": "lp-telemetry-sources-q05",
        "question": "You are writing a Sigma rule for New-InboxRule and Set-InboxRule events in Microsoft 365. Which logsource matches the module's guidance?",
        "options": [
          "product: windows, service: sysmon, category: process_creation",
          "product: m365 with service: threat_management for alerts",
          "product: m365 with service: exchange for mailbox operations",
          "product: aws with service: cloudtrail and eventSource filters"
        ],
        "answer": 2,
        "explanation": "Mailbox-related operations such as inbox-rule changes use product: m365 with service: exchange. The threat_management answer uses the right product, but that service is for higher-level Microsoft 365 Defender and Cloud App Security alert types; the sysmon process_creation answer is the Windows endpoint source, and the cloudtrail answer is the AWS source.",
        "xp": 15
      },
      {
        "id": "lp-telemetry-sources-q06",
        "question": "After a BEC case, IT resets the mailbox password and revokes active sessions. Two days later the finance director sees that copies of incoming invoices still reach an outside address. What was missed?",
        "options": [
          "The inbox rule persists on its own and must be removed separately",
          "Password resets in Exchange Online only take effect after 72 hours",
          "Search-UnifiedAuditLog must be re-run before forwarding can stop",
          "Entra ID sign-in logs must be exported before forwarding ends"
        ],
        "answer": 0,
        "explanation": "A malicious inbox rule that forwards mail persists after the credential is reset, so removing the rule is a required remediation step distinct from the password reset. The 72-hour password delay, the need to re-run Search-UnifiedAuditLog and the need to export Entra ID sign-in logs all invent delays or dependencies: searching the log or exporting sign-in data is investigation work and does not change what the rule does.",
        "xp": 20
      },
      {
        "id": "lp-telemetry-sources-q07",
        "question": "A trail has run for months. An engineer builds a rule on S3 GetObject calls against a sensitive bucket, but no GetObject events ever reach the SIEM although the bucket is being read. What is the most likely cause?",
        "options": [
          "Management events were switched off, which hides all S3 activity",
          "GetObject is a Read event that CloudTrail Insights must approve first",
          "CloudTrail redacts object names, so rules cannot match GetObject",
          "S3 object-level calls are data events, off unless enabled for that bucket"
        ],
        "answer": 3,
        "explanation": "GetObject is an S3 object-level call, which falls under data events. Data events are not logged by default because of volume and cost, so they must be enabled for the resource. Blaming switched-off management events mislabels the category, the CloudTrail Insights approval step is invented, and the redacted object names claim is invented too; the only redaction the lesson describes is that secret values are excluded.",
        "xp": 15
      },
      {
        "id": "lp-telemetry-sources-q08",
        "question": "A CloudTrail export shows iam.amazonaws.com CreateUser for a new user at 09:02, then AttachUserPolicy with an AdministratorAccess policy for the same user at 09:04. What do you conclude, and which detection idea fits?",
        "options": [
          "Routine onboarding, so alert only when an errorCode is present",
          "Likely persistence; correlate CreateUser with a broad policy attach",
          "A network activity event, so check the VPC endpoint configuration first",
          "An Insight event, so wait for ApiCallRateInsight to confirm it"
        ],
        "answer": 1,
        "explanation": "CreateUser alone grants no permissions, so a quick follow-on AdministratorAccess attachment is the persistence pattern, and correlating the two within a short window is the high-confidence detection. Calling it routine onboarding dismisses an especially strong signal, treating it as a network activity event confuses IAM management events with network activity events, and waiting for ApiCallRateInsight confuses an authored detection with a CloudTrail Insights event.",
        "xp": 20
      },
      {
        "id": "lp-telemetry-sources-q09",
        "question": "A CloudTrail AssumeRole record has userIdentity.accountId 111122223333 and a requestParameters.roleArn pointing at a role in account 444455556666. Which reading is right?",
        "options": [
          "A same-account assumption, because both IDs are twelve digits long",
          "The caller is the role, and the user in userIdentity.arn is the target",
          "Cross-account use, since the role's account differs from the caller's",
          "A failed call, because the two account IDs do not match each other"
        ],
        "answer": 2,
        "explanation": "When the account ID in requestParameters.roleArn differs from the caller's userIdentity.accountId, the call is a cross-account role assumption, routine in multi-account setups but also a way attackers pivot. The same-account answer misreads the IDs, the answer that the caller is the role reverses the fields (userIdentity.arn is the caller and roleArn is the target), and the failed-call answer confuses a mismatch with failure, which would show in errorCode.",
        "xp": 20
      },
      {
        "id": "lp-telemetry-sources-q10",
        "question": "You know Sysmon Event IDs well and now start working with Microsoft 365 and AWS logs. Which fields play the same role of naming the specific action in each source?",
        "options": [
          "UAL Operation and CloudTrail eventName",
          "UAL RecordType and CloudTrail awsRegion",
          "UAL Workload and CloudTrail eventSource",
          "UAL ObjectId and CloudTrail userIdentity"
        ],
        "answer": 0,
        "explanation": "eventName names the specific API call and is CloudTrail's equivalent of a Sysmon Event ID or a UAL Operation. RecordType is only a broad category, Workload and eventSource identify the service, awsRegion is the location, and ObjectId and userIdentity describe the target and the actor, none of which name the action itself.",
        "xp": 10
      }
    ]
  },
  {
    "slug": "lp-detection-tuning",
    "title": "Detection Engineer · Tuning",
    "description": "Knowledge check for the Learning Path module \"Tuning\" (Detection Engineer path). Every question comes from these lessons: FP analysis, Allowlists & exceptions, Tiered severities.",
    "difficulty": "Advanced",
    "category": "Threat Detection",
    "icon": "🎛️",
    "estimatedMinutes": 12,
    "questions": [
      {
        "id": "lp-detection-tuning-q01",
        "question": "A rule fired 120 times in a month: 30 were true positives and 90 were false positives. A separate incident review found 10 real attacks it never alerted on. What is the rule's recall, and what does it indicate?",
        "options": [
          "25%, meaning three of every four alerts were false alarms",
          "75%, meaning it caught three of every four real attacks",
          "30%, meaning thirty alerts were reviewed by analysts",
          "90%, meaning most alerts were closed as false positives"
        ],
        "answer": 1,
        "explanation": "Recall is true positives divided by true positives plus false negatives: 30 / (30 + 10) = 75%, so the rule catches three of four real attacks. The 25% figure is the rule's precision, 30 / (30 + 90), not its recall. The 30% and 90% figures do not correspond to either formula, and the poor precision is the separate problem that a targeted filter should address.",
        "xp": 15
      },
      {
        "id": "lp-detection-tuning-q02",
        "question": "Analysts report that a Sigma process-creation rule keeps flagging hosts, yet the raw logs on those hosts show the flagged command lines never ran. The SIEM's normalized CommandLine field turns out to be filled from a different source field than the rule assumes. Which fix does the lesson prescribe?",
        "options": [
          "Add a filter that excludes every one of the affected hosts",
          "Lower the rule's level field to informational for this rule",
          "Tighten the selection with a longer command-line fragment",
          "Fix the pipeline mapping or log parsing, not the rule logic"
        ],
        "answer": 3,
        "explanation": "A false positive caused by a data-quality or field-mapping problem is not a detection logic flaw, so it needs a pipeline or parsing fix. Excluding the affected hosts hides the symptom and creates a blind spot, lowering the level to informational does not change why the rule matches, and a longer command-line fragment tightens logic that was never the problem.",
        "xp": 15
      },
      {
        "id": "lp-detection-tuning-q03",
        "question": "Two alerts match the same Sigma rule on one day. Alert 1 involves a parent-child process pair seen thousands of times in the last 90 days. Alert 2 involves a pair never seen in that history. How does first-time-seen baselining rank them?",
        "options": [
          "Alert 2 first, since a novel combination ranks above a very common one",
          "Alert 1 first, since common pairs prove the rule is working well",
          "Equal priority, since both alerts match the same Sigma rule",
          "Alert 1 first, since pairs seen before are confirmed malicious"
        ],
        "answer": 0,
        "explanation": "First-time-seen analysis treats genuinely novel combinations as higher priority than combinations the environment has seen thousands of times, even when both match the same rule. Ranking Alert 1 first misreads frequency as proof that the rule works well or that the pair is malicious (a frequent pair is more likely benign), and giving both equal priority ignores the whole point of baselining, which is to separate common from rare.",
        "xp": 15
      },
      {
        "id": "lp-detection-tuning-q04",
        "question": "The same PowerShell rule alerts on both a disposable test VM and a production domain controller, and analysts say the test VM alerts waste their time. The rule logic itself is sound. Where does the lesson route this problem?",
        "options": [
          "To rewriting the core selection with extra distinguishing fields added",
          "To re-baselining the environment and updating the filter list entries",
          "To severity tiering, since missing asset context is a priority issue",
          "To fixing the pipeline mapping for the test VM's log source"
        ],
        "answer": 2,
        "explanation": "Identical activity flagged equally on a test VM and a domain controller is a missing-context problem, which is a severity and prioritization issue and not a detection logic flaw. Rewriting the core selection targets Category B, re-baselining the environment targets environment drift, and fixing the test VM's pipeline mapping targets data quality; none of those describe this scenario.",
        "xp": 20
      },
      {
        "id": "lp-detection-tuning-q05",
        "question": "A detection engineer renames and moves a shared rule file during a repository cleanup. Which exception keeps working without any edits?",
        "options": [
          "A SIEM console suppression created against the old rule title",
          "A comment in the rule description that mentions the exception",
          "A filter that points at the rule by its old file path",
          "A standalone Sigma filter document that lists the rule's id"
        ],
        "answer": 3,
        "explanation": "A standalone filter references its target rule by the unique id, so the link survives a rename or move. A SIEM suppression tied to the old rule title and a filter tied to the old file path both break when those values change, and a comment in the rule description is only informal text that enforces nothing.",
        "xp": 15
      },
      {
        "id": "lp-detection-tuning-q06",
        "question": "An analyst adds a Sentinel automation rule that closes alerts from approved scanner IPs. Two weeks later the Sigma rule is re-converted and redeployed from the repository and the noise returns. Why?",
        "options": [
          "Sentinel automation rules automatically expire after fourteen days",
          "The suppression lives in the SIEM, so re-conversion does not carry it over",
          "Standalone filter documents always overwrite SIEM settings on every deploy",
          "Re-conversion deletes the approved scanner watchlist by design"
        ],
        "answer": 1,
        "explanation": "SIEM-native suppression operates on the deployed platform and not on the Sigma source, so it does not survive a rule being re-converted from source unless it is separately maintained. The claims that automation rules expire after fourteen days, that standalone filters overwrite SIEM settings on every deploy, and that re-conversion deletes the scanner watchlist all invent behaviors that the lesson never describes.",
        "xp": 20
      },
      {
        "id": "lp-detection-tuning-q07",
        "question": "An exception for a vendor tool matches on its full path only. The team worries that an attacker with write access to that folder could drop malware there and inherit the exception. Which change narrows it the most?",
        "options": [
          "Add the process name as one more required match condition",
          "Shorten the path to just the parent folder instead of the file",
          "Add the tool's full file hash to the existing match conditions",
          "Extend the expiration date so it is reviewed less often"
        ],
        "answer": 2,
        "explanation": "The specificity ranking puts a full file hash above path plus parent plus user, with path alone and process name alone below. A hash ties the exception to the exact binary, so malware placed at the same path would not match. Adding the process name narrows nothing, because the full path already contains the file name and dropped malware would carry that same name; shortening the path to the parent folder is broader, not narrower; and extending the expiration date leaves the exception unreviewed for longer.",
        "xp": 15
      },
      {
        "id": "lp-detection-tuning-q08",
        "question": "A colleague proposes editing the level field of one Sigma rule per host, so the rule says critical for domain controllers and low for test VMs. Where does the lesson say this adjustment belongs?",
        "options": [
          "In SIEM or SOAR enrichment using live asset and user data",
          "In the rule's falsepositives list, with one entry for each asset",
          "In the rule's tags, with one attack tag for each asset class",
          "In the rule's logsource, with one category for each asset class"
        ],
        "answer": 0,
        "explanation": "Dynamic severity is computed downstream in SIEM or SOAR enrichment, which can see real-time asset criticality and user privilege that the rule author could not know. The falsepositives list documents benign activity, tags carry ATT&CK IDs, and the logsource selects telemetry; none of them express asset context.",
        "xp": 15
      },
      {
        "id": "lp-detection-tuning-q09",
        "question": "Using the two-dimensional severity matrix, a 'suspicious' finding fires on a domain controller, and an identical-confidence finding fires on a disposable test VM. What final tiers result?",
        "options": [
          "High on both, because confidence alone sets the tier",
          "High on the domain controller and Low on the test VM",
          "Low on the domain controller and High on the test VM",
          "Medium on the domain controller and Informational on the test VM"
        ],
        "answer": 1,
        "explanation": "The matrix crosses confidence with asset criticality, so a suspicious finding rises to High on a crown-jewel asset and settles at Low on a low-value one. High on both ignores asset criticality, Low on the domain controller with High on the test VM reverses the direction, and Medium with Informational describes the lower row of anomalous, possibly benign findings, which is a lower confidence level than the question states.",
        "xp": 15
      },
      {
        "id": "lp-detection-tuning-q10",
        "question": "Alert A is a very high-confidence detection on a disposable test VM. Alert B is a lower-confidence, ambiguous detection on a crown-jewel database server. A teammate says A must always outrank B because its confidence is higher. What does the lesson say?",
        "options": [
          "Agree: confidence is the only input that a severity model needs",
          "Agree: the higher-confidence alert always goes first in a tiered queue",
          "Disagree: confidence and business impact are separate inputs to combine",
          "Disagree: severity should ignore confidence and use asset criticality"
        ],
        "answer": 2,
        "explanation": "Detection confidence and business impact are distinct inputs that must be combined deliberately, so a high-confidence alert on a low-value asset should not automatically outrank an ambiguous one on a crown-jewel asset. Both 'Agree' answers let confidence dominate, and the claim that severity should ignore confidence makes the opposite mistake of letting asset criticality dominate and discarding confidence.",
        "xp": 20
      }
    ]
  },
  {
    "slug": "lp-adversary-emulation",
    "title": "Purple Team · Adversary Emulation",
    "description": "Knowledge check for the Learning Path module \"Adversary Emulation\" (Purple Team path). Every question comes from these lessons: Atomic Red Team, CALDERA platform, Custom TTPs.",
    "difficulty": "Advanced",
    "category": "Threat Detection",
    "icon": "🥷",
    "estimatedMinutes": 12,
    "questions": [
      {
        "id": "lp-adversary-emulation-q01",
        "question": "A teammate types Invoke-AtomicTest T1003.001 with no -TestGuids or -TestNumbers against a technique folder that contains five atomic tests, on a lab host. What will happen?",
        "options": [
          "Only the first test in the YAML file runs, because the module defaults to one test",
          "Nothing runs until the module prompts for a specific GUID and the operator confirms",
          "All five tests execute, so the operator should inspect and pick specific GUIDs first",
          "A simulation layer previews the commands and none of them execute on the host"
        ],
        "answer": 2,
        "explanation": "A bare technique ID targets every test under it, so all five execute for real. That is why the safe workflow is -ShowDetailsBrief first, then choosing specific GUIDs. The module has no single-test default and no confirmation prompt, and there is no simulation layer: the executor command is the literal command that runs.",
        "xp": 15
      },
      {
        "id": "lp-adversary-emulation-q02",
        "question": "In a CALDERA operation report, a lateral movement link is marked Discard. The earlier discovery ability never extracted a username from its output. What does the Discard status indicate?",
        "options": [
          "It never became eligible to run, because a fact it requires was never found",
          "The ability ran but the target host returned an error, so the command failed",
          "The command ran, but no SIEM or EDR telemetry was logged for it",
          "The agent lost its check-in channel before the command could be delivered"
        ],
        "answer": 0,
        "explanation": "Discard means the ability's required facts were never satisfied, here the username that discovery was supposed to produce, so the planner never queued it. A command that ran and returned an error is recorded as Failure. Link status describes what CALDERA itself executed, not whether the SIEM logged anything, and a lost agent connection is not what Discard means.",
        "xp": 15
      },
      {
        "id": "lp-adversary-emulation-q03",
        "question": "After running an atomic test for T1003.001, no alert fires. Raw telemetry shows the Sysmon Event ID 10 (ProcessAccess) event with TargetImage lsass.exe was logged normally, but no rule matched it. How should this gap be classified?",
        "options": [
          "Visibility gap: the sensor or log source is missing and must be onboarded first",
          "Cleanup failure: leftover artifacts from a previous run blocked the new alert",
          "Test failure: a run that produces no alert has no value and should be repeated",
          "Detection-logic gap: the event exists, so a rule needs writing or fixing"
        ],
        "answer": 3,
        "explanation": "The event was logged but nothing matched it, which is the definition of a detection-logic gap, so the next step is rule work. A visibility gap would mean the event was never logged. Cleanup is unrelated to whether a rule matches, and a no-alert result is a valuable finding rather than a wasted run.",
        "xp": 20
      },
      {
        "id": "lp-adversary-emulation-q04",
        "question": "A team building an emulation plan from a CTI report wants to execute the technique steps in whatever order is quickest to set up. What does the lesson say this costs the exercise?",
        "options": [
          "Nothing important, because each technique produces the same telemetry in any order",
          "It stops testing whether detections follow the real actor's kill chain as one story",
          "It makes every auto_generated_guid in the custom tests invalid until regenerated",
          "It forces the exercise to switch from a planning layer to a results layer in Navigator"
        ],
        "answer": 1,
        "explanation": "Sequencing techniques to match the real actor's kill chain is what tests correlation, not just isolated detection. An arbitrary order loses that narrative shape. GUIDs and Navigator layer types have nothing to do with execution order, and order matters precisely because it tests whether alerts connect into one incident.",
        "xp": 10
      },
      {
        "id": "lp-adversary-emulation-q05",
        "question": "Two CALDERA runs use the same adversary profile and the same abilities, but the second run switches the Sandcat agents from HTTP check-in to DNS tunneling. What additional capability does the second run validate?",
        "options": [
          "Whether the Atomic planner paces abilities more realistically than the Batch planner",
          "Whether parsers extract facts correctly from each ability's command output",
          "Whether C2 channel detections catch the agent's check-in, apart from the technique",
          "Whether cleanup_command entries fully remove artifacts left by each executed ability"
        ],
        "answer": 2,
        "explanation": "Each agent communication channel is itself a detectable artifact, so changing the channel tests C2 and network detections independent of the technique being run. Planner pacing, fact parsing and cleanup are unaffected by switching from HTTP to DNS tunneling.",
        "xp": 15
      },
      {
        "id": "lp-adversary-emulation-q06",
        "question": "A purple team lead wants to learn whether analysts can notice and correlate a slow-building intrusion, not just confirm raw technique coverage quickly. Which planner fits best?",
        "options": [
          "Atomic, which sends one usable ability at a time for the most realistic pacing",
          "Batch, which sends every usable ability at once so the whole chain appears together",
          "Buckets, which runs all usable abilities in each stage before the operation advances",
          "Any planner equally, because pacing has no effect on whether analysts correlate alerts"
        ],
        "answer": 0,
        "explanation": "The Atomic planner gives the most realistic, gradual pacing, closest to a patient human operator, which suits validating detection and correlation of a slow-building intrusion. Batch and Buckets run faster and suit quick raw coverage checks when pacing realism is not the point. Pacing does matter for this goal, so the last option is wrong.",
        "xp": 15
      },
      {
        "id": "lp-adversary-emulation-q07",
        "question": "A colleague downloaded a community adversary profile and proposes launching it in autonomous mode on the isolated range right away, since every ability is mapped to an ATT&CK technique ID. What is the correct response?",
        "options": [
          "Agree, because ATT&CK mapping shows each ability has been reviewed and is safe to run",
          "Agree, because an isolated range makes reading the individual abilities unnecessary",
          "Run it on one production host first, so the telemetry is realistic before the lab run",
          "Read what each ability does first, since a profile is only as safe as its abilities"
        ],
        "answer": 3,
        "explanation": "A profile is only as safe as the abilities it contains, and an imported or community profile should never be trusted without reading what it does. ATT&CK mapping says nothing about safety, isolation does not replace review, and agents belong on isolated range hosts only, never unapproved production endpoints.",
        "xp": 15
      },
      {
        "id": "lp-adversary-emulation-q08",
        "question": "Reviewing a planning-layer Navigator file for an actor known to use discovery and lateral movement, you see colored techniques only under Execution and Persistence. What can you conclude before anything is run?",
        "options": [
          "The SOC has already failed to detect the discovery and lateral movement techniques",
          "The emulation plan itself has a gap, because it does not exercise those tactics",
          "The results layer was built with the wrong domain value in the JSON file",
          "Scores on the colored techniques show those detections are fully validated"
        ],
        "answer": 1,
        "explanation": "A planning layer is built before the exercise to show what the plan does and does not exercise, so blank tactics reveal a gap in the plan, not in detection. No detection has been tested yet, so nothing can be concluded about SOC failures or validated detections, and this is not a results layer or a domain error.",
        "xp": 20
      },
      {
        "id": "lp-adversary-emulation-q09",
        "question": "An operator ran -Cleanup after a T1003.001 test, then noticed the dump process had also written a second file in another folder that the YAML never mentions. How should the operator treat the host?",
        "options": [
          "As clean, because -Cleanup resets the host to its state from before the test",
          "As clean, because any file written by an atomic test is deleted automatically at exit",
          "As possibly not clean, since cleanup removes only what the cleanup_command targets",
          "As needing a full module reinstall, because -Cleanup cannot run after a test"
        ],
        "answer": 2,
        "explanation": "Cleanup is scoped to the test's own footprint: if a spawned process wrote additional files, only what the YAML's cleanup_command targets is removed, so the operator must verify and remove the extra file manually. It is not a general host reset, nothing deletes files automatically, and -Cleanup is designed to run after a test.",
        "xp": 15
      },
      {
        "id": "lp-adversary-emulation-q10",
        "question": "After an atomic test finds a gap, an engineer drafts a rule that matches only command lines containing comsvcs.dll, the DLL used in the test. Why is this a weak rule?",
        "options": [
          "It keys on the tool, not the artifact, so other LSASS-dumping tools would evade it",
          "comsvcs.dll never appears in process command lines, so the rule could never match",
          "Rules written after an atomic test must be keyed on the test's auto_generated_guid",
          "It would fire on every rundll32.exe execution, making the false positive rate unusable"
        ],
        "answer": 0,
        "explanation": "Rules should target the underlying artifact, here handle access to lsass.exe, not the specific tool, because other tools produce the same artifact. The test's command line does reference comsvcs.dll, so the rule would match it. GUIDs identify tests, not rule keys, and a comsvcs.dll match would not fire on every rundll32.exe launch.",
        "xp": 20
      }
    ]
  },
  {
    "slug": "lp-detection-validation",
    "title": "Purple Team · Detection Validation",
    "description": "Knowledge check for the Learning Path module \"Detection Validation\" (Purple Team path). Every question comes from these lessons: Replay frameworks, KPI tracking.",
    "difficulty": "Advanced",
    "category": "Threat Detection",
    "icon": "✅",
    "estimatedMinutes": 12,
    "questions": [
      {
        "id": "lp-detection-validation-q01",
        "question": "A pull request adds a Sigma rule whose YAML is valid, but it references a field name that the selected Sysmon pipeline has no mapping for. Which pipeline stage catches the problem first?",
        "options": [
          "Stage 1, sigma check, because linting rejects any field name that a backend does not know",
          "Stage 2, sigma convert, because the rule fails to convert cleanly for the target platform",
          "Stage 3, the replay test, because the fixtures would simply return no matches at all",
          "Stage 4, deploy, because the SIEM's API rejects the unmapped field when it is uploaded"
        ],
        "answer": 1,
        "explanation": "A rule referencing a field the pipeline cannot map fails to convert cleanly, so it is caught at Stage 2 before it is ever tested against data. Stage 1 checks YAML syntax and Sigma schema, not field mappings, and the pipeline never reaches Stage 3 or Stage 4 because a conversion failure blocks the pull request first.",
        "xp": 15
      },
      {
        "id": "lp-detection-validation-q02",
        "question": "A rule matches TargetImage with the endswith modifier on lsass.exe. Which fixture best proves whether endswith was the right modifier choice rather than a looser contains?",
        "options": [
          "A log line about a printer event, since it is clearly unrelated and must stay unmatched",
          "The exact malicious access event captured from a real atomic test run on the host",
          "A duplicate of the known-malicious line with only the timestamp value changed",
          "A near-miss line whose TargetImage path contains lsass.exe but does not end with it"
        ],
        "answer": 3,
        "explanation": "A path that contains but does not end with the target string is exactly the edge case that separates endswith from contains. A printer event proves almost nothing about precision, and a copy of the known-malicious event (original or with a new timestamp) would match under either modifier, so it cannot distinguish them.",
        "xp": 20
      },
      {
        "id": "lp-detection-validation-q03",
        "question": "A new rule scores a 100 percent true positive rate and 0 percent false positives against its fixture set, yet after deployment analysts report noisy alerts from it. What best explains this?",
        "options": [
          "Fixtures only cover near-misses someone wrote down; production had new ones",
          "Fixture-based metrics are invalid, because replay testing can never measure false positives",
          "The replay stage must have been skipped, since a perfect score is impossible in a pipeline",
          "True positive rate is calculated from production alerts, so the fixture score meant nothing"
        ],
        "answer": 0,
        "explanation": "A rule can score perfectly on its fixtures and still produce false positives in production, because fixtures only cover near-miss cases that someone wrote down. The right response is to turn the production false positives into new benign fixtures. Replay metrics are a valid leading indicator, a perfect score is possible, and the rates are computed from fixtures, not production alerts.",
        "xp": 20
      },
      {
        "id": "lp-detection-validation-q04",
        "question": "An exercise-based MTTD is computed from six atomic tests that were detected after 3, 9, 2, 12, 4 and 6 minutes. What is the MTTD for the exercise?",
        "options": [
          "5 minutes, the median value of the six detection delays",
          "12 minutes, the slowest detection delay found in the set",
          "6 minutes, the average detection delay across the six tests",
          "36 minutes, the sum of all six detection delays combined"
        ],
        "answer": 2,
        "explanation": "MTTD is the average detection delay across the tested events: (3+9+2+12+4+6)/6 = 36/6 = 6 minutes. The median (5) is a different statistic, the maximum (12) shows only the worst case, and the sum (36) is a total that has not been divided by the number of tests.",
        "xp": 15
      },
      {
        "id": "lp-detection-validation-q05",
        "question": "A manager celebrates that MTTD fell from 20 minutes to 2 minutes after engineers broadened most rules to fire on almost any process creation. What should the manager check alongside MTTD?",
        "options": [
          "The raw rule count, because more rules always means broader real coverage",
          "The false positive rate, because broad rules can cut MTTD while flooding analysts",
          "The stale rule list, because broadened rules will stop matching and turn stale over time",
          "The regression rate, because it measures how quickly alerts reach the analysts"
        ],
        "answer": 1,
        "explanation": "A very low MTTD from broad, low-precision rules can simply mean the SOC accepted high false positive rates in exchange for speed, so MTTD must be read alongside false positive rate. Raw rule count is a weak metric, broadened rules match more rather than less, and regression rate counts previously passing fixtures that start failing, not alert speed.",
        "xp": 15
      },
      {
        "id": "lp-detection-validation-q06",
        "question": "A CI run shows a rule change dropped its false positive rate against benign fixtures to zero, but it now matches only 8 of 10 known-malicious fixtures where it previously matched all 10. What should the pipeline do?",
        "options": [
          "Pass the change, because a lower false positive rate outweighs two missed fixtures",
          "Pass the change with a warning, then wait for production to confirm the misses",
          "Deploy it only if its level is high, since misses matter less for lower levels",
          "Fail the stage and block it, because any known miss should block deployment"
        ],
        "answer": 3,
        "explanation": "A mature pipeline enforces a minimum true positive rate, for example 100% against known-malicious fixtures, because any known miss should block deployment. Trading missed detections for fewer false positives is exactly the regression the gate exists to stop, and waiting for production to reveal the misses defeats the purpose of replay testing.",
        "xp": 15
      },
      {
        "id": "lp-detection-validation-q07",
        "question": "After a false positive spike, a team reverts the offending rule commit in Git. The previous version ran fine for a year. What should happen before the reverted rule is redeployed?",
        "options": [
          "It should pass lint, convert and replay again, since the environment may have changed",
          "It can be redeployed directly, because a version that ran for a year is already proven",
          "Only the replay test needs to run, because linting and conversion cannot be affected",
          "It should skip review, because a revert is attributable to the original author"
        ],
        "answer": 0,
        "explanation": "A reverted rule must pass the full pipeline again because the SIEM schema or log format may have changed since that version was last live, so it might no longer match current data. Its past track record does not prove it still works, and skipping stages or review ignores that risk.",
        "xp": 15
      },
      {
        "id": "lp-detection-validation-q08",
        "question": "NexaCorp reports detection coverage by dividing validated detections by every technique in the full ATT&CK Enterprise matrix, although its environment has no macOS endpoints. What is the problem with this denominator?",
        "options": [
          "macOS techniques cannot be mapped to ATT&CK IDs, so they break the calculation",
          "It counts validated detections twice, once for each platform in the matrix",
          "Irrelevant techniques inflate the denominator and add no real security value",
          "It forces every detection to be scored on the DeTT&CT scale before it counts"
        ],
        "answer": 2,
        "explanation": "Coverage against irrelevant techniques inflates the denominator without adding real security value, which is why mature programs scope to relevant platforms or prioritized threat actors. macOS techniques do have ATT&CK IDs, nothing is double counted, and DeTT&CT scoring concerns what counts as covered (the numerator), not this scoping problem.",
        "xp": 15
      },
      {
        "id": "lp-detection-validation-q09",
        "question": "A detection rule for a credential theft technique has not matched anything in 14 months. A junior analyst proposes deleting it as useless. What is the better first step?",
        "options": [
          "Delete it, because a rule that never fires is redundant and only adds maintenance burden",
          "Leave it alone, because zero matches proves the environment contains no such activity",
          "Mark it healthy, because a rule that never fires has a perfect false positive rate",
          "Investigate whether it is rare-but-valid coverage or a rule silently broken upstream"
        ],
        "answer": 3,
        "explanation": "A stale rule may be genuinely rare-but-important coverage or a rule that silently broke after a log format or field name change upstream, so it should be investigated, not assumed either way. Deleting it risks losing valid coverage, zero matches does not prove the environment is clean, and calling it healthy ignores the possibility that it is broken.",
        "xp": 20
      },
      {
        "id": "lp-detection-validation-q10",
        "question": "A manager proposes adding total alerts closed per week to the executive dashboard. Nobody can say who would do what if the number fell by half. What should the team conclude?",
        "options": [
          "Add it anyway, because a number that is easy to measure is safe to track",
          "It fails the test, because no specific person would take a specific action",
          "Add it, and also add thirty more metrics so that no single number can be gamed",
          "Track it without a threshold for now, and define the action after a year of data"
        ],
        "answer": 1,
        "explanation": "A metric belongs on the dashboard only if a dramatic worsening would make a specific person take a specific action. With no owner or action it is decorative, a vanity metric. Ease of measurement is not a justification, dashboard sprawl is worse than a few reviewed numbers, and a metric with no defined threshold or action is exactly the warning sign described.",
        "xp": 15
      }
    ]
  },
  {
    "slug": "lp-reporting-and-roi",
    "title": "Purple Team · Reporting & ROI",
    "description": "Knowledge check for the Learning Path module \"Reporting & ROI\" (Purple Team path). Every question comes from these lessons: Heatmap delta, Investment justification, Detection maturity.",
    "difficulty": "Advanced",
    "category": "SOC Operations",
    "icon": "📊",
    "estimatedMinutes": 12,
    "questions": [
      {
        "id": "lp-reporting-and-roi-q01",
        "question": "While building the after layer, an engineer wants to raise T1078 from 1 to 2 because the team believes its coverage improved, although the technique was not re-tested this cycle. What is the right action?",
        "options": [
          "Raise it to 2, because team confidence is valid evidence for a detection score",
          "Remove it from the after layer, because untested techniques fall out of scope",
          "Set it to 0, because an untested change should reset the score to forensics level",
          "Leave it at 1, because techniques not re-tested keep their prior baseline score"
        ],
        "answer": 3,
        "explanation": "A technique not actively re-tested in the cycle keeps its prior baseline score unchanged in the after layer, because silently changing a score nobody touched corrupts the delta. Confidence is not evidence, dropping the technique breaks the identical scope that makes the comparison valid, and resetting it to 0 would be just as unsupported as raising it.",
        "xp": 15
      },
      {
        "id": "lp-reporting-and-roi-q02",
        "question": "A baseline-to-after comparison shows T1003.001 moved from 0 to 2, T1078 stayed at 1, and T1053.005 moved from 2 to 1. Which finding should open the stakeholder presentation?",
        "options": [
          "T1003.001, because the largest improvement is the best news to lead with",
          "T1053.005, because a negative delta is a regression and newly introduced risk",
          "T1078, because an unchanged score is the only result that needs an explanation",
          "A table of every technique's score, because tables communicate faster than a matrix"
        ],
        "answer": 1,
        "explanation": "T1053.005 has a delta of -1, a regression, and the lesson says to call out any regression explicitly and first because it is newly introduced, unaddressed risk with no owner yet. Leading with good news buries it, an unchanged score is not a regression, and the presentation should lead with the delta layer's visual rather than a table.",
        "xp": 20
      },
      {
        "id": "lp-reporting-and-roi-q03",
        "question": "Two rules cover LSASS credential dumping. Rule A matches only the literal string comsvcs.dll in a command line. Rule B matches GrantedAccess 0x1FFFFF against lsass.exe regardless of the tool used. How do they score on the DeTT&CT detection scale?",
        "options": [
          "Rule A scores 1 (Basic) as a tool-specific signature, and Rule B scores 2 (Fair)",
          "Rule A scores 2 (Fair) as a tool-specific signature, and Rule B scores 1 (Basic)",
          "Both rules score 2 (Fair), since both of them cover the same single technique",
          "Rule A scores 0 (Forensics/context) and Rule B scores 1 (Basic) as the weaker pair"
        ],
        "answer": 0,
        "explanation": "A basic signature keyed on one specific tool scores 1, and a correlation rule that catches the underlying behavior regardless of tool scores 2. The scores are not reversed, covering the same technique does not make two rules equal in quality, and a score of 0 means no detection at all, only logging, so it cannot describe an active rule.",
        "xp": 10
      },
      {
        "id": "lp-reporting-and-roi-q04",
        "question": "A proposed detection control would avoid 60,000 dollars of expected annual loss and costs 20,000 dollars for the year. What is its ROSI?",
        "options": [
          "3.0, a 300 percent return, found by dividing loss avoided by cost",
          "0.67, a 67 percent return, found by dividing net benefit by loss avoided",
          "2.0, a 200 percent return, found by dividing net benefit by cost",
          "1.0, a 100 percent return, since the control pays back its cost once"
        ],
        "answer": 2,
        "explanation": "ROSI = (loss avoided - cost) / cost = (60,000 - 20,000) / 20,000 = 2.0, a 200 percent return. Dividing loss avoided by cost gives 3.0, which ignores subtracting the cost. Dividing by loss avoided gives 0.67, which uses the wrong denominator. A simple payback of cost does not give 1.0 here because avoided loss is three times the cost.",
        "xp": 15
      },
      {
        "id": "lp-reporting-and-roi-q05",
        "question": "A detection engineer claims a new rule cuts ransomware risk by 90 percent in a ROSI calculation, but purple team testing validated it against only a handful of known procedure variants. What is the likely consequence?",
        "options": [
          "The ROSI is conservative, because validating even a few variants proves full mitigation",
          "The ROSI is unaffected, because mitigation effectiveness is not part of the formula",
          "The ROSI is understated, because loss avoided should use the full ALE figure instead",
          "The ROSI overstates the return and risks credibility on the next funding request"
        ],
        "answer": 3,
        "explanation": "Mitigation effectiveness drives the loss avoided term, and claiming 90 percent on thin validation overstates the return and risks the team's credibility on the next funding request. A few validated variants do not prove full mitigation, the percentage is central to the formula, and using the full ALE would overstate the benefit further, not understate it.",
        "xp": 20
      },
      {
        "id": "lp-reporting-and-roi-q06",
        "question": "A detection program spent 240,000 dollars in a quarter. Twenty techniques were in scope, and 12 of them newly achieved a meaningful validated detection score. What is the cost per detection?",
        "options": [
          "12,000 dollars, found by dividing the cost by all 20 techniques in the scope",
          "20,000 dollars, found by dividing the cost by the 12 newly validated techniques",
          "240,000 dollars, because the whole program cost counts as one detection's cost",
          "2,880,000 dollars, found by multiplying the cost by the 12 validated techniques"
        ],
        "answer": 1,
        "explanation": "Cost per detection is total program cost divided by the number of techniques that achieved a meaningful validated detection score in that period: 240,000 / 12 = 20,000 dollars. Dividing by all 20 scoped techniques counts techniques that did not achieve a validated detection, and the other options either skip the division or multiply instead.",
        "xp": 15
      },
      {
        "id": "lp-reporting-and-roi-q07",
        "question": "A security lead tells the board, 'We could get hacked at any time, so we need more detection budget,' with no figures. How will an experienced executive likely read this?",
        "options": [
          "As generic alarm, less credible than a case built on quantified ALE and ROSI",
          "As a strong case, because urgency is the most persuasive part of a business case",
          "As too technical, because the board expects raw DeTT&CT scores and technique IDs",
          "As a complete case, because a heatmap delta visual is not needed for budget talks"
        ],
        "answer": 0,
        "explanation": "A fear appeal with no quantified ALE and ROSI backing reads as generic alarm, and experienced executives have usually heard that framing before without acting on it. Urgency alone is not a business case, the statement is the opposite of over-technical (raw scores and IDs are a different failure), and the lesson still recommends the delta visual and financial case in a board report.",
        "xp": 15
      },
      {
        "id": "lp-reporting-and-roi-q08",
        "question": "In a SOC-CMM self-assessment, the threat hunting aspect scores top capability, but its maturity is low: one analyst does the work with no documented method. Where should it sit on the improvement roadmap?",
        "options": [
          "Low priority, because the capability score shows hunting already performs well",
          "Low priority, because the maturity scale only measures documentation volume",
          "Early priority, because a fragile high performer can fail suddenly and without warning",
          "Late priority, because foundational visibility gaps always come before process gaps"
        ],
        "answer": 2,
        "explanation": "High capability with low maturity is the single-analyst-dependency pattern: it looks fine today but is the pattern most likely to fail suddenly, so it deserves early attention. Good current performance is exactly what hides the risk, maturity measures how formally and consistently work is executed rather than document volume, and the visibility-first rule applies to detection-logic work, not to every process gap.",
        "xp": 20
      },
      {
        "id": "lp-reporting-and-roi-q09",
        "question": "A technique has a DeTT&CT detection score of 0, and its visibility score is also low because the required log source is not ingested at all. How does this differ from a technique with score 0 but high visibility?",
        "options": [
          "It is the same problem, since both only need a new rule written against existing data",
          "It is easier, because a missing log source can be fixed by lowering the data quality target",
          "It is identical in cost, because DeTT&CT combines the three dimensions into one number",
          "It is a much larger data-onboarding project, not a quick rule-writing backlog item"
        ],
        "answer": 3,
        "explanation": "A low detection score with low visibility means the data does not exist yet, which is a much larger data-onboarding project, while a low score with high visibility and good data quality is a quick rule-writing backlog item. DeTT&CT scores the three dimensions separately precisely because collapsing them would make these two problems look identical.",
        "xp": 20
      },
      {
        "id": "lp-reporting-and-roi-q10",
        "question": "A manager wants to rerun the full SOC-CMM and DeTT&CT maturity assessments after every quarterly purple team exercise. What does the lesson suggest instead?",
        "options": [
          "Reassess maturity annually or semi-annually, keeping quarterly cycles for KPIs and heatmaps",
          "Reassess maturity monthly, because process maturity shifts faster than technique scores",
          "Reassess only after a major incident, because routine assessment adds no trend value",
          "Reassess every quarter, but only the SOC-CMM process domain to save the team effort"
        ],
        "answer": 0,
        "explanation": "Process and capability maturity shift more slowly than individual technique scores, so most organizations reassess annually or semi-annually while the faster quarterly cadence stays with the KPI and heatmap-delta cycles. Monthly reassessment gets the speed backwards, assessing only after incidents loses the trend-over-time value, and the process-domain-only shortcut is not what the lesson describes.",
        "xp": 15
      }
    ]
  }
];
