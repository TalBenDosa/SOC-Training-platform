/**
 * Learning Path lesson → the closest hand-written Library lessons.
 *
 * Learning Path lessons without authored content are shown as "being prepared"
 * (never the old AI stub, which leaked a developer note to customers). This map
 * points the learner at Library lessons (ids from src/data/builtinLessons.ts)
 * that cover the same ground in the meantime. Titles are inlined so the lesson
 * API never has to load the whole Library. Keys: `${pathSlug}--${lessonSlug}`.
 */
export type RelatedLibraryLesson = { id: string; title: string };

export const PATH_LESSON_RELATED: Record<string, RelatedLibraryLesson[]> = {
  "soc-analyst--what-is-a-soc": [
    { id: "local-lesson-4", title: "What a SOC Is and What a Security Analyst Actually Does All Day" },
    { id: "topic-lesson-cia-triad-core-security-principles", title: "The CIA Triad and Core Security Principles" },
  ],
  "soc-analyst--tier-model-and-slas": [
    { id: "local-lesson-4", title: "What a SOC Is and What a Security Analyst Actually Does All Day" },
    { id: "local-lesson-27", title: "SOC Decision Making: Escalate, Close, or Dig Deeper" },
  ],
  "soc-analyst--mental-models-for-triage": [
    { id: "local-lesson-15", title: "The Analyst Mindset: How to Think, Ask the Right Questions, and Form a Hypothesis" },
    { id: "local-lesson-27", title: "SOC Decision Making: Escalate, Close, or Dig Deeper" },
    { id: "local-lesson-10", title: "SIEM Fundamentals: How an Alert Is Born and How to Triage It" },
  ],
  "soc-analyst--quiz-foundations": [
    { id: "local-lesson-4", title: "What a SOC Is and What a Security Analyst Actually Does All Day" },
    { id: "local-lesson-10", title: "SIEM Fundamentals: How an Alert Is Born and How to Triage It" },
    { id: "local-lesson-27", title: "SOC Decision Making: Escalate, Close, or Dig Deeper" },
  ],
  "soc-analyst--reading-edr-alerts": [
    { id: "local-lesson-11", title: "EDR Explained: What Endpoint Detection Sees and How to Read It" },
    { id: "local-lesson-33", title: "CrowdStrike Falcon: Detections, IOAs, and Real Time Response" },
    { id: "local-lesson-35", title: "Microsoft Defender for Endpoint: Advanced Hunting and Live Response" },
  ],
  "soc-analyst--process-trees-in-depth": [
    { id: "topic-lesson-processes-pids-process-tree", title: "Processes, PIDs, and the Process Tree" },
    { id: "local-lesson-7", title: "The Windows You'll Investigate: Processes, Services, the Registry, and Accounts" },
    { id: "local-lesson-11", title: "EDR Explained: What Endpoint Detection Sees and How to Read It" },
  ],
  "soc-analyst--severity-vs-risk-score": [
    { id: "local-lesson-10", title: "SIEM Fundamentals: How an Alert Is Born and How to Triage It" },
    { id: "local-lesson-27", title: "SOC Decision Making: Escalate, Close, or Dig Deeper" },
  ],
  "soc-analyst--containment-basics": [
    { id: "local-lesson-16", title: "The Investigation Workflow: From Alert to Root Cause and Containment" },
    { id: "playbook-lesson-1", title: "SOC Playbooks — Following the Steps, and Knowing When Not To" },
  ],
  "soc-analyst--tactics-and-techniques": [
    { id: "local-lesson-12", title: "The Attacker's Map: MITRE ATT&CK and the Cyber Kill Chain" },
  ],
  "soc-analyst--mapping-alerts-to-attack": [
    { id: "local-lesson-12", title: "The Attacker's Map: MITRE ATT&CK and the Cyber Kill Chain" },
    { id: "local-lesson-10", title: "SIEM Fundamentals: How an Alert Is Born and How to Triage It" },
  ],
  "soc-analyst--coverage-thinking": [
    { id: "local-lesson-12", title: "The Attacker's Map: MITRE ATT&CK and the Cyber Kill Chain" },
    { id: "local-lesson-26", title: "Threat Hunting: Looking for What No Alert Told You About" },
  ],
  "soc-analyst--building-timelines": [
    { id: "topic-lesson-timeline-analysis-super-timelines", title: "Timeline Analysis and Super-Timelines" },
    { id: "local-lesson-16", title: "The Investigation Workflow: From Alert to Root Cause and Containment" },
  ],
  "soc-analyst--pivoting-on-entities": [
    { id: "local-lesson-16", title: "The Investigation Workflow: From Alert to Root Cause and Containment" },
    { id: "topic-lesson-enrichment-tools-virustotal-whois-passive-dns", title: "Enrichment Tools: VirusTotal, WHOIS, and Passive DNS" },
  ],
  "soc-analyst--verdict-workflows": [
    { id: "local-lesson-27", title: "SOC Decision Making: Escalate, Close, or Dig Deeper" },
    { id: "local-lesson-17", title: "Writing the Incident Report: Turning an Investigation Into Something Others Can Act On" },
  ],
  "threat-hunter--ttp-based-hunting": [
    { id: "local-lesson-26", title: "Threat Hunting: Looking for What No Alert Told You About" },
    { id: "local-lesson-12", title: "The Attacker's Map: MITRE ATT&CK and the Cyber Kill Chain" },
  ],
  "threat-hunter--hypothesis-framework": [
    { id: "local-lesson-26", title: "Threat Hunting: Looking for What No Alert Told You About" },
    { id: "local-lesson-15", title: "The Analyst Mindset: How to Think, Ask the Right Questions, and Form a Hypothesis" },
  ],
  "threat-hunter--coverage-gaps": [
    { id: "local-lesson-26", title: "Threat Hunting: Looking for What No Alert Told You About" },
    { id: "local-lesson-12", title: "The Attacker's Map: MITRE ATT&CK and the Cyber Kill Chain" },
  ],
  "threat-hunter--kql-joins": [
    { id: "topic-lesson-advanced-hunting-kql-defender", title: "Advanced Hunting with KQL in Microsoft Defender" },
    { id: "local-lesson-35", title: "Microsoft Defender for Endpoint: Advanced Hunting and Live Response" },
  ],
  "threat-hunter--kql-aggregations": [
    { id: "topic-lesson-advanced-hunting-kql-defender", title: "Advanced Hunting with KQL in Microsoft Defender" },
  ],
  "threat-hunter--entity-baselining": [
    { id: "topic-lesson-advanced-hunting-kql-defender", title: "Advanced Hunting with KQL in Microsoft Defender" },
    { id: "topic-lesson-impossible-travel-signin-anomalies", title: "Impossible Travel and Cloud Sign-in Anomalies" },
  ],
  "threat-hunter--time-series-analysis": [
    { id: "topic-lesson-advanced-hunting-kql-defender", title: "Advanced Hunting with KQL in Microsoft Defender" },
    { id: "local-lesson-26", title: "Threat Hunting: Looking for What No Alert Told You About" },
  ],
  "threat-hunter--sigma-syntax-basics": [
    { id: "topic-lesson-yara-rules", title: "YARA Rules: Writing Detection Signatures" },
    { id: "local-lesson-3", title: "Windows Event Log Analysis for Threat Detection Using Security and Sysmon Event IDs" },
  ],
  "threat-hunter--backend-conversion": [
    { id: "topic-lesson-splunk-for-soc-analysts", title: "Splunk for SOC Analysts: Searching, SPL, and Notable Events" },
    { id: "topic-lesson-advanced-hunting-kql-defender", title: "Advanced Hunting with KQL in Microsoft Defender" },
  ],
  "threat-hunter--sigma-test-data": [
    { id: "local-lesson-3", title: "Windows Event Log Analysis for Threat Detection Using Security and Sysmon Event IDs" },
    { id: "local-lesson-6", title: "What a Log Is, Where Logs Come From, and How to Read One" },
  ],
  "incident-responder--ir-phases-overview": [
    { id: "local-lesson-16", title: "The Investigation Workflow: From Alert to Root Cause and Containment" },
    { id: "playbook-lesson-1", title: "SOC Playbooks — Following the Steps, and Knowing When Not To" },
  ],
  "incident-responder--detection-and-analysis": [
    { id: "local-lesson-10", title: "SIEM Fundamentals: How an Alert Is Born and How to Triage It" },
    { id: "local-lesson-16", title: "The Investigation Workflow: From Alert to Root Cause and Containment" },
  ],
  "incident-responder--containment-strategies": [
    { id: "local-lesson-16", title: "The Investigation Workflow: From Alert to Root Cause and Containment" },
    { id: "attack-lesson-5", title: "The Ransomware Lifecycle: From Access to Extortion" },
  ],
  "incident-responder--eradication-and-recovery": [
    { id: "attack-lesson-5", title: "The Ransomware Lifecycle: From Access to Extortion" },
    { id: "local-lesson-16", title: "The Investigation Workflow: From Alert to Root Cause and Containment" },
  ],
  "incident-responder--post-incident-review": [
    { id: "local-lesson-17", title: "Writing the Incident Report: Turning an Investigation Into Something Others Can Act On" },
  ],
  "incident-responder--ir-playbooks": [
    { id: "playbook-lesson-1", title: "SOC Playbooks — Following the Steps, and Knowing When Not To" },
  ],
  "incident-responder--triage-acquisition": [
    { id: "topic-lesson-evidence-collection-chain-of-custody", title: "Evidence Collection and Chain of Custody" },
    { id: "topic-lesson-windows-forensic-artifacts", title: "Windows Forensic Artifacts: Proving What Happened on a Machine" },
  ],
  "incident-responder--timeline-analysis": [
    { id: "topic-lesson-timeline-analysis-super-timelines", title: "Timeline Analysis and Super-Timelines" },
  ],
  "incident-responder--memory-forensics-basics": [
    { id: "topic-lesson-memory-forensics-volatility", title: "Memory Forensics with Volatility" },
    { id: "topic-lesson-process-injection", title: "Process Injection: Hiding Code Inside Trusted Processes" },
  ],
  "incident-responder--exec-briefings": [
    { id: "local-lesson-17", title: "Writing the Incident Report: Turning an Investigation Into Something Others Can Act On" },
  ],
  "incident-responder--customer-notifications": [
    { id: "local-lesson-17", title: "Writing the Incident Report: Turning an Investigation Into Something Others Can Act On" },
    { id: "attack-lesson-6", title: "Insider Threat and Data Exfiltration" },
  ],
  "incident-responder--postmortems": [
    { id: "local-lesson-17", title: "Writing the Incident Report: Turning an Investigation Into Something Others Can Act On" },
  ],
  "detection-engineer--sigma-selection-patterns": [
    { id: "topic-lesson-yara-rules", title: "YARA Rules: Writing Detection Signatures" },
    { id: "local-lesson-3", title: "Windows Event Log Analysis for Threat Detection Using Security and Sysmon Event IDs" },
  ],
  "detection-engineer--sigma-modifiers": [
    { id: "topic-lesson-yara-rules", title: "YARA Rules: Writing Detection Signatures" },
    { id: "local-lesson-3", title: "Windows Event Log Analysis for Threat Detection Using Security and Sysmon Event IDs" },
  ],
  "detection-engineer--sigma-coverage-testing": [
    { id: "local-lesson-12", title: "The Attacker's Map: MITRE ATT&CK and the Cyber Kill Chain" },
    { id: "local-lesson-3", title: "Windows Event Log Analysis for Threat Detection Using Security and Sysmon Event IDs" },
  ],
  "detection-engineer--edr-vs-sysmon": [
    { id: "local-lesson-11", title: "EDR Explained: What Endpoint Detection Sees and How to Read It" },
    { id: "local-lesson-3", title: "Windows Event Log Analysis for Threat Detection Using Security and Sysmon Event IDs" },
  ],
  "detection-engineer--o365-ual": [
    { id: "topic-lesson-microsoft-365-and-graph-for-security", title: "Microsoft 365 & Microsoft Graph for Security" },
    { id: "local-lesson-32", title: "The Microsoft Security Stack: Defender XDR, Sentinel, Entra, and Purview" },
  ],
  "detection-engineer--cloudtrail-for-detection": [
    { id: "topic-lesson-cloud-audit-logs-cloudtrail-azure-activity", title: "Cloud Audit Logs: CloudTrail, Azure Activity & API Activity" },
    { id: "topic-lesson-cloud-iam-privilege-escalation", title: "Cloud IAM and Privilege Escalation" },
  ],
  "detection-engineer--fp-analysis": [
    { id: "local-lesson-27", title: "SOC Decision Making: Escalate, Close, or Dig Deeper" },
    { id: "local-lesson-10", title: "SIEM Fundamentals: How an Alert Is Born and How to Triage It" },
  ],
  "detection-engineer--allowlists-and-exceptions": [
    { id: "local-lesson-10", title: "SIEM Fundamentals: How an Alert Is Born and How to Triage It" },
    { id: "local-lesson-27", title: "SOC Decision Making: Escalate, Close, or Dig Deeper" },
  ],
  "detection-engineer--tiered-severities": [
    { id: "local-lesson-10", title: "SIEM Fundamentals: How an Alert Is Born and How to Triage It" },
  ],
  "purple-team--atomic-red-team": [
    { id: "local-lesson-12", title: "The Attacker's Map: MITRE ATT&CK and the Cyber Kill Chain" },
    { id: "topic-lesson-lolbins-living-off-the-land", title: "LOLBins: Living Off the Land Binaries" },
  ],
  "purple-team--caldera-platform": [
    { id: "local-lesson-12", title: "The Attacker's Map: MITRE ATT&CK and the Cyber Kill Chain" },
  ],
  "purple-team--custom-ttps": [
    { id: "local-lesson-12", title: "The Attacker's Map: MITRE ATT&CK and the Cyber Kill Chain" },
    { id: "local-lesson-26", title: "Threat Hunting: Looking for What No Alert Told You About" },
  ],
  "purple-team--replay-frameworks": [
    { id: "local-lesson-3", title: "Windows Event Log Analysis for Threat Detection Using Security and Sysmon Event IDs" },
    { id: "local-lesson-6", title: "What a Log Is, Where Logs Come From, and How to Read One" },
  ],
  "purple-team--kpi-tracking": [
    { id: "local-lesson-4", title: "What a SOC Is and What a Security Analyst Actually Does All Day" },
    { id: "local-lesson-12", title: "The Attacker's Map: MITRE ATT&CK and the Cyber Kill Chain" },
  ],
  "purple-team--heatmap-delta": [
    { id: "local-lesson-12", title: "The Attacker's Map: MITRE ATT&CK and the Cyber Kill Chain" },
  ],
  "purple-team--investment-justification": [
    { id: "local-lesson-17", title: "Writing the Incident Report: Turning an Investigation Into Something Others Can Act On" },
    { id: "local-lesson-4", title: "What a SOC Is and What a Security Analyst Actually Does All Day" },
  ],
  "purple-team--detection-maturity": [
    { id: "local-lesson-12", title: "The Attacker's Map: MITRE ATT&CK and the Cyber Kill Chain" },
    { id: "local-lesson-26", title: "Threat Hunting: Looking for What No Alert Told You About" },
  ],
};
