// ─── Quiz Data: Vendor Stacks ───────────────────────────────────────────────
// Two vendor-specific quizzes that go beyond generic EDR/SIEM theory into the
// real terminology, screens, and actions of the platforms analysts actually
// use: CrowdStrike Falcon, SentinelOne Singularity, Microsoft Defender for
// Endpoint, and the wider Microsoft security stack (Defender XDR, Sentinel,
// Entra ID, Purview). Options are length-balanced so the answer can't be
// guessed by shape. Same contract as ./data.ts.

import type { Quiz } from "./data";

export const QUIZZES_VENDOR_STACKS: Quiz[] = [
  {
    slug: "vendor-edr-in-practice",
    title: "CrowdStrike, SentinelOne & Defender — Vendor EDR in Practice",
    description:
      "Beyond generic EDR theory: the real terminology and actions of CrowdStrike Falcon, SentinelOne Singularity, and Microsoft Defender for Endpoint — RTR, Storyline, Rollback, Advanced Hunting, and how the same task is named differently across all three.",
    difficulty: "Advanced",
    category: "Endpoint Security",
    icon: "🛡️",
    estimatedMinutes: 15,
    questions: [
      {
        id: "ve_01",
        question:
          "In the CrowdStrike Falcon console, a suspicious PowerShell execution triggers an alert, and ten minutes later a related lateral-movement attempt from the same host triggers another. How does Falcon represent this to the analyst?",
        options: [
          "Falcon keeps each event as its own Detection, and if it judges them related, groups them automatically into a single Incident spanning both events.",
          "Falcon deletes the earlier Detection automatically, since only the most recent event on a host is ever retained for review.",
          "Falcon requires the analyst to manually merge the two Detections into a case file before any correlation between them is possible.",
          "Falcon treats every Detection as fully independent and never links related events, even when they occur on the same host.",
        ],
        answer: 0,
        explanation:
          "A Detection is Falcon's record of one individual suspicious event. Falcon's correlation engine automatically groups related Detections — often across hosts and over time — into a single Incident, giving the analyst one view of the full campaign instead of disconnected alerts. Falcon doesn't discard older Detections, doesn't require manual merging for this baseline correlation, and does link related events by design.",
        xp: 15,
      },
      {
        id: "ve_02",
        question:
          "An analyst confirms a host is compromised and needs to collect a suspicious executable for offline analysis, terminate the malicious process, and check running services — all without asking the end user to do anything. Which Falcon capability is built for exactly this?",
        options: [
          "Real Time Response (RTR) — a remote shell to the endpoint through the existing Falcon Sensor channel, letting the analyst run commands and pull files directly.",
          "Falcon Discover — a network-scanning module that lists devices lacking the Falcon Sensor, with no ability to execute commands on a host.",
          "Prevention Policies — the configuration screen that sets which malware families the sensor blocks automatically, with no live shell access.",
          "The Detections page — a list of triggered alerts and their metadata, which does not provide any interactive access to the endpoint.",
        ],
        answer: 0,
        explanation:
          "RTR opens a live remote shell to the Falcon-protected endpoint over the sensor's existing encrypted cloud channel — no VPN or new ports needed — letting the analyst run commands, kill processes, and retrieve files for forensics. Falcon Discover only finds unmanaged devices, Prevention Policies just configure automatic blocking behaviour, and the Detections page is read-only alert data — none of them offer interactive command execution.",
        xp: 10,
      },
      {
        id: "ve_03",
        question:
          "A CrowdStrike detection fires because a process is behaving like credential-dumping tooling — reading LSASS memory in a pattern typical of Mimikatz — even though the file's hash has never been seen before. What kind of indicator triggered this detection?",
        options: [
          "An Indicator of Attack (IOA) — a behaviour-based pattern that flags malicious intent regardless of whether the specific file is already known.",
          "An Indicator of Compromise (IOC) — a static artefact like a known-bad hash or IP address that must already exist on a blocklist.",
          "A Prevention Policy exception — a rule that only fires once an administrator has manually whitelisted the offending process.",
          "A YARA signature match — a byte-pattern rule that requires the exact file contents to match a previously written rule.",
        ],
        answer: 0,
        explanation:
          "IOAs are behaviour-based — they describe what an attacker is doing (a process reading LSASS memory the way credential dumpers do), so they catch novel tools by their actions rather than their identity. IOCs are static, retrospective artefacts that only match things already known to be bad, which wouldn't catch a brand-new file. Whitelisting exceptions suppress detections rather than causing them, and a YARA match requires a known byte pattern — the opposite of 'never been seen before.'",
        xp: 15,
      },
      {
        id: "ve_04",
        question:
          "A newly onboarded business unit has its Falcon sensors running under a Prevention Policy set to Detect-only while the SOC calibrates the deployment. Malware executes on one of these hosts. What happens?",
        options: [
          "The sensor logs the activity and raises a Detection for analyst review, but it does not automatically block or kill the malicious process.",
          "The sensor automatically kills the malicious process and quarantines the file the moment the activity is first observed.",
          "The sensor silently ignores the activity entirely, since Detect-only mode disables all telemetry collection for that host.",
          "The sensor uninstalls itself from the host, because Detect-only policies are incompatible with active malware execution.",
        ],
        answer: 0,
        explanation:
          "Detect-only means the sensor observes and reports but takes no automatic blocking action — the analyst must respond manually, typically via RTR. Automatic kill-and-quarantine only happens under a Prevent policy. Detect-only does not disable telemetry (collecting telemetry is its whole purpose), and sensors don't uninstall themselves in response to policy mode.",
        xp: 10,
      },
      {
        id: "ve_05",
        question:
          "Why does the CrowdStrike Falcon Sensor run in kernel mode rather than as a normal user-space application?",
        options: [
          "Kernel mode is the most privileged layer of the OS, so the sensor can observe every process, file, and network event without malware being able to hide from it.",
          "Kernel mode reduces the CPU and memory footprint of the sensor, which is the only reason CrowdStrike chose that layer to run in.",
          "Kernel mode allows the sensor to run without any network connection to CrowdStrike's cloud, keeping all analysis fully local.",
          "Kernel mode is required so the sensor can encrypt the analyst's RTR session, a function unrelated to endpoint visibility.",
        ],
        answer: 0,
        explanation:
          "Kernel mode is the deepest, most privileged layer of the operating system, so the sensor can see every process, file operation, and network connection without a program being able to evade it. Footprint efficiency isn't the reason for that architectural choice, Falcon is explicitly cloud-native (it depends on a connection to CrowdStrike's cloud for analysis), and session encryption is unrelated to which privilege layer the sensor runs at.",
        xp: 10,
      },
      {
        id: "ve_06",
        question:
          "A host is actively beaconing to a known C2 server and the analyst wants to stop it from reaching the network while still being able to run RTR commands on it for further investigation. Which Falcon action fits this exact need?",
        options: [
          "Network Containment — it restricts the host to communicate only with the Falcon cloud, blocking all other traffic while RTR access stays available.",
          "Falcon Discover — it removes the host from the managed device inventory so it can no longer reach the corporate network at all.",
          "Prevention Policy Detect mode — it stops the sensor from sending any further telemetry until an administrator re-enables it.",
          "Uninstalling the Falcon Sensor — it physically disconnects the host's network adapter as part of the removal process.",
        ],
        answer: 0,
        explanation:
          "Network Containment restricts a host so it can only talk to the Falcon cloud, which blocks the C2 channel while keeping RTR and telemetry alive — exactly the 'isolate but keep investigating' need. Falcon Discover is just a network scanner, Detect mode has nothing to do with network isolation, and uninstalling the sensor removes visibility entirely instead of preserving it.",
        xp: 15,
      },
      {
        id: "ve_07",
        question:
          "A ransomware attack triggers 47 separate low-level signals in SentinelOne — a macro execution, a PowerShell launch, several file writes. How does the Singularity console present this to the analyst instead of 47 disconnected items?",
        options: [
          "It tags every related event with the same StorylineID, so the console displays one connected attack story from first action to last.",
          "It automatically deletes 46 of the 47 signals, keeping only the very first one that was generated during the attack.",
          "It emails the analyst a separate report for each of the 47 signals, requiring them to be read and closed one at a time.",
          "It requires the analyst to manually tag each signal with a shared case number before any of them can be viewed together.",
        ],
        answer: 0,
        explanation:
          "SentinelOne's Storyline engine automatically tags every event belonging to the same attack chain with a shared StorylineID, so the console shows one connected narrative instead of dozens of fragmented signals. Nothing is deleted, nothing is emailed one at a time, and the correlation happens automatically — the analyst doesn't have to build the linkage by hand.",
        xp: 10,
      },
      {
        id: "ve_08",
        question:
          "In the SentinelOne console, an analyst sees an item under 'Threats' with a mitigation status of Mitigated, and a separate item under 'Alerts' generated by a custom Deep Visibility STAR rule with no verdict yet. What's the practical difference between the two?",
        options: [
          "A Threat is malicious activity the agent has already classified and acted on, while an Alert from a custom rule still needs analyst triage to determine if it's malicious.",
          "A Threat only appears after 90 days of storage, while an Alert appears immediately regardless of how long telemetry has been retained.",
          "A Threat can only be generated on Windows endpoints, while an Alert can only be generated on Linux and macOS endpoints.",
          "A Threat is always a false positive by definition, while an Alert is always a confirmed malicious verdict requiring no review.",
        ],
        answer: 0,
        explanation:
          "A Threat is the agent's own classification of malicious activity, already carrying a verdict and often a mitigation action. An Alert from a custom Deep Visibility (STAR) rule is a raw signal matching a query the analyst wrote — it hasn't been classified yet and needs triage before anyone knows if it's malicious. Storage duration and operating system aren't what distinguishes the two, and the fourth option reverses their actual meanings.",
        xp: 15,
      },
      {
        id: "ve_09",
        question:
          "Ransomware encrypts 15,000 files on a laptop before SentinelOne's agent kills the process. The SOC wants the files back without restoring from last night's backup. What should they use?",
        options: [
          "Rollback — it reverts files to pre-attack versions using shadow-copy-style snapshots the agent continuously takes.",
          "Quarantine — it moves the encrypted files into an isolated folder but leaves their contents unchanged and still encrypted.",
          "Network Quarantine — it cuts the host off from the network, which has no effect on files already encrypted on disk.",
          "Deep Visibility — it lets the analyst search historical telemetry, but it cannot modify or restore any file on the endpoint.",
        ],
        answer: 0,
        explanation:
          "Rollback is SentinelOne's distinctive recovery feature: it continuously takes shadow-copy-style snapshots of file changes, so it can reverse ransomware encryption and restore the pre-attack versions of the files. Quarantine isolates a malicious file but doesn't decrypt anything, Network Quarantine only stops network traffic, and Deep Visibility is a search tool with no ability to restore file contents.",
        xp: 10,
      },
      {
        id: "ve_10",
        question:
          "An analyst wants to hunt across every SentinelOne-managed endpoint in the fleet for any process that connected to a specific suspicious IP in the last 30 days, without waiting for an alert to fire. Which feature is built for this?",
        options: [
          "Deep Visibility — a raw telemetry search interface that lets analysts query recorded process and network activity fleet-wide.",
          "Rollback — a recovery feature that restores encrypted files, with no ability to search or query historical telemetry.",
          "Network Quarantine — an isolation action applied to one host at a time, with no fleet-wide search capability at all.",
          "Storyline — a correlation view tied to specific detected threats, not a general-purpose search tool for arbitrary IPs.",
        ],
        answer: 0,
        explanation:
          "Deep Visibility is SentinelOne's raw telemetry search interface, storing months of process and network activity across the whole fleet so analysts can proactively hunt rather than wait for an automatic alert. Rollback only restores files, Network Quarantine only isolates a single host, and Storyline correlates events that are already part of a detected threat rather than answering an open-ended search.",
        xp: 10,
      },
      {
        id: "ve_11",
        question:
          "SentinelOne offers Kill, Quarantine, Remediate, and Rollback as mitigation actions. An analyst wants to remove all artefacts a threat created — dropped files, registry keys, scheduled tasks — after the process itself has already been stopped. Which action does that?",
        options: [
          "Remediate — it cleans up the artefacts a threat left behind, such as files, registry keys, and persistence mechanisms, after the process is gone.",
          "Kill — it terminates the running process only, and has no effect on any files or registry keys already created.",
          "Quarantine — it isolates the malicious file itself into a safe storage location, but leaves other dropped artefacts untouched.",
          "Rollback — it restores files encrypted by ransomware to a prior state, which is unrelated to removing dropped artefacts.",
        ],
        answer: 0,
        explanation:
          "Remediate is the action aimed specifically at cleanup — removing the files, registry keys, and persistence a threat left behind after the process has already been stopped. Kill only stops execution, Quarantine only isolates the offending file itself, and Rollback addresses encrypted data rather than leftover artefacts — none of the three clean up persistence the way Remediate does.",
        xp: 15,
      },
      {
        id: "ve_12",
        question:
          "In Microsoft Defender XDR's Advanced Hunting, an analyst wants every PowerShell process that also made an outbound connection to a public IP in the last 24 hours. Which two KQL tables must be joined to answer this?",
        options: [
          "DeviceProcessEvents and DeviceNetworkEvents — joined on DeviceId and process identifiers to link a process to its connections.",
          "DeviceFileEvents and DeviceLogonEvents — joined on DeviceId to link file creation activity to interactive sign-ins.",
          "DeviceNetworkEvents and DeviceLogonEvents — joined on AccountName to link network activity to a user's session history.",
          "DeviceProcessEvents and DeviceFileEvents — joined on ProcessId to link a process launch to the files it later modifies.",
        ],
        answer: 0,
        explanation:
          "DeviceProcessEvents holds process creation data (including PowerShell launches) and DeviceNetworkEvents holds outbound connection data — joining them on DeviceId and process identifiers is exactly how you link 'this process ran' to 'this process reached out to this IP.' The other pairings connect file, logon, or process data that don't answer a process-to-network question.",
        xp: 15,
      },
      {
        id: "ve_13",
        question:
          "A phishing email delivers a Word document whose macro tries to spawn cmd.exe to download a second-stage payload. Which Microsoft Defender capability is specifically designed to block this behaviour before it can execute?",
        options: [
          "Attack Surface Reduction (ASR) rules — pre-built rules that block Office applications from spawning child processes like cmd.exe.",
          "Automated Investigation and Response (AIR) — a post-detection workflow that only investigates alerts after they've already fired.",
          "Advanced Hunting — a KQL query interface used to search historical telemetry, with no ability to block behaviour in real time.",
          "Live Response — a remote shell tool an analyst opens manually after an incident has already been confirmed and triaged.",
        ],
        answer: 0,
        explanation:
          "ASR rules are pre-emptive, behaviour-based blocking policies — one of the standard rules specifically blocks Office applications from creating child processes, stopping the macro-to-cmd.exe chain before it runs. AIR only kicks in after an alert exists, Advanced Hunting is a search tool rather than a blocking control, and Live Response is a manual investigative shell, not a preventive control.",
        xp: 10,
      },
      {
        id: "ve_14",
        question:
          "A SOC uses CrowdStrike Falcon on one business unit, SentinelOne on another, and Microsoft Defender for Endpoint on a third. An analyst needs to cut a compromised host off from the network in each product. Which set of names is correct?",
        options: [
          "Network Containment in Falcon, Network Quarantine in SentinelOne, and Device Isolation in Microsoft Defender for Endpoint.",
          "Prevention Mode in Falcon, Deep Visibility Lock in SentinelOne, and Advanced Hunting Block in Microsoft Defender for Endpoint.",
          "RTR Lockdown in Falcon, Storyline Freeze in SentinelOne, and ASR Isolation in Microsoft Defender for Endpoint.",
          "Falcon Discover Block in Falcon, Rollback Isolation in SentinelOne, and Live Response Lock in Microsoft Defender for Endpoint.",
        ],
        answer: 0,
        explanation:
          "The same containment concept has three different vendor names: Network Containment in Falcon, Network Quarantine in SentinelOne, and Device Isolation in Microsoft Defender for Endpoint. The other options mix real feature names (Prevention Mode, Deep Visibility, ASR, Rollback, Live Response) with actions those features don't actually perform — none of them are the vendors' real names for network isolation.",
        xp: 15,
      },
    ],
  },
  {
    slug: "microsoft-security-stack",
    title: "The Microsoft Security Stack — Defender XDR, Sentinel, Entra",
    description:
      "How Microsoft's security products fit together: Defender XDR's unified suite, Microsoft Sentinel as cloud SIEM, KQL as the shared query language, and Entra ID identity controls — Conditional Access, Identity Protection, and MFA — plus Purview DLP and Sentinel automation.",
    difficulty: "Intermediate",
    category: "Microsoft Security",
    icon: "🪟",
    estimatedMinutes: 16,
    questions: [
      {
        id: "ms_01",
        question:
          "What does 'Microsoft Defender XDR' refer to, and what does it unify?",
        options: [
          "A unified security platform that correlates signals from Defender for Endpoint, Office 365, Identity, and Cloud Apps into a single incident view.",
          "A stand-alone antivirus engine that replaces Windows Defender on individual laptops, unrelated to any cloud-based service.",
          "A licensing bundle that only unifies billing across Microsoft 365 products, with no shared alerting or investigation console.",
          "A network firewall appliance that unifies perimeter traffic inspection across an organisation's on-premises data centres.",
        ],
        answer: 0,
        explanation:
          "Defender XDR (formerly Microsoft 365 Defender) is the correlation layer that pulls signals from Defender for Endpoint, Defender for Office 365, Defender for Identity, and Defender for Cloud Apps into one console and one set of Incidents. It's not a single local antivirus engine, not just a billing construct, and not a network firewall — those descriptions all miss its role as a cross-product correlation platform.",
        xp: 10,
      },
      {
        id: "ms_02",
        question:
          "A phishing email with a malicious attachment lands in a user's inbox and is later opened. Which Microsoft Defender product is responsible for detecting and detonating that attachment before delivery?",
        options: [
          "Defender for Office 365 — it scans email attachments and links, including sandbox detonation, before messages reach the inbox.",
          "Defender for Endpoint — it protects devices from malware but does not scan or detonate email attachments before delivery.",
          "Defender for Identity — it monitors on-premises Active Directory authentication and has no role in scanning email content.",
          "Defender for Cloud Apps — it governs SaaS application usage and OAuth grants, not the content of inbound email messages.",
        ],
        answer: 0,
        explanation:
          "Defender for Office 365 protects the mail and collaboration path — scanning attachments and links, including sandbox detonation, before a message ever reaches the inbox. Defender for Endpoint only sees device-level activity, Defender for Identity only watches on-premises authentication, and Defender for Cloud Apps governs SaaS usage rather than email content — none of them inspect an inbound attachment before delivery.",
        xp: 10,
      },
      {
        id: "ms_03",
        question:
          "An attacker who has already compromised a workstation runs a DCSync attack against a Domain Controller to steal password hashes. Which Microsoft Defender product is purpose-built to detect this on-premises Active Directory behaviour?",
        options: [
          "Defender for Identity — it monitors Domain Controller traffic and behaviour to detect attacks like DCSync, Kerberoasting, and Pass-the-Hash.",
          "Defender for Endpoint — it monitors device-level process activity, but has no visibility into Domain Controller authentication traffic.",
          "Defender for Cloud Apps — it monitors SaaS application sessions and has no visibility into on-premises Active Directory.",
          "Defender for Office 365 — it monitors email and collaboration content and has no visibility into domain authentication.",
        ],
        answer: 0,
        explanation:
          "Defender for Identity is deployed as a sensor on Domain Controllers specifically to catch identity-based attacks like DCSync, Kerberoasting, and Pass-the-Hash that would otherwise blend into normal authentication traffic. Defender for Endpoint watches devices, Defender for Cloud Apps watches SaaS sessions, and Defender for Office 365 watches email — none of them have visibility into Domain Controller replication traffic.",
        xp: 15,
      },
      {
        id: "ms_04",
        question:
          "An employee connects an unapproved third-party app to their corporate account and grants it broad OAuth permissions to read email. Which Microsoft Defender product is designed to detect and govern this kind of shadow IT risk?",
        options: [
          "Defender for Cloud Apps — a Cloud Access Security Broker (CASB) that discovers unsanctioned apps and can flag or revoke risky OAuth grants.",
          "Defender for Endpoint — an endpoint protection platform focused on device-level malware, not SaaS application governance.",
          "Defender for Identity — an on-premises Active Directory monitoring tool with no visibility into cloud app OAuth grants.",
          "Microsoft Purview — a data governance and compliance suite focused on labelling and protecting sensitive content, not OAuth grants.",
        ],
        answer: 0,
        explanation:
          "Defender for Cloud Apps is Microsoft's CASB — it discovers shadow IT, evaluates the OAuth permissions apps request, and can flag or revoke risky grants. Defender for Endpoint is device-focused, Defender for Identity is on-premises AD-focused, and Purview handles data classification and labelling rather than app OAuth risk — none of them govern third-party app consent the way Cloud Apps does.",
        xp: 10,
      },
      {
        id: "ms_05",
        question:
          "What's the key difference between Microsoft Sentinel and Microsoft Defender XDR?",
        options: [
          "Sentinel is a broad cloud SIEM/SOAR that ingests any data source with custom rules, while Defender XDR is a curated suite correlating Microsoft's own products.",
          "Sentinel only stores data for 24 hours, while Defender XDR retains telemetry indefinitely with no configurable retention.",
          "Sentinel is limited to on-premises deployment only, while Defender XDR is exclusively a cloud-native service with no on-prem option.",
          "Sentinel cannot generate any alerts on its own, while Defender XDR is the only Microsoft product capable of triggering an alert.",
        ],
        answer: 0,
        explanation:
          "Sentinel is a cloud-native SIEM and SOAR that can ingest logs from virtually any source — firewalls, cloud platforms, third-party tools — and run custom analytics rules, while Defender XDR is a narrower, purpose-built suite that correlates signals only from Microsoft's own security products. Sentinel's retention is configurable and far longer than 24 hours, Sentinel is a cloud service (not on-premises), and Sentinel absolutely generates its own alerts through Analytics Rules.",
        xp: 15,
      },
      {
        id: "ms_06",
        question:
          "An analyst wants to count how many failed sign-ins each user account had in Entra ID sign-in logs over the last 24 hours, sorted by user. Which KQL operators are the right building blocks?",
        options: [
          "where to filter for failed results, summarize count() by user to aggregate, and project to select the columns to display.",
          "join to merge two unrelated tables together, and extend to add a computed column, with no filtering or aggregation needed.",
          "render to draw a chart of the raw data, and take to sample a fixed number of rows, with no filtering applied first.",
          "union to combine every table in the workspace into one result set, and sort with no aggregation or filtering step.",
        ],
        answer: 0,
        explanation:
          "This query needs where to isolate failed sign-ins, summarize count() by user to aggregate per account, and project to pick which columns to show — the standard filter-aggregate-select pattern in KQL. join is for combining tables (not needed for a single-table count), render only visualises results after the real query, and union/sort/take don't provide the filtering or aggregation the question requires.",
        xp: 15,
      },
      {
        id: "ms_07",
        question:
          "In Microsoft Defender XDR, a phishing email, a malicious macro execution, and a suspicious sign-in from the same campaign each generate a separate Alert. How does the portal present these three related Alerts to the analyst?",
        options: [
          "It automatically groups related Alerts into a single Incident, giving the analyst one correlated view of the full attack chain.",
          "It requires the analyst to manually search and link each Alert one at a time, since automatic correlation is not available.",
          "It discards two of the three Alerts and keeps only the earliest one, treating the later Alerts as duplicate noise.",
          "It escalates each Alert into three separate Incidents, one per product, that must be investigated independently.",
        ],
        answer: 0,
        explanation:
          "Defender XDR automatically correlates related Alerts across products into a single Incident, so the analyst investigates one attack chain rather than three disconnected items. This is Microsoft's equivalent of the correlation concept other vendors also implement, such as SentinelOne's Storyline. Nothing is discarded, correlation doesn't require manual linking for this baseline grouping, and the Alerts aren't split into separate per-product Incidents.",
        xp: 10,
      },
      {
        id: "ms_08",
        question:
          "A SOC analyst needs to determine whether an admin recently changed a Conditional Access policy, versus checking whether a specific user's sign-in attempts were blocked by MFA. Which two Entra ID log types answer these questions respectively?",
        options: [
          "Audit logs record configuration and administrative changes; sign-in logs record authentication attempts and their outcomes.",
          "Risk logs record every failed authentication; compliance logs record every administrative change made in the tenant.",
          "Activity logs record only successful sign-ins; security logs record only failed sign-ins, with no record of admin changes.",
          "Directory logs record group membership changes only; access logs record only conditional access policy evaluations.",
        ],
        answer: 0,
        explanation:
          "Audit logs capture administrative and configuration changes, such as a Conditional Access policy edit, while sign-in logs capture every authentication attempt along with its outcome, including whether MFA blocked it. The other options invent log type names ('risk logs', 'directory logs', 'access logs') that aren't the actual Entra ID log categories used for this distinction.",
        xp: 15,
      },
      {
        id: "ms_09",
        question:
          "A company wants to block sign-ins that use legacy authentication protocols (which can't support MFA) and require that only compliant, managed devices can reach sensitive apps. Which Entra ID feature enforces both of these rules?",
        options: [
          "Conditional Access — policies that evaluate sign-in conditions and grant or block access based on protocol, device compliance, and risk.",
          "Identity Protection — a risk-scoring engine that flags risky sign-ins for review but does not itself block or grant access.",
          "Microsoft Purview — a data classification and compliance suite with no control over authentication protocols or device state.",
          "Secure Score — a benchmarking dashboard that recommends security improvements but does not enforce any access policy itself.",
        ],
        answer: 0,
        explanation:
          "Conditional Access is the policy engine that evaluates conditions like authentication protocol and device compliance at sign-in time and grants or blocks access accordingly — exactly the mechanism needed here. Identity Protection scores risk but doesn't enforce access on its own, Purview governs data rather than authentication, and Secure Score only recommends improvements without enforcing anything.",
        xp: 10,
      },
      {
        id: "ms_10",
        question:
          "A user signs in from Tel Aviv and, nine minutes later, a sign-in attempt for the same account appears from a location that would be physically impossible to reach in that time. What does Entra ID Identity Protection call this kind of signal, and what does it produce?",
        options: [
          "It's flagged as 'impossible travel,' which raises the sign-in risk level and can be used by Conditional Access to challenge or block the session.",
          "It's flagged as a 'compliance violation,' which only appears in Microsoft Purview reports and has no effect on sign-in access.",
          "It's flagged as a 'Secure Score deduction,' which lowers the tenant's overall score but takes no action on the specific sign-in.",
          "It's flagged as an 'audit anomaly,' which is recorded in the audit log for later review but never affects real-time access.",
        ],
        answer: 0,
        explanation:
          "Identity Protection specifically names this detection 'impossible travel' and raises the sign-in risk level for that session, which Conditional Access policies can then act on in real time — for example, requiring MFA or blocking the sign-in. The other three options are real Microsoft concepts (Purview, Secure Score, audit logs) misapplied here — none of them are the mechanism that scores and reacts to this specific risky sign-in.",
        xp: 15,
      },
      {
        id: "ms_11",
        question:
          "An attacker has stolen a user's password through phishing but does not have access to the user's registered authenticator app or FIDO2 security key. What stops the attacker from completing sign-in?",
        options: [
          "Multi-factor authentication (MFA) — the password alone (something you know) isn't enough without the second factor the attacker doesn't have.",
          "Conditional Access alone — it blocks every sign-in attempt from any new device, regardless of whether MFA is configured.",
          "Microsoft Purview — it encrypts the user's mailbox content, which prevents any sign-in attempt from a new device or location.",
          "Secure Score — it automatically disables the compromised account the moment the password is used from an unrecognised device.",
        ],
        answer: 0,
        explanation:
          "MFA requires a second factor from a different category, such as the authenticator app or FIDO2 key, so a stolen password alone can't complete sign-in. Conditional Access doesn't automatically block every new device by default (it enforces configured policies, and MFA is typically part of them), Purview protects data content rather than authentication, and Secure Score is a scoring dashboard with no ability to disable accounts on its own.",
        xp: 10,
      },
      {
        id: "ms_12",
        question:
          "An employee tries to email a spreadsheet containing customer credit card numbers to a personal Gmail address. Which Microsoft capability is designed to detect the sensitive content and block or warn before the email leaves the organisation?",
        options: [
          "Microsoft Purview Data Loss Prevention (DLP) — it inspects content for sensitive data types and can block, encrypt, or warn on the transfer.",
          "Defender for Endpoint — it monitors device processes and network connections, with no visibility into the content of an email.",
          "Entra ID Conditional Access — it evaluates sign-in conditions like device and location, not the content of outbound messages.",
          "Defender for Identity — it monitors on-premises Active Directory authentication traffic, not outbound email content.",
        ],
        answer: 0,
        explanation:
          "Purview DLP is built to inspect content in motion for sensitive information types like credit card numbers, and it can block, encrypt, or warn on the transfer before it leaves the organisation. Defender for Endpoint watches device activity, Conditional Access watches sign-in conditions, and Defender for Identity watches on-premises authentication — none of them inspect the content of an outbound email.",
        xp: 10,
      },
      {
        id: "ms_13",
        question: "What does Microsoft Secure Score measure, and how should a SOC use it?",
        options: [
          "It's a numeric benchmark of the tenant's security configuration against recommended improvements, used to prioritise hardening work.",
          "It's a real-time count of active incidents in Defender XDR, used by analysts to decide which alert to triage next.",
          "It's a measurement of network bandwidth consumed by security tools, used to plan infrastructure capacity for the SOC.",
          "It's a per-user risk score from Identity Protection, used to decide whether to force a password reset on a single account.",
        ],
        answer: 0,
        explanation:
          "Secure Score is a configuration benchmark — it compares the tenant's current settings against recommended improvements and gives a numeric score, which teams use to prioritise hardening actions over time. It's not an incident counter (that's what the Incidents queue is for), not a bandwidth metric, and not the same thing as Identity Protection's per-user risk level, which is a separate, account-specific signal.",
        xp: 10,
      },
      {
        id: "ms_14",
        question:
          "A SOC wants Microsoft Sentinel to ingest logs from an on-premises Palo Alto firewall alongside its existing Microsoft 365 telemetry. What does the SOC need to configure in Sentinel to make this happen?",
        options: [
          "A Data Connector for the firewall — connectors bring external log sources like on-premises or third-party devices into Sentinel's workspace.",
          "An Analytics Rule for the firewall — rules only generate alerts from data already ingested, they don't bring in new log sources.",
          "A Playbook for the firewall — playbooks automate response actions after an alert fires, they don't ingest raw log data.",
          "An Incident template for the firewall — templates define how incidents are displayed, they don't configure any data ingestion.",
        ],
        answer: 0,
        explanation:
          "Data Connectors are how Sentinel brings in log sources beyond Microsoft's own products — including on-premises and third-party devices like a Palo Alto firewall — into the Log Analytics workspace it queries. Analytics Rules only work on data already ingested, Playbooks automate response rather than ingestion, and Incident templates just control display, not data flow.",
        xp: 15,
      },
      {
        id: "ms_15",
        question:
          "A SOC wants any high-severity Defender XDR incident that reaches Sentinel to automatically isolate the affected device without a human clicking a button first. Which combination of Sentinel features achieves this?",
        options: [
          "An Analytics Rule to detect the condition paired with an Automation rule that triggers a Playbook (Logic App) to run the isolation action.",
          "A Data Connector alone — connectors both detect the condition and execute response actions without any additional configuration.",
          "Secure Score alone — a higher score automatically triggers device isolation once the tenant crosses a defined threshold.",
          "Microsoft Purview alone — it can isolate devices directly once it detects a data loss prevention policy has been violated.",
        ],
        answer: 0,
        explanation:
          "Automation in Sentinel pairs detection with response: an Analytics Rule (or the incoming incident condition) triggers an Automation rule, which calls a Playbook built on Azure Logic Apps to actually perform the isolation action. A Data Connector only brings data in, it doesn't detect conditions or take response actions; Secure Score is a passive benchmark; and Purview governs data policy, not device isolation.",
        xp: 15,
      },
    ],
  },
];
