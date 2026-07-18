/**
 * Learning Rooms — Batch 09
 *
 * Four advanced rooms covering Investigation Methodology, Threat Hunting,
 * Digital Forensics, and Email Security. Each room uses the same task
 * structure as rooms.ts (reading / question / log_analysis / flag).
 */

import type { TelemetryEvent } from "@/lib/sim/types";

// Re-use the same task-type interfaces from rooms.ts (duck-typed — no import needed).

// ---------------------------------------------------------------------------
// Room 1 — Investigation Methodology
// ---------------------------------------------------------------------------

const investigationMethodology = {
  id: "investigation-methodology",
  title: "Investigation Methodology",
  description:
    "Learn how SOC analysts think and work through an investigation — from the first alert all the way to a documented conclusion. Master timeline analysis, evidence pivoting, and SIEM workflows.",
  difficulty: "intermediate" as const,
  category: "Incident Response",
  estimatedMinutes: 55,
  xp: 550,
  icon: "🔬",
  prerequisites: ["alert-triage", "windows-event-logs"],
  tasks: [
    // ── Reading 1: Investigation Mindset & Lifecycle ──────────────────────
    {
      type: "reading" as const,
      id: "inv-method-r1",
      heading: "The Investigation Mindset and the Lifecycle",
      content: `Think of a SOC analyst as a detective — not a security guard. A security guard reacts when something already went wrong. A detective asks: *what happened, who did it, how did they do it, and how far did they get?* That detective mindset is the foundation of every investigation you will ever run.

**Two Modes of Investigation**

All SOC work falls into one of two modes:

- **Reactive investigation** — an alert fires (or a user calls the helpdesk), and you investigate that specific event. The trigger is external.
- **Proactive investigation (threat hunting)** — you go looking for evidence of an attack *before* any alert fires. You form a hypothesis and search the data for signs that match it. We cover this in depth in the Threat Hunting room, but you need to understand the distinction now.

This room focuses on reactive investigation, which is the bread-and-butter of most SOC analyst shifts.

**The Investigation Lifecycle — Six Phases**

Every reactive investigation should follow a disciplined six-phase lifecycle. Skipping phases leads to missed evidence and incomplete conclusions.

**Phase 1 — Trigger.** Something fires an alert, a user reports suspicious behaviour, or another system feeds you an IOC (Indicator of Compromise). This is where the investigation begins. Write down exactly what triggered it and when.

**Phase 2 — Scope.** Before diving into raw data, ask: *how big might this be?* Is it one host, one user, or potentially the entire domain? Scope determines how much data you need to collect and how urgently you need to escalate.

**Phase 3 — Collect.** Pull the relevant logs. This means the alert itself plus surrounding context: the host's process logs, the user's authentication history, related network traffic, and any endpoint telemetry. Use your SIEM to gather these. Important: collect *before* evidence is overwritten — logs rotate, and memory is lost when a machine reboots.

**Phase 4 — Analyze.** Go through the data methodically. Build a timeline (more on this below). Look for patterns. Ask: does what I see match a known attack technique? Are there anomalies — events that should not be there, or absences — events that should be there but are missing?

**Phase 5 — Conclude.** Form a verdict: true positive, false positive, or inconclusive. If it is a true positive, determine what the attacker did, which systems are affected, and what data may have been accessed.

**Phase 6 — Document.** Write up your findings in the ticketing system. A good investigation note includes: the trigger, the timeline you built, every piece of evidence you examined (with direct links or query strings), your analysis logic, and your conclusion. If the case ever goes to an incident response team or law enforcement, your documentation becomes the record of what happened.

**Think Like an Attacker**

When you analyze evidence, constantly ask yourself: *if I were the attacker, why would I have done this?* Attackers have goals (steal data, move laterally, establish persistence), and their actions follow a logical sequence. When you understand attacker goals, you can predict what evidence to look for next. If you see a reconnaissance scan, look for what port they found open. If you see a successful login from an unusual IP, look for what they did once they got in.`,
    },

    // ── Reading 2: Timeline Analysis & Pivot Points ───────────────────────
    {
      type: "reading" as const,
      id: "inv-method-r2",
      heading: "Timeline Analysis and Evidence Pivoting",
      content: `An **investigation timeline** is a chronological list of every relevant event in an attack — sorted from earliest to latest, with timestamps, source systems, and a brief note on what each event means. It is the single most important artifact you will build during an investigation.

**Why Timelines Matter**

Without a timeline, you are looking at individual events in isolation. With a timeline, you can see the *attack sequence* — how the attacker moved from one step to the next. A timeline answers questions like:
- When was the first foothold established?
- How much time passed between initial access and the first lateral movement?
- Was data exfiltrated before the alert fired, or after?
- Did the attacker come back a second time?

Consider this analogy: if you investigate a car accident by looking at individual photos without knowing which came first, you cannot tell who was at fault. But if you arrange those photos in chronological order, the sequence tells a clear story. That is exactly what a timeline does for an attack.

**Time Zone Awareness — A Common Trap**

Every system records timestamps, but not all in the same time zone. Your SIEM might ingest logs in UTC. The endpoint itself might be in Eastern Time (UTC-5). The email server might be in Pacific Time (UTC-8). If you do not normalize everything to **UTC** before building your timeline, events will appear in the wrong order and your investigation will be wrong.

Rule: always work in UTC. When you pull events from your SIEM, confirm it is showing UTC. When you see a raw Windows Event log, the timestamp is in the system's local time — convert it. Most SIEM platforms (Microsoft Sentinel, Splunk, Elastic) normalize to UTC automatically, but always verify.

**Evidence Pivoting**

Pivoting means: starting with one piece of evidence and using it to find more evidence. It is how an investigation expands from a single alert into a full picture of the attack.

The four most powerful pivot points are:

- **IP address → hosts.** If you find a malicious IP address, search for every host in your environment that connected to it. You might discover that three other machines are also communicating with the same C2 (command-and-control) server.
- **User account → systems.** If you suspect an account is compromised, search for every system that account logged into over the past 30 days. This reveals lateral movement.
- **File hash → hosts.** If you find a malicious file, query your EDR (Endpoint Detection and Response) platform for every machine that has that file. One machine infected by malware might mean fifty.
- **Process → network connections.** If you find a suspicious process (e.g., powershell.exe), search for every network connection that process made. This reveals the attacker's C2 infrastructure or data exfiltration targets.

**Building a Timeline in Practice**

1. Start with the triggering alert. Note its timestamp, host, user, and event type.
2. Expand the time window: look 24–48 hours *before* and after the alert. Attackers often do reconnaissance days before the final payload runs.
3. Search for the same user, same host, and same IP across all log sources.
4. Add each relevant event to your timeline document in chronological order.
5. Mark events with their source (EDR, SIEM, firewall, AD) so you know the evidence chain.

Tools that help: Microsoft Sentinel's Investigation Graph (automatically draws entity relationships), MDE (Microsoft Defender for Endpoint) Timeline tab (per-device chronological view), and even a shared spreadsheet or Google Sheet works perfectly for smaller investigations.`,
    },

    // ── Reading 3: SIEM Workflow & Case Management ────────────────────────
    {
      type: "reading" as const,
      id: "inv-method-r3",
      heading: "SIEM Investigation Workflow and Case Management",
      content: `Knowing the theory of investigation is one thing. Knowing how to execute it inside a real SIEM and ticketing system is another. This reading covers the practical workflow analysts use every day.

**The SIEM Investigation Workflow**

When an alert fires in your SIEM, follow this step-by-step process:

**Step 1 — Read the alert.** What is the SIEM telling you? What rule triggered? What are the involved entities (host, user, IP, file)? What is the severity? Write down the key fields before you start searching.

**Step 2 — Expand the time window.** The alert triggered at a specific moment, but the attack likely started earlier. Expand your SIEM query to at least 24 hours before and 24 hours after the alert time. Attackers do preparatory steps (scanning, credential testing) that often fly under the radar before the actual attack.

**Step 3 — Gather context on each entity.**
- **Host:** What does this machine normally do? Is it a developer laptop, a file server, a domain controller? Unusual activity on a domain controller is far more serious than the same activity on a user workstation.
- **User:** Is this a regular user account or a service account? Has this account been involved in prior incidents? What is normal working-hours behaviour for them?
- **IP address:** Is it internal or external? If external, look it up in threat intelligence (VirusTotal, AbuseIPDB). If internal, which device owns that IP?

**Step 4 — Search for related events.** Using the entities from Step 1, run additional queries:
- All events from this host in the time window
- All events for this user in the time window
- All events from/to this IP address
- Any other alerts on the same host or user

**Step 5 — Look for lateral movement indicators.**
- Logon Type 3 (network logon) from the compromised account to other hosts
- PSExec / WMI execution (PSEXESVC.exe, wmiprvse.exe spawning processes)
- Admin share access (\\\\hostname\\ADMIN$, \\\\hostname\\C$)
- New service installation on remote hosts (Event ID 7045)

**Step 6 — Check for exfiltration indicators.**
- Large outbound data transfers (firewall logs showing unusual byte counts)
- Connections to file-sharing services (Mega, Dropbox) from sensitive hosts
- Email forwarding rules recently created (check O365 Audit logs)
- Compression activity (7zip, WinRAR) on sensitive directories

**Case Management — Keeping the Investigation Organised**

Every investigation lives in a ticket. Common platforms:
- **TheHive** — open-source case management built for SOC teams, integrates with MISP threat intelligence
- **ServiceNow** (Security Operations module) — enterprise-grade, used in large organisations
- **Jira** — adapted by many teams, flexible but not security-specific

A good case ticket contains:
- **Summary:** one paragraph describing what happened
- **Timeline:** the chronological list of events you built
- **Evidence links:** direct links or saved query strings to every piece of evidence (not screenshots — links that other analysts can click and reproduce)
- **Affected assets:** list of hosts, users, and IPs involved
- **Chain of events:** a narrative explanation of how the attack unfolded
- **Conclusion:** true positive / false positive, severity, MITRE ATT&CK techniques used
- **Actions taken:** what was done in response (host isolated, account disabled, etc.)
- **Recommendations:** what controls should be improved to prevent recurrence

**Documentation is not bureaucracy — it is a force multiplier.** When a senior analyst can read your ticket and immediately understand the full picture, investigations run faster, escalations go smoother, and lessons are learned. Document as you go, not at the end. Memory fades; logs do not.`,
    },

    // ── Question 1 ───────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "inv-method-q1",
      question: "Which phase of the investigation lifecycle involves pulling all relevant logs before they are overwritten?",
      options: [
        "Phase 1 — Trigger",
        "Phase 2 — Scope",
        "Phase 3 — Collect",
        "Phase 5 — Conclude",
      ],
      answer: 2,
      explanation:
        "Phase 3 (Collect) is where you actively gather logs, endpoint telemetry, and network data. This phase must happen quickly because logs rotate and memory is lost on reboot. Waiting until Phase 4 (Analyze) to collect data risks losing volatile evidence. Scoping (Phase 2) determines *what* to collect; collecting (Phase 3) is the act of actually pulling it.",
      xp: 30,
    },

    // ── Question 2 ───────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "inv-method-q2",
      question: "You find a suspicious external IP address in one log. What is the first pivot you should perform?",
      options: [
        "Immediately block the IP in the firewall and close the ticket",
        "Search every host in the environment that communicated with that IP",
        "Look up the IP in Google Maps to find the attacker's location",
        "Run a port scan against that IP to see what services it is running",
      ],
      answer: 1,
      explanation:
        "When you identify a suspicious IP, the first pivot is to search your SIEM for every internal host that communicated with it. One infected machine usually means others — attackers often run C2 (command-and-control) servers that multiple compromised hosts check in with. Blocking the IP (option A) should come after scoping, not before — you might tip off the attacker before you understand the full extent of the compromise. Port scanning the attacker's IP (option D) is not a SOC analyst task and could be illegal.",
      xp: 30,
    },

    // ── Question 3 ───────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "inv-method-q3",
      question: "Why is UTC the standard for investigation timelines?",
      options: [
        "UTC is the fastest time zone to compute",
        "Different systems may record timestamps in different local time zones; UTC provides a single reference point for accurate ordering",
        "The MITRE ATT&CK framework requires UTC timestamps in all reports",
        "Firewalls only accept UTC-formatted log entries",
      ],
      answer: 1,
      explanation:
        "Systems across an organisation are often configured to different local time zones — a server in New York might log in EST (UTC-5), a cloud workload in Dublin in IST (UTC+1), and a SIEM in UTC. If you mix these without normalising, an event that happened first appears *later* in your timeline and the entire sequence looks wrong. Converting everything to UTC before building a timeline is standard practice because UTC has no daylight saving adjustments and never changes.",
      xp: 30,
    },

    // ── Log Analysis ─────────────────────────────────────────────────────
    {
      type: "log_analysis" as const,
      id: "inv-method-la1",
      heading: "Investigating Lateral Movement — Suspicious Service Account Logon",
      context: `You are a Tier 2 SOC analyst and the SIEM has escalated an alert about a service account authentication. Service accounts are a high-value target for attackers because they often have elevated privileges. Your job is to examine the Windows Security Event below and determine whether this logon is legitimate or suspicious. Pay attention to the source of the logon, the authentication package used, and the context note.`,
      event: {
        id: "inv-la1-evt-001",
        ts: "2025-06-24T03:17:42.000Z",
        source: "windows_security",
        event_type: "auth_success",
        severity: "high",
        hostname: "SRV-FINANCE-02",
        user_email: "svc-backup@corp.local",
        src_ip: "10.0.1.45",
        description: "Service account network logon from unexpected workstation using NTLM",
        mitre_technique: "T1078.002 - Valid Accounts: Domain Accounts",
        raw: {
          "event.code": "4624",
          "winlog.event_data.TargetUserName": "svc-backup",
          "winlog.event_data.LogonType": "3",
          "winlog.event_data.IpAddress": "10.0.1.45",
          "winlog.event_data.WorkstationName": "WS-DEV-09",
          "winlog.event_data.AuthenticationPackageName": "NTLM",
          "winlog.event_data.ElevatedToken": "%%1842",
          "rule.description": "Service account authenticating interactively from developer workstation",
          "data.context":
            "svc-backup is a service account that should only authenticate from SRV-BACKUP-01, not from a developer workstation",
        },
      } satisfies TelemetryEvent,
      questions: [
        {
          question: "Which field immediately tells you this logon came from a different machine than expected?",
          options: [
            "winlog.event_data.LogonType = 3",
            "winlog.event_data.WorkstationName = WS-DEV-09",
            "winlog.event_data.ElevatedToken = %%1842",
            "event.code = 4624",
          ],
          answer: 1,
          explanation:
            "WorkstationName shows the machine where the authentication originated: WS-DEV-09, a developer workstation. According to the context note, svc-backup should only authenticate from SRV-BACKUP-01. The deviation in WorkstationName is the clearest indicator that something is wrong — either an attacker has compromised WS-DEV-09 and is using the svc-backup credentials from there, or the credentials have been stolen and used from an attacker-controlled machine.",
          xp: 40,
        },
        {
          question: "Why is the NTLM authentication package significant in this alert?",
          options: [
            "NTLM is a newer protocol and always more secure than Kerberos",
            "NTLM is legacy and attackers often use Pass-the-Hash attacks that produce NTLM authentication",
            "NTLM means the logon was denied and no access was gained",
            "NTLM authentication only works from outside the network",
          ],
          answer: 1,
          explanation:
            "NTLM (NT LAN Manager) is an older Windows authentication protocol. Modern environments use Kerberos by default. When you see NTLM where Kerberos is expected, it is a red flag — attackers frequently use a technique called **Pass-the-Hash (PTH)** which exploits NTLM to authenticate with a stolen password *hash* rather than knowing the actual password. This lets them move laterally without cracking credentials. Seeing NTLM from a service account at 3am from an unexpected workstation is a strong indicator of lateral movement.",
          xp: 40,
        },
      ],
    },

    // ── Flag Task ─────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "inv-method-flag1",
      prompt: `Review the log analysis event above. The svc-backup account authenticated using a legacy protocol that attackers exploit for Pass-the-Hash attacks. Enter the authentication package name exactly as it appears in the raw log field "winlog.event_data.AuthenticationPackageName".`,
      answer: "NTLM",
      hint: "Look at the AuthenticationPackageName field in the raw log. It is a 4-letter acronym for a legacy Windows authentication protocol.",
      xp: 50,
    },

    // ── Question 4 ───────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "inv-method-q4",
      question: "Which of the following is the best description of what Windows Event ID 4624 means?",
      options: [
        "A failed logon attempt — an account tried to authenticate and was denied",
        "A successful logon — an account authenticated successfully to a system",
        "A user account was created in Active Directory",
        "A privilege escalation was detected on the endpoint",
      ],
      answer: 1,
      explanation:
        "Windows Event ID 4624 is a 'Successful Logon' event. It records every time an account successfully authenticates to a Windows system. This is one of the most important Event IDs for SOC analysts. Its counterpart, 4625, records failed logon attempts. A successful logon from an unexpected location (like a service account logging in from a developer workstation at 3am using NTLM) is just as suspicious as a failed login — sometimes more so, because the attacker already has valid credentials.",
      xp: 30,
    },

    // ── Question 5 ───────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "inv-method-q5",
      question: "You complete an investigation and determine it is a true positive. What belongs in your case documentation?",
      options: [
        "Only the final verdict — true positive or false positive",
        "Timeline, evidence links, affected assets, chain of events, conclusion, and recommendations",
        "A screenshot of the alert and a note that the host was rebooted",
        "The attacker's IP address and a request to block it",
      ],
      answer: 1,
      explanation:
        "Good case documentation is a complete, reproducible record of the investigation. It must include the timeline of events, direct links to every piece of evidence (not screenshots), the list of all affected hosts and users, a narrative explaining how the attack unfolded, your conclusion, actions taken, and recommendations for improvement. This level of detail lets other analysts review your work, supports escalation to incident responders, and builds organisational knowledge. A screenshot and a reboot note (option C) would leave the next analyst with no idea what happened or why.",
      xp: 30,
    },
  ],
};

// ---------------------------------------------------------------------------
// Room 2 — Threat Hunting Fundamentals
// ---------------------------------------------------------------------------

const threatHuntingFundamentals = {
  id: "threat-hunting-fundamentals",
  title: "Threat Hunting Fundamentals",
  description:
    "Stop waiting for alerts. Learn to proactively search your environment for attacker activity that automated tools have missed. Master hypothesis-driven hunting, TTP-based searches, and hunting workflows.",
  difficulty: "advanced" as const,
  category: "Threat Intelligence",
  estimatedMinutes: 60,
  xp: 650,
  icon: "🎯",
  prerequisites: ["investigation-methodology", "mitre-attack"],
  tasks: [
    // ── Reading 1: What is Threat Hunting & Maturity Model ────────────────
    {
      type: "reading" as const,
      id: "threat-hunt-r1",
      heading: "What is Threat Hunting — and Why Does It Matter?",
      content: `Imagine a burglar who enters a museum through a unlocked staff entrance at 2am. The alarm system did not trigger because the door was marked as "authorised staff access." The cameras recorded the intruder, but nobody was watching the live feed. The burglar wanders the museum for three nights, learning where the valuables are, before finally stealing them on the fourth night. That is when the alarm finally fires.

**Threat hunting is the act of watching the camera feeds before the alarm fires.**

In the cybersecurity world, attackers are detected on average **200+ days** after their initial compromise. They establish a foothold, then patiently learn the environment — moving laterally, elevating privileges, identifying data — while blending in with legitimate activity. Automated detection rules catch obvious threats, but sophisticated attackers know how to operate beneath detection thresholds.

**Reactive vs. Proactive**

Your SIEM fires alerts reactively — something happened, a rule matched, you investigate. Threat hunting is proactive — you form a hypothesis about attacker behaviour and go searching for evidence of it, whether or not any alert has fired. If you find something, you have caught an attacker who would otherwise have gone undetected. If you find nothing, you have either ruled out a threat or discovered that your data coverage has a gap.

According to SANS 2024 research, **51% of organisations now run active threat hunting programs**, up from far fewer a decade ago. The discipline has become a core function of mature SOC teams.

**The Threat Hunting Maturity Model**

The Hunting Maturity Model (HMM) defines four levels of sophistication:

**Level 0 — Initial (fully reactive).** The organisation relies entirely on automated alerts and signature-based tools. No proactive hunting occurs. If an attacker evades signatures, they are invisible.

**Level 1 — Minimal (IOC-based).** Analysts periodically search for known bad indicators (IP addresses, domains, file hashes) shared by threat intelligence feeds. This is reactive hunting — you are still looking for known-bad rather than attacker behaviour. It is better than nothing, but limited: attackers change IOCs constantly.

**Level 2 — Procedural (TTP-based).** Analysts hunt for attacker behaviours described in MITRE ATT\&CK. Instead of searching for a specific file hash, they search for the *technique* — e.g., any process that accesses LSASS memory. This approach works even when attackers change their tools, because they cannot easily change their fundamental behaviour.

**Level 3 — Innovative (analytics-driven).** The team develops its own statistical models and machine learning to detect anomalies unique to their environment. They generate new hunting procedures that may not exist anywhere else in the industry.

Most organisations should aim for Level 2. Level 3 requires dedicated data science resources. Level 0 is a significant risk posture. **Getting from Level 1 to Level 2 — from IOC-hunting to TTP-hunting — is the most important leap a SOC team can make.**`,
    },

    // ── Reading 2: Hypothesis-Driven Hunting ──────────────────────────────
    {
      type: "reading" as const,
      id: "threat-hunt-r2",
      heading: "How to Build a Hunt Hypothesis",
      content: `Every hunt starts with a **hypothesis** — a structured, testable statement about a specific threat behaviour you expect to find in your environment. Without a hypothesis, you are browsing data without direction. With one, you are running a focused experiment with a clear pass/fail outcome.

**The Three Components of a Good Hypothesis**

A strong hunt hypothesis always contains three elements:

1. **Threat actor or technique** — Who (or what class of attacker) are you looking for? A named APT group? A specific MITRE ATT\&CK technique?
2. **Targeted asset or data source** — Where would the evidence appear? Which log source, which system, which user population?
3. **Behavioural indicator** — What would you expect to see if this threat were present?

**Example hypotheses:**

*"APT41 uses Windows Management Instrumentation (WMI) for lateral movement (T1047). If they are active in our environment, I expect to see wmiprvse.exe spawning unexpected child processes on finance servers."*

*"Attackers targeting credential theft (T1003.001) will access the LSASS process. I expect to see rundll32.exe or procdump.exe opening handles to LSASS in our EDR process telemetry."*

*"An insider threat conducting mass data download (a common UEBA scenario) would show a user account accessing far more files than their 30-day baseline. I expect to see statistical outliers in file access counts in the past 7 days."*

Notice that each hypothesis is **specific, testable, and falsifiable** — you can search for the evidence and get a clear result.

**Where Do Hypotheses Come From?**

- **Threat intelligence reports** — A vendor publishes a report saying APT29 is targeting your industry. Formulate hypotheses based on the TTPs described.
- **Your own IR experience** — You investigated an incident last month. What TTPs did the attacker use? Hunt for those same TTPs across your wider estate.
- **MITRE ATT\&CK** — Browse the technique matrix and ask: "Do we have detection coverage for this? Have we ever hunted for it?"
- **Red team/purple team findings** — A penetration test showed a technique that your detections missed. Hunt for historical evidence of the same technique.
- **Anomaly spikes** — Your SIEM shows an unexplained spike in DNS queries at 2am. Hypothesise that it could be DNS beaconing (T1071.004) and investigate.

**The Hunt Cycle**

1. **Formulate** your hypothesis.
2. **Identify** which data source to query (EDR, SIEM, DNS logs, etc.).
3. **Create** the query (KQL, SPL, EQL — depends on your platform).
4. **Execute** the query and collect results.
5. **Analyse** the results. Is the hypothesis confirmed, denied, or inconclusive?
6. **Document** findings. Even a negative result is valuable — it means you have coverage.
7. **Convert** confirmed detections into new SIEM rules so the next occurrence is caught automatically.

This last step is crucial: threat hunting improves your detection capability over time. Every confirmed hunt finding should produce a new detection rule.`,
    },

    // ── Reading 3: Hunting Specific TTPs & Tools ──────────────────────────
    {
      type: "reading" as const,
      id: "threat-hunt-r3",
      heading: "Hunting Specific TTPs and the Analyst's Toolbox",
      content: `Now let us get practical. How do you actually hunt for specific attacker techniques in real data? Below are four high-value TTPs with concrete hunting guidance for each.

**TTP 1 — T1003.001: OS Credential Dumping (LSASS Memory)**

LSASS (Local Security Authority Subsystem Service) is the Windows process that holds password hashes and Kerberos tickets in memory. Attackers dump LSASS to steal credentials. Signs to hunt for:
- Any process opening a handle to lsass.exe with PROCESS_VM_READ (0x10) access rights
- rundll32.exe loading comsvcs.dll with the MiniDump argument (a built-in LOLBin technique)
- procdump.exe, mimikatz.exe, or lsassy.py in your process logs
- Output files named lsass.dmp, lsass.zip, or similar in user temp directories

**TTP 2 — T1059.001: PowerShell Execution (Encoded Commands)**

Attackers abuse PowerShell constantly. Hunt for:
- PowerShell with -EncodedCommand or -enc flags (hides the real command)
- PowerShell launching from unusual parents (Word, Excel, Outlook, mshta.exe)
- Download cradles: IEX (New-Object Net.WebClient).DownloadString('http://...')
- PowerShell connecting to external IPs (network events where parent is powershell.exe)
- ScriptBlock logging (Event ID 4104) capturing obfuscated or unusual code

**TTP 3 — T1071.001: C2 Beaconing over HTTP/HTTPS**

Malware "beacons" home — it calls out to the attacker's C2 server at regular intervals. Hunt for:
- Processes making repeated HTTP/HTTPS requests to the same external IP at very regular intervals (e.g., every 60 seconds)
- Unusually short User-Agent strings or non-standard User-Agent formats
- HTTP requests with high frequency but tiny response sizes (C2 check-in, not real web browsing)
- Outbound connections to newly registered domains (registered <30 days ago)

**TTP 4 — T1021.002: SMB Lateral Movement (PsExec)**

PsExec and similar tools copy a service binary to the target machine over SMB and run it remotely. Hunt for:
- PSEXESVC.exe appearing in process logs on any system
- Network events showing access to \\\\hostname\\ADMIN$ share
- Windows Event ID 7045 (New Service Installed) on any host followed by immediate removal
- Service names that are random strings or misspell legitimate names (svchosts.exe, lsasss.exe)

**The Analyst's Hunting Toolbox**

- **KQL (Kusto Query Language)** — used in Microsoft Sentinel and Microsoft Defender XDR. The most widely deployed SIEM language in enterprise environments.
- **Splunk SPL (Search Processing Language)** — used in Splunk Enterprise Security.
- **Elastic EQL (Event Query Language)** — used in Elastic SIEM. Supports sequence matching (find event A followed by event B on the same host within 5 minutes).
- **Velociraptor** — open-source DFIR and hunting platform. Deploys lightweight agents to endpoints and lets you run hunts across thousands of machines simultaneously using VQL (Velociraptor Query Language).
- **Sigma** — a vendor-agnostic rule format. You write one rule, convert it to KQL/SPL/EQL with a converter. The Sigma project maintains a community rule repository with hundreds of hunt rules you can use for free.

The key insight: the platform does not matter as much as the hypothesis and the data. A well-formed hypothesis lets you write an effective query in any language. A poorly formed hypothesis produces noise regardless of the tool.`,
    },

    // ── Question 1 ───────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "threat-hunt-q1",
      question: "According to industry research, how many days on average do attackers dwell in a victim environment before being detected?",
      options: [
        "Less than 24 hours — modern SIEMs catch attackers almost immediately",
        "About 7 days — one week is the typical detection window",
        "200 or more days — attackers often go undetected for months",
        "Exactly 30 days — the standard log retention period",
      ],
      answer: 2,
      explanation:
        "The industry average dwell time — the period between initial compromise and detection — has historically been 200+ days. This is the core argument for proactive threat hunting. Even if it has improved somewhat with better tooling, attackers who operate carefully and understand enterprise environments can persist for months inside a network before any automated alert fires. Threat hunting directly attacks this dwell time by proactively searching for activity that evades signatures.",
      xp: 30,
    },

    // ── Question 2 ───────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "threat-hunt-q2",
      question: "What is the key advantage of TTP-based hunting (Level 2) over IOC-based hunting (Level 1)?",
      options: [
        "TTP-based hunting is faster because it uses fewer queries",
        "TTPs describe attacker behaviour, which is harder to change than indicators like IP addresses or file hashes",
        "IOC-based hunting requires more expensive tools",
        "TTP-based hunting only works with threat intelligence subscriptions",
      ],
      answer: 1,
      explanation:
        "IOCs (Indicators of Compromise) like IP addresses, domain names, and file hashes are trivially easy for attackers to change — they spin up a new server, register a new domain, or repack their malware. TTPs (Tactics, Techniques, and Procedures) describe *how* attackers behave at a fundamental level — e.g., they dump LSASS to steal credentials. Changing behaviour requires completely redesigning the attack, which is expensive. This is the 'Pyramid of Pain' concept: the higher you go on the pyramid (from file hashes up to TTPs), the more pain you inflict on the attacker when you detect and block them.",
      xp: 30,
    },

    // ── Question 3 ───────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "threat-hunt-q3",
      question: "What should you do with a confirmed threat hunting finding?",
      options: [
        "Keep it secret so the attacker does not know you found them",
        "Delete the logs and reimage the machine immediately",
        "Document it and convert it into a new SIEM detection rule for automatic future detection",
        "Submit it to a bug bounty program",
      ],
      answer: 2,
      explanation:
        "A confirmed hunt finding has two immediate values: it tells you there is an active threat to respond to, and it reveals a gap in your automated detection coverage. If you caught it by hunting, your SIEM rules would not have caught it automatically. The immediate action after confirming a finding is to open a response case (investigate, contain, remediate) AND write a new SIEM rule so the next occurrence triggers an automatic alert. This is how threat hunting improves your detection posture over time — every hunt makes your SOC smarter.",
      xp: 30,
    },

    // ── Log Analysis ─────────────────────────────────────────────────────
    {
      type: "log_analysis" as const,
      id: "threat-hunt-la1",
      heading: "Hunting for LSASS Memory Dump — comsvcs.dll Technique",
      context: `You are running a threat hunt for T1003.001 (OS Credential Dumping via LSASS) across your EDR telemetry. Your hunt hypothesis is: "An attacker targeting credential theft will use rundll32.exe to load comsvcs.dll and call its MiniDump export to dump LSASS memory." You have executed a KQL query against your Falcon EDR data and received the following hit. This is a real technique used in the wild — comsvcs.dll is a legitimate Windows DLL that has a MiniDump function built in. Attackers abuse it because rundll32.exe is a trusted system binary, making it harder for security tools to block.`,
      event: {
        id: "threat-hunt-la1-evt-001",
        ts: "2025-06-24T09:44:18.000Z",
        source: "edr",
        vendor: "CrowdStrike Falcon",
        event_type: "process_create",
        severity: "critical",
        hostname: "LAPTOP-JSMITH",
        user_email: "j.smith@corp.com",
        src_ip: "10.0.2.88",
        description: "rundll32.exe loading comsvcs.dll MiniDump to dump LSASS process memory",
        mitre_technique: "T1003.001 - OS Credential Dumping: LSASS Memory",
        raw: {
          "crowdstrike.ContextProcessName": "rundll32.exe",
          "crowdstrike.CommandLine":
            "rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump 640 lsass.dmp full",
          "crowdstrike.ParentProcessName": "cmd.exe",
          "crowdstrike.UserName": "CORP\\j.smith",
          "crowdstrike.HostName": "LAPTOP-JSMITH",
          "crowdstrike.SHA256": "abc123def456abc123def456abc123def456abc123def456abc123def456ab12",
        },
      } satisfies TelemetryEvent,
      questions: [
        {
          question: "What is the purpose of the number '640' in the command line 'rundll32.exe comsvcs.dll MiniDump 640 lsass.dmp full'?",
          options: [
            "It is the port number the dump will be sent to",
            "It is the Process ID (PID) of the LSASS process to dump",
            "It is the maximum size of the dump file in megabytes",
            "It is a random session identifier generated by the attacker's tool",
          ],
          answer: 1,
          explanation:
            "In the comsvcs.dll MiniDump technique, the syntax is: MiniDump [PID] [output_file] [full]. The number 640 is the Process ID of the LSASS process on this machine. The attacker first ran 'tasklist' or similar to find LSASS's PID, then plugged it into this command to dump that specific process's memory to a file called lsass.dmp. This file would then contain password hashes, Kerberos tickets, and potentially cleartext credentials that the attacker can use to move laterally.",
          xp: 40,
        },
        {
          question: "This technique uses a legitimate Windows DLL (comsvcs.dll) to perform the dump. What category does this fall under in attacker tradecraft?",
          options: [
            "Zero-day exploitation — a previously unknown vulnerability",
            "Living Off the Land (LOLBin) — abusing legitimate system tools for malicious purposes",
            "Rootkit installation — hiding processes from the operating system",
            "Ransomware deployment — encrypting files for extortion",
          ],
          answer: 1,
          explanation:
            "LOLBins (Living Off the Land Binaries) are legitimate Windows system tools that attackers abuse to perform malicious actions. Because these tools are signed by Microsoft and are part of the operating system, many security products whitelist them. Common LOLBins include rundll32.exe, certutil.exe, mshta.exe, regsvr32.exe, and wscript.exe. The comsvcs.dll MiniDump technique is a well-documented LOLBin technique (it even has its own entry in the LOLBAS project at lolbas-project.github.io). Defenders must look at what a LOLBin is *doing*, not just what it *is*.",
          xp: 40,
        },
      ],
    },

    // ── Flag Task ─────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "threat-hunt-flag1",
      prompt: `The log analysis event above is a confirmed detection of credential dumping from LSASS memory. Enter the MITRE ATT&CK technique ID that covers this specific sub-technique (LSASS Memory Dumping). Format: T followed by numbers and a dot and three more numbers (e.g. T1234.001).`,
      answer: "T1003.001",
      hint: "The technique is OS Credential Dumping — specifically the LSASS Memory sub-technique. Look at the mitre_technique field in the raw log.",
      xp: 50,
    },

    // ── Question 4 ───────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "threat-hunt-q4",
      question: "You observe powershell.exe launching from winword.exe (Microsoft Word) on an endpoint. Why is this suspicious?",
      options: [
        "Microsoft Word is not allowed to use the network",
        "Word documents can legitimately contain PowerShell macros, so this is expected",
        "Word should never spawn PowerShell — this is a classic macro-based malware execution pattern",
        "PowerShell is not installed on standard workstations",
      ],
      answer: 2,
      explanation:
        "Microsoft Word spawning PowerShell (winword.exe → powershell.exe) is one of the most classic malware execution chains. An attacker sends a phishing email with a malicious Word document that contains an embedded macro. When the user enables macros, the macro runs and launches PowerShell to download and execute malware. Word has absolutely no legitimate reason to spawn a PowerShell process in a normal business workflow. This parent-child relationship is a high-fidelity detection that should always generate a critical alert. Hunting for unusual parent-child process relationships is one of the most effective TTP-based hunt strategies.",
      xp: 30,
    },

    // ── Question 5 ───────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "threat-hunt-q5",
      question: "What is C2 beaconing and what pattern distinguishes it from normal web browsing traffic?",
      options: [
        "C2 beaconing is HTTPS traffic; normal browsing uses HTTP — you detect it by the port number",
        "C2 beaconing makes requests at very regular, predictable intervals to the same destination; normal browsing is irregular and visits many different sites",
        "C2 beaconing only occurs during business hours; attacks outside business hours are always APT activity",
        "C2 beaconing uses IPv6 while normal browsing uses IPv4",
      ],
      answer: 1,
      explanation:
        "C2 (Command and Control) beaconing is malware checking in with the attacker's server to receive instructions. It is characterised by very regular, periodic HTTP/HTTPS requests to the same external destination — often every 30, 60, or 300 seconds like clockwork. Normal human browsing is highly irregular: you visit many different sites, at random intervals, with varying response sizes. When you see a process making identical HTTP GET requests to the same IP every 60 seconds at 3am, that is almost certainly malware, not a human. Hunting for this pattern in network logs (often called 'jitter analysis' or 'beacon analysis') is a powerful hunting technique.",
      xp: 30,
    },
  ],
};

// ---------------------------------------------------------------------------
// Room 3 — Digital Forensics Basics
// ---------------------------------------------------------------------------

const digitalForensicsBasics = {
  id: "digital-forensics-basics",
  title: "Digital Forensics Basics",
  description:
    "When an incident happens, you need to collect and preserve digital evidence correctly. Learn the order of volatility, chain of custody, memory forensics, and disk forensics used by SOC and DFIR teams.",
  difficulty: "intermediate" as const,
  category: "Forensics",
  estimatedMinutes: 50,
  xp: 550,
  icon: "🔏",
  prerequisites: ["windows-event-logs", "linux-log-analysis"],
  tasks: [
    // ── Reading 1: Forensics Introduction & Order of Volatility ──────────
    {
      type: "reading" as const,
      id: "dfir-r1",
      heading: "What is Digital Forensics — and the Order of Volatility",
      content: `Imagine a crime scene in the physical world. The first rule the police follow is: **do not contaminate the scene.** Do not touch anything. Do not move anything. Document everything exactly as you found it. The same principle applies to digital investigations — but with one critical difference: **digital evidence can disappear on its own.**

**What is Digital Forensics?**

Digital forensics is the process of collecting, preserving, analysing, and presenting digital evidence from computers, mobile devices, networks, and cloud systems. In a law enforcement context, the goal is to produce evidence that holds up in court. In a corporate SOC context, the goal is usually to understand what happened so you can contain the threat, remediate the damage, and prevent recurrence.

SOC analysts perform **incident-focused forensics** — fast, pragmatic evidence collection aimed at answering investigation questions. This differs from law enforcement forensics, which requires stricter evidence handling procedures (write blockers, court-admissible chain of custody forms, etc.). However, even in corporate investigations, following forensic best practices protects you from claims that evidence was tampered with.

**The Order of Volatility — What to Collect First**

Digital evidence is not all equal. Some evidence disappears in seconds (CPU cache), some disappears when the machine is powered off (RAM), some is persistent but might be overwritten soon (logs). The **order of volatility** tells you what to collect first, starting with the most ephemeral:

1. **CPU registers and cache** — the contents of the CPU registers at any given moment. These are lost the instant the processor moves to the next instruction. Essentially uncollectable in practice, but important to understand why a live machine is different from one that was just rebooted.

2. **RAM / main memory** — everything the computer currently has loaded: running processes, network connections, encryption keys, malware code that only exists in memory (fileless malware), and sometimes plaintext credentials. Lost immediately when the machine is powered off. **This is the most valuable and most time-sensitive forensic source.**

3. **Network connections** — the list of active TCP/UDP connections at this moment. Changes constantly as connections open and close. Run "netstat -ano" on Windows or "ss -tulpn" on Linux to capture the current state.

4. **Running processes** — the list of processes currently executing. Unlike network connections, processes are somewhat more stable, but a malicious process may self-terminate if it detects forensic tools.

5. **Disk (storage)** — the hard drive or SSD. This is persistent data — files, logs, the registry, browser history. It does not disappear when you power off the machine (unlike RAM). This is less urgent than RAM.

6. **Logs** — system, application, and security logs stored on disk. Persistent, but log rotation means old logs get overwritten. Important to collect, but less urgent than RAM.

7. **Backup media** — the most stable and least volatile. Backups do not change unless overwritten. Useful for baseline comparisons ("what did this machine look like before the incident?").

**The key rule:** always collect in order from most volatile to least volatile. If you image the disk first and then try to collect RAM, the machine may have been running for another 30 minutes — and whatever malware was in memory might have cleared its tracks.

**Chain of Custody**

Chain of custody is the documented history of evidence: who collected it, when, from where, how it was stored, and who accessed it afterward. Even in a corporate investigation (not law enforcement), chain of custody matters because:
- It proves the evidence was not modified after collection
- It protects analysts from accusations of tampering
- If the incident does lead to legal action, proper chain of custody means the evidence is admissible

A chain of custody document records: evidence item (e.g., "RAM dump from HOST-FINANCE-01"), date/time collected, analyst name, collection method, hash values (MD5/SHA256 of the collected image), and any subsequent access (who accessed it and why).`,
    },

    // ── Reading 2: Memory Forensics ───────────────────────────────────────
    {
      type: "reading" as const,
      id: "dfir-r2",
      heading: "Memory Forensics — What Lives in RAM",
      content: `RAM is the most valuable forensic source in many investigations. Here is why: when malware is classified as **fileless**, it never writes itself to the hard disk. It lives entirely in memory — injected into a legitimate process, running its code from RAM, and disappearing completely when the machine is rebooted. The only way to catch fileless malware is to analyse memory *while the machine is still running*.

But even non-fileless malware leaves critical evidence in RAM: the decrypted version of an otherwise-encrypted payload, the command-and-control URLs it connected to, stolen credentials being processed, and the complete list of what the malware was doing.

**What Can You Extract from Memory?**

- **Process list** — every process running at the time of the dump, including their PIDs (Process IDs), PPIDs (Parent Process IDs), start times, and executable paths. Malware often hides as a fake svchost.exe or masquerades as a legitimate process name.
- **Network connections** — every active network connection, including connections that the "netstat" command might hide (rootkits sometimes patch netstat to hide their connections, but memory analysis bypasses this).
- **Registry hives** — portions of the Windows registry loaded into memory. Can reveal attacker persistence mechanisms that have not yet been written to disk.
- **Loaded DLLs** — what libraries each process has loaded. Malicious injections show up as unexpected DLLs in legitimate processes.
- **Command history** — commands typed into cmd.exe and PowerShell sessions, even if the window was closed.
- **Strings** — raw text extracted from memory can reveal C2 URLs, file paths, usernames, and other attacker infrastructure details.
- **Injected code** — memory regions marked as executable but not backed by a file on disk (a sign of process injection or reflective DLL loading).

**Memory Collection Tools**

- **DumpIt** — small, portable Windows executable. Run it as Administrator, it creates a full memory dump (.raw file). Takes 2–5 minutes depending on RAM size.
- **winpmem** — open-source, runs from a USB drive, very reliable across Windows versions.
- **Belkasoft RAM Capturer** — commercial tool, GUI-based, good for less technical responders.
- On Linux: **/proc/mem** or the LiME (Linux Memory Extractor) kernel module.

Always verify the dump with a hash (MD5 or SHA256) immediately after collection. Record the hash in your chain of custody document.

**Analysing Memory with Volatility 3**

Volatility is the industry-standard open-source memory forensics framework. After installing it, you point it at a memory dump file and run plugins:

- **windows.pslist** — list all processes (like Task Manager but from memory)
- **windows.pstree** — show processes as a hierarchy (parent → child)
- **windows.netscan** — show network connections and the processes that own them
- **windows.dlllist** — show loaded DLLs per process
- **windows.cmdline** — show command-line arguments used to launch each process
- **windows.malfind** — identify memory regions that look like injected code
- **windows.dumpfiles** — extract files from memory for further analysis

**A Common Forensics Finding — the Fake svchost.exe**

svchost.exe (Service Host) is a core Windows process that hosts Windows services. There are many legitimate svchost.exe instances running at any time. Attackers know this and name their malware "svchost.exe" to blend in.

How to spot a fake svchost.exe in memory analysis:
- Parent process should be services.exe (PID often 804). If the parent is explorer.exe, cmd.exe, or PID 1 (System), it is suspicious.
- Path should be C:\\Windows\\System32\\svchost.exe. If it is running from AppData, Temp, or a user directory, it is malicious.
- Legitimate svchost.exe always has a "-k" argument (e.g., svchost.exe -k netsvcs). No argument = suspicious.`,
    },

    // ── Reading 3: Disk & Timeline Forensics ──────────────────────────────
    {
      type: "reading" as const,
      id: "dfir-r3",
      heading: "Disk Forensics and Timeline Reconstruction",
      content: `After memory, the hard disk (or SSD) is the next forensic treasure trove. Unlike memory, disk content survives reboots — which means the attacker may have left artefacts behind that persist until the disk is forensically imaged and analysed.

**Forensic Imaging — Always Work from a Copy**

The cardinal rule of disk forensics: **never analyse the original drive.** Instead, you create a **forensic image** — a bit-for-bit copy of every sector on the disk, including deleted files, slack space, and unallocated areas. You verify the copy matches the original using a hash (SHA256 of both must match). You then work from the copy, leaving the original untouched.

Why? Because forensic analysis tools sometimes modify timestamps when they access files. Working from a copy ensures the original evidence is preserved.

**Write Blockers** are hardware or software devices that allow reading a disk without writing any data to it — protecting the original from accidental modification during imaging.

**Tools for imaging:** FTK Imager (Windows, GUI-based), dd (Linux command-line — powerful but no write protection), Guymager (Linux GUI). Output formats: E01 (EnCase format, supports compression and metadata) or raw (.dd/.img).

**Key Windows Forensic Artefacts**

Once you have an image, these artefacts yield attacker activity:

**$MFT (Master File Table)** — every file and directory on an NTFS volume has an entry in the $MFT with timestamps (Created, Modified, Accessed, Changed/MFT Entry modified — these four are called MACB timestamps). Even deleted files leave entries until they are overwritten. Analysing $MFT timestamps helps you determine when files were created, modified, or deleted.

**Prefetch files** (C:\\Windows\\Prefetch\\*.pf) — Windows records every executable that has ever run on the system in Prefetch files. Even if the attacker deleted their malware, the Prefetch file may still exist, showing you the malware's name, path, and the last 8 times it ran.

**Amcache** (C:\\Windows\\AppCompat\\Programs\\Amcache.hve) — records every executable ever run, with its SHA1 hash. Useful for identifying malware that has been deleted.

**ShimCache (AppCompatCache)** — stored in the registry, records programs that have been executed on the system. Useful for determining if a binary was ever executed.

**LNK files (shortcuts)** — every time you open a file, Windows creates a shortcut (.lnk) in the Recent Items folder. LNK files contain the path, timestamps, and file size of the target — which can reveal files the attacker opened even if those files were deleted.

**$RECYCLE.BIN** — even deleted files go to the Recycle Bin first. Forensic recovery of Recycle Bin entries can reveal what an attacker deleted and when.

**Browser artefacts** — history (SQLite database of visited URLs), downloads (list of files downloaded), cookies, and cache. These can confirm which C2 sites were visited, what tools were downloaded, and what information was exfiltrated.

**Timeline Reconstruction with Plaso (log2timeline)**

After collecting all these artefacts, you need to put them in chronological order. **Plaso** (also called log2timeline) is an open-source tool that:
1. Ingests dozens of artefact types ($MFT, prefetch, event logs, browser history, LNK files, etc.)
2. Normalises all timestamps to UTC
3. Outputs a single **supertimeline** — a massive chronological CSV/JSON that covers every recorded event across all sources

A supertimeline might contain millions of events, so you filter it to the relevant time window (e.g., 3 days around the incident) and search for specific artefact types. Tools like Autopsy and Timesketch provide graphical interfaces to navigate supertimelines.

**The Goal: A Complete Attack Narrative**

By combining memory forensics (what was running), disk forensics (what files existed), and event log analysis (what actions were taken), you can reconstruct the complete attacker narrative — from initial access to final impact. This narrative becomes the foundation of your incident report.`,
    },

    // ── Question 1 ───────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "dfir-q1",
      question: "Why must you collect RAM before imaging the hard disk when responding to a live incident?",
      options: [
        "RAM contains the disk encryption key, which you need to read the disk",
        "RAM is more volatile than disk — it is lost when the machine powers off, while disk data persists",
        "Disk imaging tools require RAM analysis results to function correctly",
        "RAM collection is optional; disk imaging should always be the first step",
      ],
      answer: 1,
      explanation:
        "RAM is the most volatile digital evidence source. The moment a machine is powered off, all RAM contents are permanently lost — this includes running processes, network connections, decrypted malware payloads, and credentials being processed. Disk content persists after power-off and can be collected later. The order of volatility principle dictates that you always collect in order from most volatile (CPU/RAM/network) to least volatile (disk/logs/backups). If you image the disk first and the machine crashes or is powered off before you collect RAM, you lose the most valuable evidence.",
      xp: 30,
    },

    // ── Question 2 ───────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "dfir-q2",
      question: "What is the purpose of creating a SHA256 hash of a forensic memory dump immediately after collection?",
      options: [
        "To compress the memory dump so it takes less storage space",
        "To verify the dump was not modified after collection — the hash proves integrity",
        "To make the memory dump compatible with Volatility analysis",
        "To encrypt the memory dump so unauthorised analysts cannot access it",
      ],
      answer: 1,
      explanation:
        "A SHA256 hash is a cryptographic fingerprint — a unique 64-character string that represents the exact contents of a file. If even one byte of the memory dump changes after collection, the SHA256 hash will be completely different. By recording the hash immediately after collection and storing it in the chain of custody document, you can later prove that the evidence was not modified. This is called **integrity verification** and is fundamental to forensic evidence handling. Anyone who claims the evidence was tampered with must explain how the hash would still match.",
      xp: 30,
    },

    // ── Question 3 ───────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "dfir-q3",
      question: "An analyst finds a file named 'svchost.exe' running from 'C:\\Users\\jsmith\\AppData\\Roaming\\'. What is the significance of this location?",
      options: [
        "AppData\\Roaming is a standard location for Windows system processes",
        "This is suspicious because legitimate svchost.exe only runs from C:\\Windows\\System32\\",
        "The file is a recently installed Windows update and can be ignored",
        "AppData files are protected by Windows Defender and cannot be malicious",
      ],
      answer: 1,
      explanation:
        "Legitimate svchost.exe (Service Host) always runs from C:\\Windows\\System32\\svchost.exe. It is a critical system process that Windows starts very early in the boot sequence. A file named svchost.exe running from a user's AppData directory is almost certainly malware masquerading as a system process — a technique called **masquerading** (MITRE ATT&CK T1036). Attackers choose system process names specifically because analysts are less likely to question them. Always verify the full path, the parent process, and the command-line arguments of any process claiming to be a Windows system process.",
      xp: 30,
    },

    // ── Log Analysis ─────────────────────────────────────────────────────
    {
      type: "log_analysis" as const,
      id: "dfir-la1",
      heading: "Memory Forensics — Suspicious svchost.exe Process",
      context: `You are conducting memory forensics on a suspected compromised host using Volatility 3. You have run the "windows.pstree" plugin on a memory dump captured from HOST-FINANCE-03. The output below shows a suspicious svchost.exe process. Normally, all svchost.exe processes should be children of services.exe (PID ~804). The PPID shown here is a red flag. Analyse the event and answer the questions.`,
      event: {
        id: "dfir-la1-evt-001",
        ts: "2025-06-24T14:31:55.000Z",
        source: "edr",
        event_type: "process_create",
        severity: "critical",
        hostname: "HOST-FINANCE-03",
        description: "Volatility pslist output for HOST-FINANCE-03",
        raw: {
          "volatility.plugin": "pslist",
          "volatility.pid": "4892",
          "volatility.ppid": "1",
          "volatility.name": "svchost.exe",
          "volatility.offset": "0x0000be8f2a006080",
          "volatility.create_time": "2025-06-24T14:31:55Z",
        },
      } satisfies TelemetryEvent,
      questions: [
        {
          question: "What is the Parent Process ID (PPID) of this suspicious svchost.exe?",
          options: ["804", "4892", "1", "640"],
          answer: 2,
          explanation:
            "The PPID (Parent Process ID) is 1, which corresponds to the System process. Legitimate svchost.exe instances are spawned by services.exe, which has a PID of approximately 804 (it varies but is always services.exe). A PPID of 1 (System) means something unusual is the parent of this process — this is a classic indicator of process injection or hollow process creation, where an attacker creates a new svchost.exe process outside the normal startup hierarchy. This is one of the most reliable indicators of process injection in memory forensics.",
          xp: 40,
        },
        {
          question: "What Volatility plugin would you run next to check whether this svchost.exe has any suspicious network connections?",
          options: [
            "windows.pslist — to list all processes again",
            "windows.netscan — to show all active and recently closed network connections",
            "windows.dumpfiles — to extract files from disk",
            "windows.cmdline — to see command-line arguments only",
          ],
          answer: 1,
          explanation:
            "windows.netscan (or windows.netstat in older Volatility versions) scans memory for network connection structures and shows all active and recently closed TCP/UDP connections, including which process ID owns each connection. After finding a suspicious process with an anomalous PPID, the next question is: is it communicating with the internet? windows.netscan will tell you if PID 4892 has any outbound connections to external IPs — which would confirm it is active malware with C2 communication rather than just a crashed or orphaned process.",
          xp: 40,
        },
      ],
    },

    // ── Flag Task ─────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "dfir-flag1",
      prompt: `Look at the Volatility pslist output in the log analysis above. The suspicious svchost.exe process has an anomalous PPID. What is that PPID? Enter the number only.`,
      answer: "1",
      hint: "PPID is the Parent Process ID. Legitimate svchost.exe should have services.exe as its parent. This one has an unusually low PPID — look at the volatility.ppid field in the raw log.",
      xp: 50,
    },

    // ── Question 4 ───────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "dfir-q4",
      question: "Windows Prefetch files can help identify malware even after it has been deleted from disk. Why?",
      options: [
        "Prefetch files contain the full binary code of every program that has ever run",
        "Prefetch files record evidence that a program was executed — including its name, path, and last run times — even after the executable is deleted",
        "Prefetch files are only useful for troubleshooting slow application launches",
        "Prefetch files are stored in RAM, so they are lost when the machine reboots",
      ],
      answer: 1,
      explanation:
        "Windows creates a Prefetch file (in C:\\Windows\\Prefetch\\) every time a new executable runs. The Prefetch file records the program name, path, and the last 8 execution timestamps. Crucially, Prefetch files persist even after the original executable is deleted. An attacker who runs malware and then deletes it may not think to delete the Prefetch file. When you analyse the Prefetch directory, you can see that 'malware.exe' ran from 'C:\\Users\\victim\\AppData\\Local\\Temp\\' at 3:14am — even if the file itself is gone. This makes Prefetch an extremely valuable forensic artefact for reconstructing attacker activity.",
      xp: 30,
    },

    // ── Question 5 ───────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "dfir-q5",
      question: "What does it mean when Volatility's 'windows.malfind' plugin flags a memory region?",
      options: [
        "The memory region contains a virus that Windows Defender missed",
        "The memory region is executable but not backed by a file on disk — a potential sign of process injection or shellcode",
        "The memory region is corrupted and the RAM stick needs to be replaced",
        "The memory region is encrypted, which all modern applications do for security",
      ],
      answer: 1,
      explanation:
        "windows.malfind identifies memory regions with suspicious characteristics: they are marked executable (the CPU can run code there), but there is no corresponding file on disk backing that memory. Legitimate code is always loaded from a file (a .exe or .dll) — you can trace it back to a path. Injected shellcode or reflective DLL loading does not have a backing file — the code was written directly into memory by the attacker. This is one of the strongest indicators of process injection (T1055). When malfind flags a region, the next step is to dump that memory region and analyse it with YARA rules or a disassembler.",
      xp: 30,
    },
  ],
};

// ---------------------------------------------------------------------------
// Room 4 — Email Security
// ---------------------------------------------------------------------------

const emailSecurity = {
  id: "email-security",
  title: "Email Security",
  description:
    "Over 90% of cyber attacks start with a phishing email. Learn how email actually works, how to read email headers, how SPF/DKIM/DMARC authentication works, and how to analyse a suspicious email like a SOC analyst.",
  difficulty: "intermediate" as const,
  category: "Threat Detection",
  estimatedMinutes: 45,
  xp: 400,
  icon: "📨",
  prerequisites: ["networking-protocols"],
  tasks: [
    // ── Reading 1: How Email Works & Headers ──────────────────────────────
    {
      type: "reading" as const,
      id: "email-sec-r1",
      heading: "How Email Works — Architecture and Headers",
      content: `Email is the most targeted attack vector in cybersecurity. According to Verizon's Data Breach Investigations Report, over **90% of cyber attacks begin with a phishing email**. To defend against email-based attacks, you first need to understand how email actually works under the hood.

**The Email Journey — From Sender to Recipient**

Email is not a direct connection from sender to recipient. It travels through a chain of mail servers, and that journey is recorded in the email's headers.

1. Alice types an email in her mail client (Outlook, Gmail) and hits send.
2. Her mail client connects to her outgoing mail server (called an **SMTP server** — Simple Mail Transfer Protocol) and submits the email.
3. The SMTP server looks up the recipient domain's **MX records** (Mail eXchanger) in DNS to find where to deliver the email. For example, to deliver mail to someone@corp.com, the SMTP server looks up the MX record for corp.com.
4. The sending SMTP server connects to the recipient's SMTP server and delivers the email.
5. The recipient's mail server stores the email until the recipient's mail client fetches it using **IMAP** (Internet Message Access Protocol) or **POP3** (Post Office Protocol 3).

**Reading Email Headers — The Evidence Trail**

Every email contains **headers** — metadata fields that document the email's origin, authentication results, and path through mail servers. Attackers cannot fake all headers, but they can fake some — knowing which headers are trustworthy and which are not is essential.

**Key header fields every analyst must know:**

**Received** headers — the most important headers for tracing the email path. Each mail server that handles the email adds its own "Received" header. **Read them bottom-to-top** — the bottom-most "Received" header is where the email originated; each one above it is a subsequent server in the relay chain.

**From** (also called "Header From") — the display name and email address the *sender chose to show*. This can be completely fabricated! Attackers set "From: CEO John Smith \<ceo@your-company.com\>" even when sending from attacker@gmail.com. Never trust the From field alone.

**Reply-To** — when you click "Reply," your email client sends the reply to the Reply-To address, not necessarily the From address. Attackers use a legitimate-looking From address but set Reply-To to attacker@gmail.com so your response goes to them, not the company.

**Return-Path** (also called "Envelope From" or "MAIL FROM") — the technical address where bounced emails are sent. This is what SPF checks. If From shows "ceo@corp.com" but Return-Path is "attacker@phishing-domain.com," that is a spoofing red flag.

**X-Originating-IP** — the original IP address of the email sender, often added by webmail systems. Tracing this IP tells you where the email actually came from geographically.

**Authentication-Results** — added by the receiving mail server, this header contains the results of SPF, DKIM, and DMARC checks. This is the most important header for detecting spoofing.

**Message-ID** — a unique identifier for the email, formatted like \<string@domain\>. The domain in the Message-ID should match the sending domain. If it does not, that is suspicious.

**X-Mailer** — the mail client software used to send the email. Many marketing tools, phishing kits, and legitimate clients populate this field differently.

**Tools for header analysis:** MXToolbox Header Analyzer (mxtoolbox.com/EmailHeaders.aspx) and Google Admin Toolbox Messageheader (toolbox.googleapps.com/apps/messageheader/) both parse raw headers into a readable format. Paste the full raw headers in, and they highlight delays, path anomalies, and authentication failures.`,
    },

    // ── Reading 2: SPF, DKIM, and DMARC ──────────────────────────────────
    {
      type: "reading" as const,
      id: "email-sec-r2",
      heading: "Email Authentication — SPF, DKIM, and DMARC",
      content: `The three email authentication standards — SPF, DKIM, and DMARC — work together to verify that an email actually came from who it claims it came from. Think of them as a three-lock security system: SPF checks the return address, DKIM checks the signature, and DMARC sets the policy for what happens when the checks fail.

**SPF — Sender Policy Framework**

SPF answers the question: **"Is this mail server authorised to send email for this domain?"**

A domain owner publishes an SPF record as a DNS TXT record that lists all the mail servers (IPs or hostnames) that are allowed to send email on behalf of that domain. When a receiving mail server gets an email claiming to be from corp.com, it checks the SPF record for corp.com and verifies that the sending server's IP is on the list.

Example SPF record: \`v=spf1 include:_spf.google.com include:mail.corp.com ip4:203.0.113.42 ~all\`

Reading this: "Version is SPF1. Trust all IPs in Google's SPF record, trust mail.corp.com, trust IP 203.0.113.42. For everything else, soft-fail (~all)."

**SPF results:**
- **pass** — the sending server is authorised. Good.
- **fail (-all)** — the sending server is explicitly not authorised. Reject or mark as spam.
- **softfail (~all)** — the sending server is probably not authorised. Mark as suspicious but deliver.
- **neutral (?all)** — the domain makes no assertion about authorisation. Common in misconfigured domains.
- **none** — no SPF record exists. Cannot verify. Common in small organisations.

**DKIM — DomainKeys Identified Mail**

DKIM answers: **"Was this email cryptographically signed by the domain it claims to come from, and was it modified in transit?"**

When an email is sent, the sending mail server calculates a cryptographic signature over certain header fields and the email body, using a private key. This signature is added to the email as the **DKIM-Signature** header. The corresponding public key is published in DNS at a special subdomain.

When the receiving server checks DKIM, it fetches the public key from DNS and verifies the signature. If the signature matches, the email was:
1. Sent by someone with access to the private key (proving the domain sent it)
2. Not modified in transit (any modification would invalidate the signature)

Key fields in the DKIM-Signature header:
- **d=** the signing domain (should match the From domain)
- **s=** the selector (used to look up the public key in DNS: selector._domainkey.domain.com)
- **b=** the base64-encoded signature itself
- **h=** the list of headers that were signed

**DMARC — Domain-based Message Authentication Reporting and Conformance**

DMARC is the **policy layer** on top of SPF and DKIM. It answers: **"What should you do with email that fails SPF or DKIM?"**

A domain publishes a DMARC record in DNS as a TXT record at _dmarc.domain.com. It defines a policy (p=):
- **p=none** — do nothing special with failing email; just report it to the domain owner (monitoring mode).
- **p=quarantine** — move failing email to the spam/junk folder.
- **p=reject** — block failing email entirely; do not deliver it at all.

DMARC also adds **alignment checking** — the From domain must match the Return-Path (for SPF alignment) or the DKIM d= field (for DKIM alignment). This prevents attackers from passing SPF with a different domain than what appears in the From header.

**DMARC Reports:**
- **RUA (Aggregate reports)** — daily summary sent to the domain owner listing all sources that sent email claiming to be from their domain and what the SPF/DKIM results were. Useful for discovering if someone is spoofing you.
- **RUF (Forensic reports)** — individual copies of failing emails. Less commonly used due to privacy concerns.

**The Big Picture — How These Work Together**

If a phishing email claims to be from ceo@corp.com:
1. SPF checks if the sending IP is in corp.com's SPF record. If the attacker sends from their own server: **SPF fail**.
2. DKIM checks if the email is signed with corp.com's private key. The attacker does not have corp.com's key: **DKIM none or fail**.
3. DMARC sees both checks failed and applies the policy. If corp.com has p=reject: **email blocked**.

If corp.com has no DMARC policy, the email still reaches the inbox even with SPF fail and no DKIM. This is why publishing a DMARC record (even starting with p=none to observe before enforcing) is a fundamental email security control.`,
    },

    // ── Reading 3: Email Attack Types & Analysis Workflow ────────────────
    {
      type: "reading" as const,
      id: "email-sec-r3",
      heading: "Email Attacks and the SOC Analysis Workflow",
      content: `Now you understand how email works and how authentication protects it. Let us look at how attackers exploit email and how a SOC analyst investigates a suspicious email.

**Common Email Attack Types**

**Phishing** — mass emails sent to many recipients, trying to trick a percentage of them into clicking a link or opening an attachment. Usually impersonates a well-known brand (Microsoft, PayPal, Netflix) or a common business scenario (password expiry, invoice, package delivery).

**Spear Phishing** — targeted phishing aimed at a specific person. The attacker researches the target (LinkedIn, company website, social media) and crafts an email that is highly relevant to that person's job and relationships. Much more convincing than generic phishing.

**Whaling** — spear phishing targeting senior executives (CEO, CFO, CISO). These executives have authority to approve wire transfers and access sensitive systems, making them high-value targets.

**BEC (Business Email Compromise)** — the attacker either compromises a real executive email account or spoofs one convincingly, then emails the finance team requesting an urgent wire transfer. In 2023, BEC caused over $2.9 billion in losses (FBI IC3 report). The "urgent wire transfer" email in our log analysis example is a classic BEC attempt.

**Malicious Attachments** — common file types used:
- **.docm / .xlsm** — Office files with macros. The attacker convinces the user to "Enable Macros," which runs code.
- **.pdf** — can exploit vulnerable PDF readers or contain malicious links.
- **.html** — often used to host a credential harvesting page that runs entirely in the browser, bypassing gateway URL scanners.
- **.iso / .zip** — archive files that contain executables, bypassing email gateway attachment filters.
- **.lnk** — Windows shortcut files that run commands when opened.

**Malicious Links** — attackers use several techniques to bypass URL filters:
- URL shorteners (bit.ly, TinyURL) to hide the real destination
- Typosquatted domains (corpor4te.com vs corporate.com)
- Legitimate file hosting services (Google Drive, OneDrive, Dropbox) hosting malicious files
- Time-delayed activation — the link is safe when scanned at delivery time but becomes malicious hours later

**The SOC Email Analysis Workflow**

When a suspicious email is reported (by a user, by your email gateway alert, or by a SIEM rule), follow this workflow:

**Step 1 — Collect the raw email.** Get the full email including raw headers (.eml or .msg format). Do not just look at what the mail client shows — the headers contain critical evidence invisible in the email client.

**Step 2 — Analyse headers.** Use MXToolbox or Google Messageheader to parse the headers. Note:
- Authentication-Results (SPF/DKIM/DMARC pass or fail)
- X-Originating-IP (where did it actually come from?)
- Discrepancies between From, Reply-To, and Return-Path

**Step 3 — Check sender reputation.** If the sending IP is external, look it up in threat intelligence: VirusTotal (virustotal.com), AbuseIPDB (abuseipdb.com), MXToolbox Blacklists. Is the IP known-malicious? Is the domain newly registered? Does the domain look like a typosquat?

**Step 4 — Analyse URLs safely.** Never click links directly. Instead:
- Hover to reveal the real URL (not the display text)
- Use URLscan.io to safely visit the URL in an isolated browser and see a screenshot
- Use VirusTotal to check the URL against security vendors
- Check the domain's registration date (WHOIS) — phishing domains are often \<30 days old

**Step 5 — Analyse attachments safely.** Never open attachments on your workstation. Instead:
- Check the file hash (SHA256) in VirusTotal
- Submit to an online sandbox (Any.run, Joe Sandbox, Hybrid Analysis) to see what it does when executed in an isolated environment
- Extract URLs from within the attachment using tools like PDF-parser or olevba (for Office files)

**Step 6 — Determine scope.** Query your email gateway logs: how many employees received this email? Did anyone click the link or open the attachment? Who interacted with it, and when?

**Step 7 — Respond.** Based on your analysis:
- If malicious: quarantine/delete the email from all mailboxes, block the sender domain and IP in your email gateway, investigate any users who interacted with it
- Notify affected users and provide guidance
- Write up the case`,
    },

    // ── Question 1 ───────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "email-sec-q1",
      question: "When reading email Received headers to trace the email path, in which direction do you read them?",
      options: [
        "Top to bottom — the first Received header shows the original sender",
        "Bottom to top — the bottom-most Received header is where the email originated",
        "The order does not matter — all Received headers contain the same information",
        "Left to right within each header — the leftmost IP is always the sender",
      ],
      answer: 1,
      explanation:
        "Each mail server that handles an email prepends (adds to the top) its own Received header. This means the most recent hop is at the top and the original source is at the bottom. Reading bottom-to-top traces the email's journey from origin to destination. The bottom-most Received header shows the very first mail server that accepted the email — this is the closest to the actual sender and the most important for determining the true origin of the message.",
      xp: 25,
    },

    // ── Question 2 ───────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "email-sec-q2",
      question: "An email shows 'From: CEO John Smith <ceo@corp.com>' but the Authentication-Results header shows 'spf=fail'. What does this most likely mean?",
      options: [
        "The CEO's email account was hacked — change the password immediately",
        "The email was sent from a server not authorised in corp.com's SPF record, suggesting spoofing",
        "SPF is an optional check and the fail can be ignored",
        "The email was delayed in transit, causing the SPF check to time out",
      ],
      answer: 1,
      explanation:
        "SPF fail means the mail server that actually sent this email is NOT listed in corp.com's SPF record — in other words, it is not an authorised mail server for that domain. When combined with a From address showing ceo@corp.com, this strongly suggests email spoofing: an attacker fabricated the From address to look like the CEO, but sent the email from their own (unauthorised) mail server. SPF check results are based on the technical sending server IP, not what is displayed in the From field. An SPF fail on a high-value sender like the CEO is a high-priority alert.",
      xp: 25,
    },

    // ── Question 3 ───────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "email-sec-q3",
      question: "What is a BEC (Business Email Compromise) attack?",
      options: [
        "A brute-force attack against the company's email server login page",
        "Malware that encrypts all email attachments for ransom",
        "An attack where the attacker impersonates an executive to trick employees into wire transfers or data disclosure",
        "A phishing campaign targeting business email providers like Microsoft 365",
      ],
      answer: 2,
      explanation:
        "Business Email Compromise (BEC) is a social engineering attack where the attacker impersonates a senior executive (CEO, CFO) — either by compromising their real account or by spoofing the From address — and emails employees with authority to transfer funds or share sensitive data. The email typically creates urgency ('urgent wire transfer', 'confidential deal', 'need your social security number for payroll'). BEC is one of the most financially damaging attacks: in 2023 alone it caused nearly $3 billion in reported losses (FBI). The 'URGENT: Approve Wire Transfer $250,000' email in our log analysis is a textbook BEC attempt.",
      xp: 25,
    },

    // ── Log Analysis ─────────────────────────────────────────────────────
    {
      type: "log_analysis" as const,
      id: "email-sec-la1",
      heading: "Phishing Email Analysis — Failed Authentication and Suspicious Headers",
      context: `A finance department employee has forwarded a suspicious email to the SOC after becoming suspicious of a wire transfer request. Your email gateway captured the following metadata when the email arrived. Analyse the header fields carefully — several indicators point to email spoofing and a BEC (Business Email Compromise) attempt. Pay particular attention to the difference between what the email *shows* and what the authentication headers *reveal*.`,
      event: {
        id: "email-sec-la1-evt-001",
        ts: "2025-06-24T11:07:33.000Z",
        source: "email_gateway",
        event_type: "email_received",
        severity: "high",
        user_email: "finance@corp.com",
        src_ip: "185.220.101.45",
        description: "Suspected BEC phishing: spoofed CEO email with SPF/DKIM/DMARC failure and suspicious Reply-To",
        mitre_technique: "T1566.001 - Phishing: Spearphishing Attachment / T1078 - Valid Accounts",
        raw: {
          "email.from": "ceo@corp-secure.com",
          "email.reply_to": "attacker@gmail.com",
          "email.to": "finance@corp.com",
          "email.subject": "URGENT: Approve Wire Transfer $250,000",
          "email.message_id": "<abc@mail-out.corp-secure.com>",
          "email.x_originating_ip": "185.220.101.45",
          "email.authentication_results":
            "spf=fail smtp.mailfrom=corp-secure.com; dkim=none; dmarc=fail",
          "email.received_from": "mail-out.corp-secure.com [185.220.101.45]",
          "email.attachment": "invoice_approval.html",
          "email.header_from": "CEO John Smith <ceo@corp-secure.com>",
        },
      } satisfies TelemetryEvent,
      questions: [
        {
          question: "The email shows 'CEO John Smith <ceo@corp-secure.com>' in the From field. Which header field reveals that replies would actually go to an attacker's address?",
          options: [
            "email.message_id — the Message-ID shows the real destination",
            "email.reply_to — set to attacker@gmail.com instead of the company domain",
            "email.x_originating_ip — the IP address reveals the attacker's identity",
            "email.authentication_results — the DMARC fail reveals the reply destination",
          ],
          answer: 1,
          explanation:
            "The email.reply_to field is set to attacker@gmail.com — a completely different domain from the purported sender (corp-secure.com). When the finance employee clicks 'Reply,' their email client will automatically address the reply to attacker@gmail.com, not to the CEO. The attacker then receives the reply (which might include a confirmation of the wire transfer or sensitive financial details). This Reply-To mismatch is a classic BEC technique — the From address looks legitimate but all correspondence goes to the attacker.",
          xp: 35,
        },
        {
          question: "The attachment is named 'invoice_approval.html'. Why is an HTML file particularly dangerous as a phishing attachment?",
          options: [
            "HTML files can contain viruses that spread through Wi-Fi",
            "HTML files run in the browser, allowing a credential harvesting page to display without triggering email gateway attachment scanners that look for executables",
            "HTML attachments are always blocked by Microsoft 365",
            "HTML files automatically forward the user's password to the attacker",
          ],
          answer: 1,
          explanation:
            "HTML phishing attachments are increasingly popular because they bypass many email gateway attachment scanners. Traditional scanners look for executable files (.exe, .docm with macros), but an HTML file is just a web page. When the victim opens invoice_approval.html, it displays a realistic-looking login page (e.g., fake Microsoft 365 login) entirely within the browser. The browser then sends the entered credentials to the attacker's server. Because the page runs locally from the attachment (not from a URL that can be scanned), it often evades URL reputation checks too. HTML credential harvesters are one of the fastest-growing phishing techniques.",
          xp: 35,
        },
      ],
    },

    // ── Flag Task ─────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "email-sec-flag1",
      prompt: `In the phishing email log above, the attacker set the Reply-To header to redirect any replies away from the CEO and to an attacker-controlled address. Enter the exact email address found in the email.reply_to field.`,
      answer: "attacker@gmail.com",
      hint: "Look at the email.reply_to field in the raw log. The attacker used a free webmail provider, not the company domain.",
      xp: 40,
    },

    // ── Question 4 ───────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "email-sec-q4",
      question: "A domain publishes a DMARC policy of 'p=none'. What action does the receiving mail server take when an email from that domain fails SPF and DKIM?",
      options: [
        "The email is immediately rejected and never delivered to the recipient",
        "The email is moved to the recipient's spam/junk folder",
        "The email is delivered normally — p=none means 'take no action, just report'",
        "The email is held in quarantine for 24 hours before delivery",
      ],
      answer: 2,
      explanation:
        "DMARC p=none is 'monitoring mode' — it instructs receiving servers to take no special action on failing emails and just send aggregate reports back to the domain owner. The email is delivered normally (or goes to spam based on the email gateway's own spam filters, but not because of DMARC). p=none is a common starting point for organisations deploying DMARC for the first time — they observe the reports to ensure legitimate email is passing before moving to p=quarantine or p=reject. However, it provides no protection against spoofing during the monitoring phase.",
      xp: 25,
    },
  ],
};

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

const rooms = [
  investigationMethodology,
  threatHuntingFundamentals,
  digitalForensicsBasics,
  emailSecurity,
];

export default rooms;
