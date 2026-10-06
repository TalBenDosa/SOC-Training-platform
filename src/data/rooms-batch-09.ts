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
  xp: 280,
  icon: "🔬",
  prerequisites: ["alert-triage", "windows-event-logs", "timestamps-and-timelines"],
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
      checkpoint: {
        question: "An analyst built a clean timeline and is now writing the ticket, but it has no verdict and does not say which systems or data were affected. Which phase was skipped?",
        options: [
          "Phase 2 — Scope",
          "Phase 3 — Collect",
          "Phase 5 — Conclude",
          "Phase 6 — Document",
        ],
        answer: 2,
        explanation: "Phase 5 (Conclude) is where you form the verdict (true positive, false positive or inconclusive) and, for a true positive, state what the attacker did, which systems are affected and what data may have been accessed. “Phase 2 — Scope” is an early estimate of how big the incident might be, made before the data is pulled, not the final finding. “Phase 3 — Collect” was clearly done, because a timeline exists. “Phase 6 — Document” is the phase the analyst is in now; it records the conclusion but cannot replace reaching one.",
      },
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

Rule: always work in UTC. When you pull events from your SIEM, confirm it is showing UTC. Windows Event Log records store TimeCreated in UTC; it is the Event Viewer display that converts them to the viewer's local time, so check which view you are reading. Text logs are the usual local-time trap: many application logs, some syslog sources and IIS logs in the older IIS/NCSA formats (W3C-format IIS logs are UTC) write in the server's local zone without an offset — convert those. Most SIEM platforms (Microsoft Sentinel, Splunk, Elastic) normalize to UTC automatically, but always verify.

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
      checkpoint: {
        // Asked as a scenario rather than "which timezone?" on purpose. The bare
        // answer to that version is "UTC" — three characters against three long
        // phrases, which a student can pick off by shape without knowing why.
        question: "You are building one timeline from an Eastern-Time endpoint and a Pacific-Time mail server. According to the reading, how should you handle the timestamps?",
        options: [
          "Leave each event in its source system's own local time, noting the offset alongside each entry",
          "Convert every timestamp to UTC before ordering the events into a single sequence",
          "Convert everything to the SIEM server's local timezone, since that is where the timeline is assembled",
          "Convert everything to your own local timezone so the sequence reads naturally at handover",
        ],
        answer: 1,
        explanation: "The reading's rule is: always work in UTC. Mixing local timezones (an Eastern-Time endpoint, a Pacific-Time mail server) puts events in the wrong order, and a timeline whose order is wrong is worse than no timeline — it invents causation that never happened. Leaving each event in its source timezone pushes that conversion onto every future reader, and normalising to the SIEM's or your own timezone just picks a different arbitrary offset that breaks the moment someone in another region opens the case.",
      },
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
- The authentication package on network logons. In an Active Directory domain Kerberos is the default. A 4624 Type 3 logon that uses NTLM where Kerberos is expected deserves a look, because Pass-the-Hash (logging on with a stolen password hash instead of the password) produces NTLM authentications. NTLM also has ordinary causes, such as a server addressed by IP address or an older system, so treat it as a signal to corroborate, not as proof.

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
      question: "An alert names one server. Its local Security log rolls over about every 6 hours, and only part of it reaches the SIEM. You have scoped the case. What do you do next?",
      options: [
        "Analyse the alert on its own first, and pull host logs once you know what to look for",
        "Record the case as inconclusive now, since the evidence will roll before you finish",
        "Pull the server's logs and telemetry now, before rotation overwrites them, then analyse",
        "Reboot the server to stop any activity, then collect its logs once it is back up",
      ],
      answer: 2,
      explanation:
        "This is Phase 3 (Collect): pull the evidence before it is overwritten, then move to analysis. “Analyse the alert on its own first” reverses Collect and Analyze, and with a 6-hour rotation the logs you need may be gone by the time you know what to look for. “Record the case as inconclusive now” gives up on evidence you can still save. “Reboot the server” destroys memory evidence and still leaves the log rotation problem.",
      xp: 30,
    },

    // ── Question 2 ───────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "inv-method-q2",
      question: "One host's firewall log shows beacons to an external IP you suspect is C2. Which pivot best reveals other infected machines?",
      options: [
        "Every system the host's logged-on user accessed in the last 30 days",
        "Every internal host that connected to that IP in the time window",
        "Every connection the suspicious process on that host has made",
        "The IP's reputation and history in VirusTotal and AbuseIPDB",
      ],
      answer: 1,
      explanation:
        "The IP → hosts pivot searches all internal traffic to that IP, so any other machine checking in with the same C2 server shows up. “Every system the host's logged-on user accessed” is a user → systems pivot: it finds lateral movement by that one account, not other machines infected through other users. “Every connection the suspicious process has made” is a process → network pivot on the same single host. “The IP's reputation” is enrichment: it tells you about the IP, not which of your machines talked to it.",
      xp: 30,
    },

    // ── Question 3 ───────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "inv-method-q3",
      question: "You merge three sources into one UTC timeline: Security events read from an exported EVTX file, an IIS log in the older NCSA format from a server set to UTC+2, and Sentinel query results. Which one most likely needs manual conversion?",
      options: [
        "The EVTX events, because Windows stores event times in the host's local zone",
        "The NCSA-format IIS log, because it is written in local time with no offset",
        "The Sentinel results, because a SIEM keeps each event in its source's zone",
        "All three equally, because every source logs in its own host's local time zone",
      ],
      answer: 1,
      explanation:
        "Older IIS/NCSA-format logs are written in the server's local time without an offset, so these UTC+2 entries must be shifted by two hours before they are ordered. “The EVTX events” is a common trap: EVTX stores TimeCreated in UTC, and only the Event Viewer display converts it to local time. “The Sentinel results” is wrong because Sentinel, like most SIEMs, normalises event times to UTC (still worth confirming, but not the source that needs conversion). “All three equally” ignores that two of the three are already UTC.",
      xp: 30,
    },

    // ── Log Analysis ─────────────────────────────────────────────────────
    {
      type: "log_analysis" as const,
      id: "inv-method-la1",
      heading: "Investigating Lateral Movement — Suspicious Service Account Logon",
      context: `You are a Tier 2 SOC analyst and the SIEM has escalated an alert about a service account authentication. Service accounts are a high-value target for attackers because they often have elevated privileges. Business context from your asset inventory: svc-backup is a scheduled backup service account that should only ever authenticate from the backup server SRV-BACKUP-01. Your job is to examine the Windows Security Event below and determine whether this logon is legitimate or suspicious.`,
      event: {
        id: "inv-la1-evt-001",
        ts: "2025-06-24T03:17:42.000Z",
        source: "windows_security",
        event_type: "auth_success",
        severity: "high",
        hostname: "SRV-FINANCE-02",
        user_email: "svc-backup@corp.local",
        src_ip: "10.0.1.45",
        description: "Windows Security 4624 logon for svc-backup on SRV-FINANCE-02",
        mitre_technique: "T1078.002 - Valid Accounts: Domain Accounts",
        vendor: "Windows Security",
        raw: {
          "event.code": "4624",
          "winlog.event_data.TargetUserName": "svc-backup",
          "winlog.event_data.LogonType": "3",
          "winlog.event_data.IpAddress": "10.0.1.45",
          "winlog.event_data.WorkstationName": "WS-DEV-09",
          "winlog.event_data.AuthenticationPackageName": "NTLM",
          "winlog.event_data.ElevatedToken": "%%1842",
        },
      } satisfies TelemetryEvent,
      questions: [
        {
          question: "Checked against the asset-inventory note, which field shows this logon breaks svc-backup's expected pattern?",
          options: [
            "winlog.event_data.LogonType = 3 (network)",
            "winlog.event_data.WorkstationName = WS-DEV-09",
            "winlog.event_data.ElevatedToken = %%1842 (yes)",
            "event.code = 4624 (successful logon)",
          ],
          answer: 1,
          explanation:
            "WorkstationName shows where the authentication came from: WS-DEV-09, a developer workstation, while the inventory says svc-backup authenticates only from SRV-BACKUP-01. Either WS-DEV-09 is compromised or the credentials are being used from another machine. “LogonType = 3” is a network logon, which is exactly how a backup account normally reaches a server, so it is not the deviation. “ElevatedToken = %%1842” means the session got an elevated token, which is expected for a backup account with high privileges. “event.code = 4624” only says a logon succeeded.",
          xp: 40,
        },
        {
          question: "The logon used NTLM. How should you weigh that in this investigation?",
          options: [
            "Low value: NTLM is the normal default for domain network logons",
            "A real signal: NTLM where Kerberos is expected fits Pass-the-Hash",
            "Conclusive: NTLM from a service account proves Pass-the-Hash",
            "An artefact: event 4624 reports NTLM for every Type 3 logon",
          ],
          answer: 1,
          explanation:
            "In an Active Directory domain Kerberos is the default, and Pass-the-Hash (logging on with a stolen hash instead of the password) produces NTLM authentications. Combined with the unexpected workstation, NTLM strengthens the lateral-movement hypothesis, but it still needs corroboration (what WS-DEV-09 ran, other logons by svc-backup). “NTLM is the normal default” is wrong: that is Kerberos. “Proves Pass-the-Hash” overreaches, because NTLM also has ordinary causes such as a server addressed by IP. “4624 reports NTLM for every Type 3 logon” confuses logon type with authentication package: network logons can use Kerberos or NTLM.",
          xp: 40,
        },
      ],
    },

    // ── Flag Task ─────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "inv-method-flag1",
      prompt: `Your next step is the IP address → hosts pivot from the timeline reading: find everything else the machine that used svc-backup's credentials has been doing. Which value do you search the SIEM for? Enter it exactly as it appears in the log.`,
      answer: "10.0.1.45",
      hint: "You want the address of the machine the logon came from, not the server that received it.",
      xp: 50,
    },

    // ── Question 4 ───────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "inv-method-q4",
      question: "In SIEM workflow Step 5 you search svc-backup's activity after the logon above. Which result is a lateral-movement indicator rather than something else?",
      options: [
        "7-Zip compressing a finance share on SRV-FINANCE-02 an hour later",
        "Event 7045: a new service installed on SRV-HR-01 minutes later",
        "A new O365 inbox forwarding rule created on a finance mailbox",
        "Large outbound byte counts from SRV-FINANCE-02 to a file-sharing site",
      ],
      answer: 1,
      explanation:
        "A new service installed on another host (Event ID 7045) right after the suspicious logon is a Step 5 lateral-movement indicator: the account is being used to run code on a second machine. “7-Zip compressing a finance share” is compression on a sensitive directory, a Step 6 exfiltration indicator. “A new O365 inbox forwarding rule” is also listed under exfiltration. “Large outbound byte counts to a file-sharing site” is the classic exfiltration sign. All three matter for the case, but none shows movement to another host.",
      xp: 30,
    },

    // ── Question 5 ───────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "inv-method-q5",
      question: "A senior analyst must re-check your true-positive case tomorrow without you. Which draft ticket lets them reproduce your evidence?",
      options: [
        "Summary, timeline, a screenshot of each result, affected assets, conclusion",
        "Summary, timeline, a saved query link per result, affected assets, conclusion",
        "Summary, timeline, names of the log sources searched, affected assets, conclusion",
        "Summary, timeline, the alert ID and rule name, affected assets, conclusion",
      ],
      answer: 1,
      explanation:
        "The reading asks for evidence links: direct links or saved query strings that another analyst can click and re-run, not screenshots. Only the draft with “a saved query link per result” makes the evidence reproducible. “A screenshot of each result” shows what you saw but cannot be re-run or extended. “Names of the log sources searched” says where you looked but not what you ran. “The alert ID and rule name” points back to the trigger only, not to the evidence you gathered after it. A complete ticket also needs the chain of events, actions taken and recommendations.",
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
  xp: 280,
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

A decade ago, industry reports put average attacker dwell time — the gap between initial compromise and detection — at **over 200 days**. That number has fallen a long way since (recent Mandiant M-Trends reporting puts the global median in the days-to-weeks range), but the shape of the problem has not changed: the median is pulled down by loud, fast ransomware that announces itself, while the patient intruder is precisely the one who does not. They establish a foothold, then quietly learn the environment — moving laterally, elevating privileges, identifying data — while blending in with legitimate activity. Automated detection rules catch obvious threats, but sophisticated attackers know how to operate beneath detection thresholds. Those are the ones still sitting inside networks for months, and they are who hunting exists for.

**Reactive vs. Proactive**

Your SIEM fires alerts reactively — something happened, a rule matched, you investigate. Threat hunting is proactive — you form a hypothesis about attacker behaviour and go searching for evidence of it, whether or not any alert has fired. If you find something, you have caught an attacker who would otherwise have gone undetected. If you find nothing, you have either ruled out a threat or discovered that your data coverage has a gap.

According to SANS 2024 research, **51% of organisations now run active threat hunting programs**, up from far fewer a decade ago. The discipline has become a core function of mature SOC teams.

**The Threat Hunting Maturity Model**

The Hunting Maturity Model (HMM), created by David Bianco at Sqrrl, defines **five** levels, HMM0 to HMM4. Each level is about *how much hunting the organisation can do on its own*:

**HMM0 — Initial.** The organisation relies on automated alerting (IDS, SIEM, antivirus) and collects little routine data. It is not really capable of hunting: if an attacker evades the alerts, they are invisible.

**HMM1 — Minimal.** Still mainly alert-driven, but analysts also search their data for indicators from threat-intelligence reports (IP addresses, domains, file hashes). This is the first, limited form of hunting.

**HMM2 — Procedural.** The team collects a lot of data and runs hunting procedures **created by others** — published playbooks, community hunt queries, vendor guidance — e.g. "search for any process that opens a handle to LSASS memory". Most hunting programmes sit here.

**HMM3 — Innovative.** The team **creates its own** new hunting procedures and analysis techniques for its environment, rather than only applying published ones.

**HMM4 — Leading.** Like HMM3, plus automation: every successful hunt procedure is **turned into automated detection**, so analysts keep spending their time on new hunts.

**Indicators vs. behaviours — the Pyramid of Pain**

A separate idea, David Bianco's Pyramid of Pain, explains *what* to hunt for. At the bottom are hash values, IP addresses and domain names, which attackers can change in minutes. At the top are TTPs (tactics, techniques and procedures), which are expensive to change. Instead of searching for a specific file hash, you search for the *technique* — e.g. any process that accesses LSASS memory (MITRE ATT\&CK T1003.001). That approach still works when attackers change their tools, because they cannot easily change their fundamental behaviour. **Moving from indicator-hunting to behaviour (TTP) hunting is the most important leap a SOC team can make.**`,
      checkpoint: {
        question: "Your team already writes its own hunt procedures. According to the Hunting Maturity Model, what distinguishes the next level (HMM4 — Leading) from where you are now?",
        options: [
          "It adds searches for threat-intelligence indicators such as IPs, domains and hashes",
          "It starts following hunt procedures published by others",
          "Every successful hunt procedure is turned into automated detection",
          "It switches from routine data collection to relying on automated alerts",
        ],
        answer: 2,
        explanation: "Writing your own procedures is HMM3 (Innovative). HMM4 (Leading) is HMM3 plus automation: each successful hunt is operationalised as automated detection, so analysts can keep hunting for new things. Indicator searches describe HMM1, following others' procedures describes HMM2, and relying on automated alerts describes HMM0.",
      },
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

This last step is crucial: threat hunting improves your detection capability over time. Every confirmed hunt finding should produce a new detection rule. A confirmed finding is also a live incident, so it is handed to incident response first, with the evidence preserved, and the rule is written alongside.`,
      checkpoint: {
        question: "Your hunt confirmed rundll32.exe dumping LSASS on one laptop, and IR has taken the case. Which Hunt Cycle step turns this one hunt into a lasting improvement in the SOC’s coverage?",
        options: [
          "Document the hunt so the next hunter can re-run the same query by hand each quarter",
          "Convert the finding into a SIEM detection rule that fires on the next occurrence",
          "Add the dump file's hash to the EDR blocklist so that exact file cannot run again",
          "Schedule the same hunt as a recurring monthly hunt across the whole estate",
        ],
        answer: 1,
        explanation: "The last step of the Hunt Cycle converts a confirmed finding into a new detection rule, so the next occurrence raises an alert automatically and hunters can move on to new hypotheses. “Document the hunt…” is a real step (documentation), but a query someone re-runs by hand is still manual coverage. “Add the dump file's hash…” sits at the bottom of the Pyramid of Pain: a renamed or regenerated dump file has a different hash. “Schedule the same hunt as a recurring monthly hunt…” leaves up to a month of blindness between runs, where a rule watches continuously.",
      },
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
- PowerShell launching from unusual parents (Word, Excel, Outlook, mshta.exe). Find them by **stacking**: count each parent → child pair across the fleet and read the rare end first. A pair seen on thousands of hosts is usually baseline; a pair on a handful of hosts is where the hunt starts, and you then check those hosts against known add-ins or scripts.
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
      question: "Industry dwell-time figures have fallen a long way over the last decade — from roughly 200 days to a global median now measured in days-to-weeks. Why does that improvement NOT remove the case for proactive threat hunting?",
      options: [
        "Dwell time measures containment after an incident is declared, so it says nothing about detection",
        "The median mixes two populations: noisy ransomware pulls it down while quiet intruders stay hidden",
        "The drop comes mostly from cloud workloads, while on-premises dwell times have barely improved",
        "Hunting is required by most compliance frameworks, so faster detection does not change the need",
      ],
      answer: 1,
      explanation:
        "A median is the middle of a distribution, and this one holds two very different populations. Ransomware announces itself within hours or days and is common enough to pull the median down, while a careful espionage actor using valid credentials and built-in tools can still go unnoticed for months; hunting targets that second group. “Dwell time measures containment…” gets the definition wrong: dwell time is the gap between compromise and detection. “The drop comes mostly from cloud workloads…” is not what the reading says and does not explain why hunting is still needed. “Hunting is required by most compliance frameworks…” swaps the security reason for a compliance claim the reading never makes.",
      xp: 30,
    },

    // ── Question 2 ───────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "threat-hunt-q2",
      question: "Last month you blocked the IPs, domains and file hashes from a threat report on an intrusion group. This month the same group returns with new servers and a recompiled loader, but still dumps LSASS with rundll32.exe and comsvcs.dll. Which hunt is most likely to find them, and why?",
      options: [
        "A hunt for last month's IPs, domains and hashes, since groups tend to reuse their infrastructure",
        "A hunt for rundll32.exe loading comsvcs.dll MiniDump, since that behaviour is costly to change",
        "A hunt for newly registered domains, since fresh infrastructure is the trace a returning group leaves",
        "A hunt for the new loader's hash once a vendor publishes it, since hashes are the most precise match",
      ],
      answer: 1,
      explanation:
        "This is the Pyramid of Pain in practice: the group changed what is cheap to change (IPs, domains, hashes) and kept what is expensive (the technique), so a hunt for the comsvcs.dll MiniDump behaviour still finds them. “A hunt for last month's IPs, domains and hashes…” targets exactly the indicators they replaced. “A hunt for newly registered domains…” is a useful lead in general, but it is broad and noisy and finds no specific trace of this group. “A hunt for the new loader's hash once a vendor publishes it…” waits for someone else to catch the sample first and fails again at the next recompile.",
      xp: 30,
    },

    // ── Question 3 ───────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "threat-hunt-q3",
      question: "A hunt confirms that an attacker dumped LSASS on FIN-LAPTOP-07 yesterday, and the laptop is still online. What should happen first with this finding?",
      options: [
        "Keep it within the hunt team for now, so a wider response does not tip off the attacker",
        "Reimage the laptop at once, so the attacker loses the foothold before doing more damage",
        "Open an incident case for IR with the evidence preserved, then write the detection rule",
        "Write the detection rule first, so the case is opened when the rule fires on the activity",
      ],
      answer: 2,
      explanation:
        "A confirmed finding is a live incident: the stolen credentials may already be in use, so it goes to incident response with the evidence preserved, and the detection rule follows. “Keep it within the hunt team…” leaves an active compromise unhandled. “Reimage the laptop at once…” destroys the memory and disk evidence IR needs to scope what else the stolen credentials touched. “Write the detection rule first…” gets the order wrong: the rule protects against the next occurrence, while this one is happening now.",
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
          "crowdstrike.SHA256": "4cf5dc08b46013844c4fea30389c492ad9f704dd3fe1f3ab7ccd1148e767bd55",
        },
      } satisfies TelemetryEvent,
      questions: [
        {
          question: "What is the purpose of the number '640' in the command line 'rundll32.exe comsvcs.dll MiniDump 640 lsass.dmp full'?",
          options: [
            "It is the TCP port the dump file will be sent to",
            "It is the Process ID (PID) of the LSASS process being dumped",
            "It is the access mask the tool requests on the target process",
            "It is the session ID of the logon that owns the dumped process",
          ],
          answer: 1,
          explanation:
            "In the comsvcs.dll MiniDump technique, the syntax is: MiniDump [PID] [output_file] [full]. The number 640 is the Process ID of the LSASS process on this machine. The attacker first ran 'tasklist' or similar to find LSASS's PID, then plugged it into this command to dump that specific process's memory to a file called lsass.dmp. This file would then contain password hashes, Kerberos tickets, and potentially cleartext credentials that the attacker can use to move laterally.",
          xp: 40,
        },
        {
          question: "Your EDR blocks known credential-dumping tools such as mimikatz.exe and procdump.exe by name and hash. Why can this comsvcs.dll technique still get through?",
          options: [
            "comsvcs.dll exploits an unpatched LSASS flaw, so signature updates cannot cover it yet",
            "It runs signed Windows components, so name and hash blocklists for dumping tools never match",
            "It injects code into lsass.exe, so the dump is written by a trusted process and is not logged",
            "It renames procdump.exe to rundll32.exe, so name-based rules end up checking the wrong file",
          ],
          answer: 1,
          explanation:
            "This is living off the land: rundll32.exe and comsvcs.dll are legitimate, Microsoft-signed parts of Windows, so a blocklist of dumping-tool names and hashes has nothing to match, and defenders have to judge what the binary is doing (MiniDump of LSASS) rather than what it is. “…exploits an unpatched LSASS flaw…” describes a zero-day; MiniDump is a documented export working as designed. “It injects code into lsass.exe…” is process injection, a different technique; here rundll32.exe reads LSASS and writes the dump itself, and the EDR logged it. “It renames procdump.exe…” is masquerading; the command line shows the real rundll32.exe calling comsvcs.dll.",
          xp: 40,
        },
      ],
    },

    // ── Flag Task ─────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "threat-hunt-flag1",
      prompt: `The log analysis event above is a confirmed LSASS dump. Your next pivot is one level up the process tree: whatever launched rundll32.exe is how the attacker got a command line on this laptop. Enter the image name of that launching process, including the .exe extension.`,
      answer: "cmd.exe",
      hint: "The raw event records the process that started rundll32.exe as well as rundll32.exe itself.",
      xp: 50,
    },

    // ── Question 4 ───────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "threat-hunt-q4",
      question: "You stack 30 days of process-creation events from 2,000 workstations by parent → child pair and count the hosts per pair. Which result is the strongest lead for a macro-execution hunt?",
      options: [
        "explorer.exe → powershell.exe on 1,412 hosts, spread evenly across the month",
        "svchost.exe → powershell.exe on 1,980 hosts, recurring nightly at the same time",
        "winword.exe → powershell.exe on 3 hosts, all within the last six days",
        "outlook.exe → msedge.exe on 1,655 hosts, during working hours every day",
      ],
      answer: 2,
      explanation:
        "Stacking puts the rare end of the distribution first. Word starting PowerShell is the classic macro-execution chain, and three hosts in one week stands out against a fleet of 2,000. Some enterprise add-ins do launch scripts, which is why you baseline and check those three hosts rather than alert blindly. “explorer.exe → powershell.exe on 1,412 hosts…” is users and admins opening PowerShell themselves, which is baseline at that volume. “svchost.exe → powershell.exe on 1,980 hosts…” is a fleet-wide scheduled job. “outlook.exe → msedge.exe on 1,655 hosts…” is people clicking links in mail, which is normal behaviour.",
      xp: 30,
    },

    // ── Question 5 ───────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "threat-hunt-q5",
      question: "Proxy logs show four workstations talking to external hosts during the same hour. Which one is most likely beaconing to C2?",
      options: [
        "WS-11: 14 requests at gaps of 2 s to 9 min, varied response sizes, many other sites visited",
        "WS-27: 60 requests at gaps of 55–65 s, every response 220 bytes, one IP and nothing else",
        "WS-34: three 40–60 MB uploads to a file-sharing site at 09:00, 09:30 and 10:00 exactly",
        "WS-42: 200 requests to a CDN within 5 minutes while a page loads, then no traffic at all",
      ],
      answer: 1,
      explanation:
        "Beaconing is malware checking in on a schedule: many small requests to the same destination at near-regular intervals (small jitter around 60 s here) with tiny, uniform responses. That describes WS-27. “WS-11…” is human browsing: irregular gaps, varied sizes and many sites. “WS-34…” is regular, but three large uploads is a data-transfer pattern (possibly a sync job, possibly exfiltration), not a check-in. “WS-42…” is a single burst from loading one page, with no repetition.",
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
  xp: 280,
  icon: "🔏",
  prerequisites: ["windows-event-logs", "linux-log-analysis", "timestamps-and-timelines"],
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

3. **Network connections** — the list of active TCP/UDP connections at this moment. Changes constantly as connections open and close. Run "netstat -ano" on Windows or "ss -tunap" on Linux to capture the current state (on Linux, "ss -tulpn" adds -l, which lists only LISTENING sockets and would miss an established C2 session, so keep it for checking listeners).

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
      checkpoint: {
        question: "You reach a compromised server that is still running. Of these four, which do you capture first?",
        options: [
          "A full disk image, since the disk holds the most data",
          "A RAM dump, since it changes constantly and dies at power-off",
          "The Security event log, since log rotation may overwrite it",
          "The latest backup, to fix a pre-incident baseline first",
        ],
        answer: 1,
        explanation: "RAM comes first: it is lost at power-off and keeps changing while the host runs, and it holds processes, connections, keys and fileless code. “A full disk image” is wrong because the disk persists; holding the most data does not make it urgent. “The Security event log” is wrong because rotation is a real risk, but it works over hours or days, not at power-off. “The latest backup” is the least volatile source of all and can wait.",
      },
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
- On Linux: the LiME (Linux Memory Extractor) kernel module or Microsoft's AVML (direct reads of /dev/mem are restricted on modern kernels).

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
- Parent process should be services.exe (PID often 804). If the parent is explorer.exe, cmd.exe, or PID 4 (System), it is suspicious.
- Path should be C:\\Windows\\System32\\svchost.exe. If it is running from AppData, Temp, or a user directory, it is malicious.
- Legitimate svchost.exe always has a "-k" argument (e.g., svchost.exe -k netsvcs). No argument = suspicious.`,
      checkpoint: {
        question: "You found an svchost.exe in a memory dump and want to check whether it was started with a “-k” argument. Which plugin shows that?",
        options: [
          "windows.pslist",
          "windows.pstree",
          "windows.cmdline",
          "windows.dlllist",
        ],
        answer: 2,
        explanation: "windows.cmdline shows the command-line arguments each process was launched with, so it shows whether svchost.exe has its “-k” group. “windows.pslist” gives PIDs, PPIDs, start times and paths, but not arguments. “windows.pstree” shows the parent-child hierarchy, which is another svchost check but not this one. “windows.dlllist” lists loaded libraries, not launch arguments.",
      },
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
      question: "On a live, compromised server a colleague plans to image the disk first and dump RAM afterwards. What is wrong with this plan?",
      options: [
        "Nothing, provided the server stays powered on until the RAM dump is done",
        "RAM keeps changing and is lost at power-off; the disk persists and can wait",
        "Event logs rotate fastest, so they should be collected before both of these",
        "Order does not matter as long as both images are hashed after collection",
      ],
      answer: 1,
      explanation:
        "RAM is the most volatile source: it changes while the host runs and is gone at power-off, while the disk persists and can be imaged later. “Nothing, provided the server stays powered on” is wrong because imaging can take 30+ minutes, during which in-memory malware can exit or clean up, so staying powered on is not enough. “Event logs rotate fastest” is wrong because logs sit on disk and rotate over hours or days; they are less volatile than RAM. “Order does not matter as long as both are hashed” confuses integrity with volatility: a hash proves the copy did not change after collection, but it cannot bring back memory that was lost before collection.",
      xp: 30,
    },

    // ── Question 2 ───────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "dfir-q2",
      question: "Two weeks after you dumped RAM from HOST-FINANCE-01, legal asks you to show the file has not changed since collection. What shows that?",
      options: [
        "The handler list on the custody form, showing only you accessed it",
        "Re-hashing the dump and matching the SHA256 recorded at collection",
        "Loading it in Volatility: if the plugins still parse it, it is intact",
        "The file's last-modified time still matching the collection time",
      ],
      answer: 1,
      explanation:
        "A SHA256 hash is a fingerprint of the exact bytes. If the hash you compute now matches the one recorded in the chain of custody at collection time, not one byte has changed. “The handler list on the custody form” records who touched the file, but a list of names cannot show the bytes are unchanged; the hash recorded on the same form does that. “If the plugins still parse it” is wrong because a modified dump can still parse perfectly. “The file's last-modified time” is metadata that can be changed or kept by copying tools, so it proves nothing about the content.",
      xp: 30,
    },

    // ── Question 3 ───────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "dfir-q3",
      question: "Memory analysis shows four svchost.exe instances. Which one matches a legitimate Service Host on every check the reading gives?",
      options: [
        "C:\\Windows\\System32\\svchost.exe, parent explorer.exe, args -k netsvcs",
        "C:\\Windows\\System32\\svchost.exe, parent services.exe, args -k netsvcs",
        "C:\\Windows\\System32\\svchost.exe, parent services.exe, no arguments",
        "C:\\Users\\jsmith\\AppData\\Roaming\\svchost.exe, parent services.exe, -k netsvcs",
      ],
      answer: 1,
      explanation:
        "A genuine svchost.exe passes all three checks: it runs from C:\\Windows\\System32, its parent is services.exe, and it carries a “-k” service-group argument. The instance with “parent explorer.exe” has the right path and argument, but a user shell does not start Service Host. The one with “no arguments” has the right path and parent but no “-k” group. The one under “AppData\\Roaming” uses the right name and parent but the wrong location, which is classic masquerading (T1036). One failed check is enough to investigate: always check path, parent and command line together.",
      xp: 30,
    },

    // ── Log Analysis ─────────────────────────────────────────────────────
    {
      type: "log_analysis" as const,
      id: "dfir-la1",
      heading: "Memory Forensics — Suspicious svchost.exe Process",
      context: `You are conducting memory forensics on a suspected compromised host using Volatility 3. You have run the "windows.pslist" plugin on a memory dump captured from HOST-FINANCE-03. The output below shows one of the svchost.exe entries. Analyse the event and answer the questions.`,
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
          "volatility.ppid": "4",
          "volatility.name": "svchost.exe",
          "volatility.offset": "0x0000be8f2a006080",
          "volatility.create_time": "2025-06-24T14:31:55Z",
        },
      } satisfies TelemetryEvent,
      questions: [
        {
          // Asked as full statements rather than bare PID numbers on purpose: the
          // correct answer to "what is the PPID?" is the single character "4",
          // which a student can pick off by shape without reading the output.
          question: "Volatility lists this svchost.exe at PID 4892. What is the best reading of its parent?",
          options: [
            "Expected: System (PID 4) starts the core services, svchost included",
            "Expected: the parent is services.exe, the normal svchost parent",
            "Abnormal: System (PID 4), not services.exe, is recorded as parent",
            "Proven injection: an abnormal PPID shows code was injected here",
          ],
          answer: 2,
          explanation:
            "volatility.ppid is 4, the System process. A genuine svchost.exe is started by services.exe, so this parent is abnormal and points to masquerading or a spoofed parent. Confirm it with windows.cmdline (is there a “-k” group?) and the path. “System starts the core services, svchost included” is wrong because services are started by services.exe, not by System. “The parent is services.exe” misreads the log: the ppid field says 4. “Proven injection” overreaches: a wrong parent is a masquerading signal, while injection is shown by memory evidence such as windows.malfind hits, not by the PPID.",
          xp: 40,
        },
        {
          question: "Next you want to know whether PID 4892 is talking to an external IP. Which plugin answers that?",
          options: [
            "windows.pstree — shows the full parent-child chain of PID 4892",
            "windows.netscan — lists sockets in memory with the owning PID",
            "windows.dumpfiles — extracts files cached in memory for analysis",
            "windows.cmdline — shows the arguments PID 4892 was started with",
          ],
          answer: 1,
          explanation:
            "windows.netscan scans memory for connection structures and lists active and recently closed TCP/UDP sockets with the PID that owns each one, so you can filter for 4892 and see any external IPs. “windows.pstree” helps with the parent question, not with traffic. “windows.dumpfiles” recovers files for analysis but says nothing about connections. “windows.cmdline” is a good masquerading check (is there a “-k”?), but it does not show network activity.",
          xp: 40,
        },
      ],
    },

    // ── Flag Task ─────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "dfir-flag1",
      prompt: `In the pslist output above, the svchost.exe at PID 4892 has the wrong parent. If it were a genuine Service Host, which process would its volatility.ppid point to? Enter the executable name, including .exe.`,
      answer: "services.exe",
      hint: "The memory-forensics reading lists the checks for spotting a fake Service Host. One of them names the expected parent.",
      xp: 50,
    },

    // ── Question 4 ───────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "dfir-q4",
      question: "On a Windows 10 workstation, an attacker's tool ran several times and then deleted itself. Which artefact can still show its name, path AND its last run times?",
      options: [
        "The $RECYCLE.BIN entry for the deleted tool",
        "Its Prefetch (.pf) file in C:\\Windows\\Prefetch",
        "The LNK shortcut in the user's Recent Items",
        "The $MFT entry left behind for the deleted tool",
      ],
      answer: 1,
      explanation:
        "A Prefetch file records the program's name, path and its last 8 run times, and it stays after the executable is deleted. “The $RECYCLE.BIN entry” at best shows what was deleted and when, not when it ran (and self-deleting tools usually bypass the Recycle Bin). “The LNK shortcut” records files a user opened, with the target's timestamps, not execution history. “The $MFT entry” gives the file's MACB timestamps (created, modified and so on), which are not run times. Caveat: Prefetch is turned off by default on Windows Server, so on a server you would need other execution evidence such as 4688 events or EDR telemetry.",
      xp: 30,
    },

    // ── Question 5 ───────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "dfir-q5",
      question: "windows.malfind flags a region inside a running process. What is the right conclusion and next step?",
      options: [
        "Malware confirmed: isolate and reimage now, no further analysis needed",
        "Executable memory with no backing file: a lead to dump and analyse",
        "A known virus signature was matched: check which family it belongs to",
        "The region was paged out during capture: re-acquire memory and rerun",
      ],
      answer: 1,
      explanation:
        "malfind flags memory that is executable but not backed by a file on disk. That pattern fits injected shellcode or reflective DLL loading (T1055), so it is a strong lead, and the next step is to dump the region and analyse it (YARA, disassembler) together with the process's path, parent and command line. “Malware confirmed: isolate and reimage now” skips analysis. Programs that generate code at runtime, such as .NET applications and browsers, can also produce unbacked executable memory, so a hit must be checked. “A known virus signature was matched” is wrong because malfind looks at memory characteristics, not antivirus signatures. “Paged out during capture” describes an acquisition gap, not what a malfind hit means.",
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
    "Phishing is one of the most common ways attackers get in. Learn how email actually works, how to read email headers, how SPF/DKIM/DMARC authentication works, and how to analyse a suspicious email like a SOC analyst.",
  difficulty: "intermediate" as const,
  category: "Threat Detection",
  estimatedMinutes: 45,
  xp: 210,
  icon: "📨",
  prerequisites: ["networking-protocols"],
  tasks: [
    // ── Reading 1: How Email Works & Headers ──────────────────────────────
    {
      type: "reading" as const,
      id: "email-sec-r1",
      heading: "How Email Works — Architecture and Headers",
      content: `Email is the most targeted attack vector in cybersecurity. Verizon's Data Breach Investigations Report (DBIR) consistently ranks **phishing among the top initial-access vectors**, and finds a human element (a click, a reply, a mistake) in the majority of breaches. To defend against email-based attacks, you first need to understand how email actually works under the hood.

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
      checkpoint: {
        question: "You open the raw headers of a suspicious email to find where it started its journey. Which header do you read first?",
        options: [
          "The top Received header, added by your own mail server",
          "The bottom Received header, the first hop that was recorded",
          "The Return-Path header, because it is the envelope sender",
          "The Message-ID header, because its domain names the origin",
        ],
        answer: 1,
        explanation: "Each server adds its Received header on top of the others, so you read them bottom-to-top: the bottom one is where the email originated. “The top Received header” is the last hop, your own server receiving the mail. “The Return-Path header” is the bounce address that SPF checks, not a record of the path. “The Message-ID header” is just an identifier, and its domain is chosen by the sending software.",
      },
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
- **temperror** — a temporary (usually DNS) error stopped the check from completing; a later retry may succeed. Treat as "unknown, retry", not as pass or fail.
- **permerror** — a permanent error: the domain's SPF record is malformed or breaks a hard limit (for example, more than the RFC 7208 maximum of 10 DNS-lookup mechanisms). It signals a broken record on the sender's side that a DNS operator must fix.

Those seven values — pass, fail, softfail, neutral, none, temperror, and permerror — are the complete set defined by RFC 7208. You will meet all of them in real Authentication-Results headers, so recognise temperror and permerror rather than assuming every non-pass result means spoofing.

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

DMARC is the **policy layer** on top of SPF and DKIM. It answers: **"What should you do with email that fails BOTH aligned SPF and aligned DKIM?"** A message passes DMARC if either check passes *and* aligns with the From domain. For example, a legitimate email auto-forwarded through another server usually fails SPF (the forwarder is not in the sender's SPF record), but its DKIM signature survives, so it still passes DMARC.

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
      checkpoint: {
        question: "corp.com has watched its DMARC reports for months and now wants mail failing DMARC to reach no one, not even the junk folder. Which policy should it publish?",
        options: [
          "p=none",
          "p=quarantine",
          "p=reject",
          "p=none with an rua= address",
        ],
        answer: 2,
        explanation: "p=reject tells receivers to block failing mail entirely. “p=quarantine” still delivers it, to spam/junk, which corp.com does not want. “p=none” is monitoring mode and takes no action. “p=none with an rua= address” is what corp.com has been doing: it only adds aggregate reports and still takes no action.",
      },
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
      question: "An email shows From: ceo@corp.com and Authentication-Results reports dkim=pass, but its DKIM-Signature carries d=newsletter-tool.com. What does that tell you?",
      options: [
        "DKIM passed, so the message is proven to come from corp.com",
        "The signature is valid, but its domain is not aligned with corp.com",
        "The message was altered in transit, since d= differs from From",
        "DKIM really failed, since the s= selector must equal the From domain",
      ],
      answer: 1,
      explanation:
        "dkim=pass only proves that newsletter-tool.com signed the message and that it was not changed. For DMARC, DKIM counts only if d= aligns with the From domain, and newsletter-tool.com does not align with corp.com. “Proven to come from corp.com” ignores alignment: a pass for another domain says nothing about corp.com. “Altered in transit” is wrong because tampering would make the signature fail, and it passed. “The s= selector must equal the From domain” confuses fields: s= only tells the receiver where to find the public key in DNS.",
      xp: 25,
    },

    // ── Question 2 ───────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "email-sec-q2",
      question: "An email shows 'From: CEO John Smith <ceo@corp.com>' but the Authentication-Results header shows 'spf=fail'. What does this most likely mean?",
      options: [
        "The CEO's real mailbox was taken over, so reset the CEO's password first",
        "The sending server is not authorised for corp.com, which suggests spoofing",
        "SPF is advisory only, so a fail can be ignored when the display name matches",
        "The SPF lookup timed out, so the result reflects a DNS problem, not the sender",
      ],
      answer: 1,
      explanation:
        "spf=fail means the server that sent this message is not listed in corp.com's SPF record, so the message most likely did not come from corp.com's mail system and the From address is spoofed. SPF checks the envelope sender (Return-Path); DMARC alignment ties the result back to the visible From. “The CEO's real mailbox was taken over” is unlikely here, because mail sent from a compromised real mailbox leaves through corp.com's authorised servers and passes SPF. “SPF is advisory only” is wrong: a display name is the easiest thing to fake. “The SPF lookup timed out” describes temperror, a different result from fail.",
      xp: 25,
    },

    // ── Question 3 ───────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "email-sec-q3",
      question: "An attacker who has taken over the CFO's real mailbox emails the payables team, with no link or attachment, asking them to urgently wire $80,000 to a new account. How do you classify this?",
      options: [
        "Mass phishing, since it relies on a common business pretext",
        "Whaling, since an executive's mailbox is involved in the attack",
        "BEC, since a trusted executive mailbox is used to request a wire",
        "Malicious attachment, since payment requests carry an invoice",
      ],
      answer: 2,
      explanation:
        "Business Email Compromise uses a compromised or convincingly spoofed executive mailbox to get staff to send money or data, which is exactly this. “Mass phishing” is sent broadly to many recipients; this is one targeted request. “Whaling” means the executive is the target of the phishing; here the executive's account is the tool and the payables team is the target. “Malicious attachment” does not fit, because the message has no attachment: BEC usually works through text alone, which is why gateways often miss it.",
      xp: 25,
    },

    // ── Log Analysis ─────────────────────────────────────────────────────
    {
      type: "log_analysis" as const,
      id: "email-sec-la1",
      heading: "Phishing Email Analysis — Failed Authentication and Suspicious Headers",
      context: `A finance department employee has forwarded a wire transfer request to the SOC because it felt unusual. The company's own domain is corp.com. Your email gateway captured the following metadata when the email arrived. Analyse the header fields and answer the questions.`,
      event: {
        id: "email-sec-la1-evt-001",
        ts: "2025-06-24T11:07:33.000Z",
        source: "email_gateway",
        event_type: "email_received",
        severity: "high",
        user_email: "finance@corp.com",
        src_ip: "185.220.101.45",
        description: "Inbound email to finance@corp.com reported by the recipient",
        mitre_technique: "T1566.001 - Phishing: Spearphishing Attachment",
        raw: {
          "email.from": "ceo@corp-secure.com",
          "email.reply_to": "r.donovan1985@gmail.com",
          "email.to": "finance@corp.com",
          "email.subject": "URGENT: Approve Wire Transfer $250,000",
          "email.message_id": "<abc@mail-out.corp-secure.com>",
          "email.x_originating_ip": "185.220.101.45",
          "email.authentication_results":
            "spf=pass smtp.mailfrom=corp-secure.com; dkim=none; dmarc=none header.from=corp-secure.com",
          "email.received_from": "mail-out.corp-secure.com [185.220.101.45]",
          "email.attachment": "invoice_approval.html",
          "email.header_from": "CEO John Smith <ceo@corp-secure.com>",
        },
      } satisfies TelemetryEvent,
      questions: [
        {
          question: "Which pair of indicators in this log shows the message did not come from your CEO at corp.com?",
          options: [
            "The spf=fail and dkim=none results in Authentication-Results",
            "The lookalike From domain corp-secure.com and the Gmail Reply-To",
            "The external X-Originating-IP and the urgent subject line",
            "The .html attachment and the $250,000 amount in the subject",
          ],
          answer: 1,
          explanation:
            "The From address uses corp-secure.com, a lookalike of corp.com, and replies go to a free Gmail address. Both show the sender is not corp.com's CEO. SPF passed only because SPF was checked for corp-secure.com, a domain the attacker controls. “The spf=fail and dkim=none results” misreads the log: SPF says pass. “The external X-Originating-IP and the urgent subject line” are worth noting, but an external IP and urgency say nothing about which domain sent the mail. “The .html attachment and the $250,000 amount” are risk factors for the payload and the impact, not evidence of the sender's identity.",
          xp: 35,
        },
        {
          question: "The attachment is named 'invoice_approval.html'. Why is an HTML file particularly dangerous as a phishing attachment?",
          options: [
            "It runs embedded Office macros, which Protected View does not stop",
            "It opens a local login page in the browser, with no link for the gateway to scan",
            "It is an executable file type, so it bypasses filters that only scan documents",
            "It exploits the PDF reader to run code as soon as it is previewed",
          ],
          answer: 1,
          explanation:
            "An HTML attachment is a web page: when opened, it shows a fake login page (for example a Microsoft 365 sign-in) inside the browser and sends what the victim types to the attacker. There is no URL in the email body for the gateway's link scanner to check. “It runs embedded Office macros” describes .docm/.xlsm files; HTML has no VBA macros. “It is an executable file type” is wrong: HTML is not an executable, which is exactly why filters built for executables let it through. “It exploits the PDF reader” describes a malicious .pdf, not an HTML file.",
          xp: 35,
        },
      ],
    },

    // ── Flag Task ─────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "email-sec-flag1",
      prompt: `In the email log above, SPF returned pass. For which domain was SPF actually checked? Enter the domain only.`,
      answer: "corp-secure.com",
      hint: "SPF does not check the visible From. Recall which sender address it uses, then find that value in the authentication results.",
      xp: 40,
    },

    // ── Question 4 ───────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "email-sec-q4",
      question: "A genuine newsletter from partner.com (DMARC p=reject) is auto-forwarded to your mailbox. At your gateway SPF fails, but DKIM with d=partner.com passes. What is the DMARC outcome?",
      options: [
        "Rejected, because SPF failed and partner.com publishes p=reject",
        "Quarantined, because one failed check downgrades reject to quarantine",
        "Passes, because the aligned DKIM survived and one aligned pass is enough",
        "Not evaluated, because forwarded mail is exempt from DMARC policy",
      ],
      answer: 2,
      explanation:
        "DMARC fails only when BOTH aligned SPF and aligned DKIM fail. Forwarding breaks SPF (the forwarder is not in partner.com's record), but the DKIM signature survives and d=partner.com aligns with the From domain, so the message passes. “Rejected, because SPF failed” is the common misreading that DMARC fails on either check. “One failed check downgrades reject to quarantine” is not a DMARC rule: the policy applies only to messages that fail DMARC. “Forwarded mail is exempt” is wrong: forwarded mail is evaluated like any other message, which is why forwarding sometimes breaks DMARC when DKIM is missing.",
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
