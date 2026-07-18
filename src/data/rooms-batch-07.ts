/**
 * Learning Rooms — Batch 07
 *
 * Four rooms covering enterprise EDR platforms and threat intelligence fundamentals:
 *   1. crowdstrike-falcon       — CrowdStrike Falcon Platform (intermediate)
 *   2. sentinelone              — SentinelOne Singularity Platform (intermediate)
 *   3. malware-analysis-fundamentals — Malware Analysis Fundamentals (intermediate)
 *   4. ioc-analysis             — IOC Analysis & Threat Pivoting (intermediate)
 */

import type { TelemetryEvent } from "@/lib/sim/types";

// ---------------------------------------------------------------------------
// Task types (mirrored from rooms.ts for standalone use)
// ---------------------------------------------------------------------------

interface ReadingTask {
  type: "reading";
  id: string;
  heading: string;
  content: string;
  codeExample?: string;
}

interface QuestionTask {
  type: "question";
  id: string;
  question: string;
  options: string[];
  answer: number;
  explanation: string;
  xp: number;
}

interface LogAnalysisTask {
  type: "log_analysis";
  id: string;
  heading: string;
  context: string;
  event: TelemetryEvent;
  questions: {
    question: string;
    options: string[];
    answer: number;
    explanation: string;
    xp: number;
  }[];
}

interface FlagTask {
  type: "flag";
  id: string;
  prompt: string;
  answer: string;
  hint?: string;
  xp: number;
}

type RoomTask = ReadingTask | QuestionTask | LogAnalysisTask | FlagTask;

interface Room {
  id: string;
  title: string;
  description: string;
  difficulty: "beginner" | "intermediate" | "advanced";
  category: string;
  estimatedMinutes: number;
  xp: number;
  icon: string;
  prerequisites: string[];
  tasks: RoomTask[];
}

// ---------------------------------------------------------------------------
// Room 1 — CrowdStrike Falcon
// ---------------------------------------------------------------------------

const crowdstrikeFalcon: Room = {
  id: "crowdstrike-falcon",
  title: "CrowdStrike Falcon",
  description:
    "Learn to use CrowdStrike Falcon, one of the most widely deployed enterprise EDR/XDR platforms in the world. Understand the Falcon Sensor, the Falcon console, how detections are structured, and how SOC analysts investigate and respond to threats using CrowdStrike's tools.",
  difficulty: "intermediate",
  category: "Endpoint Security",
  estimatedMinutes: 50,
  xp: 550,
  icon: "🦅",
  prerequisites: ["endpoint-security-fundamentals"],
  tasks: [
    // ── Reading 1: Architecture & Falcon Sensor ──────────────────────────────
    {
      type: "reading",
      id: "cs-falcon-r1",
      heading: "What Is CrowdStrike Falcon — and How Does It Work?",
      content: `CrowdStrike is a cybersecurity company founded in 2011 with one key idea: stop attackers, not just malware. Instead of building a product that only looks for known virus signatures (like old-school antivirus), CrowdStrike built a platform that focuses on **adversary behaviour** — what attackers actually do inside a system, step by step.

The result is **Falcon**, a cloud-native endpoint protection platform. "Cloud-native" means that the heavy lifting — analysis, machine learning, threat intelligence — all happens in CrowdStrike's cloud, not on your laptop. Your computer only runs a tiny, lightweight piece of software called the **Falcon Sensor**.

**What Is the Falcon Sensor?**

Think of the Falcon Sensor like a security camera permanently installed inside the operating system. It runs in **kernel mode** — the deepest, most privileged layer of Windows or Linux — which means nothing on the system can hide from it. Every time a program starts, accesses a file, makes a network connection, or touches the registry, the Sensor records it and streams that telemetry to CrowdStrike's cloud in near real-time.

The Sensor is deliberately tiny (under 5 MB) and uses very little CPU. Users generally can't tell it's there. It doesn't slow down the computer or interfere with normal work.

**The CrowdStrike Cloud: Where the Intelligence Lives**

Once telemetry leaves the sensor, it arrives at the **Threat Graph** — CrowdStrike's proprietary cloud-scale data store that holds trillions of events from millions of endpoints around the world. Machine learning models run continuously against this data, looking for patterns that indicate malicious activity.

When the cloud spots something suspicious, it sends a detection back to the Falcon console for a SOC analyst to review. This design means that:
- New threat intelligence is applied to ALL customers simultaneously (no waiting for a signature update download)
- Even if a new attacker technique appears at Company A in Tokyo, CrowdStrike's cloud can recognise the same pattern at Company B in New York seconds later

**CrowdStrike's Adversary Focus**

CrowdStrike publicly names and tracks over 200 threat actor groups using animal-themed codenames: **FANCY BEAR** (Russian state actors), **COZY BEAR** (another Russian group), **LAZARUS GROUP** (North Korea, sometimes called HIDDEN COBRA), **SCATTERED SPIDER** (English-speaking cybercriminal group). This adversary intelligence approach helps SOC teams understand *who* is attacking them and *why*, not just *what malware* was used.

**Prevention vs Detection: Two Modes of Falcon**

CrowdStrike Falcon runs in two complementary modes simultaneously:

- **Falcon Prevent (NGAV — Next-Generation Antivirus):** Blocks threats before they execute. Uses machine learning models trained on millions of malware samples to score every file before it runs. If the score is above a configured threshold, execution is blocked automatically. This is *prevention* — stopping the attack before damage occurs.

- **Falcon Insight (EDR — Endpoint Detection and Response):** Monitors everything that happens on the endpoint and sends it to the cloud for analysis. Generates *detections* — alerts that tell a SOC analyst "something suspicious happened here, investigate." This catches things that slipped past prevention (novel malware, attacker using built-in Windows tools, etc.).

Both modules run from the same sensor. You don't need two products.`,
    },

    // ── Reading 2: Detections, Console & Key Features ────────────────────────
    {
      type: "reading",
      id: "cs-falcon-r2",
      heading: "The Falcon Console: Where SOC Analysts Work",
      content: `After logging into Falcon (at falcon.crowdstrike.com), SOC analysts see the **Falcon UI** — the central console for everything from reviewing alerts to remotely connecting to endpoints. Here are the areas you'll use most:

**Activity Dashboard**

The landing page shows a summary of recent threats, active detections, and the overall health of your environment. Think of it like an air traffic controller's radar screen — a bird's-eye view of what's happening across hundreds or thousands of endpoints.

**Detections Page**

This is where CrowdStrike sends alerts. Each detection card shows:
- **Detection name:** A human-readable name like "CREDENTIAL ACCESS — Credential Dumping via comsvcs.dll"
- **Severity:** Critical, High, Medium, or Low (similar to a traffic light — red = urgent)
- **MITRE Tactic/Technique:** The ATT&CK framework category (e.g., *Credential Access / T1003.001 LSASS Memory*)
- **Confidence:** How certain Falcon is that this is malicious (expressed as a percentage or level)
- **Process tree:** A visual diagram showing *exactly* what happened — which program launched which program, what commands were run, what files were touched

The process tree is one of the most powerful features in the Falcon console. Instead of seeing a single alert in isolation, you see the entire attack chain: which email attachment was double-clicked → which macro ran → which PowerShell command executed → which file was written to disk → which network connection was made. Everything connected, in sequence.

**Key Fields in a CrowdStrike Detection**

When you open a detection, these fields are critical for analysis:
- **CommandLine:** The exact command that ran. If it contains Base64-encoded text ('-EncodedCommand') or unusual paths (C:\\\\Windows\\\\Temp), be suspicious.
- **SHA256:** The cryptographic fingerprint of any file involved. You can paste this into VirusTotal to see if it's known malware.
- **LocalIP / ExternalIP:** The IP addresses of the endpoint and any remote connection
- **UserName:** Which user account was running the process (SYSTEM? A service account? A regular employee?)
- **ContextProcessName:** The parent process — what launched the suspicious process

**Investigate / Threat Graph**

The **Investigate** module (sometimes called Threat Graph) lets you do visual, interactive investigation. You can:
- Search for a process hash across your entire environment ("has any endpoint run this file?")
- See all network connections an endpoint made in the last 7 days
- Pivot from an IP address to all processes that contacted it
- Build a timeline of an entire attack from first access to lateral movement

**Host Management**

Here you manage the inventory of all endpoints with the Falcon Sensor installed. You can see each device's health, last check-in time, sensor version, operating system, and assigned policies. If a host goes offline after an incident, this is where you'll notice.

**CrowdStrike OverWatch**

**OverWatch** is CrowdStrike's 24/7 elite threat hunting team. They proactively hunt through Falcon telemetry across all customers, looking for attacker activity that automated detections might miss. When OverWatch finds something, they send a **managed detection** to the customer's Falcon console with their analysis. For organisations without a 24/7 SOC, OverWatch is like having CrowdStrike's expert hunters watching your environment around the clock.

**Falcon Discover**

Beyond protecting managed endpoints, **Falcon Discover** scans your network for devices that do *not* have the Falcon Sensor installed — rogue laptops, network printers, IoT cameras, BYOD phones. Finding unmanaged devices is critical because attackers love to pivot through systems that security can't see.`,
    },

    // ── Reading 3: RTR & Real-World Scenarios ─────────────────────────────────
    {
      type: "reading",
      id: "cs-falcon-r3",
      heading: "Real Time Response (RTR) and Common Attack Scenarios",
      content: `**Real Time Response (RTR): The Remote Control Capability**

Imagine getting an alert at 2 a.m. that an employee's laptop in another country is showing signs of a ransomware infection. You can't physically walk over to that machine. What do you do?

In CrowdStrike Falcon, you open **Real Time Response (RTR)** — a remote shell session directly to the endpoint, established through the Falcon Sensor's existing encrypted channel. No VPN required. No RDP port opened. No third-party remote access tool needed.

From RTR, a SOC analyst can:
- **Run commands** on the remote endpoint (list processes, check running services, view network connections)
- **Retrieve files** — pull a suspicious executable from the endpoint to your local machine for analysis
- **Kill processes** — instantly terminate a malicious process that's actively running
- **Put files** — push a script or remediation tool to the endpoint
- **Delete files** — remove a malicious file or persistence mechanism

RTR uses CrowdStrike-built commands (not standard cmd/bash) with tab-completion and command history. Example RTR commands:
- \`ps\` — list all running processes
- \`netstat\` — show active network connections
- \`reg query <key>\` — read a Windows registry value
- \`get <filepath>\` — retrieve a file
- \`kill <pid>\` — kill a process by its PID (Process ID)

All RTR sessions are logged and audited, so there's a full record of what actions the analyst took.

**Common Attack Scenarios Detected by CrowdStrike**

**Scenario 1 — PowerShell Encoded Commands**
Attackers love PowerShell because it's built into Windows and can do almost anything. To hide their commands, they often base64-encode them:
\`powershell.exe -EncodedCommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAc...\`

CrowdStrike flags this pattern immediately. The Falcon console decodes the base64 and shows the analyst exactly what command was trying to run — often a download of a malicious payload from the internet.

**Scenario 2 — Mimikatz / Credential Dumping**
Mimikatz is an infamous hacking tool that extracts password hashes and plaintext credentials from Windows memory. Attackers run it to "harvest" credentials they can use to move laterally through an organisation.

CrowdStrike detects Mimikatz by its behaviour: a process trying to access the **LSASS.exe** memory (Local Security Authority Subsystem Service — the process that stores credentials). The detection label is typically: *T1003.001 — OS Credential Dumping: LSASS Memory*.

**Scenario 3 — Lateral Movement via PsExec**
After compromising one machine, attackers move to others. A common tool is **PsExec**, a legitimate Windows administrative utility that attackers abuse to run commands on remote computers. CrowdStrike detects when PsExec is used to execute code on multiple machines in quick succession — a pattern that matches lateral movement rather than legitimate IT administration.

**Putting It All Together: The Analyst Workflow**

1. Detection appears in Falcon console → severity: Critical
2. Analyst opens detection → reviews process tree
3. Identifies the initial access (phishing email attachment)
4. Traces lateral movement through the network
5. Opens RTR to affected hosts → kills malicious processes
6. Collects forensic files for deeper analysis
7. Documents findings, updates tickets, requests remediation`,
    },

    // ── Question 1 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "cs-falcon-q1",
      question:
        "A SOC analyst opens a CrowdStrike detection and sees the CommandLine field contains: 'powershell.exe -EncodedCommand SQBuAHYAbwBr...'. What does this most likely indicate?",
      options: [
        "A legitimate Windows update process running in the background",
        "An attacker using base64 encoding to hide a malicious PowerShell command",
        "A normal antivirus scan initiated by the IT department",
        "A software installation script run by an application",
      ],
      answer: 1,
      explanation:
        "The '-EncodedCommand' flag in PowerShell means the command is base64-encoded — a common attacker technique to hide malicious commands from simple string-based detection. Legitimate IT automation rarely uses encoding without a clear documented reason. CrowdStrike automatically decodes these commands in the console so analysts can see what the command actually does.",
      xp: 35,
    },

    // ── Question 2 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "cs-falcon-q2",
      question:
        "What is the primary purpose of the Falcon Sensor running in kernel mode on an endpoint?",
      options: [
        "To display security alerts in a pop-up window for the end user",
        "To block all USB devices from being plugged in",
        "To record all system activity at the deepest OS level so nothing can hide from it",
        "To encrypt the hard drive to protect sensitive data",
      ],
      answer: 2,
      explanation:
        "Kernel mode is the most privileged layer of an operating system — even before the normal user-facing software loads. By running at kernel level, the Falcon Sensor can monitor every process, file operation, network connection, and registry change without any program being able to evade it. Malware that tries to hide itself cannot conceal activity from a kernel-mode sensor.",
      xp: 35,
    },

    // ── Question 3 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "cs-falcon-q3",
      question:
        "What is CrowdStrike OverWatch?",
      options: [
        "A feature that automatically quarantines all suspicious files without analyst review",
        "A 24/7 managed threat hunting team that proactively hunts for attacker activity across customer environments",
        "A network scanner that finds open ports on your firewall",
        "A reporting module that generates monthly compliance reports",
      ],
      answer: 1,
      explanation:
        "CrowdStrike OverWatch is an elite team of human threat hunters who work 24/7, searching through telemetry from millions of CrowdStrike-protected endpoints worldwide. They look for subtle attacker patterns that automated detections might miss — especially from sophisticated nation-state actors. When they find something, they send a managed detection with their analysis directly to the customer's Falcon console.",
      xp: 35,
    },

    // ── Log Analysis ──────────────────────────────────────────────────────────
    {
      type: "log_analysis",
      id: "cs-falcon-la1",
      heading: "CrowdStrike Detection: Credential Dumping Alert",
      context:
        "You are a SOC analyst on shift at 11:47 PM. A Critical severity alert fires in the CrowdStrike Falcon console. The alert is tagged with MITRE technique T1003.001 (OS Credential Dumping: LSASS Memory). The affected host is a domain controller — the most sensitive server in the organisation, as it holds all user credentials. Analyse the detection below and answer the questions.",
      event: {
        id: "cs-evt-cred-dump-001",
        ts: "2025-06-14T23:47:12.000Z",
        source: "edr",
        vendor: "CrowdStrike Falcon",
        event_type: "edr_alert",
        severity: "critical",
        hostname: "SRV-DC01",
        user_email: "svc-backup@corp.local",
        mitre_technique: "T1003.001",
        mitre_tactic: "Credential Access",
        description:
          "CrowdStrike Falcon detected a process attempting to dump credentials from LSASS memory on a domain controller. The process used comsvcs.dll MiniDump — a known credential extraction technique.",
        process: {
          name: "rundll32.exe",
          pid: 4812,
          path: "C:\\Windows\\System32\\rundll32.exe",
          parent_name: "cmd.exe",
          parent_pid: 2048,
          cmdline:
            "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 640 C:\\Windows\\Temp\\lsass.dmp full",
          user: "CORP\\svc-backup",
        },
        raw: {
          "crowdstrike.AlertType": "ProcessRollup2",
          "crowdstrike.SeverityName": "Critical",
          "crowdstrike.Technique": "T1003.001",
          "crowdstrike.TechniqueName": "LSASS Memory",
          "crowdstrike.ContextProcessName": "cmd.exe",
          "crowdstrike.ContextProcessId": "2048",
          "crowdstrike.CommandLine":
            "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 640 C:\\Windows\\Temp\\lsass.dmp full",
          "crowdstrike.TargetProcessName": "lsass.exe",
          "crowdstrike.GrantedAccess": "0x1FFFFF",
          "crowdstrike.UserName": "CORP\\svc-backup",
          "crowdstrike.HostName": "SRV-DC01",
          "crowdstrike.DetectionId": "ldt:abc123:def456",
          "crowdstrike.FalconHostLink":
            "https://falcon.crowdstrike.com/activity/detections/detail/abc123",
        },
      },
      questions: [
        {
          question:
            "The field 'crowdstrike.GrantedAccess: 0x1FFFFF' appears in the alert. In Windows, access mask 0x1FFFFF means PROCESS_ALL_ACCESS — full control over the target process. Why is this value specifically suspicious when the target is lsass.exe?",
          options: [
            "LSASS is a normal user application that should never be accessed by other programs",
            "LSASS stores all Windows credential material in memory; full access to it allows extraction of password hashes and tokens",
            "The value 0x1FFFFF is a known malware signature and always indicates infection",
            "LSASS is only accessible to processes running from the C:\\Temp directory",
          ],
          answer: 1,
          explanation:
            "LSASS (Local Security Authority Subsystem Service) is the Windows process responsible for enforcing security policies and storing credential material — including NTLM hashes, Kerberos tickets, and sometimes plaintext passwords. Requesting PROCESS_ALL_ACCESS to lsass.exe is the hallmark of credential dumping tools like Mimikatz. The attacker (or their tool) needs that access level to read LSASS memory and extract usable credentials.",
          xp: 50,
        },
        {
          question:
            "The detection shows the process was run under the account 'CORP\\svc-backup'. What does this suggest about the attacker's technique?",
          options: [
            "The attacker created a brand-new account specifically for this attack",
            "The attacker compromised a legitimate service account and is using it to blend in with normal activity",
            "svc-backup is a built-in Windows administrator account with no special privileges",
            "The attacker is a backup administrator performing routine maintenance",
          ],
          answer: 1,
          explanation:
            "Service accounts like 'svc-backup' are pre-existing accounts used by automated backup software — they often have elevated privileges (needed to access all files for backup purposes) but their activity is typically less scrutinised than human admin accounts. Attackers deliberately compromise and abuse service accounts to blend into legitimate-looking activity. This is a common privilege escalation and persistence technique.",
          xp: 50,
        },
        {
          question:
            "The dump file is being written to 'C:\\Windows\\Temp\\lsass.dmp'. As the responding SOC analyst, what is your FIRST priority action?",
          options: [
            "Email the affected user to change their password",
            "Wait 24 hours to see if more detections appear before taking action",
            "Use CrowdStrike RTR to kill the process, retrieve the dump file for evidence, and isolate the host from the network",
            "Reboot the domain controller immediately to clear the threat",
          ],
          answer: 2,
          explanation:
            "The immediate priority in credential dumping is to stop the ongoing attack while preserving evidence. RTR lets you kill the malicious rundll32.exe process (stopping further credential extraction), retrieve the .dmp file as forensic evidence (and to check what was already captured), then isolate the host to prevent the attacker from exfiltrating the credentials over the network. Rebooting would destroy volatile memory evidence and may not stop the threat if persistence is established.",
          xp: 50,
        },
      ],
    },

    // ── Flag Task ─────────────────────────────────────────────────────────────
    {
      type: "flag",
      id: "cs-falcon-flag1",
      prompt:
        "Looking at the CrowdStrike detection above, the attacker's tool is targeting a specific Windows process to extract credentials. The field 'crowdstrike.TargetProcessName' tells you which process is being attacked. What is the name of that process? (Enter the process name exactly as shown, without the file extension)",
      answer: "lsass",
      hint: "Look at the 'crowdstrike.TargetProcessName' field in the raw log. It is a four-letter Windows system process name.",
      xp: 40,
    },

    // ── Question 4 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "cs-falcon-q4",
      question:
        "A security analyst needs to remotely check running processes on a potentially compromised endpoint without opening RDP or requiring VPN access. Which CrowdStrike Falcon feature enables this?",
      options: [
        "Falcon Discover — network scanner module",
        "Falcon OverWatch — managed detection team",
        "Real Time Response (RTR) — remote shell through the existing Falcon Sensor channel",
        "Falcon Prevent — NGAV blocking module",
      ],
      answer: 2,
      explanation:
        "Real Time Response (RTR) establishes a remote shell session to any Falcon-protected endpoint through the same encrypted cloud channel the Falcon Sensor already uses. No additional ports need to be opened, no VPN is required, and no separate remote access tools are needed. The analyst types commands in the Falcon console and they execute on the remote machine.",
      xp: 35,
    },

    // ── Question 5 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "cs-falcon-q5",
      question:
        "In CrowdStrike Falcon, what does the MITRE ATT&CK tag 'T1003.001' on a detection tell a SOC analyst?",
      options: [
        "The attacker used a phishing email to gain initial access to the network",
        "The technique is OS Credential Dumping targeting LSASS Memory — the attacker is trying to steal credentials",
        "A vulnerability in web application software has been exploited",
        "The detection is a false positive generated by a software update",
      ],
      answer: 1,
      explanation:
        "MITRE ATT&CK is a publicly maintained framework cataloguing attack techniques used by real threat actors. T1003.001 specifically refers to 'OS Credential Dumping: LSASS Memory' — meaning the attacker (or their tool) accessed the LSASS process to extract credential material such as NTLM hashes or Kerberos tickets. This tag lets SOC analysts immediately understand the attacker's goal without reading raw log data.",
      xp: 35,
    },
  ],
};

// ---------------------------------------------------------------------------
// Room 2 — SentinelOne Singularity
// ---------------------------------------------------------------------------

const sentinelOne: Room = {
  id: "sentinelone",
  title: "SentinelOne Singularity",
  description:
    "Explore SentinelOne's Singularity platform — the autonomous endpoint security solution that combines EPP, EDR, and XDR in a single agent. Learn how Storyline automatically constructs attack stories, how to use the management console, and how SentinelOne's unique rollback capability can restore files encrypted by ransomware.",
  difficulty: "intermediate",
  category: "Endpoint Security",
  estimatedMinutes: 50,
  xp: 550,
  icon: "🔮",
  prerequisites: ["endpoint-security-fundamentals"],
  tasks: [
    // ── Reading 1: Architecture & Storyline ───────────────────────────────────
    {
      type: "reading",
      id: "s1-r1",
      heading: "SentinelOne Singularity: The Autonomous Security Platform",
      content: `SentinelOne was founded in 2013 with a vision that eventually became a company tagline: **autonomous security**. Where older security tools require a human analyst to correlate dozens of separate alerts before understanding an attack, SentinelOne was designed to understand attacks *automatically* — seeing the full picture, responding in real-time, and even *reversing* damage without waiting for a human.

The product is called **Singularity** — a single unified platform that covers:
- **Endpoints** (laptops, desktops, servers — Windows, macOS, Linux)
- **Cloud workloads** (containers, Kubernetes pods, virtual machines)
- **Identity** (integrations with Active Directory and identity providers)
- **Mobile** devices

All of these are protected by the same AI engine and managed from one console.

**The SentinelOne Agent**

The SentinelOne Agent installs on each endpoint, similar to CrowdStrike's Falcon Sensor. However, SentinelOne's agent is designed to work in two operational modes:

- **Detect Mode:** The agent monitors and logs everything but does not automatically block threats. Detections appear in the console for analysts to review and take manual action. This mode is typically used during initial deployment while the team calibrates the platform.
- **Protect Mode:** The agent actively blocks and responds to threats automatically — killing processes, quarantining files, even rolling back changes — without waiting for human input. This is SentinelOne's "autonomous" mode.

**Three AI Detection Engines Working Together**

SentinelOne doesn't rely on a single detection method. Three AI engines run simultaneously:

1. **Static AI (Pre-Execution):** Before a file runs, the agent scans it using a machine learning model trained on millions of malware samples. Like having a metal detector at the door — the file is screened before it's even allowed to execute. This catches known and unknown (zero-day) malware based on structural features, not just signatures.

2. **Behavioral AI (Real-Time):** Once a process is running, the Behavioral AI engine monitors every action it takes — what files it reads or writes, what registry keys it touches, what network connections it makes, what child processes it spawns. If the *behaviour* matches known attack patterns (even if the file itself looks clean), Behavioral AI triggers an alert. This is how SentinelOne catches "fileless" attacks — attacks that use legitimate system tools like PowerShell and never write a traditional malware file to disk.

3. **Deep Visibility (EDR Telemetry):** Every action by every process is recorded and stored with full fidelity for 365 days. SOC analysts can search this raw telemetry to hunt for threats, investigate incidents, and understand exactly what happened on any endpoint.

**Storyline: SentinelOne's Killer Feature**

The most distinctive feature of SentinelOne is **Storyline**. Every security product generates alerts — sometimes hundreds per hour. The problem is that a single attack might generate 47 separate alerts (one for the Word document that ran a macro, one for the PowerShell command, one for the network connection, one for each file encrypted by ransomware...). Without connecting them, a SOC analyst sees 47 separate problems instead of one attack.

SentinelOne's Storyline engine automatically links all related events into a single, connected narrative — the **attack story**. Every event in an attack chain gets tagged with the same **StorylineID** (a unique identifier like 0x1A2B3C4D). When you open a threat in the SentinelOne console, you don't see 47 alerts — you see *one story* with a complete timeline: what triggered first, what spawned next, what files were created, what network connections were made, from beginning to end.

Think of it as the difference between receiving 47 separate puzzle pieces in different boxes versus receiving a completed puzzle with all the pieces already assembled and labelled.`,
    },

    // ── Reading 2: Management Console & Response ──────────────────────────────
    {
      type: "reading",
      id: "s1-r2",
      heading: "The SentinelOne Console: Threats, Investigation, and Response",
      content: `The **SentinelOne Management Console** (also called the Singularity Operations Center in recent versions) is the web-based interface where SOC analysts monitor endpoints, investigate threats, and take response actions. Here is a tour of the main sections:

**Sentinel Overview (Dashboard)**

The home screen shows a threat summary for your environment: total threats detected, threats by severity, threats by status (active vs. resolved), and endpoint health. Trend charts show whether the number of detections is increasing or decreasing over time — an increase might signal an ongoing campaign.

**Threats Page**

This is the core of a SOC analyst's daily work in SentinelOne. Every detected threat appears here as a card. Each threat card shows:
- **Threat Name:** e.g., "Trojan.Ransom.LockBit3" (the malware family name)
- **Risk Level:** Critical, High, Medium, Low — SentinelOne's severity score
- **Classification:** Malicious, Suspicious, or Potentially Unwanted Application (PUA)
- **Confidence Level:** A percentage (e.g., 99%) representing how certain the AI engines are
- **Endpoint name and username:** Which machine and which user was affected
- **Action Taken:** What SentinelOne automatically did (Quarantine, Kill, or Monitor)
- **Storyline view button:** Click to see the complete attack story

**Endpoint (Devices) Page**

An inventory of all enrolled endpoints. You can filter by operating system, agent version, policy, or health status. Clicking on an endpoint shows you its detailed hardware information, installed software, recent activity, and threat history.

**Investigate / Deep Visibility**

This is SentinelOne's equivalent of CrowdStrike's Threat Graph — a raw telemetry search interface. Using Deep Visibility, analysts can write queries like:
- "Show me all processes that made network connections to port 443 in the last 7 days"
- "Find every endpoint where chrome_update.exe has ever executed"
- "Show me all files created with a .lockbit extension in the last 24 hours"

Deep Visibility stores 365 days of telemetry and allows hunting across the entire fleet simultaneously.

**Sentinels (Agents) Page**

Shows the health and status of every SentinelOne Agent deployment. You can see which agents are online, which are offline, which have pending updates, and which are in Detect vs. Protect mode. This is where you'd investigate if an agent stops checking in (which itself can be a sign of a sophisticated attacker disabling the security tool).

**Response Actions in SentinelOne**

When a threat is confirmed, SentinelOne offers several response options:

- **Quarantine Threat:** Moves the malicious file to an isolated quarantine folder where it cannot execute. The original file path is preserved so you can see where it came from.
- **Kill Process:** Immediately terminates the malicious process in memory. This stops active damage but does not remove the file from disk.
- **Isolate Network:** Cuts the endpoint off from the network entirely (while keeping the agent connected to the SentinelOne cloud). The infected machine can't communicate with other systems — preventing spread — but analysts can still investigate it remotely.
- **Rollback (the unique SentinelOne feature):** SentinelOne continuously takes shadow-copy-style snapshots of file changes on the endpoint. If ransomware encrypts files, the Rollback feature can *undo* those changes — restoring encrypted files to their pre-attack state. This can be the difference between a minor security incident and a catastrophic data loss event.`,
    },

    // ── Reading 3: XDR & Key Scenarios ───────────────────────────────────────
    {
      type: "reading",
      id: "s1-r3",
      heading: "SentinelOne XDR and Detecting Ransomware",
      content: `**Beyond the Endpoint: SentinelOne XDR**

Traditional EDR (Endpoint Detection and Response) only sees what happens on the endpoint itself. **XDR (Extended Detection and Response)** expands visibility to *all* data sources in the environment — firewalls, email gateways, cloud logs, identity providers, network traffic — and correlates them together.

SentinelOne Singularity's XDR capabilities connect:
- **SIEM integration:** SentinelOne can ingest logs from Splunk, Microsoft Sentinel, and other SIEM platforms, enriching those events with endpoint context
- **Identity integration:** Alert data is correlated with Microsoft Entra ID (formerly Azure Active Directory) or Okta user risk scores — so you know not just *which endpoint* was compromised but *which user account* and whether that user has been flagged for risky behaviour elsewhere
- **Cloud workload protection:** The same Singularity agent can protect Linux-based containers and cloud VMs, giving visibility into attacks that pivot from an endpoint to cloud infrastructure
- **Threat Intelligence:** SentinelOne maintains an embedded global threat intelligence database that automatically matches file hashes, IP addresses, and domains against known malicious indicators

**Purple AI: SentinelOne's AI Assistant**

Introduced in 2024, **Purple AI** lets analysts ask security questions in plain English and receive structured answers backed by Deep Visibility telemetry. Instead of writing complex query syntax, an analyst can type "Show me all connections this endpoint made to unusual foreign IPs in the past week" and Purple AI translates this into the appropriate telemetry query, runs it, and summarises the results.

Purple AI has reduced mean time to detect (MTTD) by up to 63% and mean time to remediate (MTTR) by 55% in SentinelOne's published case studies.

**Key Detection Scenario 1: Ransomware**

Ransomware is one of the most destructive attacks a company can face. Modern ransomware like LockBit 3, BlackCat (ALPHV), and Cl0p encrypts files so fast that by the time a human analyst sees an alert, thousands of files may already be locked.

SentinelOne's Behavioral AI detects ransomware through characteristic patterns:
- **Rapid file rename cascade:** Ransomware renames thousands of files per minute, appending a new extension (e.g., .lockbit, .encrypted). SentinelOne tracks file rename rates — a spike of 1,000+ renames per minute from a single process is an immediate red flag.
- **File entropy increase:** Legitimate files have predictable patterns. Encrypted files have very high entropy (randomness). SentinelOne monitors file entropy as a detection signal.
- **Shadow copy deletion:** Ransomware immediately tries to delete Windows shadow copies (backup snapshots) to prevent recovery. Commands like \`vssadmin delete shadows\` or \`wmic shadowcopy delete\` are automatically flagged.

When ransomware is detected, SentinelOne can automatically kill the process AND trigger a Rollback — restoring encrypted files from pre-attack snapshots, often within minutes.

**Key Detection Scenario 2: Cobalt Strike Beacons**

Cobalt Strike is a commercial penetration testing tool that is heavily abused by cybercriminals for real attacks. When used maliciously, Cobalt Strike installs a **beacon** — a small implant that regularly "calls home" to the attacker's command-and-control (C2) server, waiting for instructions.

Cobalt Strike beacons are specifically designed to evade detection: they inject themselves into legitimate processes (like explorer.exe or svchost.exe), use encrypted communications over HTTPS, and can sleep for hours between check-ins to avoid pattern detection.

SentinelOne detects Cobalt Strike through:
- Behavioral AI: detecting process injection signatures in memory
- Network analysis: identifying the distinctive timing patterns of beacon check-ins
- Memory scanning: recognising Cobalt Strike's shellcode patterns in process memory`,
    },

    // ── Question 1 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "s1-q1",
      question:
        "What is SentinelOne's 'Storyline' feature, and what problem does it solve for SOC analysts?",
      options: [
        "A reporting tool that creates weekly PDF summaries of detected threats",
        "An automatic correlation engine that links all related attack events (processes, files, network connections) into a single connected attack story using a shared StorylineID",
        "A training module that teaches junior analysts how to use the console",
        "A feature that automatically patches vulnerabilities on the endpoint",
      ],
      answer: 1,
      explanation:
        "Storyline solves alert fatigue and alert fragmentation. Instead of generating dozens of separate alerts for each step of an attack, SentinelOne assigns a single StorylineID to every event in an attack chain, linking them together. Analysts see one complete attack story from initial access to final impact — not 47 disconnected alerts. This dramatically reduces the time and cognitive load required to understand what happened.",
      xp: 35,
    },

    // ── Question 2 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "s1-q2",
      question:
        "An analyst sees a SentinelOne detection where 15,847 files were renamed with a '.lockbit' extension added. What type of attack does this signature indicate?",
      options: [
        "A Trojan establishing persistence via registry modification",
        "A man-in-the-middle attack intercepting network traffic",
        "Ransomware encrypting files and renaming them with its own extension as it locks them",
        "A data exfiltration attack uploading files to an external server",
      ],
      answer: 2,
      explanation:
        "Mass file renaming — especially adding a consistent new extension like .lockbit, .encrypted, or .WNCRY — is the signature behaviour of ransomware in action. LockBit 3 is a prominent ransomware family that appends '.lockbit' to every file it encrypts. The file count (15,847 in this case) tells you the scope of the damage and reinforces the urgency of response. SentinelOne's Behavioral AI detects this rename cascade pattern in real-time.",
      xp: 35,
    },

    // ── Question 3 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "s1-q3",
      question:
        "What makes SentinelOne's 'Rollback' response action uniquely valuable compared to standard 'quarantine' and 'kill process' actions?",
      options: [
        "Rollback prevents the threat from ever reaching the endpoint by filtering at the network level",
        "Rollback can undo file changes made by ransomware, restoring encrypted files to their pre-attack state using snapshots taken by the agent",
        "Rollback re-installs the operating system from a clean backup image",
        "Rollback automatically identifies the threat actor behind the attack",
      ],
      answer: 1,
      explanation:
        "Quarantine and kill-process actions stop *ongoing* damage but can't undo damage already done. SentinelOne's Rollback feature continuously tracks file changes on the endpoint and can reverse them — restoring encrypted or deleted files to their pre-attack state. For a ransomware incident, this could mean the difference between full data recovery in minutes versus days of manual restoration from backups (or paying a ransom).",
      xp: 35,
    },

    // ── Log Analysis ──────────────────────────────────────────────────────────
    {
      type: "log_analysis",
      id: "s1-la1",
      heading: "SentinelOne Alert: Ransomware Encryption Cascade",
      context:
        "It is 09:14 AM on a Monday morning. A Critical severity detection fires in your SentinelOne console. The threat name is 'Trojan.Ransom.LockBit3' and the affected machine belongs to a finance department employee. Files are actively being encrypted right now. Every minute of delay means more files locked. Analyse the detection and answer the questions.",
      event: {
        id: "s1-evt-ransomware-001",
        ts: "2025-06-16T09:14:22.000Z",
        source: "edr",
        vendor: "SentinelOne",
        event_type: "av_detection",
        severity: "critical",
        hostname: "LAPTOP-JSMITH",
        user_email: "j.smith@corp.com",
        mitre_technique: "T1486",
        mitre_tactic: "Impact",
        description:
          "SentinelOne detected LockBit 3 ransomware actively encrypting files. 15,847 files renamed with .lockbit extension. Rollback snapshots available. Automatic quarantine applied.",
        process: {
          name: "chrome_update.exe",
          pid: 7291,
          path: "C:\\Users\\j.smith\\AppData\\Local\\Temp\\chrome_update.exe",
          parent_name: "explorer.exe",
          parent_pid: 1204,
          cmdline:
            "\"C:\\Users\\j.smith\\AppData\\Local\\Temp\\chrome_update.exe\" --silent",
          user: "CORP\\j.smith",
          hash: {
            sha256:
              "3c4f8a1b2e5d6c7890abcdef1234567890abcdef1234567890abcdef12345678",
          },
        },
        file: {
          name: "chrome_update.exe",
          path: "C:\\Users\\j.smith\\AppData\\Local\\Temp\\chrome_update.exe",
          sha256:
            "3c4f8a1b2e5d6c7890abcdef1234567890abcdef1234567890abcdef12345678",
          size: 1048576,
          extension: ".exe",
        },
        raw: {
          "s1.threatName": "Trojan.Ransom.LockBit3",
          "s1.classification": "Malicious",
          "s1.confidenceLevel": "99",
          "s1.processName": "chrome_update.exe",
          "s1.processPath":
            "C:\\Users\\j.smith\\AppData\\Local\\Temp\\chrome_update.exe",
          "s1.sha256":
            "3c4f8a1b2e5d6c7890abcdef1234567890abcdef1234567890abcdef12345678",
          "s1.fileCount_renamed": "15847",
          "s1.extensionAdded": ".lockbit",
          "s1.storylineId": "0x1A2B3C4D",
          "s1.agentComputerName": "LAPTOP-JSMITH",
          "s1.userName": "j.smith",
          "s1.action": "Quarantine",
          "s1.rollbackStatus": "Available",
        },
      },
      questions: [
        {
          question:
            "The malware process is named 'chrome_update.exe' and appears to have been launched by 'explorer.exe' (the Windows file manager). Why is the name 'chrome_update.exe' significant as a red flag?",
          options: [
            "Chrome never releases updates, so any chrome_update.exe is automatically malware",
            "Attackers name their malware after trusted applications to trick users into running it; legitimate Chrome updates are delivered through Chrome itself, not via a .exe in AppData\\Temp",
            "The .exe extension is forbidden on Windows systems and should never appear",
            "The process ID 7291 is reserved for system processes only",
          ],
          answer: 1,
          explanation:
            "This is a classic attacker technique called 'masquerading' (MITRE T1036). By naming ransomware 'chrome_update.exe', the attacker hopes users and analysts will dismiss it as a routine update. However, legitimate Google Chrome updates are delivered automatically through the Chrome application itself — they never appear as standalone .exe files in the user's AppData\\Local\\Temp folder. Any 'updater' in a Temp folder should be treated with extreme suspicion.",
          xp: 50,
        },
        {
          question:
            "The field 's1.rollbackStatus: Available' appears in the detection. Given that 15,847 files have already been encrypted, what does this mean for incident response?",
          options: [
            "The ransomware has already successfully completed its attack and no recovery is possible",
            "SentinelOne can restore the encrypted files to their pre-attack state using its pre-captured snapshots, potentially preventing data loss",
            "The rollback feature will reinstall Windows on the affected laptop",
            "A rollback is available but will only work if the user manually approves it within 60 seconds",
          ],
          answer: 1,
          explanation:
            "SentinelOne's rollback capability continuously takes snapshots of file changes. When ransomware is detected, those snapshots allow the platform to reverse the encryption — restoring the original files and deleting the encrypted versions. 'Rollback Available' means this recovery option exists for this incident. This is one of SentinelOne's most powerful differentiators — other EDR platforms can stop the attack but cannot undo the damage already done.",
          xp: 50,
        },
        {
          question:
            "What is the StorylineID for this attack, and why is it useful?",
          options: [
            "The StorylineID is 'LockBit3' — the malware family name used to group all detections",
            "The StorylineID is '0x1A2B3C4D' — a unique identifier that links all events in this attack chain together so analysts can see the complete attack story in one view",
            "The StorylineID is 'j.smith' — the username of the affected account",
            "The StorylineID is the SentinelOne detection policy ID that triggered this alert",
          ],
          answer: 1,
          explanation:
            "The StorylineID (0x1A2B3C4D in this case) is SentinelOne's unique tag assigned to every event in this attack chain. Every file encryption, every registry change, every network connection made by this ransomware campaign gets tagged with the same StorylineID. In the SentinelOne console, filtering by this ID shows the analyst the complete attack story — from the initial file drop through all 15,847 file renames — in a single, connected timeline.",
          xp: 50,
        },
      ],
    },

    // ── Flag Task ─────────────────────────────────────────────────────────────
    {
      type: "flag",
      id: "s1-flag1",
      prompt:
        "Look at the SentinelOne ransomware detection above. The ransomware added a specific file extension to every file it encrypted, turning 'document.docx' into 'document.docx.XXXX'. What extension did the ransomware add? Check the field 's1.extensionAdded' in the raw log. (Enter the extension without the dot)",
      answer: "lockbit",
      hint: "Look at the 's1.extensionAdded' field in the raw log data above. The ransomware family name matches the extension it appends.",
      xp: 40,
    },

    // ── Question 4 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "s1-q4",
      question:
        "SentinelOne's 'Static AI' engine scans files before they execute. What is the key advantage of this approach compared to traditional signature-based antivirus?",
      options: [
        "Static AI only works on files downloaded from the internet, not files on USB drives",
        "Static AI uses ML models trained on millions of samples to identify malicious characteristics even in files never seen before — catching zero-day malware that has no existing signature",
        "Static AI requires an internet connection to query a signature database before every scan",
        "Static AI only scans .exe files and ignores other file types like .dll or .js",
      ],
      answer: 1,
      explanation:
        "Traditional antivirus works by matching files against a database of known malware signatures — if the signature exists, the file is blocked; if not, it passes through. Attackers defeat this by constantly modifying their malware (even a single byte change creates a new hash). SentinelOne's Static AI uses machine learning models trained on structural characteristics of millions of files — it recognises malicious *patterns* in the file's code and structure, not just exact matches to known samples. This means it can catch entirely new (zero-day) malware on first encounter.",
      xp: 35,
    },

    // ── Question 5 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "s1-q5",
      question:
        "What is the difference between SentinelOne's 'Detect Mode' and 'Protect Mode' for the endpoint agent?",
      options: [
        "Detect Mode only works on Windows; Protect Mode works on all operating systems",
        "Detect Mode monitors and logs threats for analyst review without blocking them; Protect Mode autonomously blocks, kills, and quarantines threats in real-time without waiting for human approval",
        "Detect Mode uses AI detection; Protect Mode uses only signature-based detection",
        "Both modes are identical; the difference is only in the reporting format",
      ],
      answer: 1,
      explanation:
        "In Detect Mode, the SentinelOne agent observes and records suspicious activity but takes no automatic blocking action — it waits for an analyst to review and respond. This is often used during initial deployment to reduce the risk of false positives blocking legitimate software. In Protect Mode, the agent acts autonomously: it kills malicious processes, quarantines files, isolates the network, and can trigger a rollback — all without human approval. The goal of Protect Mode is to stop attacks in milliseconds, faster than any human can respond.",
      xp: 35,
    },
  ],
};

// ---------------------------------------------------------------------------
// Room 3 — Malware Analysis Fundamentals
// ---------------------------------------------------------------------------

const malwareAnalysisFundamentals: Room = {
  id: "malware-analysis-fundamentals",
  title: "Malware Analysis Fundamentals",
  description:
    "Learn how to analyse malware — the malicious software behind most cyber attacks. Understand the difference between static and dynamic analysis, what tools analysts use, and how to extract indicators of compromise (IOCs) from a suspicious file without ever needing to be a programmer.",
  difficulty: "intermediate",
  category: "Threat Intelligence",
  estimatedMinutes: 55,
  xp: 550,
  icon: "🦠",
  prerequisites: ["endpoint-security-fundamentals"],
  tasks: [
    // ── Reading 1: What Is Malware Analysis ───────────────────────────────────
    {
      type: "reading",
      id: "malware-r1",
      heading: "What Is Malware Analysis — and Why Do SOC Analysts Need It?",
      content: `When a security alert fires in a SOC — "suspicious file detected on LAPTOP-JSMITH" — the SOC analyst faces an immediate question: **Is this file actually malicious, and if so, what is it capable of?**

This is where **malware analysis** comes in. Malware analysis is the process of studying a suspicious program to understand what it does, how it works, and what indicators of its presence you can use to find it elsewhere in your environment.

**Why SOC Analysts Need Malware Analysis Skills**

You don't need to be a software engineer or reverse engineer to benefit from basic malware analysis. Even surface-level analysis gives a SOC analyst:

- **Triage answers fast:** Is this a high-priority incident or a false positive? Knowing whether a file's hash matches known ransomware changes your response completely.
- **IOC extraction:** Every piece of malware leaves traces — IP addresses it connects to, registry keys it creates, filenames it drops. Extracting these **Indicators of Compromise (IOCs)** lets you search your entire environment: "Has any other machine contacted this IP?"
- **Detection rule creation:** Once you understand what malware does, you can write YARA rules (pattern-matching rules) or SIEM detection rules to catch it — or similar malware — across your organisation.
- **Threat actor attribution:** The techniques a malware sample uses, the infrastructure it connects to, and its code structure often reveal *who* wrote it and *what campaign* it belongs to.

**Types of Malware**

Before analysing malware, it helps to know the major categories:

- **Trojan:** Malware disguised as legitimate software. A "free video player" that is actually a keylogger. Named after the Trojan Horse.
- **RAT (Remote Access Trojan):** A Trojan that specifically gives the attacker remote control of the victim's computer. Examples: AsyncRAT, NjRAT, Quasar RAT.
- **Ransomware:** Malware that encrypts files and demands payment to restore them. Modern ransomware families: LockBit, BlackCat, Cl0p, BlackBasta.
- **Rootkit:** Malware that hides itself deeply in the operating system, often at the kernel level, to avoid detection. Very difficult to remove.
- **Spyware:** Malware that silently monitors user activity — keystrokes, screenshots, clipboard contents — and sends the data to an attacker.
- **Wiper:** Malware designed to permanently destroy data with no recovery option. Often used in nation-state attacks to cause maximum damage. Examples: WhisperGate (Ukraine 2022), Shamoon (Saudi Aramco 2012).
- **Dropper/Loader:** A first-stage malware whose only job is to download and install the *real* malware. Often used to evade detection (the dropper looks benign; the actual malicious payload is downloaded later).

**Three Approaches to Analysis**

1. **Static Analysis:** Examine the malware *without running it*. Look at the file's structure, strings, imports, and metadata. Safe because the malware never executes and cannot harm your machine.

2. **Dynamic Analysis:** *Run* the malware in a controlled, isolated environment and watch what it does. More revealing than static analysis because you see actual behaviour, but requires careful isolation.

3. **Hybrid Analysis:** Combine both. Start with static analysis to understand the file's structure, then run it dynamically to see its actual behaviour. Use the outputs of each to inform the other.

Most professional SOC analysts use online sandboxes for quick dynamic analysis — they upload the suspicious file to a website that runs it in an isolated virtual machine and reports all the observed behaviour. No setup required.`,
    },

    // ── Reading 2: Static Analysis Tools ─────────────────────────────────────
    {
      type: "reading",
      id: "malware-r2",
      heading: "Static Analysis: Examining Malware Without Running It",
      content: `Static analysis is the art of understanding a malicious file by *reading* it rather than *running* it. Think of it like examining a weapon found at a crime scene: you don't fire the gun to understand it — you study its markings, manufacturer stamps, and serial number.

**Step 1 — File Hashing: The Malware Fingerprint**

Every file has a **cryptographic hash** — a unique mathematical fingerprint calculated from the file's contents. Change even a single byte of the file and the hash changes completely. The three most common hash algorithms are:

- **MD5 (Message Digest 5):** 32 hexadecimal characters. Fast to calculate. Example: \`a1b2c3d4e5f6789012345678\`. No longer considered cryptographically secure (collisions possible), but still widely used for malware tracking.
- **SHA-1 (Secure Hash Algorithm 1):** 40 characters. Also deprecated for security purposes.
- **SHA-256:** 64 characters. The **preferred standard** for malware analysis. Computationally infeasible to forge. Example: \`5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b\`

Why do hashes matter? Once you have a SHA-256 hash, you can:
- Look it up on **VirusTotal** — paste the hash and see if any of 70+ antivirus engines recognise it as malicious
- Search **MalwareBazaar** (a free public repository) for samples with the same hash
- Share the hash with other organisations as an IOC — anyone who finds the same hash knows they have the same malware

**Step 2 — Strings Extraction**

Binary programs (.exe files) are mostly machine code that humans can't read. But embedded within that machine code are **strings** — sequences of human-readable text that the program uses. Extracting strings from a malware sample can be incredibly revealing:

- **URLs:** \`http://185.220.101.45/update/check.php\` — the attacker's command-and-control server
- **Domain names:** \`c2server.evildomain.ru\` — another C2 indicator
- **Registry paths:** \`HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\` — the malware is establishing persistence
- **Function names:** \`CreateRemoteThread, VirtualAllocEx\` — signs of process injection
- **Error messages:** Attackers often leave debugging text in their code, revealing what the malware was designed to do

Tools: **strings** (Linux command), **BinText** (Windows GUI), **FLOSS** (FireEye Labs Obfuscated String Solver — specifically designed to extract obfuscated strings that simple tools miss).

**Step 3 — PE File Analysis**

Most Windows malware is in **PE (Portable Executable)** format — the standard format for .exe and .dll files on Windows. The PE format has a specific structure with sections and headers that reveal a lot about the program's capabilities.

**PEStudio** is the go-to free tool for PE analysis. It shows:
- **File metadata:** Compilation timestamp (when was the malware compiled?), original file name, version info, digital signature (is it signed? By whom?)
- **Sections:** PE files are divided into sections. \`.text\` contains executable code. \`.data\` contains global variables. \`.rsrc\` contains resources (icons, strings, embedded files). If \`.text\` is unusually large or has a very high entropy (randomness), the malware may be packed/obfuscated.
- **Imports:** A list of Windows API functions the program calls. This tells you what the malware can *do*:
  - Imports **WinINet.dll** functions (InternetOpen, InternetConnect) → makes HTTP connections → probably communicates with a C2 server
  - Imports **Crypt32.dll** functions → performs encryption → possibly ransomware
  - Imports **WS2_32.dll** functions (socket, connect, send) → raw network sockets → advanced network communication
  - Imports **Advapi32.dll** (RegSetValueEx, CreateService) → modifies registry or creates services → persistence mechanisms

**Step 4 — YARA Rules: Pattern Matching**

**YARA** is a tool that lets security researchers write pattern-matching rules to identify malware based on specific byte sequences, strings, or structural features. A YARA rule might say: "If a file contains the string 'MiniDump' AND imports the function 'RtlCopyMemory' AND the file size is under 100KB, flag it as a potential credential dumper."

YARA rules are widely shared in the security community. **VirusTotal** runs YARA rules against uploaded files. Tools like **YARA-X** (the newer version) allow scanning your entire file system for matching files.`,
    },

    // ── Reading 3: Dynamic Analysis & Sandboxes ───────────────────────────────
    {
      type: "reading",
      id: "malware-r3",
      heading: "Dynamic Analysis: Running Malware Safely in a Sandbox",
      content: `Static analysis tells you what malware *could* do based on its code and imports. **Dynamic analysis** shows you what malware *actually does* when it runs — which is often more revealing, especially for modern malware that hides its intentions through obfuscation, encryption, or staged loading.

**What Is a Sandbox?**

A **sandbox** is an isolated virtual environment — a completely separate virtual machine (VM) cut off from your real network — that is designed to be disposable. You run the suspicious file inside the sandbox, observe everything it does, then discard the VM (returning it to a clean snapshot). The malware cannot escape to infect your real systems.

Think of a sandbox like a quarantine room in a hospital. The patient (malware) is brought in, examined thoroughly, but cannot leave to infect anyone else.

**Online Sandbox Services (No Setup Required)**

For SOC analysts, the fastest approach is to use a public online sandbox. Upload the suspicious file, wait a few minutes, and receive a full behavioural report:

- **ANY.RUN** (any.run): Interactive sandbox — you can actually *click* inside the running VM in real-time, seeing the malware execute step by step. Shows API calls, network connections, file system changes, process tree. Has a free tier.
- **Hybrid Analysis** (hybrid-analysis.com): Combines sandbox results from multiple engines (Falcon Sandbox, Cuckoo). Extensive reporting. Free tier available.
- **Joe Sandbox** (joesandbox.com): Enterprise-grade analysis with deep behavioural reporting. More detailed than most free tools.
- **Tria.ge** (tria.ge): Fast public sandbox, popular in the malware analysis community. Free with registration.
- **VirusTotal** (virustotal.com): Not just antivirus scanning — VirusTotal runs uploaded files through multiple sandbox engines and displays behaviour reports. Useful first stop.

**WARNING — Confidential Files:** Never upload a suspicious file that might contain confidential business data (a client contract, a financial spreadsheet) to a *public* sandbox. Public sandboxes share results with their entire user community. If the file contains sensitive data, use a private/on-premises sandbox instead.

**What Does a Sandbox Report Show?**

A sandbox execution report is a complete record of everything the malware did during its execution window (typically 60–180 seconds):

- **Process tree:** Which processes were launched, in what order, by what parent
- **API calls:** Every Windows API function the malware called, with parameters. If it called \`CreateFile("C:\\Windows\\System32\\svchost.exe")\`, you know it's writing or reading that file.
- **Network activity:** Every DNS query, HTTP request, TCP/UDP connection. This reveals the C2 server addresses.
- **File system changes:** Files created, modified, or deleted. A ransomware sample might create thousands of new encrypted files and delete the originals.
- **Registry changes:** New registry keys created (especially in Run/RunOnce — persistence) or existing keys modified
- **Screenshots:** Some sandboxes take screenshots at regular intervals so you can see what the malware displayed to the user

**Common Malware Behaviours to Look For**

- **Persistence:** The malware adding itself to startup locations:
  - Registry: \`HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\`
  - Scheduled Task creation
  - Windows Service installation
  - Startup folder drop

- **Evasion — Living Off the Land (LOLBins):** Instead of using its own code, the malware uses legitimate Windows tools: \`powershell.exe\`, \`certutil.exe\`, \`mshta.exe\`, \`regsvr32.exe\`. Since these are trusted system tools, they can bypass many security controls.

- **C2 Communication Patterns:**
  - Regular HTTP/HTTPS requests to an external domain at fixed intervals (beaconing)
  - DNS queries for algorithmically generated domain names (Domain Generation Algorithm — DGA). Instead of connecting to a fixed domain, the malware generates a new pseudo-random domain every day (e.g., \`xk7pmq9r.net\` today, \`bz3lnvw4.net\` tomorrow). Hard to block because defenders don't know which domain is next.

- **Process Injection:** Malware injecting its code into a trusted process (svchost.exe, explorer.exe) to hide itself. Key API calls: \`VirtualAllocEx, WriteProcessMemory, CreateRemoteThread\`.

**Analyst Toolkit for Local Dynamic Analysis**

When you need deeper analysis beyond what an online sandbox provides:
- **Process Monitor (ProcMon):** Microsoft Sysinternals tool that logs every file, registry, and network event generated by every process. Essential for local dynamic analysis.
- **Wireshark:** Captures all network traffic. Use it inside a sandbox VM to see exactly what the malware sends and receives.
- **x64dbg / OllyDbg:** Debuggers that let you step through malware code instruction by instruction. This is reverse engineering — more advanced.
- **Ghidra:** Free NSA-developed tool for decompiling binary code back into readable C-like code. The free alternative to IDA Pro.`,
    },

    // ── Question 1 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "malware-q1",
      question:
        "A suspicious file arrives in a phishing email. A SOC analyst runs a SHA-256 hash of the file and searches it on VirusTotal. The result shows '0/72 vendors detected this as malicious'. Does this mean the file is definitely safe?",
      options: [
        "Yes — if 72 antivirus engines don't detect it, it is definitely clean",
        "No — the file could be a zero-day malware sample that no vendor has seen yet, or it could be deliberately crafted to evade signature detection. Additional analysis is required.",
        "Yes — VirusTotal is 100% accurate and zero detections means zero risk",
        "No — VirusTotal only scans .pdf files and cannot analyse .exe files",
      ],
      answer: 1,
      explanation:
        "A '0/72' result on VirusTotal means no known signatures match this file — but that's not the same as 'definitely safe'. Modern attackers regularly test their malware against VirusTotal before deploying it, and deliberately modify it until detection reaches 0/72. A zero detection can mean the file is clean, or it can mean it's a sophisticated new sample. Analysts should follow up with behavioural analysis (sandboxing) for any file arriving in a suspicious context.",
      xp: 35,
    },

    // ── Question 2 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "malware-q2",
      question:
        "While performing PE file analysis in PEStudio, an analyst notices the malware imports functions from 'WS2_32.dll' and 'WinINet.dll'. What does this reveal about the malware's capabilities?",
      options: [
        "The malware can only print documents and does not perform any network activity",
        "The malware has network communication capabilities — WS2_32 provides raw socket functions and WinINet provides HTTP/S internet connectivity, suggesting it will communicate with a remote server",
        "The malware is a legitimate web browser component used by internet Explorer",
        "The malware encrypts files on disk — these DLLs are Windows encryption libraries",
      ],
      answer: 1,
      explanation:
        "DLL imports are a window into a program's capabilities. WS2_32.dll (Winsock 2) provides Windows networking at the raw socket level — the malware can make TCP/UDP connections to any IP. WinINet.dll provides higher-level HTTP/HTTPS internet functions. Together, these imports strongly suggest the malware will communicate with an external server — likely a C2 (command and control) server. This is a critical IOC: the analyst should run the sample in a sandbox to capture the actual IP addresses and domains it connects to.",
      xp: 35,
    },

    // ── Question 3 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "malware-q3",
      question:
        "What is a 'Domain Generation Algorithm' (DGA) and why do attackers use it?",
      options: [
        "A tool for registering new company domain names at reduced cost",
        "A technique where malware generates pseudo-random domain names on a daily schedule, making C2 infrastructure extremely difficult to block because defenders cannot predict which domain the malware will use next",
        "An algorithm that detects malicious domains in web traffic using machine learning",
        "A Windows feature that assigns domain names to computers on a local network",
      ],
      answer: 1,
      explanation:
        "If malware connects to a hardcoded domain like 'evil-c2.ru', defenders simply block that domain and the malware is neutralised. DGA solves this problem for attackers by generating a new, random-looking domain name every day (or hour). The attacker only needs to register *one* of those domains at the right time. Defenders must block potentially thousands of domains. DGA is used by sophisticated malware families including Emotet, Conficker, and Necurs botnet. Detection relies on analysing the statistical randomness of queried domain names.",
      xp: 35,
    },

    // ── Log Analysis ──────────────────────────────────────────────────────────
    {
      type: "log_analysis",
      id: "malware-la1",
      heading: "Microsoft Defender Alert: Malware Detected in Downloads Folder",
      context:
        "A Level 1 SOC analyst receives a Microsoft Defender alert from an employee's workstation. The alert was triggered by a file in the Downloads folder. The employee says they opened what they thought was an invoice PDF from a supplier. The file extension was .exe, not .pdf. Analyse the detection below.",
      event: {
        id: "av-evt-emotet-001",
        ts: "2025-06-17T14:23:05.000Z",
        source: "av",
        vendor: "Microsoft Defender",
        event_type: "av_detection",
        severity: "high",
        hostname: "DESKTOP-FINANCE01",
        user_email: "j.smith@corp.com",
        mitre_technique: "T1566.001",
        mitre_tactic: "Initial Access",
        description:
          "Microsoft Defender detected and quarantined Trojan:Win32/Emotet.A!ml from a file downloaded via email. File masqueraded as an invoice PDF.",
        file: {
          name: "Invoice_2025_06.exe",
          path: "C:\\Users\\j.smith\\Downloads\\Invoice_2025_06.exe",
          sha256:
            "5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b",
          md5: "a1b2c3d4e5f6789012345678",
          size: 245760,
        },
        process: {
          name: "explorer.exe",
          pid: 1204,
          path: "C:\\Windows\\explorer.exe",
          user: "j.smith",
        },
        raw: {
          "data.ms365.ThreatName": "Trojan:Win32/Emotet.A!ml",
          "data.ms365.Action": "Quarantine",
          "data.ms365.FilePath":
            "C:\\Users\\j.smith\\Downloads\\Invoice_2025_06.exe",
          "data.ms365.SHA256":
            "5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b",
          "data.ms365.MD5": "a1b2c3d4e5f6789012345678",
          "data.ms365.FileSize": "245760",
          "data.ms365.OriginalFileName": "Invoice_2025_06.exe",
          "data.ms365.CompanyName": "",
          "data.ms365.ProcessName": "explorer.exe",
          "data.ms365.UserName": "j.smith",
        },
      },
      questions: [
        {
          question:
            "The threat name is 'Trojan:Win32/Emotet.A!ml'. What does the '!ml' suffix at the end indicate?",
          options: [
            "The malware uses multiple languages (multilingual) in its code",
            "The detection was made by machine learning, not a traditional signature — meaning the file's behaviour or structure matched a trained AI model, not a known exact signature",
            "The malware is part of the 'ML' threat actor group",
            "The detection severity is 'medium-low' as indicated by the ML abbreviation",
          ],
          answer: 1,
          explanation:
            "In Microsoft Defender's naming convention, the '!ml' suffix means the detection was made by a machine learning model rather than a traditional virus signature. This is important context: the file may not be in VirusTotal's signature database yet, but Defender's AI recognised its malicious characteristics. 'Emotet' is the malware family name — Emotet is a notorious banking trojan / malware loader that was one of the world's most dangerous botnets before a 2021 law enforcement takedown (and subsequent resurrection).",
          xp: 50,
        },
        {
          question:
            "The 'data.ms365.CompanyName' field is empty ('\"\"'). During static analysis of a legitimate software file (like a browser or Office application), this field typically contains the publisher's name. Why is an empty CompanyName field suspicious for an .exe file?",
          options: [
            "All Windows executable files have empty company names — this field is not used by Windows",
            "Legitimate commercial software is almost always digitally signed and includes company metadata. An empty CompanyName suggests the file was not professionally compiled and signed — a common characteristic of malware or hastily created attack tools.",
            "Empty company name indicates the file was compiled in a country that does not require software registration",
            "This field is only populated for files downloaded from official Microsoft websites",
          ],
          answer: 1,
          explanation:
            "During PE (Portable Executable) analysis, the version information embedded in legitimate software (Microsoft, Google, Adobe, etc.) always includes the CompanyName, ProductName, FileDescription, and digital signature. Malware authors typically don't bother filling in these metadata fields, or deliberately leave them blank to avoid easy identification. An empty CompanyName on an .exe pretending to be a supplier invoice is a strong static analysis indicator of malicious intent.",
          xp: 50,
        },
        {
          question:
            "The analyst wants to determine if this exact malware sample has reached any other endpoints in the organisation. What is the FASTEST method to check?",
          options: [
            "Physically visit every employee's computer and manually check their Downloads folder",
            "Send a company-wide email asking employees if they received an invoice email",
            "Search the SIEM or EDR platform for the file's SHA-256 hash ('5a6b7c8d...') across all endpoints to find any other machine that has seen this exact file",
            "Submit the file to VirusTotal and wait for other organisations to report the same hash",
          ],
          answer: 2,
          explanation:
            "The SHA-256 hash is a unique fingerprint for this exact file. Any EDR platform (CrowdStrike, SentinelOne, Microsoft Defender) or SIEM with endpoint telemetry can be queried: 'Show me every endpoint that has seen the file with hash 5a6b7c8d...'. This search returns results in seconds and covers your entire environment simultaneously. This is exactly why SHA-256 hashes are a core IOC type — they enable instant enterprise-wide hunting.",
          xp: 50,
        },
      ],
    },

    // ── Flag Task ─────────────────────────────────────────────────────────────
    {
      type: "flag",
      id: "malware-flag1",
      prompt:
        "A SOC analyst needs to share the SHA-256 hash of the detected malware with another team so they can hunt for it in their environment. Looking at the detection above, what are the FIRST 8 characters of the SHA-256 hash? (Hint: find the 'data.ms365.SHA256' field in the raw log)",
      answer: "5a6b7c8d",
      hint: "SHA-256 hashes are 64 hexadecimal characters long. The field is 'data.ms365.SHA256' in the raw log section. Copy just the first 8 characters.",
      xp: 40,
    },

    // ── Question 4 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "malware-q4",
      question:
        "Why should a SOC analyst NEVER upload a suspicious file to a public online sandbox (like VirusTotal or ANY.RUN) if the file came from a company's internal email system and might contain sensitive business data?",
      options: [
        "Public sandboxes only accept files under 1 KB in size",
        "Public sandbox results are shared with the entire security community — any file uploaded becomes visible to other researchers worldwide, which could expose confidential client data, legal documents, or trade secrets",
        "Sandboxes can only analyse malware, not regular files, so the upload would fail",
        "The file would automatically be emailed back to the original sender",
      ],
      answer: 1,
      explanation:
        "Public sandboxes like VirusTotal make submitted files and their analysis available to all registered users (and in some cases, the public). If an employee sent a suspicious email attachment that turned out to be a legitimate (but mislabelled) confidential contract, HR document, or source code file — uploading it to VirusTotal would expose that data to the entire security research community. Always assess whether a file might contain sensitive data before submitting to any public analysis platform. For sensitive files, use a private sandbox or remove sensitive content first.",
      xp: 35,
    },

    // ── Question 5 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "malware-q5",
      question:
        "A sandbox report for a suspicious executable shows it queried the Windows registry key 'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' and wrote a new value pointing to itself. What does this behaviour indicate?",
      options: [
        "The malware is checking for Windows Update availability",
        "The malware is establishing persistence — this registry key makes programs run automatically every time the user logs into Windows",
        "The malware is reading user preferences from the system registry",
        "The malware is uninstalling itself from the system",
      ],
      answer: 1,
      explanation:
        "The Run registry key is one of the oldest and most common persistence mechanisms in Windows. Any program added to HKEY_CURRENT_USER\\...\\Run or HKEY_LOCAL_MACHINE\\...\\Run automatically starts every time Windows boots or a user logs in. Malware adds itself to this key so that even if the user reboots their computer, the malware starts again automatically. This is why sandbox reports specifically highlight Run key modifications — they're a clear sign of an attempt to survive beyond the current user session.",
      xp: 35,
    },
  ],
};

// ---------------------------------------------------------------------------
// Room 4 — IOC Analysis & Threat Pivoting
// ---------------------------------------------------------------------------

const iocAnalysis: Room = {
  id: "ioc-analysis",
  title: "IOC Analysis & Threat Pivoting",
  description:
    "Master the art of investigating Indicators of Compromise. Learn to use VirusTotal, AbuseIPDB, Shodan, and other open-source intelligence (OSINT) tools to research suspicious IPs, domains, hashes, and URLs. Understand IOC pivoting — the technique of starting with one indicator and discovering an entire threat actor's infrastructure.",
  difficulty: "intermediate",
  category: "Threat Intelligence",
  estimatedMinutes: 50,
  xp: 500,
  icon: "🔎",
  prerequisites: ["malware-analysis-fundamentals"],
  tasks: [
    // ── Reading 1: IOC Types & the Pyramid of Pain ────────────────────────────
    {
      type: "reading",
      id: "ioc-r1",
      heading: "What Are IOCs — and Which Ones Actually Matter?",
      content: `When an attacker breaks into a network, they leave traces behind. These digital breadcrumbs are called **Indicators of Compromise (IOCs)** — specific, observable pieces of evidence that a system has been compromised or targeted.

IOCs are the raw material of threat intelligence. A SOC analyst uses them to:
- Determine if an incident has occurred
- Find other affected systems in the environment
- Block future attacks using the same infrastructure
- Attribute attacks to known threat actor groups
- Share intelligence with other organisations

**Types of IOCs**

IOCs come in several varieties, each describing a different aspect of an attack:

- **File Hashes (MD5, SHA-1, SHA-256):** The cryptographic fingerprint of a specific malware file. Hash: \`5a6b7c8d9e0f1a2b...\`
- **IP Addresses:** The internet address of an attacker's server. Example: \`185.220.101.45\`
- **Domain Names:** The website address associated with attack infrastructure. Example: \`evil-c2.onion-router.cc\`
- **URLs:** Specific web addresses used in attacks. Example: \`http://185.220.101.45/payload/stage2.bin\`
- **Email Addresses:** Attacker contact addresses used in phishing campaigns
- **Registry Keys:** Windows registry modifications associated with malware persistence. Example: \`HKCU\\Software\\Microsoft\\Windows\\Run\\svchost32\`
- **File Names and Paths:** Specific filenames malware creates or uses. Example: \`C:\\Windows\\Temp\\lsass.dmp\`
- **Mutex Names:** Unique named objects malware creates in Windows memory to avoid running twice. Example: \`Global\\{A1B2C3D4-E5F6-...}\`. Highly specific — a perfect IOC.
- **User-Agent Strings:** Specific HTTP headers malware uses when communicating with a C2 server
- **X.509 Certificates:** TLS certificates used on attacker-controlled servers

**The Pyramid of Pain: Not All IOCs Are Equal**

Security researcher David Bianco developed the **Pyramid of Pain** — a model that ranks IOC types by how *painful* it is for an attacker when defenders block them:

At the **bottom of the pyramid** (easy to change, low pain for attackers):
- **Hash values:** Attacker changes one byte of their malware → completely new hash. Trivially easy to evade.

In the **middle** (moderately difficult to change):
- **IP addresses and Domain Names:** Attackers can rent new servers or change DNS records, but it takes time and resources.

Near the **top** (difficult to change, high pain for attackers):
- **Network/Host Artefacts:** Specific patterns in network traffic or files left on disk. Harder to change because these are inherent to how the tool works.

At the **very top** (hardest to change, maximum pain):
- **TTPs (Tactics, Techniques, and Procedures):** The *way* an attacker operates — their playbook. If you can detect "PowerShell downloading a payload and injecting into svchost.exe", the attacker must completely retrain and retool to evade you. This is why MITRE ATT&CK is so valuable — it focuses on TTP-level detection.

**Practical Implication:** When a vendor says "we blocked this attack by detecting the malware hash", that's useful but weak. A sophisticated attacker will simply recompile their malware. When a vendor says "we detected lateral movement via PsExec combined with LSASS dumping" — that's TTP-level detection that's much harder for attackers to evade.

**IOC Lifecycle**

IOCs have a shelf-life. A domain used for a phishing campaign last month may be abandoned today and reassigned to a legitimate website. An IP address used by a threat actor last week might now belong to an innocent cloud customer. Always note the **first seen / last seen** dates on any IOC, and treat stale IOCs (older than 3-6 months) with appropriate scepticism.`,
    },

    // ── Reading 2: VirusTotal & OSINT Tools ───────────────────────────────────
    {
      type: "reading",
      id: "ioc-r2",
      heading: "VirusTotal and the OSINT Analyst Toolkit",
      content: `**Open-Source Intelligence (OSINT)** refers to intelligence gathered from publicly available sources — no hacking required. For threat intelligence and IOC analysis, a robust set of free OSINT tools exists. Here is your professional toolkit:

**VirusTotal (virustotal.com) — The Essential Starting Point**

VirusTotal is the most widely used threat intelligence lookup platform in cybersecurity. It aggregates results from 70+ antivirus engines, sandbox systems, and blocklists into a single interface.

What you can submit to VirusTotal:
- **File or hash:** Upload a file or paste a SHA-256/MD5 hash. See detection rates from 70+ engines. View behaviour sandboxes. See which domains the file contacted.
- **URL:** Scan a web address for malicious content. See if the URL appears on phishing/malware blocklists.
- **IP address:** See if an IP is associated with known malicious activity. View which malware samples communicated with this IP (**"Communicating Files"** tab). See passive DNS history — which domains have pointed to this IP over time.
- **Domain:** Similar to IP — see reputation, passive DNS, subdomains, associated files.

**How to Read a VirusTotal IP Report:**
1. **Detection ratio:** "7/89 security vendors flagged this IP as malicious" — 7 vendors consider it malicious. Higher number = higher confidence it's bad.
2. **Last analysis date:** If the report is 18 months old, the data may be stale.
3. **Community score:** User-submitted votes. Negative score = community says it's malicious.
4. **Relations tab:** Shows files that communicated with this IP, URLs hosted on this IP, and domains that resolved to this IP. This is where IOC pivoting begins.
5. **Passive DNS:** A historical record of all domain names that have pointed to this IP. Incredibly useful for finding related infrastructure.

**AbuseIPDB (abuseipdb.com) — IP Abuse Reports**

AbuseIPDB is a community-powered database where security professionals report IP addresses that have attacked them. For each reported IP, you see:
- **Abuse confidence score (0-100%):** Higher = more likely malicious
- **Report count:** How many times this IP has been reported
- **Report categories:** Brute force, web app attack, DDoS, scanning, email spam, SSH attack, etc.
- **Recent report details:** Which ports were targeted, what attack was observed

An IP with 3,847 reports and 95% confidence (like the one in the log analysis below) is almost certainly malicious or compromised.

**Shodan (shodan.io) — The Search Engine for Connected Devices**

Shodan continuously scans the entire internet and indexes information about every publicly accessible device: what ports are open, what services are running, what software versions are installed. For threat intelligence:
- Look up an IP to see what services it's running. A suspicious IP running Cobalt Strike's default port (50050) is a strong indicator of C2 infrastructure.
- Search for specific service banners to find all instances of a particular C2 framework's default configuration
- Identify the hosting provider (ASN) of an IP — Tor exit nodes, bulletproof hosting providers, or anonymisation services are frequently used by attackers

**URLScan.io (urlscan.io) — Safe URL Analysis**

Submit any URL and URLScan.io visits it in an isolated browser, taking screenshots and recording all HTTP transactions, JavaScript execution, and resources loaded — without you ever clicking the link yourself. Perfect for safely analysing phishing URLs.

**AlienVault OTX (otx.alienvault.com) — Community Threat Intelligence**

OTX (Open Threat Exchange) is a free platform where security researchers worldwide share threat intelligence in **pulses** — collections of IOCs linked to a specific campaign or malware family. You can:
- Look up any IOC to see if it appears in a known pulse
- Subscribe to pulses from trusted researchers
- Connect OTX to your SIEM for automatic IOC matching

**MXToolbox (mxtoolbox.com) — Email & DNS Investigations**

Essential for phishing investigations:
- **MX Lookup:** Who handles email for a domain?
- **SPF/DKIM/DMARC check:** Is the sending domain properly configured to prevent spoofing?
- **Blacklist check:** Is this email server IP on any spam/abuse blacklists?
- **WHOIS lookup:** Who registered this domain, and when? A domain registered yesterday sending invoices is suspicious.`,
    },

    // ── Reading 3: IOC Pivoting & MISP ────────────────────────────────────────
    {
      type: "reading",
      id: "ioc-r3",
      heading: "IOC Pivoting: Turning One Clue Into a Full Picture",
      content: `**IOC Pivoting** is the investigation technique where you start with a single indicator and use it to discover related infrastructure, related malware samples, and ultimately the full scope of a threat actor's campaign. It is the cybersecurity equivalent of detective work — following one clue to the next.

**A Real Pivoting Example**

Suppose you receive a phishing report. The employee clicked a link and you extract the URL: \`http://185.220.101.45/invoice-portal/login.php\`

Here is how IOC pivoting works:

**Step 1 — Look up the IP on VirusTotal and AbuseIPDB**
- VirusTotal shows the IP has been reported by 7 vendors as malicious
- AbuseIPDB shows 3,847 reports, tagged as "Tor Exit Node / Scanning / Proxy"
- You look at the **Relations tab** in VirusTotal → Passive DNS shows 4 other domains have pointed to this IP: \`secure-login-portal.cc\`, \`invoice-verify.net\`, \`billing-auth.com\`, \`payment-update.org\`

**Step 2 — Research the related domains**
- You look up \`secure-login-portal.cc\` on VirusTotal
- It shows 12 phishing URLs on this domain
- The **WHOIS record** shows it was registered 3 days ago using a privacy protection service in Russia
- URLScan shows the page is a fake Office 365 login portal

**Step 3 — Find associated malware**
- VirusTotal's "Communicating Files" tab for the IP shows 3 malware samples that phoned home to this IP
- You download the SHA-256 hashes of those samples: \`3c4f8a1b...\`, \`7e9d2f4a...\`, \`1b3c5d7e...\`
- You search your SIEM for any of these hashes on your endpoints → you find one match on a machine in accounting

**Result of pivoting:** You started with one phishing URL and discovered: 4 related phishing domains, an attacker-controlled IP server, 3 malware samples, and an infected endpoint in your own environment — none of which you would have found by only blocking the original URL.

**MISP: Malware Information Sharing Platform**

**MISP** (Malware Information Sharing Platform & Threat Sharing) is an open-source platform designed for organisations to share IOCs and threat intelligence with each other. It's used by:
- Government CERTs (Computer Emergency Response Teams) sharing intelligence across national critical infrastructure
- Information Sharing and Analysis Centers (ISACs) sharing industry-specific threat data
- Large organisations sharing intelligence with their partners and supply chain

In MISP, IOCs are organised into **Events** (think: reports about specific incidents or campaigns). Each Event contains **Attributes** (the actual IOCs: hashes, IPs, domains, etc.) and is tagged with MITRE ATT&CK techniques, threat actor names, and sector information.

**Creating IOC Watchlists in Your SIEM**

Once you have a list of malicious IOCs, the next step is loading them into your SIEM so it can alert you whenever any of these indicators appear in your log data:

1. **IP blocklists:** Import into firewall rules (block outbound connections to known bad IPs) and SIEM correlation rules (alert if any internal host connects to these IPs)
2. **Domain blocklists:** Import into your DNS firewall/sinkhole (prevent DNS lookups for malicious domains) and SIEM
3. **Hash watchlists:** Import into EDR platforms to alert if any endpoint executes a file with a matching hash

**IOC Sharing Formats**

To share IOCs between different systems and organisations, standard formats exist:
- **STIX (Structured Threat Information eXpression):** A JSON-based language for describing threat intelligence. Widely used for machine-readable IOC sharing.
- **TAXII (Trusted Automated eXchange of Intelligence Information):** A protocol for transmitting STIX data between servers. MISP and most SIEM platforms support STIX/TAXII.
- **CSV:** Simple comma-separated values. Most SIEM platforms can import IOC lists in CSV format.

**IOC Quality Checklist**

Before adding an IOC to your blocklist, ask:
1. **Is it recent?** IOCs older than 3-6 months may be stale (the attacker abandoned that infrastructure)
2. **What is the confidence level?** Single source = lower confidence. Multiple independent sources = higher confidence.
3. **Could this be a false positive?** Blocking a legitimate CDN IP because one threat actor used it would break many websites.
4. **Is there context?** A hash without knowing *what* malware family it belongs to is less actionable than a hash with full campaign context.`,
    },

    // ── Question 1 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "ioc-q1",
      question:
        "According to the 'Pyramid of Pain' model, which type of indicator is the MOST valuable for defenders to detect and block — and causes the MOST disruption to attackers?",
      options: [
        "File hashes (SHA-256) of specific malware samples",
        "IP addresses of known command-and-control servers",
        "TTPs (Tactics, Techniques, and Procedures) — the attacker's methods and behaviours",
        "Email subject lines used in phishing campaigns",
      ],
      answer: 2,
      explanation:
        "TTPs sit at the top of the Pyramid of Pain. Changing an IP address takes minutes; changing an entire attack methodology requires months of retraining and retooling. When defenders detect attacks at the TTP level — 'PowerShell executing base64-encoded commands AND injecting into lsass.exe AND making outbound connections on port 443' — attackers cannot simply swap out a component. They must fundamentally change how they operate. This is why MITRE ATT&CK-based detection rules are more durable than simple hash or IP blocklists.",
      xp: 35,
    },

    // ── Question 2 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "ioc-q2",
      question:
        "An analyst uses VirusTotal to investigate an IP address found in firewall logs. The 'Passive DNS' section shows that 6 different domains have pointed to this IP over the past year, including known phishing domains. How is this information useful for the investigation?",
      options: [
        "Passive DNS confirms that the IP is safe — multiple domains using it means it's a shared legitimate hosting provider",
        "Passive DNS reveals the full history of domain names that have resolved to this IP, enabling the analyst to discover related phishing domains they may not have known about — and block them proactively",
        "Passive DNS is only relevant for email investigations and provides no useful information for IP analysis",
        "Passive DNS shows the geographic location of the IP address",
      ],
      answer: 1,
      explanation:
        "Passive DNS is one of the most powerful pivoting tools available. It shows the historical relationship between IP addresses and domain names — essentially answering 'what domain names have ever pointed to this IP?'. If a known malicious IP has hosted 6 different domains over time, all 6 of those domains are likely controlled by the same threat actor. The analyst can now block all 6 domains and search internal logs for connections to any of them — significantly expanding the scope of detection from one indicator to many.",
      xp: 35,
    },

    // ── Question 3 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "ioc-q3",
      question:
        "What is Shodan, and how is it different from a regular web search engine like Google?",
      options: [
        "Shodan is a cybersecurity news aggregator that indexes articles about recent attacks",
        "Shodan is a search engine that continuously scans and indexes internet-connected devices and their exposed services (open ports, running software, banners) — unlike Google which indexes web page content",
        "Shodan is a tool for scanning your own internal network for vulnerabilities",
        "Shodan is a SIEM platform for collecting and analysing security logs",
      ],
      answer: 1,
      explanation:
        "Shodan scans the entire public internet and indexes information about every device it finds: what port is open, what service is running, what software version, what TLS certificate is presented. This makes it invaluable for threat intelligence: you can look up a suspicious IP to see what kind of server it is (Is it running Cobalt Strike? Is it a Tor node?), or search for specific characteristics of known malware C2 infrastructure across the entire internet. Google indexes what websites *say*; Shodan indexes what servers *are*.",
      xp: 35,
    },

    // ── Log Analysis ──────────────────────────────────────────────────────────
    {
      type: "log_analysis",
      id: "ioc-la1",
      heading: "SIEM Alert: Threat Intelligence Match on Outbound Connection",
      context:
        "Your SIEM has fired a 'Threat Intelligence Match' alert. An internal laptop (LAPTOP-JSMITH) made an outbound connection to an external IP address that matched your threat intelligence feed. The SIEM automatically enriched the alert with details from AbuseIPDB. This might be an employee browsing through a VPN, connecting to malware C2, or something else entirely. Your job is to investigate.",
      event: {
        id: "ti-evt-tor-001",
        ts: "2025-06-23T16:42:18.000Z",
        source: "threat_intel",
        vendor: "AbuseIPDB / SIEM Correlation",
        event_type: "threat_intel_match",
        severity: "high",
        hostname: "LAPTOP-JSMITH",
        user_email: "j.smith@corp.com",
        src_ip: "10.0.1.55",
        dst_ip: "185.220.101.45",
        dst_port: 443,
        protocol: "tcp",
        mitre_technique: "T1090.003",
        mitre_tactic: "Command and Control",
        description:
          "Outbound connection from LAPTOP-JSMITH to IP 185.220.101.45 matched threat intelligence feed. IP classified as Tor Exit Node with 3,847 abuse reports. Connection on port 443.",
        raw: {
          "data.srcip": "185.220.101.45",
          "data.dstip": "10.0.1.55",
          "data.dstport": "443",
          "data.proto": "tcp",
          "threat_intel.indicator": "185.220.101.45",
          "threat_intel.category": "Tor Exit Node",
          "threat_intel.confidence": "95",
          "threat_intel.source": "AbuseIPDB",
          "threat_intel.report_count": "3847",
          "threat_intel.last_reported": "2025-06-23",
          "threat_intel.tags": ["proxy", "anonymizer", "scanning"],
          "data.hostname": "LAPTOP-JSMITH",
        },
      },
      questions: [
        {
          question:
            "The IP is classified as a 'Tor Exit Node'. What is Tor, and why would connecting to a Tor Exit Node be flagged as suspicious in a corporate environment?",
          options: [
            "Tor is a type of malware that automatically installs itself on corporate laptops",
            "Tor (The Onion Router) is an anonymisation network that hides internet traffic. Traffic entering Tor exits through a Tor Exit Node — meaning the actual destination IP is hidden. Attackers use Tor to anonymise C2 communications; employees might use Tor browsers to bypass corporate web filters.",
            "Tor is a legitimate Microsoft networking protocol used for encrypted communications",
            "Tor Exit Nodes are servers owned by antivirus companies for threat research",
          ],
          answer: 1,
          explanation:
            "Tor routes internet traffic through multiple encrypted relays before exiting through a 'Tor Exit Node' — the last relay before the connection reaches its final destination. This hides the true destination from corporate monitoring (the company sees traffic going to the Tor Exit Node, not the final server). Malware uses Tor to hide C2 communications (defenders can't block the real C2 server if they don't know its IP). Employees might also use Tor browsers to bypass web content filters. Either way, corporate policy in most organisations prohibits Tor use, and it warrants immediate investigation.",
          xp: 50,
        },
        {
          question:
            "The alert shows the connection was made on port 443 (HTTPS). Why might an attacker specifically use port 443 for malicious traffic rather than a non-standard port like 4444 or 8080?",
          options: [
            "Port 443 provides twice the bandwidth of other ports",
            "Port 443 is used exclusively by government networks and is automatically trusted",
            "Port 443 (HTTPS) is allowed outbound on virtually every corporate firewall because blocking it would prevent all secure web browsing. Attackers use it to blend malicious traffic with normal HTTPS web traffic and avoid firewall blocks.",
            "Port 443 is required by the Tor protocol and cannot be changed",
          ],
          answer: 2,
          explanation:
            "This technique is called 'C2 over HTTPS' or 'hiding in plain sight'. Every corporation must allow outbound port 443 — block it and employees cannot use any HTTPS website. Attackers exploit this by tunnelling their C2 communications over HTTPS on port 443, making it look like normal web traffic. Even if the destination is a Tor Exit Node or malware C2 server, the traffic *looks* identical to a normal HTTPS connection from the network perimeter. This is why content inspection (not just port filtering) is essential.",
          xp: 50,
        },
        {
          question:
            "The analyst wants to pivot from this IP address to find any related threat infrastructure. What is the MOST useful next step using VirusTotal?",
          options: [
            "Check the IP's geolocation to determine which country the attacker is in",
            "Submit the IP to VirusTotal and check the 'Relations' and 'Passive DNS' tabs to discover all domains that have ever pointed to this IP and all malware files that have ever communicated with it",
            "Block the IP in the firewall and close the investigation without further analysis",
            "Email the IP address to the Internet Service Provider and ask them to take action",
          ],
          answer: 1,
          explanation:
            "VirusTotal's Relations tab and Passive DNS are the most powerful pivoting tools available for IP investigation. Passive DNS reveals every domain name that has ever resolved to this IP — potentially exposing the attacker's entire infrastructure in one lookup. The 'Communicating Files' section shows which malware samples have called home to this IP — giving you file hashes you can search for on your own endpoints. This is how one flagged IP can expand into a complete picture of a threat actor's campaign infrastructure.",
          xp: 50,
        },
      ],
    },

    // ── Flag Task ─────────────────────────────────────────────────────────────
    {
      type: "flag",
      id: "ioc-flag1",
      prompt:
        "Looking at the threat intelligence alert above, the flagged IP address (185.220.101.45) has been categorised in the threat intelligence feed. What category has it been assigned? Check the 'threat_intel.category' field in the raw log. (Enter the category exactly as it appears — two words, initial caps)",
      answer: "Tor Exit Node",
      hint: "Find the 'threat_intel.category' field in the raw log section of the alert above. It describes what *type* of potentially malicious network node this IP is classified as.",
      xp: 40,
    },

    // ── Question 4 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "ioc-q4",
      question:
        "A security analyst receives an IOC list from a threat intelligence feed containing 500 IP addresses associated with a recent attack campaign. What is the MOST effective way to operationalise these IOCs in the SOC?",
      options: [
        "Print the list and manually check each IP against firewall logs once per week",
        "Import the IOC list into the SIEM and firewall as a watchlist, so any connection to/from these IPs automatically triggers an alert in real-time",
        "Email the list to all employees and ask them to avoid visiting these addresses",
        "Store the list in a spreadsheet and only check it when an incident occurs",
      ],
      answer: 1,
      explanation:
        "IOCs only have value when they are operationalised — actively working for you in automated systems. Importing an IOC list into the SIEM creates a correlation rule that matches every log event against the list in real-time. Importing into firewall threat feeds automatically blocks connections to those IPs. This way, the moment any internal device connects to one of the 500 known-bad IPs, an alert fires immediately — before analysts would ever have a chance to notice it manually.",
      xp: 35,
    },

    // ── Question 5 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "ioc-q5",
      question:
        "An analyst finds an IP address in a threat intelligence report published 14 months ago. Should they immediately add it to their firewall blocklist? Why or why not?",
      options: [
        "Yes — any IP ever associated with malicious activity should be permanently blocked",
        "No — IP addresses can be reassigned. The server that hosted malware 14 months ago might now be a legitimate cloud customer's web server. Adding it to a blocklist could break legitimate traffic without providing any security benefit.",
        "Yes — IP addresses never change ownership, so if it was malicious once it's always malicious",
        "No — only IP addresses from the current week should ever be considered as IOCs",
      ],
      answer: 1,
      explanation:
        "IOC staleness is a critical consideration. IP addresses are leased from hosting providers and cloud platforms — an IP used for a malware C2 server in April 2024 might have been cancelled by the attacker and re-assigned to a legitimate e-commerce website by June 2024. Blindly blocking it would create false positives and break legitimate business traffic. Always check the 'last seen' date on any IOC and assess whether recent reports exist. For IPs older than 3-6 months without recent corroboration, validate before blocking.",
      xp: 35,
    },
  ],
};

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

const rooms = [
  crowdstrikeFalcon,
  sentinelOne,
  malwareAnalysisFundamentals,
  iocAnalysis,
];

export default rooms;
