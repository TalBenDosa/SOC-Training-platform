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
  checkpoint?: {
    question: string;
    options: string[];
    answer: number;
    explanation?: string;
  };
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

interface AnalystChoiceTask {
  type: "analyst_choice";
  id: string;
  heading: string;
  scenario: string;
  event: TelemetryEvent;
  correct_verdict: "true_positive" | "false_positive" | "escalate" | "informational";
  explanation: string;
  fp_trap?: string;
  xp: number;
}

type RoomTask = ReadingTask | QuestionTask | LogAnalysisTask | FlagTask | AnalystChoiceTask;

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
  xp: 395,
  icon: "🦅",
  prerequisites: ["endpoint-security-fundamentals", "security-products-behaviour"],
  tasks: [
    // ── Reading 1: Architecture & Falcon Sensor ──────────────────────────────
    {
      type: "reading",
      id: "cs-falcon-r1",
      heading: "What Is CrowdStrike Falcon — and How Does It Work?",
      content: `CrowdStrike is a cybersecurity company founded in 2011 with one key idea: stop attackers, not just malware. Instead of building a product that only looks for known virus signatures (like old-school antivirus), CrowdStrike built a platform that focuses on **adversary behaviour** — what attackers actually do inside a system, step by step.

The result is **Falcon**, a cloud-native endpoint protection platform. "Cloud-native" means that the heavy lifting — analysis, machine learning, threat intelligence — all happens in CrowdStrike's cloud, not on your laptop. Your computer only runs a tiny, lightweight piece of software called the **Falcon Sensor**.

**What Is the Falcon Sensor?**

Think of the Falcon Sensor like a security camera permanently installed inside the operating system. It runs in **kernel mode** — the deepest, most privileged layer of Windows or Linux — which makes it very hard for anything on the system to hide from it. (Not impossible: attackers use "EDR killer" tools and vulnerable signed drivers — BYOVD — to blind or unload sensors, which is why a sensor suddenly going offline is itself an alert.) Every time a program starts, accesses a file, makes a network connection, or touches the registry, the Sensor records it and streams that telemetry to CrowdStrike's cloud in near real-time.

The Sensor is deliberately tiny (under 5 MB) and uses very little CPU. Users generally can't tell it's there. It doesn't slow down the computer or interfere with normal work.

**The CrowdStrike Cloud: Where the Intelligence Lives**

Once telemetry leaves the sensor, it arrives at the **Threat Graph** — CrowdStrike's proprietary cloud-scale data store that holds trillions of events from millions of endpoints around the world. Machine learning models run continuously against this data, looking for patterns that indicate malicious activity.

When the cloud spots something suspicious, it sends a detection back to the Falcon console for a SOC analyst to review. This design means that:
- New threat intelligence is applied to ALL customers simultaneously (no waiting for a signature update download)
- Even if a new attacker technique appears at Company A in Tokyo, CrowdStrike's cloud can recognise the same pattern at Company B in New York seconds later

**CrowdStrike's Adversary Focus**

CrowdStrike publicly names and tracks over 200 threat actor groups using animal-themed codenames: **FANCY BEAR** (Russian state actors), **COZY BEAR** (another Russian group), **LABYRINTH CHOLLIMA** (North Korea — part of what other vendors call the Lazarus Group; HIDDEN COBRA is the US-government name), **SCATTERED SPIDER** (English-speaking cybercriminal group). The animal tells you the origin: BEAR = Russia, PANDA = China, KITTEN = Iran, CHOLLIMA = North Korea, SPIDER = eCrime (financially motivated criminals). This adversary intelligence approach helps SOC teams understand *who* is attacking them and *why*, not just *what malware* was used.

**Prevention vs Detection: Two Modes of Falcon**

CrowdStrike Falcon runs in two complementary modes simultaneously:

- **Falcon Prevent (NGAV — Next-Generation Antivirus):** Blocks threats before they execute. Uses machine learning models trained on millions of malware samples to score every file before it runs. If the score is above a configured threshold, execution is blocked automatically. This is *prevention* — stopping the attack before damage occurs.

- **Falcon Insight (EDR — Endpoint Detection and Response):** Monitors everything that happens on the endpoint and sends it to the cloud for analysis. Generates *detections* — alerts that tell a SOC analyst "something suspicious happened here, investigate." This catches things that slipped past prevention (novel malware, attacker using built-in Windows tools, etc.).

Both modules run from the same sensor. You don't need two products.`,
      checkpoint: {
        question: "A user double-clicks a brand-new malicious executable. It never runs: Falcon stops it on the spot, with no analyst involved. Which Falcon capability acted?",
        options: [
          "Falcon Prevent — it scored the file before execution and blocked it",
          "Falcon Insight — it recorded the behaviour and raised a detection",
          "Real Time Response — it killed the process on the remote endpoint",
          "OverWatch — the hunting team spotted the file and stopped it",
        ],
        answer: 0,
        explanation:
          "Falcon Prevent (NGAV) scores every file with ML models before it runs and blocks it automatically when the score crosses the threshold — prevention, with no human in the loop. Falcon Insight (EDR) detects suspicious behaviour and raises detections for an analyst after something has happened; it does not stop a file before launch. Real Time Response is a remote shell an analyst uses by hand, so it cannot act before anyone is involved. OverWatch is a human hunting team that sends managed detections; it does not block files at execution time.",
      },
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
- **ContextProcessName / ContextProcessId:** The process in whose context the event happened — the process that performed the action (for a process-creation event, that is the process that launched the new one)
- **ParentBaseFileName / ParentProcessId:** The direct parent of the process the event is about

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
      checkpoint: {
        question: "During an incident, SRV-APP04 stops sending any Falcon telemetry and you suspect its sensor was blinded. Where in the console do you confirm when the host last checked in and whether its sensor is healthy?",
        options: [
          "Falcon Discover — it lists devices on the network that have no sensor",
          "Host Management — it shows each sensor's health and last check-in time",
          "Investigate — it searches the telemetry the host has already sent",
          "OverWatch — the hunting team reports every sensor that goes offline",
        ],
        answer: 1,
        explanation:
          "Host Management is the inventory of enrolled endpoints, with each sensor's health, version and last check-in time — exactly where you notice a host that went quiet after an incident. Falcon Discover finds devices that never had a sensor; SRV-APP04 is enrolled, so it is the wrong list. Investigate searches telemetry that already arrived, so it can show what the host did before it went silent but not its sensor status. OverWatch is a hunting team that sends managed detections about attacker activity; checking sensor health is your job in the console.",
      },
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

**Network Containment ("Contain host")** is Falcon's main isolation action: the host is cut off from every network connection except its link to the Falcon cloud, so the attacker loses access while you keep investigating it through RTR — but containing a server such as a Domain Controller also cuts off everyone who depends on it, so for critical servers it is a business decision as well as a technical one.

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
        "A Falcon detection shows the CommandLine 'powershell.exe -EncodedCommand SQBuAHYAbwBr...'. What is the soundest way to treat it?",
      options: [
        "As confirmed malicious — encoding exists to hide commands, so it proves an attack",
        "As a common hiding trick — decode it and check the parent process before deciding",
        "As benign — PowerShell encodes long commands itself, so encoding adds no risk",
        "As safe to close if the powershell.exe hash comes back clean on VirusTotal",
      ],
      answer: 1,
      explanation:
        "'-EncodedCommand' means the command is Base64-encoded. Attackers use it to hide commands from simple string matching, but legitimate management tools (SCCM, Intune and other agents) use it too — so decode it (Falcon shows the decoded text) and look at the parent process and what the command actually does before deciding. 'Proves an attack' overstates it for that reason. 'PowerShell encodes long commands itself' is false — the caller chooses to encode, and the encoding hides intent from the person reading the log. 'Clean powershell.exe hash' misses the point: powershell.exe is a signed Microsoft binary, so its hash is always clean; the risk is in the command it was given.",
      xp: 35,
    },

    // ── Question 2 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "cs-falcon-q2",
      question:
        "Minutes after a new, signed but outdated kernel driver is loaded on a server, its Falcon Sensor stops reporting. Why is this treated as a serious alert rather than a glitch?",
      options: [
        "Sensors often drop after a driver install; it mostly means a reboot is pending",
        "The driver likely overwrote the sensor's local signature database, so scans fail",
        "A kernel sensor is hard to evade from user mode, so attackers try to blind it with drivers",
        "The host has lost its route to the cloud proxy, so its web traffic is no longer inspected",
      ],
      answer: 2,
      explanation:
        "The Falcon Sensor records activity from kernel mode, the most privileged layer, so malware running in user mode struggles to hide from it. That is why attackers try to blind or unload the sensor itself — EDR-killer tools and vulnerable signed drivers (BYOVD) — and why a sensor going silent right after a driver load is an alert. 'A reboot is pending' explains the silence away without evidence. 'Local signature database' misdescribes Falcon: it is cloud-native and does not depend on a local signature file. 'Cloud proxy' confuses the sensor with a web proxy — it streams telemetry to the cloud, it does not route the host's web traffic.",
      xp: 35,
    },

    // ── Question 3 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "cs-falcon-q3",
      question:
        "Your company has no night shift. At 03:00 a managed detection appears in the Falcon console with a written analysis of hands-on-keyboard activity that no automated detection had flagged. Who produced it?",
      options: [
        "Falcon Prevent, whose ML model blocked a file and annotated why",
        "OverWatch, CrowdStrike's managed 24/7 threat-hunting team",
        "Falcon Discover, which flagged a device that has no sensor",
        "Falcon Insight's behavioural rules running in the cloud",
      ],
      answer: 1,
      explanation:
        "OverWatch is CrowdStrike's team of human threat hunters who search customer telemetry around the clock for activity automated detections miss, and send a managed detection with their analysis to the console — which fits a written analysis of activity no rule flagged. Falcon Prevent blocks files automatically; it does not write analyses of hands-on activity. Falcon Discover reports unmanaged devices, not attacker activity. Falcon Insight's behavioural rules are the automated detections — and the stem says none of them fired.",
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
          "crowdstrike.event_simpleName": "ProcessRollup2",
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
            "LSASS enforces the firewall policy, so full access lets a tool turn network filtering off",
            "LSASS holds credential material in memory; full access lets a tool read hashes and tickets",
            "0x1FFFFF is rare enough to prove infection by itself, whichever process is being opened",
            "Full access lets the tool terminate LSASS, forcing a reboot that wipes the attacker's traces",
          ],
          answer: 1,
          explanation:
            "LSASS (Local Security Authority Subsystem Service) enforces security policy and keeps credential material in memory — NTLM hashes, Kerberos tickets and sometimes plaintext passwords. Full access to lsass.exe lets a tool read that memory, which is what credential dumping (T1003.001) needs; here the CommandLine even writes a MiniDump to disk. 'Firewall policy' confuses LSASS's 'security policy' role with the Windows Firewall service. '0x1FFFFF proves infection by itself' is wrong — full-access handles also come from debugging and support tools, so the target and the context matter. 'Terminate LSASS to force a reboot' misreads the goal: killing LSASS crashes the machine, but the evidence here (a MiniDump of the process) shows the aim is to copy its memory.",
          xp: 50,
        },
        {
          question:
            "The process ran as 'CORP\\svc-backup', an account that has run the nightly backup jobs for three years. No change ticket covers tonight. What does this suggest?",
          options: [
            "A new account made for the attack, named to look like a service account",
            "A real service account being abused, its rights and low scrutiny helping it blend in",
            "Expected backup behaviour — backup agents read LSASS so credentials are backed up",
            "An admin testing backups — the command just runs under the backup job's account",
          ],
          answer: 1,
          explanation:
            "svc-backup is an established account with the broad rights backup software needs, and service-account activity draws less scrutiny than a human admin's — which is why attackers who obtain its credentials use it to blend in. 'A new account' is ruled out: the account has existed for three years. 'Backup agents read LSASS' is false — backup software copies files, it does not dump LSASS memory with comsvcs.dll MiniDump from a cmd.exe shell. 'An admin testing backups' has no support: there is no change ticket, and a backup test has no reason to dump the credential process on a Domain Controller.",
          xp: 50,
        },
        {
          question:
            "The dump file is being written to 'C:\\Windows\\Temp\\lsass.dmp'. As the responding SOC analyst, what is your FIRST priority action?",
          options: [
            "Email svc-backup's owner to reset its password and ask whether a backup job was running",
            "Reboot SRV-DC01 to end the dumping process and clear any credentials held in memory",
            "Kill the process via RTR, pull lsass.dmp as evidence, then contain the host per the DC plan",
            "Delete lsass.dmp from the disk via RTR so the stolen hashes cannot leave, then close the alert",
          ],
          answer: 2,
          explanation:
            "The priority is to stop the dumping while keeping the evidence. RTR lets you kill the rundll32.exe process, retrieve the .dmp file (to see exactly what was captured), and then network-contain the host so the credentials cannot leave — on a Domain Controller that decision follows the agreed plan because containment cuts off everyone who depends on it. 'Email the owner' is too slow and the reset alone does not stop an attack in progress. 'Reboot' destroys volatile memory evidence and does nothing about persistence or credentials already copied. 'Delete lsass.dmp and close' destroys the evidence and assumes the file has not already been copied off the host.",
          xp: 50,
        },
      ],
    },

    // ── Flag Task ─────────────────────────────────────────────────────────────
    {
      type: "flag",
      id: "cs-falcon-flag1",
      prompt:
        "In the credential-dumping detection above, the command line hands comsvcs.dll the process ID of the process it should dump. Enter that PID — you would compare it with the host's process list to confirm which process was targeted.",
      answer: "640",
      hint: "Several numbers in this log are process IDs. Only one of them is passed as an argument in the command that was run.",
      xp: 40,
    },

    // ── Question 4 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "cs-falcon-q4",
      question:
        "You need a copy of the suspicious file C:\\Users\\Public\\upd.exe from a laptop in another country so it can be analysed. Which approach fits Falcon's tooling?",
      options: [
        "Search its hash in Investigate, which copies the file from the endpoint",
        "Ask OverWatch to collect it, since file collection is the hunters' role",
        "Open an RTR session to the laptop and retrieve the file with 'get'",
        "Download it from the device's page in Host Management's inventory",
      ],
      answer: 2,
      explanation:
        "Real Time Response opens a remote shell through the sensor's existing channel, and its 'get' command retrieves a file from the endpoint for analysis — no VPN or RDP needed. Investigate searches telemetry (for example, which hosts ran this hash) but does not pull files off a device. OverWatch hunts and sends managed detections; collecting evidence from your endpoints is your team's job through RTR. Host Management shows sensor health and inventory details, not the files on the device.",
      xp: 35,
    },

    // ── Question 5 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "cs-falcon-q5",
      question:
        "A Falcon process tree shows PsExec on one compromised workstation launching the same command on five different servers within two minutes, using an admin account. Which ATT&CK tactic best describes this activity?",
      options: [
        "Initial Access",
        "Lateral Movement",
        "Credential Access",
        "Exfiltration",
      ],
      answer: 1,
      explanation:
        "Using a remote-administration utility from one compromised machine to run code on several others in quick succession is the lateral-movement pattern Falcon flags for PsExec. Initial Access is how the attacker first got into the network (for example a phishing attachment); here they are already on a workstation. Credential Access is stealing credentials (like the LSASS dump earlier) — the admin account is being used here, not stolen. Exfiltration is moving data out of the network, and nothing in this activity sends data out.",
      xp: 35,
    },

    // ── Analyst Choice: Office macro spawning PowerShell that injects into explorer.exe ──
    {
      type: "analyst_choice",
      id: "cs-falcon-ac1",
      heading: "Verdict: PowerShell Launched from Word on WKST-FINANCE07",
      scenario:
        "At 11:42 AM, Falcon Insight generates a Critical severity detection on WKST-FINANCE07. A Microsoft Word process (opening a file named Q3_Invoice_Reconciliation.docm) spawned PowerShell, which ran a Base64-encoded command that ultimately requested full access into a running explorer.exe process. The originating .docm file has 2 detections out of 71 vendors on VirusTotal. What is your verdict?",
      event: {
        id: "cs-falcon-ac1-evt-001",
        ts: "2025-09-17T11:42:08.000Z",
        source: "edr",
        vendor: "CrowdStrike Falcon",
        event_type: "process_create",
        severity: "critical",
        hostname: "WKST-FINANCE07",
        user_email: "l.chen@corp.local",
        mitre_technique: "T1055",
        mitre_tactic: "Defense Evasion",
        description:
          "PowerShell spawned by WINWORD.EXE executed an encoded command; Falcon observed a subsequent full-access request into a running explorer.exe process",
        process: {
          name: "powershell.exe",
          pid: 6120,
          path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
          parent_name: "winword.exe",
          parent_pid: 5560,
          cmdline:
            "powershell.exe -NoP -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcA",
          user: "CORP\\l.chen",
        },
        raw: {
          "crowdstrike.event_simpleName": "ProcessRollup2",
          "crowdstrike.SeverityName": "Critical",
          "crowdstrike.Technique": "T1055",
          "crowdstrike.TechniqueName": "Process Injection",
          "crowdstrike.ContextProcessName": "winword.exe",
          "crowdstrike.ContextProcessId": "5560",
          "crowdstrike.CommandLine":
            "powershell.exe -NoP -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcA",
          "crowdstrike.TargetProcessName": "explorer.exe",
          "crowdstrike.GrantedAccess": "0x1FFFFF",
          "crowdstrike.UserName": "CORP\\l.chen",
          "crowdstrike.HostName": "WKST-FINANCE07",
          "crowdstrike.ParentBaseFileName": "WINWORD.EXE",
          "crowdstrike.FileName": "Q3_Invoice_Reconciliation.docm",
          "crowdstrike.DetectionId": "ldt:qrt789:xyz012",
        },
      } satisfies TelemetryEvent,
      correct_verdict: "true_positive",
      explanation:
        "Word (winword.exe) launching PowerShell is not something that happens during normal document editing — it is the signature of a malicious macro executing. The '-Enc' flag hides the true command behind a Base64 blob, a standard obfuscation technique so the command line does not reveal itself to casual log review. 'crowdstrike.GrantedAccess: 0x1FFFFF' (PROCESS_ALL_ACCESS) against explorer.exe means the process requested full control over Windows Explorer — a classic process-injection move used to hide malicious code inside a legitimate, always-running process so it blends in and survives a cursory look at the process list. The low static AV detection (2/71) does not indicate low risk: it reflects that antivirus signature matching is exactly what obfuscated macro-delivered payloads are built to evade, while Falcon's behavioural detection caught the actual malicious sequence regardless. Correct response: isolate WKST-FINANCE07, capture memory before killing the process, retrieve and detonate the .docm file safely, and reset l.chen's credentials.",
      fp_trap:
        "Two details might tempt an analyst toward false_positive. First, 2 out of 71 VirusTotal detections sounds reassuring — but a low static-detection score on a freshly obfuscated file says only that it has not been signature-matched before, not that it is safe; it is the expected result for a brand-new malicious macro, not evidence of innocence. Second, PROCESS_ALL_ACCESS handles do occasionally appear from legitimate debugging or remote-support tooling, so GrantedAccess 0x1FFFFF is not damning in total isolation. What removes the ambiguity is the full chain: an Office process spawning a script interpreter (rarely legitimate), using Base64 obfuscation with a hidden window (rarely legitimate from a document), then requesting full access into a mainstream process with no debugging purpose. No single field proves this alone — the combination does.",
      xp: 30,
    } satisfies AnalystChoiceTask,
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
  xp: 365,
  icon: "🔮",
  prerequisites: ["endpoint-security-fundamentals", "security-products-behaviour"],
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
      checkpoint: {
        question: "An attack runs entirely through PowerShell and other built-in Windows tools and never writes a malware file to disk. Which SentinelOne engine is designed to catch it?",
        options: ["Behavioral AI", "Static AI", "Deep Visibility", "Rollback"],
        answer: 0,
        explanation:
          "Behavioral AI watches what running processes do — files touched, registry keys, network connections, child processes — so it can flag a 'fileless' attack even when every program involved is legitimate. Static AI screens files before they run, so an attack with no malware file gives it nothing to scan. Deep Visibility is the telemetry store analysts search when hunting; it records the activity but is not what raises the alarm here. Rollback is a response action that undoes file changes, not a detection engine.",
      },
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
- **Classification:** The threat type — e.g., Ransomware, Trojan, Infostealer, Malware, or PUA (Potentially Unwanted Application)
- **Confidence Level:** A category, not a percentage — **Malicious** (the engines are confident it is a threat) or **Suspicious** (needs analyst review)
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
      checkpoint: {
        question: "Ransomware encrypted about 2,000 files on a Windows laptop before the agent stopped it. The process is dead and the file is quarantined. Which action can return the encrypted documents to their pre-attack state?",
        options: ["Kill Process", "Quarantine Threat", "Isolate Network", "Rollback"],
        answer: 3,
        explanation:
          "Rollback uses the snapshots the agent took of file changes to restore encrypted files to their pre-attack state. Kill Process has already done its job — it stops the running process but changes nothing on disk. Quarantine Threat moves the malicious file where it cannot run; the documents it encrypted stay encrypted. Isolate Network stops the laptop talking to other systems, which limits spread but does not repair any file.",
      },
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

SentinelOne markets Purple AI on substantial reductions in mean time to detect (MTTD) and mean time to remediate (MTTR). Treat vendor-published figures like these the way you would treat any marketing claim: they come from the vendor's own selected case studies, under conditions the vendor chose, and they are not independent benchmarks. Quote a specific percentage in a report or an interview only if you can name the source and the year it was measured — otherwise say "the vendor claims significant improvement" and move on. That instinct matters well beyond this one product.

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
        "A file server's agent (in Detect Mode) shows signs of a beacon calling out every 60 seconds, but you do not yet know which processes or files are involved, and the server can reach dozens of other hosts. You want to stop any spread while you keep investigating it remotely. Which response action fits best right now?",
      options: [
        "Kill Process — terminate the process you think is beaconing",
        "Isolate Network — cut the server off but keep the agent connected",
        "Quarantine Threat — move the suspected file where it cannot run",
        "Rollback — restore the server's files to their state before the alert",
      ],
      answer: 1,
      explanation:
        "Isolate Network cuts the endpoint off from every other system while keeping its agent connected to the SentinelOne cloud, so spread stops at once and you can still investigate — the right move when you do not yet know what to kill or remove. Kill Process stops one process, but you have not identified which one, and an injected beacon may live inside a legitimate process. Quarantine Threat needs a known malicious file, which you do not have yet. Rollback undoes file changes such as ransomware encryption; it does nothing about an active network beacon.",
      xp: 35,
    },

    // ── Question 2 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "s1-q2",
      question:
        "Behavioral AI flags one unfamiliar process that renamed several thousand documents in four minutes, appending the same new extension to each. The renamed files now show very high entropy. What does this pattern indicate?",
      options: [
        "A sync client converting documents to a new format and renaming them",
        "A worm copying itself into shared folders across the network",
        "Ransomware encrypting files and appending its own extension",
        "Data exfiltration staging, renaming files before they are uploaded",
      ],
      answer: 2,
      explanation:
        "A rapid rename cascade from one process, the same appended extension on every file, and a jump in file entropy (encrypted data looks random) are the ransomware signals SentinelOne's Behavioral AI watches for. A format-converting sync client would be a known application, would not rename thousands of files a minute, and converted documents do not look random. A worm creates copies of itself; it does not rename and scramble existing documents. Exfiltration staging gathers files to send out — it has no reason to make every document unreadable in place.",
      xp: 35,
    },

    // ── Question 3 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "s1-q3",
      question:
        "After a ransomware incident on one laptop, you need to know whether the same dropper ran on any other endpoint in the last month — including machines where nothing was detected. Where in the SentinelOne console do you look?",
      options: [
        "The Sentinels (Agents) page, filtered to agents in Protect Mode",
        "Deep Visibility, searching the telemetry of every endpoint",
        "The Threats page, filtered to the dropper's threat name",
        "The Endpoint (Devices) page, checking each device's software",
      ],
      answer: 1,
      explanation:
        "Deep Visibility is the raw telemetry search across the whole fleet — it records every process that ran, so it can find the dropper even on hosts where no threat was raised. The Sentinels page shows agent health and mode, not what executed. The Threats page lists only detected threats, so it misses exactly the quiet machines you are worried about. The Devices page shows installed software and hardware details; a dropped executable is not 'installed software', and checking device by device does not scale.",
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
              "a9d6850fd4a3c9d16b93129250a8d61de131cd7a9551e768ca1426d4766f859b",
          },
        },
        file: {
          name: "chrome_update.exe",
          path: "C:\\Users\\j.smith\\AppData\\Local\\Temp\\chrome_update.exe",
          sha256:
            "a9d6850fd4a3c9d16b93129250a8d61de131cd7a9551e768ca1426d4766f859b",
          size: 1048576,
          extension: ".exe",
        },
        raw: {
          "s1.threatName": "Trojan.Ransom.LockBit3",
          "s1.classification": "Ransomware",
          "s1.confidenceLevel": "malicious",
          "s1.processName": "chrome_update.exe",
          "s1.processPath":
            "C:\\Users\\j.smith\\AppData\\Local\\Temp\\chrome_update.exe",
          "s1.sha256":
            "a9d6850fd4a3c9d16b93129250a8d61de131cd7a9551e768ca1426d4766f859b",
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
            "Look at s1.processName and s1.processPath together. What should you conclude from the name and location of this process?",
          options: [
            "Probably routine — Chrome does ship separate updater programs, so the name fits a browser update",
            "A borrowed trusted name: Chrome's real updater is Google-signed under Google\\Update, not in Temp",
            "The location settles it alone — an .exe running from a Temp folder is proof of malware by itself",
            "Lower risk — a path inside the user profile means it ran with user rights and cannot touch much",
          ],
          answer: 1,
          explanation:
            "This is masquerading (MITRE T1036): naming the binary 'chrome_update.exe' so users and analysts dismiss it as a routine update. Chrome really does update through a separate program — but that is Google's signed updater (GoogleUpdate.exe / updater.exe) under Program Files or AppData\\Local\\Google\\Update, not a 'chrome_update.exe' in AppData\\Local\\Temp; so 'the name fits a browser update' takes the premise too far. 'Temp alone is proof' overstates it — installers, Google's included, briefly unpack files in %TEMP%, so the name, the path outside Google's updater and the missing Google signature together are what settle it. 'User rights, so it cannot touch much' is wrong for ransomware: the user's own documents and mapped shares are exactly what it encrypts, as the rename count in this detection shows.",
          xp: 50,
        },
        {
          question:
            "Read s1.action and s1.rollbackStatus together. What is the state of the laptop right now?",
          options: [
            "Already recovered — the quarantine restored the files, and 'Available' confirms the restore",
            "The binary is quarantined, but the renamed files stay encrypted until a rollback is run",
            "Cut off from the network — quarantine isolates the laptop, so the shares are safe now",
            "Unrecoverable — quarantining the file also removed the snapshots taken while it ran",
          ],
          answer: 1,
          explanation:
            "s1.action 'Quarantine' means the malicious file was moved where it cannot run. It does not touch the documents it already encrypted. s1.rollbackStatus 'Available' means the agent's snapshots exist and a rollback can be run to restore those files — it has not happened yet, so it is a next step for you. 'Already recovered' misreads 'Available' as 'completed'. 'Cut off from the network' confuses Quarantine with Isolate Network, which is a separate action. 'Quarantine removed the snapshots' contradicts the field itself — rollback is still listed as available.",
          xp: 50,
        },
        {
          question:
            "You need to see how chrome_update.exe got onto the laptop and everything it did afterwards, as one chain. Which value from this detection do you pivot on?",
          options: [
            "'Trojan.Ransom.LockBit3' — the threat name groups this whole attack together",
            "'0x1A2B3C4D' — the ID shared by every event in this one attack chain",
            "'j.smith' — the username returns every event tied to that user's account",
            "The SHA-256 — the file hash returns every event involving this attack",
          ],
          answer: 1,
          explanation:
            "s1.storylineId is the tag SentinelOne puts on every related event in one attack chain — the parent that launched the dropper, the file writes, network connections and renames — so pivoting on 0x1A2B3C4D gives you the whole story in one timeline. The threat name is shared by every LockBit3 detection across the fleet, so it mixes in unrelated incidents. The username returns everything j.smith did all day, attack or not. The SHA-256 finds events involving that one file, but not the steps before it existed on disk or the other processes in the chain.",
          xp: 50,
        },
      ],
    },

    // ── Flag Task ─────────────────────────────────────────────────────────────
    {
      type: "flag",
      id: "s1-flag1",
      prompt:
        "For the impact section of the incident report you need the scale of the damage on LAPTOP-JSMITH. From the SentinelOne detection above, enter the number of files the ransomware renamed (digits only, no commas).",
      answer: "15847",
      hint: "The agent counts the files it saw being renamed during the attack.",
      xp: 40,
    },

    // ── Question 4 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "s1-q4",
      question:
        "An attacker changes one byte in a known malware file, giving it a hash no antivirus vendor has seen. Why can SentinelOne's Static AI still block it before it runs, when a signature-based antivirus would not?",
      options: [
        "It matches files against a larger, faster-updated signature list than legacy antivirus uses",
        "Its ML model judges the file's structural traits, so never-seen variants can still be flagged",
        "It watches what the process does after launch and stops it once the behaviour looks malicious",
        "It restores the file's original state from the agent's snapshots before the file can execute",
      ],
      answer: 1,
      explanation:
        "Signature-based antivirus matches exact known samples, so a one-byte change produces a new hash and slips past it. Static AI uses machine-learning models trained on the structure of millions of files, so it recognises malicious traits in a file it has never seen — including zero-days — before execution. 'A larger signature list' is still signature matching, and a brand-new hash is on no list. 'Watches the process after launch' describes Behavioral AI, not a pre-execution check. 'Restores from snapshots' describes Rollback, a response action used after damage, not a way to judge a file.",
      xp: 35,
    },

    // ── Question 5 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "s1-q5",
      question:
        "During a new rollout, the team wants SentinelOne to show for two weeks what it would catch, without blocking anything, so false positives cannot break business applications. Which choice fits, and what changes when they move on?",
      options: [
        "Protect Mode with alerts muted, so it blocks threats while keeping the console quiet",
        "Detect Mode, which logs threats for review; Protect Mode later responds automatically",
        "Detect Mode, which blocks known malware; Protect Mode later adds behavioural blocking",
        "Protect Mode, which asks an analyst to approve each block before the agent acts on it",
      ],
      answer: 1,
      explanation:
        "Detect Mode records and reports threats but takes no automatic blocking action, which is why it is used while a team calibrates a new deployment. Protect Mode then acts on its own — killing processes, quarantining files, even rolling back changes — without waiting for a human. 'Protect Mode with alerts muted' still blocks, which is exactly the risk the team wants to avoid. 'Detect Mode blocks known malware' is wrong: Detect Mode blocks nothing automatically. 'Protect Mode asks for approval' describes the opposite of autonomous response.",
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
  xp: 365,
  icon: "🦠",
  prerequisites: ["endpoint-security-fundamentals", "malware-types"],
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
      checkpoint: {
        question: "An analyst first reviews a sample's strings and imports in PEStudio, then uploads it to ANY.RUN to watch the process tree it creates. How are these two steps classified?",
        options: [
          "Static analysis first, then dynamic analysis",
          "Dynamic analysis first, then static analysis",
          "Both static — nothing runs on the analyst's PC",
          "Both dynamic — each tool loads the file to read it",
        ],
        answer: 0,
        explanation:
          "Reading strings and imports without executing the file is static analysis; running it in a sandbox and watching what it does is dynamic analysis — together, a hybrid approach. 'Dynamic first' reverses the order. 'Both static because nothing runs on the analyst's PC' confuses where the code runs with whether it runs: the sandbox executes the sample, just in an isolated VM. 'Both dynamic because the tool loads the file' confuses opening a file to read its bytes with executing it.",
      },
    },

    // ── Reading 2: Static Analysis Tools ─────────────────────────────────────
    {
      type: "reading",
      id: "malware-r2",
      heading: "Static Analysis: Examining Malware Without Running It",
      content: `Static analysis is the art of understanding a malicious file by *reading* it rather than *running* it. Think of it like examining a weapon found at a crime scene: you don't fire the gun to understand it — you study its markings, manufacturer stamps, and serial number.

**Step 1 — File Hashing: The Malware Fingerprint**

Every file has a **cryptographic hash** — a unique mathematical fingerprint calculated from the file's contents. Change even a single byte of the file and the hash changes completely. The three most common hash algorithms are:

- **MD5 (Message Digest 5):** 32 hexadecimal characters. Fast to calculate. Example: \`d41d8cd98f00b204e9800998ecf8427e\` (32 characters). No longer considered cryptographically secure (collisions possible), but still widely used for malware tracking.
- **SHA-1 (Secure Hash Algorithm 1):** 40 characters. Also deprecated for security purposes.
- **SHA-256:** 64 characters. The **preferred standard** for malware analysis. Computationally infeasible to forge. Example: \`fdfb6e68f7fa7fe7728986f3d076bbc3c436c35af43070949c1d22bbbbe20ae1\`

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
      checkpoint: {
        question: "A partner's threat report lists the IOC 'a9dc4004efb5cd5cd343345bc9f7f25e' (32 hexadecimal characters). Which hash type is it?",
        options: ["SHA-1", "SHA-256", "MD5", "CRC32"],
        answer: 2,
        explanation:
          "MD5 hashes are 32 hexadecimal characters long. SHA-1 hashes are 40 characters and SHA-256 hashes are 64, so neither fits. CRC32 is a short checksum (8 hexadecimal characters) used to detect accidental corruption, not to fingerprint malware. MD5 is still common in threat reports, but SHA-256 is the preferred standard for sharing malware IOCs because MD5 collisions are possible.",
      },
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

    // ── Reading 4: Writing a YARA Rule ────────────────────────────────────────
    {
      type: "reading",
      id: "malware-r4",
      heading: "Writing a YARA Rule",
      content: `Static analysis gives you strings, imports, and structural clues about a file. YARA is what lets you turn those clues into something reusable — a rule you can run against one file, an entire disk, or millions of samples on VirusTotal. YARA's own creators describe it as "the pattern-matching swiss army knife" for malware researchers, and that description is accurate: it is not an antivirus engine and it does not understand code the way a disassembler does. It simply asks, "Does this file contain the patterns I'm looking for?" — but that simple question turns out to be extremely powerful once you know how to phrase it.

**Anatomy of a YARA Rule**

Every YARA rule has the same structure: a name, an optional \`meta\` block for documentation, a \`strings\` block that defines the patterns you're searching for, and a \`condition\` block that decides when those patterns count as a match. Here is a complete, syntactically valid example. It is **illustrative only** — a rule shaped like something you might write for a commodity infostealer, not a rule that matches any specific named real-world malware family:

\`\`\`yara
rule Suspicious_Credential_Stealer_Strings
{
    meta:
        description = "Flags a PE containing strings commonly seen in commodity infostealers"
        author = "SOC Training"
        date = "2026-08-12"

    strings:
        $s1 = "Login Data" wide ascii
        $s2 = "\\\\AppData\\\\Local\\\\Google\\\\Chrome\\\\User Data" wide ascii  // a literal backslash must be written as \\\\ in YARA text strings
        $s3 = { 4D 5A }  // MZ header — PE file
        $re1 = /https?:\\/\\/[a-z0-9]{16,}\\.(top|xyz|info)/ nocase

    condition:
        $s3 at 0 and 1 of ($s1, $s2) and $re1
}
\`\`\`

**meta — documentation only.** Everything inside \`meta\` (description, author, date) is metadata for humans reading the rule. YARA never evaluates it against the file — you could write anything there and the rule would still match or fail based purely on \`strings\` and \`condition\`. Good practice is to always fill it in anyway, because a shared rule with no author or description is a rule nobody trusts six months later.

**strings — the patterns you're hunting for.** Each string is given a name starting with \`$\` so the condition can refer to it. YARA supports three kinds of patterns:

- **Plain text**, like \`$s1 = "Login Data"\`. The \`wide\` modifier tells YARA to also match the string encoded as UTF-16 (two bytes per character) — the encoding Windows programs commonly use internally for things like registry paths and window titles — while \`ascii\` keeps the standard single-byte match active too. \`nocase\` (used on \`$re1\` here) makes a match case-insensitive.
- **Hex bytes**, written in \`{ }\`, like \`$s3 = { 4D 5A }\`. This is a raw byte pattern rather than text — \`4D 5A\` are the two bytes that spell "MZ" in hex, which is the magic number every Windows PE file (.exe, .dll) starts with. Hex patterns are how you match binary structures, packer signatures, or shellcode fragments that aren't readable text.
- **Regular expressions**, written between \`/ /\`, like \`$re1\`. This one matches an \`http://\` or \`https://\` URL where the domain is a long lowercase alphanumeric string ending in \`.top\`, \`.xyz\`, or \`.info\` — cheap, disposable top-level domains that infostealer C2 panels are frequently hosted on. Regex strings let you catch a whole family of values instead of one exact one.

**condition — the boolean logic that decides a match.** This is where the rule stops being a list of patterns and becomes a decision. Conditions are plain boolean expressions over the strings you defined, plus a few special operators:

- \`$s3 at 0\` means the \`$s3\` pattern must occur at file offset 0 — the very first bytes of the file. Combined with the MZ header, this effectively says "this must be a PE executable," filtering out unrelated file types before anything else is checked.
- \`1 of ($s1, $s2)\` means at least one of those two named strings must be present. YARA lets you write \`N of (...)\` for any number — \`2 of ($s1, $s2, $s3)\` would require at least two of those three to match, and \`all of them\` requires every string in the rule.
- \`and\` chains conditions together the way you'd expect: every clause joined by \`and\` must be true for the rule to fire.

Read as a sentence, the full condition says: "This must be a PE file, AND it must contain at least one of the Chrome credential-store strings, AND it must contain a URL matching the disposable-TLD C2 pattern." No single condition alone would be reliable — "Login Data" appears in plenty of legitimate software, and cheap TLDs host plenty of legitimate sites — but the combination narrows things down considerably. This is the core skill in writing YARA rules: picking patterns that are individually common but collectively rare.

**Using YARA rules in practice**

Once a rule is saved (typically as a \`.yar\` file), you run it from the command line against a single file or a whole directory: \`yara rule.yar suspicious_file.exe\` prints the rule name if it matches, nothing if it doesn't. Point it at a directory recursively (\`yara -r rule.yar C:\\Users\\\`) and you can sweep an entire endpoint for anything matching your pattern in seconds — useful when an IR team needs to know "does this rule match anywhere else on this machine, or across the fleet?"

Beyond your own machine, VirusTotal lets you run YARA rules against its enormous historical corpus of submitted files — a feature often called **retrohunting**. Instead of scanning files as they arrive, you submit a rule and VirusTotal searches everything it has already collected (going back months or years) for anything matching your pattern. This is how researchers frequently discover that a technique they just identified in one sample was actually used across dozens of related files submitted over the preceding weeks — turning one detection into a whole cluster of related activity.`,
      checkpoint: {
        question:
          "A rule's condition is `$s3 at 0 and 2 of ($s1, $s2, $re1)`. A file starts with the MZ bytes ($s3) and contains $s1 and $s2, but no URL matching $re1. Does the rule match?",
        options: [
          "No — every string the rule defines has to be found before it can fire",
          "Yes — the MZ check passes and two of the three listed patterns are present",
          "No — '2 of' needs exactly two matches and one must be the regex $re1",
          "No — '2 of ($s1, ...)' means $s1 itself must appear at least twice",
        ],
        answer: 1,
        explanation:
          "'N of (...)' means at least N of the listed patterns must match, so $s1 and $s2 satisfy '2 of ($s1, $s2, $re1)', and '$s3 at 0' is satisfied because the file starts with MZ — both clauses joined by 'and' are true. 'Every string must be found' describes 'all of them', which this rule does not use. 'Exactly two, including the regex' invents conditions: 'N of' is a minimum and treats every listed pattern equally. '$s1 must appear twice' confuses counting patterns with counting occurrences of one pattern.",
      },
    },

    // ── Question 1 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "malware-q1",
      question:
        "A suspicious attachment from a phishing email is looked up on VirusTotal by its SHA-256. The result shows '0/72 vendors detected this as malicious'. How should the analyst read this?",
      options: [
        "As clean — 0/72 means every engine examined the file's code and found nothing",
        "As unproven — a new or tailored sample can evade every engine; analyse its behaviour",
        "As clean — the email came from a supplier we know, and no engine disagrees",
        "As unknown — 0/72 means VirusTotal has no record of this hash yet",
      ],
      answer: 1,
      explanation:
        "0/72 means none of the engines' signatures or models flagged the file — not that it is safe. Attackers test new samples against these engines and change them until nothing fires, so a zero score is expected for a fresh or tailored sample; the next step is behavioural (sandbox) analysis. 'Every engine examined the code' overstates what a score is: it is pattern matching, and a new sample matches no known pattern. 'A known supplier' does not help — supplier mailboxes are compromised and spoofed, and the phishing context is the reason for suspicion. 'No record yet' is wrong: a hash VirusTotal has never seen returns no result at all, whereas 0/72 is a scan result.",
      xp: 35,
    },

    // ── Question 2 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "malware-q2",
      question:
        "While performing PE file analysis in PEStudio, an analyst notices the malware imports functions from 'WS2_32.dll' and 'WinINet.dll'. What does this reveal about the malware's capabilities?",
      options: [
        "It manipulates the registry — WS2_32 and WinINet expose configuration-hive APIs",
        "It can talk over the network — raw sockets plus HTTP/S, likely to reach a C2 server",
        "It injects code into other processes — these DLLs provide memory-allocation routines",
        "It encrypts files on disk — WS2_32 and WinINet are Windows cryptographic libraries",
      ],
      answer: 1,
      explanation:
        "Imports show what a program can do. WS2_32.dll (Winsock 2) provides raw TCP/UDP sockets and WinINet.dll provides HTTP/HTTPS functions, so together they point to network communication — most likely with a command-and-control (C2) server. The next step is a sandbox run to capture the actual IPs and domains. Registry functions such as RegSetValueEx come from Advapi32.dll, not these two. Injection relies on calls like VirtualAllocEx and CreateRemoteThread, which these DLLs do not provide. Neither DLL is a cryptographic library.",
      xp: 35,
    },

    // ── Question 3 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "malware-q3",
      question:
        "DNS logs show one workstation querying about 200 random-looking domains a day (for example 'xk7pmq9r.net', 'bz3lnvw4.net'). Almost none of them resolve; then one does, and the host connects to it. What best explains this?",
      options: [
        "Malware stepping through a hardcoded backup list of C2 domains in order",
        "A DGA: malware tries generated domains until it finds the one registered",
        "Fast flux: one C2 domain rotating its IP addresses every few minutes",
        "A browser prefetching links from an ad-heavy page the user had open",
      ],
      answer: 1,
      explanation:
        "A Domain Generation Algorithm produces a new set of pseudo-random domains on a schedule; the attacker registers only one, so the malware queries many names that do not exist until it hits the live one — exactly this pattern. Defenders cannot simply block one domain because the next one is unpredictable. A hardcoded backup list is a short, fixed set of names, not hundreds of new random-looking ones a day. Fast flux is one domain name whose IP addresses keep changing; here the names themselves keep changing. Browser prefetching resolves real domains linked from a page, and real domains resolve.",
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
        vendor: "Microsoft Defender for Endpoint",
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
            "fdfb6e68f7fa7fe7728986f3d076bbc3c436c35af43070949c1d22bbbbe20ae1",
          md5: "a9dc4004efb5cd5cd343345bc9f7f25e",
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
            "fdfb6e68f7fa7fe7728986f3d076bbc3c436c35af43070949c1d22bbbbe20ae1",
          "data.ms365.MD5": "a9dc4004efb5cd5cd343345bc9f7f25e",
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
            "data.ms365.Action is 'Quarantine', and the user says they opened the file. What does that mean for your next steps?",
          options: [
            "Fully remediated — Defender removed the file, so the alert can be closed",
            "Contained here, but check whether it ran before and whether it reached others",
            "The workstation is now cut off from the network until IT releases it",
            "The verdict is uncertain, and the file is held until an analyst approves it",
          ],
          answer: 1,
          explanation:
            "Quarantine means Defender moved this copy of the file where it cannot run. It says nothing about what happened before the detection — the user says they opened it, and this family (Emotet) is a loader whose job is to fetch further malware — or about other recipients of the same email. So the work continues: check this host for execution and follow-on activity, and hunt for the file elsewhere. 'Fully remediated' stops exactly that work. 'Cut off from the network' confuses quarantining a file with isolating a device. 'Held for approval' is wrong: the action has already been taken, and the threat name identifies a known malware family.",
          xp: 50,
        },
        {
          question:
            "The data.ms365.CompanyName field is empty. How should that weigh in your assessment of this file?",
          options: [
            "No weight — the field is optional, so a blank value tells you nothing about the file",
            "Vendor software usually carries publisher info; a blank one on a fake invoice adds suspicion",
            "It shows the file is a script wrapper rather than a compiled Windows PE program",
            "It proves the file is unsigned, because CompanyName is read from the code signature",
          ],
          answer: 1,
          explanation:
            "CompanyName is part of the version information a PE file can carry. Commercial software usually fills it in, while malware authors often leave it blank, so an empty value on an .exe posing as a supplier invoice adds to the case — it is supporting evidence, not proof, because some legitimate and internal tools ship without it. 'No weight' ignores context: on its own it is weak, but here it sits next to a fake invoice name and a malware detection. 'Script wrapper' does not follow — compiled programs can have empty version info too. 'Proves it is unsigned' mixes two things: version info is text inside the file, while a digital signature is separate and must be checked on its own.",
          xp: 50,
        },
        {
          question:
            "The analyst wants to determine if this exact malware sample has reached any other endpoints in the organisation. What is the FASTEST method to check?",
          options: [
            "Search the DNS logs for the sender's domain to see which hosts resolved it",
            "Have the mail team purge the invoice email everywhere and treat the file as gone",
            "Search EDR or SIEM telemetry for the file's hash across every endpoint at once",
            "Submit the hash to VirusTotal and wait for other organisations to report it",
          ],
          answer: 2,
          explanation:
            "The file's hash is a fingerprint of this exact sample, so one EDR or SIEM search across endpoint telemetry ('every host that has seen this hash') answers the question in seconds for the whole environment — which is why hashes are a core IOC type. DNS lookups of the sender's domain show which mail systems or hosts resolved a name, not which endpoints received or ran the file. Purging the email is a sensible containment step, but it does not tell you who already saved or opened the attachment. VirusTotal tells you about the wider world, not about your own endpoints, and waiting adds delay.",
          xp: 50,
        },
      ],
    },

    // ── Flag Task ─────────────────────────────────────────────────────────────
    {
      type: "flag",
      id: "malware-flag1",
      prompt:
        "You are sharing the Defender sample above with a partner team. Use the hash type this room calls the preferred standard for malware IOCs, and enter its first 8 characters.",
      answer: "fdfb6e68",
      hint: "The detection carries more than one hash. Hash types can be told apart by their length.",
      xp: 40,
    },

    // ── Question 4 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "malware-q4",
      question:
        "A finance user forwards a suspicious .xlsx that may be a real client spreadsheet with a macro added. You need to see what the macro does when it runs. What is the right approach?",
      options: [
        "Upload it to ANY.RUN's free tier — interactive analysis is fastest and stays private",
        "Detonate it in a private or on-premises sandbox, since public ones share uploads",
        "Open it on your analyst workstation with macros enabled and watch what happens",
        "Submit just its hash to VirusTotal; a 0/72 result shows the macro is harmless",
      ],
      answer: 1,
      explanation:
        "A file that may hold real client data must not go to a public sandbox, because public services share submitted files and reports with their user community. A private or on-premises sandbox still gives you the behavioural report without exposing the data. 'ANY.RUN's free tier stays private' is the trap — the free public tier is exactly the kind of service that shares uploads. 'Open it on your workstation' runs suspected malware outside any isolation. 'Hash only' protects the data, but a 0/72 result does not show the macro is harmless, and you still have not seen its behaviour.",
      xp: 35,
    },

    // ── Question 5 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "malware-q5",
      question:
        "A sandbox report for a suspicious executable shows it queried the Windows registry key 'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' and wrote a new value pointing to itself. What does this behaviour indicate?",
      options: [
        "The malware is registering itself as a Windows service so it runs at boot",
        "The malware is establishing persistence — this key runs programs automatically at user logon",
        "The malware is changing file-association handlers so it launches whenever a document opens",
        "The malware is escalating privileges — writing to the Run key grants its process SYSTEM rights",
      ],
      answer: 1,
      explanation:
        "The Run registry key is one of the oldest and most common persistence mechanisms in Windows. A program listed under HKEY_CURRENT_USER\\...\\Run starts automatically every time that user logs on, so the malware comes back after a reboot or sign-out — which is why sandbox reports highlight Run-key writes. A Windows service is a different persistence mechanism (installed with CreateService and started by the system at boot), not a Run-key value. File-association handlers live under different keys and fire when a file type is opened. Writing to the user's own Run key needs no special rights and grants none — the program later runs with that user's normal privileges, not SYSTEM.",
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
  xp: 365,
  icon: "🔎",
  prerequisites: ["malware-analysis-fundamentals", "encoding-encryption-hashing"],
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
- **Hash values (Trivial):** Attacker changes one byte of their malware → completely new hash. Trivially easy to evade.
- **IP addresses (Easy):** Attackers simply move to a new server, proxy or VPN exit.
- **Domain names (Simple):** A little more effort — a new domain must be registered and pointed at infrastructure — but still cheap.

In the **middle**:
- **Network/Host Artefacts (Annoying):** Specific patterns in network traffic (URI paths, User-Agent strings) or files and registry keys left on disk. Changing them forces the attacker to modify how their tooling behaves.

Near the **top**:
- **Tools (Challenging):** Detecting the tool itself (e.g., any Mimikatz or Cobalt Strike variant, not one hash of it) forces the attacker to find or build a new tool and learn it.

At the **very top** (hardest to change, maximum pain):
- **TTPs (Tactics, Techniques, and Procedures):** The *way* an attacker operates — their playbook. If you can detect "PowerShell downloading a payload and injecting into svchost.exe", the attacker must completely retrain and retool to evade you. This is why MITRE ATT&CK is so valuable — it focuses on TTP-level detection.

**Practical Implication:** When a vendor says "we blocked this attack by detecting the malware hash", that's useful but weak. A sophisticated attacker will simply recompile their malware. When a vendor says "we detected lateral movement via PsExec combined with LSASS dumping" — that's TTP-level detection that's much harder for attackers to evade.

**IOC Lifecycle**

IOCs have a shelf-life. A domain used for a phishing campaign last month may be abandoned today and reassigned to a legitimate website. An IP address used by a threat actor last week might now belong to an innocent cloud customer. Always note the **first seen / last seen** dates on any IOC, and treat stale IOCs (older than 3-6 months) with appropriate scepticism.`,
      checkpoint: {
        question: "Your EDR team adds a rule that flags any variant of Mimikatz by characteristics of the tool itself, rather than by the hash of one build. On the Pyramid of Pain, which level is this detection?",
        options: [
          "Hash values (Trivial)",
          "Network/Host artefacts (Annoying)",
          "Domain names (Simple)",
          "Tools (Challenging)",
        ],
        answer: 3,
        explanation:
          "Detecting the tool itself — any variant, not one build — sits at the Tools level: to evade it the attacker must find or build a different tool and learn it. Hash values would be blocking one specific build, which a recompile defeats. Network/Host artefacts are traces such as a URI path, User-Agent or registry key that the tool leaves behind; this rule targets the tool, not its traces. Domain names are attacker infrastructure and have nothing to do with recognising a program on an endpoint. Only TTPs, the attacker's way of operating, sit higher than Tools.",
      },
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

**OPSEC — search before you upload:** uploading a file to VirusTotal (or running a public URLScan.io scan) makes it visible to other subscribers, potentially including the attacker who may be watching for their own samples, and can expose confidential content — so search by hash first and upload only when your policy allows it.

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
      checkpoint: {
        question: "A user reports an attachment that looks crafted specifically for your company. What is the safest first step with VirusTotal?",
        options: [
          "Upload the file so all 70+ engines scan it at once",
          "Search its hash first; upload only if policy allows",
          "Run a public URLScan scan of the link it came from",
          "Upload it, then delete the report once you have read it",
        ],
        answer: 1,
        explanation:
          "A hash search reveals whether the file is already known without sharing anything. An upload makes the file visible to other subscribers — potentially including the attacker watching for their tailored sample, and anyone who can read any confidential content inside it. 'Upload so all engines scan it' is the habit this warns against. A public URLScan scan is equally visible to others, so it has the same OPSEC problem. 'Delete the report afterwards' does not help: once uploaded, the file has already been shared.",
      },
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
        "After an intrusion, the SOC can deploy only one of these detections. Which would be hardest for the same attacker to evade next time?",
      options: [
        "Alert on the SHA-256 of the loader found on the first infected host",
        "Block the three C2 IP addresses named in last week's threat report",
        "Alert when an Office app spawns PowerShell that then reads LSASS memory",
        "Block the phishing domains that delivered the first-stage document",
      ],
      answer: 2,
      explanation:
        "Detecting the behaviour — Office spawning PowerShell that goes on to read LSASS memory — targets the attacker's TTPs, the top of the Pyramid of Pain; to evade it they must change how they operate, not just swap a component. The loader's hash is the bottom level: one recompile produces a new hash. C2 IP addresses are easy to replace with a new server or proxy. Phishing domains are cheap to re-register. All three are still worth blocking, but they cost the attacker little.",
      xp: 35,
    },

    // ── Question 2 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "ioc-q2",
      question:
        "Passive DNS for a C2 IP from your firewall logs lists six domains. Four are look-alike login domains first seen within days of each other this month. Two — a bakery's site and a dentist's site — pointed to the IP three years ago and not since. What is the soundest use of this?",
      options: [
        "Block all six — every domain that has pointed at a malicious IP is attacker-run",
        "Treat the four recent look-alikes as related; check the two old ones before acting",
        "Ignore it — passive DNS records MX lookups, so web domains are not shown there",
        "Treat the IP as clean — six domains on one address shows a legitimate shared host",
      ],
      answer: 1,
      explanation:
        "Passive DNS shows which domains have resolved to an IP over time, which makes it a strong pivot — but each result needs its dates and context. Four look-alike domains appearing together this month fit one actor's infrastructure and are worth blocking and hunting for internally. The two old sites most likely belonged to a previous tenant of the address, before it was reassigned, so blocking them blindly risks false positives. 'Block all six' ignores the IOC lifecycle. 'Only MX lookups' is wrong — passive DNS records the domain-to-IP resolutions you are looking at. 'Shared host, so clean' does not follow: several domains on one IP can mean shared hosting, but it does not cancel the C2 evidence that brought you here.",
      xp: 35,
    },

    // ── Question 3 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "ioc-q3",
      question:
        "During triage you want to know which services an external IP is exposing right now — for example whether port 50050, Cobalt Strike's default team-server port, is open. Which tool answers that most directly?",
      options: [
        "AbuseIPDB — its report categories show the services an IP runs",
        "Shodan — it indexes each IP's open ports and service banners",
        "MXToolbox — its blacklist check lists the ports a server opens",
        "AlienVault OTX — its pulses record every port an IP exposes",
      ],
      answer: 1,
      explanation:
        "Shodan continuously scans the internet and indexes what each IP exposes — open ports, service banners, software versions — so looking up the IP shows directly whether a C2-style service is listening. AbuseIPDB records what an IP has done to other people (brute force, scanning), not what it is running. MXToolbox's blacklist check tells you whether a mail server IP is on spam lists. OTX pulses are curated IOC collections from researchers; an IP may appear in one, but a pulse is not a scan of its current services.",
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
        vendor: "Wazuh",
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
          "data.srcip": "10.0.1.55",
          "data.dstip": "185.220.101.45",
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
            "The feed classifies the destination as a Tor node. What does an outbound connection from the laptop to it most likely mean?",
          options: [
            "Tor is a commercial VPN, so staff are likely reaching company systems from home",
            "Tor is an anonymity network; this suggests a Tor client is running on the laptop",
            "Tor is a blocklist feed, so the match by itself proves the laptop is infected",
            "Tor nodes front Microsoft 365 traffic, so this connection is routine and benign",
          ],
          answer: 1,
          explanation:
            "Tor routes traffic through three encrypted relays — guard (entry), middle and exit — so a Tor client inside your company connects OUT to its guard relay, and monitoring sees traffic to Tor relay IPs, never to the final server. An outbound connection from LAPTOP-JSMITH to a known Tor relay therefore suggests a Tor client on the laptop (many relays flagged as exits also act as guards; the flag tells you the IP is part of Tor). The opposite direction — an exit-node IP as the SOURCE of inbound traffic — would mean someone using Tor to reach your systems. On the laptop, the cause could be malware hiding its C2 or an employee bypassing web filters; both need investigation. 'A commercial VPN for home access' is wrong — Tor is not a corporate VPN, and this traffic leaves the laptop rather than coming in. 'The match proves infection' confuses Tor with the threat feed that labelled it; a Tor connection alone does not tell you whether malware or a person started it. 'Microsoft 365 traffic' is invented — Microsoft services do not route through Tor.",
          xp: 50,
        },
        {
          question:
            "The alert shows the connection was made on port 443 (HTTPS). Why might an attacker specifically use port 443 for malicious traffic rather than a non-standard port like 4444 or 8080?",
          options: [
            "Port 443 traffic is exempt from TLS inspection by design, so attackers use it to avoid decryption",
            "Most C2 frameworks can beacon over 443 alone, so the port reflects a tool limit, not a choice",
            "Port 443 is open outbound on nearly every firewall, so malicious traffic blends with normal HTTPS",
            "Tor relays listen on 443, so seeing that port is by itself enough to confirm Tor is in use",
          ],
          answer: 2,
          explanation:
            "Almost every organisation must allow outbound 443 — block it and nobody can use HTTPS websites — so attackers tunnel C2 over HTTPS to look like normal web traffic from the perimeter. That is why content inspection, not port filtering, is needed. 'Exempt from TLS inspection by design' is false: TLS inspection is built precisely for 443, though many organisations do not deploy it everywhere. 'C2 frameworks can only use 443' is wrong — they are configurable to many ports and protocols; 443 is chosen because it blends in. 'Port 443 confirms Tor' fails because nearly all HTTPS uses 443; here it is the threat-intel match, not the port, that identifies the Tor relay.",
          xp: 50,
        },
        {
          question:
            "This IP is a Tor relay shared by thousands of unrelated users. What does that mean for pivoting on it in VirusTotal (Passive DNS, Communicating Files)?",
          options: [
            "Pivots are extra reliable — every sample linked to a relay belongs to one actor",
            "Results will mix many unrelated users, so the laptop itself is the better lead",
            "Pivoting is impossible — VirusTotal withholds relations for Tor relay addresses",
            "The 3,847 reports show the laptop's user is the actor behind that abuse",
          ],
          answer: 1,
          explanation:
            "Pivoting works best on infrastructure an attacker controls. A Tor relay carries traffic for huge numbers of people, so the domains and samples linked to it in VirusTotal mostly have nothing to do with this laptop — the IOC-quality question 'could this be a false positive?' applies, just as with a shared CDN IP. The stronger lead is on the endpoint: what process on LAPTOP-JSMITH made the connection. 'Every sample belongs to one actor' assumes the IP is dedicated, which a relay is not. 'VirusTotal withholds relations' is invented — the data exists, it is just noisy. The abuse reports describe what other Tor users did through this relay, not what this laptop did.",
          xp: 50,
        },
      ],
    },

    // ── Flag Task ─────────────────────────────────────────────────────────────
    {
      type: "flag",
      id: "ioc-flag1",
      prompt:
        "To pull the laptop's DHCP and proxy records for the time of the alert, you need its internal address. From the threat-intelligence alert above, enter the IP address of the host that started this connection.",
      answer: "10.0.1.55",
      hint: "The record has two addresses. Work out which side opened the connection.",
      xp: 40,
    },

    // ── Question 4 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "ioc-q4",
      question:
        "A security analyst receives an IOC list from a threat intelligence feed containing 500 IP addresses associated with a recent attack campaign. What is the MOST effective way to operationalise these IOCs in the SOC?",
      options: [
        "Load the IPs into the SIEM as a quarterly report and review matches at the next audit",
        "Import them into the SIEM and firewall as a watchlist that alerts on any match in real time",
        "Block the IPs at the perimeter with no alerting, since blocked traffic needs no triage",
        "Keep the list in a shared spreadsheet and check IPs by hand once an incident is reported",
      ],
      answer: 1,
      explanation:
        "IOCs only help when they are operationalised in automated systems: a SIEM watchlist matches every log event against the list as it arrives, and a firewall feed blocks connections, so any internal host touching one of the 500 IPs raises an alert at once (after the usual quality checks on age and confidence). A quarterly report finds a compromise months late. Blocking with no alerting stops the connection but hides the fact that a host tried to reach attacker infrastructure — that host may already be infected and needs triage. A spreadsheet checked by hand only helps after someone already suspects an incident.",
      xp: 35,
    },

    // ── Question 5 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "ioc-q5",
      question:
        "An analyst finds an IP address in a threat intelligence report published 14 months ago. Should they immediately add it to their firewall blocklist? Why or why not?",
      options: [
        "Yes — an IP tied to an attack should stay blocked in case the same actor returns to it",
        "Not blindly — it may now belong to someone else; check for recent reports before blocking",
        "Yes — a hosting provider keeps an IP with the same customer for as long as it exists",
        "No — intelligence older than a few weeks has no value and should simply be discarded",
      ],
      answer: 1,
      explanation:
        "IPs are leased from hosting and cloud providers, so a C2 address from 14 months ago may have been released and reassigned to a legitimate customer; blocking it blindly risks breaking normal traffic for no gain. Check the last-seen date and look for recent corroboration first. 'Keep it blocked in case the actor returns' ignores reassignment and the false positives it causes. 'The same customer keeps the IP' is not how leasing works — addresses are returned and reissued. 'Older than a few weeks has no value' throws away useful context: old IOCs still help with retro-hunting and attribution, they just need validation before blocking.",
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
