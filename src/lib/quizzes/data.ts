// ─── Quiz Data ────────────────────────────────────────────────────────────────
// Each quiz has 10-12 multiple-choice questions with one correct answer.

export interface QuizQuestion {
  id: string;
  question: string;
  options: string[];
  answer: number;        // index into options[]
  explanation: string;
  xp: number;
}

export interface Quiz {
  slug: string;
  title: string;
  description: string;
  difficulty: "Beginner" | "Intermediate" | "Advanced";
  category: string;
  icon: string;        // emoji
  estimatedMinutes: number;
  questions: QuizQuestion[];
}

// ─────────────────────────────────────────────────────────────────────────────

export const QUIZZES: Quiz[] = [

  // ── 1. MITRE ATT&CK ───────────────────────────────────────────────────────
  {
    slug: "mitre-attack",
    title: "MITRE ATT&CK Framework",
    description: "Test your knowledge of tactics, techniques, and sub-techniques used by real adversaries across the full attack lifecycle.",
    difficulty: "Intermediate",
    category: "Threat Framework",
    icon: "🗺️",
    estimatedMinutes: 15,
    questions: [
      {
        id: "ma_01",
        question: "Which MITRE ATT&CK tactic describes an adversary attempting to steal credentials such as account names and passwords?",
        options: [
        "Credential Access",
        "Stealth",
        "Privilege Escalation",
        "Lateral Movement",
      ],
        answer: 0,
        explanation: "Credential Access (TA0006) covers techniques used to steal credentials like usernames, passwords, and tokens — including keylogging, credential dumping (T1003), and brute force (T1110).",
        xp: 10,
      },
      {
        id: "ma_02",
        question: "An attacker uses 'reg save HKLM\\SAM C:\\Windows\\Temp\\sam.hiv' on a compromised host. Which technique best describes this?",
        options: [
        "T1547 – Boot or Logon Autostart Execution",
        "T1059.001 – PowerShell",
        "T1003.002 – OS Credential Dumping: Security Account Manager",
        "T1112 – Modify Registry",
      ],
        answer: 2,
        explanation: "T1003.002 covers dumping the SAM hive, which stores NTLM password hashes for local accounts. The 'reg save' command copies the SAM registry hive to disk for offline cracking.",
        xp: 15,
      },
      {
        id: "ma_03",
        question: "What does the 'Discovery' tactic (TA0007) primarily involve?",
        options: [
        "Gathering information about the environment — users, hosts, network topology",
        "Encrypting data to hold for ransom",
        "Moving laterally to other systems using stolen credentials",
        "Establishing a command-and-control channel",
      ],
        answer: 0,
        explanation: "Discovery techniques let adversaries understand the target environment — who's in Active Directory (T1087), what hosts exist (T1018), what processes run (T1057), and what security tools are present (T1518.001).",
        xp: 10,
      },
      {
        id: "ma_04",
        question: "An adversary uses PsExec to run a payload on a remote host using domain admin credentials. Which ATT&CK technique describes how the payload is moved and launched on that host?",
        options: [
          "T1685.005 – Disable or Modify Tools: Clear Windows Event Logs",
          "T1055.012 – Process Injection: Process Hollowing",
          "T1021.002 – Remote Services: SMB/Windows Admin Shares",
          "T1078.002 – Valid Accounts: Domain Accounts",
        ],
        answer: 2,
        explanation: "PsExec connects over SMB (port 445) and uses admin shares (ADMIN$, C$) to copy and execute the payload remotely, leaving share access (5140/5145) followed by a service install (7045); that maps to T1021.002 under Lateral Movement. Clearing event logs is cleanup after execution, if it happens at all. Process hollowing replaces the code of a process on the same host rather than launching a payload remotely. Domain Accounts describes the domain admin credential that was used, not the mechanism that moves and runs the payload.",
        xp: 15,
      },
      {
        id: "ma_05",
        question: "What is a 'sub-technique' in the ATT&CK framework?",
        options: [
        "A more specific implementation of a parent technique",
        "A technique used only by nation-state actors",
        "A technique that evades signature-based detection",
        "A technique requiring elevated privileges",
      ],
        answer: 0,
        explanation: "Sub-techniques (denoted T1xxx.00x) provide more specific detail under a parent technique. For example, T1059.001 (PowerShell) is a sub-technique of T1059 (Command and Scripting Interpreter).",
        xp: 10,
      },
      {
        id: "ma_06",
        question: "Which technique involves an attacker abusing legitimate scheduled tasks to run malicious code persistently?",
        options: [
        "T1548 – Abuse Elevation Control Mechanism",
        "T1543.003 – Create or Modify System Process: Windows Service",
        "T1053.005 – Scheduled Task/Job: Scheduled Task",
        "T1574 – Hijack Execution Flow",
      ],
        answer: 2,
        explanation: "T1053.005 covers attackers using the Windows Task Scheduler to run code at a specified time or trigger, achieving persistence or privilege escalation. Common tools: schtasks.exe, at.exe.",
        xp: 10,
      },
      {
        id: "ma_07",
        question: "A host sends a steady stream of DNS queries for long, random-looking subdomains under one parent domain and receives its instructions back in TXT answers. Which ATT&CK technique best describes this command channel?",
        options: [
          "T1071.004 – Application Layer Protocol: DNS",
          "T1071.001 – Application Layer Protocol: Web Protocols",
          "T1568.001 – Dynamic Resolution: Fast Flux DNS",
          "T1071.003 – Application Layer Protocol: Mail Protocols",
        ],
        answer: 0,
        explanation: "Using DNS queries and TXT answers as the command channel is T1071.004, Application Layer Protocol: DNS, the technique the platform maps DNS command-and-control to. T1071.001 covers command traffic over HTTP and HTTPS, and T1071.003 covers it over mail protocols such as SMTP or IMAP; neither is DNS. T1568.001 Fast Flux DNS rotates the many IP addresses behind a domain to keep infrastructure alive; it does not carry instructions inside TXT answers.",
        xp: 15,
      },
      {
        id: "ma_08",
        question: "Which ATT&CK tactic contains the 'Phishing' technique (T1566)?",
        options: [
          "Execution",
          "Persistence",
          "Initial Access",
          "Collection",
        ],
        answer: 2,
        explanation: "T1566 (Phishing) lives under Initial Access (TA0001) — it covers spearphishing attachments, links, and service-based phishing as ways to gain a foothold in the target environment.",
        xp: 10,
      },
      {
        id: "ma_09",
        question: "An attacker injects malicious code into the memory of a running svchost.exe process. Which technique does this describe?",
        options: [
          "T1055 – Process Injection",
          "T1569.002 – System Services: Service Execution",
          "T1134 – Access Token Manipulation",
          "T1036 – Masquerading",
        ],
        answer: 0,
        explanation: "T1055 (Process Injection) involves inserting code into running processes to evade defenses and elevate privileges. svchost.exe is a common target because it's legitimate and always running. Sub-techniques include DLL injection, process hollowing, and reflective injection.",
        xp: 15,
      },
      {
        id: "ma_10",
        question: "What does the Impact tactic (TA0040) cover?",
        options: [
        "Techniques to maintain access after initial compromise",
        "Techniques to bypass security controls",
        "Techniques to move laterally between systems",
        "Techniques that manipulate, interrupt, or destroy systems and data",
      ],
        answer: 3,
        explanation: "Impact (TA0040) covers the end-goal techniques — ransomware encryption (T1486), data destruction (T1485), disk wipe (T1561), service stop (T1489), and defacement (T1491). These represent the adversary achieving their objective.",
        xp: 10,
      },
      {
        id: "ma_11",
        question: "Which tool is most associated with T1003 (OS Credential Dumping)?",
        options: [
          "Cobalt Strike",
          "Mimikatz",
          "BloodHound",
          "Metasploit",
        ],
        answer: 1,
        explanation: "Mimikatz is the most commonly used tool for credential dumping — it can extract NTLM hashes, Kerberos tickets, and plaintext passwords from LSASS memory. It's referenced in hundreds of threat intelligence reports.",
        xp: 10,
      },
      {
        id: "ma_12",
        question: "An adversary adds a new local administrator account and enables RDP on a compromised server. Which tactic does this primarily represent?",
        options: [
          "Initial Access",
          "Execution",
          "Exfiltration",
          "Persistence",
        ],
        answer: 3,
        explanation: "Creating a backdoor account (T1136, Create Account) and switching on remote access so the attacker can come back are persistence (TA0003) moves: they let the attacker return even if the original foothold is found and removed. Initial Access is how the attacker first got in, Execution is running code, and Exfiltration is moving data out; none of them describes building a way back in.",
        xp: 10,
      },
    ],
  },

  // ── 2. Incident Response ──────────────────────────────────────────────────
  {
    slug: "incident-response",
    title: "Incident Response",
    description: "Master the IR lifecycle — preparation, detection, containment, eradication, and lessons learned. Based on NIST SP 800-61 and PICERL.",
    difficulty: "Intermediate",
    category: "SOC Fundamentals",
    icon: "🚨",
    estimatedMinutes: 14,
    questions: [
      {
        id: "ir_01",
        question: "According to NIST SP 800-61, what are the four phases of the incident response lifecycle (in order)?",
        options: [
        "Preparation → Identification → Containment → Eradication → Recovery → Lessons Learned",
        "Identify → Protect → Detect → Respond → Recover (the five core functions)",
        "Detection & Triage → Investigation & Scoping → Remediation & Hardening → Executive Reporting",
        "Preparation → Detection & Analysis → Containment, Eradication & Recovery → Post-Incident Activity",
      ],
        answer: 3,
        explanation: "NIST SP 800-61 defines the IR lifecycle as: Preparation → Detection & Analysis → Containment, Eradication & Recovery → Post-Incident Activity (lessons learned). The other three are each a real model you will meet, which is exactly why they are easy to misattribute: the six-step Preparation → Identification → Containment → Eradication → Recovery → Lessons Learned is SANS' PICERL, not NIST's; Identify → Protect → Detect → Respond → Recover are the five NIST CSF core functions, which describe a whole security programme rather than the handling of one incident; and the fourth is a generic vendor-style operations flow with no standard behind it. Know which framework a phase name belongs to before you cite it in a report.",
        xp: 10,
      },
      {
        id: "ir_02",
        question: "During containment of an active ransomware incident, what is typically the FIRST action?",
        options: [
        "Wipe and rebuild all affected systems",
        "Isolate affected endpoints from the network",
        "Notify law enforcement",
        "Preserve forensic evidence",
      ],
        answer: 1,
        explanation: "Network isolation is the first priority in ransomware containment — it stops lateral movement and prevents additional encryption. After isolation, forensic preservation and eradication follow. Rebuilding comes later in Recovery.",
        xp: 15,
      },
      {
        id: "ir_03",
        question: "What is the purpose of a 'lessons learned' meeting after an incident?",
        options: [
        "To assign blame to the team that missed the alert",
        "To calculate the financial cost of the incident",
        "To verify that all malware has been removed from the network",
        "To document what happened and improve processes for future incidents",
      ],
        answer: 3,
        explanation: "The post-incident lessons learned (or post-mortem) meeting is blameless and forward-looking — it identifies what worked, what didn't, and what changes to procedures, detection rules, or tools can prevent recurrence.",
        xp: 10,
      },
      {
        id: "ir_04",
        question: "A user reports that their screen shows a ransom note and files have the extension '.locked'. What is the correct triage severity?",
        options: [
        "Low — a single workstation is not critical",
        "Critical — initiate major incident response immediately",
        "Medium — monitor and investigate",
        "High — open a ticket and investigate within 4 hours",
      ],
        answer: 1,
        explanation: "Active ransomware is a Critical/P1 incident. Encryption can spread across shared drives and network hosts within minutes. Immediate isolation and escalation to IR commander are required — every minute of delay increases the blast radius.",
        xp: 15,
      },
      {
        id: "ir_05",
        question: "What does 'dwell time' refer to in incident response?",
        options: [
          "Time taken to eradicate the threat after detection",
          "Time required to restore systems after an incident",
          "Time the attacker spends in the exfiltration phase",
          "Time from initial compromise to detection",
        ],
        answer: 3,
        explanation: "Dwell time is the gap between the attacker's initial compromise and the moment that activity was first detected, and it is the number a SOC is ultimately judged on. Time to eradicate and time to restore are later response and recovery measures, and time spent exfiltrating is only one slice of the attacker's activity. Industry medians have fallen from roughly 200 days in the mid-2010s to the days-to-weeks range, and shrinking dwell time further is a core SOC objective.",
        xp: 10,
      },
      {
        id: "ir_06",
        question: "Which document defines the roles, responsibilities, and communication plan for a security incident?",
        options: [
          "Business Continuity Plan (BCP)",
          "Incident Response Plan (IRP)",
          "System Security Plan (SSP)",
          "Disaster Recovery Plan (DRP)",
        ],
        answer: 1,
        explanation: "The Incident Response Plan (IRP) documents who does what during an incident — escalation paths, communication trees, evidence handling procedures, and decision authorities. It should be tested regularly with tabletop exercises.",
        xp: 10,
      },
      {
        id: "ir_07",
        question: "An analyst receives an alert for unusual PowerShell activity on a workstation. What is the FIRST step they should take?",
        options: [
        "Immediately isolate the workstation from the network",
        "Run an AV scan on the affected machine",
        "Open a P1 incident and page the CISO",
        "Check the alert context — review the process tree, parent process, and command line",
      ],
        answer: 3,
        explanation: "Before taking action, triage means gathering context: Is the PowerShell encoded? Who ran it? What was the parent process? Is this a known admin script? Analysis first prevents false-positive escalations and ensures the right response.",
        xp: 15,
      },
      {
        id: "ir_08",
        question: "What is 'chain of custody' important for during an incident?",
        options: [
          "Ensuring all analysts are working on the same timeline",
          "Maintaining the integrity and admissibility of digital evidence",
          "Tracking the attacker's lateral movement path",
          "Documenting the communication chain during escalation",
        ],
        answer: 1,
        explanation: "Chain of custody documents who handled evidence, when, and how — ensuring it hasn't been tampered with. This is critical if the incident leads to legal proceedings or law enforcement involvement. Break the chain and evidence may be inadmissible.",
        xp: 10,
      },
      {
        id: "ir_09",
        question: "During eradication, which action should be performed BEFORE rebuilding a compromised system?",
        options: [
        "Notify affected users",
        "Deploy endpoint detection tools",
        "Reset the domain admin password",
        "Take a forensic image of the system",
      ],
        answer: 3,
        explanation: "A forensic image (disk image) must be captured before wiping or rebuilding — it preserves evidence of attacker tools, persistence mechanisms, and malware for analysis. Rebuilding without imaging destroys evidence permanently.",
        xp: 10,
      },
      {
        id: "ir_10",
        question: "What is a 'playbook' in the context of SOC operations?",
        options: [
          "A compliance checklist used to demonstrate regulatory adherence during an external audit",
          "The attacker's plan of action, reconstructed by the SOC after an intrusion is contained",
          "A step-by-step procedure for responding to a specific type of alert or incident",
          "A list of approved security tools an analyst is authorized to use during a shift",
        ],
        answer: 2,
        explanation: "A SOC playbook is a scenario-specific, tactical procedure for handling one category of incident, such as a phishing or ransomware playbook; it reduces response time and keeps handling consistent. A compliance checklist is a governance artifact for auditors, not a response procedure. Reconstructing the attacker's plan after the fact is post-incident analysis. An approved-tools list is an asset-management record that says nothing about how to respond.",
        xp: 10,
      },
      {
        id: "ir_11",
        question: "An attacker has been evicted from the network. Before closing the incident, what critical step is often missed?",
        options: [
          "Checking for additional persistence mechanisms on every system",
          "Scanning all endpoints with antivirus to confirm a clean result",
          "Rebooting all servers to clear anything resident in memory",
          "Rotating all service account passwords across the domain",
        ],
        answer: 0,
        explanation: "Attackers commonly plant more than one persistence mechanism (scheduled tasks, Run keys, new accounts, services) as backups, and removing only the artifact the alert named leaves the others in place. An antivirus sweep finds commodity malware but not hand-built persistence. A reboot clears memory while leaving tasks and Run keys on disk. Rotating service passwords is good hygiene but locates nothing that was planted. A broad persistence hunt is what has to pass before eradication is declared complete.",
        xp: 15,
      },
    ],
  },

  // ── 3. Log Analysis & SIEM ────────────────────────────────────────────────
  {
    slug: "log-analysis-siem",
    title: "Log Analysis & SIEM",
    description: "Identify attack patterns from Windows Event Logs, Sysmon, Office 365, firewall logs, and DNS — the core skill of any SOC analyst.",
    difficulty: "Intermediate",
    category: "SOC Fundamentals",
    icon: "📋",
    estimatedMinutes: 15,
    questions: [
      {
        id: "la_01",
        question: "Windows Event ID 4624 indicates a successful logon. Which Event ID indicates a FAILED logon attempt?",
        options: [
        "4720",
        "4648",
        "4625",
        "4776",
      ],
        answer: 2,
        explanation: "Event ID 4625 is a failed logon attempt. Seeing many 4625 events from a single source IP or against a single account in a short period is a strong indicator of brute force or password spraying.",
        xp: 10,
      },
      {
        id: "la_02",
        question: "A Sysmon Event ID 1 (Process Create) log shows: ParentImage: WINWORD.EXE, Image: cmd.exe, CommandLine: 'cmd /c whoami > C:\\Users\\Public\\out.txt'. What is the most likely explanation?",
        options: [
        "A malicious macro executing a discovery command — a strong indicator of compromise",
        "A legitimate Office macro running a system command",
        "A Windows update process spawned by Office",
        "A user running cmd.exe from within Word for scripting purposes",
      ],
        answer: 0,
        explanation: "Office applications (WINWORD.EXE) should never spawn cmd.exe or powershell.exe in normal usage. This pattern — Office as parent, shell as child — is one of the most reliable indicators of a malicious macro executing a command.",
        xp: 15,
      },
      {
        id: "la_03",
        question: "In a SIEM, what does a 'correlation rule' do?",
        options: [
        "It normalizes log formats from different sources into a standard schema",
        "It routes alerts to the correct analyst based on severity",
        "It combines multiple events across sources or time to detect attack patterns",
        "It encrypts log data for compliance",
      ],
        answer: 2,
        explanation: "Correlation rules analyze events across time, users, hosts, and log sources to identify attack sequences that no single event would reveal — e.g., 'failed logins followed by success from the same IP' detects brute force success.",
        xp: 10,
      },
      {
        id: "la_04",
        question: "You observe thousands of DNS queries per minute to subdomains like 'a3f2b1.evil.com', 'd9e7c6.evil.com', each with different long random subdomains. What does this suggest?",
        options: [
        "DNS tunneling — data exfiltration or C2 communication encoded in DNS queries",
        "A CDN using DNS-based load balancing to spread traffic across edge nodes",
        "A misconfigured DNS forwarder retrying the same failed lookups",
        "A DDoS flood saturating the DNS resolver with repeated queries",
      ],
        answer: 0,
        explanation: "High-entropy subdomains in DNS queries are the hallmark of DNS tunneling. Tools like iodine, dnscat2, and custom C2 frameworks encode data into subdomain labels and TXT record responses. Legitimate DNS traffic does not have thousands of unique high-entropy subdomains.",
        xp: 15,
      },
      {
        id: "la_05",
        question: "What does Windows Event ID 4768 indicate?",
        options: [
          "A user logged on with explicitly supplied credentials",
          "A new user account was created in Active Directory",
          "A Kerberos TGT (Ticket Granting Ticket) was requested",
          "A logon session ended when the user logged off",
        ],
        answer: 2,
        explanation: "Event ID 4768 is a Kerberos Authentication Service request: a TGT (Ticket Granting Ticket) was requested, the first step of a Kerberos logon, logged on the domain controller. Option A describes 4648 (logon with explicit credentials), option B describes 4720 (account created) and option D describes a logoff (4634). In detection work, 4768 is where AS-REP Roasting shows up (a TGT issued to an account without pre-authentication); Kerberoasting shows up in 4769 service ticket requests, not 4768.",
        xp: 15,
      },
      {
        id: "la_06",
        question: "An Office 365 audit log shows 'Operation: New-InboxRule' with parameters that forward all email to an external address. What attack is this?",
        options: [
          "Business email compromise: the rule copies mail out to the attacker",
          "A spam campaign sending bulk outbound mail from the compromised account",
          "A phishing link the attacker composed and sent to the victim's contacts",
          "An account-lockout evasion trick to stay under failed-login thresholds",
        ],
        answer: 0,
        explanation: "Option A is correct: New-InboxRule with external forwarding is one of the most critical BEC signals; after compromising a mailbox, attackers create rules that forward incoming mail to an address they control. Option B is wrong because a forwarding rule copies inbound mail rather than sending bulk outbound spam. Option C is wrong because phishing from the account means composing new messages, not creating a passive rule. Option D is wrong because lockout evasion concerns failed sign-in thresholds, and this rule is created after a successful compromise.",
        xp: 15,
      },
      {
        id: "la_07",
        question: "What is log normalization in a SIEM context?",
        options: [
          "Deleting logs that are older than the configured retention period",
          "Applying statistical analysis to log volumes to surface anomalies",
          "Mapping fields from different sources onto one common schema",
          "Encrypting log data before it is written to long-term storage",
        ],
        answer: 2,
        explanation: "Option C is correct: parsing breaks a raw event into fields, and normalization maps those vendor-specific field names onto a common schema so a query written once works across many sources. Option A describes retention, not normalization. Option B describes analytics, which depends on normalized data but is a different step. Option D describes encryption of stored logs, a storage control unrelated to field mapping.",
        xp: 10,
      },
      {
        id: "la_08",
        question: "A firewall log shows 10,000 connection attempts from a single IP to sequential destination ports (22, 23, 25, 80, 443, 445...). What is happening?",
        options: [
        "Port scanning — reconnaissance activity mapping open services",
        "A legitimate network scanner performing asset inventory",
        "A DDoS attack from a botnet",
        "A misconfigured application retrying connections",
      ],
        answer: 0,
        explanation: "Sequential port connections from a single source are a textbook port scan (nmap default behavior). While this could be a legitimate internal scanner, from an external IP or unexpected internal host, it indicates reconnaissance — the first step of many attacks.",
        xp: 10,
      },
      {
        id: "la_09",
        question: "What does 'log retention' policy determine?",
        options: [
        "How many analysts can access logs simultaneously",
        "Which log sources are sent to the SIEM",
        "How long logs are stored before deletion",
        "The maximum size of a single log entry",
      ],
        answer: 2,
        explanation: "Log retention defines how long logs are kept. Compliance frameworks (PCI-DSS: 1 year, GDPR: varies) and forensic needs (average attacker dwell time ~21 days) drive retention requirements. Too short and you can't investigate historical incidents.",
        xp: 10,
      },
      {
        id: "la_10",
        question: "Sysmon Event ID 3 (Network Connection) shows rundll32.exe opening an outbound connection to 203.0.113.42 on port 443. Why is this worth investigating?",
        options: [
          "rundll32.exe routinely downloads Windows updates over port 443",
          "rundll32.exe is a LOLBIN whose external connections are rarely benign",
          "Port 443 is an unusual port that workstations seldom open connections on",
          "Sysmon Event ID 3 records connections that the firewall has blocked",
        ],
        answer: 1,
        explanation: "Option B is correct: Sysmon Event ID 3 ties an outbound connection to the process that made it, and a Living-Off-The-Land Binary such as rundll32.exe, regsvr32.exe or mshta.exe making external connections is almost always malicious. Option A is wrong because Windows updates are not fetched by rundll32.exe. Option C is wrong because 443 is the standard HTTPS port that most legitimate web traffic uses; the process, not the port, is the signal. Option D is wrong because Event ID 3 records connections a process initiates, not firewall blocks.",
        xp: 15,
      },
      {
        id: "la_11",
        question: "What is a 'false positive' in SIEM alerting?",
        options: [
        "An alert that correctly identifies a real attack",
        "A rule that fires too slowly to be actionable",
        "A critical vulnerability that is not detected by any rule",
        "An alert for a legitimate activity that is incorrectly flagged as malicious",
      ],
        answer: 3,
        explanation: "A false positive is a SIEM alert that fires on benign activity. High false positive rates cause 'alert fatigue' — analysts start ignoring alerts. Tuning rules to reduce false positives (e.g., whitelisting known admin tools) while maintaining detection coverage is a key SIEM engineering challenge.",
        xp: 10,
      },
      {
        id: "la_12",
        question: "You see Windows Event 4698 (A scheduled task was created) immediately followed by 4702 (A scheduled task was updated) and 4700 (A scheduled task was enabled). What attack pattern does this suggest?",
        options: [
          "Windows Update routinely rebuilding its own built-in system tasks",
          "Scheduled-task persistence: a task created, updated and enabled",
          "A legitimate application installing its normal update scheduler",
          "A Group Policy Object pushing approved tasks out to endpoints",
        ],
        answer: 1,
        explanation: "Option B is correct: attackers frequently create scheduled tasks to maintain persistence, and 4698 (created), 4702 (updated) and 4700 (enabled) in quick succession is a task being set up to run. Confirm by reading the task's action and the account and process that created it. Option A is wrong because built-in Microsoft tasks are maintained by the OS, not freshly created as a new task chain. Option C is wrong because a benign installer is something you must prove from the parent process and task content, not assume. Option D is wrong because a GPO push appears on many hosts within one refresh interval and traces back to a GPO change, which nothing here indicates.",
        xp: 15,
      },
    ],
  },

  // ── 4. Threat Intelligence ────────────────────────────────────────────────
  {
    slug: "threat-intelligence",
    title: "Threat Intelligence",
    description: "Understand IOC enrichment, threat actor profiling, intelligence sources, and how to operationalize TI in a SOC environment.",
    difficulty: "Advanced",
    category: "Threat Intelligence",
    icon: "🧠",
    estimatedMinutes: 13,
    questions: [
      {
        id: "ti_01",
        question: "What best distinguishes strategic from tactical threat intelligence?",
        options: [
          "Strategic is specific IOCs checked by analysts; tactical is sector trends for executives",
          "Strategic covers nation-state espionage actors; tactical covers financially motivated criminal groups",
          "Strategic is sector trends for leadership's budget calls; tactical is specific IOCs for analysts",
          "Strategic describes one campaign's TTPs for hunters; tactical describes budget risk for the CISO",
        ],
        answer: 2,
        explanation: "Strategic intelligence is the highest altitude: trends and sector targeting that a CISO or leadership team uses for resourcing decisions. Tactical intelligence is the ground floor: hashes, IPs and domains an analyst checks mid-investigation. Giving strategic the IOCs and tactical the sector trends reverses the two. Altitude is about audience and time horizon, not actor type, so the nation-state versus criminal split is wrong. Campaign TTPs used for proactive hunting are operational intelligence, the middle level, and budget risk for the CISO is strategic, so the option pairing those with strategic and tactical mislabels both levels.",
        xp: 10,
      },
      {
        id: "ti_02",
        question: "Which framework describes the relationship between attacker capabilities, infrastructure, and victims using a diamond shape?",
        options: [
        "Diamond Model of Intrusion Analysis",
        "MITRE ATT&CK",
        "Cyber Kill Chain",
        "PASTA (Process for Attack Simulation and Threat Analysis)",
      ],
        answer: 0,
        explanation: "The Diamond Model has four vertices: Adversary, Capability, Infrastructure, Victim — connected in a diamond shape. It's used to analyze intrusions and understand how changing one vertex affects the others, enabling effective attribution and detection pivoting.",
        xp: 15,
      },
      {
        id: "ti_03",
        question: "What does 'TTPs' stand for in threat intelligence, and why are they more valuable than IOCs?",
        options: [
          "Targets, Telemetry, Profiles: they describe victim environments and monitoring data",
          "Threats, Tools, Processes: they list the software an attacker installs on each host",
          "Tactics, Techniques, Procedures: they describe behavior that is costly to change",
          "Tactics, Tools, Payloads: they catalogue the files an attacker drops during an intrusion",
        ],
        answer: 2,
        explanation: "TTPs (tactics, techniques, and procedures) sit at the top of the Pyramid of Pain: denying them forces an attacker to change how they operate, which is slow and expensive, while hashes and IPs can be swapped in minutes. 'Targets, Telemetry, Profiles' and 'Threats, Tools, Processes' are not the accepted expansion. 'Tactics, Tools, Payloads' swaps in the wrong terms, and payloads and files are exactly the cheap, easily rotated artifacts at the bottom of the pyramid.",
        xp: 15,
      },
      {
        id: "ti_04",
        question: "What is STIX/TAXII used for?",
        options: [
        "Standardized formats for sharing threat intelligence between organizations",
        "Encrypting logs before transmission to a SIEM",
        "Scanning endpoints for known malware signatures",
        "Correlating alerts across different security tools",
      ],
        answer: 0,
        explanation: "STIX (Structured Threat Information eXpression) is the data format for describing threat intelligence objects (indicators, campaigns, threat actors). TAXII (Trusted Automated eXchange of Intelligence Information) is the transport protocol. Together they enable automated TI sharing between organizations and threat feeds.",
        xp: 10,
      },
      {
        id: "ti_05",
        question: "What is the 'Pyramid of Pain' and what does it demonstrate?",
        options: [
          "A severity-scoring model for software vulnerabilities, similar in spirit to CVSS",
          "A risk framework that ranks incidents by business impact to decide escalation",
          "A model ranking indicator types by how hard they are for attackers to change",
          "A chart of a data breach's cost at each stage, used for budgeting and reporting",
        ],
        answer: 2,
        explanation: "David Bianco's Pyramid of Pain ranks indicator types by how much it hurts an adversary to lose them: hash values (trivial), IP addresses, domain names, network and host artifacts, tools, and at the top TTPs, which force the attacker to change how they operate. The higher you detect, the more durable the detection. It is not a vulnerability-severity score like CVSS, not an incident-escalation framework, and not a breach-cost model.",
        xp: 15,
      },
      {
        id: "ti_06",
        question: "Which free threat intelligence platform provides SHA256 hash lookup, IP reputation, and domain analysis?",
        options: [
        "VirusTotal",
        "MISP",
        "OpenCTI",
        "TAXII Server",
      ],
        answer: 0,
        explanation: "VirusTotal aggregates results from 70+ antivirus engines and provides reputation data for hashes, IPs, domains, and URLs. It's the most widely used free lookup tool in SOC operations. MISP and OpenCTI are TI platforms for managing and sharing intelligence internally.",
        xp: 10,
      },
      {
        id: "ti_07",
        question: "What is a 'threat actor group' in the context of threat intelligence?",
        options: [
        "A group of security analysts tracking a threat",
        "A collection of malware samples with similar code",
        "A named cluster of malicious activity attributed to a specific adversary or organization",
        "A vendor-defined severity tier for vulnerability prioritization",
      ],
        answer: 2,
        explanation: "Threat actor groups (APT28, Lazarus Group, FIN7) are named clusters of attack activity believed to originate from the same adversary. Attribution is based on TTPs, infrastructure, malware, and victimology. Names differ by vendor (Mandiant vs Microsoft vs CrowdStrike).",
        xp: 10,
      },
      {
        id: "ti_08",
        question: "What is 'indicator enrichment' in a SOC workflow?",
        options: [
          "Adding context to a raw IOC — geolocation, WHOIS, reputation score, related campaigns",
          "Encrypting IOCs before sharing with external partners",
          "Removing duplicate indicators from a threat feed",
          "Converting indicators from one format (STIX) to another (CSV)",
        ],
        answer: 0,
        explanation: "Enrichment adds context to raw IOCs: an IP address becomes 'ASN: AS202425, Country: RU, Reputation: malicious, Related campaigns: APT29 SVR'. Enriched IOCs help analysts quickly assess severity and relevance without manual research.",
        xp: 10,
      },
      {
        id: "ti_09",
        question: "APT29 (Cozy Bear) is attributed to which nation-state?",
        options: [
          "China (People's Liberation Army, PLA)",
          "North Korea (Reconnaissance General Bureau)",
          "Russia (SVR Foreign Intelligence Service)",
          "Iran (Islamic Revolutionary Guard Corps)",
        ],
        answer: 2,
        explanation: "APT29 (also tracked as Cozy Bear, Midnight Blizzard and NOBELIUM) operates on behalf of Russia's Foreign Intelligence Service, the SVR. It is known for the SolarWinds supply-chain attack and for the 2023-2024 breach of Microsoft's own corporate email. North Korea's Reconnaissance General Bureau, China's PLA and Iran's Islamic Revolutionary Guard Corps sponsor other groups; none of them is APT29's sponsor.",
        xp: 10,
      },
      {
        id: "ti_10",
        question: "In a finished threat-intelligence assessment, what is the difference between likelihood and confidence?",
        options: [
          "Likelihood is how probable the judgement is; confidence is how good its evidence is",
          "Likelihood is how severe the threat is; confidence is how quickly the indicator was found",
          "They are the same measure, so a report should state only one to avoid repeating itself",
          "Likelihood counts the feeds that reported an IOC; confidence is the analyst's seniority",
        ],
        answer: 0,
        explanation: "Calibrated assessments keep two things apart that beginners merge: likelihood (how probable the judgement is, in standard words such as likely or very likely) and confidence (low, moderate or high, describing the quality of the evidence). 'Likely, with moderate confidence' is a precise statement. Severity and discovery speed are different properties altogether. Treating the two as one measure is exactly the mistake the practice exists to prevent. Feed counts and analyst seniority describe neither.",
        xp: 10,
      },
    ],
  },

  // ── 5. Network Security ───────────────────────────────────────────────────
  {
    slug: "network-security",
    title: "Network Security & Firewalls",
    description: "Understand firewall rules, network-based attack detection, protocol analysis, and common network attack patterns seen in enterprise environments.",
    difficulty: "Beginner",
    category: "Network",
    icon: "🌐",
    estimatedMinutes: 12,
    questions: [
      {
        id: "ns_01",
        question: "What is the purpose of a DMZ (Demilitarized Zone) in network architecture?",
        options: [
          "To host internet-facing servers apart from the internal network",
          "To hold backup copies of data away from production for disaster recovery",
          "To give servers a high-speed segment that improves application speed",
          "To separate internal users by department so each has its own segment",
        ],
        answer: 0,
        explanation: "Option A is correct: a DMZ (screened subnet) sits between the internal network and the internet and hosts services that must be reachable from outside, so a compromised public server does not share a segment with sensitive internal systems. Option B describes backup and disaster-recovery infrastructure. Option C is a performance goal, not the isolation a DMZ provides. Option D describes internal segmentation by department, which concerns internal traffic, not internet exposure.",
        xp: 10,
      },
      {
        id: "ns_02",
        question: "What does a stateful firewall track that a stateless (packet filter) firewall does not?",
        options: [
          "Application protocols such as HTTP and DNS inside each packet",
          "User identities and group memberships behind each connection",
          "Connection state, so return traffic is allowed automatically",
          "Deep packet content matched against malware signatures",
        ],
        answer: 2,
        explanation: "Option C is correct: a stateful firewall keeps a session table, so once a connection is approved, return traffic is automatically permitted as part of that session; a stateless filter judges every packet on its own. Option A describes application awareness, an NGFW feature (App-ID). Option B describes identity mapping (User-ID), also an NGFW feature. Option D describes IPS-style payload inspection.",
        xp: 10,
      },
      {
        id: "ns_03",
        question: "Port 445 is commonly targeted by attackers. Which protocol runs on port 445 and why is it high-value?",
        options: [
          "SMB: Windows file sharing, abused for lateral spread and ransomware",
          "RDP: remote desktop access, abused for brute force and remote logins",
          "DNS: name resolution, abused for tunnelling data out of the network",
          "LDAP: directory queries, abused for Active Directory reconnaissance",
        ],
        answer: 0,
        explanation: "Option A is correct: SMB runs on 445/TCP for Windows file sharing and is abused for lateral movement, ransomware spread and WannaCry-class worms. Option B is wrong because RDP uses 3389/TCP. Option C is wrong because DNS uses 53/UDP (TCP for large responses). Option D is wrong because LDAP uses 389.",
        xp: 15,
      },
      {
        id: "ns_04",
        question: "What is a 'beaconing' pattern in network traffic, and why is it significant?",
        options: [
        "A broadcast packet used for device discovery on the local network",
        "An ICMP ping sweep used for network reconnaissance",
        "Regular, periodic outbound connections to a C2 server indicating malware 'calling home'",
        "A legitimate keepalive mechanism used by VPN clients",
      ],
        answer: 2,
        explanation: "Beaconing is when malware makes regular outbound connections to a C2 server (e.g., every 60 seconds ± jitter). The regular interval is the key detection signal. Tools like Cobalt Strike beacon default to 60-second intervals. Network flow analysis can detect this pattern even if the payload is encrypted.",
        xp: 15,
      },
      {
        id: "ns_05",
        question: "What is an NTLM relay attack?",
        options: [
          "Forwarding captured NTLM authentication to another server in real time",
          "Capturing Kerberos tickets in transit from unpatched domain controllers",
          "Cracking captured NTLM hashes offline by guessing weak passwords",
          "Injecting forged DNS responses from an unsecured internal DNS server",
        ],
        answer: 0,
        explanation: "Option A is correct: relay forwards a captured authentication attempt onward to a real target in real time, without the attacker ever knowing or cracking the credential. It works because NTLM's challenge-response does not, by default, bind an attempt to a specific destination; SMB signing and disabling NTLM are the mitigations. Option B is wrong because it describes stealing Kerberos tickets, not forwarding an NTLM exchange. Option C describes offline cracking, which needs the password guessed. Option D describes DNS spoofing, a different attack.",
        xp: 15,
      },
      {
        id: "ns_06",
        question: "Which firewall log field helps identify whether a connection was allowed or blocked?",
        options: [
          "source.port",
          "network.protocol",
          "action / disposition",
          "session.duration",
        ],
        answer: 2,
        explanation: "The action field (allow, deny, drop, reject) tells you what the firewall did with the packet. 'allow' means traffic passed; 'deny/drop' means it was blocked. In Palo Alto logs, this is 'action'; in Fortinet, it's 'action'; in Cisco ASA, it's 'Built/Teardown' or 'Deny'.",
        xp: 10,
      },
      {
        id: "ns_07",
        question: "What is a 'split-tunnel VPN' and what security risk does it introduce?",
        options: [
          "Only corporate traffic is tunnelled, so web browsing bypasses SOC monitoring",
          "Only half of each session is encrypted, leaving the rest open to interception",
          "Two tunnels run side by side for redundancy, doubling the attack surface",
          "Admins and standard users get separate tunnels with different privileges",
        ],
        answer: 0,
        explanation: "Option A is correct: in a split tunnel only corporate traffic goes through the VPN while personal browsing goes straight to the internet, bypassing corporate security controls, so C2 traffic from a compromised laptop can avoid the SOC's proxy and firewall. Option B is wrong because a VPN tunnel encrypts what it carries; split tunnelling only decides what goes into it. Option C describes high-availability failover, not split tunnelling. Option D describes role-based access, not routing.",
        xp: 10,
      },
      {
        id: "ns_08",
        question: "What does a high volume of outbound HTTPS traffic to a newly registered domain with a self-signed certificate suggest?",
        options: [
          "A user streaming video from a newly launched streaming service",
          "Routine software updates pulled from a vendor's download servers",
          "Possible C2: new domains and self-signed certs dodge reputation checks",
          "A misconfigured internal proxy server repeatedly retrying failed requests",
        ],
        answer: 2,
        explanation: "Option C is correct: self-signed certificates and freshly registered domains are classic C2 tells, because a new domain has no reputation yet and a self-signed certificate avoids a public CA; pair them with the originating process before concluding. Option A is wrong because a legitimate streaming service presents a CA-signed certificate. Option B is wrong because vendor updates come from long-established, CA-signed domains. Option D is wrong because a proxy fault produces errors and timeouts, not a high volume of successful sessions to one new host.",
        xp: 15,
      },
      {
        id: "ns_09",
        question: "What is the purpose of Network Access Control (NAC)?",
        options: [
          "To admit only authenticated, policy-compliant devices to the network",
          "To filter which websites users may visit while browsing the internet",
          "To absorb DDoS floods at the perimeter before they reach servers",
          "To record all network traffic so it can be replayed for forensics",
        ],
        answer: 0,
        explanation: "Option A is correct: with NAC every device must prove its identity and health (posture) before receiving access, and non-compliant devices are quarantined. Option B is the job of a secure web gateway or proxy. Option C is upstream DDoS scrubbing or rate limiting. Option D is packet capture or SIEM retention, not device admission.",
        xp: 10,
      },
      {
        id: "ns_10",
        question: "Which port and protocol does Kerberos use?",
        options: [
        "TCP/UDP 389 — LDAP",
        "UDP 123 — NTP",
        "TCP 445 — SMB",
        "TCP/UDP 88 — Kerberos",
      ],
        answer: 3,
        explanation: "Kerberos uses TCP and UDP port 88 for ticket requests and responses. Port 88 traffic to domain controllers is normal; excessive AS-REQ (4768) or TGS-REQ (4769) volume, especially for service accounts, may indicate Kerberoasting or AS-REP Roasting.",
        xp: 10,
      },
      {
        id: "ns_11",
        question: "An IDS alert fires for 'ET SCAN Nmap SYN Scan'. What does this mean and should it be treated as a critical incident?",
        options: [
          "Yes: an Nmap scan means an active intrusion that needs containment now",
          "Not by itself: triage whether the scan is authorized or hostile recon",
          "No: Nmap is a sysadmin tool, so its scans can be closed as benign",
          "Yes: an Nmap SYN scan is the opening stage of a ransomware attack",
        ],
        answer: 1,
        explanation: "Option B is correct: the signature only says a SYN scan was seen. Triage decides whether it is explained (a sanctioned scanner, a pentest schedule) or malicious reconnaissance, and whether the source is internal or external. Option A is wrong because authorised scanners trigger the same rule. Option C is wrong because attackers use Nmap too, so the source still has to be checked. Option D is wrong because scanning precedes many kinds of activity, legitimate and hostile, not ransomware specifically.",
        xp: 15,
      },
    ],
  },

  // ── 6. Cloud & Identity Security ──────────────────────────────────────────
  {
    slug: "cloud-identity-security",
    title: "Cloud & Identity Security",
    description: "Azure AD, Entra ID, OAuth, MFA bypass techniques, and cloud-specific attack patterns — essential knowledge for modern enterprise SOC analysts.",
    difficulty: "Advanced",
    category: "Cloud Security",
    icon: "☁️",
    estimatedMinutes: 15,
    questions: [
      {
        id: "ci_01",
        question: "What is 'MFA Fatigue' (also called MFA Bombing)?",
        options: [
        "A technique where the attacker steals MFA tokens from the authenticator app",
        "Disabling MFA policies in Azure AD to bypass authentication",
        "Spamming a victim with MFA push notifications until they approve one out of frustration or confusion",
        "Phishing the victim's MFA backup codes via email",
      ],
        answer: 2,
        explanation: "MFA Fatigue involves sending repeated push notifications to the victim's authenticator app. Attackers (like Lapsus$) used this to compromise Uber, Cisco, and others. Mitigations: number matching, additional context in MFA prompts, push notification limits.",
        xp: 15,
      },
      {
        id: "ci_02",
        question: "What is OAuth consent phishing and how does it differ from credential phishing?",
        options: [
          "It tricks users into granting a malicious app OAuth permissions, gaining API access with no password",
          "It steals the victim's password through a fake login page and then replays it to sign in past MFA",
          "It intercepts OAuth tokens on the wire with a man-in-the-middle relay between the user and the provider",
          "It exploits a design flaw in the OAuth 2.0 protocol itself to mint tokens without any user involvement",
        ],
        answer: 0,
        explanation: "Consent phishing sends the user to the provider's real consent page and asks them to approve a malicious app's scopes, for example offline_access and Mail.Read. Once approved, the app holds a token, so no password is stolen and resetting the password does not remove access; the fix is revoking the grant. A fake login page that harvests the password is classic credential phishing. Relaying traffic to capture tokens in transit is adversary-in-the-middle, a different technique. And consent phishing abuses the legitimate OAuth consent flow rather than a flaw in the protocol.",
        xp: 15,
      },
      {
        id: "ci_03",
        question: "In Azure AD logs, what does the Office 365 operation 'Add service principal' indicate?",
        options: [
          "A new human user account was created and assigned a mailbox in the tenant",
          "An existing service account had its password reset by an administrator",
          "An application received an identity in the tenant, usable for persistence",
          "A Conditional Access policy was modified to change sign-in requirements",
        ],
        answer: 2,
        explanation: "A service principal is an application's identity in the tenant. Registering one is an audit-log event, and attackers use it for persistence because an app holding granted permissions keeps API access even after the compromised user's password is reset. Creating a human account is the separate 'Add user' operation. A password reset changes the credential of an existing account rather than creating an application identity. A Conditional Access change alters sign-in conditions for existing identities and is logged as a policy update, not as a new service principal.",
        xp: 15,
      },
      {
        id: "ci_04",
        question: "What is 'Conditional Access' in Azure AD and why is it important for security?",
        options: [
          "A policy engine that checks conditions such as device compliance, location and risk before access",
          "A firewall rule set that filters network traffic between Azure virtual networks and their subnets",
          "The tenant-wide switch that turns multi-factor authentication on for every user at the same time",
          "A threat-intelligence feed that scores IP addresses before they are allowed to reach Azure services",
        ],
        answer: 0,
        explanation: "Conditional Access is the policy engine at the heart of Entra ID: for every sign-in it evaluates signals such as the user, device compliance, location and risk, then allows, blocks, or demands stronger proof such as MFA. Filtering traffic between virtual networks is the job of Network Security Groups and Azure Firewall, not an identity control. MFA is one requirement a Conditional Access policy can enforce, so equating the two confuses the engine with one of its outputs. A threat-intelligence IP feed is an input to risk scoring, not the engine that decides access.",
        xp: 10,
      },
      {
        id: "ci_05",
        question: "An admin account's sign-in shows riskLevelDuringSignIn: high, with riskEventTypes_v2 listing anonymizedIPAddress and unfamiliarFeatures, from a non-compliant device minutes after a sign-in from another continent. Correlation confirms a probable takeover. What is the right response?",
        options: [
          "Revoke sessions and tokens, reset the password, force MFA re-registration, and hunt for persistence",
          "Dismiss the risk event and add the anonymous IP range to the tenant's list of trusted named locations",
          "Force a password reset and stop there, since a new password automatically ends existing sessions",
          "Email the admin and wait for them to confirm the sign-in was theirs before taking any containment action",
        ],
        answer: 0,
        explanation: "For a probable takeover the lesson says to act decisively: revoke active sessions and refresh tokens so the stolen session stops working, force a password reset, require MFA re-registration because attackers often add their own methods, and hunt for persistence such as OAuth grants or mailbox rules. Dismissing the risk and trusting the IP range is the response to a likely false positive, not a probable takeover. A password reset on its own does not end sessions that already hold valid tokens. Waiting on the account owner gives the attacker time, and the reply could come from the attacker who controls the mailbox.",
        xp: 15,
      },
      {
        id: "ci_06",
        question: "What is the difference between 'delegated permissions' and 'application permissions' in Microsoft Graph API?",
        options: [
          "Delegated permissions require a user to be signed in; application permissions allow the app to access data without a user context",
          "Delegated permissions are for admins; application permissions are for regular users",
          "Application permissions require MFA; delegated permissions bypass it",
          "There is no security difference — both grant the same access level",
        ],
        answer: 0,
        explanation: "Delegated permissions act on behalf of a signed-in user (limited to what that user can access). Application permissions allow the app to access all tenant data regardless of which user is signed in — making them extremely powerful and attractive to attackers (e.g., Mail.ReadAll without impersonating any user).",
        xp: 15,
      },
      {
        id: "ci_07",
        question: "What is a 'Pass-the-Cookie' attack in cloud environments?",
        options: [
          "Injecting a malicious script into a web page so that it runs in other visitors' browsers",
          "Relaying captured NTLM hashes to authenticate to other hosts on the internal network",
          "Stealing browser cookies that hold an authenticated session to bypass MFA in cloud apps",
          "Trying one common password across many cloud accounts to stay under the lockout limit",
        ],
        answer: 2,
        explanation: "In pass-the-cookie the attacker plants a stolen session cookie into their own browser and lands inside the account with no password prompt and no MFA prompt, because the real user already completed both. Cookies are typically stolen by infostealer malware reading the browser's cookie store, or captured by adversary-in-the-middle phishing kits such as Evilginx. Running a script in visitors' browsers is cross-site scripting. Relaying NTLM hashes is an on-premises credential technique with no browser session involved. Trying one password across many accounts is password spraying.",
        xp: 15,
      },
      {
        id: "ci_08",
        question: "Azure AD Privileged Identity Management (PIM) provides which security capability?",
        options: [
        "Just-in-time privileged access — requiring approval and providing time-limited admin roles",
        "Continuous monitoring of all Azure resource configurations",
        "Automated threat response for identity-based attacks",
        "Certificate-based authentication for service accounts",
      ],
        answer: 0,
        explanation: "PIM implements just-in-time (JIT) access — users don't permanently hold privileged roles. They activate them when needed (with approval and justification), for a limited time window. This dramatically reduces standing privilege exposure and forces audit trails for privileged actions.",
        xp: 10,
      },
      {
        id: "ci_09",
        question: "What does a 'Global Administrator' role in Azure AD/Entra ID allow?",
        options: [
          "Read-only visibility into every Azure subscription and resource, with no ability to change them",
          "Contributor rights over the Azure virtual machines and networks inside a single subscription",
          "Full control of the entire tenant, including any Microsoft 365 service and any user's password",
          "Access limited to billing, invoices and the purchasing of subscriptions for the organisation",
        ],
        answer: 2,
        explanation: "Global Administrator is the top Entra ID role: adding an account to it gives full control of the entire tenant, which is why the 'Add member to role' operation for this role should raise an immediate alert and why the role is protected with phishing-resistant MFA and just-in-time activation. Read-only visibility describes a Reader role. Rights over virtual machines in one subscription describe an Azure resource role such as Contributor, scoped to infrastructure rather than identity. Billing-only access describes the Billing Administrator role.",
        xp: 10,
      },
      {
        id: "ci_10",
        question: "What is 'Password Spray' and how does it differ from brute force?",
        options: [
          "Password spray tries many passwords against one account; brute force tries one password against many accounts",
          "Password spray tries one common password against many accounts to avoid account lockouts; brute force tries many passwords against one account",
          "Password spray only works against cloud accounts; brute force only works against on-premises AD",
          "There is no difference — both are the same attack",
        ],
        answer: 1,
        explanation: "Password spray avoids account lockout by trying one or a few common passwords (Password1!, Summer2024) across thousands of accounts. Each account only sees 1-2 failed attempts — below the lockout threshold. Detected in logs as many 4625/UserLoginFailed events spread across accounts from a single IP.",
        xp: 10,
      },
      {
        id: "ci_11",
        question: "Which Azure AD log source would show evidence of a successful Pass-the-Cookie attack?",
        options: [
          "Azure Activity Log entries for management operations on virtual machines and storage accounts",
          "Entra ID audit log entries showing 'Update user' changes to a user's directory attributes",
          "Exchange Online message trace records showing how each individual email was routed",
          "Entra ID sign-in log showing a token-satisfied sign-in with no MFA prompt from a new location",
        ],
        answer: 3,
        explanation: "A replayed session cookie produces a successful sign-in in the Entra ID sign-in log, often with the same session ID as the victim's earlier sign-in, a different country or network, a non-interactive flag, and an authentication detail of 'Previously satisfied', meaning the MFA requirement was met by a claim in the token with no challenge presented. The Activity Log records Azure resource management, not user authentication. 'Update user' audit entries record directory changes rather than the authentication event. Message trace follows email delivery and says nothing about sign-ins.",
        xp: 15,
      },
      {
        id: "ci_12",
        question: "What is the 'principle of least privilege' in cloud IAM and why is it critical?",
        options: [
          "Every identity should get temporary administrator rights so that work is never blocked",
          "Each identity should hold only the minimum permissions its job requires, and no more",
          "Privileged roles should be assigned permanently so that their use is easier to audit",
          "Cloud resources should be reachable only from inside the corporate office network",
        ],
        answer: 1,
        explanation: "Least privilege means granting each identity only the exact actions on the exact resources it needs. That limits the blast radius of a compromised account: a credential that can read one bucket cannot be used to rewrite IAM or reach other services. Handing out temporary admin rights to avoid friction is the opposite of least privilege. Permanent privileged assignments create standing privilege, which just-in-time tools such as PIM exist to remove. Restricting access to the office network is a network-location control, not a rule about how many permissions an identity holds.",
        xp: 10,
      },
    ],
  },
];

// Quiz packs live in their own files so the catalogue can grow without this one
// becoming unreviewable. Everything that reads QUIZZES — the index, the admin
// content manager, getQuiz — picks them up from here automatically.
import { QUIZZES_ENDPOINT_IDENTITY } from "./data-endpoint-identity";
import { QUIZZES_DETECTION_APPSEC } from "./data-detection-appsec";
import { QUIZZES_FOUNDATIONS_DATASEC } from "./data-foundations-datasec";
import { QUIZZES_SECURITY_TOOLS } from "./data-security-tools";
import { QUIZZES_PROTOCOLS_PORTS } from "./data-protocols-ports";
import { QUIZZES_SECURITY_MODELS } from "./data-security-models";
import { QUIZZES_ATTACK_TYPES } from "./data-attack-types";
import { QUIZZES_HUNTING_DECISIONS } from "./data-hunting-decisions";
import { QUIZZES_MALWARE_WINDOWS } from "./data-malware-windows";
import { QUIZZES_LINUX_CLOUD } from "./data-linux-cloud";
import { QUIZZES_VENDOR_STACKS } from "./data-vendor-stacks";

export const ALL_QUIZZES: Quiz[] = [
  ...QUIZZES,
  ...QUIZZES_ENDPOINT_IDENTITY,
  ...QUIZZES_DETECTION_APPSEC,
  ...QUIZZES_FOUNDATIONS_DATASEC,
  ...QUIZZES_SECURITY_TOOLS,
  ...QUIZZES_PROTOCOLS_PORTS,
  ...QUIZZES_SECURITY_MODELS,
  ...QUIZZES_ATTACK_TYPES,
  // Packs closing the gaps found by auditing the platform's quiz catalogue
  // against the full topic list: hunting, decision-making, malware, Windows
  // event IDs, Linux, cloud platform/infrastructure, and the vendor consoles.
  ...QUIZZES_HUNTING_DECISIONS,
  ...QUIZZES_MALWARE_WINDOWS,
  ...QUIZZES_LINUX_CLOUD,
  ...QUIZZES_VENDOR_STACKS,
];

export function getQuiz(slug: string): Quiz | undefined {
  return ALL_QUIZZES.find(q => q.slug === slug);
}
